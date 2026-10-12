//! Transactional canonical-message channel projection and PostgreSQL wake.

use crate::db::{InfraError, RowDecodeError};
use openbot_contracts::command::ChannelActivityEvent;
use openbot_contracts::ids::{BotId, ChannelId, ThreadId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::thread::MessageId;
use time::OffsetDateTime;
use tokio_postgres::Row;

pub(crate) const CHANNEL_ACTIVITY_TOPIC: &str = "openbot_channel_activity";
const MAX_PREVIEW_CODE_POINTS: usize = 200;
const MAX_NOTIFY_BYTES: usize = 7_000;

pub(crate) async fn record_from_message(
    schema: &crate::thread_history_writer::CurrentWriterSchema<'_, '_>,
    message_id: &MessageId,
) -> Result<(), InfraError> {
    // The caller observed the current schema on this original transaction before its
    // first row lock; every statement here runs on that same transaction, and none of
    // them repeats the catalog observation under the channel serial point.
    let transaction = schema.transaction();
    // Resolve only the actual written message's physical anchor. No caller text,
    // timestamp, J or arbitrary newest Run can select the source.
    let anchor = transaction
        .query_opt(
            "SELECT t.anchor_kind,t.anchor_id FROM public.messages m \
         JOIN public.runs r ON r.run_id=m.run_id AND r.thread_id=m.thread_id \
         JOIN public.threads t ON t.thread_id=r.thread_id WHERE m.message_id=$1",
            &[&message_id.as_str()],
        )
        .await
        .map_err(|e| crate::thread_history_writer::query_error("读取频道消息来源锚点", e))?
        .ok_or_else(invalid)?;
    let kind: String = decode(&anchor, "anchor_kind")?;
    if kind == "direct_bot" {
        return Ok(());
    }
    if kind != "channel" {
        return Err(invalid());
    }
    let channel: String = decode(&anchor, "anchor_id")?;
    transaction
        .query_one(
            "SELECT id FROM public.channels WHERE id=$1 FOR UPDATE NOWAIT",
            &[&channel],
        )
        .await
        .map_err(|e| crate::thread_history_writer::query_error("锁定真实频道projection", e))?;
    // This is a fresh statement after the real channel serial point. The source
    // row's guard independently retains m/r/t SHARE and H SHARE until the same
    // Tx naturally ends. Existing r/t/lease locks require NOWAIT for this edge.
    let source=transaction.query_opt(
        "SELECT t.deployment_id,t.tenant_id,t.thread_id,r.run_id,r.actor_id,r.bot_id, \
                m.role,m.actor_id AS message_actor,m.content->>'text' AS text,m.search_text, \
                m.created_at,c.last_message_at \
         FROM public.messages m JOIN public.runs r ON r.run_id=m.run_id AND r.thread_id=m.thread_id \
         JOIN public.threads t ON t.thread_id=r.thread_id \
         JOIN public.channels c ON c.id=t.anchor_id \
         WHERE m.message_id=$1 AND t.anchor_kind='channel' AND c.id=$2 \
         FOR SHARE OF m,r,t NOWAIT",
        &[&message_id.as_str(),&channel],
    ).await.map_err(|e|crate::thread_history_writer::query_error("核同真实频道消息来源",e))?
        .ok_or_else(invalid)?;
    let at: OffsetDateTime = decode(&source, "created_at")?;
    let prior_at: Option<OffsetDateTime> = decode(&source, "last_message_at")?;
    // Preserve the original strict timestamp predicate before any source write.
    if prior_at.is_some_and(|old| old >= at) {
        return Ok(());
    }
    let thread: String = decode(&source, "thread_id")?;
    schema
        .require_open(transaction, &ThreadId::new(&thread))
        .await?;
    let role: String = decode(&source, "role")?;
    let actor: Option<String> = decode(&source, "message_actor")?;
    let run_actor: String = decode(&source, "actor_id")?;
    let bot: String = decode(&source, "bot_id")?;
    let agent = match role.as_str() {
        "user" if actor.as_deref() == Some(run_actor.as_str()) => None,
        "assistant" if actor.is_none() => Some(bot),
        _ => return Err(invalid()),
    };
    let text: Option<String> = decode(&source, "text")?;
    let text = text.ok_or_else(invalid)?;
    let search: String = decode(&source, "search_text")?;
    if text != search {
        return Err(invalid());
    }
    let preview = preview(&text);
    let checksum = Sha256Digest::of(preview.as_bytes()).to_hex();
    let bytes = i32::try_from(preview.len()).map_err(|_| invalid())?;
    let deployment: String = decode(&source, "deployment_id")?;
    let tenant: String = decode(&source, "tenant_id")?;
    let run: String = decode(&source, "run_id")?;
    transaction.execute(
        "INSERT INTO openbot_internal.channel_history_sources \
         (channel_id,source_schema,deployment_id,tenant_id,thread_id,run_id,message_id, \
          message_role,message_created_at,last_message_agent_id,preview_checksum,preview_utf8_bytes) \
         VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
         ON CONFLICT(channel_id) DO UPDATE SET source_schema=EXCLUDED.source_schema, \
          deployment_id=EXCLUDED.deployment_id,tenant_id=EXCLUDED.tenant_id,thread_id=EXCLUDED.thread_id, \
          run_id=EXCLUDED.run_id,message_id=EXCLUDED.message_id,message_role=EXCLUDED.message_role, \
          message_created_at=EXCLUDED.message_created_at,last_message_agent_id=EXCLUDED.last_message_agent_id, \
          preview_checksum=EXCLUDED.preview_checksum,preview_utf8_bytes=EXCLUDED.preview_utf8_bytes",
        &[&channel,&deployment,&tenant,&thread,&run,&message_id.as_str(),&role,&at,&agent,&checksum,&bytes],
    ).await.map_err(|e|crate::thread_history_writer::query_error("登记真实频道消息source",e))?;
    let changed=transaction.execute(
        "UPDATE public.channels SET last_message=$2,last_message_at=$3,last_message_agent_id=$4, \
         updated_at=greatest(updated_at,$3) WHERE id=$1 AND (last_message_at IS NULL OR last_message_at<$3)",
        &[&channel,&preview,&at,&agent],
    ).await.map_err(|e|crate::thread_history_writer::query_error("更新真实频道消息projection",e))?;
    if changed != 1 {
        return Err(invalid());
    }
    let event = ChannelActivityEvent {
        channel_id: ChannelId::new(channel),
        last_message: Some(preview),
        last_message_at: Some(at),
        last_message_agent_id: agent.map(BotId::new),
    };
    let payload = serde_json::to_string(&event).expect("closed channel activity event serializes");
    if payload.len() > MAX_NOTIFY_BYTES {
        tracing::warn!(
            payload_bytes = payload.len(),
            "channel activity payload exceeds bounded NOTIFY budget; roster remains authoritative"
        );
        return Ok(());
    }
    transaction
        .query_one(
            "SELECT pg_notify('openbot_channel_activity',$1)",
            &[&payload],
        )
        .await
        .map_err(|e| crate::thread_history_writer::query_error("发送真实频道projection wake", e))?;
    Ok(())
}

fn invalid() -> InfraError {
    InfraError::repository_invariant("thread_history_writer_binding_invalid")
}
fn decode<T: tokio_postgres::types::FromSqlOwned>(
    row: &Row,
    column: &'static str,
) -> Result<T, InfraError> {
    row.try_get(column)
        .map_err(|source| RowDecodeError::column("(channel_history_source)", column, source).into())
}

fn preview(text: &str) -> String {
    let flattened = text
        .chars()
        .map(|character| {
            let value = character as u32;
            if value <= 0x1f || (0x7f..=0x9f).contains(&value) {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let collapsed = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_PREVIEW_CODE_POINTS {
        return collapsed;
    }
    let mut output = collapsed
        .chars()
        .take(MAX_PREVIEW_CODE_POINTS - 1)
        .collect::<String>();
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_is_one_line_control_free_and_code_point_bounded() {
        assert_eq!(preview("  hello\n\tworld\u{0085}!  "), "hello world !");
        let long = "张".repeat(250);
        let output = preview(&long);
        assert_eq!(output.chars().count(), 200);
        assert!(output.ends_with('…'));
        assert_eq!(preview("short"), "short");
    }
}
