//! The outbound sender: records run terminals from the engine's notices, then claims due delivery
//! rows of either channel and sends each through the receiver's endpoint. Nothing is logged: the
//! request URL carries the bot token.
use crate::{
    ChannelError, Connection, DELIVERY_BODY_MAX, Endpoints, FS_TOKEN_MARGIN,
    OMB_RESULT_CANCELLED_V1, OMB_RESULT_FAILED_V1, OMB_RESULT_SUCCEEDED_V1, OMB_RESULT_UNKNOWN_V1,
    STORE_BUDGET, Task, Timings,
    feishu::{TokenReply, tenant_token},
};
use omb_store::{
    Channel, Claimed, DeliveryContent, ErrorCode, Finish, RunResultFacts, TerminalKind,
    claim_delivery, finish_delivery, record_terminal, run_result_facts, send_target,
};
use openbot_application::{RunTerminalKind, RunTerminalNotice, RunTerminalSubscriber};
use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
use openbot_infra::{
    net::safe_http::{AuthorizationValue, SafeHttpBudget, SafeHttpError, SafeHttpRequest},
    vault::CredentialRecordVault,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::{
    sync::{
        Notify,
        mpsc::{self, error::TryRecvError},
        oneshot,
    },
    time::Instant,
};
use uuid::Uuid;

/// The engine's terminal subscriber: it only enqueues; a full or closed queue drops the notice,
/// which reconciliation recovers.
pub struct TerminalQueue(pub mpsc::Sender<RunTerminalNotice>);
impl RunTerminalSubscriber for TerminalQueue {
    fn on_run_terminal(&self, notice: RunTerminalNotice) {
        let _ = self.0.try_send(notice);
    }
}

#[derive(Clone)]
pub struct SenderContext {
    pub vault: CredentialRecordVault,
    pub owner: ActorId,
    pub endpoints: Endpoints,
    pub timings: Timings,
    /// The dispatcher's wake-up, signalled after a first terminal write.
    pub wake: Arc<Notify>,
}
/// The sender's in-memory tenant token of one receiver revision; the expiry is on the wall clock,
/// which keeps counting while the machine sleeps. No `Debug` and no `Clone`: the value is a bearer
/// credential.
struct TenantToken {
    receiver: Uuid,
    revision: u64,
    value: String,
    expires_at: OffsetDateTime,
}
impl TenantToken {
    fn usable(&self, receiver: Uuid, revision: u64, now: OffsetDateTime) -> bool {
        self.receiver == receiver
            && self.revision == revision
            && self.expires_at - now >= FS_TOKEN_MARGIN
    }
}

/// Bytes read of one `sendMessage` response.
pub(crate) const SEND_RESPONSE_MAX: usize = 64 * 1024;

/// Starts the sender; a stop takes effect between two sends, never during one.
pub fn start_sender(
    connection: Connection,
    context: SenderContext,
    terminals: mpsc::Receiver<RunTerminalNotice>,
) -> Task {
    Task::spawn(connection, move |client, stop| {
        send(client, context, terminals, stop)
    })
}
async fn send(
    mut client: tokio_postgres::Client,
    context: SenderContext,
    mut terminals: mpsc::Receiver<RunTerminalNotice>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    let mut queue_open = true;
    let mut received = None;
    let mut token: Option<TenantToken> = None;
    while matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
        loop {
            let notice: RunTerminalNotice = match received.take() {
                Some(notice) => notice,
                None if queue_open => match terminals.try_recv() {
                    Ok(notice) => notice,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        queue_open = false;
                        break;
                    }
                },
                None => break,
            };
            let written = record_terminal(
                &mut client,
                notice.run_id.as_str(),
                terminal_kind(notice.terminal),
                Instant::now() + STORE_BUDGET,
            )
            .await
            .map_err(store)?;
            if written.is_some_and(|terminal| terminal.written) {
                context.wake.notify_one();
            }
        }
        if let Some(claimed) = claim_delivery(&client, Instant::now() + STORE_BUDGET)
            .await
            .map_err(store)?
        {
            deliver(&client, &context, claimed, &mut token).await?;
            continue;
        }
        tokio::select! {
            _ = &mut stop => return Ok(()),
            notice = terminals.recv(), if queue_open => match notice {
                Some(notice) => received = Some(notice),
                None => queue_open = false,
            },
            () = tokio::time::sleep(context.timings.delivery_poll) => {}
        }
    }
    Ok(())
}
/// One attempt of a claimed row: the binding and receiver are read again, the credential is opened
/// from the receiver's envelope for this attempt only, and the outcome ends the attempt. A Feishu
/// tenant token is kept across attempts while its receiver revision is unchanged.
async fn deliver(
    client: &tokio_postgres::Client,
    context: &SenderContext,
    claimed: Claimed,
    token: &mut Option<TenantToken>,
) -> Result<(), ChannelError> {
    let store = |_| ChannelError::StoreFailed;
    let timings = &context.timings;
    let target = send_target(
        client,
        claimed.binding_id,
        claimed.channel,
        Instant::now() + STORE_BUDGET,
    )
    .await
    .map_err(store)?;
    let message_id;
    let finish = 'decide: {
        if !target.sender_active {
            break 'decide Finish::Failed {
                code: ErrorCode::BindingInactive,
            };
        }
        let verdict = match claimed.channel {
            Channel::Telegram => {
                let secret = target.receiver.as_ref().and_then(|(receiver, _)| {
                    context
                        .vault
                        .open(
                            &receiver.binding_id,
                            SecretKind::Connector,
                            SecretPrincipal::Actor(context.owner.clone()),
                            SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                            &receiver.credential_envelope,
                        )
                        .ok()
                        .map(|opened| opened.into_secret())
                });
                let token = secret
                    .as_ref()
                    .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
                    .filter(|token| {
                        target.receiver.as_ref().is_some_and(|(receiver, _)| {
                            token
                                .split_once(':')
                                .is_some_and(|(bot_id, _)| bot_id == receiver.source_key)
                        })
                    });
                let Some(token) = token else {
                    break 'decide after_failure(
                        claimed.attempts,
                        ErrorCode::ReceiverInactive,
                        None,
                        &timings.delivery_retry,
                    );
                };
                let Some(chat) = chat_id(&claimed.chat_key) else {
                    break 'decide Finish::Failed {
                        code: ErrorCode::ClientError,
                    };
                };
                let text = match &claimed.content {
                    DeliveryContent::Text(text) => text.clone(),
                    DeliveryContent::RunResult { run_id } => {
                        let facts = run_result_facts(client, run_id, Instant::now() + STORE_BUDGET)
                            .await
                            .map_err(store)?;
                        compose_result(run_id, &facts)
                    }
                };
                let mut url = context.endpoints.telegram.api_base.clone();
                url.set_path(&format!("/bot{token}/sendMessage"));
                let response = async {
                    let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, timings.http_send_timeout)?;
                    context
                        .endpoints
                        .telegram
                        .dialer
                        .execute(SafeHttpRequest::post_json_with_scheme(
                            url,
                            context.endpoints.telegram.scheme,
                            request_body(chat, &text),
                            None,
                            budget,
                        )?)
                        .await
                }
                .await;
                classify(
                    response
                        .as_ref()
                        .map(|response| (response.status().as_u16(), response.body()))
                        .map_err(|error| *error),
                )
            }
            Channel::Feishu => {
                let secret = target.receiver.as_ref().and_then(|(receiver, _)| {
                    context
                        .vault
                        .open(
                            &receiver.binding_id,
                            SecretKind::Connector,
                            SecretPrincipal::Actor(context.owner.clone()),
                            SecretPrincipal::Service(ServiceId::new("openmybot.feishu")),
                            &receiver.credential_envelope,
                        )
                        .ok()
                        .map(|opened| opened.into_secret())
                });
                let app_secret = secret
                    .as_ref()
                    .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
                    .filter(|secret| !secret.is_empty());
                let (Some((receiver, revision)), Some(app_secret)) = (&target.receiver, app_secret)
                else {
                    break 'decide after_failure(
                        claimed.attempts,
                        ErrorCode::ReceiverInactive,
                        None,
                        &timings.delivery_retry,
                    );
                };
                let Some(chat) = feishu_chat_id(&claimed.chat_key) else {
                    break 'decide Finish::Failed {
                        code: ErrorCode::ClientError,
                    };
                };
                let text = match &claimed.content {
                    DeliveryContent::Text(text) => text.clone(),
                    DeliveryContent::RunResult { run_id } => {
                        let facts = run_result_facts(client, run_id, Instant::now() + STORE_BUDGET)
                            .await
                            .map_err(store)?;
                        compose_result(run_id, &facts)
                    }
                };
                let endpoint = &context.endpoints.feishu;
                let reused = token.take().filter(|cached| {
                    cached.usable(receiver.binding_id, *revision, OffsetDateTime::now_utc())
                });
                let cached = match reused {
                    Some(cached) => cached,
                    None => match tenant_token(
                        endpoint,
                        &receiver.source_key,
                        app_secret,
                        timings.http_send_timeout,
                    )
                    .await
                    {
                        TokenReply::Granted { token, expire } => TenantToken {
                            receiver: receiver.binding_id,
                            revision: *revision,
                            value: token,
                            expires_at: OffsetDateTime::now_utc() + expire,
                        },
                        TokenReply::Retry(code) => {
                            break 'decide after_failure(
                                claimed.attempts,
                                code,
                                None,
                                &timings.delivery_retry,
                            );
                        }
                        TokenReply::Rejected => {
                            break 'decide Finish::Failed {
                                code: ErrorCode::ClientError,
                            };
                        }
                    },
                };
                let cached = token.insert(cached);
                let mut url = endpoint.api_base.clone();
                url.set_path("/open-apis/im/v1/messages");
                url.set_query(Some("receive_id_type=chat_id"));
                let response = async {
                    let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, timings.http_send_timeout)?;
                    let authorization =
                        AuthorizationValue::parse(&format!("Bearer {}", cached.value))?;
                    endpoint
                        .dialer
                        .execute(SafeHttpRequest::post_json_with_scheme(
                            url,
                            endpoint.scheme,
                            feishu_body(chat, &text, &claimed.idempotency_key),
                            Some(authorization),
                            budget,
                        )?)
                        .await
                }
                .await;
                classify_feishu(
                    response
                        .as_ref()
                        .map(|response| (response.status().as_u16(), response.body()))
                        .map_err(|error| *error),
                )
            }
        };
        match verdict {
            Verdict::Sent { message_id: sent } => {
                message_id = sent;
                Finish::Sent {
                    platform_message_id: &message_id,
                }
            }
            Verdict::Retry { code, retry_after } => {
                after_failure(claimed.attempts, code, retry_after, &timings.delivery_retry)
            }
            Verdict::Failed { code } => Finish::Failed { code },
            Verdict::Unknown => Finish::Unknown {
                code: ErrorCode::ResultUnknown,
            },
        }
    };
    finish_delivery(
        client,
        claimed.delivery_id,
        finish,
        Instant::now() + STORE_BUDGET,
    )
    .await
    .map_err(store)
}

/// `[OpenMyBot] <state> · run <first 8 of the run id>`, the summary, then the artifact paths; over
/// `DELIVERY_BODY_MAX` the paths are dropped from the end first, then the summary is cut on a
/// character boundary.
pub(crate) fn compose_result(run_id: &str, facts: &RunResultFacts) -> String {
    let state = match facts.terminal {
        TerminalKind::Succeeded => OMB_RESULT_SUCCEEDED_V1.to_owned(),
        TerminalKind::Failed => OMB_RESULT_FAILED_V1.to_owned(),
        TerminalKind::Cancelled => OMB_RESULT_CANCELLED_V1.to_owned(),
        TerminalKind::ReconciliationRequired => OMB_RESULT_UNKNOWN_V1.replace("{run_id}", run_id),
    };
    let short: String = run_id.chars().take(8).collect();
    let mut text = format!("[OpenMyBot] {state} · run {short}");
    let mut summary = facts.result_summary.as_deref().unwrap_or_default();
    let summary_len = |summary: &str| match summary.len() {
        0 => 0,
        len => 1 + len,
    };
    let mut paths = facts.artifact_paths.as_slice();
    let paths_len = |paths: &[String]| match paths.len() {
        0 => 0,
        count => "\n成果：".len() + paths.iter().map(String::len).sum::<usize>() + count - 1,
    };
    while !paths.is_empty()
        && text.len() + summary_len(summary) + paths_len(paths) > DELIVERY_BODY_MAX
    {
        paths = &paths[..paths.len() - 1];
    }
    if text.len() + summary_len(summary) > DELIVERY_BODY_MAX {
        let mut cut = DELIVERY_BODY_MAX.saturating_sub(text.len() + 1);
        while !summary.is_char_boundary(cut) {
            cut -= 1;
        }
        summary = &summary[..cut];
    }
    if !summary.is_empty() {
        text.push('\n');
        text.push_str(summary);
    }
    if !paths.is_empty() {
        text.push_str("\n成果：");
        text.push_str(&paths.join("\n"));
    }
    text
}
/// The decimal chat id after the `telegram:` prefix.
pub(crate) fn chat_id(chat_key: &str) -> Option<i64> {
    chat_key
        .strip_prefix("telegram:")
        .filter(|digits| !digits.starts_with('+'))?
        .parse()
        .ok()
}
/// `{"chat_id": <integer>, "text": <text>}` and no other key: the text is sent as plain text.
pub(crate) fn request_body(chat_id: i64, text: &str) -> Vec<u8> {
    serde_json::json!({"chat_id": chat_id, "text": text})
        .to_string()
        .into_bytes()
}
/// The chat id after the `feishu:` prefix, kept as the platform's text.
pub(crate) fn feishu_chat_id(chat_key: &str) -> Option<&str> {
    chat_key
        .strip_prefix("feishu:")
        .filter(|chat_id| !chat_id.is_empty())
}
/// `receive_id`, `msg_type`, `content` and `uuid` and no other key: `content` is the JSON text of
/// `{"text": <text>}`, and `uuid` the first 16 bytes of the idempotency key's SHA-256 in lower-case
/// hex, so a resent row is deduplicated by the platform.
pub(crate) fn feishu_body(chat_id: &str, text: &str, idempotency_key: &str) -> Vec<u8> {
    let uuid: String = Sha256::digest(idempotency_key.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({
        "receive_id": chat_id,
        "msg_type": "text",
        "content": json!({"text": text}).to_string(),
        "uuid": uuid,
    })
    .to_string()
    .into_bytes()
}

/// What one `sendMessage` outcome means for the row.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Sent {
        message_id: String,
    },
    /// A definite failure that takes a retry slot.
    Retry {
        code: ErrorCode,
        retry_after: Option<Duration>,
    },
    Failed {
        code: ErrorCode,
    },
    /// The request may have reached the platform; never resent.
    Unknown,
}
pub(crate) fn classify(result: Result<(u16, &[u8]), SafeHttpError>) -> Verdict {
    match result {
        Err(
            SafeHttpError::DnsUnavailable
            | SafeHttpError::DestinationDenied
            | SafeHttpError::ConnectFailed
            | SafeHttpError::PeerMismatch
            | SafeHttpError::TlsFailed
            | SafeHttpError::InvalidUrl
            | SafeHttpError::SchemeRejected
            | SafeHttpError::InvalidBudget
            | SafeHttpError::InvalidHeader
            | SafeHttpError::InvalidAllowlist,
        ) => Verdict::Retry {
            code: ErrorCode::Unreachable,
            retry_after: None,
        },
        Err(
            SafeHttpError::DeadlineExceeded
            | SafeHttpError::ProtocolFailed
            | SafeHttpError::ResponseTooLarge
            | SafeHttpError::StreamStalled
            | SafeHttpError::RedirectInvalid
            | SafeHttpError::RedirectLimit
            | SafeHttpError::RedirectMethodRejected
            | SafeHttpError::SensitiveRedirectRejected,
        ) => Verdict::Unknown,
        Ok((429, body)) => Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|body| {
                    body.pointer("/parameters/retry_after")
                        .and_then(Value::as_u64)
                })
                .map(Duration::from_secs),
        },
        Ok((500..=599, _)) => Verdict::Retry {
            code: ErrorCode::ServerError,
            retry_after: None,
        },
        Ok((200..=299, body)) => serde_json::from_slice::<Value>(body)
            .ok()
            .filter(|body| body.get("ok") == Some(&Value::Bool(true)))
            .and_then(|body| body.pointer("/result/message_id").and_then(Value::as_i64))
            .map_or(Verdict::Unknown, |id| Verdict::Sent {
                message_id: id.to_string(),
            }),
        Ok(_) => Verdict::Failed {
            code: ErrorCode::ClientError,
        },
    }
}
/// The Feishu send outcome: the rate-limit codes 230020 and 99991400 count as 429 whatever the
/// status, and only code 0 with a message id is sent.
pub(crate) fn classify_feishu(result: Result<(u16, &[u8]), SafeHttpError>) -> Verdict {
    let (status, body) = match result {
        Err(
            SafeHttpError::DnsUnavailable
            | SafeHttpError::DestinationDenied
            | SafeHttpError::ConnectFailed
            | SafeHttpError::PeerMismatch
            | SafeHttpError::TlsFailed
            | SafeHttpError::InvalidUrl
            | SafeHttpError::SchemeRejected
            | SafeHttpError::InvalidBudget
            | SafeHttpError::InvalidHeader
            | SafeHttpError::InvalidAllowlist,
        ) => {
            return Verdict::Retry {
                code: ErrorCode::Unreachable,
                retry_after: None,
            };
        }
        Err(
            SafeHttpError::DeadlineExceeded
            | SafeHttpError::ProtocolFailed
            | SafeHttpError::ResponseTooLarge
            | SafeHttpError::StreamStalled
            | SafeHttpError::RedirectInvalid
            | SafeHttpError::RedirectLimit
            | SafeHttpError::RedirectMethodRejected
            | SafeHttpError::SensitiveRedirectRejected,
        ) => return Verdict::Unknown,
        Ok((429, _)) => {
            return Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: None,
            };
        }
        Ok((500..=599, _)) => {
            return Verdict::Retry {
                code: ErrorCode::ServerError,
                retry_after: None,
            };
        }
        Ok(reply) => reply,
    };
    let body = serde_json::from_slice::<Value>(body).ok();
    match (
        status,
        body.as_ref()
            .and_then(|body| body.get("code"))
            .and_then(Value::as_i64),
    ) {
        (_, Some(230_020 | 99_991_400)) => Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: None,
        },
        (200..=299, Some(0)) => body
            .as_ref()
            .and_then(|body| body.pointer("/data/message_id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map_or(Verdict::Unknown, |id| Verdict::Sent {
                message_id: id.to_owned(),
            }),
        (200..=299, None) => Verdict::Unknown,
        _ => Verdict::Failed {
            code: ErrorCode::ClientError,
        },
    }
}
/// A definite failure of the `attempts`-th claim: retried after the planned wait, or after the
/// platform's longer wait, until the sixth claim fails as exhausted.
pub(crate) fn after_failure(
    attempts: u32,
    code: ErrorCode,
    retry_after: Option<Duration>,
    schedule: &[Duration; 5],
) -> Finish<'static> {
    match attempts
        .checked_sub(1)
        .and_then(|index| schedule.get(index as usize))
    {
        Some(planned) => Finish::Retry {
            after: (*planned).max(retry_after.unwrap_or_default()),
            code,
        },
        None => Finish::Failed {
            code: ErrorCode::RetriesExhausted,
        },
    }
}
pub(crate) fn terminal_kind(kind: RunTerminalKind) -> TerminalKind {
    match kind {
        RunTerminalKind::Succeeded => TerminalKind::Succeeded,
        RunTerminalKind::Failed => TerminalKind::Failed,
        RunTerminalKind::Cancelled => TerminalKind::Cancelled,
        RunTerminalKind::ReconciliationRequired => TerminalKind::ReconciliationRequired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::{DeploymentId, RunId, TenantId, ThreadId};

    const RUN: &str = "0192f1a2-3b4c-7d5e-8f60-718293a4b5c6";
    fn facts(terminal: TerminalKind, summary: Option<&str>, paths: &[&str]) -> RunResultFacts {
        RunResultFacts {
            terminal,
            result_summary: summary.map(str::to_owned),
            artifact_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }
    fn retry(finish: Finish<'_>) -> (Duration, ErrorCode) {
        match finish {
            Finish::Retry { after, code } => (after, code),
            _ => panic!("not a retry"),
        }
    }
    fn notice(run: &str) -> RunTerminalNotice {
        RunTerminalNotice {
            deployment: DeploymentId::new("deployment"),
            tenant: TenantId::new("tenant"),
            thread_id: ThreadId::new("thread"),
            run_id: RunId::new(run),
            terminal: RunTerminalKind::Succeeded,
        }
    }

    #[test]
    fn first_line_uses_state_text_and_first_eight_of_run_id_for_each_kind() {
        for (kind, line) in [
            (TerminalKind::Succeeded, "[OpenMyBot] 已完成 · run 0192f1a2"),
            (TerminalKind::Failed, "[OpenMyBot] 失败 · run 0192f1a2"),
            (TerminalKind::Cancelled, "[OpenMyBot] 已取消 · run 0192f1a2"),
        ] {
            assert_eq!(compose_result(RUN, &facts(kind, None, &[])), line);
        }
        let unknown = compose_result(RUN, &facts(TerminalKind::ReconciliationRequired, None, &[]));
        assert_eq!(
            unknown,
            format!(
                "[OpenMyBot] 结果未知，在本机执行 openmybot status --run {RUN} 核对 · run 0192f1a2"
            )
        );
        assert!(unknown.contains(RUN));
        assert!(!unknown.contains('\n'));
    }
    #[test]
    fn body_is_first_line_summary_and_artifacts_line() {
        let text = compose_result(
            RUN,
            &facts(
                TerminalKind::Succeeded,
                Some("wrote /srv/project/out.txt"),
                &["out.txt", "docs/a.md"],
            ),
        );
        assert_eq!(
            text,
            "[OpenMyBot] 已完成 · run 0192f1a2\nwrote /srv/project/out.txt\n成果：out.txt\ndocs/a.md"
        );
    }
    #[test]
    fn body_without_summary_or_without_artifacts_omits_that_line() {
        for summary in [None, Some("")] {
            assert_eq!(
                compose_result(RUN, &facts(TerminalKind::Succeeded, summary, &["a.txt"])),
                "[OpenMyBot] 已完成 · run 0192f1a2\n成果：a.txt"
            );
        }
        assert_eq!(
            compose_result(RUN, &facts(TerminalKind::Succeeded, Some("done"), &[])),
            "[OpenMyBot] 已完成 · run 0192f1a2\ndone"
        );
    }
    #[test]
    fn oversized_body_drops_paths_from_the_end_before_touching_the_summary() {
        let summary = "s".repeat(2048);
        let paths: Vec<String> = (0..20)
            .map(|n| format!("{n:02}-{}", "p".repeat(60)))
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let text = compose_result(RUN, &facts(TerminalKind::Succeeded, Some(&summary), &refs));
        assert!(text.len() <= DELIVERY_BODY_MAX);
        assert!(text.contains(&format!("\n{summary}\n成果：")));
        let kept = text.split("\n成果：").nth(1).unwrap().split('\n').count();
        assert!(kept < 20);
        assert_eq!(
            text.split("\n成果：")
                .nth(1)
                .unwrap()
                .split('\n')
                .collect::<Vec<_>>(),
            refs[..kept]
        );
        // One more path would not have fitted.
        assert!(text.len() + 1 + refs[kept].len() > DELIVERY_BODY_MAX);
        let huge = "q".repeat(DELIVERY_BODY_MAX);
        let alone = compose_result(
            RUN,
            &facts(TerminalKind::Succeeded, Some("done"), &[huge.as_str()]),
        );
        assert_eq!(alone, "[OpenMyBot] 已完成 · run 0192f1a2\ndone");
    }
    #[test]
    fn still_oversized_body_truncates_summary_on_a_char_boundary_without_ellipsis() {
        for unit in ["界", "ab", "é", "😀"] {
            let summary = unit.repeat(DELIVERY_BODY_MAX);
            let text = compose_result(
                RUN,
                &facts(TerminalKind::Failed, Some(&summary), &["a.txt"]),
            );
            assert!(text.len() <= DELIVERY_BODY_MAX, "{unit}");
            assert!(text.len() > DELIVERY_BODY_MAX - unit.len() - 1, "{unit}");
            assert!(!text.contains("成果："));
            assert!(!text.ends_with('…'));
            let body = text.split_once('\n').unwrap().1;
            assert!(summary.starts_with(body));
            assert!(std::str::from_utf8(text.as_bytes()).is_ok());
        }
    }
    #[test]
    fn chat_id_is_the_decimal_after_the_telegram_prefix() {
        assert_eq!(chat_id("telegram:42"), Some(42));
        assert_eq!(chat_id("telegram:-100123"), Some(-100_123));
        for key in [
            "42",
            "feishu:42",
            "telegram:",
            "telegram:4x2",
            "telegram:+42",
            "telegram:0x2a",
            "telegram:99999999999999999999",
        ] {
            assert_eq!(chat_id(key), None, "{key}");
        }
    }
    #[test]
    fn request_body_has_exactly_chat_id_and_text() {
        let body: Value = serde_json::from_slice(&request_body(-42, "你好 \"x\"\n")).unwrap();
        let object = body.as_object().unwrap();
        // Exactly these two keys: no formatting mode is ever requested.
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["chat_id", "text"]);
        assert_eq!(object["chat_id"], Value::from(-42));
        assert!(object["chat_id"].is_i64());
        assert_eq!(object["text"], "你好 \"x\"\n");
    }
    #[test]
    fn terminal_kind_maps_the_four_engine_kinds() {
        assert_eq!(
            [
                RunTerminalKind::Succeeded,
                RunTerminalKind::Failed,
                RunTerminalKind::Cancelled,
                RunTerminalKind::ReconciliationRequired,
            ]
            .map(terminal_kind),
            [
                TerminalKind::Succeeded,
                TerminalKind::Failed,
                TerminalKind::Cancelled,
                TerminalKind::ReconciliationRequired,
            ]
        );
    }
    #[test]
    fn classify_2xx_ok_true_is_sent_with_decimal_message_id() {
        assert_eq!(
            classify(Ok((
                200,
                br#"{"ok":true,"result":{"message_id":123,"text":"x"}}"#
            ))),
            Verdict::Sent {
                message_id: "123".into()
            }
        );
    }
    #[test]
    fn classify_2xx_ok_false_unparseable_or_without_message_id_is_unknown() {
        for body in [
            br#"{"ok":false,"result":{"message_id":1}}"#.as_slice(),
            b"not json",
            br#"{"ok":true,"result":{}}"#,
            br#"{"ok":true}"#,
        ] {
            assert_eq!(classify(Ok((200, body))), Verdict::Unknown);
        }
    }
    #[test]
    fn classify_429_is_rate_limited_and_reads_retry_after() {
        assert_eq!(
            classify(Ok((
                429,
                br#"{"ok":false,"error_code":429,"parameters":{"retry_after":7}}"#
            ))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: Some(Duration::from_secs(7)),
            }
        );
        assert_eq!(
            classify(Ok((429, br#"{"ok":false,"error_code":429}"#))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: None,
            }
        );
    }
    #[test]
    fn classify_5xx_is_server_error_retry() {
        for status in [500, 502, 503] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Retry {
                    code: ErrorCode::ServerError,
                    retry_after: None,
                }
            );
        }
    }
    #[test]
    fn classify_other_4xx_and_leftover_3xx_are_client_error_failed() {
        for status in [400, 401, 403, 404, 302] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Failed {
                    code: ErrorCode::ClientError
                },
                "{status}"
            );
        }
    }
    #[test]
    fn classify_errors_before_the_request_is_sent_are_unreachable_retry() {
        for error in [
            SafeHttpError::DnsUnavailable,
            SafeHttpError::DestinationDenied,
            SafeHttpError::ConnectFailed,
            SafeHttpError::PeerMismatch,
            SafeHttpError::TlsFailed,
            SafeHttpError::InvalidUrl,
            SafeHttpError::SchemeRejected,
            SafeHttpError::InvalidBudget,
            SafeHttpError::InvalidHeader,
            SafeHttpError::InvalidAllowlist,
        ] {
            assert_eq!(
                classify(Err(error)),
                Verdict::Retry {
                    code: ErrorCode::Unreachable,
                    retry_after: None,
                },
                "{error:?}"
            );
        }
    }
    #[test]
    fn classify_errors_after_the_request_is_sent_are_unknown() {
        for error in [
            SafeHttpError::DeadlineExceeded,
            SafeHttpError::ProtocolFailed,
            SafeHttpError::ResponseTooLarge,
            SafeHttpError::StreamStalled,
            SafeHttpError::RedirectInvalid,
            SafeHttpError::RedirectLimit,
            SafeHttpError::RedirectMethodRejected,
            SafeHttpError::SensitiveRedirectRejected,
        ] {
            assert_eq!(classify(Err(error)), Verdict::Unknown, "{error:?}");
        }
    }
    #[test]
    fn after_failure_schedules_retry_n_after_the_nth_planned_interval() {
        let schedule = crate::DELIVERY_RETRY;
        for attempts in 1..=5u32 {
            for code in [
                ErrorCode::Unreachable,
                ErrorCode::ServerError,
                ErrorCode::ReceiverInactive,
            ] {
                assert_eq!(
                    retry(after_failure(attempts, code, None, &schedule)),
                    (schedule[attempts as usize - 1], code)
                );
            }
        }
    }
    #[test]
    fn after_failure_429_waits_the_larger_of_retry_after_and_plan() {
        let schedule = crate::DELIVERY_RETRY;
        let code = ErrorCode::RateLimited;
        assert_eq!(
            retry(after_failure(
                1,
                code,
                Some(Duration::from_secs(300)),
                &schedule
            )),
            (Duration::from_secs(300), code)
        );
        assert_eq!(
            retry(after_failure(
                2,
                code,
                Some(Duration::from_secs(5)),
                &schedule
            )),
            (Duration::from_secs(120), code)
        );
        assert_eq!(
            retry(after_failure(3, code, None, &schedule)),
            (Duration::from_secs(240), code)
        );
    }
    #[test]
    fn after_failure_on_the_sixth_attempt_is_failed_retries_exhausted() {
        for code in [
            ErrorCode::Unreachable,
            ErrorCode::RateLimited,
            ErrorCode::ServerError,
            ErrorCode::ReceiverInactive,
        ] {
            assert!(matches!(
                after_failure(
                    6,
                    code,
                    Some(Duration::from_secs(1)),
                    &crate::DELIVERY_RETRY
                ),
                Finish::Failed {
                    code: ErrorCode::RetriesExhausted
                }
            ));
        }
    }
    #[test]
    fn terminal_queue_drops_when_full_without_blocking() {
        let (sender, mut receiver) = mpsc::channel(1);
        let queue = TerminalQueue(sender);
        queue.on_run_terminal(notice("first"));
        queue.on_run_terminal(notice("second"));
        assert_eq!(receiver.try_recv().unwrap().run_id.as_str(), "first");
        assert!(receiver.try_recv().is_err());
    }
    #[test]
    fn terminal_queue_drops_after_the_receiver_is_closed() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let queue = TerminalQueue(sender);
        queue.on_run_terminal(notice("first"));
        queue.on_run_terminal(notice("second"));
    }
    #[test]
    fn feishu_chat_id_is_the_raw_text_after_the_feishu_prefix() {
        assert_eq!(feishu_chat_id("feishu:oc_1"), Some("oc_1"));
        assert_eq!(feishu_chat_id("feishu:ou 1"), Some("ou 1"));
        for key in ["feishu:", "telegram:42", "oc_1"] {
            assert_eq!(feishu_chat_id(key), None, "{key}");
        }
        assert_eq!(chat_id("feishu:42"), None);
    }
    #[test]
    fn feishu_body_has_four_keys_and_uuid_is_the_sha256_prefix() {
        let body: Value =
            serde_json::from_slice(&feishu_body("oc_1", "你好 \"x\"\n", "control_reply:f1"))
                .unwrap();
        let object = body.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["content", "msg_type", "receive_id", "uuid"]);
        assert_eq!(object["receive_id"], "oc_1");
        assert_eq!(object["msg_type"], "text");
        let content: Value = serde_json::from_str(object["content"].as_str().unwrap()).unwrap();
        assert_eq!(content["text"], "你好 \"x\"\n");
        for (key, uuid) in [
            ("control_reply:f1", "95f12bd8e78f5b6e7d886b7f16c05d03"),
            ("result:run-9", "10587490d704f9cc303b3c5e1ad34e44"),
        ] {
            let body: Value = serde_json::from_slice(&feishu_body("oc_1", "x", key)).unwrap();
            assert_eq!(body["uuid"], uuid);
            assert_eq!(uuid.len(), 32);
            assert!(
                uuid.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }
    #[test]
    fn classify_feishu_follows_the_closed_classification() {
        for error in [
            SafeHttpError::DnsUnavailable,
            SafeHttpError::DestinationDenied,
            SafeHttpError::ConnectFailed,
            SafeHttpError::PeerMismatch,
            SafeHttpError::TlsFailed,
            SafeHttpError::InvalidUrl,
            SafeHttpError::SchemeRejected,
            SafeHttpError::InvalidBudget,
            SafeHttpError::InvalidHeader,
            SafeHttpError::InvalidAllowlist,
        ] {
            assert_eq!(
                classify_feishu(Err(error)),
                Verdict::Retry {
                    code: ErrorCode::Unreachable,
                    retry_after: None,
                },
                "{error:?}"
            );
        }
        for error in [
            SafeHttpError::DeadlineExceeded,
            SafeHttpError::ProtocolFailed,
            SafeHttpError::ResponseTooLarge,
            SafeHttpError::StreamStalled,
            SafeHttpError::RedirectInvalid,
            SafeHttpError::RedirectLimit,
            SafeHttpError::RedirectMethodRejected,
            SafeHttpError::SensitiveRedirectRejected,
        ] {
            assert_eq!(classify_feishu(Err(error)), Verdict::Unknown, "{error:?}");
        }
        let rate_limited = Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: None,
        };
        for (status, body) in [
            (429, r#"{"parameters":{"retry_after":9}}"#),
            (400, r#"{"code":230020}"#),
            (400, r#"{"code":99991400}"#),
            (200, r#"{"code":230020}"#),
        ] {
            assert_eq!(
                classify_feishu(Ok((status, body.as_bytes()))),
                rate_limited,
                "{status} {body}"
            );
        }
        for status in [500, 502] {
            assert_eq!(
                classify_feishu(Ok((status, b""))),
                Verdict::Retry {
                    code: ErrorCode::ServerError,
                    retry_after: None,
                }
            );
        }
        assert_eq!(
            classify_feishu(Ok((200, br#"{"code":0,"data":{"message_id":"om_1"}}"#))),
            Verdict::Sent {
                message_id: "om_1".into()
            }
        );
        for body in [
            r#"{"code":0}"#,
            r#"{"code":0,"data":{"message_id":""}}"#,
            "x",
            r#"{"code":"0"}"#,
        ] {
            assert_eq!(
                classify_feishu(Ok((200, body.as_bytes()))),
                Verdict::Unknown,
                "{body}"
            );
        }
        for (status, body) in [
            (200, r#"{"code":230001}"#),
            (400, r#"{"code":230002}"#),
            (404, ""),
            (403, r#"{"code":99991672}"#),
            (302, ""),
        ] {
            assert_eq!(
                classify_feishu(Ok((status, body.as_bytes()))),
                Verdict::Failed {
                    code: ErrorCode::ClientError
                },
                "{status} {body}"
            );
        }
    }
    #[test]
    fn tenant_token_is_usable_only_with_the_margin_left_on_the_wall_clock() {
        let now = OffsetDateTime::from_unix_timestamp(1_793_260_800).unwrap();
        let receiver = Uuid::from_u128(1);
        let token = |expires_at| TenantToken {
            receiver,
            revision: 3,
            value: "t-1".to_owned(),
            expires_at,
        };
        assert!(token(now + Duration::from_secs(30 * 60)).usable(receiver, 3, now));
        assert!(!token(now + Duration::from_secs(30 * 60 - 1)).usable(receiver, 3, now));
        assert!(token(now + Duration::from_secs(2 * 3600)).usable(receiver, 3, now));
        assert!(!token(now + Duration::from_secs(2 * 3600)).usable(Uuid::from_u128(2), 3, now));
        assert!(!token(now + Duration::from_secs(2 * 3600)).usable(receiver, 4, now));
        assert!(!token(now - Duration::from_secs(3600)).usable(receiver, 3, now));
    }
}
