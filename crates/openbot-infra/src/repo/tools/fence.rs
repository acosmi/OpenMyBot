//! R405: the original run row serializes every durable tool write with terminalization.
//! A call lookup before that lock is only a locator; the locked call is checked again afterwards.

use openbot_application::ToolOutcomeDraft;
use openbot_contracts::ids::ThreadId;
use tokio_postgres::Transaction;

use crate::db::InfraError;
use crate::db::tables::{tool_attempts, tool_calls};
use crate::repo::common::columns_sql;
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

pub(super) const CONFLICT: &str = "tool_journal_write_conflict";

pub(super) fn conflict() -> InfraError {
    InfraError::repository_invariant(CONFLICT)
}

pub(super) async fn initialize(tx: &Transaction<'_>) -> Result<(), InfraError> {
    tx.batch_execute("SET LOCAL lock_timeout='5s'")
        .await
        .map_err(|error| InfraError::query("设置 tool journal lock timeout", error))
}

struct LockedRun {
    actor: String,
    bot: String,
    thread: String,
    running: bool,
}

async fn lock_run(
    tx: &Transaction<'_>,
    run_id: &str,
    referenced_by_call: bool,
) -> Result<LockedRun, InfraError> {
    let row = tx
        .query_opt(
            "SELECT actor_id,bot_id,thread_id,status FROM public.runs WHERE run_id=$1 FOR UPDATE",
            &[&run_id],
        )
        .await
        .map_err(|error| InfraError::query("锁定 tool journal 原 run", error))?
        .ok_or_else(|| {
            if referenced_by_call {
                InfraError::repository_invariant("tool_call_run_missing")
            } else {
                conflict()
            }
        })?;
    let status: String = row
        .try_get("status")
        .map_err(|_| InfraError::repository_invariant("tool_run_status_decode"))?;
    let running = match status.as_str() {
        "running" => true,
        "queued" | "completed" | "failed" | "cancelled" | "reconciliation_required" => false,
        _ => return Err(InfraError::repository_invariant("tool_run_status_unknown")),
    };
    Ok(LockedRun {
        actor: row
            .try_get("actor_id")
            .map_err(|_| InfraError::repository_invariant("tool_run_actor_decode"))?,
        bot: row
            .try_get("bot_id")
            .map_err(|_| InfraError::repository_invariant("tool_run_bot_decode"))?,
        thread: row
            .try_get("thread_id")
            .map_err(|_| InfraError::repository_invariant("tool_run_thread_decode"))?,
        running,
    })
}

/// New durable work needs an open Thread history. The schema proof was observed before the
/// first row lock; the H SHARE is taken after the Run lock and stays on this transaction until
/// its natural end. A closed head is the same journal conflict a stale Run gets; lock, query
/// and invariant failures keep their own class. `outcome` never calls this, because an effect
/// that already ran must still be able to record its result.
async fn admit_open_history(
    tx: &Transaction<'_>,
    schema: &CurrentWriterSchema<'_, '_>,
    run: &LockedRun,
) -> Result<(), InfraError> {
    match schema
        .lock_thread_write_disposition(tx, &ThreadId::new(run.thread.as_str()))
        .await?
    {
        OpenOrClosed::Open => Ok(()),
        OpenOrClosed::Closed => Err(conflict()),
    }
}

pub(super) async fn decision(
    tx: &Transaction<'_>,
    schema: &CurrentWriterSchema<'_, '_>,
    call: &tool_calls::Row,
) -> Result<(), InfraError> {
    let run = lock_run(tx, &call.run_id, false).await?;
    if !run.running || run.actor != call.actor_id || run.bot != call.bot_id {
        return Err(conflict());
    }
    admit_open_history(tx, schema, &run).await
}

/// Locks the original call for a write that creates new durable work (retry, capability).
pub(super) async fn call_for_new_work(
    tx: &Transaction<'_>,
    schema: &CurrentWriterSchema<'_, '_>,
    call_id: &str,
) -> Result<tool_calls::CurrentRow, InfraError> {
    let (stored, run) = lock_call(tx, call_id).await?;
    admit_open_history(tx, schema, &run).await?;
    Ok(stored)
}

pub(super) async fn call(
    tx: &Transaction<'_>,
    call_id: &str,
) -> Result<tool_calls::CurrentRow, InfraError> {
    lock_call(tx, call_id).await.map(|(stored, _)| stored)
}

async fn lock_call(
    tx: &Transaction<'_>,
    call_id: &str,
) -> Result<(tool_calls::CurrentRow, LockedRun), InfraError> {
    let locator = tx
        .query_opt(
            "SELECT run_id FROM public.tool_calls WHERE tool_call_id=$1",
            &[&call_id],
        )
        .await
        .map_err(|error| InfraError::query("定位 tool journal 原 run", error))?
        .ok_or_else(conflict)?;
    let run_id: String = locator
        .try_get("run_id")
        .map_err(|_| InfraError::repository_invariant("tool_call_run_decode"))?;
    let run = lock_run(tx, &run_id, true).await?;
    let sql = format!(
        "SELECT {} FROM public.tool_calls WHERE tool_call_id=$1 FOR SHARE NOWAIT",
        tool_calls::CURRENT_COLUMNS.join(",")
    );
    let row = tx
        .query_opt(&sql, &[&call_id])
        .await
        .map_err(|error| InfraError::query("锁定 tool journal 原 call", error))?
        .ok_or_else(conflict)?;
    let stored = tool_calls::CurrentRow::try_from(&row)?;
    if stored.call.run_id != run_id {
        return Err(conflict());
    }
    if stored.call.actor_id != run.actor || stored.call.bot_id != run.bot {
        return Err(InfraError::repository_invariant("tool_call_run_binding"));
    }
    if !run.running {
        return Err(conflict());
    }
    Ok((stored, run))
}

fn decode_attempt(row: &tokio_postgres::Row) -> Result<tool_attempts::Row, InfraError> {
    let attempt = tool_attempts::Row::try_from(row)?;
    if !matches!(
        attempt.status.as_str(),
        "decision_recorded" | "executing" | "completed" | "reconciliation_required" | "aborted"
    ) {
        return Err(InfraError::repository_invariant(
            "tool_attempt_status_unknown",
        ));
    }
    Ok(attempt)
}

pub(super) async fn attempt_sequence(
    tx: &Transaction<'_>,
    call_id: &str,
    sequence: i64,
) -> Result<Option<tool_attempts::Row>, InfraError> {
    let sql = format!(
        "SELECT {} FROM public.tool_attempts WHERE tool_call_id=$1 AND attempt_seq=$2 \
         FOR UPDATE NOWAIT",
        columns_sql::<tool_attempts::Row>()
    );
    tx.query_opt(&sql, &[&call_id, &sequence])
        .await
        .map_err(|error| InfraError::query("锁定 tool journal 原 attempt sequence", error))?
        .as_ref()
        .map(decode_attempt)
        .transpose()
}

pub(super) async fn outcome(
    tx: &Transaction<'_>,
    draft: &ToolOutcomeDraft,
) -> Result<i64, InfraError> {
    let stored = call(tx, draft.decision.call_id.as_str()).await?;
    let c = &stored.call;
    let d = &draft.decision;
    if c.run_id != d.run_id.as_str()
        || c.actor_id != d.actor.as_str()
        || c.bot_id != d.bot.as_str()
        || c.decision_id != draft.receipt.decision().as_str()
        || Some(c.call_seq) != i64::try_from(d.call_seq).ok()
        || c.tool_name != d.metadata.name.as_str()
        || c.tool_name == "remember"
        || c.args_hash != d.args_hash.to_hex()
        || c.schema_hash != d.metadata.schema_hash.to_hex()
        || Some(c.catalog_generation) != i64::try_from(d.metadata.catalog_generation.get()).ok()
        || c.target_kind != d.target.kind
        || c.target_id != d.target.id
        || c.effect != d.metadata.effect.effect().as_str()
        || c.effect_downgraded != d.metadata.effect.was_downgraded()
        || c.idempotency != d.metadata.idempotency.as_str()
        || c.idempotency_key.as_deref() != d.idempotency_key.as_ref().map(|key| key.as_str())
        || c.approval_class != d.metadata.approval_class.as_str()
        || c.policy_version != d.policy_version.as_str()
        || stored.approval_id != d.approval_id
    {
        return Err(conflict());
    }
    let sql = format!(
        "SELECT {} FROM public.tool_attempts WHERE attempt_id=$1 AND tool_call_id=$2 \
         FOR UPDATE NOWAIT",
        columns_sql::<tool_attempts::Row>()
    );
    let row = tx
        .query_opt(&sql, &[&draft.receipt.attempt().as_str(), &c.tool_call_id])
        .await
        .map_err(|error| InfraError::query("锁定 outcome receipt 原 attempt", error))?
        .ok_or_else(conflict)?;
    let attempt = decode_attempt(&row)?;
    if attempt.tool_call_id != c.tool_call_id
        || attempt.capability_id.as_deref() != Some(draft.capability_id.as_str())
        || attempt.status != "executing"
    {
        return Err(conflict());
    }
    Ok(attempt.attempt_seq)
}
