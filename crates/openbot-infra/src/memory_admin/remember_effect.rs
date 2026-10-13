//! The sole remember business-evidence producer. Locks precede all evidence reads and writes.

use openbot_application::{
    CommittedMemoryEffect, MemoryAdministrationError as Error, RememberToolMemoryRequest,
    RememberToolScope, ToolOutcomeDraft, ToolPortError,
};
use openbot_contracts::reconciliation::valid_reconciliation_id;
use openbot_domain::audit::{
    event::{AuditEvent, AuditEventType},
    payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload},
};
use openbot_domain::tool::commit::CommitState;
use tokio_postgres::{Row, Transaction};

use crate::db::tables::remember_effect_receipts;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::repo::common::insert_sql;
use crate::run_runtime::{
    RUN_CANCEL_DESTINATION, RunCancelAcceptance, run_cancel_acceptance, run_cancel_outbox_id,
};
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

use super::history_error;

fn corrupt() -> Error {
    Error::Corrupt {
        field: "remember_effect_binding",
    }
}
fn db(_: tokio_postgres::Error) -> Error {
    Error::Unavailable
}
fn get<'a, T: tokio_postgres::types::FromSql<'a>>(row: &'a Row, field: &str) -> Result<T, Error> {
    row.try_get(field).map_err(|_| corrupt())
}
fn require(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(corrupt()) }
}
fn number(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| corrupt())
}

pub(super) struct Locked {
    run: Row,
    thread: Row,
    call: Row,
    attempt: Row,
    lease: Option<Row>,
    cancelled: bool,
    /// Set by `admit` only. A closed Thread history refuses a NEW effect (`require_fresh`),
    /// while an exact replay of an already committed receipt is still returned.
    history_closed: bool,
}

impl Locked {
    pub(super) fn require_fresh(&self) -> Result<(), Error> {
        if get::<&str>(&self.run, "status")? != "running"
            || self.cancelled
            || self.history_closed
            || get::<&str>(&self.attempt, "status")? != "executing"
        {
            return Err(Error::Conflict);
        }
        let lease = self.lease.as_ref().ok_or(Error::Conflict)?;
        if get::<i64>(lease, "fencing_token")? != get::<i64>(&self.run, "fencing_token")?
            || !get::<bool>(lease, "current")?
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

async fn lock_original(
    tx: &Transaction<'_>,
    actor: &str,
    run_id: &str,
    call_id: &str,
    attempt_id: &str,
    check_cancel: bool,
) -> Result<Locked, Error> {
    let run = tx.query_opt("SELECT run_id,thread_id,actor_id,bot_id,status,fencing_token FROM public.runs WHERE run_id=$1 FOR UPDATE NOWAIT",
        &[&run_id]).await.map_err(db)?.ok_or(Error::NotVisible)?;
    require(get::<&str>(&run, "actor_id")? == actor)?;
    let thread_id: &str = get(&run, "thread_id")?;
    // This must be a NEW statement after obtaining the run lock. Never lock the outbox row:
    // cancellation consumers own it before acquiring run, and delivery does not revoke acceptance.
    let cancelled = if check_cancel {
        cancellation(tx, run_id, thread_id, actor).await?
    } else {
        false
    };
    let thread = tx.query_opt("SELECT thread_id,deployment_id,tenant_id,anchor_kind,anchor_id,status FROM public.threads WHERE thread_id=$1 FOR UPDATE NOWAIT",
        &[&thread_id]).await.map_err(db)?.ok_or_else(corrupt)?;
    let lease = tx.query_opt("SELECT fencing_token,expires_at>clock_timestamp() AS current FROM public.thread_leases WHERE thread_id=$1 FOR UPDATE NOWAIT",
        &[&thread_id]).await.map_err(db)?;
    let call = tx.query_opt("SELECT tool_call_id,run_id,actor_id,bot_id,call_seq,decision_id,tool_name,args_hash,schema_hash,catalog_generation,target_kind,target_id FROM public.tool_calls WHERE tool_call_id=$1 FOR SHARE NOWAIT",
        &[&call_id]).await.map_err(db)?.ok_or_else(corrupt)?;
    let attempt = tx.query_opt("SELECT tool_call_id,attempt_id,attempt_seq,capability_id,status,commit_state FROM public.tool_attempts WHERE attempt_id=$1 FOR UPDATE NOWAIT",
        &[&attempt_id]).await.map_err(db)?.ok_or_else(corrupt)?;
    require(
        get::<&str>(&call, "run_id")? == run_id
            && get::<&str>(&call, "actor_id")? == actor
            && get::<&str>(&call, "bot_id")? == get::<&str>(&run, "bot_id")?
            && get::<&str>(&call, "tool_name")? == "remember"
            && get::<&str>(&attempt, "tool_call_id")? == call_id
            && get::<i64>(&call, "call_seq")? >= 0
            && get::<i64>(&attempt, "attempt_seq")? >= 0,
    )?;
    Ok(Locked {
        run,
        thread,
        call,
        attempt,
        lease,
        cancelled,
        history_closed: false,
    })
}

async fn cancellation(
    tx: &Transaction<'_>,
    run: &str,
    thread: &str,
    actor: &str,
) -> Result<bool, Error> {
    let Some(row) = tx.query_opt("SELECT aggregate_kind,aggregate_id,seq,destination,delivery_class,payload,status FROM public.outbox WHERE outbox_id=$1",
        &[&run_cancel_outbox_id(run)]).await.map_err(db)? else { return Ok(false); };
    require(
        get::<&str>(&row, "aggregate_kind")? == "run"
            && get::<&str>(&row, "aggregate_id")? == run
            && get::<i64>(&row, "seq")? == 0
            && get::<&str>(&row, "destination")? == RUN_CANCEL_DESTINATION
            && get::<&str>(&row, "delivery_class")? == "internal"
            // The one acceptance of the Run is lawful in exactly two shapes: this actor's own
            // request, or the system stop of a closed Thread history. Both fence a fresh effect.
            && match run_cancel_acceptance(
                &get::<serde_json::Value>(&row, "payload")?,
                run,
                thread,
            ) {
                Some(RunCancelAcceptance::Actor(requested_by)) => requested_by == actor,
                Some(RunCancelAcceptance::ThreadHistoryClosed { .. }) => true,
                None => false,
            }
            && matches!(
                get::<&str>(&row, "status")?,
                "pending" | "delivering" | "delivered" | "dead_letter"
            ),
    )?;
    Ok(true)
}

pub(super) async fn admit(
    tx: &Transaction<'_>,
    r: &RememberToolMemoryRequest,
) -> Result<Locked, Error> {
    tx.batch_execute("SET LOCAL lock_timeout='5s'")
        .await
        .map_err(db)?;
    // One strict schema observation before this transaction's first row lock.
    let schema = CurrentWriterSchema::observe(tx)
        .await
        .map_err(history_error)?;
    let generation = number(r.auth_generation().get())?;
    // First business row lock; direct UPDATE mode also serializes default-enabled control absence.
    if tx
        .query_opt(
            "SELECT u.id FROM public.users u WHERE u.id=$1 FOR UPDATE OF u",
            &[&r.actor().as_str()],
        )
        .await
        .map_err(db)?
        .is_none()
    {
        return Err(Error::NotVisible);
    }
    // After any actor-lock wait, a new RC statement observes committed role/deny changes.
    // Preserve the tool's user/admin rule and check it before historical receipt observation.
    if tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin')) AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))",
        &[&r.actor().as_str(),&generation]).await.map_err(db)?.is_none() { return Err(Error::NotVisible); }
    let mut locked = lock_original(
        tx,
        r.actor().as_str(),
        r.run().as_str(),
        r.call().as_str(),
        r.attempt().as_str(),
        true,
    )
    .await?;
    require(
        get::<&str>(&locked.run, "thread_id")? == r.thread().as_str()
            && get::<&str>(&locked.run, "bot_id")? == r.bot().as_str()
            && get::<&str>(&locked.thread, "deployment_id")? == r.deployment().as_str()
            && get::<&str>(&locked.thread, "tenant_id")? == r.tenant().as_str()
            && get::<&str>(&locked.call, "decision_id")? == r.decision().as_str()
            && get::<&str>(&locked.call, "args_hash")? == r.args_hash().to_hex()
            && get::<&str>(&locked.call, "schema_hash")? == r.schema_hash().to_hex()
            && get::<i64>(&locked.call, "catalog_generation")?
                == number(r.catalog_generation().get())?
            && get::<&str>(&locked.call, "target_kind")? == r.target().kind
            && get::<&str>(&locked.call, "target_id")? == r.target().id
            && get::<Option<&str>>(&locked.attempt, "capability_id")?
                == Some(r.capability().as_str()),
    )?;
    let expected = match r.arguments().scope() {
        RememberToolScope::User => ("memory_user", r.actor().as_str()),
        RememberToolScope::Bot => ("memory_bot", r.bot().as_str()),
        RememberToolScope::Thread => ("memory_thread", r.thread().as_str()),
    };
    require((r.target().kind, r.target().id.as_str()) == expected)?;
    for id in [
        r.deployment().as_str(),
        r.tenant().as_str(),
        r.thread().as_str(),
        r.run().as_str(),
        r.actor().as_str(),
        r.bot().as_str(),
        r.call().as_str(),
        r.attempt().as_str(),
        r.decision().as_str(),
        r.capability().as_str(),
        r.target().id.as_str(),
    ] {
        require(valid_reconciliation_id(id))?;
    }
    // All audit identifier failures are discovered before the first business INSERT.
    for id in [
        r.bot().as_str(),
        r.attempt().as_str(),
        r.decision().as_str(),
    ] {
        AuditIdentifier::new(id).map_err(|_| corrupt())?;
    }
    visibility(tx, r, &locked).await?;
    // H SHARE after every existing authority lock, held to the transaction's natural end. Closed
    // is recorded, not refused here: only a new effect is refused, never an exact replay.
    locked.history_closed = schema
        .lock_thread_write_disposition(tx, r.thread())
        .await
        .map_err(history_error)?
        == OpenOrClosed::Closed;
    Ok(locked)
}

async fn package(tx: &Transaction<'_>, id: Option<String>, tenant: &str) -> Result<(), Error> {
    if let Some(id) = id
        && tx
            .query_opt(
                "SELECT id FROM public.deployment_packages WHERE id::text=$1 AND tenant_id=$2 FOR SHARE NOWAIT",
                &[&id, &tenant],
            )
            .await
            .map_err(db)?
            .is_none()
    {
        return Err(Error::NotVisible);
    }
    Ok(())
}

async fn visibility(
    tx: &Transaction<'_>,
    r: &RememberToolMemoryRequest,
    locked: &Locked,
) -> Result<(), Error> {
    if get::<&str>(&locked.thread, "status")? == "deleted" {
        return Err(Error::NotVisible);
    }
    let bot = tx.query_opt("SELECT b.package_id::text AS package_id FROM public.agents b JOIN public.agent_profiles p ON p.agent_id=b.id WHERE b.id=$1 AND p.deleted_at IS NULL AND (p.visibility='public' OR p.owner_user_id=$2) FOR SHARE OF b,p NOWAIT",
        &[&r.bot().as_str(),&r.actor().as_str()]).await.map_err(db)?.ok_or(Error::NotVisible)?;
    package(tx, get(&bot, "package_id")?, r.tenant().as_str()).await?;
    let anchor: &str = get(&locked.thread, "anchor_id")?;
    match get::<&str>(&locked.thread,"anchor_kind")? {
        "direct_bot" => {
            if anchor != r.bot().as_str() || tx.query_opt("SELECT user_id FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2 FOR SHARE NOWAIT",&[&r.thread().as_str(),&r.actor().as_str()]).await.map_err(db)?.is_none() { return Err(Error::NotVisible); }
        }
        "channel" => {
            let channel = tx.query_opt("SELECT package_id::text AS package_id FROM public.channels WHERE id=$1 FOR SHARE NOWAIT",&[&anchor]).await.map_err(db)?.ok_or(Error::NotVisible)?;
            package(tx,get(&channel,"package_id")?,r.tenant().as_str()).await?;
            if tx.query_opt("SELECT cm.user_id FROM public.channel_memberships cm JOIN public.channel_agents ca ON ca.channel_id=cm.channel_id WHERE cm.channel_id=$1 AND cm.user_id=$2 AND ca.agent_id=$3 FOR SHARE OF cm,ca NOWAIT",&[&anchor,&r.actor().as_str(),&r.bot().as_str()]).await.map_err(db)?.is_none() { return Err(Error::NotVisible); }
        }
        _ => return Err(corrupt()),
    }
    Ok(())
}

fn matches_snapshot(s: &remember_effect_receipts::Row, l: &Locked) -> Result<bool, Error> {
    Ok(s.run_id == get::<&str>(&l.run, "run_id")?
        && s.thread_id == get::<&str>(&l.run, "thread_id")?
        && s.actor_id == get::<&str>(&l.run, "actor_id")?
        && s.bot_id == get::<&str>(&l.run, "bot_id")?
        && s.deployment_id == get::<&str>(&l.thread, "deployment_id")?
        && s.tenant_id == get::<&str>(&l.thread, "tenant_id")?
        && s.tool_call_id == get::<&str>(&l.call, "tool_call_id")?
        && s.call_seq == get::<i64>(&l.call, "call_seq")?
        && s.attempt_id == get::<&str>(&l.attempt, "attempt_id")?
        && s.attempt_seq == get::<i64>(&l.attempt, "attempt_seq")?
        && s.decision_id == get::<&str>(&l.call, "decision_id")?
        && Some(s.capability_id.as_str()) == get::<Option<&str>>(&l.attempt, "capability_id")?
        && s.args_hash == get::<&str>(&l.call, "args_hash")?
        && s.schema_hash == get::<&str>(&l.call, "schema_hash")?
        && s.catalog_generation == get::<i64>(&l.call, "catalog_generation")?
        && s.target_kind == get::<&str>(&l.call, "target_kind")?
        && s.target_id == get::<&str>(&l.call, "target_id")?
        && s.memory_event_seq == 0)
}

async fn receipt(
    tx: &Transaction<'_>,
    attempt: &str,
) -> Result<Option<remember_effect_receipts::Row>, Error> {
    tx.query_opt(
        "SELECT * FROM public.remember_effect_receipts WHERE attempt_id=$1",
        &[&attempt],
    )
    .await
    .map_err(db)?
    .as_ref()
    .map(remember_effect_receipts::Row::try_from)
    .transpose()
    .map_err(|_| corrupt())
}

pub(super) async fn existing(
    tx: &Transaction<'_>,
    r: &RememberToolMemoryRequest,
    locked: &Locked,
) -> Result<Option<CommittedMemoryEffect>, Error> {
    let Some(s) = receipt(tx, r.attempt().as_str()).await? else {
        return Ok(None);
    };
    require(
        matches_snapshot(&s, locked)?
            && s.auth_generation == number(r.auth_generation().get())?
            && get::<Option<&str>>(&locked.attempt, "commit_state")? != Some("not_committed"),
    )?;
    Ok(Some(CommittedMemoryEffect {
        memory_id: s.memory_id,
        receipt_id: s.receipt_id,
    }))
}

pub(super) async fn append(
    tx: &Transaction<'_>,
    r: &RememberToolMemoryRequest,
    l: &Locked,
    memory: &str,
    key: &[u8],
) -> Result<CommittedMemoryEffect, Error> {
    let receipt_id = uuid::Uuid::now_v7().to_string();
    let payload = AuditPayload::from_facts([
        AuditFact::Bot(AuditIdentifier::new(r.bot().as_str()).map_err(|_| corrupt())?),
        AuditFact::DecisionId(AuditIdentifier::new(r.decision().as_str()).map_err(|_| corrupt())?),
        AuditFact::TargetKind(AuditLabel::new("memory_create")),
        AuditFact::TargetId(AuditIdentifier::new(memory).map_err(|_| corrupt())?),
        AuditFact::CommitState(AuditLabel::new("committed")),
        AuditFact::ToolAttemptId(
            AuditIdentifier::new(r.attempt().as_str()).map_err(|_| corrupt())?,
        ),
        AuditFact::MemoryEventSequence(0),
    ])
    .map_err(|_| corrupt())?;
    let (audit_id, now) = next_event_coordinates(tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    let audit = AuditEvent {
        id: audit_id.clone(),
        actor: Some(r.actor().clone()),
        event_type: AuditEventType::MEMORY_EFFECT_COMMITTED,
        target_kind: AuditLabel::new("memory_effect_receipt"),
        target_id: Some(AuditIdentifier::new(&receipt_id).map_err(|_| corrupt())?),
        payload,
        created_at: now,
    };
    append_event_in_transaction(tx, &audit, key)
        .await
        .map_err(|_| Error::Unavailable)?;
    let row = remember_effect_receipts::Row {
        receipt_id: receipt_id.clone(),
        deployment_id: r.deployment().as_str().to_owned(),
        tenant_id: r.tenant().as_str().to_owned(),
        thread_id: r.thread().as_str().to_owned(),
        run_id: r.run().as_str().to_owned(),
        actor_id: r.actor().as_str().to_owned(),
        bot_id: r.bot().as_str().to_owned(),
        auth_generation: number(r.auth_generation().get())?,
        tool_call_id: r.call().as_str().to_owned(),
        call_seq: get(&l.call, "call_seq")?,
        attempt_id: r.attempt().as_str().to_owned(),
        attempt_seq: get(&l.attempt, "attempt_seq")?,
        decision_id: r.decision().as_str().to_owned(),
        capability_id: r.capability().as_str().to_owned(),
        args_hash: r.args_hash().to_hex(),
        schema_hash: r.schema_hash().to_hex(),
        catalog_generation: number(r.catalog_generation().get())?,
        target_kind: r.target().kind.to_owned(),
        target_id: r.target().id.clone(),
        memory_id: memory.to_owned(),
        memory_event_seq: 0,
        audit_event_id: audit_id.as_str().to_owned(),
        recorded_at: now,
    };
    tx.query_one(
        &insert_sql::<remember_effect_receipts::Row>(),
        &row.as_sql_params(),
    )
    .await
    .map_err(db)?;
    Ok(CommittedMemoryEffect {
        memory_id: memory.to_owned(),
        receipt_id,
    })
}

/// Keep an already committed remember effect from being overwritten by a late or contradictory
/// ordinary outcome. This is a fence, not a disposition or an authority to resume the old run.
pub(crate) async fn guard_outcome(
    tx: &Transaction<'_>,
    d: &ToolOutcomeDraft,
) -> Result<i64, ToolPortError> {
    let result = async {
        tx.batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(db)?;
        if tx
            .query_opt(
                "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
                &[&d.decision.actor.as_str()],
            )
            .await
            .map_err(db)?
            .is_none()
        {
            return Err(Error::NotVisible);
        }
        let l = lock_original(
            tx,
            d.decision.actor.as_str(),
            d.decision.run_id.as_str(),
            d.decision.call_id.as_str(),
            d.receipt.attempt().as_str(),
            false,
        )
        .await?;
        require(
            get::<&str>(&l.run, "bot_id")? == d.decision.bot.as_str()
                && get::<&str>(&l.call, "decision_id")? == d.receipt.decision().as_str()
                && get::<i64>(&l.call, "call_seq")? == number(d.decision.call_seq)?
                && get::<&str>(&l.call, "args_hash")? == d.decision.args_hash.to_hex()
                && get::<&str>(&l.call, "schema_hash")? == d.decision.metadata.schema_hash.to_hex()
                && get::<i64>(&l.call, "catalog_generation")?
                    == number(d.decision.metadata.catalog_generation.get())?
                && get::<&str>(&l.call, "target_kind")? == d.decision.target.kind
                && get::<&str>(&l.call, "target_id")? == d.decision.target.id
                && get::<Option<&str>>(&l.attempt, "capability_id")?
                    == Some(d.capability_id.as_str()),
        )?;
        if get::<&str>(&l.run, "status")? != "running" {
            return Err(Error::Conflict);
        }
        // Lock acquisition above may have waited for a producer. This next statement sees its commit.
        if let Some(s) = receipt(tx, d.receipt.attempt().as_str()).await? {
            require(matches_snapshot(&s, &l)?)?;
            if d.outcome.commit_state == CommitState::NotCommitted {
                return Err(Error::Conflict);
            }
        }
        get(&l.attempt, "attempt_seq")
    }
    .await;
    result.map_err(|e| match e {
        Error::Unavailable => ToolPortError::Unavailable {
            dependency: "database",
        },
        _ => ToolPortError::Conflict,
    })
}
