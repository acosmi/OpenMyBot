//! Trusted, bounded clearing of an already closed history. No Auth or Host grant is consumed.
//! Each batch keeps its original transaction owner; completion and its typed audit are atomic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{ArtifactRetentionClass, canonical_artifact_uuid_v7};
use openbot_contracts::ids::ActorId;
use openbot_contracts::ids::ThreadId;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{
    AuditFact, AuditIdentifier, AuditLabel, AuditPayload, AuditThreadHistoryClearCount,
    AuditThreadHistoryClearOperationId, AuditThreadHistoryClearSource,
};
use tokio_postgres::types::{FromSqlOwned, ToSql};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::{PostgresThreadHistoryAuthority, ThreadHistoryStopClearError};
use crate::db::InfraError;
use crate::db::pool::TransactionOwnerError;
use crate::repo::audit::{
    AUDIT_CHAIN_LOCK_KEY, append_event_in_transaction, next_event_coordinates,
};
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

type Error = ThreadHistoryStopClearError;

/// Closed provenance of the durable operation, not caller-supplied prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadHistoryClearSource {
    StopClear,
    Maintenance,
}

impl ThreadHistoryClearSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::StopClear => "stop_clear",
            Self::Maintenance => "maintenance",
        }
    }
    fn audit(self) -> AuditThreadHistoryClearSource {
        match self {
            Self::StopClear => AuditThreadHistoryClearSource::StopClear,
            Self::Maintenance => AuditThreadHistoryClearSource::Maintenance,
        }
    }
}

/// Only an acknowledged original terminal publishes progress. This is not a byte-erasure claim.
pub enum ThreadHistoryClearProgress {
    BatchCommitted { more: bool },
    AwaitingDrain,
    AwaitingReaders,
    Completed { operation_id: String },
}

impl core::fmt::Debug for ThreadHistoryClearProgress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BatchCommitted { more } => f
                .debug_struct("ThreadHistoryClearProgress::BatchCommitted")
                .field("more", more)
                .finish(),
            Self::AwaitingDrain => f.write_str("ThreadHistoryClearProgress::AwaitingDrain"),
            Self::AwaitingReaders => f.write_str("ThreadHistoryClearProgress::AwaitingReaders"),
            Self::Completed { .. } => {
                f.write_str("ThreadHistoryClearProgress::Completed(<operation-redacted>)")
            }
        }
    }
}

const MAX_BATCHES: usize = 64;
const ROW_LIMIT: usize = 128;
pub(super) const MAINTENANCE_ACTOR: &str = "system:thread-history-clear";

const BINDING: &str = r"SELECT h.closure_operation_id AS operation_id,q.actor_id,q.intent_kind,
    q.auth_generation,
    ROW(h.deployment_id,h.tenant_id,h.thread_id,h.anchor_kind,h.anchor_id,h.thread_created_at,
        h.closure_request_id,h.closure_actor_id,h.closure_auth_generation,h.closed_at)
    IS NOT DISTINCT FROM ROW(q.deployment_id,q.tenant_id,q.thread_id,q.anchor_kind,q.anchor_id,
        q.thread_created_at,q.request_id,q.actor_id,q.auth_generation,q.recorded_at)
    AND ROW(t.deployment_id,t.tenant_id,t.thread_id,t.anchor_kind,t.anchor_id,t.created_at)
    IS NOT DISTINCT FROM ROW(h.deployment_id,h.tenant_id,h.thread_id,h.anchor_kind,h.anchor_id,
        h.thread_created_at) AND q.intent_schema=1 AS bound,
    c.operation_id IS NOT NULL AS completed,
    (c.completion_schema=1 AND c.deployment_id=h.deployment_id AND c.tenant_id=h.tenant_id
     AND c.thread_id=h.thread_id AND c.source=CASE q.intent_kind
        WHEN 'stop_clear' THEN 'stop_clear' WHEN 'maintenance_clear' THEN 'maintenance' END
     AND c.batches>=1 AND c.run_output_expired=0) AS completion_bound
    FROM openbot_internal.thread_history_heads h
    JOIN openbot_internal.thread_history_clear_intents q ON q.operation_id=h.closure_operation_id
    JOIN public.threads t ON t.thread_id=h.thread_id
    LEFT JOIN openbot_internal.thread_history_clear_completions c
      ON c.operation_id=h.closure_operation_id
    WHERE h.deployment_id=$1 AND h.tenant_id=$2 AND h.thread_id=$3 AND h.phase='closed'";
const INSERT_BATCH: &str = r"INSERT INTO openbot_internal.thread_history_clear_batches
    (operation_id,batch_seq,threads_cleared,messages_cleared,run_events_cleared,
     tool_approvals_cleared,component_decisions_cleared,remote_interrupts_cleared,
     channel_sources_cleared,channels_cleared,memories_cleared,run_output_expired)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0)";
const INSERT_COMPLETION: &str = r"INSERT INTO openbot_internal.thread_history_clear_completions
    (operation_id,deployment_id,tenant_id,thread_id,completion_schema,source,batches,
     threads_cleared,messages_cleared,run_events_cleared,tool_approvals_cleared,
     component_decisions_cleared,remote_interrupts_cleared,channel_sources_cleared,
     channels_cleared,memories_cleared,run_output_expired)
    SELECT $1,$2,$3,$4,1,$5,count(*)::bigint,
     coalesce(sum(threads_cleared),0)::bigint,coalesce(sum(messages_cleared),0)::bigint,
     coalesce(sum(run_events_cleared),0)::bigint,coalesce(sum(tool_approvals_cleared),0)::bigint,
     coalesce(sum(component_decisions_cleared),0)::bigint,
     coalesce(sum(remote_interrupts_cleared),0)::bigint,
     coalesce(sum(channel_sources_cleared),0)::bigint,coalesce(sum(channels_cleared),0)::bigint,
     coalesce(sum(memories_cleared),0)::bigint,0
    FROM openbot_internal.thread_history_clear_batches WHERE operation_id=$1
    RETURNING batches,threads_cleared,messages_cleared,run_events_cleared,tool_approvals_cleared,
     component_decisions_cleared,remote_interrupts_cleared,channel_sources_cleared,
     channels_cleared,memories_cleared,run_output_expired";

struct Binding {
    operation_id: String,
    actor: String,
    source: ThreadHistoryClearSource,
    completed: bool,
}

enum Decision {
    Batch { more: bool },
    Complete(String),
    ExistingComplete(String),
    AwaitingDrain,
    AwaitingReaders,
}

impl PostgresThreadHistoryAuthority {
    /// Close only an actually soft-deleted base for trusted maintenance. This is an
    /// internal system entry: it creates no user, role, Auth context or Host grant.
    ///
    /// The original caller deadline is capped once at five seconds. A newly stored
    /// maintenance intent publishes only after the original COMMIT ACK. A history
    /// already closed by either lawful source keeps that exact operation and source
    /// and is reused only after the original ROLLBACK ACK. This does not drain,
    /// clear, publish completion or claim ACK2; those remain separate steps.
    ///
    /// # Errors
    /// Malformed identity is InvalidInput; a missing, foreign or non-deleted base
    /// is NotVisible; a broken base/head/intent binding is Corrupt. NOWAIT contention
    /// stays Unavailable, with every original owner acknowledgement result retained.
    pub async fn close_deleted_history_before(
        self: &Arc<Self>,
        thread_id: &str,
        original_deadline: Instant,
    ) -> Result<(), Error> {
        let thread = ThreadId::new(thread_id);
        if thread_id.len() != 36 || !ThreadIdentity::is_plausible(&thread) {
            return Err(Error::InvalidInput { field: "thread_id" });
        }
        let deadline = transaction_deadline(original_deadline)?;
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| Error::Unavailable)?;
        let original = client.begin_read_committed().await.map_err(owner_error)?;
        let result = self
            .close_deleted_original(original.as_transaction(), &thread, deadline)
            .await;
        match result {
            Ok(true) => original.commit().await.map_err(owner_error)?,
            Ok(false) => original.rollback().await.map_err(owner_error)?,
            Err(error) => {
                original.rollback().await.map_err(owner_error)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// True only for this transaction's new Q/H write; false is an existing, verified
    /// closed pair. The schema proof precedes the first row lock and is consumed once
    /// on this original transaction. The existing lock_joint performs 0050 lazy H
    /// registration and its complete physical base/head/intent verification.
    async fn close_deleted_original(
        &self,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<bool, Error> {
        set_timeouts(tx, deadline).await?;
        let schema = bounded(deadline, CurrentWriterSchema::observe(tx))
            .await?
            .map_err(schema_error)?;
        // This exclusive NOWAIT lock serializes maintenance of this deleted base;
        // it is not creator eligibility or a right to act on a live Thread.
        let base = rows(
            tx,
            deadline,
            "SELECT t.thread_id FROM public.threads t \
             WHERE t.thread_id=$3 AND t.deployment_id=$1 AND t.tenant_id=$2 \
               AND t.status='deleted' AND t.deleted_at IS NOT NULL FOR UPDATE OF t NOWAIT",
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
            ],
        )
        .await?;
        if base.is_empty() {
            return Err(Error::NotVisible);
        }
        if base.len() != 1 {
            return Err(corrupt("history_binding"));
        }
        let disposition = bounded(deadline, schema.lock_thread_write_disposition(tx, thread))
            .await?
            .map_err(writer_error)?;
        let heads = rows(
            tx,
            deadline,
            "SELECT h.phase FROM openbot_internal.thread_history_heads h \
             WHERE h.deployment_id=$1 AND h.tenant_id=$2 AND h.thread_id=$3 \
             FOR UPDATE OF h NOWAIT",
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
            ],
        )
        .await?;
        let [head] = heads.as_slice() else {
            return Err(corrupt("history_binding"));
        };
        match (disposition, column::<String>(head, "phase")?.as_str()) {
            (OpenOrClosed::Closed, "closed") => {
                // Validate the exact stored source without relabelling an original
                // stop_clear as maintenance or trying to create a second Q.
                self.clear_binding(tx, thread, deadline).await?;
                return Ok(false);
            }
            (OpenOrClosed::Open, "open") => {}
            _ => return Err(corrupt("history_binding")),
        }
        if !rows(
            tx,
            deadline,
            "SELECT operation_id FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1",
            &[&thread.as_str()],
        )
        .await?
        .is_empty()
        {
            return Err(corrupt("history_binding"));
        }
        let operation_id = Uuid::now_v7().to_string();
        let request_id = Uuid::now_v7().to_string();
        if canonical_artifact_uuid_v7(&operation_id).as_deref() != Some(operation_id.as_str())
            || canonical_artifact_uuid_v7(&request_id).as_deref() != Some(request_id.as_str())
        {
            return Err(corrupt("operation_id"));
        }
        // Every Q identity is copied from the locked original H. Only the two new
        // canonical operation identifiers and reserved system source are supplied.
        let inserted = execute(
            tx,
            deadline,
            "INSERT INTO openbot_internal.thread_history_clear_intents \
             (deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,\
              actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at) \
             SELECT h.deployment_id,h.tenant_id,h.thread_id,1,'maintenance_clear',$4,$5,$6,0,\
              h.anchor_kind,h.anchor_id,h.thread_created_at \
             FROM openbot_internal.thread_history_heads h \
             WHERE h.deployment_id=$1 AND h.tenant_id=$2 AND h.thread_id=$3 AND h.phase='open'",
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
                &operation_id,
                &request_id,
                &MAINTENANCE_ACTOR,
            ],
        )
        .await?;
        if inserted != 1 {
            return Err(corrupt("history_binding"));
        }
        let closed = execute(
            tx,
            deadline,
            "UPDATE openbot_internal.thread_history_heads h SET phase='closed',\
              closure_operation_id=q.operation_id,closure_request_id=q.request_id,\
              closure_actor_id=q.actor_id,closure_auth_generation=q.auth_generation,\
              closed_at=q.recorded_at \
             FROM openbot_internal.thread_history_clear_intents q \
             WHERE q.operation_id=$4 AND q.intent_kind='maintenance_clear' AND q.actor_id=$5 \
              AND q.auth_generation=0 AND h.deployment_id=q.deployment_id AND h.tenant_id=q.tenant_id \
              AND h.thread_id=q.thread_id AND h.deployment_id=$1 AND h.tenant_id=$2 \
              AND h.thread_id=$3 AND h.phase='open'",
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
                &operation_id,
                &MAINTENANCE_ACTOR,
            ],
        )
        .await?;
        if closed != 1 {
            return Err(corrupt("history_binding"));
        }
        settle(tx, deadline).await?;
        let bound = self.clear_binding(tx, thread, deadline).await?;
        if bound.operation_id != operation_id
            || bound.actor != MAINTENANCE_ACTOR
            || bound.source != ThreadHistoryClearSource::Maintenance
            || bound.completed
        {
            return Err(corrupt("history_binding"));
        }
        Ok(true)
    }

    /// Clear one closed J in at most 64 bounded batches, retaining every committed batch on error.
    /// The caller may explicitly resume; database contention is never retried inside this call.
    ///
    /// # Errors
    /// Refuses malformed identity, unknown binding, contention, corruption and unproven or late
    /// original transaction ACKs using the existing stop/clear closed error vocabulary.
    pub async fn clear_closed_history_before(
        self: &Arc<Self>,
        thread_id: &str,
        original_deadline: Instant,
    ) -> Result<ThreadHistoryClearProgress, Error> {
        let thread = ThreadId::new(thread_id);
        if thread_id.len() != 36 || !ThreadIdentity::is_plausible(&thread) {
            return Err(Error::InvalidInput { field: "thread_id" });
        }
        self.clear_checkpoint_key()?;
        let mut committed = 0;
        loop {
            let deadline = transaction_deadline(original_deadline)?;
            let mut client = self
                .pool
                .get_guarded(deadline)
                .await
                .map_err(|_| Error::Unavailable)?;
            let original = client.begin_read_committed().await.map_err(owner_error)?;
            let result = self
                .clear_original(original.as_transaction(), &thread, deadline)
                .await;
            let decision = match result {
                Ok(decision) => decision,
                Err(error) => {
                    original.rollback().await.map_err(owner_error)?;
                    return Err(error);
                }
            };
            match decision {
                Decision::Batch { more } => {
                    original.commit().await.map_err(owner_error)?;
                    committed += 1;
                    if committed == MAX_BATCHES {
                        return Ok(ThreadHistoryClearProgress::BatchCommitted { more });
                    }
                    // A new original transaction observes the immutable last batch and barrier.
                }
                Decision::Complete(operation_id) => {
                    original.commit().await.map_err(owner_error)?;
                    return Ok(ThreadHistoryClearProgress::Completed { operation_id });
                }
                Decision::ExistingComplete(operation_id) => {
                    original.rollback().await.map_err(owner_error)?;
                    return Ok(ThreadHistoryClearProgress::Completed { operation_id });
                }
                Decision::AwaitingDrain => {
                    original.rollback().await.map_err(owner_error)?;
                    return Ok(ThreadHistoryClearProgress::AwaitingDrain);
                }
                Decision::AwaitingReaders => {
                    original.rollback().await.map_err(owner_error)?;
                    return Ok(ThreadHistoryClearProgress::AwaitingReaders);
                }
            }
        }
    }

    async fn clear_original(
        &self,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<Decision, Error> {
        set_timeouts(tx, deadline).await?;
        // Complete current prefix/origin/writer observation, once and before any row lock.
        let schema = bounded(deadline, CurrentWriterSchema::observe(tx))
            .await?
            .map_err(schema_error)?;
        let binding = self.clear_binding(tx, thread, deadline).await?;
        // Q is immutable metadata, but its NOWAIT row lock serializes this operation's batch
        // sequence/count preselection with other batches and completion, without a new wait edge.
        let locked = rows(tx, deadline,
            "SELECT q.operation_id FROM openbot_internal.thread_history_clear_intents q JOIN openbot_internal.thread_history_heads h ON h.closure_operation_id=q.operation_id WHERE q.deployment_id=$1 AND q.tenant_id=$2 AND q.thread_id=$3 AND q.operation_id=$4 AND h.deployment_id=q.deployment_id AND h.tenant_id=q.tenant_id AND h.thread_id=q.thread_id AND h.phase='closed' FOR UPDATE OF q NOWAIT",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&thread.as_str(),&binding.operation_id]).await?;
        if locked.len() != 1 {
            return Err(corrupt("history_binding"));
        }
        if binding.completed {
            return Ok(Decision::ExistingComplete(binding.operation_id));
        }
        if has_live_runs(tx, thread, deadline).await? {
            return Ok(Decision::AwaitingDrain);
        }
        let erased = bodies_erased(tx, &binding.operation_id, deadline).await?;
        let count = one(tx, deadline,
            "SELECT count(*)::bigint AS batches FROM openbot_internal.thread_history_clear_batches WHERE operation_id=$1",
            &[&binding.operation_id]).await?;
        let batches: i64 = column(&count, "batches")?;
        if batches < 0 {
            return Err(corrupt("clear_batch_count"));
        }
        if erased && batches > 0 {
            return self
                .clear_completion(tx, &schema, thread, binding, deadline)
                .await;
        }
        let selection = select_batch(tx, thread, self.tenant.as_str(), deadline).await?;
        if selection.counts.total() == 0 && !erased {
            return Err(corrupt("clear_body_remaining"));
        }
        let next = one(tx, deadline,
            "SELECT coalesce(max(batch_seq),0)+1 AS next_seq FROM openbot_internal.thread_history_clear_batches WHERE operation_id=$1",
            &[&binding.operation_id]).await?;
        let sequence: i64 = column(&next, "next_seq")?;
        if sequence < 1 {
            return Err(corrupt("clear_batch_sequence"));
        }
        let counts = &selection.counts;
        if execute(
            tx,
            deadline,
            INSERT_BATCH,
            &[
                &binding.operation_id,
                &sequence,
                &counts.threads,
                &counts.messages,
                &counts.run_events,
                &counts.tool_approvals,
                &counts.component_decisions,
                &counts.remote_interrupts,
                &counts.channel_sources,
                &counts.channels,
                &counts.memories,
            ],
        )
        .await?
            != 1
        {
            return Err(corrupt("clear_batch_insert"));
        }
        // INSERT's checked guard already holds H SHARE NOWAIT. Consume the exact earlier schema
        // proof on this original transaction, checking the complete physical closed joint.
        require_closed(&schema, tx, thread, deadline).await?;
        for selected in selection.tables {
            apply_table(tx, thread, &binding.actor, selected, deadline).await?;
        }
        settle(tx, deadline).await?;
        Ok(Decision::Batch {
            more: !bodies_erased(tx, &binding.operation_id, deadline).await?,
        })
    }

    async fn clear_binding(
        &self,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<Binding, Error> {
        let found = rows(
            tx,
            deadline,
            BINDING,
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
            ],
        )
        .await?;
        let [row] = found.as_slice() else {
            return Err(if found.is_empty() {
                Error::NotVisible
            } else {
                corrupt("history_binding")
            });
        };
        if !column::<bool>(row, "bound")? {
            return Err(corrupt("history_binding"));
        }
        let operation_id: String = column(row, "operation_id")?;
        if canonical_artifact_uuid_v7(&operation_id).as_deref() != Some(operation_id.as_str()) {
            return Err(corrupt("operation_id"));
        }
        let actor: String = column(row, "actor_id")?;
        if !openbot_contracts::artifacts::is_valid_artifact_identity(&actor) {
            return Err(corrupt("actor_id"));
        }
        let source = match column::<String>(row, "intent_kind")?.as_str() {
            "stop_clear" => ThreadHistoryClearSource::StopClear,
            "maintenance_clear"
                if actor == MAINTENANCE_ACTOR && column::<i64>(row, "auth_generation")? == 0 =>
            {
                ThreadHistoryClearSource::Maintenance
            }
            _ => return Err(corrupt("history_binding")),
        };
        let completed = column::<bool>(row, "completed")?;
        if completed && column::<Option<bool>>(row, "completion_bound")? != Some(true) {
            return Err(corrupt("clear_completion_binding"));
        }
        Ok(Binding {
            operation_id,
            actor,
            source,
            completed,
        })
    }

    async fn clear_completion(
        &self,
        tx: &Transaction<'_>,
        schema: &CurrentWriterSchema<'_, '_>,
        thread: &ThreadId,
        binding: Binding,
        deadline: Instant,
    ) -> Result<Decision, Error> {
        // Exclusive H NOWAIT prevents a later batch passing our completion snapshot.
        let locked = rows(tx, deadline,
            "SELECT thread_id FROM openbot_internal.thread_history_heads WHERE deployment_id=$1 AND tenant_id=$2 AND thread_id=$3 AND phase='closed' AND closure_operation_id=$4 FOR UPDATE NOWAIT",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&thread.as_str(),&binding.operation_id]).await?;
        if locked.len() != 1 {
            return Err(corrupt("history_binding"));
        }
        require_closed(schema, tx, thread, deadline).await?;
        // Separate RC statements after the possible pre-lock race, not a stale pre-lock answer.
        let fresh = self.clear_binding(tx, thread, deadline).await?;
        if fresh.operation_id != binding.operation_id {
            return Err(corrupt("history_binding"));
        }
        if fresh.completed {
            return Ok(Decision::ExistingComplete(fresh.operation_id));
        }
        if has_live_runs(tx, thread, deadline).await? {
            return Ok(Decision::AwaitingDrain);
        }
        if !bodies_erased(tx, &binding.operation_id, deadline).await? {
            return Err(corrupt("clear_body_remaining"));
        }
        assert_run_output_noop(tx, thread, deadline).await?;
        let readers = one(
            tx,
            deadline,
            "SELECT openbot_internal.thread_history_clear_readers_quiescent($1) AS quiescent",
            &[&binding.operation_id],
        )
        .await?;
        if !column::<bool>(&readers, "quiescent")? {
            return Ok(Decision::AwaitingReaders);
        }
        let completion = one(
            tx,
            deadline,
            INSERT_COMPLETION,
            &[
                &binding.operation_id,
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
                &binding.source.as_str(),
            ],
        )
        .await?;
        let counts = ClearCounts::from_row(&completion)?;
        let batches = audit_count(column::<i64>(&completion, "batches")?)?;
        if batches.get() == 0 || column::<i64>(&completion, "run_output_expired")? != 0 {
            return Err(corrupt("clear_completion_count"));
        }
        let payload = counts.audit(&binding, batches)?;
        // Try the original audit lock and tail NOWAIT before the existing chain helpers. Their
        // advisory acquisition and tail lock are reentrant on our already-held original locks.
        let audit_lock = one(
            tx,
            deadline,
            "SELECT pg_try_advisory_xact_lock($1) AS acquired",
            &[&AUDIT_CHAIN_LOCK_KEY],
        )
        .await?;
        if !column::<bool>(&audit_lock, "acquired")? {
            return Err(Error::Unavailable);
        }
        rows(tx, deadline,"SELECT id FROM public.audit_events ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE NOWAIT",&[]).await?;
        let (id, created_at) = bounded(deadline, next_event_coordinates(tx))
            .await?
            .map_err(schema_error)?;
        let event = AuditEvent {
            id,
            actor: match binding.source {
                ThreadHistoryClearSource::StopClear => Some(ActorId::new(binding.actor.as_str())),
                ThreadHistoryClearSource::Maintenance => None,
            },
            event_type: AuditEventType::THREAD_HISTORY_CLEAR_COMPLETED,
            target_kind: AuditLabel::new("thread_history"),
            target_id: Some(
                AuditIdentifier::new(thread.as_str()).map_err(|_| corrupt("thread_id"))?,
            ),
            payload,
            created_at,
        };
        bounded(
            deadline,
            append_event_in_transaction(tx, &event, self.clear_checkpoint_key()?),
        )
        .await?
        .map_err(schema_error)?;
        // Force all completion and original writer deferred checks before COMMIT. A database
        // rejection here is known; the guarded COMMIT still owns any later unknown ACK.
        match bounded(deadline, tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")).await? {
            Ok(()) => {}
            Err(error) => {
                if let Some(waiting) = completion_wait(&error) {
                    return Ok(waiting);
                }
                return Err(statement_error(error));
            }
        }
        Ok(Decision::Complete(binding.operation_id))
    }
}

#[derive(Clone, Copy)]
enum ClearTable {
    ChannelSources,
    Channels,
    Threads,
    Messages,
    RunEvents,
    ToolApprovals,
    ComponentDecisions,
    RemoteInterrupts,
    Memories,
}

impl ClearTable {
    const ALL: [Self; 9] = [
        Self::ChannelSources,
        Self::Channels,
        Self::Threads,
        Self::Messages,
        Self::RunEvents,
        Self::ToolApprovals,
        Self::ComponentDecisions,
        Self::RemoteInterrupts,
        Self::Memories,
    ];
    fn table(self) -> &'static str {
        match self {
            Self::ChannelSources => "openbot_internal.channel_history_sources",
            Self::Channels => "public.channels",
            Self::Threads => "public.threads",
            Self::Messages => "public.messages",
            Self::RunEvents => "public.run_events",
            Self::ToolApprovals => "public.tool_approvals",
            Self::ComponentDecisions => "public.component_human_decisions",
            Self::RemoteInterrupts => "public.remote_agent_interrupts",
            Self::Memories => "public.memories",
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::ChannelSources => "e.channel_id",
            Self::Channels => "e.id",
            Self::Threads => "e.thread_id",
            Self::Messages => "e.message_id",
            Self::RunEvents => "e.event_seq",
            Self::ToolApprovals => "e.approval_id",
            Self::ComponentDecisions => "e.decision_id",
            Self::RemoteInterrupts => "e.request_id",
            Self::Memories => "e.memory_id",
        }
    }
    fn order(self) -> &'static str {
        match self {
            Self::RunEvents => "e.run_id,e.seq",
            _ => self.key(),
        }
    }
    fn joins(self) -> &'static str {
        match self {
            Self::RunEvents => {
                " JOIN public.runs r ON r.run_id=e.run_id AND r.thread_id=e.thread_id"
            }
            Self::Channels => {
                " JOIN openbot_internal.thread_history_heads h ON h.anchor_kind='channel' AND h.anchor_id=e.id AND h.thread_id=$1"
            }
            _ => "",
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::Channels => "h.thread_id=$1",
            Self::Memories => "e.scope_kind='thread' AND e.scope_id=$1",
            _ => "e.thread_id=$1",
        }
    }
    fn pending(self) -> &'static str {
        match self {
            Self::ChannelSources => "true",
            Self::Channels => {
                "NOT EXISTS(SELECT 1 FROM openbot_internal.channel_history_sources s WHERE s.channel_id=e.id AND s.thread_id<>$1) AND ROW(e.last_message,e.last_message_at,e.last_message_agent_id) IS DISTINCT FROM ROW(NULL::text,NULL::timestamptz,NULL::text)"
            }
            Self::Threads => "e.title IS NOT NULL",
            Self::Messages => {
                "(e.content IS DISTINCT FROM '{\"text\":\"\",\"retained\":false}'::jsonb OR e.search_text IS DISTINCT FROM '')"
            }
            Self::RunEvents => {
                "e.payload IS DISTINCT FROM openbot_internal.thread_history_clear_event_payload(e.event_type,e.payload,r.error_code)"
            }
            Self::ToolApprovals => {
                "(e.arguments_summary IS NOT NULL OR e.change_summary IS NOT NULL OR e.state='pending')"
            }
            Self::ComponentDecisions => {
                "(e.arguments IS DISTINCT FROM '{\"retained\":false}'::jsonb OR (e.state='answered' AND e.answer IS DISTINCT FROM '{\"retained\":false}'::jsonb) OR (e.state<>'answered' AND e.answer IS NOT NULL))"
            }
            Self::RemoteInterrupts => {
                "(e.state<>'retired' OR e.descriptor IS NOT NULL OR e.response_payload IS NOT NULL)"
            }
            Self::Memories => "(e.status IS DISTINCT FROM 'deleted' OR e.content IS NOT NULL)",
        }
    }
    fn update(self) -> &'static str {
        match self {
            Self::ChannelSources => "",
            Self::Channels => "last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL",
            Self::Threads => "title=NULL",
            Self::Messages => "content='{\"text\":\"\",\"retained\":false}'::jsonb,search_text=''",
            Self::RunEvents => {
                "payload=openbot_internal.thread_history_clear_event_payload(e.event_type,e.payload,r.error_code)"
            }
            Self::ToolApprovals => {
                "arguments_summary=NULL,change_summary=NULL,state=CASE WHEN e.state='pending' THEN 'cancelled' ELSE e.state END,decided_at=CASE WHEN e.state='pending' THEN clock_timestamp() ELSE e.decided_at END,decided_by=CASE WHEN e.state='pending' THEN NULL ELSE e.decided_by END"
            }
            Self::ComponentDecisions => {
                "arguments='{\"retained\":false}'::jsonb,answer=CASE WHEN e.state='answered' THEN '{\"retained\":false}'::jsonb ELSE NULL END"
            }
            Self::RemoteInterrupts => {
                "state='retired',descriptor=NULL,response_payload=NULL,resolved_at=coalesce(e.resolved_at,clock_timestamp()),resolved_by=NULL,resume_protocol_run_id=NULL"
            }
            Self::Memories => "status='deleted',content=NULL",
        }
    }
}

enum Keys {
    Text(Vec<String>),
    Event(Vec<i64>),
}
impl Keys {
    fn len(&self) -> usize {
        match self {
            Self::Text(v) => v.len(),
            Self::Event(v) => v.len(),
        }
    }
    fn param(&self) -> &(dyn ToSql + Sync) {
        match self {
            Self::Text(v) => v,
            Self::Event(v) => v,
        }
    }
}
struct SelectedTable {
    kind: ClearTable,
    keys: Keys,
}
struct Selection {
    tables: Vec<SelectedTable>,
    counts: ClearCounts,
}

#[derive(Default)]
struct ClearCounts {
    threads: i64,
    messages: i64,
    run_events: i64,
    tool_approvals: i64,
    component_decisions: i64,
    remote_interrupts: i64,
    channel_sources: i64,
    channels: i64,
    memories: i64,
}
impl ClearCounts {
    fn set(&mut self, table: ClearTable, count: i64) {
        match table {
            ClearTable::Threads => self.threads = count,
            ClearTable::Messages => self.messages = count,
            ClearTable::RunEvents => self.run_events = count,
            ClearTable::ToolApprovals => self.tool_approvals = count,
            ClearTable::ComponentDecisions => self.component_decisions = count,
            ClearTable::RemoteInterrupts => self.remote_interrupts = count,
            ClearTable::ChannelSources => self.channel_sources = count,
            ClearTable::Channels => self.channels = count,
            ClearTable::Memories => self.memories = count,
        }
    }
    fn total(&self) -> i64 {
        // Only nine independently checked <=128 selections enter a batch count.
        self.threads
            + self.messages
            + self.run_events
            + self.tool_approvals
            + self.component_decisions
            + self.remote_interrupts
            + self.channel_sources
            + self.channels
            + self.memories
    }
    fn from_row(row: &Row) -> Result<Self, Error> {
        Ok(Self {
            threads: column(row, "threads_cleared")?,
            messages: column(row, "messages_cleared")?,
            run_events: column(row, "run_events_cleared")?,
            tool_approvals: column(row, "tool_approvals_cleared")?,
            component_decisions: column(row, "component_decisions_cleared")?,
            remote_interrupts: column(row, "remote_interrupts_cleared")?,
            channel_sources: column(row, "channel_sources_cleared")?,
            channels: column(row, "channels_cleared")?,
            memories: column(row, "memories_cleared")?,
        })
    }
    fn audit(
        &self,
        binding: &Binding,
        batches: AuditThreadHistoryClearCount,
    ) -> Result<AuditPayload, Error> {
        AuditPayload::from_facts([
            AuditFact::ThreadHistoryClearOperationId(
                AuditThreadHistoryClearOperationId::new(binding.operation_id.as_str())
                    .map_err(|_| corrupt("operation_id"))?,
            ),
            AuditFact::ThreadHistoryClearSource(binding.source.audit()),
            AuditFact::ThreadHistoryClearThreads(audit_count(self.threads)?),
            AuditFact::ThreadHistoryClearMessages(audit_count(self.messages)?),
            AuditFact::ThreadHistoryClearRunEvents(audit_count(self.run_events)?),
            AuditFact::ThreadHistoryClearToolApprovals(audit_count(self.tool_approvals)?),
            AuditFact::ThreadHistoryClearComponentDecisions(audit_count(self.component_decisions)?),
            AuditFact::ThreadHistoryClearRemoteInterrupts(audit_count(self.remote_interrupts)?),
            AuditFact::ThreadHistoryClearChannelSources(audit_count(self.channel_sources)?),
            AuditFact::ThreadHistoryClearChannels(audit_count(self.channels)?),
            AuditFact::ThreadHistoryClearMemories(audit_count(self.memories)?),
            AuditFact::ThreadHistoryClearBatches(batches),
            AuditFact::ThreadHistoryClearRunOutputExpired,
        ])
        .map_err(|_| corrupt("audit_payload"))
    }
}

async fn select_batch(
    tx: &Transaction<'_>,
    thread: &ThreadId,
    tenant: &str,
    deadline: Instant,
) -> Result<Selection, Error> {
    let foreign = one(tx,deadline,"SELECT EXISTS(SELECT 1 FROM public.memories WHERE scope_kind='thread' AND scope_id=$1 AND tenant_id IS DISTINCT FROM $2) AS foreign_memory",&[&thread.as_str(),&tenant]).await?;
    if column::<bool>(&foreign, "foreign_memory")? {
        return Err(corrupt("memory_scope"));
    }
    let mut tables = Vec::with_capacity(ClearTable::ALL.len());
    let mut counts = ClearCounts::default();
    for kind in ClearTable::ALL {
        // Identifiers and fragments below are compiled closed vocabulary; runtime input is bound.
        let sql = format!(
            "SELECT {} AS key FROM {} e{} WHERE {} AND {} ORDER BY {} LIMIT 128",
            kind.key(),
            kind.table(),
            kind.joins(),
            kind.scope(),
            kind.pending(),
            kind.order()
        );
        let selected = rows(tx, deadline, &sql, &[&thread.as_str()]).await?;
        if selected.len() > ROW_LIMIT {
            return Err(corrupt("clear_batch_bound"));
        }
        let keys = if matches!(kind, ClearTable::RunEvents) {
            Keys::Event(
                selected
                    .iter()
                    .map(|row| column(row, "key"))
                    .collect::<Result<Vec<i64>, _>>()?,
            )
        } else {
            Keys::Text(
                selected
                    .iter()
                    .map(|row| column(row, "key"))
                    .collect::<Result<Vec<String>, _>>()?,
            )
        };
        counts.set(
            kind,
            i64::try_from(keys.len()).map_err(|_| corrupt("clear_batch_bound"))?,
        );
        tables.push(SelectedTable { kind, keys });
    }
    Ok(Selection { tables, counts })
}

async fn apply_table(
    tx: &Transaction<'_>,
    thread: &ThreadId,
    actor: &str,
    selected: SelectedTable,
    deadline: Instant,
) -> Result<(), Error> {
    let kind = selected.kind;
    let expected = selected.keys.len();
    if expected == 0 {
        return Ok(());
    }
    let sql = format!(
        "SELECT {} AS key FROM {} e{} WHERE {} AND {}=ANY($2) AND {} ORDER BY {} FOR UPDATE OF e NOWAIT",
        kind.key(),
        kind.table(),
        kind.joins(),
        kind.scope(),
        kind.key(),
        kind.pending(),
        kind.order()
    );
    let params: &[&(dyn ToSql + Sync)] = &[&thread.as_str(), selected.keys.param()];
    if rows(tx, deadline, &sql, params).await?.len() != expected {
        return Err(Error::Unavailable);
    }
    let changed=match kind {
        ClearTable::ChannelSources => execute(tx,deadline,
            "DELETE FROM openbot_internal.channel_history_sources e WHERE e.thread_id=$1 AND e.channel_id=ANY($2)",params).await?,
        ClearTable::Channels => execute(tx,deadline,
            "UPDATE public.channels e SET last_message=NULL,last_message_at=NULL,last_message_agent_id=NULL WHERE e.id=ANY($2) AND EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads h WHERE h.thread_id=$1 AND h.anchor_kind='channel' AND h.anchor_id=e.id) AND NOT EXISTS(SELECT 1 FROM openbot_internal.channel_history_sources s WHERE s.channel_id=e.id) AND ROW(e.last_message,e.last_message_at,e.last_message_agent_id) IS DISTINCT FROM ROW(NULL::text,NULL::timestamptz,NULL::text)",params).await?,
        ClearTable::RunEvents => execute(tx,deadline,
            "UPDATE public.run_events e SET payload=openbot_internal.thread_history_clear_event_payload(e.event_type,e.payload,r.error_code) FROM public.runs r WHERE r.run_id=e.run_id AND r.thread_id=e.thread_id AND e.thread_id=$1 AND e.event_seq=ANY($2) AND e.payload IS DISTINCT FROM openbot_internal.thread_history_clear_event_payload(e.event_type,e.payload,r.error_code)",params).await?,
        _ => {
            let sql=format!("UPDATE {} e SET {} WHERE {} AND {}=ANY($2) AND {}",
                kind.table(),kind.update(),kind.scope(),kind.key(),kind.pending());
            execute(tx,deadline,&sql,params).await?
        }
    };
    if usize::try_from(changed).ok() != Some(expected) {
        return Err(Error::Unavailable);
    }
    if matches!(kind, ClearTable::Memories) {
        let events=execute(tx,deadline,
            "INSERT INTO public.memory_events(memory_id,seq,event_type,actor_id,metadata,created_at) SELECT m.memory_id,coalesce((SELECT max(e.seq) FROM public.memory_events e WHERE e.memory_id=m.memory_id),-1)+1,'delete',$3,'{}'::jsonb,clock_timestamp() FROM public.memories m WHERE m.scope_kind='thread' AND m.scope_id=$1 AND m.memory_id=ANY($2)",
            &[&thread.as_str(),selected.keys.param(),&actor]).await?;
        if usize::try_from(events).ok() != Some(expected) {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}

async fn require_closed(
    schema: &CurrentWriterSchema<'_, '_>,
    tx: &Transaction<'_>,
    thread: &ThreadId,
    deadline: Instant,
) -> Result<(), Error> {
    match bounded(deadline, schema.lock_thread_write_disposition(tx, thread))
        .await?
        .map_err(writer_error)?
    {
        OpenOrClosed::Closed => Ok(()),
        OpenOrClosed::Open => Err(corrupt("history_binding")),
    }
}
async fn bodies_erased(
    tx: &Transaction<'_>,
    operation: &str,
    deadline: Instant,
) -> Result<bool, Error> {
    let row = one(
        tx,
        deadline,
        "SELECT openbot_internal.thread_history_clear_bodies_erased($1) AS erased",
        &[&operation],
    )
    .await?;
    column(&row, "erased")
}
async fn has_live_runs(
    tx: &Transaction<'_>,
    thread: &ThreadId,
    deadline: Instant,
) -> Result<bool, Error> {
    let row=one(tx,deadline,"SELECT count(*) FILTER(WHERE status='queued')::bigint AS queued,count(*) FILTER(WHERE status='running')::bigint AS running FROM public.runs WHERE thread_id=$1 AND status IN('queued','running')",&[&thread.as_str()]).await?;
    let queued: i64 = column(&row, "queued")?;
    let running: i64 = column(&row, "running")?;
    if queued != 0 || running < 0 {
        return Err(corrupt("run_status"));
    }
    Ok(running > 0)
}
async fn assert_run_output_noop(
    tx: &Transaction<'_>,
    thread: &ThreadId,
    deadline: Instant,
) -> Result<(), Error> {
    let found=rows(tx,deadline,"SELECT DISTINCT retention_class FROM openbot_internal.artifact_records WHERE source_thread_id=$1 AND status IN('available','failed_partial') LIMIT 3",&[&thread.as_str()]).await?;
    for row in found {
        let class = match column::<Option<String>>(&row, "retention_class")?.as_deref() {
            Some("explicit_saved") => ArtifactRetentionClass::ExplicitSaved,
            Some("run_output") => ArtifactRetentionClass::RunOutput,
            _ => return Err(corrupt("run_output_producer_unregistered")),
        };
        match class {
            ArtifactRetentionClass::ExplicitSaved => {}
            ArtifactRetentionClass::RunOutput => {
                return Err(corrupt("run_output_producer_unregistered"));
            }
        }
    }
    Ok(())
}

async fn set_timeouts(tx: &Transaction<'_>, deadline: Instant) -> Result<(), Error> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Unavailable)?;
    let milliseconds = left.as_millis();
    if milliseconds == 0 {
        return Err(Error::Unavailable);
    }
    let text = format!("{milliseconds}ms");
    one(
        tx,
        deadline,
        "SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$1,true)",
        &[&text],
    )
    .await?;
    Ok(())
}
fn transaction_deadline(original: Instant) -> Result<Instant, Error> {
    let now = Instant::now();
    if now >= original {
        return Err(Error::DeadlineExceeded);
    }
    Ok(original.min(
        now.checked_add(Duration::from_secs(5))
            .ok_or(Error::Unavailable)?,
    ))
}
async fn bounded<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| Error::Unavailable)
}
async fn rows(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Row>, Error> {
    bounded(deadline, tx.query(sql, params))
        .await?
        .map_err(statement_error)
}
async fn one(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Row, Error> {
    bounded(deadline, tx.query_one(sql, params))
        .await?
        .map_err(statement_error)
}
async fn execute(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<u64, Error> {
    bounded(deadline, tx.execute(sql, params))
        .await?
        .map_err(statement_error)
}
async fn settle(tx: &Transaction<'_>, deadline: Instant) -> Result<(), Error> {
    bounded(deadline, tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE"))
        .await?
        .map_err(statement_error)
}
fn column<T: FromSqlOwned>(row: &Row, name: &'static str) -> Result<T, Error> {
    row.try_get(name).map_err(|_| corrupt("row_decode"))
}
fn audit_count(value: i64) -> Result<AuditThreadHistoryClearCount, Error> {
    AuditThreadHistoryClearCount::new(
        u64::try_from(value).map_err(|_| corrupt("clear_completion_count"))?,
    )
    .map_err(|_| corrupt("clear_completion_count"))
}
const fn corrupt(field: &'static str) -> Error {
    Error::Corrupt { field }
}
fn statement_error(error: tokio_postgres::Error) -> Error {
    if let Some(db) = error.as_db_error()
        && db.code().code() == "55000"
    {
        return match db.message() {
            "run_output_producer_unregistered" => corrupt("run_output_producer_unregistered"),
            "thread_history_clear_body_remaining" => corrupt("clear_body_remaining"),
            _ => corrupt("history_binding"),
        };
    }
    match error.code().map(tokio_postgres::error::SqlState::code) {
        Some("23503" | "23514" | "23505") => corrupt("history_binding"),
        _ => Error::Unavailable,
    }
}
/// A deferred, known database refusal does not publish completion; the caller still observes
/// its original ROLLBACK ACK before returning this waiting state.
fn completion_wait(error: &tokio_postgres::Error) -> Option<Decision> {
    let db = error.as_db_error()?;
    if db.code().code() != "55000" {
        return None;
    }
    match db.message() {
        "thread_history_clear_live_run" => Some(Decision::AwaitingDrain),
        "thread_history_clear_readers_active" => Some(Decision::AwaitingReaders),
        _ => None,
    }
}
fn schema_error(error: InfraError) -> Error {
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => Error::Unavailable,
        InfraError::RowDecode(_) => corrupt("row_decode"),
        InfraError::IncompatibleDatabase(_)
        | InfraError::NativeMigration(_)
        | InfraError::RepositoryInvariant { .. } => corrupt("schema"),
    }
}
fn writer_error(error: InfraError) -> Error {
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => {
            if error.sqlstate() == Some("55000") {
                corrupt("history_binding")
            } else {
                Error::Unavailable
            }
        }
        InfraError::RowDecode(_) => corrupt("row_decode"),
        InfraError::RepositoryInvariant { .. } => corrupt("history_binding"),
        InfraError::IncompatibleDatabase(_) | InfraError::NativeMigration(_) => corrupt("schema"),
    }
}
fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::AlreadyStarted => Error::AlreadyStarted,
        TransactionOwnerError::DeadlineExceeded => Error::DeadlineExceeded,
        TransactionOwnerError::BeginUnavailable => Error::BeginUnavailable,
        TransactionOwnerError::CommitUnknown => Error::CommitUnknown,
        TransactionOwnerError::RollbackUnproven => Error::RollbackUnproven,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
    }
}
