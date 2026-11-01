//! Original explicitly saved artifact terminal/refund work on one guarded transaction.
//! An intent locates the same Store/key; only this invocation's current Host and actual ACK
//! can publish its limited terminal observation. External copies and restart recovery are separate.

use std::future::Future;
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::{
    ArtifactGoneStatus, canonical_artifact_uuid_v7, is_valid_artifact_identity,
    is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::request_binding::{ArtifactCleanupHostTailWitness, HostRequestBindingError};
use openbot_domain::artifact_cleanup::{
    ArtifactCleanupFence, ArtifactCleanupFenceKey, ArtifactCleanupFencePhase,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio_postgres::types::FromSql;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::cleanup_arm::{
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError, TerminalCurrentFailure,
    TerminalCurrentRequest,
};
use super::{PostgresArtifactAdministration, verify_artifact_read_schema_on};
use crate::artifact_bytes::ArtifactByteProbe;
use crate::artifact_store::{
    ArtifactStoreError, DatasetBoundArtifactStore, TerminalInvocationClaim,
    TerminalInvocationQueryOwner, TerminalPublishMode, TerminalWorkerLease,
};
use crate::db::InfraError;
use crate::db::pool::TransactionOwnerError;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

/// Only a fresh confirmed terminal observation, not a reusable Host or physical grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCleanupTerminalState {
    /// This invocation's original refund/pair/fence/audit transaction really committed on time.
    Committed,
    /// A fresh completed decoder and its own rollback ACK confirmed the same original fact.
    AlreadyCompleted,
}

/// Private exact-key/Store/current-tail observation, without Clone, Serde or raw authority getters.
pub struct ArtifactCleanupTerminalObservation {
    claim: Arc<TerminalInvocationClaim>,
    _original_store: Arc<DatasetBoundArtifactStore>,
    _original_key: ArtifactCleanupFenceKey,
    original_tail: Arc<dyn ArtifactCleanupHostTailWitness>,
    deadline: Instant,
    state: ArtifactCleanupTerminalState,
}

impl core::fmt::Debug for ArtifactCleanupTerminalObservation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("ArtifactCleanupTerminalObservation([redacted original terminal facts])")
    }
}

impl ArtifactCleanupTerminalObservation {
    /// Observe the limited confirmed outcome; this does not grant a later action.
    #[must_use]
    pub const fn state(&self) -> ArtifactCleanupTerminalState {
        self.state
    }

    fn verify_delivery(&self, auth: &AuthContext) -> Result<(), Error> {
        registered_remaining(&self.claim, self.deadline)?;
        let tail = self.original_tail.verify_current(auth, self.deadline);
        registered_remaining(&self.claim, self.deadline)?;
        tail.map_err(Error::Host)?;
        let checked = self.claim.verify_terminal_publish(publish_mode(self.state));
        registered_remaining(&self.claim, self.deadline)?;
        checked.map_err(|_| Error::ReadsUnproven)
    }
}

/// Closed trusted-port errors, never SQL, paths, source text or caller-controlled diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactCleanupTerminalError {
    /// The original enrolled Host/window cannot attest this invocation.
    #[error("artifact_cleanup_terminal_host_invalid")]
    Host(HostRequestBindingError),
    /// The original saved owner lacks current authority.
    #[error("artifact_cleanup_terminal_not_visible")]
    NotVisible,
    /// The original binding or immutable intent contradicts this invocation.
    #[error("artifact_cleanup_terminal_conflict")]
    Conflict,
    /// Real stored facts violate a registered invariant.
    #[error("artifact_cleanup_terminal_facts_invalid:{field}")]
    Corrupt {
        /// A registered static field only.
        field: &'static str,
    },
    /// Other original controlled owners or an original query remain unproved.
    #[error("artifact_cleanup_terminal_reads_unproven")]
    ReadsUnproven,
    /// Original guarded absence, IO or worker completion cannot be proved.
    #[error("artifact_cleanup_terminal_physical_unproven")]
    PhysicalUnproven,
    /// An original dependency is unavailable.
    #[error("artifact_cleanup_terminal_unavailable")]
    Unavailable,
    /// This invocation's one unchanged absolute budget expired.
    #[error("artifact_cleanup_terminal_deadline_expired")]
    DeadlineExpired,
    /// The actual original COMMIT started without a normal confirmed ACK.
    #[error("artifact_cleanup_terminal_commit_unknown")]
    CommitUnknown,
    /// A real original COMMIT ACK is known but late.
    #[error("artifact_cleanup_terminal_commit_acknowledged_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    /// A real original ROLLBACK ACK is known but late.
    #[error("artifact_cleanup_terminal_rollback_acknowledged_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

type Error = ArtifactCleanupTerminalError;

/// Four actual trusted cutpoints. A callback label is neither authority nor an ACK/end proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactCleanupTerminalPhase {
    /// The original worker holds its continuous IO guard after true guarded absence and sync.
    AbsenceGuarded,
    /// Before the final renewed RC/self-effects and last guarded absence permission checkpoint.
    BeforeCommit,
    /// The actual original on-time commit ACK and exact-key fact precede IO release.
    AfterCommitAckBeforeWorkerEnd,
    /// This original worker's temporary FDs and IO guard have actually dropped.
    WorkerEnded,
}

/// Narrow trusted instrumentation. The optional original leaf FD is only a tracing input.
pub trait ArtifactCleanupTerminalObserver: Send + Sync {
    /// Called outside gate/permission locks, inside the same original absolute budget.
    fn on_phase(
        &self,
        phase: ArtifactCleanupTerminalPhase,
        artifact_id: Uuid,
        original_leaf_fd: Option<RawFd>,
    );
}

struct WorkFailure {
    error: Error,
    query_unproven: bool,
}

impl WorkFailure {
    fn known(error: Error) -> Self {
        Self {
            error,
            query_unproven: false,
        }
    }

    fn elapsed() -> Self {
        Self {
            error: Error::DeadlineExpired,
            query_unproven: true,
        }
    }

    fn current(error: TerminalCurrentFailure) -> Self {
        Self {
            error: arm_error(error.error),
            query_unproven: error.query_unproven,
        }
    }
}

struct MainQueryOwner {
    permission: Arc<WorkerPermission>,
    query: Option<TerminalInvocationQueryOwner>,
    worker: Option<crate::artifact_store::CaptureBlockingWorker<Result<(), Error>>>,
    claim: Arc<TerminalInvocationClaim>,
    deadline: Instant,
    original_main_handled: bool,
}

impl Drop for MainQueryOwner {
    fn drop(&mut self) {
        // Never hold a gate while taking the permission mutex. This only wakes/stops the
        // original worker; it does not attest an ACK. A real ACK/fact does not prove that
        // this main future completed normally: post-ACK panic/abort remains unproven.
        self.permission.cancel();
        if self.query.is_some() || !self.original_main_handled {
            self.claim.mark_unproven();
        }
        self.permission.release_after_disposition();
        let _ = registered_remaining(&self.claim, self.deadline);
    }
}

struct CallerWaiter {
    permission: Arc<WorkerPermission>,
    claim: Arc<TerminalInvocationClaim>,
    deadline: Instant,
    completed: bool,
}

impl Drop for CallerWaiter {
    fn drop(&mut self) {
        if !self.completed {
            self.permission.cancel();
        }
        let _ = registered_remaining(&self.claim, self.deadline);
    }
}

impl PostgresArtifactAdministration {
    /// Complete only the same original armed saved artifact, refunding its original charge once.
    ///
    /// # Errors
    /// Refuses foreign/current-invalid inputs, bad stored facts and unknown original resources.
    pub async fn finalize_armed_explicit_saved_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        original_deadline: Instant,
    ) -> Result<ArtifactCleanupTerminalObservation, Error> {
        self.finalize_armed_explicit_saved_before_with_observer(
            auth,
            intent,
            original_deadline,
            None,
        )
        .await
    }

    /// The identical trusted producer with four nongrant actual instrumentation cutpoints.
    ///
    /// # Errors
    /// All ordinary terminal failures and the unchanged budget apply to observer waits too.
    pub async fn finalize_armed_explicit_saved_before_with_observer(
        self: &Arc<Self>,
        auth: &AuthContext,
        intent: &ArmedArtifactCleanupIntent,
        original_deadline: Instant,
        observer: Option<Arc<dyn ArtifactCleanupTerminalObserver>>,
    ) -> Result<ArtifactCleanupTerminalObservation, Error> {
        let capture_operation = self
            .store
            .begin_capture_mutation()
            .map_err(|_| Error::Unavailable)?;
        let result = async {
            let deadline = original_deadline.min(
                Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .ok_or(Error::Unavailable)?,
            );
            remaining(deadline)?;
            let (store, key) = intent
                .validated_terminal_binding(self)
                .map_err(|_| Error::Conflict)?
                .into_original_parts();
            let authority = self.read_authority();
            let target = authority.cleanup_host_target(auth);
            let _current = TerminalCurrentRequest::borrow_before(self, auth, &target, deadline)
                .map_err(arm_error)?;
            // This separate exact-key query owner is registered before the first real PG await.
            let (claim, query) =
                TerminalInvocationClaim::register(Arc::clone(&store), key.clone(), deadline)
                    .map_err(|_| Error::ReadsUnproven)?;
            let permission = WorkerPermission::new(capture_operation.delegated());
            let mut waiter = CallerWaiter {
                permission: Arc::clone(&permission),
                claim: Arc::clone(&claim),
                deadline,
                completed: false,
            };
            let (sender, receiver) = oneshot::channel();
            let administration = Arc::clone(self);
            let original_auth = auth.clone();
            // Losing only this caller does not drop the actual original query supervisor.
            self.store
                .spawn_capture_mutation(async move {
                    let result = supervise(
                        administration,
                        original_auth,
                        store,
                        key,
                        claim,
                        query,
                        permission,
                        deadline,
                        observer,
                    )
                    .await;
                    let _ = sender.send(result);
                })
                .map_err(|_| Error::Unavailable)?;
            let received = before(deadline, receiver).await;
            registered_remaining(&waiter.claim, deadline)?;
            let observation = received
                .map_err(|failure| failure.error)?
                .map_err(|_| Error::ReadsUnproven)??;
            observation.verify_delivery(auth)?;
            registered_remaining(&waiter.claim, deadline)?;
            waiter.completed = true;
            Ok(observation)
        }
        .await;
        if !matches!(
            &result,
            Err(Error::Unavailable
                | Error::DeadlineExpired
                | Error::ReadsUnproven
                | Error::PhysicalUnproven
                | Error::CommitUnknown)
        ) {
            capture_operation.complete();
        }
        result
    }
}

struct WorkOutcome {
    state: ArtifactCleanupTerminalState,
    audit_id: Option<Uuid>,
    tail: Arc<dyn ArtifactCleanupHostTailWitness>,
}

const RETAINED_IDENTITIES: [&str; 7] = [
    "request_id",
    "owner_actor_id",
    "source_thread_id",
    "source_run_id",
    "source_message_id",
    "source_call_seq",
    "source_attempt_seq",
];
const RECORD_PAYLOAD: [&str; 8] = [
    "workspace_kind",
    "workspace_id",
    "media_type",
    "byte_length",
    "sha256",
    "retention_class",
    "saved_by",
    "saved_at",
];
const OPERATION_PAYLOAD: [&str; 12] = [
    "store_id",
    "workspace_kind",
    "workspace_id",
    "expected_sha256",
    "expected_bytes",
    "charged_bytes",
    "actual_absent",
    "actual_byte_length",
    "actual_sha256",
    "actual_location",
    "observation_phase",
    "created_at",
];

#[derive(Clone)]
struct Pair {
    record: Value,
    operation: Value,
    receipt: Value,
    fence: ArtifactCleanupFence,
}

impl Pair {
    fn decode_common(
        row: &Row,
        administration: &PostgresArtifactAdministration,
        auth: &AuthContext,
        key: &ArtifactCleanupFenceKey,
    ) -> Result<Self, Error> {
        if !column::<bool>(row, "store_matches")?
            || !administration
                .store
                .matches_registry_owner(&administration.registry)
        {
            return Err(corrupt("store_binding"));
        }
        let record = column::<Option<Value>>(row, "record_row")?.ok_or(Error::NotVisible)?;
        let operation =
            column::<Option<Value>>(row, "operation_row")?.ok_or(corrupt("operation_pair"))?;
        let receipt =
            column::<Option<Value>>(row, "receipt_row")?.ok_or(corrupt("positive_receipt"))?;
        for (field, expected) in [
            ("deployment_id", key.deployment_id().as_str()),
            ("tenant_id", key.tenant_id().as_str()),
            ("dataset_id", key.dataset_id()),
            ("operation_id", key.operation_id().as_str()),
            ("artifact_id", key.artifact_id()),
        ] {
            for (value, tag) in [
                (&record, "record_pair"),
                (&operation, "operation_pair"),
                (&receipt, "positive_receipt"),
            ] {
                if text(value, field, tag)? != expected {
                    return Err(corrupt(tag));
                }
            }
        }
        for field in RETAINED_IDENTITIES {
            let expected = member(&record, field, "record_pair")?;
            if member(&operation, field, "operation_pair")? != expected
                || member(&receipt, field, "positive_receipt")? != expected
            {
                return Err(corrupt("positive_receipt"));
            }
        }
        if text(&record, "owner_actor_id", "record_pair")? != auth.actor().as_str() {
            return Err(Error::NotVisible);
        }
        for field in ["request_id", "artifact_id", "operation_id"] {
            let value = text(&record, field, "record_pair")?;
            if canonical_artifact_uuid_v7(value).as_deref() != Some(value) {
                return Err(corrupt("stored_uuid"));
            }
        }
        for field in [
            "owner_actor_id",
            "source_thread_id",
            "source_run_id",
            "source_message_id",
        ] {
            if !is_valid_artifact_identity(text(&record, field, "record_pair")?) {
                return Err(corrupt("record_pair"));
            }
        }
        match (
            member(&record, "source_call_seq", "record_pair")?,
            member(&record, "source_attempt_seq", "record_pair")?,
        ) {
            (Value::Null, Value::Null) => {}
            (call, attempt)
                if call.as_i64().is_some_and(|n| n >= 0)
                    && attempt.as_i64().is_some_and(|n| n >= 0) => {}
            _ => return Err(corrupt("record_pair")),
        }
        let value = column::<Option<Value>>(row, "fence_row")?.ok_or(corrupt("cleanup_fence"))?;
        let actual_key = ArtifactCleanupFenceKey::from_stored(
            DeploymentId::new(text(&value, "deployment_id", "cleanup_fence")?),
            TenantId::new(text(&value, "tenant_id", "cleanup_fence")?),
            text(&value, "dataset_id", "cleanup_fence")?,
            text(&value, "operation_id", "cleanup_fence")?,
            text(&value, "artifact_id", "cleanup_fence")?,
        )
        .map_err(|_| corrupt("cleanup_fence"))?;
        let fence = ArtifactCleanupFence::from_stored(
            actual_key,
            text(&value, "terminal_status", "cleanup_fence")?,
            text(&value, "phase", "cleanup_fence")?,
        )
        .map_err(|_| corrupt("cleanup_fence"))?;
        if fence.key() != key || fence.terminal_status() != ArtifactGoneStatus::Deleted {
            return Err(Error::Conflict);
        }
        Ok(Self {
            record,
            operation,
            receipt,
            fence,
        })
    }

    fn require_same(&self, original: &Self) -> Result<(), Error> {
        if self.record == original.record
            && self.operation == original.operation
            && self.receipt == original.receipt
            && self.fence == original.fence
        {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    fn completed(&self) -> Result<bool, Error> {
        match (
            text(&self.record, "status", "record_pair")?,
            text(&self.operation, "state", "operation_pair")?,
            self.fence.phase(),
        ) {
            ("available", "available", ArtifactCleanupFencePhase::Armed) => Ok(false),
            ("deleted", "deleted", ArtifactCleanupFencePhase::Completed) => {
                self.require_cleared()?;
                Ok(true)
            }
            _ => Err(Error::Conflict),
        }
    }

    fn require_cleared(&self) -> Result<(), Error> {
        for field in RECORD_PAYLOAD {
            if member(&self.record, field, "record_pair")? != &Value::Null {
                return Err(corrupt("record_pair"));
            }
        }
        for field in OPERATION_PAYLOAD {
            if member(&self.operation, field, "operation_pair")? != &Value::Null {
                return Err(corrupt("operation_pair"));
            }
        }
        Ok(())
    }
}

struct LiveFacts {
    workspace_kind: String,
    workspace_id: String,
    original_charge: i64,
}

impl LiveFacts {
    fn decode(pair: &Pair, administration: &PostgresArtifactAdministration) -> Result<Self, Error> {
        if pair.completed()? {
            return Err(Error::Conflict);
        }
        if text(&pair.record, "retention_class", "record_pair")? != "explicit_saved"
            || text(&pair.record, "saved_by", "record_pair")?
                != text(&pair.record, "owner_actor_id", "record_pair")?
            || text(&pair.record, "media_type", "record_pair")? != "text/plain; charset=utf-8"
            || !member(&pair.record, "saved_at", "record_pair")?.is_string()
        {
            return Err(corrupt("record_pair"));
        }
        let workspace_kind = text(&pair.record, "workspace_kind", "record_pair")?.to_owned();
        let workspace_id = text(&pair.record, "workspace_id", "record_pair")?.to_owned();
        if !matches!(workspace_kind.as_str(), "thread" | "channel")
            || !is_valid_artifact_identity(&workspace_id)
            || text(&pair.operation, "workspace_kind", "operation_pair")? != workspace_kind
            || text(&pair.operation, "workspace_id", "operation_pair")? != workspace_id
        {
            return Err(corrupt("operation_pair"));
        }
        let store_id = text(&pair.operation, "store_id", "operation_pair")?;
        if canonical_artifact_uuid_v7(store_id).as_deref() != Some(store_id)
            || store_id != administration.store.store_id().to_string()
        {
            return Err(corrupt("store_binding"));
        }
        let bytes = number(&pair.record, "byte_length", "record_pair")?;
        let digest = text(&pair.record, "sha256", "record_pair")?;
        if !(1..=67_108_864).contains(&bytes)
            || !is_valid_artifact_sha256(digest)
            || number(&pair.operation, "expected_bytes", "operation_pair")? != bytes
            || number(&pair.operation, "charged_bytes", "operation_pair")? != bytes
            || number(&pair.operation, "actual_byte_length", "operation_pair")? != bytes
            || text(&pair.operation, "expected_sha256", "operation_pair")? != digest
            || text(&pair.operation, "actual_sha256", "operation_pair")? != digest
            || member(&pair.operation, "actual_absent", "operation_pair")? != &Value::Bool(false)
            || text(&pair.operation, "actual_location", "operation_pair")? != "object"
            || text(&pair.operation, "observation_phase", "operation_pair")? != "installed"
            || !member(&pair.operation, "created_at", "operation_pair")?.is_string()
        {
            return Err(corrupt("operation_pair"));
        }
        Ok(Self {
            workspace_kind,
            workspace_id,
            original_charge: bytes,
        })
    }
}

struct Locked {
    pair: Pair,
    live: Option<LiveFacts>,
}

struct LiveOriginal {
    pair: Pair,
    facts: LiveFacts,
    quota_before: i64,
    quota_after: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Staged {
    Live,
    RecordDeleted,
    PairDeleted,
    FenceCompleted,
    Refunded,
}

impl LiveOriginal {
    fn expected_pair(&self, stage: Staged) -> Result<Pair, Error> {
        let mut expected = self.pair.clone();
        if stage >= Staged::RecordDeleted {
            clear_payload(&mut expected.record, "status", RECORD_PAYLOAD)?;
        }
        if stage >= Staged::PairDeleted {
            clear_payload(&mut expected.operation, "state", OPERATION_PAYLOAD)?;
        }
        if stage >= Staged::FenceCompleted {
            expected.fence = expected
                .fence
                .with_phase(ArtifactCleanupFencePhase::Completed)
                .map_err(|_| corrupt("cleanup_fence"))?;
        }
        Ok(expected)
    }
}

fn clear_payload<const N: usize>(
    value: &mut Value,
    state: &str,
    fields: [&str; N],
) -> Result<(), Error> {
    let object = value.as_object_mut().ok_or(corrupt("record_pair"))?;
    object.insert(state.to_owned(), Value::String("deleted".to_owned()));
    for field in fields {
        if !object.contains_key(field) {
            return Err(corrupt("record_pair"));
        }
        object.insert(field.to_owned(), Value::Null);
    }
    Ok(())
}

async fn observe_pair(
    current: &TerminalCurrentRequest<'_>,
    tx: &Transaction<'_>,
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    key: &ArtifactCleanupFenceKey,
    deadline: Instant,
) -> Result<(Pair, Box<dyn ArtifactCleanupHostTailWitness>), WorkFailure> {
    let (row, tail) = current
        .observe_before(tx, key, deadline)
        .await
        .map_err(WorkFailure::current)?;
    let pair = Pair::decode_common(&row, administration, auth, key).map_err(WorkFailure::known)?;
    Ok((pair, tail))
}

#[allow(clippy::too_many_arguments)] // Original Host, exact key and one original transaction.
async fn lock_pair(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    current: &TerminalCurrentRequest<'_>,
    tx: &Transaction<'_>,
    key: &ArtifactCleanupFenceKey,
    deadline: Instant,
) -> Result<Locked, WorkFailure> {
    let actor = sql(
        deadline,
        tx.query_opt(
            "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
            &[&auth.actor().as_str()],
        ),
    )
    .await?;
    if actor.is_none() {
        return Err(WorkFailure::known(Error::NotVisible));
    }
    let (original, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    let completed = original.completed().map_err(WorkFailure::known)?;
    let live = if completed {
        None
    } else {
        Some(LiveFacts::decode(&original, administration).map_err(WorkFailure::known)?)
    };
    let roles = sql(deadline, tx.query(
        "SELECT role FROM public.user_roles WHERE user_id=$1 AND role IN ('user','admin') FOR SHARE NOWAIT",
        &[&auth.actor().as_str()],
    )).await?;
    if roles.is_empty() {
        return Err(WorkFailure::known(Error::NotVisible));
    }
    let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    fresh.require_same(&original).map_err(WorkFailure::known)?;
    if let Some(live) = &live {
        let row = sql(
            deadline,
            tx.query_opt(
                "SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 \
               AND workspace_kind=$4 AND workspace_id=$5 FOR UPDATE",
                &[
                    &key.deployment_id().as_str(),
                    &key.tenant_id().as_str(),
                    &key.dataset_id(),
                    &live.workspace_kind,
                    &live.workspace_id,
                ],
            ),
        )
        .await?;
        if row.is_none() {
            return Err(WorkFailure::known(corrupt("workspace_quota")));
        }
        let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
        fresh.require_same(&original).map_err(WorkFailure::known)?;
    }
    let operation = sql(
        deadline,
        tx.query_opt(
            "SELECT operation_id FROM openbot_internal.artifact_save_operations \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 FOR UPDATE",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &key.operation_id().as_str(),
            ],
        ),
    )
    .await?;
    if operation.is_none() {
        return Err(WorkFailure::known(corrupt("operation_pair")));
    }
    let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    fresh.require_same(&original).map_err(WorkFailure::known)?;
    let record = sql(
        deadline,
        tx.query_opt(
            "SELECT artifact_id FROM openbot_internal.artifact_records \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 FOR UPDATE",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &key.artifact_id(),
            ],
        ),
    )
    .await?;
    if record.is_none() {
        return Err(WorkFailure::known(corrupt("record_pair")));
    }
    let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    fresh.require_same(&original).map_err(WorkFailure::known)?;
    let fence = sql(
        deadline,
        tx.query_opt(
            "SELECT artifact_id FROM openbot_internal.artifact_cleanup_fences \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 FOR UPDATE",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &key.artifact_id(),
            ],
        ),
    )
    .await?;
    if fence.is_none() {
        return Err(WorkFailure::known(corrupt("cleanup_fence")));
    }
    let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    fresh.require_same(&original).map_err(WorkFailure::known)?;
    Ok(Locked { pair: fresh, live })
}

async fn read_quota(
    tx: &Transaction<'_>,
    key: &ArtifactCleanupFenceKey,
    facts: &LiveFacts,
    deadline: Instant,
) -> Result<i64, WorkFailure> {
    let row = sql(
        deadline,
        tx.query_opt(
            "SELECT to_jsonb(q) AS quota_row FROM openbot_internal.artifact_workspace_quotas q \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 \
           AND workspace_kind=$4 AND workspace_id=$5",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &facts.workspace_kind,
                &facts.workspace_id,
            ],
        ),
    )
    .await?
    .ok_or_else(|| WorkFailure::known(corrupt("workspace_quota")))?;
    let quota: Value = row
        .try_get("quota_row")
        .map_err(|_| WorkFailure::known(corrupt("workspace_quota")))?;
    for (field, expected) in [
        ("deployment_id", key.deployment_id().as_str()),
        ("tenant_id", key.tenant_id().as_str()),
        ("dataset_id", key.dataset_id()),
        ("workspace_kind", facts.workspace_kind.as_str()),
        ("workspace_id", facts.workspace_id.as_str()),
    ] {
        if text(&quota, field, "workspace_quota").map_err(WorkFailure::known)? != expected {
            return Err(WorkFailure::known(corrupt("workspace_quota")));
        }
    }
    let total = number(&quota, "charged_bytes", "workspace_quota").map_err(WorkFailure::known)?;
    if !(0..=17_179_869_184).contains(&total) {
        return Err(WorkFailure::known(corrupt("workspace_quota")));
    }
    Ok(total)
}

#[allow(clippy::too_many_arguments)] // Explicit staged self-effects, never an old live decoder.
async fn refresh_staged(
    current: &TerminalCurrentRequest<'_>,
    tx: &Transaction<'_>,
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    key: &ArtifactCleanupFenceKey,
    original: &LiveOriginal,
    stage: Staged,
    deadline: Instant,
) -> Result<Box<dyn ArtifactCleanupHostTailWitness>, WorkFailure> {
    // Quota remains locked. Its original workspace comes only from the real initial live pair;
    // the following fresh joint statement observes authority after this actual quota query.
    let quota = read_quota(tx, key, &original.facts, deadline).await?;
    let expected = if stage >= Staged::Refunded {
        original.quota_after
    } else {
        original.quota_before
    };
    if quota != expected {
        return Err(WorkFailure::known(corrupt("workspace_quota")));
    }
    let (pair, tail) = observe_pair(current, tx, administration, auth, key, deadline).await?;
    pair.require_same(&original.expected_pair(stage).map_err(WorkFailure::known)?)
        .map_err(WorkFailure::known)?;
    Ok(tail)
}

#[allow(clippy::too_many_arguments)] // One original supervised query/worker and fixed inputs.
async fn work_before(
    administration: &PostgresArtifactAdministration,
    auth: &AuthContext,
    store: &Arc<DatasetBoundArtifactStore>,
    key: &ArtifactCleanupFenceKey,
    claim: &Arc<TerminalInvocationClaim>,
    permission: &Arc<WorkerPermission>,
    current: &TerminalCurrentRequest<'_>,
    tx: &Transaction<'_>,
    worker: &mut Option<crate::artifact_store::CaptureBlockingWorker<Result<(), Error>>>,
    deadline: Instant,
    observer: &Option<Arc<dyn ArtifactCleanupTerminalObserver>>,
) -> Result<WorkOutcome, WorkFailure> {
    let locked = lock_pair(administration, auth, current, tx, key, deadline).await?;
    if locked.live.is_none() {
        // No quota query/join, workspace reconstruction, worker, IO, refund or audit INSERT.
        claim
            .wait_original_reads_before()
            .await
            .map_err(|_| WorkFailure::known(Error::ReadsUnproven))?;
        let (fresh, _) = observe_pair(current, tx, administration, auth, key, deadline).await?;
        fresh
            .require_same(&locked.pair)
            .map_err(WorkFailure::known)?;
        if !fresh.completed().map_err(WorkFailure::known)? {
            return Err(WorkFailure::known(Error::Conflict));
        }
        let audit_id = claim.completed_audit_event_id().map_err(|_| {
            claim.mark_unproven();
            WorkFailure::known(corrupt("terminal_fact"))
        })?;
        verify_audit(tx, auth, key, audit_id, deadline).await?;
        let (final_pair, tail) =
            observe_pair(current, tx, administration, auth, key, deadline).await?;
        final_pair
            .require_same(&fresh)
            .map_err(WorkFailure::known)?;
        final_pair.require_cleared().map_err(WorkFailure::known)?;
        return Ok(WorkOutcome {
            state: ArtifactCleanupTerminalState::AlreadyCompleted,
            audit_id: None,
            tail: Arc::from(tail),
        });
    }
    let facts = locked
        .live
        .ok_or_else(|| WorkFailure::known(Error::Conflict))?;
    // Fresh aggregate after acquiring the actual original quota lock. Another artifact's charge
    // can change that aggregate while this call waits; its original pair cannot substitute it.
    let quota_before = read_quota(tx, key, &facts, deadline).await?;
    let quota_after = quota_before
        .checked_sub(facts.original_charge)
        .filter(|value| *value >= 0)
        .ok_or_else(|| WorkFailure::known(corrupt("workspace_quota")))?;
    let original = LiveOriginal {
        pair: locked.pair,
        facts,
        quota_before,
        quota_after,
    };
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Live,
        deadline,
    )
    .await?;
    claim
        .wait_original_reads_before()
        .await
        .map_err(|_| WorkFailure::known(Error::ReadsUnproven))?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Live,
        deadline,
    )
    .await?;
    let lease = claim
        .reserve_worker()
        .map_err(|_| WorkFailure::known(Error::ReadsUnproven))?;
    let (ready_sender, ready) = oneshot::channel();
    let (started_sender, started) = oneshot::channel();
    let worker_store = Arc::clone(store);
    let worker_claim = Arc::clone(claim);
    let worker_permission = Arc::clone(permission);
    let worker_auth = auth.clone();
    let worker_observer = observer.as_ref().map(Arc::clone);
    let artifact_id = artifact_uuid(key).map_err(WorkFailure::known)?;
    *worker = Some(store.capture_blocking(move || {
        run_worker(
            worker_store,
            worker_claim,
            lease,
            worker_permission,
            worker_auth,
            artifact_id,
            deadline,
            ready_sender,
            started_sender,
            worker_observer,
        )
    }));
    before(deadline, ready)
        .await?
        .map_err(|_| WorkFailure::known(Error::PhysicalUnproven))?
        .map_err(WorkFailure::known)?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Live,
        deadline,
    )
    .await?;
    claim
        .verify_precommit()
        .map_err(|_| WorkFailure::known(Error::ReadsUnproven))?;
    // Each allowed statement is followed by a new joint observation of current authority and
    // exactly its registered staged self-effects. No available-only decoder reads these NULLs.
    let record_count = sql(deadline, tx.execute(
        "UPDATE openbot_internal.artifact_records SET status='deleted',workspace_kind=NULL,workspace_id=NULL, \
         media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 \
           AND artifact_id=$5 AND status='available'",
        &[&key.deployment_id().as_str(), &key.tenant_id().as_str(), &key.dataset_id(),
            &key.operation_id().as_str(), &key.artifact_id()],
    )).await?;
    require_one(record_count, "record_pair")?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::RecordDeleted,
        deadline,
    )
    .await?;
    let operation_count = sql(deadline, tx.execute(
        "UPDATE openbot_internal.artifact_save_operations SET state='deleted',store_id=NULL, \
         workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL, \
         actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL, \
         observation_phase=NULL,created_at=NULL \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 \
           AND artifact_id=$5 AND state='available'",
        &[&key.deployment_id().as_str(), &key.tenant_id().as_str(), &key.dataset_id(),
            &key.operation_id().as_str(), &key.artifact_id()],
    )).await?;
    require_one(operation_count, "operation_pair")?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::PairDeleted,
        deadline,
    )
    .await?;
    let fence_count = sql(
        deadline,
        tx.execute(
            "UPDATE openbot_internal.artifact_cleanup_fences SET phase='completed' \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 \
           AND artifact_id=$5 AND terminal_status='deleted' AND phase='armed'",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &key.operation_id().as_str(),
                &key.artifact_id(),
            ],
        ),
    )
    .await?;
    require_one(fence_count, "cleanup_fence")?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::FenceCompleted,
        deadline,
    )
    .await?;
    let quota_count = sql(
        deadline,
        tx.execute(
            "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$6 \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 \
           AND workspace_id=$5 AND charged_bytes=$7",
            &[
                &key.deployment_id().as_str(),
                &key.tenant_id().as_str(),
                &key.dataset_id(),
                &original.facts.workspace_kind,
                &original.facts.workspace_id,
                &original.quota_after,
                &original.quota_before,
            ],
        ),
    )
    .await?;
    require_one(quota_count, "workspace_quota")?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Refunded,
        deadline,
    )
    .await?;
    let (id, created_at) = infra(deadline, next_event_coordinates(tx)).await?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Refunded,
        deadline,
    )
    .await?;
    let actual_audit_id =
        Uuid::parse_str(id.as_str()).map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let artifact = AuditIdentifier::new(key.artifact_id())
        .map_err(|_| WorkFailure::known(corrupt("stored_uuid")))?;
    let operation = AuditIdentifier::new(key.operation_id().as_str())
        .map_err(|_| WorkFailure::known(corrupt("stored_uuid")))?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type: AuditEventType::ARTIFACT_CLEANUP_COMPLETED,
        target_kind: AuditLabel::new("artifact"),
        target_id: Some(artifact.clone()),
        payload: AuditPayload::from_facts([
            AuditFact::ArtifactId(artifact),
            AuditFact::ArtifactOperationId(operation),
        ])
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?,
        created_at,
    };
    infra(
        deadline,
        append_event_in_transaction(tx, &event, administration.audit_key.expose()),
    )
    .await?;
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Refunded,
        deadline,
    )
    .await?;
    observe(
        observer,
        ArtifactCleanupTerminalPhase::BeforeCommit,
        artifact_id,
        None,
    );
    registered_remaining(claim, deadline).map_err(WorkFailure::known)?;
    // Returning from the observer never replaces final renewed staged RC or real IO checks.
    refresh_staged(
        current,
        tx,
        administration,
        auth,
        key,
        &original,
        Staged::Refunded,
        deadline,
    )
    .await?;
    verify_audit(tx, auth, key, actual_audit_id, deadline).await?;
    let tail: Arc<dyn ArtifactCleanupHostTailWitness> = Arc::from(
        refresh_staged(
            current,
            tx,
            administration,
            auth,
            key,
            &original,
            Staged::Refunded,
            deadline,
        )
        .await?,
    );
    permission
        .grant(claim, Arc::clone(&tail), deadline)
        .map_err(WorkFailure::known)?;
    before(deadline, started)
        .await?
        .map_err(|_| WorkFailure::known(Error::PhysicalUnproven))?
        .map_err(WorkFailure::known)?;
    registered_remaining(claim, deadline).map_err(WorkFailure::known)?;
    Ok(WorkOutcome {
        state: ArtifactCleanupTerminalState::Committed,
        audit_id: Some(actual_audit_id),
        tail,
    })
}

async fn verify_audit(
    tx: &Transaction<'_>,
    auth: &AuthContext,
    key: &ArtifactCleanupFenceKey,
    audit_id: Uuid,
    deadline: Instant,
) -> Result<(), WorkFailure> {
    let rows = sql(
        deadline,
        tx.query(
            "SELECT actor_user_id,event_type,target_type,target_id,payload \
         FROM public.audit_events WHERE id=$1",
            &[&audit_id],
        ),
    )
    .await?;
    if rows.len() != 1 {
        return Err(WorkFailure::known(corrupt("terminal_audit")));
    }
    let row = &rows[0];
    let actor: Option<String> = row
        .try_get("actor_user_id")
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let event_type: String = row
        .try_get("event_type")
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let target_kind: String = row
        .try_get("target_type")
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let target_id: Option<String> = row
        .try_get("target_id")
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let payload: Value = row
        .try_get("payload")
        .map_err(|_| WorkFailure::known(corrupt("terminal_audit")))?;
    let expected = serde_json::json!({
        "artifact_id": key.artifact_id(), "artifact_operation_id": key.operation_id().as_str(),
    });
    if actor.as_deref() != Some(auth.actor().as_str())
        || event_type != AuditEventType::ARTIFACT_CLEANUP_COMPLETED.as_str()
        || target_kind != "artifact"
        || target_id.as_deref() != Some(key.artifact_id())
        || payload != expected
    {
        return Err(WorkFailure::known(corrupt("terminal_audit")));
    }
    Ok(())
}

fn require_one(count: u64, field: &'static str) -> Result<(), WorkFailure> {
    if count == 1 {
        Ok(())
    } else {
        Err(WorkFailure::known(corrupt(field)))
    }
}

enum CommitPermission {
    Pending,
    Granted {
        claim: Arc<TerminalInvocationClaim>,
        tail: Arc<dyn ArtifactCleanupHostTailWitness>,
        deadline: Instant,
    },
    // This boundary is only permission to attempt the original COMMIT. It proves no effect/ACK.
    CommitStarted,
    Cancelled,
}

struct PermissionState {
    phase: CommitPermission,
    // Nongrant worker continuation only. No gate ACK or fact is derived from this signal.
    disposition_released: bool,
}

struct WorkerPermission {
    capture_operation: crate::artifact_store::CaptureMutationLease,
    state: Mutex<PermissionState>,
    changed: Condvar,
}

impl Drop for WorkerPermission {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.capture_operation.record_returned();
        }
    }
}

impl WorkerPermission {
    fn new(capture_operation: crate::artifact_store::CaptureMutationLease) -> Arc<Self> {
        Arc::new(Self {
            capture_operation,
            state: Mutex::new(PermissionState {
                phase: CommitPermission::Pending,
                disposition_released: false,
            }),
            changed: Condvar::new(),
        })
    }

    fn cancel(&self) {
        let retired = if let Ok(mut state) = self.state.lock() {
            match state.phase {
                CommitPermission::Pending | CommitPermission::Granted { .. } => Some(
                    std::mem::replace(&mut state.phase, CommitPermission::Cancelled),
                ),
                // Caller-only stop cannot undo a COMMIT which already won this boundary.
                CommitPermission::CommitStarted | CommitPermission::Cancelled => None,
            }
        } else {
            None
        };
        drop(retired); // No tail/claim owner is dropped while the permission mutex is held.
        self.changed.notify_all();
    }

    fn release_after_disposition(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.disposition_released = true;
        }
        self.changed.notify_all();
    }

    fn should_stop_precommit(&self, deadline: Instant) -> bool {
        Instant::now() >= deadline
            || self.state.lock().map_or(true, |state| {
                matches!(state.phase, CommitPermission::Cancelled) || state.disposition_released
            })
    }

    fn grant(
        &self,
        claim: &Arc<TerminalInvocationClaim>,
        tail: Arc<dyn ArtifactCleanupHostTailWitness>,
        deadline: Instant,
    ) -> Result<(), Error> {
        registered_remaining(claim, deadline)?;
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        if !matches!(state.phase, CommitPermission::Pending) || state.disposition_released {
            return Err(Error::Unavailable);
        }
        state.phase = CommitPermission::Granted {
            claim: Arc::clone(claim),
            tail,
            deadline,
        };
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    fn wait_granted(&self, deadline: Instant) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        loop {
            let wait = remaining(deadline)?;
            if state.disposition_released {
                return Err(Error::Unavailable);
            }
            match state.phase {
                CommitPermission::Granted { .. } => return Ok(()),
                CommitPermission::Cancelled | CommitPermission::CommitStarted => {
                    return Err(Error::Unavailable);
                }
                CommitPermission::Pending => {
                    let (next, _) = self
                        .changed
                        .wait_timeout(state, wait)
                        .map_err(|_| Error::PhysicalUnproven)?;
                    state = next;
                }
            }
        }
    }

    fn start_commit(
        &self,
        claim: &Arc<TerminalInvocationClaim>,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), Error> {
        // The worker already completed its last real guarded absence outside this mutex.
        // Permission -> gate is the sole nested order; no IO or await occurs under either.
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        let CommitPermission::Granted {
            claim: granted,
            tail,
            deadline: granted_deadline,
        } = &state.phase
        else {
            return Err(Error::Unavailable);
        };
        if state.disposition_released
            || !Arc::ptr_eq(claim, granted)
            || *granted_deadline != deadline
        {
            return Err(Error::Conflict);
        }
        registered_remaining(claim, deadline)?;
        tail.verify_current(auth, deadline).map_err(Error::Host)?;
        claim.verify_precommit().map_err(|_| Error::ReadsUnproven)?;
        registered_remaining(claim, deadline)?;
        let retired = std::mem::replace(&mut state.phase, CommitPermission::CommitStarted);
        drop(state);
        drop(retired);
        self.changed.notify_all();
        Ok(())
    }

    fn wait_disposition(&self, deadline: Instant) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::PhysicalUnproven)?;
        loop {
            let wait = remaining(deadline)?;
            if state.disposition_released {
                return Ok(());
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, wait)
                .map_err(|_| Error::PhysicalUnproven)?;
            state = next;
        }
    }
}

#[allow(clippy::too_many_arguments)] // One actual worker, exact claim and original two handshakes.
fn run_worker(
    store: Arc<DatasetBoundArtifactStore>,
    claim: Arc<TerminalInvocationClaim>,
    lease: TerminalWorkerLease,
    permission: Arc<WorkerPermission>,
    auth: AuthContext,
    artifact_id: Uuid,
    deadline: Instant,
    ready: oneshot::Sender<Result<(), Error>>,
    started: oneshot::Sender<Result<(), Error>>,
    observer: Option<Arc<dyn ArtifactCleanupTerminalObserver>>,
) -> Result<(), Error> {
    // Declared before every original IO/FD local. On panic/error unwinding drops the real
    // resources before lease Drop records ended+unproven; normal errors explicitly finish below.
    let mut original_lease = lease;
    let mut ready = Some(ready);
    let mut started = Some(started);
    let result = (|| {
        original_lease
            .mark_started()
            .map_err(|_| Error::ReadsUnproven)?;
        let io = store
            .try_physical_io_before_admitted(deadline, &permission.capture_operation)
            .map_err(store_error)?;
        let precommit = (|| {
            let mut stop = |_| permission.should_stop_precommit(deadline);
            require_absent(&claim, io.probe_actual_guarded(artifact_id, &mut stop))?;
            observe(
                &observer,
                ArtifactCleanupTerminalPhase::AbsenceGuarded,
                artifact_id,
                None,
            );
            registered_remaining(&claim, deadline)?;
            ready
                .take()
                .ok_or(Error::PhysicalUnproven)?
                .send(Ok(()))
                .map_err(|_| Error::Unavailable)?;
            permission.wait_granted(deadline)?;
            // This final real root/children/absence/sync is AFTER final RC/audit/observer waits,
            // and still under this worker's ONE continuously retained original IO guard.
            require_absent(&claim, io.probe_actual_guarded(artifact_id, &mut stop))?;
            permission.start_commit(&claim, &auth, deadline)?;
            started
                .take()
                .ok_or(Error::PhysicalUnproven)?
                .send(Ok(()))
                .map_err(|_| Error::Unavailable)?;
            Ok::<_, Error>(())
        })();
        if let Err(error) = precommit {
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(error));
            }
            if let Some(sender) = started.take() {
                let _ = sender.send(Err(error));
            }
        }
        // Even a known precommit refusal keeps this same guard until the true original
        // rollback (or explicitly unproven main loss) lets the worker continue. No fake ACK.
        if let Err(error) = permission.wait_disposition(deadline) {
            claim.mark_unproven();
            return Err(error);
        }
        // Caller-only cancellation after CommitStarted does not erase effects or make a
        // healthy on-time final physical observation fail; the original clock still applies.
        let mut final_stop = |_| Instant::now() >= deadline;
        let final_actual = io.probe_actual_guarded(artifact_id, &mut final_stop);
        require_absent(&claim, final_actual)?;
        registered_remaining(&claim, deadline)?;
        drop(io);
        Ok(())
    })();
    if let Some(sender) = ready {
        let _ = sender.send(Err(result
            .as_ref()
            .err()
            .copied()
            .unwrap_or(Error::PhysicalUnproven)));
    }
    if let Some(sender) = started {
        let _ = sender.send(Err(result
            .as_ref()
            .err()
            .copied()
            .unwrap_or(Error::PhysicalUnproven)));
    }
    // The inner scope dropped all its actual temporary descriptors and original !Send guard.
    original_lease.finish_after_resources();
    observe(
        &observer,
        ArtifactCleanupTerminalPhase::WorkerEnded,
        artifact_id,
        None,
    );
    registered_remaining(&claim, deadline)?;
    result
}

fn require_absent(claim: &TerminalInvocationClaim, actual: ArtifactByteProbe) -> Result<(), Error> {
    if matches!(actual, ArtifactByteProbe::Absent) {
        Ok(())
    } else {
        claim.mark_unproven();
        Err(Error::PhysicalUnproven)
    }
}

fn observe(
    observer: &Option<Arc<dyn ArtifactCleanupTerminalObserver>>,
    phase: ArtifactCleanupTerminalPhase,
    artifact_id: Uuid,
    original_leaf_fd: Option<RawFd>,
) {
    if let Some(observer) = observer {
        observer.on_phase(phase, artifact_id, original_leaf_fd);
    }
}

fn publish_mode(state: ArtifactCleanupTerminalState) -> TerminalPublishMode {
    match state {
        ArtifactCleanupTerminalState::Committed => TerminalPublishMode::CommittedWorker,
        ArtifactCleanupTerminalState::AlreadyCompleted => TerminalPublishMode::CompletedNoWorker,
    }
}

fn artifact_uuid(key: &ArtifactCleanupFenceKey) -> Result<Uuid, Error> {
    Uuid::parse_str(key.artifact_id()).map_err(|_| corrupt("stored_uuid"))
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::DeadlineExpired)
}

fn registered_remaining(
    claim: &TerminalInvocationClaim,
    deadline: Instant,
) -> Result<Duration, Error> {
    let result = remaining(deadline);
    if result.is_err() {
        claim.mark_unproven();
    }
    result
}

async fn before<T>(deadline: Instant, future: impl Future<Output = T>) -> Result<T, WorkFailure> {
    remaining(deadline).map_err(|_| WorkFailure::elapsed())?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| WorkFailure::elapsed())?;
    remaining(deadline).map_err(|_| WorkFailure::elapsed())?;
    Ok(result)
}

async fn sql<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, tokio_postgres::Error>>,
) -> Result<T, WorkFailure> {
    before(deadline, future)
        .await?
        .map_err(|error| WorkFailure {
            error: Error::Unavailable,
            query_unproven: error.as_db_error().is_none(),
        })
}

async fn infra<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, InfraError>>,
) -> Result<T, WorkFailure> {
    before(deadline, future).await?.map_err(|error| {
        let query_unproven = matches!(&error, InfraError::Connect { .. })
            || matches!(&error, InfraError::Query { .. }) && error.sqlstate().is_none();
        WorkFailure {
            error: Error::Unavailable,
            query_unproven,
        }
    })
}

fn arm_error(error: ArtifactCleanupArmError) -> Error {
    match error {
        ArtifactCleanupArmError::Host(error) => Error::Host(error),
        ArtifactCleanupArmError::NotVisible => Error::NotVisible,
        ArtifactCleanupArmError::Conflict | ArtifactCleanupArmError::InvalidInput { .. } => {
            Error::Conflict
        }
        ArtifactCleanupArmError::Corrupt { field } => Error::Corrupt { field },
        ArtifactCleanupArmError::CommitUnknown => Error::CommitUnknown,
        ArtifactCleanupArmError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        ArtifactCleanupArmError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        ArtifactCleanupArmError::Unavailable => Error::Unavailable,
    }
}

fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::CommitUnknown => Error::CommitUnknown,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
        TransactionOwnerError::DeadlineExceeded => Error::DeadlineExpired,
        _ => Error::Unavailable,
    }
}

fn store_error(error: ArtifactStoreError) -> Error {
    match error {
        ArtifactStoreError::BindingMismatch | ArtifactStoreError::UnsafeRoot => {
            corrupt("store_binding")
        }
        ArtifactStoreError::Unavailable | ArtifactStoreError::Busy => Error::Unavailable,
    }
}

fn corrupt(field: &'static str) -> Error {
    Error::Corrupt { field }
}

fn column<'a, T: FromSql<'a>>(row: &'a Row, field: &str) -> Result<T, Error> {
    row.try_get(field).map_err(|_| corrupt("record_pair"))
}

fn member<'a>(value: &'a Value, field: &str, tag: &'static str) -> Result<&'a Value, Error> {
    value
        .as_object()
        .and_then(|value| value.get(field))
        .ok_or(corrupt(tag))
}

fn text<'a>(value: &'a Value, field: &str, tag: &'static str) -> Result<&'a str, Error> {
    member(value, field, tag)?.as_str().ok_or(corrupt(tag))
}

fn number(value: &Value, field: &str, tag: &'static str) -> Result<i64, Error> {
    member(value, field, tag)?.as_i64().ok_or(corrupt(tag))
}

pub(super) fn current_joint_sql(desktop: bool) -> &'static str {
    static SERVER: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    (if desktop { &DESKTOP } else { &SERVER }).get_or_init(|| {
        let (canary_columns, canary_joins) = if desktop { (
            ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
             CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
             CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
             CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
             CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
             c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
             CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
            " LEFT JOIN pg_control_system() pcs ON true LEFT JOIN pg_database d ON d.datname=current_database() \
              LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$1 AND c.tenant_id=$2 AND c.key_version=1",
        ) } else { ("", "") };
        format!("/* artifact_cleanup_terminal_current_joint */ SELECT to_jsonb(r) AS record_row, \
          to_jsonb(o) AS operation_row,to_jsonb(p) AS receipt_row,to_jsonb(f) AS fence_row, \
          u.id AS current_actor,u.auth_generation AS current_generation,u.email AS current_email, \
          EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
          ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles, \
          s.id AS session_id,s.user_id AS session_user,s.token AS session_token,s.created_at AS session_created, \
          s.updated_at AS session_updated,s.expires_at AS session_expires,s.auth_generation AS session_generation, \
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings db \
            JOIN openbot_internal.artifact_store_bindings sb USING(deployment_id,tenant_id,dataset_id) \
            WHERE db.deployment_id=$1 AND db.tenant_id=$2 AND db.dataset_id=$3 AND db.binding_schema=$7 \
              AND db.initial_origin=$8 AND db.created_at=$9 AND sb.store_id=$10 \
              AND sb.root_device=$11 AND sb.root_inode=$12 AND sb.root_uid=$13) AS store_matches {canary_columns} \
          FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$5 \
          LEFT JOIN public.sessions s ON s.id=$6 AND s.user_id=u.id \
          LEFT JOIN openbot_internal.artifact_records r ON r.deployment_id=$1 AND r.tenant_id=$2 AND r.dataset_id=$3 AND r.artifact_id=$4 \
          LEFT JOIN openbot_internal.artifact_save_operations o ON o.deployment_id=r.deployment_id AND o.tenant_id=r.tenant_id AND o.dataset_id=r.dataset_id AND o.operation_id=r.operation_id \
          LEFT JOIN openbot_internal.artifact_saved_receipts p ON p.deployment_id=r.deployment_id AND p.tenant_id=r.tenant_id AND p.dataset_id=r.dataset_id AND p.operation_id=r.operation_id \
          LEFT JOIN openbot_internal.artifact_cleanup_fences f ON f.deployment_id=r.deployment_id AND f.tenant_id=r.tenant_id AND f.dataset_id=r.dataset_id AND f.artifact_id=r.artifact_id {canary_joins}")
    })
}

#[allow(clippy::too_many_arguments)] // One original invocation and its nongrant inputs only.
async fn supervise(
    administration: Arc<PostgresArtifactAdministration>,
    auth: AuthContext,
    store: Arc<DatasetBoundArtifactStore>,
    key: ArtifactCleanupFenceKey,
    claim: Arc<TerminalInvocationClaim>,
    query: TerminalInvocationQueryOwner,
    permission: Arc<WorkerPermission>,
    deadline: Instant,
    observer: Option<Arc<dyn ArtifactCleanupTerminalObserver>>,
) -> Result<ArtifactCleanupTerminalObservation, Error> {
    let mut main = MainQueryOwner {
        permission: Arc::clone(&permission),
        query: Some(query),
        worker: None,
        claim: Arc::clone(&claim),
        deadline,
        original_main_handled: false,
    };
    // Only an actual normal return from the original body acknowledges handled completion.
    // Known current-Host refusals keep their true rollback/commit disposition; unwinding or
    // abort never reaches this assignment, including after the typed ACK consumed the query.
    let handled_outcome = async {
    let authority = administration.read_authority();
    let target = authority.cleanup_host_target(&auth);
    let current = TerminalCurrentRequest::borrow_before(&administration, &auth, &target, deadline);
    let mut client = administration
        .registry
        .pool()
        .get_guarded(deadline)
        .await
        .map_err(|_| Error::Unavailable)?;
    let schema = before(deadline, verify_artifact_read_schema_on(client.as_client()))
        .await
        .map_err(|failure| failure.error)?;
    schema.map_err(|error| match error {
        openbot_application::ArtifactAdministrationError::Unavailable => Error::Unavailable,
        _ => corrupt("schema"),
    })?;
    let transaction = client.begin_read_committed().await.map_err(owner_error)?;
    let result = match current {
        Ok(current) => {
            work_before(
                &administration,
                &auth,
                &store,
                &key,
                &claim,
                &permission,
                &current,
                transaction.as_transaction(),
                &mut main.worker,
                deadline,
                &observer,
            )
            .await
        }
        Err(error) => Err(WorkFailure::known(arm_error(error))),
    };
    let committed =
        matches!(&result, Ok(outcome) if outcome.state == ArtifactCleanupTerminalState::Committed);
    if let Err(failure) = &result {
        permission.cancel();
        if failure.query_unproven {
            claim.mark_unproven();
        }
    }
    // The worker still owns the original IO guard here. It waits for the original disposition,
    // never for worker-ended before COMMIT/ROLLBACK. The typed owner is consumed only after ACK.
    let acknowledgement = if committed {
        transaction.commit().await
    } else {
        transaction.rollback().await
    };
    if let Err(error) = acknowledgement {
        claim.mark_unproven();
        permission.release_after_disposition();
        return Err(owner_error(error));
    }
    let query = main.query.take().ok_or(Error::ReadsUnproven)?;
    let registered = if committed {
        let audit_id = result
            .as_ref()
            .ok()
            .and_then(|outcome| outcome.audit_id)
            .ok_or(corrupt("terminal_audit"))?;
        query.acknowledge_commit(audit_id)
    } else {
        query.acknowledge_rollback()
    };
    // Registration failure after real commit ACK is a known committed refusal, not Unknown.
    if registered.is_err() {
        claim.mark_unproven();
        permission.release_after_disposition();
        return Err(Error::ReadsUnproven);
    }
    if committed {
        observe(
            &observer,
            ArtifactCleanupTerminalPhase::AfterCommitAckBeforeWorkerEnd,
            artifact_uuid(&key)?,
            None,
        );
    }
    let post_ack_clock = registered_remaining(&claim, deadline);
    permission.release_after_disposition();
    // The original worker's post-disposition final absence/sync and actual FD/IO drop come
    // AFTER the true ACK/fact. An error here preserves its already known committed truth.
    let worker_result = if let Some(mut worker) = main.worker.take() {
        before(deadline, &mut worker)
            .await
            .map_err(|failure| failure.error)?
            .map_err(|_| {
                claim.mark_unproven();
                Error::PhysicalUnproven
            })?
    } else {
        Ok(())
    };
    post_ack_clock?;
    registered_remaining(&claim, deadline)?;
    worker_result?;
    let outcome = result.map_err(|failure| failure.error)?;
    let tail = outcome.tail.verify_current(&auth, deadline);
    registered_remaining(&claim, deadline)?;
    tail.map_err(Error::Host)?;
    let published = claim.verify_terminal_publish(publish_mode(outcome.state));
    registered_remaining(&claim, deadline)?;
    published.map_err(|_| Error::ReadsUnproven)?;
    Ok(ArtifactCleanupTerminalObservation {
        claim,
        _original_store: store,
        _original_key: key,
        original_tail: outcome.tail,
        deadline,
        state: outcome.state,
    })
    }.await;
    main.original_main_handled = true;
    handled_outcome
}
