//! R424 real user-message registration. Every mutation owns its registry Pool and RC transaction.
//! Durable admission and IO_STARTED acknowledgements precede once-only physical IO. Unknown
//! outcomes retain the original operation/charge; observation never grants a retry or byte read.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{ArtifactAdministration, ArtifactAdministrationError};
use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactMetadata, ArtifactRecordMetadata, ArtifactRegistrationReceipt,
    ArtifactRetentionClass, ArtifactTombstone, ArtifactWorkspace, SaveRunMessageTextArtifact,
    canonical_artifact_uuid_v7, is_valid_artifact_identity, is_valid_artifact_sha256,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::artifact::{ArtifactQuotaPolicy, ArtifactWorkspaceKey};
use openbot_domain::artifact_cleanup::{
    ArtifactCleanupFence, ArtifactCleanupFenceKey, ArtifactCleanupFencePhase,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::secret::SecretBytes;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row, Transaction};
use uuid::Uuid;

use crate::artifact_bytes::ArtifactBlob;
use crate::artifact_registry::{ARTIFACT_REGISTRY_SCHEMA_SQL, ArtifactDatasetRegistry};
use crate::artifact_store::{
    ArtifactByteObservationState, ArtifactByteWritePhase, ArtifactReadControlledBarrier,
    ArtifactStoreError, DatasetBoundArtifactStore, VerifiedArtifactByteObservation,
};
use crate::db::InfraError;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::thread_directory::reconciliation_visibility::VISIBLE_RUN;
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

#[path = "artifact_read_authority.rs"]
pub mod artifact_read_authority;
#[path = "artifact_read_lifecycle.rs"]
pub mod artifact_read_lifecycle;

#[path = "artifact_administration/cleanup_arm.rs"]
mod cleanup_arm;
pub use cleanup_arm::{ArmedArtifactCleanupIntent, ArtifactCleanupArmError};

#[path = "artifact_administration/cleanup_physical.rs"]
mod cleanup_physical;
pub use cleanup_physical::{
    ArtifactCleanupPhysicalError, ArtifactCleanupPhysicalIoPhase,
    ArtifactCleanupPhysicalObservation, ArtifactCleanupPhysicalObserver,
    ArtifactCleanupPhysicalState,
};

#[path = "artifact_administration/cleanup_terminal.rs"]
mod cleanup_terminal;
pub use cleanup_terminal::{
    ArtifactCleanupTerminalError, ArtifactCleanupTerminalObservation,
    ArtifactCleanupTerminalObserver, ArtifactCleanupTerminalPhase, ArtifactCleanupTerminalState,
};

const WAIT: Duration = Duration::from_secs(5);
const PG_PHASE: Duration = Duration::from_secs(30);
const MEDIA: &str = "text/plain; charset=utf-8";
const TABLES: [&str; 6] = [
    "artifact_store_bindings",
    "artifact_workspace_quotas",
    "artifact_run_quotas",
    "artifact_save_operations",
    "artifact_records",
    "artifact_saved_receipts",
];
// Independently captured from the owned actual native0042 PostgreSQL schema. Runtime compares
// every captured catalog field exactly; capture itself never depends on this oracle.
const REGISTERED_REGISTRATION_SCHEMA: &str =
    include_str!("../../../fixtures/db/artifact-registration-0042.json");

/// Real ordered catalog observations, independently frozen by the schema generation test.
pub type ArtifactRegistrationSchemaFacts = Value;

/// Capture the six real internal relations, including exact guards, collation and enabled hooks.
pub async fn capture_artifact_registration_schema(
    pool: &Pool,
) -> Result<ArtifactRegistrationSchemaFacts, ArtifactAdministrationError> {
    let client = tokio::time::timeout(WAIT, pool.get())
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    capture_artifact_registration_schema_on(&client).await
}

/// Capture the original registration facts on this exact caller-owned connection.
pub(crate) async fn capture_artifact_registration_schema_on(
    client: &tokio_postgres::Client,
) -> Result<ArtifactRegistrationSchemaFacts, ArtifactAdministrationError> {
    let mut tables = Map::new();
    for name in TABLES {
        let sql = ARTIFACT_REGISTRY_SCHEMA_SQL.replace("artifact_dataset_bindings", name);
        let row = tokio::time::timeout(WAIT, client.query_one(&sql, &[]))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let raw: String = row.try_get(0).map_err(|_| corrupt("schema_facts"))?;
        tables.insert(
            name.to_owned(),
            serde_json::from_str(&raw).map_err(|_| corrupt("schema_facts"))?,
        );
    }
    let row = tokio::time::timeout(WAIT, client.query_one(
        "SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'definition',pg_get_functiondef(p.oid),         'arguments',pg_get_function_identity_arguments(p.oid),'securityDefiner',p.prosecdef,'configuration',p.proconfig)         ORDER BY p.proname),'[]'::jsonb)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace         WHERE n.nspname='openbot_internal' AND p.proname IN ('prevent_artifact_operation_misuse','prevent_artifact_record_misuse')", &[])).await
        .map_err(|_| unavailable())?.map_err(|_| unavailable())?;
    let raw: String = row.try_get(0).map_err(|_| corrupt("schema_guards"))?;
    tables.insert(
        "registration_guards".to_owned(),
        serde_json::from_str(&raw).map_err(|_| corrupt("schema_guards"))?,
    );
    Ok(Value::Object(tables))
}

/// Verify current native/public/registry facts and the independently captured registration oracle.
pub async fn verify_artifact_registration_schema(
    pool: &Pool,
) -> Result<(), ArtifactAdministrationError> {
    tokio::time::timeout(PG_PHASE, verify_registration_schema_inner(pool))
        .await
        .map_err(|_| unavailable())?
}

async fn verify_registration_schema_inner(pool: &Pool) -> Result<(), ArtifactAdministrationError> {
    crate::artifact_registry::verify_artifact_registry_schema(pool)
        .await
        .map_err(|_| corrupt("registry_schema"))?;
    let expected: Value = serde_json::from_str(REGISTERED_REGISTRATION_SCHEMA)
        .map_err(|_| corrupt("registration_oracle"))?;
    if capture_artifact_registration_schema(pool).await? != expected {
        return Err(corrupt("registration_schema"));
    }
    Ok(())
}

/// Reader-only composition; Save and metadata keep their original registration boundary.
pub(crate) async fn verify_artifact_read_schema_on(
    client: &tokio_postgres::Client,
) -> Result<(), ArtifactAdministrationError> {
    crate::artifact_registry::verify_artifact_registry_schema_on(client)
        .await
        .map_err(|error| match error {
            crate::artifact_registry::ArtifactRegistryError::Unavailable => unavailable(),
            _ => corrupt("registry_schema"),
        })?;
    let expected: Value = serde_json::from_str(REGISTERED_REGISTRATION_SCHEMA)
        .map_err(|_| corrupt("registration_oracle"))?;
    if capture_artifact_registration_schema_on(client).await? != expected {
        return Err(corrupt("registration_schema"));
    }
    crate::db::artifact_cleanup_schema::verify(client)
        .await
        .map_err(|error| match error {
            crate::db::artifact_cleanup_schema::ArtifactCleanupSchemaError::Unavailable => {
                unavailable()
            }
            _ => corrupt("read_cleanup_schema"),
        })
}

/// Refusal to install the one bounded original-request diagnostic recorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SaveProducerDiagnosticInstallError {
    /// The original selector is not a canonical UUIDv7.
    #[error("save_producer_diagnostic_invalid_request_id")]
    InvalidRequestId,
    /// This original administration already has a diagnostic registration.
    #[error("save_producer_diagnostic_already_installed")]
    AlreadyInstalled,
}

/// Original top-level Save boundary, with no SQL or user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveProducerDiagnosticStage {
    /// Validate the original request and selectors.
    ValidateInput,
    /// Check the original deployment and tenant.
    CheckNamespace,
    /// Verify the existing registration schema.
    VerifyRegistrationSchema,
    /// Observe space through the existing blocking worker.
    AvailableBytes,
    /// Execute the original durable admission.
    Admit,
    /// Execute the original IO_STARTED transaction.
    StartIo,
    /// Prepare and wait for the existing once-only write worker.
    WriteWorker,
    /// Execute the original finalization.
    Finalize,
}

/// The original return class before Application erases closed Infra errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveProducerDiagnosticTerminal {
    /// The original method actually returned its successful receipt.
    Success,
    /// The original method returned this unchanged closed Infra error.
    Error(ArtifactAdministrationError),
}

/// Fieldless phase copied only from an actual returned write observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveProducerDiagnosticWorkerPhase {
    /// The original write did not enter staging.
    BeforeWrite,
    /// The original observation reports staging.
    Staging,
    /// The original observation reports installation.
    Installing,
    /// The original observation reports an installed phase.
    Installed,
}

/// Fieldless state copied only from an actual returned write observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveProducerDiagnosticWorkerState {
    /// The original observation reports durable installation.
    DurableInstalled,
    /// The original observation reports durable absence.
    DurableAbsent,
    /// The original observation reports retained partial bytes.
    RetainedPartial,
    /// The original observation is indeterminate.
    Indeterminate,
}

/// Fixed boundary reached in the original finalization; no label proves completion or ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveFinalizeDiagnosticSubstage {
    /// Check the original byte observation and Store owner.
    ByteOwnerCheck,
    /// Check out the original connection.
    Checkout,
    /// Begin the original transaction.
    Begin,
    /// Run its existing setup helper.
    Setup,
    /// Observe the original actor and source authority.
    InitialAuthority,
    /// Check the original binding and lock its quota.
    BindingAndQuota,
    /// Load and validate the original operation.
    LoadAndValidateOperation,
    /// Obtain the existing audit coordinates when required.
    AuditCoordinates,
    /// Recheck the original source and binding.
    FreshAuthority,
    /// Classify the original observation and charge.
    ObservationAndCharge,
    /// Insert the original available or partial record when required.
    InsertRecord,
    /// Read and update the original workspace charge.
    ReadAndUpdateQuota,
    /// Update the original operation.
    UpdateOperation,
    /// Insert the original positive saved receipt when required.
    InsertReceipt,
    /// Build and append the existing saved audit event.
    AppendAudit,
    /// Recheck the original authority after later waits.
    FinalAuthority,
    /// Call the original commit helper.
    Commit,
    /// Return the original result after the commit helper returned.
    ReturnReceipt,
}

/// Fixed category of an actual direct PostgreSQL error, without retained error data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveFinalizePgCodeCategory {
    /// PostgreSQL reported a not-null violation.
    NotNullViolation,
    /// PostgreSQL reported a foreign-key violation.
    ForeignKeyViolation,
    /// PostgreSQL reported a unique violation.
    UniqueViolation,
    /// PostgreSQL reported a check violation.
    CheckViolation,
    /// PostgreSQL reported an undefined table.
    UndefinedTable,
    /// PostgreSQL reported an undefined column.
    UndefinedColumn,
    /// PostgreSQL reported a datatype mismatch.
    DatatypeMismatch,
    /// PostgreSQL reported a serialization failure.
    SerializationFailure,
    /// PostgreSQL reported a deadlock.
    DeadlockDetected,
    /// PostgreSQL reported an unavailable lock.
    LockNotAvailable,
    /// PostgreSQL reported cancellation of a query.
    QueryCanceled,
    /// PostgreSQL reported a failed SQL transaction.
    FailedSqlTransaction,
    /// The direct error has a different database code.
    OtherDatabaseCode,
    /// The actual direct error has no database code.
    NoDatabaseCode,
}

impl SaveFinalizePgCodeCategory {
    fn from_error(error: &tokio_postgres::Error) -> Self {
        match error.code().map(|code| code.code()) {
            Some("23502") => Self::NotNullViolation,
            Some("23503") => Self::ForeignKeyViolation,
            Some("23505") => Self::UniqueViolation,
            Some("23514") => Self::CheckViolation,
            Some("42P01") => Self::UndefinedTable,
            Some("42703") => Self::UndefinedColumn,
            Some("42804") => Self::DatatypeMismatch,
            Some("40001") => Self::SerializationFailure,
            Some("40P01") => Self::DeadlockDetected,
            Some("55P03") => Self::LockNotAvailable,
            Some("57014") => Self::QueryCanceled,
            Some("25P02") => Self::FailedSqlTransaction,
            Some(_) => Self::OtherDatabaseCode,
            None => Self::NoDatabaseCode,
        }
    }
}

/// Original closed error or existing explicit refusal branch, without raw cause data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveFinalizeDiagnosticFailure {
    /// A helper or original expression returned this unchanged closed error.
    OriginalClosedResult(ArtifactAdministrationError),
    /// The original operation state or artifact identifier did not match.
    OperationStateMismatch,
    /// The original post-commit branch returned no positive receipt.
    NonPositiveReturn,
    /// A direct PostgreSQL result actually returned this fixed category.
    DirectPg(SaveFinalizePgCodeCategory),
}

/// Fixed nongrant facts; a missing terminal or `lost` remains UNKNOWN.
/// Neither worker flag proves driver, thread, descriptor or resource closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaveProducerDiagnosticSnapshot {
    /// Last recorded original top-level boundary.
    pub main_stage: Option<SaveProducerDiagnosticStage>,
    /// Actual original return, if the caller reached one.
    pub main_terminal: Option<SaveProducerDiagnosticTerminal>,
    /// Last recorded original finalization boundary, not its successful completion.
    pub finalize_substage: Option<SaveFinalizeDiagnosticSubstage>,
    /// Last observed finalization error or existing explicit refusal branch.
    pub finalize_failure: Option<SaveFinalizeDiagnosticFailure>,
    /// The existing write closure actually began.
    pub worker_entered: bool,
    /// The existing write call actually returned an observation.
    pub worker_returned: bool,
    /// Fieldless phase of that returned observation.
    pub worker_phase: Option<SaveProducerDiagnosticWorkerPhase>,
    /// Fieldless state of that returned observation.
    pub worker_state: Option<SaveProducerDiagnosticWorkerState>,
    /// Ambiguity or a failed nonblocking observation invalidates all facts.
    pub lost: bool,
}

impl SaveProducerDiagnosticSnapshot {
    const fn empty(lost: bool) -> Self {
        Self {
            main_stage: None,
            main_terminal: None,
            finalize_substage: None,
            finalize_failure: None,
            worker_entered: false,
            worker_returned: false,
            worker_phase: None,
            worker_state: None,
            lost,
        }
    }
}

#[derive(Clone, Copy)]
enum SaveProducerDiagnosticEvent {
    Stage(SaveProducerDiagnosticStage),
    Terminal(SaveProducerDiagnosticTerminal),
    FinalizeSubstage(SaveFinalizeDiagnosticSubstage),
    FinalizeFailure(SaveFinalizeDiagnosticFailure),
    WorkerEntered,
    WorkerReturned(
        SaveProducerDiagnosticWorkerPhase,
        SaveProducerDiagnosticWorkerState,
    ),
}

/// One private strict selector and fixed facts only; holds no business resource or backlink.
pub struct SaveProducerDiagnosticCapture {
    original_request_id: String,
    claimed: AtomicBool,
    lost: AtomicBool,
    facts: Mutex<SaveProducerDiagnosticSnapshot>,
}

impl SaveProducerDiagnosticCapture {
    fn new(original_request_id: String) -> Self {
        Self {
            original_request_id,
            claimed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            facts: Mutex::new(SaveProducerDiagnosticSnapshot::empty(false)),
        }
    }

    fn begin_original(self: &Arc<Self>, original_request_id: &str) -> Option<Arc<Self>> {
        if original_request_id != self.original_request_id.as_str() {
            return None;
        }
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.lost.store(true, Ordering::Release);
            return None;
        }
        Some(Arc::clone(self))
    }

    fn record(&self, event: SaveProducerDiagnosticEvent) {
        if self.lost.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut facts) = self.facts.try_lock() else {
            self.lost.store(true, Ordering::Release);
            return;
        };
        match event {
            SaveProducerDiagnosticEvent::Stage(stage) => facts.main_stage = Some(stage),
            SaveProducerDiagnosticEvent::Terminal(terminal) => facts.main_terminal = Some(terminal),
            SaveProducerDiagnosticEvent::FinalizeSubstage(stage) => {
                facts.finalize_substage = Some(stage);
            }
            SaveProducerDiagnosticEvent::FinalizeFailure(failure) => {
                facts.finalize_failure = Some(failure);
            }
            SaveProducerDiagnosticEvent::WorkerEntered => facts.worker_entered = true,
            SaveProducerDiagnosticEvent::WorkerReturned(phase, state) => {
                facts.worker_returned = true;
                facts.worker_phase = Some(phase);
                facts.worker_state = Some(state);
            }
        }
    }

    fn record_worker_returned(&self, observation: &VerifiedArtifactByteObservation) {
        let phase = match observation.phase() {
            ArtifactByteWritePhase::BeforeWrite => SaveProducerDiagnosticWorkerPhase::BeforeWrite,
            ArtifactByteWritePhase::Staging => SaveProducerDiagnosticWorkerPhase::Staging,
            ArtifactByteWritePhase::Installing => SaveProducerDiagnosticWorkerPhase::Installing,
            ArtifactByteWritePhase::Installed => SaveProducerDiagnosticWorkerPhase::Installed,
        };
        let state = match observation.state() {
            ArtifactByteObservationState::DurableInstalled { .. } => {
                SaveProducerDiagnosticWorkerState::DurableInstalled
            }
            ArtifactByteObservationState::DurableAbsent => {
                SaveProducerDiagnosticWorkerState::DurableAbsent
            }
            ArtifactByteObservationState::RetainedPartial { .. } => {
                SaveProducerDiagnosticWorkerState::RetainedPartial
            }
            ArtifactByteObservationState::Indeterminate => {
                SaveProducerDiagnosticWorkerState::Indeterminate
            }
        };
        self.record(SaveProducerDiagnosticEvent::WorkerReturned(phase, state));
    }

    /// Copy fixed facts without waiting. Loss or contention yields only UNKNOWN.
    #[must_use]
    pub fn snapshot(&self) -> SaveProducerDiagnosticSnapshot {
        let Ok(facts) = self.facts.try_lock() else {
            self.lost.store(true, Ordering::Release);
            return SaveProducerDiagnosticSnapshot::empty(true);
        };
        if self.lost.load(Ordering::Acquire) {
            SaveProducerDiagnosticSnapshot::empty(true)
        } else {
            *facts
        }
    }
}

/// Shared authenticated save adapter, retaining the exact trusted dataset and live byte owner.
pub struct PostgresArtifactAdministration {
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    policy: ArtifactQuotaPolicy,
    audit_key: SecretBytes,
    read_authority: OnceLock<Arc<artifact_read_authority::PostgresArtifactReadAuthority>>,
    cleanup_physical_observer: OnceLock<Arc<dyn ArtifactCleanupPhysicalObserver>>,
    save_producer_diagnostic: OnceLock<Arc<SaveProducerDiagnosticCapture>>,
}

/// A single owned-PG record/source snapshot bound to its exact actual byte-store owner.
///
/// Private construction prevents a metadata DTO or caller-provided digest from becoming a
/// descriptor. This value is deliberately not a current session/window ticket: authorization
/// can change after its final PostgreSQL statement. A future public byte handoff must recheck
/// its own current host and source authority. Move this value into the actual blocking job;
/// dropping a future waiting for that job does not stop IO or release the job's root owner.
pub struct ObservedArtifactReadRecord {
    store: Arc<DatasetBoundArtifactStore>,
    blob: ArtifactBlob,
    auth_snapshot: AuthContext,
    source_snapshot: ArtifactRegistrationReceipt,
    workspace_snapshot: ArtifactWorkspaceKey,
}

impl core::fmt::Debug for ObservedArtifactReadRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObservedArtifactReadRecord")
            .field("record_and_source", &"<redacted snapshot>")
            .finish()
    }
}

impl ObservedArtifactReadRecord {
    pub(crate) fn read_cleanup_key(&self) -> Result<ArtifactCleanupFenceKey, ArtifactStoreError> {
        if !self.matches_store(&self.store) {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        ArtifactCleanupFenceKey::from_stored(
            self.auth_snapshot.deployment().clone(),
            self.auth_snapshot.tenant().clone(),
            self.store.read_dataset_id(),
            &self.source_snapshot.operation_id,
            &self.source_snapshot.artifact_id,
        )
        .map_err(|_| ArtifactStoreError::BindingMismatch)
    }

    pub(crate) fn matches_store(&self, store: &Arc<DatasetBoundArtifactStore>) -> bool {
        Arc::ptr_eq(&self.store, store)
            && self.source_snapshot.artifact_id == self.blob.id().to_string()
            && self.source_snapshot.owner_actor_id == *self.auth_snapshot.actor()
            && is_valid_artifact_identity(self.workspace_snapshot.id())
    }

    pub(crate) const fn blob(&self) -> &ArtifactBlob {
        &self.blob
    }
}

/// Failure of only the new supervised snapshot, with actual rollback uncertainty separate.
pub(super) struct PublicReadRecordFailure {
    pub(super) error: ArtifactAdministrationError,
    pub(super) rollback_unproven: bool,
}
impl PublicReadRecordFailure {
    pub(super) fn schema(error: ArtifactAdministrationError, deadline: std::time::Instant) -> Self {
        // A completed catalog mismatch precedes BEGIN and has no pending transaction ACK.
        // Connection/query failures retain their Unavailable type through every schema layer.
        if matches!(error, ArtifactAdministrationError::Corrupt { .. })
            && std::time::Instant::now() < deadline
        {
            Self::observed(error)
        } else {
            Self::unproven(error)
        }
    }
    fn observed(error: ArtifactAdministrationError) -> Self {
        Self {
            error,
            rollback_unproven: false,
        }
    }
    fn unproven(error: ArtifactAdministrationError) -> Self {
        Self {
            error,
            rollback_unproven: true,
        }
    }
}

impl PostgresArtifactAdministration {
    /// Permanently close only this original Store's controlled read inventory.
    /// This trusted Rust port grants no delete permission or physical cleanup proof.
    ///
    /// # Errors
    /// Refuses a foreign or malformed original snapshot and unavailable shared inventory.
    pub fn close_observed_artifact_reads(
        self: &Arc<Self>,
        record: &ObservedArtifactReadRecord,
    ) -> Result<ArtifactReadControlledBarrier, ArtifactStoreError> {
        if !record.matches_store(&self.store) || !self.store.matches_registry_owner(&self.registry)
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        let key = record.read_cleanup_key()?;
        let binding = self.registry.binding();
        if key.deployment_id().as_str() != binding.deployment_id()
            || key.tenant_id().as_str() != binding.tenant_id()
            || key.dataset_id() != binding.dataset_id()
        {
            return Err(ArtifactStoreError::BindingMismatch);
        }
        self.store.close_artifact_reads(key)
    }

    /// Compose actual current owners; a second Pool or caller-created transaction is not accepted.
    pub fn new(
        registry: Arc<ArtifactDatasetRegistry>,
        store: Arc<DatasetBoundArtifactStore>,
        policy: ArtifactQuotaPolicy,
        audit_key: SecretBytes,
    ) -> Result<Self, ArtifactAdministrationError> {
        if !store.matches_registry_owner(&registry) || audit_key.is_empty() {
            return Err(unavailable());
        }
        Ok(Self {
            registry,
            store,
            policy,
            audit_key,
            read_authority: OnceLock::new(),
            cleanup_physical_observer: OnceLock::new(),
            save_producer_diagnostic: OnceLock::new(),
        })
    }

    /// Install at most one nongrant recorder for this original canonical request.
    /// Installation or observation failure never changes the original Save operation.
    ///
    /// # Errors
    /// Refuses a noncanonical original UUIDv7 or an already installed registration.
    pub fn install_save_producer_diagnostic_for_request(
        self: &Arc<Self>,
        original_request_id: &str,
    ) -> Result<Arc<SaveProducerDiagnosticCapture>, SaveProducerDiagnosticInstallError> {
        if canonical_artifact_uuid_v7(original_request_id).as_deref() != Some(original_request_id) {
            return Err(SaveProducerDiagnosticInstallError::InvalidRequestId);
        }
        let capture = Arc::new(SaveProducerDiagnosticCapture::new(
            original_request_id.to_owned(),
        ));
        self.save_producer_diagnostic
            .set(Arc::clone(&capture))
            .map_err(|_| SaveProducerDiagnosticInstallError::AlreadyInstalled)?;
        Ok(capture)
    }

    /// Retain one actual reader authority; its weak administration link never forms a cycle.
    pub fn read_authority(
        self: &Arc<Self>,
    ) -> Arc<artifact_read_authority::PostgresArtifactReadAuthority> {
        Arc::clone(self.read_authority.get_or_init(|| {
            Arc::new(
                artifact_read_authority::PostgresArtifactReadAuthority::from_administration(self),
            )
        }))
    }

    /// Observe one currently visible available record using only this adapter's actual Pool.
    ///
    /// The final RC statement jointly observes the unchanged R398 source predicate, the exact
    /// saved message relationship, operation payload and current dataset/store tuple. The
    /// explicit read-only rollback completes before the snapshot is returned. No physical IO,
    /// session renewal, audit event or current byte-delivery authority is produced here.
    pub async fn observe_read_record(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        #[cfg(test)]
        return self
            .observe_read_record_inner(auth, artifact_id, None)
            .await;
        #[cfg(not(test))]
        self.observe_read_record_inner(auth, artifact_id).await
    }

    /// The original guarded owner bounds queries and rollback ACK by the caller's deadline.
    /// Cancellation or timeout retires the owner and never turns Drop into a positive ACK.
    pub(super) async fn observe_read_record_before_inner(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        deadline: std::time::Instant,
    ) -> Result<ObservedArtifactReadRecord, PublicReadRecordFailure> {
        #[cfg(test)]
        return self
            .observe_read_record_guarded(auth, artifact_id, deadline, None)
            .await;
        #[cfg(not(test))]
        self.observe_read_record_guarded(auth, artifact_id, deadline)
            .await
    }

    async fn observe_read_record_guarded(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        deadline: std::time::Instant,
        #[cfg(test)] final_query_gate: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    ) -> Result<ObservedArtifactReadRecord, PublicReadRecordFailure> {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let check_budget = || {
                deadline
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(|| PublicReadRecordFailure::observed(unavailable()))
            };
            check_budget()?;
            let id = canonical_artifact_uuid_v7(artifact_id).ok_or_else(|| {
                PublicReadRecordFailure::observed(ArtifactAdministrationError::InvalidInput {
                    field: "artifactId",
                })
            })?;
            self.check_namespace(auth)
                .map_err(PublicReadRecordFailure::observed)?;
            let checkout_limit = deadline.min(std::time::Instant::now() + WAIT);
            let mut client = tokio::time::timeout_at(
                tokio::time::Instant::from_std(checkout_limit),
                self.registry.pool().get_guarded(deadline),
            )
            .await
            .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?
            .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?;
            // Completed schema mismatches before BEGIN finish this query reservation. Unknown
            // or cancelled observations still retire the owner and leave the Store unproven.
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline.min(std::time::Instant::now() + PG_PHASE)),
                verify_artifact_read_schema_on(client.as_client()),
            )
            .await
            .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?
            .map_err(|error| PublicReadRecordFailure::schema(error, deadline))?;
            check_budget()?;
            let original_transaction = client
                .begin_read_committed_read_only()
                .await
                .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?;
            let outcome = async {
                let tx = original_transaction.as_transaction();
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(unavailable)?;
                let millis = remaining.as_millis().clamp(1, 5000);
                tx.batch_execute(&format!(
                    "SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"
                ))
                .await
                .map_err(|_| unavailable())?;
                if std::time::Instant::now() >= deadline {
                    return Err(unavailable());
                }
                let b = self.registry.binding();
                let seed = tx.query_opt(
                "SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
                 WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 \
                   AND artifact_id=$4 AND owner_actor_id=$5",
                &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&id,&auth.actor().as_str()],
            ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
                let thread: String = value(&seed, "source_thread_id")?;
                let run: String = value(&seed, "source_run_id")?;
                let generation = i64::try_from(auth.auth_generation().get())
                    .map_err(|_| ArtifactAdministrationError::NotVisible)?;
                let physical = self.store.physical_binding();
                if std::time::Instant::now() >= deadline {
                    return Err(unavailable());
                }
                // The existing private test gate coordinates only after schema/setup/seed.
                #[cfg(test)]
                if let Some((reached, proceed)) = final_query_gate {
                    reached.send(()).map_err(|_| unavailable())?;
                    proceed.await.map_err(|_| unavailable())?;
                }
                let row = tx
                    .query_opt(
                        observed_read_sql(),
                        &[
                            &thread,
                            &run,
                            &auth.actor().as_str(),
                            &auth.deployment().as_str(),
                            &auth.tenant().as_str(),
                            &generation,
                            &id,
                            &b.dataset_id(),
                            &b.binding_schema(),
                            &b.initial_origin(),
                            &b.created_at(),
                            &self.store.store_id().to_string(),
                            &physical.device(),
                            &physical.inode(),
                            &physical.uid(),
                        ],
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .ok_or(ArtifactAdministrationError::NotVisible)?;
                self.decode_read_record(auth, &row)
            }
            .await;
            // The genuine ACK is bounded by the original deadline. Queued Drop rollback is not ACK.
            original_transaction
                .rollback()
                .await
                .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?;
            check_budget()?;
            outcome.map_err(PublicReadRecordFailure::observed)
        })
        .await
        .map_err(|_| PublicReadRecordFailure::unproven(unavailable()))?
    }

    async fn observe_read_record_inner(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        #[cfg(test)] final_query_gate: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        let deadline = std::time::Instant::now()
            .checked_add(PG_PHASE)
            .ok_or_else(unavailable)?;
        #[cfg(test)]
        return self
            .observe_read_record_guarded(auth, artifact_id, deadline, final_query_gate)
            .await
            .map_err(|failure| failure.error);
        #[cfg(not(test))]
        self.observe_read_record_guarded(auth, artifact_id, deadline)
            .await
            .map_err(|failure| failure.error)
    }

    fn decode_read_record(
        &self,
        auth: &AuthContext,
        row: &Row,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        if !value::<bool>(row, "current_store_binding")?
            || !self.store.matches_registry_owner(&self.registry)
        {
            return Err(unavailable());
        }
        let status: String = value(row, "status")?;
        match status.as_str() {
            "deleted" => {
                return Err(ArtifactAdministrationError::Gone {
                    status: ArtifactGoneStatus::Deleted,
                });
            }
            "expired" => {
                return Err(ArtifactAdministrationError::Gone {
                    status: ArtifactGoneStatus::Expired,
                });
            }
            "failed_partial" => return Err(unavailable()),
            "available" => {}
            _ => return Err(corrupt("read_status")),
        }
        let DecodedArtifactReadPayload {
            source,
            workspace,
            length,
            sha256,
            cleanup_armed,
        } = self.decode_available_read_payload(auth, row)?;
        if cleanup_armed {
            return Err(unavailable());
        }
        let blob = ArtifactBlob::from_record(
            Uuid::parse_str(&source.artifact_id).map_err(|_| corrupt("read_artifact_id"))?,
            length,
            parse_digest(&sha256)?,
        )
        .map_err(|_| corrupt("read_blob_binding"))?;
        Ok(ObservedArtifactReadRecord {
            store: Arc::clone(&self.store),
            blob,
            auth_snapshot: auth.clone(),
            source_snapshot: source,
            workspace_snapshot: workspace,
        })
    }

    // Shared actual available-row invariants; this makes no byte allocation, FD or read grant.
    fn decode_available_read_payload(
        &self,
        auth: &AuthContext,
        row: &Row,
    ) -> Result<DecodedArtifactReadPayload, ArtifactAdministrationError> {
        let source = decode_receipt(row)?; // Actual row IDs, never a historical receipt lookup.
        if source.owner_actor_id != *auth.actor()
            || canonical_artifact_uuid_v7(&source.artifact_id).as_deref()
                != Some(source.artifact_id.as_str())
            || canonical_artifact_uuid_v7(&source.operation_id).as_deref()
                != Some(source.operation_id.as_str())
            || canonical_artifact_uuid_v7(&source.request_id).as_deref()
                != Some(source.request_id.as_str())
            || !ThreadIdentity::is_plausible(&source.source_thread_id)
            || !is_valid_artifact_identity(source.source_run_id.as_str())
            || !is_valid_artifact_identity(&source.source_message_id)
            || source.source_call_seq.is_some()
            || source.source_attempt_seq.is_some()
        {
            return Err(corrupt("read_source_snapshot"));
        }
        let kind: String = value(row, "workspace_kind")?;
        let workspace_id: String = value(row, "workspace_id")?;
        let workspace = ArtifactWorkspaceKey::new(
            match kind.as_str() {
                "channel" => openbot_domain::artifact::ArtifactWorkspaceKind::Channel,
                "thread" => openbot_domain::artifact::ArtifactWorkspaceKind::Thread,
                _ => return Err(corrupt("read_workspace")),
            },
            &workspace_id,
        )
        .map_err(|_| corrupt("read_workspace"))?;
        let length = unsigned(value(row, "byte_length")?)?;
        let sha256: String = value(row, "sha256")?;
        if length == 0
            || !is_valid_artifact_sha256(&sha256)
            || value::<String>(row, "media_type")? != MEDIA
            || value::<String>(row, "retention_class")? != "explicit_saved"
            || value::<Option<String>>(row, "saved_by")?.as_deref() != Some(auth.actor().as_str())
            || value::<Option<OffsetDateTime>>(row, "saved_at")?.is_none()
            || value::<String>(row, "source_workspace_kind")? != kind
            || value::<String>(row, "source_workspace_id")? != workspace_id
        {
            return Err(corrupt("read_record_payload"));
        }
        // A current record alone cannot select another operation's bytes or invent installed
        // bytes for an unresolved/partial operation. All nullable actual fields must be real.
        if value::<Option<String>>(row, "op_state")?.as_deref() != Some("available")
            || value::<Option<String>>(row, "op_store_id")?.as_deref()
                != Some(self.store.store_id().to_string().as_str())
            || value::<Option<String>>(row, "op_workspace_kind")?.as_deref() != Some(kind.as_str())
            || value::<Option<String>>(row, "op_workspace_id")?.as_deref()
                != Some(workspace_id.as_str())
            || value::<Option<String>>(row, "op_expected_sha256")?.as_deref()
                != Some(sha256.as_str())
            || value::<Option<i64>>(row, "op_expected_bytes")? != Some(integer(length)?)
            || value::<Option<i64>>(row, "op_charged_bytes")? != Some(integer(length)?)
            || value::<Option<bool>>(row, "op_actual_absent")? != Some(false)
            || value::<Option<i64>>(row, "op_actual_byte_length")? != Some(integer(length)?)
            || value::<Option<String>>(row, "op_actual_sha256")?.as_deref() != Some(sha256.as_str())
            || value::<Option<String>>(row, "op_actual_location")?.as_deref() != Some("object")
            || value::<Option<String>>(row, "op_observation_phase")?.as_deref() != Some("installed")
        {
            return Err(corrupt("read_operation_payload"));
        }
        let binding = self.registry.binding();
        let record_key = ArtifactCleanupFenceKey::from_stored(
            DeploymentId::new(binding.deployment_id()),
            TenantId::new(binding.tenant_id()),
            binding.dataset_id(),
            &source.operation_id,
            &source.artifact_id,
        )
        .map_err(|_| corrupt("read_cleanup_fence"))?;
        let cleanup_armed = match decode_read_cleanup_fence(row, &record_key)? {
            None => false,
            Some(fence) => match fence.phase() {
                ArtifactCleanupFencePhase::Armed => true,
                ArtifactCleanupFencePhase::Completed => return Err(corrupt("read_cleanup_fence")),
            },
        };
        Ok(DecodedArtifactReadPayload {
            source,
            workspace,
            length,
            sha256,
            cleanup_armed,
        })
    }

    fn decode_run_input_metadata(
        &self,
        auth: &AuthContext,
        row: &Row,
    ) -> Result<
        openbot_application::artifacts::RunInputArtifactMetadataObservation,
        ArtifactAdministrationError,
    > {
        if !value::<bool>(row, "current_store_binding")?
            || !self.store.matches_registry_owner(&self.registry)
        {
            return Err(unavailable());
        }
        match value::<String>(row, "status")?.as_str() {
            "available" => {}
            "failed_partial" | "deleted" | "expired" => {
                return Err(ArtifactAdministrationError::NotVisible);
            }
            _ => return Err(corrupt("read_status")),
        }
        let cleanup_armed = self.decode_available_read_payload(auth, row)?.cleanup_armed;
        Ok(
            openbot_application::artifacts::RunInputArtifactMetadataObservation {
                metadata: decode_metadata(row)?,
                cleanup_armed,
            },
        )
    }

    async fn connection(
        &self,
    ) -> Result<crate::db::pool::PooledClient, ArtifactAdministrationError> {
        tokio::time::timeout(WAIT, self.registry.pool().get())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
    }

    async fn admit(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        disk_bytes: u64,
    ) -> Result<AdmissionOutcome, ArtifactAdministrationError> {
        let mut client = self.connection().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| unavailable())?;
        setup(&tx).await?;
        // One strict schema observation before this transaction's first row lock.
        let schema = CurrentWriterSchema::observe(&tx)
            .await
            .map_err(history_error)?;
        self.lock_actor(&tx, auth).await?;
        let source = self.lock_source(&tx, auth, input).await?;
        self.check_binding(&tx).await?;
        self.lock_quota(&tx, &source.workspace, input.source_run_id.as_str())
            .await?;
        let existing = tx.query_opt(
            "SELECT * FROM openbot_internal.artifact_save_operations \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND request_id=$4 FOR UPDATE",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &input.request_id],
        ).await.map_err(|_| unavailable())?;
        // Unique-key/quota waits occurred after the initial authority observation. Re-read all
        // current facts in a NEW RC statement; locks keep their positive entities stable.
        let fresh = self.fresh_source(&tx, auth, input).await?;
        source.ensure_same(&fresh)?;
        self.check_binding(&tx).await?;
        if let Some(row) = existing {
            ensure_intent(&row, auth, input, &fresh)?;
            let state: String = value(&row, "state")?;
            if state == "available" {
                let op: String = value(&row, "operation_id")?;
                let receipt = self.receipt(&tx, &op).await?;
                // Do not publish an observation after any later wait without current source facts.
                self.fresh_source(&tx, auth, input)
                    .await?
                    .ensure_same(&fresh)?;
                tx.rollback().await.map_err(|_| unavailable())?;
                return Ok(AdmissionOutcome::Observed(receipt));
            }
            return Err(unavailable());
        }
        // Only a NEW operation is a new copy: a closed source Thread history refuses it. The
        // exact replay of a committed operation above is unchanged.
        require_open_history(&tx, &schema, input).await?;
        if fresh.sha256 != input.expected_sha256 {
            return Err(ArtifactAdministrationError::InvalidInput {
                field: "expectedSha256",
            });
        }
        let len = fresh.length;
        if len > disk_bytes {
            return Err(ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_disk_space",
            });
        }
        let (count, charged) = self
            .usage(&tx, &fresh.workspace, input.source_run_id.as_str())
            .await?;
        let projected = self
            .policy
            .project_registration(count, charged, len)
            .map_err(|_| ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_quota",
            })?;
        let operation_id = Uuid::now_v7().to_string();
        let artifact_id = Uuid::now_v7();
        let store_id = self.store.store_id().to_string();
        let len_pg = integer(len)?;
        let inserted = tx.execute(
            "INSERT INTO openbot_internal.artifact_save_operations \
             (deployment_id,tenant_id,dataset_id,request_id,operation_id,artifact_id,owner_actor_id,\
              source_thread_id,source_run_id,source_message_id,state,store_id,workspace_kind,workspace_id,\
              expected_sha256,expected_bytes,charged_bytes,created_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'admitted',$11,$12,$13,$14,$15,$15,clock_timestamp()) ON CONFLICT(deployment_id,tenant_id,dataset_id,request_id) DO NOTHING",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &input.request_id, &operation_id,
              &artifact_id.to_string(), &auth.actor().as_str(), &input.source_thread_id.as_str(),
              &input.source_run_id.as_str(), &input.source_message_id.as_str(), &store_id,
              &fresh.workspace.kind().as_str(), &fresh.workspace.id(), &input.expected_sha256, &len_pg],
        ).await.map_err(|_| unavailable())?;
        if inserted != 1 {
            // Another namespace locator may win without sharing this actor or workspace lock.
            // A new statement after the unique-key wait sees that original intent; never mint IO.
            self.fresh_source(&tx, auth, input)
                .await?
                .ensure_same(&fresh)?;
            self.check_binding(&tx).await?;
            return Err(ArtifactAdministrationError::RequestConflict);
        }
        self.set_usage(
            &tx,
            &fresh.workspace,
            input.source_run_id.as_str(),
            projected.run_identities(),
            projected.workspace_charged_bytes(),
        )
        .await?;
        self.fresh_source(&tx, auth, input)
            .await?
            .ensure_same(&fresh)?;
        self.check_binding(&tx).await?;
        commit(tx).await?;
        Ok(AdmissionOutcome::Prepared(Admission {
            operation_id,
            artifact_id,
            source: fresh,
            length: len,
        }))
    }

    async fn start_io(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        admission: &Admission,
    ) -> Result<(), ArtifactAdministrationError> {
        let mut client = self.connection().await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| unavailable())?;
        setup(&tx).await?;
        // One strict schema observation before this transaction's first row lock.
        let schema = CurrentWriterSchema::observe(&tx)
            .await
            .map_err(history_error)?;
        self.lock_actor(&tx, auth).await?;
        self.lock_source(&tx, auth, input)
            .await?
            .ensure_same(&admission.source)?;
        self.check_binding(&tx).await?;
        self.lock_quota(
            &tx,
            &admission.source.workspace,
            input.source_run_id.as_str(),
        )
        .await?;
        let row = self.operation(&tx, &admission.operation_id).await?;
        ensure_intent(&row, auth, input, &admission.source)?;
        if value::<String>(&row, "state")? != "admitted"
            || value::<String>(&row, "artifact_id")? != admission.artifact_id.to_string()
        {
            return Err(unavailable());
        }
        // No IO may begin from a closed source Thread history. The operation stays admitted,
        // with its original charge, exactly like any other refusal at this fence.
        require_open_history(&tx, &schema, input).await?;
        self.fresh_source(&tx, auth, input)
            .await?
            .ensure_same(&admission.source)?;
        self.check_binding(&tx).await?;
        tx.execute(
            "UPDATE openbot_internal.artifact_save_operations SET state='io_started' \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 AND state='admitted'",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.operation_id],
        ).await.map_err(|_| unavailable())?;
        commit(tx).await
    }

    async fn finalize(
        &self,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
        admission: &Admission,
        observation: &VerifiedArtifactByteObservation,
        diagnostic: &Option<Arc<SaveProducerDiagnosticCapture>>,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        // Observe each existing expression once, without retaining any business resource.
        // A direct PG error is classified before its unchanged original mapping erases it.
        macro_rules! finalize_result {
            ($expression:expr) => {{
                let original_result: Result<_, ArtifactAdministrationError> = $expression;
                if let (Some(capture), Err(error)) = (diagnostic, &original_result) {
                    capture.record(SaveProducerDiagnosticEvent::FinalizeFailure(
                        SaveFinalizeDiagnosticFailure::OriginalClosedResult(*error),
                    ));
                }
                original_result
            }};
        }
        macro_rules! finalize_pg_result {
            ($expression:expr) => {{
                let original_result: Result<_, tokio_postgres::Error> = $expression;
                if let (Some(capture), Err(error)) = (diagnostic, &original_result) {
                    capture.record(SaveProducerDiagnosticEvent::FinalizeFailure(
                        SaveFinalizeDiagnosticFailure::DirectPg(
                            SaveFinalizePgCodeCategory::from_error(error),
                        ),
                    ));
                }
                original_result
            }};
        }
        macro_rules! finalize_stage {
            ($stage:ident) => {
                if let Some(capture) = diagnostic {
                    capture.record(SaveProducerDiagnosticEvent::FinalizeSubstage(
                        SaveFinalizeDiagnosticSubstage::$stage,
                    ));
                }
            };
        }
        finalize_stage!(ByteOwnerCheck);
        if !observation.matches_store(&self.store)
            || observation.artifact_id() != admission.artifact_id
        {
            return finalize_result!(Err(corrupt("byte_owner")));
        }
        finalize_stage!(Checkout);
        let mut client = finalize_result!(self.connection().await)?;
        finalize_stage!(Begin);
        let tx = finalize_pg_result!(
            client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .start()
                .await
        )
        .map_err(|_| unavailable())?;
        finalize_stage!(Setup);
        finalize_result!(setup(&tx).await)?;
        // One strict schema observation before this transaction's first row lock.
        let schema = finalize_result!(
            CurrentWriterSchema::observe(&tx)
                .await
                .map_err(history_error)
        )?;
        // A no-row authority result does not abort the transaction. Retain real failure facts
        // under the original private admission, without granting the revoked caller a read.
        finalize_stage!(InitialAuthority);
        let authorized = match finalize_result!(self.lock_actor(&tx, auth).await) {
            Ok(()) => match finalize_result!(self.lock_source(&tx, auth, input).await) {
                Ok(source) => finalize_result!(source.ensure_same(&admission.source)).is_ok(),
                Err(
                    ArtifactAdministrationError::NotVisible
                    | ArtifactAdministrationError::InvalidInput { .. },
                ) => false,
                Err(error) => return Err(error),
            },
            Err(ArtifactAdministrationError::NotVisible) => false,
            Err(error) => return Err(error),
        };
        finalize_stage!(BindingAndQuota);
        finalize_result!(self.check_binding(&tx).await)?;
        finalize_result!(
            self.lock_quota(
                &tx,
                &admission.source.workspace,
                input.source_run_id.as_str(),
            )
            .await
        )?;
        finalize_stage!(LoadAndValidateOperation);
        let row = finalize_result!(self.operation(&tx, &admission.operation_id).await)?;
        finalize_result!(ensure_intent(&row, auth, input, &admission.source))?;
        if finalize_result!(value::<String>(&row, "state"))? != "io_started"
            || finalize_result!(value::<String>(&row, "artifact_id"))?
                != admission.artifact_id.to_string()
        {
            if let Some(capture) = diagnostic {
                capture.record(SaveProducerDiagnosticEvent::FinalizeFailure(
                    SaveFinalizeDiagnosticFailure::OperationStateMismatch,
                ));
            }
            return Err(unavailable());
        }
        // Same order as the admission and the start of IO: actor, source, quota, operation, then
        // the head. A closed source Thread history follows the source-changed path: the real byte
        // observation and its charge are kept, and no record, receipt or available state is
        // published.
        let authorized = if authorized {
            match finalize_result!(require_open_history(&tx, &schema, input).await) {
                Ok(()) => true,
                Err(ArtifactAdministrationError::NotVisible) => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        finalize_stage!(AuditCoordinates);
        let (audit_id, audit_time) = if authorized
            && matches!(
                observation.state(),
                ArtifactByteObservationState::DurableInstalled { .. }
            ) {
            let coordinates =
                finalize_result!(next_event_coordinates(&tx).await.map_err(|_| unavailable()))?;
            (Some(coordinates.0), Some(coordinates.1))
        } else {
            (None, None)
        };
        finalize_stage!(FreshAuthority);
        let authorized = authorized
            && match finalize_result!(self.fresh_source(&tx, auth, input).await) {
                Ok(current) => finalize_result!(current.ensure_same(&admission.source)).is_ok(),
                Err(
                    ArtifactAdministrationError::NotVisible
                    | ArtifactAdministrationError::InvalidInput { .. },
                ) => false,
                Err(error) => return Err(error),
            };
        finalize_result!(self.check_binding(&tx).await)?;
        finalize_stage!(ObservationAndCharge);
        let state = *observation.state();
        let mut positive = false;
        let (actual_absent, actual_len, actual_sha, actual_location, charge) = match state {
            ArtifactByteObservationState::DurableInstalled {
                byte_length,
                sha256,
            } => {
                positive = authorized
                    && byte_length == admission.length
                    && digest_hex(&sha256) == input.expected_sha256;
                (
                    Some(false),
                    Some(finalize_result!(integer(byte_length))?),
                    Some(digest_hex(&sha256)),
                    Some("object"),
                    byte_length,
                )
            }
            ArtifactByteObservationState::RetainedPartial {
                location,
                byte_length,
                sha256,
            } => (
                Some(false),
                Some(finalize_result!(integer(byte_length))?),
                Some(digest_hex(&sha256)),
                Some(location.as_str()),
                byte_length,
            ),
            ArtifactByteObservationState::DurableAbsent => (Some(true), None, None, None, 0),
            ArtifactByteObservationState::Indeterminate => {
                (None, None, None, None, admission.length)
            }
        };
        if charge > admission.length {
            return finalize_result!(Err(corrupt("unexpected_retained_length")));
        }
        let record_failed = authorized && !positive && actual_absent == Some(false);
        let next_state = if positive {
            "available"
        } else if record_failed {
            "failed_partial"
        } else {
            "unresolved"
        };
        if positive || record_failed {
            finalize_stage!(InsertRecord);
            let actual_len = finalize_result!(actual_len.ok_or_else(|| corrupt("actual_length")))?;
            let actual_sha = finalize_result!(
                actual_sha
                    .as_deref()
                    .ok_or_else(|| corrupt("actual_digest"))
            )?;
            finalize_pg_result!(tx.execute(
                "INSERT INTO openbot_internal.artifact_records \
                 (deployment_id,tenant_id,dataset_id,artifact_id,operation_id,request_id,owner_actor_id,\
                  source_thread_id,source_run_id,source_message_id,status,workspace_kind,workspace_id,\
                  media_type,byte_length,sha256,retention_class,saved_by,saved_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'explicit_saved',$7,clock_timestamp())",
                &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
                  &self.registry.binding().dataset_id(), &admission.artifact_id.to_string(), &admission.operation_id,
                  &input.request_id, &auth.actor().as_str(), &input.source_thread_id.as_str(),
                  &input.source_run_id.as_str(), &input.source_message_id.as_str(), &next_state,
                  &admission.source.workspace.kind().as_str(), &admission.source.workspace.id(),
                  &MEDIA, &actual_len, &actual_sha],
            ).await).map_err(|_| unavailable())?;
        }
        finalize_stage!(ReadAndUpdateQuota);
        let (_, charged) = finalize_result!(
            self.usage(
                &tx,
                &admission.source.workspace,
                input.source_run_id.as_str(),
            )
            .await
        )?;
        let old_charge =
            finalize_result!(unsigned(finalize_result!(value(&row, "charged_bytes"))?))?;
        let new_charged = finalize_result!(
            charged
                .checked_sub(old_charge)
                .and_then(|n| n.checked_add(charge))
                .ok_or_else(|| corrupt("quota_charge"))
        )?;
        finalize_pg_result!(tx.execute(
            "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$6 \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.source.workspace.kind().as_str(),
              &admission.source.workspace.id(), &finalize_result!(integer(new_charged))?],
        ).await).map_err(|_| unavailable())?;
        finalize_stage!(UpdateOperation);
        finalize_pg_result!(tx.execute(
            "UPDATE openbot_internal.artifact_save_operations SET state=$5,charged_bytes=$6,\
             actual_absent=$7,actual_byte_length=$8,actual_sha256=$9,actual_location=$10,observation_phase=$11 \
             WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 AND state='io_started'",
            &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
              &self.registry.binding().dataset_id(), &admission.operation_id, &next_state, &finalize_result!(integer(charge))?,
              &actual_absent, &actual_len, &actual_sha, &actual_location, &observation.phase().as_str()],
        ).await).map_err(|_| unavailable())?;
        let receipt = receipt_from(admission, auth, input);
        if positive {
            finalize_stage!(InsertReceipt);
            finalize_pg_result!(tx.execute(
                "INSERT INTO openbot_internal.artifact_saved_receipts \
                 (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,request_id,owner_actor_id,\
                  source_thread_id,source_run_id,source_message_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[&self.registry.binding().deployment_id(), &self.registry.binding().tenant_id(),
                  &self.registry.binding().dataset_id(), &receipt.operation_id, &receipt.artifact_id,
                  &receipt.request_id, &auth.actor().as_str(), &input.source_thread_id.as_str(),
                  &input.source_run_id.as_str(), &input.source_message_id.as_str()],
            ).await).map_err(|_| unavailable())?;
            finalize_stage!(AppendAudit);
            let artifact = finalize_result!(
                AuditIdentifier::new(&receipt.artifact_id)
                    .map_err(|_| corrupt("audit_artifact_id"))
            )?;
            let operation = finalize_result!(
                AuditIdentifier::new(&receipt.operation_id)
                    .map_err(|_| corrupt("audit_operation_id"))
            )?;
            let event = AuditEvent {
                id: finalize_result!(audit_id.ok_or_else(|| corrupt("audit_coordinate")))?,
                actor: Some(auth.actor().clone()),
                event_type: AuditEventType::ARTIFACT_SAVED,
                target_kind: AuditLabel::new("artifact"),
                target_id: Some(artifact.clone()),
                payload: finalize_result!(
                    AuditPayload::from_facts([
                        AuditFact::ArtifactId(artifact),
                        AuditFact::ArtifactOperationId(operation),
                    ])
                    .map_err(|_| corrupt("audit_payload"))
                )?,
                created_at: finalize_result!(
                    audit_time.ok_or_else(|| corrupt("audit_coordinate"))
                )?,
            };
            finalize_result!(
                append_event_in_transaction(&tx, &event, self.audit_key.expose())
                    .await
                    .map_err(|_| unavailable())
            )?;
            // Covers later FK/unique/audit waits. If any currently checked authority changed,
            // rollback the tentative record/receipt; the durable IO_STARTED remains charged.
            finalize_stage!(FinalAuthority);
            finalize_result!(
                finalize_result!(self.fresh_source(&tx, auth, input).await)?
                    .ensure_same(&admission.source)
            )?;
            finalize_result!(self.check_binding(&tx).await)?;
        }
        finalize_stage!(Commit);
        finalize_result!(commit(tx).await)?;
        finalize_stage!(ReturnReceipt);
        if positive {
            Ok(receipt)
        } else {
            if let Some(capture) = diagnostic {
                capture.record(SaveProducerDiagnosticEvent::FinalizeFailure(
                    SaveFinalizeDiagnosticFailure::NonPositiveReturn,
                ));
            }
            Err(unavailable())
        }
    }

    async fn lock_actor(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
    ) -> Result<(), ArtifactAdministrationError> {
        self.check_namespace(auth)?;
        tx.query_opt(
            "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
            &[&auth.actor().as_str()],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 \
             AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin')) \
             AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))",
            &[&auth.actor().as_str(), &generation],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        Ok(())
    }

    async fn lock_source(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
    ) -> Result<Source, ArtifactAdministrationError> {
        // A caller-supplied locator grants no right to lock its rows. Establish the current
        // R398/message tuple first so a foreign or mismatched source stays uniformly invisible.
        let source = self.fresh_source(tx, auth, input).await?;
        let roles = tx.query("SELECT role FROM public.user_roles WHERE user_id=$1 AND role IN ('user','admin') ORDER BY role FOR SHARE NOWAIT",
            &[&auth.actor().as_str()]).await.map_err(|_| unavailable())?;
        if roles.is_empty() {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        tx.query_opt(
            "SELECT run_id FROM public.runs WHERE run_id=$1 AND thread_id=$2 AND actor_id=$3 FOR SHARE NOWAIT",
            &[&input.source_run_id.as_str(), &input.source_thread_id.as_str(), &auth.actor().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT thread_id FROM public.threads WHERE thread_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND status<>'deleted' FOR SHARE NOWAIT",
            &[&input.source_thread_id.as_str(), &auth.deployment().as_str(), &auth.tenant().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT message_id FROM public.messages WHERE message_id=$1 AND thread_id=$2 AND run_id=$3 AND actor_id=$4 AND role='user' FOR SHARE NOWAIT",
            &[&input.source_message_id.as_str(), &input.source_thread_id.as_str(), &input.source_run_id.as_str(), &auth.actor().as_str()],
        ).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT id FROM public.agents WHERE id=$1 FOR SHARE NOWAIT",
            &[&source.bot],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        tx.query_opt(
            "SELECT agent_id FROM public.agent_profiles WHERE agent_id=$1 FOR SHARE NOWAIT",
            &[&source.bot],
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(ArtifactAdministrationError::NotVisible)?;
        if let Some(package) = &source.bot_package {
            tx.query_opt(
                "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT",
                &[package],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        }
        if source.workspace.kind().as_str() == "channel" {
            let channel = source.workspace.id();
            tx.query_opt(
                "SELECT id FROM public.channels WHERE id=$1 FOR SHARE NOWAIT",
                &[&channel],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
            tx.query_opt("SELECT channel_id FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                &[&channel, &auth.actor().as_str()]).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
            tx.query_opt("SELECT channel_id FROM public.channel_agents WHERE channel_id=$1 AND agent_id=$2 FOR SHARE NOWAIT",
                &[&channel, &source.bot]).await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
            if let Some(package) = &source.channel_package {
                tx.query_opt(
                    "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT",
                    &[package],
                )
                .await
                .map_err(|_| unavailable())?
                .ok_or(ArtifactAdministrationError::NotVisible)?;
            }
        } else {
            tx.query_opt("SELECT thread_id FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                &[&input.source_thread_id.as_str(), &auth.actor().as_str()]).await.map_err(|_| unavailable())?
                .ok_or(ArtifactAdministrationError::NotVisible)?;
        }
        let fresh = self.fresh_source(tx, auth, input).await?;
        source.ensure_same(&fresh)?;
        Ok(fresh)
    }

    async fn fresh_source(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        input: &SaveRunMessageTextArtifact,
    ) -> Result<Source, ArtifactAdministrationError> {
        let generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| ArtifactAdministrationError::NotVisible)?;
        let row = tx
            .query_opt(
                source_sql(),
                &[
                    &input.source_thread_id.as_str(),
                    &input.source_run_id.as_str(),
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                    &input.source_message_id.as_str(),
                    &integer(self.policy.max_artifact_bytes())?,
                ],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        let length = unsigned(value(&row, "text_byte_length")?)?;
        if length > self.policy.max_artifact_bytes() {
            return Err(ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_quota",
            });
        }
        let text: String = value(&row, "text")?;
        if u64::try_from(text.len()).map_err(|_| corrupt("message_length"))? != length {
            return Err(corrupt("message_length"));
        }
        let kind: String = value(&row, "anchor_kind")?;
        let anchor: String = value(&row, "anchor_id")?;
        let workspace = match kind.as_str() {
            "channel" => ArtifactWorkspaceKey::channel(&anchor),
            "direct_bot" => ArtifactWorkspaceKey::thread(input.source_thread_id.as_str()),
            _ => return Err(corrupt("workspace_kind")),
        }
        .map_err(|_| corrupt("workspace_id"))?;
        Ok(Source {
            length,
            sha256: Sha256Digest::of(text.as_bytes()).to_hex(),
            text,
            workspace,
            bot: value(&row, "bot_id")?,
            bot_package: value(&row, "bot_package")?,
            channel_package: value(&row, "channel_package")?,
        })
    }

    async fn check_binding(&self, tx: &Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        let physical = self.store.physical_binding();
        let exists: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d \
             JOIN openbot_internal.artifact_store_bindings s USING(deployment_id,tenant_id,dataset_id) \
             WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.dataset_id=$3 AND d.binding_schema=$4 \
              AND d.initial_origin=$5 AND d.created_at=$6 AND s.store_id=$7 \
              AND s.root_device=$8 AND s.root_inode=$9 AND s.root_uid=$10)",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &b.binding_schema(), &b.initial_origin(),
              &b.created_at(), &self.store.store_id().to_string(), &physical.device(), &physical.inode(), &physical.uid()],
        ).await.map_err(|_| unavailable())?.try_get(0).map_err(|_| corrupt("dataset_store_binding"))?;
        if !exists || !self.store.matches_registry_owner(&self.registry) {
            return Err(corrupt("dataset_store_binding"));
        }
        Ok(())
    }

    async fn lock_quota(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
    ) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.execute("INSERT INTO openbot_internal.artifact_workspace_quotas \
            (deployment_id,tenant_id,dataset_id,workspace_kind,workspace_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id()])
            .await.map_err(|_| unavailable())?;
        tx.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5 FOR UPDATE",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id()])
            .await.map_err(|_| unavailable())?;
        tx.execute("INSERT INTO openbot_internal.artifact_run_quotas \
            (deployment_id,tenant_id,dataset_id,source_run_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &run]).await.map_err(|_| unavailable())?;
        tx.query_one("SELECT identity_count FROM openbot_internal.artifact_run_quotas \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND source_run_id=$4 FOR UPDATE",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &run]).await.map_err(|_| unavailable())?;
        Ok(())
    }

    async fn usage(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
    ) -> Result<(u64, u64), ArtifactAdministrationError> {
        let b = self.registry.binding();
        let row = tx.query_one("SELECT q.charged_bytes,r.identity_count FROM openbot_internal.artifact_workspace_quotas q \
            JOIN openbot_internal.artifact_run_quotas r USING(deployment_id,tenant_id,dataset_id) \
            WHERE q.deployment_id=$1 AND q.tenant_id=$2 AND q.dataset_id=$3 AND q.workspace_kind=$4 AND q.workspace_id=$5 AND r.source_run_id=$6",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id(), &run])
            .await.map_err(|_| unavailable())?;
        Ok((
            unsigned(value(&row, "identity_count")?)?,
            unsigned(value(&row, "charged_bytes")?)?,
        ))
    }

    async fn set_usage(
        &self,
        tx: &Transaction<'_>,
        workspace: &ArtifactWorkspaceKey,
        run: &str,
        count: u64,
        charged: u64,
    ) -> Result<(), ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.execute("UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$6 \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5",
            &[&b.deployment_id(), &b.tenant_id(), &b.dataset_id(), &workspace.kind().as_str(), &workspace.id(), &integer(charged)?])
            .await.map_err(|_| unavailable())?;
        tx.execute(
            "UPDATE openbot_internal.artifact_run_quotas SET identity_count=$5 \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND source_run_id=$4",
            &[
                &b.deployment_id(),
                &b.tenant_id(),
                &b.dataset_id(),
                &run,
                &integer(count)?,
            ],
        )
        .await
        .map_err(|_| unavailable())?;
        Ok(())
    }

    async fn operation(
        &self,
        tx: &Transaction<'_>,
        op: &str,
    ) -> Result<Row, ArtifactAdministrationError> {
        let b = self.registry.binding();
        tx.query_opt("SELECT * FROM openbot_internal.artifact_save_operations WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 FOR UPDATE",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&op]).await.map_err(|_| unavailable())?
            .ok_or_else(|| corrupt("operation_missing"))
    }

    async fn receipt(
        &self,
        tx: &Transaction<'_>,
        op: &str,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        let b = self.registry.binding();
        let row=tx.query_opt("SELECT * FROM openbot_internal.artifact_saved_receipts WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&op]).await.map_err(|_| unavailable())?
            .ok_or_else(|| corrupt("positive_receipt_missing"))?;
        decode_receipt(&row)
    }

    fn check_namespace(&self, auth: &AuthContext) -> Result<(), ArtifactAdministrationError> {
        if auth.deployment().as_str() != self.registry.binding().deployment_id()
            || auth.tenant().as_str() != self.registry.binding().tenant_id()
        {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        for id in [
            auth.actor().as_str(),
            auth.deployment().as_str(),
            auth.tenant().as_str(),
        ] {
            if !is_valid_artifact_identity(id) {
                return Err(ArtifactAdministrationError::NotVisible);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ArtifactAdministration for PostgresArtifactAdministration {
    async fn observe_run_input_metadata_current(
        &self,
        auth: &AuthContext,
        canonical_artifact_id: &str,
        original_preread_deadline: std::time::Instant,
    ) -> Result<
        openbot_application::artifacts::RunInputArtifactMetadataObservation,
        openbot_contracts::error::AppError,
    > {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority
            .run_input_metadata_current(auth, canonical_artifact_id, original_preread_deadline)
            .await
    }

    async fn prepare_host_bound_artifact_read(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
        original_deadline: std::time::Instant,
        observer: Arc<
            dyn openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver,
        >,
    ) -> Result<
        openbot_application::artifact_read_protocol::PreparedArtifactRead,
        openbot_contracts::error::AppError,
    > {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority
            .prepare_host_bound_artifact_read(auth, artifact_id, original_deadline, observer)
            .await
    }
    async fn observe_artifact_save_receipt_current(
        &self,
        auth: &AuthContext,
        input: &openbot_contracts::artifacts::GetArtifactSaveReceipt,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentOutcome {
        let authority = self
            .read_authority
            .get()
            .ok_or(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)?;
        authority
            .artifact_save_receipt_current(auth, input, deadline)
            .await
    }
    async fn observe_source_run_artifact_ids_current(
        &self,
        auth: &AuthContext,
        input: &openbot_contracts::artifacts::GetSourceRunArtifactIds,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        let authority = self
            .read_authority
            .get()
            .ok_or(openbot_contracts::request_binding::ArtifactReadCurrentError::Unavailable)?;
        authority
            .source_run_artifact_ids_current(auth, input, deadline)
            .await
    }
    async fn open_host_bound_read_operation(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, openbot_contracts::error::AppError>
    {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority
            .open_host_bound_read_operation(auth, artifact_id)
            .await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadChunk, openbot_contracts::error::AppError>
    {
        let authority = self.read_authority.get().ok_or(
            openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "artifacts",
            },
        )?;
        authority.read_host_bound_chunk(auth, artifact_id).await
    }
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        mut input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        let diagnostic = self
            .save_producer_diagnostic
            .get()
            .and_then(|capture| capture.begin_original(&input.request_id));
        // These statement-local wrappers observe the same original Result once. They create
        // no future, resource owner, retry or new timeout, and return that Result unchanged.
        macro_rules! save_result {
            ($expression:expr) => {{
                let original_result: Result<_, ArtifactAdministrationError> = $expression;
                if let (Some(capture), Err(error)) = (&diagnostic, &original_result) {
                    capture.record(SaveProducerDiagnosticEvent::Terminal(
                        SaveProducerDiagnosticTerminal::Error(*error),
                    ));
                }
                original_result
            }};
        }
        macro_rules! save_stage {
            ($stage:ident) => {
                if let Some(capture) = &diagnostic {
                    capture.record(SaveProducerDiagnosticEvent::Stage(
                        SaveProducerDiagnosticStage::$stage,
                    ));
                }
            };
        }
        save_stage!(ValidateInput);
        input.request_id = save_result!(
            canonical_artifact_uuid_v7(&input.request_id)
                .ok_or(ArtifactAdministrationError::InvalidInput { field: "requestId" })
        )?;
        if !ThreadIdentity::is_plausible(&input.source_thread_id) {
            return save_result!(Err(ArtifactAdministrationError::InvalidInput {
                field: "sourceThreadId",
            }));
        }
        for (field, id) in [
            ("sourceRunId", input.source_run_id.as_str()),
            ("sourceMessageId", input.source_message_id.as_str()),
        ] {
            if !is_valid_artifact_identity(id) {
                return save_result!(Err(ArtifactAdministrationError::InvalidInput { field }));
            }
        }
        if !is_valid_artifact_sha256(&input.expected_sha256) {
            return save_result!(Err(ArtifactAdministrationError::InvalidInput {
                field: "expectedSha256",
            }));
        }
        save_stage!(CheckNamespace);
        save_result!(self.check_namespace(auth))?;
        save_stage!(VerifyRegistrationSchema);
        save_result!(verify_artifact_registration_schema(self.registry.pool()).await)?;
        save_stage!(AvailableBytes);
        let store = Arc::clone(&self.store);
        let disk = save_result!(
            save_result!(
                save_result!(
                    tokio::time::timeout(
                        WAIT,
                        tokio::task::spawn_blocking(move || store.available_bytes()),
                    )
                    .await
                    .map_err(|_| unavailable())
                )?
                .map_err(|_| unavailable())
            )?
            .map_err(|_| unavailable())
        )?;
        save_stage!(Admit);
        let outcome = save_result!(save_result!(
            tokio::time::timeout(PG_PHASE, self.admit(auth, &input, disk))
                .await
                .map_err(|_| ArtifactAdministrationError::CommitUnknown)
        )?)?;
        let mut admission = match outcome {
            AdmissionOutcome::Observed(receipt) => {
                if let Some(capture) = &diagnostic {
                    capture.record(SaveProducerDiagnosticEvent::Terminal(
                        SaveProducerDiagnosticTerminal::Success,
                    ));
                }
                return Ok(receipt);
            }
            AdmissionOutcome::Prepared(value) => value,
        };
        save_stage!(StartIo);
        save_result!(save_result!(
            tokio::time::timeout(PG_PHASE, self.start_io(auth, &input, &admission))
                .await
                .map_err(|_| ArtifactAdministrationError::CommitUnknown)
        )?)?;
        save_stage!(WriteWorker);
        let store = Arc::clone(&self.store);
        let id = admission.artifact_id;
        let expected = save_result!(parse_digest(&input.expected_sha256))?;
        let text = std::mem::take(&mut admission.source.text);
        let worker_diagnostic = diagnostic.clone();
        // Dropping/cancelling this waiter cannot cancel a worker; IO_STARTED and charge remain.
        let observation = save_result!(
            save_result!(
                tokio::time::timeout(
                    PG_PHASE,
                    tokio::task::spawn_blocking(move || {
                        if let Some(capture) = &worker_diagnostic {
                            capture.record(SaveProducerDiagnosticEvent::WorkerEntered);
                        }
                        let observation = store.write_text_once(id, expected, text.as_bytes());
                        if let Some(capture) = &worker_diagnostic {
                            capture.record_worker_returned(&observation);
                        }
                        observation
                    }),
                )
                .await
                .map_err(|_| unavailable())
            )?
            .map_err(|_| unavailable())
        )?;
        save_stage!(Finalize);
        let result = save_result!(save_result!(
            tokio::time::timeout(
                PG_PHASE,
                self.finalize(auth, &input, &admission, &observation, &diagnostic),
            )
            .await
            .map_err(|_| ArtifactAdministrationError::CommitUnknown)
        )?);
        if result.is_ok()
            && let Some(capture) = &diagnostic
        {
            capture.record(SaveProducerDiagnosticEvent::Terminal(
                SaveProducerDiagnosticTerminal::Success,
            ));
        }
        result
    }

    async fn get_metadata(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        tokio::time::timeout(PG_PHASE, async {
        let id=canonical_artifact_uuid_v7(artifact_id).ok_or(ArtifactAdministrationError::InvalidInput{field:"artifactId"})?;
        self.check_namespace(auth)?;
        verify_artifact_registration_schema(self.registry.pool()).await?;
        let mut client=self.connection().await?;
        let tx=client.build_transaction().isolation_level(IsolationLevel::ReadCommitted).start().await.map_err(|_| unavailable())?;
        setup(&tx).await?;
        self.check_binding(&tx).await?;
        let b=self.registry.binding();
        let raw=tx.query_opt("SELECT source_thread_id,source_run_id FROM openbot_internal.artifact_records \
            WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND owner_actor_id=$5",
            &[&b.deployment_id(),&b.tenant_id(),&b.dataset_id(),&id,&auth.actor().as_str()]).await.map_err(|_| unavailable())?
            .ok_or(ArtifactAdministrationError::NotVisible)?;
        let thread:String=value(&raw,"source_thread_id")?;
        let run:String=value(&raw,"source_run_id")?;
        let generation=i64::try_from(auth.auth_generation().get()).map_err(|_| ArtifactAdministrationError::NotVisible)?;
        let sql=format!("{VISIBLE_RUN} SELECT a.* FROM visible_run r JOIN openbot_internal.artifact_records a \
            ON a.source_thread_id=r.thread_id AND a.source_run_id=r.run_id \
            JOIN public.messages m ON m.message_id=a.source_message_id \
              AND m.thread_id=a.source_thread_id AND m.run_id=a.source_run_id \
              AND m.actor_id=a.owner_actor_id AND m.role='user' \
            WHERE a.owner_actor_id=$3 AND a.deployment_id=$4 AND a.tenant_id=$5 AND a.artifact_id=$7 AND a.dataset_id=$8");
        let row=tx.query_opt(&sql,&[&thread,&run,&auth.actor().as_str(),&auth.deployment().as_str(),&auth.tenant().as_str(),&generation,&id,&b.dataset_id()])
            .await.map_err(|_| unavailable())?.ok_or(ArtifactAdministrationError::NotVisible)?;
        self.check_binding(&tx).await?;
        let metadata=decode_metadata(&row)?;
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(metadata)
        }).await.map_err(|_| unavailable())?
    }
}

struct DecodedArtifactReadPayload {
    source: ArtifactRegistrationReceipt,
    workspace: ArtifactWorkspaceKey,
    length: u64,
    sha256: String,
    cleanup_armed: bool,
}

struct Source {
    text: String,
    length: u64,
    sha256: String,
    workspace: ArtifactWorkspaceKey,
    bot: String,
    bot_package: Option<Uuid>,
    channel_package: Option<Uuid>,
}
impl Source {
    fn ensure_same(&self, other: &Self) -> Result<(), ArtifactAdministrationError> {
        if self.sha256 != other.sha256
            || self.length != other.length
            || self.workspace != other.workspace
            || self.bot != other.bot
            || self.bot_package != other.bot_package
            || self.channel_package != other.channel_package
        {
            return Err(ArtifactAdministrationError::NotVisible);
        }
        Ok(())
    }
}
struct Admission {
    operation_id: String,
    artifact_id: Uuid,
    source: Source,
    length: u64,
}
enum AdmissionOutcome {
    Prepared(Admission),
    Observed(ArtifactRegistrationReceipt),
}

async fn setup(tx: &Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='5s'")
        .await
        .map_err(|_| unavailable())
}
/// Lock, query and invariant failures of the history admission keep their own class; none of
/// them reads as closed.
fn history_error(error: InfraError) -> ArtifactAdministrationError {
    tracing::warn!(error = %error, "artifact save history admission failed");
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => unavailable(),
        _ => corrupt("thread_history_writer"),
    }
}
/// Takes H SHARE on this transaction, held to its natural end. A closed source Thread history
/// is unknown to the caller, like any other source that is not currently visible.
async fn require_open_history(
    tx: &Transaction<'_>,
    schema: &CurrentWriterSchema<'_, '_>,
    input: &SaveRunMessageTextArtifact,
) -> Result<(), ArtifactAdministrationError> {
    match schema
        .lock_thread_write_disposition(tx, &input.source_thread_id)
        .await
        .map_err(history_error)?
    {
        OpenOrClosed::Open => Ok(()),
        OpenOrClosed::Closed => Err(ArtifactAdministrationError::NotVisible),
    }
}
async fn commit(tx: deadpool_postgres::Transaction<'_>) -> Result<(), ArtifactAdministrationError> {
    tokio::time::timeout(WAIT, tx.commit())
        .await
        .map_err(|_| ArtifactAdministrationError::CommitUnknown)?
        .map_err(|_| ArtifactAdministrationError::CommitUnknown)
}
fn source_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        format!(
            "{VISIBLE_RUN} SELECT octet_length(m.content->>'text')::bigint AS text_byte_length,\
        CASE WHEN octet_length(m.content->>'text')::bigint <= $8 THEN m.content->>'text' ELSE NULL END AS text,\
        t.anchor_kind,t.anchor_id,r.bot_id,\
        b.package_id AS bot_package,ch.package_id AS channel_package FROM visible_run r \
        JOIN public.threads t ON t.thread_id=r.thread_id JOIN public.agents b ON b.id=r.bot_id \
        JOIN public.messages m ON m.thread_id=r.thread_id AND m.run_id=r.run_id \
        LEFT JOIN public.channels ch ON t.anchor_kind='channel' AND ch.id=t.anchor_id \
        WHERE m.message_id=$7 AND m.actor_id=$3 AND m.role='user' \
          AND jsonb_typeof(m.content)='object' AND jsonb_typeof(m.content->'text')='string' \
          AND octet_length(m.content->>'text') > 0"
        )
    })
    .as_str()
}
fn ensure_intent(
    row: &Row,
    auth: &AuthContext,
    input: &SaveRunMessageTextArtifact,
    source: &Source,
) -> Result<(), ArtifactAdministrationError> {
    let state: String = value(row, "state")?;
    if matches!(state.as_str(), "deleted" | "expired") {
        return Err(unavailable());
    }
    let expected: String = value(row, "expected_sha256")?;
    if value::<String>(row, "owner_actor_id")? != auth.actor().as_str()
        || value::<String>(row, "source_thread_id")? != input.source_thread_id.as_str()
        || value::<String>(row, "source_run_id")? != input.source_run_id.as_str()
        || value::<String>(row, "source_message_id")? != input.source_message_id.as_str()
        || expected != input.expected_sha256
        || unsigned(value(row, "expected_bytes")?)? != source.length
        || value::<String>(row, "workspace_kind")? != source.workspace.kind().as_str()
        || value::<String>(row, "workspace_id")? != source.workspace.id()
    {
        return Err(ArtifactAdministrationError::RequestConflict);
    }
    if source.sha256 != expected {
        return Err(ArtifactAdministrationError::NotVisible);
    }
    Ok(())
}
fn receipt_from(
    a: &Admission,
    auth: &AuthContext,
    input: &SaveRunMessageTextArtifact,
) -> ArtifactRegistrationReceipt {
    ArtifactRegistrationReceipt {
        operation_id: a.operation_id.clone(),
        artifact_id: a.artifact_id.to_string(),
        request_id: input.request_id.clone(),
        owner_actor_id: auth.actor().clone(),
        source_thread_id: input.source_thread_id.clone(),
        source_run_id: input.source_run_id.clone(),
        source_message_id: input.source_message_id.clone(),
        source_call_seq: None,
        source_attempt_seq: None,
    }
}
fn decode_receipt(row: &Row) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
    Ok(ArtifactRegistrationReceipt {
        operation_id: value(row, "operation_id")?,
        artifact_id: value(row, "artifact_id")?,
        request_id: value(row, "request_id")?,
        owner_actor_id: ActorId::new(value::<String>(row, "owner_actor_id")?),
        source_thread_id: ThreadId::new(value::<String>(row, "source_thread_id")?),
        source_run_id: RunId::new(value::<String>(row, "source_run_id")?),
        source_message_id: value(row, "source_message_id")?,
        source_call_seq: sequence(value(row, "source_call_seq")?)?,
        source_attempt_seq: sequence(value(row, "source_attempt_seq")?)?,
    })
}
fn decode_metadata(row: &Row) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
    let status: String = value(row, "status")?;
    if matches!(status.as_str(), "deleted" | "expired") {
        let r = decode_receipt(row)?;
        let tombstone = ArtifactTombstone {
            artifact_id: r.artifact_id,
            operation_id: r.operation_id,
            request_id: r.request_id,
            owner_actor_id: r.owner_actor_id,
            source_thread_id: r.source_thread_id,
            source_run_id: r.source_run_id,
            source_message_id: r.source_message_id,
            source_call_seq: r.source_call_seq,
            source_attempt_seq: r.source_attempt_seq,
        };
        return Ok(if status == "deleted" {
            ArtifactMetadata::Deleted(tombstone)
        } else {
            ArtifactMetadata::Expired(tombstone)
        });
    }
    let kind: String = value(row, "workspace_kind")?;
    let workspace_id: String = value(row, "workspace_id")?;
    let workspace = match kind.as_str() {
        "channel" => ArtifactWorkspace::Channel { id: workspace_id },
        "thread" => ArtifactWorkspace::Thread { id: workspace_id },
        _ => return Err(corrupt("workspace_kind")),
    };
    let record = ArtifactRecordMetadata {
        artifact_id: value(row, "artifact_id")?,
        deployment_id: DeploymentId::new(value::<String>(row, "deployment_id")?),
        tenant_id: TenantId::new(value::<String>(row, "tenant_id")?),
        dataset_id: value(row, "dataset_id")?,
        owner_actor_id: ActorId::new(value::<String>(row, "owner_actor_id")?),
        workspace,
        source_thread_id: ThreadId::new(value::<String>(row, "source_thread_id")?),
        source_run_id: RunId::new(value::<String>(row, "source_run_id")?),
        source_call_seq: sequence(value(row, "source_call_seq")?)?,
        source_attempt_seq: sequence(value(row, "source_attempt_seq")?)?,
        media_type: value(row, "media_type")?,
        byte_length: unsigned(value(row, "byte_length")?)?,
        sha256: value(row, "sha256")?,
        retention_class: ArtifactRetentionClass::ExplicitSaved,
        saved_by: value::<Option<String>>(row, "saved_by")?.map(ActorId::new),
        saved_at: value::<Option<OffsetDateTime>>(row, "saved_at")?,
    };
    match status.as_str() {
        "available" => Ok(ArtifactMetadata::Available(record)),
        "failed_partial" => Ok(ArtifactMetadata::FailedPartial(record)),
        _ => Err(corrupt("status")),
    }
}
fn value<T: for<'a> tokio_postgres::types::FromSql<'a>>(
    row: &Row,
    column: &'static str,
) -> Result<T, ArtifactAdministrationError> {
    row.try_get(column).map_err(|_| corrupt(column))
}
fn integer(value: u64) -> Result<i64, ArtifactAdministrationError> {
    i64::try_from(value).map_err(|_| corrupt("integer_overflow"))
}
fn unsigned(value: i64) -> Result<u64, ArtifactAdministrationError> {
    u64::try_from(value).map_err(|_| corrupt("negative_usage"))
}
fn sequence(value: Option<i64>) -> Result<Option<u64>, ArtifactAdministrationError> {
    value.map(unsigned).transpose()
}
fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for byte in digest {
        s.push(char::from(HEX[usize::from(byte >> 4)]));
        s.push(char::from(HEX[usize::from(byte & 15)]));
    }
    s
}
fn parse_digest(text: &str) -> Result<[u8; 32], ArtifactAdministrationError> {
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        let a = char::from(text.as_bytes()[i * 2])
            .to_digit(16)
            .ok_or_else(|| corrupt("expected_digest"))?;
        let b = char::from(text.as_bytes()[i * 2 + 1])
            .to_digit(16)
            .ok_or_else(|| corrupt("expected_digest"))?;
        *byte = u8::try_from(a * 16 + b).map_err(|_| corrupt("expected_digest"))?;
    }
    Ok(digest)
}
const fn unavailable() -> ArtifactAdministrationError {
    ArtifactAdministrationError::Unavailable
}
const fn corrupt(field: &'static str) -> ArtifactAdministrationError {
    ArtifactAdministrationError::Corrupt { field }
}

fn observed_read_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| format!("{VISIBLE_RUN} \
        /* artifact_private_read_record_snapshot */ \
        SELECT a.*, \
          CASE t.anchor_kind WHEN 'channel' THEN 'channel' WHEN 'direct_bot' THEN 'thread' END AS source_workspace_kind, \
          CASE t.anchor_kind WHEN 'channel' THEN t.anchor_id WHEN 'direct_bot' THEN t.thread_id END AS source_workspace_id, \
          o.state AS op_state,o.store_id AS op_store_id,o.workspace_kind AS op_workspace_kind,o.workspace_id AS op_workspace_id, \
          o.expected_sha256 AS op_expected_sha256,o.expected_bytes AS op_expected_bytes,o.charged_bytes AS op_charged_bytes, \
          o.actual_absent AS op_actual_absent,o.actual_byte_length AS op_actual_byte_length,o.actual_sha256 AS op_actual_sha256, \
          o.actual_location AS op_actual_location,o.observation_phase AS op_observation_phase, \
          c.deployment_id AS cleanup_deployment_id,c.tenant_id AS cleanup_tenant_id, \
          c.dataset_id AS cleanup_dataset_id,c.operation_id AS cleanup_operation_id, \
          c.artifact_id AS cleanup_artifact_id,c.terminal_status AS cleanup_terminal_status, \
          c.phase AS cleanup_phase, \
          EXISTS(SELECT 1 FROM openbot_internal.artifact_dataset_bindings d \
             JOIN openbot_internal.artifact_store_bindings s USING(deployment_id,tenant_id,dataset_id) \
             WHERE d.deployment_id=$4 AND d.tenant_id=$5 AND d.dataset_id=$8 AND d.binding_schema=$9 \
               AND d.initial_origin=$10 AND d.created_at=$11 AND s.store_id=$12 \
               AND s.root_device=$13 AND s.root_inode=$14 AND s.root_uid=$15) AS current_store_binding \
        FROM visible_run r JOIN openbot_internal.artifact_records a \
          ON a.source_thread_id=r.thread_id AND a.source_run_id=r.run_id \
        JOIN public.threads t ON t.thread_id=r.thread_id \
        JOIN public.messages m ON m.message_id=a.source_message_id AND m.thread_id=a.source_thread_id \
          AND m.run_id=a.source_run_id AND m.actor_id=a.owner_actor_id AND m.role='user' \
        LEFT JOIN openbot_internal.artifact_save_operations o \
          ON o.deployment_id=a.deployment_id AND o.tenant_id=a.tenant_id AND o.dataset_id=a.dataset_id \
          AND o.operation_id=a.operation_id AND o.artifact_id=a.artifact_id AND o.request_id=a.request_id \
          AND o.owner_actor_id=a.owner_actor_id AND o.source_thread_id=a.source_thread_id \
          AND o.source_run_id=a.source_run_id AND o.source_message_id=a.source_message_id \
          AND o.source_call_seq IS NOT DISTINCT FROM a.source_call_seq \
          AND o.source_attempt_seq IS NOT DISTINCT FROM a.source_attempt_seq \
        LEFT JOIN openbot_internal.artifact_cleanup_fences c \
          ON c.deployment_id=a.deployment_id AND c.tenant_id=a.tenant_id \
          AND c.dataset_id=a.dataset_id AND c.artifact_id=a.artifact_id \
        WHERE a.owner_actor_id=$3 AND a.deployment_id=$4 AND a.tenant_id=$5 \
          AND a.artifact_id=$7 AND a.dataset_id=$8"))
}

fn decode_read_cleanup_fence(
    row: &Row,
    expected: &ArtifactCleanupFenceKey,
) -> Result<Option<ArtifactCleanupFence>, ArtifactAdministrationError> {
    let fields = [
        "cleanup_deployment_id",
        "cleanup_tenant_id",
        "cleanup_dataset_id",
        "cleanup_operation_id",
        "cleanup_artifact_id",
        "cleanup_terminal_status",
        "cleanup_phase",
    ]
    .map(|name| value::<Option<String>>(row, name));
    let fields = fields
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| corrupt("read_cleanup_fence"))?;
    if fields.iter().all(Option::is_none) {
        return Ok(None);
    }
    let stored = fields
        .iter()
        .map(|field| {
            field
                .as_deref()
                .ok_or_else(|| corrupt("read_cleanup_fence"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = ArtifactCleanupFenceKey::from_stored(
        DeploymentId::new(stored[0]),
        TenantId::new(stored[1]),
        stored[2],
        stored[3],
        stored[4],
    )
    .map_err(|_| corrupt("read_cleanup_fence"))?;
    if &key != expected {
        return Err(corrupt("read_cleanup_fence"));
    }
    ArtifactCleanupFence::from_stored(key, stored[5], stored[6])
        .map(Some)
        .map_err(|_| corrupt("read_cleanup_fence"))
}

#[cfg(test)]
#[path = "artifact_read_bridge_tests.rs"]
mod read_bridge_tests;
