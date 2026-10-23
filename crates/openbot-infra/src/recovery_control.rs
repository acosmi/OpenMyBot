//! External recovery control: bounded data and the original held owner.
//!
//! Opening control does not create an activation, epoch, ordinary authority or
//! restore grant. Consumer and original resource adapters are separate hunks.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

mod activation;
mod clock;
mod entry;
mod journal;
mod runtime;

pub use activation::{ActivationBinding, ActivationPhase};
pub use entry::{
    OwnedRecoveryRequestFile, VerifiedOrdinaryStartupIntent, VerifiedRecoveryHost,
    VerifiedRecoveryHostIntent, VerifiedServiceRecoveryHost, load_service_recovery_host_from_config,
};
pub use runtime::{RecoveryReadGate, RecoveryRuntimeOwner};
#[cfg(feature = "server-runtime")]
pub use runtime::ServerRuntimeAuthorizationKeys;

/// Redacted closed failure class; original IO stays with its original owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryControlFault {
    EntryInvalid,
    OwnerBusy,
    InitializationRequired,
    ControlInvalid,
    InputInvalid,
    ProfileInvalid,
    CapacityExceeded,
    EffectExpired,
    ConvergenceExpired,
    OwnerLost,
    ClosureUnproven,
    IoFailure,
}

/// Error retaining the same original control owner, never a success receipt.
pub struct RecoveryControlError {
    fault: RecoveryControlFault,
    retained: Option<entry::ControlOwner>,
    original_json_error: Option<serde_json::Error>,
}

impl RecoveryControlError {
    pub(crate) fn new(fault: RecoveryControlFault) -> Self {
        Self { fault, retained: None, original_json_error: None }
    }

    fn with_owner(fault: RecoveryControlFault, owner: &entry::ControlOwner) -> Self {
        Self { fault, retained: Some(Arc::clone(owner)), original_json_error: None }
    }

    fn retain(mut self, owner: &entry::ControlOwner) -> Self {
        self.retained = Some(Arc::clone(owner));
        self
    }

    fn from_json(error: serde_json::Error) -> Self {
        Self { fault: RecoveryControlFault::ControlInvalid, retained: None, original_json_error: Some(error) }
    }

    /// Stable error kind. It contains no path, secret or untrusted error text.
    #[must_use]
    pub const fn fault(&self) -> RecoveryControlFault {
        self.fault
    }
}

impl fmt::Debug for RecoveryControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryControlError")
            .field("fault", &self.fault)
            .field("retains_original_owner", &self.retained.is_some())
            .finish()
    }
}

impl fmt::Display for RecoveryControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recovery_control_{:?}", self.fault)
    }
}
impl std::error::Error for RecoveryControlError {}

/// Actual held directory/file identity. Decoded values are data, not proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}

impl RecoveryFileIdentity {
    fn validate(self) -> Result<(), RecoveryControlError> {
        if self.device == 0 || self.inode == 0 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }
}

/// Required nullable key. Untagged content decoding rejects a missing key;
/// unlike Option's missing-field behavior, null is an explicit JSON value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum RequiredNullable<T> {
    Value(T),
    Null(()),
}

/// Original trusted host's pre-request limits; there are no default values.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedHostRecoveryLimits {
    pub max_request_bytes: u64,
    pub max_activation_bytes: u64,
    pub max_journal_frame_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_journal_records: u64,
    pub max_runtime_record_bytes: u64,
    pub max_registered_runtimes: u64,
    pub max_retained_operations: u64,
    pub max_root_entries: u64,
    pub max_temp_entries: u64,
    pub max_evidence_refs: u64,
    pub max_runtime_resource_facts: u64,
    pub max_id_bytes: u64,
    pub max_component_bytes: u64,
    pub max_relative_path_bytes: u64,
    pub max_path_depth: u64,
    pub max_open_files: u64,
    pub max_metadata_bytes: u64,
    pub admission_ns: u64,
}

impl TrustedHostRecoveryLimits {
    /// Validate only the registered finite bounds and representation limits.
    pub fn checked(self) -> Result<Self, RecoveryControlError> {
        let values = [
            self.max_request_bytes, self.max_activation_bytes,
            self.max_journal_frame_bytes, self.max_journal_bytes,
            self.max_journal_records, self.max_runtime_record_bytes,
            self.max_registered_runtimes, self.max_retained_operations,
            self.max_root_entries, self.max_temp_entries, self.max_evidence_refs,
            self.max_runtime_resource_facts, self.max_id_bytes,
            self.max_component_bytes, self.max_relative_path_bytes,
            self.max_path_depth, self.max_open_files, self.max_metadata_bytes,
            self.admission_ns,
        ];
        if values.into_iter().any(|value| value == 0 || usize::try_from(value).is_err())
            || u32::try_from(self.max_journal_frame_bytes).is_err()
            || self.max_journal_frame_bytes.checked_add(44).is_none()
            || self.max_journal_bytes < self.max_journal_frame_bytes + 44
            || Instant::now().checked_add(std::time::Duration::from_nanos(self.admission_ns)).is_none()
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
        }
        Ok(self)
    }
}

/// One explicitly chosen restore operation's capacity, never a global quota.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreOperationCapacity {
    pub max_input_wire_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_material_files: u64,
    pub max_material_directories: u64,
    pub max_single_material_bytes: u64,
    pub max_material_plain_bytes: u64,
    pub max_path_bytes: u64,
    pub max_path_depth: u64,
    pub max_candidate_data_bytes: u64,
    pub max_candidate_wal_bytes: u64,
    pub max_candidate_temp_bytes: u64,
    pub max_spool_bytes: u64,
    pub max_retained_prior_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_journal_records: u64,
    pub max_metadata_bytes: u64,
    pub max_open_files: u64,
    pub max_native_tasks: u64,
    pub max_pg_connections: u64,
    pub max_pg_transactions: u64,
    pub max_pg_rows: u64,
    pub max_reconfirm_requirements: u64,
    pub max_secret_memory_bytes: u64,
    pub max_secret_structure_bytes: u64,
    pub max_total_allocation_bytes: u64,
    pub reserve_bytes: u64,
    pub free_floor_bytes: u64,
    pub max_key_medium_allocation_bytes: u64,
    pub key_medium_reserve_bytes: u64,
    pub key_medium_free_floor_bytes: u64,
}

/// Effect/convergence apply once to the same original live operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreOperationProfile {
    pub effect_ns: u64,
    pub convergence_ns: u64,
    pub capacity: RestoreOperationCapacity,
}

impl RestoreOperationProfile {
    /// Compare exactly the six named host ceilings; other explicit fields do
    /// not acquire imaginary host caps or defaults.
    pub fn checked(self, host: &TrustedHostRecoveryLimits) -> Result<Self, RecoveryControlError> {
        let c = &self.capacity;
        let values = [
            self.effect_ns, self.convergence_ns, c.max_input_wire_bytes,
            c.max_manifest_bytes, c.max_material_files, c.max_material_directories,
            c.max_single_material_bytes, c.max_material_plain_bytes, c.max_path_bytes,
            c.max_path_depth, c.max_candidate_data_bytes, c.max_candidate_wal_bytes,
            c.max_candidate_temp_bytes, c.max_spool_bytes, c.max_retained_prior_bytes,
            c.max_journal_bytes, c.max_journal_records, c.max_metadata_bytes,
            c.max_open_files, c.max_native_tasks, c.max_pg_connections,
            c.max_pg_transactions, c.max_pg_rows, c.max_reconfirm_requirements,
            c.max_secret_memory_bytes, c.max_secret_structure_bytes,
            c.max_total_allocation_bytes, c.reserve_bytes, c.free_floor_bytes,
            c.max_key_medium_allocation_bytes, c.key_medium_reserve_bytes,
            c.key_medium_free_floor_bytes,
        ];
        if values.into_iter().any(|value| value == 0 || usize::try_from(value).is_err())
            || self.effect_ns.checked_add(self.convergence_ns).is_none()
            || c.max_journal_bytes > host.max_journal_bytes
            || c.max_journal_records > host.max_journal_records
            || c.max_metadata_bytes > host.max_metadata_bytes
            || c.max_open_files > host.max_open_files
            || c.max_path_depth > host.max_path_depth
            || c.max_path_bytes > host.max_relative_path_bytes
            || c.reserve_bytes.checked_add(c.free_floor_bytes).is_none()
            || c.key_medium_reserve_bytes.checked_add(c.key_medium_free_floor_bytes).is_none()
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
        }
        Ok(self)
    }
}

/// Configuration consumes the real original host source, not a raw path.
pub struct RecoveryControlConfig {
    root: std::path::PathBuf,
    app_component: Option<std::ffi::OsString>,
    uid: u32,
    limits: TrustedHostRecoveryLimits,
    service_source: Option<VerifiedServiceRecoveryHost>,
}

impl RecoveryControlConfig {
    /// Current-user path assertion is consumed at its original host edge.
    /// open additionally authenticates real held/named owner and ancestry.
    #[cfg(feature = "desktop-local")]
    pub fn local(
        actual: crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        limits: TrustedHostRecoveryLimits,
    ) -> Result<Self, RecoveryControlError> {
        let path = actual.as_path();
        let parent = path.parent().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        let component = path.file_name().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if component == "com.acosmi.wrokbot.restore-control" {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        Ok(Self {
            root: parent.join("com.acosmi.wrokbot.restore-control"),
            app_component: Some(component.to_os_string()),
            uid: rustix::process::getuid().as_raw(),
            limits: limits.checked()?,
            service_source: None,
        })
    }

    /// Only the registered verified original service-host producer supplies
    /// this non-Serde value; a configuration DTO cannot construct it.
    pub fn server(
        mut actual: VerifiedServiceRecoveryHost,
        limits: TrustedHostRecoveryLimits,
    ) -> Result<Self, RecoveryControlError> {
        if !actual.matches_limits(&limits) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
        }
        let deadline = Instant::now().checked_add(std::time::Duration::from_nanos(limits.admission_ns))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        actual.recheck_original(deadline)?;
        let root = std::mem::take(&mut actual.root);
        let uid = actual.uid;
        Ok(Self { root, app_component: None, uid, limits: limits.checked()?, service_source: Some(actual) })
    }
}

/// Trusted-host control/admission reservations, not a restore-operation budget.
/// Unknown reservations remain held. A definite Busy attempt or an actually
/// dropped ordinary admission retires only its own header/FD, never a restore effect.
struct ControlBudget {
    metadata: u64,
    files: u64,
    metadata_limit: u64,
    file_limit: u64,
}

impl ControlBudget {
    fn charge(&mut self, metadata: u64, files: u64) -> Result<(), RecoveryControlError> {
        let m = self.metadata.checked_add(metadata);
        let f = self.files.checked_add(files);
        match (m, f) {
            (Some(m), Some(f)) if m <= self.metadata_limit && f <= self.file_limit => {
                self.metadata = m;
                self.files = f;
                Ok(())
            }
            _ => Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)),
        }
    }

    fn retire_ordinary_leases(&mut self, metadata: u64, files: u64) -> Result<(), RecoveryControlError> {
        let m = self.metadata.checked_sub(metadata);
        let f = self.files.checked_sub(files);
        match (m, f) {
            (Some(m), Some(f)) => { self.metadata = m; self.files = f; Ok(()) }
            _ => Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost)),
        }
    }
}

/// One original external-control resource owner. It has no Clone/Serde API.
pub struct RecoveryControl {
    shared: entry::ControlOwner,
}

impl RecoveryControl {
    /// Open/authenticate the external root. Missing head remains missing.
    pub fn open(config: RecoveryControlConfig) -> Result<Self, RecoveryControlError> {
        entry::open_control(config).map(|shared| Self { shared })
    }

    /// Authenticate the held original request and host within one admission
    /// deadline. No parser result or enum is a restore authority.
    pub fn verify_host_intent_before(
        &self,
        request: OwnedRecoveryRequestFile,
        host: VerifiedRecoveryHost,
        deadline: Instant,
    ) -> Result<VerifiedRecoveryHostIntent, RecoveryControlError> {
        entry::verify_intent(&self.shared, request, host, deadline)
    }

    /// Existing ordinary Server startup only. It retains original SH before
    /// connecting and performs no initialization DDL, adoption or restoration.
    /// Missing/Pending/RestoreCurrent stays closed before any pool probe.
    pub async fn open_existing_server_before(
        &mut self,
        database: &crate::db::pool::DatabaseConfig,
        configured_master_encoding: openbot_domain::vault::SecretBytes,
        deployment: &str,
        tenant: &str,
        deadline: Instant,
    ) -> Result<(crate::db::pool::DatabasePool, RecoveryRuntimeOwner), RecoveryControlError> {
        let intent = entry::observe_existing_server_before(
            &self.shared, database, configured_master_encoding, deployment, tenant, deadline,
        ).await?;
        let runtime = runtime::enter_runtime(&self.shared, intent, deadline)?;
        let files = entry::lock(&self.shared)?;
        files.existing_server_pool().map(|pool| (pool.clone(), runtime))
    }

    /// Retain the original runtime lock only after a truly published head and
    /// the original sealed ordinary-startup observation.
    pub fn enter_runtime_before(
        &self,
        intent: VerifiedOrdinaryStartupIntent,
        deadline: Instant,
    ) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        runtime::enter_runtime(&self.shared, intent, deadline)
    }
}

fn id(value: &str, limit: u64) -> Result<(), RecoveryControlError> {
    if value.is_empty() || u64::try_from(value.len()).map_or(true, |n| n > limit)
        || value.chars().any(|c| c.is_control())
    {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    Ok(())
}

fn hex(value: &str, n: usize, nonzero: bool) -> Result<(), RecoveryControlError> {
    if value.len() != n || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || (nonzero && value.bytes().all(|b| b == b'0'))
    {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    Ok(())
}

fn component(value: &str, limits: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
    id(value, limits.max_component_bytes)?;
    if value == "." || value == ".." || value.contains('/') || value.contains('\\') {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    Ok(())
}

fn before(deadline: Instant) -> Result<(), RecoveryControlError> {
    if Instant::now() >= deadline {
        Err(RecoveryControlError::new(RecoveryControlFault::EffectExpired))
    } else {
        Ok(())
    }
}
