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
    VerifiedRecoveryHostIntent, VerifiedServiceRecoveryHost,
    load_service_recovery_host_from_config,
};
#[cfg(feature = "server-runtime")]
pub use runtime::AuthorizationPurpose;
pub(crate) use runtime::RecoveryWorkerLease;
pub use runtime::{RecoveryReadGate, RecoveryRuntimeOwner};

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
        Self {
            fault,
            retained: None,
            original_json_error: None,
        }
    }

    fn with_owner(fault: RecoveryControlFault, owner: &entry::ControlOwner) -> Self {
        Self {
            fault,
            retained: Some(Arc::clone(owner)),
            original_json_error: None,
        }
    }

    fn retain(mut self, owner: &entry::ControlOwner) -> Self {
        self.retained = Some(Arc::clone(owner));
        self
    }

    fn from_json(error: serde_json::Error) -> Self {
        Self {
            fault: RecoveryControlFault::ControlInvalid,
            retained: None,
            original_json_error: Some(error),
        }
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
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
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
            self.max_request_bytes,
            self.max_activation_bytes,
            self.max_journal_frame_bytes,
            self.max_journal_bytes,
            self.max_journal_records,
            self.max_runtime_record_bytes,
            self.max_registered_runtimes,
            self.max_retained_operations,
            self.max_root_entries,
            self.max_temp_entries,
            self.max_evidence_refs,
            self.max_runtime_resource_facts,
            self.max_id_bytes,
            self.max_component_bytes,
            self.max_relative_path_bytes,
            self.max_path_depth,
            self.max_open_files,
            self.max_metadata_bytes,
            self.admission_ns,
        ];
        if values
            .into_iter()
            .any(|value| value == 0 || usize::try_from(value).is_err())
            || u32::try_from(self.max_journal_frame_bytes).is_err()
            || self.max_journal_frame_bytes.checked_add(44).is_none()
            || self.max_journal_bytes < self.max_journal_frame_bytes + 44
            || Instant::now()
                .checked_add(std::time::Duration::from_nanos(self.admission_ns))
                .is_none()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ProfileInvalid,
            ));
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
            self.effect_ns,
            self.convergence_ns,
            c.max_input_wire_bytes,
            c.max_manifest_bytes,
            c.max_material_files,
            c.max_material_directories,
            c.max_single_material_bytes,
            c.max_material_plain_bytes,
            c.max_path_bytes,
            c.max_path_depth,
            c.max_candidate_data_bytes,
            c.max_candidate_wal_bytes,
            c.max_candidate_temp_bytes,
            c.max_spool_bytes,
            c.max_retained_prior_bytes,
            c.max_journal_bytes,
            c.max_journal_records,
            c.max_metadata_bytes,
            c.max_open_files,
            c.max_native_tasks,
            c.max_pg_connections,
            c.max_pg_transactions,
            c.max_pg_rows,
            c.max_reconfirm_requirements,
            c.max_secret_memory_bytes,
            c.max_secret_structure_bytes,
            c.max_total_allocation_bytes,
            c.reserve_bytes,
            c.free_floor_bytes,
            c.max_key_medium_allocation_bytes,
            c.key_medium_reserve_bytes,
            c.key_medium_free_floor_bytes,
        ];
        if values
            .into_iter()
            .any(|value| value == 0 || usize::try_from(value).is_err())
            || self.effect_ns.checked_add(self.convergence_ns).is_none()
            || c.max_journal_bytes > host.max_journal_bytes
            || c.max_journal_records > host.max_journal_records
            || c.max_metadata_bytes > host.max_metadata_bytes
            || c.max_open_files > host.max_open_files
            || c.max_path_depth > host.max_path_depth
            || c.max_path_bytes > host.max_relative_path_bytes
            || c.reserve_bytes.checked_add(c.free_floor_bytes).is_none()
            || c.key_medium_reserve_bytes
                .checked_add(c.key_medium_free_floor_bytes)
                .is_none()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ProfileInvalid,
            ));
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
        let parent = path
            .parent()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        let component = path
            .file_name()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if component == "com.acosmi.wrokbot.restore-control" {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
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
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ProfileInvalid,
            ));
        }
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_nanos(limits.admission_ns))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
        actual.recheck_original(deadline)?;
        let root = std::mem::take(&mut actual.root);
        let uid = actual.uid;
        Ok(Self {
            root,
            app_component: None,
            uid,
            limits: limits.checked()?,
            service_source: Some(actual),
        })
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
            _ => Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            )),
        }
    }

    fn retire_ordinary_leases(
        &mut self,
        metadata: u64,
        files: u64,
    ) -> Result<(), RecoveryControlError> {
        let m = self.metadata.checked_sub(metadata);
        let f = self.files.checked_sub(files);
        match (m, f) {
            (Some(m), Some(f)) => {
                self.metadata = m;
                self.files = f;
                Ok(())
            }
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
            &self.shared,
            database,
            configured_master_encoding,
            deployment,
            tenant,
            deadline,
        )
        .await?;
        let runtime = runtime::enter_runtime(&self.shared, intent, deadline)?;
        let files = entry::lock(&self.shared)?;
        files
            .existing_server_pool()
            .map(|pool| (pool.clone(), runtime))
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
    if value.is_empty()
        || u64::try_from(value.len()).map_or(true, |n| n > limit)
        || value.chars().any(|c| c.is_control())
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    Ok(())
}

fn hex(value: &str, n: usize, nonzero: bool) -> Result<(), RecoveryControlError> {
    if value.len() != n
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || (nonzero && value.bytes().all(|b| b == b'0'))
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    Ok(())
}

/// Bytes of lowercase hex text already checked by `hex` when it was decoded.
fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    let digit = |c: u8| {
        if c.is_ascii_digit() {
            c - b'0'
        } else {
            c - b'a' + 10
        }
    };
    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    bytes
}

fn component(value: &str, limits: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
    id(value, limits.max_component_bytes)?;
    if value == "." || value == ".." || value.contains('/') || value.contains('\\') {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    Ok(())
}

fn before(deadline: Instant) -> Result<(), RecoveryControlError> {
    if Instant::now() >= deadline {
        Err(RecoveryControlError::new(
            RecoveryControlFault::EffectExpired,
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::activation::{ActivationRecord, JournalPositionRef, observe};
    use super::journal::{canonical_record, digest_hex, observe_chain};
    use super::{RecoveryControlFault, RecoveryFileIdentity, TrustedHostRecoveryLimits};

    const CONTROL: &str = "0123456789abcdef0123456789abcdef";
    const OPERATION: &str = "fedcba9876543210fedcba9876543210";
    const EPOCH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ZERO64: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn limits() -> TrustedHostRecoveryLimits {
        TrustedHostRecoveryLimits {
            max_request_bytes: 65536,
            max_activation_bytes: 65536,
            max_journal_frame_bytes: 65536,
            max_journal_bytes: 1 << 20,
            max_journal_records: 64,
            max_runtime_record_bytes: 65536,
            max_registered_runtimes: 8,
            max_retained_operations: 8,
            max_root_entries: 64,
            max_temp_entries: 8,
            max_evidence_refs: 16,
            max_runtime_resource_facts: 16,
            max_id_bytes: 128,
            max_component_bytes: 128,
            max_relative_path_bytes: 1024,
            max_path_depth: 16,
            max_open_files: 64,
            max_metadata_bytes: 1 << 24,
            admission_ns: 1_000_000_000,
        }
    }

    fn file(inode: u64) -> Value {
        json!({"device": 7, "inode": inode, "uid": 501})
    }

    fn binding() -> Value {
        let key = |kind: &str| {
            json!({"kind": kind, "reviewedService": "svc", "account": "acct",
            "keyId": "key", "keyVersion": 1, "targetInstallationId": "target", "operationId": OPERATION})
        };
        json!({"siteKind": "local_physical", "datasetId": "data", "deploymentId": "dep", "tenantId": "ten",
            "sourceInstallationId": "source", "targetInstallationId": "target",
            "generationId": "abcdefabcdefabcdefabcdefabcdef01", "generationRoot": file(11),
            "pgSystemId": 7_000_000_001u64, "databaseOid": 16384, "pgMajor": 17, "nativeVersion": 53,
            "migrationDigest": ZERO64, "authorizationEpoch": EPOCH,
            "keyRefs": [key("historical_master"), key("postgres_scram")]})
    }

    fn reference(sequence: u64) -> Value {
        json!({"contextId": OPERATION, "sequence": sequence, "digest": ZERO64})
    }

    fn position(sequence: u64) -> Value {
        json!({"contextId": OPERATION, "sequence": sequence})
    }

    fn clock() -> Value {
        json!({"clockKind": "CLOCK_MONOTONIC", "bootIdentity": "boot", "pid": 42,
            "processStart": {"seconds": 1, "nanos": 2}, "ownerNonce": CONTROL,
            "t0Ns": 10, "effectDeadlineNs": 20, "convergenceDeadlineNs": 30})
    }

    fn host() -> Value {
        json!({"siteKind": "local_physical", "actualOsOwner": {"kind": "LocalUid", "data": {"uid": 501}},
            "appDataParent": file(3), "controlRoot": file(4), "reviewedReleaseDigest": ZERO64})
    }

    fn planned() -> Value {
        json!({"siteKind": "local_physical", "trustedParent": file(3), "entryComponent": "app", "installationId": "target"})
    }

    /// One canonical descriptor per phase; each publication position is distinct.
    fn descriptors() -> [(&'static str, Value); 5] {
        let record = |phase: &str, data: Value| {
            json!({"recordType": "wrokbot-recovery-activation", "version": 1,
            "controlId": CONTROL, "revision": 1, "previousDigest": null, "phase": phase, "data": data})
        };
        [
            (
                "OrdinaryInitializing",
                record(
                    "OrdinaryInitializing",
                    json!({"intentId": OPERATION, "mode": "fresh",
                "hostBinding": host(), "plannedInstallation": planned(), "initialEpoch": EPOCH,
                "limitsDigest": ZERO64, "initJournalPrefix": position(1)}),
                ),
            ),
            (
                "OrdinaryActive",
                record(
                    "OrdinaryActive",
                    json!({"binding": binding(),
                "initializationEvidence": [reference(3)], "publishIntent": position(4)}),
                ),
            ),
            (
                "RestorePending",
                record(
                    "RestorePending",
                    json!({"operationId": OPERATION, "epoch": EPOCH,
                "profileDigest": ZERO64, "priorBinding": null,
                "candidatePlan": {"siteKind": "local_physical", "trustedParent": file(3), "entryComponent": "app",
                    "installationId": "target", "generationId": "abcdefabcdefabcdefabcdefabcdef01"},
                "inputPlanDigest": ZERO64, "ownerClock": clock(), "journalPrefix": reference(1)}),
                ),
            ),
            (
                "SwitchedPending",
                record(
                    "SwitchedPending",
                    json!({"operationId": OPERATION, "epoch": EPOCH,
                "profileDigest": ZERO64, "binding": binding(), "closureEvidence": [reference(3)],
                "publishIntent": position(7)}),
                ),
            ),
            (
                "RestoreCurrent",
                record(
                    "RestoreCurrent",
                    json!({"operationId": OPERATION, "epoch": EPOCH,
                "profileDigest": ZERO64, "binding": binding(), "closureEvidence": [reference(3)],
                "switchReadback": reference(5), "publishIntent": position(9)}),
                ),
            ),
        ]
    }

    fn canonical_descriptor(value: Value) -> Vec<u8> {
        let record: ActivationRecord = serde_json::from_value(value).expect("closed descriptor");
        serde_json::to_vec(&record).expect("descriptor encodes")
    }

    fn descriptor_digest(bytes: &[u8]) -> String {
        digest_hex(
            &Sha256::new()
                .chain_update(b"wrokbot.restore.activation.v1\0")
                .chain_update(bytes)
                .finalize()
                .into(),
        )
    }

    /// Frame each body as WBRCJ001 || L u32BE || JSON || SHA256(domain || NUL || magic || L || JSON),
    /// chaining every record's previousDigest to the prior frame digest; `edit`
    /// may then corrupt one body before its own frame digest is computed.
    fn frames_with(bodies: &[Value], edit: impl Fn(usize, &mut Value)) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut previous = ZERO64.to_owned();
        for (index, body) in bodies.iter().enumerate() {
            let mut body = body.clone();
            body["sequence"] = json!(index + 1);
            body["previousDigest"] = json!(previous);
            edit(index, &mut body);
            let json = canonical_record(body);
            let start = raw.len();
            raw.extend_from_slice(b"WBRCJ001");
            raw.extend_from_slice(&u32::try_from(json.len()).expect("small body").to_be_bytes());
            raw.extend_from_slice(&json);
            let digest = Sha256::new()
                .chain_update(b"wrokbot.restore.journal.v1\0")
                .chain_update(&raw[start..])
                .finalize();
            raw.extend_from_slice(&digest);
            previous = digest_hex(&digest.into());
        }
        raw
    }

    fn frames(bodies: &[Value]) -> Vec<u8> {
        frames_with(bodies, |_, _| ())
    }

    fn journal_record(kind: &str, data: Value) -> Value {
        json!({"recordType": "wrokbot-recovery-journal", "version": 1, "controlId": CONTROL,
            "operationId": OPERATION, "epoch": EPOCH, "sequence": 0, "previousDigest": ZERO64,
            "kind": kind, "data": data})
    }

    /// All six kinds: Fresh OperationIntent naming the Initializing descriptor,
    /// a confirmed stage, a synced publication of `active`, then a read-only result.
    fn six_kinds(initializing: &str, active: &str) -> Vec<Value> {
        vec![
            journal_record(
                "OperationIntent",
                json!({"mode": "fresh_init", "hostBinding": host(),
                "originalStartupIntent": CONTROL, "plannedInstallation": planned(),
                "ordinaryStartupBounds": {"effectNs": 5, "convergenceNs": 9},
                "initializingDescriptorDigest": initializing, "originalClockRelation": clock()}),
            ),
            journal_record(
                "StageIntent",
                json!({"stage": "ordinary_initialize", "originalEffectId": CONTROL,
                "expectedBinding": null}),
            ),
            journal_record(
                "StageObserved",
                json!({"intentSequence": 2,
                "typedDisposition": {"kind": "TaskReturned", "data": {"original_task_id": "task", "observed_ns": 3}},
                "actualBinding": null, "receiptRefs": []}),
            ),
            journal_record(
                "PublishIntent",
                json!({"expectedPhase": "OrdinaryActive", "descriptorDigest": active,
                "receiptRefs": []}),
            ),
            journal_record(
                "PublishObserved",
                json!({"intentSequence": 4, "descriptorDigest": active,
                "actualFileIdentity": file(21), "disposition": "FileAndParentSyncedReadback"}),
            ),
            journal_record(
                "ReadOnlyObservation",
                json!({"originalIntent": reference(4),
                "typedObservation": {"kind": "TaskJoinUnknown", "data": {"original_task_id": "task"}}}),
            ),
        ]
    }

    fn actual_file() -> RecoveryFileIdentity {
        RecoveryFileIdentity {
            device: 7,
            inode: 21,
            uid: 501,
        }
    }

    #[test]
    fn t046_09_activation_and_journal_round_trip_exact_bytes() {
        let limits = limits();
        let mut digests = Vec::new();
        for (phase, value) in descriptors() {
            let bytes = canonical_descriptor(value);
            let first =
                observe(&bytes, &limits).unwrap_or_else(|e| panic!("{phase} descriptor: {e}"));
            // decode -> encode -> decode keeps the exact bytes and a stable digest.
            let again = serde_json::to_vec(&first.record).expect("re-encode");
            assert_eq!(again, bytes, "{phase} re-encoding changed bytes");
            assert_eq!(
                observe(&again, &limits).expect("second observation").digest,
                first.digest
            );
            assert_eq!(
                first.digest,
                descriptor_digest(&bytes),
                "{phase} digest is domain || NUL || bytes"
            );
            digests.push(first.digest);
        }
        let (initializing, active) = (digests[0].clone(), digests[1].clone());
        let raw = frames(&six_kinds(&initializing, &active));
        let chain = observe_chain(&raw, &limits).expect("six-kind chain");
        // The Initializing position names the Fresh OperationIntent for that descriptor.
        let prefix: JournalPositionRef = serde_json::from_value(position(1)).expect("position");
        chain
            .initializing_prefix_for(&prefix, &initializing)
            .expect("initJournalPrefix");
        // The Active position reads the PublishIntent at 4 and its synced PublishObserved.
        let active_bytes = canonical_descriptor(descriptors()[1].1.clone());
        let observation = observe(&active_bytes, &limits).expect("active");
        let reference = observation.publication_reference().expect("publishIntent");
        assert_eq!(reference.sequence.get(), 4);
        chain
            .publication_for(
                CONTROL,
                &active,
                reference,
                actual_file(),
                super::ActivationPhase::OrdinaryActive,
            )
            .expect("publication at the descriptor position");
        // All four position fields survive the round trip with their own sequence.
        for (index, sequence) in [(0, 1u64), (1, 4), (3, 7), (4, 9)] {
            let bytes = canonical_descriptor(descriptors()[index].1.clone());
            let text = String::from_utf8(bytes).expect("utf8");
            assert!(
                text.contains(&format!(
                    "{{\"contextId\":\"{OPERATION}\",\"sequence\":{sequence}}}"
                )),
                "{text}"
            );
        }
    }

    #[test]
    fn t046_10_duplicate_missing_nullable_sequence_digest_torn_overflow_reject() {
        let limits = limits();
        let active =
            String::from_utf8(canonical_descriptor(descriptors()[1].1.clone())).expect("utf8");
        let fault = |raw: &[u8]| observe(raw, &limits).err().map(|e| e.fault());
        // Duplicate key, missing required-nullable key, BOM and trailing byte.
        let duplicate = active.replacen("\"revision\":1,", "\"revision\":1,\"revision\":1,", 1);
        assert!(fault(duplicate.as_bytes()).is_some());
        let missing = active.replacen("\"previousDigest\":null,", "", 1);
        assert!(fault(missing.as_bytes()).is_some());
        assert!(fault(format!("\u{feff}{active}").as_bytes()).is_some());
        assert_eq!(
            fault(format!("{active}\n").as_bytes()),
            Some(RecoveryControlFault::ControlInvalid)
        );
        // Position sequence zero never decodes.
        assert!(serde_json::from_value::<JournalPositionRef>(position(0)).is_err());
        let zero = active.replacen("\"sequence\":4}", "\"sequence\":0}", 1);
        assert!(fault(zero.as_bytes()).is_some());

        let digest = descriptor_digest(active.as_bytes());
        let initializing = descriptor_digest(&canonical_descriptor(descriptors()[0].1.clone()));
        let bodies = six_kinds(&initializing, &digest);
        let raw = frames(&bodies);
        let before = raw.clone();
        // Bad sequence and bad previous digest inside otherwise valid frames.
        let wrong_sequence = frames_with(&bodies, |i, body| {
            if i == 1 {
                body["sequence"] = json!(3)
            }
        });
        assert_eq!(
            observe_chain(&wrong_sequence, &limits)
                .err()
                .map(|e| e.fault()),
            Some(RecoveryControlFault::ControlInvalid)
        );
        let broken_link = frames_with(&bodies, |i, body| {
            if i == 1 {
                body["previousDigest"] = json!(ZERO64)
            }
        });
        assert_eq!(
            observe_chain(&broken_link, &limits)
                .err()
                .map(|e| e.fault()),
            Some(RecoveryControlFault::ControlInvalid)
        );
        // Torn tail and a frame length above the bound.
        assert!(observe_chain(&raw[..raw.len() - 1], &limits).is_err());
        let mut oversized = raw.clone();
        oversized[8..12].copy_from_slice(
            &u32::try_from(limits.max_journal_frame_bytes + 1)
                .expect("bound")
                .to_be_bytes(),
        );
        assert_eq!(
            observe_chain(&oversized, &limits).err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
        assert_eq!(raw, before, "the observed bytes are never repaired");

        let chain = observe_chain(&raw, &limits).expect("chain");
        let at = |sequence: u64| -> JournalPositionRef {
            serde_json::from_value(position(sequence)).expect("position")
        };
        let phase = super::ActivationPhase::OrdinaryActive;
        // Wrong kind (a StageIntent), wrong digest, wrong phase and beyond the tail.
        assert!(
            chain
                .publication_for(CONTROL, &digest, &at(2), actual_file(), phase)
                .is_err()
        );
        assert!(
            chain
                .publication_for(CONTROL, &initializing, &at(4), actual_file(), phase)
                .is_err()
        );
        assert!(
            chain
                .publication_for(
                    CONTROL,
                    &digest,
                    &at(4),
                    actual_file(),
                    super::ActivationPhase::RestoreCurrent
                )
                .is_err()
        );
        assert!(
            chain
                .publication_for(CONTROL, &digest, &at(7), actual_file(), phase)
                .is_err()
        );
        assert!(
            chain
                .initializing_prefix_for(&at(4), &initializing)
                .is_err()
        );
        assert!(chain.initializing_prefix_for(&at(1), &digest).is_err());
        // The same record observed for another file identity is not this publication.
        let other = RecoveryFileIdentity {
            device: 7,
            inode: 22,
            uid: 501,
        };
        assert_eq!(
            chain
                .publication_for(CONTROL, &digest, &at(4), other, phase)
                .err()
                .map(|e| e.fault()),
            Some(RecoveryControlFault::ClosureUnproven)
        );
    }
}
