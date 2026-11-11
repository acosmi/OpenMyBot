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
mod ordinary;
mod runtime;

pub use activation::{ActivationBinding, ActivationPhase, OrdinaryStartupBounds};
pub(crate) use activation::{Hex32, ServerDatabaseSite};
#[cfg(feature = "desktop-local")]
pub use entry::ReadOnlyRestoreOwner;
pub use entry::{
    OwnedRecoveryRequestFile, OwnedRestoreCandidatePlan, RecoveryRequestExpected,
    RecoveryRequestPurpose, RestoreCandidateIsolationInput, RestoreControlSession,
    RestoreOriginalObservation, RestoreTargetSlotOutcome, VerifiedRecoveryHost,
    VerifiedRecoveryHostIntent, VerifiedServiceRecoveryHost,
    load_service_recovery_host_from_config,
};
pub(crate) use entry::{RestoreStageIntent, RestoreStages};
pub(crate) use journal::{
    CommitAck as RestoreCommitAck, Disposition as RestoreDisposition,
    RollbackAck as RestoreRollbackAck, Stage as RestoreStage,
};
pub use journal::{NativeExit, PipeJoin, ProcessStart};
#[cfg(feature = "desktop-local")]
pub use ordinary::LocalFreshProof;
pub(crate) use ordinary::OrdinaryStage;
pub use ordinary::{
    OrdinaryActivationProof, OrdinaryDatabaseInitializationProof, OrdinaryInitializationSession,
    VerifiedOrdinaryLegacyProof, VerifiedOrdinaryStartupIntent,
};
#[cfg(feature = "server-runtime")]
pub use runtime::AuthorizationPurpose;
#[cfg(all(feature = "desktop-local", feature = "server-runtime"))]
pub use runtime::LocalSubjectReconfirmation;
pub(crate) use runtime::RecoveryWorkerLease;
pub use runtime::{
    LocalPostgresQuiescence, PassiveObjectKind, RecoveryReadGate, RecoveryRuntimeOwner,
    RuntimeCloseFact, RuntimeCloseReceipt, RuntimeCloseResources, RuntimeOwner, RuntimePgAck,
    RuntimeTaskOutcome,
};

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
    DatabaseUnknown,
    ClosureUnproven,
    IoFailure,
    KeyUnverified,
}

/// Error retaining the same original control owner, never a success receipt.
pub struct RecoveryControlError {
    fault: RecoveryControlFault,
    retained: Option<entry::ControlOwner>,
    _original_json_error: Option<serde_json::Error>,
    unconsumed: Option<Box<VerifiedOrdinaryStartupIntent>>,
    retained_host: Option<Box<VerifiedRecoveryHost>>,
    retained_request: Option<Box<entry::RequestOpenOwner>>,
    _retained_restore_input: Option<Box<OwnedRecoveryRequestFile>>,
    retained_restore_intent: Option<Box<VerifiedRecoveryHostIntent>>,
    retained_ordinary: Option<Box<OrdinaryInitializationSession>>,
}

impl RecoveryControlError {
    pub(crate) fn new(fault: RecoveryControlFault) -> Self {
        Self {
            fault,
            retained: None,
            _original_json_error: None,
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            _retained_restore_input: None,
            retained_restore_intent: None,
            retained_ordinary: None,
        }
    }

    fn with_owner(fault: RecoveryControlFault, owner: &entry::ControlOwner) -> Self {
        Self {
            fault,
            retained: Some(Arc::clone(owner)),
            _original_json_error: None,
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            _retained_restore_input: None,
            retained_restore_intent: None,
            retained_ordinary: None,
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
            _original_json_error: Some(error),
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            _retained_restore_input: None,
            retained_restore_intent: None,
            retained_ordinary: None,
        }
    }

    /// Stable error kind. It contains no path, secret or untrusted error text.
    #[must_use]
    pub const fn fault(&self) -> RecoveryControlFault {
        self.fault
    }

    /// The entry intent handed back by a shared-lock branch whose next step is
    /// the exclusive ordinary writer; it can be taken once.
    #[must_use]
    pub fn into_unconsumed_intent(self) -> Option<VerifiedOrdinaryStartupIntent> {
        self.unconsumed.map(|intent| *intent)
    }
}

impl fmt::Debug for RecoveryControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryControlError")
            .field("fault", &self.fault)
            .field(
                "retains_original_owner",
                &(self.retained.is_some()
                    || self.retained_host.is_some()
                    || self.retained_request.is_some()
                    || self.retained_ordinary.is_some()),
            )
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Explicit operation resources. Values are observations/reservations, never
/// an alternative source of limits or restore authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum RestoreCapacityResource {
    InputWireBytes,
    ManifestBytes,
    MaterialFiles,
    MaterialDirectories,
    SingleMaterialBytes,
    MaterialPlainBytes,
    PathBytes,
    PathDepth,
    CandidateDataBytes,
    CandidateWalBytes,
    CandidateTempBytes,
    SpoolBytes,
    RetainedPriorBytes,
    JournalBytes,
    JournalRecords,
    MetadataBytes,
    OpenFiles,
    NativeTasks,
    PgConnections,
    PgTransactions,
    PgRows,
    ReconfirmRequirements,
    SecretMemoryBytes,
    SecretStructureBytes,
    TotalAllocationBytes,
    KeyMediumAllocationBytes,
}

/// Read-only counters from the original operation ledger, not a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreCapacityObservation {
    pub limit: u64,
    pub admitted: u64,
    pub actual: u64,
}

pub struct RestoreCapacityReservation {
    operation: activation::Hex32,
    resource: RestoreCapacityResource,
    admitted: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreStorageKind {
    Working,
    KeyMedium,
}

/// One admitted write against an already held original inode. This is not a
/// filesystem quota or a fresh operation capability.
pub struct RestoreStorageReservation {
    operation: activation::Hex32,
    identity: RecoveryFileIdentity,
    allocated_before: u64,
    bytes: u64,
    kind: RestoreStorageKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreNewChildKind {
    Directory,
    File,
}

pub struct RestoreNewChildReservation {
    operation: activation::Hex32,
    parent: RecoveryFileIdentity,
    component: std::ffi::OsString,
    bytes: u64,
    kind: RestoreNewChildKind,
}

/// One live operation's ledger. Unknown effects keep their admitted charge;
/// only an actual observation may settle it. Inode accounting never replaces
/// the separate per-handle OpenFiles count.
struct RestoreCapacityLedger {
    limits: RestoreOperationCapacity,
    admitted: [u64; 26],
    actual: [u64; 26],
    inodes: Vec<RestoreInodeUse>,
    devices: Vec<RestoreDeviceUse>,
    raw_metadata: Option<std::io::Result<std::fs::Metadata>>,
    raw_space: Option<rustix::io::Result<rustix::fs::StatVfs>>,
    raw_named: Option<rustix::io::Result<rustix::fs::Stat>>,
    fault: Option<RecoveryControlFault>,
}

struct RestoreInodeUse {
    device: u64,
    inode: u64,
    allocated: u64,
    key_medium: bool,
    planned_ceiling: Option<u64>,
}

struct RestoreDeviceUse {
    device: u64,
    available: u64,
    has_key_medium: bool,
    has_working: bool,
    pending_new: u64,
}

impl RestoreCapacityLedger {
    fn new(limits: RestoreOperationCapacity) -> Self {
        Self {
            limits,
            admitted: [0; 26],
            actual: [0; 26],
            inodes: Vec::new(),
            devices: Vec::new(),
            raw_metadata: None,
            raw_space: None,
            raw_named: None,
            fault: None,
        }
    }

    fn ceiling(&self, resource: RestoreCapacityResource) -> u64 {
        use RestoreCapacityResource as R;
        let c = &self.limits;
        match resource {
            R::InputWireBytes => c.max_input_wire_bytes,
            R::ManifestBytes => c.max_manifest_bytes,
            R::MaterialFiles => c.max_material_files,
            R::MaterialDirectories => c.max_material_directories,
            R::SingleMaterialBytes => c.max_single_material_bytes,
            R::MaterialPlainBytes => c.max_material_plain_bytes,
            R::PathBytes => c.max_path_bytes,
            R::PathDepth => c.max_path_depth,
            R::CandidateDataBytes => c.max_candidate_data_bytes,
            R::CandidateWalBytes => c.max_candidate_wal_bytes,
            R::CandidateTempBytes => c.max_candidate_temp_bytes,
            R::SpoolBytes => c.max_spool_bytes,
            R::RetainedPriorBytes => c.max_retained_prior_bytes,
            R::JournalBytes => c.max_journal_bytes,
            R::JournalRecords => c.max_journal_records,
            R::MetadataBytes => c.max_metadata_bytes,
            R::OpenFiles => c.max_open_files,
            R::NativeTasks => c.max_native_tasks,
            R::PgConnections => c.max_pg_connections,
            R::PgTransactions => c.max_pg_transactions,
            R::PgRows => c.max_pg_rows,
            R::ReconfirmRequirements => c.max_reconfirm_requirements,
            R::SecretMemoryBytes => c.max_secret_memory_bytes,
            R::SecretStructureBytes => c.max_secret_structure_bytes,
            R::TotalAllocationBytes => c.max_total_allocation_bytes,
            R::KeyMediumAllocationBytes => c.max_key_medium_allocation_bytes,
        }
    }

    fn admit(
        &mut self,
        resource: RestoreCapacityResource,
        additional: u64,
    ) -> Result<(), RecoveryControlError> {
        if let Some(fault) = self.fault {
            return Err(RecoveryControlError::new(fault));
        }
        let index = resource as usize;
        let amount = if matches!(
            resource,
            RestoreCapacityResource::SingleMaterialBytes
                | RestoreCapacityResource::PathBytes
                | RestoreCapacityResource::PathDepth
        ) {
            Some(self.admitted[index].max(additional))
        } else {
            self.admitted[index].checked_add(additional)
        };
        match amount {
            Some(amount) if amount <= self.ceiling(resource) => {
                self.admitted[index] = amount;
                Ok(())
            }
            _ => {
                self.fault = Some(RecoveryControlFault::CapacityExceeded);
                Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ))
            }
        }
    }

    fn settle(
        &mut self,
        resource: RestoreCapacityResource,
        reserved: u64,
        observed: u64,
    ) -> Result<(), RecoveryControlError> {
        self.settle_prepaid_observation(resource, reserved, observed)?;
        match self.fault {
            Some(fault) => Err(RecoveryControlError::new(fault)),
            None => Ok(()),
        }
    }

    fn settle_prepaid_observation(
        &mut self,
        resource: RestoreCapacityResource,
        reserved: u64,
        observed: u64,
    ) -> Result<(), RecoveryControlError> {
        let index = resource as usize;
        let peak = matches!(
            resource,
            RestoreCapacityResource::SingleMaterialBytes
                | RestoreCapacityResource::PathBytes
                | RestoreCapacityResource::PathDepth
        );
        let actual = if peak {
            Some(self.actual[index].max(observed))
        } else {
            self.actual[index].checked_add(observed)
        };
        let admitted = if peak {
            Some(self.admitted[index].max(observed))
        } else {
            self.admitted[index]
                .checked_sub(reserved)
                .and_then(|n| n.checked_add(observed))
        };
        match (actual, admitted) {
            (Some(actual), Some(admitted))
                if observed <= reserved && admitted <= self.ceiling(resource) =>
            {
                self.actual[index] = actual;
                self.admitted[index] = admitted;
            }
            _ => {
                self.fault
                    .get_or_insert(RecoveryControlFault::CapacityExceeded);
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
        }
        Ok(())
    }

    fn observe_file(
        &mut self,
        file: &std::fs::File,
        key_medium: bool,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        use std::os::unix::fs::MetadataExt;
        before(deadline)?;
        self.raw_metadata = Some(file.metadata());
        before(deadline)?;
        let metadata = self
            .raw_metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        let device = metadata.dev();
        let inode = metadata.ino();
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if let Some(held) = self
            .inodes
            .iter_mut()
            .find(|held| held.device == device && held.inode == inode)
        {
            held.allocated = allocated;
            held.key_medium |= key_medium;
        } else {
            if self.inodes.len() == self.inodes.capacity() {
                self.admit(
                    RestoreCapacityResource::MetadataBytes,
                    2 * std::mem::size_of::<RestoreInodeUse>() as u64,
                )?;
                let old = self.inodes.capacity();
                self.inodes.try_reserve_exact(1).map_err(|_| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?;
                if self.inodes.capacity().saturating_sub(old) > 2 {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::CapacityExceeded,
                    ));
                }
            }
            self.inodes.push(RestoreInodeUse {
                device,
                inode,
                allocated,
                key_medium,
                planned_ceiling: None,
            });
        }
        self.raw_space = Some(rustix::fs::fstatvfs(file));
        before(deadline)?;
        let space = self
            .raw_space
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        let available = space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if let Some(held) = self.devices.iter_mut().find(|held| held.device == device) {
            held.available = available;
            held.has_key_medium |= key_medium;
            held.has_working |= !key_medium;
        } else {
            self.admit(
                RestoreCapacityResource::MetadataBytes,
                2 * std::mem::size_of::<RestoreDeviceUse>() as u64,
            )?;
            let old = self.devices.capacity();
            self.devices
                .try_reserve_exact(1)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if self.devices.capacity().saturating_sub(old) > 2 {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
            self.devices.push(RestoreDeviceUse {
                device,
                available,
                has_key_medium: key_medium,
                has_working: !key_medium,
                pending_new: 0,
            });
        }
        self.check_storage()
    }

    fn admit_disk_growth(
        &mut self,
        identity: RecoveryFileIdentity,
        bytes: u64,
    ) -> Result<(), RecoveryControlError> {
        let held = self
            .inodes
            .iter_mut()
            .find(|held| held.device == identity.device && held.inode == identity.inode)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::InputInvalid))?;
        if held.planned_ceiling.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        held.planned_ceiling =
            Some(held.allocated.checked_add(bytes).ok_or_else(|| {
                RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
            })?);
        self.check_storage()
    }

    fn settle_disk_growth(
        &mut self,
        original: RestoreStorageReservation,
        file: &std::fs::File,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        use std::os::unix::fs::MetadataExt;
        before(deadline)?;
        self.raw_metadata = Some(file.metadata());
        before(deadline)?;
        let metadata = self
            .raw_metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if metadata.dev() != original.identity.device
            || metadata.ino() != original.identity.inode
            || metadata.uid() != original.identity.uid
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if allocated.saturating_sub(original.allocated_before) > original.bytes {
            self.fault
                .get_or_insert(RecoveryControlFault::CapacityExceeded);
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        self.raw_space = Some(rustix::fs::fstatvfs(file));
        before(deadline)?;
        let space = self
            .raw_space
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        let available = space
            .f_bavail
            .checked_mul(space.f_frsize)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let device = self
            .devices
            .iter_mut()
            .find(|held| held.device == original.identity.device)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        device.available = available;
        let inode = self
            .inodes
            .iter_mut()
            .find(|held| {
                held.device == original.identity.device && held.inode == original.identity.inode
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        if inode.planned_ceiling != original.allocated_before.checked_add(original.bytes)
            || inode.key_medium != (original.kind == RestoreStorageKind::KeyMedium)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        inode.allocated = allocated;
        inode.planned_ceiling = None;
        self.check_storage()
    }

    fn check_storage(&mut self) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let overflow = || RecoveryControlError::new(RecoveryControlFault::CapacityExceeded);
            let mut total = 0u64;
            let mut key = 0u64;
            for inode in &self.inodes {
                if inode
                    .planned_ceiling
                    .is_some_and(|ceiling| inode.allocated > ceiling)
                {
                    return Err(overflow());
                }
                total = total.checked_add(inode.allocated).ok_or_else(overflow)?;
                if inode.key_medium {
                    key = key.checked_add(inode.allocated).ok_or_else(overflow)?;
                }
            }
            self.actual[RestoreCapacityResource::TotalAllocationBytes as usize] = total;
            self.actual[RestoreCapacityResource::KeyMediumAllocationBytes as usize] = key;
            for device in &self.devices {
                let mut planned = device.pending_new;
                let mut planned_key = 0u64;
                for inode in self
                    .inodes
                    .iter()
                    .filter(|inode| inode.device == device.device)
                {
                    let remaining = inode
                        .planned_ceiling
                        .map_or(0, |ceiling| ceiling.saturating_sub(inode.allocated));
                    planned = planned.checked_add(remaining).ok_or_else(overflow)?;
                    if inode.key_medium {
                        planned_key = planned_key.checked_add(remaining).ok_or_else(overflow)?;
                    }
                }
                total = total.checked_add(planned).ok_or_else(overflow)?;
                key = key.checked_add(planned_key).ok_or_else(overflow)?;
                let reserve = if device.has_working {
                    self.limits.reserve_bytes
                } else {
                    0
                }
                .max(if device.has_key_medium {
                    self.limits.key_medium_reserve_bytes
                } else {
                    0
                });
                let floor = if device.has_working {
                    self.limits.free_floor_bytes
                } else {
                    0
                }
                .max(if device.has_key_medium {
                    self.limits.key_medium_free_floor_bytes
                } else {
                    0
                });
                let needed = planned
                    .checked_add(reserve)
                    .and_then(|n| n.checked_add(floor))
                    .ok_or_else(overflow)?;
                if needed > device.available {
                    return Err(overflow());
                }
            }
            if total > self.limits.max_total_allocation_bytes
                || key > self.limits.max_key_medium_allocation_bytes
            {
                return Err(overflow());
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.fault.get_or_insert(error.fault());
        }
        result
    }
}

/// Configuration consumes the real original host source, not a raw path.
pub struct RecoveryControlConfig {
    root: std::path::PathBuf,
    app_component: Option<std::ffi::OsString>,
    uid: u32,
    limits: TrustedHostRecoveryLimits,
    service_source: Option<VerifiedServiceRecoveryHost>,
    preheld_restore_usage: Option<(u64, u64)>,
    original_admission_deadline: Option<Instant>,
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
            preheld_restore_usage: None,
            original_admission_deadline: None,
        })
    }

    /// Only the registered verified original service-host producer supplies
    /// this non-Serde value; a configuration DTO cannot construct it.
    pub fn server(
        mut actual: VerifiedServiceRecoveryHost,
        limits: TrustedHostRecoveryLimits,
    ) -> Result<Self, RecoveryControlError> {
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
            preheld_restore_usage: None,
            original_admission_deadline: None,
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
    /// Admit the already held Local request/release resources in the same
    /// control budget before bootstrap opens any additional descriptor.
    #[cfg(feature = "desktop-local")]
    pub fn open_local_restore_before(
        actual: crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        request: OwnedRecoveryRequestFile,
        host: VerifiedRecoveryHost,
        deadline: Instant,
    ) -> Result<(Self, VerifiedRecoveryHostIntent), RecoveryControlError> {
        let mut original_request = Some(request);
        let mut original_host = Some(host);
        let result = (|| {
            let host = original_host.as_ref().expect("original host retained");
            let request = original_request
                .as_ref()
                .expect("original request retained");
            let (host_bytes, host_files) = host.retained_usage()?;
            let (request_bytes, request_files) = request.retained_usage()?;
            let usage = (
                host_bytes.checked_add(request_bytes),
                host_files.checked_add(request_files),
            );
            let (Some(bytes), Some(files)) = usage else {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            };
            let mut config = RecoveryControlConfig::local(actual, host.trusted_limits().clone())?;
            config.preheld_restore_usage = Some((bytes, files));
            config.original_admission_deadline = Some(deadline);
            before(deadline)?;
            let control = Self::open(config)?;
            let intent = control.verify_host_intent_before(
                original_request
                    .take()
                    .expect("original request moved once"),
                original_host.take().expect("original host moved once"),
                deadline,
            )?;
            Ok((control, intent))
        })();
        result.map_err(|mut error: RecoveryControlError| {
            error.retained_host = original_host.take().map(Box::new);
            error._retained_restore_input = original_request.take().map(Box::new);
            error
        })
    }

    /// Authenticate one original request and open only the existing same-operation reader.
    #[cfg(feature = "desktop-local")]
    pub fn reopen_local_restore_before(
        actual: crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        request: OwnedRecoveryRequestFile,
        host: VerifiedRecoveryHost,
        deadline: Instant,
    ) -> Result<ReadOnlyRestoreOwner, RecoveryControlError> {
        let deadline = deadline.min(host.admission_deadline());
        let mut request = Some(request);
        let mut host = Some(host);
        let result = (|| {
            let original = host.as_ref().expect("original host retained");
            let (hb, hf) = original.retained_usage()?;
            let (rb, rf) = request
                .as_ref()
                .expect("original request retained")
                .retained_usage()?;
            let mut config =
                RecoveryControlConfig::local(actual, original.trusted_limits().clone())?;
            config.preheld_restore_usage = Some((
                hb.checked_add(rb).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?,
                hf.checked_add(rf).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?,
            ));
            config.original_admission_deadline = Some(deadline);
            let owner = entry::open_existing_control(config)?;
            let intent = entry::verify_intent(
                &owner,
                request.take().expect("original request moved once"),
                host.take().expect("original host moved once"),
                deadline,
            )?;
            ReadOnlyRestoreOwner::from_original(owner, intent, deadline)
        })();
        result.map_err(|mut error: RecoveryControlError| {
            if host.is_some() {
                error.retained_host = host.take().map(Box::new);
            }
            if request.is_some() {
                error._retained_restore_input = request.take().map(Box::new);
            }
            error
        })
    }

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

    /// Claim one original restore request under the exclusive control locks.
    pub fn claim_restore(
        &mut self,
        entry: VerifiedRecoveryHostIntent,
        profile: RestoreOperationProfile,
    ) -> Result<RestoreControlSession, RecoveryControlError> {
        entry::claim_restore(&self.shared, entry, profile)
    }

    /// Reuse the once-verified request retained by a refused claim to observe
    /// its existing operation. This cannot mint an operation or effect clock.
    #[cfg(feature = "desktop-local")]
    pub fn observe_unclaimed_restore(
        &mut self,
    ) -> Result<ReadOnlyRestoreOwner, RecoveryControlError> {
        entry::observe_unclaimed_restore(&self.shared)
    }

    /// Consume one verified Current request under its own explicit clock and
    /// count. The returned runtime holds only the existing shared enrollment;
    /// a fresh OS proof is still required before any confirmation transaction.
    #[cfg(all(feature = "desktop-local", feature = "server-runtime"))]
    pub fn enter_current_reconfirmation(
        &self,
        request: &mut VerifiedRecoveryHostIntent,
        creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
        owners: &[RuntimeOwner],
        cancel: crate::restore_reconfirmation::CancellationToken,
    ) -> Result<
        (
            RecoveryRuntimeOwner,
            crate::restore_reconfirmation::OriginalReconfirmationRequest,
            Instant,
        ),
        RecoveryControlError,
    > {
        entry::enter_current_reconfirmation(&self.shared, request, creator, owners, cancel)
            .map_err(|error| error.retain(&self.shared))
    }

    /// Ordinary Server startup (S8). One clock read seals the entry intent;
    /// an existing latest head is checked under SH, otherwise the handed-back
    /// intent takes the exclusive writer for Fresh or legacy adoption. The
    /// returned Pool is the bootstrap Pool of this site.
    #[cfg(feature = "server-runtime")]
    pub async fn open_server_before(
        &mut self,
        database: &crate::db::pool::DatabaseConfig,
        configured: &crate::auth::config::KeyEncryptionKey,
        deployment: &openbot_contracts::ids::DeploymentId,
        tenant: &openbot_contracts::ids::TenantId,
        owners: &[RuntimeOwner],
    ) -> Result<(crate::db::pool::DatabasePool, RecoveryRuntimeOwner), RecoveryControlError> {
        let intent = entry::server_intent(&self.shared, deployment, tenant, owners)?;
        let admission = intent.admission_deadline();
        let dataset = intent.server_dataset()?;
        let effect = intent.effect_deadline();
        let intent = match ordinary::shared_head(&self.shared, intent, admission) {
            Ok((published, intent)) => {
                let pool = entry::verify_existing_server_before(
                    &self.shared,
                    &published,
                    database,
                    configured,
                    &dataset,
                    effect,
                )
                .await?;
                let owner = ordinary::enroll(&self.shared, published, &intent, None)?;
                return Ok((pool, owner));
            }
            Err(error) if error.fault() == RecoveryControlFault::InitializationRequired => {
                error.into_unconsumed_intent().ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::InitializationRequired)
                })?
            }
            Err(error) => return Err(error),
        };
        let mut session = self.begin_ordinary_initialization_before(intent, admission)?;
        let pool = entry::connect_server_before(&self.shared, database, effect).await?;
        match session.initialization_source() {
            Some(ordinary::OrdinaryInitializationSource::ServerDatabaseFresh) => {
                let initialized = crate::db::initialization::initialize_owned_before(
                    &pool,
                    session.original_initialization_request(configured),
                )
                .await
                .map_err(|error| match error {
                    crate::db::initialization::DatabaseInitializationError::Recovery(error) => {
                        error
                    }
                    _ => RecoveryControlError::new(RecoveryControlFault::IoFailure),
                })?;
                session.publish_active(OrdinaryActivationProof::ServerFresh(
                    initialized.into_proof()?,
                ))?;
            }
            Some(ordinary::OrdinaryInitializationSource::LegacyAdoption {
                site: ordinary::OrdinarySite::ServerDatabase,
            }) => {
                entry::adopt_server_legacy_before(
                    &self.shared,
                    &mut session,
                    &pool,
                    database,
                    configured,
                )
                .await?;
            }
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
        }
        let owner = session.into_runtime_before()?;
        Ok((pool, owner))
    }

    /// Shared-lock ordinary startup: a published head at the latest native
    /// version enrolls this runtime; otherwise `InitializationRequired`, with
    /// the intent handed back where the exclusive writer is the next step.
    ///
    /// Before registration, under the held SH, `observe` receives the head's
    /// restored generation (`None` for the installation's own data
    /// directory). The host takes that generation's PostgreSQL start lock and
    /// observes its data directory before any spawn; its observation lets
    /// registration settle crashed Local enrollments of the same generation.
    /// A refusal from `observe` (the host keeps its own failure) releases the
    /// SH, registers nothing and is `OwnerBusy`.
    #[cfg(feature = "desktop-local")]
    pub fn open_local_before(
        &self,
        creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
        release: [u8; 32],
        services: [&str; 2],
        bounds: OrdinaryStartupBounds,
        owners: &[RuntimeOwner],
        observe: impl FnOnce(
            Option<&crate::auth::single_user::desktop_local::RestoredLocalSite>,
        ) -> Result<Option<LocalPostgresQuiescence>, ()>,
    ) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        let result = (|| {
            let intent =
                entry::local_intent(&self.shared, creator, release, services, bounds, owners)?;
            let admission = intent.admission_deadline();
            let (published, intent) =
                ordinary::shared_local_head(&self.shared, intent, admission, creator)?;
            let restored = match published.restore_cohort() {
                Some(_) => {
                    let mut files = entry::lock(&self.shared)?;
                    match files.restored_local_site_before(
                        &published,
                        creator.app_data_root(),
                        admission,
                    ) {
                        Ok(site) => Some(site),
                        Err(error) => {
                            files.latch(error.fault());
                            return Err(error);
                        }
                    }
                }
                None => None,
            };
            let Ok(local) = observe(restored.as_ref()) else {
                entry::lock(&self.shared)?.release_registration_attempt();
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            };
            ordinary::enroll(&self.shared, published, &intent, local.as_ref())
        })();
        result.map_err(|error| error.retain(&self.shared))
    }

    /// The ordinary shared-lock entry never creates a missing Local installation.
    pub fn enter_runtime_before(
        &self,
        intent: VerifiedOrdinaryStartupIntent,
        deadline: Instant,
    ) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        ordinary::enter_runtime(&self.shared, intent, deadline)
    }

    /// Exclusive ordinary writer for a handed-back intent; busy, or a head
    /// another writer changed, is `OwnerBusy` before any file is written.
    pub fn begin_ordinary_initialization_before(
        &mut self,
        intent: VerifiedOrdinaryStartupIntent,
        deadline: Instant,
    ) -> Result<OrdinaryInitializationSession, RecoveryControlError> {
        ordinary::begin(&self.shared, intent, deadline)
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
    for (byte, pair) in bytes
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0.iter())
    {
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
pub(crate) mod tests {
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

    fn restore_capacity() -> super::RestoreOperationCapacity {
        super::RestoreOperationCapacity {
            max_input_wire_bytes: 1 << 20,
            max_manifest_bytes: 1 << 16,
            max_material_files: 64,
            max_material_directories: 16,
            max_single_material_bytes: 1 << 20,
            max_material_plain_bytes: 1 << 20,
            max_path_bytes: 1024,
            max_path_depth: 16,
            max_candidate_data_bytes: 1 << 20,
            max_candidate_wal_bytes: 1 << 20,
            max_candidate_temp_bytes: 1 << 20,
            max_spool_bytes: 1 << 20,
            max_retained_prior_bytes: 1 << 20,
            max_journal_bytes: 1 << 20,
            max_journal_records: 64,
            max_metadata_bytes: 1 << 20,
            max_open_files: 64,
            max_native_tasks: 8,
            max_pg_connections: 4,
            max_pg_transactions: 4,
            max_pg_rows: 64,
            max_reconfirm_requirements: 64,
            max_secret_memory_bytes: 1 << 20,
            max_secret_structure_bytes: 1 << 16,
            max_total_allocation_bytes: 200,
            reserve_bytes: 1,
            free_floor_bytes: 1,
            max_key_medium_allocation_bytes: 200,
            key_medium_reserve_bytes: 1,
            key_medium_free_floor_bytes: 1,
        }
    }

    #[test]
    fn restore_ledger_unknown_reservation_is_not_refunded() {
        use super::RestoreCapacityResource as R;
        let mut ledger = super::RestoreCapacityLedger::new(restore_capacity());
        ledger
            .admit(R::OpenFiles, 63)
            .expect("reserve original handles");
        assert_eq!(
            ledger.admit(R::OpenFiles, 2).err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
        assert_eq!(ledger.admitted[R::OpenFiles as usize], 63);
        assert_eq!(
            ledger.admit(R::OpenFiles, 0).err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
    }

    #[test]
    fn restore_ledger_settles_only_the_original_admitted_delta() {
        use super::RestoreCapacityResource as R;
        let mut ledger = super::RestoreCapacityLedger::new(restore_capacity());
        ledger
            .admit(R::OpenFiles, 10)
            .expect("other original handles");
        ledger
            .admit(R::OpenFiles, 4)
            .expect("new handle reservation");
        ledger
            .settle(R::OpenFiles, 4, 3)
            .expect("three actually opened");
        assert_eq!(ledger.admitted[R::OpenFiles as usize], 13);
        assert_eq!(ledger.actual[R::OpenFiles as usize], 3);
        ledger
            .admit(R::OpenFiles, 1)
            .expect("another original effect");
        assert_eq!(
            ledger.settle(R::OpenFiles, 1, 2).err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
        assert_eq!(ledger.admitted[R::OpenFiles as usize], 14);
    }

    #[test]
    fn restore_ledger_inflight_growth_is_counted_once() {
        let mut ledger = super::RestoreCapacityLedger::new(restore_capacity());
        ledger.inodes.push(super::RestoreInodeUse {
            device: 7,
            inode: 11,
            allocated: 80,
            key_medium: false,
            planned_ceiling: Some(180),
        });
        ledger.devices.push(super::RestoreDeviceUse {
            device: 7,
            available: 1024,
            has_key_medium: false,
            has_working: true,
            pending_new: 0,
        });
        ledger.check_storage().expect("80 actual plus 100 planned");
        ledger.inodes[0].allocated = 160;
        ledger
            .check_storage()
            .expect("160 actual plus 20 still planned");
        ledger.inodes[0].allocated = 181;
        assert_eq!(
            ledger.check_storage().err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
    }

    #[test]
    fn restore_ledger_reserve_and_floor_apply_together() {
        let mut ledger = super::RestoreCapacityLedger::new(restore_capacity());
        ledger.devices.push(super::RestoreDeviceUse {
            device: 7,
            available: 1,
            has_key_medium: true,
            has_working: true,
            pending_new: 0,
        });
        assert_eq!(
            ledger.check_storage().err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
    }

    #[test]
    fn restore_ledger_path_limits_are_per_path() {
        use super::RestoreCapacityResource as R;
        let mut ledger = super::RestoreCapacityLedger::new(restore_capacity());
        ledger.admit(R::PathDepth, 12).expect("first depth");
        ledger
            .settle(R::PathDepth, 12, 12)
            .expect("observed first path");
        ledger
            .admit(R::PathDepth, 12)
            .expect("second path has the same depth");
        ledger
            .settle(R::PathDepth, 12, 12)
            .expect("observed second path");
        assert_eq!(ledger.actual[R::PathDepth as usize], 12);
        assert_eq!(
            ledger.admit(R::PathDepth, 17).err().map(|e| e.fault()),
            Some(RecoveryControlFault::CapacityExceeded)
        );
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
            "pgSystemId": 7_000_000_001u64, "databaseOid": 16384, "pgMajor": 17, "nativeVersion": 55,
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

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    pub(crate) struct RestoreEntryFixture {
        pub(crate) directory: std::path::PathBuf,
        limits: TrustedHostRecoveryLimits,
        pub(crate) profile: super::RestoreOperationProfile,
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    impl Drop for RestoreEntryFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    impl RestoreEntryFixture {
        pub(crate) fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            // A private task-owned root below the real checkout avoids the
            // intentionally world-writable system temporary ancestor.
            let directory = std::env::current_dir()
                .unwrap()
                .join(format!(".restore-046-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(directory.as_path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::create_dir(directory.as_path().join("release")).unwrap();
            for name in ["carrier-medium", "key-medium"] {
                let path = directory.join(name);
                std::fs::create_dir(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            for (name, bytes) in [
                ("program", vec![1]),
                ("carrier-medium/carrier", vec![2]),
                ("key-medium/key", vec![3; 104]),
            ] {
                std::fs::write(directory.as_path().join(name), bytes).unwrap();
                std::fs::set_permissions(
                    directory.as_path().join(name),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            let mut limits = limits();
            limits.admission_ns = 30_000_000_000;
            limits.max_open_files = 4096;
            limits.max_path_depth = 128;
            limits.max_relative_path_bytes = 8192;
            // A bound candidate pays its oracle trees once (about 60 MB), each
            // layout check (about 27 MB) and each clear transaction's
            // observation (about 22 MB); the heaviest restore test settles
            // about 160 MB in all.
            limits.max_metadata_bytes = 192 << 20;
            let mut capacity = restore_capacity();
            capacity.max_open_files = limits.max_open_files;
            capacity.max_metadata_bytes = limits.max_metadata_bytes;
            capacity.max_total_allocation_bytes = 1 << 32;
            capacity.max_key_medium_allocation_bytes = 1 << 30;
            let profile = super::RestoreOperationProfile {
                effect_ns: 30_000_000_000,
                convergence_ns: 30_000_000_000,
                capacity,
            };
            Self {
                directory,
                limits,
                profile,
            }
        }

        fn config(&self) -> super::RecoveryControlConfig {
            super::RecoveryControlConfig::local(
                    crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(self.directory.as_path().join("old-app")).unwrap(),
                    self.limits.clone(),
                ).unwrap()
        }

        pub(crate) fn open(&self) -> (super::RecoveryControl, super::VerifiedRecoveryHostIntent) {
            self.open_request(self.request())
        }

        pub(crate) fn request(&self) -> Value {
            let root = self.directory.as_path();
            let selected = |name: &str| json!({"parent": root, "component": name});
            json!({"formatVersion": 1, "requestId": OPERATION, "purpose": "restore_same_installation",
                    "expectedReviewedReleaseDigest": "11".repeat(32), "expectedDeploymentId": "dep", "expectedTenantId": "ten",
                    "expectedDatasetId": CONTROL, "expectedSourceInstallationId": "22".repeat(32), "expectedTargetInstallationId": "22".repeat(32),
                    "trustedInputSelection": {"carrier": {"parent": root.join("carrier-medium"), "component": "carrier"}, "keyMedium": {"parent": root.join("key-medium"), "component": "key"},
                        "expectedBundleId": "01234567-89ab-4def-8123-456789abcdef", "expectedSourceOperationId": "11234567-89ab-4def-8123-456789abcdef",
                        "expectedManifestSha256": ZERO64, "target": selected("new-generation")}, "profile": self.profile})
        }

        fn open_with_key_parent(
            &self,
            key_parent: &std::path::Path,
        ) -> (super::RecoveryControl, super::VerifiedRecoveryHostIntent) {
            let mut request = self.request();
            request["trustedInputSelection"]["keyMedium"]["parent"] = json!(key_parent);
            self.open_request(request)
        }

        pub(crate) fn open_request(
            &self,
            request: Value,
        ) -> (super::RecoveryControl, super::VerifiedRecoveryHostIntent) {
            self.try_open_request(request).unwrap()
        }

        pub(crate) fn try_open_request(
            &self,
            request: Value,
        ) -> Result<
            (super::RecoveryControl, super::VerifiedRecoveryHostIntent),
            super::RecoveryControlError,
        > {
            let (actual, request, host) = self.original_inputs(request);
            super::RecoveryControl::open_local_restore_before(
                actual,
                request,
                host,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
        }

        fn reopen(
            &self,
            deadline: std::time::Instant,
        ) -> Result<super::ReadOnlyRestoreOwner, super::RecoveryControlError> {
            let (actual, request, host) = self.original_inputs(self.request());
            super::RecoveryControl::reopen_local_restore_before(actual, request, host, deadline)
        }

        fn original_inputs(
            &self,
            request: Value,
        ) -> (
            crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
            super::OwnedRecoveryRequestFile,
            super::VerifiedRecoveryHost,
        ) {
            use std::os::unix::fs::PermissionsExt;
            let root = self.directory.as_path();
            std::fs::write(root.join("request"), serde_json::to_vec(&request).unwrap()).unwrap();
            std::fs::set_permissions(root.join("request"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let host = super::VerifiedRecoveryHost::from_local_release(
                    (std::fs::File::open(root).unwrap(), "program".into(), std::fs::File::open(root.join("program")).unwrap()),
                    (std::fs::File::open(root).unwrap(), "release".into(), std::fs::File::open(root.join("release")).unwrap()),
                    crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(root.join("old-app")).unwrap(),
                    [0x11; 32], self.limits.clone(),
                    serde_json::from_value(json!({"effectNs":30_000_000_000u64,"convergenceNs":30_000_000_000u64})).unwrap(),
                    ["test.vault", "test.postgres"],
                ).unwrap();
            let request = super::OwnedRecoveryRequestFile::from_held(
                std::fs::File::open(root).unwrap(),
                std::ffi::OsStr::new("request"),
                rustix::process::getuid().as_raw(),
            )
            .unwrap();
            (crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(root.join("old-app")).unwrap(), request, host)
        }

        fn control_root(&self) -> std::path::PathBuf {
            self.directory
                .as_path()
                .join("com.acosmi.wrokbot.restore-control")
        }
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn restore_control_bytes(
        root: &std::path::Path,
    ) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut bytes = std::collections::BTreeMap::new();
        if !root.exists() {
            return bytes;
        }
        bytes.insert(root.to_owned(), Vec::new());
        for child in std::fs::read_dir(root).unwrap() {
            let child = child.unwrap();
            if child.file_type().unwrap().is_dir() {
                bytes.extend(restore_control_bytes(&child.path()));
            } else {
                bytes.insert(child.path(), std::fs::read(child.path()).unwrap());
            }
        }
        bytes
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn closed_restore_claim(fixture: &RestoreEntryFixture) -> String {
        let (mut control, intent) = fixture.open();
        let session = control
            .claim_restore(intent, fixture.profile.clone())
            .unwrap();
        let record: Value = serde_json::from_slice(
            &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
        )
        .unwrap();
        let epoch = record["data"]["epoch"].as_str().unwrap().to_owned();
        drop(session);
        drop(control);
        epoch
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_reads_same_operation_epoch_without_writes() {
        let fixture = RestoreEntryFixture::new();
        let epoch = closed_restore_claim(&fixture);
        let before = restore_control_bytes(&fixture.control_root());
        let mut reader = fixture
            .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
            .unwrap();
        for _ in 0..2 {
            let observed = reader.observe_original().unwrap();
            assert_eq!(observed.operation_id(), OPERATION);
            assert_eq!(observed.epoch(), epoch);
            assert_eq!(observed.phase(), super::ActivationPhase::RestorePending);
        }
        drop(reader);
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_busy_preserves_every_control_byte() {
        let fixture = RestoreEntryFixture::new();
        let (mut control, intent) = fixture.open();
        let session = control
            .claim_restore(intent, fixture.profile.clone())
            .unwrap();
        let before = restore_control_bytes(&fixture.control_root());
        assert!(
            matches!(fixture.reopen(std::time::Instant::now() + std::time::Duration::from_secs(10)), Err(error) if error.fault() == super::RecoveryControlFault::OwnerBusy)
        );
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
        drop(session);
        drop(control);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_missing_layout_is_never_created() {
        let fixture = RestoreEntryFixture::new();
        assert!(
            fixture
                .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
                .is_err()
        );
        assert!(!fixture.control_root().exists());
        closed_restore_claim(&fixture);
        std::fs::remove_file(fixture.control_root().join("owner.lock")).unwrap();
        let before = restore_control_bytes(&fixture.control_root());
        assert!(
            fixture
                .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
                .is_err()
        );
        assert!(!fixture.control_root().join("owner.lock").exists());
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_torn_tail_is_not_truncated() {
        use std::io::Write;
        let fixture = RestoreEntryFixture::new();
        closed_restore_claim(&fixture);
        let journal = fixture
            .control_root()
            .join("operations")
            .join(OPERATION)
            .join("journal-v1");
        std::fs::OpenOptions::new()
            .append(true)
            .open(journal)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let before = restore_control_bytes(&fixture.control_root());
        assert!(
            fixture
                .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
                .is_err()
        );
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_original_read_deadline_cannot_renew() {
        let fixture = RestoreEntryFixture::new();
        closed_restore_claim(&fixture);
        let before = restore_control_bytes(&fixture.control_root());
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        let mut reader = fixture.reopen(deadline).unwrap();
        std::thread::sleep(
            deadline.saturating_duration_since(std::time::Instant::now())
                + std::time::Duration::from_millis(10),
        );
        assert!(reader.observe_original().is_err());
        assert!(reader.observe_original().is_err());
        drop(reader);
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_expired_host_cannot_get_a_new_read_period() {
        let mut fixture = RestoreEntryFixture::new();
        closed_restore_claim(&fixture);
        fixture.limits.admission_ns = 200_000_000;
        let (actual, request, host) = fixture.original_inputs(fixture.request());
        let original = host.admission_deadline();
        std::thread::sleep(
            original.saturating_duration_since(std::time::Instant::now())
                + std::time::Duration::from_millis(10),
        );
        let before = restore_control_bytes(&fixture.control_root());
        assert!(
            super::RecoveryControl::reopen_local_restore_before(
                actual,
                request,
                host,
                std::time::Instant::now() + std::time::Duration::from_secs(30)
            )
            .is_err()
        );
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_reopened_rejects_descriptor_prefix_digest_mismatch() {
        let fixture = RestoreEntryFixture::new();
        closed_restore_claim(&fixture);
        let path = fixture.control_root().join("activation-v1");
        let bytes = std::fs::read_to_string(&path).unwrap();
        let record: Value = serde_json::from_str(&bytes).unwrap();
        let digest = record["data"]["journalPrefix"]["digest"].as_str().unwrap();
        assert_eq!(bytes.matches(digest).count(), 1);
        let wrong = "f".repeat(64);
        assert_ne!(digest, wrong);
        std::fs::write(&path, bytes.replacen(digest, &wrong, 1)).unwrap();
        let before = restore_control_bytes(&fixture.control_root());
        assert!(
            fixture
                .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
                .is_err()
        );
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_04_busy_lock_order_creates_no_operation_pending_or_effect() {
        let fixture = RestoreEntryFixture::new();
        use std::os::unix::fs::MetadataExt;
        let carrier_parent = std::fs::metadata(fixture.directory.join("carrier-medium")).unwrap();
        let key_parent = std::fs::metadata(fixture.directory.join("key-medium")).unwrap();
        assert_eq!(
            carrier_parent.dev(),
            key_parent.dev(),
            "independent directories on the same device remain supported"
        );
        assert_ne!(carrier_parent.ino(), key_parent.ino());
        let reader = super::RecoveryControl::open(fixture.config()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        super::entry::lock(&reader.shared)
            .unwrap()
            .acquire_shared_before(deadline)
            .unwrap();
        let (mut control, entry) = fixture.open();
        let error = control
            .claim_restore(entry, fixture.profile.clone())
            .err()
            .expect("runtime SH blocks restore EX");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        assert_eq!(
            std::fs::read_dir(fixture.control_root().join("operations"))
                .unwrap()
                .count(),
            0
        );
        assert!(!fixture.control_root().join("activation-v1").exists());
        assert!(!fixture.directory.as_path().join("new-generation").exists());
        drop(error);
        drop(control);
        drop(reader);
        let (mut control, entry) = fixture.open();
        let _session = control
            .claim_restore(entry, fixture.profile.clone())
            .expect("closed empty runtime inventory admits original restore");
        let reader = super::RecoveryControl::open(fixture.config()).unwrap();
        assert_eq!(
            super::entry::lock(&reader.shared)
                .unwrap()
                .acquire_shared_before(deadline)
                .err()
                .map(|e| e.fault()),
            Some(RecoveryControlFault::OwnerBusy)
        );
        let bytes = std::fs::read(
            fixture
                .control_root()
                .join("operations")
                .join(OPERATION)
                .join("journal-v1"),
        )
        .unwrap();
        let observed = observe_chain(&bytes, &fixture.limits).unwrap();
        assert_eq!(observed.first_context().unwrap().1, OPERATION);
        assert_eq!(
            observed.restore_candidate_plan().unwrap().entry_component,
            "new-generation"
        );
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_03_control_root_is_trusted_sibling_outside_every_write_set() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let config = fixture.config();
        assert_eq!(config.root, fixture.control_root());
        assert_ne!(
            config.root.parent().unwrap(),
            fixture.directory.as_path().join("old-app")
        );
        let control = super::RecoveryControl::open(config).unwrap();
        assert!(fixture.control_root().is_dir());
        assert!(!fixture.directory.as_path().join("old-app").exists());
        drop(control);
        let link = fixture.directory.as_path().join("linked-parent");
        std::os::unix::fs::symlink(fixture.directory.as_path(), &link).unwrap();
        let config = super::RecoveryControlConfig::local(
                crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(link.join("app")).unwrap(), fixture.limits.clone(),
            ).unwrap();
        assert!(
            super::RecoveryControl::open(config).is_err(),
            "symlink ancestor cannot seal a control root"
        );
        let unsafe_parent = fixture.directory.as_path().join("group-writable");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o770)).unwrap();
        let config = super::RecoveryControlConfig::local(
                crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(unsafe_parent.join("app")).unwrap(), fixture.limits.clone(),
            ).unwrap();
        assert!(
            super::RecoveryControl::open(config).is_err(),
            "writable ancestor cannot seal a control root"
        );
        let mut overlapping = fixture.config();
        overlapping.root = fixture.directory.as_path().join("old-app").join("control");
        assert!(
            super::RecoveryControl::open(overlapping).is_err(),
            "control inside app-data is outside the admitted sibling location"
        );
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn restore_claim_existing_request_directory_never_mints_or_repairs() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let (mut control, entry) = fixture.open();
        let operation = fixture.control_root().join("operations").join(OPERATION);
        std::fs::create_dir(&operation).unwrap();
        std::fs::set_permissions(&operation, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = control
            .claim_restore(entry, fixture.profile.clone())
            .err()
            .expect("partial original operation denies reuse");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        assert_eq!(std::fs::read_dir(&operation).unwrap().count(), 0);
        assert!(!fixture.control_root().join("activation-v1").exists());
        assert_eq!(
            std::fs::read_dir(fixture.control_root().join("operations"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_12_capacity_plan_and_actual_overflow_keep_material() {
        use std::os::unix::fs::PermissionsExt;
        let mut insufficient = RestoreEntryFixture::new();
        insufficient.profile.capacity.max_metadata_bytes = 1;
        let (mut control, entry) = insufficient.open();
        assert_eq!(
            control
                .claim_restore(entry, insufficient.profile.clone())
                .err()
                .unwrap()
                .fault(),
            RecoveryControlFault::CapacityExceeded
        );
        assert_eq!(
            std::fs::read_dir(insufficient.control_root().join("operations"))
                .unwrap()
                .count(),
            0
        );
        assert!(!insufficient.control_root().join("activation-v1").exists());

        let fixture = RestoreEntryFixture::new();
        let (mut control, entry) = fixture.open();
        let mut session = control
            .claim_restore(entry, fixture.profile.clone())
            .unwrap();
        let plan = session.take_candidate_plan().unwrap();
        let journal = fixture
            .control_root()
            .join("operations")
            .join(OPERATION)
            .join("journal-v1");
        let original_journal = std::fs::read(&journal).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let reservation = session
            .admit_new_child_before(
                plan.parent(),
                std::ffi::OsStr::new("owned-overflow"),
                1,
                super::RestoreNewChildKind::File,
                deadline,
            )
            .unwrap();
        let path = fixture.directory.as_path().join("owned-overflow");
        let mut random = [0u8; 16384];
        getrandom::fill(&mut random).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::io::Write::write_all(&mut file, &random).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            session
                .settle_new_child_before(reservation, plan.parent(), &file, deadline)
                .err()
                .unwrap()
                .fault(),
            RecoveryControlFault::CapacityExceeded
        );
        assert_eq!(std::fs::read(&path).unwrap(), random);
        assert_eq!(std::fs::read(&journal).unwrap(), original_journal);
        let pending: Value = serde_json::from_slice(
            &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
        )
        .unwrap();
        assert_eq!(pending["phase"], "RestorePending");
    }

    #[test]
    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    fn restore_claim_frozen_input_transfers_original_fds_once() {
        let fixture = RestoreEntryFixture::new();
        let (mut control, entry) = fixture.open();
        let mut session = control
            .claim_restore(entry, fixture.profile.clone())
            .unwrap();
        let (_input, _intent) = session
            .frozen_input()
            .expect("same original held inputs move once");
        assert_eq!(
            session.frozen_input().err().unwrap().fault(),
            RecoveryControlFault::InputInvalid
        );
        let pending: Value = serde_json::from_slice(
            &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
        )
        .unwrap();
        assert_eq!(pending["phase"], "RestorePending");
    }

    #[test]
    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    fn restore_claim_frozen_input_rejects_replaced_key_medium() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let (mut control, entry) = fixture.open();
        let mut session = control
            .claim_restore(entry, fixture.profile.clone())
            .unwrap();
        let replacement = fixture.directory.as_path().join("replacement");
        std::fs::write(&replacement, [4u8; 104]).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(
            &replacement,
            fixture.directory.as_path().join("key-medium/key"),
        )
        .unwrap();
        assert_eq!(
            session.frozen_input().err().unwrap().fault(),
            RecoveryControlFault::InputInvalid
        );
        assert_eq!(
            std::fs::read(fixture.directory.as_path().join("key-medium/key")).unwrap(),
            [4u8; 104]
        );
        assert!(
            fixture
                .control_root()
                .join("operations")
                .join(OPERATION)
                .join("journal-v1")
                .exists()
        );
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_11_effect_convergence_and_owner_loss_are_read_only() {
        let mut fixture = RestoreEntryFixture::new();
        fixture.profile.effect_ns = 500_000_000;
        fixture.profile.convergence_ns = 200_000_000;
        let (mut control, entry) = fixture.open();
        let mut session = control
            .claim_restore(entry, fixture.profile.clone())
            .unwrap();
        let (_, t0, effect, close) = session.original_native_clock().unwrap();
        assert_eq!(effect - t0, fixture.profile.effect_ns);
        assert_eq!(close - effect, fixture.profile.convergence_ns);
        let before = restore_control_bytes(&fixture.control_root());
        let descriptor: Value = serde_json::from_slice(
            &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
        )
        .unwrap();
        let epoch = descriptor["data"]["epoch"].as_str().unwrap().to_owned();
        let now = super::clock::monotonic_ns().unwrap();
        std::thread::sleep(std::time::Duration::from_nanos(
            effect.saturating_sub(now) + 10_000_000,
        ));
        let effect_error = session
            .admit_capacity(super::RestoreCapacityResource::NativeTasks, 1)
            .err()
            .expect("original E denies a new effect");
        assert_eq!(effect_error.fault(), RecoveryControlFault::EffectExpired);
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
        drop(effect_error);
        let now = super::clock::monotonic_ns().unwrap();
        std::thread::sleep(std::time::Duration::from_nanos(
            close.saturating_sub(now) + 10_000_000,
        ));
        assert!(super::clock::monotonic_ns().unwrap() >= close);
        let close_error = session
            .admit_capacity(super::RestoreCapacityResource::NativeTasks, 1)
            .err()
            .expect("original C cannot admit a new effect");
        assert_eq!(
            close_error.fault(),
            RecoveryControlFault::ConvergenceExpired
        );
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
        drop(close_error);
        drop(session);
        drop(control);
        let mut reader = fixture
            .reopen(std::time::Instant::now() + std::time::Duration::from_secs(10))
            .unwrap();
        let observed = reader.observe_original().unwrap();
        assert_eq!(observed.operation_id(), OPERATION);
        assert_eq!(observed.epoch(), epoch);
        assert_eq!(observed.phase(), super::ActivationPhase::RestorePending);
        drop(reader);
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
        assert!(!fixture.directory.join("new-generation").exists());
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn restore_claim_effect_and_convergence_use_original_clock() {
        for convergence in [false, true] {
            let mut fixture = RestoreEntryFixture::new();
            fixture.profile.effect_ns = 500_000_000;
            fixture.profile.convergence_ns = 200_000_000;
            let (mut control, entry) = fixture.open();
            let mut session = control
                .claim_restore(entry, fixture.profile.clone())
                .unwrap();
            let (_, t0, effect, close) = session.original_native_clock().unwrap();
            assert_eq!(effect - t0, fixture.profile.effect_ns);
            assert_eq!(close - effect, fixture.profile.convergence_ns);
            let until = if convergence { close } else { effect };
            let now = super::clock::monotonic_ns().unwrap();
            std::thread::sleep(std::time::Duration::from_nanos(
                until.saturating_sub(now) + 10_000_000,
            ));
            let error = session
                .admit_capacity(super::RestoreCapacityResource::NativeTasks, 1)
                .err()
                .expect("original deadline denies a new effect");
            assert_eq!(
                error.fault(),
                if convergence {
                    RecoveryControlFault::ConvergenceExpired
                } else {
                    RecoveryControlFault::EffectExpired
                }
            );
            let pending: Value = serde_json::from_slice(
                &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
            )
            .unwrap();
            assert_eq!(pending["phase"], "RestorePending");
            assert!(!fixture.directory.as_path().join("new-generation").exists());
        }
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn restore_claim_replaced_owner_lock_cannot_advance_original_journal() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let (mut control, entry) = fixture.open();
        let mut session = control
            .claim_restore(entry, fixture.profile.clone())
            .unwrap();
        let root = fixture.control_root();
        let journal = root.join("operations").join(OPERATION).join("journal-v1");
        let before = std::fs::read(&journal).unwrap();
        let descriptor = std::fs::read(root.join("activation-v1")).unwrap();
        std::fs::rename(root.join("owner.lock"), root.join("old-owner.lock")).unwrap();
        std::fs::write(root.join("owner.lock"), b"WBRCOWN1").unwrap();
        std::fs::set_permissions(
            root.join("owner.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            session
                .check_capacity_before(
                    std::time::Instant::now() + std::time::Duration::from_secs(10)
                )
                .err()
                .unwrap()
                .fault(),
            RecoveryControlFault::OwnerLost
        );
        assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(
            std::fs::read(root.join("activation-v1")).unwrap(),
            descriptor
        );
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn restore_claim_same_actual_input_parent_is_rejected_before_mint() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let shared_parent = fixture.directory.join("carrier-medium");
        let key = shared_parent.join("key");
        std::fs::write(&key, [3u8; 104]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (mut control, entry) = fixture.open_with_key_parent(&shared_parent);
        assert_eq!(
            control
                .claim_restore(entry, fixture.profile.clone())
                .err()
                .unwrap()
                .fault(),
            RecoveryControlFault::InputInvalid
        );
        assert_eq!(
            std::fs::read_dir(fixture.control_root().join("operations"))
                .unwrap()
                .count(),
            0
        );
        assert!(!fixture.control_root().join("activation-v1").exists());
        assert_eq!(std::fs::read(&key).unwrap(), [3u8; 104]);
        assert!(!fixture.directory.join("new-generation").exists());
    }

    #[test]
    fn closed_codec_rejects_unadopted_upgrade_and_retains_52_data() {
        let mut record = journal_record(
            "OperationIntent",
            json!({
                "mode": "ordinary_upgrade", "priorActivationDigest": ZERO64,
                "fromNativeVersion": 54, "toNativeVersion": 55,
                "ordinaryStartupBounds": {"effectNs": 5, "convergenceNs": 9},
                "originalClockRelation": clock(),
            }),
        );
        record["sequence"] = json!(1);
        let body = serde_json::to_vec(&record).unwrap();
        let mut raw = b"WBRCJ001".to_vec();
        raw.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(&body);
        let digest = Sha256::new()
            .chain_update(b"wrokbot.restore.journal.v1\0")
            .chain_update(&raw)
            .finalize();
        raw.extend_from_slice(&digest);
        let error = observe_chain(&raw, &limits())
            .err()
            .expect("only original three modes decode");
        assert!(
            error._original_json_error.is_some(),
            "the fourth mode must fail closed enum decoding before canonical/publication checks"
        );

        let (_, mut prior_data) = descriptors().into_iter().nth(1).unwrap();
        prior_data["data"]["binding"]["nativeVersion"] = json!(52);
        assert!(
            observe(&canonical_descriptor(prior_data), &limits()).is_ok(),
            "strict-prior52 remains parseable DATA, not startup or migration authority"
        );
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn local_legacy_request(fixture: &RestoreEntryFixture) -> Value {
        use std::os::unix::fs::PermissionsExt;
        let root = fixture.directory.join("old-app");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut request = fixture.request();
        request["purpose"] = json!("adopt_ordinary_legacy");
        request.as_object_mut().unwrap().remove("profile");
        request["trustedInputSelection"] =
            json!({"installation":{"parent":fixture.directory,"component":"old-app"}});
        request["limits"] = json!({"effectNs":30_000_000_000u64,"convergenceNs":30_000_000_000u64});
        request
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn local_legacy_request_seals_initializing_before_site_effects() {
        let fixture = RestoreEntryFixture::new();
        let request = local_legacy_request(&fixture);
        let (mut control, entry) = fixture.open_request(request);
        assert_eq!(
            entry.purpose(),
            super::RecoveryRequestPurpose::AdoptOrdinaryLegacy
        );
        assert!(entry.restore_profile().is_none());
        let intent = entry
            .into_ordinary_legacy_intent(
                &control,
                &[
                    super::RuntimeOwner::PostgresSidecar,
                    super::RuntimeOwner::SqlDriver,
                ],
            )
            .unwrap();
        let deadline = intent.admission_deadline();
        let mut session = control
            .begin_ordinary_initialization_before(intent, deadline)
            .unwrap();
        session.seal_local_legacy_before().unwrap();
        let root = fixture.control_root();
        let bytes = std::fs::read(root.join("activation-v1")).unwrap();
        let observation = observe(&bytes, &fixture.limits).unwrap();
        assert_eq!(
            observation.record.phase,
            super::ActivationPhase::OrdinaryInitializing
        );
        assert_eq!(
            std::fs::read_dir(fixture.directory.join("old-app"))
                .unwrap()
                .count(),
            0,
            "no sidecar/schema/key effect precedes Initializing"
        );
        let journal =
            std::fs::read(root.join("operations").join(OPERATION).join("journal-v1")).unwrap();
        observe_chain(&journal, &fixture.limits).unwrap();
        let length = u32::from_be_bytes(journal[8..12].try_into().unwrap()) as usize;
        let first: Value = serde_json::from_slice(&journal[12..12 + length]).unwrap();
        assert_eq!(first["operationId"], OPERATION);
        assert_eq!(first["data"]["mode"], "legacy_adoption");
        assert_eq!(first["data"]["originalStartupIntent"], OPERATION);
        assert!(first["data"].get("request").is_none());
        // An actual EEXIST leaves the old first head and all its bytes intact.
        assert!(
            super::entry::lock(&control.shared)
                .unwrap()
                .publish_activation(&observation.record, deadline)
                .is_err()
        );
        assert_eq!(std::fs::read(root.join("activation-v1")).unwrap(), bytes);
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn local_legacy_request_rejects_cross_payload_or_enlarged_bounds() {
        for mutation in 0..3 {
            let fixture = RestoreEntryFixture::new();
            let mut request = local_legacy_request(&fixture);
            match mutation {
                0 => request["profile"] = serde_json::to_value(&fixture.profile).unwrap(),
                1 => {
                    request["trustedInputSelection"]["carrier"] =
                        json!({"parent":fixture.directory,"component":"carrier"})
                }
                _ => request["limits"]["effectNs"] = json!(30_000_000_001u64),
            }
            assert!(fixture.try_open_request(request).is_err());
            assert!(!fixture.control_root().join("activation-v1").exists());
            assert_eq!(
                std::fs::read_dir(fixture.control_root().join("operations"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    /// Class 7 (spec revision R484): the RunAssertion key is HKDF-keyed by the
    /// published epoch, so a still-unexpired assertion signed under epoch A is
    /// refused by the epoch B runtime; the signed payload keeps its field set.
    #[cfg(feature = "server-runtime")]
    #[test]
    fn t046_28_old_epoch_run_assertion_is_rejected_within_ttl() {
        use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
        use openbot_domain::remote_callback::{
            RUN_ASSERTION_TTL_MILLIS, RemoteRunAssertionSigner, RemoteRunScope, RemoteToolSet,
        };
        let binding = |epoch: &str| -> super::activation::ActivationBinding {
            let mut value = binding();
            value["authorizationEpoch"] = json!(epoch);
            serde_json::from_value(value).expect("closed binding")
        };
        let master = [0x5au8; 32];
        let signer = |epoch: &str| {
            let key = super::runtime::authorization_key(
                &binding(epoch),
                super::AuthorizationPurpose::RunAssertion,
                &master,
            );
            RemoteRunAssertionSigner::new(key.expose().to_vec()).expect("signer")
        };
        let epoch_a = signer(EPOCH);
        let epoch_b = signer(&"22".repeat(32));
        let scope = RemoteRunScope {
            deployment: DeploymentId::new("dep"),
            tenant: TenantId::new("ten"),
            bot: BotId::new("bot"),
            actor: ActorId::new("actor"),
            run: RunId::new("run"),
        };
        let tools = RemoteToolSet::new(["remember"]).expect("tools");
        let issued = 1_700_000_000_000i64;
        let signed = epoch_a
            .mint(scope, &tools, issued)
            .expect("mint under epoch A");
        let within_ttl = issued + RUN_ASSERTION_TTL_MILLIS / 2;
        // Positive control: the same epoch verifies inside the TTL.
        epoch_a
            .verify(&signed, within_ttl)
            .expect("epoch A verifies its own assertion");
        assert!(
            epoch_b.verify(&signed, within_ttl).is_err(),
            "old epoch assertion accepted"
        );
        // The same master under the same epoch derives the same key; only the epoch moved.
        signer(EPOCH)
            .verify(&signed, within_ttl)
            .expect("same epoch is stable");
        let payload = signed.split_once('.').expect("value.signature").0;
        let payload: Value = serde_json::from_slice(
            &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .expect("payload base64"),
        )
        .expect("payload json");
        let mut fields: Vec<&str> = payload
            .as_object()
            .expect("payload object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "actorId",
                "botId",
                "deploymentId",
                "exp",
                "iat",
                "runId",
                "tenantId",
                "toolSetHash",
                "version"
            ]
        );
    }

    // V7-IMPL-046 batch C: runtime close receipts and published heads below
    // the latest native version. Heads and journals are written
    // with the private writer primitives, exactly as the producers write them.

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    const ADOPTION: &str = "abcdefabcdefabcdefabcdefabcdef02";
    /// The original operation of a synthetic site; distinct from the restore request ID.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    const SITE: &str = "abcdefabcdefabcdefabcdefabcdef03";
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    const REPLACED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    const LOCAL_OWNERS: [super::RuntimeOwner; 5] = [
        super::RuntimeOwner::PostgresSidecar,
        super::RuntimeOwner::SqlDriver,
        super::RuntimeOwner::ApplicationAssembly,
        super::RuntimeOwner::DesktopAgentRelay,
        super::RuntimeOwner::DesktopAgent,
    ];

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    impl RestoreEntryFixture {
        /// The ordinary site's original app-data root, created once.
        fn site_root(&self) -> RecoveryFileIdentity {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let root = self.directory.join("old-app");
            if !root.exists() {
                std::fs::create_dir(&root).unwrap();
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let meta = std::fs::metadata(&root).unwrap();
            RecoveryFileIdentity {
                device: meta.dev(),
                inode: meta.ino(),
                uid: meta.uid(),
            }
        }

        fn open_local(
            &self,
            control: &super::RecoveryControl,
        ) -> Result<super::RecoveryRuntimeOwner, super::RecoveryControlError> {
            let store = crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore::new(
                crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(
                    self.directory.join("old-app"),
                )
                .unwrap(),
            );
            control.open_local_before(
                &store,
                [0x11; 32],
                ["test.vault", "test.postgres"],
                serde_json::from_value(
                    json!({"effectNs": 30_000_000_000u64, "convergenceNs": 30_000_000_000u64}),
                )
                .unwrap(),
                &LOCAL_OWNERS,
                |_| Ok(None),
            )
        }

        /// The handed-back intent of a below-latest head and the head it names.
        fn below_latest(
            &self,
            control: &super::RecoveryControl,
        ) -> (
            super::VerifiedOrdinaryStartupIntent,
            super::ordinary::ExpectedHead,
        ) {
            let error = self
                .open_local(control)
                .err()
                .expect("below latest is not admitted");
            assert_eq!(error.fault(), RecoveryControlFault::InitializationRequired);
            let intent = error
                .into_unconsumed_intent()
                .expect("the intent is handed back");
            let head = intent
                .expected_head()
                .cloned()
                .expect("the seen head is named");
            (intent, head)
        }
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn site_binding(fixture: &RestoreEntryFixture, native: u32) -> Value {
        let mut binding = binding();
        binding["generationRoot"] = serde_json::to_value(fixture.site_root()).unwrap();
        binding["nativeVersion"] = json!(native);
        binding
    }

    /// One operation journal of `entries`, then the publication of the
    /// descriptor `descriptor` builds from their references and its own
    /// PublishIntent position. Returns the published digest.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn publish_synthetic(
        control: &super::RecoveryControl,
        operation: &str,
        epoch: &str,
        entries: Vec<super::journal::JournalData>,
        descriptor: impl FnOnce(&[Value], Value) -> Value,
    ) -> String {
        publish_synthetic_in(control, CONTROL, operation, epoch, entries, descriptor)
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn publish_synthetic_in(
        control: &super::RecoveryControl,
        control_id: &str,
        operation: &str,
        epoch: &str,
        entries: Vec<super::journal::JournalData>,
        descriptor: impl FnOnce(&[Value], Value) -> Value,
    ) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut files = super::entry::lock(&control.shared).unwrap();
        files.acquire_writer_before(deadline).unwrap();
        let op = super::Hex32::parse(operation).unwrap();
        files
            .begin_journal(
                &op,
                &super::Hex32::parse(control_id).unwrap(),
                epoch,
                deadline,
            )
            .unwrap();
        let references: Vec<Value> = entries
            .iter()
            .map(|entry| {
                serde_json::to_value(files.append_journal(&op, entry, deadline).unwrap()).unwrap()
            })
            .collect();
        let sequence = references.len() as u64 + 1;
        let record: ActivationRecord = serde_json::from_value(descriptor(
            &references,
            json!({"contextId": operation, "sequence": sequence}),
        ))
        .unwrap();
        let (_, digest) = record.encoded().unwrap();
        files
            .append_journal(
                &op,
                &super::journal::JournalData::publish_intent(record.phase, &digest),
                deadline,
            )
            .unwrap();
        let published = files.publish_activation(&record, deadline).unwrap();
        files
            .append_journal(
                &op,
                &super::journal::JournalData::publish_observed(
                    sequence,
                    &digest,
                    published.identity,
                ),
                deadline,
            )
            .unwrap();
        files.release_writer();
        digest
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn descriptor(revision: u64, previous: &str, phase: &str, data: Value) -> Value {
        json!({"recordType": "wrokbot-recovery-activation", "version": 1, "controlId": CONTROL,
            "revision": revision, "previousDigest": previous, "phase": phase, "data": data})
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn confirmed_stage(stage: super::journal::Stage) -> [super::journal::JournalData; 2] {
        [
            super::journal::JournalData::stage_intent(stage, CONTROL),
            super::journal::JournalData::stage_observed(
                2,
                super::journal::Disposition::PgCommit(super::journal::CommitAck::TimelyAck),
            ),
        ]
    }

    /// A first published OrdinaryActive at `native`, as Fresh publishes it:
    /// its operation names the replaced Initializing digest.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn publish_active(
        fixture: &RestoreEntryFixture,
        control: &super::RecoveryControl,
        native: u32,
    ) -> String {
        let [intent, observed] = [
            super::journal::JournalData::stage_intent(
                super::journal::Stage::OrdinaryInitialize,
                CONTROL,
            ),
            super::journal::JournalData::stage_observed(
                2,
                super::journal::Disposition::TaskReturned {
                    original_task_id: "local-fresh-chain".to_owned(),
                    observed_ns: 3,
                },
            ),
        ];
        let entries = vec![
            super::journal::JournalData::fresh_init(
                serde_json::from_value(host()).unwrap(),
                SITE,
                serde_json::from_value(planned()).unwrap(),
                serde_json::from_value(json!({"effectNs": 5, "convergenceNs": 9})).unwrap(),
                REPLACED,
                serde_json::from_value(clock()).unwrap(),
            ),
            intent,
            observed,
        ];
        let binding = site_binding(fixture, native);
        publish_synthetic(control, SITE, EPOCH, entries, |refs, position| {
            descriptor(
                2,
                REPLACED,
                "OrdinaryActive",
                json!({"binding": binding,
                "initializationEvidence": [refs[2]], "publishIntent": position}),
            )
        })
    }

    /// A first published RestoreCurrent at `native` with its restore journal.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn publish_current(
        fixture: &RestoreEntryFixture,
        control: &super::RecoveryControl,
        native: u32,
    ) -> String {
        use std::os::unix::fs::MetadataExt;
        let binding = site_binding(fixture, native);
        let parent = std::fs::metadata(&fixture.directory).unwrap();
        let [intent, observed] = confirmed_stage(super::journal::Stage::Switch);
        let restore: super::journal::RestoreIntent = serde_json::from_value(json!({
            "profile": fixture.profile, "inputIdentities": {"carrier": {"file": file(5), "length": 1},
                "keyMedium": {"file": file(6), "length": 104}},
            "business": {"deploymentId": "dep", "tenantId": "ten", "datasetId": "data"},
            "sourceInstallationId": "source", "targetInstallationId": "target",
            "candidatePlan": {"siteKind": "local_physical",
                "trustedParent": {"device": parent.dev(), "inode": parent.ino(), "uid": parent.uid()},
                "entryComponent": "old-app", "installationId": binding["targetInstallationId"],
                "generationId": binding["generationId"]},
            "ownerClock": clock()})).unwrap();
        let entries = vec![
            super::journal::JournalData::restore(restore),
            intent,
            observed,
        ];
        publish_synthetic(control, SITE, EPOCH, entries, |refs, position| {
            descriptor(
                2,
                REPLACED,
                "RestoreCurrent",
                json!({"operationId": SITE, "epoch": EPOCH,
                "profileDigest": ZERO64, "binding": binding, "closureEvidence": [refs[2]],
                "switchReadback": refs[2], "publishIntent": position}),
            )
        })
    }

    /// The LegacyAdoption OperationIntent a known-site adoption writes.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn adoption_intent(replaced: &str) -> super::journal::JournalData {
        super::journal::JournalData::legacy_adoption(
            serde_json::from_value(host()).unwrap(),
            ADOPTION,
            serde_json::from_value(file(21)).unwrap(),
            serde_json::from_value(json!({"siteKind": "local_physical", "trustedParent": file(3), "entryComponent": "app"})).unwrap(),
            serde_json::from_value(json!({"deploymentId": "dep", "tenantId": "ten", "datasetId": "data",
                "sourceInstallationId": "target", "targetInstallationId": "target"})).unwrap(),
            serde_json::from_value(json!({"effectNs": 5, "convergenceNs": 9})).unwrap(),
            replaced,
            serde_json::from_value(clock()).unwrap(),
        )
    }

    /// Complete the held adoption session as its producers do after the
    /// read-only site check: one confirmed ordinary_verify, the proof of the
    /// actual site at the latest version, publication and enrollment.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn adopt(
        fixture: &RestoreEntryFixture,
        mut session: super::OrdinaryInitializationSession,
    ) -> super::RecoveryRuntimeOwner {
        use super::activation::{KeyKind, KeyReference};
        session.seal_published().unwrap();
        assert!(
            session
                .observe_commit(true, std::time::Instant::now())
                .unwrap()
        );
        let key = |kind| KeyReference {
            kind,
            reviewed_service: "svc".to_owned(),
            account: "acct".to_owned(),
            key_id: "key".to_owned(),
            key_version: 1,
            target_installation_id: "target".to_owned(),
            operation_id: OPERATION.to_owned(),
        };
        let site = super::activation::OrdinaryLocalSite {
            dataset_id: "data".to_owned(),
            deployment_id: "dep".to_owned(),
            tenant_id: "ten".to_owned(),
            installation_id: "target".to_owned(),
            generation_root: fixture.site_root(),
            pg_system_id: 7_000_000_001,
            database_oid: 16384,
            master: key(KeyKind::HistoricalMaster),
            postgres: key(KeyKind::PostgresScram),
        };
        let operation = session.operation().unwrap();
        session
            .publish_active(super::OrdinaryActivationProof::Legacy(
                super::VerifiedOrdinaryLegacyProof {
                    operation,
                    site: super::ordinary::LegacySite::Local(site),
                    native_version: crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
                    migration_digest: "ab".repeat(32),
                },
            ))
            .unwrap();
        session.into_runtime_before().unwrap()
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn head(fixture: &RestoreEntryFixture) -> Value {
        serde_json::from_slice(
            &std::fs::read(fixture.control_root().join("activation-v1")).unwrap(),
        )
        .unwrap()
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn never_started() -> super::RuntimeCloseResources {
        super::RuntimeCloseResources::new(
            LOCAL_OWNERS
                .into_iter()
                .map(|owner| super::RuntimeCloseFact::PassiveRetirement {
                    object: super::PassiveObjectKind::NeverStarted(owner),
                })
                .collect(),
        )
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn runtime_records(fixture: &RestoreEntryFixture, name: &str) -> usize {
        std::fs::read_dir(fixture.control_root().join("runtimes"))
            .unwrap()
            .filter(|runtime| runtime.as_ref().unwrap().path().join(name).exists())
            .count()
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn runtime_shared_callers_on_two_threads_never_see_each_other_busy() {
        let fixture = RestoreEntryFixture::new();
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut runtime = fixture.open_local(&control).unwrap();
        let gate = runtime.read_gate();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let first = gate.borrow_worker_before(deadline).await.unwrap();
        let second = gate.borrow_worker_before(deadline).await.unwrap();
        // Each recheck is a runtime SH section followed by a control SH section;
        // concurrent sections share both books instead of finding them taken.
        std::thread::scope(|scope| {
            for lease in [&first, &second] {
                scope.spawn(move || {
                    for _ in 0..500 {
                        lease.verify_current_before(deadline).unwrap();
                    }
                });
            }
        });
        drop((first, second));
        runtime
            .close_before(never_started(), deadline)
            .await
            .unwrap();
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn exclusive_control_custody_makes_a_shared_section_busy_at_once() {
        let fixture = RestoreEntryFixture::new();
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let exclusive = super::entry::lock(&control.shared).unwrap();
        let started = std::time::Instant::now();
        let error = super::entry::share(&control.shared, |_| ()).expect_err("taken custody");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "no wait for the exclusive owner"
        );
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        drop(error);
        drop(exclusive);
        super::entry::share(&control.shared, |_| ()).unwrap();
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_05_restore_exclusive_waits_for_both_runtime_close_receipts() {
        let fixture = RestoreEntryFixture::new();
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let first_control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut first = fixture.open_local(&first_control).unwrap();
        let second_control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut second = fixture.open_local(&second_control).unwrap();
        assert_eq!(runtime_records(&fixture, "enrollment-v1"), 2);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        first.close_before(never_started(), deadline).await.unwrap();
        drop(first);
        drop(first_control);
        let (mut control, entry) = fixture.open();
        let error = control
            .claim_restore(entry, fixture.profile.clone())
            .err()
            .expect("one runtime is still open");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        drop(error);
        drop(control);
        assert_eq!(
            std::fs::read_dir(fixture.control_root().join("operations"))
                .unwrap()
                .count(),
            1
        );
        second
            .close_before(never_started(), deadline)
            .await
            .unwrap();
        drop(second);
        drop(second_control);
        assert_eq!(runtime_records(&fixture, "receipt-v1"), 2);
        let (mut control, entry) = fixture.open();
        control
            .claim_restore(entry, fixture.profile.clone())
            .expect("both original runtimes left their close receipts");
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_06_missing_close_gone_pid_or_released_lock_keeps_pending() {
        let fixture = RestoreEntryFixture::new();
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let runtime = fixture.open_local(&control).unwrap();
        // The runtime goes away without a close: its runtime.lock SH is released.
        drop(runtime);
        drop(control);
        let enrollments = restore_control_bytes(&fixture.control_root().join("runtimes"));
        assert_eq!(runtime_records(&fixture, "enrollment-v1"), 1);
        assert_eq!(runtime_records(&fixture, "receipt-v1"), 0);
        for _ in 0..2 {
            let (mut control, entry) = fixture.open();
            assert_eq!(
                control
                    .claim_restore(entry, fixture.profile.clone())
                    .err()
                    .map(|e| e.fault()),
                Some(RecoveryControlFault::OwnerBusy),
                "a released lock is not a close receipt"
            );
        }
        assert_eq!(
            restore_control_bytes(&fixture.control_root().join("runtimes")),
            enrollments
        );
        assert!(
            !fixture
                .control_root()
                .join("operations")
                .join(OPERATION)
                .exists(),
            "no restore operation was claimed"
        );
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn runtime_entries(fixture: &RestoreEntryFixture) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(fixture.control_root().join("runtimes"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    /// A Local start whose host observed the head's own generation before spawning.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn open_local_observed(
        fixture: &RestoreEntryFixture,
        control: &super::RecoveryControl,
        generation_root: RecoveryFileIdentity,
    ) -> Result<super::RecoveryRuntimeOwner, super::RecoveryControlError> {
        let store = crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore::new(
            crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot::from_current_os_user_app_data(
                fixture.directory.join("old-app"),
            )
            .unwrap(),
        );
        control.open_local_before(
            &store,
            [0x11; 32],
            ["test.vault", "test.postgres"],
            serde_json::from_value(
                json!({"effectNs": 30_000_000_000u64, "convergenceNs": 30_000_000_000u64}),
            )
            .unwrap(),
            &LOCAL_OWNERS,
            |restored| {
                assert!(
                    restored.is_none(),
                    "an ordinary head names no restored site"
                );
                Ok(Some(super::LocalPostgresQuiescence::observed(
                    generation_root,
                )))
            },
        )
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_60_receipted_runtimes_retire_before_the_capacity_count() {
        let mut fixture = RestoreEntryFixture::new();
        fixture.limits.max_registered_runtimes = 2;
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        // N + 2 starts at capacity N: each registration first retires the
        // previous runtime's receipted entry.
        for _ in 0..4 {
            let control = super::RecoveryControl::open(fixture.config()).unwrap();
            let mut runtime = fixture.open_local(&control).unwrap();
            assert_eq!(runtime_entries(&fixture).len(), 1, "only the live entry");
            runtime
                .close_before(never_started(), deadline)
                .await
                .unwrap();
            drop(runtime);
            drop(control);
            assert_eq!(runtime_records(&fixture, "receipt-v1"), 1);
        }
        let (mut control, entry) = fixture.open();
        control
            .claim_restore(entry, fixture.profile.clone())
            .expect("the last receipt still releases the claim");
        drop(control);
        assert_eq!(
            std::fs::read_dir(fixture.control_root().join("operations"))
                .unwrap()
                .count(),
            2,
            "operations are never retired"
        );
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_61_tampered_receipts_stay_and_remnant_directories_are_removed() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = RestoreEntryFixture::new();
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut closed = Vec::new();
        for _ in 0..2 {
            let control = super::RecoveryControl::open(fixture.config()).unwrap();
            let mut runtime = fixture.open_local(&control).unwrap();
            let entry = runtime_entries(&fixture)
                .into_iter()
                .find(|entry| !closed.contains(entry))
                .unwrap();
            runtime
                .close_before(never_started(), deadline)
                .await
                .unwrap();
            drop(runtime);
            drop(control);
            closed.push(entry);
            // Keep the first entry from the next registration's retirement.
            if closed.len() == 1 {
                let receipt = closed[0].join("receipt-v1");
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
                value["clockObservations"] = json!([0]);
                std::fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        let tampered = closed[0].clone();
        // An interrupted close leaves its pending receipt beside the enrollment.
        let interrupted = closed[1].with_file_name("abcdefabcdefabcdefabcdefabcde001");
        let remnants = [
            ("abcdefabcdefabcdefabcdefabcde002", None),
            ("abcdefabcdefabcdefabcdefabcde003", Some("receipt-v1")),
            (
                "abcdefabcdefabcdefabcdefabcde004",
                Some("enrollment-v1.pending"),
            ),
        ];
        for (name, record) in remnants
            .iter()
            .map(|(name, record)| (*name, *record))
            .chain([("abcdefabcdefabcdefabcdefabcde001", Some("enrollment-v1"))])
        {
            let directory = closed[1].with_file_name(name);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            if let Some(record) = record {
                std::fs::copy(tampered.join("receipt-v1"), directory.join(record)).unwrap();
                std::fs::set_permissions(
                    directory.join(record),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
        }
        std::fs::copy(
            tampered.join("enrollment-v1"),
            interrupted.join("receipt-v1.pending"),
        )
        .unwrap();
        std::fs::set_permissions(
            interrupted.join("receipt-v1.pending"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let runtime = fixture.open_local(&control).unwrap();
        assert!(!closed[1].exists(), "the intact receipt retired");
        for (name, _) in remnants {
            assert!(!closed[1].with_file_name(name).exists(), "{name} removed");
        }
        assert!(
            tampered.join("receipt-v1").exists(),
            "tampered receipt kept"
        );
        assert!(interrupted.join("receipt-v1.pending").exists());
        assert_eq!(runtime_entries(&fixture).len(), 3);
        drop(runtime);
        drop(control);
        let (mut control, entry) = fixture.open();
        assert_eq!(
            control
                .claim_restore(entry, fixture.profile.clone())
                .err()
                .map(|error| error.fault()),
            Some(RecoveryControlFault::OwnerBusy)
        );
    }

    /// The registering process of t046_62: it enrolls under the parent's
    /// fixture and stays alive until the parent kills it. Without the
    /// parent's variables it does nothing.
    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_62_child_registers_and_waits() {
        use std::io::Write;
        let Some(directory) = std::env::var_os("OPENBOT_T046_62_FIXTURE") else {
            return;
        };
        let mut fixture = std::mem::ManuallyDrop::new(RestoreEntryFixture::new());
        std::fs::remove_dir_all(&fixture.directory).unwrap();
        fixture.directory = directory.into();
        fixture.limits.max_registered_runtimes = 3;
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let _runtime = match std::env::var("OPENBOT_T046_62_OBSERVED").unwrap().as_str() {
            "none" => fixture.open_local(&control).unwrap(),
            observed => {
                open_local_observed(&fixture, &control, serde_json::from_str(observed).unwrap())
                    .unwrap()
            }
        };
        // libtest may print its own progress on the same line first.
        println!("t046-62-registered");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(600));
    }

    /// A real runtime process registered under `fixture`; kill -9 is its crash.
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn registered_child(
        fixture: &RestoreEntryFixture,
        observed: Option<RecoveryFileIdentity>,
    ) -> std::process::Child {
        use std::io::BufRead;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_control::tests::t046_62_child_registers_and_waits",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("OPENBOT_T046_62_FIXTURE", &fixture.directory)
            .env(
                "OPENBOT_T046_62_OBSERVED",
                observed.map_or("none".to_owned(), |root| {
                    serde_json::to_string(&root).unwrap()
                }),
            )
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        assert!(
            lines.any(|line| line.unwrap().ends_with("t046-62-registered")),
            "the child enrolled"
        );
        child
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn crash(mut child: std::process::Child) {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_62_crashed_local_enrollments_settle_only_with_the_same_generation_observed() {
        let mut fixture = RestoreEntryFixture::new();
        fixture.limits.max_registered_runtimes = 3;
        let writer = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_active(
            &fixture,
            &writer,
            crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
        );
        drop(writer);
        let generation = fixture.site_root();
        let other = RecoveryFileIdentity {
            inode: generation.inode + 1,
            ..generation
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        // Three runtimes killed without a close: no observation, then another
        // generation's observation, settle nothing.
        crash(registered_child(&fixture, None));
        crash(registered_child(&fixture, None));
        crash(registered_child(&fixture, Some(other)));
        assert_eq!(runtime_entries(&fixture).len(), 3);
        let (mut claim, entry) = fixture.open();
        assert_eq!(
            claim
                .claim_restore(entry, fixture.profile.clone())
                .err()
                .map(|error| error.fault()),
            Some(RecoveryControlFault::OwnerBusy)
        );
        drop(claim);
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        assert_eq!(
            fixture
                .open_local(&control)
                .err()
                .map(|error| error.fault()),
            Some(RecoveryControlFault::CapacityExceeded),
            "unsettled crashes count"
        );
        drop(control);
        // The same generation's observation settles all of them.
        let first_control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut first = open_local_observed(&fixture, &first_control, generation).unwrap();
        assert_eq!(runtime_entries(&fixture).len(), 1, "every crash settled");
        // While registered runtimes are alive their SH denies EX: a crashed
        // entry stays even with the matching observation.
        let live = registered_child(&fixture, Some(generation));
        crash(registered_child(&fixture, Some(generation)));
        assert_eq!(runtime_entries(&fixture).len(), 3);
        first.close_before(never_started(), deadline).await.unwrap();
        drop(first);
        drop(first_control);
        let second_control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut second = open_local_observed(&fixture, &second_control, generation).unwrap();
        assert_eq!(
            runtime_entries(&fixture).len(),
            3,
            "the receipt retired; the live child keeps the crashed entry"
        );
        second
            .close_before(never_started(), deadline)
            .await
            .unwrap();
        drop(second);
        drop(second_control);
        crash(live);
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let mut runtime = open_local_observed(&fixture, &control, generation).unwrap();
        assert_eq!(runtime_entries(&fixture).len(), 1);
        runtime
            .close_before(never_started(), deadline)
            .await
            .unwrap();
        drop(runtime);
        drop(control);
        let (mut control, entry) = fixture.open();
        control
            .claim_restore(entry, fixture.profile.clone())
            .expect("settled and receipted entries release the claim");
    }

    #[tokio::test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    async fn t046_51_never_started_and_start_exit_close_while_unknown_sidecar_stays_pending() {
        use super::{
            NativeExit, PassiveObjectKind, PipeJoin, ProcessStart, RuntimeCloseFact,
            RuntimeCloseResources, RuntimeOwner,
        };
        use crate::db::pool::ConnectionDestruction;
        for case in [
            "never",
            "code",
            "signal",
            "missing",
            "duplicate",
            "drivers",
            "empty_drivers",
        ] {
            let fixture = RestoreEntryFixture::new();
            let writer = super::RecoveryControl::open(fixture.config()).unwrap();
            publish_active(
                &fixture,
                &writer,
                crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs(),
            );
            drop(writer);
            let control = super::RecoveryControl::open(fixture.config()).unwrap();
            let mut runtime = fixture.open_local(&control).unwrap();
            let root = fixture.control_root().join("runtimes");
            let original = restore_control_bytes(&root);
            let enrollment = original
                .iter()
                .find(|(path, _)| path.ends_with("enrollment-v1"))
                .unwrap();
            let passive = |owner| RuntimeCloseFact::PassiveRetirement {
                object: PassiveObjectKind::NeverStarted(owner),
            };
            let mut facts: Vec<_> = LOCAL_OWNERS
                .into_iter()
                .filter(|owner| {
                    *owner != RuntimeOwner::PostgresSidecar
                        && (!matches!(case, "drivers" | "empty_drivers")
                            || *owner != RuntimeOwner::SqlDriver)
                })
                .map(passive)
                .collect();
            // Receipt-side fixtures exercise the exact adapter fact shapes.
            // T046-50/52/54 separately observe the original native waits and
            // SQL driver destruction; these DATA do not claim an OS wait.
            if case == "never" {
                facts.push(passive(RuntimeOwner::PostgresSidecar));
            } else if case != "missing" {
                facts.push(RuntimeCloseFact::NativeWait {
                    original_program_id: RuntimeOwner::PostgresSidecar,
                    original_pid: 7,
                    original_start_identity: ProcessStart {
                        seconds: 1,
                        nanos: 0,
                    },
                    exit: if case == "signal" {
                        NativeExit::Signal { value: 9 }
                    } else {
                        NativeExit::Code { value: 17 }
                    },
                    observed_ns: super::clock::monotonic_ns().unwrap(),
                    pipes: [PipeJoin::Null, PipeJoin::Null, PipeJoin::Null],
                });
            }
            if case == "duplicate" {
                facts.push(passive(RuntimeOwner::PostgresSidecar));
            }
            if matches!(case, "drivers" | "empty_drivers") {
                let drivers = if case == "drivers" {
                    vec![
                        ConnectionDestruction::ConnectingFutureDestroyed,
                        ConnectionDestruction::ConnectionDestroyed,
                    ]
                } else {
                    Vec::new()
                };
                facts.push(RuntimeCloseFact::PassiveRetirement {
                    object: PassiveObjectKind::SqlDriver(drivers),
                });
            }
            let closes = !matches!(case, "missing" | "duplicate");
            let result = runtime
                .close_before(
                    RuntimeCloseResources::new(facts),
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await;
            assert_eq!(result.is_ok(), closes, "{case}");
            drop(result);
            drop(runtime);
            drop(control);
            assert_eq!(
                std::fs::read(enrollment.0).unwrap(),
                *enrollment.1,
                "immutable enrollment: {case}"
            );
            assert_eq!(
                runtime_records(&fixture, "receipt-v1"),
                usize::from(closes),
                "{case}"
            );
            if !closes {
                assert_eq!(restore_control_bytes(&root), original);
            }
            let (mut control, intent) = fixture.open();
            let claim = control.claim_restore(intent, fixture.profile.clone());
            assert_eq!(
                claim.is_ok(),
                closes,
                "only an actual complete receipt releases the runtime: {case}"
            );
            if !closes {
                assert_eq!(
                    claim.err().unwrap().fault(),
                    RecoveryControlFault::OwnerBusy
                );
            }
        }
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_41_low_native_active_hands_back_intent_and_busy_writer_changes_nothing() {
        let fixture = RestoreEntryFixture::new();
        // NOENT with an existing root is not handed back (no positive intent).
        fixture.site_root();
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        let error = fixture.open_local(&control).err().expect("no head");
        assert_eq!(error.fault(), RecoveryControlFault::InitializationRequired);
        assert!(error.into_unconsumed_intent().is_none());
        let digest = publish_active(
            &fixture,
            &control,
            crate::db::native::NATIVE_0052_VERSION.unsigned_abs(),
        );
        let (intent, seen) = fixture.below_latest(&control);
        assert_eq!(
            seen,
            super::ordinary::ExpectedHead::ActiveBelowLatest(digest.clone())
        );
        // Another writer holds ownerEX: begin is OwnerBusy and writes nothing.
        let before = restore_control_bytes(&fixture.control_root());
        let busy = super::RecoveryControl::open(fixture.config()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        super::entry::lock(&busy.shared)
            .unwrap()
            .acquire_writer_before(deadline)
            .unwrap();
        let mut control = control;
        let error = control
            .begin_ordinary_initialization_before(
                intent,
                std::time::Instant::now() + std::time::Duration::from_millis(200),
            )
            .err()
            .expect("writer is busy");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        assert!(
            error.into_unconsumed_intent().is_some(),
            "a busy writer keeps the intent"
        );
        drop(busy);
        assert_eq!(restore_control_bytes(&fixture.control_root()), before);
        // The head changes between SH and EX: OwnerBusy.
        let (intent, _) = fixture.below_latest(&control);
        let other = publish_synthetic(
            &control,
            ADOPTION,
            EPOCH,
            {
                let [intent, observed] = confirmed_stage(super::journal::Stage::OrdinaryVerify);
                vec![adoption_intent(&digest), intent, observed]
            },
            |refs, position| {
                descriptor(
                    3,
                    &digest,
                    "OrdinaryActive",
                    json!({"binding": site_binding(&fixture, crate::db::native::NATIVE_0053_VERSION.unsigned_abs()),
                "initializationEvidence": [refs[2]], "publishIntent": position}),
                )
            },
        );
        let error = control
            .begin_ordinary_initialization_before(
                intent,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .err()
            .expect("head changed");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        // The current head is adopted and republished at the latest version.
        let (intent, seen) = fixture.below_latest(&control);
        assert_eq!(
            seen,
            super::ordinary::ExpectedHead::ActiveBelowLatest(other.clone())
        );
        let session = control
            .begin_ordinary_initialization_before(
                intent,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .unwrap();
        assert!(session.adopts_published_head());
        let _runtime = adopt(&fixture, session);
        let republished = head(&fixture);
        assert_eq!(republished["phase"], "OrdinaryActive");
        assert_eq!(republished["revision"], 4);
        assert_eq!(republished["previousDigest"], other.as_str());
        assert_eq!(
            republished["data"]["binding"]["nativeVersion"],
            crate::db::native::NATIVE_LATEST_VERSION
        );
        assert_eq!(republished["data"]["binding"]["authorizationEpoch"], EPOCH);
        let context = republished["data"]["publishIntent"]["contextId"]
            .as_str()
            .unwrap();
        assert_ne!(context, ADOPTION);
        let journal = std::fs::read(
            fixture
                .control_root()
                .join("operations")
                .join(context)
                .join("journal-v1"),
        )
        .unwrap();
        let length = u32::from_be_bytes(journal[8..12].try_into().unwrap()) as usize;
        let first: Value = serde_json::from_slice(&journal[12..12 + length]).unwrap();
        assert_eq!(first["data"]["mode"], "legacy_adoption");
        assert_eq!(
            first["data"]["initializingDescriptorDigest"],
            other.as_str()
        );
        assert_eq!(first["epoch"], EPOCH);
        // Another startup reads the republished head and enrolls.
        let reader = super::RecoveryControl::open(fixture.config()).unwrap();
        fixture
            .open_local(&reader)
            .expect("republished head at the latest version");
    }

    #[test]
    fn t046_43_ordinary_upgrade_intent_round_trips_and_rejects_foreign_stages() {
        // The below-latest exit is a LegacyAdoption of the known
        // site; its OperationIntent names the replaced published head.
        let data = |replaced: &str| {
            json!({"mode": "legacy_adoption",
            "hostBinding": host(), "originalStartupIntent": OPERATION, "ownedIntentFileIdentity": file(21),
            "originalSiteSelection": {"siteKind": "local_physical", "trustedParent": file(3), "entryComponent": "app"},
            "expectedOriginalBusinessAndInstallation": {"deploymentId": "dep", "tenantId": "ten", "datasetId": "data",
                "sourceInstallationId": "target", "targetInstallationId": "target"},
            "ordinaryStartupBounds": {"effectNs": 5, "convergenceNs": 9},
            "initializingDescriptorDigest": replaced, "originalClockRelation": clock()})
        };
        let adoption = |replaced: &str| journal_record("OperationIntent", data(replaced));
        let stage = |name: &str| {
            journal_record(
                "StageIntent",
                json!({"stage": name, "originalEffectId": CONTROL, "expectedBinding": null}),
            )
        };
        let observed = journal_record(
            "StageObserved",
            json!({"intentSequence": 2,
            "typedDisposition": {"kind": "PgCommit", "data": "TimelyAck"}, "actualBinding": null, "receiptRefs": []}),
        );
        let raw = frames(&[adoption(REPLACED_43), stage("ordinary_verify"), observed]);
        let chain =
            observe_chain(&raw, &limits()).expect("closed LegacyAdoption decodes canonically");
        // The typed writer encodes the same first frame byte for byte.
        let typed = super::journal::JournalData::legacy_adoption(
            serde_json::from_value(host()).unwrap(),
            OPERATION,
            serde_json::from_value(file(21)).unwrap(),
            serde_json::from_value(data(REPLACED_43)["originalSiteSelection"].clone()).unwrap(),
            serde_json::from_value(
                data(REPLACED_43)["expectedOriginalBusinessAndInstallation"].clone(),
            )
            .unwrap(),
            serde_json::from_value(json!({"effectNs": 5, "convergenceNs": 9})).unwrap(),
            REPLACED_43,
            serde_json::from_value(clock()).unwrap(),
        )
        .frame(CONTROL, OPERATION, EPOCH, 1, None, &limits())
        .unwrap();
        assert_eq!(
            typed.bytes,
            raw[..typed.bytes.len()],
            "encode → decode → encode is byte-identical"
        );
        for foreign in ["ordinary_initialize", "pg_upgrade", "import", "switch"] {
            assert_eq!(
                observe_chain(&frames(&[adoption(REPLACED_43), stage(foreign)]), &limits())
                    .err()
                    .map(|e| e.fault()),
                Some(RecoveryControlFault::ControlInvalid),
                "{foreign} is not a legacy adoption stage"
            );
        }
        // Closed keys: a missing or an unknown key fails typed decoding.
        let single = |mut record: Value| {
            record["sequence"] = json!(1);
            let body = serde_json::to_vec(&record).unwrap();
            let mut raw = b"WBRCJ001".to_vec();
            raw.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            raw.extend_from_slice(&body);
            let digest = Sha256::new()
                .chain_update(b"wrokbot.restore.journal.v1\0")
                .chain_update(&raw)
                .finalize();
            raw.extend_from_slice(&digest);
            observe_chain(&raw, &limits())
        };
        for missing in [
            "initializingDescriptorDigest",
            "originalStartupIntent",
            "ownedIntentFileIdentity",
        ] {
            let mut record = adoption(REPLACED_43);
            record["data"].as_object_mut().unwrap().remove(missing);
            let error = single(record).err().expect("a required key is missing");
            assert!(
                error._original_json_error.is_some(),
                "{missing} fails typed decoding"
            );
        }
        let mut unknown = adoption(REPLACED_43);
        unknown["data"]["toNativeVersion"] = json!(54);
        let error = single(unknown).err().expect("no fourth-mode field");
        assert!(
            error._original_json_error.is_some(),
            "an unknown key fails typed decoding"
        );
        // The Active it publishes names the replaced head as previousDigest.
        let (_, mut active) = descriptors().into_iter().nth(1).unwrap();
        active["revision"] = json!(3);
        active["previousDigest"] = json!(REPLACED_43);
        active["data"]["initializationEvidence"] =
            json!([{"contextId": OPERATION, "sequence": 3, "digest": evidence_digest(&raw, 3)}]);
        let published = observe(&canonical_descriptor(active.clone()), &limits()).unwrap();
        chain
            .verify_ordinary_evidence(&published)
            .expect("names the replaced head");
        active["previousDigest"] = json!(EPOCH.replace('1', "3"));
        let published = observe(&canonical_descriptor(active), &limits()).unwrap();
        assert_eq!(
            chain
                .verify_ordinary_evidence(&published)
                .err()
                .map(|e| e.fault()),
            Some(RecoveryControlFault::ClosureUnproven),
            "an operation naming another head than previousDigest is refused"
        );
    }

    const REPLACED_43: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    /// Frame digest of record `sequence` in `raw` (1-based).
    fn evidence_digest(raw: &[u8], sequence: usize) -> String {
        let mut offset = 0;
        for index in 1..=sequence {
            let length =
                u32::from_be_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) as usize;
            let end = offset + 12 + length;
            if index == sequence {
                return digest_hex(&raw[end..end + 32].try_into().unwrap());
            }
            offset = end + 32;
        }
        unreachable!()
    }

    #[test]
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    fn t046_47_restore_current_below_latest_republishes_with_both_journals_checked() {
        let below = crate::db::native::NATIVE_0052_VERSION.unsigned_abs();
        let latest = crate::db::native::NATIVE_LATEST_VERSION.unsigned_abs();
        let fixture = RestoreEntryFixture::new();
        let mut control = super::RecoveryControl::open(fixture.config()).unwrap();
        let digest = publish_current(&fixture, &control, below);
        let (intent, seen) = fixture.below_latest(&control);
        assert_eq!(
            seen,
            super::ordinary::ExpectedHead::CurrentBelowLatest(digest.clone())
        );
        let original = head(&fixture);
        let session = control
            .begin_ordinary_initialization_before(
                intent,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .unwrap();
        let runtime = adopt(&fixture, session);
        let current = head(&fixture);
        assert_eq!(current["phase"], "RestoreCurrent");
        assert_eq!(current["revision"], 3);
        assert_eq!(current["previousDigest"], digest.as_str());
        for unchanged in [
            "operationId",
            "epoch",
            "profileDigest",
            "closureEvidence",
            "switchReadback",
        ] {
            assert_eq!(
                current["data"][unchanged], original["data"][unchanged],
                "{unchanged}"
            );
        }
        assert_eq!(current["data"]["binding"]["nativeVersion"], latest);
        assert_ne!(current["data"]["publishIntent"]["contextId"], SITE);
        drop(runtime);
        let reader = super::RecoveryControl::open(fixture.config()).unwrap();
        fixture.open_local(&reader).expect("both journals check");

        // Synthetic republications, each in its own site: one field changed → refused.
        let case = |edit: &dyn Fn(&mut Value, &mut Vec<super::journal::JournalData>)| -> Result<super::RecoveryRuntimeOwner, super::RecoveryControlError> {
            let fixture = RestoreEntryFixture::new();
            let control = super::RecoveryControl::open(fixture.config()).unwrap();
            let replaced = publish_current(&fixture, &control, below);
            let original = head(&fixture);
            let [intent, observed] = confirmed_stage(super::journal::Stage::OrdinaryVerify);
            let mut entries = vec![adoption_intent(&replaced), intent, observed];
            let mut data = original["data"].clone();
            data["binding"]["nativeVersion"] = json!(latest);
            edit(&mut data, &mut entries);
            publish_synthetic(&control, ADOPTION, EPOCH, entries, |_, position| {
                let mut data = data;
                data["publishIntent"] = position;
                descriptor(3, &replaced, "RestoreCurrent", data)
            });
            let reader = super::RecoveryControl::open(fixture.config()).unwrap();
            let result = fixture.open_local(&reader);
            drop(fixture);
            result
        };
        case(&|_, _| ()).expect("the unchanged synthetic republication is accepted");
        type CorruptPublication = dyn Fn(&mut Value, &mut Vec<super::journal::JournalData>);
        let refused: [(&str, &CorruptPublication); 6] = [
            ("operationId", &|data, _| {
                data["operationId"] = json!("abcdefabcdefabcdefabcdefabcdef09")
            }),
            ("epoch", &|data, _| {
                data["epoch"] = json!(EPOCH.replace('1', "5"))
            }),
            ("closureEvidence", &|data, _| {
                data["closureEvidence"][0]["digest"] = json!(REPLACED)
            }),
            ("switchReadback", &|data, _| {
                data["switchReadback"]["digest"] = json!(REPLACED)
            }),
            ("priorActivationDigest", &|_, entries| {
                entries[0] = adoption_intent(REPLACED)
            }),
            ("missing ordinary_verify", &|_, entries| entries.truncate(1)),
        ];
        for (name, edit) in refused {
            assert!(case(edit).is_err(), "{name}");
        }
        // publishIntent naming the restore operation with a new version is refused.
        let fixture = RestoreEntryFixture::new();
        let control = super::RecoveryControl::open(fixture.config()).unwrap();
        publish_current(&fixture, &control, below);
        let path = fixture.control_root().join("activation-v1");
        let mut changed = head(&fixture);
        changed["data"]["binding"]["nativeVersion"] = json!(latest);
        let bytes = canonical_descriptor(changed);
        std::fs::write(&path, bytes).unwrap();
        assert!(
            fixture.open_local(&control).is_err(),
            "a rewritten head has no publication"
        );
    }

    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    mod harness {
        use crate as openbot_infra;
        include!("../../../test-support/postgres_harness.rs");
    }

    /// Server site of T046-48: configuration, optional intent and control root.
    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    struct ServerSite {
        directory: std::path::PathBuf,
    }

    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    impl Drop for ServerSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    impl ServerSite {
        const DEP: &'static str = "below-latest-deployment";
        const TENANT: &'static str = "below-latest-tenant";

        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let directory = std::env::current_dir()
                .unwrap()
                .join(format!(".server-046-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory }
        }

        fn kek(bytes: [u8; 32]) -> crate::auth::config::KeyEncryptionKey {
            use base64::Engine as _;
            let env: crate::auth::config::EnvMap = [(
                "KEY_ENCRYPTION_KEY".to_owned(),
                base64::engine::general_purpose::STANDARD.encode(bytes),
            )]
            .into_iter()
            .collect();
            crate::auth::config::KeyEncryptionKey::from_env_map(
                &env,
                crate::auth::config::ExampleKeyPolicy::Reject,
            )
            .unwrap()
        }

        async fn configure(&self, pool: &crate::db::pool::DatabasePool, mode: &str) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let row = pool.get().await.unwrap().query_one(
                "SELECT pcs.system_identifier::text AS system, d.oid AS oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()", &[]).await.unwrap();
            let system: String = row.get("system");
            let oid: u32 = row.get("oid");
            let (intent, config) = (self.directory.join("intent"), self.directory.join("config"));
            let _ = std::fs::remove_file(&intent);
            let _ = std::fs::remove_file(&config);
            let bytes = serde_json::to_vec(&json!({
                "version": 1, "controlRoot": self.directory.join("control"),
                "hostLimits": {"maxRequestBytes": 65536, "maxActivationBytes": 65536, "maxJournalFrameBytes": 65536,
                    "maxJournalBytes": 1 << 20, "maxJournalRecords": 64, "maxRuntimeRecordBytes": 65536,
                    "maxRegisteredRuntimes": 8, "maxRetainedOperations": 8, "maxRootEntries": 64, "maxTempEntries": 8,
                    "maxEvidenceRefs": 16, "maxRuntimeResourceFacts": 16, "maxIdBytes": 128, "maxComponentBytes": 128,
                    "maxRelativePathBytes": 8192, "maxPathDepth": 128, "maxOpenFiles": 4096, "maxMetadataBytes": 1 << 24,
                    "admissionNs": 30_000_000_000u64},
                "ordinaryStartupBounds": {"effectNs": 60_000_000_000u64, "convergenceNs": 30_000_000_000u64},
                "expectedServiceOwner": {"uid": rustix::process::getuid().as_raw(), "service": "openbot-test"},
                "expectedInstallationBinding": {"deploymentId": Self::DEP, "tenantId": Self::TENANT, "datasetId": CONTROL,
                    "sourceInstallationId": "server-source", "targetInstallationId": "server-target"},
                "expectedServerDatabase": {"pgSystemId": system.parse::<u64>().unwrap(), "databaseOid": oid, "pgMajor": 17},
                "optionalStartupIntent": {"mode": mode, "intentFile": intent},
            })).unwrap();
            std::fs::write(&config, &bytes).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            let meta = std::fs::metadata(&config).unwrap();
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).unwrap();
            let request = serde_json::to_vec(&json!({"formatVersion": 1, "requestId": digest_hex(&Sha256::digest(id).into())[..32],
                "mode": mode, "serviceConfig": {"file": {"device": meta.dev(), "inode": meta.ino(), "uid": meta.uid()},
                "length": meta.len(), "digest": digest_hex(&Sha256::digest(&bytes).into())}})).unwrap();
            std::fs::write(&intent, request).unwrap();
            std::fs::set_permissions(&intent, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn control(&self) -> super::RecoveryControl {
            let host =
                super::load_service_recovery_host_from_config(&self.directory.join("config"))
                    .unwrap();
            let limits = host.host_limits().clone();
            super::RecoveryControl::open(
                super::RecoveryControlConfig::server(host, limits).unwrap(),
            )
            .unwrap()
        }

        async fn start(
            &self,
            database: &crate::db::pool::DatabaseConfig,
            key: [u8; 32],
        ) -> Result<
            (crate::db::pool::DatabasePool, super::RecoveryRuntimeOwner),
            super::RecoveryControlError,
        > {
            self.control()
                .open_server_before(
                    database,
                    &Self::kek(key),
                    &openbot_contracts::ids::DeploymentId::new(Self::DEP),
                    &openbot_contracts::ids::TenantId::new(Self::TENANT),
                    &[super::RuntimeOwner::RunRelay],
                )
                .await
        }

        fn head(&self) -> Value {
            serde_json::from_slice(
                &std::fs::read(self.directory.join("control").join("activation-v1")).unwrap(),
            )
            .unwrap()
        }

        fn operations(&self) -> usize {
            std::fs::read_dir(self.directory.join("control").join("operations"))
                .unwrap()
                .count()
        }

        /// Republish the latest Fresh head at the strict-prior version through
        /// the private codec, as an earlier binary would have published it.
        async fn below_latest(&self, pool: &crate::db::pool::DatabasePool) -> String {
            let head = self.head();
            let replaced = {
                let record: ActivationRecord = serde_json::from_value(head.clone()).unwrap();
                record.encoded().unwrap().1
            };
            let control_id = head["controlId"].as_str().unwrap().to_owned();
            let epoch = head["data"]["binding"]["authorizationEpoch"]
                .as_str()
                .unwrap()
                .to_owned();
            let fresh = head["data"]["publishIntent"]["contextId"]
                .as_str()
                .unwrap()
                .to_owned();
            let raw = std::fs::read(
                self.directory
                    .join("control")
                    .join("operations")
                    .join(&fresh)
                    .join("journal-v1"),
            )
            .unwrap();
            let length = u32::from_be_bytes(raw[8..12].try_into().unwrap()) as usize;
            let first: Value = serde_json::from_slice(&raw[12..12 + length]).unwrap();
            let host = first["data"]["hostBinding"].clone();
            let older: String = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT checksum FROM openbot_internal.schema_migrations WHERE version=$1",
                    &[&crate::db::native::NATIVE_0052_VERSION],
                )
                .await
                .unwrap()
                .get(0);
            let mut binding = head["data"]["binding"].clone();
            binding["nativeVersion"] = json!(crate::db::native::NATIVE_0052_VERSION);
            binding["migrationDigest"] = json!(older);
            let entries = vec![
                super::journal::JournalData::legacy_adoption(
                    serde_json::from_value(host.clone()).unwrap(),
                    ADOPTION,
                    RecoveryFileIdentity { device: 7, inode: 21, uid: rustix::process::getuid().as_raw() },
                    serde_json::from_value(json!({"siteKind": "server_database", "serviceConfig": host["serviceConfig"],
                        "expectedServerDatabase": {"pgSystemId": host["serverDatabase"]["pgSystemId"],
                            "databaseOid": host["serverDatabase"]["databaseOid"], "pgMajor": 17}})).unwrap(),
                    serde_json::from_value(json!({"deploymentId": Self::DEP, "tenantId": Self::TENANT, "datasetId": CONTROL,
                        "sourceInstallationId": "server-source", "targetInstallationId": "server-target"})).unwrap(),
                    serde_json::from_value(json!({"effectNs": 5, "convergenceNs": 9})).unwrap(),
                    &replaced,
                    serde_json::from_value(clock()).unwrap(),
                ),
                super::journal::JournalData::stage_intent(super::journal::Stage::OrdinaryVerify, CONTROL),
                super::journal::JournalData::stage_observed(2, super::journal::Disposition::PgRollback(super::journal::RollbackAck::TimelyAck)),
            ];
            let control = self.control();
            publish_synthetic_in(
                &control,
                &control_id,
                ADOPTION,
                &epoch,
                entries,
                |refs, position| {
                    json!({"recordType": "wrokbot-recovery-activation", "version": 1, "controlId": control_id,
                    "revision": head["revision"].as_u64().unwrap() + 1, "previousDigest": replaced, "phase": "OrdinaryActive",
                    "data": {"binding": binding, "initializationEvidence": [refs[2]], "publishIntent": position}})
                },
            )
        }
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    #[cfg(all(
        feature = "desktop-local",
        feature = "server-runtime",
        target_os = "macos"
    ))]
    async fn t046_48_server_active_below_latest_compares_site_before_upgrade() {
        const KEK: [u8; 32] = [0x42; 32];
        let admin = harness::admin_config("t046_48");
        harness::with_temp_database(&admin, "t046_48", |config| async move {
            let config = config.with_max_pool_size(4);
            let site = ServerSite::new();
            let pool = crate::db::pool::connect(&config)
                .await
                .map_err(|e| e.to_string())?;
            site.configure(&pool, "fresh_init").await;
            let (fresh_pool, mut runtime) = site
                .start(&config, KEK)
                .await
                .map_err(|e| format!("{e:?}"))?;
            // Close the Fresh runtime with its receipt so the writer lock is free.
            // Its only owner never started; the control root keeps the
            // original connection, so no SqlDriver owner is enrolled here.
            fresh_pool.close();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let facts = vec![super::RuntimeCloseFact::PassiveRetirement {
                object: super::PassiveObjectKind::NeverStarted(super::RuntimeOwner::RunRelay),
            }];
            runtime
                .close_before(super::RuntimeCloseResources::new(facts), deadline)
                .await
                .map_err(|e| format!("{e:?}"))?;
            drop(runtime);
            let below = site.below_latest(&pool).await;
            let operations = site.operations();
            // The unchanged configuration has no legacy_adoption intent:
            // InitializationRequired, nothing written.
            let error = site
                .start(&config, KEK)
                .await
                .err()
                .ok_or("below latest without intent")?;
            assert_eq!(error.fault(), RecoveryControlFault::InitializationRequired);
            assert_eq!(site.operations(), operations);
            // A canary under another KEK fails the site comparison before any operation.
            site.configure(&pool, "legacy_adoption").await;
            let error = site
                .start(&config, [0x24; 32])
                .await
                .err()
                .ok_or("another KEK")?;
            assert_eq!(error.fault(), RecoveryControlFault::KeyUnverified);
            assert_eq!(
                site.operations(),
                operations,
                "no adoption operation before the site check"
            );
            // A catalog that is not the latest layout is refused before any operation.
            let client = pool.get().await.map_err(|e| e.to_string())?;
            client
                .batch_execute("ALTER TABLE public.credentials RENAME TO credentials_moved")
                .await
                .map_err(|e| e.to_string())?;
            let refused = site
                .start(&config, KEK)
                .await
                .err()
                .ok_or("catalog mismatch")?;
            client
                .batch_execute("ALTER TABLE public.credentials_moved RENAME TO credentials")
                .await
                .map_err(|e| e.to_string())?;
            drop(client);
            assert_eq!(refused.fault(), RecoveryControlFault::ControlInvalid);
            assert_eq!(
                site.operations(),
                operations,
                "no adoption operation before the layout check"
            );
            // The migrated database with the operator's intent: adopted and republished.
            let (adopted, _runtime) = site
                .start(&config, KEK)
                .await
                .map_err(|e| format!("{e:?}"))?;
            adopted.close();
            let head = site.head();
            assert_eq!(head["phase"], "OrdinaryActive");
            assert_eq!(head["previousDigest"], below.as_str());
            assert_eq!(
                head["data"]["binding"]["nativeVersion"],
                crate::db::native::NATIVE_LATEST_VERSION
            );
            assert_eq!(site.operations(), operations + 1);
            let context = head["data"]["publishIntent"]["contextId"].as_str().unwrap();
            let raw = std::fs::read(
                site.directory
                    .join("control")
                    .join("operations")
                    .join(context)
                    .join("journal-v1"),
            )
            .unwrap();
            let length = u32::from_be_bytes(raw[8..12].try_into().unwrap()) as usize;
            let first: Value = serde_json::from_slice(&raw[12..12 + length]).unwrap();
            assert_eq!(first["data"]["mode"], "legacy_adoption");
            assert_eq!(
                first["data"]["initializingDescriptorDigest"],
                below.as_str()
            );
            // The republished head binds the edited configuration: the same
            // service starts again on it.
            let (again, _second) = site
                .start(&config, KEK)
                .await
                .map_err(|e| format!("{e:?}"))?;
            again.close();
            pool.close();
            Ok(())
        })
        .await;
    }

    /// One real restore driven by the real producers to a published
    /// RestoreCurrent on an owned PostgreSQL 17.11 target, then reopened as
    /// the Local runtime with the target's pool bound to its read gate. The
    /// cohort is the published operation's, so it names that target's own
    /// `restore_pg_operations` row (requirement and receipt rows have FKs).
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    pub(crate) mod restore_current {
        use super::RestoreEntryFixture;
        use crate::backup::whole_pg_restore_stream::candidate_fixture::OwnedCandidate;
        use crate::backup::whole_pg_restore_stream::{
            RestoreCandidateExit, RestoredClosedHistoryRequest,
        };
        use crate::recovery_control::RestoreCapacityResource as Resource;
        use openbot_contracts::recovery::RestoreCohortRef;
        use openbot_domain::vault::SecretBytes;
        use serde_json::json;
        use std::time::{Duration, Instant};

        /// Fields drop in order: the runtime closes its gate before the
        /// target stops and the fixture directory goes.
        pub(crate) struct RestoreCurrentFixture {
            pub(crate) runtime: crate::recovery_control::RecoveryRuntimeOwner,
            pub(crate) pool: crate::db::pool::DatabasePool,
            pub(crate) cohort: RestoreCohortRef,
            /// MetadataBytes admitted after the candidate SQL, after both
            /// slots, after the SCRAM change, after the readback, and after
            /// the publication.
            pub(crate) metadata: [u64; 5],
            _control: crate::recovery_control::RecoveryControl,
            _pg: OwnedCandidate,
            fixture: RestoreEntryFixture,
        }

        impl RestoreCurrentFixture {
            /// `seed` is SQL the source applies after its native layout, then
            /// `source` writes through a pool on the source; both precede the
            /// restore's claim, retirement and publication.
            pub(crate) async fn publish(
                seed: &str,
                source: impl AsyncFnOnce(&crate::db::pool::DatabasePool),
            ) -> Self {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut fixture = RestoreEntryFixture::new();
                let capacity = &mut fixture.profile.capacity;
                capacity.max_pg_connections = 65;
                capacity.max_pg_transactions = 64;
                capacity.max_pg_rows = 1 << 20;
                capacity.max_reconfirm_requirements = 4096;
                // The selected generation is the app-data root Local starts from.
                let mut request = fixture.request();
                request["trustedInputSelection"]["target"]["component"] = json!("old-app");
                let (mut control, intent) = fixture.open_request(request);
                let mut session = control
                    .claim_restore(intent, fixture.profile.clone())
                    .unwrap();
                let operation = session.operation_id().to_owned();
                let epoch = super::head(&fixture)["data"]["epoch"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let root = fixture.directory.join("old-app");
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .unwrap();
                let mut pg = OwnedCandidate::start_at(
                    crate::db::native::NATIVE_LATEST_VERSION,
                    seed,
                    Some(root.join("data")),
                )
                .await;
                let pool = crate::db::pool::connect_config(
                    pg.config("openbot"),
                    2,
                    Duration::from_secs(5),
                    "restore source",
                )
                .await
                .unwrap();
                source(&pool).await;
                pool.close();
                drop(pool);
                let master = SecretBytes::new(vec![0x41; 32]);
                let old = pg.scram();
                let deadline = Instant::now() + Duration::from_secs(25);
                session
                    .bind_candidate_from_source_before(
                        (Some(pg.pid()), pg.identity()),
                        &pg.uds(),
                        (pg.system_identifier.clone(), pg.database_oid),
                        (&old, &master),
                        &std::fs::File::open(&root).unwrap(),
                        deadline,
                    )
                    .await
                    .unwrap();
                session
                    .upgrade_candidate_schema_before(deadline)
                    .await
                    .unwrap();
                session.verify_absent_artifacts_for_test(deadline).await;
                session.retire_cohort_before(deadline).await.unwrap();
                session
                    .clear_restored_closed_history_before(RestoredClosedHistoryRequest::new(
                        deadline,
                    ))
                    .await
                    .unwrap();
                let ceiling = fixture.profile.capacity.max_metadata_bytes;
                let used = |session: &mut crate::recovery_control::RestoreControlSession| {
                    ceiling
                        - session
                            .input_stages()
                            .capacity_available(Resource::MetadataBytes)
                            .unwrap()
                };
                let mut metadata = [used(&mut session), 0, 0, 0, 0];
                // The Desktop slot adapter's part: both fixed pairs written
                // and read back by the store, then observed as matched.
                let mut random = [0_u8; 32];
                getrandom::fill(&mut random).unwrap();
                let new = SecretBytes::new(
                    random
                        .iter()
                        .flat_map(|b| format!("{b:02x}").into_bytes())
                        .collect(),
                );
                for kind in [
                    super::super::entry::TargetSlotKind::Master,
                    super::super::entry::TargetSlotKind::Scram,
                ] {
                    session
                        .begin_target_slot_from_session_before(deadline, kind)
                        .unwrap();
                    match kind {
                        super::super::entry::TargetSlotKind::Master => session
                            .observe_restore_master_slot_before(
                                super::super::RestoreTargetSlotOutcome::ReadbackMatched,
                                deadline,
                            ),
                        super::super::entry::TargetSlotKind::Scram => session
                            .observe_restore_scram_slot_before(
                                super::super::RestoreTargetSlotOutcome::ReadbackMatched,
                                deadline,
                            ),
                    }
                    .unwrap();
                }
                metadata[1] = used(&mut session);
                let scram = session
                    .rotate_candidate_scram_before(&new, &old, deadline)
                    .await
                    .unwrap();
                metadata[2] = used(&mut session);
                let readbacks = session
                    .verify_target_installation_before(&master, &new, deadline)
                    .await
                    .unwrap();
                metadata[3] = used(&mut session);
                let startup = wrok_bot_macos_process::ProcessIdentity::capture(pg.pid())
                    .unwrap()
                    .evidence_bytes()
                    .unwrap();
                // The production stop order: release, one TERM, then wait.
                session.release_candidate_before(deadline).await.unwrap();
                let status = pg.terminate().await;
                let exit = RestoreCandidateExit {
                    pid: u32::from_be_bytes(startup[..4].try_into().unwrap()),
                    start: super::super::ProcessStart {
                        seconds: u64::from_be_bytes(startup[4..12].try_into().unwrap()),
                        nanos: u32::from_be_bytes(startup[12..16].try_into().unwrap()) * 1000,
                    },
                    exit: super::super::NativeExit::Code {
                        value: status.code().unwrap(),
                    },
                    observed_ns: super::super::clock::monotonic_ns().unwrap(),
                    pipes: [
                        super::super::PipeJoin::Null,
                        super::super::PipeJoin::Null,
                        super::super::PipeJoin::Null,
                    ],
                };
                session
                    .publish_restore_current_before(scram, readbacks, exit, deadline)
                    .await
                    .unwrap();
                metadata[4] = used(&mut session);
                drop(session);
                drop(control);
                pg.restart(&new).await;
                let control = super::super::RecoveryControl::open(fixture.config()).unwrap();
                let runtime = fixture.open_local(&control).unwrap();
                let mut config = tokio_postgres::Config::new();
                config
                    .host_path(pg.uds())
                    .port(5432)
                    .user("desktop_admin")
                    .dbname(crate::db::desktop_local::APPLICATION_DATABASE)
                    .password(new.expose());
                let pool = crate::db::pool::connect_config(
                    config,
                    4,
                    Duration::from_secs(10),
                    "restored target",
                )
                .await
                .unwrap();
                // The restored Local binding route is the next batch; the
                // gate is bound to the same pool its verification would bind.
                super::super::entry::lock(&control.shared)
                    .unwrap()
                    .bind_original_local_pool(&pool);
                let cohort = RestoreCohortRef {
                    operation_id: super::super::hex_array(&operation),
                    epoch: super::super::hex_array(&epoch),
                };
                Self {
                    runtime,
                    pool,
                    cohort,
                    metadata,
                    _control: control,
                    _pg: pg,
                    fixture,
                }
            }

            pub(crate) fn read_gate(&self) -> crate::recovery_control::RecoveryReadGate {
                self.runtime.read_gate()
            }

            /// The key `purpose` derives from `parent` under the pre-restore
            /// binding: the same deployment and tenant, only its own epoch.
            #[cfg(feature = "server-runtime")]
            pub(crate) fn old_epoch_key(
                purpose: crate::recovery_control::AuthorizationPurpose,
                parent: &[u8],
            ) -> SecretBytes {
                super::super::runtime::authorization_key(
                    &serde_json::from_value(super::binding()).unwrap(),
                    purpose,
                    parent,
                )
            }

            /// One receipt for `requirement`, through the receipt insert
            /// guard every producer's INSERT passes.
            pub(crate) async fn confirm(
                &self,
                requirement: uuid::Uuid,
                owner: &str,
                proof_kind: &str,
            ) {
                let inserted = self.pool.get().await.unwrap().execute(
                    "INSERT INTO openbot_internal.restore_reconfirm_receipts(operation_id,epoch,requirement_id,confirmation_id,proof_ref,confirmed_by,proof_kind)
                     VALUES($1,$2,$3,$4,$5,$6,$7)",
                    &[&uuid::Uuid::from_bytes(self.cohort.operation_id), &self.cohort.epoch.as_slice(), &requirement,
                      &uuid::Uuid::now_v7(), &uuid::Uuid::now_v7(), &owner, &proof_kind],
                ).await.unwrap();
                assert_eq!(inserted, 1);
            }
        }

        #[tokio::test]
        #[ignore = "requires OPENBOT_TEST_PG_BIN PostgreSQL 17.11 for an owned candidate"]
        async fn restore_current_fixture_publishes_one_cohort_and_gates_its_pool() {
            let restored = RestoreCurrentFixture::publish("", async |_| {}).await;
            eprintln!(
                "restore fixture MetadataBytes admitted: candidate SQL {}, slots {}, SCRAM change {}, readback {}, publication {}",
                restored.metadata[0],
                restored.metadata[1],
                restored.metadata[2],
                restored.metadata[3],
                restored.metadata[4]
            );
            let gate = restored.read_gate();
            assert!(gate.matches_pool(&restored.pool));
            let deadline = Instant::now() + Duration::from_secs(10);
            let lease = gate.borrow_worker_before(deadline).await.unwrap();
            assert_eq!(lease.restore_cohort(), Some(restored.cohort));
            drop(lease);
            let row = restored.pool.get().await.unwrap().query_one(
                "SELECT count(*)::bigint FROM openbot_internal.restore_pg_operations o JOIN openbot_internal.restore_pg_seals s USING(operation_id,epoch) WHERE o.operation_id=$1 AND o.epoch=$2",
                &[&uuid::Uuid::from_bytes(restored.cohort.operation_id), &restored.cohort.epoch.as_slice()],
            ).await.unwrap();
            assert_eq!(
                row.get::<_, i64>(0),
                1,
                "the published cohort is the target's sealed operation"
            );
            let head = super::head(&restored.fixture);
            assert_eq!(head["phase"], "RestoreCurrent");
        }
    }
}
