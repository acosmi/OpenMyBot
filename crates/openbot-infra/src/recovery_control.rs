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
pub use journal::{NativeExit, PipeJoin, ProcessStart};
pub(crate) use activation::{Hex32, ServerDatabaseSite};
pub use entry::{
    OwnedRecoveryRequestFile, OwnedRestoreCandidatePlan, RecoveryRequestExpected, RecoveryRequestPurpose, RestoreControlSession, VerifiedRecoveryHost, VerifiedRecoveryHostIntent,
    VerifiedServiceRecoveryHost, load_service_recovery_host_from_config,
};
pub(crate) use ordinary::OrdinaryStage;
pub(crate) use entry::{RestoreStageIntent, RestoreStages};
pub(crate) use journal::{Stage as RestoreStage, Disposition as RestoreDisposition, CommitAck as RestoreCommitAck, RollbackAck as RestoreRollbackAck};
pub use ordinary::{
    LocalFreshProof, OrdinaryActivationProof, OrdinaryDatabaseInitializationProof, OrdinaryInitializationSession,
    VerifiedOrdinaryLegacyProof, VerifiedOrdinaryStartupIntent,
};
#[cfg(feature = "server-runtime")]
pub use runtime::AuthorizationPurpose;
pub(crate) use runtime::RecoveryWorkerLease;
pub use runtime::{
    PassiveObjectKind, RecoveryReadGate, RecoveryRuntimeOwner, RuntimeCloseFact,
    RuntimeCloseReceipt, RuntimeCloseResources, RuntimeOwner, RuntimePgAck, RuntimeTaskOutcome,
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
    original_json_error: Option<serde_json::Error>,
    unconsumed: Option<Box<VerifiedOrdinaryStartupIntent>>,
    retained_host: Option<Box<VerifiedRecoveryHost>>,
    retained_request: Option<Box<entry::RequestOpenOwner>>,
    retained_restore_input: Option<Box<OwnedRecoveryRequestFile>>,
}

impl RecoveryControlError {
    pub(crate) fn new(fault: RecoveryControlFault) -> Self {
        Self {
            fault,
            retained: None,
            original_json_error: None,
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            retained_restore_input: None,
        }
    }

    fn with_owner(fault: RecoveryControlFault, owner: &entry::ControlOwner) -> Self {
        Self {
            fault,
            retained: Some(Arc::clone(owner)),
            original_json_error: None,
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            retained_restore_input: None,
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
            unconsumed: None,
            retained_host: None,
            retained_request: None,
            retained_restore_input: None,
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
            .field("retains_original_owner", &(self.retained.is_some() || self.retained_host.is_some() || self.retained_request.is_some()))
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
pub enum RestoreNewChildKind { Directory, File }

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

    fn settle_prepaid_observation(&mut self, resource: RestoreCapacityResource, reserved: u64, observed: u64) -> Result<(), RecoveryControlError> {
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
        if observed > reserved
            || actual.is_none()
            || admitted.is_none()
            || admitted.is_some_and(|n| n > self.ceiling(resource))
        {
            self.fault
                .get_or_insert(RecoveryControlFault::CapacityExceeded);
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        } else {
            self.actual[index] = actual.expect("checked actual addition");
            self.admitted[index] = admitted.expect("checked reserved settlement");
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
                self.inodes
                .try_reserve_exact(1)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
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
            let request = original_request.as_ref().expect("original request retained");
            let (host_bytes, host_files) = host.retained_usage()?;
            let (request_bytes, request_files) = request.retained_usage()?;
            let usage = (host_bytes.checked_add(request_bytes), host_files.checked_add(request_files));
            let (Some(bytes), Some(files)) = usage else { return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)); };
            let mut config = RecoveryControlConfig::local(actual, host.trusted_limits().clone())?;
            config.preheld_restore_usage = Some((bytes, files));
            config.original_admission_deadline = Some(deadline);
            before(deadline)?;
            let control = Self::open(config)?;
            let intent = control.verify_host_intent_before(
                original_request.take().expect("original request moved once"),
                original_host.take().expect("original host moved once"),
                deadline,
            )?;
            Ok((control, intent))
        })();
        result.map_err(|mut error: RecoveryControlError| {
            error.retained_host = original_host.take().map(Box::new);
            error.retained_restore_input = original_request.take().map(Box::new);
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

    /// Ordinary Server startup (S8). One clock read seals the entry intent;
    /// an existing latest head is checked under SH, otherwise the handed-back
    /// intent takes the exclusive writer for Fresh, legacy adoption or a
    /// native upgrade. The returned Pool is the bootstrap Pool of this site.
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
                let owner = ordinary::enroll(&self.shared, published, &intent)?;
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
                entry::adopt_server_legacy_before(&self.shared, &mut session, &pool, configured)
                    .await?;
            }
            Some(_) => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
            None => {
                let binding = session
                    .held_binding()
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
                    .clone();
                let client = pool
                    .get()
                    .await
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
                entry::compare_server_site_before(
                    &client, &binding, database, configured, &dataset, effect,
                )
                .await?;
                drop(client);
                session.upgrade_native_before(&pool).await?;
            }
        }
        let owner = session.into_runtime_before()?;
        Ok((pool, owner))
    }

    /// Shared-lock ordinary startup: a published head at the latest native
    /// version enrolls this runtime; otherwise `InitializationRequired`, with
    /// the intent handed back where the exclusive writer is the next step.
    #[cfg(feature = "desktop-local")]
    pub fn open_local_before(
        &self,
        creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
        release: [u8; 32],
        services: [&str; 2],
        bounds: OrdinaryStartupBounds,
        owners: &[RuntimeOwner],
    ) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        let result = (|| {
            let intent = entry::local_intent(&self.shared, creator, release, services, bounds, owners)?;
            let admission = intent.admission_deadline();
            let (published, intent) = ordinary::shared_local_head(&self.shared, intent, admission, creator)?;
            ordinary::enroll(&self.shared, published, &intent)
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
