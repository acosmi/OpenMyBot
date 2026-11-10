//! Fixed WBRCJ001 frames and closed DATA. A hash chain is not a fresh proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::activation::{
    ActivationBinding, ActivationPhase, CandidatePlan, ExpectedServerDatabase, HostBinding,
    JournalReference, OrdinaryStartupBounds, PlannedInstallation, ServiceConfigRef,
};
use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, RequiredNullable,
    RestoreOperationProfile, TrustedHostRecoveryLimits, hex, id,
};

const MAGIC: &[u8; 8] = b"WBRCJ001";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessStart {
    /// Original operating-system process-birth seconds.
    pub seconds: u64,
    /// Original process-birth nanoseconds within the second.
    pub nanos: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OwnerClockRecord {
    pub(super) clock_kind: String,
    pub(super) boot_identity: String,
    pub(super) pid: u32,
    pub(super) process_start: ProcessStart,
    pub(super) owner_nonce: String,
    pub(super) t0_ns: u64,
    pub(super) effect_deadline_ns: u64,
    pub(super) convergence_deadline_ns: u64,
}
impl OwnerClockRecord {
    pub(super) fn validate(
        &self,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        id(&self.boot_identity, l.max_id_bytes)?;
        hex(&self.owner_nonce, 32, true)?;
        if self.clock_kind != "CLOCK_MONOTONIC"
            || self.pid == 0
            || self.process_start.nanos >= 1_000_000_000
            || self.effect_deadline_ns <= self.t0_ns
            || self.convergence_deadline_ns <= self.effect_deadline_ns
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FileInput {
    pub(super) file: RecoveryFileIdentity,
    pub(super) length: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InputIdentities {
    pub(super) carrier: FileInput,
    pub(super) key_medium: FileInput,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Business {
    pub(super) deployment_id: String,
    pub(super) tenant_id: String,
    pub(super) dataset_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RestoreIntent {
    pub(super) profile: RestoreOperationProfile,
    pub(super) input_identities: InputIdentities,
    pub(super) business: Business,
    pub(super) source_installation_id: String,
    pub(super) target_installation_id: String,
    pub(super) candidate_plan: CandidatePlan,
    pub(super) owner_clock: OwnerClockRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreshIntent {
    host_binding: HostBinding,
    original_startup_intent: String,
    planned_installation: PlannedInstallation,
    ordinary_startup_bounds: OrdinaryStartupBounds,
    initializing_descriptor_digest: String,
    original_clock_relation: OwnerClockRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "siteKind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum SiteSelection {
    LocalPhysical {
        trusted_parent: RecoveryFileIdentity,
        entry_component: String,
    },
    ServerDatabase {
        service_config: ServiceConfigRef,
        expected_server_database: ExpectedServerDatabase,
    },
}
impl SiteSelection {
    fn validate_host(
        &self,
        host: &HostBinding,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        host.validate(l)?;
        match (self, host) {
            (
                Self::LocalPhysical {
                    trusted_parent,
                    entry_component,
                },
                HostBinding::LocalPhysical {
                    app_data_parent, ..
                },
            ) => {
                trusted_parent.validate()?;
                super::component(entry_component, l)?;
                if trusted_parent != app_data_parent {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            (
                Self::ServerDatabase {
                    service_config,
                    expected_server_database,
                },
                HostBinding::ServerDatabase {
                    service_config: actual_config,
                    server_database,
                    ..
                },
            ) => {
                service_config.validate()?;
                if service_config != actual_config
                    || !expected_server_database.matches(server_database)
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BusinessAndInstallation {
    pub(super) deployment_id: String,
    pub(super) tenant_id: String,
    pub(super) dataset_id: String,
    pub(super) source_installation_id: String,
    pub(super) target_installation_id: String,
}
impl BusinessAndInstallation {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        for value in [
            &self.deployment_id,
            &self.tenant_id,
            &self.dataset_id,
            &self.source_installation_id,
            &self.target_installation_id,
        ] {
            id(value, l.max_id_bytes)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyIntent {
    host_binding: HostBinding,
    original_startup_intent: String,
    owned_intent_file_identity: RecoveryFileIdentity,
    original_site_selection: SiteSelection,
    expected_original_business_and_installation: BusinessAndInstallation,
    ordinary_startup_bounds: OrdinaryStartupBounds,
    initializing_descriptor_digest: String,
    original_clock_relation: OwnerClockRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum OperationIntent {
    Restore(RestoreIntent),
    FreshInit(FreshIntent),
    LegacyAdoption(LegacyIntent),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Import,
    Isolation,
    PgUpgrade,
    Retire,
    Reconfirm,
    KeySlot,
    ScramChange,
    HqAck2,
    Switch,
    Publish,
    ResourceClose,
    OrdinaryInitialize,
    OrdinaryVerify,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum CommitAck {
    TimelyAck,
    AcknowledgedAfterDeadline,
    CommitUnknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RollbackAck {
    TimelyAck,
    AcknowledgedAfterDeadline,
    RollbackUnproven,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub enum NativeExit {
    Code { value: i32 },
    Signal { value: i32 },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub enum PipeJoin {
    Returned { observed_ns: u64 },
    Panicked { observed_ns: u64 },
    JoinUnknown,
    Null,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(crate) enum Disposition {
    PgCommit(CommitAck),
    PgRollback(RollbackAck),
    NativeWait {
        original_program_id: String,
        original_pid: u32,
        original_start_identity: ProcessStart,
        exit_code_or_signal: NativeExit,
        observed_ns: u64,
        pipes: [PipeJoin; 3],
    },
    NativeWaitUnknown {
        original_program_id: String,
        original_pid: u32,
        original_start_identity: ProcessStart,
    },
    TaskReturned {
        original_task_id: String,
        observed_ns: u64,
    },
    TaskPanicked {
        original_task_id: String,
        observed_ns: u64,
    },
    TaskJoinUnknown {
        original_task_id: String,
    },
    OsStoreReadbackMatched {
        intent_ref: JournalReference,
        service_ref: String,
        account_ref: String,
        exact_length: u64,
    },
    OsStoreWriteUnknown {
        intent_ref: JournalReference,
        service_ref: String,
        account_ref: String,
    },
    OsStoreReadbackUnknown {
        intent_ref: JournalReference,
        service_ref: String,
        account_ref: String,
    },
    FilePublishMatched {
        intent_ref: JournalReference,
        held_file_identity: RecoveryFileIdentity,
        expected_digest: String,
    },
    FilePublishUnknown {
        intent_ref: JournalReference,
    },
    GateClosed {
        class_id: u8,
        exact_inventory_ref: JournalReference,
        original_owner_refs: Vec<String>,
    },
    GateUnknown {
        class_id: u8,
        exact_inventory_ref: JournalReference,
        original_owner_refs: Vec<String>,
    },
    ReadOnlyResult {
        original_intent_ref: JournalReference,
        observed_kind: String,
    },
}

impl Disposition {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        match self {
            Self::PgCommit(_) | Self::PgRollback(_) => (),
            Self::NativeWait {
                original_program_id,
                original_pid,
                original_start_identity,
                observed_ns,
                pipes,
                ..
            } => {
                id(original_program_id, l.max_id_bytes)?;
                if *original_pid == 0
                    || original_start_identity.nanos >= 1_000_000_000
                    || *observed_ns == 0
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
                for pipe in pipes {
                    if matches!(
                        pipe,
                        PipeJoin::Returned { observed_ns: 0 }
                            | PipeJoin::Panicked { observed_ns: 0 }
                    ) {
                        return Err(RecoveryControlError::new(
                            RecoveryControlFault::ControlInvalid,
                        ));
                    }
                }
            }
            Self::NativeWaitUnknown {
                original_program_id,
                original_pid,
                original_start_identity,
            } => {
                id(original_program_id, l.max_id_bytes)?;
                if *original_pid == 0 || original_start_identity.nanos >= 1_000_000_000 {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            Self::TaskReturned {
                original_task_id,
                observed_ns,
            }
            | Self::TaskPanicked {
                original_task_id,
                observed_ns,
            } => {
                id(original_task_id, l.max_id_bytes)?;
                if *observed_ns == 0 {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            Self::TaskJoinUnknown { original_task_id } => id(original_task_id, l.max_id_bytes)?,
            Self::OsStoreReadbackMatched {
                intent_ref,
                service_ref,
                account_ref,
                exact_length,
            } => {
                intent_ref.validate()?;
                id(service_ref, l.max_id_bytes)?;
                id(account_ref, l.max_id_bytes)?;
                if *exact_length == 0 {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            Self::OsStoreWriteUnknown {
                intent_ref,
                service_ref,
                account_ref,
            }
            | Self::OsStoreReadbackUnknown {
                intent_ref,
                service_ref,
                account_ref,
            } => {
                intent_ref.validate()?;
                id(service_ref, l.max_id_bytes)?;
                id(account_ref, l.max_id_bytes)?;
            }
            Self::FilePublishMatched {
                intent_ref,
                held_file_identity,
                expected_digest,
            } => {
                intent_ref.validate()?;
                held_file_identity.validate()?;
                hex(expected_digest, 64, false)?;
            }
            Self::FilePublishUnknown { intent_ref } => intent_ref.validate()?,
            Self::GateClosed {
                class_id,
                exact_inventory_ref,
                original_owner_refs,
            }
            | Self::GateUnknown {
                class_id,
                exact_inventory_ref,
                original_owner_refs,
            } => {
                if !(1..=9).contains(class_id)
                    || original_owner_refs.is_empty()
                    || u64::try_from(original_owner_refs.len())
                        .map_or(true, |n| n > l.max_runtime_resource_facts)
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
                exact_inventory_ref.validate()?;
                for original in original_owner_refs {
                    id(original, l.max_id_bytes)?;
                }
            }
            Self::ReadOnlyResult {
                original_intent_ref,
                observed_kind,
            } => {
                original_intent_ref.validate()?;
                id(observed_kind, l.max_id_bytes)?;
            }
        }
        Ok(())
    }

    fn confirms_effect(&self) -> bool {
        match self {
            Self::PgCommit(CommitAck::TimelyAck | CommitAck::AcknowledgedAfterDeadline)
            | Self::PgRollback(RollbackAck::TimelyAck | RollbackAck::AcknowledgedAfterDeadline)
            | Self::TaskReturned { .. }
            | Self::OsStoreReadbackMatched { .. }
            | Self::FilePublishMatched { .. }
            | Self::GateClosed { .. } => true,
            Self::NativeWait {
                exit_code_or_signal: NativeExit::Code { value: 0 },
                pipes,
                ..
            } => pipes
                .iter()
                .all(|p| matches!(p, PipeJoin::Returned { .. } | PipeJoin::Null)),
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum PublicationDisposition {
    FileAndParentSyncedReadback,
    DurabilityUnknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StageIntent {
    stage: Stage,
    original_effect_id: String,
    expected_binding: RequiredNullable<ActivationBinding>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StageObserved {
    intent_sequence: u64,
    typed_disposition: Disposition,
    actual_binding: RequiredNullable<ActivationBinding>,
    receipt_refs: Vec<JournalReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishIntent {
    expected_phase: ActivationPhase,
    descriptor_digest: String,
    receipt_refs: Vec<JournalReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishObserved {
    intent_sequence: u64,
    descriptor_digest: String,
    actual_file_identity: RequiredNullable<RecoveryFileIdentity>,
    disposition: PublicationDisposition,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadOnlyObservation {
    original_intent: JournalReference,
    typed_observation: Disposition,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Kind {
    OperationIntent,
    StageIntent,
    StageObserved,
    PublishIntent,
    PublishObserved,
    ReadOnlyObservation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Data {
    Operation(OperationIntent),
    StageIntent(StageIntent),
    StageObserved(StageObserved),
    PublishIntent(PublishIntent),
    PublishObserved(PublishObserved),
    ReadOnly(ReadOnlyObservation),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    record_type: String,
    version: u32,
    control_id: String,
    operation_id: String,
    epoch: String,
    sequence: u64,
    previous_digest: String,
    kind: Kind,
    data: Data,
}

/// One typed journal entry to append (S5). The envelope is completed by the
/// writer from the held operation tail, never by the caller.
pub(super) struct JournalData {
    kind: Kind,
    data: Data,
}

/// One encoded frame: `WBRCJ001 || L u32BE || JSON || SHA256(domain || NUL || magic || L || JSON)`.
pub(super) struct JournalFrame {
    pub(super) bytes: Vec<u8>,
    pub(super) digest: [u8; 32],
}

impl JournalData {
    pub(super) fn restore(intent: RestoreIntent) -> Self {
        Self {
            kind: Kind::OperationIntent,
            data: Data::Operation(OperationIntent::Restore(intent)),
        }
    }
    pub(super) fn fresh_init(
        host_binding: HostBinding,
        original_startup_intent: &str,
        planned_installation: PlannedInstallation,
        ordinary_startup_bounds: OrdinaryStartupBounds,
        initializing_descriptor_digest: &str,
        original_clock_relation: OwnerClockRecord,
    ) -> Self {
        Self {
            kind: Kind::OperationIntent,
            data: Data::Operation(OperationIntent::FreshInit(FreshIntent {
                host_binding,
                original_startup_intent: original_startup_intent.to_owned(),
                planned_installation,
                ordinary_startup_bounds,
                initializing_descriptor_digest: initializing_descriptor_digest.to_owned(),
                original_clock_relation,
            })),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn legacy_adoption(
        host_binding: HostBinding,
        original_startup_intent: &str,
        owned_intent_file_identity: RecoveryFileIdentity,
        original_site_selection: SiteSelection,
        expected_original_business_and_installation: BusinessAndInstallation,
        ordinary_startup_bounds: OrdinaryStartupBounds,
        initializing_descriptor_digest: &str,
        original_clock_relation: OwnerClockRecord,
    ) -> Self {
        Self {
            kind: Kind::OperationIntent,
            data: Data::Operation(OperationIntent::LegacyAdoption(LegacyIntent {
                host_binding,
                original_startup_intent: original_startup_intent.to_owned(),
                owned_intent_file_identity,
                original_site_selection,
                expected_original_business_and_installation,
                ordinary_startup_bounds,
                initializing_descriptor_digest: initializing_descriptor_digest.to_owned(),
                original_clock_relation,
            })),
        }
    }

    pub(super) fn stage_intent(stage: Stage, original_effect_id: &str) -> Self {
        Self {
            kind: Kind::StageIntent,
            data: Data::StageIntent(StageIntent {
                stage,
                original_effect_id: original_effect_id.to_owned(),
                expected_binding: RequiredNullable::Null(()),
            }),
        }
    }

    pub(super) fn stage_observed(intent_sequence: u64, typed_disposition: Disposition) -> Self {
        Self {
            kind: Kind::StageObserved,
            data: Data::StageObserved(StageObserved {
                intent_sequence,
                typed_disposition,
                actual_binding: RequiredNullable::Null(()),
                receipt_refs: Vec::new(),
            }),
        }
    }

    pub(super) fn publish_intent(expected_phase: ActivationPhase, descriptor_digest: &str) -> Self {
        Self {
            kind: Kind::PublishIntent,
            data: Data::PublishIntent(PublishIntent {
                expected_phase,
                descriptor_digest: descriptor_digest.to_owned(),
                receipt_refs: Vec::new(),
            }),
        }
    }

    pub(super) fn publish_observed(
        intent_sequence: u64,
        descriptor_digest: &str,
        actual_file_identity: RecoveryFileIdentity,
    ) -> Self {
        Self {
            kind: Kind::PublishObserved,
            data: Data::PublishObserved(PublishObserved {
                intent_sequence,
                descriptor_digest: descriptor_digest.to_owned(),
                actual_file_identity: RequiredNullable::Value(actual_file_identity),
                disposition: PublicationDisposition::FileAndParentSyncedReadback,
            }),
        }
    }

    /// Whether this entry is a stage observation that confirms its effect.
    pub(super) fn confirms_effect(&self) -> bool {
        matches!(&self.data, Data::StageObserved(v) if v.typed_disposition.confirms_effect())
    }

    /// Encode this entry with the exact ordered envelope the reader re-encodes.
    pub(super) fn frame(
        &self,
        control_id: &str,
        operation_id: &str,
        epoch: &str,
        sequence: u64,
        previous: Option<&[u8; 32]>,
        limits: &TrustedHostRecoveryLimits,
    ) -> Result<JournalFrame, RecoveryControlError> {
        let record = Record {
            record_type: "wrokbot-recovery-journal".to_owned(),
            version: 1,
            control_id: control_id.to_owned(),
            operation_id: operation_id.to_owned(),
            epoch: epoch.to_owned(),
            sequence,
            previous_digest: previous.map_or_else(|| "0".repeat(64), digest_hex),
            kind: self.kind,
            data: self.data.clone(),
        };
        let json = serde_json::to_vec(&record).map_err(RecoveryControlError::from_json)?;
        let length = u32::try_from(json.len())
            .ok()
            .filter(|n| *n != 0 && u64::from(*n) <= limits.max_journal_frame_bytes)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let mut bytes = Vec::with_capacity(json.len() + 44);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&json);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"wrokbot.restore.journal.v1\0")
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(JournalFrame { bytes, digest })
    }
}

pub(super) fn digest_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for byte in bytes {
        s.push(char::from(HEX[usize::from(byte >> 4)]));
        s.push(char::from(HEX[usize::from(byte & 15)]));
    }
    s
}

pub(super) fn hex_matches(bytes: &[u8; 32], expected: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    expected.len() == 64
        && bytes
            .iter()
            .zip(expected.as_bytes().as_chunks::<2>().0.iter())
            .all(|(byte, pair)| {
                pair[0] == HEX[usize::from(byte >> 4)] && pair[1] == HEX[usize::from(byte & 15)]
            })
}

/// Complete canonical chain observation, held privately with its source FD.
pub(super) struct JournalObservation {
    records: Vec<Record>,
    digests: Vec<[u8; 32]>,
}

/// Not Deserialize and not constructible from a DTO outside this module.
pub(super) struct VerifiedPublication {
    control_id: String,
    descriptor_digest: String,
}
impl VerifiedPublication {
    pub(super) fn matches(
        &self,
        control_id: &str,
        digest: &str,
    ) -> Result<(), RecoveryControlError> {
        if self.control_id != control_id || self.descriptor_digest != digest {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }
}

impl Record {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        if self.record_type != "wrokbot-recovery-journal" || self.version != 1 || self.sequence == 0
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        hex(&self.control_id, 32, true)?;
        hex(&self.operation_id, 32, true)?;
        hex(&self.epoch, 64, true)?;
        hex(&self.previous_digest, 64, false)?;
        match (&self.kind, &self.data) {
            (Kind::OperationIntent, Data::Operation(d)) if self.sequence == 1 => match d {
                OperationIntent::Restore(v) => {
                    v.profile.clone().checked(l)?;
                    v.candidate_plan.validate(l)?;
                    v.input_identities.carrier.file.validate()?;
                    v.input_identities.key_medium.file.validate()?;
                    if v.input_identities.carrier.length == 0
                        || v.input_identities.key_medium.length != 104
                    {
                        return Err(RecoveryControlError::new(
                            RecoveryControlFault::ControlInvalid,
                        ));
                    }
                    for s in [
                        &v.business.deployment_id,
                        &v.business.tenant_id,
                        &v.business.dataset_id,
                        &v.source_installation_id,
                        &v.target_installation_id,
                    ] {
                        id(s, l.max_id_bytes)?;
                    }
                    v.owner_clock.validate(l)?;
                }
                OperationIntent::FreshInit(v) => {
                    hex(&v.original_startup_intent, 32, true)?;
                    hex(&v.initializing_descriptor_digest, 64, false)?;
                    v.host_binding.validate_plan(&v.planned_installation, l)?;
                    v.original_clock_relation.validate(l)?;
                }
                OperationIntent::LegacyAdoption(v) => {
                    hex(&v.original_startup_intent, 32, true)?;
                    hex(&v.initializing_descriptor_digest, 64, false)?;
                    v.owned_intent_file_identity.validate()?;
                    v.original_site_selection
                        .validate_host(&v.host_binding, l)?;
                    if v.owned_intent_file_identity.uid != v.host_binding.owner_uid()? {
                        return Err(RecoveryControlError::new(
                            RecoveryControlFault::ControlInvalid,
                        ));
                    }
                    v.expected_original_business_and_installation.validate(l)?;
                    v.original_clock_relation.validate(l)?;
                }
            },
            (Kind::StageIntent, Data::StageIntent(v)) => {
                // The same bound the stage writer checked: ordinary effects
                // use minted hex IDs, restore stages their fixed effect names.
                id(&v.original_effect_id, l.max_id_bytes)?;
                if let RequiredNullable::Value(b) = &v.expected_binding {
                    b.validate(l)?;
                }
            }
            (Kind::StageObserved, Data::StageObserved(v)) => {
                if v.intent_sequence == 0 || v.intent_sequence >= self.sequence {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
                if let RequiredNullable::Value(b) = &v.actual_binding {
                    b.validate(l)?;
                }
                v.typed_disposition.validate(l)?;
                if u64::try_from(v.receipt_refs.len()).map_or(true, |n| n > l.max_evidence_refs) {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::CapacityExceeded,
                    ));
                }
                for r in &v.receipt_refs {
                    r.validate()?;
                }
            }
            (Kind::PublishIntent, Data::PublishIntent(v)) => {
                hex(&v.descriptor_digest, 64, false)?;
                if u64::try_from(v.receipt_refs.len()).map_or(true, |n| n > l.max_evidence_refs) {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::CapacityExceeded,
                    ));
                }
                for r in &v.receipt_refs {
                    r.validate()?;
                }
            }
            (Kind::PublishObserved, Data::PublishObserved(v)) => {
                hex(&v.descriptor_digest, 64, false)?;
                if v.intent_sequence == 0 || v.intent_sequence >= self.sequence {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
                match (&v.disposition, &v.actual_file_identity) {
                    (
                        PublicationDisposition::FileAndParentSyncedReadback,
                        RequiredNullable::Value(i),
                    ) => i.validate()?,
                    (PublicationDisposition::DurabilityUnknown, RequiredNullable::Null(())) => (),
                    _ => {
                        return Err(RecoveryControlError::new(
                            RecoveryControlFault::ControlInvalid,
                        ));
                    }
                }
            }
            (Kind::ReadOnlyObservation, Data::ReadOnly(v)) => {
                v.original_intent.validate()?;
                v.typed_observation.validate(l)?;
            }
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        Ok(())
    }
}

/// Caller prepays the fixed closed-node/string/vector bound and retains raw
/// bytes/FD before entering this pure parser. No partial/torn prefix is usable.
pub(super) fn observe_chain(
    raw: &[u8],
    limits: &TrustedHostRecoveryLimits,
) -> Result<JournalObservation, RecoveryControlError> {
    if raw.is_empty() || u64::try_from(raw.len()).map_or(true, |n| n > limits.max_journal_bytes) {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    let mut offset = 0usize;
    let mut records: Vec<Record> = Vec::new();
    let mut digests = Vec::new();
    while offset < raw.len() {
        let header_end = offset
            .checked_add(12)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if header_end > raw.len() || raw.get(offset..offset + 8) != Some(MAGIC.as_slice()) {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let len = u32::from_be_bytes(
            raw[offset + 8..header_end]
                .try_into()
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?,
        );
        if len == 0
            || u64::from(len) > limits.max_journal_frame_bytes
            || u64::try_from(records.len()).map_or(true, |n| n >= limits.max_journal_records)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        let body_end =
            header_end
                .checked_add(usize::try_from(len).map_err(|_| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let end = body_end
            .checked_add(32)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if end > raw.len() {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let mut digest = Sha256::new();
        digest.update(b"wrokbot.restore.journal.v1\0");
        digest.update(&raw[offset..body_end]);
        let digest: [u8; 32] = digest.finalize().into();
        if raw[body_end..end] != digest {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let record: Record = serde_json::from_slice(&raw[header_end..body_end])
            .map_err(RecoveryControlError::from_json)?;
        record.validate(limits)?;
        let canonical = serde_json::to_vec(&record).map_err(RecoveryControlError::from_json)?;
        let sequence = u64::try_from(records.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if canonical != raw[header_end..body_end]
            || record.sequence != sequence
            || record.previous_digest != digests.last().map_or_else(|| "0".repeat(64), digest_hex)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        if let Some(first) = records.first() {
            if record.control_id != first.control_id
                || record.operation_id != first.operation_id
                || record.epoch != first.epoch
            {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            if let Data::StageIntent(stage) = &record.data {
                let allowed = match &first.data {
                    Data::Operation(OperationIntent::Restore(_)) => !matches!(
                        stage.stage,
                        Stage::OrdinaryInitialize | Stage::OrdinaryVerify
                    ),
                    Data::Operation(OperationIntent::FreshInit(_)) => matches!(
                        stage.stage,
                        Stage::OrdinaryInitialize
                            | Stage::KeySlot
                            | Stage::Publish
                            | Stage::ResourceClose
                    ),
                    Data::Operation(OperationIntent::LegacyAdoption(_)) => matches!(
                        stage.stage,
                        Stage::OrdinaryVerify
                            | Stage::KeySlot
                            | Stage::Publish
                            | Stage::ResourceClose
                    ),
                    _ => false,
                };
                if !allowed {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            if let Data::StageObserved(observed) = &record.data {
                let index = usize::try_from(observed.intent_sequence - 1)
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
                if !matches!(records.get(index), Some(Record { data: Data::StageIntent(_), .. }))
                    || records.iter().any(|r| matches!(&r.data, Data::StageObserved(v) if v.intent_sequence == observed.intent_sequence))
                {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
            if let Data::PublishObserved(observed) = &record.data {
                let index = usize::try_from(observed.intent_sequence - 1)
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
                if !matches!(records.get(index), Some(Record { data: Data::PublishIntent(v), .. }) if v.descriptor_digest == observed.descriptor_digest)
                    || records.iter().any(|r| matches!(&r.data, Data::PublishObserved(v) if v.intent_sequence == observed.intent_sequence))
                {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
        } else if record.kind != Kind::OperationIntent {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        records.push(record);
        digests.push(digest);
        offset = end;
    }
    Ok(JournalObservation { records, digests })
}

/// Admission for this immutable full frame stream, before serde/Vec growth.
/// Reuses the existing closed JSON accounting for each actual body, not the
/// binary digest bytes. The old full JournalReference shape is unchanged.
pub(super) fn read_metadata_reservation(
    raw: &[u8],
    limits: &TrustedHostRecoveryLimits,
) -> Result<u64, RecoveryControlError> {
    let invalid = || RecoveryControlError::new(RecoveryControlFault::CapacityExceeded);
    let mut total = std::mem::size_of::<JournalObservation>() as u64;
    let mut offset = 0usize;
    let mut records = 0u64;
    while offset < raw.len() {
        let header = offset
            .checked_add(12)
            .filter(|end| *end <= raw.len())
            .ok_or_else(invalid)?;
        if raw.get(offset..offset + 8) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let size =
            u32::from_be_bytes(raw[offset + 8..header].try_into().map_err(|_| invalid())?) as usize;
        let body = header.checked_add(size).ok_or_else(invalid)?;
        let end = body
            .checked_add(32)
            .filter(|end| *end <= raw.len())
            .ok_or_else(invalid)?;
        records = records
            .checked_add(1)
            .filter(|n| *n <= limits.max_journal_records)
            .ok_or_else(invalid)?;
        if size == 0 || size as u64 > limits.max_journal_frame_bytes {
            return Err(invalid());
        }
        let body_fee = super::activation::read_metadata_reservation(&raw[header..body])?
            .checked_mul(2)
            .ok_or_else(invalid)?;
        let fixed = 2 * (std::mem::size_of::<Record>() + std::mem::size_of::<[u8; 32]>());
        total = total
            .checked_add(body_fee)
            .and_then(|n| n.checked_add(fixed as u64))
            .ok_or_else(invalid)?;
        offset = end;
    }
    Ok(total)
}

fn unproven() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::ClosureUnproven)
}

impl JournalObservation {
    /// Match Pending DATA to its actual first RestoreIntent and full reference.
    #[cfg(feature = "desktop-local")]
    pub(super) fn matches_restore_pending(
        &self,
        pending: &super::activation::Pending,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || RecoveryControlError::new(RecoveryControlFault::ControlInvalid);
        let first = self.records.first().ok_or_else(invalid)?;
        let Data::Operation(OperationIntent::Restore(intent)) = &first.data else {
            return Err(invalid());
        };
        let reference = &pending.journal_prefix;
        let old = &intent.owner_clock;
        let shown = &pending.owner_clock;
        let plan = &intent.candidate_plan;
        let selected = &pending.candidate_plan;
        let profile =
            serde_json::to_vec(&intent.profile).map_err(RecoveryControlError::from_json)?;
        let input = serde_json::to_vec(&intent.input_identities)
            .map_err(RecoveryControlError::from_json)?;
        if first.operation_id != pending.operation_id
            || first.epoch != pending.epoch
            || reference.context_id != first.operation_id
            || reference.sequence != 1
            || self.digests.first().map(digest_hex).as_ref() != Some(&reference.digest)
            || !hex_matches(&Sha256::digest(profile).into(), &pending.profile_digest)
            || !hex_matches(&Sha256::digest(input).into(), &pending.input_plan_digest)
            || plan.trusted_parent != selected.trusted_parent
            || plan.entry_component != selected.entry_component
            || plan.installation_id != selected.installation_id
            || plan.generation_id != selected.generation_id
            || old.clock_kind != shown.clock_kind
            || old.boot_identity != shown.boot_identity
            || old.pid != shown.pid
            || old.process_start.seconds != shown.process_start.seconds
            || old.process_start.nanos != shown.process_start.nanos
            || old.owner_nonce != shown.owner_nonce
            || old.t0_ns != shown.t0_ns
            || old.effect_deadline_ns != shown.effect_deadline_ns
            || old.convergence_deadline_ns != shown.convergence_deadline_ns
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn restore_candidate_plan(&self) -> Option<&CandidatePlan> {
        match &self.records.first()?.data {
            Data::Operation(OperationIntent::Restore(intent)) => Some(&intent.candidate_plan),
            _ => None,
        }
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn first_context(&self) -> Option<(&str, &str, &str)> {
        let first = self.records.first()?;
        Some((&first.control_id, &first.operation_id, &first.epoch))
    }
    /// Whether this operation is a restore (its first record's mode).
    pub(super) fn is_restore(&self) -> bool {
        matches!(
            self.records.first(),
            Some(Record {
                data: Data::Operation(OperationIntent::Restore(_)),
                ..
            })
        )
    }

    /// Check the original ordinary operation and actual full-digest evidence
    /// references. Unknown / other-context evidence remains closed.
    pub(super) fn verify_ordinary_evidence(
        &self,
        observation: &super::activation::ActivationObservation,
    ) -> Result<(), RecoveryControlError> {
        let (binding, evidence) = observation.ordinary_active()?;
        let first = self.records.first().ok_or_else(unproven)?;
        if first.epoch != binding.authorization_epoch() {
            return Err(unproven());
        }
        // The operation names the descriptor it replaces: its Initializing
        // head, or the published head a known-site adoption republishes.
        let replaced = match &first.data {
            Data::Operation(OperationIntent::FreshInit(v)) => &v.initializing_descriptor_digest,
            Data::Operation(OperationIntent::LegacyAdoption(v)) => {
                &v.initializing_descriptor_digest
            }
            _ => return Err(unproven()),
        };
        if Some(replaced.as_str()) != observation.record.previous_digest() {
            return Err(unproven());
        }
        self.confirmed(evidence, &first.operation_id)
    }

    /// A RestoreCurrent republished by a known-site adoption:
    /// this publication journal is that LegacyAdoption operation, naming the
    /// replaced head, under the Current epoch, with a confirmed ordinary_verify
    /// before its PublishIntent. The restore journal is checked separately.
    pub(super) fn verify_adopted_current(
        &self,
        observation: &super::activation::ActivationObservation,
    ) -> Result<(), RecoveryControlError> {
        let super::activation::ActivationPayload::Current(current) = observation.record.data()
        else {
            return Err(unproven());
        };
        let first = self.records.first().ok_or_else(unproven)?;
        let Data::Operation(OperationIntent::LegacyAdoption(adoption)) = &first.data else {
            return Err(unproven());
        };
        let publish =
            usize::try_from(current.publish_intent.sequence.get() - 1).map_err(|_| unproven())?;
        let verified = self.records.iter().take(publish).any(|record| {
            matches!(&record.data, Data::StageObserved(observed)
                if observed.typed_disposition.confirms_effect()
                    && matches!(self.records.get(usize::try_from(observed.intent_sequence - 1).unwrap_or(usize::MAX)),
                        Some(Record { data: Data::StageIntent(StageIntent { stage: Stage::OrdinaryVerify, .. }), .. })))
        });
        if first.epoch != current.epoch
            || first.operation_id == current.operation_id
            || Some(adoption.initializing_descriptor_digest.as_str())
                != observation.record.previous_digest()
            || !verified
        {
            return Err(unproven());
        }
        Ok(())
    }

    /// RestoreCurrent evidence comes from its one original restore journal.
    pub(super) fn verify_current_evidence(
        &self,
        observation: &super::activation::ActivationObservation,
    ) -> Result<(), RecoveryControlError> {
        let super::activation::ActivationPayload::Current(current) = observation.record.data()
        else {
            return Err(unproven());
        };
        let restore = self;
        let original = restore.records.first().ok_or_else(unproven)?;
        if original.operation_id != current.operation_id
            || original.epoch != current.epoch
            || !matches!(original.data, Data::Operation(OperationIntent::Restore(_)))
        {
            return Err(unproven());
        }
        restore.confirmed(&current.closure_evidence, &current.operation_id)?;
        let readback = &current.switch_readback;
        let index = usize::try_from(readback.sequence - 1).map_err(|_| unproven())?;
        if readback.context_id != current.operation_id
            || restore.digests.get(index).map(digest_hex).as_ref() != Some(&readback.digest)
        {
            return Err(unproven());
        }
        Ok(())
    }

    /// Every reference names a confirming StageObserved of `context` by digest.
    fn confirmed(
        &self,
        references: &[JournalReference],
        context: &str,
    ) -> Result<(), RecoveryControlError> {
        for reference in references {
            reference.validate()?;
            let index = usize::try_from(reference.sequence - 1).map_err(|_| unproven())?;
            if reference.context_id != context
                || self.digests.get(index).map(digest_hex).as_ref() != Some(&reference.digest)
                || !matches!(self.records.get(index), Some(Record { data: Data::StageObserved(stage), .. }) if stage.typed_disposition.confirms_effect())
            {
                return Err(unproven());
            }
        }
        Ok(())
    }

    /// Read the record at the descriptor's own position and compare its content:
    /// a `PublishIntent` for `phase` naming `descriptor_digest`,
    /// followed by exactly one synced `PublishObserved` for that position.
    /// `OrdinaryInitializing.initJournalPrefix`: the record at that position is
    /// the operation's Fresh or Legacy `OperationIntent` naming this descriptor.
    #[cfg(test)]
    pub(super) fn initializing_prefix_for(
        &self,
        reference: &super::activation::JournalPositionRef,
        descriptor_digest: &str,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || RecoveryControlError::new(RecoveryControlFault::ControlInvalid);
        let index = usize::try_from(reference.sequence.get() - 1).map_err(|_| invalid())?;
        let record = self.records.get(index).ok_or_else(invalid)?;
        let named = match &record.data {
            Data::Operation(OperationIntent::FreshInit(v)) => &v.initializing_descriptor_digest,
            Data::Operation(OperationIntent::LegacyAdoption(v)) => {
                &v.initializing_descriptor_digest
            }
            _ => return Err(invalid()),
        };
        if record.kind != Kind::OperationIntent
            || record.operation_id != reference.context_id.as_str()
            || named != descriptor_digest
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn publication_for(
        &self,
        control_id: &str,
        descriptor_digest: &str,
        reference: &super::activation::JournalPositionRef,
        actual_file: RecoveryFileIdentity,
        phase: ActivationPhase,
    ) -> Result<VerifiedPublication, RecoveryControlError> {
        let original = self
            .records
            .first()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        if original.control_id != control_id
            || original.operation_id != reference.context_id.as_str()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let index = usize::try_from(reference.sequence.get() - 1)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        let Some(Record {
            kind: Kind::PublishIntent,
            data: Data::PublishIntent(intent),
            ..
        }) = self.records.get(index)
        else {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        };
        if intent.expected_phase != phase || intent.descriptor_digest != descriptor_digest {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let observed = self.records.iter().filter(|r| matches!(&r.data,
            Data::PublishObserved(v) if v.intent_sequence == reference.sequence.get()
                && v.descriptor_digest == descriptor_digest
                && matches!(v.disposition, PublicationDisposition::FileAndParentSyncedReadback)
                && matches!(v.actual_file_identity, RequiredNullable::Value(i) if i == actual_file)
        )).count();
        if observed != 1 {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ClosureUnproven,
            ));
        }
        for r in &self.records {
            let matched = match r.kind {
                Kind::StageIntent => self.records.iter().any(|v| matches!(&v.data, Data::StageObserved(o) if o.intent_sequence == r.sequence && o.typed_disposition.confirms_effect())),
                Kind::PublishIntent => self.records.iter().any(|v| matches!(&v.data, Data::PublishObserved(o) if o.intent_sequence == r.sequence && matches!(o.disposition, PublicationDisposition::FileAndParentSyncedReadback))),
                _ => true,
            };
            if !matched {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ClosureUnproven,
                ));
            }
        }
        Ok(VerifiedPublication {
            control_id: control_id.to_owned(),
            descriptor_digest: descriptor_digest.to_owned(),
        })
    }
}

/// Canonical bytes of one closed record body, for codec tests only.
#[cfg(test)]
pub(super) fn canonical_record(value: serde_json::Value) -> Vec<u8> {
    let record: Record = serde_json::from_value(value).expect("closed journal record");
    serde_json::to_vec(&record).expect("journal record encodes")
}
