//! Fixed WBRCJ001 frames and closed DATA. A hash chain is not a fresh proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::activation::{
    ActivationBinding, ActivationPhase, CandidatePlan, HostBinding, JournalReference,
    PlannedInstallation, ServiceConfigReference, ExpectedServerDatabase,
};
use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, RequiredNullable,
    RestoreOperationProfile, TrustedHostRecoveryLimits, hex, id,
};

const MAGIC: &[u8; 8] = b"WBRCJ001";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessStart {
    pub(super) seconds: u64,
    pub(super) nanos: u32,
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
    pub(super) fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        id(&self.boot_identity, l.max_id_bytes)?;
        hex(&self.owner_nonce, 32, true)?;
        if self.clock_kind != "CLOCK_MONOTONIC" || self.pid == 0
            || self.process_start.nanos >= 1_000_000_000
            || self.effect_deadline_ns <= self.t0_ns
            || self.convergence_deadline_ns <= self.effect_deadline_ns
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileInput { file: RecoveryFileIdentity, length: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputIdentities { carrier: FileInput, key_medium: FileInput }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Business { deployment_id: String, tenant_id: String, dataset_id: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OrdinaryBounds { effect_ns: u64, convergence_ns: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreIntent {
    profile: RestoreOperationProfile,
    input_identities: InputIdentities,
    business: Business,
    source_installation_id: String,
    target_installation_id: String,
    candidate_plan: CandidatePlan,
    owner_clock: OwnerClockRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreshIntent {
    host_binding: HostBinding,
    original_startup_intent: String,
    planned_installation: PlannedInstallation,
    ordinary_startup_bounds: OrdinaryBounds,
    initializing_descriptor_digest: String,
    original_clock_relation: OwnerClockRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "siteKind", rename_all = "snake_case", rename_all_fields = "camelCase", deny_unknown_fields)]
enum SiteSelection {
    LocalPhysical { trusted_parent: RecoveryFileIdentity, entry_component: String },
    ServerDatabase { service_config: ServiceConfigReference, expected_server_database: ExpectedServerDatabase },
}
impl SiteSelection {
    fn validate_host(&self, host: &HostBinding, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        host.validate(l)?;
        match (self, host) {
            (Self::LocalPhysical { trusted_parent, entry_component }, HostBinding::LocalPhysical { app_data_parent, .. }) => {
                trusted_parent.validate()?; super::component(entry_component, l)?;
                if trusted_parent != app_data_parent { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
            }
            (Self::ServerDatabase { service_config, expected_server_database },
                HostBinding::ServerDatabase { service_config: actual_config, server_database, .. }) => {
                service_config.validate()?; expected_server_database.validate()?;
                if service_config != actual_config || !expected_server_database.matches(server_database) {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BusinessAndInstallation {
    deployment_id: String, tenant_id: String, dataset_id: String,
    source_installation_id: String, target_installation_id: String,
}
impl BusinessAndInstallation {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        for value in [&self.deployment_id, &self.tenant_id, &self.dataset_id,
            &self.source_installation_id, &self.target_installation_id] { id(value, l.max_id_bytes)?; }
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
    ordinary_startup_bounds: OrdinaryBounds,
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
enum Stage {
    Import, Isolation, PgUpgrade, Retire, Reconfirm, KeySlot, ScramChange,
    HqAck2, Switch, Publish, ResourceClose, OrdinaryInitialize, OrdinaryVerify,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum CommitAck { TimelyAck, AcknowledgedAfterDeadline, CommitUnknown }
#[derive(Clone, Debug, Serialize, Deserialize)]
enum RollbackAck { TimelyAck, AcknowledgedAfterDeadline, RollbackUnproven }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
enum NativeExit { Code { value: i32 }, Signal { value: i32 } }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
enum PipeJoin { Returned { observed_ns: u64 }, Panicked { observed_ns: u64 }, JoinUnknown }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum Disposition {
    PgCommit(CommitAck),
    PgRollback(RollbackAck),
    NativeWait {
        original_program_id: String, original_pid: u32, original_start_identity: ProcessStart,
        exit_code_or_signal: NativeExit, observed_ns: u64, pipes: [PipeJoin; 3],
    },
    NativeWaitUnknown { original_program_id: String, original_pid: u32, original_start_identity: ProcessStart },
    TaskReturned { original_task_id: String, observed_ns: u64 },
    TaskPanicked { original_task_id: String, observed_ns: u64 },
    TaskJoinUnknown { original_task_id: String },
    OsStoreReadbackMatched { intent_ref: JournalReference, service_ref: String, account_ref: String, exact_length: u64 },
    OsStoreWriteUnknown { intent_ref: JournalReference, service_ref: String, account_ref: String },
    OsStoreReadbackUnknown { intent_ref: JournalReference, service_ref: String, account_ref: String },
    FilePublishMatched { intent_ref: JournalReference, held_file_identity: RecoveryFileIdentity, expected_digest: String },
    FilePublishUnknown { intent_ref: JournalReference },
    GateClosed { class_id: u8, exact_inventory_ref: JournalReference, original_owner_refs: Vec<String> },
    GateUnknown { class_id: u8, exact_inventory_ref: JournalReference, original_owner_refs: Vec<String> },
    ReadOnlyResult { original_intent_ref: JournalReference, observed_kind: String },
}

impl Disposition {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        match self {
            Self::PgCommit(_) | Self::PgRollback(_) => (),
            Self::NativeWait { original_program_id, original_pid, original_start_identity, observed_ns, pipes, .. } => {
                id(original_program_id, l.max_id_bytes)?;
                if *original_pid == 0 || original_start_identity.nanos >= 1_000_000_000 || *observed_ns == 0 {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
                for pipe in pipes {
                    if matches!(pipe, PipeJoin::Returned { observed_ns: 0 } | PipeJoin::Panicked { observed_ns: 0 }) {
                        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                    }
                }
            }
            Self::NativeWaitUnknown { original_program_id, original_pid, original_start_identity } => {
                id(original_program_id, l.max_id_bytes)?;
                if *original_pid == 0 || original_start_identity.nanos >= 1_000_000_000 {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
            Self::TaskReturned { original_task_id, observed_ns } | Self::TaskPanicked { original_task_id, observed_ns } => {
                id(original_task_id, l.max_id_bytes)?;
                if *observed_ns == 0 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
            }
            Self::TaskJoinUnknown { original_task_id } => id(original_task_id, l.max_id_bytes)?,
            Self::OsStoreReadbackMatched { intent_ref, service_ref, account_ref, exact_length } => {
                intent_ref.validate()?; id(service_ref, l.max_id_bytes)?; id(account_ref, l.max_id_bytes)?;
                if *exact_length == 0 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
            }
            Self::OsStoreWriteUnknown { intent_ref, service_ref, account_ref }
                | Self::OsStoreReadbackUnknown { intent_ref, service_ref, account_ref } => {
                intent_ref.validate()?; id(service_ref, l.max_id_bytes)?; id(account_ref, l.max_id_bytes)?;
            }
            Self::FilePublishMatched { intent_ref, held_file_identity, expected_digest } => {
                intent_ref.validate()?; held_file_identity.validate()?; hex(expected_digest, 64, false)?;
            }
            Self::FilePublishUnknown { intent_ref } => intent_ref.validate()?,
            Self::GateClosed { class_id, exact_inventory_ref, original_owner_refs }
                | Self::GateUnknown { class_id, exact_inventory_ref, original_owner_refs } => {
                if !(1..=9).contains(class_id) || original_owner_refs.is_empty()
                    || u64::try_from(original_owner_refs.len()).map_or(true, |n| n > l.max_runtime_resource_facts)
                {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
                exact_inventory_ref.validate()?;
                for original in original_owner_refs { id(original, l.max_id_bytes)?; }
            }
            Self::ReadOnlyResult { original_intent_ref, observed_kind } => {
                original_intent_ref.validate()?; id(observed_kind, l.max_id_bytes)?;
            }
        }
        Ok(())
    }

    fn confirms_effect(&self) -> bool {
        match self {
            Self::PgCommit(CommitAck::TimelyAck | CommitAck::AcknowledgedAfterDeadline)
                | Self::PgRollback(RollbackAck::TimelyAck | RollbackAck::AcknowledgedAfterDeadline)
                | Self::TaskReturned { .. } | Self::OsStoreReadbackMatched { .. }
                | Self::FilePublishMatched { .. } | Self::GateClosed { .. } => true,
            Self::NativeWait { exit_code_or_signal: NativeExit::Code { value: 0 }, pipes, .. } =>
                pipes.iter().all(|p| matches!(p, PipeJoin::Returned { .. })),
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum PublicationDisposition { FileAndParentSyncedReadback, DurabilityUnknown }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StageIntent { stage: Stage, original_effect_id: String, expected_binding: RequiredNullable<ActivationBinding> }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StageObserved {
    intent_sequence: u64, typed_disposition: Disposition,
    actual_binding: RequiredNullable<ActivationBinding>, receipt_refs: Vec<JournalReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishIntent {
    expected_phase: ActivationPhase, descriptor_digest: String, receipt_refs: Vec<JournalReference>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishObserved {
    intent_sequence: u64, descriptor_digest: String,
    actual_file_identity: RequiredNullable<RecoveryFileIdentity>,
    disposition: PublicationDisposition,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadOnlyObservation { original_intent: JournalReference, typed_observation: Disposition }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Kind { OperationIntent, StageIntent, StageObserved, PublishIntent, PublishObserved, ReadOnlyObservation }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Data {
    Operation(OperationIntent), StageIntent(StageIntent), StageObserved(StageObserved),
    PublishIntent(PublishIntent), PublishObserved(PublishObserved), ReadOnly(ReadOnlyObservation),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    record_type: String, version: u32, control_id: String, operation_id: String,
    epoch: String, sequence: u64, previous_digest: String, kind: Kind, data: Data,
}

pub(super) fn digest_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for byte in bytes { s.push(char::from(HEX[usize::from(byte >> 4)])); s.push(char::from(HEX[usize::from(byte & 15)])); }
    s
}

pub(super) fn hex_matches(bytes: &[u8; 32], expected: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    expected.len() == 64 && bytes.iter().zip(expected.as_bytes().chunks_exact(2)).all(|(byte, pair)| {
        pair[0] == HEX[usize::from(byte >> 4)] && pair[1] == HEX[usize::from(byte & 15)]
    })
}

/// Complete canonical chain observation, held privately with its source FD.
pub(super) struct JournalObservation { records: Vec<Record>, digests: Vec<[u8; 32]> }

/// Not Deserialize and not constructible from a DTO outside this module.
pub(super) struct VerifiedPublication {
    control_id: String,
    descriptor_digest: String,
}
impl VerifiedPublication {
    pub(super) fn matches(&self, control_id: &str, digest: &str) -> Result<(), RecoveryControlError> {
        if self.control_id != control_id || self.descriptor_digest != digest {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }
}

impl Record {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        if self.record_type != "wrokbot-recovery-journal" || self.version != 1 || self.sequence == 0 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        hex(&self.control_id, 32, true)?; hex(&self.operation_id, 32, true)?;
        hex(&self.epoch, 64, true)?; hex(&self.previous_digest, 64, false)?;
        match (&self.kind, &self.data) {
            (Kind::OperationIntent, Data::Operation(d)) if self.sequence == 1 => match d {
                OperationIntent::Restore(v) => {
                    v.profile.clone().checked(l)?;
                    v.candidate_plan.validate(l)?;
                    v.input_identities.carrier.file.validate()?;
                    v.input_identities.key_medium.file.validate()?;
                    if v.input_identities.carrier.length == 0 || v.input_identities.key_medium.length != 104 {
                        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                    }
                    for s in [&v.business.deployment_id, &v.business.tenant_id, &v.business.dataset_id,
                        &v.source_installation_id, &v.target_installation_id] { id(s, l.max_id_bytes)?; }
                    v.owner_clock.validate(l)?;
                }
                OperationIntent::FreshInit(v) => {
                    hex(&v.original_startup_intent, 32, true)?;
                    hex(&v.initializing_descriptor_digest, 64, false)?;
                    v.host_binding.validate_plan(&v.planned_installation, l)?;
                    v.original_clock_relation.validate(l)?;
                    if v.ordinary_startup_bounds.effect_ns == 0 || v.ordinary_startup_bounds.convergence_ns == 0 {
                        return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
                    }
                }
                OperationIntent::LegacyAdoption(v) => {
                    hex(&v.original_startup_intent, 32, true)?;
                    hex(&v.initializing_descriptor_digest, 64, false)?;
                    v.owned_intent_file_identity.validate()?;
                    v.original_site_selection.validate_host(&v.host_binding, l)?;
                    if v.owned_intent_file_identity.uid != v.host_binding.owner_uid()? {
                        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                    }
                    v.expected_original_business_and_installation.validate(l)?;
                    v.original_clock_relation.validate(l)?;
                    if v.ordinary_startup_bounds.effect_ns == 0 || v.ordinary_startup_bounds.convergence_ns == 0 {
                        return Err(RecoveryControlError::new(RecoveryControlFault::ProfileInvalid));
                    }
                }
            },
            (Kind::StageIntent, Data::StageIntent(v)) => {
                hex(&v.original_effect_id, 32, true)?;
                if let RequiredNullable::Value(b) = &v.expected_binding { b.validate(l)?; }
            }
            (Kind::StageObserved, Data::StageObserved(v)) => {
                if v.intent_sequence == 0 || v.intent_sequence >= self.sequence {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
                if let RequiredNullable::Value(b) = &v.actual_binding { b.validate(l)?; }
                v.typed_disposition.validate(l)?;
                if u64::try_from(v.receipt_refs.len()).map_or(true, |n| n > l.max_evidence_refs) {
                    return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
                }
                for r in &v.receipt_refs { r.validate()?; }
            }
            (Kind::PublishIntent, Data::PublishIntent(v)) => {
                hex(&v.descriptor_digest, 64, false)?;
                if u64::try_from(v.receipt_refs.len()).map_or(true, |n| n > l.max_evidence_refs) {
                    return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
                }
                for r in &v.receipt_refs { r.validate()?; }
            }
            (Kind::PublishObserved, Data::PublishObserved(v)) => {
                hex(&v.descriptor_digest, 64, false)?;
                if v.intent_sequence == 0 || v.intent_sequence >= self.sequence {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
                match (&v.disposition, &v.actual_file_identity) {
                    (PublicationDisposition::FileAndParentSyncedReadback, RequiredNullable::Value(i)) => i.validate()?,
                    (PublicationDisposition::DurabilityUnknown, RequiredNullable::Null(())) => (),
                    _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
                }
            }
            (Kind::ReadOnlyObservation, Data::ReadOnly(v)) => { v.original_intent.validate()?; v.typed_observation.validate(l)?; }
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
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
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    let mut offset = 0usize;
    let mut records: Vec<Record> = Vec::new();
    let mut digests = Vec::new();
    while offset < raw.len() {
        let header_end = offset.checked_add(12)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if header_end > raw.len() || raw.get(offset..offset + 8) != Some(MAGIC.as_slice()) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let len = u32::from_be_bytes(raw[offset + 8..header_end].try_into()
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?);
        if len == 0 || u64::from(len) > limits.max_journal_frame_bytes
            || u64::try_from(records.len()).map_or(true, |n| n >= limits.max_journal_records)
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        let body_end = header_end.checked_add(usize::try_from(len)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let end = body_end.checked_add(32)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if end > raw.len() { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        let mut digest = Sha256::new();
        digest.update(b"wrokbot.restore.journal.v1\0");
        digest.update(&raw[offset..body_end]);
        let digest: [u8; 32] = digest.finalize().into();
        if raw[body_end..end] != digest {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let record: Record = serde_json::from_slice(&raw[header_end..body_end])
            .map_err(RecoveryControlError::from_json)?;
        record.validate(limits)?;
        let canonical = serde_json::to_vec(&record)
            .map_err(RecoveryControlError::from_json)?;
        let sequence = u64::try_from(records.len()).ok().and_then(|n| n.checked_add(1))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if canonical != raw[header_end..body_end] || record.sequence != sequence
            || record.previous_digest != digests.last().map_or_else(|| "0".repeat(64), digest_hex)
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        if let Some(first) = records.first() {
            if record.control_id != first.control_id || record.operation_id != first.operation_id || record.epoch != first.epoch {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            if let Data::StageIntent(stage) = &record.data {
                let allowed = match &first.data {
                    Data::Operation(OperationIntent::Restore(_)) => !matches!(stage.stage, Stage::OrdinaryInitialize | Stage::OrdinaryVerify),
                    Data::Operation(OperationIntent::FreshInit(_)) => matches!(stage.stage, Stage::OrdinaryInitialize | Stage::KeySlot | Stage::Publish | Stage::ResourceClose),
                    Data::Operation(OperationIntent::LegacyAdoption(_)) => matches!(stage.stage, Stage::OrdinaryVerify | Stage::KeySlot | Stage::Publish | Stage::ResourceClose),
                    _ => false,
                };
                if !allowed { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
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
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
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
pub(super) fn read_metadata_reservation(raw: &[u8], limits: &TrustedHostRecoveryLimits) -> Result<u64, RecoveryControlError> {
    let invalid = || RecoveryControlError::new(RecoveryControlFault::CapacityExceeded);
    let mut total = std::mem::size_of::<JournalObservation>() as u64;
    let mut offset = 0usize;
    let mut records = 0u64;
    while offset < raw.len() {
        let header = offset.checked_add(12).filter(|end| *end <= raw.len()).ok_or_else(invalid)?;
        if raw.get(offset..offset + 8) != Some(MAGIC.as_slice()) { return Err(invalid()); }
        let size = u32::from_be_bytes(raw[offset + 8..header].try_into().map_err(|_| invalid())?) as usize;
        let body = header.checked_add(size).ok_or_else(invalid)?;
        let end = body.checked_add(32).filter(|end| *end <= raw.len()).ok_or_else(invalid)?;
        records = records.checked_add(1).filter(|n| *n <= limits.max_journal_records).ok_or_else(invalid)?;
        if size == 0 || size as u64 > limits.max_journal_frame_bytes { return Err(invalid()); }
        let body_fee = super::activation::read_metadata_reservation(&raw[header..body])?
            .checked_mul(2).ok_or_else(invalid)?;
        let fixed = 2 * (std::mem::size_of::<Record>() + std::mem::size_of::<[u8; 32]>());
        total = total.checked_add(body_fee).and_then(|n| n.checked_add(fixed as u64)).ok_or_else(invalid)?;
        offset = end;
    }
    Ok(total)
}

impl JournalObservation {
    /// Check the original ordinary operation and actual full-digest evidence
    /// references. Unknown / other-context evidence remains closed.
    pub(super) fn verify_ordinary_evidence(&self, observation: &super::activation::ActivationObservation) -> Result<(), RecoveryControlError> {
        let invalid = || RecoveryControlError::new(RecoveryControlFault::ClosureUnproven);
        let (binding, evidence) = observation.ordinary_active()?;
        let first = self.records.first().ok_or_else(invalid)?;
        if first.epoch != binding.authorization_epoch()
            || !matches!(first.data, Data::Operation(OperationIntent::FreshInit(_) | OperationIntent::LegacyAdoption(_)))
        { return Err(invalid()); }
        for reference in evidence {
            reference.validate()?;
            let index = usize::try_from(reference.sequence - 1).map_err(|_| invalid())?;
            if reference.context_id != first.operation_id
                || self.digests.get(index).map(digest_hex).as_ref() != Some(&reference.digest)
                || !matches!(self.records.get(index), Some(Record { data: Data::StageObserved(stage), .. }) if stage.typed_disposition.confirms_effect())
            { return Err(invalid()); }
        }
        Ok(())
    }

    pub(super) fn publication_for(
        &self, control_id: &str, descriptor_digest: &str,
        reference: &JournalReference, actual_file: RecoveryFileIdentity,
        phase: ActivationPhase,
    ) -> Result<VerifiedPublication, RecoveryControlError> {
        reference.validate()?;
        let original = self.records.first()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        if original.control_id != control_id || original.operation_id != reference.context_id {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let index = usize::try_from(reference.sequence - 1)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        if self.digests.get(index).map(digest_hex).as_ref() != Some(&reference.digest) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let Some(Record { kind: Kind::PublishIntent, data: Data::PublishIntent(intent), .. }) = self.records.get(index) else {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        };
        if intent.expected_phase != phase || intent.descriptor_digest != descriptor_digest {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let observed = self.records.iter().filter(|r| matches!(&r.data,
            Data::PublishObserved(v) if v.intent_sequence == reference.sequence
                && v.descriptor_digest == descriptor_digest
                && matches!(v.disposition, PublicationDisposition::FileAndParentSyncedReadback)
                && matches!(v.actual_file_identity, RequiredNullable::Value(i) if i == actual_file)
        )).count();
        if observed != 1 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven));
        }
        for r in &self.records {
            let matched = match r.kind {
                Kind::StageIntent => self.records.iter().any(|v| matches!(&v.data, Data::StageObserved(o) if o.intent_sequence == r.sequence && o.typed_disposition.confirms_effect())),
                Kind::PublishIntent => self.records.iter().any(|v| matches!(&v.data, Data::PublishObserved(o) if o.intent_sequence == r.sequence && matches!(o.disposition, PublicationDisposition::FileAndParentSyncedReadback))),
                _ => true,
            };
            if !matched { return Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven)); }
        }
        Ok(VerifiedPublication { control_id: control_id.to_owned(), descriptor_digest: descriptor_digest.to_owned() })
    }
}
