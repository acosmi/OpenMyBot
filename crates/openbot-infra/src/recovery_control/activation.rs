//! Closed activation DATA. Parsing never publishes or grants a Current owner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, RequiredNullable,
    TrustedHostRecoveryLimits, component, hex, id,
};

/// The only five registered on-disk selector phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationPhase {
    OrdinaryInitializing,
    OrdinaryActive,
    RestorePending,
    SwitchedPending,
    RestoreCurrent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum KeyKind { HistoricalMaster, PostgresScram }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KeyReference {
    pub(super) kind: KeyKind,
    pub(super) reviewed_service: String,
    pub(super) account: String,
    pub(super) key_id: String,
    pub(super) key_version: u32,
    pub(super) target_installation_id: String,
    pub(super) operation_id: String,
}

/// Public binding DATA in a descriptor; this is not a usable installation or
/// authorization source, and deserializing it creates no owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationBinding {
    pub(super) dataset_id: String,
    pub(super) deployment_id: String,
    pub(super) tenant_id: String,
    pub(super) source_installation_id: String,
    pub(super) target_installation_id: String,
    pub(super) generation_id: String,
    pub(super) generation_root: RecoveryFileIdentity,
    pub(super) pg_system_id: u64,
    pub(super) database_oid: u32,
    pub(super) pg_major: u32,
    pub(super) native_version: u32,
    pub(super) migration_digest: String,
    pub(super) authorization_epoch: String,
    pub(super) key_refs: Vec<KeyReference>,
}

impl ActivationBinding {
    pub(super) fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        for s in [&self.dataset_id, &self.deployment_id, &self.tenant_id,
            &self.source_installation_id, &self.target_installation_id] {
            id(s, l.max_id_bytes)?;
        }
        hex(&self.generation_id, 32, true)?;
        self.generation_root.validate()?;
        hex(&self.migration_digest, 64, false)?;
        hex(&self.authorization_epoch, 64, true)?;
        if self.pg_system_id == 0 || self.database_oid == 0 || self.pg_major != 17
            || !matches!(self.native_version, 52 | 53) || self.key_refs.len() != 2
            || self.key_refs[0].kind != KeyKind::HistoricalMaster
            || self.key_refs[1].kind != KeyKind::PostgresScram
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        for key in &self.key_refs {
            for s in [&key.reviewed_service, &key.account, &key.key_id,
                &key.target_installation_id] { id(s, l.max_id_bytes)?; }
            hex(&key.operation_id, 32, true)?;
            if key.key_version == 0 || key.target_installation_id != self.target_installation_id {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct JournalReference {
    pub(super) context_id: String,
    pub(super) sequence: u64,
    pub(super) digest: String,
}
impl JournalReference {
    pub(super) fn validate(&self) -> Result<(), RecoveryControlError> {
        hex(&self.context_id, 32, true)?;
        hex(&self.digest, 64, false)?;
        if self.sequence == 0 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum ActualOsOwner {
    LocalUid { uid: u32 },
    ConfiguredService { uid: u32, service: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HostBinding {
    pub(super) actual_os_owner: ActualOsOwner,
    pub(super) app_data_parent: RecoveryFileIdentity,
    pub(super) control_root: RecoveryFileIdentity,
    pub(super) reviewed_release_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlannedInstallation {
    pub(super) trusted_parent: RecoveryFileIdentity,
    pub(super) entry_component: String,
    pub(super) installation_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CandidatePlan {
    pub(super) trusted_parent: RecoveryFileIdentity,
    pub(super) entry_component: String,
    pub(super) installation_id: String,
    pub(super) generation_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OrdinaryMode { Fresh, LegacyAdoption }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Initializing {
    intent_id: String,
    mode: OrdinaryMode,
    host_binding: HostBinding,
    planned_installation: PlannedInstallation,
    initial_epoch: String,
    limits_digest: String,
    init_journal_prefix: JournalReference,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Active {
    pub(super) binding: ActivationBinding,
    initialization_evidence: Vec<JournalReference>,
    pub(super) publish_intent: JournalReference,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Pending {
    operation_id: String,
    epoch: String,
    profile_digest: String,
    prior_binding: RequiredNullable<ActivationBinding>,
    candidate_plan: CandidatePlan,
    input_plan_digest: String,
    owner_clock: super::journal::OwnerClockRecord,
    journal_prefix: JournalReference,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Switched {
    operation_id: String,
    epoch: String,
    profile_digest: String,
    pub(super) binding: ActivationBinding,
    closure_evidence: Vec<JournalReference>,
    pub(super) publish_intent: JournalReference,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Current {
    operation_id: String,
    epoch: String,
    profile_digest: String,
    pub(super) binding: ActivationBinding,
    closure_evidence: Vec<JournalReference>,
    switch_readback: JournalReference,
    pub(super) publish_intent: JournalReference,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum ActivationPayload {
    Initializing(Initializing),
    Active(Active),
    Pending(Pending),
    Switched(Switched),
    Current(Current),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ActivationRecord {
    record_type: String,
    version: u32,
    pub(super) control_id: String,
    revision: u64,
    previous_digest: RequiredNullable<String>,
    pub(super) phase: ActivationPhase,
    data: ActivationPayload,
}

/// Canonical syntax observation only. A matching original publication journal
/// receipt is also required before it can become PublishedActivation.
pub(super) struct ActivationObservation {
    pub(super) record: ActivationRecord,
    pub(super) digest: String,
}

/// Produced only after the original complete journal and actual file identity
/// establish its matching PublishIntent/PublishObserved pair.
pub(super) struct PublishedActivation {
    observation: ActivationObservation,
    _publication: super::journal::VerifiedPublication,
}

impl ActivationRecord {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        if self.record_type != "wrokbot-recovery-activation" || self.version != 1 || self.revision == 0 {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        hex(&self.control_id, 32, true)?;
        match (&self.previous_digest, self.revision) {
            (RequiredNullable::Null(()), 1) => (),
            (RequiredNullable::Value(digest), revision) if revision > 1 => hex(digest, 64, false)?,
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
        }
        let evidence = |refs: &[JournalReference]| -> Result<(), RecoveryControlError> {
            if refs.is_empty() || u64::try_from(refs.len()).map_or(true, |n| n > l.max_evidence_refs) {
                return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
            }
            for r in refs { r.validate()?; }
            Ok(())
        };
        match (&self.phase, &self.data) {
            (ActivationPhase::OrdinaryInitializing, ActivationPayload::Initializing(d)) => {
                hex(&d.intent_id, 32, true)?;
                hex(&d.initial_epoch, 64, true)?;
                hex(&d.limits_digest, 64, false)?;
                d.host_binding.app_data_parent.validate()?;
                d.host_binding.control_root.validate()?;
                hex(&d.host_binding.reviewed_release_digest, 64, false)?;
                d.planned_installation.trusted_parent.validate()?;
                component(&d.planned_installation.entry_component, l)?;
                id(&d.planned_installation.installation_id, l.max_id_bytes)?;
                d.init_journal_prefix.validate()?;
            }
            (ActivationPhase::OrdinaryActive, ActivationPayload::Active(d)) => {
                d.binding.validate(l)?; evidence(&d.initialization_evidence)?; d.publish_intent.validate()?;
            }
            (ActivationPhase::RestorePending, ActivationPayload::Pending(d)) => {
                hex(&d.operation_id, 32, true)?; hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?; hex(&d.input_plan_digest, 64, false)?;
                d.candidate_plan.trusted_parent.validate()?;
                component(&d.candidate_plan.entry_component, l)?;
                id(&d.candidate_plan.installation_id, l.max_id_bytes)?;
                hex(&d.candidate_plan.generation_id, 32, true)?;
                if let RequiredNullable::Value(binding) = &d.prior_binding { binding.validate(l)?; }
                d.owner_clock.validate(l)?; d.journal_prefix.validate()?;
            }
            (ActivationPhase::SwitchedPending, ActivationPayload::Switched(d)) => {
                hex(&d.operation_id, 32, true)?; hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?;
                d.binding.validate(l)?; evidence(&d.closure_evidence)?; d.publish_intent.validate()?;
                if d.binding.native_version != 53 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
            }
            (ActivationPhase::RestoreCurrent, ActivationPayload::Current(d)) => {
                hex(&d.operation_id, 32, true)?; hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?; d.binding.validate(l)?;
                if d.binding.native_version != 53 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
                evidence(&d.closure_evidence)?; d.switch_readback.validate()?; d.publish_intent.validate()?;
            }
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
        }
        Ok(())
    }
}

pub(super) fn observe(
    raw: &[u8],
    limits: &TrustedHostRecoveryLimits,
) -> Result<ActivationObservation, RecoveryControlError> {
    if raw.is_empty() || u64::try_from(raw.len()).map_or(true, |n| n > limits.max_activation_bytes) {
        return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
    }
    let record: ActivationRecord = serde_json::from_slice(raw)
        .map_err(RecoveryControlError::from_json)?;
    record.validate(limits)?;
    let canonical = serde_json::to_vec(&record)
        .map_err(RecoveryControlError::from_json)?;
    if canonical != raw {
        return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
    }
    let mut digest = Sha256::new();
    digest.update(b"wrokbot.restore.activation.v1\0");
    digest.update(raw);
    let digest = super::journal::digest_hex(&digest.finalize().into());
    Ok(ActivationObservation { record, digest })
}

impl PublishedActivation {
    pub(super) fn bind(
        observation: ActivationObservation,
        publication: super::journal::VerifiedPublication,
    ) -> Result<Self, RecoveryControlError> {
        publication.matches(&observation.record.control_id, &observation.digest)?;
        if !matches!(observation.record.phase, ActivationPhase::OrdinaryActive | ActivationPhase::RestoreCurrent) {
            return Err(RecoveryControlError::new(RecoveryControlFault::InitializationRequired));
        }
        Ok(Self { observation, _publication: publication })
    }

    pub(super) fn binding(&self) -> &ActivationBinding {
        match &self.observation.record.data {
            ActivationPayload::Active(d) => &d.binding,
            ActivationPayload::Current(d) => &d.binding,
            _ => unreachable!("PublishedActivation only contains Active/Current"),
        }
    }

    pub(super) fn digest(&self) -> &str { &self.observation.digest }
    pub(super) fn control_id(&self) -> &str { &self.observation.record.control_id }
}

impl ActivationObservation {
    pub(super) fn publication_reference(&self) -> Result<&JournalReference, RecoveryControlError> {
        match &self.record.data {
            ActivationPayload::Active(d) => Ok(&d.publish_intent),
            ActivationPayload::Current(d) => Ok(&d.publish_intent),
            _ => Err(RecoveryControlError::new(RecoveryControlFault::InitializationRequired)),
        }
    }
}
