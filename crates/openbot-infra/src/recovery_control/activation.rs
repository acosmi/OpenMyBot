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
pub(super) enum KeyKind {
    HistoricalMaster,
    PostgresScram,
}

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
/// authorization source. The transparent wrapper keeps variant fields private.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActivationBinding {
    site: ActivationSiteBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "siteKind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ActivationSiteBinding {
    LocalPhysical {
        dataset_id: String,
        deployment_id: String,
        tenant_id: String,
        source_installation_id: String,
        target_installation_id: String,
        generation_id: String,
        generation_root: RecoveryFileIdentity,
        pg_system_id: u64,
        database_oid: u32,
        pg_major: u32,
        native_version: u32,
        migration_digest: String,
        authorization_epoch: String,
        key_refs: Vec<KeyReference>,
    },
    ServerDatabase {
        dataset_id: String,
        deployment_id: String,
        tenant_id: String,
        source_installation_id: String,
        target_installation_id: String,
        service_config: ServiceConfigRef,
        server_database: ServerDatabaseSite,
        native_version: u32,
        migration_digest: String,
        authorization_epoch: String,
        key_refs: Vec<KeyReference>,
    },
}

/// Fixed-length lowercase hexadecimal text, checked once when decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct HexText<const N: usize, const NONZERO: bool>([u8; N]);
/// 32 hex digits, never all zero: operation, control and generation IDs.
pub(super) type Hex32 = HexText<32, true>;
/// 64 hex digits: SHA-256 digests.
pub(super) type Hex64 = HexText<64, false>;

impl<const N: usize, const NONZERO: bool> HexText<N, NONZERO> {
    pub(super) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("decoded lowercase hex is ASCII")
    }
}
impl Hex64 {
    pub(super) fn of(bytes: &[u8; 32]) -> Self {
        let mut text = [0; 64];
        text.copy_from_slice(super::journal::digest_hex(bytes).as_bytes());
        Self(text)
    }
}
impl<const N: usize, const NONZERO: bool> std::fmt::Debug for HexText<N, NONZERO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl<const N: usize, const NONZERO: bool> Serialize for HexText<N, NONZERO> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de, const N: usize, const NONZERO: bool> Deserialize<'de> for HexText<N, NONZERO> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<const N: usize, const NONZERO: bool>;
        impl<const N: usize, const NONZERO: bool> serde::de::Visitor<'_> for Visitor<N, NONZERO> {
            type Value = HexText<N, NONZERO>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "exactly {N} lowercase hexadecimal characters")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                hex(value, N, NONZERO)
                    .map_err(|_| E::custom("invalid lowercase hexadecimal text"))?;
                let mut bytes = [0; N];
                bytes.copy_from_slice(value.as_bytes());
                Ok(HexText(bytes))
            }
        }
        deserializer.deserialize_str(Visitor::<N, NONZERO>)
    }
}

/// The one `ServiceConfigRef` codec (Appendix B): held config identity, length and digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceConfigRef {
    pub(super) file: RecoveryFileIdentity,
    pub(super) length: u64,
    pub(super) digest: Hex64,
}
impl ServiceConfigRef {
    pub(super) fn validate(&self) -> Result<(), RecoveryControlError> {
        self.file.validate()?;
        if self.length == 0 {
            return Err(invalid());
        }
        Ok(())
    }
}

/// PostgreSQL major version 17, the only supported value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PgMajor17;
impl Serialize for PgMajor17 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(17)
    }
}
impl<'de> Deserialize<'de> for PgMajor17 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u32::deserialize(deserializer)? {
            17 => Ok(Self),
            _ => Err(serde::de::Error::custom("pgMajor must be 17")),
        }
    }
}

/// The one expected Server database triple; nonzero and major 17 are decode checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExpectedServerDatabase {
    pub(super) pg_system_id: std::num::NonZeroU64,
    pub(super) database_oid: std::num::NonZeroU32,
    pub(super) pg_major: PgMajor17,
}
impl ExpectedServerDatabase {
    pub(super) fn matches(&self, site: &ServerDatabaseSite) -> bool {
        self.pg_system_id.get() == site.pg_system_id
            && self.database_oid.get() == site.database_oid
            && site.pg_major == 17
    }
}

/// The one ordinary startup E/C bound pair; zero is rejected when decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OrdinaryStartupBounds {
    pub(super) effect_ns: std::num::NonZeroU64,
    pub(super) convergence_ns: std::num::NonZeroU64,
}

// This is journal/descriptor DATA, not proof of authentication or a usable PG
// connection. Its actual producer and Current consumer remain separate gates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServerDatabaseSite {
    pub(super) pg_system_id: u64,
    pub(super) database_oid: u32,
    pub(super) pg_major: u32,
    pub(super) authenticated_principal: String,
    pub(super) database_owner: String,
}
impl ServerDatabaseSite {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        if self.pg_system_id == 0 || self.database_oid == 0 || self.pg_major != 17 {
            return Err(invalid());
        }
        id(&self.authenticated_principal, l.max_id_bytes)?;
        id(&self.database_owner, l.max_id_bytes)
    }
}

struct CommonBinding<'a> {
    ids: [&'a str; 5],
    native_version: u32,
    migration_digest: &'a str,
    authorization_epoch: &'a str,
    key_refs: &'a [KeyReference],
}
fn invalid() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
}

pub(super) struct OrdinaryServerBinding<'a> {
    pub(super) dataset_id: &'a str,
    pub(super) deployment_id: &'a str,
    pub(super) tenant_id: &'a str,
    pub(super) source_installation_id: &'a str,
    pub(super) target_installation_id: &'a str,
    pub(super) service_config: &'a ServiceConfigRef,
    pub(super) server_database: &'a ServerDatabaseSite,
    pub(super) native_version: u32,
    pub(super) migration_digest: &'a str,
    pub(super) master: &'a KeyReference,
    pub(super) postgres: &'a KeyReference,
}

impl ActivationBinding {
    fn common(&self) -> CommonBinding<'_> {
        match &self.site {
            ActivationSiteBinding::LocalPhysical {
                dataset_id,
                deployment_id,
                tenant_id,
                source_installation_id,
                target_installation_id,
                native_version,
                migration_digest,
                authorization_epoch,
                key_refs,
                ..
            }
            | ActivationSiteBinding::ServerDatabase {
                dataset_id,
                deployment_id,
                tenant_id,
                source_installation_id,
                target_installation_id,
                native_version,
                migration_digest,
                authorization_epoch,
                key_refs,
                ..
            } => CommonBinding {
                ids: [
                    dataset_id,
                    deployment_id,
                    tenant_id,
                    source_installation_id,
                    target_installation_id,
                ],
                native_version: *native_version,
                migration_digest,
                authorization_epoch,
                key_refs,
            },
        }
    }

    pub(super) fn authorization_epoch(&self) -> &str {
        self.common().authorization_epoch
    }
    /// Deployment and tenant IDs bound into this descriptor.
    pub(super) fn scope(&self) -> (&str, &str) {
        let ids = self.common().ids;
        (ids[1], ids[2])
    }
    pub(super) fn native_version(&self) -> u32 {
        self.common().native_version
    }

    /// Borrow the closed Server DATA. This is not a constructor or PG proof.
    pub(super) fn ordinary_server(
        &self,
    ) -> Result<OrdinaryServerBinding<'_>, RecoveryControlError> {
        match &self.site {
            ActivationSiteBinding::ServerDatabase {
                dataset_id,
                deployment_id,
                tenant_id,
                source_installation_id,
                target_installation_id,
                service_config,
                server_database,
                native_version,
                migration_digest,
                key_refs,
                ..
            } => Ok(OrdinaryServerBinding {
                dataset_id,
                deployment_id,
                tenant_id,
                source_installation_id,
                target_installation_id,
                service_config,
                server_database,
                native_version: *native_version,
                migration_digest,
                master: &key_refs[0],
                postgres: &key_refs[1],
            }),
            _ => Err(invalid()),
        }
    }
    fn is_local(&self) -> bool {
        matches!(self.site, ActivationSiteBinding::LocalPhysical { .. })
    }

    pub(super) fn validate(
        &self,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        let common = self.common();
        for value in common.ids {
            id(value, l.max_id_bytes)?;
            // Authorization key info encodes these as u16-length fields.
            if value.len() > usize::from(u16::MAX) {
                return Err(invalid());
            }
        }
        hex(common.migration_digest, 64, false)?;
        hex(common.authorization_epoch, 64, true)?;
        if !matches!(common.native_version, 52 | 53)
            || common.key_refs.len() != 2
            || common.key_refs[0].kind != KeyKind::HistoricalMaster
            || common.key_refs[1].kind != KeyKind::PostgresScram
        {
            return Err(invalid());
        }
        for key in common.key_refs {
            for value in [
                &key.reviewed_service,
                &key.account,
                &key.key_id,
                &key.target_installation_id,
            ] {
                id(value, l.max_id_bytes)?;
            }
            hex(&key.operation_id, 32, true)?;
            if key.key_version == 0 || key.target_installation_id != common.ids[4] {
                return Err(invalid());
            }
        }
        match &self.site {
            ActivationSiteBinding::LocalPhysical {
                generation_id,
                generation_root,
                pg_system_id,
                database_oid,
                pg_major,
                ..
            } => {
                hex(generation_id, 32, true)?;
                generation_root.validate()?;
                if *pg_system_id == 0 || *database_oid == 0 || *pg_major != 17 {
                    return Err(invalid());
                }
            }
            ActivationSiteBinding::ServerDatabase {
                service_config,
                server_database,
                ..
            } => {
                service_config.validate()?;
                server_database.validate(l)?;
                if common.key_refs[0].reviewed_service != "server.KEY_ENCRYPTION_KEY"
                    || common.key_refs[1].reviewed_service != "server.DATABASE_URL"
                    || common
                        .key_refs
                        .iter()
                        .any(|key| key.account != "configured-current")
                {
                    return Err(invalid());
                }
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
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }
}

/// Operation/context identifier (Appendix B `O`): 32 lowercase hex digits.
pub(super) type OpId = Hex32;

/// Position of the journal record that a descriptor's own publication intent
/// occupies. It carries no digest, so the descriptor digest
/// and the record holding it do not depend on each other; consumers read the
/// record at this position and compare its content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct JournalPositionRef {
    pub(super) context_id: OpId,
    pub(super) sequence: std::num::NonZeroU64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub(super) enum ActualOsOwner {
    LocalUid { uid: u32 },
    ConfiguredService { uid: u32, service: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "siteKind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum HostBinding {
    LocalPhysical {
        actual_os_owner: ActualOsOwner,
        app_data_parent: RecoveryFileIdentity,
        control_root: RecoveryFileIdentity,
        reviewed_release_digest: String,
    },
    ServerDatabase {
        actual_os_owner: ActualOsOwner,
        service_config: ServiceConfigRef,
        control_root: RecoveryFileIdentity,
        server_database: ServerDatabaseSite,
    },
}
impl HostBinding {
    pub(super) fn owner_uid(&self) -> Result<u32, RecoveryControlError> {
        match self {
            Self::LocalPhysical {
                actual_os_owner: ActualOsOwner::LocalUid { uid },
                ..
            }
            | Self::ServerDatabase {
                actual_os_owner: ActualOsOwner::ConfiguredService { uid, .. },
                ..
            } => Ok(*uid),
            _ => Err(invalid()),
        }
    }
    pub(super) fn validate(
        &self,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        let uid = self.owner_uid()?;
        match self {
            Self::LocalPhysical {
                app_data_parent,
                control_root,
                reviewed_release_digest,
                ..
            } => {
                app_data_parent.validate()?;
                control_root.validate()?;
                hex(reviewed_release_digest, 64, false)?;
                if control_root.uid != uid {
                    return Err(invalid());
                }
            }
            Self::ServerDatabase {
                actual_os_owner: ActualOsOwner::ConfiguredService { service, .. },
                service_config,
                control_root,
                server_database,
            } => {
                id(service, l.max_id_bytes)?;
                service_config.validate()?;
                control_root.validate()?;
                server_database.validate(l)?;
                if control_root.uid != uid || service_config.file.uid != uid {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
    pub(super) fn validate_plan(
        &self,
        plan: &PlannedInstallation,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        self.validate(l)?;
        plan.validate(l)?;
        match (self, plan) {
            (
                Self::LocalPhysical {
                    app_data_parent, ..
                },
                PlannedInstallation::LocalPhysical { trusted_parent, .. },
            ) if app_data_parent == trusted_parent => Ok(()),
            (
                Self::ServerDatabase {
                    service_config,
                    server_database,
                    ..
                },
                PlannedInstallation::ServerDatabase {
                    service_config: planned_config,
                    server_database: planned_site,
                    ..
                },
            ) if service_config == planned_config && server_database == planned_site => Ok(()),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "siteKind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum PlannedInstallation {
    LocalPhysical {
        trusted_parent: RecoveryFileIdentity,
        entry_component: String,
        installation_id: String,
    },
    ServerDatabase {
        service_config: ServiceConfigRef,
        server_database: ServerDatabaseSite,
        installation_id: String,
    },
}
impl PlannedInstallation {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        match self {
            Self::LocalPhysical {
                trusted_parent,
                entry_component,
                installation_id,
            } => {
                trusted_parent.validate()?;
                component(entry_component, l)?;
                id(installation_id, l.max_id_bytes)
            }
            Self::ServerDatabase {
                service_config,
                server_database,
                installation_id,
            } => {
                service_config.validate()?;
                server_database.validate(l)?;
                id(installation_id, l.max_id_bytes)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum LocalPhysicalSiteKind {
    #[serde(rename = "local_physical")]
    LocalPhysical,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CandidatePlan {
    site_kind: LocalPhysicalSiteKind,
    pub(super) trusted_parent: RecoveryFileIdentity,
    pub(super) entry_component: String,
    pub(super) installation_id: String,
    pub(super) generation_id: String,
}
impl CandidatePlan {
    pub(super) fn validate(
        &self,
        l: &TrustedHostRecoveryLimits,
    ) -> Result<(), RecoveryControlError> {
        self.trusted_parent.validate()?;
        component(&self.entry_component, l)?;
        id(&self.installation_id, l.max_id_bytes)?;
        hex(&self.generation_id, 32, true)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OrdinaryMode {
    Fresh,
    LegacyAdoption,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Initializing {
    intent_id: String,
    mode: OrdinaryMode,
    host_binding: HostBinding,
    planned_installation: PlannedInstallation,
    initial_epoch: String,
    limits_digest: String,
    pub(super) init_journal_prefix: JournalPositionRef,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Active {
    pub(super) binding: ActivationBinding,
    initialization_evidence: Vec<JournalReference>,
    pub(super) publish_intent: JournalPositionRef,
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
    pub(super) publish_intent: JournalPositionRef,
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
    pub(super) publish_intent: JournalPositionRef,
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
    observation: std::sync::Arc<ActivationObservation>,
    _publication: super::journal::VerifiedPublication,
}

impl ActivationRecord {
    fn validate(&self, l: &TrustedHostRecoveryLimits) -> Result<(), RecoveryControlError> {
        if self.record_type != "wrokbot-recovery-activation"
            || self.version != 1
            || self.revision == 0
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        hex(&self.control_id, 32, true)?;
        match (&self.previous_digest, self.revision) {
            (RequiredNullable::Null(()), 1) => (),
            (RequiredNullable::Value(digest), revision) if revision > 1 => hex(digest, 64, false)?,
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        let evidence = |refs: &[JournalReference]| -> Result<(), RecoveryControlError> {
            if refs.is_empty()
                || u64::try_from(refs.len()).map_or(true, |n| n > l.max_evidence_refs)
            {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
            for r in refs {
                r.validate()?;
            }
            Ok(())
        };
        match (&self.phase, &self.data) {
            (ActivationPhase::OrdinaryInitializing, ActivationPayload::Initializing(d)) => {
                hex(&d.intent_id, 32, true)?;
                hex(&d.initial_epoch, 64, true)?;
                hex(&d.limits_digest, 64, false)?;
                d.host_binding.validate_plan(&d.planned_installation, l)?;
            }
            (ActivationPhase::OrdinaryActive, ActivationPayload::Active(d)) => {
                d.binding.validate(l)?;
                evidence(&d.initialization_evidence)?;
            }
            (ActivationPhase::RestorePending, ActivationPayload::Pending(d)) => {
                hex(&d.operation_id, 32, true)?;
                hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?;
                hex(&d.input_plan_digest, 64, false)?;
                d.candidate_plan.validate(l)?;
                if let RequiredNullable::Value(binding) = &d.prior_binding {
                    binding.validate(l)?;
                    if !binding.is_local() {
                        return Err(invalid());
                    }
                }
                d.owner_clock.validate(l)?;
                d.journal_prefix.validate()?;
            }
            (ActivationPhase::SwitchedPending, ActivationPayload::Switched(d)) => {
                hex(&d.operation_id, 32, true)?;
                hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?;
                d.binding.validate(l)?;
                evidence(&d.closure_evidence)?;
                if !d.binding.is_local() || d.binding.native_version() != 53 {
                    return Err(invalid());
                }
            }
            (ActivationPhase::RestoreCurrent, ActivationPayload::Current(d)) => {
                hex(&d.operation_id, 32, true)?;
                hex(&d.epoch, 64, true)?;
                hex(&d.profile_digest, 64, false)?;
                d.binding.validate(l)?;
                if !d.binding.is_local() || d.binding.native_version() != 53 {
                    return Err(invalid());
                }
                evidence(&d.closure_evidence)?;
                d.switch_readback.validate()?;
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

// Allocation admission only, not a second JSON validator. Outside-string
// punctuation bounds map/sequence nodes, including malformed unknown fields;
// encoded string bytes bound decoded strings. The pinned serde1.0.229 Content
// envelope is bounded by two Vec headers per node. Four simultaneous Content
// layers cover payload/nullable/site/owner; typed Vec leaves are separate.
// The factor2 covers Vec growth, while16*wire prepays decoded string copies,
// escape/key scratch, canonical output and retained diagnostic text. Charge
// once for the same immutable held input, before entering serde or allocating.
pub(super) fn read_metadata_reservation(raw: &[u8]) -> Result<u64, RecoveryControlError> {
    let mut nodes = 1u64;
    let (mut quoted, mut escaped) = (false, false);
    for byte in raw {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if matches!(*byte, b'{' | b'[' | b',' | b':') {
            nodes = nodes
                .checked_add(1)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
    }
    let content = std::mem::size_of::<Vec<u8>>()
        .checked_mul(2)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    let leaf = std::mem::size_of::<KeyReference>()
        .max(std::mem::size_of::<JournalReference>())
        .max(std::mem::size_of::<JournalPositionRef>());
    let node = content
        .checked_add(leaf)
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    let fixed = std::mem::size_of::<ActivationObservation>()
        .checked_mul(2)
        .and_then(|n| n.checked_add(std::mem::size_of::<CommonBinding<'_>>()))
        .and_then(|n| n.checked_add(1024))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    nodes
        .checked_mul(
            u64::try_from(node)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?,
        )
        .and_then(|n| {
            u64::try_from(raw.len())
                .ok()
                .and_then(|wire| wire.checked_mul(16))
                .and_then(|wire| n.checked_add(wire))
        })
        .and_then(|n| {
            u64::try_from(fixed)
                .ok()
                .and_then(|fixed| n.checked_add(fixed))
        })
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))
}

pub(super) fn observe(
    raw: &[u8],
    limits: &TrustedHostRecoveryLimits,
) -> Result<ActivationObservation, RecoveryControlError> {
    if raw.is_empty() || u64::try_from(raw.len()).map_or(true, |n| n > limits.max_activation_bytes)
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::CapacityExceeded,
        ));
    }
    let record: ActivationRecord =
        serde_json::from_slice(raw).map_err(RecoveryControlError::from_json)?;
    record.validate(limits)?;
    let canonical = serde_json::to_vec(&record).map_err(RecoveryControlError::from_json)?;
    if canonical != raw {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::ControlInvalid,
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"wrokbot.restore.activation.v1\0");
    digest.update(raw);
    let digest = super::journal::digest_hex(&digest.finalize().into());
    Ok(ActivationObservation { record, digest })
}

impl PublishedActivation {
    pub(super) fn bind(
        observation: std::sync::Arc<ActivationObservation>,
        publication: super::journal::VerifiedPublication,
    ) -> Result<Self, RecoveryControlError> {
        publication.matches(&observation.record.control_id, &observation.digest)?;
        if !matches!(
            observation.record.phase,
            ActivationPhase::OrdinaryActive | ActivationPhase::RestoreCurrent
        ) {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::InitializationRequired,
            ));
        }
        Ok(Self {
            observation,
            _publication: publication,
        })
    }

    pub(super) fn binding(&self) -> &ActivationBinding {
        match &self.observation.record.data {
            ActivationPayload::Active(d) => &d.binding,
            ActivationPayload::Current(d) => &d.binding,
            _ => unreachable!("PublishedActivation only contains Active/Current"),
        }
    }

    pub(super) fn digest(&self) -> &str {
        &self.observation.digest
    }
    pub(super) fn control_id(&self) -> &str {
        &self.observation.record.control_id
    }

    /// The restored cohort of a published RestoreCurrent; none for OrdinaryActive.
    pub(super) fn restore_cohort(&self) -> Option<openbot_contracts::recovery::RestoreCohortRef> {
        match &self.observation.record.data {
            ActivationPayload::Current(d) => Some(openbot_contracts::recovery::RestoreCohortRef {
                operation_id: super::hex_array(&d.operation_id),
                epoch: super::hex_array(&d.epoch),
            }),
            _ => None,
        }
    }
}

impl ActivationObservation {
    pub(super) fn ordinary_active(
        &self,
    ) -> Result<(&ActivationBinding, &[JournalReference]), RecoveryControlError> {
        match (&self.record.phase, &self.record.data) {
            (ActivationPhase::OrdinaryActive, ActivationPayload::Active(data)) => {
                Ok((&data.binding, &data.initialization_evidence))
            }
            // RestoreCurrent still requires the separately registered subject /
            // credential reconfirmation producer. It is never normal admission.
            _ => Err(RecoveryControlError::new(
                RecoveryControlFault::InitializationRequired,
            )),
        }
    }

    pub(super) fn publication_reference(
        &self,
    ) -> Result<&JournalPositionRef, RecoveryControlError> {
        match &self.record.data {
            ActivationPayload::Active(d) => Ok(&d.publish_intent),
            ActivationPayload::Current(d) => Ok(&d.publish_intent),
            _ => Err(RecoveryControlError::new(
                RecoveryControlFault::InitializationRequired,
            )),
        }
    }
}
