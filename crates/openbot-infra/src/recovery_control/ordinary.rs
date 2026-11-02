//! Ordinary startup: the sealed entry intent, the shared-lock head branch and
//! the exclusive ordinary writer session (spec 7934, 8021, 8067-8073).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::Digest as _;

use super::activation::{
    ActivationBinding, ActivationPayload, ActivationPhase, ActivationRecord, Active, ActualOsOwner,
    ExpectedServerDatabase, Hex32, Hex64, HostBinding, Initializing, JournalPositionRef,
    JournalReference, OrdinaryLocalSite, OrdinaryMode, OrdinaryStartupBounds, PlannedInstallation,
    PublishedActivation, ServerDatabaseSite, ServiceConfigRef,
};
use super::entry::{self, ControlOwner, Head};
use super::journal::{
    BusinessAndInstallation, CommitAck, Disposition, JournalData, RollbackAck, SiteSelection, Stage,
};
use super::runtime::{self, ResourceModel, RuntimeOwner};
use super::{
    RecoveryControlError, RecoveryControlFault, RecoveryFileIdentity, RecoveryRuntimeOwner,
};
use crate::db::native;
use openbot_contracts::ids::{DeploymentId, TenantId};

/// The site an ordinary initialization source names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OrdinarySite {
    LocalPhysical,
    ServerDatabase,
}

/// The closed sealed source of an ordinary initialization (spec 8067).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OrdinaryInitializationSource {
    LocalPhysicalFresh,
    ServerDatabaseFresh,
    LegacyAdoption { site: OrdinarySite },
}

pub(super) type SealedSource = (OrdinaryInitializationSource, Hex32, RecoveryFileIdentity);

/// Trusted site expectation the producer already checked; no actual PG tuple.
pub(super) enum SiteExpectation {
    Server {
        dataset: Hex32,
        /// Deployment, tenant, source and target installation IDs.
        ids: [String; 4],
        database: ExpectedServerDatabase,
        service_config: ServiceConfigRef,
        owner: ActualOsOwner,
    },
    Local(LocalSiteExpectation),
}

pub(super) struct LocalSiteExpectation {
    pub(super) root: Option<RecoveryFileIdentity>,
    pub(super) parent: RecoveryFileIdentity,
    pub(super) component: String,
    pub(super) release: Hex64,
    pub(super) master_service: String,
    pub(super) postgres_service: String,
    pub(super) installation_id: Option<String>,
}

/// The original producer's entry intent. It is not Clone or Serde and holds
/// no actual PG tuple or transaction (spec 8329).
pub struct VerifiedOrdinaryStartupIntent {
    /// Source, original intent id and the held intent file identity.
    source: Option<SealedSource>,
    site: SiteExpectation,
    bounds: OrdinaryStartupBounds,
    t0_ns: u64,
    admission: Instant,
    effect: Instant,
    convergence: Instant,
    resource_model: ResourceModel,
    owners: Vec<RuntimeOwner>,
    #[cfg(feature = "desktop-local")]
    fresh_installation: Option<crate::auth::single_user::desktop_local::DesktopLocalInstallation>,
}

fn fault(fault: RecoveryControlFault) -> RecoveryControlError {
    RecoveryControlError::new(fault)
}

impl VerifiedOrdinaryStartupIntent {
    /// One clock read gives t0; A, E and C follow from it. The owner set is
    /// checked here once and only read afterwards.
    pub(super) fn seal(
        source: Option<SealedSource>,
        site: SiteExpectation,
        bounds: OrdinaryStartupBounds,
        admission_ns: u64,
        owners: &[RuntimeOwner],
    ) -> Result<Self, RecoveryControlError> {
        let t0 = Instant::now();
        let t0_ns = super::clock::monotonic_ns()?;
        Self::seal_at(source, site, bounds, admission_ns, owners, t0, t0_ns)
    }

    pub(super) fn seal_at(
        source: Option<SealedSource>,
        site: SiteExpectation,
        bounds: OrdinaryStartupBounds,
        admission_ns: u64,
        owners: &[RuntimeOwner],
        t0: Instant,
        t0_ns: u64,
    ) -> Result<Self, RecoveryControlError> {
        let profile = || fault(RecoveryControlFault::ProfileInvalid);
        let effect = t0
            .checked_add(Duration::from_nanos(bounds.effect_ns.get()))
            .ok_or_else(profile)?;
        let convergence = effect
            .checked_add(Duration::from_nanos(bounds.convergence_ns.get()))
            .ok_or_else(profile)?;
        let admission = t0
            .checked_add(Duration::from_nanos(admission_ns))
            .ok_or_else(profile)?
            .min(effect);
        t0_ns
            .checked_add(bounds.effect_ns.get())
            .and_then(|e| e.checked_add(bounds.convergence_ns.get()))
            .ok_or_else(profile)?;
        if owners.is_empty()
            || owners
                .iter()
                .enumerate()
                .any(|(i, owner)| owners[..i].contains(owner))
        {
            return Err(fault(RecoveryControlFault::EntryInvalid));
        }
        let resource_model = match site {
            SiteExpectation::Server { .. } => ResourceModel::Server,
            SiteExpectation::Local(_) => ResourceModel::Local,
        };
        Ok(Self {
            source,
            site,
            bounds,
            t0_ns,
            admission,
            effect,
            convergence,
            resource_model,
            owners: owners.to_vec(),
            #[cfg(feature = "desktop-local")]
            fresh_installation: None,
        })
    }

    /// Deadline A: lock acquisition and the shared-lock head read.
    #[must_use]
    pub fn admission_deadline(&self) -> Instant {
        self.admission
    }

    pub(super) fn server_dataset(&self) -> Result<Hex32, RecoveryControlError> {
        match &self.site {
            SiteExpectation::Server { dataset, .. } => Ok(*dataset),
            SiteExpectation::Local(_) => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    pub(super) fn effect_deadline(&self) -> Instant {
        self.effect
    }

    pub(super) fn resource_model(&self) -> ResourceModel {
        self.resource_model
    }

    pub(super) fn owners(&self) -> &[RuntimeOwner] {
        &self.owners
    }

    /// A published binding matches the sealed site expectation.
    pub(super) fn expects(&self, binding: &ActivationBinding) -> Result<(), RecoveryControlError> {
        match &self.site {
            SiteExpectation::Server {
                dataset,
                ids,
                database,
                service_config,
                ..
            } => {
                let actual = binding.ordinary_server()?;
                if [
                    actual.dataset_id,
                    actual.deployment_id,
                    actual.tenant_id,
                    actual.source_installation_id,
                    actual.target_installation_id,
                ] != [
                    dataset.as_str(),
                    ids[0].as_str(),
                    ids[1].as_str(),
                    ids[2].as_str(),
                    ids[3].as_str(),
                ] || actual.service_config != service_config
                    || !database.matches(actual.server_database)
                {
                    return Err(fault(RecoveryControlFault::EntryInvalid));
                }
            }
            SiteExpectation::Local(expected) => {
                let actual = binding.ordinary_local()?;
                if Some(actual.generation_root) != expected.root {
                    return Err(fault(RecoveryControlFault::EntryInvalid));
                }
            }
        }
        Ok(())
    }
}

fn latest() -> u32 {
    native::NATIVE_LATEST_VERSION.unsigned_abs()
}

/// `InitializationRequired`, handing the intent back only where the next
/// step is the exclusive ordinary writer.
fn initialization_required(intent: Option<VerifiedOrdinaryStartupIntent>) -> RecoveryControlError {
    let mut error = fault(RecoveryControlFault::InitializationRequired);
    error.unconsumed = intent.map(Box::new);
    error
}

/// Shared-lock head branch (spec 8021): admissionSH → NONBLOCK runtimeSH by A,
/// then one head read. A published head matching the sealed site at the
/// latest native version comes back with its SH still held; every other head
/// releases SH and is `InitializationRequired`, handing the intent back only
/// where the exclusive writer is the next step.
pub(super) fn shared_head(
    control: &ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
) -> Result<(PublishedActivation, VerifiedOrdinaryStartupIntent), RecoveryControlError> {
    shared_head_inner(
        control,
        intent,
        deadline,
        #[cfg(feature = "desktop-local")]
        None,
    )
}

#[cfg(feature = "desktop-local")]
pub(super) fn shared_local_head(
    control: &ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
    creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
) -> Result<(PublishedActivation, VerifiedOrdinaryStartupIntent), RecoveryControlError> {
    shared_head_inner(control, intent, deadline, Some(creator))
}

fn shared_head_inner(
    control: &ControlOwner,
    mut intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
    #[cfg(feature = "desktop-local")] creator: Option<
        &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
    >,
) -> Result<(PublishedActivation, VerifiedOrdinaryStartupIntent), RecoveryControlError> {
    let admission = deadline.min(intent.admission);
    let mut files = entry::lock(control)?;
    files.acquire_shared_before(admission)?;
    let published = match files.read_head_before(admission) {
        Ok(Head::Published(published)) => published,
        Ok(Head::Absent) => {
            #[cfg(feature = "desktop-local")]
            if let (SiteExpectation::Local(local), Some(creator)) = (&mut intent.site, creator) {
                if local.root.is_none() {
                    let (installation, root) =
                        files.create_original_local_installation(creator, intent.effect)?;
                    local.root = Some(root);
                    local.installation_id = Some(installation.authority().instance_id().to_owned());
                    intent.source = Some((
                        OrdinaryInitializationSource::LocalPhysicalFresh,
                        Hex32::mint(&mint::<16>()?)?,
                        root,
                    ));
                    intent.fresh_installation = Some(installation);
                }
            }
            files.release_registration_attempt();
            return Err(initialization_required(
                intent.source.is_some().then_some(intent),
            ));
        }
        Ok(Head::Unpublished) => {
            files.release_registration_attempt();
            return Err(initialization_required(None));
        }
        Err(error) => {
            files.latch(error.fault());
            return Err(error.retain(control));
        }
    };
    if let Err(error) = intent.expects(published.binding()) {
        files.release_registration_attempt();
        return Err(error);
    }
    if published.binding().native_version() < latest() {
        files.release_registration_attempt();
        return Err(initialization_required(None));
    }
    Ok((published, intent))
}

/// Write this runtime's enrollment under the SH a head branch still holds.
pub(super) fn enroll(
    control: &ControlOwner,
    published: PublishedActivation,
    intent: &VerifiedOrdinaryStartupIntent,
) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
    let entry = entry::lock(control)?.runtime_entry(published, intent)?;
    runtime::enter_runtime(control, entry, intent.effect)
}

/// `RecoveryControl::enter_runtime_before`: the shared head branch, then the
/// enrollment.
pub(super) fn enter_runtime(
    control: &ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
    let (published, intent) = shared_head(control, intent, deadline)?;
    enroll(control, published, &intent)
}

/// The exclusive ordinary writer: ownerEX, admissionEX and runtimeEX held in
/// the control owner from `begin` until `into_runtime_before` or drop.
pub struct OrdinaryInitializationSession {
    control: ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    /// The descriptor this session holds as head, with its digest.
    head: Option<(ActivationRecord, String)>,
    /// The open operation and its pending StageIntent sequence.
    operation: Option<Hex32>,
    pending: Option<(Stage, u64)>,
    /// Final disposition of the operation's last transaction or task.
    last: Option<Disposition>,
    evidence: Vec<JournalReference>,
}

/// Closed proofs a sealed initialization publishes; none is publicly
/// constructible.
pub enum OrdinaryActivationProof {
    ServerFresh(OrdinaryDatabaseInitializationProof),
    LocalFresh(LocalFreshProof),
    Legacy(VerifiedOrdinaryLegacyProof),
}

/// Facts of the original Local Fresh chain, observed after its canary and schema succeed.
pub struct LocalFreshProof {
    pub(super) site: OrdinaryLocalSite,
    pub(super) native_version: u32,
    pub(super) migration_digest: String,
}

/// Legacy adoption facts read back after the read-only site checks (S9).
pub struct VerifiedOrdinaryLegacyProof {
    pub(crate) site: ServerDatabaseSite,
    pub(crate) key_id: Hex32,
    pub(crate) native_version: u32,
    pub(crate) migration_digest: String,
}

/// Server Fresh facts read back on the initializing connection (S7).
pub struct OrdinaryDatabaseInitializationProof {
    pub(crate) site: ServerDatabaseSite,
    pub(crate) key_id: Hex32,
    pub(crate) migration_digest: String,
}

/// The stage a caller reports on; the journal stage enum stays private.
#[derive(Clone, Copy)]
pub(crate) enum OrdinaryStage {
    Initialize,
    Verify,
    KeySlot,
}

fn mint<const N: usize>() -> Result<[u8; N], RecoveryControlError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| fault(RecoveryControlFault::IoFailure))?;
    Ok(bytes)
}

/// Exclusive branch of `begin_ordinary_initialization_before` (spec 8069).
pub(super) fn begin(
    control: &ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
) -> Result<OrdinaryInitializationSession, RecoveryControlError> {
    let admission = deadline.min(intent.admission);
    let mut files = entry::lock(control)?;
    files.acquire_writer_before(admission)?;
    let head = match files.read_head_before(admission) {
        Ok(head) => head,
        Err(error) => {
            files.latch(error.fault());
            return Err(error.retain(control));
        }
    };
    if !matches!(head, Head::Absent) || intent.source.is_none() {
        files.release_writer();
        return Err(fault(RecoveryControlFault::OwnerBusy));
    }
    #[cfg(feature = "desktop-local")]
    if let SiteExpectation::Local(local) = &intent.site {
        files.verify_local_root_before(
            local
                .root
                .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?,
            intent.effect,
        )?;
    }
    drop(files);
    Ok(OrdinaryInitializationSession {
        control: Arc::clone(control),
        intent,
        head: None,
        operation: None,
        pending: None,
        last: None,
        evidence: Vec::new(),
    })
}

impl OrdinaryInitializationSession {
    /// Whether this original session holds a Local Fresh creation witness.
    #[cfg(feature = "desktop-local")]
    pub fn is_local_fresh(&self) -> bool {
        self.initialization_source() == Some(OrdinaryInitializationSource::LocalPhysicalFresh)
    }

    /// Consume the original Fresh installation once.
    #[cfg(feature = "desktop-local")]
    pub fn take_fresh_installation(
        &mut self,
    ) -> Option<crate::auth::single_user::desktop_local::DesktopLocalInstallation> {
        self.intent.fresh_installation.take()
    }

    /// The one Server initialization request of this session (S7); scope and
    /// deadline come from the sealed intent, not from the caller.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn original_initialization_request<'a>(
        &'a mut self,
        key: &'a crate::auth::config::KeyEncryptionKey,
    ) -> crate::db::initialization::OriginalInitializationRequest<'a> {
        crate::db::initialization::OriginalInitializationRequest { session: self, key }
    }

    /// Deployment, tenant, dataset and deadline E of a Server session.
    pub(crate) fn server_scope(
        &self,
    ) -> Result<(DeploymentId, TenantId, Hex32, Instant), RecoveryControlError> {
        match &self.intent.site {
            SiteExpectation::Server { dataset, ids, .. } => Ok((
                DeploymentId::new(ids[0].clone()),
                TenantId::new(ids[1].clone()),
                *dataset,
                self.intent.effect,
            )),
            SiteExpectation::Local(_) => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    /// The sealed source of this original initialization session.
    pub(super) fn initialization_source(&self) -> Option<OrdinaryInitializationSource> {
        self.intent.source.map(|(source, _, _)| source)
    }

    fn operation(&self) -> Result<Hex32, RecoveryControlError> {
        self.operation
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))
    }

    /// Mint the initial epoch and operation, append the Fresh OperationIntent
    /// and publish `OrdinaryInitializing` (≤E). The host binding and plan are
    /// built from the sealed expectation and the actual site.
    pub(crate) fn seal_initializing(
        &mut self,
        actual: ServerDatabaseSite,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        if self.head.is_some() {
            return Err(invalid());
        }
        let (source, _, _) = self.intent.source.ok_or_else(invalid)?;
        let mode = match source {
            OrdinaryInitializationSource::ServerDatabaseFresh => OrdinaryMode::Fresh,
            OrdinaryInitializationSource::LegacyAdoption {
                site: OrdinarySite::ServerDatabase,
            } => OrdinaryMode::LegacyAdoption,
            _ => return Err(invalid()),
        };
        let SiteExpectation::Server {
            dataset,
            ids,
            database,
            service_config,
            owner,
        } = &self.intent.site
        else {
            return Err(invalid());
        };
        if !database.matches(&actual) {
            return Err(fault(RecoveryControlFault::ControlInvalid));
        }
        let effect = self.intent.effect;
        let mut files = entry::lock(&self.control)?;
        let control_root = files.root_identity(effect)?;
        let host = HostBinding::ServerDatabase {
            actual_os_owner: owner.clone(),
            service_config: service_config.clone(),
            control_root,
            server_database: actual.clone(),
        };
        let planned = PlannedInstallation::ServerDatabase {
            service_config: service_config.clone(),
            server_database: actual,
            installation_id: ids[3].clone(),
        };
        let legacy = match mode {
            OrdinaryMode::Fresh => None,
            OrdinaryMode::LegacyAdoption => Some((
                SiteSelection::ServerDatabase {
                    service_config: service_config.clone(),
                    expected_server_database: *database,
                },
                BusinessAndInstallation {
                    deployment_id: ids[0].clone(),
                    tenant_id: ids[1].clone(),
                    dataset_id: dataset.as_str().to_owned(),
                    source_installation_id: ids[2].clone(),
                    target_installation_id: ids[3].clone(),
                },
            )),
        };
        drop(files);
        self.seal_site(host, planned, legacy)
    }

    fn seal_site(
        &mut self,
        host: HostBinding,
        planned: PlannedInstallation,
        legacy: Option<(SiteSelection, BusinessAndInstallation)>,
    ) -> Result<(), RecoveryControlError> {
        let (_, intent_id, intent_file) = self
            .intent
            .source
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?;
        let mode = if legacy.is_some() {
            OrdinaryMode::LegacyAdoption
        } else {
            OrdinaryMode::Fresh
        };
        let effect = self.intent.effect;
        let mut files = entry::lock(&self.control)?;
        host.validate_plan(&planned, &files.limits)?;
        let control_id = Hex32::mint(&mint::<16>()?)?;
        let operation = Hex32::mint(&mint::<16>()?)?;
        let epoch = Hex64::mint(&mint::<32>()?)?;
        let limits = serde_json::to_vec(&files.limits).map_err(RecoveryControlError::from_json)?;
        let limits_digest = Hex64::of(&sha2::Sha256::digest(&limits).into());
        let record = ActivationRecord::first(
            control_id.as_str(),
            Initializing {
                intent_id: intent_id.as_str().to_owned(),
                mode,
                host_binding: host.clone(),
                planned_installation: planned.clone(),
                initial_epoch: epoch.as_str().to_owned(),
                limits_digest: limits_digest.as_str().to_owned(),
                init_journal_prefix: JournalPositionRef {
                    context_id: operation,
                    sequence: std::num::NonZeroU64::MIN,
                },
            },
        );
        let (_, digest) = record.encoded()?;
        files.begin_journal(&operation, &control_id, epoch.as_str(), effect)?;
        let clock = files.owner_clock(
            Hex32::mint(&mint::<16>()?)?,
            self.intent.t0_ns,
            &self.intent.bounds,
        )?;
        let first = match legacy {
            None => JournalData::fresh_init(
                host,
                intent_id.as_str(),
                planned,
                self.intent.bounds,
                &digest,
                clock,
            ),
            Some((selection, ids)) => JournalData::legacy_adoption(
                host,
                intent_id.as_str(),
                intent_file,
                selection,
                ids,
                self.intent.bounds,
                &digest,
                clock,
            ),
        };
        files.append_journal(&operation, &first, effect)?;
        files.publish_activation(&record, effect)?;
        drop(files);
        self.head = Some((record, digest));
        self.operation = Some(operation);
        Ok(())
    }

    /// Seal the original Local Fresh reservation before sidecar initdb or schema effects.
    #[cfg(feature = "desktop-local")]
    pub fn seal_local_fresh_before(
        &mut self,
        authority: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        if self.initialization_source() != Some(OrdinaryInitializationSource::LocalPhysicalFresh)
            || self.head.is_some()
        {
            return Err(invalid());
        }
        let SiteExpectation::Local(local) = &self.intent.site else {
            return Err(invalid());
        };
        if local.installation_id.as_deref() != Some(authority.instance_id()) {
            return Err(invalid());
        }
        let mut files = entry::lock(&self.control)?;
        files.verify_local_root_before(local.root.ok_or_else(invalid)?, self.intent.effect)?;
        let host = HostBinding::LocalPhysical {
            actual_os_owner: ActualOsOwner::LocalUid {
                uid: local.root.ok_or_else(invalid)?.uid,
            },
            app_data_parent: local.parent,
            control_root: files.root_identity(self.intent.effect)?,
            reviewed_release_digest: local.release.as_str().to_owned(),
        };
        let planned = PlannedInstallation::LocalPhysical {
            trusted_parent: local.parent,
            entry_component: local.component.clone(),
            installation_id: authority.instance_id().to_owned(),
        };
        drop(files);
        self.seal_site(host, planned, None)?;
        self.intend(OrdinaryStage::Initialize)
    }

    /// Verify the actual Fresh database, canary and original root, then record the
    /// observed completion of that chain. Its internal COMMITs are not fabricated ACKs.
    #[cfg(feature = "desktop-local")]
    pub async fn verify_local_fresh_before(
        &mut self,
        authority: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
        database: &crate::db::desktop_local::DesktopLocalDatabase,
        canary: &crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary,
    ) -> Result<LocalFreshProof, RecoveryControlError> {
        use super::activation::{KeyKind, KeyReference};
        let invalid = || fault(RecoveryControlFault::ControlInvalid);
        if self.initialization_source() != Some(OrdinaryInitializationSource::LocalPhysicalFresh)
            || database.origin() != crate::db::desktop_local::DesktopLocalDatabaseOrigin::Created
            || !canary
                .matches_database(database)
                .await
                .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        let SiteExpectation::Local(local) = &self.intent.site else {
            return Err(invalid());
        };
        let root = local.root.ok_or_else(invalid)?;
        if local.installation_id.as_deref() != Some(authority.instance_id())
            || canary.deployment_id() != authority.auth_context().deployment().as_str()
            || canary.tenant_id() != authority.auth_context().tenant().as_str()
        {
            return Err(invalid());
        }
        let client = database.pool().get().await.map_err(|_| invalid())?;
        native::validate_current(&client)
            .await
            .map_err(|_| invalid())?;
        let version = latest();
        let migration_digest = ledger_checksum(&client, version).await?;
        let site = client.query_one(
            "SELECT pcs.system_identifier::text AS system_identifier, d.oid AS database_oid, current_setting('server_version_num')::int / 10000 AS pg_major FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
            &[],
        ).await.map_err(|_| invalid())?;
        let system: String = site.try_get("system_identifier").map_err(|_| invalid())?;
        let pg_system_id = system
            .parse::<u64>()
            .ok()
            .filter(|id| *id != 0)
            .ok_or_else(invalid)?;
        let database_oid: u32 = site.try_get("database_oid").map_err(|_| invalid())?;
        if database_oid == 0 || site.try_get::<_, i32>("pg_major").ok() != Some(17) {
            return Err(invalid());
        }
        let operation = self.operation()?;
        let installation = authority.instance_id().to_owned();
        let key =
            |kind, service: &str, account: String, key_id: String, key_version| KeyReference {
                kind,
                reviewed_service: service.to_owned(),
                account,
                key_id,
                key_version,
                target_installation_id: installation.clone(),
                operation_id: operation.as_str().to_owned(),
            };
        let actual = OrdinaryLocalSite {
            dataset_id: canary.dataset_id().to_owned(),
            deployment_id: canary.deployment_id().to_owned(),
            tenant_id: canary.tenant_id().to_owned(),
            installation_id: installation.clone(),
            generation_root: root,
            pg_system_id,
            database_oid,
            master: key(
                KeyKind::HistoricalMaster,
                &local.master_service,
                format!("desktop-vault-master-v1-{installation}"),
                canary.key_id().to_owned(),
                u32::try_from(canary.key_version()).map_err(|_| invalid())?,
            ),
            postgres: key(
                KeyKind::PostgresScram,
                &local.postgres_service,
                format!("postgresql-17-{installation}"),
                format!("postgresql-17-{installation}"),
                1,
            ),
        };
        drop(client);
        entry::lock(&self.control)?.verify_local_root_before(root, self.intent.convergence)?;
        let returned = Instant::now();
        let observed_ns = super::clock::monotonic_ns()?;
        if !self.observe(
            Disposition::TaskReturned {
                original_task_id: "local-fresh-chain".to_owned(),
                observed_ns,
            },
            returned <= self.intent.effect,
        )? {
            return Err(fault(RecoveryControlFault::EffectExpired));
        }
        entry::lock(&self.control)?.bind_original_local_pool(database.pool());
        Ok(LocalFreshProof {
            site: actual,
            native_version: version,
            migration_digest,
        })
    }

    /// Append the StageIntent of the next effect (≤E).
    pub(crate) fn intend(&mut self, stage: OrdinaryStage) -> Result<(), RecoveryControlError> {
        let stage = match stage {
            OrdinaryStage::Initialize => Stage::OrdinaryInitialize,
            OrdinaryStage::Verify => Stage::OrdinaryVerify,
            OrdinaryStage::KeySlot => Stage::KeySlot,
        };
        self.intend_stage(stage)
    }

    fn intend_stage(&mut self, stage: Stage) -> Result<(), RecoveryControlError> {
        if self.pending.is_some() {
            return Err(fault(RecoveryControlFault::EntryInvalid));
        }
        let operation = self.operation()?;
        let effect = Hex32::mint(&mint::<16>()?)?;
        let position = entry::lock(&self.control)?.append_journal(
            &operation,
            &JournalData::stage_intent(stage, effect.as_str()),
            self.intent.effect,
        )?;
        self.pending = Some((stage, position.sequence));
        Ok(())
    }

    /// Record the pending stage's resident outcome (≤C: the effect already
    /// happened). Only a confirmed outcome observed by E lets startup go on.
    fn observe(
        &mut self,
        disposition: Disposition,
        timely: bool,
    ) -> Result<bool, RecoveryControlError> {
        let (stage, sequence) = self
            .pending
            .take()
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?;
        let operation = self.operation()?;
        let entry = JournalData::stage_observed(sequence, disposition.clone());
        let confirms = entry.confirms_effect();
        let reference = entry::lock(&self.control)?.append_journal(
            &operation,
            &entry,
            self.intent.convergence,
        )?;
        self.last = Some(disposition);
        let timely = timely && confirms;
        if timely && stage != Stage::ResourceClose {
            self.evidence.push(reference);
        }
        Ok(timely)
    }

    /// COMMIT result returned at `returned`: Ok(true) only for a timely ACK.
    pub(crate) fn observe_commit(
        &mut self,
        acknowledged: bool,
        returned: Instant,
    ) -> Result<bool, RecoveryControlError> {
        let timely = returned <= self.intent.effect;
        let ack = match (acknowledged, timely) {
            (true, true) => CommitAck::TimelyAck,
            (true, false) => CommitAck::AcknowledgedAfterDeadline,
            (false, _) => CommitAck::CommitUnknown,
        };
        self.observe(Disposition::PgCommit(ack), acknowledged && timely)
    }

    /// ROLLBACK result returned at `returned`: Ok(true) only for a timely ACK.
    pub(crate) fn observe_rollback(
        &mut self,
        acknowledged: bool,
        returned: Instant,
    ) -> Result<bool, RecoveryControlError> {
        let timely = returned <= self.intent.effect;
        let ack = match (acknowledged, timely) {
            (true, true) => RollbackAck::TimelyAck,
            (true, false) => RollbackAck::AcknowledgedAfterDeadline,
            (false, _) => RollbackAck::RollbackUnproven,
        };
        self.observe(Disposition::PgRollback(ack), acknowledged && timely)
    }

    /// StageIntent{resource_close} → StageObserved with the operation's last
    /// transaction outcome. It only retires owned resources (≤C).
    fn resource_close(&mut self) -> Result<(), RecoveryControlError> {
        let last = self
            .last
            .clone()
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?;
        let operation = self.operation()?;
        let effect = Hex32::mint(&mint::<16>()?)?;
        let convergence = self.intent.convergence;
        let mut files = entry::lock(&self.control)?;
        let intent = files.append_journal(
            &operation,
            &JournalData::stage_intent(Stage::ResourceClose, effect.as_str()),
            convergence,
        )?;
        files.append_journal(
            &operation,
            &JournalData::stage_observed(intent.sequence, last),
            convergence,
        )?;
        Ok(())
    }

    /// PublishIntent → descriptor → PublishObserved in the open operation (≤E).
    fn publish(
        &mut self,
        phase: ActivationPhase,
        build: impl FnOnce(JournalPositionRef) -> ActivationPayload,
    ) -> Result<(), RecoveryControlError> {
        let (prior, prior_digest) = self
            .head
            .as_ref()
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?;
        let operation = self.operation()?;
        let effect = self.intent.effect;
        let mut files = entry::lock(&self.control)?;
        let position = JournalPositionRef {
            context_id: operation,
            sequence: files.next_journal_sequence()?,
        };
        let next = prior.successor(prior_digest, phase, build(position.clone()))?;
        let (_, digest) = next.encoded()?;
        let intent = files.append_journal(
            &operation,
            &JournalData::publish_intent(phase, &digest),
            effect,
        )?;
        if intent.sequence != position.sequence.get() {
            return Err(fault(RecoveryControlFault::ControlInvalid));
        }
        let published = files.publish_activation(&next, effect)?;
        files.append_journal(
            &operation,
            &JournalData::publish_observed(intent.sequence, &digest, published.identity),
            effect,
        )?;
        drop(files);
        self.head = Some((next, digest));
        Ok(())
    }

    /// Publish `OrdinaryActive` from the proof, then close this operation's
    /// resources; the writer stays held.
    pub fn publish_active(
        &mut self,
        proof: OrdinaryActivationProof,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        let (record, _) = self.head.as_ref().ok_or_else(invalid)?;
        let ActivationPayload::Initializing(initializing) = record.data() else {
            return Err(invalid());
        };
        if self.evidence.is_empty() || self.pending.is_some() {
            return Err(fault(RecoveryControlFault::ClosureUnproven));
        }
        let operation = self.operation()?;
        let binding = match (&self.intent.site, proof) {
            (SiteExpectation::Local(_), OrdinaryActivationProof::LocalFresh(proof)) => {
                ActivationBinding::local(
                    proof.site,
                    proof.native_version,
                    proof.migration_digest,
                    initializing.initial_epoch.clone(),
                    operation,
                )
            }
            (
                SiteExpectation::Server {
                    dataset,
                    ids,
                    service_config,
                    ..
                },
                OrdinaryActivationProof::ServerFresh(proof),
            ) => ActivationBinding::server(
                dataset,
                ids,
                service_config,
                proof.site,
                latest(),
                &proof.migration_digest,
                &initializing.initial_epoch,
                proof.key_id.as_str(),
                operation.as_str(),
            ),
            (
                SiteExpectation::Server {
                    dataset,
                    ids,
                    service_config,
                    ..
                },
                OrdinaryActivationProof::Legacy(proof),
            ) => ActivationBinding::server(
                dataset,
                ids,
                service_config,
                proof.site,
                proof.native_version,
                &proof.migration_digest,
                &initializing.initial_epoch,
                proof.key_id.as_str(),
                operation.as_str(),
            ),
            _ => return Err(invalid()),
        };
        binding.validate(&entry::lock(&self.control)?.limits)?;
        let evidence = self.evidence.clone();
        self.publish(ActivationPhase::OrdinaryActive, |publish_intent| {
            ActivationPayload::Active(Active {
                binding,
                initialization_evidence: evidence,
                publish_intent,
            })
        })?;
        self.resource_close()
    }

    /// Downgrade runtimeEX to SH on the same FD, write the enrollment and
    /// release ownerEX/admissionEX (spec 8073). The held head must be at the
    /// latest native version.
    pub fn into_runtime_before(self) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        let latest_head = self
            .head
            .as_ref()
            .is_some_and(|(record, _)| match record.data() {
                ActivationPayload::Active(active) => active.binding.native_version() == latest(),
                _ => false,
            });
        if !latest_head || self.pending.is_some() {
            return Err(fault(RecoveryControlFault::InitializationRequired));
        }
        let effect = self.intent.effect;
        let entry = {
            let mut files = entry::lock(&self.control)?;
            files.downgrade_runtime_before(effect)?;
            let published = match files.read_head_before(effect)? {
                Head::Published(published)
                    if Some(published.digest()) == self.head.as_ref().map(|(_, d)| d.as_str()) =>
                {
                    published
                }
                _ => return Err(fault(RecoveryControlFault::ControlInvalid)),
            };
            self.intent.expects(published.binding())?;
            files.runtime_entry(published, &self.intent)?
        };
        runtime::enter_runtime(&self.control, entry, effect)
    }
}

/// Ledger checksum of one exact native version.
async fn ledger_checksum(
    client: &tokio_postgres::Client,
    version: u32,
) -> Result<String, RecoveryControlError> {
    let version =
        i32::try_from(version).map_err(|_| fault(RecoveryControlFault::ControlInvalid))?;
    client
        .query_one(
            "SELECT checksum FROM openbot_internal.schema_migrations WHERE version = $1",
            &[&version],
        )
        .await
        .and_then(|row| row.try_get::<_, String>(0))
        .map_err(|_| fault(RecoveryControlFault::ControlInvalid))
}

impl Drop for OrdinaryInitializationSession {
    fn drop(&mut self) {
        // Before seal nothing was written; after seal the head stays where it
        // is and is never retried (spec 8073). Only the held locks go.
        if let Ok(mut files) = entry::lock(&self.control) {
            files.release_writer();
        }
    }
}
