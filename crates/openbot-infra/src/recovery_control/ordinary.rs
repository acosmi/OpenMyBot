//! Ordinary startup: the sealed entry intent, the shared-lock head branch and
//! the exclusive ordinary writer session (spec 7934, 8021, 8067-8073).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::Digest as _;

#[cfg(feature = "desktop-local")]
use super::activation::OrdinaryLocalSite;
use super::activation::{
    ActivationBinding, ActivationPayload, ActivationPhase, ActivationRecord, Active, ActualOsOwner,
    ExpectedServerDatabase, Hex32, Hex64, HostBinding, Initializing, JournalPositionRef,
    JournalReference, OrdinaryMode, OrdinaryStartupBounds, PlannedInstallation,
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
    #[cfg(feature = "desktop-local")]
    LocalPhysicalFresh,
    ServerDatabaseFresh,
    LegacyAdoption {
        site: OrdinarySite,
    },
}

pub(super) type SealedSource = (OrdinaryInitializationSource, Hex32, RecoveryFileIdentity);

/// A published head below this binary's latest native version, seen under SH
/// and handed back with its digest. The exclusive writer adopts
/// exactly that head as a known site; another head is `OwnerBusy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ExpectedHead {
    ActiveBelowLatest(String),
    CurrentBelowLatest(String),
}

impl ExpectedHead {
    fn matches(&self, published: &PublishedActivation) -> bool {
        let (phase, digest) = match self {
            Self::ActiveBelowLatest(digest) => (ActivationPhase::OrdinaryActive, digest),
            Self::CurrentBelowLatest(digest) => (ActivationPhase::RestoreCurrent, digest),
        };
        published.observation().record.phase == phase && published.digest() == digest
    }
}

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
    #[cfg(feature = "desktop-local")]
    Local(LocalSiteExpectation),
}

#[cfg(feature = "desktop-local")]
pub(super) struct LocalSiteExpectation {
    pub(super) root: Option<RecoveryFileIdentity>,
    pub(super) parent: RecoveryFileIdentity,
    pub(super) component: String,
    pub(super) release: Hex64,
    pub(super) master_service: String,
    pub(super) postgres_service: String,
    pub(super) installation_id: Option<String>,
    pub(super) legacy_expected: Option<BusinessAndInstallation>,
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
    local_request: Option<entry::VerifiedRecoveryHostIntent>,
    expected_head: Option<ExpectedHead>,
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
            #[cfg(feature = "desktop-local")]
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
            local_request: None,
            expected_head: None,
            #[cfg(feature = "desktop-local")]
            fresh_installation: None,
        })
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn seal_local_legacy(
        source: SealedSource,
        site: SiteExpectation,
        bounds: OrdinaryStartupBounds,
        admission_ns: u64,
        owners: &[RuntimeOwner],
        request: entry::VerifiedRecoveryHostIntent,
        request_deadline: Instant,
    ) -> Result<Self, RecoveryControlError> {
        match Self::seal(Some(source), site, bounds, admission_ns, owners) {
            Ok(mut intent) => {
                intent.admission = intent.admission.min(request_deadline);
                intent.local_request = Some(request);
                Ok(intent)
            }
            Err(mut error) => {
                error.retained_restore_intent = Some(Box::new(request));
                Err(error)
            }
        }
    }

    /// The below-latest head a shared-lock branch handed this intent back for.
    #[cfg(all(test, feature = "desktop-local"))]
    pub(super) fn expected_head(&self) -> Option<&ExpectedHead> {
        self.expected_head.as_ref()
    }

    /// Deadline A: lock acquisition and the shared-lock head read.
    #[must_use]
    pub fn admission_deadline(&self) -> Instant {
        self.admission
    }

    pub(super) fn server_dataset(&self) -> Result<Hex32, RecoveryControlError> {
        match &self.site {
            SiteExpectation::Server { dataset, .. } => Ok(*dataset),
            #[cfg(feature = "desktop-local")]
            SiteExpectation::Local(_) => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    pub(super) fn effect_deadline(&self) -> Instant {
        self.effect
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn convergence_deadline(&self) -> Instant {
        self.convergence
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
            #[cfg(feature = "desktop-local")]
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
            if let (SiteExpectation::Local(local), Some(creator)) = (&mut intent.site, creator)
                && local.root.is_none()
            {
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
    let below = published.binding().native_version() < latest();
    #[cfg(feature = "desktop-local")]
    if published.observation().record.phase == ActivationPhase::RestoreCurrent
        && let SiteExpectation::Local(expected) = &mut intent.site
    {
        let plan = published
            .restore_plan()
            .ok_or_else(|| fault(RecoveryControlFault::ControlInvalid))?;
        if expected.parent != plan.trusted_parent {
            files.release_registration_attempt();
            return Err(fault(RecoveryControlFault::EntryInvalid));
        }
        expected.root = Some(files.select_restored_local_root_before(&published, admission)?);
        expected.component = plan.entry_component.clone();
    }
    // Server adoption needs the operator's migrated database and its
    // legacy_adoption intent; that intent edits the
    // service configuration, which the republished head binds instead.
    let rebound = match &intent.site {
        SiteExpectation::Server { service_config, .. }
            if below
                && intent.source.map(|(source, _, _)| source)
                    == Some(OrdinaryInitializationSource::LegacyAdoption {
                        site: OrdinarySite::ServerDatabase,
                    }) =>
        {
            Some(published.binding().with_service_config(service_config))
        }
        _ => None,
    };
    if let Err(error) = intent.expects(rebound.as_ref().unwrap_or(published.binding())) {
        files.release_registration_attempt();
        return Err(error);
    }
    if below {
        files.release_registration_attempt();
        if matches!(intent.site, SiteExpectation::Server { .. }) && rebound.is_none() {
            return Err(initialization_required(None));
        }
        let digest = published.digest().to_owned();
        intent.expected_head = Some(match published.observation().record.phase {
            ActivationPhase::OrdinaryActive => ExpectedHead::ActiveBelowLatest(digest),
            _ => ExpectedHead::CurrentBelowLatest(digest),
        });
        return Err(initialization_required(Some(intent)));
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

#[cfg(feature = "desktop-local")]
enum LocalLegacyTerminal {
    Commit(Result<(), crate::db::pool::TransactionOwnerError>),
    Rollback(Result<(), crate::db::pool::TransactionOwnerError>),
}

#[derive(Default)]
#[cfg(feature = "desktop-local")]
struct LocalLegacySql {
    client: Option<crate::db::pool::GuardedClient>,
    checkout: Option<
        Result<
            Result<crate::db::pool::GuardedClient, crate::db::pool::PoolError>,
            tokio::time::error::Elapsed,
        >,
    >,
    begin: Option<
        Result<Result<(), crate::db::pool::TransactionOwnerError>, tokio::time::error::Elapsed>,
    >,
    canary: Option<
        Result<
            Result<bool, crate::db::desktop_vault_canary::DesktopVaultCanaryError>,
            tokio::time::error::Elapsed,
        >,
    >,
    layout: Option<
        Result<
            Result<
                crate::db::desktop_vault_canary::ValidatedDesktopVaultLayout,
                crate::db::InfraError,
            >,
            tokio::time::error::Elapsed,
        >,
    >,
    validation: Option<Result<Result<(), crate::db::InfraError>, tokio::time::error::Elapsed>>,
    row: Option<
        Result<Result<tokio_postgres::Row, tokio_postgres::Error>, tokio::time::error::Elapsed>,
    >,
    statement: Option<Result<Result<(), tokio_postgres::Error>, tokio::time::error::Elapsed>>,
    count: Option<Result<Result<u64, tokio_postgres::Error>, tokio::time::error::Elapsed>>,
    terminal: Option<LocalLegacyTerminal>,
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
    #[cfg(feature = "desktop-local")]
    local_sql: LocalLegacySql,
}

/// Closed proofs a sealed initialization publishes; none is publicly
/// constructible.
pub enum OrdinaryActivationProof {
    ServerFresh(OrdinaryDatabaseInitializationProof),
    #[cfg(feature = "desktop-local")]
    LocalFresh(LocalFreshProof),
    Legacy(VerifiedOrdinaryLegacyProof),
}

/// Facts of the original Local Fresh chain, observed after its canary and schema succeed.
#[cfg(feature = "desktop-local")]
pub struct LocalFreshProof {
    pub(super) site: OrdinaryLocalSite,
    pub(super) native_version: u32,
    pub(super) migration_digest: String,
}

/// Legacy adoption facts read back after the read-only site checks (S9).
pub struct VerifiedOrdinaryLegacyProof {
    pub(super) operation: Hex32,
    pub(super) site: LegacySite,
    pub(crate) native_version: u32,
    pub(crate) migration_digest: String,
}

#[cfg_attr(
    feature = "desktop-local",
    expect(
        clippy::large_enum_variant,
        reason = "Original Local site proofs stay inline in the already admitted session custody"
    )
)]
pub(super) enum LegacySite {
    #[cfg(feature = "desktop-local")]
    Local(OrdinaryLocalSite),
    Server {
        site: ServerDatabaseSite,
        key_id: Hex32,
    },
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
    let mut original = Some(intent);
    let result = (|| {
        let intent = original.as_mut().expect("original intent retained");
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
        let adopted = match (&head, &intent.expected_head) {
            (Head::Absent, None) if intent.source.is_some() => None,
            (Head::Published(published), Some(expected)) if expected.matches(published) => {
                let record = published.observation().record.clone();
                let digest = published.digest().to_owned();
                // A known Local site has no request file: the held published
                // descriptor is the positive intent.
                #[cfg(feature = "desktop-local")]
                if let SiteExpectation::Local(local) = &mut intent.site {
                    let binding = published.binding().ordinary_local()?;
                    let identity = files
                        .activation_source
                        .as_ref()
                        .ok_or_else(|| fault(RecoveryControlFault::ControlInvalid))?
                        .identity;
                    local.installation_id = Some(binding.installation_id.to_owned());
                    local.legacy_expected = Some(BusinessAndInstallation {
                        deployment_id: binding.deployment_id.to_owned(),
                        tenant_id: binding.tenant_id.to_owned(),
                        dataset_id: binding.dataset_id.to_owned(),
                        source_installation_id: binding.installation_id.to_owned(),
                        target_installation_id: binding.installation_id.to_owned(),
                    });
                    intent.source = Some((
                        OrdinaryInitializationSource::LegacyAdoption {
                            site: OrdinarySite::LocalPhysical,
                        },
                        Hex32::mint(&mint::<16>()?)?,
                        identity,
                    ));
                }
                Some((record, digest))
            }
            _ => {
                files.release_writer();
                return Err(fault(RecoveryControlFault::OwnerBusy));
            }
        };
        #[cfg(feature = "desktop-local")]
        if adopted.is_none()
            && intent.source.is_some_and(|(source, _, _)| {
                source
                    == OrdinaryInitializationSource::LegacyAdoption {
                        site: OrdinarySite::LocalPhysical,
                    }
            })
            && let Err(error) = files.require_empty_legacy_control_before(admission)
        {
            files.release_writer();
            return Err(error);
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
            intent: original.take().expect("original intent transferred once"),
            head: adopted,
            operation: None,
            pending: None,
            last: None,
            evidence: Vec::new(),
            #[cfg(feature = "desktop-local")]
            local_sql: LocalLegacySql::default(),
        })
    })();
    result.map_err(|mut error: RecoveryControlError| {
        error.unconsumed = original.take().map(Box::new);
        error.retain(control)
    })
}

impl OrdinaryInitializationSession {
    /// Whether this original session holds a Local Fresh creation witness.
    #[cfg(feature = "desktop-local")]
    pub fn is_local_fresh(&self) -> bool {
        self.initialization_source() == Some(OrdinaryInitializationSource::LocalPhysicalFresh)
    }

    /// Read the selected existing installation under this original legacy owner.
    #[cfg(feature = "desktop-local")]
    pub fn load_local_legacy_installation_before(
        &self,
        store: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
    ) -> Result<
        crate::auth::single_user::desktop_local::DesktopLocalInstallation,
        RecoveryControlError,
    > {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        if !self.is_local_legacy() || self.head.is_none() {
            return Err(invalid());
        }
        let SiteExpectation::Local(expected) = &self.intent.site else {
            return Err(invalid());
        };
        let installation = store.load_existing_installation().map_err(|_| invalid())?;
        entry::lock(&self.control)?
            .verify_local_root_before(expected.root.ok_or_else(invalid)?, self.intent.effect)?;
        if expected.installation_id.as_deref() != Some(installation.authority().instance_id()) {
            return Err(invalid());
        }
        Ok(installation)
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
            #[cfg(feature = "desktop-local")]
            SiteExpectation::Local(_) => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    /// Original effect deadline; borrowing it never renews this initialization.
    pub fn effect_deadline(&self) -> Instant {
        self.intent.effect
    }

    /// Original convergence deadline for retiring this owner's resources.
    pub fn convergence_deadline(&self) -> Instant {
        self.intent.convergence
    }

    /// Whether this owner consumed a Local legacy adoption request.
    pub fn is_local_legacy(&self) -> bool {
        self.initialization_source()
            == Some(OrdinaryInitializationSource::LegacyAdoption {
                site: OrdinarySite::LocalPhysical,
            })
    }

    /// Whether this writer adopts a published head below the latest native
    /// version as a known site.
    pub fn adopts_published_head(&self) -> bool {
        self.intent.expected_head.is_some()
    }

    /// The binding of the published head this writer adopts.
    pub(super) fn published_binding(&self) -> Result<&ActivationBinding, RecoveryControlError> {
        match (
            &self.intent.expected_head,
            self.head.as_ref().map(|(record, _)| record.data()),
        ) {
            (Some(_), Some(ActivationPayload::Active(active))) => Ok(&active.binding),
            (Some(_), Some(ActivationPayload::Current(current))) => Ok(&current.binding),
            _ => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    /// Open the legacy adoption operation of the held published head: its
    /// OperationIntent names that head's digest, the envelope keeps the
    /// binding epoch, and no head is published before the proof.
    /// Then the ordinary_verify StageIntent.
    pub(super) fn seal_published(&mut self) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        if self.operation.is_some() {
            return Err(invalid());
        }
        let (record, digest) = self.head.clone().ok_or_else(invalid)?;
        let binding = self.published_binding()?.clone();
        let (_, intent_id, intent_file) = self.intent.source.ok_or_else(invalid)?;
        let effect = self.intent.effect;
        let mut files = entry::lock(&self.control)?;
        let control_root = files.root_identity(effect)?;
        let (host, selection, ids) = match &self.intent.site {
            SiteExpectation::Server {
                ids,
                service_config,
                owner,
                database,
                ..
            } => {
                let actual = binding.ordinary_server()?;
                (
                    HostBinding::ServerDatabase {
                        actual_os_owner: owner.clone(),
                        service_config: service_config.clone(),
                        control_root,
                        server_database: actual.server_database.clone(),
                    },
                    SiteSelection::ServerDatabase {
                        service_config: service_config.clone(),
                        expected_server_database: *database,
                    },
                    BusinessAndInstallation {
                        deployment_id: ids[0].clone(),
                        tenant_id: ids[1].clone(),
                        dataset_id: actual.dataset_id.to_owned(),
                        source_installation_id: ids[2].clone(),
                        target_installation_id: ids[3].clone(),
                    },
                )
            }
            #[cfg(feature = "desktop-local")]
            SiteExpectation::Local(local) => {
                let root = local.root.ok_or_else(invalid)?;
                (
                    HostBinding::LocalPhysical {
                        actual_os_owner: ActualOsOwner::LocalUid { uid: root.uid },
                        app_data_parent: local.parent,
                        control_root,
                        reviewed_release_digest: local.release.as_str().to_owned(),
                    },
                    SiteSelection::LocalPhysical {
                        trusted_parent: local.parent,
                        entry_component: local.component.clone(),
                    },
                    local.legacy_expected.clone().ok_or_else(invalid)?,
                )
            }
        };
        files.verify_head_digest(&digest, effect)?;
        let clock = files.owner_clock(
            Hex32::mint(&mint::<16>()?)?,
            self.intent.t0_ns,
            &self.intent.bounds,
        )?;
        let control_id = Hex32::parse(&record.control_id)?;
        let epoch = match record.data() {
            ActivationPayload::Current(current) => current.epoch.as_str(),
            _ => binding.authorization_epoch(),
        };
        self.operation = Some(intent_id);
        files.begin_journal(&intent_id, &control_id, epoch, effect)?;
        files.append_journal(
            &intent_id,
            &JournalData::legacy_adoption(
                host,
                intent_id.as_str(),
                intent_file,
                selection,
                ids,
                self.intent.bounds,
                &digest,
                clock,
            ),
            effect,
        )?;
        drop(files);
        self.intend(OrdinaryStage::Verify)
    }

    /// The sealed source of this original initialization session.
    pub(super) fn initialization_source(&self) -> Option<OrdinaryInitializationSource> {
        self.intent.source.map(|(source, _, _)| source)
    }

    pub(super) fn operation(&self) -> Result<Hex32, RecoveryControlError> {
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
        let (dataset, ids, database, service_config, owner) = match &self.intent.site {
            SiteExpectation::Server {
                dataset,
                ids,
                database,
                service_config,
                owner,
            } => (dataset, ids, database, service_config, owner),
            #[cfg(feature = "desktop-local")]
            SiteExpectation::Local(_) => return Err(invalid()),
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
        if self.operation.is_some() {
            return Err(fault(RecoveryControlFault::EntryInvalid));
        }
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
        let operation = if legacy.is_some() {
            intent_id
        } else {
            Hex32::mint(&mint::<16>()?)?
        };
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
        // Keep the original operation even when its first durable write is unknown.
        self.operation = Some(operation);
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

    /// Seal the original positive Local legacy request before sidecar or schema effects.
    #[cfg(feature = "desktop-local")]
    pub fn seal_local_legacy_before(&mut self) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        if self.initialization_source()
            != Some(OrdinaryInitializationSource::LegacyAdoption {
                site: OrdinarySite::LocalPhysical,
            })
            || self.head.is_some()
        {
            return Err(invalid());
        }
        let SiteExpectation::Local(local) = &self.intent.site else {
            return Err(invalid());
        };
        let expected = local.legacy_expected.as_ref().ok_or_else(invalid)?.clone();
        let mut files = entry::lock(&self.control)?;
        files.verify_local_root_before(local.root.ok_or_else(invalid)?, self.intent.effect)?;
        entry::recheck_legacy_request_before(
            &mut files,
            self.intent.local_request.as_mut().ok_or_else(invalid)?,
            self.intent.effect,
        )?;
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
            installation_id: expected.target_installation_id.clone(),
        };
        let selection = SiteSelection::LocalPhysical {
            trusted_parent: local.parent,
            entry_component: local.component.clone(),
        };
        drop(files);
        self.seal_site(host, planned, Some((selection, expected)))?;
        self.intend(OrdinaryStage::Verify)
    }

    #[cfg(feature = "desktop-local")]
    fn local_effect_before(&self) -> Result<(), RecoveryControlError> {
        entry::lock(&self.control)?.post(self.intent.effect)
    }

    /// Verify and, only for strict52, migrate the original legacy installation
    /// inside its existing Initializing/ordinary_verify owner.
    #[cfg(all(feature = "desktop-local", feature = "server-runtime"))]
    pub async fn verify_local_legacy_before(
        &mut self,
        authority: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
        database: &crate::db::desktop_local::DesktopLocalDatabase,
        canary: &crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary,
    ) -> Result<VerifiedOrdinaryLegacyProof, RecoveryControlError> {
        use super::activation::{KeyKind, KeyReference};
        use crate::db::pool::TransactionOwnerError;
        let invalid = || fault(RecoveryControlFault::ControlInvalid);
        if self.initialization_source()
            != Some(OrdinaryInitializationSource::LegacyAdoption {
                site: OrdinarySite::LocalPhysical,
            })
            || self.pending.as_ref().map(|pending| pending.0) != Some(Stage::OrdinaryVerify)
            || self.local_sql.client.is_some()
            || self.local_sql.checkout.is_some()
            || self.local_sql.begin.is_some()
            || database.origin() == crate::db::desktop_local::DesktopLocalDatabaseOrigin::Created
        {
            return Err(invalid());
        }
        let SiteExpectation::Local(local) = &self.intent.site else {
            return Err(invalid());
        };
        let expected = local.legacy_expected.as_ref().ok_or_else(invalid)?;
        if local.installation_id.as_deref() != Some(authority.instance_id())
            || expected.target_installation_id != authority.instance_id()
            || expected.dataset_id != canary.dataset_id()
            || expected.deployment_id != canary.deployment_id()
            || expected.tenant_id != canary.tenant_id()
            || expected.deployment_id != authority.auth_context().deployment().as_str()
            || expected.tenant_id != authority.auth_context().tenant().as_str()
        {
            return Err(invalid());
        }
        let root = local.root.ok_or_else(invalid)?;
        let master_service = local.master_service.clone();
        let postgres_service = local.postgres_service.clone();
        self.local_sql.canary = Some(
            tokio::time::timeout_at(tokio::time::Instant::from_std(self.intent.effect), async {
                canary.matches_database(database).await
            })
            .await,
        );
        self.local_effect_before()?;
        if !matches!(self.local_sql.canary, Some(Ok(Ok(true)))) {
            return Err(invalid());
        }
        entry::lock(&self.control)?.prepay(
            (std::mem::size_of::<LocalLegacySql>()
                + std::mem::size_of::<crate::db::pool::GuardedClient>()) as u64,
            0,
        )?;
        self.local_sql.checkout = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(self.intent.effect),
                database.pool().get_guarded(self.intent.convergence),
            )
            .await,
        );
        self.local_effect_before()?;
        if !matches!(self.local_sql.checkout, Some(Ok(Ok(_)))) {
            return Err(fault(RecoveryControlFault::IoFailure));
        }
        self.local_sql.client = match self.local_sql.checkout.take().expect("resident checkout") {
            Ok(Ok(client)) => Some(client),
            _ => unreachable!("checked original checkout"),
        };
        let client = self
            .local_sql
            .client
            .as_ref()
            .ok_or_else(|| fault(RecoveryControlFault::IoFailure))?;
        self.local_sql.layout = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(self.intent.effect),
                crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(client.as_client()),
            )
            .await,
        );
        self.local_effect_before()?;
        let version = self
            .local_sql
            .layout
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(invalid)?
            .native_version();
        if version != native::NATIVE_0052_VERSION
            && version != native::NATIVE_0053_VERSION
            && version != native::NATIVE_LATEST_VERSION
        {
            return Err(invalid());
        }
        let mut client = self
            .local_sql
            .client
            .take()
            .expect("original client resident");
        let stage_result = {
            match tokio::time::timeout_at(
                tokio::time::Instant::from_std(self.intent.effect),
                async {
                    if version == native::NATIVE_LATEST_VERSION {
                        client.begin_read_committed_read_only().await
                    } else {
                        client.begin_read_committed().await
                    }
                },
            )
            .await
            {
                Err(error) => {
                    self.local_sql.begin = Some(Err(error));
                    Err(fault(RecoveryControlFault::EffectExpired))
                }
                Ok(Err(error)) => {
                    self.local_sql.begin = Some(Ok(Err(error)));
                    Err(fault(RecoveryControlFault::IoFailure))
                }
                Ok(Ok(owner)) => {
                    self.local_sql.begin = Some(Ok(Ok(())));
                    let transaction = owner.as_transaction();
                    let verified: Result<bool, RecoveryControlError> = async {
                        let end = tokio::time::Instant::from_std(self.intent.effect);
                        self.local_effect_before()?;
                        self.local_sql.validation = Some(tokio::time::timeout_at(end, native::lock_migrations(transaction)).await);
                        self.local_effect_before()?;
                        if !matches!(self.local_sql.validation, Some(Ok(Ok(())))) { return Err(invalid()); }
                        self.local_sql.validation = Some(tokio::time::timeout_at(end, async {
                            match version {
                                native::NATIVE_0052_VERSION => native::validate_custom_model_v2_layout_in_transaction(transaction, native::NATIVE_0052_VERSION, 40).await,
                                native::NATIVE_0053_VERSION => native::validate_custom_model_v2_layout_in_transaction(transaction, native::NATIVE_0053_VERSION, 41).await,
                                _ => native::validate_custom_model_v2_in_transaction(transaction).await,
                            }
                        }).await);
                        self.local_effect_before()?;
                        if !matches!(self.local_sql.validation, Some(Ok(Ok(())))) { return Err(invalid()); }
                        self.local_sql.row = Some(tokio::time::timeout_at(end, transaction.query_one("SELECT to_regclass('openbot_internal.restore_pg_operations') IS NOT NULL", &[])).await);
                        self.local_effect_before()?;
                        let exists: bool = self.local_sql.row.as_ref().and_then(|r| r.as_ref().ok()).and_then(|r| r.as_ref().ok()).ok_or_else(invalid)?.try_get(0).map_err(|_| invalid())?;
                        if exists {
                            self.local_sql.row = Some(tokio::time::timeout_at(end, transaction.query_one("SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations)", &[])).await);
                            self.local_effect_before()?;
                            if self.local_sql.row.as_ref().and_then(|r| r.as_ref().ok()).and_then(|r| r.as_ref().ok()).ok_or_else(invalid)?.try_get::<_,bool>(0).map_err(|_| invalid())? { return Err(invalid()); }
                        }
                        // A strict prior layout (52 or 53) upgrades through every registered increment.
                        type PendingMigration = (i32, &'static str, &'static str, fn() -> String);
                        let pending: &[PendingMigration] = match version {
                            native::NATIVE_0052_VERSION => &[
                                (native::NATIVE_0053_VERSION, native::NATIVE_0053_NAME, native::NATIVE_0053_SQL, native::native_0053_checksum),
                                (native::NATIVE_0054_VERSION, native::NATIVE_0054_NAME, native::NATIVE_0054_SQL, native::native_0054_checksum),
                            ],
                            native::NATIVE_0053_VERSION => &[
                                (native::NATIVE_0054_VERSION, native::NATIVE_0054_NAME, native::NATIVE_0054_SQL, native::native_0054_checksum),
                            ],
                            _ => &[],
                        };
                        for (next, name, sql, checksum) in pending {
                            self.local_effect_before()?;
                            self.local_sql.statement = Some(tokio::time::timeout_at(end, transaction.batch_execute(sql)).await);
                            self.local_effect_before()?;
                            if !matches!(self.local_sql.statement, Some(Ok(Ok(())))) { return Err(invalid()); }
                            let checksum = checksum();
                            self.local_sql.count = Some(tokio::time::timeout_at(end, transaction.execute("INSERT INTO openbot_internal.schema_migrations(version,name,checksum) VALUES($1,$2,$3)", &[next, name, &checksum])).await);
                            self.local_effect_before()?;
                            if !matches!(self.local_sql.count, Some(Ok(Ok(1)))) { return Err(invalid()); }
                        }
                        self.local_sql.validation = Some(tokio::time::timeout_at(end, native::validate_custom_model_v2_in_transaction(transaction)).await);
                        self.local_effect_before()?;
                        if !matches!(self.local_sql.validation, Some(Ok(Ok(())))) { return Err(invalid()); }
                        Ok(version != native::NATIVE_LATEST_VERSION)
                    }.await;
                    self.local_sql.terminal = Some(if matches!(verified, Ok(true)) {
                        LocalLegacyTerminal::Commit(owner.commit_before(self.intent.effect).await)
                    } else {
                        LocalLegacyTerminal::Rollback(
                            owner.rollback_before(self.intent.convergence).await,
                        )
                    });
                    verified
                }
            }
        };
        self.local_sql.client = Some(client);
        let returned = Instant::now();
        let observation = match self.local_sql.terminal.as_ref() {
            Some(LocalLegacyTerminal::Commit(Ok(()))) => {
                Some((Disposition::PgCommit(CommitAck::TimelyAck), true, None))
            }
            Some(LocalLegacyTerminal::Commit(Err(
                TransactionOwnerError::CommitAcknowledgedAfterDeadline,
            ))) => Some((
                Disposition::PgCommit(CommitAck::AcknowledgedAfterDeadline),
                false,
                Some(RecoveryControlFault::EffectExpired),
            )),
            Some(LocalLegacyTerminal::Commit(Err(TransactionOwnerError::CommitUnknown))) => Some((
                Disposition::PgCommit(CommitAck::CommitUnknown),
                false,
                Some(RecoveryControlFault::DatabaseUnknown),
            )),
            Some(LocalLegacyTerminal::Commit(Err(_))) => Some((
                Disposition::PgRollback(RollbackAck::RollbackUnproven),
                false,
                Some(RecoveryControlFault::EffectExpired),
            )),
            Some(LocalLegacyTerminal::Rollback(Ok(()))) => {
                let timely = returned <= self.intent.effect;
                Some((
                    Disposition::PgRollback(if timely {
                        RollbackAck::TimelyAck
                    } else {
                        RollbackAck::AcknowledgedAfterDeadline
                    }),
                    timely,
                    (!timely).then_some(RecoveryControlFault::EffectExpired),
                ))
            }
            Some(LocalLegacyTerminal::Rollback(Err(
                TransactionOwnerError::RollbackAcknowledgedAfterDeadline,
            ))) => Some((
                Disposition::PgRollback(RollbackAck::AcknowledgedAfterDeadline),
                false,
                Some(RecoveryControlFault::ConvergenceExpired),
            )),
            Some(LocalLegacyTerminal::Rollback(Err(_))) => Some((
                Disposition::PgRollback(RollbackAck::RollbackUnproven),
                false,
                Some(RecoveryControlFault::DatabaseUnknown),
            )),
            None => None,
        };
        let recorded = match observation {
            Some((disposition, timely, failure)) => {
                self.observe(disposition, timely).map(|_| ())?;
                failure
            }
            None => None,
        };
        stage_result?;
        if let Some(failure) = recorded {
            return Err(fault(failure));
        }
        self.local_effect_before()?;
        let client = self
            .local_sql
            .client
            .as_ref()
            .expect("original client restored before clock checks");
        self.local_sql.layout = Some(
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(self.intent.effect),
                crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(client.as_client()),
            )
            .await,
        );
        self.local_effect_before()?;
        if self
            .local_sql
            .layout
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(invalid)?
            .native_version()
            != native::NATIVE_LATEST_VERSION
        {
            return Err(invalid());
        }
        let client = self
            .local_sql
            .client
            .as_ref()
            .expect("original client retained");
        self.local_sql.row = Some(tokio::time::timeout_at(tokio::time::Instant::from_std(self.intent.effect), async { client.as_client().query_one("SELECT pcs.system_identifier::text AS system_identifier,d.oid AS database_oid,current_setting('server_version_num')::int / 10000 AS pg_major FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()", &[]).await }).await);
        self.local_effect_before()?;
        let row = self
            .local_sql
            .row
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(invalid)?;
        let system: String = row.try_get("system_identifier").map_err(|_| invalid())?;
        let pg_system_id = system
            .parse::<u64>()
            .ok()
            .filter(|id| *id != 0)
            .ok_or_else(invalid)?;
        let database_oid: u32 = row.try_get("database_oid").map_err(|_| invalid())?;
        if database_oid == 0 || row.try_get::<_, i32>("pg_major").ok() != Some(17) {
            return Err(invalid());
        }
        self.local_sql.canary = Some(
            tokio::time::timeout_at(tokio::time::Instant::from_std(self.intent.effect), async {
                canary.matches_database(database).await
            })
            .await,
        );
        self.local_effect_before()?;
        if !matches!(self.local_sql.canary, Some(Ok(Ok(true)))) {
            return Err(invalid());
        }
        let mut files = entry::lock(&self.control)?;
        files.verify_local_root_before(root, self.intent.effect)?;
        // A known site's positive intent is its published head, already
        // rechecked when sealed; a first adoption rechecks its request file.
        if self.intent.expected_head.is_none() {
            entry::recheck_legacy_request_before(
                &mut files,
                self.intent.local_request.as_mut().ok_or_else(invalid)?,
                self.intent.effect,
            )?;
        }
        files.bind_original_local_pool(database.pool());
        drop(files);
        let operation = self.operation()?;
        let installation = authority.instance_id().to_owned();
        let master = KeyReference {
            kind: KeyKind::HistoricalMaster,
            reviewed_service: master_service,
            account: format!("desktop-vault-master-v1-{installation}"),
            key_id: canary.key_id().to_owned(),
            key_version: u32::try_from(canary.key_version()).map_err(|_| invalid())?,
            target_installation_id: installation.clone(),
            operation_id: operation.as_str().to_owned(),
        };
        let postgres = KeyReference {
            kind: KeyKind::PostgresScram,
            reviewed_service: postgres_service,
            account: format!("postgresql-17-{installation}"),
            key_id: format!("postgresql-17-{installation}"),
            key_version: 1,
            target_installation_id: installation.clone(),
            operation_id: operation.as_str().to_owned(),
        };
        let client = self
            .local_sql
            .client
            .as_ref()
            .expect("original client retained");
        self.local_sql.row = Some(tokio::time::timeout_at(tokio::time::Instant::from_std(self.intent.effect), async { client.as_client().query_one("SELECT version,checksum FROM openbot_internal.schema_migrations WHERE version=$1", &[&native::NATIVE_LATEST_VERSION]).await }).await);
        self.local_effect_before()?;
        let row = self
            .local_sql
            .row
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(invalid)?;
        let actual_version: i32 = row.try_get("version").map_err(|_| invalid())?;
        let migration_digest: String = row.try_get("checksum").map_err(|_| invalid())?;
        if actual_version != native::NATIVE_LATEST_VERSION
            || migration_digest != native::native_0054_checksum()
        {
            return Err(invalid());
        }
        Ok(VerifiedOrdinaryLegacyProof {
            operation,
            site: LegacySite::Local(OrdinaryLocalSite {
                dataset_id: canary.dataset_id().to_owned(),
                deployment_id: canary.deployment_id().to_owned(),
                tenant_id: canary.tenant_id().to_owned(),
                installation_id: installation,
                generation_root: root,
                pg_system_id,
                database_oid,
                master,
                postgres,
            }),
            native_version: actual_version.unsigned_abs(),
            migration_digest,
        })
    }
    /// Admit the adopted database's original admin driver observations into
    /// this owner's ordinary control budget: each driver holds one
    /// socket, charged against the release hostLimits `maxOpenFiles`, with its
    /// observation handle as metadata. Missing observations stay
    /// `ClosureUnproven`.
    #[cfg(feature = "desktop-local")]
    pub fn admit_admin_observations(
        &self,
        database: &crate::db::desktop_local::DesktopLocalDatabase,
    ) -> Result<Vec<crate::db::pool::ConnectionObservation>, RecoveryControlError> {
        let observations = database
            .admin_observations()
            .ok_or_else(|| fault(RecoveryControlFault::ClosureUnproven))?;
        let count = observations.len() as u64;
        let bytes = count
            .checked_mul(std::mem::size_of::<crate::db::pool::ConnectionObservation>() as u64)
            .ok_or_else(|| fault(RecoveryControlFault::CapacityExceeded))?;
        entry::lock(&self.control)?.prepay(bytes, count)?;
        Ok(observations.to_vec())
    }

    /// Ordinary Local startup below the latest native version:
    /// the read-only check of the running site against the published binding,
    /// the legacy adoption operation of that head, the original ordinary_verify
    /// transaction with its registered increments, then the republished head.
    /// The caller then takes `into_runtime_before`.
    #[cfg(all(feature = "desktop-local", feature = "server-runtime"))]
    pub async fn adopt_local_published_before(
        &mut self,
        authority: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
        database: &crate::db::desktop_local::DesktopLocalDatabase,
        canary: &crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary,
    ) -> Result<(), RecoveryControlError> {
        let SiteExpectation::Local(local) = &self.intent.site else {
            return Err(fault(RecoveryControlFault::EntryInvalid));
        };
        let services = [local.master_service.clone(), local.postgres_service.clone()];
        entry::verify_local_binding_before(
            &self.control,
            self.published_binding()?,
            Some(authority),
            database,
            canary,
            [services[0].as_str(), services[1].as_str()],
            self.intent.effect,
        )
        .await?;
        self.seal_published()?;
        let proof = self
            .verify_local_legacy_before(authority, database, canary)
            .await?;
        self.publish_active(OrdinaryActivationProof::Legacy(proof))
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
        if self.evidence.is_empty() || self.pending.is_some() {
            return Err(fault(RecoveryControlFault::ClosureUnproven));
        }
        if self.intent.expected_head.is_some() {
            return self.publish_adopted(proof);
        }
        let (record, _) = self.head.as_ref().ok_or_else(invalid)?;
        let ActivationPayload::Initializing(initializing) = record.data() else {
            return Err(invalid());
        };
        let operation = self.operation()?;
        if let OrdinaryActivationProof::Legacy(legacy) = &proof {
            if legacy.operation != operation {
                return Err(invalid());
            }
            #[cfg(feature = "desktop-local")]
            if let (SiteExpectation::Local(expected), LegacySite::Local(site)) =
                (&self.intent.site, &legacy.site)
            {
                let business = expected.legacy_expected.as_ref().ok_or_else(invalid)?;
                if expected.root != Some(site.generation_root)
                    || expected.installation_id.as_deref() != Some(site.installation_id.as_str())
                    || business.target_installation_id != site.installation_id
                    || business.dataset_id != site.dataset_id
                    || business.deployment_id != site.deployment_id
                    || business.tenant_id != site.tenant_id
                {
                    return Err(invalid());
                }
            }
        }
        let binding = match (&self.intent.site, proof) {
            #[cfg(feature = "desktop-local")]
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
                OrdinaryActivationProof::Legacy(VerifiedOrdinaryLegacyProof {
                    site: LegacySite::Server { site, key_id },
                    native_version,
                    migration_digest,
                    ..
                }),
            ) => ActivationBinding::server(
                dataset,
                ids,
                service_config,
                site,
                native_version,
                &migration_digest,
                &initializing.initial_epoch,
                key_id.as_str(),
                operation.as_str(),
            ),
            #[cfg(feature = "desktop-local")]
            (
                SiteExpectation::Local(_),
                OrdinaryActivationProof::Legacy(VerifiedOrdinaryLegacyProof {
                    site: LegacySite::Local(site),
                    native_version,
                    migration_digest,
                    ..
                }),
            ) => ActivationBinding::local(
                site,
                native_version,
                migration_digest,
                initializing.initial_epoch.clone(),
                operation,
            ),
            #[cfg(feature = "desktop-local")]
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

    /// Republish the adopted known site at the proof's native version:
    /// revision + 1, the same epoch and binding except nativeVersion and
    /// migrationDigest; a Current keeps its restore fields.
    fn publish_adopted(
        &mut self,
        proof: OrdinaryActivationProof,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::EntryInvalid);
        let OrdinaryActivationProof::Legacy(proof) = proof else {
            return Err(invalid());
        };
        let binding = self.published_binding()?;
        let matches = match &proof.site {
            #[cfg(feature = "desktop-local")]
            LegacySite::Local(site) => binding.ordinary_local().is_ok_and(|expected| {
                expected.dataset_id == site.dataset_id
                    && expected.deployment_id == site.deployment_id
                    && expected.tenant_id == site.tenant_id
                    && expected.installation_id == site.installation_id
                    && expected.generation_root == site.generation_root
                    && expected.pg_system_id == site.pg_system_id
                    && expected.database_oid == site.database_oid
                    && expected.master.key_id == site.master.key_id
                    && expected.master.key_version == site.master.key_version
            }),
            LegacySite::Server { site, key_id } => {
                binding.ordinary_server().is_ok_and(|expected| {
                    expected.server_database == site && expected.master.key_id == key_id.as_str()
                })
            }
        };
        if proof.operation != self.operation()?
            || !matches
            || proof.native_version != latest()
            || binding.native_version() >= latest()
        {
            return Err(fault(RecoveryControlFault::ControlInvalid));
        }
        let mut binding = binding.with_native(proof.native_version, proof.migration_digest);
        match &self.intent.site {
            SiteExpectation::Server { service_config, .. } => {
                binding = binding.with_service_config(service_config);
            }
            #[cfg(feature = "desktop-local")]
            SiteExpectation::Local(_) => {}
        }
        binding.validate(&entry::lock(&self.control)?.limits)?;
        let evidence = self.evidence.clone();
        let (record, _) = self.head.as_ref().ok_or_else(invalid)?;
        match record.data().clone() {
            ActivationPayload::Active(_) => {
                self.publish(ActivationPhase::OrdinaryActive, |publish_intent| {
                    ActivationPayload::Active(Active {
                        binding,
                        initialization_evidence: evidence,
                        publish_intent,
                    })
                })?
            }
            ActivationPayload::Current(mut current) => {
                self.publish(ActivationPhase::RestoreCurrent, |publish_intent| {
                    current.binding = binding;
                    current.publish_intent = publish_intent;
                    ActivationPayload::Current(current)
                })?
            }
            _ => return Err(invalid()),
        }
        self.resource_close()
    }

    /// Downgrade runtimeEX to SH on the same FD, write the enrollment and
    /// release ownerEX/admissionEX (spec 8073). The held head must be at the
    /// latest native version.
    pub fn into_runtime_before(self) -> Result<RecoveryRuntimeOwner, RecoveryControlError> {
        let result = (|| {
            let latest_head = self
                .head
                .as_ref()
                .is_some_and(|(record, _)| match record.data() {
                    ActivationPayload::Active(active) => {
                        active.binding.native_version() == latest()
                    }
                    ActivationPayload::Current(current) => {
                        current.binding.native_version() == latest()
                    }
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
                        if Some(published.digest())
                            == self.head.as_ref().map(|(_, d)| d.as_str()) =>
                    {
                        published
                    }
                    _ => return Err(fault(RecoveryControlFault::ControlInvalid)),
                };
                self.intent.expects(published.binding())?;
                files.runtime_entry(published, &self.intent)?
            };
            runtime::enter_runtime(&self.control, entry, effect)
        })();
        result.map_err(|mut error: RecoveryControlError| {
            error.retained_ordinary = Some(Box::new(self));
            error
        })
    }
}

/// Ledger checksum of one exact native version.
#[cfg(feature = "desktop-local")]
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
