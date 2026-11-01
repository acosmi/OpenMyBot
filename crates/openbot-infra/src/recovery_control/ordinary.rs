//! Ordinary startup: the sealed entry intent, the shared-lock head branch and
//! the exclusive ordinary writer session (spec 7934, 8021, 8067-8073).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::Digest as _;

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
    Local,
}

/// The head a shared-lock branch saw; only that branch rewrites it.
enum ExpectedHead {
    Absent,
    ActiveBelowLatest(String),
    CurrentBelowLatest(String),
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
    head: ExpectedHead,
    resource_model: ResourceModel,
    owners: Vec<RuntimeOwner>,
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
            SiteExpectation::Local => ResourceModel::Local,
        };
        Ok(Self {
            source,
            site,
            bounds,
            t0_ns,
            admission,
            effect,
            convergence,
            head: ExpectedHead::Absent,
            resource_model,
            owners: owners.to_vec(),
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
            SiteExpectation::Local => Err(fault(RecoveryControlFault::EntryInvalid)),
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
            SiteExpectation::Local => {
                if !binding.is_local() {
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
    mut intent: VerifiedOrdinaryStartupIntent,
    deadline: Instant,
) -> Result<(PublishedActivation, VerifiedOrdinaryStartupIntent), RecoveryControlError> {
    let admission = deadline.min(intent.admission);
    let mut files = entry::lock(control)?;
    files.acquire_shared_before(admission)?;
    let published = match files.read_head_before(admission) {
        Ok(Head::Published(published)) => published,
        Ok(Head::Absent) => {
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
        let digest = published.digest().to_owned();
        intent.head = if published.observation().record.phase == ActivationPhase::RestoreCurrent {
            ExpectedHead::CurrentBelowLatest(digest)
        } else {
            ExpectedHead::ActiveBelowLatest(digest)
        };
        files.release_registration_attempt();
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

/// What the exclusive session will do with the head it saw.
enum SessionKind {
    Initialize,
    Upgrade,
}

/// The exclusive ordinary writer: ownerEX, admissionEX and runtimeEX held in
/// the control owner from `begin` until `into_runtime_before` or drop.
pub struct OrdinaryInitializationSession {
    control: ControlOwner,
    intent: VerifiedOrdinaryStartupIntent,
    kind: SessionKind,
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
    Legacy(VerifiedOrdinaryLegacyProof),
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
    let kind = match (&intent.head, head) {
        (ExpectedHead::Absent, Head::Absent) if intent.source.is_some() => {
            (SessionKind::Initialize, None)
        }
        (ExpectedHead::ActiveBelowLatest(seen), Head::Published(published))
            if published.observation().record.phase == ActivationPhase::OrdinaryActive
                && published.digest() == seen =>
        {
            (SessionKind::Upgrade, Some(published))
        }
        (ExpectedHead::CurrentBelowLatest(seen), Head::Published(published))
            if published.observation().record.phase == ActivationPhase::RestoreCurrent
                && published.digest() == seen =>
        {
            (SessionKind::Upgrade, Some(published))
        }
        _ => {
            files.release_writer();
            return Err(fault(RecoveryControlFault::OwnerBusy));
        }
    };
    drop(files);
    let (kind, published) = kind;
    Ok(OrdinaryInitializationSession {
        control: Arc::clone(control),
        intent,
        kind,
        head: published.map(|p| (p.observation().record.clone(), p.digest().to_owned())),
        operation: None,
        pending: None,
        last: None,
        evidence: Vec::new(),
    })
}

impl OrdinaryInitializationSession {
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
            SiteExpectation::Local => Err(fault(RecoveryControlFault::EntryInvalid)),
        }
    }

    /// The sealed source when this session initializes; `None` for an upgrade.
    pub(super) fn initialization_source(&self) -> Option<OrdinaryInitializationSource> {
        match self.kind {
            SessionKind::Initialize => self.intent.source.map(|(source, _, _)| source),
            SessionKind::Upgrade => None,
        }
    }

    /// The published binding an upgrade session starts from.
    pub(super) fn held_binding(&self) -> Option<&ActivationBinding> {
        match self.head.as_ref()?.0.data() {
            ActivationPayload::Active(active) => Some(&active.binding),
            ActivationPayload::Current(current) => Some(&current.binding),
            _ => None,
        }
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
        if !matches!(self.kind, SessionKind::Initialize) || self.head.is_some() {
            return Err(invalid());
        }
        let (source, intent_id, intent_file) = self.intent.source.ok_or_else(invalid)?;
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
        let first = match mode {
            OrdinaryMode::Fresh => JournalData::fresh_init(
                host,
                intent_id.as_str(),
                planned,
                self.intent.bounds,
                &digest,
                clock,
            ),
            OrdinaryMode::LegacyAdoption => JournalData::legacy_adoption(
                host,
                intent_id.as_str(),
                intent_file,
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
        let SiteExpectation::Server {
            dataset,
            ids,
            service_config,
            ..
        } = &self.intent.site
        else {
            return Err(invalid());
        };
        let (site, version, digest, key_id) = match proof {
            OrdinaryActivationProof::ServerFresh(proof) => {
                (proof.site, latest(), proof.migration_digest, proof.key_id)
            }
            OrdinaryActivationProof::Legacy(proof) => (
                proof.site,
                proof.native_version,
                proof.migration_digest,
                proof.key_id,
            ),
        };
        let binding = ActivationBinding::server(
            dataset,
            ids,
            service_config,
            site,
            version,
            &digest,
            &initializing.initial_epoch,
            key_id.as_str(),
            operation.as_str(),
        );
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

    /// Upgrade the held Active or Current from its sealed native version to
    /// the latest one in a new `ordinary_upgrade` operation (S6b).
    pub async fn upgrade_native_before(
        &mut self,
        pool: &crate::db::pool::DatabasePool,
    ) -> Result<(), RecoveryControlError> {
        let invalid = || fault(RecoveryControlFault::ControlInvalid);
        let (prior, prior_digest) = self
            .head
            .clone()
            .ok_or_else(|| fault(RecoveryControlFault::EntryInvalid))?;
        let binding = match prior.data() {
            ActivationPayload::Active(active) => active.binding.clone(),
            ActivationPayload::Current(current) => current.binding.clone(),
            _ => return Err(fault(RecoveryControlFault::EntryInvalid)),
        };
        let from = binding.native_version();
        let to = latest();
        if from >= to || self.pending.is_some() {
            return Err(fault(RecoveryControlFault::EntryInvalid));
        }
        let effect = self.intent.effect;
        // 1. intent
        let operation = Hex32::mint(&mint::<16>()?)?;
        {
            let mut files = entry::lock(&self.control)?;
            let control_id: Hex32 =
                serde_json::from_value(serde_json::Value::String(prior.control_id.clone()))
                    .map_err(RecoveryControlError::from_json)?;
            files.begin_journal(
                &operation,
                &control_id,
                binding.authorization_epoch(),
                effect,
            )?;
            let clock = files.owner_clock(
                Hex32::mint(&mint::<16>()?)?,
                self.intent.t0_ns,
                &self.intent.bounds,
            )?;
            files.append_journal(
                &operation,
                &JournalData::ordinary_upgrade(&prior_digest, from, to, self.intent.bounds, clock),
                effect,
            )?;
        }
        self.operation = Some(operation);
        self.last = None;
        self.evidence.clear();
        // 2. ledger check, read only, before BEGIN on the same connection
        let mut client = pool
            .get()
            .await
            .map_err(|_| fault(RecoveryControlFault::IoFailure))?;
        super::before(effect)?;
        let ledger =
            native::validate_known_prefix(&client, i32::try_from(from).map_err(|_| invalid())?)
                .await
                .map_err(|_| invalid())?;
        super::before(effect)?;
        if ledger.latest_version().unsigned_abs() != from
            || ledger_checksum(&client, from).await? != binding.migration_digest()
        {
            return Err(invalid());
        }
        super::before(effect)?;
        // 3. pg_upgrade
        self.intend_stage(Stage::PgUpgrade)?;
        let applied = {
            use crate::db::native::BootstrapTransactionClient as _;
            match client
                .bootstrap_transaction_builder()
                .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
                .start()
                .await
            {
                Ok(transaction) => {
                    match native::apply_through_in_transaction(
                        &transaction,
                        native::NATIVE_LATEST_VERSION,
                    )
                    .await
                    {
                        Ok(_) => Some(transaction.commit().await.is_ok()),
                        Err(_) => {
                            let _ = transaction.rollback().await;
                            None
                        }
                    }
                }
                Err(_) => None,
            }
        };
        let returned = Instant::now();
        let Some(acknowledged) = applied else {
            // No COMMIT was issued: the stage stays an unanswered intent.
            return Err(fault(RecoveryControlFault::IoFailure));
        };
        if !self.observe_commit(acknowledged, returned)? {
            return Err(fault(RecoveryControlFault::EffectExpired));
        }
        // 4. read back on the same connection
        native::validate_current(&client)
            .await
            .map_err(|_| invalid())?;
        let layout = crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(&client)
            .await
            .map_err(|_| invalid())?;
        if layout.native_version().unsigned_abs() != to {
            return Err(invalid());
        }
        let digest = ledger_checksum(&client, to).await?;
        super::before(effect)?;
        // 5. publish under the prior phase
        let upgraded = binding.upgraded(to, &digest);
        let evidence = self.evidence.clone();
        match prior.data() {
            ActivationPayload::Active(_) => {
                self.publish(ActivationPhase::OrdinaryActive, |publish_intent| {
                    ActivationPayload::Active(Active {
                        binding: upgraded,
                        initialization_evidence: evidence,
                        publish_intent,
                    })
                })?;
            }
            ActivationPayload::Current(current) => {
                let mut current = current.clone();
                self.publish(ActivationPhase::RestoreCurrent, |publish_intent| {
                    current.binding = upgraded;
                    current.publish_intent = publish_intent;
                    ActivationPayload::Current(current)
                })?;
            }
            _ => return Err(invalid()),
        }
        // 6. resource_close
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
                ActivationPayload::Current(current) => current.binding.native_version() == latest(),
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
