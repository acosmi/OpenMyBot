//! Current-authenticated runtime capability orchestration and trusted non-Serde host port.
//! Observations never grant actions; real composition roots and own-Pool collectors provide facts.

use openbot_contracts::auth::AuthContext;
use openbot_contracts::error::AppError;
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingIdentity, HostRequestBindingKind,
    RequestBindingIssuer, RequestBindingOwnerObservation,
};
use openbot_contracts::runtime_capabilities::{
    RuntimeCapabilitiesResponse, RuntimeCapabilityEntry, RuntimeCapabilityHostMode,
    RuntimeCapabilityId, RuntimeCapabilityReasonCode, RuntimeCapabilityState,
};
use openbot_domain::runtime_capabilities::{
    self as domain, BindingClaim, HostMode, ProjectionRevision, RuntimeCapabilityFacts,
    RuntimeCapabilityProjection, SessionLiveness, WindowBindingClaim,
};
use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One use case owns one absolute monotonic budget; hosts may only spend the remaining time.
pub const RUNTIME_CAPABILITIES_TOTAL_BUDGET: Duration = Duration::from_secs(5);

/// Sanitized collector failure; no raw SQL, locator, epoch or secret facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeCapabilitiesCollectionError {
    /// Actual host source or binding was not assembled.
    MissingHostSource,
    /// Original host/session/window authority is no longer current.
    NotCurrent,
    /// A bounded dependency or current observation cannot be established.
    Unavailable,
    /// Internal facts or projection shape violated the closed contract.
    InvalidFacts,
}
impl RuntimeCapabilitiesCollectionError {
    /// Map only after the whole current observation has passed its final tail.
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        match self {
            Self::MissingHostSource => AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            },
            Self::NotCurrent => AppError::Unauthenticated,
            Self::Unavailable | Self::InvalidFacts => AppError::DependencyUnavailable {
                dependency: "runtime_capabilities",
            },
        }
    }
}
impl From<HostRequestBindingError> for RuntimeCapabilitiesCollectionError {
    fn from(error: HostRequestBindingError) -> Self {
        match error {
            HostRequestBindingError::Missing => Self::MissingHostSource,
            HostRequestBindingError::NotCurrent => Self::NotCurrent,
            HostRequestBindingError::Unavailable => Self::Unavailable,
        }
    }
}

/// Application-minted original deadline; a copy cannot extend it.
#[derive(Clone, Copy)]
pub struct CapabilityDeadline {
    deadline: Instant,
}
impl CapabilityDeadline {
    pub(crate) fn for_use_case() -> Result<Self, RuntimeCapabilitiesCollectionError> {
        Instant::now()
            .checked_add(RUNTIME_CAPABILITIES_TOTAL_BUDGET)
            .map(|deadline| Self { deadline })
            .ok_or(RuntimeCapabilitiesCollectionError::Unavailable)
    }
    /// Original absolute monotonic deadline for real host SQL and worker budgets.
    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.deadline
    }
    /// Positive remaining budget; elapsed results must not be accepted.
    pub fn remaining(self) -> Result<Duration, RuntimeCapabilitiesCollectionError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RuntimeCapabilitiesCollectionError::Unavailable)
    }
    /// Reject an elapsed use case without resetting its budget.
    pub fn check(self) -> Result<(), RuntimeCapabilitiesCollectionError> {
        self.remaining().map(|_| ())
    }
}
impl fmt::Debug for CapabilityDeadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapabilityDeadline(<redacted>)")
    }
}

/// Original host scope minted by an audited real Server or actual Local composition.
/// It retains the opaque original binding epoch, with no raw tuple access, lifecycle lease,
/// Pool or Protocol owner.
#[derive(Clone)]
pub struct RuntimeCapabilityHostScope {
    original: HostRequestBindingIdentity,
    owner: RequestBindingOwnerObservation,
    claim: BindingClaim,
    runtime_epoch: NonZeroU64,
}
impl RuntimeCapabilityHostScope {
    /// Only the actual Server issuer may shape a Server observation.
    #[doc(hidden)]
    pub fn for_server(
        issuer: &RequestBindingIssuer,
        auth: &AuthContext,
        runtime_epoch: NonZeroU64,
    ) -> Result<Self, RuntimeCapabilitiesCollectionError> {
        let binding = auth
            .request_binding()
            .ok_or(RuntimeCapabilitiesCollectionError::MissingHostSource)?;
        if !issuer.owns_identity(binding.identity()) || !issuer.observation().is_current() {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        if !matches!(
            binding.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::ServerSingleUserOwner
        ) {
            return Err(RuntimeCapabilitiesCollectionError::MissingHostSource);
        }
        Self::from_owned(issuer, auth, runtime_epoch, HostMode::Server, None)
    }
    /// Only the actual Local factory may shape its original exact native window observation.
    /// Generic session-to-window delegation does not establish a Local runtime producer.
    #[doc(hidden)]
    pub fn for_desktop_local(
        issuer: &RequestBindingIssuer,
        auth: &AuthContext,
        runtime_epoch: NonZeroU64,
        window: WindowBindingClaim,
    ) -> Result<Self, RuntimeCapabilitiesCollectionError> {
        let binding = auth
            .request_binding()
            .ok_or(RuntimeCapabilitiesCollectionError::MissingHostSource)?;
        if !issuer.matches_desktop_window_epoch(
            binding.identity(),
            window.label(),
            window.nonce().get(),
        ) {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        Self::from_owned(
            issuer,
            auth,
            runtime_epoch,
            HostMode::DesktopLocal,
            Some(window),
        )
    }
    fn from_owned(
        issuer: &RequestBindingIssuer,
        auth: &AuthContext,
        runtime_epoch: NonZeroU64,
        mode: HostMode,
        window: Option<WindowBindingClaim>,
    ) -> Result<Self, RuntimeCapabilitiesCollectionError> {
        let binding = auth
            .request_binding()
            .ok_or(RuntimeCapabilitiesCollectionError::MissingHostSource)?;
        let claim = BindingClaim::declare(
            auth.actor().clone(),
            auth.auth_generation(),
            mode,
            SessionLiveness::Active,
            window,
        )
        .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts)?;
        Ok(Self {
            original: binding.identity().clone(),
            owner: issuer.observation(),
            claim,
            runtime_epoch,
        })
    }
    /// Explicit original identity; structure equality alone is never current proof.
    #[must_use]
    pub const fn binding_identity(&self) -> &HostRequestBindingIdentity {
        &self.original
    }
    /// Actual owner observation, independent of any temporary state upgrade.
    #[must_use]
    pub fn owner_is_current(&self) -> bool {
        self.owner.is_current()
    }
    /// Pure Domain claim shaped only after the actual issuer was checked.
    #[must_use]
    pub const fn binding_claim(&self) -> &BindingClaim {
        &self.claim
    }
    /// Actual runtime observation generation, never supplied by a renderer.
    #[must_use]
    pub const fn runtime_epoch(&self) -> NonZeroU64 {
        self.runtime_epoch
    }
    /// Factory-fixed finite host mode.
    #[must_use]
    pub const fn host_mode(&self) -> HostMode {
        self.claim.host_mode()
    }
    /// Match the original attached carrier and owner; the real collector also checks current sources.
    #[must_use]
    pub fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.owner_is_current()
            && auth
                .request_binding()
                .is_some_and(|binding| self.original.same_binding(binding.identity()))
            && self.claim.actor() == auth.actor()
            && self.claim.auth_generation() == auth.auth_generation()
    }
}
impl fmt::Debug for RuntimeCapabilityHostScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeCapabilityHostScope(<redacted>)")
    }
}

/// Per-request final source and clock observation, checked synchronously after rollback.
/// Implementations belong to audited real host factories and retain no lifecycle lease or
/// Protocol owner. They expose no raw tuple, secret, Debug or Serde surface.
pub trait RuntimeCapabilityTailWitness: Send + Sync {
    /// Recheck original owner/binding and actual session clocks or the same Local grant/native
    /// observation within the original budget. No await, database operation or renewal is allowed.
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: CapabilityDeadline,
    ) -> Result<(), RuntimeCapabilitiesCollectionError>;
}

/// A consumed, non-Serde observation, including its opaque original epoch and private final stamp.
pub struct RuntimeCapabilityObservation {
    scope: RuntimeCapabilityHostScope,
    facts: RuntimeCapabilityFacts,
    revision: ProjectionRevision,
    tail_witness: Option<Arc<dyn RuntimeCapabilityTailWitness>>,
}
impl RuntimeCapabilityObservation {
    /// Shape facts from a real audited host factory; this constructor alone proves no authority.
    #[doc(hidden)]
    pub fn from_trusted_facts(
        scope: RuntimeCapabilityHostScope,
        facts: RuntimeCapabilityFacts,
        revision: &str,
    ) -> Result<Self, RuntimeCapabilitiesCollectionError> {
        let revision = ProjectionRevision::try_from_opaque(revision)
            .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts)?;
        Ok(Self {
            scope,
            facts,
            revision,
            tail_witness: None,
        })
    }
    /// Original actual host scope.
    #[must_use]
    pub const fn scope(&self) -> &RuntimeCapabilityHostScope {
        &self.scope
    }
    /// Secret-free Domain facts; not an action permission.
    #[must_use]
    pub const fn facts(&self) -> &RuntimeCapabilityFacts {
        &self.facts
    }
    /// Bounded nonsecret owner/counter revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        self.revision.as_str()
    }
    /// Consume old facts while preserving the original carrier/scope/revision.
    #[must_use]
    pub fn replace_facts(mut self, facts: RuntimeCapabilityFacts) -> Self {
        self.facts = facts;
        self
    }
    /// Attach this request's verified final joint-source stamp from its actual host factory.
    /// This trusted Rust shape alone does not prove the implementation or its source authority.
    #[doc(hidden)]
    #[must_use]
    pub fn with_tail_witness(mut self, witness: Arc<dyn RuntimeCapabilityTailWitness>) -> Self {
        self.tail_witness = Some(witness);
        self
    }
    /// Missing final stamps cannot become positive projections. The same original binding,
    /// owner and deadline are checked around the real host's synchronous observation.
    pub fn verify_tail_witness(
        &self,
        auth: &AuthContext,
        deadline: CapabilityDeadline,
    ) -> Result<(), RuntimeCapabilitiesCollectionError> {
        if !self.scope.matches_auth(auth) {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        deadline.check()?;
        let witness = self
            .tail_witness
            .as_ref()
            .ok_or(RuntimeCapabilitiesCollectionError::Unavailable)?;
        let result = witness.verify_current(auth, deadline);
        if !self.scope.matches_auth(auth) {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        deadline.check()?;
        result
    }
}
impl fmt::Debug for RuntimeCapabilityObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeCapabilityObservation(<redacted>)")
    }
}
/// Entire observation result retained through current checks, finalization and the synchronous tail.
pub type RuntimeCapabilityObservationResult =
    Result<RuntimeCapabilityObservation, RuntimeCapabilitiesCollectionError>;
/// Explicit object-safe Send future for current host observations.
pub type RuntimeCapabilitiesFuture<'a> =
    Pin<Box<dyn Future<Output = RuntimeCapabilityObservationResult> + Send + 'a>>;
/// Real host and own-Pool facts port; no client mode/actor or external transaction is accepted.
pub trait RuntimeCapabilitiesCollector: Send + Sync {
    /// Observe only within the original deadline; return no raw source secrets.
    fn observe<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a>;
    /// Consume the ENTIRE result and jointly re-observe original current auth and applicable sources.
    /// Observer failures still reach this step; no stale negative predicates may be reused.
    fn finalize<'a>(
        &'a self,
        auth: &'a AuthContext,
        observed: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a>;
    /// Consume the ENTIRE finalized result after rollback; only synchronous owner/window/grant work.
    /// Error paths also check the original scope. No await, prompt or freshness extension is permitted.
    fn tail_current(
        &self,
        auth: &AuthContext,
        finalized: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilityObservationResult;
}

async fn bounded<T>(
    deadline: CapabilityDeadline,
    future: impl Future<Output = Result<T, RuntimeCapabilitiesCollectionError>>,
) -> Result<T, RuntimeCapabilitiesCollectionError> {
    deadline.check()?;
    let result =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.deadline()), future)
            .await
            .map_err(|_| RuntimeCapabilitiesCollectionError::Unavailable)?;
    deadline.check()?;
    result
}
fn hold_failure(
    result: RuntimeCapabilityObservationResult,
    previous: Option<RuntimeCapabilitiesCollectionError>,
) -> RuntimeCapabilityObservationResult {
    match (previous, result) {
        (Some(RuntimeCapabilitiesCollectionError::NotCurrent), _) => {
            Err(RuntimeCapabilitiesCollectionError::NotCurrent)
        }
        (_, Err(RuntimeCapabilitiesCollectionError::NotCurrent)) => {
            Err(RuntimeCapabilitiesCollectionError::NotCurrent)
        }
        (Some(error), _) => Err(error),
        (None, result) => result,
    }
}

/// Read the complete current projection; no future action authority is granted.
pub async fn get_runtime_capabilities(
    collector: Option<&dyn RuntimeCapabilitiesCollector>,
    auth: &AuthContext,
) -> Result<RuntimeCapabilitiesResponse, AppError> {
    let deadline = CapabilityDeadline::for_use_case()
        .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    let binding = auth
        .request_binding()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        })?;
    let collector = collector.ok_or(AppError::DependencyUnavailable {
        dependency: "host_request_binding",
    })?;
    bounded(deadline, async {
        binding
            .verify_current_before(auth, deadline.deadline())
            .await
            .map_err(RuntimeCapabilitiesCollectionError::from)
    })
    .await
    .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    let observed = bounded(deadline, collector.observe(auth, deadline)).await;
    let post = bounded(deadline, async {
        binding
            .verify_current_before(auth, deadline.deadline())
            .await
            .map_err(RuntimeCapabilitiesCollectionError::from)
    })
    .await;
    let observed = match post {
        Ok(()) => observed,
        Err(error) => Err(error),
    };
    let previous = observed.as_ref().err().copied();
    let finalized = hold_failure(
        bounded(deadline, collector.finalize(auth, observed, deadline)).await,
        previous,
    );
    let previous = finalized.as_ref().err().copied();
    let tailed = hold_failure(collector.tail_current(auth, finalized, deadline), previous);
    let observation = tailed.map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    deadline
        .check()
        .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    if !observation.scope.matches_auth(auth) {
        return Err(AppError::Unauthenticated);
    }
    observation
        .verify_tail_witness(auth, deadline)
        .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    let claim = observation.scope.binding_claim();
    let projection = domain::project_runtime_capabilities(domain::RuntimeCapabilityRequest {
        current_runtime: observation.scope.runtime_epoch(),
        observed_runtime: observation.scope.runtime_epoch(),
        current_binding: claim,
        observed_binding: claim,
        revision: observation.revision(),
        facts: observation.facts(),
    })
    .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts.into_app_error())?;
    let reply = projection_to_response(projection)
        .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    deadline
        .check()
        .map_err(RuntimeCapabilitiesCollectionError::into_app_error)?;
    Ok(reply)
}

/// Exhaustive pure checked conversion; Domain types remain non-Serde.
pub fn projection_to_response(
    projection: RuntimeCapabilityProjection,
) -> Result<RuntimeCapabilitiesResponse, RuntimeCapabilitiesCollectionError> {
    let mut entries = Vec::with_capacity(13);
    for status in projection.capabilities() {
        entries.push(
            RuntimeCapabilityEntry::try_new(
                wire_id(status.id()),
                wire_state(status.state()),
                wire_reason(status.reason_code()),
            )
            .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts)?,
        );
    }
    let entries = entries
        .try_into()
        .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts)?;
    RuntimeCapabilitiesResponse::try_new(
        wire_mode(projection.host_mode()),
        projection.revision().as_str().to_owned(),
        entries,
    )
    .map_err(|_| RuntimeCapabilitiesCollectionError::InvalidFacts)
}

const fn wire_id(value: domain::CapabilityId) -> RuntimeCapabilityId {
    match value {
        domain::CapabilityId::Workspace => RuntimeCapabilityId::Workspace,
        domain::CapabilityId::AgentTools => RuntimeCapabilityId::AgentTools,
        domain::CapabilityId::ModelCustomV1 => RuntimeCapabilityId::ModelCustomV1,
        domain::CapabilityId::ModelSelectionV2 => RuntimeCapabilityId::ModelSelectionV2,
        domain::CapabilityId::ModelSdkGateway => RuntimeCapabilityId::ModelSdkGateway,
        domain::CapabilityId::ModelAccountBridge => RuntimeCapabilityId::ModelAccountBridge,
        domain::CapabilityId::BrowserControl => RuntimeCapabilityId::BrowserControl,
        domain::CapabilityId::NativeControl => RuntimeCapabilityId::NativeControl,
        domain::CapabilityId::PixelEgress => RuntimeCapabilityId::PixelEgress,
        domain::CapabilityId::LocalConfirmation => RuntimeCapabilityId::LocalConfirmation,
        domain::CapabilityId::BackupRestore => RuntimeCapabilityId::BackupRestore,
        domain::CapabilityId::DynamicSso => RuntimeCapabilityId::DynamicSso,
        domain::CapabilityId::DevicePairing => RuntimeCapabilityId::DevicePairing,
    }
}

const fn wire_state(value: domain::CapabilityState) -> RuntimeCapabilityState {
    match value {
        domain::CapabilityState::Unsupported => RuntimeCapabilityState::Unsupported,
        domain::CapabilityState::Unconfigured => RuntimeCapabilityState::Unconfigured,
        domain::CapabilityState::PermissionRequired => RuntimeCapabilityState::PermissionRequired,
        domain::CapabilityState::Ready => RuntimeCapabilityState::Ready,
        domain::CapabilityState::Unavailable => RuntimeCapabilityState::Unavailable,
    }
}

const fn wire_reason(value: domain::ReasonCode) -> RuntimeCapabilityReasonCode {
    match value {
        domain::ReasonCode::CurrentChecksAvailable => {
            RuntimeCapabilityReasonCode::CurrentChecksAvailable
        }
        domain::ReasonCode::PlatformUnimplemented => {
            RuntimeCapabilityReasonCode::PlatformUnimplemented
        }
        domain::ReasonCode::IndependentApiMissing => {
            RuntimeCapabilityReasonCode::IndependentApiMissing
        }
        domain::ReasonCode::SupportUnproven => RuntimeCapabilityReasonCode::SupportUnproven,
        domain::ReasonCode::ReleaseDependencyMissing => {
            RuntimeCapabilityReasonCode::ReleaseDependencyMissing
        }
        domain::ReasonCode::ReleaseDependencyUnproven => {
            RuntimeCapabilityReasonCode::ReleaseDependencyUnproven
        }
        domain::ReasonCode::PolicyUnconfigured => RuntimeCapabilityReasonCode::PolicyUnconfigured,
        domain::ReasonCode::PolicyEmpty => RuntimeCapabilityReasonCode::PolicyEmpty,
        domain::ReasonCode::PolicyInvalid => RuntimeCapabilityReasonCode::PolicyInvalid,
        domain::ReasonCode::PolicyUnproven => RuntimeCapabilityReasonCode::PolicyUnproven,
        domain::ReasonCode::ModelKeyMissing => RuntimeCapabilityReasonCode::ModelKeyMissing,
        domain::ReasonCode::ModelKeyUnproven => RuntimeCapabilityReasonCode::ModelKeyUnproven,
        domain::ReasonCode::ConfigurationMissing => {
            RuntimeCapabilityReasonCode::ConfigurationMissing
        }
        domain::ReasonCode::ConfigurationInvalid => {
            RuntimeCapabilityReasonCode::ConfigurationInvalid
        }
        domain::ReasonCode::ConfigurationUnproven => {
            RuntimeCapabilityReasonCode::ConfigurationUnproven
        }
        domain::ReasonCode::AccountBridgeSourceBlocked => {
            RuntimeCapabilityReasonCode::AccountBridgeSourceBlocked
        }
        domain::ReasonCode::AccountBridgeSourceUnproven => {
            RuntimeCapabilityReasonCode::AccountBridgeSourceUnproven
        }
        domain::ReasonCode::ProductPermissionRequired => {
            RuntimeCapabilityReasonCode::ProductPermissionRequired
        }
        domain::ReasonCode::ProductPermissionUnproven => {
            RuntimeCapabilityReasonCode::ProductPermissionUnproven
        }
        domain::ReasonCode::OsPermissionCaptureRequired => {
            RuntimeCapabilityReasonCode::OsPermissionCaptureRequired
        }
        domain::ReasonCode::OsPermissionAccessibilityRequired => {
            RuntimeCapabilityReasonCode::OsPermissionAccessibilityRequired
        }
        domain::ReasonCode::OsPermissionInputRequired => {
            RuntimeCapabilityReasonCode::OsPermissionInputRequired
        }
        domain::ReasonCode::OsPermissionUnproven => {
            RuntimeCapabilityReasonCode::OsPermissionUnproven
        }
        domain::ReasonCode::OsPermissionExpired => RuntimeCapabilityReasonCode::OsPermissionExpired,
        domain::ReasonCode::LocalConfirmationRequired => {
            RuntimeCapabilityReasonCode::LocalConfirmationRequired
        }
        domain::ReasonCode::LocalConfirmationPending => {
            RuntimeCapabilityReasonCode::LocalConfirmationPending
        }
        domain::ReasonCode::LocalConfirmationUnavailable => {
            RuntimeCapabilityReasonCode::LocalConfirmationUnavailable
        }
        domain::ReasonCode::LocalConfirmationUnproven => {
            RuntimeCapabilityReasonCode::LocalConfirmationUnproven
        }
        domain::ReasonCode::LocalConfirmationExpired => {
            RuntimeCapabilityReasonCode::LocalConfirmationExpired
        }
        domain::ReasonCode::PixelConsentRequired => {
            RuntimeCapabilityReasonCode::PixelConsentRequired
        }
        domain::ReasonCode::PixelConsentUnproven => {
            RuntimeCapabilityReasonCode::PixelConsentUnproven
        }
        domain::ReasonCode::PixelConsentExpired => RuntimeCapabilityReasonCode::PixelConsentExpired,
        domain::ReasonCode::ComputerSourceMissing => {
            RuntimeCapabilityReasonCode::ComputerSourceMissing
        }
        domain::ReasonCode::NativeSourceMissing => RuntimeCapabilityReasonCode::NativeSourceMissing,
        domain::ReasonCode::ScreenSourceMissing => RuntimeCapabilityReasonCode::ScreenSourceMissing,
        domain::ReasonCode::SourceUnproven => RuntimeCapabilityReasonCode::SourceUnproven,
        domain::ReasonCode::SourceExpired => RuntimeCapabilityReasonCode::SourceExpired,
        domain::ReasonCode::ProviderDisconnected => {
            RuntimeCapabilityReasonCode::ProviderDisconnected
        }
        domain::ReasonCode::ProviderUnproven => RuntimeCapabilityReasonCode::ProviderUnproven,
        domain::ReasonCode::ProviderExpired => RuntimeCapabilityReasonCode::ProviderExpired,
    }
}

const fn wire_mode(value: domain::HostMode) -> RuntimeCapabilityHostMode {
    match value {
        domain::HostMode::DesktopLocal => RuntimeCapabilityHostMode::DesktopLocal,
        domain::HostMode::DesktopRemote => RuntimeCapabilityHostMode::DesktopRemote,
        domain::HostMode::Server => RuntimeCapabilityHostMode::Server,
        domain::HostMode::MobileRemote => RuntimeCapabilityHostMode::MobileRemote,
    }
}

#[cfg(test)]
mod tests {
    // These are synthetic no-I/O orchestration fixtures, never PG or host acceptance.
    use super::*;
    use domain::{
        BridgeSourceFact, ConfigFact, Evidence, ImplementationSet, LocalConfirmationFact,
        ModelKeyFact, ModelSourceFacts, PermissionFact, PolicyFact, Presence, ProviderFact,
        SourceFact,
    };
    use openbot_contracts::auth::{AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::{HostRequestBindingGuard, RequestBindingOwnerLease};
    use std::sync::{Arc, Mutex};

    type Steps = Arc<Mutex<Vec<&'static str>>>;
    // A recording-only witness for synthetic orchestration tests; it proves no host or PG fact.
    struct SyntheticNoIoTailWitness {
        steps: Steps,
        deadlines: Arc<Mutex<Vec<Instant>>>,
        failure: Option<RuntimeCapabilitiesCollectionError>,
    }
    impl RuntimeCapabilityTailWitness for SyntheticNoIoTailWitness {
        fn verify_current(
            &self,
            _auth: &AuthContext,
            deadline: CapabilityDeadline,
        ) -> Result<(), RuntimeCapabilitiesCollectionError> {
            self.steps.lock().unwrap().push("witness");
            self.deadlines.lock().unwrap().push(deadline.deadline());
            deadline.check()?;
            self.failure.map_or(Ok(()), Err)
        }
    }
    struct RecordingGuard {
        steps: Steps,
        deadlines: Arc<Mutex<Vec<Instant>>>,
    }
    impl HostRequestBindingGuard for RecordingGuard {
        fn verify_current<'a>(
            &'a self,
            _auth: &'a AuthContext,
        ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
        {
            Box::pin(async {
                panic!("capability use case must not enter the old fixed-budget path")
            })
        }
        fn verify_current_before<'a>(
            &'a self,
            _auth: &'a AuthContext,
            deadline: Instant,
        ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.steps.lock().unwrap().push("guard");
                self.deadlines.lock().unwrap().push(deadline);
                Ok(())
            })
        }
    }
    struct RecordingCollector {
        issuer: RequestBindingIssuer,
        steps: Steps,
        deadlines: Arc<Mutex<Vec<Instant>>>,
        observe_error: Option<RuntimeCapabilitiesCollectionError>,
        finalize_error: Option<RuntimeCapabilitiesCollectionError>,
        tail_error: Option<RuntimeCapabilitiesCollectionError>,
        witness_error: Option<RuntimeCapabilitiesCollectionError>,
        omit_witness: bool,
        // Implements agent tools with an unconfigured acting policy and this default model key.
        acting_model_key: Option<ModelKeyFact>,
    }
    impl RuntimeCapabilitiesCollector for RecordingCollector {
        fn observe<'a>(
            &'a self,
            auth: &'a AuthContext,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilitiesFuture<'a> {
            Box::pin(async move {
                self.steps.lock().unwrap().push("observe");
                self.deadlines.lock().unwrap().push(deadline.deadline());
                if let Some(error) = self.observe_error {
                    return Err(error);
                }
                let scope = RuntimeCapabilityHostScope::for_server(
                    &self.issuer,
                    auth,
                    NonZeroU64::new(1).unwrap(),
                )?;
                let mut facts = facts();
                if let Some(model_key) = self.acting_model_key {
                    facts.implementations.agent_tools = Presence::Present {
                        independent_api: Evidence::Present,
                        release_dependency: Evidence::Present,
                    };
                    facts.acting_policy = PolicyFact::Unconfigured;
                    facts.model_key = model_key;
                }
                let observation = RuntimeCapabilityObservation::from_trusted_facts(
                    scope,
                    facts,
                    "0123456789abcdef0123456789abcdef-1",
                )?;
                if self.omit_witness {
                    Ok(observation)
                } else {
                    Ok(
                        observation.with_tail_witness(Arc::new(SyntheticNoIoTailWitness {
                            steps: Arc::clone(&self.steps),
                            deadlines: Arc::clone(&self.deadlines),
                            failure: self.witness_error,
                        })),
                    )
                }
            })
        }
        fn finalize<'a>(
            &'a self,
            _auth: &'a AuthContext,
            observed: RuntimeCapabilityObservationResult,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilitiesFuture<'a> {
            Box::pin(async move {
                self.steps.lock().unwrap().push("finalize");
                self.deadlines.lock().unwrap().push(deadline.deadline());
                match self.finalize_error {
                    Some(error) => Err(error),
                    None => observed,
                }
            })
        }
        fn tail_current(
            &self,
            _auth: &AuthContext,
            finalized: RuntimeCapabilityObservationResult,
            deadline: CapabilityDeadline,
        ) -> RuntimeCapabilityObservationResult {
            self.steps.lock().unwrap().push("tail");
            self.deadlines.lock().unwrap().push(deadline.deadline());
            match self.tail_error {
                Some(error) => Err(error),
                None => finalized,
            }
        }
    }
    fn fixture(role: Role) -> (RequestBindingOwnerLease, AuthContext, RecordingCollector) {
        let auth = AuthContext::for_test(
            DeploymentId::new("unit"),
            TenantId::new("unit"),
            ActorId::new("unit"),
            [role],
            AuthGeneration::new(3),
            true,
        );
        let (lease, issuer) = RequestBindingOwnerLease::for_trusted_host(
            HostRequestBindingKind::ServerSingleUserOwner,
        );
        let steps = Arc::new(Mutex::new(Vec::new()));
        let deadlines = Arc::new(Mutex::new(Vec::new()));
        let binding = issuer
            .bind_single_user_owner(
                &auth,
                Arc::new(RecordingGuard {
                    steps: Arc::clone(&steps),
                    deadlines: Arc::clone(&deadlines),
                }),
            )
            .unwrap();
        let auth = auth.with_verified_request_binding(binding).unwrap();
        (
            lease,
            auth,
            RecordingCollector {
                issuer,
                steps,
                deadlines,
                observe_error: None,
                finalize_error: None,
                tail_error: None,
                witness_error: None,
                omit_witness: false,
                acting_model_key: None,
            },
        )
    }
    fn facts() -> RuntimeCapabilityFacts {
        let absent = Presence::Absent;
        let unknown_model = ModelSourceFacts {
            key: ModelKeyFact::Unknown,
            provider: ProviderFact::Unknown,
        };
        RuntimeCapabilityFacts {
            implementations: ImplementationSet {
                workspace: Presence::Present {
                    independent_api: Evidence::Present,
                    release_dependency: Evidence::Present,
                },
                agent_tools: absent,
                model_custom_v1: absent,
                model_selection_v2: absent,
                model_sdk_gateway: absent,
                model_account_bridge: absent,
                browser_control: absent,
                native_control: absent,
                pixel_egress: absent,
                local_confirmation: absent,
                backup_restore: absent,
                dynamic_sso: absent,
                device_pairing: absent,
            },
            acting_policy: PolicyFact::Unknown,
            model_key: ModelKeyFact::Unknown,
            custom_model: unknown_model,
            sdk_model: unknown_model,
            bridge_model: unknown_model,
            custom_model_config: ConfigFact::Unknown,
            selection_v2_config: ConfigFact::Unknown,
            sdk_gateway_config: ConfigFact::Unknown,
            account_bridge_config: ConfigFact::Unknown,
            account_bridge_source: BridgeSourceFact::Unknown,
            backup_config: ConfigFact::Unknown,
            sso_config: ConfigFact::Unknown,
            sso_provider: ProviderFact::Unknown,
            pairing_config: ConfigFact::Unknown,
            model_provider: ProviderFact::Unknown,
            computer_source: SourceFact::Unknown,
            native_source: SourceFact::Unknown,
            screen_source: SourceFact::Unknown,
            os_capture: PermissionFact::Unknown,
            os_accessibility: PermissionFact::Unknown,
            os_input: PermissionFact::Unknown,
            pixel_model_consent: PermissionFact::Unknown,
            product_permissions: [PermissionFact::Granted; 13],
            local_confirmation: LocalConfirmationFact::Unknown,
        }
    }
    fn assert_order(collector: &RecordingCollector) {
        let steps = collector.steps.lock().unwrap();
        assert_eq!(
            &steps[..5],
            ["guard", "observe", "guard", "finalize", "tail"]
        );
        assert!(steps.len() == 5 || (steps.len() == 6 && steps[5] == "witness"));
        let deadlines = collector.deadlines.lock().unwrap();
        assert_eq!(deadlines.len(), steps.len());
        assert!(deadlines.iter().all(|value| *value == deadlines[0]));
    }
    #[tokio::test]
    async fn synthetic_entire_result_and_one_deadline_pass_all_stages() {
        let (_lease, auth, collector) = fixture(Role::Admin);
        let reply = get_runtime_capabilities(Some(&collector), &auth)
            .await
            .unwrap();
        assert_order(&collector);
        assert_eq!(reply.schema_version(), 1);
        assert_eq!(reply.host_mode(), RuntimeCapabilityHostMode::Server);
        assert_eq!(
            reply.capabilities()[0].state(),
            RuntimeCapabilityState::Ready
        );
    }
    #[tokio::test]
    async fn observer_error_still_reaches_finalize_tail_and_current_revocation_wins() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.observe_error = Some(RuntimeCapabilitiesCollectionError::Unavailable);
        collector.finalize_error = Some(RuntimeCapabilitiesCollectionError::NotCurrent);
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::Unauthenticated)
        );
        assert_order(&collector);
    }
    #[tokio::test]
    async fn observer_error_is_not_upgraded_to_positive_projection() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.observe_error = Some(RuntimeCapabilitiesCollectionError::Unavailable);
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::DependencyUnavailable {
                dependency: "runtime_capabilities"
            })
        );
        assert_order(&collector);
    }
    #[tokio::test]
    async fn late_tail_revocation_withholds_successful_observation() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.tail_error = Some(RuntimeCapabilitiesCollectionError::NotCurrent);
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::Unauthenticated)
        );
        assert_order(&collector);
    }
    #[tokio::test]
    async fn missing_final_source_stamp_withholds_positive_projection() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.omit_witness = true;
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::DependencyUnavailable {
                dependency: "runtime_capabilities"
            })
        );
        assert_order(&collector);
    }
    #[tokio::test]
    async fn synchronous_final_source_stamp_revocation_withholds_positive_projection() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.witness_error = Some(RuntimeCapabilitiesCollectionError::NotCurrent);
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::Unauthenticated)
        );
        assert_order(&collector);
        assert_eq!(collector.steps.lock().unwrap().last(), Some(&"witness"));
    }
    #[tokio::test]
    async fn policy_level_blocker_hides_unknown_provider_and_reply_succeeds() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.acting_model_key = Some(ModelKeyFact::Present);
        let reply = get_runtime_capabilities(Some(&collector), &auth)
            .await
            .unwrap();
        assert_order(&collector);
        let agent_tools = reply.capabilities()[1];
        assert_eq!(agent_tools.id(), RuntimeCapabilityId::AgentTools);
        assert_eq!(agent_tools.state(), RuntimeCapabilityState::Unconfigured);
        assert_eq!(
            agent_tools.reason_code(),
            RuntimeCapabilityReasonCode::PolicyUnconfigured
        );
    }
    #[tokio::test]
    async fn two_states_inside_one_level_refuse_entire_reply() {
        let (_lease, auth, mut collector) = fixture(Role::User);
        collector.acting_model_key = Some(ModelKeyFact::Unknown);
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &auth).await,
            Err(AppError::DependencyUnavailable {
                dependency: "runtime_capabilities"
            })
        );
        assert_order(&collector);
    }
    #[tokio::test]
    async fn zero_role_missing_binding_or_collector_does_not_enter_observer() {
        let (_lease, auth, collector) = fixture(Role::User);
        let bare = AuthContext::for_test(
            auth.deployment().clone(),
            auth.tenant().clone(),
            auth.actor().clone(),
            std::iter::empty::<Role>(),
            auth.auth_generation(),
            true,
        );
        assert_eq!(
            get_runtime_capabilities(Some(&collector), &bare).await,
            Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding"
            })
        );
        assert_eq!(
            get_runtime_capabilities(None, &auth).await,
            Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding"
            })
        );
        assert!(collector.steps.lock().unwrap().is_empty());
    }
    #[test]
    fn foreign_issuer_and_dropped_owner_cannot_shape_current_scope() {
        let (lease, auth, collector) = fixture(Role::User);
        let (_other_lease, other) = RequestBindingOwnerLease::for_trusted_host(
            HostRequestBindingKind::ServerSingleUserOwner,
        );
        assert!(matches!(
            RuntimeCapabilityHostScope::for_server(&other, &auth, NonZeroU64::new(1).unwrap()),
            Err(RuntimeCapabilitiesCollectionError::NotCurrent)
        ));
        let scope = RuntimeCapabilityHostScope::for_server(
            &collector.issuer,
            &auth,
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
        drop(lease);
        assert!(!scope.matches_auth(&auth));
    }
    #[tokio::test]
    async fn elapsed_private_test_deadline_does_not_accept_late_result() {
        let deadline = CapabilityDeadline {
            deadline: Instant::now() + Duration::from_millis(2),
        };
        let result = bounded(deadline, async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(())
        })
        .await;
        assert_eq!(result, Err(RuntimeCapabilitiesCollectionError::Unavailable));
    }
}
