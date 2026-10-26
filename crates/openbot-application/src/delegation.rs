//! Application-owned delegated Run admission and single-use command authority.

use crate::{RemoteCallbackAuthorization, RunExecutionLease};
use async_trait::async_trait;
use openbot_contracts::auth::{
    AuthContext, AuthContextBuilder, AuthGeneration, DelegationSource, Role, VerifiedDelegation,
};
use openbot_contracts::command::{AppCommand, ThreadRunStarted};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::thread::FencingToken;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Internal, non-wire request accepted only by the delegated entry handle.
#[derive(Clone)]
pub struct BeginDelegatedThreadRun {
    /// Trusted registration source.
    pub source: DelegationSource,
    /// Exact current registration revision.
    pub revision: u64,
    /// Source's accepted event identity.
    pub trigger_id: String,
    /// Previously minted or source-bound Thread.
    pub thread_id: ThreadId,
    /// Caller-minted deterministic idempotency identity.
    pub run_id: RunId,
    /// Bot whose current configuration supplies the model.
    pub bot_id: BotId,
    /// Optional user-role untrusted input, separate from the owner template.
    pub untrusted_material: Option<DelegatedUntrustedMaterial>,
}
/// Untrusted external content, never system instructions.
#[derive(Clone)]
pub struct DelegatedUntrustedMaterial {
    /// Bounded source record reference, excluded from prompts.
    pub source_ref: String,
    /// At most 256 KiB of UTF-8 text.
    pub text: String,
}
impl core::fmt::Debug for BeginDelegatedThreadRun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BeginDelegatedThreadRun")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Debug for DelegatedUntrustedMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegatedUntrustedMaterial([redacted])")
    }
}
/// Current trusted registration resolution.
#[async_trait]
pub trait DelegationAuthority: Send + Sync {
    /// Resolve the exact current revision without distinguishing revocation reasons.
    async fn verify_current(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        source: &DelegationSource,
        revision: u64,
    ) -> Result<DelegationGrant, DelegationAuthorityError>;
}
/// Stable registration refusal or dependency failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationAuthorityError {
    /// Missing, revoked, expired or superseded registration.
    NotCurrent,
    /// Registration authority cannot be read.
    Unavailable,
}
/// Frozen registration facts; not a transport authority token.
#[derive(Clone)]
pub struct DelegationGrant {
    owner: ActorId,
    bot_id: BotId,
    revision: u64,
    granted_generation: AuthGeneration,
    expires_at: Option<SystemTime>,
    run_deadline: Option<Duration>,
    template: String,
}
impl core::fmt::Debug for DelegationGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DelegationGrant")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
impl DelegationGrant {
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: ActorId,
        bot_id: BotId,
        revision: u64,
        granted_generation: AuthGeneration,
        expires_at: Option<SystemTime>,
        run_deadline: Option<Duration>,
        template: String,
    ) -> Self {
        Self {
            owner,
            bot_id,
            revision,
            granted_generation,
            expires_at,
            run_deadline,
            template,
        }
    }
    /// Frozen owner.
    pub fn owner(&self) -> &ActorId {
        &self.owner
    }
    /// Frozen Bot.
    pub fn bot_id(&self) -> &BotId {
        &self.bot_id
    }
    /// Frozen registration revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Generation granted by the owner.
    pub fn granted_generation(&self) -> AuthGeneration {
        self.granted_generation
    }
    /// Registration expiry; absence means until revoked.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
    /// Frozen Run duration; absence means thirty minutes.
    pub fn run_deadline(&self) -> Option<Duration> {
        self.run_deadline
    }
    /// Frozen owner instructions.
    pub fn template(&self) -> &str {
        &self.template
    }
}
#[doc(hidden)]
pub struct DelegatedBegin {
    pub deployment: DeploymentId,
    pub tenant: TenantId,
    pub single_user: bool,
    pub request: BeginDelegatedThreadRun,
    pub grant: DelegationGrant,
}
#[doc(hidden)]
#[derive(Clone)]
pub struct DelegatedRunRecord {
    pub deployment: DeploymentId,
    pub tenant: TenantId,
    pub run_id: RunId,
    pub thread_id: ThreadId,
    pub bot_id: BotId,
    pub actor_id: ActorId,
    pub fencing: FencingToken,
    pub source: DelegationSource,
    pub revision: u64,
    pub trigger_id: String,
    pub granted_generation: AuthGeneration,
    pub expires_at: Option<SystemTime>,
    pub absolute_deadline: SystemTime,
    pub lease_expires_at: SystemTime,
}
impl core::fmt::Debug for DelegatedBegin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegatedBegin([redacted])")
    }
}
impl core::fmt::Debug for DelegatedRunRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegatedRunRecord([redacted])")
    }
}
#[doc(hidden)]
pub struct DelegatedCurrentRequest {
    pub record: DelegatedRunRecord,
    pub grant: DelegationGrant,
    pub expected_lease: RunExecutionLease,
}
impl core::fmt::Debug for DelegatedCurrentRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegatedCurrentRequest([redacted])")
    }
}
#[doc(hidden)]
pub struct DelegatedOwnerSnapshot {
    pub deployment: DeploymentId,
    pub tenant: TenantId,
    pub owner: ActorId,
    pub bot_id: BotId,
    pub roles: Vec<Role>,
    pub auth_generation: AuthGeneration,
    pub revoked: bool,
    pub bot_visible: bool,
    pub database_now: SystemTime,
}
#[doc(hidden)]
pub trait DelegatedContextIssuer: Send + Sync {
    fn issue(&self, owner: DelegatedOwnerSnapshot) -> Result<AuthContext, AppError>;
}
#[doc(hidden)]
#[async_trait]
pub trait DelegatedRunStore: Send + Sync {
    async fn begin(
        &self,
        request: DelegatedBegin,
        issuer: &dyn DelegatedContextIssuer,
    ) -> Result<ThreadRunStarted, AppError>;
    async fn load_run(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        run: &RunId,
    ) -> Result<Option<DelegatedRunRecord>, AppError>;
    async fn remint(
        &self,
        request: DelegatedCurrentRequest,
        issuer: &dyn DelegatedContextIssuer,
    ) -> Result<AuthContext, AppError>;
    async fn fail_confirmed_callback(
        &self,
        _record: &DelegatedRunRecord,
        _lease: &RunExecutionLease,
    ) -> Result<crate::RunWriteReceipt, crate::RunRuntimeError> {
        Err(crate::RunRuntimeError::Unavailable)
    }
}
struct Issuer {
    deployment: DeploymentId,
    tenant: TenantId,
    single_user: bool,
    source: DelegationSource,
    trigger: String,
    grant: DelegationGrant,
}
impl DelegatedContextIssuer for Issuer {
    fn issue(&self, facts: DelegatedOwnerSnapshot) -> Result<AuthContext, AppError> {
        if facts.deployment != self.deployment
            || facts.tenant != self.tenant
            || facts.owner != self.grant.owner
            || facts.bot_id != self.grant.bot_id
            || facts.revoked
            || !facts.bot_visible
            || facts.roles.is_empty()
            || facts.auth_generation != self.grant.granted_generation
            || self
                .grant
                .expires_at
                .is_some_and(|at| at <= facts.database_now)
        {
            return Err(not_current());
        }
        let delegation = VerifiedDelegation::from_verified_grant(
            self.source.clone(),
            self.grant.revision,
            self.trigger.clone(),
            self.grant.granted_generation,
            self.grant.expires_at,
        )
        .map_err(|_| not_current())?;
        Ok(AuthContextBuilder::from_verified_delegation(
            self.deployment.clone(),
            self.tenant.clone(),
            self.grant.owner.clone(),
            facts.auth_generation,
            self.single_user,
            delegation,
        )
        .with_roles(facts.roles)
        .build())
    }
}
/// Cloneable sole entry for starting delegated Runs.
#[derive(Clone)]
pub struct DelegatedRunEntry {
    runtime: Arc<DelegationRuntime>,
}
impl core::fmt::Debug for DelegatedRunEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegatedRunEntry([redacted])")
    }
}
impl DelegatedRunEntry {
    #[doc(hidden)]
    pub fn new(runtime: Arc<DelegationRuntime>) -> Self {
        Self { runtime }
    }
    /// Validate shape and current registration before the original atomic Run writer.
    pub async fn begin(
        &self,
        request: BeginDelegatedThreadRun,
    ) -> Result<ThreadRunStarted, AppError> {
        validate_request(&request)?;
        if !self.runtime.single_user {
            return Err(not_current());
        }
        let grant = self
            .runtime
            .verify(&request.source, request.revision)
            .await?;
        validate_grant(&grant, request.revision, &request.bot_id)?;
        let issuer = self.runtime.issuer(
            request.source.clone(),
            request.trigger_id.clone(),
            grant.clone(),
        );
        self.runtime
            .store
            .begin(
                DelegatedBegin {
                    deployment: self.runtime.deployment.clone(),
                    tenant: self.runtime.tenant.clone(),
                    single_user: self.runtime.single_user,
                    request,
                    grant,
                },
                &issuer,
            )
            .await
    }
}
struct RunBindingFacts {
    record: DelegatedRunRecord,
    sequence: u64,
    roles: std::collections::BTreeSet<Role>,
}
#[derive(Clone, Copy)]
enum DelegationProofOrigin {
    Lease,
    ConfirmedCallback,
}
enum CallbackTerminalState {
    Fresh,
    InFlight,
    Completed(Result<crate::RunWriteReceipt, crate::RunRuntimeError>),
}
struct RunBoundProof {
    auth: AuthContext,
    binding: RunBindingFacts,
    valid_until: Instant,
    origin: DelegationProofOrigin,
    terminal: Arc<Mutex<CallbackTerminalState>>,
}
pub(crate) struct DelegatedEffectGuard {
    coordinator: Arc<DelegationRuntime>,
    binding: RunBindingFacts,
    origin: DelegationProofOrigin,
    terminal: Arc<Mutex<CallbackTerminalState>>,
}
#[doc(hidden)]
pub struct DelegationRuntime {
    deployment: DeploymentId,
    tenant: TenantId,
    single_user: bool,
    authority: Arc<dyn DelegationAuthority>,
    store: Arc<dyn DelegatedRunStore>,
    proofs: Arc<Mutex<Vec<RunBoundProof>>>,
}
impl core::fmt::Debug for DelegationRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DelegationRuntime([redacted])")
    }
}
impl DelegationRuntime {
    #[doc(hidden)]
    pub fn new(
        deployment: DeploymentId,
        tenant: TenantId,
        single_user: bool,
        authority: Arc<dyn DelegationAuthority>,
        store: Arc<dyn DelegatedRunStore>,
    ) -> Self {
        Self {
            deployment,
            tenant,
            single_user,
            authority,
            store,
            proofs: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn shared(&self) -> Arc<Self> {
        Arc::new(Self {
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            single_user: self.single_user,
            authority: self.authority.clone(),
            store: self.store.clone(),
            proofs: self.proofs.clone(),
        })
    }
    fn issuer(&self, source: DelegationSource, trigger: String, grant: DelegationGrant) -> Issuer {
        Issuer {
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            single_user: self.single_user,
            source,
            trigger,
            grant,
        }
    }
    async fn verify(
        &self,
        source: &DelegationSource,
        revision: u64,
    ) -> Result<DelegationGrant, AppError> {
        self.authority
            .verify_current(&self.deployment, &self.tenant, source, revision)
            .await
            .map_err(|e| match e {
                DelegationAuthorityError::NotCurrent => not_current(),
                DelegationAuthorityError::Unavailable => AppError::DependencyUnavailable {
                    dependency: "delegation_authority",
                },
            })
    }
    async fn current(
        &self,
        lease: &RunExecutionLease,
    ) -> Result<(AuthContext, DelegatedRunRecord), AppError> {
        if !self.single_user {
            return Err(not_current());
        }
        let record = self
            .store
            .load_run(&self.deployment, &self.tenant, lease.run_id())
            .await?
            .ok_or_else(not_current)?;
        if record.deployment != self.deployment
            || record.tenant != self.tenant
            || record.run_id != *lease.run_id()
            || record.thread_id != *lease.thread_id()
            || record.bot_id != *lease.bot_id()
            || record.actor_id != *lease.actor_id()
            || record.fencing != lease.fencing()
            || record.lease_expires_at <= SystemTime::now()
            || record.absolute_deadline <= SystemTime::now()
        {
            return Err(not_current());
        }
        let grant = self.verify(&record.source, record.revision).await?;
        validate_grant(&grant, record.revision, &record.bot_id)?;
        if grant.owner != record.actor_id
            || grant.granted_generation != record.granted_generation
            || grant.expires_at.map(|at| {
                at.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
            }) != record.expires_at.map(|at| {
                at.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
            })
        {
            return Err(not_current());
        }
        let issuer = self.issuer(
            record.source.clone(),
            record.trigger_id.clone(),
            grant.clone(),
        );
        let auth = self
            .store
            .remint(
                DelegatedCurrentRequest {
                    record: record.clone(),
                    grant,
                    expected_lease: lease.clone(),
                },
                &issuer,
            )
            .await?;
        Ok((auth, record))
    }
    #[doc(hidden)]
    pub async fn check_sampling(&self, lease: &RunExecutionLease) -> Result<(), AppError> {
        self.current(lease).await.map(|_| ())
    }
    #[doc(hidden)]
    pub async fn remint_lease(&self, lease: &RunExecutionLease) -> Result<AuthContext, AppError> {
        self.issue_proof(lease, DelegationProofOrigin::Lease).await
    }
    async fn issue_proof(
        &self,
        lease: &RunExecutionLease,
        origin: DelegationProofOrigin,
    ) -> Result<AuthContext, AppError> {
        let (auth, record) = self.current(lease).await?;
        let now = SystemTime::now();
        let mut duration = record
            .lease_expires_at
            .duration_since(now)
            .map_err(|_| not_current())?
            .min(Duration::from_secs(30));
        duration = duration.min(
            record
                .absolute_deadline
                .duration_since(now)
                .map_err(|_| not_current())?,
        );
        if let Some(expiry) = record.expires_at {
            duration = duration.min(expiry.duration_since(now).map_err(|_| not_current())?);
        }
        if duration.is_zero() {
            return Err(not_current());
        }
        let mut proofs = self.proofs.lock().map_err(|_| not_current())?;
        proofs.retain(|p| p.valid_until > Instant::now());
        if proofs.len() >= 256 {
            return Err(not_current());
        }
        proofs.push(RunBoundProof {
            auth: auth.clone(),
            binding: RunBindingFacts {
                record,
                sequence: lease.next_event_sequence(),
                roles: auth.roles().clone(),
            },
            valid_until: Instant::now() + duration,
            origin,
            terminal: Arc::new(Mutex::new(CallbackTerminalState::Fresh)),
        });
        Ok(auth)
    }
    #[doc(hidden)]
    pub async fn remint_callback(
        &self,
        original: &RemoteCallbackAuthorization,
        lease: &RunExecutionLease,
    ) -> Result<AuthContext, AppError> {
        if original.run() != lease.run_id()
            || original.thread() != lease.thread_id()
            || original.bot() != lease.bot_id()
            || original.auth().actor() != lease.actor_id()
            || original.auth().deployment() != &self.deployment
            || original.auth().tenant() != &self.tenant
        {
            return Err(not_current());
        }
        self.issue_proof(lease, DelegationProofOrigin::ConfirmedCallback)
            .await
    }
    pub(crate) async fn admit_command(
        &self,
        auth: &AuthContext,
        command: &AppCommand,
    ) -> Result<DelegatedEffectGuard, AppError> {
        if !matches!(
            command,
            AppCommand::InvokeTool(_)
                | AppCommand::DecideComponent { .. }
                | AppCommand::AuthorizeSandboxedComponent { .. }
                | AppCommand::AwaitComponentHumanDecision(_)
        ) {
            return Err(refused());
        }
        let proof = {
            let mut proofs = self.proofs.lock().map_err(|_| refused())?;
            proofs.retain(|p| p.valid_until > Instant::now());
            let index = proofs
                .iter()
                .position(|p| {
                    p.auth == *auth
                        && p.auth
                            .delegation()
                            .zip(auth.delegation())
                            .is_some_and(|(a, b)| std::ptr::eq(a, b))
                })
                .ok_or_else(refused)?;
            proofs.remove(index)
        };
        let binding = &proof.binding;
        let valid = match command {
            AppCommand::InvokeTool(i) => {
                i.run_id == binding.record.run_id && i.bot_id == binding.record.bot_id
            }
            AppCommand::AwaitComponentHumanDecision(i) => {
                i.run_id == binding.record.run_id
                    && i.thread_id == binding.record.thread_id
                    && i.agent_id == binding.record.bot_id
            }
            AppCommand::DecideComponent { request, .. } => {
                request.agent_id == binding.record.bot_id
            }
            AppCommand::AuthorizeSandboxedComponent { agent_id, .. } => {
                *agent_id == binding.record.bot_id
            }
            _ => false,
        };
        if !valid {
            return Err(refused());
        }
        let guard = DelegatedEffectGuard {
            coordinator: self.shared(),
            binding: proof.binding,
            origin: proof.origin,
            terminal: proof.terminal,
        };
        self.check_effect(&guard).await?;
        Ok(guard)
    }
    pub(crate) async fn check_effect(&self, guard: &DelegatedEffectGuard) -> Result<(), AppError> {
        let b = &guard.binding;
        let lease = RunExecutionLease::new(
            b.record.run_id.clone(),
            b.record.thread_id.clone(),
            b.record.bot_id.clone(),
            b.record.actor_id.clone(),
            b.record.fencing,
            b.sequence,
        )
        .map_err(|_| not_current())?;
        let checked = async {
            let (current_auth, current) = self.current(&lease).await?;
            if current_auth.roles() != &b.roles
                || current.source != b.record.source
                || current.revision != b.record.revision
                || current.trigger_id != b.record.trigger_id
                || current.granted_generation != b.record.granted_generation
            {
                return Err(not_current());
            }
            Ok(())
        }
        .await;
        match checked {
            Ok(()) => Ok(()),
            Err(error) => self.current_failure(guard, &lease, error).await,
        }
    }
    async fn current_failure(
        &self,
        guard: &DelegatedEffectGuard,
        lease: &RunExecutionLease,
        error: AppError,
    ) -> Result<(), AppError> {
        if matches!(guard.origin, DelegationProofOrigin::Lease) {
            return Err(error);
        }
        let cached = {
            let mut state = guard
                .terminal
                .lock()
                .map_err(|_| AppError::DependencyUnavailable {
                    dependency: "delegation_terminal",
                })?;
            match &*state {
                CallbackTerminalState::Fresh => {
                    *state = CallbackTerminalState::InFlight;
                    None
                }
                CallbackTerminalState::InFlight => {
                    return Err(AppError::DependencyUnavailable {
                        dependency: "delegation_terminal",
                    });
                }
                CallbackTerminalState::Completed(result) => Some(*result),
            }
        };
        let result = match cached {
            Some(result) => result,
            None => {
                let result = self
                    .store
                    .fail_confirmed_callback(&guard.binding.record, lease)
                    .await;
                let mut state =
                    guard
                        .terminal
                        .lock()
                        .map_err(|_| AppError::DependencyUnavailable {
                            dependency: "delegation_terminal",
                        })?;
                *state = CallbackTerminalState::Completed(result);
                result
            }
        };
        match result {
            Ok(_) => Err(error),
            Err(crate::RunRuntimeError::CommitUnknown) => {
                Err(AppError::ReconciliationRequired { accepted: true })
            }
            Err(_) => Err(AppError::DependencyUnavailable {
                dependency: "delegation_terminal",
            }),
        }
    }
    #[doc(hidden)]
    pub fn retire_run(&self, run: &RunId) {
        if let Ok(mut proofs) = self.proofs.lock() {
            proofs.retain(|p| p.binding.record.run_id != *run && p.valid_until > Instant::now());
        }
    }
}
impl DelegatedEffectGuard {
    pub(crate) async fn recheck(&self) -> Result<(), AppError> {
        self.coordinator.check_effect(self).await
    }
}
fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}
fn validate_request(r: &BeginDelegatedThreadRun) -> Result<(), AppError> {
    let source = match &r.source {
        DelegationSource::ExternalBinding { binding_id } => binding_id,
        DelegationSource::AutomationDefinition { definition_id } => definition_id,
    };
    if !valid_identity(source)
        || !valid_identity(&r.trigger_id)
        || !ThreadIdentity::is_plausible(&r.thread_id)
        || r.run_id.as_str().is_empty()
        || r.run_id.as_str().as_bytes().contains(&0)
        || r.bot_id.as_str().is_empty()
        || r.bot_id.as_str().as_bytes().contains(&0)
    {
        return Err(AppError::MalformedPayload {
            field: "delegation",
        });
    }
    if r.untrusted_material.as_ref().is_some_and(|m| {
        m.source_ref.is_empty()
            || m.source_ref.len() > 256
            || !m.source_ref.is_ascii()
            || m.source_ref.as_bytes().contains(&0)
            || m.text.len() > 256 * 1024
            || m.text.as_bytes().contains(&0)
    }) {
        return Err(AppError::MalformedPayload {
            field: "untrusted_material",
        });
    }
    Ok(())
}
fn validate_grant(g: &DelegationGrant, revision: u64, bot: &BotId) -> Result<(), AppError> {
    let duration = g.run_deadline.unwrap_or(Duration::from_secs(1800));
    if g.owner.as_str().is_empty()
        || g.owner.as_str().as_bytes().contains(&0)
        || g.bot_id != *bot
        || g.revision != revision
        || g.template.len() > 16 * 1024
        || g.template.as_bytes().contains(&0)
        || duration < Duration::from_secs(1)
        || duration > Duration::from_secs(86400)
        || g.expires_at.is_some_and(|v| v <= SystemTime::now())
    {
        return Err(not_current());
    }
    Ok(())
}
fn not_current() -> AppError {
    AppError::PolicyRefused {
        rule: "delegation_not_current".into(),
        decision: None,
    }
}
fn refused() -> AppError {
    AppError::PolicyRefused {
        rule: "delegated_authority_refused".into(),
        decision: None,
    }
}
