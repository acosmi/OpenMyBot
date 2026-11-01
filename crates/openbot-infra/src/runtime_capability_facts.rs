//! Bounded, non-effectful capability observations issued by the actual PostgreSQL composition.
//! The last observation reads authority and every applicable source predicate in ONE statement.
//! No transaction, raw credential, source stamp or session tuple leaves this module.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::db::pool::DatabasePool as Pool;
use openbot_application::runtime_capabilities::{
    CapabilityDeadline, RuntimeCapabilitiesCollectionError as Error, RuntimeCapabilitiesCollector,
    RuntimeCapabilityHostScope, RuntimeCapabilityObservation, RuntimeCapabilityTailWitness,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::model_connections::CustomModelProtocol;
use openbot_contracts::request_binding::BorrowedServerSessionEpoch;
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::identity::session::{SessionLifetimePolicy, SessionState, evaluate_session};
use openbot_domain::policy::{ActionPolicy, CelFailure, CompiledRule, PolicyMode};
use openbot_domain::runtime_capabilities::*;
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::auth::single_user::desktop_local::{DESKTOP_LOCAL_EMAIL, DesktopLocalAuthority};
use crate::auth::single_user::{SINGLE_USER_EMAIL, VerifiedSingleUserPrincipal};
#[cfg(feature = "server-sso")]
use crate::auth::sso::ReadOnlySsoCapabilitySource;
// The narrower Local feature graph has no SSO service. This uninhabited type provides no
// observer, factory, constructor or configuration evidence; its only possible input is None.
#[cfg(not(feature = "server-sso"))]
#[derive(Clone, Copy)]
pub enum ReadOnlySsoCapabilitySource {}
#[cfg(not(feature = "server-sso"))]
impl ReadOnlySsoCapabilitySource {
    fn matches_pool_scope(&self, _pool: &Pool) -> bool {
        match *self {}
    }
    fn observe_rows(&self, _rows: &Value) -> ConfigFact {
        match *self {}
    }
    fn matches_tenant(&self, _tenant: &TenantId) -> bool {
        match *self {}
    }
}
use crate::policy::PolicyStore;
use crate::repo::{ChannelRepo, people_admin::PostgresPeopleAdministration};
use crate::thread_directory::PostgresThreadDirectory;
use crate::vault::CredentialRecordVault;

/// A trusted host factory consumes the dependencies just assembled for the same application.
pub trait RuntimeCapabilityCollectorFactory: Send + Sync {
    fn build(
        &self,
        facts: Arc<PostgresRuntimeCapabilityFacts>,
    ) -> Result<Arc<dyn RuntimeCapabilitiesCollector>, Error>;
}

/// Actual collector-owned non-secret revision sequence. It contains no configuration digest.
pub struct RuntimeCapabilityRevisionOwner {
    prefix: String,
    successful: AtomicU64,
}
impl RuntimeCapabilityRevisionOwner {
    pub fn new() -> Result<Self, Error> {
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).map_err(|_| Error::Unavailable)?;
        Ok(Self {
            prefix: uuid::Builder::from_random_bytes(entropy)
                .into_uuid()
                .simple()
                .to_string(),
            successful: AtomicU64::new(0),
        })
    }
    #[must_use]
    pub fn runtime_epoch(&self) -> std::num::NonZeroU64 {
        std::num::NonZeroU64::new(1).expect("fixed nonzero runtime epoch")
    }
    pub fn next(&self) -> Result<String, Error> {
        let prior = self
            .successful
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(format!("{}-{}", self.prefix, prior + 1))
    }
}

// Holding the exact named readers proves composition, including an empty directory. A boolean
// from configuration or an unrelated healthy pool cannot construct this private manifest.
struct WorkspaceReaders {
    _channels: ChannelRepo,
    _people: PostgresPeopleAdministration,
    _threads_and_history: PostgresThreadDirectory,
    _tools: crate::agent_tools::PostgresBuiltInToolControlPlane<
        crate::memory_admin::PostgresMemoryAdministration,
    >,
    _models: Arc<crate::model_connections::PostgresModelConnections>,
}

pub(crate) struct RuntimeCapabilityAssemblyFactsInput {
    pub pool: Pool,
    pub deployment: DeploymentId,
    pub tenant: TenantId,
    pub policy: PolicyStore,
    pub vault: CredentialRecordVault,
    pub default_key_id: String,
    pub environment_key: Option<Arc<SecretBytes>>,
    pub channels: ChannelRepo,
    pub people: PostgresPeopleAdministration,
    pub threads: PostgresThreadDirectory,
    pub tools: crate::agent_tools::PostgresBuiltInToolControlPlane<
        crate::memory_admin::PostgresMemoryAdministration,
    >,
    pub models: Arc<crate::model_connections::PostgresModelConnections>,
}

/// Own-pool raw observation capability. Only the actual application assembly constructs it.
pub struct PostgresRuntimeCapabilityFacts {
    pool: Pool,
    deployment: DeploymentId,
    tenant: TenantId,
    fallback: Option<ActionPolicy>,
    vault: CredentialRecordVault,
    default_key_id: String,
    environment_key: Option<Arc<SecretBytes>>,
    _workspace: WorkspaceReaders,
    workers: Arc<Workers>,
}

struct Workers {
    admission: Arc<Semaphore>,
    gate: Mutex<()>,
    closed: AtomicBool,
    active: AtomicUsize,
    completed: Notify,
}

struct ActualWorkerCompletion(Arc<Workers>);
impl Drop for ActualWorkerCompletion {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.completed.notify_waiters();
    }
}

// Field order releases the real permit before notifying actual completion. This value must
// move INSIDE the blocking worker; cancelling its waiter cannot finish the worker admission.
struct ActualWorkerAdmission {
    _permit: OwnedSemaphorePermit,
    _completion: ActualWorkerCompletion,
}

impl Workers {
    fn close(&self) {
        // Closing is admission revocation, not a worker-completion receipt. A thread may have
        // obtained its permit inside gate immediately before this publication.
        self.closed.store(true, Ordering::Release);
        self.admission.close();
    }

    fn try_admit(self: &Arc<Self>) -> Result<ActualWorkerAdmission, Error> {
        let _gate = self.gate.try_lock().map_err(|_| Error::Unavailable)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::NotCurrent);
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        Ok(self.register_admission(permit))
    }

    // Only called while the private admission gate is held, including the finite race test.
    fn register_admission(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> ActualWorkerAdmission {
        self.active.fetch_add(1, Ordering::AcqRel);
        ActualWorkerAdmission {
            _permit: permit,
            _completion: ActualWorkerCompletion(self.clone()),
        }
    }

    async fn drain(&self) {
        // drain is also a permanent admission barrier; it cannot race a later new admit.
        self.close();
        loop {
            let notified = self.completed.notified();
            tokio::pin!(notified);
            let _already_notified = notified.as_mut().enable();
            // Observe active ONLY after every admission critical section is quiescent. In
            // particular a permit obtained before close must be registered before zero may
            // mean drained. Never block an async executor thread on this standard mutex.
            let active = {
                match self.gate.try_lock() {
                    Ok(_gate) => Some(self.active.load(Ordering::Acquire)),
                    Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                        // Poison is fail-closed for future admission. Its recovered guard still
                        // establishes quiescence, and real already-admitted workers still drain.
                        let _gate = poisoned.into_inner();
                        Some(self.active.load(Ordering::Acquire))
                    }
                    Err(std::sync::TryLockError::WouldBlock) => None,
                }
            };
            let Some(active) = active else {
                tokio::task::yield_now().await;
                continue;
            };
            if active == 0 {
                return;
            }
            notified.await;
        }
    }
}

enum Authority<'a> {
    Session(BorrowedServerSessionEpoch<'a>, SessionLifetimePolicy),
    Canonical(&'static str),
}

/// A consumed, opaque last database snapshot; private clocks/epochs have no getters or Debug.
pub struct RuntimeCapabilityJointSnapshot {
    facts: RuntimeCapabilityFacts,
    tail: Arc<dyn RuntimeCapabilityTailWitness>,
}
impl RuntimeCapabilityJointSnapshot {
    pub fn with_local_confirmation(mut self, fact: LocalConfirmationFact) -> Self {
        self.facts.implementations.local_confirmation = supported();
        self.facts.local_confirmation = fact;
        self
    }
    pub fn apply(self, observation: RuntimeCapabilityObservation) -> RuntimeCapabilityObservation {
        observation
            .replace_facts(self.facts)
            .with_tail_witness(self.tail)
    }
    pub fn into_observation(
        self,
        scope: RuntimeCapabilityHostScope,
        revision: &str,
    ) -> Result<RuntimeCapabilityObservation, Error> {
        Ok(
            RuntimeCapabilityObservation::from_trusted_facts(scope, self.facts, revision)?
                .with_tail_witness(self.tail),
        )
    }
    pub fn with_host_tail(mut self, host: Arc<dyn RuntimeCapabilityTailWitness>) -> Self {
        self.tail = Arc::new(IntersectTail {
            database: self.tail,
            host,
        });
        self
    }
}
struct IntersectTail {
    database: Arc<dyn RuntimeCapabilityTailWitness>,
    host: Arc<dyn RuntimeCapabilityTailWitness>,
}
impl RuntimeCapabilityTailWitness for IntersectTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: CapabilityDeadline,
    ) -> Result<(), Error> {
        self.database.verify_current(auth, deadline)?;
        self.host.verify_current(auth, deadline)
    }
}
struct SessionTailClock {
    lifetime: SessionLifetimePolicy,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    expires: OffsetDateTime,
}
struct JointTail {
    scope: RuntimeCapabilityHostScope,
    session: Option<SessionTailClock>,
    monotonic: std::time::Instant,
    wall: std::time::SystemTime,
}
impl RuntimeCapabilityTailWitness for JointTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: CapabilityDeadline,
    ) -> Result<(), Error> {
        deadline.check()?;
        if !self.scope.matches_auth(auth) {
            return Err(Error::NotCurrent);
        }
        if std::time::Instant::now() < self.monotonic || std::time::SystemTime::now() < self.wall {
            return Err(Error::Unavailable);
        }
        if let Some(session) = &self.session {
            let now = OffsetDateTime::now_utc();
            if now >= session.expires {
                return Err(Error::NotCurrent);
            }
            let _live = evaluate_session(
                session.lifetime,
                SessionState::rehydrate(session.created, session.updated, auth.auth_generation()),
                auth.auth_generation(),
                now,
            )
            .map_err(|_| Error::NotCurrent)?;
        }
        deadline.check()
    }
}

impl PostgresRuntimeCapabilityFacts {
    pub(crate) fn from_assembly(input: RuntimeCapabilityAssemblyFactsInput) -> Result<Self, Error> {
        let RuntimeCapabilityAssemblyFactsInput {
            pool,
            deployment,
            tenant,
            policy,
            vault,
            default_key_id,
            environment_key,
            channels,
            people,
            threads,
            tools,
            models,
        } = input;
        if !policy.owns_pool(&pool) || !vault.matches_tenant(&tenant) {
            return Err(Error::MissingHostSource);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            fallback: policy.configured_fallback(),
            vault,
            default_key_id,
            environment_key,
            _workspace: WorkspaceReaders {
                _channels: channels,
                _people: people,
                _threads_and_history: threads,
                _tools: tools,
                _models: models,
            },
            workers: Arc::new(Workers {
                admission: Arc::new(Semaphore::new(1)),
                gate: Mutex::new(()),
                closed: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                completed: Notify::new(),
            }),
        })
    }

    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && &self.deployment == deployment
            && &self.tenant == tenant
    }

    /// Close before host resource drain. In-flight workers retain their admission until real end.
    pub fn close(&self) {
        self.workers.close();
    }

    /// Permanently revoke admission, wait for its critical section, then real worker completion.
    pub async fn drain(&self) {
        self.workers.drain().await;
    }

    #[must_use]
    pub fn is_current(&self) -> bool {
        !self.workers.closed.load(Ordering::Acquire)
    }

    pub async fn observe_server_session(
        &self,
        auth: &AuthContext,
        epoch: BorrowedServerSessionEpoch<'_>,
        lifetime: SessionLifetimePolicy,
        scope: &RuntimeCapabilityHostScope,
        sso: Option<&ReadOnlySsoCapabilitySource>,
        deadline: CapabilityDeadline,
    ) -> Result<RuntimeCapabilityJointSnapshot, Error> {
        self.observe(
            auth,
            Authority::Session(epoch, lifetime),
            scope,
            sso,
            deadline,
        )
        .await
    }

    pub async fn observe_single_user(
        &self,
        auth: &AuthContext,
        principal: &VerifiedSingleUserPrincipal,
        scope: &RuntimeCapabilityHostScope,
        sso: Option<&ReadOnlySsoCapabilitySource>,
        deadline: CapabilityDeadline,
    ) -> Result<RuntimeCapabilityJointSnapshot, Error> {
        if !principal.matches_pool_scope(&self.pool) || principal.auth_context() != auth {
            return Err(Error::NotCurrent);
        }
        self.observe(
            auth,
            Authority::Canonical(SINGLE_USER_EMAIL),
            scope,
            sso,
            deadline,
        )
        .await
    }

    pub async fn observe_desktop_local(
        &self,
        auth: &AuthContext,
        installation: &DesktopLocalAuthority,
        scope: &RuntimeCapabilityHostScope,
        deadline: CapabilityDeadline,
    ) -> Result<RuntimeCapabilityJointSnapshot, Error> {
        let original = installation.auth_context();
        if auth.deployment() != original.deployment()
            || auth.tenant() != original.tenant()
            || auth.actor() != original.actor()
            || auth.roles() != original.roles()
            || !auth.is_single_user()
        {
            return Err(Error::NotCurrent);
        }
        self.observe(
            auth,
            Authority::Canonical(DESKTOP_LOCAL_EMAIL),
            scope,
            None,
            deadline,
        )
        .await
    }

    async fn observe(
        &self,
        auth: &AuthContext,
        authority: Authority<'_>,
        scope: &RuntimeCapabilityHostScope,
        sso: Option<&ReadOnlySsoCapabilitySource>,
        deadline: CapabilityDeadline,
    ) -> Result<RuntimeCapabilityJointSnapshot, Error> {
        deadline.check()?;
        if !self.is_current() {
            return Err(Error::NotCurrent);
        }
        if auth.deployment() != &self.deployment || auth.tenant() != &self.tenant {
            return Err(Error::NotCurrent);
        }
        if sso.is_some_and(|source| {
            !source.matches_pool_scope(&self.pool) || !source.matches_tenant(&self.tenant)
        }) {
            return Err(Error::MissingHostSource);
        }
        // The original request's admission is held through the facts transaction
        // and its Vault-opens; the returned tail stays synchronous and holds none.
        let binding = auth.request_binding().ok_or(Error::Unavailable)?;
        let admission = binding
            .borrow_recovery_admission_before(auth, deadline.deadline())
            .await
            .map_err(|_| Error::Unavailable)?;
        let current = || {
            admission
                .verify_current_before(binding, auth, deadline.deadline())
                .map_err(|_| Error::Unavailable)
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.deadline()), async {
            let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
            let tx = client.build_transaction().isolation_level(tokio_postgres::IsolationLevel::ReadCommitted).read_only(true).start().await.map_err(|_| Error::Unavailable)?;
            let observed = async {
                let milliseconds = deadline.remaining()?.as_millis().min(5_000);
                if milliseconds == 0 { return Err(Error::Unavailable); }
                tx.batch_execute(&format!("SET LOCAL statement_timeout='{milliseconds}ms'; SET LOCAL lock_timeout='{milliseconds}ms'")).await.map_err(|_| Error::Unavailable)?;
                let session_id = match &authority { Authority::Session(epoch, _) => Some(epoch.lookup_id()), Authority::Canonical(_) => None };
                let row = tx.query_one(JOINT_FACTS_SQL, &[&auth.actor().as_str(), &self.deployment.as_str(), &self.tenant.as_str(), &self.default_key_id, &session_id,&sso.is_some()]).await.map_err(|_| Error::Unavailable)?;
                let session = check_authority(&row, auth, &authority)?;
                let tail=Arc::new(JointTail { scope:scope.clone(),session,monotonic:std::time::Instant::now(),wall:std::time::SystemTime::now() });
                deadline.check()?;
                let unconfirmed = unconfirmed_sources(&*tx, &row, admission.restore_cohort(), deadline).await?;
                current()?;
                let mut facts = self.parse_snapshot(row, sso.cloned(), scope.host_mode()==HostMode::Server, deadline, unconfirmed).await?;
                if !auth.has_role(Role::User) && !auth.has_role(Role::Admin) {
                    facts.product_permissions = [PermissionFact::Denied;13];
                }
                Ok(RuntimeCapabilityJointSnapshot { facts,tail })
            }.await;
            // SQL/decoder/parser errors are also held until explicit rollback completes.
            tx.rollback().await.map_err(|_| Error::Unavailable)?;
            deadline.check()?;
            if !self.is_current() { return Err(Error::NotCurrent); }
            current()?;
            observed
        }).await.map_err(|_| Error::Unavailable)?
    }

    async fn parse_snapshot(
        &self,
        row: Row,
        sso: Option<ReadOnlySsoCapabilitySource>,
        server_sso: bool,
        deadline: CapabilityDeadline,
        unconfirmed: UnconfirmedSources,
    ) -> Result<RuntimeCapabilityFacts, Error> {
        let policy: Value = row.try_get("policy").map_err(|_| Error::Unavailable)?;
        let custom: Value = row
            .try_get("custom_models")
            .map_err(|_| Error::Unavailable)?;
        let credentials: Value = row
            .try_get("default_credentials")
            .map_err(|_| Error::Unavailable)?;
        let sso_rows: Value = row.try_get("sso_rows").map_err(|_| Error::Unavailable)?;
        let admission = self.workers.try_admit()?;
        let fallback = self.fallback.clone();
        let vault = self.vault.clone();
        let actor = auth_actor_from_row(&row)?;
        let environment = self.environment_key.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let _tracked_worker = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let result = (|| {
                deadline.check()?;
                let acting_policy = observe_policy(&policy, fallback.as_ref(), deadline)?;
                deadline.check()?;
                let model_key = if unconfirmed.default_key {
                    ModelKeyFact::Unknown
                } else {
                    observe_default_key(&credentials, &vault, environment.as_deref())
                };
                let (custom_model_config, custom_key) =
                    observe_custom(&custom, &vault, &actor, &unconfirmed.connections);
                let sso_config = sso.as_ref().map_or(
                    if server_sso {
                        ConfigFact::Unknown
                    } else {
                        ConfigFact::Missing
                    },
                    |source| source.observe_rows(&sso_rows),
                );
                deadline.check()?;
                let mut facts = base_facts();
                facts.acting_policy = acting_policy;
                facts.model_key = model_key;
                facts.custom_model_config = custom_model_config;
                facts.custom_model.key = custom_key;
                facts.sso_config = sso_config;
                if server_sso || sso.is_some() {
                    facts.implementations.dynamic_sso = supported();
                }
                Ok(facts)
            })();
            let _ = sender.send(result);
        });
        receiver.await.map_err(|_| Error::Unavailable)?
    }
}

/// Restored credential sources not yet reconfirmed: their Vault-opens are skipped.
struct UnconfirmedSources {
    default_key: bool,
    connections: std::collections::BTreeSet<String>,
}

/// Read inside the facts transaction, before parsing and any Vault-open.
async fn unconfirmed_sources<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    row: &Row,
    cohort: Option<openbot_contracts::recovery::RestoreCohortRef>,
    deadline: CapabilityDeadline,
) -> Result<UnconfirmedSources, Error> {
    use crate::restore_reconfirmation::{
        RequirementKind, RequirementSource, RestoreReconfirmationError, require_confirmed_before,
    };
    let mut sources = UnconfirmedSources {
        default_key: false,
        connections: std::collections::BTreeSet::new(),
    };
    if cohort.is_none() {
        return Ok(sources);
    }
    let unconfirmed = |result: Result<(), RestoreReconfirmationError>| match result {
        Ok(()) => Ok(false),
        Err(RestoreReconfirmationError::NotConfirmed) => Ok(true),
        Err(RestoreReconfirmationError::Unavailable) => Err(Error::Unavailable),
    };
    let credentials: Value = row
        .try_get("default_credentials")
        .map_err(|_| Error::Unavailable)?;
    if let Some(id) = credentials
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("id"))
        .and_then(Value::as_str)
    {
        let source = RequirementSource {
            cohort,
            kind: RequirementKind::Credential,
            source_ref: id,
        };
        sources.default_key =
            unconfirmed(require_confirmed_before(tx, source, deadline.deadline()).await)?;
    }
    let custom: Value = row
        .try_get("custom_models")
        .map_err(|_| Error::Unavailable)?;
    for id in custom
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
    {
        let source = RequirementSource {
            cohort,
            kind: RequirementKind::ModelSecret,
            source_ref: id,
        };
        if unconfirmed(require_confirmed_before(tx, source, deadline.deadline()).await)? {
            sources.connections.insert(id.to_owned());
        }
    }
    Ok(sources)
}

fn auth_actor_from_row(row: &Row) -> Result<ActorId, Error> {
    let id: String = row.try_get("user_id").map_err(|_| Error::Unavailable)?;
    Ok(ActorId::new(id))
}

fn check_authority(
    row: &Row,
    expected: &AuthContext,
    source: &Authority<'_>,
) -> Result<Option<SessionTailClock>, Error> {
    let id: Option<String> = row.try_get("user_id").map_err(|_| Error::Unavailable)?;
    let id = id.ok_or(Error::NotCurrent)?;
    let generation: Option<i64> = row
        .try_get("current_generation")
        .map_err(|_| Error::Unavailable)?;
    let generation = generation
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(Error::NotCurrent)?;
    let revoked: bool = row.try_get("revoked").map_err(|_| Error::Unavailable)?;
    let roles: Vec<String> = row.try_get("roles").map_err(|_| Error::Unavailable)?;
    if revoked || generation != expected.auth_generation().get() || id != expected.actor().as_str()
    {
        return Err(Error::NotCurrent);
    }
    match source {
        Authority::Canonical(email) => {
            let actual: Option<String> = row.try_get("email").map_err(|_| Error::Unavailable)?;
            if actual.as_deref() != Some(*email) || roles != ["admin"] || !expected.is_single_user()
            {
                return Err(Error::NotCurrent);
            }
        }
        Authority::Session(epoch, lifetime) => {
            let session_id: Option<String> =
                row.try_get("session_id").map_err(|_| Error::Unavailable)?;
            let user: Option<String> = row
                .try_get("session_user_id")
                .map_err(|_| Error::Unavailable)?;
            let token: Option<String> = row
                .try_get("session_token")
                .map_err(|_| Error::Unavailable)?;
            let created: Option<OffsetDateTime> = row
                .try_get("session_created")
                .map_err(|_| Error::Unavailable)?;
            let updated: Option<OffsetDateTime> = row
                .try_get("session_updated")
                .map_err(|_| Error::Unavailable)?;
            let expires: Option<OffsetDateTime> = row
                .try_get("session_expires")
                .map_err(|_| Error::Unavailable)?;
            let issued: Option<i64> = row
                .try_get("session_generation")
                .map_err(|_| Error::Unavailable)?;
            let (
                Some(session_id),
                Some(user),
                Some(token),
                Some(created),
                Some(updated),
                Some(expires),
                Some(issued),
            ) = (session_id, user, token, created, updated, expires, issued)
            else {
                return Err(Error::NotCurrent);
            };
            if !epoch.matches_raw_row(&session_id, &user, &token, created, issued)
                || u64::try_from(issued).ok() != Some(generation)
            {
                return Err(Error::NotCurrent);
            }
            let now = OffsetDateTime::now_utc();
            if now >= expires {
                return Err(Error::NotCurrent);
            }
            let _live = evaluate_session(
                *lifetime,
                SessionState::rehydrate(created, updated, AuthGeneration::new(generation)),
                AuthGeneration::new(generation),
                now,
            )
            .map_err(|_| Error::NotCurrent)?;
            let parsed = roles
                .iter()
                .map(|value| value.parse::<Role>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::Unavailable)?;
            let role =
                resolve_effective_role(parsed.iter().copied()).map_err(|_| Error::NotCurrent)?;
            let actual = AuthContextBuilder::from_verified_session(
                expected.deployment().clone(),
                expected.tenant().clone(),
                ActorId::new(id),
                AuthGeneration::new(generation),
                false,
            )
            .with_role(role)
            .build();
            if &actual != expected {
                return Err(Error::NotCurrent);
            }
            return Ok(Some(SessionTailClock {
                lifetime: *lifetime,
                created,
                updated,
                expires,
            }));
        }
    }
    Ok(None)
}

fn observe_policy(
    value: &Value,
    fallback: Option<&ActionPolicy>,
    deadline: CapabilityDeadline,
) -> Result<PolicyFact, Error> {
    let classify = || -> PolicyFact {
        let Some(rows) = value.as_array() else {
            return PolicyFact::Unknown;
        };
        let owned;
        let policy = match rows.as_slice() {
            [] => match fallback {
                Some(policy) => policy,
                None => return PolicyFact::Unconfigured,
            },
            [row] => {
                if row.get("bounded").and_then(Value::as_bool) != Some(true) {
                    return PolicyFact::Unknown;
                }
                if row.get("id").and_then(Value::as_str) != Some("current") {
                    return PolicyFact::Invalid;
                }
                let Some(mode) = row
                    .get("mode")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<PolicyMode>().ok())
                else {
                    return PolicyFact::Invalid;
                };
                let Some(deny) = strings(row.get("deny")) else {
                    return PolicyFact::Invalid;
                };
                let Some(allow) = strings(row.get("allow")) else {
                    return PolicyFact::Invalid;
                };
                owned = ActionPolicy { mode, deny, allow };
                &owned
            }
            _ => return PolicyFact::Invalid,
        };
        if policy.deny.len().saturating_add(policy.allow.len()) > 256
            || policy
                .deny
                .iter()
                .chain(&policy.allow)
                .map(String::len)
                .sum::<usize>()
                > 128 * 1024
        {
            return PolicyFact::Unknown;
        }
        if policy.deny.is_empty() && policy.allow.is_empty() {
            return PolicyFact::Empty;
        }
        for rule in policy.deny.iter().chain(&policy.allow) {
            if deadline.check().is_err() {
                return PolicyFact::Unknown;
            }
            if let Some(failure) = CompiledRule::compile(rule).compile_failure() {
                return if failure == CelFailure::Runtime {
                    PolicyFact::Unknown
                } else {
                    PolicyFact::Invalid
                };
            }
        }
        PolicyFact::Configured
    };
    let result = classify();
    deadline.check()?;
    Ok(result)
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn observe_default_key(
    value: &Value,
    vault: &CredentialRecordVault,
    environment: Option<&SecretBytes>,
) -> ModelKeyFact {
    let Some(rows) = value.as_array() else {
        return ModelKeyFact::Unknown;
    };
    let Some(row) = rows.first() else {
        return match environment {
            Some(key)
                if crate::provider::openai::OpenAiApiKey::from_bytes(key.expose().to_vec())
                    .is_ok() =>
            {
                ModelKeyFact::Present
            }
            Some(_) => ModelKeyFact::Unknown,
            None => ModelKeyFact::Absent,
        };
    };
    let Some(stored) = row.get("encrypted_value").and_then(Value::as_str) else {
        return ModelKeyFact::Unknown;
    };
    let Some(id) = row
        .get("id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return ModelKeyFact::Unknown;
    };
    let Ok(opened) = vault.open(
        &id,
        SecretKind::Model,
        SecretPrincipal::Deployment,
        SecretPrincipal::Deployment,
        stored,
    ) else {
        return ModelKeyFact::Unknown;
    };
    if opened.needs_migration() {
        return ModelKeyFact::Unknown;
    }
    if crate::provider::openai::OpenAiApiKey::from_secret(opened.into_secret()).is_ok() {
        ModelKeyFact::Present
    } else {
        ModelKeyFact::Unknown
    }
}

fn observe_custom(
    value: &Value,
    vault: &CredentialRecordVault,
    actor: &ActorId,
    unconfirmed: &std::collections::BTreeSet<String>,
) -> (ConfigFact, ModelKeyFact) {
    let Some(rows) = value.as_array() else {
        return (ConfigFact::Unknown, ModelKeyFact::Unknown);
    };
    if rows.len() > 256 {
        return (ConfigFact::Unknown, ModelKeyFact::Unknown);
    }
    if rows.is_empty() {
        return (ConfigFact::Missing, ModelKeyFact::Absent);
    }
    let mut configuration = false;
    let mut key = false;
    let mut unknown = false;
    for row in rows {
        if row.get("bounded").and_then(Value::as_bool) != Some(true) {
            return (ConfigFact::Unknown, ModelKeyFact::Unknown);
        }
        let text = |field| row.get(field).and_then(Value::as_str);
        let protocol = match text("protocol") {
            Some("openai_chat_completions") => CustomModelProtocol::OpenaiChatCompletions,
            Some("openai_responses") => CustomModelProtocol::OpenaiResponses,
            Some("anthropic_messages") => CustomModelProtocol::AnthropicMessages,
            _ => continue,
        };
        let (Some(name), Some(endpoint), Some(model), Some(id)) =
            (text("name"), text("endpoint"), text("model"), text("id"))
        else {
            continue;
        };
        if !crate::model_connections::readonly_configuration_valid(
            name,
            protocol,
            endpoint,
            model,
            row.get("revision").and_then(Value::as_i64),
        ) {
            continue;
        }
        configuration = true;
        if row.get("secret_id").is_some_and(Value::is_null) {
            continue;
        }
        let (Some(secret_id), Some(stored)) = (
            text("secret_id").and_then(|value| Uuid::parse_str(value).ok()),
            text("encrypted_value"),
        ) else {
            unknown = true;
            continue;
        };
        if unconfirmed.contains(id) {
            unknown = true;
            continue;
        }
        let Ok(opened) = vault.open(
            &secret_id,
            SecretKind::Model,
            SecretPrincipal::Actor(actor.clone()),
            SecretPrincipal::Service(ServiceId::new(id)),
            stored,
        ) else {
            unknown = true;
            continue;
        };
        if opened.needs_migration() {
            unknown = true;
            continue;
        }
        let secret = opened.into_secret();
        let Ok(text) = core::str::from_utf8(secret.expose()) else {
            unknown = true;
            continue;
        };
        if text.is_empty()
            || text.len() > 16 * 1024
            || text.trim() != text
            || text.contains(['\r', '\n', '\0'])
        {
            unknown = true;
            continue;
        }
        key = true;
    }
    if key {
        (ConfigFact::Present, ModelKeyFact::Present)
    } else if configuration {
        (
            ConfigFact::Present,
            if unknown {
                ModelKeyFact::Unknown
            } else {
                ModelKeyFact::Absent
            },
        )
    } else {
        (ConfigFact::Invalid, ModelKeyFact::Absent)
    }
}

fn supported() -> Presence {
    Presence::Present {
        independent_api: Evidence::Present,
        release_dependency: Evidence::Present,
    }
}
fn independent_missing() -> Presence {
    Presence::Present {
        independent_api: Evidence::Missing,
        release_dependency: Evidence::Present,
    }
}
fn base_facts() -> RuntimeCapabilityFacts {
    RuntimeCapabilityFacts {
        implementations: ImplementationSet {
            workspace: supported(),
            agent_tools: supported(),
            model_custom_v1: supported(),
            model_selection_v2: independent_missing(),
            model_sdk_gateway: independent_missing(),
            model_account_bridge: independent_missing(),
            browser_control: independent_missing(),
            native_control: independent_missing(),
            pixel_egress: independent_missing(),
            local_confirmation: Presence::Absent,
            backup_restore: independent_missing(),
            dynamic_sso: Presence::Absent,
            device_pairing: independent_missing(),
        },
        acting_policy: PolicyFact::Unknown,
        model_key: ModelKeyFact::Unknown,
        custom_model: ModelSourceFacts {
            key: ModelKeyFact::Unknown,
            provider: ProviderFact::Unknown,
        },
        sdk_model: ModelSourceFacts {
            key: ModelKeyFact::Unknown,
            provider: ProviderFact::Unknown,
        },
        bridge_model: ModelSourceFacts {
            key: ModelKeyFact::Unknown,
            provider: ProviderFact::Unknown,
        },
        custom_model_config: ConfigFact::Unknown,
        selection_v2_config: ConfigFact::Unknown,
        sdk_gateway_config: ConfigFact::Unknown,
        account_bridge_config: ConfigFact::Unknown,
        account_bridge_source: BridgeSourceFact::Unknown,
        backup_config: ConfigFact::Unknown,
        sso_config: ConfigFact::Missing,
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
        local_confirmation: LocalConfirmationFact::Unavailable,
    }
}

// Bounded before materialization, including negative insertions; no old-id-only reread.
const JOINT_FACTS_SQL: &str = r#"
WITH policy_scan AS MATERIALIZED (SELECT CASE WHEN octet_length(p.id)<=512 THEN p.id END AS id,
  CASE WHEN octet_length(p.mode)<=512 THEN p.mode END AS mode,
  CASE WHEN bounds.bounded THEN p.deny END AS deny,CASE WHEN bounds.bounded THEN p.allow END AS allow,bounds.bounded
  FROM public.action_policy p CROSS JOIN LATERAL (SELECT
  CASE WHEN coalesce(cardinality(p.deny),0)+coalesce(cardinality(p.allow),0)<=256 THEN
  coalesce((SELECT sum(octet_length(x)::bigint) FROM unnest(coalesce(p.deny,ARRAY[]::text[])||coalesce(p.allow,ARRAY[]::text[])) x),0)<=131072 ELSE false END AS bounded) bounds ORDER BY p.id LIMIT 2),
custom_scan AS MATERIALIZED (SELECT mc.id,ms.id AS secret_id,
  coalesce(octet_length(ms.encrypted_value),0)<=65536 AS cipher_bounded,
  44::bigint+CASE WHEN ms.id IS NULL THEN 0 ELSE 36 END+coalesce(octet_length(mc.name),0)::bigint+coalesce(octet_length(mc.protocol),0)::bigint+
  coalesce(octet_length(mc.endpoint),0)::bigint+coalesce(octet_length(mc.model),0)::bigint+coalesce(octet_length(ms.encrypted_value),0)::bigint AS bytes
  FROM public.model_connections mc LEFT JOIN public.model_connection_secrets ms ON ms.id=mc.current_secret_id
  AND ms.connection_id=mc.id AND ms.deployment_id=mc.deployment_id AND ms.tenant_id=mc.tenant_id AND ms.owner_user_id=mc.owner_user_id AND ms.retired_at IS NULL
  WHERE mc.deployment_id=$2 AND mc.tenant_id=$3 AND mc.owner_user_id=$1 AND mc.enabled=true AND mc.deleted_at IS NULL ORDER BY mc.id LIMIT 257),
custom_bounded AS MATERIALIZED (SELECT scan.id,scan.secret_id,mc.revision,bounds.bounded,
  CASE WHEN bounds.bounded THEN mc.name END AS name,CASE WHEN bounds.bounded THEN mc.protocol END AS protocol,
  CASE WHEN bounds.bounded THEN mc.endpoint END AS endpoint,CASE WHEN bounds.bounded THEN mc.model END AS model,
  CASE WHEN bounds.bounded THEN ms.encrypted_value END AS encrypted_value
  FROM custom_scan scan JOIN public.model_connections mc ON mc.id=scan.id
  LEFT JOIN public.model_connection_secrets ms ON ms.id=scan.secret_id AND ms.connection_id=mc.id
  AND ms.deployment_id=mc.deployment_id AND ms.tenant_id=mc.tenant_id AND ms.owner_user_id=mc.owner_user_id AND ms.retired_at IS NULL
  CROSS JOIN LATERAL (SELECT scan.cipher_bounded AND scan.bytes<=1048576 AND totals.total<=1048576 AND totals.count<=256 AS bounded
    FROM (SELECT sum(bytes) AS total,count(*) AS count FROM custom_scan) totals) bounds),
sso_scan AS MATERIALIZED (SELECT CASE WHEN octet_length(id)<=512 THEN id END AS id,
  coalesce(octet_length(oidc_config),0)<=65536 AND coalesce(octet_length(saml_config),0)<=65536 AS cipher_bounded,
  coalesce(octet_length(id),0)::bigint+coalesce(octet_length(issuer),0)::bigint+coalesce(octet_length(provider_id),0)::bigint+
  coalesce(octet_length(domain),0)::bigint+coalesce(octet_length(organization_id),0)::bigint+
  coalesce(octet_length(oidc_config),0)::bigint+coalesce(octet_length(saml_config),0)::bigint AS bytes
  FROM public.sso_providers WHERE $6::boolean ORDER BY id LIMIT 257),
sso_bounded AS MATERIALIZED (SELECT bounds.bounded,
  CASE WHEN bounds.bounded THEN provider.provider_id END AS provider_id,CASE WHEN bounds.bounded THEN provider.issuer END AS issuer,
  CASE WHEN bounds.bounded THEN provider.domain END AS domain,CASE WHEN bounds.bounded THEN provider.organization_id END AS organization_id,
  CASE WHEN bounds.bounded THEN provider.oidc_config END AS oidc_config,CASE WHEN bounds.bounded THEN provider.saml_config END AS saml_config
  FROM sso_scan scan LEFT JOIN public.sso_providers provider ON provider.id=scan.id
  CROSS JOIN LATERAL (SELECT scan.id IS NOT NULL AND scan.cipher_bounded AND scan.bytes<=1048576 AND totals.total<=1048576 AND totals.count<=256 AS bounded
    FROM (SELECT sum(bytes) AS total,count(*) AS count FROM sso_scan) totals) bounds)
SELECT u.id AS user_id,CASE WHEN octet_length(u.email)<=512 THEN u.email END AS email,u.auth_generation AS current_generation,
  EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS revoked,
  ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles,
  s.id AS session_id,s.user_id AS session_user_id,CASE WHEN octet_length(s.token)<=512 THEN s.token END AS session_token,s.created_at AS session_created,s.updated_at AS session_updated,s.expires_at AS session_expires,s.auth_generation AS session_generation,
  coalesce((SELECT jsonb_agg(jsonb_build_object('id',CASE WHEN octet_length(id)<=512 THEN id END,'mode',CASE WHEN octet_length(mode)<=512 THEN mode END,'bounded',bounded,
    'deny',CASE WHEN bounded THEN deny END,'allow',CASE WHEN bounded THEN allow END)) FROM policy_scan),'[]'::jsonb) AS policy,
  coalesce((SELECT jsonb_agg(CASE WHEN bounded THEN jsonb_build_object('bounded',true,'id',id,'name',name,'protocol',protocol,'endpoint',endpoint,'model',model,'revision',revision,'secret_id',secret_id,'encrypted_value',encrypted_value)
    ELSE jsonb_build_object('bounded',false) END) FROM custom_bounded),'[]'::jsonb) AS custom_models,
  coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'encrypted_value',CASE WHEN octet_length(encrypted_value)<=65536 THEN encrypted_value END)) FROM
    (SELECT id,encrypted_value FROM public.credentials WHERE kind='model' AND provider='openai' AND key_id=$4 AND revoked_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1) credential),'[]'::jsonb) AS default_credentials,
  coalesce((SELECT jsonb_agg(CASE WHEN bounded THEN jsonb_build_object('bounded',true,'provider_id',provider_id,'issuer',issuer,'domain',domain,'organization_id',organization_id,'oidc_config',oidc_config,'saml_config',saml_config)
    ELSE jsonb_build_object('bounded',false) END) FROM sso_bounded),'[]'::jsonb) AS sso_rows,
  EXISTS(SELECT 1 FROM public.channels c WHERE c.id IN (SELECT cm.channel_id FROM public.channel_memberships cm WHERE cm.user_id=$1)) AS channel_reader,
  EXISTS(SELECT 1 FROM public.threads t WHERE t.deployment_id=$2 AND t.tenant_id=$3 AND t.created_by=$1) AS thread_reader,
  EXISTS(SELECT 1 FROM public.messages m JOIN public.threads t ON t.thread_id=m.thread_id WHERE t.deployment_id=$2 AND t.tenant_id=$3 AND t.created_by=$1) AS history_reader
FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$1 LEFT JOIN public.sessions s ON s.id=$5 AND s.user_id=u.id
"#;

#[cfg(test)]
mod worker_admission_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn workers() -> Arc<Workers> {
        Arc::new(Workers {
            admission: Arc::new(Semaphore::new(1)),
            gate: Mutex::new(()),
            closed: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            completed: Notify::new(),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_drain_waits_for_real_permit_paused_before_active_registration() {
        let workers = workers();
        let (paused_tx, paused_rx) = tokio::sync::oneshot::channel();
        let (registered_tx, registered_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let actual = workers.clone();
        let worker = std::thread::spawn(move || {
            // Exercise the actual gate/permit interval that preceded active registration.
            // Only this private finite test splits the synchronous production critical section.
            let gate = actual.gate.try_lock().expect("new real gate");
            assert!(!actual.closed.load(Ordering::Acquire));
            let permit = actual
                .admission
                .clone()
                .try_acquire_owned()
                .expect("real permit");
            paused_tx.send(()).expect("live test controller");
            resume_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("finite registration release");
            let admission = actual.register_admission(permit);
            drop(gate);
            registered_tx.send(()).expect("live registration observer");
            finish_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("finite actual worker release");
            drop(admission);
        });
        paused_rx
            .await
            .expect("actual permit acquired before registration");
        assert_eq!(workers.active.load(Ordering::Acquire), 0);
        assert_eq!(workers.admission.available_permits(), 0);
        workers.close();
        let draining = workers.clone();
        let mut drain = tokio::spawn(async move { draining.drain().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut drain)
                .await
                .is_err()
        );
        resume_tx
            .send(())
            .expect("actual registration is still pending");
        registered_rx.await.expect("actual permit now registered");
        assert_eq!(workers.active.load(Ordering::Acquire), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut drain)
                .await
                .is_err()
        );
        finish_tx
            .send(())
            .expect("actual admitted worker is still pending");
        worker.join().expect("real finite worker ended");
        tokio::time::timeout(Duration::from_secs(1), &mut drain)
            .await
            .expect("drain sees actual end")
            .expect("drain task");
        assert_eq!(workers.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn drain_permanently_closes_admission_without_a_prior_close_call() {
        let workers = workers();
        workers.drain().await;
        assert!(workers.closed.load(Ordering::Acquire));
        assert!(matches!(workers.try_admit(), Err(Error::NotCurrent)));
        workers.close();
        workers.drain().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_does_not_release_actual_blocking_worker_admission() {
        let workers = workers();
        let admission = workers.try_admit().expect("actual admission");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            started_tx.send(()).expect("live worker observer");
            finish_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("finite actual work release");
        });
        let waiter = tokio::spawn(async move { worker.await.expect("actual worker end") });
        started_rx.await.expect("actual blocking work began");
        waiter.abort();
        assert!(waiter.await.expect_err("waiter cancelled").is_cancelled());
        assert_eq!(workers.active.load(Ordering::Acquire), 1);
        assert_eq!(workers.admission.available_permits(), 0);
        workers.close();
        let draining = workers.clone();
        let mut drain = tokio::spawn(async move { draining.drain().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut drain)
                .await
                .is_err()
        );
        finish_tx
            .send(())
            .expect("actual detached work remains alive");
        tokio::time::timeout(Duration::from_secs(1), &mut drain)
            .await
            .expect("drain waits for actual completion")
            .expect("drain task");
        assert_eq!(workers.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poisoned_gate_is_fail_closed_and_still_waits_for_real_worker_end() {
        let workers = workers();
        let admission = workers.try_admit().expect("actual admission before poison");
        let poisoned = workers.clone();
        assert!(
            std::thread::spawn(move || {
                let _gate = poisoned.gate.lock().expect("unpoisoned gate");
                panic!("controlled private gate poison");
            })
            .join()
            .is_err()
        );
        assert!(matches!(workers.try_admit(), Err(Error::Unavailable)));
        let (finish_tx, finish_rx) = mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            finish_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("finite poisoned-owner work release");
        });
        workers.close();
        let draining = workers.clone();
        let mut drain = tokio::spawn(async move { draining.drain().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut drain)
                .await
                .is_err()
        );
        finish_tx
            .send(())
            .expect("actual worker remains tracked despite poison");
        worker.await.expect("actual worker stopped");
        tokio::time::timeout(Duration::from_secs(1), &mut drain)
            .await
            .expect("poisoned gate still drains real work")
            .expect("drain task");
        assert_eq!(workers.active.load(Ordering::Acquire), 0);
    }
}
