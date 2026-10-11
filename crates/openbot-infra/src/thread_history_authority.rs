//! One-J current management observation. No result is a later clear/delete permission.

use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{DeploymentId, TenantId, ThreadId, ThreadIdentity};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingKind, RequestBindingIssuer,
    ThreadHistoryHostObservation, ThreadHistoryHostTailWitness, ThreadHistoryHostTarget,
    ThreadHistorySessionFacts,
};
use openbot_domain::identity::roles::resolve_effective_role;
use time::OffsetDateTime;
use tokio_postgres::types::{FromSqlOwned, ToSql};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::artifact_registry::ArtifactDatasetRegistry;
use crate::auth::single_user::desktop_local::{DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL};
use crate::auth::single_user::{SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL};
use crate::db::pool::{DatabasePool, GuardedTransaction, TransactionOwnerError};
use crate::db::{InfraError, native, thread_origin_schema};
use crate::thread_origin;

/// Closed internal observation failures. No runtime SQL, row, locator or secret is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadHistoryObservationError {
    #[error("thread_history_invalid_input")]
    InvalidInput { field: &'static str },
    #[error("thread_history_host_refused")]
    Host(HostRequestBindingError),
    #[error("thread_history_not_visible")]
    NotVisible,
    #[error("thread_history_unavailable")]
    Unavailable,
    #[error("thread_history_corrupt")]
    Corrupt { field: &'static str },
    #[error("thread_history_transaction_already_started")]
    AlreadyStarted,
    #[error("thread_history_transaction_deadline_exceeded")]
    DeadlineExceeded,
    #[error("thread_history_transaction_begin_unavailable")]
    BeginUnavailable,
    #[error("thread_history_transaction_commit_unknown")]
    CommitUnknown,
    #[error("thread_history_transaction_rollback_unproven")]
    RollbackUnproven,
    #[error("thread_history_transaction_commit_ack_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    #[error("thread_history_transaction_rollback_ack_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

type Error = ThreadHistoryObservationError;

/// Bounded J observed under the original request. It is neither a lease nor a future grant.
pub struct ObservedThreadHistoryManagement {
    deployment: DeploymentId,
    tenant: TenantId,
    thread: ThreadId,
}
impl ObservedThreadHistoryManagement {
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant
    }
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread
    }
}
impl core::fmt::Debug for ObservedThreadHistoryManagement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ObservedThreadHistoryManagement(<one-J-current-snapshot>)")
    }
}

struct OriginalRegistry {
    registry: Weak<ArtifactDatasetRegistry>,
    owner: Weak<()>,
}

/// Actual original Pool/namespace, private invocation identity and once-enrolled host issuer.
pub struct PostgresThreadHistoryAuthority {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    authority: Arc<()>,
    issuer: OnceLock<RequestBindingIssuer>,
    registry: OnceLock<Result<OriginalRegistry, HostRequestBindingError>>,
}
impl core::fmt::Debug for PostgresThreadHistoryAuthority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgresThreadHistoryAuthority(<original-bound>)")
    }
}
impl PostgresThreadHistoryAuthority {
    /// Bind trusted startup inputs without checkout, repair, write or current permission.
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, Error> {
        if !is_valid_artifact_identity(deployment.as_str()) {
            return Err(Error::InvalidInput {
                field: "deployment",
            });
        }
        if !is_valid_artifact_identity(tenant.as_str()) {
            return Err(Error::InvalidInput { field: "tenant" });
        }
        if pool.is_closed() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            authority: Arc::new(()),
            issuer: OnceLock::new(),
            registry: OnceLock::new(),
        })
    }
    /// The actual immutable manager and namespace match; this bool supplies no grant.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        !self.pool.is_closed()
            && !pool.is_closed()
            && std::ptr::eq(self.pool.manager(), pool.manager())
            && &self.deployment == deployment
            && &self.tenant == tenant
    }
    /// Compare this exact invocation identity and its original attached Auth.
    #[must_use]
    pub fn matches_host_target(
        &self,
        target: &dyn ThreadHistoryHostTarget,
        auth: &AuthContext,
    ) -> bool {
        self.scope(auth).is_ok()
            && target.matches_authority(&self.authority)
            && target.matches_auth(auth)
    }
    /// The actual producer's original issuer is enrolled once, without its lifecycle lease.
    pub fn enroll_host_issuer(
        &self,
        issuer: &RequestBindingIssuer,
    ) -> Result<(), HostRequestBindingError> {
        if self.pool.is_closed() || !issuer.observation().is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.issuer
            .set(issuer.clone())
            .map_err(|_| HostRequestBindingError::Unavailable)
    }
    /// Bind the real original registry and owner once, including a failed first adoption.
    pub fn enroll_original_registry(
        &self,
        registry: &Arc<ArtifactDatasetRegistry>,
    ) -> Result<(), HostRequestBindingError> {
        let original = if self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
            && registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            Ok(OriginalRegistry {
                registry: Arc::downgrade(registry),
                owner: Arc::downgrade(&registry.owner()),
            })
        } else {
            Err(HostRequestBindingError::NotCurrent)
        };
        self.registry
            .set(original)
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        self.original_registry().map(|_| ())
    }
    fn original_registry(&self) -> Result<Arc<ArtifactDatasetRegistry>, HostRequestBindingError> {
        let original = self
            .registry
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let original = original.as_ref().map_err(|error| *error)?;
        let registry = original
            .registry
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if original.owner.upgrade().is_none()
            || !registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
            || !self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(registry)
    }
    fn scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            return Err(Error::NotVisible);
        }
        if self.pool.is_closed() {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    /// Observe one J under a single absolute deadline and actual original RC/ROLLBACK owner.
    pub async fn observe_management_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        thread_id: &str,
        original_deadline: Instant,
    ) -> Result<ObservedThreadHistoryManagement, Error> {
        let entry = Instant::now();
        let cap = entry
            .checked_add(Duration::from_secs(5))
            .ok_or(Error::Unavailable)?;
        let deadline = original_deadline.min(cap);
        if thread_id.len() != 36 {
            return Err(Error::InvalidInput { field: "thread_id" });
        }
        let thread = ThreadId::new(thread_id);
        if !ThreadIdentity::is_plausible(&thread) {
            return Err(Error::InvalidInput { field: "thread_id" });
        }
        remaining(deadline)?;
        self.scope(auth)?;
        let target = OriginalInvocation {
            authority: &self.authority,
            auth,
        };
        let current = CurrentThreadHistoryRequest::borrow(self, auth, &target, deadline)?;
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| Error::Unavailable)?;
        // Same actual client before BEGIN; no second Pool or Client performs validation.
        bounded(deadline, thread_origin_schema::verify(client.as_client()))
            .await?
            .map_err(schema_error)?;
        current.check_attachment(deadline)?;
        let transaction = client.begin_read_committed().await.map_err(owner_error)?;
        let transaction = ThreadHistoryTransaction {
            authority: self,
            transaction,
        };
        let result = self
            .observe_original(&current, &transaction, &thread, deadline)
            .await;
        transaction
            .transaction
            .rollback()
            .await
            .map_err(owner_error)?;
        // Even an ordinary refusal retains its real terminal ACK before it is returned.
        let snapshot = result?;
        current.check_attachment(deadline)?;
        snapshot
            .witness
            .verify_current(auth, deadline)
            .map_err(Error::Host)?;
        current.check_attachment(deadline)?;
        Ok(ObservedThreadHistoryManagement {
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            thread,
        })
    }
    async fn observe_original(
        &self,
        current: &CurrentThreadHistoryRequest<'_>,
        original: &ThreadHistoryTransaction<'_>,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<CurrentSnapshot, Error> {
        if !std::ptr::eq(original.authority, self) {
            return Err(Error::Corrupt {
                field: "host_binding",
            });
        }
        let tx = original.transaction.as_transaction();
        bounded(deadline, native::validate_thread_origin_in_transaction(tx))
            .await?
            .map_err(schema_error)?;
        current.check_attachment(deadline)?;
        required(
            tx,
            deadline,
            "SELECT id FROM public.users WHERE id=$1 FOR SHARE",
            &[&current.auth.actor().as_str()],
        )
        .await?;
        // Every allowed wait is complete before these NOWAIT positive locks and the fresh joint.
        let roles = bounded(
            deadline,
            tx.query(
                "SELECT user_id FROM public.user_roles WHERE user_id=$1 \
            AND role IN ('user','admin') FOR SHARE NOWAIT",
                &[&current.auth.actor().as_str()],
            ),
        )
        .await?
        .map_err(|_| Error::Unavailable)?;
        if roles.is_empty() {
            return Err(Error::NotVisible);
        }
        if let Some(epoch) = current.host.server_session_epoch() {
            required(
                tx,
                deadline,
                "SELECT id FROM public.sessions WHERE id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                &[&epoch.lookup_id(), &current.auth.actor().as_str()],
            )
            .await?;
        }
        let base = required(tx, deadline, "SELECT thread_id,anchor_kind,anchor_id FROM public.threads \
            WHERE thread_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND status<>'deleted' FOR SHARE NOWAIT",
            &[&thread.as_str(), &self.deployment.as_str(), &self.tenant.as_str()]).await?;
        let kind: String = column(&base, "anchor_kind")?;
        let anchor: String = column(&base, "anchor_id")?;
        let package = match kind.as_str() {
            "direct_bot" => {
                let bot = required(
                    tx,
                    deadline,
                    "SELECT id,package_id FROM public.agents WHERE id=$1 FOR SHARE NOWAIT",
                    &[&anchor],
                )
                .await?;
                required(
                    tx,
                    deadline,
                    "SELECT agent_id FROM public.agent_profiles WHERE agent_id=$1 FOR SHARE NOWAIT",
                    &[&anchor],
                )
                .await?;
                required(tx, deadline, "SELECT thread_id FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                    &[&thread.as_str(), &current.auth.actor().as_str()]).await?;
                column::<Option<Uuid>>(&bot, "package_id")?
            }
            "channel" => {
                let channel = required(
                    tx,
                    deadline,
                    "SELECT id,package_id FROM public.channels WHERE id=$1 FOR SHARE NOWAIT",
                    &[&anchor],
                )
                .await?;
                required(tx, deadline, "SELECT channel_id FROM public.channel_memberships WHERE channel_id=$1 AND user_id=$2 FOR SHARE NOWAIT",
                    &[&anchor, &current.auth.actor().as_str()]).await?;
                column::<Option<Uuid>>(&channel, "package_id")?
            }
            _ => {
                return Err(Error::Corrupt {
                    field: "target_binding",
                });
            }
        };
        if let Some(package) = package {
            required(
                tx,
                deadline,
                "SELECT id FROM public.deployment_packages WHERE id=$1 FOR SHARE NOWAIT",
                &[&package],
            )
            .await?;
        }
        current.check_attachment(deadline)?;
        let epoch = current.host.server_session_epoch();
        let session = epoch.as_ref().map(|epoch| epoch.lookup_id());
        let desktop = current.host.kind() == HostRequestBindingKind::DesktopWindow;
        let row = bounded(
            deadline,
            tx.query_one(
                current_sql(desktop),
                &[
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &thread.as_str(),
                    &current.auth.actor().as_str(),
                    &session,
                ],
            ),
        )
        .await?
        .map_err(|_| Error::Unavailable)?;
        current.check_attachment(deadline)?;
        if column::<Option<String>>(&row, "thread_id")?.is_none() {
            return Err(Error::NotVisible);
        }
        let known = thread_origin::decode_known_row(&row, thread.as_str()).map_err(origin_error)?;
        if known.deployment() != self.deployment.as_str()
            || known.tenant() != self.tenant.as_str()
            || known.creator() != current.auth.actor().as_str()
        {
            return Err(Error::NotVisible);
        }
        if !column::<bool>(&row, "management_visible")? {
            return Err(Error::NotVisible);
        }
        let session = current.decode_host(&row, deadline)?;
        let witness = current
            .host
            .witness(current.auth, session, deadline)
            .map_err(Error::Host)?;
        current.check_attachment(deadline)?;
        witness
            .verify_current(current.auth, deadline)
            .map_err(Error::Host)?;
        current.check_attachment(deadline)?;
        Ok(CurrentSnapshot { witness })
    }
}

/// Only this authority's actual guarded checkout can construct this original transaction.
struct ThreadHistoryTransaction<'a> {
    authority: &'a PostgresThreadHistoryAuthority,
    transaction: GuardedTransaction<'a>,
}
struct CurrentSnapshot {
    witness: Box<dyn ThreadHistoryHostTailWitness>,
}
struct OriginalInvocation<'a> {
    authority: &'a Arc<()>,
    auth: &'a AuthContext,
}
impl ThreadHistoryHostTarget for OriginalInvocation<'_> {
    fn matches_authority(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(self.authority, authority)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.auth == auth
            && self
                .auth
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
    }
}
struct CurrentThreadHistoryRequest<'a> {
    authority: &'a PostgresThreadHistoryAuthority,
    auth: &'a AuthContext,
    issuer: &'a RequestBindingIssuer,
    host: ThreadHistoryHostObservation<'a>,
    registry: Weak<ArtifactDatasetRegistry>,
}
impl<'a> CurrentThreadHistoryRequest<'a> {
    fn borrow(
        authority: &'a PostgresThreadHistoryAuthority,
        auth: &'a AuthContext,
        target: &'a dyn ThreadHistoryHostTarget,
        deadline: Instant,
    ) -> Result<Self, Error> {
        remaining(deadline)?;
        let issuer = authority.issuer.get().ok_or(Error::Unavailable)?;
        let binding = auth
            .request_binding()
            .ok_or(Error::Host(HostRequestBindingError::Missing))?;
        if !issuer.observation().is_current() || !issuer.owns_identity(binding.identity()) {
            return Err(Error::Host(HostRequestBindingError::NotCurrent));
        }
        let host = binding
            .borrow_thread_history_host_before(auth, target, deadline)
            .map_err(Error::Host)?;
        let registry = {
            let original = authority.original_registry().map_err(Error::Host)?;
            Arc::downgrade(&original)
        };
        let current = Self {
            authority,
            auth,
            issuer,
            host,
            registry,
        };
        current.check_attachment(deadline)?;
        Ok(current)
    }
    fn check_attachment(&self, deadline: Instant) -> Result<(), Error> {
        remaining(deadline)?;
        let binding = self
            .auth
            .request_binding()
            .ok_or(Error::Host(HostRequestBindingError::Missing))?;
        let registry = self.authority.original_registry().map_err(Error::Host)?;
        let expected = self
            .registry
            .upgrade()
            .ok_or(Error::Host(HostRequestBindingError::Unavailable))?;
        if !self.issuer.observation().is_current()
            || !self.issuer.owns_identity(self.host.identity())
            || self.host.kind() != binding.kind()
            || !self.host.identity().same_binding(binding.identity())
            || !Arc::ptr_eq(&registry, &expected)
        {
            return Err(Error::Host(HostRequestBindingError::NotCurrent));
        }
        Ok(())
    }
    fn decode_host(
        &self,
        row: &Row,
        deadline: Instant,
    ) -> Result<Option<ThreadHistorySessionFacts>, Error> {
        let actor: Option<String> = column(row, "current_actor")?;
        let raw: Option<i64> = column(row, "current_generation")?;
        let generation = raw
            .and_then(|v| u64::try_from(v).ok())
            .ok_or(Error::NotVisible)?;
        if actor.as_deref() != Some(self.auth.actor().as_str())
            || generation != self.auth.auth_generation().get()
            || column::<bool>(row, "denied")?
        {
            return Err(Error::NotVisible);
        }
        let roles: Vec<String> = column(row, "current_roles")?;
        let parsed = roles
            .iter()
            .map(|r| r.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::NotVisible)?;
        let session = match self.host.kind() {
            HostRequestBindingKind::ServerSession => {
                if self.auth.is_single_user() {
                    return Err(Error::NotVisible);
                }
                let epoch = self
                    .host
                    .server_session_epoch()
                    .ok_or(Error::Host(HostRequestBindingError::NotCurrent))?;
                let (
                    Some(id),
                    Some(user),
                    Some(token),
                    Some(created),
                    Some(updated),
                    Some(expires),
                    Some(issued),
                ) = (
                    column::<Option<String>>(row, "session_id")?,
                    column::<Option<String>>(row, "session_user")?,
                    column::<Option<String>>(row, "session_token")?,
                    column::<Option<OffsetDateTime>>(row, "session_created")?,
                    column::<Option<OffsetDateTime>>(row, "session_updated")?,
                    column::<Option<OffsetDateTime>>(row, "session_expires")?,
                    column::<Option<i64>>(row, "session_generation")?,
                )
                else {
                    return Err(Error::NotVisible);
                };
                if !epoch.matches_raw_row(&id, &user, &token, created, issued)
                    || Some(issued) != raw
                {
                    return Err(Error::NotVisible);
                }
                let role = resolve_effective_role(parsed).map_err(|_| Error::NotVisible)?;
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    false,
                )
                .with_role(role)
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                Some(ThreadHistorySessionFacts {
                    created_at: created,
                    updated_at: updated,
                    expires_at: expires,
                    observed_wall: OffsetDateTime::now_utc(),
                    observed_monotonic: Instant::now(),
                })
            }
            HostRequestBindingKind::ServerSingleUserOwner
            | HostRequestBindingKind::DesktopWindow => {
                if !self.auth.is_single_user()
                    || self.host.server_session_epoch().is_some()
                    || roles.as_slice() != ["admin"]
                {
                    return Err(Error::NotVisible);
                }
                let (actor, email) =
                    if self.host.kind() == HostRequestBindingKind::ServerSingleUserOwner {
                        (SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL)
                    } else {
                        (DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL)
                    };
                if self.auth.actor().as_str() != actor
                    || column::<Option<String>>(row, "current_email")?.as_deref() != Some(email)
                {
                    return Err(Error::NotVisible);
                }
                if self.host.kind() == HostRequestBindingKind::DesktopWindow {
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    {
                        let registry = self.authority.original_registry().map_err(Error::Host)?;
                        let expected = self
                            .registry
                            .upgrade()
                            .ok_or(Error::Host(HostRequestBindingError::Unavailable))?;
                        if !Arc::ptr_eq(&registry, &expected)
                            || !registry
                                .matches_desktop_read_current_row(row)
                                .map_err(|_| Error::Corrupt {
                                    field: "host_binding",
                                })?
                        {
                            return Err(Error::Host(HostRequestBindingError::NotCurrent));
                        }
                    }
                    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                    return Err(Error::Unavailable);
                }
                let current = AuthContextBuilder::from_verified_session(
                    self.auth.deployment().clone(),
                    self.auth.tenant().clone(),
                    self.auth.actor().clone(),
                    AuthGeneration::new(generation),
                    true,
                )
                .with_roles([Role::Admin, Role::User])
                .build();
                if current != *self.auth {
                    return Err(Error::NotVisible);
                }
                None
            }
        };
        self.check_attachment(deadline)?;
        Ok(session)
    }
}

async fn bounded<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, Error> {
    remaining(deadline)?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| Error::Unavailable)?;
    remaining(deadline)?;
    Ok(result)
}
fn remaining(deadline: Instant) -> Result<(), Error> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}
fn column<T: FromSqlOwned>(row: &Row, name: &'static str) -> Result<T, Error> {
    row.try_get(name).map_err(|_| Error::Corrupt {
        field: "row_decode",
    })
}
async fn required(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Row, Error> {
    bounded(deadline, tx.query_opt(sql, params))
        .await?
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)
}
fn schema_error(error: InfraError) -> Error {
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => Error::Unavailable,
        InfraError::RowDecode(_) => Error::Corrupt {
            field: "row_decode",
        },
        InfraError::IncompatibleDatabase(_)
        | InfraError::NativeMigration(_)
        | InfraError::RepositoryInvariant { .. } => Error::Corrupt { field: "schema" },
    }
}
fn origin_error(error: InfraError) -> Error {
    match error {
        InfraError::Connect { .. } | InfraError::Query { .. } => Error::Unavailable,
        InfraError::RowDecode(_) => Error::Corrupt {
            field: "row_decode",
        },
        InfraError::RepositoryInvariant { .. } => Error::Corrupt {
            field: "origin_binding",
        },
        InfraError::IncompatibleDatabase(_) | InfraError::NativeMigration(_) => {
            Error::Corrupt { field: "schema" }
        }
    }
}
fn owner_error(error: TransactionOwnerError) -> Error {
    match error {
        TransactionOwnerError::AlreadyStarted => Error::AlreadyStarted,
        TransactionOwnerError::DeadlineExceeded => Error::DeadlineExceeded,
        TransactionOwnerError::BeginUnavailable => Error::BeginUnavailable,
        TransactionOwnerError::CommitUnknown => Error::CommitUnknown,
        TransactionOwnerError::RollbackUnproven => Error::RollbackUnproven,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Error::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Error::RollbackAcknowledgedAfterDeadline
        }
    }
}

fn current_sql(desktop: bool) -> &'static str {
    static SERVER: OnceLock<String> = OnceLock::new();
    static DESKTOP: OnceLock<String> = OnceLock::new();
    (if desktop { &DESKTOP } else { &SERVER }).get_or_init(|| {
        let (columns,joins) = if desktop { (
            ",pcs.system_identifier::text AS read_database_system_identifier,d.oid AS read_database_oid, \
             CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
             CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
             CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
             CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
             c.key_version AS read_canary_key_version,c.canary_schema AS read_canary_schema, \
             CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted",
            " LEFT JOIN pg_catalog.pg_control_system() pcs ON true \
              LEFT JOIN pg_catalog.pg_database d ON d.datname=current_database() \
              LEFT JOIN openbot_internal.desktop_vault_canaries c ON c.deployment_id=$1 AND c.tenant_id=$2 AND c.key_version=1",
        ) } else { ("","") };
        format!("/* thread_history_management_current_joint */ SELECT {}, \
            u.id AS current_actor,coalesce(u.auth_generation,0) AS current_generation, \
            CASE WHEN octet_length(u.email) BETWEEN 1 AND 512 THEN u.email END AS current_email, \
            EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS denied, \
            ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS current_roles, \
            s.id AS session_id,s.user_id AS session_user,s.token AS session_token, \
            s.created_at AS session_created,s.updated_at AS session_updated,s.expires_at AS session_expires,s.auth_generation AS session_generation, \
            coalesce(t.thread_id=$3 AND t.deployment_id=$1 AND t.tenant_id=$2 AND t.status<>'deleted' \
              AND o.creator_actor_id=$4 AND u.id=$4 \
              AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin')) \
              AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) \
              AND ((t.anchor_kind='direct_bot' AND b.id=t.anchor_id AND p.agent_id=b.id AND p.deleted_at IS NULL \
                    AND (p.visibility='public' OR p.owner_user_id=$4) \
                    AND (b.package_id IS NULL OR (bp.id=b.package_id AND bp.tenant_id=$2)) \
                    AND EXISTS(SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) \
                OR (t.anchor_kind='channel' AND ch.id=t.anchor_id \
                    AND (ch.package_id IS NULL OR (cp.id=ch.package_id AND cp.tenant_id=$2)) \
                    AND EXISTS(SELECT 1 FROM public.channel_memberships cm WHERE cm.channel_id=ch.id AND cm.user_id=$4))),false) AS management_visible {} \
            FROM (SELECT 1) anchor LEFT JOIN public.users u ON u.id=$4 \
            LEFT JOIN public.threads t ON t.thread_id=$3 \
            LEFT JOIN openbot_internal.thread_origins o ON o.thread_id=$3 \
            LEFT JOIN public.agents b ON t.anchor_kind='direct_bot' AND b.id=t.anchor_id \
            LEFT JOIN public.agent_profiles p ON p.agent_id=b.id \
            LEFT JOIN public.deployment_packages bp ON bp.id=b.package_id \
            LEFT JOIN public.channels ch ON t.anchor_kind='channel' AND ch.id=t.anchor_id \
            LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id \
            LEFT JOIN public.sessions s ON s.id=$5::text AND s.user_id=u.id {}", thread_origin::CURRENT_COLUMNS, columns, joins)
    }).as_str()
}
