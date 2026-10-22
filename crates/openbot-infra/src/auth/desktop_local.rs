//! Desktop Local current-OS-user + app-instance authority source.
//!
//! The current OS user is represented by the caller-provided *per-user application data root*, not
//! by `USER`/`USERNAME` environment variables. A non-secret random instance ID is elected once in
//! that root with a no-clobber hard-link transaction. The resulting deployment/tenant plus the
//! single local actor form the identity described by v4 §6.1.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::db::pool::DatabasePool as Pool;
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageApplyError, TenantPackageAudienceContext, TenantPackageError,
    TenantPackageSyncReport, synchronize_tenant_package,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel, AuditPayload};

use super::{initialize_canonical_principal, load_canonical_generation};
use crate::db::InfraError;
use crate::db::desktop_local::{
    AttestedDesktopLocalAdmin, DesktopLocalDatabase, FreshDesktopDatabaseProof,
    UnattestedDesktopLocalAdmin,
};
use crate::db::desktop_vault_canary::{self, VerifiedDesktopVaultCanary};
use crate::db::initialization::{
    DatabaseInitializationError, DatabaseOrigin, initialize as initialize_database,
};
use crate::db::native;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::tenant::PostgresTenantPackageSynchronizer;

const FILE_NAME: &str = "desktop-instance-v1";
const FILE_HEADER: &str = "openbot-desktop-instance-v1";
const INSTANCE_PREFIX: &str = "instance=";
const INSTANCE_BYTES: usize = 32;
const INSTANCE_HEX_LEN: usize = INSTANCE_BYTES * 2;
const FILE_MAX_BYTES: u64 = 128;
const POSTGRES_MAJOR: u32 = 17;
const SIDECAR_DATA_PREFIX: &str = "postgresql-17-";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Desktop Local's only actor inside its per-user, per-instance deployment.
pub const DESKTOP_LOCAL_ACTOR_ID: &str = "desktop-local-user";

/// Canonical non-routable profile email for the per-instance local principal.
pub const DESKTOP_LOCAL_EMAIL: &str = "desktop-local@localhost.invalid";

/// Canonical profile name; it does not claim to be the OS account's display name.
pub const DESKTOP_LOCAL_NAME: &str = "Desktop Local User";

/// Stable failure classes; paths, OS usernames and file contents never enter the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DesktopLocalAuthorityError {
    /// The caller did not provide an absolute per-user app-data root.
    #[error("desktop_local_app_data_root_invalid")]
    InvalidAppDataRoot,
    /// Filesystem or CSPRNG operation was unavailable.
    #[error("desktop_local_identity_unavailable")]
    Unavailable,
    /// Existing identity bytes, type, version or encoding were invalid.
    #[error("desktop_local_identity_corrupt")]
    Corrupt,
    /// On Unix the existing identity file is visible to group/other principals.
    #[error("desktop_local_identity_permissions_insecure")]
    InsecurePermissions,
    /// The instance-bound PostgreSQL data path exists as a non-directory or symbolic link.
    #[error("desktop_local_sidecar_path_corrupt")]
    SidecarPathCorrupt,
    /// The existing PostgreSQL data directory is visible to group/other principals on Unix.
    #[error("desktop_local_sidecar_permissions_insecure")]
    SidecarPermissionsInsecure,
}

/// Host assertion that this absolute directory came from the current OS user's app-data API.
///
/// This type does not infer identity from environment variables. A future Tauri setup obtains its
/// path from `AppHandle::path().app_data_dir()` and makes that trust decision at the host edge.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentOsUserAppDataRoot(PathBuf);

impl core::fmt::Debug for CurrentOsUserAppDataRoot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentOsUserAppDataRoot(<redacted>)")
    }
}

impl CurrentOsUserAppDataRoot {
    /// Wrap an absolute path already resolved by the host's current-user app-data API.
    pub fn from_current_os_user_app_data(
        path: impl Into<PathBuf>,
    ) -> Result<Self, DesktopLocalAuthorityError> {
        let path = path.into();
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(DesktopLocalAuthorityError::InvalidAppDataRoot);
        }
        Ok(Self(path))
    }

    /// Borrow the asserted app-data root.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Stable Desktop Local authority derived from one elected app-instance identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopLocalAuthority {
    instance_id: Arc<str>,
    auth: AuthContext,
}

impl DesktopLocalAuthority {
    /// Lowercase 256-bit app-instance identifier. It is an identifier, not a credential.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Borrow installation scope identifiers; this pre-database context is not runtime authority.
    /// Runtime assembly must use [`Self::load_runtime_auth_context`] after provisioning.
    #[must_use]
    pub const fn auth_context(&self) -> &AuthContext {
        &self.auth
    }

    /// Consume the installation scope record; generation is not a PostgreSQL runtime snapshot.
    #[must_use]
    pub fn into_auth_context(self) -> AuthContext {
        self.auth
    }

    /// Atomically provision/repair the canonical PostgreSQL user and sole admin role.
    pub async fn provision_postgres(&self, pool: &Pool) -> Result<(), InfraError> {
        initialize_canonical_principal(
            pool,
            DESKTOP_LOCAL_ACTOR_ID,
            DESKTOP_LOCAL_EMAIL,
            DESKTOP_LOCAL_NAME,
        )
        .await
    }

    /// Advance `users.auth_generation`, terminate sessions, cancel pending approvals, expire member thread leases, abort minted executing capabilities, cancel pending component human decisions, and expire pending remote interrupts (V6-PR-020/021/023/025/027/028/029/030).
    /// Does not clear tickets/run assertions (later knife).
    pub async fn advance_auth_generation(
        &self,
        pool: &Pool,
        checkpoint_key: &[u8],
    ) -> Result<u64, InfraError> {
        if checkpoint_key.is_empty() {
            return Err(InfraError::repository_invariant(
                "desktop_local_audit_checkpoint_key_empty",
            ));
        }
        let mut client = pool
            .get()
            .await
            .map_err(|error| InfraError::connect("取 desktop-local generation 连接", error))?;
        let transaction = client
            .transaction()
            .await
            .map_err(|error| InfraError::query("开始 desktop-local generation 事务", error))?;
        let next =
            crate::repo::people_admin::advance_generation(&transaction, self.auth.actor(), None)
                .await?;
        // V6-PR-021: same-transaction session termination for this principal only.
        transaction
            .execute(
                "DELETE FROM public.sessions WHERE user_id=$1",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("终止 desktop-local sessions", error))?;
        // V6-PR-027: expire unexpired thread_leases on threads this actor is a member of.
        transaction
            .execute(
                "UPDATE public.thread_leases AS l                  SET expires_at=greatest(clock_timestamp(), l.acquired_at + interval '1 microsecond'),                      updated_at=clock_timestamp()                  WHERE l.expires_at > clock_timestamp()                    AND EXISTS (                      SELECT 1 FROM public.thread_memberships AS tm                      WHERE tm.thread_id=l.thread_id AND tm.user_id=$1                    )",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("使 desktop-local 成员 thread_leases 过期", error))?;
        // V6-PR-028: abort this actor's executing attempts that already minted a capability.
        transaction
            .execute(
                "UPDATE public.tool_attempts AS a                  SET status='aborted',                      finished_at=greatest(clock_timestamp(), a.started_at)                  FROM public.tool_calls AS c                  WHERE a.tool_call_id=c.tool_call_id                    AND c.actor_id=$1                    AND a.status='executing'                    AND a.capability_id IS NOT NULL",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("中止 desktop-local 已铸造 capability", error))?;
        // V6-PR-029: cancel pending component human decisions and write cancel audit.
        let cancelled_decisions = transaction
            .query(
                "UPDATE public.component_human_decisions                  SET state='cancelled', resolved_at=clock_timestamp(), resolved_by=NULL,                      updated_at=clock_timestamp()                  WHERE actor_id=$1 AND state='pending'                  RETURNING decision_id, component_name",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("取消 desktop-local pending human decisions", error))?;
        for row in cancelled_decisions {
            let component_name: String = row
                .try_get(1)
                .map_err(|error| InfraError::query("读 cancelled component_name", error))?;
            let (id, created_at) = next_event_coordinates(&transaction).await?;
            let event = AuditEvent {
                id,
                actor: Some(self.auth.actor().clone()),
                event_type: AuditEventType::COMPONENT_HUMAN_CANCELLED,
                target_kind: AuditLabel::new("component"),
                target_id: Some(AuditIdentifier::new(&component_name).map_err(|_| {
                    InfraError::repository_invariant("desktop_local_component_name_invalid")
                })?),
                payload: AuditPayload::empty(),
                created_at,
            };
            append_event_in_transaction(&transaction, &event, checkpoint_key).await?;
        }
        // V6-PR-030: expire pending remote interrupts (system invalidation, not actor cancel).
        let expired_interrupts = transaction
            .query(
                "UPDATE public.remote_agent_interrupts                  SET state='expired', response_status='cancelled', response_payload=NULL,                      resolved_at=clock_timestamp(), resolved_by=NULL,                      updated_at=clock_timestamp()                  WHERE actor_id=$1 AND state='pending'                  RETURNING request_id, run_id",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("使 desktop-local pending remote interrupts 过期", error))?;
        for row in expired_interrupts {
            let run_id: String = row
                .try_get(1)
                .map_err(|error| InfraError::query("读 expired interrupt run_id", error))?;
            let (id, created_at) = next_event_coordinates(&transaction).await?;
            let event = AuditEvent {
                id,
                actor: Some(self.auth.actor().clone()),
                event_type: AuditEventType::AGENT_REMOTE_INTERRUPT_EXPIRED,
                target_kind: AuditLabel::new("run"),
                target_id: Some(AuditIdentifier::new(&run_id).map_err(|_| {
                    InfraError::repository_invariant("desktop_local_interrupt_run_id_invalid")
                })?),
                payload: AuditPayload::empty(),
                created_at,
            };
            append_event_in_transaction(&transaction, &event, checkpoint_key).await?;
        }
        // V6-PR-023/025: cancel pending approvals and write cancel audit in the same transaction.
        // cancelled rows require decided_at set and decided_by NULL (native_0020 checks).
        let cancelled = transaction
            .query(
                "UPDATE public.tool_approvals                  SET state='cancelled', decided_at=clock_timestamp(), decided_by=NULL,                      arguments_summary=NULL, change_summary=NULL,                      updated_at=clock_timestamp()                  WHERE actor_id=$1 AND state='pending'                  RETURNING approval_id",
                &[&self.auth.actor().as_str()],
            )
            .await
            .map_err(|error| InfraError::query("取消 desktop-local pending approvals", error))?;
        for row in cancelled {
            let approval_id: String = row
                .try_get(0)
                .map_err(|error| InfraError::query("读 cancelled approval_id", error))?;
            let (id, created_at) = next_event_coordinates(&transaction).await?;
            let event = AuditEvent {
                id,
                actor: Some(self.auth.actor().clone()),
                event_type: AuditEventType::TOOL_APPROVAL_CANCELLED,
                target_kind: AuditLabel::new("tool_approval"),
                target_id: Some(AuditIdentifier::new(&approval_id).map_err(|_| {
                    InfraError::repository_invariant("desktop_local_approval_id_invalid")
                })?),
                payload: AuditPayload::empty(),
                created_at,
            };
            append_event_in_transaction(&transaction, &event, checkpoint_key).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| InfraError::query("提交 desktop-local generation", error))?;
        Ok(next)
    }

    /// Resolve runtime authority from the attested installation's business database after repair.
    /// The Desktop actor and instance scope are fixed by this authority, never an external context.
    pub async fn load_runtime_auth_context(&self, pool: &Pool) -> Result<AuthContext, InfraError> {
        let generation =
            load_canonical_generation(pool, DESKTOP_LOCAL_ACTOR_ID, DESKTOP_LOCAL_EMAIL).await?;
        Ok(AuthContextBuilder::from_verified_session(
            self.auth.deployment().clone(),
            self.auth.tenant().clone(),
            ActorId::new(DESKTOP_LOCAL_ACTOR_ID),
            generation,
            true,
        )
        // Preserve the existing local-runtime Admin + User projection after verifying soleAdmin in PG.
        .with_roles([Role::Admin, Role::User])
        .build())
    }

    /// Build the exact single-user audience context used by Tenant Package synchronization.
    pub fn tenant_package_audience_context(
        &self,
    ) -> Result<TenantPackageAudienceContext, TenantPackageError> {
        TenantPackageAudienceContext::single_user(self.auth.actor().clone())
    }
}

/// One current-user app instance and its only permitted PostgreSQL 17 data directory.
///
/// Paths are intentionally omitted from [`Debug`]. The sidecar supervisor needs the path for
/// process assembly, but logs and errors must not reveal the OS account's application-data root.
#[derive(Clone, PartialEq, Eq)]
pub struct DesktopLocalInstallation {
    authority: DesktopLocalAuthority,
    sidecar_data_dir: PathBuf,
}

impl core::fmt::Debug for DesktopLocalInstallation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopLocalInstallation")
            .field("instance_id", &self.authority.instance_id())
            .field("sidecar_data_dir", &"<redacted>")
            .finish()
    }
}

impl DesktopLocalInstallation {
    /// Borrow the app-instance authority that must own every database principal and window.
    #[must_use]
    pub const fn authority(&self) -> &DesktopLocalAuthority {
        &self.authority
    }

    /// Borrow the direct, instance-bound child directory reserved for PostgreSQL 17.
    #[must_use]
    pub fn sidecar_data_dir(&self) -> &Path {
        &self.sidecar_data_dir
    }

    /// Consume an administrative pool only after the live server proves the exact instance data
    /// directory, PostgreSQL 17, numeric loopback and all-host SCRAM boundary.
    ///
    /// The returned type is the only local adapter state that can create/reconcile the fixed
    /// `openbot` database, making attestation-before-write a type-level startup ordering rule.
    pub async fn attest_postgres_admin(
        &self,
        admin: UnattestedDesktopLocalAdmin,
    ) -> Result<AttestedDesktopLocalAdmin, DesktopLocalBootstrapError> {
        if let Err(error) = verify_postgres_sidecar(admin.pool(), &self.sidecar_data_dir).await {
            admin.close();
            return Err(error);
        }
        Ok(admin.into_attested())
    }

    /// Reject a Tenant Package from any other app instance before database creation or schema
    /// mutation. [`Self::bootstrap_postgres`] repeats the same check as defense in depth.
    pub fn validate_package_scope(
        &self,
        package: &LoadedTenantPackage,
    ) -> Result<(), DesktopLocalBootstrapError> {
        if package.package.tenant_id != self.authority.auth_context().tenant().as_str() {
            return Err(DesktopLocalBootstrapError::TenantScopeMismatch);
        }
        Ok(())
    }

    /// Verify the connected sidecar and initialize the shared schema, stopping before business
    /// principal/package writes so Desktop Vault canary verification can run.
    ///
    /// # Errors
    ///
    /// Fails closed when PostgreSQL is not version 17, is not local-only, does not use SCRAM for
    /// new passwords, reports a different data directory, cannot initialize the shared schema,
    /// cannot provision the canonical principal, or cannot synchronize the exact-tenant package.
    pub async fn initialize_postgres_schema(
        &self,
        database: &DesktopLocalDatabase,
        package: &LoadedTenantPackage,
        fresh: &FreshDesktopDatabaseProof,
    ) -> Result<DatabaseOrigin, DesktopLocalBootstrapError> {
        self.validate_package_scope(package)?;
        if !fresh.matches(database) {
            return Err(DesktopLocalBootstrapError::VaultCanaryMismatch);
        }
        let pool = database.pool();
        verify_postgres_sidecar(pool, &self.sidecar_data_dir).await?;
        initialize_database(pool).await.map_err(Into::into)
    }

    /// Provision the principal/package only after an unforgeable verified canary proof.
    pub async fn complete_postgres_after_vault(
        &self,
        database: &DesktopLocalDatabase,
        package: &LoadedTenantPackage,
        database_origin: DatabaseOrigin,
        proof: &VerifiedDesktopVaultCanary,
    ) -> Result<DesktopLocalBootstrapReport, DesktopLocalBootstrapError> {
        self.validate_package_scope(package)?;
        if proof.deployment_id() != self.authority.auth_context().deployment().as_str()
            || proof.tenant_id() != self.authority.auth_context().tenant().as_str()
        {
            return Err(DesktopLocalBootstrapError::VaultCanaryMismatch);
        }
        if !proof
            .matches_database(database)
            .await
            .map_err(|_| DesktopLocalBootstrapError::VaultCanaryMismatch)?
        {
            return Err(DesktopLocalBootstrapError::VaultCanaryMismatch);
        }
        let pool = database.pool();
        verify_postgres_sidecar(pool, &self.sidecar_data_dir).await?;
        let layout = desktop_vault_canary::verify_pre_upgrade_layout(pool)
            .await
            .map_err(|_| DesktopLocalBootstrapError::VaultCanaryMismatch)?;
        if layout.native_version() < native::NATIVE_LATEST_VERSION {
            if !proof
                .matches_database(database)
                .await
                .map_err(|_| DesktopLocalBootstrapError::VaultCanaryMismatch)?
            {
                return Err(DesktopLocalBootstrapError::VaultCanaryMismatch);
            }
            let mut client = pool.get().await.map_err(|source| {
                DesktopLocalBootstrapError::Database(
                    InfraError::connect("取 Desktop canary 后迁移连接", source).into(),
                )
            })?;
            native::apply(&mut client)
                .await
                .map_err(|error| DesktopLocalBootstrapError::Database(error.into()))?;
        }
        desktop_vault_canary::verify_current_layout(pool)
            .await
            .map_err(|_| DesktopLocalBootstrapError::VaultCanaryMismatch)?;
        if !proof
            .matches_database(database)
            .await
            .map_err(|_| DesktopLocalBootstrapError::VaultCanaryMismatch)?
        {
            return Err(DesktopLocalBootstrapError::VaultCanaryMismatch);
        }
        self.authority
            .provision_postgres(pool)
            .await
            .map_err(DesktopLocalBootstrapError::Principal)?;
        let audience = self.authority.tenant_package_audience_context()?;
        let package = synchronize_tenant_package(
            &PostgresTenantPackageSynchronizer::new(pool.clone()),
            package,
            &audience,
        )
        .await?;
        Ok(DesktopLocalBootstrapReport {
            database_origin,
            package,
        })
    }
}

/// Mechanical result of the pre-window Desktop Local database bootstrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopLocalBootstrapReport {
    /// Whether this was a fresh, already Rust-managed, or verified legacy database.
    pub database_origin: DatabaseOrigin,
    /// Existing Tenant Package synchronization counts and compatibility flags.
    pub package: TenantPackageSyncReport,
}

/// Stable Desktop Local database-bootstrap failures; no path, setting value, or secret is stored.
#[derive(Debug, thiserror::Error)]
pub enum DesktopLocalBootstrapError {
    /// The package tenant does not exactly equal the app-instance tenant.
    #[error("desktop_local_package_tenant_mismatch")]
    TenantScopeMismatch,
    /// PostgreSQL settings or server endpoint could not be safely read.
    #[error("desktop_local_postgres_attestation_unavailable")]
    PostgresAttestationUnavailable,
    /// PostgreSQL reports a data directory other than this app instance's direct child.
    #[error("desktop_local_postgres_data_directory_mismatch")]
    PostgresDataDirectoryMismatch,
    /// The connected PostgreSQL major is not the pinned major 17.
    #[error("desktop_local_postgres_major_unsupported")]
    PostgresMajorUnsupported,
    /// The server listens on, or this pool connected through, a non-local address.
    #[error("desktop_local_postgres_exposure_refused")]
    PostgresExposureRefused,
    /// New PostgreSQL passwords are not configured for SCRAM-SHA-256.
    #[error("desktop_local_postgres_scram_required")]
    PostgresScramRequired,
    /// Shared baseline/native initialization failed.
    #[error(transparent)]
    Database(#[from] DatabaseInitializationError),
    /// Canonical principal provisioning failed after database initialization.
    #[error("desktop_local_principal_provision_failed")]
    Principal(#[source] InfraError),
    /// The exact single-user audience could not be constructed.
    #[error(transparent)]
    Audience(#[from] TenantPackageError),
    /// Tenant Package synchronization failed.
    #[error(transparent)]
    Package(#[from] TenantPackageApplyError),
    /// The cryptographic dataset proof did not match this installation authority.
    #[error("desktop_local_vault_canary_mismatch")]
    VaultCanaryMismatch,
}

/// Persistent authority source for one current-user application data root.
#[derive(Clone)]
pub struct DesktopLocalAuthorityStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    root: CurrentOsUserAppDataRoot,
    mutation: Mutex<()>,
}

impl DesktopLocalAuthorityStore {
    /// Bind to one host-asserted current-user app-data root.
    #[must_use]
    pub fn new(root: CurrentOsUserAppDataRoot) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                root,
                mutation: Mutex::new(()),
            }),
        }
    }

    /// Load the existing identity or atomically elect one fully-written CSPRNG candidate.
    pub fn load_or_create(&self) -> Result<DesktopLocalAuthority, DesktopLocalAuthorityError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        self.load_or_create_locked()
    }

    /// Load/elect the authority and reserve its direct private PostgreSQL 17 data directory.
    ///
    /// This is the Desktop setup entry point. The ordinary authority-only method intentionally
    /// does not create a database directory, keeping identity reads free of side effects outside
    /// the identity file.
    pub fn load_or_create_installation(
        &self,
    ) -> Result<DesktopLocalInstallation, DesktopLocalAuthorityError> {
        let _guard = self
            .inner
            .mutation
            .lock()
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        let authority = self.load_or_create_locked()?;
        let sidecar_data_dir =
            prepare_sidecar_data_dir(self.inner.root.as_path(), authority.instance_id())?;
        Ok(DesktopLocalInstallation {
            authority,
            sidecar_data_dir,
        })
    }

    fn load_or_create_locked(&self) -> Result<DesktopLocalAuthority, DesktopLocalAuthorityError> {
        prepare_root(self.inner.root.as_path())?;
        let path = self.inner.root.as_path().join(FILE_NAME);
        let instance = match read_instance(&path)? {
            Some(instance) => {
                cleanup_matching_temporary(self.inner.root.as_path(), instance)?;
                instance
            }
            None => elect_instance(self.inner.root.as_path(), &path)?,
        };
        Ok(authority(instance))
    }
}

fn prepare_sidecar_data_dir(
    root: &Path,
    instance_id: &str,
) -> Result<PathBuf, DesktopLocalAuthorityError> {
    if instance_id.len() != INSTANCE_HEX_LEN
        || !instance_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DesktopLocalAuthorityError::Corrupt);
    }
    let path = root.join(format!("{SIDECAR_DATA_PREFIX}{instance_id}"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(DesktopLocalAuthorityError::SidecarPathCorrupt);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(DesktopLocalAuthorityError::SidecarPermissionsInsecure);
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder
                .create(&path)
                .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
            sync_directory(root)?;
        }
        Err(_) => return Err(DesktopLocalAuthorityError::Unavailable),
    }
    let canonical_root =
        fs::canonicalize(root).map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
    let canonical_path =
        fs::canonicalize(&path).map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
    if canonical_path.parent() != Some(canonical_root.as_path()) {
        return Err(DesktopLocalAuthorityError::SidecarPathCorrupt);
    }
    Ok(path)
}

async fn verify_postgres_sidecar(
    pool: &Pool,
    expected_data_dir: &Path,
) -> Result<(), DesktopLocalBootstrapError> {
    let client = pool
        .get()
        .await
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let row = client
        .query_one(
            "SELECT current_setting('data_directory'), \
                    current_setting('server_version_num'), \
                    current_setting('listen_addresses'), \
                    current_setting('password_encryption'), \
                    host(inet_server_addr()), \
                    (SELECT coalesce(bool_and(auth_method='scram-sha-256'), false) \
                       FROM pg_hba_file_rules WHERE error IS NULL AND type LIKE 'host%'), \
                    NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL)",
            &[],
        )
        .await
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let data_directory = row
        .try_get::<_, String>(0)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let version = row
        .try_get::<_, String>(1)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let listen_addresses = row
        .try_get::<_, String>(2)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let password_encryption = row
        .try_get::<_, String>(3)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let server_address = row
        .try_get::<_, Option<String>>(4)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let host_scram_only = row
        .try_get::<_, bool>(5)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let hba_valid = row
        .try_get::<_, bool>(6)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;

    validate_postgres_sidecar_attestation(
        expected_data_dir,
        PostgresSidecarAttestation {
            data_directory: &data_directory,
            version: &version,
            listen_addresses: &listen_addresses,
            password_encryption: &password_encryption,
            server_address: server_address.as_deref(),
            host_scram_only,
            hba_valid,
        },
    )
}

#[derive(Clone, Copy)]
struct PostgresSidecarAttestation<'a> {
    data_directory: &'a str,
    version: &'a str,
    listen_addresses: &'a str,
    password_encryption: &'a str,
    server_address: Option<&'a str>,
    host_scram_only: bool,
    hba_valid: bool,
}

fn validate_postgres_sidecar_attestation(
    expected_data_dir: &Path,
    attestation: PostgresSidecarAttestation<'_>,
) -> Result<(), DesktopLocalBootstrapError> {
    let expected = fs::canonicalize(expected_data_dir)
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)?;
    let reported = PathBuf::from(attestation.data_directory);
    if !reported.is_absolute() {
        return Err(DesktopLocalBootstrapError::PostgresDataDirectoryMismatch);
    }
    let reported = fs::canonicalize(reported)
        .map_err(|_| DesktopLocalBootstrapError::PostgresDataDirectoryMismatch)?;
    if reported != expected {
        return Err(DesktopLocalBootstrapError::PostgresDataDirectoryMismatch);
    }

    let version = attestation
        .version
        .parse::<u32>()
        .map_err(|_| DesktopLocalBootstrapError::PostgresMajorUnsupported)?;
    if version / 10_000 != POSTGRES_MAJOR {
        return Err(DesktopLocalBootstrapError::PostgresMajorUnsupported);
    }
    if !listen_addresses_are_local(attestation.listen_addresses)
        || attestation.server_address.is_some_and(|address| {
            address
                .parse::<std::net::IpAddr>()
                .map_or(true, |address| !address.is_loopback())
        })
    {
        return Err(DesktopLocalBootstrapError::PostgresExposureRefused);
    }
    if attestation.password_encryption != "scram-sha-256"
        || !attestation.host_scram_only
        || !attestation.hba_valid
    {
        return Err(DesktopLocalBootstrapError::PostgresScramRequired);
    }
    Ok(())
}

fn listen_addresses_are_local(value: &str) -> bool {
    value
        .split(',')
        .all(|address| matches!(address.trim(), "" | "127.0.0.1" | "::1"))
}

fn prepare_root(root: &Path) -> Result<(), DesktopLocalAuthorityError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(DesktopLocalAuthorityError::InvalidAppDataRoot);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        }
        Err(_) => return Err(DesktopLocalAuthorityError::Unavailable),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
    }
    Ok(())
}

fn read_instance(path: &Path) -> Result<Option<[u8; INSTANCE_BYTES]>, DesktopLocalAuthorityError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DesktopLocalAuthorityError::Unavailable),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > FILE_MAX_BYTES
    {
        return Err(DesktopLocalAuthorityError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(DesktopLocalAuthorityError::InsecurePermissions);
        }
    }
    let raw = fs::read_to_string(path).map_err(|_| DesktopLocalAuthorityError::Corrupt)?;
    parse(&raw).map(Some)
}

fn elect_instance(
    root: &Path,
    final_path: &Path,
) -> Result<[u8; INSTANCE_BYTES], DesktopLocalAuthorityError> {
    let mut candidate = [0_u8; INSTANCE_BYTES];
    getrandom::fill(&mut candidate).map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
    let encoded = render(candidate);
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".{FILE_NAME}.tmp.{}.{}.{}",
        std::process::id(),
        sequence,
        &encode(candidate)[..16]
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        file.write_all(encoded.as_bytes())
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        file.sync_all()
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        drop(file);

        match fs::hard_link(&temporary, final_path) {
            Ok(()) => {
                sync_directory(root)?;
                remove_temporary(&temporary)?;
                sync_directory(root)?;
                Ok(candidate)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                remove_temporary(&temporary)?;
                read_instance(final_path)?.ok_or(DesktopLocalAuthorityError::Corrupt)
            }
            Err(_) => Err(DesktopLocalAuthorityError::Unavailable),
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_temporary(path: &Path) -> Result<(), DesktopLocalAuthorityError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DesktopLocalAuthorityError::Unavailable),
    }
}

fn cleanup_matching_temporary(
    root: &Path,
    instance: [u8; INSTANCE_BYTES],
) -> Result<(), DesktopLocalAuthorityError> {
    let prefix = format!(".{FILE_NAME}.tmp.");
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(|_| DesktopLocalAuthorityError::Unavailable)? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > FILE_MAX_BYTES
        {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        if parse(&raw).ok() == Some(instance) {
            remove_temporary(&entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DesktopLocalAuthorityError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DesktopLocalAuthorityError::Unavailable)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DesktopLocalAuthorityError> {
    Ok(())
}

fn authority(instance: [u8; INSTANCE_BYTES]) -> DesktopLocalAuthority {
    let instance_id = encode(instance);
    let scope_id = format!("desktop-local-{instance_id}");
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new(scope_id.clone()),
        TenantId::new(scope_id),
        ActorId::new(DESKTOP_LOCAL_ACTOR_ID),
        AuthGeneration::new(0),
        true,
    )
    .with_roles([Role::Admin, Role::User])
    .build();
    DesktopLocalAuthority {
        instance_id: Arc::from(instance_id),
        auth,
    }
}

fn render(instance: [u8; INSTANCE_BYTES]) -> String {
    format!("{FILE_HEADER}\n{INSTANCE_PREFIX}{}\n", encode(instance))
}

fn parse(raw: &str) -> Result<[u8; INSTANCE_BYTES], DesktopLocalAuthorityError> {
    let mut lines = raw.lines();
    if lines.next() != Some(FILE_HEADER) {
        return Err(DesktopLocalAuthorityError::Corrupt);
    }
    let encoded = lines
        .next()
        .and_then(|line| line.strip_prefix(INSTANCE_PREFIX))
        .ok_or(DesktopLocalAuthorityError::Corrupt)?;
    if lines.next().is_some() {
        return Err(DesktopLocalAuthorityError::Corrupt);
    }
    decode(encoded).ok_or(DesktopLocalAuthorityError::Corrupt)
}

fn encode(bytes: [u8; INSTANCE_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(INSTANCE_HEX_LEN);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode(value: &str) -> Option<[u8; INSTANCE_BYTES]> {
    if value.len() != INSTANCE_HEX_LEN {
        return None;
    }
    let mut decoded = [0_u8; INSTANCE_BYTES];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    for (index, pair) in pairs.iter().enumerate() {
        decoded[index] = lower_hex(pair[0])? << 4 | lower_hex(pair[1])?;
    }
    Some(decoded)
}

const fn lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "openbot-desktop-local-authority-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn store(path: &Path) -> DesktopLocalAuthorityStore {
        DesktopLocalAuthorityStore::new(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(path).unwrap(),
        )
    }

    #[test]
    fn first_run_and_restart_produce_the_same_single_user_admin_authority() {
        let root = root("restart");
        let first = store(&root).load_or_create().unwrap();
        let bytes = fs::read(root.join(FILE_NAME)).unwrap();
        let second = store(&root).load_or_create().unwrap();
        assert_eq!(first, second);
        assert_eq!(fs::read(root.join(FILE_NAME)).unwrap(), bytes);
        assert_eq!(first.instance_id().len(), INSTANCE_HEX_LEN);
        assert!(
            first
                .instance_id()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        let auth = first.auth_context();
        assert!(auth.is_single_user());
        assert!(auth.has_role(Role::Admin));
        assert!(auth.has_role(Role::User));
        assert_eq!(auth.auth_generation().get(), 0);
        assert_eq!(auth.actor().as_str(), DESKTOP_LOCAL_ACTOR_ID);
        assert_eq!(auth.deployment().as_str(), auth.tenant().as_str());
        assert!(auth.deployment().as_str().ends_with(first.instance_id()));
        assert_eq!(
            first
                .tenant_package_audience_context()
                .unwrap()
                .single_user_principal(),
            Some(auth.actor())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(FILE_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            1,
            "no temporary identity file may remain"
        );

        let stale = root.join(format!(".{FILE_NAME}.tmp.stale"));
        fs::hard_link(root.join(FILE_NAME), &stale).unwrap();
        assert!(stale.exists());
        assert_eq!(store(&root).load_or_create().unwrap(), first);
        assert!(!stale.exists(), "matching crash residue must be reclaimed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn independent_store_objects_elect_exactly_one_cross_thread_candidate() {
        let root = root("race");
        let workers = 32;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();
        for _ in 0..workers {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store(&root)
                    .load_or_create()
                    .unwrap()
                    .instance_id()
                    .to_owned()
            }));
        }
        let identities = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(identities.iter().all(|identity| identity == &identities[0]));
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installation_reserves_one_private_direct_child_bound_to_the_instance() {
        let root = root("installation");
        let installation = store(&root).load_or_create_installation().unwrap();
        let expected_name = format!(
            "{SIDECAR_DATA_PREFIX}{}",
            installation.authority().instance_id()
        );
        assert_eq!(
            installation.sidecar_data_dir().parent(),
            Some(root.as_path())
        );
        assert_eq!(
            installation.sidecar_data_dir().file_name().unwrap(),
            expected_name.as_str()
        );
        assert!(installation.sidecar_data_dir().is_dir());
        assert!(!format!("{installation:?}").contains(root.to_str().unwrap()));
        let restarted = store(&root).load_or_create_installation().unwrap();
        assert_eq!(restarted, installation);
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            2,
            "identity file plus exactly one instance-bound PostgreSQL directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(installation.sidecar_data_dir())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_symlink_and_broad_permissions_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let symlink_root = root("sidecar-symlink");
        let installation = store(&symlink_root).load_or_create_installation().unwrap();
        let sidecar = installation.sidecar_data_dir().to_owned();
        fs::remove_dir(&sidecar).unwrap();
        let target = root("sidecar-target");
        fs::create_dir(&target).unwrap();
        symlink(&target, &sidecar).unwrap();
        assert_eq!(
            store(&symlink_root).load_or_create_installation(),
            Err(DesktopLocalAuthorityError::SidecarPathCorrupt)
        );
        fs::remove_dir_all(symlink_root).unwrap();
        fs::remove_dir_all(target).unwrap();

        let permission_root = root("sidecar-permissions");
        let installation = store(&permission_root)
            .load_or_create_installation()
            .unwrap();
        fs::set_permissions(
            installation.sidecar_data_dir(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(
            store(&permission_root).load_or_create_installation(),
            Err(DesktopLocalAuthorityError::SidecarPermissionsInsecure)
        );
        fs::remove_dir_all(permission_root).unwrap();
    }

    #[test]
    fn postgres_listener_allowlist_is_closed() {
        for allowed in ["", "127.0.0.1", "::1", "127.0.0.1, ::1"] {
            assert!(listen_addresses_are_local(allowed), "rejected {allowed}");
        }
        for rejected in ["*", "0.0.0.0", "localhost", "127.0.0.1,10.0.0.2"] {
            assert!(!listen_addresses_are_local(rejected), "accepted {rejected}");
        }
    }

    #[test]
    fn postgres_attestation_rejects_wrong_scope_version_exposure_and_password_mode() {
        let root = root("postgres-attestation");
        let expected = root.join("expected");
        let other = root.join("other");
        fs::create_dir_all(&expected).unwrap();
        fs::create_dir(&other).unwrap();
        let expected_text = expected.to_str().unwrap();
        let other_text = other.to_str().unwrap();
        let valid = PostgresSidecarAttestation {
            data_directory: expected_text,
            version: "170011",
            listen_addresses: "127.0.0.1",
            password_encryption: "scram-sha-256",
            server_address: Some("127.0.0.1"),
            host_scram_only: true,
            hba_valid: true,
        };
        assert!(validate_postgres_sidecar_attestation(&expected, valid).is_ok());
        assert!(matches!(
            validate_postgres_sidecar_attestation(
                &expected,
                PostgresSidecarAttestation {
                    data_directory: other_text,
                    ..valid
                },
            ),
            Err(DesktopLocalBootstrapError::PostgresDataDirectoryMismatch)
        ));
        assert!(matches!(
            validate_postgres_sidecar_attestation(
                &expected,
                PostgresSidecarAttestation {
                    version: "160009",
                    ..valid
                },
            ),
            Err(DesktopLocalBootstrapError::PostgresMajorUnsupported)
        ));
        for (listen, address) in [
            ("*", Some("127.0.0.1")),
            ("127.0.0.1", Some("10.0.0.2")),
            ("127.0.0.1", Some("not-an-ip")),
        ] {
            assert!(matches!(
                validate_postgres_sidecar_attestation(
                    &expected,
                    PostgresSidecarAttestation {
                        listen_addresses: listen,
                        server_address: address,
                        ..valid
                    },
                ),
                Err(DesktopLocalBootstrapError::PostgresExposureRefused)
            ));
        }
        assert!(matches!(
            validate_postgres_sidecar_attestation(
                &expected,
                PostgresSidecarAttestation {
                    password_encryption: "md5",
                    ..valid
                },
            ),
            Err(DesktopLocalBootstrapError::PostgresScramRequired)
        ));
        for (host_scram_only, hba_valid) in [(false, true), (true, false)] {
            assert!(matches!(
                validate_postgres_sidecar_attestation(
                    &expected,
                    PostgresSidecarAttestation {
                        host_scram_only,
                        hba_valid,
                        ..valid
                    },
                ),
                Err(DesktopLocalBootstrapError::PostgresScramRequired)
            ));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_symlink_and_broad_permissions_fail_closed() {
        let corrupt_root = root("corrupt");
        prepare_root(&corrupt_root).unwrap();
        fs::write(corrupt_root.join(FILE_NAME), "bad\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                corrupt_root.join(FILE_NAME),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert_eq!(
            store(&corrupt_root).load_or_create(),
            Err(DesktopLocalAuthorityError::Corrupt)
        );
        fs::remove_dir_all(corrupt_root).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};

            let permission_root = root("permissions");
            let _ = store(&permission_root).load_or_create().unwrap();
            fs::set_permissions(
                permission_root.join(FILE_NAME),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert_eq!(
                store(&permission_root).load_or_create(),
                Err(DesktopLocalAuthorityError::InsecurePermissions)
            );
            fs::remove_dir_all(permission_root).unwrap();

            let symlink_root = root("symlink");
            prepare_root(&symlink_root).unwrap();
            let target = symlink_root.join("target");
            fs::write(&target, render([7; INSTANCE_BYTES])).unwrap();
            symlink(&target, symlink_root.join(FILE_NAME)).unwrap();
            assert_eq!(
                store(&symlink_root).load_or_create(),
                Err(DesktopLocalAuthorityError::Corrupt)
            );
            fs::remove_dir_all(symlink_root).unwrap();
        }
    }

    #[test]
    fn format_is_closed_and_app_data_root_must_be_absolute() {
        assert_eq!(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data("relative"),
            Err(DesktopLocalAuthorityError::InvalidAppDataRoot)
        );
        let bytes = [0xab; INSTANCE_BYTES];
        let encoded = encode(bytes);
        assert_eq!(decode(&encoded), Some(bytes));
        assert!(decode(&encoded.to_ascii_uppercase()).is_none());
        assert!(
            parse(&format!(
                "{FILE_HEADER}\n{INSTANCE_PREFIX}{encoded}\nextra=x\n"
            ))
            .is_err()
        );
        let forbidden_env_read = ["std::env", "::var"].concat();
        assert!(!include_str!("desktop_local.rs").contains(&forbidden_env_read));
    }
}

/// Original installation descriptors retained by the armed startup owner.
/// Borrowed descriptors and identity observations do not confer a capture source grant.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub struct RetainedInstallationCapture {
    root: File,
    marker: File,
    root_identity: InstallationCaptureIdentity,
    marker_identity: InstallationCaptureIdentity,
    original_instance: Arc<str>,
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
#[derive(Clone, Copy, PartialEq, Eq)]
struct InstallationCaptureIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    mtime: i64,
    mtime_ns: i64,
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl InstallationCaptureIdentity {
    fn observe_before(
        file: &File,
        clock: &dyn crate::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<Self, openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        use std::os::unix::fs::MetadataExt as _;
        clock.require_effect()?;
        let observed = file.metadata();
        clock.require_effect()?;
        let meta = observed.map_err(|_| Fault::IoFailure)?;
        Ok(Self {
            device: meta.dev(), inode: meta.ino(), uid: meta.uid(), mode: meta.mode(),
            links: meta.nlink(), bytes: meta.len(), mtime: meta.mtime(),
            mtime_ns: meta.mtime_nsec(),
        })
    }

    fn observe(file: &File) -> Result<Self, DesktopLocalAuthorityError> {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            mode: meta.mode(),
            links: meta.nlink(),
            bytes: meta.len(),
            mtime: meta.mtime(),
            mtime_ns: meta.mtime_nsec(),
        })
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl DesktopLocalInstallation {
    /// Retain the original installation descriptors before the capture operation starts.
    pub fn retain_capture_installation(
        &self,
    ) -> Result<RetainedInstallationCapture, DesktopLocalAuthorityError> {
        use rustix::fs::{Mode, OFlags};
        let parent = self
            .sidecar_data_dir
            .parent()
            .ok_or(DesktopLocalAuthorityError::Corrupt)?;
        let root = crate::artifact_store::open_trusted_host_root(parent)
            .map_err(|_| DesktopLocalAuthorityError::InsecurePermissions)?;
        let marker = File::from(
            rustix::fs::openat(
                &root,
                FILE_NAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| DesktopLocalAuthorityError::Corrupt)?,
        );
        let root_identity = InstallationCaptureIdentity::observe(&root)?;
        let marker_identity = InstallationCaptureIdentity::observe(&marker)?;
        if root_identity.mode & 0o7777 != 0o700
            || marker_identity.mode & 0o170000 != 0o100000
            || marker_identity.mode & 0o7777 != 0o600
            || marker_identity.links != 1
            || marker_identity.uid != root_identity.uid
            || marker_identity.bytes > FILE_MAX_BYTES
        {
            return Err(DesktopLocalAuthorityError::InsecurePermissions);
        }
        let mut retained = RetainedInstallationCapture {
            root,
            marker,
            root_identity,
            marker_identity,
            original_instance: Arc::clone(&self.authority.instance_id),
        };
        retained.verify_original_startup()?;
        Ok(retained)
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl RetainedInstallationCapture {
    /// Borrow the startup-retained root without reopening or duplicating it.
    pub fn original_root(&self) -> &File {
        &self.root
    }
    /// Borrow the startup-retained marker without reopening or duplicating it.
    pub fn original_marker(&self) -> &File {
        &self.marker
    }
    // Only retain_capture_installation calls this pre-t0 verifier.
    fn verify_original_startup(&mut self) -> Result<(), DesktopLocalAuthorityError> {
        use std::os::unix::fs::FileExt;
        // Root mtime/size may legitimately change as the same startup creates known children;
        // its kernel identity/owner/mode cannot. Marker contents and every marker identity
        // field are immutable, even when its original name has been replaced.
        let root = InstallationCaptureIdentity::observe(&self.root)?;
        if (root.device, root.inode, root.uid, root.mode)
            != (
                self.root_identity.device,
                self.root_identity.inode,
                self.root_identity.uid,
                self.root_identity.mode,
            )
            || InstallationCaptureIdentity::observe(&self.marker)? != self.marker_identity
        {
            return Err(DesktopLocalAuthorityError::Corrupt);
        }
        let named =
            rustix::fs::statat(&self.root, FILE_NAME, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| DesktopLocalAuthorityError::Corrupt)?;
        if named.st_ino != self.marker_identity.inode
            || named.st_dev as u64 != self.marker_identity.device
        {
            return Err(DesktopLocalAuthorityError::Corrupt);
        }
        let mut raw = [0_u8; FILE_MAX_BYTES as usize];
        let length = usize::try_from(self.marker_identity.bytes)
            .map_err(|_| DesktopLocalAuthorityError::Corrupt)?;
        let mut offset = 0;
        while offset < length {
            let n = self
                .marker
                .read_at(&mut raw[offset..length], offset as u64)
                .map_err(|_| DesktopLocalAuthorityError::Unavailable)?;
            if n == 0 {
                return Err(DesktopLocalAuthorityError::Corrupt);
            }
            offset += n;
        }
        let mut extra = [0_u8; 1];
        if self
            .marker
            .read_at(&mut extra, length as u64)
            .map_err(|_| DesktopLocalAuthorityError::Unavailable)?
            != 0
        {
            return Err(DesktopLocalAuthorityError::Corrupt);
        }
        let parsed = parse(
            std::str::from_utf8(&raw[..length]).map_err(|_| DesktopLocalAuthorityError::Corrupt)?,
        )?;
        if encode(parsed) != self.original_instance.as_ref()
            || InstallationCaptureIdentity::observe(&self.marker)? != self.marker_identity
        {
            return Err(DesktopLocalAuthorityError::Corrupt);
        }
        Ok(())
    }
    /// Revalidate the original descriptors with the same operation's per-effect clock.
    pub fn verify_original(
        &mut self,
        clock: &dyn crate::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        use std::os::unix::fs::FileExt as _;
        clock.require_effect()?;
        let root = InstallationCaptureIdentity::observe_before(&self.root, clock)?;
        if (root.device, root.inode, root.uid, root.mode)
            != (self.root_identity.device, self.root_identity.inode,
                self.root_identity.uid, self.root_identity.mode)
            || InstallationCaptureIdentity::observe_before(&self.marker, clock)?
                != self.marker_identity
        {
            return Err(Fault::SourceChanged);
        }
        self.verify_marker_name_before(clock)?;
        let length = usize::try_from(self.marker_identity.bytes)
            .map_err(|_| Fault::BoundsOverflow)?;
        if length == 0 || length > FILE_MAX_BYTES as usize {
            return Err(Fault::SourceChanged);
        }
        let mut raw = [0_u8; FILE_MAX_BYTES as usize];
        let mut offset = 0;
        while offset < length {
            clock.require_effect()?;
            let observed = self.marker.read_at(&mut raw[offset..length], offset as u64);
            // The original E postcheck runs before every result classification, including Err.
            clock.require_effect()?;
            match observed {
                Ok(0) => return Err(Fault::SourceChanged),
                Ok(n) => offset = offset.checked_add(n).ok_or(Fault::BoundsOverflow)?,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Fault::IoFailure),
            }
        }
        let mut extra = [0_u8; 1];
        loop {
            clock.require_effect()?;
            let observed = self.marker.read_at(&mut extra, length as u64);
            clock.require_effect()?;
            match observed {
                Ok(0) => break,
                Ok(_) => return Err(Fault::SourceChanged),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Fault::IoFailure),
            }
        }
        let parsed = parse(std::str::from_utf8(&raw[..length])
            .map_err(|_| Fault::SourceChanged)?)
            .map_err(|_| Fault::SourceChanged)?;
        if encode(parsed) != self.original_instance.as_ref()
            || InstallationCaptureIdentity::observe_before(&self.marker, clock)?
                != self.marker_identity
        {
            return Err(Fault::SourceChanged);
        }
        self.verify_marker_name_before(clock)?;
        let root = InstallationCaptureIdentity::observe_before(&self.root, clock)?;
        if (root.device, root.inode, root.uid, root.mode)
            != (self.root_identity.device, self.root_identity.inode,
                self.root_identity.uid, self.root_identity.mode)
        {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()
    }

    fn verify_marker_name_before(
        &self,
        clock: &dyn crate::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        clock.require_effect()?;
        let observed = rustix::fs::statat(
            &self.root, FILE_NAME, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
        clock.require_effect()?;
        let named = observed.map_err(|_| Fault::IoFailure)?;
        if named.st_ino != self.marker_identity.inode
            || named.st_dev as u64 != self.marker_identity.device
            || named.st_uid != self.marker_identity.uid
            || u32::from(named.st_mode) != self.marker_identity.mode
            || named.st_nlink as u64 != self.marker_identity.links
            || u64::try_from(named.st_size).map_err(|_| Fault::SourceChanged)?
                != self.marker_identity.bytes
        {
            return Err(Fault::SourceChanged);
        }
        Ok(())
    }

    /// Move both originals only after the unique caller's all-sources-closed barrier.
    pub fn into_owned_parts(self) -> (File, File) {
        (self.root, self.marker)
    }
}
