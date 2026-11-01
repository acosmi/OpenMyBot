//! Composition owner from a verified PostgreSQL child to the shared Desktop Local data plane.
//!
//! This module deliberately stops before Tauri window creation. Its success value proves the
//! exact sequence required by v4 R153–R156: same installation/data directory, exact Tenant Package
//! scope, administrative SCRAM connection, live sidecar attestation, fixed database
//! create/reconciliation, shared migrations, canonical principal, and package membership. The
//! Tauri background runtime now consumes this owner and may bind a window only while it remains
//! alive.

use openbot_application::tenant::package::LoadedTenantPackage;
use openbot_contracts::auth::AuthContext;
use openbot_domain::vault::secret::SecretBytes;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::auth::single_user::desktop_local::{
    DesktopLocalAuthority, DesktopLocalBootstrapError, DesktopLocalBootstrapReport,
    DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{
    DesktopLocalDatabase, DesktopLocalDatabaseError, DesktopLocalDatabaseOrigin,
    connect_for_attestation,
};
use openbot_infra::db::desktop_vault_canary::VerifiedDesktopVaultCanary;
use openbot_infra::db::initialization::DatabaseOrigin;
use openbot_infra::db::pool::DatabasePool;
use openbot_infra::thread_listener::ThreadListenerDatabase;

use crate::postgres_sidecar::{PostgresSidecarOrigin, RunningPostgresSidecar};

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
use openbot_infra::db::desktop_local::{
    DesktopLocalDriverCustody, connect_for_attestation_retained,
};

enum StartupDriverCustody {
    Ordinary,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    Armed(DesktopLocalDriverCustody),
}

const STARTUP_DB_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One running PostgreSQL child plus the exact verified business pool and app-instance authority.
///
/// Dropping this owner without [`Self::shutdown`] closes the pool, then lets the sidecar's unclean
/// Drop preserve its stale start lock before killing the child. Clean application shutdown must
/// call the async method so verified `pg_ctl` can release the lock.
pub struct RunningDesktopLocalDataPlane {
    database: DesktopLocalDatabase,
    sidecar: Option<RunningPostgresSidecar>,
    installation: DesktopLocalInstallation,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture_custody: Option<DesktopLocalDriverCustody>,
    runtime_auth: AuthContext,
    report: DesktopLocalBootstrapReport,
    artifact_datasets: std::sync::Arc<ArtifactDatasetRegistry>,
}

/// PG-attested data plane that exposes no runtime authority before Vault canary verification.
pub struct PreparedDesktopLocalDataPlane {
    database: DesktopLocalDatabase,
    sidecar: Option<RunningPostgresSidecar>,
    installation: DesktopLocalInstallation,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture_custody: Option<DesktopLocalDriverCustody>,
    #[cfg(feature = "desktop-vault")]
    pub(crate) vault_creation_attempted: std::sync::atomic::AtomicBool,
}

impl RunningDesktopLocalDataPlane {
    /// Installation identity for package/key-store scope. Runtime application/window binding must
    /// use [`Self::auth_context`] so it receives the PostgreSQL generation snapshot.
    #[must_use]
    pub fn authority(&self) -> &DesktopLocalAuthority {
        self.installation.authority()
    }

    /// Borrow the database-verified runtime authority, including its preserved generation.
    #[must_use]
    pub const fn auth_context(&self) -> &AuthContext {
        &self.runtime_auth
    }

    /// Borrow the verified business pool for production adapter assembly.
    #[must_use]
    pub const fn pool(&self) -> &DatabasePool {
        self.database.pool()
    }

    /// Whether the fixed `openbot` database was created, pre-existing, or reconciled.
    #[must_use]
    pub const fn database_origin(&self) -> DesktopLocalDatabaseOrigin {
        self.database.origin()
    }

    /// Whether the PostgreSQL cluster itself was initialized by this process start.
    #[must_use]
    pub fn sidecar_origin(&self) -> Option<PostgresSidecarOrigin> {
        self.sidecar.as_ref().map(RunningPostgresSidecar::origin)
    }

    /// Shared migration and Tenant Package synchronization report.
    #[must_use]
    pub const fn bootstrap_report(&self) -> &DesktopLocalBootstrapReport {
        &self.report
    }

    /// Trusted namespace observation retained by this running database owner.
    /// This registry does not provide artifact bytes or product readiness.
    #[must_use]
    pub fn artifact_dataset_registry(&self) -> &ArtifactDatasetRegistry {
        self.artifact_datasets.as_ref()
    }

    /// Retain this exact live registry owner for the trusted local store composition.
    #[cfg(all(
        feature = "desktop-local-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    pub(crate) fn artifact_dataset_owner(&self) -> std::sync::Arc<ArtifactDatasetRegistry> {
        std::sync::Arc::clone(&self.artifact_datasets)
    }

    /// Adopt only the fixed artifacts child of this current installation and sidecar owner.
    #[cfg(all(
        feature = "desktop-local-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    pub(crate) async fn open_artifact_store(
        &self,
        policy: openbot_domain::artifact::ArtifactQuotaPolicy,
    ) -> Result<
        std::sync::Arc<openbot_infra::artifact_store::DatasetBoundArtifactStore>,
        DesktopLocalCompositionError,
    > {
        let current = || {
            self.sidecar
                .as_ref()
                .ok_or(DesktopLocalCompositionError::InstallationMismatch)?
                .ensure_owner_current()
                .map_err(|_| DesktopLocalCompositionError::InstallationMismatch)
        };
        current()?;
        let parent = self
            .installation
            .sidecar_data_dir()
            .parent()
            .ok_or(DesktopLocalCompositionError::InstallationMismatch)?
            .to_path_buf();
        let root = tokio::task::spawn_blocking(move || {
            openbot_infra::artifact_store::open_trusted_installation_artifact_root(&parent)
        })
        .await
        .map_err(|_| DesktopLocalCompositionError::ArtifactStore)?
        .map_err(|_| DesktopLocalCompositionError::ArtifactStore)?;
        current()?;
        let store = openbot_infra::artifact_store::DatasetBoundArtifactStore::bind_host_root(
            root,
            self.artifact_dataset_owner(),
            policy,
        )
        .await
        .map_err(|_| DesktopLocalCompositionError::ArtifactStore)?;
        current()?;
        Ok(std::sync::Arc::new(store))
    }

    /// Build a redacted dedicated LISTEN config directly from the owned SCRAM bytes, without a
    /// password `String`. The future shared application assembly consumes this before any window.
    pub fn thread_listener_database(
        &self,
    ) -> Result<ThreadListenerDatabase, DesktopLocalCompositionError> {
        let Some(sidecar) = self.sidecar.as_ref() else {
            return Err(DesktopLocalCompositionError::ListenerConfiguration);
        };
        let connection = sidecar.connection();
        ThreadListenerDatabase::desktop_local(connection.port(), connection.expose_password())
            .map_err(|_| DesktopLocalCompositionError::ListenerConfiguration)
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn capture_custody_mut(&mut self) -> Option<&mut DesktopLocalDriverCustody> {
        self.capture_custody.as_mut()
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn capture_sidecar_port(&self) -> Option<u16> {
        self.sidecar
            .as_ref()
            .map(|sidecar| sidecar.connection().port())
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn take_sidecar_for_capture(&mut self) -> Option<RunningPostgresSidecar> {
        self.sidecar.take()
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn installation(&self) -> &DesktopLocalInstallation {
        &self.installation
    }

    /// Close the application pool, then stop the exact child through its verified `pg_ctl` before
    /// releasing the single-instance lock.
    pub async fn shutdown(mut self) -> Result<(), DesktopLocalCompositionError> {
        self.database.close();
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(custody) = self.capture_custody.as_mut() {
            close_startup_original_drivers(custody).await;
        }
        let Some(sidecar) = self.sidecar.take() else {
            return Err(DesktopLocalCompositionError::SidecarShutdown);
        };
        sidecar
            .shutdown()
            .await
            .map_err(|_| DesktopLocalCompositionError::SidecarShutdown)
    }
}

impl PreparedDesktopLocalDataPlane {
    pub(crate) fn authority(&self) -> &DesktopLocalAuthority {
        self.installation.authority()
    }

    pub(crate) fn pool(&self) -> &DatabasePool {
        self.database.pool()
    }

    pub(crate) fn database(&self) -> &DesktopLocalDatabase {
        &self.database
    }

    pub(crate) fn database_origin(&self) -> DesktopLocalDatabaseOrigin {
        self.database.origin()
    }

    pub(crate) fn sidecar_origin(&self) -> Option<PostgresSidecarOrigin> {
        self.sidecar.as_ref().map(RunningPostgresSidecar::origin)
    }

    pub(crate) fn data_dir(&self) -> &std::path::Path {
        self.installation.sidecar_data_dir()
    }

    pub(crate) fn ensure_owner_current(&self) -> Result<(), DesktopLocalCompositionError> {
        self.sidecar
            .as_ref()
            .ok_or(DesktopLocalCompositionError::InstallationMismatch)?
            .ensure_owner_current()
            .map_err(|_| DesktopLocalCompositionError::InstallationMismatch)
    }

    pub(crate) async fn initialize_fresh_schema(
        &self,
        package: &LoadedTenantPackage,
    ) -> Result<DatabaseOrigin, DesktopLocalCompositionError> {
        if self.sidecar_origin() != Some(PostgresSidecarOrigin::Fresh)
            || self.database_origin() != DesktopLocalDatabaseOrigin::Created
        {
            return Err(DesktopLocalCompositionError::Bootstrap(
                DesktopLocalBootstrapError::VaultCanaryMismatch,
            ));
        }
        self.ensure_owner_current()?;
        let fresh = self.database.fresh_initialization_proof().ok_or_else(|| {
            DesktopLocalCompositionError::Bootstrap(DesktopLocalBootstrapError::VaultCanaryMismatch)
        })?;
        let origin = tokio::time::timeout(
            STARTUP_DB_STEP_TIMEOUT,
            self.installation
                .initialize_postgres_schema(&self.database, package, &fresh),
        )
        .await
        .map_err(|_| {
            DesktopLocalCompositionError::Bootstrap(
                DesktopLocalBootstrapError::PostgresAttestationUnavailable,
            )
        })?
        .map_err(DesktopLocalCompositionError::Bootstrap)?;
        self.ensure_owner_current()?;
        if origin != DatabaseOrigin::Fresh {
            return Err(DesktopLocalCompositionError::Bootstrap(
                DesktopLocalBootstrapError::VaultCanaryMismatch,
            ));
        }
        Ok(origin)
    }

    pub(crate) async fn complete_after_vault(
        mut self,
        package: &LoadedTenantPackage,
        database_origin: DatabaseOrigin,
        proof: &VerifiedDesktopVaultCanary,
        audit_checkpoint_key: &[u8],
    ) -> Result<RunningDesktopLocalDataPlane, DesktopLocalCompositionError> {
        if let Err(error) = self.ensure_owner_current() {
            return Err(self.cleanup_with(error).await);
        }
        let report = match tokio::time::timeout(
            STARTUP_DB_STEP_TIMEOUT,
            self.installation.complete_postgres_after_vault(
                &self.database,
                package,
                database_origin,
                proof,
            ),
        )
        .await
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)
        .and_then(std::convert::identity)
        {
            Ok(report) => report,
            Err(error) => {
                return Err(self
                    .cleanup_with(DesktopLocalCompositionError::Bootstrap(error))
                    .await);
            }
        };
        if let Err(error) = self.ensure_owner_current() {
            return Err(self.cleanup_with(error).await);
        }
        // V6-PR-020/024: matching required → bump once per epoch (applied witness), then clear required.
        #[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
        {
            let sidecar = self
                .sidecar
                .as_ref()
                .ok_or(DesktopLocalCompositionError::SidecarShutdown)?;
            let outstanding = match sidecar.auth_invalidation_outstanding() {
                Ok(value) => value,
                Err(_) => {
                    return Err(self
                        .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                            DesktopLocalBootstrapError::Principal(
                                openbot_infra::db::InfraError::repository_invariant(
                                    "desktop_local_auth_invalidation_witness_invalid",
                                ),
                            ),
                        ))
                        .await);
                }
            };
            if outstanding {
                // V6-PR-024: if applied already matches this epoch, skip SQL (once-per-epoch).
                let already_applied = match sidecar.auth_invalidation_applied() {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(self
                            .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                                DesktopLocalBootstrapError::Principal(
                                    openbot_infra::db::InfraError::repository_invariant(
                                        "desktop_local_auth_invalidation_applied_invalid",
                                    ),
                                ),
                            ))
                            .await);
                    }
                };
                if !already_applied {
                    if let Err(error) = tokio::time::timeout(
                        STARTUP_DB_STEP_TIMEOUT,
                        self.installation
                            .authority()
                            .advance_auth_generation(self.database.pool(), audit_checkpoint_key),
                    )
                    .await
                    .map_err(|_| {
                        openbot_infra::db::InfraError::repository_invariant(
                            "desktop_local_auth_generation_advance_timeout",
                        )
                    })
                    .and_then(std::convert::identity)
                    {
                        return Err(self
                            .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                                DesktopLocalBootstrapError::Principal(error),
                            ))
                            .await);
                    }
                    if sidecar.mark_auth_invalidation_applied().is_err() {
                        return Err(self
                            .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                                DesktopLocalBootstrapError::Principal(
                                    openbot_infra::db::InfraError::repository_invariant(
                                        "desktop_local_auth_invalidation_applied_failed",
                                    ),
                                ),
                            ))
                            .await);
                    }
                }
                if sidecar.clear_auth_invalidation_after_advance().is_err() {
                    return Err(self
                        .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                            DesktopLocalBootstrapError::Principal(
                                openbot_infra::db::InfraError::repository_invariant(
                                    "desktop_local_auth_invalidation_clear_failed",
                                ),
                            ),
                        ))
                        .await);
                }
                if let Err(error) = self.ensure_owner_current() {
                    return Err(self.cleanup_with(error).await);
                }
            }
        }
        let runtime_auth = match tokio::time::timeout(
            STARTUP_DB_STEP_TIMEOUT,
            self.installation
                .authority()
                .load_runtime_auth_context(self.database.pool()),
        )
        .await
        .map_err(|_| {
            openbot_infra::db::InfraError::repository_invariant(
                "desktop_local_runtime_auth_timeout",
            )
        })
        .and_then(std::convert::identity)
        {
            Ok(auth) => auth,
            Err(error) => {
                return Err(self
                    .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                        DesktopLocalBootstrapError::Principal(error),
                    ))
                    .await);
            }
        };
        if let Err(error) = self.ensure_owner_current() {
            return Err(self.cleanup_with(error).await);
        }
        let artifact_datasets = match tokio::time::timeout(
            STARTUP_DB_STEP_TIMEOUT,
            ArtifactDatasetRegistry::from_desktop(&self.database, proof),
        )
        .await
        {
            Ok(Ok(registry)) => registry,
            Ok(Err(_)) | Err(_) => {
                return Err(self
                    .cleanup_with(DesktopLocalCompositionError::Bootstrap(
                        DesktopLocalBootstrapError::Principal(
                            openbot_infra::db::InfraError::repository_invariant(
                                "desktop_artifact_dataset_binding_unavailable",
                            ),
                        ),
                    ))
                    .await);
            }
        };
        if let Err(error) = self.ensure_owner_current() {
            return Err(self.cleanup_with(error).await);
        }
        Ok(RunningDesktopLocalDataPlane {
            database: self.database,
            sidecar: self.sidecar.take(),
            installation: self.installation,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            capture_custody: self.capture_custody.take(),
            runtime_auth,
            report,
            artifact_datasets: std::sync::Arc::new(artifact_datasets),
        })
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), DesktopLocalCompositionError> {
        self.database.close();
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(custody) = self.capture_custody.as_mut() {
            close_startup_original_drivers(custody).await;
        }
        self.sidecar
            .take()
            .ok_or(DesktopLocalCompositionError::SidecarShutdown)?
            .shutdown()
            .await
            .map_err(|_| DesktopLocalCompositionError::SidecarShutdown)
    }

    async fn cleanup_with(
        mut self,
        original: DesktopLocalCompositionError,
    ) -> DesktopLocalCompositionError {
        self.database.close();
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(custody) = self.capture_custody.as_mut() {
            close_startup_original_drivers(custody).await;
        }
        let result = match self.sidecar.take() {
            Some(sidecar) => sidecar.shutdown().await,
            None => return DesktopLocalCompositionError::FailureCleanup,
        };
        if result.is_ok() {
            original
        } else {
            DesktopLocalCompositionError::FailureCleanup
        }
    }
}

impl core::fmt::Debug for RunningDesktopLocalDataPlane {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RunningDesktopLocalDataPlane")
            .field("instance", &"<redacted>")
            .field("database_origin", &self.database.origin())
            .field("sidecar_origin", &self.sidecar_origin())
            .field("pool", &"<redacted>")
            .finish()
    }
}

impl Drop for RunningDesktopLocalDataPlane {
    fn drop(&mut self) {
        self.database.close();
    }
}

/// Stable pre-window composition failures; path, package contents and SCRAM bytes are never kept.
#[derive(Debug, thiserror::Error)]
pub enum DesktopLocalCompositionError {
    /// The current installation could not adopt its actual exclusive artifact byte root.
    #[cfg(feature = "desktop-local-runtime")]
    #[error("desktop_local_artifact_store_unavailable")]
    ArtifactStore,
    /// The running child belongs to a different app-instance data directory.
    #[error("desktop_local_sidecar_installation_mismatch")]
    InstallationMismatch,
    /// The package tenant differs from the installation authority, rejected before DB creation.
    #[error("desktop_local_package_scope_mismatch")]
    PackageScope(#[source] DesktopLocalBootstrapError),
    /// Administrative connection or fixed database create/reconciliation failed.
    #[error("desktop_local_database_assembly_failed")]
    Database(#[source] DesktopLocalDatabaseError),
    /// Live attestation or shared migration/principal/package bootstrap failed.
    #[error("desktop_local_bootstrap_failed")]
    Bootstrap(#[source] DesktopLocalBootstrapError),
    /// Failure cleanup could not prove a verified clean stop; the stale lock remains fail-closed.
    #[error("desktop_local_failure_cleanup_failed")]
    FailureCleanup,
    /// Explicit clean shutdown did not complete through verified `pg_ctl` and exact-child wait.
    #[error("desktop_local_sidecar_shutdown_failed")]
    SidecarShutdown,
    /// Dedicated PostgreSQL LISTEN configuration could not be built from the owned sidecar.
    #[error("desktop_local_listener_configuration_failed")]
    ListenerConfiguration,
}

/// Consume one SCRAM-ready child and close the full Batch79 bootstrap before any window authority
/// can be issued.
pub async fn prepare_running_sidecar(
    installation: DesktopLocalInstallation,
    sidecar: RunningPostgresSidecar,
    package: &LoadedTenantPackage,
) -> Result<PreparedDesktopLocalDataPlane, DesktopLocalCompositionError> {
    prepare_running_sidecar_inner(
        installation,
        sidecar,
        package,
        StartupDriverCustody::Ordinary,
    )
    .await
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
pub(crate) async fn prepare_running_sidecar_retained(
    installation: DesktopLocalInstallation,
    sidecar: RunningPostgresSidecar,
    package: &LoadedTenantPackage,
    custody: DesktopLocalDriverCustody,
) -> Result<PreparedDesktopLocalDataPlane, DesktopLocalCompositionError> {
    prepare_running_sidecar_inner(
        installation,
        sidecar,
        package,
        StartupDriverCustody::Armed(custody),
    )
    .await
}

async fn prepare_running_sidecar_inner(
    installation: DesktopLocalInstallation,
    sidecar: RunningPostgresSidecar,
    package: &LoadedTenantPackage,
    mut custody: StartupDriverCustody,
) -> Result<PreparedDesktopLocalDataPlane, DesktopLocalCompositionError> {
    if sidecar.data_dir() != installation.sidecar_data_dir() {
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
        )
        .await);
    }
    if let Err(error) = installation.validate_package_scope(package) {
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::PackageScope(error),
            &mut custody,
        )
        .await);
    }

    if sidecar.ensure_owner_current().is_err() {
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
        )
        .await);
    }

    let (port, password) = {
        let connection = sidecar.connection();
        (
            connection.port(),
            SecretBytes::new(connection.expose_password().to_vec()),
        )
    };
    let connect = async {
        match &custody {
            StartupDriverCustody::Ordinary => connect_for_attestation(port, password).await,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            StartupDriverCustody::Armed(retained) => {
                connect_for_attestation_retained(port, password, retained).await
            }
        }
    };
    let admin = tokio::time::timeout(STARTUP_DB_STEP_TIMEOUT, connect)
        .await
        .map_err(|_| DesktopLocalDatabaseError::ShapeInvalid)
        .and_then(std::convert::identity);
    let admin = match admin {
        Ok(admin) => admin,
        Err(error) => {
            return Err(cleanup_after_failure_with_custody(
                sidecar,
                DesktopLocalCompositionError::Database(error),
                &mut custody,
            )
            .await);
        }
    };
    if sidecar.ensure_owner_current().is_err() {
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
        )
        .await);
    }
    let admin = match tokio::time::timeout(
        STARTUP_DB_STEP_TIMEOUT,
        installation.attest_postgres_admin(admin),
    )
    .await
    .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)
    .and_then(std::convert::identity)
    {
        Ok(admin) => admin,
        Err(error) => {
            return Err(cleanup_after_failure_with_custody(
                sidecar,
                DesktopLocalCompositionError::Bootstrap(error),
                &mut custody,
            )
            .await);
        }
    };
    if sidecar.ensure_owner_current().is_err() {
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
        )
        .await);
    }
    let allow_create = sidecar.origin() == PostgresSidecarOrigin::Fresh;
    let database = match tokio::time::timeout(
        STARTUP_DB_STEP_TIMEOUT,
        admin.connect_application(allow_create),
    )
    .await
    .map_err(|_| DesktopLocalDatabaseError::ShapeInvalid)
    .and_then(std::convert::identity)
    {
        Ok(database) => database,
        Err(error) => {
            return Err(cleanup_after_failure_with_custody(
                sidecar,
                DesktopLocalCompositionError::Database(error),
                &mut custody,
            )
            .await);
        }
    };
    if sidecar.ensure_owner_current().is_err() {
        database.close();
        return Err(cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
        )
        .await);
    }
    Ok(PreparedDesktopLocalDataPlane {
        database,
        sidecar: Some(sidecar),
        installation,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        capture_custody: match custody {
            StartupDriverCustody::Ordinary => None,
            StartupDriverCustody::Armed(retained) => Some(retained),
        },
        #[cfg(feature = "desktop-vault")]
        vault_creation_attempted: std::sync::atomic::AtomicBool::new(false),
    })
}

async fn cleanup_after_failure_with_custody(
    sidecar: RunningPostgresSidecar,
    original: DesktopLocalCompositionError,
    custody: &mut StartupDriverCustody,
) -> DesktopLocalCompositionError {
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    if let StartupDriverCustody::Armed(retained) = custody {
        close_startup_original_drivers(retained).await;
    }
    let _ = custody;
    cleanup_after_failure(sidecar, original).await
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
async fn close_startup_original_drivers(custody: &mut DesktopLocalDriverCustody) {
    // No capture operation exists on this path. Only original startup resources are closed.
    let mut drivers = match custody.freeze() {
        Ok(drivers) => drivers,
        Err(_) => {
            std::future::pending::<()>().await;
            let _keep_original_custody = custody;
            return;
        }
    };
    let mut actual_facts_ok = true;
    while let Some(retirement) = drivers.next_retirement() {
        retirement.request();
    }
    while drivers.original_tasks_remaining() != 0 {
        match drivers.join_next_original().await {
            Some(fact) => {
                actual_facts_ok &= fact.destruction().is_some();
            }
            None => {
                actual_facts_ok = false;
                break;
            }
        }
    }
    let deadline = tokio::time::Instant::now() + STARTUP_DB_STEP_TIMEOUT;
    while drivers.live_proxy_future_count() != 0 && tokio::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    if !actual_facts_ok
        || drivers.original_tasks_remaining() != 0
        || drivers.original_destructions_missing() != 0
        || drivers.live_proxy_future_count() != 0
    {
        std::future::pending::<()>().await;
        drop(drivers);
    }
}

async fn cleanup_after_failure(
    sidecar: RunningPostgresSidecar,
    original: DesktopLocalCompositionError,
) -> DesktopLocalCompositionError {
    match sidecar.shutdown().await {
        Ok(()) => original,
        Err(_) => DesktopLocalCompositionError::FailureCleanup,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn errors_and_debug_never_retain_runtime_values() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let path = "/Users/private/example/postgresql-17-secret";
        let error = DesktopLocalCompositionError::InstallationMismatch;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains(path));
        assert_ne!(Path::new(path), Path::new("/different"));
    }
}
