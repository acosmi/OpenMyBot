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
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
use openbot_infra::auth::single_user::desktop_local::RestoredLocalSite;
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
use openbot_infra::db::pool::{ConnectionDestruction, ConnectionObservation};
use openbot_infra::thread_listener::ThreadListenerDatabase;

use crate::postgres_sidecar::{
    PostgresSidecarOrigin, RunningPostgresSidecar, SidecarExit, SidecarOutcome,
};

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

/// Original application-pool resources retained for runtime-close observation.
#[derive(Debug)]
pub enum SqlDriverOutcome {
    /// This startup never constructed the application pool or one of its drivers.
    NeverStarted,
    /// Retained original drivers were joined and their destruction was observed.
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    Joined(Vec<ConnectionDestruction>),
    /// The pool's original observations, to be awaited within the close deadline.
    Observed(Vec<ConnectionObservation>),
    /// A driver may have existed without an observed join or destruction.
    Unknown,
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) fn sidecar_close_fact(
    result: Result<SidecarExit, SidecarOutcome>,
) -> Option<openbot_infra::recovery_control::RuntimeCloseFact> {
    sidecar_close_fact_ref(&result)
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) fn sidecar_close_fact_ref(
    result: &Result<SidecarExit, SidecarOutcome>,
) -> Option<openbot_infra::recovery_control::RuntimeCloseFact> {
    use openbot_infra::recovery_control::{
        NativeExit, PassiveObjectKind, PipeJoin, ProcessStart, RuntimeCloseFact, RuntimeOwner,
    };
    use std::os::unix::process::ExitStatusExt;
    let (evidence, status, observed_ns) = match result {
        Ok(exit) => {
            let (evidence, status, _, _, observed_ns) = exit.original_wait();
            (evidence?, status, observed_ns?)
        }
        Err(SidecarOutcome::NeverSpawned) => {
            return Some(RuntimeCloseFact::PassiveRetirement {
                object: PassiveObjectKind::NeverStarted(RuntimeOwner::PostgresSidecar),
            });
        }
        Err(SidecarOutcome::Exited {
            start_evidence,
            status,
            observed_ns,
            ..
        }) => (*start_evidence, *status, (*observed_ns)?),
        Err(SidecarOutcome::Unknown) => return None,
    };
    let exit = match status.code() {
        Some(value) => NativeExit::Code { value },
        None => NativeExit::Signal {
            value: status.signal()?,
        },
    };
    Some(RuntimeCloseFact::NativeWait {
        original_program_id: RuntimeOwner::PostgresSidecar,
        original_pid: u32::from_be_bytes(evidence[..4].try_into().expect("fixed process pid")),
        original_start_identity: ProcessStart {
            seconds: u64::from_be_bytes(evidence[4..12].try_into().expect("fixed process seconds")),
            nanos: u32::from_be_bytes(
                evidence[12..16]
                    .try_into()
                    .expect("fixed process microseconds"),
            )
            .checked_mul(1_000)?,
        },
        exit,
        observed_ns,
        pipes: [PipeJoin::Null, PipeJoin::Null, PipeJoin::Null],
    })
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) async fn sql_driver_close_fact(
    result: SqlDriverOutcome,
    deadline: std::time::Instant,
) -> Option<openbot_infra::recovery_control::RuntimeCloseFact> {
    sql_driver_close_fact_ref(&result, deadline).await
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) async fn sql_driver_close_fact_ref(
    result: &SqlDriverOutcome,
    deadline: std::time::Instant,
) -> Option<openbot_infra::recovery_control::RuntimeCloseFact> {
    use openbot_infra::recovery_control::{PassiveObjectKind, RuntimeCloseFact, RuntimeOwner};
    let object = match result {
        SqlDriverOutcome::NeverStarted => PassiveObjectKind::NeverStarted(RuntimeOwner::SqlDriver),
        SqlDriverOutcome::Joined(facts) => PassiveObjectKind::SqlDriver(facts.clone()),
        SqlDriverOutcome::Observed(observations) => {
            let mut facts = Vec::with_capacity(observations.len());
            for observation in observations {
                facts.push(
                    observation
                        .wait_for_destruction_before(deadline)
                        .await
                        .ok()?,
                );
            }
            PassiveObjectKind::SqlDriver(facts)
        }
        SqlDriverOutcome::Unknown => return None,
    };
    Some(RuntimeCloseFact::PassiveRetirement { object })
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
/// Its site is an installation, or a restored generation that has not yet passed its Current gate
/// and therefore has no installation authority at all (spec revision R484 ¶8023).
pub struct PreparedDesktopLocalDataPlane<S = DesktopLocalInstallation> {
    initialization_deadlines: Option<(std::time::Instant, std::time::Instant)>,
    database: DesktopLocalDatabase,
    sidecar: Option<RunningPostgresSidecar>,
    installation: S,
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
    #[expect(
        clippy::result_large_err,
        reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
    )]
    pub async fn shutdown(
        mut self,
    ) -> Result<
        (SidecarExit, Vec<ConnectionObservation>),
        (
            DesktopLocalCompositionError,
            Result<SidecarExit, SidecarOutcome>,
            SqlDriverOutcome,
        ),
    > {
        let observations = self.database.pool().connection_observations();
        self.database.close();
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let retired = match self.capture_custody.as_mut() {
            Some(custody) => close_startup_original_drivers(custody).await.is_some(),
            None => true,
        };
        #[cfg(not(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        )))]
        let retired = true;
        let sql = if retired {
            SqlDriverOutcome::Observed(observations)
        } else {
            SqlDriverOutcome::Unknown
        };
        let Some(sidecar) = self.sidecar.take() else {
            return Err((
                DesktopLocalCompositionError::SidecarShutdown,
                Err(SidecarOutcome::Unknown),
                sql,
            ));
        };
        match sidecar.shutdown().await {
            Ok(exit) => match sql {
                SqlDriverOutcome::Observed(observations) => Ok((exit, observations)),
                unknown => Err((
                    DesktopLocalCompositionError::SidecarShutdown,
                    Ok(exit),
                    unknown,
                )),
            },
            Err((_, outcome)) => Err((
                DesktopLocalCompositionError::SidecarShutdown,
                Err(outcome),
                sql,
            )),
        }
    }
}

impl PreparedDesktopLocalDataPlane {
    pub(crate) fn authority(&self) -> &DesktopLocalAuthority {
        self.installation.authority()
    }

    pub(crate) fn data_dir(&self) -> &std::path::Path {
        self.installation.sidecar_data_dir()
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl PreparedDesktopLocalDataPlane<RestoredLocalSite> {
    pub(crate) fn site(&self) -> &RestoredLocalSite {
        &self.installation
    }

    /// The installation formed only after this generation's Current gate
    /// (spec revision R484 ¶8024) takes over the same running data plane.
    pub(crate) fn into_current(
        self,
        installation: DesktopLocalInstallation,
    ) -> PreparedDesktopLocalDataPlane {
        PreparedDesktopLocalDataPlane {
            initialization_deadlines: self.initialization_deadlines,
            database: self.database,
            sidecar: self.sidecar,
            installation,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            capture_custody: self.capture_custody,
            #[cfg(feature = "desktop-vault")]
            vault_creation_attempted: self.vault_creation_attempted,
        }
    }
}

impl<S> PreparedDesktopLocalDataPlane<S> {
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

    pub(crate) fn ensure_owner_current(&self) -> Result<(), DesktopLocalCompositionError> {
        if self
            .initialization_deadlines
            .is_some_and(|(effect, _)| std::time::Instant::now() >= effect)
        {
            return Err(DesktopLocalCompositionError::InstallationMismatch);
        }
        self.sidecar
            .as_ref()
            .ok_or(DesktopLocalCompositionError::InstallationMismatch)?
            .ensure_owner_current()
            .map_err(|_| DesktopLocalCompositionError::InstallationMismatch)
    }
}

impl PreparedDesktopLocalDataPlane {
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

    #[expect(
        clippy::result_large_err,
        reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
    )]
    pub(crate) async fn complete_after_vault(
        mut self,
        package: &LoadedTenantPackage,
        database_origin: DatabaseOrigin,
        proof: &VerifiedDesktopVaultCanary,
        audit_checkpoint_key: &[u8],
    ) -> Result<
        RunningDesktopLocalDataPlane,
        (
            DesktopLocalCompositionError,
            Result<SidecarExit, SidecarOutcome>,
            SqlDriverOutcome,
        ),
    > {
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
            let sidecar = self.sidecar.as_ref().ok_or((
                DesktopLocalCompositionError::SidecarShutdown,
                Err(SidecarOutcome::Unknown),
                SqlDriverOutcome::Unknown,
            ))?;
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
}

impl<S> PreparedDesktopLocalDataPlane<S> {
    #[expect(
        clippy::result_large_err,
        reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
    )]
    pub(crate) async fn shutdown(
        mut self,
    ) -> Result<
        (SidecarExit, Vec<ConnectionObservation>),
        (
            DesktopLocalCompositionError,
            Result<SidecarExit, SidecarOutcome>,
            SqlDriverOutcome,
        ),
    > {
        let observations = self.database.pool().connection_observations();
        self.database.close();
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let retired = match self.capture_custody.as_mut() {
            Some(custody) => close_startup_original_drivers(custody).await.is_some(),
            None => true,
        };
        #[cfg(not(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        )))]
        let retired = true;
        let sql = if retired {
            SqlDriverOutcome::Observed(observations)
        } else {
            SqlDriverOutcome::Unknown
        };
        let Some(sidecar) = self.sidecar.take() else {
            return Err((
                DesktopLocalCompositionError::SidecarShutdown,
                Err(SidecarOutcome::Unknown),
                sql,
            ));
        };
        let stopped = match self.initialization_deadlines {
            Some((_, convergence)) => sidecar.shutdown_before(convergence).await,
            None => sidecar.shutdown().await,
        };
        match stopped {
            Ok(exit) => match sql {
                SqlDriverOutcome::Observed(observations) => Ok((exit, observations)),
                unknown => Err((
                    DesktopLocalCompositionError::SidecarShutdown,
                    Ok(exit),
                    unknown,
                )),
            },
            Err((error, outcome)) => Err((
                if self.initialization_deadlines.is_some() {
                    DesktopLocalCompositionError::LegacySidecarShutdown {
                        original: None,
                        error,
                    }
                } else {
                    DesktopLocalCompositionError::SidecarShutdown
                },
                Err(outcome),
                sql,
            )),
        }
    }

    async fn cleanup_with(
        self,
        original: DesktopLocalCompositionError,
    ) -> (
        DesktopLocalCompositionError,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ) {
        match self.shutdown().await {
            Ok((exit, observations)) => {
                (original, Ok(exit), SqlDriverOutcome::Observed(observations))
            }
            Err((_, sidecar, sql)) => (DesktopLocalCompositionError::FailureCleanup, sidecar, sql),
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
    /// Original adoption cleanup failed; preserve both startup and exact sidecar error.
    #[error("desktop_local_legacy_sidecar_shutdown_failed")]
    LegacySidecarShutdown {
        /// Original startup failure retained alongside its cleanup failure.
        original: Option<Box<DesktopLocalCompositionError>>,
        /// Exact error returned while stopping the original sidecar.
        error: crate::postgres_sidecar::PostgresSidecarError,
    },
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
    let scope = installation.validate_package_scope(package);
    prepare_running_sidecar_inner(
        installation,
        sidecar,
        scope,
        StartupDriverCustody::Ordinary,
        None,
    )
    .await
    .map_err(|(error, ..)| error)
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
#[expect(
    clippy::result_large_err,
    reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
)]
pub(crate) async fn prepare_running_sidecar_retained(
    installation: DesktopLocalInstallation,
    sidecar: RunningPostgresSidecar,
    package: &LoadedTenantPackage,
    custody: Option<DesktopLocalDriverCustody>,
    legacy: Option<&openbot_infra::recovery_control::OrdinaryInitializationSession>,
) -> Result<
    PreparedDesktopLocalDataPlane,
    (
        DesktopLocalCompositionError,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ),
> {
    let scope = installation.validate_package_scope(package);
    prepare_running_sidecar_inner(
        installation,
        sidecar,
        scope,
        match custody {
            Some(custody) => StartupDriverCustody::Armed(custody),
            None => StartupDriverCustody::Ordinary,
        },
        legacy.map(|owner| (owner.effect_deadline(), owner.convergence_deadline())),
    )
    .await
}

/// Prepare the selected restored generation's running child the same way, before any
/// installation authority exists; no package or database creation is involved.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[expect(
    clippy::result_large_err,
    reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
)]
pub(crate) async fn prepare_restored_sidecar(
    site: RestoredLocalSite,
    sidecar: RunningPostgresSidecar,
) -> Result<
    PreparedDesktopLocalDataPlane<RestoredLocalSite>,
    (
        DesktopLocalCompositionError,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ),
> {
    prepare_running_sidecar_inner(site, sidecar, Ok(()), StartupDriverCustody::Ordinary, None).await
}

/// Where opening a restored generation stopped, with what its original sidecar and SQL owners
/// actually observed for the runtime close.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[derive(Debug)]
pub(crate) enum RestoredOpenFailure {
    Sidecar(crate::postgres_sidecar::PostgresSidecarError),
    DataPlane(DesktopLocalCompositionError),
    Vault(crate::desktop_vault::DesktopVaultKeyError),
    Control(openbot_infra::recovery_control::RecoveryControlError),
    /// The Local subject gate refused or could not be read.
    Gate(openbot_infra::restore_reconfirmation::RestoreReconfirmationError),
    /// The confirmed generation's directory could not form an installation.
    Authority,
}

/// A restored generation opened to its real Current readback: its sidecar,
/// pool and Vault are running and the result is Pending, with no
/// installation authority (spec revision R484 ¶8023, ¶8132).
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) struct OpenedRestoredGeneration {
    pub(crate) data_plane: PreparedDesktopLocalDataPlane<RestoredLocalSite>,
    pub(crate) vault: crate::desktop_vault::VaultReadyDesktopMaterial,
    pub(crate) pending:
        openbot_infra::auth::single_user::desktop_local::VerifiedRestoreInstallationBinding,
}

/// Start the selected generation `runtime` names with its SCRAM slot, attest it, open its Vault
/// with its master slot and read it back against the published binding.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[expect(
    clippy::result_large_err,
    reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
)]
pub(crate) async fn open_restored_generation<S: crate::os_secret_store::OsSecretStore + ?Sized>(
    runtime: &mut openbot_infra::recovery_control::RecoveryRuntimeOwner,
    site: RestoredLocalSite,
    bundle: crate::postgres_sidecar::VerifiedPostgresBundle,
    store: &S,
    postgres_service: &crate::postgres_sidecar::ReviewedPostgresKeyStoreService,
    vault_service: &crate::desktop_vault::ReviewedDesktopVaultKeyStoreService,
    held: Option<crate::postgres_sidecar::KernelStartLock>,
) -> Result<
    OpenedRestoredGeneration,
    (
        RestoredOpenFailure,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ),
> {
    let sidecar = crate::postgres_sidecar::PostgresSidecarSupervisor::start_restored_current(
        bundle,
        &site,
        store,
        postgres_service,
        held,
    )
    .await
    .map_err(|(error, outcome)| {
        (
            RestoredOpenFailure::Sidecar(error),
            Err(outcome),
            SqlDriverOutcome::NeverStarted,
        )
    })?;
    let data_plane = prepare_restored_sidecar(site, sidecar)
        .await
        .map_err(|(error, sidecar, sql)| (RestoredOpenFailure::DataPlane(error), sidecar, sql))?;
    let vault = match data_plane
        .verify_restored_key_material(store, vault_service)
        .await
    {
        Ok(vault) => vault,
        Err(error) => {
            let (_, sidecar, sql) = data_plane
                .cleanup_with(DesktopLocalCompositionError::SidecarShutdown)
                .await;
            return Err((RestoredOpenFailure::Vault(error), sidecar, sql));
        }
    };
    let services = [vault_service.as_str(), postgres_service.as_str()];
    let pending = runtime
        .verify_restored_local_before(
            data_plane.database(),
            vault.canary(),
            services,
            data_plane.site(),
        )
        .await;
    match pending {
        Ok(pending) => Ok(OpenedRestoredGeneration {
            data_plane,
            vault,
            pending,
        }),
        Err(error) => {
            drop(vault);
            let (_, sidecar, sql) = data_plane
                .cleanup_with(DesktopLocalCompositionError::SidecarShutdown)
                .await;
            Err((RestoredOpenFailure::Control(error), sidecar, sql))
        }
    }
}

/// Startup's consumption of a restored Current: the opened generation passes
/// the Local subject gate, and only then does the one restricted factory form
/// its installation, which takes over the same running data plane (spec
/// revision R484 ¶8024, ¶8089). A Pending binding never reaches a factory.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[expect(
    clippy::result_large_err,
    reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
)]
pub(crate) async fn open_current_installation<S: crate::os_secret_store::OsSecretStore + ?Sized>(
    runtime: &mut openbot_infra::recovery_control::RecoveryRuntimeOwner,
    site: RestoredLocalSite,
    bundle: crate::postgres_sidecar::VerifiedPostgresBundle,
    store: &S,
    postgres_service: &crate::postgres_sidecar::ReviewedPostgresKeyStoreService,
    vault_service: &crate::desktop_vault::ReviewedDesktopVaultKeyStoreService,
    held: Option<crate::postgres_sidecar::KernelStartLock>,
) -> Result<
    (
        DesktopLocalInstallation,
        PreparedDesktopLocalDataPlane,
        crate::desktop_vault::VaultReadyDesktopMaterial,
    ),
    (
        RestoredOpenFailure,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ),
> {
    let OpenedRestoredGeneration {
        data_plane,
        vault,
        pending,
    } = open_restored_generation(
        runtime,
        site,
        bundle,
        store,
        postgres_service,
        vault_service,
        held,
    )
    .await?;
    let gate = runtime
        .current_restore_installation_before(
            data_plane.pool(),
            pending,
            std::time::Instant::now() + STARTUP_DB_STEP_TIMEOUT,
        )
        .await
        .map_err(RestoredOpenFailure::Gate)
        .and_then(|current| {
            DesktopLocalInstallation::from_verified_current_restore(current)
                .map_err(|_| RestoredOpenFailure::Authority)
        });
    match gate {
        Ok(installation) => {
            let prepared = data_plane.into_current(installation.clone());
            Ok((installation, prepared, vault))
        }
        Err(failure) => {
            drop(vault);
            let (_, sidecar, sql) = data_plane
                .cleanup_with(DesktopLocalCompositionError::SidecarShutdown)
                .await;
            Err((failure, sidecar, sql))
        }
    }
}

/// The two sites a prepared data plane can belong to.
trait DataPlaneSite {
    fn data_dir(&self) -> &std::path::Path;
    fn attest(
        &self,
        admin: openbot_infra::db::desktop_local::UnattestedDesktopLocalAdmin,
    ) -> impl std::future::Future<
        Output = Result<
            openbot_infra::db::desktop_local::AttestedDesktopLocalAdmin,
            DesktopLocalBootstrapError,
        >,
    > + Send;
}

impl DataPlaneSite for DesktopLocalInstallation {
    fn data_dir(&self) -> &std::path::Path {
        self.sidecar_data_dir()
    }
    fn attest(
        &self,
        admin: openbot_infra::db::desktop_local::UnattestedDesktopLocalAdmin,
    ) -> impl std::future::Future<
        Output = Result<
            openbot_infra::db::desktop_local::AttestedDesktopLocalAdmin,
            DesktopLocalBootstrapError,
        >,
    > + Send {
        self.attest_postgres_admin(admin)
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl DataPlaneSite for RestoredLocalSite {
    fn data_dir(&self) -> &std::path::Path {
        RestoredLocalSite::data_dir(self)
    }
    fn attest(
        &self,
        admin: openbot_infra::db::desktop_local::UnattestedDesktopLocalAdmin,
    ) -> impl std::future::Future<
        Output = Result<
            openbot_infra::db::desktop_local::AttestedDesktopLocalAdmin,
            DesktopLocalBootstrapError,
        >,
    > + Send {
        self.attest_postgres_admin(admin)
    }
}

#[expect(
    clippy::result_large_err,
    reason = "Return the original sidecar and SQL-driver failure custody without allocating after failed admission"
)]
async fn prepare_running_sidecar_inner<S: DataPlaneSite>(
    installation: S,
    sidecar: RunningPostgresSidecar,
    scope: Result<(), DesktopLocalBootstrapError>,
    mut custody: StartupDriverCustody,
    initialization_deadlines: Option<(std::time::Instant, std::time::Instant)>,
) -> Result<
    PreparedDesktopLocalDataPlane<S>,
    (
        DesktopLocalCompositionError,
        Result<SidecarExit, SidecarOutcome>,
        SqlDriverOutcome,
    ),
> {
    let step_deadline = || {
        initialization_deadlines
            .map(|(effect, _)| tokio::time::Instant::from_std(effect))
            .map_or(
                tokio::time::Instant::now() + STARTUP_DB_STEP_TIMEOUT,
                |effect| effect.min(tokio::time::Instant::now() + STARTUP_DB_STEP_TIMEOUT),
            )
    };
    if sidecar.data_dir() != installation.data_dir() {
        let (error, sidecar, _) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
    }
    if let Err(error) = scope {
        let (error, sidecar, _) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::PackageScope(error),
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
    }

    if sidecar.ensure_owner_current().is_err()
        || initialization_deadlines.is_some_and(|(effect, _)| std::time::Instant::now() >= effect)
    {
        let (error, sidecar, _) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
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
    let admin = tokio::time::timeout_at(step_deadline(), connect)
        .await
        .map_err(|_| DesktopLocalDatabaseError::ShapeInvalid)
        .and_then(std::convert::identity);
    let admin = match admin {
        Ok(admin) => admin,
        Err(error) => {
            let (error, sidecar, _) = cleanup_after_failure_with_custody(
                sidecar,
                DesktopLocalCompositionError::Database(error),
                &mut custody,
                initialization_deadlines.map(|(_, convergence)| convergence),
            )
            .await;
            return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
        }
    };
    if sidecar.ensure_owner_current().is_err()
        || initialization_deadlines.is_some_and(|(effect, _)| std::time::Instant::now() >= effect)
    {
        let (error, sidecar, _) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
    }
    let admin = match tokio::time::timeout_at(step_deadline(), installation.attest(admin))
        .await
        .map_err(|_| DesktopLocalBootstrapError::PostgresAttestationUnavailable)
        .and_then(std::convert::identity)
    {
        Ok(admin) => admin,
        Err(error) => {
            let (error, sidecar, _) = cleanup_after_failure_with_custody(
                sidecar,
                DesktopLocalCompositionError::Bootstrap(error),
                &mut custody,
                initialization_deadlines.map(|(_, convergence)| convergence),
            )
            .await;
            return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
        }
    };
    if sidecar.ensure_owner_current().is_err()
        || initialization_deadlines.is_some_and(|(effect, _)| std::time::Instant::now() >= effect)
    {
        let (error, sidecar, _) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        return Err((error, sidecar, SqlDriverOutcome::NeverStarted));
    }
    let allow_create = sidecar.origin() == PostgresSidecarOrigin::Fresh;
    let database =
        match tokio::time::timeout_at(step_deadline(), admin.connect_application(allow_create))
            .await
            .map_err(|_| DesktopLocalDatabaseError::ShapeInvalid)
            .and_then(std::convert::identity)
        {
            Ok(database) => database,
            Err(error) => {
                let never_started = matches!(
                    error,
                    DesktopLocalDatabaseError::Missing
                        | DesktopLocalDatabaseError::Inspect(_)
                        | DesktopLocalDatabaseError::Create(_)
                );
                let (error, sidecar, joined) = cleanup_after_failure_with_custody(
                    sidecar,
                    DesktopLocalCompositionError::Database(error),
                    &mut custody,
                    initialization_deadlines.map(|(_, convergence)| convergence),
                )
                .await;
                let sql = if never_started {
                    SqlDriverOutcome::NeverStarted
                } else {
                    match joined {
                        #[cfg(all(
                            feature = "desktop-launcher",
                            feature = "postgres-maintenance",
                            target_os = "macos"
                        ))]
                        Some(destructions) => SqlDriverOutcome::Joined(destructions),
                        _ => SqlDriverOutcome::Unknown,
                    }
                };
                return Err((error, sidecar, sql));
            }
        };
    if sidecar.ensure_owner_current().is_err()
        || initialization_deadlines.is_some_and(|(effect, _)| std::time::Instant::now() >= effect)
    {
        let observations = database.pool().connection_observations();
        database.close();
        let (error, sidecar, joined) = cleanup_after_failure_with_custody(
            sidecar,
            DesktopLocalCompositionError::InstallationMismatch,
            &mut custody,
            initialization_deadlines.map(|(_, convergence)| convergence),
        )
        .await;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let retired = !matches!(custody, StartupDriverCustody::Armed(_)) || joined.is_some();
        #[cfg(not(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        )))]
        let retired = {
            let _ = joined;
            true
        };
        return Err((
            error,
            sidecar,
            if retired {
                SqlDriverOutcome::Observed(observations)
            } else {
                SqlDriverOutcome::Unknown
            },
        ));
    }
    Ok(PreparedDesktopLocalDataPlane {
        initialization_deadlines,
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
    convergence: Option<std::time::Instant>,
) -> (
    DesktopLocalCompositionError,
    Result<SidecarExit, SidecarOutcome>,
    Option<Vec<ConnectionDestruction>>,
) {
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let joined = match custody {
        StartupDriverCustody::Armed(retained) => close_startup_original_drivers(retained).await,
        StartupDriverCustody::Ordinary => None,
    };
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let joined = {
        let _ = custody;
        None
    };
    let (error, outcome) = cleanup_after_failure(sidecar, original, convergence).await;
    (error, outcome, joined)
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
async fn close_startup_original_drivers(
    custody: &mut DesktopLocalDriverCustody,
) -> Option<Vec<ConnectionDestruction>> {
    // No capture operation exists on this path. Only original startup resources are closed.
    let mut drivers = match custody.freeze() {
        Ok(drivers) => drivers,
        Err(_) => return None,
    };
    let mut actual_facts_ok = true;
    let mut destructions = Vec::new();
    while let Some(retirement) = drivers.next_retirement() {
        retirement.request();
    }
    while drivers.original_tasks_remaining() != 0 {
        match drivers.join_next_original().await {
            Some(fact) => {
                actual_facts_ok &= fact.destruction().is_some();
                if let Some(destruction) = fact.destruction() {
                    destructions.push(destruction);
                }
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
        return None;
    }
    Some(destructions)
}

async fn cleanup_after_failure(
    sidecar: RunningPostgresSidecar,
    original: DesktopLocalCompositionError,
    convergence: Option<std::time::Instant>,
) -> (
    DesktopLocalCompositionError,
    Result<SidecarExit, SidecarOutcome>,
) {
    let stopped = match convergence {
        Some(cap) => sidecar.shutdown_before(cap).await,
        None => sidecar.shutdown().await,
    };
    match stopped {
        Ok(exit) => (original, Ok(exit)),
        Err((error, outcome)) => (
            if convergence.is_some() {
                DesktopLocalCompositionError::LegacySidecarShutdown {
                    original: Some(Box::new(original)),
                    error,
                }
            } else {
                DesktopLocalCompositionError::FailureCleanup
            },
            Err(outcome),
        ),
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
