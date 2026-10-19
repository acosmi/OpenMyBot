//! Original-pool dataset provenance for current-database custom model V2 operations.
//!
//! This binding reuses storage identity, never artifact or user authorization. Its
//! transaction can only come from the once-enrolled registry's original pool.

use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

use openbot_application::RunModelDatasetInitialOrigin;
use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::ids::{DeploymentId, TenantId};

use crate::artifact_registry::{ArtifactDatasetRegistry, ArtifactRegistryError};
use crate::db::pool::{DatabasePool, GuardedClient, GuardedTransaction, TransactionOwnerError};

/// Closed dataset failures. Transaction completion keeps its original owner type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModelDatasetError {
    /// The original pool, scope, schema, tuple or trusted producer does not match.
    #[error("model_dataset_invalid_binding")]
    InvalidBinding,
    /// The bounded actual observation could not complete.
    #[error("model_dataset_unavailable")]
    Unavailable,
}

struct OriginalRegistryEnrollment {
    registry: Weak<ArtifactDatasetRegistry>,
    owner: Weak<()>,
}

/// Once-enrolled current-database identity. It has no free dataset/transaction constructor.
pub struct PostgresModelDatasetBinding {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    enrollment: OnceLock<Result<OriginalRegistryEnrollment, ModelDatasetError>>,
}

impl core::fmt::Debug for PostgresModelDatasetBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgresModelDatasetBinding(<original-registry>)")
    }
}

impl PostgresModelDatasetBinding {
    pub(crate) fn unbound(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, ModelDatasetError> {
        if pool.is_closed()
            || !is_valid_artifact_identity(deployment.as_str())
            || !is_valid_artifact_identity(tenant.as_str())
        {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            enrollment: OnceLock::new(),
        })
    }

    /// Enroll the original trusted startup producer exactly once, including a failed first call.
    /// A failed or duplicate call must terminate the capability's host assembly.
    pub fn enroll_original_registry(
        &self,
        registry: &Arc<ArtifactDatasetRegistry>,
    ) -> Result<(), ModelDatasetError> {
        let result = if self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
            && registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            Ok(OriginalRegistryEnrollment {
                registry: Arc::downgrade(registry),
                owner: Arc::downgrade(&registry.owner()),
            })
        } else {
            Err(ModelDatasetError::InvalidBinding)
        };
        self.enrollment
            .set(result)
            .map_err(|_| ModelDatasetError::InvalidBinding)?;
        self.original_registry().map(|_| ())
    }

    /// Compare actual manager identity and both configured scopes, without granting authority.
    /// The original unbound Arc may be connected to consumers before host enrollment.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        self.matches_original_pool(pool) && &self.deployment == deployment && &self.tenant == tenant
    }

    pub(crate) fn matches_original_pool(&self, pool: &DatabasePool) -> bool {
        !self.pool.is_closed()
            && !pool.is_closed()
            && std::ptr::eq(self.pool.manager(), pool.manager())
    }

    fn original_registry(&self) -> Result<Arc<ArtifactDatasetRegistry>, ModelDatasetError> {
        let enrollment = self
            .enrollment
            .get()
            .ok_or(ModelDatasetError::InvalidBinding)?
            .as_ref()
            .map_err(|error| *error)?;
        let registry = enrollment
            .registry
            .upgrade()
            .ok_or(ModelDatasetError::InvalidBinding)?;
        let owner = enrollment
            .owner
            .upgrade()
            .ok_or(ModelDatasetError::InvalidBinding)?;
        if !registry.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
            || !self.matches_pool_scope(registry.pool(), &self.deployment, &self.tenant)
            || !Arc::ptr_eq(&owner, &registry.owner())
        {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(registry)
    }

    pub(crate) async fn checkout(
        &self,
        deadline: Instant,
    ) -> Result<ModelDatasetCheckout<'_>, ModelDatasetError> {
        let registry = self.original_registry()?;
        if Instant::now() >= deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        let client = registry
            .pool()
            .get_guarded(deadline)
            .await
            .map_err(|_| ModelDatasetError::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        // Recheck after the only checkout await; an ended/closed producer cannot grant a Tx.
        let current = self.original_registry()?;
        if !Arc::ptr_eq(&current, &registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        Ok(ModelDatasetCheckout {
            binding: self,
            registry,
            client,
            deadline,
        })
    }
}

pub(crate) struct ModelDatasetCheckout<'a> {
    binding: &'a PostgresModelDatasetBinding,
    registry: Arc<ArtifactDatasetRegistry>,
    client: GuardedClient,
    deadline: Instant,
}

impl core::fmt::Debug for ModelDatasetCheckout<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetCheckout(<original-owner>)")
    }
}

impl ModelDatasetCheckout<'_> {
    pub(crate) async fn begin_read_committed(
        &mut self,
    ) -> Result<ModelDatasetTransaction<'_>, TransactionOwnerError> {
        let transaction = self.client.begin_read_committed().await?;
        Ok(ModelDatasetTransaction {
            transaction,
            binding: self.binding,
            registry: &self.registry,
            deadline: self.deadline,
        })
    }
}

pub(crate) struct ModelDatasetTransaction<'a> {
    transaction: GuardedTransaction<'a>,
    binding: &'a PostgresModelDatasetBinding,
    registry: &'a ArtifactDatasetRegistry,
    deadline: Instant,
}

impl core::fmt::Debug for ModelDatasetTransaction<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetTransaction(<original-owner>)")
    }
}

impl<'a> ModelDatasetTransaction<'a> {
    pub(crate) fn as_transaction(&self) -> &tokio_postgres::Transaction<'a> {
        self.transaction.as_transaction()
    }

    pub(crate) async fn verify_current_dataset(
        &self,
    ) -> Result<ModelDatasetFacts, ModelDatasetError> {
        let current = self.binding.original_registry()?;
        if !std::ptr::eq(Arc::as_ptr(&current), self.registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        if Instant::now() >= self.deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.registry
                .verify_model_dataset_in_transaction(self.as_transaction()),
        )
        .await
        .map_err(|_| ModelDatasetError::Unavailable)?
        .map_err(|error| match error {
            ArtifactRegistryError::Unavailable => ModelDatasetError::Unavailable,
            _ => ModelDatasetError::InvalidBinding,
        })?;
        if Instant::now() >= self.deadline {
            return Err(ModelDatasetError::Unavailable);
        }
        let current = self.binding.original_registry()?;
        if !std::ptr::eq(Arc::as_ptr(&current), self.registry) {
            return Err(ModelDatasetError::InvalidBinding);
        }
        let binding = self.registry.binding();
        let initial_origin = match binding.initial_origin() {
            "desktop_canary" => RunModelDatasetInitialOrigin::DesktopCanary,
            "server_first_adoption" => RunModelDatasetInitialOrigin::ServerFirstAdoption,
            _ => return Err(ModelDatasetError::InvalidBinding),
        };
        Ok(ModelDatasetFacts {
            deployment: self.binding.deployment.clone(),
            tenant: self.binding.tenant.clone(),
            dataset_id: binding.dataset_id().to_owned(),
            binding_schema: binding.binding_schema(),
            initial_origin,
            created_at: binding.created_at(),
        })
    }

    pub(crate) async fn commit(self) -> Result<(), TransactionOwnerError> {
        self.transaction.commit().await
    }

    pub(crate) async fn rollback(self) -> Result<(), TransactionOwnerError> {
        self.transaction.rollback().await
    }
}

pub(crate) struct ModelDatasetFacts {
    deployment: DeploymentId,
    tenant: TenantId,
    dataset_id: String,
    binding_schema: i16,
    initial_origin: RunModelDatasetInitialOrigin,
    created_at: time::OffsetDateTime,
}

impl core::fmt::Debug for ModelDatasetFacts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ModelDatasetFacts(<verified-original-tuple>)")
    }
}

impl ModelDatasetFacts {
    pub(crate) fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }
    pub(crate) fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub(crate) fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub(crate) fn binding_schema(&self) -> i16 {
        self.binding_schema
    }
    pub(crate) fn initial_origin(&self) -> RunModelDatasetInitialOrigin {
        self.initial_origin
    }
    pub(crate) fn created_at(&self) -> time::OffsetDateTime {
        self.created_at
    }
}

// A controlled physical replacement is a refusal fault, never a restore capability.
// The tests keep the real original Desktop owner, registry and manager across the fault.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod physical_lineage_tests {
    use super::PostgresModelDatasetBinding;
    use crate::artifact_registry::{
        ArtifactDatasetRegistry, ArtifactRegistryError, verify_artifact_registry_schema,
    };
    use crate::auth::single_user::desktop_local::{
        CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
    };
    use crate::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
    use crate::db::desktop_vault_canary::{self, VerifiedDesktopVaultCanary};
    use crate::db::fresh;
    use crate::db::pool::{self, ConnectionDestruction, DatabaseConfig, DatabasePool};
    use crate::model_connections::PostgresModelConnections;
    use crate::thread_directory::PostgresThreadDirectory;
    use crate::vault::CredentialRecordVault;
    use openbot_application::model_connections::ModelConnectionAdministration;
    use openbot_application::{BeginThreadRunV2Request, ThreadDirectory, ThreadDirectoryError};
    use openbot_contracts::auth::AuthContext;
    use openbot_contracts::command::{BeginThreadRunV2, ThreadRunAnchor};
    use openbot_contracts::ids::thread::ThreadIdentity;
    use openbot_contracts::ids::{BotId, RunId};
    use openbot_contracts::model_connections::{
        CreateModelConnection, CustomModelProtocol, ModelApiKey, ModelConnection,
    };
    use openbot_contracts::versioned_model_selection::{
        ModelSelectionIntentSource, RunModelSelectionV2,
    };
    use openbot_domain::vault::{
        DesktopVaultCanaryBinding, DesktopVaultCanaryEnvelope, KeyVersion, NONCE_BYTES, Nonce,
        SecretBytes, WrappingKey, open_desktop_vault_canary, seal_desktop_vault_canary,
    };
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::net::TcpListener;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const TEST_USER: &str = "desktop_admin";
    const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const APP_DATABASE: &str = "openbot";

    async fn run_tool(mut command: Command, phase: &'static str) {
        tokio::task::spawn_blocking(move || {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let child = command.spawn().expect("owned fixed PG tool did not start");
            let pid = child.id();
            assert!(pid > 1 && pid <= i32::MAX as u32);
            eprintln!("CUSTOM_V2_LINEAGE_TOOL_START phase={phase} original_child_pid={pid}");
            let output = child.wait_with_output().expect("original owned PG tool wait failed");
            assert!(
                output.status.success(),
                "owned PG tool {phase} failed with {:?}; retain its own root/logs",
                output.status.code()
            );
            assert!(output.stdout.len() <= 1_048_576 && output.stderr.len() <= 1_048_576);
            eprintln!(
                "CUSTOM_V2_LINEAGE_TOOL phase={phase} original_child_pid={pid} original_wait_exit=0 stdout_closed=true stderr_closed=true"
            );
        })
        .await
        .expect("owned PG tool wait task did not join");
    }

    struct OwnedCluster {
        pg_bin: PathBuf,
        app_root: PathBuf,
        app_identity: (u64, u64),
        installation: DesktopLocalInstallation,
        data_dir: PathBuf,
        port: u16,
        postmaster_pid: Option<u32>,
        started: bool,
        stopped: bool,
        finished: bool,
    }

    impl OwnedCluster {
        fn command(&self, name: &str) -> Command {
            assert!(matches!(
                name,
                "initdb" | "pg_ctl" | "pg_dump" | "pg_restore"
            ));
            let executable = self.pg_bin.join(name);
            assert!(executable.is_absolute() && executable.is_file());
            let mut command = Command::new(executable);
            command
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", format!("{}:/usr/bin:/bin", self.pg_bin.display()))
                .env("TMPDIR", &self.app_root)
                .env("PGHOST", "127.0.0.1")
                .env("PGPORT", self.port.to_string())
                .env("PGUSER", TEST_USER)
                .env("PGPASSWORD", TEST_PASSWORD)
                .env("PGDATABASE", "postgres")
                .env("PGSSLMODE", "disable")
                .env("PGCONNECT_TIMEOUT", "5")
                .env("PGPASSFILE", self.app_root.join("absent-pgpass"))
                .env("PGSERVICEFILE", self.app_root.join("absent-service"))
                .env("PGSYSCONFDIR", &self.app_root)
                .stdin(Stdio::null());
            command
        }

        async fn start(reuse_port: Option<u16>) -> Self {
            let parent = fs::canonicalize(std::env::temp_dir()).expect("controlled TMPDIR");
            assert_eq!(parent.file_name().unwrap(), "desktop-tmp");
            let app_root = parent.join(format!(
                "openbot-v2-lineage-{}",
                uuid::Uuid::now_v7().simple()
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&app_root)
                .expect("exclusive owned app root");
            let metadata = fs::symlink_metadata(&app_root).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            let installation = DesktopLocalAuthorityStore::new(
                CurrentOsUserAppDataRoot::from_current_os_user_app_data(&app_root).unwrap(),
            )
            .load_or_create_installation()
            .unwrap();
            let data_dir = installation.sidecar_data_dir().to_owned();
            assert_eq!(data_dir.parent(), Some(app_root.as_path()));
            let port = if let Some(port) = reuse_port {
                let selector = TcpListener::bind(("127.0.0.1", port))
                    .expect("original stopped owned endpoint must be free");
                drop(selector);
                port
            } else {
                loop {
                    let selector = TcpListener::bind(("127.0.0.1", 0)).unwrap();
                    let port = selector.local_addr().unwrap().port();
                    drop(selector);
                    if ![39025, 39027].contains(&port) {
                        break port;
                    }
                }
            };
            assert!(![39025, 39027].contains(&port));
            let pg_bin = PathBuf::from(
                std::env::var_os("OPENBOT_TEST_PG_BIN").expect("Source fixed PG17 tools"),
            );
            assert!(pg_bin.is_absolute());
            let mut owned = Self {
                pg_bin,
                app_root,
                app_identity: (metadata.dev(), metadata.ino()),
                installation,
                data_dir,
                port,
                postmaster_pid: None,
                started: false,
                stopped: false,
                finished: false,
            };
            eprintln!(
                "CUSTOM_V2_LINEAGE_SETUP controlled_app_root={} data_dir={} port={port}",
                owned.app_root.display(),
                owned.data_dir.display()
            );
            let password_file = owned.app_root.join("owned-initdb-password");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&password_file)
                .unwrap();
            writeln!(file, "{TEST_PASSWORD}").unwrap();
            file.sync_all().unwrap();
            drop(file);
            let mut command = owned.command("initdb");
            command
                .arg("--pgdata")
                .arg(&owned.data_dir)
                .arg(format!("--username={TEST_USER}"))
                .arg("--pwfile")
                .arg(&password_file)
                .args([
                    "--auth-local=reject",
                    "--auth-host=scram-sha-256",
                    "--encoding=UTF8",
                    "--no-locale",
                ]);
            run_tool(command, "initdb").await;
            fs::remove_file(password_file).unwrap();
            let mut config = OpenOptions::new()
                .append(true)
                .open(owned.data_dir.join("postgresql.conf"))
                .unwrap();
            writeln!(config, "\nlisten_addresses='127.0.0.1'\nport={port}\nunix_socket_directories=''\npassword_encryption='scram-sha-256'\nmax_connections=16\ndynamic_shared_memory_type='posix'")
                .unwrap();
            config.sync_all().unwrap();
            drop(config);
            let mut command = owned.command("pg_ctl");
            command
                .arg("-D")
                .arg(&owned.data_dir)
                .arg("-l")
                .arg(owned.app_root.join("postgres.log"))
                .args(["-w", "-t", "15", "start"]);
            owned.started = true;
            run_tool(command, "start").await;
            let pid = owned.read_pid();
            owned.postmaster_pid = Some(pid);
            eprintln!(
                "CUSTOM_V2_LINEAGE_ACTUAL_RESOURCE original_postmaster_pid={pid} controlled_app_root={} original_PID_file={} data_dir={}",
                owned.app_root.display(),
                owned.data_dir.join("postmaster.pid").display(),
                owned.data_dir.display()
            );
            owned
        }

        fn read_pid(&self) -> u32 {
            let raw = fs::read_to_string(self.data_dir.join("postmaster.pid")).unwrap();
            let lines: Vec<_> = raw.lines().collect();
            assert!(lines.len() >= 4);
            let pid: u32 = lines[0].parse().unwrap();
            assert!(pid > 1 && pid <= i32::MAX as u32);
            assert_eq!(fs::canonicalize(lines[1]).unwrap(), self.data_dir);
            assert_eq!(lines[3].parse::<u16>().unwrap(), self.port);
            pid
        }

        fn config(&self, database: &str) -> DatabaseConfig {
            DatabaseConfig::new("127.0.0.1", self.port, TEST_USER, database)
                .with_password(TEST_PASSWORD)
                .with_application_name("openbot-v2-lineage-control")
                .with_max_pool_size(2)
        }

        fn require_pid_absent(&self) {
            let pid = self.postmaster_pid.expect("captured original PID");
            let output = Command::new("/bin/kill")
                .env_clear()
                .env("LC_ALL", "C")
                .args(["-0", &pid.to_string()])
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("No such process"));
            assert!(matches!(
                fs::symlink_metadata(self.data_dir.join("postmaster.pid")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ));
        }

        async fn stop(&mut self) {
            assert!(self.started && !self.stopped);
            assert_eq!(Some(self.read_pid()), self.postmaster_pid);
            let mut command = self.command("pg_ctl");
            command
                .arg("-D")
                .arg(&self.data_dir)
                .args(["-w", "-t", "15", "-m", "fast", "stop"]);
            run_tool(command, "stop").await;
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                let pid = self.postmaster_pid.unwrap();
                let probe = Command::new("/bin/kill")
                    .env_clear()
                    .env("LC_ALL", "C")
                    .args(["-0", &pid.to_string()])
                    .output()
                    .unwrap();
                if probe.status.code() == Some(1)
                    && String::from_utf8_lossy(&probe.stderr).contains("No such process")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            self.require_pid_absent();
            self.stopped = true;
        }

        async fn finish(&mut self) {
            if !self.stopped {
                self.stop().await;
            }
            self.require_pid_absent();
            let metadata = fs::symlink_metadata(&self.app_root).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            assert_eq!((metadata.dev(), metadata.ino()), self.app_identity);
            fs::remove_dir_all(&self.app_root).unwrap();
            assert!(matches!(
                fs::symlink_metadata(&self.app_root),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ));
            self.finished = true;
            eprintln!(
                "CUSTOM_V2_LINEAGE_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true original_PID_file_gone=true app_root_gone=true normal_pg_ctl_wait_exit=0",
                self.postmaster_pid.unwrap()
            );
        }
    }

    impl Drop for OwnedCluster {
        fn drop(&mut self) {
            if !self.finished {
                // Never delete evidence or emit successful closure from a fallback.
                // Best-effort stop is confined to this exact owned PID/data directory.
                if self.started && !self.stopped {
                    let same_pid = self.postmaster_pid.is_some_and(|pid| {
                        fs::read_to_string(self.data_dir.join("postmaster.pid"))
                            .ok()
                            .and_then(|text| text.lines().next()?.parse::<u32>().ok())
                            == Some(pid)
                    });
                    if same_pid {
                        let mut command = self.command("pg_ctl");
                        command
                            .arg("-D")
                            .arg(&self.data_dir)
                            .args(["-w", "-t", "15", "-m", "fast", "stop"]);
                        let _ = command.output();
                    }
                }
                eprintln!(
                    "CUSTOM_V2_LINEAGE_FAILURE retained_unproven_cleanup=true app_root={} fallback_never_acceptance=true",
                    self.app_root.display()
                );
            }
        }
    }

    async fn close_owned_pool(pool: &DatabasePool) {
        let observations = pool.connection_observations();
        pool.close();
        let deadline = Instant::now() + Duration::from_secs(10);
        for observation in observations {
            assert_eq!(
                observation
                    .wait_for_destruction_before(deadline)
                    .await
                    .unwrap(),
                ConnectionDestruction::ConnectionDestroyed
            );
        }
    }

    async fn identity(pool: &DatabasePool) -> (String, u32) {
        let client = pool.get().await.unwrap();
        let row = client
            .query_one(
                "SELECT pcs.system_identifier::text,d.oid FROM pg_catalog.pg_control_system() pcs \
                 JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()",
                &[],
            )
            .await
            .unwrap();
        let identity = (row.get::<_, String>(0), row.get::<_, u32>(1));
        assert!(!identity.0.is_empty() && identity.1 != 0);
        identity
    }

    async fn durable_image(pool: &DatabasePool) -> BTreeMap<&'static str, Value> {
        let client = pool.get().await.unwrap();
        let mut image = BTreeMap::new();
        for table in [
            "public.threads",
            "public.thread_memberships",
            "public.thread_leases",
            "public.runs",
            "public.messages",
            "public.run_events",
            "public.outbox",
            "public.run_model_selections",
            "openbot_internal.run_model_selection_v2_snapshots",
            "openbot_internal.artifact_dataset_bindings",
            "openbot_internal.desktop_vault_canaries",
            "openbot_internal.schema_migrations",
            "public.model_connections",
            "public.model_connection_secrets",
        ] {
            let row = client
                .query_one(
                    &format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text COLLATE \"C\"),'[]'::jsonb) FROM {table} t"),
                    &[],
                )
                .await
                .unwrap();
            image.insert(table, row.get(0));
        }
        image
    }

    struct ModelFixture {
        cluster: OwnedCluster,
        database: DesktopLocalDatabase,
        proof: VerifiedDesktopVaultCanary,
        registry: Arc<ArtifactDatasetRegistry>,
        binding: Arc<PostgresModelDatasetBinding>,
        directory: PostgresThreadDirectory,
        auth: AuthContext,
        model: ModelConnection,
        master: SecretBytes,
    }

    struct OriginalLineage {
        database_owner: Arc<()>,
        pool: DatabasePool,
        registry: Arc<ArtifactDatasetRegistry>,
        registry_owner: Arc<()>,
        physical: (String, u32),
        image: BTreeMap<&'static str, Value>,
    }

    impl ModelFixture {
        async fn new() -> Self {
            let cluster = OwnedCluster::start(None).await;
            let admin = connect_for_attestation(
                cluster.port,
                SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()),
            )
            .await
            .unwrap();
            let admin = cluster
                .installation
                .attest_postgres_admin(admin)
                .await
                .unwrap();
            let database = admin.connect_application(true).await.unwrap();
            let mut client = database.pool().get().await.unwrap();
            fresh::apply(&mut client).await.unwrap();
            drop(client);
            cluster
                .installation
                .authority()
                .provision_postgres(database.pool())
                .await
                .unwrap();
            let auth = cluster.installation.authority().auth_context().clone();
            let master = SecretBytes::new(vec![0x5a; 32]);
            let dataset = uuid::Uuid::now_v7().simple().to_string();
            let key_id = uuid::Uuid::now_v7().simple().to_string();
            let canary_binding = DesktopVaultCanaryBinding::new(
                &dataset,
                auth.deployment().as_str(),
                auth.tenant().as_str(),
                &key_id,
                KeyVersion::new(1),
            )
            .unwrap();
            let envelope = seal_desktop_vault_canary(
                &master,
                &canary_binding,
                Nonce::from_array([0x33; NONCE_BYTES]),
            )
            .unwrap();
            let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
                &dataset,
                auth.deployment().as_str(),
                auth.tenant().as_str(),
                &key_id,
                envelope.to_column_value(),
            )
            .unwrap();
            desktop_vault_canary::insert_once(database.pool(), &row)
                .await
                .unwrap();
            let proof = desktop_vault_canary::verify_persisted(
                &database,
                &master,
                &dataset,
                auth.deployment().as_str(),
                auth.tenant().as_str(),
                &key_id,
            )
            .await
            .unwrap();
            let registry = Arc::new(
                ArtifactDatasetRegistry::from_desktop(&database, &proof)
                    .await
                    .unwrap(),
            );
            let binding = Arc::new(
                PostgresModelDatasetBinding::unbound(
                    database.clone_pool(),
                    auth.deployment().clone(),
                    auth.tenant().clone(),
                )
                .unwrap(),
            );
            binding.enroll_original_registry(&registry).unwrap();
            let client = database.pool().get().await.unwrap();
            client.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('lineage-bot','Owned lineage bot','built_in','{\"systemPrompt\":\"Owned physical lineage fixture\",\"providerSource\":\"managed\"}')").await.unwrap();
            client.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('lineage-bot',$1,'Owned lineage bot','','owned','public')",&[&auth.actor().as_str()]).await.unwrap();
            drop(client);
            let models = PostgresModelConnections::new(
                database.clone_pool(),
                CredentialRecordVault::single_key(
                    auth.tenant().clone(),
                    KeyVersion::new(1),
                    WrappingKey::from_bytes(vec![0x61; 32]).unwrap(),
                ),
                auth.deployment().clone(),
                auth.tenant().clone(),
                SecretBytes::new(vec![0x62; 32]),
            )
            .unwrap();
            let model = models
                .create(
                    &auth,
                    &CreateModelConnection {
                        name: "Owned physical lineage choice".into(),
                        protocol: CustomModelProtocol::OpenaiChatCompletions,
                        endpoint: "https://owned-v2-lineage.example.test/v1".into(),
                        model: "owned-lineage-model".into(),
                        enabled: true,
                        api_key: ModelApiKey::new(Zeroizing::new(
                            "OWNED_LINEAGE_SYNTHETIC_KEY".into(),
                        ))
                        .unwrap(),
                    },
                )
                .await
                .unwrap();
            drop(models);
            let directory = PostgresThreadDirectory::with_runtime(
                database.clone_pool(),
                cluster.config(APP_DATABASE),
                "owned-original-lineage-runtime".into(),
                time::Duration::seconds(30),
            )
            .unwrap()
            .with_model_dataset_binding(binding.clone())
            .unwrap();
            Self {
                cluster,
                database,
                proof,
                registry,
                binding,
                directory,
                auth,
                model,
                master,
            }
        }

        fn request(&self, number: u64) -> BeginThreadRunV2Request {
            let mut entropy = [0u8; 16];
            entropy[8..].copy_from_slice(&number.to_be_bytes());
            BeginThreadRunV2Request {
                deployment: self.auth.deployment().clone(),
                tenant: self.auth.tenant().clone(),
                actor: self.auth.actor().clone(),
                auth_generation: self.auth.auth_generation(),
                command: BeginThreadRunV2 {
                    artifact_refs: Vec::new(),
                    thread_id: ThreadIdentity::new(self.auth.deployment())
                        .mint_from_entropy(entropy),
                    run_id: RunId::new(format!("owned-lineage-run-{number}")),
                    bot_id: BotId::new("lineage-bot"),
                    anchor: ThreadRunAnchor::DirectBot,
                    message: "Owned physical replacement must be refused".into(),
                    selected_skill_slugs: vec![],
                    model_selection: RunModelSelectionV2::new(
                        ModelSelectionIntentSource::Custom,
                        self.model.id.clone(),
                        self.model.revision,
                        format!("custom:{}", self.model.id),
                        1,
                    )
                    .unwrap(),
                },
            }
        }

        async fn positive(&self) {
            assert!(self.proof.matches_database(&self.database).await.unwrap());
            let receipt = self
                .directory
                .begin_thread_run_v2(self.request(1))
                .await
                .unwrap();
            assert!(!receipt.replayed);
            let client = self.database.pool().get().await.unwrap();
            let row=client.query_one("SELECT s.dataset_id,s.dataset_binding_schema,s.dataset_initial_origin,s.dataset_binding_created_at,d.created_at FROM openbot_internal.run_model_selection_v2_snapshots s JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=s.deployment_id AND d.tenant_id=s.tenant_id WHERE s.run_id=$1",&[&self.request(1).command.run_id.as_str()]).await.unwrap();
            assert_eq!(
                row.get::<_, String>(0),
                self.registry.binding().dataset_id()
            );
            assert_eq!(row.get::<_, i16>(1), 1);
            assert_eq!(row.get::<_, String>(2), "desktop_canary");
            assert_eq!(
                row.get::<_, time::OffsetDateTime>(3),
                row.get::<_, time::OffsetDateTime>(4)
            );
        }

        async fn refuse_second_real_owner_and_manager(&self) {
            let original_owner = self.database.owner_token();
            let original_physical = identity(self.database.pool()).await;
            let before = durable_image(self.database.pool()).await;
            let admin = connect_for_attestation(
                self.cluster.port,
                SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()),
            )
            .await
            .unwrap();
            let admin_observations = admin.pool().connection_observations();
            assert!(!admin_observations.is_empty());
            let admin_observed = admin_observations.len();
            let admin = self
                .cluster
                .installation
                .attest_postgres_admin(admin)
                .await
                .unwrap();
            let second = admin.connect_application(false).await.unwrap();
            let second_owner = second.owner_token();
            assert!(!Arc::ptr_eq(&original_owner, &second_owner));
            assert!(!second.owns_token(&original_owner));
            assert!(!self.database.owns_token(&second_owner));
            assert!(!std::ptr::eq(
                second.pool().manager(),
                self.database.pool().manager()
            ));
            assert_eq!(identity(second.pool()).await, original_physical);
            assert_eq!(durable_image(second.pool()).await, before);
            assert!(!self.proof.matches_database(&second).await.unwrap());
            assert!(matches!(
                ArtifactDatasetRegistry::from_desktop(&second, &self.proof).await,
                Err(ArtifactRegistryError::Corrupt {
                    field: "desktop_proof"
                })
            ));
            assert!(!self.binding.matches_pool_scope(
                second.pool(),
                self.auth.deployment(),
                self.auth.tenant()
            ));
            assert_eq!(durable_image(self.database.pool()).await, before);
            let second_observed = second.pool().connection_observations().len();
            assert!(second_observed > 0);
            close_owned_pool(second.pool()).await;
            let deadline = Instant::now() + Duration::from_secs(10);
            for observation in admin_observations {
                assert_eq!(
                    observation
                        .wait_for_destruction_before(deadline)
                        .await
                        .unwrap(),
                    ConnectionDestruction::ConnectionDestroyed
                );
            }
            assert!(!self.database.pool().is_closed());
            assert!(self.database.owns_token(&original_owner));
            assert!(self.proof.matches_database(&self.database).await.unwrap());
            assert!(self.binding.matches_pool_scope(
                self.database.pool(),
                self.auth.deployment(),
                self.auth.tenant()
            ));
            assert!(Arc::ptr_eq(
                &self.binding.original_registry().unwrap(),
                &self.registry
            ));
            eprintln!(
                "CUSTOM_V2_LINEAGE_SECOND_OWNER same_actual_system_and_oid=true different_actual_owner_and_manager=true old_proof_refused=true original_binding_foreign_pool_refused=true business_image_unchanged=true second_pool_connections={second_observed} factory_admin_connections={admin_observed} all_observed_original_connections_destroyed=true original_consumer_still_current=true"
            );
        }

        async fn capture_original(&self) -> OriginalLineage {
            OriginalLineage {
                database_owner: self.database.owner_token(),
                pool: self.database.clone_pool(),
                registry: self.binding.original_registry().unwrap(),
                registry_owner: self.registry.owner(),
                physical: identity(self.database.pool()).await,
                image: durable_image(self.database.pool()).await,
            }
        }

        async fn refuse_replacement(&self, original: &OriginalLineage, same_system: bool) {
            let original_pool = &original.pool;
            assert!(!original_pool.is_closed());
            assert!(self.database.owns_token(&original.database_owner));
            assert!(std::ptr::eq(
                original_pool.manager(),
                self.binding.pool.manager()
            ));
            assert!(std::ptr::eq(
                original_pool.manager(),
                self.database.pool().manager()
            ));
            assert!(self.binding.matches_pool_scope(
                original_pool,
                self.auth.deployment(),
                self.auth.tenant()
            ));
            assert!(Arc::ptr_eq(
                &self.binding.original_registry().unwrap(),
                &original.registry
            ));
            assert!(Arc::ptr_eq(&original.registry, &self.registry));
            assert!(Arc::ptr_eq(
                &original.registry_owner,
                &self.registry.owner()
            ));
            // Independently require all original layout predicates and crypto to remain valid.
            // Therefore neither a schema mismatch nor a wrong-owner shortcut stands in for ID.
            verify_artifact_registry_schema(original_pool)
                .await
                .unwrap();
            desktop_vault_canary::verify_current_layout(original_pool)
                .await
                .unwrap();
            let current = identity(original_pool).await;
            eprintln!(
                "CUSTOM_V2_LINEAGE_PHYSICAL_ID original_system_identifier={} current_system_identifier={} original_database_oid={} current_database_oid={}",
                original.physical.0, current.0, original.physical.1, current.1
            );
            if same_system {
                assert_eq!(current.0, original.physical.0);
                assert_ne!(current.1, original.physical.1);
            } else {
                assert_ne!(current.0, original.physical.0);
            }
            let row = desktop_vault_canary::read(
                original_pool,
                self.auth.deployment().as_str(),
                self.auth.tenant().as_str(),
            )
            .await
            .unwrap()
            .unwrap();
            let crypto_binding = DesktopVaultCanaryBinding::new(
                row.dataset_id(),
                row.deployment_id(),
                row.tenant_id(),
                row.key_id(),
                KeyVersion::new(u32::try_from(row.key_version()).unwrap()),
            )
            .unwrap();
            let envelope = DesktopVaultCanaryEnvelope::parse(row.encrypted_canary()).unwrap();
            open_desktop_vault_canary(&self.master, &crypto_binding, &envelope).unwrap();
            assert!(self.database.owns_token(&original.database_owner));
            assert!(!self.proof.matches_database(&self.database).await.unwrap());
            let before = durable_image(original_pool).await;
            assert_eq!(before, original.image);
            assert!(matches!(
                self.directory.begin_thread_run_v2(self.request(2)).await,
                Err(ThreadDirectoryError::Corrupt {
                    field: "model_dataset_binding"
                })
            ));
            assert_eq!(durable_image(original_pool).await, before);
            assert!(!original_pool.is_closed());
            assert!(self.database.owns_token(&original.database_owner));
            assert!(Arc::ptr_eq(
                &self.binding.original_registry().unwrap(),
                &original.registry
            ));
            eprintln!(
                "CUSTOM_V2_LINEAGE_REFUSAL same_original_manager=true same_original_database_owner=true same_original_registry=true original_crypto_valid=true original_schema_valid=true actual_system_equal={same_system} new_business_rows=0 TLS_fixture=absent"
            );
        }

        async fn finish(&mut self) {
            close_owned_pool(self.database.pool()).await;
            self.cluster.finish().await;
        }
    }

    async fn end_original_database_backends(admin: &DatabasePool) {
        let client = admin.get().await.unwrap();
        let rows=client.query("SELECT pid,application_name FROM pg_catalog.pg_stat_activity WHERE datname='openbot' AND pid<>pg_backend_pid()",&[]).await.unwrap();
        for row in rows {
            let pid: i32 = row.get(0);
            let application: String = row.get(1);
            assert!(
                application == "openbot-desktop-local"
                    || application.starts_with("openbot-v2-lineage")
            );
            assert!(pid > 1);
            assert!(
                client
                    .query_one("SELECT pg_catalog.pg_terminate_backend($1,5000)", &[&pid])
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let count: i64 = client
                .query_one(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname='openbot'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if count == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned template connections did not end"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires Source-owned PG17 physical replacement tools and desktop-tmp"]
    async fn original_desktop_oid_replacement_preserves_manager_and_refuses_v2_accept() {
        let mut fixture = ModelFixture::new().await;
        fixture.refuse_second_real_owner_and_manager().await;
        fixture.positive().await;
        let original = fixture.capture_original().await;
        let admin = pool::connect(&fixture.cluster.config("postgres"))
            .await
            .unwrap();
        end_original_database_backends(&admin).await;
        let client = admin.get().await.unwrap();
        client
            .batch_execute(
                "CREATE DATABASE openbot_v2_replacement WITH TEMPLATE=openbot OWNER=desktop_admin",
            )
            .await
            .unwrap();
        client
            .batch_execute("ALTER DATABASE openbot RENAME TO openbot_v2_previous")
            .await
            .unwrap();
        client
            .batch_execute("ALTER DATABASE openbot_v2_replacement RENAME TO openbot")
            .await
            .unwrap();
        drop(client);
        assert!(std::ptr::eq(
            original.pool.manager(),
            fixture.database.pool().manager()
        ));
        assert!(fixture.database.owns_token(&original.database_owner));
        assert_eq!(durable_image(fixture.database.pool()).await, original.image);
        fixture.refuse_replacement(&original, true).await;
        close_owned_pool(&admin).await;
        fixture.finish().await;
    }

    #[tokio::test]
    #[ignore = "requires Source-owned PG17 pg_dump/pg_restore and desktop-tmp"]
    async fn original_desktop_system_identifier_replacement_preserves_manager_and_refuses_v2_accept()
     {
        let mut fixture = ModelFixture::new().await;
        fixture.positive().await;
        let original = fixture.capture_original().await;
        let dump = fixture.cluster.app_root.join("owned-original-db.dump");
        let mut command = fixture.cluster.command("pg_dump");
        command
            .args([
                "--format=custom",
                "--lock-wait-timeout=5s",
                "--dbname=openbot",
            ])
            .arg("--file")
            .arg(&dump);
        run_tool(command, "dump").await;
        let dump_metadata = fs::symlink_metadata(&dump).unwrap();
        assert!(dump_metadata.is_file() && !dump_metadata.file_type().is_symlink());
        assert!(dump_metadata.len() > 0 && dump_metadata.len() <= 16 * 1024 * 1024);
        fixture.cluster.stop().await;
        // The original manager is intentionally left open; no new Desktop database owner or
        // new proof is installed. Its ended connections reconnect to this controlled endpoint.
        assert!(!original.pool.is_closed());
        let mut replacement = OwnedCluster::start(Some(fixture.cluster.port)).await;
        assert_ne!(replacement.postmaster_pid, fixture.cluster.postmaster_pid);
        let admin = pool::connect(&replacement.config("postgres"))
            .await
            .unwrap();
        let client = admin.get().await.unwrap();
        client.batch_execute("CREATE DATABASE openbot WITH OWNER=desktop_admin TEMPLATE=template0 ENCODING='UTF8' LC_COLLATE='C' LC_CTYPE='C'").await.unwrap();
        drop(client);
        let mut command = replacement.command("pg_restore");
        command
            .args(["--exit-on-error", "--no-owner", "--dbname=openbot"])
            .arg(&dump);
        run_tool(command, "restore").await;
        // Reparse the original BETWEEN syntax for this owned fixture's one CHECK.
        // pg_dump's deparsed >=/<= form flattens its leading AND on restore.
        let identity_bounds = include_str!("../sql/native_0035.sql")
            .split_once("    CONSTRAINT remember_effect_receipts_identity_bounds CHECK (\n")
            .unwrap()
            .1
            .split_once("\n    ),\n")
            .unwrap()
            .0;
        let mut client = original.pool.get().await.unwrap();
        let transaction = client.transaction().await.unwrap();
        transaction
            .batch_execute(&format!(
                "ALTER TABLE public.remember_effect_receipts \
                 DROP CONSTRAINT remember_effect_receipts_identity_bounds; \
                 ALTER TABLE public.remember_effect_receipts \
                 ADD CONSTRAINT remember_effect_receipts_identity_bounds \
                 CHECK ({identity_bounds});"
            ))
            .await
            .unwrap();
        // Replay the three original internal BETWEEN CHECKs for this owned fixture.
        let internal_schema = include_str!("../sql/native_0041.sql");
        for constraint in [
            "artifact_dataset_bindings_deployment_shape",
            "artifact_dataset_bindings_tenant_shape",
            "artifact_dataset_bindings_dataset_shape",
        ] {
            let anchor = format!("    CONSTRAINT {constraint} CHECK (\n");
            assert_eq!(internal_schema.matches(anchor.as_str()).count(), 1);
            let predicate = internal_schema
                .split_once(anchor.as_str())
                .unwrap()
                .1
                .split_once("\n    ),\n")
                .unwrap()
                .0;
            transaction
                .batch_execute(&format!(
                    "ALTER TABLE openbot_internal.artifact_dataset_bindings \
                     DROP CONSTRAINT {constraint}; \
                     ALTER TABLE openbot_internal.artifact_dataset_bindings \
                     ADD CONSTRAINT {constraint} CHECK ({predicate});"
                ))
                .await
                .unwrap();
        }
        // Replay the two original V2 snapshot BETWEEN CHECKs for this owned fixture.
        let snapshot_schema = include_str!("../sql/native_0047.sql");
        for constraint in [
            "run_model_selection_v2_snapshots_scope_check",
            "run_model_selection_v2_snapshots_dataset_id_check",
        ] {
            let anchor = format!("    CONSTRAINT {constraint}\n        CHECK (");
            assert_eq!(snapshot_schema.matches(anchor.as_str()).count(), 1);
            let predicate = snapshot_schema
                .split_once(anchor.as_str())
                .unwrap()
                .1
                .split_once("),\n    CONSTRAINT ")
                .unwrap()
                .0;
            transaction
                .batch_execute(&format!(
                    "ALTER TABLE openbot_internal.run_model_selection_v2_snapshots \
                     DROP CONSTRAINT {constraint}; \
                     ALTER TABLE openbot_internal.run_model_selection_v2_snapshots \
                     ADD CONSTRAINT {constraint} CHECK ({predicate});"
                ))
                .await
                .unwrap();
        }
        transaction.commit().await.unwrap();
        drop(client);
        assert!(std::ptr::eq(
            original.pool.manager(),
            fixture.database.pool().manager()
        ));
        assert!(fixture.database.owns_token(&original.database_owner));
        assert_eq!(durable_image(fixture.database.pool()).await, original.image);
        fixture.refuse_replacement(&original, false).await;
        close_owned_pool(&admin).await;
        fixture.finish().await;
        replacement.finish().await;
    }
}
