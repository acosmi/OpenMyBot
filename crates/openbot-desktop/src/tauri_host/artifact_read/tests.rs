//! Actual installation, live numeric-loopback/SCRAM sidecar, persisted Vault canary proof,
//! original Window/Local source, actual Application/PG/FS and Rust-only chunk handoff.
//! Test-owned process launch does not certify the release supervisor, UI or Keychain.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use async_trait::async_trait;
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest,
    CurrentArtifactReadChunk, OpenBotApplication, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{BotId, RunId};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    seal_desktop_vault_canary,
};
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
use openbot_infra::db::desktop_vault_canary;
use openbot_infra::db::{fresh, pool};
use openbot_infra::repo::channels::ChannelRepo;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_listener::ThreadListenerDatabase;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TEXT: &str = "  OWNED_CURRENT_BINDING_ARTIFACT_CANARY\n成果 café 🦀\t  ";
const SHA256: &str = "67f316d58f706da6dce7dd1f9c20937d723ebf772a24fa9298f8da6e402eefb2";
fn require(value: bool, error: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(error.to_owned()) }
}

const TEST_USER: &str = "desktop_admin";
const TEST_PASSWORD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn postgres_binary(name: &str) -> Result<PathBuf, String> {
    let directory = std::env::var_os("OPENBOT_TEST_PG_BIN")
        .map(PathBuf::from)
        .ok_or_else(|| "owned runner must set OPENBOT_TEST_PG_BIN".to_owned())?;
    if !directory.is_absolute() {
        return Err(
            "OPENBOT_TEST_PG_BIN must be an absolute owned test binary directory".to_owned(),
        );
    }
    let binary = directory.join(name);
    if !binary.is_file() {
        return Err(format!("owned PostgreSQL binary missing: {name}"));
    }
    Ok(binary)
}

fn run(command: &mut Command, phase: &'static str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|_| format!("{phase}: process unavailable"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{phase}: exit={:?}", output.status.code()))
    }
}

fn mutate_owned_read_only_file<M, E>(
    path: &std::path::Path,
    mutation: M,
    expected: E,
) -> Result<(), String>
where
    M: FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    E: FnOnce(&[u8], &[u8]) -> bool,
{
    let original = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        original.is_file() && original.mode() & 0o7777 == 0o400 && original.nlink() == 1,
        "owned mutation requires the original regular0400 single-link file",
    )?;
    let anchor = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let anchored = anchor.metadata().map_err(|error| error.to_string())?;
    require(
        anchored.is_file()
            && anchored.dev() == original.dev()
            && anchored.ino() == original.ino()
            && anchored.uid() == original.uid()
            && anchored.mode() & 0o7777 == 0o400
            && anchored.nlink() == 1,
        "owned mutation read FD is not the original0400 inode",
    )?;
    let mut before = Vec::new();
    (&anchor)
        .read_to_end(&mut before)
        .map_err(|error| error.to_string())?;
    struct RestoreReadOnly<'a> {
        file: &'a std::fs::File,
        armed: bool,
    }
    impl Drop for RestoreReadOnly<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = self
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o400));
                let _ = self.file.sync_all();
            }
        }
    }
    let mut restore = RestoreReadOnly {
        file: &anchor,
        armed: true,
    };
    anchor
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let writable = writer.metadata().map_err(|error| error.to_string())?;
    require(
        writable.is_file()
            && writable.dev() == original.dev()
            && writable.ino() == original.ino()
            && writable.uid() == original.uid()
            && writable.mode() & 0o7777 == 0o600
            && writable.nlink() == 1,
        "owned mutation write FD is not the original temporary0600 inode",
    )?;
    let mutation_result = mutation(&mut writer, &before);
    let mutation_sync = writer.sync_all();
    // Restore even when mutation or its sync failed; the anchored guard also covers early errors.
    let restored = writer.set_permissions(std::fs::Permissions::from_mode(0o400));
    let restore_sync = writer.sync_all();
    if restored.is_ok() && restore_sync.is_ok() {
        restore.armed = false;
    }
    restored.map_err(|error| error.to_string())?;
    restore_sync.map_err(|error| error.to_string())?;
    let actual = writer.metadata().map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        actual.is_file()
            && installed.is_file()
            && actual.dev() == original.dev()
            && actual.ino() == original.ino()
            && actual.uid() == original.uid()
            && installed.dev() == original.dev()
            && installed.ino() == original.ino()
            && actual.mode() & 0o7777 == 0o400
            && installed.mode() & 0o7777 == 0o400
            && actual.nlink() == 1
            && installed.nlink() == 1,
        "owned mutation did not restore original inode and0400 permissions",
    )?;
    mutation_result.map_err(|error| error.to_string())?;
    mutation_sync.map_err(|error| error.to_string())?;
    (&anchor)
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut after = Vec::new();
    (&anchor)
        .read_to_end(&mut after)
        .map_err(|error| error.to_string())?;
    require(
        before != after && expected(&before, &after),
        "owned mutation did not cause exact real byte drift",
    )
}

/// 只清理本测试 create_new 的路径，先停自己的 PG；不接触用户目录。
struct OwnedSidecar {
    pg_ctl: PathBuf,
    app_root: PathBuf,
    data_dir: PathBuf,
    socket_dir: PathBuf,
    socket_created: bool,
    started: bool,
    postmaster_pid: Option<u32>,
}

impl OwnedSidecar {
    fn read_owned_postmaster_pid(&self) -> Result<u32, String> {
        let content = fs::read_to_string(self.data_dir.join("postmaster.pid"))
            .map_err(|_| "read owned postmaster.pid failed".to_owned())?;
        content
            .lines()
            .next()
            .and_then(|line| line.parse::<u32>().ok())
            .filter(|pid| *pid > 1 && *pid <= i32::MAX as u32)
            .ok_or_else(|| "owned postmaster PID is not a positive process identity".to_owned())
    }

    fn stop_verified(&mut self) -> Result<u32, String> {
        let pid = self
            .postmaster_pid
            .map_or_else(|| self.read_owned_postmaster_pid(), Ok)?;
        if self.read_owned_postmaster_pid()? != pid {
            return Err("owned postmaster.pid changed before stop".to_owned());
        }
        // success() means actual exit 0; no Drop result stands in for this acceptance.
        run(
            Command::new(&self.pg_ctl)
                .arg("-D")
                .arg(&self.data_dir)
                .args(["-t", "15", "-m", "fast", "-w", "stop"]),
            "owned pg_ctl stop",
        )?;
        match fs::symlink_metadata(self.data_dir.join("postmaster.pid")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(
                    "owned postmaster.pid remains or cannot be observed after stop".to_owned(),
                );
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // Signal 0 only queries the PID captured from this test's own PG data directory.
            // Require ESRCH text in a fixed locale; EPERM or a missing tool proves nothing.
            let probe = Command::new("/bin/kill")
                .env("LC_ALL", "C")
                .args(["-0", &pid.to_string()])
                .output()
                .map_err(|_| "query owned stopped PID failed".to_owned())?;
            if probe.status.code() == Some(1)
                && String::from_utf8_lossy(&probe.stderr).contains("No such process")
            {
                break;
            }
            if !probe.status.success() || std::time::Instant::now() >= deadline {
                return Err(
                    "owned old postmaster PID is still present or absence was not proved"
                        .to_owned(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        self.started = false;
        Ok(pid)
    }

    fn cleanup_owned_paths(&mut self) -> Result<(), String> {
        match fs::remove_dir_all(&self.app_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("remove owned stopped app root failed".to_owned()),
        }
        if self.socket_created {
            match fs::remove_dir_all(&self.socket_dir) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("remove owned stopped socket root failed".to_owned()),
            }
            self.socket_created = false;
        }
        Ok(())
    }

    fn finish(&mut self, test: &'static str) -> Result<(), String> {
        if !self.started {
            return Err("owned successful fixture must explicitly stop its started PG".to_owned());
        }
        let pid = self.stop_verified()?;
        self.cleanup_owned_paths()?;
        println!(
            "artifact_read_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
        );
        Ok(())
    }
}

impl Drop for OwnedSidecar {
    fn drop(&mut self) {
        // Failed tests/startups retain this best-effort fallback. A successful test must use
        // explicit finish, and only that path emits its acceptance receipt.
        let stopped = !self.started || self.stop_verified().is_ok();
        if stopped {
            let _ = self.cleanup_owned_paths();
        }
    }
}

struct OwnedDesktop {
    database: DesktopLocalDatabase,
    installation: DesktopLocalInstallation,
    port: u16,
    _sidecar: OwnedSidecar,
}

impl OwnedDesktop {
    fn finish(mut self, test: &'static str) -> Result<(), String> {
        self.database.close();
        self._sidecar.finish(test)
    }
}

fn append_postgres_config(data_dir: &Path, socket_dir: &Path, port: u16) -> Result<(), String> {
    let socket = socket_dir
        .to_str()
        .filter(|s| !s.contains('\''))
        .ok_or_else(|| "owned socket path is not a safe setting".to_owned())?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(data_dir.join("postgresql.conf"))
        .map_err(|_| "open owned postgresql.conf failed".to_owned())?;
    writeln!(file, "\nlisten_addresses = '127.0.0.1'\ntrack_activity_query_size=16384\nlog_lock_waits=on\ndeadlock_timeout=\'25ms\'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700")
        .map_err(|_| "write owned postgresql.conf failed".to_owned())?;
    file.sync_all()
        .map_err(|_| "sync owned postgresql.conf failed".to_owned())
}

async fn start_owned_desktop() -> Result<OwnedDesktop, String> {
    let pg_ctl = postgres_binary("pg_ctl")?;
    let initdb = postgres_binary("initdb")?;
    let id = uuid::Uuid::now_v7().simple().to_string();
    let app_root = std::env::temp_dir().join(format!("openbot-binding-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obbind-{id}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&app_root)
        .map_err(|_| "create owned app root failed".to_owned())?;
    let mut sidecar = OwnedSidecar {
        pg_ctl,
        data_dir: app_root.join("not-started"),
        app_root,
        socket_dir,
        socket_created: false,
        started: false,
        postmaster_pid: None,
    };
    let store = DesktopLocalAuthorityStore::new(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&sidecar.app_root)
            .map_err(|e| e.to_string())?,
    );
    let installation = store
        .load_or_create_installation()
        .map_err(|e| e.to_string())?;
    sidecar.data_dir = installation.sidecar_data_dir().to_owned();
    let password_file = sidecar.app_root.join(".test-postgres-password");
    let mut password = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&password_file)
        .map_err(|_| "create owned initdb credential failed".to_owned())?;
    writeln!(password, "{TEST_PASSWORD}")
        .map_err(|_| "write owned initdb credential failed".to_owned())?;
    password
        .sync_all()
        .map_err(|_| "sync owned initdb credential failed".to_owned())?;
    drop(password);
    run(
        Command::new(initdb)
            .arg("--pgdata")
            .arg(&sidecar.data_dir)
            .arg(format!("--username={TEST_USER}"))
            .arg("--pwfile")
            .arg(&password_file)
            .args([
                "--auth-host=scram-sha-256",
                "--auth-local=trust",
                "--encoding=UTF8",
                "--no-locale",
            ]),
        "initdb",
    )?;
    fs::remove_file(password_file)
        .map_err(|_| "remove owned initdb credential failed".to_owned())?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&sidecar.socket_dir)
        .map_err(|_| "create owned socket root failed".to_owned())?;
    sidecar.socket_created = true;
    let probe = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "allocate owned loopback port failed".to_owned())?;
    let port = probe
        .local_addr()
        .map_err(|_| "read owned loopback port failed".to_owned())?
        .port();
    drop(probe);
    append_postgres_config(&sidecar.data_dir, &sidecar.socket_dir, port)?;
    sidecar.started = true;
    run(
        Command::new(&sidecar.pg_ctl)
            .arg("-D")
            .arg(&sidecar.data_dir)
            .arg("-l")
            .arg(sidecar.app_root.join("postgres.log"))
            .args(["-w", "start"]),
        "pg_ctl start",
    )?;
    sidecar.postmaster_pid = Some(sidecar.read_owned_postmaster_pid()?);
    let admin = connect_for_attestation(port, SecretBytes::new(TEST_PASSWORD.as_bytes().to_vec()))
        .await
        .map_err(|e| e.to_string())?;
    let admin = installation
        .attest_postgres_admin(admin)
        .await
        .map_err(|e| e.to_string())?;
    let database = admin
        .connect_application(true)
        .await
        .map_err(|e| e.to_string())?;
    let mut c = database.pool().get().await.map_err(|e| e.to_string())?;
    fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
    drop(c);
    Ok(OwnedDesktop {
        database,
        installation,
        port,
        _sidecar: sidecar,
    })
}

struct CountActualArtifactPort {
    actual: Arc<PostgresArtifactAdministration>,
    reads: AtomicUsize,
    pending_gate: Mutex<Option<Arc<PendingGate>>>,
}
#[async_trait]
impl ArtifactAdministration for CountActualArtifactPort {
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.actual.save_run_message_text(auth, input).await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let gate = self
            .pending_gate
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?
            .take();
        let pending = self.actual.read_host_bound_chunk(auth, id).await?;
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        Ok(pending)
    }
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.actual.get_metadata(auth, id).await
    }
}

struct LocalFixture {
    desktop: OwnedDesktop,
    source: Arc<PostgresLocalConfirmationAuthority>,
    original: AuthContext,
    application: Arc<dyn ApplicationService>,
    port: Arc<CountActualArtifactPort>,
    receipt: ArtifactRegistrationReceipt,
    assets: PathBuf,
    artifact_root: PathBuf,
}
impl LocalFixture {
    async fn new() -> Result<Self, String> {
        let desktop = start_owned_desktop().await?;
        let database = desktop.database.pool();
        // Actual canonical provisioning is setup-only, after exact live-sidecar attestation and
        // migrations. Runtime checks below never call it or repair the controlled mutations.
        desktop
            .installation
            .authority()
            .provision_postgres(database)
            .await
            .map_err(|e| e.to_string())?;
        let original = desktop
            .installation
            .authority()
            .load_runtime_auth_context(database)
            .await
            .map_err(|e| e.to_string())?;
        require(
            original.auth_generation().get() == 0 && original.is_single_user(),
            "actual fresh Local canonical principal was not generation zero",
        )?;
        let dataset = "d".repeat(32);
        let key_id = "b".repeat(32);
        let master = SecretBytes::new(vec![0x5a; 32]);
        let binding = DesktopVaultCanaryBinding::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            KeyVersion::new(1),
        )
        .map_err(|e| e.to_string())?;
        let envelope =
            seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x33; NONCE_BYTES]))
                .map_err(|e| e.to_string())?;
        let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            envelope.to_column_value(),
        )
        .map_err(|e| e.to_string())?;
        desktop_vault_canary::insert_once(database, &row)
            .await
            .map_err(|e| e.to_string())?;
        let proof = desktop_vault_canary::verify_persisted(
            &desktop.database,
            &master,
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
        )
        .await
        .map_err(|e| e.to_string())?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_desktop(&desktop.database, &proof)
                .await
                .map_err(|e| e.to_string())?,
        );
        {
            let c = database.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('local-binding-bot','Binding fixture','built_in','{}')").await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000005',$1,'fixture','fixture')",&[&original.tenant().as_str()]).await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('local-binding-bot',$1,'Binding fixture','fixture','fixture','public')",&[&original.actor().as_str()]).await.map_err(|e|e.to_string())?;
        }
        let begin = BeginThreadRunRequest {
            deployment: original.deployment().clone(),
            tenant: original.tenant().clone(),
            actor: original.actor().clone(),
            auth_generation: original.auth_generation(),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(original.deployment()).mint_from_entropy([6; 16]),
                run_id: RunId::new("actual/local-binding-run%成果"),
                bot_id: BotId::new("local-binding-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let listener =
            ThreadListenerDatabase::desktop_local(desktop.port, TEST_PASSWORD.as_bytes())
                .map_err(|e| e.to_string())?;
        PostgresThreadDirectory::with_runtime(
            database.clone(),
            listener,
            "local-binding-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let artifact_root = desktop._sidecar.app_root.join("artifacts");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&artifact_root)
            .map_err(|e| e.to_string())?;
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                fs::File::open(&artifact_root).map_err(|e| e.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x75; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let receipt = actual
            .save_run_message_text(
                &original,
                SaveRunMessageTextArtifact {
                    request_id: uuid::Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id.clone(),
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: SHA256.to_owned(),
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let port = Arc::new(CountActualArtifactPort {
            actual,
            reads: AtomicUsize::new(0),
            pending_gate: Mutex::new(None),
        });
        // The selected real OpenBotApplication uses its production metadata use case and actual
        // artifact repository. Other uninvolved adapters are unavailable, never canned replies.
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(ChannelRepo::new(database.clone()))
                .with_artifacts(port.clone()),
        );
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            database.clone(),
        ));
        source
            .install_artifact_read_authority(&port.actual.read_authority())
            .map_err(|_| "actual same-Pool Local authority enrollment refused".to_owned())?;
        let assets = desktop._sidecar.app_root.join("assets");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|e| e.to_string())?;
        fs::write(assets.join("index.html"),"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e|e.to_string())?;
        fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").map_err(|e| e.to_string())?;
        Ok(Self {
            desktop,
            source,
            original,
            application,
            port,
            receipt,
            assets,
            artifact_root,
        })
    }
    fn pool(&self) -> &pool::DatabasePool {
        self.desktop.database.pool()
    }
    fn protocol(&self) -> Result<DesktopTauriProtocol, String> {
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map(|protocol| protocol.with_current_identity_source(self.source.clone()))
        .map_err(|e| e.to_string())
    }
    fn bound_auth(
        &self,
        protocol: &DesktopTauriProtocol,
        label: &str,
    ) -> Result<AuthContext, String> {
        protocol
            .windows
            .read()
            .map_err(|_| "actual Local window map unreadable")?
            .get(label)
            .map(|authority| authority.auth.clone())
            .ok_or_else(|| "actual Local window map entry missing".to_owned())
    }
    fn pending_gate(&self) -> Result<Arc<PendingGate>, String> {
        let gate = Arc::new(PendingGate {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *self
            .port
            .pending_gate
            .lock()
            .map_err(|_| "pending gate poisoned".to_owned())? = Some(gate.clone());
        Ok(gate)
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool()
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|error| error.to_string())
    }
    fn finish(self, test: &'static str) -> Result<(), String> {
        drop(self.application);
        drop(self.port);
        drop(self.source);
        self.desktop.finish(test)
    }
}
struct PendingGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
type FixtureFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;
async fn with_fixture<F>(name: &'static str, body: F)
where
    F: for<'a> FnOnce(&'a LocalFixture) -> FixtureFuture<'a>,
{
    let fixture = LocalFixture::new()
        .await
        .unwrap_or_else(|error| panic!("{name} actual Local setup failed: {error}"));
    let outcome = body(&fixture).await;
    let cleanup = fixture.finish(name);
    outcome.unwrap_or_else(|error| panic!("{name} failed: {error}"));
    cleanup.unwrap_or_else(|error| panic!("{name} actual owned stop/cleanup failed: {error}"));
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_canary_window_application_and_protocol_release_exact_first_chunk() {
    with_fixture("local_read_positive", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let body = protocol
                .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                body == TEXT.as_bytes(),
                "actual Local protocol did not return original artifact bytes",
            )?;
            require(
                fixture.port.reads.load(Ordering::SeqCst) == 1,
                "actual Local artifact producer port was not called",
            )?;
            let auth = fixture.bound_auth(&protocol, "main")?;
            let transport = InProcessTransport::new(fixture.application.clone());
            require(
                Arc::ptr_eq(transport.service(), &fixture.application),
                "Local transport did not retain the same ApplicationService",
            )?;
            let pending = transport
                .read_current_artifact_chunk(auth.clone(), fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                pending.handoff(&auth).map_err(|error| error.to_string())? == TEXT.as_bytes(),
                "actual typed Local transport changed current body",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_two_local_protocols_same_label_and_id_one_cannot_exchange_pending_body() {
    with_fixture("local_read_owner_collision", |fixture| {
        Box::pin(async move {
            let a = fixture.protocol()?;
            let b = fixture.protocol()?;
            for protocol in [&a, &b] {
                protocol
                    .bind_window("main", fixture.original.clone(), None)
                    .map_err(|error| error.to_string())?;
            }
            let auth_a = fixture.bound_auth(&a, "main")?;
            let auth_b = fixture.bound_auth(&b, "main")?;
            require(
                auth_a == auth_b,
                "actual collision fixture six facts differed",
            )?;
            require(
                a.windows
                    .read()
                    .map_err(|_| "A map unavailable".to_owned())?["main"]
                    .binding_id
                    == 1
                    && b.windows
                        .read()
                        .map_err(|_| "B map unavailable".to_owned())?["main"]
                        .binding_id
                        == 1,
                "collision fixture did not use original id-one epochs",
            )?;
            let pending = fixture
                .application
                .read_current_artifact_chunk(auth_a, fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                matches!(pending.handoff(&auth_b), Err(AppError::Unauthenticated)),
                "pending body crossed genuine protocol owners",
            )?;
            for protocol in [&a, &b] {
                require(
                    protocol
                        .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                        .await
                        .map_err(|error| error.to_string())?
                        == TEXT.as_bytes(),
                    "a genuine current owner lost its own bytes",
                )?;
            }
            Ok(())
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_current_raw_generation_email_role_and_deny_refuse_without_repair() {
    with_fixture("local_read_current_matrix", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        let mutations = [
            ("UPDATE public.users SET auth_generation=NULL WHERE id='desktop-local-user'", "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'"),
            ("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='desktop-local-user'", "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'; ALTER TABLE public.users ADD CONSTRAINT users_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation>=0)"),
            ("UPDATE public.users SET email='changed-local@example.test' WHERE id='desktop-local-user'", "UPDATE public.users SET email='desktop-local@localhost.invalid' WHERE id='desktop-local-user'"),
            ("UPDATE public.user_roles SET role='user' WHERE user_id='desktop-local-user'", "UPDATE public.user_roles SET role='admin' WHERE user_id='desktop-local-user'"),
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('desktop-local@localhost.invalid','desktop-local-user')", "DELETE FROM public.revoked_access WHERE email='desktop-local@localhost.invalid'"),
        ];
        for (mutation, restore) in mutations {
            fixture.sql(mutation).await?;
            require(matches!(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await, Err(AppError::Unauthenticated)), "changed Local current authority released bytes")?;
            fixture.sql(restore).await?;
            require(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())? == TEXT.as_bytes(), "unmodified original Local authority was repaired/rebound instead of observed")?;
        }
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_rebind_during_last_await_never_receives_original_pending_body() {
    with_fixture("local_read_rebind", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            require(
                protocol
                    .unbind_window("main")
                    .map_err(|error| error.to_string())?,
                "original window was not physically removed",
            )?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::Unauthenticated)
                ),
                "replacement Local window received pending old bytes",
            )?;
            require(
                protocol
                    .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                    .await
                    .map_err(|error| error.to_string())?
                    == TEXT.as_bytes(),
                "new genuine window failed fresh current read",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_protocol_close_during_last_await_refuses_pending_body() {
    with_fixture("local_read_owner_close", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            protocol.close_request_bindings();
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::Unauthenticated)
                ),
                "closed actual protocol released old body",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_last_protocol_drop_does_not_let_pending_witness_retain_real_owner() {
    with_fixture("local_read_last_owner_drop", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let auth = fixture.bound_auth(&protocol, "main")?;
            let pending = fixture
                .application
                .read_current_artifact_chunk(auth.clone(), fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            drop(protocol);
            require(
                matches!(pending.handoff(&auth), Err(AppError::Unauthenticated)),
                "pending witness retained the last actual protocol lease",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_original_fd_mutation_during_last_await_refuses_pending_body() {
    with_fixture("local_read_retained_fd", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            mutate_owned_read_only_file(
                &fixture
                    .artifact_root
                    .join("objects")
                    .join(&fixture.receipt.artifact_id),
                |fd, _| fd.write_all(b"X"),
                |before, after| {
                    before.first() == Some(&b' ')
                        && after.first() == Some(&b'X')
                        && after.len() == before.len()
                        && after[1..] == before[1..]
                },
            )?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::DependencyUnavailable {
                        dependency: "artifacts"
                    })
                ),
                "changed original Local FD released bytes",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_map_contention_refuses_initial_and_pending_handoff() {
    with_fixture("local_read_map_contention", |fixture| {
        Box::pin(async move {
            let protocol = Arc::new(fixture.protocol()?);
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            {
                let _held = OwnedWindowWriteHold::new(&protocol)?;
                require(
                    matches!(
                        protocol
                            .read_current_artifact_chunk(
                                "main",
                                fixture.receipt.artifact_id.clone()
                            )
                            .await,
                        Err(AppError::DependencyUnavailable {
                            dependency: "host_request_binding"
                        })
                    ),
                    "busy map waited or released bytes",
                )?;
                require(
                    fixture.port.reads.load(Ordering::SeqCst) == 0,
                    "initial busy map reached the actual read producer",
                )?;
            }
            let gate = fixture.pending_gate()?;
            let called = protocol.clone();
            let id = fixture.receipt.artifact_id.clone();
            let task =
                tokio::spawn(async move { called.read_current_artifact_chunk("main", id).await });
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .map_err(|_| "actual pending Local chunk not observed".to_owned())?;
            let _held = OwnedWindowWriteHold::new(&protocol)?;
            gate.release.notify_one();
            require(
                matches!(
                    task.await.map_err(|error| error.to_string())?,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "busy original map released pending bytes",
            )
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_window_map_poison_is_unavailable_before_any_read_port() {
    with_fixture("local_read_map_poison", |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|error| error.to_string())?;
            let windows = protocol.windows.clone();
            require(
                std::thread::spawn(move || {
                    let _write = windows.write().unwrap();
                    panic!("controlled owned window-map poison");
                })
                .join()
                .is_err(),
                "actual map was not poisoned",
            )?;
            require(
                matches!(
                    protocol
                        .read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone())
                        .await,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "poisoned original map did not fail closed",
            )?;
            require(
                fixture.port.reads.load(Ordering::SeqCst) == 0,
                "poisoned map reached actual artifact port",
            )
        })
    })
    .await;
}

struct OwnedWindowWriteHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl OwnedWindowWriteHold {
    fn new(protocol: &DesktopTauriProtocol) -> Result<Self, String> {
        let windows = protocol.windows.clone();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _map = windows.write().unwrap();
            entered.send(()).unwrap();
            finish.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        ready
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "owned map write holder did not acquire original map".to_owned())?;
        Ok(Self {
            release: Some(release),
            worker: Some(worker),
        })
    }
}
impl Drop for OwnedWindowWriteHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            assert!(
                worker.join().is_ok(),
                "owned map write holder did not physically finish"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local sidecar"]
async fn actual_local_final_canary_cipher_row_is_rechecked_after_installation_proof() {
    with_fixture("local_read_current_canary", |fixture| Box::pin(async move {
        let protocol = fixture.protocol()?;
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        require(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())? == TEXT.as_bytes(), "original genuine canary could not read")?;
        fixture.sql("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=encrypted_canary||'-controlled-change'").await?;
        require(matches!(protocol.read_current_artifact_chunk("main", fixture.receipt.artifact_id.clone()).await, Err(AppError::Unauthenticated)), "changed current persisted canary was replaced by old proof")
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local final-query Lock/COMMIT ACK"]
async fn actual_local_worker_ack_then_final_joint_wait_observes_current_generation_commit() {
    use tracing::instrument::WithSubscriber as _;
    with_fixture("local_read_real_final_wait", |fixture| Box::pin(async move {

        let protocol = Arc::new(fixture.protocol()?);
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        let mut controller = fixture.pool().get().await.map_err(|error| error.to_string())?;
        let observer = fixture.pool().get().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let observer_pid: i32 = observer.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let activity_capacity_bytes: i64 = observer.query_one(
            "SELECT pg_size_bytes(current_setting('track_activity_query_size'))", &[],
        ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        require(controller_pid != observer_pid, "actual controller and observer PIDs were not distinct")?;
        require(activity_capacity_bytes >= 16_384, "owned Local activity query width was not actually sixteen KiB")?;
        let mut diagnostic = HostReadWaitDiagnostic {
            controller_pid,
            observer_pid,
            activity_capacity_bytes,
            ..HostReadWaitDiagnostic::default()
        };
        let gate = TracePhaseGate::new();
        let dispatch = tracing::Dispatch::new(ReadPhaseSubscriber(gate.clone()));
        let called = protocol.clone();
        let id = fixture.receipt.artifact_id.clone();
        let mut task = Some(tokio::spawn(
            async move { called.read_current_artifact_chunk("main", id).await }.with_subscriber(dispatch),
        ));
        let notification = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await;
        let entered_at = std::time::Instant::now();
        diagnostic.io_seen = gate.io_seen.load(Ordering::SeqCst);
        diagnostic.ready_seen = gate.ready_seen.load(Ordering::SeqCst);
        let mut failure = notification
            .map_err(|_| "actual Local IO/final-ready phases were not observed".to_owned())
            .and_then(|_| require(diagnostic.io_seen && diagnostic.ready_seen, "actual Local worker ACK did not precede final-ready"))
            .err();
        let mut transaction = if failure.is_none() {
            match controller.transaction().await {
                Ok(transaction) => Some(transaction),
                Err(error) => {
                    failure = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        let attempted: Result<i32, String> = if let Some(error) = failure {
            Err(error)
        } else {
            async {
                transaction.as_ref().expect("actual controller transaction retained")
                    .batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|error| error.to_string())?;
                diagnostic.controller_lock_ack = true;
                diagnostic.entered_notification_to_lock_ack_ms = Some(entered_at.elapsed().as_millis());
                diagnostic.barrier_timed_out_before_release = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_before_release = Some(task.as_ref().expect("original reader retained").is_finished());
                require(diagnostic.barrier_timed_out_before_release == Some(false), "Local trace barrier timed out instead of controller release")?;
                gate.release();
                let observed = actual_final_wait(&observer, controller_pid, &mut diagnostic).await;
                diagnostic.barrier_timed_out_after_observation = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_after_observation = Some(task.as_ref().expect("original reader retained").is_finished());
                let waiter = observed?;
                require(diagnostic.barrier_timed_out_after_observation == Some(false), "Local trace barrier timed out instead of controller release")?;
                transaction.as_ref().expect("actual controller transaction retained")
                    .execute("UPDATE public.users SET auth_generation=NULL WHERE id=$1", &[&fixture.original.actor().as_str()]).await.map_err(|error| error.to_string())?;
                transaction.take().expect("actual controller transaction retained")
                    .commit().await.map_err(|error| error.to_string())?;
                diagnostic.controller_commit_ack = true;
                Ok(waiter)
            }.await
        };
        gate.release();
        if let Some(transaction) = transaction.take() {
            diagnostic.controller_rollback_attempted = true;
            diagnostic.controller_rollback_ack = transaction.rollback().await.is_ok();
        }
        let joined = task.take().expect("original reader retained").await;
        let read_result = match joined {
            Ok(result) => {
                diagnostic.reader_join_ack = true;
                diagnostic.reader_join_outcome = Some("read_result");
                diagnostic.reader_terminal_class = Some(host_read_terminal_class(&result));
                Ok(result)
            }
            Err(error) => {
                let (closed, failure) = if error.is_panic() {
                    ("read_task_panicked", "actual read task panicked")
                } else {
                    ("read_task_cancelled", "actual read task was cancelled")
                };
                diagnostic.reader_join_outcome = Some(closed);
                Err(failure.to_owned())
            }
        };
        let outcome = match attempted {
            Err(original_failure) => Err(original_failure),
            Ok(waiter) => match read_result {
                Ok(Err(AppError::Unauthenticated)) => {
                    eprintln!("ARTIFACT_CURRENT_LOCAL_FINAL_WAIT io_ack=true final_marker=true wait_type=Lock blocker_pid={controller_pid} waiter_pid={waiter} controller_commit_ack=true");
                    Ok(())
                }
                Ok(_) => Err("actual Local final statement did not observe committed NULL current generation".to_owned()),
                Err(error) => Err(error),
            },
        };
        if outcome.is_err() {
            emit_host_read_wait_diagnostic(&diagnostic);
        }
        drop(transaction);
        drop(observer);
        drop(controller);
        drop(protocol);
        outcome
     })).await;
}

struct TracePhaseGate {
    io_seen: std::sync::atomic::AtomicBool,
    ready_seen: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
    timed_out: std::sync::atomic::AtomicBool,
}
impl TracePhaseGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            io_seen: std::sync::atomic::AtomicBool::new(false),
            ready_seen: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
            timed_out: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
struct PhaseVisitor(Option<&'static str>);
impl tracing::field::Visit for PhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "artifact_read_phase" {
            self.0 = match value {
                "actual_io_completed_before_joint" => Some("actual_io_completed_before_joint"),
                "joint_statement_ready" => Some("joint_statement_ready"),
                _ => None,
            };
        }
    }
}
struct ReadPhaseSubscriber(Arc<TracePhaseGate>);
impl tracing::Subscriber for ReadPhaseSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = PhaseVisitor(None);
        event.record(&mut visitor);
        match visitor.0 {
            Some("actual_io_completed_before_joint") => {
                self.0.io_seen.store(true, Ordering::SeqCst);
            }
            Some("joint_statement_ready")
                if self.0.io_seen.load(Ordering::SeqCst)
                    && !self.0.ready_seen.swap(true, Ordering::SeqCst) =>
            {
                self.0.entered.notify_one();
                let released = self.0.released.lock().unwrap();
                let (_released, timeout) = self
                    .0
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                    .unwrap();
                if timeout.timed_out() {
                    self.0.timed_out.store(true, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }
}
#[derive(Default)]
struct HostReadWaitDiagnostic {
    controller_pid: i32,
    observer_pid: i32,
    io_seen: bool,
    ready_seen: bool,
    controller_lock_ack: bool,
    entered_notification_to_lock_ack_ms: Option<u128>,
    barrier_timed_out_before_release: Option<bool>,
    barrier_timed_out_after_observation: Option<bool>,
    read_task_finished_before_release: Option<bool>,
    activity_capacity_bytes: i64,
    observer_samples: u32,
    marker_candidates: i32,
    marker_active_candidates: i32,
    marker_idle_in_transaction_candidates: i32,
    marker_idle_candidates: i32,
    marker_other_state_candidates: i32,
    marker_lock_candidates: i32,
    exact_waiter_count: i32,
    exact_waiter_pid: Option<i32>,
    read_task_finished_after_observation: Option<bool>,
    controller_commit_ack: bool,
    controller_rollback_attempted: bool,
    controller_rollback_ack: bool,
    reader_join_ack: bool,
    reader_join_outcome: Option<&'static str>,
    reader_terminal_class: Option<&'static str>,
}

fn host_read_terminal_class(result: &Result<Vec<u8>, AppError>) -> &'static str {
    match result {
        Ok(_) => "body_returned",
        Err(AppError::Unauthenticated) => "unauthenticated",
        Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        }) => "host_request_binding_unavailable",
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        }) => "artifacts_unavailable",
        Err(_) => "other_closed_error",
    }
}

fn emit_host_read_wait_diagnostic(diagnostic: &HostReadWaitDiagnostic) {
    let sampled = diagnostic.observer_samples > 0;
    let observer_sample_status = if sampled { "sampled" } else { "not_sampled" };
    let exact_waiter_pid = if sampled {
        diagnostic.exact_waiter_pid
    } else {
        None
    };
    eprintln!(
        concat!(
            "ARTIFACT_CURRENT_LOCAL_FINAL_WAIT_DIAGNOSTIC controller_pid={} observer_pid={} io_seen={} ready_seen={} ",
            "controller_lock_ack={} entered_notification_to_lock_ack_ms={:?} ",
            "barrier_timed_out_before_release={:?} barrier_timed_out_after_observation={:?} ",
            "read_task_finished_before_release={:?} activity_capacity_bytes={} ",
            "observer_samples={} observer_sample_status={} marker_candidates={:?} ",
            "marker_active_candidates={:?} marker_idle_in_transaction_candidates={:?} ",
            "marker_idle_candidates={:?} marker_other_state_candidates={:?} ",
            "marker_lock_candidates={:?} exact_waiter_count={:?} exact_waiter_pid={:?} ",
            "read_task_finished_after_observation={:?} controller_commit_ack={} ",
            "controller_rollback_attempted={} controller_rollback_ack={} reader_join_ack={} ",
            "reader_join_outcome={:?} reader_terminal_class={:?} ",
            "ack_semantics=\"true=actual successful ACK; false=ACK not obtained, ",
            "not proof that an effect did not occur\""
        ),
        diagnostic.controller_pid,
        diagnostic.observer_pid,
        diagnostic.io_seen,
        diagnostic.ready_seen,
        diagnostic.controller_lock_ack,
        diagnostic.entered_notification_to_lock_ack_ms,
        diagnostic.barrier_timed_out_before_release,
        diagnostic.barrier_timed_out_after_observation,
        diagnostic.read_task_finished_before_release,
        diagnostic.activity_capacity_bytes,
        diagnostic.observer_samples,
        observer_sample_status,
        sampled.then_some(diagnostic.marker_candidates),
        sampled.then_some(diagnostic.marker_active_candidates),
        sampled.then_some(diagnostic.marker_idle_in_transaction_candidates),
        sampled.then_some(diagnostic.marker_idle_candidates),
        sampled.then_some(diagnostic.marker_other_state_candidates),
        sampled.then_some(diagnostic.marker_lock_candidates),
        sampled.then_some(diagnostic.exact_waiter_count),
        exact_waiter_pid,
        diagnostic.read_task_finished_after_observation,
        diagnostic.controller_commit_ack,
        diagnostic.controller_rollback_attempted,
        diagnostic.controller_rollback_ack,
        diagnostic.reader_join_ack,
        diagnostic.reader_join_outcome,
        diagnostic.reader_terminal_class,
    );
}

async fn actual_final_wait(
    observer: &tokio_postgres::Client,
    blocker: i32,
    diagnostic: &mut HostReadWaitDiagnostic,
) -> Result<i32, String> {
    for _ in 0..150 {
        let row = observer.query_one(
            r#"SELECT COUNT(*)::integer AS marker_candidates,
       COUNT(*) FILTER (WHERE a.state='active')::integer AS marker_active_candidates,
       COUNT(*) FILTER (WHERE a.state='idle in transaction')::integer AS marker_idle_in_transaction_candidates,
       COUNT(*) FILTER (WHERE a.state='idle')::integer AS marker_idle_candidates,
       COUNT(*) FILTER (WHERE a.state IS NULL OR a.state NOT IN ('active','idle in transaction','idle'))::integer AS marker_other_state_candidates,
       COUNT(*) FILTER (WHERE a.wait_event_type='Lock')::integer AS marker_lock_candidates,
       COUNT(*) FILTER (WHERE a.wait_event_type='Lock'
                        AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)))::integer AS exact_waiter_count,
       MIN(a.pid) FILTER (WHERE a.wait_event_type='Lock'
                          AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))) AS exact_waiter_pid
FROM pg_catalog.pg_stat_activity a
WHERE a.datname=current_database()
  AND a.pid<>pg_backend_pid()
  AND a.query LIKE '%/* artifact_current_host_joint_read_after_io */%'"#,
            &[&blocker],
        ).await.map_err(|error| error.to_string())?;
        let marker_candidates: i32 = row
            .try_get("marker_candidates")
            .map_err(|error| error.to_string())?;
        let marker_active_candidates: i32 = row
            .try_get("marker_active_candidates")
            .map_err(|error| error.to_string())?;
        let marker_idle_in_transaction_candidates: i32 = row
            .try_get("marker_idle_in_transaction_candidates")
            .map_err(|error| error.to_string())?;
        let marker_idle_candidates: i32 = row
            .try_get("marker_idle_candidates")
            .map_err(|error| error.to_string())?;
        let marker_other_state_candidates: i32 = row
            .try_get("marker_other_state_candidates")
            .map_err(|error| error.to_string())?;
        let marker_lock_candidates: i32 = row
            .try_get("marker_lock_candidates")
            .map_err(|error| error.to_string())?;
        let exact_waiter_count: i32 = row
            .try_get("exact_waiter_count")
            .map_err(|error| error.to_string())?;
        let exact_waiter_pid: Option<i32> = row
            .try_get("exact_waiter_pid")
            .map_err(|error| error.to_string())?;
        diagnostic.marker_candidates = marker_candidates;
        diagnostic.marker_active_candidates = marker_active_candidates;
        diagnostic.marker_idle_in_transaction_candidates = marker_idle_in_transaction_candidates;
        diagnostic.marker_idle_candidates = marker_idle_candidates;
        diagnostic.marker_other_state_candidates = marker_other_state_candidates;
        diagnostic.marker_lock_candidates = marker_lock_candidates;
        diagnostic.exact_waiter_count = exact_waiter_count;
        diagnostic.exact_waiter_pid = exact_waiter_pid;
        diagnostic.observer_samples += 1;
        if exact_waiter_count == 1 {
            return exact_waiter_pid
                .ok_or_else(|| "actual exact Lock waiter PID was not decoded".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("actual final joint statement/controller Lock wait was not observed".to_owned())
}

// Controlled 0044 rows are consumer inputs only. These observations never assert deletion,
// directory sync, refund, cleanup authorization or a producer receipt.
const CLEANUP_PUBLIC_READ_FACTS: &str = "SELECT jsonb_build_object( \
 'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY to_jsonb(b)::text),'[]') FROM openbot_internal.artifact_dataset_bindings b), \
 'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
 'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
 'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
 'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]') FROM openbot_internal.artifact_store_bindings s), \
 'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
 'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
 'fences',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]') FROM openbot_internal.artifact_cleanup_fences f), \
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text),'[]') FROM public.audit_events e), \
 'users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY to_jsonb(u)::text),'[]') FROM public.users u), \
 'roles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM public.user_roles r), \
 'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.sessions s), \
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]') FROM public.messages m))";

async fn cleanup_public_read_facts_on(
    client: &tokio_postgres::Client,
) -> Result<serde_json::Value, String> {
    client
        .query_one(CLEANUP_PUBLIC_READ_FACTS, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL binaries and actual Local final-query Lock/COMMIT ACK"]
async fn actual_local_worker_ack_then_final_cleanup_fence_wait_observes_armed_commit() {
    use tracing::instrument::WithSubscriber as _;
    with_fixture("local_read_cleanup_final_wait", |fixture| Box::pin(async move {

        let protocol = Arc::new(fixture.protocol()?);
        protocol.bind_window("main", fixture.original.clone(), None).map_err(|error| error.to_string())?;
        let mut controller = fixture.pool().get().await.map_err(|error| error.to_string())?;
        let observer = fixture.pool().get().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let observer_pid: i32 = observer.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let activity_capacity_bytes: i64 = observer.query_one(
            "SELECT pg_size_bytes(current_setting('track_activity_query_size'))", &[],
        ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        require(controller_pid != observer_pid, "actual controller and observer PIDs were not distinct")?;
        require(activity_capacity_bytes >= 16_384, "owned Local activity query width was not actually sixteen KiB")?;
        let artifact_path = fixture.artifact_root.join("objects").join(&fixture.receipt.artifact_id);
        require(cleanup_owned_inode_fds(&artifact_path)?.is_empty(),
            "owned original Local artifact unexpectedly began with a live read FD")?;
        let before = cleanup_public_read_facts_on(&observer).await?;
        require(before["fences"] == serde_json::json!([]), "owned final-wait fixture unexpectedly began fenced")?;
        let mut expected = before.clone();
        let mut diagnostic = HostReadWaitDiagnostic {
            controller_pid,
            observer_pid,
            activity_capacity_bytes,
            ..HostReadWaitDiagnostic::default()
        };
        let gate = TracePhaseGate::new();
        let dispatch = tracing::Dispatch::new(ReadPhaseSubscriber(gate.clone()));
        let called = protocol.clone();
        let id = fixture.receipt.artifact_id.clone();
        let mut task = Some(tokio::spawn(
            async move { called.read_current_artifact_chunk("main", id).await }.with_subscriber(dispatch),
        ));
        let notification = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await;
        let entered_at = std::time::Instant::now();
        diagnostic.io_seen = gate.io_seen.load(Ordering::SeqCst);
        diagnostic.ready_seen = gate.ready_seen.load(Ordering::SeqCst);
        let mut failure = notification
            .map_err(|_| "actual Local IO/final-ready phases were not observed".to_owned())
            .and_then(|_| require(diagnostic.io_seen && diagnostic.ready_seen, "actual Local worker ACK did not precede final-ready"))
            .err();
        let mut transaction = if failure.is_none() {
            match controller.transaction().await {
                Ok(transaction) => Some(transaction),
                Err(error) => {
                    failure = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        let attempted: Result<i32, String> = if let Some(error) = failure {
            Err(error)
        } else {
            async {
                transaction.as_ref().expect("actual controller transaction retained")
                    .batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|error| error.to_string())?;
                diagnostic.controller_lock_ack = true;
                diagnostic.entered_notification_to_lock_ack_ms = Some(entered_at.elapsed().as_millis());
                diagnostic.barrier_timed_out_before_release = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_before_release = Some(task.as_ref().expect("original reader retained").is_finished());
                require(diagnostic.barrier_timed_out_before_release == Some(false), "Local trace barrier timed out instead of controller release")?;
                require(diagnostic.read_task_finished_before_release == Some(false), "original Local reader ended before the actual final PG wait")?;
                gate.release();
                let observed = actual_final_wait(&observer, controller_pid, &mut diagnostic).await;
                diagnostic.barrier_timed_out_after_observation = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_after_observation = Some(task.as_ref().expect("original reader retained").is_finished());
                let waiter = observed?;
                require(diagnostic.barrier_timed_out_after_observation == Some(false), "Local trace barrier timed out instead of controller release")?;
                require(waiter != controller_pid && waiter != observer_pid,
                    "final waiter borrowed the actual controller or observer connection")?;
                require(diagnostic.read_task_finished_after_observation == Some(false),
                    "original reader ended while its tagged final SQL was actually blocked")?;
                let inserted: serde_json::Value = transaction.as_ref().expect("actual controller transaction retained")
                    .query_one(
                        "INSERT INTO openbot_internal.artifact_cleanup_fences \
                         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
                         SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
                         FROM openbot_internal.artifact_records \
                         WHERE deployment_id=$1 AND tenant_id=$2 AND operation_id=$3 AND artifact_id=$4 AND owner_actor_id=$5 \
                         RETURNING to_jsonb(artifact_cleanup_fences)",
                        &[&fixture.original.deployment().as_str(), &fixture.original.tenant().as_str(),
                          &fixture.receipt.operation_id, &fixture.receipt.artifact_id, &fixture.original.actor().as_str()],
                    ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
                require(inserted["operation_id"] == fixture.receipt.operation_id
                    && inserted["artifact_id"] == fixture.receipt.artifact_id
                    && inserted["terminal_status"] == "deleted" && inserted["phase"] == "armed",
                    "controlled armed fence did not retain the actual original pair and intent")?;
                expected["fences"] = serde_json::json!([inserted]);
                transaction.take().expect("actual controller transaction retained")
                    .commit().await.map_err(|error| error.to_string())?;
                diagnostic.controller_commit_ack = true;
                Ok(waiter)
            }.await
        };
        gate.release();
        if let Some(transaction) = transaction.take() {
            diagnostic.controller_rollback_attempted = true;
            diagnostic.controller_rollback_ack = transaction.rollback().await.is_ok();
        }
        let joined = task.take().expect("original reader retained").await;
        let read_result = match joined {
            Ok(result) => {
                diagnostic.reader_join_ack = true;
                diagnostic.reader_join_outcome = Some("read_result");
                diagnostic.reader_terminal_class = Some(host_read_terminal_class(&result));
                Ok(result)
            }
            Err(error) => {
                let (closed, failure) = if error.is_panic() {
                    ("read_task_panicked", "actual read task panicked")
                } else {
                    ("read_task_cancelled", "actual read task was cancelled")
                };
                diagnostic.reader_join_outcome = Some(closed);
                Err(failure.to_owned())
            }
        };
        let outcome = match attempted {
            Err(original_failure) => Err(original_failure),
            Ok(waiter) => match read_result {
                Ok(Err(AppError::DependencyUnavailable { dependency: "artifacts" })) => {
                    require(diagnostic.controller_commit_ack && diagnostic.reader_join_ack,
                        "actual cleanup fence refusal lacked original COMMIT and reader join ACK")?;
                    require(cleanup_public_read_facts_on(&observer).await? == expected,
                        "actual final cleanup-fence consumer changed original source, record, receipt, charge, quota, store, fence or audit facts")?;
                    let lifecycle = fixture.port.actual.read_authority().read_lifecycle();
                    lifecycle.close();
                    lifecycle.drain_before(std::time::Instant::now() + Duration::from_secs(5)).await
                        .map_err(|_| "original Local final-wait inventory did not actually drain".to_owned())?;
                    require(cleanup_owned_inode_fds(&artifact_path)?.is_empty(),
                        "original Local object inode FD survived actual final refusal and inventory drain")?;
                    eprintln!("ARTIFACT_CURRENT_LOCAL_CLEANUP_FINAL_WAIT io_ack=true final_marker=true wait_type=Lock blocker_pid={controller_pid} observer_pid={observer_pid} waiter_pid={waiter} controller_commit_ack=true original_reader_join_ack=true actual_inventory_drain_ack=true own_inode_fd_absent=true body_refused=true business_facts_unchanged=true");
                    Ok(())
                }
                Ok(_) => Err("actual Local final statement did not refuse the committed original armed cleanup fence".to_owned()),
                Err(error) => Err(error),
            },
        };
        if outcome.is_err() {
            emit_host_read_wait_diagnostic(&diagnostic);
        }
        drop(transaction);
        drop(observer);
        drop(controller);
        drop(protocol);
        outcome
     })).await;
}

// Read only this Rust process's bounded f/device/inode inventory. No path fields or peer PIDs.
fn cleanup_owned_inode_fds(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<std::collections::BTreeSet<u32>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "own-PID lsof is unavailable (Unproven)".to_owned())?;
        let stdout = child.stdout.take().ok_or("lsof stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("lsof stderr unavailable")?;
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output.join();
                let _ = errors.join();
                return Err("own-PID lsof exceeded original five seconds (Unproven)".to_owned());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = output
            .join()
            .map_err(|_| "lsof output worker panicked")?
            .map_err(|error| error.to_string())?;
        let errors = errors
            .join()
            .map_err(|_| "lsof error worker panicked")?
            .map_err(|error| error.to_string())?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.len() <= 8_192
                && output.ends_with(b"\n"),
            "lsof incomplete/failed/truncated (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "lsof output invalid (Unproven)")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("lsof empty field (Unproven)")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "lsof observed another PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(inode) {
                        found.insert(
                            fd.ok_or("original inode has an ambiguous nonnumeric FD (Unproven)")?,
                        );
                    }
                    fd = value.parse::<u32>().ok();
                    dev = None;
                    ino = None;
                }
                "D" => {
                    dev = Some(
                        if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16)
                        } else {
                            value.parse::<u64>()
                        }
                        .map_err(|_| "lsof device invalid (Unproven)")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "lsof inode invalid (Unproven)")?,
                    );
                }
                _ => return Err("lsof unexpected field (Unproven)".to_owned()),
            }
        }
        require(self_pid, "lsof self-PID field missing (Unproven)")?;
        Ok(found)
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "own original FD inventory was unstable (Unproven)",
    )?;
    Ok(first)
}
