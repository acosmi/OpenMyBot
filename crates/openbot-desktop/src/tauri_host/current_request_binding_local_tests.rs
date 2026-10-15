//! Actual Local installation + attested numeric-loopback/SCRAM PostgreSQL owner and private
//! production Local source + actual Protocol/App/artifact port. The test-owned binary launch is
//! not a release sidecar manifest/supervisor, native GUI, Keychain or full readiness acceptance.

use super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use async_trait::async_trait;
use http::{Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest,
    OpenBotApplication, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, GetArtifactMetadata, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{BotId, RunId};
use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingGuard};
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
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
            "binding_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    writeln!(file, "\nlisten_addresses = '127.0.0.1'\nport = {port}\npassword_encryption = 'scram-sha-256'\ndynamic_shared_memory_type = 'posix'\nunix_socket_directories = '{socket}'\nunix_socket_permissions = 0700")
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
    metadata_calls: AtomicUsize,
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
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
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
struct ProtocolFacts {
    status: StatusCode,
    value: Value,
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
            metadata_calls: AtomicUsize::new(0),
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
    async fn metadata(
        &self,
        protocol: &DesktopTauriProtocol,
        label: &str,
    ) -> Result<ProtocolFacts, String> {
        let request = Request::builder()
            .uri(format!("/api/artifacts/{}", self.receipt.artifact_id))
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let response = protocol.handle(label, request).await;
        require(
            response
                .headers()
                .get("cache-control")
                .and_then(|x| x.to_str().ok())
                == Some("no-store"),
            "actual Local metadata response lost no-store",
        )?;
        Ok(ProtocolFacts {
            status: response.status(),
            value: serde_json::from_slice(response.body()).map_err(|e| e.to_string())?,
        })
    }
    async fn app_metadata(&self, auth: &AuthContext) -> Result<AppReply, AppError> {
        self.application
            .execute(
                auth.clone(),
                AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                    artifact_id: self.receipt.artifact_id.clone(),
                }),
            )
            .await
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool().get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object(
            'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
            'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
            'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
            'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
            'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
            'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a WHERE event_type='artifact.saved'))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
    }
    async fn canonical_facts(&self) -> Result<Value, String> {
        self.pool().get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object('users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY id),'[]') FROM public.users u),'roles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY user_id,role),'[]') FROM public.user_roles r),'deny',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY email),'[]') FROM public.revoked_access d))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
    }
    async fn unchanged(&self, facts: &Value) -> Result<(), String> {
        require(
            &self.facts().await? == facts
                && fs::read(
                    self.artifact_root
                        .join("objects")
                        .join(&self.receipt.artifact_id),
                )
                .map_err(|e| e.to_string())?
                    == TEXT.as_bytes(),
            "Local binding check mutated actual artifact/charge/receipt/audit/bytes facts",
        )
    }
    fn finish(self, test: &'static str) -> Result<(), String> {
        drop(self.application);
        drop(self.port);
        drop(self.source);
        self.desktop.finish(test)
    }
}

type FixtureFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;
async fn with_fixture<F>(name: &'static str, body: F)
where
    F: for<'a> FnOnce(&'a LocalFixture) -> FixtureFuture<'a>,
{
    let fixture = LocalFixture::new()
        .await
        .unwrap_or_else(|e| panic!("{name} actual Local setup failed: {e}"));
    let outcome = body(&fixture).await;
    let cleanup = fixture.finish(name);
    outcome.unwrap_or_else(|e| panic!("{name} failed: {e}"));
    cleanup.unwrap_or_else(|e| panic!("{name} actual owned Local stop/cleanup failed: {e}"));
}
async fn verify(auth: &AuthContext) -> Result<(), HostRequestBindingError> {
    auth.request_binding()
        .ok_or(HostRequestBindingError::Missing)?
        .verify_current(auth)
        .await
}
fn private_failure(
    fixture: &LocalFixture,
    response: &ProtocolFacts,
    status: StatusCode,
    code: &str,
) -> Result<(), String> {
    require(
        response.status == status
            && response.value.get("code").and_then(Value::as_str) == Some(code),
        "actual Local failure status/code mismatch",
    )?;
    let encoded = response.value.to_string();
    for private in [
        fixture.receipt.artifact_id.as_str(),
        fixture.receipt.source_message_id.as_str(),
        fixture.receipt.source_thread_id.as_str(),
        fixture.receipt.source_run_id.as_str(),
        SHA256,
        TEXT,
    ] {
        require(
            !encoded.contains(private),
            "actual Local failure leaked old metadata/content",
        )?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_local_two_protocols_first_id_one_are_distinct_and_each_current_for_own_context() {
    with_fixture("local_two_owners", |fixture| {
        Box::pin(async move {
            let facts = fixture.facts().await?;
            let a = fixture.protocol()?;
            let b = fixture.protocol()?;
            a.bind_window("main", fixture.original.clone(), None)
                .map_err(|e| e.to_string())?;
            b.bind_window("main", fixture.original.clone(), None)
                .map_err(|e| e.to_string())?;
            // These are actual private registry fields, not guessed from a label or fabricated id.
            require(
                a.windows
                    .read()
                    .map_err(|_| "A map poisoned")?
                    .get("main")
                    .ok_or("A actual entry absent")?
                    .binding_id
                    == 1
                    && b.windows
                        .read()
                        .map_err(|_| "B map poisoned")?
                        .get("main")
                        .ok_or("B actual entry absent")?
                        .binding_id
                        == 1,
                "actual first protocol entries did not both use id one",
            )?;
            let auth_a = fixture.bound_auth(&a, "main")?;
            let auth_b = fixture.bound_auth(&b, "main")?;
            let proof_a = auth_a.request_binding().ok_or("A proof missing")?;
            let proof_b = auth_b.request_binding().ok_or("B proof missing")?;
            require(
                auth_a == auth_b && !proof_a.identity().same_binding(proof_b.identity()),
                "actual different Local owners collapsed identical label/id/six facts",
            )?;
            require(
                verify(&auth_a).await.is_ok() && verify(&auth_b).await.is_ok(),
                "actual own installation/current-PG Local guards refused a live owner",
            )?;
            require(
                proof_a.verify_current(&auth_b).await == Err(HostRequestBindingError::NotCurrent),
                "actual B-bound context accepted A proof",
            )?;
            require(
                fixture.metadata(&a, "main").await?.status == StatusCode::OK
                    && fixture.metadata(&b, "main").await?.status == StatusCode::OK,
                "actual Local Protocol/App/PG metadata failed",
            )?;
            let sessions: i64 = fixture
                .pool()
                .get()
                .await
                .map_err(|e| e.to_string())?
                .query_one("SELECT count(*) FROM public.sessions", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            require(
                sessions == 0,
                "actual Local source fabricated a Server session",
            )?;
            drop(auth_a.clone());
            require(
                verify(&auth_a).await.is_ok(),
                "Local proof clone drop closed its actual owner",
            )?;
            drop(a);
            require(
                verify(&auth_a).await == Err(HostRequestBindingError::NotCurrent)
                    && verify(&auth_b).await.is_ok(),
                "dropping final actual owner A did not close only its own proof",
            )?;
            fixture.unchanged(&facts).await
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_minted_local_generation_zero_refuses_only_users_generation_null_without_repair() {
    with_fixture("local_current_null", |fixture| {
        Box::pin(async move {
            let facts = fixture.facts().await?;
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|e| e.to_string())?;
            let captured = fixture.bound_auth(&protocol, "main")?;
            require(
                verify(&captured).await.is_ok(),
                "actual gen0 Local window was not current before mutation",
            )?;
            fixture
                .pool()
                .get()
                .await
                .map_err(|e| e.to_string())?
                .execute(
                    "UPDATE public.users SET auth_generation=NULL WHERE id=$1",
                    &[&fixture.original.actor().as_str()],
                )
                .await
                .map_err(|e| e.to_string())?;
            let canonical = fixture.canonical_facts().await?;
            require(
                HostRequestBindingGuard::verify_current(fixture.source.as_ref(), &fixture.original)
                    .await
                    == Err(HostRequestBindingError::NotCurrent),
                "new production Local source coalesced raw NULL into generation zero",
            )?;
            require(
                verify(&captured).await == Err(HostRequestBindingError::NotCurrent),
                "actual Local window accepted NULL current generation",
            )?;
            private_failure(
                fixture,
                &fixture.metadata(&protocol, "main").await?,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            )?;
            require(
                fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
                "NULL Local preguard entered real artifact PG",
            )?;
            require(
                fixture.canonical_facts().await? == canonical,
                "current Local check provisioned/repaired canonical facts",
            )?;
            fixture.unchanged(&facts).await
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_local_current_email_role_deny_and_generation_each_refuse_without_repair_or_upgrade()
{
    with_fixture("local_current_matrix",|fixture|Box::pin(async move {
        let facts=fixture.facts().await?;
        let protocol=fixture.protocol()?;
        protocol.bind_window("main",fixture.original.clone(),None).map_err(|e|e.to_string())?;
        let captured=fixture.bound_auth(&protocol,"main")?;
        let original_email:String=fixture.pool().get().await.map_err(|e|e.to_string())?.query_one("SELECT email FROM public.users WHERE id=$1",&[&fixture.original.actor().as_str()]).await.map_err(|e|e.to_string())?.get(0);
        let actor=fixture.original.actor().as_str();
        for case in 0..4 {
            {
                let c=fixture.pool().get().await.map_err(|e|e.to_string())?;
                match case {
                    0 => { c.execute("UPDATE public.users SET email='changed-local@example.test' WHERE id=$1",&[&actor]).await.map_err(|e|e.to_string())?; }
                    1 => { c.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",&[&actor]).await.map_err(|e|e.to_string())?; }
                    2 => { c.execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES($1,$2)",&[&original_email,&actor]).await.map_err(|e|e.to_string())?; }
                    3 => { c.execute("UPDATE public.users SET auth_generation=1 WHERE id=$1",&[&actor]).await.map_err(|e|e.to_string())?; }
                    _ => unreachable!(),
                }
            }
            let changed=fixture.canonical_facts().await?;
            require(verify(&captured).await==Err(HostRequestBindingError::NotCurrent),"actual Local current predicate accepted a controlled canonical mutation")?;
            private_failure(fixture,&fixture.metadata(&protocol,"main").await?,StatusCode::UNAUTHORIZED,"unauthenticated")?;
            require(fixture.canonical_facts().await?==changed,"Local guard repaired/advanced canonical facts")?;
            // Explicit test-controller restoration in the owned database is not a production
            // generation downgrade or a runtime repair. It isolates four independent predicates.
            let c=fixture.pool().get().await.map_err(|e|e.to_string())?;
            c.execute("UPDATE public.users SET email=$1,auth_generation=0 WHERE id=$2",&[&original_email,&actor]).await.map_err(|e|e.to_string())?;
            c.execute("DELETE FROM public.user_roles WHERE user_id=$1 AND role='user'",&[&actor]).await.map_err(|e|e.to_string())?;
            c.execute("DELETE FROM public.revoked_access WHERE email=$1",&[&original_email]).await.map_err(|e|e.to_string())?;
            drop(c);
            require(verify(&captured).await.is_ok(),"actual original source did not return current after test-controller restoration")?;
        }
        require(fixture.port.metadata_calls.load(Ordering::SeqCst)==0,"changed Local canonical preguard entered artifact PG")?;
        fixture.unchanged(&facts).await
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_local_current_pool_acquisition_is_in_total_five_second_budget_and_static_503() {
    with_fixture("local_pool_budget", |fixture| {
        Box::pin(async move {
            let facts = fixture.facts().await?;
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|e| e.to_string())?;
            let captured = fixture.bound_auth(&protocol, "main")?;
            let mut held = Vec::new();
            for _ in 0..16 {
                held.push(fixture.pool().get().await.map_err(|e| e.to_string())?);
            }
            let start = tokio::time::Instant::now();
            let response = fixture.metadata(&protocol, "main").await?;
            let elapsed = start.elapsed();
            private_failure(
                fixture,
                &response,
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
            )?;
            require(
                elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(7),
                "real Local current acquisition did not obey total five-second bound",
            )?;
            require(
                fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
                "bounded Local acquisition failure entered artifact PG",
            )?;
            drop(held);
            require(
                verify(&captured).await.is_ok(),
                "Local acquisition timeout mutated otherwise-current original proof",
            )?;
            fixture.unchanged(&facts).await
        })
    })
    .await;
}

async fn actual_blocked_query(
    fixture: &LocalFixture,
    blocker: i32,
    needle: &str,
) -> Result<i32, String> {
    for _ in 0..200 {
        let rows=fixture.pool().get().await.map_err(|e|e.to_string())?.query("SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.query LIKE $2 AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))",&[&blocker,&needle]).await.map_err(|e|e.to_string())?;
        if rows.len() == 1 {
            return Ok(rows[0].get(0));
        }
        require(
            rows.is_empty(),
            "multiple actual Local producers reached one owned controller lock",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("actual Local producer did not reach its PostgreSQL controlled wait".to_owned())
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_local_current_sql_table_wait_is_bounded_and_rolled_back_before_reuse() {
    with_fixture("local_statement_budget",|fixture|Box::pin(async move {
        let facts=fixture.facts().await?;
        let protocol=fixture.protocol()?;
        protocol.bind_window("main",fixture.original.clone(),None).map_err(|e|e.to_string())?;
        let captured=fixture.bound_auth(&protocol,"main")?;
        let mut c=fixture.pool().get().await.map_err(|e|e.to_string())?;
        let blocker:i32=c.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("SET LOCAL lock_timeout='2s'; LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
        // Retain one independent observer connection so a returned producer connection cannot
        // be checked out by its own observer and make an idle transaction appear active.
        let observer=fixture.pool().get().await.map_err(|e|e.to_string())?;
        let observer_pid:i32=observer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let start=tokio::time::Instant::now();
        let request=fixture.metadata(&protocol,"main");
        tokio::pin!(request);
        let producer=tokio::select! {
            ready=&mut request => return Err(format!("actual Local preguard finished before its SQL wait: {:?}",ready.map(|x|x.status))),
            observed=actual_blocked_query(fixture,blocker,"%canonical_email%") => observed?,
        };
        require(producer!=blocker && producer!=observer_pid,"controlled statement waiter was not a distinct actual connection")?;
        let response=tokio::time::timeout(Duration::from_secs(7),request).await.map_err(|_|"Local SQL wait exceeded complete guard deadline")??;
        private_failure(fixture,&response,StatusCode::SERVICE_UNAVAILABLE,"dependency_unavailable")?;
        require(start.elapsed()>=Duration::from_secs(4) && start.elapsed()<Duration::from_secs(7),"actual Local statement wait ignored five-second total budget")?;
        require(fixture.port.metadata_calls.load(Ordering::SeqCst)==0,"Local SQL-timeout preguard entered artifact PG")?;
        tx.rollback().await.map_err(|e|e.to_string())?;
        drop(c);
        // Outer timeout itself proves no stopped worker. Observe the exact producer's actual
        // transaction ending after blocker release before considering reuse/teardown verified.
        let mut quiescent=false;
        for _ in 0..200 {
            let active:bool=observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND (xact_start IS NOT NULL OR state='active'))",&[&producer]).await.map_err(|e|e.to_string())?.get(0);
            if !active {quiescent=true;break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        require(quiescent,"exact timed-out Local producer transaction did not actually end after release")?;
        drop(observer);
        require(verify(&captured).await.is_ok(),"real Local current guard could not reuse the released healthy source")?;
        fixture.unchanged(&facts).await
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn actual_local_current_null_during_real_metadata_pg_wait_withholds_old_available() {
    with_fixture("local_metadata_null",|fixture|Box::pin(async move {
        let facts=fixture.facts().await?;
        let protocol=fixture.protocol()?;
        protocol.bind_window("main",fixture.original.clone(),None).map_err(|e|e.to_string())?;
        let auth=fixture.bound_auth(&protocol,"main")?;
        let mut c=fixture.pool().get().await.map_err(|e|e.to_string())?;
        let blocker:i32=c.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("SET LOCAL lock_timeout='2s'; LOCK TABLE openbot_internal.artifact_records IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
        let request=fixture.metadata(&protocol,"main");
        tokio::pin!(request);
        tokio::select! {
            ready=&mut request => return Err(format!("Local metadata completed before actual PG wait: {:?}",ready.map(|x|x.status))),
            observed=actual_blocked_query(fixture,blocker,"%artifact_records%") => {observed?;},
        }
        require(fixture.port.metadata_calls.load(Ordering::SeqCst)==1,"real Local preguard did not enter exactly one metadata PG call")?;
        fixture.pool().get().await.map_err(|e|e.to_string())?.execute("UPDATE public.users SET auth_generation=NULL WHERE id=$1",&[&fixture.original.actor().as_str()]).await.map_err(|e|e.to_string())?;
        tx.rollback().await.map_err(|e|e.to_string())?;
        drop(c);
        let response=tokio::time::timeout(Duration::from_secs(8),request).await.map_err(|_|"Local metadata did not finish after actual table release")??;
        private_failure(fixture,&response,StatusCode::UNAUTHORIZED,"unauthenticated")?;
        require(verify(&auth).await==Err(HostRequestBindingError::NotCurrent),"Local postguard accepted the old gen0 proof after real PG wait")?;
        fixture.unchanged(&facts).await
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
async fn last_actual_local_protocol_drop_during_real_app_metadata_wait_closes_weak_map_proof() {
    with_fixture("local_metadata_drop",|fixture|Box::pin(async move {
        let facts=fixture.facts().await?;
        let protocol=fixture.protocol()?;
        protocol.bind_window("main",fixture.original.clone(),None).map_err(|e|e.to_string())?;
        let auth=fixture.bound_auth(&protocol,"main")?;
        require(verify(&auth).await.is_ok(),"actual Local proof did not initially verify")?;
        let mut c=fixture.pool().get().await.map_err(|e|e.to_string())?;
        let blocker:i32=c.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("SET LOCAL lock_timeout='2s'; LOCK TABLE openbot_internal.artifact_records IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
        // This actual App future retains only the captured guard/context. It holds no Protocol
        // reference; dropping the last owner below is real, not just closing a synthetic lease.
        let request=fixture.app_metadata(&auth);
        tokio::pin!(request);
        tokio::select! {
            ready=&mut request => return Err(format!("real App metadata completed before PG wait: {ready:?}")),
            observed=actual_blocked_query(fixture,blocker,"%artifact_records%") => {observed?;},
        }
        drop(protocol);
        tx.rollback().await.map_err(|e|e.to_string())?;
        drop(c);
        require(matches!(tokio::time::timeout(Duration::from_secs(8),request).await.map_err(|_|"real App metadata did not finish after owner drop")?,Err(AppError::Unauthenticated)),"last actual Local Protocol drop allowed old metadata result across await")?;
        require(verify(&auth).await==Err(HostRequestBindingError::NotCurrent),"retained proof/map observation revived dropped Local owner")?;
        require(HostRequestBindingGuard::verify_current(fixture.source.as_ref(),&fixture.original).await.is_ok(),"window owner drop incorrectly changed separate current Local canonical source")?;
        fixture.unchanged(&facts).await
    })).await;
}

#[tokio::test]
#[ignore = "requires root-owned PG17 binaries; starts and explicitly stops its own Local sidecar"]
// Deliberately retain the owned write guard while exercising the production try_read refusal.
#[allow(clippy::await_holding_lock)]
async fn actual_local_map_contention_and_poison_are_unavailable_before_artifact_pg() {
    with_fixture("local_map_unavailable", |fixture| {
        Box::pin(async move {
            let facts = fixture.facts().await?;
            let protocol = fixture.protocol()?;
            protocol
                .bind_window("main", fixture.original.clone(), None)
                .map_err(|e| e.to_string())?;
            let auth = fixture.bound_auth(&protocol, "main")?;
            {
                let _held = protocol
                    .windows
                    .write()
                    .map_err(|_| "actual map already poisoned")?;
                require(
                    verify(&auth).await == Err(HostRequestBindingError::Unavailable),
                    "actual map contention blocked or authorized instead of unavailable",
                )?;
                require(
                    matches!(
                        fixture.app_metadata(&auth).await,
                        Err(AppError::DependencyUnavailable {
                            dependency: "host_request_binding"
                        })
                    ),
                    "map contention did not project static binding 503",
                )?;
            }
            require(
                verify(&auth).await.is_ok(),
                "released actual map contention closed its live binding",
            )?;
            let windows = protocol.windows.clone();
            require(
                std::thread::spawn(move || {
                    let _held = windows.write().expect("unpoisoned owned map");
                    panic!("controlled owned Local window-map poison");
                })
                .join()
                .is_err(),
                "controlled actual map poison did not occur",
            )?;
            require(
                verify(&auth).await == Err(HostRequestBindingError::Unavailable),
                "actual poisoned map was treated as current or absent authority",
            )?;
            require(
                matches!(
                    fixture.app_metadata(&auth).await,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "actual poisoned map did not produce binding dependency 503",
            )?;
            require(
                fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
                "unavailable actual map preguard entered artifact PG",
            )?;
            fixture.unchanged(&facts).await
        })
    })
    .await;
}
