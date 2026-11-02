//! V7-IMPL-031 part 1 Desktop Local window Host case: the actual owned installation, attested
//! sidecar, sealed canary and original window drive the public history deletion route through the
//! real protocol and Application. This is finite test-owned Local coverage, not release
//! supervisor/GUI/Keychain readiness.
use super::DesktopTauriProtocol;
use crate::{InProcessTransport, local_confirmation_authority::PostgresLocalConfirmationAuthority};
use http::{Method, Request, Response, StatusCode};
use openbot_application::{
    ApplicationService, BeginThreadRunRequest, OpenBotApplication, RunRuntime, RunTerminal,
    ThreadDirectory,
};
use openbot_contracts::{
    auth::AuthContext,
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{BotId, RunId},
};
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    seal_desktop_vault_canary,
};
use openbot_infra::{
    artifact_registry::ArtifactDatasetRegistry,
    auth::single_user::desktop_local::{
        CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
    },
    db::{
        desktop_local::{DesktopLocalDatabase, connect_for_attestation},
        desktop_vault_canary, fresh, pool,
    },
    repo::ChannelRepo,
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory},
    thread_history_authority::PostgresThreadHistoryAuthority,
    thread_listener::ThreadListenerDatabase,
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::TcpListener,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
type TestResult<T = ()> = Result<T, String>;
fn require(value: bool, error: &'static str) -> TestResult {
    if value { Ok(()) } else { Err(error.to_owned()) }
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}
const BOT: &str = "owned-delete-local-bot";
const PROCESS: &str = "owned-delete-local-runtime";
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

/// Removes only the paths this test created with create_new, after stopping its own PostgreSQL;
/// no user directory is touched.
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
            "history_deletion_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    let app_root = std::env::temp_dir().join(format!("openbot-delete-local-{id}"));
    // A PostgreSQL Unix socket path is short; it is still a create_new path owned by this test.
    let socket_dir = PathBuf::from("/tmp").join(format!("obdel-{id}"));
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
    let captured_postmaster_pid = sidecar.read_owned_postmaster_pid()?;
    sidecar.postmaster_pid = Some(captured_postmaster_pid);
    eprintln!(
        "HISTORY_DELETION_TEST_OWNED_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={captured_postmaster_pid} controlled_app_root={} original_PID_file={}/postmaster.pid data_dir={} socket_root={}",
        sidecar.app_root.display(),
        sidecar.data_dir.display(),
        sidecar.data_dir.display(),
        sidecar.socket_dir.display()
    );
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

/// The one Run request of this fixture's Thread. A further Run on the same J differs in `run` only.
fn begin_request(original: &AuthContext, run: &str) -> BeginThreadRunRequest {
    BeginThreadRunRequest {
        deployment: original.deployment().clone(),
        tenant: original.tenant().clone(),
        actor: original.actor().clone(),
        auth_generation: original.auth_generation(),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: ThreadIdentity::new(original.deployment()).mint_from_entropy([0x46; 16]),
            run_id: RunId::new(run),
            bot_id: BotId::new(BOT),
            anchor: ThreadRunAnchor::DirectBot,
            message: "OWNED_HISTORY_DELETION_LOCAL_BODY_CANARY café".into(),
            selected_skill_slugs: vec![],
            model_selection: None,
        },
    }
}

/// Claim, acknowledge and complete the one pending dispatch, which must be `run`'s own: the
/// Thread then holds no live Run of that dispatch.
async fn settle_dispatch(pool: &pool::DatabasePool, run: &RunId) -> TestResult {
    let runtime = PostgresRunRuntime::new(
        pool.clone(),
        PROCESS.into(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
            &pool,
            &openbot_contracts::ids::DeploymentId::new("outside"),
            &openbot_contracts::ids::TenantId::new("outside"),
        ),
    )
    .map_err(|e| e.to_string())?;
    let claim = runtime
        .claim_dispatch()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("owned Local real dispatch missing")?;
    let lease = runtime
        .acknowledge_dispatch(&claim)
        .await
        .map_err(|e| e.to_string())?;
    require(
        lease.run_id() == run,
        "owned Local dispatch claimed different Run",
    )?;
    runtime
        .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
        .await
        .map_err(|e| e.to_string())
        .map(|_| ())
}

struct LocalFixture {
    desktop: OwnedDesktop,
    original: AuthContext,
    source: Arc<PostgresLocalConfirmationAuthority>,
    authority: Arc<PostgresThreadHistoryAuthority>,
    registry: Arc<ArtifactDatasetRegistry>,
    application: Arc<dyn ApplicationService>,
    directory: PostgresThreadDirectory,
    assets: PathBuf,
    j: String,
}
impl LocalFixture {
    async fn new() -> TestResult<Self> {
        let desktop = start_owned_desktop().await?;
        let p = desktop.database.pool();
        desktop
            .installation
            .authority()
            .provision_postgres(p)
            .await
            .map_err(|e| e.to_string())?;
        let original = desktop
            .installation
            .authority()
            .load_runtime_auth_context(p)
            .await
            .map_err(|e| e.to_string())?;
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
            seal_desktop_vault_canary(&master, &binding, Nonce::from_array([0x34; NONCE_BYTES]))
                .map_err(|e| e.to_string())?;
        let row = desktop_vault_canary::DesktopVaultCanaryRow::new(
            &dataset,
            original.deployment().as_str(),
            original.tenant().as_str(),
            &key_id,
            envelope.to_column_value(),
        )
        .map_err(|e| e.to_string())?;
        desktop_vault_canary::insert_once(p, &row)
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
        let authority = Arc::new(
            PostgresThreadHistoryAuthority::new(
                p.clone(),
                original.deployment().clone(),
                original.tenant().clone(),
            )
            .map_err(text)?,
        );
        authority
            .enroll_original_registry(&registry)
            .map_err(text)?;
        authority
            .enroll_clear_audit_checkpoint_key(SecretBytes::new(vec![0x5b; 32]))
            .map_err(text)?;
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            p.clone(),
        ));
        source
            .install_thread_history_authority(&authority)
            .map_err(text)?;
        {
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.execute(
                "INSERT INTO public.agents(id,name,type,configuration) VALUES($1,'Owned delete Local','built_in','{}')",
                &[&BOT],
            )
            .await
            .map_err(|e| e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES($1,$2,'Owned delete Local','fixture','fixture','public')",&[&BOT,&original.actor().as_str()]).await.map_err(|e|e.to_string())?;
        }
        let listener =
            ThreadListenerDatabase::desktop_local(desktop.port, TEST_PASSWORD.as_bytes())
                .map_err(|e| e.to_string())?;
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            listener,
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                &p,
                &openbot_contracts::ids::DeploymentId::new("outside"),
                &openbot_contracts::ids::TenantId::new("outside"),
            ),
        )
        .map_err(|e| e.to_string())?;
        let req = begin_request(&original, "owned-delete-local-run");
        directory
            .begin_thread_run(req.clone())
            .await
            .map_err(|e| e.to_string())?;
        settle_dispatch(p, &req.command.run_id).await?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(ChannelRepo::new(p.clone()))
                .with_thread_history_deletion(authority.clone()),
        );
        let assets = desktop._sidecar.app_root.join("assets");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|e| e.to_string())?;
        fs::write(assets.join("index.html"),"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e|e.to_string())?;
        fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").map_err(|e| e.to_string())?;
        Ok(Self {
            desktop,
            original,
            source,
            authority,
            registry,
            application,
            directory,
            assets,
            j: req.command.thread_id.as_str().into(),
        })
    }
    fn pool(&self) -> &pool::DatabasePool {
        self.desktop.database.pool()
    }
    fn protocol(&self) -> TestResult<DesktopTauriProtocol> {
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map_err(|e| e.to_string())?
        .with_thread_history_identity_source(self.source.clone())
        .map_err(text)
    }
    /// Every history deletion fact with row versions and the Thread's status: any new intent,
    /// batch, completion or soft delete changes this value.
    async fn history_facts(&self) -> TestResult<Value> {
        let c = self.pool().get().await.map_err(text)?;
        c.query_one(
            "SELECT jsonb_build_object(\
               'heads',(SELECT coalesce(jsonb_agg(to_jsonb(x)||jsonb_build_object('xmin',x.xmin::text) ORDER BY thread_id),'[]') FROM openbot_internal.thread_history_heads x),\
               'intents',(SELECT coalesce(jsonb_agg(to_jsonb(x)||jsonb_build_object('xmin',x.xmin::text) ORDER BY operation_id),'[]') FROM openbot_internal.thread_history_clear_intents x),\
               'batches',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY operation_id,batch_seq),'[]') FROM openbot_internal.thread_history_clear_batches x),\
               'completions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY operation_id),'[]') FROM openbot_internal.thread_history_clear_completions x),\
               'threads',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',thread_id,'status',status,'xmin',xmin::text) ORDER BY thread_id),'[]') FROM public.threads))",
            &[],
        )
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)
    }
    /// J is soft deleted and cleared under this request's own stop/clear operation.
    async fn cleared(&self, request: &str) -> TestResult {
        let c = self.pool().get().await.map_err(text)?;
        let exact: bool = c
            .query_one(
                "SELECT t.status='deleted' AND t.deleted_at IS NOT NULL AND t.title IS NULL \
                   AND q.intent_kind='stop_clear' AND q.request_id=$2 AND q.actor_id=$3 \
                   AND c.source='stop_clear' AND c.operation_id=q.operation_id \
                 FROM public.threads t \
                 JOIN openbot_internal.thread_history_clear_intents q ON q.thread_id=t.thread_id \
                 JOIN openbot_internal.thread_history_clear_completions c ON c.thread_id=t.thread_id \
                 WHERE t.thread_id=$1",
                &[&self.j, &request, &self.original.actor().as_str()],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        require(
            exact,
            "J is not cleared and soft deleted under this request's own operation",
        )
    }
    async fn finish(self, test: &'static str) -> TestResult {
        let p = self.desktop.database.pool().clone();
        drop(self.application);
        drop(self.directory);
        drop(self.authority);
        drop(self.source);
        drop(self.registry);
        let observations = p.connection_observations();
        p.close();
        for observation in observations {
            require(
                observation
                    .wait_for_destruction_before(Instant::now() + Duration::from_secs(10))
                    .await
                    .map_err(|e| e.to_string())?
                    == pool::ConnectionDestruction::ConnectionDestroyed,
                "original Local connection destruction unobserved",
            )?;
        }
        drop(p);
        self.desktop.finish(test)
    }
}

fn deletion_request(method: Method, j: &str, body: &str) -> TestResult<Request<Vec<u8>>> {
    Request::builder()
        .method(method)
        .uri(format!("/api/threads/{j}/history/deletions"))
        .header("content-type", "application/json")
        .body(body.as_bytes().to_vec())
        .map_err(text)
}

/// The status and JSON body of a no-store response; every answer of this route is no-store.
fn answered(response: &Response<Vec<u8>>) -> TestResult<(StatusCode, Value)> {
    require(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "the Local deletion route answered without no-store",
    )?;
    let value = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body()).map_err(text)?
    };
    Ok((response.status(), value))
}

/// The legs, in order, on one actual Local sidecar and one protocol owner.
async fn exercise(f: &LocalFixture) -> TestResult {
    let protocol = f.protocol()?;
    protocol
        .bind_window("main", f.original.clone(), None)
        .map_err(text)?;
    let facts = f.history_facts().await?;
    let request = Uuid::now_v7().to_string();
    let body = json!({"requestId": request}).to_string();

    // L1: only POST, and only the closed body with an exact request id; nothing is written.
    let (status, _) = answered(
        &protocol
            .handle("main", deletion_request(Method::GET, &f.j, "")?)
            .await,
    )?;
    require(
        status == StatusCode::METHOD_NOT_ALLOWED,
        "a GET deletion was not 405",
    )?;
    for bad in [
        json!({"requestId": request, "threadId": f.j}).to_string(),
        json!({}).to_string(),
        "not json".to_owned(),
        json!({"requestId": request.to_uppercase()}).to_string(),
        json!({"requestId": "6ba7b810-9dad-41d1-80b4-00c04fd430c8"}).to_string(),
    ] {
        let (status, value) = answered(
            &protocol
                .handle("main", deletion_request(Method::POST, &f.j, &bad)?)
                .await,
        )?;
        require(
            status == StatusCode::BAD_REQUEST && value == json!({"code": "malformed_payload"}),
            "a bad Local deletion body was not 400",
        )?;
    }
    require(
        facts == f.history_facts().await?,
        "a refused Local deletion wrote a history fact",
    )?;
    eprintln!("THREAD_HISTORY_DELETION_LOCAL id=L01 leg=L1 get=405 bad_body=400");

    // L2: a window authority captured before its label was rebound is refused before dispatch.
    let stale = protocol
        .authority("main")
        .map_err(text)?
        .ok_or("owned Local window authority missing")?;
    require(
        protocol.unbind_window("main").map_err(text)?,
        "original Local window withdrawal absent",
    )?;
    let (status, value) = answered(
        &protocol
            .handle("main", deletion_request(Method::POST, &f.j, &body)?)
            .await,
    )?;
    require(
        status == StatusCode::UNAUTHORIZED && value == json!({"code": "unauthenticated"}),
        "an unbound Local window was not 401",
    )?;
    protocol
        .bind_window("main", f.original.clone(), None)
        .map_err(text)?;
    let (status, value) = answered(
        &protocol
            .thread_history_deletion(
                "main",
                deletion_request(Method::POST, &f.j, &body)?,
                stale,
                &f.j,
            )
            .await,
    )?;
    require(
        status == StatusCode::UNAUTHORIZED && value == json!({"code": "unauthenticated"}),
        "a stale Local window authority was not 401",
    )?;
    require(
        facts == f.history_facts().await?,
        "a stale Local window deletion wrote a history fact",
    )?;
    eprintln!("THREAD_HISTORY_DELETION_LOCAL id=L01 leg=L2 unbound=401 stale_authority=401");

    // L3: the current window deletes J; the same request id resumes it until it is cleared.
    let mut cleared = false;
    let mut pending = 0;
    for _ in 0..40 {
        let (status, value) = answered(
            &protocol
                .handle("main", deletion_request(Method::POST, &f.j, &body)?)
                .await,
        )?;
        if status == StatusCode::OK {
            require(
                value == json!({"threadId": f.j, "requestId": request, "state": "cleared"}),
                "the cleared Local receipt differs",
            )?;
            cleared = true;
            break;
        }
        require(
            status == StatusCode::ACCEPTED
                && value == json!({"threadId": f.j, "requestId": request, "state": "pending"}),
            "a Local deletion step was neither the 202 pending nor the 200 cleared receipt",
        )?;
        pending += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    require(cleared, "the Local deletion never cleared")?;
    f.cleared(&request).await?;
    let (status, value) = answered(
        &protocol
            .handle("main", deletion_request(Method::POST, &f.j, &body)?)
            .await,
    )?;
    require(
        status == StatusCode::NOT_FOUND && value == json!({"code": "not_visible"}),
        "a Local resend after the deletion was not 404",
    )?;
    eprintln!(
        "THREAD_HISTORY_DELETION_LOCAL id=L01 leg=L3 pending_resends={pending} cleared=200 soft_deleted=true resend=404"
    );
    drop(protocol);
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL17.11 binaries via OPENBOT_TEST_PG_BIN"]
async fn thread_history_deletion_real_local_window_clears_and_stale_window_refuses() {
    const NAME: &str = "thread_history_deletion_real_local_window_clears_and_stale_window_refuses";
    let f = LocalFixture::new()
        .await
        .unwrap_or_else(|e| panic!("{NAME} actual Local setup: {e}"));
    let outcome = exercise(&f).await;
    let cleanup = f.finish(NAME).await;
    outcome.unwrap_or_else(|e| panic!("{NAME} failed: {e}"));
    cleanup.unwrap_or_else(|e| panic!("{NAME} original owned closure failed: {e}"));
}
