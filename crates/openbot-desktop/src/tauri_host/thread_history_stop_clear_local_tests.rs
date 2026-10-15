//! V7-IMPL-038 Desktop Local window Host case: the actual owned installation, attested sidecar,
//! sealed canary and original window drive the one-J stop/clear intent producer. This is finite
//! test-owned Local authority coverage, not release supervisor/GUI/Keychain readiness.
//!
//! Known limit: the Local sidecar pool connects to PostgreSQL directly, so no relay can withhold
//! a real ROLLBACK or COMMIT acknowledgement here. The withheld-acknowledgement cases belong to
//! the Server cases of the same producer; this module proves the Local Host, window epoch and
//! owner behavior around the producer's one original transaction.
use super::DesktopTauriProtocol;
use crate::{InProcessTransport, local_confirmation_authority::PostgresLocalConfirmationAuthority};
use openbot_application::{
    ApplicationService, BeginThreadRunRequest, OpenBotApplication, RunRuntime, RunTerminal,
    ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::{
    auth::AuthContext,
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{BotId, RunId},
    request_binding::HostRequestBindingError,
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
    thread_history_authority::{
        PostgresThreadHistoryAuthority, ThreadHistoryStopClearConfirmation as Confirmation,
        ThreadHistoryStopClearError as Stop, ThreadHistoryStopClearIntent as Intent,
    },
    thread_listener::ThreadListenerDatabase,
};
use serde_json::Value;
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
type Close = Result<Intent, Stop>;
fn require(value: bool, error: &'static str) -> TestResult {
    if value { Ok(()) } else { Err(error.to_owned()) }
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn request_id() -> String {
    Uuid::now_v7().to_string()
}
const BOT: &str = "owned-stopclear-local-bot";
const PROCESS: &str = "owned-stopclear-local-runtime";
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
            "stop_clear_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    let app_root = std::env::temp_dir().join(format!("openbot-stopclear-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obstop-{id}"));
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

/// The one Run request of this fixture's Thread. A further Run on the same J differs in `run` only.
fn begin_request(original: &AuthContext, run: &str) -> BeginThreadRunRequest {
    BeginThreadRunRequest {
        deployment: original.deployment().clone(),
        tenant: original.tenant().clone(),
        actor: original.actor().clone(),
        auth_generation: original.auth_generation(),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: ThreadIdentity::new(original.deployment()).mint_from_entropy([0x45; 16]),
            run_id: RunId::new(run),
            bot_id: BotId::new(BOT),
            anchor: ThreadRunAnchor::DirectBot,
            message: "OWNED_STOP_CLEAR_LOCAL_BODY_CANARY café".into(),
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

/// The call was refused by the actual Host, and the closed reason is exactly `NotCurrent`: a
/// withdrawn window epoch of the same actor and label, like a closed owner, is no longer current.
/// `Missing`, `Unavailable` and every other result do not count.
fn host_not_current(r: &Close) -> TestResult {
    match r {
        Err(Stop::Host(HostRequestBindingError::NotCurrent)) => Ok(()),
        Err(other) => Err(format!("expected Host(NotCurrent), got {other:?}")),
        Ok(intent) => Err(format!("expected Host(NotCurrent), got {intent:?}")),
    }
}

/// The exact acknowledged-commit result for this request; returns the new operation id.
fn committed(r: &Close, auth: &AuthContext, j: &str, request: &str) -> TestResult<String> {
    let intent = r.as_ref().map_err(|e| format!("not committed: {e:?}"))?;
    require(
        intent.confirmation() == Confirmation::CommitAcknowledged
            && intent.request_id() == request
            && intent.thread_id().as_str() == j
            && intent.deployment_id() == auth.deployment()
            && intent.tenant_id() == auth.tenant(),
        "result is not the exact acknowledged commit for this J and request",
    )?;
    let operation = intent.operation_id();
    let shown = format!("{intent:?}");
    require(
        !shown.contains(operation) && !shown.contains(j) && !shown.contains(request),
        "the result's Debug output leaks an identifier",
    )?;
    let parsed = Uuid::parse_str(operation).map_err(text)?;
    require(
        parsed.get_version_num() == 7 && parsed.hyphenated().to_string() == operation,
        "operation id is not canonical lowercase UUIDv7",
    )?;
    Ok(operation.to_owned())
}

/// The exact replay of an earlier intent: its original operation id, no new write.
fn replayed(r: &Close, j: &str, request: &str, operation: &str) -> TestResult {
    let intent = r.as_ref().map_err(|e| format!("not replayed: {e:?}"))?;
    require(
        intent.confirmation() == Confirmation::ExactReplayRollbackAcknowledged
            && intent.request_id() == request
            && intent.thread_id().as_str() == j
            && intent.operation_id() == operation,
        "result is not the exact replay with the original operation id",
    )
}

/// Whether two windows of the same label belong to the same binding epoch.
fn same_window_epoch(a: &AuthContext, b: &AuthContext) -> TestResult<bool> {
    let a = a.request_binding().ok_or("Local window binding missing")?;
    let b = b.request_binding().ok_or("Local window binding missing")?;
    Ok(a.identity().same_binding(b.identity()))
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
        require(
            original.auth_generation().get() == 0 && original.is_single_user(),
            "initial genuine Local principal must be nonnull generation zero",
        )?;
        {
            let c = p.get().await.map_err(|e| e.to_string())?;
            let raw: Option<i64> = c
                .query_one(
                    "SELECT auth_generation FROM public.users WHERE id=$1",
                    &[&original.actor().as_str()],
                )
                .await
                .map_err(|e| e.to_string())?
                .try_get(0)
                .map_err(|e| e.to_string())?;
            require(
                raw == Some(0),
                "Host fixture initial canonical row is not nonnull zero",
            )?;
        }
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
            .map_err(|e| format!("{e:?}"))?,
        );
        authority
            .enroll_original_registry(&registry)
            .map_err(|e| format!("{e:?}"))?;
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            p.clone(),
        ));
        source
            .install_thread_history_authority(&authority)
            .map_err(|e| format!("{e:?}"))?;
        {
            let c = p.get().await.map_err(|e| e.to_string())?;
            c.execute(
                "INSERT INTO public.agents(id,name,type,configuration) VALUES($1,'Owned stop clear Local','built_in','{}')",
                &[&BOT],
            )
            .await
            .map_err(|e| e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES($1,$2,'Owned stop clear Local','fixture','fixture','public')",&[&BOT,&original.actor().as_str()]).await.map_err(|e|e.to_string())?;
        }
        let listener =
            ThreadListenerDatabase::desktop_local(desktop.port, TEST_PASSWORD.as_bytes())
                .map_err(|e| e.to_string())?;
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            listener,
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let req = begin_request(&original, "owned-stopclear-local-run");
        directory
            .begin_thread_run(req.clone())
            .await
            .map_err(|e| e.to_string())?;
        settle_dispatch(p, &req.command.run_id).await?;
        let application: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(ChannelRepo::new(p.clone())));
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
        .map_err(|e| format!("{e:?}"))
    }
    fn bound(&self, protocol: &DesktopTauriProtocol) -> TestResult<AuthContext> {
        protocol
            .windows
            .read()
            .map_err(|_| "owned Local window map unreadable")?
            .get("main")
            .map(|w| w.auth.clone())
            .ok_or_else(|| "owned Local current window missing".into())
    }
    /// Withdraw the current "main" window and bind the same label again: the same actor under a
    /// new epoch. The previous epoch's Auth must stay refused from then on.
    fn rebind(
        &self,
        protocol: &DesktopTauriProtocol,
        previous: &AuthContext,
    ) -> TestResult<AuthContext> {
        require(
            protocol.unbind_window("main").map_err(text)?,
            "original Local window withdrawal absent",
        )?;
        protocol
            .bind_window("main", self.original.clone(), None)
            .map_err(text)?;
        let next = self.bound(protocol)?;
        require(
            !same_window_epoch(previous, &next)?,
            "same label reused old Local epoch",
        )?;
        Ok(next)
    }
    async fn facts(&self) -> TestResult<Value> {
        let c = self.pool().get().await.map_err(|e| e.to_string())?;
        let mut facts = serde_json::Map::new();
        for table in [
            "public.users",
            "public.user_roles",
            "public.revoked_access",
            "public.threads",
            "public.thread_memberships",
            "public.messages",
            "public.runs",
            "public.run_events",
            "public.outbox",
            "openbot_internal.thread_origins",
            "openbot_internal.desktop_vault_canaries",
            "openbot_internal.artifact_dataset_bindings",
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM {table} t) q"
            );
            let value: Value = c
                .query_one(&sql, &[])
                .await
                .map_err(|e| e.to_string())?
                .try_get(0)
                .map_err(|e| e.to_string())?;
            facts.insert(table.into(), value);
        }
        Ok(Value::Object(facts))
    }
    async fn eligible(&self, auth: &AuthContext) -> TestResult {
        let before = self.facts().await?;
        let observed = self
            .authority
            .observe_management_before(auth, &self.j, deadline())
            .await
            .map_err(|e| format!("{e:?}"))?;
        require(
            observed.deployment_id() == self.original.deployment()
                && observed.tenant_id() == self.original.tenant()
                && observed.thread_id().as_str() == self.j,
            "Local snapshot differs from exact J",
        )?;
        require(
            before == self.facts().await?,
            "Local observer wrote business/canary/origin facts",
        )
    }
    /// One producer call for the exact J of this fixture.
    async fn close(&self, auth: &AuthContext, request: &str) -> Close {
        self.authority
            .close_for_stop_clear_before(auth, &self.j, request, deadline())
            .await
    }
    /// One producer call as its own task, so a test can hold the actor row from outside.
    fn spawn_close(&self, auth: &AuthContext, request: &str) -> tokio::task::JoinHandle<Close> {
        let authority = Arc::clone(&self.authority);
        let (auth, j, request) = (auth.clone(), self.j.clone(), request.to_owned());
        tokio::spawn(async move {
            authority
                .close_for_stop_clear_before(&auth, &j, &request, deadline())
                .await
        })
    }
    /// Both whole tables with row versions: any rewrite, new row or repair changes this value.
    async fn hq(&self) -> TestResult<Value> {
        let c = self.pool().get().await.map_err(text)?;
        let mut out = serde_json::Map::new();
        for (name, order) in [
            ("openbot_internal.thread_history_heads", "x.thread_id"),
            (
                "openbot_internal.thread_history_clear_intents",
                "x.operation_id",
            ),
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(x)||jsonb_build_object('xmin',x.xmin::text) ORDER BY {order}),'[]'::jsonb) FROM {name} x"
            );
            let value: Value = c
                .query_one(&sql, &[])
                .await
                .map_err(text)?
                .try_get(0)
                .map_err(text)?;
            out.insert(name.into(), value);
        }
        Ok(Value::Object(out))
    }
    async fn intents(&self) -> TestResult<i64> {
        self.pool()
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT count(*) FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1",
                &[&self.j],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    async fn phase(&self) -> TestResult<Option<String>> {
        let c = self.pool().get().await.map_err(text)?;
        let row = c
            .query_opt(
                "SELECT phase FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
                &[&self.j],
            )
            .await
            .map_err(text)?;
        row.map(|r| r.try_get(0).map_err(text)).transpose()
    }
    /// Backends other than this one that sit idle inside an open transaction: a producer that
    /// returned without its terminal statement would leave one behind.
    async fn idle_in_tx(&self) -> TestResult<i64> {
        self.pool()
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE state LIKE 'idle in transaction%' AND pid<>pg_backend_pid()",
                &[],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    /// A refused producer call leaves H and Q (with row versions) and every original fact as they
    /// were, and no transaction open.
    async fn nothing_written(&self, hq: &Value, facts: &Value, leg: &'static str) -> TestResult {
        if *hq != self.hq().await? {
            return Err(format!("{leg}: H or Q changed"));
        }
        if *facts != self.facts().await? {
            return Err(format!("{leg}: an original fact changed"));
        }
        let open = self.idle_in_tx().await?;
        if open != 0 {
            return Err(format!(
                "{leg}: {open} backend(s) left idle in a transaction"
            ));
        }
        Ok(())
    }
    /// Independent exact check of the stored Q and the H closed from it.
    async fn stored(
        &self,
        auth: &AuthContext,
        request: &str,
        operation: &str,
        generation: i64,
    ) -> TestResult {
        let c = self.pool().get().await.map_err(text)?;
        let row = c
            .query_one(
                "SELECT (SELECT count(*) FROM openbot_internal.thread_history_clear_intents WHERE thread_id=$1) AS q_rows, \
                        (SELECT count(*) FROM openbot_internal.thread_history_heads WHERE thread_id=$1) AS h_rows, \
                        EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_intents q \
                               JOIN openbot_internal.thread_history_heads h ON h.thread_id=q.thread_id \
                               JOIN public.threads t ON t.thread_id=q.thread_id \
                               WHERE q.thread_id=$1 AND q.deployment_id=$2 AND q.tenant_id=$3 \
                                 AND q.intent_schema=1 AND q.intent_kind='stop_clear' AND q.operation_id=$4 \
                                 AND q.request_id=$5 AND q.actor_id=$6 AND q.auth_generation=$7 \
                                 AND q.anchor_kind=t.anchor_kind AND q.anchor_id=t.anchor_id \
                                 AND q.thread_created_at=t.created_at \
                                 AND h.head_schema=1 AND h.phase='closed' AND h.closure_operation_id=q.operation_id \
                                 AND h.closure_request_id=q.request_id AND h.closure_actor_id=q.actor_id \
                                 AND h.closure_auth_generation=q.auth_generation AND h.closed_at=q.recorded_at \
                                 AND h.anchor_kind=q.anchor_kind AND h.anchor_id=q.anchor_id \
                                 AND h.thread_created_at=q.thread_created_at) AS exact",
                &[
                    &self.j,
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &operation,
                    &request,
                    &auth.actor().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(text)?;
        let q: i64 = row.try_get("q_rows").map_err(text)?;
        let h: i64 = row.try_get("h_rows").map_err(text)?;
        let exact: bool = row.try_get("exact").map_err(text)?;
        require(
            q == 1 && h == 1 && exact,
            "stored Q/H pair is not the exact single acknowledged intent",
        )
    }
    /// A further Run request for the fixture's Thread: only the Run id differs from the first.
    fn further_run(&self, run: &str) -> TestResult<BeginThreadRunRequest> {
        let request = begin_request(&self.original, run);
        require(
            request.command.thread_id.as_str() == self.j,
            "rebuilt Run request names another Thread",
        )?;
        Ok(request)
    }
    /// The Thread holds exactly `expected` Runs and all of them are completed: none is queued or
    /// running.
    async fn runs_all_completed(&self, expected: i64) -> TestResult {
        let row = self
            .pool()
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT count(*) AS runs, count(*) FILTER (WHERE status='completed') AS completed, \
                        count(*) FILTER (WHERE status IN ('queued','running')) AS live \
                 FROM public.runs WHERE thread_id=$1",
                &[&self.j],
            )
            .await
            .map_err(text)?;
        let runs: i64 = row.try_get("runs").map_err(text)?;
        let completed: i64 = row.try_get("completed").map_err(text)?;
        let live: i64 = row.try_get("live").map_err(text)?;
        require(
            runs == expected && completed == expected && live == 0,
            "the Thread does not hold exactly the expected completed Runs and no live Run",
        )
    }
    /// Positive control for `begin_again_refused`: while H is open a further Run on the same J is
    /// admitted as a new Run. It is run to its terminal state at once, so the Thread holds no live
    /// Run afterwards and only the closure can refuse the next one.
    async fn open_admits_further_run(&self) -> TestResult {
        let further = self.further_run("owned-stopclear-local-run-open")?;
        let started = self
            .directory
            .begin_thread_run(further.clone())
            .await
            .map_err(text)?;
        require(
            started.thread_id.as_str() == self.j
                && started.run_id == further.command.run_id
                && !started.replayed,
            "open Local J did not admit the further Run as a new Run",
        )?;
        settle_dispatch(self.pool(), &further.command.run_id).await?;
        self.runs_all_completed(2).await
    }
    /// A further new Run on the same J; only a closed H may make this refuse.
    async fn begin_again_refused(&self) -> TestResult {
        let again = self.further_run("owned-stopclear-local-run-again")?;
        require(
            matches!(
                self.directory.begin_thread_run(again).await,
                Err(ThreadDirectoryError::NotVisible)
            ),
            "closed Local J admitted a new Run",
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
async fn wait_actor(pool: &pool::DatabasePool, blocker: i32) -> TestResult<i32> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let c = pool.get().await.map_err(|e| e.to_string())?;
        let r=c.query_opt("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%users%' AND pid<>pg_backend_pid() LIMIT 1",&[&blocker]).await.map_err(|e|e.to_string())?;
        if let Some(r) = r {
            return r.try_get(0).map_err(|e| e.to_string());
        }
        drop(c);
        require(
            Instant::now() < until,
            "actual Local actor wait was not reached",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The six legs, in order, on one actual Local sidecar and one protocol owner.
async fn exercise(f: &LocalFixture) -> TestResult {
    // L0: the genuine original window is eligible, H is open and there is no intent. While H is
    // open a further Run on the same J is admitted and run to its terminal state first; that is
    // the positive control for the refusal L3 expects after the closure. Only then is the baseline
    // taken.
    let protocol = f.protocol()?;
    protocol
        .bind_window("main", f.original.clone(), None)
        .map_err(text)?;
    let first = f.bound(&protocol)?;
    f.eligible(&first).await?;
    require(
        f.phase().await?.as_deref() == Some("open") && f.intents().await? == 0,
        "premise: the Thread head is open and has no intent",
    )?;
    f.open_admits_further_run().await?;
    eprintln!("THREAD_HISTORY_STOP_CLEAR id=L01 leg=L0 open_admits_further_run=true");
    let hq0 = f.hq().await?;
    let facts0 = f.facts().await?;
    require(
        hq0["openbot_internal.thread_history_heads"]
            .as_array()
            .is_some_and(|heads| heads.len() == 1 && heads[0]["phase"] == "open")
            && hq0["openbot_internal.thread_history_clear_intents"]
                .as_array()
                .is_some_and(|intents| intents.is_empty()),
        "premise: exactly one open head and no intent in the whole sidecar",
    )?;
    f.nothing_written(&hq0, &facts0, "L0 baseline").await?;

    // L1: a window withdrawn before the call borrows its Host is refused and nothing is written.
    // The window map now holds another binding id under the label, so the guard's `check_window`
    // answers NotCurrent while the producer borrows its Host, before it takes a connection.
    let second = f.rebind(&protocol, &first)?;
    let request_a = request_id();
    host_not_current(&f.close(&first, &request_a).await)?;
    f.nothing_written(&hq0, &facts0, "L1 stale window before borrow")
        .await?;
    eprintln!("THREAD_HISTORY_STOP_CLEAR id=L01 leg=L1 host_refusal=NotCurrent");

    // L2: the window is withdrawn while the producer's original transaction waits for the actor
    // row. The refusal comes after the wait ends (the Host tail witness of the first fresh joint
    // statement finds another binding id under the label and answers NotCurrent), and its ROLLBACK
    // leaves nothing behind.
    let request_b = request_id();
    let mut writer = f.pool().get().await.map_err(text)?;
    let writer_pid: i32 = writer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)?;
    let tx = writer.transaction().await.map_err(text)?;
    tx.execute(
        "UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",
        &[&f.original.actor().as_str()],
    )
    .await
    .map_err(text)?;
    // Positive control for every idle-in-transaction count of this case: this open writer shows.
    require(
        f.idle_in_tx().await? == 1,
        "the open writer transaction is not visible as idle in transaction",
    )?;
    let task = f.spawn_close(&second, &request_b);
    let actor_wait_pid = wait_actor(f.pool(), writer_pid).await?;
    let third = f.rebind(&protocol, &second)?;
    tx.rollback().await.map_err(text)?;
    drop(writer);
    host_not_current(&task.await.map_err(text)?)?;
    f.nothing_written(&hq0, &facts0, "L2 stale window inside the transaction")
        .await?;
    eprintln!(
        "THREAD_HISTORY_STOP_CLEAR id=L01 leg=L2 actual_actor_wait_pid={actor_wait_pid} original_writer_pid={writer_pid} host_refusal=NotCurrent"
    );

    // L3: the current window closes J with the very request id L1 was refused with. The H/Q
    // snapshot (row versions included) is taken right after the stored pair was checked, and every
    // later step has to leave it exactly as it is.
    let closed = f.close(&third, &request_a).await;
    let operation = committed(&closed, &third, &f.j, &request_a)?;
    f.stored(&third, &request_a, &operation, 0).await?;
    let hq1 = f.hq().await?;
    require(
        facts0 == f.facts().await?,
        "the producer changed an original fact other than H and Q",
    )?;
    f.begin_again_refused().await?;
    require(
        hq1 == f.hq().await?,
        "the refused further Run changed H or Q",
    )?;
    f.authority
        .observe_management_before(&third, &f.j, deadline())
        .await
        .map_err(text)?;
    require(hq1 == f.hq().await?, "the 034 observer changed H or Q")?;
    let replay = f.close(&third, &request_a).await;
    replayed(&replay, &f.j, &request_a, &operation)?;
    f.nothing_written(&hq1, &facts0, "L3 exact replay").await?;

    // L4: a window withdrawn after the commit is refused and does not poison its successor.
    let fourth = f.rebind(&protocol, &third)?;
    host_not_current(&f.close(&third, &request_a).await)?;
    f.nothing_written(&hq1, &facts0, "L4 stale window after commit")
        .await?;
    let replay = f.close(&fourth, &request_a).await;
    replayed(&replay, &f.j, &request_a, &operation)?;
    f.nothing_written(&hq1, &facts0, "L4 exact replay").await?;
    eprintln!(
        "THREAD_HISTORY_STOP_CLEAR id=L01 leg=L4 host_refusal=NotCurrent operation_unchanged=true"
    );

    // L5: once the protocol owner closes, even the last current window is refused, and the reason
    // is exactly NotCurrent. Dropping the protocol closes its owner lease synchronously. The first
    // check that refuses here is the closed-owner check of `CurrentThreadHistoryRequest::borrow`
    // (`!issuer.observation().is_current()`), which answers NotCurrent before any window map,
    // identity source or statement is consulted. Only these checks run ahead of it, and none of
    // them fires in this case: the input validation of `close_for_stop_clear_before` (InvalidInput;
    // both ids are valid), the remaining deadline (Unavailable; the deadline is taken afresh with 5
    // seconds), `scope` (NotVisible for a foreign scope or role, Unavailable for a closed Pool;
    // scope and role fit and the Pool is open), the enrolled issuer (Unavailable; `f.protocol()`
    // enrolled it with the authority and that enrollment outlives the protocol) and the binding
    // (Missing; `fourth` carries one). The window guard behind it would answer NotCurrent first for
    // a closed owner as well (`check_window`), so neither its window-map branch nor its
    // missing-source branch (Unavailable) is ever reached.
    drop(protocol);
    host_not_current(&f.close(&fourth, &request_a).await)?;
    f.nothing_written(&hq1, &facts0, "L5 owner closed").await?;
    eprintln!("THREAD_HISTORY_STOP_CLEAR id=L01 leg=L5 host_refusal=NotCurrent");

    eprintln!(
        "THREAD_HISTORY_STOP_CLEAR id=L01 actual_actor_wait_pid={actor_wait_pid} stale_before_borrow_refused=true stale_in_tx_refused=true commit_ack=true exact_replay=true stale_after_commit_refused=true owner_closed_refused=true"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned PostgreSQL17.11 binaries via OPENBOT_TEST_PG_BIN"]
async fn thread_history_stop_clear_real_local_window_closes_and_stale_window_refuses() {
    const NAME: &str =
        "thread_history_stop_clear_real_local_window_closes_and_stale_window_refuses";
    let f = LocalFixture::new()
        .await
        .unwrap_or_else(|e| panic!("{NAME} actual Local setup: {e}"));
    let outcome = exercise(&f).await;
    let cleanup = f.finish(NAME).await;
    outcome.unwrap_or_else(|e| panic!("{NAME} failed: {e}"));
    cleanup.unwrap_or_else(|e| panic!("{NAME} original owned closure failed: {e}"));
}
