//! R454 H12: actual owned installation, attested sidecar, sealed canary and original window.
//! This is finite test-owned Local authority coverage, not release supervisor/GUI/Keychain readiness.
use super::DesktopTauriProtocol;
use crate::{InProcessTransport, local_confirmation_authority::PostgresLocalConfirmationAuthority};
use openbot_application::{
    ApplicationService, BeginThreadRunRequest, OpenBotApplication, RunRuntime, RunTerminal,
    ThreadDirectory,
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
        PostgresThreadHistoryAuthority, ThreadHistoryObservationError as Error,
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
type TestResult<T = ()> = Result<T, String>;
fn require(value: bool, error: &'static str) -> TestResult {
    if value { Ok(()) } else { Err(error.to_owned()) }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
const BOT: &str = "owned-history-local-bot";
const PROCESS: &str = "owned-history-local-runtime";
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
            "history_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    let app_root = std::env::temp_dir().join(format!("openbot-history-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obhistory-{id}"));
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
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('owned-history-local-bot','Owned history Local','built_in','{}')").await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES($1,$2,'Owned history Local','fixture','fixture','public')",&[&BOT,&original.actor().as_str()]).await.map_err(|e|e.to_string())?;
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
        let req = BeginThreadRunRequest {
            deployment: original.deployment().clone(),
            tenant: original.tenant().clone(),
            actor: original.actor().clone(),
            auth_generation: original.auth_generation(),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(original.deployment()).mint_from_entropy([0x45; 16]),
                run_id: RunId::new("owned-history-local-run"),
                bot_id: BotId::new(BOT),
                anchor: ThreadRunAnchor::DirectBot,
                message: "OWNED_HISTORY_LOCAL_BODY_CANARY café".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        directory
            .begin_thread_run(req.clone())
            .await
            .map_err(|e| e.to_string())?;
        let runtime = PostgresRunRuntime::new(
            p.clone(),
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
            lease.run_id() == &req.command.run_id,
            "owned Local dispatch claimed different Run",
        )?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(|e| e.to_string())?;
        drop(runtime);
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
    async fn sql(&self, sql: &str) -> TestResult {
        self.pool()
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
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
async fn refused(f: &LocalFixture, auth: &AuthContext) -> TestResult {
    require(
        f.authority
            .observe_management_before(auth, &f.j, deadline())
            .await
            .is_err(),
        "stale Local Host or current canary accepted",
    )
}

#[tokio::test]
#[ignore = "requires explicitly owned PG17 binaries; starts and proves stop of its own Local sidecar"]
async fn thread_history_management_real_local_canary_window_and_deadline_closure_are_required() {
    const NAME: &str =
        "thread_history_management_real_local_canary_window_and_deadline_closure_are_required";
    let f = LocalFixture::new()
        .await
        .unwrap_or_else(|e| panic!("{NAME} actual Local setup: {e}"));
    let outcome:TestResult=async {
  let protocol=f.protocol()?;protocol.bind_window("main",f.original.clone(),None).map_err(|e|e.to_string())?;
  let first=f.bound(&protocol)?;f.eligible(&first).await?;
  // Mint the genuine Host from nonnull zero, then exercise only the new purpose's NULL0 rule.
  f.sql("UPDATE public.users SET auth_generation=NULL WHERE id='desktop-local-user'").await?;f.eligible(&first).await?;
  require(first.request_binding().ok_or("genuine Local binding missing")?.verify_current(&first).await==Err(HostRequestBindingError::NotCurrent),"old general Local binding raw-NULL refusal changed")?;
  f.sql("UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'").await?;
  // Real canary mismatch: leave the original proof untouched, mutate and restore the persisted tuple.
  let encrypted:String=f.pool().get().await.map_err(|e|e.to_string())?.query_one("SELECT encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",&[&f.original.deployment().as_str(),&f.original.tenant().as_str()]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
  {let c=f.pool().get().await.map_err(|e|e.to_string())?;let bad=format!("{encrypted}A");c.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$3 WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",&[&f.original.deployment().as_str(),&f.original.tenant().as_str(),&bad]).await.map_err(|e|e.to_string())?;}
  refused(&f,&first).await?;
  {let c=f.pool().get().await.map_err(|e|e.to_string())?;c.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$3 WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",&[&f.original.deployment().as_str(),&f.original.tenant().as_str(),&encrypted]).await.map_err(|e|e.to_string())?;}
  f.eligible(&first).await?;
  for (bad,restore) in [("UPDATE public.users SET auth_generation=1 WHERE id='desktop-local-user'","UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'"),("DELETE FROM public.user_roles WHERE user_id='desktop-local-user'","INSERT INTO public.user_roles(user_id,role) VALUES('desktop-local-user','admin')"),("INSERT INTO public.revoked_access(email,revoked_by) VALUES('desktop-local@localhost.invalid','desktop-local-user')","DELETE FROM public.revoked_access WHERE email='desktop-local@localhost.invalid'")]{f.sql(bad).await?;refused(&f,&first).await?;f.sql(restore).await?;f.eligible(&first).await?;}
  // The actual original actor lock proves that withdrawal happens before the fresh joint.
  let mut writer=f.pool().get().await.map_err(|e|e.to_string())?;let pid:i32=writer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
  let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",&[&f.original.actor().as_str()]).await.map_err(|e|e.to_string())?;
  let authority=f.authority.clone();let auth=first.clone();let j=f.j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&auth,&j,deadline()).await});let blocked=wait_actor(f.pool(),pid).await?;
  require(protocol.unbind_window("main").map_err(|e|e.to_string())?,"original Local window withdrawal absent")?;protocol.bind_window("main",f.original.clone(),None).map_err(|e|e.to_string())?;
  let next=f.bound(&protocol)?;require(!first.request_binding().unwrap().identity().same_binding(next.request_binding().unwrap().identity()),"same label reused old Local epoch")?;
  tx.rollback().await.map_err(|e|e.to_string())?;require(task.await.map_err(|e|e.to_string())?.is_err(),"withdrawn Local window escaped actual actor wait")?;drop(writer);f.eligible(&next).await?;
  eprintln!("THREAD_HISTORY_OBSERVATION id=H12 actual_actor_wait_pid={blocked} original_writer_pid={pid} old_window_refused=true new_original_epoch_valid=true original_rollback_ack=true");
  // Original deadline includes the real actor wait. It is never renewed for a later stage.
  let mut writer=f.pool().get().await.map_err(|e|e.to_string())?;let pid:i32=writer.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;let tx=writer.transaction().await.map_err(|e|e.to_string())?;tx.execute("UPDATE public.users SET auth_generation=auth_generation WHERE id=$1",&[&f.original.actor().as_str()]).await.map_err(|e|e.to_string())?;
  let original=Instant::now()+Duration::from_secs(2);let authority=f.authority.clone();let auth=next.clone();let j=f.j.clone();let task=tokio::spawn(async move{authority.observe_management_before(&auth,&j,original).await});let _=wait_actor(f.pool(),pid).await?;
  require(!task.is_finished(),"original Local observer ended before the real actor lock wait")?;
  let result=tokio::time::timeout_at(tokio::time::Instant::from_std(original+Duration::from_secs(1)),task).await.map_err(|_|"original Local deadline renewed during the actor lock wait")?.map_err(|e|e.to_string())?;require(matches!(result,Err(Error::Unavailable|Error::DeadlineExceeded|Error::RollbackUnproven|Error::RollbackAcknowledgedAfterDeadline)),"original Local lock deadline unexpectedly granted snapshot")?;
  require(Instant::now()<=original+Duration::from_secs(1),"original Local deadline renewed during the actor lock wait")?;tx.rollback().await.map_err(|e|e.to_string())?;drop(writer);f.eligible(&next).await?;
  // The original Protocol's owner close is observable, and does not change the stored origin.
  drop(protocol);require(matches!(f.authority.observe_management_before(&next,&f.j,deadline()).await,Err(Error::Host(_))),"closed original Local protocol remained a valid Host")?;
  eprintln!("THREAD_HISTORY_OBSERVATION id=H12 genuine_from_desktop_canary=true same_attested_pool=true snapshots_write_nothing=true original_deadline_not_renewed=true actual_RowDecode_credit=0");Ok(())
 }.await;
    let cleanup = f.finish(NAME).await;
    outcome.unwrap_or_else(|e| panic!("{NAME} failed: {e}"));
    cleanup.unwrap_or_else(|e| panic!("{NAME} original owned closure failed: {e}"));
}
