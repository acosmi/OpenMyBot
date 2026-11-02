//! Actual owned installation and attested numeric-loopback/SCRAM Desktop Local database,
//! same production Local collector/service/grant and actual Protocol/App. Native callbacks and
//! foreground dispatch are controlled adapters: no native GUI, Keychain, user DB or full release
//! supervisor/provider readiness is represented. Success requires explicit owned PG stop/PID/
//! app-root/socket-root cleanup; returning a capability deadline is never that receipt.

use super::DesktopTauriProtocol;
use super::runtime_capabilities::DesktopRuntimeCapabilityFactory;
use crate::InProcessTransport;
use crate::local_confirmation::{
    ConfirmationAttempt, NativeCompletionToken, NativeDisposition, NativeOutcome,
};
use crate::local_confirmation_authority::PostgresLocalConfirmationAuthority;
use crate::local_confirmation_host::{LocalConfirmationDispatcher, LocalConfirmationHost};
use crate::local_confirmation_service::{
    FinishLocalConfirmation, LocalConfirmationNative, LocalConfirmationService,
    PrepareLocalConfirmation, sample_now,
};
use async_trait::async_trait;
use http::{Method, Request, StatusCode};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::runtime_capabilities::{
    CapabilityDeadline, RuntimeCapabilitiesCollectionError, RuntimeCapabilitiesCollector,
    RuntimeCapabilitiesFuture, RuntimeCapabilityObservationResult,
};
use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::desktop::local_confirmation::{
    LOCAL_CONFIRMATION_PATH, LocalConfirmationReceipt,
};
use openbot_contracts::error::AppError;
use openbot_contracts::runtime_capabilities::{
    RuntimeCapabilitiesResponse, RuntimeCapabilityId as Id, RuntimeCapabilityReasonCode as Reason,
    RuntimeCapabilityState as State,
};
use openbot_contracts::ui::UiLocale;
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore, DesktopLocalInstallation,
};
use openbot_infra::db::desktop_local::{DesktopLocalDatabase, connect_for_attestation};
use openbot_infra::db::{fresh, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::runtime_capability_facts::{
    PostgresRuntimeCapabilityFacts, RuntimeCapabilityCollectorFactory,
};
use openbot_infra::thread_listener::ThreadListenerDatabase;
use openbot_infra::vault::CredentialRecordVault;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, oneshot};
use url::Url;
const PATH: &str = "/api/me/capabilities";
fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
const TEST_USER: &str = "desktop_admin";

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
            "capability_local_owned_sidecar_receipt test={test} stop_exit=0 postmaster_pid_absent=true old_pid={pid} old_pid_absent=true app_root_removed=true socket_root_removed=true"
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
    password: String,
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
    let app_root = std::env::temp_dir().join(format!("openbot-capability-local-{id}"));
    // PG Unix socket 路径长度有限，仍只使用 create_new 的测试自有路径。
    let socket_dir = PathBuf::from("/tmp").join(format!("obcap-{id}"));
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
    let credential = format!(
        "{}{}",
        uuid::Uuid::now_v7().simple(),
        uuid::Uuid::now_v7().simple()
    );
    let password_file = sidecar.app_root.join(".test-postgres-password");
    let mut password = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&password_file)
        .map_err(|_| "create owned initdb credential failed".to_owned())?;
    writeln!(password, "{credential}")
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
        "CAPABILITY_TEST_OWNED_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={captured_postmaster_pid} controlled_app_root={} original_PID_file={}/postmaster.pid data_dir={} socket_root={}",
        sidecar.app_root.display(),
        sidecar.data_dir.display(),
        sidecar.data_dir.display(),
        sidecar.socket_dir.display()
    );
    let admin = connect_for_attestation(port, SecretBytes::new(credential.as_bytes().to_vec()))
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
        password: credential,
        _sidecar: sidecar,
    })
}

struct NativeEvent {
    completion: Option<NativeCompletionToken>,
    sender: Option<oneshot::Sender<NativeDisposition>>,
    active: Arc<AtomicUsize>,
}
impl NativeEvent {
    fn deliver(&mut self, succeeded: bool) -> Result<(), String> {
        let now = sample_now();
        let outcome = if succeeded {
            NativeOutcome::Succeeded { at: now }
        } else {
            NativeOutcome::Cancelled
        };
        let result = self
            .completion
            .as_ref()
            .ok_or("native completion already retired")?
            .record_outcome(outcome, now)
            .map_err(|_| "controlled native completion was rejected".to_owned())?;
        self.sender
            .take()
            .ok_or("native sender already used")?
            .send(result)
            .map_err(|_| "real confirmation request did not retain native callback".to_owned())
    }
    fn retire(mut self) {
        if let Some(completion) = self.completion.take() {
            completion.native_stopped();
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
impl Drop for NativeEvent {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            completion.native_stopped();
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
struct NativeProbe {
    healthy: AtomicBool,
    starts: AtomicUsize,
    active: Arc<AtomicUsize>,
    ready: Semaphore,
    events: Mutex<VecDeque<NativeEvent>>,
}
impl NativeProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            healthy: AtomicBool::new(true),
            starts: AtomicUsize::new(0),
            active: Arc::new(AtomicUsize::new(0)),
            ready: Semaphore::new(0),
            events: Mutex::new(VecDeque::new()),
        })
    }
    async fn take(&self) -> Result<NativeEvent, String> {
        tokio::time::timeout(Duration::from_secs(2), self.ready.acquire())
            .await
            .map_err(|_| "actual service did not start controlled native owner".to_owned())?
            .map_err(|_| "native ready gate closed".to_owned())?
            .forget();
        self.events
            .lock()
            .map_err(|_| "native owner queue poisoned".to_owned())?
            .pop_front()
            .ok_or_else(|| "native completion queue empty".to_owned())
    }
}
impl LocalConfirmationNative for NativeProbe {
    fn is_available(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
    fn start(
        &self,
        _: UiLocale,
        completion: NativeCompletionToken,
    ) -> Result<oneshot::Receiver<NativeDisposition>, AppError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = oneshot::channel();
        let mut events = self
            .events
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "test_native_owner",
            })?;
        self.active.fetch_add(1, Ordering::SeqCst);
        events.push_back(NativeEvent {
            completion: Some(completion),
            sender: Some(sender),
            active: self.active.clone(),
        });
        self.ready.add_permits(1);
        Ok(receiver)
    }
    fn stop(&self) {
        self.healthy.store(false, Ordering::SeqCst);
        if let Ok(mut events) = self.events.lock() {
            for event in events.drain(..) {
                event.retire();
            }
        }
    }
}
/// Controlled foreground/main-thread scheduling, but admission/install execute the actual
/// Protocol critical sections. This adapter does not attest a Wry/AppKit window.
struct ActualProtocolDispatcher {
    protocol: Weak<DesktopTauriProtocol>,
    native: Weak<NativeProbe>,
}
#[async_trait]
impl LocalConfirmationDispatcher for ActualProtocolDispatcher {
    fn cleanup_on_main_thread(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn is_native_stopped(&self) -> bool {
        self.native
            .upgrade()
            .is_none_or(|native| native.active.load(Ordering::SeqCst) == 0)
    }
    async fn prepare(
        &self,
        label: &str,
        id: u64,
        job: PrepareLocalConfirmation,
    ) -> Result<ConfirmationAttempt, AppError> {
        self.protocol
            .upgrade()
            .ok_or(AppError::Unauthenticated)?
            .prepare_local_confirmation(label, id, job)
    }
    async fn finish(
        &self,
        label: &str,
        id: u64,
        job: FinishLocalConfirmation,
    ) -> Result<LocalConfirmationReceipt, AppError> {
        self.protocol
            .upgrade()
            .ok_or(AppError::Unauthenticated)?
            .finish_local_confirmation(label, id, job)
    }
}
struct FinalizeGate {
    entered: Semaphore,
    released: Semaphore,
}
impl FinalizeGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            released: Semaphore::new(0),
        })
    }
    async fn entered(&self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(2), self.entered.acquire())
            .await
            .map_err(|_| "actual Local finalizer entry not observed".to_owned())?
            .map_err(|_| "Local finalizer gate closed".to_owned())?
            .forget();
        Ok(())
    }
    fn release(&self) {
        self.released.add_permits(1);
    }
}
enum TailDowngrade {
    NativeUnavailable(Arc<NativeProbe>),
    Unbind(Weak<DesktopTauriProtocol>),
}
struct CountActualCollector {
    actual: Arc<dyn RuntimeCapabilitiesCollector>,
    calls: [AtomicUsize; 3],
    gate: Option<Arc<FinalizeGate>>,
    tail_downgrade: Mutex<Option<TailDowngrade>>,
}
impl RuntimeCapabilitiesCollector for CountActualCollector {
    fn observe<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        self.calls[0].fetch_add(1, Ordering::SeqCst);
        self.actual.observe(auth, deadline)
    }
    fn finalize<'a>(
        &'a self,
        auth: &'a AuthContext,
        observed: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        self.calls[1].fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.entered.add_permits(1);
                gate.released
                    .acquire()
                    .await
                    .map_err(|_| RuntimeCapabilitiesCollectionError::Unavailable)?
                    .forget();
            }
            self.actual.finalize(auth, observed, deadline).await
        })
    }
    fn tail_current(
        &self,
        auth: &AuthContext,
        finalized: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilityObservationResult {
        self.calls[2].fetch_add(1, Ordering::SeqCst);
        let result = self.actual.tail_current(auth, finalized, deadline);
        // A test-only world change after the real collector tail must still be seen by the
        // App's mandatory same-observation synchronous witness. No fact/result is replaced.
        if let Some(change) = self
            .tail_downgrade
            .lock()
            .map_err(|_| RuntimeCapabilitiesCollectionError::Unavailable)?
            .take()
        {
            match change {
                TailDowngrade::NativeUnavailable(native) => {
                    native.healthy.store(false, Ordering::SeqCst)
                }
                TailDowngrade::Unbind(protocol) => {
                    protocol
                        .upgrade()
                        .ok_or(RuntimeCapabilitiesCollectionError::NotCurrent)?
                        .unbind_window("main")
                        .map_err(|_| RuntimeCapabilitiesCollectionError::Unavailable)?;
                }
            }
        }
        result
    }
}
struct CountActualFactory {
    actual: Arc<DesktopRuntimeCapabilityFactory>,
    port: Mutex<Option<Arc<CountActualCollector>>>,
    gate: Option<Arc<FinalizeGate>>,
}
impl RuntimeCapabilityCollectorFactory for CountActualFactory {
    fn build(
        &self,
        facts: Arc<PostgresRuntimeCapabilityFacts>,
    ) -> Result<Arc<dyn RuntimeCapabilitiesCollector>, RuntimeCapabilitiesCollectionError> {
        let port = Arc::new(CountActualCollector {
            actual: self.actual.build(facts)?,
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            gate: self.gate.clone(),
            tail_downgrade: Mutex::new(None),
        });
        *self
            .port
            .lock()
            .map_err(|_| RuntimeCapabilitiesCollectionError::Unavailable)? = Some(port.clone());
        Ok(port)
    }
}
struct ObservedApplication {
    actual: Arc<dyn ApplicationService>,
    calls: AtomicUsize,
    last_error: Mutex<Option<AppError>>,
}
#[async_trait]
impl ApplicationService for ObservedApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        if matches!(&command, AppCommand::GetRuntimeCapabilities) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.actual.execute(auth, command).await;
        // Record this actual return, including None after success, without a second call.
        *self
            .last_error
            .lock()
            .expect("actual App error observer poisoned") = result.as_ref().err().cloned();
        result
    }
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        self.actual.subscribe(auth, request).await
    }
}
struct UnusedRemote;
#[async_trait]
impl RemoteAguiTransport for UnusedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        panic!("capability GET must not start inference or a remote provider")
    }
}
struct LocalFixture {
    desktop: OwnedDesktop,
    original: AuthContext,
    protocol: Arc<DesktopTauriProtocol>,
    application: Arc<ObservedApplication>,
    facts: Arc<PostgresRuntimeCapabilityFacts>,
    port: Arc<CountActualCollector>,
    native: Arc<NativeProbe>,
    service: Arc<LocalConfirmationService>,
    reconciler: openbot_infra::mcp_connections::McpRevocationReconciler,
}
impl LocalFixture {
    async fn new(gate: Option<Arc<FinalizeGate>>) -> Result<Self, String> {
        let desktop = start_owned_desktop().await?;
        let database = desktop.database.pool();
        desktop
            .installation
            .authority()
            .provision_postgres(database)
            .await
            .map_err(|_| "owned attested Local canonical provisioning failed".to_owned())?;
        let original = desktop
            .installation
            .authority()
            .load_runtime_auth_context(database)
            .await
            .map_err(|_| "actual Local canonical proof failed".to_owned())?;
        require(
            original.is_single_user() && original.auth_generation().get() == 0,
            "actual Local original principal facts differ",
        )?;
        let source = Arc::new(PostgresLocalConfirmationAuthority::new(
            desktop.installation.authority().clone(),
            desktop.database.clone_pool(),
        ));
        let actual_factory = DesktopRuntimeCapabilityFactory::new(
            desktop.database.clone_pool(),
            desktop.installation.authority().clone(),
        )
        .map_err(|_| "actual Local capability factory refused owned source".to_owned())?;
        let factory = Arc::new(CountActualFactory {
            actual: actual_factory.clone(),
            port: Mutex::new(None),
            gate,
        });
        let policy = PolicyStore::postgres(desktop.database.clone_pool(), None);
        policy
            .load()
            .await
            .map_err(|_| "actual Local policy setup failed".to_owned())?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            recovery_gate:
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &desktop.database.clone_pool(),
                    &original.deployment(),
                    &original.tenant(),
                ),
            pool: desktop.database.clone_pool(),
            listener_database: ThreadListenerDatabase::desktop_local(
                desktop.port,
                desktop.password.as_bytes(),
            )
            .map_err(|_| "actual owned Local listener identity rejected".to_owned())?,
            deployment: original.deployment().clone(),
            tenant: original.tenant().clone(),
            single_user: true,
            admin_floor: None,
            model: "unused-owned-local-model".to_owned(),
            credential_key_id: "unused-owned-local-key".to_owned(),
            credential_vault: CredentialRecordVault::single_key(
                original.tenant().clone(),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x76; 32])
                    .map_err(|_| "controlled Local wrapping key rejected".to_owned())?,
            ),
            audit_key: SecretBytes::new(vec![0x75; 32]),
            remote_assertions: Arc::new(
                RemoteRunAssertionSigner::new(vec![0x77; 32])
                    .map_err(|_| "controlled Local signer rejected".to_owned())?,
            ),
            mcp_oauth_state_key: SecretBytes::new(vec![0x78; 32]),
            policy_store: policy,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: Some(factory.clone()),
            remote_agent_probe: Arc::new(UnusedRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(|_| "controlled Local unused endpoint invalid".to_owned())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        })
        .await
        .map_err(|_| "actual Local application assembly failed".to_owned())?;
        let facts = assembly
            .runtime_capability_facts
            .ok_or("actual Local facts were not assembled")?;
        let application = Arc::new(ObservedApplication {
            actual: assembly.application,
            calls: AtomicUsize::new(0),
            last_error: Mutex::new(None),
        });
        let assets = desktop._sidecar.app_root.join("assets");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|_| "owned Local assets create failed".to_owned())?;
        fs::write(assets.join("index.html"),"<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|_|"owned Local index failed".to_owned())?;
        fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|_| "owned Local bootstrap failed".to_owned())?;
        let protocol = Arc::new(
            DesktopTauriProtocol::open(
                &assets,
                Arc::new(InProcessTransport::new(application.clone())),
            )
            .map_err(|_| "actual Local Protocol open failed".to_owned())?
            .with_current_identity_source(source.clone()),
        );
        actual_factory
            .install(&protocol)
            .map_err(|_| "actual Local factory/protocol provenance refused".to_owned())?;
        let native = NativeProbe::new();
        let service = Arc::new(
            LocalConfirmationService::new(
                desktop.installation.authority().instance_id(),
                source,
                Some(native.clone()),
            )
            .map_err(|_| "actual Local confirmation service setup failed".to_owned())?,
        );
        protocol
            .install_local_confirmation(LocalConfirmationHost {
                service: service.clone(),
                dispatcher: Arc::new(ActualProtocolDispatcher {
                    protocol: Arc::downgrade(&protocol),
                    native: Arc::downgrade(&native),
                }),
            })
            .map_err(|_| "actual Local service slot install failed".to_owned())?;
        protocol
            .bind_window("main", original.clone(), None)
            .map_err(|_| "actual Local window admission failed".to_owned())?;
        let port = factory
            .port
            .lock()
            .map_err(|_| "actual Local collector capture poisoned".to_owned())?
            .clone()
            .ok_or("actual Local assembly never built collector")?;
        Ok(Self {
            desktop,
            original,
            protocol,
            application,
            facts,
            port,
            native,
            service,
            reconciler: assembly.mcp_revocation_reconciler,
        })
    }
    fn auth(&self) -> Result<AuthContext, String> {
        self.protocol
            .authority("main")
            .map_err(|_| "actual Local registry unavailable".to_owned())?
            .map(|authority| authority.auth)
            .ok_or_else(|| "actual Local window unbound".to_owned())
    }
    async fn capabilities(&self) -> Result<(StatusCode, Value), String> {
        capabilities(&self.protocol).await
    }
    async fn database_facts(&self) -> Result<Value, String> {
        self.desktop.database.pool().get().await.map_err(|_|"actual Local source observer acquire failed".to_owned())?.query_one("SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.users x),'roles',(SELECT jsonb_agg(to_jsonb(x) ORDER BY user_id,role) FROM public.user_roles x),'deny',(SELECT jsonb_agg(to_jsonb(x) ORDER BY email) FROM public.revoked_access x),'sessions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.sessions x),'policy',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.action_policy x),'credentials',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.credentials x),'models',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.model_connections x),'secrets',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.model_connection_secrets x),'audit',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM public.audit_events x))",&[]).await.map_err(|_|"actual Local full source fingerprint failed".to_owned())?.try_get(0).map_err(|_|"actual Local full source fingerprint decode failed".to_owned())
    }
    async fn fresh(&self) -> Result<(), String> {
        let protocol = self.protocol.clone();
        let task = tokio::spawn(async move {
            protocol
                .handle(
                    "main",
                    Request::builder()
                        .method(Method::POST)
                        .uri(LOCAL_CONFIRMATION_PATH)
                        .body(Vec::new())
                        .unwrap(),
                )
                .await
        });
        let mut event = self.native.take().await?;
        event.deliver(true)?;
        let response = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .map_err(|_| "actual confirmation did not install grant".to_owned())?
            .map_err(|_| "actual confirmation task failed".to_owned())?;
        event.retire();
        require(
            response.status() == StatusCode::OK,
            "actual controlled-native confirmation did not succeed",
        )?;
        let receipt: LocalConfirmationReceipt = serde_json::from_slice(response.body())
            .map_err(|_| "actual confirmation receipt malformed".to_owned())?;
        require(receipt.outcome==openbot_contracts::desktop::local_confirmation::LocalConfirmationOutcome::Confirmed,"actual Local confirmation outcome differs")
    }
    async fn finish(self, test: &'static str) -> Result<(), String> {
        self.protocol.shutdown_local_confirmation();
        drop(self.protocol);
        self.facts.close();
        self.facts.drain().await;
        drop(self.service);
        self.reconciler.stop().await;
        require(
            self.native.active.load(Ordering::SeqCst) == 0,
            "controlled native owner tokens were not actually retired",
        )?;
        self.desktop.finish(test)
    }
}
async fn capabilities(protocol: &DesktopTauriProtocol) -> Result<(StatusCode, Value), String> {
    let response = protocol
        .handle(
            "main",
            Request::builder()
                .method(Method::GET)
                .uri(PATH)
                .body(Vec::new())
                .map_err(|_| "Local capability request invalid".to_owned())?,
        )
        .await;
    require(
        response
            .headers()
            .get("cache-control")
            .and_then(|h| h.to_str().ok())
            == Some("no-store"),
        "actual Local capabilities lost no-store",
    )?;
    Ok((
        response.status(),
        serde_json::from_slice(response.body())
            .map_err(|_| "actual Local capability body malformed".to_owned())?,
    ))
}
fn entry(
    value: &RuntimeCapabilitiesResponse,
    id: Id,
) -> openbot_contracts::runtime_capabilities::RuntimeCapabilityEntry {
    *value
        .capabilities()
        .iter()
        .find(|entry| entry.id() == id)
        .expect("validated closed Local projection")
}
fn projection(result: (StatusCode, Value)) -> Result<RuntimeCapabilitiesResponse, String> {
    require(
        result.0 == StatusCode::OK,
        "actual Local capability query did not produce projection",
    )?;
    serde_json::from_value(result.1).map_err(|_| "actual Local projection invalid".to_owned())
}
type LocalTestFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + 'a>>;
async fn with_fixture(
    test: &'static str,
    gate: Option<Arc<FinalizeGate>>,
    body: impl for<'a> FnOnce(&'a LocalFixture) -> LocalTestFuture<'a>,
) {
    let fixture = LocalFixture::new(gate)
        .await
        .unwrap_or_else(|error| panic!("{test}: {error}"));
    let result = body(&fixture).await;
    let cleanup = fixture.finish(test).await;
    if let Err(error) = result {
        panic!("{test}: {error}; explicit cleanup={}", cleanup.is_ok());
    }
    cleanup.unwrap_or_else(|error| panic!("{test}: {error}"));
}

#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN; actual owned Local installation/PG"]
async fn actual_local_required_without_models_keeps_workspace_ready_and_get_never_prompts() {
    with_fixture("cap_local_required",None,|fixture|Box::pin(async move{
        let before=fixture.database_facts().await?;let value=projection(fixture.capabilities().await?)?;
        require(value.host_mode()==openbot_contracts::runtime_capabilities::RuntimeCapabilityHostMode::DesktopLocal,"Local real factory mode differs")?;
        require(entry(&value,Id::Workspace).state()==State::Ready,"actual Local empty workspace borrowed model prerequisites")?;
        require(entry(&value,Id::LocalConfirmation).state()==State::PermissionRequired && entry(&value,Id::LocalConfirmation).reason_code()==Reason::LocalConfirmationRequired,"actual Local service/current grant did not project Required")?;
        require(fixture.native.starts.load(Ordering::SeqCst)==0,"capability GET prompted native owner")?;
        require(fixture.database_facts().await?==before,"actual Local GET wrote source facts")?;Ok(())
    })).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_post_admitted_same_service_grant_fresh_projects_ready_without_renewal() {
    with_fixture("cap_local_fresh", None, |fixture| {
        Box::pin(async move {
            fixture.fresh().await?;
            let before = fixture.database_facts().await?;
            let value = projection(fixture.capabilities().await?)?;
            require(
                entry(&value, Id::LocalConfirmation).state() == State::Ready
                    && entry(&value, Id::LocalConfirmation).reason_code()
                        == Reason::CurrentChecksAvailable,
                "genuine controlled-native same grant Fresh did not project Ready",
            )?;
            require(
                fixture.native.starts.load(Ordering::SeqCst) == 1,
                "GET renewed or re-prompted actual grant",
            )?;
            require(
                fixture.database_facts().await? == before,
                "Fresh observation wrote actual Local sources",
            )?;
            Ok(())
        })
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_service_pending_then_cancelled_uses_original_attempt_without_get_prompt() {
    with_fixture("cap_local_pending", None, |fixture| {
        Box::pin(async move {
            let protocol = fixture.protocol.clone();
            let task = tokio::spawn(async move {
                protocol
                    .handle(
                        "main",
                        Request::builder()
                            .method(Method::POST)
                            .uri(LOCAL_CONFIRMATION_PATH)
                            .body(Vec::new())
                            .unwrap(),
                    )
                    .await
            });
            let mut event = fixture.native.take().await?;
            let pending = projection(fixture.capabilities().await?)?;
            require(
                entry(&pending, Id::LocalConfirmation).reason_code()
                    == Reason::LocalConfirmationPending,
                "actual pending attempt was replaced or invented Fresh",
            )?;
            event.deliver(false)?;
            let response = task
                .await
                .map_err(|_| "actual cancelled confirmation task failed".to_owned())?;
            event.retire();
            require(
                response.status() == StatusCode::OK,
                "actual cancellation receipt missing",
            )?;
            let required = projection(fixture.capabilities().await?)?;
            require(
                entry(&required, Id::LocalConfirmation).reason_code()
                    == Reason::LocalConfirmationRequired,
                "cancelled genuine attempt became Fresh",
            )?;
            require(
                fixture.native.starts.load(Ordering::SeqCst) == 1,
                "GET restarted native confirmation",
            )?;
            Ok(())
        })
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_generation_zero_binding_refuses_current_null_before_collector() {
    with_fixture("cap_local_null", None, |fixture| {
        Box::pin(async move {
            let auth = fixture.auth()?;
            fixture
                .desktop
                .database
                .pool()
                .get()
                .await
                .map_err(|_| "NULL controller acquire failed".to_owned())?
                .execute(
                    "UPDATE public.users SET auth_generation=NULL WHERE id=$1",
                    &[&auth.actor().as_str()],
                )
                .await
                .map_err(|_| "actual Local NULL mutation failed".to_owned())?;
            let before = fixture.database_facts().await?;
            require(
                fixture.capabilities().await?.0 == StatusCode::UNAUTHORIZED,
                "actual Local gen0 survived NULL current generation",
            )?;
            require(
                fixture
                    .port
                    .calls
                    .iter()
                    .all(|calls| calls.load(Ordering::SeqCst) == 0),
                "invalid canonical preguard called collector",
            )?;
            require(
                fixture.database_facts().await? == before,
                "NULL denial repaired authority",
            )?;
            Ok(())
        })
    })
    .await;
}
#[derive(Clone, Copy)]
enum CanonicalChange {
    NegativeGeneration,
    RoleChanged,
    DeniedEmail,
}
async fn canonical_denied(test: &'static str, change: CanonicalChange) {
    with_fixture(test,None,|fixture|Box::pin(async move{
        let auth=fixture.auth()?;let client=fixture.desktop.database.pool().get().await.map_err(|_|"owned canonical controller acquire failed".to_owned())?;
        match change{
            CanonicalChange::NegativeGeneration=>{
                // This fresh owned DB alone models a corrupt legacy row by removing its guard;
                // no valid writer is represented as able to create a negative generation.
                client.batch_execute("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative").await.map_err(|_|"owned corrupt-row fixture constraint removal failed".to_owned())?;
                client.execute("UPDATE public.users SET auth_generation=-1 WHERE id=$1",&[&auth.actor().as_str()]).await.map_err(|_|"owned corrupt Local generation setup failed".to_owned())?;
            }
            CanonicalChange::RoleChanged=>{client.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",&[&auth.actor().as_str()]).await.map_err(|_|"owned canonical role change failed".to_owned())?;}
            CanonicalChange::DeniedEmail=>{client.execute("INSERT INTO public.revoked_access(email,revoked_by) SELECT lower(email),id FROM public.users WHERE id=$1",&[&auth.actor().as_str()]).await.map_err(|_|"owned canonical deny insertion failed".to_owned())?;}
        }
        drop(client);let before=fixture.database_facts().await?;
        require(fixture.capabilities().await?.0==StatusCode::UNAUTHORIZED,"changed actual Local canonical proof survived capability admission")?;
        require(fixture.port.calls.iter().all(|calls|calls.load(Ordering::SeqCst)==0),"rejected canonical proof entered capability collector")?;
        require(fixture.native.starts.load(Ordering::SeqCst)==0,"canonical capability rejection prompted native owner")?;
        require(fixture.database_facts().await?==before,"canonical rejection repaired or otherwise wrote source facts")?;Ok(())
    })).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN; corrupt legacy negative row only in fresh owned DB"]
async fn actual_local_original_proof_refuses_corrupt_current_negative_generation() {
    canonical_denied("cap_local_negative", CanonicalChange::NegativeGeneration).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_original_proof_refuses_changed_canonical_roles_without_repair() {
    canonical_denied("cap_local_roles", CanonicalChange::RoleChanged).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_original_proof_refuses_new_canonical_email_deny_without_repair() {
    canonical_denied("cap_local_deny", CanonicalChange::DeniedEmail).await;
}
#[derive(Clone, Copy)]
enum LocalWaitChange {
    NativeHealth,
    Unbind,
    Rebind,
    Cancel,
    GenerationNull,
    ExpireGrant,
    OwnerClose,
}
async fn actual_blocked_pid(observer: &pool::DatabasePool, blocker: i32) -> Result<i32, String> {
    let observer = observer
        .get()
        .await
        .map_err(|_| "owned Local wait observer acquire failed".to_owned())?;
    for _ in 0..200 {
        let rows=observer.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND query LIKE '%WITH policy_scan AS MATERIALIZED%' AND $1=ANY(pg_blocking_pids(pid))",&[&blocker]).await.map_err(|_|"actual Local final wait query failed".to_owned())?;
        if rows.len() == 1 {
            return rows[0]
                .try_get(0)
                .map_err(|_| "actual Local producer PID decode failed".to_owned());
        }
        if rows.len() > 1 {
            return Err("ambiguous actual Local finalizer PID".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("actual Local final source SQL wait was not observed".to_owned())
}
async fn local_final_wait(test: &'static str, change: LocalWaitChange) {
    let gate = FinalizeGate::new();
    with_fixture(test, Some(gate.clone()), |fixture| {
        Box::pin(async move {
            fixture.fresh().await?;
            let before = fixture.database_facts().await?;
            let protocol = fixture.protocol.clone();
            let task = tokio::spawn(async move { capabilities(&protocol).await });
            gate.entered().await?;
            let mut controller = fixture
                .desktop
                .database
                .pool()
                .get()
                .await
                .map_err(|_| "owned Local final controller acquire failed".to_owned())?;
            let pid: i32 = controller
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|_| "owned Local controller PID failed".to_owned())?
                .get(0);
            let tx = controller
                .transaction()
                .await
                .map_err(|_| "owned Local source controller begin failed".to_owned())?;
            tx.batch_execute("LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE")
                .await
                .map_err(|_| "owned Local final source lock failed".to_owned())?;
            gate.release();
            let producer = actual_blocked_pid(fixture.desktop.database.pool(), pid).await?;
            require(producer != pid, "actual Local producer was controller")?;
            match change {
                LocalWaitChange::NativeHealth => {
                    fixture.native.healthy.store(false, Ordering::SeqCst)
                }
                LocalWaitChange::Unbind => {
                    fixture
                        .protocol
                        .unbind_window("main")
                        .map_err(|_| "actual Local late unbind failed".to_owned())?;
                }
                LocalWaitChange::Rebind => {
                    fixture
                        .protocol
                        .unbind_window("main")
                        .map_err(|_| "actual Local old window unbind failed".to_owned())?;
                    fixture
                        .protocol
                        .bind_window("main", fixture.original.clone(), None)
                        .map_err(|_| "actual Local replacement window failed".to_owned())?;
                }
                LocalWaitChange::Cancel => fixture
                    .protocol
                    .authority("main")
                    .map_err(|_| "actual Local cancellation registry failed".to_owned())?
                    .ok_or("actual Local cancellation window missing")?
                    .closed
                    .cancel(),
                LocalWaitChange::GenerationNull => {
                    tx.execute(
                        "UPDATE public.users SET auth_generation=NULL WHERE id=$1",
                        &[&fixture.original.actor().as_str()],
                    )
                    .await
                    .map_err(|_| "actual Local postwait NULL change failed".to_owned())?;
                }
                LocalWaitChange::OwnerClose => fixture.protocol.close_request_bindings(),
                LocalWaitChange::ExpireGrant => {
                    fixture
                        .protocol
                        .authority("main")
                        .map_err(|_| "actual Local grant registry failed".to_owned())?
                        .ok_or("actual Local existing window missing")?
                        .local_confirmation
                        .ok_or("actual Local admitted service missing")?
                        .grant
                        .expire_existing_grant_for_test()
                        .map_err(|_| "downgrade of actual existing grant failed".to_owned())?;
                }
            }
            tx.commit()
                .await
                .map_err(|_| "owned Local final source release failed".to_owned())?;
            let result = tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .map_err(|_| {
                    "actual Local finalizer did not finish after source release".to_owned()
                })?
                .map_err(|_| "actual Local capability task failed".to_owned())??;
            match change {
                LocalWaitChange::NativeHealth => {
                    let value = projection(result)?;
                    require(
                        entry(&value, Id::LocalConfirmation).state() == State::Unavailable
                            && entry(&value, Id::LocalConfirmation).reason_code()
                                == Reason::LocalConfirmationUnavailable,
                        "late native health loss returned old Fresh",
                    )?;
                }
                LocalWaitChange::ExpireGrant => {
                    let value = projection(result)?;
                    require(
                        entry(&value, Id::LocalConfirmation).state() == State::Unavailable
                            && entry(&value, Id::LocalConfirmation).reason_code()
                                == Reason::LocalConfirmationExpired,
                        "same actual grant expiry returned old Fresh or was renewed",
                    )?;
                }
                LocalWaitChange::Unbind
                | LocalWaitChange::Rebind
                | LocalWaitChange::Cancel
                | LocalWaitChange::GenerationNull
                | LocalWaitChange::OwnerClose => require(
                    result.0 == StatusCode::UNAUTHORIZED,
                    "late original window/canonical change returned old body",
                )?,
            }
            require(
                fixture.native.starts.load(Ordering::SeqCst) == 1,
                "final query renewed existing grant/prompt",
            )?;
            if !matches!(change, LocalWaitChange::GenerationNull) {
                require(
                    fixture.database_facts().await? == before,
                    "postwait capability query wrote Local source facts",
                )?;
            }
            Ok(())
        })
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_joint_wait_rechecks_native_owner_health_without_callback() {
    local_final_wait("cap_local_late_health", LocalWaitChange::NativeHealth).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_joint_wait_refuses_old_unbound_window() {
    local_final_wait("cap_local_late_unbind", LocalWaitChange::Unbind).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_joint_wait_refuses_same_label_replacement_grant() {
    local_final_wait("cap_local_late_rebind", LocalWaitChange::Rebind).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_joint_wait_refuses_original_closed_token() {
    local_final_wait("cap_local_late_cancel", LocalWaitChange::Cancel).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_joint_wait_refuses_raw_current_generation_null() {
    local_final_wait("cap_local_late_null", LocalWaitChange::GenerationNull).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN; cfg(test) downgrade-only original grant expiry"]
async fn actual_existing_post_admitted_grant_expiry_after_final_wait_never_renews() {
    local_final_wait("cap_local_late_expiry", LocalWaitChange::ExpireGrant).await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_owner_close_during_final_joint_wait_withholds_original_projection() {
    local_final_wait("cap_local_late_close", LocalWaitChange::OwnerClose).await;
}

#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn mandatory_app_tail_witness_withholds_fresh_after_real_collector_tail_native_health_loss() {
    with_fixture("cap_local_app_tail_health", None, |fixture| {
        Box::pin(async move {
            fixture.fresh().await?;
            *fixture
                .port
                .tail_downgrade
                .lock()
                .map_err(|_| "tail downgrade fixture poisoned".to_owned())? =
                Some(TailDowngrade::NativeUnavailable(fixture.native.clone()));
            let result = fixture.capabilities().await?;
            require(
                result.0 == StatusCode::SERVICE_UNAVAILABLE
                    && result.1 == serde_json::json!({"code":"dependency_unavailable"})
                    && fixture
                        .application
                        .last_error
                        .lock()
                        .map_err(|_| "actual App error observer poisoned".to_owned())?
                        .as_ref()
                        == Some(&AppError::DependencyUnavailable {
                            dependency: "runtime_capabilities",
                        }),
                "App accepted old Fresh after actual tail health changed",
            )?;
            require(
                result.1.get("capabilities").is_none(),
                "mandatory tail failure exposed old vector",
            )?;
            Ok(())
        })
    })
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn mandatory_app_tail_witness_withholds_old_reply_after_real_collector_tail_window_unbind() {
    with_fixture("cap_local_app_tail_unbind", None, |fixture| {
        Box::pin(async move {
            fixture.fresh().await?;
            *fixture
                .port
                .tail_downgrade
                .lock()
                .map_err(|_| "tail downgrade fixture poisoned".to_owned())? =
                Some(TailDowngrade::Unbind(Arc::downgrade(&fixture.protocol)));
            require(
                fixture.capabilities().await?.0 == StatusCode::UNAUTHORIZED,
                "App accepted old vector after collector tail's original window disappeared",
            )?;
            Ok(())
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_capability_whole_budget_bounds_own_pool_wait_without_old_120s_status() {
    with_fixture("cap_local_pool_budget", None, |fixture| {
        Box::pin(async move {
            let mut held = Vec::new();
            for _ in 0..16 {
                held.push(
                    fixture
                        .desktop
                        .database
                        .pool()
                        .get()
                        .await
                        .map_err(|_| "owned Local pool saturation failed".to_owned())?,
                );
            }
            let began = Instant::now();
            let result = tokio::time::timeout(Duration::from_millis(6500), fixture.capabilities())
                .await
                .map_err(|_| "capability pool wait used old120s or stacked5s".to_owned())??;
            require(
                result.0 == StatusCode::SERVICE_UNAVAILABLE
                    && result.1 == serde_json::json!({"code":"dependency_unavailable"})
                    && fixture
                        .application
                        .last_error
                        .lock()
                        .map_err(|_| "actual App error observer poisoned".to_owned())?
                        .as_ref()
                        == Some(&AppError::DependencyUnavailable {
                            dependency: "runtime_capabilities",
                        }),
                "Local capability pool timeout returned old body or wrong static failure",
            )?;
            require(
                began.elapsed() >= Duration::from_secs(4)
                    && began.elapsed() < Duration::from_millis(6500),
                "actual Local capability did not retain one total5s deadline",
            )?;
            require(
                fixture
                    .port
                    .calls
                    .iter()
                    .all(|calls| calls.load(Ordering::SeqCst) == 0),
                "expired Local preguard budget called collector",
            )?;
            require(
                fixture.native.starts.load(Ordering::SeqCst) == 0,
                "bounded GET prompted Local native owner",
            )?;
            drop(held);
            Ok(())
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_local_final_sql_budget_timeout_has_separate_real_producer_quiescence_and_owned_stop()
 {
    let gate = FinalizeGate::new();
    with_fixture("cap_local_final_budget", Some(gate.clone()), |fixture| {
        Box::pin(async move {
            let before = fixture.database_facts().await?;
            let began = Instant::now();
            let protocol = fixture.protocol.clone();
            let task = tokio::spawn(async move { capabilities(&protocol).await });
            gate.entered().await?;
            let mut controller = fixture
                .desktop
                .database
                .pool()
                .get()
                .await
                .map_err(|_| "Local budget controller acquire failed".to_owned())?;
            let blocker: i32 = controller
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|_| "Local budget controller PID failed".to_owned())?
                .get(0);
            let tx = controller
                .transaction()
                .await
                .map_err(|_| "Local budget controller transaction failed".to_owned())?;
            tx.batch_execute("LOCK TABLE public.action_policy IN ACCESS EXCLUSIVE MODE")
                .await
                .map_err(|_| "Local budget source lock failed".to_owned())?;
            // Keep this separate observer connection checked out throughout the request; it must
            // not become the timed-out producer when queried for actual post-release quiescence.
            let observer = fixture
                .desktop
                .database
                .pool()
                .get()
                .await
                .map_err(|_| "Local budget fixed observer acquire failed".to_owned())?;
            let observer_pid: i32 = observer
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|_| "Local budget fixed observer PID failed".to_owned())?
                .get(0);
            gate.release();
            let producer = actual_blocked_pid(fixture.desktop.database.pool(), blocker).await?;
            require(
                producer != observer_pid,
                "actual Local observer conflated producer",
            )?;
            let result = tokio::time::timeout(Duration::from_millis(6500), task)
                .await
                .map_err(|_| "Local finalizer exceeded total5s deadline".to_owned())?
                .map_err(|_| "Local finalizer timeout task failed".to_owned())??;
            require(
                result.0 == StatusCode::SERVICE_UNAVAILABLE
                    && result.1 == serde_json::json!({"code":"dependency_unavailable"})
                    && fixture
                        .application
                        .last_error
                        .lock()
                        .map_err(|_| "actual App error observer poisoned".to_owned())?
                        .as_ref()
                        == Some(&AppError::DependencyUnavailable {
                            dependency: "runtime_capabilities",
                        }),
                "Local final SQL timeout returned a partial/old projection",
            )?;
            require(
                began.elapsed() >= Duration::from_secs(4)
                    && began.elapsed() < Duration::from_millis(6500),
                "Local finalizer reset or stacked total deadline",
            )?;
            tx.rollback()
                .await
                .map_err(|_| "Local final timeout lock release failed".to_owned())?;
            let mut quiescent = false;
            for _ in 0..200 {
                let row = observer
                    .query_opt(
                        "SELECT state,xact_start FROM pg_stat_activity WHERE pid=$1",
                        &[&producer],
                    )
                    .await
                    .map_err(|_| "Local actual timed-out producer observe failed".to_owned())?;
                quiescent = match row {
                    None => true,
                    Some(row) => {
                        row.get::<_, String>(0) != "active"
                            && row.get::<_, Option<time::OffsetDateTime>>(1).is_none()
                    }
                };
                if quiescent {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            require(
                quiescent,
                "Local timeout did not actually quiesce producer after lock release",
            )?;
            fixture.facts.drain().await;
            require(
                fixture.database_facts().await? == before,
                "Local timeout wrote source facts",
            )?;
            Ok(())
        })
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned OPENBOT_TEST_PG_BIN"]
async fn actual_last_local_protocol_drop_closes_proof_even_after_current_guard_weak_upgrade_pool_wait()
 {
    let fixture = LocalFixture::new(None).await.unwrap();
    let auth = fixture.auth().unwrap();
    let LocalFixture {
        desktop,
        protocol,
        application,
        facts,
        port,
        native,
        service,
        reconciler,
        ..
    } = fixture;
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(desktop.database.pool().get().await.unwrap());
    }
    let mut pending = Box::pin(application.execute(auth, AppCommand::GetRuntimeCapabilities));
    assert!(
        matches!(
            std::future::Future::poll(
                pending.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            ),
            std::task::Poll::Pending
        ),
        "real current Local guard did not enter actual pool wait"
    );
    let weak = Arc::downgrade(&protocol);
    drop(protocol);
    assert!(
        weak.upgrade().is_none(),
        "proof/App/collector kept actual Protocol owner alive"
    );
    drop(held.pop());
    let result = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap();
    let outcome = if result == Err(AppError::Unauthenticated)
        && port
            .calls
            .iter()
            .all(|calls| calls.load(Ordering::SeqCst) == 0)
    {
        Ok(())
    } else {
        Err("last actual Local owner drop survived preguard or called collector".to_owned())
    };
    drop(held);
    facts.close();
    facts.drain().await;
    service.shutdown();
    drop(service);
    reconciler.stop().await;
    let native_retired = native.active.load(Ordering::SeqCst) == 0;
    let cleanup = desktop.finish("cap_local_last_owner_drop");
    assert!(native_retired, "controlled native owner did not retire");
    outcome.unwrap();
    cleanup.unwrap();
}
