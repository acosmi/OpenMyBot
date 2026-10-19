//! Actual Server/Application segmented reads and finite original-resource drain inventory.
//! Each PostgreSQL database and artifact inode belongs only to this controlled fixture.
#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use http::Request;
use openbot_application::{
    ApplicationService, ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory,
};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool, pool::DatabaseConfig};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, ServerBuilder, ServerState};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

const DEPLOYMENT: &str = "artifact-current-host-deployment";
const TENANT: &str = "artifact-current-host-tenant";
const OWNER: &str = "current-read-owner";
const A_ID: &str = "actual-read-session-a";
const B_ID: &str = "actual-read-session-b";
const COOKIE_A: &str = "owned-current-artifact-read-session-token-a-001";
const COOKIE_B: &str = "owned-current-artifact-read-session-token-b-002";
const SESSION_KEY: &[u8] = b"owned-current-artifact-read-session-hash-key";
const TEXT: &str = "small actual Begin; controlled source update precedes actual Save";
const FIRST_BLOCK: usize = 4 * 1024 * 1024;

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn token_column(token: &str) -> String {
    SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value()
}
fn parts(cookie: &str) -> Result<http::request::Parts, String> {
    Request::builder()
        .uri("/trusted-rust-artifact-consumer")
        .header("cookie", format!("openbot_session={cookie}"))
        .body(())
        .map(|request| request.into_parts().0)
        .map_err(|error| error.to_string())
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path =
            std::env::temp_dir().join(format!("openbot-artifact-current-read-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "ARTIFACT_CURRENT_HOST_ROOT_CLEANUP removed={} absent={absent}",
            removed.is_ok()
        );
        if !std::thread::panicking() {
            assert!(removed.is_ok() && absent, "owned read root did not close");
        }
    }
}

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    resolver: Arc<PostgresSessionAuthResolver>,
    state: ServerState,
    actual: Arc<PostgresArtifactAdministration>,
    payload: String,
    receipt: ArtifactRegistrationReceipt,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, length: usize) -> Result<Self, String> {
        let payload = "L".repeat(length);
        let pool = pool::connect(&config.clone().with_max_pool_size(8))
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('current-read-owner','current-read-owner@example.test',0);
                INSERT INTO public.user_roles(user_id,role) VALUES('current-read-owner','user');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('current-read-bot','Current read fixture','built_in','{}');
                INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000008','artifact-current-host-tenant','fixture','fixture');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('current-read-bot','current-read-owner','Read fixture','fixture','fixture','public');")
                .await.map_err(|error| error.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, cookie) in [(A_ID, COOKIE_A), (B_ID, COOKIE_B)] {
                client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",
                    &[&id, &OWNER, &token_column(cookie), &(now + time::Duration::hours(1)), &(now - time::Duration::minutes(1))]).await.map_err(|error| error.to_string())?;
            }
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|error| error.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([8; 16]),
                run_id: RunId::new("actual/current-read-run%成果"),
                bot_id: BotId::new("current-read-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "artifact-current-read-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|error| error.to_string())?;
        // The public Begin remains small. Only this owned database fixture is then updated;
        // this does not claim the public Begin surface accepts a multi-megabyte message.
        let changed = pool.get().await.map_err(|error| error.to_string())?.execute(
            "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb($2::text)), search_text=$2 WHERE message_id=$1",
            &[&format!("{}:input", begin.command.run_id.as_str()), &payload],
        ).await.map_err(|error| error.to_string())?;
        require(
            changed == 1,
            "owned fixture did not change exactly its original source",
        )?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|error| error.to_string())?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(|error| error.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|error| error.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x88; 32]),
            )
            .map_err(|error| error.to_string())?,
        );
        resolver
            .install_artifact_read_authority(&actual.read_authority())
            .map_err(|_| "actual resolver enrollment refused".to_owned())?;
        let auth = resolver
            .resolve(&parts(COOKIE_A)?)
            .await
            .map_err(|error| error.to_string())?;
        let receipt = actual
            .save_run_message_text(
                &auth,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id.clone(),
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(actual.clone()),
        );
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|error| format!("fixture transport config: {error:?}"))?
            .transport_policy(true);
        let state = ServerBuilder::new(application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .build();
        Ok(Self {
            pool,
            resolver,
            state,
            actual,
            payload,
            receipt,
            root,
        })
    }
}

#[derive(Clone, Copy)]
enum GatePhase {
    PartialIo,
    FinalJoint,
}
struct ReadGate {
    phase: GatePhase,
    entered: tokio::sync::Notify,
    io_seen: AtomicBool,
    reached: AtomicBool,
    partial_events: AtomicUsize,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl ReadGate {
    fn new(phase: GatePhase) -> Arc<Self> {
        Arc::new(Self {
            phase,
            entered: tokio::sync::Notify::new(),
            io_seen: AtomicBool::new(false),
            reached: AtomicBool::new(false),
            partial_events: AtomicUsize::new(0),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            wake: Condvar::new(),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
    fn hold(&self) {
        if self.reached.swap(true, Ordering::SeqCst) {
            return;
        }
        self.entered.notify_one();
        let released = self.released.lock().unwrap();
        let (_released, timed_out) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
            .unwrap();
        self.timed_out
            .store(timed_out.timed_out(), Ordering::SeqCst);
    }
}
struct ReleaseReadGate(Arc<ReadGate>);
impl Drop for ReleaseReadGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct PhaseVisitor {
    partial: bool,
    io: bool,
    ready: bool,
}
impl tracing::field::Visit for PhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match (field.name(), value) {
            ("artifact_read_lifecycle_phase", "physical_segment_completed_before_more_io") => {
                self.partial = true
            }
            ("artifact_read_phase", "actual_io_completed_before_joint") => self.io = true,
            ("artifact_read_phase", "joint_statement_ready") => self.ready = true,
            _ => {}
        }
    }
}
struct ReadSubscriber(Arc<ReadGate>);
impl tracing::Subscriber for ReadSubscriber {
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
        let mut visitor = PhaseVisitor {
            partial: false,
            io: false,
            ready: false,
        };
        event.record(&mut visitor);
        if visitor.partial {
            self.0.partial_events.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.io {
            self.0.io_seen.store(true, Ordering::SeqCst);
        }
        match self.0.phase {
            GatePhase::PartialIo if visitor.partial => self.0.hold(),
            GatePhase::FinalJoint if visitor.ready && self.0.io_seen.load(Ordering::SeqCst) => {
                self.0.hold()
            }
            _ => {}
        }
    }
}

// Read only this Rust process's bounded f/device/inode inventory. No path fields or peer PIDs.
fn owned_file_fds(path: &Path) -> Result<BTreeSet<u32>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<BTreeSet<u32>, String> {
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
        let mut found = BTreeSet::new();
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

async fn await_gate(gate: &ReadGate) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .map_err(|_| "actual original worker/ready phase was not reached".to_owned())?;
    require(
        gate.reached.load(Ordering::SeqCst) && !gate.timed_out.load(Ordering::SeqCst),
        "actual gate expired",
    )
}
async fn with_fixture<F, Fut>(tag: &str, length: usize, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, length).await?).await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL and own-PID original FD observation"]
async fn actual_production_worker_cancel_after_partial_io_drains_original_fd() {
    with_fixture("lifecycle-partial-cancel", 256 * 1024, |fixture| async move {
        let mut operation = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())?;
        let path = fixture.root.0.join("objects").join(&fixture.receipt.artifact_id);
        let gate = ReadGate::new(GatePhase::PartialIo);
        let _release = ReleaseReadGate(gate.clone());
        let task = tokio::spawn(async move { operation.next_block().await }.with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))));
        let tracker = fixture.actual.read_authority().read_lifecycle();
        let attempted = async {
            await_gate(&gate).await?;
            let original = owned_file_fds(&path)?;
            require(original.len() == 1, "actual partial worker did not hold exactly its original FD")?;
            task.abort();
            fixture.resolver.close_request_bindings();
            tracker.close();
            require(tokio::time::timeout(Duration::from_millis(20), tracker.drain()).await.is_err(), "cancel falsely released physical read inventory")?;
            require(owned_file_fds(&path)? == original, "cancel ended/replaced original FD before actual worker completion")?;
            require(!gate.timed_out.load(Ordering::SeqCst), "partial worker gate expired")
        }.await;
        task.abort();
        gate.release();
        let cancelled = task.await;
        fixture.resolver.close_request_bindings(); tracker.close();
        let drained = tracker.drain_before(Instant::now() + Duration::from_secs(5)).await;
        attempted?;
        require(cancelled.is_err_and(|error| error.is_cancelled()), "original consumer cancellation was not actually joined")?;
        require(drained.is_ok(), "actual original worker/resources never drained")?;
        require(owned_file_fds(&path)?.is_empty(), "original FD survived actual worker completion and drain")?;
        let reopened = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone()).await;
        require(reopened.is_err(), "closed actual Session owner admitted another operation")?;
        let reread = fixture.state.read_current_artifact_chunk(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))).await;
        require(reread.is_err() && gate.partial_events.load(Ordering::SeqCst) == 1, "closed original owner admitted another physical read or emitted a body")?;
        eprintln!("ARTIFACT_LIFECYCLE_SERVER partial_actual=true consumer_cancel_join=true drain_ack=true original_fd_absent=true");
        Ok(())
    }).await;
}

async fn actual_final_wait(observer: &tokio_postgres::Client, blocker: i32) -> Result<i32, String> {
    for _ in 0..150 {
        let row = observer.query_one(
            "SELECT COUNT(*)::integer, MIN(a.pid) FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)) AND a.query LIKE '%/* artifact_current_host_joint_read_after_io */%'",
            &[&blocker],
        ).await.map_err(|error| error.to_string())?;
        let count: i32 = row.try_get(0).map_err(|error| error.to_string())?;
        let pid: Option<i32> = row.try_get(1).map_err(|error| error.to_string())?;
        if count == 1 {
            return pid.ok_or("actual final Lock PID was missing".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("actual final joint Lock with the original controller PID was not observed".to_owned())
}

async fn second_block_drift(fixture: Fixture, session: bool) -> Result<(), String> {
    let mut operation = fixture
        .state
        .open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
        .await
        .map_err(|error| error.to_string())?;
    let first = operation
        .next_block()
        .await
        .map_err(|error| error.to_string())?
        .ok_or("nonempty first block missing")?;
    require(
        first.len() == FIRST_BLOCK
            && first.as_bytes() == &fixture.payload.as_bytes()[..FIRST_BLOCK],
        "first actual leased block differs",
    )?;
    drop(first);
    let mut controller = fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?;
    let observer = fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?;
    let controller_pid: i32 = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    let observer_pid: i32 = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())?;
    require(
        controller_pid != observer_pid,
        "same-Pool controller/observer are not distinct",
    )?;
    let gate = ReadGate::new(GatePhase::FinalJoint);
    let _release = ReleaseReadGate(gate.clone());
    let task = tokio::spawn(
        async move { operation.next_block().await }
            .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))),
    );
    let mut transaction = None;
    let attempted = async {
        await_gate(&gate).await?;
        require(gate.io_seen.load(Ordering::SeqCst), "actual second worker ACK did not precede final-ready")?;
        transaction = Some(controller.transaction().await.map_err(|error| error.to_string())?);
        transaction.as_ref().unwrap().batch_execute(if session {
            "SET LOCAL lock_timeout='1s'; LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE"
        } else {
            "SET LOCAL lock_timeout='1s'; LOCK TABLE public.messages IN ACCESS EXCLUSIVE MODE"
        }).await.map_err(|error| error.to_string())?;
        require(!gate.timed_out.load(Ordering::SeqCst) && !task.is_finished(), "final-ready barrier expired or second reader already ended")?;
        gate.release();
        let waiter = actual_final_wait(&observer, controller_pid).await?;
        let affected = if session {
            transaction.as_ref().unwrap().execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await
        } else {
            transaction.as_ref().unwrap().execute("DELETE FROM public.messages WHERE message_id=$1", &[&fixture.receipt.source_message_id]).await
        }.map_err(|error| error.to_string())?;
        require(affected == 1, "controller did not delete exactly its original row")?;
        transaction.take().unwrap().commit().await.map_err(|error| error.to_string())?;
        eprintln!("ARTIFACT_LIFECYCLE_SERVER_SECOND_WAIT io_ack=true final_ready=true actual_lock=true controller_pid={controller_pid} waiter_pid={waiter} commit_ack=true session={session}");
        Ok::<(), String>(())
    }.await;
    gate.release();
    let rollback = match transaction.take() {
        Some(transaction) => Some(transaction.rollback().await.is_ok()),
        None => None,
    };
    let result = task.await.map_err(|error| error.to_string());
    attempted?;
    require(
        rollback != Some(false),
        "original controller rollback did not ACK",
    )?;
    let result = result?;
    require(
        if session {
            matches!(result, Err(AppError::Unauthenticated))
        } else {
            matches!(result, Err(AppError::NotVisible))
        },
        "actual second joint did not deny the original changed authority/source",
    )?;
    if session {
        let mut b = fixture
            .state
            .open_current_artifact_read(&parts(COOKIE_B)?, fixture.receipt.artifact_id.clone())
            .await
            .map_err(|error| error.to_string())?;
        let b_body = b
            .next_block()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("actual B first block missing")?;
        require(
            b_body.len() == FIRST_BLOCK,
            "unaffected original B session lost its read",
        )?;
        drop(b_body);
        drop(b);
    }
    let tracker = fixture.actual.read_authority().read_lifecycle();
    tracker.close();
    require(
        tracker
            .drain_before(Instant::now() + Duration::from_secs(5))
            .await
            .is_ok(),
        "second-block failure did not drain actual resources",
    )?;
    require(
        owned_file_fds(
            &fixture
                .root
                .0
                .join("objects")
                .join(&fixture.receipt.artifact_id),
        )?
        .is_empty(),
        "failed second block retained original FD",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL and actual final Session Lock/COMMIT ACK"]
async fn second_block_final_session_wait_delete_commit_ack_denies_body() {
    with_fixture(
        "lifecycle-second-session",
        FIRST_BLOCK + 128 * 1024,
        |fixture| second_block_drift(fixture, true),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL and actual final source Lock/COMMIT ACK"]
async fn second_block_final_source_wait_delete_commit_ack_returns_404() {
    with_fixture(
        "lifecycle-second-source",
        FIRST_BLOCK + 128 * 1024,
        |fixture| second_block_drift(fixture, false),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and actual second-block cleanup-fence Lock/COMMIT ACK"]
async fn second_block_final_cleanup_fence_wait_commit_ack_denies_body() {
    with_fixture("lifecycle-second-cleanup", FIRST_BLOCK + 128 * 1024, |fixture| async move {
        let mut operation = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .await.map_err(|error| error.to_string())?;
        let first = operation.next_block().await.map_err(|error| error.to_string())?.ok_or("actual first block missing")?;
        require(first.as_bytes() == &fixture.payload.as_bytes()[..FIRST_BLOCK], "first real block changed before cleanup input")?;
        drop(first);
        let mut controller = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let observer = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|error| error.to_string())?.get(0);
        let observer_pid: i32 = observer.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|error| error.to_string())?.get(0);
        require(controller_pid != observer_pid, "original cleanup controller and observer share a PID")?;
        const FACTS: &str = "SELECT jsonb_build_object( \
          'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
          'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
          'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
          'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
          'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
          'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))";
        let before: serde_json::Value = observer.query_one(FACTS, &[]).await.map_err(|error| error.to_string())?.get(0);
        let gate = ReadGate::new(GatePhase::FinalJoint);
        let _release = ReleaseReadGate(Arc::clone(&gate));
        let dispatch = tracing::Dispatch::new(ReadSubscriber(Arc::clone(&gate)));
        let task = tokio::spawn(async move { operation.next_block().await }.with_subscriber(dispatch));
        let mut transaction = None;
        let attempted = async {
            await_gate(&gate).await?;
            require(gate.io_seen.load(Ordering::SeqCst), "actual second-block worker ACK was not observed before final-ready")?;
            transaction = Some(controller.transaction().await.map_err(|error| error.to_string())?);
            transaction.as_ref().unwrap().batch_execute(
                "SET LOCAL lock_timeout='1s'; LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE",
            ).await.map_err(|error| error.to_string())?;
            require(!gate.timed_out.load(Ordering::SeqCst) && !task.is_finished(), "second-block final-ready gate expired or original reader ended")?;
            gate.release();
            let waiter = actual_final_wait(&observer, controller_pid).await?;
            require(waiter != observer_pid && waiter != controller_pid && !gate.timed_out.load(Ordering::SeqCst), "second-block exact final waiter/gate was invalid")?;
            let changed = transaction.as_ref().unwrap().execute(
                "INSERT INTO openbot_internal.artifact_cleanup_fences \
                 (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
                 SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
                 FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND artifact_id=$3",
                &[&DEPLOYMENT, &TENANT, &fixture.receipt.artifact_id],
            ).await.map_err(|error| error.to_string())?;
            require(changed == 1, "controlled fence was not on exactly the original actual Save row")?;
            transaction.take().unwrap().commit().await.map_err(|error| error.to_string())?;
            Ok::<_, String>(waiter)
        }.await;
        gate.release();
        let rollback = match transaction.take() {
            Some(transaction) => transaction.rollback().await.map_err(|error| error.to_string()),
            None => Ok(()),
        };
        drop(transaction);
        let result = task.await.map_err(|error| error.to_string());
        let after = observer.query_one(FACTS, &[]).await.map_err(|error| error.to_string()).map(|row| row.get::<_, serde_json::Value>(0));
        let lifecycle = fixture.actual.read_authority().read_lifecycle();
        lifecycle.close();
        let drained = lifecycle.drain_before(Instant::now() + Duration::from_secs(3)).await;
        let fd_closed = owned_file_fds(&fixture.root.0.join("objects").join(&fixture.receipt.artifact_id))?.is_empty();
        fixture.resolver.close_request_bindings();
        drop(observer);
        drop(controller);
        let observations = fixture.pool.connection_observations();
        fixture.pool.close();
        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        for observation in observations { observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?; }
        let waiter = attempted?;
        rollback?;
        require(matches!(result?, Err(AppError::DependencyUnavailable { dependency: "artifacts" })), "actual second block ignored the committed armed fence or yielded bytes")?;
        require(before == after?, "second-block consumer changed original business/charge/receipt/audit rows")?;
        require(drained.is_ok() && fd_closed, "failed second block retained actual FD/worker/allocation resources")?;
        require(fixture.root.0.join("objects").join(&fixture.receipt.artifact_id).is_file(), "armed reader refusal was confused with actual deletion")?;
        eprintln!("ARTIFACT_LIFECYCLE_SERVER_SECOND_CLEANUP io_ack=true final_ready=true actual_lock=true controller_pid={controller_pid} observer_pid={observer_pid} waiter_pid={waiter} commit_ack=true body_released=false original_fd_absent=true");
        Ok(())
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; three finite-inventory facts, legacy Vec lifetime UNTRACKED"]
async fn legacy_first_chunk_workers_are_in_same_root_drain_inventory() {
    with_fixture(
        "lifecycle-legacy-worker",
        256 * 1024,
        |fixture| async move {
            let state = fixture.state.clone();
            let id = fixture.receipt.artifact_id.clone();
            let request = parts(COOKIE_A)?;
            let path = fixture.root.0.join("objects").join(&id);
            let gate = ReadGate::new(GatePhase::PartialIo);
            let _release = ReleaseReadGate(gate.clone());
            let task = tokio::spawn(
                async move { state.read_current_artifact_chunk(&request, id).await }
                    .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))),
            );
            let tracker = fixture.actual.read_authority().read_lifecycle();
            let attempted = async {
                await_gate(&gate).await?;
                let original = owned_file_fds(&path)?;
                require(
                    original.len() == 1,
                    "legacy actual worker original FD missing",
                )?;
                task.abort();
                fixture.resolver.close_request_bindings();
                tracker.close();
                require(
                    tokio::time::timeout(Duration::from_millis(20), tracker.drain())
                        .await
                        .is_err(),
                    "legacy working resource falsely drained",
                )?;
                require(
                    owned_file_fds(&path)? == original,
                    "legacy cancellation replaced/closed the active original FD",
                )
            }
            .await;
            task.abort();
            gate.release();
            let joined = task.await;
            fixture.resolver.close_request_bindings();
            tracker.close();
            let drained = tracker
                .drain_before(Instant::now() + Duration::from_secs(5))
                .await;
            attempted?;
            require(
                joined.is_err_and(|error| error.is_cancelled()),
                "legacy consumer cancellation was not joined",
            )?;
            require(
                drained.is_ok() && owned_file_fds(&path)?.is_empty(),
                "legacy worker actual cleanup did not ACK/close FD",
            )?;
            eprintln!(
                "ARTIFACT_LIFECYCLE_LEGACY fact=working_original_resource actual_drain_ack=true"
            );
            Ok(())
        },
    )
    .await;
    with_fixture("lifecycle-legacy-vector", 256 * 1024, |fixture| async move {
        let bytes = fixture.state.read_current_artifact_chunk(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())?;
        fixture.resolver.close_request_bindings(); let tracker = fixture.actual.read_authority().read_lifecycle(); tracker.close();
        require(tracker.drain_before(Instant::now() + Duration::from_secs(5)).await.is_ok(), "held legacy Vec incorrectly retained the limited inventory")?;
        require(bytes == fixture.payload.as_bytes() && owned_file_fds(&fixture.root.0.join("objects").join(&fixture.receipt.artifact_id))?.is_empty(), "legacy Vec bytes/original physical cleanup differ")?;
        eprintln!("ARTIFACT_LIFECYCLE_LEGACY fact=successful_bare_vec lifetime=UNTRACKED bytes_still_valid=true limited_drain_ack=true"); drop(bytes); Ok(())
    }).await;
    with_fixture("lifecycle-original-lease", 256 * 1024, |fixture| async move {
        let mut operation = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())?;
        let block = operation.next_block().await.map_err(|error| error.to_string())?.ok_or("original leased block missing")?;
        require(block.as_bytes() == fixture.payload.as_bytes(), "original leased bytes differ")?;
        fixture.resolver.close_request_bindings(); let tracker = fixture.actual.read_authority().read_lifecycle(); tracker.close();
        let held = tokio::time::timeout(Duration::from_millis(20), tracker.drain()).await;
        drop(operation); drop(block);
        let drained = tracker.drain_before(Instant::now() + Duration::from_secs(5)).await;
        require(held.is_err() && drained.is_ok(), "original allocation lease did not hold then release actual inventory")?;
        require(owned_file_fds(&fixture.root.0.join("objects").join(&fixture.receipt.artifact_id))?.is_empty(), "original lease cleanup did not close FD")?;
        eprintln!("ARTIFACT_LIFECYCLE_LEGACY fact=new_original_lease held_no_ack=true actual_drop_drain_ack=true"); Ok(())
    }).await;
}

async fn shared_lifecycle_business_facts(fixture: &Fixture) -> Result<serde_json::Value, String> {
    fixture.pool.get().await.map_err(|error| error.to_string())?.query_one(
        "SELECT jsonb_build_object( \
         'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
         'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
         'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
         'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
         'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
         'fences',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]') FROM openbot_internal.artifact_cleanup_fences c), \
         'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a))", &[],
    ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
}

async fn shared_lifecycle_record(
    fixture: &Fixture,
) -> Result<openbot_infra::artifact_administration::ObservedArtifactReadRecord, String> {
    let auth = fixture
        .resolver
        .resolve(&parts(COOKIE_A)?)
        .await
        .map_err(|error| error.to_string())?;
    fixture
        .actual
        .observe_read_record(&auth, &fixture.receipt.artifact_id)
        .await
        .map_err(|error| error.to_string())
}

async fn finish_shared_lifecycle_fixture(fixture: &Fixture) -> Result<(), String> {
    let lifecycle = fixture.actual.read_authority().read_lifecycle();
    lifecycle.close();
    lifecycle
        .drain_before(Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|error| format!("{error:?}"))?;
    let observations = fixture.pool.connection_observations();
    fixture.pool.close();
    let deadline = Instant::now() + Duration::from_secs(5);
    for original in observations {
        require(
            original
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "shared lifecycle original connection did not actually destruct",
        )?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; shared original worker/FD inventory, not deletion"]
async fn shared_read_barrier_cancellation_keeps_actual_worker_and_fd_accounted() {
    with_fixture("shared-worker-cancel", 256 * 1024, |fixture| async move {
        let record = shared_lifecycle_record(&fixture).await?;
        let before = shared_lifecycle_business_facts(&fixture).await?;
        let mut operation = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .await.map_err(|error| error.to_string())?;
        let path = fixture.root.0.join("objects").join(&fixture.receipt.artifact_id);
        let gate = ReadGate::new(GatePhase::PartialIo);
        let release = ReleaseReadGate(gate.clone());
        let subscriber = tracing::Dispatch::new(ReadSubscriber(gate.clone()));
        let task = tokio::spawn(async move { operation.next_block().await }.with_subscriber(subscriber));
        let observed = async {
            await_gate(&gate).await?;
            let original_fds = owned_file_fds(&path)?;
            require(original_fds.len() == 1, "shared original worker did not hold exactly its original FD")?;
            let barrier = fixture.actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
            require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(),
                "shared close ACKed while the original actual worker held its FD")?;
            task.abort();
            require(owned_file_fds(&path)? == original_fds,
                "consumer abort replaced or closed a held original worker FD")?;
            Ok::<_, String>(barrier)
        }.await;
        task.abort();
        // Reap the actual consumer while the real blocking worker is still held.
        let joined = task.await;
        let while_reaped = owned_file_fds(&path);
        gate.release();
        drop(release);
        let barrier = observed?;
        require(joined.is_err_and(|error| error.is_cancelled()), "original shared consumer was not actually reaped as cancelled")?;
        require(while_reaped?.len() == 1, "reaping the consumer falsely proved its original blocking worker ended")?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
        require(!gate.timed_out.load(Ordering::SeqCst) && owned_file_fds(&path)?.is_empty(),
            "shared worker ended only by timeout or retained its actual original FD")?;
        let reopened = fixture.state.read_current_artifact_chunk(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))).await;
        require(reopened.is_err() && gate.partial_events.load(Ordering::SeqCst) == 1,
            "closed shared key admitted another actual body worker")?;
        require(before == shared_lifecycle_business_facts(&fixture).await?,
            "shared cancellation changed original business/charge/receipt/fence/audit facts")?;
        require(path.is_file(), "shared drain was mistaken for actual object deletion")?;
        drop(ack); drop(barrier); drop(record);
        finish_shared_lifecycle_fixture(&fixture).await?;
        eprintln!("ARTIFACT_SHARED_WORKER consumer_cancel_reaped=true held_original_fd=true actual_worker_end=true original_fd_absent=true controlled_ack=true deletion=false auth_idle_touch=allowed");
        Ok(())
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; actual raw Vec and leased allocation have different scopes"]
async fn shared_read_barrier_legacy_and_leased_allocations_have_distinct_scope() {
    with_fixture("shared-legacy-vec", 256 * 1024, |fixture| async move {
        let record = shared_lifecycle_record(&fixture).await?;
        let before = shared_lifecycle_business_facts(&fixture).await?;
        let bytes = fixture.state.read_current_artifact_chunk(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .await.map_err(|error| error.to_string())?;
        let barrier = fixture.actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
        require(bytes == fixture.payload.as_bytes(), "controlled ACK was incorrectly treated as destruction of transferred raw Vec")?;
        require(owned_file_fds(&fixture.root.0.join("objects").join(&fixture.receipt.artifact_id))?.is_empty(),
            "legacy raw Vec transfer retained its original physical FD")?;
        let old = fixture.actual.read_authority().read_lifecycle(); old.close();
        require(old.drain_before(Instant::now() + Duration::from_secs(3)).await.is_ok(),
            "legacy limited inventory oracle changed")?;
        require(before == shared_lifecycle_business_facts(&fixture).await?, "raw Vec shared close changed original business facts")?;
        drop(bytes); drop(ack); drop(barrier); drop(record);
        finish_shared_lifecycle_fixture(&fixture).await?;
        eprintln!("ARTIFACT_SHARED_ALLOCATION fact=legacy_raw_vec external_lifetime=UNTRACKED bytes_still_valid_at_controlled_ack=true deletion_authorized=false");
        Ok(())
    }).await;
    with_fixture("shared-original-lease", 256 * 1024, |fixture| async move {
        let record = shared_lifecycle_record(&fixture).await?;
        let before = shared_lifecycle_business_facts(&fixture).await?;
        let mut operation = fixture.state.open_current_artifact_read(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone())
            .await.map_err(|error| error.to_string())?;
        let block = operation.next_block().await.map_err(|error| error.to_string())?.ok_or("original leased block missing")?;
        require(block.as_bytes() == fixture.payload.as_bytes(), "original leased allocation prefix differs")?;
        let path = fixture.root.0.join("objects").join(&fixture.receipt.artifact_id);
        let original_fds = owned_file_fds(&path)?;
        require(original_fds.len() == 1, "original leased block did not retain its actual FD")?;
        let barrier = fixture.actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err()
            && owned_file_fds(&path)? == original_fds,
            "shared ACK escaped a held full original leased allocation")?;
        drop(operation);
        require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(),
            "operation Drop substituted for the actual last allocation owner")?;
        drop(block);
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
        require(owned_file_fds(&path)?.is_empty() && path.is_file(), "leased resource end was not actual FD closure with object retained")?;
        require(before == shared_lifecycle_business_facts(&fixture).await?, "leased shared close changed original business facts")?;
        drop(ack); drop(barrier); drop(record);
        finish_shared_lifecycle_fixture(&fixture).await?;
        eprintln!("ARTIFACT_SHARED_ALLOCATION fact=original_lease held_no_ack=true operation_drop_no_ack=true last_allocation_owner_dropped=true original_fd_absent=true controlled_ack=true");
        Ok(())
    }).await;
}
