//! Actual Session/Application Save -> current saved-owner arm on an owned PG and Store.
//! Fault controllers change only their named original rows. Arm is not physical deletion.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use http::Request;
use openbot_application::{ApplicationService, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifact_read_protocol::OpenArtifactRead;
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_contracts::request_binding::HostRequestBindingError;
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::{
    ArmedArtifactCleanupIntent, ArtifactCleanupArmError as Error,
    ArtifactCleanupPhysicalError as PhysicalError, ArtifactCleanupPhysicalIoPhase as PhysicalPhase,
    ArtifactCleanupPhysicalObserver, ArtifactCleanupPhysicalState as PhysicalState,
    ArtifactCleanupTerminalError as TerminalError, ArtifactCleanupTerminalObserver,
    ArtifactCleanupTerminalPhase as TerminalPhase, ArtifactCleanupTerminalState as TerminalState,
    PostgresArtifactAdministration,
};
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::{
    ConnectionDestruction, ConnectionObservation, DatabaseConfig, DatabasePool,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const DEPLOYMENT: &str = "cleanup/deployment%成果";
const TENANT: &str = "cleanup-tenant";
const OWNER: &str = "cleanup-owner";
const ADMIN: &str = "cleanup-foreign-admin";
const COOKIE_A: &str = "owned-cleanup-original-session-cookie-a-001";
const COOKIE_B: &str = "owned-cleanup-other-session-cookie-b-002";
const COOKIE_ADMIN: &str = "owned-cleanup-foreign-admin-cookie-c-003";
const A_ID: &str = "cleanup-session-a";
const SESSION_KEY: &[u8] = b"owned-cleanup-session-hash-key";
const TEXT: &str = "  original saved cleanup text\n成果 café 🦀\t  ";
const AUDIT_LOCK: i64 = 0x4f50_454e_4155_4431;

// The complete source snapshot text follows the 1481-byte visible_run CTE. With PostgreSQL's
// 1kB default, pg_stat_activity truncates it before the asserted marker and FROM/JOIN text.
// The owned QA PostgreSQL contract fixes track_activity_query_size=16384; report its absence
// as the environment fact instead of a product statement that never reached its lock.
async fn require_activity_width(admin: &DatabasePool) -> Result<(), String> {
    let width: i64 = admin.get().await.map_err(|error| error.to_string())?
        .query_one("SELECT pg_catalog.pg_size_bytes(pg_catalog.current_setting('track_activity_query_size'))", &[])
        .await.map_err(|error| error.to_string())?.get(0);
    require(
        width >= 16_384,
        "owned PostgreSQL track_activity_query_size was not actually sixteen KiB",
    )
}

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
async fn resolve(resolver: &dyn AuthResolver, cookie: &str) -> Result<AuthContext, String> {
    let parts = Request::builder()
        .uri("/trusted-rust-artifact-cleanup")
        .header("cookie", format!("openbot_session={cookie}"))
        .body(())
        .map_err(|e| e.to_string())?
        .into_parts()
        .0;
    resolver.resolve(&parts).await.map_err(|e| e.to_string())
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let p =
            std::env::temp_dir().join(format!("openbot-artifact-cleanup-arm-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .map_err(|e| e.to_string())?;
        Ok(Self(p))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_CLEANUP_ARM_OWNED_ROOT removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned fixture root did not close");
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ObjectFact {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    sha256: String,
}
fn object_fact(path: &Path) -> Result<ObjectFact, String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        m.is_file() && m.mode() & 0o7777 == 0o400 && m.nlink() == 1,
        "original object identity/type/0400 drifted",
    )?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(ObjectFact {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}

async fn database_facts(pool: &DatabasePool) -> Result<BTreeMap<String, Value>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let tables = c.query("SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','openbot_internal') AND c.relkind='r' ORDER BY n.nspname,c.relname", &[]).await.map_err(|e| e.to_string())?;
    let mut facts = BTreeMap::new();
    for t in tables {
        let schema: String = t.get(0);
        let name: String = t.get(1);
        let quoted = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let sql = format!(
            "SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(t),'xmin',t.xmin::text,'ctid',t.ctid::text) ORDER BY to_jsonb(t)::text,t.ctid),'[]'::jsonb) FROM {}.{} t",
            quoted(&schema),
            quoted(&name)
        );
        facts.insert(
            format!("{schema}.{name}"),
            c.query_one(&sql, &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0),
        );
    }
    Ok(facts)
}
fn only_tables_changed(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    allowed: &[&str],
) -> Result<(), String> {
    require(
        before.keys().eq(after.keys()),
        "controller or producer added/removed an ordinary table",
    )?;
    for (table, original) in before {
        if !allowed.contains(&table.as_str()) && after.get(table) != Some(original) {
            return Err(format!(
                "unexpected ordinary table or physical row change: {table}"
            ));
        }
    }
    Ok(())
}
const ARM_TABLES: &[&str] = &[
    "openbot_internal.artifact_cleanup_fences",
    "public.audit_events",
    "public.audit_checkpoints",
];
fn original_arm_append_only(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<(), String> {
    only_tables_changed(before, after, ARM_TABLES)?;
    let old_fences = before
        .get("openbot_internal.artifact_cleanup_fences")
        .and_then(Value::as_array)
        .ok_or("original fence facts missing")?;
    let new_fences = after
        .get("openbot_internal.artifact_cleanup_fences")
        .and_then(Value::as_array)
        .ok_or("current fence facts missing")?;
    require(
        old_fences.is_empty() && new_fences.len() == 1,
        "first arm did not append exactly one fence to the owned empty inventory",
    )?;
    let old_audit = before
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("original audit facts missing")?;
    let new_audit = after
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("current audit facts missing")?;
    require(
        !old_audit.is_empty()
            && new_audit.len() == old_audit.len() + 1
            && old_audit.iter().all(|r| new_audit.contains(r)),
        "first arm changed a previous audit/physical row or appended more than one event",
    )?;
    require(
        before.get("public.audit_checkpoints") == after.get("public.audit_checkpoints"),
        "arm changed the existing real Save genesis/checkpoint",
    )
}

fn controller_update_columns(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
    columns: &[&str],
) -> Result<(), String> {
    let original = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original controller table missing")?;
    let current = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current controller table missing")?;
    let selects = |v: &&Value| {
        v.get("row")
            .and_then(|r| r.get(selector))
            .and_then(Value::as_str)
            == Some(id)
    };
    let old: Vec<_> = original.iter().filter(selects).collect();
    let new: Vec<_> = current.iter().filter(selects).collect();
    require(
        old.len() == 1 && new.len() == 1,
        "controller update was not on its unique actual original row",
    )?;
    require(
        original
            .iter()
            .filter(|v| !selects(v))
            .eq(current.iter().filter(|v| !selects(v))),
        "controller changed an unrelated row or physical row carrier",
    )?;
    let mut old_payload = old[0]["row"]
        .as_object()
        .ok_or("original row is not an object")?
        .clone();
    let mut new_payload = new[0]["row"]
        .as_object()
        .ok_or("current row is not an object")?
        .clone();
    let mut changed = false;
    for column in columns {
        let previous = old_payload
            .remove(*column)
            .ok_or("registered original controller column missing")?;
        let next = new_payload
            .remove(*column)
            .ok_or("registered current controller column missing")?;
        changed |= previous != next;
    }
    require(
        changed && old_payload == new_payload,
        "controller changed undeclared columns or did not change the registered column",
    )
}
fn controller_removed_row(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
) -> Result<(), String> {
    let old = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original removed-row table missing")?;
    let new = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current removed-row table missing")?;
    let retained: Vec<_> = old
        .iter()
        .filter(|v| v["row"][selector].as_str() != Some(id))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == old.len() && retained == *new,
        "controller removal did not preserve every unrelated row/physical carrier",
    )
}
fn controller_inserted_row(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    selector: &str,
    id: &str,
) -> Result<(), String> {
    let old = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("original inserted-row table missing")?;
    let new = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("current inserted-row table missing")?;
    let retained: Vec<_> = new
        .iter()
        .filter(|v| v["row"][selector].as_str() != Some(id))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == new.len() && retained == *old,
        "controller insertion did not preserve every unrelated row/physical carrier",
    )
}

struct Fixture {
    admin: DatabasePool,
    pool: DatabasePool,
    actual: Arc<PostgresArtifactAdministration>,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    resolver: Arc<PostgresSessionAuthResolver>,
    auth: AuthContext,
    application: Arc<dyn ApplicationService>,
    receipt: ArtifactRegistrationReceipt,
    root: OwnedRoot,
    relay: Option<OwnedRelay>,
}
impl Fixture {
    async fn new(config: DatabaseConfig, relay: bool) -> Result<Self, String> {
        let direct = config.clone().with_max_pool_size(5);
        let admin = pool::connect(&direct).await.map_err(|e| e.to_string())?;
        {
            let mut c = admin.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES ('cleanup-owner','cleanup-owner@example.test',0),('cleanup-foreign-admin','cleanup-admin@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('cleanup-owner','user'),('cleanup-foreign-admin','admin'); INSERT INTO public.agents(id,name,type,configuration) VALUES('cleanup-bot','Cleanup fixture','built_in','{}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('cleanup-bot','cleanup-owner','Cleanup fixture','fixture','fixture','public');").await.map_err(|e| e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, actor, token) in [
                (A_ID, OWNER, COOKIE_A),
                ("cleanup-session-b", OWNER, COOKIE_B),
                ("cleanup-session-admin", ADMIN, COOKIE_ADMIN),
            ] {
                c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)", &[&id,&actor,&token_column(token),&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e| e.to_string())?;
            }
        }
        let relay = if relay {
            Some(OwnedRelay::start(&direct).await?)
        } else {
            None
        };
        let production = relay
            .as_ref()
            .map_or(config.clone(), |r| r.config(&config))
            .with_max_pool_size(1);
        let pool = pool::connect(&production)
            .await
            .map_err(|e| e.to_string())?;
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([18; 16]),
                run_id: RunId::new("actual/cleanup-run%成果"),
                bot_id: BotId::new("cleanup-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            admin.clone(),
            direct,
            "cleanup-arm-owned-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(|e| e.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry.clone(),
                store.clone(),
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x18; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(|e| e.to_string())?,
        );
        resolver
            .install_artifact_read_authority(&actual.read_authority())
            .map_err(|_| "actual artifact authority installation refused")?;
        let auth = resolve(resolver.as_ref(), COOKIE_A).await?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(actual.clone()),
        );
        let reply = application
            .execute(
                auth.clone(),
                AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id,
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
                }),
            )
            .await
            .map_err(|e| e.to_string())?;
        let receipt = match reply {
            AppReply::ArtifactRegistrationReceipt(r) => r,
            _ => return Err("actual Save returned another reply".to_owned()),
        };
        Ok(Self {
            admin,
            pool,
            actual,
            registry,
            store,
            resolver,
            auth,
            application,
            receipt,
            root,
            relay,
        })
    }
    fn path(&self) -> PathBuf {
        self.root.0.join("objects").join(&self.receipt.artifact_id)
    }
    async fn arm(&self) -> Result<ArmedArtifactCleanupIntent, Error> {
        self.actual
            .arm_explicit_saved_delete_before(
                &self.auth,
                &self.receipt.artifact_id,
                Instant::now() + Duration::from_secs(10),
            )
            .await
    }
    async fn original(&self) -> Result<(i32, ConnectionObservation, Arc<SocketFacts>), String> {
        let c = self.pool.get().await.map_err(|e| e.to_string())?;
        let pid = c
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let observation = c.observation();
        let socket = self
            .relay
            .as_ref()
            .ok_or("original socket requires owned relay")?
            .socket_for_pid(pid)?;
        drop(c);
        Ok((pid, observation, socket))
    }
    async fn verify_one_arm(&self) -> Result<(), String> {
        let c = self.admin.get().await.map_err(|e| e.to_string())?;
        let rows = c.query("SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase FROM openbot_internal.artifact_cleanup_fences", &[]).await.map_err(|e| e.to_string())?;
        require(
            rows.len() == 1,
            "arm did not write exactly one original fence",
        )?;
        let r = &rows[0];
        require(
            r.get::<_, String>(0) == DEPLOYMENT
                && r.get::<_, String>(1) == TENANT
                && r.get::<_, String>(2) == self.registry.binding().dataset_id()
                && r.get::<_, String>(3) == self.receipt.operation_id
                && r.get::<_, String>(4) == self.receipt.artifact_id
                && r.get::<_, String>(5) == "deleted"
                && r.get::<_, String>(6) == "armed",
            "arm rebound the original five-key or intent",
        )?;
        let a=c.query("SELECT actor_user_id,event_type,target_type,target_id,payload,row_hash FROM public.audit_events WHERE event_type='artifact.cleanup_armed'",&[]).await.map_err(|e|e.to_string())?;
        require(a.len() == 1, "arm audit was absent or duplicated")?;
        let p: Value = a[0].get("payload");
        require(
            a[0].get::<_, Option<String>>("actor_user_id").as_deref() == Some(OWNER)
                && a[0].get::<_, String>("target_type") == "artifact"
                && a[0].get::<_, Option<String>>("target_id").as_deref()
                    == Some(self.receipt.artifact_id.as_str())
                && p == serde_json::json!({"artifact_id":self.receipt.artifact_id,"artifact_operation_id":self.receipt.operation_id})
                && a[0]
                    .get::<_, Option<String>>("row_hash")
                    .is_some_and(|h| h.len() == 64),
            "arm audit changed fixed typed fields, target or owner",
        )
    }
    async fn finish(mut self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        let observations = self.pool.connection_observations();
        // This is the original fixture's real stock admission shutdown, after
        // every body assertion. Only the observations below prove destruction.
        self.pool.close();
        self.admin.close();
        let relay = self.relay.take();
        drop(self);
        let deadline = Instant::now() + Duration::from_secs(3);
        let observation_count = observations.len();
        for (index, o) in observations.into_iter().enumerate() {
            let original = o.snapshot();
            let expected = if original.connection_started {
                ConnectionDestruction::ConnectionDestroyed
            } else if original.connecting_future_started {
                ConnectionDestruction::ConnectingFutureDestroyed
            } else {
                ConnectionDestruction::ConnectingOwnerDestroyedBeforeStart
            };
            let destroyed = o.wait_for_destruction_before(deadline).await.map_err(|error| {
                eprintln!("ARTIFACT_CLEANUP_ARM_FIXTURE_TAIL_ERROR index={index} count={observation_count} before={original:?} after={:?}", o.snapshot());
                error.to_string()
            })?;
            require(
                destroyed == expected,
                "original production connection owner did not close its actually started resource",
            )?;
        }
        if let Some(r) = relay {
            r.finish().await?;
        }
        Ok(())
    }
}

// Only this test file owns this finite protocol relay. It forwards an already owned local PG
// endpoint, records a backend PID and three command ACK bits, and can withhold one ACK/startup.
// Startup/password/SQL packet bytes are neither logged nor retained as diagnostic evidence.
const BEGIN_BIT: u8 = 1;
const COMMIT_BIT: u8 = 2;
const ROLLBACK_BIT: u8 = 4;
#[derive(Clone, Copy)]
#[repr(u8)]
enum Hold {
    Startup = 1,
    Begin = 2,
    Commit = 3,
    Rollback = 4,
}
#[derive(Default)]
struct SocketFacts {
    pid: AtomicI32,
    frontend_eof: AtomicBool,
    entered: AtomicU8,
    server_ack: AtomicU8,
    forwarded_ack: AtomicU8,
    withheld: AtomicU8,
    release_original_ack: AtomicU8,
    hold_next_begin_after_forwarded_rollback: AtomicBool,
    forwarded_host_rollback_before_source_begin: AtomicBool,
    post_schema_source_begin_held: AtomicBool,
    post_schema_source_begin_forwarded: AtomicBool,
    // Actual ErrorResponse observation for the one owned terminal audit INSERT fault only.
    terminal_g35_audit_fault_p0001: AtomicBool,
    terminal_g35_audit_fault_error_forwarded: AtomicBool,
}
#[derive(Default)]
struct RelayState {
    next: AtomicU64,
    hold: AtomicU8,
    sockets: Mutex<BTreeMap<u64, Arc<SocketFacts>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
struct OwnedRelay {
    address: SocketAddr,
    state: Arc<RelayState>,
    accept: tokio::task::JoinHandle<()>,
}
struct AbortPump(tokio::task::JoinHandle<Result<(), std::io::Error>>);
impl Drop for AbortPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl OwnedRelay {
    fn release_original_ack(&self, socket: &SocketFacts, hold: Hold) -> Result<(), String> {
        require(
            socket.withheld.load(Ordering::SeqCst) == hold as u8,
            "release did not address the actual held original socket",
        )?;
        socket
            .release_original_ack
            .store(hold as u8, Ordering::SeqCst);
        Ok(())
    }
    async fn finish(mut self) -> Result<(), String> {
        self.accept.abort();
        require(
            (&mut self.accept).await.is_err_and(|e| e.is_cancelled()),
            "owned relay accept task did not join its requested stop",
        )?;
        let tasks = std::mem::take(
            &mut *self
                .state
                .tasks
                .lock()
                .map_err(|_| "owned relay task inventory poisoned")?,
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        for mut task in tasks {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Err("original owned relay connection task failed to join".to_owned());
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Err(
                        "original relay connection required abort rather than natural EOF"
                            .to_owned(),
                    );
                }
            }
        }
        require(
            self.state
                .sockets
                .lock()
                .map_err(|_| "owned relay socket inventory poisoned")?
                .values()
                .all(|s| s.frontend_eof.load(Ordering::SeqCst)),
            "owned relay original socket lacks natural EOF",
        )
    }
    async fn start(config: &DatabaseConfig) -> Result<Self, String> {
        let ip = config
            .host
            .parse::<IpAddr>()
            .map_err(|_| "relay requires owned numeric loopback PG".to_owned())?;
        require(ip.is_loopback(), "relay refused a non-loopback PG endpoint")?;
        let upstream = SocketAddr::new(ip, config.port);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| "owned relay bind failed".to_owned())?;
        let address = listener
            .local_addr()
            .map_err(|_| "owned relay address failed".to_owned())?;
        let state = Arc::new(RelayState::default());
        let shared = state.clone();
        let accept = tokio::spawn(async move {
            while let Ok((front, _)) = listener.accept().await {
                let id = shared.next.fetch_add(1, Ordering::SeqCst);
                let facts = Arc::new(SocketFacts::default());
                shared
                    .sockets
                    .lock()
                    .expect("relay socket facts")
                    .insert(id, facts.clone());
                let connection_state = shared.clone();
                let task = tokio::spawn(async move {
                    let _ = relay_original(front, upstream, &connection_state, &facts).await;
                });
                shared.tasks.lock().expect("relay owned tasks").push(task);
            }
        });
        Ok(Self {
            address,
            state,
            accept,
        })
    }
    fn config(&self, config: &DatabaseConfig) -> DatabaseConfig {
        let mut config = config.clone();
        config.host = self.address.ip().to_string();
        config.port = self.address.port();
        config
    }
    fn arm(&self, hold: Hold) {
        self.state.hold.store(hold as u8, Ordering::SeqCst);
    }
    fn socket_for_pid(&self, pid: i32) -> Result<Arc<SocketFacts>, String> {
        self.state
            .sockets
            .lock()
            .map_err(|_| "relay facts poisoned".to_owned())?
            .values()
            .find(|f| f.pid.load(Ordering::SeqCst) == pid)
            .cloned()
            .ok_or_else(|| "original PID did not belong to this relay socket".to_owned())
    }
    fn newest_socket(&self) -> Result<Arc<SocketFacts>, String> {
        self.state
            .sockets
            .lock()
            .map_err(|_| "relay facts poisoned".to_owned())?
            .last_key_value()
            .map(|(_, f)| f.clone())
            .ok_or_else(|| "owned relay has not accepted original socket".to_owned())
    }
}
impl Drop for OwnedRelay {
    fn drop(&mut self) {
        self.accept.abort();
        if let Ok(tasks) = self.state.tasks.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}

fn command_bit(bytes: &[u8]) -> u8 {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let text = text.trim_end_matches('\0').trim().to_ascii_uppercase();
    if text == "BEGIN" || text.starts_with("BEGIN ") || text.starts_with("START TRANSACTION") {
        BEGIN_BIT
    } else if text == "COMMIT" || text == "COMMIT;" {
        COMMIT_BIT
    } else if text == "ROLLBACK" || text == "ROLLBACK;" {
        ROLLBACK_BIT
    } else {
        0
    }
}
async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Option<Vec<u8>>> {
    let mut kind = [0u8; 1];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let mut length = [0u8; 4];
    reader.read_exact(&mut length).await?;
    let n = u32::from_be_bytes(length) as usize;
    if !(4..=1024 * 1024).contains(&n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "owned PG frame bound",
        ));
    }
    let mut packet = vec![0; n + 1];
    packet[0] = kind[0];
    packet[1..5].copy_from_slice(&length);
    reader.read_exact(&mut packet[5..]).await?;
    Ok(Some(packet))
}
async fn relay_original(
    mut front: TcpStream,
    upstream: SocketAddr,
    state: &Arc<RelayState>,
    facts: &Arc<SocketFacts>,
) -> std::io::Result<()> {
    let mut length = [0u8; 4];
    front.read_exact(&mut length).await?;
    let n = u32::from_be_bytes(length) as usize;
    if !(8..=1024 * 1024).contains(&n) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "owned PG startup bound",
        ));
    }
    let mut startup = vec![0; n];
    startup[..4].copy_from_slice(&length);
    front.read_exact(&mut startup[4..]).await?;
    if state
        .hold
        .compare_exchange(Hold::Startup as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        facts.withheld.store(Hold::Startup as u8, Ordering::SeqCst);
        drop(startup);
        let mut discard = [0u8; 4096];
        loop {
            if front.read(&mut discard).await? == 0 {
                facts.frontend_eof.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }
    }
    let mut backend = TcpStream::connect(upstream).await?;
    backend.write_all(&startup).await?;
    drop(startup);
    let (mut frontend_read, mut frontend_write) = front.into_split();
    let (mut backend_read, mut backend_write) = backend.into_split();
    let backend_facts = facts.clone();
    let backend_state = state.clone();
    let mut server = AbortPump(tokio::spawn(async move {
        let mut holding = 0;
        let mut original_held_packets = Vec::new();
        while let Some(packet) = frame(&mut backend_read).await? {
            let terminal_g35_fault = terminal_g35_is_original_audit_fault(&packet);
            if terminal_g35_fault {
                backend_facts
                    .terminal_g35_audit_fault_p0001
                    .store(true, Ordering::SeqCst);
            }
            if packet[0] == b'K' && packet.len() == 13 {
                backend_facts.pid.store(
                    i32::from_be_bytes(packet[5..9].try_into().expect("PID width")),
                    Ordering::SeqCst,
                );
            }
            let bit = if packet[0] == b'C' {
                command_bit(&packet[5..])
            } else {
                0
            };
            if bit != 0 {
                backend_facts.server_ack.fetch_or(bit, Ordering::SeqCst);
                let selected = match bit {
                    BEGIN_BIT => Hold::Begin,
                    COMMIT_BIT => Hold::Commit,
                    _ => Hold::Rollback,
                };
                if backend_state
                    .hold
                    .compare_exchange(selected as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    holding = selected as u8;
                    backend_facts.withheld.store(holding, Ordering::SeqCst);
                    if selected as u8 == Hold::Begin as u8
                        && backend_facts
                            .forwarded_host_rollback_before_source_begin
                            .load(Ordering::SeqCst)
                    {
                        backend_facts
                            .post_schema_source_begin_held
                            .store(true, Ordering::SeqCst);
                    }
                }
            }
            if holding == 0 {
                frontend_write.write_all(&packet).await?;
                if terminal_g35_fault {
                    backend_facts
                        .terminal_g35_audit_fault_error_forwarded
                        .store(true, Ordering::SeqCst);
                }
                if bit != 0 {
                    backend_facts.forwarded_ack.fetch_or(bit, Ordering::SeqCst);
                    if bit == ROLLBACK_BIT
                        && backend_facts
                            .hold_next_begin_after_forwarded_rollback
                            .swap(false, Ordering::SeqCst)
                    {
                        // This same original ACK was actually written. Arm the following
                        // BEGIN before forwarding ReadyForQuery lets the caller continue.
                        backend_state
                            .hold
                            .compare_exchange(
                                0,
                                Hold::Begin as u8,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .map_err(|_| {
                                std::io::Error::other(
                                    "original source BEGIN gate collided with another hold",
                                )
                            })?;
                        backend_facts
                            .forwarded_host_rollback_before_source_begin
                            .store(true, Ordering::SeqCst);
                    }
                }
            } else {
                let ready = packet[0] == b'Z';
                original_held_packets.push(packet);
                if ready {
                    // The exact original upstream packets are retained without alteration.
                    // Loss/deadline fixtures never release them; genuine host-tail fixtures
                    // explicitly release this same accepted socket before its original budget.
                    while backend_facts.release_original_ack.load(Ordering::SeqCst) != holding {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    for original in original_held_packets.drain(..) {
                        frontend_write.write_all(&original).await?;
                        if original[0] == b'C' {
                            let original_bit = command_bit(&original[5..]);
                            backend_facts
                                .forwarded_ack
                                .fetch_or(original_bit, Ordering::SeqCst);
                            if original_bit == BEGIN_BIT
                                && holding == Hold::Begin as u8
                                && backend_facts
                                    .post_schema_source_begin_held
                                    .load(Ordering::SeqCst)
                            {
                                backend_facts
                                    .post_schema_source_begin_forwarded
                                    .store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    backend_facts
                        .release_original_ack
                        .store(0, Ordering::SeqCst);
                    holding = 0;
                }
            }
        }
        Ok::<(), std::io::Error>(())
    }));
    let outcome = async {
        let mut backend_writable = true;
        loop {
            let Some(packet) = frame(&mut frontend_read).await? else {
                facts.frontend_eof.store(true, Ordering::SeqCst);
                return Ok::<(), std::io::Error>(());
            };
            if packet[0] == b'Q' {
                facts
                    .entered
                    .fetch_or(command_bit(&packet[5..]), Ordering::SeqCst);
            }
            if backend_writable && backend_write.write_all(&packet).await.is_err() {
                backend_writable = false;
            }
        }
    }
    .await;
    server.0.abort();
    let _ = (&mut server.0).await;
    outcome
}

async fn wait_fact(
    fact: impl Fn() -> bool,
    deadline: Instant,
    message: &'static str,
) -> Result<(), String> {
    loop {
        if fact() {
            return Ok(());
        }
        require(Instant::now() < deadline, message)?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn retired_original(
    f: &Fixture,
    pid: i32,
    observation: &ConnectionObservation,
    socket: &SocketFacts,
) -> Result<(), String> {
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    require(
        observation
            .wait_for_destruction_before(cleanup_deadline)
            .await
            .map_err(|e| e.to_string())?
            == ConnectionDestruction::ConnectionDestroyed,
        "original owned Connection destructor was not observed",
    )?;
    wait_fact(
        || socket.frontend_eof.load(Ordering::SeqCst),
        cleanup_deadline,
        "corresponding original accepted socket had no EOF",
    )
    .await?;
    loop {
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        let alive = c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1)",
                &[&pid],
            )
            .await
            .map_err(|e| e.to_string())?
            .get::<_, bool>(0);
        if !alive {
            break;
        }
        require(
            Instant::now() < cleanup_deadline,
            "original owned PG backend persisted after destructor and EOF",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let c = f.pool.get().await.map_err(|e| e.to_string())?;
    require(
        c.query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get::<_, i32>(0)
            != pid,
        "failed original connection returned to the pool",
    )
}
fn original_five_seconds(started: Instant) -> Result<(), String> {
    let elapsed = started.elapsed();
    require(
        elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_millis(6250),
        "one entry's five-second deadline was shortened or renewed across an await",
    )
}

fn clear_transaction_facts(socket: &SocketFacts) {
    socket.entered.store(0, Ordering::SeqCst);
    socket.server_ack.store(0, Ordering::SeqCst);
    socket.forwarded_ack.store(0, Ordering::SeqCst);
    socket.withheld.store(0, Ordering::SeqCst);
    socket.release_original_ack.store(0, Ordering::SeqCst);
}

async fn wait_blocked(
    admin: &DatabasePool,
    pid: i32,
    query_fragment: &str,
    controller_pid: i32,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let c = admin.get().await.map_err(|e| e.to_string())?;
        let row = c
            .query_opt(
                "SELECT wait_event_type='Lock' AND position($2::text in query)>0 AND $3::integer=ANY(pg_catalog.pg_blocking_pids(pid)) AS blocked
             FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&pid, &query_fragment, &controller_pid],
            )
            .await
            .map_err(|e| e.to_string())?;
        if row.is_some_and(|r| r.get::<_, Option<bool>>(0) == Some(true)) {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "original operation did not reach its intended actual PG wait",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn with_fixture<F>(tag: &str, relay: bool, body: F)
where
    F: for<'a> FnOnce(
        &'a Fixture,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    >,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config, relay).await?;
        let outcome = body(&f).await;
        let cleaned = f.finish().await;
        outcome.and(cleaned)
    })
    .await;
}
fn owned_object_fds(path: &Path) -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return owned_macos_object_fds(path);
    }
    let original = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    let inventory = "/proc/self/fd";
    let mut fds = Vec::new();
    for entry in std::fs::read_dir(inventory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if std::fs::metadata(entry.path())
            .is_ok_and(|m| m.is_file() && m.dev() == original.dev() && m.ino() == original.ino())
        {
            fds.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    fds.sort();
    Ok(fds)
}

// The same bounded, own-PID device/inode oracle exercised by the real 017 leased case.
// macOS /dev/fd entries have devfs metadata; they are not Linux procfs descriptor aliases.
fn owned_macos_object_fds(path: &Path) -> Result<Vec<String>, String> {
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
    Ok(first.into_iter().map(|fd| fd.to_string()).collect())
}
async fn hard_delete_original_message(f: &Fixture) -> Result<(), String> {
    let before = database_facts(&f.admin).await?;
    let mut c = f.admin.get().await.map_err(|e| e.to_string())?;
    let tx = c.transaction().await.map_err(|e| e.to_string())?;
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        tx.execute(
            "DELETE FROM public.messages WHERE message_id=$1",
            &[&f.receipt.source_message_id],
        )
        .await
        .map_err(|e| e.to_string())?
            == 1,
        "source controller did not hard-delete exactly the original message",
    )?;
    tx.commit().await.map_err(|e| e.to_string())?;
    drop(c);
    let after = database_facts(&f.admin).await?;
    only_tables_changed(&before, &after, &["public.messages"])?;
    controller_removed_row(
        &before,
        &after,
        "public.messages",
        "message_id",
        &f.receipt.source_message_id,
    )?;
    require(
        before.get("public.messages") != after.get("public.messages"),
        "source controller had no actual committed row difference",
    )?;
    eprintln!(
        "ARTIFACT_CLEANUP_ARM_CONTROLLER kind=original_message_hard_delete controller_pid={pid} commit_ack=true changed_tables=public.messages retained_pair_unchanged=true"
    );
    Ok(())
}
async fn read_is_404(f: &Fixture) -> Result<(), String> {
    require(
        matches!(
            f.application
                .read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone())
                .await,
            Err(AppError::NotVisible)
        ),
        "missing source body did not remain original404",
    )?;
    require(
        matches!(
            f.application
                .execute(
                    f.auth.clone(),
                    AppCommand::GetArtifactMetadata(
                        openbot_contracts::artifacts::GetArtifactMetadata {
                            artifact_id: f.receipt.artifact_id.clone()
                        }
                    )
                )
                .await,
            Err(AppError::NotVisible)
        ),
        "cleanup owner management exposed missing-source metadata",
    )
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and owned Store; exact include-ignored only"]
async fn current_saved_owner_arms_after_source_hard_delete_and_read_stays_404() {
    with_fixture("cleanup-original-owner",false,|f|Box::pin(async move {
        let original=object_fact(&f.path())?;
        let mut operation=f.application.open_current_artifact_read(f.auth.clone(),f.receipt.artifact_id.clone()).await.map_err(|e|e.to_string())?;
        let pending=operation.next_block(&f.auth).await.map_err(|e|e.to_string())?;
        require(pending.prefix_length().map_err(|e|e.to_string())?==TEXT.len(),"original Application did not materialize its actual pending allocation")?;
        let frame=pending.handoff_frame(&f.auth).map_err(|e|e.to_string())?;
        require(frame.as_bytes()==TEXT.as_bytes(),"original leased frame differs from actual saved bytes")?;
        let original_fds=owned_object_fds(&f.path())?;
        require(original_fds.len()==1,"original leased allocation did not own exactly its real object FD")?;
        hard_delete_original_message(f).await?; read_is_404(f).await?;
        let before=database_facts(&f.admin).await?;
        let intent=f.arm().await.map_err(|e|e.to_string())?;
        f.verify_one_arm().await?;
        let after=database_facts(&f.admin).await?; original_arm_append_only(&before,&after)?;
        require(object_fact(&f.path())?==original,"arm changed or removed original bytes/charge backing")?;
        let barrier=f.actual.close_armed_artifact_reads(&intent).map_err(|e|e.to_string())?;
        require(barrier.drain_before(Instant::now()+Duration::from_millis(25)).await.is_err(),"armed bridge ACKed while the original leased allocation and FD remained")?;
        require(frame.verify_current_tail(&f.auth).is_err(),"closed original leased frame still provided a current delivery witness")?;
        require(owned_object_fds(&f.path())?==original_fds,"stop request was mistaken for actual original FD release")?;
        drop(operation);
        require(barrier.drain_before(Instant::now()+Duration::from_millis(25)).await.is_err()&&owned_object_fds(&f.path())?==original_fds,"operation Drop substituted for the original last complete allocation owner")?;
        drop(frame);
        let ack=barrier.drain_before(Instant::now()+Duration::from_secs(3)).await.map_err(|e|format!("{e:?}"))?;
        require(owned_object_fds(&f.path())?.is_empty() && object_fact(&f.path())?==original,"finite ACK did not follow actual FD drop or physically deleted object")?;
        read_is_404(f).await?;
        require(database_facts(&f.admin).await?==after,"finite close or missing-source reads wrote business facts")?;
        drop(ack);drop(barrier);drop(intent);
        eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_OWNER source_message_absent=true saved_owner_current=true original_commit_ack=true exact_arm_audit=true original_leased_allocation_materialized=true held_allocation_no_ack=true operation_drop_no_ack=true last_allocation_owner_dropped=true original_fd_drop_ack=true object_unchanged=true physical_delete=false");
        Ok(())
    })).await;
}

async fn original_session_revocation_read_leg(
    f: &Fixture,
    operation_path: bool,
) -> Result<(), String> {
    let phase = if operation_path { "operation" } else { "chunk" };
    let original_object = object_fact(&f.path())?;
    let before = database_facts(&f.admin).await?;
    let (original_pid, _original_connection, socket) = f.original().await?;
    clear_transaction_facts(&socket);
    let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        transaction
            .execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID])
            .await
            .map_err(|error| error.to_string())?
            == 1,
        "P1 controller did not revoke exactly the actual original Session",
    )?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    drop(controller);
    let revoked = database_facts(&f.admin).await?;
    only_tables_changed(&before, &revoked, &["public.sessions"])?;
    let old_sessions = before["public.sessions"]
        .as_array()
        .ok_or("P1 original sessions missing")?;
    let retained: Vec<_> = old_sessions
        .iter()
        .filter(|row| row["row"]["id"].as_str() != Some(A_ID))
        .cloned()
        .collect();
    require(
        retained.len() + 1 == old_sessions.len()
            && revoked["public.sessions"].as_array() == Some(&retained),
        "P1 Session revoke changed another session or physical row carrier",
    )?;

    // Construct this actual operation after revocation so the real preliminary Host
    // port, rather than a preceding close_binding stop, produces the refusal.
    let old_error = if operation_path {
        let mut operation = f
            .application
            .open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 old operation construction: {error}"))?;
        let result = operation.next_block(&f.auth).await;
        drop(operation);
        result.err()
    } else {
        f.application
            .read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone())
            .await
            .err()
    };
    require(
        matches!(old_error, Some(AppError::Unauthenticated)),
        "P1 revoked original Session did not preserve its actual Host refusal",
    )?;
    let rollback = Hold::Rollback as u8;
    require(
        socket.server_ack.load(Ordering::SeqCst) & rollback != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & rollback != 0
            && socket.withheld.load(Ordering::SeqCst) == 0,
        "P1 known Session refusal lacked the original forwarded ROLLBACK ACK",
    )?;
    require(
        database_facts(&f.admin).await? == revoked && object_fact(&f.path())? == original_object,
        "P1 old Session refusal changed original business rows or object",
    )?;

    let fresh = resolve(f.resolver.as_ref(), COOKIE_B).await?;
    require(
        fresh == f.auth
            && !fresh
                .request_binding()
                .ok_or("P1 new Session binding missing")?
                .identity()
                .same_binding(
                    f.auth
                        .request_binding()
                        .ok_or("P1 old Session binding missing")?
                        .identity(),
                ),
        "P1 new real Session changed six Auth facts or reused the revoked Session identity",
    )?;
    fresh
        .request_binding()
        .ok_or("P1 fresh Session missing")?
        .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|error| format!("P1 new real Session was not current: {error:?}"))?;
    let after_auth = database_facts(&f.admin).await?;
    only_tables_changed(&revoked, &after_auth, &["public.sessions"])?;
    let mut expected_sessions = revoked["public.sessions"]
        .as_array()
        .ok_or("P1 revoked sessions missing")?
        .clone();
    let fresh_sessions = after_auth["public.sessions"]
        .as_array()
        .ok_or("P1 fresh sessions missing")?;
    require(
        expected_sessions.len() == fresh_sessions.len(),
        "P1 new authentication changed the Session inventory",
    )?;
    for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
        if old["row"]["id"].as_str() == Some("cleanup-session-b") {
            old["row"]["updated_at"] = new["row"]["updated_at"].clone();
            old["xmin"] = new["xmin"].clone();
            old["ctid"] = new["ctid"].clone();
        }
    }
    require(
        expected_sessions == *fresh_sessions,
        "P1 new Session authentication changed fields beyond its original idle clock",
    )?;

    // Exercise the same original first-chunk path with the new valid Host. A raw
    // returned Vec is outside the finite allocation ACK and is never used as its proof.
    if !operation_path {
        let chunk = f
            .application
            .read_current_artifact_chunk(fresh.clone(), f.receipt.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 fresh same-Store chunk remained refused: {error}"))?;
        require(
            owned_object_fds(&f.path())?.len() == 1,
            "P1 real legacy chunk did not retain its original target FD before handoff",
        )?;
        let bytes = chunk.handoff(&fresh).map_err(|error| error.to_string())?;
        require(
            bytes == TEXT.as_bytes(),
            "P1 new Session chunk changed original saved bytes",
        )?;
        drop(bytes);
        require(
            owned_object_fds(&f.path())?.is_empty(),
            "P1 original legacy target FD did not close after its synchronous handoff",
        )?;
    }
    let mut operation = f
        .application
        .open_current_artifact_read(fresh.clone(), f.receipt.artifact_id.clone())
        .await
        .map_err(|error| format!("P1 fresh same-Store operation remained refused: {error}"))?;
    let pending = operation
        .next_block(&fresh)
        .await
        .map_err(|error| format!("P1 fresh same-Store block remained refused: {error}"))?;
    require(
        pending.prefix_length().map_err(|error| error.to_string())? == TEXT.len(),
        "P1 new Session did not materialize the genuine full leased allocation",
    )?;
    let frame = pending
        .handoff_frame(&fresh)
        .map_err(|error| error.to_string())?;
    require(
        frame.as_bytes() == TEXT.as_bytes(),
        "P1 new Session leased frame changed original saved bytes",
    )?;
    let held_fds = owned_object_fds(&f.path())?;
    require(
        held_fds.len() == 1,
        "P1 new real Session did not own exactly its original object FD",
    )?;
    let record = f
        .actual
        .observe_read_record(&fresh, &f.receipt.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let barrier = f
        .actual
        .close_observed_artifact_reads(&record)
        .map_err(|error| error.to_string())?;
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ),
        "P1 fresh Session inventory ACKed a held real allocation or stayed poisoned",
    )?;
    drop(operation);
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ) && owned_object_fds(&f.path())? == held_fds,
        "P1 operation Drop substituted for the original last allocation owner",
    )?;
    drop(frame);
    let ack = barrier
        .drain_before(Instant::now() + Duration::from_secs(3))
        .await
        .map_err(|error| {
            format!("P1 same original Store failed its real finite drain: {error:?}")
        })?;
    require(
        owned_object_fds(&f.path())?.is_empty()
            && object_fact(&f.path())? == original_object
            && database_facts(&f.admin).await? == after_auth,
        "P1 actual frame/FD closure changed original business facts or retained its FD",
    )?;
    drop(ack);
    drop(barrier);
    eprintln!(
        "ARTIFACT_READ_P1_SESSION leg={phase} original_pid={original_pid} revoke_controller_pid={controller_pid} original_session_delete_commit_ack=true original_read_unauthenticated=true original_rollback_ack_forwarded=true new_real_session_current=true same_store_same_pair=true new_actual_bytes=true held_allocation_no_ack=true last_original_owner_dropped=true original_fd_absent=true finite_controlled_ack=true physical_delete=false legacy_returned_vec_lifetime=UNTRACKED"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL, original Session revocation and same owned Store"]
async fn revoked_original_server_session_does_not_poison_new_same_store_artifact_reads_and_drain() {
    let failures = Arc::new(Mutex::new(Vec::new()));
    for operation_path in [false, true] {
        let tag = if operation_path {
            "p1_session_operation"
        } else {
            "p1_session_chunk"
        };
        let failures = Arc::clone(&failures);
        with_fixture(tag, true, move |fixture| {
            Box::pin(async move {
                let outcome = original_session_revocation_read_leg(fixture, operation_path).await;
                if let Err(error) = outcome {
                    eprintln!("ARTIFACT_READ_P1_SESSION leg={tag} actual_result=FAILED");
                    failures
                        .lock()
                        .map_err(|_| "P1 failure aggregation poisoned")?
                        .push(format!("{tag}: {error}"));
                }
                // Preserve both real sub-leg failures while letting the original fixture
                // close before the final single libtest result is asserted below.
                Ok(())
            })
        })
        .await;
    }
    let failures = failures.lock().expect("P1 original failure records");
    assert!(
        failures.is_empty(),
        "genuine old/new Session read and finite drain regressions: {failures:?}"
    );
}

#[tokio::test]
#[ignore = "requires actual original guarded read, withheld ROLLBACK ACK and same owned Store"]
async fn lost_original_guarded_read_rollback_ack_keeps_same_store_unproven_after_owner_revocation()
{
    with_fixture("p1-original-read-rollback-unknown", true, |f| Box::pin(async move {
        // This genuine original record supplies only the existing finite close key.
        // It neither replaces the Store nor proves deletion or a public read grant.
        let original_record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await
            .map_err(|error| error.to_string())?;
        let original_object = object_fact(&f.path())?;
        let before = database_facts(&f.admin).await?;
        let (original_pid, original_connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let relay = f.relay.as_ref().ok_or("P1 original guarded read relay missing")?;
        let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
        let transaction = controller.transaction().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = transaction.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.get(0);
        socket.hold_next_begin_after_forwarded_rollback.store(true, Ordering::SeqCst);
        let application = Arc::clone(&f.application);
        let original_auth = f.auth.clone();
        let artifact_id = f.receipt.artifact_id.clone();
        let started = Instant::now();
        let worker = tokio::spawn(async move {
            application.execute(original_auth, AppCommand::OpenArtifactRead(OpenArtifactRead { artifact_id })).await
        });
        let controlled = async {
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8
                && socket.forwarded_host_rollback_before_source_begin.load(Ordering::SeqCst)
                && socket.post_schema_source_begin_held.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 original source BEGIN ACK was not held after the actual forwarded Host ROLLBACK").await?;
            require(socket.pid.load(Ordering::SeqCst) == original_pid
                && !socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                "P1 source BEGIN hold changed original producer or had already forwarded its ACK")?;
            let observer = f.admin.get().await.map_err(|error| error.to_string())?;
            let row = observer.query_one(
                "SELECT pg_catalog.pg_backend_pid() AS observer_pid,state,query,xact_start IS NOT NULL AS actual_transaction FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&original_pid],
            ).await.map_err(|error| error.to_string())?;
            let begin_observer_pid: i32 = row.get("observer_pid");
            let begin_query: String = row.get("query");
            require(begin_observer_pid != original_pid && begin_observer_pid != controller_pid && original_pid != controller_pid
                && row.get::<_, Option<String>>("state").as_deref() == Some("idle in transaction")
                && row.get::<_, bool>("actual_transaction")
                && (begin_query.trim_start().starts_with("BEGIN") || begin_query.trim_start().starts_with("START TRANSACTION"))
                && begin_query.contains("READ COMMITTED") && begin_query.contains("READ ONLY"),
                "P1 held post-schema source BEGIN was not the original read-only transaction with distinct observer/controller")?;
            drop(observer);
            // The original source schema is now complete; its actual BEGIN ACK remains
            // withheld so no source table query can preempt this genuine controller lock.
            require_activity_width(&f.admin).await?;
            transaction.batch_execute("LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE").await
                .map_err(|error| error.to_string())?;
            relay.release_original_ack(&socket, Hold::Begin)?;
            wait_fact(|| socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 did not release exactly the held original post-schema source BEGIN ACK").await?;
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            let observer_pid = loop {
                let observer = f.admin.get().await.map_err(|error| error.to_string())?;
                let row = observer.query_opt(
                    "SELECT pg_catalog.pg_backend_pid() AS observer_pid,query,wait_event_type,pg_catalog.pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                    &[&original_pid],
                ).await.map_err(|error| error.to_string())?;
                if let Some(row) = row {
                    let query: String = row.get("query");
                    let wait_type: Option<String> = row.get("wait_event_type");
                    let blockers: Vec<i32> = row.get("blockers");
                    if wait_type.as_deref() == Some("Lock")
                        && blockers.contains(&controller_pid)
                        && query.contains("artifact_private_read_record_snapshot")
                        && query.contains("FROM visible_run r JOIN openbot_internal.artifact_records a")
                        && query.contains("LEFT JOIN openbot_internal.artifact_cleanup_fences c")
                    {
                        let observer_pid: i32 = row.get("observer_pid");
                        require(original_pid != controller_pid && observer_pid != original_pid && observer_pid != controller_pid,
                            "P1 source query producer/controller/observer were not distinct actual backends")?;
                        break observer_pid;
                    }
                }
                require(Instant::now() < wait_deadline,
                    "P1 original guarded read never reached the complete source snapshot at its actual controller lock")?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            // Preliminary Host and schema queries are already past. Withhold only the
            // ensuing original guarded read's ROLLBACK, after the proven source wait.
            clear_transaction_facts(&socket);
            relay.arm(Hold::Rollback);
            transaction.rollback().await.map_err(|error| error.to_string())?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2),
                "P1 actual original guarded read ROLLBACK did not reach its upstream ACK").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
                && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P1 read uncertainty was not its actual original upstream ROLLBACK ACK withheld from the driver")?;
            Ok::<i32, String>(observer_pid)
        }.await;
        drop(controller);
        // Reap the original task even when a control assertion fails. A requested stop
        // on that failure path is never a substitute for the evidence below.
        if controlled.is_err() {
            let _ = f.application.close_public_artifact_reads();
        }
        let original_outcome = worker.await.map_err(|error| error.to_string())?;
        let observer_pid = controlled?;
        require(matches!(original_outcome, Err(AppError::DependencyUnavailable { .. })),
            "P1 missing original read ROLLBACK ACK returned a byte/control grant or definite Host refusal")?;
        original_five_seconds(started)?;
        retired_original(f, original_pid, &original_connection, &socket).await?;
        require(socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
            "P1 original held read ACK was later forwarded or credited after retirement")?;
        require(database_facts(&f.admin).await? == before && object_fact(&f.path())? == original_object
            && owned_object_fds(&f.path())?.is_empty(),
            "P1 original uncertain read changed business/object facts or opened an unowned object FD")?;

        // Revoke the actual old issuer only after its original connection has truly
        // retired. Install a fresh real resolver on the SAME Administration/Store.
        f.resolver.close_request_bindings();
        let fresh_resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY, default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT)).map_err(|error| error.to_string())?;
        fresh_resolver.install_artifact_read_authority(&f.actual.read_authority())
            .map_err(|_| "P1 new genuine Session issuer enrollment failed")?;
        let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("P1 recovery Session binding missing")?.identity()
                .same_binding(f.auth.request_binding().ok_or("P1 original Session binding missing")?.identity()),
                "P1 uncertain read recovery reused the closed owner or changed six Auth facts")?;
            fresh.request_binding().ok_or("P1 new valid Session missing")?.verify_current_before(&fresh,
                Instant::now() + Duration::from_secs(5)).await
                .map_err(|error| format!("P1 new actual Session was not valid independently of Store poison: {error:?}"))?;
            let after_auth = database_facts(&f.admin).await?;
            only_tables_changed(&before, &after_auth, &["public.sessions"])?;
            let mut expected_sessions = before["public.sessions"].as_array().ok_or("P1 original session facts missing")?.clone();
            let fresh_sessions = after_auth["public.sessions"].as_array().ok_or("P1 recovery session facts missing")?;
            require(expected_sessions.len() == fresh_sessions.len(), "P1 recovery changed original Session inventory")?;
            for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
                if old["row"]["id"].as_str() == Some("cleanup-session-b") {
                    old["row"]["updated_at"] = new["row"]["updated_at"].clone();
                    old["xmin"] = new["xmin"].clone();
                    old["ctid"] = new["ctid"].clone();
                }
            }
            require(expected_sessions == *fresh_sessions,
                "P1 recovery changed fields beyond the named new Session idle observation")?;
            let refused = f.application.read_current_artifact_chunk(fresh.clone(), f.receipt.artifact_id.clone()).await;
            require(matches!(refused, Err(AppError::DependencyUnavailable { .. })),
                "P1 valid new owner erased original read uncertainty or gained actual bytes")?;
            let barrier = f.actual.close_observed_artifact_reads(&original_record).map_err(|error| error.to_string())?;
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_secs(3)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)),
                "P1 new Host or original driver retirement fabricated a finite Store drain ACK")?;
            require(database_facts(&f.admin).await? == after_auth && object_fact(&f.path())? == original_object
                && owned_object_fds(&f.path())?.is_empty(),
                "P1 permanent uncertain refusal wrote producer rows, changed object or retained its FD")?;
            drop(barrier);
            eprintln!("ARTIFACT_READ_P1_ROLLBACK_UNKNOWN original_producer_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_host_rollback_forwarded_before_source_begin=true actual_post_schema_source_begin_held_and_released=true complete_original_source_query_lock_wait=true controller_rollback_ack=true original_upstream_read_rollback_ack=true original_forwarded_read_rollback_ack=false original_five_second_error=true original_driver_destroyed=true corresponding_frontend_eof=true original_backend_gone=true original_owner_closed_after_retirement=true new_true_owner_valid=true same_original_store_pair=true byte_grant=false finite_store_ack=false business_object_unchanged=true held_read_rollback_ack_released=false physical_delete=false");
            Ok::<(), String>(())
        }.await;
        fresh_resolver.close_request_bindings();
        recovery
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and owned Store; exact include-ignored only"]
async fn foreign_current_admin_or_namespace_cannot_arm_original_saved_pair() {
    with_fixture("cleanup-foreign-owner",false,|f|Box::pin(async move {
        let admin_auth=resolve(f.resolver.as_ref(),COOKIE_ADMIN).await?;
        let new_unenrolled=PostgresSessionAuthResolver::new(f.pool.clone(),SESSION_KEY,default_session_lifetime(),DeploymentId::new(DEPLOYMENT),TenantId::new(TENANT)).map_err(|e|e.to_string())?;
        let unenrolled_auth=resolve(&new_unenrolled,COOKIE_A).await?;
        require(unenrolled_auth==f.auth && !unenrolled_auth.request_binding().unwrap().identity().same_binding(f.auth.request_binding().unwrap().identity()),"foreign issuer fixture did not preserve six facts while changing original Host binding")?;
        let other_actual=Arc::new(PostgresArtifactAdministration::new(f.registry.clone(),f.store.clone(),ArtifactQuotaPolicy::default(),SecretBytes::new(vec![0x18;32])).map_err(|e|e.to_string())?);
        let foreign_root=OwnedRoot::new()?;
        let deployment=DeploymentId::new("foreign-cleanup-deployment");let tenant=TenantId::new("foreign-cleanup-tenant");
        let registry=Arc::new(ArtifactDatasetRegistry::from_server(f.pool.clone(),&deployment,&tenant).await.map_err(|e|e.to_string())?);
        let store=Arc::new(DatasetBoundArtifactStore::bind_host_root(std::fs::File::open(&foreign_root.0).map_err(|e|e.to_string())?,registry.clone(),ArtifactQuotaPolicy::default()).await.map_err(|e|e.to_string())?);
        let foreign=Arc::new(PostgresArtifactAdministration::new(registry,store,ArtifactQuotaPolicy::default(),SecretBytes::new(vec![0x19;32])).map_err(|e|e.to_string())?);
        let foreign_host=PostgresSessionAuthResolver::new(f.pool.clone(),SESSION_KEY,default_session_lifetime(),deployment,tenant).map_err(|e|e.to_string())?;
        foreign_host.install_artifact_read_authority(&foreign.read_authority()).map_err(|_|"foreign true authority enrollment failed")?;
        let foreign_auth=resolve(&foreign_host,COOKIE_A).await?;
        let before=database_facts(&f.admin).await?; let original=object_fact(&f.path())?;
        require(matches!(f.actual.arm_explicit_saved_delete_before(&admin_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::NotVisible)),"another current admin took over the retained saving owner")?;
        require(matches!(other_actual.arm_explicit_saved_delete_before(&f.auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::Host(HostRequestBindingError::Unavailable))),"same Store/new Administration bypassed actual enrolled authority")?;
        require(matches!(f.actual.arm_explicit_saved_delete_before(&unenrolled_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::Host(HostRequestBindingError::Unavailable))),"same six facts/new original issuer bypassed enrollment")?;
        require(matches!(foreign.arm_explicit_saved_delete_before(&foreign_auth,&f.receipt.artifact_id,Instant::now()+Duration::from_secs(5)).await,Err(Error::NotVisible)),"foreign real namespace resolved the original saved pair")?;
        require(database_facts(&f.admin).await?==before && object_fact(&f.path())?==original,"foreign refusal changed rows, physical tuples or original object")?;
        foreign_host.close_request_bindings();new_unenrolled.close_request_bindings();
        drop(foreign);drop(other_actual);drop(foreign_root);
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL, original Session and controlled PG waits"]
async fn current_generation_role_deny_and_session_epoch_are_rechecked_after_wait() {
    for mutation in [
        "generation",
        "role",
        "deny",
        "session_epoch",
        "session_expiry",
        "owner_close",
    ] {
        with_fixture("cleanup-current-after-wait",false,|f|Box::pin(async move {
            let held=f.pool.get().await.map_err(|e|e.to_string())?;
            let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);drop(held);
            let before=database_facts(&f.admin).await?;
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;
            let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER]).await.map_err(|e|e.to_string())?;
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
            let original=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            wait_blocked(&f.admin,pid,"public.users",controller_pid).await?;
            let (sql,table)=match mutation {
                "generation"=>("UPDATE public.users SET auth_generation=1 WHERE id='cleanup-owner'","public.users"),
                "role"=>("DELETE FROM public.user_roles WHERE user_id='cleanup-owner'","public.user_roles"),
                "deny"=>("INSERT INTO public.revoked_access(email,revoked_by) VALUES('cleanup-owner@example.test','owned-cleanup-test-controller')","public.revoked_access"),
                "session_epoch"=>("UPDATE public.sessions SET token='owned-replaced-original-cleanup-session-token' WHERE id='cleanup-session-a'","public.sessions"),
                "session_expiry"=>("UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='cleanup-session-a'","public.sessions"),
                _=>("SELECT 1",""),
            };
            tx.batch_execute(sql).await.map_err(|e|e.to_string())?;
            if mutation=="owner_close" {f.resolver.close_request_bindings();}
            tx.commit().await.map_err(|e|e.to_string())?;drop(c);
            let outcome=original.await.map_err(|e|e.to_string())?;
            require(matches!(outcome,Err(Error::NotVisible)|Err(Error::Host(HostRequestBindingError::NotCurrent))),"resumed arm ignored current generation/role/deny/session/original owner")?;
            let after=database_facts(&f.admin).await?;
            only_tables_changed(&before,&after,if table.is_empty(){&[]}else{std::slice::from_ref(&table)})?;
            match mutation {
                "generation"=>controller_update_columns(&before,&after,table,"id",OWNER,&["auth_generation"])? ,
                "role"=>controller_removed_row(&before,&after,table,"user_id",OWNER)? ,
                "deny"=>controller_inserted_row(&before,&after,table,"email","cleanup-owner@example.test")? ,
                "session_epoch"=>controller_update_columns(&before,&after,table,"id",A_ID,&["token"])? ,
                "session_expiry"=>controller_update_columns(&before,&after,table,"id",A_ID,&["expires_at"])? ,
                _=>{},
            }
            require(object_fact(&f.path())?.sha256==format!("{:x}",Sha256::digest(TEXT.as_bytes())),"current refusal altered original object")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_AFTER_WAIT mutation={mutation} waiter_pid={pid} controller_pid={controller_pid} actual_actor_lock=true controller_commit_ack=true original_refusal_after_ack=true allowed_table={table}");
            Ok(())
        })).await;
    }
    for wait in ["quota", "audit"] {
        for mutation in ["deny", "session_epoch"] {
            with_fixture("cleanup-current-after-later-wait",false,|f|Box::pin(async move {
                let held=f.pool.get().await.map_err(|e|e.to_string())?;
                let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);drop(held);
                let before=database_facts(&f.admin).await?;
                let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
                let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
                let fragment=if wait=="quota" {tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;"artifact_workspace_quotas"} else {tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e|e.to_string())?;"pg_advisory_xact_lock"};
                let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
                let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
                wait_blocked(&f.admin,pid,fragment,controller_pid).await?;
                let table=if mutation=="deny" {
                    require(tx.execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES('cleanup-owner@example.test','owned-cleanup-test-controller')",&[]).await.map_err(|e|e.to_string())?==1,"later-wait controller did not insert its original owner deny")?;
                    "public.revoked_access"
                }else{
                    require(tx.execute("UPDATE public.sessions SET token='owned-cleanup-replaced-epoch-after-real-wait' WHERE id=$1",&[&A_ID]).await.map_err(|e|e.to_string())?==1,"later-wait controller did not replace the original session token")?;
                    "public.sessions"
                };
                tx.commit().await.map_err(|e|e.to_string())?;drop(c);
                require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::NotVisible)),"later quota/audit wait reused the old permitted Host/actor statement")?;
                let after=database_facts(&f.admin).await?;only_tables_changed(&before,&after,&[table])?;
                if mutation=="deny" {controller_inserted_row(&before,&after,table,"email","cleanup-owner@example.test")?;}else{controller_update_columns(&before,&after,table,"id",A_ID,&["token"])?;}
                eprintln!("ARTIFACT_CLEANUP_ARM_AFTER_LATER_WAIT wait={wait} mutation={mutation} waiter_pid={pid} controller_pid={controller_pid} real_blocking_pid_bound=true controller_commit_ack=true fresh_rc_refusal=true producer_rows_unchanged=true");
                Ok(())
            })).await;
        }
    }
    for noop in [false, true] {
        with_fixture("cleanup-original-ack-host-tail",true,|f|Box::pin(async move {
            if noop {drop(f.arm().await.map_err(|e|e.to_string())?);}
            let before=database_facts(&f.admin).await?;let object=object_fact(&f.path())?;
            let (_pid,_observation,socket)=f.original().await?;clear_transaction_facts(&socket);
            let hold=if noop {Hold::Rollback}else{Hold::Commit};
            let bit=if noop {ROLLBACK_BIT}else{COMMIT_BIT};
            f.relay.as_ref().unwrap().arm(hold);
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            wait_fact(||socket.withheld.load(Ordering::SeqCst)==hold as u8,Instant::now()+Duration::from_secs(2),"host-tail fixture did not hold its actual original ACK").await?;
            require(socket.entered.load(Ordering::SeqCst)&bit!=0&&socket.server_ack.load(Ordering::SeqCst)&bit!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&bit==0,"host-tail change preceded the original upstream ACK or followed a delivered ACK")?;
            f.verify_one_arm().await?;
            let confirmed=database_facts(&f.admin).await?;
            if noop {require(before==confirmed,"original no-op ACK wait changed any row")?;}else{original_arm_append_only(&before,&confirmed)?;}
            // Actual original owner retirement occurs strictly between the original real
            // upstream ACK and delivery of those unmodified ACK/ReadyForQuery packets.
            f.resolver.close_request_bindings();
            f.relay.as_ref().unwrap().release_original_ack(&socket,hold)?;
            require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::Host(HostRequestBindingError::NotCurrent))),"true original ACK minted an intent after actual original Host owner closed")?;
            require(socket.forwarded_ack.load(Ordering::SeqCst)&bit!=0,"tail refusal was obtained without releasing the true original ACK")?;
            require(database_facts(&f.admin).await?==confirmed&&object_fact(&f.path())?==object,"post-ACK Host refusal erased committed intent or changed retained charge/bytes")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_ACK_HOST_TAIL noop={noop} original_upstream_ack_before_owner_close=true original_owner_closed=true unmodified_original_ack_released=true result=HostNotCurrent usable_intent=false known_committed_arm_retained=true charge_unchanged=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original saved pair; exact include-ignored only"]
async fn same_original_armed_retry_is_noop_and_conflicting_intent_is_refused() {
    with_fixture("cleanup-noop",true,|f|Box::pin(async move {
        let before=database_facts(&f.admin).await?;
        let first=f.arm().await.map_err(|e|e.to_string())?;f.verify_one_arm().await?;
        let after=database_facts(&f.admin).await?;original_arm_append_only(&before,&after)?;
        let (_pid,_observation,socket)=f.original().await?;clear_transaction_facts(&socket);
        let retry=f.arm().await.map_err(|e|e.to_string())?;
        require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0 && socket.entered.load(Ordering::SeqCst)&COMMIT_BIT==0,"exact no-op did not await the original ROLLBACK ACK")?;
        require(database_facts(&f.admin).await?==after,"exact no-op changed original row coordinates or duplicated arm audit")?;
        drop(retry);drop(first);
        let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_identity_guard").await.map_err(|e|e.to_string())?;
        require(tx.execute("UPDATE openbot_internal.artifact_cleanup_fences SET terminal_status='expired' WHERE artifact_id=$1",&[&f.receipt.artifact_id]).await.map_err(|e|e.to_string())?==1,"controlled terminal conflict did not change the actual original fence")?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences ENABLE TRIGGER artifact_cleanup_fences_identity_guard").await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e|e.to_string())?;drop(c);
        let conflict=database_facts(&f.admin).await?;only_tables_changed(&after,&conflict,&["openbot_internal.artifact_cleanup_fences"])?;
        controller_update_columns(&after,&conflict,"openbot_internal.artifact_cleanup_fences","artifact_id",&f.receipt.artifact_id,&["terminal_status"])?;
        require(matches!(f.arm().await,Err(Error::Conflict)),"delete arm coerced the existing expired intent")?;
        require(database_facts(&f.admin).await?==conflict,"conflicting arm reopened or rebound immutable intent")?;
        Ok(())
    })).await;
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and controlled original row/catalog/audit faults"]
async fn original_pair_charge_or_cleanup_schema_drift_refuses_without_mutation() {
    for fault in [
        "operation_artifact",
        "request_receipt",
        "source_pair",
        "nullable_sequence_pair",
        "charge",
        "workspace_charge",
        "positive_receipt_missing",
        "store_physical",
        "cleanup_schema",
        "audit_insert",
    ] {
        with_fixture("cleanup-original-corruption",fault=="audit_insert",|f|Box::pin(async move {
            let original=object_fact(&f.path())?;
            let before=database_facts(&f.admin).await?;
            let (audit_original,audit_worker)=if fault=="audit_insert" {
                let original=f.original().await?;clear_transaction_facts(&original.2);
                f.relay.as_ref().unwrap().arm(Hold::Begin);
                let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();
                let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
                let socket=&original.2;
                wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Begin as u8,Instant::now()+Duration::from_secs(2),"audit fault did not hold the actual original post-schema BEGIN ACK").await?;
                require(socket.entered.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT==0,"audit fault controller ran before the original schema check or after a delivered BEGIN ACK")?;
                (Some(original),Some(worker))
            }else{(None,None)};
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;
            let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let (allowed,expected_field)=match fault {
                "operation_artifact"|"source_pair"|"nullable_sequence_pair"|"charge"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
                    let changed=match fault {
                        "operation_artifact"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET artifact_id=$1 WHERE operation_id=$2",&[&Uuid::now_v7().to_string(),&f.receipt.operation_id]).await,
                        "source_pair"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET source_message_id='owned-different-source-message' WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                        "nullable_sequence_pair"=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET source_call_seq=1,source_attempt_seq=0 WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                        _=>tx.execute("UPDATE openbot_internal.artifact_save_operations SET charged_bytes=charged_bytes-1 WHERE operation_id=$1",&[&f.receipt.operation_id]).await,
                    }.map_err(|e|e.to_string())?;
                    require(changed==1,"controller did not corrupt exactly its actual original operation")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_save_operations",if fault=="operation_artifact"||fault=="charge"{"operation_pair"}else{"positive_receipt"})
                },
                "request_receipt"|"positive_receipt_missing"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_saved_receipts DISABLE TRIGGER artifact_saved_receipts_append_only").await.map_err(|e|e.to_string())?;
                    let changed=if fault=="request_receipt" { tx.execute("UPDATE openbot_internal.artifact_saved_receipts SET request_id=$1 WHERE operation_id=$2",&[&Uuid::now_v7().to_string(),&f.receipt.operation_id]).await } else {tx.execute("DELETE FROM openbot_internal.artifact_saved_receipts WHERE operation_id=$1",&[&f.receipt.operation_id]).await}.map_err(|e|e.to_string())?;
                    require(changed==1,"controller did not change exactly its actual original positive receipt")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_saved_receipts ENABLE TRIGGER artifact_saved_receipts_append_only").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_saved_receipts","positive_receipt")
                },
                "workspace_charge"=>{
                    require(tx.execute("UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=0 WHERE workspace_id=$1",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?==1,"controller did not change exactly its original workspace quota")?;
                    ("openbot_internal.artifact_workspace_quotas","workspace_quota")
                },
                "store_physical"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e|e.to_string())?;
                    require(tx.execute("UPDATE openbot_internal.artifact_store_bindings SET root_inode=(root_inode::numeric+1)::text WHERE store_id=$1",&[&f.store.store_id().to_string()]).await.map_err(|e|e.to_string())?==1,"controller did not change the actual original stored physical tuple")?;
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e|e.to_string())?;
                    ("openbot_internal.artifact_store_bindings","store_binding")
                },
                "cleanup_schema"=>{
                    tx.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences RENAME CONSTRAINT artifact_cleanup_fences_phase TO owned_cleanup_test_phase_drift").await.map_err(|e|e.to_string())?;
                    ("","schema")
                },
                _=>{
                    // Install only while the genuine original BEGIN ACK is withheld: that
                    // same production connection has already passed its exact schema check.
                    // The controller's real COMMIT ACK precedes release of the original ACK.
                    // This sequence is controlled test instrumentation, not a business table.
                    // Its nontransactional advance proves the original real audit INSERT reached
                    // this trigger even though that same transaction must roll back all writes.
                    tx.batch_execute("CREATE SEQUENCE public.owned_cleanup_arm_audit_fault_seen; CREATE FUNCTION public.owned_cleanup_arm_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='artifact.cleanup_armed' THEN PERFORM nextval('public.owned_cleanup_arm_audit_fault_seen'); RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='owned cleanup arm audit insert fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_cleanup_arm_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_cleanup_arm_audit_fault();").await.map_err(|e|e.to_string())?;
                    ("","")
                },
            };
            tx.commit().await.map_err(|e|e.to_string())?;drop(c);
            let controlled=database_facts(&f.admin).await?;
            only_tables_changed(&before,&controlled,if allowed.is_empty(){&[]}else{std::slice::from_ref(&allowed)})?;
            if !allowed.is_empty() {require(before.get(allowed)!=controlled.get(allowed),"declared row corruption was never actually committed")?;}
            match fault {
                "operation_artifact"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["artifact_id"])? ,
                "source_pair"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["source_message_id"])? ,
                "nullable_sequence_pair"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["source_call_seq","source_attempt_seq"])? ,
                "charge"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["charged_bytes"])? ,
                "request_receipt"=>controller_update_columns(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id,&["request_id"])? ,
                "positive_receipt_missing"=>controller_removed_row(&before,&controlled,allowed,"operation_id",&f.receipt.operation_id)? ,
                "workspace_charge"=>controller_update_columns(&before,&controlled,allowed,"workspace_id",f.receipt.source_thread_id.as_str(),&["charged_bytes"])? ,
                "store_physical"=>controller_update_columns(&before,&controlled,allowed,"store_id",&f.store.store_id().to_string(),&["root_inode"])? ,
                _=>{},
            }
            let result=if let Some(worker)=audit_worker {
                let socket=&audit_original.as_ref().ok_or("actual audit original socket missing")?.2;
                f.relay.as_ref().unwrap().release_original_ack(socket,Hold::Begin)?;
                let result=worker.await.map_err(|e|e.to_string())?;
                require(socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0,"audit fault did not resume using the same unmodified original BEGIN ACK")?;
                result
            }else{f.arm().await};
            if fault=="audit_insert" {
                require(matches!(result,Err(Error::Unavailable)),"actual failing audit INSERT returned an accepted arm or was never reached")?;
                let socket=&audit_original.as_ref().ok_or("actual audit original socket missing")?.2;
                require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0&&socket.entered.load(Ordering::SeqCst)&COMMIT_BIT==0,"actual audit fault did not await the same original ROLLBACK ACK")?;
                let c=f.admin.get().await.map_err(|e|e.to_string())?;
                let seen=c.query_one("SELECT last_value,is_called FROM public.owned_cleanup_arm_audit_fault_seen",&[]).await.map_err(|e|e.to_string())?;
                require(seen.get::<_,i64>(0)==1 && seen.get::<_,bool>(1),"original audit failure was inferred from a catalog name rather than its actual INSERT")?;
                eprintln!("ARTIFACT_CLEANUP_ARM_AUDIT_FAULT original_schema_passed_before_begin_ack=true original_begin_ack_held=true controller_fault_install_commit_ack=true same_original_begin_ack_released=true original_audit_insert_seen=true original_rollback_ack=true schema_guard_unchanged=true");
            }else{
                require(matches!(result,Err(Error::Corrupt{field}) if field==expected_field),"arm did not reject the precise original pair/charge/schema corruption")?;
            }
            require(database_facts(&f.admin).await?==controlled && object_fact(&f.path())?==original,"refused or audit-failed arm left fence/audit/charge/state/object mutation")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_FAULT kind={fault} controller_pid={controller_pid} controller_commit_ack=true original_row_actual=true allowed_table={allowed} producer_ordinary_rows_unchanged=true object_unchanged=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original connections/loopback fault relay"]
async fn original_arm_deadline_and_cancel_retire_unacknowledged_connection() {
    for wait in ["actor", "quota", "operation", "fence_fk_record", "audit"] {
        with_fixture("cleanup-original-budget",true,|f|Box::pin(async move {
            let before=database_facts(&f.admin).await?;let original_object=object_fact(&f.path())?;
            let held=f.pool.get().await.map_err(|e|e.to_string())?;
            let pid:i32=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let observation=held.observation();let socket=f.relay.as_ref().unwrap().socket_for_pid(pid)?;
            let mut c=f.admin.get().await.map_err(|e|e.to_string())?;let tx=c.transaction().await.map_err(|e|e.to_string())?;
            let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let fragment=match wait {
                "actor"=>{tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER]).await.map_err(|e|e.to_string())?;"public.users"},
                "quota"=>{tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&f.receipt.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;"artifact_workspace_quotas"},
                "operation"=>{tx.query_one("SELECT operation_id FROM openbot_internal.artifact_save_operations WHERE operation_id=$1 FOR UPDATE",&[&f.receipt.operation_id]).await.map_err(|e|e.to_string())?;"artifact_save_operations"},
                // The real uncommitted fence INSERT takes its exact original FK KEY SHARE.
                // The producer therefore waits at record FOR UPDATE first, not at a later
                // unique/fence statement. Observe that real coupled wait without relabelling it.
                "fence_fk_record"=>{tx.execute("INSERT INTO openbot_internal.artifact_cleanup_fences(deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) VALUES($1,$2,$3,$4,$5,'deleted','armed')",&[&DEPLOYMENT,&TENANT,&f.registry.binding().dataset_id(),&f.receipt.operation_id,&f.receipt.artifact_id]).await.map_err(|e|e.to_string())?;"artifact_records"},
                _=>{tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e|e.to_string())?;"pg_advisory_xact_lock"},
            };
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(30)).await});
            tokio::time::sleep(Duration::from_secs(2)).await;
            require(!worker.is_finished(),"original entry did not actually wait for its original Pool slot")?;drop(held);
            wait_blocked(&f.admin,pid,fragment,controller_pid).await?;
            let result=worker.await.map_err(|e|e.to_string())?;
            require(matches!(result,Err(Error::Unavailable)|Err(Error::RollbackAcknowledgedAfterDeadline)),"original deadline minted an intent or renewed its budget")?;
            original_five_seconds(started)?;
            let deadline=Instant::now()+Duration::from_secs(2);
            require(observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectionDestroyed,"absolute deadline lacked original driver destruction")?;
            wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),deadline,"original deadline lacked corresponding relay socket EOF").await?;
            // Original destructor/EOF are proved before releasing this owned test lock.
            // Backend disappearance is checked only after its true rollback ACK.
            tx.rollback().await.map_err(|e|e.to_string())?;drop(c);
            retired_original(f,pid,&observation,&socket).await?;
            require(database_facts(&f.admin).await?==before && object_fact(&f.path())?==original_object,"expired original arm committed fence/audit or refunded/changed original bytes")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_ORIGINAL_BUDGET wait={wait} waiter_pid={pid} controller_pid={controller_pid} pool_wait_ms=2000 absolute_original5s=true original_error={:?} original_driver_destroyed=true matching_socket_eof=true lock_rollback_ack=true backend_gone=true",result.err());
            Ok(())
        })).await;
    }
    for mode in ["begin_deadline", "begin_cancel", "cold_connect"] {
        with_fixture("cleanup-original-cancel",true,|f|Box::pin(async move {
            let before=database_facts(&f.admin).await?;
            let (pid,observation,socket)=f.original().await?;clear_transaction_facts(&socket);
            if mode=="cold_connect" {
                let c=f.admin.get().await.map_err(|e|e.to_string())?;
                require(c.query_one("SELECT pg_terminate_backend($1)",&[&pid]).await.map_err(|e|e.to_string())?.get(0),"owned cached backend could not be retired for cold connect")?;drop(c);
                let deadline=Instant::now()+Duration::from_secs(2);
                require(observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectionDestroyed,"controlled cold cache lacked original driver destruction")?;
                wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),deadline,"controlled cold cache lacked original socket EOF").await?;
                loop {
                    let c=f.admin.get().await.map_err(|e|e.to_string())?;
                    let alive:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1)",&[&pid]).await.map_err(|e|e.to_string())?.get(0);
                    if !alive {break;}
                    require(Instant::now()<deadline,"controlled cold original backend persisted after driver destruction and EOF")?;
                    drop(c);tokio::time::sleep(Duration::from_millis(10)).await;
                }
                f.relay.as_ref().unwrap().arm(Hold::Startup);
            }else{f.relay.as_ref().unwrap().arm(Hold::Begin);}
            let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
            let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
            let (operation_observation,operation_socket)=if mode=="cold_connect" {
                wait_fact(||f.pool.connection_observations().iter().any(|o|{let s=o.snapshot();s.connecting_future_started&&!s.connection_started&&s.destruction.is_none()}),Instant::now()+Duration::from_secs(2),"arm did not start its real owned Config::connect future").await?;
                let connecting=f.pool.connection_observations().into_iter().find(|o|{let s=o.snapshot();s.connecting_future_started&&!s.connection_started&&s.destruction.is_none()}).ok_or("original connecting owner missing")?;
                wait_fact(||f.relay.as_ref().unwrap().newest_socket().is_ok_and(|s|s.withheld.load(Ordering::SeqCst)==Hold::Startup as u8),Instant::now()+Duration::from_secs(2),"arm cold connect did not reach original accepted socket").await?;
                (connecting,f.relay.as_ref().unwrap().newest_socket()?)
            }else{
                wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Begin as u8,Instant::now()+Duration::from_secs(2),"arm BEGIN did not reach a true original upstream ACK").await?;
                require(socket.entered.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&BEGIN_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&BEGIN_BIT==0,"arm BEGIN fault was not original ACK loss")?;
                (observation,socket)
            };
            if mode=="begin_cancel" {worker.abort();require(worker.await.is_err_and(|e|e.is_cancelled()),"caller cancellation did not join the original arm future")?;}else{
                require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::Unavailable)),"BEGIN/connect deadline returned intent or a definite transaction outcome")?;original_five_seconds(started)?;
            }
            if mode=="cold_connect" {
                let deadline=Instant::now()+Duration::from_secs(2);
                require(operation_observation.wait_for_destruction_before(deadline).await.map_err(|e|e.to_string())?==ConnectionDestruction::ConnectingFutureDestroyed,"arm cold deadline lacked Config::connect future destruction")?;
                wait_fact(||operation_socket.frontend_eof.load(Ordering::SeqCst),deadline,"original cold-connect accepted socket did not reach EOF").await?;
                require(operation_socket.pid.load(Ordering::SeqCst)==0,"held original startup was silently forwarded to PostgreSQL")?;
            }else{retired_original(f,pid,&operation_observation,&operation_socket).await?;}
            require(database_facts(&f.admin).await?==before,"original connect/BEGIN/cancel attempt committed any business row")?;
            eprintln!("ARTIFACT_CLEANUP_ARM_RETIRE mode={mode} original_resource_destroyed=true corresponding_socket_eof=true no_intent=true");
            Ok(())
        })).await;
    }
}

#[tokio::test]
#[ignore = "requires actual isolated PostgreSQL and original COMMIT framed ACK-loss relay"]
async fn lost_original_arm_commit_ack_remains_unknown_without_cleanup_grant() {
    with_fixture("cleanup-original-commit-unknown",true,|f|Box::pin(async move {
        let before=database_facts(&f.admin).await?;let object=object_fact(&f.path())?;
        let (pid,observation,socket)=f.original().await?;clear_transaction_facts(&socket);
        f.relay.as_ref().unwrap().arm(Hold::Commit);
        let actual=f.actual.clone();let auth=f.auth.clone();let artifact=f.receipt.artifact_id.clone();let started=Instant::now();
        let worker=tokio::spawn(async move {actual.arm_explicit_saved_delete_before(&auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
        wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Commit as u8,Instant::now()+Duration::from_secs(2),"original arm COMMIT did not reach true upstream ACK").await?;
        require(socket.entered.load(Ordering::SeqCst)&COMMIT_BIT!=0&&socket.server_ack.load(Ordering::SeqCst)&COMMIT_BIT!=0&&socket.forwarded_ack.load(Ordering::SeqCst)&COMMIT_BIT==0,"commit uncertainty was not actual original ACK loss")?;
        f.verify_one_arm().await?;
        let durable=database_facts(&f.admin).await?;original_arm_append_only(&before,&durable)?;
        require(matches!(worker.await.map_err(|e|e.to_string())?,Err(Error::CommitUnknown)),"lost original arm ACK minted an intent, claimed not-written or relabelled definite late ACK")?;
        original_five_seconds(started)?;
        retired_original(f,pid,&observation,&socket).await?;
        require(database_facts(&f.admin).await?==durable&&object_fact(&f.path())?==object,"unknown arm erased durable intent, repeated IO, changed charge or deleted original object")?;
        eprintln!("ARTIFACT_CLEANUP_ARM_COMMIT_UNKNOWN original_upstream_commit_ack=true original_forwarded_commit_ack=false original_error=CommitUnknown durable_fence_and_audit=true original_driver_destroyed=true matching_frontend_eof=true original_backend_gone=true usable_intent=false physical_delete=false retry=false");
        Ok(())
    })).await;
}

// Task020: this oracle follows only the originally saved dev/inode, including nlink=0.
fn physical_macos_inode_fds_for(
    original_device: u64,
    original_inode: u64,
) -> Result<Vec<String>, String> {
    let device = original_device & u64::from(u32::MAX);
    let sample = || -> Result<Vec<String>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "finite original own-PID lsof unavailable (Unproven)")?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("finite original lsof streams unavailable (Unproven)".to_owned());
        };
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let waited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => break Err("finite original own-PID lsof timed out (Unproven)"),
                Err(_) => break Err("finite original own-PID lsof wait failed (Unproven)"),
            }
        };
        // All error paths still reap this original child and both original pipe workers.
        // A killed/timed-out/error child is never credited as a natural successful sample.
        if waited.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let output = output.join();
        let errors = errors.join();
        let status = waited?;
        let output = output
            .map_err(|_| "original lsof stdout worker failed")?
            .map_err(|_| "original lsof stdout read failed")?;
        let errors = errors
            .map_err(|_| "original lsof stderr worker failed")?
            .map_err(|_| "original lsof stderr read failed")?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.is_empty()
                && output.ends_with(b"\n"),
            "original lsof was failed, incomplete, truncated or emitted stderr (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "original lsof output invalid")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("original lsof empty field")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "original lsof observed a peer PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(original_inode) {
                        found.insert(fd.ok_or("original inode had a nonnumeric ambiguous FD")?);
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
                        .map_err(|_| "original lsof device invalid")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "original lsof inode invalid")?,
                    );
                }
                _ => return Err("original lsof unexpected field".to_owned()),
            }
        }
        require(self_pid, "original lsof self-PID field missing")?;
        Ok(found.into_iter().map(|fd| fd.to_string()).collect())
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "original inode FD inventory changed between two actual samples (Unproven)",
    )?;
    Ok(first)
}

#[derive(Default)]
struct PhysicalPhaseFacts {
    seen: [usize; 4],
    original_fd: Option<i32>,
    nlink_after_unlink: Option<u64>,
    error: Option<String>,
    released: bool,
}
struct PhysicalPhaseGate {
    artifact: Uuid,
    original: ObjectFact,
    pause: usize,
    absent_at_entry: bool,
    facts: Mutex<PhysicalPhaseFacts>,
    changed: Condvar,
}
impl PhysicalPhaseGate {
    fn new(
        f: &Fixture,
        original: ObjectFact,
        pause: usize,
        absent_at_entry: bool,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            artifact: Uuid::parse_str(&f.receipt.artifact_id).map_err(|e| e.to_string())?,
            original,
            pause,
            absent_at_entry,
            facts: Mutex::new(PhysicalPhaseFacts::default()),
            changed: Condvar::new(),
        }))
    }
    fn release(&self) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.released = true;
            self.changed.notify_all();
        }
    }
    fn saw(&self, phase: usize) -> bool {
        self.facts.lock().is_ok_and(|f| f.seen[phase - 1] > 0)
    }
    fn check(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "original physical observer poisoned")?;
        match &facts.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    async fn wait(&self, phase: usize, deadline: Instant) -> Result<(), String> {
        wait_fact(
            || self.saw(phase),
            deadline,
            "actual original physical phase was not reached",
        )
        .await?;
        self.check()
    }
    fn after_unlink_is_original_zero_link(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "original physical observer poisoned")?;
        require(
            facts.seen[2] == 1
                && facts.original_fd.is_some()
                && facts.nlink_after_unlink == Some(0),
            "AfterUnlink did not observe the actually held original inode with nlink=0",
        )
    }
}
impl ArtifactCleanupPhysicalObserver for PhysicalPhaseGate {
    fn on_phase(&self, phase: PhysicalPhase, artifact_id: Uuid, original_leaf_fd: Option<i32>) {
        let index = match phase {
            PhysicalPhase::PreflightReady => 1,
            PhysicalPhase::BeforeFirstUnlink => 2,
            PhysicalPhase::AfterUnlinkBeforeSync => 3,
            PhysicalPhase::WorkerEnded => 4,
        };
        // A finite duplicate of the explicitly supplied live original FD is metadata-only.
        // It closes before the callback pauses or WorkerEnded is accepted; it is not an
        // original-worker closure receipt, nor does it read body bytes.
        let observed = (|| -> Result<Option<u64>, String> {
            require(
                artifact_id == self.artifact,
                "physical observer rebound artifact UUID",
            )?;
            if index == 4 {
                require(
                    original_leaf_fd.is_none(),
                    "WorkerEnded still exported a live leaf FD",
                )?;
                return Ok(None);
            }
            let Some(fd) = original_leaf_fd else {
                require(
                    self.absent_at_entry
                        || self
                            .facts
                            .lock()
                            .is_ok_and(|f| f.nlink_after_unlink == Some(0)),
                    "retained preflight did not hold its actual original leaf FD",
                )?;
                return Ok(None);
            };
            let duplicate = std::fs::File::open(format!("/dev/fd/{fd}"))
                .map_err(|_| "original physical FD duplicate failed")?;
            let metadata = duplicate
                .metadata()
                .map_err(|_| "original physical FD metadata failed")?;
            let valid = metadata.is_file()
                && metadata.dev() == self.original.dev
                && metadata.ino() == self.original.ino
                && metadata.uid() == self.original.uid
                && metadata.mode() == self.original.mode
                && metadata.len() == self.original.len;
            let nlink = metadata.nlink();
            drop(duplicate);
            require(
                valid,
                "phase FD was not the originally saved physical inode",
            )?;
            require(
                if index == 3 { nlink == 0 } else { nlink == 1 },
                "original phase FD had unexpected actual link count",
            )?;
            Ok(Some(nlink))
        })();
        let Ok(mut facts) = self.facts.lock() else {
            return;
        };
        facts.seen[index - 1] += 1;
        match observed {
            Ok(nlink) => {
                if let Some(fd) = original_leaf_fd {
                    facts.original_fd = Some(fd);
                }
                if index == 3 {
                    facts.nlink_after_unlink = nlink;
                }
            }
            Err(error) => facts.error = Some(error),
        }
        self.changed.notify_all();
        // The producer's deadline is unchanged. This separate finite fixture wait can
        // retain a worker after its main query expires, for genuine unproven cleanup.
        let stop = Instant::now() + Duration::from_secs(8);
        while index == self.pause && !facts.released {
            let remaining = stop.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                facts.error =
                    Some("original physical phase controller was not released".to_owned());
                break;
            }
            match self.changed.wait_timeout(facts, remaining) {
                Ok((next, _)) => facts = next,
                Err(_) => return,
            }
        }
    }
}
struct PhysicalGateRelease(Arc<PhysicalPhaseGate>);
impl Drop for PhysicalGateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn install_physical_gate(
    f: &Fixture,
    original: ObjectFact,
    pause: usize,
    absent: bool,
) -> Result<Arc<PhysicalPhaseGate>, String> {
    let gate = PhysicalPhaseGate::new(f, original, pause, absent)?;
    f.actual
        .install_cleanup_physical_observer(gate.clone())
        .map_err(|e| format!("{e:?}"))?;
    Ok(gate)
}
fn physical_inode_fds(original: &ObjectFact) -> Result<Vec<String>, String> {
    physical_inode_fds_for(original.dev, original.ino)
}
fn physical_inode_fds_for(device: u64, inode: u64) -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return physical_macos_inode_fds_for(device, inode);
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if std::fs::metadata(entry.path()).is_ok_and(|m| m.dev() == device && m.ino() == inode) {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found.sort();
    Ok(found)
}
async fn physical_original_fd_closed(gate: &Arc<PhysicalPhaseGate>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    gate.wait(4, deadline).await?;
    let original = gate.original.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        loop {
            if physical_inode_fds(&original)?.is_empty() {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "WorkerEnded label did not close the actual original inode FD",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    gate.check()
}
async fn physical_normal_original_ack(
    f: &Fixture,
    pid: i32,
    socket: &SocketFacts,
) -> Result<(), String> {
    require(
        socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | ROLLBACK_BIT)
                == (BEGIN_BIT | ROLLBACK_BIT)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
        "normal physical observation lacked this original query's true BEGIN/ROLLBACK ACK",
    )?;
    let current = f.pool.get().await.map_err(|e| e.to_string())?;
    let current_pid: i32 = current
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        current_pid == pid,
        "normal original acknowledged query was retired rather than reusable",
    )
}
fn physical_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
async fn physical_poison_refuses(
    f: &Fixture,
    auth: &AuthContext,
    intent: &ArmedArtifactCleanupIntent,
    original_record: &openbot_infra::artifact_administration::ObservedArtifactReadRecord,
) -> Result<(), String> {
    require(
        f.actual
            .remove_armed_explicit_saved_bytes_before(
                auth,
                intent,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .is_err(),
        "new remove erased original physical/read uncertainty",
    )?;
    require(
        f.actual
            .observe_armed_explicit_saved_bytes_before(
                auth,
                intent,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .is_err(),
        "new observe erased original physical/read uncertainty",
    )?;
    let barrier = f
        .actual
        .close_observed_artifact_reads(original_record)
        .map_err(|e| e.to_string())?;
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_secs(2))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)
        ),
        "original poisoned shared Store fabricated a finite drain ACK",
    )
}

#[tokio::test]
#[ignore = "requires Root-owned PostgreSQL and original armed Store; actual finite physical IO only"]
async fn actual_original_armed_object_unlink_and_directory_sync_prove_absence_without_refund() {
    with_fixture("physical-original-source-deleted", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        hard_delete_original_message(f).await?;
        read_is_404(f).await?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        f.verify_one_arm().await?;
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 0, false)?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let started = Instant::now();
        let result = f.actual.remove_armed_explicit_saved_bytes_before(&f.auth, &intent,
            started + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        require(started.elapsed() < Duration::from_secs(5) && result.state() == PhysicalState::DurableAbsent,
            "actual original cleanup lacked a normal in-budget DurableAbsent observation")?;
        gate.after_unlink_is_original_zero_link()?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
            "actual producer did not leave both canonical names absent")?;
        require(database_facts(&f.admin).await? == armed, "physical IO changed original charge/Run32/pair/fence/audit rows or physical carriers")?;
        let retry = f.application.execute(f.auth.clone(), AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
            request_id: Uuid::now_v7().to_string(), source_thread_id: f.receipt.source_thread_id.clone(),
            source_run_id: f.receipt.source_run_id.clone(), source_message_id: f.receipt.source_message_id.clone(),
            expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
        })).await;
        require(matches!(retry, Err(AppError::NotVisible)), "source-deleted locator Save recreated its armed object")?;
        read_is_404(f).await?;
        require(database_facts(&f.admin).await? == armed && physical_absent(&f.path()), "source-deleted retry mutated original armed facts")?;
        let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(2)).await.map_err(|e| format!("{e:?}"))?;
        drop(ack); drop(barrier); drop(result); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P01 actual_original_unlink=true original_fd_nlink_zero=true original_fd_closed=true guarded_directory_sync_and_double_absence=true original_query_rollback_ack=true business_charge_fence_audit_unchanged=true source_save_404=true terminal_refund=false");
        Ok(())
    })).await;
}

async fn physical_genuine_original_read_ack_loss(f: &Fixture) -> Result<(), String> {
    // This genuine original record supplies only the existing finite close key.
    // It neither replaces the Store nor proves deletion or a public read grant.
    let original_record = f
        .actual
        .observe_read_record(&f.auth, &f.receipt.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let original_object = object_fact(&f.path())?;
    let before = database_facts(&f.admin).await?;
    let (original_pid, original_connection, socket) = f.original().await?;
    clear_transaction_facts(&socket);
    let relay = f
        .relay
        .as_ref()
        .ok_or("P1 original guarded read relay missing")?;
    let mut controller = f.admin.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    socket
        .hold_next_begin_after_forwarded_rollback
        .store(true, Ordering::SeqCst);
    let application = Arc::clone(&f.application);
    let original_auth = f.auth.clone();
    let artifact_id = f.receipt.artifact_id.clone();
    let started = Instant::now();
    let worker = tokio::spawn(async move {
        application
            .execute(
                original_auth,
                AppCommand::OpenArtifactRead(OpenArtifactRead { artifact_id }),
            )
            .await
    });
    let controlled = async {
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8
                && socket.forwarded_host_rollback_before_source_begin.load(Ordering::SeqCst)
                && socket.post_schema_source_begin_held.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 original source BEGIN ACK was not held after the actual forwarded Host ROLLBACK").await?;
            require(socket.pid.load(Ordering::SeqCst) == original_pid
                && !socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                "P1 source BEGIN hold changed original producer or had already forwarded its ACK")?;
            let observer = f.admin.get().await.map_err(|error| error.to_string())?;
            let row = observer.query_one(
                "SELECT pg_catalog.pg_backend_pid() AS observer_pid,state,query,xact_start IS NOT NULL AS actual_transaction FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&original_pid],
            ).await.map_err(|error| error.to_string())?;
            let begin_observer_pid: i32 = row.get("observer_pid");
            let begin_query: String = row.get("query");
            require(begin_observer_pid != original_pid && begin_observer_pid != controller_pid && original_pid != controller_pid
                && row.get::<_, Option<String>>("state").as_deref() == Some("idle in transaction")
                && row.get::<_, bool>("actual_transaction")
                && (begin_query.trim_start().starts_with("BEGIN") || begin_query.trim_start().starts_with("START TRANSACTION"))
                && begin_query.contains("READ COMMITTED") && begin_query.contains("READ ONLY"),
                "P1 held post-schema source BEGIN was not the original read-only transaction with distinct observer/controller")?;
            drop(observer);
            // The original source schema is now complete; its actual BEGIN ACK remains
            // withheld so no source table query can preempt this genuine controller lock.
            require_activity_width(&f.admin).await?;
            transaction.batch_execute("LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE").await
                .map_err(|error| error.to_string())?;
            relay.release_original_ack(&socket, Hold::Begin)?;
            wait_fact(|| socket.post_schema_source_begin_forwarded.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(2),
                "P1 did not release exactly the held original post-schema source BEGIN ACK").await?;
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            let observer_pid = loop {
                let observer = f.admin.get().await.map_err(|error| error.to_string())?;
                let row = observer.query_opt(
                    "SELECT pg_catalog.pg_backend_pid() AS observer_pid,query,wait_event_type,pg_catalog.pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                    &[&original_pid],
                ).await.map_err(|error| error.to_string())?;
                if let Some(row) = row {
                    let query: String = row.get("query");
                    let wait_type: Option<String> = row.get("wait_event_type");
                    let blockers: Vec<i32> = row.get("blockers");
                    if wait_type.as_deref() == Some("Lock")
                        && blockers.contains(&controller_pid)
                        && query.contains("artifact_private_read_record_snapshot")
                        && query.contains("FROM visible_run r JOIN openbot_internal.artifact_records a")
                        && query.contains("LEFT JOIN openbot_internal.artifact_cleanup_fences c")
                    {
                        let observer_pid: i32 = row.get("observer_pid");
                        require(original_pid != controller_pid && observer_pid != original_pid && observer_pid != controller_pid,
                            "P1 source query producer/controller/observer were not distinct actual backends")?;
                        break observer_pid;
                    }
                }
                require(Instant::now() < wait_deadline,
                    "P1 original guarded read never reached the complete source snapshot at its actual controller lock")?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            // Preliminary Host and schema queries are already past. Withhold only the
            // ensuing original guarded read's ROLLBACK, after the proven source wait.
            clear_transaction_facts(&socket);
            relay.arm(Hold::Rollback);
            transaction.rollback().await.map_err(|error| error.to_string())?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2),
                "P1 actual original guarded read ROLLBACK did not reach its upstream ACK").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
                && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P1 read uncertainty was not its actual original upstream ROLLBACK ACK withheld from the driver")?;
            Ok::<i32, String>(observer_pid)
        }.await;
    drop(controller);
    // Reap the original task even when a control assertion fails. A requested stop
    // on that failure path is never a substitute for the evidence below.
    if controlled.is_err() {
        let _ = f.application.close_public_artifact_reads();
    }
    let original_outcome = worker.await.map_err(|error| error.to_string())?;
    let observer_pid = controlled?;
    require(
        matches!(
            original_outcome,
            Err(AppError::DependencyUnavailable { .. })
        ),
        "P1 missing original read ROLLBACK ACK returned a byte/control grant or definite Host refusal",
    )?;
    original_five_seconds(started)?;
    retired_original(f, original_pid, &original_connection, &socket).await?;
    require(
        socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
        "P1 original held read ACK was later forwarded or credited after retirement",
    )?;
    require(
        database_facts(&f.admin).await? == before
            && object_fact(&f.path())? == original_object
            && owned_object_fds(&f.path())?.is_empty(),
        "P1 original uncertain read changed business/object facts or opened an unowned object FD",
    )?;

    // Revoke the actual old issuer only after its original connection has truly
    // retired. Install a fresh real resolver on the SAME Administration/Store.
    f.resolver.close_request_bindings();
    let fresh_resolver = PostgresSessionAuthResolver::new(
        f.pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
    )
    .map_err(|error| error.to_string())?;
    fresh_resolver
        .install_artifact_read_authority(&f.actual.read_authority())
        .map_err(|_| "P1 new genuine Session issuer enrollment failed")?;
    let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("P1 recovery Session binding missing")?.identity()
                .same_binding(f.auth.request_binding().ok_or("P1 original Session binding missing")?.identity()),
                "P1 uncertain read recovery reused the closed owner or changed six Auth facts")?;
            fresh.request_binding().ok_or("P1 new valid Session missing")?.verify_current_before(&fresh,
                Instant::now() + Duration::from_secs(5)).await
                .map_err(|error| format!("P1 new actual Session was not valid independently of Store poison: {error:?}"))?;
            let after_auth = database_facts(&f.admin).await?;
            only_tables_changed(&before, &after_auth, &["public.sessions"])?;
            let mut expected_sessions = before["public.sessions"].as_array().ok_or("P1 original session facts missing")?.clone();
            let fresh_sessions = after_auth["public.sessions"].as_array().ok_or("P1 recovery session facts missing")?;
            require(expected_sessions.len() == fresh_sessions.len(), "P1 recovery changed original Session inventory")?;
            for (old, new) in expected_sessions.iter_mut().zip(fresh_sessions) {
                if old["row"]["id"].as_str() == Some("cleanup-session-b") {
                    old["row"]["updated_at"] = new["row"]["updated_at"].clone();
                    old["xmin"] = new["xmin"].clone();
                    old["ctid"] = new["ctid"].clone();
                }
            }
            require(expected_sessions == *fresh_sessions,
                "P1 recovery changed fields beyond the named new Session idle observation")?;
            let intent = f.actual.arm_explicit_saved_delete_before(&fresh, &f.receipt.artifact_id,
                Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("genuine fresh-owner arm: {error:?}"))?;
            f.verify_one_arm().await?;
            let armed = database_facts(&f.admin).await?;
            original_arm_append_only(&after_auth, &armed)?;
            physical_poison_refuses(f, &fresh, &intent, &original_record).await?;
            require(database_facts(&f.admin).await? == armed && object_fact(&f.path())? == original_object
                && owned_object_fds(&f.path())?.is_empty(),
                "P02 permanent uncertain refusal mutated armed business facts or original object")?;
            drop(intent);
            eprintln!("ARTIFACT_PHYSICAL_P02_ORIGINAL_READ_ROLLBACK_UNKNOWN original_producer_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_host_rollback_forwarded_before_source_begin=true actual_post_schema_source_begin_held_and_released=true complete_original_source_query_lock_wait=true controller_rollback_ack=true original_upstream_read_rollback_ack=true original_forwarded_read_rollback_ack=false original_five_second_error=true original_driver_destroyed=true corresponding_frontend_eof=true original_backend_gone=true original_owner_closed_after_retirement=true new_true_owner_valid=true same_original_store_pair=true byte_grant=false finite_store_ack=false business_object_unchanged=true held_read_rollback_ack_released=false physical_delete=false");
            Ok::<(), String>(())
        }.await;
    fresh_resolver.close_request_bindings();
    recovery
}

struct PhysicalFrameBytesOwner(
    openbot_application::artifact_read_lifecycle::CurrentArtifactReadFrame,
);
impl AsRef<[u8]> for PhysicalFrameBytesOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[tokio::test]
#[ignore = "requires genuine leased frame/Bytes owners and a real original read rollback-ACK loss"]
async fn actual_original_leased_owner_and_query_unproven_block_physical_cleanup() {
    with_fixture("physical-held-original-allocation", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let mut operation = f.application.open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone()).await.map_err(|e| e.to_string())?;
        let pending = operation.next_block(&f.auth).await.map_err(|e| e.to_string())?;
        require(pending.prefix_length().map_err(|e| e.to_string())? == TEXT.len(), "P02 did not obtain the genuine full leased allocation")?;
        let frame = pending.handoff_frame(&f.auth).map_err(|e| e.to_string())?;
        require(frame.as_bytes() == TEXT.as_bytes(), "P02 genuine frame changed saved bytes")?;
        let bytes = axum::body::Bytes::from_owner(PhysicalFrameBytesOwner(frame));
        let held = bytes.clone();
        let sliced = bytes.slice(1..bytes.len());
        drop(bytes);
        let object = object_fact(&f.path())?;
        let original_fds = owned_object_fds(&f.path())?;
        require(original_fds.len() == 1, "P02 original leased owner did not retain its actual object FD")?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object.clone(), 0, false)?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            wait_fact(|| socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
                Instant::now() + Duration::from_secs(2), "P02 physical invocation never obtained its actual original BEGIN ACK").await?;
            let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)), "P02 shared ACK ignored held original Bytes owners")?;
            require(!gate.saw(1) && object_fact(&f.path())? == object && owned_object_fds(&f.path())? == original_fds,
                "P02 worker preflight/unlink preceded actual original allocation/FD drain")?;
            drop(operation);
            drop(held);
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)), "P02 clone Drop ignored a real surviving Bytes slice")?;
            require(!gate.saw(1) && object_fact(&f.path())? == object, "P02 surviving slice allowed physical IO")?;
            drop(sliced);
            drop(barrier);
            Ok::<(), String>(())
        }.await;
        let outcome = task.await.map_err(|e| e.to_string())?;
        controlled?;
        let observed = outcome.map_err(|e| format!("{e:?}"))?;
        require(started.elapsed() < Duration::from_secs(5) && observed.state() == PhysicalState::DurableAbsent,
            "P02 same original invocation did not continue normally after in-budget last-owner release")?;
        gate.after_unlink_is_original_zero_link()?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P02 original invocation changed armed business facts or retained canonical bytes")?;
        drop(observed); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P02_LEASE held_frame_bytes_clone_slice=true held_original_fd=true no_preflight_while_owned=true same_original_invocation_continued=true original_query_excluded_old_read_inventory=true original_post_io_rollback_ack=true actual_original_fd_closed=true no_refund=true");
        Ok(())
    })).await;
    with_fixture("physical-old-read-query-unproven", true, |f| {
        Box::pin(physical_genuine_original_read_ack_loss(f))
    })
    .await;
}

#[tokio::test]
#[ignore = "requires actual original preflight FD and controlled leaf/fixed-child replacement"]
async fn actual_foreign_store_or_preflight_replaced_object_refuses_cleanup_without_unlink() {
    with_fixture("physical-foreign-original-store", true, |f| Box::pin(async move {
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let foreign_root = OwnedRoot::new()?;
        let foreign_deployment = DeploymentId::new("foreign-physical-deployment");
        let foreign_tenant = TenantId::new("foreign-physical-tenant");
        let foreign_registry = Arc::new(ArtifactDatasetRegistry::from_server(f.pool.clone(),
            &foreign_deployment, &foreign_tenant).await.map_err(|e| e.to_string())?);
        let foreign_store = Arc::new(DatasetBoundArtifactStore::bind_host_root(
            std::fs::File::open(&foreign_root.0).map_err(|e| e.to_string())?, foreign_registry.clone(), ArtifactQuotaPolicy::default()).await.map_err(|e| e.to_string())?);
        let foreign = Arc::new(PostgresArtifactAdministration::new(foreign_registry.clone(), foreign_store,
            ArtifactQuotaPolicy::default(), SecretBytes::new(vec![0x18; 32])).map_err(|e| e.to_string())?);
        let original = object_fact(&f.path())?;
        let gate = install_physical_gate(f, original.clone(), 0, false)?;
        let before = database_facts(&f.admin).await?;
        require(matches!(foreign.remove_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await, Err(PhysicalError::Conflict)),
            "foreign Store accepted original mechanical intent or refused only after fake Host IO")?;
        require(!gate.saw(1) && !gate.saw(2) && !gate.saw(3) && !gate.saw(4), "foreign mechanical intent started the original worker")?;
        require(database_facts(&f.admin).await? == before && object_fact(&f.path())? == original && owned_object_fds(&f.path())?.is_empty(),
            "foreign Store refusal changed original business/object facts")?;
        drop(foreign); drop(foreign_registry); drop(foreign_root); drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P03_FOREIGN original_store_identity_mismatch=true mechanical_conflict=true worker_not_started=true zero_unlink=true business_original_object_unchanged=true");
        Ok(())
    })).await;
    for kind in [0_u8, 1, 2] {
        let tag = match kind {
            0 => "physical-preflight-leaf-replaced",
            1 => "physical-preflight-objects-replaced",
            _ => "physical-preflight-staging-symlink",
        };
        with_fixture(tag, true, move |f| Box::pin(async move {
            let original = object_fact(&f.path())?;
            let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
            let before = database_facts(&f.admin).await?;
            let gate = install_physical_gate(f, original.clone(), 2, false)?;
            let release = PhysicalGateRelease(gate.clone());
            let (pid, _, socket) = f.original().await?;
            clear_transaction_facts(&socket);
            let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
            let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth,
                &original_intent, Instant::now() + Duration::from_secs(5)).await });
            let controlled = async {
                gate.wait(2, Instant::now() + Duration::from_secs(2)).await?;
                require(gate.saw(1) && !gate.saw(3), "drift controller did not run after actual full preflight and before unlink")?;
                let kept;
                let replaced;
                if kind == 0 {
                    kept = f.root.0.join("controller-original-retained-object");
                    std::fs::rename(f.path(), &kept).map_err(|e| e.to_string())?;
                    std::fs::write(f.path(), TEXT.as_bytes()).map_err(|e| e.to_string())?;
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
                    replaced = object_fact(&f.path())?;
                    require(replaced.ino != original.ino && replaced.sha256 == original.sha256 && object_fact(&kept)? == original,
                        "preflight leaf replacement was not a distinct actual inode with original retained")?;
                } else if kind == 1 {
                    kept = f.root.0.join("controller-original-objects");
                    std::fs::rename(f.root.0.join("objects"), &kept).map_err(|e| e.to_string())?;
                    std::fs::DirBuilder::new().mode(0o700).create(f.root.0.join("objects")).map_err(|e| e.to_string())?;
                    std::fs::write(f.path(), TEXT.as_bytes()).map_err(|e| e.to_string())?;
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
                    replaced = object_fact(&f.path())?;
                    require(replaced.ino != original.ino && replaced.sha256 == original.sha256
                        && object_fact(&kept.join(&f.receipt.artifact_id))? == original,
                        "fixed objects child replacement did not preserve original and distinct replacement inodes")?;
                } else {
                    kept = f.root.0.join("controller-original-staging");
                    std::fs::rename(f.root.0.join("staging"), &kept).map_err(|e| e.to_string())?;
                    std::os::unix::fs::symlink(&kept, f.root.0.join("staging")).map_err(|e| e.to_string())?;
                    require(std::fs::symlink_metadata(f.root.0.join("staging")).map_err(|e| e.to_string())?.file_type().is_symlink(),
                        "fixed staging child was not an actual NOFOLLOW symlink counterexample")?;
                    replaced = object_fact(&f.path())?;
                }
                Ok::<(PathBuf, ObjectFact), String>((kept, replaced))
            }.await;
            drop(release);
            let result = task.await.map_err(|e| e.to_string())?;
            let (kept, replacement) = controlled?;
            require(matches!(result, Err(PhysicalError::Corrupt { field: "object" | "store_binding" })),
                "actual preflight leaf/fixed-child drift gained unlink or a normal observation")?;
            physical_original_fd_closed(&gate).await?;
            physical_normal_original_ack(f, pid, &socket).await?;
            require(!gate.saw(3) && object_fact(&f.path())? == replacement && database_facts(&f.admin).await? == before,
                "drift refusal unlinked replacement or mutated original armed business facts")?;
            if kind == 0 { require(object_fact(&kept)? == original, "leaf drift refusal damaged retained original")?; }
            if kind == 1 { require(object_fact(&kept.join(&f.receipt.artifact_id))? == original, "child drift refusal damaged original held directory object")?; }
            if kind == 2 { require(object_fact(&f.path())? == original, "staging NOFOLLOW refusal damaged original object")?; }
            if kind != 0 {
                let original_child = std::fs::symlink_metadata(&kept).map_err(|e| e.to_string())?;
                require(original_child.is_dir(), "fixed-child controller lost the original retained directory")?;
                let device = original_child.dev(); let inode = original_child.ino();
                let held_directory = tokio::task::spawn_blocking(move || physical_inode_fds_for(device, inode)).await.map_err(|e| e.to_string())??;
                require(!held_directory.is_empty(), "still-live original Store lost its actual held root-child FD identity")?;
            }
            drop(intent);
            eprintln!("ARTIFACT_PHYSICAL_P03_DRIFT kind={kind} original_preflight_fd_fullsha=true distinct_controller_replacement=true zero_unlink=true original_leaf_fd_closed=true held_store_directory_inventory_not_claimed_zero=true original_query_rollback_ack=true business_unchanged=true");
            Ok(())
        })).await;
    }
}

async fn physical_schema_wait(f: &Fixture, pid: i32, controller_pid: i32) -> Result<(), String> {
    wait_blocked(
        &f.admin,
        pid,
        "openbot_internal.schema_migrations",
        controller_pid,
    )
    .await?;
    let observer = f.admin.get().await.map_err(|e| e.to_string())?;
    let row = observer.query_one("SELECT pg_backend_pid() AS observer_pid,query,wait_event_type,pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_stat_activity WHERE pid=$1", &[&pid]).await.map_err(|e| e.to_string())?;
    let observer_pid: i32 = row.get("observer_pid");
    require(
        observer_pid != pid
            && observer_pid != controller_pid
            && pid != controller_pid
            && row.get::<_, Option<String>>("wait_event_type").as_deref() == Some("Lock")
            && row.get::<_, Vec<i32>>("blockers").contains(&controller_pid)
            && row.get::<_, String>("query").contains(
                "SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=$1",
            ),
        "original physical schema waiter did not have a unique actual producer/controller/observer",
    )
}
async fn physical_connection_check_interval(f: &Fixture) -> Result<(), String> {
    let c = f.pool.get().await.map_err(|e| e.to_string())?;
    c.batch_execute("SET client_connection_check_interval='10ms'")
        .await
        .map_err(|e| e.to_string())?;
    let setting: String = c
        .query_one(
            "SELECT current_setting('client_connection_check_interval')",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(
        setting == "10ms",
        "owned connection did not enable actual finite server-side disappearance checks",
    )
}

#[tokio::test]
#[ignore = "requires actual unlink, caller-only cancel, original expiry and main-runtime owner Drop"]
async fn actual_original_physical_worker_cancel_and_expiry_keep_armed_charge_without_relabelling_effects()
 {
    with_fixture("physical-caller-wait-only-cancel", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()
        }.await;
        // This JoinHandle owns only the public caller waiter, not the implementation's
        // independently owned main/query supervisor. Actual cancellation is reaped.
        task.abort();
        let joined = task.await;
        drop(release);
        controlled?;
        require(joined.is_err_and(|e| e.is_cancelled()), "P04-A original caller waiter was not actually cancelled and reaped")?;
        physical_original_fd_closed(&gate).await?;
        wait_fact(|| socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0,
            started + Duration::from_secs(5), "P04-A retained original supervisor did not forward its real in-budget ROLLBACK ACK").await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(database_facts(&f.admin).await? == armed && physical_absent(&f.path()), "P04-A waiter cancellation relabelled true unlink or changed charge/fence")?;
        let observed = f.actual.observe_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("P04-A new acknowledged reobservation: {e:?}"))?;
        require(observed.state() == PhysicalState::DurableAbsent, "P04-A new observe did not independently prove actual double absence")?;
        require(database_facts(&f.admin).await? == armed && gate.facts.lock().map_err(|_| "P04-A observer poisoned")?.seen[2] == 1, "P04-A reobservation repeated unlink or changed armed facts")?;
        gate.check()?;
        let barrier = f.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?;
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(2)).await.map_err(|e| format!("{e:?}"))?;
        drop(ack); drop(barrier); drop(observed); drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_A original_waiter_cancelled_reaped=true original_unlink_effect_kept=true original_main_supervisor_retained=true original_on_time_rollback_ack=true actual_original_fd_closed=true later_new_observe_only_durable_absent=true original_waiter_not_relabelled=true no_poison_clear=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-original-post-unlink-expiry", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()
        }.await;
        let result = task.await.map_err(|e| e.to_string())?;
        drop(release); controlled?;
        require(result.is_err(), "P04-B expired original invocation produced a normal physical witness")?;
        original_five_seconds(started)?;
        physical_original_fd_closed(&gate).await?;
        retired_original(f, pid, &connection, &socket).await?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P04-B late resource end erased actual unlink or changed original armed facts")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_B actual_unlink_before_expiry=true original_fd_nlink_zero=true original_five_second_fail=true late_worker_fd_closed=true original_driver_backend_gone=true permanent_same_store_poison=true no_normal_reobservation=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-main-runtime-owner-drop", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let object = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, object.clone(), 0, false)?;
        physical_connection_check_interval(f).await?;
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        tx.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|e| e.to_string())?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let original = runtime.spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth,
            &original_intent, Instant::now() + Duration::from_secs(5)).await });
        let controlled = physical_schema_wait(f, pid, controller_pid).await;
        // Normal Drop of THIS fixture-owned runtime destroys the actual main supervisor,
        // while the external original Store/Pool/Host and its driver remain owned here.
        tokio::task::spawn_blocking(move || drop(runtime)).await.map_err(|e| e.to_string())?;
        let joined = original.await;
        let controller_ack = tx.rollback().await.map_err(|e| e.to_string()); drop(controller);
        controlled?; controller_ack?;
        require(joined.is_err_and(|e| e.is_cancelled()), "P04-C actual runtime-owner Drop did not destroy and reap the original task")?;
        retired_original(f, pid, &connection, &socket).await?;
        require(!gate.saw(1) && !gate.saw(3) && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0,
            "P04-C main owner Drop was mistaken for an original ACK or physical worker")?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(database_facts(&f.admin).await? == armed && object_fact(&f.path())? == object && owned_object_fds(&f.path())?.is_empty(),
            "P04-C genuine main owner retirement changed rows/object or retained original leaf FD")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P04_C actual_original_schema_lock_pid=true actual_main_runtime_owner_dropped=true original_task_cancelled_reaped=true original_query_ack=false original_driver_backend_gone=true permanent_same_store_poison=true zero_unlink=true charge_fence_unchanged=true");
        Ok(())
    })).await;
}

fn physical_session_b_idle_only(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<(), String> {
    only_tables_changed(before, after, &["public.sessions"])?;
    let mut expected = before["public.sessions"]
        .as_array()
        .ok_or("physical original Session facts missing")?
        .clone();
    let actual = after["public.sessions"]
        .as_array()
        .ok_or("physical fresh Session facts missing")?;
    require(
        expected.len() == actual.len(),
        "physical Session observation changed row inventory",
    )?;
    for (old, new) in expected.iter_mut().zip(actual) {
        if old["row"]["id"].as_str() == Some("cleanup-session-b") {
            old["row"]["updated_at"] = new["row"]["updated_at"].clone();
            old["xmin"] = new["xmin"].clone();
            old["ctid"] = new["ctid"].clone();
        }
    }
    require(
        expected == *actual,
        "physical current Session changed more than original B idle touch",
    )
}

#[tokio::test]
#[ignore = "requires actual absent names, original current refusal/unknown and post-IO rollback-ACK loss"]
async fn actual_already_absent_armed_pair_requires_current_authority_and_acknowledged_reobservation()
 {
    with_fixture("physical-original-already-absent", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let armed = database_facts(&f.admin).await?;
        std::fs::remove_file(f.path()).map_err(|e| e.to_string())?;
        require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
            "P05-A controlled fixture names were not actually absent")?;
        let gate = install_physical_gate(f, original, 0, true)?;
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let observed = f.actual.observe_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        require(observed.state() == PhysicalState::DurableAbsent && !gate.saw(2) && !gate.saw(3),
            "P05-A ordinary absence falsely reported a retained leaf or performed unlink")?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(database_facts(&f.admin).await? == armed, "P05-A actual observe mutated original charge/receipt/fence/audit")?;
        drop(observed); drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P05_A both_names_actually_absent_before_call=true new_current_original_query=true guarded_three_directory_sync=true original_worker_ended=true original_rollback_ack=true zero_unlink=true durable_absent=true no_refund=true");
        Ok(())
    })).await;
    with_fixture("physical-pregrant-known-session-refusal", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original.clone(), 1, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, _, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent,
            started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(1, Instant::now() + Duration::from_secs(2)).await?;
            let mut c = f.admin.get().await.map_err(|e| e.to_string())?;
            let tx = c.transaction().await.map_err(|e| e.to_string())?;
            let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            require(controller_pid != pid && tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await.map_err(|e| e.to_string())? == 1,
                "P05-B-known did not revoke the actual original Session row independently")?;
            tx.commit().await.map_err(|e| e.to_string())?;
            let changed = database_facts(&f.admin).await?;
            only_tables_changed(&armed, &changed, &["public.sessions"])?;
            controller_removed_row(&armed, &changed, "public.sessions", "id", A_ID)?;
            Ok::<BTreeMap<String, Value>, String>(changed)
        }.await;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        let revoked = controlled?;
        eprintln!("ARTIFACT_PHYSICAL_P05_B_KNOWN_CURRENT_RESULT original_closed_error={:?} original_elapsed_ms={} old_source_fail_not_relabelled=true",
            result.as_ref().err(), started.elapsed().as_millis());
        require(matches!(result, Err(PhysicalError::NotVisible)) && started.elapsed() < Duration::from_secs(5),
            "P05-B-known current committed Session refusal was not definite original NotVisible")?;
        physical_original_fd_closed(&gate).await?;
        physical_normal_original_ack(f, pid, &socket).await?;
        require(!gate.saw(2) && !gate.saw(3) && object_fact(&f.path())? == original && database_facts(&f.admin).await? == revoked,
            "P05-B-known rejection started unlink or changed rows beyond the actual Session controller")?;
        f.resolver.close_request_bindings();
        let fresh_resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY, default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT)).map_err(|e| e.to_string())?;
        fresh_resolver.install_artifact_read_authority(&f.actual.read_authority()).map_err(|_| "P05-B-known fresh issuer enrollment failed")?;
        let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth && !fresh.request_binding().ok_or("fresh Session missing")?.identity().same_binding(f.auth.request_binding().ok_or("original Session missing")?.identity()),
                "P05-B-known reobservation reused the revoked original Host")?;
            fresh.request_binding().ok_or("fresh Session missing")?.verify_current_before(&fresh, Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
            let touched = database_facts(&f.admin).await?; physical_session_b_idle_only(&revoked, &touched)?;
            let observed = f.actual.observe_armed_explicit_saved_bytes_before(&fresh, &intent, Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("known ACK must not invent poison: {e:?}"))?;
            require(observed.state() == PhysicalState::Retained && !gate.saw(3) && object_fact(&f.path())? == original
                && database_facts(&f.admin).await? == touched, "P05-B-known normal new observation changed bytes/business or retained false poison")?;
            physical_original_fd_closed(&gate).await?; gate.check()?;
            drop(observed);
            Ok::<(), String>(())
        }.await;
        fresh_resolver.close_request_bindings(); recovery?;
        drop(intent);
        eprintln!("ARTIFACT_PHYSICAL_P05_B_KNOWN preflight_original_fd=true actual_session_controller_commit=true original_current_host_refusal=true original_on_time_rollback_ack=true actual_original_fd_closed=true zero_unlink=true new_true_session_retained_observation=true unknown_not_inferred_from_error=true no_poison_clear=true");
        Ok(())
    })).await;
    with_fixture("physical-pregrant-original-schema-unknown", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original.clone(), 0, false)?;
        physical_connection_check_interval(f).await?;
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        tx.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = physical_schema_wait(f, pid, controller_pid).await;
        let result = task.await.map_err(|e| e.to_string())?;
        let controller_ack = tx.rollback().await.map_err(|e| e.to_string()); drop(controller);
        controlled?; controller_ack?;
        require(result.is_err(), "P05-B-unknown original schema timeout produced a normal observation")?;
        original_five_seconds(started)?;
        retired_original(f, pid, &connection, &socket).await?;
        require(!gate.saw(1) && !gate.saw(3) && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0,
            "P05-B-unknown timeout fabricated worker effects or an original query ACK")?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(object_fact(&f.path())? == original && database_facts(&f.admin).await? == armed && owned_object_fds(&f.path())?.is_empty(),
            "P05-B-unknown retirement changed original object/business facts")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P05_B_UNKNOWN actual_original_schema_lock=true original_five_second_error=true original_query_ack=false original_driver_backend_gone=true permanent_same_store_poison=true zero_worker_unlink=true later_resources_not_normal_ack=true charge_fence_unchanged=true");
        Ok(())
    })).await;
    with_fixture("physical-post-io-original-rollback-ack-loss", true, |f| Box::pin(async move {
        let record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await.map_err(|e| e.to_string())?;
        let original = object_fact(&f.path())?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let gate = install_physical_gate(f, original, 3, false)?;
        let release = PhysicalGateRelease(gate.clone());
        let (pid, connection, socket) = f.original().await?; clear_transaction_facts(&socket);
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(&auth, &original_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            gate.after_unlink_is_original_zero_link()?;
            require(socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
                "P05-C held IO did not belong to this original acknowledged BEGIN")?;
            f.relay.as_ref().ok_or("P05-C original relay missing")?.arm(Hold::Rollback);
            Ok::<(), String>(())
        }.await;
        drop(release);
        let held = async {
            controlled?;
            gate.wait(4, Instant::now() + Duration::from_secs(2)).await?;
            wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
                Instant::now() + Duration::from_secs(2), "P05-C actual post-IO original rollback ACK was not withheld").await?;
            require(socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0 && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
                && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0 && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                "P05-C uncertainty was not this original physical query's upstream rollback ACK")?;
            physical_original_fd_closed(&gate).await?;
            require(physical_absent(&f.path()) && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
                "P05-C lost ACK preceded actual physical unlink/sync/double absence")?;
            Ok::<(), String>(())
        }.await;
        let result = task.await.map_err(|e| e.to_string())?;
        held?;
        require(result.is_err(), "P05-C missing original rollback ACK produced a normal physical witness")?;
        original_five_seconds(started)?;
        retired_original(f, pid, &connection, &socket).await?;
        physical_poison_refuses(f, &f.auth, &intent, &record).await?;
        require(socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0 && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0 && physical_absent(&f.path()) && database_facts(&f.admin).await? == armed,
            "P05-C late retirement/observation laundered original missing ACK or true physical effects")?;
        drop(intent); drop(record);
        eprintln!("ARTIFACT_PHYSICAL_P05_C actual_io_worker_ended_before_ack_loss=true actual_original_fd_closed=true both_names_absent=true original_upstream_rollback_ack=true forwarded_original_ack=false original_driver_backend_gone=true permanent_same_store_poison=true physical_effects_kept=true normal_witness=false refund=false");
        Ok(())
    })).await;
}

// Terminal assertions use real row images and the fixture's original wire,
// independently of the producer's observer or in-memory committed fact.
const TERMINAL_TABLES: &[&str] = &[
    "openbot_internal.artifact_workspace_quotas",
    "openbot_internal.artifact_save_operations",
    "openbot_internal.artifact_records",
    "openbot_internal.artifact_cleanup_fences",
    "public.audit_events",
    "public.audit_checkpoints",
];
const TERMINAL_OPERATION_NULLS: &[&str] = &[
    "store_id",
    "workspace_kind",
    "workspace_id",
    "expected_sha256",
    "expected_bytes",
    "charged_bytes",
    "actual_absent",
    "actual_byte_length",
    "actual_sha256",
    "actual_location",
    "observation_phase",
    "created_at",
];
const TERMINAL_RECORD_NULLS: &[&str] = &[
    "workspace_kind",
    "workspace_id",
    "media_type",
    "byte_length",
    "sha256",
    "retention_class",
    "saved_by",
    "saved_at",
];

fn terminal_original_row<'a>(
    facts: &'a BTreeMap<String, Value>,
    table: &str,
    id_column: &str,
    id: &str,
) -> Result<&'a Value, String> {
    let rows = facts
        .get(table)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing original terminal table {table}"))?;
    let mut matching = rows
        .iter()
        .filter_map(|entry| entry.get("row"))
        .filter(|row| row.get(id_column).and_then(Value::as_str) == Some(id));
    let row = matching
        .next()
        .ok_or_else(|| format!("missing exact terminal row {table}"))?;
    require(matching.next().is_none(), "ambiguous exact terminal row")?;
    Ok(row)
}

fn terminal_exact_one_row_change(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    table: &str,
    id_column: &str,
    id: &str,
    expected: &Value,
) -> Result<(), String> {
    let old = before
        .get(table)
        .and_then(Value::as_array)
        .ok_or("old terminal table absent")?;
    let new = after
        .get(table)
        .and_then(Value::as_array)
        .ok_or("new terminal table absent")?;
    require(
        old.len() == new.len(),
        "terminal added or removed an original business row",
    )?;
    require(
        terminal_original_row(after, table, id_column, id)? == expected,
        "terminal changed more than its exact registered fields",
    )?;
    for entry in old {
        let row = entry
            .get("row")
            .ok_or("original terminal physical row absent")?;
        if row.get(id_column).and_then(Value::as_str) != Some(id) {
            require(
                new.contains(entry),
                "terminal changed an unrelated physical business row",
            )?;
        }
    }
    Ok(())
}

fn terminal_verify_once(
    f: &Fixture,
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Result<Uuid, String> {
    only_tables_changed(before, after, TERMINAL_TABLES)?;
    let original_operation = terminal_original_row(
        before,
        "openbot_internal.artifact_save_operations",
        "operation_id",
        &f.receipt.operation_id,
    )?;
    let charge = original_operation
        .get("charged_bytes")
        .and_then(Value::as_i64)
        .ok_or("positive original operation charge absent")?;
    require(
        charge == i64::try_from(TEXT.len()).map_err(|e| e.to_string())? && charge > 0,
        "terminal fixture did not start with its genuine original Save charge",
    )?;
    let mut operation = original_operation.clone();
    operation["state"] = Value::String("deleted".to_owned());
    for field in TERMINAL_OPERATION_NULLS {
        operation[*field] = Value::Null;
    }
    terminal_exact_one_row_change(
        before,
        after,
        "openbot_internal.artifact_save_operations",
        "operation_id",
        &f.receipt.operation_id,
        &operation,
    )?;
    let mut record = terminal_original_row(
        before,
        "openbot_internal.artifact_records",
        "artifact_id",
        &f.receipt.artifact_id,
    )?
    .clone();
    record["status"] = Value::String("deleted".to_owned());
    for field in TERMINAL_RECORD_NULLS {
        record[*field] = Value::Null;
    }
    terminal_exact_one_row_change(
        before,
        after,
        "openbot_internal.artifact_records",
        "artifact_id",
        &f.receipt.artifact_id,
        &record,
    )?;
    let mut fence = terminal_original_row(
        before,
        "openbot_internal.artifact_cleanup_fences",
        "artifact_id",
        &f.receipt.artifact_id,
    )?
    .clone();
    fence["phase"] = Value::String("completed".to_owned());
    terminal_exact_one_row_change(
        before,
        after,
        "openbot_internal.artifact_cleanup_fences",
        "artifact_id",
        &f.receipt.artifact_id,
        &fence,
    )?;
    let mut quota = terminal_original_row(
        before,
        "openbot_internal.artifact_workspace_quotas",
        "workspace_id",
        f.receipt.source_thread_id.as_str(),
    )?
    .clone();
    let total = quota["charged_bytes"]
        .as_i64()
        .ok_or("original quota total absent")?;
    quota["charged_bytes"] = Value::from(
        total
            .checked_sub(charge)
            .filter(|remaining| *remaining >= 0)
            .ok_or("original quota subtraction invalid")?,
    );
    terminal_exact_one_row_change(
        before,
        after,
        "openbot_internal.artifact_workspace_quotas",
        "workspace_id",
        f.receipt.source_thread_id.as_str(),
        &quota,
    )?;
    let old = before
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("old audit rows absent")?;
    let new = after
        .get("public.audit_events")
        .and_then(Value::as_array)
        .ok_or("new audit rows absent")?;
    require(
        new.len() == old.len() + 1 && old.iter().all(|row| new.contains(row)),
        "terminal did not append exactly one audit while preserving original physical rows",
    )?;
    let event = new
        .iter()
        .find(|row| !old.contains(row))
        .and_then(|row| row.get("row"))
        .ok_or("actual appended audit row absent")?;
    require(
        event["actor_user_id"].as_str() == Some(OWNER)
            && event["event_type"].as_str() == Some("artifact.cleanup_completed")
            && event["target_type"].as_str() == Some("artifact")
            && event["target_id"].as_str() == Some(f.receipt.artifact_id.as_str())
            && event["payload"]
                == serde_json::json!({
                    "artifact_id":f.receipt.artifact_id,
                    "artifact_operation_id":f.receipt.operation_id
                })
            && event["row_hash"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64),
        "terminal audit changed its actual actor/type/target or exact content-free payload",
    )?;
    Uuid::parse_str(
        event["id"]
            .as_str()
            .ok_or("actual append audit UUID absent")?,
    )
    .map_err(|e| e.to_string())
}

async fn terminal_prepare(f: &Fixture) -> Result<ArmedArtifactCleanupIntent, String> {
    let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
    let physical = f
        .actual
        .remove_armed_explicit_saved_bytes_before(
            &f.auth,
            &intent,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
    require(
        physical.state() == PhysicalState::DurableAbsent
            && physical_absent(&f.path())
            && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
        "terminal precondition did not obtain genuine original physical double absence",
    )?;
    drop(physical);
    Ok(intent)
}

#[derive(Default)]
struct TerminalObserverFacts {
    phases: Mutex<Vec<TerminalPhase>>,
}
impl ArtifactCleanupTerminalObserver for TerminalObserverFacts {
    fn on_phase(&self, phase: TerminalPhase, _artifact_id: Uuid, original_leaf_fd: Option<i32>) {
        assert!(
            original_leaf_fd.is_none(),
            "absent terminal worker acquired a leaf FD"
        );
        self.phases
            .lock()
            .expect("original terminal phase facts")
            .push(phase);
    }
}
impl TerminalObserverFacts {
    fn normal_order(&self) -> Result<(), String> {
        require(
            *self
                .phases
                .lock()
                .map_err(|_| "terminal phase facts poisoned")?
                == [
                    TerminalPhase::AbsenceGuarded,
                    TerminalPhase::BeforeCommit,
                    TerminalPhase::AfterCommitAckBeforeWorkerEnd,
                    TerminalPhase::WorkerEnded,
                ],
            "terminal original worker/permission/ACK/actual resource-end observer order changed",
        )
    }
    fn no_worker(&self) -> Result<(), String> {
        require(
            self.phases
                .lock()
                .map_err(|_| "terminal phase facts poisoned")?
                .is_empty(),
            "completed retry reserved a physical worker or pretended resource End",
        )
    }
}

async fn terminal_original_ack(
    f: &Fixture,
    pid: i32,
    socket: &SocketFacts,
    commit: bool,
) -> Result<(), String> {
    let bit = if commit { COMMIT_BIT } else { ROLLBACK_BIT };
    require(
        socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
        "terminal result lacked true original BEGIN/disposition packets",
    )?;
    if !commit {
        require(
            socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0,
            "completed or refused terminal entered COMMIT",
        )?;
    }
    let current = f.pool.get().await.map_err(|e| e.to_string())?;
    require(
        current
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get::<_, i32>(0)
            == pid,
        "normal original terminal query was retired rather than reusable",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PG and real original Store terminal transaction"]
async fn actual_terminal_commits_once_refunds_original_charge_and_retry_has_no_worker_or_recharge()
{
    with_fixture("terminal-original-once", true, |f| Box::pin(async move {
        let intent = terminal_prepare(f).await?;
        let before = database_facts(&f.admin).await?;
        let observer = Arc::new(TerminalObserverFacts::default());
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let started = Instant::now();
        let observed = f.actual.finalize_armed_explicit_saved_before_with_observer(
            &f.auth, &intent, started + Duration::from_secs(5), Some(observer.clone()))
            .await.map_err(|e| format!("{e:?}"))?;
        require(started.elapsed() < Duration::from_secs(5)
            && observed.state() == TerminalState::Committed, "terminal did not commit inside original budget")?;
        terminal_original_ack(f, pid, &socket, true).await?;
        observer.normal_order()?;
        let after = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &after)?;
        let gone = AppError::ArtifactGone {
            status: openbot_contracts::artifacts::ArtifactGoneStatus::Deleted,
        };
        require(gone.http_status() == 410 && matches!(
            f.application.read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone()).await,
            Err(error) if error == gone,
        ), "source-present terminal body did not retain the exact deleted410 error")?;
        let retained = openbot_application::ArtifactAdministration::get_metadata(
            f.actual.as_ref(), &f.auth, &f.receipt.artifact_id,
        ).await.map_err(|e| e.to_string())?;
        require(retained == openbot_contracts::artifacts::ArtifactMetadata::Deleted(
            openbot_contracts::artifacts::ArtifactTombstone {
                artifact_id: f.receipt.artifact_id.clone(),
                operation_id: f.receipt.operation_id.clone(),
                request_id: f.receipt.request_id.clone(),
                owner_actor_id: f.receipt.owner_actor_id.clone(),
                source_thread_id: f.receipt.source_thread_id.clone(),
                source_run_id: f.receipt.source_run_id.clone(),
                source_message_id: f.receipt.source_message_id.clone(),
                source_call_seq: f.receipt.source_call_seq,
                source_attempt_seq: f.receipt.source_attempt_seq,
            },
        ), "source-present terminal metadata changed its complete original tombstone")?;
        require(matches!(f.application.execute(f.auth.clone(), AppCommand::GetArtifactMetadata(
            openbot_contracts::artifacts::GetArtifactMetadata { artifact_id: f.receipt.artifact_id.clone() },
        )).await, Err(error) if error == gone),
            "public source-present terminal metadata did not project the exact deleted410 error")?;
        drop(observed);
        // This real lock remains held during CompletedTerminal. A retry that
        // touches/initializes quota must fail its original deadline.
        let mut held = f.admin.get().await.map_err(|e| e.to_string())?;
        let quota_lock = held.transaction().await.map_err(|e| e.to_string())?;
        quota_lock.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",
            &[&f.receipt.source_thread_id.as_str()]).await.map_err(|e| e.to_string())?;
        let retry_observer = Arc::new(TerminalObserverFacts::default());
        clear_transaction_facts(&socket);
        let retry = f.actual.finalize_armed_explicit_saved_before_with_observer(
            &f.auth, &intent, Instant::now() + Duration::from_secs(2), Some(retry_observer.clone()))
            .await.map_err(|e| format!("{e:?}"))?;
        require(retry.state() == TerminalState::AlreadyCompleted, "healthy same-live Store retry was not Completed")?;
        terminal_original_ack(f, pid, &socket, false).await?;
        retry_observer.no_worker()?;
        require(database_facts(&f.admin).await? == after,
            "completed retry changed any original business/receipt/Run/quota/audit physical row")?;
        quota_lock.rollback().await.map_err(|e| e.to_string())?;
        drop(held); drop(retry); drop(intent);
        eprintln!("ARTIFACT_TERMINAL_G01 original_pid={pid} actual_audit_event_id={event_id} original_commit_ack=true exact_original_refund_once=true record8null_operation12null=true seven_identities_positive_receipt_and_run_preserved=true completed_own_rollback_ack=true completed_locked_quota_not_accessed=true completed_no_worker_or_repeat_audit=true");
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires original source deletion, real arm/physical and actual terminal transaction"]
async fn actual_terminal_after_source_hard_delete_keeps_management_and_body404() {
    with_fixture("terminal-original-source-deleted", true, |f| Box::pin(async move {
        hard_delete_original_message(f).await?;
        read_is_404(f).await?;
        let intent = terminal_prepare(f).await?;
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let result = f.actual.finalize_armed_explicit_saved_before(
            &f.auth, &intent, Instant::now() + Duration::from_secs(5))
            .await.map_err(|e| format!("{e:?}"))?;
        require(result.state() == TerminalState::Committed,
            "hard-deleted source prevented current original saved-owner terminal management")?;
        terminal_original_ack(f, pid, &socket, true).await?;
        let after = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &after)?;
        read_is_404(f).await?;
        require(database_facts(&f.admin).await? == after,
            "source body/metadata refusal changed completed original facts")?;
        drop(result); drop(intent);
        eprintln!("ARTIFACT_TERMINAL_SOURCE_DELETED original_pid={pid} actual_audit_event_id={event_id} original_source_stays_absent=true saved_owner_management_current=true body_metadata404=true original_commit_ack=true");
        Ok(())
    })).await;
}

// V7-IMPL-022 registered Server G01/G02/G04 suffix. Controlled rows and unlink
// below belong only to the harness's synthetic owned fixture; they are not Save
// UUID collisions, another producer's refund, or a successful physical020 call.
#[allow(non_camel_case_types)]
struct terminal_g124_PhaseGate {
    pause: TerminalPhase,
    original_deadline: Instant,
    facts: Mutex<(bool, bool, Vec<TerminalPhase>)>,
    changed: Condvar,
}
impl terminal_g124_PhaseGate {
    fn new(pause: TerminalPhase, original_deadline: Instant) -> Arc<Self> {
        Arc::new(Self {
            pause,
            original_deadline,
            facts: Mutex::new((false, false, Vec::new())),
            changed: Condvar::new(),
        })
    }
    fn seen(&self) -> bool {
        self.facts.lock().is_ok_and(|facts| facts.0)
    }
    fn release(&self) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.1 = true;
            self.changed.notify_all();
        }
    }
    fn normal_order(&self) -> Result<(), String> {
        require(
            self.facts
                .lock()
                .map_err(|_| "G124 original observer facts poisoned")?
                .2
                == [
                    TerminalPhase::AbsenceGuarded,
                    TerminalPhase::BeforeCommit,
                    TerminalPhase::AfterCommitAckBeforeWorkerEnd,
                    TerminalPhase::WorkerEnded,
                ],
            "G124 original resource/permission/ACK/end order changed",
        )
    }
}
impl ArtifactCleanupTerminalObserver for terminal_g124_PhaseGate {
    fn on_phase(&self, phase: TerminalPhase, _artifact: Uuid, original_leaf_fd: Option<i32>) {
        assert!(
            original_leaf_fd.is_none(),
            "G124 absent terminal retained a body FD"
        );
        let record_and_pause = || {
            let Ok(mut facts) = self.facts.lock() else {
                return;
            };
            facts.2.push(phase);
            if phase == self.pause {
                facts.0 = true;
                self.changed.notify_all();
                while !facts.1 && Instant::now() < self.original_deadline {
                    let remaining = self
                        .original_deadline
                        .saturating_duration_since(Instant::now());
                    let Ok((next, _)) = self.changed.wait_timeout(facts, remaining) else {
                        return;
                    };
                    facts = next;
                }
            }
        };
        if phase == TerminalPhase::BeforeCommit && phase == self.pause {
            // This cutpoint runs in the real async supervisor. Hand its multi-thread
            // runtime work off before announcing the pause and blocking this thread.
            tokio::task::block_in_place(record_and_pause);
        } else {
            // AbsenceGuarded already runs in the original spawn_blocking worker.
            record_and_pause();
        }
    }
}
#[allow(non_camel_case_types)]
struct terminal_g124_PhaseRelease(Arc<terminal_g124_PhaseGate>);
impl Drop for terminal_g124_PhaseRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn terminal_g124_save_second(f: &Fixture) -> Result<ArtifactRegistrationReceipt, String> {
    let reply = f
        .application
        .execute(
            f.auth.clone(),
            AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: Uuid::now_v7().to_string(),
                source_thread_id: f.receipt.source_thread_id.clone(),
                source_run_id: f.receipt.source_run_id.clone(),
                source_message_id: f.receipt.source_message_id.clone(),
                expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
    let AppReply::ArtifactRegistrationReceipt(receipt) = reply else {
        return Err("G124 genuine second Save returned another reply".to_owned());
    };
    require(
        receipt.artifact_id != f.receipt.artifact_id
            && receipt.operation_id != f.receipt.operation_id,
        "G124 genuine second Save did not mint its own exact pair",
    )?;
    require(
        object_fact(&f.root.0.join("objects").join(&receipt.artifact_id))?.sha256
            == format!("{:x}", Sha256::digest(TEXT.as_bytes())),
        "G124 genuine second Save did not materialize its actual object",
    )?;
    Ok(receipt)
}

fn terminal_g124_unlink_owned_original(f: &Fixture, original: &ObjectFact) -> Result<(), String> {
    require(
        object_fact(&f.path())? == *original
            && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
        "G124 controlled absence did not select its original owned canonical inode",
    )?;
    std::fs::remove_file(f.path()).map_err(|e| e.to_string())?;
    std::fs::File::open(f.root.0.join("objects"))
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())?;
    std::fs::File::open(f.root.0.join("staging"))
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())?;
    require(
        physical_absent(&f.path())
            && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
        "G124 fixture controller did not leave the two actual owned names absent",
    )
}

fn terminal_g124_unlinked_inode_still_owned(original: &ObjectFact) -> Result<Vec<String>, String> {
    let fds = physical_inode_fds(original)?;
    require(
        !fds.is_empty(),
        "G124 old allocation lost its original FD before actual last-owner release",
    )?;
    for fd in &fds {
        let duplicate = std::fs::File::open(format!("/dev/fd/{fd}")).map_err(|e| e.to_string())?;
        let metadata = duplicate.metadata().map_err(|e| e.to_string())?;
        let valid = metadata.is_file()
            && metadata.dev() == original.dev
            && metadata.ino() == original.ino
            && metadata.uid() == original.uid
            && metadata.len() == original.len
            && metadata.nlink() == 0;
        drop(duplicate);
        require(
            valid,
            "G124 actual old FD was not the unlinked original saved inode",
        )?;
    }
    Ok(fds)
}

async fn terminal_g124_inode_really_closed(original: ObjectFact) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    tokio::task::spawn_blocking(move || {
        let mut unstable_samples = 0_u32;
        loop {
            match physical_inode_fds(&original) {
                Ok(fds) if fds.is_empty() => {
                    require(Instant::now() < deadline,
                        "G124 original FD empty observation arrived after its existing tail budget")?;
                    eprintln!("ARTIFACT_TERMINAL_G124_FD_TAIL stable_double_empty=true transient_unstable_samples={unstable_samples} original_two_second_tail=true");
                    return Ok(());
                }
                Ok(_) => {}
                Err(error) if error == "original inode FD inventory changed between two actual samples (Unproven)" => {
                    // Actual async cleanup can close this inode between the two strict
                    // samples. This observation proves no closure; await a stable pair.
                    unstable_samples += 1;
                }
                Err(error) => return Err(error),
            }
            require(
                Instant::now() < deadline,
                "G124 original old inode FD did not actually end",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn terminal_g124_open_control(f: &Fixture) -> Result<String, String> {
    let reply = f
        .application
        .execute(
            f.auth.clone(),
            AppCommand::OpenArtifactRead(OpenArtifactRead {
                artifact_id: f.receipt.artifact_id.clone(),
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
    let AppReply::ArtifactReadOpened(opened) = &reply else {
        return Err("G124 actual public original reader was not opened".to_owned());
    };
    let handle = opened.handle_id.clone();
    require(
        opened.artifact_id == f.receipt.artifact_id && opened.byte_length == TEXT.len() as u64,
        "G124 real public reader did not prepare the exact saved object",
    )?;
    let delivery = f
        .application
        .take_artifact_read_control_delivery(f.auth.clone(), reply)
        .map_err(|e| e.to_string())?;
    delivery
        .verify_current_tail(&f.auth)
        .map_err(|e| e.to_string())?;
    drop(delivery);
    Ok(handle)
}

#[allow(non_camel_case_types)]
struct terminal_g124_HeldControlQuery {
    original_pid: i32,
    original_connection: ConnectionObservation,
    socket: Arc<SocketFacts>,
    task: tokio::task::JoinHandle<Result<AppReply, AppError>>,
}

// This is the genuine public Close control-tail joint, not a labelled metadata
// fixture or a new Host lease. Its own schema is complete before the real BEGIN
// ACK is held. The original read-only source joint then waits on the controller's
// actual fence relation lock; only its ensuing original ROLLBACK is withheld.
async fn terminal_g124_hold_original_control_tail(
    f: &Fixture,
    handle_id: String,
) -> Result<terminal_g124_HeldControlQuery, String> {
    let (pid, connection, socket) = f.original().await?;
    clear_transaction_facts(&socket);
    let relay = f
        .relay
        .as_ref()
        .ok_or("G124 original control relay absent")?;
    relay.arm(Hold::Begin);
    let application = Arc::clone(&f.application);
    let auth = f.auth.clone();
    let task = tokio::spawn(async move {
        application
            .execute(
                auth,
                AppCommand::CloseArtifactRead(
                    openbot_contracts::artifact_read_protocol::CloseArtifactRead { handle_id },
                ),
            )
            .await
    });
    let controlled = async {
        wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8,
            Instant::now() + Duration::from_secs(2), "G124 actual control BEGIN ACK did not reach original relay").await?;
        let observer = f.admin.get().await.map_err(|e| e.to_string())?;
        let row = observer.query_one(
            "SELECT pg_backend_pid() AS observer_pid,state,query,xact_start IS NOT NULL AS actual_transaction FROM pg_catalog.pg_stat_activity WHERE pid=$1",
            &[&pid],
        ).await.map_err(|e| e.to_string())?;
        let query: String = row.get("query");
        require(row.get::<_, i32>("observer_pid") != pid
            && row.get::<_, Option<String>>("state").as_deref() == Some("idle in transaction")
            && row.get::<_, bool>("actual_transaction")
            && (query.trim_start().starts_with("BEGIN") || query.trim_start().starts_with("START TRANSACTION"))
            && query.contains("READ COMMITTED") && query.contains("READ ONLY"),
            "G124 held control BEGIN was not the original actual read-only transaction")?;
        drop(observer);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let transaction = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = transaction.query_one("SELECT pg_backend_pid()", &[])
            .await.map_err(|e| e.to_string())?.get(0);
        require(controller_pid != pid, "G124 control query and controller reused the same backend")?;
        transaction.batch_execute("LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE")
            .await.map_err(|e| e.to_string())?;
        relay.release_original_ack(&socket, Hold::Begin)?;
        wait_blocked(&f.admin, pid, "artifact_current_host_joint_read_after_io", controller_pid).await?;
        // Preliminary authentication is absent from this tail: its real original
        // CurrentArtifactReadControlTail owns this reached source joint and query reservation.
        relay.arm(Hold::Rollback);
        transaction.rollback().await.map_err(|e| e.to_string())?;
        drop(controller);
        wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8,
            Instant::now() + Duration::from_secs(2), "G124 actual reached control ROLLBACK ACK was not withheld").await?;
        require(socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
            "G124 control uncertainty was not the actual original driver ACK boundary")?;
        eprintln!("ARTIFACT_TERMINAL_G124_CONTROL original_pid={pid} controller_pid={controller_pid} actual_control_tail_joint_lock_wait=true original_readonly_begin_ack_released=true original_upstream_rollback_ack=true original_forwarded_rollback_ack=false");
        Ok::<(), String>(())
    }.await;
    if let Err(error) = controlled {
        match socket.withheld.load(Ordering::SeqCst) {
            value if value == Hold::Begin as u8 => {
                let _ = relay.release_original_ack(&socket, Hold::Begin);
            }
            value if value == Hold::Rollback as u8 => {
                let _ = relay.release_original_ack(&socket, Hold::Rollback);
            }
            _ => {}
        }
        let _ = task.await;
        return Err(error);
    }
    Ok(terminal_g124_HeldControlQuery {
        original_pid: pid,
        original_connection: connection,
        socket,
        task,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires original Store invocation slots, real exact-key transactions and genuine second Save"]
async fn actual_terminal_slot_excludes_same_key_and_preserves_independent_keys() {
    with_fixture("terminal-g124-real-key-slots", true, |f| Box::pin(async move {
        let second = terminal_g124_save_second(f).await?;
        let second_intent = Arc::new(f.actual.arm_explicit_saved_delete_before(
            &f.auth, &second.artifact_id, Instant::now() + Duration::from_secs(5),
        ).await.map_err(|e| format!("{e:?}"))?);
        let second_path = f.root.0.join("objects").join(&second.artifact_id);
        let second_original = object_fact(&second_path)?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        let gate = terminal_g124_PhaseGate::new(TerminalPhase::BeforeCommit, deadline);
        let release = terminal_g124_PhaseRelease(Arc::clone(&gate));
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let original = Arc::clone(&intent);
        let observer = Arc::clone(&gate);
        let first = tokio::spawn(async move { actual.finalize_armed_explicit_saved_before_with_observer(
            &auth, &original, deadline, Some(observer),
        ).await });
        let controlled = async {
            wait_fact(|| gate.seen(), Instant::now() + Duration::from_secs(2),
                "G124 original terminal never reached the real BeforeCommit pause").await?;
            require(socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0,
                "G124 original terminal committed before its real pause")?;
            let duplicate_started = Instant::now();
            let duplicate = f.actual.finalize_armed_explicit_saved_before(
                &f.auth, &intent, deadline,
            ).await;
            let phases = gate.facts.lock().map_err(|_| "G124 phase diagnostic mutex poisoned")?.2.clone();
            eprintln!("ARTIFACT_TERMINAL_G124_DUPLICATE original_pid={pid} actual_result={duplicate:?} phases={phases:?} entry_elapsed_us={} duplicate_elapsed_us={} original_deadline_elapsed={} relay_entered={} relay_server_ack={} relay_forwarded_ack={} relay_withheld={} relay_release={}",
                started.elapsed().as_micros(), duplicate_started.elapsed().as_micros(), Instant::now() >= deadline,
                socket.entered.load(Ordering::SeqCst), socket.server_ack.load(Ordering::SeqCst),
                socket.forwarded_ack.load(Ordering::SeqCst), socket.withheld.load(Ordering::SeqCst),
                socket.release_original_ack.load(Ordering::SeqCst));
            require(matches!(duplicate, Err(TerminalError::ReadsUnproven)),
                "G124 same-key terminal duplicate entered another original query")?;
            require(matches!(f.actual.remove_armed_explicit_saved_bytes_before(
                &f.auth, &intent, deadline,
            ).await, Err(PhysicalError::PhysicalUnproven)), "G124 physical cross-mode invocation bypassed the same active slot")?;
            require(matches!(f.actual.observe_armed_explicit_saved_bytes_before(
                &f.auth, &intent, deadline,
            ).await, Err(PhysicalError::PhysicalUnproven)), "G124 observe cross-mode invocation bypassed the same active slot")?;
            require(object_fact(&second_path)? == second_original && database_facts(&f.admin).await? == before,
                "G124 refused duplicates changed another artifact or published uncommitted original rows")?;
            Ok::<(), String>(())
        }.await;
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let other_intent = Arc::clone(&second_intent);
        let independent = tokio::spawn(async move { actual.remove_armed_explicit_saved_bytes_before(
            &auth, &other_intent, deadline,
        ).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        let independent_waiting = !independent.is_finished() && object_fact(&second_path)? == second_original;
        drop(release);
        let first_outcome = first.await.map_err(|e| e.to_string())?;
        let independent_outcome = independent.await.map_err(|e| e.to_string())?;
        controlled?;
        require(independent_waiting, "G124 distinct-key invocation was rejected instead of waiting for its actual shared Pool")?;
        let committed = first_outcome.map_err(|e| format!("{e:?}"))?;
        let absent = independent_outcome.map_err(|e| format!("{e:?}"))?;
        require(committed.state() == TerminalState::Committed && absent.state() == PhysicalState::DurableAbsent
            && started.elapsed() < Duration::from_secs(5), "G124 exact independent key did not continue inside its original budget")?;
        terminal_original_ack(f, pid, &socket, true).await?;
        gate.normal_order()?;
        let after = database_facts(&f.admin).await?;
        let event = terminal_verify_once(f, &before, &after)?;
        require(physical_absent(&second_path), "G124 actual second physical worker did not remove its own original object")?;
        drop(absent); drop(committed); drop(intent); drop(second_intent);
        eprintln!("ARTIFACT_TERMINAL_G124_SLOT original_pid={pid} actual_audit_event_id={event} original_before_commit_paused=true same_key_terminal_and_both_physical_modes_refused=true second_genuine_save_distinct_pair=true independent_key_waited_real_pool=true independent_key_normal_physical_absence=true original_terminal_commit_ack=true exact_original_refund_once=true");
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires original quota row waiter and explicit synthetic controller aggregate change"]
async fn actual_terminal_original_quota_wait_uses_latest_aggregate_once() {
    with_fixture("terminal-g124-fresh-real-quota", true, |f| Box::pin(async move {
        let second = terminal_g124_save_second(f).await?;
        let second_path = f.root.0.join("objects").join(&second.artifact_id);
        let second_original = object_fact(&second_path)?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let charge = i64::try_from(TEXT.len()).map_err(|e| e.to_string())?;
        let original_total = terminal_original_row(&before, "openbot_internal.artifact_workspace_quotas",
            "workspace_id", f.receipt.source_thread_id.as_str())?["charged_bytes"].as_i64().ok_or("G124 original aggregate absent")?;
        require(original_total == charge * 2, "G124 both genuine Save charges were not present before terminal entry")?;
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let transaction = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = transaction.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        transaction.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",
            &[&f.receipt.source_thread_id.as_str()]).await.map_err(|e| e.to_string())?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let started = Instant::now(); let deadline = started + Duration::from_secs(5);
        let gate = terminal_g124_PhaseGate::new(TerminalPhase::AbsenceGuarded, deadline);
        let release = terminal_g124_PhaseRelease(Arc::clone(&gate));
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let original = Arc::clone(&intent); let observer = Arc::clone(&gate);
        let task = tokio::spawn(async move { actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original, deadline, Some(observer)).await });
        let controlled = async {
            wait_blocked(&f.admin, pid, "artifact_workspace_quotas", controller_pid).await?;
            require(!gate.seen() && socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0,
                "G124 worker or COMMIT preceded the real original quota lock")?;
            // This is an explicit owned counter input, NOT another concurrent Save.
            // The second genuine artifact already existed before entry. Changing the
            // nominal aggregate while the real waiter is blocked exposes a stale read.
            let controlled_extra: i64 = 13;
            let fresh_total = original_total.checked_add(controlled_extra).ok_or("G124 counter overflow")?;
            require(transaction.execute(
                "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=$1 WHERE workspace_id=$2",
                &[&fresh_total, &f.receipt.source_thread_id.as_str()],
            ).await.map_err(|e| e.to_string())? == 1, "G124 controller did not change its one original quota row")?;
            transaction.commit().await.map_err(|e| e.to_string())?;
            wait_fact(|| gate.seen(), Instant::now() + Duration::from_secs(2),
                "G124 terminal did not resume from the genuine original quota wait").await?;
            let fresh = database_facts(&f.admin).await?;
            only_tables_changed(&before, &fresh, &["openbot_internal.artifact_workspace_quotas"])?;
            controller_update_columns(&before, &fresh, "openbot_internal.artifact_workspace_quotas",
                "workspace_id", f.receipt.source_thread_id.as_str(), &["charged_bytes"])?;
            require(terminal_original_row(&fresh, "openbot_internal.artifact_workspace_quotas", "workspace_id",
                f.receipt.source_thread_id.as_str())?["charged_bytes"].as_i64() == Some(fresh_total),
                "G124 nominal controller aggregate was not actually visible after its real COMMIT")?;
            Ok::<_, String>((fresh, fresh_total, controlled_extra))
        }.await;
        drop(controller);
        drop(release);
        let outcome = task.await.map_err(|e| e.to_string())?;
        let (fresh, fresh_total, controlled_extra) = controlled?;
        let committed = outcome.map_err(|e| format!("{e:?}"))?;
        require(committed.state() == TerminalState::Committed && started.elapsed() < Duration::from_secs(5),
            "G124 resumed terminal did not commit within its original quota-wait budget")?;
        terminal_original_ack(f, pid, &socket, true).await?;
        gate.normal_order()?;
        let after = database_facts(&f.admin).await?;
        let event = terminal_verify_once(f, &fresh, &after)?;
        require(terminal_original_row(&after, "openbot_internal.artifact_workspace_quotas", "workspace_id",
            f.receipt.source_thread_id.as_str())?["charged_bytes"].as_i64() == fresh_total.checked_sub(charge)
            && object_fact(&second_path)? == second_original,
            "G124 terminal used its earlier aggregate or changed the second genuine artifact")?;
        clear_transaction_facts(&socket);
        let retry = f.actual.finalize_armed_explicit_saved_before(&f.auth, &intent, Instant::now() + Duration::from_secs(2))
            .await.map_err(|e| format!("{e:?}"))?;
        require(retry.state() == TerminalState::AlreadyCompleted && database_facts(&f.admin).await? == after,
            "G124 healthy retry subtracted the current aggregate twice")?;
        terminal_original_ack(f, pid, &socket, false).await?;
        drop(retry); drop(committed); drop(intent);
        eprintln!("ARTIFACT_TERMINAL_G124_QUOTA original_pid={pid} controller_pid={controller_pid} actual_audit_event_id={event} second_genuine_save_preexisted=true concurrent_second_save_claimed=false controlled_extra_nominal_bytes={controlled_extra} actual_original_quota_wait=true fresh_aggregate={fresh_total} original_charge={charge} one_checked_sub_refund=true second_pair_and_object_unchanged=true original_commit_ack=true completed_own_rollback_ack=true");
        Ok(())
    })).await;
}

#[allow(non_camel_case_types)]
struct terminal_g124_AlternateNamespace {
    root: OwnedRoot,
    store: Arc<DatasetBoundArtifactStore>,
    actual: Arc<PostgresArtifactAdministration>,
    resolver: PostgresSessionAuthResolver,
    auth: AuthContext,
}
impl terminal_g124_AlternateNamespace {
    fn close(self) {
        self.resolver.close_request_bindings();
        drop(self.auth);
        drop(self.actual);
        drop(self.store);
        drop(self.resolver);
        drop(self.root);
    }
}

// Legal INSERTs retain every SQL guard. Same UUIDs in another namespace are an
// explicit synthetic input; no claim is made that real Save generated a collision.
// receipt_mode: 0 = absent, 1 = full original positive receipt, 2 = new legal
// positive receipt with a different request identity for strict-decoder refusal.
async fn terminal_g124_alternate_namespace(
    f: &Fixture,
    original: &BTreeMap<String, Value>,
    receipt_mode: u8,
) -> Result<terminal_g124_AlternateNamespace, String> {
    let root = OwnedRoot::new()?;
    let deployment = DeploymentId::new(format!("owned-terminal-g124-{}", Uuid::now_v7()));
    let tenant = TenantId::new("owned-terminal-g124-alternate");
    let registry = Arc::new(
        ArtifactDatasetRegistry::from_server(f.pool.clone(), &deployment, &tenant)
            .await
            .map_err(|e| e.to_string())?,
    );
    let store = Arc::new(
        DatasetBoundArtifactStore::bind_host_root(
            std::fs::File::open(&root.0).map_err(|e| e.to_string())?,
            Arc::clone(&registry),
            ArtifactQuotaPolicy::default(),
        )
        .await
        .map_err(|e| e.to_string())?,
    );
    let actual = Arc::new(
        PostgresArtifactAdministration::new(
            Arc::clone(&registry),
            Arc::clone(&store),
            ArtifactQuotaPolicy::default(),
            SecretBytes::new(vec![0x18; 32]),
        )
        .map_err(|e| e.to_string())?,
    );
    let resolver = PostgresSessionAuthResolver::new(
        f.pool.clone(),
        SESSION_KEY,
        default_session_lifetime(),
        deployment,
        tenant,
    )
    .map_err(|e| e.to_string())?;
    resolver
        .install_artifact_read_authority(&actual.read_authority())
        .map_err(|_| "G124 actual alternate namespace authority enrollment failed")?;
    let auth = resolve(&resolver, COOKIE_B).await?;
    let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
    let transaction = controller.transaction().await.map_err(|e| e.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    let binding = registry.binding();
    for (table, selector, id) in [
        (
            "openbot_internal.artifact_save_operations",
            "operation_id",
            f.receipt.operation_id.as_str(),
        ),
        (
            "openbot_internal.artifact_records",
            "artifact_id",
            f.receipt.artifact_id.as_str(),
        ),
        (
            "openbot_internal.artifact_workspace_quotas",
            "workspace_id",
            f.receipt.source_thread_id.as_str(),
        ),
        (
            "openbot_internal.artifact_saved_receipts",
            "operation_id",
            f.receipt.operation_id.as_str(),
        ),
    ] {
        if table == "openbot_internal.artifact_saved_receipts" && receipt_mode == 0 {
            continue;
        }
        let mut row = terminal_original_row(original, table, selector, id)?.clone();
        row["deployment_id"] = Value::String(binding.deployment_id().to_owned());
        row["tenant_id"] = Value::String(binding.tenant_id().to_owned());
        row["dataset_id"] = Value::String(binding.dataset_id().to_owned());
        if table == "openbot_internal.artifact_save_operations" {
            row["store_id"] = Value::String(store.store_id().to_string());
        }
        if table == "openbot_internal.artifact_saved_receipts" && receipt_mode == 2 {
            row["request_id"] = Value::String(Uuid::now_v7().to_string());
        }
        // Identifiers are from the four fixed owned tables above, never input SQL.
        let sql = format!(
            "INSERT INTO {table} SELECT (jsonb_populate_record(NULL::{table},$1::jsonb)).*"
        );
        require(
            transaction
                .execute(&sql, &[&row])
                .await
                .map_err(|e| e.to_string())?
                == 1,
            "G124 legal controller input did not insert its one alternate namespace row",
        )?;
    }
    transaction.commit().await.map_err(|e| e.to_string())?;
    drop(controller);
    eprintln!(
        "ARTIFACT_TERMINAL_G124_NAMESPACE controller_pid={controller_pid} controlled_same_two_uuid_namespace_input=true real_save_uuid_collision_claimed=false sql_guards_retained=true receipt_mode={receipt_mode} controller_commit_ack=true"
    );
    Ok(terminal_g124_AlternateNamespace {
        root,
        store,
        actual,
        resolver,
        auth,
    })
}

async fn terminal_g124_controller_complete_namespace(
    f: &Fixture,
    alternate: &terminal_g124_AlternateNamespace,
) -> Result<(), String> {
    let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
    let transaction = controller.transaction().await.map_err(|e| e.to_string())?;
    let controller_pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    let row = transaction.query_one(
        "SELECT deployment_id,tenant_id,dataset_id FROM openbot_internal.artifact_store_bindings WHERE store_id=$1",
        &[&alternate.store.store_id().to_string()],
    ).await.map_err(|e| e.to_string())?;
    let deployment: String = row.get(0);
    let tenant: String = row.get(1);
    let dataset: String = row.get(2);
    require(transaction.execute(
        "UPDATE openbot_internal.artifact_records SET status='deleted',workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND status='available'",
        &[&deployment, &tenant, &dataset, &f.receipt.artifact_id],
    ).await.map_err(|e| e.to_string())? == 1, "G124 controlled namespace record transition did not reach its actual pair")?;
    require(transaction.execute(
        "UPDATE openbot_internal.artifact_save_operations SET state='deleted',store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 AND state='available'",
        &[&deployment, &tenant, &dataset, &f.receipt.operation_id],
    ).await.map_err(|e| e.to_string())? == 1, "G124 controlled namespace operation transition did not reach its actual pair")?;
    require(transaction.execute(
        "UPDATE openbot_internal.artifact_cleanup_fences SET phase='completed' WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND phase='armed'",
        &[&deployment, &tenant, &dataset, &f.receipt.artifact_id],
    ).await.map_err(|e| e.to_string())? == 1, "G124 retained 44/45 guards refused the legal exact completed namespace pair")?;
    require(transaction.execute(
        "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=0 WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_id=$4",
        &[&deployment, &tenant, &dataset, &f.receipt.source_thread_id.as_str()],
    ).await.map_err(|e| e.to_string())? == 1, "G124 controlled namespace quota input did not select its own scope")?;
    transaction.commit().await.map_err(|e| e.to_string())?;
    drop(controller);
    require(
        physical_absent(
            &alternate
                .root
                .0
                .join("objects")
                .join(&f.receipt.artifact_id),
        ),
        "G124 alternate controlled pair unexpectedly materialized a Save object",
    )?;
    eprintln!(
        "ARTIFACT_TERMINAL_G124_CONTROLLED_COMPLETE controller_pid={controller_pid} exact_original_seven_and_full_positive_receipt_retained=true legal_record8null_operation12null_fence_completed=true namespace_counter_controller_zero=true sql_identity_and_receipt_guards_retained=true terminal_producer_commit_claimed=false terminal_fact_manufactured=false"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real original committed fact, same-root exclusive Busy and a genuine new namespace Store with legal same UUID input"]
async fn actual_terminal_completed_refuses_other_namespace_same_ids_or_missing_original_fact() {
    with_fixture("terminal-g124-exact-original-fact", true, |f| Box::pin(async move {
        let live = database_facts(&f.admin).await?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let armed = database_facts(&f.admin).await?;
        // The genuine original Store and intent hold this root's exclusive lock.
        // A second bind cannot mint a concurrent Store or a forged restart intent.
        let same_root = DatasetBoundArtifactStore::bind_host_root(
            std::fs::File::open(&f.root.0).map_err(|e| e.to_string())?, Arc::clone(&f.registry), ArtifactQuotaPolicy::default(),
        ).await;
        require(matches!(same_root, Err(openbot_infra::artifact_store::ArtifactStoreError::Busy))
            && database_facts(&f.admin).await? == armed,
            "G124 original exclusive root permitted another Store or second bind changed business facts")?;
        let physical = f.actual.remove_armed_explicit_saved_bytes_before(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        require(physical.state() == PhysicalState::DurableAbsent, "G124 original physical producer lacked true absence")?;
        drop(physical);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let committed = f.actual.finalize_armed_explicit_saved_before(&f.auth, &intent, Instant::now() + Duration::from_secs(5))
            .await.map_err(|e| format!("{e:?}"))?;
        require(committed.state() == TerminalState::Committed, "G124 original same-live Store did not commit")?;
        terminal_original_ack(f, pid, &socket, true).await?;
        let completed = database_facts(&f.admin).await?;
        let original_audit_id = terminal_verify_once(f, &before, &completed)?;
        drop(committed);

        // The two canonical UUIDs now legally appear in another genuine namespace.
        // Its actual new Store has an independently acquired different root lock.
        // Controlled completed rows have the full exact receipt but no fact from a
        // real terminal COMMIT. This is reachable missing-fact coverage, not cold
        // reopen recovery. The global real original audit still matches both IDs.
        let alternate = terminal_g124_alternate_namespace(f, &live, 1).await?;
        require(alternate.store.store_id() != f.store.store_id(),
            "G124 alternate namespace reused the original durable Store identity")?;
        let alternate_intent = alternate.actual.arm_explicit_saved_delete_before(&alternate.auth, &f.receipt.artifact_id,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
        terminal_g124_controller_complete_namespace(f, &alternate).await?;
        let controlled = database_facts(&f.admin).await?;
        let retained_event = controlled["public.audit_events"].as_array().ok_or("G124 global audits absent")?.iter()
            .find(|entry| entry["row"]["id"].as_str() == Some(original_audit_id.to_string().as_str()))
            .ok_or("G124 actual original append audit disappeared")?;
        require(retained_event["row"]["payload"] == serde_json::json!({
            "artifact_id": f.receipt.artifact_id, "artifact_operation_id": f.receipt.operation_id,
        }), "G124 alternate input did not coexist with the global actual matching two-ID audit")?;
        let alternate_observer = Arc::new(TerminalObserverFacts::default());
        clear_transaction_facts(&socket);
        let wrong_namespace = alternate.actual.finalize_armed_explicit_saved_before_with_observer(
            &alternate.auth, &alternate_intent, Instant::now() + Duration::from_secs(5),
            Some(Arc::clone(&alternate_observer) as Arc<dyn ArtifactCleanupTerminalObserver>),
        ).await;
        require(matches!(wrong_namespace, Err(TerminalError::ReadsUnproven)),
            "G124 matching global two-ID audit supplied the missing exact-key fact to the new namespace Store")?;
        terminal_original_ack(f, pid, &socket, false).await?;
        alternate_observer.no_worker()?;
        require(database_facts(&f.admin).await? == controlled, "G124 other-namespace Completed refusal changed any physical business row")?;
        let healthy_observer = Arc::new(TerminalObserverFacts::default());
        clear_transaction_facts(&socket);
        let healthy = f.actual.finalize_armed_explicit_saved_before_with_observer(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5), Some(Arc::clone(&healthy_observer) as Arc<dyn ArtifactCleanupTerminalObserver>))
            .await.map_err(|e| format!("{e:?}"))?;
        require(healthy.state() == TerminalState::AlreadyCompleted && database_facts(&f.admin).await? == controlled,
            "G124 foreign missing fact poisoned or refunded the original healthy Store")?;
        terminal_original_ack(f, pid, &socket, false).await?;
        healthy_observer.no_worker()?;
        drop(healthy); drop(alternate_intent); alternate.close(); drop(intent);
        eprintln!("ARTIFACT_TERMINAL_G124_EXACT_FACT original_pid={pid} original_audit_event_id={original_audit_id} actual_original_store_commit_ack=true concurrent_original_root_bind_exact_busy=true new_namespace_store_and_root_genuine=true new_store_exact_key_missing_fact_refused=true cold_reopen_terminal_decoder_claimed=false legal_other_namespace_same_two_uuid_full_receipt=true matching_global_sql_audit_cannot_supply_other_fact=true refused_own_rollback_ack=true refused_no_worker_or_repair=true original_same_live_store_completed_retry_healthy=true healthy_own_rollback_no_worker=true");
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires genuine Server allocation/Bytes clone owners, real old control-tail query and controlled owned unlink"]
async fn actual_terminal_original_allocation_clone_and_control_tail_block_precommit() {
    with_fixture("terminal-g124-real-old-owners", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let mut operation = f.application.open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone())
            .await.map_err(|e| e.to_string())?;
        let pending = operation.next_block(&f.auth).await.map_err(|e| e.to_string())?;
        require(pending.prefix_length().map_err(|e| e.to_string())? == TEXT.len(),
            "G124 original full leased allocation was not actually materialized")?;
        let frame = pending.handoff_frame(&f.auth).map_err(|e| e.to_string())?;
        require(frame.as_bytes() == TEXT.as_bytes(), "G124 original leased allocation changed saved bytes")?;
        let bytes = axum::body::Bytes::from_owner(PhysicalFrameBytesOwner(frame));
        let held_clone = bytes.clone();
        let surviving_slice = bytes.slice(1..bytes.len());
        let control_handle = terminal_g124_open_control(f).await?;
        let original_fds = physical_inode_fds(&original)?;
        require(original_fds.len() == 2, "G124 original direct allocation and actual public reader did not each retain their real FD")?;
        let intent = Arc::new(f.arm().await.map_err(|e| format!("{e:?}"))?);
        let armed = database_facts(&f.admin).await?;
        let old = terminal_g124_hold_original_control_tail(f, control_handle).await?;
        terminal_g124_unlink_owned_original(f, &original)?;
        require(terminal_g124_unlinked_inode_still_owned(&original)? == original_fds,
            "G124 controller absence closed old reader/allocation owners instead of unlinking owned names")?;
        let relay = f.relay.as_ref().ok_or("G124 control relay absent")?;
        let registered_old_socket = relay.socket_for_pid(old.original_pid)?;
        require(Arc::ptr_eq(&old.socket, &registered_old_socket)
            && old.socket.pid.load(Ordering::SeqCst) == old.original_pid
            && old.socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8
            && old.socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !old.socket.frontend_eof.load(Ordering::SeqCst) && !old.task.is_finished(),
            "G124 rebase did not retain the same actual pending old control ROLLBACK socket")?;
        // Terminal has not been spawned. Remove only inherited BEGIN/COMMIT bits;
        // keep the old ROLLBACK that the original upstream C packet actually set.
        let old_entered_before = old.socket.entered.fetch_and(ROLLBACK_BIT, Ordering::SeqCst);
        let old_server_ack_before = old.socket.server_ack.fetch_and(ROLLBACK_BIT, Ordering::SeqCst);
        let old_forwarded_ack_before = old.socket.forwarded_ack.swap(0, Ordering::SeqCst);
        let old_entered_after = old.socket.entered.load(Ordering::SeqCst);
        let old_server_ack_after = old.socket.server_ack.load(Ordering::SeqCst);
        let old_forwarded_ack_after = old.socket.forwarded_ack.load(Ordering::SeqCst);
        require(old_entered_before & ROLLBACK_BIT != 0 && old_entered_before & COMMIT_BIT == 0
            && old_server_ack_before & ROLLBACK_BIT != 0 && old_server_ack_before & COMMIT_BIT == 0
            && old_forwarded_ack_before & (ROLLBACK_BIT | COMMIT_BIT) == 0
            && old_entered_after == ROLLBACK_BIT && old_server_ack_after == ROLLBACK_BIT
            && old_forwarded_ack_after == 0
            && old.socket.pid.load(Ordering::SeqCst) == old.original_pid
            && old.socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !old.socket.frontend_eof.load(Ordering::SeqCst) && !old.task.is_finished(),
            "G124 old upstream ROLLBACK evidence changed while clearing only inherited transaction bits")?;
        eprintln!("ARTIFACT_TERMINAL_G124_CONTROL_REBASE original_pid={} same_registered_socket={} entered_before={old_entered_before} entered_after={old_entered_after} server_ack_before={old_server_ack_before} server_ack_after={old_server_ack_after} forwarded_ack_before={old_forwarded_ack_before} forwarded_ack_after={old_forwarded_ack_after} withheld={} release={} frontend_eof={} old_task_finished={}",
            old.original_pid, Arc::ptr_eq(&old.socket, &registered_old_socket),
            old.socket.withheld.load(Ordering::SeqCst), old.socket.release_original_ack.load(Ordering::SeqCst),
            old.socket.frontend_eof.load(Ordering::SeqCst), old.task.is_finished());
        let observer = Arc::new(TerminalObserverFacts::default());
        let started = Instant::now(); let deadline = started + Duration::from_secs(5);
        let actual = Arc::clone(&f.actual); let auth = f.auth.clone(); let original_intent = Arc::clone(&intent);
        let phase_observer = Arc::clone(&observer);
        let task = tokio::spawn(async move { actual.finalize_armed_explicit_saved_before_with_observer(
            &auth, &original_intent, deadline, Some(phase_observer),
        ).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        require(!task.is_finished() && observer.no_worker().is_ok()
            && old.socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0
            && database_facts(&f.admin).await? == armed,
            "G124 terminal permission ignored the original outstanding public control-tail query")?;
        require(Arc::ptr_eq(&old.socket, &relay.socket_for_pid(old.original_pid)?)
            && old.socket.pid.load(Ordering::SeqCst) == old.original_pid
            && old.socket.withheld.load(Ordering::SeqCst) == Hold::Rollback as u8
            && old.socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !old.socket.frontend_eof.load(Ordering::SeqCst) && !old.task.is_finished(),
            "G124 release no longer addressed the same actual unforwarded old ROLLBACK")?;
        relay.release_original_ack(&old.socket, Hold::Rollback)?;
        let old_result = old.task.await.map_err(|e| e.to_string())?;
        wait_fact(|| old.socket.release_original_ack.load(Ordering::SeqCst) == 0,
            deadline, "G124 original held ROLLBACK C/Z release was not consumed inside the original terminal budget").await?;
        eprintln!("ARTIFACT_TERMINAL_G124_KNOWN_CONTROL original_pid={} actual_error={:?} terminal_elapsed_us={} original_terminal_deadline_elapsed={} relay_entered={} relay_server_ack={} relay_forwarded_ack={} relay_release={}",
            old.original_pid, old_result.as_ref().err(), started.elapsed().as_micros(), Instant::now() >= deadline,
            old.socket.entered.load(Ordering::SeqCst), old.socket.server_ack.load(Ordering::SeqCst),
            old.socket.forwarded_ack.load(Ordering::SeqCst), old.socket.release_original_ack.load(Ordering::SeqCst));
        require(matches!(old_result, Err(AppError::DependencyUnavailable { dependency: "artifacts" }))
            && Arc::ptr_eq(&old.socket, &relay.socket_for_pid(old.original_pid)?)
            && old.socket.pid.load(Ordering::SeqCst) == old.original_pid
            && old.socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !old.socket.frontend_eof.load(Ordering::SeqCst) && Instant::now() < deadline,
            "G124 original public Close refusal did not consume its real in-budget source ROLLBACK ACK")?;
        // The real old task has completed and its original C/Z release is consumed.
        // Retire only that old fixture latch; a new terminal BEGIN may already exist.
        let consumed_old_hold = old.socket.withheld.compare_exchange(
            Hold::Rollback as u8, 0, Ordering::SeqCst, Ordering::SeqCst,
        ).map_err(|actual| format!("G124 consumed old ROLLBACK latch changed before retirement: {actual}"))?;
        require(consumed_old_hold == Hold::Rollback as u8
            && old.socket.withheld.load(Ordering::SeqCst) == 0
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0,
            "G124 consumed old control latch remained live after its real ACK and task completion")?;
        eprintln!("ARTIFACT_TERMINAL_G124_CONTROL_CONSUMED original_pid={} consumed_old_hold={consumed_old_hold} entered={} server_ack={} forwarded_ack={} withheld={} release={} terminal_elapsed_us={}",
            old.original_pid, old.socket.entered.load(Ordering::SeqCst), old.socket.server_ack.load(Ordering::SeqCst),
            old.socket.forwarded_ack.load(Ordering::SeqCst), old.socket.withheld.load(Ordering::SeqCst),
            old.socket.release_original_ack.load(Ordering::SeqCst), started.elapsed().as_micros());
        wait_fact(|| old.socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
            Instant::now() + Duration::from_secs(2), "G124 terminal did not obtain its own original BEGIN after actual old query drain").await?;
        let barrier = f.actual.close_armed_artifact_reads(&intent).map_err(|e| e.to_string())?;
        require(!task.is_finished() && observer.no_worker().is_ok()
            && matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)),
            "G124 terminal started physical work while original complete allocation owners survived")?;
        drop(operation); drop(bytes); drop(held_clone);
        wait_fact(|| physical_inode_fds(&original).is_ok_and(|fds| fds.len() == 1),
            deadline, "G124 actual public reader FD had not ended after its real control refusal").await?;
        require(terminal_g124_unlinked_inode_still_owned(&original)?.len() == 1
            && !task.is_finished() && observer.no_worker().is_ok()
            && old.socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0,
            "G124 operation/base/clone Drop substituted for the original surviving Bytes slice owner")?;
        drop(surviving_slice);
        terminal_g124_inode_really_closed(original).await?;
        let committed = task.await.map_err(|e| e.to_string())?.map_err(|e| format!("{e:?}"))?;
        require(committed.state() == TerminalState::Committed && started.elapsed() < Duration::from_secs(5),
            "G124 same terminal invocation did not continue after real in-budget old owner release")?;
        terminal_original_ack(f, old.original_pid, &old.socket, true).await?;
        observer.normal_order()?;
        let after = database_facts(&f.admin).await?;
        let event = terminal_verify_once(f, &armed, &after)?;
        drop(committed);
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(2)).await.map_err(|e| format!("{e:?}"))?;
        require(physical_absent(&f.path()) && database_facts(&f.admin).await? == after,
            "G124 final actual owner/control/query drain changed committed facts")?;
        drop(ack); drop(barrier); drop(intent); drop(old.original_connection);
        eprintln!("ARTIFACT_TERMINAL_G124_REAL_OWNERS original_pid={} actual_audit_event_id={event} genuine_complete_allocation=true original_axum_owned_bytes_clone_and_slice=true actual_public_close_control_tail_query_held=true old_original_rollback_ack_released=true controlled_owned_canonical_unlink=true physical020_success_claimed=false original_unlinked_fd_nlink_zero=true no_permission_while_query_or_last_bytes_owner_live=true actual_original_fd_end=true same_five_second_invocation_commit_ack=true local_copy_or_responder_claimed=false", old.original_pid);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires held genuine old allocation expiry and actual original control-tail rollback ACK loss"]
async fn actual_terminal_expiry_and_unknown_reader_or_query_remain_permanently_unproven() {
    with_fixture("terminal-g124-old-allocation-expiry", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let observed_record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id)
            .await.map_err(|e| e.to_string())?;
        let mut operation = f.application.open_current_artifact_read(f.auth.clone(), f.receipt.artifact_id.clone())
            .await.map_err(|e| e.to_string())?;
        let pending = operation.next_block(&f.auth).await.map_err(|e| e.to_string())?;
        require(pending.prefix_length().map_err(|e| e.to_string())? == TEXT.len(),
            "G124 expiry did not hold the genuine complete old allocation")?;
        let frame = pending.handoff_frame(&f.auth).map_err(|e| e.to_string())?;
        let bytes = axum::body::Bytes::from_owner(PhysicalFrameBytesOwner(frame));
        let surviving = bytes.clone(); drop(bytes);
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let armed = database_facts(&f.admin).await?;
        terminal_g124_unlink_owned_original(f, &original)?;
        require(terminal_g124_unlinked_inode_still_owned(&original)?.len() == 1,
            "G124 expiry controlled unlink did not retain the actual old allocation FD")?;
        let (pid, connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let observer = Arc::new(TerminalObserverFacts::default());
        let started = Instant::now();
        let expired = f.actual.finalize_armed_explicit_saved_before_with_observer(
            &f.auth, &intent, started + Duration::from_secs(5),
            Some(Arc::clone(&observer) as Arc<dyn ArtifactCleanupTerminalObserver>),
        ).await;
        require(matches!(expired, Err(TerminalError::DeadlineExpired) | Err(TerminalError::ReadsUnproven)),
            "G124 held old allocation expiry returned a normal or unrelated terminal result")?;
        original_five_seconds(started)?;
        observer.no_worker()?;
        require(socket.entered.load(Ordering::SeqCst) & BEGIN_BIT != 0
            && socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0
            && database_facts(&f.admin).await? == armed,
            "G124 expired old-owner wait entered COMMIT or changed original business facts")?;
        retired_original(f, pid, &connection, &socket).await?;
        drop(operation); drop(surviving);
        terminal_g124_inode_really_closed(original).await?;
        let fresh = resolve(f.resolver.as_ref(), COOKIE_B).await?;
        require(fresh == f.auth && !fresh.request_binding().ok_or("G124 fresh expiry Session missing")?.identity()
            .same_binding(f.auth.request_binding().ok_or("G124 original expiry Session missing")?.identity()),
            "G124 expiry recovery did not use a distinct genuine current Session")?;
        fresh.request_binding().ok_or("G124 fresh expiry binding missing")?
            .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
            .await.map_err(|e| format!("{e:?}"))?;
        let after_auth = database_facts(&f.admin).await?;
        only_tables_changed(&armed, &after_auth, &["public.sessions"])?;
        require(matches!(f.actual.finalize_armed_explicit_saved_before(
            &fresh, &intent, Instant::now() + Duration::from_secs(5),
        ).await, Err(TerminalError::ReadsUnproven)), "G124 late old-owner release or new valid Session repaired expired terminal uncertainty")?;
        physical_poison_refuses(f, &fresh, &intent, &observed_record).await?;
        require(database_facts(&f.admin).await? == after_auth && physical_absent(&f.path()),
            "G124 permanent expiry refusal repaired original charge/fence/audit or absent object")?;
        drop(fresh); drop(intent); drop(observed_record);
        eprintln!("ARTIFACT_TERMINAL_G124_EXPIRY original_pid={pid} genuine_old_full_allocation_and_fd_held=true controlled_owned_unlink=true physical020_success_claimed=false original_five_second_error=true zero_terminal_worker_or_commit=true original_connection_destructor_eof_backend_gone=true actual_late_original_owner_fd_end=true new_real_session_current=true terminal_and_physical_permanent_same_store_unproven=true no_refund_or_repair=true");
        Ok(())
    })).await;

    with_fixture("terminal-g124-real-old-control-ack-unknown", true, |f| Box::pin(async move {
        let original = object_fact(&f.path())?;
        let observed_record = f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id)
            .await.map_err(|e| e.to_string())?;
        let control_handle = terminal_g124_open_control(f).await?;
        let intent = f.arm().await.map_err(|e| format!("{e:?}"))?;
        let armed = database_facts(&f.admin).await?;
        let started = Instant::now();
        let old = terminal_g124_hold_original_control_tail(f, control_handle).await?;
        // Deliberately never release this genuine original upstream ROLLBACK ACK.
        // The original closed-control budget stays five seconds, and its producer
        // must report uncertainty and retire the actual guarded driver/connection.
        let old_result = old.task.await.map_err(|e| e.to_string())?;
        require(matches!(old_result, Err(AppError::DependencyUnavailable { .. })),
            "G124 actual old control-tail ACK loss returned a grant or definite source refusal")?;
        original_five_seconds(started)?;
        retired_original(f, old.original_pid, &old.original_connection, &old.socket).await?;
        require(old.socket.server_ack.load(Ordering::SeqCst) & ROLLBACK_BIT != 0
            && old.socket.forwarded_ack.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && old.socket.release_original_ack.load(Ordering::SeqCst) == 0
            && old.socket.frontend_eof.load(Ordering::SeqCst)
            && database_facts(&f.admin).await? == armed && object_fact(&f.path())? == original,
            "G124 retirement laundered the original lost control ACK or changed armed original facts")?;
        terminal_g124_inode_really_closed(original.clone()).await?;
        let fresh = resolve(f.resolver.as_ref(), COOKIE_B).await?;
        require(fresh == f.auth && !fresh.request_binding().ok_or("G124 new control-loss Session missing")?.identity()
            .same_binding(f.auth.request_binding().ok_or("G124 old control-loss Session missing")?.identity()),
            "G124 unknown control recovery reused its original Session binding")?;
        fresh.request_binding().ok_or("G124 new control-loss binding missing")?
            .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
            .await.map_err(|e| format!("{e:?}"))?;
        let after_auth = database_facts(&f.admin).await?;
        only_tables_changed(&armed, &after_auth, &["public.sessions"])?;
        let observer = Arc::new(TerminalObserverFacts::default());
        require(matches!(f.actual.finalize_armed_explicit_saved_before_with_observer(
            &fresh, &intent, Instant::now() + Duration::from_secs(5),
            Some(Arc::clone(&observer) as Arc<dyn ArtifactCleanupTerminalObserver>),
        ).await, Err(TerminalError::ReadsUnproven)), "G124 old true query ACK loss was repaired by a new genuine Session")?;
        observer.no_worker()?;
        physical_poison_refuses(f, &fresh, &intent, &observed_record).await?;
        require(database_facts(&f.admin).await? == after_auth && object_fact(&f.path())? == original
            && physical_inode_fds(&original)?.is_empty(),
            "G124 unknown control refusal changed actual object, rows or recreated an original FD owner")?;
        drop(fresh); drop(intent); drop(observed_record);
        eprintln!("ARTIFACT_TERMINAL_G124_OLD_CONTROL_UNKNOWN original_pid={} genuine_original_public_close_tail_joint=true original_upstream_rollback_ack=true original_forwarded_rollback_ack=false original_five_second_error=true original_owned_connection_destructor_eof_backend_gone=true old_true_fd_end=true new_real_session_current=true terminal_and_physical_permanent_same_key_refusal=true original_object_and_business_facts_kept=true released_missing_ack=false", old.original_pid);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned strict pair/quota/catalog refusals and legal alternate missing/mismatched receipt inputs"]
async fn actual_terminal_pair_receipt_schema_or_original_quota_corruption_refuses_without_repair() {
    for fault in [
        "workspace_quota",
        "mixed_record",
        "mixed_operation",
        "cleanup_schema",
    ] {
        with_fixture("terminal-g124-strict-original-refusal", true, |f| Box::pin(async move {
            // These GET assertions exercise the genuine missing-source 404 path.
            // Armed/live or mixed rows alone have distinct closed 503/410 errors.
            if fault != "cleanup_schema" {
                hard_delete_original_message(f).await?;
                read_is_404(f).await?;
            }
            let intent = terminal_prepare(f).await?;
            let schema_metadata = if fault == "cleanup_schema" {
                let original_metadata = f.application.execute(f.auth.clone(), AppCommand::GetArtifactMetadata(
                    openbot_contracts::artifacts::GetArtifactMetadata { artifact_id: f.receipt.artifact_id.clone() },
                )).await.map_err(|e| e.to_string())?;
                require(matches!(&original_metadata, AppReply::ArtifactMetadata(
                    openbot_contracts::artifacts::ArtifactMetadata::Available(_))),
                    "G124 schema input lacked its genuine complete available metadata DTO")?;
                Some(original_metadata)
            } else {
                None
            };
            let before = database_facts(&f.admin).await?;
            let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
            let transaction = controller.transaction().await.map_err(|e| e.to_string())?;
            let controller_pid: i32 = transaction.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            let changed_table = match fault {
                "workspace_quota" => {
                    require(transaction.execute(
                        "UPDATE openbot_internal.artifact_workspace_quotas SET charged_bytes=0 WHERE workspace_id=$1",
                        &[&f.receipt.source_thread_id.as_str()],
                    ).await.map_err(|e| e.to_string())? == 1, "G124 original insufficient quota input was not committed")?;
                    "openbot_internal.artifact_workspace_quotas"
                }
                "mixed_record" => {
                    // Legal available -> deleted transition with all eight payloads
                    // cleared. Native identity guards remain fully enabled. Operation
                    // is still live and fence is armed, so the terminal pair is mixed.
                    require(transaction.execute(
                        "UPDATE openbot_internal.artifact_records SET status='deleted',workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE artifact_id=$1 AND status='available'",
                        &[&f.receipt.artifact_id],
                    ).await.map_err(|e| e.to_string())? == 1, "G124 legal controlled mixed record was not reached")?;
                    "openbot_internal.artifact_records"
                }
                "mixed_operation" => {
                    require(transaction.execute(
                        "UPDATE openbot_internal.artifact_save_operations SET state='deleted',store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE operation_id=$1 AND state='available'",
                        &[&f.receipt.operation_id],
                    ).await.map_err(|e| e.to_string())? == 1, "G124 legal controlled mixed operation was not reached")?;
                    "openbot_internal.artifact_save_operations"
                }
                _ => {
                    transaction.batch_execute("ALTER TABLE openbot_internal.artifact_cleanup_fences RENAME CONSTRAINT artifact_cleanup_fences_phase TO owned_terminal_g124_phase_drift")
                        .await.map_err(|e| e.to_string())?;
                    ""
                }
            };
            transaction.commit().await.map_err(|e| e.to_string())?;
            drop(controller);
            let controlled = database_facts(&f.admin).await?;
            only_tables_changed(&before, &controlled,
                if changed_table.is_empty() { &[] } else { std::slice::from_ref(&changed_table) })?;
            match fault {
                "workspace_quota" => controller_update_columns(&before, &controlled, changed_table,
                    "workspace_id", f.receipt.source_thread_id.as_str(), &["charged_bytes"])?,
                "mixed_record" => {
                    let mut expected = terminal_original_row(&before, changed_table, "artifact_id", &f.receipt.artifact_id)?.clone();
                    expected["status"] = Value::String("deleted".to_owned());
                    for field in TERMINAL_RECORD_NULLS { expected[*field] = Value::Null; }
                    terminal_exact_one_row_change(&before, &controlled, changed_table, "artifact_id", &f.receipt.artifact_id, &expected)?;
                }
                "mixed_operation" => {
                    let mut expected = terminal_original_row(&before, changed_table, "operation_id", &f.receipt.operation_id)?.clone();
                    expected["state"] = Value::String("deleted".to_owned());
                    for field in TERMINAL_OPERATION_NULLS { expected[*field] = Value::Null; }
                    terminal_exact_one_row_change(&before, &controlled, changed_table, "operation_id", &f.receipt.operation_id, &expected)?;
                }
                _ => {}
            }
            let (pid, connection, socket) = f.original().await?;
            clear_transaction_facts(&socket);
            let observer = Arc::new(TerminalObserverFacts::default());
            let refused = f.actual.finalize_armed_explicit_saved_before_with_observer(
                &f.auth, &intent, Instant::now() + Duration::from_secs(5),
                Some(Arc::clone(&observer) as Arc<dyn ArtifactCleanupTerminalObserver>),
            ).await;
            match fault {
                "workspace_quota" => require(matches!(refused, Err(TerminalError::Corrupt { field: "workspace_quota" })),
                    "G124 strict terminal did not refuse its actual insufficient original aggregate")?,
                "mixed_record" | "mixed_operation" => require(matches!(refused, Err(TerminalError::Conflict)),
                    "G124 strict terminal coerced a legal but mixed live/completed pair")?,
                _ => require(matches!(refused, Err(TerminalError::Corrupt { field: "schema" })),
                    "G124 actual cleanup catalog drift was not a schema refusal")?,
            }
            observer.no_worker()?;
            if fault == "cleanup_schema" {
                require(socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT | ROLLBACK_BIT) == 0,
                    "G124 schema refusal ran an original terminal transaction")?;
                retired_original(f, pid, &connection, &socket).await?;
                let after_metadata = f.application.execute(f.auth.clone(), AppCommand::GetArtifactMetadata(
                    openbot_contracts::artifacts::GetArtifactMetadata { artifact_id: f.receipt.artifact_id.clone() },
                )).await.map_err(|e| e.to_string())?;
                require(schema_metadata.as_ref() == Some(&after_metadata),
                    "G124 cleanup-only schema drift changed the full original registration-bound metadata DTO")?;
                require(matches!(f.actual.observe_read_record(&f.auth, &f.receipt.artifact_id).await,
                    Err(openbot_application::ArtifactAdministrationError::Corrupt { field: "read_cleanup_schema" })),
                    "G124 actual reader schema observer did not reject the original cleanup catalog drift")?;
                require(matches!(f.application.read_current_artifact_chunk(f.auth.clone(), f.receipt.artifact_id.clone()).await,
                    Err(AppError::DependencyUnavailable { dependency: "host_request_binding" })),
                    "G124 closed-body current Host/source schema observation did not return its exact refusal")?;
            } else {
                terminal_original_ack(f, pid, &socket, false).await?;
                read_is_404(f).await?;
            }
            require(database_facts(&f.admin).await? == controlled && physical_absent(&f.path())
                && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
                "G124 refused terminal or GET repaired pair, receipt, charge, seven identities, Run32, audit or actual absence")?;
            drop(intent);
            eprintln!("ARTIFACT_TERMINAL_G124_STRICT fault={fault} original_pid={pid} controller_pid={controller_pid} controlled_legal_row_or_actual_catalog_input=true sql_guards_not_disabled=true real_original_refusal=true normal_worker_false=true original_terminal_commit_false=true original_business_rows_and_positive_receipt_kept=true get_no_repair=true");
            Ok(())
        })).await;
    }

    // Missing/mismatched positive receipts can be legally inserted in a NEW
    // namespace. A genuine current arm rejects each before it can mint an
    // ArmedIntent. This is explicit arm coverage, not fabricated terminal reach.
    for receipt_mode in [0, 2] {
        with_fixture("terminal-g124-legal-strict-receipt-input", true, |f| Box::pin(async move {
            let live = database_facts(&f.admin).await?;
            let original_object = object_fact(&f.path())?;
            let alternate = terminal_g124_alternate_namespace(f, &live, receipt_mode).await?;
            let controlled = database_facts(&f.admin).await?;
            let (pid, _, socket) = f.original().await?;
            clear_transaction_facts(&socket);
            let refused = alternate.actual.arm_explicit_saved_delete_before(&alternate.auth, &f.receipt.artifact_id,
                Instant::now() + Duration::from_secs(5)).await;
            require(matches!(refused, Err(Error::Corrupt { field: "positive_receipt" })),
                "G124 actual arm manufactured a valid intent from legal missing/mismatched receipt input")?;
            terminal_original_ack(f, pid, &socket, false).await?;
            require(database_facts(&f.admin).await? == controlled && object_fact(&f.path())? == original_object,
                "G124 strict receipt refusal repaired either namespace or original saved object")?;
            let original_receipt = terminal_original_row(&live, "openbot_internal.artifact_saved_receipts", "operation_id", &f.receipt.operation_id)?;
            let retained = controlled["openbot_internal.artifact_saved_receipts"].as_array().ok_or("G124 receipt physical facts absent")?
                .iter().any(|entry| &entry["row"] == original_receipt);
            require(retained, "G124 original append-only positive receipt was changed by alternate input")?;
            alternate.close();
            eprintln!("ARTIFACT_TERMINAL_G124_RECEIPT receipt_mode={receipt_mode} original_pid={pid} controlled_legal_new_namespace_same_ids=true original_append_only_receipt_unchanged=true real_arm_positive_receipt_refused=true arm_original_rollback_ack=true valid_terminal_intent_minted=false terminal_bad_receipt_decoder_runtime=NOT_REACHED_SQL_AND_ARM_GUARDS_RETAINED");
            Ok(())
        })).await;
    }
}

// G03/G05 use only original wire packets, owned SQL controllers and actual owner destruction.
// Observer cutpoints enlarge a controlled race; they never serve as an ACK or FD-end oracle.
fn terminal_g35_is_original_audit_fault(packet: &[u8]) -> bool {
    if packet.first() != Some(&b'E') || packet.len() < 6 {
        return false;
    }
    let declared = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
    if declared.checked_add(1) != Some(packet.len()) {
        return false;
    }
    let mut offset = 5;
    let mut code = false;
    let mut message = false;
    while offset < packet.len() && packet[offset] != 0 {
        let field = packet[offset];
        offset += 1;
        let Some(end) = packet[offset..].iter().position(|byte| *byte == 0) else {
            return false;
        };
        let value = &packet[offset..offset + end];
        if field == b'C' {
            code = value == b"P0001";
        } else if field == b'M' {
            message = value == b"owned terminal cleanup audit insert fault";
        }
        offset += end + 1;
    }
    code && message && offset + 1 == packet.len() && packet[offset] == 0
}

#[derive(Default)]
struct TerminalG35PhaseFacts {
    phases: Vec<TerminalPhase>,
    phase_times: Vec<(TerminalPhase, Instant)>,
    released: bool,
    invalid_observation: bool,
    controller_expired: bool,
    original_runtime: Option<(tokio::runtime::Handle, std::thread::ThreadId)>,
}
struct TerminalG35Gate {
    artifact_id: Uuid,
    pause: Option<TerminalPhase>,
    panic_after_original_ack: bool,
    controller_deadline: Instant,
    facts: Mutex<TerminalG35PhaseFacts>,
    changed: Condvar,
}
impl TerminalG35Gate {
    fn terminal_g35_new(
        f: &Fixture,
        pause: Option<TerminalPhase>,
        panic_after_original_ack: bool,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            artifact_id: Uuid::parse_str(&f.receipt.artifact_id).map_err(|e| e.to_string())?,
            pause,
            panic_after_original_ack,
            // This bounds a test callback's cleanup only; it never changes the producer's five seconds.
            controller_deadline: Instant::now() + Duration::from_secs(9),
            facts: Mutex::new(TerminalG35PhaseFacts::default()),
            changed: Condvar::new(),
        }))
    }
    fn terminal_g35_saw(&self, phase: TerminalPhase) -> bool {
        self.facts
            .lock()
            .is_ok_and(|facts| facts.phases.contains(&phase))
    }
    fn terminal_g35_release(&self) {
        let mut facts = self.facts.lock().unwrap_or_else(|error| error.into_inner());
        facts.released = true;
        self.changed.notify_all();
    }
    fn terminal_g35_check(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "terminal G35 observation poisoned")?;
        require(
            !facts.invalid_observation && !facts.controller_expired,
            "terminal G35 observer saw a foreign artifact/leaf FD or its cleanup controller expired",
        )
    }
    fn terminal_g35_no_worker(&self) -> Result<(), String> {
        self.terminal_g35_check()?;
        require(
            self.facts
                .lock()
                .map_err(|_| "terminal G35 observation poisoned")?
                .phases
                .is_empty(),
            "terminal G35 preworker refusal reserved a worker or claimed resource end",
        )
    }
    fn terminal_g35_runtime(
        &self,
    ) -> Result<(tokio::runtime::Handle, std::thread::ThreadId), String> {
        self.facts
            .lock()
            .map_err(|_| "terminal G35 runtime observation poisoned")?
            .original_runtime
            .clone()
            .ok_or_else(|| "terminal G35 original BeforeCommit runtime not reached".to_owned())
    }
}
impl ArtifactCleanupTerminalObserver for TerminalG35Gate {
    fn on_phase(&self, phase: TerminalPhase, artifact_id: Uuid, original_leaf_fd: Option<i32>) {
        let mut facts = self
            .facts
            .lock()
            .expect("terminal G35 original observations");
        facts.invalid_observation |= artifact_id != self.artifact_id || original_leaf_fd.is_some();
        facts.phases.push(phase);
        facts.phase_times.push((phase, Instant::now()));
        if phase == TerminalPhase::BeforeCommit {
            facts.original_runtime = Some((
                tokio::runtime::Handle::current(),
                std::thread::current().id(),
            ));
        }
        self.changed.notify_all();
        drop(facts);
        if self.panic_after_original_ack && phase == TerminalPhase::AfterCommitAckBeforeWorkerEnd {
            // Actual panic destroys the independently owned main supervisor. It does not abort the caller.
            panic!("owned terminal G35 original post-ACK main observer panic");
        }
        if self.pause == Some(phase) {
            // Only the existing multi-thread post-ACK pause legs enter this branch. Let
            // that executor hand off its core while this same synchronous callback waits;
            // the dedicated current-thread late-poll leg has pause=None and never enters.
            tokio::task::block_in_place(|| {
                let mut facts = self
                    .facts
                    .lock()
                    .expect("terminal G35 original phase controller");
                while !facts.released {
                    let Some(wait) = self
                        .controller_deadline
                        .checked_duration_since(Instant::now())
                    else {
                        facts.controller_expired = true;
                        break;
                    };
                    let (next, _) = self
                        .changed
                        .wait_timeout(facts, wait)
                        .expect("terminal G35 original phase controller");
                    facts = next;
                }
            });
        }
    }
}
struct TerminalG35Release(Arc<TerminalG35Gate>);
impl Drop for TerminalG35Release {
    fn drop(&mut self) {
        self.0.terminal_g35_release();
    }
}
async fn terminal_g35_wait_phase(
    gate: &TerminalG35Gate,
    phase: TerminalPhase,
    deadline: Instant,
) -> Result<(), String> {
    wait_fact(
        || gate.terminal_g35_saw(phase),
        deadline,
        "terminal G35 actual original phase did not occur before its controlled deadline",
    )
    .await?;
    require(
        Instant::now() < deadline,
        "terminal G35 controller observed the original phase only after its controlled deadline",
    )
}
fn terminal_g35_log_controller(
    gate: &TerminalG35Gate,
    pid: i32,
    socket: &SocketFacts,
    phase: TerminalPhase,
    started: Instant,
    deadline: Instant,
    label: &'static str,
) -> Result<(), String> {
    let phase_at = gate
        .facts
        .lock()
        .map_err(|_| "terminal G35 controller observation poisoned")?
        .phase_times
        .iter()
        .find_map(|(observed, at)| (*observed == phase).then_some(*at));
    let now = Instant::now();
    eprintln!(
        "ARTIFACT_TERMINAL_G35_CONTROLLER label={label} original_pid={pid} actual_socket_pid={} entered={} server_ack={} forwarded_ack={} withheld={} release_request={} original_eof={} phase={phase:?} phase_at={phase_at:?} phase_elapsed_us={:?} controller_elapsed_us={} original_budget_remaining_us={:?}",
        socket.pid.load(Ordering::SeqCst),
        socket.entered.load(Ordering::SeqCst),
        socket.server_ack.load(Ordering::SeqCst),
        socket.forwarded_ack.load(Ordering::SeqCst),
        socket.withheld.load(Ordering::SeqCst),
        socket.release_original_ack.load(Ordering::SeqCst),
        socket.frontend_eof.load(Ordering::SeqCst),
        phase_at
            .and_then(|at| at.checked_duration_since(started))
            .map(|elapsed| elapsed.as_micros()),
        now.saturating_duration_since(started).as_micros(),
        deadline
            .checked_duration_since(now)
            .map(|remaining| remaining.as_micros()),
    );
    Ok(())
}
async fn terminal_g35_worker_resources_ended(
    gate: &TerminalG35Gate,
    original_leaf: &ObjectFact,
) -> Result<(), String> {
    terminal_g35_wait_phase(
        gate,
        TerminalPhase::WorkerEnded,
        Instant::now() + Duration::from_secs(2),
    )
    .await?;
    // Actual process-scoped inode FD enumeration complements the producer's reviewed IO-first scope.
    require(
        physical_inode_fds(original_leaf)?.is_empty(),
        "terminal G35 original leaf inode retained a real descriptor after worker resource end",
    )?;
    gate.terminal_g35_check()
}
async fn terminal_g35_original_normal_ack(
    f: &Fixture,
    pid: i32,
    socket: &SocketFacts,
    commit: bool,
    original_hold: Option<Hold>,
) -> Result<(), String> {
    let bit = if commit { COMMIT_BIT } else { ROLLBACK_BIT };
    require(
        socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | bit) == (BEGIN_BIT | bit)
            && socket.withheld.load(Ordering::SeqCst) == original_hold.map_or(0, |hold| hold as u8)
            && socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
        "terminal G35 normal disposition lacked its same true original unmodified packets",
    )?;
    if !commit {
        require(
            socket.entered.load(Ordering::SeqCst) & COMMIT_BIT == 0,
            "terminal G35 known refused transaction actually entered COMMIT",
        )?;
    }
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    require(
        client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get::<_, i32>(0)
            == pid,
        "terminal G35 normal original disposition did not leave the actual original connection reusable",
    )
}
async fn terminal_g35_fresh_valid_auth(f: &Fixture) -> Result<AuthContext, String> {
    let fresh = resolve(f.resolver.as_ref(), COOKIE_B).await?;
    require(
        fresh == f.auth
            && !fresh
                .request_binding()
                .ok_or("terminal G35 fresh original Session binding missing")?
                .identity()
                .same_binding(
                    f.auth
                        .request_binding()
                        .ok_or("terminal G35 old original Session binding missing")?
                        .identity(),
                ),
        "terminal G35 retry did not use a new genuine Session with the same saving owner",
    )?;
    fresh
        .request_binding()
        .ok_or("terminal G35 fresh original Session binding missing")?
        .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|e| format!("terminal G35 independent genuine Session validity: {e:?}"))?;
    Ok(fresh)
}
async fn terminal_g35_poison_refuses_without_mutation(
    f: &Fixture,
    intent: &ArmedArtifactCleanupIntent,
    original_effects: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let fresh = terminal_g35_fresh_valid_auth(f).await?;
    let after_auth = database_facts(&f.admin).await?;
    physical_session_b_idle_only(original_effects, &after_auth)?;
    let observer = Arc::new(TerminalObserverFacts::default());
    require(
        matches!(
            f.actual
                .finalize_armed_explicit_saved_before_with_observer(
                    &fresh,
                    intent,
                    Instant::now() + Duration::from_secs(2),
                    Some(observer.clone())
                )
                .await,
            Err(TerminalError::ReadsUnproven)
        ),
        "terminal G35 same live Store/key permanent uncertainty was cleared by new valid Session or completed DB rows",
    )?;
    observer.no_worker()?;
    require(
        database_facts(&f.admin).await? == after_auth,
        "terminal G35 permanently unproved retry wrote a row, repeated a refund or appended another audit",
    )
}
async fn terminal_g35_wait_true_held_commit(
    socket: &SocketFacts,
    deadline: Instant,
) -> Result<(), String> {
    wait_fact(
        || socket.withheld.load(Ordering::SeqCst) == Hold::Commit as u8,
        deadline,
        "terminal G35 actual original COMMIT CommandComplete was not held",
    )
    .await?;
    require(
        socket.entered.load(Ordering::SeqCst) & COMMIT_BIT != 0
            && socket.server_ack.load(Ordering::SeqCst) & COMMIT_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & COMMIT_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
        "terminal G35 held disposition lacked a true upstream original COMMIT or had already been forwarded",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires true original quota/audit waits, owned current Session/deny controllers and real rollback ACK"]
async fn actual_terminal_current_host_loss_after_quota_and_audit_wait_rolls_back() {
    for wait in ["quota", "audit"] {
        for mutation in [
            "session_deleted",
            "session_epoch",
            "session_generation",
            "deny",
        ] {
            with_fixture("terminal-g35-current-after-real-wait", true, |f| Box::pin(async move {
                let leaf = object_fact(&f.path())?;
                let intent = Arc::new(terminal_prepare(f).await?);
                let before = database_facts(&f.admin).await?;
                let (pid, _, socket) = f.original().await?;
                clear_transaction_facts(&socket);
                let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
                let tx = controller.transaction().await.map_err(|e| e.to_string())?;
                let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
                let fragment = if wait == "quota" {
                    tx.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",
                        &[&f.receipt.source_thread_id.as_str()]).await.map_err(|e| e.to_string())?;
                    "artifact_workspace_quotas"
                } else {
                    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_LOCK]).await.map_err(|e| e.to_string())?;
                    "pg_advisory_xact_lock"
                };
                let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
                let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
                let started = Instant::now();
                let task = tokio::spawn(async move {
                    actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                        started + Duration::from_secs(5), Some(original_observer)).await
                });
                let controlled = async {
                    wait_blocked(&f.admin, pid, fragment, controller_pid).await?;
                    // The actor/role rows are already locked by the original producer. These
                    // independently writable original Session/deny rows require no bypass of them.
                    let changed = match mutation {
                        "session_deleted" => tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await,
                        "session_epoch" => tx.execute("UPDATE public.sessions SET token='owned-terminal-g35-replaced-session-epoch' WHERE id=$1", &[&A_ID]).await,
                        "session_generation" => tx.execute("UPDATE public.sessions SET auth_generation=1 WHERE id=$1", &[&A_ID]).await,
                        _ => tx.execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES('cleanup-owner@example.test','owned-terminal-g35-controller')", &[]).await,
                    }.map_err(|e| e.to_string())?;
                    require(changed == 1, "terminal G35 current controller did not change its unique owned original row")
                }.await;
                let controller_ack = tx.commit().await.map_err(|e| e.to_string());
                drop(controller);
                let outcome = task.await.map_err(|e| e.to_string())?;
                controlled?; controller_ack?;
                require(started.elapsed() < Duration::from_secs(5)
                    && matches!(outcome, Err(TerminalError::NotVisible) | Err(TerminalError::Host(HostRequestBindingError::NotCurrent))),
                    "terminal G35 quota/audit wait reused stale permitted Host or relabelled explicit refusal as infrastructure uncertainty")?;
                terminal_g35_original_normal_ack(f, pid, &socket, false, None).await?;
                if wait == "quota" {
                    observer.terminal_g35_no_worker()?;
                } else {
                    require(observer.terminal_g35_saw(TerminalPhase::AbsenceGuarded)
                        && !observer.terminal_g35_saw(TerminalPhase::BeforeCommit)
                        && !observer.terminal_g35_saw(TerminalPhase::AfterCommitAckBeforeWorkerEnd),
                        "terminal G35 audit wait did not retain its actual guarded worker or reached COMMIT despite current refusal")?;
                    terminal_g35_worker_resources_ended(&observer, &leaf).await?;
                }
                let after = database_facts(&f.admin).await?;
                let table = if mutation == "deny" { "public.revoked_access" } else { "public.sessions" };
                only_tables_changed(&before, &after, &[table])?;
                match mutation {
                    "session_deleted" => controller_removed_row(&before, &after, table, "id", A_ID)?,
                    "session_epoch" => controller_update_columns(&before, &after, table, "id", A_ID, &["token"])?,
                    "session_generation" => controller_update_columns(&before, &after, table, "id", A_ID, &["auth_generation"])?,
                    _ => controller_inserted_row(&before, &after, table, "email", "cleanup-owner@example.test")?,
                }
                require(physical_absent(&f.path())
                    && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id))
                    && physical_inode_fds(&leaf)?.is_empty(),
                    "terminal G35 current refusal recreated a saved body/staging name or retained original leaf FD")?;
                eprintln!("ARTIFACT_TERMINAL_G03_CURRENT wait={wait} mutation={mutation} original_pid={pid} controller_pid={controller_pid} actual_pg_blocking_pid=true controller_commit_ack=true original_rollback_ack=true producer_business_and_physical_rows_unchanged=true original_charge_kept=true actor_role_locks_not_bypassed=true");
                drop(intent);
                Ok(())
            })).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires reached true cleanup_completed INSERT fault, genuine P0001 wire response and original rollback"]
async fn actual_terminal_reached_audit_insert_fault_rolls_back_original_mutations() {
    with_fixture("terminal-g35-actual-audit-insert-fault", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        require(!socket.terminal_g35_audit_fault_p0001.load(Ordering::SeqCst)
            && !socket.terminal_g35_audit_fault_error_forwarded.load(Ordering::SeqCst),
            "terminal G35 audit fault evidence existed before actual terminal entry")?;
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.arm(Hold::Begin);
        let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                started + Duration::from_secs(5), Some(original_observer)).await
        });
        wait_fact(|| socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8,
            started + Duration::from_secs(2), "terminal G35 audit fault did not hold the true original post-schema BEGIN ACK").await?;
        require(socket.entered.load(Ordering::SeqCst) & BEGIN_BIT != 0
            && socket.server_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & BEGIN_BIT == 0,
            "terminal G35 fault was installed before original schema validation or after its delivered BEGIN")?;
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("CREATE SEQUENCE public.terminal_g35_audit_fault_seen; CREATE FUNCTION public.terminal_g35_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='artifact.cleanup_completed' THEN PERFORM nextval('public.terminal_g35_audit_fault_seen'); RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='owned terminal cleanup audit insert fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER terminal_g35_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.terminal_g35_audit_fault();")
            .await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        drop(controller);
        require(database_facts(&f.admin).await? == before,
            "terminal G35 owned fault instrumentation changed a business row")?;
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.release_original_ack(&socket, Hold::Begin)?;
        let result = task.await.map_err(|e| e.to_string())?;
        require(started.elapsed() < Duration::from_secs(5) && matches!(result, Err(TerminalError::Unavailable)),
            "terminal G35 reached actual audit fault was accepted or misreported as a schema refusal")?;
        terminal_g35_original_normal_ack(f, pid, &socket, false, Some(Hold::Begin)).await?;
        require(socket.terminal_g35_audit_fault_p0001.load(Ordering::SeqCst)
            && socket.terminal_g35_audit_fault_error_forwarded.load(Ordering::SeqCst),
            "terminal G35 audit INSERT fault had no actual original P0001/ErrorResponse or it was not forwarded unchanged")?;
        let controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let seen = controller.query_one("SELECT last_value,is_called FROM public.terminal_g35_audit_fault_seen", &[])
            .await.map_err(|e| e.to_string())?;
        require(seen.get::<_, i64>(0) == 1 && seen.get::<_, bool>(1),
            "terminal G35 audit fault was inferred from its trigger name instead of a reached real INSERT")?;
        require(observer.terminal_g35_saw(TerminalPhase::AbsenceGuarded)
            && !observer.terminal_g35_saw(TerminalPhase::BeforeCommit)
            && !observer.terminal_g35_saw(TerminalPhase::AfterCommitAckBeforeWorkerEnd),
            "terminal G35 fault failed before its guarded worker or got as far as terminal COMMIT")?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        require(database_facts(&f.admin).await? == before && physical_absent(&f.path())
            && physical_absent(&f.root.0.join("staging").join(&f.receipt.artifact_id)),
            "terminal G35 true original rollback did not restore all record/operation/fence/quota/audit physical rows")?;
        controller.batch_execute("DROP TRIGGER terminal_g35_audit_fault ON public.audit_events; DROP FUNCTION public.terminal_g35_audit_fault(); DROP SEQUENCE public.terminal_g35_audit_fault_seen;")
            .await.map_err(|e| e.to_string())?;
        drop(controller);
        require(database_facts(&f.admin).await? == before,
            "terminal G35 owned fault teardown changed original business facts")?;
        eprintln!("ARTIFACT_TERMINAL_G03_AUDIT_FAULT original_pid={pid} schema_passed_before_actual_begin=true controller_install_commit_ack=true genuine_cleanup_completed_insert_sequence1=true original_errorresponse_p0001_forwarded=true original_rollback_ack=true all_original_business_physical_rows_restored=true no_refund_or_audit_committed=true");
        drop(intent);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires actual durable COMMIT with lost original ACK, real driver/EOF/backend closure and new valid Session"]
async fn actual_terminal_commit_ack_loss_preserves_effects_and_refuses_completed_retry() {
    with_fixture("terminal-g35-original-commit-ack-loss", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.arm(Hold::Commit);
        let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                started + Duration::from_secs(5), Some(original_observer)).await
        });
        terminal_g35_wait_true_held_commit(&socket, started + Duration::from_secs(2)).await?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        let result = task.await.map_err(|e| e.to_string())?;
        require(matches!(result, Err(TerminalError::CommitUnknown) | Err(TerminalError::DeadlineExpired)),
            "terminal G35 lost true original COMMIT ACK produced a normal result or a known normal ACK")?;
        original_five_seconds(started)?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        require(!observer.terminal_g35_saw(TerminalPhase::AfterCommitAckBeforeWorkerEnd)
            && socket.forwarded_ack.load(Ordering::SeqCst) & COMMIT_BIT == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0,
            "terminal G35 lost original ACK was manufactured by observer, trace or cleanup")?;
        retired_original(f, pid, &connection, &socket).await?;
        require(database_facts(&f.admin).await? == committed && physical_absent(&f.path()),
            "terminal G35 unknown original disposition erased true already committed rows/refund/audit")?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &committed).await?;
        eprintln!("ARTIFACT_TERMINAL_G05_LOST_ACK original_pid={pid} actual_audit_event_id={event_id} durable_original_commit_effects=true original_upstream_commit_ack=true forwarded_original_ack=false original_budget5s=true actual_worker_resources_ended=true original_driver_destroyed_eof_backend_gone=true new_valid_session_same_store_permanent_unproven=true repeat_refund_audit=false normal_result=false");
        drop(intent);
        Ok(())
    })).await;
}

struct TerminalG35RuntimeBlock {
    thread: std::thread::ThreadId,
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}
impl TerminalG35RuntimeBlock {
    fn terminal_g35_block_here(&self) {
        assert_eq!(
            std::thread::current().id(),
            self.thread,
            "terminal G35 controlled task did not run on the original single supervisor thread"
        );
        let mut released = self.released.lock().expect("terminal G35 runtime control");
        self.entered.store(true, Ordering::SeqCst);
        let cleanup_deadline = Instant::now() + Duration::from_secs(8);
        while !*released {
            let Some(wait) = cleanup_deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            released = self
                .changed
                .wait_timeout(released, wait)
                .expect("terminal G35 runtime control")
                .0;
        }
    }
    fn terminal_g35_release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = true;
        self.changed.notify_all();
    }
}
struct TerminalG35RuntimeRelease(Arc<TerminalG35RuntimeBlock>);
impl Drop for TerminalG35RuntimeRelease {
    fn drop(&mut self) {
        self.0.terminal_g35_release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real original COMMIT packets, parent-runtime driver and a controlled original supervisor thread stall"]
async fn actual_terminal_commit_ack_held_then_late_never_becomes_grant() {
    with_fixture("terminal-g35-original-commit-late-poll", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        // Checkout occurs in THIS parent runtime. The same original driver and relay remain here.
        let (pid, connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.arm(Hold::Commit);
        let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let original_connection = connection.clone();
        let started = Instant::now();
        let original_deadline = started + Duration::from_secs(5);
        let thread = std::thread::spawn(move || -> Result<Result<TerminalState, TerminalError>, String> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
            runtime.block_on(async move {
                let result = actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                    original_deadline, Some(original_observer)).await.map(|observation| observation.state());
                // Keep this exact runtime alive until the real original query owner/driver ends.
                // Returning from the public wait alone must not manufacture supervisor Drop.
                let destruction = original_connection.wait_for_destruction_before(Instant::now() + Duration::from_secs(2))
                    .await.map_err(|e| e.to_string())?;
                require(destruction == ConnectionDestruction::ConnectionDestroyed,
                    "terminal G35 late-poll runtime ended without actual original driver destruction")?;
                Ok(result)
            })
        });
        let controlled = async {
            terminal_g35_wait_true_held_commit(&socket, started + Duration::from_secs(2)).await?;
            let committed = database_facts(&f.admin).await?;
            let event_id = terminal_verify_once(f, &before, &committed)?;
            let (runtime, runtime_thread) = observer.terminal_g35_runtime()?;
            let blocker = Arc::new(TerminalG35RuntimeBlock {
                thread: runtime_thread, entered: AtomicBool::new(false), released: Mutex::new(false), changed: Condvar::new(),
            });
            let release = TerminalG35RuntimeRelease(blocker.clone());
            let actual_blocker = blocker.clone();
            let blocking_task = runtime.spawn(async move { actual_blocker.terminal_g35_block_here(); });
            wait_fact(|| blocker.entered.load(Ordering::SeqCst), started + Duration::from_secs(3),
                "terminal G35 original supervisor thread never entered its post-COMMIT controlled stall").await?;
            require(Instant::now() < original_deadline,
                "terminal G35 controlled stall or ACK release started after original budget already expired")?;
            f.relay.as_ref().ok_or("terminal G35 original relay missing")?.release_original_ack(&socket, Hold::Commit)?;
            wait_fact(|| socket.forwarded_ack.load(Ordering::SeqCst) & COMMIT_BIT != 0
                && socket.release_original_ack.load(Ordering::SeqCst) == 0,
                original_deadline, "terminal G35 same original C/Ready packets did not actually write before deadline").await?;
            require(!socket.frontend_eof.load(Ordering::SeqCst),
                "terminal G35 original driver retired before its actual on-time unmodified packet forwarding")?;
            tokio::time::sleep_until(tokio::time::Instant::from_std(original_deadline + Duration::from_millis(100))).await;
            // Only this original supervisor thread resumes late. The parent driver was never blocked.
            drop(release);
            blocking_task.await.map_err(|e| e.to_string())?;
            Ok::<_, String>((committed, event_id))
        }.await;
        let result = tokio::task::spawn_blocking(move || thread.join())
            .await.map_err(|e| e.to_string())?.map_err(|_| "terminal G35 original runtime thread panicked")??;
        let (committed, event_id) = controlled?;
        require(matches!(result, Err(TerminalError::DeadlineExpired) | Err(TerminalError::CommitAcknowledgedAfterDeadline)),
            "terminal G35 late original supervisor polling minted a normal terminal grant")?;
        original_five_seconds(started)?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        require(!observer.terminal_g35_saw(TerminalPhase::AfterCommitAckBeforeWorkerEnd),
            "terminal G35 late acknowledgement was registered as a normal committed fact/grant")?;
        retired_original(f, pid, &connection, &socket).await?;
        require(database_facts(&f.admin).await? == committed,
            "terminal G35 late polling changed true original committed terminal effects")?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &committed).await?;
        // The public caller checks its absolute clock before forwarding an inner error. Its
        // DeadlineExpired does not expose Pool's private late disposition. The locked Tokio
        // Timeout polls the ready original future first; that inner classification stays a
        // reviewed Source inference, not a runtime ACK enum assertion or a manufactured getter.
        eprintln!("ARTIFACT_TERMINAL_G05_LATE_POLL original_pid={pid} actual_audit_event_id={event_id} actual_original_commit=true original_packets_forwarded_before_deadline=true original_supervisor_thread_really_blocked_after_commit=true original_thread_resumed_after5s=true public_result={result:?} pool_private_late_classification=SOURCE_INFERENCE_ONLY actual_original_driver_destroyed_eof_backend_gone=true same_store_permanent_unproven=true normal_result=false repeat_refund_audit=false");
        drop(intent);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires caller-only abort and separate actual main-runtime Drop/post-normal-ACK panic"]
async fn actual_terminal_waiter_cancel_keeps_supervisor_but_main_loss_is_unproven() {
    with_fixture("terminal-g35-caller-only-post-started-cancel", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.arm(Hold::Commit);
        let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                started + Duration::from_secs(5), Some(original_observer)).await
        });
        terminal_g35_wait_true_held_commit(&socket, started + Duration::from_secs(2)).await?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        task.abort();
        let cancelled = task.await;
        require(cancelled.is_err_and(|e| e.is_cancelled()),
            "terminal G35 public waiter was not actually cancelled and reaped")?;
        f.relay.as_ref().ok_or("terminal G35 original relay missing")?.release_original_ack(&socket, Hold::Commit)?;
        terminal_g35_wait_phase(&observer, TerminalPhase::AfterCommitAckBeforeWorkerEnd, started + Duration::from_secs(5)).await?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        terminal_g35_original_normal_ack(f, pid, &socket, true, Some(Hold::Commit)).await?;
        require(started.elapsed() < Duration::from_secs(5) && database_facts(&f.admin).await? == committed,
            "terminal G35 caller-only cancellation undid a started COMMIT or poisoned an on-time original acknowledgement")?;
        clear_transaction_facts(&socket);
        let retry_observer = Arc::new(TerminalObserverFacts::default());
        let retry = f.actual.finalize_armed_explicit_saved_before_with_observer(&f.auth, &intent,
            Instant::now() + Duration::from_secs(2), Some(retry_observer.clone())).await.map_err(|e| format!("{e:?}"))?;
        require(retry.state() == TerminalState::AlreadyCompleted,
            "terminal G35 retained supervisor did not preserve original exact audit fact after caller-only cancel")?;
        terminal_g35_original_normal_ack(f, pid, &socket, false, None).await?;
        retry_observer.no_worker()?;
        require(database_facts(&f.admin).await? == committed,
            "terminal G35 completed retry after caller cancel changed rows/refund/audit")?;
        drop(retry); drop(intent);
        eprintln!("ARTIFACT_TERMINAL_G05_CALLER_CANCEL original_pid={pid} actual_audit_event_id={event_id} actual_public_waiter_aborted_reaped=true original_commit_already_started=true independently_owned_main_retained=true original_on_time_commit_ack=true actual_worker_resources_ended=true exact_audit_fact_completed_retry=true completed_own_rollback_ack=true repeat_refund_audit=false");
        Ok(())
    })).await;
    with_fixture("terminal-g35-real-main-runtime-drop", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        physical_connection_check_interval(f).await?;
        let (pid, connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let mut controller = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = controller.transaction().await.map_err(|e| e.to_string())?;
        let controller_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        tx.batch_execute("LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|e| e.to_string())?;
        let observer = TerminalG35Gate::terminal_g35_new(f, None, false)?;
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let original = runtime.spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                Instant::now() + Duration::from_secs(5), Some(original_observer)).await
        });
        let controlled = physical_schema_wait(f, pid, controller_pid).await;
        // The actual independently owned main supervisor lives in this owned runtime.
        tokio::task::spawn_blocking(move || drop(runtime)).await.map_err(|e| e.to_string())?;
        let cancelled = original.await;
        let controller_ack = tx.rollback().await.map_err(|e| e.to_string());
        drop(controller);
        controlled?; controller_ack?;
        require(cancelled.is_err_and(|e| e.is_cancelled()),
            "terminal G35 main-runtime Drop did not actually destroy and reap the original task")?;
        observer.terminal_g35_no_worker()?;
        retired_original(f, pid, &connection, &socket).await?;
        require(socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT | ROLLBACK_BIT) == 0
            && socket.forwarded_ack.load(Ordering::SeqCst) & (COMMIT_BIT | ROLLBACK_BIT) == 0
            && physical_inode_fds(&leaf)?.is_empty()
            && database_facts(&f.admin).await? == before,
            "terminal G35 real main loss fabricated an original ACK/end or changed original business rows")?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &before).await?;
        eprintln!("ARTIFACT_TERMINAL_G05_MAIN_RUNTIME_DROP original_pid={pid} controller_pid={controller_pid} actual_original_schema_wait=true owned_main_runtime_dropped=true original_task_cancelled_reaped=true original_query_ack=false original_driver_destroyed_eof_backend_gone=true original_worker_not_reserved=true new_valid_session_permanent_unproven=true original_business_physical_rows_unchanged=true");
        drop(intent);
        Ok(())
    })).await;
    with_fixture("terminal-g35-real-main-post-normal-ack-panic", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = terminal_prepare(f).await?;
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let observer = TerminalG35Gate::terminal_g35_new(f, None, true)?;
        let result = f.actual.finalize_armed_explicit_saved_before_with_observer(&f.auth, &intent,
            Instant::now() + Duration::from_secs(5), Some(observer.clone())).await;
        require(matches!(result, Err(TerminalError::ReadsUnproven)),
            "terminal G35 actual main observer panic after true ACK returned a normal terminal result")?;
        require(observer.terminal_g35_saw(TerminalPhase::AfterCommitAckBeforeWorkerEnd),
            "terminal G35 main panic occurred before actual original normal ACK/fact registration")?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        // The normal original COMMIT was already known; do not require or invent its retirement.
        terminal_g35_original_normal_ack(f, pid, &socket, true, None).await?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &committed).await?;
        eprintln!("ARTIFACT_TERMINAL_G05_POST_ACK_MAIN_PANIC original_pid={pid} actual_audit_event_id={event_id} real_owned_supervisor_observer_panicked=true original_normal_commit_ack_preserved=true true_original_committed_effects_kept=true real_worker_resources_ended=true normal_original_driver_reusable=true new_valid_session_same_store_permanent_unproven=true second_refund_audit=false caller_abort_used=false");
        drop(intent);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires actual on-time original ACK/fact then genuine Host owner closure or original clock loss"]
async fn actual_terminal_on_time_ack_then_host_or_tail_loss_keeps_fact_and_effects() {
    with_fixture("terminal-g35-post-ack-known-host-loss", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let observer = TerminalG35Gate::terminal_g35_new(f, Some(TerminalPhase::AfterCommitAckBeforeWorkerEnd), false)?;
        let release = TerminalG35Release(observer.clone());
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                started + Duration::from_secs(5), Some(original_observer)).await
        });
        let phase_wait = terminal_g35_wait_phase(&observer, TerminalPhase::AfterCommitAckBeforeWorkerEnd, started + Duration::from_secs(2)).await;
        terminal_g35_log_controller(&observer, pid, &socket, TerminalPhase::AfterCommitAckBeforeWorkerEnd,
            started, started + Duration::from_secs(5), "known_host_loss")?;
        phase_wait?;
        require(socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
            "terminal G35 known Host loss preceded actual normal original COMMIT ACK")?;
        require(Instant::now() < started + Duration::from_secs(5),
            "terminal G35 known Host loss controller reached its cutpoint after the original five seconds")?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        f.resolver.close_request_bindings();
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        require(matches!(result, Err(TerminalError::Host(HostRequestBindingError::NotCurrent))),
            "terminal G35 true normal ACK then actual owner closure produced a grant or was relabelled CommitUnknown")?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        terminal_g35_original_normal_ack(f, pid, &socket, true, None).await?;
        require(database_facts(&f.admin).await? == committed,
            "terminal G35 known post-ACK Host refusal changed actual terminal effects")?;
        let fresh_resolver = PostgresSessionAuthResolver::new(f.pool.clone(), SESSION_KEY, default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT), TenantId::new(TENANT)).map_err(|e| e.to_string())?;
        fresh_resolver.install_artifact_read_authority(&f.actual.read_authority())
            .map_err(|_| "terminal G35 fresh genuine owner authority enrollment failed")?;
        let recovery = async {
            let fresh = resolve(&fresh_resolver, COOKIE_B).await?;
            require(fresh == f.auth
                && !fresh.request_binding().ok_or("terminal G35 fresh owner binding missing")?.identity()
                    .same_binding(f.auth.request_binding().ok_or("terminal G35 old owner binding missing")?.identity()),
                "terminal G35 recovery did not change the actual closed owner/session")?;
            fresh.request_binding().ok_or("terminal G35 fresh owner binding missing")?
                .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?;
            let after_auth = database_facts(&f.admin).await?;
            physical_session_b_idle_only(&committed, &after_auth)?;
            clear_transaction_facts(&socket);
            let retry_observer = Arc::new(TerminalObserverFacts::default());
            let retry = f.actual.finalize_armed_explicit_saved_before_with_observer(&fresh, &intent,
                Instant::now() + Duration::from_secs(2), Some(retry_observer.clone())).await.map_err(|e| format!("{e:?}"))?;
            require(retry.state() == TerminalState::AlreadyCompleted,
                "terminal G35 exact committed audit fact was lost or known Host rejection poisoned the original key")?;
            terminal_g35_original_normal_ack(f, pid, &socket, false, None).await?;
            retry_observer.no_worker()?;
            require(database_facts(&f.admin).await? == after_auth,
                "terminal G35 completed retry after known Host refusal changed any business physical row/refund/audit")?;
            drop(retry);
            Ok::<_, String>(())
        }.await;
        fresh_resolver.close_request_bindings();
        recovery?;
        eprintln!("ARTIFACT_TERMINAL_G05_KNOWN_POST_ACK_HOST_LOSS original_pid={pid} actual_audit_event_id={event_id} real_original_normal_commit_ack_then_host_owner_closed=true known_commit_not_relabelled_unknown=true true_effects_and_exact_audit_fact_preserved=true actual_worker_resources_ended=true new_valid_owner_same_store_completed=true completed_own_rollback_ack_no_worker=true repeat_refund_audit=false");
        drop(intent);
        Ok(())
    })).await;
    with_fixture("terminal-g35-post-ack-original-clock-loss", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, connection, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let observer = TerminalG35Gate::terminal_g35_new(f, Some(TerminalPhase::AfterCommitAckBeforeWorkerEnd), false)?;
        let release = TerminalG35Release(observer.clone());
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let original_deadline = started + Duration::from_secs(5);
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                original_deadline, Some(original_observer)).await
        });
        let phase_wait = terminal_g35_wait_phase(&observer, TerminalPhase::AfterCommitAckBeforeWorkerEnd, started + Duration::from_secs(2)).await;
        terminal_g35_log_controller(&observer, pid, &socket, TerminalPhase::AfterCommitAckBeforeWorkerEnd,
            started, original_deadline, "original_clock_loss")?;
        phase_wait?;
        require(socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
            "terminal G35 clock-loss leg lacked actual normal on-time ACK before the controlled clock wait")?;
        require(Instant::now() < original_deadline,
            "terminal G35 clock-loss controller reached its ACK cutpoint after the original five seconds")?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        tokio::time::sleep_until(tokio::time::Instant::from_std(original_deadline + Duration::from_millis(75))).await;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        require(matches!(result, Err(TerminalError::DeadlineExpired)),
            "terminal G35 post-normal-ACK clock loss yielded a grant or changed real acknowledged truth to CommitUnknown")?;
        original_five_seconds(started)?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        retired_original(f, pid, &connection, &socket).await?;
        require(database_facts(&f.admin).await? == committed
            && socket.forwarded_ack.load(Ordering::SeqCst) & COMMIT_BIT != 0
            && socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT == 0,
            "terminal G35 post-ACK late cleanup erased real original ACK/committed rows or manufactured rollback")?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &committed).await?;
        eprintln!("ARTIFACT_TERMINAL_G05_KNOWN_POST_ACK_CLOCK_LOSS original_pid={pid} actual_audit_event_id={event_id} real_normal_original_ack_fact_before5s=true actual_original_clock_exhausted=true acknowledged_truth_not_unknown=true true_effects_kept=true original_driver_destroyed_eof_backend_gone=true real_worker_resources_ended=true new_valid_session_permanent_unproven=true second_refund_audit=false normal_result=false");
        drop(intent);
        Ok(())
    })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires same original IO guard through true COMMIT ACK then controlled actual child inode drift"]
async fn actual_terminal_original_guard_final_root_drift_refuses_without_ack_relabelling() {
    with_fixture("terminal-g35-post-ack-final-original-root-child-drift", true, |f| Box::pin(async move {
        let leaf = object_fact(&f.path())?;
        let intent = Arc::new(terminal_prepare(f).await?);
        let before = database_facts(&f.admin).await?;
        let (pid, _, socket) = f.original().await?;
        clear_transaction_facts(&socket);
        let observer = TerminalG35Gate::terminal_g35_new(f, Some(TerminalPhase::AfterCommitAckBeforeWorkerEnd), false)?;
        let release = TerminalG35Release(observer.clone());
        let actual = f.actual.clone(); let auth = f.auth.clone(); let original_intent = intent.clone(); let original_observer = observer.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            actual.finalize_armed_explicit_saved_before_with_observer(&auth, &original_intent,
                started + Duration::from_secs(5), Some(original_observer)).await
        });
        let phase_wait = terminal_g35_wait_phase(&observer, TerminalPhase::AfterCommitAckBeforeWorkerEnd, started + Duration::from_secs(2)).await;
        terminal_g35_log_controller(&observer, pid, &socket, TerminalPhase::AfterCommitAckBeforeWorkerEnd,
            started, started + Duration::from_secs(5), "final_original_child_drift")?;
        phase_wait?;
        require(socket.pid.load(Ordering::SeqCst) == pid
            && socket.entered.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.server_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.forwarded_ack.load(Ordering::SeqCst) & (BEGIN_BIT | COMMIT_BIT) == (BEGIN_BIT | COMMIT_BIT)
            && socket.withheld.load(Ordering::SeqCst) == 0
            && socket.release_original_ack.load(Ordering::SeqCst) == 0
            && !socket.frontend_eof.load(Ordering::SeqCst),
            "terminal G35 child-drift controller ran before a genuine normal original COMMIT ACK")?;
        require(Instant::now() < started + Duration::from_secs(5),
            "terminal G35 child-drift controller reached its cutpoint after the original five seconds")?;
        let committed = database_facts(&f.admin).await?;
        let event_id = terminal_verify_once(f, &before, &committed)?;
        let objects = f.root.0.join("objects");
        let retained = f.root.0.join("terminal_g35_original_objects_retained");
        let original_child = std::fs::symlink_metadata(&objects).map_err(|e| e.to_string())?;
        require(original_child.is_dir() && physical_absent(&retained),
            "terminal G35 controlled original child or unique retained name was invalid")?;
        std::fs::rename(&objects, &retained).map_err(|e| e.to_string())?;
        std::fs::DirBuilder::new().mode(0o700).create(&objects).map_err(|e| e.to_string())?;
        let replacement = std::fs::symlink_metadata(&objects).map_err(|e| e.to_string())?;
        require(replacement.is_dir() && (replacement.dev(), replacement.ino()) != (original_child.dev(), original_child.ino()),
            "terminal G35 controller did not produce a real new root child inode")?;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        terminal_g35_worker_resources_ended(&observer, &leaf).await?;
        // Restore only the two owned test names. Restoration cannot clear the original key's poison.
        std::fs::remove_dir(&objects).map_err(|e| e.to_string())?;
        std::fs::rename(&retained, &objects).map_err(|e| e.to_string())?;
        let restored = std::fs::symlink_metadata(&objects).map_err(|e| e.to_string())?;
        require((restored.dev(), restored.ino()) == (original_child.dev(), original_child.ino()) && physical_absent(&retained),
            "terminal G35 controller did not restore its exact retained original child")?;
        require(matches!(result, Err(TerminalError::PhysicalUnproven) | Err(TerminalError::ReadsUnproven)),
            "terminal G35 actual final original guard accepted child drift or relabelled already normal ACK as Unknown")?;
        terminal_g35_original_normal_ack(f, pid, &socket, true, None).await?;
        require(started.elapsed() < Duration::from_secs(5)
            && socket.entered.load(Ordering::SeqCst) & ROLLBACK_BIT == 0
            && database_facts(&f.admin).await? == committed,
            "terminal G35 final IO refusal changed original normal ACK or durable terminal effects/refund/audit")?;
        terminal_g35_poison_refuses_without_mutation(f, &intent, &committed).await?;
        eprintln!("ARTIFACT_TERMINAL_G05_FINAL_GUARD_DRIFT original_pid={pid} actual_audit_event_id={event_id} original_normal_commit_ack=true actual_objects_child_inode_replaced=true same_original_continuous_io_guard_final_probe_refused=true real_worker_resources_ended=true exact_original_child_restored=true true_committed_effects_kept=true new_valid_session_same_store_permanent_unproven=true normal_ack_not_unknown=true repeat_refund_audit=false");
        drop(intent);
        Ok(())
    })).await;
}
