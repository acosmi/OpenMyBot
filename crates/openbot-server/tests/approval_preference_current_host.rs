//! Real production Session/verified SingleUser -> internal preference port -> owned PostgreSQL.
//! The cookie rows, Bot/Thread rows and loopback fault relay are owned fixtures. They do not prove
//! an enterprise SSO journey, Desktop authority, a public route or remember-effect authorization.

#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::Request;
use openbot_application::approval_preferences::{
    RememberPreferenceRepository, RememberPreferenceRepositoryError as Error,
};
use openbot_contracts::approval_preferences::{
    RememberPreference as Preference, RememberPreferenceState as State,
    RememberPreferenceTarget as Target, StoredRememberPreference,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::ids::{BotId, DeploymentId, TenantId, ThreadId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionLifetimePolicy, SessionToken, SessionTokenHash,
};
use openbot_domain::vault::SecretBytes;
use openbot_infra::approval_preferences::PostgresRememberPreferenceRepository;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::{
    SINGLE_USER_ACTOR_ID, initialize_single_user, load_single_user_principal,
};
use openbot_infra::db::pool::{
    ConnectionDestruction, ConnectionObservation, DatabaseConfig, DatabasePool,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, SingleUserAuthResolver};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use uuid::Uuid;

const DEPLOYMENT: &str = "preference/deployment%成果";
const TENANT: &str = "preference-tenant";
const OWNER: &str = "preference-owner";
const OTHER: &str = "preference-other";
const ADMIN: &str = "preference-admin";
const BOT: &str = "preference-bot";
const SESSION_KEY: &[u8] = b"owned-preference-session-hash-key";
const COOKIE_A: &str = "owned-preference-cookie-a-001";
const COOKIE_B: &str = "owned-preference-cookie-b-002";
const COOKIE_OTHER: &str = "owned-preference-cookie-other-003";
const COOKIE_ADMIN: &str = "owned-preference-cookie-admin-004";
const DIRECT: &str = "preference/direct%thread 成果";
const DIRECT_TWO: &str = "preference/direct-second";
const CHANNEL_THREAD: &str = "preference/channel-thread";
const CHANNEL: &str = "preference-channel";
const AUDIT_LOCK: i64 = 0x4f50_454e_4155_4431;

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

async fn resolve(resolver: &dyn AuthResolver, cookie: Option<&str>) -> Result<AuthContext, String> {
    let mut request = Request::builder().uri("/api/me");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("openbot_session={cookie}"));
    }
    let (parts, ()) = request.body(()).map_err(|e| e.to_string())?.into_parts();
    resolver.resolve(&parts).await.map_err(|e| e.to_string())
}

enum Host {
    Session(Arc<PostgresSessionAuthResolver>),
    Single(Arc<SingleUserAuthResolver>),
}
impl Host {
    fn resolver(&self) -> &dyn AuthResolver {
        match self {
            Self::Session(h) => h.as_ref(),
            Self::Single(h) => h.as_ref(),
        }
    }
    fn close(&self) {
        match self {
            Self::Session(h) => h.close_request_bindings(),
            Self::Single(h) => h.close_request_bindings(),
        }
    }
}

struct Fixture {
    admin: DatabasePool,
    pool: DatabasePool,
    repository: Arc<PostgresRememberPreferenceRepository>,
    host: Host,
    auth: AuthContext,
    direct_config: DatabaseConfig,
    relay: Option<OwnedRelay>,
}
impl Fixture {
    async fn tamper_thread_identity(&self, sql: &str) -> Result<(), String> {
        let mut client = self.admin.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_thread_identity(&tx, sql, &[]).await?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    async fn new(config: DatabaseConfig, single: bool, relay: bool) -> Result<Self, String> {
        Self::with_lifetime(
            config.with_max_pool_size(1),
            single,
            relay,
            default_session_lifetime(),
        )
        .await
    }
    async fn with_lifetime(
        config: DatabaseConfig,
        single: bool,
        relay: bool,
        lifetime: SessionLifetimePolicy,
    ) -> Result<Self, String> {
        let direct_config = config.clone().with_max_pool_size(4);
        let admin = pool::connect(&direct_config)
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut c = admin.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('preference-owner','owner@example.test',0),
                   ('preference-other','other@example.test',0),
                   ('preference-admin','admin@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('preference-owner','user'),('preference-other','user'),
                   ('preference-admin','admin');
                 INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES
                   ('00000000-0000-4000-8000-000000000001','preference-tenant','owned','owned'),
                   ('00000000-0000-4000-8000-000000000002','other-tenant','owned','owned');",
            )
            .await
            .map_err(|e| e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, actor, token) in [
                ("preference-session-a", OWNER, COOKIE_A),
                ("preference-session-b", OWNER, COOKIE_B),
                ("preference-session-other", OTHER, COOKIE_OTHER),
                ("preference-session-admin", ADMIN, COOKIE_ADMIN),
            ] {
                c.execute(
                    "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation)
                     VALUES($1,$2,$3,$4,$5,$5,0)",
                    &[&id, &actor, &token_column(token), &(now + time::Duration::hours(1)), &now],
                ).await.map_err(|e| e.to_string())?;
            }
        }
        let relay = if relay {
            Some(OwnedRelay::start(&direct_config).await?)
        } else {
            None
        };
        let host_config = if let Some(relay) = &relay {
            relay.config(&direct_config)
        } else {
            config.clone()
        }
        .with_max_pool_size(config.max_pool_size);
        let pool = pool::connect(&host_config)
            .await
            .map_err(|e| e.to_string())?;
        if single {
            initialize_single_user(&pool, true)
                .await
                .map_err(|e| e.to_string())?;
        }
        let actor = if single { SINGLE_USER_ACTOR_ID } else { OWNER };
        {
            let c = admin.get().await.map_err(|e| e.to_string())?;
            for (id, owner, visibility, package, deleted) in [
                (BOT, actor, "public", None, false),
                ("preference-bot-second", actor, "public", None, false),
                ("private-owned", actor, "private", None, false),
                ("private-other", OTHER, "private", None, false),
                ("deleted-bot", actor, "public", None, true),
                ("tenant-package-bot", actor, "public", Some(1), false),
                ("foreign-package-bot", actor, "public", Some(2), false),
            ] {
                let package = package.map(|n| Uuid::from_u128(0x40008000000000000000 + n));
                // Package UUIDs are genuine rows; NULL is independently a valid no-package case.
                c.execute(
                    "INSERT INTO public.agents(id,name,type,configuration,package_id)
                     VALUES($1,'Owned preference Bot','built_in','{}',$2)",
                    &[&id, &package],
                )
                .await
                .map_err(|e| e.to_string())?;
                c.execute(
                    "INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at)
                     VALUES($1,$2,'Owned preference Bot','owned','owned',$3::text::public.agent_visibility,
                       CASE WHEN $4::bool THEN clock_timestamp() END)",
                    &[&id, &owner, &visibility, &deleted],
                ).await.map_err(|e| e.to_string())?;
            }
            c.execute("INSERT INTO public.channels(id,name,description) VALUES($1,'Owned channel','owned')",
                &[&CHANNEL]).await.map_err(|e| e.to_string())?;
            c.execute(
                "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",
                &[&CHANNEL, &actor],
            )
            .await
            .map_err(|e| e.to_string())?;
            c.execute(
                "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES($1,$2)",
                &[&CHANNEL, &BOT],
            )
            .await
            .map_err(|e| e.to_string())?;
            for (id, kind, anchor) in [
                (DIRECT, "direct_bot", BOT),
                (DIRECT_TWO, "direct_bot", BOT),
                (CHANNEL_THREAD, "channel", CHANNEL),
            ] {
                c.execute(
                    "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id)
                     VALUES($1,$2,$3,$4,$5,$6)",
                    &[&id, &TENANT, &DEPLOYMENT, &actor, &kind, &anchor],
                ).await.map_err(|e| e.to_string())?;
                if kind == "direct_bot" {
                    c.execute(
                        "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,$2)",
                        &[&id, &actor],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        if !single && lifetime.idle() <= time::Duration::seconds(2) {
            let c = admin.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("UPDATE public.sessions SET created_at=clock_timestamp(),updated_at=clock_timestamp()")
                .await.map_err(|e|e.to_string())?;
        }
        let repository = make_repository(&pool, DEPLOYMENT, TENANT)?;
        let host = if single {
            let principal = load_single_user_principal(
                &pool,
                DeploymentId::new(DEPLOYMENT),
                TenantId::new(TENANT),
            )
            .await
            .map_err(|e| e.to_string())?;
            let resolver = Arc::new(SingleUserAuthResolver::from_verified_principal(
                principal, lifetime,
            ));
            resolver
                .install_remember_preference_repository(&repository)
                .map_err(|_| "real SingleUser repository installation failed".to_owned())?;
            Host::Single(resolver)
        } else {
            let resolver = session_resolver(&pool, &repository, DEPLOYMENT, TENANT, lifetime)?;
            Host::Session(resolver)
        };
        let auth = resolve(host.resolver(), (!single).then_some(COOKIE_A)).await?;
        Ok(Self {
            admin,
            pool,
            repository,
            host,
            auth,
            direct_config,
            relay,
        })
    }

    async fn snapshot(&self) -> Result<Value, String> {
        let c = self.admin.get().await.map_err(|e| e.to_string())?;
        c.query_one(
            "SELECT jsonb_build_object(
               'preferences',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY preference_id)
                 FROM openbot_internal.approval_preferences p),'[]'::jsonb),
               'audit',coalesce((SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id)
                 FROM public.audit_events a),'[]'::jsonb),
               'checkpoints',coalesce((SELECT jsonb_agg(to_jsonb(c) ORDER BY sequence)
                 FROM public.audit_checkpoints c),'[]'::jsonb))",
            &[],
        )
        .await
        .map(|r| r.get(0))
        .map_err(|e| e.to_string())
    }
    async fn counts(&self) -> Result<(i64, i64, i64), String> {
        let c = self.admin.get().await.map_err(|e| e.to_string())?;
        let r = c.query_one(
            "SELECT (SELECT count(*) FROM openbot_internal.approval_preferences),
               (SELECT count(*) FROM public.audit_events),(SELECT count(*) FROM public.audit_checkpoints)", &[],
        ).await.map_err(|e| e.to_string())?;
        Ok((r.get(0), r.get(1), r.get(2)))
    }
    async fn original(&self) -> Result<(i32, ConnectionObservation, Arc<SocketFacts>), String> {
        let client = self.pool.get().await.map_err(|e| e.to_string())?;
        let pid = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let observation = client.observation();
        let socket = self
            .relay
            .as_ref()
            .ok_or_else(|| "original socket requires owned relay".to_owned())?
            .socket_for_pid(pid)?;
        drop(client);
        Ok((pid, observation, socket))
    }
    async fn verify_audit(
        &self,
        saved: &StoredRememberPreference,
        expected_total: i64,
    ) -> Result<(), String> {
        let c = self.admin.get().await.map_err(|e| e.to_string())?;
        let rows = c
            .query(
                "SELECT actor_user_id,event_type,target_type,target_id,payload,row_hash
             FROM public.audit_events ORDER BY created_at,id",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            rows.len() as i64 == expected_total,
            "audit cardinality is not one per accepted save",
        )?;
        let row = rows
            .last()
            .ok_or_else(|| "accepted save has no audit".to_owned())?;
        let payload: Value = row.get("payload");
        require(
            row.get::<_, Option<String>>("actor_user_id").as_deref()
                == Some(saved.key().actor_id().as_str())
                && row.get::<_, String>("event_type") == "configuration.changed"
                && row.get::<_, String>("target_type") == "approval_preference"
                && row.get::<_, Option<String>>("target_id").as_deref() == Some(saved.id())
                && payload.get("change").and_then(Value::as_str)
                    == Some("approval_preference_saved")
                && payload
                    .get("approval_preference_revision")
                    .and_then(Value::as_i64)
                    == Some(saved.revision().get())
                && row
                    .get::<_, Option<String>>("row_hash")
                    .is_some_and(|v| v.len() == 64),
            "audit does not contain actual actor, stable row and typed revision facts",
        )?;
        require(
            self.counts().await?.2 == 1,
            "accepted saves did not share one genesis checkpoint",
        )
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
        while let Some(packet) = frame(&mut backend_read).await? {
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
                }
            }
            if holding == 0 {
                frontend_write.write_all(&packet).await?;
                if bit != 0 {
                    backend_facts.forwarded_ack.fetch_or(bit, Ordering::SeqCst);
                }
            } else if packet[0] == b'Z' {
                // Keep the original socket open. Only its real caller retirement can complete EOF.
                std::future::pending::<()>().await;
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

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and owned relay; explicit exact --include-ignored only"]
async fn original_five_seconds_include_pool_then_actor_row_and_audit_waits() {
    let admin =
        harness::admin_config("original_five_seconds_include_pool_then_actor_row_and_audit_waits");
    for wait in ["actor", "key", "row", "audit"] {
        harness::with_temp_database(&admin,"pref_single_deadline",|config|async move {
            let f=Fixture::new(config,false,true).await?;
            let first=saved(&f,&f.auth,BOT,Target::User,Preference::Ask,None).await?;
            let before=f.snapshot().await?;
            let held=f.pool.get().await.map_err(|e|e.to_string())?;
            let pid=held.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get::<_,i32>(0);
            let observation=held.observation();
            let socket=f.relay.as_ref().expect("owned relay").socket_for_pid(pid)?;
            let mut blocker=f.admin.get().await.map_err(|e|e.to_string())?;
            let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
            let fragment=match wait {
                "actor"=>{
                    tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER]).await.map_err(|e|e.to_string())?;
                    "public.users"
                }
                "row"=>{
                    tx.query_one("SELECT preference_id FROM openbot_internal.approval_preferences WHERE preference_id=$1::text::uuid FOR UPDATE",
                        &[&first.id()]).await.map_err(|e|e.to_string())?;
                    "openbot_internal.approval_preferences"
                }
                "key"=>{
                    tx.query_one("SELECT pg_advisory_xact_lock(hashtextextended(\
                        jsonb_build_array($1::text,$2::text,$3::text,$4::text,$5::text,$6::text)::text,$7))",
                        &[&DEPLOYMENT,&TENANT,&OWNER,&BOT,&"memory_user",&OWNER,&0x4150_5052_4546_3031_i64])
                        .await.map_err(|e|e.to_string())?;
                    "pg_advisory_xact_lock"
                }
                _=>{
                    tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e|e.to_string())?;
                    "pg_advisory_xact_lock"
                }
            };
            let repository=f.repository.clone();let auth=f.auth.clone();
            let started=Instant::now();
            let original=tokio::spawn(async move {
                repository.write(&auth,&BotId::new(BOT),Target::User,Preference::Never,Some(1)).await
            });
            // These two seconds occupy the same entry budget before any connection is acquired.
            tokio::time::sleep(Duration::from_secs(2)).await;
            require(!original.is_finished(),"entry did not actually wait for its own Pool slot")?;
            drop(held);
            wait_blocked(&f.admin,pid,fragment).await?;
            require(original.await.map_err(|e|e.to_string())?==Err(Error::Unavailable),
                "expired original wait returned a timely save or renewed a transaction budget")?;
            original_five_seconds(started)?;
            let cleanup=Instant::now()+Duration::from_secs(2);
            require(observation.wait_for_destruction_before(cleanup).await.map_err(|e|e.to_string())?
                ==ConnectionDestruction::ConnectionDestroyed,"deadline did not destroy original Connection")?;
            wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),cleanup,"deadline original socket EOF missing").await?;
            // Backend disappearance is only a crosscheck, after releasing this deliberately held
            // test lock; it cannot substitute for the original destructor and socket evidence.
            tx.rollback().await.map_err(|e|e.to_string())?;
            retired_original(&f,pid,&observation,&socket).await?;
            require(f.snapshot().await?==before,"timed-out actor/row/audit wait committed business or audit")
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and owned relay; explicit exact --include-ignored only"]
async fn original_five_seconds_include_connect_and_begin_ack_waits() {
    let admin = harness::admin_config("original_five_seconds_include_connect_and_begin_ack_waits");
    for wait in ["connect", "begin"] {
        harness::with_temp_database(&admin, "pref_connect_begin", |config| async move {
            let f = Fixture::new(config, true, true).await?;
            let before = f.snapshot().await?;
            let (pid, observation, socket) = f.original().await?;
            if wait == "connect" {
                // Remove only this owned cached backend. Principal verification and enrollment
                // used this exact original Pool, which remains the same Manager throughout.
                let c = f.admin.get().await.map_err(|e| e.to_string())?;
                require(
                    c.query_one("SELECT pg_terminate_backend($1)", &[&pid])
                        .await
                        .map_err(|e| e.to_string())?
                        .get(0),
                    "owned cached backend was not terminated for cold-connect fixture",
                )?;
                drop(c);
                let cleanup = Instant::now() + Duration::from_secs(2);
                require(
                    observation
                        .wait_for_destruction_before(cleanup)
                        .await
                        .map_err(|e| e.to_string())?
                        == ConnectionDestruction::ConnectionDestroyed,
                    "cold fixture did not destroy its old Connection",
                )?;
                wait_fact(
                    || socket.frontend_eof.load(Ordering::SeqCst),
                    cleanup,
                    "cold fixture original socket EOF missing",
                )
                .await?;
                f.relay.as_ref().expect("owned relay").arm(Hold::Startup);
            } else {
                f.relay.as_ref().expect("owned relay").arm(Hold::Begin);
            }
            let repository = f.repository.clone();
            let auth = f.auth.clone();
            let started = Instant::now();
            let original = tokio::spawn(async move {
                repository.read(&auth, &BotId::new(BOT), Target::User).await
            });
            let (operation_observation, operation_socket) = if wait == "connect" {
                wait_fact(
                    || {
                        f.pool.connection_observations().iter().any(|o| {
                            let s = o.snapshot();
                            s.connecting_future_started && !s.connection_started
                        })
                    },
                    Instant::now() + Duration::from_secs(2),
                    "original cold connect future was not observed before cancellation",
                )
                .await?;
                let connecting = f
                    .pool
                    .connection_observations()
                    .into_iter()
                    .find(|o| {
                        let s = o.snapshot();
                        s.connecting_future_started && !s.connection_started
                    })
                    .ok_or_else(|| {
                        "original connecting owner disappeared before observation".to_owned()
                    })?;
                wait_fact(
                    || {
                        f.relay
                            .as_ref()
                            .expect("owned relay")
                            .newest_socket()
                            .is_ok_and(|s| s.withheld.load(Ordering::SeqCst) == Hold::Startup as u8)
                    },
                    Instant::now() + Duration::from_secs(2),
                    "cold connect did not reach its owned accepted socket",
                )
                .await?;
                (
                    connecting,
                    f.relay.as_ref().expect("owned relay").newest_socket()?,
                )
            } else {
                wait_fact(
                    || socket.withheld.load(Ordering::SeqCst) == Hold::Begin as u8,
                    Instant::now() + Duration::from_secs(2),
                    "original BEGIN did not reach a real upstream ACK",
                )
                .await?;
                (observation.clone(), socket.clone())
            };
            require(
                original.await.map_err(|e| e.to_string())? == Err(Error::Unavailable),
                "connect/BEGIN ACK wait returned a timely result after original deadline",
            )?;
            original_five_seconds(started)?;
            if wait == "connect" {
                let cleanup = Instant::now() + Duration::from_secs(2);
                require(
                    operation_observation
                        .wait_for_destruction_before(cleanup)
                        .await
                        .map_err(|e| e.to_string())?
                        == ConnectionDestruction::ConnectingFutureDestroyed,
                    "deadline did not destroy the original Config::connect future",
                )?;
                wait_fact(
                    || operation_socket.frontend_eof.load(Ordering::SeqCst),
                    cleanup,
                    "original cold connecting socket had no EOF",
                )
                .await?;
                require(
                    operation_socket.pid.load(Ordering::SeqCst) == 0,
                    "held startup was silently forwarded upstream",
                )?;
                let c = f.pool.get().await.map_err(|e| e.to_string())?;
                require(
                    c.query_one("SELECT pg_backend_pid()", &[])
                        .await
                        .map_err(|e| e.to_string())?
                        .get::<_, i32>(0)
                        != pid,
                    "failed cold connection reused retired cached backend",
                )?;
            } else {
                require(
                    operation_socket.server_ack.load(Ordering::SeqCst) & BEGIN_BIT != 0,
                    "synthetic BEGIN fault lacked a real original BEGIN ACK",
                )?;
                retired_original(&f, pid, &operation_observation, &operation_socket).await?;
            }
            require(
                f.snapshot().await? == before,
                "connect/BEGIN fault wrote business or audit",
            )
        })
        .await;
    }
}

fn clear_transaction_facts(socket: &SocketFacts) {
    socket.entered.store(0, Ordering::SeqCst);
    socket.server_ack.store(0, Ordering::SeqCst);
    socket.forwarded_ack.store(0, Ordering::SeqCst);
    socket.withheld.store(0, Ordering::SeqCst);
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and owned relay; explicit exact --include-ignored only"]
async fn synthetic_audit_insert_failure_rolls_back_business_and_audit() {
    harness::with_temp_database(&harness::admin_config("synthetic_audit_insert_failure_rolls_back_business_and_audit"),
        "pref_audit_failure",|config|async move {
        let f=Fixture::new(config,true,true).await?;
        let before=f.snapshot().await?;
        let c=f.admin.get().await.map_err(|e|e.to_string())?;
        c.batch_execute("CREATE FUNCTION public.owned_preference_test_audit_failure() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='owned synthetic audit fault'; END $$;
            CREATE TRIGGER owned_preference_test_audit_failure BEFORE INSERT ON public.audit_events
            FOR EACH ROW EXECUTE FUNCTION public.owned_preference_test_audit_failure()")
            .await.map_err(|e|e.to_string())?;
        drop(c);
        let (pid,observation,socket)=f.original().await?;
        clear_transaction_facts(&socket);
        require(f.repository.write(&f.auth,&BotId::new(BOT),Target::User,Preference::Never,None).await
            ==Err(Error::Unavailable),"synthetic audit insertion failure returned accepted preference")?;
        require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0
            && socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0
            && socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0,
            "failure did not complete the same original ROLLBACK ACK")?;
        require(f.snapshot().await?==before && f.counts().await?==(0,0,0),
            "failed audit committed preference, audit or genesis checkpoint")?;
        require(observation.snapshot().destruction.is_none(),"timely acknowledged rollback unexpectedly retired original")?;
        let c=f.pool.get().await.map_err(|e|e.to_string())?;
        require(c.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get::<_,i32>(0)==pid,
            "same original acknowledged rollback connection was not reusable")
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and owned relay; explicit exact --include-ignored only"]
async fn synthetic_commit_ack_loss_remains_unknown_and_retires_original() {
    harness::with_temp_database(
        &harness::admin_config("synthetic_commit_ack_loss_remains_unknown_and_retires_original"),
        "pref_commit_unknown",
        |config| async move {
            let f = Fixture::new(config, true, true).await?;
            let (pid, observation, socket) = f.original().await?;
            clear_transaction_facts(&socket);
            f.relay.as_ref().expect("owned relay").arm(Hold::Commit);
            let repository = f.repository.clone();
            let auth = f.auth.clone();
            let started = Instant::now();
            let original = tokio::spawn(async move {
                repository
                    .write(
                        &auth,
                        &BotId::new(BOT),
                        Target::User,
                        Preference::Never,
                        None,
                    )
                    .await
            });
            wait_fact(
                || socket.withheld.load(Ordering::SeqCst) == Hold::Commit as u8,
                Instant::now() + Duration::from_secs(2),
                "original COMMIT was not forwarded and acknowledged upstream",
            )
            .await?;
            require(
                socket.entered.load(Ordering::SeqCst) & COMMIT_BIT != 0
                    && socket.server_ack.load(Ordering::SeqCst) & COMMIT_BIT != 0
                    && socket.forwarded_ack.load(Ordering::SeqCst) & COMMIT_BIT == 0,
                "COMMIT uncertainty fixture did not lose the original real ACK",
            )?;
            require(
                f.counts().await? == (1, 1, 1),
                "upstream committed operation was not actually durable",
            )?;
            require(
                original.await.map_err(|e| e.to_string())? == Err(Error::CommitUnknown),
                "lost original COMMIT ACK became a definite result or an automatic retry",
            )?;
            original_five_seconds(started)?;
            retired_original(&f, pid, &observation, &socket).await?;
            require(
                f.counts().await? == (1, 1, 1),
                "uncertain write was replayed or mislabeled rollback",
            )
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL and owned relay; explicit exact --include-ignored only"]
async fn synthetic_rollback_ack_loss_and_caller_cancel_do_not_return_original_client() {
    let admin = harness::admin_config(
        "synthetic_rollback_ack_loss_and_caller_cancel_do_not_return_original_client",
    );
    for fault in ["rollback_ack", "caller_cancel"] {
        harness::with_temp_database(&admin,"pref_rollback_cancel",|config|async move {
            let f=Fixture::new(config,true,true).await?;
            let first=if fault=="caller_cancel" {
                Some(saved(&f,&f.auth,BOT,Target::User,Preference::Ask,None).await?)
            }else{None};
            let before=f.snapshot().await?;
            let (pid,observation,socket)=f.original().await?;
            clear_transaction_facts(&socket);
            if fault=="rollback_ack" {
                f.relay.as_ref().expect("owned relay").arm(Hold::Rollback);
                let repository=f.repository.clone();let auth=f.auth.clone();let started=Instant::now();
                let original=tokio::spawn(async move {repository.read(&auth,&BotId::new(BOT),Target::User).await});
                wait_fact(||socket.withheld.load(Ordering::SeqCst)==Hold::Rollback as u8,
                    Instant::now()+Duration::from_secs(2),"original ROLLBACK did not receive an upstream ACK").await?;
                require(original.await.map_err(|e|e.to_string())?==Err(Error::Unavailable),
                    "lost original ROLLBACK ACK returned a timely default read")?;
                original_five_seconds(started)?;
                require(socket.entered.load(Ordering::SeqCst)&ROLLBACK_BIT!=0
                    && socket.server_ack.load(Ordering::SeqCst)&ROLLBACK_BIT!=0
                    && socket.forwarded_ack.load(Ordering::SeqCst)&ROLLBACK_BIT==0,
                    "rollback loss did not withhold the same original real ACK")?;
            }else{
                let mut blocker=f.admin.get().await.map_err(|e|e.to_string())?;
                let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
                tx.query_one("SELECT preference_id FROM openbot_internal.approval_preferences WHERE preference_id=$1::text::uuid FOR UPDATE",
                    &[&first.as_ref().expect("controlled current row").id()]).await.map_err(|e|e.to_string())?;
                let repository=f.repository.clone();let auth=f.auth.clone();
                let original=tokio::spawn(async move {
                    repository.write(&auth,&BotId::new(BOT),Target::User,Preference::Never,Some(1)).await
                });
                wait_blocked(&f.admin,pid,"openbot_internal.approval_preferences").await?;
                original.abort();
                require(original.await.is_err_and(|e|e.is_cancelled()),"original entry was not actually caller-cancelled")?;
                let cleanup=Instant::now()+Duration::from_secs(2);
                require(observation.wait_for_destruction_before(cleanup).await.map_err(|e|e.to_string())?
                    ==ConnectionDestruction::ConnectionDestroyed,"caller cancellation lacked original destructor")?;
                wait_fact(||socket.frontend_eof.load(Ordering::SeqCst),cleanup,
                    "caller-cancelled original socket EOF missing").await?;
                tx.rollback().await.map_err(|e|e.to_string())?;
            }
            retired_original(&f,pid,&observation,&socket).await?;
            require(f.snapshot().await?==before,"rollback loss/caller cancellation changed business or audit")
        }).await;
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.host.close();
        self.pool.close();
        self.admin.close();
    }
}

fn make_repository(
    pool: &DatabasePool,
    deployment: &str,
    tenant: &str,
) -> Result<Arc<PostgresRememberPreferenceRepository>, String> {
    PostgresRememberPreferenceRepository::new(
        pool.clone(),
        DeploymentId::new(deployment),
        TenantId::new(tenant),
        SecretBytes::new(vec![0x62; 32]),
    )
    .map(Arc::new)
    .map_err(|e| e.to_string())
}
fn session_resolver(
    pool: &DatabasePool,
    repository: &Arc<PostgresRememberPreferenceRepository>,
    deployment: &str,
    tenant: &str,
    lifetime: SessionLifetimePolicy,
) -> Result<Arc<PostgresSessionAuthResolver>, String> {
    let resolver = Arc::new(
        PostgresSessionAuthResolver::new(
            pool.clone(),
            SESSION_KEY,
            lifetime,
            DeploymentId::new(deployment),
            TenantId::new(tenant),
        )
        .map_err(|e| e.to_string())?,
    );
    resolver
        .install_remember_preference_repository(repository)
        .map_err(|_| "real Session repository installation failed".to_owned())?;
    Ok(resolver)
}

async fn saved(
    fixture: &Fixture,
    auth: &AuthContext,
    bot: &str,
    target: Target,
    preference: Preference,
    expected: Option<i64>,
) -> Result<StoredRememberPreference, String> {
    fixture
        .repository
        .write(auth, &BotId::new(bot), target, preference, expected)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_absent_ask_has_no_row_revision_or_audit() {
    harness::with_temp_database(
        &harness::admin_config("actual_session_absent_ask_has_no_row_revision_or_audit"),
        "pref_absent",
        |config| async move {
            let f = Fixture::new(config, false, false).await?;
            require(
                !f.auth.is_single_user() && f.auth.request_binding().is_some(),
                "actual Session binding missing",
            )?;
            let before = f.snapshot().await?;
            for target in [
                Target::User,
                Target::Bot,
                Target::Thread(ThreadId::new(DIRECT)),
                Target::Thread(ThreadId::new(CHANNEL_THREAD)),
            ] {
                let state = f
                    .repository
                    .read(&f.auth, &BotId::new(BOT), target)
                    .await
                    .map_err(|e| e.to_string())?;
                require(
                    matches!(&state, State::Absent)
                        && state.effective_preference() == Preference::Ask,
                    "missing row was materialized or did not default to Ask",
                )?;
            }
            require(
                f.snapshot().await? == before && f.counts().await? == (0, 0, 0),
                "default Ask read inserted an ID, revision, timestamp, audit or checkpoint",
            )
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_full_key_cas_returns_exact_current_snapshot() {
    harness::with_temp_database(&harness::admin_config("actual_session_full_key_cas_returns_exact_current_snapshot"),
        "pref_cas", |config| async move {
        let f = Fixture::new(config, false, false).await?;
        let mut total = 0;
        for target in [Target::User, Target::Bot, Target::Thread(ThreadId::new(DIRECT))] {
            let first = saved(&f, &f.auth, BOT, target.clone(), Preference::Ask, None).await?;
            total += 1;
            require(first.revision().get() == 1 && first.created_at() == first.updated_at(),
                "create did not return revision one and actual equal initial timestamps")?;
            f.verify_audit(&first, total).await?;
            let second = saved(&f, &f.auth, BOT, target.clone(), Preference::Ask, Some(1)).await?;
            total += 1;
            require(second.revision().get() == 2 && first.id() == second.id()
                && first.key() == second.key() && first.created_at() == second.created_at(),
                "same-value save did not advance revision with immutable identity/key/created time")?;
            f.verify_audit(&second, total).await?;
            let snapshot = second.revision_snapshot().map_err(|e| e.to_string())?;
            let before = f.snapshot().await?;
            for expected in [None, Some(1)] {
                require(f.repository.write(&f.auth, &BotId::new(BOT), target.clone(), Preference::Never, expected)
                    .await == Err(Error::Conflict { snapshot }), "conflict did not carry exact authorized current three-field snapshot")?;
            }
            for expected in [0, -1, i64::MIN] {
                require(f.repository.write(&f.auth, &BotId::new(BOT), target.clone(), Preference::Never, Some(expected))
                    .await == Err(Error::InvalidInput { field: "expected_revision" }), "nonpositive revision did not fail as 400")?;
            }
            require(f.repository.read(&f.auth, &BotId::new(BOT), target).await == Ok(State::Stored(second)),
                "read did not return actual current stored record")?;
            require(f.snapshot().await? == before, "read/conflict/invalid input changed business or audit")?;
        }
        require(f.repository.write(&f.auth, &BotId::new(BOT), Target::Thread(ThreadId::new(DIRECT_TWO)),
            Preference::Never, Some(1)).await == Err(Error::NotVisible), "positive revision on absent key did not return 404")?;
        // Each full-key dimension uses an actual producer in that namespace, or a genuine visible Bot/Thread.
        let other = resolve(f.host.resolver(), Some(COOKIE_OTHER)).await?;
        let actor_row = saved(&f, &other, BOT, Target::User, Preference::Never, None).await?;
        let bot_row = saved(&f, &f.auth, "preference-bot-second", Target::User, Preference::AllowIfPolicy, None).await?;
        let target_row = saved(&f, &f.auth, BOT, Target::Thread(ThreadId::new(DIRECT_TWO)), Preference::Never, None).await?;
        let mut namespace_owners = Vec::new();
        for (deployment, tenant) in [("second-deployment", TENANT), (DEPLOYMENT, "second-tenant")] {
            let repository = make_repository(&f.pool, deployment, tenant)?;
            let resolver = session_resolver(&f.pool, &repository, deployment, tenant, default_session_lifetime())?;
            let auth = resolve(resolver.as_ref(), Some(COOKIE_A)).await?;
            let row = repository.write(&auth, &BotId::new(BOT), Target::User, Preference::Never, None)
                .await.map_err(|e| e.to_string())?;
            require(row.revision().get() == 1 && row.key().deployment_id().as_str() == deployment
                && row.key().tenant_id().as_str() == tenant, "namespace dimension reused another key")?;
            namespace_owners.push((repository,resolver));
        }
        require(actor_row.key().actor_id().as_str() == OTHER && bot_row.key().bot_id().as_str() == "preference-bot-second"
            && target_row.key().target_id() == DIRECT_TWO && f.counts().await? == (8,11,1),
            "complete key dimensions collided or modified an unrelated row")?;
        // A separately inserted maximum revision is a legitimate storage fixture, not a guard bypass/update.
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        let max_id = Uuid::now_v7();
        c.execute("INSERT INTO openbot_internal.approval_preferences
            (preference_id,deployment_id,tenant_id,actor_id,bot_id,target_kind,target_id,tool_name,effect,preference,revision,created_at,updated_at)
            VALUES($1,$2,$3,$4,'preference-bot-second','memory_bot','preference-bot-second','remember','write','ask',$5,clock_timestamp(),clock_timestamp())",
            &[&max_id, &DEPLOYMENT, &TENANT, &OWNER, &i64::MAX]).await.map_err(|e| e.to_string())?;
        drop(c);
        let before = f.snapshot().await?;
        require(f.repository.write(&f.auth, &BotId::new("preference-bot-second"), Target::Bot,
            Preference::Never, Some(i64::MAX)).await == Err(Error::Unavailable), "revision overflow did not refuse")?;
        require(f.snapshot().await? == before, "overflow changed revision or appended audit")
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_create_and_same_revision_races_commit_one_audit_each() {
    harness::with_temp_database(
        &harness::admin_config(
            "actual_session_create_and_same_revision_races_commit_one_audit_each",
        ),
        "pref_race",
        |config| async move {
            let f = Fixture::with_lifetime(
                config.with_max_pool_size(2),
                false,
                false,
                default_session_lifetime(),
            )
            .await?;
            let auth_b = resolve(f.host.resolver(), Some(COOKIE_B)).await?;
            for (expected, resulting_revision, audit_total) in [(None, 1, 1), (Some(1), 2, 2)] {
                let barrier = Arc::new(Barrier::new(3));
                let mut tasks = Vec::new();
                for (auth, preference) in [
                    (f.auth.clone(), Preference::Never),
                    (auth_b.clone(), Preference::AllowIfPolicy),
                ] {
                    let repository = f.repository.clone();
                    let barrier = barrier.clone();
                    tasks.push(tokio::spawn(async move {
                        barrier.wait().await;
                        repository
                            .write(&auth, &BotId::new(BOT), Target::User, preference, expected)
                            .await
                    }));
                }
                barrier.wait().await;
                let a = tasks.remove(0).await.map_err(|e| e.to_string())?;
                let b = tasks.remove(0).await.map_err(|e| e.to_string())?;
                let (winner, loser) =
                    match (a, b) {
                        (Ok(row), Err(error)) | (Err(error), Ok(row)) => (row, error),
                        _ => return Err(
                            "same original revision race did not yield exactly one accepted save"
                                .to_owned(),
                        ),
                    };
                require(
                    winner.revision().get() == resulting_revision
                        && loser
                            == Error::Conflict {
                                snapshot: winner.revision_snapshot().map_err(|e| e.to_string())?,
                            },
                    "losing race did not receive actual winner's current snapshot",
                )?;
                f.verify_audit(&winner, audit_total).await?;
                require(
                    f.counts().await? == (1, audit_total, 1),
                    "CAS race appended duplicate business/audit writes",
                )?;
            }
            f.host.close();
            Ok(())
        },
    )
    .await;
}

async fn refuses_current(
    f: &Fixture,
    auth: &AuthContext,
    bot: &str,
    target: Target,
) -> Result<(), String> {
    let before = f.snapshot().await?;
    require(
        f.repository
            .read(auth, &BotId::new(bot), target.clone())
            .await
            == Err(Error::NotVisible),
        "current invisible source was exposed by read",
    )?;
    require(
        f.repository
            .write(auth, &BotId::new(bot), target, Preference::Never, None)
            .await
            == Err(Error::NotVisible),
        "current invisible source accepted a write",
    )?;
    require(
        f.snapshot().await? == before,
        "current-authority refusal wrote business or audit",
    )
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_bot_scope_package_and_admin_matrix_is_current() {
    harness::with_temp_database(&harness::admin_config("actual_session_bot_scope_package_and_admin_matrix_is_current"),
        "pref_bot_scope", |config| async move {
        let f = Fixture::new(config, false, false).await?;
        for bot in [BOT, "private-owned", "tenant-package-bot"] {
            require(f.repository.read(&f.auth, &BotId::new(bot), Target::Bot).await == Ok(State::Absent),
                "actual visible owner/public/valid tenant package Bot was rejected")?;
        }
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('profile-missing','Owned missing-profile Bot','built_in','{}')")
            .await.map_err(|e|e.to_string())?;
        drop(c);
        for bot in ["private-other", "deleted-bot", "profile-missing", "foreign-package-bot", "missing-bot"] {
            refuses_current(&f, &f.auth, bot, Target::Bot).await?;
        }
        let admin = resolve(f.host.resolver(), Some(COOKIE_ADMIN)).await?;
        require(admin.has_role(Role::Admin), "actual admin fixture did not resolve current role")?;
        refuses_current(&f, &admin, "private-owned", Target::Bot).await?;
        let other = resolve(f.host.resolver(), Some(COOKIE_OTHER)).await?;
        let own_private = saved(&f, &other, "private-other", Target::Bot, Preference::Never, None).await?;
        f.verify_audit(&own_private,1).await?;
        let public_admin = saved(&f, &admin, BOT, Target::Bot, Preference::Ask, None).await?;
        f.verify_audit(&public_admin,2).await?;
        // Scope comes from the repository namespace, never from a syntactically valid other context.
        let wrong_namespace_repo = make_repository(&f.pool, "wrong-deployment", TENANT)?;
        let wrong_namespace_host = session_resolver(&f.pool, &wrong_namespace_repo,
            "wrong-deployment", TENANT, default_session_lifetime())?;
        let wrong_auth = resolve(wrong_namespace_host.as_ref(), Some(COOKIE_A)).await?;
        refuses_current(&f, &wrong_auth, BOT, Target::User).await?;
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        c.execute("UPDATE public.agent_profiles SET visibility='private',owner_user_id=$2 WHERE agent_id=$1",
            &[&BOT,&OTHER]).await.map_err(|e| e.to_string())?;
        drop(c);
        refuses_current(&f, &f.auth, BOT, Target::User).await?;
        require(f.counts().await? == (2,2,1), "Bot permission refusals appended audit")
    }).await;
}

// Privileged corruption control is confined to this owned disposable test DB.
// Probe the real guard for every change/restore and re-enable it in the same transaction.
async fn tamper_owned_thread_identity(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const NEW_GUARDS: [&str; 3] = [
        "threads_history_body_before_update",
        "threads_history_canonical_before",
        "threads_history_source_final",
    ];
    const OLD: &str = "threads_history_protect_identity_update";
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Thread guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_current_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_current_identity_probe; RELEASE SAVEPOINT owned_current_identity_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_state_binding_invalid"
                        | "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err("ordinary current Thread identity DML was not explicitly refused".into());
    }
    // Suppress only these owned fixture events BEFORE corrupting DML. Re-enabling
    // at COMMIT cannot remove an already queued deferred event; none is bypassed.
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.batch_execute("SAVEPOINT owned_original50_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let original = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_original50_identity_probe; RELEASE SAVEPOINT owned_original50_identity_probe").await.map_err(|e|e.to_string())?;
    if !original
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000" && e.message() == "thread_history_state_binding_invalid"
        })
    {
        return Err("original0050 single identity guard control lost its exact refusal".into());
    }
    tx.batch_execute(
        "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    tx.batch_execute(
        "ALTER TABLE public.threads ENABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Thread guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned identity control changed no row".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_direct_and_channel_thread_visibility_is_current() {
    harness::with_temp_database(&harness::admin_config("actual_session_direct_and_channel_thread_visibility_is_current"),
        "pref_thread_scope", |config| async move {
        let f = Fixture::new(config, false, false).await?;
        let direct = saved(&f,&f.auth,BOT,Target::Thread(ThreadId::new(DIRECT)),Preference::Ask,None).await?;
        f.verify_audit(&direct,1).await?;
        let c = f.admin.get().await.map_err(|e| e.to_string())?;
        require(c.query_one("SELECT count(*) FROM public.thread_memberships WHERE thread_id=$1",
            &[&CHANNEL_THREAD]).await.map_err(|e| e.to_string())?.get::<_,i64>(0) == 0,
            "channel positive control accidentally had a direct Thread membership")?;
        drop(c);
        let channel = saved(&f,&f.auth,BOT,Target::Thread(ThreadId::new(CHANNEL_THREAD)),Preference::Never,None).await?;
        f.verify_audit(&channel,2).await?;
        let other = resolve(f.host.resolver(),Some(COOKIE_OTHER)).await?;
        refuses_current(&f,&other,BOT,Target::Thread(ThreadId::new(DIRECT))).await?;
        for (change, restore, thread) in [
            ("DELETE FROM public.thread_memberships WHERE thread_id='preference/direct%thread 成果'",
             "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES('preference/direct%thread 成果','preference-owner')", DIRECT),
            ("UPDATE public.threads SET anchor_id='preference-bot-second' WHERE thread_id='preference/direct%thread 成果'",
             "UPDATE public.threads SET anchor_id='preference-bot' WHERE thread_id='preference/direct%thread 成果'", DIRECT),
            ("UPDATE public.threads SET tenant_id='other-tenant' WHERE thread_id='preference/direct%thread 成果'",
             "UPDATE public.threads SET tenant_id='preference-tenant' WHERE thread_id='preference/direct%thread 成果'", DIRECT),
            ("UPDATE public.threads SET deployment_id='other-deployment' WHERE thread_id='preference/direct%thread 成果'",
             "UPDATE public.threads SET deployment_id='preference/deployment%成果' WHERE thread_id='preference/direct%thread 成果'", DIRECT),
            ("UPDATE public.threads SET status='deleted',deleted_at=clock_timestamp() WHERE thread_id='preference/direct%thread 成果'",
             "UPDATE public.threads SET status='active',deleted_at=NULL WHERE thread_id='preference/direct%thread 成果'", DIRECT),
            ("DELETE FROM public.channel_memberships WHERE channel_id='preference-channel'",
             "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('preference-channel','preference-owner')", CHANNEL_THREAD),
            ("DELETE FROM public.channel_agents WHERE channel_id='preference-channel'",
             "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('preference-channel','preference-bot')", CHANNEL_THREAD),
            ("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000002' WHERE id='preference-channel'",
             "UPDATE public.channels SET package_id=NULL WHERE id='preference-channel'", CHANNEL_THREAD),
            ("UPDATE public.threads SET anchor_id='missing-channel' WHERE thread_id='preference/channel-thread'",
             "UPDATE public.threads SET anchor_id='preference-channel' WHERE thread_id='preference/channel-thread'", CHANNEL_THREAD),
        ] {
            let corrupts_thread_identity = matches!(change,
                "UPDATE public.threads SET anchor_id='preference-bot-second' WHERE thread_id='preference/direct%thread 成果'"
                | "UPDATE public.threads SET tenant_id='other-tenant' WHERE thread_id='preference/direct%thread 成果'"
                | "UPDATE public.threads SET deployment_id='other-deployment' WHERE thread_id='preference/direct%thread 成果'"
                | "UPDATE public.threads SET anchor_id='missing-channel' WHERE thread_id='preference/channel-thread'");
            if corrupts_thread_identity {
                f.tamper_thread_identity(change).await?;
            } else {
                let c = f.admin.get().await.map_err(|e| e.to_string())?;
                c.batch_execute(change).await.map_err(|e| e.to_string())?;
            }
            refuses_current(&f,&f.auth,BOT,Target::Thread(ThreadId::new(thread))).await?;
            if corrupts_thread_identity {
                f.tamper_thread_identity(restore).await?;
            } else {
                let c = f.admin.get().await.map_err(|e| e.to_string())?;
                c.batch_execute(restore).await.map_err(|e| e.to_string())?;
            }
        }
        // Source rows cannot silently wait: the actual source FOR SHARE NOWAIT path fails promptly.
        let mut blocker = f.admin.get().await.map_err(|e| e.to_string())?;
        let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one("SELECT id FROM public.agents WHERE id=$1 FOR UPDATE", &[&BOT])
            .await.map_err(|e| e.to_string())?;
        let started = Instant::now();
        require(f.repository.read(&f.auth,&BotId::new(BOT),Target::Thread(ThreadId::new(DIRECT))).await
            == Err(Error::Unavailable), "locked source did not refuse NOWAIT")?;
        require(started.elapsed() < Duration::from_secs(2), "source lock consumed the permitted wait path")?;
        tx.rollback().await.map_err(|e| e.to_string())?;
        require(f.counts().await? == (2,2,1), "Thread permission/NOWAIT refusals changed business or audit")
    }).await;
}

async fn wait_blocked(admin: &DatabasePool, pid: i32, query_fragment: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let c = admin.get().await.map_err(|e| e.to_string())?;
        let row = c
            .query_opt(
                "SELECT wait_event_type='Lock' AND position($2::text in query)>0 AS blocked
             FROM pg_catalog.pg_stat_activity WHERE pid=$1",
                &[&pid, &query_fragment],
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

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_rechecks_original_epoch_access_and_owner_after_wait() {
    let admin =
        harness::admin_config("actual_session_rechecks_original_epoch_access_and_owner_after_wait");
    for mutation in [
        "actor_generation",
        "role_removed",
        "deny_added",
        "owner_closed",
        "idle_expired",
        "absolute_expired",
    ] {
        harness::with_temp_database(&admin,"pref_current_tail",|config| async move {
            let lifetime = match mutation {
                "idle_expired" => SessionLifetimePolicy::new(time::Duration::seconds(2),time::Duration::hours(1),time::Duration::milliseconds(100)),
                "absolute_expired" => SessionLifetimePolicy::new(time::Duration::seconds(2),time::Duration::seconds(2),time::Duration::milliseconds(100)),
                _ => Ok(default_session_lifetime()),
            }.map_err(|e| e.to_string())?;
            let f = Fixture::with_lifetime(config.with_max_pool_size(1),false,true,lifetime).await?;
            let first = saved(&f,&f.auth,BOT,Target::User,Preference::Ask,None).await?;
            let before = f.snapshot().await?;
            let (pid,_,_) = f.original().await?;
            let mut blocker = f.admin.get().await.map_err(|e| e.to_string())?;
            let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
            if mutation == "actor_generation" {
                tx.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&OWNER])
                    .await.map_err(|e|e.to_string())?;
            } else if mutation == "owner_closed" {
                tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&AUDIT_LOCK]).await.map_err(|e| e.to_string())?;
            } else {
                tx.query_one("SELECT preference_id FROM openbot_internal.approval_preferences WHERE preference_id=$1::text::uuid FOR UPDATE",
                    &[&first.id()]).await.map_err(|e| e.to_string())?;
            }
            let repository = f.repository.clone(); let auth = f.auth.clone();
            let original = tokio::spawn(async move {
                repository.write(&auth,&BotId::new(BOT),Target::User,Preference::Never,Some(1)).await
            });
            wait_blocked(&f.admin,pid,match mutation {
                "actor_generation"=>"public.users",
                "owner_closed"=>"pg_advisory_xact_lock",
                _=>"openbot_internal.approval_preferences",
            }).await?;
            if mutation == "actor_generation" {
                tx.execute("UPDATE public.users SET auth_generation=1 WHERE id=$1",&[&OWNER])
                    .await.map_err(|e|e.to_string())?;
            } else if mutation == "owner_closed" { f.host.close(); }
            else if mutation.ends_with("expired") { tokio::time::sleep(Duration::from_millis(2200)).await; }
            else {
                let c = f.admin.get().await.map_err(|e| e.to_string())?;
                c.batch_execute(match mutation {
                    "role_removed" => "DELETE FROM public.user_roles WHERE user_id='preference-owner'",
                    "deny_added" => "INSERT INTO public.revoked_access(email,revoked_by) VALUES('owner@example.test','owned-test')",
                    _ => return Err("unregistered current-tail fixture".to_owned()),
                }).await.map_err(|e| e.to_string())?;
            }
            if mutation=="actor_generation" {
                tx.commit().await.map_err(|e|e.to_string())?;
            }else{
                tx.rollback().await.map_err(|e| e.to_string())?;
            }
            require(original.await.map_err(|e| e.to_string())? == Err(Error::NotVisible),
                "wait resumed under changed original session/access/owner/lifetime")?;
            require(f.snapshot().await? == before,"current tail refusal committed business or audit")?;
            // Parent-generation UPDATE commits before this request obtains its first SHARE lock.
            // Other cases never pretend an UPDATE committed while that original SHARE was held.
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_original_row_stays_locked_until_preference_commit() {
    harness::with_temp_database(
        &harness::admin_config("pref_logout_commit"),
        "pref_logout_commit",
        |config| async move {
            let f = Fixture::new(config, false, false).await?;
            let pid: i32 = f
                .pool
                .get()
                .await
                .map_err(|e| e.to_string())?
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            let mut blocker = f.admin.get().await.map_err(|e| e.to_string())?;
            let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
            tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_LOCK])
                .await
                .map_err(|e| e.to_string())?;
            let repository = f.repository.clone();
            let auth = f.auth.clone();
            let write = tokio::spawn(async move {
                repository
                    .write(
                        &auth,
                        &BotId::new(BOT),
                        Target::User,
                        Preference::Never,
                        None,
                    )
                    .await
            });
            wait_blocked(&f.admin, pid, "pg_advisory_xact_lock").await?;
            let deleter = f.admin.get().await.map_err(|e| e.to_string())?;
            let delete_pid: i32 = deleter
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            let logout = tokio::spawn(async move {
                deleter
                    .execute(
                        "DELETE FROM public.sessions WHERE id='preference-session-a'",
                        &[],
                    )
                    .await
            });
            wait_blocked(&f.admin, delete_pid, "DELETE FROM public.sessions").await?;
            let observer = f.admin.get().await.map_err(|e| e.to_string())?;
            let row = observer
                .query_one(
                    "SELECT $1::integer = ANY(pg_blocking_pids($2))",
                    &[&pid, &delete_pid],
                )
                .await
                .map_err(|e| e.to_string())?;
            require(
                row.get::<_, bool>(0),
                "logout was not blocked by the original preference transaction",
            )?;
            drop(observer);
            require(
                f.counts().await? == (0, 0, 0),
                "uncommitted preference became visible during logout wait",
            )?;
            tx.rollback().await.map_err(|e| e.to_string())?;
            let stored = write
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            require(
                stored.preference() == Preference::Never,
                "preference failed despite current locked original session",
            )?;
            require(
                logout
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|_| "owned logout SQL failed")?
                    == 1,
                "logout did not resume after the original transaction ended",
            )?;
            require(
                f.counts().await? == (1, 1, 1),
                "preference/logout race changed the expected single commit",
            )?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_session_changed_epoch_before_lock_cannot_commit_preference() {
    let admin = harness::admin_config("pref_prior_epoch");
    for mutation in [
        "DELETE FROM public.sessions WHERE id='preference-session-a'",
        "UPDATE public.sessions SET token='replacement-epoch-token',created_at=created_at+interval '1 microsecond' WHERE id='preference-session-a'",
        "UPDATE public.sessions SET auth_generation=1 WHERE id='preference-session-a'",
    ] {
        harness::with_temp_database(&admin, "pref_prior_epoch", |config| async move {
            let f = Fixture::new(config, false, false).await?;
            let before = f.snapshot().await?;
            f.admin
                .get()
                .await
                .map_err(|e| e.to_string())?
                .batch_execute(mutation)
                .await
                .map_err(|e| e.to_string())?;
            require(
                f.repository
                    .write(
                        &f.auth,
                        &BotId::new(BOT),
                        Target::User,
                        Preference::Never,
                        None,
                    )
                    .await
                    == Err(Error::NotVisible),
                "changed original epoch was allowed to commit",
            )?;
            require(
                f.snapshot().await? == before,
                "prior session change altered business or audit",
            )?;
            Ok(())
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL; explicit exact --include-ignored only"]
async fn actual_single_user_uses_verified_canonical_owner_and_exact_pool() {
    harness::with_temp_database(&harness::admin_config("actual_single_user_uses_verified_canonical_owner_and_exact_pool"),
        "pref_single", |config| async move {
        let f=Fixture::new(config,true,false).await?;
        require(f.auth.is_single_user() && f.auth.actor().as_str()==SINGLE_USER_ACTOR_ID
            && f.auth.has_role(Role::Admin) && f.auth.request_binding().is_some(),
            "actual canonical verified SingleUser owner missing")?;
        let principal=load_single_user_principal(&f.pool,DeploymentId::new(DEPLOYMENT),TenantId::new(TENANT))
            .await.map_err(|e|e.to_string())?;
        let actual=SingleUserAuthResolver::from_verified_principal(principal,default_session_lifetime());
        let foreign=DatabasePool::build_unprobed(&f.direct_config).map_err(|e|e.to_string())?;
        let foreign_repository=make_repository(&foreign,DEPLOYMENT,TENANT)?;
        require(actual.install_remember_preference_repository(&foreign_repository).is_err(),
            "equal configuration for another actual Manager was accepted")?;
        let foreign_namespace=make_repository(&f.pool,DEPLOYMENT,"foreign-tenant")?;
        require(actual.install_remember_preference_repository(&foreign_namespace).is_err(),
            "canonical principal accepted foreign repository namespace")?;
        let original=make_repository(&f.pool,DEPLOYMENT,TENANT)?;
        actual.install_remember_preference_repository(&original)
            .map_err(|_|"same original canonical Pool installation failed".to_owned())?;
        let auth=resolve(&actual,None).await?;
        let first=original.write(&auth,&BotId::new(BOT),Target::User,Preference::Never,None)
            .await.map_err(|e|e.to_string())?;
        f.verify_audit(&first,1).await?;
        let before=f.snapshot().await?;
        let c=f.admin.get().await.map_err(|e|e.to_string())?;
        c.execute("DELETE FROM public.user_roles WHERE user_id=$1 AND role='admin'",&[&SINGLE_USER_ACTOR_ID])
            .await.map_err(|e|e.to_string())?;
        drop(c);
        require(original.write(&auth,&BotId::new(BOT),Target::Bot,Preference::Ask,None).await==Err(Error::NotVisible),
            "canonical identity text bypassed current admin role")?;
        let c=f.admin.get().await.map_err(|e|e.to_string())?;
        c.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'admin')",&[&SINGLE_USER_ACTOR_ID])
            .await.map_err(|e|e.to_string())?;
        c.execute("INSERT INTO public.revoked_access(email,revoked_by) VALUES('dev@openbot.local','owned-test')",&[])
            .await.map_err(|e|e.to_string())?;
        drop(c);
        require(original.read(&auth,&BotId::new(BOT),Target::Bot).await==Err(Error::NotVisible),
            "canonical identity bypassed current deny list")?;
        let c=f.admin.get().await.map_err(|e|e.to_string())?;
        c.batch_execute("DELETE FROM public.revoked_access WHERE email='dev@openbot.local';
            UPDATE public.users SET auth_generation=1 WHERE id='dev-local-user'")
            .await.map_err(|e|e.to_string())?;
        drop(c);
        require(original.read(&auth,&BotId::new(BOT),Target::User).await==Err(Error::NotVisible),
            "verified canonical original generation remained current after an actual change")?;
        actual.close_request_bindings();
        require(original.read(&auth,&BotId::new(BOT),Target::User).await==Err(Error::NotVisible),
            "closed original SingleUser owner remained valid")?;
        foreign.close();
        require(f.snapshot().await?==before,"canonical current-authority refusal wrote business or audit")
    }).await;
}
