//! V7-IMPL-040: the system drain of a closed Thread history's in-flight Runs, on an owned
//! PostgreSQL. The close is the real 038 producer on a real Server Session; the stop is consumed
//! by the real run runtime and relay. The fixtures, the consumer, the lock probes and the forged
//! rows are test-owned and grant no authority. Nothing here credits ACK2 clearing, byte deletion
//! or Ready.

#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::{
    BeginThreadRunRequest, CancelThreadRunRequest, CommittedMemoryEffect,
    MemoryAdministrationError, RememberToolMemory, RememberToolMemoryRequest,
    RunCancellationDisposition, RunDispatchConsumer, RunDispatchDecision, RunExecutionLease,
    RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel, RunTerminal, ThreadDirectory,
    ThreadDirectoryError, ToolDecisionDraft, ToolJournal, ToolOutcomeDraft, ToolPortError,
    ToolRefusalDraft, invoke_tool,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{
    BeginThreadRun, CancelThreadRun, ThreadRunAnchor, ThreadRunCancellationState,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{
    ActorId, BotId, CapabilityId, ChannelId, DeploymentId, RunId, TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::tool::{ToolInvocation, ToolResult};
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::tool::pipeline::DurableDecisionReceipt;
use openbot_infra::agent_tools::PostgresBuiltInToolControlPlane;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::db::{fresh, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::thread_history_authority::{
    PostgresThreadHistoryAuthority, ThreadHistoryRunDrain,
    ThreadHistoryStopClearConfirmation as Confirmation, ThreadHistoryStopClearError as Stop,
};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, String>;
type Drain = std::result::Result<ThreadHistoryRunDrain, Stop>;

const DEP: &str = "owned-drain-deployment";
const TENANT: &str = "owned-drain-tenant";
const A: &str = "drain-a";
const B: &str = "drain-b";
const C: &str = "drain-admin";
const BOT: &str = "drain-bot";
const PROCESS: &str = "owned-drain-runtime";
const TEXT: &str = "OWNED_RUN_DRAIN_BODY_CANARY café";
const SESSION_KEY: &[u8] = b"owned-run-drain-session-key";
const AUDIT_KEY: &[u8] = b"owned-run-drain-remember-audit-key";
const CANCEL_SOURCE: &str = "thread_history_closed";

fn check(ok: bool, reason: &str) -> Result {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}
/// The exact counts of one drain call, and a Debug output that leaks no identifier.
fn drained(result: &Drain, j: &str, operation: &str, counts: (usize, usize, usize)) -> Result {
    let drain = result
        .as_ref()
        .map_err(|error| format!("the drain refused: {error:?}"))?;
    let seen = (
        drain.newly_requested(),
        drain.already_requested(),
        drain.outstanding_nonterminal(),
    );
    check(
        drain.operation_id() == operation
            && seen == counts
            && drain.is_complete() == (counts.2 == 0),
        &format!("drain result {seen:?} is not the expected {counts:?}"),
    )?;
    let shown = format!("{drain:?}");
    check(
        !shown.contains(operation) && !shown.contains(j) && !shown.contains(&seen.0.to_string()),
        "the drain's Debug output leaks an identifier or a count",
    )
}
fn unavailable(result: &Drain) -> Result {
    check(
        matches!(result, Err(Stop::Unavailable)),
        &format!(
            "expected exact Unavailable, got {:?}",
            result.as_ref().err()
        ),
    )
}
fn not_visible(result: &Drain) -> Result {
    check(
        matches!(result, Err(Stop::NotVisible)),
        &format!("expected exact NotVisible, got {:?}", result.as_ref().err()),
    )
}
fn corrupt(result: &Drain, field: &'static str) -> Result {
    check(
        matches!(result, Err(Stop::Corrupt { field: seen }) if *seen == field),
        &format!("expected Corrupt {field}, got {:?}", result.as_ref().err()),
    )
}

/// A test-owned dispatch consumer. It never starts a model or a tool: it only records what the
/// relay asked of it, and answers a cancellation with a local child only for a Run it was told
/// to signal.
#[derive(Default)]
struct Consumer {
    signalled: Mutex<HashSet<String>>,
    revoked: Mutex<Vec<String>>,
    dispatched: Mutex<Vec<String>>,
}
impl Consumer {
    fn signal(&self, run: &str) {
        self.signalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(run.to_owned());
    }
    fn revoked(&self) -> Vec<String> {
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    fn dispatched(&self) -> Vec<String> {
        self.dispatched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
#[async_trait]
impl RunDispatchConsumer for Consumer {
    async fn dispatch(&self, lease: RunExecutionLease) -> RunDispatchDecision {
        self.dispatched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(lease.run_id().as_str().to_owned());
        RunDispatchDecision::RetryableBusy
    }
    async fn activate(&self, _: &RunExecutionLease) -> std::result::Result<(), RunFailureCode> {
        Ok(())
    }
    async fn revoke(&self, lease: &RunExecutionLease) -> RunCancellationDisposition {
        let run = lease.run_id().as_str().to_owned();
        self.revoked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(run.clone());
        if self
            .signalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&run)
        {
            RunCancellationDisposition::ChildSignalled
        } else {
            RunCancellationDisposition::NoLocalChild
        }
    }
}

/// A Run that was begun and whose dispatch was claimed and acknowledged: it holds the lease.
struct Flight {
    req: BeginThreadRunRequest,
    j: String,
    run: String,
    runtime: PostgresRunRuntime,
    lease: RunExecutionLease,
}

struct Fixture {
    pool: pool::DatabasePool,
    config: pool::DatabaseConfig,
    registry: Arc<ArtifactDatasetRegistry>,
    authority: Arc<PostgresThreadHistoryAuthority>,
    resolver: Arc<PostgresSessionAuthResolver>,
    directory: PostgresThreadDirectory,
}
impl Fixture {
    async fn new(config: pool::DatabaseConfig, generation: u64) -> Result<Self> {
        let config = config.with_max_pool_size(12);
        let pool = pool::connect(&config).await.map_err(text)?;
        {
            let mut c = pool.get().await.map_err(text)?;
            fresh::apply(&mut c).await.map_err(text)?;
            let g = i64::try_from(generation).map_err(text)?;
            for (actor, email, role) in [
                (A, "drain-a@example.test", "user"),
                (B, "drain-b@example.test", "user"),
                (C, "drain-admin@example.test", "admin"),
            ] {
                c.execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,$3)",
                    &[&actor, &email, &g],
                )
                .await
                .map_err(text)?;
                c.execute(
                    "INSERT INTO public.user_roles(user_id,role) VALUES($1,$2::text::public.role)",
                    &[&actor, &role],
                )
                .await
                .map_err(text)?;
            }
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('drain-bot','Drain bot','built_in','{\"systemPrompt\":\"Owned drain prompt\",\"providerSource\":\"managed\"}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('drain-bot','drain-a','Drain bot','','drain','public');").await.map_err(text)?;
            let now = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            for (actor, index) in [(A, 1_u8), (B, 1), (C, 1)] {
                let id = format!("{actor}-session-{index}");
                let cookie = format!("owned-drain-cookie-{actor}-{index:02}");
                let hash = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,$6)",&[&id,&actor,&hash,&(now+time::Duration::hours(1)),&now,&g]).await.map_err(text)?;
            }
        }
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                pool.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(text)?,
        );
        let authority = Arc::new(
            PostgresThreadHistoryAuthority::new(
                pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(text)?,
        );
        authority
            .enroll_original_registry(&registry)
            .map_err(text)?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                openbot_infra::auth::config::default_session_lifetime(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .map_err(text)?,
        );
        resolver
            .install_thread_history_authority(&authority)
            .map_err(text)?;
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(text)?;
        Ok(Self {
            pool,
            config,
            registry,
            authority,
            resolver,
            directory,
        })
    }
    async fn auth(&self, actor: &str, index: u8) -> Result<AuthContext> {
        self.resolver
            .resolve(
                &http::Request::builder()
                    .uri("/owned-drain")
                    .header(
                        "cookie",
                        format!("openbot_session=owned-drain-cookie-{actor}-{index:02}"),
                    )
                    .body(())
                    .map_err(text)?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(text)
    }
    async fn sql(&self, sql: &str) -> Result {
        self.pool
            .get()
            .await
            .map_err(text)?
            .batch_execute(sql)
            .await
            .map_err(text)
    }
    async fn one<T: tokio_postgres::types::FromSqlOwned>(&self, sql: &str, key: &str) -> Result<T> {
        self.pool
            .get()
            .await
            .map_err(text)?
            .query_one(sql, &[&key])
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    /// One boolean database fact about one key, for polling a background relay.
    async fn holds(&self, sql: &str, key: &str) -> Result<bool> {
        self.one(sql, key).await
    }
    fn request(
        &self,
        auth: &AuthContext,
        index: u64,
        anchor: ThreadRunAnchor,
    ) -> BeginThreadRunRequest {
        let mut entropy = [0; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunRequest {
            deployment: auth.deployment().clone(),
            tenant: auth.tenant().clone(),
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            command: BeginThreadRun {
                thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-drain-run-{index}")),
                bot_id: BotId::new(BOT),
                anchor,
                message: TEXT.into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        }
    }
    /// A new direct Thread of the actor with its first Run begun (not yet claimed).
    async fn begin(&self, auth: &AuthContext, index: u64) -> Result<BeginThreadRunRequest> {
        let req = self.request(auth, index, ThreadRunAnchor::DirectBot);
        self.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(text)?;
        Ok(req)
    }
    /// A further new Run on the same Thread; only a closed head can make this refuse.
    async fn begin_again(&self, req: &BeginThreadRunRequest, run: &str) -> Result {
        let mut again = req.clone();
        again.command.run_id = RunId::new(run);
        self.directory
            .begin_thread_run(again)
            .await
            .map(|_| ())
            .map_err(text)
    }
    async fn claim(&self, run: &str) -> Result<(PostgresRunRuntime, RunExecutionLease)> {
        let runtime = PostgresRunRuntime::new(
            self.pool.clone(),
            PROCESS.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(text)?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(text)?
            .ok_or("pending real dispatch absent")?;
        let lease = runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
        check(
            lease.run_id().as_str() == run,
            "a different run was claimed",
        )?;
        Ok((runtime, lease))
    }
    fn flight(
        req: BeginThreadRunRequest,
        runtime: PostgresRunRuntime,
        lease: RunExecutionLease,
    ) -> Flight {
        Flight {
            j: req.command.thread_id.as_str().to_owned(),
            run: req.command.run_id.as_str().to_owned(),
            req,
            runtime,
            lease,
        }
    }
    /// A new direct Thread whose only Run is in flight: begun, dispatched and leased.
    async fn in_flight(&self, auth: &AuthContext, index: u64) -> Result<Flight> {
        let req = self.begin(auth, index).await?;
        let (runtime, lease) = self.claim(req.command.run_id.as_str()).await?;
        Ok(Self::flight(req, runtime, lease))
    }
    /// A private agent channel of the creator with the other actors added as members.
    async fn channel(&self, creator: &AuthContext, members: &[&str]) -> Result<(String, String)> {
        let created = openbot_application::create_channel(
            &ChannelRepo::new(self.pool.clone()),
            creator,
            vec![BotId::new(BOT)],
        )
        .await
        .map_err(text)?;
        let channel: String = created.id.as_str().into();
        for member in members {
            self.sql(&format!(
                "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('{channel}','{member}')"
            ))
            .await?;
        }
        let thread = created
            .thread_id
            .ok_or("channel producer did not mint a Thread")?;
        Ok((channel, thread.as_str().into()))
    }
    /// A member's Run in a channel Thread, in flight.
    async fn channel_in_flight(
        &self,
        member: &AuthContext,
        index: u64,
        channel: &str,
        j: &str,
    ) -> Result<Flight> {
        let mut req = self.request(
            member,
            index,
            ThreadRunAnchor::Channel {
                channel_id: ChannelId::new(channel),
            },
        );
        req.command.thread_id = ThreadId::new(j);
        self.directory
            .begin_thread_run(req.clone())
            .await
            .map_err(text)?;
        let (runtime, lease) = self.claim(req.command.run_id.as_str()).await?;
        Ok(Self::flight(req, runtime, lease))
    }
    /// The real 038 producer on the creator's real Session: returns the request and operation.
    async fn close(&self, creator: &AuthContext, j: &str) -> Result<(String, String)> {
        let request = Uuid::now_v7().to_string();
        let intent = self
            .authority
            .close_for_stop_clear_before(creator, j, &request, deadline())
            .await
            .map_err(|error| format!("the real ACK1 was refused: {error:?}"))?;
        check(
            intent.confirmation() == Confirmation::CommitAcknowledged
                && intent.thread_id().as_str() == j
                && intent.request_id() == request,
            "the close is not the acknowledged commit for this Thread and request",
        )?;
        let operation = intent.operation_id().to_owned();
        let stored: String = self
            .one(
                "SELECT closure_operation_id FROM openbot_internal.thread_history_heads \
                 WHERE thread_id=$1 AND phase='closed'",
                j,
            )
            .await?;
        check(
            stored == operation,
            "the head is not closed by the returned intent",
        )?;
        Ok((request, operation))
    }
    async fn drain(&self, j: &str) -> Drain {
        self.authority
            .drain_closed_history_runs_before(j, deadline())
            .await
    }
    fn relay(&self, consumer: &Arc<Consumer>) -> Result<RunRelay> {
        let runtime: Arc<dyn RunRuntime> = Arc::new(
            PostgresRunRuntime::new(
                self.pool.clone(),
                PROCESS.into(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(text)?,
        );
        let consumer: Arc<dyn RunDispatchConsumer> = consumer.clone();
        Ok(RunRelay::start(runtime, consumer))
    }
    async fn run_status(&self, run: &str) -> Result<String> {
        self.one("SELECT status FROM public.runs WHERE run_id=$1", run)
            .await
    }
    async fn is_status(&self, run: &str, status: &str) -> Result<bool> {
        Ok(self.run_status(run).await? == status)
    }
    async fn cancel_status(&self, run: &str) -> Result<String> {
        self.one(
            "SELECT status FROM public.outbox WHERE outbox_id=$1",
            &format!("{run}:agent_run_cancel"),
        )
        .await
    }
    async fn cancel_is(&self, run: &str, status: &str) -> Result<bool> {
        Ok(self.cancel_status(run).await? == status)
    }
    /// One Run's cancellation acceptance exactly as stored, with its row version.
    async fn acceptance(&self, run: &str) -> Result<Option<Value>> {
        let row = self
            .pool
            .get()
            .await
            .map_err(text)?
            .query_opt(
                "SELECT jsonb_build_object('outbox_id',o.outbox_id,'aggregate_kind',o.aggregate_kind,\
                 'aggregate_id',o.aggregate_id,'seq',o.seq,'destination',o.destination,\
                 'delivery_class',o.delivery_class,'payload',o.payload,'status',o.status,\
                 'claimed_by',o.claimed_by,'last_error_code',o.last_error_code,'xmin',o.xmin::text) \
                 FROM public.outbox o WHERE o.outbox_id=$1",
                &[&format!("{run}:agent_run_cancel")],
            )
            .await
            .map_err(text)?;
        row.map(|r| r.try_get(0).map_err(text)).transpose()
    }
    /// Every cancellation acceptance with its row version: any rewrite or new row changes this.
    async fn acceptances(&self) -> Result<Value> {
        self.pool
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT coalesce(jsonb_agg(to_jsonb(o)||jsonb_build_object('xmin',o.xmin::text) ORDER BY o.outbox_id),'[]'::jsonb) \
                 FROM public.outbox o WHERE o.destination='agent_run_cancel'",
                &[],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    async fn cancel_rows(&self) -> Result<i64> {
        self.pool
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT count(*) FROM public.outbox WHERE destination='agent_run_cancel'",
                &[],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)
    }
    /// Every original fact except H, Q and the cancellation acceptances; a drain changes none.
    async fn facts(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(text)?;
        let mut out = serde_json::Map::new();
        for table in [
            "public.users",
            "public.user_roles",
            "public.revoked_access",
            "public.sessions",
            "public.threads",
            "public.thread_memberships",
            "public.channels",
            "public.channel_memberships",
            "public.channel_agents",
            "public.messages",
            "public.runs",
            "public.run_events",
            "public.thread_leases",
            "public.thread_run_occupancy",
            "public.outbox",
            "openbot_internal.thread_origins",
        ] {
            let filter = if table == "public.outbox" {
                "WHERE t.destination<>'agent_run_cancel'"
            } else {
                ""
            };
            let sql = format!(
                "SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM {table} t {filter}) q"
            );
            let value: Value = c
                .query_one(&sql, &[])
                .await
                .map_err(text)?
                .try_get(0)
                .map_err(text)?;
            out.insert(table.into(), value);
        }
        Ok(Value::Object(out))
    }
    /// Both whole tables with row versions: any rewrite, new row or repair changes this value.
    async fn hq(&self) -> Result<Value> {
        let c = self.pool.get().await.map_err(text)?;
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
    async fn cancel_as(
        &self,
        who: &str,
        j: &str,
        run: &str,
    ) -> std::result::Result<ThreadRunCancellationState, ThreadDirectoryError> {
        self.directory
            .cancel_thread_run(CancelThreadRunRequest {
                deployment: DeploymentId::new(DEP),
                tenant: TenantId::new(TENANT),
                actor: ActorId::new(who),
                command: CancelThreadRun {
                    thread_id: ThreadId::new(j),
                    run_id: RunId::new(run),
                },
            })
            .await
            .map(|reply| reply.state)
    }
    /// The Run ended cancelled on the closed-history path: the fixed payload, no body, no code.
    async fn ended_cancelled_without_body(&self, run: &str) -> Result {
        check(
            self.run_status(run).await? == "cancelled",
            "the Run did not end cancelled",
        )?;
        let payload: Value = self
            .one(
                "SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",
                run,
            )
            .await?;
        check(
            payload == json!({"status": "cancelled"}),
            "the terminal payload is not the fixed cancelled payload",
        )?;
        let terminals: i64 = self
            .one(
                "SELECT count(*) FROM public.run_events WHERE run_id=$1 AND terminal",
                run,
            )
            .await?;
        let bodies: i64 = self
            .one(
                "SELECT count(*) FROM public.messages WHERE run_id=$1 AND role='assistant'",
                run,
            )
            .await?;
        let code: Option<String> = self
            .one("SELECT error_code FROM public.runs WHERE run_id=$1", run)
            .await?;
        check(
            terminals == 1 && bodies == 0 && code.is_none(),
            "the cancelled Run has more than one terminal, a body or an error code",
        )
    }
    /// A forged cancellation acceptance row of the given payload, pending.
    async fn forge(&self, run: &str, payload: &Value) -> Result {
        self.pool
            .get()
            .await
            .map_err(text)?
            .execute(
                "INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,\
                 delivery_class,payload) VALUES($1,'run',$2,0,'agent_run_cancel','internal',$3)",
                &[&format!("{run}:agent_run_cancel"), &run, payload],
            )
            .await
            .map_err(text)
            .map(|_| ())
    }
    /// A held transaction that has locked one Run row with this lock clause.
    async fn hold_run(&self, run: &str, clause: &str) -> Result<pool::PooledClient> {
        let held = self.pool.get().await.map_err(text)?;
        held.batch_execute("BEGIN").await.map_err(text)?;
        held.batch_execute(&format!(
            "SELECT 1 FROM public.runs WHERE run_id='{run}' {clause}"
        ))
        .await
        .map_err(text)?;
        Ok(held)
    }
    /// A connection of its own that listens on the run control channel of the relay wakeups.
    async fn listen(&self, channel: &str) -> Result<Listener> {
        let mut config = tokio_postgres::Config::new();
        config
            .host(&self.config.host)
            .port(self.config.port)
            .user(&self.config.user)
            .dbname(&self.config.dbname);
        if let Some(password) = &self.config.password {
            config.password(password);
        }
        let (client, mut connection) = config.connect(tokio_postgres::NoTls).await.map_err(text)?;
        let (sender, notifications) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(message) = std::future::poll_fn(|cx| connection.poll_message(cx)).await {
                match message {
                    Ok(tokio_postgres::AsyncMessage::Notification(note)) => {
                        let pair = (note.channel().to_owned(), note.payload().to_owned());
                        if sender.send(pair).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        client
            .batch_execute(&format!("LISTEN {channel}"))
            .await
            .map_err(text)?;
        Ok(Listener {
            _client: client,
            notifications,
            task,
        })
    }
    async fn finish(self) -> Result {
        self.resolver.close_request_bindings();
        drop(self.directory);
        drop(self.authority);
        drop(self.registry);
        drop(self.resolver);
        close_pool(self.pool).await
    }
}
/// The notifications of one listening connection, in the order the server delivered them.
struct Listener {
    _client: tokio_postgres::Client,
    notifications: tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    task: tokio::task::JoinHandle<()>,
}
impl Listener {
    async fn next(&mut self) -> Result<(String, String)> {
        tokio::time::timeout(Duration::from_secs(3), self.notifications.recv())
            .await
            .map_err(|_| "no notification arrived".to_owned())?
            .ok_or_else(|| "the listening connection ended".to_owned())
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn release(held: pool::PooledClient) -> Result {
    held.batch_execute("ROLLBACK").await.map_err(text)
}
async fn close_pool(p: pool::DatabasePool) -> Result {
    let observations = p.connection_observations();
    p.close();
    for o in observations {
        check(
            o.wait_for_destruction_before(Instant::now() + Duration::from_secs(10))
                .await
                .map_err(text)?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "own connection destruction unobserved",
        )?;
    }
    Ok(())
}
async fn owned<F, Fut>(tag: &str, generation: u64, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config, generation).await?;
        body(f).await
    })
    .await;
}
/// Polls a durable effect of the background relay; the relay offers no hook to wait on.
async fn until<F, Fut>(what: &str, mut probe: F) -> Result
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if probe().await? {
            return Ok(());
        }
        check(Instant::now() < end, &format!("timed out waiting: {what}"))?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
/// No other backend of this database is running a statement or holds an open transaction: a
/// connection that the drain gave up is gone and no longer holds its Run lock.
async fn quiesced(f: &Fixture) -> Result {
    until("every other backend is idle", || async {
        let busy: i64 = f
            .pool
            .get()
            .await
            .map_err(text)?
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() \
                 AND pid<>pg_backend_pid() AND state IN ('active','idle in transaction')",
                &[],
            )
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        Ok(busy == 0)
    })
    .await
}
async fn backend_pid(c: &pool::PooledClient) -> Result<i32> {
    c.query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)
}
/// A compact view of the other backends, only for a failed wait probe's message.
async fn activity_snapshot(pool: &pool::DatabasePool) -> Result<String> {
    let c = pool.get().await.map_err(text)?;
    let rows = c
        .query(
            "SELECT pid,state,coalesce(wait_event_type,''),coalesce(wait_event,''),pg_blocking_pids(pid)::text,left(query,90) \
             FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'",
            &[],
        )
        .await
        .map_err(text)?;
    Ok(rows
        .iter()
        .map(|r| {
            format!(
                "[{} {} {}/{} blocked_by={} {}]",
                r.get::<_, i32>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2),
                r.get::<_, String>(3),
                r.get::<_, String>(4),
                r.get::<_, String>(5)
            )
        })
        .collect::<Vec<_>>()
        .join(" "))
}
/// Polls the real server for a backend that is Lock-waiting behind `blocker` on this statement.
/// The wait itself is the evidence; a poll interval stands in for no lock fact.
async fn wait_blocked(pool: &pool::DatabasePool, blocker: i32, statement: &str) -> Result<i32> {
    let until = Instant::now() + Duration::from_secs(3);
    let pattern = format!("%{statement}%");
    loop {
        let c = pool.get().await.map_err(text)?;
        let r = c
            .query_opt(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() \
                 AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) \
                 AND query LIKE $2 AND pid<>pg_backend_pid() LIMIT 1",
                &[&blocker, &pattern],
            )
            .await
            .map_err(text)?;
        if let Some(r) = r {
            return r.try_get(0).map_err(text);
        }
        drop(c);
        if Instant::now() >= until {
            let seen = activity_snapshot(pool).await?;
            return Err(format!(
                "real lock wait on `{statement}` never reached; blocker {blocker}; backends: {seen}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
/// A pre-0050 Thread has no head yet. Only an owned superuser transaction may remove one.
async fn drop_head(f: &Fixture, j: &str) -> Result {
    let mut c = f.pool.get().await.map_err(text)?;
    let tx = c.transaction().await.map_err(text)?;
    tx.batch_execute("ALTER TABLE openbot_internal.thread_history_heads DISABLE TRIGGER USER")
        .await
        .map_err(text)?;
    let removed = tx
        .execute(
            "DELETE FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
            &[&j],
        )
        .await
        .map_err(text)?;
    // The delete queued deferred reference checks; fire them before the table may be altered.
    tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
        .await
        .map_err(text)?;
    tx.batch_execute("ALTER TABLE openbot_internal.thread_history_heads ENABLE TRIGGER USER")
        .await
        .map_err(text)?;
    check(
        removed == 1,
        "owned head removal did not hit exactly one row",
    )?;
    tx.commit().await.map_err(text)
}
/// A non-foreground running Run of the same Thread, bound to the Thread lease the Flight holds,
/// with the delivered dispatch row that every unstarted cancellation settles. It is a fixture:
/// production begins exactly one foreground Run per Thread.
async fn background_running_run(f: &Fixture, of: &Flight, run: &str, dispatch_seq: i64) -> Result {
    f.sql(&format!(
        "INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at) \
         SELECT '{run}',thread_id,bot_id,actor_id,false,'running',fencing_token,0,clock_timestamp(),clock_timestamp() \
         FROM public.runs WHERE run_id='{origin}'; \
         INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload,status,delivered_at) \
         VALUES('{run}:agent_run_dispatch','thread','{j}',{dispatch_seq},'agent_run_dispatch','internal',\
         '{{\"runId\":\"{run}\",\"threadId\":\"{j}\",\"eventSequence\":{dispatch_seq}}}'::jsonb,'delivered',clock_timestamp())",
        origin = of.run,
        j = of.j,
    ))
    .await
}

// ---------------------------------------------------------------------------------------------
// D01
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_cancels_other_members_in_flight_run_after_real_ack1_without_body()
{
    owned("drain01", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let (channel, j) = f.channel(&a, &[B]).await?;
        // The other member's Run is in flight and has streamed a chunk while the history was open.
        let member = f.channel_in_flight(&b, 101, &channel, &j).await?;
        let run = member.run.clone();
        let seq = member.lease.next_event_sequence();
        member
            .runtime
            .append_semantic_chunk(
                &member.lease,
                seq,
                RunSemanticChannel::Text,
                "BODY_ACCEPTED_WHILE_OPEN",
            )
            .await
            .map_err(text)?;
        // Another Thread of the creator stays open with its own Run in flight: not this J's.
        let elsewhere = f.in_flight(&a, 102).await?;
        let mut control = f.listen("openbot_run_control").await?;
        // The real ACK1 by the creator closes J. It stops nothing.
        let (_, operation) = f.close(&a, &j).await?;
        check(
            f.cancel_rows().await? == 0 && f.run_status(&run).await? == "running",
            "ACK1 alone wrote a cancellation or ended the Run",
        )?;
        // The drain is a system action: it needs neither the creator's Session nor their access.
        f.sql("DELETE FROM public.sessions WHERE user_id='drain-a'; \
               INSERT INTO public.revoked_access(email,revoked_by) VALUES('drain-a@example.test','drain-admin')")
            .await?;
        let (facts, hq) = (f.facts().await?, f.hq().await?);
        let result = f.drain(&j).await;
        drained(&result, &j, &operation, (1, 0, 1))?;
        // The same channel and payload as the user's producer wake the relay.
        check(
            control.next().await? == ("openbot_run_control".to_owned(), String::new()),
            "the drain did not notify the run control channel",
        )?;
        // The one acceptance has exactly the four system keys, the operation and no requester.
        let accepted = f.acceptance(&run).await?.ok_or("no acceptance was written")?;
        let payload = &accepted["payload"];
        check(
            *payload
                == json!({"runId": run, "threadId": j, "source": CANCEL_SOURCE, "operationId": operation})
                && payload.as_object().map(serde_json::Map::len) == Some(4)
                && payload.get("requestedBy").is_none()
                && accepted["status"] == "pending"
                && accepted["outbox_id"] == format!("{run}:agent_run_cancel")
                && accepted["aggregate_kind"] == "run"
                && accepted["aggregate_id"] == run.as_str()
                && accepted["seq"] == 0
                && accepted["destination"] == "agent_run_cancel"
                && accepted["delivery_class"] == "internal",
            "the acceptance is not the exact system shape",
        )?;
        check(
            f.cancel_rows().await? == 1
                && facts == f.facts().await?
                && hq == f.hq().await?
                && f.acceptance(&elsewhere.run).await?.is_none()
                && f.is_status(&elsewhere.run, "running").await?,
            "the drain wrote anything but the one acceptance, or touched another Thread",
        )?;
        // The existing consumer ends the other member's Run cancelled, with no body.
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("the other member's Run is cancelled", || {
            f.is_status(&run, "cancelled")
        })
        .await?;
        until("the acceptance is delivered", || f.cancel_is(&run, "delivered")).await?;
        relay.stop().await;
        f.ended_cancelled_without_body(&run).await?;
        check(
            consumer.revoked() == vec![run.clone()]
                && f.one::<String>(
                    "SELECT status FROM public.outbox WHERE outbox_id=$1",
                    &format!("{run}:agent_run_dispatch"),
                )
                .await?
                    == "delivered"
                && f.is_status(&elsewhere.run, "running").await?
                && f.acceptance(&elsewhere.run).await?.is_none(),
            "the relay did not revoke exactly this Run, or reached another Thread",
        )?;
        // Done: nothing is outstanding and a rerun finds nothing to do.
        let again = f.drain(&j).await;
        drained(&again, &j, &operation, (0, 0, 0))?;
        // Neither the consumer nor the rerun woke the control channel again: the next
        // notification in order is the sentinel sent now.
        f.sql("SELECT pg_notify('openbot_run_control','sentinel')").await?;
        check(
            control.next().await?.1 == "sentinel",
            "a later step notified the run control channel",
        )?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D01 acceptance_keys=4 requested_by_absent=true operation_is_q=true notified=openbot_run_control no_session_no_access_needed=true terminal_payload_cancelled=true assistant_messages=0 other_thread_untouched=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D02
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_member_cannot_cancel_another_members_run_and_own_cancel_observes_system_request()
 {
    owned("drain02", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let (channel, j) = f.channel(&a, &[B, C]).await?;
        let member = f.channel_in_flight(&b, 201, &channel, &j).await?;
        let run = member.run.clone();
        let not_visible_to = |who: &'static str| {
            let (f, j, run) = (&f, j.clone(), run.clone());
            async move {
                check(
                    matches!(
                        f.cancel_as(who, &j, &run).await,
                        Err(ThreadDirectoryError::NotVisible)
                    ),
                    &format!("{who} could cancel another member's Run"),
                )
            }
        };
        // The ordinary rule: neither the creator nor an admin member may cancel another's Run.
        not_visible_to(A).await?;
        not_visible_to(C).await?;
        let (_, operation) = f.close(&a, &j).await?;
        not_visible_to(A).await?;
        not_visible_to(C).await?;
        check(f.cancel_rows().await? == 0, "a refused cancel wrote an acceptance")?;
        drained(&f.drain(&j).await, &j, &operation, (1, 0, 1))?;
        // The stop grants nobody anything: still not visible to the creator or the admin.
        not_visible_to(A).await?;
        not_visible_to(C).await?;
        let system = f.acceptance(&run).await?.ok_or("no system acceptance")?;
        // The Run's own member asking now observes the existing system request: no Corrupt, no
        // second row, and the stored system acceptance is neither replaced nor rewritten.
        check(
            matches!(
                f.cancel_as(B, &j, &run).await,
                Ok(ThreadRunCancellationState::AlreadyRequested)
            ),
            "the member's own cancel did not observe the system request",
        )?;
        check(
            f.acceptance(&run).await?.as_ref() == Some(&system) && f.cancel_rows().await? == 1,
            "the member's own cancel replaced or duplicated the system acceptance",
        )?;

        // The other direction: the user's own request first. The drain counts it as already
        // requested, keeps it the user's, and the consumer ends the Run on the user's shape.
        let own = f.in_flight(&a, 202).await?;
        check(
            matches!(
                f.cancel_as(A, &own.j, &own.run).await,
                Ok(ThreadRunCancellationState::Requested)
            ),
            "the creator's own cancel was not requested",
        )?;
        let user = f.acceptance(&own.run).await?.ok_or("no user acceptance")?;
        check(
            user["payload"] == json!({"runId": own.run, "threadId": own.j, "requestedBy": A}),
            "the user's acceptance is not the user shape",
        )?;
        let (_, own_operation) = f.close(&a, &own.j).await?;
        drained(&f.drain(&own.j).await, &own.j, &own_operation, (0, 1, 1))?;
        check(
            f.acceptance(&own.run).await?.as_ref() == Some(&user),
            "the drain overwrote or rewrote the user's own request",
        )?;

        // Forged system acceptances are consumed only for a Thread closed by exactly that
        // intent: another operation, another Thread's operation and an open Thread are all
        // dead-lettered as a scope binding and their Runs keep running.
        let forged_closed = f.in_flight(&a, 203).await?;
        let forged_other = f.in_flight(&a, 204).await?;
        let forged_open = f.in_flight(&a, 205).await?;
        f.close(&a, &forged_closed.j).await?;
        let (_, borrowed) = f.close(&a, &forged_other.j).await?;
        let stranger = Uuid::now_v7().to_string();
        for (flight, operation) in [
            (&forged_closed, stranger.as_str()),
            (&forged_other, operation.as_str()),
            (&forged_open, borrowed.as_str()),
        ] {
            f.forge(
                &flight.run,
                &json!({"runId": flight.run, "threadId": flight.j, "source": CANCEL_SOURCE, "operationId": operation}),
            )
            .await?;
        }
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        for flight in [&forged_closed, &forged_other, &forged_open] {
            until("a forged system acceptance is dead-lettered", || {
                f.holds(
                    "SELECT status='dead_letter' AND last_error_code='cancel_scope_binding' \
                     FROM public.outbox WHERE outbox_id=$1::text||':agent_run_cancel'",
                    &flight.run,
                )
            })
            .await?;
        }
        // The two real requests are consumed meanwhile, the forged ones never.
        until("the member's and the creator's Runs are cancelled", || async {
            Ok(f.is_status(&run, "cancelled").await? && f.is_status(&own.run, "cancelled").await?)
        })
        .await?;
        relay.stop().await;
        f.ended_cancelled_without_body(&run).await?;
        f.ended_cancelled_without_body(&own.run).await?;
        let revoked = consumer.revoked();
        for flight in [&forged_closed, &forged_other, &forged_open] {
            check(
                f.is_status(&flight.run, "running").await? && !revoked.contains(&flight.run),
                "a forged system acceptance stopped a Run",
            )?;
        }
        // After the terminal the user's cancel is a closed observation.
        check(
            matches!(
                f.cancel_as(B, &j, &run).await,
                Ok(ThreadRunCancellationState::AlreadyTerminal)
            ) && matches!(
                f.cancel_as(A, &own.j, &own.run).await,
                Ok(ThreadRunCancellationState::AlreadyTerminal)
            ),
            "a cancel after the terminal was not a closed observation",
        )?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D02 creator_and_admin_not_visible=true member_own_cancel=AlreadyRequested system_row_untouched=true user_request_kept=true forged_system_dead_letters=3 forged_runs_stopped=0"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D03
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_rerun_is_idempotent_and_writes_nothing() {
    owned("drain03", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let flight = f.in_flight(&a, 301).await?;
        let (_, operation) = f.close(&a, &flight.j).await?;
        drained(&f.drain(&flight.j).await, &flight.j, &operation, (1, 0, 1))?;
        let (facts, hq, rows) = (f.facts().await?, f.hq().await?, f.acceptances().await?);
        // Rerun again and again: the Run is already requested and nothing is written, not even
        // a rewritten row version.
        for _ in 0..3 {
            drained(&f.drain(&flight.j).await, &flight.j, &operation, (0, 1, 1))?;
            check(
                facts == f.facts().await?
                    && hq == f.hq().await?
                    && rows == f.acceptances().await?,
                "a rerun wrote a row, a version or another fact",
            )?;
        }
        // Concurrent callers on a fresh Thread whose Run was begun but never dispatched: whoever
        // holds the Run lock writes the one acceptance; each other call is either Unavailable or
        // already requested.
        let racing_req = f.begin(&a, 302).await?;
        let racing_j = racing_req.command.thread_id.as_str().to_owned();
        let racing_run = racing_req.command.run_id.as_str().to_owned();
        let dispatch = format!("{racing_run}:agent_run_dispatch");
        check(
            f.one::<String>("SELECT status FROM public.outbox WHERE outbox_id=$1", &dispatch)
                .await?
                == "pending",
            "premise: the racing Run's dispatch is still pending",
        )?;
        let (_, racing_operation) = f.close(&a, &racing_j).await?;
        let calls = (0..4)
            .map(|_| {
                let authority = Arc::clone(&f.authority);
                let j = racing_j.clone();
                tokio::spawn(async move {
                    authority
                        .drain_closed_history_runs_before(&j, deadline())
                        .await
                })
            })
            .collect::<Vec<_>>();
        let mut newly = 0;
        for call in calls {
            match call.await.map_err(text)? {
                Ok(drain) => {
                    check(
                        drain.operation_id() == racing_operation
                            && drain.outstanding_nonterminal() == 1,
                        "a concurrent drain reported another operation or count",
                    )?;
                    newly += drain.newly_requested();
                }
                Err(Stop::Unavailable) => {}
                Err(other) => return Err(format!("a concurrent drain was {other:?}")),
            }
        }
        check(
            newly == 1 && f.acceptance(&racing_run).await?.is_some(),
            "the concurrent drains did not write exactly one acceptance",
        )?;
        drained(&f.drain(&racing_j).await, &racing_j, &racing_operation, (0, 1, 1))?;
        // The consumer ends both Runs: the dispatched one, and the one that never started, whose
        // dispatch is settled by its cancellation instead of ever reaching the consumer. A rerun
        // is then complete and still writes nothing.
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("both Runs are cancelled and delivered", || async {
            Ok(f.cancel_is(&flight.run, "delivered").await?
                && f.cancel_is(&racing_run, "delivered").await?)
        })
        .await?;
        relay.stop().await;
        f.ended_cancelled_without_body(&racing_run).await?;
        let (settled, settled_rows) = (f.facts().await?, f.acceptances().await?);
        drained(&f.drain(&flight.j).await, &flight.j, &operation, (0, 0, 0))?;
        drained(&f.drain(&racing_j).await, &racing_j, &racing_operation, (0, 0, 0))?;
        check(
            settled == f.facts().await?
                && settled_rows == f.acceptances().await?
                && f.one::<String>("SELECT status FROM public.outbox WHERE outbox_id=$1", &dispatch)
                    .await?
                    == "delivered"
                && consumer.dispatched().is_empty(),
            "a complete rerun wrote, or the relay dispatched a stopped Run",
        )?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D03 reruns=3 row_versions_unchanged=true concurrent_callers=4 acceptances_written=1 unstarted_run_never_dispatched=true complete_rerun_writes_nothing=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D04
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_resumes_after_contended_run_and_completes_when_no_nonterminal_run()
 {
    owned("drain04", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let b = f.auth(B, 1).await?;
        let (channel, j) = f.channel(&a, &[B]).await?;
        // Two Runs can act in this Thread only as a fixture: the member's real Run, and a
        // later non-foreground running Run bound to the same lease.
        let first = f.channel_in_flight(&b, 401, &channel, &j).await?;
        background_running_run(&f, &first, "owned-drain-run-402", 424_242).await?;
        let second = "owned-drain-run-402";
        let (_, operation) = f.close(&a, &j).await?;
        // The second Run is held by a real writer-style lock: the call stops there, Unavailable.
        let held = f.hold_run(second, "FOR UPDATE").await?;
        let result = f.drain(&j).await;
        unavailable(&result)?;
        check(
            f.acceptance(&first.run).await?.is_some() && f.acceptance(second).await?.is_none(),
            "committed progress was not kept, or the contended Run was written",
        )?;
        let progress = f.acceptance(&first.run).await?;
        release(held).await?;
        // Resume: the first stays as it is, the second is written, both remain outstanding.
        drained(&f.drain(&j).await, &j, &operation, (1, 1, 2))?;
        check(
            f.acceptance(&first.run).await? == progress && f.cancel_rows().await? == 2,
            "the resumed drain rewrote the committed acceptance",
        )?;
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("both Runs are cancelled", || async {
            Ok(f.is_status(&first.run, "cancelled").await? && f.is_status(second, "cancelled").await?)
        })
        .await?;
        until("both acceptances are delivered", || async {
            Ok(f.cancel_is(&first.run, "delivered").await? && f.cancel_is(second, "delivered").await?)
        })
        .await?;
        relay.stop().await;
        f.ended_cancelled_without_body(&first.run).await?;
        f.ended_cancelled_without_body(second).await?;
        drained(&f.drain(&j).await, &j, &operation, (0, 0, 0))?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D04 contended_second_run=Unavailable committed_progress_kept=true resumed_newly=1 resumed_already=1 complete_after_consumption=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D05
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_streaming_and_custom_v2_start_window_terminate_after_drain() {
    owned("drain05", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        // A custom v2 start holds the shared lock of Thread, Run and lease while it sends.
        let window = f.in_flight(&a, 501).await?;
        let (_, window_operation) = f.close(&a, &window.j).await?;
        let sending = f.pool.get().await.map_err(text)?;
        sending.batch_execute("BEGIN").await.map_err(text)?;
        sending
            .query_one(
                "SELECT t.thread_id FROM public.threads t JOIN public.runs r ON r.thread_id=t.thread_id \
                 JOIN public.thread_leases l ON l.thread_id=t.thread_id AND l.fencing_token=r.fencing_token \
                 WHERE r.run_id=$1 FOR SHARE OF t,r,l",
                &[&window.run],
            )
            .await
            .map_err(text)?;
        let (facts, hq) = (f.facts().await?, f.hq().await?);
        unavailable(&f.drain(&window.j).await)?;
        check(
            f.cancel_rows().await? == 0 && facts == f.facts().await? && hq == f.hq().await?,
            "a drain during the send window wrote",
        )?;
        // The start returns and its original transaction rolls back: the stop is written.
        release(sending).await?;
        drained(&f.drain(&window.j).await, &window.j, &window_operation, (1, 0, 1))?;

        // An already dispatched streaming Run has a local child. The relay signals it, the child
        // cannot stream on (the closed history refuses its chunk) and stops with its fenced
        // lease, and the terminal is cancelled without any body.
        let streaming = f.in_flight(&a, 502).await?;
        let seq = streaming.lease.next_event_sequence();
        streaming
            .runtime
            .append_semantic_chunk(
                &streaming.lease,
                seq,
                RunSemanticChannel::Text,
                "STREAMED_WHILE_OPEN",
            )
            .await
            .map_err(text)?;
        let (_, streaming_operation) = f.close(&a, &streaming.j).await?;
        drained(&f.drain(&streaming.j).await, &streaming.j, &streaming_operation, (1, 0, 1))?;
        let consumer = Arc::new(Consumer::default());
        consumer.signal(&streaming.run);
        let relay = f.relay(&consumer)?;
        until("the streaming Run's child is signalled", || {
            f.holds(
                "SELECT status='delivering' AND last_error_code='child_signalled' \
                 FROM public.outbox WHERE outbox_id=$1::text||':agent_run_cancel'",
                &streaming.run,
            )
        })
        .await?;
        until("the send-window Run is cancelled", || {
            f.is_status(&window.run, "cancelled")
        })
        .await?;
        check(
            f.is_status(&streaming.run, "running").await?,
            "the signalled Run ended before its child stopped",
        )?;
        check(
            matches!(
                streaming
                    .runtime
                    .append_semantic_chunk(
                        &streaming.lease,
                        seq + 1,
                        RunSemanticChannel::Text,
                        "STREAMED_AFTER_STOP"
                    )
                    .await,
                Err(RunRuntimeError::StaleLease)
            ),
            "the closed history admitted another streamed chunk",
        )?;
        streaming
            .runtime
            .finish_run(&streaming.lease, seq + 1, RunTerminal::Cancelled)
            .await
            .map_err(text)?;
        until("the signalled acceptance is delivered", || {
            f.cancel_is(&streaming.run, "delivered")
        })
        .await?;
        relay.stop().await;
        for run in [&window.run, &streaming.run] {
            f.ended_cancelled_without_body(run).await?;
        }
        check(
            consumer.revoked().len() == 2 && consumer.dispatched().is_empty(),
            "the relay did not revoke exactly the two accepted Runs",
        )?;
        drained(&f.drain(&window.j).await, &window.j, &window_operation, (0, 0, 0))?;
        drained(&f.drain(&streaming.j).await, &streaming.j, &streaming_operation, (0, 0, 0))?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D05 v2_window_share_lock=Unavailable released_then_written=true streaming_child_signalled=true late_chunk_refused=true both_cancelled_without_body=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D06
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_terminal_and_reconciliation_required_runs_are_skipped_unchanged()
{
    owned("drain06", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        // One Thread with a Run of every terminal kind; reconciliation-required keeps the slot.
        let first = f.in_flight(&a, 601).await?;
        first
            .runtime
            .finish_run(&first.lease, first.lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(text)?;
        let mut last = first.run.clone();
        for (index, terminal) in [
            RunTerminal::Failed(RunFailureCode::ProviderUnavailable),
            RunTerminal::Cancelled,
            RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
        ]
        .into_iter()
        .enumerate()
        {
            last = format!("owned-drain-run-601-{index}");
            f.begin_again(&first.req, &last).await?;
            let (runtime, lease) = f.claim(&last).await?;
            runtime
                .finish_run(&lease, lease.next_event_sequence(), terminal)
                .await
                .map_err(text)?;
        }
        check(
            f.is_status(&last, "reconciliation_required").await?,
            "premise: the last Run is reconciliation-required",
        )?;
        let (_, operation) = f.close(&a, &first.j).await?;
        let (facts, hq, rows) = (f.facts().await?, f.hq().await?, f.acceptances().await?);
        drained(&f.drain(&first.j).await, &first.j, &operation, (0, 0, 0))?;
        check(
            facts == f.facts().await? && hq == f.hq().await? && rows == f.acceptances().await?,
            "the drain changed a terminal Run, its events or anything else",
        )?;

        // The lease recovery ended the Run first, after the close: it keeps that terminal.
        let stale = f.in_flight(&a, 602).await?;
        let (_, stale_operation) = f.close(&a, &stale.j).await?;
        f.sql(&format!(
            "UPDATE public.thread_leases SET acquired_at=clock_timestamp()-interval '2 minutes',\
             updated_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()-interval '1 second' \
             WHERE thread_id='{}'",
            stale.j
        ))
        .await?;
        stale
            .runtime
            .recover_one_stale_run()
            .await
            .map_err(text)?
            .ok_or("the lease recovery found no stale Run")?;
        check(
            f.is_status(&stale.run, "reconciliation_required").await?,
            "premise: the recovery ended the Run reconciliation-required",
        )?;
        let (facts, rows) = (f.facts().await?, f.acceptances().await?);
        drained(&f.drain(&stale.j).await, &stale.j, &stale_operation, (0, 0, 0))?;
        check(
            facts == f.facts().await? && rows == f.acceptances().await?,
            "the drain changed a Run that the lease recovery ended first",
        )?;

        // The worker commits its own terminal after the acceptance: that terminal wins and the
        // consumer only delivers the acceptance, without touching the Run.
        let racing = f.in_flight(&a, 603).await?;
        let (_, racing_operation) = f.close(&a, &racing.j).await?;
        drained(&f.drain(&racing.j).await, &racing.j, &racing_operation, (1, 0, 1))?;
        racing
            .runtime
            .finish_run(&racing.lease, racing.lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(text)?;
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("the acceptance of the completed Run is delivered", || {
            f.cancel_is(&racing.run, "delivered")
        })
        .await?;
        relay.stop().await;
        let payload: Value = f
            .one(
                "SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",
                &racing.run,
            )
            .await?;
        check(
            f.is_status(&racing.run, "completed").await?
                && payload == json!({"status": "completed"})
                && consumer.revoked().is_empty()
                && consumer.dispatched().is_empty(),
            "the cancellation overrode, or was applied to, the Run that completed first",
        )?;
        drained(&f.drain(&racing.j).await, &racing.j, &racing_operation, (0, 0, 0))?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D06 terminal_kinds=completed,failed,cancelled,reconciliation_required skipped_unchanged=true lease_recovery_first_kept=true worker_terminal_first_kept=true revoked=0"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D07
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_lock_conflicts_classify_unavailable_never_conflict_or_closed() {
    owned("drain07", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let flight = f.in_flight(&a, 701).await?;
        let (_, operation) = f.close(&a, &flight.j).await?;
        let (facts, hq) = (f.facts().await?, f.hq().await?);
        // (a) Any row lock another transaction holds on the Run is refused at once (NOWAIT),
        // from the weakest key-share lock of a child insert to a full update lock.
        for clause in ["FOR KEY SHARE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR UPDATE"] {
            let held = f.hold_run(&flight.run, clause).await?;
            let started = Instant::now();
            unavailable(&f.drain(&flight.j).await)?;
            check(
                started.elapsed() < Duration::from_secs(2),
                "the refusal of a held Run lock waited",
            )?;
            release(held).await?;
            check(
                f.cancel_rows().await? == 0 && facts == f.facts().await? && hq == f.hq().await?,
                "a refused drain wrote",
            )?;
        }
        // (b) The unique key of the acceptance is held by an uncommitted insert of another
        // transaction, so the drain waits for it after it locked the Run. A deadlock is
        // detected by the server and is Unavailable too: the drain started waiting first.
        let timeout: String = f
            .pool
            .get()
            .await
            .map_err(text)?
            .query_one("SELECT current_setting('deadlock_timeout')", &[])
            .await
            .map_err(text)?
            .try_get(0)
            .map_err(text)?;
        check(
            timeout == "1s",
            &format!("the owned server's deadlock_timeout is {timeout:?}, not 1s"),
        )?;
        let session = f.pool.get().await.map_err(text)?;
        session.batch_execute("BEGIN").await.map_err(text)?;
        session
            .batch_execute("SET LOCAL deadlock_timeout='3s'")
            .await
            .map_err(text)?;
        session
            .execute(
                "INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,\
                 delivery_class,payload) VALUES($1,'run',$2,0,'agent_run_cancel','internal',$3)",
                &[
                    &format!("{}:agent_run_cancel", flight.run),
                    &flight.run,
                    &json!({"runId": flight.run, "threadId": flight.j, "requestedBy": A}),
                ],
            )
            .await
            .map_err(text)?;
        let holder = backend_pid(&session).await?;
        let waiter = async {
            wait_blocked(&f.pool, holder, "INSERT INTO public.outbox").await?;
            // The drain holds the Run row lock and waits for the session: closing the cycle.
            session
                .batch_execute(&format!(
                    "SELECT 1 FROM public.runs WHERE run_id='{}' FOR UPDATE",
                    flight.run
                ))
                .await
                .map_err(text)
        };
        let started = Instant::now();
        let (deadlocked, waited) = tokio::join!(f.drain(&flight.j), waiter);
        waited?;
        unavailable(&deadlocked)?;
        check(
            started.elapsed() < Duration::from_secs(3),
            "the deadlock was ended by the deadline, not detected by the server",
        )?;
        release(session).await?;
        check(
            f.cancel_rows().await? == 0 && facts == f.facts().await? && hq == f.hq().await?,
            "a deadlocked drain wrote",
        )?;
        // (c) The same wait without a cycle ends at the lock wait limit or the shared deadline,
        // both bounded by the original deadline: a deadline-class refusal, never closed.
        let session = f.pool.get().await.map_err(text)?;
        session.batch_execute("BEGIN").await.map_err(text)?;
        session
            .execute(
                "INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,\
                 delivery_class,payload) VALUES($1,'run',$2,0,'agent_run_cancel','internal',$3)",
                &[
                    &format!("{}:agent_run_cancel", flight.run),
                    &flight.run,
                    &json!({"runId": flight.run, "threadId": flight.j, "requestedBy": A}),
                ],
            )
            .await
            .map_err(text)?;
        let holder = backend_pid(&session).await?;
        let started = Instant::now();
        let bounded = f.authority.drain_closed_history_runs_before(
            &flight.j,
            Instant::now() + Duration::from_millis(2000),
        );
        let observer = wait_blocked(&f.pool, holder, "INSERT INTO public.outbox");
        let (ended, seen) = tokio::join!(bounded, observer);
        seen?;
        check(
            matches!(ended, Err(Stop::Unavailable | Stop::DeadlineExceeded))
                && (Duration::from_millis(1500)..Duration::from_secs(4)).contains(&started.elapsed()),
            &format!(
                "the bounded wait was {:?} after {:?}",
                ended.as_ref().err(),
                started.elapsed()
            ),
        )?;
        release(session).await?;
        check(
            f.cancel_rows().await? == 0 && facts == f.facts().await? && hq == f.hq().await?,
            "a drain that ran out of time wrote",
        )?;
        // After every refusal the same call resumes and writes exactly the one acceptance.
        quiesced(&f).await?;
        drained(&f.drain(&flight.j).await, &flight.j, &operation, (1, 0, 1))?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D07 held_locks=4 nowait_refusals=Unavailable deadlock_40P01=Unavailable bounded_wait_deadline_class=true conflict_or_closed=0 resumed=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D08: a remember effect meets the system acceptance
// ---------------------------------------------------------------------------------------------

struct CapturingMemory(Mutex<Option<RememberToolMemoryRequest>>);
#[async_trait]
impl RememberToolMemory for CapturingMemory {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> std::result::Result<CommittedMemoryEffect, MemoryAdministrationError> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(request);
        Err(MemoryAdministrationError::CommitUnknown)
    }
}
/// The real journal, except that no outcome is recorded: the captured request commits no effect.
struct CapturingJournal(PostgresToolJournal);
#[async_trait]
impl ToolJournal for CapturingJournal {
    async fn record_refusal(
        &self,
        draft: &ToolRefusalDraft,
    ) -> std::result::Result<(), ToolPortError> {
        self.0.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> std::result::Result<DurableDecisionReceipt, ToolPortError> {
        self.0.record_decision(draft).await
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> std::result::Result<(), ToolPortError> {
        self.0.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, _: &ToolOutcomeDraft) -> std::result::Result<(), ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "owned_capture_only",
        })
    }
}
fn memory(pool: &pool::DatabasePool) -> Result<PostgresMemoryAdministration> {
    PostgresMemoryAdministration::new(pool.clone())
        .with_effect_audit_key(AUDIT_KEY.to_vec())
        .map_err(text)
}
/// The real capability pipeline up to the remember request; it creates no memory effect.
async fn capture(
    f: &Fixture,
    auth: &AuthContext,
    flight: &Flight,
    seq: u64,
) -> Result<RememberToolMemoryRequest> {
    let policy = PolicyStore::postgres(f.pool.clone(), None);
    policy.load().await.map_err(text)?;
    policy
        .set(
            ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: vec![],
                allow: vec!["tool.name == \"remember\"".into()],
            },
            Some(auth.actor().as_str()),
        )
        .await
        .map_err(text)?;
    let captured = Arc::new(CapturingMemory(Mutex::new(None)));
    let control = PostgresBuiltInToolControlPlane::new(
        f.pool.clone(),
        auth.deployment().clone(),
        auth.tenant().clone(),
        policy,
        Arc::clone(&captured),
    );
    let journal = CapturingJournal(
        PostgresToolJournal::new(f.pool.clone(), AUDIT_KEY.to_vec()).map_err(text)?,
    );
    let result: std::result::Result<ToolResult, AppError> = invoke_tool(
        &control,
        &journal,
        auth,
        ToolInvocation {
            call_id: ToolCallId::new(format!("owned-drain-call-{}-{seq}", flight.run)),
            run_id: flight.req.command.run_id.clone(),
            bot_id: flight.req.command.bot_id.clone(),
            call_seq: seq,
            tool_name: "remember".into(),
            arguments: json!({"memoryKind":"preference","scope":"user","content":"OWNED_DRAIN_REMEMBER_CONTENT","tags":["drain-tag"],"sensitivity":"normal"}),
        },
    )
    .await;
    check(
        matches!(result, Err(AppError::ReconciliationRequired { .. })),
        "capture must leave the outcome unresolved",
    )?;
    captured
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or_else(|| "the request did not reach the capture".to_owned())
}
/// The remember-owned rows: any new effect, receipt or audit changes this.
async fn effects(f: &Fixture) -> Result<Value> {
    f.pool
        .get()
        .await
        .map_err(text)?
        .query_one(
            "SELECT jsonb_build_object( \
             'memories',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY memory_id),'[]') FROM public.memories m), \
             'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq),'[]') FROM public.memory_events e), \
             'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY receipt_id),'[]') FROM public.remember_effect_receipts r), \
             'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY created_at,id),'[]') FROM public.audit_events a))",
            &[],
        )
        .await
        .map_err(text)?
        .try_get(0)
        .map_err(text)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_remember_exact_replay_survives_system_cancel_and_fresh_effect_conflicts()
 {
    owned("drain08", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        let flight = f.in_flight(&a, 801).await?;
        let committed_request = capture(&f, &a, &flight, 0).await?;
        let fresh_request = capture(&f, &a, &flight, 1).await?;
        // One real effect is committed while the history is open.
        let receipt = memory(&f.pool)?
            .remember_from_tool(committed_request.clone())
            .await
            .map_err(text)?;
        let (_, operation) = f.close(&a, &flight.j).await?;
        drained(&f.drain(&flight.j).await, &flight.j, &operation, (1, 0, 1))?;
        let effects_after_effect = effects(&f).await?;
        // While the system acceptance is pending: the exact replay returns the committed receipt
        // (it was Corrupt for an unrecognised shape) and a fresh effect is refused.
        check(
            memory(&f.pool)?
                .remember_from_tool(committed_request.clone())
                .await
                == Ok(receipt.clone()),
            "the exact replay did not survive the pending system acceptance",
        )?;
        check(
            memory(&f.pool)?.remember_from_tool(fresh_request.clone()).await
                == Err(MemoryAdministrationError::Conflict),
            "a fresh effect was not refused while the system acceptance is pending",
        )?;
        // After the consumer delivered it and the Run is cancelled: the same two answers.
        let consumer = Arc::new(Consumer::default());
        let relay = f.relay(&consumer)?;
        until("the Run is cancelled and its acceptance delivered", || async {
            Ok(f.is_status(&flight.run, "cancelled").await?
                && f.cancel_is(&flight.run, "delivered").await?)
        })
        .await?;
        relay.stop().await;
        check(
            memory(&f.pool)?
                .remember_from_tool(committed_request.clone())
                .await
                == Ok(receipt),
            "the exact replay did not survive the delivered system acceptance",
        )?;
        check(
            memory(&f.pool)?.remember_from_tool(fresh_request).await
                == Err(MemoryAdministrationError::Conflict),
            "a fresh effect was not refused after the Run was cancelled",
        )?;
        check(
            effects_after_effect == effects(&f).await?,
            "a replay or a refusal changed a remember-owned row",
        )?;

        // The recogniser is the one shared shape judge: on an open Thread a system-shaped row
        // fences a fresh effect, and a row of any other shape is a corrupt binding.
        let open = f.in_flight(&a, 802).await?;
        let probe = capture(&f, &a, &open, 0).await?;
        let before = effects(&f).await?;
        f.forge(
            &open.run,
            &json!({"runId": open.run, "threadId": open.j, "source": CANCEL_SOURCE, "operationId": Uuid::now_v7().to_string()}),
        )
        .await?;
        check(
            memory(&f.pool)?.remember_from_tool(probe.clone()).await
                == Err(MemoryAdministrationError::Conflict),
            "a system-shaped acceptance did not fence a fresh effect",
        )?;
        for broken in [
            json!({"runId": open.run, "threadId": open.j, "source": CANCEL_SOURCE, "operationId": "o", "requestedBy": A}),
            json!({"runId": open.run, "threadId": open.j, "source": "user", "operationId": "o"}),
            json!({"runId": open.run, "threadId": open.j, "requestedBy": "someone-else"}),
            json!({"runId": open.run, "threadId": "another-thread", "source": CANCEL_SOURCE, "operationId": "o"}),
        ] {
            f.sql(&format!(
                "UPDATE public.outbox SET payload='{broken}'::jsonb WHERE outbox_id='{}:agent_run_cancel'",
                open.run
            ))
            .await?;
            check(
                matches!(
                    memory(&f.pool)?.remember_from_tool(probe.clone()).await,
                    Err(MemoryAdministrationError::Corrupt { .. })
                ),
                "a broken acceptance shape was not a corrupt binding",
            )?;
        }
        check(before == effects(&f).await?, "a refusal wrote a remember-owned row")?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D08 replay_pending=receipt replay_delivered=receipt fresh_effect=Conflict system_shape_fences_open_thread=true broken_shapes_corrupt=4 effects_unchanged=true"
        );
        f.finish().await
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// D09
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn thread_history_run_drain_open_history_is_not_visible_and_queued_row_is_corrupt() {
    owned("drain09", 7, |f| async move {
        let a = f.auth(A, 1).await?;
        // An open head, a Thread without a head, an unknown Thread and malformed ids: nothing
        // is written for any of them.
        let open = f.in_flight(&a, 901).await?;
        let headless = f.in_flight(&a, 902).await?;
        drop_head(&f, &headless.j).await?;
        let unknown = f
            .request(&a, 903, ThreadRunAnchor::DirectBot)
            .command
            .thread_id
            .as_str()
            .to_owned();
        let (facts, hq, rows) = (f.facts().await?, f.hq().await?, f.acceptances().await?);
        for j in [&open.j, &headless.j, &unknown] {
            not_visible(&f.drain(j).await)?;
        }
        for bad in ["", "not-a-thread", "00000000-0000-4000-8000-000000000000\n"] {
            check(
                matches!(
                    f.drain(bad).await,
                    Err(Stop::InvalidInput { field: "thread_id" })
                ),
                "an invalid Thread id must fail the exact input boundary",
            )?;
        }
        check(
            facts == f.facts().await? && hq == f.hq().await? && rows == f.acceptances().await?,
            "a refused drain wrote",
        )?;
        // The same Thread turns visible exactly when ACK1 closed it.
        let (_, open_operation) = f.close(&a, &open.j).await?;
        drained(&f.drain(&open.j).await, &open.j, &open_operation, (1, 0, 1))?;

        // A queued row is a broken one: production begins a Run directly as running. The valid
        // Run before it keeps its acceptance, the queued row is never made cancellable.
        let valid = f.in_flight(&a, 904).await?;
        f.sql(&format!(
            "INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,created_at) \
             SELECT 'owned-drain-queued',thread_id,bot_id,actor_id,false,'queued',fencing_token,clock_timestamp() \
             FROM public.runs WHERE run_id='{}'",
            valid.run
        ))
        .await?;
        let (_, operation) = f.close(&a, &valid.j).await?;
        corrupt(&f.drain(&valid.j).await, "run_status")?;
        check(
            f.acceptance(&valid.run).await?.is_some()
                && f.acceptance("owned-drain-queued").await?.is_none()
                && f.is_status("owned-drain-queued", "queued").await?,
            "the queued row was made cancellable, or the earlier progress was lost",
        )?;
        corrupt(&f.drain(&valid.j).await, "run_status")?;

        // An acceptance that cannot be this Run's request is corrupt, never repaired and never
        // overwritten: a delivered or dead-lettered one on a Run that still runs, a foreign
        // requester, another operation and every other shape.
        let broken = f.in_flight(&a, 905).await?;
        let (_, broken_operation) = f.close(&a, &broken.j).await?;
        let user = json!({"runId": broken.run, "threadId": broken.j, "requestedBy": A});
        f.forge(&broken.run, &user).await?;
        drained(&f.drain(&broken.j).await, &broken.j, &broken_operation, (0, 1, 1))?;
        let outbox = format!("{}:agent_run_cancel", broken.run);
        let rows_before = f.cancel_rows().await?;
        for (state, payload) in [
            ("status='delivered',delivered_at=clock_timestamp()", user.clone()),
            ("status='dead_letter',delivered_at=NULL", user.clone()),
            (
                "status='pending',delivered_at=NULL",
                json!({"runId": broken.run, "threadId": broken.j, "requestedBy": B}),
            ),
            (
                "status='pending',delivered_at=NULL",
                json!({"runId": broken.run, "threadId": broken.j, "source": CANCEL_SOURCE, "operationId": operation}),
            ),
            (
                "status='pending',delivered_at=NULL",
                json!({"runId": broken.run, "threadId": broken.j, "source": CANCEL_SOURCE, "operationId": broken_operation, "requestedBy": A}),
            ),
            (
                "status='pending',delivered_at=NULL",
                json!({"runId": broken.run, "threadId": "another-thread", "requestedBy": A}),
            ),
            ("status='pending',delivered_at=NULL", json!({})),
        ] {
            f.sql(&format!(
                "UPDATE public.outbox SET {state},payload='{payload}'::jsonb WHERE outbox_id='{outbox}'"
            ))
            .await?;
            let stored = f.acceptance(&broken.run).await?;
            corrupt(&f.drain(&broken.j).await, "run_cancel_outbox")?;
            check(
                f.acceptance(&broken.run).await? == stored && f.cancel_rows().await? == rows_before,
                "a corrupt acceptance was rewritten or duplicated",
            )?;
        }
        // The same delivery key under another identifier is two names for one acceptance.
        f.sql(&format!(
            "UPDATE public.outbox SET status='pending',delivered_at=NULL,payload='{user}'::jsonb,outbox_id='other-name' WHERE outbox_id='{outbox}'"
        ))
        .await?;
        corrupt(&f.drain(&broken.j).await, "run_cancel_outbox")?;
        f.sql(&format!(
            "UPDATE public.outbox SET outbox_id='{outbox}' WHERE outbox_id='other-name'"
        ))
        .await?;
        // Restored to the lawful user request, the same call resumes: already requested.
        drained(&f.drain(&broken.j).await, &broken.j, &broken_operation, (0, 1, 1))?;
        eprintln!(
            "THREAD_HISTORY_RUN_DRAIN id=D09 open_head=NotVisible headless=NotVisible unknown=NotVisible bad_ids=InvalidInput queued=Corrupt(run_status) earlier_progress_kept=true corrupt_acceptance_shapes=8 never_rewritten=true"
        );
        f.finish().await
    })
    .await;
}
