//! Consumer-side refusal for a closed Thread history on owned PostgreSQL 17.11.
//!
//! Each case closes the permanent head with test-owned privileged SQL in an owned throwaway
//! database: a closing intent plus the open->closed update in one natural COMMIT. That row is
//! not authority; it only lets the existing consumers show what they refuse. Waits and races are
//! ordered with real locks and `pg_blocking_pids`, never by a sleep standing in for evidence.
#![cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]

mod harness;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_agent::{BuiltInAgentConfig, BuiltInAgentRuntime, NoAgentToolInvoker};
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{
    AgentContextError, AgentContextSource, ArtifactAdministration, ArtifactAdministrationError,
    BeginThreadRunRequest, BeginThreadRunV2Request, CommittedMemoryEffect, MemoryAdministration,
    MemoryAdministrationError, ProviderAdapter, ProviderPortError, ProviderRequest,
    ProviderSession, RememberMemoryRequest, RememberToolMemory, RememberToolMemoryRequest,
    RunDispatchDecision, RunExecutionLease, RunRuntime, ThreadDirectory, ToolDecisionDraft,
    ToolJournal, ToolOutcomeDraft, ToolPortError, ToolRefusalDraft, invoke_tool,
};
use openbot_contracts::artifacts::SaveRunMessageTextArtifact;
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, BeginThreadRunV2, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{
    ActorId, BotId, CapabilityId, CatalogGeneration, ChannelId, DeploymentId, RunId, TenantId,
    ThreadId, ToolCallId,
};
use openbot_contracts::memory::{
    MemoryKind, MemoryScope, MemorySensitivity, MemorySource, RememberMemory,
};
use openbot_contracts::model_connections::{
    CreateModelConnection, CustomModelProtocol, ModelApiKey, ModelConnection, RunModelSelection,
};
use openbot_contracts::tool::ToolInvocation;
use openbot_contracts::versioned_model_selection::{
    ModelSelectionIntentSource, RunModelSelectionV2,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::thread::FencingToken;
use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
use openbot_domain::tool::commit::CommitState;
use openbot_domain::tool::metadata::{
    ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    ToolMetadata, ToolName,
};
use openbot_domain::tool::pipeline::{DurableDecisionReceipt, ToolOutcome};
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::agent_tools::PostgresBuiltInToolControlPlane;
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::db::tables::tool_attempts;
use openbot_infra::db::{InfraError, baseline, fresh, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::model_connections::PostgresModelConnections;
use openbot_infra::model_dataset::PostgresModelDatasetBinding;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer, SafeHttpBudget,
};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::custom::PostgresCustomModelProvider;
use openbot_infra::repo::tools::{PostgresToolJournal, ToolAttemptRepo};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::vault::CredentialRecordVault;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, String>;

const DEP: &str = "closure-deployment";
const TENANT: &str = "closure-tenant";
const PROCESS: &str = "closure-runtime";
const MODEL_KEY: &str = "OWNED_CLOSURE_MODEL_CANARY";
const AUDIT_KEY: &[u8] = b"owned-consumer-closure-audit-key-0001";
/// Application names of the pools whose backends are the entries under lock-order evidence.
const ENTRY_TOOLS: &str = "closure_entry_tools";
const ENTRY_REMEMBER: &str = "closure_entry_remember";
const ENTRY_MEMORY: &str = "closure_entry_memory";
const ENTRY_SAVE: &str = "closure_entry_save";

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn require(condition: bool, reason: &'static str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}

// ---------------------------------------------------------------------------------------------
// Owned database, seed rows and request builders
// ---------------------------------------------------------------------------------------------

async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(text)?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "owned connection destruction unobserved",
        )?;
    }
    Ok(())
}

/// A fresh isolated database on the explicitly owned loopback instance, already at the current
/// native prefix with the seed rows below.
async fn owned<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(pool::DatabasePool, pool::DatabaseConfig) -> Fut,
    Fut: Future<Output = TestResult>,
{
    owned_with(tag, true, body).await;
}

/// The same owned database; `seeded == false` leaves it empty for a case that builds its own
/// historical schema.
async fn owned_with<F, Fut>(tag: &str, seeded: bool, body: F)
where
    F: FnOnce(pool::DatabasePool, pool::DatabaseConfig) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(tag);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "literal loopback required",
    )
    .expect("owned fixture prerequisite");
    harness::with_temp_database(&admin, tag, |config| async move {
        require(
            config.dbname.starts_with("openbot_it_"),
            "owned database name missing",
        )?;
        let config = config.with_max_pool_size(8);
        let p = pool::connect(&config).await.map_err(text)?;
        let prepared = async {
            let c = p.get().await.map_err(text)?;
            let r = c
                .query_one(
                    "SELECT current_setting('server_version_num')::int,current_setting('server_encoding'),current_setting('block_size')::int",
                    &[],
                )
                .await
                .map_err(text)?;
            require(
                r.get::<_, i32>(0) == 170011
                    && r.get::<_, String>(1) == "UTF8"
                    && r.get::<_, i32>(2) == 8192,
                "frozen PG17.11 prerequisites differ",
            )?;
            drop(c);
            if seeded { seed(&p).await } else { Ok(()) }
        }
        .await;
        let result = match prepared {
            Ok(()) => body(p.clone(), config).await,
            Err(error) => Err(error),
        };
        result.and(close_pool(p).await)
    })
    .await;
}

async fn seed(p: &pool::DatabasePool) -> TestResult {
    let mut c = p.get().await.map_err(text)?;
    require(
        fresh::apply(&mut c).await.map_err(text)?
            == fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied),
        "fresh native prefix not applied",
    )?;
    c.batch_execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES
           ('alice','alice@example.test',7),('bob','bob@example.test',7);
         INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
         INSERT INTO public.agents(id,name,type,configuration) VALUES
           ('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
         INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
           VALUES('bot','alice','Owned bot','','owned','public');
         INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups)
           VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
         INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
         INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');",
    )
    .await
    .map_err(text)
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}

fn thread_for(index: u64) -> ThreadId {
    let mut entropy = [0u8; 16];
    entropy[8..].copy_from_slice(&index.to_be_bytes());
    ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy)
}

fn anchor(channel: bool) -> ThreadRunAnchor {
    if channel {
        ThreadRunAnchor::Channel {
            channel_id: ChannelId::new("channel"),
        }
    } else {
        ThreadRunAnchor::DirectBot
    }
}

fn begin_v1(
    index: u64,
    channel: bool,
    selection: Option<RunModelSelection>,
) -> BeginThreadRunRequest {
    BeginThreadRunRequest {
        deployment: DeploymentId::new(DEP),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new("alice"),
        auth_generation: AuthGeneration::new(7),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: thread_for(index),
            run_id: RunId::new(format!("closure-run-{index}")),
            bot_id: BotId::new("bot"),
            anchor: anchor(channel),
            message: format!("User prompt {index}"),
            selected_skill_slugs: vec![],
            model_selection: selection,
        },
    }
}

fn lease_of(run: &RunId, thread: &ThreadId) -> RunExecutionLease {
    RunExecutionLease::new(
        run.clone(),
        thread.clone(),
        BotId::new("bot"),
        ActorId::new("alice"),
        FencingToken::new(1).unwrap(),
        0,
    )
    .unwrap()
}

fn directory(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
) -> TestResult<PostgresThreadDirectory> {
    PostgresThreadDirectory::with_runtime(
        p.clone(),
        config.clone(),
        PROCESS.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .map_err(text)
}

fn context_on(p: &pool::DatabasePool) -> PostgresAgentContextSource {
    PostgresAgentContextSource::new(
        p.clone(),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        Some(32),
    )
    .unwrap()
}

/// The Thread's history closes exactly like the admission tests do it: a closing intent and the
/// open->closed head update, committed together. This verifies consumers only.
const CLOSE_INTENT_SQL: &str = "INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,'owned-close-actor',7,anchor_kind,anchor_id,thread_created_at,$4 FROM openbot_internal.thread_history_heads WHERE thread_id=$1";
const CLOSE_HEAD_SQL: &str = "UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='owned-close-actor',closure_auth_generation=7,closed_at=$4 WHERE thread_id=$1";

/// The two closing statements on a transaction the caller already opened (and commits).
async fn close_statements(c: &Client, thread: &ThreadId) -> TestResult {
    let op = uuid::Uuid::now_v7().to_string();
    let request = uuid::Uuid::now_v7().to_string();
    let at: time::OffsetDateTime = c
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(text)?
        .get(0);
    c.execute(CLOSE_INTENT_SQL, &[&thread.as_str(), &op, &request, &at])
        .await
        .map_err(text)?;
    c.execute(CLOSE_HEAD_SQL, &[&thread.as_str(), &op, &request, &at])
        .await
        .map_err(text)?;
    Ok(())
}

async fn head_phase(c: &Client, thread: &ThreadId) -> TestResult<Option<String>> {
    Ok(c.query_opt(
        "SELECT phase FROM openbot_internal.thread_history_heads WHERE thread_id=$1",
        &[&thread.as_str()],
    )
    .await
    .map_err(text)?
    .map(|row| row.get(0)))
}

async fn close_head(p: &pool::DatabasePool, thread: &ThreadId) -> TestResult {
    let c = p.get().await.map_err(text)?;
    require(
        head_phase(&c, thread).await?.as_deref() == Some("open"),
        "premise: the head must be open before it is closed",
    )?;
    c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    close_statements(&c, thread).await?;
    c.batch_execute("COMMIT").await.map_err(text)?;
    require(
        head_phase(&c, thread).await?.as_deref() == Some("closed"),
        "the owned closure did not naturally commit",
    )
}

async fn count(p: &pool::DatabasePool, sql: &str) -> TestResult<i64> {
    let c = p.get().await.map_err(text)?;
    Ok(c.query_one(sql, &[]).await.map_err(text)?.get(0))
}

// ---------------------------------------------------------------------------------------------
// Real lock evidence
// ---------------------------------------------------------------------------------------------

async fn backend_pid(c: &Client) -> TestResult<i32> {
    Ok(c.query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(text)?
        .get(0))
}

/// A one-connection pool whose single backend is known, so a wait can be tied to it.
async fn dedicated(
    config: &pool::DatabaseConfig,
    name: &str,
) -> TestResult<(pool::DatabasePool, i32)> {
    let dedicated = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(name),
    )
    .await
    .map_err(text)?;
    let c = dedicated.get().await.map_err(text)?;
    let pid = backend_pid(&c).await?;
    drop(c);
    Ok((dedicated, pid))
}

/// Holds an owned lock transaction: BEGIN plus one statement, returning its backend.
async fn hold(c: &Client, lock_sql: &str) -> TestResult<i32> {
    c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    c.batch_execute(lock_sql).await.map_err(text)?;
    backend_pid(c).await
}

async fn release(c: &Client) -> TestResult {
    c.batch_execute("ROLLBACK").await.map_err(text)
}

async fn until<F, Fut>(what: &'static str, mut probe: F) -> TestResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = TestResult<bool>>,
{
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if probe().await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("not observed: {what}"));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// `worker` is really waiting behind `owner` (directly or transitively) in PostgreSQL.
async fn wait_blocked(observer: &Client, worker: i32, owner: i32) -> TestResult {
    until("a real two-transaction lock wait", || async move {
        Ok(observer
            .query_one(
                "WITH RECURSIVE waits(pid,path) AS (SELECT $1::integer,ARRAY[$1::integer] \
                 UNION ALL SELECT b.pid,waits.path||b.pid FROM waits \
                 CROSS JOIN LATERAL unnest(pg_blocking_pids(waits.pid)) b(pid) \
                 WHERE NOT b.pid=ANY(waits.path) AND cardinality(waits.path)<16) \
                 SELECT EXISTS(SELECT 1 FROM waits WHERE pid=$2 AND cardinality(path)>1)",
                &[&worker, &owner],
            )
            .await
            .map_err(text)?
            .get::<_, bool>(0))
    })
    .await
}

async fn activity(observer: &Client, pid: i32) -> TestResult<(String, String)> {
    let row = observer
        .query_one(
            "SELECT coalesce(state,''),coalesce(query,'') FROM pg_stat_activity WHERE pid=$1",
            &[&pid],
        )
        .await
        .map_err(text)?;
    Ok((row.get(0), row.get(1)))
}

/// A NOWAIT probe on a separate connection: `true` when the row was lockable (nobody holds it).
async fn lockable(c: &Client, sql: &str, key: &str) -> TestResult<bool> {
    c.batch_execute("BEGIN").await.map_err(text)?;
    let result = c.query(sql, &[&key]).await;
    c.batch_execute("ROLLBACK").await.map_err(text)?;
    match result {
        Ok(_) => Ok(true),
        Err(error) if error.code().is_some_and(|code| code.code() == "55P03") => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// The first statement of the strict writer-schema observation, exactly as the writer sends it.
const OBSERVATION_SQL: &str = "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1";
/// Stops every reader of the migration ledger, which the observation reads first.
const LEDGER_LOCK_SQL: &str =
    "LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE";

/// A pool whose backends carry `application`, so a lock wait can be tied to the entry using it.
async fn entry_pool(
    config: &pool::DatabaseConfig,
    application: &str,
    size: usize,
) -> TestResult<pool::DatabasePool> {
    pool::connect(
        &config
            .clone()
            .with_max_pool_size(size)
            .with_application_name(application),
    )
    .await
    .map_err(text)
}

/// Row-level locks `pid` holds: tuple and advisory locks, and the RowShare and RowExclusive
/// relation locks that every row-locking or writing statement takes first. A transaction that is
/// still waiting inside its schema observation holds none of them.
async fn row_level_locks(observer: &Client, pid: i32) -> TestResult<i64> {
    Ok(observer
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=$1 AND granted \
             AND (locktype IN ('tuple','advisory') \
               OR (locktype='relation' AND mode IN ('RowShareLock','RowExclusiveLock')))",
            &[&pid],
        )
        .await
        .map_err(text)?
        .get(0))
}

/// The backends of the pool named `application` (the entry under test) that wait for the ledger
/// lock behind exactly `holder`, with their statements.
async fn ledger_waiters(
    observer: &Client,
    holder: i32,
    application: &str,
) -> TestResult<Vec<(i32, String)>> {
    let rows = observer
        .query(
            "SELECT l.pid,coalesce(a.query,'') FROM pg_catalog.pg_locks l \
             JOIN pg_catalog.pg_stat_activity a ON a.pid=l.pid \
             WHERE l.locktype='relation' AND NOT l.granted \
               AND l.relation='openbot_internal.schema_migrations'::regclass \
               AND pg_catalog.pg_blocking_pids(l.pid)=ARRAY[$1::integer] \
               AND a.application_name=$2 ORDER BY l.pid",
            &[&holder, &application],
        )
        .await
        .map_err(text)?;
    Ok(rows.iter().map(|row| (row.get(0), row.get(1))).collect())
}

/// Controllers for the lock-order evidence of one consumer: an owned holder of the ledger lock,
/// an observer of `pg_locks` and `pg_stat_activity`, and NOWAIT probes of the rows the consumer
/// locks after its observation.
struct LockOrder {
    observer: pool::PooledClient,
    holder: pool::PooledClient,
    probe: pool::PooledClient,
    probes: Vec<(String, String)>,
    application: String,
}

impl LockOrder {
    /// `application` names the pool of the entry under test. Controls come first: each probe
    /// refuses a real row holder, and the row-level lock counter sees that holder.
    async fn new(
        p: &pool::DatabasePool,
        application: &str,
        probes: &[(&str, &str)],
    ) -> TestResult<Self> {
        let observer = p.get().await.map_err(text)?;
        let holder = p.get().await.map_err(text)?;
        let probe = p.get().await.map_err(text)?;
        for (sql, key) in probes {
            let control = p.get().await.map_err(text)?;
            control.batch_execute("BEGIN").await.map_err(text)?;
            control.query(*sql, &[key]).await.map_err(text)?;
            let refused = !lockable(&probe, sql, key).await?;
            let counted = row_level_locks(&observer, backend_pid(&control).await?).await? > 0;
            control.batch_execute("ROLLBACK").await.map_err(text)?;
            require(
                refused,
                "control: the probe did not refuse a real row holder",
            )?;
            require(
                counted,
                "control: the lock counter did not see a real row lock",
            )?;
        }
        Ok(Self {
            observer,
            holder,
            probe,
            probes: probes
                .iter()
                .map(|(sql, key)| ((*sql).to_owned(), (*key).to_owned()))
                .collect(),
            application: application.to_owned(),
        })
    }

    /// Locks the ledger on the holder's own transaction; returns the holder's backend.
    async fn hold_ledger(&self) -> TestResult<i32> {
        hold(&self.holder, LEDGER_LOCK_SQL).await
    }

    async fn release_ledger(&self) -> TestResult {
        release(&self.holder).await
    }

    /// From the real wait behind `holder`: exactly one backend waits for the ledger lock, it is
    /// the entry's (its pool's application name), its statement is the observation itself, it
    /// holds no row-level lock, and the rows the entry locks afterwards are still free.
    async fn evidence(&self, holder: i32) -> TestResult {
        let application = self.application.as_str();
        let seen = Arc::new(Mutex::new(Vec::new()));
        until("a backend waiting for the ledger lock", || {
            let seen = Arc::clone(&seen);
            let observer = &self.observer;
            async move {
                let waiters = ledger_waiters(observer, holder, application).await?;
                let found = !waiters.is_empty();
                *seen.lock().unwrap() = waiters;
                Ok(found)
            }
        })
        .await?;
        let waiters = seen.lock().unwrap().clone();
        if waiters.len() != 1 || waiters[0].1 != OBSERVATION_SQL {
            return Err(format!(
                "the wait behind the ledger holder was not the one schema observation: {waiters:?}"
            ));
        }
        let held = row_level_locks(&self.observer, waiters[0].0).await?;
        if held != 0 {
            return Err(format!(
                "the backend held {held} row-level locks while it observed the schema"
            ));
        }
        for (sql, key) in &self.probes {
            require(
                lockable(&self.probe, sql, key).await?,
                "a row was locked before the schema observation",
            )?;
        }
        require(
            ledger_waiters(&self.observer, holder, application).await? == waiters,
            "the wait changed while it was examined",
        )
    }

    /// While the save waits for its operation row behind `blocker`, it already holds the
    /// workspace quota row and has not yet touched the head of `thread`.
    async fn quota_before_head(&self, blocker: i32, thread: &ThreadId) -> TestResult {
        let application = self.application.as_str();
        let seen = Arc::new(Mutex::new(Vec::new()));
        until("the save waiting for its operation row", || {
            let seen = Arc::clone(&seen);
            let observer = &self.observer;
            async move {
                let rows = observer
                    .query(
                        "SELECT pid,coalesce(query,'') FROM pg_catalog.pg_stat_activity \
                         WHERE pg_catalog.pg_blocking_pids(pid)=ARRAY[$1::integer] \
                           AND application_name=$2 ORDER BY pid",
                        &[&blocker, &application],
                    )
                    .await
                    .map_err(text)?;
                let waiters: Vec<(i32, String)> =
                    rows.iter().map(|row| (row.get(0), row.get(1))).collect();
                let found = !waiters.is_empty();
                *seen.lock().unwrap() = waiters;
                Ok(found)
            }
        })
        .await?;
        let waiters = seen.lock().unwrap().clone();
        if waiters.len() != 1
            || !waiters[0].1.contains("artifact_save_operations")
            || !waiters[0].1.contains("FOR UPDATE")
        {
            return Err(format!(
                "the wait behind the operation row was not the save's operation lock: {waiters:?}"
            ));
        }
        let held = |relation: &'static str, modes: &'static str| {
            let sql = format!(
                "SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=$1 AND granted \
                 AND locktype='relation' AND relation='{relation}'::regclass AND mode IN ({modes})"
            );
            let (observer, pid) = (&self.observer, waiters[0].0);
            async move {
                Ok::<i64, String>(
                    observer
                        .query_one(&sql, &[&pid])
                        .await
                        .map_err(text)?
                        .get(0),
                )
            }
        };
        require(
            held(
                "openbot_internal.artifact_workspace_quotas",
                "'RowShareLock'",
            )
            .await?
                > 0,
            "the save did not hold the workspace quota row before its operation row",
        )?;
        require(
            held(
                "openbot_internal.thread_history_heads",
                "'RowShareLock','RowExclusiveLock'",
            )
            .await?
                == 0,
            "the save took the head before its quota and operation rows",
        )?;
        require(
            lockable(&self.probe, H_FOR_UPDATE_NOWAIT, thread.as_str()).await?,
            "the head was locked before the quota and operation rows",
        )
    }
}

/// Lock-order evidence for one consumer: `work` starts while the owned ledger lock is held, the
/// evidence is taken from its real wait (see [`LockOrder`]), and `work` finishes once the lock is
/// released. Its result is returned.
async fn observation_precedes_locks<T>(
    p: &pool::DatabasePool,
    application: &str,
    probes: &[(&str, &str)],
    work: impl Future<Output = T> + Send + 'static,
) -> TestResult<T>
where
    T: Send + 'static,
{
    let order = LockOrder::new(p, application, probes).await?;
    let holder = order.hold_ledger().await?;
    let worker = tokio::spawn(work);
    let evidence = order.evidence(holder).await;
    order.release_ledger().await?;
    let output = worker.await.map_err(text)?;
    evidence?;
    Ok(output)
}

// ---------------------------------------------------------------------------------------------
// Current-dataset custom model fixtures (V2 begin, context and start)
// ---------------------------------------------------------------------------------------------

struct ClosedProbe;
#[async_trait]
impl openbot_application::provider::RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<
        Box<dyn openbot_application::provider::RemoteAguiEventStream>,
        openbot_application::provider::RemoteAguiTransportError,
    > {
        Err(openbot_application::provider::RemoteAguiTransportError::Unavailable)
    }
}

fn vault(key: u8) -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        TenantId::new(TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![key; 32]).unwrap(),
    )
}

struct V2 {
    assembly: PostgresApplicationAssembly,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    binding: Arc<PostgresModelDatasetBinding>,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
}

impl V2 {
    async fn new(p: &pool::DatabasePool, config: &pool::DatabaseConfig) -> TestResult<Self> {
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                p.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(text)?,
        );
        let policy_store = PolicyStore::postgres(p.clone(), None);
        policy_store.load().await.map_err(text)?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: p.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault(0x71),
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap()),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(text)?;
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).map_err(text)?;
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            config.clone(),
            PROCESS.to_owned(),
            time::Duration::seconds(30),
        )
        .map_err(text)?
        .with_model_dataset_binding(binding.clone())
        .map_err(text)?;
        let models = PostgresModelConnections::new(
            p.clone(),
            vault(0x71),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x72; 32]),
        )
        .map_err(text)?;
        Ok(Self {
            assembly,
            registry: Some(registry),
            binding,
            directory,
            models,
        })
    }

    fn context(&self, p: &pool::DatabasePool) -> PostgresAgentContextSource {
        context_on(p)
            .with_model_dataset_binding(self.binding.clone())
            .unwrap()
    }

    async fn model(
        &self,
        protocol: CustomModelProtocol,
        endpoint: &str,
    ) -> TestResult<ModelConnection> {
        self.models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Owned choice".into(),
                    protocol,
                    endpoint: endpoint.into(),
                    model: "owned-selected-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new(MODEL_KEY.into())).map_err(text)?,
                },
            )
            .await
            .map_err(text)
    }

    fn request(&self, index: u64, model: &ModelConnection) -> BeginThreadRunV2Request {
        BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                artifact_refs: Vec::new(),
                thread_id: thread_for(index),
                run_id: RunId::new(format!("closure-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: format!("User prompt {index}"),
                selected_skill_slugs: vec![],
                model_selection: RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    model.id.clone(),
                    model.revision,
                    format!("custom:{}", model.id),
                    1,
                )
                .unwrap(),
            },
        }
    }

    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
    }
}

// ---------------------------------------------------------------------------------------------
// c01 -- context load
// ---------------------------------------------------------------------------------------------

fn loaded_prompt(request: &ProviderRequest, index: u64) -> bool {
    request
        .messages
        .iter()
        .any(|message| message.content == format!("User prompt {index}"))
}

/// The load statements wait behind two successive owned table locks so a close can commit at
/// exactly the point of interest: first inside the admission statement, then only after the
/// body has been read. Returns the loader's result after the controlled close.
async fn load_with_close_after_body_read(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
    index: u64,
    terminate_instead: bool,
) -> TestResult<Result<ProviderRequest, AgentContextError>> {
    let begin = begin_v1(index, false, None);
    directory(p, config)?
        .begin_thread_run(begin.clone())
        .await
        .map_err(text)?;
    let lease = lease_of(&begin.command.run_id, &begin.command.thread_id);
    let (loader_pool, loader) = dedicated(config, "closure_context_loader").await?;
    let source = context_on(&loader_pool);
    let observer = p.get().await.map_err(text)?;
    let heads_first = p.get().await.map_err(text)?;
    let messages = p.get().await.map_err(text)?;
    let heads_second = p.get().await.map_err(text)?;
    const HEADS: &str = "LOCK TABLE openbot_internal.thread_history_heads IN ACCESS EXCLUSIVE MODE";
    // 1. The admission statement reads the heads, so it waits behind the first holder.
    let first = hold(&heads_first, HEADS).await?;
    let task = tokio::spawn(async move { source.load(&lease).await });
    wait_blocked(&observer, loader, first).await?;
    let (_, query) = activity(&observer, loader).await?;
    require(
        query.contains("assertion_issued_at_millis") && query.contains("thread_history_heads"),
        "the first wait was not the folded admission statement",
    )?;
    // 2. Move the wait to the body read: take the messages first, then let the heads go.
    let second = hold(
        &messages,
        "LOCK TABLE public.messages IN ACCESS EXCLUSIVE MODE",
    )
    .await?;
    release(&heads_first).await?;
    wait_blocked(&observer, loader, second).await?;
    let (_, query) = activity(&observer, loader).await?;
    require(
        query.contains("FROM public.messages") && query.contains("count(*)"),
        "the second wait was not the first body read",
    )?;
    // 3. Move the wait to the post-read check: hold the heads again, then let the body go.
    let third = hold(&heads_second, HEADS).await?;
    release(&messages).await?;
    wait_blocked(&observer, loader, third).await?;
    let (_, query) = activity(&observer, loader).await?;
    require(
        query.contains("SELECT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads")
            && !query.contains("assertion_issued_at_millis"),
        "the third wait was not the post-read closed-head check",
    )?;
    if terminate_instead {
        observer
            .query_one("SELECT pg_terminate_backend($1)", &[&loader])
            .await
            .map_err(text)?;
        release(&heads_second).await?;
    } else {
        close_statements(&heads_second, &begin.command.thread_id).await?;
        heads_second.batch_execute("COMMIT").await.map_err(text)?;
        require(
            head_phase(&observer, &begin.command.thread_id)
                .await?
                .as_deref()
                == Some("closed"),
            "the controlled close did not commit",
        )?;
    }
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .map_err(|_| "the post-read check never returned".to_owned())?
        .map_err(text)?;
    drop((observer, heads_first, messages, heads_second));
    close_pool(loader_pool).await?;
    Ok(outcome)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_context_refuses_closed_history_legacy_and_v2() {
    owned("closure_context", |p, config| async move {
        let v2 = V2::new(&p, &config).await?;
        let result = async {
            let plain = directory(&p, &config)?;
            let model = v2
                .model(
                    CustomModelProtocol::OpenaiResponses,
                    "https://owned-closure.example.test/v1",
                )
                .await?;
            let legacy_closed = begin_v1(11, false, None);
            let legacy_open = begin_v1(12, true, None);
            let v2_closed = v2.request(13, &model);
            let v2_open = v2.request(14, &model);
            for request in [&legacy_closed, &legacy_open] {
                plain
                    .begin_thread_run(request.clone())
                    .await
                    .map_err(text)?;
            }
            for request in [&v2_closed, &v2_open] {
                v2.directory
                    .begin_thread_run_v2(request.clone())
                    .await
                    .map_err(text)?;
            }
            let lease_legacy_closed = lease_of(
                &legacy_closed.command.run_id,
                &legacy_closed.command.thread_id,
            );
            let lease_legacy_open =
                lease_of(&legacy_open.command.run_id, &legacy_open.command.thread_id);
            let lease_v2_closed = lease_of(&v2_closed.command.run_id, &v2_closed.command.thread_id);
            let lease_v2_open = lease_of(&v2_open.command.run_id, &v2_open.command.thread_id);
            let unconfigured = context_on(&p);
            let configured = v2.context(&p);

            // Open: every path loads the real history.
            require(
                unconfigured
                    .load(&lease_legacy_closed)
                    .await
                    .is_ok_and(|r| loaded_prompt(&r, 11))
                    && configured
                        .load(&lease_legacy_closed)
                        .await
                        .is_ok_and(|r| loaded_prompt(&r, 11))
                    && configured
                        .load(&lease_v2_closed)
                        .await
                        .is_ok_and(|r| loaded_prompt(&r, 13)),
                "premise: the open legacy and V2 histories must load",
            )?;

            close_head(&p, &legacy_closed.command.thread_id).await?;
            close_head(&p, &v2_closed.command.thread_id).await?;
            let before = count(&p, "SELECT count(*) FROM public.messages").await?;
            for (path, result) in [
                (
                    "legacy via the unconfigured source",
                    unconfigured.load(&lease_legacy_closed).await,
                ),
                (
                    "legacy via the configured source",
                    configured.load(&lease_legacy_closed).await,
                ),
                (
                    "v2 via the configured source",
                    configured.load(&lease_v2_closed).await,
                ),
            ] {
                match result {
                    Err(AgentContextError::Stale) => {}
                    Err(other) => {
                        return Err(format!(
                            "{path}: closed history must be Stale, got {other:?}"
                        ));
                    }
                    Ok(_) => return Err(format!("{path}: closed history produced a request")),
                }
            }
            // Another open Thread is untouched, whichever path loads it.
            require(
                unconfigured
                    .load(&lease_legacy_open)
                    .await
                    .is_ok_and(|r| loaded_prompt(&r, 12))
                    && configured
                        .load(&lease_legacy_open)
                        .await
                        .is_ok_and(|r| loaded_prompt(&r, 12))
                    && configured
                        .load(&lease_v2_open)
                        .await
                        .is_ok_and(|r| loaded_prompt(&r, 14)),
                "an unrelated open history stopped loading",
            )?;
            require(
                count(&p, "SELECT count(*) FROM public.messages").await? == before,
                "a refused load wrote history",
            )?;

            // A close that commits after the body has been read is still caught by the re-check.
            let outcome = load_with_close_after_body_read(&p, &config, 15, false).await?;
            require(
                outcome.as_ref().err() == Some(&AgentContextError::Stale),
                "a close committed after the body read still produced a request",
            )
        }
        .await;
        v2.finish().await;
        result
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c02 -- a Run whose context load meets a closed history ends without a provider start
// ---------------------------------------------------------------------------------------------

struct CountingProvider(Arc<AtomicUsize>);
#[async_trait]
impl ProviderAdapter for CountingProvider {
    async fn start(
        &self,
        _: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProviderPortError::Unavailable)
    }
}

async fn channel_image(p: &pool::DatabasePool) -> TestResult<Value> {
    let c = p.get().await.map_err(text)?;
    Ok(c.query_one(
        "SELECT jsonb_build_object(
           'channels',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM public.channels x),
           'sources',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY channel_id),'[]'::jsonb)
                      FROM openbot_internal.channel_history_sources x))",
        &[],
    )
    .await
    .map_err(text)?
    .get(0))
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_closed_context_run_ends_without_provider_start() {
    owned("closure_run_end", |p, config| async move {
        // A channel Thread, so the canonical channel preview can be shown unchanged.
        let begin = begin_v1(21, true, None);
        directory(&p, &config)?
            .begin_thread_run(begin.clone())
            .await
            .map_err(text)?;
        let runtime = Arc::new(
            PostgresRunRuntime::new(
                p.clone(),
                PROCESS.to_owned(),
                DEFAULT_THREAD_LEASE_DURATION,
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .map_err(text)?,
        );
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(text)?
            .ok_or("the begun Run has no pending dispatch")?;
        let lease = runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
        require(
            lease.run_id() == &begin.command.run_id,
            "the claim selected another Run",
        )?;
        let preview = channel_image(&p).await?;
        close_head(&p, &begin.command.thread_id).await?;

        let starts = Arc::new(AtomicUsize::new(0));
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(context_on(&p)),
            Arc::new(CountingProvider(starts.clone())),
            Arc::new(NoAgentToolInvoker),
            Arc::new(
                openbot_infra::agent_audit::PostgresAgentAudit::new(p.clone(), AUDIT_KEY.to_vec())
                    .map_err(text)?,
            ),
            BuiltInAgentConfig {
                queue_capacity: 4,
                max_concurrency: 2,
                max_tool_concurrency: 1,
                // No heartbeat can fire during the case: the context load is the only way out.
                lease_renew_interval: Duration::from_secs(60),
                run_deadline: Some(Duration::from_secs(30)),
            },
        )
        .map_err(|code| code.as_str().to_owned())?;
        let consumer = agent.consumer();
        let outcome = async {
            require(
                consumer.dispatch(lease.clone()).await == RunDispatchDecision::Accepted,
                "the closed Run's dispatch was not accepted for reservation",
            )?;
            consumer
                .activate(&lease)
                .await
                .map_err(|code| code.as_str().to_owned())?;
            let observer = p.get().await.map_err(text)?;
            until("the Run reaches a durable terminal", || async {
                Ok(observer
                    .query_one(
                        "SELECT status<>'running' FROM public.runs WHERE run_id=$1",
                        &[&begin.command.run_id.as_str()],
                    )
                    .await
                    .map_err(text)?
                    .get::<_, bool>(0))
            })
            .await
        }
        .await;
        agent.stop().await;
        outcome?;

        require(
            starts.load(Ordering::SeqCst) == 0,
            "a provider was started for a closed history",
        )?;
        let c = p.get().await.map_err(text)?;
        let run = c
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&begin.command.run_id.as_str()],
            )
            .await
            .map_err(text)?;
        let (status, code) = (run.get::<_, String>(0), run.get::<_, Option<String>>(1));
        // Stale maps to AgentFailure::RuntimeLeaseLost, whose stable Run code is
        // `runtime_lease_expired`; no new failure code exists for a closed history.
        if status != "reconciliation_required" || code.as_deref() != Some("runtime_lease_expired") {
            return Err(format!(
                "the closed context did not end through the lease-lost reconciliation path: {status} {code:?}"
            ));
        }
        let terminal: Vec<Value> = c
            .query(
                "SELECT payload FROM public.run_events WHERE run_id=$1 AND terminal",
                &[&begin.command.run_id.as_str()],
            )
            .await
            .map_err(text)?
            .iter()
            .map(|row| row.get(0))
            .collect();
        require(
            terminal
                == [json!({"status":"reconciliation_required","errorCode":"runtime_lease_expired"})],
            "the terminal is not the one fixed lease-lost reconciliation event",
        )?;
        let r = c
            .query_one(
                "SELECT (SELECT count(*) FROM public.messages WHERE run_id=$1 AND role='assistant'),
                        (SELECT count(*) FROM public.run_events WHERE run_id=$1 AND event_type='semantic_chunk')",
                &[&begin.command.run_id.as_str()],
            )
            .await
            .map_err(text)?;
        require(
            r.get::<_, i64>(0) == 0 && r.get::<_, i64>(1) == 0,
            "a closed history gained assistant text or text chunks",
        )?;
        require(
            channel_image(&p).await? == preview,
            "the canonical channel preview or its source changed",
        )
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c03 -- custom start (both routes) refuses a closed history before the Vault and the send
// ---------------------------------------------------------------------------------------------

const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY_DER_BASE64: &str =
    "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

struct LocalResolver {
    address: SocketAddr,
    resolved: Arc<AtomicUsize>,
}
#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.resolved.fetch_add(1, Ordering::SeqCst);
        if host != "idp.test" || port != self.address.port() {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}

/// A loopback TLS model endpoint. Every request waits for one `gate` permit before it is answered,
/// so a start can be held inside the adapter while PostgreSQL is observed.
struct Tls {
    address: SocketAddr,
    root: CertificateDer<'static>,
    accepted: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    resolved: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Tls {
    async fn new() -> Self {
        let root = CertificateDer::from(STANDARD.decode(TEST_CA_DER_BASE64).unwrap());
        let leaf = CertificateDer::from(STANDARD.decode(TEST_LEAF_DER_BASE64).unwrap());
        let key = PrivateKeyDer::try_from(STANDARD.decode(TEST_KEY_DER_BASE64).unwrap()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let resolved = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let (stop, mut stopped) = oneshot::channel();
        let (seen_accept, seen_request, held) = (accepted.clone(), requests.clone(), gate.clone());
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    connection = listener.accept() => {
                        let Ok((stream, _)) = connection else { break };
                        seen_accept.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let seen_request = seen_request.clone();
                        let held = held.clone();
                        children.spawn(async move {
                            let Ok(mut stream) = acceptor.accept(stream).await else { return };
                            if !read_request(&mut stream).await { return }
                            seen_request.fetch_add(1, Ordering::SeqCst);
                            let Ok(permit) = held.acquire().await else { return };
                            permit.forget();
                            let body = format!(
                                "data: {}\n\ndata: [DONE]\n\n",
                                json!({"id":"chat-owned","choices":[{"index":0,"delta":{"content":"hello custom"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}})
                            );
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            if stream.write_all(head.as_bytes()).await.is_ok() {
                                let _ = stream.write_all(body.as_bytes()).await;
                            }
                            let _ = stream.shutdown().await;
                        });
                    },
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            address,
            root,
            accepted,
            requests,
            resolved,
            gate,
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn endpoint(&self) -> String {
        format!("https://idp.test:{}/v1", self.address.port())
    }

    fn dialer(&self) -> SafeDialer {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap()),
            Arc::new(LocalResolver {
                address: self.address,
                resolved: self.resolved.clone(),
            }),
            [self.root.clone()],
        )
        .unwrap()
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}

/// Reads one complete HTTP request; `false` when the peer vanished first.
async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let split = loop {
        let Ok(n) = stream.read(&mut buffer).await else {
            return false;
        };
        if n == 0 {
            return false;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < split + length {
        let Ok(n) = stream.read(&mut buffer).await else {
            return false;
        };
        if n == 0 {
            return false;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    true
}

fn authority_refusal(result: &Result<Box<dyn ProviderSession>, ProviderPortError>) -> bool {
    matches!(
        result,
        Err(ProviderPortError::InvalidRequest {
            field: "custom_model_authority"
        })
    )
}

const H_FOR_UPDATE_NOWAIT: &str = "SELECT thread_id FROM openbot_internal.thread_history_heads WHERE thread_id=$1 FOR UPDATE NOWAIT";
const THREAD_FOR_UPDATE_NOWAIT: &str =
    "SELECT thread_id FROM public.threads WHERE thread_id=$1 FOR UPDATE NOWAIT";

/// While a start waits inside the adapter, its transaction keeps none of the locks the `free`
/// probes need: the head for both routes and, on the legacy route, the Thread row too, so the
/// Run's durable cancel claim (which needs the Thread row exclusively) is never held back by it.
/// The current-dataset route keeps the shares of its own authority load, so its Thread row is not
/// probed. A control first proves that the probes do refuse a real share holder.
async fn start_holds_no_history_lock_across_send(
    p: &pool::DatabasePool,
    tls: &Tls,
    provider: &Arc<PostgresCustomModelProvider>,
    request: ProviderRequest,
    thread: &ThreadId,
    free: &[&str],
) -> TestResult {
    let probe = p.get().await.map_err(text)?;
    let holder = p.get().await.map_err(text)?;
    holder.batch_execute("BEGIN").await.map_err(text)?;
    holder
        .query(
            "SELECT thread_id FROM public.threads WHERE thread_id=$1 FOR SHARE",
            &[&thread.as_str()],
        )
        .await
        .map_err(text)?;
    holder
        .query(
            "SELECT thread_id FROM openbot_internal.thread_history_heads WHERE thread_id=$1 FOR SHARE",
            &[&thread.as_str()],
        )
        .await
        .map_err(text)?;
    let mut seen = true;
    for sql in free {
        seen &= !lockable(&probe, sql, thread.as_str()).await?;
    }
    holder.batch_execute("ROLLBACK").await.map_err(text)?;
    require(
        seen,
        "premise: the probes did not see a real Thread and head share",
    )?;

    let before = tls.requests();
    let start = {
        let provider = Arc::clone(provider);
        tokio::spawn(async move { provider.start(request).await })
    };
    until("the start reaching the owned model endpoint", || async {
        Ok(tls.requests() == before + 1)
    })
    .await?;
    let mut unlocked = true;
    for sql in free {
        unlocked &= lockable(&probe, sql, thread.as_str()).await?;
    }
    tls.gate.add_permits(1);
    let session = tokio::time::timeout(Duration::from_secs(10), start)
        .await
        .map_err(|_| "the start never returned".to_owned())?
        .map_err(text)?;
    require(
        unlocked,
        "a start inside the adapter held a lock the probes need",
    )?;
    require(
        session.is_ok(),
        "the open history's start did not return a session",
    )?;
    drop((probe, holder));
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_custom_start_refuses_closed_history_before_send() {
    owned("closure_custom_start", |p, config| async move {
        let tls = Tls::new().await;
        let v2 = V2::new(&p, &config).await?;
        let result = async {
            let model = v2
                .model(CustomModelProtocol::OpenaiChatCompletions, &tls.endpoint())
                .await?;
            let selection = RunModelSelection {
                connection_id: model.id.clone(),
                expected_revision: model.revision,
            };
            let plain = directory(&p, &config)?;
            let context = v2.context(&p);
            let budget = SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(20)).unwrap();
            let provider_for = |vault_key: u8| {
                PostgresCustomModelProvider::new(
                    p.clone(),
                    vault(vault_key),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                    tls.dialer(),
                    budget,
                    Some(Duration::from_secs(2)),
                )
                .unwrap()
                .with_model_dataset_binding(v2.binding.clone())
                .unwrap()
            };
            let provider = Arc::new(provider_for(0x71));
            // The same start with a Vault that cannot open the stored secret: it fails on the
            // credential only when the start gets as far as the Vault.
            let unopenable = provider_for(0x7f);

            // Runs 31/33/35 are current-dataset selections, 32/34/36 are legacy selections.
            let mut requests = Vec::new();
            for index in 31..=36u64 {
                let (thread, run) = if index % 2 == 1 {
                    let begin = v2.request(index, &model);
                    v2.directory
                        .begin_thread_run_v2(begin.clone())
                        .await
                        .map_err(text)?;
                    (begin.command.thread_id, begin.command.run_id)
                } else {
                    let begin = begin_v1(index, false, Some(selection.clone()));
                    plain.begin_thread_run(begin.clone()).await.map_err(text)?;
                    (begin.command.thread_id, begin.command.run_id)
                };
                let request = context.load(&lease_of(&run, &thread)).await.map_err(text)?;
                requests.push((index, thread, request));
            }
            let request_of = |index: u64| requests.iter().find(|r| r.0 == index).unwrap();

            // Open histories: the start reaches the Vault and the endpoint.
            for index in [31u64, 32] {
                let (_, _, request) = request_of(index);
                require(
                    matches!(
                        unopenable.start(request.clone()).await,
                        Err(ProviderPortError::InvalidRequest {
                            field: "custom_model_credential"
                        })
                    ),
                    "premise: an open history must reach the Vault",
                )?;
                tls.gate.add_permits(1);
                require(
                    provider.start(request.clone()).await.is_ok(),
                    "premise: an open history must start the provider",
                )?;
            }
            let reached = tls.requests();
            require(reached == 2, "premise: exactly two sends so far")?;

            // Closed histories: the existing authority refusal on both routes, before the Vault
            // and the network.
            let accepted = tls.accepted.load(Ordering::SeqCst);
            let runs_before = count(&p, "SELECT count(*) FROM public.runs").await?;
            for index in [33u64, 34] {
                let (_, thread, request) = request_of(index);
                close_head(&p, thread).await?;
                require(
                    authority_refusal(&provider.start(request.clone()).await),
                    "a closed history did not get the custom-model authority refusal",
                )?;
                require(
                    authority_refusal(&unopenable.start(request.clone()).await),
                    "a closed history reached the Vault before it was refused",
                )?;
            }
            require(
                tls.requests() == reached && tls.accepted.load(Ordering::SeqCst) == accepted,
                "a refused start opened a connection to the model endpoint",
            )?;
            require(
                count(&p, "SELECT count(*) FROM public.runs").await? == runs_before,
                "a refused start changed Run state",
            )?;

            // Neither route keeps a head lock across the send, and the legacy route keeps no
            // Thread lock either, so a durable cancel can still claim the Run while the response
            // headers are pending.
            {
                let (_, thread, request) = request_of(35);
                start_holds_no_history_lock_across_send(
                    &p,
                    &tls,
                    &provider,
                    request.clone(),
                    thread,
                    &[H_FOR_UPDATE_NOWAIT],
                )
                .await?;
            }
            {
                let (_, thread, request) = request_of(36);
                start_holds_no_history_lock_across_send(
                    &p,
                    &tls,
                    &provider,
                    request.clone(),
                    thread,
                    &[THREAD_FOR_UPDATE_NOWAIT, H_FOR_UPDATE_NOWAIT],
                )
                .await?;
            }
            Ok(())
        }
        .await;
        v2.finish().await;
        tls.stop().await;
        result
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c04 -- tool decision / retry / capability refuse a closed history, outcomes are still kept
// ---------------------------------------------------------------------------------------------

fn tool_draft(run: &RunId, call: &str, sequence: u64) -> ToolDecisionDraft {
    ToolDecisionDraft {
        call_id: ToolCallId::new(call),
        run_id: run.clone(),
        call_seq: sequence,
        actor: ActorId::new("alice"),
        bot: BotId::new("bot"),
        metadata: ToolMetadata {
            name: ToolName::new("computer.write").unwrap(),
            schema_hash: Sha256Digest::of(b"closure schema"),
            catalog_generation: CatalogGeneration::new(3),
            effect: EffectClassification::declared(Effect::Write),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(5),
            approval_class: ApprovalClass::NotRequired,
            sandbox: SandboxRequirement::RequiredNoEgress,
            limits: ToolLimits {
                max_input_bytes: 1024,
                max_output_bytes: 1024,
                max_model_visible_bytes: 1024,
            },
            resource_locks: Vec::new(),
        },
        args_hash: Sha256Digest::of(b"closure arguments"),
        target: ApprovalTarget {
            kind: "browser_tab",
            id: "owned-tab".to_owned(),
        },
        policy_version: PolicyVersionTag::new("closure-policy"),
        approval_id: None,
        idempotency_key: None,
    }
}

fn pristine_attempt(call: &str, sequence: i64) -> tool_attempts::Row {
    tool_attempts::Row {
        tool_call_id: call.to_owned(),
        attempt_seq: sequence,
        attempt_id: uuid::Uuid::now_v7().to_string(),
        capability_id: None,
        status: "decision_recorded".to_owned(),
        commit_state: None,
        output_bytes: None,
        duration_ms: None,
        error_code: None,
        started_at: None,
        finished_at: None,
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn tool_outcome(
    decision: &ToolDecisionDraft,
    receipt: DurableDecisionReceipt,
    capability: &CapabilityId,
) -> ToolOutcomeDraft {
    ToolOutcomeDraft {
        decision: decision.clone(),
        receipt,
        capability_id: capability.clone(),
        outcome: ToolOutcome {
            commit_state: CommitState::Committed,
            output_bytes: 12,
            duration: Duration::from_millis(1),
            error_code: None,
        },
    }
}

/// Journal rows plus the audit chain: what a refused write must leave untouched.
async fn journal_image(p: &pool::DatabasePool) -> TestResult<Value> {
    let c = p.get().await.map_err(text)?;
    Ok(c.query_one(
        "SELECT jsonb_build_object(
           'calls',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY tool_call_id),'[]'::jsonb) FROM public.tool_calls x),
           'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY tool_call_id,attempt_seq),'[]'::jsonb) FROM public.tool_attempts x),
           'audit',(SELECT count(*) FROM public.audit_events),
           'checkpoints',(SELECT count(*) FROM public.audit_checkpoints))",
        &[],
    )
    .await
    .map_err(text)?
    .get(0))
}

fn conflict_refusal(error: &InfraError) -> bool {
    matches!(
        error,
        InfraError::RepositoryInvariant {
            code: "tool_journal_write_conflict"
        }
    )
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_tool_decision_retry_attach_refuse_before_effect_outcome_kept() {
    owned("closure_tools", |p, config| async move {
        let dir = directory(&p, &config)?;
        let closing = begin_v1(41, false, None);
        let open = begin_v1(42, false, None);
        for request in [&closing, &open] {
            dir.begin_thread_run(request.clone()).await.map_err(text)?;
        }
        let journal = PostgresToolJournal::new(p.clone(), AUDIT_KEY.to_vec()).map_err(text)?;
        let attempts = ToolAttemptRepo::new(p.clone());

        // Before the close: call 1 is executing, call 2 is decided only.
        let call1 = tool_draft(&closing.command.run_id, "closure-call-1", 0);
        let receipt1 = journal.record_decision(&call1).await.map_err(text)?;
        let capability1 = CapabilityId::new(uuid::Uuid::now_v7().to_string());
        journal
            .attach_capability(&call1.call_id, &capability1)
            .await
            .map_err(text)?;
        let call2 = tool_draft(&closing.command.run_id, "closure-call-2", 1);
        journal.record_decision(&call2).await.map_err(text)?;
        let outcome1 = tool_outcome(&call1, receipt1, &capability1);

        close_head(&p, &closing.command.thread_id).await?;
        let before = journal_image(&p).await?;

        let call3 = tool_draft(&closing.command.run_id, "closure-call-3", 2);
        require(
            journal.record_decision(&call3).await.err() == Some(ToolPortError::Conflict),
            "a new decision on a closed history was not the journal conflict",
        )?;
        require(
            attempts
                .insert_retry(&pristine_attempt("closure-call-2", 1))
                .await
                .err()
                .as_ref()
                .is_some_and(conflict_refusal),
            "a retry on a closed history was not the journal conflict",
        )?;
        require(
            journal
                .attach_capability(
                    &call2.call_id,
                    &CapabilityId::new(uuid::Uuid::now_v7().to_string()),
                )
                .await
                == Err(ToolPortError::Conflict),
            "a capability on a closed history was not the journal conflict",
        )?;
        require(
            attempts
                .attach_capability(
                    "closure-call-2",
                    0,
                    &uuid::Uuid::now_v7().to_string(),
                    time::OffsetDateTime::now_utc(),
                )
                .await
                .err()
                .as_ref()
                .is_some_and(conflict_refusal),
            "the low-level capability attach on a closed history was not the journal conflict",
        )?;
        require(
            journal_image(&p).await? == before,
            "a refused write changed calls, attempts or audit",
        )?;
        let c = p.get().await.map_err(text)?;
        let state = c
            .query_one(
                "SELECT status,capability_id FROM public.tool_attempts WHERE tool_call_id='closure-call-2' AND attempt_seq=0",
                &[],
            )
            .await
            .map_err(text)?;
        require(
            state.get::<_, String>(0) == "decision_recorded"
                && state.get::<_, Option<String>>(1).is_none(),
            "the decided-only attempt left decision_recorded",
        )?;

        // An effect that already ran still records what happened.
        journal.record_outcome(&outcome1).await.map_err(text)?;
        let done = c
            .query_one(
                "SELECT status,commit_state FROM public.tool_attempts WHERE tool_call_id='closure-call-1' AND attempt_seq=0",
                &[],
            )
            .await
            .map_err(text)?;
        require(
            done.get::<_, String>(0) == "completed"
                && done.get::<_, Option<String>>(1).as_deref() == Some("committed"),
            "the executed attempt's outcome was not recorded on a closed history",
        )?;
        require(
            c.query_one("SELECT count(*) FROM public.audit_events", &[])
                .await
                .map_err(text)?
                .get::<_, i64>(0)
                == before["audit"].as_i64().unwrap() + 1,
            "the executed effect's outcome did not reach the audit chain",
        )?;

        // Another open Thread keeps every one of these writes.
        let call4 = tool_draft(&open.command.run_id, "closure-call-4", 0);
        let receipt4 = journal.record_decision(&call4).await.map_err(text)?;
        let capability4 = CapabilityId::new(uuid::Uuid::now_v7().to_string());
        journal
            .attach_capability(&call4.call_id, &capability4)
            .await
            .map_err(text)?;
        let call5 = tool_draft(&open.command.run_id, "closure-call-5", 1);
        journal.record_decision(&call5).await.map_err(text)?;
        attempts
            .insert_retry(&pristine_attempt("closure-call-5", 1))
            .await
            .map_err(text)?;
        journal
            .record_outcome(&tool_outcome(&call4, receipt4, &capability4))
            .await
            .map_err(text)?;

        // Lock order: the observation is the entry's own first statement, and until it finishes
        // the Run is still unlocked. The entry runs on a pool of its own, so the one backend
        // waiting for the ledger can only be the entry's.
        let entry = entry_pool(&config, ENTRY_TOOLS, 2).await?;
        let entry_journal = PostgresToolJournal::new(entry.clone(), AUDIT_KEY.to_vec()).map_err(text)?;
        let entry_attempts = ToolAttemptRepo::new(entry.clone());
        let run_probe = "SELECT run_id FROM public.runs WHERE run_id=$1 FOR UPDATE NOWAIT";
        let run_key = open.command.run_id.as_str().to_owned();
        let call6 = tool_draft(&open.command.run_id, "closure-call-6", 2);
        let ordered = async {
            let decided = observation_precedes_locks(&p, ENTRY_TOOLS, &[(run_probe, &run_key)], {
                let (journal, call6) = (entry_journal.clone(), call6.clone());
                async move { journal.record_decision(&call6).await }
            })
            .await?;
            require(decided.is_ok(), "the held-back decision never completed")?;
            let capability6 = CapabilityId::new(uuid::Uuid::now_v7().to_string());
            let attached = observation_precedes_locks(&p, ENTRY_TOOLS, &[(run_probe, &run_key)], {
                let (journal, id, capability6) =
                    (entry_journal.clone(), call6.call_id.clone(), capability6.clone());
                async move { journal.attach_capability(&id, &capability6).await }
            })
            .await?;
            require(attached.is_ok(), "the held-back capability never completed")?;
            let retried = observation_precedes_locks(&p, ENTRY_TOOLS, &[(run_probe, &run_key)], {
                let attempts = entry_attempts.clone();
                async move {
                    attempts
                        .insert_retry(&pristine_attempt("closure-call-6", 1))
                        .await
                }
            })
            .await?;
            require(retried.is_ok(), "the held-back retry never completed")
        }
        .await;
        close_pool(entry).await.and(ordered)
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c05 -- remember effect refuses a new effect and replays an existing receipt
// ---------------------------------------------------------------------------------------------

struct CaptureMemory {
    request: Mutex<Option<RememberToolMemoryRequest>>,
}
#[async_trait]
impl RememberToolMemory for CaptureMemory {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<CommittedMemoryEffect, MemoryAdministrationError> {
        *self.request.lock().unwrap() = Some(request);
        Err(MemoryAdministrationError::CommitUnknown)
    }
}

/// The real journal, except that the outcome is never recorded: the call stays executing, which
/// is exactly the state a remember effect is admitted from.
struct KeepExecuting {
    inner: PostgresToolJournal,
}
#[async_trait]
impl ToolJournal for KeepExecuting {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.inner.record_decision(draft).await
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.inner.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, _: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "owned_capture",
        })
    }
}

/// Runs the real capability pipeline for a `remember` call and keeps only the request the memory
/// adapter would have received.
async fn capture_remember(
    p: &pool::DatabasePool,
    run: &RunId,
    sequence: u64,
    content: &str,
) -> TestResult<RememberToolMemoryRequest> {
    let policy = PolicyStore::postgres(p.clone(), None);
    policy.load().await.map_err(text)?;
    policy
        .set(
            ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: vec![],
                allow: vec!["tool.name == \"remember\"".into()],
            },
            Some("alice"),
        )
        .await
        .map_err(text)?;
    let memory = Arc::new(CaptureMemory {
        request: Mutex::new(None),
    });
    let control = PostgresBuiltInToolControlPlane::new(
        p.clone(),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        policy,
        memory.clone(),
    );
    let journal = KeepExecuting {
        inner: PostgresToolJournal::new(p.clone(), AUDIT_KEY.to_vec()).map_err(text)?,
    };
    let invocation = ToolInvocation {
        call_id: ToolCallId::new(format!("closure-remember-{sequence}")),
        run_id: run.clone(),
        bot_id: BotId::new("bot"),
        call_seq: sequence,
        tool_name: "remember".into(),
        arguments: json!({"memoryKind":"preference","scope":"user","content":content,"tags":["closure"],"sensitivity":"normal"}),
    };
    let result = invoke_tool(&control, &journal, &auth(), invocation).await;
    let request = memory.request.lock().unwrap().clone();
    request.ok_or_else(|| format!("the pipeline never reached the memory adapter: {result:?}"))
}

async fn remember_image(p: &pool::DatabasePool) -> TestResult<Vec<i64>> {
    let mut image = Vec::new();
    for table in [
        "public.memories",
        "public.memory_events",
        "public.remember_effect_receipts",
        "public.audit_events",
    ] {
        image.push(count(p, &format!("SELECT count(*) FROM {table}")).await?);
    }
    Ok(image)
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_remember_effect_refuses_new_and_replays_existing() {
    owned("closure_remember", |p, config| async move {
        let lease_for = time::Duration::minutes(10);
        let begin = begin_v1(51, false, None);
        PostgresThreadDirectory::with_runtime(p.clone(), config.clone(), PROCESS.to_owned(), lease_for)
            .map_err(text)?
            .begin_thread_run(begin.clone())
            .await
            .map_err(text)?;
        let runtime = PostgresRunRuntime::new(
            p.clone(),
            PROCESS.to_owned(),
            lease_for,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(text)?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(text)?
            .ok_or("the begun Run has no pending dispatch")?;
        runtime.acknowledge_dispatch(&claim).await.map_err(text)?;

        // Two real executing remember calls on one Run; the first one commits while open.
        let first = capture_remember(&p, &begin.command.run_id, 0, "closure content one").await?;
        let second = capture_remember(&p, &begin.command.run_id, 1, "closure content two").await?;
        let store = PostgresMemoryAdministration::new(p.clone())
            .with_effect_audit_key(AUDIT_KEY.to_vec())
            .map_err(text)?;
        // The first effect commits while open, on a pool of its own: with the schema observation
        // held back, the one backend waiting for the ledger can only be the entry's, and the
        // actor row is still unlocked.
        let users_probe = "SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT";
        let entry = entry_pool(&config, ENTRY_REMEMBER, 2).await?;
        let entry_store = PostgresMemoryAdministration::new(entry.clone())
            .with_effect_audit_key(AUDIT_KEY.to_vec())
            .map_err(text)?;
        let ordered = observation_precedes_locks(&p, ENTRY_REMEMBER, &[(users_probe, "alice")], {
            let first = first.clone();
            async move { entry_store.remember_from_tool(first).await }
        })
        .await;
        let closed = close_pool(entry).await;
        let committed = ordered?.map_err(text)?;
        closed?;
        let image = remember_image(&p).await?;
        require(
            image[..3] == [1, 1, 1],
            "premise: one memory, event and receipt were committed",
        )?;

        close_head(&p, &begin.command.thread_id).await?;
        require(
            store.remember_from_tool(first.clone()).await.as_ref() == Ok(&committed),
            "the exact replay of a committed effect did not return its original receipt",
        )?;
        require(
            store.remember_from_tool(second.clone()).await == Err(MemoryAdministrationError::Conflict),
            "a new remember effect on a closed history was not refused as a conflict",
        )?;
        require(
            remember_image(&p).await? == image,
            "a refused or replayed remember effect wrote memories, events, receipts or audit",
        )?;
        let c = p.get().await.map_err(text)?;
        let state = c
            .query_one(
                "SELECT status,commit_state FROM public.tool_attempts a JOIN public.tool_calls c USING(tool_call_id) WHERE c.call_seq=1 AND c.run_id=$1",
                &[&begin.command.run_id.as_str()],
            )
            .await
            .map_err(text)?;
        require(
            state.get::<_, String>(0) == "executing" && state.get::<_, Option<String>>(1).is_none(),
            "the refused effect's attempt was touched",
        )
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c06 -- explicit save refuses a new admission, a start of IO, and a registration after IO
// ---------------------------------------------------------------------------------------------

/// The only filesystem tree this case may remove: a freshly created random private root.
struct OwnedRoot(PathBuf);

impl OwnedRoot {
    fn new() -> TestResult<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path =
            std::env::temp_dir().join(format!("openbot-consumer-closure-{}", uuid::Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(text)?;
        Ok(Self(path))
    }

    fn object_count(&self) -> TestResult<usize> {
        std::fs::read_dir(self.0.join("objects"))
            .map(|entries| entries.count())
            .map_err(text)
    }

    fn object_bytes(&self, artifact_id: &str) -> TestResult<Vec<u8>> {
        std::fs::read(self.0.join("objects").join(artifact_id)).map_err(text)
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0).is_ok() && !self.0.exists();
        if !std::thread::panicking() {
            assert!(removed, "owned artifact root cleanup failed");
        }
    }
}

struct ArmedHold {
    tag: &'static [u8],
    remaining: usize,
    arrived: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// The controller's side of one held backend frame.
struct HeldAck {
    arrived: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
}

impl HeldAck {
    async fn arrived(&mut self) -> TestResult {
        tokio::time::timeout(Duration::from_secs(30), &mut self.arrived)
            .await
            .map_err(|_| "the selected backend frame never arrived".to_owned())?
            .map_err(|_| "the proxy dropped the selected backend frame".to_owned())
    }

    fn release(self) -> TestResult {
        self.release
            .send(())
            .map_err(|()| "the proxy no longer waits for the held frame".to_owned())
    }
}

/// A PostgreSQL wire proxy that can hold one chosen backend frame, so the successful completion
/// of a statement (here COMMIT or START TRANSACTION) reaches the client only after the controller acted. The
/// statement has really run; only its acknowledgement is delayed.
struct AckProxy {
    port: u16,
    armed: Arc<Mutex<Option<ArmedHold>>>,
    task: JoinHandle<()>,
}

impl AckProxy {
    async fn start(host: String, port: u16) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let proxy_port = listener.local_addr().map_err(text)?.port();
        let armed = Arc::new(Mutex::new(None::<ArmedHold>));
        let shared = Arc::clone(&armed);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let shared = Arc::clone(&shared);
                children.spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err::<(), std::io::Error>(std::io::Error::other(
                                    "invalid owned proxy frame",
                                ));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            let selected = if kind == b'C' {
                                let mut guard = shared.lock().unwrap();
                                match guard.as_mut() {
                                    Some(hold) if hold.tag == payload.as_slice() => {
                                        hold.remaining -= 1;
                                        if hold.remaining == 0 {
                                            guard.take()
                                        } else {
                                            None
                                        }
                                    }
                                    _ => None,
                                }
                            } else {
                                None
                            };
                            if let Some(hold) = selected {
                                hold.arrived.send(()).map_err(|()| {
                                    std::io::Error::other("owned ACK controller closed")
                                })?;
                                tokio::time::timeout(Duration::from_secs(20), hold.release)
                                    .await
                                    .map_err(|_| std::io::Error::other("owned ACK hold timed out"))?
                                    .map_err(|_| {
                                        std::io::Error::other("owned ACK release closed")
                                    })?;
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = backend => {},
                    }
                });
            }
        });
        Ok(Self {
            port: proxy_port,
            armed,
            task,
        })
    }

    /// Hold the acknowledgement of the `ordinal`-th `tag` ("COMMIT\0" or "START TRANSACTION\0") from now on.
    fn arm(&self, tag: &'static [u8], ordinal: usize) -> TestResult<HeldAck> {
        let (arrived_sender, arrived) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        let mut armed = self.armed.lock().unwrap();
        require(armed.is_none(), "owned ACK hold already armed")?;
        *armed = Some(ArmedHold {
            tag,
            remaining: ordinal,
            arrived: arrived_sender,
            release: release_receiver,
        });
        Ok(HeldAck { arrived, release })
    }
}

impl Drop for AckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn sha256_hex(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn save_request(begin: &BeginThreadRunRequest) -> SaveRunMessageTextArtifact {
    SaveRunMessageTextArtifact {
        request_id: uuid::Uuid::now_v7().to_string(),
        source_thread_id: begin.command.thread_id.clone(),
        source_run_id: begin.command.run_id.clone(),
        source_message_id: format!("{}:input", begin.command.run_id.as_str()),
        expected_sha256: sha256_hex(&begin.command.message),
    }
}

async fn artifact_facts(p: &pool::DatabasePool) -> TestResult<Value> {
    let c = p.get().await.map_err(text)?;
    Ok(c.query_one(
        "SELECT jsonb_build_object(
           'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
           'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
           'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
           'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
           'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
           'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a WHERE event_type='artifact.saved'))",
        &[],
    )
    .await
    .map_err(text)?
    .get(0))
}

fn rows_of<'a>(facts: &'a Value, key: &str) -> &'a [Value] {
    facts[key].as_array().map_or(&[], Vec::as_slice)
}

/// A controller transaction holding the save operation row of `thread` (it exists from the
/// admission on), so the save's own wait for that row can be examined.
async fn hold_operation(
    direct: &pool::DatabasePool,
    thread: &ThreadId,
) -> TestResult<(pool::PooledClient, i32)> {
    let facts = artifact_facts(direct).await?;
    let operation_id = rows_of(&facts, "operations")
        .iter()
        .find(|operation| operation["source_thread_id"] == thread.as_str())
        .and_then(|operation| operation["operation_id"].as_str())
        .ok_or("the save has no operation row yet")?
        .to_owned();
    let holder = direct.get().await.map_err(text)?;
    holder
        .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    holder
        .query_one(
            "SELECT operation_id FROM openbot_internal.artifact_save_operations WHERE operation_id=$1 FOR UPDATE",
            &[&operation_id],
        )
        .await
        .map_err(text)?;
    let pid = backend_pid(&holder).await?;
    Ok((holder, pid))
}

/// Builds the save adapter over `registry` and a fresh private root.
async fn artifact_admin(
    registry: Arc<ArtifactDatasetRegistry>,
) -> TestResult<(PostgresArtifactAdministration, OwnedRoot)> {
    let root = OwnedRoot::new()?;
    let policy = ArtifactQuotaPolicy::default();
    let store = DatasetBoundArtifactStore::bind_host_root(
        std::fs::File::open(&root.0).map_err(text)?,
        Arc::clone(&registry),
        policy,
    )
    .await
    .map_err(text)?;
    let administration = PostgresArtifactAdministration::new(
        registry,
        Arc::new(store),
        policy,
        SecretBytes::new(vec![0x81; 32]),
    )
    .map_err(text)?;
    Ok((administration, root))
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_explicit_save_refuses_admission_and_post_io_registration() {
    let admin = harness::admin_config("closure_save");
    harness::with_temp_database(&admin, "closuresave", |config| async move {
        // Controllers talk to PostgreSQL directly; the saving adapter goes through the proxy.
        let direct = pool::connect(&config.clone().with_max_pool_size(4))
            .await
            .map_err(text)?;
        seed(&direct).await?;
        let proxy = AckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config.clone();
        proxied.host = "127.0.0.1".to_owned();
        proxied.port = proxy.port;
        let proxied = proxied
            .with_max_pool_size(8)
            .with_application_name(ENTRY_SAVE);
        let p = pool::connect(&proxied).await.map_err(text)?;
        let result = save_case(&direct, &p, &proxied, &proxy).await;
        let closed = close_pool(p).await;
        result.and(closed).and(close_pool(direct).await)
    })
    .await;
}

async fn save_case(
    direct: &pool::DatabasePool,
    p: &pool::DatabasePool,
    proxied: &pool::DatabaseConfig,
    proxy: &AckProxy,
) -> TestResult {
    let registry = Arc::new(
        ArtifactDatasetRegistry::from_server(
            p.clone(),
            &DeploymentId::new(DEP),
            &TenantId::new(TENANT),
        )
        .await
        .map_err(text)?,
    );
    let (administration, root) = artifact_admin(registry).await?;
    let administration = Arc::new(administration);
    let dir = directory(p, proxied)?;
    let [refused, before_io, after_io, replayed, ordered] =
        [61u64, 62, 63, 64, 65].map(|i| begin_v1(i, false, None));
    for begin in [&refused, &before_io, &after_io, &replayed, &ordered] {
        dir.begin_thread_run(begin.clone()).await.map_err(text)?;
    }
    let owner = auth();

    // 1. A first save on a closed history: unknown source, and nothing was reserved.
    close_head(direct, &refused.command.thread_id).await?;
    require(
        administration
            .save_run_message_text(&owner, save_request(&refused))
            .await
            == Err(ArtifactAdministrationError::NotVisible),
        "a first save on a closed history was not refused as an unknown source",
    )?;
    let facts = artifact_facts(direct).await?;
    for table in [
        "operations",
        "records",
        "receipts",
        "workspaces",
        "runs",
        "audit",
    ] {
        require(
            rows_of(&facts, table).is_empty(),
            "a refused first save left an operation, reservation, record, receipt or audit",
        )?;
    }
    require(
        root.object_count()? == 0,
        "a refused first save wrote bytes",
    )?;

    // 2. Admitted, then the history closes before IO starts: refused, zero IO, original charge.
    let request = save_request(&before_io);
    let mut held = proxy.arm(b"COMMIT\0", 1)?;
    let save = {
        let (administration, owner, request) =
            (Arc::clone(&administration), owner.clone(), request.clone());
        tokio::spawn(async move { administration.save_run_message_text(&owner, request).await })
    };
    held.arrived()
        .await
        .map_err(|e| format!("admission COMMIT: {e}"))?;
    let admitted = artifact_facts(direct).await?;
    require(
        rows_of(&admitted, "operations").len() == 1
            && rows_of(&admitted, "operations")[0]["state"] == "admitted",
        "premise: the admission must be durable before the close",
    )?;
    close_head(direct, &before_io.command.thread_id).await?;
    held.release()?;
    let outcome = tokio::time::timeout(Duration::from_secs(15), save)
        .await
        .map_err(|_| "the refused start of IO never returned".to_owned())?
        .map_err(text)?;
    require(
        outcome == Err(ArtifactAdministrationError::NotVisible),
        "a start of IO on a closed history was not refused as an unknown source",
    )?;
    let facts = artifact_facts(direct).await?;
    require(
        rows_of(&facts, "operations").len() == 1
            && rows_of(&facts, "operations")[0]["state"] == "admitted"
            && rows_of(&facts, "operations")[0]["charged_bytes"]
                == admitted["operations"][0]["charged_bytes"]
            && rows_of(&facts, "records").is_empty()
            && rows_of(&facts, "receipts").is_empty()
            && rows_of(&facts, "audit").is_empty(),
        "a refused start of IO changed the admitted operation, or published something",
    )?;
    require(
        root.object_count()? == 0,
        "IO began although the history was closed",
    )?;

    // 3. IO has run, then the history closes before the registration: the real bytes and their
    //    charge are kept, and nothing becomes available.
    let request = save_request(&after_io);
    let mut start_io = proxy.arm(b"COMMIT\0", 2)?;
    let save = {
        let (administration, owner, request) =
            (Arc::clone(&administration), owner.clone(), request.clone());
        tokio::spawn(async move { administration.save_run_message_text(&owner, request).await })
    };
    start_io
        .arrived()
        .await
        .map_err(|e| format!("start_io COMMIT: {e}"))?;
    // The IO fence is durable. Arm the next transaction start before the IO is let go: it is the
    // registration transaction's, which only starts after the bytes were written.
    let mut registration = proxy.arm(b"START TRANSACTION\0", 1)?;
    start_io.release()?;
    registration
        .arrived()
        .await
        .map_err(|e| format!("registration START TRANSACTION: {e}"))?;
    let io_done = artifact_facts(direct).await?;
    require(
        rows_of(&io_done, "operations").len() == 2
            && rows_of(&io_done, "operations")
                .iter()
                .any(|operation| operation["state"] == "io_started")
            && root.object_count()? == 1
            && rows_of(&io_done, "records").is_empty(),
        "premise: the bytes must be written and unregistered before the close",
    )?;
    close_head(direct, &after_io.command.thread_id).await?;
    registration.release()?;
    let outcome = tokio::time::timeout(Duration::from_secs(15), save)
        .await
        .map_err(|_| "the refused registration never returned".to_owned())?
        .map_err(text)?;
    require(
        outcome == Err(ArtifactAdministrationError::Unavailable),
        "a registration on a closed history did not take the source-changed path",
    )?;
    let facts = artifact_facts(direct).await?;
    let operation = rows_of(&facts, "operations")
        .iter()
        .find(|operation| operation["source_thread_id"] == after_io.command.thread_id.as_str())
        .ok_or("the post-IO operation vanished")?;
    let artifact_id = operation["artifact_id"]
        .as_str()
        .ok_or("operation without artifact")?
        .to_owned();
    let bytes = root.object_bytes(&artifact_id)?;
    require(
        operation["state"] == "unresolved"
            && operation["charged_bytes"] == after_io.command.message.len() as u64
            && operation["actual_absent"] == false
            && operation["actual_byte_length"] == bytes.len() as u64
            && operation["actual_sha256"] == format!("{:x}", Sha256::digest(&bytes))
            && operation["actual_location"] == "object"
            && operation["observation_phase"] == "installed"
            && bytes == after_io.command.message.as_bytes(),
        "the real byte observation or its charge was not kept",
    )?;
    require(
        rows_of(&facts, "records").is_empty()
            && rows_of(&facts, "receipts").is_empty()
            && rows_of(&facts, "audit").is_empty(),
        "a closed history published a record, receipt or audit after IO",
    )?;

    // 4. A save committed while open still observes its original receipt after the close; any
    //    other request on that history is refused.
    let request = save_request(&replayed);
    let receipt = administration
        .save_run_message_text(&owner, request.clone())
        .await
        .map_err(text)?;
    close_head(direct, &replayed.command.thread_id).await?;
    let stable = artifact_facts(direct).await?;
    require(
        administration
            .save_run_message_text(&owner, request)
            .await
            .as_ref()
            == Ok(&receipt),
        "the exact replay of a committed save did not observe its original receipt",
    )?;
    require(
        administration
            .save_run_message_text(&owner, save_request(&replayed))
            .await
            == Err(ArtifactAdministrationError::NotVisible),
        "a different save on the closed history was not refused",
    )?;
    require(
        artifact_facts(direct).await? == stable,
        "a replay or refused save changed operations, records, receipts, charges or audit",
    )?;

    // 5. In each of its three transactions the save observes the schema before its first row
    //    lock. The proxy holds the acknowledgement of the transaction start, so the ledger is
    //    locked only once the save has passed its registration verification and stands at the
    //    start of that very transaction; the wait that follows is the observation of the save's
    //    own backend, which then holds no row-level lock while the actor row is still free. The
    //    start of IO and the registration also take the head only after their quota rows and
    //    operation row, the same order as the admission.
    let request = save_request(&ordered);
    let users_probe = "SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT";
    let order = LockOrder::new(direct, ENTRY_SAVE, &[(users_probe, "alice")]).await?;
    let mut gate = Some(proxy.arm(b"START TRANSACTION\0", 1)?);
    let save = {
        let (administration, owner) = (Arc::clone(&administration), owner.clone());
        tokio::spawn(async move { administration.save_run_message_text(&owner, request).await })
    };
    for (index, transaction) in ["admission", "start of IO", "registration"]
        .into_iter()
        .enumerate()
    {
        let mut start = gate.take().ok_or("the transaction start was not held")?;
        start
            .arrived()
            .await
            .map_err(|e| format!("{transaction} START TRANSACTION: {e}"))?;
        // From the start of IO on, the operation row exists. A controller holds it, so that the
        // save's later wait for it shows which locks it already took: the quota rows, not the head.
        let operation = if index > 0 {
            Some(hold_operation(direct, &ordered.command.thread_id).await?)
        } else {
            None
        };
        let holder = order.hold_ledger().await?;
        start.release()?;
        let evidence = order.evidence(holder).await;
        // The next transaction start is caught before the ledger is let go.
        if index < 2 {
            gate = Some(proxy.arm(b"START TRANSACTION\0", 1)?);
        }
        order.release_ledger().await?;
        evidence.map_err(|e| format!("{transaction}: {e}"))?;
        if let Some((operation_holder, blocker)) = operation {
            let ordered_locks = order
                .quota_before_head(blocker, &ordered.command.thread_id)
                .await;
            release(&operation_holder).await?;
            ordered_locks.map_err(|e| format!("{transaction}: {e}"))?;
        }
    }
    let saved = tokio::time::timeout(Duration::from_secs(30), save)
        .await
        .map_err(|_| "the held-back save never completed".to_owned())?
        .map_err(text)?;
    require(
        saved.is_ok(),
        "the held-back save was refused on an open history",
    )
}

// ---------------------------------------------------------------------------------------------
// c07 -- a user's "remember this" from a message of a closed history
// ---------------------------------------------------------------------------------------------

fn memory_request(source: Option<MemorySource>, content: &str) -> RememberMemoryRequest {
    RememberMemoryRequest {
        deployment: DeploymentId::new(DEP),
        auth_generation: AuthGeneration::new(7),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new("alice"),
        input: RememberMemory {
            memory_kind: MemoryKind::Preference,
            scope: MemoryScope::User,
            content: content.to_owned(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            source,
            expires_at: None,
        },
    }
}

fn source_message(begin: &BeginThreadRunRequest) -> MemorySource {
    MemorySource {
        thread_id: begin.command.thread_id.clone(),
        message_id: format!("{}:input", begin.command.run_id.as_str()),
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_manual_memory_with_closed_source_refuses() {
    owned("closure_manual_memory", |p, config| async move {
        let dir = directory(&p, &config)?;
        let closing = begin_v1(81, false, None);
        let open = begin_v1(82, false, None);
        for begin in [&closing, &open] {
            dir.begin_thread_run(begin.clone()).await.map_err(text)?;
        }
        let store = PostgresMemoryAdministration::new(p.clone());
        let memories = "SELECT count(*) FROM public.memories";
        let events = "SELECT count(*) FROM public.memory_events";

        // While open, a memory made from the message keeps that message as its source.
        let created = store
            .remember(memory_request(
                Some(source_message(&closing)),
                "made while open",
            ))
            .await
            .map_err(text)?;
        require(
            created.source == Some(source_message(&closing)),
            "premise: the memory must keep its source message",
        )?;

        close_head(&p, &closing.command.thread_id).await?;
        let image = (count(&p, memories).await?, count(&p, events).await?);
        require(
            store
                .remember(memory_request(
                    Some(source_message(&closing)),
                    "must not exist",
                ))
                .await
                == Err(MemoryAdministrationError::NotVisible),
            "a memory from a closed history's message was not refused as an unknown source",
        )?;
        require(
            (count(&p, memories).await?, count(&p, events).await?) == image,
            "a refused memory left a row or an event",
        )?;

        // Other memories are unchanged: one with no source, one from another open history.
        store
            .remember(memory_request(None, "no source at all"))
            .await
            .map_err(text)?;
        store
            .remember(memory_request(
                Some(source_message(&open)),
                "another open history",
            ))
            .await
            .map_err(text)?;
        require(
            count(&p, memories).await? == image.0 + 2,
            "the unaffected memories were not stored",
        )?;

        // A memory with no source reads no Thread history, so it does not wait on the schema
        // observation; one with a source observes the schema before its first row lock.
        let holder = p.get().await.map_err(text)?;
        hold(
            &holder,
            "LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE",
        )
        .await?;
        let free = tokio::time::timeout(
            Duration::from_secs(10),
            store.remember(memory_request(None, "no source while the ledger is locked")),
        )
        .await;
        release(&holder).await?;
        require(
            matches!(free, Ok(Ok(_))),
            "a memory with no source waited on the schema observation",
        )?;
        drop(holder);
        let entry = entry_pool(&config, ENTRY_MEMORY, 2).await?;
        let entry_store = PostgresMemoryAdministration::new(entry.clone());
        let ordered = observation_precedes_locks(
            &p,
            ENTRY_MEMORY,
            &[(
                "SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT",
                "alice",
            )],
            {
                let source = source_message(&open);
                async move {
                    entry_store
                        .remember(memory_request(Some(source), "ordered"))
                        .await
                }
            },
        )
        .await;
        let closed = close_pool(entry).await;
        let ordered = ordered?;
        closed?;
        require(ordered.is_ok(), "the held-back memory never completed")
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// c08 -- lock conflicts and failures are never read as closed
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires explicitly owned loopback SCRAM PostgreSQL17.11"]
async fn consumer_closure_lock_conflicts_and_failures_are_not_closed() {
    owned("closure_not_closed", |p, config| async move {
        let tls = Tls::new().await;
        let v2 = V2::new(&p, &config).await?;
        let result = not_closed_case(&p, &config, &tls, &v2).await;
        v2.finish().await;
        tls.stop().await;
        result
    })
    .await;
    // The query failure of the reader, and a Thread that predates every head.
    owned("closure_reader_failure", |p, config| async move {
        let thread = thread_for(77);
        let outcome = load_with_close_after_body_read(&p, &config, 77, true).await?;
        require(
            outcome.as_ref().err() == Some(&AgentContextError::Unavailable),
            "a failed closed-head check read as open or as closed",
        )?;
        let c = p.get().await.map_err(text)?;
        require(
            head_phase(&c, &thread).await?.as_deref() == Some("open"),
            "premise: the head stayed open while its check failed",
        )
    })
    .await;
    owned_with("closure_missing_head", false, |p, _| async move {
        let mut c = p.get().await.map_err(text)?;
        baseline::apply(&c).await.map_err(text)?;
        require(
            native::apply_through(&mut c, 49).await.map_err(text)? == native::ApplyOutcome::Applied,
            "explicit historical 49 not applied",
        )?;
        let thread = thread_for(91);
        c.batch_execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES('alice','alice@example.test',7);
             INSERT INTO public.user_roles(user_id,role) VALUES('alice','user');
             INSERT INTO public.agents(id,name,type,configuration) VALUES
               ('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
             INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
               VALUES('bot','alice','Owned bot','','owned','public');",
        )
        .await
        .map_err(text)?;
        c.execute(
            "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status,next_message_seq,next_event_seq,created_at,updated_at,deleted_at) VALUES($1,$2,$3,'alice','direct_bot','bot','Historical thread','active',1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z',NULL)",
            &[&thread.as_str(), &TENANT, &DEP],
        )
        .await
        .map_err(text)?;
        c.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'alice')", &[&thread.as_str()])
            .await
            .map_err(text)?;
        c.execute(
            "INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at) VALUES('closure-historical-run',$1,'bot','alice',false,'running',1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",
            &[&thread.as_str()],
        )
        .await
        .map_err(text)?;
        c.execute(
            "INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) VALUES('closure-historical-message',$1,0,'user','{\"text\":\"Historical prompt\"}','Historical prompt','closure-historical-run','alice','2026-09-01T00:00:00Z')",
            &[&thread.as_str()],
        )
        .await
        .map_err(text)?;
        require(
            native::apply(&mut c).await.map_err(text)? == native::ApplyOutcome::Applied,
            "the upgrade to the current native prefix was not applied",
        )?;
        require(
            head_phase(&c, &thread).await?.is_none(),
            "premise: the upgrade must not have registered a head for the historical Thread",
        )?;
        drop(c);
        let lease = lease_of(&RunId::new("closure-historical-run"), &thread);
        let request = context_on(&p).load(&lease).await.map_err(|e| format!("a Thread with no head did not load: {e:?}"))?;
        require(
            request.messages.iter().any(|m| m.content == "Historical prompt"),
            "the historical Thread did not load its real history",
        )
    })
    .await;
}

async fn not_closed_case(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
    tls: &Tls,
    v2: &V2,
) -> TestResult {
    let dir = PostgresThreadDirectory::with_runtime(
        p.clone(),
        config.clone(),
        PROCESS.to_owned(),
        time::Duration::minutes(10),
    )
    .map_err(text)?;
    let lease_for = time::Duration::minutes(10);
    let model = v2
        .model(CustomModelProtocol::OpenaiChatCompletions, &tls.endpoint())
        .await?;
    let selection = RunModelSelection {
        connection_id: model.id.clone(),
        expected_revision: model.revision,
    };
    let (tool, memory, manual, legacy, current, save) = (
        begin_v1(71, false, None),
        begin_v1(72, false, None),
        begin_v1(73, false, None),
        begin_v1(74, false, Some(selection)),
        v2.request(75, &model),
        begin_v1(76, false, None),
    );
    for begin in [&tool, &memory, &manual, &legacy, &save] {
        dir.begin_thread_run(begin.clone()).await.map_err(text)?;
    }
    v2.directory
        .begin_thread_run_v2(current.clone())
        .await
        .map_err(text)?;
    let runtime = PostgresRunRuntime::new(
        p.clone(),
        PROCESS.to_owned(),
        lease_for,
        DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .map_err(text)?;
    // The remember effect needs its own Run leased; the others do not.
    while let Some(claim) = runtime.claim_dispatch().await.map_err(text)? {
        runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
    }

    // Everything these consumers need is made while the histories are open.
    let journal = PostgresToolJournal::new(p.clone(), AUDIT_KEY.to_vec()).map_err(text)?;
    let attempts = ToolAttemptRepo::new(p.clone());
    let decided = tool_draft(&tool.command.run_id, "closure-held-1", 0);
    journal.record_decision(&decided).await.map_err(text)?;
    let effect = capture_remember(p, &memory.command.run_id, 0, "held remember content").await?;
    let store = PostgresMemoryAdministration::new(p.clone())
        .with_effect_audit_key(AUDIT_KEY.to_vec())
        .map_err(text)?;
    let context = v2.context(p);
    let budget = SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(20)).unwrap();
    let provider = PostgresCustomModelProvider::new(
        p.clone(),
        vault(0x71),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        tls.dialer(),
        budget,
        Some(Duration::from_secs(2)),
    )
    .map_err(text)?
    .with_model_dataset_binding(v2.binding.clone())
    .map_err(text)?;
    let legacy_request = context
        .load(&lease_of(&legacy.command.run_id, &legacy.command.thread_id))
        .await
        .map_err(text)?;
    let current_request = context
        .load(&lease_of(
            &current.command.run_id,
            &current.command.thread_id,
        ))
        .await
        .map_err(text)?;
    let registry = v2.registry.clone().ok_or("the dataset registry is gone")?;
    let (administration, _root) = artifact_admin(registry).await?;
    let owner = auth();
    let save_asked = save_request(&save);

    // A real writer holds every one of these heads: a consumer taking the share is refused with
    // 55P03, while the reader-style legacy start is not held back.
    let threads = [
        tool.command.thread_id.as_str().to_owned(),
        memory.command.thread_id.as_str().to_owned(),
        manual.command.thread_id.as_str().to_owned(),
        legacy.command.thread_id.as_str().to_owned(),
        current.command.thread_id.clone().as_str().to_owned(),
        save.command.thread_id.as_str().to_owned(),
    ];
    let holder = p.get().await.map_err(text)?;
    holder
        .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(text)?;
    let held = holder
        .query(
            "SELECT thread_id FROM openbot_internal.thread_history_heads WHERE thread_id=ANY($1) FOR UPDATE",
            &[&threads.as_slice()],
        )
        .await
        .map_err(text)?;
    require(
        held.len() == threads.len(),
        "premise: every head must be held",
    )?;
    let before = (
        journal_image(p).await?,
        remember_image(p).await?,
        artifact_facts(p).await?,
    );

    let unavailable_tool = Err(ToolPortError::Unavailable {
        dependency: "database",
    });
    require(
        journal
            .record_decision(&tool_draft(&tool.command.run_id, "closure-held-2", 1))
            .await
            .map(|_| ())
            == unavailable_tool,
        "a head lock conflict on a tool decision read as closed or as success",
    )?;
    require(
        journal
            .attach_capability(
                &decided.call_id,
                &CapabilityId::new(uuid::Uuid::now_v7().to_string()),
            )
            .await
            == unavailable_tool,
        "a head lock conflict on a capability read as closed or as success",
    )?;
    let low_level = attempts
        .attach_capability(
            "closure-held-1",
            0,
            &uuid::Uuid::now_v7().to_string(),
            time::OffsetDateTime::now_utc(),
        )
        .await;
    require(
        low_level.as_ref().err().and_then(InfraError::sqlstate) == Some("55P03"),
        "the head conflict was not the real lock-not-available refusal",
    )?;
    require(
        store.remember_from_tool(effect.clone()).await
            == Err(MemoryAdministrationError::Unavailable),
        "a head lock conflict on a remember effect read as closed or as success",
    )?;
    require(
        PostgresMemoryAdministration::new(p.clone())
            .remember(memory_request(Some(source_message(&manual)), "held"))
            .await
            == Err(MemoryAdministrationError::Unavailable),
        "a head lock conflict on a memory from a message read as closed or as success",
    )?;
    // Both custom starts only read the head: a writer's lock neither blocks it nor closes it.
    tls.gate.add_permits(2);
    require(
        provider.start(current_request.clone()).await.is_ok(),
        "a head held by a writer blocked or closed the current-dataset start",
    )?;
    require(
        provider.start(legacy_request.clone()).await.is_ok(),
        "a head held by a writer blocked or closed the legacy start",
    )?;
    require(
        administration
            .save_run_message_text(&owner, save_asked.clone())
            .await
            == Err(ArtifactAdministrationError::Unavailable),
        "a head lock conflict on an explicit save read as closed or as success",
    )?;
    require(
        (
            journal_image(p).await?,
            remember_image(p).await?,
            artifact_facts(p).await?,
        ) == before,
        "a refused-for-lock consumer changed journal, memory or artifact state",
    )?;
    require(
        tls.requests() == 2,
        "a consumer other than the two custom starts reached the model endpoint behind a held head",
    )?;

    // Once the real writer is gone, the very same calls are admitted.
    release(&holder).await?;
    drop(holder);
    journal
        .record_decision(&tool_draft(&tool.command.run_id, "closure-held-2", 1))
        .await
        .map_err(text)?;
    journal
        .attach_capability(
            &decided.call_id,
            &CapabilityId::new(uuid::Uuid::now_v7().to_string()),
        )
        .await
        .map_err(text)?;
    store.remember_from_tool(effect).await.map_err(text)?;
    PostgresMemoryAdministration::new(p.clone())
        .remember(memory_request(Some(source_message(&manual)), "released"))
        .await
        .map_err(text)?;
    administration
        .save_run_message_text(&owner, save_asked)
        .await
        .map_err(text)?;
    let c = p.get().await.map_err(text)?;
    for thread in &threads {
        require(
            head_phase(&c, &ThreadId::new(thread.as_str()))
                .await?
                .as_deref()
                == Some("open"),
            "a lock conflict closed or removed a head",
        )?;
    }
    drop(c);
    legacy_start_query_failure(p, config, &dir, tls, v2, &model).await
}

/// A custom start's closed-head read is a real query. When its backend is terminated while that
/// read waits behind an owned table lock, the start fails as `Unavailable`: neither closed nor
/// admitted, and nothing reaches the endpoint. Shown on the legacy route, whose first wait behind
/// such a lock is that read; the current-dataset route calls the very same function after its
/// authority load, and its own schema verification waits behind the lock first.
async fn legacy_start_query_failure(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
    dir: &PostgresThreadDirectory,
    tls: &Tls,
    v2: &V2,
    model: &ModelConnection,
) -> TestResult {
    let begin = begin_v1(
        78,
        false,
        Some(RunModelSelection {
            connection_id: model.id.clone(),
            expected_revision: model.revision,
        }),
    );
    dir.begin_thread_run(begin.clone()).await.map_err(text)?;
    let request = v2
        .context(p)
        .load(&lease_of(&begin.command.run_id, &begin.command.thread_id))
        .await
        .map_err(text)?;
    let (starter_pool, starter) = dedicated(config, "closure_legacy_starter").await?;
    let budget = SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(20)).unwrap();
    let provider = PostgresCustomModelProvider::new(
        starter_pool.clone(),
        vault(0x71),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        tls.dialer(),
        budget,
        Some(Duration::from_secs(2)),
    )
    .map_err(text)?;
    let sends = tls.requests();
    let observer = p.get().await.map_err(text)?;
    let heads = p.get().await.map_err(text)?;
    let held = hold(
        &heads,
        "LOCK TABLE openbot_internal.thread_history_heads IN ACCESS EXCLUSIVE MODE",
    )
    .await?;
    let task = tokio::spawn(async move { provider.start(request).await });
    wait_blocked(&observer, starter, held).await?;
    let (_, query) = activity(&observer, starter).await?;
    require(
        query.contains("SELECT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads"),
        "the wait was not the legacy start's closed-head read",
    )?;
    observer
        .query_one("SELECT pg_terminate_backend($1)", &[&starter])
        .await
        .map_err(text)?;
    release(&heads).await?;
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .map_err(|_| "the failed legacy start never returned".to_owned())?
        .map_err(text)?;
    require(
        matches!(outcome, Err(ProviderPortError::Unavailable)),
        "a failed closed-head read of the legacy start read as closed or as admitted",
    )?;
    require(
        tls.requests() == sends,
        "a legacy start with a failed closed-head read reached the endpoint",
    )?;
    let c = p.get().await.map_err(text)?;
    require(
        head_phase(&c, &begin.command.thread_id).await?.as_deref() == Some("open"),
        "a failed closed-head read closed or removed the head",
    )?;
    drop((observer, heads, c));
    close_pool(starter_pool).await?;
    v2_start_early_dataset_query_failure(p, config, tls, v2).await
}

/// Independent current-dataset start error classification before its closed-head read or send.
/// Its original AuthorizedStart user/target/model locks precede this dataset schema observation.
/// The owned heads table lock stops a registered schema capture, without granting an H row lock.
/// The original legacy case above retains its distinct exact closed-predicate witness.
async fn v2_start_early_dataset_query_failure(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
    tls: &Tls,
    v2: &V2,
) -> TestResult {
    let model = v2
        .model(CustomModelProtocol::OpenaiResponses, &tls.endpoint())
        .await?;
    let begin = v2.request(79, &model);
    v2.directory
        .begin_thread_run_v2(begin.clone())
        .await
        .map_err(text)?;
    let request = v2
        .context(p)
        .load(&lease_of(&begin.command.run_id, &begin.command.thread_id))
        .await
        .map_err(text)?;
    let (starter_pool, starter) = dedicated(config, "closure_v2_early_dataset_starter").await?;
    // A V2 binding cannot be borrowed from a same-DSN different Pool. Enrol this pool's actual
    // registry via the existing V2 assembly; it observes the same real persisted dataset tuple.
    let original = V2::new(&starter_pool, config).await?;
    let provider = PostgresCustomModelProvider::new(
        starter_pool.clone(),
        vault(0x71),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        tls.dialer(),
        SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(20)).map_err(text)?,
        Some(Duration::from_secs(2)),
    )
    .map_err(text)?
    .with_model_dataset_binding(original.binding.clone())
    .map_err(text)?;
    let sends = tls.requests();
    let accepts = tls.accepted.load(Ordering::SeqCst);
    let resolves = tls.resolved.load(Ordering::SeqCst);
    let observer = p.get().await.map_err(text)?;
    let heads = p.get().await.map_err(text)?;
    let blocker = hold(
        &heads,
        "LOCK TABLE openbot_internal.thread_history_heads IN ACCESS EXCLUSIVE MODE",
    )
    .await?;
    let task = tokio::spawn(async move { provider.start(request).await });
    wait_blocked(&observer, starter, blocker).await?;
    let (_, query) = activity(&observer, starter).await?;
    // These are the original CAPTURE_SQL prefixes in the already registered native V2 check.
    let original_schema_prefixes = [
        "WITH\nwanted_relations(schema_name, relation_name) AS (\n VALUES ('public'::text,'model_connections'::text),",
        "WITH\nwanted_relations(schema_name, relation_name) AS (\n VALUES ('openbot_internal'::text,'run_model_selection_v2_snapshots'::text)",
        "WITH\nwanted_relations(schema_name, relation_name) AS (\n VALUES ('openbot_internal'::text,'gateway_authorization_attempts'::text)",
        "WITH\nwanted_relations(schema_name, relation_name) AS (\n VALUES ('openbot_internal'::text,'thread_origins'::text)",
        "WITH\nwanted_relations(schema_name, relation_name) AS (\n VALUES ('openbot_internal'::text,'thread_history_heads'::text),",
    ];
    eprintln!(
        "THREAD_HISTORY_V2_DATASET_WITNESS original_backend_pid={starter} blocker_pid={blocker} query={query:?}"
    );
    require(
        query.contains("pg_catalog")
            && !query.contains("SELECT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads")
            && original_schema_prefixes
                .iter()
                .any(|prefix| query.starts_with(*prefix))
            && {
                let rows = observer
                    .query(
                        "SELECT l.locktype,coalesce(n.nspname||'.'||c.relname,''),l.mode \
                         FROM pg_catalog.pg_locks l \
                         LEFT JOIN pg_catalog.pg_class c ON c.oid=l.relation \
                         LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace \
                         WHERE l.pid=$1 AND l.granted \
                           AND (l.locktype IN ('tuple','advisory') \
                             OR (l.locktype='relation' AND l.mode IN ('RowShareLock','RowExclusiveLock'))) \
                         ORDER BY l.locktype COLLATE \"C\",coalesce(n.nspname||'.'||c.relname,'') COLLATE \"C\",l.mode COLLATE \"C\"",
                        &[&starter],
                    )
                    .await
                    .map_err(text)?;
                let observed: Vec<(String, String, String)> = rows
                    .into_iter()
                    .map(|row| (row.get(0), row.get(1), row.get(2)))
                    .collect();
                let expected: Vec<(String, String, String)> = [
                    "public.agent_profiles",
                    "public.agents",
                    "public.custom_model_catalogs",
                    "public.model_connection_secrets",
                    "public.model_connections",
                    "public.runs",
                    "public.thread_leases",
                    "public.thread_memberships",
                    "public.threads",
                    "public.user_roles",
                    "public.users",
                ]
                .into_iter()
                .map(|relation| {
                    (
                        "relation".to_owned(),
                        relation.to_owned(),
                        "RowShareLock".to_owned(),
                    )
                })
                .collect();
                eprintln!(
                    "THREAD_HISTORY_V2_DATASET_WITNESS original_backend_pid={starter} granted_row_level_classes={observed:?}"
                );
                observed == expected
            },
        "V2 witness was not its original dataset/schema read with exactly the original authority locks",
    )?;
    let terminated: bool = observer
        .query_one("SELECT pg_terminate_backend($1)", &[&starter])
        .await
        .map_err(text)?
        .get(0);
    require(terminated, "owned early V2 backend was not terminated")?;
    release(&heads).await?;
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .map_err(|_| "the failed early V2 schema read never returned".to_owned())?
        .map_err(text)?;
    require(
        matches!(outcome, Err(ProviderPortError::Unavailable)),
        "V2 early dataset query error read as closed, admitted or invalid request",
    )?;
    require(
        tls.resolved.load(Ordering::SeqCst) == resolves
            && tls.requests() == sends
            && tls.accepted.load(Ordering::SeqCst) == accepts,
        "V2 early query failure reached owned DNS/TLS/HTTP endpoint",
    )?;
    let c = p.get().await.map_err(text)?;
    require(
        head_phase(&c, &begin.command.thread_id).await?.as_deref() == Some("open"),
        "V2 early schema failure closed or removed its original head",
    )?;
    drop((observer, heads, c));
    original.finish().await;
    close_pool(starter_pool).await
}
