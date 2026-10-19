//! Positive Memory effect while the original run is still running, then an owned PG restart.
//! One finite composition uses the production Builtin control, producer, journal and Runtime.
//! The ordinary outcome pauses before checkout; no receipt/error/terminal is synthesized.
mod harness;
#[path = "run_positive_recovery/support.rs"]
mod support;

use async_trait::async_trait;
use openbot_application::{
    AuthorizedToolCall, BeginThreadRunRequest, CommittedMemoryEffect, MemoryAdministrationError,
    RememberToolMemory, RememberToolMemoryRequest, ResolvedToolScope, RunExecutionLease,
    RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel, RunTerminal, RunWriteReceipt,
    ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError, ToolApprovalRequest,
    ToolControlPlane, ToolDecisionDraft, ToolExecutionReport, ToolJournal, ToolOutcomeDraft,
    ToolPolicyEvaluation, ToolPortError, ToolRefusalDraft, invoke_tool,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, ThreadForegroundRunState, ThreadRunAnchor, ThreadRunStarted},
    error::AppError,
    ids::{
        ActorId, BotId, CapabilityId, DeploymentId, RunId, TenantId, ToolCallId,
        thread::ThreadIdentity,
    },
    reconciliation::{
        RunEffectReceiptFact, RunReconciliationAttemptStatus, RunReconciliationStatus,
    },
    tool::{ToolInvocation, ToolResult},
};
use openbot_domain::{
    policy::{ActionPolicy, PolicyMode, context::PolicyContext},
    tool::{
        args::ToolArguments,
        commit::CommitState,
        metadata::{ToolMetadata, ToolName},
        pipeline::{ApprovalOutcome, DurableDecisionReceipt},
    },
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    agent_tools::PostgresBuiltInToolControlPlane,
    db::{fresh, pool, pool::DatabaseConfig},
    memory_admin::PostgresMemoryAdministration,
    policy::PolicyStore,
    repo::{run::RunRepo, tools::PostgresToolJournal},
    run_runtime::PostgresRunRuntime,
    thread_directory::PostgresThreadDirectory,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{Observer, OwnedFrameProxy, WireEvidence};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinHandle,
};

const BOUND: Duration = Duration::from_secs(10);
const RESTART_BOUND: Duration = Duration::from_secs(45);
const EXPIRY_BOUND: Duration = Duration::from_secs(30);
const LEASE_DURATION: time::Duration = time::Duration::seconds(12);
const CLAIM_DURATION: time::Duration = time::Duration::seconds(1);
const KEY: &[u8] = b"owned-positive-running-recovery-audit-key";
const ACTOR: &str = "positive-recovery-owner";
const BOT: &str = "positive-recovery-bot";
const OWNER: &str = "positive-recovery-original-runtime";
const RECOVERY_OWNER: &str = "positive-recovery-new-runtime";
const CONTENT: &str = "owned positive Memory survives a still-running PostgreSQL restart";
const TABLES: [&str; 16] = [
    "runs",
    "threads",
    "thread_leases",
    "thread_run_occupancy",
    "messages",
    "run_events",
    "outbox",
    "tool_calls",
    "tool_attempts",
    "tool_approvals",
    "memories",
    "memory_events",
    "user_memory_controls",
    "remember_effect_receipts",
    "audit_events",
    "audit_checkpoints",
];

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn rows<'a>(value: &'a Value, table: &str) -> &'a [Value] {
    value[table].as_array().expect("owned16-table facts")
}
fn one<'a>(value: &'a Value, table: &str) -> Result<&'a Value, String> {
    let r = rows(value, table);
    require(
        r.len() == 1,
        &format!("expected exactly one original {table}"),
    )?;
    Ok(&r[0])
}
fn timestamp(value: &Value) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(
        value.as_str().ok_or("missing actual database timestamp")?,
        &Rfc3339,
    )
    .map_err(|e| e.to_string())
}
fn stable_columns(
    before: &Value,
    after: &Value,
    table: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut b = one(before, table)?
        .as_object()
        .ok_or("original row not an object")?
        .clone();
    let mut a = one(after, table)?
        .as_object()
        .ok_or("recovered row not an object")?
        .clone();
    for key in ["_xmin", "_ctid"]
        .into_iter()
        .chain(allowed.iter().copied())
    {
        b.remove(key);
        a.remove(key);
    }
    require(b == a, &format!("recovery changed stable {table} columns"))
}

/// A max1 real pool is kept open; SET/SHOW config is directed test default, not actual TX isolation.
async fn pool_observation(pool: &Pool, label: &str) -> Result<Value, String> {
    let c = tokio::time::timeout(BOUND, pool.get())
        .await
        .map_err(|_| "live pool checkout timed out")?
        .map_err(|e| e.to_string())?;
    c.batch_execute("SET default_transaction_isolation='repeatable read'")
        .await
        .map_err(|e| e.to_string())?;
    let default: String = c
        .query_one("SHOW default_transaction_isolation", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    require(default == "repeatable read", "test pool defaultRR missing")?;
    let v: Value = c.query_one(
        "SELECT jsonb_build_object('backendPid',pg_backend_pid(),'database',current_database(),\
         'postmasterStartedAt',pg_postmaster_start_time(),'defaultIsolation',current_setting('default_transaction_isolation'))", &[])
        .await.map_err(|e| e.to_string())?.get(0);
    println!("POSITIVE_POOL {}", json!({"label":label,"observation":v}));
    Ok(v)
}

struct PausedJournal {
    inner: PostgresToolJournal,
    wire: Arc<WireEvidence>,
    entered: Notify,
    gate: Semaphore,
    decisions: AtomicUsize,
    receipts: AtomicUsize,
    attaches: AtomicUsize,
    outcomes: AtomicUsize,
    refusals: AtomicUsize,
    outcome: Mutex<Option<ToolOutcomeDraft>>,
    actual_result: Mutex<Option<Result<(), ToolPortError>>>,
}
impl PausedJournal {
    fn counts(&self) -> Value {
        json!({"decision_entries":self.decisions.load(Ordering::SeqCst),
            "returned_durable_receipts":self.receipts.load(Ordering::SeqCst),
            "attach_entries":self.attaches.load(Ordering::SeqCst),
            "outcome_entries":self.outcomes.load(Ordering::SeqCst),
            "refusal_entries":self.refusals.load(Ordering::SeqCst)})
    }
    fn draft(&self) -> Result<ToolOutcomeDraft, String> {
        self.outcome
            .lock()
            .expect("owned original outcome")
            .clone()
            .ok_or("real ordinary outcome not reached".into())
    }
}
#[async_trait]
impl ToolJournal for PausedJournal {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.record_decision(draft).await;
        if result.is_ok() {
            self.receipts.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.attaches.fetch_add(1, Ordering::SeqCst);
        self.inner.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        self.outcomes.fetch_add(1, Ordering::SeqCst);
        *self.outcome.lock().expect("owned original outcome") = Some(draft.clone());
        // The production adapter has not checked out a client or acquired any DB lock yet.
        self.entered.notify_one();
        self.gate
            .acquire()
            .await
            .expect("owned paused ordinary outcome")
            .forget();
        self.wire
            .begin_phase("late_original_ordinary_after_actual_recovery", false);
        let result = self.inner.record_outcome(draft).await;
        *self
            .actual_result
            .lock()
            .expect("actual ordinary outcome result") = Some(result);
        result
    }
}

struct ForwardMemory {
    inner: PostgresMemoryAdministration,
    entries: AtomicUsize,
    request: Mutex<Option<RememberToolMemoryRequest>>,
    effect: Mutex<Option<CommittedMemoryEffect>>,
}
#[async_trait]
impl RememberToolMemory for ForwardMemory {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<CommittedMemoryEffect, MemoryAdministrationError> {
        self.entries.fetch_add(1, Ordering::SeqCst);
        *self.request.lock().expect("real private request") = Some(request.clone());
        let result = self.inner.remember_from_tool(request).await;
        if let Ok(effect) = &result {
            *self.effect.lock().expect("real positive effect") = Some(effect.clone());
        }
        result
    }
}
struct ForwardBuiltIn {
    inner: PostgresBuiltInToolControlPlane<ForwardMemory>,
    executions: AtomicUsize,
}
#[async_trait]
impl ToolControlPlane for ForwardBuiltIn {
    async fn metadata(&self, n: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        self.inner.metadata(n).await
    }
    async fn resolve_scope(
        &self,
        a: &AuthContext,
        i: &ToolInvocation,
        args: &ToolArguments,
        m: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        self.inner.resolve_scope(a, i, args, m).await
    }
    async fn evaluate_policy(
        &self,
        c: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        self.inner.evaluate_policy(c).await
    }
    async fn approval(&self, r: &ToolApprovalRequest) -> Result<ApprovalOutcome, ToolPortError> {
        self.inner.approval(r).await
    }
    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        self.executions.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(call).await
    }
}

struct Fixture {
    config: DatabaseConfig,
    pool: Pool,
    journal_pool: Pool,
    recovery_pool: Option<Pool>,
    observer: Arc<Observer>,
    proxy: Option<OwnedFrameProxy>,
    journal: Arc<PausedJournal>,
    runtime: PostgresRunRuntime,
    begin: BeginThreadRunRequest,
    original_begin: ThreadRunStarted,
    lease: RunExecutionLease,
    auth: AuthContext,
    invocation: ToolInvocation,
    task: Option<JoinHandle<Result<ToolResult, AppError>>>,
    initial_pool: Value,
    initial_journal: Value,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        require(
            CLAIM_DURATION > time::Duration::ZERO && CLAIM_DURATION < LEASE_DURATION,
            "owned claim_duration must be positive and below lease_duration",
        )?;
        let pool = pool::connect(&config.clone().with_max_pool_size(1))
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut c = pool.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('positive-recovery-owner','owner@positive-recovery.example.test',0);INSERT INTO public.user_roles(user_id,role) VALUES('positive-recovery-owner','user');INSERT INTO public.agents(id,name,type,configuration) VALUES('positive-recovery-bot','Positive running recovery fixture','built_in','{}');INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('positive-recovery-bot',NULL,'Positive running recovery fixture','owned synthetic','positive-recovery','public')").await.map_err(|e|e.to_string())?;
        }
        let initial_pool = pool_observation(&pool, "original_runtime_before_begin").await?;
        let deployment = DeploymentId::new("positive-recovery-deployment");
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: TenantId::new("positive-recovery-tenant"),
            actor: ActorId::new(ACTOR),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([0x79; 16]),
                run_id: RunId::new("positive-recovery-original-run"),
                bot_id: BotId::new(BOT),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned original positive-running prompt".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            OWNER.into(),
            LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let original_begin = directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let runtime =
            PostgresRunRuntime::new(pool.clone(), OWNER.into(), LEASE_DURATION, CLAIM_DURATION)
                .map_err(|e| e.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("actual dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        let observer = Observer::new(&config).await?;
        let proxy = OwnedFrameProxy::start(&config).await?;
        let mut journal_config = config
            .clone()
            .with_max_pool_size(1)
            .with_application_name("owned-positive-recovery-original-journal");
        journal_config.host = "127.0.0.1".into();
        journal_config.port = proxy.port;
        let journal_pool = pool::connect(&journal_config)
            .await
            .map_err(|e| e.to_string())?;
        let initial_journal =
            pool_observation(&journal_pool, "original_journal_before_execution").await?;
        require(
            initial_journal["backendPid"] != observer.pid
                && initial_pool["backendPid"] != observer.pid
                && initial_pool["backendPid"] != initial_journal["backendPid"],
            "original pools/observer need independent actual PIDs",
        )?;
        let journal = Arc::new(PausedJournal {
            inner: PostgresToolJournal::new(journal_pool.clone(), KEY)
                .map_err(|e| e.to_string())?,
            wire: proxy.evidence.clone(),
            entered: Notify::new(),
            gate: Semaphore::new(0),
            decisions: AtomicUsize::new(0),
            receipts: AtomicUsize::new(0),
            attaches: AtomicUsize::new(0),
            outcomes: AtomicUsize::new(0),
            refusals: AtomicUsize::new(0),
            outcome: Mutex::new(None),
            actual_result: Mutex::new(None),
        });
        let auth = AuthContextBuilder::from_verified_session(
            begin.deployment.clone(),
            begin.tenant.clone(),
            begin.actor.clone(),
            begin.auth_generation,
            false,
        )
        .with_role(Role::User)
        .build();
        let invocation = ToolInvocation {
            call_id: ToolCallId::new("positive-recovery-original-remember-call"),
            run_id: begin.command.run_id.clone(),
            bot_id: begin.command.bot_id.clone(),
            call_seq: 0,
            tool_name: "remember".into(),
            arguments: json!({"scope":"thread","content":CONTENT,"tags":["positive-recovery"],"memoryKind":"fact","sensitivity":"normal"}),
        };
        Ok(Self {
            config,
            pool,
            journal_pool,
            recovery_pool: None,
            observer,
            proxy: Some(proxy),
            journal,
            runtime,
            begin,
            original_begin,
            lease,
            auth,
            invocation,
            task: None,
            initial_pool,
            initial_journal,
        })
    }
    fn launch(&mut self, control: Arc<ForwardBuiltIn>) {
        let journal = self.journal.clone();
        let auth = self.auth.clone();
        let invocation = self.invocation.clone();
        journal
            .wire
            .begin_phase("real_original_remember_before_paused_outcome", false);
        self.task = Some(tokio::spawn(async move {
            invoke_tool(control.as_ref(), journal.as_ref(), &auth, invocation).await
        }));
    }
    async fn resume(&mut self) -> Result<Result<ToolResult, AppError>, String> {
        self.journal.gate.add_permits(1);
        let mut task = self.task.take().ok_or("actual paused invocation missing")?;
        match tokio::time::timeout(BOUND, &mut task).await {
            Ok(result) => result.map_err(|e| e.to_string()),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("real late original outcome did not finish".into())
            }
        }
    }
    async fn close(&mut self) -> Result<(), String> {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.journal_pool.close();
        self.pool.close();
        if let Some(pool) = self.recovery_pool.take() {
            pool.close();
        }
        let proxy = if let Some(proxy) = self.proxy.take() {
            proxy.close().await
        } else {
            Ok(())
        };
        let observer = self.observer.close().await;
        proxy.and(observer)
    }
}

fn assert_binding(snapshot: &Value, draft: &ToolDecisionDraft) -> Result<(), String> {
    let call = one(snapshot, "tool_calls")?;
    let attempt = one(snapshot, "tool_attempts")?;
    for (key, expected) in [
        ("tool_call_id", json!(draft.call_id.as_str())),
        ("run_id", json!(draft.run_id.as_str())),
        ("call_seq", json!(draft.call_seq)),
        ("actor_id", json!(draft.actor.as_str())),
        ("bot_id", json!(draft.bot.as_str())),
        ("tool_name", json!(draft.metadata.name.as_str())),
        ("schema_hash", json!(draft.metadata.schema_hash.to_hex())),
        (
            "catalog_generation",
            json!(draft.metadata.catalog_generation.get()),
        ),
        ("args_hash", json!(draft.args_hash.to_hex())),
        ("target_kind", json!(draft.target.kind)),
        ("target_id", json!(draft.target.id)),
        ("effect", json!(draft.metadata.effect.effect().as_str())),
        (
            "effect_downgraded",
            json!(draft.metadata.effect.was_downgraded()),
        ),
        ("idempotency", json!(draft.metadata.idempotency.as_str())),
        (
            "approval_class",
            json!(draft.metadata.approval_class.as_str()),
        ),
        ("policy_version", json!(draft.policy_version.as_str())),
        ("approval_id", json!(draft.approval_id)),
    ] {
        require(
            call[key] == expected,
            &format!("call binding mismatch {key}"),
        )?;
    }
    require(
        call["idempotency_key"].is_null(),
        "unexpected call idempotency key",
    )?;
    for field in ["decision_id", "attempt_id"] {
        let id = if field == "decision_id" {
            &call[field]
        } else {
            &attempt[field]
        };
        let id = id.as_str().ok_or("missing repository minted ID")?;
        let uuid = uuid::Uuid::parse_str(id).map_err(|e| e.to_string())?;
        require(
            uuid.get_version_num() == 7,
            "decision/attempt must be real Rust generated UUIDv7",
        )?;
    }
    require(
        attempt["tool_call_id"] == call["tool_call_id"] && attempt["attempt_seq"] == 0,
        "wrong first attempt identity",
    )
}

fn assert_positive(
    before: &Value,
    draft: &ToolOutcomeDraft,
    request: &RememberToolMemoryRequest,
    effect: &CommittedMemoryEffect,
    f: &Fixture,
) -> Result<(), String> {
    assert_binding(before, &draft.decision)?;
    let receipt = one(before, "remember_effect_receipts")?;
    let memory = one(before, "memories")?;
    let event = one(before, "memory_events")?;
    let attempt = one(before, "tool_attempts")?;
    let run = one(before, "runs")?;
    let outbox = one(before, "outbox")?;
    require(
        draft.decision.metadata.name.as_str() == "remember"
            && draft.outcome.commit_state == CommitState::Committed
            && draft.outcome.error_code.is_none()
            && attempt["status"] == "executing"
            && attempt["commit_state"].is_null()
            && !attempt["started_at"].is_null()
            && attempt["finished_at"].is_null()
            && attempt["capability_id"] == draft.capability_id.as_str(),
        "original real producer/ordinary-attempt facts mismatch",
    )?;
    require(
        run["run_id"] == f.begin.command.run_id.as_str()
            && run["status"] == "running"
            && run["terminal_event_seq"].is_null()
            && run["finished_at"].is_null()
            && run["error_code"].is_null()
            && run["fencing_token"] == f.lease.fencing().get()
            && outbox["status"] == "delivered"
            && outbox["payload"]["runId"] == run["run_id"]
            && outbox["attempt_count"] == 1,
        "positive must precede recovery while original run is actually running/delivered",
    )?;
    require(
        receipt["receipt_id"] == effect.receipt_id
            && receipt["memory_id"] == effect.memory_id
            && memory["memory_id"] == effect.memory_id
            && memory["origin"] == "remember_tool"
            && memory["content"] == CONTENT
            && event["memory_id"] == effect.memory_id
            && event["seq"] == 0
            && receipt["memory_event_seq"] == 0,
        "positive memory/event/receipt identities mismatch",
    )?;
    require(
        request.call() == &draft.decision.call_id
            && request.attempt() == draft.receipt.attempt()
            && request.decision() == draft.receipt.decision()
            && request.capability() == &draft.capability_id
            && request.args_hash() == &draft.decision.args_hash
            && request.schema_hash() == &draft.decision.metadata.schema_hash
            && request.catalog_generation() == draft.decision.metadata.catalog_generation
            && request.target() == &draft.decision.target,
        "actual redeemed private request changed original journal binding",
    )?;
    for (key, expected) in [
        ("deployment_id", json!(request.deployment().as_str())),
        ("tenant_id", json!(request.tenant().as_str())),
        ("actor_id", json!(request.actor().as_str())),
        ("auth_generation", json!(request.auth_generation().get())),
        ("bot_id", json!(request.bot().as_str())),
        ("thread_id", json!(request.thread().as_str())),
        ("run_id", json!(request.run().as_str())),
        ("tool_call_id", json!(draft.decision.call_id.as_str())),
        ("call_seq", json!(draft.decision.call_seq)),
        ("attempt_id", json!(draft.receipt.attempt().as_str())),
        ("attempt_seq", json!(0)),
        ("decision_id", json!(draft.receipt.decision().as_str())),
        ("capability_id", json!(draft.capability_id.as_str())),
        ("args_hash", json!(draft.decision.args_hash.to_hex())),
        (
            "schema_hash",
            json!(draft.decision.metadata.schema_hash.to_hex()),
        ),
        (
            "catalog_generation",
            json!(draft.decision.metadata.catalog_generation.get()),
        ),
        ("target_kind", json!(draft.decision.target.kind)),
        ("target_id", json!(draft.decision.target.id)),
    ] {
        require(
            receipt[key] == expected,
            &format!("positive original receipt binding mismatch {key}"),
        )?;
    }
    let audit = one(before, "audit_events")?;
    require(
        audit["event_type"] == "memory.effect_committed"
            && audit["id"] == receipt["audit_event_id"]
            && audit["target_type"] == "memory_effect_receipt"
            && audit["target_id"] == receipt["receipt_id"]
            && audit["payload"]["decision_id"] == receipt["decision_id"],
        "real positive business audit missing",
    )?;
    require(
        rows(before, "messages").len() == 1
            && rows(before, "run_events").len() == 1
            && rows(before, "thread_run_occupancy").len() == 1
            && rows(before, "tool_approvals").is_empty(),
        "new run/prompt/approval or terminal manufactured before restart",
    )
}

fn assert_recovery(
    before: &Value,
    after: &Value,
    terminal: &RunWriteReceipt,
    lease: &RunExecutionLease,
) -> Result<(), String> {
    for table in TABLES {
        if !["runs", "threads", "thread_leases", "run_events"].contains(&table) {
            require(
                before[table] == after[table],
                &format!("recovery mutated protected {table}"),
            )?;
        }
    }
    stable_columns(
        before,
        after,
        "runs",
        &[
            "status",
            "fencing_token",
            "next_event_seq",
            "terminal_event_seq",
            "error_code",
            "finished_at",
        ],
    )?;
    stable_columns(before, after, "threads", &["next_event_seq", "updated_at"])?;
    stable_columns(
        before,
        after,
        "thread_leases",
        &[
            "owner_id",
            "fencing_token",
            "acquired_at",
            "expires_at",
            "updated_at",
        ],
    )?;
    let run = one(after, "runs")?;
    let old_run = one(before, "runs")?;
    let thread = one(after, "threads")?;
    let old_thread = one(before, "threads")?;
    let recovered = one(after, "thread_leases")?;
    let old_lease = one(before, "thread_leases")?;
    let n = lease.fencing().get();
    let next = n.checked_add(1).ok_or("fixture old fence cannot be MAX")?;
    require(
        n > 0
            && old_run["fencing_token"] == n
            && old_lease["fencing_token"] == n
            && run["fencing_token"] == next
            && recovered["fencing_token"] == next
            && recovered["owner_id"] == RECOVERY_OWNER
            && recovered["thread_id"] == old_lease["thread_id"],
        "actual recovery did not take over exact original lease with N+1",
    )?;
    require(
        !terminal.replayed
            && terminal.message_sequence.is_none()
            && run["status"] == "reconciliation_required"
            && run["error_code"] == "runtime_lease_expired"
            && run["run_id"] == lease.run_id().as_str()
            && run["thread_id"] == lease.thread_id().as_str()
            && run["terminal_event_seq"] == terminal.run_event_sequence
            && run["next_event_seq"]
                == terminal
                    .run_event_sequence
                    .checked_add(1)
                    .ok_or("run seq overflow")?
            && old_run["next_event_seq"] == terminal.run_event_sequence,
        "actual recovery lost original run or event identity",
    )?;
    let old_thread_next = old_thread["next_event_seq"]
        .as_u64()
        .ok_or("old thread event missing")?;
    require(
        thread["next_event_seq"]
            == old_thread_next
                .checked_add(1)
                .ok_or("thread seq overflow")?
            && terminal.thread_event_sequence == old_thread_next,
        "thread recovery event advance differs",
    )?;
    let old_events = rows(before, "run_events");
    let events = rows(after, "run_events");
    let terminal_events = events
        .iter()
        .filter(|e| e["terminal"] == true)
        .collect::<Vec<_>>();
    require(
        events.len() == old_events.len() + 1
            && old_events.iter().all(|old| events.contains(old))
            && terminal_events.len() == 1,
        "recovery rewrote historical events or appended extra terminal",
    )?;
    let event = terminal_events[0];
    require(
        event["run_id"] == lease.run_id().as_str()
            && event["thread_id"] == lease.thread_id().as_str()
            && event["seq"] == terminal.run_event_sequence
            && event["event_seq"] == old_thread_next
            && event["event_type"] == "reconciliation_required"
            && event["payload"]
                == json!({"status":"reconciliation_required","errorCode":"runtime_lease_expired"}),
        "wrong actual original recovery terminal payload",
    )?;
    let acquired = timestamp(&recovered["acquired_at"])?;
    let finish = timestamp(&run["finished_at"])?;
    let release = timestamp(&recovered["expires_at"])?;
    let minimum = acquired
        .checked_add(time::Duration::microseconds(1))
        .ok_or("recovery clock overflow")?;
    require(
        acquired > timestamp(&old_lease["acquired_at"])?
            && finish == acquired
            && release == finish.max(minimum)
            && run["finished_at"] == thread["updated_at"]
            && run["finished_at"] == recovered["updated_at"]
            && run["finished_at"] == event["created_at"],
        "recovery DB clocks or max(finish,acquired+1us) lease release differ",
    )?;
    Ok(())
}

async fn restart_owned(handshake: &Path) -> Result<(), String> {
    require(
        handshake.is_absolute()
            && handshake.is_dir()
            && !handshake.join("request").exists()
            && !handshake.join("ready").exists(),
        "explicit fresh owned restart handshake required",
    )?;
    std::fs::write(handshake.join("request"), b"restart-owned-cluster\n")
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(RESTART_BOUND, async {
        while !handshake.join("ready").is_file() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "owned PG actual stop/start acknowledgement timed out")?;
    require(
        std::fs::read(handshake.join("ready")).map_err(|e| e.to_string())?
            == b"same-data-directory-restarted\n",
        "owned restart marker mismatch",
    )
}

#[tokio::test]
#[ignore = "requires owned PG same-data restart controller and OPENBOT_TEST_RESTART_HANDSHAKE_DIR"]
async fn positive_running_restart_recovers_original_and_fences_late_writers() {
    let handshake = PathBuf::from(
        std::env::var_os("OPENBOT_TEST_RESTART_HANDSHAKE_DIR")
            .expect("root-owned same-PG data-dir restart controller required"),
    );
    let tag = "positive_running_restart";
    harness::with_temp_database(&harness::admin_config(tag),tag,|config|async move {
        let mut f=Fixture::new(config).await?;
        let result=async {
            let policy=PolicyStore::postgres(f.pool.clone(),None);
            policy.load().await.map_err(|e|e.to_string())?;
            policy.set(ActionPolicy {mode:PolicyMode::Enforce,deny:vec![],allow:vec!["tool.name == \"remember\"".into()]},Some(ACTOR))
                .await.map_err(|e|e.to_string())?;
            let memory=Arc::new(ForwardMemory {inner:PostgresMemoryAdministration::new(f.pool.clone())
                .with_effect_audit_key(KEY.to_vec()).map_err(|e|e.to_string())?,entries:AtomicUsize::new(0),
                request:Mutex::new(None),effect:Mutex::new(None)});
            let control=Arc::new(ForwardBuiltIn {inner:PostgresBuiltInToolControlPlane::new(f.pool.clone(),
                f.begin.deployment.clone(),f.begin.tenant.clone(),policy,memory.clone()),executions:AtomicUsize::new(0)});
            f.launch(control.clone());
            tokio::time::timeout(BOUND,f.journal.entered.notified()).await
                .map_err(|_|"real positive producer did not reach pre-checkout ordinary-outcome gate")?;
            let draft=f.journal.draft()?;
            let request=memory.request.lock().expect("real private request").clone().ok_or("actual remember not reached")?;
            let effect=memory.effect.lock().expect("real business result").clone().ok_or("real Memory business COMMIT missing")?;
            let before=f.observer.snapshot().await?;
            assert_positive(&before,&draft,&request,&effect,&f)?;
            require(control.executions.load(Ordering::SeqCst)==1 && memory.entries.load(Ordering::SeqCst)==1
                && f.journal.counts()==json!({"decision_entries":1,"returned_durable_receipts":1,"attach_entries":1,
                    "outcome_entries":1,"refusal_entries":0}),"real pipeline automatically repeated")?;
            let process_before=f.observer.observation(f.begin.command.thread_id.as_str()).await?;
            require(process_before["leaseExpired"]==false,"positive baseline must have actual unexpired DB lease")?;
            let expected_data=handshake.parent().ok_or("owned handshake parent missing")?.join("data");
            require(process_before["dataDirectory"].as_str()==expected_data.to_str(),"observer connected to wrong owned PG data directory")?;
            // Both max1 pools are available with no checked-out client while the original future pauses.
            let idle_journal=pool_observation(&f.journal_pool,"paused_original_journal_no_checkout").await?;
            require(idle_journal["backendPid"]==f.initial_journal["backendPid"],"original journal pool changed before restart")?;
            require(f.runtime.claim_dispatch().await.map_err(|e|e.to_string())?.is_none(),
                "delivered original ACK was claimed before expiry")?;
            require(f.observer.snapshot().await?==before,"finite sameOWNER delivered claim changed16table state")?;
            println!("POSITIVE_RUNNING_BASELINE {}",json!({"facts":before,"process":process_before,
                "original_pool":f.initial_pool,"original_journal":f.initial_journal,"counts":f.journal.counts(),
                "executor":control.executions.load(Ordering::SeqCst),"business_producer":memory.entries.load(Ordering::SeqCst)}));
            // Keep original journal and producer/runtime pools open; only direct old observer is joined.
            f.observer.close().await?;
            restart_owned(&handshake).await?;
            f.observer=Observer::new(&f.config).await?;
            let process_after=f.observer.observation(f.begin.command.thread_id.as_str()).await?;
            require(process_after["database"]==process_before["database"]
                && process_after["dataDirectory"]==process_before["dataDirectory"]
                && process_after["backendPid"]!=process_before["backendPid"]
                && timestamp(&process_after["postmasterStartedAt"])? > timestamp(&process_before["postmasterStartedAt"])? ,
                "restart did not preserve owned DB/path and change actual process/backend")?;
            let restarted=f.observer.snapshot().await?;
            require(restarted==before,"actual PG restart itself changed16 persisted tables")?;
            require(one(&restarted,"runs")?["status"]=="running","restart prematurely terminalized original run")?;
            // Successful real SQL on the SAME still-open original max1 pools; no invoke_tool retry.
            let live_journal=pool_observation(&f.journal_pool,"same_original_journal_live_after_restart").await?;
            let live_original=pool_observation(&f.pool,"same_original_runtime_live_after_restart").await?;
            require(live_journal["backendPid"]!=f.initial_journal["backendPid"]
                && live_original["backendPid"]!=f.initial_pool["backendPid"]
                && live_journal["backendPid"]!=process_after["backendPid"]
                && live_original["backendPid"]!=process_after["backendPid"]
                && live_original["backendPid"]!=live_journal["backendPid"]
                && live_journal["database"]==process_after["database"]
                && live_original["database"]==process_after["database"]
                && live_journal["postmasterStartedAt"]==process_after["postmasterStartedAt"]
                && live_original["postmasterStartedAt"]==process_after["postmasterStartedAt"],
                "old pools do not have actual fresh live independent backends")?;
            let recovery_pool=pool::connect(&f.config.clone().with_max_pool_size(1)
                .with_application_name("owned-positive-recovery-new-runtime")).await.map_err(|e|e.to_string())?;
            f.recovery_pool=Some(recovery_pool.clone());
            let recovery_backend=pool_observation(&recovery_pool,"new_recovery_runtime_defaultRR").await?;
            require(recovery_backend["backendPid"]!=live_journal["backendPid"]
                && recovery_backend["backendPid"]!=live_original["backendPid"]
                && recovery_backend["backendPid"]!=process_after["backendPid"], "recovery requires independent actual backend")?;
            println!("POSITIVE_ACTUAL_RESTART {}",json!({"before_process":process_before,"after_process":process_after,
                "before":before,"after":restarted,"live_original_journal":live_journal,"live_original_runtime":live_original,
                "new_recovery_backend":recovery_backend,"same_open_journal_adapter":true}));
            let mut clock_polls=0u64;
            let expired=tokio::time::timeout(EXPIRY_BOUND,async {
                loop {
                    clock_polls+=1;
                    let fact=f.observer.observation(f.begin.command.thread_id.as_str()).await?;
                    if fact["leaseExpired"]==true {return Ok::<_,String>(fact);}
                    // Timer only paces bounded real DB observations; it does not establish expiry.
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.map_err(|_|"original lease did not naturally expire in bounded DB observation")??;
            require(f.observer.snapshot().await?==restarted,"waiting for natural expiry wrote persistent facts")?;
            let recovery=PostgresRunRuntime::new(recovery_pool.clone(),RECOVERY_OWNER.into(),LEASE_DURATION,CLAIM_DURATION)
                .map_err(|e|e.to_string())?;
            let terminal=recovery.recover_one_stale_run().await.map_err(|e|e.to_string())?
                .ok_or("actual expired positive-running original not recovered")?;
            let rr=f.observer.snapshot().await?;
            assert_recovery(&restarted,&rr,&terminal,&f.lease)?;
            require(recovery.recover_one_stale_run().await.map_err(|e|e.to_string())?.is_none(),
                "actual original was recovered twice")?;
            require(f.observer.snapshot().await?==rr,"second actual recoverNone mutated16tables")?;
            require(f.runtime.claim_dispatch().await.map_err(|e|e.to_string())?.is_none(),
                "same original OWNER re-claimed delivered terminal original")?;
            require(f.observer.snapshot().await?==rr,"terminal delivered claimNone mutated16tables")?;
            println!("POSITIVE_ACTUAL_RECOVERY {}",json!({"before":restarted,"after":rr,"natural_expiry":expired,
                "DB_clock_polls":clock_polls,"terminal_run_sequence":terminal.run_event_sequence,
                "terminal_thread_sequence":terminal.thread_event_sequence,"terminal_message_sequence":terminal.message_sequence,
                "replayed":terminal.replayed,"first_recovery_some":true,"second_recovery_none":true,"sameOWNER_claim_none":true}));
            let late=f.resume().await?;
            require(late==Err(AppError::ReconciliationRequired {accepted:false}),
                "late genuine original ordinary outcome must preserve unaccepted reconciliation")?;
            require(*f.journal.actual_result.lock().expect("actual late journal error")==Some(Err(ToolPortError::Conflict)),
                "late original ordinary journal must reject terminal via actual Conflict, not closed/unavailable pool")?;
            let after_late=f.observer.snapshot().await?;
            require(after_late==rr,"late ordinary journal rewrote16table terminal/positive state")?;
            let same_live=pool_observation(&f.journal_pool,"same_original_journal_after_actualConflict").await?;
            require(same_live["backendPid"]==live_journal["backendPid"],"late journal used different backend than proven live original pool")?;
            let wire=f.journal.wire.events();
            let phase=wire.iter().rposition(|e|e["phase"]=="late_original_ordinary_after_actual_recovery")
                .ok_or("real late original journal phase missing")?;
            let late_wire=&wire[phase+1..];
            require(late_wire.iter().any(|e|e["frontend_sql"]=="START TRANSACTION ISOLATION LEVEL READ COMMITTED")
                && late_wire.iter().any(|e|e["frontend_sql"].as_str().is_some_and(|sql|sql.contains("FROM public.runs") && sql.contains("FOR UPDATE NOWAIT")))
                && !late_wire.iter().any(|e|e["frontend_sql"]=="COMMIT" || !e["backend_error"].is_null())
                && f.journal.wire.suppressed.load(Ordering::SeqCst)==0,
                "late original Conflict was not real live production specialized guard")?;
            require(control.executions.load(Ordering::SeqCst)==1 && memory.entries.load(Ordering::SeqCst)==1
                && f.journal.counts()==json!({"decision_entries":1,"returned_durable_receipts":1,"attach_entries":1,
                    "outcome_entries":1,"refusal_entries":0}),"old future caused repeat executor/producer/decision")?;
            println!("POSITIVE_LATE_JOURNAL {}",json!({"before":rr,"after":after_late,"application_result":format!("{late:?}"),
                "journal_result":"Conflict","live_backend":same_live,"wire":wire,"counts":f.journal.counts(),
                "executor":control.executions.load(Ordering::SeqCst),"business_producer":memory.entries.load(Ordering::SeqCst)}));
            // Valid original lease inputs hit StaleLease identity/fence, not malformed input or same-fence Conflict.
            require(f.runtime.renew_lease(&f.lease).await==Err(RunRuntimeError::StaleLease),"late original renew was not StaleLease")?;
            require(f.observer.snapshot().await?==rr,"late original renew changed16tables")?;
            require(f.runtime.append_semantic_chunk(&f.lease,f.lease.next_event_sequence(),RunSemanticChannel::Text,"owned rejected late text").await
                ==Err(RunRuntimeError::StaleLease),"late original semantic chunk was not StaleLease")?;
            require(f.observer.snapshot().await?==rr,"late original chunk changed16tables")?;
            require(f.runtime.finish_run(&f.lease,f.lease.next_event_sequence(),RunTerminal::ReconciliationRequired(RunFailureCode::RuntimeLeaseExpired)).await
                ==Err(RunRuntimeError::StaleLease),"late original finish was not StaleLease before terminal replay")?;
            require(f.observer.snapshot().await?==rr,"late original finish changed16tables")?;
            println!("POSITIVE_LATE_RUNTIME {}",json!({"old_fence":f.lease.fencing().get(),"current_fence":one(&rr,"runs")?["fencing_token"],
                "renew":"StaleLease","semantic_chunk":"StaleLease","finish":"StaleLease","before":rr,"after":f.observer.snapshot().await?}));
            let historical=PostgresMemoryAdministration::new(recovery_pool.clone())
                .with_effect_audit_key(KEY.to_vec()).map_err(|e|e.to_string())?
                .remember_from_tool(request).await.map_err(|e|e.to_string())?;
            require(historical==effect && f.observer.snapshot().await?==rr,"current-authorized exact history duplicated business effect or changed16tables")?;
            println!("POSITIVE_HISTORICAL_RECEIPT {}",json!({"receipt_id":historical.receipt_id,"memory_id":historical.memory_id,
                "historical_read_entries":1,"original_executed_business_entries":memory.entries.load(Ordering::SeqCst),"full16_equal":true}));
            let directory=PostgresThreadDirectory::with_runtime(recovery_pool.clone(),f.config.clone(),RECOVERY_OWNER.into(),LEASE_DURATION)
                .map_err(|e|e.to_string())?;
            let replay=directory.begin_thread_run(f.begin.clone()).await.map_err(|e|e.to_string())?;
            let mut original_replay=f.original_begin.clone();original_replay.replayed=true;
            require(replay==original_replay && f.observer.snapshot().await?==rr,"exact original begin replay changed source or durable state")?;
            let mut next=f.begin.clone();next.command.run_id=RunId::new("positive-recovery-blocked-successor");
            require(directory.begin_thread_run(next).await==Err(ThreadDirectoryError::LeaseConflict)
                && f.observer.snapshot().await?==rr,"fresh successor bypassed original Unknown occupancy or wrote prompt/outbox")?;
            let conversation=directory.thread_conversation(ThreadConversationRequest {deployment:f.begin.deployment.clone(),tenant:f.begin.tenant.clone(),actor:f.begin.actor.clone(),thread:f.begin.command.thread_id.clone()})
                .await.map_err(|e|e.to_string())?;
            require(conversation.active_run_id==Some(f.begin.command.run_id.clone())
                && conversation.active_run_state==Some(ThreadForegroundRunState::ReconciliationRequired)
                && !conversation.active_run_cancellable && conversation.active_run_text.is_empty()
                && conversation.messages.len()==1 && conversation.messages[0].content==f.begin.command.message
                && f.observer.snapshot().await?==rr,"conversation lost original Unknown or replayed prompt")?;
            let active=RunRepo::new(recovery_pool.clone()).active_foreground_for_thread(f.begin.command.thread_id.as_str())
                .await.map_err(|e|e.to_string())?.ok_or("original internal occupancy missing")?;
            require(active.run_id==f.begin.command.run_id.as_str() && active.status=="reconciliation_required"
                && f.observer.snapshot().await?==rr,"internal occupancy did not preserve exact original RR")?;
            let facts=openbot_application::use_cases::thread::get_run_reconciliation(&directory,&f.auth,
                f.begin.command.thread_id.clone(),f.begin.command.run_id.clone(),None,Some(50)).await.map_err(|e|e.to_string())?;
            require(f.observer.snapshot().await?==rr,"actual Application074 read changed16tables")?;
            let positive=openbot_application::use_cases::thread::get_run_effect_receipts(&directory,&f.auth,
                f.begin.command.thread_id.clone(),f.begin.command.run_id.clone(),None,Some(50)).await.map_err(|e|e.to_string())?;
            require(f.observer.snapshot().await?==rr,"actual Application075 read changed16tables")?;
            require(facts.status==RunReconciliationStatus::ReconciliationRequired && facts.run_id==f.begin.command.run_id
                && facts.thread_id==f.begin.command.thread_id && facts.terminal_event_sequence==terminal.run_event_sequence
                && facts.foreground_blocked && facts.available_actions.is_empty() && facts.next.is_none()
                && facts.attempts.len()==1 && facts.attempts[0].status==RunReconciliationAttemptStatus::Executing
                && facts.attempts[0].recorded_commit_state.is_none() && facts.attempts[0].attempt_id==draft.receipt.attempt().as_str(),
                "actual Application074 lost original unresolved ordinary outcome")?;
            let raw_receipt=one(&rr,"remember_effect_receipts")?;
            let original_call_sequence=i64::try_from(draft.decision.call_seq)
                .map_err(|_|"original actual call sequence exceeds signed receipt contract")?;
            require(positive.status==facts.status && positive.run_id==facts.run_id && positive.thread_id==facts.thread_id
                && positive.terminal_event_sequence==facts.terminal_event_sequence && positive.foreground_blocked
                && positive.available_actions.is_empty() && positive.next.is_none() && positive.receipts.len()==1
                && positive.receipts[0].receipt_id==effect.receipt_id && positive.receipts[0].fact==RunEffectReceiptFact::MemoryCreated
                && positive.receipts[0].attempt_id==draft.receipt.attempt().as_str()
                && positive.receipts[0].tool_call_id==draft.decision.call_id.as_str()
                && positive.receipts[0].attempt_sequence==0 && positive.receipts[0].call_sequence==original_call_sequence
                && positive.receipts[0].recorded_at==timestamp(&raw_receipt["recorded_at"])? ,
                "actual Application075 lost original exact positive business receipt")?;
            println!("POSITIVE_FIVE_CONSUMERS {}",json!({"begin_original_replayed":replay,"new_begin":"LeaseConflict",
                "conversation":conversation,"internal_active_run_id":active.run_id,"internal_active_status":active.status,
                "074":facts,"075":positive,"before":rr,"after":f.observer.snapshot().await?,
                "no_auto_replay_finite_only":true,"fullAgent_or_hostwire_claim":false}));
            Ok(())
        }.await;
        let closed=f.close().await;result.and(closed)
    }).await;
}
