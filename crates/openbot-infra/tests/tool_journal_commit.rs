//! Actual invoke_tool/coordinator/journal COMMIT boundaries on fresh owned PostgreSQL.
//! Synthetic catalog/executor controls isolate the first two decision gates; the third executes
//! the production remember control plane and producer. No fake journal result or receipt exists.
mod harness;
#[path = "tool_journal_commit/support.rs"]
mod support;

use async_trait::async_trait;
use openbot_application::{
    AuthorizedToolCall, BeginThreadRunRequest, CommittedMemoryEffect, MemoryAdministrationError,
    RememberToolMemory, RememberToolMemoryRequest, ResolvedToolScope, RunExecutionLease,
    RunFailureCode, RunReconciliationRequest, RunRuntime, RunTerminal, ThreadDirectory,
    ToolApprovalAdministration, ToolApprovalPresentation, ToolApprovalRequest, ToolControlPlane,
    ToolDecisionDraft, ToolExecutionReport, ToolJournal, ToolOutcomeDraft, ToolPolicyEvaluation,
    ToolPortError, ToolRefusalDraft, invoke_tool,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, ThreadRunAnchor},
    error::AppError,
    ids::{
        ActorId, BotId, CapabilityId, CatalogGeneration, ComputerGeneration, DeploymentId, RunId,
        TenantId, ThreadId, ToolCallId, thread::ThreadIdentity,
    },
    reconciliation::{
        RunEffectReceiptFact, RunReconciliationAttemptStatus, RunReconciliationStatus,
    },
    tool::{ToolApprovalDecision, ToolInvocation, ToolResult},
};
use openbot_domain::{
    audit::hash::Sha256Digest,
    policy::{
        ActionPolicy, CompiledActionPolicy, PolicyMode,
        context::{ActorRef, BotRef, PageRef, PolicyContext, ToolRef},
        evaluate,
    },
    tool::{
        approval::{ApprovalBinding, ApprovalObservation, ApprovalTarget},
        args::ToolArguments,
        commit::CommitState,
        metadata::{
            ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement,
            ToolLimits, ToolMetadata, ToolName,
        },
        pipeline::{ApprovalEvidence, ApprovalOutcome, DurableDecisionReceipt},
    },
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    agent_tools::PostgresBuiltInToolControlPlane,
    db::{fresh, pool, pool::DatabaseConfig},
    memory_admin::PostgresMemoryAdministration,
    policy::PolicyStore,
    repo::tools::PostgresToolJournal,
    run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime},
    thread_directory::PostgresThreadDirectory,
    tool_approval::{DurableHumanDecision, PostgresToolApprovalCoordinator},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{Observer, OwnedFrameProxy, WireEvidence};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinHandle,
};

const BOUND: Duration = Duration::from_secs(10);
const KEY: &[u8] = b"owned-journal-commit-boundaries-audit-key";
const ACTOR: &str = "journal-commit-owner";
const BOT: &str = "journal-commit-bot";
const OWNER: &str = "journal-commit-runtime";
const CONTENT: &str = "owned synthetic remember COMMIT evidence";
const APPROVED_TOOL: &str = "mcp__journal_commit__write";
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
fn rows<'a>(snapshot: &'a Value, table: &str) -> &'a [Value] {
    snapshot[table].as_array().expect("owned16-table facts")
}
fn one<'a>(snapshot: &'a Value, table: &str) -> Result<&'a Value, String> {
    let r = rows(snapshot, table);
    require(r.len() == 1, &format!("expected one original {table}"))?;
    Ok(&r[0])
}
fn unchanged_except(before: &Value, after: &Value, allowed: &[&str]) -> Result<(), String> {
    for table in TABLES {
        if !allowed.contains(&table) {
            require(
                before[table] == after[table],
                &format!("unexpected durable {table} mutation"),
            )?;
        }
    }
    Ok(())
}
async fn wait(notify: &Notify, label: &str) -> Result<(), String> {
    tokio::time::timeout(BOUND, notify.notified())
        .await
        .map_err(|_| format!("{label} did not reach real phase"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Decision,
    Outcome,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Decision => "first_decision",
            Self::Outcome => "ordinary_remember_outcome",
        }
    }
}

struct JournalObserver {
    inner: PostgresToolJournal,
    phase: Phase,
    lose_response: bool,
    wire: Arc<WireEvidence>,
    entered: Notify,
    gate: Semaphore,
    decisions: AtomicUsize,
    receipts: AtomicUsize,
    attaches: AtomicUsize,
    outcomes: AtomicUsize,
    refusals: AtomicUsize,
    decision: Mutex<Option<ToolDecisionDraft>>,
    outcome: Mutex<Option<ToolOutcomeDraft>>,
    decision_result: Mutex<Option<Result<DurableDecisionReceipt, ToolPortError>>>,
    outcome_result: Mutex<Option<Result<(), ToolPortError>>>,
}
impl JournalObserver {
    async fn pause(&self, phase: Phase) {
        if self.phase == phase {
            self.entered.notify_one();
            self.gate
                .acquire()
                .await
                .expect("owned journal phase gate")
                .forget();
            self.wire.begin_phase(phase.name(), self.lose_response);
        }
    }
    fn counts(&self) -> Value {
        json!({"decision_entries":self.decisions.load(Ordering::SeqCst),"returned_durable_receipts":self.receipts.load(Ordering::SeqCst),"attach_entries":self.attaches.load(Ordering::SeqCst),"outcome_entries":self.outcomes.load(Ordering::SeqCst),"refusal_entries":self.refusals.load(Ordering::SeqCst)})
    }
    fn draft(&self) -> Result<ToolDecisionDraft, String> {
        self.decision
            .lock()
            .expect("owned decision capture")
            .clone()
            .ok_or("real decision not captured".into())
    }
    fn outcome_draft(&self) -> Result<ToolOutcomeDraft, String> {
        self.outcome
            .lock()
            .expect("owned outcome capture")
            .clone()
            .ok_or("real outcome not captured".into())
    }
}
#[async_trait]
impl ToolJournal for JournalObserver {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.decisions.fetch_add(1, Ordering::SeqCst);
        *self.decision.lock().expect("owned decision capture") = Some(draft.clone());
        self.pause(Phase::Decision).await;
        let result = self.inner.record_decision(draft).await;
        if result.is_ok() {
            self.receipts.fetch_add(1, Ordering::SeqCst);
        }
        *self
            .decision_result
            .lock()
            .expect("owned real decision result") = Some(result.clone());
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
        *self.outcome.lock().expect("owned outcome capture") = Some(draft.clone());
        self.pause(Phase::Outcome).await;
        let result = self.inner.record_outcome(draft).await;
        *self
            .outcome_result
            .lock()
            .expect("owned real outcome result") = Some(result);
        result
    }
}

// This catalog is an explicit test control. Its human evidence is the real coordinator's grant;
// current user generation/role/deny, run/lease and clock are read from this owned database.
struct ApprovedControl {
    pool: Pool,
    thread: ThreadId,
    coordinator: PostgresToolApprovalCoordinator,
    request: Mutex<Option<ToolApprovalRequest>>,
    executions: AtomicUsize,
}
#[async_trait]
impl ToolControlPlane for ApprovedControl {
    async fn metadata(&self, name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        if name.as_str() != APPROVED_TOOL {
            return Err(ToolPortError::InvalidInput { field: "tool_name" });
        }
        Ok(ToolMetadata {
            name: name.clone(),
            schema_hash: Sha256Digest::of(b"owned-journal-commit-schema"),
            catalog_generation: CatalogGeneration::new(9),
            effect: EffectClassification::declared(Effect::Write),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(5),
            approval_class: ApprovalClass::EveryCall,
            sandbox: SandboxRequirement::RequiredNoEgress,
            limits: ToolLimits {
                max_input_bytes: 4096,
                max_output_bytes: 4096,
                max_model_visible_bytes: 4096,
            },
            resource_locks: vec![],
        })
    }
    async fn resolve_scope(
        &self,
        auth: &AuthContext,
        invocation: &ToolInvocation,
        _args: &ToolArguments,
        _metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        Ok(ResolvedToolScope {
            tenant_id: auth.tenant().clone(),
            run_id: invocation.run_id.clone(),
            thread_id: self.thread.clone(),
            bot_id: invocation.bot_id.clone(),
            call_seq: invocation.call_seq,
            target: ApprovalTarget {
                kind: "mcp_tool",
                id: "owned-journal-commit-target".into(),
            },
            computer_generation: ComputerGeneration::new(0),
            target_document_generation: None,
            approval_presentation: Some(ToolApprovalPresentation {
                arguments_summary: json!({"fixture":"owned redacted write"}),
                change_summary: Some(json!({"kind":"owned_write"})),
            }),
            policy_context: PolicyContext {
                tool: ToolRef {
                    name: invocation.tool_name.clone(),
                },
                bot: BotRef {
                    id: invocation.bot_id.as_str().into(),
                },
                page: PageRef {
                    url: "https://journal-commit.example.test/".into(),
                    host: "journal-commit.example.test".into(),
                },
                actor: ActorRef {
                    id: auth.actor().as_str().into(),
                },
                element: None,
                key: None,
                intent: None,
                file: None,
                mcp: None,
                command: None,
            },
            idempotency_key: None,
            preflight_refusal: None,
        })
    }
    async fn evaluate_policy(
        &self,
        context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        let policy = CompiledActionPolicy::compile(&ActionPolicy {
            mode: PolicyMode::Enforce,
            deny: vec![],
            allow: vec!["true".into()],
        });
        Ok(ToolPolicyEvaluation::from_domain(&evaluate(
            &policy, context,
        )))
    }
    async fn approval(
        &self,
        request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        *self.request.lock().expect("owned real approval request") = Some(request.clone());
        match self.coordinator.request_and_wait(request).await? {
            DurableHumanDecision::Denied => Ok(ApprovalOutcome::Denied),
            DurableHumanDecision::Granted {
                approval_id,
                expires_at,
            } => {
                let c = self
                    .pool
                    .get()
                    .await
                    .map_err(|_| ToolPortError::Unavailable {
                        dependency: "owned_authority_observation",
                    })?;
                let row=c.query_one("SELECT clock_timestamp(),coalesce(u.auth_generation,0),EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) FROM public.users u WHERE u.id=$1",&[&request.actor.as_str()]).await.map_err(|_|ToolPortError::Unavailable{dependency:"owned_authority_observation"})?;
                let generation: i64 = row.get(1);
                let current: bool = row.get(2);
                let generation = u64::try_from(generation).map_err(|_| ToolPortError::Corrupt {
                    field: "auth_generation",
                })?;
                let binding = ApprovalBinding {
                    actor: request.actor.clone(),
                    auth_generation: request.auth_generation,
                    bot: request.bot.clone(),
                    run: request.run.clone(),
                    tool: request.tool.clone(),
                    args_hash: request.args_hash,
                    target: request.target.clone(),
                    computer_generation: request.computer_generation,
                    catalog_generation: request.catalog_generation,
                    target_document_generation: request.target_document_generation,
                    policy_version: request.policy_version.clone(),
                    expires_at,
                };
                let observed = ApprovalObservation {
                    actor: request.actor.clone(),
                    auth_generation: AuthGeneration::new(generation),
                    bot: request.bot.clone(),
                    run: request.run.clone(),
                    tool: request.tool.clone(),
                    args_hash: request.args_hash,
                    target: request.target.clone(),
                    computer_generation: ComputerGeneration::new(0),
                    catalog_generation: CatalogGeneration::new(9),
                    target_document_generation: None,
                    policy_version: request.policy_version.clone(),
                    actor_role_revoked: !current,
                    now: row.get(0),
                };
                Ok(ApprovalOutcome::Granted(Box::new(ApprovalEvidence {
                    approval_id,
                    binding,
                    observed,
                })))
            }
        }
    }
    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let (_, redeemed) = call.redeem();
        ToolExecutionReport::new(
            redeemed,
            "owned synthetic executor".into(),
            CommitState::Committed,
            Duration::ZERO,
            None,
        )
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
        *self.request.lock().expect("owned genuine private request") = Some(request.clone());
        let result = self.inner.remember_from_tool(request).await;
        if let Ok(effect) = &result {
            *self.effect.lock().expect("owned actual business result") = Some(effect.clone());
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
    pool: Pool,
    journal_pool: Pool,
    observer: Arc<Observer>,
    proxy: Option<OwnedFrameProxy>,
    journal: Arc<JournalObserver>,
    directory: PostgresThreadDirectory,
    runtime: PostgresRunRuntime,
    lease: RunExecutionLease,
    begin: BeginThreadRunRequest,
    invocation: ToolInvocation,
    auth: AuthContext,
    task: Option<JoinHandle<Result<ToolResult, AppError>>>,
    journal_pid: i32,
}
impl Fixture {
    async fn new(
        config: DatabaseConfig,
        tag: &str,
        phase: Phase,
        lose_response: bool,
    ) -> Result<Self, String> {
        let pool = pool::connect(&config.clone().with_max_pool_size(4))
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut c = pool.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('journal-commit-owner','owner@journal-commit.example.test',0);INSERT INTO public.user_roles(user_id,role) VALUES('journal-commit-owner','user');INSERT INTO public.agents(id,name,type,configuration) VALUES('journal-commit-bot','Journal COMMIT fixture','built_in','{}');INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('journal-commit-bot',NULL,'Journal COMMIT fixture','owned synthetic','journal-commit','public')").await.map_err(|e|e.to_string())?;
        }
        let deployment = DeploymentId::new("journal-commit-deployment");
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: TenantId::new("journal-commit-tenant"),
            actor: ActorId::new(ACTOR),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([109; 16]),
                run_id: RunId::new(format!("journal-commit-original-{tag}")),
                bot_id: BotId::new(BOT),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned synthetic journal source".into(),
                selected_skill_slugs: vec![],
                model_selection: None,
            },
        };
        let duration = time::Duration::minutes(10);
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            OWNER.into(),
            duration,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let runtime = PostgresRunRuntime::new(
            pool.clone(),
            OWNER.into(),
            duration,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("real tool fixture dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        let observer = Observer::new(&config).await?;
        let proxy = OwnedFrameProxy::start(&config).await?;
        let mut config = config
            .with_max_pool_size(1)
            .with_application_name("owned-journal-commit-worker");
        config.host = "127.0.0.1".into();
        config.port = proxy.port;
        let journal_pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let journal_pid = {
            let c = journal_pool.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("SET default_transaction_isolation='repeatable read'")
                .await
                .map_err(|e| e.to_string())?;
            require(
                c.query_one("SHOW default_transaction_isolation", &[])
                    .await
                    .map_err(|e| e.to_string())?
                    .get::<_, String>(0)
                    == "repeatable read",
                "journal directed defaultRR missing",
            )?;
            c.query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|e| e.to_string())?
                .get::<_, i32>(0)
        };
        require(
            journal_pid != observer.pid,
            "journal and observer must be independent backends",
        )?;
        let journal = Arc::new(JournalObserver {
            inner: PostgresToolJournal::new(journal_pool.clone(), KEY)
                .map_err(|e| e.to_string())?,
            phase,
            lose_response,
            wire: proxy.evidence.clone(),
            entered: Notify::new(),
            gate: Semaphore::new(0),
            decisions: AtomicUsize::new(0),
            receipts: AtomicUsize::new(0),
            attaches: AtomicUsize::new(0),
            outcomes: AtomicUsize::new(0),
            refusals: AtomicUsize::new(0),
            decision: Mutex::new(None),
            outcome: Mutex::new(None),
            decision_result: Mutex::new(None),
            outcome_result: Mutex::new(None),
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
            call_id: ToolCallId::new(format!("journal-commit-call-{tag}")),
            run_id: begin.command.run_id.clone(),
            bot_id: begin.command.bot_id.clone(),
            call_seq: 0,
            tool_name: if phase == Phase::Outcome {
                "remember".into()
            } else {
                APPROVED_TOOL.into()
            },
            arguments: if phase == Phase::Outcome {
                json!({"scope":"thread","content":CONTENT,"tags":["journal-commit"],"memoryKind":"fact","sensitivity":"normal"})
            } else {
                json!({"write":"owned synthetic write"})
            },
        };
        println!(
            "JOURNAL_FIXTURE {tag} journal_pid={journal_pid} observer_pid={} test_default=repeatable_read journal_actual_RC_observed_separately approval_runtime_default_not_claimed",
            observer.pid
        );
        Ok(Self {
            pool,
            journal_pool,
            observer,
            proxy: Some(proxy),
            journal,
            directory,
            runtime,
            lease,
            begin,
            invocation,
            auth,
            task: None,
            journal_pid,
        })
    }
    fn launch<C: ToolControlPlane + 'static>(&mut self, control: Arc<C>) {
        let journal = self.journal.clone();
        let auth = self.auth.clone();
        let invocation = self.invocation.clone();
        self.task = Some(tokio::spawn(async move {
            invoke_tool(control.as_ref(), journal.as_ref(), &auth, invocation).await
        }));
    }
    async fn finish(&mut self) -> Result<Result<ToolResult, AppError>, String> {
        self.journal.gate.add_permits(1);
        let mut task = self.task.take().ok_or("actual invocation not running")?;
        let result = tokio::time::timeout(BOUND, &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
            return Err("actual invocation did not finish".into());
        }
        result.expect("checked timeout").map_err(|e| e.to_string())
    }
    async fn approve(&self, control: &ApprovedControl) -> Result<(), String> {
        let pending = tokio::time::timeout(BOUND, async {
            loop {
                let page = control
                    .coordinator
                    .list_pending(&self.auth)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(pending) = page.approvals.into_iter().next() {
                    return Ok::<_, String>(pending);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "real approval not visible")??;
        require(
            pending.call_id == self.invocation.call_id,
            "pending approval belongs to another call",
        )?;
        control
            .coordinator
            .decide(
                &self.auth,
                &pending.approval_id,
                ToolApprovalDecision::Grant,
            )
            .await
            .map_err(|e| e.to_string())?;
        wait(&self.journal.entered, "post-grant firstdecision").await
    }
    fn approved_control(&self) -> Result<Arc<ApprovedControl>, String> {
        Ok(Arc::new(ApprovedControl {
            pool: self.pool.clone(),
            thread: self.begin.command.thread_id.clone(),
            coordinator: PostgresToolApprovalCoordinator::new(
                self.pool.clone(),
                self.begin.deployment.clone(),
                self.begin.tenant.clone(),
                KEY.to_vec(),
            )
            .map_err(|e| e.to_string())?,
            request: Mutex::new(None),
            executions: AtomicUsize::new(0),
        }))
    }
    async fn trigger(&self, table: &str, selector: &str) -> Result<(), String> {
        let c = self.pool.get().await.map_err(|e| e.to_string())?;
        let pid: i32 = c
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            pid != self.journal_pid && pid != self.observer.pid,
            "DDL controller must use a distinct unproxied backend",
        )?;
        println!(
            "JOURNAL_CONTROLLER {}",
            json!({
                "phase":self.journal.phase.name(),"controller_pid":pid,
                "journal_pid":self.journal_pid,"observer_pid":self.observer.pid
            })
        );
        let name = "owned_journal_commit_reject";
        c.batch_execute(&format!("CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {selector} THEN RAISE EXCEPTION 'owned journal COMMIT rejection phase={} tx=% isolation=%',txid_current(),current_setting('transaction_isolation') USING ERRCODE='P0001'; END IF;RETURN NEW;END $$;CREATE CONSTRAINT TRIGGER {name} AFTER INSERT ON public.{table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.{name}();",self.journal.phase.name())).await.map_err(|e|e.to_string())?;
        let row=c.query_one("SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgname=$1 AND tgrelid=$2::text::regclass",&[&name,&format!("public.{table}")]).await.map_err(|e|e.to_string())?;
        require(
            row.get::<_, bool>(0) && row.get::<_, bool>(1),
            "journal fault must fire at deferred COMMIT",
        )
    }
    fn assert_wire(&self, lost: bool) -> Result<(), String> {
        let wire = self.proxy.as_ref().ok_or("owned proxy missing")?;
        let events = wire.evidence.events();
        println!(
            "JOURNAL_WIRE {}",
            json!({"phase":self.journal.phase.name(),"journal_pid":self.journal_pid,"events":events,"suppressed":wire.evidence.suppressed.load(Ordering::SeqCst)})
        );
        require(
            events.iter().any(|e| e["backend_pid"] == self.journal_pid),
            "wire backend differs from configured journal PID",
        )?;
        require(
            events.iter().any(|e| {
                e["frontend_sql"].as_str().is_some_and(|sql| {
                    sql.contains("TRANSACTION") && sql.contains("READ COMMITTED")
                })
            }),
            "real target journal transaction not observed explicitRC",
        )?;
        let commit = events
            .iter()
            .position(|e| e["frontend_sql"] == "COMMIT")
            .ok_or("no actual target journal COMMIT")?;
        if lost {
            require(
                wire.evidence.suppressed.load(Ordering::SeqCst) == 1
                    && events
                        .iter()
                        .filter(|e| e["backend_command"] == "COMMIT" && e["suppressed"] == true)
                        .count()
                        == 1
                    && !events.iter().any(|e| !e["backend_error"].is_null()),
                "commit response loss not actual one successful COMMIT",
            )
        } else {
            let error = events
                .iter()
                .position(|e| {
                    e["backend_error"]["C"] == "P0001"
                        && e["backend_error"]["M"].as_str().is_some_and(|m| {
                            m.contains("owned journal COMMIT rejection")
                                && m.contains("isolation=read committed")
                        })
                })
                .ok_or("real deferred target COMMIT error missing")?;
            require(
                commit < error
                    && !events.iter().any(|e| e["backend_command"] == "COMMIT")
                    && wire.evidence.suppressed.load(Ordering::SeqCst) == 0,
                "COMMIT rejection confused with successful response loss",
            )
        }
    }
    async fn close(&mut self) -> Result<(), String> {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.journal_pool.close();
        self.pool.close();
        if let Some(proxy) = self.proxy.take() {
            proxy.close().await?;
        }
        self.observer.close().await
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
fn assert_grant(
    snapshot: &Value,
    draft: &ToolDecisionDraft,
    request: &ToolApprovalRequest,
) -> Result<(), String> {
    let approval = one(snapshot, "tool_approvals")?;
    require(
        approval["state"] == "granted"
            && approval["approval_id"] == json!(draft.approval_id)
            && approval["tool_call_id"] == draft.call_id.as_str(),
        "actual grant not linked to original draft",
    )?;
    for (key, expected) in [
        ("actor_id", json!(request.actor.as_str())),
        ("auth_generation", json!(request.auth_generation.get())),
        ("run_id", json!(request.run.as_str())),
        ("thread_id", json!(request.thread.as_str())),
        ("bot_id", json!(request.bot.as_str())),
        ("tool_name", json!(request.tool.as_str())),
        ("args_hash", json!(request.args_hash.to_hex())),
        ("target_kind", json!(request.target.kind)),
        ("target_id", json!(request.target.id)),
        ("effect", json!(request.effect.as_str())),
        ("approval_class", json!(request.approval_class.as_str())),
        (
            "computer_generation",
            json!(request.computer_generation.get()),
        ),
        (
            "catalog_generation",
            json!(request.catalog_generation.get()),
        ),
        ("document_generation", Value::Null),
        ("policy_version", json!(request.policy_version.as_str())),
    ] {
        require(
            approval[key] == expected,
            &format!("real grant binding mismatch {key}"),
        )?;
    }
    let audits = rows(snapshot, "audit_events");
    require(
        audits.len() == 2
            && audits
                .iter()
                .filter(|a| a["event_type"] == "tool.approval_requested")
                .count()
                == 1
            && audits
                .iter()
                .filter(|a| a["event_type"] == "tool.approval_granted")
                .count()
                == 1,
        "actual request/grant audits missing or fabricated decision audit",
    )?;
    require(
        audits.iter().all(|a| {
            a["actor_user_id"] == ACTOR
                && a["target_type"] == "tool_approval"
                && a["target_id"] == approval["approval_id"]
                && a["row_hash"].as_str().is_some_and(|s| s.len() == 64)
        }),
        "grant audit target/hash chain binding changed",
    )
}
fn no_business(snapshot: &Value) -> Result<(), String> {
    for table in [
        "memories",
        "memory_events",
        "user_memory_controls",
        "remember_effect_receipts",
    ] {
        require(
            rows(snapshot, table).is_empty(),
            &format!("firstdecision manufactured {table}"),
        )?;
    }
    Ok(())
}
fn assert_first_counts(f: &Fixture, control: &ApprovedControl) -> Result<(), String> {
    require(
        f.journal.counts()
            == json!({"decision_entries":1,"returned_durable_receipts":0,"attach_entries":0,"outcome_entries":0,"refusal_entries":0})
            && control.executions.load(Ordering::SeqCst) == 0,
        "firstdecision error crossed execution gate or repeated invocation",
    )?;
    require(
        *f.journal.decision_result.lock().expect("owned real error")
            == Some(Err(ToolPortError::Unavailable {
                dependency: "database",
            })),
        "unexpected actual firstdecision journal error",
    )
}
async fn fixture<F, Fut>(tag: &str, phase: Phase, lost: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, tag, phase, lost).await?).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn firstdecision_commit_rejection_keeps_real_grant_and_blocks_execution() {
    fixture(
        "journal_first_reject",
        Phase::Decision,
        false,
        |mut f| async move {
            let result = async {
                let control = f.approved_control()?;
                f.launch(control.clone());
                f.approve(&control).await?;
                let draft = f.journal.draft()?;
                let request = control
                    .request
                    .lock()
                    .expect("owned approval request")
                    .clone()
                    .ok_or("missing real request")?;
                let before = f.observer.snapshot().await?;
                assert_grant(&before, &draft, &request)?;
                no_business(&before)?;
                require(
                    rows(&before, "tool_calls").is_empty()
                        && rows(&before, "tool_attempts").is_empty(),
                    "predecision call already exists",
                )?;
                // INSERT has approval_id=NULL; the original call, not that nullable column, selects the fault.
                let call = draft.call_id.as_str().replace('\'', "''");
                f.trigger("tool_calls", &format!("NEW.tool_call_id='{call}'"))
                    .await?;
                let result = f.finish().await?;
                let after = f.observer.snapshot().await?;
                println!(
                    "JOURNAL_FIRST_REJECTION {}",
                    json!({
                        "before":before, "after":after, "counts":f.journal.counts(),
                        "executor":control.executions.load(Ordering::SeqCst),
                        "application_result":format!("{result:?}")
                    })
                );
                require(
                    result
                        == Err(AppError::DependencyUnavailable {
                            dependency: "database",
                        }),
                    "actual firstdecision rejection not application dependency failure",
                )?;
                assert_first_counts(&f, &control)?;
                require(
                    before == after,
                    "deferred firstdecision COMMIT changed16-table baseline",
                )?;
                f.assert_wire(false)
            }
            .await;
            let closed = f.close().await;
            result.and(closed)
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn firstdecision_commit_response_loss_keeps_real_rows_and_blocks_execution() {
    fixture(
        "journal_first_lost",
        Phase::Decision,
        true,
        |mut f| async move {
            let result = async {
                let control = f.approved_control()?;
                f.launch(control.clone());
                f.approve(&control).await?;
                let draft = f.journal.draft()?;
                let request = control
                    .request
                    .lock()
                    .expect("owned approval request")
                    .clone()
                    .ok_or("missing actual request")?;
                let before = f.observer.snapshot().await?;
                assert_grant(&before, &draft, &request)?;
                require(
                    rows(&before, "tool_calls").is_empty()
                        && rows(&before, "tool_attempts").is_empty(),
                    "predecision call already exists",
                )?;
                let result = f.finish().await?;
                let after = f.observer.snapshot().await?;
                println!(
                    "JOURNAL_FIRST_RESPONSE_LOSS {}",
                    json!({
                        "before":before, "after":after, "counts":f.journal.counts(),
                        "executor":control.executions.load(Ordering::SeqCst),
                        "application_result":format!("{result:?}")
                    })
                );
                require(
                    result
                        == Err(AppError::DependencyUnavailable {
                            dependency: "database",
                        }),
                    "actual lost decision acknowledgement not dependency failure",
                )?;
                assert_first_counts(&f, &control)?;
                unchanged_except(&before, &after, &["tool_calls", "tool_attempts"])?;
                assert_grant(&after, &draft, &request)?;
                assert_binding(&after, &draft)?;
                no_business(&after)?;
                let attempt = one(&after, "tool_attempts")?;
                require(
                    attempt["status"] == "decision_recorded",
                    "lost response must preserve pristine first attempt",
                )?;
                for field in [
                    "capability_id",
                    "commit_state",
                    "output_bytes",
                    "duration_ms",
                    "error_code",
                    "started_at",
                    "finished_at",
                ] {
                    require(
                        attempt[field].is_null(),
                        &format!("unreturned receipt gained attempt field {field}"),
                    )?;
                }
                require(
                    f.observer.snapshot().await? == after,
                    "readonly original firstdecision inspection changed state",
                )?;
                f.assert_wire(true)
            }
            .await;
            let closed = f.close().await;
            result.and(closed)
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn remember_positive_commit_survives_outcome_commit_rejection_and_original_rr() {
    fixture("journal_remember_outcome", Phase::Outcome, false, |mut f| async move {
        let result = async {
            let policy = PolicyStore::postgres(f.pool.clone(), None);
            policy.load().await.map_err(|e| e.to_string())?;
            policy.set(ActionPolicy { mode:PolicyMode::Enforce, deny:vec![],
                allow:vec!["tool.name == \"remember\"".into()] }, Some(ACTOR))
                .await.map_err(|e| e.to_string())?;
            let memory = Arc::new(ForwardMemory {
                inner:PostgresMemoryAdministration::new(f.pool.clone())
                    .with_effect_audit_key(KEY.to_vec()).map_err(|e| e.to_string())?,
                entries:AtomicUsize::new(0), request:Mutex::new(None), effect:Mutex::new(None)
            });
            let control = Arc::new(ForwardBuiltIn {
                inner:PostgresBuiltInToolControlPlane::new(f.pool.clone(),
                    f.begin.deployment.clone(), f.begin.tenant.clone(), policy, memory.clone()),
                executions:AtomicUsize::new(0)
            });
            f.launch(control.clone());
            wait(&f.journal.entered, "positive producer before ordinaryoutcome").await?;
            let draft = f.journal.outcome_draft()?;
            let request = memory.request.lock().expect("owned real private request")
                .clone().ok_or("real producer not reached")?;
            let effect = memory.effect.lock().expect("owned positive memory result")
                .clone().ok_or("actual producer did not commit")?;
            let before = f.observer.snapshot().await?;
            assert_binding(&before, &draft.decision)?;
            let receipt = one(&before, "remember_effect_receipts")?;
            let memory_row = one(&before, "memories")?;
            let event = one(&before, "memory_events")?;
            let attempt = one(&before, "tool_attempts")?;
            require(control.executions.load(Ordering::SeqCst) == 1
                && memory.entries.load(Ordering::SeqCst) == 1
                && f.journal.counts() == json!({"decision_entries":1,
                    "returned_durable_receipts":1,"attach_entries":1,"outcome_entries":1,
                    "refusal_entries":0}), "actual producer pipeline not exactly once")?;
            require(draft.decision.metadata.name.as_str() == "remember"
                && draft.outcome.commit_state == CommitState::Committed
                && draft.outcome.error_code.is_none() && attempt["status"] == "executing"
                && attempt["commit_state"].is_null()
                && attempt["capability_id"] == draft.capability_id.as_str(),
                "pre-outcome original positive/executing facts mismatch")?;
            require(receipt["receipt_id"] == effect.receipt_id
                && receipt["memory_id"] == effect.memory_id
                && memory_row["memory_id"] == effect.memory_id
                && event["memory_id"] == effect.memory_id && event["seq"] == 0
                && receipt["memory_event_seq"] == 0,
                "positive memory/event/receipt identity mismatch")?;
            require(request.call() == &draft.decision.call_id
                && request.attempt() == draft.receipt.attempt()
                && request.decision() == draft.receipt.decision()
                && request.capability() == &draft.capability_id
                && request.args_hash() == &draft.decision.args_hash
                && request.schema_hash() == &draft.decision.metadata.schema_hash
                && request.catalog_generation() == draft.decision.metadata.catalog_generation
                && request.target() == &draft.decision.target,
                "actual private execution envelope changed journal binding")?;
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
                ("schema_hash", json!(draft.decision.metadata.schema_hash.to_hex())),
                ("catalog_generation", json!(draft.decision.metadata.catalog_generation.get())),
                ("target_kind", json!(draft.decision.target.kind)),
                ("target_id", json!(draft.decision.target.id))
            ] {
                require(receipt[key] == expected,
                    &format!("actual businessreceipt binding mismatch {key}"))?;
            }
            let audits = rows(&before, "audit_events");
            require(audits.len() == 1 && audits[0]["event_type"] == "memory.effect_committed"
                && audits[0]["id"] == receipt["audit_event_id"]
                && audits[0]["target_type"] == "memory_effect_receipt"
                && audits[0]["target_id"] == receipt["receipt_id"]
                && audits[0]["payload"]["decision_id"] == receipt["decision_id"],
                "special positive commit audit missing")?;
            // This real ordinary audit uses decision_id. The earlier business audit stays untouched.
            let decision = draft.receipt.decision().as_str().replace('\'', "''");
            f.trigger("audit_events", &format!(
                "NEW.event_type='memory.remember_succeeded' AND NEW.payload->>'decision_id'='{decision}'"
            )).await?;
            let result = f.finish().await?;
            let after = f.observer.snapshot().await?;
            println!("JOURNAL_POSITIVE_OUTCOME_REJECTION {}", json!({
                "before":before,"after":after,"counts":f.journal.counts(),
                "executor":control.executions.load(Ordering::SeqCst),
                "actual_memory_producer":memory.entries.load(Ordering::SeqCst),
                "receipt":effect.receipt_id,"application_result":format!("{result:?}")
            }));
            require(result == Err(AppError::ReconciliationRequired { accepted:false }),
                "ordinary COMMIT failure did not preserve unaccepted reconciliation")?;
            require(*f.journal.outcome_result.lock().expect("owned real outcome error")
                == Some(Err(ToolPortError::Unavailable { dependency:"database" })),
                "ordinary outcome did not reach actual DB failure")?;
            require(before == after,
                "ordinary outcome/audit/checkpoint COMMIT did not fully rollback16 tables")?;
            require(control.executions.load(Ordering::SeqCst) == 1
                && memory.entries.load(Ordering::SeqCst) == 1,
                "executor/business effect automatically repeated")?;
            f.assert_wire(false)?;
            // Running was required by the specialized outcome guard. Only now commit actual RR.
            let terminal = f.runtime.finish_run(&f.lease, f.lease.next_event_sequence(),
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown))
                .await.map_err(|e| e.to_string())?;
            require(!terminal.replayed && terminal.message_sequence.is_none(),
                "RR terminal must be a separate actual first commit without an assistant message")?;
            let rr = f.observer.snapshot().await?;
            unchanged_except(&after, &rr, &["runs","threads","thread_leases","run_events"])?;
            for (table, mutable) in [
                ("runs", &["status","next_event_seq","terminal_event_seq","error_code","finished_at"][..]),
                ("threads", &["next_event_seq","updated_at"][..]),
                ("thread_leases", &["expires_at","updated_at"][..])
            ] {
                let mut stable_before = one(&after, table)?.as_object()
                    .ok_or("original RR row must be an object")?.clone();
                let mut stable_after = one(&rr, table)?.as_object()
                    .ok_or("released RR row must be an object")?.clone();
                for field in ["_xmin","_ctid"].into_iter().chain(mutable.iter().copied()) {
                    stable_before.remove(field);
                    stable_after.remove(field);
                }
                require(stable_before == stable_after,
                    &format!("RR changed stable original {table} columns"))?;
            }
            let run = one(&rr, "runs")?;
            let old_thread = one(&after, "threads")?;
            let thread = one(&rr, "threads")?;
            let old_thread_next = old_thread["next_event_seq"].as_u64()
                .ok_or("original thread event sequence missing")?;
            let next_thread = old_thread_next.checked_add(1)
                .ok_or("original thread event sequence overflow")?;
            let next_run = terminal.run_event_sequence.checked_add(1)
                .ok_or("original run event sequence overflow")?;
            require(run["run_id"] == f.begin.command.run_id.as_str()
                && run["status"] == "reconciliation_required"
                && run["error_code"] == "journal_commit_unknown"
                && run["terminal_event_seq"] == terminal.run_event_sequence
                && run["next_event_seq"] == next_run
                && thread["next_event_seq"] == next_thread
                && rr["thread_run_occupancy"] == after["thread_run_occupancy"],
                "actual RR replaced original Unknown/occupancy")?;
            let old_events = rows(&after, "run_events");
            let events = rows(&rr, "run_events");
            let terminal_events = events.iter().filter(|event| event["terminal"] == true)
                .collect::<Vec<_>>();
            require(events.len() == old_events.len() + 1 && old_events.iter().all(|old| events.contains(old))
                && terminal_events.len() == 1
                && terminal_events[0]["run_id"] == f.begin.command.run_id.as_str()
                && terminal_events[0]["thread_id"] == f.begin.command.thread_id.as_str()
                && terminal_events[0]["seq"] == terminal.run_event_sequence
                && terminal_events[0]["event_seq"] == old_thread_next
                && terminal_events[0]["event_type"] == "reconciliation_required"
                && terminal_events[0]["payload"] == json!({"status":"reconciliation_required","errorCode":"journal_commit_unknown"}),
                "RR did not append exactly one original terminal while preserving prior events")?;
            let old_lease = one(&after, "thread_leases")?;
            let released = one(&rr, "thread_leases")?;
            for field in ["thread_id","owner_id","fencing_token","acquired_at"] {
                require(old_lease[field] == released[field],
                    "actual RR changed or deleted original lease identity")?;
            }
            require(released["expires_at"] == released["updated_at"]
                && run["finished_at"] == thread["updated_at"]
                && thread["updated_at"] == released["updated_at"]
                && run["finished_at"] == terminal_events[0]["created_at"]
                && released["updated_at"] != old_lease["updated_at"],
                "actual RR finish/thread/terminal/retained-lease release time diverged")?;
            let query = RunReconciliationRequest {
                deployment:f.begin.deployment.clone(),tenant:f.begin.tenant.clone(),
                actor:f.begin.actor.clone(),auth_generation:f.begin.auth_generation,
                thread:f.begin.command.thread_id.clone(),run:f.begin.command.run_id.clone(),
                after:None,limit:50
            };
            let facts = f.directory.run_reconciliation(query.clone()).await
                .map_err(|e| e.to_string())?;
            let positive = f.directory.run_effect_receipts(query).await.map_err(|e| e.to_string())?;
            require(facts.status == RunReconciliationStatus::ReconciliationRequired
                && facts.run_id == f.begin.command.run_id
                && facts.thread_id == f.begin.command.thread_id
                && facts.terminal_event_sequence == terminal.run_event_sequence
                && facts.foreground_blocked && facts.available_actions.is_empty()
                && facts.attempts.len() == 1
                && facts.attempts[0].status == RunReconciliationAttemptStatus::Executing
                && facts.attempts[0].recorded_commit_state.is_none(),
                "074 lost original unresolved attempt facts")?;
            require(positive.receipts.len() == 1 && positive.receipts[0].receipt_id == effect.receipt_id
                && positive.receipts[0].fact == RunEffectReceiptFact::MemoryCreated
                && positive.run_id == facts.run_id && positive.thread_id == facts.thread_id
                && positive.terminal_event_sequence == facts.terminal_event_sequence
                && positive.foreground_blocked && positive.available_actions.is_empty(),
                "075 lost positive businessfact or granted continuation")?;
            require(f.observer.snapshot().await? == rr,
                "actual original074/075 read changed durable state")?;
            println!("JOURNAL_SEPARATE_RR_READ {}", json!({
                "before_terminal":after,"actual_terminal":rr,"074":facts,"075":positive,
                "positive_business_commit_is_not_rewritten":true
            }));
            Ok(())
        }.await;
        let closed = f.close().await;
        result.and(closed)
    }).await;
}
