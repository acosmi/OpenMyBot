use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use openbot_application::{
    AuthorizedToolCall, BeginThreadRunRequest, ResolvedToolScope, RunExecutionLease, RunRuntime,
    ThreadDirectory, ToolApprovalRequest, ToolControlPlane, ToolDecisionDraft, ToolExecutionReport,
    ToolJournal, ToolOutcomeDraft, ToolPolicyEvaluation, ToolPortError, ToolRefusalDraft,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{
    ActorId, BotId, CapabilityId, CatalogGeneration, ComputerGeneration, DeploymentId, RunId,
    TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::tool::ToolInvocation;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::policy::context::{ActorRef, BotRef, PageRef, PolicyContext, ToolRef};
use openbot_domain::policy::{ActionPolicy, CompiledActionPolicy, PolicyMode, evaluate};
use openbot_domain::tool::approval::ApprovalTarget;
use openbot_domain::tool::args::ToolArguments;
use openbot_domain::tool::commit::CommitState;
use openbot_domain::tool::metadata::{
    ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    ToolMetadata, ToolName,
};
use openbot_domain::tool::pipeline::{ApprovalOutcome, DurableDecisionReceipt};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::PostgresThreadDirectory;
use serde_json::{Value, json};
use tokio::sync::{Notify, Semaphore};

const OWNER: &str = "journal-journey-original-worker";
const LEASE_DURATION: time::Duration = time::Duration::seconds(120);
const AUDIT_KEY: &[u8] = b"synthetic-v6-pr-076-journal-journey-audit-key";

pub struct Fixture {
    pub pool: openbot_infra::db::pool::DatabasePool,
    pub runtime: Arc<PostgresRunRuntime>,
    pub lease: RunExecutionLease,
    pub request: BeginThreadRunRequest,
    config: DatabaseConfig,
}

impl Fixture {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, String> {
        let pool = pool::connect(config)
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
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email) VALUES('actor-a','a@example.test');
                 INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user');
                 INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('bot-1','Journey bot','built_in','{}'::jsonb);
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                 ) VALUES('bot-1',NULL,'Journey bot','Synthetic journey','seed','public',NULL);",
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        let deployment = DeploymentId::new("dep-journal-journey");
        let request = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment: deployment.clone(),
            tenant: TenantId::new("tenant-journey"),
            actor: ActorId::new("actor-a"),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                model_selection: None,
                selected_skill_slugs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([76_u8; 16]),
                run_id: RunId::new("run-journal-original"),
                bot_id: BotId::new("bot-1"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "synthetic terminal fence journey".to_owned(),
            },
        };
        let directory = directory(&pool, config, OWNER)?;
        directory
            .begin_thread_run(request.clone())
            .await
            .map_err(|error| error.to_string())?;
        let runtime = Arc::new(runtime(&pool, OWNER)?);
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("original run was not claimable")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        if lease.run_id() != &request.command.run_id || lease.next_event_sequence() != 1 {
            return Err("real dispatch did not yield the original running lease".to_owned());
        }
        Ok(Self {
            pool,
            runtime,
            lease,
            request,
            config: config.clone(),
        })
    }

    pub fn auth(&self) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            self.request.deployment.clone(),
            self.request.tenant.clone(),
            self.request.actor.clone(),
            self.request.auth_generation,
            false,
        )
        .with_role(Role::User)
        .build()
    }

    pub fn invocation(&self) -> ToolInvocation {
        ToolInvocation {
            call_id: ToolCallId::new("call-journal-original"),
            run_id: self.request.command.run_id.clone(),
            bot_id: self.request.command.bot_id.clone(),
            call_seq: 0,
            tool_name: "computer.write".to_owned(),
            arguments: json!({"message":"hello"}),
        }
    }

    pub fn control(&self) -> CountingControl {
        CountingControl {
            thread_id: self.lease.thread_id().clone(),
            executions: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn journal(&self, stage: Stage) -> Result<PausingJournal, String> {
        Ok(PausingJournal {
            inner: PostgresToolJournal::new(self.pool.clone(), AUDIT_KEY)
                .map_err(|error| error.to_string())?,
            stage,
            gate: Arc::new(Gate {
                entered: Notify::new(),
                resume: Semaphore::new(0),
                last_result: Mutex::new(None),
            }),
        })
    }

    pub fn fresh_directory(&self) -> Result<PostgresThreadDirectory, String> {
        directory(&self.pool, &self.config, "journal-journey-new-worker")
    }

    pub fn fresh_runtime(&self) -> Result<PostgresRunRuntime, String> {
        runtime(&self.pool, "journal-journey-new-worker")
    }

    // A separate production adapter instance commits terminal using the original, real lease.
    pub fn terminal_writer(&self) -> Result<PostgresRunRuntime, String> {
        runtime(&self.pool, OWNER)
    }

    pub fn successor_request(&self) -> BeginThreadRunRequest {
        let mut request = self.request.clone();
        request.command.run_id = RunId::new("run-journal-successor");
        request.command.message = "new legitimate foreground run".to_owned();
        request
    }

    pub async fn begin_successor(&self) -> Result<RunExecutionLease, String> {
        let request = self.successor_request();
        self.fresh_directory()?
            .begin_thread_run(request.clone())
            .await
            .map_err(|error| error.to_string())?;
        let runtime = self.fresh_runtime()?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("successor run was not claimable")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        if lease.run_id() != &request.command.run_id || lease.fencing() == self.lease.fencing() {
            return Err("successor did not receive its own new fenced lease".to_owned());
        }
        runtime
            .renew_lease(&lease)
            .await
            .map_err(|error| error.to_string())?;
        Ok(lease)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.pool.close();
    }
}

fn directory(
    pool: &openbot_infra::db::pool::DatabasePool,
    config: &DatabaseConfig,
    owner: &str,
) -> Result<PostgresThreadDirectory, String> {
    PostgresThreadDirectory::with_runtime(
        pool.clone(),
        config.clone(),
        owner.to_owned(),
        LEASE_DURATION,
    )
    .map_err(|error| error.to_string())
}

fn runtime(
    pool: &openbot_infra::db::pool::DatabasePool,
    owner: &str,
) -> Result<PostgresRunRuntime, String> {
    PostgresRunRuntime::new(
        pool.clone(),
        owner.to_owned(),
        LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Decision,
    Attach,
    Outcome,
}

pub struct Gate {
    pub entered: Notify,
    pub resume: Semaphore,
    pub last_result: Mutex<Option<Result<(), ToolPortError>>>,
}

#[derive(Clone)]
pub struct PausingJournal {
    inner: PostgresToolJournal,
    stage: Stage,
    pub gate: Arc<Gate>,
}

impl PausingJournal {
    async fn pause(&self, stage: Stage) {
        if self.stage == stage {
            self.gate.entered.notify_one();
            self.gate
                .resume
                .acquire()
                .await
                .expect("test gate remains open")
                .forget();
        }
    }

    fn observe(&self, stage: Stage, result: Result<(), ToolPortError>) {
        if self.stage == stage {
            *self
                .gate
                .last_result
                .lock()
                .expect("journal observation lock") = Some(result);
        }
    }
}

#[async_trait]
impl ToolJournal for PausingJournal {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.inner.record_refusal(draft).await
    }

    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.pause(Stage::Decision).await;
        let result = self.inner.record_decision(draft).await;
        self.observe(
            Stage::Decision,
            result.as_ref().map(|_| ()).map_err(|error| *error),
        );
        result
    }

    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.pause(Stage::Attach).await;
        let result = self.inner.attach_capability(call, capability).await;
        self.observe(Stage::Attach, result);
        result
    }

    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        self.pause(Stage::Outcome).await;
        let result = self.inner.record_outcome(draft).await;
        self.observe(Stage::Outcome, result);
        result
    }
}

#[derive(Clone)]
pub struct CountingControl {
    thread_id: ThreadId,
    executions: Arc<AtomicUsize>,
}

impl CountingControl {
    pub fn executions(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ToolControlPlane for CountingControl {
    async fn metadata(&self, name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        if name.as_str() != "computer.write" {
            return Err(ToolPortError::InvalidInput { field: "tool_name" });
        }
        Ok(ToolMetadata {
            name: ToolName::new("computer.write").expect("static valid tool name"),
            schema_hash: Sha256Digest::of(b"synthetic-journey-schema"),
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
        })
    }

    async fn resolve_scope(
        &self,
        auth: &AuthContext,
        invocation: &ToolInvocation,
        _arguments: &ToolArguments,
        _metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        Ok(ResolvedToolScope {
            tenant_id: auth.tenant().clone(),
            run_id: invocation.run_id.clone(),
            thread_id: self.thread_id.clone(),
            bot_id: invocation.bot_id.clone(),
            call_seq: invocation.call_seq,
            target: ApprovalTarget {
                kind: "computer",
                id: "synthetic-computer".to_owned(),
            },
            computer_generation: ComputerGeneration::new(1),
            target_document_generation: None,
            approval_presentation: None,
            policy_context: PolicyContext {
                tool: ToolRef {
                    name: invocation.tool_name.clone(),
                },
                bot: BotRef {
                    id: invocation.bot_id.as_str().to_owned(),
                },
                page: PageRef {
                    url: "https://example.test/".to_owned(),
                    host: "example.test".to_owned(),
                },
                actor: ActorRef {
                    id: auth.actor().as_str().to_owned(),
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
            deny: Vec::new(),
            allow: vec!["true".to_owned()],
        });
        Ok(ToolPolicyEvaluation::from_domain(&evaluate(
            &policy, context,
        )))
    }

    async fn approval(
        &self,
        _request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        Err(ToolPortError::Corrupt {
            field: "unexpected_approval_lookup",
        })
    }

    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        let (call, redeemed) = call.redeem();
        assert_eq!(call.arguments().as_value(), &json!({"message":"hello"}));
        // This increment is the synthetic executor's effect, not a claim about an external vendor.
        self.executions.fetch_add(1, Ordering::SeqCst);
        ToolExecutionReport::new(
            redeemed,
            "redacted-result".to_owned(),
            CommitState::Committed,
            Duration::from_millis(1),
            None,
        )
    }
}

pub async fn wait_for(notification: &Notify) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), notification.notified())
        .await
        .map_err(|_| "timed out waiting for the deterministic journey barrier".to_owned())
}

/// One statement observes all rows, including xmin/ctid, so an otherwise invisible UPDATE fails
/// the equality check. Only synthetic rows in this test's isolated database are inspected.
pub async fn snapshot(pool: &openbot_infra::db::pool::DatabasePool) -> Result<Value, String> {
    let tables = [
        "runs",
        "threads",
        "thread_memberships",
        "thread_leases",
        "run_events",
        "messages",
        "outbox",
        "tool_calls",
        "tool_attempts",
        "remember_effect_receipts",
        "audit_events",
        "audit_checkpoints",
    ];
    let fields: Vec<String> = tables.iter().map(|table| format!(
        "'{table}',(SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(t),'xmin',t.xmin::text,'ctid',t.ctid::text) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.{table} t)"
    )).collect();
    let sql = format!("SELECT jsonb_build_object({})", fields.join(","));
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(&sql, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}
