//! Production RunRelay + built-in host + PostgreSQL context/journal 的 text provider 竖切。

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_agent::{
    AgentToolInvoker, AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime,
    NoAgentToolInvoker, ProviderRouter, RemoteAguiProvider, RetryingProvider,
    RetryingProviderConfig,
};
use openbot_application::{
    AppEventStream, ApplicationService, BeginThreadRunRequest, CancelThreadRunRequest,
    ComponentAdministration, MemoryAdministrationError, OpenBotApplication, ProviderAdapter,
    ProviderEvent, ProviderMessage, ProviderPortError, ProviderRequest, ProviderSession,
    ProviderUsage, RememberToolMemory, RememberToolMemoryRequest, RemoteInterruptCoordinator,
    RunExecutionLease, RunRuntime, RunToolExchange, ThreadDirectory, remember_provider_tool,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{
    AppCommand, AppReply, BeginThreadRun, CancelThreadRun, SubscriptionRequest, ThreadRunAnchor,
    ThreadRunCancellationState,
};
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ComponentApprovalAnswer, ComponentApprovalDecision,
    ComponentHumanDecisionAnswer, SHOW_NOTICE_COMPONENT_NAME, SHOW_QUOTE_COMPONENT_NAME,
    compiled_component_manifest,
};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_contracts::remote_interrupt::{RemoteInterruptAnswer, RemoteInterruptAnswerStatus};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::{RemoteRunAssertionSigner, RemoteToolSet};
use openbot_domain::thread::FencingToken;
use openbot_domain::vault::{KeyVersion, SecretBytes, SecretKind, SecretPrincipal, WrappingKey};
use openbot_infra::agent_audit::PostgresAgentAudit;
use openbot_infra::agent_tools::{
    PostgresAgentAuthorizationSource, PostgresBuiltInToolControlPlane,
};
use openbot_infra::component_catalogue::PostgresComponentAdministration;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::anthropic::{
    AnthropicApiKey, AnthropicProvider, AnthropicProviderConfig,
};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::google::{GoogleApiKey, GoogleProvider, GoogleProviderConfig};
use openbot_infra::provider::openai::{
    OpenAiApiKey, OpenAiCredentialError, OpenAiCredentialSource, OpenAiProtocol, OpenAiProvider,
    OpenAiProviderConfig,
};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use openbot_infra::remote_interrupt::PostgresRemoteInterruptCoordinator;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::vault::CredentialRecordVault;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Barrier, oneshot};
use url::Url;
use uuid::Uuid;

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
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
             INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
               VALUES('tenant-a','/fixture',repeat('a',64));
             INSERT INTO public.agents(id,name,type,configuration,package_id)
               SELECT 'bot-1','Bot 1','built_in',
                      jsonb_build_object('systemPrompt','Test system role.'),id
               FROM public.deployment_packages WHERE tenant_id='tenant-a';
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[derive(Default)]
struct RecordedProvider {
    requests: Mutex<Vec<ProviderRequest>>,
}

#[async_trait]
impl ProviderAdapter for RecordedProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.requests.lock().expect("provider lock").push(request);
        Ok(Box::new(RecordedSession {
            events: vec![
                ProviderEvent::ResponseStarted {
                    response_id: "response-local".to_owned(),
                },
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "provider says hi".to_owned(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 2,
                    output_tokens: 3,
                    total_tokens: 5,
                }),
                ProviderEvent::Completed,
            ]
            .into(),
        }))
    }
}

struct RecordedSession {
    events: VecDeque<ProviderEvent>,
}

#[derive(Default)]
struct ParallelComponentProvider {
    requests: Mutex<Vec<ProviderRequest>>,
}

#[async_trait]
impl ProviderAdapter for ParallelComponentProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let turn = {
            let mut requests = self.requests.lock().expect("parallel provider lock");
            let turn = requests.len();
            requests.push(request);
            turn
        };
        let events = match turn {
            0 => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 1,
                    call_id: "provider-notice".to_owned(),
                    name: SHOW_NOTICE_COMPONENT_NAME.to_owned(),
                    arguments: serde_json::json!({
                        "title":"Status",
                        "body":"Both views are ready.",
                        "tone":"positive"
                    }),
                },
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-quote".to_owned(),
                    name: SHOW_QUOTE_COMPONENT_NAME.to_owned(),
                    arguments: serde_json::json!({
                        "quote":"Concurrency is bounded.",
                        "attribution":"runtime proof"
                    }),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 4,
                    output_tokens: 4,
                    total_tokens: 8,
                }),
                ProviderEvent::Completed,
            ],
            1 => vec![
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "parallel components complete".to_owned(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 4,
                    output_tokens: 2,
                    total_tokens: 6,
                }),
                ProviderEvent::Completed,
            ],
            _ => {
                return Err(ProviderPortError::InvalidRequest {
                    field: "parallel_component_turn_count",
                });
            }
        };
        Ok(Box::new(RecordedSession {
            events: events.into(),
        }))
    }
}

struct ConcurrentComponentApplication {
    inner: Arc<dyn ApplicationService>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    barrier: Barrier,
}

impl ConcurrentComponentApplication {
    fn new(inner: Arc<dyn ApplicationService>) -> Self {
        Self {
            inner,
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            barrier: Barrier::new(2),
        }
    }
}

#[async_trait]
impl ApplicationService for ConcurrentComponentApplication {
    async fn execute(
        &self,
        auth: openbot_contracts::auth::AuthContext,
        command: AppCommand,
    ) -> Result<AppReply, openbot_contracts::error::AppError> {
        let component_decision = matches!(&command, AppCommand::DecideComponent { .. });
        if component_decision {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            self.barrier.wait().await;
        }
        let result = self.inner.execute(auth, command).await;
        if component_decision {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
        result
    }

    async fn subscribe(
        &self,
        auth: openbot_contracts::auth::AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, openbot_contracts::error::AppError> {
        self.inner.subscribe(auth, request).await
    }
}

#[derive(Default)]
struct DecisionLoopProvider {
    requests: Mutex<Vec<ProviderRequest>>,
}

#[async_trait]
impl ProviderAdapter for DecisionLoopProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let turn = {
            let mut requests = self.requests.lock().expect("decision provider lock");
            let turn = requests.len();
            requests.push(request);
            turn
        };
        let events = match turn {
            0 => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-approval-1".to_owned(),
                    name: ASK_APPROVAL_COMPONENT_NAME.to_owned(),
                    arguments: serde_json::json!({
                        "title":"Refund this order?",
                        "summary":"The charge was duplicated.",
                        "details":[{"label":"Amount","value":"$128.40"}]
                    }),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 5,
                    output_tokens: 3,
                    total_tokens: 8,
                }),
                ProviderEvent::Completed,
            ],
            1 => vec![
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "The refund was approved.".to_owned(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 9,
                    output_tokens: 4,
                    total_tokens: 13,
                }),
                ProviderEvent::Completed,
            ],
            _ => {
                return Err(ProviderPortError::InvalidRequest {
                    field: "decision_turn_count",
                });
            }
        };
        Ok(Box::new(RecordedSession {
            events: events.into(),
        }))
    }
}

#[derive(Default)]
struct RememberLoopProvider {
    requests: Mutex<Vec<ProviderRequest>>,
}

struct RevokeBeforeSecondRemember {
    inner: PostgresMemoryAdministration,
    pool: openbot_infra::db::pool::DatabasePool,
    policy: PolicyStore,
    calls: AtomicUsize,
}

#[async_trait]
impl RememberToolMemory for RevokeBeforeSecondRemember {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<openbot_application::CommittedMemoryEffect, MemoryAdministrationError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.pool
                .get()
                .await
                .map_err(|_| MemoryAdministrationError::Unavailable)?
                .execute(
                    "UPDATE public.users SET auth_generation=coalesce(auth_generation,0)+1 \
                     WHERE id='actor-a'",
                    &[],
                )
                .await
                .map_err(|_| MemoryAdministrationError::Unavailable)?;
            self.policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: vec![r#"tool.name == "remember""#.to_owned()],
                        allow: Vec::new(),
                    },
                    Some("actor-a"),
                )
                .await
                .map_err(|_| MemoryAdministrationError::Unavailable)?;
        }
        self.inner.remember_from_tool(request).await
    }
}

#[async_trait]
impl ProviderAdapter for RememberLoopProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let turn = {
            let mut requests = self.requests.lock().expect("remember provider lock");
            let turn = requests.len();
            requests.push(request);
            turn
        };
        let events = match turn {
            0 => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-remember-1".to_owned(),
                    name: "remember".to_owned(),
                    arguments: serde_json::json!({
                        "memoryKind":"fact",
                        "scope":"thread",
                        "content":"The user prefers tea.",
                        "tags":["drink"],
                        "sensitivity":"normal"
                    }),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 5,
                    output_tokens: 3,
                    total_tokens: 8,
                }),
                ProviderEvent::Completed,
            ],
            1 => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-remember-2".to_owned(),
                    name: "remember".to_owned(),
                    arguments: serde_json::json!({
                        "memoryKind":"preference",
                        "scope":"user",
                        "content":"The user prefers coffee.",
                        "tags":["drink"],
                        "sensitivity":"normal"
                    }),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 9,
                    output_tokens: 3,
                    total_tokens: 12,
                }),
                ProviderEvent::Completed,
            ],
            2 => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-remember-3".to_owned(),
                    name: "remember".to_owned(),
                    arguments: serde_json::json!({
                        "memoryKind":"preference",
                        "scope":"user",
                        "content":"The user prefers water.",
                        "tags":["drink"],
                        "sensitivity":"normal"
                    }),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 13,
                    output_tokens: 3,
                    total_tokens: 16,
                }),
                ProviderEvent::Completed,
            ],
            3 => vec![
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "I remembered that.".to_owned(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 17,
                    output_tokens: 4,
                    total_tokens: 21,
                }),
                ProviderEvent::Completed,
            ],
            _ => {
                return Err(ProviderPortError::InvalidRequest {
                    field: "remember_turn_count",
                });
            }
        };
        Ok(Box::new(RecordedSession {
            events: events.into(),
        }))
    }
}

#[derive(Default)]
struct RejectingPackageProvider {
    calls: std::sync::atomic::AtomicUsize,
}

struct HoldingAgentContext;

struct CancellationHoldingContext {
    dropped: Arc<AtomicBool>,
}

struct ContextDropProbe(Arc<AtomicBool>);

impl Drop for ContextDropProbe {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl openbot_application::AgentContextSource for CancellationHoldingContext {
    async fn load(
        &self,
        _lease: &openbot_application::RunExecutionLease,
    ) -> Result<ProviderRequest, openbot_application::AgentContextError> {
        let _probe = ContextDropProbe(self.dropped.clone());
        std::future::pending().await
    }
}

#[async_trait]
impl openbot_application::AgentContextSource for HoldingAgentContext {
    async fn load(
        &self,
        _lease: &openbot_application::RunExecutionLease,
    ) -> Result<ProviderRequest, openbot_application::AgentContextError> {
        std::future::pending().await
    }
}

#[async_trait]
impl ProviderAdapter for RejectingPackageProvider {
    async fn start(
        &self,
        _request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ProviderPortError::InvalidRequest {
            field: "wrong_package_route",
        })
    }
}

#[async_trait]
impl ProviderSession for RecordedSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.events.pop_front())
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn provider_delta_flows_through_agent_host_into_replay_history_and_terminal() {
    let admin = batch6_admin_config(
        "provider_delta_flows_through_agent_host_into_replay_history_and_terminal",
    );
    with_temp_database(&admin, "agentruntime", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let owner = "runtime-agent-a".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(32),
                )
                .map_err(|error| error.to_string())?,
            );
            let provider = Arc::new(RecordedProvider::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider.clone(),
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 2,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime.clone(), agent.consumer());
            let mut entropy = [0_u8; 16];
            entropy[15] = 1;
            let thread = ThreadIdentity::new(&deployment).mint_from_entropy(entropy);
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: deployment.clone(),
                    tenant,
                    actor: ActorId::new("actor-a"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: thread.clone(),
                        run_id: RunId::new("run-agent-1"),
                        bot_id: BotId::new("bot-1"),
                        anchor: ThreadRunAnchor::DirectBot,
                        message: "hello provider".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;

            let mut final_shape = None;
            for _ in 0..100 {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let row = client
                    .query_one(
                        "SELECT r.status,r.error_code,o.status,
                                (SELECT count(*)::bigint FROM public.run_events e
                                 WHERE e.run_id=r.run_id),
                                (SELECT content->>'text' FROM public.messages m
                                 WHERE m.run_id=r.run_id AND m.role='assistant')
                         FROM public.runs r JOIN public.outbox o
                           ON o.outbox_id=r.run_id || ':agent_run_dispatch'
                         WHERE r.run_id='run-agent-1'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let shape: (String, Option<String>, String, i64, Option<String>) = (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                    row.try_get(2).map_err(|error| error.to_string())?,
                    row.try_get(3).map_err(|error| error.to_string())?,
                    row.try_get(4).map_err(|error| error.to_string())?,
                );
                if shape.0 != "running" {
                    final_shape = Some(shape);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            relay.stop().await;
            agent.stop().await;
            if final_shape
                != Some((
                    "completed".to_owned(),
                    None,
                    "delivered".to_owned(),
                    3,
                    Some("provider says hi".to_owned()),
                ))
            {
                return Err(format!("agent PG terminal shape 漂移：{final_shape:?}"));
            }
            let requests = provider.requests.lock().expect("provider lock").clone();
            if requests.len() != 1
                || requests[0].messages.len() != 2
                || requests[0].messages[0].role != openbot_application::ProviderMessageRole::System
                || requests[0].messages[0].tool_call_id.is_some()
                || !requests[0].messages[0]
                    .content
                    .starts_with("Test system role.\n\nSay where an answer came from.")
                || requests[0].messages[1]
                    != (ProviderMessage {
                        role: openbot_application::ProviderMessageRole::User,
                        content: "hello provider".to_owned(),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: Vec::new(),
                    })
            {
                return Err(format!("provider context projection 漂移：{requests:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let invoked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events \
                     WHERE event_type='agent.invoked' AND target_id='run-agent-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if invoked != 1 {
                return Err(format!("agent.invoked audit 漂移：{invoked}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn parallel_safe_components_share_budget_and_persist_provider_order_on_real_postgres() {
    let admin = batch6_admin_config(
        "parallel_safe_components_share_budget_and_persist_provider_order_on_real_postgres",
    );
    with_temp_database(&admin, "agentparallel", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let auth = AuthContextBuilder::from_verified_session(
                deployment.clone(),
                tenant.clone(),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User])
            .build();
            let components = Arc::new(
                PostgresComponentAdministration::new(pool.clone(), vec![0xda; 32])
                    .map_err(|error| error.to_string())?,
            );
            components
                .sync_catalogue(&auth, &compiled_component_manifest())
                .await
                .map_err(|error| error.to_string())?;
            let owner = "runtime-parallel".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let inner: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_component_administration(components.clone()),
            );
            let observed = Arc::new(ConcurrentComponentApplication::new(inner));
            let application: Arc<dyn ApplicationService> = observed.clone();
            let tools: Arc<dyn AgentToolInvoker> = Arc::new(AuthorizedAgentToolGateway::new(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                )),
            ));
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?
                .with_components(components),
            );
            let provider = Arc::new(ParallelComponentProvider::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider.clone(),
                tools,
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xda; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(10)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime, agent.consumer());
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                9,
                "run-parallel-components",
                "Show two components.",
            )
            .await?;
            wait_for_terminal(
                &pool,
                "run-parallel-components",
                "parallel components complete",
            )
            .await?;

            if observed.max_active.load(Ordering::SeqCst) != 2
                || observed.active.load(Ordering::SeqCst) != 0
            {
                return Err(format!(
                    "component concurrency drift: active={} max={}",
                    observed.active.load(Ordering::SeqCst),
                    observed.max_active.load(Ordering::SeqCst)
                ));
            }
            let requests = provider.requests.lock().unwrap().clone();
            if requests.len() != 2 {
                return Err(format!(
                    "parallel provider request count drift: {requests:?}"
                ));
            }
            let tool_ids = requests[1]
                .messages
                .iter()
                .filter(|message| message.role == openbot_application::ProviderMessageRole::Tool)
                .filter_map(|message| message.tool_call_id.as_deref())
                .collect::<Vec<_>>();
            if tool_ids != ["provider-quote", "provider-notice"] {
                return Err(format!("provider tool result order drift: {tool_ids:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query(
                    "SELECT content->>'toolCallId' AS provider_call_id
                       FROM public.messages
                      WHERE run_id='run-parallel-components' AND role='tool'
                      ORDER BY seq",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let durable_ids = rows
                .iter()
                .map(|row| {
                    row.try_get::<_, String>(0)
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if durable_ids != ["provider-quote", "provider-notice"] {
                return Err(format!("durable tool result order drift: {durable_ids:?}"));
            }
            relay.stop().await;
            agent.stop().await;
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn component_decision_suspends_cross_replica_answer_then_commits_exchange_before_resample() {
    let admin = batch6_admin_config(
        "component_decision_suspends_cross_replica_answer_then_commits_exchange_before_resample",
    );
    with_temp_database(&admin, "agentdecision", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let auth = AuthContextBuilder::from_verified_session(
                deployment.clone(),
                tenant.clone(),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User])
            .build();
            let components = Arc::new(
                PostgresComponentAdministration::new(pool.clone(), vec![0xd8; 32])
                    .map_err(|error| error.to_string())?,
            );
            components
                .sync_catalogue(&auth, &compiled_component_manifest())
                .await
                .map_err(|error| error.to_string())?;
            let owner = "runtime-decision".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_component_administration(components.clone()),
            );
            let tools: Arc<dyn AgentToolInvoker> = Arc::new(AuthorizedAgentToolGateway::new(
                application.clone(),
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                )),
            ));
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?
                .with_components(components),
            );
            let provider = Arc::new(DecisionLoopProvider::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider.clone(),
                tools,
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xd8; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(10)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime, agent.consumer());
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                10,
                "run-decision",
                "Ask before refunding.",
            )
            .await?;

            let mut pending = None;
            for _ in 0..120 {
                match application
                    .execute(auth.clone(), AppCommand::ListPendingComponentHumanDecisions)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    AppReply::PendingComponentHumanDecisions(page) if page.decisions.len() == 1 => {
                        pending = page.decisions.into_iter().next();
                        break;
                    }
                    AppReply::PendingComponentHumanDecisions(_) => {}
                    reply => return Err(format!("pending decision reply drift: {reply:?}")),
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let pending = pending.ok_or_else(|| "decision never became pending".to_owned())?;
            if pending.run_id.as_str() != "run-decision"
                || pending.provider_call_id != "provider-approval-1"
                || pending.component_name != ASK_APPROVAL_COMPONENT_NAME
                || provider.requests.lock().unwrap().len() != 1
            {
                return Err(format!("pending decision/provider drift: {pending:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let before: (String, i64) = {
                let row = client
                    .query_one(
                        "SELECT status,(SELECT count(*)::bigint FROM public.messages
                          WHERE run_id='run-decision' AND role='tool')
                           FROM public.runs WHERE run_id='run-decision'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                )
            };
            if before != ("running".to_owned(), 0) {
                return Err(format!("run did not suspend before answer: {before:?}"));
            }
            drop(client);
            let answer = ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                decision: ComponentApprovalDecision::Approved,
                note: Some("duplicate charge".to_owned()),
            });
            match application
                .execute(
                    auth,
                    AppCommand::ResolveComponentHumanDecision {
                        decision_id: pending.decision_id.clone(),
                        answer: answer.clone(),
                    },
                )
                .await
                .map_err(|error| error.to_string())?
            {
                AppReply::ComponentHumanDecisionResolved(resolved)
                    if resolved.decision_id == pending.decision_id && resolved.answer == answer => {
                }
                reply => return Err(format!("answer receipt drift: {reply:?}")),
            }
            wait_for_terminal(&pool, "run-decision", "The refund was approved.").await?;
            relay.stop().await;
            agent.stop().await;

            let requests = provider.requests.lock().unwrap().clone();
            let expected_result =
                serde_json::to_string(&answer).map_err(|error| error.to_string())?;
            if requests.len() != 2
                || requests[0]
                    .tools
                    .iter()
                    .all(|tool| tool.name != ASK_APPROVAL_COMPONENT_NAME)
                || requests[1].messages.iter().all(|message| {
                    message.role != openbot_application::ProviderMessageRole::Assistant
                        || message.tool_calls.len() != 1
                        || message.tool_calls[0].call_id != "provider-approval-1"
                        || message.tool_calls[0].name != ASK_APPROVAL_COMPONENT_NAME
                })
                || requests[1].messages.iter().all(|message| {
                    message.role != openbot_application::ProviderMessageRole::Tool
                        || message.tool_call_id.as_deref() != Some("provider-approval-1")
                        || message.tool_name.as_deref() != Some(ASK_APPROVAL_COMPONENT_NAME)
                        || message.content != expected_result
                })
            {
                return Err(format!(
                    "decision provider resume history drift: {requests:?}"
                ));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT d.state,d.answer,
                            (SELECT count(*)::bigint FROM public.audit_events a
                              WHERE a.event_type='component.human_requested'
                                AND a.target_id='askApproval'),
                            (SELECT count(*)::bigint FROM public.audit_events a
                              WHERE a.event_type='component.human_answered'
                                AND a.target_id='askApproval'),
                            (SELECT count(*)::bigint FROM public.messages m
                              WHERE m.run_id='run-decision' AND m.role='tool'
                                AND m.content->>'toolCallId'='provider-approval-1')
                       FROM public.component_human_decisions d
                      WHERE d.decision_id=$1",
                    &[&pending.decision_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let shape: (String, serde_json::Value, i64, i64, i64) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
                row.try_get(2).map_err(|error| error.to_string())?,
                row.try_get(3).map_err(|error| error.to_string())?,
                row.try_get(4).map_err(|error| error.to_string())?,
            );
            if shape
                != (
                    "answered".to_owned(),
                    serde_json::to_value(&answer).map_err(|error| error.to_string())?,
                    1,
                    1,
                    1,
                )
            {
                return Err(format!("decision durable/audit shape drift: {shape:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_SOCKET/PORT/USER 后加 --include-ignored 运行"]
async fn remember_tool_runs_through_policy_capability_memory_audit_and_second_sampling() {
    let admin = batch6_admin_config(
        "remember_tool_runs_through_policy_capability_memory_audit_and_second_sampling",
    );
    with_temp_database(&admin, "agentremember", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let owner = "runtime-remember".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let policy = PolicyStore::postgres(pool.clone(), None);
            policy.load().await.map_err(|error| error.to_string())?;
            policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: Vec::new(),
                        allow: vec![r#"tool.name == "remember""#.to_owned()],
                    },
                    Some("actor-a"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let memory = PostgresMemoryAdministration::new(pool.clone())
                .with_effect_audit_key(vec![0xa5; 32])
                .map_err(|error| error.to_string())?;
            let tool_memory = Arc::new(RevokeBeforeSecondRemember {
                inner: memory.clone(),
                pool: pool.clone(),
                policy: policy.clone(),
                calls: AtomicUsize::new(0),
            });
            let control = PostgresBuiltInToolControlPlane::new(
                pool.clone(),
                deployment.clone(),
                tenant.clone(),
                policy.clone(),
                tool_memory.clone(),
            );
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policy)
                    .with_tools(
                        control,
                        PostgresToolJournal::new(pool.clone(), vec![0xa5; 32])
                            .map_err(|error| error.to_string())?,
                    )
                    .with_memory(memory),
            );
            let tools: Arc<dyn AgentToolInvoker> = Arc::new(AuthorizedAgentToolGateway::new(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                )),
            ));
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?
                .with_tools(vec![remember_provider_tool()]),
            );
            let provider = Arc::new(RememberLoopProvider::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider.clone(),
                tools,
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime.clone(), agent.consumer());
            let remember_thread = begin_test_run(
                &directory,
                &deployment,
                &tenant,
                9,
                "run-remember",
                "Please remember that I prefer tea.",
            )
            .await?;
            wait_for_terminal(&pool, "run-remember", "I remembered that.").await?;
            relay.stop().await;
            agent.stop().await;

            let requests = provider
                .requests
                .lock()
                .expect("remember provider lock")
                .clone();
            if requests.len() != 4
                || requests[0].tools.len() != 1
                || requests[0].tools[0].name != "remember"
                || requests[1].messages.iter().all(|message| {
                    message.role != openbot_application::ProviderMessageRole::Assistant
                        || message.tool_calls.len() != 1
                        || message.tool_calls[0].call_id != "provider-remember-1"
                })
                || requests[1].messages.iter().all(|message| {
                    message.role != openbot_application::ProviderMessageRole::Tool
                        || message.tool_call_id.as_deref() != Some("provider-remember-1")
                        || message.tool_name.as_deref() != Some("remember")
                })
                || requests[3]
                    .messages
                    .iter()
                    .filter(|message| {
                        message.role == openbot_application::ProviderMessageRole::Tool
                    })
                    .count()
                    != 3
            {
                return Err(format!("remember provider history 漂移：{requests:?}"));
            }
            if tool_memory.calls.load(Ordering::SeqCst) != 2 {
                return Err("policy refusal reached remember executor".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let replay_row = client
                .query_one(
                    "SELECT c.tool_call_id,m.content->>'text' AS result \
                     FROM public.tool_calls c JOIN public.messages m ON m.run_id=c.run_id \
                     WHERE c.run_id='run-remember' AND c.call_seq=0 AND m.role='tool' \
                       AND m.content->>'toolCallId'='provider-remember-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let internal_call_id: String = replay_row
                .try_get("tool_call_id")
                .map_err(|error| error.to_string())?;
            let model_result: String = replay_row
                .try_get("result")
                .map_err(|error| error.to_string())?;
            let replay_lease = RunExecutionLease::new(
                RunId::new("run-remember"),
                remember_thread.clone(),
                BotId::new("bot-1"),
                ActorId::new("actor-a"),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                1,
            )
            .map_err(|error| error.to_string())?;
            let exact_exchange = RunToolExchange::new(
                openbot_contracts::ids::ToolCallId::new(internal_call_id),
                "provider-remember-1".to_owned(),
                "remember".to_owned(),
                serde_json::json!({
                    "memoryKind":"fact",
                    "scope":"thread",
                    "content":"The user prefers tea.",
                    "tags":["drink"],
                    "sensitivity":"normal"
                }),
                model_result,
                None,
            )
            .map_err(|error| error.to_string())?;
            let replay = runtime
                .append_tool_exchange(&replay_lease, 1, &exact_exchange)
                .await
                .map_err(|error| error.to_string())?;
            if !replay.replayed {
                return Err("tool exchange exact replay 没返回 replayed".to_owned());
            }
            let tampered = RunToolExchange::new(
                exact_exchange.internal_call_id().clone(),
                "provider-remember-1".to_owned(),
                "remember".to_owned(),
                exact_exchange.arguments().clone(),
                "tampered".to_owned(),
                None,
            )
            .map_err(|error| error.to_string())?;
            if runtime
                .append_tool_exchange(&replay_lease, 1, &tampered)
                .await
                != Err(openbot_application::RunRuntimeError::Conflict)
            {
                return Err("tool exchange tampered replay 未拒绝".to_owned());
            }
            let memory = client
                .query_one(
                    "SELECT owner_user_id,scope_kind,scope_id,memory_kind,content,origin, \
                            source_thread_id,source_message_id,status \
                     FROM public.memories",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let memory_shape = (
                memory.try_get::<_, String>(0).map_err(|error| error.to_string())?,
                memory.try_get::<_, String>(1).map_err(|error| error.to_string())?,
                memory.try_get::<_, Option<String>>(2).map_err(|error| error.to_string())?,
                memory.try_get::<_, String>(3).map_err(|error| error.to_string())?,
                memory.try_get::<_, Option<String>>(4).map_err(|error| error.to_string())?,
                memory.try_get::<_, String>(5).map_err(|error| error.to_string())?,
                memory.try_get::<_, Option<String>>(6).map_err(|error| error.to_string())?,
                memory.try_get::<_, Option<String>>(7).map_err(|error| error.to_string())?,
                memory.try_get::<_, String>(8).map_err(|error| error.to_string())?,
            );
            if memory_shape.0 != "actor-a"
                || memory_shape.1 != "thread"
                || memory_shape.2.as_deref() != Some(remember_thread.as_str())
                || memory_shape.3 != "fact"
                || memory_shape.4.as_deref() != Some("The user prefers tea.")
                || memory_shape.5 != "remember_tool"
                || memory_shape.6 != memory_shape.2
                || memory_shape.7.as_deref().is_none_or(str::is_empty)
                || memory_shape.8 != "active"
            {
                return Err(format!("remember memory shape 漂移：{memory_shape:?}"));
            }
            let tool_shape = client
                .query(
                    "SELECT c.tool_name,c.call_seq,a.status,a.commit_state \
                     FROM public.tool_calls c JOIN public.tool_attempts a USING(tool_call_id) \
                     WHERE c.run_id='run-remember' ORDER BY c.call_seq",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| {
                    Ok::<_, String>((
                        row.try_get::<_, String>(0).map_err(|error| error.to_string())?,
                        row.try_get::<_, i64>(1).map_err(|error| error.to_string())?,
                        row.try_get::<_, String>(2).map_err(|error| error.to_string())?,
                        row.try_get::<_, Option<String>>(3).map_err(|error| error.to_string())?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if tool_shape
                != [
                    (
                        "remember".to_owned(),
                        0,
                        "completed".to_owned(),
                        Some("committed".to_owned()),
                    ),
                    (
                        "remember".to_owned(),
                        1,
                        "completed".to_owned(),
                        Some("not_committed".to_owned()),
                    ),
                ]
            {
                return Err(format!("remember tool journal 漂移：{tool_shape:?}"));
            }
            let memory_audits: Vec<String> = client
                .query(
                    "SELECT event_type FROM public.audit_events \
                     WHERE event_type LIKE 'memory.remember_%' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.try_get(0).map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?;
            let checkpoint_count: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events \
                     WHERE run_id='run-remember' AND event_type='checkpoint' \
                       AND payload->>'kind'='tool_exchange'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let roles: Vec<String> = client
                .query(
                    "SELECT role FROM public.messages WHERE run_id='run-remember' ORDER BY seq",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.try_get(0).map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?;
            let auth_generation: i64 = client
                .query_one("SELECT auth_generation FROM public.users WHERE id='actor-a'", &[])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if memory_audits
                != [
                    "memory.remember_succeeded".to_owned(),
                    "memory.remember_failed".to_owned(),
                    "memory.remember_refused".to_owned(),
                ]
                || checkpoint_count != 3
                || roles
                    != [
                        "user",
                        "assistant",
                        "tool",
                        "assistant",
                        "tool",
                        "assistant",
                        "tool",
                        "assistant",
                    ]
                || auth_generation != 1
            {
                return Err(format!(
                    "remember durable projection 漂移：audits={memory_audits:?} checkpoint={checkpoint_count} roles={roles:?} generation={auth_generation}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn remote_agui_row_routes_through_safe_sse_into_durable_text_reasoning_and_terminal() {
    let admin = batch6_admin_config(
        "remote_agui_row_routes_through_safe_sse_into_durable_text_reasoning_and_terminal",
    );
    with_temp_database(&admin, "agentremote", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let auth = AuthContextBuilder::from_verified_session(
                deployment.clone(),
                tenant.clone(),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User])
            .build();
            let components = Arc::new(
                PostgresComponentAdministration::new(pool.clone(), vec![0xa6; 32])
                    .map_err(|error| error.to_string())?,
            );
            components
                .sync_catalogue(&auth, &compiled_component_manifest())
                .await
                .map_err(|error| error.to_string())?;
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let address = listener.local_addr().map_err(|error| error.to_string())?;
            let endpoint = format!("http://{address}/ag-ui");
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.agents(id,name,type,configuration,package_id) \
                       SELECT 'bot-remote','Remote Risk','remote_ag_ui', \
                              jsonb_build_object('endpoint',$1::text),id \
                       FROM public.deployment_packages WHERE tenant_id='tenant-a'",
                    &[&endpoint],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.agent_profiles( \
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at \
                     ) VALUES('bot-remote',NULL,'Risk Analyst','Investigate controls.','remote-seed','public',NULL)",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let assertion_signer = Arc::new(
                RemoteRunAssertionSigner::new(b"remote-test-master".to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let assertion_verifier = assertion_signer.clone();
            let (preterminal_sent, preterminal_received) = oneshot::channel();
            let (allow_terminal, terminal_allowed) = oneshot::channel();
            let remote_server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
                let request = read_http_request(&mut stream).await?;
                if !request.starts_with("POST /ag-ui ") {
                    return Err("remote AG-UI path 漂移".to_owned());
                }
                let body: serde_json::Value = serde_json::from_str(
                    request
                        .split("\r\n\r\n")
                        .nth(1)
                        .ok_or_else(|| "remote request body missing".to_owned())?,
                )
                .map_err(|error| error.to_string())?;
                let tools = body["tools"]
                    .as_array()
                    .ok_or_else(|| "remote tools missing".to_owned())?;
                let offered_quote = tools.iter().any(|tool| {
                    tool["name"] == SHOW_QUOTE_COMPONENT_NAME && tool["parameters"].is_object()
                });
                if body["runId"] != "run-remote"
                    || body["forwardedProps"]["openbotBotId"] != "bot-remote"
                    || !offered_quote
                    || !body["forwardedProps"]["openbotDeploymentTools"]
                        .as_array()
                        .is_some_and(|tools| {
                            tools.iter().any(|tool| tool == SHOW_QUOTE_COMPONENT_NAME)
                        })
                    || body["messages"][0]["role"] != "system"
                    || !body["messages"][0]["content"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("You are Remote Risk, Risk Analyst."))
                {
                    return Err(format!("remote RunAgentInput 漂移：{body:?}"));
                }
                let assertion = body["forwardedProps"]["openbotRun"]
                    .as_str()
                    .ok_or_else(|| "signed openbotRun missing".to_owned())?;
                let now_millis = i64::try_from(
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
                )
                .map_err(|_| "current time outside i64".to_owned())?;
                let verified = assertion_verifier
                    .verify(assertion, now_millis)
                    .map_err(|error| error.to_string())?;
                if verified.scope().bot.as_str() != "bot-remote"
                    || verified.scope().actor.as_str() != "actor-a"
                    || verified.scope().run.as_str() != "run-remote"
                    || verified.tool_set_digest() != RemoteToolSet::empty().digest()
                {
                    return Err("remote signed scope/tool-set drift".to_owned());
                }
                let thread_id = body["threadId"]
                    .as_str()
                    .ok_or_else(|| "threadId missing".to_owned())?;
                let preterminal_events = [
                    serde_json::json!({"type":"RUN_STARTED","threadId":thread_id,"runId":"run-remote"}),
                    serde_json::json!({"type":"STEP_STARTED","stepName":"investigate"}),
                    serde_json::json!({"type":"STATE_SNAPSHOT","snapshot":{"phase":"start"}}),
                    serde_json::json!({"type":"STATE_DELTA","delta":[{"op":"replace","path":"/phase","value":"done"}]}),
                    serde_json::json!({"type":"MESSAGES_SNAPSHOT","messages":[{"id":"u","role":"user","content":"hello"}]}),
                    serde_json::json!({"type":"ACTIVITY_SNAPSHOT","messageId":"a","activityType":"PLAN","content":{"done":false}}),
                    serde_json::json!({"type":"ACTIVITY_DELTA","messageId":"a","activityType":"PLAN","patch":[{"op":"replace","path":"/done","value":true}]}),
                    serde_json::json!({"type":"TOOL_CALL_START","toolCallId":"remote-result-call","toolCallName":SHOW_QUOTE_COMPONENT_NAME}),
                    serde_json::json!({"type":"TOOL_CALL_ARGS","toolCallId":"remote-result-call","delta":"{\"quote\":\"Remote result only.\",\"attribution\":\"remote\"}"}),
                    serde_json::json!({"type":"TOOL_CALL_END","toolCallId":"remote-result-call"}),
                    serde_json::json!({"type":"TOOL_CALL_RESULT","messageId":"remote-result-message","toolCallId":"remote-result-call","content":"REMOTE_TOOL_RESULT_SECRET_CANARY"}),
                    serde_json::json!({"type":"RAW","event":{"untrusted":true,"canary":"REMOTE_PROJECTION_SECRET_CANARY"},"source":"remote"}),
                    serde_json::json!({"type":"CUSTOM","name":"future","value":{"permission":"none"}}),
                    serde_json::json!({"type":"REASONING_START","messageId":"reason"}),
                    serde_json::json!({"type":"REASONING_MESSAGE_START","messageId":"reason-message","role":"reasoning"}),
                    serde_json::json!({"type":"REASONING_MESSAGE_CONTENT","messageId":"reason-message","delta":"checked evidence"}),
                    serde_json::json!({"type":"REASONING_ENCRYPTED_VALUE","subtype":"message","entityId":"reason-message","encryptedValue":"ENCRYPTED_REASONING_CANARY"}),
                    serde_json::json!({"type":"REASONING_MESSAGE_END","messageId":"reason-message"}),
                    serde_json::json!({"type":"REASONING_END","messageId":"reason"}),
                    serde_json::json!({"type":"TEXT_MESSAGE_START","messageId":"answer","role":"assistant"}),
                    serde_json::json!({"type":"TEXT_MESSAGE_CONTENT","messageId":"answer","delta":"remote answer"}),
                    serde_json::json!({"type":"TEXT_MESSAGE_END","messageId":"answer"}),
                    serde_json::json!({"type":"STEP_FINISHED","stepName":"investigate"}),
                ];
                let preterminal_body = preterminal_events
                    .into_iter()
                    .map(|event| format!("data: {event}\n\n"))
                    .collect::<String>();
                let terminal_body = format!(
                    "data: {}\n\n",
                    serde_json::json!({"type":"RUN_FINISHED","threadId":thread_id,"runId":"run-remote"})
                );
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    preterminal_body.len() + terminal_body.len()
                );
                stream
                    .write_all(header.as_bytes())
                    .await
                    .map_err(|error| error.to_string())?;
                for chunk in preterminal_body.as_bytes().chunks(5) {
                    stream
                        .write_all(chunk)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                stream.flush().await.map_err(|error| error.to_string())?;
                preterminal_sent
                    .send(())
                    .map_err(|_| "projection observer dropped before preterminal".to_owned())?;
                terminal_allowed
                    .await
                    .map_err(|_| "terminal permission dropped".to_owned())?;
                for chunk in terminal_body.as_bytes().chunks(5) {
                    stream
                        .write_all(chunk)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Ok::<_, String>(())
            });

            let owner = "runtime-remote".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let package = Arc::new(RejectingPackageProvider::default());
            let remote_transport = Arc::new(
                SafeRemoteAguiTransport::new(
                    SafeDialer::new(EgressPolicy::new(
                        CidrAllowlist::parse_exact(["127.0.0.1/32"])
                            .map_err(|error| error.to_string())?,
                    )),
                    SafeHttpBudget::new(1024 * 1024, Duration::from_secs(3))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_secs(1)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
            );
            let router: Arc<dyn ProviderAdapter> = Arc::new(
                ProviderRouter::new(package.clone(), None)
                    .with_remote_agui(Arc::new(RemoteAguiProvider::new(remote_transport))),
            );
            let provider = Arc::new(
                RetryingProvider::new(router, RetryingProviderConfig::default())
                    .map_err(|error| error.to_string())?,
            );
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?
                .with_tools(vec![remember_provider_tool()])
                .with_components(components)
                .with_remote_assertions(assertion_signer),
            );
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider,
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime, agent.consumer());
            let mut entropy = [0_u8; 16];
            entropy[15] = 10;
            let thread = ThreadIdentity::new(&deployment).mint_from_entropy(entropy);
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: ActorId::new("actor-a"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: thread,
                        run_id: RunId::new("run-remote"),
                        bot_id: BotId::new("bot-remote"),
                        anchor: ThreadRunAnchor::DirectBot,
                        message: "Investigate".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            tokio::time::timeout(Duration::from_secs(3), preterminal_received)
                .await
                .map_err(|_| "remote preterminal write timed out".to_owned())?
                .map_err(|_| "remote preterminal server ended".to_owned())?;
            wait_for_remote_projection_count(&pool, "run-remote", 10).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let active_projection = client
                .query_one(
                    "SELECT array_agg(payload->>'family' ORDER BY seq), \
                            count(*) FILTER (WHERE payload->>'untrusted'='true' \
                              AND payload->>'source'='remote_ag_ui')::bigint, \
                            count(*) FILTER (WHERE payload->>'family'='state' \
                              AND payload->'untrustedValue'->>'phase'='done')::bigint, \
                            count(*) FILTER (WHERE payload->>'family'='activity' \
                              AND payload->'untrustedValue'->>'done'='true')::bigint, \
                            count(*) FILTER (WHERE payload::text LIKE \
                              '%REMOTE_PROJECTION_SECRET_CANARY%')::bigint, \
                            count(*) FILTER (WHERE payload->>'family'='tool_result' \
                              AND payload->>'untrustedKey'='remote-result-call' \
                              AND payload->>'untrustedType'='remote-result-message' \
                              AND payload->>'untrustedValue'='REMOTE_TOOL_RESULT_SECRET_CANARY')::bigint \
                     FROM public.run_events WHERE run_id='run-remote' \
                       AND event_type='checkpoint' \
                       AND payload->>'kind'='remote_agui_projection'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let families: Vec<String> = active_projection
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let untrusted: i64 = active_projection
                .try_get(1)
                .map_err(|error| error.to_string())?;
            let patched_state: i64 = active_projection
                .try_get(2)
                .map_err(|error| error.to_string())?;
            let patched_activity: i64 = active_projection
                .try_get(3)
                .map_err(|error| error.to_string())?;
            let active_canary: i64 = active_projection
                .try_get(4)
                .map_err(|error| error.to_string())?;
            let tool_result: i64 = active_projection
                .try_get(5)
                .map_err(|error| error.to_string())?;
            if families
                != [
                    "step_started",
                    "state",
                    "state",
                    "messages",
                    "activity",
                    "activity",
                    "tool_result",
                    "raw",
                    "custom",
                    "step_finished",
                ]
                || untrusted != 10
                || patched_state != 1
                || patched_activity != 1
                || active_canary != 1
                || tool_result != 1
            {
                return Err(format!(
                    "active remote projections drifted: families={families:?} untrusted={untrusted} state={patched_state} activity={patched_activity} canary={active_canary} toolResult={tool_result}"
                ));
            }
            drop(client);
            allow_terminal
                .send(())
                .map_err(|_| "remote terminal server ended before permission".to_owned())?;
            wait_for_terminal(&pool, "run-remote", "remote answer").await?;

            for (run_id, entropy_tail, fixture, expected_code) in [
                (
                    "run-remote-error",
                    11,
                    RemoteFailureFixture::RunError,
                    "provider_generation_failed",
                ),
                (
                    "run-remote-malformed",
                    12,
                    RemoteFailureFixture::MalformedMessage,
                    "provider_invalid_response",
                ),
            ] {
                let failure_listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|error| error.to_string())?;
                let failure_address = failure_listener
                    .local_addr()
                    .map_err(|error| error.to_string())?;
                let failure_endpoint = format!("http://{failure_address}/ag-ui");
                let client = pool.get().await.map_err(|error| error.to_string())?;
                client
                    .execute(
                        "UPDATE public.agents SET configuration=jsonb_build_object('endpoint',$2::text)
                          WHERE id=$1",
                        &[&"bot-remote", &failure_endpoint],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                drop(client);
                let failure_server = tokio::spawn(one_remote_agui_failure(
                    failure_listener,
                    run_id,
                    fixture,
                ));
                begin_test_run_for_bot(
                    &directory,
                    &deployment,
                    &tenant,
                    entropy_tail,
                    run_id,
                    "bot-remote",
                    "Trigger remote failure",
                )
                .await?;
                wait_for_failure(&pool, run_id, expected_code).await?;
                failure_server
                    .await
                    .map_err(|error| error.to_string())??;
            }
            relay.stop().await;
            agent.stop().await;
            remote_server.await.map_err(|error| error.to_string())??;
            if package.calls.load(Ordering::SeqCst) != 0 {
                return Err("remote route touched package provider".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let reasoning_markers: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events \
                     WHERE run_id='run-remote' AND event_type='semantic_chunk' \
                       AND payload->>'channel'='reasoning' \
                       AND payload=jsonb_build_object( \
                         'channel','reasoning','delta','','retained',false \
                       )",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let projection_markers: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events \
                     WHERE run_id='run-remote' AND event_type='checkpoint' \
                       AND payload=jsonb_build_object( \
                         'kind','remote_agui_projection','source','remote_ag_ui', \
                         'retained',false,'untrusted',true \
                       )",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let invoked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events \
                     WHERE event_type='agent.invoked' AND target_id LIKE 'run-remote%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let canary_rows: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM (
                       SELECT content::text AS value FROM public.messages
                       UNION ALL SELECT payload::text FROM public.run_events
                       UNION ALL SELECT payload::text FROM public.audit_events
                     ) AS persisted WHERE value LIKE '%REMOTE_ERROR_SECRET_CANARY%'
                                      OR value LIKE '%ENCRYPTED_REASONING_CANARY%'
                                      OR value LIKE '%checked evidence%'
                                      OR value LIKE '%REMOTE_PROJECTION_SECRET_CANARY%'
                                      OR value LIKE '%REMOTE_TOOL_RESULT_SECRET_CANARY%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let local_tool_effects: i64 = client
                .query_one(
                    "SELECT (SELECT count(*) FROM public.messages \
                              WHERE run_id='run-remote' AND role='tool') \
                          + (SELECT count(*) FROM public.tool_calls \
                              WHERE run_id='run-remote')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if reasoning_markers != 1
                || projection_markers != 10
                || invoked != 3
                || canary_rows != 0
                || local_tool_effects != 0
            {
                return Err(format!(
                    "remote durable projection 漂移：reasoningMarkers={reasoning_markers} projectionMarkers={projection_markers} invoked={invoked} canary={canary_rows} localToolEffects={local_tool_effects}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn remote_agui_interrupt_resolves_through_application_and_makes_a_second_safe_request() {
    let admin = batch6_admin_config(
        "remote_agui_interrupt_resolves_through_application_and_makes_a_second_safe_request",
    );
    with_temp_database(&admin, "agentinterrupt", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let auth = AuthContextBuilder::from_verified_session(
                deployment.clone(),
                tenant.clone(),
                ActorId::new("actor-a"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User])
            .build();
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let address = listener.local_addr().map_err(|error| error.to_string())?;
            let endpoint = format!("http://{address}/ag-ui");
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.agents(id,name,type,configuration,package_id) \
                       SELECT 'bot-interrupt','Remote Interrupt','remote_ag_ui', \
                              jsonb_build_object('endpoint',$1::text),id \
                       FROM public.deployment_packages WHERE tenant_id='tenant-a'",
                    &[&endpoint],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.agent_profiles( \
                       agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at \
                     ) VALUES('bot-interrupt',NULL,'Remote Interrupt','Wait for reviewed input.', \
                              'interrupt-seed','public',NULL)",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let requests = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
            let server_requests = requests.clone();
            let remote_server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await.map_err(|error| error.to_string())?;
                let first_request = read_http_request(&mut first).await?;
                let first_body: serde_json::Value = serde_json::from_str(
                    first_request
                        .split("\r\n\r\n")
                        .nth(1)
                        .ok_or_else(|| "first remote body missing".to_owned())?,
                )
                .map_err(|error| error.to_string())?;
                if first_body["runId"] != "run-interrupt"
                    || first_body.get("parentRunId").is_some()
                    || first_body.get("resume").is_some()
                {
                    return Err(format!("first AG-UI request lineage drifted: {first_body:?}"));
                }
                let thread_id = first_body["threadId"]
                    .as_str()
                    .ok_or_else(|| "first thread id missing".to_owned())?;
                server_requests.lock().expect("request bodies").push(first_body.clone());
                let first_events = [
                    serde_json::json!({"type":"RUN_STARTED","threadId":thread_id,"runId":"run-interrupt"}),
                    serde_json::json!({
                        "type":"RUN_FINISHED",
                        "threadId":thread_id,
                        "runId":"run-interrupt",
                        "outcome":{
                            "type":"interrupt",
                            "interrupts":[{
                                "id":"remote-confirm-1",
                                "reason":"confirmation",
                                "message":"REMOTE_INTERRUPT_MESSAGE_CANARY",
                                "responseSchema":{"type":"object","properties":{"approved":{"type":"boolean"}}},
                                "metadata":{"authority":"REMOTE_AUTHORITY_CANARY"}
                            }]
                        }
                    }),
                ];
                let body = first_events
                    .into_iter()
                    .map(|event| format!("data: {event}\n\n"))
                    .collect::<String>();
                write_sse_response(&mut first, &body).await?;

                let (mut second, _) = listener.accept().await.map_err(|error| error.to_string())?;
                let second_request = read_http_request(&mut second).await?;
                let second_body: serde_json::Value = serde_json::from_str(
                    second_request
                        .split("\r\n\r\n")
                        .nth(1)
                        .ok_or_else(|| "second remote body missing".to_owned())?,
                )
                .map_err(|error| error.to_string())?;
                let second_run = second_body["runId"]
                    .as_str()
                    .ok_or_else(|| "second run id missing".to_owned())?;
                if second_run == "run-interrupt"
                    || second_body["parentRunId"] != "run-interrupt"
                    || second_body["resume"]
                        != serde_json::json!([{
                            "interruptId":"remote-confirm-1",
                            "status":"resolved",
                            "payload":{"approved":true,"canary":"RESUME_PAYLOAD_CANARY"}
                        }])
                {
                    return Err(format!("second AG-UI request lineage drifted: {second_body:?}"));
                }
                server_requests
                    .lock()
                    .expect("request bodies")
                    .push(second_body.clone());
                let second_events = [
                    serde_json::json!({"type":"RUN_STARTED","threadId":thread_id,"runId":second_run}),
                    serde_json::json!({"type":"TEXT_MESSAGE_START","messageId":"answer","role":"assistant"}),
                    serde_json::json!({"type":"TEXT_MESSAGE_CONTENT","messageId":"answer","delta":"resumed answer"}),
                    serde_json::json!({"type":"TEXT_MESSAGE_END","messageId":"answer"}),
                    serde_json::json!({"type":"RUN_FINISHED","threadId":thread_id,"runId":second_run}),
                ];
                let body = second_events
                    .into_iter()
                    .map(|event| format!("data: {event}\n\n"))
                    .collect::<String>();
                write_sse_response(&mut second, &body).await?;
                Ok::<_, String>(())
            });

            let owner = "runtime-interrupt".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner.clone(),
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let remote_interrupts = Arc::new(
                PostgresRemoteInterruptCoordinator::new(
                    pool.clone(),
                    owner,
                    vec![0xb8; 32],
                )
                .map_err(|error| error.to_string())?,
            );
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_remote_interrupts(remote_interrupts.clone()),
            );
            let assertion_signer = Arc::new(
                RemoteRunAssertionSigner::new(b"interrupt-test-master".to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let remote_transport = Arc::new(
                SafeRemoteAguiTransport::new(
                    SafeDialer::new(EgressPolicy::new(
                        CidrAllowlist::parse_exact(["127.0.0.1/32"])
                            .map_err(|error| error.to_string())?,
                    )),
                    SafeHttpBudget::new(1024 * 1024, Duration::from_secs(3))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_secs(1)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
            );
            let provider: Arc<dyn ProviderAdapter> = Arc::new(RemoteAguiProvider::new(
                remote_transport,
            ));
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?
                .with_remote_assertions(assertion_signer),
            );
            let remote_runtime_port: Arc<dyn RemoteInterruptCoordinator> = remote_interrupts;
            let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
                runtime.clone(),
                context,
                provider,
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xb8; 32])
                        .map_err(|error| error.to_string())?,
                ),
                remote_runtime_port,
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 1,
                    lease_renew_interval: Duration::from_millis(200),
                    run_deadline: Some(Duration::from_secs(8)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime, agent.consumer());
            let mut entropy = [0_u8; 16];
            entropy[15] = 44;
            directory
                .begin_thread_run(BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: ActorId::new("actor-a"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: None,
                        selected_skill_slugs: Vec::new(),
                        thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(entropy),
                        run_id: RunId::new("run-interrupt"),
                        bot_id: BotId::new("bot-interrupt"),
                        anchor: ThreadRunAnchor::DirectBot,
                        message: "Need confirmation".to_owned(),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;

            let pending = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match application
                        .execute(auth.clone(), AppCommand::ListPendingRemoteInterrupts)
                        .await
                    {
                        Ok(AppReply::PendingRemoteInterrupts(page))
                            if page.interrupts.len() == 1 => return Ok::<_, String>(page),
                        Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                    }
                }
            })
            .await
            .map_err(|_| "remote interrupt did not reach ApplicationService".to_owned())??;
            let request_id = pending.interrupts[0].request_id.clone();
            if pending.interrupts[0].untrusted_reason != "confirmation"
                || pending.interrupts[0].untrusted_message.as_deref()
                    != Some("REMOTE_INTERRUPT_MESSAGE_CANARY")
            {
                return Err(format!("pending projection drifted: {pending:?}"));
            }
            let answer = RemoteInterruptAnswer {
                status: RemoteInterruptAnswerStatus::Resolved,
                payload: Some(serde_json::json!({
                    "approved":true,
                    "canary":"RESUME_PAYLOAD_CANARY"
                })),
            };
            match application
                .execute(
                    auth.clone(),
                    AppCommand::ResolveRemoteInterrupt {
                        request_id: request_id.clone(),
                        answer: answer.clone(),
                    },
                )
                .await
                .map_err(|error| error.to_string())?
            {
                AppReply::RemoteInterruptResolved(receipt)
                    if receipt.request_id == request_id
                        && receipt.status == RemoteInterruptAnswerStatus::Resolved
                        && !receipt.replayed => {}
                other => return Err(format!("resolve receipt drifted: {other:?}")),
            }
            wait_for_terminal(&pool, "run-interrupt", "resumed answer").await?;
            relay.stop().await;
            agent.stop().await;
            remote_server.await.map_err(|error| error.to_string())??;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let durable = client
                .query_one(
                    "SELECT count(*)::bigint AS rows, \
                            count(*) FILTER (WHERE state='retired' AND descriptor IS NULL \
                              AND response_payload IS NULL AND resume_protocol_run_id IS NULL)::bigint AS retired \
                       FROM public.remote_agent_interrupts WHERE run_id='run-interrupt'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let rows: i64 = durable.get("rows");
            let retired: i64 = durable.get("retired");
            let audits: Vec<String> = client
                .query(
                    "SELECT event_type FROM public.audit_events \
                      WHERE event_type LIKE 'agent.remote_interrupt_%' ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            let leaked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM ( \
                       SELECT content::text AS value FROM public.messages \
                       UNION ALL SELECT payload::text FROM public.run_events \
                       UNION ALL SELECT payload::text FROM public.audit_events \
                       UNION ALL SELECT coalesce(descriptor::text,'') FROM public.remote_agent_interrupts \
                       UNION ALL SELECT coalesce(response_payload::text,'') FROM public.remote_agent_interrupts \
                     ) persisted WHERE value LIKE '%REMOTE_INTERRUPT_MESSAGE_CANARY%' \
                                      OR value LIKE '%REMOTE_AUTHORITY_CANARY%' \
                                      OR value LIKE '%RESUME_PAYLOAD_CANARY%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            if rows != 1
                || retired != 1
                || audits
                    != [
                        "agent.remote_interrupt_requested",
                        "agent.remote_interrupt_resolved",
                    ]
                || leaked != 0
                || requests.lock().expect("request bodies").len() != 2
            {
                return Err(format!(
                    "remote interrupt durable terminal drifted: rows={rows} retired={retired} audits={audits:?} leaked={leaked}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn real_openai_http_stream_uses_fresh_vault_credential_and_durable_reasoning_channel() {
    let admin = batch6_admin_config(
        "real_openai_http_stream_uses_fresh_vault_credential_and_durable_reasoning_channel",
    );
    with_temp_database(&admin, "agentopenai", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let address = listener.local_addr().map_err(|error| error.to_string())?;
            let provider_server = tokio::spawn(recording_openai_server(listener));

            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let vault = CredentialRecordVault::single_key(
                tenant.clone(),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x42; 32]).map_err(|error| error.to_string())?,
            );
            let missing_vault = vault.clone();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let old = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
            let tied = old + time::Duration::days(1);
            let future = tied + time::Duration::days(1);
            let cases = [
                (
                    "00000000-0000-4000-8000-000000000009",
                    SecretKind::Model,
                    "openai",
                    "openai-key",
                    b"older-key".as_slice(),
                    old,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000001",
                    SecretKind::Model,
                    "openai",
                    "openai-key",
                    b"lower-tie-key".as_slice(),
                    tied,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000002",
                    SecretKind::Model,
                    "openai",
                    "openai-key",
                    b"stored-provider-key".as_slice(),
                    tied,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000003",
                    SecretKind::Connector,
                    "openai",
                    "openai-key",
                    b"wrong-kind-key".as_slice(),
                    future,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000004",
                    SecretKind::Model,
                    "other",
                    "openai-key",
                    b"wrong-provider-key".as_slice(),
                    future,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000005",
                    SecretKind::Model,
                    "openai",
                    "other-key",
                    b"wrong-key-id".as_slice(),
                    future,
                    None,
                ),
                (
                    "00000000-0000-4000-8000-000000000006",
                    SecretKind::Model,
                    "openai",
                    "openai-key",
                    b"revoked-newer-key".as_slice(),
                    future,
                    Some(future),
                ),
            ];
            for (id, kind, provider_name, key_id, plaintext, created_at, revoked_at) in cases {
                let id = Uuid::parse_str(id).map_err(|error| error.to_string())?;
                let plaintext = SecretBytes::new(plaintext.to_vec());
                let encrypted = vault
                    .seal(
                        &id,
                        kind,
                        SecretPrincipal::Deployment,
                        SecretPrincipal::Deployment,
                        &plaintext,
                    )
                    .map_err(|error| error.to_string())?;
                client
                    .execute(
                        "INSERT INTO public.credentials( \
                           id,kind,provider,encrypted_value,key_id,metadata,revoked_at,created_at,updated_at \
                         ) VALUES($1,$2::text::public.credential_kind,$3,$4,$5,'{}'::jsonb,$6,$7,$7)",
                        &[
                            &id,
                            &kind.as_str(),
                            &provider_name,
                            &encrypted,
                            &key_id,
                            &revoked_at,
                            &created_at,
                        ],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
            }
            drop(client);

            let credentials = Arc::new(
                PostgresOpenAiCredentialSource::new(
                    pool.clone(),
                    vault,
                    "openai-key".to_owned(),
                    Some(
                        OpenAiApiKey::from_bytes(b"environment-provider-key".to_vec())
                            .map_err(|error| error.to_string())?,
                    ),
                )
                .map_err(|error| error.to_string())?,
            );
            let provider = Arc::new(OpenAiProvider::new_with_credential_source(
                OpenAiProviderConfig::new_with_transport_policy(
                    Url::parse(&format!("http://{address}/v1/responses"))
                        .map_err(|error| error.to_string())?,
                    "package-model".to_owned(),
                    OpenAiProtocol::Responses,
                    SafeHttpBudget::new(64 * 1024, Duration::from_secs(2))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_secs(1)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
                credentials,
                SafeDialer::new(EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                )),
            ));
            let owner = "runtime-openai-http".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(32),
                )
                .map_err(|error| error.to_string())?,
            );
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                provider,
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 2,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start(runtime, agent.consumer());

            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                2,
                "run-openai-http-1",
                "first request",
            )
            .await?;
            wait_for_terminal(&pool, "run-openai-http-1", "provider answer 1").await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.credentials SET revoked_at=clock_timestamp(), \
                     updated_at=clock_timestamp() WHERE kind='model' AND provider='openai' \
                     AND key_id='openai-key' AND revoked_at IS NULL",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.agents SET configuration= \
                     jsonb_build_object('systemPrompt','Updated system role.') WHERE id='bot-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                3,
                "run-openai-http-2",
                "second request",
            )
            .await?;
            wait_for_terminal(&pool, "run-openai-http-2", "provider answer 2").await?;

            let corrupt_id = Uuid::now_v7();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.credentials( \
                       id,kind,provider,encrypted_value,key_id,metadata \
                     ) VALUES($1,'model','openai','corrupt','openai-key','{}'::jsonb)",
                    &[&corrupt_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                4,
                "run-openai-http-3",
                "corrupt credential must not fall back",
            )
            .await?;
            wait_for_failure(&pool, "run-openai-http-3", "provider_authentication").await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.credentials SET revoked_at=clock_timestamp(), \
                     updated_at=clock_timestamp() WHERE id=$1",
                    &[&corrupt_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let no_fallback = PostgresOpenAiCredentialSource::new(
                pool.clone(),
                missing_vault,
                "openai-key".to_owned(),
                None,
            )
            .map_err(|error| error.to_string())?;
            if !matches!(
                no_fallback.resolve().await,
                Err(OpenAiCredentialError::Missing)
            ) {
                return Err("missing model credential 未保持明确 Missing".to_owned());
            }

            relay.stop().await;
            agent.stop().await;
            let requests = provider_server.await.map_err(|error| error.to_string())??;
            if requests.len() != 2
                || header_value(&requests[0], "authorization") != Some("Bearer stored-provider-key")
                || header_value(&requests[1], "authorization")
                    != Some("Bearer environment-provider-key")
            {
                return Err("stored-first/fresh-revocation credential order 漂移".to_owned());
            }
            for (index, request) in requests.iter().enumerate() {
                let body: serde_json::Value = serde_json::from_str(
                    request
                        .split("\r\n\r\n")
                        .nth(1)
                        .ok_or("provider request body missing")?,
                )
                .map_err(|error| error.to_string())?;
                let expected_role = if index == 0 {
                    "Test system role."
                } else {
                    "Updated system role."
                };
                if body["model"] != "package-model"
                    || body["input"][0]["role"] != "system"
                    || !body["input"][0]["content"]
                        .as_str()
                        .is_some_and(|value| value.starts_with(expected_role))
                {
                    return Err(format!("package model/standing prompt 漂移：{body:?}"));
                }
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let reasoning_count: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.run_events \
                     WHERE run_id='run-openai-http-1' \
                       AND event_type='semantic_chunk' AND payload->>'channel'='reasoning'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if reasoning_count != 1 {
                return Err(format!("reasoning durable channel 漂移：{reasoning_count}"));
            }
            let invoked_count: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events \
                     WHERE event_type='agent.invoked' AND target_id LIKE 'run-openai-http-%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if invoked_count != 3 {
                return Err(format!("OpenAI invoked audit count 漂移：{invoked_count}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn managed_route_runs_anthropic_and_google_without_touching_package_provider() {
    let admin = batch6_admin_config(
        "managed_route_runs_anthropic_and_google_without_touching_package_provider",
    );
    with_temp_database(&admin, "agentmanaged", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.agents SET configuration=jsonb_build_object( \
                       'systemPrompt','Managed system role.','providerSource','managed' \
                     ) WHERE id='bot-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let owner = "runtime-managed".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?,
            );
            let package = Arc::new(RejectingPackageProvider::default());
            let harness = ManagedRunHarness {
                runtime,
                context,
                package: package.clone(),
                directory: &directory,
                pool: &pool,
                deployment: &deployment,
                tenant: &tenant,
            };

            let anthropic_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let anthropic_address = anthropic_listener
                .local_addr()
                .map_err(|error| error.to_string())?;
            let anthropic_server = tokio::spawn(one_anthropic_response(anthropic_listener));
            let anthropic: Arc<dyn ProviderAdapter> = Arc::new(AnthropicProvider::new(
                AnthropicProviderConfig::new_with_transport_policy(
                    Url::parse(&format!("http://{anthropic_address}/v1/messages"))
                        .map_err(|error| error.to_string())?,
                    "claude-sonnet-4-5".to_owned(),
                    AnthropicApiKey::from_bytes(b"anthropic-managed-key".to_vec())
                        .map_err(|error| error.to_string())?,
                    SafeHttpBudget::new(64 * 1024, Duration::from_secs(2))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_secs(1)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
                SafeDialer::new(EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                )),
            ));
            harness
                .run(
                    anthropic,
                    5,
                    "run-managed-anthropic",
                    "anthropic managed",
                )
                .await?;
            anthropic_server
                .await
                .map_err(|error| error.to_string())??;

            let google_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let google_address = google_listener
                .local_addr()
                .map_err(|error| error.to_string())?;
            let google_server = tokio::spawn(one_google_response(google_listener));
            let google: Arc<dyn ProviderAdapter> = Arc::new(GoogleProvider::new(
                GoogleProviderConfig::new_with_transport_policy(
                    Url::parse(&format!(
                        "http://{google_address}/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
                    ))
                    .map_err(|error| error.to_string())?,
                    "gemini-2.5-flash".to_owned(),
                    GoogleApiKey::from_bytes(b"google-managed-key".to_vec())
                        .map_err(|error| error.to_string())?,
                    SafeHttpBudget::new(64 * 1024, Duration::from_secs(2))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_secs(1)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
                SafeDialer::new(EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                )),
            ));
            harness
                .run(google, 6, "run-managed-google", "google managed")
                .await?;
            google_server.await.map_err(|error| error.to_string())??;
            if package.calls.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                return Err("managed route touched package provider".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let invoked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events \
                     WHERE event_type='agent.invoked' AND target_id LIKE 'run-managed-%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if invoked != 2 {
                return Err(format!("managed invoked audit count 漂移：{invoked}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn cross_replica_durable_cancel_drops_the_active_child_before_cancelled_terminal() {
    let admin = batch6_admin_config(
        "cross_replica_durable_cancel_drops_the_active_child_before_cancelled_terminal",
    );
    with_temp_database(&admin, "agentcancel", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let owner = "runtime-user-cancel".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config.clone(),
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );
            let child_dropped = Arc::new(AtomicBool::new(false));
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                Arc::new(CancellationHoldingContext {
                    dropped: child_dropped.clone(),
                }),
                Arc::new(RejectingPackageProvider::default()),
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_millis(10),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let relay = RunRelay::start_with_database(
                runtime,
                agent.consumer(),
                config.with_application_name("test-run-control-listener"),
            );
            let thread = begin_test_run(
                &directory,
                &deployment,
                &tenant,
                6,
                "run-user-cancel",
                "hold until user stop",
            )
            .await?;

            let mut invoked = false;
            for _ in 0..100 {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let row = client
                    .query_one(
                        "SELECT o.status,
                                EXISTS(SELECT 1 FROM public.audit_events
                                  WHERE event_type='agent.invoked'
                                    AND target_id='run-user-cancel')
                         FROM public.outbox o
                         WHERE o.outbox_id='run-user-cancel:agent_run_dispatch'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let dispatch: String = row.try_get(0).map_err(|error| error.to_string())?;
                let audited: bool = row.try_get(1).map_err(|error| error.to_string())?;
                if dispatch == "delivered" && audited {
                    invoked = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if !invoked || child_dropped.load(Ordering::SeqCst) {
                return Err(format!(
                    "active child precondition drifted: invoked={invoked} dropped={}",
                    child_dropped.load(Ordering::SeqCst)
                ));
            }

            let request = directory
                .cancel_thread_run(CancelThreadRunRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: ActorId::new("actor-a"),
                    command: CancelThreadRun {
                        thread_id: thread,
                        run_id: RunId::new("run-user-cancel"),
                    },
                })
                .await
                .map_err(|error| error.to_string())?;
            if request.state != ThreadRunCancellationState::Requested {
                return Err(format!("cancel request was not newly durable: {request:?}"));
            }
            wait_for_status(&pool, "run-user-cancel", "cancelled", None).await?;
            let mut cancel_delivered = false;
            for _ in 0..100 {
                let client = pool.get().await.map_err(|error| error.to_string())?;
                let status: String = client
                    .query_one(
                        "SELECT status FROM public.outbox
                         WHERE outbox_id='run-user-cancel:agent_run_cancel'",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .try_get(0)
                    .map_err(|error| error.to_string())?;
                if status == "delivered" {
                    cancel_delivered = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            relay.stop().await;
            agent.stop().await;
            if !child_dropped.load(Ordering::SeqCst) || !cancel_delivered {
                return Err(format!(
                    "cancel child/order did not settle: dropped={} delivered={cancel_delivered}",
                    child_dropped.load(Ordering::SeqCst)
                ));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let shape: (i64, i64) = {
                let row = client
                    .query_one(
                        "SELECT
                           (SELECT count(*)::bigint FROM public.run_events
                             WHERE run_id='run-user-cancel' AND event_type='cancelled'),
                           (SELECT count(*)::bigint FROM public.run_events
                             WHERE run_id='run-user-cancel' AND terminal)",
                        &[],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                )
            };
            if shape != (1, 1) {
                return Err(format!("cancel terminal cardinality drifted: {shape:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn deadline_and_real_stream_stall_append_hash_chain_audits_before_terminal() {
    let admin = batch6_admin_config(
        "deadline_and_real_stream_stall_append_hash_chain_audits_before_terminal",
    );
    with_temp_database(&admin, "agentaudit", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("dep-a");
            let tenant = TenantId::new("tenant-a");
            let owner = "runtime-audit".to_owned();
            let directory = PostgresThreadDirectory::with_runtime(
                pool.clone(),
                config,
                owner.clone(),
                DEFAULT_THREAD_LEASE_DURATION,
            )
            .map_err(|error| error.to_string())?;
            let runtime: Arc<dyn RunRuntime> = Arc::new(
                PostgresRunRuntime::new(
                    pool.clone(),
                    owner,
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|error| error.to_string())?,
            );

            let deadline_agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                Arc::new(HoldingAgentContext),
                Arc::new(RejectingPackageProvider::default()),
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_millis(5),
                    run_deadline: Some(Duration::from_millis(30)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let deadline_relay = RunRelay::start(runtime.clone(), deadline_agent.consumer());
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                7,
                "run-audit-deadline",
                "deadline",
            )
            .await?;
            wait_for_status(&pool, "run-audit-deadline", "cancelled", None).await?;
            deadline_relay.stop().await;
            deadline_agent.stop().await;

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let address = listener.local_addr().map_err(|error| error.to_string())?;
            let stall_server = tokio::spawn(one_stalling_openai_response(listener));
            let openai: Arc<dyn ProviderAdapter> = Arc::new(OpenAiProvider::new(
                OpenAiProviderConfig::new_with_transport_policy(
                    Url::parse(&format!("http://{address}/v1/responses"))
                        .map_err(|error| error.to_string())?,
                    "model".to_owned(),
                    OpenAiProtocol::Responses,
                    SafeHttpBudget::new(64 * 1024, Duration::from_secs(2))
                        .map_err(|error| error.to_string())?,
                    Some(Duration::from_millis(20)),
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?,
                OpenAiApiKey::from_bytes(b"stall-key".to_vec())
                    .map_err(|error| error.to_string())?,
                SafeDialer::new(EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                )),
            ));
            let stall_provider = Arc::new(
                RetryingProvider::new(openai, RetryingProviderConfig::default())
                    .map_err(|error| error.to_string())?,
            );
            let context = Arc::new(
                PostgresAgentContextSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    Some(64),
                )
                .map_err(|error| error.to_string())?,
            );
            let stall_agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                context,
                stall_provider,
                Arc::new(NoAgentToolInvoker),
                Arc::new(
                    PostgresAgentAudit::new(pool.clone(), vec![0xa5; 32])
                        .map_err(|error| error.to_string())?,
                ),
                BuiltInAgentConfig {
                    queue_capacity: 4,
                    max_concurrency: 1,
                    max_tool_concurrency: 2,
                    lease_renew_interval: Duration::from_secs(1),
                    run_deadline: Some(Duration::from_secs(5)),
                },
            )
            .map_err(|code| format!("agent config {code:?}"))?;
            let stall_relay = RunRelay::start(runtime, stall_agent.consumer());
            begin_test_run(
                &directory,
                &deployment,
                &tenant,
                8,
                "run-audit-stall",
                "stall",
            )
            .await?;
            wait_for_status(
                &pool,
                "run-audit-stall",
                "failed",
                Some("agent_stream_stalled"),
            )
            .await?;
            stall_relay.stop().await;
            stall_agent.stop().await;
            stall_server.await.map_err(|error| error.to_string())??;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query(
                    "SELECT event_type,target_id,payload,prev_hash,row_hash \
                     FROM public.audit_events ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let shapes = rows
                .iter()
                .map(|row| {
                    Ok::<_, String>((
                        row.try_get::<_, String>(0)
                            .map_err(|error| error.to_string())?,
                        row.try_get::<_, Option<String>>(1)
                            .map_err(|error| error.to_string())?,
                        row.try_get::<_, serde_json::Value>(2)
                            .map_err(|error| error.to_string())?,
                        row.try_get::<_, Option<String>>(3)
                            .map_err(|error| error.to_string())?,
                        row.try_get::<_, Option<String>>(4)
                            .map_err(|error| error.to_string())?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if shapes.len() != 4
                || shapes[0].0 != "agent.invoked"
                || shapes[1].0 != "agent.run_deadline_exceeded"
                || shapes[2].0 != "agent.invoked"
                || shapes[3].0 != "agent.stream_stalled"
                || shapes[1].1.as_deref() != Some("run-audit-deadline")
                || shapes[3].1.as_deref() != Some("run-audit-stall")
                || shapes[1].2["error_code"] != "run_deadline_exceeded"
                || shapes[3].2["error_code"] != "agent_stream_stalled"
                || shapes.iter().any(|shape| shape.4.is_none())
                || shapes.iter().skip(1).any(|shape| shape.3.is_none())
            {
                return Err(format!("Agent lifecycle audit chain 漂移：{shapes:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

struct ManagedRunHarness<'a> {
    runtime: Arc<dyn RunRuntime>,
    context: Arc<PostgresAgentContextSource>,
    package: Arc<RejectingPackageProvider>,
    directory: &'a PostgresThreadDirectory,
    pool: &'a openbot_infra::db::pool::DatabasePool,
    deployment: &'a DeploymentId,
    tenant: &'a TenantId,
}

impl ManagedRunHarness<'_> {
    async fn run(
        &self,
        managed: Arc<dyn ProviderAdapter>,
        entropy_tail: u8,
        run_id: &str,
        expected_text: &str,
    ) -> Result<(), String> {
        let router: Arc<dyn ProviderAdapter> =
            Arc::new(ProviderRouter::new(self.package.clone(), Some(managed)));
        let provider = Arc::new(
            RetryingProvider::new(router, RetryingProviderConfig::default())
                .map_err(|error| error.to_string())?,
        );
        let agent = BuiltInAgentRuntime::start(
            self.runtime.clone(),
            self.context.clone(),
            provider,
            Arc::new(NoAgentToolInvoker),
            Arc::new(
                PostgresAgentAudit::new(self.pool.clone(), vec![0xa5; 32])
                    .map_err(|error| error.to_string())?,
            ),
            BuiltInAgentConfig {
                queue_capacity: 4,
                max_concurrency: 2,
                max_tool_concurrency: 2,
                lease_renew_interval: Duration::from_secs(1),
                run_deadline: Some(Duration::from_secs(5)),
            },
        )
        .map_err(|code| format!("agent config {code:?}"))?;
        let relay = RunRelay::start(self.runtime.clone(), agent.consumer());
        begin_test_run(
            self.directory,
            self.deployment,
            self.tenant,
            entropy_tail,
            run_id,
            "managed request",
        )
        .await?;
        wait_for_terminal(self.pool, run_id, expected_text).await?;
        relay.stop().await;
        agent.stop().await;
        Ok(())
    }
}

fn batch6_admin_config(test_name: &str) -> DatabaseConfig {
    let Ok(socket) = std::env::var("OPENBOT_TEST_DATABASE_SOCKET") else {
        return admin_config(test_name);
    };
    let port = std::env::var("OPENBOT_TEST_DATABASE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(5432);
    let user =
        std::env::var("OPENBOT_TEST_DATABASE_USER").unwrap_or_else(|_| "postgres".to_owned());
    DatabaseConfig::new(socket, port, user, "postgres")
        .with_application_name("openbot-postgres-integration-test")
        .with_max_pool_size(2)
}

async fn begin_test_run(
    directory: &PostgresThreadDirectory,
    deployment: &DeploymentId,
    tenant: &TenantId,
    entropy_tail: u8,
    run_id: &str,
    message: &str,
) -> Result<openbot_contracts::ids::ThreadId, String> {
    begin_test_run_for_bot(
        directory,
        deployment,
        tenant,
        entropy_tail,
        run_id,
        "bot-1",
        message,
    )
    .await
}

async fn begin_test_run_for_bot(
    directory: &PostgresThreadDirectory,
    deployment: &DeploymentId,
    tenant: &TenantId,
    entropy_tail: u8,
    run_id: &str,
    bot_id: &str,
    message: &str,
) -> Result<openbot_contracts::ids::ThreadId, String> {
    let mut entropy = [0_u8; 16];
    entropy[15] = entropy_tail;
    let thread = ThreadIdentity::new(deployment).mint_from_entropy(entropy);
    directory
        .begin_thread_run(BeginThreadRunRequest {
            auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new("actor-a"),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                model_selection: None,
                selected_skill_slugs: Vec::new(),
                thread_id: thread.clone(),
                run_id: RunId::new(run_id),
                bot_id: BotId::new(bot_id),
                anchor: ThreadRunAnchor::DirectBot,
                message: message.to_owned(),
            },
        })
        .await
        .map(|_| thread)
        .map_err(|error| error.to_string())
}

async fn wait_for_terminal(
    pool: &openbot_infra::db::pool::DatabasePool,
    run_id: &str,
    expected_text: &str,
) -> Result<(), String> {
    for _ in 0..200 {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT status,error_code,(SELECT content->>'text' FROM public.messages \
                 WHERE run_id=$1 AND role='assistant' ORDER BY seq DESC LIMIT 1) \
                 FROM public.runs WHERE run_id=$1",
                &[&run_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        let status: String = row.try_get(0).map_err(|error| error.to_string())?;
        if status != "running" {
            let error: Option<String> = row.try_get(1).map_err(|error| error.to_string())?;
            let text: Option<String> = row.try_get(2).map_err(|error| error.to_string())?;
            return if status == "completed"
                && error.is_none()
                && text.as_deref() == Some(expected_text)
            {
                Ok(())
            } else {
                Err(format!(
                    "run {run_id} terminal 漂移：{status}/{error:?}/{text:?}"
                ))
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("run {run_id} 未在本地期限内 terminal"))
}

async fn wait_for_remote_projection_count(
    pool: &openbot_infra::db::pool::DatabasePool,
    run_id: &str,
    expected: i64,
) -> Result<(), String> {
    for _ in 0..200 {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let count: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM public.run_events \
                 WHERE run_id=$1 AND event_type='checkpoint' \
                   AND payload->>'kind'='remote_agui_projection' \
                   AND payload->>'retained' IS NULL",
                &[&run_id],
            )
            .await
            .map_err(|error| error.to_string())?
            .try_get(0)
            .map_err(|error| error.to_string())?;
        if count == expected {
            return Ok(());
        }
        if count > expected {
            return Err(format!(
                "run {run_id} remote projection count exceeded {expected}: {count}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!(
        "run {run_id} did not persist {expected} active remote projections"
    ))
}

async fn wait_for_failure(
    pool: &openbot_infra::db::pool::DatabasePool,
    run_id: &str,
    expected_code: &str,
) -> Result<(), String> {
    for _ in 0..200 {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&run_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        let status: String = row.try_get(0).map_err(|error| error.to_string())?;
        if status != "running" {
            let code: Option<String> = row.try_get(1).map_err(|error| error.to_string())?;
            return if status == "failed" && code.as_deref() == Some(expected_code) {
                Ok(())
            } else {
                Err(format!("run {run_id} failure 漂移：{status}/{code:?}"))
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("run {run_id} 未在本地期限内 failed"))
}

async fn wait_for_status(
    pool: &openbot_infra::db::pool::DatabasePool,
    run_id: &str,
    expected_status: &str,
    expected_code: Option<&str>,
) -> Result<(), String> {
    for _ in 0..200 {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let row = client
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&run_id],
            )
            .await
            .map_err(|error| error.to_string())?;
        let status: String = row.try_get(0).map_err(|error| error.to_string())?;
        if status != "running" {
            let code: Option<String> = row.try_get(1).map_err(|error| error.to_string())?;
            return if status == expected_status && code.as_deref() == expected_code {
                Ok(())
            } else {
                Err(format!("run {run_id} status 漂移：{status}/{code:?}"))
            };
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("run {run_id} 未在本地期限内到达 {expected_status}"))
}

async fn one_stalling_openai_response(listener: TcpListener) -> Result<(), String> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .map_err(|_| "stall provider local accept timeout".to_owned())?
        .map_err(|error| error.to_string())?;
    let _request = read_http_request(&mut stream).await?;
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = stream.write_all(b"d\r\ndata: late\n\n\r\n0\r\n\r\n").await;
    Ok(())
}

#[derive(Clone, Copy)]
enum RemoteFailureFixture {
    RunError,
    MalformedMessage,
}

async fn one_remote_agui_failure(
    listener: TcpListener,
    expected_run: &'static str,
    fixture: RemoteFailureFixture,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
    let request = read_http_request(&mut stream).await?;
    if !request.starts_with("POST /ag-ui ") {
        return Err("remote AG-UI failure path drift".to_owned());
    }
    let input: serde_json::Value = serde_json::from_str(
        request
            .split("\r\n\r\n")
            .nth(1)
            .ok_or_else(|| "remote failure request body missing".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    if input["runId"] != expected_run {
        return Err(format!("remote failure run drift: {input:?}"));
    }
    let thread_id = input["threadId"]
        .as_str()
        .ok_or_else(|| "remote failure thread missing".to_owned())?;
    let terminal = match fixture {
        RemoteFailureFixture::RunError => serde_json::json!({
            "type":"RUN_ERROR",
            "message":"REMOTE_ERROR_SECRET_CANARY",
            "code":"vendor-secret-code"
        }),
        RemoteFailureFixture::MalformedMessage => serde_json::json!({
            "type":"MESSAGES_SNAPSHOT",
            "messages":[{"id":"bad","role":"assistant","content":{"secret":"REMOTE_ERROR_SECRET_CANARY"}}]
        }),
    };
    let events = [
        serde_json::json!({"type":"RUN_STARTED","threadId":thread_id,"runId":expected_run}),
        terminal,
    ];
    let body = events
        .into_iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect::<String>();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn one_anthropic_response(listener: TcpListener) -> Result<(), String> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .map_err(|_| "Anthropic local accept timeout".to_owned())?
        .map_err(|error| error.to_string())?;
    let request = read_http_request(&mut stream).await?;
    if header_value(&request, "x-api-key") != Some("anthropic-managed-key")
        || header_value(&request, "anthropic-version") != Some("2023-06-01")
    {
        return Err("Anthropic managed credential headers 漂移".to_owned());
    }
    let body: serde_json::Value = serde_json::from_str(
        request
            .split("\r\n\r\n")
            .nth(1)
            .ok_or("Anthropic request body missing")?,
    )
    .map_err(|error| error.to_string())?;
    if body["model"] != "claude-sonnet-4-5"
        || !body["system"]
            .as_str()
            .is_some_and(|value| value.starts_with("Managed system role."))
    {
        return Err(format!("Anthropic managed request 漂移：{body:?}"));
    }
    let sse = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"managed-a\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"anthropic managed\"}}\n\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    write_sse_response(&mut stream, sse).await
}

async fn one_google_response(listener: TcpListener) -> Result<(), String> {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .map_err(|_| "Google local accept timeout".to_owned())?
        .map_err(|error| error.to_string())?;
    let request = read_http_request(&mut stream).await?;
    if header_value(&request, "x-goog-api-key") != Some("google-managed-key")
        || request.contains("key=google-managed-key")
    {
        return Err("Google managed credential placement 漂移".to_owned());
    }
    let body: serde_json::Value = serde_json::from_str(
        request
            .split("\r\n\r\n")
            .nth(1)
            .ok_or("Google request body missing")?,
    )
    .map_err(|error| error.to_string())?;
    if !body["systemInstruction"]["parts"][0]["text"]
        .as_str()
        .is_some_and(|value| value.starts_with("Managed system role."))
    {
        return Err(format!("Google managed request 漂移：{body:?}"));
    }
    let sse = "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"google managed\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":2,\"totalTokenCount\":3}}\n\n";
    write_sse_response(&mut stream, sse).await
}

async fn write_sse_response(stream: &mut TcpStream, body: &str) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(|error| error.to_string())
}

async fn recording_openai_server(listener: TcpListener) -> Result<Vec<String>, String> {
    let mut requests = Vec::new();
    for index in 1..=2 {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .map_err(|_| "provider local accept timeout".to_owned())?
            .map_err(|error| error.to_string())?;
        requests.push(read_http_request(&mut stream).await?);
        let reasoning = if index == 1 {
            concat!(
                "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"reasoning\"},\"sequence_number\":1}\n\n",
                "data: {\"type\":\"response.reasoning_text.delta\",\"output_index\":0,\"delta\":\"private thought\",\"sequence_number\":2}\n\n"
            )
        } else {
            ""
        };
        let text_sequence = if index == 1 { 3 } else { 1 };
        let complete_sequence = text_sequence + 1;
        let body = format!(
            "data: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_{index}\"}},\"sequence_number\":0}}\n\n{reasoning}data: {{\"type\":\"response.output_text.delta\",\"output_index\":1,\"delta\":\"provider answer {index}\",\"sequence_number\":{text_sequence}}}\n\ndata: {{\"type\":\"response.completed\",\"response\":{{\"usage\":{{\"input_tokens\":2,\"output_tokens\":3,\"total_tokens\":5}}}},\"sequence_number\":{complete_sequence}}}\n\n"
        );
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(body.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(requests)
}

async fn read_http_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("provider request ended before headers".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = core::str::from_utf8(&bytes[..header_end]).map_err(|error| error.to_string())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.parse::<usize>().ok())
        })
        .ok_or("provider request content-length missing")?;
    while bytes.len() < header_end + content_length {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("provider request ended before body".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}
