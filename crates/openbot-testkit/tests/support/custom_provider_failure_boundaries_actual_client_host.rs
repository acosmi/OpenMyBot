//! Actual assembled finite C3 host. IPC observes real runs; only the browser starts them.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use openbot_agent::{
    AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime, ProviderRouter,
    RemoteAguiProvider, RetryingProvider, RetryingProviderConfig,
};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderMessageRole, ProviderPortError,
    ProviderRequest, ProviderRoute, ProviderSession, RunModelBinding, remember_provider_tool,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::agent_audit::PostgresAgentAudit;
use openbot_infra::agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::{fresh, pool};
use openbot_infra::net::safe_http::{SafeHttpBudget, SchemePolicy};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::custom::PostgresCustomModelProvider;
use openbot_infra::provider::openai::{
    OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig,
};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use openbot_infra::run_runtime::RunRelay;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder, StaticApp,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::{Mutex, mpsc, oneshot};
use url::Url;
use uuid::Uuid;

use super::custom_provider_failure_boundaries_tls_fixture::{
    Counts, FaultMode, OwnedWire, PositiveStreamWitness, PositiveSubscription, WireRecord,
};

const INTENT_B_PREFIX: &str = "owned C3 partial current text";
const INTENT_A: &str = "owned C3 positive request";
const INTENT_B: &str = "owned C3 boundary request";
const DEPLOYMENT: &str = "owned-customboundary-client-deployment";
const TENANT: &str = "owned-customboundary-client-tenant";
const SESSION_KEY: &[u8] = b"owned-customboundary-client-session-key-at-least-32-bytes";
const MODEL_KEY: &str = "owned-c3-model-key";
const MANAGED_KEY: &str = "owned-c3-managed-key";
const MODEL: &str = "owned-c3-model";
const POSITIVE_TEXT: &str = "owned C3 custom positive text";
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);

// Existing non-production idp.test test CA/leaf/key; no system trust or vendor key is used.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default)]
struct Counters {
    custom: AtomicU64,
    package: AtomicU64,
    managed: AtomicU64,
    remote_validate: AtomicU64,
    remote_start: AtomicU64,
    api_ingress: AtomicU64,
    model_post: AtomicU64,
    agent_post: AtomicU64,
    mint_post: AtomicU64,
    begin_post: AtomicU64,
    cap_get: AtomicU64,
    served_index: AtomicU64,
    sequence: AtomicU64,
    collection_failed: AtomicBool,
}

struct CountingCustom {
    inner: Arc<PostgresCustomModelProvider>,
    counters: Arc<Counters>,
    observations: Arc<FaultObservations>,
    dependency: Arc<DependencyController>,
}

#[async_trait]
impl ProviderAdapter for CountingCustom {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let target = Target::from_request(&request);
        if let Some(target) = &target
            && target.is_b
            && self.dependency.mode == FaultMode::PreSendDependency
            && let Err(code) = self.dependency.arm(target.clone()).await
        {
            self.observations.fail(&code).await;
        }
        // Count only the unchanged call actually delegated to the original adapter.
        self.counters.custom.fetch_add(1, Ordering::SeqCst);
        let index = self.observations.begin(target.as_ref()).await;
        let watcher = if target.as_ref().is_some_and(|target| target.is_b)
            && self.dependency.mode == FaultMode::PreSendDependency
        {
            Some(
                self.dependency
                    .watch(index, self.observations.clone())
                    .await,
            )
        } else {
            None
        };
        let result = self.inner.start(request).await;
        let label = match &result {
            Ok(_) => "session",
            Err(ProviderPortError::Unavailable) => "unavailable",
            Err(ProviderPortError::CommitUnknown) => "commit_unknown",
            Err(ProviderPortError::InvalidRequest { .. }) => "invalid_request",
        };
        self.observations.start_return(index, label).await;
        if let Some((stop, task)) = watcher {
            let _ = stop.send(());
            match tokio::time::timeout(CLOSE_TIMEOUT, task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(code))) => self.observations.fail(&code).await,
                _ => {
                    self.observations
                        .fail("owned_dependency_observer_join")
                        .await
                }
            }
        }
        // Every original port result and session event is forwarded without substitution.
        result.map(|inner| {
            Box::new(CountingSession {
                inner,
                index,
                observations: self.observations.clone(),
            }) as Box<dyn ProviderSession>
        })
    }
}

struct CountingSession {
    inner: Box<dyn ProviderSession>,
    index: usize,
    observations: Arc<FaultObservations>,
}

#[async_trait]
impl ProviderSession for CountingSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        let result = self.inner.next_event().await;
        self.observations.event(self.index, &result).await;
        result
    }
}

#[derive(Clone)]
struct Target {
    binding: RunModelBinding,
    run: String,
    thread: String,
    bot: String,
    is_b: bool,
}

impl Target {
    fn from_request(request: &ProviderRequest) -> Option<Self> {
        let ProviderRoute::CustomModel(binding) = &request.route else {
            return None;
        };
        let lease = binding.identity_lease().ok()?;
        let last = request
            .messages
            .iter()
            .rev()
            .find(|message| message.role == ProviderMessageRole::User)?;
        if last.content != INTENT_A && last.content != INTENT_B {
            return None;
        }
        Some(Self {
            binding: binding.clone(),
            run: lease.run_id().as_str().to_owned(),
            thread: lease.thread_id().as_str().to_owned(),
            bot: lease.bot_id().as_str().to_owned(),
            is_b: last.content == INTENT_B,
        })
    }
}

struct FaultObservations {
    mode: String,
    started: tokio::time::Instant,
    attempts: Mutex<Vec<Value>>,
    counters: Arc<Counters>,
    errors: Arc<Mutex<Value>>,
}

impl FaultObservations {
    async fn fail(&self, code: &str) {
        self.counters
            .collection_failed
            .store(true, Ordering::SeqCst);
        let mut facts = self.errors.lock().await;
        if facts["error"].is_null() {
            facts["error"] = json!(code);
        }
    }

    async fn begin(&self, target: Option<&Target>) -> usize {
        let mut attempts = self.attempts.lock().await;
        let index = attempts.len();
        if index >= 8 || target.is_none() {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        let value = target.map_or_else(|| json!({
            "ordinal":index+1,"runId":null,"threadId":null,"botId":null,"actorId":null,
            "authGeneration":null,"connectionId":null,"connectionRevision":null,"secretId":null,
            "isB":false,"startElapsedMs":self.started.elapsed().as_millis(),
            "startReturnElapsedMs":null,"startResult":null,"firstEvent":null,"terminalEvent":null,"blockedQuery":null
        }), |target| json!({
            "ordinal":index+1,"runId":target.run,"threadId":target.thread,"botId":target.bot,
            "actorId":target.binding.actor().as_str(),"authGeneration":target.binding.auth_generation().get(),
            "connectionId":target.binding.connection_id(),"connectionRevision":target.binding.connection_revision(),
            "secretId":target.binding.secret_id(),"isB":target.is_b,
            "startElapsedMs":self.started.elapsed().as_millis(),"startReturnElapsedMs":null,
            "startResult":null,"firstEvent":null,"terminalEvent":null,"blockedQuery":null
        }));
        attempts.push(value);
        index
    }

    async fn start_return(&self, index: usize, label: &str) {
        if let Some(row) = self.attempts.lock().await.get_mut(index) {
            row["startReturnElapsedMs"] = json!(self.started.elapsed().as_millis());
            row["startResult"] = json!(label);
        } else {
            self.fail("owned_attempt_missing").await;
        }
    }

    async fn event(&self, index: usize, result: &Result<Option<ProviderEvent>, ProviderPortError>) {
        let label = match result {
            Ok(Some(ProviderEvent::ResponseStarted { .. })) => "response_started".to_owned(),
            Ok(Some(ProviderEvent::OutputItemAdded { .. })) => "output_item_added".to_owned(),
            Ok(Some(ProviderEvent::TextDelta { .. })) => "text_delta".to_owned(),
            Ok(Some(ProviderEvent::Completed)) => "completed".to_owned(),
            Ok(Some(ProviderEvent::Failed(failure))) => format!(
                "failed:{}",
                match failure {
                    ProviderFailure::Authentication => "authentication",
                    ProviderFailure::RateLimited { .. } => "rate_limited",
                    ProviderFailure::ServerUnavailable { .. } => "server_unavailable",
                    ProviderFailure::InvalidResponse => "invalid_response",
                    ProviderFailure::StreamStalled => "stream_stalled",
                    ProviderFailure::Transport => "transport",
                    ProviderFailure::GenerationFailed => "generation_failed",
                }
            ),
            Ok(Some(_)) => "other".to_owned(),
            Ok(None) => "end_of_stream".to_owned(),
            Err(ProviderPortError::Unavailable) => "port_error:unavailable".to_owned(),
            Err(ProviderPortError::CommitUnknown) => "port_error:commit_unknown".to_owned(),
            Err(ProviderPortError::InvalidRequest { .. }) => {
                "port_error:invalid_request".to_owned()
            }
        };
        if let Some(row) = self.attempts.lock().await.get_mut(index) {
            if row["firstEvent"].is_null() {
                row["firstEvent"] = json!(label);
            }
            if matches!(
                result,
                Ok(Some(ProviderEvent::Completed | ProviderEvent::Failed(_)))
            ) {
                row["terminalEvent"] = json!(label);
            }
        } else {
            self.fail("owned_attempt_missing").await;
        }
    }
}

const APPLICATION_NAME: &str = "owned-customboundary-client-application";
const CONTROLLER_NAME: &str = "owned-customboundary-client-controller";
const AUTHORIZED_QUERY_SHA256: &str =
    "64c1f5489f141eaad010ec09dfa335d61cd7f3de47055cc83f6be1b09752095c";

// Full fixed production query, used only to observe exact owned query disappearance.
const AUTHORIZED_CURRENT_QUERY: &str = "SELECT c.name,c.protocol,c.endpoint,c.model,\n        (r.budget_cost_currency IS NOT NULL OR r.budget_max_cost_micro_units IS NOT NULL) AS has_cost_cap\n        FROM public.model_connections c\n        JOIN public.run_model_selections s ON s.connection_id=c.id AND s.run_id=$1\n        JOIN public.runs r ON r.run_id=s.run_id JOIN public.threads t ON t.thread_id=r.thread_id\n        JOIN public.messages input ON input.message_id=r.run_id||':input'\n        JOIN public.agents a ON a.id=r.bot_id JOIN public.agent_profiles p ON p.agent_id=a.id\n        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id\n        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 AND r.fencing_token=$5\n          AND r.status='running' AND t.deployment_id=$6 AND t.tenant_id=$7 AND t.status='active'\n          AND EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4 AND coalesce(u.auth_generation,0)=$8\n            AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))\n            AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)))\n          AND EXISTS(SELECT 1 FROM public.thread_leases l WHERE l.thread_id=t.thread_id\n            AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp())\n          AND input.role='user' AND input.run_id=r.run_id AND input.thread_id=t.thread_id AND input.actor_id=r.actor_id\n          AND input.content->'modelSelection'=$15::jsonb\n          AND s.deployment_id=$6 AND s.tenant_id=$7 AND s.owner_user_id=$4 AND s.auth_generation=$8\n          AND s.connection_id=$9 AND s.connection_revision=$10 AND s.secret_id=$11\n          AND s.protocol=$12 AND s.endpoint=$13 AND s.model=$14 AND s.created_at=r.created_at\n          AND c.deployment_id=$6 AND c.tenant_id=$7 AND c.owner_user_id=$4\n          AND c.revision=s.connection_revision AND c.current_secret_id=s.secret_id\n          AND c.protocol=s.protocol AND c.endpoint=s.endpoint AND c.model=s.model\n          AND c.enabled AND c.deleted_at IS NULL\n          AND a.type='built_in' AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$7)\n          AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(\n            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))\n          AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(\n            SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4))\n            OR (t.anchor_kind='channel' AND EXISTS(SELECT 1 FROM public.channels ch\n              JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4\n              JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id\n              LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id\n              WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$7))))\n         FOR SHARE OF c";

// Exact test-only row lock. It is acquired only after the original context made this binding.
// No product row is inserted, updated, deleted or accepted from a renderer/control DTO.
const LOCK_CURRENT_B: &str = "SELECT c.id FROM public.model_connections c
 JOIN public.run_model_selections s ON s.connection_id=c.id
 JOIN public.runs r ON r.run_id=s.run_id JOIN public.threads t USING(thread_id)
 JOIN public.messages input ON input.message_id=r.run_id||':input' AND input.run_id=r.run_id
 JOIN public.model_connection_secrets secret ON secret.id=c.current_secret_id AND secret.connection_id=c.id
 JOIN public.users u ON u.id=r.actor_id
 WHERE c.id=$1 AND c.revision=$2 AND c.current_secret_id=$3 AND s.run_id=$4
 AND r.thread_id=$5 AND r.bot_id=$6 AND r.actor_id=$7 AND r.status='running' AND t.status='active'
 AND s.auth_generation=$8 AND u.auth_generation=$8
 AND c.deployment_id=$9 AND c.tenant_id=$10 AND c.owner_user_id=$7
 AND t.deployment_id=$9 AND t.tenant_id=$10
 AND s.deployment_id=$9 AND s.tenant_id=$10 AND s.owner_user_id=$7
 AND s.connection_revision=c.revision AND s.secret_id=c.current_secret_id
 AND s.protocol=c.protocol AND s.endpoint=c.endpoint AND s.model=c.model AND s.created_at=r.created_at
 AND c.protocol=$11 AND c.endpoint=$12 AND c.model=$13 AND c.enabled AND c.deleted_at IS NULL
 AND secret.deployment_id=$9 AND secret.tenant_id=$10 AND secret.owner_user_id=$7 AND secret.retired_at IS NULL
 AND input.role='user' AND input.actor_id=$7 AND input.thread_id=r.thread_id AND input.content->>'text'=$14
 FOR UPDATE OF c";

struct DependencyController {
    pool: Pool,
    mode: FaultMode,
    facts: Arc<Mutex<Value>>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    task: Mutex<Option<tokio::task::JoinHandle<Result<(), String>>>>,
    watch_tasks: Mutex<Vec<tokio::task::JoinHandle<Result<(), String>>>>,
    closing: AtomicBool,
}

impl DependencyController {
    fn new(pool: Pool, mode: FaultMode) -> Self {
        Self {
            pool,
            mode,
            facts: Arc::new(Mutex::new(json!({
                "armed":false,"lockAcquired":false,"runId":null,"threadId":null,"actorId":null,
                "authGeneration":null,"connectionId":null,"connectionRevision":null,"secretId":null,
                "controllerPid":null,"controllerBackendStart":null,"controllerXactStart":null,
                "database":null,"user":null,"applicationName":null,"lockQuerySha256":null,"lockRowMatched":false,
                "rollbackAttempted":false,"rollbackReturned":false,"stopSent":false,"taskJoined":false,
                "remainingBlockedQueries":null,"error":null
            }))),
            stop: Mutex::new(None),
            task: Mutex::new(None),
            watch_tasks: Mutex::new(Vec::new()),
            closing: AtomicBool::new(false),
        }
    }

    async fn fail(&self, code: &str) {
        let mut facts = self.facts.lock().await;
        if facts["error"].is_null() {
            facts["error"] = json!(code);
        }
    }

    async fn arm(&self, target: Target) -> Result<(), String> {
        let mut task_slot = self.task.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err("owned_dependency_closed".to_owned());
        }
        if task_slot.is_some() {
            let facts = self.facts.lock().await;
            if facts["lockAcquired"] == true
                && facts["runId"] == target.run
                && facts["connectionId"] == target.binding.connection_id()
                && facts["connectionRevision"] == target.binding.connection_revision()
                && facts["secretId"] == target.binding.secret_id()
                && facts["actorId"] == target.binding.actor().as_str()
            {
                return Ok(());
            }
            return Err("owned_dependency_rearm_identity".to_owned());
        }
        let id = Uuid::parse_str(target.binding.connection_id())
            .map_err(|_| "owned_dependency_model_id")?;
        let secret = Uuid::parse_str(target.binding.secret_id())
            .map_err(|_| "owned_dependency_secret_id")?;
        {
            let mut facts = self.facts.lock().await;
            facts["armed"] = json!(true);
            facts["runId"] = json!(target.run);
            facts["threadId"] = json!(target.thread);
            facts["actorId"] = json!(target.binding.actor().as_str());
            facts["authGeneration"] = json!(target.binding.auth_generation().get());
            facts["connectionId"] = json!(target.binding.connection_id());
            facts["connectionRevision"] = json!(target.binding.connection_revision());
            facts["secretId"] = json!(target.binding.secret_id());
            facts["lockQuerySha256"] = json!(Sha256Digest::of(LOCK_CURRENT_B.as_bytes()).to_hex());
        }
        let (stop, stopped) = oneshot::channel();
        *self.stop.lock().await = Some(stop);
        let (ready, prepared) = oneshot::channel();
        let facts = self.facts.clone();
        let observer = self.pool.clone();
        *task_slot = Some(tokio::spawn(async move {
            let result = async {
                let deadline=tokio::time::Instant::now()+Duration::from_secs(6);
                let mut client=tokio::time::timeout_at(deadline,observer.get()).await
                    .map_err(|_| "owned_dependency_setup_deadline")?.map_err(|_| "owned_dependency_connection")?;
                let tx=tokio::time::timeout_at(deadline,client.transaction()).await
                    .map_err(|_| "owned_dependency_setup_deadline")?.map_err(|_| "owned_dependency_begin")?;
                // This owned controller also has a genuine six-second SQL budget.
                tokio::time::timeout_at(deadline,tx.query_one("SELECT set_config('statement_timeout','6000',true),set_config('application_name',$1,true)",
                    &[&CONTROLLER_NAME])).await.map_err(|_| "owned_dependency_setup_deadline")?
                    .map_err(|_| "owned_dependency_config")?;
                let generation = i64::try_from(target.binding.auth_generation().get()).map_err(|_| "owned_dependency_generation")?;
                let protocol = match target.binding.protocol() {
                    openbot_contracts::model_connections::CustomModelProtocol::OpenaiChatCompletions => "openai_chat_completions",
                    openbot_contracts::model_connections::CustomModelProtocol::OpenaiResponses => "openai_responses",
                    openbot_contracts::model_connections::CustomModelProtocol::AnthropicMessages => "anthropic_messages",
                };
                let row = tokio::time::timeout_at(deadline,tx.query_opt(LOCK_CURRENT_B, &[&id,&target.binding.connection_revision(),&secret,
                    &target.run,&target.thread,&target.bot,&target.binding.actor().as_str(),&generation,
                    &target.binding.deployment().as_str(),&target.binding.tenant().as_str(),&protocol,
                    &target.binding.endpoint(),&target.binding.model(),&INTENT_B]))
                    .await.map_err(|_| "owned_dependency_setup_deadline")?.map_err(|_| "owned_dependency_actual_lock")?.ok_or("owned_dependency_original_b_missing")?;
                if row.try_get::<_,Uuid>(0).map_err(|_| "owned_dependency_lock_shape")? != id {
                    return Err("owned_dependency_original_b_mismatch".to_owned());
                }
                let identity:Value=tokio::time::timeout_at(deadline,tx.query_one("SELECT jsonb_build_object('pid',a.pid,'backendStart',a.backend_start::text,
                    'xactStart',a.xact_start::text,'database',a.datname,'user',a.usename,'applicationName',a.application_name)
                    FROM pg_stat_activity a WHERE a.pid=pg_backend_pid()",&[]))
                    .await.map_err(|_| "owned_dependency_setup_deadline")?.map_err(|_| "owned_dependency_controller_identity")?.get(0);
                {
                    let mut record = facts.lock().await;
                    record["controllerPid"]=identity["pid"].clone();
                    record["controllerBackendStart"]=identity["backendStart"].clone();
                    record["controllerXactStart"]=identity["xactStart"].clone();
                    record["database"]=identity["database"].clone(); record["user"]=identity["user"].clone();
                    record["applicationName"]=identity["applicationName"].clone();
                    record["lockAcquired"]=json!(true); record["lockRowMatched"]=json!(true);
                }
                ready.send(()).map_err(|_| "owned_dependency_ready_receiver")?;
                stopped.await.map_err(|_| "owned_dependency_stop_receiver")?;
                facts.lock().await["rollbackAttempted"] = json!(true);
                tokio::time::timeout(Duration::from_secs(6),tx.rollback()).await
                    .map_err(|_| "owned_dependency_rollback_deadline")?
                    .map_err(|_| "owned_dependency_rollback")?;
                facts.lock().await["rollbackReturned"] = json!(true);
                Ok::<(),String>(())
            }.await;
            if let Err(code) = &result {
                let mut record = facts.lock().await;
                if record["error"].is_null() {
                    record["error"] = json!(code);
                }
            }
            result
        }));
        drop(task_slot);
        match tokio::time::timeout(Duration::from_secs(6), prepared).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                self.fail("owned_dependency_lock_ready").await;
                Err("owned_dependency_lock_ready".to_owned())
            }
        }
    }

    async fn watch(
        &self,
        index: usize,
        observations: Arc<FaultObservations>,
    ) -> (oneshot::Sender<()>, oneshot::Receiver<Result<(), String>>) {
        let (stop, mut stopped) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let mut tasks = self.watch_tasks.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            let _ = completed.send(Err("owned_dependency_observer_closed".to_owned()));
            return (stop, completion);
        }
        let facts = self.facts.lock().await.clone();
        let pool = self.pool.clone();
        tasks.push(tokio::spawn(async move {
            let result=async {
                let pid=facts["controllerPid"].as_i64().and_then(|pid|i32::try_from(pid).ok()).ok_or("owned_dependency_controller_pid")?;
                let backend=facts["controllerBackendStart"].as_str().ok_or("owned_dependency_controller_backend")?;
                let xact=facts["controllerXactStart"].as_str().ok_or("owned_dependency_controller_xact")?;
                loop {
                    let rows=tokio::time::timeout(Duration::from_secs(6),async {
                        let mut client=pool.get().await.map_err(|_| "owned_dependency_observer_connection")?;
                        let tx=client.build_transaction().read_only(true).start().await.map_err(|_| "owned_dependency_observer_begin")?;
                        tx.query_one("SELECT set_config('statement_timeout','6000',true)",&[])
                            .await.map_err(|_| "owned_dependency_observer_budget")?;
                        let rows=tx.query("SELECT jsonb_build_object('pid',a.pid,'backendStart',a.backend_start::text,
                            'xactStart',a.xact_start::text,'database',a.datname,'user',a.usename,'applicationName',a.application_name,
                            'waitEventType',a.wait_event_type,'waitEvent',a.wait_event,'blockingPids',to_jsonb(pg_blocking_pids(a.pid))),a.query
                            FROM pg_stat_activity a JOIN pg_stat_activity own ON own.pid=$1
                            WHERE a.datname=own.datname AND a.usename=own.usename AND a.application_name=$2
                            AND own.backend_start::text=$3 AND own.xact_start::text=$4
                            AND a.pid<>own.pid AND a.state='active' AND a.wait_event_type='Lock'
                            AND $1=ANY(pg_blocking_pids(a.pid))", &[&pid,&APPLICATION_NAME,&backend,&xact])
                            .await.map_err(|_| "owned_dependency_actual_wait_query")?;
                        tx.commit().await.map_err(|_| "owned_dependency_observer_end")?;
                        Ok::<_,String>(rows)
                    }).await.map_err(|_| "owned_dependency_observer_deadline")??;
                    if rows.len()>1 {return Err("owned_dependency_ambiguous_wait_query".to_owned());}
                    if let Some(row)=rows.first() {
                        let query:String=row.try_get(1).map_err(|_| "owned_dependency_actual_query_shape")?;
                        let hash=Sha256Digest::of(query.as_bytes()).to_hex();
                        // A physically truncated pg_stat_activity query remains RED.
                        if hash!=AUTHORIZED_QUERY_SHA256 {return Err("owned_dependency_original_query_hash".to_owned());}
                        let mut value:Value=row.try_get(0).map_err(|_| "owned_dependency_wait_identity_shape")?;
                        value["querySha256"]=json!(hash);
                        if let Some(attempt)=observations.attempts.lock().await.get_mut(index) {
                            attempt["blockedQuery"]=value;
                        } else {return Err("owned_dependency_attempt_missing".to_owned());}
                        return Ok::<(),String>(());
                    }
                    tokio::select! {
                        _=&mut stopped=>return Err("owned_dependency_block_not_observed".to_owned()),
                        _=tokio::time::sleep(Duration::from_millis(50))=>{}
                    }
                }
            }.await;
            let _=completed.send(result.clone());
            result
        }));
        (stop, completion)
    }

    async fn wait_observed(&self, observations: &FaultObservations, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if observations
                .attempts
                .lock()
                .await
                .iter()
                .any(|attempt| attempt["isB"] == true && !attempt["blockedQuery"].is_null())
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn close(&self) -> bool {
        self.closing.store(true, Ordering::SeqCst);
        let mut task = self.task.lock().await.take();
        let mut controller_ok = true;
        let mut controller_joined = false;
        if let Some(handle) = task.as_mut() {
            let sent = self
                .stop
                .lock()
                .await
                .take()
                .is_some_and(|sender| sender.send(()).is_ok());
            self.facts.lock().await["stopSent"] = json!(sent);
            if !sent {
                self.fail("owned_dependency_stop_sender").await;
                controller_ok = false;
            }
            match tokio::time::timeout(CLOSE_TIMEOUT, &mut *handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(code))) => {
                    self.fail(&code).await;
                    controller_ok = false;
                }
                Ok(Err(_)) => {
                    self.fail("owned_dependency_task_join").await;
                    controller_ok = false;
                }
                Err(_) => {
                    self.fail("owned_dependency_task_join_deadline").await;
                    controller_ok = false;
                    // Setup/rollback SQL are bounded. Keep the failed deadline and await the
                    // actual task. Dropping its JoinHandle would not supply a join fact.
                    let _ = handle.await;
                }
            }
            controller_joined = true;
        } else if self.mode == FaultMode::PreSendDependency {
            self.fail("owned_dependency_controller_missing").await;
            controller_ok = false;
            controller_joined = false;
        }
        let tasks = std::mem::take(&mut *self.watch_tasks.lock().await);
        let mut observers_ok = true;
        for mut task in tasks {
            match tokio::time::timeout(CLOSE_TIMEOUT, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(code))) => {
                    self.fail(&code).await;
                    observers_ok = false;
                }
                Ok(Err(_)) => {
                    self.fail("owned_dependency_observer_join").await;
                    observers_ok = false;
                }
                Err(_) => {
                    self.fail("owned_dependency_observer_join_deadline").await;
                    observers_ok = false;
                    let _ = task.await;
                }
            }
        }
        self.facts.lock().await["taskJoined"] = json!(controller_joined);
        if self.mode != FaultMode::PreSendDependency {
            // No query-disappearance observation was made in these three inactive modes.
            return controller_ok && observers_ok && self.facts.lock().await["error"].is_null();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        loop {
            let result=tokio::time::timeout_at(deadline,async {
                let client=self.pool.get().await.map_err(|_| "owned_dependency_disappearance_connection")?;
                let facts=self.facts.lock().await.clone();
                let database=facts["database"].as_str().ok_or("owned_dependency_database")?;
                let user=facts["user"].as_str().ok_or("owned_dependency_user")?;
                let count:i64=client.query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND datname=$2 AND usename=$3 AND state='active' AND query=$4",
                    &[&APPLICATION_NAME,&database,&user,&AUTHORIZED_CURRENT_QUERY]).await.map_err(|_| "owned_dependency_disappearance_query")?.get(0);
                Ok::<i64,String>(count)
            }).await.unwrap_or(Err("owned_dependency_disappearance_deadline".to_owned()));
            match result {
                Ok(count) => {
                    self.facts.lock().await["remainingBlockedQueries"] = json!(count);
                    if count == 0 {
                        break;
                    }
                }
                Err(code) => {
                    self.fail(&code).await;
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                self.fail("owned_dependency_query_remaining").await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        controller_ok && observers_ok && self.facts.lock().await["error"].is_null()
    }
}

struct CountingProvider {
    inner: Arc<dyn ProviderAdapter>,
    counters: Arc<Counters>,
    managed: bool,
}

#[async_trait]
impl ProviderAdapter for CountingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let counter = if self.managed {
            &self.counters.managed
        } else {
            &self.counters.package
        };
        counter.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}

struct CountingRemote {
    inner: Arc<SafeRemoteAguiTransport>,
    counters: Arc<Counters>,
}

#[async_trait]
impl RemoteAguiTransport for CountingRemote {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.counters.remote_validate.fetch_add(1, Ordering::SeqCst);
        self.inner.validate_endpoint(endpoint).await
    }

    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.counters.remote_start.fetch_add(1, Ordering::SeqCst);
        self.inner.start(endpoint, authorization, body).await
    }
}

#[derive(Clone)]
struct Case {
    actor: String,
    session: String,
    model_id: Option<Uuid>,
}

struct State {
    observer: Pool,
    vault: CredentialRecordVault,
    counters: Arc<Counters>,
    case: Mutex<Option<Case>>,
    requests: Mutex<Vec<Value>>,
    case_id: String,
    held_run_id: Mutex<Option<String>>,
    positive_stream_witness: PositiveStreamWitness,
    mode: FaultMode,
    observations: Arc<FaultObservations>,
    dependency: Arc<DependencyController>,
}

async fn observe_http(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/") {
        state.counters.api_ingress.fetch_add(1, Ordering::SeqCst);
    }
    let admission = match (method.as_str(), path.as_str()) {
        ("POST", "/api/me/model-connections") => Some(&state.counters.model_post),
        ("POST", "/api/agents") => Some(&state.counters.agent_post),
        ("POST", "/api/threads/mint") => Some(&state.counters.mint_post),
        ("GET", "/api/me/capabilities") => Some(&state.counters.cap_get),
        ("POST", path) if begin_path(path) => Some(&state.counters.begin_post),
        _ => None,
    };
    if let Some(counter) = admission {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let sequence = state.counters.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    let response = next.run(request).await;
    if method == "GET"
        && response.status() == axum::http::StatusCode::OK
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
        && let Some(thread) = events_path(&path)
        && let Err(code) =
            observe_positive_subscription(&state, thread, sequence, response.status().as_u16())
                .await
    {
        state.positive_stream_witness.fail(code);
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
    }
    if response.status().is_success()
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"))
    {
        state.counters.served_index.fetch_add(1, Ordering::SeqCst);
    }
    let mut records = state.requests.lock().await;
    if records.len() >= 4096 || path.len() > 2048 {
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
    } else {
        records.push(json!({"sequence":sequence,"method":method,"path":path,
            "status":response.status().as_u16()}));
    }
    response
}

fn begin_path(path: &str) -> bool {
    path.starts_with("/api/threads/") && path.ends_with("/runs") && path.split('/').count() == 5
}

fn events_path(path: &str) -> Option<&str> {
    let thread = path
        .strip_prefix("/api/threads/")?
        .strip_suffix("/events")?;
    (!thread.is_empty()
        && thread.len() <= 128
        && !thread.contains('/')
        && !thread.chars().any(char::is_control))
    .then_some(thread)
}

async fn observe_positive_subscription(
    state: &State,
    thread: &str,
    sequence: u64,
    status: u16,
) -> Result<(), &'static str> {
    let Some(current) = state.case.lock().await.clone() else {
        return Ok(());
    };
    let Some(model) = current.model_id else {
        return Ok(());
    };
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "positive_subscription_connection")?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "positive_subscription_readonly_begin")?;
    // The original events handler has already authenticated and subscribed. This additional
    // read-only observation binds that actual 200 to this live A and current frozen Custom.
    let row=transaction.query_opt("SELECT r.run_id,s.auth_generation
        FROM public.runs r JOIN public.threads t USING(thread_id)
        JOIN public.run_model_selections s ON s.run_id=r.run_id
        JOIN public.model_connections c ON c.id=s.connection_id AND c.deployment_id=s.deployment_id
            AND c.tenant_id=s.tenant_id AND c.owner_user_id=s.owner_user_id
        JOIN public.model_connection_secrets secret ON secret.id=c.current_secret_id AND secret.connection_id=c.id
            AND secret.deployment_id=c.deployment_id AND secret.tenant_id=c.tenant_id AND secret.owner_user_id=c.owner_user_id
        JOIN public.messages input ON input.message_id=r.run_id||':input' AND input.run_id=r.run_id
            AND input.thread_id=r.thread_id AND input.actor_id=r.actor_id
        JOIN public.users u ON u.id=r.actor_id
        JOIN public.sessions session ON session.user_id=u.id AND session.id=$3
        WHERE r.thread_id=$1 AND r.actor_id=$2 AND r.status='running' AND t.status='active'
            AND c.id=$4 AND input.role='user' AND input.content->>'text'=$5
            AND t.deployment_id=$6 AND t.tenant_id=$7
            AND s.deployment_id=t.deployment_id AND s.tenant_id=t.tenant_id AND s.owner_user_id=r.actor_id
            AND s.connection_revision=c.revision AND s.secret_id=c.current_secret_id
            AND s.protocol=c.protocol AND s.endpoint=c.endpoint AND s.model=c.model AND s.created_at=r.created_at
            AND c.enabled AND c.deleted_at IS NULL AND secret.retired_at IS NULL
            AND s.auth_generation=u.auth_generation AND session.auth_generation=u.auth_generation
            AND u.auth_generation>=0 AND session.expires_at>statement_timestamp()
            AND NOT EXISTS(SELECT 1 FROM public.revoked_access revoked WHERE revoked.email=lower(u.email))",
        &[&thread,&current.actor,&current.session,&model,&INTENT_A,&DEPLOYMENT,&TENANT]).await
        .map_err(|_|"positive_subscription_original_joint")?;
    let subscription = if let Some(row) = row {
        Some(PositiveSubscription {
            thread_id: thread.to_owned(),
            run_id: row
                .try_get(0)
                .map_err(|_| "positive_subscription_run_shape")?,
            actor_id: current.actor,
            session_id: current.session,
            auth_generation: row
                .try_get(1)
                .map_err(|_| "positive_subscription_auth_shape")?,
            sequence,
            status,
        })
    } else {
        None
    };
    transaction
        .commit()
        .await
        .map_err(|_| "positive_subscription_readonly_end")?;
    if let Some(subscription) = subscription {
        state.positive_stream_witness.observe(subscription)?;
    }
    Ok(())
}

fn positive_sse() -> String {
    let delta = json!({"id":"owned-c3-response","object":"chat.completion.chunk",
        "choices":[{"index":0,"delta":{"content":POSITIVE_TEXT},"finish_reason":null}]});
    let stop = json!({"id":"owned-c3-response","object":"chat.completion.chunk",
        "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let usage = json!({"id":"owned-c3-response","object":"chat.completion.chunk",
        "choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
    format!("data: {delta}\n\ndata: {stop}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}

fn prefix_sse() -> String {
    let delta = json!({"id":"owned-c3-partial-response","object":"chat.completion.chunk",
        "choices":[{"index":0,"delta":{"content":INTENT_B_PREFIX},"finish_reason":null}]});
    format!("data: {delta}\n\n")
}

fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC3_HOST {text}").map_err(|_| "protocol_write")?;
    output.flush().map_err(|_| "protocol_flush".to_owned())
}

fn stdin_owner() -> (
    mpsc::Receiver<Result<Value, String>>,
    std::thread::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::channel(8);
    let thread = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut bytes = Vec::new();
            let message = loop {
                let available = match input.fill_buf() {
                    Ok(value) => value,
                    Err(_) => break Err("protocol_read".to_owned()),
                };
                if available.is_empty() {
                    if bytes.is_empty() {
                        return;
                    }
                    break Err("protocol_partial_eof".to_owned());
                }
                let length = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |index| index + 1);
                if bytes.len() + length > 65_536 {
                    break Err("protocol_line_limit".to_owned());
                }
                let newline = available[length - 1] == b'\n';
                bytes.extend_from_slice(&available[..length]);
                input.consume(length);
                if newline {
                    break serde_json::from_slice(&bytes)
                        .map_err(|_| "protocol_invalid_json_or_utf8".to_owned());
                }
            };
            let invalid = message.is_err();
            if sender.blocking_send(message).is_err() || invalid {
                return;
            }
        }
    });
    (receiver, thread)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("protocol_invalid_{field}"))
}

fn fields(value: &Value, extra: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("protocol_object_required")?;
    if value["schemaVersion"] != 1
        || object.keys().any(|key| {
            !["schemaVersion", "id", "command"].contains(&key.as_str())
                && !extra.contains(&key.as_str())
        })
    {
        return Err("protocol_unknown_field_or_version".to_owned());
    }
    Ok(())
}

async fn case(state: &State) -> Result<Case, String> {
    state
        .case
        .lock()
        .await
        .clone()
        .ok_or_else(|| "case_not_prepared".to_owned())
}

async fn prepare(state: &State, wire: &OwnedWire) -> Result<Value, String> {
    let mut slot = state.case.lock().await;
    if slot.is_some() {
        return Err("case_already_prepared".to_owned());
    }
    let actor = format!("owned-c3-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C3_SESSION_{}", Uuid::new_v4());
    let channel = format!("owned-c3-channel-{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let transaction = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c3.test");
    transaction
        .execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
            &[&actor, &email],
        )
        .await
        .map_err(|_| "prepare_user")?;
    transaction
        .execute(
            "INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",
            &[&actor],
        )
        .await
        .map_err(|_| "prepare_role")?;
    let now = OffsetDateTime::now_utc();
    let token_hash = SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    transaction
        .execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",
            &[&session,&actor,&token_hash,&(now+time::Duration::hours(2)),&now])
        .await.map_err(|_| "prepare_session")?;
    transaction
        .execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned C3 channel','',ARRAY[]::text[],ARRAY[]::text[])", &[&channel])
        .await.map_err(|_| "prepare_channel")?;
    transaction
        .execute(
            "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",
            &[&channel, &actor],
        )
        .await
        .map_err(|_| "prepare_membership")?;
    transaction.commit().await.map_err(|_| "prepare_commit")?;
    *slot = Some(Case {
        actor: actor.clone(),
        session: session.clone(),
        model_id: None,
    });
    Ok(json!({"caseId":state.case_id,"actor":actor,
        "session":{"id":session,"userId":actor,"token":token,"cookieName":"openbot_session"},
        "model":{"name":"Owned C3 model","protocol":"openai_chat_completions",
            "endpoint":format!("{}/v1",wire.origin()),"model":MODEL,"enabled":true,"apiKey":MODEL_KEY},
        "agent":{"name":"Owned C3 Bot","title":"Owned C3 Bot","roleDescription":"Return the owned canary text without tools.","visibility":"public"},
        "channelId":channel,"intents":{"a":INTENT_A,"b":INTENT_B,"aText":POSITIVE_TEXT,"bPrefix":INTENT_B_PREFIX}}))
}

fn fingerprint(value: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "observer_hash_encode")?;
    Ok(
        json!({"count":value.as_array().map_or(0,Vec::len),"sha256":Sha256Digest::of(&bytes).to_hex()}),
    )
}

// Only owned relations. Cipher/signature columns never leave SQL as their original value.
const SNAPSHOT: &str = "SELECT jsonb_build_object(
 'model_connections',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM public.model_connections m),
 'model_connection_secrets',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'encrypted_value') || jsonb_build_object('encrypted_value_sql_md5',md5(encrypted_value)) ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets s),
 'credentials',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'encrypted_value') || jsonb_build_object('encrypted_value_sql_md5',md5(encrypted_value)) ORDER BY id),'[]'::jsonb) FROM public.credentials c),
 'action_policy',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM public.action_policy p),
 'agents',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.agents a),
 'agent_profiles',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY agent_id),'[]'::jsonb) FROM public.agent_profiles p),
 'channels',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]'::jsonb) FROM public.channels c),
 'channel_memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY channel_id,user_id),'[]'::jsonb) FROM public.channel_memberships m),
 'threads',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY thread_id),'[]'::jsonb) FROM public.threads t),
 'thread_memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY thread_id,user_id),'[]'::jsonb) FROM public.thread_memberships m),
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY message_id),'[]'::jsonb) FROM public.messages m),
 'runs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY run_id),'[]'::jsonb) FROM public.runs r),
 'run_model_selections',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY run_id),'[]'::jsonb) FROM public.run_model_selections s),
 'run_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY run_id,event_seq),'[]'::jsonb) FROM public.run_events e),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]'::jsonb) FROM public.outbox o),
 'tool_calls',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY tool_call_id),'[]'::jsonb) FROM public.tool_calls c),
 'tool_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY tool_call_id,attempt_seq),'[]'::jsonb) FROM public.tool_attempts a),
 'remember_effect_receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY receipt_id),'[]'::jsonb) FROM public.remember_effect_receipts r),
 'memories',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY memory_id),'[]'::jsonb) FROM public.memories m),
 'memory_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq),'[]'::jsonb) FROM public.memory_events e),
 'audit_events',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.audit_events a),
 'audit_checkpoints',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'signature') || jsonb_build_object('signature_sql_md5',md5(signature)) ORDER BY sequence),'[]'::jsonb) FROM public.audit_checkpoints c))";

async fn live_counters(state: &State, counts: Counts) -> Value {
    let records = state.requests.lock().await;
    let matching = |method: &str, path: &str, status: Option<u64>| -> usize {
        records
            .iter()
            .filter(|record| {
                record["method"] == method
                    && record["path"] == path
                    && status.is_none_or(|status| record["status"].as_u64() == Some(status))
            })
            .count()
    };
    let begin = |status: Option<u64>| -> usize {
        records
            .iter()
            .filter(|record| {
                record["method"] == "POST"
                    && record["path"].as_str().is_some_and(begin_path)
                    && status.is_none_or(|status| record["status"].as_u64() == Some(status))
            })
            .count()
    };
    json!({"modelPost":state.counters.model_post.load(Ordering::SeqCst),
        "model201":matching("POST","/api/me/model-connections",Some(201)),
        "agentPost":state.counters.agent_post.load(Ordering::SeqCst),"agent201":matching("POST","/api/agents",Some(201)),
        "mintPost":state.counters.mint_post.load(Ordering::SeqCst),"beginPost":state.counters.begin_post.load(Ordering::SeqCst),"begin201":begin(Some(201)),
        "capGet":state.counters.cap_get.load(Ordering::SeqCst),"cap200":matching("GET","/api/me/capabilities",Some(200)),
        "customStart":state.counters.custom.load(Ordering::SeqCst),"packageStart":state.counters.package.load(Ordering::SeqCst),
        "managedStart":state.counters.managed.load(Ordering::SeqCst),
        "remoteValidate":state.counters.remote_validate.load(Ordering::SeqCst),"remoteStart":state.counters.remote_start.load(Ordering::SeqCst),
        "dns":counts.dns,"tcp":counts.tcp,"http":counts.http,
        "apiIngressCount":state.counters.api_ingress.load(Ordering::SeqCst),
        "servedIndex":state.counters.served_index.load(Ordering::SeqCst),
        "collectionFailed":state.counters.collection_failed.load(Ordering::SeqCst)})
}

fn wire_requests(wire: &OwnedWire) -> Result<Value, String> {
    let mut records = Vec::new();
    let expected_host = wire.origin().trim_start_matches("https://").to_owned();
    for request in wire.requests().map_err(str::to_owned)? {
        let body: Value = serde_json::from_slice(&request.body).map_err(|_| "owned_wire_json")?;
        let messages = body
            .get("messages")
            .and_then(Value::as_array)
            .ok_or("owned_wire_messages")?;
        let last_user = messages
            .iter()
            .rev()
            .find(|item| item["role"] == "user")
            .and_then(|item| item["content"].as_str())
            .ok_or("owned_wire_last_user")?;
        records.push(json!({"method":request.method,"target":request.target,"model":body.get("model"),"stream":body.get("stream"),
            "authorizationMatches":request.headers.get("authorization").is_some_and(|header|header==&format!("Bearer {MODEL_KEY}")),
            "authorizationHeaderCount":request.header_counts.get("authorization").copied().unwrap_or(0),
            "secretInBody":request.body.windows(MODEL_KEY.len()).any(|bytes|bytes==MODEL_KEY.as_bytes()),
            "bodySha256":Sha256Digest::of(&request.body).to_hex(),"requestOrdinal":request.request_ordinal,
            "lastUserCanaryA":last_user==INTENT_A,"lastUserCanaryB":last_user==INTENT_B,
            "hostMatches":request.headers.get("host")==Some(&expected_host),
            "hostHeaderCount":request.header_counts.get("host").copied().unwrap_or(0)}));
    }
    Ok(json!(records))
}

async fn probe(state: &State, wire: &OwnedWire) -> Result<Value, String> {
    let current = case(state).await?;
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "observer_connection")?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "observer_begin")?;
    let pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|_| "observer_pid")?
        .get(0);
    let full: Value = transaction
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "observer_snapshot")?
        .get(0);
    if serde_json::to_vec(&full)
        .map_err(|_| "observer_encode")?
        .len()
        > 262_144
    {
        return Err("observer_snapshot_limit".to_owned());
    }
    let session: Value = transaction
        .query_one(
            "SELECT to_jsonb(s)-'token' FROM public.sessions s WHERE id=$1 AND user_id=$2",
            &[&current.session, &current.actor],
        )
        .await
        .map_err(|_| "observer_session")?
        .get(0);
    let mut row = Value::Null;
    let mut secret = Value::Null;
    let mut vault = Value::Null;
    if let Some(id) = current.model_id {
        let record=transaction.query_one("SELECT to_jsonb(m),to_jsonb(s)-'encrypted_value',s.encrypted_value,s.id FROM public.model_connections m JOIN public.model_connection_secrets s ON s.id=m.current_secret_id AND s.connection_id=m.id AND s.deployment_id=m.deployment_id AND s.tenant_id=m.tenant_id AND s.owner_user_id=m.owner_user_id WHERE m.id=$1 AND m.deployment_id=$2 AND m.tenant_id=$3 AND m.owner_user_id=$4",
            &[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"observer_current_model_secret")?;
        row = record.get(0);
        secret = record.get(1);
        let encrypted: String = record.get(2);
        let secret_id: Uuid = record.get(3);
        secret["encrypted_value_sha256"] = json!(Sha256Digest::of(encrypted.as_bytes()).to_hex());
        let owner = SecretPrincipal::Actor(ActorId::new(current.actor.clone()));
        let service = SecretPrincipal::Service(ServiceId::new(id.to_string()));
        let opened = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                owner.clone(),
                service.clone(),
                &encrypted,
            )
            .map_err(|_| "observer_vault_open")?;
        let migration = opened.needs_migration();
        let plaintext = opened.into_secret();
        let wrong_owner = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("owned-c3-wrong-owner")),
                service.clone(),
                &encrypted,
            )
            .is_err();
        let wrong_service = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                owner.clone(),
                SecretPrincipal::Service(ServiceId::new("owned-c3-wrong-service")),
                &encrypted,
            )
            .is_err();
        let wrong_tenant = CredentialRecordVault::single_key(
            TenantId::new("owned-c3-wrong-tenant"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "observer_wrong_tenant_key")?,
        );
        vault = json!({"canaryMatches":plaintext.expose()==MODEL_KEY.as_bytes(),"needsMigration":migration,
            "wrongOwnerRejected":wrong_owner,"wrongServiceRejected":wrong_service,
            "wrongTenantRejected":wrong_tenant.open(&secret_id,SecretKind::Model,owner,service,&encrypted).is_err()});
    }
    transaction.commit().await.map_err(|_| "observer_end")?;
    let array = |name: &str| -> Result<&Vec<Value>, String> {
        full.get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("observer_relation_{name}"))
    };
    let model_creates: Vec<Value> = array("audit_events")?
        .iter()
        .filter(|value| {
            value["event_type"] == "configuration.changed"
                && value["target_type"] == "model_connection"
                && value["payload"]["change"] == "model_connection_created"
        })
        .cloned()
        .collect();
    let mut business = serde_json::Map::new();
    let mut audit = serde_json::Map::new();
    for (name, value) in full.as_object().ok_or("observer_snapshot_shape")? {
        if name.starts_with("audit_") {
            audit.insert(name.clone(), fingerprint(value)?);
        } else {
            business.insert(name.clone(), fingerprint(value)?);
        }
    }
    audit.insert("modelCreates".to_owned(), json!(model_creates));
    // These are original safe append-only Agent audit rows, not fingerprint inference.
    let agent_audits: Vec<Value> = array("audit_events")?
        .iter()
        .filter(|value| {
            value["actor_user_id"] == current.actor
                && value["target_type"] == "run"
                && (value["event_type"] == "agent.invoked"
                    || value["event_type"] == "agent.stream_stalled")
        })
        .cloned()
        .collect();
    let fault_observation = json!({"mode":state.observations.mode,
        "attempts":state.observations.attempts.lock().await.clone(),
        "dependency":state.dependency.facts.lock().await.clone(),"agentAudits":agent_audits});
    let policy = array("action_policy")?
        .first()
        .cloned()
        .unwrap_or(Value::Null);
    let counts = json!({"modelConnections":array("model_connections")?.len(),"modelConnectionSecrets":array("model_connection_secrets")?.len(),
        "activeModelSecrets":array("model_connection_secrets")?.iter().filter(|value|value["retired_at"].is_null()).count(),
        "runs":array("runs")?.len(),"dispatch":array("outbox")?.iter().filter(|value|value["destination"]=="agent_run_dispatch").count(),
        "toolEffects":array("tool_calls")?.len()+array("tool_attempts")?.len()+array("remember_effect_receipts")?.len()
            +array("memories")?.len()+array("memory_events")?.len()
            +array("messages")?.iter().filter(|value|value["role"]=="tool").count(),"modelCreateAudits":model_creates.len()});
    Ok(
        json!({"caseId":state.case_id,"boundModelId":current.model_id,"row":row,"currentSecret":secret,"vault":vault,
        "counts":counts,"business":business,"audit":audit,"session":session,"policy":policy,
        "counters":live_counters(state,wire.counts()).await,"requests":state.requests.lock().await.clone(),
        "wireRequests":wire_requests(wire)?,"wireState":wire.state().map_err(str::to_owned)?,
        "observer":{"backendPid":pid,"readOnly":true,"isolation":"read committed"},"faultObservation":fault_observation}),
    )
}

async fn bind_model(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let id = Uuid::parse_str(text(value, "modelId")?).map_err(|_| "model_id_invalid")?;
    let mut slot = state.case.lock().await;
    let current = slot.as_mut().ok_or("case_not_prepared")?;
    if current.model_id.is_some() {
        return Err("model_already_bound".to_owned());
    }
    let client = state.observer.get().await.map_err(|_| "bind_connection")?;
    let row:Value=client.query_one("SELECT to_jsonb(m) FROM public.model_connections m WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND deleted_at IS NULL",
        &[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"bind_original_model")?.get(0);
    current.model_id = Some(id);
    drop(slot);
    Ok(
        json!({"caseId":state.case_id,"modelId":id,"revision":row["revision"],"probe":probe(state,wire).await?}),
    )
}

async fn terminal_snapshot(state: &State, run: &str) -> Result<Value, String> {
    let current = case(state).await?;
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "terminal_connection")?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "terminal_readonly_begin")?;
    let observed: Value = transaction.query_one("WITH owned_run AS (
        SELECT r.* FROM public.runs r JOIN public.threads t USING(thread_id)
        WHERE r.run_id=$1 AND r.actor_id=$2 AND t.deployment_id=$3 AND t.tenant_id=$4)
        SELECT jsonb_build_object(
        'run',(SELECT to_jsonb(r) FROM owned_run r),
        'modelSelection',(SELECT to_jsonb(s) FROM public.run_model_selections s WHERE run_id=$1 AND owner_user_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND EXISTS(SELECT 1 FROM owned_run)),
        'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_seq),'[]'::jsonb) FROM public.run_events e WHERE run_id=$1 AND EXISTS(SELECT 1 FROM owned_run)),
        'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY seq),'[]'::jsonb) FROM public.messages m WHERE run_id=$1 AND EXISTS(SELECT 1 FROM owned_run)),
        'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]'::jsonb) FROM public.outbox o WHERE outbox_id=$1 || ':agent_run_dispatch' AND EXISTS(SELECT 1 FROM owned_run)))",
        &[&run,&current.actor,&DEPLOYMENT,&TENANT]).await.map_err(|_|"terminal_original_rows")?
        .try_get(0).map_err(|_|"terminal_shape".to_owned())?;
    transaction
        .commit()
        .await
        .map_err(|_| "terminal_readonly_end")?;
    Ok(observed)
}

fn run_id(value: &Value) -> Result<&str, String> {
    text(value, "runId").and_then(|run| {
        if run.len() > 128 || run.chars().any(char::is_control) {
            Err("run_id_invalid".to_owned())
        } else {
            Ok(run)
        }
    })
}

async fn validate_current_b(
    state: &State,
    wire: &OwnedWire,
    run: &str,
    observed: &Value,
) -> Result<(), String> {
    let current = case(state).await?;
    let id = current.model_id.ok_or("gate_model_not_bound")?;
    let matching_input = observed["messages"]
        .as_array()
        .ok_or("gate_messages_shape")?
        .iter()
        .any(|row| {
            row["message_id"] == format!("{run}:input")
                && row["run_id"] == run
                && row["role"] == "user"
                && row["actor_id"] == current.actor
                && row["content"]["text"] == INTENT_B
        });
    let client = state
        .observer
        .get()
        .await
        .map_err(|_| "gate_original_connection")?;
    let row:Value=client.query_one("SELECT jsonb_build_object('revision',c.revision,'secretId',c.current_secret_id,
        'authGeneration',s.auth_generation,'threadId',r.thread_id,'botId',r.bot_id)
        FROM public.run_model_selections s JOIN public.model_connections c ON c.id=s.connection_id
        JOIN public.runs r ON r.run_id=s.run_id JOIN public.threads t USING(thread_id)
        JOIN public.model_connection_secrets secret ON secret.id=c.current_secret_id AND secret.connection_id=c.id
        JOIN public.users u ON u.id=r.actor_id JOIN public.sessions session ON session.user_id=u.id AND session.id=$3
        WHERE s.run_id=$1 AND c.id=$2 AND r.actor_id=$4 AND r.status='running' AND t.status='active'
        AND s.owner_user_id=$4 AND c.owner_user_id=$4 AND secret.owner_user_id=$4
        AND s.deployment_id=$5 AND c.deployment_id=$5 AND secret.deployment_id=$5 AND t.deployment_id=$5
        AND s.tenant_id=$6 AND c.tenant_id=$6 AND secret.tenant_id=$6 AND t.tenant_id=$6
        AND c.revision=s.connection_revision AND c.current_secret_id=s.secret_id
        AND c.protocol=s.protocol AND c.endpoint=s.endpoint AND c.model=s.model AND s.created_at=r.created_at
        AND s.auth_generation=u.auth_generation AND session.auth_generation=u.auth_generation
        AND session.expires_at>statement_timestamp() AND c.enabled AND c.deleted_at IS NULL AND secret.retired_at IS NULL",
        &[&run,&id,&current.session,&current.actor,&DEPLOYMENT,&TENANT])
        .await.map_err(|_| "gate_original_current_binding")?.get(0);
    if observed["run"]["run_id"] != run
        || observed["run"]["status"] != "running"
        || observed["run"]["actor_id"] != current.actor
        || !matching_input
        || observed["modelSelection"]["run_id"] != run
        || observed["modelSelection"]["connection_id"] != id.to_string()
        || observed["modelSelection"]["connection_revision"] != row["revision"]
        || observed["modelSelection"]["secret_id"] != row["secretId"]
        || observed["modelSelection"]["auth_generation"] != row["authGeneration"]
    {
        return Err("gate_actual_current_b_identity".to_owned());
    }
    let attempts = state.observations.attempts.lock().await;
    let attempt = attempts
        .iter()
        .find(|attempt| attempt["runId"] == run && attempt["isB"] == true)
        .ok_or("gate_actual_current_b_start_missing")?;
    if attempt["threadId"] != row["threadId"]
        || attempt["botId"] != row["botId"]
        || attempt["actorId"] != current.actor
        || attempt["authGeneration"] != row["authGeneration"]
        || attempt["connectionId"] != id.to_string()
        || attempt["connectionRevision"] != row["revision"]
        || attempt["secretId"] != row["secretId"]
    {
        return Err("gate_original_typed_binding_identity".to_owned());
    }
    if state.mode == FaultMode::PreSendDependency {
        if attempt["blockedQuery"].is_null() {
            return Err("gate_actual_selected_query_not_observed".to_owned());
        }
        let facts = state.dependency.facts.lock().await;
        if facts["lockAcquired"] != true
            || facts["runId"] != run
            || facts["lockRowMatched"] != true
            || facts["secretId"] != row["secretId"]
            || facts["connectionRevision"] != row["revision"]
        {
            return Err("gate_actual_selected_query_identity".to_owned());
        }
    } else {
        let requests = wire_requests(wire)?;
        let request = requests
            .as_array()
            .and_then(|items| items.get(1))
            .ok_or("gate_actual_second_request_missing")?;
        if request["requestOrdinal"] != 2
            || request["lastUserCanaryB"] != true
            || request["lastUserCanaryA"] != false
        {
            return Err("gate_actual_current_b_request_identity".to_owned());
        }
    }
    Ok(())
}

async fn hold_fault(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let run = run_id(value)?;
    let millis = value["timeoutMs"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= 4000)
        .ok_or("gate_timeout_invalid")?;
    if state.held_run_id.lock().await.is_some() {
        return Err("gate_run_already_bound".to_owned());
    }
    let held = if state.mode == FaultMode::PreSendDependency {
        state
            .dependency
            .wait_observed(&state.observations, Duration::from_millis(millis))
            .await
    } else {
        wire.wait_held(Duration::from_millis(millis))
            .await
            .map_err(str::to_owned)?
    };
    let mut observed = terminal_snapshot(state, run).await?;
    if held {
        validate_current_b(state, wire, run, &observed).await?;
        *state.held_run_id.lock().await = Some(run.to_owned());
    }
    observed["caseId"] = json!(state.case_id);
    observed["runId"] = json!(run);
    observed["timedOut"] = json!(!held);
    observed["held"] = json!(held);
    observed["gate"] = wire.gate().map_err(str::to_owned)?;
    observed["probe"] = probe(state, wire).await?;
    Ok(observed)
}

async fn release_fault(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let run = run_id(value)?;
    if !state.mode.allows_release() {
        return Err("gate_mode_never_releases".to_owned());
    }
    if state.held_run_id.lock().await.as_deref() != Some(run) {
        return Err("gate_bound_run_mismatch".to_owned());
    }
    let observed = terminal_snapshot(state, run).await?;
    validate_current_b(state, wire, run, &observed).await?;
    wire.release_fault().map_err(str::to_owned)?;
    Ok(
        json!({"caseId":state.case_id,"runId":run,"released":true,"gate":wire.gate().map_err(str::to_owned)?}),
    )
}

async fn wait_terminal(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let run = run_id(value)?;
    let millis = value["timeoutMs"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= 240_000)
        .ok_or("terminal_timeout_invalid")?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(millis);
    loop {
        let mut observed = terminal_snapshot(state, run).await?;
        let terminals = observed["events"]
            .as_array()
            .ok_or("terminal_events_shape")?
            .iter()
            .filter(|event| event["terminal"] == true)
            .count();
        let delivered = observed["outbox"]
            .as_array()
            .ok_or("terminal_outbox_shape")?
            .iter()
            .any(|item| item["status"] == "delivered");
        let terminal = observed["run"]["status"]
            .as_str()
            .is_some_and(|status| status != "running" && status != "queued");
        let timed_out = tokio::time::Instant::now() >= deadline;
        if (terminal && terminals == 1 && delivered) || timed_out {
            observed["caseId"] = json!(state.case_id);
            observed["runId"] = json!(run);
            observed["timedOut"] = json!(timed_out);
            observed["terminalObserved"] = json!(terminal && terminals == 1 && delivered);
            observed["probe"] = probe(state, wire).await?;
            return Ok(observed);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn execute(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let command = text(value, "command")?;
    let extra: &[&str] = match command {
        "prepare" | "probe" => &["caseId"],
        "bind_model" => &["caseId", "modelId"],
        "wait_terminal" => &["caseId", "runId", "timeoutMs"],
        "hold_fault" => &["caseId", "runId", "timeoutMs"],
        "release_fault" => &["caseId", "runId"],
        "shutdown" => &[],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    fields(value, extra)?;
    if command != "shutdown" && text(value, "caseId")? != state.case_id {
        return Err("protocol_case_mismatch".to_owned());
    }
    match command {
        "prepare" => prepare(state, wire).await,
        "bind_model" => bind_model(state, wire, value).await,
        "probe" => probe(state, wire).await,
        "wait_terminal" => wait_terminal(state, wire, value).await,
        "hold_fault" => hold_fault(state, wire, value).await,
        "release_fault" => release_fault(state, wire, value).await,
        "shutdown" => Ok(json!({"stopping":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
}

pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C3_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C3_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C3_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C3_CASE_ID").map_err(|_| "missing_case_id")?;
    if FaultMode::parse(&case_id).is_none()
        || source.len() != 40
        || spec.len() != 64
        || !source.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !spec.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !std::path::Path::new(&dist).is_absolute()
    {
        return Err("invalid_outer_identity".to_owned());
    }
    let mode = FaultMode::parse(&case_id).ok_or("unknown_c3_mode")?;
    let static_app = StaticApp::open(&dist).map_err(|_| "invalid_owned_dist")?;
    let mut application_config = config.clone();
    application_config.max_pool_size = 8;
    application_config.application_name =
        Some("owned-customboundary-client-application".to_owned());
    let application_pool = pool::connect(&application_config)
        .await
        .map_err(|_| "application_pool")?;
    let mut observer_config = config.clone();
    observer_config.max_pool_size = 4;
    observer_config.application_name = Some("owned-customboundary-client-observer".to_owned());
    let observer_pool = pool::connect(&observer_config)
        .await
        .map_err(|_| "observer_pool")?;
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    drop(client);
    let wire = OwnedWire::new(
        positive_sse(),
        prefix_sse(),
        mode,
        [TEST_CA, TEST_LEAF, TEST_KEY],
    )
    .await
    .map_err(|_| "owned_tls_setup")?;
    let counters = Arc::new(Counters::default());
    let dependency = Arc::new(DependencyController::new(observer_pool.clone(), mode));
    let observations = Arc::new(FaultObservations {
        mode: case_id.clone(),
        started: tokio::time::Instant::now(),
        attempts: Mutex::new(Vec::new()),
        counters: counters.clone(),
        errors: dependency.facts.clone(),
    });
    let tenant = TenantId::new(TENANT);
    let deployment = DeploymentId::new(DEPLOYMENT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "owned_vault_key")?,
    );
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        vault: vault.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
        held_run_id: Mutex::new(None),
        positive_stream_witness: wire.positive_witness(),
        mode,
        observations: observations.clone(),
        dependency: dependency.clone(),
    });
    let mut assembly = None;
    let mut auth_owner = None;
    let mut agent = None;
    let mut relay = None;
    let mut listener_task = None;
    let mut stop_sender = None;
    let mut stdin_thread = None;
    let result=async {
        let policies=PolicyStore::postgres(application_pool.clone(),None);
        policies.set(ActionPolicy{mode:PolicyMode::Enforce,deny:vec!["true".to_owned()],allow:Vec::new()},None)
            .await.map_err(|_|"owned_deny_all_policy")?;
        policies.load().await.map_err(|_|"owned_policy_load")?;
        let assertions=Arc::new(RemoteRunAssertionSigner::new(vec![0x83;32]).map_err(|_|"owned_assertion_key")?);
        let auth=Arc::new(PostgresSessionAuthResolver::new(application_pool.clone(),SESSION_KEY,default_session_lifetime(),deployment.clone(),tenant.clone())
            .map_err(|_|"owned_session_resolver")?);
        auth_owner=Some(auth.clone());
        let budget=SafeHttpBudget::new(64*1024*1024,Duration::from_secs(6)).map_err(|_|"owned_http_budget")?;
        let remote:Arc<dyn RemoteAguiTransport>=Arc::new(CountingRemote{inner:Arc::new(SafeRemoteAguiTransport::new(wire.dialer(),budget,Some(Duration::from_secs(2)),SchemePolicy::HttpsOnly)
            .map_err(|_|"owned_actual_remote")?),counters:counters.clone()});
        // This actual adapter is a legal CreateAgent prerequisite. Its key remains only in memory.
        let managed_inner:Option<Arc<dyn ProviderAdapter>>=Some(Arc::new(OpenAiProvider::new(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/chat/completions",wire.origin())).map_err(|_|"owned_managed_endpoint")?,
            "owned-managed-model".to_owned(),OpenAiProtocol::ChatCompletions,budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_managed_config")?,OpenAiApiKey::from_bytes(MANAGED_KEY.as_bytes().to_vec()).map_err(|_|"owned_managed_key")?,wire.dialer())));
        let managed_slot_available=managed_inner.is_some();
        let managed=managed_inner.map(|inner|Arc::new(CountingProvider{inner,counters:counters.clone(),managed:true}) as Arc<dyn ProviderAdapter>);
        assembly=Some(assemble_postgres_application(PostgresApplicationAssemblyInput{
            pool:application_pool.clone(),listener_database:application_config.clone().into(),deployment:deployment.clone(),tenant:tenant.clone(),single_user:false,admin_floor:None,
            model:"unused-default-model".to_owned(),credential_key_id:"unused-default-model-key".to_owned(),credential_vault:vault.clone(),audit_key:SecretBytes::new(vec![0x82;32]),
            remote_assertions:assertions.clone(),mcp_oauth_state_key:SecretBytes::new(vec![0x84;32]),policy_store:policies,
            ui_preferences:Arc::new(PostgresUiPreferenceAdministration::new(application_pool.clone(),deployment.clone(),tenant.clone(),SecretBytes::new(vec![0x82;32])).map_err(|_|"owned_preferences")?),
            screen_sessions:Arc::new(openbot_application::NoScreenSessionAdministration),artifacts:None,
            runtime_capabilities:Some(auth.runtime_capability_factory(None).map_err(|_|"owned_actual_capability_factory")?),
            remote_agent_probe:remote.clone(),managed_slot_available,
            channel_routing_provider:ChannelRoutingProviderInput{endpoint:Url::parse(&format!("{}/v1/chat/completions",wire.origin())).map_err(|_|"owned_channel_endpoint")?,environment_api_key:None,egress_allow_cidrs:vec!["127.0.0.1/32".to_owned()],allow_http:false},
            stall_timeout:Some(Duration::from_secs(2)),oauth_public_url:None,app_url:None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        }).await.map_err(|_|"owned_production_assembly")?);
        let assembled=assembly.as_ref().ok_or("assembly_missing")?;
        let package_credentials=Arc::new(PostgresOpenAiCredentialSource::new(application_pool.clone(),vault.clone(),"unused-default-model-key".to_owned(),None).map_err(|_|"owned_default_source")?);
        let package:Arc<dyn ProviderAdapter>=Arc::new(CountingProvider{inner:Arc::new(OpenAiProvider::new_with_credential_source(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/responses",wire.origin())).map_err(|_|"owned_package_endpoint")?,"unused-default-model".to_owned(),OpenAiProtocol::Responses,budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_package_config")?,package_credentials,wire.dialer())),counters:counters.clone(),managed:false});
        let custom:Arc<dyn ProviderAdapter>=Arc::new(CountingCustom{inner:Arc::new(PostgresCustomModelProvider::new(application_pool.clone(),vault.clone(),deployment.clone(),tenant.clone(),wire.dialer(),budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone(),observations:observations.clone(),dependency:dependency.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(RemoteAguiProvider::new(remote)))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
        let context=Arc::new(PostgresAgentContextSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),Some(32)).map_err(|_|"owned_context")?
            .with_tools(vec![remember_provider_tool()]).with_remote_assertions(assertions).with_mcp_catalog(assembled.mcp_catalog.clone())
            .with_components(assembled.components.clone()).with_sandboxed_components(assembled.sandboxed_components.clone()).with_agent_credential_vault(vault.clone()));
        let tools=Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(assembled.application.clone(),Arc::new(PostgresAgentAuthorizationSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),false)),
            Arc::new(PostgresAgentToolSequence::new(application_pool.clone())),assembled.tool_cancellations.clone()));
        let audit=Arc::new(PostgresAgentAudit::new(application_pool.clone(),vec![0x82;32]).map_err(|_|"owned_agent_audit")?);
        agent=Some(BuiltInAgentRuntime::start_with_remote_interrupts(assembled.run_runtime.clone(),context,provider,tools,audit,assembled.remote_interrupts.clone(),
            BuiltInAgentConfig::default()).map_err(|_|"owned_actual_agent")?);
        relay=Some(RunRelay::start_with_database(assembled.run_runtime.clone(),agent.as_ref().ok_or("agent_missing")?.consumer(),application_config.clone()));
        let listener=tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await.map_err(|_|"owned_http_bind")?;
        let origin=format!("http://{}",listener.local_addr().map_err(|_|"owned_http_address")?);
        let transport=ServerConfig::from_env_map(&EnvMap::new()).map_err(|_|"owned_transport_config")?.transport_policy(true);
        let router=ServerBuilder::new(assembled.application.clone(),auth).with_transport_policy(transport)
            .with_sensitive_write_security(SensitiveWriteSecurity::new(default_session_lifetime(),TrustedOrigins::from_configured([origin.as_str()]).map_err(|_|"owned_origin")?))
            .with_static_app(static_app).into_router().layer(axum::middleware::from_fn_with_state(state.clone(),observe_http));
        let (stop,stopped)=oneshot::channel();stop_sender=Some(stop);
        listener_task=Some(tokio::spawn(async move {axum::serve(listener,router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async {let _=stopped.await;}).await}));
        let (mut input,thread)=stdin_owner();stdin_thread=Some(thread);
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":wire.origin(),"dist":dist,
        "sourceHead":source,"specSha256":spec,"producer":"same-Pool SessionAuthResolver/CapabilityFactory/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/ActualCustom/Agent/RunRelay/StrictOwnedTLSFiniteFailure/OriginalRetryDefaults/ActualEventsReadonlyPGWitness/OwnedSelectedRowLockObserver","caseEvidence":"none"}))?;
        let mut ids=BTreeSet::new();
        loop {
            let value=tokio::time::timeout(Duration::from_secs(90),input.recv()).await.map_err(|_|"protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id=text(&value,"id")?.to_owned();
            if id.len()>64 || !id.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"._-".contains(&byte)) || !ids.insert(id.clone()) || ids.len()>4096{return Err("protocol_invalid_or_reused_id".to_owned());}
            let reply=execute(&state,&wire,&value).await;
            let shutdown=reply.is_ok() && text(&value,"command")?=="shutdown";
            let frame=match reply {Ok(result)=>json!({"schemaVersion":1,"id":id,"ok":true,"result":result}),Err(error)=>json!({"schemaVersion":1,"id":id,"ok":false,"error":error})};
            emit(&frame)?;
            if shutdown{return Ok::<(),String>(());}
        }
    }.await;
    if let Some(auth) = auth_owner {
        auth.close_request_bindings();
    }
    if let Some(assembled) = &assembly
        && let Some(facts) = &assembled.runtime_capability_facts
    {
        facts.close();
    }
    if let Some(stop) = stop_sender {
        let _ = stop.send(());
    }
    let mut close_errors = Vec::new();
    let listener_joined = if let Some(mut task) = listener_task {
        let joined = matches!(
            tokio::time::timeout(CLOSE_TIMEOUT, &mut task).await,
            Ok(Ok(Ok(())))
        );
        if !joined {
            task.abort();
            let _ = task.await;
            close_errors.push("http_listener_join");
        }
        joined
    } else {
        false
    };
    let facts_drained = if let Some(assembled) = &assembly {
        if let Some(facts) = &assembled.runtime_capability_facts {
            let drained = tokio::time::timeout(CLOSE_TIMEOUT, facts.drain())
                .await
                .is_ok();
            if !drained {
                close_errors.push("capability_worker_drain");
            }
            drained
        } else {
            false
        }
    } else {
        false
    };
    let dependency_closed = dependency.close().await;
    if !dependency_closed {
        close_errors.push("owned_dependency_controller_close");
    }
    let relay_stopped = if let Some(relay) = relay {
        let stopped = tokio::time::timeout(CLOSE_TIMEOUT, relay.stop())
            .await
            .is_ok();
        if !stopped {
            close_errors.push("relay_stop");
        }
        stopped
    } else {
        false
    };
    let agent_stopped = if let Some(agent) = agent {
        let stopped = tokio::time::timeout(CLOSE_TIMEOUT, agent.stop())
            .await
            .is_ok();
        if !stopped {
            close_errors.push("agent_stop");
        }
        stopped
    } else {
        false
    };
    let assembly_closed = if let Some(assembled) = assembly {
        let stopped = tokio::time::timeout(CLOSE_TIMEOUT, assembled.shutdown())
            .await
            .is_ok();
        if !stopped {
            close_errors.push("assembly_shutdown");
        }
        stopped
    } else {
        false
    };
    let wire_record: WireRecord = wire.finish().await;
    if wire_record.requests.len() != wire_record.counts.http {
        close_errors.push("owned_tls_request_capture_incomplete");
    }
    if wire_record.failed != 0 {
        close_errors.push("owned_tls_child_failed");
    }
    let expected = mode.expected_requests();
    let connections = wire_record.state["connections"].as_array();
    let complete_connections = connections.is_some_and(|rows| {
        rows.len() == expected
            && rows.iter().enumerate().all(|(index, row)| {
                let common = row["tlsAccepted"] == true
                    && row["requestCaptured"] == true
                    && row["requestOrdinal"] == index + 1
                    && row["shutdownAttempted"] == true
                    && row["shutdownReturned"] == true
                    && row["error"].is_null();
                if index == 1 && mode == FaultMode::HeadersStall {
                    common
                        && row["status"].is_null()
                        && row["headersWritten"] == false
                        && row["bodyWritten"] == false
                        && row["prefixWritten"] == false
                        && row["unsentTail"] == true
                        && row["peerCloseObserved"] == true
                } else if index == 1 && mode == FaultMode::PrefixStall {
                    common
                        && row["status"] == 200
                        && row["headersWritten"] == true
                        && row["bodyWritten"] == false
                        && row["prefixWritten"] == true
                        && row["unsentTail"] == true
                        && row["peerCloseObserved"] == true
                } else {
                    common
                        && row["status"] == (if index == 0 { 200 } else { 503 })
                        && row["headersWritten"] == true
                        && row["bodyWritten"] == true
                        && row["prefixWritten"] == false
                        && row["unsentTail"] == false
                        && row["peerCloseObserved"] == false
                }
            })
    });
    let gate = &wire_record.state["faultGate"];
    let gate_complete = if mode == FaultMode::PreSendDependency {
        gate["requestCaptured"] == false
            && gate["requestOrdinal"].is_null()
            && gate["headerHeld"] == false
            && gate["releaseSent"] == false
    } else {
        gate["requestCaptured"] == true
            && gate["requestOrdinal"] == 2
            && gate["headerHeld"] == true
            && gate["releaseSent"] == mode.allows_release()
    };
    if !complete_connections
        || wire_record.joined != expected
        || wire_record.counts.http != expected
        || wire_record.counts.tcp != expected
        || wire_record.counts.dns != expected
        || wire_record.state["remainingReplies"] != 0
        || !gate_complete
        || wire_record.state["positiveStreamGate"]["armed"] != true
        || wire_record.state["positiveStreamGate"]["subscriptionObserved"] != true
        || wire_record.state["positiveStreamGate"]["bodyReleaseSent"] != true
        || !wire_record.state["positiveStreamGate"]["error"].is_null()
        || wire_record.state["listenerErrors"]
            .as_array()
            .is_none_or(|errors| !errors.is_empty())
    {
        close_errors.push("owned_tls_finite_closure_incomplete");
    }
    let final_counters = live_counters(&state, wire_record.counts).await;
    observer_pool.close();
    application_pool.close();
    let stdin_joined = if let Some(thread) = stdin_thread {
        let mut join = tokio::task::spawn_blocking(move || thread.join());
        let joined = matches!(
            tokio::time::timeout(CLOSE_TIMEOUT, &mut join).await,
            Ok(Ok(Ok(())))
        );
        if !joined {
            close_errors.push("stdin_eof_join");
        }
        joined
    } else {
        false
    };
    let collection_failed = counters.collection_failed.load(Ordering::SeqCst);
    emit(
        &json!({"schemaVersion":1,"event":"closed","caseId":case_id,"sourceHead":source,"specSha256":spec,
        "listenerJoined":listener_joined,"factsDrained":facts_drained,"relayStopReturned":relay_stopped,"agentStopReturned":agent_stopped,
        "assemblyShutdownReturned":assembly_closed,"wireFinishReturned":true,"wireJoined":wire_record.joined,"wireFailed":wire_record.failed,
        "wireCounts":{"dns":wire_record.counts.dns,"tcp":wire_record.counts.tcp,"http":wire_record.counts.http},
        "wireState":wire_record.state,"dependency":dependency.facts.lock().await.clone(),
        "stdinJoined":stdin_joined,"observerPoolCloseCalled":true,"applicationPoolCloseCalled":true,"counters":final_counters,
        "collectionFailed":collection_failed,"closeErrors":close_errors}),
    )?;
    if !listener_joined
        || !facts_drained
        || !relay_stopped
        || !agent_stopped
        || !assembly_closed
        || !dependency_closed
        || !stdin_joined
        || collection_failed
        || !close_errors.is_empty()
    {
        return Err("owned_close_incomplete".to_owned());
    }
    result
}
