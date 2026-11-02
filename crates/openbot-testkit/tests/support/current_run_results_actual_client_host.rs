//! Actual assembled finite C6 host. Only original UI/API producers create runs and terminal facts.

use futures_core::Stream;
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
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
    AgentAudit, AgentAuditError, AgentAuditKind, ProviderAdapter, ProviderEvent, ProviderFailure,
    ProviderMessageRole, ProviderPortError, ProviderRequest, ProviderRoute, ProviderSession,
    RunExecutionLease, remember_provider_tool,
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

use super::current_run_results_owned_tls_fixture::{
    CaseMode, Counts, OwnedWire, PositiveStreamWitness, PositiveSubscription, RawRequest,
    WireRecord,
};

const INTENT_A: &str = "owned C6 positive request";
const INTENT_B: &str = "owned C6 current request";
const INTENT_B_PREFIX: &str = "owned C6 partial current text";
const INTENT_B_TAIL: &str = " and completed current text";
const POSITIVE_TEXT: &str = "owned C6 preceding positive text";
const DEPLOYMENT: &str = "owned-currentrun-client-deployment";
const TENANT: &str = "owned-currentrun-client-tenant";
const SESSION_KEY: &[u8] = b"owned-currentrun-client-session-key-at-least-32-bytes";
const MODEL_KEY: &str = "owned-c6-model-key";
const MANAGED_KEY: &str = "owned-c6-managed-key";
const MODEL: &str = "owned-c6-model";
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);
const ORIGINAL_AUDIT_INSERT: &str = "INSERT INTO public.audit_events (id, actor_user_id, event_type, target_type, target_id, payload, created_at, prev_hash, row_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)";

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
    cancel_post: AtomicU64,
    reconciliation_get: AtomicU64,
    receipts_get: AtomicU64,
    sse_get: AtomicU64,
    served_index: AtomicU64,
    sequence: AtomicU64,
    collection_failed: AtomicBool,
}
struct ProviderObservations {
    started: tokio::time::Instant,
    rows: StdMutex<Vec<Value>>,
    counters: Arc<Counters>,
}
impl ProviderObservations {
    fn update(&self, index: usize, update: impl FnOnce(&mut Value)) {
        match self.rows.lock() {
            Ok(mut rows) => match rows.get_mut(index) {
                Some(row) => update(row),
                None => {
                    self.counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                }
            },
            Err(_) => {
                self.counters
                    .collection_failed
                    .store(true, Ordering::SeqCst);
            }
        }
    }
    fn begin(&self, request: &ProviderRequest) -> Result<usize, ProviderPortError> {
        let ProviderRoute::CustomModel(binding) = &request.route else {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
            return Err(ProviderPortError::Unavailable);
        };
        let lease = binding
            .identity_lease()
            .map_err(|_| ProviderPortError::Unavailable)?;
        let last = request
            .messages
            .iter()
            .rev()
            .find(|m| m.role == ProviderMessageRole::User)
            .ok_or(ProviderPortError::Unavailable)?;
        if last.content != INTENT_A && last.content != INTENT_B {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ProviderPortError::Unavailable)?;
        let index = rows.len();
        if index >= 2 {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        rows.push(json!({"ordinal":index+1,"runId":lease.run_id().as_str(),"threadId":lease.thread_id().as_str(),
            "botId":lease.bot_id().as_str(),"actorId":binding.actor().as_str(),"authGeneration":binding.auth_generation().get(),
            "deploymentId":binding.deployment().as_str(),"tenantId":binding.tenant().as_str(),
            "connectionId":binding.connection_id(),"connectionRevision":binding.connection_revision(),"secretId":binding.secret_id(),
            "isB":last.content==INTENT_B,"startElapsedMs":self.started.elapsed().as_millis(),"startReturnElapsedMs":null,
            "startResult":null,"firstEvent":null,"terminalEvent":null,"sessionDropObserved":false}));
        Ok(index)
    }
    fn snapshot(&self) -> Result<Value, String> {
        self.rows
            .lock()
            .map(|rows| json!(*rows))
            .map_err(|_| "provider_observation_poisoned".to_owned())
    }
}
struct CountingCustom {
    inner: Arc<PostgresCustomModelProvider>,
    counters: Arc<Counters>,
    observations: Arc<ProviderObservations>,
}
#[async_trait]
impl ProviderAdapter for CountingCustom {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let observation = self.observations.begin(&request);
        self.counters.custom.fetch_add(1, Ordering::SeqCst);
        // The original request and every actual port result are delegated without substitution.
        let result = self.inner.start(request).await;
        if let Ok(index) = observation {
            let label = match &result {
                Ok(_) => "session",
                Err(ProviderPortError::Unavailable) => "unavailable",
                Err(ProviderPortError::CommitUnknown) => "commit_unknown",
                Err(ProviderPortError::InvalidRequest { .. }) => "invalid_request",
            };
            self.observations.update(index, |row| {
                row["startReturnElapsedMs"] =
                    json!(self.observations.started.elapsed().as_millis());
                row["startResult"] = json!(label);
            });
            result.map(|inner| {
                Box::new(CountingSession {
                    inner,
                    index,
                    observations: self.observations.clone(),
                }) as Box<dyn ProviderSession>
            })
        } else {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
            result
        }
    }
}
struct CountingSession {
    inner: Box<dyn ProviderSession>,
    index: usize,
    observations: Arc<ProviderObservations>,
}
#[async_trait]
impl ProviderSession for CountingSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        let result = self.inner.next_event().await;
        let label = match &result {
            Ok(Some(ProviderEvent::ResponseStarted { .. })) => "response_started",
            Ok(Some(ProviderEvent::OutputItemAdded { .. })) => "output_item_added",
            Ok(Some(ProviderEvent::TextDelta { .. })) => "text_delta",
            Ok(Some(ProviderEvent::Completed)) => "completed",
            Ok(Some(ProviderEvent::Failed(f))) => match f {
                ProviderFailure::Authentication => "failed:authentication",
                ProviderFailure::RateLimited { .. } => "failed:rate_limited",
                ProviderFailure::ServerUnavailable { .. } => "failed:server_unavailable",
                ProviderFailure::InvalidResponse => "failed:invalid_response",
                ProviderFailure::StreamStalled => "failed:stream_stalled",
                ProviderFailure::Transport => "failed:transport",
                ProviderFailure::GenerationFailed => "failed:generation_failed",
            },
            Ok(Some(_)) => "other",
            Ok(None) => "end_of_stream",
            Err(ProviderPortError::Unavailable) => "port_error:unavailable",
            Err(ProviderPortError::CommitUnknown) => "port_error:commit_unknown",
            Err(ProviderPortError::InvalidRequest { .. }) => "port_error:invalid_request",
        };
        self.observations.update(self.index, |row| {
            if row["firstEvent"].is_null() {
                row["firstEvent"] = json!(label);
            }
            if matches!(
                &result,
                Ok(Some(ProviderEvent::Completed | ProviderEvent::Failed(_)))
            ) {
                row["terminalEvent"] = json!(label);
            }
        });
        result
    }
}
impl Drop for CountingSession {
    fn drop(&mut self) {
        self.observations
            .update(self.index, |row| row["sessionDropObserved"] = json!(true));
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
    token: String,
    model_id: Option<Uuid>,
}
struct State {
    observer: Pool,
    controller: Pool,
    vault: CredentialRecordVault,
    counters: Arc<Counters>,
    case: Mutex<Option<Case>>,
    requests: Mutex<Vec<Value>>,
    case_id: String,
    mode: CaseMode,
    positive_stream_witness: PositiveStreamWitness,
    observations: Arc<ProviderObservations>,
    baseline: Mutex<Option<Value>>,
    audit_fault: Arc<AuditFault>,
    sse: Arc<SseController>,
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

fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC6_HOST {text}").map_err(|_| "protocol_write")?;
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
    let actor = format!("owned-c6-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C6_SESSION_{}", Uuid::new_v4());
    let channel = format!("owned-c6-channel-{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let transaction = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c6.test");
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
        .execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned C6 channel','',ARRAY[]::text[],ARRAY[]::text[])", &[&channel])
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
        token: token.clone(),
    });
    Ok(json!({"caseId":state.case_id,"actor":actor,
        "session":{"id":session,"userId":actor,"token":token,"cookieName":"openbot_session"},
        "model":{"name":"Owned C6 model","protocol":"openai_chat_completions",
            "endpoint":format!("{}/v1",wire.origin()),"model":MODEL,"enabled":true,"apiKey":MODEL_KEY},
        "agent":{"name":"Owned C6 Bot","title":"Owned C6 Bot","roleDescription":"Return the owned canary text without tools.","visibility":"public"},
        "channelId":channel,"intents":{"a":INTENT_A,"b":INTENT_B,"aText":POSITIVE_TEXT,"bPrefix":INTENT_B_PREFIX,"bTail":INTENT_B_TAIL},"budgets":budgets()}))
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
        'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]'::jsonb) FROM public.outbox o WHERE outbox_id IN ($1 || ':agent_run_dispatch',$1 || ':agent_run_cancel') AND EXISTS(SELECT 1 FROM owned_run)))",
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

fn budgets() -> Value {
    json!({"responseBodyBytes":67108864,"startupMs":6000,"bodyStallMs":2000,"ownedTLSChildMs":8000,
    "ownedCloseMs":12000,"rpcMs":12000,"apiMs":35000,"readyMs":25000,"wholeCaseMs":180000,
    "waitTerminalMaxMs":240000,"waitTerminalRpcMs":255000,"observeProviderMaxMs":4000,"observeProviderRpcMs":6000,
    "criticalControlMs":1000,"sseReconnectGateMs":12000})
}
fn positive_sse() -> String {
    let delta = json!({"id":"owned-c6-positive","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":POSITIVE_TEXT},"finish_reason":null}]});
    let stop = json!({"id":"owned-c6-positive","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let usage = json!({"id":"owned-c6-positive","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
    format!("data: {delta}\n\ndata: {stop}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}
fn prefix_sse() -> String {
    let delta = json!({"id":"owned-c6-current","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":INTENT_B_PREFIX},"finish_reason":null}]});
    format!("data: {delta}\n\n")
}
fn tail_sse(mode: CaseMode) -> String {
    if mode == CaseMode::Failed {
        let failure = json!({"id":"owned-c6-current","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"content_filter"}]});
        return format!("data: {failure}\n\n");
    }
    let delta = json!({"id":"owned-c6-current","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":INTENT_B_TAIL},"finish_reason":null}]});
    let stop = json!({"id":"owned-c6-current","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let usage = json!({"id":"owned-c6-current","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
    format!("data: {delta}\n\ndata: {stop}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}
const RELATIONS: [&str; 23] = [
    "model_connections",
    "model_connection_secrets",
    "credentials",
    "action_policy",
    "agents",
    "agent_profiles",
    "channels",
    "channel_memberships",
    "threads",
    "thread_leases",
    "thread_memberships",
    "messages",
    "runs",
    "run_model_selections",
    "run_events",
    "outbox",
    "tool_calls",
    "tool_attempts",
    "remember_effect_receipts",
    "memories",
    "memory_events",
    "audit_events",
    "audit_checkpoints",
];
async fn full_snapshot(transaction: &deadpool_postgres::Transaction<'_>) -> Result<Value, String> {
    let mut map = serde_json::Map::new();
    for name in RELATIONS {
        // The only SQL identifier inputs are these fixed original relation names. Secret-bearing
        // rows stay inside native memory; no hash/ciphertext/credential bytes leave this function.
        let sql = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text),'[]'::jsonb) FROM public.{name} row"
        );
        let value: Value = transaction
            .query_one(sql.as_str(), &[])
            .await
            .map_err(|_| "observer_relation")?
            .get(0);
        map.insert(name.to_owned(), value);
    }
    Ok(Value::Object(map))
}
fn safe_audit_rows(full: &Value, predicate: impl Fn(&Value) -> bool) -> Result<Vec<Value>, String> {
    Ok(full["audit_events"].as_array().ok_or("observer_audit_shape")?.iter().filter(|row|predicate(row)).map(|row|{
        json!({"id":row["id"],"actor_user_id":row["actor_user_id"],"event_type":row["event_type"],"target_type":row["target_type"],"target_id":row["target_id"],"payload":row["payload"],"created_at":row["created_at"]})
    }).collect())
}
async fn probe(state: &State, wire: &OwnedWire) -> Result<Value, String> {
    let current = case(state).await?;
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "observer_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "observer_begin")?;
    let observer_row=tx.query_one("SELECT pg_backend_pid(),current_setting('transaction_read_only'),current_setting('transaction_isolation')",&[]).await.map_err(|_|"observer_transaction_settings")?;
    let pid: i32 = observer_row.get(0);
    let read_only: String = observer_row.get(1);
    let isolation: String = observer_row.get(2);
    if read_only != "on" || isolation != "read committed" {
        return Err("observer_actual_transaction_settings".to_owned());
    }
    let full = full_snapshot(&tx).await?;
    let session: Value = tx
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
        let record=tx.query_one("SELECT to_jsonb(m),to_jsonb(s)-'encrypted_value',s.encrypted_value,s.id FROM public.model_connections m JOIN public.model_connection_secrets s ON s.id=m.current_secret_id AND s.connection_id=m.id AND s.deployment_id=m.deployment_id AND s.tenant_id=m.tenant_id AND s.owner_user_id=m.owner_user_id WHERE m.id=$1 AND m.deployment_id=$2 AND m.tenant_id=$3 AND m.owner_user_id=$4",&[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"observer_current_model")?;
        row = record.get(0);
        secret = record.get(1);
        let encrypted: String = record.get(2);
        let secret_id: Uuid = record.get(3);
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
            .map_err(|_| "observer_actual_vault_open")?;
        let migration = opened.needs_migration();
        let plaintext = opened.into_secret();
        let wrong_tenant = CredentialRecordVault::single_key(
            TenantId::new("owned-c6-wrong-tenant"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "observer_wrong_tenant_key")?,
        );
        vault = json!({"canaryMatches":plaintext.expose()==MODEL_KEY.as_bytes(),"needsMigration":migration,
            "wrongOwnerRejected":state.vault.open(&secret_id,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("owned-c6-wrong-owner")),service.clone(),&encrypted).is_err(),
            "wrongServiceRejected":state.vault.open(&secret_id,SecretKind::Model,owner.clone(),SecretPrincipal::Service(ServiceId::new("owned-c6-wrong-service")),&encrypted).is_err(),
            "wrongTenantRejected":wrong_tenant.open(&secret_id,SecretKind::Model,owner,service,&encrypted).is_err()});
    }
    tx.commit().await.map_err(|_| "observer_end")?;
    let baseline = state.baseline.lock().await;
    let mut business = serde_json::Map::new();
    for name in RELATIONS {
        business.insert(name.to_owned(),json!({"count":full[name].as_array().ok_or("observer_relation_shape")?.len(),"unchangedFromModelBinding":baseline.as_ref().map(|b|b[name]==full[name])}));
    }
    drop(baseline);
    let models = safe_audit_rows(&full, |v| {
        v["event_type"] == "configuration.changed"
            && v["target_type"] == "model_connection"
            && v["payload"]["change"] == "model_connection_created"
    })?;
    let audits = safe_audit_rows(&full, |v| {
        v["actor_user_id"] == current.actor
            && v["target_type"] == "run"
            && (v["event_type"] == "agent.invoked" || v["event_type"] == "agent.stream_stalled")
    })?;
    let rows = |name: &str| {
        full[name]
            .as_array()
            .ok_or_else(|| "observer_relation_shape".to_owned())
    };
    let tool_effects = rows("tool_calls")?.len()
        + rows("tool_attempts")?.len()
        + rows("remember_effect_receipts")?.len()
        + rows("memories")?.len()
        + rows("memory_events")?.len()
        + rows("messages")?
            .iter()
            .filter(|r| r["role"] == "tool")
            .count();
    let counts = json!({"modelConnections":rows("model_connections")?.len(),"modelConnectionSecrets":rows("model_connection_secrets")?.len(),"activeModelSecrets":rows("model_connection_secrets")?.iter().filter(|r|r["retired_at"].is_null()).count(),"agents":rows("agents")?.len(),"threads":rows("threads")?.len(),"runs":rows("runs")?.len(),"messages":rows("messages")?.len(),"runEvents":rows("run_events")?.len(),"runSelections":rows("run_model_selections")?.len(),"dispatch":rows("outbox")?.iter().filter(|r|r["destination"]=="agent_run_dispatch").count(),"cancelDispatch":rows("outbox")?.iter().filter(|r|r["destination"]=="agent_run_cancel").count(),"toolEffects":tool_effects,"modelCreateAudits":models.len(),"agentInvokedAudits":audits.iter().filter(|r|r["event_type"]=="agent.invoked").count(),"agentStreamStalledAudits":audits.iter().filter(|r|r["event_type"]=="agent.stream_stalled").count()});
    state.audit_fault.refresh().await?;
    Ok(
        json!({"caseId":state.case_id,"boundModelId":current.model_id,"row":row,"currentSecret":secret,"vault":vault,"counts":counts,"business":business,
        "audit":{"audit_events":business["audit_events"],"audit_checkpoints":business["audit_checkpoints"],"modelCreates":models,"agentAudits":audits},
        "session":session,"policy":full["action_policy"].as_array().and_then(|v|v.first()).cloned().unwrap_or(Value::Null),
        "counters":live_counters(state,wire.counts()).await,"requests":state.requests.lock().await.clone(),"wireRequests":wire_requests(&wire.requests().map_err(str::to_owned)?,&wire.origin())?,
        "observer":{"backendPid":pid,"readOnly":read_only=="on","isolation":isolation},"wireState":wire.state().map_err(str::to_owned)?,
        "providerObservations":state.observations.snapshot()?,"controllers":{"auditFault":state.audit_fault.snapshot()?,"sseTransport":state.sse.snapshot()?}}),
    )
}
async fn bind_model(state: &State, wire: &OwnedWire, args: &Value) -> Result<Value, String> {
    let id = Uuid::parse_str(text(args, "modelId")?).map_err(|_| "model_id_invalid")?;
    let mut slot = state.case.lock().await;
    let current = slot.as_mut().ok_or("case_not_prepared")?;
    if current.model_id.is_some() {
        return Err("model_already_bound".to_owned());
    }
    let mut client = state.observer.get().await.map_err(|_| "bind_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "bind_readonly_begin")?;
    let row:Value=tx.query_one("SELECT to_jsonb(m) FROM public.model_connections m WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND deleted_at IS NULL",&[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"bind_original_model")?.get(0);
    let full = full_snapshot(&tx).await?;
    tx.commit().await.map_err(|_| "bind_readonly_end")?;
    current.model_id = Some(id);
    *state.baseline.lock().await = Some(full);
    drop(slot);
    Ok(
        json!({"caseId":state.case_id,"modelId":id,"revision":row["revision"],"probe":probe(state,wire).await?}),
    )
}
fn route(path: &str, suffix: &str) -> bool {
    path.starts_with("/api/threads/") && path.ends_with(suffix)
}
async fn live_counters(state: &State, wire: Counts) -> Value {
    let requests = state.requests.lock().await;
    let count = |method: &str, predicate: &dyn Fn(&str) -> bool, status: u64| {
        requests
            .iter()
            .filter(|r| {
                r["method"] == method
                    && r["path"].as_str().is_some_and(predicate)
                    && r["status"] == status
            })
            .count()
    };
    json!({"modelPost":state.counters.model_post.load(Ordering::SeqCst),"model201":count("POST",&|p|p=="/api/me/model-connections",201),"agentPost":state.counters.agent_post.load(Ordering::SeqCst),"agent201":count("POST",&|p|p=="/api/agents",201),"mintPost":state.counters.mint_post.load(Ordering::SeqCst),"beginPost":state.counters.begin_post.load(Ordering::SeqCst),"begin201":count("POST",&|p|route(p,"/runs"),201),"capGet":state.counters.cap_get.load(Ordering::SeqCst),"cap200":count("GET",&|p|p=="/api/me/capabilities",200),"customStart":state.counters.custom.load(Ordering::SeqCst),"packageStart":state.counters.package.load(Ordering::SeqCst),"managedStart":state.counters.managed.load(Ordering::SeqCst),"remoteValidate":state.counters.remote_validate.load(Ordering::SeqCst),"remoteStart":state.counters.remote_start.load(Ordering::SeqCst),"dns":wire.dns,"tcp":wire.tcp,"http":wire.http,"apiIngressCount":state.counters.api_ingress.load(Ordering::SeqCst),"servedIndex":state.counters.served_index.load(Ordering::SeqCst),"collectionFailed":state.counters.collection_failed.load(Ordering::SeqCst),"cancelPost":state.counters.cancel_post.load(Ordering::SeqCst),"cancel202":count("POST",&|p|route(p,"/cancel"),202),"reconciliationGet":state.counters.reconciliation_get.load(Ordering::SeqCst),"reconciliation200":count("GET",&|p|route(p,"/reconciliation"),200),"effectReceiptsGet":state.counters.receipts_get.load(Ordering::SeqCst),"effectReceipts200":count("GET",&|p|route(p,"/reconciliation/receipts"),200),"sseGet":state.counters.sse_get.load(Ordering::SeqCst),"sse200":count("GET",&|p|events_path(p).is_some(),200)})
}
fn wire_requests(requests: &[RawRequest], origin: &str) -> Result<Value, String> {
    let expected = origin.trim_start_matches("https://");
    let mut safe = Vec::new();
    for request in requests {
        let body: Value =
            serde_json::from_slice(&request.body).map_err(|_| "wire_original_json")?;
        let last = body["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|r| r["role"] == "user"))
            .and_then(|r| r["content"].as_str())
            .ok_or("wire_original_user")?;
        safe.push(json!({"method":request.method,"target":request.target,"model":body["model"],"stream":body["stream"],"authorizationMatches":request.headers.get("authorization").is_some_and(|h|h==&format!("Bearer {MODEL_KEY}")),"authorizationHeaderCount":request.header_counts.get("authorization").copied().unwrap_or(0),"secretInBody":request.body.windows(MODEL_KEY.len()).any(|v|v==MODEL_KEY.as_bytes()),"bodySha256":null,"requestOrdinal":request.request_ordinal,"lastUserCanaryA":last==INTENT_A,"lastUserCanaryB":last==INTENT_B,"hostMatches":request.headers.get("host").is_some_and(|v|v==expected),"hostHeaderCount":request.header_counts.get("host").copied().unwrap_or(0)}));
    }
    Ok(json!(safe))
}
fn events_path(path: &str) -> Option<&str> {
    let t = path
        .strip_prefix("/api/threads/")?
        .strip_suffix("/events")?;
    (!t.is_empty() && t.len() <= 128 && !t.contains('/') && !t.chars().any(char::is_control))
        .then_some(t)
}

const AUDIT_DDL_TEMPLATE: &str = r###"CREATE SCHEMA owned_c6_fault;
CREATE SEQUENCE owned_c6_fault.stream_stalled_once START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 2 CACHE 1 NO CYCLE;
CREATE FUNCTION owned_c6_fault.reject_one_stream_stalled() RETURNS trigger LANGUAGE plpgsql AS $owned$
BEGIN
  IF NEW.actor_user_id = __ACTOR__ AND NEW.target_type = 'run' AND NEW.target_id = __RUN__ AND NEW.event_type = 'agent.stream_stalled' AND __ACTUAL_JOINT_EXISTS__ THEN
    IF nextval('owned_c6_fault.stream_stalled_once') = 1 THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'owned_c6_matching_stream_stalled', DETAIL = __SAFE_BOUND_TUPLE_DETAIL__;
    END IF;
  END IF;
  RETURN NEW;
END;
$owned$;
CREATE TRIGGER owned_c6_one_stream_stalled BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION owned_c6_fault.reject_one_stream_stalled();"###;
const AUDIT_JOINT_TEMPLATE: &str = r###"EXISTS (SELECT 1 FROM public.runs r JOIN public.threads t USING(thread_id) JOIN public.run_model_selections s USING(run_id) WHERE r.run_id = __RUN__ AND r.actor_id = __ACTOR__ AND r.thread_id = __THREAD__ AND r.bot_id = __BOT__ AND t.deployment_id = __DEPLOYMENT__ AND t.tenant_id = __TENANT__ AND s.owner_user_id = __ACTOR__ AND s.deployment_id = __DEPLOYMENT__ AND s.tenant_id = __TENANT__ AND s.auth_generation = __AUTH_GENERATION__ AND s.connection_id = __CONNECTION__::uuid AND s.connection_revision = __REVISION__ AND s.secret_id = __SECRET__::uuid)"###;
const AUDIT_FAULT_KEYS: &[&str] = &[
    "phase",
    "armed",
    "runId",
    "threadId",
    "botId",
    "actorId",
    "deploymentId",
    "tenantId",
    "sessionId",
    "authGeneration",
    "connectionId",
    "connectionRevision",
    "secretId",
    "ddlInstalled",
    "ddlSha256",
    "matchingSequenceValue",
    "matchingSequenceCalled",
    "errorWitness",
    "calls",
    "disarmAttempted",
    "disarmReturned",
    "remainingObjects",
    "error",
];
const SSE_TRANSPORT_KEYS: &[&str] = &[
    "phase",
    "runId",
    "threadId",
    "actorId",
    "sessionId",
    "authGeneration",
    "lastObservedGlobalCursor",
    "closedStreamId",
    "closeRequested",
    "originalBodyDropObserved",
    "closeCount",
    "reconnectCaptured",
    "reconnectRequestSequence",
    "lastEventId",
    "queryCursor",
    "cookieMatches",
    "originalHandlerReturned200",
    "releaseSent",
    "reconnectReceiverReturned",
    "reconnectReceiverDropped",
    "streams",
    "remainingWrappers",
    "remainingGates",
    "error",
];
fn empty_facts(keys: &[&str]) -> Value {
    Value::Object(
        keys.iter()
            .map(|k| ((*k).to_owned(), Value::Null))
            .collect(),
    )
}
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn locked_value(value: &StdMutex<Value>) -> Result<Value, String> {
    value
        .lock()
        .map(|v| v.clone())
        .map_err(|_| "controller_observation_poisoned".to_owned())
}
struct AuditFault {
    pool: Pool,
    facts: StdMutex<Value>,
    calls: StdMutex<Vec<Value>>,
    log: std::path::PathBuf,
    log_device: u64,
    log_inode: u64,
    log_start: AtomicU64,
}
impl AuditFault {
    fn new(pool: Pool, log: std::path::PathBuf, device: u64, inode: u64) -> Self {
        let mut facts = empty_facts(AUDIT_FAULT_KEYS);
        facts["phase"] = json!("inactive");
        for key in ["armed", "ddlInstalled", "disarmAttempted", "disarmReturned"] {
            facts[key] = json!(false);
        }
        facts["calls"] = json!([]);
        facts["remainingObjects"] = json!(0);
        Self {
            pool,
            facts: StdMutex::new(facts),
            calls: StdMutex::new(Vec::new()),
            log,
            log_device: device,
            log_inode: inode,
            log_start: AtomicU64::new(0),
        }
    }
    fn snapshot(&self) -> Result<Value, String> {
        let mut facts = locked_value(&self.facts)?;
        facts["calls"] = json!(
            *self
                .calls
                .lock()
                .map_err(|_| "audit_call_observation_poisoned")?
        );
        Ok(facts)
    }
    async fn refresh(&self) -> Result<(), String> {
        let facts = self.snapshot()?;
        if facts["ddlInstalled"] != true {
            return Ok(());
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| "audit_fault_observer_connection")?;
        let seq = client
            .query_one(
                "SELECT last_value,is_called FROM owned_c6_fault.stream_stalled_once",
                &[],
            )
            .await
            .map_err(|_| "audit_fault_sequence_read")?;
        let number: i64 = seq.get(0);
        let called: bool = seq.get(1);
        {
            let mut f = self
                .facts
                .lock()
                .map_err(|_| "audit_fault_observation_poisoned")?;
            f["matchingSequenceValue"] = json!(number);
            f["matchingSequenceCalled"] = json!(called);
        }
        if !called {
            return Ok(());
        }
        if number != 1 {
            return Err("audit_fault_not_once".to_owned());
        }
        let run = text(&facts, "runId")?;
        let matching: Vec<&Value> = facts["calls"]
            .as_array()
            .ok_or("audit_calls_shape")?
            .iter()
            .filter(|v| v["runId"] == run && v["kind"] == "stream_stalled")
            .collect();
        if matching.len() > 1 {
            return Err("audit_fault_extra_original_call".to_owned());
        }
        if matching.len() == 1 && matching[0]["result"] == "unavailable" {
            let witness = self.read_error_witness(&facts)?;
            let identity = client
                .query_one("SELECT current_database(),current_user", &[])
                .await
                .map_err(|_| "audit_actual_database_user")?;
            let database: String = identity.get(0);
            let user: String = identity.get(1);
            if witness["database"] != database || witness["user"] != user {
                return Err("audit_error_database_user_mismatch".to_owned());
            }
            self.facts
                .lock()
                .map_err(|_| "audit_fault_observation_poisoned")?["errorWitness"] = witness;
        }
        Ok(())
    }
    fn read_log(&self) -> Result<Vec<u8>, String> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let before = std::fs::symlink_metadata(&self.log).map_err(|_| "audit_log_metadata")?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.dev() != self.log_device
            || before.ino() != self.log_inode
            || before.len() > 2 * 1024 * 1024
        {
            return Err("audit_log_identity_or_limit".to_owned());
        }
        let mut file = std::fs::File::open(&self.log).map_err(|_| "audit_log_open")?;
        let opened = file.metadata().map_err(|_| "audit_log_opened_metadata")?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err("audit_log_open_identity".to_owned());
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "audit_log_read")?;
        let after = std::fs::symlink_metadata(&self.log).map_err(|_| "audit_log_after_metadata")?;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || bytes.len() > 2 * 1024 * 1024
        {
            return Err("audit_log_after_identity_or_limit".to_owned());
        }
        Ok(bytes)
    }
    fn read_error_witness(&self, facts: &Value) -> Result<Value, String> {
        let bytes = self.read_log()?;
        let offset = self.log_start.load(Ordering::SeqCst) as usize;
        if offset > bytes.len() {
            return Err("audit_log_truncated".to_owned());
        }
        let textlog = std::str::from_utf8(&bytes[offset..]).map_err(|_| "audit_log_utf8")?;
        let marker = "owned_c6_matching_stream_stalled";
        let mut offset_now = offset;
        let mut error_lines = Vec::new();
        for line in textlog.split_inclusive('\n') {
            if line.contains("sqlstate=P0001:") && line.contains("ERROR:") && line.contains(marker)
            {
                error_lines.push((offset_now, line));
            }
            offset_now += line.len();
        }
        if error_lines.len() != 1 {
            return Err("audit_exact_original_error_missing_or_ambiguous".to_owned());
        }
        let (start, line) = error_lines[0];
        let prefix = line.split("ERROR:").next().ok_or("audit_error_prefix")?;
        let number = |key: &str| -> Result<i32, String> {
            let v = prefix
                .split(&format!(",{key}="))
                .nth(1)
                .and_then(|v| v.split(',').next())
                .ok_or("audit_error_prefix_field")?;
            v.parse().map_err(|_| "audit_error_prefix_value".to_owned())
        };
        let pid = number("pid")?;
        let field = |key: &str| -> Result<String, String> {
            prefix
                .split(&format!(",{key}="))
                .nth(1)
                .and_then(|v| v.split(',').next())
                .map(str::to_owned)
                .ok_or_else(|| "audit_error_prefix_field".to_owned())
        };
        let database = field("db")?;
        let user = field("user")?;
        let tail = &std::str::from_utf8(&bytes).map_err(|_| "audit_log_utf8")?[start..];
        let mut detail = None;
        let mut statement = None;
        let mut end = start;
        for line in tail.split_inclusive('\n').take(12) {
            end += line.len();
            if !line.contains(&format!(",pid={pid},db={database},user={user},")) {
                continue;
            }
            if let Some(s) = line.split("DETAIL:  ").nth(1) {
                detail = Some(s.trim());
            }
            if let Some(s) = line.split("STATEMENT:  ").nth(1) {
                statement = Some(s.trim());
                break;
            }
        }
        let expected = serde_json::to_string(&safe_fault_tuple(facts))
            .map_err(|_| "audit_error_detail_encode")?;
        if detail != Some(expected.as_str()) || statement != Some(ORIGINAL_AUDIT_INSERT) {
            return Err("audit_error_detail_or_original_insert_mismatch".to_owned());
        }
        let mut witness = empty_facts(&[
            "observed",
            "sqlState",
            "marker",
            "backendPid",
            "database",
            "user",
            "actorId",
            "runId",
            "threadId",
            "deploymentId",
            "tenantId",
            "connectionId",
            "connectionRevision",
            "secretId",
            "originalInsertSha256",
            "logByteStart",
            "logByteEnd",
            "boundary",
        ]);
        for key in [
            "actorId",
            "runId",
            "threadId",
            "deploymentId",
            "tenantId",
            "connectionId",
            "connectionRevision",
            "secretId",
        ] {
            witness[key] = facts[key].clone();
        }
        witness["observed"] = json!(true);
        witness["sqlState"] = json!("P0001");
        witness["marker"] = json!(marker);
        witness["backendPid"] = json!(pid);
        witness["database"] = json!(database);
        witness["user"] = json!(user);
        witness["originalInsertSha256"] =
            json!(Sha256Digest::of(ORIGINAL_AUDIT_INSERT.as_bytes()).to_hex());
        witness["logByteStart"] = json!(start);
        witness["logByteEnd"] = json!(end);
        witness["boundary"] = json!(
            "actual owned PostgreSQL ERROR/DETAIL/parameterized STATEMENT after installed-DDL byte offset and original forwarded Unavailable; no bind parameter/raw log exported"
        );
        Ok(witness)
    }
    async fn disarm(&self) -> Result<(), String> {
        let attempted = self.snapshot()?["armed"] == true;
        if !attempted {
            return Ok(());
        }
        self.facts.lock().map_err(|_| "audit_fault_poisoned")?["disarmAttempted"] = json!(true);
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| "audit_disarm_connection")?;
        let mut errors = Vec::new();
        for sql in [
            "DROP TRIGGER IF EXISTS owned_c6_one_stream_stalled ON public.audit_events",
            "DROP FUNCTION IF EXISTS owned_c6_fault.reject_one_stream_stalled()",
            "DROP SEQUENCE IF EXISTS owned_c6_fault.stream_stalled_once",
            "DROP SCHEMA IF EXISTS owned_c6_fault",
        ] {
            if client.batch_execute(sql).await.is_err() {
                errors.push("audit_disarm_ddl");
            }
        }
        let count:i64=client.query_one("SELECT (SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='owned_c6_fault') + (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='owned_c6_fault' AND p.proname='reject_one_stream_stalled') + (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='owned_c6_fault' AND c.relname='stream_stalled_once' AND c.relkind='S') + (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgname='owned_c6_one_stream_stalled' AND tgrelid='public.audit_events'::regclass)",&[]).await.map_err(|_|"audit_disarm_catalog")?.get(0);
        let mut f = self.facts.lock().map_err(|_| "audit_fault_poisoned")?;
        f["remainingObjects"] = json!(count);
        f["disarmReturned"] = json!(errors.is_empty() && count == 0);
        if errors.is_empty() && count == 0 {
            f["phase"] = json!("disarmed");
            f["ddlInstalled"] = json!(false);
            Ok(())
        } else {
            f["error"] = json!("audit_disarm_failed");
            Err("audit_disarm_failed".to_owned())
        }
    }
}
fn safe_fault_tuple(f: &Value) -> Value {
    json!({"actorId":f["actorId"],"runId":f["runId"],"threadId":f["threadId"],"deploymentId":f["deploymentId"],"tenantId":f["tenantId"],"connectionId":f["connectionId"],"connectionRevision":f["connectionRevision"],"secretId":f["secretId"]})
}
struct ObservedAudit {
    inner: Arc<PostgresAgentAudit>,
    fault: Arc<AuditFault>,
}
#[async_trait]
impl AgentAudit for ObservedAudit {
    async fn record(
        &self,
        lease: &RunExecutionLease,
        kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError> {
        let label = match kind {
            AgentAuditKind::Invoked => "invoked",
            AgentAuditKind::StreamStalled => "stream_stalled",
            AgentAuditKind::RunDeadlineExceeded => "run_deadline_exceeded",
            AgentAuditKind::RunCostBudgetUnpriced => "run_cost_budget_unpriced",
            AgentAuditKind::RunCostBudgetCurrencyMismatch => "run_cost_budget_currency_mismatch",
            AgentAuditKind::RunCostBudgetExceeded => "run_cost_budget_exceeded",
        };
        let index = match self.fault.calls.lock() {
            Ok(mut calls) => {
                let index = calls.len();
                calls.push(json!({"ordinal":index+1,"runId":lease.run_id().as_str(),"threadId":lease.thread_id().as_str(),"botId":lease.bot_id().as_str(),"actorId":lease.actor_id().as_str(),"fencing":lease.fencing().get(),"nextRunSequence":lease.next_event_sequence(),"kind":label,"forwarded":true,"startedAtMs":now_ms(),"returnedAtMs":null,"result":null}));
                Some(index)
            }
            Err(_) => None,
        };
        // The original same-pool PostgresAgentAudit creates and executes its actual transaction.
        // No fabricated error or return substitutes the original port.
        let result = self.inner.record(lease, kind).await;
        if let Some(index) = index
            && let Ok(mut calls) = self.fault.calls.lock()
            && let Some(row) = calls.get_mut(index)
        {
            row["returnedAtMs"] = json!(now_ms());
            row["result"] = json!(if result.is_ok() { "ok" } else { "unavailable" });
        }
        result
    }
}

struct StreamControl {
    close: AtomicBool,
    nominated: AtomicBool,
    waker: StdMutex<Option<std::task::Waker>>,
}
struct SseRequestMetadata {
    generation: u64,
    last_id: Option<u64>,
    cursor: Option<u64>,
    cookie_matches: bool,
}
struct SseController {
    facts: StdMutex<Value>,
    controls: StdMutex<std::collections::BTreeMap<u64, Arc<StreamControl>>>,
    sender: StdMutex<Option<oneshot::Sender<()>>>,
}
impl SseController {
    fn new() -> Self {
        let mut facts = empty_facts(SSE_TRANSPORT_KEYS);
        facts["phase"] = json!("inactive");
        facts["streams"] = json!([]);
        for key in [
            "closeRequested",
            "originalBodyDropObserved",
            "reconnectCaptured",
            "cookieMatches",
            "originalHandlerReturned200",
            "releaseSent",
            "reconnectReceiverReturned",
            "reconnectReceiverDropped",
        ] {
            facts[key] = json!(false);
        }
        facts["closeCount"] = json!(0);
        facts["remainingWrappers"] = json!(0);
        facts["remainingGates"] = json!(0);
        Self {
            facts: StdMutex::new(facts),
            controls: StdMutex::new(std::collections::BTreeMap::new()),
            sender: StdMutex::new(None),
        }
    }
    fn snapshot(&self) -> Result<Value, String> {
        locked_value(&self.facts)
    }
    fn register(
        self: &Arc<Self>,
        body: axum::body::Body,
        sequence: u64,
        thread: &str,
        current: &Case,
        metadata: SseRequestMetadata,
    ) -> Result<axum::body::Body, (String, axum::body::Body)> {
        let SseRequestMetadata {
            generation,
            last_id,
            cursor,
            cookie_matches,
        } = metadata;
        let control = Arc::new(StreamControl {
            close: AtomicBool::new(false),
            nominated: AtomicBool::new(false),
            waker: StdMutex::new(None),
        });
        let mut controls = match self.controls.lock() {
            Ok(v) => v,
            Err(_) => return Err(("sse_controls_poisoned".to_owned(), body)),
        };
        let mut facts = match self.facts.lock() {
            Ok(v) => v,
            Err(_) => return Err(("sse_observation_poisoned".to_owned(), body)),
        };
        let pending = match facts["remainingWrappers"].as_u64() {
            Some(v) => v,
            None => return Err(("sse_pending_shape".to_owned(), body)),
        };
        let rows = match facts["streams"].as_array_mut() {
            Some(v) => v,
            None => return Err(("sse_stream_shape".to_owned(), body)),
        };
        if rows.len() >= 8 {
            return Err(("sse_stream_limit".to_owned(), body));
        }
        let index = rows.len();
        rows.push(json!({"streamId":sequence,"requestSequence":sequence,"threadId":thread,"sessionId":current.session,"actorId":current.actor,"authGeneration":generation,"lastEventId":last_id,"queryCursor":cursor,"cookieMatches":cookie_matches,"originalHandlerReturned200":true,"forwardedFrames":0,"lastForwardedEventId":null,"bodyDropObserved":false,"controllerClosed":false,"error":null}));
        facts["remainingWrappers"] = json!(pending + 1);
        if facts["reconnectRequestSequence"] == sequence {
            facts["originalHandlerReturned200"] = json!(true);
            facts["phase"] = json!("reconnected");
        }
        controls.insert(sequence, control.clone());
        drop(facts);
        drop(controls);
        Ok(axum::body::Body::from_stream(OriginalBodyStream {
            inner: Some(Box::pin(body.into_data_stream())),
            owner: self.clone(),
            control,
            index,
            sequence,
            buffer: Vec::new(),
            dropped: false,
        }))
    }
    fn frame(&self, index: usize, bytes: &[u8], buffer: &mut Vec<u8>) -> Result<(), String> {
        buffer.extend_from_slice(bytes);
        if buffer.len() > 262144 {
            return Err("sse_frame_observation_limit".to_owned());
        }
        while let Some(end) = buffer.windows(2).position(|v| v == b"\n\n") {
            let frame: Vec<u8> = buffer.drain(..end + 2).collect();
            let text = std::str::from_utf8(&frame).map_err(|_| "sse_original_frame_utf8")?;
            let id = text
                .lines()
                .find_map(|l| l.strip_prefix("id:").map(str::trim))
                .map(str::parse::<u64>)
                .transpose()
                .map_err(|_| "sse_original_id_invalid")?;
            let data = text
                .lines()
                .filter_map(|l| l.strip_prefix("data:").map(str::trim_start))
                .collect::<Vec<_>>()
                .join("\n");
            if !data.is_empty() {
                let _: openbot_contracts::command::AppEvent =
                    serde_json::from_str(&data).map_err(|_| "sse_original_app_event_invalid")?;
            }
            let mut facts = self.facts.lock().map_err(|_| "sse_observation_poisoned")?;
            let row = facts["streams"]
                .as_array_mut()
                .and_then(|r| r.get_mut(index))
                .ok_or("sse_stream_missing")?;
            row["forwardedFrames"] =
                json!(row["forwardedFrames"].as_u64().ok_or("sse_frame_count")? + 1);
            if let Some(id) = id {
                row["lastForwardedEventId"] = json!(id);
            }
        }
        Ok(())
    }
    fn dropped(&self, index: usize, sequence: u64, controlled: bool) {
        if let Ok(mut facts) = self.facts.lock()
            && let Some(row) = facts["streams"]
                .as_array_mut()
                .and_then(|r| r.get_mut(index))
            && row["bodyDropObserved"] != true
        {
            row["bodyDropObserved"] = json!(true);
            row["controllerClosed"] = json!(controlled);
            facts["remainingWrappers"] = json!(
                facts["remainingWrappers"]
                    .as_u64()
                    .unwrap_or(1)
                    .saturating_sub(1)
            );
            if controlled {
                facts["originalBodyDropObserved"] = json!(true);
                facts["closeCount"] = json!(facts["closeCount"].as_u64().unwrap_or(0) + 1);
                facts["phase"] = json!("disconnected");
            }
        }
        if let Ok(mut controls) = self.controls.lock() {
            controls.remove(&sequence);
        }
    }
    fn request_close(
        &self,
        current: &Case,
        run: &str,
        thread: &str,
        cursor: u64,
    ) -> Result<bool, String> {
        let mut facts = self.facts.lock().map_err(|_| "sse_observation_poisoned")?;
        if facts["closeRequested"] == true {
            return Err("sse_close_already_requested".to_owned());
        }
        let streams = facts["streams"].as_array().ok_or("sse_stream_shape")?;
        let matching: Vec<&Value> = streams
            .iter()
            .filter(|s| {
                s["threadId"] == thread
                    && s["sessionId"] == current.session
                    && s["actorId"] == current.actor
                    && s["bodyDropObserved"] == false
                    && s["lastForwardedEventId"] == cursor
                    && s["originalHandlerReturned200"] == true
                    && s["cookieMatches"] == true
            })
            .collect();
        if matching.len() != 1 {
            return Err("sse_live_original_cursor_missing_or_ambiguous".to_owned());
        }
        let id = matching[0]["streamId"].as_u64().ok_or("sse_stream_id")?;
        let generation = matching[0]["authGeneration"].clone();
        facts["phase"] = json!("close_requested");
        facts["runId"] = json!(run);
        facts["threadId"] = json!(thread);
        facts["actorId"] = json!(current.actor);
        facts["sessionId"] = json!(current.session);
        facts["authGeneration"] = generation;
        facts["lastObservedGlobalCursor"] = json!(cursor);
        facts["closedStreamId"] = json!(id);
        facts["closeRequested"] = json!(true);
        drop(facts);
        let control = self
            .controls
            .lock()
            .map_err(|_| "sse_controls_poisoned")?
            .get(&id)
            .cloned()
            .ok_or("sse_live_body_missing")?;
        control.nominated.store(true, Ordering::SeqCst);
        control.close.store(true, Ordering::SeqCst);
        if let Some(waker) = control
            .waker
            .lock()
            .map_err(|_| "sse_waker_poisoned")?
            .take()
        {
            waker.wake();
        }
        Ok(true)
    }
    async fn maybe_hold(
        self: &Arc<Self>,
        sequence: u64,
        thread: &str,
        current: &Case,
        metadata: SseRequestMetadata,
    ) -> Result<(), String> {
        let SseRequestMetadata {
            generation,
            last_id,
            cursor,
            cookie_matches: cookie,
        } = metadata;
        let receiver = {
            let mut facts = self.facts.lock().map_err(|_| "sse_observation_poisoned")?;
            if facts["closeRequested"] != true || facts["threadId"] != thread {
                return Ok(());
            }
            if facts["reconnectCaptured"] == true {
                // A new EventSource may bootstrap from the cursor already forwarded by the retry.
                let ordinary_bootstrap = facts["releaseSent"] == true
                    && facts["reconnectReceiverReturned"] == true
                    && facts["originalHandlerReturned200"] == true
                    && facts["remainingGates"] == 0
                    && facts["sessionId"] == current.session
                    && facts["actorId"] == current.actor
                    && facts["authGeneration"] == generation
                    && cookie
                    && last_id.is_none()
                    && cursor.is_some_and(|fresh| {
                        facts["lastObservedGlobalCursor"]
                            .as_u64()
                            .is_some_and(|prior| fresh > prior)
                            && facts["streams"].as_array().is_some_and(|streams| {
                                streams.iter().any(|stream| {
                                    stream["requestSequence"] == facts["reconnectRequestSequence"]
                                        && stream["originalHandlerReturned200"] == true
                                        && stream["lastForwardedEventId"].as_u64() == Some(fresh)
                                })
                            })
                    });
                if ordinary_bootstrap {
                    return Ok(());
                }
                return Err("sse_extra_matching_reconnect".to_owned());
            }
            if facts["sessionId"] != current.session
                || facts["actorId"] != current.actor
                || facts["authGeneration"] != generation
                || !cookie
                || last_id.is_none()
                || json!(last_id) != facts["lastObservedGlobalCursor"]
            {
                return Err("sse_real_reconnect_scope_or_cursor_mismatch".to_owned());
            }
            let (sender, receiver) = oneshot::channel();
            *self.sender.lock().map_err(|_| "sse_sender_poisoned")? = Some(sender);
            facts["reconnectCaptured"] = json!(true);
            facts["reconnectRequestSequence"] = json!(sequence);
            facts["lastEventId"] = json!(last_id);
            facts["queryCursor"] = json!(cursor);
            facts["cookieMatches"] = json!(cookie);
            facts["remainingGates"] = json!(1);
            facts["phase"] = json!("reconnect_held");
            receiver
        };
        let mut owned = ReconnectReceiver {
            owner: self.clone(),
            receiver: Some(receiver),
            returned: false,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            owned.receiver.as_mut().ok_or("sse_receiver_missing")?,
        )
        .await;
        let returned = matches!(result, Ok(Ok(())));
        owned.receiver.take();
        owned.returned = returned;
        let mut facts = self.facts.lock().map_err(|_| "sse_observation_poisoned")?;
        facts["remainingGates"] = json!(0);
        if returned {
            facts["reconnectReceiverReturned"] = json!(true);
            Ok(())
        } else {
            facts["reconnectReceiverDropped"] = json!(true);
            facts["error"] = json!("sse_reconnect_gate_not_released");
            Err("sse_reconnect_gate_not_released".to_owned())
        }
    }

    fn release(&self) -> Result<(), String> {
        let mut facts = self.facts.lock().map_err(|_| "sse_observation_poisoned")?;
        if facts["reconnectCaptured"] != true
            || facts["releaseSent"] == true
            || facts["remainingGates"] != 1
        {
            return Err("sse_release_gate_state".to_owned());
        }
        self.sender
            .lock()
            .map_err(|_| "sse_sender_poisoned")?
            .take()
            .ok_or("sse_release_sender_missing")?
            .send(())
            .map_err(|_| "sse_release_receiver_closed")?;
        facts["releaseSent"] = json!(true);
        facts["phase"] = json!("reconnect_released");
        Ok(())
    }
    fn stop(&self) -> Result<(), String> {
        self.sender
            .lock()
            .map_err(|_| "sse_sender_poisoned")?
            .take();
        for control in self
            .controls
            .lock()
            .map_err(|_| "sse_controls_poisoned")?
            .values()
        {
            control.close.store(true, Ordering::SeqCst);
            if let Ok(mut waker) = control.waker.lock()
                && let Some(w) = waker.take()
            {
                w.wake();
            }
        }
        Ok(())
    }
}
struct ReconnectReceiver {
    owner: Arc<SseController>,
    receiver: Option<oneshot::Receiver<()>>,
    returned: bool,
}
impl Drop for ReconnectReceiver {
    fn drop(&mut self) {
        let was_pending = self.receiver.take().is_some();
        if was_pending && !self.returned {
            if let Ok(mut facts) = self.owner.facts.lock() {
                facts["reconnectReceiverDropped"] = json!(true);
                facts["remainingGates"] = json!(0);
                facts["error"] = json!("sse_reconnect_receiver_cancelled");
            }
            if let Ok(mut sender) = self.owner.sender.lock() {
                sender.take();
            }
        }
    }
}

struct OriginalBodyStream {
    inner: Option<Pin<Box<axum::body::BodyDataStream>>>,
    owner: Arc<SseController>,
    control: Arc<StreamControl>,
    index: usize,
    sequence: u64,
    buffer: Vec<u8>,
    dropped: bool,
}
impl Stream for OriginalBodyStream {
    type Item = Result<axum::body::Bytes, axum::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Ok(mut waker) = this.control.waker.lock() {
            *waker = Some(cx.waker().clone());
        }
        if this.control.close.load(Ordering::SeqCst) {
            this.inner.take();
            if !this.dropped {
                this.owner.dropped(
                    this.index,
                    this.sequence,
                    this.control.nominated.load(Ordering::SeqCst),
                );
                this.dropped = true;
            }
            return Poll::Ready(None);
        }
        let Some(inner) = &mut this.inner else {
            return Poll::Ready(None);
        };
        match inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Err(code) = this.owner.frame(this.index, &bytes, &mut this.buffer) {
                    if let Ok(mut f) = this.owner.facts.lock() {
                        f["error"] = json!(code);
                    }
                    this.buffer.clear();
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(None) => {
                this.inner.take();
                if !this.dropped {
                    this.owner.dropped(this.index, this.sequence, false);
                    this.dropped = true;
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                if let Ok(mut facts) = this.owner.facts.lock() {
                    facts["error"] = json!("sse_original_body_error");
                    if let Some(row) = facts["streams"]
                        .as_array_mut()
                        .and_then(|rows| rows.get_mut(this.index))
                    {
                        row["error"] = json!("sse_original_body_error");
                    }
                }
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for OriginalBodyStream {
    fn drop(&mut self) {
        self.inner.take();
        if !self.dropped {
            self.owner.dropped(
                self.index,
                self.sequence,
                self.control.nominated.load(Ordering::SeqCst),
            );
            self.dropped = true;
        }
    }
}

async fn actual_session_generation(state: &State, current: &Case) -> Result<u64, String> {
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "sse_session_read_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "sse_session_readonly_begin")?;
    let row=tx.query_one("SELECT s.auth_generation FROM public.sessions s JOIN public.users u ON u.id=s.user_id AND u.auth_generation=s.auth_generation WHERE s.id=$1 AND s.user_id=$2 AND s.expires_at>statement_timestamp()",&[&current.session,&current.actor]).await.map_err(|_|"sse_actual_session_generation")?;
    let generation: i64 = row.get(0);
    tx.commit().await.map_err(|_| "sse_session_readonly_end")?;
    u64::try_from(generation).map_err(|_| "sse_session_generation_invalid".to_owned())
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
    let counter = match (method.as_str(), path.as_str()) {
        ("POST", "/api/me/model-connections") => Some(&state.counters.model_post),
        ("POST", "/api/agents") => Some(&state.counters.agent_post),
        ("POST", "/api/threads/mint") => Some(&state.counters.mint_post),
        ("GET", "/api/me/capabilities") => Some(&state.counters.cap_get),
        ("POST", p) if route(p, "/runs") => Some(&state.counters.begin_post),
        ("POST", p) if route(p, "/cancel") => Some(&state.counters.cancel_post),
        ("GET", p) if route(p, "/reconciliation/receipts") => Some(&state.counters.receipts_get),
        ("GET", p) if route(p, "/reconciliation") => Some(&state.counters.reconciliation_get),
        ("GET", p) if events_path(p).is_some() => Some(&state.counters.sse_get),
        _ => None,
    };
    if let Some(c) = counter {
        c.fetch_add(1, Ordering::SeqCst);
    }
    let sequence = state.counters.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    let current = state.case.lock().await.clone();
    let thread = if method == "GET" {
        events_path(&path).map(str::to_owned)
    } else {
        None
    };
    let cookie = current.as_ref().is_some_and(|c| {
        request
            .headers()
            .get(axum::http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| {
                s.split(';')
                    .any(|v| v.trim() == format!("openbot_session={}", c.token))
            })
    });
    let last_id = request
        .headers()
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u64>().ok());
    let cursor = request.uri().query().and_then(|s| {
        url::form_urlencoded::parse(s.as_bytes())
            .find(|(k, _)| k == "cursor")
            .and_then(|(_, v)| v.parse::<u64>().ok())
    });
    let generation = if thread.is_some() && cookie {
        if let Some(c) = &current {
            match actual_session_generation(&state, c).await {
                Ok(g) => Some(g),
                Err(_) => {
                    state
                        .counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    if state.mode == CaseMode::Reconnect
        && let (Some(thread), Some(c), Some(generation)) = (&thread, &current, generation)
        && let Err(code) = state
            .sse
            .maybe_hold(
                sequence,
                thread,
                c,
                SseRequestMetadata {
                    generation,
                    last_id,
                    cursor,
                    cookie_matches: cookie,
                },
            )
            .await
    {
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
        if let Ok(mut facts) = state.sse.facts.lock() {
            facts["error"] = json!(code);
        }
        // A control observation failure stays RED, but never fabricates a product response.
    }
    let mut response = next.run(request).await;
    if response.status().is_success()
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/html"))
    {
        state.counters.served_index.fetch_add(1, Ordering::SeqCst);
    }
    if response.status() == axum::http::StatusCode::OK
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"))
        && let Some(thread) = &thread
    {
        if let Err(code) = observe_positive_subscription(&state, thread, sequence, 200).await {
            state.positive_stream_witness.fail(code);
            state
                .counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        if let Some(c) = current
            && let Some(generation) = generation
            && cookie
        {
            let original_body = std::mem::replace(response.body_mut(), axum::body::Body::empty());
            match state.sse.register(
                original_body,
                sequence,
                thread,
                &c,
                SseRequestMetadata {
                    generation,
                    last_id,
                    cursor,
                    cookie_matches: cookie,
                },
            ) {
                Ok(body) => *response.body_mut() = body,
                Err((code, body)) => {
                    *response.body_mut() = body;
                    state
                        .counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                    if let Ok(mut f) = state.sse.facts.lock() {
                        f["error"] = json!(code);
                    }
                }
            }
        }
    }
    let mut records = state.requests.lock().await;
    if records.len() >= 4096 || path.len() > 2048 {
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
    } else {
        records.push(json!({"sequence":sequence,"method":method,"path":path,"status":response.status().as_u16()}));
    }
    response
}
fn exact_args(value: &Value, keys: &[&str]) -> Result<(), String> {
    let o = value.as_object().ok_or("protocol_args_object")?;
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return Err("protocol_args_closed_schema".to_owned());
    }
    Ok(())
}
async fn current_b(state: &State, run: &str, require_running: bool) -> Result<Value, String> {
    let current = case(state).await?;
    let observed = terminal_snapshot(state, run).await?;
    let model = current.model_id.ok_or("current_model_unbound")?;
    let r = &observed["run"];
    let selection = &observed["modelSelection"];
    let input = observed["messages"]
        .as_array()
        .ok_or("current_messages_shape")?
        .iter()
        .filter(|m| {
            m["message_id"] == format!("{run}:input")
                && m["role"] == "user"
                && m["actor_id"] == current.actor
                && m["content"]["text"] == INTENT_B
        })
        .count();
    if input != 1
        || r["run_id"] != run
        || r["actor_id"] != current.actor
        || (require_running && r["status"] != "running")
        || selection["run_id"] != run
        || selection["connection_id"] != model.to_string()
        || selection["owner_user_id"] != current.actor
        || selection["deployment_id"] != DEPLOYMENT
        || selection["tenant_id"] != TENANT
    {
        return Err("current_b_original_identity".to_owned());
    }
    let attempts = state.observations.snapshot()?;
    let matching: Vec<&Value> = attempts
        .as_array()
        .ok_or("provider_observation_shape")?
        .iter()
        .filter(|v| v["runId"] == run && v["isB"] == true)
        .collect();
    if matching.len() != 1 {
        return Err("current_b_actual_provider_denominator".to_owned());
    }
    let a = matching[0];
    if a["threadId"] != r["thread_id"]
        || a["botId"] != r["bot_id"]
        || a["actorId"] != r["actor_id"]
        || a["connectionId"] != selection["connection_id"]
        || a["connectionRevision"] != selection["connection_revision"]
        || a["secretId"] != selection["secret_id"]
        || a["authGeneration"] != selection["auth_generation"]
        || a["deploymentId"] != selection["deployment_id"]
        || a["tenantId"] != selection["tenant_id"]
    {
        return Err("current_b_original_typed_binding".to_owned());
    }
    let client = state
        .observer
        .get()
        .await
        .map_err(|_| "current_b_model_connection")?;
    let row=client.query_one("SELECT c.revision,c.current_secret_id,s.auth_generation FROM public.model_connections c JOIN public.sessions s ON s.id=$2 AND s.user_id=$3 WHERE c.id=$1 AND c.owner_user_id=$3 AND c.deployment_id=$4 AND c.tenant_id=$5 AND c.enabled AND c.deleted_at IS NULL AND s.expires_at>statement_timestamp()",&[&model,&current.session,&current.actor,&DEPLOYMENT,&TENANT]).await.map_err(|_|"current_b_live_tuple")?;
    let revision: i64 = row.get(0);
    let secret: Uuid = row.get(1);
    let generation: i64 = row.get(2);
    if selection["connection_revision"] != revision
        || selection["secret_id"] != secret.to_string()
        || selection["auth_generation"] != generation
    {
        return Err("current_b_live_tuple_mismatch".to_owned());
    }
    Ok(observed)
}
async fn prefix_observed(state: &State, run: &str, witness: &Value) -> Result<Value, String> {
    exact_args(
        witness,
        &[
            "pgEventSequence",
            "sseEventSequence",
            "sseEventId",
            "sseBodySha256",
            "context",
            "domRunId",
            "domTextMatches",
            "observedAtMs",
        ],
    )?;
    let observed = current_b(state, run, true).await?;
    let sequence = witness["pgEventSequence"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or("prefix_sequence_invalid")?;
    let digest = text(witness, "sseBodySha256")?;
    let sse_event_id = sequence.to_string();
    let committed = observed["events"]
        .as_array()
        .ok_or("prefix_events_shape")?
        .iter()
        .filter(|e| {
            e["event_seq"] == sequence
                && e["event_type"] == "semantic_chunk"
                && e["payload"]["channel"] == "text"
                && e["payload"]["delta"] == INTENT_B_PREFIX
                && e["terminal"] == false
        })
        .count();
    if committed != 1
        || witness["sseEventSequence"] != sequence
        || witness["sseEventId"].as_str() != Some(sse_event_id.as_str())
        || witness["domRunId"] != run
        || witness["domTextMatches"] != true
        || text(witness, "context")?.is_empty()
        || digest.len() != 64
        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        || witness["observedAtMs"].as_u64().is_none()
    {
        return Err("prefix_actual_order_witness_mismatch".to_owned());
    }
    Ok(observed)
}
fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
async fn arm_audit(state: &State, wire: &OwnedWire, args: &Value) -> Result<Value, String> {
    if state.mode != CaseMode::AuditUnknown {
        return Err("audit_fault_case_scope".to_owned());
    }
    let run = run_id(args)?;
    let observed = prefix_observed(state, run, &args["actualPrefixWitness"]).await?;
    let current = case(state).await?;
    let existing = state.audit_fault.snapshot()?;
    if existing["armed"] == true {
        return Err("audit_fault_already_armed".to_owned());
    }
    let selection = &observed["modelSelection"];
    let r = &observed["run"];
    let mut f = existing;
    for (key, value) in [
        ("runId", json!(run)),
        ("threadId", r["thread_id"].clone()),
        ("botId", r["bot_id"].clone()),
        ("actorId", json!(current.actor)),
        ("sessionId", json!(current.session)),
        ("deploymentId", selection["deployment_id"].clone()),
        ("tenantId", selection["tenant_id"].clone()),
        ("authGeneration", selection["auth_generation"].clone()),
        ("connectionId", selection["connection_id"].clone()),
        (
            "connectionRevision",
            selection["connection_revision"].clone(),
        ),
        ("secretId", selection["secret_id"].clone()),
    ] {
        f[key] = value;
    }
    let mut replacements = Vec::new();
    for (key, field) in [
        ("__RUN__", "runId"),
        ("__ACTOR__", "actorId"),
        ("__THREAD__", "threadId"),
        ("__BOT__", "botId"),
        ("__DEPLOYMENT__", "deploymentId"),
        ("__TENANT__", "tenantId"),
        ("__CONNECTION__", "connectionId"),
        ("__SECRET__", "secretId"),
    ] {
        replacements.push((key, sql_literal(text(&f, field)?)));
    }
    replacements.push((
        "__AUTH_GENERATION__",
        f["authGeneration"]
            .as_u64()
            .ok_or("audit_binding_generation")?
            .to_string(),
    ));
    replacements.push((
        "__REVISION__",
        f["connectionRevision"]
            .as_i64()
            .filter(|v| *v > 0)
            .ok_or("audit_binding_revision")?
            .to_string(),
    ));
    let mut joint = AUDIT_JOINT_TEMPLATE.to_owned();
    for (key, value) in &replacements {
        joint = joint.replace(key, value);
    }
    let detail = serde_json::to_string(&safe_fault_tuple(&f)).map_err(|_| "audit_detail_encode")?;
    let mut ddl = AUDIT_DDL_TEMPLATE
        .replace("__ACTUAL_JOINT_EXISTS__", &joint)
        .replace("__SAFE_BOUND_TUPLE_DETAIL__", &sql_literal(&detail));
    for (key, value) in &replacements {
        ddl = ddl.replace(key, value);
    }
    if ddl.contains("__") {
        return Err("audit_unbound_ddl_template".to_owned());
    }
    let bytes = state.audit_fault.read_log()?;
    state
        .audit_fault
        .log_start
        .store(bytes.len() as u64, Ordering::SeqCst);
    let client = state
        .controller
        .get()
        .await
        .map_err(|_| "audit_control_connection")?;
    f["phase"] = json!("installing");
    f["armed"] = json!(true);
    f["ddlSha256"] = json!(Sha256Digest::of(ddl.as_bytes()).to_hex());
    *state
        .audit_fault
        .facts
        .lock()
        .map_err(|_| "audit_fault_observation_poisoned")? = f.clone();
    client
        .batch_execute(&ddl)
        .await
        .map_err(|_| "audit_actual_ddl_install")?;
    f["phase"] = json!("armed");
    f["armed"] = json!(true);
    f["ddlInstalled"] = json!(true);
    f["ddlSha256"] = json!(Sha256Digest::of(ddl.as_bytes()).to_hex());
    f["remainingObjects"] = json!(4);
    *state
        .audit_fault
        .facts
        .lock()
        .map_err(|_| "audit_fault_observation_poisoned")? = f;
    Ok(
        json!({"caseId":state.case_id,"runId":run,"armed":true,"auditFault":state.audit_fault.snapshot()?,"probe":probe(state,wire).await?}),
    )
}
async fn execute(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    exact_args(value, &["schemaVersion", "id", "command", "args"])?;
    if value["schemaVersion"] != 1 {
        return Err("protocol_version".to_owned());
    }
    let command = text(value, "command")?;
    let args = &value["args"];
    let keys: &[&str] = match command {
        "prepare" => &["caseId"],
        "bind_model" => &["caseId", "modelId"],
        "observe_run" => &["caseId", "runId"],
        "wait_terminal" | "observe_provider" => &["caseId", "runId", "timeoutMs"],
        "release_provider" => &["caseId", "runId", "phase"],
        "arm_stall_audit_fault" => &["caseId", "runId", "actualPrefixWitness"],
        "arm_reconnect" => &[
            "caseId",
            "runId",
            "lastObservedGlobalCursor",
            "actualPrefixWitness",
        ],
        "release_reconnect" => &["caseId", "runId"],
        "shutdown" => &[],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    exact_args(args, keys)?;
    if command != "shutdown" && text(args, "caseId")? != state.case_id {
        return Err("protocol_case_mismatch".to_owned());
    }
    match command {
        "prepare" => prepare(state, wire).await,
        "bind_model" => bind_model(state, wire, args).await,
        "observe_run" => {
            let run = run_id(args)?;
            let mut snap = terminal_snapshot(state, run).await?;
            snap["caseId"] = json!(state.case_id);
            snap["runId"] = json!(run);
            snap["probe"] = probe(state, wire).await?;
            Ok(snap)
        }
        "wait_terminal" => wait_terminal(state, wire, args).await,
        "observe_provider" => {
            let run = run_id(args)?;
            let ms = args["timeoutMs"]
                .as_u64()
                .filter(|m| *m > 0 && *m <= 4000)
                .ok_or("provider_observe_timeout")?;
            let captured = wire
                .wait_captured(Duration::from_millis(ms))
                .await
                .map_err(str::to_owned)?;
            let mut snap = if captured {
                current_b(state, run, true).await?
            } else {
                terminal_snapshot(state, run).await?
            };
            snap["caseId"] = json!(state.case_id);
            snap["runId"] = json!(run);
            snap["timedOut"] = json!(!captured);
            snap["captured"] = json!(captured);
            snap["probe"] = probe(state, wire).await?;
            Ok(snap)
        }
        "release_provider" => {
            let run = run_id(args)?;
            current_b(state, run, true).await?;
            let phase = text(args, "phase")?;
            wire.release(phase).map_err(str::to_owned)?;
            Ok(
                json!({"caseId":state.case_id,"runId":run,"phase":phase,"released":true,"wireState":wire.state().map_err(str::to_owned)?}),
            )
        }
        "arm_stall_audit_fault" => arm_audit(state, wire, args).await,
        "arm_reconnect" => {
            if state.mode != CaseMode::Reconnect {
                return Err("sse_control_case_scope".to_owned());
            }
            let run = run_id(args)?;
            let observed = prefix_observed(state, run, &args["actualPrefixWitness"]).await?;
            let cursor = args["lastObservedGlobalCursor"]
                .as_u64()
                .filter(|v| *v > 0)
                .ok_or("sse_global_cursor_invalid")?;
            if args["actualPrefixWitness"]["sseEventSequence"] != cursor {
                return Err("sse_prefix_global_cursor".to_owned());
            }
            let closed = state.sse.request_close(
                &case(state).await?,
                run,
                text(&observed["run"], "thread_id")?,
                cursor,
            )?;
            Ok(
                json!({"caseId":state.case_id,"runId":run,"closed":closed,"sseTransport":state.sse.snapshot()?}),
            )
        }
        "release_reconnect" => {
            if state.mode != CaseMode::Reconnect {
                return Err("sse_control_case_scope".to_owned());
            }
            let run = run_id(args)?;
            let observed = current_b(state, run, false).await?;
            if observed["run"]["status"] != "completed"
                || observed["events"]
                    .as_array()
                    .ok_or("sse_terminal_events_shape")?
                    .iter()
                    .filter(|e| e["terminal"] == true && e["event_type"] == "completed")
                    .count()
                    != 1
            {
                return Err("sse_actual_disconnected_terminal_missing".to_owned());
            }
            let f = state.sse.snapshot()?;
            if f["runId"] != run || f["originalBodyDropObserved"] != true || f["closeCount"] != 1 {
                return Err("sse_original_once_close_witness".to_owned());
            }
            state.sse.release()?;
            Ok(
                json!({"caseId":state.case_id,"runId":run,"released":true,"sseTransport":state.sse.snapshot()?}),
            )
        }
        "shutdown" => Ok(json!({})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
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

pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C6_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C6_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C6_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C6_CASE_ID").map_err(|_| "missing_case_id")?;
    let mode = CaseMode::parse(&case_id).ok_or("unknown_c6_mode")?;
    if source.len() != 40
        || spec.len() != 64
        || !source.bytes().all(|b| b.is_ascii_hexdigit())
        || !spec.bytes().all(|b| b.is_ascii_hexdigit())
        || !std::path::Path::new(&dist).is_absolute()
    {
        return Err("invalid_outer_identity".to_owned());
    }
    let log = std::path::PathBuf::from(
        std::env::var("C6_OWNED_PG_LOG").map_err(|_| "missing_owned_pg_log")?,
    );
    let log_device: u64 = std::env::var("C6_OWNED_PG_LOG_DEVICE")
        .map_err(|_| "missing_owned_pg_log_device")?
        .parse()
        .map_err(|_| "owned_pg_log_device")?;
    let log_inode: u64 = std::env::var("C6_OWNED_PG_LOG_INODE")
        .map_err(|_| "missing_owned_pg_log_inode")?
        .parse()
        .map_err(|_| "owned_pg_log_inode")?;
    if !log.is_absolute() {
        return Err("owned_pg_log_path".to_owned());
    }
    let static_app = StaticApp::open(&dist).map_err(|_| "invalid_owned_dist")?;
    let mut application_config = config.clone();
    application_config.max_pool_size = 8;
    application_config.application_name = Some("owned-currentrun-client-application".to_owned());
    let application_pool = pool::connect(&application_config)
        .await
        .map_err(|_| "application_pool")?;
    let mut pool_owners = PoolOwners(vec![application_pool.clone()]);
    let mut observer_config = config.clone();
    observer_config.max_pool_size = 4;
    observer_config.application_name = Some("owned-currentrun-client-observer".to_owned());
    let observer_pool = pool::connect(&observer_config)
        .await
        .map_err(|_| "observer_pool")?;
    pool_owners.0.push(observer_pool.clone());
    let mut controller_config = config.clone();
    controller_config.max_pool_size = 2;
    controller_config.application_name = Some("owned-currentrun-client-controller".to_owned());
    let controller_pool = pool::connect(&controller_config)
        .await
        .map_err(|_| "controller_pool")?;
    pool_owners.0.push(controller_pool.clone());
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    let identity_tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "ready_readonly_begin")?;
    let identity_row = identity_tx
        .query_one(
            "SELECT current_database(),current_user,pg_backend_pid()",
            &[],
        )
        .await
        .map_err(|_| "ready_owned_database_identity")?;
    let actual_database: String = identity_row.get(0);
    let actual_user: String = identity_row.get(1);
    let actual_backend_pid: i32 = identity_row.get(2);
    let case_evidence =
        json!({"database":actual_database,"user":actual_user,"backendPid":actual_backend_pid});
    identity_tx
        .commit()
        .await
        .map_err(|_| "ready_readonly_end")?;
    drop(client);
    let audit_fault = Arc::new(AuditFault::new(
        controller_pool.clone(),
        log,
        log_device,
        log_inode,
    ));
    audit_fault.read_log()?;
    let tenant = TenantId::new(TENANT);
    let deployment = DeploymentId::new(DEPLOYMENT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "owned_vault_key")?,
    );
    // All fallible setup without asynchronous owners precedes starting the TLS listener.
    let wire = OwnedWire::new(
        positive_sse(),
        prefix_sse(),
        tail_sse(mode),
        mode,
        [TEST_CA, TEST_LEAF, TEST_KEY],
    )
    .await
    .map_err(|_| "owned_tls_setup")?;
    let counters = Arc::new(Counters::default());
    let observations = Arc::new(ProviderObservations {
        started: tokio::time::Instant::now(),
        rows: StdMutex::new(Vec::new()),
        counters: counters.clone(),
    });
    let sse = Arc::new(SseController::new());
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        controller: controller_pool.clone(),
        vault: vault.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
        mode,
        positive_stream_witness: wire.positive_witness(),
        observations: observations.clone(),
        baseline: Mutex::new(None),
        audit_fault: audit_fault.clone(),
        sse: sse.clone(),
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
            recovery_gate:openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&application_pool,&deployment,&tenant),
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
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone(),observations:observations.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(RemoteAguiProvider::new(remote)))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
        let context=Arc::new(PostgresAgentContextSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),Some(32)).map_err(|_|"owned_context")?
            .with_tools(vec![remember_provider_tool()]).with_remote_assertions(assertions).with_mcp_catalog(assembled.mcp_catalog.clone())
            .with_components(assembled.components.clone()).with_sandboxed_components(assembled.sandboxed_components.clone()).with_agent_credential_vault(vault.clone()));
        let tools=Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(assembled.application.clone(),Arc::new(PostgresAgentAuthorizationSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),false)),
            Arc::new(PostgresAgentToolSequence::new(application_pool.clone())),assembled.tool_cancellations.clone()));
        let audit=Arc::new(ObservedAudit{inner:Arc::new(PostgresAgentAudit::new(application_pool.clone(),vec![0x82;32]).map_err(|_|"owned_agent_audit")?),fault:audit_fault.clone()});
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
        listener_task=Some(tokio::spawn(async move {axum::serve(listener,router.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(async{let _=stopped.await;}).await}));
        let (mut input,thread)=stdin_owner();stdin_thread=Some(thread);
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":wire.origin(),"dist":dist,"sourceHead":source,"specSha256":spec,"producer":"same-Pool original SessionAuthResolver/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/CustomProvider/Agent/RunRelay/PostgresAgentAudit-forwarding/strict-owned-TLS/transparent-original-Body-stream","caseEvidence":case_evidence}))?;
        let mut ids=BTreeSet::new();
        loop {
            let value=tokio::time::timeout(Duration::from_secs(90),input.recv()).await.map_err(|_|"protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id=text(&value,"id")?.to_owned();if id.len()>64||!id.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b))||!ids.insert(id.clone())||ids.len()>4096{return Err("protocol_invalid_or_reused_id".to_owned());}
            let command=text(&value,"command")?;
            let reply=if matches!(command,"release_provider"|"arm_stall_audit_fault"|"arm_reconnect"|"release_reconnect") {
                tokio::time::timeout(Duration::from_millis(1000),execute(&state,&wire,&value)).await.map_err(|_|"critical_control_budget_exceeded".to_owned()).and_then(|v|v)
            } else {execute(&state,&wire,&value).await};
            let shutdown=reply.is_ok()&&command=="shutdown";
            emit(&match reply {Ok(result)=>json!({"schemaVersion":1,"id":id,"ok":true,"result":result}),Err(error)=>json!({"schemaVersion":1,"id":id,"ok":false,"error":error})})?;
            if shutdown{return Ok::<(),String>(());}
        }
    }.await;
    let mut close_errors = Vec::new();
    if let Some(auth) = auth_owner {
        auth.close_request_bindings();
    }
    if let Some(assembled) = &assembly
        && let Some(facts) = &assembled.runtime_capability_facts
    {
        facts.close();
    }
    if sse.stop().is_err() {
        close_errors.push("sse_owned_stop");
    }
    if let Some(stop) = stop_sender {
        let _ = stop.send(());
    }
    let listener_joined = if let Some(mut task) = listener_task {
        match tokio::time::timeout(CLOSE_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => true,
            _ => {
                close_errors.push("http_listener_join");
                task.abort();
                let _ = task.await;
                false
            }
        }
    } else {
        false
    };
    let facts_drained = if let Some(assembled) = &assembly
        && let Some(facts) = &assembled.runtime_capability_facts
    {
        let ok = tokio::time::timeout(CLOSE_TIMEOUT, facts.drain())
            .await
            .is_ok();
        if !ok {
            close_errors.push("capability_worker_drain");
        }
        ok
    } else {
        false
    };
    let relay_stopped = if let Some(relay) = relay {
        let ok = tokio::time::timeout(CLOSE_TIMEOUT, relay.stop())
            .await
            .is_ok();
        if !ok {
            close_errors.push("relay_stop");
        }
        ok
    } else {
        false
    };
    let agent_stopped = if let Some(agent) = agent {
        let ok = tokio::time::timeout(CLOSE_TIMEOUT, agent.stop())
            .await
            .is_ok();
        if !ok {
            close_errors.push("agent_stop");
        }
        ok
    } else {
        false
    };
    if audit_fault.refresh().await.is_err() {
        close_errors.push("audit_fault_final_actual_witness");
    }
    if audit_fault.disarm().await.is_err() {
        close_errors.push("audit_fault_disarm");
    }
    let assembly_closed = if let Some(assembled) = assembly {
        let ok = tokio::time::timeout(CLOSE_TIMEOUT, assembled.shutdown())
            .await
            .is_ok();
        if !ok {
            close_errors.push("assembly_shutdown");
        }
        ok
    } else {
        false
    };
    let provider_origin = wire.origin();
    let wire_record: WireRecord = wire.finish().await;
    if wire_record.failed != 0
        || wire_record.requests.len() != wire_record.counts.http
        || wire_record.joined != wire_record.counts.tcp
        || wire_record.state["remainingChildren"] != 0
        || wire_record.state["remainingGates"] != 0
        || wire_record.state["remainingReplies"] != 0
        || wire_record.state["listenerErrors"]
            .as_array()
            .is_none_or(|e| !e.is_empty())
    {
        close_errors.push("owned_tls_natural_closure_incomplete");
    }
    let wire_safe = match wire_requests(&wire_record.requests, &provider_origin) {
        Ok(v) => v,
        Err(_) => {
            close_errors.push("final_wire_safe_projection");
            json!([])
        }
    };
    let controllers = match (audit_fault.snapshot(), sse.snapshot()) {
        (Ok(a), Ok(s)) => json!({"auditFault":a,"sseTransport":s}),
        _ => {
            close_errors.push("controller_final_projection");
            Value::Null
        }
    };
    if controllers["sseTransport"]["remainingWrappers"] != 0
        || controllers["sseTransport"]["remainingGates"] != 0
        || !controllers["sseTransport"]["error"].is_null()
    {
        close_errors.push("sse_controller_final_closure");
    }
    let final_counters = live_counters(&state, wire_record.counts).await;
    observer_pool.close();
    controller_pool.close();
    application_pool.close();
    let stdin_joined = if let Some(thread) = stdin_thread {
        let mut join = tokio::task::spawn_blocking(move || thread.join());
        let ok = matches!(
            tokio::time::timeout(CLOSE_TIMEOUT, &mut join).await,
            Ok(Ok(Ok(())))
        );
        if !ok {
            close_errors.push("stdin_eof_join");
        }
        ok
    } else {
        false
    };
    let collection_failed = counters.collection_failed.load(Ordering::SeqCst);
    emit(
        &json!({"schemaVersion":1,"event":"closed","caseId":case_id,"sourceHead":source,"specSha256":spec,"listenerJoined":listener_joined,"factsDrained":facts_drained,"relayStopReturned":relay_stopped,"agentStopReturned":agent_stopped,"assemblyShutdownReturned":assembly_closed,"wireFinishReturned":true,"wireJoined":wire_record.joined,"wireFailed":wire_record.failed,"wireCounts":{"dns":wire_record.counts.dns,"tcp":wire_record.counts.tcp,"http":wire_record.counts.http},"wireRequests":wire_safe,"wireState":wire_record.state,"controllers":controllers,"stdinJoined":stdin_joined,"observerPoolCloseCalled":true,"applicationPoolCloseCalled":true,"counters":final_counters,"collectionFailed":collection_failed,"closeErrors":close_errors}),
    )?;
    // The closed receipt carries every cleanup failure independently. Preserve an original
    // command/producer failure rather than replacing it with a later cleanup classification.
    result?;
    if !listener_joined
        || !facts_drained
        || !relay_stopped
        || !agent_stopped
        || !assembly_closed
        || !stdin_joined
        || collection_failed
        || !close_errors.is_empty()
    {
        return Err("owned_close_incomplete".to_owned());
    }
    Ok(())
}
struct PoolOwners(Vec<Pool>);
impl Drop for PoolOwners {
    fn drop(&mut self) {
        for pool in &self.0 {
            pool.close();
        }
    }
}
