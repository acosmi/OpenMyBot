//! Original unsaved Agents Test through one actual Application/Session/PG assembly.
//! Every probe and TLS observation is passive; IPC cannot Save, Begin or forge a verdict.
use std::collections::BTreeSet;
use std::future::Future;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
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
    ProviderAdapter, ProviderPortError, ProviderRequest, ProviderSession, remember_provider_tool,
};
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
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

use super::agent_connection_probe_owned_tls_fixture::{
    AUTH_LATE, CASES, ERROR_CODE, ERROR_MESSAGE, OwnedWire, ProbeObservations, WireRecord,
    WireView, late,
};
const DEPLOYMENT: &str = "owned-agent-probe-client-deployment";
const TENANT: &str = "owned-agent-probe-client-tenant";
const SESSION_KEY: &[u8] = b"owned-agent-probe-client-session-key-at-least-32-bytes";
const MANAGED_KEY: &str = "owned-c5-unused-managed-key";
const APPLICATION_NAME: &str = "owned-agent-probe-client-application";
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);
const PG_BUDGET: Duration = Duration::from_secs(6);
// Existing non-production idp.test test CA/leaf/key; no system trust or vendor key is used.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default)]
struct Counters {
    custom: AtomicU64,
    package: AtomicU64,
    managed: AtomicU64,
    business_remote: AtomicU64,
    probe_validate: AtomicU64,
    probe_start: AtomicU64,
    api_ingress: AtomicU64,
    agent_post: AtomicU64,
    agent_put: AtomicU64,
    agent_delete: AtomicU64,
    model_post: AtomicU64,
    model_put: AtomicU64,
    model_delete: AtomicU64,
    credential: AtomicU64,
    callback: AtomicU64,
    mint_post: AtomicU64,
    begin_post: AtomicU64,
    cap_get: AtomicU64,
    probe_post: AtomicU64,
    served_index: AtomicU64,
    sequence: AtomicU64,
    collection_failed: AtomicBool,
}
struct CountingCustom {
    inner: Arc<PostgresCustomModelProvider>,
    counters: Arc<Counters>,
}
#[async_trait]
impl ProviderAdapter for CountingCustom {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.counters.custom.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}
struct CountingProvider {
    inner: Arc<dyn ProviderAdapter>,
    counters: Arc<Counters>,
    kind: u8,
}
#[async_trait]
impl ProviderAdapter for CountingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let counter = match self.kind {
            1 => &self.counters.managed,
            2 => &self.counters.business_remote,
            _ => &self.counters.package,
        };
        counter.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}
fn transport_error(error: RemoteAguiTransportError) -> &'static str {
    match error {
        RemoteAguiTransportError::DestinationRejected => "destination_rejected",
        RemoteAguiTransportError::Unavailable => "unavailable",
        RemoteAguiTransportError::CommitUnknown => "commit_unknown",
        RemoteAguiTransportError::Authentication => "authentication",
        RemoteAguiTransportError::RateLimited => "rate_limited",
        RemoteAguiTransportError::ServerUnavailable => "server_unavailable",
        RemoteAguiTransportError::InvalidResponse => "invalid_response",
        RemoteAguiTransportError::StreamStalled => "stream_stalled",
    }
}
fn observed_set(
    rows: &ProbeObservations,
    counters: &Counters,
    index: usize,
    key: &str,
    value: Value,
) {
    match rows.lock() {
        Ok(mut rows) => match rows.get_mut(index) {
            Some(row) => row[key] = value,
            None => counters.collection_failed.store(true, Ordering::SeqCst),
        },
        Err(_) => counters.collection_failed.store(true, Ordering::SeqCst),
    }
}
struct StartGuard {
    rows: ProbeObservations,
    counters: Arc<Counters>,
    index: usize,
    returned: bool,
}
impl Drop for StartGuard {
    fn drop(&mut self) {
        if !self.returned {
            observed_set(
                &self.rows,
                &self.counters,
                self.index,
                "startFutureDropObserved",
                json!(true),
            );
        }
    }
}
struct ObservedStream {
    inner: Box<dyn RemoteAguiEventStream>,
    rows: ProbeObservations,
    counters: Arc<Counters>,
    index: usize,
}
#[async_trait]
impl RemoteAguiEventStream for ObservedStream {
    async fn next_data(&mut self) -> Result<Option<String>, RemoteAguiTransportError> {
        if let Ok(mut rows) = self.rows.lock() {
            let row = &mut rows[self.index];
            let n = row["nextDataCalls"].as_u64().unwrap_or(0);
            row["nextDataCalls"] = json!(n + 1);
        } else {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        let value = self.inner.next_data().await;
        match &value {
            Ok(Some(data)) => {
                let kind = serde_json::from_str::<Value>(data)
                    .ok()
                    .and_then(|v| v.get("type").and_then(Value::as_str).map(str::to_owned));
                if let Ok(mut rows) = self.rows.lock() {
                    if rows[self.index]["firstEventType"].is_null() {
                        rows[self.index]["firstEventType"] = json!(match kind.as_deref() {
                            Some("RUN_STARTED") => "RUN_STARTED",
                            Some("RUN_ERROR") => "RUN_ERROR",
                            Some("run_started") => "run_started",
                            _ => "other",
                        });
                    }
                } else {
                    self.counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                }
            }
            Ok(None) => observed_set(
                &self.rows,
                &self.counters,
                self.index,
                "eofObserved",
                json!(true),
            ),
            Err(_) => {}
        }
        value
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        observed_set(
            &self.rows,
            &self.counters,
            self.index,
            "wrapperStreamDropObserved",
            json!(true),
        );
    }
}
struct CountingRemote {
    inner: Arc<SafeRemoteAguiTransport>,
    counters: Arc<Counters>,
    rows: ProbeObservations,
}
#[async_trait]
impl RemoteAguiTransport for CountingRemote {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.counters.probe_validate.fetch_add(1, Ordering::SeqCst);
        let index = match self.rows.lock() {
            Ok(mut rows) => {
                let index = rows.len();
                rows.push(json!({"ordinal":index+1,"endpoint":endpoint,"threadId":null,"runId":null,"messageId":null,
                "validateCalled":true,"validateReturn":null,"validateElapsedMicros":null,"startCalled":false,"startReturn":null,"startElapsedMicros":null,
                "startFutureDropObserved":false,"firstEventType":null,"nextDataCalls":0,"eofObserved":false,"wrapperStreamDropObserved":false}));
                Some(index)
            }
            Err(_) => {
                self.counters
                    .collection_failed
                    .store(true, Ordering::SeqCst);
                None
            }
        };
        let started = std::time::Instant::now();
        let result = self.inner.validate_endpoint(endpoint).await;
        if let Some(index) = index {
            observed_set(
                &self.rows,
                &self.counters,
                index,
                "validateReturn",
                json!(match result {
                    Ok(()) => "ok",
                    Err(error) => transport_error(error),
                }),
            );
            observed_set(
                &self.rows,
                &self.counters,
                index,
                "validateElapsedMicros",
                json!(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
            );
        }
        result
    }
    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.counters.probe_start.fetch_add(1, Ordering::SeqCst);
        let parsed = serde_json::from_slice::<Value>(&body).ok();
        let index = match self.rows.lock() {
            Ok(mut rows) => {
                let found = rows
                    .iter()
                    .position(|r| r["endpoint"] == endpoint && r["startCalled"] == false);
                if let Some(index) = found {
                    rows[index]["startCalled"] = json!(true);
                    if let Some(value) = &parsed {
                        for key in ["threadId", "runId"] {
                            rows[index][key] = value[key].clone();
                        }
                        rows[index]["messageId"] = value["messages"][0]["id"].clone();
                    }
                } else {
                    self.counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                }
                found
            }
            Err(_) => {
                self.counters
                    .collection_failed
                    .store(true, Ordering::SeqCst);
                None
            }
        };
        let mut guard = index.map(|index| StartGuard {
            rows: self.rows.clone(),
            counters: self.counters.clone(),
            index,
            returned: false,
        });
        let started = std::time::Instant::now();
        let result = self.inner.start(endpoint, authorization, body).await;
        if let Some(ref mut guard) = guard {
            guard.returned = true;
            observed_set(
                &self.rows,
                &self.counters,
                guard.index,
                "startElapsedMicros",
                json!(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
            );
            observed_set(
                &self.rows,
                &self.counters,
                guard.index,
                "startReturn",
                json!(match &result {
                    Ok(_) => "stream",
                    Err(error) => transport_error(*error),
                }),
            );
        }
        match (result, index) {
            (Ok(inner), Some(index)) => Ok(Box::new(ObservedStream {
                inner,
                rows: self.rows.clone(),
                counters: self.counters.clone(),
                index,
            })),
            (value, _) => value,
        }
    }
}
// Preserve ownership after a budget breach; the observed overrun stays RED.
async fn bounded_completion<F: Future>(future: F, budget: Duration) -> (F::Output, bool) {
    tokio::pin!(future);
    match tokio::time::timeout(budget, &mut future).await {
        Ok(value) => (value, false),
        Err(_) => (future.await, true),
    }
}
#[derive(Clone)]
struct Case {
    actor: String,
    session: String,
}
struct State {
    observer: Pool,
    counters: Arc<Counters>,
    case: Mutex<Option<Case>>,
    requests: Mutex<Vec<Value>>,
    case_id: String,
    observations: ProbeObservations,
    baseline: Mutex<Option<Value>>,
}
fn item_path(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}
fn begin_path(path: &str) -> bool {
    path.starts_with("/api/threads/") && path.ends_with("/runs") && path.split('/').count() == 5
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
        ("POST", "/api/agents/test-connection") => Some(&state.counters.probe_post),
        ("POST", "/api/agents") => Some(&state.counters.agent_post),
        ("PATCH" | "PUT", p) if item_path(p, "/api/agents/") => Some(&state.counters.agent_put),
        ("DELETE", p) if item_path(p, "/api/agents/") => Some(&state.counters.agent_delete),
        ("POST", "/api/me/model-connections") => Some(&state.counters.model_post),
        ("PUT", p) if item_path(p, "/api/me/model-connections/") => Some(&state.counters.model_put),
        ("DELETE", p) if item_path(p, "/api/me/model-connections/") => {
            Some(&state.counters.model_delete)
        }
        ("POST", "/api/threads/mint") => Some(&state.counters.mint_post),
        ("POST", p) if begin_path(p) => Some(&state.counters.begin_post),
        ("GET", "/api/me/capabilities") => Some(&state.counters.cap_get),
        (_, p)
            if (method != "GET"
                && (p == "/api/admin/credentials" || p.starts_with("/api/admin/credentials/")))
                || ((method == "POST" || method == "DELETE")
                    && p.starts_with("/api/agents/")
                    && p.ends_with("/callback-token")
                    && p.split('/').count() == 5) =>
        {
            Some(&state.counters.credential)
        }
        ("POST", "/api/agent-tools/call") => Some(&state.counters.callback),
        _ => None,
    };
    if let Some(counter) = admission {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let sequence = state.counters.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    let response = next.run(request).await;
    if response.status().is_success()
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/html"))
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
        records.push(json!({"sequence":sequence,"method":method,"path":path,"status":response.status().as_u16()}));
    }
    response
}
fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC5_HOST {text}").map_err(|_| "protocol_write")?;
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
 'thread_leases',(SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY thread_id),'[]'::jsonb) FROM public.thread_leases l),
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

async fn case(state: &State) -> Result<Case, String> {
    state
        .case
        .lock()
        .await
        .clone()
        .ok_or_else(|| "case_not_prepared".to_owned())
}
async fn prepare(state: &State, wire: &WireView) -> Result<Value, String> {
    let mut slot = state.case.lock().await;
    if slot.is_some() {
        return Err("case_already_prepared".to_owned());
    }
    let actor = format!("owned-c5-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C5_SESSION_{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let tx = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c5.test");
    tx.execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
        &[&actor, &email],
    )
    .await
    .map_err(|_| "prepare_user")?;
    tx.execute(
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
    tx.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",&[&session,&actor,&token_hash,&(now+time::Duration::hours(2)),&now]).await.map_err(|_|"prepare_session")?;
    tx.commit().await.map_err(|_| "prepare_commit")?;
    *slot = Some(Case {
        actor: actor.clone(),
        session: session.clone(),
    });
    drop(slot);
    let baseline = probe(state, wire).await?;
    *state.baseline.lock().await = Some(baseline["business"].clone());
    let (a, b) = wire.keys();
    let first = format!("{}/ag-ui/a", wire.origin());
    let second = if state.case_id == AUTH_LATE {
        first.clone()
    } else {
        format!("{}/ag-ui/b", wire.origin())
    };
    Ok(
        json!({"caseId":state.case_id,"actor":actor,"session":{"id":session,"userId":actor,"cookieName":"openbot_session","token":token},
        "endpoints":{"first":first,"second":second},"secrets":{"apiKeyA":a,"apiKeyB":b},"canaries":{"runErrorMessage":ERROR_MESSAGE,"runErrorCode":ERROR_CODE},
        "budgets":{"responseBytes":64*1024*1024,"connectHeadersMs":30000,"bodyStallMs":null,"resolverBoundary":"owned pinned resolver separately observed; not execute_stream budget","ownedIoMs":12000,"selectedJsonMs":35000,"wholeCaseMs":180000}}),
    )
}
async fn live_counters(state: &State, wire: &WireView) -> Value {
    let records = state.requests.lock().await;
    let c = &state.counters;
    let wire = wire.counts();
    json!({"agentSavePost":c.agent_post.load(Ordering::SeqCst),"agentSavePut":c.agent_put.load(Ordering::SeqCst),"agentDelete":c.agent_delete.load(Ordering::SeqCst),
        "modelSavePost":c.model_post.load(Ordering::SeqCst),"modelSavePut":c.model_put.load(Ordering::SeqCst),"modelDelete":c.model_delete.load(Ordering::SeqCst),
        "credentialMutation":c.credential.load(Ordering::SeqCst),"callbackPost":c.callback.load(Ordering::SeqCst),"threadMintPost":c.mint_post.load(Ordering::SeqCst),"beginPost":c.begin_post.load(Ordering::SeqCst),"capabilityGet":c.cap_get.load(Ordering::SeqCst),
        "probePost":c.probe_post.load(Ordering::SeqCst),"probe200":records.iter().filter(|r|r["method"]=="POST" && r["path"]=="/api/agents/test-connection" && r["status"]==200).count(),
        "probeValidate":c.probe_validate.load(Ordering::SeqCst),"probeStart":c.probe_start.load(Ordering::SeqCst),
        "customStart":c.custom.load(Ordering::SeqCst),"packageStart":c.package.load(Ordering::SeqCst),"managedStart":c.managed.load(Ordering::SeqCst),"businessRemoteStart":c.business_remote.load(Ordering::SeqCst),
        "dns":wire["dns"],"tcp":wire["tcp"],"http":wire["http"],"apiIngressCount":c.api_ingress.load(Ordering::SeqCst),"servedIndex":c.served_index.load(Ordering::SeqCst),"collectionFailed":c.collection_failed.load(Ordering::SeqCst)})
}
async fn probe(state: &State, wire: &WireView) -> Result<Value, String> {
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
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|_| "observer_pid")?
        .get(0);
    let full: Value = tx
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "observer_snapshot")?
        .get(0);
    if serde_json::to_vec(&full)
        .map_err(|_| "observer_encode")?
        .len()
        > 262144
    {
        return Err("observer_snapshot_limit".to_owned());
    }
    let session: Value = tx
        .query_one(
            "SELECT to_jsonb(s)-'token' FROM public.sessions s WHERE id=$1 AND user_id=$2",
            &[&current.session, &current.actor],
        )
        .await
        .map_err(|_| "observer_session")?
        .get(0);
    let observations = state
        .observations
        .lock()
        .map_err(|_| "probe_observation_lock")?
        .clone();
    let ids: Vec<String> = observations
        .iter()
        .flat_map(|v| {
            ["threadId", "runId", "messageId"]
                .iter()
                .filter_map(|key| v[*key].as_str().map(str::to_owned))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let absent=tx.query_one("SELECT (SELECT count(*) FROM public.runs WHERE run_id=ANY($1::text[])),(SELECT count(*) FROM public.threads WHERE thread_id=ANY($1::text[])),(SELECT count(*) FROM public.messages WHERE message_id=ANY($1::text[]) OR run_id=ANY($1::text[])),(SELECT count(*) FROM public.outbox o WHERE o.outbox_id=ANY($1::text[]) OR o.aggregate_id=ANY($1::text[]) OR EXISTS(SELECT 1 FROM unnest($1::text[]) AS probe_id(value) WHERE strpos(o.payload::text,probe_id.value)>0))",&[&ids]).await.map_err(|_|"observer_ephemeral_ids")?;
    let totals: [i64; 4] = [absent.get(0), absent.get(1), absent.get(2), absent.get(3)];
    let readonly: String = tx
        .query_one("SHOW transaction_read_only", &[])
        .await
        .map_err(|_| "observer_readonly")?
        .get(0);
    tx.commit().await.map_err(|_| "observer_commit")?;
    let object = full.as_object().ok_or("observer_snapshot_shape")?;
    let mut business = serde_json::Map::new();
    let mut counts = serde_json::Map::new();
    for (name, rows) in object {
        let f = fingerprint(rows)?;
        counts.insert(name.clone(), f["count"].clone());
        business.insert(name.clone(), f);
    }
    Ok(
        json!({"caseId":state.case_id,"session":session,"policy":full["action_policy"],"business":business,"counts":counts,
        "counters":live_counters(state,wire).await,"requests":state.requests.lock().await.clone(),"wireRequests":wire.requests()?,"wireCounts":wire.counts(),"probeObservations":observations,
        "probeIdsAbsent":{"checkedIds":ids,"runs":totals[0],"threads":totals[1],"messages":totals[2],"outbox":totals[3],"allAbsent":totals.iter().all(|n|*n==0)},
        "observer":{"backendPid":pid,"transactionReadOnly":readonly=="on","sameApplicationPool":true,"allOwnedRelations":object.len(),"resolverObservations":wire.resolver()?,
            "physicalVaultSealCalls":null,"physicalVaultMigrationCalls":null,"physicalVaultObservationBoundary":"concrete Vault has no internal call spy; dynamic physical calls unobserved",
            "sourcePathInference":{"TestTraversesVault":false,"boundary":"static original authorize_scope -> commit -> SafeRemote path, separate from dynamic PG/admission observations"}}}),
    )
}
async fn execute(state: &State, wire: &WireView, value: &Value) -> Result<Value, String> {
    let command = text(value, "command")?;
    let extra = match command {
        "prepare" | "probe" | "release_probe" => &["caseId"][..],
        "shutdown" => &[][..],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    fields(value, extra)?;
    if command != "shutdown" && text(value, "caseId")? != state.case_id {
        return Err("protocol_case_mismatch".to_owned());
    }
    match command {
        "prepare" => prepare(state, wire).await,
        "probe" => tokio::time::timeout(PG_BUDGET, probe(state, wire))
            .await
            .map_err(|_| "observer_deadline".to_owned())?,
        "release_probe" => {
            if !late(&state.case_id) {
                return Err("release_probe_not_late_case".to_owned());
            }
            let actual = tokio::time::timeout(PG_BUDGET, probe(state, wire))
                .await
                .map_err(|_| "release_observer_deadline")??;
            let baseline = state.baseline.lock().await;
            if baseline.as_ref() != Some(&actual["business"])
                || actual["probeIdsAbsent"]["allAbsent"] != true
            {
                return Err("held_probe_durable_effect_changed".to_owned());
            }
            let requests = wire.requests()?;
            if requests.len() != 2
                || requests[1]["intendedStatus"] != 401
                || requests[1]["headersWriteReturned"] != true
                || requests[1]["bodyWriteReturned"] != true
                || requests[1]["flushReturned"] != true
                || !actual["probeObservations"].as_array().is_some_and(|rows| {
                    rows.iter()
                        .any(|row| row["ordinal"] == 2 && row["startReturn"] == "authentication")
                })
                || !actual["requests"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row["method"] == "POST"
                            && row["path"] == "/api/agents/test-connection"
                            && row["status"] == 200
                    })
                })
            {
                return Err("held_probe_current_B_original_authentication_not_observed".to_owned());
            }
            let released = wire.release()?;
            Ok(
                json!({"caseId":state.case_id,"released":released["released"],"requestOrdinal":released["requestOrdinal"]}),
            )
        }
        "shutdown" => Ok(json!({"stopping":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
}
pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C5_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C5_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C5_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C5_CASE_ID").map_err(|_| "missing_case_id")?;
    if !CASES.contains(&case_id.as_str())
        || source.len() != 40
        || spec.len() != 64
        || !source.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !spec.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !std::path::Path::new(&dist).is_absolute()
    {
        return Err("invalid_outer_identity".to_owned());
    }
    let static_app = StaticApp::open(&dist).map_err(|_| "invalid_owned_dist")?;
    let mut application_config = config.clone();
    application_config.max_pool_size = 8;
    application_config.application_name = Some(APPLICATION_NAME.to_owned());
    let application_pool = pool::connect(&application_config)
        .await
        .map_err(|_| "application_pool")?;
    // Observation uses the SAME original ApplicationPool instance, never a parallel authority.
    let observer_pool = application_pool.clone();
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    drop(client);
    let observations: ProbeObservations = Arc::new(StdMutex::new(Vec::new()));
    let wire = OwnedWire::new(
        &case_id,
        [TEST_CA, TEST_LEAF, TEST_KEY],
        observations.clone(),
    )
    .await?;
    let view = wire.view();
    let counters = Arc::new(Counters::default());
    let tenant = TenantId::new(TENANT);
    let deployment = DeploymentId::new(DEPLOYMENT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "owned_vault_key")?,
    );
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
        observations: observations.clone(),
        baseline: Mutex::new(None),
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
        let budget=SafeHttpBudget::new(64*1024*1024,Duration::from_secs(30)).map_err(|_|"owned_http_budget")?;
        let remote:Arc<dyn RemoteAguiTransport>=Arc::new(CountingRemote{inner:Arc::new(SafeRemoteAguiTransport::new(view.dialer()?,budget,None,SchemePolicy::HttpsOnly)
            .map_err(|_|"owned_actual_remote")?),counters:counters.clone(),rows:observations.clone()});
        // This actual adapter is a legal CreateAgent prerequisite. Its key remains only in memory.
        let managed_inner:Option<Arc<dyn ProviderAdapter>>=Some(Arc::new(OpenAiProvider::new(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/chat/completions",view.origin())).map_err(|_|"owned_managed_endpoint")?,
            "owned-managed-model".to_owned(),OpenAiProtocol::ChatCompletions,budget,None)
            .map_err(|_|"owned_managed_config")?,OpenAiApiKey::from_bytes(MANAGED_KEY.as_bytes().to_vec()).map_err(|_|"owned_managed_key")?,view.dialer()?)));
        let managed_slot_available=managed_inner.is_some();
        let managed=managed_inner.map(|inner|Arc::new(CountingProvider{inner,counters:counters.clone(),kind:1}) as Arc<dyn ProviderAdapter>);
        assembly=Some(assemble_postgres_application(PostgresApplicationAssemblyInput{
            pool:application_pool.clone(),listener_database:application_config.clone().into(),deployment:deployment.clone(),tenant:tenant.clone(),single_user:false,admin_floor:None,
            model:"unused-default-model".to_owned(),credential_key_id:"unused-default-model-key".to_owned(),credential_vault:vault.clone(),audit_key:SecretBytes::new(vec![0x82;32]),
            remote_assertions:assertions.clone(),mcp_oauth_state_key:SecretBytes::new(vec![0x84;32]),policy_store:policies,
            ui_preferences:Arc::new(PostgresUiPreferenceAdministration::new(application_pool.clone(),deployment.clone(),tenant.clone(),SecretBytes::new(vec![0x82;32])).map_err(|_|"owned_preferences")?),
            screen_sessions:Arc::new(openbot_application::NoScreenSessionAdministration),artifacts:None,
            runtime_capabilities:Some(auth.runtime_capability_factory(None).map_err(|_|"owned_actual_capability_factory")?),
            remote_agent_probe:remote.clone(),managed_slot_available,
            channel_routing_provider:ChannelRoutingProviderInput{endpoint:Url::parse(&format!("{}/v1/chat/completions",view.origin())).map_err(|_|"owned_channel_endpoint")?,environment_api_key:None,egress_allow_cidrs:vec!["127.0.0.1/32".to_owned()],allow_http:false},
            stall_timeout:None,oauth_public_url:None,app_url:None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        }).await.map_err(|_|"owned_production_assembly")?);
        let assembled=assembly.as_ref().ok_or("assembly_missing")?;
        let package_credentials=Arc::new(PostgresOpenAiCredentialSource::new(application_pool.clone(),vault.clone(),"unused-default-model-key".to_owned(),None).map_err(|_|"owned_default_source")?);
        let package:Arc<dyn ProviderAdapter>=Arc::new(CountingProvider{inner:Arc::new(OpenAiProvider::new_with_credential_source(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/responses",view.origin())).map_err(|_|"owned_package_endpoint")?,"unused-default-model".to_owned(),OpenAiProtocol::Responses,budget,None)
            .map_err(|_|"owned_package_config")?,package_credentials,view.dialer()?)),counters:counters.clone(),kind:0});
        let custom:Arc<dyn ProviderAdapter>=Arc::new(CountingCustom{inner:Arc::new(PostgresCustomModelProvider::new(application_pool.clone(),vault.clone(),deployment.clone(),tenant.clone(),view.dialer()?,budget,None)
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(CountingProvider{inner:Arc::new(RemoteAguiProvider::new(remote)),counters:counters.clone(),kind:2}))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
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
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":view.origin(),"dist":dist,
            "sourceHead":source,"specSha256":spec,"producer":"same-Pool SessionAuthResolver/CapabilityFactory/SameApplicationPool/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/PassiveOriginalSafeRemote/StrictOwnedFiniteTLS/23ReadOnlyRelationFingerprints","caseEvidence":"none"}))?;
        let mut ids=BTreeSet::new();
        loop {
            let value=tokio::time::timeout(Duration::from_secs(90),input.recv()).await.map_err(|_|"protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id=text(&value,"id")?.to_owned();
            if id.len()>64 || !id.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"._-".contains(&byte)) || !ids.insert(id.clone()) || ids.len()>4096{return Err("protocol_invalid_or_reused_id".to_owned());}
            let reply=execute(&state,&view,&value).await;
            let shutdown=reply.is_ok() && text(&value,"command")?=="shutdown";
            let frame=match reply {Ok(result)=>json!({"schemaVersion":1,"id":id,"ok":true,"result":result}),Err(error)=>json!({"schemaVersion":1,"id":id,"ok":false,"error":error})};
            emit(&frame)?;
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
    if let Some(stop) = stop_sender
        && stop.send(()).is_err()
    {
        close_errors.push("http_listener_stop_send");
    }
    // Closing an unreleased owned gate is recorded; it cannot become a positive probe.
    // Do this before App graceful join so an early browser failure cannot strand A.
    if view.close_held().is_err() {
        close_errors.push("owned_held_gate_close");
    }
    let listener_joined = if let Some(task) = listener_task {
        let (outcome, over_budget) = bounded_completion(task, CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("http_listener_join_deadline");
        }
        match outcome {
            Ok(Ok(())) => true,
            Ok(Err(_)) => {
                close_errors.push("http_listener_return_error");
                false
            }
            Err(_) => {
                close_errors.push("http_listener_join_error");
                false
            }
        }
    } else {
        false
    };
    let facts_drained = if let Some(assembled) = &assembly {
        if let Some(facts) = &assembled.runtime_capability_facts {
            let ((), over_budget) = bounded_completion(facts.drain(), CLOSE_TIMEOUT).await;
            if over_budget {
                close_errors.push("capability_worker_drain_deadline");
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    let relay_stopped = if let Some(relay) = relay {
        let ((), over_budget) = bounded_completion(relay.stop(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("relay_stop_deadline");
        }
        true
    } else {
        false
    };
    let agent_stopped = if let Some(agent) = agent {
        let ((), over_budget) = bounded_completion(agent.stop(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("agent_stop_deadline");
        }
        true
    } else {
        false
    };
    let assembly_closed = if let Some(assembled) = assembly {
        let ((), over_budget) = bounded_completion(assembled.shutdown(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("assembly_shutdown_deadline");
        }
        true
    } else {
        false
    };
    // Always await our actual listener and every TLS child. Errors stay visible.
    let wire_task = tokio::spawn(wire.finish());
    let (outcome, over_budget) = bounded_completion(wire_task, CLOSE_TIMEOUT).await;
    if over_budget {
        close_errors.push("owned_wire_finish_deadline");
    }
    let wire_record: Option<WireRecord> = match outcome {
        Ok(Ok(record)) => Some(record),
        Ok(Err(_)) => {
            close_errors.push("owned_wire_finish_error");
            None
        }
        Err(_) => {
            close_errors.push("owned_wire_finish_join_error");
            None
        }
    };
    if let Some(record) = &wire_record {
        if record.failed != 0
            || record.summary["unexpectedErrors"]
                .as_array()
                .is_none_or(|v| !v.is_empty())
            || record.summary["remainingChildren"] != 0
            || record.summary["remainingReplies"] != 0
            || record.summary["remainingGates"] != 0
            || record.summary["childrenSpawned"].as_u64() != Some(record.joined as u64)
        {
            close_errors.push("owned_wire_actual_closure_or_IO_failure");
            counters.collection_failed.store(true, Ordering::SeqCst);
        }
        if record.requests.len() as u64 != record.counts["http"].as_u64().unwrap_or(u64::MAX) {
            close_errors.push("owned_wire_capture_incomplete");
        }
    } else {
        counters.collection_failed.store(true, Ordering::SeqCst);
    }
    let final_counters = live_counters(&state, &view).await;
    observer_pool.close();
    application_pool.close();
    let stdin_joined = if let Some(thread) = stdin_thread {
        let join = tokio::task::spawn_blocking(move || thread.join());
        let (outcome, over_budget) = bounded_completion(join, CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("stdin_eof_join_deadline");
        }
        match outcome {
            Ok(Ok(())) => true,
            _ => {
                close_errors.push("stdin_eof_join_error");
                false
            }
        }
    } else {
        false
    };
    let collection_failed = counters.collection_failed.load(Ordering::SeqCst);
    let wire_finish_returned = wire_record.is_some();
    emit(
        &json!({"schemaVersion":1,"event":"closed","caseId":case_id,"sourceHead":source,"specSha256":spec,
        "listenerJoined":listener_joined,"factsDrained":facts_drained,"relayStopReturned":relay_stopped,
        "agentStopReturned":agent_stopped,"assemblyShutdownReturned":assembly_closed,
        "wireFinishReturned":wire_finish_returned,"wireJoined":wire_record.as_ref().map(|record|record.joined),
        "wireFailed":wire_record.as_ref().map(|record|record.failed),
        "wireCounts":wire_record.as_ref().map(|record|record.counts.clone()),
        "wireRequests":wire_record.as_ref().map(|record|record.requests.clone()),
        "wireSummary":wire_record.as_ref().map(|record|record.summary.clone()),"stdinJoined":stdin_joined,"observerPoolCloseCalled":true,
        "applicationPoolCloseCalled":true,"counters":final_counters,"collectionFailed":collection_failed,"closeErrors":close_errors}),
    )?;
    if !listener_joined
        || !facts_drained
        || !relay_stopped
        || !agent_stopped
        || !assembly_closed
        || !wire_finish_returned
        || !stdin_joined
        || collection_failed
        || !close_errors.is_empty()
    {
        return Err("owned_close_incomplete".to_owned());
    }
    result
}
