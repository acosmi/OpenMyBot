//! Two delivered GUI consumers share the actual PostgreSQL/Application/HTTP/Vault host.
//! IPC prepares an owned session or reads facts; model creation and Run begin remain normal HTTP.
//! Capability GET is independent evidence and does not establish a GUI readiness consumer.

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
    ProviderAdapter, ProviderPortError, ProviderRequest, ProviderSession, remember_provider_tool,
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

use super::provider_target_fixture::{Counts, OwnedWire, Reply, WireRecord};

const WORKSPACE: &str = "C7.workspace-computer-current-run";
const MODELS: &str = "C7.models-directory-current-storage";
const DEPLOYMENT: &str = "owned-delivered-capability-client-deployment";
const TENANT: &str = "owned-delivered-capability-client-tenant";
const SESSION_KEY: &[u8] = b"owned-delivered-capability-client-session-key-at-least-32-bytes";
const MODEL_KEY: &str = "owned-c7-model-key";
const MANAGED_KEY: &str = "owned-c7-managed-key";
const MODEL: &str = "owned-c7-model";
const POSITIVE_TEXT: &str = "owned C7 custom current text";
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

fn positive_sse() -> String {
    let delta = json!({"id":"owned-c7-response","object":"chat.completion.chunk",
        "choices":[{"index":0,"delta":{"content":POSITIVE_TEXT},"finish_reason":null}]});
    let stop = json!({"id":"owned-c7-response","object":"chat.completion.chunk",
        "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let usage = json!({"id":"owned-c7-response","object":"chat.completion.chunk",
        "choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
    format!("data: {delta}\n\ndata: {stop}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}

fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC7_HOST {text}").map_err(|_| "protocol_write")?;
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
    let actor = format!("owned-c7-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C7_SESSION_{}", Uuid::new_v4());
    let channel = format!("owned-c7-channel-{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let transaction = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c7.test");
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
        .execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned C7 channel','',ARRAY[]::text[],ARRAY[]::text[])", &[&channel])
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
        "model":{"name":"Owned C7 model","protocol":"openai_chat_completions",
            "endpoint":format!("{}/v1",wire.origin()),"model":MODEL,"enabled":true,"apiKey":MODEL_KEY},
        "agent":{"name":"Owned C7 Bot","title":"Owned C7 Bot","roleDescription":"Return the owned canary text without tools.","visibility":"public"},
        "channelId":channel}))
}

fn fingerprint(value: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "observer_hash_encode")?;
    Ok(
        json!({"count":value.as_array().map_or(0,Vec::len),"sha256":Sha256Digest::of(&bytes).to_hex()}),
    )
}

// Only owned relations. PostgreSQL supplies ciphertext equality witnesses, then removes the
// original encrypted columns before the snapshot crosses this boundary. Replies contain only
// relation fingerprints; equivalent re-encryption must still count as a storage mutation.
const SNAPSHOT: &str = "SELECT jsonb_build_object(
 'model_connections',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM public.model_connections m),
 'model_connection_secrets',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'encrypted_value') || jsonb_build_object('ciphertext_sha256',encode(sha256(convert_to(s.encrypted_value,'UTF8')),'hex')) ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets s),
 'credentials',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'encrypted_value') || jsonb_build_object('ciphertext_sha256',encode(sha256(convert_to(c.encrypted_value,'UTF8')),'hex')) ORDER BY id),'[]'::jsonb) FROM public.credentials c),
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
 'audit_checkpoints',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'signature') ORDER BY sequence),'[]'::jsonb) FROM public.audit_checkpoints c))";

pub(super) async fn verify_ciphertext_snapshot_mutation(
    config: pool::DatabaseConfig,
) -> Result<(), String> {
    let pool = pool::connect(&config)
        .await
        .map_err(|_| "cipher_observer_pool")?;
    let mut client = pool.get().await.map_err(|_| "cipher_observer_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "cipher_observer_schema")?;
    let connection = Uuid::now_v7();
    let secret = Uuid::now_v7();
    let credential = Uuid::now_v7();
    let before_cipher = "owned-ciphertext-before-canary";
    let after_cipher = "owned-ciphertext-after-canary";
    let tx = client
        .transaction()
        .await
        .map_err(|_| "cipher_fixture_begin")?;
    tx.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('cipher-observer-owner','cipher-observer@example.test',0)")
        .await.map_err(|_| "cipher_fixture_owner")?;
    tx.execute("INSERT INTO public.model_connections
        (id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,
         revision,current_secret_id,created_at,updated_at)
        VALUES($1,'owned-deployment','owned-tenant','cipher-observer-owner','Owned observer',
         'openai_responses','https://observer.example.test/v1','owned-model',false,1,$2,now(),now())",
        &[&connection, &secret]).await.map_err(|_| "cipher_fixture_model")?;
    tx.execute(
        "INSERT INTO public.model_connection_secrets
        (id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at)
        VALUES($1,$2,'owned-deployment','owned-tenant','cipher-observer-owner',$3,now())",
        &[&secret, &connection, &before_cipher],
    )
    .await
    .map_err(|_| "cipher_fixture_secret")?;
    tx.execute(
        "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata)
        VALUES($1,'model','owned-observer',$2,'owned-key','{}')",
        &[&credential, &before_cipher],
    )
    .await
    .map_err(|_| "cipher_fixture_credential")?;
    tx.commit().await.map_err(|_| "cipher_fixture_commit")?;
    let before: Value = client
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "cipher_snapshot_before")?
        .get(0);
    for (table, id) in [
        ("model_connection_secrets", secret),
        ("credentials", credential),
    ] {
        client
            .execute(
                &format!("UPDATE public.{table} SET encrypted_value=$2 WHERE id=$1"),
                &[&id, &after_cipher],
            )
            .await
            .map_err(|_| "cipher_fixture_change")?;
        let after: Value = client
            .query_one(SNAPSHOT, &[])
            .await
            .map_err(|_| "cipher_snapshot_after")?
            .get(0);
        if fingerprint(&before[table])? == fingerprint(&after[table])? {
            return Err("cipher_only_mutation_was_invisible".to_owned());
        }
        let encoded = serde_json::to_string(&after).map_err(|_| "cipher_snapshot_encode")?;
        if encoded.contains(before_cipher)
            || encoded.contains(after_cipher)
            || encoded.contains("encrypted_value")
        {
            return Err("cipher_snapshot_exposed_original_cipher".to_owned());
        }
        client
            .execute(
                &format!("UPDATE public.{table} SET encrypted_value=$2 WHERE id=$1"),
                &[&id, &before_cipher],
            )
            .await
            .map_err(|_| "cipher_fixture_restore")?;
        let restored: Value = client
            .query_one(SNAPSHOT, &[])
            .await
            .map_err(|_| "cipher_snapshot_restored")?
            .get(0);
        if fingerprint(&before[table])? != fingerprint(&restored[table])? {
            return Err("cipher_snapshot_other_columns_changed".to_owned());
        }
    }
    drop(client);
    pool.close();
    Ok(())
}

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
    for request in wire.requests() {
        let body: Value = serde_json::from_slice(&request.body).map_err(|_| "owned_wire_json")?;
        records.push(json!({"method":request.method,"target":request.target,"model":body.get("model"),"stream":body.get("stream"),
            "authorizationMatches":request.headers.get("authorization").is_some_and(|header|header==&format!("Bearer {MODEL_KEY}")),
            "authorizationHeaderCount":request.header_counts.get("authorization").copied().unwrap_or(0),
            "secretInBody":request.body.windows(MODEL_KEY.len()).any(|bytes|bytes==MODEL_KEY.as_bytes()),
            "bodySha256":Value::Null}));
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
    let observation = transaction
        .query_one("SELECT pg_backend_pid(),current_setting('transaction_read_only'),current_setting('transaction_isolation')", &[])
        .await
        .map_err(|_| "observer_settings")?;
    let pid: i32 = observation.get(0);
    let read_only: String = observation.get(1);
    let isolation: String = observation.get(2);
    if pid <= 0 || read_only != "on" || isolation != "read committed" {
        return Err("observer_transaction_settings".to_owned());
    }
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
                SecretPrincipal::Actor(ActorId::new("owned-c7-wrong-owner")),
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
                SecretPrincipal::Service(ServiceId::new("owned-c7-wrong-service")),
                &encrypted,
            )
            .is_err();
        let wrong_tenant = CredentialRecordVault::single_key(
            TenantId::new("owned-c7-wrong-tenant"),
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
        "wireRequests":wire_requests(wire)?,"observer":{"backendPid":pid,"readOnly":read_only=="on","isolation":isolation}}),
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
    let client = state
        .observer
        .get()
        .await
        .map_err(|_| "terminal_connection")?;
    let observed: Value = client.query_one("SELECT jsonb_build_object(
        'run',(SELECT to_jsonb(r) FROM public.runs r JOIN public.threads t USING(thread_id) WHERE r.run_id=$1 AND r.actor_id=$2 AND t.deployment_id=$3 AND t.tenant_id=$4),
        'modelSelection',(SELECT to_jsonb(s) FROM public.run_model_selections s WHERE run_id=$1 AND owner_user_id=$2 AND deployment_id=$3 AND tenant_id=$4),
        'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_seq),'[]'::jsonb) FROM public.run_events e WHERE run_id=$1),
        'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY seq),'[]'::jsonb) FROM public.messages m WHERE run_id=$1),
        'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]'::jsonb) FROM public.outbox o WHERE outbox_id=$1 || ':agent_run_dispatch'))",
        &[&run,&current.actor,&DEPLOYMENT,&TENANT]).await.map_err(|_|"terminal_original_rows")?
        .try_get(0).map_err(|_|"terminal_shape".to_owned())?;
    if observed["run"].is_null() || observed["modelSelection"].is_null() {
        return Err("terminal_owned_run_binding".to_owned());
    }
    Ok(observed)
}

async fn observe_run(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    if state.case_id != WORKSPACE {
        return Err("observe_run_workspace_only".to_owned());
    }
    let run = text(value, "runId")?;
    Uuid::parse_str(run).map_err(|_| "run_id_invalid")?;
    let mut observed = terminal_snapshot(state, run).await?;
    observed["caseId"] = json!(state.case_id);
    observed["runId"] = json!(run);
    observed["probe"] = probe(state, wire).await?;
    Ok(observed)
}

async fn wait_terminal(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    if state.case_id != WORKSPACE {
        return Err("terminal_workspace_only".to_owned());
    }
    let run = text(value, "runId")?;
    Uuid::parse_str(run).map_err(|_| "run_id_invalid")?;
    let millis = value["timeoutMs"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= 12_000)
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
        "observe_run" => &["caseId", "runId"],
        "wait_terminal" => &["caseId", "runId", "timeoutMs"],
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
        "observe_run" => observe_run(state, wire, value).await,
        "wait_terminal" => wait_terminal(state, wire, value).await,
        "shutdown" => Ok(json!({"stopping":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
}

pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C7_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C7_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C7_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C7_CASE_ID").map_err(|_| "missing_case_id")?;
    if ![WORKSPACE, MODELS].contains(&case_id.as_str())
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
    application_config.application_name =
        Some("owned-delivered-capability-client-application".to_owned());
    let application_pool = pool::connect(&application_config)
        .await
        .map_err(|_| "application_pool")?;
    let mut observer_config = config.clone();
    observer_config.max_pool_size = 4;
    observer_config.application_name =
        Some("owned-delivered-capability-client-observer".to_owned());
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
    let replies = if case_id == WORKSPACE {
        vec![Reply {
            content_type: "text/event-stream",
            body: positive_sse(),
        }]
    } else {
        Vec::new()
    };
    let wire = OwnedWire::new(replies, [TEST_CA, TEST_LEAF, TEST_KEY]).await;
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
        vault: vault.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
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
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(RemoteAguiProvider::new(remote)))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
        let context=Arc::new(PostgresAgentContextSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),Some(32)).map_err(|_|"owned_context")?
            .with_tools(vec![remember_provider_tool()]).with_remote_assertions(assertions).with_mcp_catalog(assembled.mcp_catalog.clone())
            .with_components(assembled.components.clone()).with_sandboxed_components(assembled.sandboxed_components.clone()).with_agent_credential_vault(vault.clone()));
        let tools=Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(assembled.application.clone(),Arc::new(PostgresAgentAuthorizationSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),false)),
            Arc::new(PostgresAgentToolSequence::new(application_pool.clone())),assembled.tool_cancellations.clone()));
        let audit=Arc::new(PostgresAgentAudit::new(application_pool.clone(),vec![0x82;32]).map_err(|_|"owned_agent_audit")?);
        agent=Some(BuiltInAgentRuntime::start_with_remote_interrupts(assembled.run_runtime.clone(),context,provider,tools,audit,assembled.remote_interrupts.clone(),
            BuiltInAgentConfig{run_deadline:Some(Duration::from_secs(12)),..BuiltInAgentConfig::default()}).map_err(|_|"owned_actual_agent")?);
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
        let mut evidence_client=application_pool.get().await.map_err(|_|"owned_identity_connection")?;
        let evidence_tx=evidence_client.build_transaction().read_only(true).start().await.map_err(|_|"owned_identity_begin")?;
        let actual=evidence_tx.query_one("SELECT current_database(),current_user,pg_backend_pid()",&[]).await.map_err(|_|"owned_identity_read")?;
        let database:String=actual.get(0);let user:String=actual.get(1);let backend_pid:i32=actual.get(2);
        if database.is_empty() || user.is_empty() || backend_pid<=0{return Err("owned_identity_invalid".to_owned());}
        evidence_tx.commit().await.map_err(|_|"owned_identity_end")?;
        drop(evidence_client);
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":wire.origin(),"dist":dist,
            "sourceHead":source,"specSha256":spec,"producer":"same-Pool SessionAuthResolver/CapabilityFactory/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/ActualCustom/Agent/RunRelay/OwnedTLS","caseEvidence":{"database":database,"user":user,"backendPid":backend_pid}}))?;
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
        "stdinJoined":stdin_joined,"observerPoolCloseCalled":true,"applicationPoolCloseCalled":true,"counters":final_counters,
        "collectionFailed":collection_failed,"closeErrors":close_errors}),
    )?;
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
    result
}
