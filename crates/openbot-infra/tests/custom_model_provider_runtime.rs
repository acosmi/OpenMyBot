//! Owned PG + TLS integration for actual personal provider starts, without vendor accounts.
mod harness;
#[path = "custom_model_provider_runtime/target_identity.rs"]
mod target_identity;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openbot_application::model_connections::ModelConnectionAdministration;
use openbot_application::{
    AgentContextSource, BeginThreadRunRequest, ProviderAdapter, ProviderEvent, ProviderPortError,
    ProviderRequest, ProviderRoute, ProviderSession, RunExecutionLease, ThreadDirectory,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    command::{BeginThreadRun, ThreadRunAnchor},
    ids::thread::ThreadIdentity,
    ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId},
    model_connections::*,
};
use openbot_domain::{
    thread::FencingToken,
    vault::{KeyVersion, SecretBytes, WrappingKey},
};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer, SafeHttpBudget,
};
use openbot_infra::{
    db::{
        fresh,
        pool::{self, DatabaseConfig},
    },
    model_connections::PostgresModelConnections,
    provider::{context::PostgresAgentContextSource, custom::PostgresCustomModelProvider},
    thread_directory::PostgresThreadDirectory,
    vault::CredentialRecordVault,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use zeroize::Zeroizing;
const DEP: &str = "custom-runtime-dep";
const TENANT: &str = "custom-runtime-tenant";
const OWNER: &str = "custom-runtime";
const KEY: &str = "OWNED_CUSTOM_MODEL_CANARY";
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
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    config: DatabaseConfig,
    directory: PostgresThreadDirectory,
    models: Arc<PostgresModelConnections>,
    vault: CredentialRecordVault,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Self {
        let config = config.with_max_pool_size(6);
        let pool = pool::connect(&config).await.unwrap();
        let mut c = pool.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','alice@example.test',7),('bob','bob@example.test',3);INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Bot','built_in','{\"systemPrompt\":\"Standing prompt.\",\"providerSource\":\"managed\"}');INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Bot','','seed','public');INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Channel','',ARRAY[]::text[],ARRAY[]::text[]);INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x71; 32]).unwrap(),
        );
        let models = PostgresModelConnections::new(
            pool.clone(),
            vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x72; 32]),
        )
        .unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            OWNER.into(),
            time::Duration::seconds(30),
        )
        .unwrap();
        Self {
            pool,
            config,
            directory,
            models: Arc::new(models),
            vault,
        }
    }
    fn context(&self) -> PostgresAgentContextSource {
        PostgresAgentContextSource::new(
            self.pool.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            Some(32),
        )
        .unwrap()
    }
    fn adapter(&self, dialer: SafeDialer, timeout: Duration) -> PostgresCustomModelProvider {
        PostgresCustomModelProvider::new(
            self.pool.clone(),
            self.vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            dialer,
            SafeHttpBudget::new(64 * 1024 * 1024, timeout).unwrap(),
            Some(Duration::from_secs(2)),
        )
        .unwrap()
    }
    async fn begin(
        &self,
        index: u64,
        protocol: CustomModelProtocol,
        endpoint: &str,
        channel: bool,
    ) -> (ModelConnection, BeginThreadRunRequest, ProviderRequest) {
        let model = self
            .models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Chosen connection".into(),
                    protocol,
                    endpoint: endpoint.into(),
                    model: "exact-chosen-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new(KEY.into())).unwrap(),
                },
            )
            .await
            .unwrap();
        let mut entropy = [0; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        let req = BeginThreadRunRequest {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("custom-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "User prompt".into(),
                selected_skill_slugs: vec![],
                model_selection: Some(RunModelSelection {
                    connection_id: model.id.clone(),
                    expected_revision: model.revision,
                }),
            },
        };
        self.directory.begin_thread_run(req.clone()).await.unwrap();
        let request = self.context().load(&lease(&req)).await.unwrap();
        (model, req, request)
    }
}
fn lease(req: &BeginThreadRunRequest) -> RunExecutionLease {
    RunExecutionLease::new(
        req.command.run_id.clone(),
        req.command.thread_id.clone(),
        req.command.bot_id.clone(),
        req.actor.clone(),
        FencingToken::new(1).unwrap(),
        0,
    )
    .unwrap()
}
fn update(model: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: model.revision,
        name: model.name.clone(),
        protocol: model.protocol,
        endpoint: model.endpoint.clone(),
        model: model.model.clone(),
        enabled: model.enabled,
        api_key: None,
    }
}
#[derive(Clone)]
struct ResponsePlan {
    status: u16,
    body: String,
    location: Option<String>,
    header_gate: Option<Arc<Semaphore>>,
    body_gate: Option<Arc<Semaphore>>,
}
impl ResponsePlan {
    fn ok(body: String) -> Self {
        Self {
            status: 200,
            body,
            location: None,
            header_gate: None,
            body_gate: None,
        }
    }
    fn retry() -> Self {
        Self {
            status: 429,
            body: "{}".into(),
            location: None,
            header_gate: None,
            body_gate: None,
        }
    }
}
#[derive(Clone)]
struct Capture {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}
struct LocalResolver {
    address: SocketAddr,
    calls: AtomicUsize,
    fail_after_first: bool,
}
#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if host != "idp.test" || port != self.address.port() || (self.fail_after_first && n > 0) {
            return Err(DnsUnavailable);
        }
        Ok(vec![self.address])
    }
}
struct TlsFixture {
    address: SocketAddr,
    root: CertificateDer<'static>,
    captures: Arc<Mutex<Vec<Capture>>>,
    plans: Arc<Mutex<VecDeque<ResponsePlan>>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl TlsFixture {
    async fn new(plans: Vec<ResponsePlan>) -> Self {
        let root = CertificateDer::from(STANDARD.decode(TEST_CA_DER_BASE64).unwrap());
        let leaf = CertificateDer::from(STANDARD.decode(TEST_LEAF_DER_BASE64).unwrap());
        let key = PrivateKeyDer::try_from(STANDARD.decode(TEST_KEY_DER_BASE64).unwrap()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(![39025, 39027].contains(&address.port()));
        let captures = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(plans)));
        let seen = captures.clone();
        let planned = queue.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let tls = tls.clone();
                        let seen = seen.clone();
                        let planned = planned.clone();
                        children.spawn(async move {
                            let Ok(mut stream) = tls.accept(stream).await else { return; };
                            let Some(capture) = read_http(&mut stream).await else { return; };
                            let plan = planned.lock().unwrap().pop_front()
                                .unwrap_or_else(|| ResponsePlan::ok(chat_text()));
                            seen.lock().unwrap().push(capture);
                            if let Some(gate) = &plan.header_gate {
                                let Ok(permit) = gate.acquire().await else { return; };
                                permit.forget();
                            }
                            let extra = plan.location.as_ref()
                                .map(|url| format!("Location: {url}\r\n")).unwrap_or_default();
                            let retry = if plan.status == 429 { "Retry-After: 1\r\n" } else { "" };
                            let headers = format!(
                                "HTTP/1.1 {} OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n{extra}{retry}\r\n",
                                plan.status, plan.body.len()
                            );
                            if stream.write_all(headers.as_bytes()).await.is_err() { return; }
                            if let Some(gate) = &plan.body_gate {
                                let Ok(permit) = gate.acquire().await else { return; };
                                permit.forget();
                            }
                            let _ = stream.write_all(plan.body.as_bytes()).await;
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
            captures,
            plans: queue,
            stop: Some(stop),
            task: Some(task),
        }
    }
    fn endpoint(&self) -> String {
        format!("https://idp.test:{}/v1", self.address.port())
    }
    fn dialer(&self) -> SafeDialer {
        self.dialer_with(false, true)
    }
    fn dialer_with(&self, fail_after_first: bool, allow: bool) -> SafeDialer {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(if allow { vec!["127.0.0.1/32"] } else { vec![] })
                    .unwrap(),
            ),
            Arc::new(LocalResolver {
                address: self.address,
                calls: AtomicUsize::new(0),
                fail_after_first,
            }),
            [self.root.clone()],
        )
        .unwrap()
    }
    fn count(&self) -> usize {
        self.captures.lock().unwrap().len()
    }
    async fn wait_count(&self, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.count() < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "owned TLS request deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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
impl Drop for TlsFixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn read_http<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Capture> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let split = loop {
        let n = stream.read(&mut buffer).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 8 * 1024 * 1024 {
            return None;
        }
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8(bytes[..split].to_vec()).ok()?;
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.into();
    let path = first.next()?.into();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < split + length {
        let n = stream.read(&mut buffer).await.ok()?;
        if n == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    let body = if length == 0 {
        Value::Null
    } else {
        serde_json::from_slice(&bytes[split..split + length]).ok()?
    };
    Some(Capture {
        method,
        path,
        headers,
        body,
    })
}
fn chat_text() -> String {
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"id":"chat-owned","choices":[{"index":0,"delta":{"content":"hello custom"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}})
    )
}
fn responses_text() -> String {
    [
 json!({"type":"response.created","response":{"id":"responses-owned"},"sequence_number":0}),
 json!({"type":"response.output_text.delta","output_index":0,"delta":"hello custom","sequence_number":1}),
 json!({"type":"response.completed","response":{"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}},"sequence_number":2})].into_iter().map(|v|format!("data: {v}\n\n")).collect()
}
fn anthropic_text() -> String {
    [
 json!({"type":"message_start","message":{"id":"anthropic-owned","content":[],"usage":{"input_tokens":2,"output_tokens":0}}}),
 json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
 json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello custom"}}),
 json!({"type":"content_block_stop","index":0}),json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}),json!({"type":"message_stop"})].into_iter().map(|v|format!("data: {v}\n\n")).collect()
}
async fn events(mut session: Box<dyn ProviderSession>) -> Vec<ProviderEvent> {
    let mut out = vec![];
    while let Some(event) = session.next_event().await.unwrap() {
        out.push(event);
    }
    out
}
#[tokio::test]
#[ignore = "requires isolated PG and owned TLS; explicit include-ignored only"]
async fn three_protocols_use_frozen_endpoint_model_and_vault_key_through_real_tls() {
    let admin = harness::admin_config("custom_three_tls");
    harness::with_temp_database(&admin, "customtls", |config| async move {
        let f = Fixture::new(config).await;
        let tls = TlsFixture::new(vec![
            ResponsePlan::ok(chat_text()),
            ResponsePlan::ok(responses_text()),
            ResponsePlan::ok(anthropic_text()),
        ])
        .await;
        for (index, protocol) in [
            CustomModelProtocol::OpenaiChatCompletions,
            CustomModelProtocol::OpenaiResponses,
            CustomModelProtocol::AnthropicMessages,
        ]
        .into_iter()
        .enumerate()
        {
            let (model, _, request) = f
                .begin(index as u64 + 1, protocol, &tls.endpoint(), false)
                .await;
            let ProviderRoute::CustomModel(binding) = &request.route else {
                panic!("explicit selection must be custom");
            };
            assert_eq!(binding.endpoint(), model.endpoint);
            assert_eq!(binding.model(), model.model);
            assert!(request.rate_card.is_none());
            let debug = format!("{binding:?}");
            for hidden in [
                binding.endpoint(),
                binding.secret_id(),
                binding.connection_id(),
                KEY,
            ] {
                assert!(!debug.contains(hidden));
            }
            let output = events(
                f.adapter(tls.dialer(), Duration::from_secs(3))
                    .start(request)
                    .await
                    .unwrap(),
            )
            .await;
            assert!(
                output.iter().any(
                    |e| matches!(e,ProviderEvent::TextDelta{delta,..} if delta=="hello custom")
                )
            );
            assert_eq!(output.last(), Some(&ProviderEvent::Completed));
            let capture = tls.captures.lock().unwrap()[index].clone();
            assert_eq!(capture.method, "POST");
            assert_eq!(
                capture.path,
                url::Url::parse(&model.endpoint).unwrap().path()
            );
            assert_eq!(capture.body["model"], "exact-chosen-model");
            assert_eq!(capture.body["stream"], true);
            let encoded = capture.body.to_string();
            for hidden in [
                KEY,
                "modelSelection",
                "connectionId",
                "secretId",
                "authGeneration",
            ] {
                assert!(!encoded.contains(hidden));
            }
            match protocol {
                CustomModelProtocol::AnthropicMessages => {
                    assert_eq!(capture.headers["x-api-key"], KEY);
                    assert_eq!(capture.headers["anthropic-version"], "2023-06-01");
                    assert!(capture.body.get("system").is_some());
                }
                _ => assert_eq!(capture.headers["authorization"], format!("Bearer {KEY}")),
            }
        }
        assert_eq!(tls.count(), 3);
        tls.stop().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

// Existing W-7 non-production test CA/leaf/key, SAN=idp.test; no host trust modification.
const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY_DER_BASE64: &str =
    "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default)]
struct NoFallback(AtomicUsize);
#[async_trait]
impl ProviderAdapter for NoFallback {
    async fn start(
        &self,
        _: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProviderPortError::InvalidRequest {
            field: "unexpected_legacy",
        })
    }
}
fn retried(inner: Arc<dyn ProviderAdapter>) -> openbot_agent::RetryingProvider {
    openbot_agent::RetryingProvider::new(
        inner,
        openbot_agent::RetryingProviderConfig {
            max_retries: 1,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(100),
            jitter: false,
        },
    )
    .unwrap()
}
// R437/0046 makes a connection's (id,deployment,tenant,owner) scope immutable: the catalog
// FK is ON UPDATE RESTRICT and the sync trigger refuses a rebinding. First prove that ordinary
// DML is refused, then move the connection, secret and catalog scope jointly inside this owned
// disposable superuser DB only, with replica role scoped to that one transaction.
async fn tamper_owned_connection_scope(c: &tokio_postgres::Client, column: &str, value: &str) {
    let sql = format!(
        "UPDATE public.model_connections SET {column}='{value}';\
         UPDATE public.model_connection_secrets SET {column}='{value}';\
         UPDATE public.custom_model_catalogs SET {column}='{value}'"
    );
    let refused = c
        .batch_execute(&format!("BEGIN;{sql};COMMIT"))
        .await
        .unwrap_err();
    c.batch_execute("ROLLBACK").await.unwrap();
    let db = refused
        .as_db_error()
        .expect("ordinary scope rebinding must be a database refusal");
    assert_eq!(
        (db.code().code(), db.constraint()),
        ("23503", Some("custom_model_catalogs_connection_scope_fkey"))
    );
    let superuser: bool = c
        .query_one(
            "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        superuser,
        "owned scope corruption requires the disposable superuser test database"
    );
    c.batch_execute(&format!(
        "BEGIN;SET LOCAL session_replication_role=replica;{sql};COMMIT"
    ))
    .await
    .unwrap();
    let role: String = c
        .query_one("SELECT current_setting('session_replication_role')", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(role, "origin");
}

fn closed(result: Result<Box<dyn ProviderSession>, ProviderPortError>) {
    assert!(
        matches!(result, Err(ProviderPortError::InvalidRequest { .. })),
        "expected a static pre-send refusal"
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn retry_revalidates_revision_and_actor_after_429_without_a_second_post() {
    let admin = harness::admin_config("custom_retry");
    harness::with_temp_database(&admin,"customretry",|config|async move {
        let f=Fixture::new(config).await;
        for mode in 0..3 {
            let tls=TlsFixture::new(vec![ResponsePlan::retry(),ResponsePlan::ok(chat_text())]).await;
            let (model,_,request)=f.begin(20+mode,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
            let legacy=Arc::new(NoFallback::default());
            let router=openbot_agent::ProviderRouter::new(legacy.clone(),None)
                .with_custom(Arc::new(f.adapter(tls.dialer(),Duration::from_secs(3))));
            let task=tokio::spawn(async move{retried(Arc::new(router)).start(request).await});
            tls.wait_count(1).await;
            if mode==1 {
                let mut edit=update(&model);edit.model="changed-after-429".into();
                f.models.update(&auth(),&model.id,&edit).await.unwrap();
            } else if mode==2 {
                f.pool.get().await.unwrap().execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[]).await.unwrap();
            }
            let result=tokio::time::timeout(Duration::from_secs(5),task).await.unwrap().unwrap();
            if mode==0 {assert_eq!(events(result.unwrap()).await.last(),Some(&ProviderEvent::Completed));assert_eq!(tls.count(),2);}
            else {closed(result);assert_eq!(tls.count(),1,"revocation must prevent the second POST");}
            assert_eq!(legacy.0.load(Ordering::SeqCst),0);
            tls.stop().await;
        }
        println!("real TLS retry: unchanged=2 POST; revision changed=1 POST; generation changed=1 POST; legacy=0");
        f.pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn current_authority_ciphertext_and_bidirectional_snapshot_fail_closed_before_tls() {
    use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
    let admin = harness::admin_config("custom_authority");
    harness::with_temp_database(&admin,"customauthority",|config|async move {
        let f=Fixture::new(config).await;
        let tls=TlsFixture::new(vec![]).await;
        let (model,begin,request)=f.begin(40,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let c=f.pool.get().await.unwrap();
        let id=Uuid::parse_str(&model.id).unwrap();
        let secret:Uuid=c.query_one("SELECT current_secret_id FROM public.model_connections WHERE id=$1",&[&id]).await.unwrap().get(0);
        // All these changes are committed before the independent production start transaction.
        let cases=[
            ("generation", "UPDATE public.users SET auth_generation=8 WHERE id='alice'", "UPDATE public.users SET auth_generation=7 WHERE id='alice'"),
            ("role", "DELETE FROM public.user_roles WHERE user_id='alice'", "INSERT INTO public.user_roles(user_id,role) VALUES('alice','user')"),
            ("deny", "INSERT INTO public.revoked_access(email,revoked_by) VALUES('alice@example.test','bob')", "DELETE FROM public.revoked_access WHERE email='alice@example.test'"),
            ("direct membership", "DELETE FROM public.thread_memberships WHERE user_id='alice'", "INSERT INTO public.thread_memberships(thread_id,user_id) SELECT thread_id,'alice' FROM public.threads"),
            ("bot removed", "UPDATE public.agent_profiles SET deleted_at=clock_timestamp() WHERE agent_id='bot'", "UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='bot'"),
            ("bot private", "UPDATE public.agent_profiles SET visibility='private',owner_user_id='bob' WHERE agent_id='bot'", "UPDATE public.agent_profiles SET visibility='public',owner_user_id='alice' WHERE agent_id='bot'"),
            ("bot package tenant", "INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES('other','/owned-qa',repeat('a',64));UPDATE public.agents SET package_id=(SELECT id FROM public.deployment_packages WHERE tenant_id='other') WHERE id='bot'", "UPDATE public.agents SET package_id=NULL WHERE id='bot';DELETE FROM public.deployment_packages WHERE tenant_id='other'"),
            ("lease expired", "UPDATE public.thread_leases SET acquired_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second'", "UPDATE public.thread_leases SET expires_at=clock_timestamp()+interval '30 seconds'"),
            ("fencing", "UPDATE public.runs SET fencing_token=2", "UPDATE public.runs SET fencing_token=1"),
            ("disabled", "UPDATE public.model_connections SET enabled=false", "UPDATE public.model_connections SET enabled=true"),
            ("deleted", "UPDATE public.model_connections SET deleted_at=clock_timestamp()", "UPDATE public.model_connections SET deleted_at=NULL"),
            ("revision", "UPDATE public.model_connections SET revision=2", "UPDATE public.model_connections SET revision=1"),
            ("model", "UPDATE public.model_connections SET model='other'", "UPDATE public.model_connections SET model='exact-chosen-model'"),
            ("protocol", "UPDATE public.model_connections SET protocol='openai_responses'", "UPDATE public.model_connections SET protocol='openai_chat_completions'"),
            ("retired", "UPDATE public.model_connection_secrets SET retired_at=clock_timestamp()", "UPDATE public.model_connection_secrets SET retired_at=NULL"),
            ("input role", "UPDATE public.messages SET role='assistant' WHERE role='user'", "UPDATE public.messages SET role='user' WHERE role='assistant'"),
            ("input null", "UPDATE public.messages SET content=jsonb_set(content,'{modelSelection}','null') WHERE role='user'", "UPDATE public.messages SET content=jsonb_set(content,'{modelSelection}',jsonb_build_object('connectionId',(SELECT id::text FROM public.model_connections),'expectedRevision',1)) WHERE role='user'"),
            ("input missing", "UPDATE public.messages SET content=content-'modelSelection' WHERE role='user'", "UPDATE public.messages SET content=content||jsonb_build_object('modelSelection',jsonb_build_object('connectionId',(SELECT id::text FROM public.model_connections),'expectedRevision',1)) WHERE role='user'"),
            ("snapshot mismatch", "UPDATE public.run_model_selections SET model='other'", "UPDATE public.run_model_selections SET model='exact-chosen-model'"),
        ];
        let adapter=f.adapter(tls.dialer(),Duration::from_secs(3));
        for (label,change,restore) in cases {
            c.batch_execute(change).await.unwrap_or_else(|_|panic!("setup {label}"));
            closed(adapter.start(request.clone()).await);
            assert_eq!(tls.count(),0,"{label}");
            c.batch_execute(restore).await.unwrap_or_else(|_|panic!("restore {label}"));
        }
        let original:String=c.query_one("SELECT encrypted_value FROM public.model_connection_secrets WHERE id=$1",&[&secret]).await.unwrap().get(0);
        for mode in 0..4 {
            let encrypted=if mode==0 {"not-an-envelope".into()}else{
                f.vault.seal(&secret,SecretKind::Model,
                    SecretPrincipal::Actor(ActorId::new(if mode==1 {"bob"}else{"alice"})),
                    SecretPrincipal::Service(ServiceId::new(if mode==2 {"wrong-connection"}else{&model.id})),
                    &SecretBytes::new(if mode==3 {b" bad key\n".to_vec()}else{KEY.as_bytes().to_vec()})).unwrap()
            };
            c.execute("UPDATE public.model_connection_secrets SET encrypted_value=$1 WHERE id=$2",&[&encrypted,&secret]).await.unwrap();
            closed(adapter.start(request.clone()).await);assert_eq!(tls.count(),0);
        }
        c.execute("UPDATE public.model_connection_secrets SET encrypted_value=$1 WHERE id=$2",&[&original,&secret]).await.unwrap();
        c.execute("DELETE FROM public.run_model_selections WHERE run_id=$1",&[&begin.command.run_id.as_str()]).await.unwrap();
        closed(adapter.start(request).await);assert_eq!(tls.count(),0);
        drop(c);
        println!("authority=19 committed mutations; credential=4; intent-only=1; actual HTTPS requests=0");
        tls.stop().await;f.pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn channel_current_membership_and_binding_are_required_without_direct_membership() {
    let admin = harness::admin_config("custom_channel");
    harness::with_temp_database(&admin,"customchannel",|config|async move {
        let f=Fixture::new(config).await;let tls=TlsFixture::new(vec![]).await;
        let (_,begin,request)=f.begin(60,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),true).await;
        let c=f.pool.get().await.unwrap();
        c.execute("DELETE FROM public.thread_memberships WHERE thread_id=$1",&[&begin.command.thread_id.as_str()]).await.unwrap();
        assert!(matches!(f.context().load(&lease(&begin)).await.unwrap().route,ProviderRoute::CustomModel(_)));
        assert_eq!(events(f.adapter(tls.dialer(),Duration::from_secs(3)).start(request.clone()).await.unwrap()).await.last(),Some(&ProviderEvent::Completed));
        for (change,restore) in [
            ("DELETE FROM public.channel_memberships WHERE user_id='alice'","INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice')"),
            ("DELETE FROM public.channel_agents WHERE agent_id='bot'","INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot')"),
            ("INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES('other','/owned-qa',repeat('b',64));UPDATE public.channels SET package_id=(SELECT id FROM public.deployment_packages WHERE tenant_id='other')","UPDATE public.channels SET package_id=NULL;DELETE FROM public.deployment_packages WHERE tenant_id='other'")
        ] {
            c.batch_execute(change).await.unwrap();closed(f.adapter(tls.dialer(),Duration::from_secs(3)).start(request.clone()).await);
            assert!(f.context().load(&lease(&begin)).await.is_err());c.batch_execute(restore).await.unwrap();
        }
        assert_eq!(tls.count(),1);drop(c);tls.stop().await;f.pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn redirect_after_post_is_unknown_and_private_egress_never_bypasses_safe_dialer() {
    let admin = harness::admin_config("custom_redirect");
    harness::with_temp_database(&admin, "customredirect", |config| async move {
        let f = Fixture::new(config).await;
        let tls = TlsFixture::new(vec![]).await;
        tls.plans.lock().unwrap().push_back(ResponsePlan {
            status: 303,
            body: String::new(),
            location: Some(format!("{}/redirected", tls.endpoint())),
            header_gate: None,
            body_gate: None,
        });
        let (_, _, request) = f
            .begin(
                70,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        let result = retried(Arc::new(
            f.adapter(tls.dialer_with(true, true), Duration::from_secs(3)),
        ))
        .start(request.clone())
        .await;
        assert!(matches!(result, Err(ProviderPortError::CommitUnknown)));
        assert_eq!(tls.count(), 1);
        let result = retried(Arc::new(
            f.adapter(tls.dialer_with(false, false), Duration::from_secs(3)),
        ))
        .start(request)
        .await;
        assert!(result.is_err());
        assert_eq!(
            tls.count(),
            1,
            "default private-address denial must occur before a second request"
        );
        tls.stop().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn headers_hold_authority_but_sse_does_not_and_cancellation_releases_locks() {
    let admin = harness::admin_config("custom_locks");
    harness::with_temp_database(&admin,"customlocks",|config|async move {
        let f=Fixture::new(config).await;
        for mode in 0..3 {
            let gate=Arc::new(Semaphore::new(0));let mut plan=ResponsePlan::ok(chat_text());
            if mode==2 {plan.body_gate=Some(gate.clone());}else{plan.header_gate=Some(gate.clone());}
            let tls=TlsFixture::new(vec![plan]).await;
            let (model,_,request)=f.begin(80+mode,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
            let adapter=Arc::new(f.adapter(tls.dialer(),if mode==1 {Duration::from_millis(400)}else{Duration::from_secs(3)}));
            let task={let adapter=adapter.clone();let request=request.clone();tokio::spawn(async move{adapter.start(request).await})};
            tls.wait_count(1).await;
            if mode==2 {
                let session=tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap().unwrap();
                let mut edit=update(&model);edit.enabled=false;
                tokio::time::timeout(Duration::from_secs(2),f.models.update(&auth(),&model.id,&edit)).await.unwrap().unwrap();
                gate.add_permits(1);assert_eq!(events(session).await.last(),Some(&ProviderEvent::Completed));
                closed(adapter.start(request).await);
            }else{
                let models=f.models.clone();let mut edit=update(&model);edit.enabled=false;let id=model.id.clone();
                let mut change=tokio::spawn(async move{models.update(&auth(),&id,&edit).await});
                assert!(tokio::time::timeout(Duration::from_millis(60),&mut change).await.is_err(),"key source cannot change during pending headers");
                if mode==0 {task.abort();assert!(matches!(task.await, Err(error) if error.is_cancelled()));}
                else{assert!(matches!(task.await.unwrap(),Err(ProviderPortError::CommitUnknown)));}
                tokio::time::timeout(Duration::from_secs(3),change).await.unwrap().unwrap().unwrap();
            }
            assert_eq!(tls.count(),1);tls.stop().await;
        }
        println!("headers: source update blocked; abort and deadline: lock released; SSE: source update commits; old binding next start rejected");
        f.pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn cancellation_of_pending_sql_releases_user_lock_before_source_blocker_finishes() {
    let admin = harness::admin_config("custom_sql_cancel");
    harness::with_temp_database(&admin,"customsqlcancel",|config|async move {
        let f=Fixture::new(config).await;let tls=TlsFixture::new(vec![]).await;
        let (model,_,request)=f.begin(90,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let mut blocker=f.pool.get().await.unwrap();let tx=blocker.transaction().await.unwrap();
        tx.execute("UPDATE public.model_connections SET name=name WHERE id=$1",&[&Uuid::parse_str(&model.id).unwrap()]).await.unwrap();
        let adapter=f.adapter(tls.dialer(),Duration::from_secs(5));let task=tokio::spawn(async move{adapter.start(request).await});
        let observer=f.pool.get().await.unwrap();let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
        loop {
            let waiting:i64=observer.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT c.name%'",&[]).await.unwrap().get(0);
            if waiting>0 {break;}assert!(tokio::time::Instant::now()<deadline,"start must reach held source lock");tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(2),observer.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[])).await.unwrap().unwrap();
        // The blocker remains open throughout the proof; only this start's detached cancellation frees the user.
        tx.rollback().await.unwrap();assert_eq!(tls.count(),0);drop(observer);drop(blocker);
        tls.stop().await;f.pool.close();Ok(())
    }).await;
}

// QA-only transparent PG framing fault, fixed to this test's owned loopback database.
// No payload/password is logged. The server receives ROLLBACK, but its ReadyForQuery is lost.
struct PgAckLoss {
    config: DatabaseConfig,
    lost: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl PgAckLoss {
    async fn new(config: &DatabaseConfig) -> Self {
        assert_eq!(config.host, "127.0.0.1");
        let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut routed = config.clone();
        routed.port = listener.local_addr().unwrap().port();
        assert!(![39025, 39027].contains(&routed.port));
        let lost = Arc::new(AtomicUsize::new(0));
        let lost_task = lost.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    accepted=listener.accept()=>{
                        let Ok((mut downstream,_))=accepted else{break;};let lost=lost_task.clone();
                        children.spawn(async move {
                            let Ok(mut upstream)=TcpStream::connect(upstream).await else{return;};
                            let Ok(len)=downstream.read_u32().await else{return;};
                            if !(8..=65536).contains(&len){return;}
                            let mut startup=vec![0;len as usize-4];if downstream.read_exact(&mut startup).await.is_err(){return;}
                            if upstream.write_u32(len).await.is_err()||upstream.write_all(&startup).await.is_err(){return;}
                            if startup[..4]==80877102_u32.to_be_bytes(){return;}
                            let (mut down_read,mut down_write)=downstream.into_split();let (mut up_read,mut up_write)=upstream.into_split();
                            let rollback=Arc::new(std::sync::atomic::AtomicBool::new(false));let flag=rollback.clone();
                            let client=async move {
                                while let Some((tag,bytes))=pg_frame(&mut down_read).await {
                                    if tag==b'Q' && bytes.eq_ignore_ascii_case(b"ROLLBACK\0") {flag.store(true,Ordering::SeqCst);}
                                    if up_write.write_u8(tag).await.is_err()||up_write.write_u32(bytes.len() as u32+4).await.is_err()||up_write.write_all(&bytes).await.is_err(){break;}
                                }
                            };
                            let server=async move {
                                while let Some((tag,bytes))=pg_frame(&mut up_read).await {
                                    if tag==b'Z' && rollback.load(Ordering::SeqCst) {lost.fetch_add(1,Ordering::SeqCst);break;}
                                    if down_write.write_u8(tag).await.is_err()||down_write.write_u32(bytes.len() as u32+4).await.is_err()||down_write.write_all(&bytes).await.is_err(){break;}
                                }
                            };
                            tokio::select!{_=client=>{},_=server=>{}}
                        });
                    },
                    Some(_)=children.join_next(),if !children.is_empty()=>{}
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Self {
            config: routed,
            lost,
            stop: Some(stop),
            task: Some(task),
        }
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
impl Drop for PgAckLoss {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn pg_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Option<(u8, Vec<u8>)> {
    let tag = reader.read_u8().await.ok()?;
    let len = reader.read_u32().await.ok()?;
    if !(4..=8 * 1024 * 1024).contains(&len) {
        return None;
    }
    let mut bytes = vec![0; len as usize - 4];
    reader.read_exact(&mut bytes).await.ok()?;
    Some((tag, bytes))
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS/proxy; explicit include-ignored only"]
async fn lost_rollback_ack_after_headers_is_unknown_without_http_replay() {
    let admin = harness::admin_config("custom_ack_loss");
    harness::with_temp_database(&admin, "customackloss", |config| async move {
        let f = Fixture::new(config).await;
        let tls = TlsFixture::new(vec![]).await;
        let (model, _, request) = f
            .begin(
                100,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        let proxy = PgAckLoss::new(&f.config).await;
        let pool = pool::connect(&proxy.config).await.unwrap();
        let adapter = PostgresCustomModelProvider::new(
            pool.clone(),
            f.vault.clone(),
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            tls.dialer(),
            SafeHttpBudget::new(64 * 1024 * 1024, Duration::from_secs(3)).unwrap(),
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        assert!(matches!(
            retried(Arc::new(adapter)).start(request).await,
            Err(ProviderPortError::CommitUnknown)
        ));
        assert_eq!(tls.count(), 1);
        assert_eq!(proxy.lost.load(Ordering::SeqCst), 1);
        let mut edit = update(&model);
        edit.enabled = false;
        tokio::time::timeout(
            Duration::from_secs(2),
            f.models.update(&auth(), &model.id, &edit),
        )
        .await
        .unwrap()
        .unwrap();
        pool.close();
        proxy.stop().await;
        tls.stop().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

struct RunningAgent {
    agent: openbot_agent::BuiltInAgentRuntime,
    relay: openbot_infra::run_runtime::RunRelay,
    legacy: Arc<NoFallback>,
}
impl RunningAgent {
    fn start(
        f: &Fixture,
        context: Arc<dyn AgentContextSource>,
        adapter: PostgresCustomModelProvider,
        tools: Arc<dyn openbot_agent::AgentToolInvoker>,
    ) -> Self {
        use openbot_infra::run_runtime::{
            DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime, RunRelay,
        };
        let runtime: Arc<dyn openbot_application::RunRuntime> = Arc::new(
            PostgresRunRuntime::new(
                f.pool.clone(),
                OWNER.into(),
                time::Duration::seconds(30),
                DEFAULT_DISPATCH_CLAIM_DURATION,
            )
            .unwrap(),
        );
        let legacy = Arc::new(NoFallback::default());
        let router =
            openbot_agent::ProviderRouter::new(legacy.clone(), None).with_custom(Arc::new(adapter));
        let agent = openbot_agent::BuiltInAgentRuntime::start(
            runtime.clone(),
            context,
            Arc::new(retried(Arc::new(router))),
            tools,
            Arc::new(
                openbot_infra::agent_audit::PostgresAgentAudit::new(f.pool.clone(), vec![0x72; 32])
                    .unwrap(),
            ),
            openbot_agent::BuiltInAgentConfig {
                queue_capacity: 8,
                max_concurrency: 2,
                max_tool_concurrency: 1,
                lease_renew_interval: Duration::from_millis(200),
                run_deadline: Some(Duration::from_secs(10)),
            },
        )
        .unwrap();
        let relay = RunRelay::start(runtime, agent.consumer());
        Self {
            agent,
            relay,
            legacy,
        }
    }
    async fn stop(self) {
        self.relay.stop().await;
        self.agent.stop().await;
        assert_eq!(self.legacy.0.load(Ordering::SeqCst), 0);
    }
}
async fn terminal(
    pool: &openbot_infra::db::pool::DatabasePool,
    run: &RunId,
) -> (String, Option<String>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let c = pool.get().await.unwrap();
        let row = c
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&run.as_str()],
            )
            .await
            .unwrap();
        let status: String = row.get(0);
        if status != "running" {
            let count: i64 = c
                .query_one(
                    "SELECT count(*) FROM public.run_events WHERE run_id=$1 AND terminal",
                    &[&run.as_str()],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(count, 1);
            return (status, row.get(1));
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "durable terminal deadline"
        );
        drop(c);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
fn chat_tool() -> String {
    format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"id":"chat-tool-owned","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"owned-notice-call","type":"function","function":{"name":"showNotice","arguments":json!({"title":"Ready","body":"Tool result delivered","tone":"positive"}).to_string()}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}})
    )
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn real_agent_tool_pipeline_persists_exchange_and_samples_same_custom_model_again() {
    use openbot_application::{ApplicationService, ComponentAdministration, OpenBotApplication};
    use openbot_infra::{
        agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence},
        component_catalogue::PostgresComponentAdministration,
        repo::ChannelRepo,
    };
    let admin = harness::admin_config("custom_tool_sampling");
    harness::with_temp_database(&admin,"customtoolsampling",|config|async move {
        let f=Fixture::new(config).await;
        let components=Arc::new(PostgresComponentAdministration::new(f.pool.clone(),vec![0x72;32]).unwrap());
        components.sync_catalogue(&auth(),&openbot_contracts::components::compiled_component_manifest()).await.unwrap();
        let application:Arc<dyn ApplicationService>=Arc::new(OpenBotApplication::new(ChannelRepo::new(f.pool.clone())).with_component_administration(components.clone()));
        let gateway=openbot_agent::AuthorizedAgentToolGateway::with_sequence(application,
            Arc::new(PostgresAgentAuthorizationSource::new(f.pool.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),false)),Arc::new(PostgresAgentToolSequence::new(f.pool.clone())));
        let tls=TlsFixture::new(vec![ResponsePlan::ok(chat_tool()),ResponsePlan::ok(chat_text())]).await;
        let (_,begin,_)=f.begin(110,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let running=RunningAgent::start(&f,Arc::new(f.context().with_components(components)),f.adapter(tls.dialer(),Duration::from_secs(3)),Arc::new(gateway));
        let result=terminal(&f.pool,&begin.command.run_id).await;running.stop().await;
        assert_eq!(result,("completed".into(),None));assert_eq!(tls.count(),2);
        let captures=tls.captures.lock().unwrap().clone();
        for capture in &captures {assert_eq!(capture.body["model"],"exact-chosen-model");assert_eq!(capture.headers["authorization"],format!("Bearer {KEY}"));}
        assert_eq!(captures[0].path,captures[1].path);
        let messages=captures[1].body["messages"].as_array().unwrap();
        let result=messages.iter().find(|m|m["role"]=="tool").unwrap();assert_eq!(result["tool_call_id"],"owned-notice-call");
        assert!(result["content"].as_str().unwrap().contains("The notice is now on screen"));
        let c=f.pool.get().await.unwrap();
        let count:i64=c.query_one("SELECT count(*) FROM public.messages WHERE run_id=$1 AND role='tool'",&[&begin.command.run_id.as_str()]).await.unwrap().get(0);assert_eq!(count,1);
        let count:i64=c.query_one("SELECT count(*) FROM public.run_events WHERE run_id=$1 AND event_type='checkpoint' AND payload->>'kind'='tool_exchange'",&[&begin.command.run_id.as_str()]).await.unwrap().get(0);assert_eq!(count,1);
        drop(c);tls.stop().await;f.pool.close();Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn unpriced_custom_run_is_durably_rejected_and_authoritative_cap_cannot_be_omitted() {
    use openbot_application::{
        ProviderBillingFamily, ProviderRateCard, ProviderRateCardInput, RunCostCap,
    };
    let admin = harness::admin_config("custom_unpriced");
    harness::with_temp_database(&admin,"customunpriced",|config|async move {
        let f=Fixture::new(config).await;let tls=TlsFixture::new(vec![]).await;
        let (_,begin,request)=f.begin(120,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let rate=ProviderRateCard::new(ProviderRateCardInput{family:ProviderBillingFamily::OpenAiCompatible,model:"package-model".into(),currency:"USD".into(),max_input_micro_units_per_million_tokens:1,max_output_micro_units_per_million_tokens:2,source_url:"https://prices.example.test/owned".into(),source_sha256:"a".repeat(64),observed_at:time::macros::datetime!(2026-08-30 12:00 UTC)}).unwrap();
        let adapter=f.adapter(tls.dialer(),Duration::from_secs(3));let mut forged=request.clone();forged.rate_card=Some(rate.clone());closed(adapter.start(forged).await);
        let mut forged=request.clone();forged.cost_cap=Some(RunCostCap::new("USD".into(),1000).unwrap());closed(adapter.start(forged).await);
        f.pool.get().await.unwrap().execute("UPDATE public.runs SET budget_cost_currency='USD',budget_max_cost_micro_units=1000 WHERE run_id=$1",&[&begin.command.run_id.as_str()]).await.unwrap();
        closed(adapter.start(request).await);
        let context=f.context().with_rate_cards(Some(rate.clone()),Some(rate));
        let actual=context.load(&lease(&begin)).await.unwrap();assert!(actual.rate_card.is_none());assert!(actual.cost_cap.is_some());
        let running=RunningAgent::start(&f,Arc::new(context),adapter,Arc::new(openbot_agent::NoAgentToolInvoker));
        let result=terminal(&f.pool,&begin.command.run_id).await;running.stop().await;
        assert_eq!(result,("failed".into(),Some("run_cost_budget_unpriced".into())));assert_eq!(tls.count(),0);
        tls.stop().await;f.pool.close();Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn durable_cancel_while_headers_pending_stops_agent_and_releases_source() {
    let admin = harness::admin_config("custom_durable_cancel");
    harness::with_temp_database(&admin, "customdurablecancel", |config| async move {
        let f = Fixture::new(config).await;
        let gate = Arc::new(Semaphore::new(0));
        let mut plan = ResponsePlan::ok(chat_text());
        plan.header_gate = Some(gate);
        let tls = TlsFixture::new(vec![plan]).await;
        let (model, begin, _) = f
            .begin(
                130,
                CustomModelProtocol::OpenaiChatCompletions,
                &tls.endpoint(),
                false,
            )
            .await;
        let running = RunningAgent::start(
            &f,
            Arc::new(f.context()),
            f.adapter(tls.dialer(), Duration::from_secs(3)),
            Arc::new(openbot_agent::NoAgentToolInvoker),
        );
        tls.wait_count(1).await;
        f.directory
            .cancel_thread_run(openbot_application::CancelThreadRunRequest {
                deployment: DeploymentId::new(DEP),
                tenant: TenantId::new(TENANT),
                actor: ActorId::new("alice"),
                command: openbot_contracts::command::CancelThreadRun {
                    thread_id: begin.command.thread_id.clone(),
                    run_id: begin.command.run_id.clone(),
                },
            })
            .await
            .unwrap();
        let result = terminal(&f.pool, &begin.command.run_id).await;
        running.stop().await;
        assert_eq!(result.0, "cancelled");
        let mut edit = update(&model);
        edit.enabled = false;
        tokio::time::timeout(
            Duration::from_secs(2),
            f.models.update(&auth(), &model.id, &edit),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(tls.count(), 1);
        tls.stop().await;
        f.pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17; explicit include-ignored only"]
async fn context_projection_has_no_authority_row_locks_and_cancelled_reads_do_not_pin_actor() {
    let admin = harness::admin_config("custom_context_locks");
    harness::with_temp_database(&admin,"customcontextlocks",|config|async move {
        let f=Fixture::new(config).await;let tls=TlsFixture::new(vec![]).await;
        let (model,begin,_)=f.begin(140,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let mut blocker=f.pool.get().await.unwrap();let tx=blocker.transaction().await.unwrap();
        tx.execute("UPDATE public.model_connections SET name=name WHERE id=$1",&[&Uuid::parse_str(&model.id).unwrap()]).await.unwrap();
        let value=tokio::time::timeout(Duration::from_secs(1),f.context().load(&lease(&begin))).await.unwrap().unwrap();
        assert!(matches!(value.route,ProviderRoute::CustomModel(_)));
        tx.rollback().await.unwrap();
        // A deliberately blocked late SELECT is cancellable without a retained user SHARE lock.
        // ACCESS EXCLUSIVE is test-only; normal connection edits above do not block context.
        let tx=blocker.transaction().await.unwrap();tx.batch_execute("LOCK TABLE public.model_connection_secrets IN ACCESS EXCLUSIVE MODE").await.unwrap();
        let context=f.context();let run_lease=lease(&begin);
        let task=tokio::spawn(async move{context.load(&run_lease).await});
        let observer=f.pool.get().await.unwrap();let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
        loop {let waiting:i64=observer.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT s.encrypted_value%'",&[]).await.unwrap().get(0);
            if waiting>0 {break;}assert!(tokio::time::Instant::now()<deadline);tokio::time::sleep(Duration::from_millis(10)).await;}
        task.abort();assert!(matches!(task.await,Err(error) if error.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(1),observer.execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'",&[])).await.unwrap().unwrap();
        tx.rollback().await.unwrap();drop(observer);drop(blocker);
        assert!(f.context().load(&lease(&begin)).await.is_err());assert_eq!(tls.count(),0);
        tls.stop().await;f.pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL 17 and owned TLS; explicit include-ignored only"]
async fn deployment_tenant_owner_current_reference_and_valid_legacy_cipher_are_not_portable() {
    use openbot_domain::vault::{SecretKind, SecretPrincipal, ServiceId};
    let admin = harness::admin_config("custom_scope_key");
    harness::with_temp_database(&admin,"customscopekey",|config|async move {
        let f=Fixture::new(config).await;let tls=TlsFixture::new(vec![]).await;
        let (model,_,request)=f.begin(150,CustomModelProtocol::OpenaiChatCompletions,&tls.endpoint(),false).await;
        let c=f.pool.get().await.unwrap();
        for (column,other,original) in [
            ("deployment_id","other","custom-runtime-dep"),
            ("tenant_id","other","custom-runtime-tenant"),
            ("owner_user_id","bob","alice"),
        ] {
            tamper_owned_connection_scope(&c,column,other).await;closed(f.adapter(tls.dialer(),Duration::from_secs(3)).start(request.clone()).await);
            tamper_owned_connection_scope(&c,column,original).await;
        }
        let secret:Uuid=c.query_one("SELECT current_secret_id FROM public.model_connections",&[]).await.unwrap().get(0);
        let replacement=Uuid::new_v4();
        c.execute("INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at) SELECT $1,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at FROM public.model_connection_secrets WHERE id=$2",&[&replacement,&secret]).await.unwrap();
        c.execute("UPDATE public.model_connections SET current_secret_id=$1",&[&replacement]).await.unwrap();
        closed(f.adapter(tls.dialer(),Duration::from_secs(3)).start(request.clone()).await);
        c.execute("UPDATE public.model_connections SET current_secret_id=$1",&[&secret]).await.unwrap();
        let wrong_tenant_vault=CredentialRecordVault::single_key(TenantId::new("other"),KeyVersion::new(1),WrappingKey::from_bytes(vec![0x71;32]).unwrap());
        let wrong=wrong_tenant_vault.seal(&secret,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("alice")),SecretPrincipal::Service(ServiceId::new(&model.id)),&SecretBytes::new(KEY.as_bytes().to_vec())).unwrap();
        c.execute("UPDATE public.model_connection_secrets SET encrypted_value=$1 WHERE id=$2",&[&wrong,&secret]).await.unwrap();
        closed(f.adapter(tls.dialer(),Duration::from_secs(3)).start(request.clone()).await);
        const LEGACY: &str = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
        let legacy_vault=CredentialRecordVault::single_key(TenantId::new(TENANT),KeyVersion::new(1),WrappingKey::from_bytes((0_u8..32).collect()).unwrap());
        assert!(legacy_vault.open(&secret,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("alice")),SecretPrincipal::Service(ServiceId::new(&model.id)),LEGACY).unwrap().needs_migration());
        c.execute("UPDATE public.model_connection_secrets SET encrypted_value=$1 WHERE id=$2",&[&LEGACY,&secret]).await.unwrap();
        let adapter=PostgresCustomModelProvider::new(f.pool.clone(),legacy_vault,DeploymentId::new(DEP),TenantId::new(TENANT),tls.dialer(),SafeHttpBudget::new(64*1024*1024,Duration::from_secs(3)).unwrap(),Some(Duration::from_secs(2))).unwrap();
        closed(adapter.start(request).await);assert_eq!(tls.count(),0);
        drop(c);tls.stop().await;f.pool.close();Ok(())
    }).await;
}
