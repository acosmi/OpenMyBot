//! Pinned RMCP client over SafeDialer against a real pinned RMCP Streamable HTTP server.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::response::IntoResponse as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openbot_agent::{AgentToolInvoker, AuthorizedAgentToolGateway};
use openbot_application::{
    AgentContextSource, ApplicationService, McpConnectionAdministration, OpenBotApplication,
    RunExecutionLease, ToolApprovalAdministration, ToolCallSequence, ToolCancellationReason,
    ToolCancellationRegistry, tool_execution_cancellation,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId, ToolCallId};
use openbot_contracts::mcp::McpCustomServerRegistration;
use openbot_contracts::tool::ToolApprovalDecision;
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::thread::FencingToken;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::agent_tools::{
    PostgresAgentAuthorizationSource, PostgresAgentToolSequence, PostgresBuiltInToolControlPlane,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::mcp::{MAX_MCP_RESULT_CHARS, McpClientError, SafeRmcpClient, normalize_result};
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::mcp_connections::PostgresMcpConnections;
use openbot_infra::mcp_credentials::PostgresMcpCredentialBroker;
use openbot_infra::mcp_oauth::McpOAuthClient;
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer, SafeHttpBudget,
    SafeHttpRequest, SchemePolicy,
};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::tool_approval::PostgresToolApprovalCoordinator;
use openbot_infra::vault::CredentialRecordVault;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelledNotificationParam,
    ContentBlock, Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

// Long-lived test-only Ed25519 CA/leaf for `idp.test`; copied from the repository's W-7 TLS
// conformance fixture so no certificate generation or network dependency enters this test.
const TLS_CA_DER: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TLS_LEAF_DER: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TLS_LEAF_KEY_DER: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
const RMCP_RUN_CANCELLATION_FIXTURE: &str =
    include_str!("../../../fixtures/mcp/rmcp-run-cancellation.json");
const RMCP_RUN_CANCELLATION_FIXTURE_BYTES: usize = 1_111;
const RMCP_RUN_CANCELLATION_FIXTURE_SHA256: &str =
    "ec9644f41e8b0773e0983efa52179eef1e32387b2bbd0ec69101afd4874e6b56";

fn cancellation_fixture() -> Value {
    serde_json::from_str(RMCP_RUN_CANCELLATION_FIXTURE).expect("valid RMCP cancellation fixture")
}

#[derive(Clone)]
struct RealMcpServer {
    received: Arc<Mutex<Vec<Value>>>,
    listed: Arc<Mutex<Vec<Tool>>>,
    cancellation: Arc<CancellationProbe>,
}

#[derive(Default)]
struct CancellationProbe {
    block_list: AtomicBool,
    list_started: Notify,
    list_stopped: Notify,
    started: Notify,
    handler_stopped: Notify,
    notification_received: Notify,
    notifications: Mutex<Vec<Value>>,
    protocol_versions: Mutex<Vec<String>>,
}

impl RealMcpServer {
    fn tools() -> Vec<Tool> {
        let schema = |required: bool| {
            let mut value = json!({
                "type":"object",
                "properties":{"query":{"type":"string"}},
            });
            if required {
                value["required"] = json!(["query"]);
            }
            value.as_object().cloned().unwrap()
        };
        vec![
            Tool::new(
                "search_issues",
                "Find issues matching a query.",
                schema(true),
            ),
            Tool::new_with_raw("bare", None, schema(false)),
            Tool::new("long_answer", "Returns far too much.", schema(false)),
            Tool::new("returns_an_image", "Not text.", schema(false)),
            Tool::new("mixed_content", "Mixed.", schema(false)),
            Tool::new("always_fails", "Tool-level failure.", schema(false)),
        ]
    }
}

impl ServerHandler for RealMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("openbot-test-rmcp", "3.1.4"))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.cancellation.protocol_versions.lock().unwrap().push(
            context.protocol_version().map_or_else(
                || "missing".to_owned(),
                |version| version.as_str().to_owned(),
            ),
        );
        if self.cancellation.block_list.load(Ordering::Acquire) {
            self.cancellation.list_started.notify_one();
            context.ct.cancelled().await;
            self.cancellation.list_stopped.notify_one();
        }
        Ok(ListToolsResult::with_all_items(
            self.listed.lock().unwrap().clone(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.cancellation.protocol_versions.lock().unwrap().push(
            context.protocol_version().map_or_else(
                || "missing".to_owned(),
                |version| version.as_str().to_owned(),
            ),
        );
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let result = match request.name.as_ref() {
            "search_issues" => {
                self.received.lock().unwrap().push(arguments.clone());
                let query = arguments
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                CallToolResult::success(vec![ContentBlock::text(format!(
                    "Found 2 issues for {query}"
                ))])
            }
            "bare" => CallToolResult::success(Vec::new()),
            "long_answer" => {
                self.received.lock().unwrap().push(arguments.clone());
                CallToolResult::success(vec![ContentBlock::text("x".repeat(25_000))])
            }
            "returns_an_image" => {
                CallToolResult::success(vec![ContentBlock::image("AA==", "image/png")])
            }
            "mixed_content" => CallToolResult::success(vec![
                ContentBlock::text("here is the chart"),
                ContentBlock::image("AA==", "image/png"),
            ]),
            "always_fails" => CallToolResult::error(vec![ContentBlock::text("vendor said no")]),
            "wait_for_cancel" => {
                self.cancellation.started.notify_one();
                context.ct.cancelled().await;
                self.cancellation.handler_stopped.notify_one();
                CallToolResult::success(vec![ContentBlock::text("cancelled")])
            }
            _ => return Err(McpError::invalid_params("unknown tool", None)),
        };
        Ok(CallToolResponse::Complete(result))
    }

    async fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) {
        self.cancellation
            .notifications
            .lock()
            .unwrap()
            .push(serde_json::to_value(notification).unwrap());
        self.cancellation.notification_received.notify_one();
    }
}

async fn spawn_server() -> Result<
    (
        String,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<Tool>>>,
        Arc<Mutex<Vec<String>>>,
        Arc<CancellationProbe>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    spawn_server_with_mode(false).await
}

async fn spawn_legacy_server() -> Result<
    (
        String,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<Tool>>>,
        Arc<Mutex<Vec<String>>>,
        Arc<CancellationProbe>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    spawn_server_with_mode(true).await
}

async fn spawn_server_with_mode(
    reject_discover: bool,
) -> Result<
    (
        String,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<Tool>>>,
        Arc<Mutex<Vec<String>>>,
        Arc<CancellationProbe>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let received = Arc::new(Mutex::new(Vec::new()));
    let listed = Arc::new(Mutex::new(RealMcpServer::tools()));
    let traffic = Arc::new(Mutex::new(Vec::new()));
    let cancellation = Arc::new(CancellationProbe::default());
    let server = RealMcpServer {
        received: received.clone(),
        listed: listed.clone(),
        cancellation: cancellation.clone(),
    };
    let service = StreamableHttpService::new(
        move || Ok::<_, std::io::Error>(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_allowed_hosts([
            "localhost",
            "127.0.0.1",
            "::1",
            "idp.test",
        ]),
    );
    let traffic_log = traffic.clone();
    let router =
        axum::Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let traffic = traffic_log.clone();
                    async move {
                        let method = request.method().clone();
                        let path = request.uri().path().to_owned();
                        let mcp_method = request
                            .headers()
                            .get("mcp-method")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("-")
                            .to_owned();
                        let protocol = request
                            .headers()
                            .get("mcp-protocol-version")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("-")
                            .to_owned();
                        let prefix = format!("{method} {path} mcp={mcp_method} version={protocol}");
                        traffic.lock().unwrap().push(format!("{prefix} started"));
                        let response = next.run(request).await;
                        traffic
                            .lock()
                            .unwrap()
                            .push(format!("{prefix} {}", response.status()));
                        response
                    }
                },
            ));
    let router = if reject_discover {
        router.layer(axum::middleware::from_fn(reject_server_discover))
    } else {
        router
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((
        format!("http://{address}/mcp"),
        received,
        listed,
        traffic,
        cancellation,
        handle,
    ))
}

async fn reject_server_discover(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 4 * 1024 * 1024).await else {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    };
    let value = serde_json::from_slice::<Value>(&bytes).ok();
    if value
        .as_ref()
        .and_then(|value| value.get("method"))
        .and_then(Value::as_str)
        == Some("server/discover")
    {
        let id = value
            .as_ref()
            .and_then(|value| value.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        return (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            axum::Json(json!({
                "jsonrpc":"2.0",
                "id":id,
                "error":{"code":-32601,"message":"Method not found"}
            })),
        )
            .into_response();
    }
    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
    .await
}

#[derive(Clone)]
struct LocalResolver(SocketAddr);

#[async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        Ok(vec![self.0])
    }
}

async fn spawn_tls_server() -> Result<
    (
        String,
        SocketAddr,
        CertificateDer<'static>,
        Arc<Mutex<Vec<Value>>>,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (backend_url, received, _listed, traffic, _cancellation, backend_handle) =
        spawn_server().await?;
    let backend = url::Url::parse(&backend_url).map_err(|error| error.to_string())?;
    let backend_address = SocketAddr::new(
        backend
            .host_str()
            .ok_or("TLS proxy backend host missing")?
            .parse()
            .map_err(|error: std::net::AddrParseError| error.to_string())?,
        backend.port().ok_or("TLS proxy backend port missing")?,
    );
    let errors = Arc::new(Mutex::new(Vec::new()));
    let root = CertificateDer::from(
        BASE64_STANDARD
            .decode(TLS_CA_DER)
            .map_err(|error| error.to_string())?,
    );
    let leaf = CertificateDer::from(
        BASE64_STANDARD
            .decode(TLS_LEAF_DER)
            .map_err(|error| error.to_string())?,
    );
    let key = PrivateKeyDer::try_from(
        BASE64_STANDARD
            .decode(TLS_LEAF_KEY_DER)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .map_err(|error| error.to_string())?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let server_errors = errors.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let errors = server_errors.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        errors.lock().unwrap().push(format!("tls: {error}"));
                        return;
                    }
                };
                let mut backend = match TcpStream::connect(backend_address).await {
                    Ok(backend) => backend,
                    Err(error) => {
                        errors.lock().unwrap().push(format!("backend: {error}"));
                        return;
                    }
                };
                if let Err(error) = tokio::io::copy_bidirectional(&mut stream, &mut backend).await {
                    errors.lock().unwrap().push(format!("proxy: {error}"));
                }
            });
        }
    });
    Ok((
        format!("https://idp.test:{}/mcp", address.port()),
        address,
        root,
        received,
        errors,
        traffic,
        handle,
        backend_handle,
    ))
}

fn client() -> SafeRmcpClient {
    SafeRmcpClient::new(
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
        )),
        SchemePolicy::HttpOrHttps,
        Some(std::time::Duration::from_secs(2)),
    )
}

#[tokio::test]
async fn real_rmcp_server_lists_calls_normalizes_and_closes_per_operation() {
    let (url, received, listed, _traffic, _cancellation, server) = spawn_server().await.unwrap();
    let client = client();
    let tools = client.list_tools(&url, None).await.unwrap();
    assert_eq!(tools.len(), 6);
    let search = tools
        .iter()
        .find(|tool| tool.name == "search_issues")
        .unwrap();
    assert_eq!(search.description, "Find issues matching a query.");
    assert_eq!(search.input_schema["type"], "object");
    assert_eq!(
        tools
            .iter()
            .find(|tool| tool.name == "bare")
            .unwrap()
            .description,
        ""
    );

    let answer = client
        .call_tool(&url, None, "search_issues", json!({"query":"billing"}))
        .await
        .unwrap();
    assert_eq!(answer.text, "Found 2 issues for billing");
    assert!(!answer.is_error);
    assert!(!answer.truncated);
    assert_eq!(
        received.lock().unwrap().as_slice(),
        [json!({"query":"billing"})]
    );

    let image = client
        .call_tool(&url, None, "returns_an_image", json!({}))
        .await
        .unwrap();
    assert_eq!(image.text, "[image]");
    let mixed = client
        .call_tool(&url, None, "mixed_content", json!({}))
        .await
        .unwrap();
    assert_eq!(mixed.text, "here is the chart\n[image]");
    let failed = client
        .call_tool(&url, None, "always_fails", json!({}))
        .await
        .unwrap();
    assert!(failed.is_error);
    assert_eq!(failed.text, "vendor said no");
    let empty = client
        .call_tool(&url, None, "bare", json!({}))
        .await
        .unwrap();
    assert!(empty.text.to_ascii_lowercase().contains("nothing"));

    let long = client
        .call_tool(&url, None, "long_answer", json!({}))
        .await
        .unwrap();
    assert!(long.truncated);
    assert!(long.text.contains("25000 characters"));
    assert_eq!(
        long.text.chars().take(MAX_MCP_RESULT_CHARS).count(),
        MAX_MCP_RESULT_CHARS
    );
    assert_eq!(
        client
            .call_tool(&url, None, "no_such_tool", json!({}))
            .await,
        Err(McpClientError::ToolMissing)
    );
    let expected_schema_hash = openbot_domain::audit::hash::Sha256Digest::of(
        &serde_json::to_vec(&search.input_schema).unwrap(),
    );
    let before = received.lock().unwrap().len();
    listed
        .lock()
        .unwrap()
        .iter_mut()
        .find(|tool| tool.name == "search_issues")
        .unwrap()
        .input_schema = Arc::new(
        json!({"type":"object","properties":{"term":{"type":"string"}},"required":["term"]})
            .as_object()
            .cloned()
            .unwrap(),
    );
    assert_eq!(
        client
            .call_tool_bound(
                &url,
                None,
                "search_issues",
                expected_schema_hash,
                json!({"query":"must-not-send"}),
            )
            .await,
        Err(McpClientError::CatalogChanged)
    );
    assert_eq!(received.lock().unwrap().len(), before);
    server.abort();
}

#[tokio::test]
async fn unreachable_server_is_an_error_not_an_empty_catalog() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(
        client()
            .list_tools(&format!("http://{address}/mcp"), None)
            .await
            .is_err()
    );
}

#[test]
fn rmcp_run_cancellation_fixture_is_closed_and_current() {
    let fixture = cancellation_fixture();
    assert_eq!(
        RMCP_RUN_CANCELLATION_FIXTURE.len(),
        RMCP_RUN_CANCELLATION_FIXTURE_BYTES
    );
    assert_eq!(
        openbot_domain::audit::hash::Sha256Digest::of(RMCP_RUN_CANCELLATION_FIXTURE.as_bytes())
            .to_hex(),
        RMCP_RUN_CANCELLATION_FIXTURE_SHA256
    );
    assert_eq!(fixture["schema"], "openbot-rmcp-run-cancellation-v2");
    assert_eq!(fixture["transport"], "streamable-http");
    let mut top = fixture
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    top.sort();
    assert_eq!(top, ["cases", "protocols", "schema", "transport"]);
    assert_eq!(fixture["protocols"]["preferredModern"], "2026-07-28");
    assert_eq!(fixture["protocols"]["legacyFallback"], "2025-11-25");
    assert_eq!(
        {
            let mut keys = fixture["protocols"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            keys.sort();
            keys
        },
        ["legacyFallback", "preferredModern"]
    );
    let mut cases = fixture["cases"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    cases.sort();
    assert_eq!(
        cases,
        [
            "beforeAnyNetwork",
            "legacyDuringToolCall",
            "modernDuringFreshList",
            "modernDuringToolCall",
        ]
    );
    let sorted_keys = |value: &Value| {
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };
    assert_eq!(
        sorted_keys(&fixture["cases"]["beforeAnyNetwork"]),
        ["acceptedSockets", "errorCode"]
    );
    assert_eq!(
        sorted_keys(&fixture["cases"]["modernDuringFreshList"]),
        [
            "cancellationNotificationPosts",
            "errorCode",
            "localReason",
            "signal",
            "toolCalls",
        ]
    );
    assert_eq!(
        sorted_keys(&fixture["cases"]["modernDuringToolCall"]),
        [
            "attemptStatus",
            "cancellationNotificationPosts",
            "commitState",
            "errorCode",
            "failedAudits",
            "localReason",
            "signal",
            "successAudits",
        ]
    );
    assert_eq!(
        sorted_keys(&fixture["cases"]["legacyDuringToolCall"]),
        [
            "cancellationNotificationPosts",
            "errorCode",
            "reason",
            "requestIdRequired",
            "signal",
        ]
    );
    assert_eq!(fixture["cases"]["beforeAnyNetwork"]["acceptedSockets"], 0);
    assert_eq!(fixture["cases"]["modernDuringFreshList"]["toolCalls"], 0);
    assert_eq!(
        fixture["cases"]["modernDuringFreshList"]["signal"],
        "close_response_stream"
    );
    assert_eq!(
        fixture["cases"]["modernDuringToolCall"]["signal"],
        "close_response_stream"
    );
    assert_eq!(
        fixture["cases"]["legacyDuringToolCall"]["signal"],
        "notifications/cancelled"
    );
    assert_eq!(
        fixture["cases"]["modernDuringToolCall"]["commitState"],
        "unknown"
    );
}

#[tokio::test]
async fn cancellation_already_requested_prevents_every_rmcp_network_effect() {
    let fixture = cancellation_fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (cancel, cancellation) = tool_execution_cancellation();
    assert!(cancel.cancel(ToolCancellationReason::User));
    let result = client()
        .call_tool_bound_cancellable(
            &format!("http://{address}/mcp"),
            None,
            "must_not_send",
            openbot_domain::audit::hash::Sha256Digest::of(b"must-not-matter"),
            json!({}),
            cancellation,
        )
        .await;
    assert_eq!(
        result.as_ref().map_err(ToString::to_string),
        Err(fixture["cases"]["beforeAnyNetwork"]["errorCode"]
            .as_str()
            .unwrap()
            .to_owned())
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "pre-cancelled call must not open a socket"
    );
}

#[tokio::test]
async fn modern_fresh_list_cancellation_closes_response_stream_without_notification_post() {
    let fixture = cancellation_fixture();
    let (url, _received, _listed, traffic, probe, server) = spawn_server().await.unwrap();
    probe.block_list.store(true, Ordering::Release);
    let (cancel, cancellation) = tool_execution_cancellation();
    let call = tokio::spawn(async move {
        client()
            .call_tool_bound_cancellable(
                &url,
                None,
                "must_not_reach_call",
                openbot_domain::audit::hash::Sha256Digest::of(b"must-not-matter"),
                json!({}),
                cancellation,
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.list_started.notified(),
    )
    .await
    .expect("fresh tools/list starts");
    assert!(cancel.cancel(ToolCancellationReason::Deadline));
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.list_stopped.notified(),
    )
    .await
    .expect("list handler stops");
    assert_eq!(
        call.await.unwrap().as_ref().map_err(ToString::to_string),
        Err(fixture["cases"]["modernDuringFreshList"]["errorCode"]
            .as_str()
            .unwrap()
            .to_owned())
    );
    let notifications = probe.notifications.lock().unwrap().clone();
    assert!(
        notifications.is_empty(),
        "2026-07-28 Streamable HTTP forbids a cancelled notification POST"
    );
    assert_eq!(
        probe.protocol_versions.lock().unwrap().as_slice(),
        ["2026-07-28"]
    );
    let traffic = traffic.lock().unwrap().clone();
    assert!(traffic.iter().any(|entry| {
        entry.contains("mcp=server/discover") && entry.contains("version=2026-07-28")
    }));
    assert!(
        traffic.iter().any(|entry| {
            entry.contains("mcp=tools/list") && entry.contains("version=2026-07-28")
        })
    );
    assert!(
        !traffic
            .iter()
            .any(|entry| entry.contains("notifications/cancelled"))
    );
    assert_eq!(
        fixture["cases"]["modernDuringFreshList"]["signal"],
        "close_response_stream"
    );
    server.abort();
}

#[tokio::test]
async fn modern_tool_call_cancellation_closes_response_stream_without_notification_post() {
    let fixture = cancellation_fixture();
    let (url, _received, listed, traffic, probe, server) = spawn_server().await.unwrap();
    let schema = json!({"type":"object","properties":{}})
        .as_object()
        .cloned()
        .unwrap();
    let schema_hash = openbot_domain::audit::hash::Sha256Digest::of(
        &serde_json::to_vec(&Value::Object(schema.clone())).unwrap(),
    );
    listed.lock().unwrap().push(Tool::new(
        "wait_for_cancel",
        "Waits until the modern response stream is closed.",
        schema,
    ));
    let (cancel, cancellation) = tool_execution_cancellation();
    let call = tokio::spawn(async move {
        client()
            .call_tool_bound_cancellable(
                &url,
                None,
                "wait_for_cancel",
                schema_hash,
                json!({}),
                cancellation,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), probe.started.notified())
        .await
        .expect("modern tools/call starts");
    assert!(cancel.cancel(ToolCancellationReason::User));
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.handler_stopped.notified(),
    )
    .await
    .expect("modern call handler stops when its response stream closes");
    assert_eq!(call.await.unwrap(), Err(McpClientError::CancelledAfterCall));
    assert!(probe.notifications.lock().unwrap().is_empty());
    assert_eq!(
        probe.protocol_versions.lock().unwrap().as_slice(),
        ["2026-07-28", "2026-07-28"]
    );
    let traffic = traffic.lock().unwrap().clone();
    assert!(
        traffic.iter().any(|entry| {
            entry.contains("mcp=tools/call") && entry.contains("version=2026-07-28")
        })
    );
    assert!(
        !traffic
            .iter()
            .any(|entry| entry.contains("notifications/cancelled"))
    );
    assert_eq!(
        fixture["cases"]["modernDuringToolCall"]["signal"],
        "close_response_stream"
    );
    assert_eq!(
        fixture["cases"]["modernDuringToolCall"]["errorCode"],
        "mcp_cancelled_after_call"
    );
    server.abort();
}

#[tokio::test]
async fn legacy_auto_fallback_sends_cancelled_notification_with_exact_request_id() {
    let fixture = cancellation_fixture();
    let (url, _received, listed, traffic, probe, server) = spawn_legacy_server().await.unwrap();
    let schema = json!({"type":"object","properties":{}})
        .as_object()
        .cloned()
        .unwrap();
    let schema_hash = openbot_domain::audit::hash::Sha256Digest::of(
        &serde_json::to_vec(&Value::Object(schema.clone())).unwrap(),
    );
    listed.lock().unwrap().push(Tool::new(
        "wait_for_cancel",
        "Waits until the exact legacy request is cancelled.",
        schema,
    ));
    let (cancel, cancellation) = tool_execution_cancellation();
    let call = tokio::spawn(async move {
        client()
            .call_tool_bound_cancellable(
                &url,
                None,
                "wait_for_cancel",
                schema_hash,
                json!({}),
                cancellation,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), probe.started.notified())
        .await
        .expect("legacy tools/call starts after auto fallback");
    assert!(cancel.cancel(ToolCancellationReason::User));
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.notification_received.notified(),
    )
    .await
    .expect("legacy server receives cancelled notification");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        probe.handler_stopped.notified(),
    )
    .await
    .expect("legacy handler stops");
    assert_eq!(call.await.unwrap(), Err(McpClientError::CancelledAfterCall));
    let notifications = probe.notifications.lock().unwrap().clone();
    assert_eq!(notifications.len(), 1);
    assert!(!notifications[0]["requestId"].is_null());
    assert_eq!(notifications[0]["reason"], "run_cancelled");
    assert_eq!(
        probe.protocol_versions.lock().unwrap().as_slice(),
        ["2025-11-25", "2025-11-25"]
    );
    let traffic = traffic.lock().unwrap().clone();
    assert!(
        traffic
            .iter()
            .any(|entry| entry.contains("version=2025-11-25"))
    );
    assert_eq!(
        fixture["cases"]["legacyDuringToolCall"]["signal"],
        "notifications/cancelled"
    );
    server.abort();
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与本机 TLS：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn custom_admin_private_egress_is_db_bound_refreshes_and_retires_atomically() {
    let admin = harness::admin_config(
        "custom_admin_private_egress_is_db_bound_refreshes_and_retires_atomically",
    );
    harness::with_temp_database(&admin, "mcpadmin", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation)
                   VALUES('mcp-admin','mcp-admin@example.test',0);
                 INSERT INTO public.user_roles(user_id,role)
                   VALUES('mcp-admin','admin');
                 INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('mcp-holder','MCP Holder','remote_ag_ui','{}');
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at)
                   VALUES('mcp-holder','mcp-admin','MCP Holder','role','mcp-holder-seed','public',NULL);",
            )
            .await
            .map_err(|error| error.to_string())?;

            let (
                endpoint,
                address,
                root,
                _received,
                tls_errors,
                tls_traffic,
                tls_server,
                backend_server,
            ) = spawn_tls_server().await?;
            let direct_dialer = SafeDialer::with_extra_roots(
                EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                ),
                Arc::new(LocalResolver(address)),
                [root.clone()],
            )
            .map_err(|error| error.to_string())?;
            direct_dialer
                .validate_destination(
                    &url::Url::parse(&endpoint).map_err(|error| error.to_string())?,
                    SchemePolicy::HttpsOnly,
                )
                .await
                .map_err(|error| format!("direct destination control: {error:?}"))?;
            direct_dialer
                .execute(
                    SafeHttpRequest::get(
                        url::Url::parse(&endpoint).map_err(|error| error.to_string())?,
                        SchemePolicy::HttpsOnly,
                        SafeHttpBudget::new(64 * 1024, std::time::Duration::from_secs(2))
                            .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await
                .map_err(|error| format!("direct TLS HTTP control: {error:?}"))?;
            let direct_result = SafeRmcpClient::new(
                direct_dialer,
                SchemePolicy::HttpsOnly,
                Some(std::time::Duration::from_secs(2)),
            )
            .list_tools(&endpoint, None)
            .await;
            let direct_tools = match direct_result {
                Ok(tools) => tools,
                Err(error) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    return Err(format!(
                        "direct TLS RMCP control: {error:?}; server={:?}; traffic={:?}",
                        tls_errors.lock().unwrap(),
                        tls_traffic.lock().unwrap()
                    ));
                }
            };
            if direct_tools.len() != 6 {
                return Err(format!(
                    "direct TLS RMCP tool count: {}",
                    direct_tools.len()
                ));
            }
            let dialer = SafeDialer::with_extra_roots(
                EgressPolicy::default(),
                Arc::new(LocalResolver(address)),
                [root],
            )
            .map_err(|error| error.to_string())?;
            let rmcp = SafeRmcpClient::new(
                dialer.clone(),
                SchemePolicy::HttpsOnly,
                Some(std::time::Duration::from_secs(2)),
            );
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp, vec![0x91; 32])
                    .map_err(|error| error.to_string())?,
            );
            let vault = CredentialRecordVault::single_key(
                TenantId::new("mcp-admin-tenant"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x92; 32]).map_err(|error| error.to_string())?,
            );
            let credential_id = uuid::Uuid::now_v7();
            let encrypted = vault
                .seal(
                    &credential_id,
                    SecretKind::Mcp,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new("private-notes")),
                    &SecretBytes::new(b"deployment-bearer-canary".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp','private-notes',$2,'mcp-admin-test','{}')",
                &[&credential_id, &encrypted],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let broker = Arc::new(PostgresMcpCredentialBroker::new(
                pool.clone(),
                vault.clone(),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            ));
            let connections = PostgresMcpConnections::new(
                pool.clone(),
                vault.clone(),
                McpOAuthClient::new(dialer, SchemePolicy::HttpsOnly),
                catalog,
                DeploymentId::new("mcp-admin-deployment"),
                TenantId::new("mcp-admin-tenant"),
                vec![0x93; 32],
                vec![0x91; 32],
                None,
                None,
                SchemePolicy::HttpsOnly,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?
            .with_mcp_credentials(broker);
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("mcp-admin-deployment"),
                TenantId::new("mcp-admin-tenant"),
                ActorId::new("mcp-admin"),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::Admin])
            .build();
            let mut registration = McpCustomServerRegistration {
                id: "private-notes".to_owned(),
                title: "Private notes".to_owned(),
                url: endpoint.clone(),
                credential_id: Some(credential_id.to_string()),
                egress_allow_cidrs: Vec::new(),
            };
            let denied = connections
                .add_custom_server(&auth, &registration)
                .await
                .expect_err("private destination without explicit CIDR must fail closed");
            if denied.to_string() != "mcp_connection_unavailable" {
                return Err(format!("unexpected private-egress refusal: {denied}"));
            }
            let denied_page = connections
                .list_admin_page(&auth)
                .await
                .map_err(|error| format!("denied admin page: {error}"))?;
            if denied_page.servers.len() != 1
                || denied_page.servers[0].authentication
                    != openbot_contracts::mcp::McpAdminAuthentication::DeploymentBearer
                || denied_page.servers[0].last_error.as_deref() != Some("mcp_catalog_unavailable")
                || !denied_page.servers[0].tools.is_empty()
            {
                return Err(format!("failed refresh projection drift: {denied_page:?}"));
            }

            registration.egress_allow_cidrs = vec!["127.0.0.1/32".to_owned()];
            let added = connections
                .add_custom_server(&auth, &registration)
                .await
                .map_err(|error| format!("authorized custom add: {error}"))?;
            if added.catalog_generation != 1 || added.tool_count != 6 {
                return Err(format!("custom server refresh drift: {added:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(
                   kind,ref,agent_id,granted_by,state,catalog_generation,schema_hash,effect,
                   transport_fingerprint,credential_generation)
                 SELECT 'mcp','private-notes/search_issues','mcp-holder','mcp-admin','active',
                        s.catalog_generation,t.schema_hash,t.effect,
                        s.catalog_transport_fingerprint,coalesce(s.credential_generation,0)
                   FROM public.mcp_servers s JOIN public.mcp_tools t ON t.server_id=s.id
                  WHERE s.id='private-notes' AND t.name='search_issues'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let granted_page = connections
                .list_admin_page(&auth)
                .await
                .map_err(|error| format!("granted admin page: {error}"))?;
            let search = granted_page.servers[0]
                .tools
                .iter()
                .find(|tool| tool.name == "search_issues")
                .ok_or("search tool missing from admin page")?;
            if search.granted_to != ["mcp-holder"]
                || granted_page.bots_may_call_back
                || granted_page.catalogue.len() != 1
            {
                return Err(format!(
                    "admin page grant/catalogue drift: {granted_page:?}"
                ));
            }

            registration.egress_allow_cidrs =
                vec!["127.0.0.1/32".to_owned(), "10.0.0.0/8".to_owned()];
            let rotated_credential_id = uuid::Uuid::now_v7();
            let rotated_encrypted = vault
                .seal(
                    &rotated_credential_id,
                    SecretKind::Mcp,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new("private-notes")),
                    &SecretBytes::new(b"rotated-deployment-bearer".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp','private-notes',$2,'mcp-admin-rotated','{}')",
                &[&rotated_credential_id, &rotated_encrypted],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            registration.credential_id = Some(rotated_credential_id.to_string());
            let policy_changed = connections
                .add_custom_server(&auth, &registration)
                .await
                .map_err(|error| format!("egress policy update: {error}"))?;
            if policy_changed.catalog_generation != 2 || policy_changed.suspended_grants != 1 {
                return Err(format!(
                    "egress fingerprint did not suspend old grant: {policy_changed:?}"
                ));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let old_retired: bool = pg
                .query_one(
                    "SELECT revoked_at IS NOT NULL FROM public.credentials WHERE id=$1",
                    &[&credential_id],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !old_retired {
                return Err("replaced MCP credential remained active".to_owned());
            }
            drop(pg);
            let page = connections
                .list_admin_page(&auth)
                .await
                .map_err(|error| format!("suspended admin page: {error}"))?;
            if page.servers[0].egress_allow_cidrs != ["10.0.0.0/8", "127.0.0.1/32"]
                || page.servers[0]
                    .tools
                    .iter()
                    .any(|tool| !tool.granted_to.is_empty())
            {
                return Err(format!(
                    "canonical egress/suspension projection drift: {page:?}"
                ));
            }

            connections
                .remove_server(&auth, "private-notes")
                .await
                .map_err(|error| format!("server removal: {error}"))?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let counts = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.mcp_servers
                         WHERE id='private-notes') AS servers,
                       (SELECT count(*)::bigint FROM public.mcp_tools
                         WHERE server_id='private-notes') AS tools,
                       (SELECT count(*)::bigint FROM public.plugin_grants
                         WHERE ref='private-notes/search_issues') AS grants,
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE id IN ($1,$2) AND revoked_at IS NOT NULL) AS retired,
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE id=$2 AND metadata->>'revocation_status'='operator_required'
                           AND metadata ? 'operator_required_at'
                           AND metadata ? 'server_removal_revocation') AS operator_required,
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='configuration.changed'
                           AND target_type='mcp_server' AND target_id='private-notes'
                           AND row_hash IS NOT NULL) AS audits",
                    &[&credential_id, &rotated_credential_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let observed = (
                counts.try_get::<_, i64>("servers").unwrap_or(-1),
                counts.try_get::<_, i64>("tools").unwrap_or(-1),
                counts.try_get::<_, i64>("grants").unwrap_or(-1),
                counts.try_get::<_, i64>("retired").unwrap_or(-1),
                counts
                    .try_get::<_, i64>("operator_required")
                    .unwrap_or(-1),
                counts.try_get::<_, i64>("audits").unwrap_or(-1),
            );
            if observed != (0, 0, 0, 2, 1, 4) {
                return Err(format!("removal/audit closure drift: {observed:?}"));
            }
            tls_server.abort();
            backend_server.abort();
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[test]
fn pure_result_projection_preserves_whitespace_next_to_real_content() {
    let result = normalize_result(
        &[ContentBlock::text(" "), ContentBlock::text("real")],
        false,
    )
    .unwrap();
    assert!(result.text.contains("real"));
    assert!(!result.truncated);
    let exact = "x".repeat(MAX_MCP_RESULT_CHARS);
    let result = normalize_result(&[ContentBlock::text(exact.clone())], false).unwrap();
    assert_eq!(result.text, exact);
    assert!(!result.truncated);
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn catalog_generation_suspends_missing_and_changed_grants_without_auto_revival() {
    let admin = harness::admin_config(
        "catalog_generation_suspends_missing_and_changed_grants_without_auto_revival",
    );
    harness::with_temp_database(&admin, "mcpcatalog", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            let (url, _received, listed, _traffic, _cancellation, server) =
                spawn_server().await?;
            let search = RealMcpServer::tools().remove(0);
            let schema = Value::Object((*search.input_schema).clone());
            let schema_hash = openbot_domain::audit::hash::Sha256Digest::of(
                &serde_json::to_vec(&schema).map_err(|error| error.to_string())?,
            )
            .to_hex();
            pg.execute(
                "INSERT INTO public.users(id,email) VALUES('actor-a','actor@example.test')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.agents(id,name,type,configuration) VALUES
                   ('holder','Holder','remote_ag_ui','{}'),
                   ('stranger','Stranger','remote_ag_ui','{}')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,catalog_generation,catalog_hash,
                   catalog_transport_fingerprint,egress_allow_cidrs
                 ) VALUES('notes','Notes','notes',$1,'custom',0,repeat('0',64),repeat('0',64),
                          ARRAY['127.0.0.1/32'])",
                &[&url],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_tools(
                   server_id,name,description,input_schema,schema_hash,effect,catalog_generation,
                   first_seen_at,last_seen_at,available
                 ) VALUES('notes','search_issues','Find issues matching a query.',$1,$2,'read',0,
                          clock_timestamp(),clock_timestamp(),true)",
                &[&schema, &schema_hash],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id)
                   VALUES('mcp','notes/search_issues','holder')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let catalog = PostgresMcpCatalog::new(pool.clone(), client(), vec![0x99; 32])
                .map_err(|error| error.to_string())?;
            let first = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if first.generation.get() != 1 || first.suspended_grants != 0 {
                return Err(format!("first catalog refresh drift: {first:?}"));
            }
            let holder = catalog
                .granted_tools(
                    &openbot_contracts::ids::BotId::new("holder"),
                    &openbot_contracts::ids::ActorId::new("actor-a"),
                )
                .await
                .map_err(|error| error.to_string())?;
            if holder.len() != 1
                || holder[0].model_name != "mcp__notes__search_issues"
                || holder[0].input_schema["required"] != json!(["query"])
                || holder[0].effect != openbot_domain::tool::metadata::Effect::Read
            {
                return Err(format!("reviewed grant projection drift: {holder:?}"));
            }
            if !catalog
                .granted_tools(
                    &openbot_contracts::ids::BotId::new("stranger"),
                    &openbot_contracts::ids::ActorId::new("actor-a"),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err("Bot without grant received MCP tool".to_owned());
            }
            let second = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if second.generation.get() != 2 || second.suspended_grants != 0 {
                return Err(format!("unchanged refresh drift: {second:?}"));
            }

            listed
                .lock()
                .unwrap()
                .retain(|tool| tool.name != "search_issues");
            let missing = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if missing.generation.get() != 3 || missing.suspended_grants != 1 {
                return Err(format!("missing suspension drift: {missing:?}"));
            }
            listed.lock().unwrap().push(search.clone());
            let reappeared = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if reappeared.generation.get() != 4 || reappeared.suspended_grants != 0 {
                return Err(format!("reappearance drift: {reappeared:?}"));
            }
            if !catalog
                .granted_tools(
                    &openbot_contracts::ids::BotId::new("holder"),
                    &openbot_contracts::ids::ActorId::new("actor-a"),
                )
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err("suspended grant auto-revived".to_owned());
            }

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,effect=t.effect
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='notes/search_issues' AND g.agent_id='holder'
                   AND t.server_id='notes' AND t.name='search_issues'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let mut changed = search.clone();
            changed.input_schema = Arc::new(
                json!({"type":"object","properties":{"term":{"type":"string"}},"required":["term"]})
                    .as_object()
                    .cloned()
                    .unwrap(),
            );
            *listed.lock().unwrap() = vec![changed];
            let changed = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if changed.generation.get() != 5 || changed.suspended_grants != 1 {
                return Err(format!("schema-change suspension drift: {changed:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,effect=t.effect,
                   transport_fingerprint=s.catalog_transport_fingerprint
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='notes/search_issues' AND g.agent_id='holder'
                   AND t.server_id='notes' AND t.name='search_issues'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers SET vendor='notes-v2' WHERE id='notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            if !matches!(
                catalog
                    .granted_tools(
                        &openbot_contracts::ids::BotId::new("holder"),
                        &openbot_contracts::ids::ActorId::new("actor-a"),
                    )
                    .await,
                Err(openbot_infra::mcp_catalog::McpCatalogError::Corrupt {
                    field: "catalog_transport_fingerprint"
                })
            ) {
                return Err("transport changed before refresh but old grant remained visible".to_owned());
            }
            let transport_changed = catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            if transport_changed.generation.get() != 6
                || transport_changed.suspended_grants != 1
            {
                return Err(format!(
                    "transport/vendor suspension drift: {transport_changed:?}"
                ));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let audit_count: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type='mcp.tool_suspended_missing'
                        AND target_id='notes/search_issues'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let state: String = pg
                .query_one(
                    "SELECT state FROM public.plugin_grants
                      WHERE kind='mcp' AND ref='notes/search_issues' AND agent_id='holder'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if audit_count != 3 || state != "suspended_missing" {
                return Err(format!(
                    "suspension audit/state drift: {audit_count}/{state}"
                ));
            }
            server.abort();
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
async fn server_side_tools_cover_no_grant_vendor_schema_real_rmcp_audit_and_policy_refusal() {
    let admin = harness::admin_config(
        "server_side_tools_cover_no_grant_vendor_schema_real_rmcp_audit_and_policy_refusal",
    );
    harness::with_temp_database(&admin, "mcptoolplane", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let cancellation_contract = cancellation_fixture();
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            let (url, received, listed, traffic, cancellation, server) =
                spawn_server().await?;
            pg.execute(
                "INSERT INTO public.users(id,email,auth_generation)
                   VALUES('actor-mcp','actor-mcp@example.test',0)",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.user_roles(user_id,role) VALUES('actor-mcp','user')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                   VALUES('tenant-mcp','/fixture',repeat('a',64));
                 INSERT INTO public.agents(id,name,type,configuration,package_id)
                   SELECT 'holder-mcp','Holder MCP','built_in',
                          '{\"systemPrompt\":\"Use granted tools.\",\"providerSource\":\"package\"}',id
                     FROM public.deployment_packages WHERE tenant_id='tenant-mcp';
                 INSERT INTO public.agents(id,name,type,configuration,package_id)
                   SELECT 'stranger-mcp','Stranger MCP','built_in',
                          '{\"systemPrompt\":\"No tools.\",\"providerSource\":\"package\"}',id
                     FROM public.deployment_packages WHERE tenant_id='tenant-mcp';
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                 ) VALUES
                   ('holder-mcp',NULL,'Holder MCP','role','seed-a','public',NULL),
                   ('stranger-mcp',NULL,'Stranger MCP','role','seed-b','public',NULL);
                 INSERT INTO public.threads(
                   thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                   next_message_seq,next_event_seq,created_at,updated_at
                 ) VALUES(
                   'thread-mcp','tenant-mcp','deployment-mcp','actor-mcp','direct_bot',
                   'holder-mcp','active',1,0,clock_timestamp(),clock_timestamp()
                 );
                 INSERT INTO public.thread_memberships(thread_id,user_id)
                   VALUES('thread-mcp','actor-mcp');
                 INSERT INTO public.runs(
                   run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                   next_event_seq,created_at,started_at
                 ) VALUES(
                   'run-mcp','thread-mcp','holder-mcp','actor-mcp',true,'running',1,
                   0,clock_timestamp(),clock_timestamp()
                 );
                 INSERT INTO public.thread_leases(
                   thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                 ) VALUES(
                   'thread-mcp','runtime-mcp',1,clock_timestamp(),
                   clock_timestamp()+interval '10 minutes',clock_timestamp()
                 );
                 INSERT INTO public.messages(
                   message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                 ) VALUES(
                   'message-mcp','thread-mcp',0,'user','{\"text\":\"Search invoices.\"}',
                   'Search invoices.','run-mcp','actor-mcp',clock_timestamp()
                 );",
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,egress_allow_cidrs)
                   VALUES('notes','Notes','notes',$1,'custom',ARRAY['127.0.0.1/32'])",
                &[&url],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','notes/search_issues','holder-mcp','admin-mcp')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let rmcp = client();
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp.clone(), vec![0x71; 32])
                    .map_err(|error| error.to_string())?,
            );
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_tools SET effect='read'
                   WHERE server_id='notes' AND name='search_issues'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,
                   effect=t.effect,transport_fingerprint=s.catalog_transport_fingerprint,
                   updated_at=clock_timestamp()
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='notes/search_issues'
                   AND g.agent_id='holder-mcp' AND t.server_id='notes'
                   AND t.name='search_issues'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let holder = BotId::new("holder-mcp");
            let stranger = BotId::new("stranger-mcp");
            let actor = ActorId::new("actor-mcp");
            if !catalog
                .granted_tools(&stranger, &actor)
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err("Bot with no grant was offered an MCP tool".to_owned());
            }
            let granted = catalog
                .granted_tools(&holder, &actor)
                .await
                .map_err(|error| error.to_string())?;
            if granted.len() != 1
                || !catalog
                    .validate_arguments(&granted[0], &json!({"query":"invoices"}))
                    .await
                    .map_err(|error| error.to_string())?
                || catalog
                    .validate_arguments(&granted[0], &json!({}))
                    .await
                    .map_err(|error| error.to_string())?
            {
                return Err(format!("vendor schema projection/validation drift: {granted:?}"));
            }

            let lease = RunExecutionLease::new(
                RunId::new("run-mcp"),
                ThreadId::new("thread-mcp"),
                holder.clone(),
                actor.clone(),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let context = PostgresAgentContextSource::new(
                pool.clone(),
                DeploymentId::new("deployment-mcp"),
                TenantId::new("tenant-mcp"),
                Some(128),
            )
            .map_err(|error| error.to_string())?
            .with_mcp_catalog(catalog.clone());
            let request = context
                .load(&lease)
                .await
                .map_err(|error| error.to_string())?;
            if request.tools.len() != 1
                || request.tools[0].name != "mcp__notes__search_issues"
                || request.tools[0].description != "Find issues matching a query."
                || request.tools[0].input_schema != granted[0].input_schema
                || !request.messages[0]
                    .content
                    .contains("- notes: search_issues")
            {
                return Err(format!("provider tool projection drift: {:?}", request.tools));
            }

            let policy = PolicyStore::postgres(pool.clone(), None);
            policy.load().await.map_err(|error| error.to_string())?;
            policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: Vec::new(),
                        allow: vec!["true".to_owned()],
                    },
                    Some("actor-mcp"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let approvals = Arc::new(
                PostgresToolApprovalCoordinator::new(
                    pool.clone(),
                    DeploymentId::new("deployment-mcp"),
                    TenantId::new("tenant-mcp"),
                    vec![0x71; 32],
                    openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
                )
                .map_err(|error| error.to_string())?,
            );
            let memory = PostgresMemoryAdministration::new(pool.clone());
            let tool_cancellations = Arc::new(ToolCancellationRegistry::default());
            let control = PostgresBuiltInToolControlPlane::new(
                pool.clone(),
                DeploymentId::new("deployment-mcp"),
                TenantId::new("tenant-mcp"),
                policy.clone(),
                Arc::new(memory.clone()),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .with_mcp(catalog.clone(), rmcp)
            .with_tool_cancellations(tool_cancellations.clone())
            .with_tool_approvals(approvals.clone());
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policy.clone())
                    .with_tools(
                        control,
                        PostgresToolJournal::new(pool.clone(), vec![0x71; 32])
                            .map_err(|error| error.to_string())?,
                    )
                    .with_memory(memory)
                    .with_tool_approvals(approvals.clone()),
            );
            let gateway = Arc::new(
                AuthorizedAgentToolGateway::with_sequence_and_cancellations(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    DeploymentId::new("deployment-mcp"),
                    TenantId::new("tenant-mcp"),
                    false,
                )),
                Arc::new(PostgresAgentToolSequence::new(pool.clone())),
                tool_cancellations.clone(),
            ));
            let reply = gateway
                .invoke(
                    &lease,
                    "provider-mcp-search-1",
                    "mcp__notes__search_issues",
                    json!({"query":"invoices"}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if reply.error_code().is_some()
                || !reply.content().contains("Found 2 issues for invoices")
                || received.lock().unwrap().as_slice() != [json!({"query":"invoices"})]
            {
                return Err(format!("real governed MCP call drift: {reply:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let audit = pg
                .query_one(
                    "SELECT actor_user_id,payload->>'bot',
                            (SELECT next_tool_call_seq FROM public.runs WHERE run_id='run-mcp')
                       FROM public.audit_events
                      WHERE event_type='mcp.call_succeeded'
                        AND target_id='notes/search_issues'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let audit_actor: Option<String> =
                audit.try_get(0).map_err(|error| error.to_string())?;
            let audit_bot: Option<String> =
                audit.try_get(1).map_err(|error| error.to_string())?;
            let next_sequence: Option<i64> =
                audit.try_get(2).map_err(|error| error.to_string())?;
            if audit_actor.as_deref() != Some("actor-mcp")
                || audit_bot.as_deref() != Some("holder-mcp")
                || next_sequence != Some(1)
            {
                return Err(format!(
                    "MCP audit/sequence drift: {audit_actor:?}/{audit_bot:?}/{next_sequence:?}"
                ));
            }
            drop(pg);

            listed.lock().unwrap().push(Tool::new(
                "wait_for_cancel",
                "Waits until the exact MCP request is cancelled.",
                {
                    json!({"type":"object","properties":{}})
                        .as_object()
                        .cloned()
                        .unwrap()
                },
            ));
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_tools SET effect='read'
                   WHERE server_id='notes' AND name='wait_for_cancel'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','notes/wait_for_cancel','holder-mcp','admin-mcp')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,
                   effect=t.effect,transport_fingerprint=s.catalog_transport_fingerprint,
                   updated_at=clock_timestamp()
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='notes/wait_for_cancel'
                   AND g.agent_id='holder-mcp' AND t.server_id='notes'
                   AND t.name='wait_for_cancel'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let (cancel_handle, cancellation_receiver) = tool_execution_cancellation();
            let traffic_before_cancel = traffic.lock().unwrap().len();
            let cancelled_call = {
                let gateway = gateway.clone();
                let lease = lease.clone();
                tokio::spawn(async move {
                    gateway
                        .invoke_cancellable(
                            &lease,
                            "provider-mcp-protocol-cancel",
                            "mcp__notes__wait_for_cancel",
                            json!({}),
                            cancellation_receiver,
                        )
                        .await
                })
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                cancellation.started.notified(),
            )
            .await
            .map_err(|_| "RMCP cancellation tool never started".to_owned())?;
            if !cancel_handle.cancel(ToolCancellationReason::User) {
                return Err("first tool cancellation signal was not accepted".to_owned());
            }
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                cancellation.handler_stopped.notified(),
            )
            .await
            .map_err(|_| "server tool handler did not stop after protocol cancellation".to_owned())?;
            let cancelled_result = cancelled_call
                .await
                .map_err(|error| error.to_string())?;
            if cancelled_result != Err(openbot_agent::AgentToolInvokeError::ReconciliationRequired)
            {
                return Err(format!(
                    "cancelled MCP result was not reconciliation: {cancelled_result:?}"
                ));
            }
            let notifications = cancellation.notifications.lock().unwrap().clone();
            let cancellation_traffic = traffic.lock().unwrap()[traffic_before_cancel..].to_vec();
            if !notifications.is_empty()
                || !cancellation
                    .protocol_versions
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|version| version == "2026-07-28")
                || cancellation_traffic
                    .iter()
                    .any(|entry| entry.contains("notifications/cancelled"))
                || !cancellation_traffic
                    .iter()
                    .any(|entry| entry.contains("mcp=tools/call")
                        && entry.contains("version=2026-07-28"))
            {
                return Err(format!(
                    "modern MCP stream-close cancellation drifted: notifications={notifications:?}; traffic={cancellation_traffic:?}"
                ));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let cancelled_evidence = pg
                .query_one(
                    "SELECT tc.tool_call_id,ta.status,ta.commit_state,ta.error_code,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.call_failed'
                                AND target_id='notes/wait_for_cancel'
                                AND payload->>'error_code'='mcp_cancelled_after_call'),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.call_succeeded'
                                AND target_id='notes/wait_for_cancel')
                       FROM public.tool_calls tc
                       JOIN public.tool_attempts ta ON ta.tool_call_id=tc.tool_call_id
                      WHERE tc.run_id='run-mcp'
                        AND tc.tool_name='mcp__notes__wait_for_cancel'
                      ORDER BY tc.call_seq DESC LIMIT 1",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let cancelled_call_id: String = cancelled_evidence
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let cancelled_status: String = cancelled_evidence
                .try_get(1)
                .map_err(|error| error.to_string())?;
            let cancelled_commit: Option<String> = cancelled_evidence
                .try_get(2)
                .map_err(|error| error.to_string())?;
            let cancelled_code: Option<String> = cancelled_evidence
                .try_get(3)
                .map_err(|error| error.to_string())?;
            let failed_audits: i64 = cancelled_evidence
                .try_get(4)
                .map_err(|error| error.to_string())?;
            let false_success_audits: i64 = cancelled_evidence
                .try_get(5)
                .map_err(|error| error.to_string())?;
            if cancelled_status
                != cancellation_contract["cases"]["modernDuringToolCall"]["attemptStatus"]
                    .as_str()
                    .unwrap()
                || cancelled_commit.as_deref()
                    != cancellation_contract["cases"]["modernDuringToolCall"]["commitState"]
                        .as_str()
                || cancelled_code.as_deref()
                    != cancellation_contract["cases"]["modernDuringToolCall"]["errorCode"].as_str()
                || failed_audits
                    != cancellation_contract["cases"]["modernDuringToolCall"]["failedAudits"]
                        .as_i64()
                        .unwrap()
                || false_success_audits
                    != cancellation_contract["cases"]["modernDuringToolCall"]["successAudits"]
                        .as_i64()
                        .unwrap()
                || tool_cancellations
                    .cancellation_for(&ToolCallId::new(cancelled_call_id))
                    .is_some()
            {
                return Err(format!(
                    "cancelled MCP durable evidence drifted: {cancelled_status}/{cancelled_commit:?}/{cancelled_code:?}/{failed_audits}/{false_success_audits}"
                ));
            }
            drop(pg);

            let secret_refused = gateway
                .invoke(
                    &lease,
                    "provider-mcp-search-secret",
                    "mcp__notes__search_issues",
                    json!({"query":"OPENBOT_SECRET_CANARY-do-not-send"}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if secret_refused.error_code() != Some("policy_refused")
                || !secret_refused.content().starts_with("Refused.")
                || received.lock().unwrap().len() != 1
            {
                return Err(format!(
                    "content-governance refusal drift: {secret_refused:?}"
                ));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let secret_audit: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type='mcp.call_rejected'
                        AND target_id='notes/search_issues'
                        AND payload->>'error_code'='content_secret_blocked'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if secret_audit != 1 {
                return Err(format!("secret refusal audit drift: {secret_audit}"));
            }
            drop(pg);

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_tools SET effect='read'
                   WHERE server_id='notes' AND name='always_fails'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','notes/always_fails','holder-mcp','admin-mcp')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let vendor_failed = gateway
                .invoke(
                    &lease,
                    "provider-mcp-vendor-failed",
                    "mcp__notes__always_fails",
                    json!({}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if vendor_failed.error_code() != Some("mcp_vendor_error")
                || !vendor_failed
                    .content()
                    .contains("The vendor reported an error: vendor said no")
                || received.lock().unwrap().len() != 1
            {
                return Err(format!("vendor failure projection drift: {vendor_failed:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let failed_audit: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type='mcp.call_failed'
                        AND target_id='notes/always_fails'
                        AND payload->>'bot'='holder-mcp'
                        AND payload->>'error_code'='mcp_vendor_error'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if failed_audit != 1 {
                return Err(format!("vendor failure audit drift: {failed_audit}"));
            }
            drop(pg);

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','notes/long_answer','holder-mcp','admin-mcp')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            catalog
                .refresh("notes", None)
                .await
                .map_err(|error| error.to_string())?;
            let acting_waiter = {
                let gateway = gateway.clone();
                let lease = lease.clone();
                tokio::spawn(async move {
                    gateway
                        .invoke(
                            &lease,
                            "provider-mcp-approved",
                            "mcp__notes__long_answer",
                            json!({}),
                        )
                        .await
                })
            };
            let approval_auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("deployment-mcp"),
                TenantId::new("tenant-mcp"),
                ActorId::new("actor-mcp"),
                AuthGeneration::new(0),
                false,
            )
            .with_role(Role::User)
            .build();
            let pending = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    let page = approvals
                        .list_pending(&approval_auth)
                        .await
                        .map_err(|error| error.to_string())?;
                    if let Some(pending) = page.approvals.into_iter().next() {
                        return Ok::<_, String>(pending);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "acting approval did not become pending".to_owned())??;
            if pending.tool_name != "mcp__notes__long_answer"
                || pending.target_id != "notes/long_answer"
                || pending.effect != openbot_contracts::tool::ToolApprovalEffect::Execute
                || pending.arguments_summary != json!({})
            {
                return Err(format!("acting approval presentation drift: {pending:?}"));
            }
            approvals
                .decide(
                    &approval_auth,
                    &pending.approval_id,
                    ToolApprovalDecision::Grant,
                )
                .await
                .map_err(|error| error.to_string())?;
            let approved = acting_waiter
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            if approved.error_code().is_some()
                || !approved.content().contains("[truncated:")
                || received.lock().unwrap().len() != 2
            {
                return Err(format!("approved acting MCP call drift: {approved:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let approval_evidence = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_requested'
                           AND target_id=$1),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_granted'
                           AND target_id=$1),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.call_succeeded'
                           AND target_id='notes/long_answer'),
                       (SELECT count(*)::bigint FROM public.tool_calls
                         WHERE run_id='run-mcp' AND tool_name='mcp__notes__long_answer'),
                       (SELECT approval_id FROM public.tool_calls
                         WHERE run_id='run-mcp' AND tool_name='mcp__notes__long_answer'),
                       (SELECT payload->>'approval_id' FROM public.audit_events
                         WHERE event_type='mcp.call_succeeded'
                           AND target_id='notes/long_answer')",
                    &[&pending.approval_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let requested_audit: i64 = approval_evidence
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let granted_audit: i64 = approval_evidence
                .try_get(1)
                .map_err(|error| error.to_string())?;
            let succeeded_audit: i64 = approval_evidence
                .try_get(2)
                .map_err(|error| error.to_string())?;
            let acting_decisions: i64 = approval_evidence
                .try_get(3)
                .map_err(|error| error.to_string())?;
            let decision_approval: Option<String> = approval_evidence
                .try_get(4)
                .map_err(|error| error.to_string())?;
            let audit_approval: Option<String> = approval_evidence
                .try_get(5)
                .map_err(|error| error.to_string())?;
            if requested_audit != 1
                || granted_audit != 1
                || succeeded_audit != 1
                || acting_decisions != 1
                || decision_approval.as_deref() != Some(pending.approval_id.as_str())
                || audit_approval.as_deref() != Some(pending.approval_id.as_str())
            {
                return Err(format!(
                    "acting approval boundary drift: {requested_audit}/{granted_audit}/{succeeded_audit}/{acting_decisions}/{decision_approval:?}/{audit_approval:?}"
                ));
            }
            drop(pg);

            let denied_waiter = {
                let gateway = gateway.clone();
                let lease = lease.clone();
                tokio::spawn(async move {
                    gateway
                        .invoke(
                            &lease,
                            "provider-mcp-denied",
                            "mcp__notes__long_answer",
                            json!({}),
                        )
                        .await
                })
            };
            let denied_pending = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    let page = approvals
                        .list_pending(&approval_auth)
                        .await
                        .map_err(|error| error.to_string())?;
                    if let Some(pending) = page.approvals.into_iter().next() {
                        return Ok::<_, String>(pending);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "denial approval did not become pending".to_owned())??;
            approvals
                .decide(
                    &approval_auth,
                    &denied_pending.approval_id,
                    ToolApprovalDecision::Deny,
                )
                .await
                .map_err(|error| error.to_string())?;
            let denied = denied_waiter
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            if denied.error_code() != Some("policy_refused")
                || !denied.content().starts_with("Refused.")
                || received.lock().unwrap().len() != 2
            {
                return Err(format!("denied acting MCP call drift: {denied:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let denial_evidence = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='tool.approval_denied' AND target_id=$1),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.call_rejected'
                           AND target_id='notes/long_answer'
                           AND payload->>'error_code'='approval_denied'),
                       (SELECT count(*)::bigint FROM public.tool_calls
                         WHERE run_id='run-mcp' AND tool_name='mcp__notes__long_answer')",
                    &[&denied_pending.approval_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let denied_audit: i64 = denial_evidence
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let rejected_audit: i64 = denial_evidence
                .try_get(1)
                .map_err(|error| error.to_string())?;
            let acting_decisions: i64 = denial_evidence
                .try_get(2)
                .map_err(|error| error.to_string())?;
            if denied_audit != 1 || rejected_audit != 1 || acting_decisions != 1 {
                return Err(format!(
                    "acting denial boundary drift: {denied_audit}/{rejected_audit}/{acting_decisions}"
                ));
            }
            drop(pg);

            policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: vec![r#"mcp.server == "notes""#.to_owned()],
                        allow: vec!["true".to_owned()],
                    },
                    Some("actor-mcp"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let refused = gateway
                .invoke(
                    &lease,
                    "provider-mcp-policy-refused",
                    "mcp__notes__search_issues",
                    json!({"query":"must-not-send"}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if refused.error_code() != Some("policy_refused")
                || !refused.content().starts_with("Refused.")
                || received.lock().unwrap().len() != 2
            {
                return Err(format!("policy refusal projection drift: {refused:?}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let rejected: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events
                      WHERE event_type='mcp.call_rejected'
                        AND target_id='notes/search_issues'
                        AND payload->>'bot'='holder-mcp'
                        AND payload->>'error_code'='policy_refused'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let sequence: Option<i64> = pg
                .query_one(
                    "SELECT next_tool_call_seq FROM public.runs WHERE run_id='run-mcp'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if rejected != 1 || sequence != Some(7) {
                return Err(format!(
                    "policy audit/durable sequence drift: {rejected}/{sequence:?}"
                ));
            }
            drop(pg);
            let first_replica = PostgresAgentToolSequence::new(pool.clone());
            let second_replica = PostgresAgentToolSequence::new(pool.clone());
            let sequence_run = RunId::new("run-mcp");
            let (left, right) = tokio::join!(
                first_replica.next(&sequence_run),
                second_replica.next(&sequence_run),
            );
            let mut allocated = [
                left.map_err(|error| error.to_string())?,
                right.map_err(|error| error.to_string())?,
            ];
            allocated.sort_unstable();
            let after_reconstruction = PostgresAgentToolSequence::new(pool.clone())
                .next(&sequence_run)
                .await
                .map_err(|error| error.to_string())?;
            if allocated != [7, 8] || after_reconstruction != 9 {
                return Err(format!(
                    "cross-replica sequence allocation drift: {allocated:?}/{after_reconstruction}"
                ));
            }
            server.abort();
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
