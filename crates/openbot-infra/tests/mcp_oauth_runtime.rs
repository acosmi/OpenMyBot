//! MCP OAuth production slice: PRM/AS discovery, RFC 8707 refresh rotation, actor binding and one
//! controlled RMCP 401 retry against real loopback HTTP plus PostgreSQL 17.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openbot_agent::{AgentToolInvoker, AuthorizedAgentToolGateway};
use openbot_application::{
    ApplicationService, McpConnectionAdministration, McpConnectionError, McpOAuthCallback,
    McpOAuthCallbackInput, OpenBotApplication, RunExecutionLease,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::mcp::{
    McpOAuthClientAuthMethod, McpOAuthClientRegistration, McpOAuthReturnTo,
    McpVendorRevocationStatus,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::thread::FencingToken;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::agent_tools::{
    PostgresAgentAuthorizationSource, PostgresAgentToolSequence, PostgresBuiltInToolControlPlane,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::mcp::{McpClientError, SafeRmcpClient};
use openbot_infra::mcp_catalog::{McpAuthentication, PostgresMcpCatalog};
use openbot_infra::mcp_connections::PostgresMcpConnections;
use openbot_infra::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use openbot_infra::mcp_oauth::McpOAuthClient;
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::vault::CredentialRecordVault;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use sha2::Digest as _;

const ACTOR: &str = "oauth-owner";
const OTHER: &str = "oauth-other";
const BOT: &str = "oauth-bot";
const SERVER: &str = "oauth-notes";
const CLIENT_ID: &str = "oauth-client-id";
const CLIENT_SECRET: &str = "oauth-client-secret";
const SCOPE: &str = "notes:read";
const AUDIT_KEY: &[u8] = b"mcp-oauth-runtime-audit-key-at-least-32";

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback sockets; set OPENBOT_TEST_DATABASE_URL"]
async fn admin_credential_retirement_keeps_exact_oauth_context_through_retry_replacement_and_server_removal()
 {
    use openbot_application::credential_admin::CredentialAdministration;
    use openbot_contracts::credential_admin::CredentialExternalRevocation;
    use openbot_infra::credential_admin::PostgresCredentialAdministration;
    let config = harness::admin_config("admin_credential_oauth_retirement");
    harness::with_temp_database(&config, "credoauth", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            let mut pg = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&pg).await.map_err(|e| e.to_string())?;
            native::apply(&mut pg).await.map_err(|e| e.to_string())?;
            pg.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('credential-admin','admin@example.test',0),('token-one','one@example.test',0),('token-two','two@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('credential-admin','admin');").await.map_err(|e| e.to_string())?;
            let spawned = spawn_oauth_mcp().await?;
            let vault = CredentialRecordVault::single_key(TenantId::new("admin-token-tenant"), KeyVersion::new(1), WrappingKey::from_bytes(vec![0x59;32]).map_err(|e| e.to_string())?);
            let client_id = uuid::Uuid::now_v7();
            let client_body = serde_json::to_vec(&serde_json::json!({"clientId":CLIENT_ID,"clientSecret":CLIENT_SECRET,"issuer":spawned.state.issuer.as_ref(),"tokenEndpointAuthMethod":"client_secret_basic"})).unwrap();
            let cipher = vault.seal(&client_id,SecretKind::McpOauthClient,SecretPrincipal::Deployment,SecretPrincipal::Service(ServiceId::new(SERVER)),&SecretBytes::new(client_body)).unwrap();
            pg.execute("INSERT INTO public.credentials(id,kind,provider,key_id,encrypted_value,metadata) VALUES($1,'mcp_oauth_client',$2,'oauth-client',$3,'{}')",&[&client_id,&SERVER,&cipher]).await.map_err(|e| format!("{e:?}"))?;
            pg.execute("INSERT INTO public.mcp_servers(id,title,vendor,url,provenance,transport,credential_id,credential_generation,egress_allow_cidrs) VALUES($1,'OAuth Notes','test',$2,'custom','mcp',$3,0,ARRAY['127.0.0.1/32'])",&[&SERVER,&spawned.resource.as_str(),&client_id]).await.map_err(|e| format!("{e:?}"))?;
            let mut tokens = Vec::new();
            for owner in ["token-one","token-two"] {
                let id = uuid::Uuid::now_v7();
                let encrypted = vault.seal(&id,SecretKind::McpUserToken,SecretPrincipal::Actor(ActorId::new(owner)),SecretPrincipal::Service(ServiceId::new(SERVER)),&SecretBytes::new(format!("refresh-{owner}").into_bytes())).unwrap();
                pg.execute("INSERT INTO public.credentials(id,kind,provider,key_id,encrypted_value,metadata) VALUES($1,'mcp_user_token',$2,$3,$4,'{\"revocation_status\":\"active\"}')",&[&id,&SERVER,&owner,&encrypted]).await.map_err(|e| format!("{e:?}"))?;
                pg.execute("INSERT INTO public.mcp_user_credentials(server_id,user_id,credential_id,scope) VALUES($1,$2,$3,$4)",&[&SERVER,&owner,&id,&SCOPE]).await.map_err(|e| format!("{e:?}"))?;
                tokens.push(id);
            }
            drop(pg);
            let catalog = Arc::new(PostgresMcpCatalog::new(pool.clone(),rmcp_client(),AUDIT_KEY.to_vec()).map_err(|e| e.to_string())?);
            let connections = Arc::new(PostgresMcpConnections::new(pool.clone(),vault.clone(),McpOAuthClient::new(SafeDialer::new(EgressPolicy::default()),SchemePolicy::HttpOrHttps),catalog,DeploymentId::new("admin-token-deployment"),TenantId::new("admin-token-tenant"),vec![0x5a;32],AUDIT_KEY.to_vec(),None,None,SchemePolicy::HttpOrHttps, openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).map_err(|e| e.to_string())?);
            let admin = PostgresCredentialAdministration::new(pool.clone(),vault,DeploymentId::new("admin-token-deployment"),TenantId::new("admin-token-tenant"),SecretBytes::new(AUDIT_KEY.to_vec()),connections.clone()).map_err(|e| e.to_string())?;
            let auth = AuthContextBuilder::from_verified_session(DeploymentId::new("admin-token-deployment"),TenantId::new("admin-token-tenant"),ActorId::new("credential-admin"),AuthGeneration::new(0),false).with_roles([Role::Admin]).build();
            let retired = admin.revoke(&auth,&tokens[0].to_string()).await.map_err(|e| e.to_string())?;
            assert_eq!(retired.external_revocation,CredentialExternalRevocation::Pending);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.mcp_user_credentials",&[]).await.map_err(|e| e.to_string())?.get::<_,i64>(0),1);
            pg.execute("UPDATE public.credentials SET updated_at=clock_timestamp()-interval '1 minute' WHERE id=$1",&[&tokens[0]]).await.map_err(|e| e.to_string())?;drop(pg);
            spawned.state.revoke_failure.store(true,Ordering::SeqCst);
            let failed=connections.reconcile_pending_revocations().await.map_err(|e| e.to_string())?;
            assert_eq!((failed.attempted,failed.pending,failed.revoked),(1,1,0));
            spawned.state.revoke_failure.store(false,Ordering::SeqCst);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            pg.execute("UPDATE public.credentials SET updated_at=clock_timestamp()-interval '1 minute' WHERE id=$1",&[&tokens[0]]).await.map_err(|e| e.to_string())?;drop(pg);
            assert_eq!(connections.reconcile_pending_revocations().await.map_err(|e| e.to_string())?.revoked,1);

            // Retiring the deployment client locally retires the remaining user token too.
            assert_eq!(admin.revoke(&auth,&client_id.to_string()).await.map_err(|e| e.to_string())?.external_revocation,CredentialExternalRevocation::OperatorRequired);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.mcp_user_credentials",&[]).await.map_err(|e| e.to_string())?.get::<_,i64>(0),0);
            drop(pg);
            connections.register_oauth_client(&auth,SERVER,&McpOAuthClientRegistration::new("different-client".to_owned(),"different-secret".to_owned(),spawned.state.issuer.to_string(),McpOAuthClientAuthMethod::ClientSecretBasic,None).unwrap()).await.map_err(|e| e.to_string())?;
            connections.remove_server(&auth,SERVER).await.map_err(|e| e.to_string())?;
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            pg.execute("UPDATE public.credentials SET updated_at=clock_timestamp()-interval '1 minute' WHERE id=$1",&[&tokens[1]]).await.map_err(|e| e.to_string())?;drop(pg);
            let last=connections.reconcile_pending_revocations().await.map_err(|e| e.to_string())?;
            assert_eq!((last.attempted,last.revoked,last.pending),(1,1,0));
            assert_eq!(spawned.state.revoke_calls.load(Ordering::SeqCst),3);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            let row=pg.query_one("SELECT metadata->>'revocation_status', metadata ? 'credential_revocation' FROM public.credentials WHERE id=$1",&[&tokens[1]]).await.map_err(|e| e.to_string())?;
            assert_eq!(row.get::<_,String>(0),"revoked"); assert!(!row.get::<_,bool>(1));
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.audit_events WHERE event_type='credential.revoked' AND actor_user_id='credential-admin'",&[]).await.map_err(|e| e.to_string())?.get::<_,i64>(0),2);
            pg.execute("UPDATE public.credentials SET metadata=metadata || '{\"revocation_status\":\"pending\",\"revocation_reason\":\"credential_revoked\",\"credential_revocation\":{\"version\":999}}', updated_at=clock_timestamp()-interval '1 minute' WHERE id=$1", &[&tokens[0]]).await.map_err(|e| e.to_string())?;
            drop(pg);
            let corrupted=connections.reconcile_pending_revocations().await.map_err(|e| e.to_string())?;
            assert_eq!((corrupted.attempted,corrupted.operator_required),(1,1));
            assert_eq!(spawned.state.revoke_calls.load(Ordering::SeqCst),3);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.credentials WHERE kind='mcp_oauth_client' AND metadata ? 'automatic_user_token_revocation_failed_at'",&[]).await.map_err(|e| e.to_string())?.get::<_,i64>(0),0);
            spawned.handle.abort();
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[derive(Clone)]
struct OAuthFixtureState {
    resource: Arc<str>,
    issuer: Arc<str>,
    current_refresh: Arc<Mutex<String>>,
    token_calls: Arc<AtomicUsize>,
    token_observations: Arc<Mutex<Vec<TokenObservation>>>,
    rejected_access_three: Arc<AtomicUsize>,
    code_calls: Arc<AtomicUsize>,
    expected_challenge: Arc<Mutex<Option<String>>>,
    revoke_calls: Arc<AtomicUsize>,
    revoke_failure: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct TokenObservation {
    authorization: String,
    form: BTreeMap<String, String>,
}

async fn protected_resource_metadata(State(state): State<OAuthFixtureState>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "resource":state.resource.as_ref(),
        "authorization_servers":[state.issuer.as_ref()],
        "scopes_supported":[SCOPE]
    }))
}

async fn authorization_server_metadata(
    State(state): State<OAuthFixtureState>,
) -> impl IntoResponse {
    let base = state
        .resource
        .strip_suffix("/mcp")
        .expect("fixture resource suffix");
    axum::Json(serde_json::json!({
        "issuer":state.issuer.as_ref(),
        "authorization_endpoint":format!("{base}/oauth/authorize"),
        "token_endpoint":format!("{base}/oauth/token"),
        "revocation_endpoint":format!("{base}/oauth/revoke"),
        "code_challenge_methods_supported":["S256"],
        "token_endpoint_auth_methods_supported":["client_secret_basic"],
        "scopes_supported":[SCOPE,"offline_access"],
        "authorization_response_iss_parameter_supported":true
    }))
}

async fn token_endpoint(
    State(state): State<OAuthFixtureState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let form = url::form_urlencoded::parse(&body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    state
        .token_observations
        .lock()
        .unwrap()
        .push(TokenObservation {
            authorization: authorization.clone(),
            form: form.clone(),
        });
    let expected_basic = format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if form.get("grant_type").map(String::as_str) == Some("authorization_code") {
        let base = state
            .resource
            .strip_suffix("/mcp")
            .expect("fixture resource suffix");
        let verifier = form.get("code_verifier").map_or("", String::as_str);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        let expected_challenge = state.expected_challenge.lock().unwrap().clone();
        if authorization != expected_basic
            || form.get("code").map(String::as_str) != Some("authorization-code")
            || form.get("resource").map(String::as_str) != Some(state.resource.as_ref())
            || form.get("redirect_uri").map(String::as_str)
                != Some(format!("{base}/api/plugins/oauth/callback").as_str())
            || expected_challenge.as_deref() != Some(challenge.as_str())
            || form.contains_key("client_id")
            || form.contains_key("client_secret")
        {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error":"invalid_grant"})),
            )
                .into_response();
        }
        let call = state.code_calls.fetch_add(1, Ordering::SeqCst) + 1;
        *state.current_refresh.lock().unwrap() = format!("connected-refresh-{call}");
        return axum::Json(serde_json::json!({
            "access_token":format!("access-code-{call}"),
            "token_type":"Bearer",
            "refresh_token":format!("connected-refresh-{call}"),
            "scope":SCOPE,
            "expires_in":60
        }))
        .into_response();
    }
    let refresh_matches = state.current_refresh.lock().unwrap().as_str()
        == form.get("refresh_token").map_or("", String::as_str);
    if authorization != expected_basic
        || form.get("grant_type").map(String::as_str) != Some("refresh_token")
        || form.get("resource").map(String::as_str) != Some(state.resource.as_ref())
        || form.get("scope").map(String::as_str) != Some(SCOPE)
        || form.contains_key("client_id")
        || form.contains_key("client_secret")
        || !refresh_matches
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error":"invalid_grant"})),
        )
            .into_response();
    }
    let call = state.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
    *state.current_refresh.lock().unwrap() = format!("refresh-{call}");
    axum::Json(serde_json::json!({
        "access_token":format!("access-{call}"),
        "token_type":"Bearer",
        "refresh_token":format!("refresh-{call}"),
        "scope":SCOPE,
        "expires_in":60
    }))
    .into_response()
}

async fn revocation_endpoint(
    State(state): State<OAuthFixtureState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let expected_basic = format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    let form = url::form_urlencoded::parse(&body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    state.revoke_calls.fetch_add(1, Ordering::SeqCst);
    if state.revoke_failure.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if authorization != expected_basic
        || form.get("token_type_hint").map(String::as_str) != Some("refresh_token")
        || !form.get("token").is_some_and(|token| {
            token.starts_with("connected-refresh-") || token.starts_with("refresh-")
        })
        || form.contains_key("client_secret")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    StatusCode::OK.into_response()
}

async fn require_rotating_bearer(
    State(state): State<OAuthFixtureState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let bearer = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if bearer == Some("Bearer access-3") {
        state.rejected_access_three.fetch_add(1, Ordering::SeqCst);
    }
    if !matches!(
        bearer,
        Some("Bearer access-1" | "Bearer access-2" | "Bearer access-4")
    ) && !bearer.is_some_and(|value| value.starts_with("Bearer access-code-"))
    {
        return (
            StatusCode::UNAUTHORIZED,
            [(
                http::header::WWW_AUTHENTICATE,
                format!(
                    "Bearer resource_metadata=\"{}/oauth/resource-metadata\"",
                    state
                        .resource
                        .strip_suffix("/mcp")
                        .expect("fixture resource suffix")
                ),
            )],
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Clone)]
struct OAuthMcpServer {
    received: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl ServerHandler for OAuthMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("openbot-oauth-test", "3.1.4"))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "search_notes",
            "Search notes for an exact query.",
            serde_json::json!({
                "type":"object",
                "properties":{"query":{"type":"string"}},
                "required":["query"],
                "additionalProperties":false
            })
            .as_object()
            .cloned()
            .unwrap(),
        )]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name.as_ref() != "search_notes" {
            return Err(McpError::invalid_params("unknown tool", None));
        }
        let arguments = serde_json::Value::Object(request.arguments.unwrap_or_default());
        self.received.lock().unwrap().push(arguments.clone());
        let query = arguments
            .get("query")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Ok(CallToolResponse::Complete(CallToolResult::success(vec![
            ContentBlock::text(format!("Found OAuth note for {query}.")),
        ])))
    }
}

struct SpawnedOAuthMcp {
    resource: String,
    state: OAuthFixtureState,
    received: Arc<Mutex<Vec<serde_json::Value>>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn spawn_oauth_mcp() -> Result<SpawnedOAuthMcp, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let resource: Arc<str> = Arc::from(format!("http://{address}/mcp"));
    let issuer: Arc<str> = Arc::from(format!("http://{address}/auth/tenant"));
    let state = OAuthFixtureState {
        resource: resource.clone(),
        issuer,
        current_refresh: Arc::new(Mutex::new("refresh-0".to_owned())),
        token_calls: Arc::new(AtomicUsize::new(0)),
        token_observations: Arc::new(Mutex::new(Vec::new())),
        rejected_access_three: Arc::new(AtomicUsize::new(0)),
        code_calls: Arc::new(AtomicUsize::new(0)),
        expected_challenge: Arc::new(Mutex::new(None)),
        revoke_calls: Arc::new(AtomicUsize::new(0)),
        revoke_failure: Arc::new(AtomicBool::new(false)),
    };
    let received = Arc::new(Mutex::new(Vec::new()));
    let server = OAuthMcpServer {
        received: received.clone(),
    };
    let rmcp = StreamableHttpService::new(
        move || Ok::<_, std::io::Error>(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let protected =
        axum::Router::new()
            .nest_service("/mcp", rmcp)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_rotating_bearer,
            ));
    let router = axum::Router::new()
        .route("/oauth/resource-metadata", get(protected_resource_metadata))
        .route(
            "/.well-known/oauth-authorization-server/auth/tenant",
            get(authorization_server_metadata),
        )
        .route("/oauth/token", post(token_endpoint))
        .route("/oauth/revoke", post(revocation_endpoint))
        .with_state(state.clone())
        .merge(protected);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(SpawnedOAuthMcp {
        resource: resource.to_string(),
        state,
        received,
        handle,
    })
}

fn loopback_policy() -> EgressPolicy {
    EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap())
}

fn rmcp_client() -> SafeRmcpClient {
    SafeRmcpClient::new(
        SafeDialer::new(loopback_policy()),
        SchemePolicy::HttpOrHttps,
        Some(std::time::Duration::from_secs(2)),
    )
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn actor_oauth_rotates_before_use_and_retries_one_401_exactly_once() {
    let admin =
        harness::admin_config("actor_oauth_rotates_before_use_and_retries_one_401_exactly_once");
    harness::with_temp_database(&admin, "mcpoauth", |config| async move {
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
            let spawned = spawn_oauth_mcp().await?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('oauth-owner','oauth-owner@example.test',0),
                   ('oauth-other','oauth-other@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('oauth-owner','user'),('oauth-other','user');
                 INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                   VALUES('oauth-tenant','/oauth-fixture',repeat('c',64));
                 INSERT INTO public.agents(id,name,type,configuration,package_id)
                   SELECT 'oauth-bot','OAuth Bot','built_in',
                          '{\"systemPrompt\":\"Use the connected notes.\",\"providerSource\":\"package\"}',id
                     FROM public.deployment_packages WHERE tenant_id='oauth-tenant';
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                 ) VALUES('oauth-bot',NULL,'OAuth Bot','role','oauth-seed','public',NULL);
                 INSERT INTO public.threads(
                   thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                   next_message_seq,next_event_seq,created_at,updated_at
                 ) VALUES('oauth-thread','oauth-tenant','oauth-deployment','oauth-owner',
                          'direct_bot','oauth-bot','active',1,0,clock_timestamp(),clock_timestamp());
                 INSERT INTO public.thread_memberships(thread_id,user_id)
                   VALUES('oauth-thread','oauth-owner');
                 INSERT INTO public.runs(
                   run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                   next_event_seq,created_at,started_at
                 ) VALUES('oauth-run','oauth-thread','oauth-bot','oauth-owner',true,'running',1,
                          0,clock_timestamp(),clock_timestamp());
                 INSERT INTO public.thread_leases(
                   thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                 ) VALUES('oauth-thread','oauth-runtime',1,clock_timestamp(),
                          clock_timestamp()+interval '10 minutes',clock_timestamp());
                 INSERT INTO public.messages(
                   message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                 ) VALUES('oauth-message','oauth-thread',0,'user',
                          '{\"text\":\"Search invoices.\"}','Search invoices.',
                          'oauth-run','oauth-owner',clock_timestamp());",
            )
            .await
            .map_err(|error| error.to_string())?;

            let vault = CredentialRecordVault::single_key(
                TenantId::new("oauth-tenant"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x73; 32]).map_err(|error| error.to_string())?,
            );
            let client_credential_id = uuid::Uuid::now_v7();
            let user_credential_id = uuid::Uuid::now_v7();
            let client_json = serde_json::to_vec(&serde_json::json!({
                "clientId":CLIENT_ID,
                "clientSecret":CLIENT_SECRET,
                "issuer":spawned.state.issuer.as_ref(),
                "tokenEndpointAuthMethod":"client_secret_basic"
            }))
            .map_err(|error| error.to_string())?;
            let sealed_client = vault
                .seal(
                    &client_credential_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(SERVER)),
                    &SecretBytes::new(client_json),
                )
                .map_err(|error| error.to_string())?;
            let sealed_refresh = vault
                .seal(
                    &user_credential_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(ActorId::new(ACTOR)),
                    SecretPrincipal::Service(ServiceId::new(SERVER)),
                    &SecretBytes::new(b"refresh-0".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata)
                   VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}')",
                &[&client_credential_id, &SERVER, &sealed_client],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata)
                   VALUES($1,'mcp_user_token',$2,$3,$4,'{}')",
                &[&user_credential_id, &SERVER, &sealed_refresh, &ACTOR],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,egress_allow_cidrs)
                   VALUES($1,'OAuth Notes','oauth-notes',$2,'custom',$3,
                          ARRAY['127.0.0.1/32'])",
                &[&SERVER, &spawned.resource, &client_credential_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_user_credentials(server_id,user_id,credential_id,scope)
                   VALUES($1,$2,$3,$4)",
                &[&SERVER, &ACTOR, &user_credential_id, &SCOPE],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','oauth-notes/search_notes','oauth-bot','oauth-owner')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let broker = Arc::new(
                PostgresMcpCredentialBroker::new(pool.clone(), vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")))
                    .with_user_oauth(
                        SafeDialer::new(EgressPolicy::default()),
                        SchemePolicy::HttpOrHttps,
                        AUDIT_KEY.to_vec(),
                    )
                    .map_err(|error| error.to_string())?,
            );
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers SET egress_allow_cidrs=NULL WHERE id=$1",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            if !matches!(
                broker.bearer_for(SERVER, &ActorId::new(ACTOR)).await,
                Err(McpCredentialError::Unavailable)
            )
                || spawned.state.token_calls.load(Ordering::SeqCst) != 0
            {
                return Err("runtime OAuth refresh escaped the default deny policy".to_owned());
            }
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.mcp_servers
                        SET egress_allow_cidrs=ARRAY['127.0.0.1/32'] WHERE id=$1",
                    &[&SERVER],
                )
                .await
                .map_err(|error| error.to_string())?;
            // R395: changing configuration cannot reclaim a durable refresh operation. Even a
            // pre-admission discovery failure remains a tombstone across configuration rollback.
            if !matches!(
                broker.bearer_for(SERVER, &ActorId::new(ACTOR)).await,
                Err(McpCredentialError::CommitUnknown)
            ) || spawned.state.token_calls.load(Ordering::SeqCst) != 0
            {
                return Err("configuration rollback reopened an owned refresh operation".to_owned());
            }
            // Explicit fixture reconnect allocates a new credential identity just like the
            // callback writer. The old pending row is retained, never deleted to make tests pass.
            let previous_credential_id = user_credential_id;
            let user_credential_id = uuid::Uuid::now_v7();
            let sealed_refresh = vault.seal(
                &user_credential_id,
                SecretKind::McpUserToken,
                SecretPrincipal::Actor(ActorId::new(ACTOR)),
                SecretPrincipal::Service(ServiceId::new(SERVER)),
                &SecretBytes::new(b"refresh-0".to_vec()),
            ).map_err(|error| error.to_string())?;
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            let tx = pg.transaction().await.map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata)
                   VALUES($1,'mcp_user_token',$2,$3,$4,'{}')",
                &[&user_credential_id, &SERVER, &sealed_refresh, &ACTOR],
            ).await.map_err(|error| error.to_string())?;
            tx.execute("UPDATE public.mcp_user_credentials SET credential_id=$3,updated_at=clock_timestamp() WHERE server_id=$1 AND user_id=$2", &[&SERVER, &ACTOR, &user_credential_id]).await.map_err(|error| error.to_string())?;
            tx.execute("UPDATE public.credentials SET revoked_at=clock_timestamp() WHERE id=$1", &[&previous_credential_id]).await.map_err(|error| error.to_string())?;
            let old = tx.query_one("SELECT state,admitted_at IS NULL FROM public.oauth_refresh_operations WHERE credential_id=$1", &[&previous_credential_id]).await.map_err(|error| error.to_string())?;
            if old.get::<_,String>(0) != "pending" || !old.get::<_,bool>(1) {
                return Err("pre-admission tombstone changed during reconnect".to_owned());
            }
            tx.commit().await.map_err(|error| error.to_string())?;
            drop(pg);
            if !matches!(
                broker.bearer_for(SERVER, &ActorId::new(OTHER)).await,
                Err(McpCredentialError::AuthRequired)
            ) || spawned.state.token_calls.load(Ordering::SeqCst) != 0
            {
                return Err("actor without connection reached the token endpoint".to_owned());
            }
            let rmcp = rmcp_client();
            if rmcp.list_tools(&spawned.resource, None).await
                != Err(McpClientError::AuthRequired)
            {
                return Err("protected MCP did not classify anonymous 401".to_owned());
            }
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp.clone(), AUDIT_KEY.to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let bearer = broker
                .bearer_for(SERVER, &ActorId::new(ACTOR))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "OAuth credential resolved anonymous".to_owned())?;
            catalog
                .refresh(SERVER, Some(bearer))
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_tools SET effect='read'
                   WHERE server_id=$1 AND name='search_notes'",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let bearer = broker
                .bearer_for(SERVER, &ActorId::new(ACTOR))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "second OAuth credential resolved anonymous".to_owned())?;
            catalog
                .refresh(SERVER, Some(bearer))
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,
                   effect=t.effect,transport_fingerprint=s.catalog_transport_fingerprint,
                   updated_at=clock_timestamp()
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='oauth-notes/search_notes'
                   AND g.agent_id='oauth-bot' AND t.server_id='oauth-notes'
                   AND t.name='search_notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let owner_tools = catalog
                .granted_tools(&BotId::new(BOT), &ActorId::new(ACTOR))
                .await
                .map_err(|error| error.to_string())?;
            if owner_tools.len() != 1
                || owner_tools[0].authentication != McpAuthentication::UserOAuth
                || !catalog
                    .granted_tools(&BotId::new(BOT), &ActorId::new(OTHER))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_empty()
            {
                return Err("actor-scoped OAuth catalog visibility drift".to_owned());
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
                    Some(ACTOR),
                )
                .await
                .map_err(|error| error.to_string())?;
            let memory = PostgresMemoryAdministration::new(pool.clone());
            let control = PostgresBuiltInToolControlPlane::new(
                pool.clone(),
                DeploymentId::new("oauth-deployment"),
                TenantId::new("oauth-tenant"),
                policy.clone(),
                Arc::new(memory.clone()),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .with_mcp(catalog.clone(), rmcp)
            .with_mcp_credentials(broker.clone());
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policy)
                    .with_tools(
                        control,
                        PostgresToolJournal::new(pool.clone(), AUDIT_KEY.to_vec())
                            .map_err(|error| error.to_string())?,
                    )
                    .with_memory(memory),
            );
            let gateway = AuthorizedAgentToolGateway::with_sequence(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    DeploymentId::new("oauth-deployment"),
                    TenantId::new("oauth-tenant"),
                    false,
                )),
                Arc::new(PostgresAgentToolSequence::new(pool.clone())),
            );
            let lease = RunExecutionLease::new(
                RunId::new("oauth-run"),
                ThreadId::new("oauth-thread"),
                BotId::new(BOT),
                ActorId::new(ACTOR),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let reply = gateway
                .invoke(
                    &lease,
                    "provider-oauth-search",
                    "mcp__oauth-notes__search_notes",
                    serde_json::json!({"query":"invoices"}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if reply.error_code().is_some()
                || !reply.content().contains("Found OAuth note for invoices")
                || spawned.received.lock().unwrap().as_slice()
                    != [serde_json::json!({"query":"invoices"})]
                || spawned.state.token_calls.load(Ordering::SeqCst) != 4
                || spawned
                    .state
                    .rejected_access_three
                    .load(Ordering::SeqCst)
                    != 1
            {
                return Err(format!("OAuth governed call drift: {reply:?}"));
            }

            let observations = spawned.state.token_observations.lock().unwrap().clone();
            if observations.len() != 4
                || observations.iter().any(|observation| {
                    observation.authorization
                        != format!(
                            "Basic {}",
                            BASE64_STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
                        )
                        || observation.form.get("resource").map(String::as_str)
                            != Some(spawned.resource.as_str())
                        || observation.form.get("scope").map(String::as_str) != Some(SCOPE)
                        || observation.form.contains_key("client_secret")
                })
                || observations
                    .iter()
                    .enumerate()
                    .any(|(index, observation)| {
                        observation.form.get("refresh_token").map(String::as_str)
                            != Some(format!("refresh-{index}").as_str())
                    })
            {
                return Err("RFC 8707/basic/rotation token request drift".to_owned());
            }
            drop(observations);

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let evidence = pg
                .query_one(
                    "SELECT encrypted_value,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='credential.rotated'
                                AND actor_user_id='oauth-owner'
                                AND target_id=$1::uuid::text),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.call_succeeded'
                                AND target_id='oauth-notes/search_notes'
                                AND actor_user_id='oauth-owner'),
                            (SELECT next_tool_call_seq FROM public.runs
                              WHERE run_id='oauth-run')
                       FROM public.credentials WHERE id=$1::uuid",
                    &[&user_credential_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let encrypted: String = evidence.try_get(0).map_err(|error| error.to_string())?;
            let rotations: i64 = evidence.try_get(1).map_err(|error| error.to_string())?;
            let success: i64 = evidence.try_get(2).map_err(|error| error.to_string())?;
            let sequence: Option<i64> = evidence.try_get(3).map_err(|error| error.to_string())?;
            if encrypted == sealed_refresh || rotations != 4 || success != 1 || sequence != Some(1)
            {
                return Err("durable OAuth rotation/tool evidence drift".to_owned());
            }
            let current = vault
                .open(
                    &user_credential_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(ActorId::new(ACTOR)),
                    SecretPrincipal::Service(ServiceId::new(SERVER)),
                    &encrypted,
                )
                .map_err(|error| error.to_string())?
                .into_secret();
            if current.expose() != b"refresh-4"
                || encrypted.contains("refresh-")
                || encrypted.contains("access-")
            {
                return Err("rotated credential plaintext/storage boundary drift".to_owned());
            }
            drop(pg);
            spawned.handle.abort();
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
async fn authorization_code_state_pkce_callback_and_local_first_disconnect_are_real() {
    let admin = harness::admin_config(
        "authorization_code_state_pkce_callback_and_local_first_disconnect_are_real",
    );
    harness::with_temp_database(&admin, "mcpconnect", |config| async move {
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
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation)
                   VALUES('oauth-owner','oauth-owner@example.test',0),
                         ('oauth-other','oauth-other@example.test',0);
                 INSERT INTO public.user_roles(user_id,role)
                   VALUES('oauth-owner','user'),('oauth-owner','admin'),
                         ('oauth-other','user');",
            )
            .await
            .map_err(|error| error.to_string())?;
            let spawned = spawn_oauth_mcp().await?;
            let base = spawned
                .resource
                .strip_suffix("/mcp")
                .ok_or_else(|| "fixture resource suffix missing".to_owned())?
                .to_owned();
            let vault = CredentialRecordVault::single_key(
                TenantId::new("oauth-connect-tenant"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x55; 32]).map_err(|error| error.to_string())?,
            );
            pg.execute(
                "INSERT INTO public.mcp_servers(id,title,vendor,url,provenance)
                   VALUES($1,'OAuth Notes','oauth-notes',$2,'custom')",
                &[&SERVER, &spawned.resource],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('oauth-registration-bot','Registration Bot','remote_ag_ui','{}');
                 INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','oauth-notes/search_notes','oauth-registration-bot','oauth-owner');",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let rmcp = rmcp_client();
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp, AUDIT_KEY.to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let connections = PostgresMcpConnections::new(
                pool.clone(),
                vault.clone(),
                McpOAuthClient::new(
                    SafeDialer::new(EgressPolicy::default()),
                    SchemePolicy::HttpOrHttps,
                ),
                catalog.clone(),
                DeploymentId::new("oauth-connect-deployment"),
                TenantId::new("oauth-connect-tenant"),
                vec![0x66; 32],
                AUDIT_KEY.to_vec(),
                Some(&base),
                Some("http://app.example.test"),
                SchemePolicy::HttpOrHttps,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?;
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("oauth-connect-deployment"),
                TenantId::new("oauth-connect-tenant"),
                ActorId::new(ACTOR),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User, Role::Admin])
            .build();
            let registration_input = McpOAuthClientRegistration::new(
                CLIENT_ID.to_owned(),
                CLIENT_SECRET.to_owned(),
                spawned.state.issuer.to_string(),
                McpOAuthClientAuthMethod::ClientSecretBasic,
                None,
            )
            .map_err(|error| error.to_string())?;
            if connections
                .register_oauth_client(
                    &auth,
                    SERVER,
                    &registration_input,
                )
                .await
                != Err(McpConnectionError::VendorFailure)
            {
                return Err("private OAuth discovery escaped the default deny policy".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let denied_writes: i64 = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE kind='mcp_oauth_client' AND provider=$1) +
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.oauth_client_registered' AND target_id=$1)",
                    &[&SERVER],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if denied_writes != 0 {
                return Err("denied private OAuth discovery wrote credential or audit".to_owned());
            }
            pg.execute(
                "UPDATE public.mcp_servers
                    SET egress_allow_cidrs=ARRAY['127.0.0.1/32'] WHERE id=$1",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let registered = connections
                .register_oauth_client(&auth, SERVER, &registration_input)
                .await
                .map_err(|error| error.to_string())?;
            if !registered.ok {
                return Err("OAuth client registration acknowledgement drift".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let registration = pg
                .query_one(
                    "SELECT s.credential_generation,g.credential_generation,
                            s.catalog_generation IS NULL,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.oauth_client_registered'
                                AND actor_user_id=$1)
                       FROM public.mcp_servers s JOIN public.plugin_grants g
                         ON split_part(g.ref,'/',1)=s.id
                      WHERE s.id=$2",
                    &[&ACTOR, &SERVER],
                )
                .await
                .map_err(|error| error.to_string())?;
            let server_generation: Option<i64> =
                registration.try_get(0).map_err(|error| error.to_string())?;
            let grant_generation: Option<i64> =
                registration.try_get(1).map_err(|error| error.to_string())?;
            let catalog_cleared: bool =
                registration.try_get(2).map_err(|error| error.to_string())?;
            let registration_audit: i64 =
                registration.try_get(3).map_err(|error| error.to_string())?;
            drop(pg);
            if server_generation != Some(1)
                || grant_generation != Some(0)
                || !catalog_cleared
                || registration_audit != 1
            {
                return Err("OAuth client credential-generation registration drift".to_owned());
            }
            if !connections
                .list_connections(&auth)
                .await
                .map_err(|error| error.to_string())?
                .connections
                .is_empty()
            {
                return Err("fresh actor unexpectedly had a connection".to_owned());
            }

            let drift_attempt = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Settings)
                .await
                .map_err(|error| error.to_string())?;
            let drift_state = url::Url::parse(&drift_attempt.authorization_url)
                .map_err(|error| error.to_string())?
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned())
                .ok_or_else(|| "egress-bound state missing".to_owned())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers
                    SET egress_allow_cidrs=ARRAY['127.0.0.0/8'] WHERE id=$1",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let drifted = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    drift_state.into_bytes(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if drifted.redirect_to
                != "http://app.example.test/settings/connected-accounts?connected=failed"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 0
            {
                return Err("egress authority drift reached the token endpoint".to_owned());
            }
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.mcp_servers
                        SET egress_allow_cidrs=ARRAY['127.0.0.1/32'] WHERE id=$1",
                    &[&SERVER],
                )
                .await
                .map_err(|error| error.to_string())?;

            let begin = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Settings)
                .await
                .map_err(|error| error.to_string())?;
            let authorization =
                url::Url::parse(&begin.authorization_url).map_err(|error| error.to_string())?;
            let params = authorization
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeMap<_, _>>();
            let state = params
                .get("state")
                .cloned()
                .ok_or_else(|| "authorization state missing".to_owned())?;
            let challenge = params
                .get("code_challenge")
                .cloned()
                .ok_or_else(|| "PKCE challenge missing".to_owned())?;
            if authorization.path() != "/oauth/authorize"
                || params.get("resource").map(String::as_str) != Some(spawned.resource.as_str())
                || params.get("redirect_uri").map(String::as_str)
                    != Some(format!("{base}/api/plugins/oauth/callback").as_str())
                || params.get("code_challenge_method").map(String::as_str) != Some("S256")
                || params.get("scope").map(String::as_str) != Some("notes:read offline_access")
                || params.contains_key("code_verifier")
                || state.len() < 43
                || challenge.len() < 43
            {
                return Err("authorization URL/state/PKCE/resource drift".to_owned());
            }
            *spawned.state.expected_challenge.lock().unwrap() = Some(challenge);
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let attempt = pg
                .query_one(
                    "SELECT identifier,value FROM public.verifications
                      WHERE identifier LIKE 'mcp-oauth-attempt:%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let identifier: String = attempt.try_get(0).map_err(|error| error.to_string())?;
            let stored_value: String = attempt.try_get(1).map_err(|error| error.to_string())?;
            if identifier.contains(&state)
                || stored_value.contains(ACTOR)
                || stored_value.contains("code_verifier")
                || stored_value.contains("oauth-notes")
            {
                return Err("state/verifier/actor were stored without HMAC+AEAD".to_owned());
            }
            drop(pg);

            let wrong_key_connections = PostgresMcpConnections::new(
                pool.clone(),
                vault.clone(),
                McpOAuthClient::new(
                    SafeDialer::new(EgressPolicy::default()),
                    SchemePolicy::HttpOrHttps,
                ),
                catalog,
                DeploymentId::new("oauth-connect-deployment"),
                TenantId::new("oauth-connect-tenant"),
                vec![0x67; 32],
                AUDIT_KEY.to_vec(),
                Some(&base),
                Some("http://app.example.test"),
                SchemePolicy::HttpOrHttps,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?;
            let wrong_key = wrong_key_connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    state.as_bytes().to_vec(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            let mut tampered_state = state.as_bytes().to_vec();
            tampered_state[0] = if tampered_state[0] == b'A' { b'B' } else { b'A' };
            let tampered = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    tampered_state,
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if wrong_key.redirect_to
                != "http://app.example.test/settings/connected-accounts?connected=failed"
                || tampered.redirect_to
                    != "http://app.example.test/settings/connected-accounts?connected=failed"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 0
            {
                return Err("wrong-key or tampered state reached token exchange".to_owned());
            }

            let outcome = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    state.as_bytes().to_vec(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if outcome.redirect_to
                != "http://app.example.test/settings/connected-accounts/oauth-notes"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 1
            {
                return Err("successful callback redirect/token exchange drift".to_owned());
            }
            let observations = spawned.state.token_observations.lock().unwrap().clone();
            let verifier = observations
                .iter()
                .find(|observation| {
                    observation.form.get("grant_type").map(String::as_str)
                        == Some("authorization_code")
                })
                .and_then(|observation| observation.form.get("code_verifier"))
                .ok_or_else(|| "authorization code verifier was not observed".to_owned())?;
            if !(43..=128).contains(&verifier.len())
                || !verifier.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
                || base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes()))
                    != params["code_challenge"]
            {
                return Err("PKCE verifier length/alphabet/S256 drift".to_owned());
            }
            drop(observations);
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let stale_grant = pg
                .query_one(
                    "SELECT g.state,g.credential_generation,s.credential_generation
                       FROM public.plugin_grants g JOIN public.mcp_servers s
                         ON split_part(g.ref,'/',1)=s.id
                      WHERE g.ref='oauth-notes/search_notes'
                        AND g.agent_id='oauth-registration-bot'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let grant_state: Option<String> =
                stale_grant.try_get(0).map_err(|error| error.to_string())?;
            let grant_generation: Option<i64> =
                stale_grant.try_get(1).map_err(|error| error.to_string())?;
            let server_generation: Option<i64> =
                stale_grant.try_get(2).map_err(|error| error.to_string())?;
            drop(pg);
            if grant_state.as_deref() != Some("suspended_missing")
                || grant_generation != Some(0)
                || server_generation != Some(1)
            {
                return Err("credential change silently revived a stale grant".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,
                   effect=t.effect,transport_fingerprint=s.catalog_transport_fingerprint,
                   credential_generation=coalesce(s.credential_generation,0),
                   updated_at=clock_timestamp()
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.ref='oauth-notes/search_notes'
                   AND g.agent_id='oauth-registration-bot'
                   AND t.server_id='oauth-notes' AND t.name='search_notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let broker = PostgresMcpCredentialBroker::new(pool.clone(), vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")))
                .with_user_oauth(
                    SafeDialer::new(EgressPolicy::default()),
                    SchemePolicy::HttpOrHttps,
                    AUDIT_KEY.to_vec(),
                )
                .map_err(|error| error.to_string())?;
            let bearer = broker
                .bearer_for(SERVER, &ActorId::new(ACTOR))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "connected OAuth runtime resolved anonymous".to_owned())?;
            if rmcp_client()
                .list_tools(&spawned.resource, Some(bearer))
                .await
                .map_err(|error| error.to_string())?
                .len()
                != 1
                || spawned.state.token_calls.load(Ordering::SeqCst) != 1
            {
                return Err("callback credential did not feed production RMCP runtime".to_owned());
            }
            let replay = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    state.as_bytes().to_vec(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if replay.redirect_to
                != "http://app.example.test/settings/connected-accounts?connected=failed"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 1
            {
                return Err("callback state replay reached token endpoint".to_owned());
            }
            let page = connections
                .list_connections(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if page.connections.len() != 1
                || page.connections[0].server_id != SERVER
                || page.connections[0].scope != SCOPE
                || page.redirect_uri.as_deref()
                    != Some(format!("{base}/api/plugins/oauth/callback").as_str())
            {
                return Err("connected-account projection drift".to_owned());
            }

            let mixed = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Admin)
                .await
                .map_err(|error| error.to_string())?;
            let mixed_url =
                url::Url::parse(&mixed.authorization_url).map_err(|error| error.to_string())?;
            let mixed_params = mixed_url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeMap<_, _>>();
            let mixed_state = mixed_params
                .get("state")
                .cloned()
                .ok_or_else(|| "mix-up state missing".to_owned())?;
            if mixed_state == state
                || mixed_params.get("code_challenge") == params.get("code_challenge")
            {
                return Err("two OAuth attempts reused state or PKCE verifier".to_owned());
            }
            *spawned.state.expected_challenge.lock().unwrap() =
                mixed_params.get("code_challenge").cloned();
            let mixed_outcome = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    mixed_state.as_bytes().to_vec(),
                    Some("http://attacker.invalid/issuer".to_owned()),
                ))
                .await;
            if mixed_outcome.redirect_to
                != "http://app.example.test/settings/connected-accounts?connected=failed"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 1
            {
                return Err("issuer mix-up was not stopped before token exchange".to_owned());
            }

            let expiring = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Settings)
                .await
                .map_err(|error| error.to_string())?;
            let expiring_url =
                url::Url::parse(&expiring.authorization_url).map_err(|error| error.to_string())?;
            let expiring_state = expiring_url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned())
                .ok_or_else(|| "expiring state missing".to_owned())?;
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.verifications SET expires_at=clock_timestamp()-interval '1 second'
                      WHERE identifier LIKE 'mcp-oauth-attempt:%'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let expired = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    expiring_state.into_bytes(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if expired.redirect_to
                != "http://app.example.test/settings/connected-accounts?connected=failed"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 1
            {
                return Err("expired state reached token exchange".to_owned());
            }

            spawned.state.revoke_failure.store(true, Ordering::SeqCst);
            let pending = connections
                .disconnect(&auth, SERVER)
                .await
                .map_err(|error| error.to_string())?;
            if pending.vendor_revocation != McpVendorRevocationStatus::Pending
                || !connections
                    .list_connections(&auth)
                    .await
                    .map_err(|error| error.to_string())?
                    .connections
                    .is_empty()
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 1
            {
                return Err("vendor failure restored or preserved local connection".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let pending_evidence: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.credentials
                      WHERE kind='mcp_user_token' AND key_id=$1 AND revoked_at IS NOT NULL
                        AND metadata->>'revocation_status'='pending'",
                    &[&ACTOR],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(pg);
            if pending_evidence != 1 {
                return Err("local tombstone did not persist revocation_pending".to_owned());
            }

            spawned.state.revoke_failure.store(false, Ordering::SeqCst);
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers SET egress_allow_cidrs=NULL WHERE id=$1",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                  WHERE kind='mcp_user_token' AND key_id=$1
                    AND metadata->>'revocation_status'='pending'",
                &[&ACTOR],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let denied_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if denied_sweep.attempted != 1
                || denied_sweep.revoked != 0
                || denied_sweep.pending != 1
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 1
            {
                return Err("revocation retry escaped current private-egress denial".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers
                    SET egress_allow_cidrs=ARRAY['127.0.0.1/32'] WHERE id=$1",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                  WHERE kind='mcp_user_token' AND key_id=$1
                    AND metadata->>'revocation_status'='pending'",
                &[&ACTOR],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if sweep.attempted != 1
                || sweep.revoked != 1
                || sweep.pending != 0
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 2
            {
                return Err("revocation_pending retry sweep drift".to_owned());
            }

            let reconnect = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Admin)
                .await
                .map_err(|error| error.to_string())?;
            let reconnect_url =
                url::Url::parse(&reconnect.authorization_url).map_err(|error| error.to_string())?;
            let reconnect_params = reconnect_url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeMap<_, _>>();
            *spawned.state.expected_challenge.lock().unwrap() =
                reconnect_params.get("code_challenge").cloned();
            let reconnect_outcome = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    reconnect_params
                        .get("state")
                        .ok_or_else(|| "reconnect state missing".to_owned())?
                        .as_bytes()
                        .to_vec(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if reconnect_outcome.redirect_to != "http://app.example.test/admin/plugins/oauth-notes"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 2
            {
                return Err("admin reconnect callback drift".to_owned());
            }
            spawned.state.revoke_failure.store(false, Ordering::SeqCst);
            let revoked = connections
                .disconnect(&auth, SERVER)
                .await
                .map_err(|error| error.to_string())?;
            if revoked.vendor_revocation != McpVendorRevocationStatus::Revoked
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 3
            {
                return Err("confirmed vendor revocation receipt drift".to_owned());
            }

            let removal_connect = connections
                .begin_oauth(&auth, SERVER, McpOAuthReturnTo::Admin)
                .await
                .map_err(|error| error.to_string())?;
            let removal_url = url::Url::parse(&removal_connect.authorization_url)
                .map_err(|error| error.to_string())?;
            let removal_params = removal_url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeMap<_, _>>();
            *spawned.state.expected_challenge.lock().unwrap() =
                removal_params.get("code_challenge").cloned();
            let removal_connected = connections
                .complete(McpOAuthCallbackInput::new(
                    b"authorization-code".to_vec(),
                    removal_params
                        .get("state")
                        .ok_or_else(|| "server-removal state missing".to_owned())?
                        .as_bytes()
                        .to_vec(),
                    Some(spawned.state.issuer.to_string()),
                ))
                .await;
            if removal_connected.redirect_to != "http://app.example.test/admin/plugins/oauth-notes"
                || spawned.state.code_calls.load(Ordering::SeqCst) != 3
            {
                return Err("server-removal connection setup drift".to_owned());
            }
            let old_client_id: uuid::Uuid = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT credential_id FROM public.mcp_servers WHERE id=$1",
                    &[&SERVER],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let removed = connections
                .remove_server(&auth, SERVER)
                .await
                .map_err(|error| error.to_string())?;
            if !removed.ok {
                return Err("admin server removal acknowledgement drift".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let local_removal = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.mcp_servers WHERE id=$1),
                       (SELECT count(*)::bigint FROM public.mcp_user_credentials WHERE server_id=$1),
                       (SELECT count(*)::bigint FROM public.plugin_grants
                         WHERE kind='mcp' AND split_part(ref,'/',1)=$1),
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE kind='mcp_user_token' AND provider=$1
                           AND metadata->>'revocation_reason'='mcp_server_removed'
                           AND metadata->>'revocation_status'='pending'
                           AND metadata#>>'{server_removal_revocation,client_credential_id}'=$2)",
                    &[&SERVER, &old_client_id.to_string()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let server_rows: i64 = local_removal.try_get(0).map_err(|error| error.to_string())?;
            let joins: i64 = local_removal.try_get(1).map_err(|error| error.to_string())?;
            let grants: i64 = local_removal.try_get(2).map_err(|error| error.to_string())?;
            let queued: i64 = local_removal.try_get(3).map_err(|error| error.to_string())?;
            if server_rows != 0 || joins != 0 || grants != 0 || queued != 1 {
                return Err("admin removal local closure/context drift".to_owned());
            }

            let replacement_client_id = uuid::Uuid::now_v7();
            let replacement_client = serde_json::to_vec(&serde_json::json!({
                "clientId":"replacement-client",
                "clientSecret":"replacement-secret",
                "issuer":"http://127.0.0.1:9/auth/tenant",
                "tokenEndpointAuthMethod":"client_secret_basic"
            }))
            .map_err(|error| error.to_string())?;
            let sealed_replacement = vault
                .seal(
                    &replacement_client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(SERVER)),
                    &SecretBytes::new(replacement_client),
                )
                .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}')",
                &[&replacement_client_id, &SERVER, &sealed_replacement],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,transport,egress_allow_cidrs)
                 VALUES($1,'Replacement','127.0.0.1','http://127.0.0.1:9/mcp','custom',$2,
                        'mcp',ARRAY['127.0.0.1/32'])",
                &[&SERVER, &replacement_client_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                  WHERE kind='mcp_user_token' AND provider=$1
                    AND metadata->>'revocation_status'='pending'",
                &[&SERVER],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            spawned.state.revoke_failure.store(true, Ordering::SeqCst);
            let failed_removal_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if failed_removal_sweep.attempted != 1
                || failed_removal_sweep.revoked != 0
                || failed_removal_sweep.pending != 1
                || failed_removal_sweep.operator_required != 0
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 4
            {
                return Err("server-removal vendor failure was not retained for retry".to_owned());
            }
            spawned.state.revoke_failure.store(false, Ordering::SeqCst);
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                      WHERE kind='mcp_user_token' AND provider=$1
                        AND metadata->>'revocation_status'='pending'",
                    &[&SERVER],
                )
                .await
                .map_err(|error| error.to_string())?;
            let removal_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if removal_sweep.attempted != 1
                || removal_sweep.revoked != 1
                || removal_sweep.pending != 0
                || removal_sweep.operator_required != 0
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 5
            {
                return Err("server-removal revocation used replacement authority".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let removal_final = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE kind='mcp_user_token' AND provider=$1
                           AND metadata->>'revocation_reason'='mcp_server_removed'
                           AND metadata->>'revocation_status'='revoked'
                           AND NOT metadata ? 'server_removal_revocation'),
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE id=$2 AND revoked_at IS NOT NULL
                           AND metadata->>'revocation_status'='operator_required'
                           AND metadata ? 'user_token_revocations_completed_at'),
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE id=$3 AND revoked_at IS NULL),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='configuration.changed' AND target_type='mcp_server'
                           AND target_id=$1 AND payload->>'change'='mcp_server_removed')",
                    &[&SERVER, &old_client_id, &replacement_client_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            let token_revoked: i64 =
                removal_final.try_get(0).map_err(|error| error.to_string())?;
            let client_operator: i64 =
                removal_final.try_get(1).map_err(|error| error.to_string())?;
            let replacement_live: i64 =
                removal_final.try_get(2).map_err(|error| error.to_string())?;
            let removal_audit: i64 =
                removal_final.try_get(3).map_err(|error| error.to_string())?;
            if token_revoked != 1
                || client_operator != 1
                || replacement_live != 1
                || removal_audit != 1
            {
                return Err("server-removal final compensation/runbook state drift".to_owned());
            }
            drop(pg);
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let evidence = pg
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.verifications
                         WHERE identifier LIKE 'mcp-oauth-attempt:%'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.account_connected' AND actor_user_id=$1),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.account_disconnected' AND actor_user_id=$1
                           AND payload->>'vendor_revoked'='false'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.account_disconnected' AND actor_user_id=$1
                           AND payload->>'vendor_revoked'='true'),
                       (SELECT count(*)::bigint FROM public.credentials
                         WHERE kind='mcp_user_token' AND key_id=$1
                           AND encrypted_value LIKE '%connected-refresh%')",
                    &[&ACTOR],
                )
                .await
                .map_err(|error| error.to_string())?;
            let attempts: i64 = evidence.try_get(0).map_err(|error| error.to_string())?;
            let connected: i64 = evidence.try_get(1).map_err(|error| error.to_string())?;
            let local_disconnects: i64 = evidence.try_get(2).map_err(|error| error.to_string())?;
            let vendor_disconnects: i64 = evidence.try_get(3).map_err(|error| error.to_string())?;
            let plaintext: i64 = evidence.try_get(4).map_err(|error| error.to_string())?;
            if attempts != 0
                || connected != 3
                || local_disconnects != 3
                || vendor_disconnects != 3
                || plaintext != 0
            {
                return Err("connect/disconnect audit or secret evidence drift".to_owned());
            }
            drop(pg);

            let empty_server = "oauth-empty";
            let empty_client_id = uuid::Uuid::now_v7();
            let valid_retained_client = serde_json::to_vec(&serde_json::json!({
                "clientId":CLIENT_ID,
                "clientSecret":CLIENT_SECRET,
                "issuer":spawned.state.issuer.as_ref(),
                "tokenEndpointAuthMethod":"client_secret_basic"
            }))
            .map_err(|error| error.to_string())?;
            let empty_client_ciphertext = vault
                .seal(
                    &empty_client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(empty_server)),
                    &SecretBytes::new(valid_retained_client),
                )
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}')",
                &[&empty_client_id, &empty_server, &empty_client_ciphertext],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,transport,egress_allow_cidrs)
                 VALUES($1,'Empty OAuth','oauth-empty',$2,'custom',$3,
                        'mcp',ARRAY['127.0.0.1/32'])",
                &[&empty_server, &spawned.resource, &empty_client_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            connections
                .remove_server(&auth, empty_server)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let empty_result = pg
                .query_one(
                    "SELECT
                       NOT EXISTS(SELECT 1 FROM public.mcp_servers WHERE id=$1),
                       revoked_at IS NOT NULL,
                       metadata->>'revocation_status'='operator_required',
                       metadata ? 'operator_required_at',
                       metadata ? 'user_token_revocations_completed_at',
                       metadata#>>'{server_removal_revocation,client_credential_id}'=$2
                     FROM public.credentials WHERE id=$3",
                    &[
                        &empty_server,
                        &empty_client_id.to_string(),
                        &empty_client_id,
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;
            if !(0..6).all(|index| empty_result.try_get::<_, bool>(index).unwrap_or(false)) {
                return Err("zero-user OAuth client remained retained without operator work".to_owned());
            }
            drop(pg);

            let corrupt_server = "oauth-corrupt";
            let corrupt_client_id = uuid::Uuid::now_v7();
            let corrupt_client_ciphertext = vault
                .seal(
                    &corrupt_client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(corrupt_server)),
                    &SecretBytes::new(b"not-a-client-registration".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            let corrupt_user_token_id = uuid::Uuid::now_v7();
            let corrupt_user_token = vault
                .seal(
                    &corrupt_user_token_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(ActorId::new(OTHER)),
                    SecretPrincipal::Service(ServiceId::new(corrupt_server)),
                    &SecretBytes::new(b"corrupt-client-refresh".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}'),
                       ($4,'mcp_user_token',$2,$5,$6,
                        '{\"revocation_status\":\"active\"}'::jsonb)",
                &[
                    &corrupt_client_id,
                    &corrupt_server,
                    &corrupt_client_ciphertext,
                    &corrupt_user_token_id,
                    &corrupt_user_token,
                    &OTHER,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,transport,egress_allow_cidrs)
                 VALUES($1,'Corrupt OAuth','oauth-corrupt',$2,'custom',$3,
                        'mcp',ARRAY['127.0.0.1/32'])",
                &[&corrupt_server, &spawned.resource, &corrupt_client_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_user_credentials(
                   server_id,user_id,credential_id,scope)
                 VALUES($1,$2,$3,$4)",
                &[&corrupt_server, &OTHER, &corrupt_user_token_id, &SCOPE],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            connections
                .remove_server(&auth, corrupt_server)
                .await
                .map_err(|error| error.to_string())?;
            let corrupt_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if corrupt_sweep.attempted != 0
                || corrupt_sweep.revoked != 0
                || corrupt_sweep.pending != 0
                || corrupt_sweep.operator_required != 0
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 5
            {
                return Err("operator-required credential entered an automatic retry loop".to_owned());
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let corrupt_result = pg
                .query_one(
                    "SELECT
                       NOT EXISTS(SELECT 1 FROM public.mcp_servers WHERE id=$1),
                       NOT EXISTS(SELECT 1 FROM public.mcp_user_credentials WHERE server_id=$1),
                       (SELECT revoked_at IS NOT NULL
                          AND metadata->>'revocation_status'='operator_required'
                          AND metadata ? 'operator_required_at'
                          AND metadata#>'{server_removal_revocation,client_credential_id}'='null'::jsonb
                          FROM public.credentials WHERE id=$2),
                       (SELECT revoked_at IS NOT NULL
                          AND metadata->>'revocation_status'='operator_required'
                          AND metadata ? 'operator_required_at'
                          FROM public.credentials WHERE id=$3),
                       (SELECT count(*)=1 FROM public.audit_events
                         WHERE event_type='mcp.account_disconnected' AND actor_user_id=$4
                           AND target_id=$1 AND payload->>'vendor_revoked'='false'
                           AND payload->>'revocation_reason'='mcp_server_removed')",
                    &[
                        &corrupt_server,
                        &corrupt_user_token_id,
                        &corrupt_client_id,
                        &OTHER,
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;
            if !(0..5).all(|index| corrupt_result.try_get::<_, bool>(index).unwrap_or(false)) {
                return Err("corrupt retained client did not fail closed to operator work".to_owned());
            }
            drop(pg);

            let post_corrupt_server = "oauth-post-corrupt";
            let post_corrupt_client_id = uuid::Uuid::now_v7();
            let post_corrupt_client = serde_json::to_vec(&serde_json::json!({
                "clientId":CLIENT_ID,
                "clientSecret":CLIENT_SECRET,
                "issuer":spawned.state.issuer.as_ref(),
                "tokenEndpointAuthMethod":"client_secret_basic"
            }))
            .map_err(|error| error.to_string())?;
            let post_corrupt_client_ciphertext = vault
                .seal(
                    &post_corrupt_client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(post_corrupt_server)),
                    &SecretBytes::new(post_corrupt_client),
                )
                .map_err(|error| error.to_string())?;
            let post_corrupt_user_token_id = uuid::Uuid::now_v7();
            let post_corrupt_user_token = vault
                .seal(
                    &post_corrupt_user_token_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(ActorId::new(OTHER)),
                    SecretPrincipal::Service(ServiceId::new(post_corrupt_server)),
                    &SecretBytes::new(b"post-removal-refresh".to_vec()),
                )
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}'),
                       ($4,'mcp_user_token',$2,$5,$6,
                        '{\"revocation_status\":\"active\"}'::jsonb)",
                &[
                    &post_corrupt_client_id,
                    &post_corrupt_server,
                    &post_corrupt_client_ciphertext,
                    &post_corrupt_user_token_id,
                    &post_corrupt_user_token,
                    &OTHER,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,transport,egress_allow_cidrs)
                 VALUES($1,'Post-removal corruption','oauth-post-corrupt',$2,'custom',$3,
                        'mcp',ARRAY['127.0.0.1/32'])",
                &[
                    &post_corrupt_server,
                    &spawned.resource,
                    &post_corrupt_client_id,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_user_credentials(
                   server_id,user_id,credential_id,scope)
                 VALUES($1,$2,$3,$4)",
                &[
                    &post_corrupt_server,
                    &OTHER,
                    &post_corrupt_user_token_id,
                    &SCOPE,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            connections
                .remove_server(&auth, post_corrupt_server)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.credentials SET encrypted_value='corrupt-after-removal'
                  WHERE id=$1",
                &[&post_corrupt_client_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                  WHERE id=$1 AND metadata->>'revocation_status'='pending'",
                &[&post_corrupt_user_token_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let post_corrupt_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            let post_corrupt_second_sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if post_corrupt_sweep.attempted != 1
                || post_corrupt_sweep.revoked != 0
                || post_corrupt_sweep.pending != 0
                || post_corrupt_sweep.operator_required != 1
                || post_corrupt_second_sweep.attempted != 0
                || spawned.state.revoke_calls.load(Ordering::SeqCst) != 5
            {
                return Err("post-removal corruption was retried or reached the vendor".to_owned());
            }
            let post_corrupt_result = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT
                       (SELECT metadata->>'revocation_status'='operator_required'
                          AND metadata ? 'operator_required_at'
                          FROM public.credentials WHERE id=$1),
                       (SELECT metadata->>'revocation_status'='operator_required'
                          AND metadata ? 'automatic_user_token_revocation_failed_at'
                          FROM public.credentials WHERE id=$2),
                       (SELECT count(*)=1 FROM public.audit_events
                         WHERE event_type='mcp.account_disconnected' AND actor_user_id=$3
                           AND target_id=$4 AND payload->>'vendor_revoked'='false'
                           AND payload->>'revocation_reason'='vendor_revoke_operator_required')",
                    &[
                        &post_corrupt_user_token_id,
                        &post_corrupt_client_id,
                        &OTHER,
                        &post_corrupt_server,
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;
            if !(0..3).all(|index| {
                post_corrupt_result
                    .try_get::<_, bool>(index)
                    .unwrap_or(false)
            }) {
                return Err("post-removal corruption operator state/audit drift".to_owned());
            }

            let mismatch_server = "oauth-mismatch";
            let unrelated_credential_id = uuid::Uuid::now_v7();
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata)
                 VALUES($1,'model','unrelated-provider','opaque','unrelated','{}')",
                &[&unrelated_credential_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,transport,egress_allow_cidrs)
                 VALUES($1,'Mismatched','oauth-mismatch',$2,'custom',$3,
                        'mcp',ARRAY['127.0.0.1/32'])",
                &[&mismatch_server, &spawned.resource, &unrelated_credential_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            connections
                .remove_server(&auth, mismatch_server)
                .await
                .map_err(|error| error.to_string())?;
            let mismatch_intact: bool = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT revoked_at IS NULL
                         AND NOT metadata ? 'revocation_reason'
                         AND NOT EXISTS(SELECT 1 FROM public.mcp_servers WHERE id=$2)
                       FROM public.credentials WHERE id=$1",
                    &[&unrelated_credential_id, &mismatch_server],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if !mismatch_intact {
                return Err("corrupt server pointer revoked an unrelated credential".to_owned());
            }
            spawned.handle.abort();
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
