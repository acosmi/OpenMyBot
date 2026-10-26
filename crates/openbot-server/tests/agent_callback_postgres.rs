//! Axum + production session + ApplicationService + PostgreSQL remote callback security slice.

#[path = "support/transport_fixture.rs"]
mod transport_fixture;

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use harness::{admin_config, with_temp_database};
use http::{Method, Request, StatusCode};
use openbot_agent::{AuthorizedAgentToolGateway, RemoteAgentToolInvoker};
use openbot_application::{
    AgentContextSource, ApplicationService, OpenBotApplication, ProviderRoute, RunExecutionLease,
};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::{
    RemoteRunAssertionSigner, RemoteRunScope, RemoteToolSet, callback_token_hash,
};
use openbot_domain::thread::FencingToken;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::agent_callback::{
    PostgresAgentCallbackTokens, PostgresRemoteCallbackAuthenticator,
};
use openbot_infra::agent_tools::{
    PostgresAgentAuthorizationSource, PostgresAgentToolSequence, PostgresBuiltInToolControlPlane,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::mcp::{McpClientError, SafeRmcpClient};
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

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

const RAW_SESSION: &str = "callback-http-session-token-with-enough-entropy";
const SESSION_KEY: &[u8] = b"callback-http-session-hash-key";
const AUDIT_KEY: &[u8] = b"callback-http-audit-checkpoint-key";
const ORIGIN: &str = "https://app.example.test";
const CALLBACK_MCP_BEARER: &str = "callback-mcp-bearer-with-test-entropy";

#[derive(Clone)]
struct CallbackMcpHttpAuth {
    rejected: Arc<AtomicUsize>,
    challenge: Arc<str>,
}

async fn require_callback_mcp_bearer(
    State(state): State<CallbackMcpHttpAuth>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let expected = format!("Bearer {CALLBACK_MCP_BEARER}");
    if request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(expected.as_str())
    {
        state.rejected.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::UNAUTHORIZED,
            [(http::header::WWW_AUTHENTICATE, state.challenge.as_ref())],
        )
            .into_response();
    }
    next.run(request).await
}

#[derive(Clone)]
struct CallbackMcpServer {
    received: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl ServerHandler for CallbackMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("openbot-callback-test", "3.1.4"))
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "search_notes",
            "Search the notes.",
            serde_json::json!({
                "type":"object",
                "properties":{"query":{"type":"string"}},
                "required":["query"]
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
            ContentBlock::text(format!("Found one note about {query}.")),
        ])))
    }
}

async fn spawn_callback_mcp_server() -> Result<
    (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let received = Arc::new(Mutex::new(Vec::new()));
    let rejected = Arc::new(AtomicUsize::new(0));
    let server = CallbackMcpServer {
        received: received.clone(),
    };
    let service = StreamableHttpService::new(
        move || Ok::<_, std::io::Error>(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let rejected_server = rejected.clone();
    let handle = tokio::spawn(async move {
        let router = axum::Router::new().nest_service("/mcp", service).layer(
            axum::middleware::from_fn_with_state(
                CallbackMcpHttpAuth {
                    rejected: rejected_server,
                    challenge: Arc::from(format!(
                        "Bearer resource_metadata=\"http://{address}/.well-known/oauth-protected-resource/mcp\""
                    )),
                },
                require_callback_mcp_bearer,
            ),
        );
        let _ = axum::serve(listener, router).await;
    });
    Ok((format!("http://{address}/mcp"), received, rejected, handle))
}

fn callback_mcp_client() -> SafeRmcpClient {
    SafeRmcpClient::new(
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
        )),
        SchemePolicy::HttpOrHttps,
        Some(std::time::Duration::from_secs(2)),
    )
}

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    let now = OffsetDateTime::now_utc();
    let token_hash = SessionTokenHash::compute(
        SessionToken::new(RAW_SESSION.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    client
        .execute(
            "INSERT INTO public.users(id,email,name,auth_generation) VALUES($1,$2,$3,0)",
            &[&"owner-a", &"owner@example.test", &"Owner"],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.user_roles(user_id,role) VALUES('owner-a','user')",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.sessions(
               id,user_id,token,expires_at,created_at,updated_at,auth_generation
             ) VALUES($1,'owner-a',$2,$3,$4,$4,0)",
            &[
                &"session-callback",
                &token_hash,
                &(now + Duration::hours(1)),
                &(now - Duration::minutes(1)),
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES(
               'remote-owner','Owner Remote','remote_ag_ui',
               '{\"endpoint\":\"https://remote.invalid\"}',NULL
             );
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('remote-owner','owner-a','Owner Remote','role','seed','private',NULL);
             INSERT INTO public.threads(
               thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
               next_message_seq,next_event_seq,created_at,updated_at
             ) VALUES(
               'thread-callback','tenant-a','deployment-a','owner-a','direct_bot',
               'remote-owner','active',0,0,clock_timestamp(),clock_timestamp()
             );
             INSERT INTO public.thread_memberships(thread_id,user_id)
               VALUES('thread-callback','owner-a');
             INSERT INTO public.runs(
               run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
               next_event_seq,created_at,started_at
             ) VALUES(
               'run-callback','thread-callback','remote-owner','owner-a',true,'running',1,
               0,clock_timestamp(),clock_timestamp()
             );
             INSERT INTO public.thread_leases(
               thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
             ) VALUES(
               'thread-callback','runtime-a',1,clock_timestamp(),
               clock_timestamp()+interval '10 minutes',clock_timestamp()
             );",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn send(
    app: axum::Router,
    method: Method,
    path: &str,
    origin: Option<&str>,
    agent_token: Option<&str>,
    body: Option<String>,
) -> Result<(StatusCode, Vec<u8>), String> {
    let mut request = Request::builder().method(method).uri(path).header(
        http::header::COOKIE,
        format!("openbot_session={RAW_SESSION}"),
    );
    if let Some(origin) = origin {
        request = request.header(http::header::ORIGIN, origin);
    }
    if let Some(token) = agent_token {
        request = request.header("x-openbot-agent-token", token);
    }
    let body = match body {
        Some(body) => {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
            Body::from(body)
        }
        None => Body::empty(),
    };
    let response = app
        .oneshot(request.body(body).map_err(|error| error.to_string())?)
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .map_err(|error| error.to_string())?
        .to_vec();
    Ok((status, bytes))
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn production_http_issues_hash_only_token_and_refuses_ungranted_callback() {
    let admin =
        admin_config("production_http_issues_hash_only_token_and_refuses_ungranted_callback");
    with_temp_database(&admin, "callbackhttp", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let deployment = DeploymentId::new("deployment-a");
            let tenant = TenantId::new("tenant-a");
            let signer = Arc::new(
                RemoteRunAssertionSigner::new(b"callback-http-master".to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let token_store = PostgresAgentCallbackTokens::new(
                pool.clone(),
                deployment.clone(),
                tenant.clone(),
                AUDIT_KEY.to_vec(),
            )
            .map_err(|error| error.to_string())?;
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_agent_callback_tokens(token_store),
            );
            let resolver = PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|error| error.to_string())?;
            let authenticator = Arc::new(
                PostgresRemoteCallbackAuthenticator::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                    signer.clone(),
                    AUDIT_KEY.to_vec(),
                )
                .map_err(|error| error.to_string())?,
            );
            let app = transport_fixture::loopback_router(
                ServerBuilder::new(application, Arc::new(resolver))
                    .with_transport_policy(transport_fixture::loopback_policy())
                    .with_sensitive_write_security(SensitiveWriteSecurity::new(
                        default_session_lifetime(),
                        TrustedOrigins::from_configured([ORIGIN])
                            .map_err(|error| error.to_string())?,
                    ))
                    .with_remote_callback_authenticator(authenticator)
                    .build(),
            );

            let (status, _) = send(
                app.clone(),
                Method::POST,
                "/api/agents/remote-owner/callback-token",
                None,
                None,
                None,
            )
            .await?;
            if status != StatusCode::FORBIDDEN {
                return Err(format!("missing Origin status drift: {status}"));
            }

            let (status, body) = send(
                app.clone(),
                Method::POST,
                "/api/agents/remote-owner/callback-token",
                Some(ORIGIN),
                None,
                None,
            )
            .await?;
            if status != StatusCode::CREATED {
                return Err(format!("callback token issue status drift: {status}"));
            }
            let body: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            let token = body["token"]
                .as_str()
                .ok_or_else(|| "callback token response missing".to_owned())?
                .to_owned();
            let expected_hash = callback_token_hash(&token)
                .map_err(|error| error.to_string())?
                .to_hex();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let stored: Option<String> = client
                .query_one(
                    "SELECT callback_token_hash FROM public.agent_profiles \
                      WHERE agent_id='remote-owner'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let now_millis: i64 = client
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if stored.as_deref() != Some(expected_hash.as_str())
                || stored.as_deref() == Some(token.as_str())
            {
                return Err("HTTP issue did not store hash-only".to_owned());
            }
            drop(client);
            let assertion = signer
                .mint(
                    RemoteRunScope {
                        deployment,
                        tenant,
                        bot: BotId::new("remote-owner"),
                        actor: ActorId::new("owner-a"),
                        run: RunId::new("run-callback"),
                    },
                    &RemoteToolSet::empty(),
                    now_millis,
                )
                .map_err(|error| error.to_string())?;
            let callback_body = serde_json::json!({
                "name":"mcp__drive__search",
                "args":{},
                "run":assertion,
            })
            .to_string();
            let (status, _) = send(
                app.clone(),
                Method::POST,
                "/api/agent-tools/call",
                None,
                Some(&token),
                Some(callback_body.clone()),
            )
            .await?;
            if status != StatusCode::NOT_FOUND {
                return Err(format!("ungranted callback status drift: {status}"));
            }
            let unknown = openbot_domain::remote_callback::callback_token_from_entropy([0x44; 32]);
            let (status, _) = send(
                app.clone(),
                Method::POST,
                "/api/agent-tools/call",
                None,
                Some(&unknown),
                Some(callback_body),
            )
            .await?;
            if status != StatusCode::UNAUTHORIZED {
                return Err(format!("unknown callback status drift: {status}"));
            }

            let (status, body) = send(
                app,
                Method::DELETE,
                "/api/agents/remote-owner/callback-token",
                Some(ORIGIN),
                None,
                None,
            )
            .await?;
            if status != StatusCode::NO_CONTENT || !body.is_empty() {
                return Err(format!("callback revoke response drift: {status}/{body:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let evidence = client
                .query_one(
                    "SELECT callback_token_hash IS NULL,callback_token_issued_at IS NULL,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='bot.callback_token_issued'
                                AND target_id='remote-owner'),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='bot.callback_token_revoked'
                                AND target_id='remote-owner'),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.callback_refused')
                       FROM public.agent_profiles WHERE agent_id='remote-owner'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let hash_null: bool = evidence.try_get(0).map_err(|error| error.to_string())?;
            let issued_null: bool = evidence.try_get(1).map_err(|error| error.to_string())?;
            let issued: i64 = evidence.try_get(2).map_err(|error| error.to_string())?;
            let revoked: i64 = evidence.try_get(3).map_err(|error| error.to_string())?;
            let refused: i64 = evidence.try_get(4).map_err(|error| error.to_string())?;
            if !hash_null || !issued_null || issued != 1 || revoked != 1 || refused != 2 {
                return Err(format!(
                    "HTTP callback durable evidence drift: hash_null={hash_null} issued_null={issued_null} issued={issued} revoked={revoked} refused={refused}"
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
async fn production_callback_http_reaches_governed_real_rmcp_with_durable_sequence() {
    let admin =
        admin_config("production_callback_http_reaches_governed_real_rmcp_with_durable_sequence");
    with_temp_database(&admin, "callbackrmcp", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let (mcp_url, received, rejected_http, mcp_server) =
                spawn_callback_mcp_server().await?;
            let credential_vault = CredentialRecordVault::single_key(
                TenantId::new("tenant-a"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x62; 32]).map_err(|error| error.to_string())?,
            );
            let credential_id = uuid::Uuid::now_v7();
            let encrypted_bearer = credential_vault
                .seal(
                    &credential_id,
                    SecretKind::Mcp,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new("notes")),
                    &SecretBytes::new(CALLBACK_MCP_BEARER.as_bytes().to_vec()),
                )
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(
                   id,kind,provider,encrypted_value,key_id,metadata
                 ) VALUES($1,'mcp','notes',$2,'deployment-mcp-test','{}')",
                &[&credential_id, &encrypted_bearer],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,credential_id,egress_allow_cidrs
                 ) VALUES('notes','Notes','notes',$1,'custom',$2,ARRAY['127.0.0.1/32'])",
                &[&mcp_url, &credential_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by)
                   VALUES('mcp','notes/search_notes','remote-owner','owner-a')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                   VALUES('tenant-a','/callback-fixture',repeat('b',64));
                 UPDATE public.agents SET package_id=(
                   SELECT id FROM public.deployment_packages WHERE tenant_id='tenant-a'
                 ) WHERE id='remote-owner';
                 UPDATE public.threads SET next_message_seq=1 WHERE thread_id='thread-callback';
                 INSERT INTO public.messages(
                   message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                 ) VALUES(
                   'message-callback','thread-callback',0,'user',
                   '{\"text\":\"Search invoices.\"}','Search invoices.',
                   'run-callback','owner-a',clock_timestamp()
                 );",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let rmcp = callback_mcp_client();
            if rmcp.list_tools(&mcp_url, None).await != Err(McpClientError::AuthRequired) {
                return Err("protected RMCP 401 was not classified as AuthRequired".to_owned());
            }
            let credential_broker = Arc::new(PostgresMcpCredentialBroker::new(
                pool.clone(),
                credential_vault,
            ));
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp.clone(), AUDIT_KEY.to_vec())
                    .map_err(|error| error.to_string())?,
            );
            if catalog.refresh("notes", None).await.is_ok() {
                return Err("protected RMCP catalog refreshed without bearer".to_owned());
            }
            let bearer = credential_broker
                .bearer_for("notes", &ActorId::new("owner-a"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "deployment bearer resolved as anonymous".to_owned())?;
            catalog
                .refresh("notes", Some(bearer))
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_tools SET effect='read'
                   WHERE server_id='notes' AND name='search_notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let bearer = credential_broker
                .bearer_for("notes", &ActorId::new("owner-a"))
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "deployment bearer disappeared".to_owned())?;
            catalog
                .refresh("notes", Some(bearer))
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.plugin_grants g SET state='active',
                   catalog_generation=s.catalog_generation,schema_hash=t.schema_hash,
                   effect=t.effect,transport_fingerprint=s.catalog_transport_fingerprint,
                   updated_at=clock_timestamp()
                  FROM public.mcp_tools t JOIN public.mcp_servers s ON s.id=t.server_id
                 WHERE g.kind='mcp' AND g.ref='notes/search_notes'
                   AND g.agent_id='remote-owner' AND t.server_id='notes'
                   AND t.name='search_notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let deployment = DeploymentId::new("deployment-a");
            let tenant = TenantId::new("tenant-a");
            let signer = Arc::new(
                RemoteRunAssertionSigner::new(b"callback-real-rmcp-master".to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let lease = RunExecutionLease::new(
                RunId::new("run-callback"),
                openbot_contracts::ids::ThreadId::new("thread-callback"),
                BotId::new("remote-owner"),
                ActorId::new("owner-a"),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let remote_request = PostgresAgentContextSource::new(
                pool.clone(),
                deployment.clone(),
                tenant.clone(),
                None,
            )
            .map_err(|error| error.to_string())?
            .with_remote_assertions(signer.clone())
            .with_mcp_catalog(catalog.clone())
            .load(&lease)
            .await
            .map_err(|error| error.to_string())?;
            if remote_request.tools.len() != 1
                || remote_request.tools[0].name != "mcp__notes__search_notes"
                || remote_request.tools[0].input_schema["required"] != serde_json::json!(["query"])
            {
                return Err(format!(
                    "remote RunAgentInput tool projection drift: {:?}",
                    remote_request.tools
                ));
            }
            let assertion = match &remote_request.route {
                ProviderRoute::RemoteAgUi(route) => route
                    .run_assertion()
                    .ok_or_else(|| "remote assertion missing".to_owned())?
                    .to_owned(),
                ProviderRoute::PackageOpenAi
                | ProviderRoute::Managed
                | ProviderRoute::CustomModel(_) => {
                    return Err("remote Agent selected a local provider route".to_owned());
                }
                ProviderRoute::Extension(_) => {
                    return Err("remote Agent selected an unexpected extension route".to_owned());
                }
            };
            let policy = PolicyStore::postgres(pool.clone(), None);
            policy.load().await.map_err(|error| error.to_string())?;
            policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: Vec::new(),
                        allow: vec!["true".to_owned()],
                    },
                    Some("owner-a"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let memory = PostgresMemoryAdministration::new(pool.clone());
            let control = PostgresBuiltInToolControlPlane::new(
                pool.clone(),
                deployment.clone(),
                tenant.clone(),
                policy.clone(),
                Arc::new(memory.clone()),
            )
            .with_mcp(catalog.clone(), rmcp)
            .with_mcp_credentials(credential_broker.clone());
            let callback_tokens = PostgresAgentCallbackTokens::new(
                pool.clone(),
                deployment.clone(),
                tenant.clone(),
                AUDIT_KEY.to_vec(),
            )
            .map_err(|error| error.to_string())?;
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policy)
                    .with_tools(
                        control,
                        PostgresToolJournal::new(pool.clone(), AUDIT_KEY.to_vec())
                            .map_err(|error| error.to_string())?,
                    )
                    .with_memory(memory)
                    .with_agent_callback_tokens(callback_tokens),
            );
            let resolver = PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|error| error.to_string())?;
            let authenticator = Arc::new(
                PostgresRemoteCallbackAuthenticator::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                    signer.clone(),
                    AUDIT_KEY.to_vec(),
                )
                .map_err(|error| error.to_string())?
                .with_mcp_catalog(catalog.clone()),
            );
            let governed = Arc::new(AuthorizedAgentToolGateway::with_sequence(
                application.clone(),
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    deployment.clone(),
                    tenant.clone(),
                    false,
                )),
                Arc::new(PostgresAgentToolSequence::new(pool.clone())),
            ));
            let callback_tools: Arc<dyn RemoteAgentToolInvoker> = governed;
            let app = transport_fixture::loopback_router(
                ServerBuilder::new(application, Arc::new(resolver))
                    .with_transport_policy(transport_fixture::loopback_policy())
                    .with_sensitive_write_security(SensitiveWriteSecurity::new(
                        default_session_lifetime(),
                        TrustedOrigins::from_configured([ORIGIN])
                            .map_err(|error| error.to_string())?,
                    ))
                    .with_remote_callback_authenticator(authenticator)
                    .with_remote_callback_tools(callback_tools)
                    .build(),
            );

            let (status, body) = send(
                app.clone(),
                Method::POST,
                "/api/agents/remote-owner/callback-token",
                Some(ORIGIN),
                None,
                None,
            )
            .await?;
            if status != StatusCode::CREATED {
                return Err(format!("callback token issue status drift: {status}"));
            }
            let body: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            let token = body["token"]
                .as_str()
                .ok_or_else(|| "callback token response missing".to_owned())?;
            let callback = serde_json::json!({
                "name":"mcp__notes__search_notes",
                "args":{"query":"invoices"},
                "run":assertion,
            })
            .to_string();
            let (status, body) = send(
                app,
                Method::POST,
                "/api/agent-tools/call",
                None,
                Some(token),
                Some(callback),
            )
            .await?;
            let body: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            if status != StatusCode::OK
                || body["isError"] != serde_json::json!(false)
                || !body["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("Found one note about invoices"))
                || received.lock().unwrap().as_slice() != [serde_json::json!({"query":"invoices"})]
                || rejected_http.load(Ordering::SeqCst) == 0
            {
                return Err(format!("real callback result drift: {status}/{body}"));
            }
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let evidence = pg
                .query_one(
                    "SELECT
                       (SELECT next_tool_call_seq FROM public.runs WHERE run_id='run-callback'),
                       (SELECT count(*)::bigint FROM public.tool_calls
                         WHERE run_id='run-callback' AND call_seq=0
                           AND bot_id='remote-owner' AND actor_id='owner-a'),
                       (SELECT count(*)::bigint FROM public.audit_events
                         WHERE event_type='mcp.call_succeeded'
                           AND target_id='notes/search_notes'
                           AND payload->>'bot'='remote-owner'
                           AND actor_user_id='owner-a')",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let sequence: Option<i64> = evidence.try_get(0).map_err(|error| error.to_string())?;
            let calls: i64 = evidence.try_get(1).map_err(|error| error.to_string())?;
            let audits: i64 = evidence.try_get(2).map_err(|error| error.to_string())?;
            if sequence != Some(1) || calls != 1 || audits != 1 {
                return Err(format!(
                    "callback durable evidence drift: {sequence:?}/{calls}/{audits}"
                ));
            }
            pg.execute(
                "UPDATE public.credentials SET revoked_at=clock_timestamp() WHERE id=$1",
                &[&credential_id],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            if !matches!(
                credential_broker
                    .bearer_for("notes", &ActorId::new("owner-a"))
                    .await,
                Err(McpCredentialError::AuthRequired)
            ) || !catalog
                .granted_tools(&BotId::new("remote-owner"), &ActorId::new("owner-a"))
                .await
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err("revoked deployment bearer remained usable/visible".to_owned());
            }
            mcp_server.abort();
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
