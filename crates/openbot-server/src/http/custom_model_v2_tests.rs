//! Real binary composition tests. This module is intentionally a child of main.rs, so its
//! consumer is the actual private build_built_in_agent rather than a parallel test assembly.
//! The only replaced I/O is DNS and the owned TLS trust root. PostgreSQL, Vault, context,
//! custom provider, Agent runtime and remember tool use their production implementations.

use super::*;
use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use http::{Request, StatusCode};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{AgentContextSource, RunDispatchDecision};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, ThreadRunStarted};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_infra::application_assembly::PostgresApplicationAssembly;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::db::fresh;
use openbot_infra::net::safe_http::{DnsResolver, DnsUnavailable};
use serde_json::{Value, json};
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use time::OffsetDateTime;
use tower::ServiceExt as _;

mod harness {
    use std::future::Future;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}

const DEP: &str = "owned-v2-server-deployment";
const TENANT: &str = "owned-v2-server-tenant";
const ACTOR: &str = "owned-v2-server-owner";
const SESSION_KEY: &[u8] = b"owned-v2-server-session-hash-key";
const COOKIE: &str = "owned-v2-server-cookie-00000000001";
const NEW_COOKIE: &str = "owned-v2-server-cookie-00000000002";
const ORIGIN: &str = "https://owned-v2-server.example.test";
const API_KEY: &str = "OWNED_V2_HOST_SYNTHETIC_KEY";
const PROXY_SECRET: &str = "2525252525252525252525252525252525252525252525252525252525252525";

struct ClosedRemoteProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedRemoteProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}

struct ServerFixture {
    pool: pool::DatabasePool,
    assembly: Option<PostgresApplicationAssembly>,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    vault: CredentialRecordVault,
    assertions: Arc<RemoteRunAssertionSigner>,
    resolver: Arc<PostgresSessionAuthResolver>,
}

impl ServerFixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let config = config.with_max_pool_size(6);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        fresh::apply(&mut client).await.map_err(|e| e.to_string())?;
        client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('owned-v2-server-owner','owned-v2-server@example.test',7); INSERT INTO public.user_roles(user_id,role) VALUES('owned-v2-server-owner','user'); INSERT INTO public.agents(id,name,type,configuration) VALUES('owned-v2-bot','Owned V2 bot','built_in','{\"systemPrompt\":\"Remember the requested fact, then answer.\",\"providerSource\":\"package\"}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('owned-v2-bot','owned-v2-server-owner','Owned V2 bot','','owned','public');").await.map_err(|e| e.to_string())?;
        let now = OffsetDateTime::now_utc();
        for (id, cookie) in [
            ("owned-v2-server-session", COOKIE),
            ("owned-v2-server-new-session", NEW_COOKIE),
        ] {
            let hash = SessionTokenHash::compute(
                SessionToken::new(cookie.as_bytes()),
                SessionHashKey::new(SESSION_KEY),
            )
            .to_column_value();
            client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,7)", &[&id,&ACTOR,&hash,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e| e.to_string())?;
        }
        drop(client);
        let deployment = DeploymentId::new(DEP);
        let tenant = TenantId::new(TENANT);
        let vault = CredentialRecordVault::single_key(
            tenant.clone(),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x41; 32]).map_err(|e| e.to_string())?,
        );
        let assertions =
            Arc::new(RemoteRunAssertionSigner::new(vec![0x42; 32]).map_err(|e| e.to_string())?);
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let policy_store = PolicyStore::postgres(pool.clone(), None);
        policy_store.set(openbot_domain::policy::ActionPolicy {
            mode: openbot_domain::policy::PolicyMode::Enforce,
            deny: vec![],
            allow: vec![r#"tool.name == "remember" && bot.id == "owned-v2-bot" && actor.id == "owned-v2-server-owner""#.to_owned()],
        }, Some(ACTOR)).await.map_err(|e|e.to_string())?;
        require(
            policy_store.load().await.map_err(|e| e.to_string())?
                == openbot_infra::policy::PolicyOrigin::Database,
            "custom-V2 policy must load from database",
        )?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: pool.clone(),
            listener_database: config.into(),
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            single_user: false,
            admin_floor: None,
            model: "unselected-package-model".to_owned(),
            credential_key_id: "unused-package-key".to_owned(),
            credential_vault: vault.clone(),
            audit_key: SecretBytes::new(vec![0x43; 32]),
            remote_assertions: assertions.clone(),
            mcp_oauth_state_key: SecretBytes::new(vec![0x44; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedRemoteProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: Url::parse("https://unused-package.example.test/v1/chat/completions")
                    .map_err(|e| e.to_string())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: false,
            },
            stall_timeout: Some(Duration::from_secs(3)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(|e| e.to_string())?;
        assembly
            .model_dataset_binding
            .enroll_original_registry(&registry)
            .map_err(|e| e.to_string())?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(|e| e.to_string())?,
        );
        Ok(Self {
            pool,
            assembly: Some(assembly),
            registry: Some(registry),
            vault,
            assertions,
            resolver,
        })
    }

    fn assembly(&self) -> &PostgresApplicationAssembly {
        self.assembly.as_ref().expect("assembly already closed")
    }

    fn router(&self) -> axum::Router {
        let environment = openbot_server::config::EnvMap::from([
            ("OPENBOT_PUBLIC_URL".to_owned(), ORIGIN.to_owned()),
            (
                "OPENBOT_TLS_PROXY_SECRET".to_owned(),
                PROXY_SECRET.to_owned(),
            ),
        ]);
        let configuration = openbot_server::config::ServerConfig::from_env_map(&environment)
            .expect("owned HTTPS proxy configuration");
        ServerBuilder::new(
            Arc::clone(&self.assembly().application),
            self.resolver.clone(),
        )
        .with_transport_policy(configuration.transport_policy(false))
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).unwrap(),
        ))
        .into_router()
    }

    async fn auth(&self) -> Result<AuthContext, String> {
        self.resolver
            .resolve(
                &Request::builder()
                    .uri("/api/threads/mint")
                    .header("cookie", format!("openbot_session={COOKIE}"))
                    .body(())
                    .map_err(|e| e.to_string())?
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())
    }

    fn agent(&self, tls: &OwnedTls) -> Result<AgentAssembly, String> {
        let assembly = self.assembly();
        let tools: Arc<dyn AgentToolInvoker> =
            Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(
                Arc::clone(&assembly.application),
                Arc::new(PostgresAgentAuthorizationSource::new(
                    self.pool.clone(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                    false,
                )),
                Arc::new(PostgresAgentToolSequence::new(self.pool.clone())),
                Arc::clone(&assembly.tool_cancellations),
            ));
        build_built_in_agent(BuiltInAgentAssemblyInput {
            pool: self.pool.clone(),
            model_dataset_binding: Arc::clone(&assembly.model_dataset_binding),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            runtime: Arc::clone(&assembly.run_runtime),
            required: true,
            requires_managed: false,
            model: "unselected-package-model".to_owned(),
            package_rate_card: None,
            credential_key_id: "unused-package-key".to_owned(),
            provider: PackageOpenAiProviderConfig {
                base_url: openbot_server::config::DeploymentAddress::parse(
                    "https://unused-package.example.test/v1",
                )
                .map_err(|e| format!("{e:?}"))?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: false,
            },
            managed_provider: None,
            credential_vault: self.vault.clone(),
            tools,
            audit: Arc::new(
                PostgresAgentAudit::new(self.pool.clone(), vec![0x43; 32])
                    .map_err(|e| e.to_string())?,
            ),
            remote_interrupts: assembly.remote_interrupts.clone(),
            remote_assertions: self.assertions.clone(),
            mcp_catalog: assembly.mcp_catalog.clone(),
            components: assembly.components.clone(),
            sandboxed_components: assembly.sandboxed_components.clone(),
            budgets: AgentBudgets {
                stall_timeout: Some(Duration::from_secs(3)),
                run_deadline: Some(Duration::from_secs(20)),
                max_output_tokens: 1024,
            },
            custom_model_dialer: Some(tls.dialer()?),
        })
        .map_err(|e| e.to_string())
    }

    async fn finish(mut self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        if let Some(assembly) = self.assembly.take() {
            assembly.shutdown().await;
        }
        drop(self.registry.take());
        let observations = self.pool.connection_observations();
        self.pool.close();
        let deadline = Instant::now() + Duration::from_secs(10);
        for observation in observations {
            if observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                != pool::ConnectionDestruction::ConnectionDestroyed
            {
                return Err(
                    "original Server connection destruction was not acknowledged".to_owned(),
                );
            }
        }
        Ok(())
    }
}

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
macro_rules! checked {
    ($condition:expr $(, $message:literal)?) => {
        require(
            $condition,
            concat!("custom-V2 assertion: ", stringify!($condition)),
        )?
    };
}
macro_rules! checked_eq {
    ($actual:expr,$expected:expr $(, $message:literal)?) => {
        require(
            $actual == $expected,
            concat!(
                "custom-V2 equality: ",
                stringify!($actual),
                " == ",
                stringify!($expected)
            ),
        )?
    };
}

async fn post(
    router: axum::Router,
    path: &str,
    raw: Vec<u8>,
    cookie: Option<&str>,
) -> Result<(StatusCode, Value), String> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("x-wrok-bot-proxy-secret", PROXY_SECRET)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "owned-v2-server.example.test")
        // Controlled oneshot peer input, not evidence of an incoming TCP socket.
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            41025,
        ))));
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("openbot_session={cookie}"));
    }
    let response = router
        .oneshot(request.body(Body::from(raw)).map_err(|e| e.to_string())?)
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    if status.is_success() {
        require(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store"),
            "actual Server success missed no-store",
        )?;
    }
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    eprintln!("CUSTOM_V2_SERVER_ROUTE_STATUS status={status}");
    Ok((status, value))
}

fn raw_body(run: &str, selection: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"runId":run,"botId":"owned-v2-bot","anchor":{"kind":"direct_bot"},"message":"Please remember the synthetic fact, then answer.","modelSelection":selection})).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PG17 and pinned Python SSL fixture; actual binary Agent assembly"]
async fn actual_server_session_raw_v2_snapshot_context_and_repeated_sampling() {
    harness::with_temp_database(&harness::admin_config("v2_server_host"),"v2serverhost",|config|async move {
        let fixture = ServerFixture::new(config).await?;
        let tls = OwnedTls::new("server")?;
        let mut agent = None;
        let outcome = async {
            let application = &fixture.assembly().application;
            let created = application.execute(fixture.auth().await?, AppCommand::CreateModelConnection(serde_json::from_value(json!({
                "name":"Owned host choice","protocol":"openai_responses","endpoint":tls.endpoint(),"model":"owned-host-model","enabled":true,"apiKey":API_KEY,
            })).map_err(|e|e.to_string())?)).await.map_err(|e|e.to_string())?;
            let AppReply::ModelConnection(model) = created else { return Err("actual model creation reply mismatch".to_owned()); };
            let selection = json!({"schemaVersion":2,"source":"custom","connectionId":model.id,"expectedConnectionRevision":model.revision,"modelId":format!("custom:{}",model.id),"expectedCatalogRevision":1});
            let thread = ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy([0x25;16]);
            let path = format!("/api/threads/{}/runs",thread.as_str());
            let router = fixture.router();
            let raw = raw_body("owned-server-v2-run",&selection);
            checked_eq!(post(router.clone(),&path,raw.clone(),None).await?.0,StatusCode::UNAUTHORIZED);
            let malformed = raw_body("owned-server-malformed-run",&json!({"schemaVersion":2,"connectionId":model.id,"expectedRevision":model.revision}));
            checked_eq!(post(router.clone(),&path,malformed,Some(COOKIE)).await?.0,StatusCode::BAD_REQUEST);
            let selector = selection.to_string();
            let oversized = format!("{{\"runId\":\"owned-server-large-run\",\"botId\":\"owned-v2-bot\",\"anchor\":{{\"kind\":\"direct_bot\"}},\"message\":\"x\",\"modelSelection\":{}{selector}}}"," ".repeat(4097-selector.len())).into_bytes();
            checked_eq!(post(router.clone(),&path,oversized,Some(COOKIE)).await?.0,StatusCode::BAD_REQUEST);
            // A definite rejection of the original session must not poison this model/dataset
            // for another valid session. The second session has an independently keyed token.
            let client=fixture.pool.get().await.map_err(|e|e.to_string())?;
            checked_eq!(client.execute("DELETE FROM public.sessions WHERE id='owned-v2-server-session'",&[]).await.map_err(|e|e.to_string())?,1);
            drop(client);
            checked_eq!(post(router.clone(),&path,raw.clone(),Some(COOKIE)).await?.0,StatusCode::UNAUTHORIZED);
            let (status,receipt) = post(router.clone(),&path,raw.clone(),Some(NEW_COOKIE)).await?;
            checked_eq!(status,StatusCode::CREATED);
            let receipt:ThreadRunStarted = serde_json::from_value(receipt).map_err(|e|e.to_string())?;
            checked!(!receipt.replayed);
            let client = fixture.pool.get().await.map_err(|e|e.to_string())?;
            let row = client.query_one("SELECT s.*,r.created_at AS run_time,m.content,d.dataset_id AS current_dataset,d.initial_origin AS current_origin,d.created_at AS current_dataset_time,c.current_secret_id AS current_secret FROM openbot_internal.run_model_selection_v2_snapshots s JOIN public.runs r USING(run_id) JOIN public.messages m ON m.message_id=r.run_id||':input' JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=s.deployment_id AND d.tenant_id=s.tenant_id JOIN public.model_connections c ON c.id=s.connection_id WHERE s.run_id=$1",&[&"owned-server-v2-run"]).await.map_err(|e|e.to_string())?;
            let snapshot = openbot_infra::db::tables::run_model_selection_v2_snapshots::Row::try_from(&row).map_err(|e|e.to_string())?;
            checked_eq!(snapshot.run_id,"owned-server-v2-run"); checked_eq!(snapshot.deployment_id,DEP); checked_eq!(snapshot.tenant_id,TENANT); checked_eq!(snapshot.owner_user_id,ACTOR);
            checked_eq!(snapshot.auth_generation,7); checked_eq!(snapshot.connection_id.to_string(),model.id); checked_eq!(snapshot.connection_revision,model.revision); checked_eq!(snapshot.protocol,model.protocol.as_str());
            checked_eq!(snapshot.endpoint,model.endpoint); checked_eq!(snapshot.model,model.model); checked_eq!(snapshot.secret_id,row.get::<_,uuid::Uuid>("current_secret")); checked_eq!(snapshot.created_at,row.get::<_,OffsetDateTime>("run_time"));
            checked_eq!(snapshot.snapshot_schema,2); checked_eq!(snapshot.source,"custom"); checked_eq!(snapshot.model_id,format!("custom:{}",model.id)); checked_eq!(snapshot.catalog_revision,1);
            checked_eq!(snapshot.dataset_id,row.get::<_,String>("current_dataset")); checked_eq!(snapshot.dataset_binding_schema,1); checked_eq!(snapshot.dataset_initial_origin,row.get::<_,String>("current_origin")); checked_eq!(snapshot.dataset_initial_origin,"server_first_adoption");
            checked_eq!(snapshot.dataset_binding_created_at,row.get::<_,OffsetDateTime>("current_dataset_time")); checked_eq!(snapshot.credential_policy,"custom_fixed_secret_revision_v1");
            checked_eq!(row.get::<_,Value>("content"),json!({"text":"Please remember the synthetic fact, then answer.","modelSelection":selection,"runAnchor":{"kind":"direct_bot"}}));
            checked_eq!(client.query_one("SELECT count(*) FROM public.run_events WHERE run_id=$1 AND seq=0",&[&"owned-server-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
            checked_eq!(client.query_one("SELECT count(*) FROM public.outbox WHERE outbox_id=$1",&[&"owned-server-v2-run:agent_run_dispatch"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
            checked_eq!(client.query_one("SELECT count(*) FROM public.run_model_selections WHERE run_id=$1",&[&"owned-server-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),0); drop(client);
            let (status,replayed) = post(router,&path,raw,Some(NEW_COOKIE)).await?;
            checked_eq!(status,StatusCode::OK); checked_eq!(replayed["replayed"],true);
            let claim = fixture.assembly().run_runtime.claim_dispatch().await.map_err(|e|e.to_string())?.ok_or("actual dispatch missing")?;
            let context = PostgresAgentContextSource::new(fixture.pool.clone(),DeploymentId::new(DEP),TenantId::new(TENANT),Some(1024)).map_err(|e|e.to_string())?
                .with_model_dataset_binding(fixture.assembly().model_dataset_binding.clone()).map_err(|e|e.to_string())?;
            let first = context.load(claim.lease()).await.map_err(|e|e.to_string())?;
            let second = context.load(claim.lease()).await.map_err(|e|e.to_string())?;
            let (openbot_application::ProviderRoute::CustomModel(first),openbot_application::ProviderRoute::CustomModel(second)) = (&first.route,&second.route) else { return Err("actual context did not produce custom route".to_owned()); };
            checked_eq!(first,second); checked_eq!(first.v2_snapshot().ok_or("actual V2 provenance missing")?.dataset().dataset_id(),snapshot.dataset_id);
            let (consumer,actual_agent) = fixture.agent(&tls)?;
            agent = actual_agent;
            checked_eq!(consumer.dispatch(claim.lease().clone()).await,RunDispatchDecision::Accepted);
            let active_lease = fixture.assembly().run_runtime.acknowledge_dispatch(&claim).await.map_err(|e|e.to_string())?;
            consumer.activate(&active_lease).await.map_err(|code|format!("actual dispatch activation failed: {code:?}"))?;
            tls.release()?;
            wait_completed(&fixture.pool,"owned-server-v2-run").await?;
            let captures = tls.captures()?;
            checked_eq!(captures.len(),2,"remember must cause a second actual sampling");
            for capture in &captures {
                checked_eq!(capture["path"],"/v1/responses"); checked_eq!(capture["authorization"],format!("Bearer {API_KEY}")); checked_eq!(capture["body"]["model"],"owned-host-model");
                let body = capture["body"].to_string();
                for hidden in ["modelSelection","datasetId","secretId","authGeneration",API_KEY] { checked!(!body.contains(hidden)); }
            }
            checked!(captures[1]["body"].to_string().contains("function_call_output"));
            let client = fixture.pool.get().await.map_err(|e|e.to_string())?;
            checked_eq!(client.query_one("SELECT count(*) FROM public.remember_effect_receipts WHERE run_id=$1",&[&"owned-server-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
            client.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&snapshot.connection_id]).await.map_err(|e|e.to_string())?; drop(client);
            let denied = post(fixture.router(),&path,raw_body("owned-server-disabled-run",&selection),Some(NEW_COOKIE)).await?;
            checked!(!denied.0.is_success()); checked_eq!(tls.captures()?.len(),2);
            Ok(())
        }.await;
        if let Some(agent) = agent { agent.stop().await; }
        let tls_closed = tls.finish();
        let database_closed = fixture.finish().await;
        eprintln!("CUSTOM_V2_SERVER_CLOSURE tls_ok={} database_ok={}",tls_closed.is_ok(),database_closed.is_ok());
        outcome?; tls_closed?; database_closed?; Ok(())
    }).await;
}

async fn wait_completed(pool: &pool::DatabasePool, run: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&run],
            )
            .await
            .map_err(|e| e.to_string())?;
        let status: String = row.get(0);
        if status == "completed" {
            return Ok(());
        }
        if !["queued", "running"].contains(&status.as_str()) {
            return Err(format!(
                "actual host run ended as {status}, code={:?}",
                row.get::<_, Option<String>>(1)
            ));
        }
        if Instant::now() >= deadline {
            return Err("actual host sampling did not finish within its test window".to_owned());
        }
        drop(client);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// The Python interpreter is an explicit Root-frozen test input. It only owns this fixture's
// random temporary directory, listener and child process; it never changes system trust.
struct OwnedTls {
    root: PathBuf,
    child: Option<Child>,
    address: SocketAddr,
    ca: Vec<u8>,
    stdout_reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
    root_removed: bool,
}

impl OwnedTls {
    fn new(label: &str) -> Result<Self, String> {
        let interpreter = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_TLS_PYTHON")
                .ok_or("Root-pinned Python TLS interpreter missing")?,
        );
        if !interpreter.is_absolute() {
            return Err("TLS interpreter must be an absolute pinned input".to_owned());
        }
        let root = std::env::temp_dir().join(format!(
            "openbot-v2-owned-tls-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let child = Command::new(interpreter)
            .args(["-I", "-u", "-c", PYTHON_TLS])
            .arg(&root)
            .args([TEST_CA, TEST_LEAF, TEST_KEY])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut fixture = Self {
            root,
            child: Some(child),
            address: "127.0.0.1:0".parse().unwrap(),
            ca: Vec::new(),
            stdout_reader: None,
            root_removed: false,
        };
        let stdout = fixture
            .child
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .ok_or("owned TLS stdout missing")?;
        let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
        fixture.stdout_reader = Some(std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            let bytes = reader
                .by_ref()
                .take(8193)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            if bytes == 0 || bytes > 8192 {
                return Err("owned TLS startup output missing or unbounded".to_owned());
            }
            ready_send.send(line).map_err(|e| e.to_string())?;
            let mut tail = Vec::new();
            reader
                .take(65537)
                .read_to_end(&mut tail)
                .map_err(|e| e.to_string())?;
            if tail.len() > 65536 {
                return Err("owned TLS stdout tail exceeded budget".to_owned());
            }
            Ok(tail)
        }));
        let line = ready_receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("owned TLS startup not acknowledged: {e}"))?;
        let ready: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let port = ready["port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("owned TLS port invalid")?;
        if port == 0 || [39025, 39027].contains(&port) {
            return Err("owned TLS port is outside fixture policy".to_owned());
        }
        fixture.address = SocketAddr::from(([127, 0, 0, 1], port));
        fixture.ca = serde_json::from_value(ready["ca"].clone()).map_err(|e| e.to_string())?;
        eprintln!(
            "CUSTOM_V2_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
            fixture.child.as_ref().unwrap().id(),
            fixture.root.display()
        );
        Ok(fixture)
    }
    fn endpoint(&self) -> String {
        format!("https://idp.test:{}/v1", self.address.port())
    }
    fn dialer(&self) -> Result<SafeDialer, String> {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|e| e.to_string())?,
            ),
            Arc::new(OwnedDns(self.address)),
            [self.ca.clone().into()],
        )
        .map_err(|e| e.to_string())
    }
    fn release(&self) -> Result<(), String> {
        std::fs::write(self.root.join("release"), b"owned").map_err(|e| e.to_string())
    }
    fn captures(&self) -> Result<Vec<Value>, String> {
        let path = self.root.join("captures.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
            return Err("owned TLS captures exceeded budget".to_owned());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let captures: Vec<Value> = contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if captures.len() > 16 {
            return Err("owned TLS capture count exceeded budget".to_owned());
        }
        Ok(captures)
    }
    fn finish(mut self) -> Result<(), String> {
        self.release()?;
        let child = self.child.as_mut().ok_or("owned TLS child absent")?;
        child
            .stdin
            .as_mut()
            .ok_or("owned TLS stop channel absent")?
            .write_all(b"x")
            .map_err(|e| e.to_string())?;
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if !status.success() {
                    return Err("owned TLS child did not exit naturally with zero".to_owned());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("owned TLS child did not acknowledge stop".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = child.id();
        drop(self.child.take());
        let tail = self
            .stdout_reader
            .take()
            .ok_or("owned TLS stdout reader absent")?
            .join()
            .map_err(|_| "owned TLS stdout reader panicked")??;
        let stopped: Value = serde_json::from_slice(&tail).map_err(|e| e.to_string())?;
        if stopped["stopped"] != true {
            return Err("owned TLS stop output missing".to_owned());
        }
        let count = self.captures()?.len();
        std::fs::remove_dir_all(&self.root).map_err(|e| e.to_string())?;
        if self.root.exists() {
            return Err("owned TLS root survived cleanup".to_owned());
        }
        self.root_removed = true;
        eprintln!(
            "CUSTOM_V2_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
            self.root.display()
        );
        Ok(())
    }
}
impl Drop for OwnedTls {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("CUSTOM_V2_OWNED_TLS fallback_kill=true natural_stop_unproven=true");
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if !self.root_removed {
            eprintln!(
                "CUSTOM_V2_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
                self.root.display()
            );
        }
    }
}
struct OwnedDns(SocketAddr);
#[async_trait]
impl DnsResolver for OwnedDns {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        if host == "idp.test" && port == self.0.port() {
            Ok(vec![self.0])
        } else {
            Err(DnsUnavailable)
        }
    }
}

const PYTHON_TLS: &str = r#"
import base64,http.server,json,os,pathlib,ssl,sys,threading,time
root=pathlib.Path(sys.argv[1]); os.umask(0o077)
ca,leaf,key=[base64.b64decode(x,validate=True) for x in sys.argv[2:5]]
def pem(kind,data): return ('-----BEGIN '+kind+'-----\n'+base64.encodebytes(data).decode()+'-----END '+kind+'-----\n')
(root/'leaf.pem').write_text(pem('CERTIFICATE',leaf)); (root/'key.pem').write_text(pem('PRIVATE KEY',key))
stop=threading.Event(); count=0
def stopping(): sys.stdin.buffer.read(1); stop.set()
thread=threading.Thread(target=stopping); thread.start()
def events(tool):
    result=[{'type':'response.created','response':{'id':'owned-v2-response'},'sequence_number':0}]
    if tool:
        args=json.dumps({'memoryKind':'fact','scope':'thread','content':'Owned synthetic fact','tags':[],'sensitivity':'normal'},separators=(',',':'))
        item={'id':'owned-v2-function','type':'function_call','status':'completed','arguments':args,'call_id':'owned-v2-call','name':'remember'}
        result += [{'type':'response.output_item.added','item':dict(item,status='in_progress',arguments=''),'output_index':0,'sequence_number':1}, {'type':'response.function_call_arguments.delta','delta':args,'item_id':item['id'],'output_index':0,'sequence_number':2}, {'type':'response.function_call_arguments.done','arguments':args,'item_id':item['id'],'output_index':0,'sequence_number':3}, {'type':'response.output_item.done','item':item,'output_index':0,'sequence_number':4}]
    else: result += [{'type':'response.output_text.delta','delta':'Owned host complete','output_index':0,'sequence_number':1}]
    result += [{'type':'response.completed','response':{'usage':{'input_tokens':2,'output_tokens':3,'total_tokens':5}},'sequence_number':5}]
    return ''.join('data: '+json.dumps(e,separators=(',',':'))+'\n\n' for e in result).encode()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        global count
        self.connection.settimeout(5)
        n=int(self.headers.get('Content-Length','-1'))
        if not 0<=n<=262144 or count>=16: raise RuntimeError('owned request budget')
        body=json.loads(self.rfile.read(n)); count+=1
        capture={'path':self.path,'authorization':self.headers.get('Authorization'),'body':body}
        with (root/'captures.jsonl').open('a') as f: f.write(json.dumps(capture,separators=(',',':'))+'\n'); f.flush()
        deadline=time.monotonic()+15
        while not (root/'release').exists() and not stop.is_set():
            if time.monotonic()>=deadline: raise RuntimeError('owned response gate deadline')
            time.sleep(.01)
        data=events(count==1)
        self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Content-Length',str(len(data))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'leaf.pem',root/'key.pem')
class Server(http.server.HTTPServer):
    def get_request(self):
        raw,address=self.socket.accept(); raw.settimeout(3)
        try: return context.wrap_socket(raw,server_side=True),address
        except BaseException: raw.close(); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=.2
print(json.dumps({'port':server.server_port,'ca':list(ca)}),flush=True)
try:
    while not stop.is_set(): server.handle_request()
finally: server.server_close(); stop.set(); thread.join(timeout=2)
if thread.is_alive(): raise RuntimeError('owned stop reader did not join')
print(json.dumps({'stopped':True,'requests':count}),flush=True)
"#;

// Existing repository non-production W7 CA/leaf/key, SAN=idp.test. Never installed in OS trust.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
