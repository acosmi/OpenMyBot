//! Selected R424 ApplicationService/Server/Desktop routes with real owned PG and artifact bytes.
//! Identity/session rows and the minimal asset bundle are controlled local fixtures. Server uses
//! its actual session resolver and Origin gate; Desktop receives that verified session as its
//! host-bound window authority. This is not a live SSO, GUI, provider, or Keychain acceptance.

#![cfg(target_os = "macos")]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use harness::{admin_config, with_temp_database};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::ArtifactRegistrationReceipt;
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::auth::AuthResolver as _;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const DEPLOYMENT: &str = "artifact-host-deployment";
const TENANT: &str = "artifact-host-tenant";
const ORIGIN: &str = "https://artifact-ui.example.test";
const SESSION_KEY: &[u8] = b"synthetic-artifact-host-session-hash-key";
const OWNER_COOKIE: &str = "synthetic-artifact-owner-session-token-001";
const OTHER_COOKIE: &str = "synthetic-artifact-other-session-token-002";
const EXACT_TEXT: &str = "  ARTIFACT_REGISTRATION_PRIVATE_CANARY\n成果 café 🦀\t  ";
const EXACT_SHA256: &str = "bfa294e00339f0fafc019c454640258a5f9ac3ac768e27c624a70ab076af2361";
const SAVE_PATH: &str = "/api/artifacts/save-run-message-text";

struct UnusedRemote;

#[async_trait]
impl RemoteAguiTransport for UnusedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        panic!("explicit user-message save must not invoke a remote Agent");
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct OwnedRoot(PathBuf);

impl OwnedRoot {
    fn new(tag: &str) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path =
            std::env::temp_dir().join(format!("openbot-artifact-host-{tag}-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path))
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let outcome = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "ARTIFACT_HOST_ROOT_CLEANUP removed={} absent={absent}",
            outcome.is_ok()
        );
        if !std::thread::panicking() {
            assert!(
                outcome.is_ok() && absent,
                "owned artifact host root cleanup failed"
            );
        }
    }
}

struct ResponseFacts {
    status: StatusCode,
    value: Value,
}

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    router: axum::Router,
    desktop: DesktopTauriProtocol,
    begin: BeginThreadRunRequest,
    root: OwnedRoot,
    _assets: OwnedRoot,
}

impl Fixture {
    async fn new(
        config: DatabaseConfig,
        policy: ArtifactQuotaPolicy,
        with_store: bool,
    ) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('actor-a','owner@example.test',0),('actor-b','other@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user'),('actor-b','admin');
                 INSERT INTO public.agents(id,name,type,configuration) VALUES('bot-a','Artifact fixture','built_in','{}');
                 INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                   VALUES('bot-a','actor-a','Artifact fixture','fixture','fixture','public');
                 INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                   VALUES('00000000-0000-4000-8000-000000000041','artifact-host-tenant','fixture','fixture');"
            ).await.map_err(|error|error.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, actor, token) in [
                ("owner-session", "actor-a", OWNER_COOKIE),
                ("other-session", "actor-b", OTHER_COOKIE),
            ] {
                let token = SessionTokenHash::compute(
                    SessionToken::new(token.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                client.execute(
                    "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation)
                     VALUES($1,$2,$3,$4,$5,$5,0)",
                    &[&id,&actor,&token,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))],
                ).await.map_err(|error|error.to_string())?;
            }
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new("actor-a"),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([11; 16]),
                run_id: RunId::new("actual/host-run%成果"),
                bot_id: BotId::new("bot-a"),
                anchor: ThreadRunAnchor::DirectBot,
                message: EXACT_TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "artifact-host-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        let root = OwnedRoot::new("bytes")?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|error| error.to_string())?,
        );
        let artifacts: Option<Arc<dyn openbot_application::ArtifactAdministration>> = if with_store
        {
            let store = Arc::new(
                DatasetBoundArtifactStore::bind_host_root(
                    std::fs::File::open(&root.0).map_err(|error| error.to_string())?,
                    Arc::clone(&registry),
                    policy,
                )
                .await
                .map_err(|error| error.to_string())?,
            );
            Some(Arc::new(
                PostgresArtifactAdministration::new(
                    registry,
                    store,
                    policy,
                    SecretBytes::new(vec![0x82; 32]),
                )
                .map_err(|error| error.to_string())?,
            ))
        } else {
            None
        };
        let policies = PolicyStore::postgres(pool.clone(), None);
        policies.load().await.map_err(|error| error.to_string())?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: pool.clone(),
            listener_database: config.into(),
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            single_user: false,
            admin_floor: None,
            model: "unused-artifact-model".to_owned(),
            credential_key_id: "unused-artifact-key".to_owned(),
            credential_vault: CredentialRecordVault::single_key(
                tenant.clone(),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x83; 32]).map_err(|error| error.to_string())?,
            ),
            audit_key: SecretBytes::new(vec![0x82; 32]),
            remote_assertions: Arc::new(
                RemoteRunAssertionSigner::new(vec![0x84; 32]).map_err(|error| error.to_string())?,
            ),
            mcp_oauth_state_key: SecretBytes::new(vec![0x85; 32]),
            policy_store: policies,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(UnusedRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(|error| error.to_string())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(|error| error.to_string())?;
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(|error| error.to_string())?,
        );
        let security = SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).map_err(|error| error.to_string())?,
        );
        let transport_policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|error| format!("fixture transport config: {error:?}"))?
            .transport_policy(true);
        let state = ServerBuilder::new(assembly.application.clone(), resolver.clone())
            .with_transport_policy(transport_policy)
            .with_sensitive_write_security(security)
            .build();
        // oneshot has no accepted socket. Supply its exact fixture peer out-of-band; the real
        // production transport gate runs and no user-controlled header can provide this fact.
        let router = openbot_server::router(state).layer(axum::Extension(ConnectInfo(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
        )));
        let assets = OwnedRoot::new("assets")?;
        std::fs::write(assets.0.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>")
            .map_err(|error|error.to_string())?;
        std::fs::write(assets.0.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|error| error.to_string())?;
        let desktop = DesktopTauriProtocol::open(
            &assets.0,
            Arc::new(InProcessTransport::new(assembly.application.clone())),
        )
        .map_err(|error| error.to_string())?;
        for (label, cookie) in [("owner", OWNER_COOKIE), ("other", OTHER_COOKIE)] {
            let (parts, ()) = Request::builder()
                .uri("/api/me")
                .header("cookie", format!("openbot_session={cookie}"))
                .body(())
                .map_err(|error| error.to_string())?
                .into_parts();
            let session = resolver
                .resolve_with_assurance(&parts)
                .await
                .map_err(|error| error.to_string())?;
            require(
                session.has_revocable_session(),
                "Desktop carrier did not come from a current PG session",
            )?;
            desktop
                .bind_window(label, session.into_context(), Some(Duration::from_secs(60)))
                .map_err(|error| error.to_string())?;
        }
        Ok(Self {
            pool,
            router,
            desktop,
            begin,
            root,
            _assets: assets,
        })
    }

    fn request(&self) -> Value {
        json!({
            "requestId":Uuid::now_v7().to_string(),"sourceThreadId":self.begin.command.thread_id.as_str(),
            "sourceRunId":self.begin.command.run_id.as_str(),"sourceMessageId":format!("{}:input",self.begin.command.run_id.as_str()),
            "expectedSha256":EXACT_SHA256,
        })
    }

    async fn http(
        &self,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
        body: Option<Value>,
    ) -> Result<ResponseFacts, String> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", format!("openbot_session={cookie}"));
        }
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .map_err(|error| error.to_string())?;
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        require(
            response
                .headers()
                .get("cache-control")
                .is_some_and(|value| value == "no-store"),
            "Server artifact framing omitted no-store",
        )?;
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        Ok(ResponseFacts {
            status,
            value: serde_json::from_slice(&bytes).map_err(|error| error.to_string())?,
        })
    }

    async fn desktop(
        &self,
        label: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<ResponseFacts, String> {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(body.map_or_else(Vec::new, |value| value.to_string().into_bytes()))
            .map_err(|error| error.to_string())?;
        let response = self.desktop.handle(label, request).await;
        require(
            response
                .headers()
                .get("cache-control")
                .is_some_and(|value| value == "no-store"),
            "Desktop artifact framing omitted no-store",
        )?;
        Ok(ResponseFacts {
            status: response.status(),
            value: serde_json::from_slice(response.body()).map_err(|error| error.to_string())?,
        })
    }

    async fn effect_counts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|error|error.to_string())?.query_one(
            "SELECT jsonb_build_object('operations',(SELECT count(*) FROM openbot_internal.artifact_save_operations),
              'records',(SELECT count(*) FROM openbot_internal.artifact_records),
              'receipts',(SELECT count(*) FROM openbot_internal.artifact_saved_receipts),
              'audit',(SELECT count(*) FROM public.audit_events WHERE event_type='artifact.saved'))",&[]
        ).await.map_err(|error|error.to_string())?.try_get(0).map_err(|error|error.to_string())
    }
}

async fn with_fixture<F, Fut>(tag: &str, policy: ArtifactQuotaPolicy, with_store: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(tag);
    with_temp_database(&admin, tag, |config| async move {
        body(Fixture::new(config, policy, with_store).await?).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn real_session_server_save_and_bound_window_replay_share_one_byte_effect() {
    with_fixture(
        "ah_real_chain",
        ArtifactQuotaPolicy::default(),
        true,
        |fixture| async move {
            let request = fixture.request();
            let saved = fixture
                .http(
                    Method::POST,
                    SAVE_PATH,
                    Some(OWNER_COOKIE),
                    Some(ORIGIN),
                    Some(request.clone()),
                )
                .await?;
            require(
                saved.status == StatusCode::OK,
                "authenticated Server save failed",
            )?;
            let receipt: ArtifactRegistrationReceipt =
                serde_json::from_value(saved.value.clone()).map_err(|error| error.to_string())?;
            require(
                saved
                    .value
                    .as_object()
                    .is_some_and(|value| value.len() == 9),
                "positive receipt added content or replay facts",
            )?;
            let mut alias = request;
            alias["requestId"] = json!(receipt.request_id.to_uppercase());
            let observed = fixture
                .desktop("owner", Method::POST, SAVE_PATH, Some(alias))
                .await?;
            require(
                observed.status == StatusCode::OK && observed.value == saved.value,
                "trusted Desktop replay changed the positive registration fact",
            )?;
            let path = format!("/api/artifacts/{}", receipt.artifact_id);
            let server = fixture
                .http(Method::GET, &path, Some(OWNER_COOKIE), None, None)
                .await?;
            let desktop = fixture.desktop("owner", Method::GET, &path, None).await?;
            require(
                server.status == StatusCode::OK
                    && desktop.status == StatusCode::OK
                    && server.value == desktop.value,
                "actual PG metadata differed across host carriers",
            )?;
            require(
                server.value["status"] == "available"
                    && server.value["byteLength"] == EXACT_TEXT.len() as u64
                    && server.value["sha256"] == EXACT_SHA256,
                "metadata did not describe actual logical UTF8 bytes",
            )?;
            let bytes = std::fs::read(fixture.root.0.join("objects").join(&receipt.artifact_id))
                .map_err(|error| error.to_string())?;
            require(
                bytes == EXACT_TEXT.as_bytes(),
                "actual host chain trimmed or reserialized the real message",
            )?;
            require(
                fixture.effect_counts().await?
                    == json!({"operations":1,"records":1,"receipts":1,"audit":1}),
                "host replay duplicated persistent effect",
            )?;
            let other = fixture
                .http(Method::GET, &path, Some(OTHER_COOKIE), None, None)
                .await?;
            let other_desktop = fixture.desktop("other", Method::GET, &path, None).await?;
            require(
                other.status == StatusCode::NOT_FOUND
                    && other_desktop.status == StatusCode::NOT_FOUND,
                "current admin session read another Run owner's artifact",
            )?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn real_session_origin_unknown_key_and_window_gates_create_no_effect() {
    with_fixture(
        "ah_request_gates",
        ArtifactQuotaPolicy::default(),
        true,
        |fixture| async move {
            let request = fixture.request();
            for origin in [None, Some("https://other-origin.example.test")] {
                let refused = fixture
                    .http(
                        Method::POST,
                        SAVE_PATH,
                        Some(OWNER_COOKIE),
                        origin,
                        Some(request.clone()),
                    )
                    .await?;
                require(
                    refused.status == StatusCode::FORBIDDEN,
                    "sensitive artifact write accepted missing/wrong Origin",
                )?;
            }
            let unauthenticated = fixture
                .http(
                    Method::POST,
                    SAVE_PATH,
                    None,
                    Some(ORIGIN),
                    Some(request.clone()),
                )
                .await?;
            require(
                unauthenticated.status == StatusCode::UNAUTHORIZED,
                "artifact write accepted missing current PG session",
            )?;
            let mut injected = request.clone();
            injected["body"] = json!("client manufactured text");
            let server = fixture
                .http(
                    Method::POST,
                    SAVE_PATH,
                    Some(OWNER_COOKIE),
                    Some(ORIGIN),
                    Some(injected.clone()),
                )
                .await?;
            let desktop = fixture
                .desktop("owner", Method::POST, SAVE_PATH, Some(injected))
                .await?;
            require(
                server.status == StatusCode::BAD_REQUEST
                    && desktop.status == StatusCode::BAD_REQUEST,
                "closed request accepted caller-supplied body",
            )?;
            let unbound = fixture
                .desktop(
                    "not-a-host-bound-window",
                    Method::POST,
                    SAVE_PATH,
                    Some(request),
                )
                .await?;
            require(
                unbound.status == StatusCode::UNAUTHORIZED,
                "unknown window acquired a user save authority",
            )?;
            require(
                fixture.effect_counts().await?
                    == json!({"operations":0,"records":0,"receipts":0,"audit":0}),
                "host gate rejection left artifact effects",
            )?;
            require(
                std::fs::read_dir(fixture.root.0.join("objects"))
                    .map_err(|error| error.to_string())?
                    .count()
                    == 0,
                "host gate rejection wrote an object",
            )?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_quota_and_changed_intent_keep_both_host_error_rules_and_effects_equal() {
    let policy = ArtifactQuotaPolicy::new(1024, 32, EXACT_TEXT.len() as u64)
        .expect("tightened fixture policy");
    with_fixture("ah_quota_conflict", policy, true, |fixture| async move {
        let request = fixture.request();
        let saved = fixture
            .desktop("owner", Method::POST, SAVE_PATH, Some(request.clone()))
            .await?;
        require(
            saved.status == StatusCode::OK,
            "trusted window could not save exact boundary object",
        )?;
        let mut changed = request;
        changed["expectedSha256"] = json!("a".repeat(64));
        let server = fixture
            .http(
                Method::POST,
                SAVE_PATH,
                Some(OWNER_COOKIE),
                Some(ORIGIN),
                Some(changed.clone()),
            )
            .await?;
        let desktop = fixture
            .desktop("owner", Method::POST, SAVE_PATH, Some(changed))
            .await?;
        require(
            server.status == StatusCode::CONFLICT && desktop.status == StatusCode::CONFLICT,
            "changed locator intent lost409 parity",
        )?;
        let new_request = fixture.request();
        let server = fixture
            .http(
                Method::POST,
                SAVE_PATH,
                Some(OWNER_COOKIE),
                Some(ORIGIN),
                Some(new_request.clone()),
            )
            .await?;
        let desktop = fixture
            .desktop("owner", Method::POST, SAVE_PATH, Some(new_request))
            .await?;
        require(
            server.status == StatusCode::FORBIDDEN && desktop.status == StatusCode::FORBIDDEN,
            "tightened workspace quota failed at a host",
        )?;
        require(
            server.value["rule"] == "artifact_quota"
                && desktop.value["rule"] == server.value["rule"],
            "quota host framing changed the shared static rule",
        )?;
        require(
            fixture.effect_counts().await?
                == json!({"operations":1,"records":1,"receipts":1,"audit":1}),
            "conflict/quota rejection added effects",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn production_assembly_without_actual_store_returns_truthful_dependency_unavailable() {
    with_fixture(
        "ah_missing_store",
        ArtifactQuotaPolicy::default(),
        false,
        |fixture| async move {
            let request = fixture.request();
            let server = fixture
                .http(
                    Method::POST,
                    SAVE_PATH,
                    Some(OWNER_COOKIE),
                    Some(ORIGIN),
                    Some(request.clone()),
                )
                .await?;
            let desktop = fixture
                .desktop("owner", Method::POST, SAVE_PATH, Some(request))
                .await?;
            require(
                server.status == StatusCode::SERVICE_UNAVAILABLE
                    && desktop.status == StatusCode::SERVICE_UNAVAILABLE,
                "missing physical store projected a successful save",
            )?;
            require(
                fixture.effect_counts().await?
                    == json!({"operations":0,"records":0,"receipts":0,"audit":0}),
                "unavailable default manufactured artifact facts",
            )?;
            Ok(())
        },
    )
    .await;
}
