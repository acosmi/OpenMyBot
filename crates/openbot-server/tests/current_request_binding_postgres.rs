//! R425 actual owned PostgreSQL session/SingleUser -> real artifact PG port -> shared App/HTTP.
//! Principals, package and unused remote port are controlled fixtures, not SSO/provider evidence.
//! No Desktop Local, one-use reader, byte streaming or complete readiness is proved here.

#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use harness::{admin_config, with_temp_database};
use http::{Request, StatusCode};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest,
    ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, GetArtifactMetadata, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
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
use openbot_infra::auth::single_user::{
    SINGLE_USER_ACTOR_ID, initialize_single_user, load_single_user_principal,
};
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::policy::PolicyStore;
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder,
    SingleUserAuthResolver,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const DEPLOYMENT: &str = "current-binding-deployment";
const TENANT: &str = "current-binding-tenant";
const OWNER: &str = "binding-owner";
const A_ID: &str = "actual-session-a";
const B_ID: &str = "actual-session-b";
const COOKIE_A: &str = "owned-current-binding-session-token-a-001";
const COOKIE_B: &str = "owned-current-binding-session-token-b-002";
const SESSION_KEY: &[u8] = b"owned-current-binding-session-hash-key";
const TEXT: &str = "  OWNED_CURRENT_BINDING_ARTIFACT_CANARY\n成果 café 🦀\t  ";

fn require(value: bool, error: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(error.to_owned()) }
}

fn token_column(token: &str) -> String {
    SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value()
}

fn plain_copy(auth: &AuthContext) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        auth.deployment().clone(),
        auth.tenant().clone(),
        auth.actor().clone(),
        auth.auth_generation(),
        auth.is_single_user(),
    )
    .with_roles(auth.roles().iter().copied())
    .build()
}

async fn verify(auth: &AuthContext) -> Result<(), HostRequestBindingError> {
    auth.request_binding()
        .ok_or(HostRequestBindingError::Missing)?
        .verify_current(auth)
        .await
}

struct UnusedRemote;
#[async_trait]
impl RemoteAguiTransport for UnusedRemote {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        panic!("artifact metadata fixture must not invoke a remote provider")
    }
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path = std::env::temp_dir().join(format!("openbot-current-binding-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "CURRENT_BINDING_ROOT_CLEANUP removed={} absent={absent}",
            removed.is_ok()
        );
        if !std::thread::panicking() {
            assert!(
                removed.is_ok() && absent,
                "owned current-binding root cleanup failed"
            );
        }
    }
}

struct CountActualArtifactPort {
    actual: Arc<PostgresArtifactAdministration>,
    metadata_calls: AtomicUsize,
}
#[async_trait]
impl ArtifactAdministration for CountActualArtifactPort {
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.actual.save_run_message_text(auth, input).await
    }
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
        self.actual.get_metadata(auth, id).await
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Sessions,
    SingleUser,
}
impl Mode {
    const fn actor(self) -> &'static str {
        match self {
            Self::Sessions => OWNER,
            Self::SingleUser => SINGLE_USER_ACTOR_ID,
        }
    }
    const fn is_single_user(self) -> bool {
        matches!(self, Self::SingleUser)
    }
}

struct HttpFacts {
    status: StatusCode,
    value: Value,
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    config: DatabaseConfig,
    resolver: Arc<dyn AuthResolver>,
    application: Arc<dyn ApplicationService>,
    router: axum::Router,
    port: Arc<CountActualArtifactPort>,
    receipt: ArtifactRegistrationReceipt,
    root: OwnedRoot,
}

impl Fixture {
    async fn new(config: DatabaseConfig, mode: Mode) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut c = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&c).await.map_err(|e| e.to_string())?;
            native::apply(&mut c).await.map_err(|e| e.to_string())?;
        }
        if mode.is_single_user() {
            initialize_single_user(&pool, true)
                .await
                .map_err(|e| e.to_string())?;
        } else {
            pool.get().await.map_err(|e|e.to_string())?.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES('binding-owner','binding-owner@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES('binding-owner','user');"
            ).await.map_err(|e|e.to_string())?;
        }
        {
            let c = pool.get().await.map_err(|e| e.to_string())?;
            c.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('binding-bot','Binding fixture','built_in','{}');
                INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000005','current-binding-tenant','fixture','fixture');")
                .await.map_err(|e|e.to_string())?;
            c.execute("INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('binding-bot',$1,'Binding fixture','fixture','fixture','public')", &[&mode.actor()]).await.map_err(|e|e.to_string())?;
            if !mode.is_single_user() {
                let now = OffsetDateTime::now_utc();
                for (id, token) in [(A_ID, COOKIE_A), (B_ID, COOKIE_B)] {
                    c.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation)
                        VALUES($1,$2,$3,$4,$5,$5,0)", &[&id,&mode.actor(),&token_column(token),&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))])
                        .await.map_err(|e|e.to_string())?;
                }
            }
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let resolver: Arc<dyn AuthResolver> = if mode.is_single_user() {
            let principal = load_single_user_principal(&pool, deployment.clone(), tenant.clone())
                .await
                .map_err(|e| e.to_string())?;
            Arc::new(SingleUserAuthResolver::from_verified_principal(
                principal,
                default_session_lifetime(),
            ))
        } else {
            Arc::new(
                PostgresSessionAuthResolver::new(
                    pool.clone(),
                    SESSION_KEY,
                    default_session_lifetime(),
                    deployment.clone(),
                    tenant.clone(),
                )
                .map_err(|e| e.to_string())?,
            )
        };
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(mode.actor()),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([5; 16]),
                run_id: RunId::new("actual/binding-run%成果"),
                bot_id: BotId::new("binding-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "current-binding-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(|e| e.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x75; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let (parts, ()) = Request::builder()
            .uri("/api/me")
            .header("cookie", format!("openbot_session={COOKIE_A}"))
            .body(())
            .map_err(|e| e.to_string())?
            .into_parts();
        let auth = resolver.resolve(&parts).await.map_err(|e| e.to_string())?;
        let receipt = actual
            .save_run_message_text(
                &auth,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id.clone(),
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let port = Arc::new(CountActualArtifactPort {
            actual,
            metadata_calls: AtomicUsize::new(0),
        });
        let policies = PolicyStore::postgres(pool.clone(), None);
        policies.load().await.map_err(|e| e.to_string())?;
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: pool.clone(),
            listener_database: config.clone().into(),
            deployment,
            tenant: tenant.clone(),
            single_user: mode.is_single_user(),
            admin_floor: None,
            model: "unused-model".to_owned(),
            credential_key_id: "unused-key".to_owned(),
            credential_vault: CredentialRecordVault::single_key(
                tenant,
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x76; 32]).map_err(|e| e.to_string())?,
            ),
            audit_key: SecretBytes::new(vec![0x75; 32]),
            remote_assertions: Arc::new(
                RemoteRunAssertionSigner::new(vec![0x77; 32]).map_err(|e| e.to_string())?,
            ),
            mcp_oauth_state_key: SecretBytes::new(vec![0x78; 32]),
            policy_store: policies,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: Some(port.clone()),
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(UnusedRemote),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: Url::parse("http://127.0.0.1:9/v1/chat/completions")
                    .map_err(|e| e.to_string())?,
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".to_owned()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .map_err(|e| e.to_string())?;
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|e| format!("fixture transport config: {e:?}"))?
            .transport_policy(true);
        let security = SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured(["https://binding-ui.example.test"])
                .map_err(|e| e.to_string())?,
        );
        let state = ServerBuilder::new(assembly.application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .with_sensitive_write_security(security)
            .build();
        let router = openbot_server::router(state).layer(axum::Extension(ConnectInfo(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_005)),
        )));
        Ok(Self {
            pool,
            config,
            resolver,
            application: assembly.application,
            router,
            port,
            receipt,
            root,
        })
    }

    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        let (parts, ()) = Request::builder()
            .uri("/api/me")
            .header("cookie", format!("openbot_session={cookie}"))
            .body(())
            .map_err(|e| e.to_string())?
            .into_parts();
        self.resolver
            .resolve(&parts)
            .await
            .map_err(|e| e.to_string())
    }
    async fn resolved(&self, cookie: &str) -> Result<openbot_server::auth::ResolvedAuth, String> {
        let (parts, ()) = Request::builder()
            .uri("/api/me")
            .header("cookie", format!("openbot_session={cookie}"))
            .body(())
            .map_err(|e| e.to_string())?
            .into_parts();
        self.resolver
            .resolve_with_assurance(&parts)
            .await
            .map_err(|e| e.to_string())
    }
    async fn app_metadata(&self, auth: &AuthContext) -> Result<AppReply, AppError> {
        self.application
            .execute(
                auth.clone(),
                AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                    artifact_id: self.receipt.artifact_id.clone(),
                }),
            )
            .await
    }
    async fn http_metadata(&self, cookie: &str) -> Result<HttpFacts, String> {
        let request = Request::builder()
            .uri(format!("/api/artifacts/{}", self.receipt.artifact_id))
            .header("cookie", format!("openbot_session={cookie}"))
            .body(Body::empty())
            .map_err(|e| e.to_string())?;
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        require(
            response
                .headers()
                .get("cache-control")
                .and_then(|x| x.to_str().ok())
                == Some("no-store"),
            "actual metadata response lost no-store",
        )?;
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .map_err(|e| e.to_string())?;
        Ok(HttpFacts {
            status,
            value: serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
        })
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT jsonb_build_object(
            'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
            'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
            'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
            'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
            'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
            'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a WHERE event_type='artifact.saved'))",&[])
            .await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        std::fs::read(self.root.0.join("objects").join(&self.receipt.artifact_id))
            .map_err(|e| e.to_string())
    }
    async fn unchanged(&self, facts: &Value) -> Result<(), String> {
        require(
            &self.facts().await? == facts && self.bytes()? == TEXT.as_bytes(),
            "current-binding observation mutated durable artifact facts or actual bytes",
        )
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
    }
}

async fn with_fixture<F, Fut>(tag: &str, mode: Mode, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    with_temp_database(&admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, mode).await?).await
    })
    .await;
}

async fn actual_metadata_wait(fixture: &Fixture, blocking_pid: i32) -> Result<i32, String> {
    for _ in 0..200 {
        let rows = fixture
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query(
                "SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database()
             AND a.pid<>pg_backend_pid() AND a.query LIKE '%artifact_records%'
             AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))",
                &[&blocking_pid],
            )
            .await
            .map_err(|e| e.to_string())?;
        if rows.len() == 1 {
            return Ok(rows[0].get(0));
        }
        require(
            rows.is_empty(),
            "more than one metadata producer blocked on the owned test lock",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("real artifact metadata SELECT never reached its exact owned PostgreSQL wait".to_owned())
}

fn assert_private_failure(
    fixture: &Fixture,
    response: &HttpFacts,
    status: StatusCode,
    code: &str,
) -> Result<(), String> {
    require(
        response.status == status,
        "actual metadata returned the wrong failure status",
    )?;
    require(
        response.value.get("code").and_then(Value::as_str) == Some(code),
        "actual metadata returned the wrong stable error code",
    )?;
    let encoded = response.value.to_string();
    for private in [
        fixture.receipt.artifact_id.as_str(),
        fixture.receipt.source_message_id.as_str(),
        fixture.receipt.source_run_id.as_str(),
        fixture.receipt.source_thread_id.as_str(),
    ] {
        require(
            !encoded.contains(private),
            "failure response leaked old artifact/source metadata",
        )?;
    }
    require(
        !encoded.contains(TEXT)
            && !encoded.contains(&format!("{:x}", Sha256::digest(TEXT.as_bytes()))),
        "failure response leaked old content or digest",
    )
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn two_real_same_actor_sessions_have_distinct_binding_and_only_revoked_a_stops() {
    with_fixture("binding-two-sessions",Mode::Sessions,|fixture|async move {
        let facts=fixture.facts().await?;
        let a=fixture.auth(COOKIE_A).await?;
        let b=fixture.auth(COOKIE_B).await?;
        let repeated=fixture.auth(COOKIE_A).await?;
        require(a==b && a.auth_generation()==AuthGeneration::new(0),"actual A/B original six facts differ")?;
        let a_binding=a.request_binding().ok_or("A binding missing")?;
        let b_binding=b.request_binding().ok_or("B binding missing")?;
        require(a_binding.kind()==HostRequestBindingKind::ServerSession && !a_binding.identity().same_binding(b_binding.identity()),"actual A/B session epochs were collapsed")?;
        require(a_binding.identity().same_binding(repeated.request_binding().ok_or("repeat binding missing")?.identity()),"repeated actual row did not preserve binding identity")?;
        require(verify(&a).await.is_ok() && verify(&b).await.is_ok(),"actual A/B current guards refused live rows")?;
        require(fixture.http_metadata(COOKIE_A).await?.status==StatusCode::OK && fixture.http_metadata(COOKIE_B).await?.status==StatusCode::OK,"actual live-session metadata failed")?;
        let b_before:Value=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT to_jsonb(s) FROM public.sessions s WHERE id=$1",&[&B_ID]).await.map_err(|e|e.to_string())?.get(0);
        fixture.resolver.revoke_session(&fixture.resolved(COOKIE_A).await?).await.map_err(|e|e.to_string())?;
        let c=fixture.pool.get().await.map_err(|e|e.to_string())?;
        let row=c.query_one("SELECT u.auth_generation,(SELECT count(*) FROM public.sessions WHERE id=$1) AS a_count,(SELECT to_jsonb(s) FROM public.sessions s WHERE id=$2) AS b FROM public.users u WHERE id=$3",&[&A_ID,&B_ID,&OWNER]).await.map_err(|e|e.to_string())?;
        require(row.get::<_,i64>(0)==0 && row.get::<_,i64>(1)==0 && row.get::<_,Value>(2)==b_before,"actual logout changed generation or sibling session")?;
        drop(c);
        require(verify(&a).await==Err(HostRequestBindingError::NotCurrent) && verify(&b).await.is_ok(),"actual row revoke did not invalidate exactly A")?;
        require(matches!(fixture.app_metadata(&a).await,Err(AppError::Unauthenticated)),"captured A returned metadata after logout")?;
        assert_private_failure(&fixture,&fixture.http_metadata(COOKIE_A).await?,StatusCode::UNAUTHORIZED,"unauthenticated")?;
        require(fixture.http_metadata(COOKIE_B).await?.status==StatusCode::OK,"live sibling B stopped after A logout")?;
        fixture.unchanged(&facts).await
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn updated_idle_timestamp_is_current_observation_not_an_immutable_epoch_and_checks_do_not_touch()
 {
    with_fixture("binding-idle-update",Mode::Sessions,|fixture|async move {
        let a=fixture.auth(COOKIE_A).await?;
        fixture.sql("UPDATE public.sessions SET updated_at=clock_timestamp() WHERE id='actual-session-a'").await?;
        let repeated=fixture.auth(COOKIE_A).await?;
        require(a.request_binding().ok_or("A binding missing")?.identity().same_binding(repeated.request_binding().ok_or("repeat binding missing")?.identity()),"mutable updated_at changed exact binding epoch")?;
        let before:OffsetDateTime=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT updated_at FROM public.sessions WHERE id=$1",&[&A_ID]).await.map_err(|e|e.to_string())?.get(0);
        require(verify(&a).await.is_ok(),"current mutable idle timestamp refused")?;
        require(matches!(fixture.app_metadata(&a).await,Ok(AppReply::ArtifactMetadata(ArtifactMetadata::Available(_)))),"actual application metadata refused updated timestamp")?;
        let after:OffsetDateTime=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT updated_at FROM public.sessions WHERE id=$1",&[&A_ID]).await.map_err(|e|e.to_string())?.get(0);
        require(before==after,"binding checks touched/extended session activity")
    }).await;
}

async fn replaced_session_epoch(tag: &str, replace_token: bool) {
    with_fixture(tag,Mode::Sessions,move|fixture|async move {
        let facts=fixture.facts().await?;
        let old=fixture.auth(COOKIE_A).await?;
        let replacement_cookie="owned-replacement-binding-token-a-003";
        if replace_token {
            fixture.pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.sessions SET token=$1 WHERE id=$2",&[&token_column(replacement_cookie),&A_ID]).await.map_err(|e|e.to_string())?;
        } else { fixture.sql("UPDATE public.sessions SET created_at=created_at-interval '1 millisecond' WHERE id='actual-session-a'").await?; }
        let current=fixture.auth(if replace_token { replacement_cookie } else { COOKIE_A }).await?;
        require(old==current,"row replacement changed original six facts in this controlled fixture")?;
        require(!old.request_binding().ok_or("old binding missing")?.identity().same_binding(current.request_binding().ok_or("new binding missing")?.identity()),"same-id immutable tuple replacement revived original proof")?;
        require(verify(&old).await==Err(HostRequestBindingError::NotCurrent) && verify(&current).await.is_ok(),"original tuple was not independently refused")?;
        require(matches!(fixture.app_metadata(&old).await,Err(AppError::Unauthenticated)),"old tuple returned actual metadata")?;
        require(matches!(fixture.app_metadata(&current).await,Ok(AppReply::ArtifactMetadata(ArtifactMetadata::Available(_)))),"replacement tuple did not acquire its own current proof")?;
        fixture.unchanged(&facts).await
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn same_id_token_column_replacement_cannot_reuse_old_session_binding() {
    replaced_session_epoch("binding-token-replace", true).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn same_id_created_at_replacement_cannot_reuse_old_session_binding() {
    replaced_session_epoch("binding-created-replace", false).await;
}

async fn changed_session_authority(tag: &str, sql: &str) {
    with_fixture(tag, Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let a = fixture.auth(COOKIE_A).await?;
        fixture.sql(sql).await?;
        require(
            verify(&a).await == Err(HostRequestBindingError::NotCurrent),
            "actual current session authority mutation was accepted",
        )?;
        require(
            matches!(
                fixture.app_metadata(&a).await,
                Err(AppError::Unauthenticated)
            ),
            "actual stale authority returned metadata",
        )?;
        require(
            fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
            "precheck refusal entered the actual artifact port",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_generation_zero_session_refuses_current_user_generation_null() {
    changed_session_authority(
        "binding-user-gen-null",
        "UPDATE public.users SET auth_generation=NULL WHERE id='binding-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_issued_generation_null() {
    changed_session_authority(
        "binding-issued-gen-null",
        "UPDATE public.sessions SET auth_generation=NULL WHERE id='actual-session-a'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_issued_generation_negative() {
    // Normal migration 0015 forbids this row. In this owned database only, remove that CHECK to
    // model a corrupt/legacy negative value; the real guard must still refuse it independently.
    changed_session_authority("binding-issued-neg","ALTER TABLE public.sessions DROP CONSTRAINT sessions_auth_generation_nonnegative; UPDATE public.sessions SET auth_generation=-1 WHERE id='actual-session-a'").await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_current_user_generation_advance() {
    changed_session_authority(
        "binding-user-gen-advance",
        "UPDATE public.users SET auth_generation=1 WHERE id='binding-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_current_effective_role_change() {
    changed_session_authority(
        "binding-role-change",
        "UPDATE public.user_roles SET role='admin' WHERE user_id='binding-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_current_deny() {
    changed_session_authority(
        "binding-current-deny",
        "INSERT INTO public.revoked_access(email,revoked_by) VALUES('binding-owner@example.test','owned-test-controller')",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_current_absolute_expiry() {
    changed_session_authority("binding-absolute-expiry","UPDATE public.sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id='actual-session-a'").await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_session_refuses_current_idle_expiry() {
    changed_session_authority("binding-idle-expiry","UPDATE public.sessions SET updated_at=clock_timestamp()-interval '31 days' WHERE id='actual-session-a'").await;
}

#[derive(Clone, Copy)]
enum DuringWait {
    RevokeA,
    RevokeAAndDeleteMessage,
    OwnerClose,
    SingleUserGeneration,
}

async fn metadata_after_real_pg_wait(tag: &str, mode: Mode, change: DuringWait) {
    with_fixture(tag,mode,move|fixture|async move {
        let facts=fixture.facts().await?;
        let old=fixture.auth(COOKIE_A).await?;
        require(matches!(fixture.app_metadata(&old).await,Ok(AppReply::ArtifactMetadata(ArtifactMetadata::Available(_)))),"actual initial metadata was not Available")?;
        let before=fixture.port.metadata_calls.load(Ordering::SeqCst);
        let mut controller=fixture.pool.get().await.map_err(|e|e.to_string())?;
        let blocker:i32=controller.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let transaction=controller.transaction().await.map_err(|e|e.to_string())?;
        transaction.batch_execute("SET LOCAL lock_timeout='2s'; LOCK TABLE openbot_internal.artifact_records IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
        let request=fixture.http_metadata(COOKIE_A);
        tokio::pin!(request);
        let producer=tokio::select! {
            ready=&mut request => return Err(format!("metadata finished before actual PG wait: {:?}",ready.map(|x|x.status))),
            observed=actual_metadata_wait(&fixture,blocker) => observed?,
        };
        require(producer!=blocker && fixture.port.metadata_calls.load(Ordering::SeqCst)==before+1,"real metadata producer did not pass preguard and enter actual port exactly once")?;
        match change {
            DuringWait::RevokeA | DuringWait::RevokeAAndDeleteMessage => {
                fixture.resolver.revoke_session(&fixture.resolved(COOKIE_A).await?).await.map_err(|e|e.to_string())?;
                if matches!(change,DuringWait::RevokeAAndDeleteMessage) {
                    fixture.pool.get().await.map_err(|e|e.to_string())?.execute("DELETE FROM public.messages WHERE message_id=$1",&[&fixture.receipt.source_message_id]).await.map_err(|e|e.to_string())?;
                }
                let row=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT auth_generation,(SELECT count(*) FROM public.sessions WHERE id='actual-session-a') FROM public.users WHERE id='binding-owner'",&[]).await.map_err(|e|e.to_string())?;
                require(row.get::<_,i64>(0)==0 && row.get::<_,i64>(1)==0,"actual A revoke during metadata wait was not committed without generation change")?;
            }
            DuringWait::OwnerClose => fixture.resolver.close_request_bindings(),
            DuringWait::SingleUserGeneration => fixture.sql("UPDATE public.users SET auth_generation=1 WHERE id='dev-local-user'").await?,
        }
        transaction.rollback().await.map_err(|e|e.to_string())?;
        drop(controller);
        let response=tokio::time::timeout(Duration::from_secs(8),request).await.map_err(|_|"metadata did not finish after exact PG blocker release")??;
        assert_private_failure(&fixture,&response,StatusCode::UNAUTHORIZED,"unauthenticated")?;
        require(verify(&old).await==Err(HostRequestBindingError::NotCurrent),"captured guard was revived after real PG await")?;
        match change {
            DuringWait::RevokeA => {
                require(fixture.port.actual.get_metadata(&old,&fixture.receipt.artifact_id).await.is_ok(),"actual repository source did not remain independently valid after session-only revoke")?;
                require(fixture.http_metadata(COOKIE_B).await?.status==StatusCode::OK,"sibling session failed after waited A logout")?;
            }
            DuringWait::RevokeAAndDeleteMessage => {
                require(fixture.port.actual.get_metadata(&old,&fixture.receipt.artifact_id).await==Err(ArtifactAdministrationError::NotVisible),"real repository error counterexample was not actual NotVisible")?;
            }
            DuringWait::OwnerClose | DuringWait::SingleUserGeneration => {}
        }
        fixture.unchanged(&facts).await
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_session_logout_after_metadata_pg_wait_withholds_old_available_and_keeps_sibling() {
    metadata_after_real_pg_wait("binding-wait-logout", Mode::Sessions, DuringWait::RevokeA).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn postguard_also_overrides_actual_pg_not_visible_after_logout_and_source_delete() {
    metadata_after_real_pg_wait(
        "binding-wait-pg-error",
        Mode::Sessions,
        DuringWait::RevokeAAndDeleteMessage,
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_session_owner_close_during_metadata_pg_wait_withholds_old_available() {
    metadata_after_real_pg_wait(
        "binding-wait-owner-close",
        Mode::Sessions,
        DuringWait::OwnerClose,
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_single_user_generation_change_during_metadata_pg_wait_withholds_old_available() {
    metadata_after_real_pg_wait(
        "binding-wait-single-gen",
        Mode::SingleUser,
        DuringWait::SingleUserGeneration,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn missing_binding_is_static_503_before_actual_artifact_port_and_malformed_selector_stays_400()
 {
    with_fixture("binding-missing", Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let plain = plain_copy(&fixture.auth(COOKIE_A).await?);
        require(
            matches!(
                fixture.app_metadata(&plain).await,
                Err(AppError::DependencyUnavailable {
                    dependency: "host_request_binding"
                })
            ),
            "missing actual binding was not static 503",
        )?;
        require(
            matches!(
                fixture
                    .application
                    .execute(
                        plain.clone(),
                        AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                            artifact_id: "malformed-selector".to_owned()
                        })
                    )
                    .await,
                Err(AppError::MalformedPayload {
                    field: "artifactId"
                })
            ),
            "selector validation order changed",
        )?;
        require(
            fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
            "missing/malformed binding entered actual artifact PG port",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn real_guard_pool_acquisition_timeout_is_bounded_static_503_before_artifact_pg() {
    with_fixture(
        "binding-pool-timeout",
        Mode::Sessions,
        |fixture| async move {
            let facts = fixture.facts().await?;
            let auth = fixture.auth(COOKIE_A).await?;
            let mut held = Vec::new();
            for _ in 0..8 {
                held.push(fixture.pool.get().await.map_err(|e| e.to_string())?);
            }
            let started = tokio::time::Instant::now();
            let result = fixture.app_metadata(&auth).await;
            let elapsed = started.elapsed();
            require(
                matches!(
                    result,
                    Err(AppError::DependencyUnavailable {
                        dependency: "host_request_binding"
                    })
                ),
                "real exhausted owning pool did not produce static host binding 503",
            )?;
            require(
                elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(7),
                "current guard did not enforce its total five-second acquisition budget",
            )?;
            require(
                fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
                "timeout preguard entered actual artifact PG",
            )?;
            drop(held);
            require(
                verify(&auth).await.is_ok(),
                "bounded timeout permanently changed otherwise current proof",
            )?;
            fixture.unchanged(&facts).await
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_single_user_canonical_source_is_sessionless_and_owns_current_pool() {
    with_fixture(
        "binding-single-positive",
        Mode::SingleUser,
        |fixture| async move {
            let facts = fixture.facts().await?;
            let auth = fixture.auth(COOKIE_A).await?;
            let binding = auth
                .request_binding()
                .ok_or("single-user binding missing")?;
            require(
                binding.kind() == HostRequestBindingKind::ServerSingleUserOwner
                    && auth.is_single_user(),
                "actual canonical principal was not bound to its resolver owner",
            )?;
            require(
                verify(&auth).await.is_ok()
                    && fixture.http_metadata(COOKIE_A).await?.status == StatusCode::OK,
                "actual single-user metadata refused current principal",
            )?;
            let count: i64 = fixture
                .pool
                .get()
                .await
                .map_err(|e| e.to_string())?
                .query_one("SELECT count(*) FROM public.sessions", &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            require(count == 0, "single-user metadata fabricated a session row")?;
            require(
                matches!(
                    fixture
                        .resolver
                        .revoke_session(&fixture.resolved(COOKIE_A).await?)
                        .await,
                    Err(AppError::RequestConflict {
                        resource: "session"
                    })
                ),
                "sessionless single-user revoke ceased being explicit conflict",
            )?;
            fixture.unchanged(&facts).await
        },
    )
    .await;
}

async fn changed_single_user_authority(tag: &str, sql: &str) {
    with_fixture(tag, Mode::SingleUser, |fixture| async move {
        let facts = fixture.facts().await?;
        let auth = fixture.auth(COOKIE_A).await?;
        let principal = load_single_user_principal(
            &fixture.pool,
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
        )
        .await
        .map_err(|e| e.to_string())?;
        fixture.sql(sql).await?;
        require(
            principal.verify_current().await
                == Err(
                    openbot_infra::auth::single_user::SingleUserPrincipalCurrentError::NotCurrent,
                ),
            "typed ownPool canonical proof accepted changed principal",
        )?;
        require(
            verify(&auth).await == Err(HostRequestBindingError::NotCurrent),
            "actual SingleUser owner guard accepted stale canonical source",
        )?;
        require(
            matches!(
                fixture.app_metadata(&auth).await,
                Err(AppError::Unauthenticated)
            ),
            "captured single-user authority returned stale metadata",
        )?;
        assert_private_failure(
            &fixture,
            &fixture.http_metadata(COOKIE_A).await?,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        )?;
        require(
            fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
            "refused canonical preguard entered actual artifact PG",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_generation_zero_single_user_refuses_only_current_generation_null() {
    changed_single_user_authority(
        "binding-single-gen-null",
        "UPDATE public.users SET auth_generation=NULL WHERE id='dev-local-user'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_single_user_refuses_canonical_email_change_without_repair() {
    changed_single_user_authority(
        "binding-single-email",
        "UPDATE public.users SET email='changed-canonical@example.test' WHERE id='dev-local-user'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_single_user_refuses_nonsole_admin_without_role_repair() {
    changed_single_user_authority(
        "binding-single-role",
        "INSERT INTO public.user_roles(user_id,role) VALUES('dev-local-user','user')",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn minted_single_user_refuses_current_canonical_deny_without_repair() {
    changed_single_user_authority(
        "binding-single-deny",
        "INSERT INTO public.revoked_access(email,revoked_by) VALUES('dev@openbot.local','owned-test-controller')",
    )
    .await;
}

fn poll_current_once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

async fn last_actual_owner_drop_while_guard_waits_for_own_pool(tag: &str, mode: Mode) {
    with_fixture(tag, mode, move |fixture| async move {
        // Separate real producer: the fixture/router resolver must not accidentally retain it.
        let producer_pool = pool::connect(&fixture.config.clone().with_max_pool_size(1))
            .await
            .map_err(|e| e.to_string())?;
        let resolver: Arc<dyn AuthResolver> = if mode.is_single_user() {
            Arc::new(SingleUserAuthResolver::from_verified_principal(
                load_single_user_principal(
                    &producer_pool,
                    DeploymentId::new(DEPLOYMENT),
                    TenantId::new(TENANT),
                )
                .await
                .map_err(|e| e.to_string())?,
                default_session_lifetime(),
            ))
        } else {
            Arc::new(
                PostgresSessionAuthResolver::new(
                    producer_pool.clone(),
                    SESSION_KEY,
                    default_session_lifetime(),
                    DeploymentId::new(DEPLOYMENT),
                    TenantId::new(TENANT),
                )
                .map_err(|e| e.to_string())?,
            )
        };
        let (parts, ()) = Request::builder()
            .uri("/api/me")
            .header("cookie", format!("openbot_session={COOKIE_A}"))
            .body(())
            .map_err(|e| e.to_string())?
            .into_parts();
        let auth = resolver.resolve(&parts).await.map_err(|e| e.to_string())?;
        drop(resolver.clone());
        drop(auth.clone());
        require(
            verify(&auth).await.is_ok(),
            "ordinary resolver/proof clone drop closed actual owner",
        )?;
        let held = producer_pool.get().await.map_err(|e| e.to_string())?;
        let binding = auth.request_binding().ok_or("producer binding missing")?;
        let current = binding.verify_current(&auth);
        tokio::pin!(current);
        // Polling the real guard with its sole pool connection held reaches a genuine pending
        // acquisition after its weak probe upgrade; no fake callback supplies an authority result.
        require(
            poll_current_once(current.as_mut()).is_pending(),
            "real owning-pool guard did not actually await acquisition",
        )?;
        drop(resolver);
        drop(held);
        require(
            tokio::time::timeout(Duration::from_secs(7), current)
                .await
                .map_err(|_| "closed real owner guard did not finish")?
                == Err(HostRequestBindingError::NotCurrent),
            "upgraded probe retained the final real owner lease across await",
        )?;
        require(
            verify(&auth).await == Err(HostRequestBindingError::NotCurrent),
            "closed producer proof revived on another check",
        )?;
        // A new resolver using the exact same live database has a new owner identity.
        let fresh: Arc<dyn AuthResolver> = if mode.is_single_user() {
            Arc::new(SingleUserAuthResolver::from_verified_principal(
                load_single_user_principal(
                    &producer_pool,
                    DeploymentId::new(DEPLOYMENT),
                    TenantId::new(TENANT),
                )
                .await
                .map_err(|e| e.to_string())?,
                default_session_lifetime(),
            ))
        } else {
            Arc::new(
                PostgresSessionAuthResolver::new(
                    producer_pool.clone(),
                    SESSION_KEY,
                    default_session_lifetime(),
                    DeploymentId::new(DEPLOYMENT),
                    TenantId::new(TENANT),
                )
                .map_err(|e| e.to_string())?,
            )
        };
        let new = fresh.resolve(&parts).await.map_err(|e| e.to_string())?;
        require(
            verify(&new).await.is_ok()
                && !binding.identity().same_binding(
                    new.request_binding()
                        .ok_or("new binding missing")?
                        .identity(),
                ),
            "new real owner revived or shared original closed identity",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn last_real_session_resolver_drop_closes_weak_probe_even_after_upgrade_before_pool_await() {
    last_actual_owner_drop_while_guard_waits_for_own_pool("bind-session-last", Mode::Sessions)
        .await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn last_real_single_user_resolver_drop_closes_weak_probe_even_after_upgrade_before_pool_await()
 {
    last_actual_owner_drop_while_guard_waits_for_own_pool("bind-single-last", Mode::SingleUser)
        .await;
}
