//! R425 real owned Server session -> actual Desktop protocol -> observed real App -> real PG port.
//! The observing decorator delegates every result to the production ApplicationService.
//! This proves actual session delegation; production Desktop Local is tested separately in its
//! private module. No native GUI, SSO/provider, byte streaming or complete readiness is proved.

#![cfg(target_os = "macos")]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::{Request, StatusCode};
use harness::{admin_config, with_temp_database};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{
    AppEventStream, ApplicationService, ArtifactAdministration, ArtifactAdministrationError,
    BeginThreadRunRequest, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, GetArtifactMetadata, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration};
use openbot_contracts::command::{
    AppCommand, AppReply, BeginThreadRun, SubscriptionRequest, ThreadRunAnchor,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::{HostRequestBindingError, HostRequestBindingKind};
use openbot_desktop::{DesktopTauriProtocol, InProcessTransport};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
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
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, SingleUserAuthResolver};
use serde_json::Value;
use time::OffsetDateTime;
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
const SHA256: &str = "67f316d58f706da6dce7dd1f9c20937d723ebf772a24fa9298f8da6e402eefb2";

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

struct ObservedApplication {
    actual: Arc<dyn ApplicationService>,
    observed: Mutex<Vec<AuthContext>>,
}
#[async_trait]
impl ApplicationService for ObservedApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        if matches!(&command, AppCommand::GetArtifactMetadata(_)) {
            self.observed
                .lock()
                .map_err(|_| AppError::DependencyUnavailable {
                    dependency: "test_observer",
                })?
                .push(auth.clone());
        }
        self.actual.execute(auth, command).await
    }
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        self.actual.subscribe(auth, request).await
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

struct ProtocolFacts {
    status: StatusCode,
    value: Value,
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    resolver: Arc<dyn AuthResolver>,
    application: Arc<ObservedApplication>,
    assets: OwnedRoot,
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
                    expected_sha256: SHA256.to_owned(),
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
        let application = Arc::new(ObservedApplication {
            actual: assembly.application,
            observed: Mutex::new(Vec::new()),
        });
        let assets = OwnedRoot::new()?;
        std::fs::write(assets.0.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e|e.to_string())?;
        std::fs::write(assets.0.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|e| e.to_string())?;
        Ok(Self {
            pool,
            resolver,
            application,
            assets,
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
    fn protocol(&self) -> Result<DesktopTauriProtocol, String> {
        DesktopTauriProtocol::open(
            &self.assets.0,
            Arc::new(InProcessTransport::new(self.application.clone())),
        )
        .map_err(|e| e.to_string())
    }
    async fn metadata(
        &self,
        protocol: &DesktopTauriProtocol,
        label: &str,
    ) -> Result<ProtocolFacts, String> {
        let request = Request::builder()
            .uri(format!("/api/artifacts/{}", self.receipt.artifact_id))
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let response = protocol.handle(label, request).await;
        require(
            response
                .headers()
                .get("cache-control")
                .and_then(|x| x.to_str().ok())
                == Some("no-store"),
            "actual protocol metadata lost no-store",
        )?;
        Ok(ProtocolFacts {
            status: response.status(),
            value: serde_json::from_slice(response.body()).map_err(|e| e.to_string())?,
        })
    }
    fn captured(&self) -> Result<AuthContext, String> {
        self.application
            .observed
            .lock()
            .map_err(|_| "observed actual auth lock poisoned")?
            .last()
            .cloned()
            .ok_or_else(|| "actual ApplicationService received no metadata authority".to_owned())
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

async fn actual_metadata_wait(fixture: &Fixture, blocker: i32) -> Result<(), String> {
    for _ in 0..200 {
        let rows=fixture.pool.get().await.map_err(|e|e.to_string())?.query("SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.query LIKE '%artifact_records%' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))",&[&blocker]).await.map_err(|e|e.to_string())?;
        if rows.len() == 1 {
            return Ok(());
        }
        require(
            rows.is_empty(),
            "multiple actual metadata producers reached one controlled wait",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("actual Desktop metadata producer did not reach PostgreSQL table wait".to_owned())
}

fn private_failure(
    fixture: &Fixture,
    response: &ProtocolFacts,
    status: StatusCode,
    code: &str,
) -> Result<(), String> {
    require(
        response.status == status
            && response.value.get("code").and_then(Value::as_str) == Some(code),
        "actual protocol failure status/code mismatch",
    )?;
    let encoded = response.value.to_string();
    for private in [
        fixture.receipt.artifact_id.as_str(),
        fixture.receipt.source_message_id.as_str(),
        fixture.receipt.source_thread_id.as_str(),
        fixture.receipt.source_run_id.as_str(),
        SHA256,
        TEXT,
    ] {
        require(
            !encoded.contains(private),
            "actual protocol failure leaked old metadata/content",
        )?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn two_actual_protocol_owners_with_same_first_label_have_distinct_current_proofs() {
    with_fixture("pw-two-owner", Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let source = fixture.auth(COOKIE_A).await?;
        require(
            source
                .request_binding()
                .ok_or("actual session binding missing")?
                .kind()
                == HostRequestBindingKind::ServerSession,
            "protocol source was not a real session binding",
        )?;
        let a = fixture.protocol()?;
        let b = fixture.protocol()?;
        a.bind_window("main", source.clone(), None)
            .map_err(|e| e.to_string())?;
        b.bind_window("main", source, None)
            .map_err(|e| e.to_string())?;
        require(
            fixture.metadata(&a, "main").await?.status == StatusCode::OK,
            "owner A actual metadata failed",
        )?;
        let auth_a = fixture.captured()?;
        require(
            fixture.metadata(&b, "main").await?.status == StatusCode::OK,
            "owner B actual metadata failed",
        )?;
        let auth_b = fixture.captured()?;
        let proof_a = auth_a.request_binding().ok_or("window A proof missing")?;
        let proof_b = auth_b.request_binding().ok_or("window B proof missing")?;
        require(
            auth_a == auth_b
                && proof_a.kind() == HostRequestBindingKind::DesktopWindow
                && proof_b.kind() == HostRequestBindingKind::DesktopWindow,
            "window contexts did not preserve their six original source facts",
        )?;
        require(
            !proof_a.identity().same_binding(proof_b.identity()),
            "different actual protocol owners collapsed to one label identity",
        )?;
        require(
            verify(&auth_a).await.is_ok() && verify(&auth_b).await.is_ok(),
            "a valid own-protocol proof was refused while both real owners were live",
        )?;
        // This cross-owner check has an actual B context; it does not invent an absent B input.
        require(
            proof_a.verify_current(&auth_b).await == Err(HostRequestBindingError::NotCurrent),
            "A proof authorized actual B-bound context",
        )?;
        drop(auth_a.clone());
        require(
            verify(&auth_a).await.is_ok(),
            "ordinary proof clone drop closed live protocol owner",
        )?;
        drop(a);
        require(
            verify(&auth_a).await == Err(HostRequestBindingError::NotCurrent)
                && verify(&auth_b).await.is_ok(),
            "last protocol A drop did not close exactly A",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_same_label_rebind_cannot_revive_captured_old_window_authority() {
    with_fixture("pw-rebind", Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|e| e.to_string())?;
        require(
            fixture.metadata(&protocol, "main").await?.status == StatusCode::OK,
            "original actual window metadata failed",
        )?;
        let old = fixture.captured()?;
        require(
            protocol.unbind_window("main").map_err(|e| e.to_string())?,
            "actual old map entry was not removed",
        )?;
        protocol
            .bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|e| e.to_string())?;
        require(
            fixture.metadata(&protocol, "main").await?.status == StatusCode::OK,
            "new actual window metadata failed",
        )?;
        let current = fixture.captured()?;
        require(
            old == current
                && !old
                    .request_binding()
                    .ok_or("old proof missing")?
                    .identity()
                    .same_binding(
                        current
                            .request_binding()
                            .ok_or("new proof missing")?
                            .identity(),
                    ),
            "same label rebind reused original binding identity",
        )?;
        require(
            verify(&old).await == Err(HostRequestBindingError::NotCurrent)
                && verify(&current).await.is_ok(),
            "new current map entry revived old window proof",
        )?;
        require(
            matches!(
                fixture.app_metadata(&old).await,
                Err(AppError::Unauthenticated)
            ),
            "actual App returned old rebound-window metadata",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_window_delegation_observes_only_its_exact_session_delete_without_generation_change()
{
    with_fixture("pw-upstream-delete", Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("a", fixture.auth(COOKIE_A).await?, None)
            .map_err(|e| e.to_string())?;
        protocol
            .bind_window("b", fixture.auth(COOKIE_B).await?, None)
            .map_err(|e| e.to_string())?;
        require(
            fixture.metadata(&protocol, "a").await?.status == StatusCode::OK,
            "actual A window delegation initially failed",
        )?;
        let old_a = fixture.captured()?;
        let before = fixture.port.metadata_calls.load(Ordering::SeqCst);
        fixture
            .resolver
            .revoke_session(&fixture.resolved(COOKIE_A).await?)
            .await
            .map_err(|e| e.to_string())?;
        private_failure(
            &fixture,
            &fixture.metadata(&protocol, "a").await?,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        )?;
        require(
            fixture.port.metadata_calls.load(Ordering::SeqCst) == before,
            "revoked source preguard reached actual metadata PG",
        )?;
        require(
            verify(&old_a).await == Err(HostRequestBindingError::NotCurrent),
            "old window guard did not preserve exact real upstream session proof",
        )?;
        require(
            fixture.metadata(&protocol, "b").await?.status == StatusCode::OK,
            "same actor/gen sibling window B was invalidated by only A logout",
        )?;
        let generation: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT auth_generation FROM public.users WHERE id='binding-owner'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            generation == 0,
            "session-only window revocation advanced user generation",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}

#[derive(Clone, Copy)]
enum DuringWait {
    Unbind,
    Rebind,
    OwnerClose,
    SessionDelete,
    SessionDeleteAndSourceError,
}

async fn actual_protocol_metadata_wait(tag: &str, change: DuringWait) {
    with_fixture(tag,Mode::Sessions,move|fixture|async move {
        let facts=fixture.facts().await?;
        let protocol=fixture.protocol()?;
        protocol.bind_window("main",fixture.auth(COOKIE_A).await?,None).map_err(|e|e.to_string())?;
        require(fixture.metadata(&protocol,"main").await?.status==StatusCode::OK,"actual current-window metadata was not initially Available")?;
        let old=fixture.captured()?;
        let before=fixture.port.metadata_calls.load(Ordering::SeqCst);
        let mut controller=fixture.pool.get().await.map_err(|e|e.to_string())?;
        let blocker:i32=controller.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        let tx=controller.transaction().await.map_err(|e|e.to_string())?;
        tx.batch_execute("SET LOCAL lock_timeout='2s'; LOCK TABLE openbot_internal.artifact_records IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
        let request=fixture.metadata(&protocol,"main");
        tokio::pin!(request);
        tokio::select! {
            ready=&mut request => return Err(format!("protocol metadata completed before real PG wait: {:?}",ready.map(|x|x.status))),
            observed=actual_metadata_wait(&fixture,blocker) => observed?,
        }
        require(fixture.port.metadata_calls.load(Ordering::SeqCst)==before+1,"actual protocol did not enter one real metadata PG call after preguard")?;
        match change {
            DuringWait::Unbind | DuringWait::Rebind => {
                require(protocol.unbind_window("main").map_err(|e|e.to_string())?,"actual old window removal failed while PG awaited")?;
                if matches!(change,DuringWait::Rebind) { protocol.bind_window("main",fixture.auth(COOKIE_A).await?,None).map_err(|e|e.to_string())?; }
            }
            DuringWait::OwnerClose => protocol.close_request_bindings(),
            DuringWait::SessionDelete | DuringWait::SessionDeleteAndSourceError => {
                fixture.resolver.revoke_session(&fixture.resolved(COOKIE_A).await?).await.map_err(|e|e.to_string())?;
                if matches!(change,DuringWait::SessionDeleteAndSourceError) { fixture.pool.get().await.map_err(|e|e.to_string())?.execute("DELETE FROM public.messages WHERE message_id=$1",&[&fixture.receipt.source_message_id]).await.map_err(|e|e.to_string())?; }
            }
        }
        tx.rollback().await.map_err(|e|e.to_string())?;
        drop(controller);
        let response=tokio::time::timeout(Duration::from_secs(8),request).await.map_err(|_|"actual protocol did not finish after owned metadata lock release")??;
        private_failure(&fixture,&response,StatusCode::UNAUTHORIZED,"unauthenticated")?;
        require(verify(&old).await==Err(HostRequestBindingError::NotCurrent),"real PG wait result revived stale window/source authority")?;
        if matches!(change,DuringWait::Rebind) { require(fixture.metadata(&protocol,"main").await?.status==StatusCode::OK,"new actual map entry could not use its own valid proof")?; }
        if matches!(change,DuringWait::SessionDeleteAndSourceError) { require(fixture.port.actual.get_metadata(&old,&fixture.receipt.artifact_id).await==Err(ArtifactAdministrationError::NotVisible),"entire-result counterexample did not have an actual PG NotVisible result")?; }
        fixture.unchanged(&facts).await
    }).await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_window_unbind_during_metadata_pg_wait_withholds_old_result_without_holding_map_lock()
 {
    actual_protocol_metadata_wait("pw-wait-unbind", DuringWait::Unbind).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_same_label_rebind_during_metadata_pg_wait_withholds_old_result() {
    actual_protocol_metadata_wait("pw-wait-rebind", DuringWait::Rebind).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_protocol_owner_close_during_metadata_pg_wait_withholds_old_result() {
    actual_protocol_metadata_wait("pw-wait-close", DuringWait::OwnerClose).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_upstream_session_delete_during_window_metadata_wait_withholds_old_result() {
    actual_protocol_metadata_wait("pw-wait-upstream", DuringWait::SessionDelete).await;
}
#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn actual_window_postguard_overrides_entire_actual_pg_error_after_upstream_logout() {
    actual_protocol_metadata_wait("pw-wait-pg-error", DuringWait::SessionDeleteAndSourceError)
        .await;
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn unbound_generic_source_and_rowless_single_user_source_are_missing_before_actual_artifact_pg()
 {
    for mode in [Mode::Sessions, Mode::SingleUser] {
        with_fixture(
            if mode.is_single_user() {
                "pw-rowless-missing"
            } else {
                "pw-generic-missing"
            },
            mode,
            move |fixture| async move {
                let facts = fixture.facts().await?;
                let auth = fixture.auth(COOKIE_A).await?;
                let source = if mode.is_single_user() {
                    auth
                } else {
                    plain_copy(&auth)
                };
                let protocol = fixture.protocol()?;
                protocol
                    .bind_window("main", source, None)
                    .map_err(|e| e.to_string())?;
                private_failure(
                    &fixture,
                    &fixture.metadata(&protocol, "main").await?,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "dependency_unavailable",
                )?;
                let captured = fixture.captured()?;
                require(
                    verify(&captured).await == Err(HostRequestBindingError::Missing),
                    "generic/rowless window was manufactured into a real session source",
                )?;
                require(
                    fixture.port.metadata_calls.load(Ordering::SeqCst) == 0,
                    "missing session source entered actual artifact PG",
                )?;
                fixture.unchanged(&facts).await
            },
        )
        .await;
    }
}

fn poll_current_once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

#[tokio::test]
#[ignore = "requires root-owned disposable PostgreSQL; never a user database"]
async fn last_protocol_drop_closes_window_guard_after_real_upstream_probe_upgrade_before_pool_await()
 {
    with_fixture("pw-last-drop", Mode::Sessions, |fixture| async move {
        let facts = fixture.facts().await?;
        let protocol = fixture.protocol()?;
        protocol
            .bind_window("main", fixture.auth(COOKIE_A).await?, None)
            .map_err(|e| e.to_string())?;
        require(
            fixture.metadata(&protocol, "main").await?.status == StatusCode::OK,
            "actual delegation did not initially succeed",
        )?;
        let auth = fixture.captured()?;
        drop(auth.clone());
        require(
            verify(&auth).await.is_ok(),
            "ordinary observed-proof clone drop closed actual owner",
        )?;
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(fixture.pool.get().await.map_err(|e| e.to_string())?);
        }
        let current = verify(&auth);
        tokio::pin!(current);
        require(
            poll_current_once(current.as_mut()).is_pending(),
            "actual window source guard did not await owning PG pool acquisition",
        )?;
        drop(protocol);
        drop(held);
        require(
            tokio::time::timeout(Duration::from_secs(7), current)
                .await
                .map_err(|_| "closed protocol guard did not complete")?
                == Err(HostRequestBindingError::NotCurrent),
            "temporary weak-map/probe upgrade retained the last real protocol owner",
        )?;
        require(
            verify(&fixture.auth(COOKIE_A).await?).await.is_ok(),
            "window owner drop incorrectly closed its separate real session source",
        )?;
        fixture.unchanged(&facts).await
    })
    .await;
}
