//! Genuine owned Session, Application and Axum consumers of current source Run artifact IDs.
//! Synthetic principals are isolated fixtures, not SSO/provider or full R414 acceptance.
#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}
use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetSourceRunArtifactIds, SaveRunMessageTextArtifact,
    SourceRunArtifactIds,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{SessionHashKey, SessionToken, SessionTokenHash};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool, pool::DatabaseConfig};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, ServerBuilder};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

const DEPLOYMENT: &str = "artifact-current-host-deployment";
const TENANT: &str = "artifact-current-host-tenant";
const OWNER: &str = "current-read-owner";
const A_ID: &str = "actual-read-session-a";
const B_ID: &str = "actual-read-session-b";
const COOKIE_A: &str = "owned-current-artifact-read-session-token-a-001";
const COOKIE_B: &str = "owned-current-artifact-read-session-token-b-002";
const SESSION_KEY: &[u8] = b"owned-current-artifact-read-session-hash-key";
const TEXT: &str = "  OWNED_CURRENT_ARTIFACT_READ_CANARY\n成果 café 🦀\t  ";

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn token_column(token: &str) -> String {
    SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value()
}
fn parts(cookie: &str) -> Result<http::request::Parts, String> {
    Request::builder()
        .uri("/trusted-rust-artifact-consumer")
        .header("cookie", format!("openbot_session={cookie}"))
        .body(())
        .map(|request| request.into_parts().0)
        .map_err(|error| error.to_string())
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-source-run-host-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        let mut owner = Self(path);
        let before = std::fs::symlink_metadata(&owner.0).map_err(|error| error.to_string())?;
        let canonical = std::fs::canonicalize(&owner.0).map_err(|error| error.to_string())?;
        let after = std::fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
        require(
            before.is_dir()
                && !before.file_type().is_symlink()
                && after.is_dir()
                && !after.file_type().is_symlink()
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.uid() == after.uid()
                && before.mode() & 0o7777 == 0o700
                && after.mode() & 0o7777 == 0o700,
            "owned source root canonicalization changed the original private inode",
        )?;
        owner.0 = canonical;
        Ok(owner)
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "SOURCE_RUN_SERVER_ROOT_CLEANUP removed={} absent={absent}",
            removed.is_ok()
        );
        if !std::thread::panicking() {
            assert!(
                removed.is_ok() && absent,
                "owned source root cleanup failed"
            );
        }
    }
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    resolver: Arc<PostgresSessionAuthResolver>,
    application: Arc<dyn ApplicationService>,
    router: axum::Router,
    receipt: ArtifactRegistrationReceipt,
    empty: GetSourceRunArtifactIds,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let pool = pool::connect(&config.clone().with_max_pool_size(8))
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
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('current-read-owner','current-read-owner@example.test',0);
                INSERT INTO public.user_roles(user_id,role) VALUES('current-read-owner','user');
                INSERT INTO public.agents(id,name,type,configuration) VALUES('current-read-bot','Current read fixture','built_in','{}');
                INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum) VALUES('00000000-0000-4000-8000-000000000008','artifact-current-host-tenant','fixture','fixture');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('current-read-bot','current-read-owner','Read fixture','fixture','fixture','public');")
                .await.map_err(|error| error.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, cookie) in [(A_ID, COOKIE_A), (B_ID, COOKIE_B)] {
                client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",
                    &[&id, &OWNER, &token_column(cookie), &(now + time::Duration::hours(1)), &(now - time::Duration::minutes(1))]).await.map_err(|error| error.to_string())?;
            }
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment.clone(),
                tenant.clone(),
            )
            .map_err(|error| error.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([8; 16]),
                run_id: RunId::new("actual/current-read-run%成果"),
                bot_id: BotId::new("current-read-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "artifact-current-read-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|error| error.to_string())?;
        let empty_begin = BeginThreadRunRequest {
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([10; 16]),
                run_id: RunId::new("actual/empty-source-run%成果"),
                message: "empty materialized source".to_owned(),
                ..begin.command.clone()
            },
            ..begin.clone()
        };
        PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config.clone(),
            "source-empty-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?
        .begin_thread_run(empty_begin.clone())
        .await
        .map_err(|error| error.to_string())?;
        let empty = GetSourceRunArtifactIds {
            source_thread_id: empty_begin.command.thread_id,
            source_run_id: empty_begin.command.run_id,
        };
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|error| error.to_string())?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(|error| error.to_string())?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|error| error.to_string())?,
        );
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x88; 32]),
            )
            .map_err(|error| error.to_string())?,
        );
        resolver
            .install_artifact_read_authority(&actual.read_authority())
            .map_err(|_| "actual resolver enrollment refused".to_owned())?;
        let auth = resolver
            .resolve(&parts(COOKIE_A)?)
            .await
            .map_err(|error| error.to_string())?;
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
            .map_err(|error| error.to_string())?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(actual),
        );
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|error| format!("fixture transport config: {error:?}"))?
            .transport_policy(true);
        let state = ServerBuilder::new(application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .build();
        Ok(Self {
            pool,
            resolver,
            application,
            router: openbot_server::router(state).layer(axum::Extension(
                axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    std::net::Ipv4Addr::LOCALHOST,
                    40_010,
                ))),
            )),
            receipt,
            empty,
            root,
        })
    }
    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        self.resolver
            .resolve(&parts(cookie)?)
            .await
            .map_err(|error| error.to_string())
    }
    fn source(&self) -> GetSourceRunArtifactIds {
        GetSourceRunArtifactIds {
            source_thread_id: self.receipt.source_thread_id.clone(),
            source_run_id: self.receipt.source_run_id.clone(),
        }
    }
    async fn execute(
        &self,
        auth: &AuthContext,
        input: GetSourceRunArtifactIds,
    ) -> Result<SourceRunArtifactIds, AppError> {
        match self
            .application
            .execute(auth.clone(), AppCommand::GetSourceRunArtifactIds(input))
            .await?
        {
            AppReply::SourceRunArtifactIds(ids) => Ok(ids),
            _ => Err(AppError::DependencyUnavailable {
                dependency: "application",
            }),
        }
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|error| error.to_string())
    }
    async fn corrupt(&self, corrupt: bool) -> Result<(), String> {
        let digest = if corrupt {
            "f".repeat(64)
        } else {
            format!("{:x}", Sha256::digest(TEXT.as_bytes()))
        };
        let mut client = self.pool.get().await.map_err(|error| error.to_string())?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| error.to_string())?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|error| error.to_string())?;
        let changed=tx.execute("UPDATE openbot_internal.artifact_save_operations SET actual_sha256=$1 WHERE artifact_id=$2", &[&digest,&self.receipt.artifact_id]).await.map_err(|error| error.to_string())?;
        require(
            changed == 1,
            "owned corruption did not change exactly original operation",
        )?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|error| error.to_string())?;
        tx.commit().await.map_err(|error| error.to_string())
    }
}
async fn with_fixture<F>(tag: &str, body: F)
where
    F: for<'a> FnOnce(&'a Fixture) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config).await?;
        let outcome = body(&fixture).await;
        require(
            fixture.root.0.is_dir(),
            "owned store root disappeared before original consumer completion",
        )?;
        drop(fixture);
        outcome
    })
    .await;
}
fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("string formatting");
        }
    }
    encoded
}
fn route(input: &GetSourceRunArtifactIds) -> String {
    format!(
        "/api/artifacts/source-runs/{}/{}",
        encode_segment(input.source_thread_id.as_str()),
        encode_segment(input.source_run_id.as_str())
    )
}
struct HttpFacts {
    status: StatusCode,
    value: Option<serde_json::Value>,
}
async fn request(
    router: axum::Router,
    cookie: &str,
    method: Method,
    uri: &str,
    body: &'static str,
) -> Result<HttpFacts, String> {
    let response = router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("cookie", format!("openbot_session={cookie}"))
                .body(Body::from(body))
                .map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    require(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "actual source route lost no-store",
    )?;
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .map_err(|error| error.to_string())?;
    let value = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|error| error.to_string())?)
    };
    Ok(HttpFacts { status, value })
}

fn static_error(facts: &HttpFacts, status: StatusCode, code: &str) -> Result<(), String> {
    require(
        facts.status == status && facts.value == Some(serde_json::json!({"code":code})),
        "source route exposed a nonstatic error or wrong status",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned isolated PostgreSQL and actual Session/Axum source-ID consumers"]
async fn actual_session_router_lists_only_its_visible_source_ids_with_no_store() {
    with_fixture("source-ids-session-route",|fixture| Box::pin(async move {
        let original=fixture.source();
        let uri=route(&original);
        let expected=serde_json::json!({"sourceThreadId":original.source_thread_id,"sourceRunId":original.source_run_id,"artifactIds":[fixture.receipt.artifact_id]});
        for cookie in [COOKIE_A,COOKIE_B] {
            let facts=request(fixture.router.clone(),cookie,Method::GET,&uri,"").await?;
            let diagnostic_code = facts.value.as_ref().and_then(|value| value.get("code")).and_then(serde_json::Value::as_str)
                .filter(|code| matches!(*code, "unauthenticated" | "forbidden" | "not_visible" | "malformed_payload" | "dependency_unavailable"))
                .unwrap_or("absent_or_other");
            eprintln!(
                "SOURCE_RUN_SERVER_PUBLIC_SHAPE status={} code={} key_count={:?} thread_match={} run_match={} ids_count={:?} ids_match={} dto_match={}",
                facts.status.as_u16(), diagnostic_code,
                facts.value.as_ref().and_then(serde_json::Value::as_object).map(|object| object.len()),
                facts.value.as_ref().and_then(|value| value.get("sourceThreadId")) == expected.get("sourceThreadId"),
                facts.value.as_ref().and_then(|value| value.get("sourceRunId")) == expected.get("sourceRunId"),
                facts.value.as_ref().and_then(|value| value.get("artifactIds")).and_then(serde_json::Value::as_array).map(|ids| ids.len()),
                facts.value.as_ref().and_then(|value| value.get("artifactIds")) == expected.get("artifactIds"),
                facts.value.as_ref() == Some(&expected),
            );
            require(facts.status==StatusCode::OK && facts.value==Some(expected.clone()),"actual source route changed identity or added byte fields")?;
        }
        let a=fixture.auth(COOKIE_A).await?;
        let b=fixture.auth(COOKIE_B).await?;
        require(a==b
            && !a.request_binding().ok_or("original A binding missing")?.identity().same_binding(b.request_binding().ok_or("original B binding missing")?.identity()),
            "two genuine sessions did not share six facts with distinct original bindings")?;
        let empty=request(fixture.router.clone(),COOKIE_A,Method::GET,&route(&fixture.empty),"").await?;
        require(empty.status==StatusCode::OK && empty.value.as_ref().and_then(|v|v.get("artifactIds"))==Some(&serde_json::json!([])),"visible empty source was refused or fabricated IDs")?;
        let head=request(fixture.router.clone(),COOKIE_A,Method::HEAD,&uri,"").await?;
        require(head.status==StatusCode::METHOD_NOT_ALLOWED && head.value.is_none(),"HEAD implicitly returned source IDs")?;
        for malformed in [format!("{uri}?unexpected=true"),format!("{uri}?"),format!("/api/artifacts/source-runs/{}/%ZZ",encode_segment(original.source_thread_id.as_str()))] {
            let facts=request(fixture.router.clone(),COOKIE_A,Method::GET,&malformed,"").await?;
            static_error(&facts,StatusCode::BAD_REQUEST,"malformed_payload")?;
        }
        static_error(&request(fixture.router.clone(),COOKIE_A,Method::GET,"/api/artifacts/source-runs/not-a-thread/valid-run","").await?,StatusCode::NOT_FOUND,"not_visible")?;
        static_error(&request(fixture.router.clone(),COOKIE_A,Method::GET,&uri,"body").await?,StatusCode::BAD_REQUEST,"malformed_payload")?;
        static_error(&request(fixture.router.clone(),"invalid-original-session",Method::GET,&uri,"").await?,StatusCode::UNAUTHORIZED,"unauthenticated")?;
        let doubled=uri.replace("%2F","%252F");
        require(doubled!=uri,"source Run fixture lacked a once-decoded slash")?;
        static_error(&request(fixture.router.clone(),COOKIE_A,Method::GET,&doubled,"").await?,StatusCode::NOT_FOUND,"not_visible")?;
        fixture.corrupt(true).await?;
        static_error(&request(fixture.router.clone(),COOKIE_A,Method::GET,&uri,"").await?,StatusCode::SERVICE_UNAVAILABLE,"dependency_unavailable")?;
        fixture.corrupt(false).await?;
        let session=fixture.pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT created_at,expires_at FROM public.sessions WHERE id=$1",&[&A_ID]).await.map_err(|e|e.to_string())?;
        let created:OffsetDateTime=session.try_get(0).map_err(|e|e.to_string())?;
        let expires:OffsetDateTime=session.try_get(1).map_err(|e|e.to_string())?;
        let mutations=[
            ("current_null","UPDATE public.users SET auth_generation=NULL WHERE id='current-read-owner'",false),
            ("current_negative","UPDATE public.users SET auth_generation=-1 WHERE id='current-read-owner'",false),
            ("issued_null","UPDATE public.sessions SET auth_generation=NULL WHERE id='actual-read-session-a'",true),
            ("issued_negative","UPDATE public.sessions SET auth_generation=-1 WHERE id='actual-read-session-a'",false),
            ("role","UPDATE public.user_roles SET role='admin' WHERE user_id='current-read-owner'",false),
            ("deny","INSERT INTO public.revoked_access(email,revoked_by) VALUES('current-read-owner@example.test','current-read-owner')",false),
            ("expiry","UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='actual-read-session-a'",true),
            ("token","UPDATE public.sessions SET token='controlled-original-token-replacement' WHERE id='actual-read-session-a'",true),
            ("created","UPDATE public.sessions SET created_at=created_at+interval '1 second' WHERE id='actual-read-session-a'",true),
        ];
        for (name,mutation,peer_live) in mutations {
            for source in ["valid","empty","missing","corrupt"] {
                let original_a=fixture.auth(COOKIE_A).await?;
                let original_b=fixture.auth(COOKIE_B).await?;
                let input=match source {
                    "empty"=>fixture.empty.clone(),
                    "missing"=>GetSourceRunArtifactIds {source_run_id:RunId::new("missing-original-source"),..original.clone()},
                    _=>original.clone(),
                };
                if source=="corrupt" { fixture.corrupt(true).await?; }
                let invalid_schema=name=="current_negative" || name=="issued_negative";
                if name=="current_negative" {fixture.sql("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative").await?;}
                if name=="issued_negative" {fixture.sql("ALTER TABLE public.sessions DROP CONSTRAINT sessions_auth_generation_nonnegative").await?;}
                fixture.sql(mutation).await?;
                let observed=fixture.execute(&original_a,input).await;
                if invalid_schema {
                    require(matches!(observed,Err(AppError::DependencyUnavailable {dependency}) if dependency=="host_request_binding"),"negative fixture with altered trusted schema did not refuse dependency503")?;
                } else {
                    require(matches!(observed,Err(AppError::Unauthenticated)),"raw current/issued/role/deny/tuple failure lost host-first401 for held source outcome")?;
                }
                if peer_live {
                    let peer=fixture.execute(&original_b,fixture.empty.clone()).await.map_err(|e|e.to_string())?;
                    require(peer.artifact_ids.is_empty(),"unaffected sameactor original B was rebound or refused")?;
                }
                fixture.sql("DELETE FROM public.revoked_access WHERE email='current-read-owner@example.test'; UPDATE public.user_roles SET role='user' WHERE user_id='current-read-owner'; UPDATE public.users SET auth_generation=0 WHERE id='current-read-owner'; UPDATE public.sessions SET auth_generation=0 WHERE id='actual-read-session-a'").await?;
                if name=="current_negative" {fixture.sql("ALTER TABLE ONLY public.users ADD CONSTRAINT users_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation >= 0)").await?;}
                if name=="issued_negative" {fixture.sql("ALTER TABLE ONLY public.sessions ADD CONSTRAINT sessions_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation >= 0)").await?;}
                fixture.pool.get().await.map_err(|e|e.to_string())?.execute("UPDATE public.sessions SET token=$1,created_at=$2,expires_at=$3 WHERE id=$4",&[&token_column(COOKIE_A),&created,&expires,&A_ID]).await.map_err(|e|e.to_string())?;
                if source=="corrupt" { fixture.corrupt(false).await?; }
                if invalid_schema {
                    eprintln!("SOURCE_RUN_SERVER_INVALID_SCHEMA mutation={name} source={source} dependency_503=true restored_schema=true");
                } else {
                    eprintln!("SOURCE_RUN_SERVER_ORIGINAL_EPOCH mutation={name} source={source} original_host_401=true peer_enforced={peer_live}");
                }
            }
        }
        let returned=request(fixture.router.clone(),COOKIE_A,Method::GET,&uri,"").await?;
        require(returned.status==StatusCode::OK && returned.value==Some(expected),"restored fixture did not return original registered IDs")?;
        Ok(())
    })).await;
}

struct SourceGate {
    phase: &'static str,
    phases: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    held: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl SourceGate {
    fn new(phase: &'static str) -> Arc<Self> {
        Arc::new(Self {
            phase,
            phases: std::sync::atomic::AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            held: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            wake: Condvar::new(),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
    fn hold(&self) {
        if self.held.swap(true, Ordering::SeqCst) {
            return;
        }
        self.entered.notify_one();
        tokio::task::block_in_place(|| {
            let released = self.released.lock().unwrap();
            let (_released, timeout) = self
                .wake
                .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                .unwrap();
            self.timed_out.store(timeout.timed_out(), Ordering::SeqCst);
        });
    }
}
struct ReleaseGate(Arc<SourceGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct SourcePhase(Option<&'static str>);
impl tracing::field::Visit for SourcePhase {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "source_run_ids_phase" {
            self.0 = match value {
                "joint_statement_ready" => Some("joint_statement_ready"),
                "joint_result_observed_before_rollback" => {
                    Some("joint_result_observed_before_rollback")
                }
                "rollback_acknowledged_before_tail" => Some("rollback_acknowledged_before_tail"),
                _ => None,
            };
        }
    }
}
struct SourceSubscriber(Arc<SourceGate>);
impl tracing::Subscriber for SourceSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut phase = SourcePhase(None);
        event.record(&mut phase);
        if let Some(phase) = phase.0 {
            let bit = match phase {
                "joint_statement_ready" => 1,
                "joint_result_observed_before_rollback" => 2,
                "rollback_acknowledged_before_tail" => 4,
                _ => 0,
            };
            self.0.phases.fetch_or(bit, Ordering::SeqCst);
            if phase == self.0.phase {
                self.0.hold();
            }
        }
    }
}
async fn await_source_gate(gate: &SourceGate) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .map_err(|_| "real source phase was not observed".to_owned())?;
    require(
        gate.held.load(Ordering::SeqCst) && !gate.timed_out.load(Ordering::SeqCst),
        "actual source phase gate expired",
    )
}
#[derive(Debug)]
struct WaitSample {
    marker: i32,
    active: i32,
    locked: i32,
    exact: i32,
    waiter: Option<i32>,
}
async fn actual_source_wait(
    observer: &openbot_infra::db::pool::PooledClient,
    controller: i32,
    sample: &mut Option<WaitSample>,
) -> Result<i32, String> {
    for _ in 0..150 {
        let row=observer.query_one("SELECT count(*)::integer AS marker, count(*) FILTER (WHERE a.state='active')::integer AS active, count(*) FILTER (WHERE a.wait_event_type='Lock')::integer AS locked, count(*) FILTER (WHERE a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)))::integer AS exact, min(a.pid) FILTER (WHERE a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))) AS waiter FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.query LIKE '%source_run_artifact_ids_joint_current%'",&[&controller]).await.map_err(|e|e.to_string())?;
        let observed = WaitSample {
            marker: row.try_get("marker").map_err(|e| e.to_string())?,
            active: row.try_get("active").map_err(|e| e.to_string())?,
            locked: row.try_get("locked").map_err(|e| e.to_string())?,
            exact: row.try_get("exact").map_err(|e| e.to_string())?,
            waiter: row.try_get("waiter").map_err(|e| e.to_string())?,
        };
        let waiter = if observed.exact == 1 {
            observed.waiter
        } else {
            None
        };
        *sample = Some(observed);
        if let Some(waiter) = waiter {
            return Ok(waiter);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("actual final source query Lock with original controller PID was not observed".to_owned())
}
async fn query_wait_case(fixture: &Fixture, mode: &'static str) -> Result<(), String> {
    // Reserve the same business Pool's original controller and observer before the scoped gate.
    let mut controller = fixture.pool.get().await.map_err(|e| e.to_string())?;
    let observer = fixture.pool.get().await.map_err(|e| e.to_string())?;
    let controller_pid: i32 = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .try_get(0)
        .map_err(|e| e.to_string())?;
    let observer_pid: i32 = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .try_get(0)
        .map_err(|e| e.to_string())?;
    require(
        controller_pid > 0 && observer_pid > 0 && controller_pid != observer_pid,
        "original source controller and observer PIDs invalid",
    )?;
    let gate = SourceGate::new("joint_statement_ready");
    let _release = ReleaseGate(gate.clone());
    let uri = route(&fixture.source());
    let router = fixture.router.clone();
    let task = tokio::spawn(
        async move { request(router, COOKIE_A, Method::GET, &uri, "").await }
            .with_subscriber(tracing::Dispatch::new(SourceSubscriber(gate.clone()))),
    );
    let notification = await_source_gate(&gate).await;
    let mut setup_error = notification.err();
    let mut transaction = if setup_error.is_none() {
        match controller.transaction().await {
            Ok(tx) => Some(tx),
            Err(error) => {
                setup_error = Some(error.to_string());
                None
            }
        }
    } else {
        None
    };
    let mut lock_ack = false;
    let mut commit_ack = false;
    let mut cleanup_rollback_ack = None;
    let mut sample = None;
    let attempted = async {
        if let Some(error) = setup_error {
            return Err(error);
        }
        let tx = transaction
            .as_ref()
            .ok_or("original controller transaction missing")?;
        tx.batch_execute(
            "SET LOCAL lock_timeout='1s'; LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE",
        )
        .await
        .map_err(|e| e.to_string())?;
        lock_ack = true;
        require(
            !gate.timed_out.load(Ordering::SeqCst) && !task.is_finished(),
            "scoped ready gate ended before real controller lock",
        )?;
        gate.release();
        let waiter = actual_source_wait(&observer, controller_pid, &mut sample).await?;
        require(
            !gate.timed_out.load(Ordering::SeqCst)
                && waiter != controller_pid
                && waiter != observer_pid,
            "final query waiter was not the original physical request",
        )?;
        let tx = transaction
            .as_ref()
            .ok_or("original controller transaction disappeared")?;
        if mode != "source_revoke" {
            require(
                tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID])
                    .await
                    .map_err(|e| e.to_string())?
                    == 1,
                "controller did not delete exactly original session A",
            )?;
        }
        if mode != "session_delete" {
            require(
                tx.execute(
                    "DELETE FROM public.thread_memberships WHERE thread_id=$1 AND user_id=$2",
                    &[&fixture.receipt.source_thread_id.as_str(), &OWNER],
                )
                .await
                .map_err(|e| e.to_string())?
                    == 1,
                "controller did not revoke exactly original source membership",
            )?;
        }
        transaction
            .take()
            .ok_or("original controller transaction absent before COMMIT")?
            .commit()
            .await
            .map_err(|e| e.to_string())?;
        commit_ack = true;
        Ok::<_, String>(waiter)
    }
    .await;
    gate.release();
    if let Some(tx) = transaction.take() {
        cleanup_rollback_ack = Some(tx.rollback().await.is_ok());
    }
    let joined = task.await.map_err(|e| e.to_string());
    let phases = gate.phases.load(Ordering::SeqCst);
    eprintln!(
        "SOURCE_RUN_SERVER_WAIT mode={mode} controller_pid={controller_pid} observer_pid={observer_pid} controller_lock_ack={lock_ack} sample_status={} marker={:?} active={:?} lock={:?} exact={:?} waiter={:?} controller_commit_ack={commit_ack} cleanup_rollback_ack={cleanup_rollback_ack:?} original_joint_result_observed={} original_rollback_ack_observed={} joined={} gate_timeout={}",
        if sample.is_some() {
            "sampled"
        } else {
            "not_sampled"
        },
        sample.as_ref().map(|s| s.marker),
        sample.as_ref().map(|s| s.active),
        sample.as_ref().map(|s| s.locked),
        sample.as_ref().map(|s| s.exact),
        sample.as_ref().and_then(|s| s.waiter),
        phases & 2 != 0,
        phases & 4 != 0,
        joined.is_ok(),
        gate.timed_out.load(Ordering::SeqCst)
    );
    attempted?;
    let facts = joined??;
    static_error(
        &facts,
        if mode == "source_revoke" {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        },
        if mode == "source_revoke" {
            "not_visible"
        } else {
            "unauthenticated"
        },
    )?;
    require(
        lock_ack
            && commit_ack
            && phases & 5 == 5
            && (mode != "source_revoke" || phases & 2 == 2)
            && !gate.timed_out.load(Ordering::SeqCst),
        "query/COMMIT/actual rollback phases did not all physically complete",
    )?;
    if mode == "session_delete" {
        let peer = request(
            fixture.router.clone(),
            COOKIE_B,
            Method::GET,
            &route(&fixture.source()),
            "",
        )
        .await?;
        require(
            peer.status == StatusCode::OK,
            "session A deletion invalidated actual unaffected B",
        )?;
    }
    Ok(())
}
async fn post_ack_tail_case(
    fixture: &Fixture,
    source: &'static str,
    tail: &'static str,
) -> Result<(), String> {
    let input = if source == "missing" {
        GetSourceRunArtifactIds {
            source_run_id: RunId::new("missing-source-after-final"),
            ..fixture.source()
        }
    } else {
        fixture.source()
    };
    if source == "corrupt" {
        fixture.corrupt(true).await?;
    }
    let expires = OffsetDateTime::now_utc() + time::Duration::milliseconds(700);
    if tail == "clock" {
        fixture
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .execute(
                "UPDATE public.sessions SET expires_at=$1 WHERE id=$2",
                &[&expires, &A_ID],
            )
            .await
            .map_err(|e| e.to_string())?;
    }
    let gate = SourceGate::new("rollback_acknowledged_before_tail");
    let _release = ReleaseGate(gate.clone());
    let router = fixture.router.clone();
    let uri = route(&input);
    let task = tokio::spawn(
        async move { request(router, COOKIE_A, Method::GET, &uri, "").await }
            .with_subscriber(tracing::Dispatch::new(SourceSubscriber(gate.clone()))),
    );
    let attempted = async {
        await_source_gate(&gate).await?;
        require(
            gate.phases.load(Ordering::SeqCst) == 7 && !task.is_finished(),
            "source outcome/actual rollback ACK was not held before original tail",
        )?;
        if tail == "owner" {
            fixture.resolver.close_request_bindings();
        } else {
            while OffsetDateTime::now_utc() <= expires {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        require(
            !gate.timed_out.load(Ordering::SeqCst),
            "post-ACK observer expired instead of original owner/clock action",
        )
    }
    .await;
    gate.release();
    let joined = task.await.map_err(|e| e.to_string());
    attempted?;
    static_error(&joined??, StatusCode::UNAUTHORIZED, "unauthenticated")?;
    eprintln!(
        "SOURCE_RUN_SERVER_POST_ACK source={source} tail={tail} actual_joint_result=true actual_rollback_ack=true original_host_401=true rollback_pending_proof=false"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL, actual final-query Lock/blocker/COMMIT and original Session tails"]
async fn actual_joint_source_query_wait_and_original_session_tail_withhold_stale_ids() {
    for mode in ["session_delete", "source_revoke", "both"] {
        with_fixture("source-ids-final-lock", move |fixture| {
            Box::pin(query_wait_case(fixture, mode))
        })
        .await;
    }
    for source in ["valid", "missing", "corrupt"] {
        for tail in ["owner", "clock"] {
            with_fixture("source-ids-original-tail", move |fixture| {
                Box::pin(post_ack_tail_case(fixture, source, tail))
            })
            .await;
        }
    }
}
