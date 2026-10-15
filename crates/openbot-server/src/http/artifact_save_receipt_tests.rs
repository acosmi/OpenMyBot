//! Genuine Session/own-PG receipt observers through Application and the current Axum GET.
//! Synthetic principals are isolated fixtures, not SSO/provider or full R414 acceptance.
#![cfg(unix)]

mod harness {
    include!("../../../../test-support/postgres_harness.rs");
}
use crate as openbot_server;
use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetArtifactSaveReceipt, SaveRunMessageTextArtifact,
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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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
        let path =
            std::env::temp_dir().join(format!("openbot-save-receipt-host-{}", Uuid::now_v7()));
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
            "SAVE_RECEIPT_SERVER_ROOT_CLEANUP removed={} absent={absent}",
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
                    40_011,
                ))),
            )),
            receipt,
            root,
        })
    }
    async fn auth(&self, cookie: &str) -> Result<AuthContext, String> {
        self.resolver
            .resolve(&parts(cookie)?)
            .await
            .map_err(|error| error.to_string())
    }
    async fn execute(
        &self,
        auth: &AuthContext,
        request: &str,
    ) -> Result<ArtifactRegistrationReceipt, AppError> {
        match self
            .application
            .execute(
                auth.clone(),
                AppCommand::GetArtifactSaveReceipt(GetArtifactSaveReceipt {
                    request_id: request.into(),
                }),
            )
            .await?
        {
            AppReply::ArtifactRegistrationReceipt(receipt) => Ok(receipt),
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
    async fn facts(&self) -> Result<serde_json::Value, String> {
        self.pool.get().await.map_err(|e|e.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
              'workspaces',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
              'runs',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a WHERE event_type='artifact.saved'))", &[])
            .await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())
    }
    async fn terminal_reader_fixture(&self) -> Result<(), String> {
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        // A controlled reader shape after a genuine Save, not a delivered deletion producer.
        tx.batch_execute("SET LOCAL session_replication_role='replica'")
            .await
            .map_err(|e| e.to_string())?;
        require(tx.execute("UPDATE openbot_internal.artifact_save_operations SET state='deleted',store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE artifact_id=$1", &[&self.receipt.artifact_id])
            .await.map_err(|e| e.to_string())? == 1, "terminal reader fixture original operation missing")?;
        require(tx.execute("UPDATE openbot_internal.artifact_records SET status='deleted',workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE artifact_id=$1", &[&self.receipt.artifact_id])
            .await.map_err(|e| e.to_string())? == 1, "terminal reader fixture original record missing")?;
        tx.commit().await.map_err(|e| e.to_string())
    }
    fn bytes(&self) -> Result<(u64, u64, u64, String), String> {
        let path = self.root.0.join("objects").join(&self.receipt.artifact_id);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(
            meta.is_file() && !meta.file_type().is_symlink(),
            "owned original object became nonregular",
        )?;
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        Ok((
            meta.dev(),
            meta.ino(),
            meta.len(),
            format!("{:x}", Sha256::digest(bytes)),
        ))
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
        fixture.pool.close();
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
fn route(request: &str) -> String {
    format!("/api/artifacts/save-requests/{}", encode_segment(request))
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

struct ReceiptGate {
    phase: &'static str,
    phases: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    held: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl ReceiptGate {
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
struct ReleaseGate(Arc<ReceiptGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct ReceiptPhase(Option<&'static str>);
impl tracing::field::Visit for ReceiptPhase {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "save_receipt_phase" {
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
struct ReceiptSubscriber(Arc<ReceiptGate>);
impl tracing::Subscriber for ReceiptSubscriber {
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
        let mut phase = ReceiptPhase(None);
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
async fn await_receipt_gate(gate: &ReceiptGate) -> Result<(), String> {
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
async fn actual_receipt_wait(
    observer: &openbot_infra::db::pool::PooledClient,
    controller: i32,
    sample: &mut Option<WaitSample>,
) -> Result<i32, String> {
    for _ in 0..150 {
        let row=observer.query_one("SELECT count(*)::integer AS marker, count(*) FILTER (WHERE a.state='active')::integer AS active, count(*) FILTER (WHERE a.wait_event_type='Lock')::integer AS locked, count(*) FILTER (WHERE a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)))::integer AS exact, min(a.pid) FILTER (WHERE a.state='active' AND a.wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))) AS waiter FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.query LIKE '%artifact_save_receipt_joint_current%'",&[&controller]).await.map_err(|e|e.to_string())?;
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
    let before = fixture.facts().await?;
    let original_bytes = fixture.bytes()?;
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
    let gate = ReceiptGate::new("joint_statement_ready");
    let _release = ReleaseGate(gate.clone());
    let uri = route(&fixture.receipt.request_id);
    let router = fixture.router.clone();
    let task = tokio::spawn(
        async move { request(router, COOKIE_A, Method::GET, &uri, "").await }
            .with_subscriber(tracing::Dispatch::new(ReceiptSubscriber(gate.clone()))),
    );
    let notification = await_receipt_gate(&gate).await;
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
        let waiter = actual_receipt_wait(&observer, controller_pid, &mut sample).await?;
        require(
            !gate.timed_out.load(Ordering::SeqCst)
                && waiter != controller_pid
                && waiter != observer_pid,
            "final query waiter was not the original physical request",
        )?;
        let tx = transaction
            .as_ref()
            .ok_or("original controller transaction disappeared")?;
        if matches!(mode, "session_delete" | "both") {
            require(
                tx.execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID])
                    .await
                    .map_err(|e| e.to_string())?
                    == 1,
                "controller did not delete exactly original session A",
            )?;
        }
        if matches!(mode, "source_revoke" | "both") {
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
        "SAVE_RECEIPT_SERVER_WAIT mode={mode} controller_pid={controller_pid} observer_pid={observer_pid} controller_lock_ack={lock_ack} sample_status={} marker={:?} active={:?} lock={:?} exact={:?} waiter={:?} controller_commit_ack={commit_ack} cleanup_rollback_ack={cleanup_rollback_ack:?} original_joint_result_observed={} original_rollback_ack_observed={} joined={} gate_timeout={}",
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
    if mode == "release_positive" {
        require(
            facts.status == StatusCode::OK
                && facts.value
                    == Some(serde_json::to_value(&fixture.receipt).map_err(|e| e.to_string())?),
            "actual controller release lost the original positive receipt",
        )?;
    } else {
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
    }
    require(
        lock_ack
            && commit_ack
            && phases & 5 == 5
            && (!matches!(mode, "source_revoke" | "release_positive") || phases & 2 == 2)
            && !gate.timed_out.load(Ordering::SeqCst),
        "query/COMMIT/actual rollback phases did not all physically complete",
    )?;
    if mode == "session_delete" {
        let peer = request(
            fixture.router.clone(),
            COOKIE_B,
            Method::GET,
            &route(&fixture.receipt.request_id),
            "",
        )
        .await?;
        require(
            peer.status == StatusCode::OK,
            "session A deletion invalidated actual unaffected B",
        )?;
    }
    require(
        fixture.facts().await? == before && fixture.bytes()? == original_bytes,
        "real Lock/release/session/source cases changed original artifact or object facts",
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, real Session resolver, enrolled own Pool and current HTTP receipt GET"]
async fn genuine_session_http_get_recovers_original_receipt_and_preserves_artifact_facts() {
    with_fixture("save_receipt_http", |f| Box::pin(async move {
        let auth_a = f.auth(COOKIE_A).await?; let auth_b = f.auth(COOKIE_B).await?;
        require(auth_a == auth_b && !auth_a.request_binding().zip(auth_b.request_binding())
            .is_some_and(|(a,b)| a.identity().same_binding(b.identity())), "real A/B sessions must retain distinct original epochs")?;
        let before = f.facts().await?; let before_bytes = f.bytes()?;
        let updated_before: OffsetDateTime = f.pool.get().await.map_err(|e|e.to_string())?
            .query_one("SELECT updated_at FROM public.sessions WHERE id=$1", &[&A_ID]).await.map_err(|e|e.to_string())?.get(0);
        let uri = route(&f.receipt.request_id);
        for cookie in [COOKIE_A, COOKIE_B] {
            let actual = request(f.router.clone(), cookie, Method::GET, &uri, "").await?;
            require(actual.status == StatusCode::OK && actual.value == Some(serde_json::to_value(&f.receipt).map_err(|e|e.to_string())?),
                "genuine GET must recover exactly the original real nine-field receipt")?;
        }
        require(f.execute(&auth_a, &f.receipt.request_id.to_uppercase()).await == Ok(f.receipt.clone()),
            "typed alias must recover the same original genuine receipt")?;
        for (method, suffix, body, status) in [
            (Method::GET, "?", "", StatusCode::BAD_REQUEST), (Method::GET, "?forged=1", "", StatusCode::BAD_REQUEST),
            (Method::GET, "", "{}", StatusCode::BAD_REQUEST), (Method::HEAD, "", "", StatusCode::METHOD_NOT_ALLOWED),
            (Method::POST, "", "", StatusCode::METHOD_NOT_ALLOWED), (Method::GET, "/extra", "", StatusCode::BAD_REQUEST),
        ] {
            let actual = request(f.router.clone(), COOKIE_A, method.clone(), &format!("{uri}{suffix}"), body).await?;
            require(actual.status == status, "genuine receipt framing class mismatch")?;
            if method == Method::HEAD { require(actual.value.is_none(), "HEAD must return an empty body")?; }
        }
        for segment in ["%ZZ", "%2F", "%252F", "not-a-request", ""] {
            static_error(&request(f.router.clone(), COOKIE_A, Method::GET, &format!("/api/artifacts/save-requests/{segment}"), "").await?,
                StatusCode::BAD_REQUEST, "malformed_payload")?;
        }
        f.sql("UPDATE public.messages SET content='{}'::jsonb").await?;
        let changed_text = request(f.router.clone(), COOKIE_A, Method::GET, &uri, "").await?;
        require(changed_text.value == Some(serde_json::to_value(&f.receipt).map_err(|e|e.to_string())?) && changed_text.status == StatusCode::OK,
            "current text changes must not become Save intent reexecution")?;
        require(f.facts().await? == before && f.bytes()? == before_bytes,
            "HTTP observer changed original operations/records/receipts/charge/audit/identity or bytes")?;
        let updated_after: OffsetDateTime = f.pool.get().await.map_err(|e|e.to_string())?
            .query_one("SELECT updated_at FROM public.sessions WHERE id=$1", &[&A_ID]).await.map_err(|e|e.to_string())?.get(0);
        require(updated_after >= updated_before, "normal Authenticated touch must not move session idle time backwards")?;
        let generation: Option<i64> = f.pool.get().await.map_err(|e|e.to_string())?
            .query_one("SELECT auth_generation FROM public.users WHERE id=$1", &[&OWNER]).await.map_err(|e|e.to_string())?.get(0);
        f.sql("DELETE FROM public.sessions WHERE id='actual-read-session-a'").await?;
        static_error(&request(f.router.clone(), COOKIE_A, Method::GET, &uri, "").await?, StatusCode::UNAUTHORIZED, "unauthenticated")?;
        require(f.execute(&auth_a, &f.receipt.request_id).await.err() == Some(AppError::Unauthenticated),
            "retained original A attachment must not revive deleted session")?;
        let peer = request(f.router.clone(), COOKIE_B, Method::GET, &uri, "").await?;
        require(peer.status == StatusCode::OK && peer.value == Some(serde_json::to_value(&f.receipt).map_err(|e|e.to_string())?),
            "real unaffected B must remain positive after A deletion")?;
        let current_generation: Option<i64> = f.pool.get().await.map_err(|e|e.to_string())?
            .query_one("SELECT auth_generation FROM public.users WHERE id=$1", &[&OWNER]).await.map_err(|e|e.to_string())?.get(0);
        require(current_generation == generation && f.facts().await? == before && f.bytes()? == before_bytes,
            "session-specific refusal altered original generation/artifact facts")?;
        eprintln!("SAVE_RECEIPT_GENUINE_SESSION original_receipt=true same_actor_distinct_A_B=true normal_idle_touch_allowed={} artifact_business_unchanged=true", updated_after >= updated_before);
        Ok(())
    })).await;
}

// Only the original response on an owned loopback PostgreSQL connection is held. The server
// has actually executed ROLLBACK; its CommandComplete and following ReadyForQuery have not
// reached the same consumer future. No Drop, fake ACK, or after-ACK trace stands in for this.
struct RollbackAckControl {
    armed: AtomicBool,
    held: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    timed_out: AtomicBool,
}
struct RollbackAckProxy {
    port: u16,
    control: Arc<RollbackAckControl>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}
impl RollbackAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let own_port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let control = Arc::new(RollbackAckControl {
            armed: AtomicBool::new(false),
            held: std::sync::atomic::AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            timed_out: AtomicBool::new(false),
        });
        let owned = control.clone();
        let (shutdown, mut stopping) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    _ = &mut stopping => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((client, _)) = accepted else {
                    break;
                };
                let host = host.clone();
                let control = owned.clone();
                children.spawn(async move {
                    let server = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err::<(), std::io::Error>(std::io::Error::other(
                                    "invalid owned backend frame",
                                ));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C'
                                && payload == b"ROLLBACK\0"
                                && control.armed.swap(false, Ordering::SeqCst)
                            {
                                control.held.fetch_add(1, Ordering::SeqCst);
                                control.entered.notify_one();
                                if tokio::time::timeout(
                                    Duration::from_secs(3),
                                    control.release.notified(),
                                )
                                .await
                                .is_err()
                                {
                                    control.timed_out.store(true, Ordering::SeqCst);
                                    return Err(std::io::Error::other(
                                        "original rollback ACK was not released",
                                    ));
                                }
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = backend => {},
                    }
                    Ok::<(), std::io::Error>(())
                });
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(Self {
            port: own_port,
            control,
            shutdown: Some(shutdown),
            worker: Some(worker),
        })
    }
    async fn finish(mut self) -> Result<(), String> {
        self.control.release.notify_one();
        if let Some(stopping) = self.shutdown.take() {
            let _ = stopping.send(());
        }
        let mut worker = self
            .worker
            .take()
            .ok_or("owned rollback proxy task missing")?;
        match tokio::time::timeout(Duration::from_secs(5), &mut worker).await {
            Ok(joined) => joined.map_err(|e| e.to_string()),
            Err(_) => {
                worker.abort();
                let _ = worker.await;
                Err("owned rollback proxy failed normal task join".to_owned())
            }
        }
    }
}
impl Drop for RollbackAckProxy {
    fn drop(&mut self) {
        self.control.release.notify_one();
        if let Some(stopping) = self.shutdown.take() {
            let _ = stopping.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

async fn pending_original_ack_case(source: &'static str, tail: &'static str) {
    let tag = format!("receipt_ack_{source}_{tail}");
    harness::with_temp_database(&harness::admin_config(&tag), &tag, |config| async move {
        let proxy = RollbackAckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config;
        proxied.host = "127.0.0.1".into();
        proxied.port = proxy.port;
        let fixture = match Fixture::new(proxied).await {
            Ok(fixture) => fixture,
            Err(error) => { proxy.finish().await?; return Err(error); }
        };
        let result = async {
            let request_id = if source == "missing" { Uuid::now_v7().to_string() }
                else { fixture.receipt.request_id.clone() };
            if source == "corrupt" { fixture.corrupt(true).await?; }
            if source == "terminal" { fixture.terminal_reader_fixture().await?; }
            let before = fixture.facts().await?;
            let before_bytes = fixture.bytes()?;
            let expires = OffsetDateTime::now_utc() + time::Duration::milliseconds(900);
            if tail == "clock" {
                require(fixture.pool.get().await.map_err(|e| e.to_string())?
                    .execute("UPDATE public.sessions SET expires_at=$1 WHERE id=$2", &[&expires, &A_ID])
                    .await.map_err(|e| e.to_string())? == 1, "actual Session expiry setup missing")?;
            }
            // Let the actual joint result reach the production rollback boundary before arming
            // the sole response hold; resolver/schema setup cannot consume the rollback trap.
            let gate = ReceiptGate::new("joint_result_observed_before_rollback");
            let _release = ReleaseGate(gate.clone());
            let router = fixture.router.clone();
            let uri = route(&request_id);
            let task = tokio::spawn(async move {
                request(router, COOKIE_A, Method::GET, &uri, "").await
            }.with_subscriber(tracing::Dispatch::new(ReceiptSubscriber(gate.clone()))));
            let attempted = async {
                await_receipt_gate(&gate).await?;
                require(gate.phases.load(Ordering::SeqCst) == 3 && !task.is_finished(),
                    "actual joint result did not precede original rollback")?;
                proxy.control.armed.store(true, Ordering::SeqCst);
                gate.release();
                tokio::time::timeout(Duration::from_secs(2), proxy.control.entered.notified())
                    .await.map_err(|_| "actual ROLLBACK frame was never held".to_owned())?;
                require(proxy.control.held.load(Ordering::SeqCst) == 1
                    && gate.phases.load(Ordering::SeqCst) == 3 && !task.is_finished(),
                    "same original request escaped before physical rollback ACK")?;
                if tail == "owner" {
                    fixture.resolver.close_request_bindings();
                } else {
                    while OffsetDateTime::now_utc() <= expires {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                require(!task.is_finished() && gate.phases.load(Ordering::SeqCst) == 3,
                    "original outcome escaped while its ACK was still withheld")
            }.await;
            gate.release();
            proxy.control.release.notify_one();
            let joined = task.await.map_err(|e| e.to_string());
            attempted?;
            static_error(&joined??, StatusCode::UNAUTHORIZED, "unauthenticated")?;
            require(gate.phases.load(Ordering::SeqCst) == 7
                && !gate.timed_out.load(Ordering::SeqCst)
                && !proxy.control.timed_out.load(Ordering::SeqCst),
                "same original rollback did not receive its released ACK before tail")?;
            require(fixture.facts().await? == before && fixture.bytes()? == before_bytes,
                "held original receipt outcome changed durable artifact or physical object facts")?;
            eprintln!("SAVE_RECEIPT_SESSION_REAL_ROLLBACK source={source} tail={tail} original_rollback_frame_held=true request_pending_before_original_ACK=true same_original_ACK_released=true original_401=true first_poll_core_gate_qualification=false");
            Ok::<_, String>(())
        }.await;
        fixture.pool.close();
        drop(fixture);
        let stopped = proxy.finish().await;
        eprintln!("SAVE_RECEIPT_SESSION_PROXY joined={} presumed_drop_ACK=false", stopped.is_ok());
        result.and(stopped)
    }).await;
}

async fn current_host_first_cases(fixture: &Fixture) -> Result<(), String> {
    let original = fixture.auth(COOKIE_A).await?;
    let mutations = [
        (
            "raw_null",
            "UPDATE public.users SET auth_generation=NULL WHERE id='current-read-owner'",
            "UPDATE public.users SET auth_generation=0 WHERE id='current-read-owner'",
        ),
        (
            "generation",
            "UPDATE public.users SET auth_generation=1 WHERE id='current-read-owner'",
            "UPDATE public.users SET auth_generation=0 WHERE id='current-read-owner'",
        ),
        (
            "role",
            "UPDATE public.user_roles SET role='admin' WHERE user_id='current-read-owner'",
            "UPDATE public.user_roles SET role='user' WHERE user_id='current-read-owner'",
        ),
        (
            "deny",
            "INSERT INTO public.revoked_access(email,revoked_by) VALUES('current-read-owner@example.test','current-read-owner')",
            "DELETE FROM public.revoked_access WHERE email='current-read-owner@example.test'",
        ),
    ];
    for (name, mutation, restore) in mutations {
        fixture.sql(mutation).await?;
        let attempted = async {
            for source in ["valid", "missing", "corrupt"] {
                let locator = if source == "missing" { Uuid::now_v7().to_string() }
                    else { fixture.receipt.request_id.clone() };
                if source == "corrupt" { fixture.corrupt(true).await?; }
                let before = fixture.facts().await?;
                let bytes = fixture.bytes()?;
                let outcome = fixture.execute(&original, &locator).await;
                let wire = request(fixture.router.clone(), COOKIE_A, Method::GET, &route(&locator), "").await;
                let facts_unchanged = fixture.facts().await? == before;
                let bytes_unchanged = fixture.bytes()? == bytes;
                let restored = if source == "corrupt" { fixture.corrupt(false).await } else { Ok(()) };
                require(outcome == Err(AppError::Unauthenticated), "real joint host-first released source outcome under invalid original host")?;
                if name != "role" {
                    static_error(&wire?, StatusCode::UNAUTHORIZED, "unauthenticated")?;
                } else {
                    // A fresh resolver may legitimately mint the newly effective Admin+User.
                    // Only the retained original User attachment is stale in this row.
                    let expected = match source {
                        "missing" => StatusCode::NOT_FOUND,
                        "corrupt" => StatusCode::SERVICE_UNAVAILABLE,
                        _ => StatusCode::OK,
                    };
                    require(wire?.status == expected, "fresh role resolver confused current and retained original authority")?;
                }
                require(facts_unchanged && bytes_unchanged, "host-first observer altered durable facts or original bytes")?;
                restored?;
                eprintln!("SAVE_RECEIPT_SESSION_HOST_FIRST mutation={name} source={source} schema_intact=true retained_original_401=true fresh_role_resolver_distinguished={}", name == "role");
            }
            Ok::<_, String>(())
        }.await;
        let restored = fixture.sql(restore).await;
        attempted.and(restored)?;
    }
    // A deliberately broken native constraint invalidates schema trust before decoding the
    // host. Its correct result is 503; it cannot count as a valid-schema negative-generation 401.
    fixture.sql("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='current-read-owner'").await?;
    let attempted = fixture
        .execute(&original, &Uuid::now_v7().to_string())
        .await;
    let restored = fixture.sql("UPDATE public.users SET auth_generation=0 WHERE id='current-read-owner'; ALTER TABLE public.users ADD CONSTRAINT users_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation>=0)").await;
    require(
        matches!(attempted, Err(AppError::DependencyUnavailable { .. })),
        "broken native schema must remain unavailable",
    )?;
    restored?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, genuine Session joint SQL Lock/PIDs/COMMIT and original rollback ACK"]
async fn genuine_session_joint_host_first_and_lock_release_withhold_stale_receipt_results() {
    with_fixture("receipt_host_first", |fixture| {
        Box::pin(current_host_first_cases(fixture))
    })
    .await;
    for mode in [
        "release_positive",
        "session_delete",
        "source_revoke",
        "both",
    ] {
        with_fixture("receipt_joint_lock", move |fixture| {
            Box::pin(query_wait_case(fixture, mode))
        })
        .await;
    }
    for source in ["valid", "missing", "terminal", "corrupt"] {
        for tail in ["owner", "clock"] {
            pending_original_ack_case(source, tail).await;
        }
    }
}
