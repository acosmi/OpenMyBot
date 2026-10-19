//! New finite public-reader tests use owned PostgreSQL, real sessions, Application and body polls.
//! These fixtures never connect to a user database or claim OS/client copy closure.

mod harness {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}

use crate::auth::SensitiveWriteSecurity;
use crate::config::{EnvMap, ServerConfig};
use crate::{AuthResolver, PostgresSessionAuthResolver, ServerBuilder};
use axum::body::{Body, to_bytes};
use futures_util::StreamExt as _;
use http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory,
};
use openbot_contracts::artifact_read_protocol::{
    ArtifactReadAcknowledged, ArtifactReadClosed, ArtifactReadOpened,
};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool, pool::DatabaseConfig};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

const DEPLOYMENT: &str = "artifact-current-host-deployment";
const TENANT: &str = "artifact-current-host-tenant";
const OWNER: &str = "current-read-owner";
const A_ID: &str = "actual-read-session-a";
const B_ID: &str = "actual-read-session-b";
const COOKIE_A: &str = "owned-current-artifact-read-session-token-a-001";
const COOKIE_B: &str = "owned-current-artifact-read-session-token-b-002";
const SESSION_KEY: &[u8] = b"owned-current-artifact-read-session-hash-key";
const TEXT: &str = "small actual Begin; controlled source update precedes actual Save";
const FIRST_BLOCK: usize = 4 * 1024 * 1024;
const ORIGIN: &str = "https://public-reader.example.test";

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

struct OwnedRoot(PathBuf, bool);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path =
            std::env::temp_dir().join(format!("openbot-public-artifact-read-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path, true))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if !self.1 {
            eprintln!("PUBLIC_ARTIFACT_SERVER_ROOT_CLEANUP retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "PUBLIC_ARTIFACT_SERVER_ROOT_CLEANUP removed={} absent={absent}",
            removed.is_ok()
        );
        if !std::thread::panicking() {
            assert!(removed.is_ok() && absent, "owned read root did not close");
        }
    }
}

type OriginalCompletion =
    Arc<dyn openbot_application::artifact_read_protocol::ArtifactReadOperationCompletion>;

#[derive(Default)]
struct OriginalCompletions(Mutex<Vec<OriginalCompletion>>);
impl OriginalCompletions {
    fn count(&self) -> Result<usize, String> {
        self.0
            .lock()
            .map(|entries| entries.len())
            .map_err(|_| "original completion capture poisoned".to_owned())
    }
    fn original_after(&self, before: usize) -> Result<OriginalCompletion, String> {
        let entries = self
            .0
            .lock()
            .map_err(|_| "original completion capture poisoned".to_owned())?;
        require(
            entries.len() == before + 1,
            "actual Open did not enroll exactly one original operation",
        )?;
        entries
            .get(before)
            .cloned()
            .ok_or_else(|| "original operation enrollment missing".to_owned())
    }
}
struct OriginalObserver {
    downstream:
        Arc<dyn openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver>,
    captured: Arc<OriginalCompletions>,
}
impl openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver
    for OriginalObserver
{
    fn original_entry_stop(
        &self,
    ) -> Option<Arc<dyn openbot_application::artifact_read_protocol::ArtifactReadEntryStop>> {
        self.downstream.original_entry_stop()
    }
    fn enrolled(
        &self,
        completion: OriginalCompletion,
    ) -> Result<(), openbot_contracts::error::AppError> {
        // The Application receives exactly the same actual Arc as PreparedArtifactRead.
        // Capturing an additional owner does not create or replace its physical completion.
        self.downstream.enrolled(Arc::clone(&completion))?;
        self.captured
            .0
            .lock()
            .map_err(
                |_| openbot_contracts::error::AppError::DependencyUnavailable {
                    dependency: "artifacts",
                },
            )?
            .push(completion);
        Ok(())
    }
}
struct ObservedAdministration {
    actual: Arc<PostgresArtifactAdministration>,
    captured: Arc<OriginalCompletions>,
}
#[async_trait::async_trait]
impl ArtifactAdministration for ObservedAdministration {
    async fn prepare_host_bound_artifact_read(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        artifact_id: &str,
        original_deadline: Instant,
        observer: Arc<
            dyn openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver,
        >,
    ) -> Result<
        openbot_application::artifact_read_protocol::PreparedArtifactRead,
        openbot_contracts::error::AppError,
    > {
        self.actual
            .prepare_host_bound_artifact_read(
                auth,
                artifact_id,
                original_deadline,
                Arc::new(OriginalObserver {
                    downstream: observer,
                    captured: Arc::clone(&self.captured),
                }),
            )
            .await
    }
    async fn observe_source_run_artifact_ids_current(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        input: &openbot_contracts::artifacts::GetSourceRunArtifactIds,
        deadline: Instant,
    ) -> openbot_contracts::request_binding::SourceRunArtifactIdsCurrentOutcome {
        self.actual
            .observe_source_run_artifact_ids_current(auth, input, deadline)
            .await
    }
    async fn open_host_bound_read_operation(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadOperation, openbot_contracts::error::AppError>
    {
        self.actual
            .open_host_bound_read_operation(auth, artifact_id)
            .await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        artifact_id: &str,
    ) -> Result<openbot_application::CurrentArtifactReadChunk, openbot_contracts::error::AppError>
    {
        self.actual.read_host_bound_chunk(auth, artifact_id).await
    }
    async fn save_run_message_text(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, openbot_application::ArtifactAdministrationError> {
        self.actual.save_run_message_text(auth, input).await
    }
    async fn get_metadata(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        artifact_id: &str,
    ) -> Result<
        openbot_contracts::artifacts::ArtifactMetadata,
        openbot_application::ArtifactAdministrationError,
    > {
        self.actual.get_metadata(auth, artifact_id).await
    }
}

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    resolver: Arc<PostgresSessionAuthResolver>,
    application: Arc<dyn ApplicationService>,
    router: axum::Router,
    actual: Arc<PostgresArtifactAdministration>,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    begin: BeginThreadRunRequest,
    original_completions: Arc<OriginalCompletions>,
    payload: String,
    receipt: ArtifactRegistrationReceipt,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, length: usize) -> Result<Self, String> {
        let payload = "L".repeat(length);
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
        // The public Begin remains small. Only this owned database fixture is then updated;
        // this does not claim the public Begin surface accepts a multi-megabyte message.
        let changed = pool.get().await.map_err(|error| error.to_string())?.execute(
            "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb($2::text)), search_text=$2 WHERE message_id=$1",
            &[&format!("{}:input", begin.command.run_id.as_str()), &payload],
        ).await.map_err(|error| error.to_string())?;
        require(
            changed == 1,
            "owned fixture did not change exactly its original source",
        )?;
        let mut root = OwnedRoot::new()?;
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
                registry.clone(),
                store.clone(),
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
                    expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        let original_completions = Arc::new(OriginalCompletions::default());
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(Arc::new(ObservedAdministration {
                actual: Arc::clone(&actual),
                captured: Arc::clone(&original_completions),
            })),
        );
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|error| format!("fixture transport config: {error:?}"))?
            .transport_policy(true);
        let router = ServerBuilder::new(application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured([ORIGIN]).map_err(|error| error.to_string())?,
            ))
            .into_router()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 40_012)),
            )));
        root.1 = false;
        Ok(Self {
            pool,
            resolver,
            application,
            router,
            actual,
            registry,
            store,
            begin,
            original_completions,
            payload,
            receipt,
            root,
        })
    }

    async fn request_raw(
        &self,
        method: Method,
        path: &str,
        cookie: &str,
        body: Vec<u8>,
    ) -> Result<axum::response::Response, String> {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", format!("openbot_session={cookie}"))
            .header("origin", ORIGIN)
            .header("content-type", "application/json")
            .header("content-length", body.len().to_string())
            .body(Body::from(body))
            .map_err(|error| error.to_string())?;
        self.router
            .clone()
            .oneshot(request)
            .await
            .map_err(|error| error.to_string())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        cookie: &str,
        body: Option<serde_json::Value>,
    ) -> Result<axum::response::Response, String> {
        let body = body
            .map(|value| serde_json::to_vec(&value))
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        self.request_raw(method, path, cookie, body).await
    }

    async fn open(&self, cookie: &str) -> Result<ArtifactReadOpened, String> {
        control(
            self.request(
                Method::POST,
                super::PREFIX,
                cookie,
                Some(serde_json::json!({"artifactId": self.receipt.artifact_id})),
            )
            .await?,
        )
        .await
    }

    async fn next(
        &self,
        cookie: &str,
        handle: &str,
        sequence: u32,
    ) -> Result<axum::response::Response, String> {
        self.request(
            Method::POST,
            &format!("{}/{handle}/next", super::PREFIX),
            cookie,
            Some(serde_json::json!({"sequence": sequence})),
        )
        .await
    }

    async fn open_with_original_completion(
        &self,
        cookie: &str,
    ) -> Result<(ArtifactReadOpened, OriginalCompletion), String> {
        let before = self.original_completions.count()?;
        let opened = self.open(cookie).await?;
        let completion = self.original_completions.original_after(before)?;
        Ok((opened, completion))
    }

    async fn ack(
        &self,
        cookie: &str,
        handle: &str,
        sequence: u32,
    ) -> Result<axum::response::Response, String> {
        self.request(
            Method::POST,
            &format!("{}/{handle}/ack", super::PREFIX),
            cookie,
            Some(serde_json::json!({"sequence": sequence})),
        )
        .await
    }

    async fn close(&self, cookie: &str, handle: &str) -> Result<axum::response::Response, String> {
        self.request(
            Method::DELETE,
            &format!("{}/{handle}", super::PREFIX),
            cookie,
            None,
        )
        .await
    }

    async fn finish(mut self) -> Result<(), String> {
        self.resolver.close_request_bindings();
        let closed = self.application.close_public_artifact_reads();
        let lifecycle = self.actual.read_authority().read_lifecycle();
        lifecycle.close();
        let drained = lifecycle
            .drain_before(Instant::now() + Duration::from_secs(5))
            .await;
        self.pool.close();
        require(
            closed.is_ok(),
            "actual Application reader owner closure refused",
        )?;
        require(
            drained.is_ok(),
            "actual Server original read inventory did not drain",
        )?;
        require(
            self.root.0.is_dir(),
            "owned original artifact root changed before closure",
        )?;
        self.root.1 = true;
        eprintln!("PUBLIC_ARTIFACT_SERVER_PHYSICAL_CLEANUP actual_inventory_drained=true");
        Ok(())
    }
}

async fn shared_public_business_facts(fixture: &Fixture) -> Result<serde_json::Value, String> {
    fixture.pool.get().await.map_err(|error| error.to_string())?.query_one(
        "SELECT jsonb_build_object( \
         'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
         'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
         'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
         'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
         'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
         'fences',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]') FROM openbot_internal.artifact_cleanup_fences c), \
         'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]') FROM openbot_internal.artifact_store_bindings s), \
         'registry',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY to_jsonb(b)::text),'[]') FROM openbot_internal.artifact_dataset_bindings b), \
         'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM public.audit_events a))", &[],
    ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
}

fn shared_public_peer(
    fixture: &Fixture,
) -> Result<
    (
        Arc<PostgresArtifactAdministration>,
        Arc<PostgresSessionAuthResolver>,
        crate::ServerState,
    ),
    String,
> {
    let actual = Arc::new(
        PostgresArtifactAdministration::new(
            fixture.registry.clone(),
            fixture.store.clone(),
            ArtifactQuotaPolicy::default(),
            SecretBytes::new(vec![0x88; 32]),
        )
        .map_err(|error| error.to_string())?,
    );
    let resolver = Arc::new(
        PostgresSessionAuthResolver::new(
            fixture.pool.clone(),
            SESSION_KEY,
            default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
        )
        .map_err(|error| error.to_string())?,
    );
    resolver
        .install_artifact_read_authority(&actual.read_authority())
        .map_err(|_| "independent actual resolver enrollment refused".to_owned())?;
    let application: Arc<dyn ApplicationService> = Arc::new(
        openbot_application::OpenBotApplication::new(
            openbot_infra::repo::channels::ChannelRepo::new(fixture.pool.clone()),
        )
        .with_artifacts(actual.clone()),
    );
    let policy = ServerConfig::from_env_map(&EnvMap::new())
        .map_err(|error| format!("shared peer policy: {error:?}"))?
        .transport_policy(true);
    let state = ServerBuilder::new(application, resolver.clone())
        .with_transport_policy(policy)
        .build();
    Ok((actual, resolver, state))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, actual shared Store and independent Server Session guards"]
async fn shared_read_barrier_closes_all_administrations_and_keeps_other_artifact() {
    let tag = "shared-administration-key";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 31).await?;
        let outcome = async {
            let auth_a = fixture.resolver.resolve(&parts(COOKIE_A)?).await.map_err(|error| error.to_string())?;
            let record = fixture.actual.observe_read_record(&auth_a, &fixture.receipt.artifact_id).await.map_err(|error| error.to_string())?;
            let (admin_b, resolver_b, state_b) = shared_public_peer(&fixture)?;
            let auth_b = resolver_b.resolve(&parts(COOKIE_B)?).await.map_err(|error| error.to_string())?;
            require(!auth_a.request_binding().ok_or("original A binding missing")?.identity().same_binding(
                auth_b.request_binding().ok_or("independent B binding missing")?.identity()),
                "cross-administration test reused the original host guard")?;
            require(admin_b.read_host_bound_chunk(&auth_a, &fixture.receipt.artifact_id).await.is_err(),
                "B authority accepted A's real Session guard")?;
            let saved_b = admin_b.save_run_message_text(&auth_b, SaveRunMessageTextArtifact {
                request_id: Uuid::now_v7().to_string(),
                source_thread_id: fixture.begin.command.thread_id.clone(), source_run_id: fixture.begin.command.run_id.clone(),
                source_message_id: format!("{}:input", fixture.begin.command.run_id.as_str()),
                expected_sha256: format!("{:x}", Sha256::digest(fixture.payload.as_bytes())),
            }).await.map_err(|error| error.to_string())?;
            require(saved_b.artifact_id != fixture.receipt.artifact_id && saved_b.operation_id != fixture.receipt.operation_id,
                "other artifact did not come from a distinct actual Save")?;

            // A different actual namespace/root owner cannot close the original Store snapshot.
            let mut foreign_root = OwnedRoot::new()?;
            let foreign_registry = Arc::new(ArtifactDatasetRegistry::from_server(fixture.pool.clone(),
                &DeploymentId::new("shared-foreign-deployment"), &TenantId::new("shared-foreign-tenant"))
                .await.map_err(|error| error.to_string())?);
            let foreign_store = Arc::new(DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&foreign_root.0).map_err(|error| error.to_string())?, foreign_registry.clone(), ArtifactQuotaPolicy::default(),
            ).await.map_err(|error| error.to_string())?);
            let foreign_weak = Arc::downgrade(&foreign_store);
            let foreign = Arc::new(PostgresArtifactAdministration::new(foreign_registry.clone(), foreign_store.clone(),
                ArtifactQuotaPolicy::default(), SecretBytes::new(vec![0x88; 32])).map_err(|error| error.to_string())?);
            require(foreign.close_observed_artifact_reads(&record).is_err(), "actual foreign Store closed an original snapshot by string identity")?;
            drop(foreign); drop(foreign_store); drop(foreign_registry);
            require(foreign_weak.upgrade().is_none(), "extra foreign test Store Arc remained live")?;
            let original_root = std::fs::File::open(&foreign_root.0).map_err(|error| error.to_string())?;
            require(original_root.try_lock().is_ok(), "actual foreign Store kernel owner survived last Arc Drop")?;
            drop(original_root); foreign_root.1 = true; drop(foreign_root);

            let before = shared_public_business_facts(&fixture).await?;
            let mut a = fixture.actual.open_host_bound_read_operation(&auth_a, &fixture.receipt.artifact_id).await.map_err(|error| error.to_string())?;
            let mut b = state_b.open_current_artifact_read(&parts(COOKIE_B)?, fixture.receipt.artifact_id.clone()).await.map_err(|error| error.to_string())?;
            let a_block = a.next_block(&auth_a).await.map_err(|error| error.to_string())?.handoff_frame(&auth_a).map_err(|error| error.to_string())?;
            let b_block = b.next_block().await.map_err(|error| error.to_string())?.ok_or("B original block missing")?;
            require(a_block.as_bytes() == fixture.payload.as_bytes() && b_block.as_bytes() == fixture.payload.as_bytes(),
                "two real original guards did not read the same original Store bytes")?;
            let barrier = Arc::new(fixture.actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?);
            require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(), "shared close ignored held A/B original allocations")?;
            let waiter_barrier = barrier.clone();
            let (entered, reached) = tokio::sync::oneshot::channel();
            let waiter = tokio::spawn(async move {
                let mut original_wait = Box::pin(waiter_barrier.drain_before(Instant::now() + Duration::from_secs(5)));
                let pending = tokio::time::timeout(Duration::from_millis(25), original_wait.as_mut()).await.is_err();
                let _ = entered.send(pending);
                original_wait.await
            });
            require(reached.await.map_err(|error| error.to_string())?, "shared drain cancellation did not poll a truly pending original waiter")?;
            waiter.abort();
            require(waiter.await.is_err_and(|error| error.is_cancelled()), "shared drain waiter was not actually reaped")?;
            drop(barrier);
            let (admin_c, resolver_c, state_c) = shared_public_peer(&fixture)?;
            require(state_b.read_current_artifact_chunk(&parts(COOKIE_B)?, fixture.receipt.artifact_id.clone()).await.is_err()
                && state_c.read_current_artifact_chunk(&parts(COOKIE_A)?, fixture.receipt.artifact_id.clone()).await.is_err(),
                "timeout/cancel/barrier Drop or new administration reopened the shared body gate")?;
            let other = state_c.read_current_artifact_chunk(&parts(COOKIE_A)?, saved_b.artifact_id.clone()).await.map_err(|error| error.to_string())?;
            require(other == fixture.payload.as_bytes(), "closing the original key blocked the other actual Save")?;
            drop(other); // successful legacy raw bytes remain an external ownership boundary.
            let barrier = admin_c.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
            require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(), "recreating a waiter discarded held A/B inventory")?;
            drop(a_block); drop(b_block); drop(a); drop(b);
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
            require(before == shared_public_business_facts(&fixture).await?, "shared close mutated original business/charge/receipt/fence/store/audit facts")?;
            require(fixture.root.0.join("objects").join(&fixture.receipt.artifact_id).is_file(), "shared gate performed unregistered deletion")?;
            drop(ack); drop(barrier); drop(record);
            resolver_b.close_request_bindings(); resolver_c.close_request_bindings();
            for authority in [admin_b.read_authority(), admin_c.read_authority()] {
                let lifecycle = authority.read_lifecycle(); lifecycle.close();
                lifecycle.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
            }
            drop(state_b); drop(state_c); drop(admin_b); drop(admin_c); drop(resolver_b); drop(resolver_c);
            eprintln!("ARTIFACT_SHARED_ADMINS real_a_b_c_guards=true foreign_store_refused=true other_actual_save_readable=true timeout_cancel_drop_permanent=true controlled_ack=true auth_idle_touch=allowed deletion=false");
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and actual last Server Bytes clone ownership"]
async fn shared_read_barrier_waits_for_original_server_bytes_last_owner() {
    let tag = "shared-server-bytes-owner";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 37).await?;
        let outcome = async {
            let auth = fixture.resolver.resolve(&parts(COOKIE_A)?).await.map_err(|error| error.to_string())?;
            let record = fixture.actual.observe_read_record(&auth, &fixture.receipt.artifact_id).await.map_err(|error| error.to_string())?;
            let before = shared_public_business_facts(&fixture).await?;
            let opened = fixture.open(COOKIE_A).await?;
            let response = fixture.next(COOKIE_A, &opened.handle_id, 0).await?;
            data_headers(&response, &opened.handle_id, 0)?;
            let mut body = response.into_body().into_data_stream();
            let bytes = body.next().await.ok_or("real body never yielded its original carrier")?.map_err(|error| error.to_string())?;
            let held = bytes.clone();
            let sliced = bytes.slice(1..bytes.len());
            require(body.next().await.is_none(), "real body did not perform its terminal poll")?;
            drop(body); drop(bytes);
            let path = fixture.root.0.join("objects").join(&fixture.receipt.artifact_id);
            require(cleanup_owned_inode_fds(&path)?.len() == 1, "held real Bytes carriers did not retain the original FD")?;
            let barrier = fixture.actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
            require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(), "shared close ACKed with original clone and slice held")?;
            require(held.as_ref() == fixture.payload.as_bytes(), "shared stop was falsely represented as revoking already-selected bytes")?;
            drop(held);
            require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(), "clone Drop ignored the surviving actual Bytes slice owner")?;
            drop(sliced);
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|error| format!("{error:?}"))?;
            require(cleanup_owned_inode_fds(&path)?.is_empty() && path.is_file(), "last real Bytes owner did not end its actual FD or performed deletion")?;
            require(before == shared_public_business_facts(&fixture).await?, "shared Server close changed original business facts")?;
            drop(ack); drop(barrier); drop(record);
            eprintln!("ARTIFACT_SHARED_SERVER body_terminal=true clone_held_no_ack=true slice_held_no_ack=true last_owner_drop=true original_fd_absent=true controlled_ack=true");
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}

fn no_store(response: &axum::response::Response) -> Result<(), String> {
    require(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "public-reader response omitted no-store",
    )
}

async fn control<T: serde::de::DeserializeOwned>(
    response: axum::response::Response,
) -> Result<T, String> {
    no_store(&response)?;
    require(
        response.status() == StatusCode::OK,
        "actual public control was not successful",
    )?;
    let body = to_bytes(response.into_body(), 8192)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

async fn status(response: axum::response::Response, expected: StatusCode) -> Result<(), String> {
    no_store(&response)?;
    require(
        response.status() == expected,
        "public-reader refusal had an unexpected status",
    )?;
    let body = to_bytes(response.into_body(), 8192)
        .await
        .map_err(|error| error.to_string())?;
    require(
        !body.windows(TEXT.len()).any(|part| part == TEXT.as_bytes()),
        "public-reader refusal exposed source text",
    )
}

fn data_headers(
    response: &axum::response::Response,
    handle: &str,
    sequence: u32,
) -> Result<(usize, bool), String> {
    no_store(response)?;
    require(
        response.status() == StatusCode::OK,
        "actual public block was not successful",
    )
    .map_err(|message| {
        format!(
            "{message}: status={} input_sequence={sequence}",
            response.status().as_u16()
        )
    })?;
    require(
        response.headers().get("content-length").is_none(),
        "zero-length framing could bypass the actual EOF body poll",
    )?;
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or("actual public block header missing".to_owned())
    };
    require(
        header("x-artifact-read-handle")? == handle,
        "block handle changed",
    )?;
    require(
        header("x-artifact-read-sequence")?
            .parse::<u32>()
            .map_err(|error| error.to_string())?
            == sequence,
        "block sequence changed",
    )?;
    let length = header("x-artifact-read-length")?
        .parse::<usize>()
        .map_err(|error| error.to_string())?;
    let eof = match header("x-artifact-read-eof")? {
        "true" => true,
        "false" => false,
        _ => return Err("actual EOF header was not closed boolean framing".to_owned()),
    };
    require(
        length <= FIRST_BLOCK && eof == (length == 0),
        "actual block shape was invalid",
    )?;
    Ok((length, eof))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; real sessions and original public byte carriers"]
async fn actual_server_session_public_reader_stream_ack_eof_and_foreign_scope() {
    let tag = "public-reader-stream";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, FIRST_BLOCK + 913).await?;
        let outcome = async {
            let opened = fixture.open(COOKIE_A).await?;
            require(
                opened.artifact_id == fixture.receipt.artifact_id
                    && opened.byte_length == fixture.payload.len() as u64
                    && opened.sha256 == format!("{:x}", Sha256::digest(fixture.payload.as_bytes()))
                    && opened.remaining_millis > 0
                    && opened.remaining_millis <= 600_000,
                "Open did not return actual same-record bounded facts",
            )?;
            status(
                fixture.next(COOKIE_B, &opened.handle_id, 0).await?,
                StatusCode::NOT_FOUND,
            )
            .await?;
            status(
                fixture.ack(COOKIE_B, &opened.handle_id, 0).await?,
                StatusCode::NOT_FOUND,
            )
            .await?;
            let mut sequence = 0_u32;
            let mut received = Vec::new();
            loop {
                let response = fixture.next(COOKIE_A, &opened.handle_id, sequence).await?;
                let (length, eof) = data_headers(&response, &opened.handle_id, sequence)?;
                let bytes = to_bytes(response.into_body(), FIRST_BLOCK)
                    .await
                    .map_err(|error| error.to_string())?;
                require(
                    bytes.len() == length,
                    "actual carrier length differed from descriptor",
                )?;
                if eof {
                    require(bytes.is_empty(), "actual zero EOF delivered bytes")?;
                    break;
                }
                require(!bytes.is_empty(), "non-EOF omitted its actual prefix")?;
                received.extend_from_slice(&bytes);
                status(
                    fixture.next(COOKIE_A, &opened.handle_id, sequence).await?,
                    StatusCode::CONFLICT,
                )
                .await?;
                status(
                    fixture
                        .ack(COOKIE_A, &opened.handle_id, sequence + 1)
                        .await?,
                    StatusCode::CONFLICT,
                )
                .await?;
                // The original body owner, not this test's copied transcript, must end before ACK.
                drop(bytes);
                let ack: ArtifactReadAcknowledged =
                    control(fixture.ack(COOKIE_A, &opened.handle_id, sequence).await?).await?;
                let duplicate: ArtifactReadAcknowledged =
                    control(fixture.ack(COOKIE_A, &opened.handle_id, sequence).await?).await?;
                require(
                    ack == duplicate
                        && ack.handle_id == opened.handle_id
                        && ack.sequence == sequence,
                    "matching ACK retry changed or replayed the original block",
                )?;
                sequence = sequence.checked_add(1).ok_or("test sequence overflow")?;
                require(
                    received.len() <= fixture.payload.len(),
                    "reader replayed a prior prefix",
                )?;
            }
            require(
                received.as_slice() == fixture.payload.as_bytes(),
                "actual sequential bytes did not reconstruct original source",
            )?;
            require(
                format!("{:x}", Sha256::digest(&received)) == opened.sha256,
                "actual reconstructed bytes failed the prepared original digest",
            )?;
            // A genuine zero EOF already requires true original per-reader completion.
            // No additional post-EOF Close idempotency contract is assumed here.
            Ok(())
        }
        .await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and an acknowledged pre-BEGIN schema refusal"]
async fn actual_completed_schema_refusal_does_not_poison_shared_read_admission() {
    let tag = "read_schema_refusal";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 4096).await?;
        let outcome = async {
            let auth = fixture.resolver.resolve(&parts(COOKIE_A)?).await.map_err(|e| e.to_string())?;
            let record = fixture.actual.observe_read_record(&auth, &fixture.receipt.artifact_id).await.map_err(|e| e.to_string())?;
            for (disable, restore) in [
                ("ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_saved_receipt_guard",
                 "ALTER TABLE openbot_internal.artifact_cleanup_fences ENABLE TRIGGER artifact_cleanup_fences_saved_receipt_guard"),
                ("ALTER TABLE openbot_internal.artifact_records DISABLE TRIGGER artifact_records_identity_guard",
                 "ALTER TABLE openbot_internal.artifact_records ENABLE TRIGGER artifact_records_identity_guard"),
            ] {
                fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(disable).await.map_err(|e| e.to_string())?;
                let before = fixture.original_completions.count()?;
                status(fixture.request(Method::POST, super::PREFIX, COOKIE_A,
                    Some(serde_json::json!({"artifactId": fixture.receipt.artifact_id}))).await?,
                    StatusCode::SERVICE_UNAVAILABLE).await?;
                let failed = fixture.original_completions.original_after(before)?;
                failed.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|e| e.to_string())?;
                fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(restore).await.map_err(|e| e.to_string())?;
                let (opened, original) = fixture.open_with_original_completion(COOKIE_A).await?;
                let _: ArtifactReadClosed = control(fixture.close(COOKIE_A, &opened.handle_id).await?).await?;
                original.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|e| e.to_string())?;
            }
            fixture.actual.close_observed_artifact_reads(&record).map_err(|e| e.to_string())?
                .drain_before(Instant::now() + Duration::from_secs(5)).await
                .map_err(|_| "acknowledged schema refusal poisoned the original Store".to_owned())?;
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}

struct ActualSingleUserRead {
    resolver: Arc<crate::SingleUserAuthResolver>,
    router: axum::Router,
    receipt: ArtifactRegistrationReceipt,
}
impl ActualSingleUserRead {
    async fn new(fixture: &Fixture, config: DatabaseConfig) -> Result<Self, String> {
        use openbot_infra::auth::single_user::{
            SINGLE_USER_ACTOR_ID, SINGLE_USER_EMAIL, load_single_user_principal,
        };
        let client = fixture.pool.get().await.map_err(|e| e.to_string())?;
        client
            .execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
                &[&SINGLE_USER_ACTOR_ID, &SINGLE_USER_EMAIL],
            )
            .await
            .map_err(|e| e.to_string())?;
        client
            .execute(
                "INSERT INTO public.user_roles(user_id,role) VALUES($1,'admin')",
                &[&SINGLE_USER_ACTOR_ID],
            )
            .await
            .map_err(|e| e.to_string())?;
        drop(client);
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let principal =
            load_single_user_principal(&fixture.pool, deployment.clone(), tenant.clone())
                .await
                .map_err(|e| e.to_string())?;
        let resolver = Arc::new(crate::SingleUserAuthResolver::from_verified_principal(
            principal,
            default_session_lifetime(),
        ));
        let foreign_pool = pool::connect(&config.clone().with_max_pool_size(1))
            .await
            .map_err(|e| e.to_string())?;
        let foreign = crate::SingleUserAuthResolver::from_verified_principal(
            load_single_user_principal(&foreign_pool, deployment.clone(), tenant.clone())
                .await
                .map_err(|e| e.to_string())?,
            default_session_lifetime(),
        );
        require(
            foreign
                .install_artifact_read_authority(&fixture.actual.read_authority())
                .is_err(),
            "different actual Pool enrolled as the original SingleUser read owner",
        )?;
        foreign.close_request_bindings();
        foreign_pool.close();
        resolver
            .install_artifact_read_authority(&fixture.actual.read_authority())
            .map_err(|_| "canonical same-Pool read enrollment failed")?;
        let auth = resolver
            .resolve(&parts(COOKIE_A)?)
            .await
            .map_err(|e| e.to_string())?;
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant,
            actor: auth.actor().clone(),
            auth_generation: auth.auth_generation(),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([17; 16]),
                run_id: RunId::new(format!("single-user-read-{}", Uuid::now_v7())),
                bot_id: BotId::new("current-read-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            fixture.pool.clone(),
            config,
            "single-user-read-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?
        .begin_thread_run(begin.clone())
        .await
        .map_err(|e| e.to_string())?;
        let receipt = fixture
            .actual
            .save_run_message_text(
                &auth,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: begin.command.thread_id,
                    source_run_id: begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", begin.command.run_id.as_str()),
                    expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|_| "owned single-user transport config")?
            .transport_policy(true);
        let router = ServerBuilder::new(fixture.application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured([ORIGIN]).map_err(|e| e.to_string())?,
            ))
            .into_router()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 40_013)),
            )));
        Ok(Self {
            resolver,
            router,
            receipt,
        })
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        payload: Option<serde_json::Value>,
    ) -> Result<axum::response::Response, String> {
        let body = payload
            .map(|value| serde_json::to_vec(&value))
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", ORIGIN)
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(Body::from(body))
            .map_err(|e| e.to_string())?;
        self.router
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| e.to_string())
    }
    async fn open(&self) -> Result<ArtifactReadOpened, String> {
        let response = self
            .request(
                Method::POST,
                super::PREFIX,
                Some(serde_json::json!({"artifactId": self.receipt.artifact_id})),
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(format!(
                "SingleUser original Open returned HTTP {}",
                response.status().as_u16()
            ));
        }
        control(response).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, canonical SingleUser owner and actual public byte carriers"]
async fn actual_single_user_public_reader_delivers_original_bytes_and_closes_owner() {
    let tag = "single_user_reader";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config.clone(), 4096).await?;
        let single = ActualSingleUserRead::new(&fixture, config).await?;
        let outcome = async {
            let sessions: i64 = fixture
                .pool
                .get()
                .await
                .map_err(|e| e.to_string())?
                .query_one(
                    "SELECT count(*) FROM public.sessions WHERE user_id='dev-local-user'",
                    &[],
                )
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            require(
                sessions == 0,
                "SingleUser read required a synthetic Session",
            )?;
            let opened = single.open().await?;
            let next = format!("{}/{}/next", super::PREFIX, opened.handle_id);
            let response = single
                .request(Method::POST, &next, Some(serde_json::json!({"sequence":0})))
                .await?;
            let (length, eof) = data_headers(&response, &opened.handle_id, 0)?;
            let bytes = to_bytes(response.into_body(), FIRST_BLOCK)
                .await
                .map_err(|e| format!("SingleUser original first body: {e}"))?;
            require(
                !eof && length == TEXT.len() && bytes.as_ref() == TEXT.as_bytes(),
                "SingleUser actual body differed from the saved source",
            )?;
            drop(bytes);
            let _: ArtifactReadAcknowledged = control(
                single
                    .request(
                        Method::POST,
                        &format!("{}/{}/ack", super::PREFIX, opened.handle_id),
                        Some(serde_json::json!({"sequence":0})),
                    )
                    .await?,
            )
            .await?;
            let response = single
                .request(Method::POST, &next, Some(serde_json::json!({"sequence":1})))
                .await?;
            require(
                data_headers(&response, &opened.handle_id, 1)? == (0, true),
                "SingleUser read did not reach genuine EOF",
            )?;
            require(
                to_bytes(response.into_body(), FIRST_BLOCK)
                    .await
                    .map_err(|e| format!("SingleUser original EOF body: {e}"))?
                    .is_empty(),
                "SingleUser EOF contained bytes",
            )?;
            let before = fixture.original_completions.count()?;
            let live = single.open().await?;
            let completion = fixture.original_completions.original_after(before)?;
            single.resolver.close_request_bindings();
            status(
                single
                    .request(
                        Method::POST,
                        &format!("{}/{}/next", super::PREFIX, live.handle_id),
                        Some(serde_json::json!({"sequence":0})),
                    )
                    .await?,
                StatusCode::UNAUTHORIZED,
            )
            .await?;
            completion
                .drain_before(Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|e| format!("SingleUser original close drain: {e}"))?;
            Ok(())
        }
        .await;
        single.resolver.close_request_bindings();
        drop(single);
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and original SingleUser last-owner drop"]
async fn actual_single_user_drop_stops_original_cached_entry_without_global_close() {
    let tag = "single_user_drop";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config.clone(), 4096).await?;
        let single = ActualSingleUserRead::new(&fixture, config).await?;
        let outcome = async {
            let before = fixture.original_completions.count()?;
            let _opened = single.open().await?;
            let original = fixture.original_completions.original_after(before)?;
            // The Router and resolver are the last real issuer owners. No explicit issuer
            // or Application-wide close occurs before this original physical drain.
            drop(single);
            original
                .drain_before(Instant::now() + Duration::from_secs(5))
                .await
                .map_err(|e| format!("SingleUser last-owner original drain: {e}"))?;
            Ok(())
        }
        .await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and canonical SingleUser changes after actual Open"]
async fn actual_single_user_cached_first_rechecks_canonical_role_email_generation_and_deny() {
    let tag = "single_user_current";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config.clone(), 4096).await?;
        let single = ActualSingleUserRead::new(&fixture, config).await?;
        let outcome = async {
            for (change, restore) in [
                ("DELETE FROM public.user_roles WHERE user_id='dev-local-user'",
                 "INSERT INTO public.user_roles(user_id,role) VALUES('dev-local-user','admin')"),
                ("UPDATE public.users SET email='changed@example.test' WHERE id='dev-local-user'",
                 "UPDATE public.users SET email='dev@openbot.local' WHERE id='dev-local-user'"),
                ("UPDATE public.users SET auth_generation=1 WHERE id='dev-local-user'",
                 "UPDATE public.users SET auth_generation=0 WHERE id='dev-local-user'"),
                ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('dev@openbot.local','owned-test')",
                 "DELETE FROM public.revoked_access WHERE email='dev@openbot.local'"),
            ] {
                let before = fixture.original_completions.count()?;
                let opened = single.open().await?;
                let original = fixture.original_completions.original_after(before)?;
                fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(change).await.map_err(|e| e.to_string())?;
                status(single.request(Method::POST, &format!("{}/{}/next", super::PREFIX, opened.handle_id),
                    Some(serde_json::json!({"sequence":0}))).await?, StatusCode::UNAUTHORIZED).await?;
                original.drain_before(Instant::now() + Duration::from_secs(5)).await.map_err(|e| e.to_string())?;
                fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(restore).await.map_err(|e| e.to_string())?;
            }
            Ok(())
        }.await;
        single.resolver.close_request_bindings();
        drop(single);
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; true Bytes last-owner drop and per-reader close"]
async fn actual_server_session_public_reader_delayed_body_and_close_wait_for_original_carrier() {
    let tag = "public-reader-carrier";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 29).await?;
        let outcome = async {
            let original = fixture.open(COOKIE_A).await?;
            let peer = fixture.open(COOKIE_B).await?;
            let response = fixture.next(COOKIE_A, &original.handle_id, 0).await?;
            data_headers(&response, &original.handle_id, 0)?;
            let mut stream = response.into_body().into_data_stream();
            let bytes = stream.next().await.ok_or("actual first body frame missing")?
                .map_err(|error| error.to_string())?;
            let held_original = bytes.clone();
            require(stream.next().await.is_none(),
                "normal response did not actually observe its stream terminal poll")?;
            drop(bytes);
            drop(stream);
            let mut closing = Box::pin(fixture.close(COOKIE_A, &original.handle_id));
            let while_held = async {
                require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                    "Close falsely acknowledged while a real original Bytes clone remained")?;
                let response = fixture.next(COOKIE_B, &peer.handle_id, 0).await?;
                let (length, eof) = data_headers(&response, &peer.handle_id, 0)?;
                let peer_bytes = to_bytes(response.into_body(), FIRST_BLOCK).await.map_err(|error| error.to_string())?;
                require(!eof && length == fixture.payload.len() && peer_bytes.as_ref() == fixture.payload.as_bytes(),
                    "closing original handle blocked or destroyed another real session's reader")?;
                drop(peer_bytes);
                let peer_closed: ArtifactReadClosed = control(fixture.close(COOKIE_B, &peer.handle_id).await?).await?;
                require(peer_closed.handle_id == peer.handle_id, "peer close borrowed original handle resources")?;
                require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                    "peer close falsely released another original carrier")
            }.await;
            drop(held_original);
            let closed = tokio::time::timeout(Duration::from_secs(4), &mut closing).await
                .map_err(|_| "original carrier drop did not unblock true own Close")?;
            while_held?;
            let closed: ArtifactReadClosed = control(closed?).await?;
            require(closed.handle_id == original.handle_id, "original true Close returned another locator")?;
            let (unpolled, unpolled_completion) = fixture.open_with_original_completion(COOKIE_A).await?;
            let response = fixture.next(COOKIE_A, &unpolled.handle_id, 0).await?;
            data_headers(&response, &unpolled.handle_id, 0)?;
            // Dropping the real unpolled body consumes its original prepared owner.
            drop(response);
            // This existing port requests own stop as well as waiting for actual drain.
            // The proof is same-operation closure after Drop, not a passive Drop-only oracle.
            require(unpolled_completion.drain_before(Instant::now() + Duration::from_secs(4)).await.is_ok(),
                "actual unpolled body's original operation did not close and drain")?;
            let (canceled, canceled_completion) = fixture.open_with_original_completion(COOKIE_A).await?;
            let surviving = fixture.open(COOKIE_B).await?;
            let response = fixture.next(COOKIE_A, &canceled.handle_id, 0).await?;
            data_headers(&response, &canceled.handle_id, 0)?;
            let mut canceled_stream = response.into_body().into_data_stream();
            let canceled_carrier = canceled_stream.next().await.ok_or("canceled stream never yielded its real carrier")?
                .map_err(|error| error.to_string())?;
            require(canceled_carrier.as_ref() == fixture.payload.as_bytes(),
                "canceled stream did not hold its original genuine prefix")?;
            // No terminal poll is made: this actual Body Drop is the observable cancellation.
            drop(canceled_stream);
            let while_canceled_carrier_held = async {
                let response = fixture.next(COOKIE_B, &surviving.handle_id, 0).await?;
                let (length, eof) = data_headers(&response, &surviving.handle_id, 0)?;
                let bytes = to_bytes(response.into_body(), FIRST_BLOCK).await.map_err(|error| error.to_string())?;
                require(!eof && length == fixture.payload.len() && bytes.as_ref() == fixture.payload.as_bytes(),
                    "observable stream cancellation destroyed a peer Session's original reader")?;
                drop(bytes);
                let peer_closed: ArtifactReadClosed = control(fixture.close(COOKIE_B, &surviving.handle_id).await?).await?;
                require(peer_closed.handle_id == surviving.handle_id,
                    "canceled reader borrowed another Session's completion")?;
                require(canceled_completion.drain_before(Instant::now() + Duration::from_millis(30)).await.is_err(),
                    "cancellation falsely acknowledged disposal of a still-held actual Bytes carrier")
            }.await;
            drop(canceled_carrier);
            let canceled_drained = canceled_completion.drain_before(Instant::now() + Duration::from_secs(4)).await;
            while_canceled_carrier_held?;
            require(canceled_drained.is_ok(),
                "observable cancellation did not supervise true own closure after actual last carrier Drop")?;
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL; actual closed HTTP framing and issuer shutdown"]
async fn actual_server_session_public_reader_closed_framing_and_owner_shutdown() {
    let tag = "public-reader-framing";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 17).await?;
        let outcome = async {
            let artifact = &fixture.receipt.artifact_id;
            status(
                fixture
                    .request(
                        Method::POST,
                        super::PREFIX,
                        "invalid-owned-session",
                        Some(serde_json::json!({"artifactId": artifact})),
                    )
                    .await?,
                StatusCode::UNAUTHORIZED,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::POST,
                        super::PREFIX,
                        COOKIE_A,
                        Some(serde_json::json!({"artifactId": artifact, "path": "/forbidden"})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::POST,
                        "/api/artifact-reads?",
                        COOKIE_A,
                        Some(serde_json::json!({"artifactId": artifact})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request(Method::HEAD, super::PREFIX, COOKIE_A, None)
                    .await?,
                StatusCode::METHOD_NOT_ALLOWED,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::POST,
                        "/api/artifact-reads/not-a-handle/next",
                        COOKIE_A,
                        Some(serde_json::json!({"sequence": 0})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::GET,
                        "/api/artifact-reads/unknown/suffix",
                        COOKIE_A,
                        None,
                    )
                    .await?,
                StatusCode::NOT_FOUND,
            )
            .await?;
            status(
                fixture
                    .request_raw(
                        Method::POST,
                        super::PREFIX,
                        COOKIE_A,
                        vec![b'x'; crate::http::REQUEST_BODY_LIMIT_BYTES + 1],
                    )
                    .await?,
                StatusCode::PAYLOAD_TOO_LARGE,
            )
            .await?;
            let opened = fixture.open(COOKIE_A).await?;
            status(
                fixture
                    .request(
                        Method::DELETE,
                        &format!("{}/{}/", super::PREFIX, opened.handle_id),
                        COOKIE_A,
                        None,
                    )
                    .await?,
                StatusCode::NOT_FOUND,
            )
            .await?;
            let alias = opened.handle_id.replacen('-', "%2D", 1);
            status(
                fixture
                    .request(
                        Method::POST,
                        &format!("{}/{alias}/next", super::PREFIX),
                        COOKIE_A,
                        Some(serde_json::json!({"sequence": 0})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::POST,
                        &format!("{}/{}/next", super::PREFIX, opened.handle_id),
                        COOKIE_A,
                        Some(serde_json::json!({"sequence": 0.5})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request(
                        Method::POST,
                        &format!("{}/{}/next", super::PREFIX, opened.handle_id),
                        COOKIE_A,
                        Some(serde_json::json!({"sequence": 0, "range": "0-4"})),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            status(
                fixture
                    .request_raw(
                        Method::DELETE,
                        &format!("{}/{}", super::PREFIX, opened.handle_id),
                        COOKIE_A,
                        b"{}".to_vec(),
                    )
                    .await?,
                StatusCode::BAD_REQUEST,
            )
            .await?;
            let pending_data = fixture.next(COOKIE_A, &opened.handle_id, 0).await?;
            let pending_control = fixture
                .request(
                    Method::POST,
                    super::PREFIX,
                    COOKIE_A,
                    Some(serde_json::json!({"artifactId": artifact})),
                )
                .await?;
            no_store(&pending_data)?;
            no_store(&pending_control)?;
            require(
                pending_data.status() == StatusCode::OK
                    && pending_control.status() == StatusCode::OK,
                "actual shutdown test did not prepare both genuine response kinds",
            )?;
            fixture.resolver.close_request_bindings();
            fixture
                .application
                .close_public_artifact_reads()
                .map_err(|error| error.to_string())?;
            require(
                to_bytes(pending_data.into_body(), FIRST_BLOCK)
                    .await
                    .is_err(),
                "unpolled data response yielded bytes after actual original issuer closure",
            )?;
            require(
                to_bytes(pending_control.into_body(), 8192).await.is_err(),
                "unpolled control response skipped its actual current original tail",
            )?;
            status(
                fixture
                    .request(
                        Method::POST,
                        super::PREFIX,
                        COOKIE_A,
                        Some(serde_json::json!({"artifactId": artifact})),
                    )
                    .await?,
                StatusCode::UNAUTHORIZED,
            )
            .await
        }
        .await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    })
    .await;
}

// Controlled 0044 rows are consumer inputs only. These observations never assert deletion,
// directory sync, refund, cleanup authorization or a producer receipt.
const CLEANUP_PUBLIC_READ_FACTS: &str = "SELECT jsonb_build_object( \
 'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY to_jsonb(b)::text),'[]') FROM openbot_internal.artifact_dataset_bindings b), \
 'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
 'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
 'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
 'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]') FROM openbot_internal.artifact_store_bindings s), \
 'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
 'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
 'fences',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]') FROM openbot_internal.artifact_cleanup_fences f), \
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text),'[]') FROM public.audit_events e), \
 'users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY to_jsonb(u)::text),'[]') FROM public.users u), \
 'roles',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM public.user_roles r), \
 'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM public.sessions s), \
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]') FROM public.messages m))";

async fn cleanup_public_read_facts_on(
    client: &tokio_postgres::Client,
) -> Result<serde_json::Value, String> {
    client
        .query_one(CLEANUP_PUBLIC_READ_FACTS, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[derive(Default)]
struct CleanupCachedIoPhases {
    io: std::sync::atomic::AtomicUsize,
    joint: std::sync::atomic::AtomicUsize,
    segments: std::sync::atomic::AtomicUsize,
}
impl CleanupCachedIoPhases {
    fn actual_counts(&self) -> (usize, usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.io.load(Ordering::SeqCst),
            self.joint.load(Ordering::SeqCst),
            self.segments.load(Ordering::SeqCst),
        )
    }
}
struct CleanupCachedPhaseVisitor {
    io: bool,
    joint: bool,
    segment: bool,
}
impl tracing::field::Visit for CleanupCachedPhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match (field.name(), value) {
            ("artifact_read_phase", "actual_io_completed_before_joint") => self.io = true,
            ("artifact_read_phase", "joint_statement_ready") => self.joint = true,
            ("artifact_read_lifecycle_phase", "physical_segment_completed_before_more_io") => {
                self.segment = true
            }
            _ => {}
        }
    }
}
struct CleanupCachedPhaseSubscriber(Arc<CleanupCachedIoPhases>);
impl tracing::Subscriber for CleanupCachedPhaseSubscriber {
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
        use std::sync::atomic::Ordering;
        let mut visitor = CleanupCachedPhaseVisitor {
            io: false,
            joint: false,
            segment: false,
        };
        event.record(&mut visitor);
        if visitor.io {
            self.0.io.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.joint {
            self.0.joint.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.segment {
            self.0.segments.fetch_add(1, Ordering::SeqCst);
        }
    }
}

async fn arm_cached_first_cleanup_fence(
    pool: &openbot_infra::db::pool::DatabasePool,
    deployment: &str,
    tenant: &str,
    owner: &str,
    receipt: &ArtifactRegistrationReceipt,
) -> Result<serde_json::Value, String> {
    let mut controller = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = controller
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let inserted: serde_json::Value = transaction.query_one(
        "INSERT INTO openbot_internal.artifact_cleanup_fences \
         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
         SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
         FROM openbot_internal.artifact_records \
         WHERE deployment_id=$1 AND tenant_id=$2 AND operation_id=$3 AND artifact_id=$4 AND owner_actor_id=$5 \
         RETURNING to_jsonb(artifact_cleanup_fences)",
        &[&deployment, &tenant, &receipt.operation_id, &receipt.artifact_id, &owner],
    ).await.map_err(|error| error.to_string())?
        .try_get(0).map_err(|error| error.to_string())?;
    require(
        inserted["operation_id"] == receipt.operation_id
            && inserted["artifact_id"] == receipt.artifact_id
            && inserted["terminal_status"] == "deleted"
            && inserted["phase"] == "armed",
        "controlled consumer fence did not retain the original pair and intent",
    )?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(inserted)
}

#[cfg(target_os = "macos")]
// Read only this Rust process's bounded f/device/inode inventory. No path fields or peer PIDs.
fn cleanup_owned_inode_fds(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<std::collections::BTreeSet<u32>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "own-PID lsof is unavailable (Unproven)".to_owned())?;
        let stdout = child.stdout.take().ok_or("lsof stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("lsof stderr unavailable")?;
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output.join();
                let _ = errors.join();
                return Err("own-PID lsof exceeded original five seconds (Unproven)".to_owned());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = output
            .join()
            .map_err(|_| "lsof output worker panicked")?
            .map_err(|error| error.to_string())?;
        let errors = errors
            .join()
            .map_err(|_| "lsof error worker panicked")?
            .map_err(|error| error.to_string())?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.len() <= 8_192
                && output.ends_with(b"\n"),
            "lsof incomplete/failed/truncated (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "lsof output invalid (Unproven)")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("lsof empty field (Unproven)")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "lsof observed another PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(inode) {
                        found.insert(
                            fd.ok_or("original inode has an ambiguous nonnumeric FD (Unproven)")?,
                        );
                    }
                    fd = value.parse::<u32>().ok();
                    dev = None;
                    ino = None;
                }
                "D" => {
                    dev = Some(
                        if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16)
                        } else {
                            value.parse::<u64>()
                        }
                        .map_err(|_| "lsof device invalid (Unproven)")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "lsof inode invalid (Unproven)")?,
                    );
                }
                _ => return Err("lsof unexpected field (Unproven)".to_owned()),
            }
        }
        require(self_pid, "lsof self-PID field missing (Unproven)")?;
        Ok(found)
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "own original FD inventory was unstable (Unproven)",
    )?;
    Ok(first)
}

#[cfg(target_os = "linux")]
fn cleanup_owned_inode_fds(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::os::unix::fs::MetadataExt as _;
    let original = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        original.is_file() && original.nlink() == 1,
        "owned FD oracle requires the original regular inode",
    )?;
    let sample = || -> Result<std::collections::BTreeSet<u32>, String> {
        let mut found = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir("/proc/self/fd").map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let fd = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or("own-PID fd inventory contained a nonnumeric descriptor")?;
            match std::fs::metadata(entry.path()) {
                Ok(metadata)
                    if metadata.dev() == original.dev() && metadata.ino() == original.ino() =>
                {
                    found.insert(fd);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(found)
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "own original inode FD inventory was unstable (Unproven)",
    )?;
    Ok(first)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cleanup_owned_inode_fds(_: &std::path::Path) -> Result<std::collections::BTreeSet<u32>, String> {
    Err("actual owned inode FD oracle is unavailable on this platform (Unproven)".to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL, committed 0044 consumer fence and original retained reader"]
async fn actual_server_session_public_reader_cached_first_cleanup_fence_recheck_refuses_body() {
    use tracing::instrument::WithSubscriber as _;
    let tag = "public-reader-cached-cleanup";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Fixture::new(config, 29).await?;
        let outcome = async {
            let path = fixture.root.0.join("objects").join(&fixture.receipt.artifact_id);
            require(cleanup_owned_inode_fds(&path)?.is_empty(),
                "owned saved artifact unexpectedly began with a live read FD")?;
            let phases = Arc::new(CleanupCachedIoPhases::default());
            let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
            let (opened, original_completion) = fixture.open_with_original_completion(COOKIE_A)
                .with_subscriber(dispatch.clone()).await?;
            require(opened.artifact_id == fixture.receipt.artifact_id
                && opened.byte_length == fixture.payload.len() as u64
                && opened.sha256 == format!("{:x}", Sha256::digest(fixture.payload.as_bytes())),
                "actual Open did not retain the original saved artifact facts")?;
            let after_open = phases.actual_counts();
            require(after_open.0 == 1 && after_open.1 >= 2,
                "successful real Open did not complete its original physical prefix and current queries")?;
            let original_fds = cleanup_owned_inode_fds(&path)?;
            require(!original_fds.is_empty(),
                "successful Open did not retain the actual original object FD")?;
            let client = fixture.pool.get().await.map_err(|error| error.to_string())?;
            let mut expected = cleanup_public_read_facts_on(&client).await?;
            require(expected["fences"] == serde_json::json!([]),
                "owned cached-first fixture unexpectedly began fenced")?;
            let idle_before: OffsetDateTime = client.query_one(
                "SELECT updated_at FROM public.sessions WHERE id=$1", &[&A_ID],
            ).await.map_err(|error| error.to_string())?
                .try_get(0).map_err(|error| error.to_string())?;
            drop(client);
            let inserted = arm_cached_first_cleanup_fence(
                &fixture.pool, DEPLOYMENT, TENANT, OWNER, &fixture.receipt,
            ).await?;
            expected["fences"] = serde_json::json!([inserted]);
            // Only this true COMMIT ACK permits the delayed seq0 consumer to start.
            let response = fixture.next(COOKIE_A, &opened.handle_id, 0)
                .with_subscriber(dispatch).await?;
            no_store(&response)?;
            require(response.status() == StatusCode::SERVICE_UNAVAILABLE,
                "delayed cached first block did not refuse the committed armed fence")?;
            require(["x-artifact-read-handle", "x-artifact-read-sequence",
                "x-artifact-read-length", "x-artifact-read-eof"].iter()
                .all(|name| response.headers().get(*name).is_none()),
                "cleanup-fence refusal retained data descriptor headers")?;
            let body = to_bytes(response.into_body(), 8192).await.map_err(|error| error.to_string())?;
            let error: serde_json::Value = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
            require(error == serde_json::json!({"code":"dependency_unavailable"})
                && !body.windows(fixture.payload.len()).any(|part| part == fixture.payload.as_bytes()),
                "cleanup-fence refusal exposed payload or expanded the original static error")?;
            drop(body);
            let after_refusal = phases.actual_counts();
            require(after_refusal.0 == after_open.0
                && after_refusal.2 == after_open.2 && after_refusal.1 == after_open.1 + 1,
                "cached first refusal repeated physical prefix work or omitted its real final query")?;
            // This is the same actual producer Arc enrolled before the original Open's first await.
            // Its own protocol awaits the original job, full allocation and descriptor disposal.
            original_completion.drain_before(Instant::now() + Duration::from_secs(5)).await
                .map_err(|_| "same original cached first operation did not actually close and drain".to_owned())?;
            require(cleanup_owned_inode_fds(&path)?.is_empty(),
                "same original object inode still had a live FD after actual completion ACK")?;
            let client = fixture.pool.get().await.map_err(|error| error.to_string())?;
            let mut actual = cleanup_public_read_facts_on(&client).await?;
            let idle_after: OffsetDateTime = client.query_one(
                "SELECT updated_at FROM public.sessions WHERE id=$1", &[&A_ID],
            ).await.map_err(|error| error.to_string())?
                .try_get(0).map_err(|error| error.to_string())?;
            require(idle_after >= idle_before && idle_after <= OffsetDateTime::now_utc(),
                "genuine Session idle touch escaped its original monotonic current timestamp")?;
            // The only excluded field is this original authenticated Session's legal idle touch.
            // Peer Session fields, all auth generations and every business fact remain byte values.
            for facts in [&mut expected, &mut actual] {
                let sessions = facts["sessions"].as_array_mut().ok_or("original sessions facts were not an array")?;
                let mut own = 0;
                for session in sessions {
                    if session["id"] == A_ID {
                        session.as_object_mut().ok_or("original Session fact was not an object")?
                            .remove("updated_at").ok_or("original Session idle field missing")?;
                        own += 1;
                    }
                }
                require(own == 1, "idle touch exception did not select exactly the original Session")?;
            }
            require(actual == expected,
                "cached first consumer changed source, record, receipt, quota, charge, store, fence, audit, host or peer Session facts")?;
            require(std::fs::read(&path).map_err(|error| error.to_string())? == fixture.payload.as_bytes(),
                "consumer fence changed the owned physical artifact bytes")?;
            eprintln!("PUBLIC_ARTIFACT_SERVER_CACHED_CLEANUP original_open=true controller_commit_ack=true seq0_refused=true no_store=true no_payload=true original_io_ack_count={} final_query_increment=1 same_original_completion_ack=true own_inode_fd_absent=true business_facts_unchanged=true legal_original_session_idle_touch=true",
                after_open.0);
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        outcome.and(cleaned)
    }).await;
}
