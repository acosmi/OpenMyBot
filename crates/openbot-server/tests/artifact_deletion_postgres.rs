//! V7-IMPL-031 part 2: public deletion of an explicitly saved artifact through the real Axum
//! router, a real Session and an owned PostgreSQL. The artifact comes from a real Run and Save;
//! the fixture grants no authority. On macOS the Store's capture barrier is armed as on Desktop,
//! so an unproven step of an overlapping deletion would poison it and refuse the next Save.
#![cfg(any(target_os = "macos", target_os = "linux"))]

#[path = "support/transport_fixture.rs"]
mod transport_fixture;

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode};
use openbot_application::{ApplicationService, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
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
use openbot_infra::db::pool::{DatabaseConfig, DatabasePool};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, String>;

const DEPLOYMENT: &str = "deletion/deployment";
const TENANT: &str = "deletion-tenant";
const OWNER: &str = "deletion-owner";
const OTHER: &str = "deletion-other";
const SESSION_KEY: &[u8] = b"owned-artifact-deletion-session-key";
const ORIGIN: &str = "https://wrok-ui.example.test";
const TEXT: &str = "OWNED_ARTIFACT_DELETION_BODY_CANARY";
/// Resends of one deletion before the test gives up on it completing.
const RESENDS: usize = 40;

fn check(ok: bool, reason: &str) -> Result {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}
fn cookie(actor: &str) -> String {
    format!("owned-artifact-deletion-cookie-{actor}-01")
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("openbot-artifact-deletion-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(text)?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0).is_ok();
        if !std::thread::panicking() {
            assert!(removed, "owned artifact root did not close");
        }
    }
}

struct Fixture {
    admin: DatabasePool,
    pool: DatabasePool,
    resolver: Arc<PostgresSessionAuthResolver>,
    router: axum::Router,
    application: Arc<dyn ApplicationService>,
    begin: BeginThreadRun,
    _actual: Arc<PostgresArtifactAdministration>,
    _root: OwnedRoot,
}

impl Fixture {
    /// One real Run of the owner, as in the arm fixture; `save` saves its user message.
    async fn new(config: DatabaseConfig) -> Result<Self> {
        let direct = config.clone().with_max_pool_size(5);
        let admin = pool::connect(&direct).await.map_err(text)?;
        {
            let mut c = admin.get().await.map_err(text)?;
            baseline::apply(&c).await.map_err(text)?;
            native::apply(&mut c).await.map_err(text)?;
            c.batch_execute(&format!(
                "INSERT INTO public.users(id,email,auth_generation) VALUES \
                 ('{OWNER}','{OWNER}@example.test',0),('{OTHER}','{OTHER}@example.test',0); \
                 INSERT INTO public.user_roles(user_id,role) VALUES('{OWNER}','user'),('{OTHER}','user'); \
                 INSERT INTO public.agents(id,name,type,configuration) VALUES('deletion-bot','Deletion fixture','built_in','{{}}'); \
                 INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) \
                 VALUES('deletion-bot','{OWNER}','Deletion fixture','fixture','fixture','public');"
            ))
            .await
            .map_err(text)?;
            let now = OffsetDateTime::now_utc();
            for actor in [OWNER, OTHER] {
                let token = SessionTokenHash::compute(
                    SessionToken::new(cookie(actor).as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                c.execute(
                    "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
                     VALUES($1,$2,$3,$4,$5,$5,0)",
                    &[
                        &format!("session-{actor}"),
                        &actor,
                        &token,
                        &(now + time::Duration::hours(1)),
                        &(now - time::Duration::minutes(1)),
                    ],
                )
                .await
                .map_err(text)?;
            }
        }
        let pool = pool::connect(&config.clone().with_max_pool_size(1))
            .await
            .map_err(text)?;
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([31; 16]),
                run_id: RunId::new("actual/deletion-run"),
                bot_id: BotId::new("deletion-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: TEXT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        PostgresThreadDirectory::with_runtime(
            admin.clone(),
            direct,
            "artifact-deletion-owned-fixture".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(text)?
        .begin_thread_run(begin.clone())
        .await
        .map_err(text)?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(text)?,
        );
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                std::fs::File::open(&root.0).map_err(text)?,
                registry.clone(),
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(text)?,
        );
        #[cfg(target_os = "macos")]
        store.arm_capture_barrier(3).map_err(text)?;
        let actual = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                ArtifactQuotaPolicy::default(),
                SecretBytes::new(vec![0x31; 32]),
            )
            .map_err(text)?,
        );
        let resolver = Arc::new(
            PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(text)?,
        );
        resolver
            .install_artifact_read_authority(&actual.read_authority())
            .map_err(|_| "artifact authority installation refused")?;
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(actual.clone()),
        );
        let router = transport_fixture::loopback_router(
            ServerBuilder::new(application.clone(), resolver.clone())
                .with_transport_policy(transport_fixture::loopback_policy())
                .with_sensitive_write_security(SensitiveWriteSecurity::new(
                    default_session_lifetime(),
                    TrustedOrigins::from_configured([ORIGIN]).map_err(text)?,
                ))
                .build(),
        );
        Ok(Self {
            admin,
            pool,
            resolver,
            router,
            application,
            begin: begin.command,
            _actual: actual,
            _root: root,
        })
    }

    /// One real Save of the owner's Run message.
    async fn save(&self) -> Result<ArtifactRegistrationReceipt> {
        let AppReply::ArtifactRegistrationReceipt(receipt) = self
            .application
            .execute(
                resolve(self.resolver.as_ref(), OWNER).await?,
                AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_message_id: format!("{}:input", self.begin.run_id.as_str()),
                    source_thread_id: self.begin.thread_id.clone(),
                    source_run_id: self.begin.run_id.clone(),
                    expected_sha256: format!("{:x}", Sha256::digest(TEXT.as_bytes())),
                }),
            )
            .await
            .map_err(text)?
        else {
            return Err("the Save returned another reply".to_owned());
        };
        Ok(receipt)
    }

    async fn delete(&self, actor: &str, id: &str) -> Result<(StatusCode, Value)> {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/artifacts/{id}"))
                    .header(
                        http::header::COOKIE,
                        format!("openbot_session={}", cookie(actor)),
                    )
                    .header(http::header::ORIGIN, ORIGIN)
                    .body(Body::empty())
                    .map_err(text)?,
            )
            .await
            .map_err(text)?;
        let status = response.status();
        check(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                == Some("no-store"),
            "the deletion route answered without no-store",
        )?;
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .map_err(text)?;
        Ok((status, serde_json::from_slice(&body).map_err(text)?))
    }

    fn finish(self) {
        self.resolver.close_request_bindings();
        self.pool.close();
        self.admin.close();
    }
}

async fn resolve(resolver: &dyn AuthResolver, actor: &str) -> Result<AuthContext> {
    let parts = Request::builder()
        .uri("/owned-artifact-deletion")
        .header("cookie", format!("openbot_session={}", cookie(actor)))
        .body(())
        .map_err(text)?
        .into_parts()
        .0;
    resolver.resolve(&parts).await.map_err(text)
}

async fn exercise(f: &Fixture) -> Result {
    let receipt = f.save().await?;
    let id = receipt.artifact_id.as_str();
    let receipt_of = |state: &str| {
        json!({
            "artifactId": id,
            "state": state,
            "injectedCopies": "retained_until_thread_history_clear",
        })
    };
    // Every answer to the owner is 200 deleted, 202 pending or, once completed, 409; never 503.
    let answered = |(status, value): (StatusCode, Value)| -> Result<StatusCode> {
        check(
            (status == StatusCode::OK && value == receipt_of("deleted"))
                || (status == StatusCode::ACCEPTED && value == receipt_of("pending"))
                || (status == StatusCode::CONFLICT && value == json!({"code": "request_conflict"})),
            &format!("an owner's deletion answered {status} {value}"),
        )?;
        Ok(status)
    };

    // Two overlapping deletions by the owner: one advances the artifact and the other answers
    // pending without touching its slot. The pending one is resent until it is deleted (200) or
    // found deleted (409).
    let (first, second) = tokio::join!(f.delete(OWNER, id), f.delete(OWNER, id));
    let overlapping = [answered(first?)?, answered(second?)?];
    check(
        overlapping.contains(&StatusCode::ACCEPTED),
        "neither overlapping deletion answered pending",
    )?;
    let mut pending_resends = 0;
    let mut status = StatusCode::ACCEPTED;
    while status == StatusCode::ACCEPTED {
        check(pending_resends < RESENDS, "the deletion never completed")?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        status = answered(f.delete(OWNER, id).await?)?;
        pending_resends += 1;
    }
    let completed: bool = f
        .admin
        .get()
        .await
        .map_err(text)?
        .query_one(
            "SELECT r.status='deleted' AND f.phase='completed' \
             FROM openbot_internal.artifact_records r \
             JOIN openbot_internal.artifact_cleanup_fences f USING(deployment_id,tenant_id,dataset_id,artifact_id) \
             WHERE r.artifact_id=$1",
            &[&id],
        )
        .await
        .map_err(text)?
        .get(0);
    check(completed, "the record or its fence was not completed")?;

    // After completion the owner's resend is a conflict and another user cannot see it.
    let (status_after, value) = f.delete(OWNER, id).await?;
    check(
        status_after == StatusCode::CONFLICT && value == json!({"code": "request_conflict"}),
        &format!("the owner's resend after deletion was not 409: {status_after} {value}"),
    )?;
    let (status_other, value) = f.delete(OTHER, id).await?;
    check(
        status_other == StatusCode::NOT_FOUND && value == json!({"code": "not_visible"}),
        &format!("another user's deletion was not 404: {status_other} {value}"),
    )?;
    // The capture barrier is not poisoned: the owner saves the same message again.
    f.save().await?;
    eprintln!(
        "ARTIFACT_DELETION overlapping={},{} pending_resends={pending_resends} resumed={} \
         owner_resend=409 other=404 resave=ok no_store=true",
        overlapping[0].as_u16(),
        overlapping[1].as_u16(),
        status.as_u16(),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicitly owned loopback PostgreSQL17.11"]
async fn artifact_deletion_http_overlapping_owner_deletes_complete_then_conflict_and_resave() {
    let tag = "artifact_deletion";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let f = Fixture::new(config).await?;
        let outcome = exercise(&f).await;
        f.finish();
        outcome
    })
    .await;
}
