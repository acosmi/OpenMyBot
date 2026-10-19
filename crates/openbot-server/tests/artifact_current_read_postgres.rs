//! Owned PostgreSQL and actual filesystem -> actual Session/Application/Rust consumer.
//! Synthetic principals and package are controlled fixtures, without SSO/provider acceptance.
#![cfg(unix)]

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use async_trait::async_trait;
use http::Request;
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, BeginThreadRunRequest,
    CurrentArtifactReadChunk, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactMetadata, ArtifactRegistrationReceipt, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_contracts::request_binding::HostRequestBindingError;
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
use openbot_server::{AuthResolver, PostgresSessionAuthResolver, ServerBuilder, ServerState};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
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

fn mutate_owned_read_only_file<M, E>(
    path: &std::path::Path,
    mutation: M,
    expected: E,
) -> Result<(), String>
where
    M: FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    E: FnOnce(&[u8], &[u8]) -> bool,
{
    let original = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        original.is_file() && original.mode() & 0o7777 == 0o400 && original.nlink() == 1,
        "owned mutation requires the original regular0400 single-link file",
    )?;
    let anchor = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let anchored = anchor.metadata().map_err(|error| error.to_string())?;
    require(
        anchored.is_file()
            && anchored.dev() == original.dev()
            && anchored.ino() == original.ino()
            && anchored.uid() == original.uid()
            && anchored.mode() & 0o7777 == 0o400
            && anchored.nlink() == 1,
        "owned mutation read FD is not the original0400 inode",
    )?;
    let mut before = Vec::new();
    (&anchor)
        .read_to_end(&mut before)
        .map_err(|error| error.to_string())?;
    struct RestoreReadOnly<'a> {
        file: &'a std::fs::File,
        armed: bool,
    }
    impl Drop for RestoreReadOnly<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = self
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o400));
                let _ = self.file.sync_all();
            }
        }
    }
    let mut restore = RestoreReadOnly {
        file: &anchor,
        armed: true,
    };
    anchor
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let writable = writer.metadata().map_err(|error| error.to_string())?;
    require(
        writable.is_file()
            && writable.dev() == original.dev()
            && writable.ino() == original.ino()
            && writable.uid() == original.uid()
            && writable.mode() & 0o7777 == 0o600
            && writable.nlink() == 1,
        "owned mutation write FD is not the original temporary0600 inode",
    )?;
    let mutation_result = mutation(&mut writer, &before);
    let mutation_sync = writer.sync_all();
    // Restore even when mutation or its sync failed; the anchored guard also covers early errors.
    let restored = writer.set_permissions(std::fs::Permissions::from_mode(0o400));
    let restore_sync = writer.sync_all();
    if restored.is_ok() && restore_sync.is_ok() {
        restore.armed = false;
    }
    restored.map_err(|error| error.to_string())?;
    restore_sync.map_err(|error| error.to_string())?;
    let actual = writer.metadata().map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        actual.is_file()
            && installed.is_file()
            && actual.dev() == original.dev()
            && actual.ino() == original.ino()
            && actual.uid() == original.uid()
            && installed.dev() == original.dev()
            && installed.ino() == original.ino()
            && actual.mode() & 0o7777 == 0o400
            && installed.mode() & 0o7777 == 0o400
            && actual.nlink() == 1
            && installed.nlink() == 1,
        "owned mutation did not restore original inode and0400 permissions",
    )?;
    mutation_result.map_err(|error| error.to_string())?;
    mutation_sync.map_err(|error| error.to_string())?;
    (&anchor)
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut after = Vec::new();
    (&anchor)
        .read_to_end(&mut after)
        .map_err(|error| error.to_string())?;
    require(
        before != after && expected(&before, &after),
        "owned mutation did not cause exact real byte drift",
    )
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let path =
            std::env::temp_dir().join(format!("openbot-artifact-current-read-{}", Uuid::now_v7()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        let absent = !self.0.exists();
        eprintln!(
            "ARTIFACT_CURRENT_HOST_ROOT_CLEANUP removed={} absent={absent}",
            removed.is_ok()
        );
        if !std::thread::panicking() {
            assert!(removed.is_ok() && absent, "owned read root did not close");
        }
    }
}

// This gate holds an already produced sealed result. It neither creates authority nor claims
// the database can observe commits after the final query. It tests the final owner/FD/clock tail.
struct PendingGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl PendingGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}
struct ActualPort {
    actual: Arc<PostgresArtifactAdministration>,
    reads: AtomicUsize,
    pending_gate: Mutex<Option<Arc<PendingGate>>>,
}
#[async_trait]
impl ArtifactAdministration for ActualPort {
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
        self.actual.get_metadata(auth, id).await
    }
    async fn read_host_bound_chunk(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<CurrentArtifactReadChunk, AppError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let gate = self
            .pending_gate
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?
            .take();
        let pending = self.actual.read_host_bound_chunk(auth, id).await?;
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        Ok(pending)
    }
}
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    config: DatabaseConfig,
    resolver: Arc<PostgresSessionAuthResolver>,
    application: Arc<dyn ApplicationService>,
    state: ServerState,
    port: Arc<ActualPort>,
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
        let port = Arc::new(ActualPort {
            actual,
            reads: AtomicUsize::new(0),
            pending_gate: Mutex::new(None),
        });
        let application: Arc<dyn ApplicationService> = Arc::new(
            openbot_application::OpenBotApplication::new(
                openbot_infra::repo::channels::ChannelRepo::new(pool.clone()),
            )
            .with_artifacts(port.clone()),
        );
        let policy = ServerConfig::from_env_map(&EnvMap::new())
            .map_err(|error| format!("fixture transport config: {error:?}"))?
            .transport_policy(true);
        let state = ServerBuilder::new(application.clone(), resolver.clone())
            .with_transport_policy(policy)
            .build();
        Ok(Self {
            pool,
            config,
            resolver,
            application,
            state,
            port,
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
    async fn read(&self, auth: AuthContext) -> Result<Vec<u8>, AppError> {
        self.application
            .read_current_artifact_chunk(auth.clone(), self.receipt.artifact_id.clone())
            .await?
            .handoff(&auth)
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
    fn pending_gate(&self) -> Result<Arc<PendingGate>, String> {
        let gate = PendingGate::new();
        *self
            .port
            .pending_gate
            .lock()
            .map_err(|_| "pending gate poisoned".to_owned())? = Some(gate.clone());
        Ok(gate)
    }
}
async fn with_fixture<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config).await?).await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn actual_session_application_and_rust_server_consumer_release_exact_first_chunk() {
    with_fixture("read-session-positive", |fixture| async move {
        let retained_root = fixture.root;
        for cookie in [COOKIE_A, COOKIE_B] {
            let body = fixture
                .state
                .read_current_artifact_chunk(&parts(cookie)?, fixture.receipt.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            require(
                body == TEXT.as_bytes(),
                "actual consumer did not return exact original bytes",
            )?;
        }
        let observed = require(
            fixture.port.reads.load(Ordering::SeqCst) == 2,
            "actual production port was not used",
        );
        drop(retained_root);
        observed
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn same_actor_generation_session_a_delete_refuses_only_original_a() {
    with_fixture("read-session-delete-a", |fixture| async move {
        let a = fixture.auth(COOKIE_A).await?;
        let b = fixture.auth(COOKIE_B).await?;
        fixture
            .sql("DELETE FROM public.sessions WHERE id='actual-read-session-a'")
            .await?;
        require(
            matches!(fixture.read(a).await, Err(AppError::Unauthenticated)),
            "deleted actual A received bytes",
        )?;
        require(
            fixture.read(b).await.map_err(|error| error.to_string())? == TEXT.as_bytes(),
            "unaffected actual B lost authority",
        )
    })
    .await;
}

async fn changed_original_session(tag: &str, sql: &'static str) {
    with_fixture(tag, |fixture| async move {
        let auth = fixture.auth(COOKIE_A).await?;
        fixture.sql(sql).await?;
        require(
            matches!(fixture.read(auth).await, Err(AppError::Unauthenticated)),
            "changed original session received bytes",
        )
    })
    .await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn same_id_token_replacement_does_not_rebind_original_read() {
    changed_original_session(
        "read-token-replacement",
        "UPDATE public.sessions SET token='replaced-hmac-column' WHERE id='actual-read-session-a'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn same_id_created_epoch_replacement_does_not_rebind_original_read() {
    changed_original_session("read-created-replacement", "UPDATE public.sessions SET created_at=created_at-interval '1 second' WHERE id='actual-read-session-a'").await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn raw_null_current_generation_is_not_original_zero() {
    changed_original_session(
        "read-current-null",
        "UPDATE public.users SET auth_generation=NULL WHERE id='current-read-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn raw_negative_current_generation_is_not_original_zero() {
    changed_original_session("read-current-negative", "ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='current-read-owner'").await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn raw_null_issued_generation_is_not_original_zero() {
    changed_original_session(
        "read-issued-null",
        "UPDATE public.sessions SET auth_generation=NULL WHERE id='actual-read-session-a'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn raw_negative_issued_generation_is_not_original_zero() {
    changed_original_session("read-issued-negative", "ALTER TABLE public.sessions DROP CONSTRAINT sessions_auth_generation_nonnegative; UPDATE public.sessions SET auth_generation=-1 WHERE id='actual-read-session-a'").await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn current_role_change_refuses_original_user_read() {
    changed_original_session(
        "read-role-replacement",
        "UPDATE public.user_roles SET role='admin' WHERE user_id='current-read-owner'",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn current_deny_refuses_original_session_read() {
    changed_original_session(
        "read-deny",
        "INSERT INTO public.revoked_access(email,revoked_by) VALUES('current-read-owner@example.test','current-read-owner')",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn missing_binding_and_malformed_selector_reach_zero_actual_read_ports() {
    with_fixture("read-missing-binding", |fixture| async move {
        let bound = fixture.auth(COOKIE_A).await?;
        let plain = AuthContextBuilder::from_verified_session(
            bound.deployment().clone(),
            bound.tenant().clone(),
            bound.actor().clone(),
            bound.auth_generation(),
            bound.is_single_user(),
        )
        .with_roles(bound.roles().iter().copied())
        .build();
        require(
            matches!(
                fixture.read(plain).await,
                Err(AppError::DependencyUnavailable {
                    dependency: "host_request_binding"
                })
            ),
            "missing binding did not refuse statically",
        )?;
        require(
            matches!(
                fixture
                    .application
                    .read_current_artifact_chunk(bound, "malformed-selector".to_owned())
                    .await,
                Err(AppError::MalformedPayload { .. })
            ),
            "selector validator was bypassed",
        )?;
        require(
            fixture.port.reads.load(Ordering::SeqCst) == 0,
            "missing binding/invalid selector called actual port",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn pending_chunk_cannot_handoff_to_other_actual_session_with_same_six_facts() {
    with_fixture("read-foreign-binding", |fixture| async move {
        let a = fixture.auth(COOKIE_A).await?;
        let b = fixture.auth(COOKIE_B).await?;
        require(a == b, "A/B fixture six facts were not identical")?;
        let pending = fixture
            .application
            .read_current_artifact_chunk(a, fixture.receipt.artifact_id.clone())
            .await
            .map_err(|error| error.to_string())?;
        require(
            matches!(pending.handoff(&b), Err(AppError::Unauthenticated)),
            "original A pending bytes escaped through B binding",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn real_owner_close_during_last_application_await_refuses_pending_body() {
    with_fixture("read-owner-close", |fixture| async move {
        let gate = fixture.pending_gate()?;
        let state = fixture.state.clone();
        let id = fixture.receipt.artifact_id.clone();
        let request = parts(COOKIE_A)?;
        let task =
            tokio::spawn(async move { state.read_current_artifact_chunk(&request, id).await });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .map_err(|_| "actual sealed pending result was not observed".to_owned())?;
        fixture.resolver.close_request_bindings();
        gate.release.notify_one();
        require(
            matches!(
                task.await.map_err(|error| error.to_string())?,
                Err(AppError::Unauthenticated)
            ),
            "closed real owner released pending bytes",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn original_fd_change_during_last_application_await_refuses_pending_body() {
    with_fixture("read-retained-fd", |fixture| async move {
        use std::io::Write as _;
        let gate = fixture.pending_gate()?;
        let state = fixture.state.clone();
        let id = fixture.receipt.artifact_id.clone();
        let request = parts(COOKIE_A)?;
        let task =
            tokio::spawn(async move { state.read_current_artifact_chunk(&request, id).await });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .map_err(|_| "actual sealed pending result was not observed".to_owned())?;
        mutate_owned_read_only_file(
            &fixture
                .root
                .0
                .join("objects")
                .join(&fixture.receipt.artifact_id),
            |fd, _| fd.write_all(b"X"),
            |before, after| {
                before.first() == Some(&b' ')
                    && after.first() == Some(&b'X')
                    && after.len() == before.len()
                    && after[1..] == before[1..]
            },
        )?;
        gate.release.notify_one();
        require(
            matches!(
                task.await.map_err(|error| error.to_string())?,
                Err(AppError::DependencyUnavailable {
                    dependency: "artifacts"
                })
            ),
            "changed original FD released pending bytes",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL; real synchronous clock expiry"]
async fn real_session_clock_expires_while_pending_result_is_withheld() {
    with_fixture("read-clock-expiry", |fixture| async move {
        let expires = OffsetDateTime::now_utc() + time::Duration::seconds(2);
        fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "UPDATE public.sessions SET expires_at=$1 WHERE id=$2",
                &[&expires, &A_ID],
            )
            .await
            .map_err(|error| error.to_string())?;
        let gate = fixture.pending_gate()?;
        let state = fixture.state.clone();
        let id = fixture.receipt.artifact_id.clone();
        let request = parts(COOKIE_A)?;
        let task =
            tokio::spawn(async move { state.read_current_artifact_chunk(&request, id).await });
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .map_err(|_| "actual sealed pending result was not observed".to_owned())?;
        while OffsetDateTime::now_utc() < expires {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        gate.release.notify_one();
        require(
            matches!(
                task.await.map_err(|error| error.to_string())?,
                Err(AppError::Unauthenticated)
            ),
            "expired original session clock released pending bytes",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn authority_foreign_pool_and_replacement_enrollment_are_refused() {
    with_fixture("read-foreign-pool", |fixture| async move {
        require(
            fixture
                .resolver
                .install_artifact_read_authority(&fixture.port.actual.read_authority())
                == Err(HostRequestBindingError::Unavailable),
            "authority enrollment was replaceable",
        )?;
        let foreign_pool = pool::connect(&fixture.config)
            .await
            .map_err(|error| error.to_string())?;
        let foreign = PostgresSessionAuthResolver::new(
            foreign_pool,
            SESSION_KEY,
            default_session_lifetime(),
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
        )
        .map_err(|error| error.to_string())?;
        require(
            foreign.install_artifact_read_authority(&fixture.port.actual.read_authority())
                == Err(HostRequestBindingError::Unavailable),
            "foreign physical Pool enrolled artifact owner",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-owned isolated PostgreSQL"]
async fn last_real_resolver_owner_drop_refuses_prepared_chunk_without_lease_retention() {
    with_fixture("read-last-owner-drop", |fixture| async move {
        let auth = fixture.auth(COOKIE_A).await?;
        let pending = fixture
            .application
            .read_current_artifact_chunk(auth.clone(), fixture.receipt.artifact_id.clone())
            .await
            .map_err(|error| error.to_string())?;
        let Fixture {
            resolver,
            state,
            root,
            ..
        } = fixture;
        drop(state);
        drop(resolver);
        require(
            matches!(pending.handoff(&auth), Err(AppError::Unauthenticated)),
            "pending witness retained last real resolver lease",
        )?;
        drop(root);
        Ok(())
    })
    .await;
}

struct TracePhaseGate {
    io_seen: std::sync::atomic::AtomicBool,
    ready_seen: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
    timed_out: std::sync::atomic::AtomicBool,
}
impl TracePhaseGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            io_seen: std::sync::atomic::AtomicBool::new(false),
            ready_seen: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
            timed_out: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
struct PhaseVisitor(Option<&'static str>);
impl tracing::field::Visit for PhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "artifact_read_phase" {
            self.0 = match value {
                "actual_io_completed_before_joint" => Some("actual_io_completed_before_joint"),
                "joint_statement_ready" => Some("joint_statement_ready"),
                _ => None,
            };
        }
    }
}
struct ReadPhaseSubscriber(Arc<TracePhaseGate>);
impl tracing::Subscriber for ReadPhaseSubscriber {
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
        let mut visitor = PhaseVisitor(None);
        event.record(&mut visitor);
        match visitor.0 {
            Some("actual_io_completed_before_joint") => {
                self.0.io_seen.store(true, Ordering::SeqCst);
            }
            Some("joint_statement_ready")
                if self.0.io_seen.load(Ordering::SeqCst)
                    && !self.0.ready_seen.swap(true, Ordering::SeqCst) =>
            {
                self.0.entered.notify_one();
                let released = self.0.released.lock().unwrap();
                let (_released, timeout) = self
                    .0
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
                    .unwrap();
                if timeout.timed_out() {
                    self.0.timed_out.store(true, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }
}
#[derive(Default)]
struct HostReadWaitDiagnostic {
    controller_pid: i32,
    observer_pid: i32,
    io_seen: bool,
    ready_seen: bool,
    controller_lock_ack: bool,
    entered_notification_to_lock_ack_ms: Option<u128>,
    barrier_timed_out_before_release: Option<bool>,
    barrier_timed_out_after_observation: Option<bool>,
    read_task_finished_before_release: Option<bool>,
    activity_capacity_bytes: i64,
    observer_samples: u32,
    marker_candidates: i32,
    marker_active_candidates: i32,
    marker_idle_in_transaction_candidates: i32,
    marker_idle_candidates: i32,
    marker_other_state_candidates: i32,
    marker_lock_candidates: i32,
    exact_waiter_count: i32,
    exact_waiter_pid: Option<i32>,
    read_task_finished_after_observation: Option<bool>,
    controller_commit_ack: bool,
    controller_rollback_attempted: bool,
    controller_rollback_ack: bool,
    reader_join_ack: bool,
    reader_join_outcome: Option<&'static str>,
    reader_terminal_class: Option<&'static str>,
}

fn host_read_terminal_class(result: &Result<Vec<u8>, AppError>) -> &'static str {
    match result {
        Ok(_) => "body_returned",
        Err(AppError::Unauthenticated) => "unauthenticated",
        Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        }) => "host_request_binding_unavailable",
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        }) => "artifacts_unavailable",
        Err(_) => "other_closed_error",
    }
}

fn emit_host_read_wait_diagnostic(diagnostic: &HostReadWaitDiagnostic) {
    let sampled = diagnostic.observer_samples > 0;
    let observer_sample_status = if sampled { "sampled" } else { "not_sampled" };
    let exact_waiter_pid = if sampled {
        diagnostic.exact_waiter_pid
    } else {
        None
    };
    eprintln!(
        concat!(
            "ARTIFACT_CURRENT_SERVER_FINAL_WAIT_DIAGNOSTIC controller_pid={} observer_pid={} io_seen={} ready_seen={} ",
            "controller_lock_ack={} entered_notification_to_lock_ack_ms={:?} ",
            "barrier_timed_out_before_release={:?} barrier_timed_out_after_observation={:?} ",
            "read_task_finished_before_release={:?} activity_capacity_bytes={} ",
            "observer_samples={} observer_sample_status={} marker_candidates={:?} ",
            "marker_active_candidates={:?} marker_idle_in_transaction_candidates={:?} ",
            "marker_idle_candidates={:?} marker_other_state_candidates={:?} ",
            "marker_lock_candidates={:?} exact_waiter_count={:?} exact_waiter_pid={:?} ",
            "read_task_finished_after_observation={:?} controller_commit_ack={} ",
            "controller_rollback_attempted={} controller_rollback_ack={} reader_join_ack={} ",
            "reader_join_outcome={:?} reader_terminal_class={:?} ",
            "ack_semantics=\"true=actual successful ACK; false=ACK not obtained, ",
            "not proof that an effect did not occur\""
        ),
        diagnostic.controller_pid,
        diagnostic.observer_pid,
        diagnostic.io_seen,
        diagnostic.ready_seen,
        diagnostic.controller_lock_ack,
        diagnostic.entered_notification_to_lock_ack_ms,
        diagnostic.barrier_timed_out_before_release,
        diagnostic.barrier_timed_out_after_observation,
        diagnostic.read_task_finished_before_release,
        diagnostic.activity_capacity_bytes,
        diagnostic.observer_samples,
        observer_sample_status,
        sampled.then_some(diagnostic.marker_candidates),
        sampled.then_some(diagnostic.marker_active_candidates),
        sampled.then_some(diagnostic.marker_idle_in_transaction_candidates),
        sampled.then_some(diagnostic.marker_idle_candidates),
        sampled.then_some(diagnostic.marker_other_state_candidates),
        sampled.then_some(diagnostic.marker_lock_candidates),
        sampled.then_some(diagnostic.exact_waiter_count),
        exact_waiter_pid,
        diagnostic.read_task_finished_after_observation,
        diagnostic.controller_commit_ack,
        diagnostic.controller_rollback_attempted,
        diagnostic.controller_rollback_ack,
        diagnostic.reader_join_ack,
        diagnostic.reader_join_outcome,
        diagnostic.reader_terminal_class,
    );
}

async fn actual_final_wait(
    observer: &tokio_postgres::Client,
    blocker: i32,
    diagnostic: &mut HostReadWaitDiagnostic,
) -> Result<i32, String> {
    for _ in 0..150 {
        let row = observer.query_one(
            r#"SELECT COUNT(*)::integer AS marker_candidates,
       COUNT(*) FILTER (WHERE a.state='active')::integer AS marker_active_candidates,
       COUNT(*) FILTER (WHERE a.state='idle in transaction')::integer AS marker_idle_in_transaction_candidates,
       COUNT(*) FILTER (WHERE a.state='idle')::integer AS marker_idle_candidates,
       COUNT(*) FILTER (WHERE a.state IS NULL OR a.state NOT IN ('active','idle in transaction','idle'))::integer AS marker_other_state_candidates,
       COUNT(*) FILTER (WHERE a.wait_event_type='Lock')::integer AS marker_lock_candidates,
       COUNT(*) FILTER (WHERE a.wait_event_type='Lock'
                        AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)))::integer AS exact_waiter_count,
       MIN(a.pid) FILTER (WHERE a.wait_event_type='Lock'
                          AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid))) AS exact_waiter_pid
FROM pg_catalog.pg_stat_activity a
WHERE a.datname=current_database()
  AND a.pid<>pg_backend_pid()
  AND a.query LIKE '%/* artifact_current_host_joint_read_after_io */%'"#,
            &[&blocker],
        ).await.map_err(|error| error.to_string())?;
        let marker_candidates: i32 = row
            .try_get("marker_candidates")
            .map_err(|error| error.to_string())?;
        let marker_active_candidates: i32 = row
            .try_get("marker_active_candidates")
            .map_err(|error| error.to_string())?;
        let marker_idle_in_transaction_candidates: i32 = row
            .try_get("marker_idle_in_transaction_candidates")
            .map_err(|error| error.to_string())?;
        let marker_idle_candidates: i32 = row
            .try_get("marker_idle_candidates")
            .map_err(|error| error.to_string())?;
        let marker_other_state_candidates: i32 = row
            .try_get("marker_other_state_candidates")
            .map_err(|error| error.to_string())?;
        let marker_lock_candidates: i32 = row
            .try_get("marker_lock_candidates")
            .map_err(|error| error.to_string())?;
        let exact_waiter_count: i32 = row
            .try_get("exact_waiter_count")
            .map_err(|error| error.to_string())?;
        let exact_waiter_pid: Option<i32> = row
            .try_get("exact_waiter_pid")
            .map_err(|error| error.to_string())?;
        diagnostic.marker_candidates = marker_candidates;
        diagnostic.marker_active_candidates = marker_active_candidates;
        diagnostic.marker_idle_in_transaction_candidates = marker_idle_in_transaction_candidates;
        diagnostic.marker_idle_candidates = marker_idle_candidates;
        diagnostic.marker_other_state_candidates = marker_other_state_candidates;
        diagnostic.marker_lock_candidates = marker_lock_candidates;
        diagnostic.exact_waiter_count = exact_waiter_count;
        diagnostic.exact_waiter_pid = exact_waiter_pid;
        diagnostic.observer_samples += 1;
        if exact_waiter_count == 1 {
            return exact_waiter_pid
                .ok_or_else(|| "actual exact Lock waiter PID was not decoded".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("actual final joint statement/controller Lock wait was not observed".to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned isolated PostgreSQL and real final-query Lock/COMMIT ACK"]
async fn actual_worker_ack_then_final_session_statement_wait_observes_delete_commit() {
    use tracing::instrument::WithSubscriber as _;
    with_fixture("read-real-final-wait", |fixture| async move {
        let retained_root = fixture.root;

        let mut controller = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let observer = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let observer_pid: i32 = observer.query_one("SELECT pg_backend_pid()", &[]).await
            .map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        let activity_capacity_bytes: i64 = observer.query_one(
            "SELECT pg_size_bytes(current_setting('track_activity_query_size'))", &[],
        ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        require(controller_pid != observer_pid, "actual controller and observer PIDs were not distinct")?;
        require(activity_capacity_bytes >= 16_384, "owned Server activity query width was not actually sixteen KiB")?;
        let mut diagnostic = HostReadWaitDiagnostic {
            controller_pid,
            observer_pid,
            activity_capacity_bytes,
            ..HostReadWaitDiagnostic::default()
        };
        let gate = TracePhaseGate::new();
        let dispatch = tracing::Dispatch::new(ReadPhaseSubscriber(gate.clone()));
        let state = fixture.state.clone();
        let id = fixture.receipt.artifact_id.clone();
        let request = parts(COOKIE_A)?;
        let mut task = Some(tokio::spawn(
            async move { state.read_current_artifact_chunk(&request, id).await }.with_subscriber(dispatch),
        ));
        let notification = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await;
        let entered_at = std::time::Instant::now();
        diagnostic.io_seen = gate.io_seen.load(Ordering::SeqCst);
        diagnostic.ready_seen = gate.ready_seen.load(Ordering::SeqCst);
        let mut failure = notification
            .map_err(|_| "actual IO/final-ready phases were not observed".to_owned())
            .and_then(|_| require(diagnostic.io_seen && diagnostic.ready_seen, "actual worker ACK did not precede final-ready phase"))
            .err();
        let mut transaction = if failure.is_none() {
            match controller.transaction().await {
                Ok(transaction) => Some(transaction),
                Err(error) => {
                    failure = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        let attempted: Result<i32, String> = if let Some(error) = failure {
            Err(error)
        } else {
            async {
                transaction.as_ref().expect("actual controller transaction retained")
                    .batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE").await.map_err(|error| error.to_string())?;
                diagnostic.controller_lock_ack = true;
                diagnostic.entered_notification_to_lock_ack_ms = Some(entered_at.elapsed().as_millis());
                diagnostic.barrier_timed_out_before_release = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_before_release = Some(task.as_ref().expect("original reader retained").is_finished());
                require(diagnostic.barrier_timed_out_before_release == Some(false), "trace barrier expired rather than controller release")?;
                gate.release();
                let observed = actual_final_wait(&observer, controller_pid, &mut diagnostic).await;
                diagnostic.barrier_timed_out_after_observation = Some(gate.timed_out.load(Ordering::SeqCst));
                diagnostic.read_task_finished_after_observation = Some(task.as_ref().expect("original reader retained").is_finished());
                let waiter = observed?;
                require(diagnostic.barrier_timed_out_after_observation == Some(false), "trace barrier expired rather than controller release")?;
                transaction.as_ref().expect("actual controller transaction retained")
                    .execute("DELETE FROM public.sessions WHERE id=$1", &[&A_ID]).await.map_err(|error| error.to_string())?;
                transaction.take().expect("actual controller transaction retained")
                    .commit().await.map_err(|error| error.to_string())?;
                diagnostic.controller_commit_ack = true;
                Ok(waiter)
            }.await
        };
        gate.release();
        if let Some(transaction) = transaction.take() {
            diagnostic.controller_rollback_attempted = true;
            diagnostic.controller_rollback_ack = transaction.rollback().await.is_ok();
        }
        let joined = task.take().expect("original reader retained").await;
        let read_result = match joined {
            Ok(result) => {
                diagnostic.reader_join_ack = true;
                diagnostic.reader_join_outcome = Some("read_result");
                diagnostic.reader_terminal_class = Some(host_read_terminal_class(&result));
                Ok(result)
            }
            Err(error) => {
                let (closed, failure) = if error.is_panic() {
                    ("read_task_panicked", "actual read task panicked")
                } else {
                    ("read_task_cancelled", "actual read task was cancelled")
                };
                diagnostic.reader_join_outcome = Some(closed);
                Err(failure.to_owned())
            }
        };
        let outcome = match attempted {
            Err(original_failure) => Err(original_failure),
            Ok(waiter) => match read_result {
                Ok(Err(AppError::Unauthenticated)) => {
                    eprintln!("ARTIFACT_CURRENT_SERVER_FINAL_WAIT io_ack=true final_marker=true wait_type=Lock blocker_pid={controller_pid} waiter_pid={waiter} controller_commit_ack=true");
                    Ok(())
                }
                Ok(_) => Err("actual final joint query did not observe committed A deletion".to_owned()),
                Err(error) => Err(error),
            },
        };
        if outcome.is_err() {
            emit_host_read_wait_diagnostic(&diagnostic);
        }
        drop(transaction);
        drop(observer);
        drop(controller);
        drop(retained_root);
        outcome
    }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned PostgreSQL and real post-IO cleanup-fence Lock/COMMIT ACK"]
async fn actual_worker_ack_then_final_cleanup_fence_wait_observes_armed_commit() {
    use tracing::instrument::WithSubscriber as _;
    with_fixture("read-real-cleanup-final-wait", |fixture| async move {
        let mut controller = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let observer = fixture.pool.get().await.map_err(|error| error.to_string())?;
        let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|error| error.to_string())?.get(0);
        let observer_pid: i32 = observer.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|error| error.to_string())?.get(0);
        let activity_capacity_bytes: i64 = observer.query_one(
            "SELECT pg_size_bytes(current_setting('track_activity_query_size'))", &[],
        ).await.map_err(|error| error.to_string())?.get(0);
        require(controller_pid != observer_pid && activity_capacity_bytes >= 16_384, "actual controller/observer or original activity width was invalid")?;
        const FACTS: &str = "SELECT jsonb_build_object( \
          'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
          'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
          'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
          'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
          'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
          'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))";
        let before: serde_json::Value = observer.query_one(FACTS, &[]).await.map_err(|error| error.to_string())?.get(0);
        let mut diagnostic = HostReadWaitDiagnostic { controller_pid, observer_pid, activity_capacity_bytes, ..HostReadWaitDiagnostic::default() };
        let gate = TracePhaseGate::new();
        let dispatch = tracing::Dispatch::new(ReadPhaseSubscriber(Arc::clone(&gate)));
        let state = fixture.state.clone();
        let id = fixture.receipt.artifact_id.clone();
        let request = parts(COOKIE_A)?;
        let task = tokio::spawn(async move { state.read_current_artifact_chunk(&request, id).await }.with_subscriber(dispatch));
        let mut transaction = None;
        let attempted = async {
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await.map_err(|_| "actual cleanup read final-ready phase not observed".to_owned())?;
            diagnostic.io_seen = gate.io_seen.load(Ordering::SeqCst);
            diagnostic.ready_seen = gate.ready_seen.load(Ordering::SeqCst);
            require(diagnostic.io_seen && diagnostic.ready_seen && !gate.timed_out.load(Ordering::SeqCst), "actual worker ACK did not precede controlled final joint")?;
            transaction = Some(controller.transaction().await.map_err(|error| error.to_string())?);
            transaction.as_ref().unwrap().batch_execute(
                "SET LOCAL lock_timeout='1s'; LOCK TABLE openbot_internal.artifact_cleanup_fences IN ACCESS EXCLUSIVE MODE",
            ).await.map_err(|error| error.to_string())?;
            diagnostic.controller_lock_ack = true;
            diagnostic.barrier_timed_out_before_release = Some(gate.timed_out.load(Ordering::SeqCst));
            diagnostic.read_task_finished_before_release = Some(task.is_finished());
            require(!gate.timed_out.load(Ordering::SeqCst) && !task.is_finished(), "final-ready gate expired or original read ended before release")?;
            gate.release();
            let waiter = actual_final_wait(&observer, controller_pid, &mut diagnostic).await?;
            require(waiter != controller_pid && waiter != observer_pid && !gate.timed_out.load(Ordering::SeqCst) && !task.is_finished(), "original final waiter identity or gate state was invalid")?;
            // Only a controlled input on the actual saved five-key row; no cleanup producer.
            let changed = transaction.as_ref().unwrap().execute(
                "INSERT INTO openbot_internal.artifact_cleanup_fences \
                 (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
                 SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
                 FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND artifact_id=$3",
                &[&DEPLOYMENT, &TENANT, &fixture.receipt.artifact_id],
            ).await.map_err(|error| error.to_string())?;
            require(changed == 1, "controller did not arm exactly the original real Save row")?;
            transaction.take().unwrap().commit().await.map_err(|error| error.to_string())?;
            diagnostic.controller_commit_ack = true;
            Ok::<_, String>(waiter)
        }.await;
        gate.release();
        let rollback = match transaction.take() {
            Some(transaction) => {
                diagnostic.controller_rollback_attempted = true;
                let result = transaction.rollback().await;
                diagnostic.controller_rollback_ack = result.is_ok();
                result.map_err(|error| error.to_string())
            }
            None => Ok(()),
        };
        drop(transaction);
        let joined = task.await;
        diagnostic.reader_join_ack = joined.is_ok();
        let result = joined.map_err(|error| error.to_string());
        if let Ok(result) = &result { diagnostic.reader_terminal_class = Some(host_read_terminal_class(result)); }
        let after = observer.query_one(FACTS, &[]).await.map_err(|error| error.to_string()).map(|row| row.get::<_, serde_json::Value>(0));
        let lifecycle = fixture.port.actual.read_authority().read_lifecycle();
        lifecycle.close();
        let drained = lifecycle.drain_before(std::time::Instant::now() + Duration::from_secs(3)).await;
        let outcome = async {
            let waiter = attempted?;
            rollback?;
            require(matches!(result?, Err(AppError::DependencyUnavailable { dependency: "artifacts" })), "actual final joint ignored the committed armed fence or released a body")?;
            require(before == after?, "read-only cleanup consumer changed original business/charge/receipt/audit rows")?;
            require(drained.is_ok(), "original failed read resources did not really drain")?;
            require(fixture.root.0.join("objects").join(&fixture.receipt.artifact_id).is_file(), "controlled armed input was counted as physical deletion")?;
            eprintln!("ARTIFACT_CURRENT_SERVER_CLEANUP_FINAL_WAIT io_ack=true final_ready=true actual_lock=true controller_pid={controller_pid} observer_pid={observer_pid} waiter_pid={waiter} commit_ack=true bytes_released=false");
            Ok::<_, String>(())
        }.await;
        if outcome.is_err() { emit_host_read_wait_diagnostic(&diagnostic); }
        fixture.resolver.close_request_bindings();
        drop(observer);
        drop(controller);
        let observations = fixture.pool.connection_observations();
        fixture.pool.close();
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(3);
        for observation in observations { observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?; }
        outcome
    }).await;
}
