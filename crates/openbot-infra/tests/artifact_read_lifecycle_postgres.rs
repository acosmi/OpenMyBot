//! Genuine owned-PG Begin/Save and retained-reader lifecycle, through the actual CORE port.
//! The issuer guard is a test seam; real Server and Desktop hosts are separate consumers.
//! All descriptor samples select only this fixture test process, never paths or another PID.
#![cfg(all(unix, feature = "server-runtime"))]

mod harness;

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, Permissions};
use std::future::Future;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use openbot_application::{
    ArtifactAdministration, BeginThreadRunRequest, CurrentArtifactReadOperation, ThreadDirectory,
};
use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, MAX_ARTIFACT_READ_CHUNK_BYTES, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, DeploymentId, RunId, TenantId, thread::ThreadIdentity,
};
use openbot_contracts::request_binding::*;
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::{SessionLifetimePolicy, SessionState, evaluate_session};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::PostgresArtifactAdministration;
use openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority;
use openbot_infra::artifact_registry::ArtifactDatasetRegistry;
use openbot_infra::artifact_store::DatasetBoundArtifactStore;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::{baseline, native, pool, pool::DatabaseConfig};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use time::OffsetDateTime;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

const DEPLOYMENT: &str = "lifecycle-core-owned-deployment";
const TENANT: &str = "lifecycle-core-owned-tenant";
const OWNER: &str = "lifecycle-core-owner";
const SESSION: &str = "lifecycle-core-session";
const COLUMN: &str = "owned-lifecycle-test-session-column";
const PARTIAL: &str = "physical_segment_completed_before_more_io";
const JOINT: &str = "joint_statement_ready";

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn unavailable(error: &AppError) -> bool {
    matches!(
        error,
        AppError::DependencyUnavailable {
            dependency: "artifacts"
        }
    )
}
fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        time::Duration::minutes(30),
        time::Duration::hours(1),
        time::Duration::seconds(1),
    )
    .unwrap()
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "openbot-artifact-lifecycle-core-{}",
            Uuid::now_v7()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "owned_root_create_failed")?;
        Ok(Self(
            fs::canonicalize(path).map_err(|_| "owned_root_canonicalize_failed")?,
        ))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_LIFECYCLE_CORE_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned lifecycle root cleanup failed");
        }
    }
}

struct CoreSessionGuard {
    pool: Pool,
    issuer: RequestBindingIssuer,
    authority: Weak<PostgresArtifactReadAuthority>,
    final_calls: Arc<AtomicUsize>,
}
impl HostRequestBindingGuard for CoreSessionGuard {
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            let identity = auth
                .request_binding()
                .ok_or(HostRequestBindingError::Missing)?
                .identity();
            let epoch = self.issuer.borrow_server_session_epoch(identity)?;
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = client.query_opt(
                "SELECT u.auth_generation,u.email,EXISTS(SELECT 1 FROM public.revoked_access r WHERE r.email=lower(u.email)) AS revoked, \
                 ARRAY(SELECT role::text FROM public.user_roles WHERE user_id=u.id ORDER BY role::text) AS roles, \
                 s.id,s.user_id,s.token,s.created_at,s.updated_at,s.expires_at,s.auth_generation AS issued \
                 FROM public.users u JOIN public.sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2",
                &[&auth.actor().as_str(), &epoch.lookup_id()],
            ).await.map_err(|_| HostRequestBindingError::Unavailable)?.ok_or(HostRequestBindingError::NotCurrent)?;
            let generation: Option<i64> = row
                .try_get("auth_generation")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let issued: Option<i64> = row
                .try_get("issued")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let roles: Vec<String> = row
                .try_get("roles")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let revoked: bool = row
                .try_get("revoked")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let id: String = row
                .try_get("id")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let user: String = row
                .try_get("user_id")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let token: String = row
                .try_get("token")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let created: OffsetDateTime = row
                .try_get("created_at")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let updated: OffsetDateTime = row
                .try_get("updated_at")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let expires: OffsetDateTime = row
                .try_get("expires_at")
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let now = OffsetDateTime::now_utc();
            if generation != Some(0)
                || issued != Some(0)
                || auth.auth_generation().get() != 0
                || roles != ["user"]
                || revoked
                || now >= expires
                || !epoch.matches_raw_row(&id, &user, &token, created, 0)
                || evaluate_session(
                    lifetime(),
                    SessionState::rehydrate(created, updated, auth.auth_generation()),
                    auth.auth_generation(),
                    now,
                )
                .is_err()
            {
                return Err(HostRequestBindingError::NotCurrent);
            }
            Ok(())
        })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> ArtifactReadCurrentCheck<'a> {
        Box::pin(async move {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            let authority = self
                .authority
                .upgrade()
                .ok_or(ArtifactReadCurrentError::Unavailable)?;
            let identity = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Unavailable)?
                .identity();
            let epoch = self
                .issuer
                .borrow_server_session_epoch(identity)
                .map_err(ArtifactReadCurrentError::Host)?;
            authority
                .observe_server_session(auth, target, epoch, lifetime(), deadline)
                .await
        })
    }
}

struct Fixture {
    pool: Pool,
    administration: Arc<PostgresArtifactAdministration>,
    owner: RequestBindingOwnerLease,
    auth: AuthContext,
    begin: BeginThreadRunRequest,
    final_calls: Arc<AtomicUsize>,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config)
            .await
            .map_err(|_| "owned_pool_connect_failed")?;
        {
            let mut client = pool.get().await.map_err(|_| "owned_pool_get_failed")?;
            baseline::apply(&client)
                .await
                .map_err(|_| "owned_baseline_failed")?;
            native::apply(&mut client)
                .await
                .map_err(|_| "owned_native_failed")?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('lifecycle-core-owner','lifecycle-core-owner@example.test',0);
              INSERT INTO public.user_roles(user_id,role) VALUES('lifecycle-core-owner','user');
              INSERT INTO public.agents(id,name,type,configuration) VALUES('lifecycle-core-bot','Lifecycle fixture','built_in','{}');
              INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('lifecycle-core-bot','lifecycle-core-owner','Lifecycle fixture','fixture','fixture','public');
              INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000009','lifecycle-core-owned-tenant','fixture','fixture');")
                .await.map_err(|_| "owned_identity_seed_failed")?;
            let created = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            client.execute("INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,$3,$4,$4,$5,0)",
                &[&SESSION, &OWNER, &COLUMN, &created, &(created + time::Duration::hours(1))])
                .await.map_err(|_| "owned_session_seed_failed")?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let begin = BeginThreadRunRequest {
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            actor: ActorId::new(OWNER),
            auth_generation: AuthGeneration::new(0),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([0x59; 16]),
                run_id: RunId::new("lifecycle/core-source"),
                bot_id: BotId::new("lifecycle-core-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "small actual Begin; controlled own-row update then actual Save".into(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "lifecycle-core-fixture-owner".into(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|_| "owned_directory_failed")?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|_| "owned_begin_failed")?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|_| "owned_registry_failed")?,
        );
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|_| "owned_root_open_failed")?,
                registry.clone(),
                policy,
            )
            .await
            .map_err(|_| "owned_store_bind_failed")?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                policy,
                SecretBytes::new(vec![0x59; 32]),
            )
            .map_err(|_| "owned_administration_failed")?,
        );
        let authority = administration.read_authority();
        require(
            authority.matches_pool_scope(&pool, &deployment, &tenant),
            "actual_same_pool_enrollment_failed",
        )?;
        require(
            Arc::ptr_eq(
                &authority.read_lifecycle(),
                &administration.read_authority().read_lifecycle(),
            ),
            "factory_tracker_identity_changed",
        )?;
        let (owner, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let plain = AuthContextBuilder::from_verified_session(
            deployment,
            tenant,
            ActorId::new(OWNER),
            AuthGeneration::new(0),
            false,
        )
        .with_role(Role::User)
        .build();
        let created: OffsetDateTime = pool
            .get()
            .await
            .map_err(|_| "owned_pool_get_failed")?
            .query_one(
                "SELECT created_at FROM public.sessions WHERE id=$1",
                &[&SESSION],
            )
            .await
            .map_err(|_| "owned_session_observation_failed")?
            .get(0);
        let final_calls = Arc::new(AtomicUsize::new(0));
        let binding = issuer
            .bind_server_session(
                &plain,
                ServerSessionBindingIdentity::from_verified_row(
                    SESSION.into(),
                    plain.actor().clone(),
                    COLUMN.into(),
                    created,
                    plain.auth_generation(),
                ),
                Arc::new(CoreSessionGuard {
                    pool: pool.clone(),
                    issuer: issuer.clone(),
                    authority: Arc::downgrade(&authority),
                    final_calls: final_calls.clone(),
                }),
            )
            .map_err(|_| "owned_epoch_bind_failed")?;
        let auth = plain
            .with_verified_request_binding(binding)
            .map_err(|_| "owned_epoch_attach_failed")?;
        Ok(Self {
            pool,
            administration,
            owner,
            auth,
            begin,
            final_calls,
            root,
        })
    }
    async fn save_length(
        &self,
        length: usize,
    ) -> Result<(String, ArtifactRegistrationReceipt), String> {
        let payload = "L".repeat(length);
        require(length != 0, "zero_available_artifact_is_not_an_oracle")?;
        let message_id = format!("{}:input", self.begin.command.run_id.as_str());
        let changed = self.pool.get().await.map_err(|_| "owned_pool_get_failed")?.execute(
            "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb($1::text)) WHERE message_id=$2",
            &[&payload, &message_id],
        ).await.map_err(|_| "owned_source_update_failed")?;
        require(changed == 1, "owned_source_update_not_single_row")?;
        let receipt = self
            .administration
            .save_run_message_text(
                &self.auth,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: message_id,
                    expected_sha256: Sha256Digest::of(payload.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|_| "actual_owned_save_failed")?;
        Ok((payload, receipt))
    }
    async fn open(
        &self,
        receipt: &ArtifactRegistrationReceipt,
    ) -> Result<CurrentArtifactReadOperation, String> {
        self.administration
            .open_host_bound_read_operation(&self.auth, &receipt.artifact_id)
            .await
            .map_err(|_| "actual_owned_operation_open_failed".into())
    }
    fn object(&self, receipt: &ArtifactRegistrationReceipt) -> PathBuf {
        self.root.0.join("objects").join(&receipt.artifact_id)
    }
    async fn finish(self) -> Result<(), String> {
        let lifecycle = self.administration.read_authority().read_lifecycle();
        lifecycle.close();
        let result = lifecycle
            .drain_before(Instant::now() + Duration::from_secs(5))
            .await;
        if result.is_err() {
            lifecycle.drain().await;
        }
        self.owner.close();
        self.pool.close();
        require(
            result.is_ok(),
            "actual_inventory_cleanup_exceeded_original_deadline",
        )?;
        drop(self);
        Ok(())
    }
}
async fn with_fixture<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Arc<Fixture>) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let fixture = Arc::new(Fixture::new(config).await?);
        let result = body(fixture.clone()).await;
        let fixture =
            Arc::try_unwrap(fixture).map_err(|_| "fixture_owner_not_returned_after_actual_body")?;
        let cleanup = fixture.finish().await;
        result.and(cleanup)
    })
    .await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OriginalFd {
    fd: u32,
    device: u64,
    inode: u64,
}
#[derive(Default)]
struct FileFields {
    fd: Option<u32>,
    device: Option<u64>,
    inode: Option<u64>,
}
fn parse_fields(raw: &[u8]) -> Result<Vec<FileFields>, String> {
    require(
        !raw.is_empty() && raw.last() == Some(&b'\n') && raw.is_ascii(),
        "fd_oracle_incomplete_ascii_output",
    )?;
    let text = std::str::from_utf8(raw).map_err(|_| "fd_oracle_invalid_utf8")?;
    let mut process = None;
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    let mut current: Option<FileFields> = None;
    for line in text.lines() {
        require(
            !line.is_empty() && line.len() <= 1024,
            "fd_oracle_field_boundary_failed",
        )?;
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                require(
                    process.is_none() && current.is_none(),
                    "fd_oracle_duplicate_process",
                )?;
                require(
                    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                    "fd_oracle_process_encoding",
                )?;
                let pid = value
                    .parse::<u32>()
                    .map_err(|_| "fd_oracle_process_encoding")?;
                require(pid == std::process::id(), "fd_oracle_other_pid")?;
                process = Some(pid);
            }
            "f" => {
                require(process.is_some(), "fd_oracle_file_before_process")?;
                if let Some(file) = current.take() {
                    files.push(file);
                }
                let numeric = value
                    .strip_suffix('r')
                    .or_else(|| value.strip_suffix('w'))
                    .or_else(|| value.strip_suffix('u'))
                    .unwrap_or(value);
                let fd = if !numeric.is_empty() && numeric.bytes().all(|b| b.is_ascii_digit()) {
                    require(
                        value.len() - numeric.len() <= 1,
                        "fd_oracle_bad_access_suffix",
                    )?;
                    let fd = numeric
                        .parse::<u32>()
                        .map_err(|_| "fd_oracle_descriptor_encoding")?;
                    require(seen.insert(fd), "fd_oracle_duplicate_numeric_fd")?;
                    Some(fd)
                } else {
                    require(
                        matches!(value, "cwd" | "rtd" | "txt" | "mem" | "DEL" | "PD"),
                        "fd_oracle_descriptor_kind",
                    )?;
                    None
                };
                current = Some(FileFields {
                    fd,
                    ..FileFields::default()
                });
            }
            "D" => {
                let file = current.as_mut().ok_or("fd_oracle_unattached_device")?;
                require(file.device.is_none(), "fd_oracle_duplicate_device")?;
                let device = if let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    require(
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()),
                        "fd_oracle_device_encoding",
                    )?;
                    u64::from_str_radix(hex, 16).map_err(|_| "fd_oracle_device_encoding")?
                } else {
                    require(
                        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                        "fd_oracle_device_encoding",
                    )?;
                    value
                        .parse::<u64>()
                        .map_err(|_| "fd_oracle_device_encoding")?
                };
                if cfg!(target_os = "macos") {
                    require(device <= u32::MAX.into(), "fd_oracle_device_overflow")?;
                }
                file.device = Some(device);
            }
            "i" => {
                let file = current.as_mut().ok_or("fd_oracle_unattached_inode")?;
                require(file.inode.is_none(), "fd_oracle_duplicate_inode")?;
                require(
                    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                    "fd_oracle_inode_encoding",
                )?;
                file.inode = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "fd_oracle_inode_encoding")?,
                );
            }
            _ => return Err("fd_oracle_unrequested_field".into()),
        }
    }
    if let Some(file) = current {
        files.push(file);
    }
    require(
        process == Some(std::process::id()) && !files.is_empty(),
        "fd_oracle_missing_inventory",
    )?;
    Ok(files)
}
struct OwnedFdOracleChild {
    child: Child,
    reaped: bool,
}
impl OwnedFdOracleChild {
    fn try_status(&mut self) -> Result<Option<ExitStatus>, &'static str> {
        let status = self
            .child
            .try_wait()
            .map_err(|_| "owned_fd_oracle_wait_failed")?;
        self.reaped = status.is_some();
        Ok(status)
    }
}
impl Drop for OwnedFdOracleChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Cancellation drops this owner too. Kill targets only its original child;
        // actual wait/reap, rather than JoinHandle or pipe Drop, ends child ownership.
        let kill_ack = self.child.kill().is_ok();
        let reap_ack = self.child.wait().is_ok();
        self.reaped = reap_ack;
        if !reap_ack {
            eprintln!("OWNED_FD_ORACLE_CHILD_CLEANUP kill_ack={kill_ack} reap_ack={reap_ack}");
            if !std::thread::panicking() {
                panic!("owned_fd_oracle_child_reap_failed");
            }
        }
    }
}
struct FdOracleObserverCancellation {
    stopped: Arc<AtomicBool>,
    completed: bool,
}
impl Drop for FdOracleObserverCancellation {
    fn drop(&mut self) {
        if !self.completed {
            // Observer cancellation requests stop. The blocking worker retains its
            // original Child until actual kill/reap; observer Drop is no end ACK.
            self.stopped.store(true, Ordering::SeqCst);
        }
    }
}
fn oracle_pipe_nonblocking(pipe: &impl std::os::fd::AsFd) -> Result<(), &'static str> {
    let flags = rustix::fs::fcntl_getfl(pipe).map_err(|_| "owned_fd_oracle_nonblocking_failed")?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| "owned_fd_oracle_nonblocking_failed")
}
fn read_oracle_pipe(
    pipe: &mut impl std::io::Read,
    bytes: &mut Vec<u8>,
    limit: usize,
    eof: &mut bool,
    failure: &'static str,
) -> Result<(), &'static str> {
    if *eof {
        return Ok(());
    }
    let remaining = limit
        .checked_sub(bytes.len())
        .ok_or("owned_fd_oracle_capture_overflow")?;
    let mut chunk = [0; 4096];
    // At the limit, one bounded byte distinguishes overflow from real EOF. It is
    // never appended, so the retained stdout/stderr captures stay within limits.
    let take = (remaining + 1).min(chunk.len());
    match pipe.read(&mut chunk[..take]) {
        Ok(0) => *eof = true,
        Ok(read) => {
            if read > remaining {
                return Err("owned_fd_oracle_capture_overflow");
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) => {}
        Err(_) => return Err(failure),
    }
    Ok(())
}
fn fd_sample_blocking(
    submitted: Instant,
    deadline: Instant,
    stopped: &AtomicBool,
) -> Result<Vec<FileFields>, String> {
    if stopped.load(Ordering::SeqCst) {
        return Err("owned_fd_oracle_observer_cancelled".into());
    }
    if Instant::now() >= deadline {
        return Err("owned_fd_oracle_absolute_deadline".into());
    }
    let tool = Path::new("/usr/sbin/lsof");
    let metadata = fs::metadata(tool).map_err(|_| "owned_fd_oracle_tool_unavailable")?;
    require(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "owned_fd_oracle_tool_identity",
    )?;
    if stopped.load(Ordering::SeqCst) {
        return Err("owned_fd_oracle_observer_cancelled".into());
    }
    if Instant::now() >= deadline {
        return Err("owned_fd_oracle_absolute_deadline".into());
    }
    let child = Command::new(tool)
        .args(["-nP", "-a", "-p", &std::process::id().to_string(), "-FfDi"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "owned_fd_oracle_spawn_failed")?;
    // Establish custody before any fallible pipe setup or await.
    let mut owned = OwnedFdOracleChild {
        child,
        reaped: false,
    };
    let mut stdout = owned
        .child
        .stdout
        .take()
        .ok_or("owned_fd_oracle_stdout_missing")?;
    let mut stderr = owned
        .child
        .stderr
        .take()
        .ok_or("owned_fd_oracle_stderr_missing")?;
    oracle_pipe_nonblocking(&stdout)?;
    oracle_pipe_nonblocking(&stderr)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    let mut completed_polls = 0_u32;
    let sampling = (|| {
        loop {
            if stopped.load(Ordering::SeqCst) {
                return Err("owned_fd_oracle_observer_cancelled");
            }
            if Instant::now() >= deadline {
                return Err("owned_fd_oracle_absolute_deadline");
            }
            read_oracle_pipe(
                &mut stdout,
                &mut stdout_bytes,
                64 * 1024,
                &mut stdout_eof,
                "owned_fd_oracle_stdout_failed",
            )?;
            read_oracle_pipe(
                &mut stderr,
                &mut stderr_bytes,
                8 * 1024,
                &mut stderr_eof,
                "owned_fd_oracle_stderr_failed",
            )?;
            if status.is_none() {
                status = owned.try_status()?;
            }
            completed_polls = completed_polls.saturating_add(1);
            if stopped.load(Ordering::SeqCst) {
                return Err("owned_fd_oracle_observer_cancelled");
            }
            if Instant::now() >= deadline {
                return Err("owned_fd_oracle_absolute_deadline");
            }
            if stdout_eof && stderr_eof && status.is_some() {
                break;
            }
            std::thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        Ok::<_, &'static str>(())
    })();
    if let Err(reason) = sampling {
        // These are bounded owned-buffer/child progress facts, never FD paths
        // or raw captures. False EOF ACK means ACK not obtained; None exit
        // status means not observed, never a proved negative process state.
        eprintln!(
            "OWNED_FD_ORACLE_FAILURE reason={reason} child_pid={} completed_polls={completed_polls} captured_stdout_bytes={} captured_stderr_bytes={} stdout_eof_ack={stdout_eof} stderr_eof_ack={stderr_eof} observed_exit_success={:?} elapsed_ms={}",
            owned.child.id(),
            stdout_bytes.len(),
            stderr_bytes.len(),
            status.map(|value: ExitStatus| value.success()),
            submitted.elapsed().as_millis(),
        );
        return Err(reason.into());
    }
    require(
        stdout_bytes.len() <= 64 * 1024 && stderr_bytes.len() <= 8 * 1024,
        "owned_fd_oracle_capture_overflow",
    )?;
    require(
        status.ok_or("owned_fd_oracle_wait_failed")?.success() && stderr_bytes.is_empty(),
        "owned_fd_oracle_exit_or_warning",
    )?;
    parse_fields(&stdout_bytes)
}
async fn fd_sample() -> Result<Vec<FileFields>, String> {
    let submitted = Instant::now();
    let deadline = submitted + Duration::from_secs(5);
    let stopped = Arc::new(AtomicBool::new(false));
    let mut observer = FdOracleObserverCancellation {
        stopped: Arc::clone(&stopped),
        completed: false,
    };
    let result =
        tokio::task::spawn_blocking(move || fd_sample_blocking(submitted, deadline, &stopped))
            .await
            .map_err(|_| "owned_fd_oracle_worker_join_failed")?;
    observer.completed = true; // The real worker has returned, not merely detached.
    result
}
fn device(metadata: &fs::Metadata) -> u64 {
    if cfg!(target_os = "macos") {
        metadata.dev() & u64::from(u32::MAX)
    } else {
        metadata.dev()
    }
}
async fn original_fd(
    metadata: &fs::Metadata,
    expected: Option<OriginalFd>,
    present: bool,
) -> Result<Option<OriginalFd>, String> {
    require(
        metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o7777 == 0o400,
        "owned_artifact_tuple_not_regular0400",
    )?;
    let mut stable = None;
    for _ in 0..2 {
        let matches = fd_sample()
            .await?
            .into_iter()
            .filter(|file| {
                file.fd.is_some()
                    && file.device == Some(device(metadata))
                    && file.inode == Some(metadata.ino())
            })
            .map(|file| OriginalFd {
                fd: file.fd.unwrap(),
                device: file.device.unwrap(),
                inode: file.inode.unwrap(),
            })
            .collect::<Vec<_>>();
        require(
            matches.len() == usize::from(present),
            "original_fd_tuple_presence_not_proven",
        )?;
        let sample = matches.first().copied();
        if let Some(expected) = expected
            && present
        {
            require(
                sample == Some(expected),
                "original_numeric_fd_reopened_or_replaced",
            )?;
        }
        if let Some(before) = stable {
            require(before == sample, "original_fd_two_samples_not_stable")?;
        }
        stable = Some(sample);
    }
    Ok(stable.flatten())
}

struct PhaseGate {
    selected: &'static str,
    reached: AtomicBool,
    timed_out: AtomicBool,
    release: Mutex<bool>,
    changed: Condvar,
    notified: tokio::sync::Notify,
    partial: AtomicUsize,
    io: AtomicUsize,
}
impl PhaseGate {
    fn new(selected: &'static str) -> Arc<Self> {
        Arc::new(Self {
            selected,
            reached: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            release: Mutex::new(false),
            changed: Condvar::new(),
            notified: tokio::sync::Notify::new(),
            partial: AtomicUsize::new(0),
            io: AtomicUsize::new(0),
        })
    }
    fn release(&self) {
        *self.release.lock().unwrap() = true;
        self.changed.notify_all();
    }
    fn observe(&self, value: &str) {
        if value == PARTIAL {
            self.partial.fetch_add(1, Ordering::SeqCst);
        }
        if value == "actual_io_completed_before_joint" {
            self.io.fetch_add(1, Ordering::SeqCst);
        }
        // R432 control-before emits the same joint phase before any body IO; the selected
        // FinalJoint is the one that follows this operation's actual IO.
        if value == JOINT && self.io.load(Ordering::SeqCst) == 0 {
            return;
        }
        if value != self.selected || self.reached.swap(true, Ordering::SeqCst) {
            return;
        }
        self.notified.notify_waiters();
        let deadline = Instant::now() + Duration::from_secs(5);
        if self.selected == JOINT {
            tokio::task::block_in_place(|| self.wait_until_released(deadline));
        } else {
            self.wait_until_released(deadline);
        }
    }
    fn wait_until_released(&self, deadline: Instant) {
        let mut released = self.release.lock().unwrap();
        while !*released {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.timed_out.store(true, Ordering::SeqCst);
                break;
            }
            let (guard, timeout) = self.changed.wait_timeout(released, remaining).unwrap();
            released = guard;
            if timeout.timed_out() && !*released {
                self.timed_out.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}
struct ReleaseOnDrop(Arc<PhaseGate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct Subscriber(Arc<PhaseGate>);
impl tracing::Subscriber for Subscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor<'a>(&'a PhaseGate);
        impl tracing::field::Visit for Visitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "artifact_read_lifecycle_phase"
                    || field.name() == "artifact_read_phase"
                {
                    self.0.observe(value);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        event.record(&mut Visitor(&self.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }
}

async fn cancel_actual_phase(
    fixture: &Fixture,
    receipt: &ArtifactRegistrationReceipt,
    phase: &'static str,
) -> Result<(), String> {
    let mut operation = fixture.open(receipt).await?;
    let gate = PhaseGate::new(phase);
    let release = ReleaseOnDrop(gate.clone());
    let dispatcher = tracing::Dispatch::new(Subscriber(gate.clone()));
    let mut waiter = Box::pin(
        operation
            .next_block(&fixture.auth)
            .with_subscriber(dispatcher),
    );
    let actual_phase = async {
        loop {
            let notified = gate.notified.notified();
            if gate.reached.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    };
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(5)) => return Err("actual_production_phase_not_observed".into()),
        _ = actual_phase => {},
        _ = &mut waiter => return Err("actual_operation_ended_before_selected_phase".into()),
    }
    require(
        !gate.timed_out.load(Ordering::SeqCst),
        "actual_phase_gate_deadline_elapsed",
    )?;
    let physical =
        fs::symlink_metadata(fixture.object(receipt)).map_err(|_| "owned_artifact_stat_failed")?;
    let fd = original_fd(&physical, None, true)
        .await?
        .ok_or("original_worker_fd_missing")?;
    let counters = (
        gate.partial.load(Ordering::SeqCst),
        gate.io.load(Ordering::SeqCst),
        fixture.final_calls.load(Ordering::SeqCst),
    );
    drop(waiter); // The real borrowed operation future is cancelled, not a Rust borrow check.
    require(
        matches!(operation.next_block(&fixture.auth).await, Err(ref e) if unavailable(e)),
        "cancelled_original_operation_reentered",
    )?;
    // R432/§3679: a cancelled FinalJoint leaves its exact key closed, so the denied next still
    // makes one no-body RequestedTarget host-first classification. A cancelled Working phase
    // keeps body admission and is refused by its own operation lifecycle without a statement.
    let classified = usize::from(phase == JOINT);
    require(
        (counters.0, counters.1, counters.2 + classified)
            == (
                gate.partial.load(Ordering::SeqCst),
                gate.io.load(Ordering::SeqCst),
                fixture.final_calls.load(Ordering::SeqCst),
            ),
        "denied_next_started_new_worker_or_joint",
    )?;
    original_fd(&physical, Some(fd), true).await?;
    let lifecycle = fixture.administration.read_authority().read_lifecycle();
    lifecycle.close();
    require(
        lifecycle
            .drain_before(Instant::now() + Duration::from_millis(30))
            .await
            .is_err(),
        "worker_or_final_collector_false_drain_ack",
    )?;
    drop(release);
    lifecycle
        .drain_before(Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|_| "actual_cancelled_collector_did_not_end")?;
    original_fd(&physical, Some(fd), false).await?;
    require(
        !gate.timed_out.load(Ordering::SeqCst),
        "phase_gate_timed_out_instead_of_actual_release",
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn retained_original_fd_sequential_sizes_and_verified_eof() {
    with_fixture("lifecycle_sizes", |fixture| async move {
        // Facts 1-4 are real saved nonempty sources, not fabricated available records.
        for length in [
            1,
            MAX_ARTIFACT_READ_CHUNK_BYTES,
            MAX_ARTIFACT_READ_CHUNK_BYTES + 1,
            64 * 1024 * 1024,
        ] {
            let (payload, receipt) = fixture.save_length(length).await?;
            let physical = fs::symlink_metadata(fixture.object(&receipt))
                .map_err(|_| "owned_artifact_stat_failed")?;
            original_fd(&physical, None, false).await?;
            let mut operation = fixture.open(&receipt).await?;
            let mut position = 0;
            let mut retained = None;
            let before = fixture.final_calls.load(Ordering::SeqCst);
            let mut blocks = 0;
            loop {
                let current = operation
                    .next_block(&fixture.auth)
                    .await
                    .map_err(|_| "actual_sequential_block_failed")?;
                retained = original_fd(&physical, retained, true).await?;
                let Some(block) = current
                    .handoff(&fixture.auth)
                    .map_err(|_| "actual_sequential_handoff_failed")?
                else {
                    break;
                };
                require(
                    block.len() <= MAX_ARTIFACT_READ_CHUNK_BYTES && !block.is_empty(),
                    "actual_chunk_limit_or_empty_handoff",
                )?;
                let end = position + block.len();
                require(
                    block.as_bytes() == &payload.as_bytes()[position..end],
                    "actual_original_stream_order_changed",
                )?;
                position = end;
                blocks += 1;
                drop(block);
                original_fd(&physical, retained, true).await?;
            }
            // Fact 5: zero is an actual read on the original nonempty saved FD, with final joint
            // and handoff completed. EOF closes it; a subsequent next cannot reopen it.
            require(position == length, "actual_stream_length_changed")?;
            // Each admitted block, including the verified EOF, runs its R432 control-before and
            // then its final joint through the same original guard.
            require(
                fixture.final_calls.load(Ordering::SeqCst) == before + 2 * (blocks + 1),
                "verified_eof_missing_actual_joint",
            )?;
            original_fd(&physical, retained, false).await?;
            let final_count = fixture.final_calls.load(Ordering::SeqCst);
            require(
                matches!(operation.next_block(&fixture.auth).await, Err(ref e) if unavailable(e)),
                "verified_eof_operation_reopened",
            )?;
            require(
                fixture.final_calls.load(Ordering::SeqCst) == final_count,
                "next_after_eof_started_another_joint",
            )?;
            original_fd(&physical, retained, false).await?;
        }
        Ok(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn original_allocation_owner_prevents_next_worker_joint_and_buffer() {
    // Facts 1-2 cancel real accepted Working/FinalJoint futures and deny their next entry.
    for (tag, phase) in [("lifecycle_working", PARTIAL), ("lifecycle_final", JOINT)] {
        with_fixture(tag, move |fixture| async move {
            let (_, receipt) = fixture
                .save_length(MAX_ARTIFACT_READ_CHUNK_BYTES + 1)
                .await?;
            cancel_actual_phase(&fixture, &receipt, phase).await
        })
        .await;
    }
    // Facts 3-4 retain the actual Pending and then original-allocation Leased owners.
    with_fixture("lifecycle_lease", |fixture| async move {
        let (payload, receipt) = fixture
            .save_length(MAX_ARTIFACT_READ_CHUNK_BYTES + 1)
            .await?;
        let physical = fs::symlink_metadata(fixture.object(&receipt))
            .map_err(|_| "owned_artifact_stat_failed")?;
        let mut operation = fixture.open(&receipt).await?;
        let pending = operation
            .next_block(&fixture.auth)
            .await
            .map_err(|_| "actual_pending_read_failed")?;
        let retained = original_fd(&physical, None, true)
            .await?
            .ok_or("actual_pending_fd_missing")?;
        let before = fixture.final_calls.load(Ordering::SeqCst);
        require(
            matches!(operation.next_block(&fixture.auth).await, Err(ref e) if unavailable(e)),
            "pending_owner_admitted_next",
        )?;
        require(
            fixture.final_calls.load(Ordering::SeqCst) == before,
            "pending_busy_started_another_joint",
        )?;
        original_fd(&physical, Some(retained), true).await?;
        let leased = pending
            .handoff(&fixture.auth)
            .map_err(|_| "actual_lease_handoff_failed")?
            .ok_or("actual_first_block_was_eof")?;
        let original_allocation_prefix = leased.as_bytes().as_ptr();
        require(
            leased.len() == MAX_ARTIFACT_READ_CHUNK_BYTES
                && leased.as_bytes() == &payload.as_bytes()[..MAX_ARTIFACT_READ_CHUNK_BYTES],
            "actual_original_lease_prefix_changed",
        )?;
        require(
            matches!(operation.next_block(&fixture.auth).await, Err(ref e) if unavailable(e)),
            "leased_allocation_admitted_next",
        )?;
        require(
            leased.as_bytes().as_ptr() == original_allocation_prefix
                && fixture.final_calls.load(Ordering::SeqCst) == before,
            "leased_busy_started_joint_or_replaced_original_allocation",
        )?;
        original_fd(&physical, Some(retained), true).await?;
        drop(leased); // The original full allocation ends before the real next slot opens.
        let second = operation
            .next_block(&fixture.auth)
            .await
            .map_err(|_| "lease_drop_did_not_release_next_slot")?
            .handoff(&fixture.auth)
            .map_err(|_| "actual_second_handoff_failed")?
            .ok_or("actual_second_block_was_eof")?;
        // The busy refusals above keep body admission and make no statement; the admitted
        // second block runs its R432 control-before and then its final joint.
        require(
            second.as_bytes() == b"L" && fixture.final_calls.load(Ordering::SeqCst) == before + 2,
            "actual_second_sequential_block_changed",
        )?;
        original_fd(&physical, Some(retained), true).await?;
        drop(second);
        require(
            operation
                .next_block(&fixture.auth)
                .await
                .map_err(|_| "actual_eof_read_failed")?
                .handoff(&fixture.auth)
                .map_err(|_| "actual_eof_handoff_failed")?
                .is_none(),
            "actual_eof_not_verified",
        )?;
        original_fd(&physical, Some(retained), false).await?;
        Ok(())
    })
    .await;
}

fn mutate_original_file(path: &Path) -> Result<(), String> {
    let original = fs::symlink_metadata(path).map_err(|_| "owned_mutation_stat_failed")?;
    require(
        original.is_file() && original.nlink() == 1 && original.mode() & 0o7777 == 0o400,
        "owned_mutation_requires_original0400",
    )?;
    let anchor = File::open(path).map_err(|_| "owned_mutation_anchor_failed")?;
    let mut before = [0];
    (&anchor)
        .read_exact(&mut before)
        .map_err(|_| "owned_mutation_original_byte_failed")?;
    require(
        before != *b"X",
        "owned_mutation_original_byte_already_changed",
    )?;
    struct Restore<'a>(&'a File);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = self.0.set_permissions(Permissions::from_mode(0o400));
            let _ = self.0.sync_all();
        }
    }
    let restore = Restore(&anchor);
    anchor
        .set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| "owned_mutation_writable_mode_failed")?;
    let mut writer = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| "owned_mutation_writer_failed")?;
    let current = writer
        .metadata()
        .map_err(|_| "owned_mutation_writer_stat_failed")?;
    require(
        current.dev() == original.dev() && current.ino() == original.ino(),
        "owned_mutation_different_inode",
    )?;
    let mutation = (|| {
        writer
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| "owned_mutation_seek_failed")?;
        writer
            .write_all(b"X")
            .map_err(|_| "owned_mutation_write_failed")?;
        writer.sync_all().map_err(|_| "owned_mutation_sync_failed")
    })();
    drop(writer);
    anchor
        .set_permissions(Permissions::from_mode(0o400))
        .map_err(|_| "owned_mutation_restore_mode_failed")?;
    anchor
        .sync_all()
        .map_err(|_| "owned_mutation_restore_sync_failed")?;
    drop(restore);
    mutation?;
    let changed = fs::symlink_metadata(path).map_err(|_| "owned_mutation_final_stat_failed")?;
    require(
        changed.dev() == original.dev()
            && changed.ino() == original.ino()
            && changed.mode() & 0o7777 == 0o400
            && changed.len() == original.len()
            && (changed.mtime() != original.mtime()
                || changed.mtime_nsec() != original.mtime_nsec()
                || changed.ctime() != original.ctime()
                || changed.ctime_nsec() != original.ctime_nsec()),
        "owned_original_fd_metadata_drift_not_real",
    )?;
    (&anchor)
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|_| "owned_mutation_observation_seek_failed")?;
    let mut after = [0];
    (&anchor)
        .read_exact(&mut after)
        .map_err(|_| "owned_mutation_actual_byte_failed")?;
    require(
        after == *b"X" && before != after,
        "owned_mutation_exact_real_byte_drift_not_observed",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn second_block_physical_root_marker_or_original_fd_drift_is_terminal() {
    // Three owned submatrices; every one starts with a successful actual first lease.
    for kind in ["original_fd", "root", "marker"] {
        with_fixture(&format!("lifecycle_drift_{kind}"), move |fixture| async move {
            let (_, receipt) = fixture.save_length(MAX_ARTIFACT_READ_CHUNK_BYTES + 1).await?;
            let physical = fs::symlink_metadata(fixture.object(&receipt)).map_err(|_| "owned_artifact_stat_failed")?;
            let mut operation = fixture.open(&receipt).await?;
            let first = operation.next_block(&fixture.auth).await.map_err(|_| "actual_first_read_failed")?
                .handoff(&fixture.auth).map_err(|_| "actual_first_handoff_failed")?.ok_or("actual_first_was_eof")?;
            let retained = original_fd(&physical, None, true).await?.ok_or("actual_first_fd_missing")?;
            drop(first);
            match kind {
                "original_fd" => mutate_original_file(&fixture.object(&receipt))?,
                "root" => fs::set_permissions(&fixture.root.0, Permissions::from_mode(0o755)).map_err(|_| "owned_root_drift_failed")?,
                "marker" => mutate_original_file(&fixture.root.0.join(".artifact-store-v1"))?,
                _ => unreachable!(),
            }
            let result = operation.next_block(&fixture.auth).await;
            if kind == "root" { fs::set_permissions(&fixture.root.0, Permissions::from_mode(0o700)).map_err(|_| "owned_root_restore_failed")?; }
            require(matches!(result, Err(ref e) if unavailable(e)), "physical_drift_released_a_second_body")?;
            original_fd(&physical, Some(retained), false).await?;
            let before = fixture.final_calls.load(Ordering::SeqCst);
            require(matches!(operation.next_block(&fixture.auth).await, Err(ref e) if unavailable(e)), "failed_physical_operation_reopened")?;
            require(fixture.final_calls.load(Ordering::SeqCst) == before, "terminal_physical_failure_started_another_joint")?;
            original_fd(&physical, Some(retained), false).await?;
            Ok(())
        }).await;
    }
}
