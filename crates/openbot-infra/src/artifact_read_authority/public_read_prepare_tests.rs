//! Actual owned-PG/save/FD preparation and original blocking-job closure.
//! The issuer is a trusted test seam over real Session rows; real host acceptance is separate.
//! Short original deadlines below test real monotonic expiry, not a full600s elapsed claim.

use std::fs::{self, File};
use std::future::Future;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::db::pool::DatabasePool as Pool;
use openbot_application::artifact_read_protocol::{
    ArtifactReadOperationCompletion, ArtifactReadPreparationObserver,
};
use openbot_application::{ArtifactAdministration, BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::{
    ArtifactReadCurrentError, ArtifactReadCurrentTarget, ArtifactReadTailWitness,
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind, RequestBindingIssuer,
    RequestBindingOwnerLease, ServerSessionBindingIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::SessionLifetimePolicy;
use openbot_domain::vault::SecretBytes;
use time::OffsetDateTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use super::super::{CurrentHost, decode_host};
use super::{PostgresArtifactReadAuthority, PublicPrepareProbe, ReadOperationState};
use crate::artifact_administration::PostgresArtifactAdministration;
use crate::artifact_read_lifecycle::ReadPhase;
use crate::artifact_registry::ArtifactDatasetRegistry;
use crate::artifact_store::DatasetBoundArtifactStore;
use crate::db::pool::DatabaseConfig;
use crate::db::{baseline, native, pool};
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

mod harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}

const DEPLOYMENT: &str = "artifact-read-owned-deployment";
const TENANT: &str = "artifact-read-owned-tenant";
const ACTOR: &str = "public-read-owner";

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct OwnedRoot {
    path: PathBuf,
    cleanup_after_completed_scenario: bool,
}
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!("openbot-public-read-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            path: fs::canonicalize(root).map_err(|e| e.to_string())?,
            cleanup_after_completed_scenario: false,
        })
    }
    fn allow_cleanup_after_actual_completions(&mut self) {
        self.cleanup_after_completed_scenario = true;
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        // An error can leave the original worker, collector, FD or carrier unproved.
        // Releasing its hold or canceling its waiter is not a completion ACK.
        if !self.cleanup_after_completed_scenario || std::thread::panicking() {
            eprintln!(
                "PUBLIC_ARTIFACT_READ_OWN_ROOT_KEEP completed_scenario={} panicking={} root={:?}",
                self.cleanup_after_completed_scenario,
                std::thread::panicking(),
                self.path
            );
            return;
        }
        let removed = fs::remove_dir_all(&self.path).is_ok();
        let absent = !self.path.exists();
        eprintln!("PUBLIC_ARTIFACT_READ_OWN_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(
                removed && absent,
                "owned public-read fixture root cleanup failed"
            );
        }
    }
}

#[derive(Default)]
struct Observer {
    completion: Mutex<Option<Arc<dyn ArtifactReadOperationCompletion>>>,
    reject: bool,
}
impl Observer {
    fn actual(&self) -> Result<Arc<dyn ArtifactReadOperationCompletion>, String> {
        self.completion
            .lock()
            .map_err(|_| "observer poisoned".to_owned())?
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| "actual State not enrolled".to_owned())
    }
}
impl ArtifactReadPreparationObserver for Observer {
    fn enrolled(
        &self,
        completion: Arc<dyn ArtifactReadOperationCompletion>,
    ) -> Result<(), AppError> {
        let mut original = self
            .completion
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?;
        if original.is_some() {
            return Err(AppError::DependencyUnavailable {
                dependency: "artifacts",
            });
        }
        *original = Some(completion);
        if self.reject {
            Err(AppError::DependencyUnavailable {
                dependency: "artifacts",
            })
        } else {
            Ok(())
        }
    }
}

struct Fixture {
    pool: Pool,
    administration: Arc<PostgresArtifactAdministration>,
    authority: Arc<PostgresArtifactReadAuthority>,
    auth: AuthContext,
    _lease: RequestBindingOwnerLease,
    begin: BeginThreadRunRequest,
    source: String,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation,groups)
                VALUES('public-read-owner','public-read-owner@example.test',0,ARRAY['public-read']);
                INSERT INTO public.user_roles(user_id,role) VALUES('public-read-owner','user');
                INSERT INTO public.agents(id,name,type,configuration)
                VALUES('public-read-bot','Public read fixture','built_in','{}');
                INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('public-read-bot','public-read-owner','Read fixture','fixture','fixture','public');
                INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000071','artifact-read-owned-tenant','fixture','fixture');")
                .await.map_err(|e| e.to_string())?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment,
            tenant,
            actor: ActorId::new(ACTOR),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT))
                    .mint_from_entropy([17; 16]),
                run_id: RunId::new("public-read/source%成果"),
                bot_id: BotId::new("public-read-bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned public-read source".to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "public-read-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let source = format!("{}  原始尾 café 🦀\n", "p".repeat(4 * 1024 * 1024 + 113));
        let message = format!("{}:input", begin.command.run_id.as_str());
        let changed = pool.get().await.map_err(|e| e.to_string())?
            .execute("UPDATE public.messages SET content=jsonb_build_object('text',$1::text) WHERE message_id=$2",
                &[&source, &message]).await.map_err(|e| e.to_string())?;
        require(
            changed == 1,
            "real original user message changed exactly once",
        )?;
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.path).map_err(|e| e.to_string())?,
                registry.clone(),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                registry,
                store,
                policy,
                SecretBytes::new(vec![0x94; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let authority = administration.read_authority();
        let created = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let expires = created + time::Duration::hours(1);
        pool.get().await.map_err(|e| e.to_string())?.execute(
            "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation)
                VALUES('public-read-session-a',$1,'owned-public-read-session-column-a',$2,$2,$3,0)",
            &[&ACTOR,&created,&expires]).await.map_err(|e| e.to_string())?;
        let created: OffsetDateTime = pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT created_at FROM public.sessions WHERE id='public-read-session-a'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let (_lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let auth = AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            ActorId::new(ACTOR),
            AuthGeneration::new(0),
            false,
        )
        .with_role(Role::User)
        .build();
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            "public-read-session-a".into(),
            auth.actor().clone(),
            "owned-public-read-session-column-a".into(),
            created,
            auth.auth_generation(),
        );
        let guard = Arc::new(SessionGuard {
            authority: Arc::downgrade(&authority),
            issuer: issuer.clone(),
        });
        let binding = issuer
            .bind_server_session(&auth, epoch, guard)
            .map_err(|_| "trusted original epoch rejected".to_owned())?;
        let auth = auth
            .with_verified_request_binding(binding)
            .map_err(|_| "trusted original binding rejected".to_owned())?;
        Ok(Self {
            pool,
            administration,
            authority,
            auth,
            _lease,
            begin,
            source,
            root,
        })
    }
    async fn save(&self) -> Result<ArtifactRegistrationReceipt, String> {
        self.administration
            .save_run_message_text(
                &self.auth,
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: format!("{}:input", self.begin.command.run_id.as_str()),
                    expected_sha256: Sha256Digest::of(self.source.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|e| e.to_string())
    }
    fn install_probe(&self, probe: Arc<PublicPrepareProbe>) -> Result<(), String> {
        let mut slot = self
            .authority
            .public_prepare_probe
            .lock()
            .map_err(|_| "probe slot poisoned".to_owned())?;
        require(slot.is_none(), "probe belongs to one original prepare")?;
        *slot = Some(probe);
        Ok(())
    }
    fn state(probe: &PublicPrepareProbe) -> Result<Arc<ReadOperationState>, String> {
        probe
            .state
            .lock()
            .map_err(|_| "probe State poisoned".to_owned())?
            .upgrade()
            .ok_or_else(|| "original State ended before observation".to_owned())
    }
    async fn wait_collector_tail(state: &ReadOperationState) -> Result<(), String> {
        // Sending the first result can wake prepare before the original permit Drop runs.
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.actual_jobs() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .map_err(|_| "original collector permit did not actually end".to_owned())
    }
}

struct SessionGuard {
    authority: Weak<PostgresArtifactReadAuthority>,
    issuer: RequestBindingIssuer,
}

struct CleanupOriginalObserver {
    downstream: Arc<dyn ArtifactReadPreparationObserver>,
    original: Arc<Observer>,
}
impl ArtifactReadPreparationObserver for CleanupOriginalObserver {
    fn original_entry_stop(
        &self,
    ) -> Option<Arc<dyn openbot_application::artifact_read_protocol::ArtifactReadEntryStop>> {
        self.downstream.original_entry_stop()
    }
    fn enrolled(
        &self,
        completion: Arc<dyn ArtifactReadOperationCompletion>,
    ) -> Result<(), AppError> {
        self.downstream.enrolled(Arc::clone(&completion))?;
        self.original.enrolled(completion)
    }
}
struct CleanupObservedAdministration {
    actual: Arc<PostgresArtifactAdministration>,
    original: Arc<Observer>,
}
#[async_trait::async_trait]
impl ArtifactAdministration for CleanupObservedAdministration {
    async fn prepare_host_bound_artifact_read(
        &self,
        auth: &AuthContext,
        id: &str,
        deadline: Instant,
        observer: Arc<dyn ArtifactReadPreparationObserver>,
    ) -> Result<openbot_application::artifact_read_protocol::PreparedArtifactRead, AppError> {
        self.actual
            .prepare_host_bound_artifact_read(
                auth,
                id,
                deadline,
                Arc::new(CleanupOriginalObserver {
                    downstream: observer,
                    original: Arc::clone(&self.original),
                }),
            )
            .await
    }
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, openbot_application::ArtifactAdministrationError> {
        self.actual.save_run_message_text(auth, input).await
    }
    async fn get_metadata(
        &self,
        auth: &AuthContext,
        id: &str,
    ) -> Result<
        openbot_contracts::artifacts::ArtifactMetadata,
        openbot_application::ArtifactAdministrationError,
    > {
        self.actual.get_metadata(auth, id).await
    }
}

async fn cleanup_prepare_facts(f: &Fixture) -> Result<serde_json::Value, String> {
    let client = f.pool.get().await.map_err(|error| error.to_string())?;
    client.query_one(
        "SELECT jsonb_build_object( \
         'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
         'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
         'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
         'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
         'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
         'fences',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_cleanup_fences q), \
         'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))", &[],
    ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
}

async fn arm_cleanup_prepare_fixture(f: &Fixture, id: &str) -> Result<(), String> {
    let changed = f.pool.get().await.map_err(|error| error.to_string())?.execute(
        "INSERT INTO openbot_internal.artifact_cleanup_fences \
         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
         SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,'deleted','armed' \
         FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND artifact_id=$3",
        &[&DEPLOYMENT, &TENANT, &id],
    ).await.map_err(|error| error.to_string())?;
    require(
        changed == 1,
        "controlled fence was not on exactly the original actual Save row",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, real prepared/cache first and original IO/completion evidence"]
async fn public_prepare_cleanup_fence_refusal_keeps_original_io_accounting() {
    use openbot_application::ApplicationService as _;
    use openbot_contracts::artifact_read_protocol::{OpenArtifactRead, ReadArtifactReadBlock};
    use openbot_contracts::command::{AppCommand, AppReply};

    for initially_armed in [true, false] {
        let tag = if initially_armed {
            "cleanup_prepare_initial"
        } else {
            "cleanup_prepare_cached_first"
        };
        harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
            let mut f = Fixture::new(config).await?;
            let saved = f.save().await?;
            let probe = PublicPrepareProbe::new();
            f.install_probe(Arc::clone(&probe))?;
            let original = Arc::new(Observer::default());
            let application = openbot_application::OpenBotApplication::new(
                crate::repo::channels::ChannelRepo::new(f.pool.clone()),
            ).with_artifacts(Arc::new(CleanupObservedAdministration {
                actual: Arc::clone(&f.administration), original: Arc::clone(&original),
            }));
            if initially_armed { arm_cleanup_prepare_fixture(&f, &saved.artifact_id).await?; }
            let before_open = cleanup_prepare_facts(&f).await?;
            let opened = application.execute(f.auth.clone(), AppCommand::OpenArtifactRead(OpenArtifactRead { artifact_id: saved.artifact_id.clone() })).await;
            let state = Fixture::state(&probe)?;
            let completion = original.actual()?;
            let outcome = async {
                if initially_armed {
                    require(matches!(opened, Err(AppError::DependencyUnavailable { dependency: "artifacts" })), "initial armed fence produced a public reader/control")?;
                    require(probe.sha_segments.load(Ordering::SeqCst) == 0 && probe.prefix.lock().map_err(|_| "prefix probe poisoned")?.is_none(), "initial armed fence ran actual SHA/prefix IO")?;
                    require(before_open == cleanup_prepare_facts(&f).await?, "initial armed refusal changed business/fence facts")?;
                } else {
                    let reply = opened.map_err(|error| error.to_string())?;
                    let opened = match &reply {
                        AppReply::ArtifactReadOpened(opened) => opened.clone(),
                        _ => return Err("actual public Open did not return its closed control reply".to_owned()),
                    };
                    let control = application.take_artifact_read_control_delivery(f.auth.clone(), reply).map_err(|error| error.to_string())?;
                    control.verify_current_tail(&f.auth).map_err(|error| error.to_string())?;
                    drop(control);
                    Fixture::wait_collector_tail(&state).await?;
                    let sha_segments = probe.sha_segments.load(Ordering::SeqCst);
                    let prefix = probe.prefix.lock().map_err(|_| "prefix probe poisoned")?.clone();
                    require(sha_segments == f.source.len().div_ceil(64 * 1024)
                        && prefix == Some((4 * 1024 * 1024, 4 * 1024 * 1024, Sha256Digest::of(&f.source.as_bytes()[..4 * 1024 * 1024]).to_hex())),
                        "actual prepare did not retain its one original full SHA/first prefix")?;
                    {
                        let data = state.data.lock().map_err(|_| "original state poisoned")?;
                        require(data.reader.is_some() && data.resource.is_some() && data.position == 4 * 1024 * 1024 && data.phase == ReadPhase::Pending, "actual cached first lost its original FD/allocation before client delay")?;
                        data.reader.as_ref().unwrap().verify_physical_current().map_err(|error| error.to_string())?;
                    }
                    require(opened.artifact_id == saved.artifact_id && opened.byte_length == f.source.len() as u64
                        && opened.sha256 == Sha256Digest::of(f.source.as_bytes()).to_hex(), "Open changed original real prepared facts")?;
                    // Delay is causal, not a timer: Open actually finished before this COMMIT.
                    arm_cleanup_prepare_fixture(&f, &saved.artifact_id).await?;
                    let before_next = cleanup_prepare_facts(&f).await?;
                    let input = ReadArtifactReadBlock { handle_id: opened.handle_id, sequence: 0 };
                    let next = application.execute(f.auth.clone(), AppCommand::ReadArtifactReadBlock(input.clone())).await;
                    require(matches!(next, Err(AppError::DependencyUnavailable { dependency: "artifacts" })), "actual cached-first next ignored the new armed fence")?;
                    require(application.take_artifact_read_delivery(f.auth.clone(), input).is_err(), "refused cached first could still be selected as payload")?;
                    require(probe.sha_segments.load(Ordering::SeqCst) == sha_segments
                        && *probe.prefix.lock().map_err(|_| "prefix probe poisoned")? == prefix, "cached-first refresh reopened/rehashed/reread original bytes")?;
                    require(before_next == cleanup_prepare_facts(&f).await?, "cached-first refusal changed business/charge/receipt/fence/audit facts")?;
                }
                Ok::<(), String>(())
            }.await;
            let closed = application.close_public_artifact_reads();
            completion.close();
            let completed = completion.drain_before(Instant::now() + Duration::from_secs(3)).await;
            let lifecycle = f.authority.read_lifecycle();
            lifecycle.close();
            let drained = lifecycle.drain_before(Instant::now() + Duration::from_secs(3)).await;
            {
                let data = state.data.lock().map_err(|_| "original final state poisoned")?;
                require(data.reader.is_none() && data.resource.is_none() && state.actual_jobs() == 0, "original cached first/worker/FD/full allocation did not actually finish")?;
            }
            let observations = f.pool.connection_observations();
            f.pool.close();
            let cleanup_deadline = Instant::now() + Duration::from_secs(3);
            for observation in observations { observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?; }
            outcome?;
            closed.map_err(|error| error.to_string())?;
            completed.map_err(|error| error.to_string())?;
            drained.map_err(|error| format!("{error:?}"))?;
            require(f.root.path.join("objects").join(&saved.artifact_id).is_file(), "reader refusal was counted as physical cleanup")?;
            f.root.allow_cleanup_after_actual_completions();
            Ok(())
        }).await;
    }
}

#[cfg(target_os = "macos")]
fn shared_prepare_owned_fds(
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

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL; actual Application cached first, weak Entry stop and original allocation"]
async fn shared_read_barrier_stops_cached_first_without_another_request() {
    use openbot_application::ApplicationService as _;
    use openbot_contracts::artifact_read_protocol::{OpenArtifactRead, ReadArtifactReadBlock};
    use openbot_contracts::command::{AppCommand, AppReply};
    let tag = "shared-cached-first-stop";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let mut f = Fixture::new(config).await?;
        let saved = f.save().await?;
        let record = f.administration.observe_read_record(&f.auth, &saved.artifact_id).await.map_err(|error| error.to_string())?;
        let path = f.root.path.join("objects").join(&saved.artifact_id);
        require(shared_prepare_owned_fds(&path)?.is_empty(), "cached-first original inode began with a live reader")?;
        let probe = PublicPrepareProbe::new();
        f.install_probe(probe.clone())?;
        let original = Arc::new(Observer::default());
        let application = openbot_application::OpenBotApplication::new(
            crate::repo::channels::ChannelRepo::new(f.pool.clone()),
        ).with_artifacts(Arc::new(CleanupObservedAdministration {
            actual: f.administration.clone(), original: original.clone(),
        }));
        let reply = application.execute(f.auth.clone(), AppCommand::OpenArtifactRead(OpenArtifactRead {
            artifact_id: saved.artifact_id.clone(),
        })).await.map_err(|error| error.to_string())?;
        let opened = match &reply {
            AppReply::ArtifactReadOpened(opened) => opened.clone(),
            _ => return Err("real shared Open returned another control".to_owned()),
        };
        let control = application.take_artifact_read_control_delivery(f.auth.clone(), reply).map_err(|error| error.to_string())?;
        control.verify_current_tail(&f.auth).map_err(|error| error.to_string())?;
        drop(control);
        let state = Fixture::state(&probe)?;
        let completion = original.actual()?;
        Fixture::wait_collector_tail(&state).await?;
        let outcome = async {
            let before = cleanup_prepare_facts(&f).await?;
            let sha_segments = probe.sha_segments.load(Ordering::SeqCst);
            let prefix = probe.prefix.lock().map_err(|_| "original prefix probe poisoned")?.clone();
            require(sha_segments == f.source.len().div_ceil(64 * 1024) && prefix.as_ref().is_some_and(|value|
                *value == (4 * 1024 * 1024, 4 * 1024 * 1024, Sha256Digest::of(&f.source.as_bytes()[..4 * 1024 * 1024]).to_hex())),
                "cached first did not perform exactly its original full SHA and prefix")?;
            {
                let data = state.data.lock().map_err(|_| "original cached State poisoned")?;
                require(data.phase == ReadPhase::Pending && data.reader.is_some() && data.resource.is_some() && state.actual_jobs() == 0,
                    "Open did not retain the original cached first allocation and reader")?;
            }
            let original_fds = shared_prepare_owned_fds(&path)?;
            require(original_fds.len() == 1, "actual cached first did not retain exactly its original FD")?;
            let barrier = f.administration.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
            // No Next, explicit Close, completion.close or lifecycle.close runs before this ACK.
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(3)).await.map_err(|error| format!("{error:?}"))?;
            require(shared_prepare_owned_fds(&path)?.is_empty(), "weak Entry stop did not actually close the cached original FD")?;
            {
                let data = state.data.lock().map_err(|_| "closed original State poisoned")?;
                require(data.phase == ReadPhase::Terminal && data.reader.is_none() && data.resource.is_none() && state.actual_jobs() == 0,
                    "shared cached ACK did not follow actual original owner release")?;
            }
            require(probe.sha_segments.load(Ordering::SeqCst) == sha_segments
                && *probe.prefix.lock().map_err(|_| "original prefix probe poisoned")? == prefix,
                "proactive shared stop reopened, rehashed or reread cached bytes")?;
            require(before == cleanup_prepare_facts(&f).await? && path.is_file(),
                "shared cached stop changed business/fence facts or deleted the object")?;
            // Only after actual proactive drain, exercise the old locator refusal.
            let input = ReadArtifactReadBlock { handle_id: opened.handle_id.clone(), sequence: 0 };
            require(application.execute(f.auth.clone(), AppCommand::ReadArtifactReadBlock(input.clone())).await.is_err()
                && application.take_artifact_read_delivery(f.auth.clone(), input).is_err(),
                "the stopped cached first still yielded a body")?;
            drop(ack); drop(barrier);
            eprintln!("ARTIFACT_SHARED_CACHED no_next_before_ack=true weak_entry_stop=true original_allocation_drop=true original_fd_absent=true original_sha_prefix_unchanged=true object_retained=true core_guard_only=true");
            Ok::<_, String>(())
        }.await;
        let closed = application.close_public_artifact_reads();
        completion.close();
        let completed = completion.drain_before(Instant::now() + Duration::from_secs(3)).await;
        let lifecycle = f.authority.read_lifecycle(); lifecycle.close();
        let drained = lifecycle.drain_before(Instant::now() + Duration::from_secs(3)).await;
        drop(application); drop(original); drop(completion); drop(state); drop(probe); drop(record);
        let observations = f.pool.connection_observations(); f.pool.close();
        let deadline = Instant::now() + Duration::from_secs(3);
        for original in observations {
            require(original.wait_for_destruction_before(deadline).await.map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
                "cached-first original connection did not actually destruct")?;
        }
        outcome?; closed.map_err(|error| error.to_string())?; completed.map_err(|error| error.to_string())?;
        drained.map_err(|error| format!("{error:?}"))?;
        f.root.allow_cleanup_after_actual_completions();
        Ok(())
    }).await;
}

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        time::Duration::minutes(30),
        time::Duration::hours(1),
        time::Duration::seconds(1),
    )
    .unwrap()
}
impl HostRequestBindingGuard for SessionGuard {
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        self.verify_current_before(auth, Instant::now() + Duration::from_secs(5))
    }
    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            let authority = self
                .authority
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let administration = authority
                .administration
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let binding = auth
                .request_binding()
                .ok_or(HostRequestBindingError::Missing)?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())?;
            let mut client = administration
                .registry
                .pool()
                .get()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .read_only(true)
                .start()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let outcome=async {
                let remaining=deadline.checked_duration_since(Instant::now()).ok_or(HostRequestBindingError::Unavailable)?;
                let millis=remaining.as_millis().clamp(1,5000);
                tx.batch_execute(&format!("SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"))
                    .await.map_err(|_|HostRequestBindingError::Unavailable)?;
                let row=tx.query_one("SELECT u.id AS read_host_user,u.auth_generation AS read_host_generation,
                    u.email AS read_host_email,EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked,
                    ARRAY(SELECT role::text FROM public.user_roles WHERE user_id=u.id ORDER BY role::text) AS read_host_roles,
                    s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token,
                    s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,s.auth_generation AS read_session_generation
                    FROM (SELECT 1) a LEFT JOIN public.users u ON u.id=$1 LEFT JOIN public.sessions s ON s.id=$2 AND s.user_id=u.id",
                    &[&auth.actor().as_str(),&epoch.lookup_id()]).await.map_err(|_|HostRequestBindingError::Unavailable)?;
                decode_host(&administration,auth,&row,&CurrentHost::Session { epoch, lifetime:lifetime() })
                    .map_err(|error|match error { ArtifactReadCurrentError::Host(error)=>error,_=>HostRequestBindingError::Unavailable })
            }.await;
            tx.rollback()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let witness = outcome?;
            witness
                .verify_current(auth, deadline)
                .map_err(|error| match error {
                    ArtifactReadCurrentError::Host(error) => error,
                    _ => HostRequestBindingError::Unavailable,
                })
        })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let authority = self
                .authority
                .upgrade()
                .ok_or(ArtifactReadCurrentError::Unavailable)?;
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Unavailable)?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())
                .map_err(ArtifactReadCurrentError::Host)?;
            authority
                .observe_server_session(auth, target, epoch, lifetime(), deadline)
                .await
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn public_prepare_retains_same_fd_first_pending_and_isolated_true_close() {
    let tag = "public_read_prepare_same_fd";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let mut f = Fixture::new(config).await?;
        let saved = f.save().await?;
        let a = PublicPrepareProbe::new();
        f.install_probe(a.clone())?;
        let a_observer = Arc::new(Observer::default());
        let prepared_a = f
            .administration
            .prepare_host_bound_artifact_read(
                &f.auth,
                &saved.artifact_id,
                Instant::now() + Duration::from_secs(600),
                a_observer.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
        let state_a = Fixture::state(&a)?;
        Fixture::wait_collector_tail(&state_a).await?;
        let original_sha = Sha256Digest::of(f.source.as_bytes()).to_hex();
        {
            let data = state_a
                .data
                .lock()
                .map_err(|_| "actual A data".to_owned())?;
            let reader = data
                .reader
                .as_ref()
                .ok_or_else(|| "actual retained A FD missing".to_owned())?;
            let record = reader.record_snapshot();
            require(
                data.phase == ReadPhase::Pending
                    && !data.eof
                    && data.position == 4 * 1024 * 1024
                    && data.resource.is_some()
                    && state_a.actual_jobs() == 0,
                "actual first pending retains FD/resource after true worker join",
            )?;
            require(
                record.source_snapshot.artifact_id == saved.artifact_id
                    && record.blob().byte_length() == f.source.len() as u64
                    && Sha256Digest::from_bytes(*record.blob().sha256()).to_hex() == original_sha,
                "same original actual FD snapshot facts",
            )?;
            reader
                .verify_physical_current()
                .map_err(|e| e.to_string())?;
        }
        require(
            a.sha_segments.load(Ordering::SeqCst) == f.source.len().div_ceil(64 * 1024),
            "real fullSHA actual segment count",
        )?;
        let prefix = a
            .prefix
            .lock()
            .map_err(|_| "actual prefix probe".to_owned())?
            .clone();
        require(
            prefix
                == Some((
                    4 * 1024 * 1024,
                    4 * 1024 * 1024,
                    Sha256Digest::of(&f.source.as_bytes()[..4 * 1024 * 1024]).to_hex(),
                )),
            "real original first prefix/full initialized allocation/digest",
        )?;
        let b = PublicPrepareProbe::new();
        f.install_probe(b.clone())?;
        let b_observer = Arc::new(Observer::default());
        let prepared_b = f
            .administration
            .prepare_host_bound_artifact_read(
                &f.auth,
                &saved.artifact_id,
                Instant::now() + Duration::from_secs(600),
                b_observer.clone(),
            )
            .await
            .map_err(|e| e.to_string())?;
        let state_b = Fixture::state(&b)?;
        require(
            !Arc::ptr_eq(&state_a, &state_b),
            "two actual independent operations",
        )?;
        let completion_a = a_observer.actual()?;
        require(
            completion_a
                .drain_before(Instant::now() + Duration::from_millis(30))
                .await
                .is_err(),
            "held original full pending allocation prevents false Close ACK",
        )?;
        drop(prepared_a);
        completion_a
            .drain_before(Instant::now() + Duration::from_secs(2))
            .await
            .map_err(|e| e.to_string())?;
        {
            let data = state_a
                .data
                .lock()
                .map_err(|_| "closed A data".to_owned())?;
            require(
                data.phase == ReadPhase::Terminal
                    && data.reader.is_none()
                    && data.resource.is_none()
                    && state_a.actual_jobs() == 0,
                "A original resources truly ended",
            )?;
        }
        {
            let data = state_b.data.lock().map_err(|_| "live B data".to_owned())?;
            require(
                !state_b.is_stopped()
                    && data.phase == ReadPhase::Pending
                    && data.reader.is_some()
                    && data.resource.is_some(),
                "A close preserves unrelated B original reader",
            )?;
            data.reader
                .as_ref()
                .unwrap()
                .verify_physical_current()
                .map_err(|e| e.to_string())?;
        }
        drop(prepared_b);
        b_observer
            .actual()?
            .drain_before(Instant::now() + Duration::from_secs(2))
            .await
            .map_err(|e| e.to_string())?;
        let rejected = Arc::new(Observer {
            reject: true,
            ..Observer::default()
        });
        require(
            f.administration
                .prepare_host_bound_artifact_read(
                    &f.auth,
                    &saved.artifact_id,
                    Instant::now() + Duration::from_secs(600),
                    rejected.clone(),
                )
                .await
                .is_err(),
            "observer rejection refuses before IO",
        )?;
        rejected
            .actual()?
            .drain_before(Instant::now() + Duration::from_secs(1))
            .await
            .map_err(|e| e.to_string())?;
        require(
            f.root
                .path
                .join("objects")
                .join(&saved.artifact_id)
                .is_file(),
            "fixture original object retained",
        )?;
        f.pool.close();
        // A, B and the rejected preparation have each returned their actual original
        // completion ACK; no pending allocation, collector or hold remains unproved.
        f.root.allow_cleanup_after_actual_completions();
        Ok(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn public_prepare_deadline_and_cancel_keep_actual_blocking_join_accounted() {
    let tag = "public_read_prepare_true_join";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let mut f = Fixture::new(config).await?;
        let saved = f.save().await?;
        for sha_expiry in [false, true] {
            let probe = PublicPrepareProbe::new();
            let (entered, release) = if sha_expiry {
                probe.hold_first_sha_segment()
            } else {
                probe.hold_worker()
            };
            f.install_probe(probe.clone())?;
            let observer = Arc::new(Observer::default());
            let administration = f.administration.clone();
            let auth = f.auth.clone();
            let id = saved.artifact_id.clone();
            let original_deadline =
                Instant::now() + Duration::from_secs(if sha_expiry { 2 } else { 10 });
            let actual_observer = observer.clone();
            let waiter = tokio::spawn(async move {
                administration
                    .prepare_host_bound_artifact_read(
                        &auth,
                        &id,
                        original_deadline,
                        actual_observer,
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), entered)
                .await
                .map_err(|_| "actual worker gate not entered".to_owned())?
                .map_err(|_| "original worker gate closed".to_owned())?;
            let state = Fixture::state(&probe)?;
            require(
                state.actual_jobs() == 1,
                "original collector owns one real blocking job",
            )?;
            let completion = observer.actual()?;
            if sha_expiry {
                require(
                    probe.sha_segments.load(Ordering::SeqCst) == 1,
                    "original FD first64KiB SHA actually completed",
                )?;
                tokio::time::sleep_until(tokio::time::Instant::from_std(
                    original_deadline + Duration::from_millis(25),
                ))
                .await;
                let outcome = waiter.await.map_err(|e| e.to_string())?;
                require(
                    outcome.is_err() && Instant::now() >= original_deadline,
                    "real monotonic expiry refuses original preparation",
                )?;
            } else {
                waiter.abort();
                require(
                    waiter.await.is_err_and(|error| error.is_cancelled()),
                    "cancelled original preparation waiter joined",
                )?;
                require(
                    probe.sha_segments.load(Ordering::SeqCst) == 0,
                    "held worker has not opened/hash-read object",
                )?;
            }
            require(
                state.actual_jobs() == 1
                    && probe
                        .prefix
                        .lock()
                        .map_err(|_| "pending probe".to_owned())?
                        .is_none(),
                "cancel/elapsed waiter does not end actual blocking worker or publish prefix",
            )?;
            require(
                completion
                    .drain_before(Instant::now() + Duration::from_millis(30))
                    .await
                    .is_err(),
                "blocked actual worker cannot yield a Close ACK",
            )?;
            release
                .send(())
                .map_err(|_| "original blocking release failed".to_owned())?;
            completion
                .drain_before(Instant::now() + Duration::from_secs(3))
                .await
                .map_err(|e| e.to_string())?;
            let data = state.data.lock().map_err(|_| "joined State".to_owned())?;
            require(
                data.phase == ReadPhase::Terminal
                    && data.reader.is_none()
                    && data.resource.is_none()
                    && state.actual_jobs() == 0,
                "released original worker truly joined and closed every original resource",
            )?;
            require(
                probe.sha_segments.load(Ordering::SeqCst) == usize::from(sha_expiry),
                "no additional SHA segment after stop/expiry",
            )?;
            drop(data);
        }
        f.pool.close();
        // Both original waiters settled, both original holds were released, and each
        // same-operation completion ACK followed its real worker/collector join.
        f.root.allow_cleanup_after_actual_completions();
        Ok(())
    })
    .await;
}
