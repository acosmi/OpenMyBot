//! Owned disposable PG + actual Begin/Save/byte-root tests of the internal snapshot-to-FD port.
//! AuthContextBuilder values are synthetic local principals, not live host bindings or byte
//! handoff grants. No test claims public download, deletion/expiry cleanup or backup delivery.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "macos")]
fn shared_bridge_owned_fds(path: &Path) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::io::Read as _;
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
#[ignore = "requires owned PostgreSQL; actual original Store reader FD and external caller buffer"]
async fn shared_read_barrier_tracks_direct_store_reader_until_actual_drop() {
    with_fixture("shared-direct-reader", false, |f| async move {
        use std::time::Instant;
        let saved = f.save().await?;
        let record = f.observe(&saved.artifact_id).await.map_err(|error| error.to_string())?;
        let before = f.facts().await?;
        let path = f.root.0.join("objects").join(&saved.artifact_id);
        let mut reader = f.store.open_observed_record(
            f.observe(&saved.artifact_id).await.map_err(|error| error.to_string())?,
        ).map_err(|error| error.to_string())?;
        let original_fds = shared_bridge_owned_fds(&path)?;
        require(original_fds.len() == 1, "direct original reader did not retain its actual object FD")?;
        let mut output = [0_u8; 80];
        let count = reader.read_observed_chunk(&mut output).map_err(|error| error.to_string())?;
        let caller_owned_copy = output[..count].to_vec();
        require(caller_owned_copy == EXACT.as_bytes(), "direct original reader produced different saved bytes")?;

        // This is a controlled malformed private snapshot after actual original-key binding.
        // It is not a legal mismatched PG row, another Save, or a cleanup producer.
        let mut malformed = f.observe(&saved.artifact_id).await.map_err(|error| error.to_string())?;
        malformed.source_snapshot.operation_id = Uuid::now_v7().to_string();
        require(f.administration.close_observed_artifact_reads(&malformed).is_err(),
            "different operation in a malformed private snapshot closed an already-bound original key")?;
        reader.verify_physical_current().map_err(|error| error.to_string())?;
        drop(malformed);
        let barrier = f.administration.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err()
            && shared_bridge_owned_fds(&path)? == original_fds,
            "direct FD lease released before the actual original File")?;
        require(f.store.open_observed_record(f.observe(&saved.artifact_id).await.map_err(|error| error.to_string())?).is_err(),
            "permanently closed direct path opened another original FD/full SHA")?;
        output.fill(0xA5);
        require(reader.read_observed_chunk(&mut output).is_err() && output.iter().all(|byte| *byte == 0),
            "closed direct reader delivered another chunk or did not wipe rejected caller output")?;
        drop(reader);
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(3)).await.map_err(|error| format!("{error:?}"))?;
        require(shared_bridge_owned_fds(&path)?.is_empty(), "direct original File survived controlled ACK")?;
        require(caller_owned_copy == EXACT.as_bytes() && path.is_file(),
            "controlled ACK falsely claimed caller-output destruction or actual deletion")?;
        require(before == f.facts().await?, "direct shared close changed original business/charge/receipt/audit facts")?;
        let fence_count: i64 = f.pool.get().await.map_err(|error| error.to_string())?
            .query_one("SELECT COUNT(*) FROM openbot_internal.artifact_cleanup_fences", &[])
            .await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())?;
        require(fence_count == 0, "direct shared barrier created a durable cleanup producer")?;
        drop(caller_owned_copy); drop(ack); drop(barrier); drop(record);
        let observations = f.pool.connection_observations(); f.pool.close();
        let deadline = Instant::now() + Duration::from_secs(3);
        for original in observations {
            require(original.wait_for_destruction_before(deadline).await.map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed, "direct fixture original connection survived actual closure")?;
        }
        eprintln!("ARTIFACT_SHARED_DIRECT original_fd_held_no_ack=true malformed_private_operation_refused=true actual_file_drop_before_lease=true caller_output_lifetime=UNTRACKED copied_bytes_still_valid_at_ack=true object_retained=true");
        Ok(())
    }).await;
}

use openbot_application::{BeginThreadRunRequest, RunRuntime, RunTerminal, ThreadDirectory};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::{BotId, ChannelId};
use serde_json::Value;

use super::*;
use crate::artifact_bytes::{ArtifactByteError, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_READ_CHUNK_BYTES};
use crate::artifact_store::{
    ArtifactReadBridgeError, ArtifactStoreError, StoreBoundArtifactReader,
};
use crate::db::pool::DatabaseConfig;
use crate::db::{baseline, native, pool};
use crate::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

mod harness {
    use crate as openbot_infra;
    include!("../../../test-support/postgres_harness.rs");
}

const DEPLOYMENT: &str = "artifact-read-owned-deployment";
const TENANT: &str = "artifact-read-owned-tenant";
const OWNER: &str = "read-owner";
const OTHER: &str = "read-other";
const EXACT: &str = "  PRIVATE_READ_SOURCE_CANARY\n成果 café 🦀\t  ";

fn require(ok: bool, message: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-read-bridge-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self(fs::canonicalize(path).map_err(|e| e.to_string())?))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_READ_BRIDGE_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned read-root cleanup failed");
        }
    }
}

struct Fixture {
    pool: Pool,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    administration: Arc<PostgresArtifactAdministration>,
    begin: BeginThreadRunRequest,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, channel: bool) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation,groups) VALUES
              ('read-owner','read-owner@example.test',0,ARRAY['read-fixture']),
              ('read-other','read-other@example.test',0,ARRAY['read-fixture']);
              INSERT INTO public.user_roles(user_id,role) VALUES('read-owner','user'),('read-other','admin');
              INSERT INTO public.agents(id,name,type,configuration) VALUES('read-bot','Read fixture','built_in','{}');
              INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('read-bot','read-owner','Read fixture','fixture','fixture','public');
              INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000051','artifact-read-owned-tenant','fixture','fixture');
              INSERT INTO public.channels(id,name,description,allowed_groups)
                VALUES('read-channel','Read fixture','fixture',ARRAY['read-fixture']);
              INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner'),('read-channel','read-other');
              INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot');")
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
            actor: ActorId::new(OWNER),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT))
                    .mint_from_entropy([9; 16]),
                run_id: RunId::new("read/source%成果"),
                bot_id: BotId::new("read-bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("read-channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: EXACT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "read-bridge-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|e| e.to_string())?,
                Arc::clone(&registry),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                Arc::clone(&registry),
                Arc::clone(&store),
                policy,
                SecretBytes::new(vec![0x83; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        Ok(Self {
            pool,
            registry,
            store,
            administration,
            begin,
            root,
        })
    }

    fn auth_as(&self, actor: &str, generation: u64) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            ActorId::new(actor),
            AuthGeneration::new(generation),
            false,
        )
        .with_role(if actor == OTHER {
            Role::Admin
        } else {
            Role::User
        })
        .build()
    }
    fn auth(&self) -> AuthContext {
        self.auth_as(OWNER, 0)
    }
    fn message_id(&self) -> String {
        format!("{}:input", self.begin.command.run_id.as_str())
    }
    async fn save(&self) -> Result<ArtifactRegistrationReceipt, String> {
        self.administration
            .save_run_message_text(
                &self.auth(),
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: self.message_id(),
                    expected_sha256: Sha256Digest::of(EXACT.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|e| e.to_string())
    }
    async fn observe(
        &self,
        id: &str,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        self.administration
            .observe_read_record(&self.auth(), id)
            .await
    }
    fn object(&self, id: &str) -> PathBuf {
        self.root.0.join("objects").join(id)
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
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|e| e.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
              'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
              'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))", &[])
            .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())
    }
    async fn reader(&self, id: &str) -> Result<StoreBoundArtifactReader, String> {
        let record = self.observe(id).await.map_err(|e| e.to_string())?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.open_observed_record(record))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
    async fn read_all(&self, id: &str) -> Result<Vec<u8>, String> {
        let mut reader = self.reader(id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            let mut chunk = [0; 11];
            loop {
                let n = reader
                    .read_observed_chunk(&mut chunk)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

async fn with_fixture<F, Fut>(tag: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, channel).await?).await
    })
    .await;
}

#[derive(Debug, PartialEq, Eq)]
struct OwnedFileFacts {
    path: PathBuf,
    inode: u64,
    mode: u32,
    byte_length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Vec<u8>,
}

fn filesystem_facts(path: &Path) -> Result<Vec<OwnedFileFacts>, String> {
    let mut result = Vec::new();
    let mut paths = vec![path.to_path_buf()];
    while let Some(current) = paths.pop() {
        let m = fs::symlink_metadata(&current).map_err(|e| e.to_string())?;
        let bytes = if m.is_file() {
            fs::read(&current).map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        result.push(OwnedFileFacts {
            path: current.clone(),
            inode: m.ino(),
            mode: m.mode(),
            byte_length: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
            bytes,
        });
        if m.is_dir() {
            for entry in fs::read_dir(current).map_err(|e| e.to_string())? {
                paths.push(entry.map_err(|e| e.to_string())?.path());
            }
        }
    }
    // Access time is deliberately excluded: actual reads may update it through the OS. No
    // business write, mode/length/content/mtime/ctime change is accepted as a read side effect.
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_saved_utf8_record_fd_reads_are_content_exact_and_have_zero_business_writes() {
    with_fixture("arb_exact", false, |f| async move {
        let r = f.save().await?;
        let before = f.facts().await?;
        let fs_before = filesystem_facts(&f.root.0)?;
        require(
            f.auth().request_binding().is_none(),
            "fixture silently claimed an actual host binding",
        )?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "real saved bytes were changed",
        )?;
        require(
            f.facts().await? == before && filesystem_facts(&f.root.0)? == fs_before,
            "read mutated PG business facts or actual stored files",
        )?;
        let record = f
            .observe(&r.artifact_id.to_uppercase())
            .await
            .map_err(|e| e.to_string())?;
        require(
            !format!("{record:?}").contains(&r.artifact_id),
            "descriptor debug revealed a locator",
        )?;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_queued_running_completed_sources_use_ordinary_r398_visibility() {
    with_fixture("arb_status", false, |f| async move {
        let r = f.save().await?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        let original = client
            .query_one(
                "SELECT status,started_at FROM public.runs WHERE run_id=$1",
                &[&f.begin.command.run_id.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        let original_started: Option<time::OffsetDateTime> = original.get("started_at");
        require(
            original.get::<_, String>("status") == "running" && original_started.is_some(),
            "actual Begin did not establish running source",
        )?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "actual Begin running source refused",
        )?;
        // This controlled owned-PG row tests the unchanged queued visibility predicate;
        // it is not evidence of a queued producer or promotion implementation.
        require(
            client
                .execute(
                    "UPDATE public.runs SET status='queued',started_at=NULL WHERE run_id=$1 AND status='running'",
                    &[&f.begin.command.run_id.as_str()],
                )
                .await
                .map_err(|e| e.to_string())? == 1,
            "controlled queued source was not established",
        )?;
        let queued = client
            .query_one(
                "SELECT status,started_at FROM public.runs WHERE run_id=$1",
                &[&f.begin.command.run_id.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            queued.get::<_, String>("status") == "queued"
                && queued.get::<_, Option<time::OffsetDateTime>>("started_at").is_none(),
            "controlled queued source readback differs",
        )?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "controlled queued source refused",
        )?;
        require(
            client
                .execute(
                    "UPDATE public.runs SET status='running',started_at=$2 WHERE run_id=$1 AND status='queued'",
                    &[&f.begin.command.run_id.as_str(), &original_started],
                )
                .await
                .map_err(|e| e.to_string())? == 1,
            "original running source was not restored",
        )?;
        let restored = client
            .query_one(
                "SELECT status,started_at FROM public.runs WHERE run_id=$1",
                &[&f.begin.command.run_id.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            restored.get::<_, String>("status") == "running"
                && restored.get::<_, Option<time::OffsetDateTime>>("started_at") == original_started,
            "original running source restoration differs",
        )?;
        drop(client);
        let runtime = PostgresRunRuntime::new(
            f.pool.clone(),
            "read-bridge-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|e| e.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("actual dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "running source refused",
        )?;
        runtime
            .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
            .await
            .map_err(|e| e.to_string())?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "completed source refused",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn current_generation_and_roles_are_read_from_pg_not_synthetic_auth_claims() {
    with_fixture("arb_gen_role", false, |f| async move {
        let r = f.save().await?;
        f.sql("UPDATE public.users SET auth_generation=1 WHERE id='read-owner'").await?;
        require(matches!(f.observe(&r.artifact_id).await, Err(ArtifactAdministrationError::NotVisible)), "stale generation minted descriptor")?;
        require(f.administration.observe_read_record(&f.auth_as(OWNER,1),&r.artifact_id).await.is_ok(), "current generation was refused")?;
        f.sql("UPDATE public.users SET auth_generation=0 WHERE id='read-owner'; DELETE FROM public.user_roles WHERE user_id='read-owner'").await?;
        require(matches!(f.observe(&r.artifact_id).await, Err(ArtifactAdministrationError::NotVisible)), "claimed role bypassed actual role deletion")?;
        f.sql("INSERT INTO public.user_roles(user_id,role) VALUES('read-owner','user'); UPDATE public.users SET auth_generation=NULL WHERE id='read-owner'").await?;
        require(f.observe(&r.artifact_id).await.is_ok(), "private R398 legacy NULL-to-zero semantics changed")
    }).await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_deny_profile_and_bot_package_changes_hide_the_saved_record() {
    with_fixture("arb_authority", false, |f| async move {
        let r = f.save().await?;
        for (deny, restore) in [
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('read-owner@example.test','read-other')", "DELETE FROM public.revoked_access WHERE email='read-owner@example.test'"),
            ("UPDATE public.agent_profiles SET visibility='private',owner_user_id='read-other' WHERE agent_id='read-bot'", "UPDATE public.agent_profiles SET visibility='public',owner_user_id='read-owner' WHERE agent_id='read-bot'"),
            ("UPDATE public.agent_profiles SET deleted_at=now() WHERE agent_id='read-bot'", "UPDATE public.agent_profiles SET deleted_at=NULL WHERE agent_id='read-bot'"),
            ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000051' WHERE id='read-bot'; UPDATE public.deployment_packages SET tenant_id='foreign'", "UPDATE public.agents SET package_id=NULL WHERE id='read-bot'; UPDATE public.deployment_packages SET tenant_id='artifact-read-owned-tenant'"),
        ] {
            f.sql(deny).await?;
            require(matches!(f.observe(&r.artifact_id).await, Err(ArtifactAdministrationError::NotVisible)), "current deny/profile/package facts were ignored")?;
            f.sql(restore).await?;
            require(f.observe(&r.artifact_id).await.is_ok(), "restored source remained hidden")?;
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_channel_membership_assignment_package_and_owner_are_current() {
    with_fixture("arb_channel", true, |f| async move {
        let r = f.save().await?;
        require(matches!(f.administration.observe_read_record(&f.auth_as(OTHER,0), &r.artifact_id).await,
            Err(ArtifactAdministrationError::NotVisible)), "channel admin read another actor's saved bytes")?;
        for (deny, restore) in [
            ("DELETE FROM public.channel_memberships WHERE user_id='read-owner'", "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner')"),
            ("DELETE FROM public.channel_agents WHERE channel_id='read-channel'", "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot')"),
            ("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000051'; UPDATE public.deployment_packages SET tenant_id='foreign'", "UPDATE public.channels SET package_id=NULL; UPDATE public.deployment_packages SET tenant_id='artifact-read-owned-tenant'"),
        ] {
            f.sql(deny).await?;
            require(matches!(f.observe(&r.artifact_id).await, Err(ArtifactAdministrationError::NotVisible)), "channel current permission change was ignored")?;
            f.sql(restore).await?;
        }
        require(f.read_all(&r.artifact_id).await? == EXACT.as_bytes(), "restored channel record refused")
    }).await;
}

// Privileged corruption control is confined to this owned disposable test DB.
// Probe the real guard for every change/restore and re-enable it in the same transaction.

// Finite privileged joint corruption in this disposable test DB. Ordinary
// open direct-source metadata changes stay ordinary DML; missing actual Run or
// referenced canonical mutations first prove their precise new55000 refusal.
async fn tamper_owned_message_joint(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const GUARDS: [&str; 3] = [
        "messages_history_body_before",
        "messages_history_canonical_before",
        "messages_history_source_final",
    ];
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!("owned message guard {guard} was not enabled"));
        }
    }
    tx.batch_execute("SAVEPOINT owned_message_joint_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    if matches!(&ordinary,Ok(n) if *n>0) {
        tx.batch_execute("RELEASE SAVEPOINT owned_message_joint_probe")
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_message_joint_probe; RELEASE SAVEPOINT owned_message_joint_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err(
            "message joint control did not encounter its explicit registered refusal".into(),
        );
    }
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    let n = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "message guard {guard} was not restored before natural COMMIT/product reader"
            ));
        }
    }
    if n == 0 {
        return Err("owned message corruption changed no row".into());
    }
    Ok(())
}
async fn tamper_owned_thread_identity(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const NEW_GUARDS: [&str; 3] = [
        "threads_history_body_before_update",
        "threads_history_canonical_before",
        "threads_history_source_final",
    ];
    const OLD: &str = "threads_history_protect_identity_update";
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Thread guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_current_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_current_identity_probe; RELEASE SAVEPOINT owned_current_identity_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_state_binding_invalid"
                        | "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err("ordinary current Thread identity DML was not explicitly refused".into());
    }
    // Suppress only these owned fixture events BEFORE corrupting DML. Re-enabling
    // at COMMIT cannot remove an already queued deferred event; none is bypassed.
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.batch_execute("SAVEPOINT owned_original50_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let original = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_original50_identity_probe; RELEASE SAVEPOINT owned_original50_identity_probe").await.map_err(|e|e.to_string())?;
    if !original
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000" && e.message() == "thread_history_state_binding_invalid"
        })
    {
        return Err("original0050 single identity guard control lost its exact refusal".into());
    }
    tx.batch_execute(
        "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    tx.batch_execute(
        "ALTER TABLE public.threads ENABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Thread guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned identity control changed no row".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_direct_membership_and_thread_namespace_are_current() {
    with_fixture("arb_direct", false, |f| async move {
        let r = f.save().await?;
        f.sql("DELETE FROM public.thread_memberships WHERE user_id='read-owner'")
            .await?;
        require(
            matches!(
                f.observe(&r.artifact_id).await,
                Err(ArtifactAdministrationError::NotVisible)
            ),
            "direct membership deletion ignored",
        )?;
        let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
        client
            .execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'read-owner')",
                &[&f.begin.command.thread_id.as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_thread_identity(
            &tx,
            "UPDATE public.threads SET tenant_id='foreign' WHERE thread_id=$1",
            &[&f.begin.command.thread_id.as_str()],
        )
        .await?;
        tx.commit().await.map_err(|e| e.to_string())?;
        require(
            matches!(
                f.observe(&r.artifact_id).await,
                Err(ArtifactAdministrationError::NotVisible)
            ),
            "foreign actual thread namespace accepted",
        )?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tamper_owned_thread_identity(
            &tx,
            "UPDATE public.threads SET tenant_id=$2,deployment_id='foreign' WHERE thread_id=$1",
            &[&f.begin.command.thread_id.as_str(), &TENANT],
        )
        .await?;
        tx.commit().await.map_err(|e| e.to_string())?;
        require(
            matches!(
                f.observe(&r.artifact_id).await,
                Err(ArtifactAdministrationError::NotVisible)
            ),
            "foreign actual thread deployment accepted",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_message_role_actor_run_and_harddelete_control_visibility() {
    with_fixture("arb_message", false, |f| async move {
        let r = f.save().await?;
        let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
        for (column, bad, good) in [
            ("role", "assistant", "user"),
            ("actor_id", "read-other", "read-owner"),
            ("run_id", "another-run", f.begin.command.run_id.as_str()),
        ] {
            // Columns are a fixed test-owned closed set, never a product SQL input.
            let tx = client.transaction().await.map_err(|e| e.to_string())?;
            tamper_owned_message_joint(
                &tx,
                &format!("UPDATE public.messages SET {column}=$2 WHERE message_id=$1"),
                &[&f.message_id(), &bad],
            )
            .await?;
            tx.commit().await.map_err(|e| e.to_string())?;
            require(
                matches!(
                    f.observe(&r.artifact_id).await,
                    Err(ArtifactAdministrationError::NotVisible)
                ),
                "actual message relationship ignored",
            )?;
            let tx = client.transaction().await.map_err(|e| e.to_string())?;
            tamper_owned_message_joint(
                &tx,
                &format!("UPDATE public.messages SET {column}=$2 WHERE message_id=$1"),
                &[&f.message_id(), &good],
            )
            .await?;
            tx.commit().await.map_err(|e| e.to_string())?;
        }
        client
            .execute(
                "DELETE FROM public.messages WHERE message_id=$1",
                &[&f.message_id()],
            )
            .await
            .map_err(|e| e.to_string())?;
        require(
            matches!(
                f.observe(&r.artifact_id).await,
                Err(ArtifactAdministrationError::NotVisible)
            ),
            "harddeleted source message remained visible",
        )?;
        require(
            fs::read(f.object(&r.artifact_id)).map_err(|e| e.to_string())? == EXACT.as_bytes(),
            "source deletion erased historical bytes",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn source_text_edits_do_not_rehash_historical_saved_bytes() {
    with_fixture("arb_edit", false, |f| async move {
        let r = f.save().await?;
        f.pool.get().await.map_err(|e|e.to_string())?.execute(r#"UPDATE public.messages SET content='{"text":"changed source"}'::jsonb WHERE message_id=$1"#, &[&f.message_id()]).await.map_err(|e|e.to_string())?;
        require(f.read_all(&r.artifact_id).await? == EXACT.as_bytes(), "mutable source content replaced historical saved bytes")
    }).await;
}

async fn tombstone(f: &Fixture, state: &str) -> Result<(), String> {
    // Real allowed native0042 transitions, only in this disposable fixture. The physical object
    // deliberately stays present; this does not implement or certify a cleanup producer.
    let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
    let tx = client.transaction().await.map_err(|e| e.to_string())?;
    tx.execute("UPDATE openbot_internal.artifact_records SET status=$1,workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL", &[&state]).await.map_err(|e|e.to_string())?;
    tx.execute("UPDATE openbot_internal.artifact_save_operations SET state=$1,store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL", &[&state]).await.map_err(|e|e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_visible_deleted_and_expired_rows_are_gone_without_opening_bytes() {
    for state in ["deleted", "expired"] {
        with_fixture(
            if state == "deleted" {
                "arb_deleted"
            } else {
                "arb_expired"
            },
            false,
            |f| async move {
                let r = f.save().await?;
                tombstone(&f, state).await?;
                let expected = if state == "deleted" {
                    ArtifactGoneStatus::Deleted
                } else {
                    ArtifactGoneStatus::Expired
                };
                require(
                    f.observe(&r.artifact_id).await.unwrap_err()
                        == ArtifactAdministrationError::Gone { status: expected },
                    "visible tombstone did not produce closed Gone",
                )?;
                f.sql("DELETE FROM public.user_roles WHERE user_id='read-owner'")
                    .await?;
                require(
                    matches!(
                        f.observe(&r.artifact_id).await,
                        Err(ArtifactAdministrationError::NotVisible)
                    ),
                    "invisible tombstone revealed Gone",
                )?;
                require(
                    f.object(&r.artifact_id).exists(),
                    "read unexpectedly cleaned physical tombstone object",
                )
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn partial_unresolved_and_mismatched_operation_payload_never_mint_reader() {
    with_fixture("arb_op_bad", false, |f| async move {
        let r=f.save().await?;
        for (bad, restore, partial) in [
            ("ALTER TABLE openbot_internal.artifact_records DISABLE TRIGGER artifact_records_identity_guard; UPDATE openbot_internal.artifact_records SET status='failed_partial'; ALTER TABLE openbot_internal.artifact_records ENABLE TRIGGER artifact_records_identity_guard", "ALTER TABLE openbot_internal.artifact_records DISABLE TRIGGER artifact_records_identity_guard; UPDATE openbot_internal.artifact_records SET status='available'; ALTER TABLE openbot_internal.artifact_records ENABLE TRIGGER artifact_records_identity_guard", true),
            ("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET state='unresolved'; ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard", "ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET state='available'; ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard", false),
            ("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET actual_sha256=repeat('0',64); ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard", "ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET actual_sha256=expected_sha256; ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard", false),
        ] {
            f.sql(bad).await?; let e=f.observe(&r.artifact_id).await.unwrap_err();
            require(if partial {e==ArtifactAdministrationError::Unavailable} else {matches!(e,ArtifactAdministrationError::Corrupt{..})}, "private failed/unknown/mismatched operation minted descriptor")?;
            f.sql(restore).await?;
        }
        require(f.observe(&r.artifact_id).await.is_ok(), "restored actual positive payload refused")
    }).await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_registry_store_tuple_or_schema_drift_fails_closed() {
    with_fixture("arb_tuple", false, |f| async move {
        let r=f.save().await?;
        f.sql("ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only; UPDATE openbot_internal.artifact_store_bindings SET root_inode='0'; ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only").await?;
        require(matches!(f.observe(&r.artifact_id).await,Err(ArtifactAdministrationError::Unavailable)), "changed current PG physical tuple accepted")?;
        f.sql("ALTER TABLE openbot_internal.artifact_records DISABLE TRIGGER artifact_records_identity_guard").await?;
        require(matches!(f.observe(&r.artifact_id).await,Err(ArtifactAdministrationError::Corrupt{..})), "schema drift accepted")
    }).await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn foreign_actual_store_in_same_pool_cannot_consume_original_descriptor() {
    with_fixture("arb_foreign", false, |f| async move {
        let r = f.save().await?;
        let record = f.observe(&r.artifact_id).await.map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                f.pool.clone(),
                &DeploymentId::new("different-owned-deployment"),
                &TenantId::new(TENANT),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let foreign = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|e| e.to_string())?,
                registry,
                ArtifactQuotaPolicy::default(),
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        require(
            matches!(
                foreign.open_observed_record(record),
                Err(ArtifactReadBridgeError::Store(
                    ArtifactStoreError::BindingMismatch
                ))
            ),
            "foreign Store Arc consumed original descriptor",
        )
    })
    .await;
}

fn mutate_object(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::set_permissions(path, Permissions::from_mode(0o400)).map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_object_missing_truncation_symlink_and_wrong_hash_refuse_open() {
    with_fixture("arb_object", false, |f| async move {
        let r = f.save().await?;
        let path = f.object(&r.artifact_id);
        let backup = path.with_extension("owned-backup");
        fs::rename(&path, &backup).map_err(|e| e.to_string())?;
        require(
            f.reader(&r.artifact_id).await.is_err(),
            "missing actual object opened",
        )?;
        symlink(&backup, &path).map_err(|e| e.to_string())?;
        require(
            f.reader(&r.artifact_id).await.is_err(),
            "object symlink opened",
        )?;
        fs::remove_file(&path).map_err(|e| e.to_string())?;
        fs::rename(&backup, &path).map_err(|e| e.to_string())?;
        mutate_object(&path, b"short")?;
        require(
            f.reader(&r.artifact_id).await.is_err(),
            "truncated object opened",
        )?;
        mutate_object(&path, &vec![b'X'; EXACT.len()])?;
        require(
            f.reader(&r.artifact_id).await.is_err(),
            "same-length wrong hash opened",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_fd_drift_is_terminal_and_wipes_all_unhanded_bytes() {
    with_fixture("arb_fd_drift", false, |f| async move {
        let r = f.save().await?;
        let mut reader = f.reader(&r.artifact_id).await?;
        mutate_object(&f.object(&r.artifact_id), &vec![b'X'; EXACT.len()])?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = [0xa5; 80];
            require(
                reader.read_observed_chunk(&mut bytes).is_err() && bytes == [0; 80],
                "changed FD returned unhanded bytes",
            )?;
            bytes.fill(0xa5);
            require(
                reader.read_observed_chunk(&mut bytes).is_err() && bytes == [0; 80],
                "terminal reader resumed after error",
            )
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_root_marker_change_is_terminal_without_leaking_the_pending_chunk() {
    with_fixture("arb_root_drift", false, |f| async move {
        let r = f.save().await?;
        let mut reader = f.reader(&r.artifact_id).await?;
        mutate_object(
            &f.root.0.join(".artifact-store-v1"),
            b"changed owned marker",
        )?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = [0xa5; 80];
            require(
                matches!(
                    reader.read_observed_chunk(&mut bytes),
                    Err(ArtifactReadBridgeError::Store(_))
                ) && bytes == [0; 80],
                "marker drift handed off a chunk",
            )?;
            bytes.fill(0xa5);
            require(
                reader.read_observed_chunk(&mut bytes).is_err() && bytes == [0; 80],
                "marker failure was not terminal",
            )
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn physical_chunk_ceiling_and_invalid_buffer_are_terminal() {
    with_fixture("arb_chunk", false, |f| async move {
        let r = f.save().await?;
        let mut reader = f.reader(&r.artifact_id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES];
            let n = reader
                .read_observed_chunk(&mut bytes)
                .map_err(|e| e.to_string())?;
            require(
                n == EXACT.len() && &bytes[..n] == EXACT.as_bytes(),
                "exact 4MiB buffer refused bounded real data",
            )?;
            require(
                reader
                    .read_observed_chunk(&mut bytes)
                    .map_err(|e| e.to_string())?
                    == 0,
                "EOF failed",
            )?;
            let mut too_large = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES + 1];
            require(
                matches!(
                    reader.read_observed_chunk(&mut too_large),
                    Err(ArtifactReadBridgeError::Bytes(
                        ArtifactByteError::InvalidChunk
                    ))
                ) && too_large.iter().all(|b| *b == 0),
                "oversize buffer was not refused/wiped",
            )?;
            require(
                reader.read_observed_chunk(&mut bytes).is_err() && bytes.iter().all(|b| *b == 0),
                "invalid chunk did not terminate reader",
            )
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn pg_descriptor_is_only_a_snapshot_after_source_revocation() {
    with_fixture("arb_snapshot", false, |f| async move {
        let r = f.save().await?;
        let record = f.observe(&r.artifact_id).await.map_err(|e| e.to_string())?;
        f.sql("DELETE FROM public.user_roles WHERE user_id='read-owner'")
            .await?;
        require(
            matches!(
                f.observe(&r.artifact_id).await,
                Err(ArtifactAdministrationError::NotVisible)
            ),
            "fresh source revocation ignored",
        )?;
        let store = Arc::clone(&f.store);
        tokio::task::spawn_blocking(move || {
            // Deliberately proves the limitation: this physical FD bridge observes historical
            // bytes only, so it is not wired to a public transport or a current authorization port.
            let mut reader = store
                .open_observed_record(record)
                .map_err(|e| e.to_string())?;
            let mut bytes = [0; 80];
            let n = reader
                .read_observed_chunk(&mut bytes)
                .map_err(|e| e.to_string())?;
            require(
                &bytes[..n] == EXACT.as_bytes(),
                "snapshot physical evidence did not identify the original object",
            )
        })
        .await
        .map_err(|e| e.to_string())?
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn cancelled_waiter_keeps_actual_root_owner_until_blocking_reader_really_ends() {
    with_fixture("arb_lifetime", false, |f| async move {
        let r = f.save().await?;
        let record = f.observe(&r.artifact_id).await.map_err(|e| e.to_string())?;
        let Fixture {
            store,
            administration,
            root,
            ..
        } = f;
        let weak = Arc::downgrade(&store);
        let worker_store = Arc::clone(&store);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let outcome = (|| {
                    let mut reader = worker_store
                        .open_observed_record(record)
                        .map_err(|e| e.to_string())?;
                    entered_tx
                        .send(())
                        .map_err(|_| "worker entry receiver dropped".to_owned())?;
                    release_rx
                        .recv_timeout(Duration::from_secs(10))
                        .map_err(|e| e.to_string())?;
                    let mut bytes = [0; 80];
                    let n = reader
                        .read_observed_chunk(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    require(
                        &bytes[..n] == EXACT.as_bytes(),
                        "cancelled waiter changed actual worker bytes",
                    )
                })();
                drop(worker_store);
                let _ = done_tx.send(outcome);
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), entered_rx)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        waiter.abort();
        drop(waiter);
        drop(administration);
        drop(store);
        let attempted = File::open(&root.0).map_err(|e| e.to_string())?;
        require(
            attempted.try_lock().is_err() && weak.upgrade().is_some(),
            "cancelled waiter released live root owner",
        )?;
        release_tx.send(()).map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(10), done_rx)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())??;
        require(
            weak.upgrade().is_none(),
            "actual completed worker retained a store owner",
        )?;
        require(
            attempted.try_lock().is_ok(),
            "actual worker end did not release kernel root owner",
        )
    })
    .await;
}

#[test]
fn physical_record_binding_keeps_the_frozen_sixty_four_mib_ceiling() {
    let id = Uuid::now_v7();
    assert!(ArtifactBlob::from_record(id, MAX_ARTIFACT_BYTES, [0; 32]).is_ok());
    assert_eq!(
        ArtifactBlob::from_record(id, MAX_ARTIFACT_BYTES + 1, [0; 32]).unwrap_err(),
        ArtifactByteError::TooLarge
    );
    // Pure physical construction is explicitly not the private owned-PG mint.
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn copied_marker_root_cannot_become_an_actual_store_for_the_original_dataset() {
    with_fixture("arb_copy_root", false, |f| async move {
        let r = f.save().await?;
        let root = OwnedRoot::new()?;
        let marker = root.0.join(".artifact-store-v1");
        fs::copy(f.root.0.join(".artifact-store-v1"), &marker).map_err(|e| e.to_string())?;
        fs::set_permissions(&marker, Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
        let adopted = DatasetBoundArtifactStore::bind_host_root(
            File::open(&root.0).map_err(|e| e.to_string())?,
            Arc::clone(&f.registry),
            ArtifactQuotaPolicy::default(),
        )
        .await;
        require(
            matches!(adopted, Err(ArtifactStoreError::BindingMismatch)),
            "copied marker became a restore/Store proof",
        )?;
        require(
            f.read_all(&r.artifact_id).await? == EXACT.as_bytes(),
            "copied marker changed original Store",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_run_and_thread_harddelete_hide_records_but_do_not_erase_saved_bytes() {
    for delete_thread in [false, true] {
        with_fixture(
            if delete_thread {
                "arb_thread_delete"
            } else {
                "arb_run_delete"
            },
            false,
            |f| async move {
                let r = f.save().await?;
                let runtime = PostgresRunRuntime::new(
                    f.pool.clone(),
                    "read-bridge-fixture-owner".to_owned(),
                    DEFAULT_THREAD_LEASE_DURATION,
                    DEFAULT_DISPATCH_CLAIM_DURATION,
                )
                .map_err(|e| e.to_string())?;
                let claim = runtime
                    .claim_dispatch()
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("actual dispatch missing before harddelete")?;
                let lease = runtime
                    .acknowledge_dispatch(&claim)
                    .await
                    .map_err(|e| e.to_string())?;
                runtime
                    .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
                    .await
                    .map_err(|e| e.to_string())?;
                let client = f.pool.get().await.map_err(|e| e.to_string())?;
                let terminal = client
                    .query_one(
                        "SELECT status FROM public.runs WHERE run_id=$1",
                        &[&f.begin.command.run_id.as_str()],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                require(
                    terminal.get::<_, String>("status") == "completed",
                    "source was not completed before harddelete",
                )?;
                let occupancy = client
                    .query_one(
                        "SELECT count(*) AS remaining FROM public.thread_run_occupancy WHERE run_id=$1",
                        &[&f.begin.command.run_id.as_str()],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                require(
                    occupancy.get::<_, i64>("remaining") == 0,
                    "actual terminal retained occupancy before harddelete",
                )?;
                if delete_thread {
                    client
                        .execute(
                            "DELETE FROM public.threads WHERE thread_id=$1",
                            &[&f.begin.command.thread_id.as_str()],
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    client
                        .execute(
                            "DELETE FROM public.runs WHERE run_id=$1",
                            &[&f.begin.command.run_id.as_str()],
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                }
                require(
                    matches!(
                        f.observe(&r.artifact_id).await,
                        Err(ArtifactAdministrationError::NotVisible)
                    ),
                    "deleted run/thread still minted descriptor",
                )?;
                require(
                    fs::read(f.object(&r.artifact_id)).map_err(|e| e.to_string())?
                        == EXACT.as_bytes(),
                    "read erased independent saved bytes",
                )
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn final_joint_statement_observes_source_revocation_after_its_actual_relation_wait() {
    with_fixture("arb_final_wait",false,|f|async move{
        let r=f.save().await?;
        let (reached_tx,reached_rx)=tokio::sync::oneshot::channel();
        let (proceed_tx,proceed_rx)=tokio::sync::oneshot::channel();
        let auth=f.auth();
        let observe=f.administration.observe_read_record_inner(&auth,&r.artifact_id,Some((reached_tx,proceed_rx)));
        let change=async {
            reached_rx.await.map_err(|_|"real observe flow did not reach its final-query gate".to_owned())?;
            let mut blocker=f.pool.get().await.map_err(|e|e.to_string())?;
            let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
            let mutation=async {
                tx.batch_execute("LOCK TABLE public.user_roles IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
                proceed_tx.send(()).map_err(|_|"real observer ended before final query was released".to_owned())?;
                let observer=f.pool.get().await.map_err(|e|e.to_string())?;
                // The marker follows the 1481-byte visible_run CTE; PostgreSQL's 1kB default
                // truncates it. The owned QA contract fixes track_activity_query_size=16384.
                let width:i64=observer.query_one("SELECT pg_catalog.pg_size_bytes(pg_catalog.current_setting('track_activity_query_size'))",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
                require(width>=16_384,"owned PostgreSQL track_activity_query_size was not actually sixteen KiB")?;
                let mut actual_wait=false;
                for _ in 0..150 {
                    let held:bool=observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND a.query LIKE '%artifact_private_read_record_snapshot%' AND a.wait_event_type='Lock' AND cardinality(pg_blocking_pids(a.pid))>0)",&[]).await.map_err(|e|e.to_string())?.try_get(0).map_err(|e|e.to_string())?;
                    if held {actual_wait=true;break;}
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                require(actual_wait,"actual final joint statement never reached the owned relation lock")?;
                eprintln!("ARTIFACT_READ_BRIDGE_FINAL_QUERY actual_pg_relation_wait=true");
                tx.batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='read-owner'").await.map_err(|e|e.to_string())
            }.await;
            // Always release the actual controller lock before reporting a fixture failure.
            let commit=tx.commit().await.map_err(|e|e.to_string());
            eprintln!("ARTIFACT_READ_BRIDGE_FINAL_QUERY controller_commit_ack={}",commit.is_ok());
            mutation?;commit
        };
        let(result,controller)=tokio::join!(observe,change);controller?;
        require(matches!(result,Err(ArtifactAdministrationError::NotVisible)),"joint current snapshot predated the actual relation wait")
    }).await;
}
