//! Genuine Prepared/DesktopLocalBackgroundOwner and original local read resource ownership.
//! Only controlled app/bundle directories and own-PID inode observations are used.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::super::DesktopTauriProtocol;
use crate::InProcessTransport;
use crate::desktop_vault::ReviewedDesktopVaultKeyStoreService;
use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
use crate::postgres_sidecar::{
    POSTGRES_SOURCE_SHA256, POSTGRES_VERSION, PostgresBundleDigest,
    ReviewedPostgresKeyStoreService, ReviewedPostgresSigningIdentity, VerifiedPostgresBundle,
};
use crate::tauri_background::{
    DesktopLocalApplicationInput, DesktopLocalReleaseInput, DesktopLocalRuntimeConfig,
    DesktopLocalRuntimePhase, DesktopLocalRuntimeState, PreparedDesktopLocalRuntime,
    prepare_desktop_local_runtime,
};
use crate::{DesktopAgentBudgets, DesktopOpenAiProviderInput};
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{BotId, RunId, thread::ThreadIdentity};
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tracing::instrument::WithSubscriber as _;

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

#[derive(Clone, Copy)]
enum GatePhase {
    PartialIo,
}
struct ReadGate {
    phase: GatePhase,
    entered: tokio::sync::Notify,
    io_seen: AtomicBool,
    reached: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl ReadGate {
    fn new(phase: GatePhase) -> Arc<Self> {
        Arc::new(Self {
            phase,
            entered: tokio::sync::Notify::new(),
            io_seen: AtomicBool::new(false),
            reached: AtomicBool::new(false),
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
        if self.reached.swap(true, Ordering::SeqCst) {
            return;
        }
        self.entered.notify_one();
        let released = self.released.lock().unwrap();
        let (_released, timed_out) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(2), |released| !*released)
            .unwrap();
        self.timed_out
            .store(timed_out.timed_out(), Ordering::SeqCst);
    }
}
struct ReleaseReadGate(Arc<ReadGate>);
impl Drop for ReleaseReadGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct PhaseVisitor {
    partial: bool,
    io: bool,
    ready: bool,
}
impl tracing::field::Visit for PhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match (field.name(), value) {
            ("artifact_read_lifecycle_phase", "physical_segment_completed_before_more_io") => {
                self.partial = true
            }
            ("artifact_read_phase", "actual_io_completed_before_joint") => self.io = true,
            ("artifact_read_phase", "joint_statement_ready") => self.ready = true,
            _ => {}
        }
    }
}
struct ReadSubscriber(Arc<ReadGate>);
impl tracing::Subscriber for ReadSubscriber {
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
        let mut visitor = PhaseVisitor {
            partial: false,
            io: false,
            ready: false,
        };
        event.record(&mut visitor);
        if visitor.io {
            self.0.io_seen.store(true, Ordering::SeqCst);
        }
        match self.0.phase {
            GatePhase::PartialIo if visitor.partial => self.0.hold(),
            _ => {}
        }
    }
}

// Read only this Rust process's bounded f/device/inode inventory. No path fields or peer PIDs.
fn owned_file_fds(path: &Path) -> Result<BTreeSet<u32>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<BTreeSet<u32>, String> {
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
        let mut found = BTreeSet::new();
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

async fn await_gate(gate: &ReadGate) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .map_err(|_| "actual original worker/ready phase was not reached".to_owned())?;
    require(
        gate.reached.load(Ordering::SeqCst) && !gate.timed_out.load(Ordering::SeqCst),
        "actual gate expired",
    )
}

struct OwnedRoot(PathBuf, bool);
impl OwnedRoot {
    fn new(label: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "openbot-lifecycle-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| error.to_string())?;
        let mut owned = Self(path, true);
        let before = std::fs::symlink_metadata(&owned.0).map_err(|error| error.to_string())?;
        let canonical = std::fs::canonicalize(&owned.0).map_err(|error| error.to_string())?;
        let after = std::fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
        require(
            before.file_type().is_dir()
                && !before.file_type().is_symlink()
                && after.file_type().is_dir()
                && !after.file_type().is_symlink()
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.uid() == after.uid()
                && before.mode() & 0o7777 == 0o700
                && after.mode() & 0o7777 == 0o700,
            "owned Local root canonicalization changed the original private inode",
        )?;
        owned.0 = canonical;
        Ok(owned)
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if !self.1 {
            eprintln!("ARTIFACT_LIFECYCLE_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "ARTIFACT_LIFECYCLE_LOCAL_OWNED_ROOT removed={} absent={}",
            removed.is_ok(),
            !self.0.exists()
        );
        if !std::thread::panicking() {
            assert!(
                removed.is_ok() && !self.0.exists(),
                "owned lifecycle root cleanup failed"
            );
        }
    }
}

#[derive(Default)]
struct MemorySecretStore(Mutex<BTreeMap<(String, String), Vec<u8>>>);
impl OsSecretStore for MemorySecretStore {
    fn read(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        self.0
            .lock()
            .map(|values| {
                values
                    .get(&(service.to_owned(), account.to_owned()))
                    .cloned()
                    .map(SecretBytes::new)
            })
            .map_err(|_| OsSecretStoreError::Unknown)
    }
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        self.0
            .lock()
            .map_err(|_| OsSecretStoreError::Unknown)?
            .insert((service.to_owned(), account.to_owned()), secret.to_vec());
        Ok(())
    }
}

struct OwnedBundle {
    root: OwnedRoot,
    digest: PostgresBundleDigest,
    signing: ReviewedPostgresSigningIdentity,
}
impl OwnedBundle {
    fn materialize() -> Result<Self, String> {
        let bin = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_PG_BIN")
                .ok_or("Root-owned PostgreSQL binary directory is required")?,
        );
        require(
            bin.is_absolute(),
            "owned PostgreSQL bin directory is not absolute",
        )?;
        let configuration = |option: &str| -> Result<String, String> {
            let output = Command::new(bin.join("pg_config"))
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .arg(option)
                .stdin(Stdio::null())
                .output()
                .map_err(|_| "matching pg_config unavailable")?;
            require(
                output.status.success()
                    && output.stdout.len() <= 4096
                    && output.stderr.len() <= 4096,
                "owned pg_config failed or was unbounded",
            )?;
            String::from_utf8(output.stdout)
                .map(|value| value.trim().to_owned())
                .map_err(|_| "pg_config output invalid".to_owned())
        };
        require(
            configuration("--version")? == format!("PostgreSQL {POSTGRES_VERSION}"),
            "owned PG installation is not the exact pinned version",
        )?;
        require(
            std::fs::canonicalize(configuration("--bindir")?).map_err(|error| error.to_string())?
                == std::fs::canonicalize(&bin).map_err(|error| error.to_string())?,
            "pg_config and actual binary installation differ",
        )?;
        let share = PathBuf::from(configuration("--sharedir")?);
        let library = PathBuf::from(configuration("--pkglibdir")?);
        require(
            share.is_absolute() && library.is_absolute(),
            "owned PG resource paths are not absolute",
        )?;
        let root = OwnedRoot::new("bundle")?;
        std::fs::create_dir(root.0.join("bin")).map_err(|error| error.to_string())?;
        std::fs::create_dir(root.0.join("share")).map_err(|error| error.to_string())?;
        std::fs::create_dir(root.0.join("lib")).map_err(|error| error.to_string())?;
        let mut copied_files = 0;
        let mut copied_bytes = 0;
        for name in ["postgres", "initdb", "pg_ctl"] {
            copy_resources(
                &bin.join(name),
                &root.0.join("bin").join(name),
                0,
                &mut copied_files,
                &mut copied_bytes,
            )?;
        }
        copy_resources(
            &share,
            &root.0.join("share/postgresql"),
            0,
            &mut copied_files,
            &mut copied_bytes,
        )?;
        copy_resources(
            &library,
            &root.0.join("lib/postgresql"),
            0,
            &mut copied_files,
            &mut copied_bytes,
        )?;
        for required in [
            "share/postgresql/postgres.bki",
            "share/postgresql/information_schema.sql",
            "lib/postgresql/plpgsql.dylib",
        ] {
            require(
                root.0.join(required).is_file(),
                "actual PG bootstrap resource missing",
            )?;
        }
        let mut files = BTreeMap::new();
        inventory_hashes(&root.0, &root.0, &mut files)?;
        let signing_text = "Developer ID Application: Example Product (ABCDE12345)";
        let signing = ReviewedPostgresSigningIdentity::from_reviewed_release(signing_text)
            .map_err(|error| error.to_string())?;
        let manifest = serde_json::json!({
            "schema": "openbot-postgres-sidecar-bundle", "schema_version": 1,
            "platform": "macos", "arch": std::env::consts::ARCH,
            "postgresql_version": POSTGRES_VERSION, "source_archive_sha256": POSTGRES_SOURCE_SHA256,
            "release_epoch": ENGINE_RELEASE_EPOCH, "minimum_compatible_core": env!("CARGO_PKG_VERSION"),
            "signing_identity": signing_text,
            "programs": { "postgres": "bin/postgres", "initdb": "bin/initdb", "pg_ctl": "bin/pg_ctl" },
            "files": files,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= 1024 * 1024,
            "owned PG manifest exceeded the existing bound",
        )?;
        std::fs::write(root.0.join("manifest.json"), &bytes).map_err(|error| error.to_string())?;
        let digest = PostgresBundleDigest::from_hex(&format!("{:x}", Sha256::digest(&bytes)))
            .map_err(|error| error.to_string())?;
        // Exact inventory/hash verification is real; this controlled fixture is not release-signing acceptance.
        VerifiedPostgresBundle::open(&root.0, digest, &signing)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            root,
            digest,
            signing,
        })
    }
    fn open(&self) -> Result<VerifiedPostgresBundle, String> {
        VerifiedPostgresBundle::open(&self.root.0, self.digest, &self.signing)
            .map_err(|error| error.to_string())
    }
}

fn copy_resources(
    source: &Path,
    destination: &Path,
    depth: usize,
    files: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    require(depth <= 32, "owned PG resource depth exceeded")?;
    let metadata = std::fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        std::fs::create_dir(destination).map_err(|error| error.to_string())?;
        for entry in std::fs::read_dir(source).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            copy_resources(
                &entry.path(),
                &destination.join(entry.file_name()),
                depth + 1,
                files,
                bytes,
            )?;
        }
    } else {
        require(
            metadata.is_file() && *files < 8192,
            "owned PG resource is not regular or file budget exceeded",
        )?;
        *bytes = bytes
            .checked_add(metadata.len())
            .filter(|bytes| *bytes <= 2 * 1024 * 1024 * 1024)
            .ok_or("owned PG resource byte budget exceeded")?;
        std::fs::copy(source, destination).map_err(|error| error.to_string())?;
        *files += 1;
    }
    Ok(())
}
fn inventory_hashes(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if std::fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            inventory_hashes(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "owned inventory escaped root")?
                .to_str()
                .ok_or("owned inventory is not UTF-8")?
                .to_owned();
            let mut file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 65_536];
            loop {
                let length = file.read(&mut buffer).map_err(|error| error.to_string())?;
                if length == 0 {
                    break;
                }
                digest.update(&buffer[..length]);
            }
            files.insert(relative, format!("{:x}", digest.finalize()));
        }
    }
    Ok(())
}

fn package(
    tenant: &str,
) -> Result<LoadedTenantPackage, openbot_application::tenant::package::TenantPackageError> {
    let files = TenantPackageFiles {
        brand: format!("tenant: {{ id: {tenant}, product_name: Desktop Local }}"),
        agents: "agents: [{ id: desktop-assistant, name: Assistant, title: Local Assistant, role_description: Help locally., type: built-in, system_prompt: Answer carefully. }]".to_owned(),
        channels: "channels: [{ id: desktop-home, name: Home, description: Local home., permitted_agents: [desktop-assistant], allowed_groups: [all] }]".to_owned(),
        model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }".to_owned(),
        knowledge: "sources: []".to_owned(),
    };
    LoadedTenantPackage::new(
        validate_tenant_package(files)?,
        "/controlled/local-lifecycle-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    assets: PathBuf,
    prepared: Option<PreparedDesktopLocalRuntime>,
    artifact: ArtifactRegistrationReceipt,
    payload: String,
    postmaster_pid: u32,
}
impl LocalFixture {
    async fn new(bundle: &OwnedBundle, label: &str) -> Result<Self, String> {
        let mut root = OwnedRoot::new(label)?;
        let assets = root.0.join("assets");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|error| error.to_string())?;
        std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|error| error.to_string())?;
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|error| error.to_string())?;
        let release = DesktopLocalReleaseInput::new(
            &assets,
            "openbot",
            "main",
            bundle.open()?,
            ReviewedPostgresKeyStoreService::from_reviewed_release(
                "com.example.review.lifecycle-scram",
            )
            .map_err(|error| error.to_string())?,
            ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
                "com.example.review.lifecycle-vault",
            )
            .map_err(|error| error.to_string())?,
            Arc::new(MemorySecretStore::default()),
        )
        .map_err(|error| error.to_string())?;
        // No provider credential is stored, and this fixture never supplies a network reply.
        let application = DesktopLocalApplicationInput::new(
            DesktopOpenAiProviderInput::new(
                "https://api.example.test/v1",
                vec!["203.0.113.0/24".to_owned()],
            )
            .map_err(|error| error.to_string())?,
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        root.1 = false;
        let prepared = prepare_desktop_local_runtime(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root.0)
                .map_err(|error| error.to_string())?,
            DesktopLocalRuntimeConfig::new(release, application, |authority| {
                package(authority.auth_context().tenant().as_str())
            }),
        )
        .await
        .map_err(|error| error.to_string())?;
        let populated = async {
            prepared.protocol().bind_window("main", prepared.auth_context().clone(), None).map_err(|error| error.to_string())?;
            let auth = prepared.protocol().windows.try_read().map_err(|_| "actual window lock unavailable")?.get("main").ok_or("actual main missing")?.auth.clone();
            let begin = BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy([9; 16]),
                run_id: RunId::new("actual/local-lifecycle-run"), bot_id: BotId::new("desktop-assistant"),
                anchor: ThreadRunAnchor::DirectBot, message: "small actual local Begin".to_owned(), selected_skill_slugs: Vec::new(), model_selection: None,
            };
            require(matches!(prepared.application().execute(auth.clone(), AppCommand::BeginThreadRun(begin.clone())).await.map_err(|error| error.to_string())?, AppReply::ThreadRunStarted(_)), "actual Local Begin did not return its durable receipt")?;
            // The real Local runtime settles this provider-less Run in its own Run-locked
            // transaction (now also carrying the per-transaction 0051 writer observation);
            // the fixture's own NOWAIT source save must not race that background settlement.
            let settled = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let status: String = prepared.pool().get().await.map_err(|error| error.to_string())?
                        .query_one("SELECT status FROM public.runs WHERE run_id=$1", &[&begin.run_id.as_str()])
                        .await.map_err(|error| error.to_string())?.get(0);
                    if status != "queued" && status != "running" { return Ok::<_, String>(()); }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.map_err(|_| "actual Local runtime did not settle the begun Run".to_owned())?;
            settled?;
            let payload = "D".repeat(256 * 1024);
            let source = format!("{}:input", begin.run_id.as_str());
            let changed = prepared.pool().get().await.map_err(|error| error.to_string())?.execute(
                "UPDATE public.messages SET content=jsonb_set(content,'{text}',to_jsonb($2::text)), search_text=$2 WHERE message_id=$1", &[&source, &payload],
            ).await.map_err(|error| error.to_string())?;
            require(changed == 1, "owned Local fixture did not mutate exactly its small Begin source")?;
            // This controlled UPDATE is not acceptance of a larger public Begin input.
            let receipt = prepared.application().execute(auth, AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: uuid::Uuid::now_v7().to_string(), source_thread_id: begin.thread_id, source_run_id: begin.run_id,
                source_message_id: source, expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
            })).await.map_err(|error| error.to_string())?;
            let artifact = match receipt { AppReply::ArtifactRegistrationReceipt(receipt) => receipt, _ => return Err("actual Local Save returned another reply".to_owned()) };
            let mut pids = Vec::new();
            for entry in std::fs::read_dir(&root.0).map_err(|error| error.to_string())? {
                let path = entry.map_err(|error| error.to_string())?.path();
                if path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("postgresql-17-")) && path.is_dir() {
                    let pid = std::fs::read_to_string(path.join("postmaster.pid")).map_err(|error| error.to_string())?.lines().next().ok_or("actual postmaster PID missing")?.parse::<u32>().map_err(|_| "actual postmaster PID invalid")?;
                    require(pid > 1, "owned postmaster PID is invalid")?; pids.push(pid);
                }
            }
            require(pids.len() == 1, "genuine Prepared did not own exactly one controlled sidecar")?;
            Ok::<_, String>((artifact, payload, pids[0]))
        }.await;
        match populated {
            Ok((artifact, payload, postmaster_pid)) => {
                root.1 = true;
                eprintln!(
                    "ARTIFACT_LIFECYCLE_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={}",
                    root.0.display()
                );
                Ok(Self {
                    root,
                    assets,
                    prepared: Some(prepared),
                    artifact,
                    payload,
                    postmaster_pid,
                })
            }
            Err(error) => {
                let cleaned = prepared.shutdown().await;
                if cleaned.is_ok() {
                    root.1 = true;
                }
                require(
                    cleaned.is_ok(),
                    "failed real Prepared fixture setup cleanup did not ACK",
                )?;
                Err(error)
            }
        }
    }
    fn prepared(&self) -> &PreparedDesktopLocalRuntime {
        self.prepared
            .as_ref()
            .expect("actual Prepared not transferred yet")
    }
    fn artifact_path(&self) -> PathBuf {
        self.root
            .0
            .join("artifacts/objects")
            .join(&self.artifact.artifact_id)
    }
    fn tracker(
        &self,
    ) -> Result<Arc<openbot_infra::artifact_read_lifecycle::ArtifactReadLifecycle>, String> {
        self.prepared()
            .protocol()
            .local_capability_authority
            .as_ref()
            .and_then(|source| source.artifact_read_lifecycle())
            .ok_or("same actual Local read tracker was unavailable; no ACK")
            .map_err(str::to_owned)
    }
    fn new_protocol(&self) -> Result<Arc<DesktopTauriProtocol>, String> {
        let source = self
            .prepared()
            .protocol()
            .local_capability_authority
            .clone()
            .ok_or("actual Local identity source missing")?;
        DesktopTauriProtocol::open(
            &self.assets,
            Arc::new(InProcessTransport::new(
                self.prepared().application().clone(),
            )),
        )
        .map(|protocol| Arc::new(protocol.with_current_identity_source(source)))
        .map_err(|error| error.to_string())
    }
    async fn finish(mut self) -> Result<(), String> {
        let closing_ok = match self.prepared.take() {
            Some(prepared) => prepared.shutdown().await.is_ok(),
            None => true,
        };
        self.root.1 = false;
        require(
            !owned_postmaster_live(self.postmaster_pid)?,
            "original owned postmaster PID survived real shutdown",
        )?;
        self.root.1 = true;
        require(closing_ok, "genuine BackgroundOwner cleanup did not ACK")?;
        eprintln!(
            "ARTIFACT_LIFECYCLE_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true",
            self.postmaster_pid
        );
        Ok(())
    }
}

fn owned_postmaster_live(pid: u32) -> Result<bool, String> {
    let status = Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "owned postmaster liveness observation failed")?;
    Ok(status.success())
}
async fn real_terminal_state(
    state: &DesktopLocalRuntimeState,
) -> Result<DesktopLocalRuntimePhase, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let phase = state.phase();
        if matches!(
            phase,
            DesktopLocalRuntimePhase::Stopped | DesktopLocalRuntimePhase::Failed
        ) {
            return Ok(phase);
        }
        if Instant::now() >= deadline {
            return Err(
                "actual closing job never reached its real terminal state (Unproven)".to_owned(),
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn require_original_job_unacknowledged(state: &DesktopLocalRuntimeState) -> Result<(), String> {
    let (drain, postgres, finished, outcome) =
        state
            .closing_acknowledgements_for_reviewed_test()
            .ok_or("actual closing observation unavailable (Unproven)")?;
    require(
        drain.is_none() && postgres.is_none() && finished.is_none() && outcome.is_none(),
        "held original resource already acquired a closing job ACK/outcome",
    )
}

fn require_original_job_acknowledged(
    state: &DesktopLocalRuntimeState,
    succeeded: bool,
) -> Result<(), String> {
    let (Some(drain), Some(postgres), Some(finished), Some(outcome)) = state
        .closing_acknowledgements_for_reviewed_test()
        .ok_or("actual closing observation unavailable (Unproven)")?
    else {
        return Err(
            "actual drain/pg_ctl/job completion ACK or known outcome was missing (Unproven)"
                .to_owned(),
        );
    };
    require(
        drain <= postgres && postgres <= finished && outcome == succeeded,
        "actual closing ACK order/outcome differs; Unknown is not completed teardown",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine Prepared/owned sidecar and own-PID original FD observation; four inline facts"]
async fn actual_local_partial_worker_window_close_and_owner_collision_drains() {
    let bundle = OwnedBundle::materialize().unwrap();
    for variant in [
        "unbind",
        "rebind",
        "last_owner_drop",
        "same_label_id_other_owner",
    ] {
        let fixture = LocalFixture::new(&bundle, variant).await.unwrap();
        let mut protocol = Some(fixture.new_protocol().unwrap());
        protocol
            .as_ref()
            .unwrap()
            .bind_window("main", fixture.prepared().auth_context().clone(), None)
            .unwrap();
        let peer = fixture.new_protocol().unwrap();
        peer.bind_window("main", fixture.prepared().auth_context().clone(), None)
            .unwrap();
        let mut operation = protocol
            .as_ref()
            .unwrap()
            .open_current_artifact_read("main", fixture.artifact.artifact_id.clone())
            .await
            .unwrap();
        let path = fixture.artifact_path();
        let tracker = fixture.tracker().unwrap();
        let gate = ReadGate::new(GatePhase::PartialIo);
        let _release = ReleaseReadGate(gate.clone());
        let task = tokio::spawn(
            async move { operation.next_block().await }
                .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))),
        );
        let attempted = async {
            await_gate(&gate).await?;
            let original_fds = owned_file_fds(&path)?;
            require(
                original_fds.len() == 1,
                "genuine Local partial worker original FD missing/ambiguous",
            )?;
            {
                let a = protocol
                    .as_ref()
                    .unwrap()
                    .windows
                    .try_read()
                    .map_err(|_| "actual original window lock unavailable")?;
                let b = peer
                    .windows
                    .try_read()
                    .map_err(|_| "actual peer window lock unavailable")?;
                let a = a.get("main").ok_or("original main missing")?;
                let b = b.get("main").ok_or("peer main missing")?;
                require(
                    a.binding_id == b.binding_id
                        && a.auth.actor() == b.auth.actor()
                        && a.auth.auth_generation() == b.auth.auth_generation(),
                    "owner collision fixture did not share actual label/counter/actor/generation",
                )?;
                require(
                    !a.auth
                        .request_binding()
                        .ok_or("original binding missing")?
                        .identity()
                        .same_binding(
                            b.auth
                                .request_binding()
                                .ok_or("peer binding missing")?
                                .identity(),
                        ),
                    "independent Protocol owners accidentally share a binding",
                )?;
            }
            match variant {
                "unbind" => {
                    require(
                        protocol
                            .as_ref()
                            .unwrap()
                            .unbind_window("main")
                            .map_err(|error| error.to_string())?,
                        "actual original window was not unbound",
                    )?;
                }
                "rebind" => {
                    require(
                        protocol
                            .as_ref()
                            .unwrap()
                            .unbind_window("main")
                            .map_err(|error| error.to_string())?,
                        "original window was not removed before replacement",
                    )?;
                    protocol
                        .as_ref()
                        .unwrap()
                        .bind_window("main", fixture.prepared().auth_context().clone(), None)
                        .map_err(|error| error.to_string())?;
                }
                "last_owner_drop" => {
                    drop(protocol.take());
                }
                "same_label_id_other_owner" => {
                    protocol.as_ref().unwrap().close_request_bindings();
                }
                _ => return Err("unregistered Local matrix case".to_owned()),
            }
            // This real peer consumes through its independent owner before global close.
            let mut peer_operation = peer
                .open_current_artifact_read("main", fixture.artifact.artifact_id.clone())
                .await
                .map_err(|error| error.to_string())?;
            let peer_block = peer_operation
                .next_block()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("actual unaffected peer returned EOF")?;
            require(
                peer_block.as_bytes() == fixture.payload.as_bytes(),
                "scope close leaked into the independently owned same-label peer",
            )?;
            drop(peer_block);
            drop(peer_operation);
            tracker.close();
            require(
                tokio::time::timeout(Duration::from_millis(20), tracker.drain())
                    .await
                    .is_err(),
                "real partial Local worker falsely drained before completion",
            )?;
            require(
                owned_file_fds(&path)? == original_fds,
                "Window/owner close replaced or ended original FD while worker was physically held",
            )?;
            require(
                !gate.timed_out.load(Ordering::SeqCst),
                "actual Local partial barrier expired",
            )
        }
        .await;
        gate.release();
        let result = task.await;
        tracker.close();
        let drained = tracker
            .drain_before(Instant::now() + Duration::from_secs(5))
            .await;
        drop(protocol);
        drop(peer);
        let outcome = async {
            attempted?;
            require(matches!(result.map_err(|error| error.to_string())?, Err(AppError::Unauthenticated)), "closed original Local worker returned bytes or lost host-first 401")?;
            require(drained.is_ok() && owned_file_fds(&path)?.is_empty(), "actual Local worker/FD did not drain after true completion")?;
            eprintln!("ARTIFACT_LIFECYCLE_LOCAL_SCOPE inline_fact={variant} genuine_prepared=true partial_actual=true original_host_401=true independent_peer_positive=true original_fd_absent=true drain_ack=true");
            Ok::<(), String>(())
        }.await;
        let cleanup = fixture.finish().await;
        outcome.and(cleanup).unwrap();
    }
}

async fn held_worker_shutdown(fixture: &mut LocalFixture, poll_waiter: bool) -> Result<(), String> {
    let mut operation = fixture
        .prepared()
        .protocol()
        .open_current_artifact_read("main", fixture.artifact.artifact_id.clone())
        .await
        .map_err(|error| error.to_string())?;
    let path = fixture.artifact_path();
    let pool = fixture.prepared().pool().clone();
    let tracker = fixture.tracker()?;
    let gate = ReadGate::new(GatePhase::PartialIo);
    let _release = ReleaseReadGate(gate.clone());
    let task = tokio::spawn(
        async move { operation.next_block().await }
            .with_subscriber(tracing::Dispatch::new(ReadSubscriber(gate.clone()))),
    );
    let mut state = None;
    let attempted = async {
        await_gate(&gate).await?;
        let original_fds = owned_file_fds(&path)?;
        require(
            original_fds.len() == 1,
            "actual shutdown partial worker did not hold its original FD",
        )?;
        let (actual_state, mut waiter) = fixture
            .prepared
            .take()
            .ok_or("actual Prepared owner missing")?
            .start_closing_for_reviewed_test()
            .map_err(|error| error.to_string())?;
        state = Some(actual_state.clone());
        if poll_waiter {
            require(
                tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                    .await
                    .is_err(),
                "polled closing waiter falsely ACKed a physically held worker",
            )?;
        }
        drop(waiter);
        tokio::time::sleep(Duration::from_millis(20)).await;
        require(
            actual_state.phase() == DesktopLocalRuntimePhase::Stopping,
            "dropping original closing observer published an early terminal state",
        )?;
        require_original_job_unacknowledged(&actual_state)?;
        require(
            owned_postmaster_live(fixture.postmaster_pid)?,
            "dropping closing observer killed actual original sidecar before read drain",
        )?;
        require(
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .query_one("SELECT 1::integer", &[])
                .await
                .map_err(|error| error.to_string())?
                .get::<_, i32>(0)
                == 1,
            "original Pool was closed before actual read drain",
        )?;
        require(
            owned_file_fds(&path)? == original_fds && !gate.timed_out.load(Ordering::SeqCst),
            "closing observer Drop ended/replaced original active FD or barrier expired",
        )
    }
    .await;
    gate.release();
    let result = task.await;
    tracker.close();
    let drained = tracker
        .drain_before(Instant::now() + Duration::from_secs(5))
        .await;
    let terminal = match &state {
        Some(state) => Some(real_terminal_state(state).await),
        None => None,
    };
    attempted?;
    require(
        matches!(
            result.map_err(|error| error.to_string())?,
            Err(AppError::Unauthenticated)
        ),
        "genuine closed main window worker did not preserve host-first 401",
    )?;
    require(
        drained.is_ok(),
        "actual original worker did not yield drain ACK after real completion",
    )?;
    require(
        matches!(terminal, Some(Ok(DesktopLocalRuntimePhase::Stopped))),
        "actual closing job failed to project its successful completed teardown",
    )?;
    require_original_job_acknowledged(state.as_ref().ok_or("actual closing state missing")?, true)?;
    require(
        !owned_postmaster_live(fixture.postmaster_pid)?
            && pool.get().await.is_err()
            && owned_file_fds(&path)?.is_empty(),
        "genuine original worker/FD/Pool/sidecar resources survived real cleanup",
    )?;
    eprintln!(
        "ARTIFACT_LIFECYCLE_LOCAL_REAL_SHUTDOWN held=worker waiter_polled={poll_waiter} waiter_detached=true before_release_state=stopping original_pg_alive_before=true original_fd_alive_before=true actual_job_state=stopped original_pg_gone=true caller_ack=false"
    );
    Ok(())
}

async fn held_lease_shutdown(
    fixture: &mut LocalFixture,
    poll_waiter: bool,
    late: bool,
) -> Result<(), String> {
    let mut operation = fixture
        .prepared()
        .protocol()
        .open_current_artifact_read("main", fixture.artifact.artifact_id.clone())
        .await
        .map_err(|error| error.to_string())?;
    let block = operation
        .next_block()
        .await
        .map_err(|error| error.to_string())?
        .ok_or("genuine held leased block missing")?;
    require(
        block.as_bytes() == fixture.payload.as_bytes(),
        "original leased allocation bytes differ",
    )?;
    let path = fixture.artifact_path();
    let original_fds = owned_file_fds(&path)?;
    require(
        original_fds.len() == 1,
        "original leased block did not retain the original FD",
    )?;
    let pool = fixture.prepared().pool().clone();
    let tracker = fixture.tracker()?;
    let (state, mut waiter) = fixture
        .prepared
        .take()
        .ok_or("actual Prepared owner missing")?
        .start_closing_for_reviewed_test()
        .map_err(|error| error.to_string())?;
    let returned_at = Instant::now();
    let attempted = async {
        if poll_waiter {
            require(
                tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                    .await
                    .is_err(),
                "polled closing waiter falsely ACKed original held allocation",
            )?;
        }
        drop(waiter);
        if late {
            // Conservative observer hold starts after sync job transfer; it extends no production budget.
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                returned_at + crate::cancel::SHUTDOWN_DEADLINE + Duration::from_millis(50),
            ))
            .await;
            require(
                returned_at.elapsed() > crate::cancel::SHUTDOWN_DEADLINE,
                "held original allocation did not outlive the single original deadline",
            )?;
        } else {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        require(
            state.phase() == DesktopLocalRuntimePhase::Stopping,
            "waiter detach/deadline falsely published completion before actual resource cleanup",
        )?;
        require_original_job_unacknowledged(&state)?;
        require(
            owned_postmaster_live(fixture.postmaster_pid)?,
            "held original allocation lost its genuine sidecar owner before read drain",
        )?;
        require(
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .query_one("SELECT 1::integer", &[])
                .await
                .map_err(|error| error.to_string())?
                .get::<_, i32>(0)
                == 1,
            "original data-plane Pool was closed while original allocation was held",
        )?;
        require(
            owned_file_fds(&path)? == original_fds,
            "closing job replaced/ended the original held-allocation FD",
        )?;
        require(
            tokio::time::timeout(Duration::from_millis(20), tracker.drain())
                .await
                .is_err(),
            "held original allocation produced a false finite-inventory ACK",
        )
    }
    .await;
    drop(operation);
    drop(block);
    let drained = tracker
        .drain_before(Instant::now() + Duration::from_secs(5))
        .await;
    let terminal = real_terminal_state(&state).await;
    attempted?;
    require(
        drained.is_ok(),
        "original allocation Drop failed to yield actual inventory cleanup",
    )?;
    require(
        terminal?
            == if late {
                DesktopLocalRuntimePhase::Failed
            } else {
                DesktopLocalRuntimePhase::Stopped
            },
        "actual late cleanup renewed the deadline or normal teardown failed",
    )?;
    require_original_job_acknowledged(&state, !late)?;
    require(
        !owned_postmaster_live(fixture.postmaster_pid)?
            && pool.get().await.is_err()
            && owned_file_fds(&path)?.is_empty(),
        "actual original leased allocation/FD/Pool/sidecar resources survived cleanup",
    )?;
    eprintln!(
        "ARTIFACT_LIFECYCLE_LOCAL_REAL_SHUTDOWN held=original_lease waiter_polled={poll_waiter} late={late} waiter_detached=true original_pg_alive_before=true original_fd_alive_before=true real_drain_ack=true original_pg_gone=true caller_ack=false late_result_can_upgrade=false"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine Prepared/BackgroundOwner/DatabaseProvisioner; five original-resource shutdown facts"]
async fn real_local_database_shutdown_waits_for_original_read_resources() {
    let bundle = OwnedBundle::materialize().unwrap();
    for (held, poll_waiter, late) in [
        ("worker", false, false),
        ("worker", true, false),
        ("original_lease", false, false),
        ("original_lease", true, false),
        ("original_lease", true, true),
    ] {
        let mut fixture = LocalFixture::new(&bundle, "real-owner-shutdown")
            .await
            .unwrap();
        let outcome = if held == "worker" {
            held_worker_shutdown(&mut fixture, poll_waiter).await
        } else {
            held_lease_shutdown(&mut fixture, poll_waiter, late).await
        };
        let cleanup = fixture.finish().await;
        outcome.and(cleanup).unwrap();
    }
}
