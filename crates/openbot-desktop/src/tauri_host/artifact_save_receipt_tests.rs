//! Genuine Prepared Local/Window original Save-receipt observers, with only owned sidecar and memory secrets.
//! This fixture is not release-signing, provider-network, or full R414 acceptance.
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
    PreparedDesktopLocalRuntime, prepare_desktop_local_runtime,
};
use crate::{DesktopAgentBudgets, DesktopOpenAiProviderInput};
use http::{Method, Request, Response, StatusCode};
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_contracts::artifacts::{
    ArtifactRegistrationReceipt, GetArtifactSaveReceipt, SaveRunMessageTextArtifact,
};
use openbot_contracts::command::{AppCommand, AppReply, BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{BotId, RunId, thread::ThreadIdentity};
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tracing::instrument::WithSubscriber as _;

fn require(value: bool, message: &'static str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct OwnedRoot(PathBuf, bool);
impl OwnedRoot {
    fn new(label: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "openbot-save-receipt-{label}-{}",
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
            eprintln!("SAVE_RECEIPT_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "SAVE_RECEIPT_LOCAL_OWNED_ROOT removed={} absent={}",
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
        "/controlled/source-run-local-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    assets: PathBuf,
    prepared: Option<PreparedDesktopLocalRuntime>,
    artifact: ArtifactRegistrationReceipt,
    postmaster_pid: u32,
    postmaster_file: PathBuf,
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
            prepared
                .protocol()
                .bind_window("main", prepared.auth_context().clone(), None)
                .map_err(|error| error.to_string())?;
            let auth = prepared
                .protocol()
                .windows
                .try_read()
                .map_err(|_| "actual window lock unavailable")?
                .get("main")
                .ok_or("actual main missing")?
                .auth
                .clone();
            let payload = "genuine Local source IDs text".to_owned();
            let begin = BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy([9; 16]),
                run_id: RunId::new("actual/local-lifecycle-run"),
                bot_id: BotId::new("desktop-assistant"),
                anchor: ThreadRunAnchor::DirectBot,
                message: payload.clone(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            };
            require(
                matches!(
                    prepared
                        .application()
                        .execute(auth.clone(), AppCommand::BeginThreadRun(begin.clone()))
                        .await
                        .map_err(|error| error.to_string())?,
                    AppReply::ThreadRunStarted(_)
                ),
                "actual Local Begin did not return its durable receipt",
            )?;
            // Save locks the source run with FOR SHARE NOWAIT; wait until the dispatched run is
            // durably inactive so the single Save does not race its own terminal transition.
            let fixture_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let AppReply::ThreadConversation(conversation) = prepared
                    .application()
                    .execute(
                        auth.clone(),
                        AppCommand::GetThreadConversation {
                            thread_id: begin.thread_id.clone(),
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?
                else {
                    return Err("actual Local conversation returned another reply".to_owned());
                };
                if conversation.active_run_id.is_none() && conversation.active_run_state.is_none() {
                    break;
                }
                require(
                    tokio::time::Instant::now() < fixture_deadline,
                    "actual Local run did not become inactive before Save",
                )?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let source = format!("{}:input", begin.run_id.as_str());
            let receipt = prepared
                .application()
                .execute(
                    auth,
                    AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                        request_id: uuid::Uuid::now_v7().to_string(),
                        source_thread_id: begin.thread_id,
                        source_run_id: begin.run_id,
                        source_message_id: source,
                        expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
                    }),
                )
                .await
                .map_err(|error| error.to_string())?;
            let artifact = match receipt {
                AppReply::ArtifactRegistrationReceipt(receipt) => receipt,
                _ => return Err("actual Local Save returned another reply".to_owned()),
            };
            let mut pids = Vec::new();
            for entry in std::fs::read_dir(&root.0).map_err(|error| error.to_string())? {
                let path = entry.map_err(|error| error.to_string())?.path();
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("postgresql-17-"))
                    && path.is_dir()
                {
                    let pid = std::fs::read_to_string(path.join("postmaster.pid"))
                        .map_err(|error| error.to_string())?
                        .lines()
                        .next()
                        .ok_or("actual postmaster PID missing")?
                        .parse::<u32>()
                        .map_err(|_| "actual postmaster PID invalid")?;
                    require(pid > 1, "owned postmaster PID is invalid")?;
                    pids.push((pid, path.join("postmaster.pid")));
                }
            }
            require(
                pids.len() == 1,
                "genuine Prepared did not own exactly one controlled sidecar",
            )?;
            let (pid, file) = pids
                .into_iter()
                .next()
                .ok_or("original owned postmaster identity missing")?;
            Ok::<_, String>((artifact, pid, file))
        }
        .await;
        match populated {
            Ok((artifact, postmaster_pid, postmaster_file)) => {
                // Keep a live owned sidecar root until explicit shutdown and PID observation.
                root.1 = false;
                eprintln!(
                    "SAVE_RECEIPT_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={}",
                    root.0.display()
                );
                Ok(Self {
                    root,
                    assets,
                    prepared: Some(prepared),
                    artifact,
                    postmaster_pid,
                    postmaster_file,
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
    fn selector(&self) -> GetArtifactSaveReceipt {
        GetArtifactSaveReceipt {
            request_id: self.artifact.request_id.clone(),
        }
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.prepared()
            .pool()
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
    }
    async fn corrupt(&self, corrupt: bool) -> Result<(), String> {
        let mut client = self
            .prepared()
            .pool()
            .get()
            .await
            .map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        let digest = if corrupt {
            "f".repeat(64)
        } else {
            format!("{:x}", Sha256::digest(b"genuine Local source IDs text"))
        };
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
        require(tx.execute("UPDATE openbot_internal.artifact_save_operations SET actual_sha256=$1 WHERE artifact_id=$2",&[&digest,&self.artifact.artifact_id]).await.map_err(|e|e.to_string())?==1,"owned Local operation mutation was not exact")?;
        tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
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
    async fn facts(&self) -> Result<serde_json::Value, String> {
        self.prepared().pool().get().await.map_err(|e|e.to_string())?.query_one(
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
        let mut client = self
            .prepared()
            .pool()
            .get()
            .await
            .map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        // A controlled reader shape after a genuine Save, not a delivered deletion producer.
        tx.batch_execute("SET LOCAL session_replication_role='replica'")
            .await
            .map_err(|e| e.to_string())?;
        require(tx.execute("UPDATE openbot_internal.artifact_save_operations SET state='deleted',store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL WHERE artifact_id=$1", &[&self.artifact.artifact_id])
            .await.map_err(|e| e.to_string())? == 1, "terminal reader fixture original operation missing")?;
        require(tx.execute("UPDATE openbot_internal.artifact_records SET status='deleted',workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL WHERE artifact_id=$1", &[&self.artifact.artifact_id])
            .await.map_err(|e| e.to_string())? == 1, "terminal reader fixture original record missing")?;
        tx.commit().await.map_err(|e| e.to_string())
    }
    fn bytes(&self) -> Result<(u64, u64, u64, String), String> {
        let path = self
            .root
            .0
            .join("artifacts")
            .join("objects")
            .join(&self.artifact.artifact_id);
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "actual Local artifact is no longer regular",
        )?;
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        Ok((
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            format!("{:x}", Sha256::digest(bytes)),
        ))
    }
    async fn finish(mut self) -> Result<(), String> {
        let closing_ok = match self.prepared.take() {
            Some(prepared) => prepared.shutdown().await.is_ok(),
            None => true,
        };
        self.root.1 = false;
        require(
            !owned_postmaster_live(self.postmaster_pid)? && !self.postmaster_file.exists(),
            "original owned postmaster PID or its PID file survived real shutdown",
        )?;
        self.root.1 = true;
        require(closing_ok, "genuine BackgroundOwner cleanup did not ACK")?;
        eprintln!(
            "SAVE_RECEIPT_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true original_PID_file_gone=true",
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

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("String formatting");
        }
    }
    encoded
}
fn route(input: &GetArtifactSaveReceipt) -> String {
    format!(
        "/api/artifacts/save-requests/{}",
        encode_segment(&input.request_id)
    )
}
async fn local_request(
    protocol: &DesktopTauriProtocol,
    label: &str,
    method: Method,
    uri: &str,
    body: &'static str,
) -> Result<Response<Vec<u8>>, String> {
    let response = protocol
        .handle(
            label,
            Request::builder()
                .method(method)
                .uri(uri)
                .body(body.as_bytes().to_vec())
                .map_err(|e| e.to_string())?,
        )
        .await;
    require(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            == Some("no-store"),
        "genuine Local source response lost no-store",
    )?;
    Ok(response)
}
fn error_is(response: &Response<Vec<u8>>, status: StatusCode, code: &str) -> Result<(), String> {
    require(
        response.status() == status
            && serde_json::from_slice::<serde_json::Value>(response.body())
                .map_err(|e| e.to_string())?
                == serde_json::json!({"code":code}),
        "Local source error changed static framing or released source IDs",
    )
}
fn receipt_matches(response: &Response<Vec<u8>>, fixture: &LocalFixture) -> Result<(), String> {
    require(
        response.status() == StatusCode::OK
            && serde_json::from_slice::<serde_json::Value>(response.body())
                .map_err(|e| e.to_string())?
                == serde_json::to_value(&fixture.artifact).map_err(|e| e.to_string())?,
        "genuine Local GET changed the original bare nine-field receipt",
    )
}
fn gone_reader_matches(response: &Response<Vec<u8>>) -> Result<(), String> {
    require(
        response.status() == StatusCode::GONE
            && serde_json::from_slice::<serde_json::Value>(response.body())
                .map_err(|e| e.to_string())?
                == serde_json::json!({"code":"artifact_gone","status":"deleted"}),
        "terminal reader fixture lost its closed deleted 410 shape",
    )
}
struct OwnedWindowWriteHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl OwnedWindowWriteHold {
    fn new(
        windows: Arc<RwLock<BTreeMap<String, super::super::WindowAuthority>>>,
    ) -> Result<Self, String> {
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _map = windows
                .write()
                .map_err(|_| "owned original map holder could not acquire map".to_owned())?;
            entered
                .send(())
                .map_err(|_| "owned map holder notification closed".to_owned())?;
            finish
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| "owned map holder was not explicitly released".to_owned())?;
            Ok(())
        });
        let owned = Self {
            release: Some(release),
            worker: Some(worker),
        };
        ready
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "owned map holder acquisition was not observed".to_owned())?;
        Ok(owned)
    }
    fn finish(mut self) -> Result<(), String> {
        if let Some(release) = self.release.take() {
            release
                .send(())
                .map_err(|_| "owned map holder release was unavailable".to_owned())?;
        }
        let joined = self
            .worker
            .take()
            .ok_or("owned map holder thread missing")?
            .join()
            .map_err(|_| "owned map holder thread panicked".to_owned())?;
        eprintln!(
            "SAVE_RECEIPT_LOCAL_MAP_HOLDER actual_join_ack={} explicitly_released=true",
            joined.is_ok()
        );
        joined
    }
}
impl Drop for OwnedWindowWriteHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            eprintln!(
                "SAVE_RECEIPT_LOCAL_MAP_HOLDER fallback_join_ack={} presumed_ack=false",
                matches!(joined, Ok(Ok(())))
            );
        }
    }
}

enum HeldReceipt {
    Protocol(Result<Response<Vec<u8>>, String>),
    Application(Box<Result<AppReply, AppError>>),
}
async fn original_window_tail(
    fixture: &LocalFixture,
    source: &'static str,
    variant: &'static str,
) -> Result<(), String> {
    let mut original = Some(fixture.new_protocol()?);
    let peer = fixture.new_protocol()?;
    for protocol in [original.as_ref().unwrap(), &peer] {
        protocol
            .bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|e| e.to_string())?;
    }
    let original_authority = original
        .as_ref()
        .unwrap()
        .windows
        .try_read()
        .map_err(|_| "original source map unreadable")?
        .get("main")
        .ok_or("original source window missing")?
        .clone();
    let peer_authority = peer
        .windows
        .try_read()
        .map_err(|_| "peer source map unreadable")?
        .get("main")
        .ok_or("peer source window missing")?
        .clone();
    require(
        original_authority.binding_id == peer_authority.binding_id
            && original_authority.auth == peer_authority.auth
            && !original_authority
                .auth
                .request_binding()
                .ok_or("original binding missing")?
                .identity()
                .same_binding(
                    peer_authority
                        .auth
                        .request_binding()
                        .ok_or("peer binding missing")?
                        .identity(),
                ),
        "real Local owners did not collide on label/id/six facts with distinct issuer identities",
    )?;
    require(
        matches!(
            original
                .as_ref()
                .unwrap()
                .artifact_save_receipt_binding_current("main", &peer_authority),
            Err(AppError::Unauthenticated)
        ),
        "foreign same-label/id original owner was accepted by bounded source consumer",
    )?;
    let input = if source == "missing" {
        GetArtifactSaveReceipt {
            request_id: uuid::Uuid::now_v7().to_string(),
        }
    } else {
        fixture.selector()
    };
    if source == "corrupt" {
        fixture.corrupt(true).await?;
    }
    let uri = route(&input);
    let baseline = local_request(original.as_ref().unwrap(), "main", Method::GET, &uri, "").await?;
    match source {
        "valid" => receipt_matches(&baseline, fixture)?,
        "missing" => error_is(&baseline, StatusCode::NOT_FOUND, "not_visible")?,
        "corrupt" => error_is(
            &baseline,
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
        )?,
        "terminal" => gone_reader_matches(&baseline)?,
        _ => return Err("unregistered original receipt outcome".to_owned()),
    }
    let before = fixture.facts().await?;
    let original_bytes = fixture.bytes()?;
    let gate = ReceiptGate::new("rollback_acknowledged_before_tail");
    let _release = ReleaseGate(gate.clone());
    let in_call = if variant == "last_owner_drop" {
        None
    } else {
        original.clone()
    };
    let application = fixture.prepared().application().clone();
    let auth = original_authority.auth.clone();
    let task = tokio::spawn(
        async move {
            match in_call {
                Some(protocol) => HeldReceipt::Protocol(
                    local_request(&protocol, "main", Method::GET, &uri, "").await,
                ),
                None => HeldReceipt::Application(Box::new(
                    application
                        .execute(auth, AppCommand::GetArtifactSaveReceipt(input))
                        .await,
                )),
            }
        }
        .with_subscriber(tracing::Dispatch::new(ReceiptSubscriber(gate.clone()))),
    );
    let windows = original.as_ref().unwrap().windows.clone();
    let mut held = None;
    let mut poisoned = false;
    let mut settled_facts = None;
    let attempted = async {
        await_receipt_gate(&gate).await?;
        require(
            gate.phases.load(Ordering::SeqCst) == 7 && !task.is_finished(),
            "original source outcome and rollback ACK were not held before real Window tail",
        )?;
        require(
            fixture.facts().await? == before && fixture.bytes()? == original_bytes,
            "original observer changed artifacts before its held window tail",
        )?;
        if source == "corrupt" {
            fixture.corrupt(false).await?;
        }
        settled_facts = Some(fixture.facts().await?);
        match variant {
            "rebind" => {
                require(
                    original
                        .as_ref()
                        .unwrap()
                        .unbind_window("main")
                        .map_err(|e| e.to_string())?,
                    "actual original Window was not unbound",
                )?;
                original
                    .as_ref()
                    .unwrap()
                    .bind_window("main", fixture.prepared().auth_context().clone(), None)
                    .map_err(|e| e.to_string())?;
            }
            "unbind" => {
                require(
                    original
                        .as_ref()
                        .unwrap()
                        .unbind_window("main")
                        .map_err(|e| e.to_string())?,
                    "actual original Window was not unbound",
                )?;
            }
            "last_owner_drop" => {
                drop(original.take());
            }
            "owner_close" => {
                original.as_ref().unwrap().close_request_bindings();
            }
            "map_contention" => {
                held = Some(OwnedWindowWriteHold::new(windows.clone())?);
            }
            "map_poison" => {
                let map = windows.clone();
                let poison = std::thread::spawn(move || {
                    let _guard = map.write().unwrap();
                    panic!("owned-source-window-map-poison");
                })
                .join();
                require(
                    poison.is_err() && windows.is_poisoned(),
                    "original controlled Window map was not actually poisoned",
                )?;
                poisoned = true;
            }
            _ => return Err("unregistered Local source tail variant".to_owned()),
        }
        let peer_reply =
            local_request(&peer, "main", Method::GET, &route(&fixture.selector()), "").await?;
        if source == "terminal" {
            gone_reader_matches(&peer_reply)?;
        } else {
            receipt_matches(&peer_reply, fixture)?;
        }
        require(
            !gate.timed_out.load(Ordering::SeqCst),
            "actual original Window action exceeded the unchanged phase gate",
        )
    }
    .await;
    gate.release();
    let joined = task.await.map_err(|e| e.to_string());
    let holder_finished = held.map(OwnedWindowWriteHold::finish).unwrap_or(Ok(()));
    if poisoned {
        windows.clear_poison();
    }
    let restored = if source == "corrupt" {
        fixture.corrupt(false).await
    } else {
        Ok(())
    };
    attempted.and(restored).and(holder_finished)?;
    match joined? {
        HeldReceipt::Protocol(response) => {
            let locked = matches!(variant, "map_contention" | "map_poison");
            error_is(
                &response?,
                if locked {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::UNAUTHORIZED
                },
                if locked {
                    "dependency_unavailable"
                } else {
                    "unauthenticated"
                },
            )?;
        }
        HeldReceipt::Application(result) => {
            require(
                matches!(*result, Err(AppError::Unauthenticated)),
                "last true Protocol drop released held source outcome or lost original401",
            )?;
        }
    }
    require(
        !gate.timed_out.load(Ordering::SeqCst),
        "Window tail resumed only on observer timeout",
    )?;
    require(
        settled_facts == Some(fixture.facts().await?) && fixture.bytes()? == original_bytes,
        "window owner action or peer observation altered durable artifact/physical facts",
    )?;
    eprintln!(
        "SAVE_RECEIPT_LOCAL_WINDOW source={source} variant={variant} genuine_prepared=true original_joint_result=true actual_rollback_ack=true distinct_owner_same_label_id=true independent_peer_receipt=true rollback_pending_proof=false"
    );
    drop(original);
    drop(peer);
    drop(windows);
    Ok(())
}

async fn current_local_receipt_cases(fixture: &LocalFixture) -> Result<(), String> {
    let protocol = fixture.prepared().protocol();
    let original_auth = protocol
        .windows
        .try_read()
        .map_err(|_| "original Local map unavailable")?
        .get("main")
        .ok_or("original Prepared main missing")?
        .auth
        .clone();
    require(
        original_auth.has_role(openbot_contracts::auth::Role::Admin)
            && original_auth.has_role(openbot_contracts::auth::Role::User),
        "genuine canonical Local must retain current Admin plus implied User",
    )?;
    let before = fixture.facts().await?;
    let bytes = fixture.bytes()?;
    let uri = route(&fixture.selector());
    receipt_matches(
        &local_request(protocol, "main", Method::GET, &uri, "").await?,
        fixture,
    )?;
    let typed = fixture
        .prepared()
        .application()
        .execute(
            original_auth.clone(),
            AppCommand::GetArtifactSaveReceipt(GetArtifactSaveReceipt {
                request_id: fixture.artifact.request_id.to_uppercase(),
            }),
        )
        .await;
    require(
        typed
            == Ok(AppReply::ArtifactRegistrationReceipt(
                fixture.artifact.clone(),
            )),
        "same genuine Local Application failed canonical receipt alias",
    )?;
    for (method, suffix, body, status) in [
        (Method::HEAD, "", "", StatusCode::METHOD_NOT_ALLOWED),
        (Method::POST, "", "", StatusCode::METHOD_NOT_ALLOWED),
        (Method::GET, "?", "", StatusCode::BAD_REQUEST),
        (
            Method::GET,
            "?ownerActorId=forged",
            "",
            StatusCode::BAD_REQUEST,
        ),
        (Method::GET, "", "{}", StatusCode::BAD_REQUEST),
        (Method::GET, "/extra", "", StatusCode::BAD_REQUEST),
    ] {
        let response = local_request(
            protocol,
            "main",
            method.clone(),
            &format!("{uri}{suffix}"),
            body,
        )
        .await?;
        require(
            response.status() == status,
            "genuine Local receipt framing class mismatch",
        )?;
        if method == Method::HEAD {
            require(response.body().is_empty(), "receipt HEAD returned a body")?;
        }
    }
    for segment in ["%ZZ", "%2F", "%252F", "not-a-request", ""] {
        error_is(
            &local_request(
                protocol,
                "main",
                Method::GET,
                &format!("/api/artifacts/save-requests/{segment}"),
                "",
            )
            .await?,
            StatusCode::BAD_REQUEST,
            "malformed_payload",
        )?;
    }
    error_is(
        &local_request(protocol, "unbound-window", Method::GET, &uri, "").await?,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )?;
    fixture
        .sql("UPDATE public.messages SET content='{}'::jsonb")
        .await?;
    receipt_matches(
        &local_request(protocol, "main", Method::GET, &uri, "").await?,
        fixture,
    )?;
    require(
        fixture.facts().await? == before && fixture.bytes()? == bytes,
        "genuine Local observer changed operation/record/receipt/charge/audit/physical bytes",
    )?;
    let mutations = [
        (
            "raw_null",
            "UPDATE public.users SET auth_generation=NULL WHERE id='desktop-local-user'",
            "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'",
        ),
        (
            "generation",
            "UPDATE public.users SET auth_generation=1 WHERE id='desktop-local-user'",
            "UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'",
        ),
        (
            "canonical_email",
            "UPDATE public.users SET email='changed-local@example.test' WHERE id='desktop-local-user'",
            "UPDATE public.users SET email='desktop-local@localhost.invalid' WHERE id='desktop-local-user'",
        ),
        (
            "role",
            "UPDATE public.user_roles SET role='user' WHERE user_id='desktop-local-user'",
            "UPDATE public.user_roles SET role='admin' WHERE user_id='desktop-local-user'",
        ),
        (
            "deny",
            "INSERT INTO public.revoked_access(email,revoked_by) VALUES('desktop-local@localhost.invalid','desktop-local-user')",
            "DELETE FROM public.revoked_access WHERE email='desktop-local@localhost.invalid'",
        ),
    ];
    for (name, mutation, restore) in mutations {
        fixture.sql(mutation).await?;
        let attempted = async {
            for source in ["valid", "missing", "corrupt"] {
                let input = if source == "missing" { GetArtifactSaveReceipt { request_id: uuid::Uuid::now_v7().to_string() } }
                    else { fixture.selector() };
                if source == "corrupt" { fixture.corrupt(true).await?; }
                let current_facts = fixture.facts().await?;
                let response = local_request(protocol, "main", Method::GET, &route(&input), "").await;
                let outcome = fixture.prepared().application().execute(original_auth.clone(),
                    AppCommand::GetArtifactSaveReceipt(input)).await;
                let unchanged = fixture.facts().await? == current_facts && fixture.bytes()? == bytes;
                let restored = if source == "corrupt" { fixture.corrupt(false).await } else { Ok(()) };
                error_is(&response?, StatusCode::UNAUTHORIZED, "unauthenticated")?;
                require(outcome == Err(AppError::Unauthenticated) && unchanged,
                    "real Local host-first released stale result or changed artifact facts")?;
                restored?;
                eprintln!("SAVE_RECEIPT_LOCAL_CURRENT mutation={name} source={source} genuine_prepared=true schema_intact=true original_host_401=true");
            }
            Ok::<_, String>(())
        }.await;
        let restored = fixture.sql(restore).await;
        attempted.and(restored)?;
        receipt_matches(
            &local_request(protocol, "main", Method::GET, &uri, "").await?,
            fixture,
        )?;
    }
    // Deliberate native-schema corruption belongs to schema-unavailable qualification.
    fixture.sql("ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='desktop-local-user'").await?;
    let attempted = local_request(protocol, "main", Method::GET, &uri, "").await;
    let restored = fixture.sql("UPDATE public.users SET auth_generation=0 WHERE id='desktop-local-user'; ALTER TABLE public.users ADD CONSTRAINT users_auth_generation_nonnegative CHECK (auth_generation IS NULL OR auth_generation>=0)").await;
    error_is(
        &attempted?,
        StatusCode::SERVICE_UNAVAILABLE,
        "dependency_unavailable",
    )?;
    restored?;
    let canary: String = fixture.prepared().pool().get().await.map_err(|e| e.to_string())?
        .query_one("SELECT encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2",
            &[&original_auth.deployment().as_str(), &original_auth.tenant().as_str()])
        .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())?;
    fixture.sql("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=encrypted_canary||'-owned-receipt-change'").await?;
    let changed = async {
        for source in ["valid", "missing", "corrupt"] {
            let input = if source == "missing" {
                GetArtifactSaveReceipt {
                    request_id: uuid::Uuid::now_v7().to_string(),
                }
            } else {
                fixture.selector()
            };
            if source == "corrupt" {
                fixture.corrupt(true).await?;
            }
            let response = local_request(protocol, "main", Method::GET, &route(&input), "").await;
            let restored = if source == "corrupt" {
                fixture.corrupt(false).await
            } else {
                Ok(())
            };
            error_is(&response?, StatusCode::UNAUTHORIZED, "unauthenticated")?;
            restored?;
        }
        Ok::<_, String>(())
    }
    .await;
    let restored = fixture.prepared().pool().get().await.map_err(|e| e.to_string())?
        .execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1 WHERE deployment_id=$2 AND tenant_id=$3",
            &[&canary, &original_auth.deployment().as_str(), &original_auth.tenant().as_str()])
        .await.map_err(|e| e.to_string())?;
    require(
        restored == 1,
        "original actual installation canary was not exactly restored",
    )?;
    changed?;
    receipt_matches(
        &local_request(protocol, "main", Method::GET, &uri, "").await?,
        fixture,
    )?;
    let upstream = DesktopTauriProtocol::open(
        &fixture.assets,
        Arc::new(InProcessTransport::new(
            fixture.prepared().application().clone(),
        )),
    )
    .map_err(|e| e.to_string())?;
    upstream
        .bind_window("main", original_auth, None)
        .map_err(|e| e.to_string())?;
    error_is(
        &local_request(&upstream, "main", Method::GET, &uri, "").await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "dependency_unavailable",
    )?;
    let unsupported_application = Arc::new(openbot_application::OpenBotApplication::new(
        openbot_infra::repo::channels::ChannelRepo::new(fixture.prepared().pool().clone()),
    ));
    let source = protocol
        .local_capability_authority
        .clone()
        .ok_or("genuine Local source missing")?;
    let unsupported = DesktopTauriProtocol::open(
        &fixture.assets,
        Arc::new(InProcessTransport::new(unsupported_application)),
    )
    .map_err(|e| e.to_string())?
    .with_current_identity_source(source);
    unsupported
        .bind_window("main", fixture.prepared().auth_context().clone(), None)
        .map_err(|e| e.to_string())?;
    error_is(
        &local_request(&unsupported, "main", Method::GET, &uri, "").await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "dependency_unavailable",
    )?;
    // Exercise the public dispatcher while the original real window map is held.
    let held = OwnedWindowWriteHold::new(protocol.windows.clone())?;
    let blocked = local_request(protocol, "main", Method::GET, &uri, "").await;
    let released = held.finish();
    error_is(
        &blocked?,
        StatusCode::SERVICE_UNAVAILABLE,
        "dependency_unavailable",
    )?;
    released?;
    receipt_matches(
        &local_request(protocol, "main", Method::GET, &uri, "").await?,
        fixture,
    )?;
    require(
        fixture.facts().await? == before && fixture.bytes()? == bytes,
        "canonical Local/current-canary/unsupported observations altered original artifact facts",
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine Prepared Local, owned sidecar, memory-only secrets and original same-Pool canary"]
async fn genuine_prepared_local_get_recovers_receipt_under_original_window_and_canary() {
    let bundle = OwnedBundle::materialize().expect("controlled owned PostgreSQL bundle");
    let fixture = LocalFixture::new(&bundle, "receipt-current")
        .await
        .expect("owned genuine Prepared fixture");
    let outcome = current_local_receipt_cases(&fixture).await;
    let shutdown = fixture.finish().await;
    outcome
        .and(shutdown)
        .expect("genuine Local receipt consumer and explicit physical shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine Local, original window epochs, rollback ACK tails and explicit own sidecar shutdown"]
async fn genuine_local_rebind_unbind_and_last_owner_drop_withhold_all_receipt_outcomes() {
    let bundle = OwnedBundle::materialize().expect("controlled owned PostgreSQL bundle");
    let fixture = LocalFixture::new(&bundle, "receipt-window-tail")
        .await
        .expect("owned genuine Prepared fixture");
    let outcome = async {
        for source in ["valid", "missing", "corrupt"] {
            for variant in [
                "rebind",
                "unbind",
                "last_owner_drop",
                "owner_close",
                "map_contention",
                "map_poison",
            ] {
                original_window_tail(&fixture, source, variant).await?;
            }
        }
        fixture.terminal_reader_fixture().await?;
        for variant in [
            "rebind",
            "unbind",
            "last_owner_drop",
            "owner_close",
            "map_contention",
            "map_poison",
        ] {
            original_window_tail(&fixture, "terminal", variant).await?;
        }
        Ok::<_, String>(())
    }
    .await;
    let shutdown = fixture.finish().await;
    outcome
        .and(shutdown)
        .expect("genuine original Window receipt outcomes and explicit physical shutdown");
}
