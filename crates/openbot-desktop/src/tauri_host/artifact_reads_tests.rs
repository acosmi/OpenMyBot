//! New public reader tests prepare genuine Local/Window authority and only owned sidecar roots.
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
use openbot_contracts::artifact_read_protocol::{
    ArtifactReadAcknowledged, ArtifactReadClosed, ArtifactReadOpened,
};
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{
    AppCommand, AppEvent, AppReply, BeginThreadRun, SubscriptionRequest, ThreadRunAnchor,
    ThreadRunEventKind,
};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::ids::{BotId, RunId, thread::ThreadIdentity};
use openbot_domain::vault::SecretBytes;
use openbot_infra::artifact_administration::{
    ArmedArtifactCleanupIntent, ArtifactCleanupPhysicalError as PhysicalError,
    ArtifactCleanupPhysicalIoPhase as PhysicalPhase, ArtifactCleanupPhysicalObserver,
    ArtifactCleanupPhysicalState as PhysicalState, ArtifactCleanupTerminalError as TerminalError,
    ArtifactCleanupTerminalObserver, ArtifactCleanupTerminalPhase as TerminalPhase,
    ArtifactCleanupTerminalState as TerminalState,
};
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const PAYLOAD: &str = "genuine Local public artifact text";

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
            "openbot-public-read-{label}-{}",
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
            eprintln!("PUBLIC_ARTIFACT_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "PUBLIC_ARTIFACT_LOCAL_OWNED_ROOT removed={} absent={}",
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
        let mut root = OwnedRoot::new("bundle")?;
        // Keep the actual sidecar bundle through any startup or shutdown uncertainty.
        root.1 = false;
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
        "/controlled/public-artifact-read-local-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    assets: PathBuf,
    prepared: Option<PreparedDesktopLocalRuntime>,
    artifact: ArtifactRegistrationReceipt,
    postmaster_pid: u32,
}

// Registration10: an observation after the original P1 Save has already failed. This fixed
// statement returns only booleans and explicit closed classes, never row values or source text.
const ORIGINAL_P1_SAVE_FAILURE_FACTS_SQL: &str = r#"
WITH d AS (
 SELECT dataset_id FROM openbot_internal.artifact_dataset_bindings
 WHERE deployment_id=$1 AND tenant_id=$2
), o AS (
 SELECT o.* FROM openbot_internal.artifact_save_operations o JOIN d USING(dataset_id)
 WHERE o.deployment_id=$1 AND o.tenant_id=$2 AND o.request_id=$3 AND o.owner_actor_id=$4
), r AS (
 SELECT r.* FROM openbot_internal.artifact_records r JOIN o
 USING(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
), p AS (
 SELECT p.* FROM openbot_internal.artifact_saved_receipts p JOIN o
 USING(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
), q AS (
 SELECT q.* FROM openbot_internal.artifact_workspace_quotas q JOIN o
 USING(deployment_id,tenant_id,dataset_id,workspace_kind,workspace_id)
)
SELECT jsonb_build_object(
 'operation_exists',EXISTS(SELECT 1 FROM o),
 'operation_state',coalesce((SELECT CASE WHEN state IN
  ('admitted','io_started','available','failed_partial','unresolved','deleted','expired')
  THEN state ELSE 'invalid' END FROM o),'missing'),
 'observation_phase',coalesce((SELECT CASE WHEN observation_phase IN
  ('before_write','staging','installing','installed') THEN observation_phase
  WHEN observation_phase IS NULL THEN 'null' ELSE 'invalid' END FROM o),'missing'),
 'actual_absence',coalesce((SELECT CASE WHEN actual_absent IS TRUE THEN 'true'
  WHEN actual_absent IS FALSE THEN 'false' ELSE 'null' END FROM o),'missing'),
 'actual_location',coalesce((SELECT CASE WHEN actual_location IN ('staging','object')
  THEN actual_location WHEN actual_location IS NULL THEN 'null' ELSE 'invalid' END FROM o),'missing'),
 'record_exists',EXISTS(SELECT 1 FROM r),
 'record_status',coalesce((SELECT CASE WHEN status IN
  ('available','failed_partial','deleted','expired') THEN status ELSE 'invalid' END FROM r),'missing'),
 'record_identity_matches',EXISTS(SELECT 1 FROM r JOIN o
  USING(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
  WHERE ROW(r.request_id,r.owner_actor_id,r.source_thread_id,r.source_run_id,r.source_message_id,
   r.source_call_seq,r.source_attempt_seq) IS NOT DISTINCT FROM
   ROW(o.request_id,o.owner_actor_id,o.source_thread_id,o.source_run_id,o.source_message_id,
   o.source_call_seq,o.source_attempt_seq)),
 'positive_receipt_exists',EXISTS(SELECT 1 FROM p),
 'receipt_identity_matches',EXISTS(SELECT 1 FROM p JOIN o
  USING(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
  WHERE ROW(p.request_id,p.owner_actor_id,p.source_thread_id,p.source_run_id,p.source_message_id,
   p.source_call_seq,p.source_attempt_seq) IS NOT DISTINCT FROM
   ROW(o.request_id,o.owner_actor_id,o.source_thread_id,o.source_run_id,o.source_message_id,
   o.source_call_seq,o.source_attempt_seq)),
 'operation_matches_original_source',EXISTS(SELECT 1 FROM o WHERE source_thread_id=$6
  AND source_run_id=$7 AND source_message_id=$8 AND source_call_seq IS NULL
  AND source_attempt_seq IS NULL AND expected_sha256=$10),
 'expected_actual_charge_matches',EXISTS(SELECT 1 FROM o WHERE expected_bytes=charged_bytes
  AND expected_bytes=actual_byte_length AND expected_sha256=actual_sha256),
 'record_actual_matches',EXISTS(SELECT 1 FROM r JOIN o
  USING(deployment_id,tenant_id,dataset_id,operation_id,artifact_id)
  WHERE r.byte_length=o.actual_byte_length AND r.sha256=o.actual_sha256),
 'quota_exists',EXISTS(SELECT 1 FROM q),
 'quota_covers_original_charge',EXISTS(SELECT 1 FROM q JOIN o
  USING(deployment_id,tenant_id,dataset_id,workspace_kind,workspace_id)
  WHERE q.charged_bytes>=o.charged_bytes),
 'source_thread_exists',EXISTS(SELECT 1 FROM public.threads t WHERE t.thread_id=$6
  AND t.deployment_id=$1 AND t.tenant_id=$2 AND t.status<>'deleted'),
 'source_run_owner_matches',EXISTS(SELECT 1 FROM public.runs rr WHERE rr.run_id=$7
  AND rr.thread_id=$6 AND rr.actor_id=$4),
 'source_user_message_matches',EXISTS(SELECT 1 FROM public.messages m WHERE m.message_id=$8
  AND m.thread_id=$6 AND m.run_id=$7 AND m.actor_id=$4 AND m.role='user'),
 'source_payload_matches',EXISTS(SELECT 1 FROM public.messages m WHERE m.message_id=$8
  AND m.thread_id=$6 AND m.run_id=$7 AND m.actor_id=$4 AND m.role='user'
  AND jsonb_typeof(m.content->'text')='string' AND m.content->>'text'=$9),
 'actor_exists',EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4),
 'actor_generation_matches',EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4
  AND coalesce(u.auth_generation,0)=$5),
 'actor_role_valid',EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4
  AND ur.role IN ('user','admin')),
 'actor_deny_clear',EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4
  AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)))
)
"#;

async fn capture_original_p1_setup_failure_before(
    prepared: &PreparedDesktopLocalRuntime,
    original_auth: &openbot_contracts::auth::AuthContext,
    original_save: &SaveRunMessageTextArtifact,
    original_save_started: Instant,
    deadline: Instant,
) {
    let original_window_unclosed_same_epoch = prepared
        .protocol()
        .windows
        .try_read()
        .ok()
        .and_then(|windows| {
            windows.get("main").map(|window| {
                !window.closed.is_cancelled()
                    && window.auth == *original_auth
                    && window
                        .auth
                        .request_binding()
                        .zip(original_auth.request_binding())
                        .is_some_and(|(current, original)| {
                            current.identity().same_binding(original.identity())
                        })
            })
        })
        .unwrap_or(false);
    eprintln!(
        "ARTIFACT_LOCAL_P1_SETUP_FACTS original_save_elapsed_ms={} window_unclosed_same_epoch={} window_fact_is_only_local_observation=true original_save_result_unchanged=true",
        original_save_started.elapsed().as_millis(),
        original_window_unclosed_same_epoch
    );
    let Ok(generation) = i64::try_from(original_auth.auth_generation().get()) else {
        eprintln!("ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=original_generation_out_of_range");
        return;
    };
    if Instant::now() >= deadline {
        eprintln!(
            "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=deadline_before_checkout no_connection_closure_claim=true"
        );
        return;
    }
    // Reserve part of this same total budget for original connection destruction, not a new
    // query/retry budget. The failed Save's own deadline/result is never changed.
    let query_deadline = deadline.min(Instant::now() + Duration::from_millis(1_500));
    let query_at = tokio::time::Instant::from_std(query_deadline);
    let client = match tokio::time::timeout_at(query_at, prepared.pool().get()).await {
        Ok(Ok(client)) => client,
        Ok(Err(_)) => {
            eprintln!("ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=checkout_error");
            return;
        }
        Err(_) => {
            eprintln!(
                "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=checkout_deadline no_checkout_closure_claim=true"
            );
            return;
        }
    };
    let original_connection = client.observation();
    // This acquired client cannot be returned by legacy Drop, including on query cancellation.
    let client = openbot_infra::db::pool::PooledClient::take(client);
    if Instant::now() >= query_deadline {
        eprintln!(
            "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=deadline_after_checkout no_query_started=true"
        );
    } else {
        let facts = tokio::time::timeout_at(
            query_at,
            client.query_one(
                ORIGINAL_P1_SAVE_FAILURE_FACTS_SQL,
                &[
                    &original_auth.deployment().as_str(),
                    &original_auth.tenant().as_str(),
                    &original_save.request_id,
                    &original_auth.actor().as_str(),
                    &generation,
                    &original_save.source_thread_id.as_str(),
                    &original_save.source_run_id.as_str(),
                    &original_save.source_message_id.as_str(),
                    &PAYLOAD,
                    &original_save.expected_sha256,
                ],
            ),
        )
        .await;
        match facts {
            Ok(Ok(row)) => match row.try_get::<_, serde_json::Value>(0) {
                Ok(facts) => eprintln!(
                    "ARTIFACT_LOCAL_P1_SETUP_FACTS fixed_original_selector_facts={facts} ids_body_hash_path_omitted=true readonly_observation_not_original_commit_ack=true"
                ),
                Err(_) => eprintln!("ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=facts_decode_error"),
            },
            Ok(Err(error)) => {
                let code = error
                    .as_db_error()
                    .map(|error| error.code().code())
                    .unwrap_or("non_database");
                eprintln!(
                    "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=query_error sqlstate={code} pg_message_omitted=true"
                );
            }
            Err(_) => eprintln!(
                "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic=query_deadline no_original_save_ack_claim=true"
            ),
        }
    }
    drop(client);
    let destruction_observed = original_connection
        .wait_for_destruction_before(deadline)
        .await
        .is_ok();
    let snapshot = original_connection.snapshot();
    eprintln!(
        "ARTIFACT_LOCAL_P1_SETUP_FACTS diagnostic_driver_destruction_observed={} original_connection_started={} original_connection_destroyed={} original_retirement_requested={} result_is_not_fixture_cleanup_ack=true",
        destruction_observed,
        snapshot.connection_started,
        snapshot.connection_destroyed,
        snapshot.retirement_requested
    );
}

fn capture_original_p1_postmaster(root: &Path, deadline: Instant) -> Option<u32> {
    let root_before = std::fs::symlink_metadata(root).ok()?;
    if !root_before.is_dir()
        || root_before.file_type().is_symlink()
        || root_before.mode() & 0o7777 != 0o700
    {
        return None;
    }
    let mut selected = None;
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(root).ok()? {
        entries += 1;
        if entries > 64 || Instant::now() >= deadline {
            return None;
        }
        let path = entry.ok()?.path();
        if !path.file_name()?.to_str()?.starts_with("postgresql-17-") {
            continue;
        }
        let directory = std::fs::symlink_metadata(&path).ok()?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != root_before.uid()
            || directory.mode() & 0o7777 != 0o700
        {
            return None;
        }
        let pid_path = path.join("postmaster.pid");
        let before = std::fs::symlink_metadata(&pid_path).ok()?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.nlink() != 1
            || before.uid() != root_before.uid()
            || before.len() > 4_096
        {
            return None;
        }
        let file = std::fs::File::open(&pid_path).ok()?;
        let descriptor = file.metadata().ok()?;
        if !descriptor.is_file()
            || descriptor.dev() != before.dev()
            || descriptor.ino() != before.ino()
            || descriptor.uid() != before.uid()
            || descriptor.nlink() != 1
            || descriptor.len() != before.len()
        {
            return None;
        }
        let mut text = String::new();
        file.take(4_097).read_to_string(&mut text).ok()?;
        let after = std::fs::symlink_metadata(&pid_path).ok()?;
        if text.len() > 4_096
            || after.file_type().is_symlink()
            || !after.is_file()
            || after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.len() != before.len()
            || after.uid() != before.uid()
            || after.nlink() != 1
            || Instant::now() >= deadline
        {
            return None;
        }
        let pid = text.lines().next()?.parse::<u32>().ok()?;
        if !(2..=i32::MAX as u32).contains(&pid) || selected.replace(pid).is_some() {
            return None;
        }
    }
    let root_after = std::fs::symlink_metadata(root).ok()?;
    if root_after.file_type().is_symlink()
        || !root_after.is_dir()
        || root_after.dev() != root_before.dev()
        || root_after.ino() != root_before.ino()
        || root_after.uid() != root_before.uid()
        || root_after.mode() & 0o7777 != 0o700
        || Instant::now() >= deadline
    {
        return None;
    }
    selected
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
        let p1_setup_diagnostic = matches!(label, "p1-window-chunk" | "p1-window-operation");
        let arm_setup_diagnostic = label == "cleanup-arm-original-window";
        let setup_diagnostic = if p1_setup_diagnostic {
            Some("ARTIFACT_LOCAL_P1_SETUP_DIAGNOSTIC")
        } else if label == "public-read-cached-cleanup" {
            Some("ARTIFACT_LOCAL_CACHED_SETUP_DIAGNOSTIC")
        } else {
            None
        };
        let mut failed_p1_postmaster_pid = None;
        let populated = async {
            prepared
                .protocol()
                .bind_window("main", prepared.auth_context().clone(), None)
                .map_err(|error| {
                    if p1_setup_diagnostic {
                        eprintln!("ARTIFACT_LOCAL_P1_SETUP_DIAGNOSTIC phase=bind_window original_app_error={error}");
                    }
                    error.to_string()
                })?;
            let auth = prepared
                .protocol()
                .windows
                .try_read()
                .map_err(|_| "actual window lock unavailable")?
                .get("main")
                .ok_or("actual main missing")?
                .auth
                .clone();
            let payload = PAYLOAD.to_owned();
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
            let begin_reply = prepared
                .application()
                .execute(auth.clone(), AppCommand::BeginThreadRun(begin.clone()))
                .await
                .map_err(|error| {
                    if let Some(diagnostic) = setup_diagnostic {
                        eprintln!("{diagnostic} phase=BeginThreadRun original_app_error={error}");
                    }
                    if arm_setup_diagnostic {
                        eprintln!("ARTIFACT_LOCAL_ARM_SETUP_DIAGNOSTIC phase=BeginThreadRun original_app_error={error} original_passive=true nongrant=true original_single_save_executed=false original_result_unchanged=true");
                    }
                    error.to_string()
                })?;
            let AppReply::ThreadRunStarted(begin_receipt) = begin_reply else {
                return Err("actual Local Begin did not return its durable receipt".to_owned());
            };
            if arm_setup_diagnostic {
                eprintln!("ARTIFACT_LOCAL_ARM_SETUP_DIAGNOSTIC phase=BeginThreadRun actual_thread_run_started_reply=true original_passive=true nongrant=true agent_terminal_observation_claimed=false original_result_unchanged=true");
            }
            // Every fixture label Saves only after its dispatched source Run is durably terminal
            // and the thread foreground is inactive. A live Run holds FOR UPDATE on its
            // run/thread/lease rows while Save's source locks are NOWAIT, so an earlier Save gets
            // a legitimate immediate Unavailable. A missing or unknown terminal fails right here.
            require(
                begin_receipt.thread_id == begin.thread_id
                    && begin_receipt.run_id == begin.run_id,
                "P1 original Begin receipt selected another run",
            )?;
            // This fixture precondition observes the actual dispatched run before the
            // single Save. It does not alter Save's original budget or claim Agent join ACK.
            let fixture_deadline = Instant::now() + Duration::from_secs(5);
            tokio::time::timeout_at(tokio::time::Instant::from_std(fixture_deadline), async {
                let mut events = prepared.application().subscribe(auth.clone(),
                    SubscriptionRequest::ThreadEvents {
                        thread_id: begin.thread_id.clone(),
                        after_event_sequence: Some(begin_receipt.event_sequence),
                    }).await.map_err(|error| error.to_string())?;
                let mut cursor = begin_receipt.event_sequence;
                let terminal = loop {
                    let event = core::future::poll_fn(|cx| events.as_mut().poll_next(cx)).await
                        .ok_or("P1 original run stream ended before durable terminal")?;
                    let AppEvent::ThreadRunEvent(event) = event else {
                        return Err("P1 original run stream failed or returned another envelope".to_owned());
                    };
                    require(event.thread_id == begin.thread_id && event.run_id == begin.run_id
                        && event.event_sequence > cursor
                        && event.terminal == event.event_type.is_terminal(),
                        "P1 original run event identity, cursor or terminal flag differed")?;
                    cursor = event.event_sequence;
                    match event.event_type {
                        ThreadRunEventKind::Completed | ThreadRunEventKind::Failed
                            | ThreadRunEventKind::Cancelled => break event.event_type,
                        ThreadRunEventKind::ReconciliationRequired => return Err(
                            "P1 original run has unknown terminal facts".to_owned()),
                        ThreadRunEventKind::Started | ThreadRunEventKind::SemanticChunk
                            | ThreadRunEventKind::Checkpoint => {}
                    }
                };
                let conversation = prepared.application().execute(auth.clone(),
                    AppCommand::GetThreadConversation { thread_id: begin.thread_id.clone() })
                    .await.map_err(|error| error.to_string())?;
                let AppReply::ThreadConversation(conversation) = conversation else {
                    return Err("P1 original conversation returned another reply".to_owned());
                };
                require(conversation.active_run_id.is_none()
                    && conversation.active_run_state.is_none()
                    && conversation.last_event_sequence.is_some_and(|value| value >= cursor),
                    "P1 original run foreground was not durably inactive")?;
                require(Instant::now() < fixture_deadline,
                    "P1 original run fixture deadline expired")?;
                // Dropping this real stream requests its existing producer to stop;
                // neither Drop nor durable terminal observation is a resource closure ACK.
                drop(events);
                eprintln!("ARTIFACT_LOCAL_P1_RUN_PRECONDITION fixture_label={label} original_run_terminal={terminal:?} original_foreground_inactive=true one_absolute_fixture_budget=true original_save_not_started=true stream_drop_is_not_join_ack=true");
                Ok::<_, String>(())
            }).await.map_err(|_| "P1 original run fixture deadline expired".to_owned())??;
            let source = format!("{}:input", begin.run_id.as_str());
            let original_save = SaveRunMessageTextArtifact {
                request_id: uuid::Uuid::now_v7().to_string(),
                source_thread_id: begin.thread_id,
                source_run_id: begin.run_id,
                source_message_id: source,
                expected_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
            };
            let original_save_auth = auth.clone();
            // Scope04: observation only on the same Admin consumed by this Application.
            // Installation loss cannot skip or change the single original Save below.
            let original_save_diagnostic = if p1_setup_diagnostic || arm_setup_diagnostic {
                Some(prepared.artifact_administration
                    .install_save_producer_diagnostic_for_request(&original_save.request_id))
            } else {
                None
            };
            let original_save_started = Instant::now();
            let receipt = prepared
                .application()
                .execute(
                    auth,
                    AppCommand::SaveRunMessageTextArtifact(original_save.clone()),
                )
                .await;
            if let Some(diagnostic) = setup_diagnostic
                && let Err(error) = &receipt
            {
                eprintln!("{diagnostic} phase=SaveRunMessageTextArtifact original_app_error={error}");
                if p1_setup_diagnostic {
                    match &original_save_diagnostic {
                        Some(Ok(capture)) => eprintln!(
                            "ARTIFACT_LOCAL_P1_ORIGINAL_SAVE_PRODUCER snapshot={:?} original_single_save_executed=true nongrant=true",
                            capture.snapshot()
                        ),
                        Some(Err(install_error)) => eprintln!(
                            "ARTIFACT_LOCAL_P1_ORIGINAL_SAVE_PRODUCER install_error={install_error:?} original_single_save_executed=true diagnostic_UNKNOWN=true"
                        ),
                        None => eprintln!(
                            "ARTIFACT_LOCAL_P1_ORIGINAL_SAVE_PRODUCER original_single_save_executed=true diagnostic_UNKNOWN=true"
                        ),
                    }
                    let diagnostic_deadline = Instant::now() + Duration::from_secs(2);
                    failed_p1_postmaster_pid = capture_original_p1_postmaster(&root.0, diagnostic_deadline);
                    match failed_p1_postmaster_pid {
                        Some(pid) => eprintln!("ARTIFACT_LOCAL_P1_SETUP_FACTS original_owned_postmaster_pid={pid} original_private_root_pidfile_bound=true root_path_omitted=true"),
                        None => eprintln!("ARTIFACT_LOCAL_P1_SETUP_FACTS original_private_root_pidfile_bound=false no_original_pg_termination_claim=true"),
                    }
                    capture_original_p1_setup_failure_before(&prepared, &original_save_auth,
                        &original_save, original_save_started, diagnostic_deadline).await;
                }
                let schema = openbot_infra::artifact_administration::verify_artifact_registration_schema(prepared.pool()).await;
                eprintln!("{diagnostic} phase=post_original_Save_error legacy41_42={schema:?}");
                if matches!(&schema, Err(openbot_application::ArtifactAdministrationError::Corrupt { field: "registration_schema" })) {
                    let expected = serde_json::from_str::<serde_json::Value>(include_str!("../../../../fixtures/db/artifact-registration-0042.json"));
                    let actual = openbot_infra::artifact_administration::capture_artifact_registration_schema(prepared.pool()).await;
                    match (expected, actual) {
                        (Ok(expected), Ok(actual)) => {
                            let mut paths = Vec::new();
                            cleanup_cached_schema_difference_paths(&expected, &actual, "", &mut paths);
                            eprintln!("{diagnostic} legacy42_difference_paths={paths:?} path_limit=16 values_omitted=true");
                        }
                        (Err(_), _) => eprintln!("{diagnostic} fixed_original_oracle_decode_failed=true"),
                        (_, Err(error)) => eprintln!("{diagnostic} legacy42_capture_error={error:?}"),
                    }
                }
            }
            if arm_setup_diagnostic && let Err(error) = &receipt {
                eprintln!("ARTIFACT_LOCAL_ARM_SETUP_DIAGNOSTIC phase=SaveRunMessageTextArtifact original_app_error={error} original_save_elapsed_ms={} original_passive=true nongrant=true original_single_save_executed=true original_result_unchanged=true original_budget_unchanged=true",
                    original_save_started.elapsed().as_millis());
                match &original_save_diagnostic {
                    Some(Ok(capture)) => {
                        let snapshot = capture.snapshot();
                        let diagnostic_unknown = snapshot.lost || snapshot.main_stage.is_none()
                            || snapshot.main_terminal.is_none();
                        eprintln!("ARTIFACT_LOCAL_ARM_ORIGINAL_SAVE_PRODUCER snapshot={snapshot:?} diagnostic_UNKNOWN={diagnostic_unknown} original_passive=true nongrant=true original_single_save_executed=true original_result_unchanged=true original_budget_unchanged=true resource_or_query_ack_claimed=false");
                    }
                    Some(Err(install_error)) => eprintln!(
                        "ARTIFACT_LOCAL_ARM_ORIGINAL_SAVE_PRODUCER install_error={install_error:?} diagnostic_UNKNOWN=true original_passive=true nongrant=true original_single_save_executed=true original_result_unchanged=true original_budget_unchanged=true resource_or_query_ack_claimed=false"
                    ),
                    None => eprintln!(
                        "ARTIFACT_LOCAL_ARM_ORIGINAL_SAVE_PRODUCER diagnostic_UNKNOWN=true original_passive=true nongrant=true original_single_save_executed=true original_result_unchanged=true original_budget_unchanged=true resource_or_query_ack_claimed=false"
                    ),
                }
            }
            // Preserve the original Save outcome; diagnostics never retry or replace it.
            let receipt = receipt.map_err(|error| error.to_string())?;
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
                    pids.push(pid);
                }
            }
            require(
                pids.len() == 1,
                "genuine Prepared did not own exactly one controlled sidecar",
            )?;
            Ok::<_, String>((artifact, pids[0]))
        }
        .await;
        match populated {
            Ok((artifact, postmaster_pid)) => {
                // Active sidecar resources must survive an unexpected test panic. Only
                // finish() may permit root removal after genuine shutdown and PID-gone proof.
                root.1 = false;
                eprintln!(
                    "PUBLIC_ARTIFACT_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={}",
                    root.0.display()
                );
                Ok(Self {
                    root,
                    assets,
                    prepared: Some(prepared),
                    artifact,
                    postmaster_pid,
                })
            }
            Err(error) => {
                let failed_arm_postmaster_pid = if arm_setup_diagnostic {
                    // This finite identity observation occurs after the original setup Err.
                    // It does not extend or replay the original Save or change cleanup rules.
                    let pid = capture_original_p1_postmaster(
                        &root.0,
                        Instant::now() + Duration::from_secs(2),
                    );
                    match pid {
                        Some(pid) => eprintln!(
                            "ARTIFACT_LOCAL_ARM_SETUP_FACTS original_owned_postmaster_pid={pid} original_private_root_pidfile_bound=true root_path_omitted=true original_passive=true nongrant=true original_setup_error_preserved=true resource_or_query_ack_claimed=false"
                        ),
                        None => eprintln!(
                            "ARTIFACT_LOCAL_ARM_SETUP_FACTS original_private_root_pidfile_bound=false diagnostic_UNKNOWN=true root_path_omitted=true original_passive=true nongrant=true original_setup_error_preserved=true resource_or_query_ack_claimed=false"
                        ),
                    }
                    pid
                } else {
                    None
                };
                let cleaned = prepared.shutdown().await;
                if p1_setup_diagnostic {
                    match failed_p1_postmaster_pid {
                        Some(pid) => match owned_postmaster_live(pid) {
                            Ok(live) => eprintln!(
                                "ARTIFACT_LOCAL_P1_SETUP_FACTS original_owned_postmaster_pid={pid} original_pid_gone_observed={} original_shutdown_ok={} original_save_error_preserved=true bundle_cleanup_not_inferred=true",
                                !live,
                                cleaned.is_ok()
                            ),
                            Err(_) => eprintln!(
                                "ARTIFACT_LOCAL_P1_SETUP_FACTS original_pid_gone_observed=false pid_observation_failed=true original_save_error_preserved=true bundle_cleanup_not_inferred=true"
                            ),
                        },
                        None => eprintln!(
                            "ARTIFACT_LOCAL_P1_SETUP_FACTS original_pid_binding_missing=true original_save_error_preserved=true bundle_cleanup_not_inferred=true"
                        ),
                    }
                }
                if arm_setup_diagnostic {
                    match failed_arm_postmaster_pid {
                        Some(pid) => match owned_postmaster_live(pid) {
                            Ok(live) => eprintln!(
                                "ARTIFACT_LOCAL_ARM_SETUP_FACTS original_owned_postmaster_pid={pid} original_pid_gone_observed={} original_shutdown_ok={} original_passive=true nongrant=true original_setup_error_preserved=true bundle_cleanup_not_inferred=true save_or_query_ack_claimed=false",
                                !live,
                                cleaned.is_ok()
                            ),
                            Err(_) => eprintln!(
                                "ARTIFACT_LOCAL_ARM_SETUP_FACTS original_pid_gone_observed=UNKNOWN pid_observation_failed=true original_shutdown_ok={} original_passive=true nongrant=true original_setup_error_preserved=true bundle_cleanup_not_inferred=true save_or_query_ack_claimed=false",
                                cleaned.is_ok()
                            ),
                        },
                        None => eprintln!(
                            "ARTIFACT_LOCAL_ARM_SETUP_FACTS original_pid_gone_observed=UNKNOWN original_pid_binding_missing=true original_shutdown_ok={} original_passive=true nongrant=true original_setup_error_preserved=true bundle_cleanup_not_inferred=true save_or_query_ack_claimed=false",
                            cleaned.is_ok()
                        ),
                    }
                }
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
        require(closing_ok, "genuine BackgroundOwner cleanup did not ACK")?;
        self.root.1 = true;
        eprintln!(
            "PUBLIC_ARTIFACT_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true",
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

fn request(
    method: Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<Request<Vec<u8>>, String> {
    let body = body
        .map(|value| serde_json::to_vec(&value))
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    Request::builder()
        .method(method)
        .uri(format!("openbot://localhost{path}"))
        .header("content-type", "application/json")
        .body(body)
        .map_err(|error| error.to_string())
}

fn open_request(artifact: &str) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        super::PREFIX,
        Some(serde_json::json!({"artifactId": artifact})),
    )
}

fn next_request(handle: &str, sequence: u32) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        &format!("{}/{handle}/next", super::PREFIX),
        Some(serde_json::json!({"sequence": sequence})),
    )
}

fn ack_request(handle: &str, sequence: u32) -> Result<Request<Vec<u8>>, String> {
    request(
        Method::POST,
        &format!("{}/{handle}/ack", super::PREFIX),
        Some(serde_json::json!({"sequence": sequence})),
    )
}

fn close_request(handle: &str) -> Result<Request<Vec<u8>>, String> {
    request(Method::DELETE, &format!("{}/{handle}", super::PREFIX), None)
}

async fn bridge(
    protocol: &DesktopTauriProtocol,
    label: &str,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let prepared = protocol
        .prepare_public_artifact_read_response(label, request)
        .await;
    protocol.finish_public_artifact_read_response(label, prepared, |response| response)
}

fn no_store(response: &Response<Vec<u8>>) -> Result<(), String> {
    require(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "actual Desktop public-reader response omitted no-store",
    )
}

fn control<T: serde::de::DeserializeOwned>(response: Response<Vec<u8>>) -> Result<T, String> {
    no_store(&response)?;
    require(
        response.status() == StatusCode::OK,
        "actual Desktop control did not succeed",
    )
    .map_err(|message| format!("{message}: status={}", response.status().as_u16()))?;
    serde_json::from_slice(response.body()).map_err(|error| error.to_string())
}

fn status(response: Response<Vec<u8>>, expected: StatusCode) -> Result<(), String> {
    no_store(&response)?;
    require(
        response.status() == expected,
        "actual Desktop refusal had unexpected status",
    )?;
    require(
        !response
            .body()
            .windows(PAYLOAD.len())
            .any(|part| part == PAYLOAD.as_bytes()),
        "actual Desktop refusal exposed source text",
    )
}

fn data(
    response: &Response<Vec<u8>>,
    handle: &str,
    sequence: u32,
    eof: bool,
) -> Result<(), String> {
    no_store(response)?;
    require(
        response.status() == StatusCode::OK,
        "actual Desktop byte handoff did not succeed",
    )?;
    let header = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or("actual Desktop block header missing".to_owned())
    };
    require(
        header("x-artifact-read-handle")? == handle,
        "Desktop changed original handle",
    )?;
    require(
        header("x-artifact-read-sequence")?
            .parse::<u32>()
            .map_err(|error| error.to_string())?
            == sequence,
        "Desktop changed original sequence",
    )?;
    require(
        header("x-artifact-read-length")?
            .parse::<usize>()
            .map_err(|error| error.to_string())?
            == response.body().len(),
        "Desktop copy length differed from actual original descriptor",
    )?;
    require(
        header("x-artifact-read-eof")? == if eof { "true" } else { "false" },
        "Desktop EOF framing changed actual zero observation",
    )?;
    require(
        response.body().len() <= 4 * 1024 * 1024 && eof == response.body().is_empty(),
        "Desktop copy violated bounded actual block shape",
    )
}

struct CarrierGate {
    entered: tokio::sync::Notify,
    reached: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    release_changed: Condvar,
}

impl CarrierGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            reached: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            release_changed: Condvar::new(),
        })
    }

    fn hold_actual_thread(&self) {
        self.reached.store(true, Ordering::SeqCst);
        self.entered.notify_one();
        let held = self.released.lock().expect("owned gate mutex poisoned");
        let (released, timeout) = self
            .release_changed
            .wait_timeout_while(held, Duration::from_secs(5), |released| !*released)
            .expect("owned gate wait poisoned");
        self.timed_out
            .store(timeout.timed_out() && !*released, Ordering::SeqCst);
    }

    fn release(&self) {
        *self.released.lock().expect("owned gate mutex poisoned") = true;
        self.release_changed.notify_all();
    }

    async fn await_entered(&self) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
            .await
            .map_err(|_| "actual same-response gate was not reached".to_owned())?;
        require(
            self.reached.load(Ordering::SeqCst) && !self.timed_out.load(Ordering::SeqCst),
            "actual same-response gate timed out",
        )
    }
}

struct ReleaseCarrierGate(Arc<CarrierGate>);
impl Drop for ReleaseCarrierGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct CopyTailSubscriber(Arc<CarrierGate>);
impl tracing::Subscriber for CopyTailSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Phase(bool);
        impl tracing::field::Visit for Phase {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "public_artifact_read_host_phase"
                    && value == "desktop_copy_complete_before_final_tail"
                {
                    self.0 = true;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut phase = Phase(false);
        event.record(&mut phase);
        if phase.0 {
            self.0.hold_actual_thread();
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local PostgreSQL bundle"]
async fn actual_prepared_local_public_reader_uses_shared_responder_bridge_and_eof() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-bridge")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        let opened: ArtifactReadOpened = control(
            bridge(
                protocol,
                "main",
                open_request(&fixture.artifact.artifact_id)?,
            )
            .await,
        )?;
        require(
            opened.artifact_id == fixture.artifact.artifact_id
                && opened.byte_length == PAYLOAD.len() as u64
                && opened.sha256 == format!("{:x}", Sha256::digest(PAYLOAD.as_bytes()))
                && opened.remaining_millis > 0
                && opened.remaining_millis <= 600_000,
            "Local Open did not use actual original prepared facts",
        )?;
        let prepared = protocol
            .prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?)
            .await;
        let called = AtomicBool::new(false);
        let response =
            protocol.finish_public_artifact_read_response("main", prepared, |response| {
                called.store(true, Ordering::SeqCst);
                response
            });
        require(
            called.load(Ordering::SeqCst),
            "shared real responder bridge was bypassed",
        )?;
        data(&response, &opened.handle_id, 0, false)?;
        require(
            response.body().as_slice() == PAYLOAD.as_bytes(),
            "actual Local bytes changed original text",
        )?;
        // This callback's returned Vec is a framework/test copy, not the original RAII carrier.
        // The real finish path has now returned and dropped its controlled original owner.
        status(
            protocol
                .handle("main", next_request(&opened.handle_id, 0)?)
                .await,
            StatusCode::CONFLICT,
        )?;
        let ack: ArtifactReadAcknowledged = control(
            protocol
                .handle("main", ack_request(&opened.handle_id, 0)?)
                .await,
        )?;
        let duplicate: ArtifactReadAcknowledged =
            control(bridge(protocol, "main", ack_request(&opened.handle_id, 0)?).await)?;
        require(
            ack == duplicate && ack.handle_id == opened.handle_id && ack.sequence == 0,
            "Local matching ACK retry changed original accepted sequence",
        )?;
        status(
            protocol
                .handle(
                    "main",
                    request(
                        Method::DELETE,
                        &format!("{}/{}/", super::PREFIX, opened.handle_id),
                        None,
                    )?,
                )
                .await,
            StatusCode::NOT_FOUND,
        )?;
        let eof = protocol
            .handle("main", next_request(&opened.handle_id, 1)?)
            .await;
        data(&eof, &opened.handle_id, 1, true)?;
        require(
            response.body().as_slice() == PAYLOAD.as_bytes(),
            "original cleanup falsely claimed framework-transferred Vec destruction",
        )?;
        Ok(())
    }
    .await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local public bridge/eof and resource closure");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local and actual bounded copy-tail barrier"]
async fn actual_prepared_local_public_reader_copy_tail_and_rebinding_withhold_data() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-copy-tail")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        let opened: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)?;
        let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?).await;
        let gate = CarrierGate::new();
        let release = ReleaseCarrierGate(gate.clone());
        let worker_protocol = protocol.clone();
        let worker_gate = gate.clone();
        let worker = tokio::task::spawn_blocking(move || {
            tracing::subscriber::with_default(CopyTailSubscriber(worker_gate), || {
                worker_protocol.finish_public_artifact_read_response("main", prepared, |response| response)
            })
        });
        let changed = async {
            gate.await_entered().await?;
            protocol.unbind_window("main").map_err(|error| error.to_string())?;
            protocol.bind_window("main", fixture.prepared().auth_context().clone(), None)
                .map_err(|error| error.to_string())?;
            require(!gate.timed_out.load(Ordering::SeqCst), "real copy gate expired before original rebinding")
        }.await;
        gate.release();
        let response = worker.await.map_err(|error| error.to_string())?;
        drop(release);
        changed?;
        require(!gate.timed_out.load(Ordering::SeqCst), "real copy tail resumed only after timeout")?;
        status(response, StatusCode::UNAUTHORIZED)?;
        let fresh: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)?;
        let foreign = fixture.new_protocol()?;
        foreign.bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        status(foreign.handle("main", next_request(&fresh.handle_id, 0)?).await,
            StatusCode::NOT_FOUND)?;
        foreign.close_request_bindings();
        let response = protocol.handle("main", next_request(&fresh.handle_id, 0)?).await;
        data(&response, &fresh.handle_id, 0, false)?;
        require(response.body().as_slice() == PAYLOAD.as_bytes(), "foreign owner closure destroyed current original reader")?;
        let closed: ArtifactReadClosed = control(bridge(protocol, "main", close_request(&fresh.handle_id)?).await)?;
        require(closed.handle_id == fresh.handle_id, "Local Close changed original handle")?;
        let prepared_control = protocol.prepare_public_artifact_read_response("main", open_request(&fixture.artifact.artifact_id)?).await;
        protocol.unbind_window("main").map_err(|error| error.to_string())?;
        protocol.bind_window("main", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        status(protocol.finish_public_artifact_read_response("main", prepared_control, |response| response),
            StatusCode::UNAUTHORIZED)?;
        status(protocol.handle("main", request(Method::POST, "/api/artifact-reads?", Some(
            serde_json::json!({"artifactId": fixture.artifact.artifact_id})))?).await, StatusCode::BAD_REQUEST)?;
        status(protocol.handle("main", request(Method::POST, super::PREFIX, Some(
            serde_json::json!({"artifactId": fixture.artifact.artifact_id, "path": "/forbidden"})))?).await,
            StatusCode::BAD_REQUEST)?;
        status(protocol.handle("main", request(Method::HEAD, super::PREFIX, None)?).await,
            StatusCode::METHOD_NOT_ALLOWED)?;
        let oversized = Request::builder().method(Method::POST).uri("openbot://localhost/api/artifact-reads")
            .header("content-type", "application/json").body(vec![b'x'; super::API_BODY_MAX_BYTES + 1])
            .map_err(|error| error.to_string())?;
        status(protocol.handle("main", oversized).await, StatusCode::PAYLOAD_TOO_LARGE)?;
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local copy/window tail and physical cleanup");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local and held actual responder carrier"]
async fn actual_prepared_local_public_reader_close_isolated_original_resources() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-own-close")
        .await
        .expect("genuine own Local setup");
    let outcome = async {
        let protocol = fixture.prepared().protocol();
        protocol.bind_window("peer", fixture.prepared().auth_context().clone(), None)
            .map_err(|error| error.to_string())?;
        let original: ArtifactReadOpened = control(bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("original_open: {error}"))?;
        let peer: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("peer_open: {error}"))?;
        status(protocol.handle("peer", next_request(&original.handle_id, 0)?).await, StatusCode::NOT_FOUND)?;
        let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&original.handle_id, 0)?).await;
        let original_close_request = close_request(&original.handle_id)?;
        let gate = CarrierGate::new();
        let release = ReleaseCarrierGate(gate.clone());
        let worker_protocol = protocol.clone();
        let worker_gate = gate.clone();
        let responder = tokio::task::spawn_blocking(move || {
            worker_protocol.finish_public_artifact_read_response("main", prepared, |response| {
                // The original transport block remains truly owned until this actual callback returns.
                worker_gate.hold_actual_thread();
                response
            })
        });
        let mut closing = Box::pin(protocol.handle("main", original_close_request));
        let while_held = async {
            gate.await_entered().await?;
            require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                "Local Close falsely ACKed while the actual responder still owned original allocation")?;
            let peer_data = protocol.handle("peer", next_request(&peer.handle_id, 0)?).await;
            data(&peer_data, &peer.handle_id, 0, false)?;
            require(peer_data.body().as_slice() == PAYLOAD.as_bytes(), "own Close blocked another real Window's bytes")?;
            let peer_closed: ArtifactReadClosed = control(protocol.handle("peer", close_request(&peer.handle_id)?).await)
                .map_err(|error| format!("peer_close: {error}"))?;
            require(peer_closed.handle_id == peer.handle_id, "peer Close borrowed original resource inventory")?;
            require(tokio::time::timeout(Duration::from_millis(30), &mut closing).await.is_err(),
                "peer completion falsely closed a still-held original responder owner")
        }.await;
        gate.release();
        let response = responder.await.map_err(|error| error.to_string())?;
        drop(release);
        let closed = tokio::time::timeout(Duration::from_secs(4), &mut closing).await
            .map_err(|_| "original real responder return did not unblock own Close")?;
        while_held?;
        require(!gate.timed_out.load(Ordering::SeqCst), "actual responder was released only by timeout")?;
        data(&response, &original.handle_id, 0, false)?;
        let closed: ArtifactReadClosed = control(closed)
            .map_err(|error| format!("original_close: {error}"))?;
        require(closed.handle_id == original.handle_id, "real original Close returned another Window's handle")?;
        protocol.unbind_window("main").map_err(|error| error.to_string())?;
        let surviving: ArtifactReadOpened = control(bridge(protocol, "peer", open_request(&fixture.artifact.artifact_id)?).await)
            .map_err(|error| format!("surviving_open: {error}"))?;
        let survived = protocol.handle("peer", next_request(&surviving.handle_id, 0)?).await;
        data(&survived, &surviving.handle_id, 0, false)?;
        let _: ArtifactReadClosed = control(protocol.handle("peer", close_request(&surviving.handle_id)?).await)
            .map_err(|error| format!("surviving_close: {error}"))?;
        protocol.unbind_window("peer").map_err(|error| error.to_string())?;
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    // Only the original BackgroundOwner ACK plus owned PID absence permits retirement.
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local isolated original resource closure");
}

// Controlled 0044 rows are consumer inputs only. These observations never assert deletion,
// directory sync, refund, cleanup authorization or a producer receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine owned Prepared Local and actual shared copy/responder owners"]
async fn shared_read_barrier_waits_for_desktop_copy_and_responder_tail() {
    use tracing::instrument::WithSubscriber as _;
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "shared-local-copy-responder")
        .await
        .expect("genuine owned Prepared Local setup");
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let outcome = async {
        let auth = {
            protocol.windows.try_read().map_err(|_| "actual original window registry unavailable")?
                .get("main").ok_or("actual original main Window missing")?.auth.clone()
        };
        // Both keys are materialized by the real already-assembled Local Application/Save.
        let saved_b = fixture.prepared().application().execute(auth.clone(),
            AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: uuid::Uuid::now_v7().to_string(),
                source_thread_id: fixture.artifact.source_thread_id.clone(),
                source_run_id: fixture.artifact.source_run_id.clone(),
                source_message_id: fixture.artifact.source_message_id.clone(),
                expected_sha256: format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
            }),
        ).await.map_err(|error| error.to_string())?;
        let saved_b = match saved_b {
            AppReply::ArtifactRegistrationReceipt(saved) => saved,
            _ => return Err("second actual Local Save returned another receipt".to_owned()),
        };
        require(saved_b.artifact_id != fixture.artifact.artifact_id && saved_b.operation_id != fixture.artifact.operation_id,
            "Local responder leg did not use a different actual saved key")?;
        for (saved, copy_tail) in [(&fixture.artifact, true), (&saved_b, false)] {
            let record = actual.observe_read_record(&auth, &saved.artifact_id).await.map_err(|error| error.to_string())?;
            let path = fixture.root.0.join("artifacts/objects").join(&saved.artifact_id);
            require(cleanup_owned_inode_fds(&path)?.is_empty(), "Local key began with an unexpected reader FD")?;
            let phases = Arc::new(CleanupCachedIoPhases::default());
            let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
            let opened: ArtifactReadOpened = control(bridge(&protocol, "main", open_request(&saved.artifact_id)?)
                .with_subscriber(dispatch.clone()).await)?;
            let prepared = protocol.prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?)
                .with_subscriber(dispatch).await;
            let io_before = phases.io.load(Ordering::SeqCst);
            let joint_before = phases.joint.load(Ordering::SeqCst);
            let segments_before = phases.segments.load(Ordering::SeqCst);
            require(io_before == 1 && joint_before >= 2,
                "real Local preparation/cached refresh did not complete its original IO and final joint query")?;
            let client = fixture.prepared().pool().get().await.map_err(|error| error.to_string())?;
            let before = cleanup_public_read_facts_on(&client).await?;
            drop(client);
            let gate = CarrierGate::new();
            let release = ReleaseCarrierGate(gate.clone());
            let worker_protocol = protocol.clone();
            let worker_gate = gate.clone();
            let worker = tokio::task::spawn_blocking(move || {
                if copy_tail {
                    tracing::subscriber::with_default(CopyTailSubscriber(worker_gate), || {
                        worker_protocol.finish_public_artifact_read_response("main", prepared, |response| response)
                    })
                } else {
                    worker_protocol.finish_public_artifact_read_response("main", prepared, |response| {
                        // Keep the actual original transport allocation until the real callback returns.
                        worker_gate.hold_actual_thread();
                        response
                    })
                }
            });
            let observed = async {
                gate.await_entered().await?;
                require(cleanup_owned_inode_fds(&path)?.len() == 1, "held actual Local copy/responder did not retain its original FD")?;
                let barrier = actual.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
                require(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await.is_err(),
                    "shared Local close ACKed before the original actual copy/responder owner ended")?;
                require(cleanup_owned_inode_fds(&path)?.len() == 1, "shared close dropped a still-used Local FD")?;
                Ok::<_, String>(barrier)
            }.await;
            gate.release();
            let response = worker.await.map_err(|error| error.to_string())?;
            drop(release);
            let barrier = observed?;
            require(!gate.timed_out.load(Ordering::SeqCst), "actual Local owner ended only because its gate timed out")?;
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(4)).await.map_err(|error| format!("{error:?}"))?;
            require(cleanup_owned_inode_fds(&path)?.is_empty() && path.is_file(),
                "actual Local original block ended without FD closure or deleted the object")?;
            if copy_tail {
                status(response, StatusCode::SERVICE_UNAVAILABLE)?;
            } else {
                data(&response, &opened.handle_id, 0, false)?;
                require(response.body().as_slice() == PAYLOAD.as_bytes(),
                    "controlled Local ACK falsely claimed returned response Vec destruction")?;
                drop(response);
            }
            require(phases.io.load(Ordering::SeqCst) == io_before
                && phases.joint.load(Ordering::SeqCst) == joint_before
                && phases.segments.load(Ordering::SeqCst) == segments_before,
                "shared synchronous Local copy/responder was mistaken for another IO or PG wait")?;
            let client = fixture.prepared().pool().get().await.map_err(|error| error.to_string())?;
            let after = cleanup_public_read_facts_on(&client).await?;
            drop(client);
            require(before == after, "shared Local close mutated original business/charge/receipt/fence/audit/identity facts")?;
            drop(ack); drop(barrier); drop(record);
            eprintln!("ARTIFACT_SHARED_LOCAL copy_tail={copy_tail} actual_owner_held_no_ack=true real_callback_joined=true original_fd_absent=true controlled_ack=true io_joint_unchanged=true pg_wait=false returned_response_lifetime=UNTRACKED");
        }
        Ok::<_, String>(())
    }.await;
    // Retire every extra test owner before the actual runtime shutdown/PID proof.
    drop(protocol);
    drop(actual);
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual shared Local copy/responder owners and original physical closure");
}

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

fn cleanup_cached_schema_difference_paths(
    expected: &serde_json::Value,
    actual: &serde_json::Value,
    path: &str,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    if expected == actual || out.len() >= 16 {
        return;
    }
    match (expected, actual) {
        (Value::Object(left), Value::Object(right)) => {
            for (key, value) in left {
                if out.len() >= 16 {
                    return;
                }
                let next = format!("{path}/{key}");
                match right.get(key) {
                    Some(other) => cleanup_cached_schema_difference_paths(value, other, &next, out),
                    None => out.push(next),
                }
            }
            if out.len() < 16 && right.keys().any(|key| !left.contains_key(key)) {
                out.push(format!("{path}/<unexpected-object-key>"));
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                out.push(format!("{path}/<array-length>"));
            }
            for (index, (value, other)) in left.iter().zip(right).enumerate() {
                if out.len() >= 16 {
                    return;
                }
                cleanup_cached_schema_difference_paths(
                    value,
                    other,
                    &format!("{path}/{index}"),
                    out,
                );
            }
        }
        _ => out.push(path.to_owned()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local, committed 0044 consumer fence and original retained reader"]
async fn actual_prepared_local_public_reader_cached_first_cleanup_fence_recheck_refuses_body() {
    use tracing::instrument::WithSubscriber as _;
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "public-read-cached-cleanup")
        .await
        .expect("genuine owned Prepared Local setup");
    let outcome = async {
        let prepared = fixture.prepared();
        let protocol = prepared.protocol();
        let path = fixture.root.0.join("artifacts/objects").join(&fixture.artifact.artifact_id);
        require(cleanup_owned_inode_fds(&path)?.is_empty(),
            "owned saved Local artifact unexpectedly began with a live read FD")?;
        let tracker = protocol.local_capability_authority.as_ref()
            .and_then(|source| source.artifact_read_lifecycle())
            .ok_or("same genuine Local artifact lifecycle unavailable")?;
        let phases = Arc::new(CleanupCachedIoPhases::default());
        let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
        let opened: ArtifactReadOpened = control(
            bridge(protocol, "main", open_request(&fixture.artifact.artifact_id)?)
                .with_subscriber(dispatch.clone()).await,
        )?;
        require(opened.artifact_id == fixture.artifact.artifact_id
            && opened.byte_length == PAYLOAD.len() as u64
            && opened.sha256 == format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
            "genuine Prepared Local Open did not retain original Save facts")?;
        let after_open = phases.actual_counts();
        require(after_open.0 == 1 && after_open.1 >= 2,
            "successful genuine Local Open did not complete original physical prefix and current queries")?;
        require(!cleanup_owned_inode_fds(&path)?.is_empty(),
            "successful Local Open did not retain its actual original object FD")?;
        let client = prepared.pool().get().await.map_err(|error| error.to_string())?;
        let mut expected = cleanup_public_read_facts_on(&client).await?;
        require(expected["fences"] == serde_json::json!([]),
            "owned cached-first Local fixture unexpectedly began fenced")?;
        drop(client);
        let original_auth = prepared.auth_context();
        let inserted = arm_cached_first_cleanup_fence(
            prepared.pool(), original_auth.deployment().as_str(), original_auth.tenant().as_str(),
            original_auth.actor().as_str(), &fixture.artifact,
        ).await?;
        expected["fences"] = serde_json::json!([inserted]);
        // The actual transaction's COMMIT ACK precedes this same handle's delayed seq0 request.
        let response = bridge(protocol, "main", next_request(&opened.handle_id, 0)?)
            .with_subscriber(dispatch).await;
        no_store(&response)?;
        require(response.status() == StatusCode::SERVICE_UNAVAILABLE,
            "delayed genuine Local cached first did not refuse its committed armed fence")?;
        require(["x-artifact-read-handle", "x-artifact-read-sequence",
            "x-artifact-read-length", "x-artifact-read-eof"].iter()
            .all(|name| response.headers().get(*name).is_none()),
            "Local cleanup-fence refusal retained data descriptor headers")?;
        let error: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| error.to_string())?;
        require(error == serde_json::json!({"code":"dependency_unavailable"})
            && !response.body().windows(PAYLOAD.len()).any(|part| part == PAYLOAD.as_bytes()),
            "Local cleanup refusal exposed cached payload or changed original static error")?;
        drop(response);
        let after_refusal = phases.actual_counts();
        require(after_refusal.0 == after_open.0
            && after_refusal.2 == after_open.2 && after_refusal.1 == after_open.1 + 1,
            "genuine cached first refusal repeated physical prefix work or omitted the real final query")?;
        // Prepared Local keeps per-operation Completion inside the real application's registry.
        // This existing protocol closes and awaits only this actual authority's fixture inventory;
        // its ACK requires jobs and physical resource owners to end. No replacement Completion is used.
        prepared.application().close_public_artifact_reads().map_err(|error| error.to_string())?;
        tracker.close();
        tracker.drain_before(std::time::Instant::now() + Duration::from_secs(5)).await
            .map_err(|_| "same Prepared Local read inventory did not actually drain".to_owned())?;
        require(cleanup_owned_inode_fds(&path)?.is_empty(),
            "original Local object inode retained a live FD after actual inventory drain ACK")?;
        let client = prepared.pool().get().await.map_err(|error| error.to_string())?;
        require(cleanup_public_read_facts_on(&client).await? == expected,
            "Local cached first consumer changed original source, receipt, record, charge, quota, store, fence, audit or host facts")?;
        require(std::fs::read(&path).map_err(|error| error.to_string())? == PAYLOAD.as_bytes(),
            "consumer fence changed the original owned Local artifact bytes")?;
        eprintln!("PUBLIC_ARTIFACT_LOCAL_CACHED_CLEANUP original_prepared_open=true controller_commit_ack=true seq0_refused=true no_store=true no_payload=true original_io_ack_count={} final_query_increment=1 same_authority_fixture_inventory_drain_ack=true own_inode_fd_absent=true business_facts_unchanged=true",
            after_open.0);
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("genuine Prepared Local cached first cleanup-fence refusal and physical closure");
}

async fn cleanup_arm_local_database_facts(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let tables=c.query("SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','openbot_internal') AND c.relkind='r' ORDER BY n.nspname,c.relname",&[]).await.map_err(|e|e.to_string())?;
    let mut facts = BTreeMap::new();
    for row in tables {
        let schema: String = row.get(0);
        let name: String = row.get(1);
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let sql = format!(
            "SELECT coalesce(jsonb_agg(jsonb_build_object('row',to_jsonb(t),'xmin',t.xmin::text,'ctid',t.ctid::text) ORDER BY to_jsonb(t)::text,t.ctid),'[]'::jsonb) FROM {}.{} t",
            quote(&schema),
            quote(&name)
        );
        facts.insert(
            format!("{schema}.{name}"),
            c.query_one(&sql, &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0),
        );
    }
    Ok(facts)
}
fn cleanup_arm_local_only_tables_changed(
    before: &BTreeMap<String, serde_json::Value>,
    after: &BTreeMap<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), String> {
    require(
        before.keys().eq(after.keys()),
        "Local controller/arm changed ordinary table inventory",
    )?;
    for (table, value) in before {
        if !allowed.contains(&table.as_str()) && after.get(table) != Some(value) {
            return Err(format!(
                "Local arm changed unexpected ordinary/physical table: {table}"
            ));
        }
    }
    Ok(())
}
fn cleanup_arm_local_object_fact(path: &Path) -> Result<PhysicalLocalObjectFact, String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        m.is_file() && m.mode() & 0o7777 == 0o400 && m.nlink() == 1,
        "Local original artifact inode/type/mode changed",
    )?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.len(),
        format!("{:x}", Sha256::digest(&bytes)),
    ))
}
async fn cleanup_arm_local_waiter(
    pool: &openbot_infra::db::pool::DatabasePool,
    controller_pid: i32,
) -> Result<(i32, i32), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let observer = pool.get().await.map_err(|e| e.to_string())?;
        let observer_pid: i32 = observer
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let rows=observer.query("SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event_type='Lock' AND query LIKE '%artifact_workspace_quotas%' AND $1::integer=ANY(pg_catalog.pg_blocking_pids(pid))",&[&controller_pid]).await.map_err(|e|e.to_string())?;
        if rows.len() == 1 {
            let waiter: i32 = rows[0].get(0);
            require(
                waiter != controller_pid
                    && waiter != observer_pid
                    && controller_pid != observer_pid,
                "Local original waiter/controller/observer PIDs were not distinct",
            )?;
            return Ok((waiter, observer_pid));
        }
        require(
            Instant::now() < deadline,
            "Local arm did not reach the actual owned quota PG lock",
        )?;
        drop(observer);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires genuine Prepared Local/Window, owned PostgreSQL bundle and real Save/arm"]
async fn actual_local_original_window_arms_missing_source_and_rebound_window_is_refused() {
    use openbot_infra::artifact_administration::ArtifactCleanupArmError as ArmError;
    let missing_source_status = |response: Response<Vec<u8>>, phase: &'static str| {
        let actual_status = response.status().as_u16();
        eprintln!(
            "ARTIFACT_CLEANUP_ARM_LOCAL_REFUSAL phase={phase} expected_status=404 actual_status={actual_status} response_body_omitted=true"
        );
        status(response, StatusCode::NOT_FOUND).map_err(|error| {
            format!("{error}: phase={phase} expected_status=404 actual_status={actual_status}")
        })
    };
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact PG bundle");
    let fixture = LocalFixture::new(&bundle, "cleanup-arm-original-window")
        .await
        .expect("genuine Prepared Local setup");
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let outcome=async {
        let original_auth=protocol.windows.try_read().map_err(|_|"original Window registry unavailable")?.get("main").ok_or("original actual main Window missing")?.auth.clone();
        let second=fixture.prepared().application().execute(original_auth.clone(),AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact{
            request_id:uuid::Uuid::now_v7().to_string(),source_thread_id:fixture.artifact.source_thread_id.clone(),source_run_id:fixture.artifact.source_run_id.clone(),source_message_id:fixture.artifact.source_message_id.clone(),expected_sha256:format!("{:x}",Sha256::digest(PAYLOAD.as_bytes())),
        })).await.map_err(|e|e.to_string())?;
        let second=match second {AppReply::ArtifactRegistrationReceipt(r)=>r,_=>return Err("second genuine Local Save returned another reply".to_owned())};
        require(second.artifact_id!=fixture.artifact.artifact_id&&second.operation_id!=fixture.artifact.operation_id,"Local refusal key reused the already armed original operation")?;
        let path=fixture.root.0.join("artifacts/objects").join(&fixture.artifact.artifact_id);
        let second_path=fixture.root.0.join("artifacts/objects").join(&second.artifact_id);
        let first_object=cleanup_arm_local_object_fact(&path)?;let second_object=cleanup_arm_local_object_fact(&second_path)?;
        let opened:ArtifactReadOpened=control(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await)?;
        require(opened.artifact_id==fixture.artifact.artifact_id&&cleanup_owned_inode_fds(&path)?.len()==1,"original actual Local cached reader has no real original key/FD")?;
        let before_source=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let mut controller=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let tx=controller.transaction().await.map_err(|e|e.to_string())?;
        let source_controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        require(tx.execute("DELETE FROM public.messages WHERE message_id=$1",&[&fixture.artifact.source_message_id]).await.map_err(|e|e.to_string())?==1,"Local source controller did not hard-delete the original message")?;
        tx.commit().await.map_err(|e|e.to_string())?;drop(controller);
        let after_source=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        cleanup_arm_local_only_tables_changed(&before_source,&after_source,&["public.messages"])?;
        let original_messages=before_source.get("public.messages").and_then(serde_json::Value::as_array).ok_or("original Local messages missing")?;
        let current_messages=after_source.get("public.messages").and_then(serde_json::Value::as_array).ok_or("current Local messages missing")?;
        let retained_messages:Vec<_>=original_messages.iter().filter(|v|v["row"]["message_id"].as_str()!=Some(fixture.artifact.source_message_id.as_str())).cloned().collect();
        require(retained_messages.len()+1==original_messages.len()&&retained_messages==*current_messages,"Local source controller changed undeclared messages or physical row carriers")?;
        require(before_source.get("public.messages")!=after_source.get("public.messages"),"Local source controller did not commit a real source row difference")?;
        missing_source_status(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await,"source_hard_delete_commit_ack_before_arm")?;
        require(matches!(fixture.prepared().application().execute(original_auth.clone(),AppCommand::GetArtifactMetadata(openbot_contracts::artifacts::GetArtifactMetadata{artifact_id:fixture.artifact.artifact_id.clone()})).await,Err(openbot_contracts::error::AppError::NotVisible)),"Local cleanup owner management reopened missing-source metadata")?;
        let before_arm=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let intent=actual.arm_explicit_saved_delete_before(&original_auth,&fixture.artifact.artifact_id,Instant::now()+Duration::from_secs(10)).await.map_err(|e|e.to_string())?;
        let armed=cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        cleanup_arm_local_only_tables_changed(&before_arm,&armed,&["openbot_internal.artifact_cleanup_fences","public.audit_events","public.audit_checkpoints"])?;
        let old_audit=before_arm.get("public.audit_events").and_then(serde_json::Value::as_array).ok_or("Local original audit facts missing")?;
        let new_audit=armed.get("public.audit_events").and_then(serde_json::Value::as_array).ok_or("Local current audit facts missing")?;
        require(!old_audit.is_empty()&&new_audit.len()==old_audit.len()+1&&old_audit.iter().all(|v|new_audit.contains(v))&&before_arm.get("public.audit_checkpoints")==armed.get("public.audit_checkpoints"),"Local arm changed previous real Save audit/physical rows or checkpoint")?;
        let c=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let original_dataset:String=c.query_one("SELECT dataset_id FROM openbot_internal.artifact_records WHERE deployment_id=$1 AND tenant_id=$2 AND operation_id=$3 AND artifact_id=$4",&[&original_auth.deployment().as_str(),&original_auth.tenant().as_str(),&fixture.artifact.operation_id,&fixture.artifact.artifact_id]).await.map_err(|e|e.to_string())?.get(0);
        let fence=c.query("SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase FROM openbot_internal.artifact_cleanup_fences",&[]).await.map_err(|e|e.to_string())?;
        require(fence.len()==1&&fence[0].get::<_,String>(0)==original_auth.deployment().as_str()&&fence[0].get::<_,String>(1)==original_auth.tenant().as_str()&&fence[0].get::<_,String>(2)==original_dataset&&fence[0].get::<_,String>(3)==fixture.artifact.operation_id&&fence[0].get::<_,String>(4)==fixture.artifact.artifact_id&&fence[0].get::<_,String>(5)=="deleted"&&fence[0].get::<_,String>(6)=="armed","Local arm did not preserve exact original namespace/pair and fixed intent")?;
        let audit=c.query("SELECT actor_user_id,target_type,target_id,payload FROM public.audit_events WHERE event_type='artifact.cleanup_armed'",&[]).await.map_err(|e|e.to_string())?;
        require(audit.len()==1&&audit[0].get::<_,Option<String>>(0).as_deref()==Some(original_auth.actor().as_str())&&audit[0].get::<_,String>(1)=="artifact"&&audit[0].get::<_,Option<String>>(2).as_deref()==Some(fixture.artifact.artifact_id.as_str())&&audit[0].get::<_,serde_json::Value>(3)==serde_json::json!({"artifact_id":fixture.artifact.artifact_id,"artifact_operation_id":fixture.artifact.operation_id}),"Local arm audit was missing, duplicated or changed fixed typed IDs")?;drop(c);
        let barrier=actual.close_armed_artifact_reads(&intent).map_err(|e|e.to_string())?;
        let ack=barrier.drain_before(Instant::now()+Duration::from_secs(4)).await.map_err(|e|format!("{e:?}"))?;
        require(cleanup_owned_inode_fds(&path)?.is_empty()&&cleanup_arm_local_object_fact(&path)?==first_object,"Local finite armed close ACK lacked actual FD end or deleted original object")?;
        missing_source_status(bridge(&protocol,"main",open_request(&fixture.artifact.artifact_id)?).await,"armed_close_ack_original_source_missing")?;
        require(cleanup_arm_local_database_facts(fixture.prepared().pool()).await?==armed,"Local finite close or stopped reader wrote business rows")?;
        drop(ack);drop(barrier);drop(intent);
        // A second actual pair remains unfenced. Wait for its real original arm quota query,
        // then replace the original window before releasing the controller's actual lock.
        let mut controller=fixture.prepared().pool().get().await.map_err(|e|e.to_string())?;
        let tx=controller.transaction().await.map_err(|e|e.to_string())?;
        let controller_pid:i32=tx.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
        tx.query_one("SELECT workspace_id FROM openbot_internal.artifact_workspace_quotas WHERE workspace_id=$1 FOR UPDATE",&[&second.source_thread_id.as_str()]).await.map_err(|e|e.to_string())?;
        let worker_actual=actual.clone();let worker_auth=original_auth.clone();let artifact=second.artifact_id.clone();
        let worker=tokio::spawn(async move {worker_actual.arm_explicit_saved_delete_before(&worker_auth,&artifact,Instant::now()+Duration::from_secs(10)).await});
        let (waiter_pid,observer_pid)=cleanup_arm_local_waiter(fixture.prepared().pool(),controller_pid).await?;
        protocol.unbind_window("main").map_err(|e|e.to_string())?;
        protocol.bind_window("main",fixture.prepared().auth_context().clone(),None).map_err(|e|e.to_string())?;
        let rebound=protocol.windows.try_read().map_err(|_|"new actual Window unavailable")?.get("main").ok_or("new actual Window missing")?.auth.clone();
        require(rebound==original_auth&&!rebound.request_binding().unwrap().identity().same_binding(original_auth.request_binding().unwrap().identity()),"Local same-label rebind did not replace the original epoch while retaining six Auth facts")?;
        tx.rollback().await.map_err(|e|e.to_string())?;drop(controller);
        require(matches!(worker.await.map_err(|e|e.to_string())?,Err(ArmError::Host(openbot_contracts::request_binding::HostRequestBindingError::NotCurrent))),"actual quota waiter armed using the replaced original Window")?;
        require(cleanup_arm_local_database_facts(fixture.prepared().pool()).await?==armed&&cleanup_arm_local_object_fact(&path)?==first_object&&cleanup_arm_local_object_fact(&second_path)?==second_object,"rebound-window refusal changed original pair/charge/fence/audit/bytes")?;
        eprintln!("ARTIFACT_CLEANUP_ARM_LOCAL source_controller_pid={source_controller_pid} source_hard_delete_commit_ack=true original_window_arm_ack=true exact_arm_audit=true controlled_original_fd_absent=true original_object_unchanged=true waiter_pid={waiter_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_quota_lock=true window_replaced_before_unlock=true controller_rollback_ack=true old_request_refused=true physical_delete=false");
        Ok::<_,String>(())
    }.await;
    drop(protocol);
    drop(actual);
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    drop(bundle);
    outcome
        .and(cleaned)
        .expect("actual Local original Window cleanup arm and physical owned closure");
}

async fn original_window_revocation_read_leg(
    fixture: &LocalFixture,
    operation_path: bool,
) -> Result<(), String> {
    let phase = if operation_path { "operation" } else { "chunk" };
    let prepared = fixture.prepared();
    let actual = Arc::clone(&prepared.artifact_administration);
    let protocol = Arc::clone(prepared.protocol());
    let original_auth = protocol
        .windows
        .try_read()
        .map_err(|_| "P1 original Window registry unavailable")?
        .get("main")
        .ok_or("P1 original main Window missing")?
        .auth
        .clone();
    let path = fixture
        .root
        .0
        .join("artifacts/objects")
        .join(&fixture.artifact.artifact_id);
    let original_object = cleanup_arm_local_object_fact(&path)?;
    let before = cleanup_arm_local_database_facts(prepared.pool()).await?;
    require(
        protocol
            .unbind_window("main")
            .map_err(|error| error.to_string())?,
        "P1 original actual Window was not revoked",
    )?;
    protocol
        .bind_window("main", prepared.auth_context().clone(), None)
        .map_err(|error| error.to_string())?;
    let fresh = protocol
        .windows
        .try_read()
        .map_err(|_| "P1 rebound Window registry unavailable")?
        .get("main")
        .ok_or("P1 rebound actual Window missing")?
        .auth
        .clone();
    require(
        fresh == original_auth
            && !fresh
                .request_binding()
                .ok_or("P1 new Window binding missing")?
                .identity()
                .same_binding(
                    original_auth
                        .request_binding()
                        .ok_or("P1 old Window binding missing")?
                        .identity(),
                ),
        "P1 real same-label Window rebind changed six Auth facts or reused the old epoch",
    )?;
    require(
        cleanup_arm_local_database_facts(prepared.pool()).await? == before,
        "P1 Window revocation/rebind wrote business rows",
    )?;

    // unbind_window stops only previously registered original States. Creating this
    // operation after revoke makes the genuine old-epoch Host port reject it instead.
    let old_error = if operation_path {
        let mut operation = prepared
            .application()
            .open_current_artifact_read(original_auth.clone(), fixture.artifact.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 old Window operation construction: {error}"))?;
        let result = operation.next_block(&original_auth).await;
        drop(operation);
        result.err()
    } else {
        prepared
            .application()
            .read_current_artifact_chunk(
                original_auth.clone(),
                fixture.artifact.artifact_id.clone(),
            )
            .await
            .err()
    };
    require(
        matches!(
            old_error,
            Some(openbot_contracts::error::AppError::Unauthenticated)
        ),
        "P1 revoked original Window did not preserve its actual Host refusal",
    )?;
    require(
        cleanup_arm_local_database_facts(prepared.pool()).await? == before
            && cleanup_arm_local_object_fact(&path)? == original_object,
        "P1 old Window refusal changed business rows or original object",
    )?;
    fresh
        .request_binding()
        .ok_or("P1 new actual Window missing")?
        .verify_current_before(&fresh, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|error| format!("P1 rebound genuine Window was not current: {error:?}"))?;
    require(
        Arc::ptr_eq(&actual, &prepared.artifact_administration),
        "P1 Local recovery replaced the original Administration/Store",
    )?;

    if !operation_path {
        let chunk = prepared
            .application()
            .read_current_artifact_chunk(fresh.clone(), fixture.artifact.artifact_id.clone())
            .await
            .map_err(|error| format!("P1 rebound same-Store chunk remained refused: {error}"))?;
        require(
            cleanup_owned_inode_fds(&path)?.len() == 1,
            "P1 real Local legacy chunk did not retain its original target FD before handoff",
        )?;
        let bytes = chunk.handoff(&fresh).map_err(|error| error.to_string())?;
        require(
            bytes == PAYLOAD.as_bytes(),
            "P1 rebound Window chunk changed actual saved bytes",
        )?;
        // This external legacy Vec has no finite allocation-release receipt.
        drop(bytes);
        require(
            cleanup_owned_inode_fds(&path)?.is_empty(),
            "P1 original Local legacy target FD did not close after its synchronous handoff",
        )?;
    }
    let mut operation = prepared
        .application()
        .open_current_artifact_read(fresh.clone(), fixture.artifact.artifact_id.clone())
        .await
        .map_err(|error| format!("P1 rebound same-Store operation remained refused: {error}"))?;
    let pending = operation
        .next_block(&fresh)
        .await
        .map_err(|error| format!("P1 rebound same-Store block remained refused: {error}"))?;
    require(
        pending.prefix_length().map_err(|error| error.to_string())? == PAYLOAD.len(),
        "P1 rebound Window did not materialize its genuine full leased allocation",
    )?;
    let frame = pending
        .handoff_frame(&fresh)
        .map_err(|error| error.to_string())?;
    require(
        frame.as_bytes() == PAYLOAD.as_bytes(),
        "P1 rebound Window leased frame changed saved bytes",
    )?;
    let held_fds = cleanup_owned_inode_fds(&path)?;
    require(
        held_fds.len() == 1,
        "P1 rebound Window did not own exactly its original object FD",
    )?;
    let record = actual
        .observe_read_record(&fresh, &fixture.artifact.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let barrier = actual
        .close_observed_artifact_reads(&record)
        .map_err(|error| error.to_string())?;
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ),
        "P1 rebound inventory ACKed a held real allocation or stayed poisoned",
    )?;
    drop(operation);
    require(
        matches!(
            barrier
                .drain_before(Instant::now() + Duration::from_millis(25))
                .await,
            Err(openbot_infra::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)
        ) && cleanup_owned_inode_fds(&path)? == held_fds,
        "P1 Local operation Drop substituted for the original last allocation owner",
    )?;
    drop(frame);
    let ack = barrier
        .drain_before(Instant::now() + Duration::from_secs(3))
        .await
        .map_err(|error| {
            format!("P1 same original Local Store failed its finite drain: {error:?}")
        })?;
    require(
        cleanup_owned_inode_fds(&path)?.is_empty()
            && cleanup_arm_local_object_fact(&path)? == original_object
            && cleanup_arm_local_database_facts(prepared.pool()).await? == before,
        "P1 rebound original allocation/FD closure changed rows or retained its actual FD",
    )?;
    drop(ack);
    drop(barrier);
    eprintln!(
        "ARTIFACT_READ_P1_LOCAL leg={phase} original_window_revoked=true distinct_rebound_epoch=true old_actual_host_refused=true new_true_window_current=true same_original_store_pair=true new_actual_bytes=true held_allocation_no_ack=true last_original_owner_dropped=true original_fd_absent=true finite_controlled_ack=true physical_delete=false legacy_returned_vec_lifetime=UNTRACKED"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires genuine Prepared Local, revoked/rebound original Window and owned PostgreSQL"]
async fn revoked_original_window_epoch_does_not_poison_rebound_same_store_artifact_reads_and_drain()
{
    let mut failures = Vec::new();
    for operation_path in [false, true] {
        let tag = if operation_path {
            "p1-window-operation"
        } else {
            "p1-window-chunk"
        };
        let mut bundle = OwnedBundle::materialize().expect("P1 exact owned PostgreSQL bundle");
        let fixture = LocalFixture::new(&bundle, tag)
            .await
            .expect("P1 genuine Prepared Local setup");
        let outcome = original_window_revocation_read_leg(&fixture, operation_path).await;
        let cleaned = fixture.finish().await;
        if cleaned.is_ok() {
            bundle.root.1 = true;
        }
        drop(bundle);
        if let Err(error) = outcome.and(cleaned) {
            eprintln!("ARTIFACT_READ_P1_LOCAL leg={tag} actual_result=FAILED");
            failures.push(format!("{tag}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "genuine old/new Window read and finite drain regressions: {failures:?}"
    );
}

// Task020 original inode inventory also remains meaningful after actual unlink.
fn physical_local_inode_fds(original: &PhysicalLocalObjectFact) -> Result<Vec<String>, String> {
    physical_local_inode_fds_for(original.0, original.1)
}
fn physical_local_inode_fds_for(
    original_device: u64,
    original_inode: u64,
) -> Result<Vec<String>, String> {
    let device = original_device & u64::from(u32::MAX);
    let sample = || -> Result<Vec<String>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "finite original own-PID lsof unavailable (Unproven)")?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("finite original lsof streams unavailable (Unproven)".to_owned());
        };
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let waited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Ok(None) => break Err("finite original own-PID lsof timed out (Unproven)"),
                Err(_) => break Err("finite original own-PID lsof wait failed (Unproven)"),
            }
        };
        // All error paths still reap this original child and both original pipe workers.
        // A killed/timed-out/error child is never credited as a natural successful sample.
        if waited.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let output = output.join();
        let errors = errors.join();
        let status = waited?;
        let output = output
            .map_err(|_| "original lsof stdout worker failed")?
            .map_err(|_| "original lsof stdout read failed")?;
        let errors = errors
            .map_err(|_| "original lsof stderr worker failed")?
            .map_err(|_| "original lsof stderr read failed")?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.is_empty()
                && output.ends_with(b"\n"),
            "original lsof was failed, incomplete, truncated or emitted stderr (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "original lsof output invalid")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("original lsof empty field")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "original lsof observed a peer PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(original_inode) {
                        found.insert(fd.ok_or("original inode had a nonnumeric ambiguous FD")?);
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
                        .map_err(|_| "original lsof device invalid")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "original lsof inode invalid")?,
                    );
                }
                _ => return Err("original lsof unexpected field".to_owned()),
            }
        }
        require(self_pid, "original lsof self-PID field missing")?;
        Ok(found.into_iter().map(|fd| fd.to_string()).collect())
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "original inode FD inventory changed between two actual samples (Unproven)",
    )?;
    Ok(first)
}

type PhysicalLocalObjectFact = (u64, u64, u32, u32, u64, u64, String);
#[derive(Default)]
struct PhysicalLocalPhaseFacts {
    seen: [usize; 4],
    original_fd: Option<i32>,
    nlink_after_unlink: Option<u64>,
    error: Option<String>,
    released: bool,
}
struct PhysicalLocalPhaseGate {
    artifact: uuid::Uuid,
    original: PhysicalLocalObjectFact,
    pause: usize,
    facts: Mutex<PhysicalLocalPhaseFacts>,
    changed: Condvar,
}
impl PhysicalLocalPhaseGate {
    fn new(
        artifact: &str,
        original: PhysicalLocalObjectFact,
        pause: usize,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            artifact: uuid::Uuid::parse_str(artifact).map_err(|e| e.to_string())?,
            original,
            pause,
            facts: Mutex::new(PhysicalLocalPhaseFacts::default()),
            changed: Condvar::new(),
        }))
    }
    fn release(&self) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.released = true;
            self.changed.notify_all();
        }
    }
    fn check(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "Local physical observer poisoned")?;
        match &facts.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    async fn wait(&self, phase: usize, deadline: Instant) -> Result<(), String> {
        loop {
            let seen = self
                .facts
                .lock()
                .map_err(|_| "Local physical observer poisoned")?
                .seen[phase - 1]
                > 0;
            if seen {
                return self.check();
            }
            require(
                Instant::now() < deadline,
                "Local actual original physical phase was not reached",
            )?;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    fn after_unlink_zero_link(&self) -> Result<(), String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "Local physical observer poisoned")?;
        require(
            facts.seen[2] == 1
                && facts.original_fd.is_some()
                && facts.nlink_after_unlink == Some(0),
            "Local original worker did not actually hold the original zero-link inode after unlink",
        )
    }
    fn observe(&self, phase: PhysicalPhase, artifact: uuid::Uuid, original_leaf_fd: Option<i32>) {
        let index = match phase {
            PhysicalPhase::PreflightReady => 1,
            PhysicalPhase::BeforeFirstUnlink => 2,
            PhysicalPhase::AfterUnlinkBeforeSync => 3,
            PhysicalPhase::WorkerEnded => 4,
        };
        let observed = (|| -> Result<Option<u64>, String> {
            require(
                artifact == self.artifact,
                "Local original observer changed artifact UUID",
            )?;
            if index == 4 {
                require(
                    original_leaf_fd.is_none(),
                    "Local WorkerEnded retained its leaf FD",
                )?;
                return Ok(None);
            }
            let Some(fd) = original_leaf_fd else {
                require(
                    self.facts
                        .lock()
                        .is_ok_and(|f| f.nlink_after_unlink == Some(0)),
                    "Local retained preflight did not have an actual original leaf FD",
                )?;
                return Ok(None);
            };
            // Explicit original same-process RawFd, no body read, unsafe borrow or FD scan.
            let duplicate = std::fs::File::open(format!("/dev/fd/{fd}"))
                .map_err(|_| "Local original physical FD duplicate failed")?;
            let m = duplicate
                .metadata()
                .map_err(|_| "Local original physical FD metadata failed")?;
            let valid = m.is_file()
                && m.dev() == self.original.0
                && m.ino() == self.original.1
                && m.uid() == self.original.2
                && m.mode() == self.original.3
                && m.len() == self.original.5;
            let nlink = m.nlink();
            drop(duplicate);
            require(
                valid && if index == 3 { nlink == 0 } else { nlink == 1 },
                "Local supplied phase FD was not the original inode with its actual expected link count",
            )?;
            Ok(Some(nlink))
        })();
        let Ok(mut facts) = self.facts.lock() else {
            return;
        };
        facts.seen[index - 1] += 1;
        match observed {
            Ok(nlink) => {
                if original_leaf_fd.is_some() {
                    facts.original_fd = original_leaf_fd;
                }
                if index == 3 {
                    facts.nlink_after_unlink = nlink;
                }
            }
            Err(e) => facts.error = Some(e),
        }
        self.changed.notify_all();
        let stop = Instant::now() + Duration::from_secs(8);
        while index == self.pause && !facts.released {
            let remaining = stop.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                facts.error = Some("Local original physical gate was not released".to_owned());
                break;
            }
            match self.changed.wait_timeout(facts, remaining) {
                Ok((next, _)) => facts = next,
                Err(_) => return,
            }
        }
    }
}
#[derive(Default)]
struct PhysicalLocalOriginalObserver {
    selected: Mutex<Option<Arc<PhysicalLocalPhaseGate>>>,
}
impl PhysicalLocalOriginalObserver {
    fn select(&self, gate: Arc<PhysicalLocalPhaseGate>) -> Result<(), String> {
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| "Local original observer selection poisoned")?;
        if let Some(previous) = selected.as_ref() {
            require(
                previous
                    .facts
                    .lock()
                    .map_err(|_| "Local prior observer poisoned")?
                    .seen[3]
                    > 0,
                "Local observer replaced a still-live previous original worker",
            )?;
        }
        *selected = Some(gate);
        Ok(())
    }
}
impl ArtifactCleanupPhysicalObserver for PhysicalLocalOriginalObserver {
    fn on_phase(&self, phase: PhysicalPhase, artifact: uuid::Uuid, original_leaf_fd: Option<i32>) {
        let selected = self.selected.lock().ok().and_then(|s| s.clone());
        if let Some(gate) = selected {
            gate.observe(phase, artifact, original_leaf_fd);
        }
    }
}
struct PhysicalLocalGateRelease(Arc<PhysicalLocalPhaseGate>);
impl Drop for PhysicalLocalGateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn physical_local_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
async fn physical_local_original_fd_closed(
    gate: &Arc<PhysicalLocalPhaseGate>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    gate.wait(4, deadline).await?;
    let original = gate.original.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        loop {
            if physical_local_inode_fds(&original)?.is_empty() {
                return Ok(());
            }
            require(
                Instant::now() < deadline,
                "Local ended label did not close the actual original inode FD",
            )?;
            std::thread::sleep(Duration::from_millis(5));
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    gate.check()
}
async fn physical_local_actual_query_pid(
    observer: &openbot_infra::db::pool::PooledClient,
) -> Result<i32, String> {
    let rows = observer.query("SELECT pg_backend_pid() AS observer_pid,pid,xact_start IS NOT NULL AS actual_transaction,state FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND query LIKE '%artifact_cleanup_arm_current_joint%' AND state='idle in transaction'", &[]).await.map_err(|e| e.to_string())?;
    require(
        rows.len() == 1,
        "Local preflight did not identify exactly one real original joint-query producer",
    )?;
    let pid: i32 = rows[0].get("pid");
    require(
        pid != rows[0].get::<_, i32>("observer_pid")
            && rows[0].get::<_, bool>("actual_transaction"),
        "Local preflight query observer replaced the true original transaction",
    )?;
    Ok(pid)
}
async fn physical_local_original_rollback_ack(
    pool: &openbot_infra::db::pool::DatabasePool,
    observer: &openbot_infra::db::pool::PooledClient,
    pid: i32,
) -> Result<(), String> {
    // A backend ROLLBACK by itself is not client ACK. First observe that exact backend's
    // original transaction ended, then really reacquire that same live connection from
    // its original Pool and execute a new command; retired or merely Drop-requested
    // connections cannot satisfy this driver/protocol reuse proof.
    let row = observer.query_opt("SELECT pg_backend_pid() AS observer_pid,state,xact_start IS NULL AS no_transaction,query FROM pg_catalog.pg_stat_activity WHERE pid=$1", &[&pid]).await.map_err(|e| e.to_string())?.ok_or("Local original acknowledged producer disappeared")?;
    require(
        row.get::<_, i32>("observer_pid") != pid
            && row.get::<_, Option<String>>("state").as_deref() == Some("idle")
            && row.get::<_, bool>("no_transaction")
            && row
                .get::<_, String>("query")
                .trim()
                .eq_ignore_ascii_case("ROLLBACK"),
        "Local original physical query lacked its actual original completed ROLLBACK",
    )?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut original_leases = Vec::new();
    let mut found = false;
    for _ in 0..16 {
        let c = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), pool.get())
            .await
            .map_err(
                |_| "Local original driver did not become reusable within finite proof budget",
            )?
            .map_err(|e| e.to_string())?;
        let actual: i32 = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            c.query_one("SELECT pg_backend_pid()", &[]),
        )
        .await
        .map_err(|_| "Local original reuse command timed out")?
        .map_err(|e| e.to_string())?
        .get(0);
        if actual == pid {
            require(
                c.observation().snapshot().connection_started,
                "Local reused original driver was not actually started",
            )?;
            found = true;
        }
        original_leases.push(c);
        if found {
            break;
        }
    }
    drop(original_leases);
    require(
        found,
        "Local original ROLLBACK did not really ACK/reuse its original driver",
    )
}

#[tokio::test]
#[ignore = "requires genuine Prepared Local/original Arc, two actual objects and original-window physical gates"]
async fn actual_local_original_window_is_required_through_physical_cleanup_completion() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact Local PostgreSQL bundle");
    let bundle_path = bundle.root.0.clone();
    let fixture = LocalFixture::new(&bundle, "physical-cleanup-original-window")
        .await
        .expect("genuine Prepared Local physical setup");
    let fixture_path = fixture.root.0.clone();
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let observer = Arc::new(PhysicalLocalOriginalObserver::default());
    let outcome = async {
        let original_auth = protocol.windows.try_read().map_err(|_| "Local Window registry unavailable")?.get("main").ok_or("Local original Window missing")?.auth.clone();
        let second = fixture.prepared().application().execute(original_auth.clone(), AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
            request_id: uuid::Uuid::now_v7().to_string(), source_thread_id: fixture.artifact.source_thread_id.clone(),
            source_run_id: fixture.artifact.source_run_id.clone(), source_message_id: fixture.artifact.source_message_id.clone(),
            expected_sha256: format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
        })).await.map_err(|e| e.to_string())?;
        let second = match second { AppReply::ArtifactRegistrationReceipt(r) => r, _ => return Err("Local second genuine Save returned another reply".to_owned()) };
        require(second.artifact_id != fixture.artifact.artifact_id && second.operation_id != fixture.artifact.operation_id,
            "Local physical sublegs did not have two distinct genuinely saved original objects")?;
        let first_path = fixture.root.0.join("artifacts/objects").join(&fixture.artifact.artifact_id);
        let second_path = fixture.root.0.join("artifacts/objects").join(&second.artifact_id);
        let first_object = cleanup_arm_local_object_fact(&first_path)?;
        let second_object = cleanup_arm_local_object_fact(&second_path)?;
        actual.install_cleanup_physical_observer(observer.clone()).map_err(|e| format!("{e:?}"))?;
        let first_intent = Arc::new(actual.arm_explicit_saved_delete_before(&original_auth, &fixture.artifact.artifact_id,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?);
        let first_armed = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let first_gate = PhysicalLocalPhaseGate::new(&fixture.artifact.artifact_id, first_object.clone(), 1)?;
        observer.select(first_gate.clone())?;
        let release = PhysicalLocalGateRelease(first_gate.clone());
        let worker_actual = actual.clone(); let worker_auth = original_auth.clone(); let worker_intent = first_intent.clone();
        let independent_observer = fixture.prepared().pool().get().await.map_err(|e| e.to_string())?;
        let started = Instant::now();
        let task = tokio::spawn(async move { worker_actual.remove_armed_explicit_saved_bytes_before(&worker_auth, &worker_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            first_gate.wait(1, Instant::now() + Duration::from_secs(2)).await?;
            let pid = physical_local_actual_query_pid(&independent_observer).await?;
            protocol.unbind_window("main").map_err(|e| e.to_string())?;
            protocol.bind_window("main", fixture.prepared().auth_context().clone(), None).map_err(|e| e.to_string())?;
            let rebound = protocol.windows.try_read().map_err(|_| "Local rebound Window unavailable")?.get("main").ok_or("Local rebound Window missing")?.auth.clone();
            require(rebound == original_auth && !rebound.request_binding().ok_or("Local rebound binding missing")?.identity()
                .same_binding(original_auth.request_binding().ok_or("Local original binding missing")?.identity()),
                "Local pregrant controller did not really replace the original Window epoch")?;
            Ok::<_, String>((pid, rebound))
        }.await;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        let (first_pid, rebound) = controlled?;
        require(matches!(result, Err(PhysicalError::Host(openbot_contracts::request_binding::HostRequestBindingError::NotCurrent)))
            && started.elapsed() < Duration::from_secs(5), "Local pregrant original Window replacement gained a normal observation or unknown classification")?;
        physical_local_original_rollback_ack(fixture.prepared().pool(), &independent_observer, first_pid).await?;
        drop(independent_observer);
        physical_local_original_fd_closed(&first_gate).await?;
        require(first_gate.facts.lock().map_err(|_| "Local first phase facts poisoned")?.seen[2] == 0
            && cleanup_arm_local_object_fact(&first_path)? == first_object
            && cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == first_armed,
            "Local pregrant refusal unlinked bytes or changed armed business facts")?;
        let retained = actual.observe_armed_explicit_saved_bytes_before(&rebound, &first_intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("Local definite acknowledged refusal invented poison: {e:?}"))?;
        require(retained.state() == PhysicalState::Retained && cleanup_arm_local_object_fact(&first_path)? == first_object,
            "Local rebound observe did not preserve its actually retained original object")?;
        physical_local_original_fd_closed(&first_gate).await?;
        drop(retained); drop(first_intent);
        eprintln!("ARTIFACT_PHYSICAL_LOCAL_PREGRANT original_query_pid={first_pid} actual_preflight_original_fd=true original_window_replaced=true true_original_rollback_ack_and_driver_reuse=true zero_unlink=true original_object_retained=true new_current_same_store_retained_observation=true no_poison_clear=true");

        let second_intent = Arc::new(actual.arm_explicit_saved_delete_before(&rebound, &second.artifact_id,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("{e:?}"))?);
        let second_armed = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let second_gate = PhysicalLocalPhaseGate::new(&second.artifact_id, second_object, 3)?;
        observer.select(second_gate.clone())?;
        let release = PhysicalLocalGateRelease(second_gate.clone());
        let worker_actual = actual.clone(); let worker_auth = rebound.clone(); let worker_intent = second_intent.clone();
        let independent_observer = fixture.prepared().pool().get().await.map_err(|e| e.to_string())?;
        let started = Instant::now();
        let task = tokio::spawn(async move { worker_actual.remove_armed_explicit_saved_bytes_before(&worker_auth, &worker_intent, started + Duration::from_secs(5)).await });
        let controlled = async {
            second_gate.wait(3, Instant::now() + Duration::from_secs(2)).await?;
            second_gate.after_unlink_zero_link()?;
            let pid = physical_local_actual_query_pid(&independent_observer).await?;
            protocol.unbind_window("main").map_err(|e| e.to_string())?;
            protocol.bind_window("main", fixture.prepared().auth_context().clone(), None).map_err(|e| e.to_string())?;
            let latest = protocol.windows.try_read().map_err(|_| "Local newest Window unavailable")?.get("main").ok_or("Local newest Window missing")?.auth.clone();
            require(latest == rebound && !latest.request_binding().ok_or("Local latest binding missing")?.identity()
                .same_binding(rebound.request_binding().ok_or("Local second original binding missing")?.identity()),
                "Local post-Started controller did not replace the real second original Window epoch")?;
            Ok::<_, String>((pid, latest))
        }.await;
        drop(release);
        let result = task.await.map_err(|e| e.to_string())?;
        let (second_pid, latest) = controlled?;
        require(matches!(result, Err(PhysicalError::Host(openbot_contracts::request_binding::HostRequestBindingError::NotCurrent)))
            && started.elapsed() < Duration::from_secs(5), "Local post-IO closed original Window published a normal witness or hid original classification")?;
        physical_local_original_rollback_ack(fixture.prepared().pool(), &independent_observer, second_pid).await?;
        drop(independent_observer);
        physical_local_original_fd_closed(&second_gate).await?;
        require(physical_local_absent(&second_path) && physical_local_absent(&fixture.root.0.join("artifacts/staging").join(&second.artifact_id))
            && cleanup_arm_local_object_fact(&first_path)? == first_object && cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == second_armed,
            "Local postIO rejection relabelled true effects or changed original pair/charge/fence/audit")?;
        let absent = actual.observe_armed_explicit_saved_bytes_before(&latest, &second_intent,
            Instant::now() + Duration::from_secs(5)).await.map_err(|e| format!("Local acknowledged postIO rejection invented poison: {e:?}"))?;
        require(absent.state() == PhysicalState::DurableAbsent && cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == second_armed,
            "Local latest current observation did not independently prove limited absence without business writes")?;
        physical_local_original_fd_closed(&second_gate).await?;
        first_gate.check()?; second_gate.check()?;
        drop(absent); drop(second_intent);
        eprintln!("ARTIFACT_PHYSICAL_LOCAL_POSTIO original_query_pid={second_pid} actual_unlink_original_fd_nlink_zero=true original_window_rebound_after_started=true true_original_rollback_ack_and_driver_reuse=true actual_original_fd_closed=true original_io_effects_kept=true normal_old_witness=false new_current_same_store_observe_durable_absent=true charge_fence_audit_unchanged=true terminal_refund=false");
        Ok::<(), String>(())
    }.await;
    drop(observer);
    drop(protocol);
    drop(actual);
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    let fixture_absent = physical_local_absent(&fixture_path);
    drop(bundle);
    let bundle_absent = physical_local_absent(&bundle_path);
    outcome
        .and(cleaned)
        .and(require(
            fixture_absent && bundle_absent,
            "Local original sidecar closure did not actually remove both owned roots",
        ))
        .expect("actual Local original Window physical cleanup and finite owned closure");
    eprintln!(
        "ARTIFACT_PHYSICAL_LOCAL_OWNED_TAIL original_sidecar_pid_gone=true original_worker_inode_fds_absent=true prepared_extra_original_arcs_dropped=true actual_application_root_absent=true actual_bundle_root_absent=true external_copies_untracked=true"
    );
}

// R436 instrumentation controls actual original callbacks; labels alone prove neither ACK nor End.
#[derive(Default)]
struct TerminalLocalPhaseFacts {
    seen: [usize; 4],
    released: [bool; 4],
    controller_stage: &'static str,
    controller_pid: Option<i32>,
    error: Option<String>,
}
struct TerminalLocalObserver {
    artifact: uuid::Uuid,
    deadline: Instant,
    pause: [bool; 4],
    facts: Mutex<TerminalLocalPhaseFacts>,
    changed: Condvar,
}
impl TerminalLocalObserver {
    fn new(artifact: &str, deadline: Instant, pause: [bool; 4]) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            artifact: uuid::Uuid::parse_str(artifact).map_err(|e| e.to_string())?,
            deadline,
            pause,
            facts: Mutex::new(TerminalLocalPhaseFacts::default()),
            changed: Condvar::new(),
        }))
    }
    fn release(&self, index: usize) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.released[index] = true;
            self.changed.notify_all();
        }
    }
    fn release_all(&self) {
        for index in 0..4 {
            self.release(index);
        }
    }
    fn controller_stage(&self, stage: &'static str, pid: Option<i32>) {
        if let Ok(mut facts) = self.facts.lock() {
            facts.controller_stage = stage;
            if pid.is_some() {
                facts.controller_pid = pid;
            }
        }
    }
    fn diagnostic(&self) -> String {
        match self.facts.lock() {
            Ok(facts) => format!(
                "seen={:?} released={:?} controller_stage={} original_query_pid={:?} deadline_expired={} overdue={:?}",
                facts.seen,
                facts.released,
                facts.controller_stage,
                facts.controller_pid,
                Instant::now() >= self.deadline,
                Instant::now().saturating_duration_since(self.deadline),
            ),
            Err(_) => "Local terminal phase mutex poisoned".to_owned(),
        }
    }
    fn counts(&self) -> Result<[usize; 4], String> {
        let facts = self
            .facts
            .lock()
            .map_err(|_| "Local terminal phase mutex poisoned")?;
        match &facts.error {
            Some(error) => Err(error.clone()),
            None => Ok(facts.seen),
        }
    }
    async fn wait(&self, index: usize) -> Result<(), String> {
        loop {
            if self.counts()?[index] != 0 {
                if Instant::now() >= self.deadline {
                    return Err(format!(
                        "Local terminal phase observed after original deadline index={index} {}",
                        self.diagnostic(),
                    ));
                }
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err(format!(
                    "Local original terminal cutpoint deadline elapsed index={index} {}",
                    self.diagnostic(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}
impl ArtifactCleanupTerminalObserver for TerminalLocalObserver {
    fn on_phase(&self, phase: TerminalPhase, artifact: uuid::Uuid, original_leaf_fd: Option<i32>) {
        let index = match phase {
            TerminalPhase::AbsenceGuarded => 0,
            TerminalPhase::BeforeCommit => 1,
            TerminalPhase::AfterCommitAckBeforeWorkerEnd => 2,
            TerminalPhase::WorkerEnded => 3,
        };
        let Ok(mut facts) = self.facts.lock() else {
            return;
        };
        facts.seen[index] += 1;
        if artifact != self.artifact || original_leaf_fd.is_some() || facts.seen[index] != 1 {
            facts.error =
                Some("Local already-absent terminal callback changed identity/FD/order".to_owned());
        }
        self.changed.notify_all();
        drop(facts);
        if self.pause[index] {
            // These two test fixtures use multi_thread(2). Hand the executor core over while
            // this synchronous callback waits for its genuine asynchronous controller.
            tokio::task::block_in_place(|| {
                let Ok(mut facts) = self.facts.lock() else {
                    return;
                };
                while !facts.released[index] {
                    let remaining = self.deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        facts.error = Some(format!(
                            "Local actual terminal callback was not released inside original budget index={index} phase={phase:?} seen={:?} released={:?} controller_stage={} original_query_pid={:?} overdue={:?}",
                            facts.seen,
                            facts.released,
                            facts.controller_stage,
                            facts.controller_pid,
                            Instant::now().saturating_duration_since(self.deadline),
                        ));
                        break;
                    }
                    match self.changed.wait_timeout(facts, remaining) {
                        Ok((next, _)) => facts = next,
                        Err(_) => return,
                    }
                }
            });
        }
    }
}
struct TerminalLocalRelease(Arc<TerminalLocalObserver>);
impl Drop for TerminalLocalRelease {
    fn drop(&mut self) {
        self.0.release_all();
    }
}

fn terminal_local_row<'a>(
    facts: &'a BTreeMap<String, serde_json::Value>,
    table: &str,
    saved: &ArtifactRegistrationReceipt,
) -> Result<&'a serde_json::Value, String> {
    let rows = facts
        .get(table)
        .and_then(serde_json::Value::as_array)
        .ok_or("Local terminal table facts missing")?;
    let selected: Vec<_> = rows
        .iter()
        .filter(|value| {
            value["row"]["artifact_id"].as_str() == Some(saved.artifact_id.as_str())
                && value["row"]["operation_id"].as_str() == Some(saved.operation_id.as_str())
        })
        .collect();
    require(
        selected.len() == 1,
        "Local terminal did not retain exactly one original pair row",
    )?;
    let selected: &'a serde_json::Value = selected[0];
    Ok(&selected["row"])
}
fn terminal_local_expect_commit(
    before: &BTreeMap<String, serde_json::Value>,
    after: &BTreeMap<String, serde_json::Value>,
    saved: &ArtifactRegistrationReceipt,
    auth: &AuthContext,
) -> Result<(), String> {
    let changed = [
        "openbot_internal.artifact_records",
        "openbot_internal.artifact_save_operations",
        "openbot_internal.artifact_workspace_quotas",
        "openbot_internal.artifact_cleanup_fences",
        "public.audit_events",
        "public.audit_checkpoints",
    ];
    cleanup_arm_local_only_tables_changed(before, after, &changed)?;
    let old_record = terminal_local_row(before, changed[0], saved)?;
    let old_operation = terminal_local_row(before, changed[1], saved)?;
    let record = terminal_local_row(after, changed[0], saved)?;
    let operation = terminal_local_row(after, changed[1], saved)?;
    let fence = terminal_local_row(after, changed[3], saved)?;
    let receipt = terminal_local_row(after, "openbot_internal.artifact_saved_receipts", saved)?;
    require(
        old_record["status"] == "available"
            && old_record["retention_class"] == "explicit_saved"
            && old_operation["state"] == "available"
            && record["status"] == "deleted"
            && operation["state"] == "deleted"
            && fence["terminal_status"] == "deleted"
            && fence["phase"] == "completed",
        "Local terminal did not transform the exact original available/armed pair",
    )?;
    for field in [
        "deployment_id",
        "tenant_id",
        "dataset_id",
        "operation_id",
        "artifact_id",
        "request_id",
        "owner_actor_id",
        "source_thread_id",
        "source_run_id",
        "source_message_id",
        "source_call_seq",
        "source_attempt_seq",
    ] {
        let expected = old_operation
            .get(field)
            .ok_or("Local original operation identity field missing")?;
        require(
            record.get(field) == Some(expected)
                && operation.get(field) == Some(expected)
                && receipt.get(field) == Some(expected)
                && old_record.get(field) == Some(expected),
            "Local terminal changed an original five-key/seven-identity or positive receipt",
        )?;
    }
    require(
        operation["request_id"] == saved.request_id
            && operation["owner_actor_id"].as_str() == Some(auth.actor().as_str())
            && operation["deployment_id"].as_str() == Some(auth.deployment().as_str())
            && operation["tenant_id"].as_str() == Some(auth.tenant().as_str()),
        "Local terminal did not preserve the actual original saved request/namespace/owner",
    )?;
    for field in [
        "workspace_kind",
        "workspace_id",
        "media_type",
        "byte_length",
        "sha256",
        "retention_class",
        "saved_by",
        "saved_at",
    ] {
        require(
            record.get(field).is_some_and(serde_json::Value::is_null),
            "Local terminal record8NULL was incomplete",
        )?;
    }
    for field in [
        "store_id",
        "workspace_kind",
        "workspace_id",
        "expected_sha256",
        "expected_bytes",
        "charged_bytes",
        "actual_absent",
        "actual_byte_length",
        "actual_sha256",
        "actual_location",
        "observation_phase",
        "created_at",
    ] {
        require(
            operation.get(field).is_some_and(serde_json::Value::is_null),
            "Local terminal operation12NULL was incomplete",
        )?;
    }
    let quota_table = "openbot_internal.artifact_workspace_quotas";
    let quota_matches = |value: &&serde_json::Value| {
        [
            "deployment_id",
            "tenant_id",
            "dataset_id",
            "workspace_kind",
            "workspace_id",
        ]
        .iter()
        .all(|field| value["row"].get(*field) == old_operation.get(*field))
    };
    let old_quotas = before[quota_table]
        .as_array()
        .ok_or("Local original quota facts missing")?;
    let new_quotas = after[quota_table]
        .as_array()
        .ok_or("Local terminal quota facts missing")?;
    let old_quota: Vec<_> = old_quotas.iter().filter(quota_matches).collect();
    let new_quota: Vec<_> = new_quotas.iter().filter(quota_matches).collect();
    require(
        old_quota.len() == 1 && new_quota.len() == 1,
        "Local terminal changed the exact quota identity",
    )?;
    let charge = old_operation["charged_bytes"]
        .as_i64()
        .ok_or("Local original operation charge missing")?;
    let total = old_quota[0]["row"]["charged_bytes"]
        .as_i64()
        .ok_or("Local original aggregate missing")?;
    require(
        charge == i64::try_from(PAYLOAD.len()).map_err(|e| e.to_string())?
            && new_quota[0]["row"]["charged_bytes"].as_i64() == total.checked_sub(charge),
        "Local terminal did not refund exactly the original operation charge once",
    )?;
    for table in [changed[0], changed[1], changed[3]] {
        let old_rows = before[table]
            .as_array()
            .ok_or("Local before pair inventory missing")?;
        let new_rows = after[table]
            .as_array()
            .ok_or("Local after pair inventory missing")?;
        let foreign = |value: &&serde_json::Value| {
            value["row"]["artifact_id"].as_str() != Some(saved.artifact_id.as_str())
        };
        require(
            old_rows.len() == new_rows.len()
                && old_rows
                    .iter()
                    .filter(foreign)
                    .eq(new_rows.iter().filter(foreign)),
            "Local terminal changed another original artifact or its physical row carrier",
        )?;
    }
    require(
        old_quotas.len() == new_quotas.len()
            && old_quotas
                .iter()
                .filter(|row| !quota_matches(row))
                .eq(new_quotas.iter().filter(|row| !quota_matches(row))),
        "Local terminal changed another workspace aggregate",
    )?;
    let old_audit = before["public.audit_events"]
        .as_array()
        .ok_or("Local original audit inventory missing")?;
    let new_audit = after["public.audit_events"]
        .as_array()
        .ok_or("Local terminal audit inventory missing")?;
    let appended: Vec<_> = new_audit
        .iter()
        .filter(|row| !old_audit.contains(row))
        .collect();
    require(
        new_audit.len() == old_audit.len() + 1
            && appended.len() == 1
            && old_audit.iter().all(|row| new_audit.contains(row)),
        "Local terminal duplicated final audit or rewrote old audit physical rows",
    )?;
    let event = &appended[0]["row"];
    require(
        event["event_type"] == "artifact.cleanup_completed"
            && event["target_type"] == "artifact"
            && event["actor_user_id"].as_str() == Some(auth.actor().as_str())
            && event["target_id"] == saved.artifact_id
            && event["payload"]
                == serde_json::json!({"artifact_id":saved.artifact_id,"artifact_operation_id":saved.operation_id})
            && event["id"]
                .as_str()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
        "Local actual terminal audit changed original typed IDs/actor/target or invented an audit UUIDv7 restriction",
    )?;
    Ok(())
}

fn terminal_local_root_inodes(fixture: &LocalFixture) -> Result<Vec<(u64, u64)>, String> {
    ["artifacts", "artifacts/objects", "artifacts/staging"]
        .iter()
        .map(|name| {
            let metadata =
                std::fs::symlink_metadata(fixture.root.0.join(name)).map_err(|e| e.to_string())?;
            require(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Local original root-child identity drifted",
            )?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect()
}
fn terminal_local_root_fds(inodes: &[(u64, u64)]) -> Result<Vec<Vec<String>>, String> {
    inodes
        .iter()
        .map(|(device, inode)| physical_local_inode_fds_for(*device, *inode))
        .collect()
}
fn terminal_local_rebind(
    fixture: &LocalFixture,
    original: &AuthContext,
) -> Result<AuthContext, String> {
    let protocol = fixture.prepared().protocol();
    require(
        protocol.unbind_window("main").map_err(|e| e.to_string())?,
        "Local terminal original Window was not unbound",
    )?;
    protocol
        .bind_window("main", fixture.prepared().auth_context().clone(), None)
        .map_err(|e| e.to_string())?;
    let fresh = protocol
        .windows
        .try_read()
        .map_err(|_| "Local terminal rebound registry unavailable")?
        .get("main")
        .ok_or("Local terminal rebound Window missing")?
        .auth
        .clone();
    require(
        fresh == *original
            && !fresh
                .request_binding()
                .ok_or("Local terminal new binding missing")?
                .identity()
                .same_binding(
                    original
                        .request_binding()
                        .ok_or("Local terminal old binding missing")?
                        .identity(),
                ),
        "Local terminal same-label rebind reused old epoch or changed six Auth facts",
    )?;
    Ok(fresh)
}
async fn terminal_local_query_pid(
    observer: &openbot_infra::db::pool::PooledClient,
    marker: &str,
    deadline: Instant,
) -> Result<i32, String> {
    let pattern = format!("%{marker}%");
    loop {
        let rows = observer.query("SELECT pg_backend_pid() AS observer_pid,pid FROM pg_catalog.pg_stat_activity \
            WHERE datname=current_database() AND state='idle in transaction' AND xact_start IS NOT NULL AND query LIKE $1",
            &[&pattern]).await.map_err(|e| e.to_string())?;
        if rows.len() == 1 {
            let pid: i32 = rows[0].get("pid");
            require(
                pid != rows[0].get::<_, i32>("observer_pid"),
                "Local terminal substituted observer for original producer",
            )?;
            eprintln!(
                "ARTIFACT_TERMINAL_LOCAL_QUERY_PID marker={marker} matching_rows={} original_pid={pid} observer_pid={} before_original_deadline={}",
                rows.len(),
                rows[0].get::<_, i32>("observer_pid"),
                Instant::now() < deadline,
            );
            return Ok(pid);
        }
        if !rows.is_empty() || Instant::now() >= deadline {
            let actual_pids: Vec<i32> = rows.iter().map(|row| row.get("pid")).collect();
            return Err(format!(
                "Local exact original terminal/query PID was absent or ambiguous marker={marker} matching_rows={} actual_pids={actual_pids:?} deadline_expired={} overdue={:?}",
                rows.len(),
                Instant::now() >= deadline,
                Instant::now().saturating_duration_since(deadline),
            ));
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
async fn terminal_local_server_disposition(
    observer: &openbot_infra::db::pool::PooledClient,
    pid: i32,
    disposition: &str,
) -> Result<(), String> {
    let row = observer
        .query_opt(
            "SELECT state,xact_start IS NULL AS no_transaction,query \
        FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND pid<>pg_backend_pid()",
            &[&pid],
        )
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Local original terminal backend disappeared")?;
    require(
        row.get::<_, Option<String>>("state").as_deref() == Some("idle")
            && row.get::<_, bool>("no_transaction")
            && row
                .get::<_, String>("query")
                .trim()
                .eq_ignore_ascii_case(disposition),
        "Local original terminal did not actually finish its own expected transaction",
    )?;
    // Server disposition alone does not prove that the original driver received its ACK.
    Ok(())
}
async fn terminal_local_original_ack(
    pool: &openbot_infra::db::pool::DatabasePool,
    observer: &openbot_infra::db::pool::PooledClient,
    pid: i32,
    disposition: &str,
) -> Result<(), String> {
    terminal_local_server_disposition(observer, pid, disposition).await?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut leases = Vec::new();
    let mut original_reused = false;
    for _ in 0..16 {
        let client = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), pool.get())
            .await
            .map_err(|_| "Local original terminal ACK/driver reuse budget elapsed")?
            .map_err(|e| e.to_string())?;
        let actual: i32 = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            client.query_one("SELECT pg_backend_pid()", &[]),
        )
        .await
        .map_err(|_| "Local original terminal reuse command expired")?
        .map_err(|e| e.to_string())?
        .get(0);
        if actual == pid {
            require(
                client.observation().snapshot().connection_started,
                "Local original terminal driver never started",
            )?;
            original_reused = true;
        }
        leases.push(client);
        if original_reused {
            break;
        }
    }
    drop(leases);
    require(
        original_reused,
        "Local terminal original guarded connection did not really ACK and become reusable",
    )
}

async fn terminal_local_commit(
    fixture: &LocalFixture,
    saved: &ArtifactRegistrationReceipt,
    auth: &AuthContext,
    intent: &Arc<ArmedArtifactCleanupIntent>,
    rebind_after_ack: bool,
) -> Result<AuthContext, String> {
    let before = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
    let roots = terminal_local_root_inodes(fixture)?;
    let root_fds = terminal_local_root_fds(&roots)?;
    let observer = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let gate =
        TerminalLocalObserver::new(&saved.artifact_id, deadline, [false, true, true, false])?;
    let release = TerminalLocalRelease(gate.clone());
    let administration = fixture.prepared().artifact_administration.clone();
    let original_auth = auth.clone();
    let original_intent = intent.clone();
    let recorder = gate.clone();
    let task = tokio::spawn(async move {
        administration
            .finalize_armed_explicit_saved_before_with_observer(
                &original_auth,
                &original_intent,
                deadline,
                Some(recorder),
            )
            .await
    });
    let controlled = async {
        gate.controller_stage("commit_wait_before_commit", None);
        gate.wait(1).await?;
        gate.controller_stage("commit_query_original_pid", None);
        let pid = terminal_local_query_pid(
            &observer,
            "artifact_cleanup_terminal_current_joint",
            deadline,
        )
        .await?;
        gate.controller_stage("commit_release_before_commit", Some(pid));
        gate.release(1);
        gate.controller_stage("commit_wait_after_ack", Some(pid));
        gate.wait(2).await?;
        gate.controller_stage("commit_observe_original_server_disposition", Some(pid));
        terminal_local_server_disposition(&observer, pid, "COMMIT").await?;
        require(
            gate.counts()?[0] == 1 && gate.counts()?[3] == 0,
            "Local worker falsely ended before original real COMMIT and fact cutpoint",
        )?;
        let current = if rebind_after_ack {
            gate.controller_stage("commit_rebind_actual_window_after_ack", Some(pid));
            terminal_local_rebind(fixture, auth)?
        } else {
            auth.clone()
        };
        Ok::<_, String>((pid, current))
    }
    .await;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_CONTROLLER kind=commit rebind_after_ack={rebind_after_ack} controlled_ok={} controlled_error={:?} {}",
        controlled.is_ok(),
        controlled.as_ref().err(),
        gate.diagnostic(),
    );
    gate.release_all();
    let result = task.await.map_err(|e| e.to_string())?;
    drop(release);
    let (pid, current) = controlled?;
    if rebind_after_ack {
        require(
            matches!(
                result,
                Err(TerminalError::Host(
                    openbot_contracts::request_binding::HostRequestBindingError::NotCurrent
                ))
            ),
            "Local acknowledged terminal rebind published old authority or relabelled known COMMIT",
        )?;
    } else {
        let observation = result.map_err(|e| format!("{e:?}"))?;
        require(
            observation.state() == TerminalState::Committed,
            "Local terminal did not publish its actual committed state",
        )?;
        drop(observation);
    }
    require(
        Instant::now() < deadline && gate.counts()? == [1, 1, 1, 1],
        "Local terminal original budget or actual worker cutpoint sequence failed",
    )?;
    terminal_local_original_ack(fixture.prepared().pool(), &observer, pid, "COMMIT").await?;
    drop(observer);
    let after = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
    terminal_local_expect_commit(&before, &after, saved, auth)?;
    require(
        terminal_local_root_fds(&roots)? == root_fds
            && physical_local_absent(
                &fixture
                    .root
                    .0
                    .join("artifacts/objects")
                    .join(&saved.artifact_id),
            )
            && physical_local_absent(
                &fixture
                    .root
                    .0
                    .join("artifacts/staging")
                    .join(&saved.artifact_id),
            ),
        "Local terminal retained temporary directory FDs or lost actual guarded absence",
    )?;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_COMMIT original_query_pid={pid} original_server_commit=true original_driver_ack_reused=true before_worker_end=true actual_temporary_root_fd_inventory_restored=true rebind_after_ack={rebind_after_ack} known_effects_retained=true original_run_identity_and_positive_receipt_kept=true"
    );
    Ok(current)
}

async fn terminal_local_completed_without_quota(
    fixture: &LocalFixture,
    saved: &ArtifactRegistrationReceipt,
    auth: &AuthContext,
    intent: &Arc<ArmedArtifactCleanupIntent>,
    live: &BTreeMap<String, serde_json::Value>,
) -> Result<(), String> {
    let before = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
    let original = terminal_local_row(live, "openbot_internal.artifact_save_operations", saved)?;
    let key: Vec<_> = [
        "deployment_id",
        "tenant_id",
        "dataset_id",
        "workspace_kind",
        "workspace_id",
    ]
    .iter()
    .map(|field| {
        original[*field]
            .as_str()
            .map(str::to_owned)
            .ok_or("Local original quota key missing")
    })
    .collect::<Result<_, _>>()?;
    let mut quota_client = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let quota = quota_client
        .transaction()
        .await
        .map_err(|e| e.to_string())?;
    quota.query_one("SELECT charged_bytes FROM openbot_internal.artifact_workspace_quotas \
        WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND workspace_kind=$4 AND workspace_id=$5 FOR UPDATE",
        &[&key[0], &key[1], &key[2], &key[3], &key[4]]).await.map_err(|e| e.to_string())?;
    let mut operation_client = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let operation = operation_client
        .transaction()
        .await
        .map_err(|e| e.to_string())?;
    let blocker: i32 = operation
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    operation
        .query_one(
            "SELECT operation_id FROM openbot_internal.artifact_save_operations \
        WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND operation_id=$4 FOR UPDATE",
            &[&key[0], &key[1], &key[2], &saved.operation_id],
        )
        .await
        .map_err(|e| e.to_string())?;
    let observer = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let phases = TerminalLocalObserver::new(&saved.artifact_id, deadline, [false; 4])?;
    let administration = fixture.prepared().artifact_administration.clone();
    let original_auth = auth.clone();
    let original_intent = intent.clone();
    let recorder = phases.clone();
    let mut task = tokio::spawn(async move {
        administration
            .finalize_armed_explicit_saved_before_with_observer(
                &original_auth,
                &original_intent,
                deadline,
                Some(recorder),
            )
            .await
    });
    let waited = async {
        loop {
            let rows = observer
                .query(
                    "SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=current_database() \
                AND wait_event_type='Lock' AND $1=ANY(pg_catalog.pg_blocking_pids(pid)) \
                AND query LIKE '%artifact_save_operations%' AND query LIKE '%FOR UPDATE%'",
                    &[&blocker],
                )
                .await
                .map_err(|e| e.to_string())?;
            if rows.len() == 1 {
                return Ok::<i32, String>(rows[0].get(0));
            }
            require(
                rows.is_empty() && Instant::now() < deadline,
                "Local completed operation waiter absent or ambiguous",
            )?;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    .await;
    let operation_released = operation.rollback().await.map_err(|e| e.to_string());
    let timed = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
    let quota_released = quota.rollback().await.map_err(|e| e.to_string());
    let (result, before_quota_release) = match timed {
        Ok(joined) => (joined.map_err(|e| e.to_string())?, true),
        Err(_) => (task.await.map_err(|e| e.to_string())?, false),
    };
    operation_released?;
    quota_released?;
    let pid = waited?;
    require(
        before_quota_release && Instant::now() < deadline,
        "Local healthy completed decoder joined/accessed locked original quota or renewed the budget",
    )?;
    let observation = result.map_err(|e| format!("{e:?}"))?;
    require(
        observation.state() == TerminalState::AlreadyCompleted && phases.counts()? == [0; 4],
        "Local completed retry created a worker/IO/commit instead of its own read observation",
    )?;
    drop(observation);
    terminal_local_original_ack(fixture.prepared().pool(), &observer, pid, "ROLLBACK").await?;
    drop(observer);
    drop(operation_client);
    drop(quota_client);
    require(
        cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == before,
        "Local completed retry refunded or inserted audit or repaired the original facts",
    )?;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_COMPLETED original_query_pid={pid} actual_operation_waiter=true original_quota_controller_held_through_result=true own_original_rollback_ack_and_driver_reuse=true worker_phases_zero=true business_and_physical_rows_unchanged=true no_recharge_or_second_refund=true"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned genuine Prepared Local and original R436 transaction/worker resources"]
async fn actual_prepared_local_terminal_commits_once_and_window_retry_has_no_io() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact Local PostgreSQL bundle");
    let bundle_path = bundle.root.0.clone();
    // Reuse the original P1 durable terminal/foreground-inactive precondition, never retry Save.
    let fixture = LocalFixture::new(&bundle, "p1-window-chunk")
        .await
        .expect("genuine Local terminal setup");
    let fixture_path = fixture.root.0.clone();
    let roots = terminal_local_root_inodes(&fixture).expect("original Local root-child inodes");
    let outcome = async {
        let actual = fixture.prepared().artifact_administration.clone();
        let auth = fixture
            .prepared()
            .protocol()
            .windows
            .try_read()
            .map_err(|_| "Local terminal Window registry unavailable")?
            .get("main")
            .ok_or("Local terminal original Window missing")?
            .auth
            .clone();
        let intent = Arc::new(
            actual
                .arm_explicit_saved_delete_before(
                    &auth,
                    &fixture.artifact.artifact_id,
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .map_err(|e| format!("{e:?}"))?,
        );
        let live = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
        let absent = actual
            .remove_armed_explicit_saved_bytes_before(
                &auth,
                &intent,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
        require(
            absent.state() == PhysicalState::DurableAbsent
                && cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == live,
            "Local original physical producer failed absence or prematurely terminalized/refunded",
        )?;
        drop(absent);
        let current =
            terminal_local_commit(&fixture, &fixture.artifact, &auth, &intent, false).await?;
        terminal_local_completed_without_quota(
            &fixture,
            &fixture.artifact,
            &current,
            &intent,
            &live,
        )
        .await?;
        status(
            bridge(
                fixture.prepared().protocol(),
                "main",
                open_request(&fixture.artifact.artifact_id)?,
            )
            .await,
            StatusCode::GONE,
        )?;
        drop(intent);
        drop(actual);
        Ok::<(), String>(())
    }
    .await;
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    let fixture_absent = physical_local_absent(&fixture_path);
    drop(bundle);
    let original_fds_closed = terminal_local_root_fds(&roots).and_then(|fds| {
        require(
            fixture_absent && physical_local_absent(&bundle_path) && fds.iter().all(Vec::is_empty),
            "Local terminal original worker/Store/sidecar/root resources did not actually close",
        )
    });
    outcome
        .and(cleaned)
        .and(original_fds_closed)
        .expect("actual Prepared Local terminal once/healthy completed and original owned closure");
}

async fn terminal_local_carrier_then_physical(
    fixture: &LocalFixture,
    saved: &ArtifactRegistrationReceipt,
    auth: &AuthContext,
    copy_tail: bool,
) -> Result<
    (
        Arc<ArmedArtifactCleanupIntent>,
        BTreeMap<String, serde_json::Value>,
    ),
    String,
> {
    use tracing::instrument::WithSubscriber as _;
    let actual = fixture.prepared().artifact_administration.clone();
    let protocol = fixture.prepared().protocol().clone();
    let path = fixture
        .root
        .0
        .join("artifacts/objects")
        .join(&saved.artifact_id);
    let original_object = cleanup_arm_local_object_fact(&path)?;
    let phases = Arc::new(CleanupCachedIoPhases::default());
    let dispatch = tracing::Dispatch::new(CleanupCachedPhaseSubscriber(phases.clone()));
    let opened: ArtifactReadOpened = control(
        bridge(&protocol, "main", open_request(&saved.artifact_id)?)
            .with_subscriber(dispatch.clone())
            .await,
    )?;
    let prepared = protocol
        .prepare_public_artifact_read_response("main", next_request(&opened.handle_id, 0)?)
        .with_subscriber(dispatch)
        .await;
    let original_counts = phases.actual_counts();
    require(
        original_counts.0 == 1 && original_counts.1 >= 2,
        "Local terminal carrier fixture did not perform its real IO and final joint observation",
    )?;
    // The original transport block is already prepared. Arm cannot remove that allocation.
    let intent = Arc::new(
        actual
            .arm_explicit_saved_delete_before(
                auth,
                &saved.artifact_id,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .map_err(|e| format!("{e:?}"))?,
    );
    let armed = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
    let gate = CarrierGate::new();
    let release = ReleaseCarrierGate(gate.clone());
    let observer = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let worker_protocol = protocol.clone();
    let worker_gate = gate.clone();
    let carrier = tokio::task::spawn_blocking(move || {
        if copy_tail {
            tracing::subscriber::with_default(CopyTailSubscriber(worker_gate), || {
                worker_protocol
                    .finish_public_artifact_read_response("main", prepared, |response| response)
            })
        } else {
            worker_protocol.finish_public_artifact_read_response("main", prepared, |response| {
                worker_gate.hold_actual_thread();
                response
            })
        }
    });
    let entered = gate.await_entered().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker_actual = actual.clone();
    let worker_auth = auth.clone();
    let worker_intent = intent.clone();
    let mut physical = tokio::spawn(async move {
        worker_actual
            .remove_armed_explicit_saved_bytes_before(&worker_auth, &worker_intent, deadline)
            .await
    });
    let mut early_physical = None;
    let controlled = async {
        entered?;
        let pid =
            terminal_local_query_pid(&observer, "artifact_cleanup_arm_current_joint", deadline)
                .await?;
        if let Ok(joined) = tokio::time::timeout(Duration::from_millis(30), &mut physical).await {
            // Preserve an unexpected real early result and never poll a consumed JoinHandle twice.
            early_physical = Some(joined);
            return Err(
                "Local original physical producer ignored a held actual copy/responder owner"
                    .to_owned(),
            );
        }
        require(
            cleanup_owned_inode_fds(&path)?.len() == 1
                && cleanup_arm_local_object_fact(&path)? == original_object,
            "Local held original carrier lost its live FD or physical cleanup unlinked early",
        )?;
        Ok::<_, String>(pid)
    }
    .await;
    gate.release();
    let response = carrier.await.map_err(|e| e.to_string());
    drop(release);
    let result = match early_physical {
        Some(joined) => joined.map_err(|e| e.to_string()),
        None => physical.await.map_err(|e| e.to_string()),
    };
    let response = response?;
    let result = result?;
    let pid = controlled?;
    require(
        !gate.timed_out.load(Ordering::SeqCst) && Instant::now() < deadline,
        "Local carrier released only through timeout or physical cleanup renewed its original deadline",
    )?;
    let absent = result.map_err(|e| format!("{e:?}"))?;
    require(
        absent.state() == PhysicalState::DurableAbsent,
        "Local released carrier did not allow genuine original absence",
    )?;
    drop(absent);
    physical_local_original_rollback_ack(fixture.prepared().pool(), &observer, pid).await?;
    drop(observer);
    if copy_tail {
        status(response, StatusCode::SERVICE_UNAVAILABLE)?;
    } else {
        data(&response, &opened.handle_id, 0, false)?;
        require(
            response.body().as_slice() == PAYLOAD.as_bytes(),
            "Local actual responder callback changed original bytes",
        )?;
        // This response Vec is already external; its Drop is not an erasure or resource ACK.
        drop(response);
    }
    require(
        physical_local_inode_fds(&original_object)?.is_empty()
            && physical_local_absent(&path)
            && physical_local_absent(
                &fixture
                    .root
                    .0
                    .join("artifacts/staging")
                    .join(&saved.artifact_id),
            )
            && phases.actual_counts() == original_counts
            && cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == armed,
        "Local physical completion lacked original carrier/FD end or changed armed business facts",
    )?;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_CARRIER copy_tail={copy_tail} original_query_pid={pid} actual_prepared_carrier_held=true real_original_fd_retained=true physical_no_unlink_while_held=true release_inside_same_original_budget=true actual_callback_joined=true original_physical_rollback_ack_driver_reused=true original_inode_fds_absent=true real_guarded_absence=true terminal_not_started_before_drain=true returned_external_vec_untracked=true"
    );
    drop(protocol);
    drop(actual);
    Ok((intent, armed))
}

async fn terminal_local_precommit_rebind(
    fixture: &LocalFixture,
    saved: &ArtifactRegistrationReceipt,
    auth: &AuthContext,
    intent: &Arc<ArmedArtifactCleanupIntent>,
) -> Result<AuthContext, String> {
    let before = cleanup_arm_local_database_facts(fixture.prepared().pool()).await?;
    let observer = fixture
        .prepared()
        .pool()
        .get()
        .await
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let gate =
        TerminalLocalObserver::new(&saved.artifact_id, deadline, [false, true, false, false])?;
    let release = TerminalLocalRelease(gate.clone());
    let actual = fixture.prepared().artifact_administration.clone();
    let original_auth = auth.clone();
    let original_intent = intent.clone();
    let recorder = gate.clone();
    let task = tokio::spawn(async move {
        actual
            .finalize_armed_explicit_saved_before_with_observer(
                &original_auth,
                &original_intent,
                deadline,
                Some(recorder),
            )
            .await
    });
    let controlled = async {
        gate.controller_stage("precommit_rebind_wait_before_commit", None);
        gate.wait(1).await?;
        gate.controller_stage("precommit_rebind_query_original_pid", None);
        let pid = terminal_local_query_pid(
            &observer,
            "artifact_cleanup_terminal_current_joint",
            deadline,
        )
        .await?;
        gate.controller_stage("precommit_rebind_actual_window", Some(pid));
        let fresh = terminal_local_rebind(fixture, auth)?;
        Ok::<_, String>((pid, fresh))
    }
    .await;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_CONTROLLER kind=precommit_rebind controlled_ok={} controlled_error={:?} {}",
        controlled.is_ok(),
        controlled.as_ref().err(),
        gate.diagnostic(),
    );
    gate.release_all();
    let result = task.await.map_err(|e| e.to_string())?;
    drop(release);
    let (pid, fresh) = controlled?;
    require(
        matches!(
            result,
            Err(TerminalError::Host(
                openbot_contracts::request_binding::HostRequestBindingError::NotCurrent
            ))
        ) && Instant::now() < deadline
            && gate.counts()? == [1, 1, 0, 1],
        "Local BeforeCommit rebind committed or hid its acknowledged original Host refusal",
    )?;
    terminal_local_original_ack(fixture.prepared().pool(), &observer, pid, "ROLLBACK").await?;
    drop(observer);
    require(
        cleanup_arm_local_database_facts(fixture.prepared().pool()).await? == before,
        "Local precommit original rollback left staged refund/pair/audit mutations",
    )?;
    eprintln!(
        "ARTIFACT_TERMINAL_LOCAL_PRECOMMIT original_query_pid={pid} real_window_replaced_before_commit_permission=true original_rollback_ack_driver_reused=true staged_mutations_atomic_rollback=true worker_resources_ended=true no_poison_repair=true"
    );
    Ok(fresh)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires genuine Local copy/responder carriers, original Window epochs and true terminal ACK controls"]
async fn actual_prepared_local_terminal_revoke_and_rebind_keep_truth_and_store_scope() {
    let mut bundle = OwnedBundle::materialize().expect("Root-owned exact Local PostgreSQL bundle");
    let bundle_path = bundle.root.0.clone();
    let fixture = LocalFixture::new(&bundle, "p1-window-operation")
        .await
        .expect("genuine Local terminal/window setup");
    let fixture_path = fixture.root.0.clone();
    let roots = terminal_local_root_inodes(&fixture).expect("original Local root-child inodes");
    let outcome = async {
        let actual = fixture.prepared().artifact_administration.clone();
        let mut auth = fixture
            .prepared()
            .protocol()
            .windows
            .try_read()
            .map_err(|_| "Local terminal original Window unavailable")?
            .get("main")
            .ok_or("Local terminal actual main missing")?
            .auth
            .clone();
        let second = fixture
            .prepared()
            .application()
            .execute(
                auth.clone(),
                AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                    request_id: uuid::Uuid::now_v7().to_string(),
                    source_thread_id: fixture.artifact.source_thread_id.clone(),
                    source_run_id: fixture.artifact.source_run_id.clone(),
                    source_message_id: fixture.artifact.source_message_id.clone(),
                    expected_sha256: format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
                }),
            )
            .await
            .map_err(|e| e.to_string())?;
        let second = match second {
            AppReply::ArtifactRegistrationReceipt(saved) => saved,
            _ => return Err(
                "Local terminal responder leg did not genuinely Save its original second artifact"
                    .to_owned(),
            ),
        };
        require(
            second.artifact_id != fixture.artifact.artifact_id
                && second.operation_id != fixture.artifact.operation_id,
            "Local terminal two carrier legs reused another object's identity",
        )?;
        for (saved, copy_tail) in [(&fixture.artifact, true), (&second, false)] {
            require(
                Arc::ptr_eq(&actual, &fixture.prepared().artifact_administration),
                "Local terminal recovery replaced the original Administration/Store",
            )?;
            let (intent, live) =
                terminal_local_carrier_then_physical(&fixture, saved, &auth, copy_tail).await?;
            if copy_tail {
                auth = terminal_local_precommit_rebind(&fixture, saved, &auth, &intent).await?;
                // The prior refusal had its own genuine rollback ACK; this fresh original Store
                // invocation is new authority, not repair of an unknown or expired query.
                auth = terminal_local_commit(&fixture, saved, &auth, &intent, false).await?;
            } else {
                // Actual normal COMMIT/fact is already observed while the worker still holds IO.
                // Rebind here must withhold old authority while preserving real committed truth.
                auth = terminal_local_commit(&fixture, saved, &auth, &intent, true).await?;
            }
            terminal_local_completed_without_quota(&fixture, saved, &auth, &intent, &live).await?;
            drop(intent);
        }
        drop(actual);
        Ok::<(), String>(())
    }
    .await;
    let cleaned = fixture.finish().await;
    if cleaned.is_ok() {
        bundle.root.1 = true;
    }
    let fixture_absent = physical_local_absent(&fixture_path);
    drop(bundle);
    let original_fds_closed = terminal_local_root_fds(&roots).and_then(|fds| {
        require(
            fixture_absent && physical_local_absent(&bundle_path) && fds.iter().all(Vec::is_empty),
            "Local carrier/terminal original Store/sidecar/root resources did not actually close",
        )
    });
    outcome.and(cleaned).and(original_fds_closed)
        .expect("actual Local terminal carrier holds/window rebind/known ACK fact and original owned closure");
}
