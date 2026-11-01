//! V7-IMPL-031 part 2 Desktop Local window Host case: a genuine Prepared Local runtime, its
//! original window and a real Save drive the public artifact deletion route until the artifact is
//! deleted; a window authority captured before its label was rebound is then refused. This is
//! finite test-owned Local coverage, not release supervisor/GUI/Keychain readiness.
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
use openbot_contracts::artifacts::{ArtifactRegistrationReceipt, SaveRunMessageTextArtifact};
use openbot_contracts::command::{
    AppCommand, AppEvent, AppReply, BeginThreadRun, SubscriptionRequest, ThreadRunAnchor,
    ThreadRunEventKind,
};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::ids::{BotId, RunId, thread::ThreadIdentity};
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type TestResult<T = ()> = Result<T, String>;
fn require(value: bool, error: &'static str) -> TestResult {
    if value { Ok(()) } else { Err(error.to_owned()) }
}
fn text<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}

const PAYLOAD: &str = "genuine Local artifact deletion text";
/// Resends of one deletion before the test gives up on it completing.
const RESENDS: usize = 40;
/// The window freshness of this test; the Prepared runtime installs no native confirmation.
const FRESH: Duration = Duration::from_secs(300);

/// A private directory this test created; removed on drop only when `remove` is set.
struct OwnedRoot {
    path: PathBuf,
    remove: bool,
}
impl OwnedRoot {
    fn new(label: &str) -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "openbot-artifact-deletion-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(text)?;
        let path = std::fs::canonicalize(&path).map_err(text)?;
        Ok(Self { path, remove: true })
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if !self.remove {
            eprintln!("ARTIFACT_DELETION_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.path).is_ok();
        if !std::thread::panicking() {
            assert!(removed, "owned Local root cleanup failed");
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

/// The owned PostgreSQL17.11 installation of `OPENBOT_TEST_PG_BIN`, copied into a sidecar bundle
/// with an exact inventory. This controlled fixture is not release-signing acceptance.
struct OwnedBundle {
    root: OwnedRoot,
    digest: PostgresBundleDigest,
    signing: ReviewedPostgresSigningIdentity,
}
impl OwnedBundle {
    fn materialize() -> TestResult<Self> {
        let bin = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_PG_BIN")
                .ok_or("owned runner must set OPENBOT_TEST_PG_BIN")?,
        );
        require(
            bin.is_absolute(),
            "OPENBOT_TEST_PG_BIN must be an absolute owned test binary directory",
        )?;
        let configuration = |option: &str| -> TestResult<String> {
            let output = Command::new(bin.join("pg_config"))
                .env("LC_ALL", "C")
                .arg(option)
                .stdin(Stdio::null())
                .output()
                .map_err(|_| "matching pg_config unavailable")?;
            require(output.status.success(), "owned pg_config failed")?;
            String::from_utf8(output.stdout)
                .map(|value| value.trim().to_owned())
                .map_err(|_| "pg_config output invalid".to_owned())
        };
        require(
            configuration("--version")? == format!("PostgreSQL {POSTGRES_VERSION}"),
            "owned PG installation is not the exact pinned version",
        )?;
        let share = PathBuf::from(configuration("--sharedir")?);
        let library = PathBuf::from(configuration("--pkglibdir")?);
        let mut root = OwnedRoot::new("bundle")?;
        // Keep the bundle through any startup or shutdown uncertainty.
        root.remove = false;
        for directory in ["bin", "share", "lib"] {
            std::fs::create_dir(root.path.join(directory)).map_err(text)?;
        }
        for name in ["postgres", "initdb", "pg_ctl"] {
            copy_resources(&bin.join(name), &root.path.join("bin").join(name))?;
        }
        copy_resources(&share, &root.path.join("share/postgresql"))?;
        copy_resources(&library, &root.path.join("lib/postgresql"))?;
        let mut files = BTreeMap::new();
        inventory_hashes(&root.path, &root.path, &mut files)?;
        let signing_text = "Developer ID Application: Example Product (ABCDE12345)";
        let signing =
            ReviewedPostgresSigningIdentity::from_reviewed_release(signing_text).map_err(text)?;
        let manifest = json!({
            "schema": "openbot-postgres-sidecar-bundle", "schema_version": 1,
            "platform": "macos", "arch": std::env::consts::ARCH,
            "postgresql_version": POSTGRES_VERSION, "source_archive_sha256": POSTGRES_SOURCE_SHA256,
            "release_epoch": ENGINE_RELEASE_EPOCH, "minimum_compatible_core": env!("CARGO_PKG_VERSION"),
            "signing_identity": signing_text,
            "programs": { "postgres": "bin/postgres", "initdb": "bin/initdb", "pg_ctl": "bin/pg_ctl" },
            "files": files,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(text)?;
        std::fs::write(root.path.join("manifest.json"), &bytes).map_err(text)?;
        let digest = PostgresBundleDigest::from_hex(&format!("{:x}", Sha256::digest(&bytes)))
            .map_err(text)?;
        Ok(Self {
            root,
            digest,
            signing,
        })
    }
    fn open(&self) -> TestResult<VerifiedPostgresBundle> {
        VerifiedPostgresBundle::open(&self.root.path, self.digest, &self.signing).map_err(text)
    }
}

fn copy_resources(source: &Path, destination: &Path) -> TestResult {
    if std::fs::symlink_metadata(source).map_err(text)?.is_dir() {
        std::fs::create_dir(destination).map_err(text)?;
        for entry in std::fs::read_dir(source).map_err(text)? {
            let entry = entry.map_err(text)?;
            copy_resources(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        std::fs::copy(source, destination).map_err(text)?;
    }
    Ok(())
}

fn inventory_hashes(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> TestResult {
    for entry in std::fs::read_dir(directory).map_err(text)? {
        let path = entry.map_err(text)?.path();
        if std::fs::symlink_metadata(&path).map_err(text)?.is_dir() {
            inventory_hashes(root, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(text)?
            .to_str()
            .ok_or("owned inventory is not UTF-8")?
            .to_owned();
        let mut file = std::fs::File::open(&path).map_err(text)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 65_536];
        loop {
            let length = file.read(&mut buffer).map_err(text)?;
            if length == 0 {
                break;
            }
            digest.update(&buffer[..length]);
        }
        files.insert(relative, format!("{:x}", digest.finalize()));
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
        "/controlled/artifact-deletion-local-package".to_owned(),
        "d".repeat(64),
    )
}

async fn prepare(
    bundle: &OwnedBundle,
    root: &OwnedRoot,
) -> TestResult<PreparedDesktopLocalRuntime> {
    let assets = root.path.join("assets");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&assets)
        .map_err(text)?;
    std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(text)?;
    std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};").map_err(text)?;
    let release = DesktopLocalReleaseInput::new(
        &assets,
        "openbot",
        "main",
        bundle.open()?,
        ReviewedPostgresKeyStoreService::from_reviewed_release("com.example.review.deletion-scram")
            .map_err(text)?,
        ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
            "com.example.review.deletion-vault",
        )
        .map_err(text)?,
        Arc::new(MemorySecretStore::default()),
    )
    .map_err(text)?;
    // No provider credential is stored, and this fixture never supplies a network reply.
    let application = DesktopLocalApplicationInput::new(
        DesktopOpenAiProviderInput::new(
            "https://api.example.test/v1",
            vec!["203.0.113.0/24".to_owned()],
        )
        .map_err(text)?,
        DesktopAgentBudgets::new(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(1_800)),
            16_384,
        )
        .map_err(text)?,
    )
    .map_err(text)?;
    prepare_desktop_local_runtime(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root.path).map_err(text)?,
        DesktopLocalRuntimeConfig::new(release, application, |authority| {
            package(authority.auth_context().tenant().as_str())
        }),
    )
    .await
    .map_err(text)
}

/// One real Run on the original window until it is durably terminal, then one real Save of its
/// user message: Save takes the source locks NOWAIT, so it must follow the Run.
async fn save(prepared: &PreparedDesktopLocalRuntime) -> TestResult<ArtifactRegistrationReceipt> {
    let auth = prepared
        .protocol()
        .authority("main")
        .map_err(text)?
        .ok_or("original Local window missing")?
        .auth;
    let begin = BeginThreadRun {
        artifact_refs: Vec::new(),
        thread_id: ThreadIdentity::new(auth.deployment()).mint_from_entropy([31; 16]),
        run_id: RunId::new("actual/local-deletion-run"),
        bot_id: BotId::new("desktop-assistant"),
        anchor: ThreadRunAnchor::DirectBot,
        message: PAYLOAD.to_owned(),
        selected_skill_slugs: Vec::new(),
        model_selection: None,
    };
    let AppReply::ThreadRunStarted(started) = prepared
        .application()
        .execute(auth.clone(), AppCommand::BeginThreadRun(begin.clone()))
        .await
        .map_err(text)?
    else {
        return Err("Local Begin returned another reply".to_owned());
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    tokio::time::timeout_at(deadline, async {
        let mut events = prepared
            .application()
            .subscribe(
                auth.clone(),
                SubscriptionRequest::ThreadEvents {
                    thread_id: begin.thread_id.clone(),
                    after_event_sequence: Some(started.event_sequence),
                },
            )
            .await
            .map_err(text)?;
        loop {
            let event = core::future::poll_fn(|cx| events.as_mut().poll_next(cx))
                .await
                .ok_or("Local Run stream ended before its terminal")?;
            let AppEvent::ThreadRunEvent(event) = event else {
                return Err("Local Run stream returned another envelope".to_owned());
            };
            match event.event_type {
                ThreadRunEventKind::Completed
                | ThreadRunEventKind::Failed
                | ThreadRunEventKind::Cancelled => break,
                ThreadRunEventKind::ReconciliationRequired => {
                    return Err("Local Run has unknown terminal facts".to_owned());
                }
                ThreadRunEventKind::Started
                | ThreadRunEventKind::SemanticChunk
                | ThreadRunEventKind::Checkpoint => {}
            }
        }
        let AppReply::ThreadConversation(conversation) = prepared
            .application()
            .execute(
                auth.clone(),
                AppCommand::GetThreadConversation {
                    thread_id: begin.thread_id.clone(),
                },
            )
            .await
            .map_err(text)?
        else {
            return Err("Local conversation returned another reply".to_owned());
        };
        require(
            conversation.active_run_id.is_none(),
            "Local Run foreground was not durably inactive",
        )
    })
    .await
    .map_err(|_| "Local Run fixture deadline expired".to_owned())??;
    let AppReply::ArtifactRegistrationReceipt(receipt) = prepared
        .application()
        .execute(
            auth,
            AppCommand::SaveRunMessageTextArtifact(SaveRunMessageTextArtifact {
                request_id: uuid::Uuid::now_v7().to_string(),
                source_message_id: format!("{}:input", begin.run_id.as_str()),
                source_thread_id: begin.thread_id,
                source_run_id: begin.run_id,
                expected_sha256: format!("{:x}", Sha256::digest(PAYLOAD.as_bytes())),
            }),
        )
        .await
        .map_err(text)?
    else {
        return Err("Local Save returned another reply".to_owned());
    };
    Ok(receipt)
}

fn delete_request(artifact_id: &str) -> TestResult<Request<Vec<u8>>> {
    Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/artifacts/{artifact_id}"))
        .body(Vec::new())
        .map_err(text)
}

/// The status and JSON body of a no-store response; every answer of this route is no-store.
fn answered(response: &Response<Vec<u8>>) -> TestResult<(StatusCode, Value)> {
    require(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("no-store"),
        "the Local deletion route answered without no-store",
    )?;
    let value = serde_json::from_slice(response.body()).map_err(text)?;
    Ok((response.status(), value))
}

async fn exercise(prepared: &PreparedDesktopLocalRuntime) -> TestResult {
    let protocol = prepared.protocol();
    protocol
        .bind_window("main", prepared.auth_context().clone(), Some(FRESH))
        .map_err(text)?;
    let artifact = save(prepared).await?;
    let id = artifact.artifact_id.as_str();

    // The original window deletes the artifact; resending the same deletion resumes it.
    let mut pending = 0;
    let mut deleted = false;
    for _ in 0..RESENDS {
        let (status, value) = answered(&protocol.handle("main", delete_request(id)?).await)?;
        let state = if status == StatusCode::OK {
            "deleted"
        } else {
            "pending"
        };
        require(
            matches!(status, StatusCode::OK | StatusCode::ACCEPTED)
                && value
                    == json!({
                        "artifactId": id,
                        "state": state,
                        "injectedCopies": "retained_until_thread_history_clear",
                    }),
            "a Local deletion step was neither the 202 pending nor the 200 deleted receipt",
        )?;
        if status == StatusCode::OK {
            deleted = true;
            break;
        }
        pending += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    require(deleted, "the Local deletion never completed")?;

    // A window authority captured before its label was rebound is refused before dispatch.
    let stale = protocol
        .authority("main")
        .map_err(text)?
        .ok_or("original Local window missing")?;
    require(
        protocol.unbind_window("main").map_err(text)?,
        "original Local window withdrawal absent",
    )?;
    protocol
        .bind_window("main", prepared.auth_context().clone(), Some(FRESH))
        .map_err(text)?;
    let (status, value) = answered(&protocol.artifacts("main", delete_request(id)?, stale).await)?;
    require(
        status == StatusCode::UNAUTHORIZED && value == json!({"code": "unauthenticated"}),
        "a stale Local window deletion was not 401",
    )?;
    eprintln!(
        "ARTIFACT_DELETION_LOCAL pending_resends={pending} deleted=200 stale_window=401 no_store=true"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicitly owned PostgreSQL17.11 binaries via OPENBOT_TEST_PG_BIN"]
async fn artifact_deletion_real_local_window_deletes_and_stale_window_refuses() {
    let mut bundle = OwnedBundle::materialize().expect("owned PostgreSQL bundle");
    let mut root = OwnedRoot::new("app").expect("owned Local app-data root");
    // The sidecar data directory lives under this root until a real shutdown ACK.
    root.remove = false;
    let prepared = prepare(&bundle, &root)
        .await
        .expect("genuine Prepared Local setup");
    let outcome = exercise(&prepared).await;
    let closed = prepared.shutdown().await;
    if closed.is_ok() {
        root.remove = true;
        bundle.root.remove = true;
    }
    drop(root);
    drop(bundle);
    outcome.expect("Local artifact deletion");
    closed.expect("genuine Prepared Local shutdown");
}
