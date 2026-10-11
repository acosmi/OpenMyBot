//! Genuine Prepared Local custom-V2 consumer tests with real owned PG, Vault and Agent host.
//! Controlled bundle hashing does not certify release signing, restore or a renderer ACK.
#![cfg(all(feature = "desktop-local-runtime", target_os = "macos"))]

use super::*;
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
use async_trait::async_trait;
use openbot_application::tenant::package::{
    LoadedTenantPackage, TenantPackageFiles, validate_tenant_package,
};
use openbot_contracts::command::ThreadRunStarted;
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
            "openbot-custom-v2-{label}-{}",
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
            eprintln!("CUSTOM_V2_LOCAL_OWNED_ROOT retained_unproven_cleanup=true");
            return;
        }
        let removed = std::fs::remove_dir_all(&self.0);
        eprintln!(
            "CUSTOM_V2_LOCAL_OWNED_ROOT removed={} absent={}",
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
        "/controlled/custom-v2-local-package".to_owned(),
        "d".repeat(64),
    )
}

struct LocalFixture {
    root: OwnedRoot,
    prepared: Option<PreparedDesktopLocalRuntime>,
    postmaster_pid: u32,
    postmaster_file: PathBuf,
}
impl LocalFixture {
    async fn new(bundle: &OwnedBundle, label: &str, tls: &OwnedTls) -> Result<Self, String> {
        let mut root = OwnedRoot::new(label)?;
        let assets = root.0.join("assets");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&assets)
            .map_err(|e| e.to_string())?;
        std::fs::write(assets.join("index.html"), "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>").map_err(|e| e.to_string())?;
        std::fs::write(assets.join("openbot-bootstrap.mjs"), "export {};")
            .map_err(|e| e.to_string())?;
        let release = DesktopLocalReleaseInput::new(
            &assets,
            "openbot",
            "main",
            bundle.open()?,
            ReviewedPostgresKeyStoreService::from_reviewed_release(
                "com.example.review.custom-v2-scram",
            )
            .map_err(|e| e.to_string())?,
            ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
                "com.example.review.custom-v2-vault",
            )
            .map_err(|e| e.to_string())?,
            Arc::new(MemorySecretStore::default()),
        )
        .map_err(|e| e.to_string())?;
        let application = DesktopLocalApplicationInput::new(
            DesktopOpenAiProviderInput::new(&tls.endpoint(), vec!["127.0.0.1/32".to_owned()])
                .map_err(|e| e.to_string())?
                .with_test_custom_model_dialer(tls.dialer()?),
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // From this point an unproved shutdown keeps the owned evidence, including failures.
        root.1 = false;
        let prepared = prepare_desktop_local_runtime(
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&root.0)
                .map_err(|e| e.to_string())?,
            DesktopLocalRuntimeConfig::new(release, application, |authority| {
                package(authority.auth_context().tenant().as_str())
            }),
        )
        .await
        .map_err(|e| e.to_string())?;
        let populated = async {
            prepared
                .protocol()
                .bind_window(
                    "main",
                    prepared.auth_context().clone(),
                    Some(Duration::from_secs(60)),
                )
                .map_err(|e| e.to_string())?;
            let mut pids = Vec::new();
            for entry in std::fs::read_dir(&root.0).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("postgresql-17-"))
                    && path.is_dir()
                {
                    let pid = std::fs::read_to_string(path.join("postmaster.pid"))
                        .map_err(|e| e.to_string())?
                        .lines()
                        .next()
                        .ok_or("owned PID missing")?
                        .parse::<u32>()
                        .map_err(|_| "owned PID invalid")?;
                    require(pid > 1, "owned postmaster PID invalid")?;
                    pids.push((pid, path.join("postmaster.pid")));
                }
            }
            require(
                pids.len() == 1,
                "actual Prepared did not own exactly one postmaster",
            )?;
            pids.into_iter()
                .next()
                .ok_or_else(|| "owned postmaster identity missing".to_owned())
        }
        .await;
        match populated {
            Ok((postmaster_pid, postmaster_file)) => {
                eprintln!(
                    "CUSTOM_V2_LOCAL_ACTUAL_RESOURCE original_postmaster_pid={postmaster_pid} controlled_app_root={} original_PID_file={} data_dir={}",
                    root.0.display(),
                    postmaster_file.display(),
                    postmaster_file
                        .parent()
                        .expect("owned PID directory")
                        .display()
                );
                Ok(Self {
                    root,
                    prepared: Some(prepared),
                    postmaster_pid,
                    postmaster_file,
                })
            }
            Err(error) => {
                let cleaned = prepared.shutdown().await;
                if cleaned.is_ok() {
                    root.1 = true;
                }
                require(cleaned.is_ok(), "failed Prepared setup cleanup did not ACK")?;
                Err(error)
            }
        }
    }
    fn prepared(&self) -> &PreparedDesktopLocalRuntime {
        self.prepared
            .as_ref()
            .expect("owned Prepared already moved")
    }
    async fn finish(mut self) -> Result<(), String> {
        let closing_ok = match self.prepared.take() {
            Some(prepared) => prepared.shutdown().await.is_ok(),
            None => true,
        };
        self.root.1 = false;
        require(
            !owned_postmaster_live(self.postmaster_pid)? && !self.postmaster_file.exists(),
            "owned original postmaster or PID file survived shutdown",
        )?;
        require(closing_ok, "actual Prepared shutdown did not ACK")?;
        self.root.1 = true;
        eprintln!(
            "CUSTOM_V2_LOCAL_PHYSICAL_CLEANUP own_postmaster_pid={} pid_gone=true original_PID_file_gone=true",
            self.postmaster_pid
        );
        Ok(())
    }
}
fn owned_postmaster_live(pid: u32) -> Result<bool, String> {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|_| "owned postmaster liveness observation failed".to_owned())
}

const API_KEY: &str = "OWNED_V2_HOST_SYNTHETIC_KEY";

macro_rules! checked {
    ($condition:expr $(, $message:literal)?) => {
        require(
            $condition,
            concat!("custom-V2 assertion: ", stringify!($condition)),
        )?
    };
}
macro_rules! checked_eq {
    ($actual:expr,$expected:expr $(, $message:literal)?) => {
        require(
            $actual == $expected,
            concat!(
                "custom-V2 equality: ",
                stringify!($actual),
                " == ",
                stringify!($expected)
            ),
        )?
    };
}

fn v2_request(method: Method, path: &str, body: Vec<u8>) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body)
        .expect("static request shape")
}

fn v2_body(run: &str, selection: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"runId":run,"botId":"desktop-assistant","anchor":{"kind":"direct_bot"},"message":"Please remember the synthetic fact, then answer.","modelSelection":selection})).expect("static JSON")
}

#[test]
fn local_original_v2_body_is_zeroed_before_typed_dispatch() {
    let selection = json!({"schemaVersion":2,"source":"custom","connectionId":"01234567-89AB-CDEF-0123-456789ABCDEF","expectedConnectionRevision":9,"modelId":"owned-model","expectedCatalogRevision":1});
    let mut request = v2_request(
        Method::POST,
        "/api/threads/owned/runs",
        v2_body("owned-zeroing", &selection),
    );
    let parsed = parse_sensitive_begin_body(&mut request, CHANNEL_THREAD_BODY_MAX_BYTES).unwrap();
    assert!(request.body().iter().all(|byte| *byte == 0));
    let openbot_contracts::begin_thread_run_wire::DecodedBeginThreadRunBody::V2(owned) = parsed
    else {
        panic!("V2 downgraded")
    };
    assert_eq!(
        owned.model_selection.connection_id(),
        "01234567-89AB-CDEF-0123-456789ABCDEF"
    );
    for raw in [
        b"{malformed".to_vec(),
        v2_body(
            "owned-bad-union",
            &json!({"schemaVersion":2,"connectionId":"01234567-89AB-CDEF-0123-456789ABCDEF","expectedRevision":9}),
        ),
    ] {
        let mut request = v2_request(Method::POST, "/api/threads/owned/runs", raw);
        assert!(parse_sensitive_begin_body(&mut request, CHANNEL_THREAD_BODY_MAX_BYTES).is_err());
        assert!(request.body().iter().all(|byte| *byte == 0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Root-owned pinned PG17 bundle and Python SSL; genuine Prepared Local Agent host"]
async fn genuine_prepared_local_raw_v2_snapshot_and_repeated_sampling() {
    let bundle = OwnedBundle::materialize().expect("owned pinned PG bundle");
    let tls = OwnedTls::new("local").expect("owned pinned Python TLS fixture");
    let fixture = LocalFixture::new(&bundle, "v2-consumption", &tls)
        .await
        .expect("genuine Prepared Local startup");
    let result:Result<(),String>=async {
        let prepared=fixture.prepared();
        let protocol=prepared.protocol();
        let policy=openbot_contracts::policy::ActionPolicyDocument {
            mode:openbot_contracts::policy::ActionPolicyMode::Enforce,
            deny:vec![],
            allow:vec![r#"tool.name == "remember" && bot.id == "desktop-assistant" && actor.id == "desktop-local-user""#.to_owned()],
        };
        let installed=prepared.application().execute(prepared.auth_context().clone(),
            openbot_contracts::command::AppCommand::SetActionPolicy{policy:policy.clone()})
            .await.map_err(|e|e.to_string())?;
        let openbot_contracts::command::AppReply::ActionPolicy{policy:Some(actual)}=installed
            else{return Err("actual Local action policy installation reply mismatch".to_owned());};
        checked_eq!(actual,policy);
        let create=protocol.handle("main",v2_request(Method::POST,"/api/me/model-connections",serde_json::to_vec(&json!({
            "name":"Owned Local V2 model","protocol":"openai_responses","endpoint":tls.endpoint(),"model":"owned-host-model","enabled":true,"apiKey":API_KEY,
        })).map_err(|e|e.to_string())?)).await;
        checked_eq!(create.status(),StatusCode::CREATED);
        let model:openbot_contracts::model_connections::ModelConnection=serde_json::from_slice(create.body()).map_err(|e|e.to_string())?;
        let selection=json!({"schemaVersion":2,"source":"custom","connectionId":model.id,"expectedConnectionRevision":model.revision,"modelId":format!("custom:{}",model.id),"expectedCatalogRevision":1});
        let thread=ThreadIdentity::new(prepared.auth_context().deployment()).mint_from_entropy([0x26;16]);
        let path=format!("/api/threads/{}/runs",thread.as_str());
        let raw=v2_body("owned-local-v2-run",&selection);
        let invalid=v2_body("owned-local-malformed-run",&json!({"schemaVersion":2,"connectionId":model.id,"expectedRevision":model.revision}));
        checked_eq!(protocol.handle("main",v2_request(Method::POST,&path,invalid)).await.status(),StatusCode::BAD_REQUEST);
        let selector=selection.to_string();
        let oversized=format!("{{\"runId\":\"owned-local-large-run\",\"botId\":\"desktop-assistant\",\"anchor\":{{\"kind\":\"direct_bot\"}},\"message\":\"x\",\"modelSelection\":{}{selector}}}"," ".repeat(4097-selector.len())).into_bytes();
        checked_eq!(protocol.handle("main",v2_request(Method::POST,&path,oversized)).await.status(),StatusCode::BAD_REQUEST);
        checked_eq!(protocol.handle("unbound",v2_request(Method::POST,&path,raw.clone())).await.status(),StatusCode::UNAUTHORIZED);
        tls.release()?;
        let reply=protocol.handle("main",v2_request(Method::POST,&path,raw.clone())).await;
        checked_eq!(reply.status(),StatusCode::CREATED);
        let receipt:ThreadRunStarted=serde_json::from_slice(reply.body()).map_err(|e|e.to_string())?;
        checked!(!receipt.replayed);
        wait_local_completed(prepared.pool(),"owned-local-v2-run").await?;
        let client=prepared.pool().get().await.map_err(|e|e.to_string())?;
        let row=client.query_one("SELECT s.*,r.created_at AS run_time,m.content,d.dataset_id AS current_dataset,d.initial_origin AS current_origin,d.created_at AS current_dataset_time,c.current_secret_id AS current_secret FROM openbot_internal.run_model_selection_v2_snapshots s JOIN public.runs r USING(run_id) JOIN public.messages m ON m.message_id=r.run_id||':input' JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=s.deployment_id AND d.tenant_id=s.tenant_id JOIN public.model_connections c ON c.id=s.connection_id WHERE s.run_id=$1",&[&"owned-local-v2-run"]).await.map_err(|e|e.to_string())?;
        let snapshot=openbot_infra::db::tables::run_model_selection_v2_snapshots::Row::try_from(&row).map_err(|e|e.to_string())?;
        let auth=prepared.auth_context();
        checked_eq!(snapshot.run_id,"owned-local-v2-run"); checked_eq!(snapshot.deployment_id,auth.deployment().as_str()); checked_eq!(snapshot.tenant_id,auth.tenant().as_str()); checked_eq!(snapshot.owner_user_id,auth.actor().as_str());
        checked_eq!(snapshot.auth_generation,i64::try_from(auth.auth_generation().get()).map_err(|e|e.to_string())?); checked_eq!(snapshot.connection_id.to_string(),model.id); checked_eq!(snapshot.connection_revision,model.revision);
        checked_eq!(snapshot.secret_id,row.get::<_,uuid::Uuid>("current_secret")); checked_eq!(snapshot.protocol,model.protocol.as_str()); checked_eq!(snapshot.endpoint,model.endpoint); checked_eq!(snapshot.model,model.model);
        checked_eq!(snapshot.created_at,row.get::<_,time::OffsetDateTime>("run_time")); checked_eq!(snapshot.snapshot_schema,2); checked_eq!(snapshot.source,"custom"); checked_eq!(snapshot.model_id,format!("custom:{}",model.id)); checked_eq!(snapshot.catalog_revision,1);
        checked_eq!(snapshot.dataset_id,row.get::<_,String>("current_dataset")); checked_eq!(snapshot.dataset_binding_schema,1); checked_eq!(snapshot.dataset_initial_origin,row.get::<_,String>("current_origin")); checked_eq!(snapshot.dataset_initial_origin,"desktop_canary");
        checked_eq!(snapshot.dataset_binding_created_at,row.get::<_,time::OffsetDateTime>("current_dataset_time")); checked_eq!(snapshot.credential_policy,"custom_fixed_secret_revision_v1");
        let canary=client.query_one("SELECT dataset_id,key_id,key_version,canary_schema,encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2",&[&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?;
        checked_eq!(canary.get::<_,String>("dataset_id"),snapshot.dataset_id);
        checked_eq!(canary.get::<_,String>("key_id").len(),32); checked_eq!(canary.get::<_,i32>("key_version"),1); checked_eq!(canary.get::<_,i16>("canary_schema"),1);
        let encrypted_canary:String=canary.get("encrypted_canary"); checked!(!encrypted_canary.is_empty());
        checked_eq!(row.get::<_,Value>("content"),json!({"text":"Please remember the synthetic fact, then answer.","modelSelection":selection,"runAnchor":{"kind":"direct_bot"}}));
        checked_eq!(client.query_one("SELECT count(*) FROM public.run_events WHERE run_id=$1 AND seq=0",&[&"owned-local-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
        checked_eq!(client.query_one("SELECT count(*) FROM public.outbox WHERE outbox_id=$1",&[&"owned-local-v2-run:agent_run_dispatch"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
        checked_eq!(client.query_one("SELECT count(*) FROM public.run_model_selections WHERE run_id=$1",&[&"owned-local-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),0);
        checked_eq!(client.query_one("SELECT count(*) FROM public.remember_effect_receipts WHERE run_id=$1",&[&"owned-local-v2-run"]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1); drop(client);
        let replay=protocol.handle("main",v2_request(Method::POST,&path,raw.clone())).await;
        checked_eq!(replay.status(),StatusCode::OK);
        checked_eq!(serde_json::from_slice::<Value>(replay.body()).map_err(|e|e.to_string())?["replayed"],true);
        let captures=tls.captures()?;
        checked_eq!(captures.len(),2);
        for capture in &captures {
            checked_eq!(capture["path"],"/v1/responses"); checked_eq!(capture["authorization"],format!("Bearer {API_KEY}")); checked_eq!(capture["body"]["model"],"owned-host-model");
            let body=capture["body"].to_string();
            for hidden in ["modelSelection","datasetId","secretId","authGeneration",API_KEY] { checked!(!body.contains(hidden)); }
        }
        checked!(captures[1]["body"].to_string().contains("function_call_output"));
        let client=prepared.pool().get().await.map_err(|e|e.to_string())?;
        client.execute("UPDATE public.model_connections SET enabled=false WHERE id=$1",&[&snapshot.connection_id]).await.map_err(|e|e.to_string())?; drop(client);
        let denied=protocol.handle("main",v2_request(Method::POST,&path,v2_body("owned-local-disabled-run",&selection))).await;
        checked!(!denied.status().is_success()); checked_eq!(tls.captures()?.len(),2);
        let client=prepared.pool().get().await.map_err(|e|e.to_string())?;
        client.execute("UPDATE public.model_connections SET enabled=true WHERE id=$1",&[&snapshot.connection_id]).await.map_err(|e|e.to_string())?;
        // The original sync trigger advances catalog revision on disable and reenable.
        // Fresh fault requests use the actual current revision; historical replay keeps raw.
        let current=client.query_one("SELECT c.revision AS connection_revision,cc.catalog_revision FROM public.model_connections c JOIN public.custom_model_catalogs cc ON cc.connection_id=c.id AND cc.deployment_id=c.deployment_id AND cc.tenant_id=c.tenant_id AND cc.owner_user_id=c.owner_user_id WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND c.enabled AND c.deleted_at IS NULL AND cc.enabled AND NOT cc.retired",&[&snapshot.connection_id,&auth.deployment().as_str(),&auth.tenant().as_str(),&auth.actor().as_str()]).await.map_err(|e|e.to_string())?;
        let connection_revision:i64=current.try_get("connection_revision").map_err(|e|e.to_string())?;
        let catalog_revision:i64=current.try_get("catalog_revision").map_err(|e|e.to_string())?;
        checked_eq!(connection_revision,model.revision);
        checked!(catalog_revision>0 && catalog_revision>selection["expectedCatalogRevision"].as_i64().ok_or("original catalog revision missing")?);
        let mut current_selection=selection.clone();
        current_selection["expectedCatalogRevision"]=json!(catalog_revision);
        eprintln!("CUSTOM_V2_LOCAL_CURRENT_SELECTOR connection_revision={connection_revision} catalog_revision={catalog_revision}");
        // Controlled fault injection into this synthetic database only. Production must reject
        // the altered digest; the fixture restores its saved original after recording refusal.
        checked_eq!(client.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1 WHERE deployment_id=$2 AND tenant_id=$3",&[&format!("{encrypted_canary}x"),&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?,1); drop(client);
        let canary_denied=protocol.handle("main",v2_request(Method::POST,&path,v2_body("owned-local-canary-drift-run",&current_selection))).await;
        let client=prepared.pool().get().await.map_err(|e|e.to_string())?;
        client.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1 WHERE deployment_id=$2 AND tenant_id=$3",&[&encrypted_canary,&auth.deployment().as_str(),&auth.tenant().as_str()]).await.map_err(|e|e.to_string())?;
        eprintln!("CUSTOM_V2_LOCAL_CANARY_RESPONSE status={}",canary_denied.status());
        checked_eq!(canary_denied.status(),StatusCode::SERVICE_UNAVAILABLE);
        let canary_error:Value=serde_json::from_slice(canary_denied.body()).map_err(|e|e.to_string())?;
        checked_eq!(canary_error["code"],"dependency_unavailable");
        checked_eq!(tls.captures()?.len(),2);
        checked_eq!(client.query_one("SELECT count(*) FROM public.runs WHERE run_id IN ('owned-local-malformed-run','owned-local-large-run','owned-local-disabled-run','owned-local-canary-drift-run')",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),0);
        drop(client);
        local_m04_original_lineage_faults(prepared,&tls,&path,&raw,&current_selection).await?;
        Ok(())
    }.await;
    // Ordinary assertions return Result so both actual owners close even on a failure.
    let tls_closed = tls.finish();
    let local_closed = fixture.finish().await;
    eprintln!(
        "CUSTOM_V2_LOCAL_CLOSURE tls_ok={} prepared_ok={}",
        tls_closed.is_ok(),
        local_closed.is_ok()
    );
    result.expect("genuine Local raw-to-provider chain");
    tls_closed.expect("owned TLS normal child closure");
    local_closed.expect("genuine Prepared PG normal shutdown and original PID closure");
}

#[derive(Clone, Copy, Debug)]
enum LocalM04Fault {
    DatasetDeployment,
    DatasetTenant,
    DatasetIdentity,
    DatasetOrigin,
    DatasetCreatedAt,
    DatasetBindingSchemaCheck,
    CanaryDataset,
    CanaryDeployment,
    CanaryTenant,
    CanaryKeyId,
    CanaryKeyVersion,
    CanarySchemaCheck,
    CanaryDigest,
    NativeChecksum,
    NativeMissingVersion,
    SnapshotColumnShape,
    CanaryColumnShape,
    NamespaceShape,
}
impl LocalM04Fault {
    const ALL: [Self; 18] = [
        Self::DatasetDeployment,
        Self::DatasetTenant,
        Self::DatasetIdentity,
        Self::DatasetOrigin,
        Self::DatasetCreatedAt,
        Self::DatasetBindingSchemaCheck,
        Self::CanaryDataset,
        Self::CanaryDeployment,
        Self::CanaryTenant,
        Self::CanaryKeyId,
        Self::CanaryKeyVersion,
        Self::CanarySchemaCheck,
        Self::CanaryDigest,
        Self::NativeChecksum,
        Self::NativeMissingVersion,
        Self::SnapshotColumnShape,
        Self::CanaryColumnShape,
        Self::NamespaceShape,
    ];
    fn original_check(self) -> bool {
        matches!(
            self,
            Self::DatasetBindingSchemaCheck | Self::CanarySchemaCheck
        )
    }
    fn dataset_row(self) -> bool {
        matches!(
            self,
            Self::DatasetDeployment
                | Self::DatasetTenant
                | Self::DatasetIdentity
                | Self::DatasetOrigin
                | Self::DatasetCreatedAt
                | Self::DatasetBindingSchemaCheck
        )
    }
}

// Only values read from this genuine Prepared startup are retained for restoration.
// None of these row values constructs a canary proof, DB owner or dataset grant.
#[derive(PartialEq)]
struct OriginalLocalLineage {
    deployment: String,
    tenant: String,
    dataset: String,
    binding_schema: i16,
    initial_origin: String,
    binding_created_at: time::OffsetDateTime,
    canary_dataset: String,
    canary_deployment: String,
    canary_tenant: String,
    key_id: String,
    key_version: i32,
    canary_schema: i16,
    encrypted_canary: String,
    canary_created_at: time::OffsetDateTime,
    native_version: i32,
    native_name: String,
    native_checksum: String,
    native_applied_at: time::OffsetDateTime,
}
impl OriginalLocalLineage {
    async fn read(pool: &openbot_infra::db::pool::DatabasePool) -> Result<Self, String> {
        let c = pool.get().await.map_err(|e| e.to_string())?;
        let bindings=c.query("SELECT deployment_id,tenant_id,dataset_id,binding_schema,initial_origin,created_at FROM openbot_internal.artifact_dataset_bindings",&[]).await.map_err(|e|e.to_string())?;
        require(
            bindings.len() == 1,
            "owned Local fixture must have exactly one original dataset binding",
        )?;
        let d = &bindings[0];
        let canaries=c.query("SELECT dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary,created_at FROM openbot_internal.desktop_vault_canaries",&[]).await.map_err(|e|e.to_string())?;
        require(
            canaries.len() == 1,
            "owned Local fixture must have exactly one original canary",
        )?;
        let a = &canaries[0];
        let migration=c.query_one("SELECT version,name,checksum,applied_at FROM openbot_internal.schema_migrations WHERE version=47",&[]).await.map_err(|e|e.to_string())?;
        Ok(Self {
            deployment: d.try_get(0).map_err(|e| e.to_string())?,
            tenant: d.try_get(1).map_err(|e| e.to_string())?,
            dataset: d.try_get(2).map_err(|e| e.to_string())?,
            binding_schema: d.try_get(3).map_err(|e| e.to_string())?,
            initial_origin: d.try_get(4).map_err(|e| e.to_string())?,
            binding_created_at: d.try_get(5).map_err(|e| e.to_string())?,
            canary_dataset: a.try_get(0).map_err(|e| e.to_string())?,
            canary_deployment: a.try_get(1).map_err(|e| e.to_string())?,
            canary_tenant: a.try_get(2).map_err(|e| e.to_string())?,
            key_id: a.try_get(3).map_err(|e| e.to_string())?,
            key_version: a.try_get(4).map_err(|e| e.to_string())?,
            canary_schema: a.try_get(5).map_err(|e| e.to_string())?,
            encrypted_canary: a.try_get(6).map_err(|e| e.to_string())?,
            canary_created_at: a.try_get(7).map_err(|e| e.to_string())?,
            native_version: migration.try_get(0).map_err(|e| e.to_string())?,
            native_name: migration.try_get(1).map_err(|e| e.to_string())?,
            native_checksum: migration.try_get(2).map_err(|e| e.to_string())?,
            native_applied_at: migration.try_get(3).map_err(|e| e.to_string())?,
        })
    }
    async fn inject(
        &self,
        c: &openbot_infra::db::pool::PooledClient,
        fault: LocalM04Fault,
    ) -> Result<(), String> {
        // Validate all saved mutation inputs before temporarily changing the
        // append-only trigger. An invalid fixture must not bypass restoration.
        let changed_dataset = different_hex(&self.dataset)?;
        let changed_canary_dataset = different_hex(&self.canary_dataset)?;
        let changed_key_id = different_hex(&self.key_id)?;
        let changed_canary = different_first_ascii(&self.encrypted_canary)?;
        let changed_checksum = different_hex(&self.native_checksum)?;
        if fault.dataset_row() {
            c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e|e.to_string())?;
        }
        let changed=match fault {
            LocalM04Fault::DatasetDeployment=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET deployment_id=$1",&[&format!("{}-owned-drift",self.deployment)]).await,
            LocalM04Fault::DatasetTenant=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET tenant_id=$1",&[&format!("{}-owned-drift",self.tenant)]).await,
            LocalM04Fault::DatasetIdentity=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET dataset_id=$1",&[&changed_dataset]).await,
            LocalM04Fault::DatasetOrigin=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='server_first_adoption'",&[]).await,
            LocalM04Fault::DatasetCreatedAt=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET created_at=$1",&[&(self.binding_created_at+time::Duration::seconds(1))]).await,
            LocalM04Fault::DatasetBindingSchemaCheck=>c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET binding_schema=2",&[]).await,
            LocalM04Fault::CanaryDataset=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET dataset_id=$1",&[&changed_canary_dataset]).await,
            LocalM04Fault::CanaryDeployment=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET deployment_id=$1",&[&format!("{}-owned-drift",self.canary_deployment)]).await,
            LocalM04Fault::CanaryTenant=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET tenant_id=$1",&[&format!("{}-owned-drift",self.canary_tenant)]).await,
            LocalM04Fault::CanaryKeyId=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET key_id=$1",&[&changed_key_id]).await,
            LocalM04Fault::CanaryKeyVersion=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET key_version=2",&[]).await,
            LocalM04Fault::CanarySchemaCheck=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET canary_schema=2",&[]).await,
            LocalM04Fault::CanaryDigest=>c.execute("UPDATE openbot_internal.desktop_vault_canaries SET encrypted_canary=$1",&[&changed_canary]).await,
            LocalM04Fault::NativeChecksum=>c.execute("UPDATE openbot_internal.schema_migrations SET checksum=$1 WHERE version=$2",&[&changed_checksum,&self.native_version]).await,
            LocalM04Fault::NativeMissingVersion=>c.execute("DELETE FROM openbot_internal.schema_migrations WHERE version=$1",&[&self.native_version]).await,
            LocalM04Fault::SnapshotColumnShape=>{
                c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME COLUMN credential_policy TO owned_fault_credential_policy").await.map_err(|e|e.to_string())?;return Ok(());
            }
            LocalM04Fault::CanaryColumnShape=>{
                c.batch_execute("ALTER TABLE openbot_internal.desktop_vault_canaries RENAME COLUMN encrypted_canary TO owned_fault_encrypted_canary").await.map_err(|e|e.to_string())?;return Ok(());
            }
            LocalM04Fault::NamespaceShape=>{
                c.batch_execute("ALTER SCHEMA openbot_internal RENAME TO owned_local_m04_namespace_fault").await.map_err(|e|e.to_string())?;return Ok(());
            }
        };
        if fault.dataset_row() {
            // Restore the precise original trigger before inspecting a mutation
            // result or invoking the real consumer. Never leave a disabled guard
            // as the reason a tuple fault is rejected by its shape validator.
            c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e|e.to_string())?;
            let enabled:String=c.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='openbot_internal.artifact_dataset_bindings'::regclass AND tgname='artifact_dataset_bindings_append_only'",&[]).await.map_err(|e|e.to_string())?.get(0);
            require(
                enabled == "O",
                "owned dataset append-only trigger was not restored",
            )?;
        }
        if fault.original_check() {
            // Under the real validated CHECK (=1), a schema=2 row cannot exist.
            // This is an actual DB refusal, separately labelled from a consumer
            // rejecting an injected row. No CHECK is dropped or forged valid.
            let error = changed
                .err()
                .ok_or("original Local schema CHECK unexpectedly accepted2")?;
            require(
                error.code().is_some_and(|code| code.code() == "23514"),
                "original Local schema CHECK did not issue check_violation",
            )?;
        } else {
            require(
                changed.map_err(|e| e.to_string())? == 1,
                "owned Local fault did not affect exactly one saved row",
            )?;
        }
        Ok(())
    }
    async fn restore(
        &self,
        c: &openbot_infra::db::pool::PooledClient,
        fault: LocalM04Fault,
    ) -> Result<(), String> {
        match fault {
            LocalM04Fault::SnapshotColumnShape=>c.batch_execute("ALTER TABLE openbot_internal.run_model_selection_v2_snapshots RENAME COLUMN owned_fault_credential_policy TO credential_policy").await.map_err(|e|e.to_string())?,
            LocalM04Fault::CanaryColumnShape=>c.batch_execute("ALTER TABLE openbot_internal.desktop_vault_canaries RENAME COLUMN owned_fault_encrypted_canary TO encrypted_canary").await.map_err(|e|e.to_string())?,
            LocalM04Fault::NamespaceShape=>c.batch_execute("ALTER SCHEMA owned_local_m04_namespace_fault RENAME TO openbot_internal").await.map_err(|e|e.to_string())?,
            _=>{}
        }
        c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e|e.to_string())?;
        let restored=c.execute("UPDATE openbot_internal.artifact_dataset_bindings SET deployment_id=$1,tenant_id=$2,dataset_id=$3,binding_schema=$4,initial_origin=$5,created_at=$6",&[&self.deployment,&self.tenant,&self.dataset,&self.binding_schema,&self.initial_origin,&self.binding_created_at]).await;
        c.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e|e.to_string())?;
        require(
            restored.map_err(|e| e.to_string())? == 1,
            "owned Local original dataset restore row count",
        )?;
        require(c.execute("UPDATE openbot_internal.desktop_vault_canaries SET dataset_id=$1,deployment_id=$2,tenant_id=$3,key_id=$4,key_version=$5,canary_schema=$6,encrypted_canary=$7,created_at=$8",&[&self.canary_dataset,&self.canary_deployment,&self.canary_tenant,&self.key_id,&self.key_version,&self.canary_schema,&self.encrypted_canary,&self.canary_created_at]).await.map_err(|e|e.to_string())?==1,"owned Local original canary restore row count")?;
        c.execute("INSERT INTO openbot_internal.schema_migrations(version,name,checksum,applied_at) VALUES($1,$2,$3,$4) ON CONFLICT(version) DO UPDATE SET name=excluded.name,checksum=excluded.checksum,applied_at=excluded.applied_at",&[&self.native_version,&self.native_name,&self.native_checksum,&self.native_applied_at]).await.map_err(|e|e.to_string())?;
        Ok(())
    }
}
fn different_hex(original: &str) -> Result<String, String> {
    require(
        !original.is_empty()
            && original
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "owned original hex fixture value invalid",
    )?;
    let mut bytes = original.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).map_err(|_| "owned changed hex fixture value invalid".to_owned())
}
fn different_first_ascii(original: &str) -> Result<String, String> {
    require(
        !original.is_empty() && original.is_ascii(),
        "owned original canary envelope invalid",
    )?;
    let mut bytes = original.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'x' { b'y' } else { b'x' };
    String::from_utf8(bytes).map_err(|_| "owned changed envelope invalid".to_owned())
}
async fn local_m04_business_counts(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<Vec<i64>, String> {
    let c = pool.get().await.map_err(|e| e.to_string())?;
    let mut counts = Vec::new();
    for table in [
        "public.threads",
        "public.thread_memberships",
        "public.thread_leases",
        "public.runs",
        "public.messages",
        "public.run_events",
        "public.outbox",
        "public.run_model_selections",
        "openbot_internal.run_model_selection_v2_snapshots",
    ] {
        counts.push(
            c.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .map_err(|e| e.to_string())?
                .get(0),
        );
    }
    Ok(counts)
}
async fn local_m04_original_lineage_faults(
    prepared: &PreparedDesktopLocalRuntime,
    tls: &OwnedTls,
    path: &str,
    original_body: &[u8],
    selection: &Value,
) -> Result<(), String> {
    let original = OriginalLocalLineage::read(prepared.pool()).await?;
    require(
        original.initial_origin == "desktop_canary"
            && original.binding_schema == 1
            && original.canary_schema == 1
            && original.key_version == 1,
        "owned Local baseline lineage was not the genuine current tuple",
    )?;
    let counts = local_m04_business_counts(prepared.pool()).await?;
    for (index, fault) in LocalM04Fault::ALL.into_iter().enumerate() {
        let c = prepared.pool().get().await.map_err(|e| e.to_string())?;
        let injected = original.inject(&c, fault).await;
        drop(c);
        let check_row_unchanged = if injected.is_ok() && fault.original_check() {
            Some(
                OriginalLocalLineage::read(prepared.pool())
                    .await
                    .map(|actual| actual == original),
            )
        } else {
            None
        };
        let denied = if injected.is_ok() && !fault.original_check() {
            Some(
                prepared
                    .protocol()
                    .handle(
                        "main",
                        v2_request(
                            Method::POST,
                            path,
                            v2_body(&format!("owned-local-m04-{index}"), selection),
                        ),
                    )
                    .await,
            )
        } else {
            None
        };
        // Always attempt restoration before returning an injection/refusal error.
        let c = prepared.pool().get().await.map_err(|e| e.to_string())?;
        let restored = original.restore(&c, fault).await;
        drop(c);
        restored?;
        injected?;
        if let Some(unchanged) = check_row_unchanged {
            require(
                unchanged?,
                "original Local CHECK refusal changed the saved typed row",
            )?;
        }
        require(
            OriginalLocalLineage::read(prepared.pool()).await? == original,
            "owned original Local typed lineage was not restored exactly",
        )?;
        if let Some(denied) = denied {
            // Do not count an expired/unbound window's401, parser400 or unrelated
            // permission refusal as a model/dataset fault producer.
            eprintln!(
                "CUSTOM_V2_LOCAL_M04_RESPONSE branch={fault:?} status={}",
                denied.status()
            );
            require(
                denied.status() == StatusCode::SERVICE_UNAVAILABLE,
                "owned Local lineage fault did not reach the production dependency rejection",
            )?;
            let error: Value = serde_json::from_slice(denied.body()).map_err(|e| e.to_string())?;
            let observed_code = if error["code"] == "dependency_unavailable" {
                "dependency_unavailable"
            } else {
                "unexpected_public_code"
            };
            eprintln!("CUSTOM_V2_LOCAL_M04_ERROR branch={fault:?} code={observed_code}");
            require(
                error["code"] == "dependency_unavailable",
                "owned Local lineage fault returned an unrelated error",
            )?;
        }
        require(
            local_m04_business_counts(prepared.pool()).await? == counts,
            "owned Local denied fault committed business rows",
        )?;
        require(
            tls.captures()?.len() == 2,
            "owned Local denied fault reached an extra provider request",
        )?;
        let replay = prepared
            .protocol()
            .handle(
                "main",
                v2_request(Method::POST, path, original_body.to_vec()),
            )
            .await;
        require(
            replay.status() == StatusCode::OK,
            "restored original Local receipt was not usable",
        )?;
        let receipt: ThreadRunStarted =
            serde_json::from_slice(replay.body()).map_err(|e| e.to_string())?;
        require(
            receipt.replayed && receipt.run_id.as_str() == "owned-local-v2-run",
            "restored Local reply was not the original exact receipt",
        )?;
        require(
            local_m04_business_counts(prepared.pool()).await? == counts
                && tls.captures()?.len() == 2,
            "restored Local exact replay changed business counts or sampled again",
        )?;
        eprintln!(
            "CUSTOM_V2_LOCAL_M04 branch={fault:?} observation={} original_typed_values_restored=true original_receipt_replayed=true business_counts_unchanged=true tls_requests=2",
            if fault.original_check() {
                "original_check_violation"
            } else {
                "actual_URI_dependency_rejection"
            }
        );
    }
    Ok(())
}

async fn wait_local_completed(
    pool: &openbot_infra::db::pool::DatabasePool,
    run: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one(
                "SELECT status,error_code FROM public.runs WHERE run_id=$1",
                &[&run],
            )
            .await
            .map_err(|e| e.to_string())?;
        let status: String = row.get(0);
        if status == "completed" {
            return Ok(());
        }
        if !["queued", "running"].contains(&status.as_str()) {
            return Err(format!(
                "actual Local run ended as {status}, code={:?}",
                row.get::<_, Option<String>>(1)
            ));
        }
        if Instant::now() >= deadline {
            return Err("actual Local sampling did not finish within test window".to_owned());
        }
        drop(client);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// The Python interpreter is an explicit Root-frozen test input. It only owns this fixture's
// random temporary directory, listener and child process; it never changes system trust.
struct OwnedTls {
    root: PathBuf,
    child: Option<Child>,
    address: SocketAddr,
    ca: Vec<u8>,
    stdout_reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
    root_removed: bool,
}

impl OwnedTls {
    fn new(label: &str) -> Result<Self, String> {
        let interpreter = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_TLS_PYTHON")
                .ok_or("Root-pinned Python TLS interpreter missing")?,
        );
        if !interpreter.is_absolute() {
            return Err("TLS interpreter must be an absolute pinned input".to_owned());
        }
        let root = std::env::temp_dir().join(format!(
            "openbot-v2-owned-tls-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let child = Command::new(interpreter)
            .args(["-I", "-u", "-c", PYTHON_TLS])
            .arg(&root)
            .args([TEST_CA, TEST_LEAF, TEST_KEY])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut fixture = Self {
            root,
            child: Some(child),
            address: "127.0.0.1:0".parse().unwrap(),
            ca: Vec::new(),
            stdout_reader: None,
            root_removed: false,
        };
        let stdout = fixture
            .child
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .ok_or("owned TLS stdout missing")?;
        let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
        fixture.stdout_reader = Some(std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            let bytes = reader
                .by_ref()
                .take(8193)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            if bytes == 0 || bytes > 8192 {
                return Err("owned TLS startup output missing or unbounded".to_owned());
            }
            ready_send.send(line).map_err(|e| e.to_string())?;
            let mut tail = Vec::new();
            reader
                .take(65537)
                .read_to_end(&mut tail)
                .map_err(|e| e.to_string())?;
            if tail.len() > 65536 {
                return Err("owned TLS stdout tail exceeded budget".to_owned());
            }
            Ok(tail)
        }));
        let line = ready_receive
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("owned TLS startup not acknowledged: {e}"))?;
        let ready: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let port = ready["port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("owned TLS port invalid")?;
        if port == 0 || [39025, 39027].contains(&port) {
            return Err("owned TLS port is outside fixture policy".to_owned());
        }
        fixture.address = SocketAddr::from(([127, 0, 0, 1], port));
        fixture.ca = serde_json::from_value(ready["ca"].clone()).map_err(|e| e.to_string())?;
        eprintln!(
            "CUSTOM_V2_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
            fixture.child.as_ref().unwrap().id(),
            fixture.root.display()
        );
        Ok(fixture)
    }
    fn endpoint(&self) -> String {
        format!("https://idp.test:{}/v1", self.address.port())
    }
    fn dialer(&self) -> Result<SafeDialer, String> {
        SafeDialer::with_extra_roots(
            EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|e| e.to_string())?,
            ),
            Arc::new(OwnedDns(self.address)),
            [self.ca.clone().into()],
        )
        .map_err(|e| e.to_string())
    }
    fn release(&self) -> Result<(), String> {
        std::fs::write(self.root.join("release"), b"owned").map_err(|e| e.to_string())
    }
    fn captures(&self) -> Result<Vec<Value>, String> {
        let path = self.root.join("captures.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
            return Err("owned TLS captures exceeded budget".to_owned());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let captures: Vec<Value> = contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if captures.len() > 16 {
            return Err("owned TLS capture count exceeded budget".to_owned());
        }
        Ok(captures)
    }
    fn finish(mut self) -> Result<(), String> {
        self.release()?;
        let child = self.child.as_mut().ok_or("owned TLS child absent")?;
        child
            .stdin
            .as_mut()
            .ok_or("owned TLS stop channel absent")?
            .write_all(b"x")
            .map_err(|e| e.to_string())?;
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if !status.success() {
                    return Err("owned TLS child did not exit naturally with zero".to_owned());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("owned TLS child did not acknowledge stop".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = child.id();
        drop(self.child.take());
        let tail = self
            .stdout_reader
            .take()
            .ok_or("owned TLS stdout reader absent")?
            .join()
            .map_err(|_| "owned TLS stdout reader panicked")??;
        let stopped: Value = serde_json::from_slice(&tail).map_err(|e| e.to_string())?;
        if stopped["stopped"] != true {
            return Err("owned TLS stop output missing".to_owned());
        }
        let count = self.captures()?.len();
        std::fs::remove_dir_all(&self.root).map_err(|e| e.to_string())?;
        if self.root.exists() {
            return Err("owned TLS root survived cleanup".to_owned());
        }
        self.root_removed = true;
        eprintln!(
            "CUSTOM_V2_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
            self.root.display()
        );
        Ok(())
    }
}
impl Drop for OwnedTls {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("CUSTOM_V2_OWNED_TLS fallback_kill=true natural_stop_unproven=true");
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if !self.root_removed {
            eprintln!(
                "CUSTOM_V2_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
                self.root.display()
            );
        }
    }
}
struct OwnedDns(SocketAddr);
#[async_trait]
impl DnsResolver for OwnedDns {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        if host == "idp.test" && port == self.0.port() {
            Ok(vec![self.0])
        } else {
            Err(DnsUnavailable)
        }
    }
}

const PYTHON_TLS: &str = r#"
import base64,http.server,json,os,pathlib,ssl,sys,threading,time
root=pathlib.Path(sys.argv[1]); os.umask(0o077)
ca,leaf,key=[base64.b64decode(x,validate=True) for x in sys.argv[2:5]]
def pem(kind,data): return ('-----BEGIN '+kind+'-----\n'+base64.encodebytes(data).decode()+'-----END '+kind+'-----\n')
(root/'leaf.pem').write_text(pem('CERTIFICATE',leaf)); (root/'key.pem').write_text(pem('PRIVATE KEY',key))
stop=threading.Event(); count=0
def stopping(): sys.stdin.buffer.read(1); stop.set()
thread=threading.Thread(target=stopping); thread.start()
def events(tool):
    result=[{'type':'response.created','response':{'id':'owned-v2-response'},'sequence_number':0}]
    if tool:
        args=json.dumps({'memoryKind':'fact','scope':'thread','content':'Owned synthetic fact','tags':[],'sensitivity':'normal'},separators=(',',':'))
        item={'id':'owned-v2-function','type':'function_call','status':'completed','arguments':args,'call_id':'owned-v2-call','name':'remember'}
        result += [{'type':'response.output_item.added','item':dict(item,status='in_progress',arguments=''),'output_index':0,'sequence_number':1}, {'type':'response.function_call_arguments.delta','delta':args,'item_id':item['id'],'output_index':0,'sequence_number':2}, {'type':'response.function_call_arguments.done','arguments':args,'item_id':item['id'],'output_index':0,'sequence_number':3}, {'type':'response.output_item.done','item':item,'output_index':0,'sequence_number':4}]
    else: result += [{'type':'response.output_text.delta','delta':'Owned host complete','output_index':0,'sequence_number':1}]
    result += [{'type':'response.completed','response':{'usage':{'input_tokens':2,'output_tokens':3,'total_tokens':5}},'sequence_number':5}]
    return ''.join('data: '+json.dumps(e,separators=(',',':'))+'\n\n' for e in result).encode()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        global count
        self.connection.settimeout(5)
        n=int(self.headers.get('Content-Length','-1'))
        if not 0<=n<=262144 or count>=16: raise RuntimeError('owned request budget')
        body=json.loads(self.rfile.read(n)); count+=1
        capture={'path':self.path,'authorization':self.headers.get('Authorization'),'body':body}
        with (root/'captures.jsonl').open('a') as f: f.write(json.dumps(capture,separators=(',',':'))+'\n'); f.flush()
        deadline=time.monotonic()+15
        while not (root/'release').exists() and not stop.is_set():
            if time.monotonic()>=deadline: raise RuntimeError('owned response gate deadline')
            time.sleep(.01)
        data=events(count==1)
        self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Content-Length',str(len(data))); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'leaf.pem',root/'key.pem')
class Server(http.server.HTTPServer):
    def get_request(self):
        raw,address=self.socket.accept(); raw.settimeout(3)
        try: return context.wrap_socket(raw,server_side=True),address
        except BaseException: raw.close(); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=.2
print(json.dumps({'port':server.server_port,'ca':list(ca)}),flush=True)
try:
    while not stop.is_set(): server.handle_request()
finally: server.server_close(); stop.set(); thread.join(timeout=2)
if thread.is_alive(): raise RuntimeError('owned stop reader did not join')
print(json.dumps({'stopped':True,'requests':count}),flush=True)
"#;

// Existing repository non-production W7 CA/leaf/key, SAN=idp.test. Never installed in OS trust.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
