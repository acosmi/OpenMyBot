//! `openbot-migrate intelligence-import` 的真实文件/crypto/进程/PG17 竖切。

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::process::Command;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer as _, SigningKey};
use harness::{admin_config, with_temp_database};
use hkdf::Hkdf;
use openbot_application::INTELLIGENCE_SOURCE_COMMIT;
use openbot_contracts::intelligence::{
    INTELLIGENCE_BUNDLE_FORMAT, INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundleEnvelope,
    IntelligenceBundlePayload, IntelligenceBundleProvenance, IntelligenceImportMapping,
};
use openbot_infra::db::pool;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use time::macros::datetime;

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn cli_rejects_public_secret_file_then_imports_empty_signed_bundle() {
    let admin = admin_config("cli_rejects_public_secret_file_then_imports_empty_signed_bundle");
    with_temp_database(&admin, "intelligence_cli", |config| async move {
        let directory =
            std::env::temp_dir().join(format!("openbot-intelligence-cli-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let result = async {
            let payload = IntelligenceBundlePayload {
                schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
                bundle_id: "bundle-cli-1".to_owned(),
                source_deployment_id: "source-deployment".to_owned(),
                exported_at: datetime!(2026-08-24 00:00 UTC),
                provenance: IntelligenceBundleProvenance {
                    upstream_commit: INTELLIGENCE_SOURCE_COMMIT.to_owned(),
                    exporter_version: "independent-test-exporter-v1".to_owned(),
                    project_id: "project-cli".to_owned(),
                },
                threads: Vec::new(),
            };
            let key = [3_u8; 32];
            let signing = SigningKey::from_bytes(&[9_u8; 32]);
            let bundle = independently_seal(&payload, &key, &signing)?;
            let mapping = IntelligenceImportMapping {
                target_deployment_id: "target-deployment".to_owned(),
                target_tenant_id: "tenant-a".to_owned(),
                users: Default::default(),
                bots: Default::default(),
                channels: Default::default(),
                claimed_thread_ids: Default::default(),
            };
            let bundle_path = directory.join("bundle.json");
            let mapping_path = directory.join("mapping.json");
            let secret_path = directory.join("decrypt.hex");
            let public_path = directory.join("verify.hex");
            std::fs::write(&bundle_path, bundle).map_err(|error| error.to_string())?;
            std::fs::write(
                &mapping_path,
                serde_json::to_vec(&mapping).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(&secret_path, hex(&key)).map_err(|error| error.to_string())?;
            std::fs::write(&public_path, hex(signing.verifying_key().as_bytes()))
                .map_err(|error| error.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o644))
                    .map_err(|error| error.to_string())?;
            }
            let database_url = connection_string(&config)?;
            let bad = run_cli(
                &database_url,
                &bundle_path,
                &mapping_path,
                &secret_path,
                &public_path,
            )?;
            #[cfg(unix)]
            {
                if bad.status.code() != Some(65)
                    || String::from_utf8_lossy(&bad.stderr).trim()
                        != r#"{"code":"intelligence_import_key_file_permissions"}"#
                {
                    return Err(format!("公开 secret file 未被拒绝：{bad:?}"));
                }
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| error.to_string())?;
            }
            let output = run_cli(
                &database_url,
                &bundle_path,
                &mapping_path,
                &secret_path,
                &public_path,
            )?;
            if output.status.code() != Some(0) || !output.stderr.is_empty() {
                return Err(format!("import CLI 失败：{output:?}"));
            }
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
            if report
                != json!({
                    "bundleId":"bundle-cli-1",
                    "targetDeploymentId":"target-deployment",
                    "status":"completed",
                    "claimRequired":[],
                    "threadCount":0,
                    "messageCount":0,
                    "eventCount":0,
                    "memoryCount":0,
                    "cursor":"$none",
                })
            {
                return Err(format!("CLI report 漂移：{report}"));
            }
            let pool = pool::connect(&config)
                .await
                .map_err(|error| error.to_string())?;
            let row = pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT count(*)::bigint,
                            count(*) FILTER (WHERE status='completed' AND cursor='$none')::bigint
                     FROM public.intelligence_import_cursors WHERE bundle_id='bundle-cli-1'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let shape: (i64, i64) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
            );
            pool.close();
            if shape != (4, 4) {
                return Err(format!("empty bundle cursor 漂移：{shape:?}"));
            }
            let finalized = run_finalize_cli(&database_url)?;
            if finalized.status.code() != Some(0) || !finalized.stderr.is_empty() {
                return Err(format!("FK finalize CLI 失败：{finalized:?}"));
            }
            let report: serde_json::Value =
                serde_json::from_slice(&finalized.stdout).map_err(|error| error.to_string())?;
            if report
                != json!({
                    "incompleteBundleCount":0,
                    "orphanToolCallCount":0,
                    "validated":true,
                })
            {
                return Err(format!("FK finalize report 漂移：{report}"));
            }
            Ok(())
        }
        .await;
        for name in ["bundle.json", "mapping.json", "decrypt.hex", "verify.hex"] {
            let _ = std::fs::remove_file(directory.join(name));
        }
        let _ = std::fs::remove_dir(directory);
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL: set OPENBOT_TEST_DATABASE_URL and run with --include-ignored"]
async fn migrate_schema_cli_brings_an_empty_database_to_latest_idempotently() {
    let admin = admin_config("migrate_schema_cli_brings_an_empty_database_to_latest_idempotently");
    with_temp_database(&admin, "migrate_schema_cli", |config| async move {
        let database_url = connection_string(&config)?;
        for run in ["first", "second"] {
            let output = Command::new(env!("CARGO_BIN_EXE_openbot-migrate"))
                .env_clear()
                .env("DATABASE_URL", &database_url)
                .arg("migrate-schema")
                .output()
                .map_err(|error| error.to_string())?;
            if output.status.code() != Some(0)
                || !output.stderr.is_empty()
                || String::from_utf8_lossy(&output.stdout).trim()
                    != r#"{"code":"migration_completed"}"#
            {
                return Err(format!("{run} migrate-schema run failed: {output:?}"));
            }
        }
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let version: i32 = client
            .query_one(
                "SELECT max(version) FROM openbot_internal.schema_migrations",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        let validated: bool = client
            .query_one(
                "SELECT convalidated FROM pg_constraint
                 WHERE conrelid='public.tool_calls'::regclass AND conname='tool_calls_run_id_fkey'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        drop(client);
        pool.close();
        if version != openbot_infra::db::native::NATIVE_LATEST_VERSION || validated {
            return Err(format!(
                "ledger {version} or tool_calls_run_id_fkey validated={validated}"
            ));
        }
        Ok(())
    })
    .await;
}

fn run_cli(
    database_url: &str,
    bundle: &std::path::Path,
    mapping: &std::path::Path,
    secret: &std::path::Path,
    public: &std::path::Path,
) -> Result<std::process::Output, String> {
    Command::new(env!("CARGO_BIN_EXE_openbot-migrate"))
        .env_clear()
        .env("DATABASE_URL", database_url)
        .args([
            "intelligence-import",
            "--bundle",
            bundle.to_str().ok_or("bundle path")?,
            "--mapping",
            mapping.to_str().ok_or("mapping path")?,
            "--decryption-key-file",
            secret.to_str().ok_or("secret path")?,
            "--verification-key-file",
            public.to_str().ok_or("public path")?,
            "--signing-key-id",
            "key-cli-1",
        ])
        .output()
        .map_err(|error| error.to_string())
}

fn run_finalize_cli(database_url: &str) -> Result<std::process::Output, String> {
    Command::new(env!("CARGO_BIN_EXE_openbot-migrate"))
        .env_clear()
        .env("DATABASE_URL", database_url)
        .arg("intelligence-validate-tool-run-fk")
        .output()
        .map_err(|error| error.to_string())
}

fn independently_seal(
    payload: &IntelligenceBundlePayload,
    key: &[u8; 32],
    signing: &SigningKey,
) -> Result<Vec<u8>, String> {
    let plaintext = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
    let hash: [u8; 32] = Sha256::digest(&plaintext).into();
    let nonce = [7_u8; 12];
    let aad = framed([
        INTELLIGENCE_BUNDLE_FORMAT.as_bytes(),
        payload.bundle_id.as_bytes(),
        payload.source_deployment_id.as_bytes(),
        b"key-cli-1",
        &hash,
    ])?;
    let mut derived = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&hash), key)
        .expand(&aad, &mut derived)
        .map_err(|_| "hkdf".to_owned())?;
    let ciphertext = Aes256Gcm::new_from_slice(&derived)
        .map_err(|error| error.to_string())?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "encrypt".to_owned())?;
    let signed = framed([
        INTELLIGENCE_BUNDLE_FORMAT.as_bytes(),
        payload.bundle_id.as_bytes(),
        payload.source_deployment_id.as_bytes(),
        b"key-cli-1",
        &hash,
        &nonce,
        &ciphertext,
    ])?;
    serde_json::to_vec(&IntelligenceBundleEnvelope {
        format: INTELLIGENCE_BUNDLE_FORMAT.to_owned(),
        bundle_id: payload.bundle_id.clone(),
        source_deployment_id: payload.source_deployment_id.clone(),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
        payload_sha256: hex(&hash),
        signing_key_id: "key-cli-1".to_owned(),
        signature: BASE64.encode(signing.sign(&signed).to_bytes()),
    })
    .map_err(|error| error.to_string())
}

fn framed<const N: usize>(fields: [&[u8]; N]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    for field in fields {
        output.extend(
            u64::try_from(field.len())
                .map_err(|error| error.to_string())?
                .to_be_bytes(),
        );
        output.extend(field);
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn connection_string(config: &pool::DatabaseConfig) -> Result<String, String> {
    let config = config.to_pg_config();
    let host = config
        .get_hosts()
        .first()
        .and_then(|host| match host {
            tokio_postgres::config::Host::Tcp(host) => Some(host.as_str()),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(_) => None,
        })
        .ok_or("tcp host")?;
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let user = config.get_user().ok_or("user")?;
    let dbname = config.get_dbname().ok_or("dbname")?;
    let password = config
        .get_password()
        .and_then(|value| core::str::from_utf8(value).ok())
        .unwrap_or("");
    Ok(format!(
        "host={host} port={port} user={user} password={password} dbname={dbname}"
    ))
}
