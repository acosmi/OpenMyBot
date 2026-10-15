//! OpenBot PostgreSQL/cutover migration binary；不进入最终 runtime request path。

use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_application::tenant::package::TenantPackageEnvironment;
use openbot_application::{
    IntelligenceImportError, import_intelligence_bundle, validate_intelligence_tool_run_fk,
};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::intelligence::IntelligenceImportMapping;
use openbot_domain::vault::{ApplicationKeyPurpose, SecretBytes, derive_application_key};
use openbot_infra::auth::config::{ExampleKeyPolicy, KeyEncryptionKey};
use openbot_infra::db::pool;
use openbot_infra::db::pool::DatabaseConfig;
use openbot_infra::intelligence_bundle::{
    IntelligenceBundleDecryptionKey, IntelligenceBundleVerificationKey,
    MAX_INTELLIGENCE_BUNDLE_BYTES, verify_intelligence_bundle,
};
use openbot_infra::intelligence_import::PostgresIntelligenceImportStore;
use openbot_infra::tenant::load_tenant_package;
use openbot_infra::thread_history_authority::{
    PostgresThreadHistoryAuthority, ThreadHistoryClearProgress, ThreadHistoryStopClearError,
};
use openbot_server::config::{
    DEFAULT_TENANT_PACKAGE_DIR, DeploymentEnvironment, ServerConfig, env_map_from_process,
    preflight_audit_retention,
};

const ACTION_REQUIRED_EXIT: u8 = 2;
const USAGE_EXIT: u8 = 64;
const DATA_EXIT: u8 = 65;
const UNAVAILABLE_EXIT: u8 = 69;
const SOFTWARE_EXIT: u8 = 70;
const TEMPORARY_EXIT: u8 = 75;
const MAX_MAPPING_BYTES: usize = 8 * 1024 * 1024;
const MAX_KEY_FILE_BYTES: usize = 1024;
const CLEAR_CALLS: usize = 3;
const CLEAR_BUDGET: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|value| value == "thread-history-clear-deleted")
    {
        return match parse_clear_thread(&arguments) {
            Ok(thread) => match run_clear_deleted(thread).await {
                Ok(progress) => {
                    println!("{progress}");
                    if progress == "thread_history_clear_completed" {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(TEMPORARY_EXIT)
                    }
                }
                Err(failure) => fail(failure.code, failure.exit),
            },
            Err(failure) => fail(failure.code, failure.exit),
        };
    }
    if arguments.len() == 1 && arguments[0] == "preflight-audit-retention" {
        return run_audit_preflight();
    }
    if arguments.len() == 1 && arguments[0] == "intelligence-validate-tool-run-fk" {
        return match run_tool_run_fk_validation().await {
            Ok(report) => {
                let rendered = match serde_json::to_string_pretty(&report) {
                    Ok(rendered) => rendered,
                    Err(_) => {
                        return fail("intelligence_import_serialization_failed", SOFTWARE_EXIT);
                    }
                };
                println!("{rendered}");
                if report.requires_action() {
                    ExitCode::from(ACTION_REQUIRED_EXIT)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(failure) => fail(failure.code, failure.exit),
        };
    }
    if arguments
        .first()
        .is_some_and(|value| value == "intelligence-import")
    {
        let result = match parse_import_arguments(&arguments) {
            Ok(arguments) => run_import_files(arguments).await,
            Err(error) => Err(error),
        };
        return match result {
            Ok(report) => {
                let rendered = match serde_json::to_string_pretty(&report) {
                    Ok(rendered) => rendered,
                    Err(_) => {
                        return fail("intelligence_import_serialization_failed", SOFTWARE_EXIT);
                    }
                };
                println!("{rendered}");
                if report.requires_action() {
                    ExitCode::from(ACTION_REQUIRED_EXIT)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(failure) => fail(failure.code, failure.exit),
        };
    }
    fail("migration_preflight_usage", USAGE_EXIT)
}

fn parse_clear_thread(arguments: &[OsString]) -> Result<&str, MigrationFailure> {
    let [command, thread] = arguments else {
        return Err(MigrationFailure {
            code: "thread_history_clear_usage",
            exit: USAGE_EXIT,
        });
    };
    if command != "thread-history-clear-deleted" {
        return Err(MigrationFailure {
            code: "thread_history_clear_usage",
            exit: USAGE_EXIT,
        });
    }
    let thread = thread
        .to_str()
        .ok_or_else(|| MigrationFailure::data("thread_history_clear_invalid_thread"))?;
    if thread.len() != 36
        || !ThreadIdentity::is_plausible(&openbot_contracts::ids::ThreadId::new(thread))
    {
        return Err(MigrationFailure::data(
            "thread_history_clear_invalid_thread",
        ));
    }
    Ok(thread)
}

async fn run_clear_deleted(thread: &str) -> Result<&'static str, MigrationFailure> {
    // Use the deployed host's existing namespace and domain-separated audit key. Neither is
    // inferred from a target database row, supplied as a new permission, or randomly generated.
    let environment =
        openbot_server::config::launch::prepare_environment(env_map_from_process(), false)
            .map_err(|_| MigrationFailure::data("thread_history_clear_environment_invalid"))?;
    let server = ServerConfig::from_env_map(&environment)
        .map_err(|_| MigrationFailure::data("thread_history_clear_environment_invalid"))?;
    let mut directory = PathBuf::from(&server.tenant_package_directory);
    if !directory.is_dir() && server.tenant_package_directory == DEFAULT_TENANT_PACKAGE_DIR {
        let workspace_default = PathBuf::from("examples/fintech");
        if workspace_default.is_dir() {
            directory = workspace_default;
        }
    }
    let package_environment =
        TenantPackageEnvironment::from_allowlist(&environment, &["MANAGED_AGENT_AG_UI_URL"]);
    let package = load_tenant_package(&directory, &package_environment)
        .map_err(|_| MigrationFailure::data("thread_history_clear_package_invalid"))?;
    let tenant = TenantId::new(&package.package.tenant_id);
    let deployment = DeploymentId::new(server.deployment_id.as_deref().unwrap_or(tenant.as_str()));
    let key_policy = match server.deployment_environment {
        DeploymentEnvironment::Production => ExampleKeyPolicy::Reject,
        DeploymentEnvironment::Development => ExampleKeyPolicy::Allow,
    };
    let _validated_master = KeyEncryptionKey::from_env_map(&environment, key_policy)
        .map_err(|_| MigrationFailure::data("thread_history_clear_key_invalid"))?;
    let master = openbot_server::config::env::optional(&environment, "KEY_ENCRYPTION_KEY")
        .ok_or_else(|| MigrationFailure::unavailable("thread_history_clear_key_missing"))?;
    let checkpoint_key = derive_application_key(
        &SecretBytes::new(master.as_bytes().to_vec()),
        ApplicationKeyPurpose::AuditCheckpoint,
    )
    .map_err(|_| MigrationFailure::data("thread_history_clear_key_invalid"))?;
    let database_url = openbot_server::config::env::optional(&environment, "DATABASE_URL")
        .ok_or_else(|| MigrationFailure::unavailable("database_url_missing"))?;
    let database: DatabaseConfig = database_url
        .parse()
        .map_err(|_| MigrationFailure::data("database_url_invalid"))?;
    let pool = pool::connect(&database)
        .await
        .map_err(|_| MigrationFailure::unavailable("database_unavailable"))?;
    let result = async {
        openbot_server::database::initialize(&pool)
            .await
            .map_err(|_| MigrationFailure::unavailable("database_initialization_failed"))?;
        let authority = Arc::new(
            PostgresThreadHistoryAuthority::new(pool.clone(), deployment, tenant)
                .map_err(|_| MigrationFailure::data("thread_history_clear_namespace_invalid"))?,
        );
        authority
            .enroll_clear_audit_checkpoint_key(checkpoint_key)
            .map_err(|_| MigrationFailure::unavailable("thread_history_clear_audit_unavailable"))?;
        let deadline = Instant::now().checked_add(CLEAR_BUDGET).ok_or_else(|| {
            MigrationFailure::unavailable("thread_history_clear_deadline_invalid")
        })?;
        authority
            .close_deleted_history_before(thread, deadline)
            .await
            .map_err(MigrationFailure::from_clear)?;
        let drain = authority
            .drain_closed_history_runs_before(thread, deadline)
            .await
            .map_err(MigrationFailure::from_clear)?;
        if !drain.is_complete() {
            return Ok("thread_history_clear_awaiting_drain");
        }
        for _ in 0..CLEAR_CALLS {
            match authority
                .clear_closed_history_before(thread, deadline)
                .await
                .map_err(MigrationFailure::from_clear)?
            {
                ThreadHistoryClearProgress::Completed { .. } => {
                    return Ok("thread_history_clear_completed");
                }
                ThreadHistoryClearProgress::AwaitingDrain => {
                    return Ok("thread_history_clear_awaiting_drain");
                }
                ThreadHistoryClearProgress::AwaitingReaders => {
                    return Ok("thread_history_clear_awaiting_readers");
                }
                ThreadHistoryClearProgress::BatchCommitted { .. } => {}
            }
        }
        Ok("thread_history_clear_batch_budget_exhausted")
    }
    .await;
    pool.close();
    result
}

fn run_audit_preflight() -> ExitCode {
    let report = preflight_audit_retention(&env_map_from_process());
    let rendered = match serde_json::to_string_pretty(&report) {
        Ok(rendered) => rendered,
        Err(_) => return fail("migration_preflight_serialization_failed", SOFTWARE_EXIT),
    };
    println!("{rendered}");
    if report.requires_action() {
        ExitCode::from(ACTION_REQUIRED_EXIT)
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Debug)]
struct IntelligenceImportArguments {
    bundle: PathBuf,
    mapping: PathBuf,
    decryption_key: PathBuf,
    verification_key: PathBuf,
    signing_key_id: String,
}

fn parse_import_arguments(
    arguments: &[OsString],
) -> Result<IntelligenceImportArguments, MigrationFailure> {
    if arguments.len() != 11 {
        return Err(MigrationFailure::usage());
    }
    let mut bundle = None;
    let mut mapping = None;
    let mut decryption_key = None;
    let mut verification_key = None;
    let mut signing_key_id = None;
    let (pairs, remainder) = arguments[1..].as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(MigrationFailure::usage());
    }
    for pair in pairs {
        let flag = pair[0].to_str().ok_or_else(MigrationFailure::usage)?;
        match flag {
            "--bundle" if bundle.is_none() => bundle = Some(PathBuf::from(&pair[1])),
            "--mapping" if mapping.is_none() => mapping = Some(PathBuf::from(&pair[1])),
            "--decryption-key-file" if decryption_key.is_none() => {
                decryption_key = Some(PathBuf::from(&pair[1]));
            }
            "--verification-key-file" if verification_key.is_none() => {
                verification_key = Some(PathBuf::from(&pair[1]));
            }
            "--signing-key-id" if signing_key_id.is_none() => {
                signing_key_id = Some(
                    pair[1]
                        .to_str()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(MigrationFailure::usage)?
                        .to_owned(),
                );
            }
            _ => return Err(MigrationFailure::usage()),
        }
    }
    Ok(IntelligenceImportArguments {
        bundle: bundle.ok_or_else(MigrationFailure::usage)?,
        mapping: mapping.ok_or_else(MigrationFailure::usage)?,
        decryption_key: decryption_key.ok_or_else(MigrationFailure::usage)?,
        verification_key: verification_key.ok_or_else(MigrationFailure::usage)?,
        signing_key_id: signing_key_id.ok_or_else(MigrationFailure::usage)?,
    })
}

async fn run_import_files(
    arguments: IntelligenceImportArguments,
) -> Result<openbot_application::IntelligenceImportReport, MigrationFailure> {
    let bundle = read_bounded(&arguments.bundle, MAX_INTELLIGENCE_BUNDLE_BYTES, false)?;
    let mapping_bytes = read_bounded(&arguments.mapping, MAX_MAPPING_BYTES, false)?;
    let encoded_secret = SecretBytes::new(read_bounded(
        &arguments.decryption_key,
        MAX_KEY_FILE_BYTES,
        true,
    )?);
    let decryption_key =
        IntelligenceBundleDecryptionKey::from_bytes(decode_hex_key(encoded_secret.expose())?)
            .map_err(MigrationFailure::from_import)?;
    let verification_bytes = read_bounded(&arguments.verification_key, MAX_KEY_FILE_BYTES, false)?;
    let verification_key = IntelligenceBundleVerificationKey::from_bytes(
        arguments.signing_key_id,
        &decode_hex_key(&verification_bytes)?,
    )
    .map_err(MigrationFailure::from_import)?;
    let verified = verify_intelligence_bundle(&bundle, &decryption_key, &verification_key)
        .map_err(MigrationFailure::from_import)?;
    let mapping: IntelligenceImportMapping = serde_json::from_slice(&mapping_bytes)
        .map_err(|_| MigrationFailure::data("intelligence_import_mapping_invalid"))?;
    let pool = connect_migration_database().await?;
    let store = PostgresIntelligenceImportStore::new(pool.clone());
    let result = import_intelligence_bundle(&store, verified, mapping)
        .await
        .map_err(MigrationFailure::from_import);
    pool.close();
    result
}

async fn run_tool_run_fk_validation()
-> Result<openbot_application::IntelligenceToolRunFkReport, MigrationFailure> {
    let pool = connect_migration_database().await?;
    let store = PostgresIntelligenceImportStore::new(pool.clone());
    let result = validate_intelligence_tool_run_fk(&store)
        .await
        .map_err(MigrationFailure::from_import);
    pool.close();
    result
}

async fn connect_migration_database()
-> Result<openbot_infra::db::pool::DatabasePool, MigrationFailure> {
    let database_url = std::env::var_os("DATABASE_URL")
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MigrationFailure::unavailable("database_url_missing"))?;
    let database: DatabaseConfig = database_url
        .parse()
        .map_err(|_| MigrationFailure::data("database_url_invalid"))?;
    let pool = pool::connect(&database)
        .await
        .map_err(|_| MigrationFailure::unavailable("database_unavailable"))?;
    if openbot_server::database::initialize(&pool).await.is_err() {
        pool.close();
        return Err(MigrationFailure::unavailable(
            "database_initialization_failed",
        ));
    }
    Ok(pool)
}

fn read_bounded(
    path: &Path,
    maximum: usize,
    require_private_permissions: bool,
) -> Result<Vec<u8>, MigrationFailure> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| MigrationFailure::data("intelligence_import_file_invalid"))?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(MigrationFailure::data("intelligence_import_file_invalid"));
    }
    let file = std::fs::File::open(path)
        .map_err(|_| MigrationFailure::data("intelligence_import_file_invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| MigrationFailure::data("intelligence_import_file_invalid"))?;
    if !metadata.is_file() {
        return Err(MigrationFailure::data("intelligence_import_file_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            return Err(MigrationFailure::data("intelligence_import_file_changed"));
        }
        if require_private_permissions && metadata.mode() & 0o077 != 0 {
            return Err(MigrationFailure::data(
                "intelligence_import_key_file_permissions",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = require_private_permissions;
    let length = metadata.len();
    if length == 0
        || usize::try_from(length)
            .ok()
            .is_none_or(|value| value > maximum)
    {
        return Err(MigrationFailure::data("intelligence_import_file_size"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(maximum));
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| MigrationFailure::data("intelligence_import_file_invalid"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(MigrationFailure::data("intelligence_import_file_size"));
    }
    Ok(bytes)
}

fn decode_hex_key(input: &[u8]) -> Result<Vec<u8>, MigrationFailure> {
    let input = input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input);
    if input.len() != 64
        || !input
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(MigrationFailure::data(
            "intelligence_import_key_file_invalid",
        ));
    }
    input
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .map_err(|_| MigrationFailure::data("intelligence_import_key_file_invalid"))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct MigrationFailure {
    code: &'static str,
    exit: u8,
}

impl MigrationFailure {
    const fn from_clear(error: ThreadHistoryStopClearError) -> Self {
        match error {
            ThreadHistoryStopClearError::InvalidInput { .. }
            | ThreadHistoryStopClearError::NotVisible
            | ThreadHistoryStopClearError::Conflict
            | ThreadHistoryStopClearError::Corrupt { .. } => {
                Self::data("thread_history_clear_refused")
            }
            ThreadHistoryStopClearError::Unavailable
            | ThreadHistoryStopClearError::BeginUnavailable => {
                Self::unavailable("thread_history_clear_unavailable")
            }
            ThreadHistoryStopClearError::DeadlineExceeded
            | ThreadHistoryStopClearError::CommitUnknown
            | ThreadHistoryStopClearError::RollbackUnproven
            | ThreadHistoryStopClearError::CommitAcknowledgedAfterDeadline
            | ThreadHistoryStopClearError::RollbackAcknowledgedAfterDeadline => Self {
                code: "thread_history_clear_transaction_unproven_or_late",
                exit: TEMPORARY_EXIT,
            },
            ThreadHistoryStopClearError::Host(_) | ThreadHistoryStopClearError::AlreadyStarted => {
                Self {
                    code: "thread_history_clear_internal_binding_failed",
                    exit: SOFTWARE_EXIT,
                }
            }
        }
    }

    const fn usage() -> Self {
        Self {
            code: "intelligence_import_usage",
            exit: USAGE_EXIT,
        }
    }

    const fn data(code: &'static str) -> Self {
        Self {
            code,
            exit: DATA_EXIT,
        }
    }

    const fn unavailable(code: &'static str) -> Self {
        Self {
            code,
            exit: UNAVAILABLE_EXIT,
        }
    }

    const fn from_import(error: IntelligenceImportError) -> Self {
        match error {
            IntelligenceImportError::Invalid { .. }
            | IntelligenceImportError::Conflict { .. }
            | IntelligenceImportError::Corrupt { .. } => Self::data("intelligence_import_invalid"),
            IntelligenceImportError::Unavailable => {
                Self::unavailable("intelligence_import_unavailable")
            }
            IntelligenceImportError::CommitUnknown => Self {
                code: "intelligence_import_commit_unknown",
                exit: TEMPORARY_EXIT,
            },
        }
    }
}

fn fail(code: &'static str, exit: u8) -> ExitCode {
    eprintln!(r#"{{"code":"{code}"}}"#);
    ExitCode::from(exit)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn clear_deleted_requires_exact_arity_and_plausible_thread_before_configuration() {
        let thread = ThreadIdentity::new(&DeploymentId::new("owned-cli-deployment"))
            .mint_from_entropy([9; 16]);
        let valid = [
            OsString::from("thread-history-clear-deleted"),
            OsString::from(thread.as_str()),
        ];
        assert_eq!(parse_clear_thread(&valid).unwrap(), thread.as_str());
        for args in [
            vec![],
            vec![valid[0].clone()],
            vec![valid[0].clone(), valid[1].clone(), OsString::from("extra")],
        ] {
            assert_eq!(parse_clear_thread(&args).unwrap_err().exit, USAGE_EXIT);
        }
        for invalid in [
            "",
            "other-thread",
            "00000000-0000-0000-0000-00000000000z",
            " 00000000-0000-0000-0000-000000000000",
        ] {
            let args = [valid[0].clone(), OsString::from(invalid)];
            assert_eq!(parse_clear_thread(&args).unwrap_err().exit, DATA_EXIT);
        }
    }

    #[test]
    fn key_file_hex_is_exact_lowercase_with_at_most_one_line_ending() {
        let raw = b"00".repeat(32);
        assert_eq!(decode_hex_key(&raw).unwrap(), vec![0; 32]);
        let mut newline = raw.clone();
        newline.push(b'\n');
        assert_eq!(decode_hex_key(&newline).unwrap(), vec![0; 32]);
        assert!(decode_hex_key(&b"AA".repeat(32)).is_err());
        assert!(decode_hex_key(&[raw, b"\n\n".to_vec()].concat()).is_err());
    }

    #[test]
    fn duplicate_or_incomplete_import_flags_are_usage_errors() {
        let args = [
            "intelligence-import",
            "--bundle",
            "a",
            "--bundle",
            "b",
            "--mapping",
            "m",
            "--decryption-key-file",
            "d",
            "--verification-key-file",
            "v",
        ]
        .map(OsString::from);
        assert_eq!(parse_import_arguments(&args).unwrap_err().exit, USAGE_EXIT);
        assert_eq!(
            parse_import_arguments(&[OsString::from("intelligence-import")])
                .unwrap_err()
                .exit,
            USAGE_EXIT
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_file_must_be_the_same_regular_inode_and_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!(
            "openbot-intelligence-key-{}.txt",
            uuid::Uuid::now_v7()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&b"00".repeat(32)).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_bounded(&path, MAX_KEY_FILE_BYTES, true)
                .unwrap_err()
                .code,
            "intelligence_import_key_file_permissions"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_bounded(&path, MAX_KEY_FILE_BYTES, true).unwrap(),
            b"00".repeat(32)
        );
        std::fs::remove_file(path).unwrap();
    }
}
