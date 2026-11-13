//! `cargo xtask release root`: assemble one Desktop release resource root and its outer digest.
//!
//! The manifest is the launcher's existing closed schema 3; this command adds no field. Inputs are
//! loaded and checked against the launcher's inventory bounds (spec revision R485)
//! before anything is written. The launcher's own `--check-release` remains the authority on the
//! result; `--check-with` runs it against the new root and records the outcome.
//!
//! Output layout under `--out` (which must not exist yet):
//! - `resources/`: the release root (`--resource-root`, or `Contents/Resources` in the app);
//! - `release-root-record.json`: outer digest, launcher build environment and optional check.
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

use crate::checked_input;

// Fixed product values of `crates/openbot-desktop/src/desktop_release.rs`.
const PRODUCT_NAME: &str = "Wrok Bot";
const BUNDLE_IDENTIFIER: &str = "com.acosmi.wrokbot";
const PROTOCOL_SCHEME: &str = "wrokbot";
const MAIN_WINDOW: &str = "main";
const POSTGRES_KEY_STORE_SERVICE: &str = "com.acosmi.wrokbot.postgresql";
const VAULT_KEY_STORE_SERVICE: &str = "com.acosmi.wrokbot.vault";
const RELEASE_MANIFEST_FILE: &str = "wrok-bot-release.json";
const MAINTENANCE_OUTER_FILE: &str = "wrokbot-pg-maintenance-release.json";
const POSTGRES_MANIFEST_FILE: &str = "manifest.json";
const RECORD_FILE: &str = "release-root-record.json";

// Launcher inventory bounds for the outer manifest and the UI and tenant trees.
const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
const TENANT_FILE_MAX_BYTES: u64 = 1024 * 1024;
const TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const TREE_MAX_ENTRIES: usize = 8192;
const PATH_MAX_BYTES: usize = 512;

const OPTIONS: [&str; 11] = [
    "mode",
    "ui",
    "tenant",
    "postgres",
    "maintenance",
    "provider",
    "agent-budgets",
    "recovery-control",
    "normal-capture",
    "out",
    "check-with",
];

#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    schema_version: u32,
    product_name: &'static str,
    bundle_identifier: &'static str,
    scheme: &'static str,
    window_label: &'static str,
    core_version: &'static str,
    release_epoch: u64,
    platform: &'static str,
    arch: &'static str,
    ui: ResourceTree,
    tenant: ResourceTree,
    postgres: PostgresResource,
    vault_key_store_service: &'static str,
    provider: ProviderInput,
    agent_budgets: AgentBudgets,
    normal_capture: Option<CaptureRequest>,
    recovery_control: RecoveryControl,
}

#[derive(Serialize)]
struct ResourceTree {
    root: &'static str,
    files: Vec<ResourceFile>,
}

#[derive(Serialize)]
struct ResourceFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct PostgresResource {
    root: &'static str,
    manifest_sha256: String,
    signing_identity: String,
    key_store_service: &'static str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderInput {
    base_url: String,
    egress_allow_cidrs: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentBudgets {
    stall_timeout_ms: Option<u64>,
    run_deadline_ms: Option<u64>,
    max_output_tokens: u32,
}

/// Top-level keys are closed here; nested values pass through to the launcher's typed check.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecoveryControl {
    version: u32,
    host_limits: Value,
    ordinary_startup_bounds: Value,
}

/// Passed through unchanged. It binds destinations by device, inode and uid of this machine.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureRequest {
    request_id: Value,
    trigger: Value,
    profile: Value,
    maintenance_outer_sha256: Value,
    maintenance_root: Value,
    output_root: Value,
    independent_key_medium: Value,
}

/// The recorded signer of a PostgreSQL bundle; `-` marks an ad-hoc signature.
#[derive(Deserialize)]
struct BundleIdentity {
    signing_identity: Option<String>,
}

#[derive(Serialize)]
struct Record {
    mode: &'static str,
    release_root: PathBuf,
    manifest_sha256: String,
    launcher_build_env: BTreeMap<&'static str, String>,
    normal_capture: &'static str,
    check_release: Option<CheckRelease>,
}

#[derive(Serialize)]
struct CheckRelease {
    launcher: PathBuf,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Loaded tree: relative path to (bytes, executable).
type Tree = BTreeMap<String, (Vec<u8>, bool)>;

pub(super) fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let mut options = BTreeMap::new();
    for pair in args.chunks(2) {
        let [key, value] = pair else {
            bail!("release_root_option_value_required: {}", pair[0]);
        };
        let name = key
            .strip_prefix("--")
            .filter(|name| OPTIONS.contains(name))
            .ok_or_else(|| anyhow!("release_root_option_unknown: {key}"))?;
        if value.is_empty() || options.insert(name, PathBuf::from(value)).is_some() {
            bail!("release_root_option_duplicate_or_empty: {key}");
        }
    }
    let option = |name: &str| {
        options
            .get(name)
            .ok_or_else(|| anyhow!("release_root_option_missing: --{name}"))
    };
    let json_input = |name: &str| -> Result<Option<Vec<u8>>> {
        options
            .get(name)
            .map(|path| {
                checked_input::read_argument(path, MANIFEST_MAX_BYTES)
                    .map_err(|error| anyhow!("release_root_input_unreadable: --{name}: {error:?}"))
            })
            .transpose()
    };
    fn parse<T: for<'de> Deserialize<'de>>(name: &str, bytes: &[u8]) -> Result<T> {
        checked_input::json(bytes).with_context(|| format!("release_root_json_invalid: --{name}"))
    }

    // Everything is loaded and checked before the first write.
    let release = match option("mode")?.to_str() {
        Some("release") => true,
        Some("development") => false,
        _ => bail!("release_root_mode_invalid: expected development or release"),
    };
    let ui = load_tree(option("ui")?, Some(ui_file_limit))?;
    let tenant = load_tree(option("tenant")?, Some(|_: &str| TENANT_FILE_MAX_BYTES))?;
    let postgres = load_tree(option("postgres")?, None)?;
    let maintenance = options
        .get("maintenance")
        .map(|path| load_tree(path, None))
        .transpose()?;
    let required = |name: &str| -> Result<Vec<u8>> {
        json_input(name)?.ok_or_else(|| anyhow!("release_root_option_missing: --{name}"))
    };
    let provider: ProviderInput = parse("provider", &required("provider")?)?;
    let agent_budgets: AgentBudgets = parse("agent-budgets", &required("agent-budgets")?)?;
    // A release declares both run budgets; without them the SDK gateway is not assembled.
    if release
        && (agent_budgets.stall_timeout_ms.is_none() || agent_budgets.run_deadline_ms.is_none())
    {
        bail!(
            "release_root_agent_budgets_refused: release mode requires stall_timeout_ms and run_deadline_ms"
        );
    }
    let recovery_control: RecoveryControl =
        parse("recovery-control", &required("recovery-control")?)?;
    let normal_capture: Option<CaptureRequest> = json_input("normal-capture")?
        .map(|bytes| parse("normal-capture", &bytes))
        .transpose()?;
    let out = option("out")?;
    let launcher = options.get("check-with");

    let (postgres_manifest, _) = postgres
        .get(POSTGRES_MANIFEST_FILE)
        .context("release_root_postgres_manifest_missing")?;
    let signing_identity = serde_json::from_slice::<BundleIdentity>(postgres_manifest)
        .context("release_root_postgres_manifest_invalid")?
        .signing_identity
        .context("release_root_postgres_manifest_invalid")?;
    // An ad-hoc signed bundle may serve a development root only, never a release root.
    let maintenance_identity = maintenance
        .as_ref()
        .and_then(|tree| tree.get("postgres-maintenance/manifest.json"))
        .map(|(bytes, _)| serde_json::from_slice::<BundleIdentity>(bytes))
        .transpose()
        .context("release_root_maintenance_manifest_invalid")?
        .and_then(|identity| identity.signing_identity);
    if release && (signing_identity == "-" || maintenance_identity.as_deref() == Some("-")) {
        bail!("release_root_ad_hoc_signature_refused: release mode requires a signing identity");
    }
    let engine = fs::read_to_string(workspace.join("crates/openbot-contracts/src/engine.rs"))
        .context("release_root_epoch_source_unreadable")?;
    let release_epoch =
        regex::Regex::new(r"(?m)^pub const ENGINE_RELEASE_EPOCH: u64 = ([0-9]+);$")?
            .captures(&engine)
            .context("release_root_epoch_missing")?[1]
            .parse()?;
    let host_bound = normal_capture.is_some();
    let manifest = Manifest {
        schema: "wrok-bot-desktop-release",
        schema_version: 3,
        product_name: PRODUCT_NAME,
        bundle_identifier: BUNDLE_IDENTIFIER,
        scheme: PROTOCOL_SCHEME,
        window_label: MAIN_WINDOW,
        // The launcher compares this with its own package version; both use the workspace version.
        core_version: env!("CARGO_PKG_VERSION"),
        release_epoch,
        platform: "macos",
        arch: std::env::consts::ARCH,
        ui: ResourceTree {
            root: "ui",
            files: inventory(&ui),
        },
        tenant: ResourceTree {
            root: "tenant",
            files: inventory(&tenant),
        },
        postgres: PostgresResource {
            root: "postgres",
            manifest_sha256: sha256(postgres_manifest),
            signing_identity,
            key_store_service: POSTGRES_KEY_STORE_SERVICE,
        },
        vault_key_store_service: VAULT_KEY_STORE_SERVICE,
        provider,
        agent_budgets,
        normal_capture,
        recovery_control,
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    if manifest_bytes.len() as u64 > MANIFEST_MAX_BYTES {
        bail!("release_root_manifest_too_large");
    }

    fs::create_dir(out).with_context(|| {
        format!(
            "release_root_out_not_created (it must not exist): {}",
            out.display()
        )
    })?;
    let resources = out.join("resources");
    let mut trees = vec![("ui", &ui), ("tenant", &tenant), ("postgres", &postgres)];
    if let Some(maintenance) = &maintenance {
        trees.push(("maintenance", maintenance));
    }
    for (name, tree) in trees {
        for (relative, (bytes, executable)) in tree {
            let path = resources.join(name).join(relative);
            fs::create_dir_all(path.parent().context("release_root_path_invalid")?)?;
            fs::write(&path, bytes)?;
            // Programs keep 0755 and everything else is 0644, as the maintenance bundle requires.
            let mode = if *executable { 0o755 } else { 0o644 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        }
    }
    let manifest_path = resources.join(RELEASE_MANIFEST_FILE);
    fs::write(&manifest_path, &manifest_bytes)?;
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644))?;
    for entry in WalkDir::new(out) {
        let entry = entry?;
        if entry.file_type().is_dir() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o755))?;
        }
    }

    // The launcher requires the canonical absolute root.
    let release_root = fs::canonicalize(&resources)?;
    let manifest_sha256 = sha256(&manifest_bytes);
    let mut launcher_build_env =
        BTreeMap::from([("WROK_BOT_DESKTOP_RELEASE_SHA256", manifest_sha256.clone())]);
    if let Some((outer, _)) = maintenance
        .as_ref()
        .and_then(|tree| tree.get(MAINTENANCE_OUTER_FILE))
    {
        launcher_build_env.insert("WROK_BOT_PG_MAINTENANCE_BUNDLE_SHA256", sha256(outer));
    }
    let check_release = launcher
        .map(|launcher| -> Result<CheckRelease> {
            let output = Command::new(launcher)
                .arg("--resource-root")
                .arg(&release_root)
                .arg("--check-release")
                .output()
                .with_context(|| {
                    format!("release_root_check_not_started: {}", launcher.display())
                })?;
            Ok(CheckRelease {
                launcher: launcher.clone(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            })
        })
        .transpose()?;
    let check_failed = check_release
        .as_ref()
        .is_some_and(|check| check.exit_code != Some(0));
    let record = Record {
        mode: if release { "release" } else { "development" },
        release_root,
        manifest_sha256,
        launcher_build_env,
        normal_capture: if host_bound {
            "host_bound: binds this machine's output and key destinations by device, inode and uid; use this root only on this machine"
        } else {
            "null"
        },
        check_release,
    };
    let mut record_bytes = serde_json::to_vec_pretty(&record)?;
    record_bytes.push(b'\n');
    let record_path = out.join(RECORD_FILE);
    fs::write(&record_path, &record_bytes)?;
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o644))?;

    println!("release_root={}", record.release_root.display());
    println!("manifest_sha256={}", record.manifest_sha256);
    println!("record={}", record_path.display());
    if host_bound {
        eprintln!(
            "warning: normal_capture is host-bound; use this release root only on this machine"
        );
    }
    if let Some(check) = &record.check_release {
        println!(
            "check_release exit={:?} stdout={} stderr={}",
            check.exit_code, check.stdout, check.stderr
        );
    }
    if check_failed {
        bail!("release_root_check_failed");
    }
    Ok(())
}

fn ui_file_limit(relative: &str) -> u64 {
    if relative == "index.html" {
        1024 * 1024
    } else if Path::new(relative)
        .extension()
        .and_then(|value| value.to_str())
        == Some("wasm")
    {
        16 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    }
}

/// Loads one input tree of plain directories and regular files. `limit` selects the launcher's
/// inventory bounds (UI and tenant); the PostgreSQL trees are verified by their own manifests.
fn load_tree(source: &Path, limit: Option<fn(&str) -> u64>) -> Result<Tree> {
    if !fs::symlink_metadata(source)
        .with_context(|| format!("release_root_input_missing: {}", source.display()))?
        .is_dir()
    {
        bail!("release_root_input_not_directory: {}", source.display());
    }
    let mut files = Vec::new();
    let mut names = BTreeSet::new();
    let (mut entries, mut total) = (0_usize, 0_u64);
    for entry in WalkDir::new(source).min_depth(1) {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let relative = entry
            .path()
            .strip_prefix(source)?
            .to_str()
            .context("release_root_path_not_utf8")?
            .to_owned();
        if metadata.mode() & 0o7000 != 0 {
            bail!("release_root_input_mode_invalid: {relative}");
        }
        if !metadata.is_dir() && !metadata.is_file() {
            bail!("release_root_input_not_regular: {relative}");
        }
        entries += 1;
        if let Some(limit) = limit {
            if !valid_relative_path(&relative)
                || !names.insert(relative.to_ascii_lowercase())
                || (metadata.is_file() && metadata.len() > limit(&relative))
            {
                bail!("release_root_inventory_invalid: {relative}");
            }
            total += metadata.len();
        }
        if metadata.is_file() {
            files.push((relative, metadata.mode() & 0o111 != 0));
        }
    }
    if limit.is_some() && (files.is_empty() || entries > TREE_MAX_ENTRIES || total > TREE_MAX_BYTES)
    {
        bail!("release_root_inventory_limit: {}", source.display());
    }
    files
        .into_iter()
        .map(|(relative, executable)| {
            let bytes = fs::read(source.join(&relative))?;
            Ok((relative, (bytes, executable)))
        })
        .collect()
}

/// The launcher's relative path rule for the UI and tenant inventories.
fn valid_relative_path(value: &str) -> bool {
    value.len() <= PATH_MAX_BYTES
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

fn inventory(tree: &Tree) -> Vec<ResourceFile> {
    tree.iter()
        .map(|(path, (bytes, _))| ResourceFile {
            path: path.clone(),
            bytes: bytes.len() as u64,
            sha256: sha256(bytes),
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "xtask-release-root-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            path
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// A shape-only input set. The launcher would reject its PostgreSQL bundle; these tests cover
    /// the builder, and the launcher's `--check-release` is exercised against real trees.
    fn inputs(temp: &Temp) -> Vec<String> {
        temp.write("in/ui/index.html", b"<!doctype html>");
        temp.write("in/ui/openbot-bootstrap.mjs", b"export {};");
        temp.write("in/ui/fonts/a.woff2", b"font");
        for name in [
            "brand.yaml",
            "agents.yaml",
            "channels.yaml",
            "model.yaml",
            "knowledge.yaml",
        ] {
            temp.write(&format!("in/tenant/{name}"), name.as_bytes());
        }
        temp.write(
            "in/postgres/manifest.json",
            br#"{"schema":"openbot-postgres-sidecar-bundle","signing_identity":"unit"}"#,
        );
        let program = temp.write("in/postgres/bin/postgres", b"program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        temp.write("in/maintenance/wrokbot-pg-maintenance-release.json", b"{}");
        temp.write(
            "in/provider.json",
            br#"{"base_url":"https://api.example.invalid/v1/","egress_allow_cidrs":[]}"#,
        );
        temp.write(
            "in/budgets.json",
            br#"{"stall_timeout_ms":30000,"run_deadline_ms":300000,"max_output_tokens":4096}"#,
        );
        temp.write(
            "in/recovery.json",
            br#"{"version":1,"hostLimits":{"maxRequestBytes":65536},"ordinaryStartupBounds":{"effectNs":1,"convergenceNs":1}}"#,
        );
        let input = |name: &str| temp.0.join("in").join(name).display().to_string();
        [
            ("--ui", input("ui")),
            ("--tenant", input("tenant")),
            ("--postgres", input("postgres")),
            ("--maintenance", input("maintenance")),
            ("--provider", input("provider.json")),
            ("--agent-budgets", input("budgets.json")),
            ("--recovery-control", input("recovery.json")),
            ("--mode", "release".to_owned()),
        ]
        .into_iter()
        .flat_map(|(key, value)| [key.to_owned(), value])
        .collect()
    }

    fn build(args: &[String], out: &Path) -> Result<()> {
        let mut args = args.to_vec();
        args.extend(["--out".to_owned(), out.display().to_string()]);
        run(&workspace(), &args)
    }

    fn rejected(args: &[String], temp: &Temp, code: &str) {
        let out = temp.0.join("out-rejected");
        let error = format!("{:#}", build(args, &out).unwrap_err());
        assert!(error.contains(code), "{error}");
        assert!(!out.exists(), "{code}: nothing may be written");
    }

    #[test]
    fn root_is_deterministic_closed_and_normalized() {
        let temp = Temp::new();
        let args = inputs(&temp);
        build(&args, &temp.0.join("a")).unwrap();
        build(&args, &temp.0.join("b")).unwrap();
        let manifest_a = fs::read(temp.0.join("a/resources").join(RELEASE_MANIFEST_FILE)).unwrap();
        let manifest_b = fs::read(temp.0.join("b/resources").join(RELEASE_MANIFEST_FILE)).unwrap();
        assert_eq!(manifest_a, manifest_b);
        let record: Value =
            serde_json::from_slice(&fs::read(temp.0.join("a").join(RECORD_FILE)).unwrap()).unwrap();
        assert_eq!(record["manifest_sha256"], sha256(&manifest_a));
        assert_eq!(
            record["launcher_build_env"]["WROK_BOT_DESKTOP_RELEASE_SHA256"],
            sha256(&manifest_a)
        );
        assert_eq!(
            record["launcher_build_env"]["WROK_BOT_PG_MAINTENANCE_BUNDLE_SHA256"],
            sha256(b"{}")
        );
        assert_eq!(record["normal_capture"], "null");

        let manifest: Value = serde_json::from_slice(&manifest_a).unwrap();
        let keys: Vec<_> = manifest.as_object().unwrap().keys().cloned().collect();
        let mut expected = vec![
            "schema",
            "schema_version",
            "product_name",
            "bundle_identifier",
            "scheme",
            "window_label",
            "core_version",
            "release_epoch",
            "platform",
            "arch",
            "ui",
            "tenant",
            "postgres",
            "vault_key_store_service",
            "provider",
            "agent_budgets",
            "normal_capture",
            "recovery_control",
        ];
        expected.sort_unstable();
        let mut keys = keys;
        keys.sort_unstable();
        assert_eq!(keys, expected);
        assert_eq!(manifest["schema_version"], 3);
        let engine =
            fs::read_to_string(workspace().join("crates/openbot-contracts/src/engine.rs")).unwrap();
        let epoch = manifest["release_epoch"].as_u64().unwrap();
        assert!(engine.contains(&format!(
            "\npub const ENGINE_RELEASE_EPOCH: u64 = {epoch};\n"
        )));
        assert_eq!(manifest["normal_capture"], Value::Null);
        assert_eq!(manifest["postgres"]["signing_identity"], "unit");
        let ui_paths: Vec<_> = manifest["ui"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            ui_paths,
            ["fonts/a.woff2", "index.html", "openbot-bootstrap.mjs"]
        );

        let mode = |relative: &str| {
            fs::metadata(temp.0.join("a").join(relative))
                .unwrap()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("resources"), 0o755);
        assert_eq!(mode("resources/ui/fonts"), 0o755);
        assert_eq!(mode("resources/ui/index.html"), 0o644);
        assert_eq!(mode("resources/postgres/bin/postgres"), 0o755);
        assert_eq!(mode("resources/maintenance"), 0o755);
        assert_eq!(mode(&format!("resources/{RELEASE_MANIFEST_FILE}")), 0o644);
    }

    #[test]
    fn capture_request_passes_through_and_marks_the_root_host_bound() {
        let temp = Temp::new();
        let mut args = inputs(&temp);
        let request = br#"{"request_id":"r","trigger":"t","profile":{"native":{"z":1,"a":2}},"maintenance_outer_sha256":"m","maintenance_root":"maintenance","output_root":{"absolute_path":"/o","device":1,"inode":2,"uid":3},"independent_key_medium":{"absolute_path":"/k","device":1,"inode":4,"uid":3}}"#;
        let path = temp.write("in/capture.json", request);
        args.extend(["--normal-capture".to_owned(), path.display().to_string()]);
        build(&args, &temp.0.join("a")).unwrap();
        let manifest: Value = serde_json::from_slice(
            &fs::read(temp.0.join("a/resources").join(RELEASE_MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        let request: Value = serde_json::from_slice(request).unwrap();
        assert_eq!(manifest["normal_capture"], request);
        let record: Value =
            serde_json::from_slice(&fs::read(temp.0.join("a").join(RECORD_FILE)).unwrap()).unwrap();
        assert!(
            record["normal_capture"]
                .as_str()
                .unwrap()
                .starts_with("host_bound")
        );
    }

    #[test]
    fn release_mode_refuses_ad_hoc_bundles_and_development_mode_records_itself() {
        let temp = Temp::new();
        let args = inputs(&temp);
        let mode = |args: &[String], mode: &str| {
            let mut args = args.to_vec();
            let index = args.iter().position(|arg| arg == "--mode").unwrap();
            args[index + 1] = mode.to_owned();
            args
        };
        rejected(&mode(&args, "staging"), &temp, "release_root_mode_invalid");
        let without_mode: Vec<_> = args
            .chunks(2)
            .filter(|pair| pair[0] != "--mode")
            .flatten()
            .cloned()
            .collect();
        rejected(&without_mode, &temp, "release_root_option_missing: --mode");
        temp.write(
            "in/maintenance/postgres-maintenance/manifest.json",
            br#"{"signing_identity":"-"}"#,
        );
        rejected(&args, &temp, "release_root_ad_hoc_signature_refused");
        fs::remove_file(
            temp.0
                .join("in/maintenance/postgres-maintenance/manifest.json"),
        )
        .unwrap();
        temp.write("in/postgres/manifest.json", br#"{"signing_identity":"-"}"#);
        rejected(&args, &temp, "release_root_ad_hoc_signature_refused");
        build(&mode(&args, "development"), &temp.0.join("dev")).unwrap();
        let record: Value =
            serde_json::from_slice(&fs::read(temp.0.join("dev").join(RECORD_FILE)).unwrap())
                .unwrap();
        assert_eq!(record["mode"], "development");
    }

    #[test]
    fn release_mode_refuses_budgets_without_run_deadline() {
        let temp = Temp::new();
        let args = inputs(&temp);
        temp.write(
            "in/budgets.json",
            br#"{"stall_timeout_ms":30000,"max_output_tokens":4096}"#,
        );
        rejected(&args, &temp, "release_root_agent_budgets_refused");
    }

    #[test]
    fn invalid_inputs_are_refused_before_any_write() {
        let temp = Temp::new();
        let args = inputs(&temp);
        let replace = |key: &str, value: &Path| {
            let mut args = args.clone();
            let index = args.iter().position(|arg| arg == key).unwrap();
            args[index + 1] = value.display().to_string();
            args
        };

        rejected(
            &replace("--ui", &temp.0.join("missing")),
            &temp,
            "release_root_input_missing",
        );
        let without_tenant: Vec<_> = args
            .chunks(2)
            .filter(|pair| pair[0] != "--tenant")
            .flatten()
            .cloned()
            .collect();
        rejected(
            &without_tenant,
            &temp,
            "release_root_option_missing: --tenant",
        );
        let mut unknown = args.clone();
        unknown.extend(["--signing".to_owned(), "x".to_owned()]);
        rejected(&unknown, &temp, "release_root_option_unknown");

        for (key, file, body) in [
            (
                "--provider",
                "p.json",
                &br#"{"base_url":"https://a.invalid/","egress_allow_cidrs":[],"x":1}"#[..],
            ),
            (
                "--agent-budgets",
                "b.json",
                br#"{"stall_timeout_ms":1,"run_deadline_ms":1,"max_output_tokens":1,"x":1}"#,
            ),
            (
                "--recovery-control",
                "r.json",
                br#"{"version":1,"hostLimits":{},"ordinaryStartupBounds":{},"x":1}"#,
            ),
            ("--normal-capture", "c.json", br#"{"request_id":"r","x":1}"#),
            (
                "--provider",
                "d.json",
                br#"{"base_url":"a","base_url":"b","egress_allow_cidrs":[]}"#,
            ),
        ] {
            let path = temp.write(&format!("in/{file}"), body);
            let mut bad = args.clone();
            if key == "--normal-capture" {
                bad.extend([key.to_owned(), path.display().to_string()]);
            } else {
                bad = replace(key, &path);
            }
            rejected(&bad, &temp, &format!("release_root_json_invalid: {key}"));
        }

        let ui = |name: &str| {
            let root = temp.0.join(name);
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("index.html"), b"x").unwrap();
            root
        };
        let large = ui("ui-large");
        fs::File::create(large.join("app.js"))
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        rejected(
            &replace("--ui", &large),
            &temp,
            "release_root_inventory_invalid: app.js",
        );
        let total = ui("ui-total");
        for index in 0..17 {
            fs::File::create(total.join(format!("{index}.wasm")))
                .unwrap()
                .set_len(16 * 1024 * 1024)
                .unwrap();
        }
        rejected(
            &replace("--ui", &total),
            &temp,
            "release_root_inventory_limit",
        );
        let many = ui("ui-many");
        for index in 0..TREE_MAX_ENTRIES {
            fs::write(many.join(format!("{index}.js")), b"").unwrap();
        }
        rejected(
            &replace("--ui", &many),
            &temp,
            "release_root_inventory_limit",
        );
        let long = ui("ui-long");
        let deep = long.join("a".repeat(200)).join("b".repeat(200));
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("c".repeat(120)), b"x").unwrap();
        rejected(
            &replace("--ui", &long),
            &temp,
            "release_root_inventory_invalid",
        );
        let name = ui("ui-name");
        fs::write(name.join("a b.js"), b"x").unwrap();
        rejected(
            &replace("--ui", &name),
            &temp,
            "release_root_inventory_invalid: a b.js",
        );
        let tenant = temp.0.join("tenant-large");
        fs::create_dir(&tenant).unwrap();
        fs::File::create(tenant.join("brand.yaml"))
            .unwrap()
            .set_len(TENANT_FILE_MAX_BYTES + 1)
            .unwrap();
        rejected(
            &replace("--tenant", &tenant),
            &temp,
            "release_root_inventory_invalid: brand.yaml",
        );

        let setuid = temp.0.join("pg-setuid");
        fs::create_dir(&setuid).unwrap();
        fs::write(setuid.join("manifest.json"), b"{}").unwrap();
        fs::write(setuid.join("postgres"), b"x").unwrap();
        fs::set_permissions(setuid.join("postgres"), fs::Permissions::from_mode(0o4755)).unwrap();
        rejected(
            &replace("--postgres", &setuid),
            &temp,
            "release_root_input_mode_invalid: postgres",
        );
        let linked = ui("ui-link");
        std::os::unix::fs::symlink("/etc/hosts", linked.join("hosts.js")).unwrap();
        rejected(
            &replace("--ui", &linked),
            &temp,
            "release_root_input_not_regular: hosts.js",
        );

        let existing = temp.0.join("existing");
        fs::create_dir(&existing).unwrap();
        let error = format!("{:#}", build(&args, &existing).unwrap_err());
        assert!(error.contains("release_root_out_not_created"), "{error}");
        assert_eq!(fs::read_dir(&existing).unwrap().count(), 0);
    }

    #[test]
    fn fixed_values_match_the_launcher_source() {
        let source =
            fs::read_to_string(workspace().join("crates/openbot-desktop/src/desktop_release.rs"))
                .unwrap();
        for line in [
            format!("pub const PRODUCT_NAME: &str = \"{PRODUCT_NAME}\";"),
            format!("pub const BUNDLE_IDENTIFIER: &str = \"{BUNDLE_IDENTIFIER}\";"),
            format!("pub const PROTOCOL_SCHEME: &str = \"{PROTOCOL_SCHEME}\";"),
            format!("pub const MAIN_WINDOW: &str = \"{MAIN_WINDOW}\";"),
            format!(
                "pub const POSTGRES_KEY_STORE_SERVICE: &str = \"{POSTGRES_KEY_STORE_SERVICE}\";"
            ),
            format!("pub const VAULT_KEY_STORE_SERVICE: &str = \"{VAULT_KEY_STORE_SERVICE}\";"),
            format!("pub const RELEASE_MANIFEST_FILE: &str = \"{RELEASE_MANIFEST_FILE}\";"),
            "const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;".to_owned(),
            "const TENANT_FILE_MAX_BYTES: u64 = 1024 * 1024;".to_owned(),
            "const TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;".to_owned(),
            format!("const TREE_MAX_ENTRIES: usize = {TREE_MAX_ENTRIES};"),
            format!("value.len() <= {PATH_MAX_BYTES}"),
        ] {
            assert!(source.contains(&line), "{line}");
        }
    }
}
