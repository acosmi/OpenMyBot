use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use openbot_infra::recovery_control::{
    RecoveryRequestPurpose, RestoreOperationCapacity, RestoreOperationProfile,
    TrustedHostRecoveryLimits,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::desktop_release::{
    BUNDLE_IDENTIFIER, INSTANCE_BRAND_TEMPLATE, MAIN_WINDOW, POSTGRES_KEY_STORE_SERVICE,
    PRODUCT_NAME, PROTOCOL_SCHEME, RELEASE_MANIFEST_FILE, TrustedDesktopReleaseDigest,
    VAULT_KEY_STORE_SERVICE, VerifiedDesktopRelease,
};
use crate::postgres_sidecar::{POSTGRES_SOURCE_SHA256, POSTGRES_VERSION};

use super::input::RestoreEntryInput;
use super::{DesktopRestoreError, VerifiedRestoreEntry};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct EntryFixture {
    root: PathBuf,
    release: PathBuf,
    request: PathBuf,
    app: PathBuf,
    pin: String,
    host: TrustedHostRecoveryLimits,
}

impl EntryFixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join(format!(
                ".wrok-restore-entry-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let release = root.join("release");
        for path in [
            "release",
            "release/ui",
            "release/tenant",
            "release/postgres",
            "release/postgres/bin",
            "requests",
            "inputs",
        ] {
            DirBuilder::new()
                .mode(0o700)
                .create(root.join(path))
                .unwrap();
        }
        let host = TrustedHostRecoveryLimits {
            max_request_bytes: 65_536,
            max_activation_bytes: 262_144,
            max_journal_frame_bytes: 65_536,
            max_journal_bytes: 1 << 20,
            max_journal_records: 128,
            max_runtime_record_bytes: 65_536,
            max_registered_runtimes: 16,
            max_retained_operations: 16,
            max_root_entries: 64,
            max_temp_entries: 16,
            max_evidence_refs: 32,
            max_runtime_resource_facts: 32,
            max_id_bytes: 128,
            max_component_bytes: 255,
            max_relative_path_bytes: 4096,
            max_path_depth: 64,
            max_open_files: 256,
            max_metadata_bytes: 32 << 20,
            admission_ns: 30_000_000_000,
        };
        // Unexecuted inventory bytes exercise the real release verifier only;
        // this fixture is not a PostgreSQL process or a signing attestation.
        let programs = ["postgres", "initdb", "pg_ctl"];
        let mut inventory = serde_json::Map::new();
        for name in programs {
            let path = format!("bin/{name}");
            let bytes = format!("unexecuted recovery entry unit fixture: {name}\n");
            fs::write(release.join("postgres").join(&path), &bytes).unwrap();
            fs::set_permissions(
                release.join("postgres").join(&path),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            inventory.insert(path, json!(digest(bytes.as_bytes())));
        }
        let pg_manifest = serde_json::to_vec(&json!({
            "schema":"openbot-postgres-sidecar-bundle", "schema_version":1,
            "platform":"macos", "arch":std::env::consts::ARCH,
            "postgresql_version":POSTGRES_VERSION,"source_archive_sha256":POSTGRES_SOURCE_SHA256,
            "release_epoch":ENGINE_RELEASE_EPOCH,"minimum_compatible_core":env!("CARGO_PKG_VERSION"),
            "signing_identity":"unit-recovery-unexecuted",
            "programs":{"postgres":"bin/postgres","initdb":"bin/initdb","pg_ctl":"bin/pg_ctl"},
            "files":inventory,
        })).unwrap();
        fs::write(release.join("postgres/manifest.json"), &pg_manifest).unwrap();
        let index = "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>";
        fs::write(release.join("ui/index.html"), index).unwrap();
        fs::write(release.join("ui/openbot-bootstrap.mjs"), b"export {};").unwrap();
        let tenant = [
            ("brand.yaml", INSTANCE_BRAND_TEMPLATE),
            (
                "agents.yaml",
                include_str!("../../../../examples/wrok-bot/agents.yaml"),
            ),
            (
                "channels.yaml",
                include_str!("../../../../examples/wrok-bot/channels.yaml"),
            ),
            (
                "model.yaml",
                include_str!("../../../../examples/wrok-bot/model.yaml"),
            ),
            (
                "knowledge.yaml",
                include_str!("../../../../examples/wrok-bot/knowledge.yaml"),
            ),
        ];
        for (name, contents) in tenant {
            fs::write(release.join("tenant").join(name), contents).unwrap();
        }
        let row = |name: &str, bytes: &[u8]| json!({"path":name,"bytes":bytes.len(),"sha256":digest(bytes)});
        let manifest = serde_json::to_vec(&json!({
            "schema":"wrok-bot-desktop-release", "schema_version":3,
            "product_name":PRODUCT_NAME,"bundle_identifier":BUNDLE_IDENTIFIER,
            "scheme":PROTOCOL_SCHEME,"window_label":MAIN_WINDOW,
            "core_version":env!("CARGO_PKG_VERSION"),"release_epoch":ENGINE_RELEASE_EPOCH,
            "platform":"macos","arch":std::env::consts::ARCH,
            "ui":{"root":"ui","files":[row("index.html",index.as_bytes()),row("openbot-bootstrap.mjs",b"export {};")]},
            "tenant":{"root":"tenant","files":tenant.iter().map(|(name,contents)|row(name,contents.as_bytes())).collect::<Vec<_>>()},
            "postgres":{"root":"postgres","manifest_sha256":digest(&pg_manifest),
                "signing_identity":"unit-recovery-unexecuted","key_store_service":POSTGRES_KEY_STORE_SERVICE},
            "vault_key_store_service":VAULT_KEY_STORE_SERVICE,
            "provider":{"base_url":"https://api.example.invalid/v1/","egress_allow_cidrs":[]},
            "agent_budgets":{"stall_timeout_ms":30000,"run_deadline_ms":300000,"max_output_tokens":4096},
            "normal_capture":null,
            "recovery_control":{"version":1,"hostLimits":host,
                "ordinaryStartupBounds":{"effectNs":60_000_000_000u64,"convergenceNs":10_000_000_000u64}},
        })).unwrap();
        let pin = digest(&manifest);
        fs::write(release.join(RELEASE_MANIFEST_FILE), manifest).unwrap();
        let fixture = Self {
            request: root.join("requests/request.json"),
            app: root.join("app"),
            root,
            release,
            pin,
            host,
        };
        // Entry checks select original file identities; they do not authenticate
        // these marker bytes as a carrier/key medium or authorize a PG stage.
        for name in ["carrier", "key-medium"] {
            let path = fixture.root.join("inputs").join(name);
            fs::write(&path, b"unconsumed input identity fixture\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fixture.write_request(&fixture.request_value());
        fixture
    }

    fn request_value(&self) -> Value {
        let profile = RestoreOperationProfile {
            effect_ns: 60_000_000_000,
            convergence_ns: 10_000_000_000,
            capacity: RestoreOperationCapacity {
                max_input_wire_bytes: 1 << 20,
                max_manifest_bytes: 65_536,
                max_material_files: 128,
                max_material_directories: 64,
                max_single_material_bytes: 1 << 20,
                max_material_plain_bytes: 1 << 20,
                max_path_bytes: 4096,
                max_path_depth: 64,
                max_candidate_data_bytes: 1 << 20,
                max_candidate_wal_bytes: 1 << 20,
                max_candidate_temp_bytes: 1 << 20,
                max_spool_bytes: 1 << 20,
                max_retained_prior_bytes: 1 << 20,
                max_journal_bytes: 1 << 20,
                max_journal_records: 128,
                max_metadata_bytes: 32 << 20,
                max_open_files: 256,
                max_native_tasks: 8,
                max_pg_connections: 8,
                max_pg_transactions: 32,
                max_pg_rows: 1024,
                max_reconfirm_requirements: 128,
                max_secret_memory_bytes: 1 << 20,
                max_secret_structure_bytes: 65_536,
                max_total_allocation_bytes: 64 << 20,
                reserve_bytes: 1 << 20,
                free_floor_bytes: 1 << 20,
                max_key_medium_allocation_bytes: 1 << 20,
                key_medium_reserve_bytes: 1 << 20,
                key_medium_free_floor_bytes: 1 << 20,
            },
        };
        json!({
            "formatVersion":1,"requestId":"0123456789abcdef0123456789abcdef",
            "purpose":"restore_new_installation","expectedReviewedReleaseDigest":self.pin,
            "expectedDeploymentId":"entry-deployment","expectedTenantId":"entry-tenant",
            "expectedDatasetId":"11111111111111111111111111111111",
            "expectedSourceInstallationId":"a".repeat(64),"expectedTargetInstallationId":"b".repeat(64),
            "trustedInputSelection":{
                "carrier":{"parent":self.root.join("inputs"),"component":"carrier"},
                "keyMedium":{"parent":self.root.join("inputs"),"component":"key-medium"},
                "expectedBundleId":"dd12725e-f2b5-4c53-914d-d441c1ad9174",
                "expectedSourceOperationId":"ff12725e-f2b5-4c53-914d-d441c1ad9174",
                "expectedManifestSha256":"c".repeat(64),
                "target":{"parent":self.root,"component":"app"},
            },
            "profile":profile,
        })
    }

    fn write_request(&self, request: &Value) {
        fs::write(&self.request, serde_json::to_vec(request).unwrap()).unwrap();
        fs::set_permissions(&self.request, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn release(&self) -> VerifiedDesktopRelease {
        VerifiedDesktopRelease::open(
            &self.release,
            TrustedDesktopReleaseDigest::from_reviewed_build(Some(&self.pin)).unwrap(),
        )
        .unwrap()
    }

    fn entry(&self) -> Result<VerifiedRestoreEntry, DesktopRestoreError> {
        let mut release = self.release();
        let mut original = RestoreEntryInput::new();
        let (control, intent) = original.verify(
            &mut release,
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&self.app).unwrap(),
            &std::env::current_exe().unwrap(),
            &self.request,
        )?;
        Ok(VerifiedRestoreEntry {
            control,
            intent,
            original,
        })
    }

    fn assert_no_operation_or_application(&self) {
        assert!(!self.app.exists());
        let control = self.root.join("com.acosmi.wrokbot.restore-control");
        for name in ["operations", "runtimes"] {
            if control.join(name).exists() {
                assert_eq!(fs::read_dir(control.join(name)).unwrap().count(), 0);
            }
        }
        assert!(!control.join("activation-v1").exists());
    }
}

impl Drop for EntryFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn t046_01_release_and_request_verify_without_business_grant() {
    let context: tauri::Context<tauri::Wry> = tauri::generate_context!();
    crate::desktop_release::validate_product_context(&context).unwrap();
    assert!(context.config().app.windows.is_empty());
    let fixture = EntryFixture::new();
    assert!(
        VerifiedDesktopRelease::open(
            &fixture.release,
            TrustedDesktopReleaseDigest::from_reviewed_build(Some(&"f".repeat(64))).unwrap()
        )
        .is_err()
    );
    fixture.assert_no_operation_or_application();
    let original_request = fs::read(&fixture.request).unwrap();
    let entry = fixture
        .entry()
        .expect("original release and held closed request verify");
    assert_eq!(
        entry.intent.purpose(),
        RecoveryRequestPurpose::RestoreNewInstallation
    );
    assert_eq!(
        entry.intent.expected().reviewed_release_digest(),
        fixture.pin
    );
    assert_eq!(entry.intent.expected().deployment_id(), "entry-deployment");
    assert_eq!(entry.intent.expected().tenant_id(), "entry-tenant");
    assert!(entry.intent.restore_profile().is_some());
    assert_eq!(fs::read(&fixture.request).unwrap(), original_request);
    fixture.assert_no_operation_or_application();
    drop(entry);
    fixture.assert_no_operation_or_application();
}

#[test]
fn malformed_entry_refuses_before_claim_and_keeps_the_request() {
    for case in ["unknown", "duplicate", "oversized"] {
        let fixture = EntryFixture::new();
        let original = fs::read(&fixture.request).unwrap();
        let bytes = match case {
            "unknown" => {
                let mut value = fixture.request_value();
                value["unexpected"] = json!(true);
                serde_json::to_vec(&value).unwrap()
            }
            "duplicate" => {
                let mut bytes = br#"{"formatVersion":1,"#.to_vec();
                bytes.extend_from_slice(&original[1..]);
                bytes
            }
            "oversized" => vec![b' '; fixture.host.max_request_bytes as usize + 1],
            _ => unreachable!(),
        };
        fs::write(&fixture.request, &bytes).unwrap();
        assert!(fixture.entry().is_err(), "case {case}");
        assert_eq!(fs::read(&fixture.request).unwrap(), bytes);
        fixture.assert_no_operation_or_application();
    }
}
