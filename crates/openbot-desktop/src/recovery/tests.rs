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

pub(crate) struct PublicationTest {
    read_only_root: Option<PathBuf>,
    capacity: std::sync::Mutex<Vec<(openbot_infra::recovery_control::RestoreCapacityResource, openbot_infra::recovery_control::RestoreCapacityObservation)>>,
}

impl PublicationTest {
    pub(super) fn before_publish(&self) {
        if let Some(root) = &self.read_only_root {
            fs::set_permissions(root, fs::Permissions::from_mode(0o500)).unwrap();
        }
    }

    pub(super) fn observe(&self, owner: &super::OwnedDesktopRestore) {
        use openbot_infra::recovery_control::RestoreCapacityResource::*;
        let mut observations = self.capacity.lock().unwrap();
        assert!(observations.is_empty());
        for resource in [InputWireBytes, ManifestBytes, MaterialFiles, MaterialDirectories,
            SingleMaterialBytes, MaterialPlainBytes, PathBytes, PathDepth, CandidateDataBytes,
            CandidateWalBytes, CandidateTempBytes, SpoolBytes, RetainedPriorBytes, JournalBytes,
            JournalRecords, MetadataBytes, OpenFiles, NativeTasks, PgConnections, PgTransactions,
            PgRows, ReconfirmRequirements, SecretMemoryBytes, SecretStructureBytes,
            TotalAllocationBytes, KeyMediumAllocationBytes]
        {
            let observation = owner.capacity_observation(resource).expect("the original ledger remains available as DATA");
            assert!(observation.admitted <= observation.limit, "{resource:?}");
            assert!(observation.actual <= observation.limit, "{resource:?}");
            eprintln!("restore_capacity {resource:?} admitted={} actual={} limit={}",
                observation.admitted, observation.actual, observation.limit);
            observations.push((resource, observation));
        }
    }
}

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
        Self::with_open_file_limit(256)
    }

    fn with_open_file_limit(max_open_files: u64) -> Self {
        Self::with_entry_limits(max_open_files, 256 << 20)
    }

    fn with_entry_limits(max_open_files: u64, max_metadata_bytes: u64) -> Self {
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
            max_open_files,
            // A bound candidate pays its oracle trees once (about 60 MB) and
            // each layout and history observation; T046-38 runs them all.
            max_metadata_bytes,
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
        if std::thread::panicking() {
            eprintln!("retained failed entry component fixture: {}", self.root.display());
            return;
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// A real held-request producer reused by the four S23 store scenarios. Its
// numbers are the existing S17 CAR profile, fixed before any case executes.
fn s23_car_request(fixture: &EntryFixture) -> RestoreOperationProfile {
    let source = PathBuf::from(std::env::var_os("OPENBOT_TEST_WHOLE_PG_CARRIER_DIR").expect("explicit authorized CAR"));
    for (directory, original, leaf) in [("carrier-medium", "carrier", "carrier"), ("key-medium", "key", "key")] {
        DirBuilder::new().mode(0o700).create(fixture.root.join(directory)).unwrap();
        let mut entries = fs::read_dir(source.join(original)).unwrap();
        let path = entries.next().expect("one CAR file").unwrap().path();
        assert!(entries.next().is_none());
        fs::copy(path, fixture.root.join(directory).join(leaf)).unwrap();
        fs::set_permissions(fixture.root.join(directory).join(leaf), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::copy(source.join("expected.json"), fixture.root.join("expected.json")).unwrap();
    let expected: Value = serde_json::from_slice(&fs::read(fixture.root.join("expected.json")).unwrap()).unwrap();
    let mut request = fixture.request_value();
    request["profile"]["effectNs"] = json!(120_000_000_000u64);
    request["profile"]["convergenceNs"] = json!(30_000_000_000u64);
    for (field, value) in [
        ("maxInputWireBytes", 64u64 << 20), ("maxManifestBytes", 4 << 20),
        ("maxMaterialFiles", 4096), ("maxMaterialDirectories", 512),
        ("maxSingleMaterialBytes", 32 << 20), ("maxMaterialPlainBytes", 64 << 20),
        ("maxPathBytes", 1024), ("maxPathDepth", 16),
        ("maxCandidateDataBytes", 64 << 20), ("maxCandidateWalBytes", 64 << 20),
        ("maxCandidateTempBytes", 16 << 20), ("maxSpoolBytes", 64 << 20),
        ("maxRetainedPriorBytes", 64 << 20), ("maxJournalRecords", 64),
        ("maxMetadataBytes", 1 << 24), ("maxOpenFiles", 4096),
        ("maxPgConnections", 4), ("maxPgTransactions", 4), ("maxPgRows", 64),
        ("maxReconfirmRequirements", 64), ("maxSecretMemoryBytes", 8 << 20),
        ("maxTotalAllocationBytes", 1 << 32), ("reserveBytes", 1), ("freeFloorBytes", 1),
        ("maxKeyMediumAllocationBytes", 1 << 30), ("keyMediumReserveBytes", 1), ("keyMediumFreeFloorBytes", 1),
    ] { request["profile"]["capacity"][field] = json!(value); }
    for (field, original) in [("expectedDeploymentId", "deploymentId"), ("expectedTenantId", "tenantId"), ("expectedDatasetId", "datasetId"), ("expectedSourceInstallationId", "sourceInstallationId")] {
        request[field] = expected[original].clone();
    }
    for (field, original) in [("expectedBundleId", "bundleId"), ("expectedSourceOperationId", "sourceOperationId"), ("expectedManifestSha256", "manifestSha256")] {
        request["trustedInputSelection"][field] = expected[original].clone();
    }
    request["trustedInputSelection"]["carrier"] = json!({"parent":fixture.root.join("carrier-medium"),"component":"carrier"});
    request["trustedInputSelection"]["keyMedium"] = json!({"parent":fixture.root.join("key-medium"),"component":"key"});
    request["trustedInputSelection"]["target"] = json!({"parent":fixture.root,"component":"new-generation"});
    let profile = serde_json::from_value(request["profile"].clone()).unwrap();
    fixture.write_request(&request);
    profile
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
fn current_reconfirmation_request_is_closed_and_selects_the_local_os_owner() {
    let fixture = EntryFixture::new();
    let mut request = fixture.request_value();
    request["purpose"] = json!("reconfirm_current_binding");
    request.as_object_mut().unwrap().remove("profile");
    request["trustedInputSelection"] = json!({"localSubject":"current_os_owner"});
    request["limits"] = json!({"effectNs":30_000_000_000u64,"convergenceNs":10_000_000_000u64,"maxConfirmations":1});
    // Current preserves the original source ID after a new-installation
    // restore; both IDs match the real descriptor before enrollment.
    fixture.write_request(&request);
    let entry = fixture.entry().expect("closed Current request");
    assert_eq!(entry.intent.purpose(), RecoveryRequestPurpose::ReconfirmCurrentBinding);
    assert!(entry.intent.restore_profile().is_none());
    drop(entry);
    for (pointer, wrong) in [
        ("/limits/maxConfirmations", json!(2)),
        ("/limits/effectNs", json!(0)),
        ("/limits/convergenceNs", json!(0)),
        ("/trustedInputSelection/localSubject", json!("another_user")),
    ] {
        let mut invalid = request.clone();
        *invalid.pointer_mut(pointer).unwrap() = wrong;
        fixture.write_request(&invalid);
        assert!(fixture.entry().is_err(), "{pointer}");
    }
    let mut cross_purpose = request.clone();
    cross_purpose["trustedInputSelection"]["carrier"] = json!({"parent":fixture.root,"component":"carrier"});
    fixture.write_request(&cross_purpose);
    assert!(fixture.entry().is_err());
    request.as_object_mut().unwrap().remove("limits");
    fixture.write_request(&request);
    assert!(fixture.entry().is_err());
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

#[test]
fn t046_02_unknown_duplicate_oversize_or_replaced_request_is_rejected() {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};
    use openbot_infra::recovery_control::{OwnedRecoveryRequestFile, RecoveryControl, RecoveryControlFault, VerifiedRecoveryHost};
    fn tree(path: &std::path::Path, found: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        if !path.exists() { return; }
        if path.is_dir() {
            found.insert(path.to_owned(), Vec::new());
            for child in fs::read_dir(path).unwrap() { tree(&child.unwrap().path(), found); }
        } else { found.insert(path.to_owned(), fs::read(path).unwrap()); }
    }
    for case in ["unknown", "duplicate", "oversized"] {
        let fixture = EntryFixture::new();
        let original = fs::read(&fixture.request).unwrap();
        let bytes = match case {
            "unknown" => { let mut value = fixture.request_value(); value["unexpected"] = json!(true); serde_json::to_vec(&value).unwrap() },
            "duplicate" => { let mut bytes = br#"{"formatVersion":1,"#.to_vec(); bytes.extend_from_slice(&original[1..]); bytes },
            _ => vec![b' '; fixture.host.max_request_bytes as usize + 1],
        };
        fs::write(&fixture.request, &bytes).unwrap();
        let error = fixture.entry().err().expect("malformed real request refused before claim");
        if case == "oversized" { assert_eq!(error, DesktopRestoreError::CapacityExceeded); }
        else { assert!(matches!(error, DesktopRestoreError::EntryInvalid | DesktopRestoreError::ControlInvalid), "{case}: {error:?}"); }
        assert_eq!(fs::read(&fixture.request).unwrap(), bytes);
        fixture.assert_no_operation_or_application();
    }
    // Hold the actual original request FD before changing its named inode.
    {
        let fixture = EntryFixture::new();
        let mut release = fixture.release();
        let bootstrap = release.recovery.as_ref().unwrap().clone();
        let program = std::env::current_exe().unwrap();
        let actual = CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap();
        let host = VerifiedRecoveryHost::from_local_release(
            (fs::File::open(program.parent().unwrap()).unwrap(), program.file_name().unwrap().into(), fs::File::open(&program).unwrap()),
            release.original_release.take().unwrap(), actual.clone(), bootstrap.release_digest,
            bootstrap.host_limits, bootstrap.bounds, [VAULT_KEY_STORE_SERVICE, POSTGRES_KEY_STORE_SERVICE],
        ).unwrap();
        let request = OwnedRecoveryRequestFile::from_held(fs::File::open(fixture.request.parent().unwrap()).unwrap(), fixture.request.file_name().unwrap(), rustix::process::getuid().as_raw()).unwrap();
        let before = fs::metadata(&fixture.request).unwrap();
        let bytes = fs::read(&fixture.request).unwrap();
        let old = fixture.request.with_file_name("original-request.json");
        fs::rename(&fixture.request, &old).unwrap();
        fs::write(&fixture.request, &bytes).unwrap();
        fs::set_permissions(&fixture.request, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(before.ino(), fs::metadata(&fixture.request).unwrap().ino());
        let error = RecoveryControl::open_local_restore_before(actual, request, host, Instant::now() + Duration::from_secs(10)).err().expect("held/named inode mismatch refused");
        assert_eq!(error.fault(), RecoveryControlFault::EntryInvalid);
        assert_eq!(fs::read(old).unwrap(), bytes);
        assert_eq!(fs::read(&fixture.request).unwrap(), bytes);
        fixture.assert_no_operation_or_application();
    }
    for version in [1, 2] {
        let mut fixture = EntryFixture::new();
        let path = fixture.release.join(RELEASE_MANIFEST_FILE);
        let mut outer: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        outer["schema_version"] = json!(version);
        outer.as_object_mut().unwrap().remove("recovery_control");
        if version == 1 { outer.as_object_mut().unwrap().remove("normal_capture"); }
        let bytes = serde_json::to_vec(&outer).unwrap();
        fixture.pin = digest(&bytes);
        fs::write(path, bytes).unwrap();
        let _verified_old_release = fixture.release();
        let original_request = fs::read(&fixture.request).unwrap();
        assert!(matches!(fixture.entry(), Err(DesktopRestoreError::InitializationRequired)));
        assert_eq!(fs::read(&fixture.request).unwrap(), original_request);
        fixture.assert_no_operation_or_application();
    }
    // A real first intent exists: the second consumption must preserve it, not erase it.
    {
        let fixture = EntryFixture::new();
        let key_parent = fixture.root.join("key-inputs");
        DirBuilder::new().mode(0o700).create(&key_parent).unwrap();
        let key = key_parent.join("key-medium");
        fs::write(&key, [3u8; 104]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let mut request = fixture.request_value();
        request["trustedInputSelection"]["keyMedium"] = json!({"parent":key_parent,"component":"key-medium"});
        request["trustedInputSelection"]["target"]["component"] = json!("new-generation");
        // Same finite total-allocation ceiling as the existing S23 real-program profile;
        // the entry-only 64MiB ceiling is below this actual test executable's allocation.
        request["profile"]["capacity"]["maxTotalAllocationBytes"] = json!(1u64 << 32);
        let profile: RestoreOperationProfile = serde_json::from_value(request["profile"].clone()).unwrap();
        fixture.write_request(&request);
        let VerifiedRestoreEntry { mut control, intent, original } = fixture.entry().unwrap();
        let session = control.claim_restore(intent, profile.clone()).unwrap();
        drop(session); drop(control); drop(original);
        let root = fixture.root.join("com.acosmi.wrokbot.restore-control");
        let mut before = std::collections::BTreeMap::new(); tree(&root, &mut before);
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 1);
        let request_bytes = fs::read(&fixture.request).unwrap();
        let VerifiedRestoreEntry { mut control, intent, original } = fixture.entry().unwrap();
        let error = control.claim_restore(intent, profile).err().expect("same requestId cannot be consumed again");
        assert_eq!(error.fault(), RecoveryControlFault::OwnerBusy);
        let mut after = std::collections::BTreeMap::new(); tree(&root, &mut after);
        assert_eq!(after, before);
        assert_eq!(fs::read(&fixture.request).unwrap(), request_bytes);
        assert!(!fixture.app.exists());
        assert!(!fixture.root.join("new-generation").exists());
        drop(error); drop(control); drop(original);
    }
}

#[tokio::test]
#[ignore = "explicit task CAR; real entry/claim/authenticated staging and FS copy only"]
async fn s20_authenticated_staging_copies_pg_files_and_closed_configuration() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use openbot_domain::backup::WholePgMaterialKind as K;
    use openbot_infra::backup::whole_pg_restore_stream::verify_whole_pg_restore_input;

    fn hash_file(path: &std::path::Path) -> [u8; 32] {
        let mut file = fs::File::open(path).expect("independent output reader");
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer).expect("independent bounded read");
            if count == 0 { break; }
            hash.update(&buffer[..count]);
        }
        hash.finalize().into()
    }
    fn leaves(root: &std::path::Path, parent: &std::path::Path, found: &mut BTreeSet<PathBuf>) {
        for entry in fs::read_dir(parent).expect("candidate directory reader") {
            let path = entry.expect("candidate entry").path();
            let metadata = fs::symlink_metadata(&path).expect("actual named output identity");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() { leaves(root, &path, found); }
            else {
                assert!(metadata.is_file());
                assert_eq!(metadata.nlink(), 1);
                found.insert(path.strip_prefix(root).expect("inside actual candidate").to_owned());
            }
        }
    }

    let source = PathBuf::from(std::env::var_os("OPENBOT_TEST_WHOLE_PG_CARRIER_DIR").expect("explicit authorized CAR directory"));
    let fixture = EntryFixture::with_open_file_limit(4096);
    DirBuilder::new().mode(0o700).create(&fixture.app).expect("independent owned prior site");
    let sentinel = fixture.app.join("sentinel");
    fs::write(&sentinel, b"owned prior-site component sentinel\n").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let old_site = fs::metadata(&fixture.app).unwrap();
    let old_sentinel = fs::metadata(&sentinel).unwrap();
    let old_contents = fs::read(&sentinel).unwrap();
    let old_entries: BTreeSet<_> = fs::read_dir(&fixture.app).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    for (directory, source_directory, leaf) in [("carrier-medium", "carrier", "carrier"), ("key-medium", "key", "key")] {
        DirBuilder::new().mode(0o700).create(fixture.root.join(directory)).unwrap();
        let mut files = fs::read_dir(source.join(source_directory)).expect("authorized CAR medium");
        let path = files.next().expect("one CAR file").expect("CAR entry").path();
        assert!(files.next().is_none());
        fs::copy(path, fixture.root.join(directory).join(leaf)).expect("task-owned medium copy");
        fs::set_permissions(fixture.root.join(directory).join(leaf), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::copy(source.join("expected.json"), fixture.root.join("expected.json")).unwrap();
    let expected: Value = serde_json::from_slice(&fs::read(fixture.root.join("expected.json")).unwrap()).unwrap();
    // Exactly the finite profile used by the existing S17 real-CAR tests.
    // No profile is enlarged in response to a copy failure.
    let profile = RestoreOperationProfile {
        effect_ns: 120_000_000_000, convergence_ns: 30_000_000_000,
        capacity: RestoreOperationCapacity {
            max_input_wire_bytes: 64 << 20, max_manifest_bytes: 4 << 20,
            max_material_files: 4096, max_material_directories: 512,
            max_single_material_bytes: 32 << 20, max_material_plain_bytes: 64 << 20,
            max_path_bytes: 1024, max_path_depth: 16,
            max_candidate_data_bytes: 64 << 20, max_candidate_wal_bytes: 64 << 20,
            max_candidate_temp_bytes: 16 << 20, max_spool_bytes: 64 << 20,
            max_retained_prior_bytes: 64 << 20, max_journal_bytes: 1 << 20,
            max_journal_records: 64, max_metadata_bytes: 1 << 24, max_open_files: 4096,
            max_native_tasks: 8, max_pg_connections: 4, max_pg_transactions: 4,
            max_pg_rows: 64, max_reconfirm_requirements: 64,
            max_secret_memory_bytes: 8 << 20, max_secret_structure_bytes: 1 << 16,
            max_total_allocation_bytes: 1 << 32, reserve_bytes: 1, free_floor_bytes: 1,
            max_key_medium_allocation_bytes: 1 << 30,
            key_medium_reserve_bytes: 1, key_medium_free_floor_bytes: 1,
        },
    };
    let mut request = fixture.request_value();
    request["profile"] = json!(profile);
    for (request_key, expected_key) in [("expectedDeploymentId", "deploymentId"), ("expectedTenantId", "tenantId"), ("expectedDatasetId", "datasetId"), ("expectedSourceInstallationId", "sourceInstallationId")] {
        request[request_key] = expected[expected_key].clone();
    }
    for (request_key, expected_key) in [("expectedBundleId", "bundleId"), ("expectedSourceOperationId", "sourceOperationId"), ("expectedManifestSha256", "manifestSha256")] {
        request["trustedInputSelection"][request_key] = expected[expected_key].clone();
    }
    request["trustedInputSelection"]["carrier"] = json!({"parent":fixture.root.join("carrier-medium"),"component":"carrier"});
    request["trustedInputSelection"]["keyMedium"] = json!({"parent":fixture.root.join("key-medium"),"component":"key"});
    // R484 permits selecting a fresh NOENT leaf under the trusted parent.
    // This copy test selects a different leaf so it can actually exercise
    // preservation of the independent, existing prior site above.
    request["trustedInputSelection"]["target"] = json!({"parent":fixture.root,"component":"new-generation"});
    fixture.write_request(&request);
    let carrier = fixture.root.join("carrier-medium/carrier");
    let key = fixture.root.join("key-medium/key");
    let carrier_before = hash_file(&carrier);
    let key_before = hash_file(&key);
    let VerifiedRestoreEntry { mut control, intent, original: _original } = fixture.entry().expect("real release/OS/held-request entry");
    let mut session = control.claim_restore(intent, profile).expect("real exclusive FS claim");
    let (input, intent) = session.frozen_input().expect("one real held input transfer");
    let staging = verify_whole_pg_restore_input(input, intent, &mut session).await
        .unwrap_or_else(|failure| panic!("actual material authentication failed: {:?}", failure.fault()));
    let mut candidate = super::candidate::CandidateGeneration::new(staging);
    candidate.prepare_directories(&mut session).expect("same-generation directories and original Isolation intent");
    candidate.prepare_postgres(&mut session).expect("actual original staging FD copies and closed configuration");
    let (_, data) = candidate.data_directory().expect("actual held data root");
    let (_, socket) = candidate.socket_directory().expect("actual held UDS root");
    assert_eq!(candidate.staging().candidate_plan().parent_path(), fixture.root);
    assert_eq!(candidate.staging().candidate_plan().component(), "new-generation");
    assert_eq!(data, fixture.root.join("new-generation/data"));
    let mut expected_leaves = BTreeSet::new();
    let mut data_files = 0;
    let mut wal_files = 0;
    for material in candidate.staging().manifest().materials() {
        if !matches!(material.kind, K::PostgresBase | K::WalSegment) { continue; }
        let relative = material.relative_path.strip_prefix("pgdata/").expect("authenticated namespace");
        if material.kind == K::WalSegment { assert!(relative.starts_with("pg_wal/")); wal_files += 1; }
        else { assert!(!relative.starts_with("pg_wal/")); data_files += 1; }
        expected_leaves.insert(PathBuf::from(relative));
        let path = data.join(relative);
        let metadata = fs::symlink_metadata(&path).expect("named new output file");
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.len(), material.plain_len);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(hash_file(&path), material.plain_sha256, "independent per-file digest");
    }
    assert!(data_files > 0 && wal_files > 0);
    for name in ["postgresql.conf", "pg_hba.conf", "pg_ident.conf", "postgresql.auto.conf"] { expected_leaves.insert(PathBuf::from(name)); }
    let mut actual_leaves = BTreeSet::new();
    leaves(data, data, &mut actual_leaves);
    assert_eq!(actual_leaves, expected_leaves);
    assert_eq!(fs::read(data.join("postgresql.auto.conf")).unwrap(), b"");
    assert_eq!(fs::read(data.join("pg_ident.conf")).unwrap(), b"");
    assert_eq!(fs::read(data.join("pg_hba.conf")).unwrap(), b"local all desktop_admin scram-sha-256\nlocal all all reject\nlocal replication all reject\n");
    assert_eq!(fs::read_dir(data.join("pg_tblspc")).unwrap().count(), 0);
    let configuration = fs::read_to_string(data.join("postgresql.conf")).unwrap();
    let actual: BTreeMap<_, _> = configuration.lines().map(|line| {
        let (key, value) = line.split_once('=').expect("only fixed assignments");
        (key.trim().to_owned(), value.trim().to_owned())
    }).collect();
    assert_eq!(configuration.lines().count(), actual.len(), "no repeated assignments");
    let mut expected: BTreeMap<String, String> = [
        ("listen_addresses", "''"), ("port", "5432"), ("unix_socket_permissions", "0600"),
        ("shared_preload_libraries", "''"), ("session_preload_libraries", "''"), ("local_preload_libraries", "''"),
        ("archive_mode", "off"), ("archive_command", "''"), ("archive_library", "''"),
        ("restore_command", "''"), ("recovery_end_command", "''"), ("archive_cleanup_command", "''"),
        ("primary_conninfo", "''"), ("primary_slot_name", "''"), ("ssl", "off"),
        ("logging_collector", "off"), ("log_statement", "'none'"), ("log_min_error_statement", "panic"),
        ("shared_memory_type", "mmap"), ("dynamic_shared_memory_type", "mmap"), ("temp_tablespaces", "''"),
    ].into_iter().map(|(key, value)| (key.to_owned(), value.to_owned())).collect();
    expected.insert("unix_socket_directories".to_owned(), format!("'{}'", socket.display()));
    assert_eq!(actual, expected);
    assert_eq!(hash_file(&carrier), carrier_before);
    assert_eq!(hash_file(&key), key_before);
    let prior_after = fs::metadata(&fixture.app).unwrap();
    assert_eq!((prior_after.dev(), prior_after.ino(), prior_after.uid(), prior_after.mode()),
        (old_site.dev(), old_site.ino(), old_site.uid(), old_site.mode()));
    let sentinel_after = fs::metadata(&sentinel).unwrap();
    assert_eq!((sentinel_after.dev(), sentinel_after.ino(), sentinel_after.mode()),
        (old_sentinel.dev(), old_sentinel.ino(), old_sentinel.mode()));
    assert_eq!(fs::read(&sentinel).unwrap(), old_contents);
    assert_eq!(fs::read_dir(&fixture.app).unwrap().map(|entry| entry.unwrap().file_name()).collect::<BTreeSet<_>>(), old_entries);
    assert!(candidate.original_program().is_none(), "no process or candidate PG authority");
}

#[tokio::test]
#[ignore = "explicit CAR; genuine Import-completed source and named memory store only"]
async fn s23_real_staging_two_named_slots_preserve_old_and_never_retry_unknown() {
    use std::sync::Mutex;
    use openbot_domain::vault::SecretBytes;
    use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
    use super::slots::install_target_slots_before;

    struct NamedMemoryStore {
        expected: [(String, String); 2],
        values: Mutex<Vec<(String, String, SecretBytes)>>,
        reads: Mutex<Vec<(String, String)>>,
        writes: Mutex<Vec<(String, String)>>,
        fault: u8,
    }
    impl NamedMemoryStore {
        fn target(&self, service: &str, account: &str) -> usize {
            self.expected.iter().position(|pair| pair.0 == service && pair.1 == account)
                .expect("native calls use only the two original fixed target pairs")
        }
        fn value(&self, service: &str, account: &str) -> Option<SecretBytes> {
            self.values.lock().unwrap().iter().find(|entry| entry.0 == service && entry.1 == account)
                .map(|entry| SecretBytes::new(entry.2.expose().to_vec()))
        }
    }
    impl OsSecretStore for NamedMemoryStore {
        fn read(&self, service: &str, account: &str) -> Result<Option<SecretBytes>, OsSecretStoreError> {
            let index = self.target(service, account);
            self.reads.lock().unwrap().push((service.to_owned(), account.to_owned()));
            let value = self.value(service, account);
            if self.fault == 3 && index == 1 && self.writes.lock().unwrap().len() == 2 {
                let value = value.expect("actual persisted new SCRAM before injected stale readback");
                let mut bytes = zeroize::Zeroizing::new(value.expose().to_vec());
                bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
                return Ok(Some(SecretBytes::new(std::mem::take(&mut *bytes))));
            }
            Ok(value)
        }
        fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
            let index = self.target(service, account);
            assert_eq!(secret.len(), if index == 0 { 33 } else { 64 });
            self.writes.lock().unwrap().push((service.to_owned(), account.to_owned()));
            let mut values = self.values.lock().unwrap();
            assert!(!values.iter().any(|entry| entry.0 == service && entry.1 == account), "absence before write");
            values.push((service.to_owned(), account.to_owned(), SecretBytes::new(secret.to_vec())));
            if self.fault == 2 && index == 1 { return Err(OsSecretStoreError::Unknown); }
            Ok(())
        }
    }

    for fault in 0..4 {
        // Every scenario has its own genuine claim/clock/staging. A failed
        // session is used again only to assert that the same work sends no IO.
        let fixture = EntryFixture::with_open_file_limit(4096);
        let profile = s23_car_request(&fixture);
        let VerifiedRestoreEntry { mut control, intent, original: _original } = fixture.entry().expect("original verified release/OS/request");
        let mut session = control.claim_restore(intent, profile).expect("actual same-session source claim");
        let (input, intent) = session.frozen_input().expect("one actual held source transfer");
        let staging = openbot_infra::backup::whole_pg_restore_stream::verify_whole_pg_restore_input(input, intent, &mut session).await
            .unwrap_or_else(|failure| panic!("actual source authentication failed: {:?}", failure.fault()));
        let target = staging.candidate_plan().target_installation_id();
        let source = staging.candidate_plan().source_installation_id();
        let expected = [
            (VAULT_KEY_STORE_SERVICE.to_owned(), format!("desktop-vault-master-v1-{target}-r-{}", session.operation_id())),
            (POSTGRES_KEY_STORE_SERVICE.to_owned(), format!("postgresql-17-{target}-r-{}", session.operation_id())),
        ];
        let old_master = (VAULT_KEY_STORE_SERVICE.to_owned(), format!("desktop-vault-master-v1-{source}"));
        let old_scram = (POSTGRES_KEY_STORE_SERVICE.to_owned(), format!("postgresql-17-{source}"));
        let mut values = vec![
            (old_master.0.clone(), old_master.1.clone(), crate::desktop_vault::frame_stored(staging.authenticated_secrets().historical_master())),
            (old_scram.0.clone(), old_scram.1.clone(), SecretBytes::new(staging.authenticated_secrets().postgres_scram().expose().to_vec())),
        ];
        if fault == 1 {
            values.push((expected[0].0.clone(), expected[0].1.clone(), crate::desktop_vault::frame_stored(staging.authenticated_secrets().historical_master())));
        }
        let store = NamedMemoryStore { expected, values: Mutex::new(values), reads: Mutex::new(Vec::new()), writes: Mutex::new(Vec::new()), fault };
        let mut work = None;
        let result = install_target_slots_before(&mut work, &staging, &mut session, &store);
        assert_eq!(result, if fault == 0 { Ok(()) } else { Err(DesktopRestoreError::KeyStoreUnknown) });
        let writes = store.writes.lock().unwrap().len();
        let reads = store.reads.lock().unwrap().len();
        assert_eq!((reads, writes), match fault { 0 => (4, 2), 1 => (1, 0), 2 => (3, 2), _ => (4, 2) });
        assert_eq!(install_target_slots_before(&mut work, &staging, &mut session, &store), result);
        assert_eq!((store.reads.lock().unwrap().len(), store.writes.lock().unwrap().len()), (reads, writes), "same work never resends native calls");
        let retained = work.as_ref().expect("original private work retained");
        if fault == 1 {
            assert!(matches!(retained.returned_absence(0), Some(Ok(Some(_)))));
            assert!(retained.returned_write(0).is_none());
        } else {
            assert!(retained.returned_readback(0).is_some_and(|result| result.as_ref().is_ok_and(|value| value.is_some())));
            let master = store.value(&store.expected[0].0, &store.expected[0].1).expect("actual target master");
            assert!(master.len() == 33 && master.expose()[0] == 1);
            let payload = SecretBytes::new(master.expose()[1..].to_vec());
            assert!(payload.ct_eq(staging.authenticated_secrets().historical_master()));
            let scram = store.value(&store.expected[1].0, &store.expected[1].1).expect("actual target new SCRAM");
            assert!(scram.len() == 64 && scram.expose().iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
            assert!(!scram.ct_eq(staging.authenticated_secrets().postgres_scram()), "new password, not historical SCRAM");
            if fault == 2 {
                assert!(matches!(retained.returned_write(1), Some(Err(OsSecretStoreError::Unknown))));
                assert!(retained.returned_readback(1).is_none());
            } else if fault == 3 {
                let returned = retained.returned_readback(1).and_then(|result| result.as_ref().ok()).and_then(Option::as_ref).expect("original wrong readback payload retained");
                assert!(returned.len() == 64 && !returned.ct_eq(&scram));
            }
        }
        assert!(store.value(&old_master.0, &old_master.1).expect("old master unchanged").ct_eq(&crate::desktop_vault::frame_stored(staging.authenticated_secrets().historical_master())));
        assert!(store.value(&old_scram.0, &old_scram.1).expect("old SCRAM unchanged").ct_eq(staging.authenticated_secrets().postgres_scram()));
        eprintln!("S23 named MemoryStore scenario {fault}: actual reads={reads} writes={writes}; old slots intact; repeated work zero IO");
    }
}

/// A real PostgreSQL bundle, Desktop dist and memory key store shared by the
/// startups of one real-sidecar case.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
struct SidecarRelease {
    bundle_root: PathBuf,
    digest: crate::postgres_sidecar::PostgresBundleDigest,
    dist: PathBuf,
    store: std::sync::Arc<crate::postgres_sidecar::RuntimeMemorySecretStore>,
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl SidecarRelease {
    fn new() -> Self {
        let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
        let (bundle_root, digest) =
            crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
        Self {
            bundle_root,
            digest,
            dist: crate::postgres_sidecar::materialize_desktop_dist(),
            store: std::sync::Arc::new(crate::postgres_sidecar::RuntimeMemorySecretStore::empty()),
        }
    }

    fn config(
        &self,
        host_limits: TrustedHostRecoveryLimits,
    ) -> crate::tauri_background::DesktopLocalRuntimeConfig {
        use crate::tauri_background::{
            DesktopLocalApplicationInput, DesktopLocalReleaseInput, DesktopLocalRuntimeConfig,
            DesktopRecoveryBootstrap,
        };
        use crate::{DesktopAgentBudgets, DesktopOpenAiProviderInput};
        use std::time::Duration;
        let bundle = crate::postgres_sidecar::VerifiedPostgresBundle::open(
            &self.bundle_root,
            self.digest,
            &crate::postgres_sidecar::signing_identity(),
        )
        .unwrap();
        let release = DesktopLocalReleaseInput::new(
            &self.dist,
            "openbot",
            "main",
            bundle,
            crate::postgres_sidecar::ReviewedPostgresKeyStoreService::from_reviewed_release(
                "com.example.product.postgresql.t046-local",
            )
            .unwrap(),
            crate::desktop_vault::ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
                "com.example.product.desktop-vault.t046-local",
            )
            .unwrap(),
            self.store.clone(),
        )
        .unwrap();
        let application = DesktopLocalApplicationInput::new(
            DesktopOpenAiProviderInput::new("https://api.example.test/v1", Vec::new()).unwrap(),
            DesktopAgentBudgets::new(
                Some(Duration::from_secs(2)),
                Some(Duration::from_secs(1_800)),
                16_384,
            )
            .unwrap(),
        )
        .unwrap();
        DesktopLocalRuntimeConfig::new(release, application, |authority| {
            Ok(crate::postgres_sidecar::loaded_desktop_package(
                authority.auth_context().tenant().as_str(),
            ))
        })
        .with_recovery_bootstrap(DesktopRecoveryBootstrap {
            host_limits,
            bounds: serde_json::from_value(
                json!({ "effectNs": 120_000_000_000u64, "convergenceNs": 30_000_000_000u64 }),
            )
            .unwrap(),
            release_digest: [11; 32],
        })
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl Drop for SidecarRelease {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.bundle_root);
        let _ = fs::remove_dir_all(&self.dist);
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
fn local_journal(control: &std::path::Path, operation: &str) -> Vec<Value> {
    let raw = fs::read(
        control
            .join("operations")
            .join(operation)
            .join("journal-v1"),
    )
    .unwrap();
    let (mut records, mut offset) = (Vec::new(), 0);
    while offset < raw.len() {
        let length = u32::from_be_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) as usize;
        records.push(serde_json::from_slice(&raw[offset + 12..offset + 12 + length]).unwrap());
        offset += 12 + length + 32;
    }
    records
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
fn local_head(control: &std::path::Path) -> Value {
    serde_json::from_slice(&fs::read(control.join("activation-v1")).unwrap()).unwrap()
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
fn local_runtimes(control: &std::path::Path) -> Vec<PathBuf> {
    fs::read_dir(control.join("runtimes"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[test]
#[ignore = "requires dedicated PostgreSQL 17.11 binaries via OPENBOT_TEST_POSTGRES_BIN_DIR"]
fn t046_07_local_fresh_proof_publishes_ordinary_active() {
    crate::testing::on_large_stack(t046_07_run);
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
async fn t046_07_run() {
    use crate::tauri_background::prepare_desktop_local_runtime;
    use openbot_infra::db::native::NATIVE_LATEST_VERSION;

    let site = SidecarRelease::new();
    let parent = crate::postgres_sidecar::fixture_root("t046-07b-fresh");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let app_root = parent.join("app");
    let control_root = parent.join("com.acosmi.wrokbot.restore-control");
    let host_limits = TrustedHostRecoveryLimits {
        max_request_bytes: 65_536,
        max_activation_bytes: 65_536,
        max_journal_frame_bytes: 65_536,
        max_journal_bytes: 1 << 20,
        max_journal_records: 64,
        max_runtime_record_bytes: 65_536,
        max_registered_runtimes: 8,
        max_retained_operations: 8,
        max_root_entries: 64,
        max_temp_entries: 8,
        max_evidence_refs: 16,
        max_runtime_resource_facts: 16,
        max_id_bytes: 128,
        max_component_bytes: 128,
        max_relative_path_bytes: 1024,
        max_path_depth: 16,
        max_open_files: 64,
        max_metadata_bytes: 1 << 24,
        admission_ns: 5_000_000_000,
    };
    // A new app-data root: LocalPhysicalFresh, Created/Fresh proof, OrdinaryActive.
    let prepared = prepare_desktop_local_runtime(
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(&app_root).unwrap(),
        site.config(host_limits),
    )
    .await
    .unwrap();
    let head = local_head(&control_root);
    assert_eq!(head["phase"], "OrdinaryActive");
    assert_eq!(
        head["revision"], 2,
        "OrdinaryInitializing precedes the Active head"
    );
    assert_eq!(
        head["data"]["binding"]["nativeVersion"],
        NATIVE_LATEST_VERSION
    );
    let version: i32 = prepared
        .pool()
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT max(version) FROM openbot_internal.schema_migrations",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(version, NATIVE_LATEST_VERSION);
    // The evidence is exactly the ordinary_initialize StageObserved, and the
    // operation closed its resources.
    let evidence = head["data"]["initializationEvidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 1);
    let records = local_journal(&control_root, evidence[0]["contextId"].as_str().unwrap());
    let observed = &records[evidence[0]["sequence"].as_u64().unwrap() as usize - 1];
    assert_eq!(observed["kind"], "StageObserved");
    let intent = &records[observed["data"]["intentSequence"].as_u64().unwrap() as usize - 1];
    assert_eq!(intent["data"]["stage"], "ordinary_initialize");
    assert_eq!(records[0]["data"]["mode"], "fresh_init");
    assert!(records.iter().any(
        |record| record["kind"] == "StageIntent" && record["data"]["stage"] == "resource_close"
    ));
    // The runtime holds SH under one enrollment until its receipt.
    let runtimes = local_runtimes(&control_root);
    assert_eq!(runtimes.len(), 1);
    assert!(runtimes[0].join("enrollment-v1").is_file());
    assert!(!runtimes[0].join("receipt-v1").exists());
    prepared.shutdown().await.unwrap();
    assert!(runtimes[0].join("receipt-v1").is_file());
    fs::remove_dir_all(parent).unwrap();
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[test]
#[ignore = "requires dedicated PostgreSQL 17.11 binaries via OPENBOT_TEST_POSTGRES_BIN_DIR"]
fn t046_08_local_legacy_needs_positive_intent_and_rejects_known_restore() {
    crate::testing::on_large_stack(t046_08_run);
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
async fn t046_08_run() {
    use crate::tauri_background::{
        DesktopLocalRuntimeError, execute_local_legacy_adoption, prepare_desktop_local_runtime,
    };
    use openbot_infra::db::native::NATIVE_LATEST_VERSION;
    use openbot_infra::recovery_control::RecoveryControlFault;

    let site = SidecarRelease::new();
    let fixture = EntryFixture::new();
    let control = fixture.root.join("com.acosmi.wrokbot.restore-control");
    let app = || CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap();
    // An installation the ordinary Fresh path built and closed with its receipt.
    let prepared = prepare_desktop_local_runtime(app(), site.config(fixture.host.clone()))
        .await
        .unwrap();
    prepared.shutdown().await.unwrap();
    let fresh = local_head(&control)["data"]["binding"].clone();
    // Without its control state the installation exists and has no head.
    fs::remove_file(control.join("activation-v1")).unwrap();
    for directory in ["operations", "runtimes"] {
        for entry in fs::read_dir(control.join(directory)).unwrap() {
            fs::remove_dir_all(entry.unwrap().path()).unwrap();
        }
    }

    // (a) An ordinary start of the headless installation has no positive intent.
    let headless = prepare_desktop_local_runtime(app(), site.config(fixture.host.clone())).await;
    assert!(matches!(
        headless,
        Err(DesktopLocalRuntimeError::InitializationRequired)
    ));
    assert!(!control.join("activation-v1").exists());
    assert_eq!(fs::read_dir(control.join("operations")).unwrap().count(), 0);

    let mut request = fixture.request_value();
    request["purpose"] = json!("adopt_ordinary_legacy");
    request.as_object_mut().unwrap().remove("profile");
    request["trustedInputSelection"] =
        json!({"installation": {"parent": fixture.root, "component": "app"}});
    request["limits"] = json!({"effectNs": 60_000_000_000u64, "convergenceNs": 10_000_000_000u64});
    for (field, binding) in [
        ("expectedDeploymentId", "deploymentId"),
        ("expectedTenantId", "tenantId"),
        ("expectedDatasetId", "datasetId"),
        ("expectedSourceInstallationId", "targetInstallationId"),
        ("expectedTargetInstallationId", "targetInstallationId"),
    ] {
        request[field] = fresh[binding].clone();
    }
    let adopt = || {
        fixture.write_request(&request);
        fixture.entry().unwrap()
    };

    // (c) A retained restore staging operation in the control root refuses the
    // adoption before Initializing: nothing is published.
    let staging = control
        .join("operations")
        .join("5aa1e5aa1e5aa1e5aa1e5aa1e5aa1e5a");
    DirBuilder::new().mode(0o700).create(&staging).unwrap();
    match execute_local_legacy_adoption(app(), site.config(fixture.host.clone()), adopt()).await {
        Err(DesktopLocalRuntimeError::RecoveryControl(error)) => {
            assert_eq!(error.fault(), RecoveryControlFault::InitializationRequired)
        }
        other => panic!("known staging was not refused: {:?}", other.err()),
    }
    assert!(!control.join("activation-v1").exists());
    assert_eq!(fs::read_dir(control.join("operations")).unwrap().count(), 1);
    fs::remove_dir(&staging).unwrap();

    // (b) The adopt request publishes the latest Active and writes the runtime
    // receipt before returning.
    execute_local_legacy_adoption(app(), site.config(fixture.host.clone()), adopt()).await.unwrap();
    let head = local_head(&control);
    assert_eq!(head["phase"], "OrdinaryActive");
    assert_eq!(head["revision"], 2, "OrdinaryInitializing is revision 1");
    let binding = &head["data"]["binding"];
    assert_eq!(binding["nativeVersion"], NATIVE_LATEST_VERSION);
    assert_eq!(binding["datasetId"], fresh["datasetId"]);
    let evidence = head["data"]["initializationEvidence"].as_array().unwrap();
    let records = local_journal(&control, evidence[0]["contextId"].as_str().unwrap());
    assert_eq!(records[0]["data"]["mode"], "legacy_adoption");
    assert_eq!(
        records[0]["epoch"], binding["authorizationEpoch"],
        "the Active keeps the epoch Initializing sealed"
    );
    let runtimes = local_runtimes(&control);
    assert_eq!(runtimes.len(), 1);
    assert!(runtimes[0].join("enrollment-v1").is_file());
    assert!(
        runtimes[0].join("receipt-v1").is_file(),
        "receipt written before exit"
    );
}

/// A task-owned generation and three excluded original locations under one
/// short private root, an initdb'd PostgreSQL 17.11 data directory with the
/// candidate's closed configuration, and the authenticated software bundle.
struct SandboxFixture {
    root: PathBuf,
    bundle: crate::postgres_sidecar::VerifiedPostgresBundle,
    bundle_root: PathBuf,
    password: String,
    paths: Vec<PathBuf>,
    held: Vec<fs::File>,
    parent: fs::File,
}

impl SandboxFixture {
    const GENERATION: [&str; 6] = [
        "gen",
        "gen/data",
        "gen/wal",
        "gen/temp",
        "gen/uds",
        "gen/materials",
    ];
    const EXCLUDED: [&str; 3] = ["old-site", "control", "key-medium"];

    fn new() -> Self {
        let bin = PathBuf::from(
            std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR")
                .expect("OPENBOT_TEST_POSTGRES_BIN_DIR"),
        );
        let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin);
        let bundle = crate::postgres_sidecar::VerifiedPostgresBundle::open(
            &bundle_root,
            digest,
            &crate::postgres_sidecar::signing_identity(),
        )
        .unwrap();
        // The UDS path must stay below PostgreSQL's 103-byte limit.
        let root = PathBuf::from(format!(
            "/private/tmp/wb046-{}",
            &uuid::Uuid::now_v7().simple().to_string()[20..]
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        for leaf in Self::GENERATION.iter().chain(&Self::EXCLUDED) {
            DirBuilder::new()
                .mode(0o700)
                .create(root.join(leaf))
                .unwrap();
        }
        for leaf in Self::EXCLUDED {
            fs::write(root.join(leaf).join("sentinel"), leaf).unwrap();
        }
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).unwrap();
        let password: String = random.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(root.join("pw"), &password).unwrap();
        let status = std::process::Command::new(bin.join("initdb"))
            .arg("-D")
            .arg(root.join("gen/data"))
            .args([
                "-U",
                "desktop_admin",
                "--auth=scram-sha-256",
                "-E",
                "UTF8",
                "--locale=C",
            ])
            .arg(format!("--pwfile={}", root.join("pw").display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_file(root.join("pw")).unwrap();
        let paths: Vec<PathBuf> = Self::GENERATION
            .iter()
            .map(|leaf| root.join(leaf))
            .collect();
        let held = paths
            .iter()
            .map(|path| fs::File::open(path).unwrap())
            .collect();
        let parent = fs::File::open(&root).unwrap();
        let fixture = Self {
            root,
            bundle,
            bundle_root,
            password,
            paths,
            held,
            parent,
        };
        fixture.configure("''");
        fixture
    }

    fn data(&self) -> PathBuf {
        self.root.join("gen/data")
    }

    fn configure(&self, listen: &str) {
        fs::write(self.data().join("postgresql.conf"), format!(
            "listen_addresses = {listen}\nport = 5432\nunix_socket_directories = '{}'\nunix_socket_permissions = 0600\nshared_preload_libraries = ''\narchive_mode = off\nssl = off\nlogging_collector = off\nshared_memory_type = mmap\ndynamic_shared_memory_type = mmap\n",
            self.root.join("gen/uds").display())).unwrap();
        fs::write(self.data().join("pg_hba.conf"), "local all desktop_admin scram-sha-256\nlocal all all reject\nlocal replication all reject\n").unwrap();
        fs::write(self.data().join("pg_ident.conf"), "").unwrap();
        fs::write(self.data().join("postgresql.auto.conf"), "").unwrap();
    }

    fn policy<'a>(
        &'a self,
        loaders: &'a [&'a std::path::Path],
    ) -> crate::postgres_maintenance::runner::restore_isolation::RestoreIsolationPolicy<'a> {
        use crate::postgres_maintenance::runner::restore_isolation::{
            Directory, ExcludedLocation, Generation, RestoreIsolationPolicy,
        };
        let directory = |index: usize| Directory {
            path: &self.paths[index],
            original: &self.held[index],
        };
        RestoreIsolationPolicy::prepare(
            Generation {
                root: directory(0),
                data: directory(1),
                wal: directory(2),
                temp: directory(3),
                uds: directory(4),
                materials: directory(5),
            },
            Self::EXCLUDED.map(|component| ExcludedLocation {
                parent: Directory {
                    path: &self.root,
                    original: &self.parent,
                },
                component,
            }),
            loaders,
            1 << 20,
        )
        .unwrap()
    }

    fn excluded_state(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut state = Vec::new();
        for leaf in Self::EXCLUDED {
            for entry in fs::read_dir(self.root.join(leaf)).unwrap() {
                let path = entry.unwrap().path();
                state.push((path.clone(), fs::read(&path).unwrap()));
            }
        }
        state.sort();
        state
    }
}

impl Drop for SandboxFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.bundle_root);
    }
}

#[tokio::test]
#[ignore = "BIN SBX: real /usr/bin/sandbox-exec and OPENBOT_TEST_POSTGRES_BIN_DIR PostgreSQL 17.11"]
async fn t046_19_candidate_sandbox_denies_network_exec_original_site_and_control_writes() {
    let fixture = SandboxFixture::new();
    let loader_files = fixture
        .bundle
        .system_loader_files()
        .unwrap_or_else(|_| panic!("actual loader inventory"));
    let loaders: Vec<&std::path::Path> = loader_files.iter().map(PathBuf::as_path).collect();
    assert!(
        loaders.contains(&std::path::Path::new("/usr/lib/dyld")),
        "actual loader inventory"
    );
    let policy = fixture.policy(&loaders);
    let before = fixture.excluded_state();
    let run = |args: Vec<std::ffi::OsString>, input: Vec<u8>| {
        let mut command = policy
            .checked_postgres_command(&fixture.bundle, &args)
            .unwrap_or_else(|_| panic!("original policy command"));
        async move {
            use tokio::io::AsyncWriteExt;
            let mut child = command.spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&input).await.unwrap();
            drop(stdin);
            tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
                .await
                .unwrap()
                .unwrap()
        }
    };
    let data = fixture.data().into_os_string();

    // The candidate's only listener is its private UDS: a TCP listener fails.
    fixture.configure("'127.0.0.1'");
    let output = run(
        vec!["-D".into(), data.clone(), "-p".into(), "45432".into()],
        Vec::new(),
    )
    .await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not bind IPv4 address \"127.0.0.1\": Operation not permitted"),
        "{stderr}"
    );
    fixture.configure("''");

    // The same policy denies executing anything but the authenticated postgres.
    let command = policy
        .checked_postgres_command(&fixture.bundle, &[])
        .unwrap_or_else(|_| panic!("original policy command"));
    let mut args = command.as_std().get_args();
    assert_eq!(args.next(), Some(std::ffi::OsStr::new("-p")));
    let profile = args.next().unwrap().to_owned();
    let shell = std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .args(["/bin/sh", "-c", "exit 0"])
        .output()
        .unwrap();
    assert!(!shell.status.success());
    assert!(String::from_utf8_lossy(&shell.stderr).contains("Operation not permitted"));

    // The sandboxed postgres itself cannot write into the original site, the
    // control root or the key-medium directory (server-side COPY TO through a
    // client on its private UDS).
    let mut server = policy
        .checked_postgres_command(&fixture.bundle, &["-D".into(), data])
        .unwrap_or_else(|_| panic!("original policy command"));
    let mut child = server.spawn().unwrap();
    let ready = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !fs::read_to_string(fixture.data().join("postmaster.pid"))
        .is_ok_and(|text| text.lines().nth(7).map(str::trim) == Some("ready"))
    {
        assert!(std::time::Instant::now() < ready, "candidate readiness");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut config = tokio_postgres::Config::new();
    config
        .host_path(fixture.root.join("gen/uds"))
        .port(5432)
        .user("desktop_admin")
        .dbname("postgres")
        .password(fixture.password.as_str());
    let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    for leaf in SandboxFixture::EXCLUDED {
        let error = client
            .batch_execute(&format!(
                "COPY (SELECT 'leak') TO '{}'",
                fixture.root.join(leaf).join("written").display()
            ))
            .await
            .unwrap_err();
        let message = error.as_db_error().map(|e| e.message().to_owned());
        assert!(
            message
                .as_deref()
                .is_some_and(|m| m.contains("Operation not permitted")),
            "{message:?}"
        );
    }
    // The candidate's own temp directory stays writable under the same policy.
    client
        .batch_execute(&format!(
            "COPY (SELECT 'own') TO '{}'",
            fixture.root.join("gen/temp/own").display()
        ))
        .await
        .unwrap();
    assert_eq!(
        fs::read(fixture.root.join("gen/temp/own")).unwrap(),
        b"own\n"
    );
    drop(client);
    driver.await.unwrap().unwrap();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap(),
        rustix::process::Signal::INT,
    )
    .unwrap();
    assert!(child.wait().await.unwrap().success());
    assert_eq!(fixture.excluded_state(), before);
}

#[tokio::test]
#[ignore = "BIN SBX: real /usr/bin/sandbox-exec and OPENBOT_TEST_POSTGRES_BIN_DIR PostgreSQL 17.11"]
async fn t046_20_candidate_child_three_pipes_and_driver_close_or_stay_unknown() {
    use crate::postgres_maintenance::clock::OperationClock;
    use crate::postgres_maintenance::runner::{self, RestorePipeJoin};
    let entry = EntryFixture::new();
    let key_parent = entry.root.join("key-inputs");
    DirBuilder::new().mode(0o700).create(&key_parent).unwrap();
    fs::write(key_parent.join("key-medium"), [3u8; 104]).unwrap();
    fs::set_permissions(
        key_parent.join("key-medium"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut request = entry.request_value();
    request["trustedInputSelection"]["keyMedium"] =
        json!({"parent":key_parent,"component":"key-medium"});
    request["trustedInputSelection"]["target"]["component"] = json!("new-generation");
    request["profile"]["capacity"]["maxTotalAllocationBytes"] = json!(1u64 << 32);
    let profile: RestoreOperationProfile =
        serde_json::from_value(request["profile"].clone()).unwrap();
    entry.write_request(&request);
    let VerifiedRestoreEntry {
        mut control,
        intent,
        original: _original,
    } = entry.entry().unwrap();
    let mut session = control.claim_restore(intent, profile).unwrap();
    let clock = OperationClock::from_restore_session(&mut session).unwrap();

    let fixture = SandboxFixture::new();
    let loader_files = fixture
        .bundle
        .system_loader_files()
        .unwrap_or_else(|_| panic!("actual loader inventory"));
    let loaders: Vec<&std::path::Path> = loader_files.iter().map(PathBuf::as_path).collect();
    let policy = fixture.policy(&loaders);
    let secret = std::sync::Arc::new(openbot_domain::vault::SecretBytes::new(
        fixture.password.as_bytes().to_vec(),
    ));
    let mut owner = runner::spawn_restore_program(
        &policy,
        &fixture.bundle,
        &["-D".into(), fixture.data().into_os_string()],
        &clock,
        secret,
        (1 << 20, 1 << 20, true),
    )
    .unwrap_or_else(|_| panic!("original sandboxed candidate spawn"));
    let pid = owner.original_child().id().unwrap();
    assert!(
        owner.original_identity().is_ok()
            && owner.post_directories().is_ok()
            && owner.post_software().is_ok()
    );
    let ready = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !fs::read_to_string(fixture.data().join("postmaster.pid"))
        .is_ok_and(|text| text.lines().nth(7).map(str::trim) == Some("ready"))
    {
        assert!(std::time::Instant::now() < ready, "candidate readiness");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // A connected driver keeps the smart shutdown waiting.
    let mut config = tokio_postgres::Config::new();
    config
        .host_path(fixture.root.join("gen/uds"))
        .port(5432)
        .user("desktop_admin")
        .dbname("postgres")
        .password(fixture.password.as_str());
    let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    assert_eq!(
        client
            .query_one("SELECT current_setting('listen_addresses')", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        ""
    );
    runner::request_restore_stop(&mut owner, &clock)
        .unwrap_or_else(|_| panic!("one original TERM"));
    // The capacity observer fails on its first call: the wait still owns the
    // same Child and must keep that failure next to the real exit.
    let mut wait = Box::pin(runner::wait_restore_program(
        owner,
        &clock,
        || Err(crate::postgres_maintenance::MaintenanceError::CapacityExceeded),
        true,
    ));
    // Cancelling the observation leaves the original wait resident: no exit is invented.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait)
            .await
            .is_err()
    );
    // Closing the driver lets the same Child exit; the same wait then returns.
    drop(client);
    driver.await.unwrap().unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), wait)
        .await
        .unwrap();
    assert_eq!(result.native_wait(), Some((pid, Some(0), None)));
    // The observer failure stays Unknown on the result; the real exit does not erase it.
    assert!(matches!(
        result.retained_error(),
        Some(crate::postgres_maintenance::MaintenanceError::CapacityExceeded)
    ));
    // No stdin writer task exists for the server; stdout and stderr readers returned.
    assert_eq!(
        result.pipes(),
        [
            RestorePipeJoin::Absent,
            RestorePipeJoin::Returned,
            RestorePipeJoin::Returned
        ]
    );
    drop(session);
}

#[tokio::test]
#[ignore = "explicit task CAR plus BIN SBX: real staging, /usr/bin/sandbox-exec and OPENBOT_TEST_POSTGRES_BIN_DIR PostgreSQL 17.11"]
async fn t046_20b_desktop_candidate_start_bind_and_startup_death() {
    use super::candidate::CandidateGeneration;
    use openbot_infra::backup::whole_pg_restore_stream::verify_whole_pg_restore_input;
    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = crate::postgres_sidecar::VerifiedPostgresBundle::open(
        &bundle_root,
        digest,
        &crate::postgres_sidecar::signing_identity(),
    )
    .unwrap();
    let crate_dir = std::env::current_dir().unwrap();
    for death in [false, true] {
        // A short owned fixture root keeps the candidate UDS path below 103
        // bytes and every ancestor trusted (no world-writable temp directory);
        // tests run one at a time, so the working directory is ours.
        let short = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".wb046-{}",
            &uuid::Uuid::now_v7().simple().to_string()[20..]
        ));
        DirBuilder::new().mode(0o700).create(&short).unwrap();
        std::env::set_current_dir(&short).unwrap();
        let fixture = EntryFixture::with_open_file_limit(4096);
        std::env::set_current_dir(&crate_dir).unwrap();
        s23_car_request(&fixture);
        let mut request: Value =
            serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
        // The bind pays the oracle trees once (about 60 MB) on top of staging.
        request["profile"]["capacity"]["maxMetadataBytes"] = json!(96u64 << 20);
        let profile: RestoreOperationProfile =
            serde_json::from_value(request["profile"].clone()).unwrap();
        fixture.write_request(&request);
        let VerifiedRestoreEntry {
            mut control,
            intent,
            original: _original,
        } = fixture
            .entry()
            .expect("original verified release/OS/request");
        let mut session = control
            .claim_restore(intent, profile)
            .expect("actual same-session claim");
        let operation = session.operation_id().to_owned();
        let (input, intent) = session
            .frozen_input()
            .expect("one actual held source transfer");
        let staging = verify_whole_pg_restore_input(input, intent, &mut session)
            .await
            .unwrap_or_else(|failure| {
                panic!("actual source authentication failed: {:?}", failure.fault())
            });
        let mut candidate = CandidateGeneration::new(staging);
        candidate
            .prepare_directories(&mut session)
            .expect("same-generation directories and Isolation intent");
        candidate
            .prepare_postgres(&mut session)
            .expect("staging copies and closed configuration");
        if death {
            // An invalid setting makes the candidate exit FATAL at startup.
            let (_, data) = candidate.data_directory().expect("held data root");
            std::io::Write::write_all(
                &mut fs::OpenOptions::new()
                    .append(true)
                    .open(data.join("postgresql.conf"))
                    .unwrap(),
                b"shared_buffers = 'not-a-size'\n",
            )
            .unwrap();
        }
        let started = std::time::Instant::now();
        let start = candidate.start_postgres(&mut session, &bundle);
        let bound = match start {
            Ok(()) => candidate.bind_postgres(&mut session, &bundle).await,
            Err(fault) => Err(fault),
        };
        if death {
            assert_eq!(bound, Err(DesktopRestoreError::IsolationUnproven));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(20),
                "classified well before the 120 s effect deadline"
            );
        } else {
            bound.expect("real candidate bound through the staging-based session bind");
            let records = serde_json::to_string(&local_journal(
                &fixture.root.join("com.acosmi.wrokbot.restore-control"),
                &operation,
            ))
            .unwrap();
            assert!(
                records.contains("candidate_isolation"),
                "Isolation stage confirmed"
            );
        }
        // Fast shutdown closes the bound pool's connection; the same Child is then reaped.
        if let Some(pid) = candidate
            .original_program()
            .and_then(|program| program.original_child().id())
        {
            let _ = rustix::process::kill_process(
                rustix::process::Pid::from_raw(pid as i32).unwrap(),
                rustix::process::Signal::INT,
            );
        }
        let mut owned = Some(session);
        candidate
            .begin_wait(&mut owned)
            .expect("original wait owns the same Child");
        let reaped =
            tokio::time::timeout(std::time::Duration::from_secs(40), candidate.observe_wait())
                .await
                .expect("same Child reaped")
                .is_ok();
        assert!(reaped || death);
        drop(candidate);
        drop(fixture);
        let _ = fs::remove_dir_all(&short);
    }
    let _ = fs::remove_dir_all(&bundle_root);
}

/// A current-user store stand-in for the S23 target-slot cases: one value
/// per exact service/account pair, nothing else.
#[derive(Default)]
struct SlotMemoryStore(std::sync::Mutex<Vec<(String, String, Vec<u8>)>>);

impl SlotMemoryStore {
    fn raw(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        self.0.lock().unwrap().iter()
            .find(|entry| entry.0 == service && entry.1 == account)
            .map(|entry| entry.2.clone())
    }
}

impl crate::os_secret_store::OsSecretStore for SlotMemoryStore {
    fn read(&self, service: &str, account: &str) -> Result<Option<openbot_domain::vault::SecretBytes>, crate::os_secret_store::OsSecretStoreError> {
        Ok(self.raw(service, account).map(openbot_domain::vault::SecretBytes::new))
    }
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), crate::os_secret_store::OsSecretStoreError> {
        let mut values = self.0.lock().unwrap();
        values.retain(|entry| !(entry.0 == service && entry.1 == account));
        values.push((service.to_owned(), account.to_owned(), secret.to_vec()));
        Ok(())
    }
}

#[test]
fn t046_37_historical_master_moves_to_target_slot_and_old_slot_stays() {
    use crate::desktop_vault::{decode_stored, frame_stored};
    use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
    use openbot_domain::vault::{
        DesktopVaultCanaryBinding, DesktopVaultCanaryEnvelope, KeyVersion, Nonce, SecretBytes,
        open_desktop_vault_canary, seal_desktop_vault_canary,
    };
    let installation = "ab".repeat(32);
    let old_account = format!("desktop-vault-master-v1-{installation}");
    let new_account = format!("desktop-vault-master-v1-{installation}-r-{}", "cd".repeat(16));
    let historical = SecretBytes::new(vec![0x5a; 32]);
    let canary_binding = || DesktopVaultCanaryBinding::new("11".repeat(16), "dep", "ten", "33".repeat(16), KeyVersion::new(1)).unwrap();
    // A fixture ciphertext sealed under the historical master.
    let sealed = seal_desktop_vault_canary(&historical, &canary_binding(), Nonce::from_slice(&[7; 12]).unwrap())
        .unwrap()
        .to_column_value();
    let store = SlotMemoryStore::default();
    let original = frame_stored(&historical);
    store.write(VAULT_KEY_STORE_SERVICE, &old_account, original.expose()).unwrap();

    // The old slot is read by the original read path and decoded by the
    // original codec; the target slot gets the original frame by the original write.
    let old = decode_stored(store.read(VAULT_KEY_STORE_SERVICE, &old_account).unwrap().unwrap()).unwrap();
    let moved = frame_stored(old.secret_bytes());
    store.write(VAULT_KEY_STORE_SERVICE, &new_account, moved.expose()).unwrap();
    let readback = store.read_bounded(VAULT_KEY_STORE_SERVICE, &new_account, 33).unwrap().expect("target slot written");
    assert!(readback.ct_eq(&moved), "target slot reads back the exact frame");
    let master = decode_stored(readback).unwrap();
    open_desktop_vault_canary(master.secret_bytes(), &canary_binding(), &DesktopVaultCanaryEnvelope::parse(&sealed).unwrap())
        .expect("the moved historical master opens the fixture ciphertext");
    assert!(open_desktop_vault_canary(&SecretBytes::new(vec![0x5b; 32]), &canary_binding(), &DesktopVaultCanaryEnvelope::parse(&sealed).unwrap()).is_err());
    assert_eq!(store.raw(VAULT_KEY_STORE_SERVICE, &old_account).as_deref(), Some(original.expose()), "old slot bytes unchanged");

    // The bounded read refuses a value longer than the slot frame.
    store.write(VAULT_KEY_STORE_SERVICE, "oversized", &[1; 34]).unwrap();
    assert!(matches!(store.read_bounded(VAULT_KEY_STORE_SERVICE, "oversized", 33), Err(OsSecretStoreError::Unknown)));
    assert!(matches!(store.read_bounded(VAULT_KEY_STORE_SERVICE, &new_account, 32), Err(OsSecretStoreError::Unknown)));
    assert!(matches!(store.read_bounded(VAULT_KEY_STORE_SERVICE, "absent", 33), Ok(None)));
}

/// An administrator connection to a candidate's own UDS with one password.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
async fn candidate_admin(
    socket: &std::path::Path,
    password: &[u8],
) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
    let mut config = tokio_postgres::Config::new();
    config
        .host_path(socket)
        .port(5432)
        .user("desktop_admin")
        .dbname(openbot_infra::db::desktop_local::APPLICATION_DATABASE)
        .password(password);
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}

#[tokio::test]
#[ignore = "explicit task CAR plus BIN SBX: real staging, /usr/bin/sandbox-exec and OPENBOT_TEST_POSTGRES_BIN_DIR PostgreSQL 17.11"]
async fn t046_38_scram_rotation_acknowledges_new_password_and_rejects_old() {
    use super::candidate::CandidateGeneration;
    use openbot_infra::backup::whole_pg_restore_stream::{
        RestoredClosedHistoryRequest, verify_whole_pg_restore_input,
    };
    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = crate::postgres_sidecar::VerifiedPostgresBundle::open(
        &bundle_root,
        digest,
        &crate::postgres_sidecar::signing_identity(),
    )
    .unwrap();
    let crate_dir = std::env::current_dir().unwrap();
    let invalid_password = |error: tokio_postgres::Error| {
        error.code() == Some(&tokio_postgres::error::SqlState::INVALID_PASSWORD)
    };
    for unknown in [false, true] {
        let short = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".wb046-{}",
            &uuid::Uuid::now_v7().simple().to_string()[20..]
        ));
        DirBuilder::new().mode(0o700).create(&short).unwrap();
        std::env::set_current_dir(&short).unwrap();
        let fixture = EntryFixture::with_open_file_limit(4096);
        std::env::set_current_dir(&crate_dir).unwrap();
        s23_car_request(&fixture);
        let mut request: Value = serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
        // The bind pays the oracle trees once, each candidate SQL stage its
        // layout and history observations; every transaction its own lease.
        for (field, value) in [
            ("maxMetadataBytes", 256u64 << 20), ("maxPgConnections", 64), ("maxPgTransactions", 63),
            ("maxPgRows", 1 << 20), ("maxReconfirmRequirements", 4096), ("maxJournalRecords", 128),
            ("maxNativeTasks", 32),
        ] {
            request["profile"]["capacity"][field] = json!(value);
        }
        let profile: RestoreOperationProfile = serde_json::from_value(request["profile"].clone()).unwrap();
        fixture.write_request(&request);
        let VerifiedRestoreEntry { mut control, intent, original: _original } =
            fixture.entry().expect("original verified release/OS/request");
        let mut session = control.claim_restore(intent, profile).expect("actual same-session claim");
        let operation = session.operation_id().to_owned();
        let (input, intent) = session.frozen_input().expect("one actual held source transfer");
        let staging = verify_whole_pg_restore_input(input, intent, &mut session)
            .await
            .unwrap_or_else(|failure| panic!("actual source authentication failed: {:?}", failure.fault()));
        let target = staging.candidate_plan().target_installation_id().to_owned();
        let mut candidate = CandidateGeneration::new(staging);
        candidate.prepare_directories(&mut session).expect("directories and Isolation intent");
        candidate.prepare_postgres(&mut session).expect("staging copies and closed configuration");
        candidate.start_postgres(&mut session, &bundle).expect("sandboxed candidate started");
        candidate.bind_postgres(&mut session, &bundle).await.expect("candidate bound");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(110);
        session.upgrade_candidate_schema_before(deadline).await.expect("schema at the latest layout");
        session.retire_cohort_before(deadline).await.expect("cohort retired and sealed");
        session
            .clear_restored_closed_history_before(RestoredClosedHistoryRequest::new(deadline))
            .await
            .expect("closed history ACK2");
        let store = SlotMemoryStore::default();
        candidate.restore_artifacts(&mut session, deadline).await.expect("captured artifact root placed and rebound");
        candidate.install_target_slots(&mut session, &store).expect("both target slots matched");
        let socket = candidate.socket_directory().expect("held UDS").1.to_owned();
        let old = candidate.staging().authenticated_secrets().postgres_scram().expose().to_vec();
        let new = store
            .raw(POSTGRES_KEY_STORE_SERVICE, &format!("postgresql-17-{target}-r-{operation}"))
            .expect("new SCRAM in its target slot");
        let journal = fixture.root.join("com.acosmi.wrokbot.restore-control");
        if unknown {
            // An uncommitted ALTER of the same role holds its catalog row; the
            // rotation's own ALTER waits on it until a third connection ends
            // that backend, so its outcome is never acknowledged.
            let blocker = candidate_admin(&socket, &old).await.unwrap();
            blocker
                .batch_execute("BEGIN; ALTER ROLE desktop_admin PASSWORD 'blocker-held-change'")
                .await
                .unwrap();
            let killer = candidate_admin(&socket, &old).await.unwrap();
            let killing = tokio::spawn(async move {
                loop {
                    let ended: i64 = killer
                        .query_one(
                            "SELECT count(pg_catalog.pg_terminate_backend(pid)) FROM pg_catalog.pg_stat_activity WHERE application_name='wrokbot_restore_candidate' AND wait_event_type='Lock'",
                            &[],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    if ended > 0 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            });
            let rotated = candidate.rotate_candidate_scram(&mut session, deadline).await;
            killing.await.unwrap();
            assert!(rotated.is_err(), "an ALTER without its ACK is not acknowledged");
            blocker.batch_execute("ROLLBACK").await.unwrap();
            let records = local_journal(&journal, &operation);
            let intents = records.iter().filter(|record| record.to_string().contains("restore_scram_change")).count();
            assert!(candidate.rotate_candidate_scram(&mut session, deadline).await.is_err());
            let again = local_journal(&journal, &operation);
            assert_eq!(
                again.iter().filter(|record| record.to_string().contains("restore_scram_change")).count(),
                intents,
                "no second SCRAM change is started"
            );
            // Nothing changed the role: the old password still authenticates.
            candidate_admin(&socket, &old).await.expect("old password unchanged");
            assert!(candidate_admin(&socket, &new).await.err().is_some_and(invalid_password));
            // No publication follows an unknown change; a fast shutdown ends this leg.
            if let Some(pid) = candidate.original_program().and_then(|program| program.original_child().id()) {
                let _ = rustix::process::kill_process(
                    rustix::process::Pid::from_raw(pid as i32).unwrap(),
                    rustix::process::Signal::INT,
                );
            }
        } else {
            candidate.rotate_candidate_scram(&mut session, deadline).await.expect("timely COMMIT ACK and both proofs");
            let records = local_journal(&journal, &operation);
            let intent = records
                .iter()
                .position(|record| record.to_string().contains("restore_scram_change"))
                .expect("ScramChange intent");
            let observed = records[intent + 1].to_string();
            assert!(observed.contains("PgCommit") && observed.contains("TimelyAck"), "ALTER COMMIT acknowledged in time");
            candidate_admin(&socket, &new).await.expect("new password authenticates");
            assert!(candidate_admin(&socket, &old).await.err().is_some_and(invalid_password), "old password refused with 28P01");
            candidate
                .verify_target_installation(&mut session, deadline)
                .await
                .expect("identity, layout, sealed operation and canary under the new slot keys");
            // The production stop order: the session's clients and pool go
            // first, so the one original TERM (a smart shutdown) completes.
            candidate.release_candidate(&mut session, deadline).await.expect("candidate clients released");
            candidate.request_stop().expect("one original TERM");
        }
        let mut owned = Some(session);
        candidate.begin_wait(&mut owned).expect("original wait owns the same Child");
        let reaped = tokio::time::timeout(std::time::Duration::from_secs(40), candidate.observe_wait())
            .await
            .expect("same Child reaped")
            .is_ok();
        assert!(reaped || unknown, "the original TERM's smart shutdown completed");
        if !unknown {
            // A repeat refuses on the acknowledged state before any SQL.
            let mut session = candidate.take_wait_session().expect("original session returned");
            assert!(
                matches!(candidate.rotate_candidate_scram(&mut session, deadline).await, Err(DesktopRestoreError::DatabaseUnknown)),
                "the change is acknowledged once"
            );
        }
        drop(candidate);
        drop(fixture);
        let _ = fs::remove_dir_all(&short);
    }
    let _ = fs::remove_dir_all(&bundle_root);
}

struct ArtifactCommitRelay {
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    remaining: std::sync::Arc<AtomicU64>,
    updates: std::sync::Arc<AtomicU64>,
    dropped: std::sync::Arc<AtomicU64>,
    statements: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ArtifactCommitRelay {
    async fn start(socket: &std::path::Path) -> Self {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let real = socket.join(".s.PGSQL.1");
        let exposed = socket.join(".s.PGSQL.5432");
        fs::rename(&exposed, &real).unwrap();
        let listener = tokio::net::UnixListener::bind(&exposed).unwrap();
        fs::set_permissions(&exposed, fs::Permissions::from_mode(0o600)).unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let remaining = Arc::new(AtomicU64::new(0));
        let updates = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let statements = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let state = (armed.clone(), remaining.clone(), updates.clone(), dropped.clone(), statements.clone());
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let client = tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => accepted.unwrap().0,
                };
                let server = tokio::net::UnixStream::connect(&real).await.unwrap();
                let (armed, remaining, updates, dropped, statements) = state.clone();
                children.spawn(async move {
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = server.into_split();
                    let frontend = async {
                        // NoTls uses one length-prefixed startup packet, then
                        // regular typed messages. Never record bind/auth bytes.
                        let length = cr.read_u32().await?;
                        if !(4..=16 * 1024 * 1024).contains(&length) { return Err(std::io::Error::other("invalid owned startup frame")); }
                        let mut payload = vec![0; (length - 4) as usize];
                        cr.read_exact(&mut payload).await?;
                        sw.write_u32(length).await?;
                        sw.write_all(&payload).await?;
                        loop {
                            let kind = cr.read_u8().await?;
                            let length = cr.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) { return Err(std::io::Error::other("invalid owned frontend frame")); }
                            payload.resize((length - 4) as usize, 0);
                            cr.read_exact(&mut payload).await?;
                            if armed.load(Ordering::SeqCst) && matches!(kind, b'P' | b'Q') {
                                let start = if kind == b'P' { payload.iter().position(|b| *b == 0).unwrap() + 1 } else { 0 };
                                let end = payload[start..].iter().position(|b| *b == 0).unwrap() + start;
                                let sql = std::str::from_utf8(&payload[start..end]).unwrap();
                                let mut trace = statements.lock().unwrap();
                                assert!(trace.len() < 64);
                                trace.push(sql.to_owned());
                            }
                            sw.write_u8(kind).await?;
                            sw.write_u32(length).await?;
                            sw.write_all(&payload).await?;
                        }
                    };
                    let backend = async {
                        loop {
                            let kind = sr.read_u8().await?;
                            let length = sr.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) { return Err(std::io::Error::other("invalid owned backend frame")); }
                            let mut payload = vec![0; (length - 4) as usize];
                            sr.read_exact(&mut payload).await?;
                            if armed.load(Ordering::SeqCst) && kind == b'C' {
                                if payload == b"UPDATE 1\0" { updates.fetch_add(1, Ordering::SeqCst); }
                                if payload == b"COMMIT\0" && remaining.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)) == Ok(1) {
                                    dropped.fetch_add(1, Ordering::SeqCst);
                                    // PostgreSQL has committed; the original caller
                                    // receives neither CommandComplete nor ReadyForQuery.
                                    return Ok::<(), std::io::Error>(());
                                }
                            }
                            cw.write_u8(kind).await?;
                            cw.write_u32(length).await?;
                            cw.write_all(&payload).await?;
                        }
                    };
                    tokio::select! { result = frontend => result, result = backend => result }
                });
            }
            drop(listener);
            while let Some(joined) = children.join_next().await {
                let _transport_result = joined.expect("original relay task joined");
            }
        });
        Self { armed, remaining, updates, dropped, statements, stop: Some(stop), task: Some(task) }
    }

    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), self.task.take().unwrap())
            .await.expect("original relay converged").expect("original relay joined");
    }
}

impl Drop for ArtifactCommitRelay {
    fn drop(&mut self) {
        // A failed fixture never reports this cancellation as a successful join.
        if let Some(task) = &self.task { task.abort(); }
    }
}

#[test]
#[ignore = "explicit task CAR and real isolated PostgreSQL 17.11; actual COMMIT ACK loss over owned UDS"]
fn artifact_rebind_rejects_mismatched_source_and_never_repeats_unknown_commit() {
    crate::testing::on_large_stack(artifact_rebind_faults_run);
}

async fn artifact_rebind_faults_run() {
    use super::candidate::CandidateGeneration;
    use openbot_infra::backup::whole_pg_restore_stream::{RestoredClosedHistoryRequest, verify_whole_pg_restore_input};
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};
    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = crate::postgres_sidecar::VerifiedPostgresBundle::open(&bundle_root, digest, &crate::postgres_sidecar::signing_identity()).unwrap();
    let cwd = std::env::current_dir().unwrap();
    for mismatch in [true, false] {
        let short = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(".wb046-{}", &uuid::Uuid::now_v7().simple().to_string()[20..]));
        DirBuilder::new().mode(0o700).create(&short).unwrap();
        std::env::set_current_dir(&short).unwrap();
        let fixture = EntryFixture::with_entry_limits(4096, 384 << 20);
        std::env::set_current_dir(&cwd).unwrap();
        s23_car_request(&fixture);
        let mut request: Value = serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
        for (field, value) in [
            ("maxMetadataBytes", 384u64 << 20), ("maxPgConnections", 64), ("maxPgTransactions", 63),
            ("maxPgRows", 1 << 20), ("maxReconfirmRequirements", 4096), ("maxJournalRecords", 128), ("maxNativeTasks", 32),
        ] { request["profile"]["capacity"][field] = json!(value); }
        let profile = serde_json::from_value(request["profile"].clone()).unwrap();
        fixture.write_request(&request);
        let VerifiedRestoreEntry { mut control, intent, original: _original } = fixture.entry().unwrap();
        let mut session = control.claim_restore(intent, profile).unwrap();
        let operation = session.operation_id().to_owned();
        let (input, intent) = session.frozen_input().unwrap();
        let staging = verify_whole_pg_restore_input(input, intent, &mut session).await
            .unwrap_or_else(|failure| panic!("source authentication: {:?}", failure.fault()));
        let mut candidate = CandidateGeneration::new(staging);
        candidate.prepare_directories(&mut session).unwrap();
        candidate.prepare_postgres(&mut session).unwrap();
        candidate.start_postgres(&mut session, &bundle).unwrap();
        let deadline = candidate.effect_deadline().unwrap();
        while !fs::read_to_string(candidate.data_directory().unwrap().1.join("postmaster.pid"))
            .is_ok_and(|text| text.lines().nth(7).map(str::trim) == Some("ready"))
        {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let socket = candidate.socket_directory().unwrap().1.to_owned();
        let relay = ArtifactCommitRelay::start(&socket).await;
        candidate.bind_postgres(&mut session, &bundle).await.unwrap();
        session.upgrade_candidate_schema_before(deadline).await.unwrap();
        session.retire_cohort_before(deadline).await.unwrap();
        session.clear_restored_closed_history_before(RestoredClosedHistoryRequest::new(deadline)).await.unwrap();
        let mut config = tokio_postgres::Config::new();
        config.host_path(&socket).port(1).user("desktop_admin")
            .dbname(openbot_infra::db::desktop_local::APPLICATION_DATABASE)
            .password(candidate.staging().authenticated_secrets().postgres_scram().expose());
        let (admin, driver) = config.connect(tokio_postgres::NoTls).await.unwrap();
        let driver = tokio::spawn(driver);
        if mismatch {
            admin.batch_execute("BEGIN; ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only").await.unwrap();
            admin.execute("UPDATE openbot_internal.artifact_store_bindings SET store_id=$1", &[&uuid::Uuid::now_v7().to_string()]).await.unwrap();
            admin.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only; COMMIT").await.unwrap();
        }
        let before = admin.query_one("SELECT store_id,root_device,root_inode,root_uid FROM openbot_internal.artifact_store_bindings", &[]).await.unwrap();
        relay.remaining.store(if mismatch { 0 } else { 2 }, Ordering::SeqCst);
        relay.armed.store(true, Ordering::SeqCst);
        let outcome = candidate.restore_artifacts(&mut session, deadline).await;
        let generation = fixture.root.join("new-generation");
        let control_root = fixture.root.join("com.acosmi.wrokbot.restore-control");
        if mismatch {
            assert_eq!(outcome, Err(DesktopRestoreError::InputInvalid));
            assert!(!generation.join("artifacts").exists());
            assert_eq!(relay.updates.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(outcome, Err(DesktopRestoreError::DatabaseUnknown));
            assert_eq!(relay.dropped.load(Ordering::SeqCst), 1);
            assert_eq!(relay.updates.load(Ordering::SeqCst), 1, "the real backend updated exactly one row");
            let records = local_journal(&control_root, &operation);
            assert_eq!(candidate.restore_artifacts(&mut session, deadline).await, Err(DesktopRestoreError::DatabaseUnknown));
            assert_eq!(local_journal(&control_root, &operation), records, "re-entry observes without a new stage");
            assert_eq!(relay.updates.load(Ordering::SeqCst), 1, "no second physical update");
            let trace = relay.statements.lock().unwrap();
            let disable = trace.iter().position(|sql| sql == "ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only").unwrap();
            let begin = trace[..disable].iter().rposition(|sql| sql.starts_with("START TRANSACTION")).unwrap();
            let commit = trace[disable..].iter().position(|sql| sql == "COMMIT").unwrap() + disable;
            assert!(trace[begin].contains("READ COMMITTED") && !trace[begin].contains("READ ONLY"));
            let writes: Vec<_> = trace[begin + 1..commit].iter().filter(|sql| {
                ["ALTER", "UPDATE", "INSERT", "DELETE", "CREATE", "TRUNCATE"].iter().any(|prefix| sql.starts_with(prefix))
            }).collect();
            assert_eq!(writes.len(), 3, "only disable, the one tuple update and enable");
            assert!(writes[1].starts_with("UPDATE openbot_internal.artifact_store_bindings SET root_device="));
            assert_eq!(writes[2].as_str(), "ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only");
        }
        let after = admin.query_one("SELECT store_id,root_device,root_inode,root_uid,(SELECT tgenabled='O' FROM pg_catalog.pg_trigger WHERE tgrelid='openbot_internal.artifact_store_bindings'::regclass AND tgname='artifact_store_bindings_append_only') FROM openbot_internal.artifact_store_bindings", &[]).await.unwrap();
        assert_eq!(after.get::<_, String>(0), before.get::<_, String>(0));
        assert!(after.get::<_, bool>(4), "the dedicated transaction restored the trigger");
        if mismatch {
            for index in 1..4 { assert_eq!(after.get::<_, String>(index), before.get::<_, String>(index)); }
        } else {
            let root = fs::metadata(generation.join("artifacts")).unwrap();
            assert_eq!([after.get::<_, String>(1), after.get(2), after.get(3)],
                [root.dev().to_string(), root.ino().to_string(), root.uid().to_string()]);
        }
        assert_eq!(local_head(&control_root)["phase"], "RestorePending");
        drop(admin);
        driver.await.unwrap().unwrap();
        session.abandon_candidate_connections();
        candidate.request_stop().unwrap();
        let mut owner = Some(session);
        candidate.begin_wait(&mut owner).unwrap();
        let _pending = tokio::time::timeout(Duration::from_secs(30), candidate.observe_wait()).await.expect("original Child converged");
        relay.close().await;
        drop(candidate);
        drop(control);
        let original_records = local_journal(&control_root, &operation);
        let mut release = fixture.release();
        release.postgres = crate::postgres_sidecar::VerifiedPostgresBundle::open(&bundle_root, digest, &crate::postgres_sidecar::signing_identity()).unwrap();
        release.restore_test_store = Some(std::sync::Arc::new(SlotMemoryStore::default()));
        assert_eq!(super::run_restore_request(release, &fixture.request,
            CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap(),
            || panic!("a reopened Pending operation has no native confirmation"),
        ).await.expect("reopened operation stays read-only"), super::RestoreExecutionObservation::Pending);
        assert_eq!(local_journal(&control_root, &operation), original_records);
        drop(fixture);
        fs::remove_dir_all(short).unwrap();
    }
    fs::remove_dir_all(bundle_root).unwrap();
}

#[test]
#[ignore = "explicit task CAR and real isolated PostgreSQL 17.11; in-memory OS store only"]
fn t046_14_new_installation_restore_keeps_business_ids() {
    crate::testing::on_large_stack(t046_14_run);
}

async fn t046_14_run() {
    use std::sync::Arc;
    use super::{RestoreExecutionObservation, run_restore_request};
    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = || crate::postgres_sidecar::VerifiedPostgresBundle::open(
        &bundle_root, digest, &crate::postgres_sidecar::signing_identity(),
    ).unwrap();
    let original_cwd = std::env::current_dir().unwrap();
    let short = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(format!(".wb046-{}", &uuid::Uuid::now_v7().simple().to_string()[20..]));
    DirBuilder::new().mode(0o700).create(&short).unwrap();
    std::env::set_current_dir(&short).unwrap();
    let fixture = EntryFixture::with_entry_limits(4096, 384 << 20);
    std::env::set_current_dir(&original_cwd).unwrap();
    s23_car_request(&fixture);
    let mut request: Value = serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
    // This complete driver also pays the two artifact-binding transactions;
    // choose its finite budget before the operation, never after a rejection.
    for (field, value) in [
        ("maxMetadataBytes", 384u64 << 20), ("maxPgConnections", 64), ("maxPgTransactions", 63),
        ("maxPgRows", 1 << 20), ("maxReconfirmRequirements", 4096), ("maxJournalRecords", 128),
        ("maxNativeTasks", 32),
    ] { request["profile"]["capacity"][field] = json!(value); }
    fixture.write_request(&request);
    assert_ne!(request["expectedSourceInstallationId"], request["expectedTargetInstallationId"]);
    let store = Arc::new(SlotMemoryStore::default());
    let release = || {
        let mut release = fixture.release();
        release.postgres = bundle();
        release.restore_test_store = Some(store.clone());
        release
    };
    let actual = || CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap();
    let release_input = release();
    let request_path = fixture.request.clone();
    let actual_root = actual();
    // The fixture is prepared on the larger test stack, but the production
    // restore future is polled by a default Tokio worker, as in the launcher.
    let restored = tokio::spawn(async move {
        run_restore_request(release_input, &request_path, actual_root, || {
            panic!("a restore must not request a native confirmation or fabricate an AppHandle")
        }).await
    }).await.expect("the original restore worker joined");
    assert_eq!(restored.expect("the complete production restore driver"), RestoreExecutionObservation::Current);
    let control = fixture.root.join("com.acosmi.wrokbot.restore-control");
    let head = local_head(&control);
    assert_eq!(head["phase"], "RestoreCurrent");
    let binding = &head["data"]["binding"];
    for (field, expected) in [
        ("deploymentId", "expectedDeploymentId"), ("tenantId", "expectedTenantId"),
        ("datasetId", "expectedDatasetId"), ("sourceInstallationId", "expectedSourceInstallationId"),
        ("targetInstallationId", "expectedTargetInstallationId"),
    ] { assert_eq!(binding[field], request[expected], "{field}"); }
    let operation = request["requestId"].as_str().unwrap();
    let records = local_journal(&control, operation);
    let activation = fs::read(control.join("activation-v1")).unwrap();
    assert_eq!(run_restore_request(release(), &fixture.request, actual(), || {
        panic!("same-operation observation must not invoke native confirmation")
    }).await.expect("same request reopens only its completed journal"), RestoreExecutionObservation::Current);
    assert_eq!(fs::read(control.join("activation-v1")).unwrap(), activation);
    assert_eq!(local_journal(&control, operation), records, "re-entry writes no stage or epoch");
    assert_eq!(fs::read_dir(control.join("operations")).unwrap().count(), 1);
    drop(fixture);
    fs::remove_dir_all(short).unwrap();
    fs::remove_dir_all(bundle_root).unwrap();
}

#[test]
#[ignore = "explicit task CAR and real isolated PostgreSQL 17.11; actual publication write denial"]
fn restore_publication_write_failure_stays_pending_on_reentry() {
    crate::testing::on_large_stack(restore_publication_failure_run);
}

async fn restore_publication_failure_run() {
    use std::sync::Arc;
    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = || crate::postgres_sidecar::VerifiedPostgresBundle::open(&bundle_root, digest, &crate::postgres_sidecar::signing_identity()).unwrap();
    let cwd = std::env::current_dir().unwrap();
    let short = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(".wb046-{}", &uuid::Uuid::now_v7().simple().to_string()[20..]));
    DirBuilder::new().mode(0o700).create(&short).unwrap();
    std::env::set_current_dir(&short).unwrap();
    let fixture = EntryFixture::with_entry_limits(4096, 384 << 20);
    std::env::set_current_dir(&cwd).unwrap();
    s23_car_request(&fixture);
    let mut request: Value = serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
    request["purpose"] = json!("restore_same_installation");
    request["expectedTargetInstallationId"] = request["expectedSourceInstallationId"].clone();
    for (field, value) in [
        ("maxMetadataBytes", 384u64 << 20), ("maxPgConnections", 64), ("maxPgTransactions", 63),
        ("maxPgRows", 1 << 20), ("maxReconfirmRequirements", 4096), ("maxJournalRecords", 128), ("maxNativeTasks", 32),
    ] { request["profile"]["capacity"][field] = json!(value); }
    fixture.write_request(&request);
    let root = fixture.root.join("com.acosmi.wrokbot.restore-control");
    let publication = Arc::new(PublicationTest { read_only_root: Some(root.clone()), capacity: Default::default() });
    let store = Arc::new(SlotMemoryStore::default());
    let release = || {
        let mut release = fixture.release();
        release.postgres = bundle();
        release.restore_test_store = Some(store.clone());
        release
    };
    let mut first = release();
    first.restore_test_publication = Some(publication.clone());
    let actual = || CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap();
    let outcome = super::run_restore_request(first, &fixture.request, actual(), || panic!("restore has no native confirmation")).await;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(outcome.is_err(), "the real 0500 control root refuses publication");
    assert_eq!(local_head(&root)["phase"], "RestorePending");
    assert_eq!(publication.capacity.lock().unwrap().len(), 26, "the full driver reached publication after its actual original wait");
    assert!(!fixture.root.join("new-generation/data/postmaster.pid").exists(), "the original candidate was reaped");
    let records = local_journal(&root, request["requestId"].as_str().unwrap());
    let head = fs::read(root.join("activation-v1")).unwrap();
    assert_eq!(super::run_restore_request(release(), &fixture.request, actual(), || panic!("read-only re-entry has no native confirmation"))
        .await.unwrap(), super::RestoreExecutionObservation::Pending);
    assert_eq!(fs::read(root.join("activation-v1")).unwrap(), head);
    assert_eq!(local_journal(&root, request["requestId"].as_str().unwrap()), records);
    drop(fixture);
    fs::remove_dir_all(short).unwrap();
    fs::remove_dir_all(bundle_root).unwrap();
}

/// A narrow private stand-in for the original native confirmation owner, for
/// T046-35 only. It confirms at most once and reports the two clocks of that
/// confirmation; it opens no window and holds no authority. It is not an OS
/// measurement: it proves nothing about Touch ID, the session monitor or the
/// native owner's stop, which only the real `MacLocalAuthOwner` observes.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
struct StandInConfirmation {
    used: bool,
    session_changed: bool,
    wall_skew: std::time::Duration,
    confirmed: Option<super::entry::ConfirmedLocalOwner>,
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl StandInConfirmation {
    fn new() -> Self {
        Self { used: false, session_changed: false, wall_skew: std::time::Duration::ZERO, confirmed: None }
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl super::entry::OriginalLocalConfirmation for StandInConfirmation {
    async fn confirm_once(
        &mut self,
        effect: std::time::Instant,
        _convergence: std::time::Instant,
    ) -> Result<(), DesktopRestoreError> {
        if std::mem::replace(&mut self.used, true) {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        // The real owner reports a session change as a lost owner.
        if self.session_changed {
            return Err(DesktopRestoreError::OwnerLost);
        }
        if std::time::Instant::now() >= effect {
            return Err(DesktopRestoreError::EffectExpired);
        }
        self.confirmed = Some(super::entry::ConfirmedLocalOwner {
            at: std::time::Instant::now(),
            wall: std::time::SystemTime::now() + self.wall_skew,
        });
        Ok(())
    }

    fn take_confirmation(&mut self) -> Result<super::entry::ConfirmedLocalOwner, DesktopRestoreError> {
        self.confirmed.take().ok_or(DesktopRestoreError::ClosureUnproven)
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
#[test]
#[ignore = "explicit task CAR plus BIN SBX: real staging, /usr/bin/sandbox-exec and OPENBOT_TEST_POSTGRES_BIN_DIR PostgreSQL 17.11"]
fn t046_35_local_reconfirmation_consumes_one_os_confirmation_before_any_window() {
    crate::testing::on_large_stack(t046_35_run);
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
async fn t046_35_run() {
    use super::candidate::CandidateGeneration;
    use super::entry::{OriginalLocalConfirmationRequest, OwnedVerifiedCurrentReconfirmationEntry};
    use crate::tauri_background::{
        DesktopLocalApplicationInput, DesktopLocalReleaseInput, DesktopLocalRuntimeConfig,
        DesktopLocalRuntimeError, prepare_desktop_local_runtime,
    };
    use openbot_infra::auth::single_user::desktop_local::DesktopLocalAuthorityStore;
    use openbot_infra::backup::whole_pg_restore_stream::{
        RestoredClosedHistoryRequest, verify_whole_pg_restore_input,
    };
    use openbot_infra::recovery_control::{
        RecoveryControl, RecoveryControlConfig, RuntimeOwner,
    };
    use openbot_infra::restore_reconfirmation::CancellationToken;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = crate::postgres_sidecar::materialize_host_postgres_bundle(&bin_dir);
    let bundle = || {
        crate::postgres_sidecar::VerifiedPostgresBundle::open(
            &bundle_root,
            digest,
            &crate::postgres_sidecar::signing_identity(),
        )
        .unwrap()
    };
    let crate_dir = std::env::current_dir().unwrap();
    let short = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(format!(".wb046-{}", &uuid::Uuid::now_v7().simple().to_string()[20..]));
    DirBuilder::new().mode(0o700).create(&short).unwrap();
    std::env::set_current_dir(&short).unwrap();
    let fixture = EntryFixture::with_open_file_limit(4096);
    std::env::set_current_dir(&crate_dir).unwrap();
    s23_car_request(&fixture);
    let mut request: Value = serde_json::from_slice(&fs::read(&fixture.request).unwrap()).unwrap();
    for (field, value) in [
        ("maxMetadataBytes", 256u64 << 20), ("maxPgConnections", 64), ("maxPgTransactions", 63),
        ("maxPgRows", 1 << 20), ("maxReconfirmRequirements", 4096), ("maxJournalRecords", 128),
        ("maxNativeTasks", 32),
    ] {
        request["profile"]["capacity"][field] = json!(value);
    }
    let profile: RestoreOperationProfile = serde_json::from_value(request["profile"].clone()).unwrap();
    fixture.write_request(&request);

    // The real restore to RestoreCurrent, in the production order.
    let VerifiedRestoreEntry { mut control, intent, original: _original } =
        fixture.entry().expect("original verified release/OS/request");
    let mut session = control.claim_restore(intent, profile).expect("actual same-session claim");
    let (input, intent) = session.frozen_input().expect("one actual held source transfer");
    let staging = verify_whole_pg_restore_input(input, intent, &mut session)
        .await
        .unwrap_or_else(|failure| panic!("actual source authentication failed: {:?}", failure.fault()));
    let mut candidate = CandidateGeneration::new(staging);
    candidate.prepare_directories(&mut session).expect("directories and Isolation intent");
    candidate.prepare_postgres(&mut session).expect("staging copies and closed configuration");
    candidate.start_postgres(&mut session, &bundle()).expect("sandboxed candidate started");
    candidate.bind_postgres(&mut session, &bundle()).await.expect("candidate bound");
    let deadline = Instant::now() + Duration::from_secs(110);
    session.upgrade_candidate_schema_before(deadline).await.expect("schema at the latest layout");
    session.retire_cohort_before(deadline).await.expect("cohort retired and sealed");
    session
        .clear_restored_closed_history_before(RestoredClosedHistoryRequest::new(deadline))
        .await
        .expect("closed history ACK2");
    let store = Arc::new(SlotMemoryStore::default());
    candidate.restore_artifacts(&mut session, deadline).await.expect("captured artifact root placed and rebound");
    candidate.install_target_slots(&mut session, &*store).expect("both target slots matched");
    let scram = candidate.rotate_candidate_scram(&mut session, deadline).await.expect("SCRAM change acknowledged");
    let readbacks = candidate
        .verify_target_installation(&mut session, deadline)
        .await
        .expect("installation read back under the new slot keys");
    candidate.release_candidate(&mut session, deadline).await.expect("candidate clients released");
    candidate.request_stop().expect("one original TERM");
    let mut owned = Some(session);
    candidate.begin_wait(&mut owned).expect("original wait owns the same Child");
    tokio::time::timeout(Duration::from_secs(40), candidate.observe_wait())
        .await
        .expect("same Child reaped")
        .expect("smart shutdown completed");
    let mut session = candidate.take_wait_session().expect("original session returned");
    let exit = candidate.program_result().and_then(|result| result.candidate_exit())
        .expect("original birth, Child wait and real pipe joins");
    session
        .publish_restore_current_before(scram, readbacks, exit, deadline)
        .await
        .expect("RestoreCurrent published");
    drop(session);
    drop(candidate);
    drop(control);
    assert_eq!(local_head(&fixture.root.join("com.acosmi.wrokbot.restore-control"))["phase"], "RestoreCurrent");

    // The Manager keeps its original app-data leaf. Current selects the
    // separately published generation from the original verified journal.
    let generation = fixture.root.join("new-generation");
    let app = || CurrentOsUserAppDataRoot::from_current_os_user_app_data(&fixture.app).unwrap();
    let bootstrap = fixture.release().recovery.clone().expect("release recovery control");
    let owners = [
        RuntimeOwner::PostgresSidecar,
        RuntimeOwner::SqlDriver,
        RuntimeOwner::ApplicationAssembly,
        RuntimeOwner::DesktopAgentRelay,
        RuntimeOwner::DesktopAgent,
    ];
    let runtime = || {
        let control =
            RecoveryControl::open(RecoveryControlConfig::local(app(), bootstrap.host_limits.clone()).unwrap()).unwrap();
        control
            .open_local_before(
                &DesktopLocalAuthorityStore::new(app()),
                bootstrap.release_digest,
                [VAULT_KEY_STORE_SERVICE, POSTGRES_KEY_STORE_SERVICE],
                bootstrap.bounds,
                &owners,
            )
            .expect("the Current head enrolls a runtime")
    };
    let dist = crate::postgres_sidecar::materialize_desktop_dist();
    let startup = || {
        let release = DesktopLocalReleaseInput::new(
            dist.clone(),
            "openbot",
            "main",
            bundle(),
            crate::postgres_sidecar::ReviewedPostgresKeyStoreService::from_reviewed_release(POSTGRES_KEY_STORE_SERVICE)
                .unwrap(),
            crate::desktop_vault::ReviewedDesktopVaultKeyStoreService::from_reviewed_release(VAULT_KEY_STORE_SERVICE)
                .unwrap(),
            store.clone(),
        )
        .unwrap();
        let application = DesktopLocalApplicationInput::new(
            crate::DesktopOpenAiProviderInput::new("https://api.example.test/v1", Vec::new()).unwrap(),
            crate::DesktopAgentBudgets::new(Some(Duration::from_secs(2)), Some(Duration::from_secs(1_800)), 16_384)
                .unwrap(),
        )
        .unwrap();
        DesktopLocalRuntimeConfig::new(release, application, |authority| {
            Ok(crate::postgres_sidecar::loaded_desktop_package(authority.auth_context().tenant().as_str()))
        })
        .with_recovery_bootstrap(bootstrap.clone())
    };

    // Before any confirmation the Current gate keeps startup closed: no
    // installation, principal or window is formed from a Pending binding.
    let refused = prepare_desktop_local_runtime(app(), startup()).await.err();
    assert!(
        matches!(refused, Some(DesktopLocalRuntimeError::RecoveryRequired)),
        "an unconfirmed Current opens nothing: {refused:?}"
    );

    let reconfirm = |native: StandInConfirmation, cancel: CancellationToken, request_id: uuid::Uuid| {
        let mut release = fixture.release();
        release.postgres = bundle();
        let mut current = request.clone();
        current.as_object_mut().unwrap().remove("profile");
        current["purpose"] = json!("reconfirm_current_binding");
        current["requestId"] = json!(request_id.simple().to_string());
        current["trustedInputSelection"] = json!({"localSubject":"current_os_owner"});
        current["limits"] = json!({"effectNs":60_000_000_000u64,"convergenceNs":10_000_000_000u64,"maxConfirmations":1});
        let path = fixture.root.join("requests").join(format!("current-{}.json", request_id.simple()));
        fs::write(&path, serde_json::to_vec(&current).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut original = RestoreEntryInput::new();
        let (control, intent) = original.verify(&mut release, app(), &std::env::current_exe().unwrap(), &path).unwrap();
        let mut verified = VerifiedRestoreEntry { control, intent, original };
        let (runtime, sql, convergence) = verified.control.enter_current_reconfirmation(
            &mut verified.intent, &DesktopLocalAuthorityStore::new(app()), &owners, cancel.clone(),
        ).expect("the closed Current request selects the actual source and target");
        assert!(verified.control.enter_current_reconfirmation(
            &mut verified.intent, &DesktopLocalAuthorityStore::new(app()), &owners, cancel.clone(),
        ).is_err(), "the original request is consumed once");
        let entry = OwnedVerifiedCurrentReconfirmationEntry::new(app(), runtime).unwrap();
        let request = OriginalLocalConfirmationRequest::new(native, sql.deadline(), convergence, cancel, sql).unwrap();
        let store = store.clone();
        async move {
            let result = release.reconfirm_restored_local_owner_for_test(entry, request, &*store).await;
            drop(verified);
            result
        }
    };
    // A cancelled request, a session change, a confirmation already used and
    // a wall clock ahead of the request each write no receipt.
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        reconfirm(StandInConfirmation::new(), cancel, uuid::Uuid::now_v7()).await.unwrap_err(),
        DesktopRestoreError::OwnerLost,
        "cancelled"
    );
    let mut changed = StandInConfirmation::new();
    changed.session_changed = true;
    assert_eq!(reconfirm(changed, CancellationToken::new(), uuid::Uuid::now_v7()).await.unwrap_err(), DesktopRestoreError::OwnerLost);
    let mut used = StandInConfirmation::new();
    used.used = true;
    assert_eq!(reconfirm(used, CancellationToken::new(), uuid::Uuid::now_v7()).await.unwrap_err(), DesktopRestoreError::EntryInvalid);
    let mut ahead = StandInConfirmation::new();
    ahead.wall_skew = Duration::from_secs(3_600);
    assert_eq!(reconfirm(ahead, CancellationToken::new(), uuid::Uuid::now_v7()).await.unwrap_err(), DesktopRestoreError::OwnerLost);
    // One confirmation of the real Current, both clocks inside the request:
    // the Local actor's fresh_local_os receipt and its audit commit together.
    let confirmation_request_id = uuid::Uuid::now_v7();
    let fact = reconfirm(StandInConfirmation::new(), CancellationToken::new(), confirmation_request_id)
        .await
        .expect("one confirmed request writes its receipt");

    // Startup's consumption of the Current now passes its gate: the one
    // restricted factory forms the installation over the running data plane.
    let mut runtime = runtime();
    let site = runtime.restored_local_site(&app()).unwrap().expect("a restored site");
    let (installation, prepared, vault) = crate::desktop_local_bootstrap::open_current_installation(
        &mut runtime,
        site,
        bundle(),
        store.as_ref(),
        &crate::postgres_sidecar::ReviewedPostgresKeyStoreService::from_reviewed_release(POSTGRES_KEY_STORE_SERVICE)
            .unwrap(),
        &crate::desktop_vault::ReviewedDesktopVaultKeyStoreService::from_reviewed_release(VAULT_KEY_STORE_SERVICE)
            .unwrap(),
    )
    .await
    .map_err(|(failure, ..)| failure)
    .expect("the confirmed Current forms its installation");
    assert_eq!(installation.sidecar_data_dir(), generation.join("data"));
    let client = prepared.pool().get().await.unwrap();
    let receipts = client
        .query(
            "SELECT confirmation_id, confirmed_by, proof_kind, proof_ref FROM openbot_internal.restore_reconfirm_receipts r
              JOIN openbot_internal.restore_reconfirm_requirements q USING (requirement_id)
             WHERE q.source_kind='subject'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(receipts.len(), 1, "exactly one receipt; the refused requests wrote none");
    assert_eq!(receipts[0].get::<_, uuid::Uuid>(0), fact.confirmation_id());
    assert_eq!(receipts[0].get::<_, String>(1), openbot_infra::auth::single_user::desktop_local::DESKTOP_LOCAL_ACTOR_ID);
    assert_eq!(receipts[0].get::<_, String>(2), "fresh_local_os");
    assert_eq!(receipts[0].get::<_, uuid::Uuid>(3), confirmation_request_id, "the original request ID is the one proof reference");
    let audited: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM public.audit_events WHERE target_id=$1",
            &[&fact.requirement_id().to_string()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 1);
    drop(client);
    drop(vault);
    let (exit, observations) = prepared.shutdown().await.map_err(|(error, ..)| error).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut facts: Vec<_> = [RuntimeOwner::ApplicationAssembly, RuntimeOwner::DesktopAgentRelay, RuntimeOwner::DesktopAgent]
        .into_iter()
        .map(|owner| openbot_infra::recovery_control::RuntimeCloseFact::PassiveRetirement {
            object: openbot_infra::recovery_control::PassiveObjectKind::NeverStarted(owner),
        })
        .collect();
    facts.extend(crate::desktop_local_bootstrap::sidecar_close_fact(Ok(exit)));
    facts.extend(
        crate::desktop_local_bootstrap::sql_driver_close_fact(
            crate::desktop_local_bootstrap::SqlDriverOutcome::Observed(observations),
            deadline,
        )
        .await,
    );
    runtime
        .close_before(openbot_infra::recovery_control::RuntimeCloseResources::new(facts), deadline)
        .await
        .expect("the consuming runtime closes");

    // Continue through the complete startup, including the existing artifact
    // reader. The restore's dedicated transaction must leave its trigger on.
    let running = prepare_desktop_local_runtime(app(), startup()).await.expect("complete Current startup");
    let client = running.pool().get().await.unwrap();
    let enabled: bool = client.query_one(
        "SELECT tgenabled='O' FROM pg_catalog.pg_trigger WHERE tgrelid='openbot_internal.artifact_store_bindings'::regclass AND tgname='artifact_store_bindings_append_only'",
        &[],
    ).await.unwrap().get(0);
    assert!(enabled);
    drop(client);
    running.shutdown().await.unwrap();

    // The same real restored PG is opened by the complete startup again.
    // Only the marker's store ID changes; the ordinary binding reader must
    // refuse it and must not rewrite either the marker or the PG tuple.
    let marker_path = generation.join("artifacts/.artifact-store-v1");
    let original_marker = fs::read(&marker_path).unwrap();
    let mut wrong: Value = serde_json::from_slice(&original_marker).unwrap();
    wrong["storeId"] = json!(uuid::Uuid::now_v7().to_string());
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).unwrap();
    let wrong_bytes = serde_json::to_vec(&wrong).unwrap();
    fs::write(&marker_path, &wrong_bytes).unwrap();
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(prepare_desktop_local_runtime(app(), startup()).await,
        Err(DesktopLocalRuntimeError::Application)), "mismatched marker refuses complete startup");
    assert_eq!(fs::read(&marker_path).unwrap(), wrong_bytes, "startup never replaces the existing marker");
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&marker_path, &original_marker).unwrap();
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o400)).unwrap();
    prepare_desktop_local_runtime(app(), startup()).await.expect("restoring only original marker bytes reopens startup")
        .shutdown().await.unwrap();
    drop(fixture);
    let _ = fs::remove_dir_all(&short);
    let _ = fs::remove_dir_all(&bundle_root);
    let _ = fs::remove_dir_all(&dist);
}
