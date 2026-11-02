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
        Self::with_open_file_limit(256)
    }

    fn with_open_file_limit(max_open_files: u64) -> Self {
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
