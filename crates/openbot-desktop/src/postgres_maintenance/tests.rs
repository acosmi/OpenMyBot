use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{MaintenanceError, bundle};

fn fresh_root(label: &str) -> PathBuf {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).expect("test CSPRNG");
    let parent = std::env::temp_dir()
        .canonicalize()
        .expect("existing test temp parent");
    let root = parent.join(format!("wb44-{label}-{}", bundle::encode_hex(&nonce)));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("new private test root");
    // Keep these small fixtures on failure as well. No test traverses an existing user directory.
    root
}
fn put(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("test bytes");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("test permissions");
}
fn macho(file_type: u32, import: Option<&str>) -> Vec<u8> {
    let mut commands = Vec::new();
    let mut string_command = |kind: u32, offset: u32, text: &str| {
        let len = (offset as usize + text.len() + 1 + 7) & !7;
        let mut command = vec![0; len];
        command[..4].copy_from_slice(&kind.to_le_bytes());
        command[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        command[8..12].copy_from_slice(&offset.to_le_bytes());
        command[offset as usize..offset as usize + text.len()].copy_from_slice(text.as_bytes());
        commands.extend(command);
    };
    let count = if let Some(import) = import {
        string_command(0xc, 24, import);
        string_command(0x8000001c, 12, "@executable_path/../lib");
        2_u32
    } else {
        string_command(0xd, 24, "@rpath/libpq.5.dylib");
        1_u32
    };
    let mut header = vec![0; 32];
    header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    let cpu = match std::env::consts::ARCH {
        "aarch64" => 0x0100000c_u32,
        "x86_64" => 0x01000007,
        _ => panic!("test arch"),
    };
    header[4..8].copy_from_slice(&cpu.to_le_bytes());
    header[12..16].copy_from_slice(&file_type.to_le_bytes());
    header[16..20].copy_from_slice(&count.to_le_bytes());
    header[20..24].copy_from_slice(&(commands.len() as u32).to_le_bytes());
    header.extend(commands);
    header
}
struct Fixture {
    root: PathBuf,
    digest: [u8; 32],
    manifest: Value,
}
impl Fixture {
    fn new(escape: bool) -> Self {
        let root = fresh_root("bundle");
        let resource = root.join("postgres-maintenance");
        fs::create_dir(&resource).expect("resource");
        for dir in ["bin", "lib", "share"] {
            fs::create_dir(resource.join(dir)).expect("closed directory");
        }
        let program = macho(
            2,
            Some(if escape {
                "/usr/local/lib/unreviewed.dylib"
            } else {
                "@rpath/libpq.5.dylib"
            }),
        );
        let library = macho(6, None);
        let mut files = Vec::new();
        for (path, bytes, mode) in [
            ("bin/postgres", program.as_slice(), 0o755_u32),
            ("bin/initdb", program.as_slice(), 0o755),
            ("bin/pg_ctl", program.as_slice(), 0o755),
            ("bin/wrokbot-pg-basebackup", program.as_slice(), 0o755),
            ("lib/libpq.5.dylib", library.as_slice(), 0o644),
            ("share/postgres.bki", b"unit-fixture".as_slice(), 0o644),
        ] {
            put(&resource.join(path), bytes, mode);
            files.push(json!({"path":path,"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"mode":mode}));
        }
        files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        let derived = [
            ("src/bin/pg_basebackup/pg_basebackup.c", true),
            ("src/bin/pg_basebackup/streamutil.c", true),
            ("src/bin/pg_basebackup/streamutil.h", true),
            ("src/bin/pg_basebackup/receivelog.c", true),
            ("src/bin/pg_basebackup/receivelog.h", true),
            ("src/bin/pg_basebackup/walmethods.c", true),
            ("src/bin/pg_basebackup/wrokbot_owner.c", false),
            ("src/bin/pg_basebackup/wrokbot_owner.h", false),
            ("src/bin/pg_basebackup/Makefile", true),
            ("src/interfaces/libpq/fe-connect.c", true),
            ("src/common/logging.c", true),
        ]
        .into_iter()
        .map(|(path, old)| {
            let unchanged_header = match path {
                "src/bin/pg_basebackup/streamutil.h" => Some((2540, "82451cfacf2e033cc33923563d14e7cdd41ae0c09e1f76e3d54ffa40e975e62d")),
                "src/bin/pg_basebackup/receivelog.h" => Some((1889, "88e5bfdf7aec9dd7db8ee8b3d02bbbd25235513e72592d968c39b41f29a5ee6a")),
                _ => None,
            };
            if let Some((bytes, sha256)) = unchanged_header {
                return json!({"path":path,"before":{"bytes":bytes,"sha256":sha256},"after":{"bytes":bytes,"sha256":sha256}});
            }
            json!({"path":path,
            "before":if old{json!({"bytes":1,"sha256":"0".repeat(64)})}else{Value::Null},
            "after":{"bytes":2,"sha256":"1".repeat(64)}})
        })
        .collect::<Vec<_>>();
        let tools=["git","shell","make","compiler","archiver","ranlib","linker","compilerResolved","linkerResolved","otool"]
            .into_iter().map(|role|json!({"role":role,"path":format!("/reviewed-unit/{role}"),"bytes":1,"sha256":"2".repeat(64)}))
            .chain(bundle::FIXED_INTERNAL_TOOLS.into_iter().map(|(role,path,bytes,sha256)|json!({"role":role,"path":path,"bytes":bytes,"sha256":sha256}))).collect::<Vec<_>>();
        let manifest = json!({
            "schema":"openbot-postgres-maintenance-bundle","schema_version":2,"postgres_version":"17.11",
            "source_archive_bytes":28397423,"source_archive_sha256":crate::postgres_sidecar::POSTGRES_SOURCE_SHA256,
            "product_patch_bytes":2,"product_patch_sha256":"3".repeat(64),"recipe_sha256":"4".repeat(64),
            "build_profile_sha256":"5".repeat(64),"release_epoch":5,"minimum_core_version":env!("CARGO_PKG_VERSION"),
            "platform":"macos","arch":std::env::consts::ARCH,
            "programs":{"postgres":"bin/postgres","initdb":"bin/initdb","pg_ctl":"bin/pg_ctl","basebackup":"bin/wrokbot-pg-basebackup"},
            "files":files,"derived_sources":derived,"build_tools":tools
        });
        let mut fixture = Self {
            root,
            digest: [0; 32],
            manifest,
        };
        fixture.reseal();
        fixture
    }
    fn reseal(&mut self) {
        let inner = serde_json::to_vec(&self.manifest).expect("unit JSON");
        put(
            &self.root.join("postgres-maintenance/manifest.json"),
            &inner,
            0o644,
        );
        let outer = json!({"schema":"wrokbot-pg-maintenance-release","schema_version":1,
            "postgres":{"root":"postgres-maintenance","manifest_sha256":format!("{:x}",Sha256::digest(&inner))}});
        let outer = serde_json::to_vec(&outer).expect("outer JSON");
        put(&self.root.join(bundle::OUTER_FILE), &outer, 0o644);
        self.digest = Sha256::digest(&outer).into();
    }
    fn verify(&self) -> Result<bundle::VerifiedMaintenanceBundle, MaintenanceError> {
        bundle::verify_bundle(&self.root, bundle::fixture_binding(self.digest))
    }
}

#[test]
fn v1_bundle_contract_is_unchanged() {
    use crate::postgres_sidecar::{
        PostgresBundleDigest, ReviewedPostgresSigningIdentity, VerifiedPostgresBundle,
    };
    let root = fresh_root("v1");
    fs::create_dir(root.join("bin")).expect("bin");
    let mut files = BTreeMap::new();
    for path in ["bin/postgres", "bin/initdb", "bin/pg_ctl"] {
        let bytes = path.as_bytes();
        put(&root.join(path), bytes, 0o755);
        files.insert(path, format!("{:x}", Sha256::digest(bytes)));
    }
    let mut manifest = json!({
        "schema":"openbot-postgres-sidecar-bundle","schema_version":1,"platform":"macos","arch":std::env::consts::ARCH,
        "postgresql_version":"17.11","source_archive_sha256":crate::postgres_sidecar::POSTGRES_SOURCE_SHA256,
        "release_epoch":openbot_contracts::engine::ENGINE_RELEASE_EPOCH,
        "minimum_compatible_core":env!("CARGO_PKG_VERSION"),"signing_identity":"Wrok Bot unit fixture only",
        "programs":{"postgres":"bin/postgres","initdb":"bin/initdb","pg_ctl":"bin/pg_ctl"},"files":files
    });
    let identity =
        ReviewedPostgresSigningIdentity::from_reviewed_release("Wrok Bot unit fixture only")
            .expect("fixture identity");
    let bytes = serde_json::to_vec(&manifest).expect("manifest");
    put(&root.join("manifest.json"), &bytes, 0o644);
    let digest =
        PostgresBundleDigest::from_hex(&format!("{:x}", Sha256::digest(&bytes))).expect("digest");
    let old =
        VerifiedPostgresBundle::open(&root, digest, &identity).expect("unchanged three-role v1");
    assert!(old.postgres().ends_with("bin/postgres"));
    assert!(old.initdb().ends_with("bin/initdb"));
    assert!(old.pg_ctl().ends_with("bin/pg_ctl"));
    manifest["programs"]["basebackup"] = json!("bin/wrokbot-pg-basebackup");
    let bytes = serde_json::to_vec(&manifest).expect("manifest");
    put(&root.join("manifest.json"), &bytes, 0o644);
    let digest =
        PostgresBundleDigest::from_hex(&format!("{:x}", Sha256::digest(&bytes))).expect("digest");
    assert!(VerifiedPostgresBundle::open(&root, digest, &identity).is_err());
}

#[test]
fn source_authenticated_bundle_rejects_self_expected_extra_program_and_library_escape() {
    let good = Fixture::new(false);
    assert_eq!(
        good.manifest["derived_sources"].as_array().unwrap().len(),
        11
    );
    assert!(good.verify().is_ok());
    assert_eq!(good.manifest["build_tools"].as_array().unwrap().len(), 31);
    let mut missing_fixed = Fixture::new(false);
    missing_fixed.manifest["build_tools"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["role"] != "nm");
    missing_fixed.reseal();
    assert!(matches!(
        missing_fixed.verify(),
        Err(MaintenanceError::BuildToolUnavailable)
    ));
    let mut changed_fixed = Fixture::new(false);
    let row = changed_fixed.manifest["build_tools"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["role"] == "nm")
        .unwrap();
    row["sha256"] = json!("0".repeat(64));
    changed_fixed.reseal();
    assert!(matches!(
        changed_fixed.verify(),
        Err(MaintenanceError::BuildToolUnavailable)
    ));
    for header in [
        "src/bin/pg_basebackup/streamutil.h",
        "src/bin/pg_basebackup/receivelog.h",
    ] {
        let mut changed = Fixture::new(false);
        let row = changed.manifest["derived_sources"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["path"] == header)
            .unwrap();
        row["after"]["bytes"] = json!(1);
        changed.reseal();
        assert!(matches!(
            changed.verify(),
            Err(MaintenanceError::DerivedTreeMismatch)
        ));
    }
    let mut unchanged_product = Fixture::new(false);
    unchanged_product.manifest["derived_sources"][0]["before"] =
        unchanged_product.manifest["derived_sources"][0]["after"].clone();
    unchanged_product.reseal();
    assert!(matches!(
        unchanged_product.verify(),
        Err(MaintenanceError::DerivedTreeMismatch)
    ));
    assert!(matches!(
        bundle::verify_bundle(&good.root, bundle::fixture_binding([0; 32])),
        Err(MaintenanceError::BundleInvalid)
    ));
    put(
        &good.root.join("postgres-maintenance/bin/pg_dump"),
        b"extra",
        0o755,
    );
    assert!(matches!(
        good.verify(),
        Err(MaintenanceError::BundleInvalid)
    ));
    let escaping = Fixture::new(true);
    assert!(matches!(
        escaping.verify(),
        Err(MaintenanceError::LibraryClosureInvalid)
    ));
    let empty_dir = Fixture::new(false);
    fs::create_dir(empty_dir.root.join("postgres-maintenance/unregistered"))
        .expect("extra directory");
    assert!(matches!(
        empty_dir.verify(),
        Err(MaintenanceError::BundleInvalid)
    ));
    let mut unknown = Fixture::new(false);
    unknown.manifest["expected_sha256"] = json!("0".repeat(64));
    unknown.reseal();
    assert!(matches!(
        unknown.verify(),
        Err(MaintenanceError::BundleInvalid)
    ));
    let mut role = Fixture::new(false);
    role.manifest["build_tools"][0]["role"] = json!("discover-on-PATH");
    role.reseal();
    assert!(matches!(
        role.verify(),
        Err(MaintenanceError::BuildToolUnavailable)
    ));
}

#[test]
fn missing_compiled_binding_never_runs_native() {
    assert!(bundle::compiled_value_is_missing(None));
    assert!(bundle::compiled_value_is_missing(Some("")));
    assert!(bundle::compiled_value_is_missing(Some(&"A".repeat(64))));
    assert!(bundle::compiled_value_is_missing(Some("self-expected")));
    // The only production authority constructor reads the compiled value. CLI has no expected,
    // credential, force, URL or arbitrary program switch, including in a valid-bound build.
    for values in [
        vec!["verify", "--bundle", "/bundle", "--expected", "abc"],
        vec![
            "selftest-owned",
            "--bundle",
            "/bundle",
            "--new-owned-root",
            "/new",
            "--profile",
            "/p",
            "--force",
        ],
        vec!["selftest-owned", "--database-url", "postgres://sensitive"],
        vec!["verify", "--bundle", "/bundle", "--bundle", "/other"],
    ] {
        let values = values
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        assert!(super::parse_cli(&values).is_err());
    }
}

#[test]
fn fixture_adhoc_is_not_production_signature() {
    let mut fixture = Fixture::new(false);
    let verified = fixture.verify().expect("source-authenticated unit fixture");
    let receipt = serde_json::to_value(verified.verification_receipt()).expect("receipt");
    assert_eq!(receipt["source_authenticated"], true);
    assert_eq!(receipt["platform_signature_verified"], false);
    assert_eq!(receipt["production_release_authorized"], false);
    fixture.manifest["signing_identity"] = json!("-");
    fixture.reseal();
    assert!(matches!(
        fixture.verify(),
        Err(MaintenanceError::BundleInvalid)
    ));
}
