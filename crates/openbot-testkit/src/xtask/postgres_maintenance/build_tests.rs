//! Four directed build contracts; native PG/build execution has its separate gates.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wrokbot-maintenance-build-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
fn budget() -> Budget {
    Budget {
        end: clock().unwrap().checked_add(30_000_000_000).unwrap(),
        close: clock().unwrap().checked_add(60_000_000_000).unwrap(),
        direct_limit: 1,
        direct_commands: 0,
        live_process_cap: None,
        owned: None,
    }
}
fn fixture_pins(path: &str, before: FileDigest, after: FileDigest) -> Pins {
    Pins {
        schema: "wrokbot-pg-maintenance-pins".into(),
        schema_version: 1,
        source: PinSource {
            version: "17.11".into(),
            archive_bytes: manifest::ARCHIVE_BYTES,
            archive_sha256: manifest::ARCHIVE_SHA.into(),
        },
        patch: PinPatch {
            path: "tools/patches/postgresql-17.11-wrokbot-basebackup-owner-v1.patch".into(),
            bytes: 1,
            sha256: "1".repeat(64),
        },
        bundle: PinBundle {
            schema: "openbot-postgres-maintenance-bundle".into(),
            schema_version: 2,
            release_epoch: 5,
            programs: Programs::exact(),
        },
        derived_sources: vec![DerivedSource {
            path: path.into(),
            before: Some(before),
            after,
        }],
    }
}
#[test]
fn official_cache_stays_unchanged_and_derived_patch_is_exact() {
    #[cfg(target_os = "macos")]
    {
        // A fixed root-owned external tool may be a genuine Apple hardlink. This checks the
        // dedicated mechanical reader only; a test digest never creates release authority.
        let path = Path::new("/usr/bin/git");
        let bytes = fs::read(path).unwrap();
        let expected = manifest::digest_bytes(&bytes);
        assert_eq!(
            hash_fixed_system_tool(path, expected.bytes).unwrap(),
            expected
        );
        assert!(hash_fixed_system_tool(path, expected.bytes - 1).is_err());
        // The global source/output reader must still reject that hardlink if one is present.
        if fs::symlink_metadata(path).unwrap().nlink() > 1 {
            assert!(manifest::hash_regular(path, expected.bytes).is_err());
        }
    }
    let p = pins(&repo()).unwrap();
    let patch = manifest::read_regular(&repo().join(&p.patch.path), p.patch.bytes).unwrap();
    assert_eq!(
        manifest::digest_bytes(&patch),
        FileDigest {
            bytes: p.patch.bytes,
            sha256: p.patch.sha256
        }
    );
    let names = validate_patch_scope(&patch).unwrap();
    assert!(names.contains("src/bin/pg_basebackup/wrokbot_owner.c"));
    assert!(names.contains("src/interfaces/libpq/fe-connect.c"));
    assert_eq!(p.derived_sources.len(), 11);
    assert_eq!(
        p.derived_sources
            .iter()
            .filter(|s| s.before.is_none())
            .count(),
        2
    );
    // The same preimage checker is applied to a distinct derivative, never to a reference tree.
    let f = Fixture::new();
    let original = f.0.join("official");
    let derived = f.0.join("derived");
    fresh_dir(&original).unwrap();
    fresh_dir(&derived).unwrap();
    fs::write(original.join("source.c"), b"official source\n").unwrap();
    fs::copy(original.join("source.c"), derived.join("source.c")).unwrap();
    let before = manifest::digest_bytes(b"official source\n");
    let after = manifest::digest_bytes(b"derived source\n");
    let p = fixture_pins("source.c", before.clone(), after);
    preimages(&derived, &p, &budget(), false).unwrap();
    fs::write(derived.join("source.c"), b"derived source\n").unwrap();
    preimages(&derived, &p, &budget(), true).unwrap();
    assert_eq!(
        manifest::hash_regular(&original.join("source.c"), 128).unwrap(),
        before
    );
}
#[test]
fn build_rejects_patch_escape_unknown_file_and_preimage_mismatch() {
    for path in ["../outside.c", "/tmp/outside.c", "src/backend/postmaster.c"] {
        let patch = format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-a\n+b\n");
        assert!(validate_patch_scope(patch.as_bytes()).is_err());
    }
    assert!(
        validate_patch_scope(
            b"--- a/src/common/logging.c\n+++ b/src/bin/pg_basebackup/streamutil.c\n"
        )
        .is_err()
    );
    assert!(validate_patch_scope(b"GIT binary patch\n").is_err());
    let f = Fixture::new();
    fs::write(f.0.join("source.c"), b"wrong preimage\n").unwrap();
    let p = fixture_pins(
        "source.c",
        manifest::digest_bytes(b"expected\n"),
        manifest::digest_bytes(b"after\n"),
    );
    assert!(preimages(&f.0, &p, &budget(), false).is_err());
    assert_eq!(fs::read(f.0.join("source.c")).unwrap(), b"wrong preimage\n");
}
#[test]
fn bundle_manifest_has_four_programs_no_self_hash_cycle() {
    let f = Fixture::new();
    let cpu = match std::env::consts::ARCH {
        "aarch64" => 0x0100000c_u32,
        "x86_64" => 0x01000007,
        _ => panic!("unsupported test architecture"),
    };
    for kind in [2_u32, 6, 8] {
        let mut header = [0u8; 32];
        header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        header[4..8].copy_from_slice(&cpu.to_le_bytes());
        header[12..16].copy_from_slice(&kind.to_le_bytes());
        let path = f.0.join(format!("PGXS-kind-{kind}"));
        fs::write(&path, header).unwrap();
        assert_eq!(runtime_library_file(&path).unwrap(), matches!(kind, 6 | 8));
        header[4..8].copy_from_slice(&(cpu ^ 1).to_le_bytes());
        fs::write(&path, header).unwrap();
        assert!(!runtime_library_file(&path).unwrap());
    }
    let resource = f.0.join(manifest::RESOURCE_ROOT);
    fresh_dir(&resource).unwrap();
    fresh_dir(&resource.join("bin")).unwrap();
    for role in Programs::exact().paths() {
        fs::write(resource.join(role), format!("fixture {role}\n")).unwrap();
        fs::set_permissions(resource.join(role), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let inventory = manifest::collect(&resource, 32, 4096).unwrap();
    assert_eq!(inventory.len(), 4);
    assert!(!inventory.iter().any(|f| f.path == manifest::INNER_FILE));
    let p = pins(&repo()).unwrap();
    let m = Manifest {
        schema: "openbot-postgres-maintenance-bundle".into(),
        schema_version: 2,
        postgres_version: "17.11".into(),
        source_archive_bytes: manifest::ARCHIVE_BYTES,
        source_archive_sha256: manifest::ARCHIVE_SHA.into(),
        product_patch_bytes: p.patch.bytes,
        product_patch_sha256: p.patch.sha256,
        recipe_sha256: "2".repeat(64),
        build_profile_sha256: "3".repeat(64),
        release_epoch: 5,
        minimum_core_version: env!("CARGO_PKG_VERSION").into(),
        platform: "macos".into(),
        arch: std::env::consts::ARCH.into(),
        programs: Programs::exact(),
        files: inventory,
        derived_sources: p.derived_sources,
        build_tools: [
            "git",
            "shell",
            "make",
            "compiler",
            "archiver",
            "ranlib",
            "linker",
            "compilerResolved",
            "linkerResolved",
            "otool",
        ]
        .into_iter()
        .map(|role| BuildTool {
            role: role.into(),
            path: "/usr/bin/git".into(),
            bytes: 1,
            sha256: "4".repeat(64),
        })
        .chain(
            manifest::FIXED_INTERNAL_TOOLS
                .into_iter()
                .map(|(role, path, bytes, sha256)| BuildTool {
                    role: role.into(),
                    path: path.into(),
                    bytes,
                    sha256: sha256.into(),
                }),
        )
        .collect(),
    };
    let inner = serde_json::to_vec(&m).unwrap();
    write_new(&resource.join(manifest::INNER_FILE), &inner).unwrap();
    let outer = Outer {
        schema: "wrokbot-pg-maintenance-release".into(),
        schema_version: 1,
        postgres: OuterPostgres {
            root: manifest::RESOURCE_ROOT.into(),
            manifest_sha256: manifest::digest_bytes(&inner).sha256,
        },
    };
    write_new(
        &f.0.join(manifest::OUTER_FILE),
        &serde_json::to_vec(&outer).unwrap(),
    )
    .unwrap();
    let facts = manifest::inspect(&f.0, None).unwrap();
    assert_eq!(facts.program_count, 4);
    assert!(!facts.source_authenticated);
    assert!(!facts.platform_signature_verified);
    assert!(!facts.production_release_authorized);
    fs::write(resource.join("bin/initdb"), b"changed\n").unwrap();
    assert!(manifest::inspect(&f.0, None).is_err());
}
#[test]
fn build_profile_and_child_deadline_are_explicit() {
    // Pure calculation only: never change the shared test runner's real limits.
    let inherited = rustix::process::Rlimit {
        current: Some(64),
        maximum: Some(128),
    };
    assert_eq!(
        finite_process_capacity(32, inherited, 501, 501).unwrap(),
        rustix::process::Rlimit {
            current: Some(32),
            maximum: Some(32),
        }
    );
    for (n, uid, euid) in [
        (0, 501, 501),
        (65, 501, 501),
        (32, 0, 0),
        (32, 501, 0),
        (32, 501, 502),
        (i64::MAX as u64, 501, 501),
    ] {
        assert!(finite_process_capacity(n, inherited, uid, euid).is_err());
    }
    assert!(
        finite_process_capacity(
            32,
            rustix::process::Rlimit {
                current: None,
                maximum: Some(31),
            },
            501,
            501,
        )
        .is_err()
    );
    assert!(
        finite_process_capacity(
            32,
            rustix::process::Rlimit {
                current: None,
                maximum: None
            },
            501,
            501,
        )
        .is_ok()
    );
    let l = Limits {
        effect_ns: 1,
        convergence_ns: 2,
        max_archive_bytes: manifest::ARCHIVE_BYTES,
        max_expanded_source_bytes: 1,
        max_source_files: 1,
        max_derived_bytes: 1,
        max_install_bytes: 1,
        max_bundle_bytes: 1,
        max_build_files: 1,
        max_build_processes: 12,
        max_build_jobs: 1,
        max_tool_output_bytes: 1,
        capacity_reserve_bytes: 1,
        free_floor_bytes: 1,
    };
    let v = serde_json::to_value(&l).unwrap();
    let mut bounded: Limits = serde_json::from_value(v.clone()).unwrap();
    let mut missing = v.clone();
    missing.as_object_mut().unwrap().remove("effectNs");
    assert!(serde_json::from_value::<Limits>(missing).is_err());
    let mut unknown = v;
    unknown["defaultDeadline"] = 1.into();
    assert!(serde_json::from_value::<Limits>(unknown).is_err());
    let mut overflow = l;
    overflow.effect_ns = u64::MAX;
    assert!(Budget::new(&overflow).is_err());
    assert!(serde_json::from_value::<Utilities>(serde_json::json!({})).is_err());
    let explicit_nulls = serde_json::json!({
        "awk":null,"basename":null,"cat":null,"chmod":null,"cp":null,"cut":null,
        "dirname":null,"expr":null,"find":null,"grep":null,"head":null,"install":null,
        "ln":null,"mkdir":null,"mv":null,"perl":null,"pwd":null,"rm":null,"sed":null,
        "sort":null,"tail":null,"test":null,"tr":null,"uname":null
    });
    assert!(serde_json::from_value::<Utilities>(explicit_nulls.clone()).is_ok());
    let tool = || Tool {
        path: "/usr/bin/git".into(),
        bytes: 1,
        sha256: "1".repeat(64),
    };
    bounded.max_expanded_source_bytes = 4096;
    bounded.max_derived_bytes = 1;
    let mut profile = Profile {
        schema: "wrokbot-pg-maintenance-build-profile".into(),
        schema_version: 1,
        operation: "1".repeat(32),
        platform: Platform {
            os: "macos".into(),
            arch: std::env::consts::ARCH.into(),
        },
        source: Source {
            archive_bytes: manifest::ARCHIVE_BYTES,
            archive_sha256: manifest::ARCHIVE_SHA.into(),
        },
        patch: FileDigest {
            bytes: 1,
            sha256: "1".repeat(64),
        },
        limits: bounded,
        recipe: Recipe {
            configure_argv: vec![],
            make_argv: vec![],
            install_argv: vec![],
            loader_rewrite: None,
            environment: Environment {
                path: String::new(),
                cc: String::new(),
                ar: String::new(),
                ranlib: String::new(),
                sdkroot: String::new(),
                deployment: String::new(),
                cflags: String::new(),
                cppflags: String::new(),
                ldflags: String::new(),
                locale: String::new(),
            },
        },
        tools: Tools {
            git: tool(),
            shell: tool(),
            make: tool(),
            compiler: tool(),
            archiver: tool(),
            ranlib: tool(),
            linker: tool(),
            otool: None,
            install_name_tool: None,
            sdk: Sdk {
                path: "/fixture/sdk".into(),
                tree_sha256: "1".repeat(64),
                version: "fixture".into(),
            },
            system_utilities: serde_json::from_value(explicit_nulls).unwrap(),
            configure_source: ConfigureSource {
                relative_path: "configure".into(),
                bytes: 1,
                sha256: "1".repeat(64),
            },
        },
    };
    // This isolates archive-capacity admission; it does not authenticate a fixture as PG source.
    let environment = serde_json::to_value(&profile.recipe.environment).unwrap();
    assert_eq!(environment.as_object().unwrap().len(), 11);
    assert!(environment.get("DEVELOPER_DIR").is_none());
    assert_ne!(
        actual_recipe_hash(&profile.recipe).unwrap(),
        manifest::digest_bytes(&serde_json::to_vec(&profile.recipe).unwrap()).sha256
    );
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("postgresql-17.11/test.c").unwrap();
    header.set_size(9);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, &b"123456789"[..]).unwrap();
    let raw = tar.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&raw).unwrap();
    let gzip = gzip.finish().unwrap();
    assert!(archive_inventory(&gzip, &profile, &budget()).is_err());
    profile.limits.max_derived_bytes = 4096;
    assert!(archive_inventory(&gzip, &profile, &budget()).is_ok());
    // All four programs spend the same budget as subsequent lib/share files.
    // The violating destination must not be created, including a fourth program.
    let f = Fixture::new();
    let source = f.0.join("program");
    fs::write(&source, b"123").unwrap();
    for (case, bytes, files, accepted) in [
        ("bytes", 11, 64, 3),
        ("files", 64, 3, 3),
        ("after-four", 12, 64, 4),
    ] {
        profile.limits.max_bundle_bytes = bytes;
        profile.limits.max_build_files = files;
        let target = f.0.join(case);
        fresh_dir(&target).unwrap();
        let (mut sum, mut count) = (0u64, 0u64);
        for index in 0..accepted {
            copy_bundle_file(
                &source,
                &target.join(format!("program-{index}")),
                0o755,
                &profile,
                &budget(),
                &mut sum,
                &mut count,
            )
            .unwrap();
        }
        let rejected = target.join("rejected");
        assert!(
            copy_bundle_file(
                &source,
                &rejected,
                0o644,
                &profile,
                &budget(),
                &mut sum,
                &mut count,
            )
            .is_err()
        );
        assert!(!rejected.exists());
        assert_eq!((sum, count), (accepted * 3, accepted));
    }
}
