//! Private owned-FS preparation checks. The PG immutable binding and actor/source authority are
//! exercised separately; preparing a syntactically valid marker does not establish either.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{
    ArtifactRootPhysicalBinding, ArtifactStoreError, MARKER_NAME, MAX_MARKER_BYTES, StoreMarker,
    open_trusted_host_root, open_trusted_installation_artifact_root, prepare_root, read_marker,
};

struct OwnedRoot {
    container: PathBuf,
    root: PathBuf,
}

impl OwnedRoot {
    fn new() -> Self {
        let container =
            std::env::temp_dir().join(format!("openbot-artifact-root-{}", Uuid::now_v7()));
        DirBuilder::new().mode(0o700).create(&container).unwrap();
        // macOS may expose the temporary directory through an alias. Positive paths explicitly
        // resolve only our new container; negative tests then create their own symlink components.
        let container = fs::canonicalize(container).unwrap();
        let root = container.join("root");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { container, root }
    }

    fn open(&self) -> File {
        File::open(&self.root).unwrap()
    }

    fn marker_path(&self) -> PathBuf {
        self.root.join(MARKER_NAME)
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let outcome = fs::remove_dir_all(&self.container);
        let absent = !self.container.exists();
        eprintln!(
            "ARTIFACT_ROOT_UNIT_CLEANUP removed={} absent={absent}",
            outcome.is_ok()
        );
        if !std::thread::panicking() {
            assert!(outcome.is_ok() && absent, "owned root cleanup failed");
        }
    }
}

fn namespace() -> (String, String, String) {
    (
        "owned-test-deployment".to_owned(),
        "owned-test-tenant".to_owned(),
        "018f0000-aaaa-7aaa-8aaa-aaaaaaaaaaaa".to_owned(),
    )
}

fn marker() -> StoreMarker {
    let ns = namespace();
    StoreMarker {
        schema: 1,
        deployment_id: ns.0,
        tenant_id: ns.1,
        dataset_id: ns.2,
        store_id: "018f0000-bbbb-7bbb-8bbb-bbbbbbbbbbbb".to_owned(),
    }
}

fn actual_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn empty_private_root_gets_a_sealed_canonical_marker_and_reopens_without_minting_identity() {
    let owned = OwnedRoot::new();
    let prepared = prepare_root(owned.open(), namespace()).unwrap();
    let actual = prepared.root.0.metadata().unwrap();
    assert!(prepared.fresh_marker);
    assert_eq!(actual.mode() & 0o7777, 0o700);
    assert_eq!(actual.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(prepared.physical.device(), actual.dev().to_string());
    assert_eq!(prepared.physical.inode(), actual.ino().to_string());
    assert_eq!(prepared.physical.uid(), actual.uid().to_string());
    let marker_metadata = fs::symlink_metadata(owned.marker_path()).unwrap();
    assert!(marker_metadata.is_file());
    assert_eq!(marker_metadata.mode() & 0o7777, 0o400);
    assert_eq!(marker_metadata.nlink(), 1);
    assert_eq!(marker_metadata.uid(), actual.uid());
    let id = Uuid::parse_str(&prepared.marker.store_id).unwrap();
    assert_eq!(id.get_version_num(), 7);
    assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    assert_eq!(id.to_string(), prepared.marker.store_id);
    assert_eq!(prepared.marker.schema, 1);
    assert_eq!(
        fs::read(owned.marker_path()).unwrap(),
        prepared.marker_bytes
    );
    assert_eq!(
        serde_json::to_vec(&prepared.marker).unwrap(),
        prepared.marker_bytes
    );
    let bytes = prepared.marker_bytes.clone();
    let physical = prepared.physical.clone();
    drop(prepared);
    let reopened = prepare_root(owned.open(), namespace()).unwrap();
    assert!(!reopened.fresh_marker);
    assert_eq!(reopened.marker_bytes, bytes);
    assert_eq!(reopened.physical, physical);
}

#[test]
fn actual_independently_opened_descriptor_cannot_acquire_a_live_kernel_owner_lock() {
    let owned = OwnedRoot::new();
    let first = prepare_root(owned.open(), namespace()).unwrap();
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::Busy)
    ));
    drop(first);
    assert!(prepare_root(owned.open(), namespace()).is_ok());
}

#[test]
fn release_is_not_delayed_by_a_concurrent_spawn() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let owned = OwnedRoot::new();
    let stop = AtomicBool::new(false);
    let mut cycles = 0_u64;
    let failure = std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    std::process::Command::new("/bin/sleep")
                        .arg("0")
                        .spawn()
                        .unwrap()
                        .wait()
                        .unwrap();
                }
            });
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut prepared = prepare_root(owned.open(), namespace());
        while prepared.is_ok() && Instant::now() < deadline {
            drop(prepared);
            prepared = prepare_root(owned.open(), namespace());
            cycles += 1;
        }
        stop.store(true, Ordering::Relaxed);
        prepared.err()
    });
    assert!(
        failure.is_none(),
        "re-prepare after release failed on cycle {cycles}: {failure:?}"
    );
}

#[test]
fn actual_root_modes_must_be_exactly_private_and_do_not_create_markers_on_refusal() {
    let owned = OwnedRoot::new();
    for mode in [0o600, 0o755, 0o777, 0o1700] {
        fs::set_permissions(&owned.root, Permissions::from_mode(mode)).unwrap();
        let result = prepare_root(owned.open(), namespace());
        fs::set_permissions(&owned.root, Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(ArtifactStoreError::UnsafeRoot)));
        assert!(!owned.marker_path().exists());
    }
}

#[test]
fn a_regular_file_descriptor_is_not_a_directory_root() {
    let owned = OwnedRoot::new();
    let path = owned.container.join("regular-file");
    actual_file(&path, b"owned content", 0o700);
    assert!(matches!(
        prepare_root(File::open(path).unwrap(), namespace()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(!owned.marker_path().exists());
}

#[test]
fn nonempty_unmarked_root_is_refused_without_adopting_existing_data() {
    let owned = OwnedRoot::new();
    let existing = owned.root.join("existing-owned-data");
    actual_file(&existing, b"existing content", 0o600);
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::BindingMismatch)
    ));
    assert_eq!(fs::read(existing).unwrap(), b"existing content");
    assert!(!owned.marker_path().exists());
}

#[test]
fn each_changed_namespace_component_refuses_the_unchanged_sealed_marker() {
    let owned = OwnedRoot::new();
    let original = prepare_root(owned.open(), namespace()).unwrap();
    let bytes = original.marker_bytes.clone();
    drop(original);
    for changed in [
        (
            "changed-deployment".to_owned(),
            namespace().1,
            namespace().2,
        ),
        (namespace().0, "changed-tenant".to_owned(), namespace().2),
        (
            namespace().0,
            namespace().1,
            "018f0000-cccc-7ccc-8ccc-cccccccccccc".to_owned(),
        ),
    ] {
        assert!(matches!(
            prepare_root(owned.open(), changed),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn copying_a_valid_marker_does_not_copy_the_actual_physical_root_tuple() {
    let original = OwnedRoot::new();
    let prepared = prepare_root(original.open(), namespace()).unwrap();
    let bytes = prepared.marker_bytes.clone();
    let physical = prepared.physical.clone();
    let store_id = prepared.marker.store_id.clone();
    drop(prepared);
    let copied = OwnedRoot::new();
    actual_file(&copied.marker_path(), &bytes, 0o400);
    // This private preparation helper parses local syntax. The actual PG factory separately
    // rejects the different root tuple; marker syntax alone must never be reported as that GO.
    let local = prepare_root(copied.open(), namespace()).unwrap();
    assert!(!local.fresh_marker);
    assert_eq!(local.marker.store_id, store_id);
    assert_eq!(local.marker_bytes, bytes);
    assert_ne!(local.physical, physical);
}

#[test]
fn invalid_json_unknown_fields_and_noncanonical_serialization_are_refused() {
    let canonical = serde_json::to_vec(&marker()).unwrap();
    let mut unknown = serde_json::to_value(marker()).unwrap();
    unknown["callerRoot"] = serde_json::Value::String("untrusted".to_owned());
    let mut trailing_whitespace = canonical.clone();
    trailing_whitespace.push(b'\n');
    let fixtures = [
        b"not JSON".to_vec(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec_pretty(&marker()).unwrap(),
        trailing_whitespace,
    ];
    for bytes in fixtures {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &bytes, 0o400);
        assert!(matches!(
            prepare_root(owned.open(), namespace()),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn marker_schema_uuid_version_variant_and_canonical_case_are_checked() {
    let mut bad_schema = marker();
    bad_schema.schema = 2;
    let mut wrong_version = marker();
    wrong_version.store_id = "018f0000-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned();
    let mut wrong_variant = marker();
    wrong_variant.store_id = "018f0000-bbbb-7bbb-0bbb-bbbbbbbbbbbb".to_owned();
    let mut wrong_case = marker();
    wrong_case.store_id = wrong_case.store_id.to_ascii_uppercase();
    let mut invalid_id = marker();
    invalid_id.store_id = "opaque-store-id".to_owned();
    for fixture in [
        bad_schema,
        wrong_version,
        wrong_variant,
        wrong_case,
        invalid_id,
    ] {
        let owned = OwnedRoot::new();
        let bytes = serde_json::to_vec(&fixture).unwrap();
        actual_file(&owned.marker_path(), &bytes, 0o400);
        assert!(matches!(
            prepare_root(owned.open(), namespace()),
            Err(ArtifactStoreError::BindingMismatch)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn actual_marker_mode_must_be_exactly_read_only_for_the_current_owner() {
    let bytes = serde_json::to_vec(&marker()).unwrap();
    for mode in [0o600, 0o444, 0o640, 0o700] {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &bytes, mode);
        assert!(matches!(
            read_marker(&owned.open()),
            Err(ArtifactStoreError::UnsafeRoot)
        ));
        assert_eq!(fs::read(owned.marker_path()).unwrap(), bytes);
    }
}

#[test]
fn actual_marker_symlink_is_refused_and_its_owned_target_is_unchanged() {
    let owned = OwnedRoot::new();
    let target = owned.container.join("target-marker");
    let bytes = serde_json::to_vec(&marker()).unwrap();
    actual_file(&target, &bytes, 0o400);
    symlink(&target, owned.marker_path()).unwrap();
    assert!(matches!(
        prepare_root(owned.open(), namespace()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::read(target).unwrap(), bytes);
    assert!(
        fs::symlink_metadata(owned.marker_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_second_actual_hard_link_prevents_marker_acceptance() {
    let owned = OwnedRoot::new();
    let bytes = serde_json::to_vec(&marker()).unwrap();
    actual_file(&owned.marker_path(), &bytes, 0o400);
    fs::hard_link(owned.marker_path(), owned.container.join("second-link")).unwrap();
    assert_eq!(fs::metadata(owned.marker_path()).unwrap().nlink(), 2);
    assert!(matches!(
        read_marker(&owned.open()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn empty_or_oversized_actual_marker_is_unsafe_instead_of_an_absent_marker() {
    for length in [0, MAX_MARKER_BYTES + 1] {
        let owned = OwnedRoot::new();
        actual_file(&owned.marker_path(), &vec![b'x'; length as usize], 0o400);
        assert!(matches!(
            read_marker(&owned.open()),
            Err(ArtifactStoreError::UnsafeRoot)
        ));
        assert_eq!(fs::metadata(owned.marker_path()).unwrap().len(), length);
    }
}

#[test]
fn a_directory_at_the_marker_name_is_not_a_marker() {
    let owned = OwnedRoot::new();
    DirBuilder::new()
        .mode(0o700)
        .create(owned.marker_path())
        .unwrap();
    assert!(matches!(
        read_marker(&owned.open()),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn trusted_host_open_uses_the_actual_current_uid_and_rejects_relative_or_parent_paths() {
    let owned = OwnedRoot::new();
    let actual = open_trusted_host_root(&owned.root).unwrap();
    let observed = ArtifactRootPhysicalBinding::observe(&actual).unwrap();
    assert_eq!(
        observed.uid(),
        rustix::process::geteuid().as_raw().to_string()
    );
    assert_eq!(
        observed.inode(),
        fs::metadata(&owned.root).unwrap().ino().to_string()
    );
    assert!(matches!(
        open_trusted_host_root(Path::new("relative-owned-root")),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    let with_parent = owned.container.join("root/../root");
    assert!(matches!(
        open_trusted_host_root(&with_parent),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
}

#[test]
fn trusted_host_open_refuses_a_real_symlink_in_a_parent_component() {
    let owned = OwnedRoot::new();
    let alias = owned.container.join("alias-parent");
    symlink(&owned.container, &alias).unwrap();
    assert!(matches!(
        open_trusted_host_root(&alias.join("root")),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::metadata(&owned.root).unwrap().mode() & 0o7777, 0o700);
    assert!(!owned.marker_path().exists());
}

#[test]
fn trusted_host_open_refuses_a_real_symlink_for_the_final_directory() {
    let owned = OwnedRoot::new();
    let alias = owned.container.join("alias-root");
    symlink(&owned.root, &alias).unwrap();
    assert!(matches!(
        open_trusted_host_root(&alias),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(!owned.marker_path().exists());
}

#[test]
fn trusted_installation_creates_only_the_private_fixed_child_and_reopens_its_identity() {
    let owned = OwnedRoot::new();
    let first = open_trusted_installation_artifact_root(&owned.root).unwrap();
    let child = owned.root.join("artifacts");
    let first_metadata = first.metadata().unwrap();
    assert_eq!(first_metadata.mode() & 0o7777, 0o700);
    assert_eq!(first_metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(first_metadata.ino(), fs::metadata(&child).unwrap().ino());
    assert_eq!(
        first_metadata.dev(),
        fs::metadata(&owned.root).unwrap().dev()
    );
    let entries = fs::read_dir(&owned.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![std::ffi::OsString::from("artifacts")]);
    drop(first);
    let reopened = open_trusted_installation_artifact_root(&owned.root).unwrap();
    assert_eq!(reopened.metadata().unwrap().ino(), first_metadata.ino());
    assert_eq!(reopened.metadata().unwrap().dev(), first_metadata.dev());
}

#[test]
fn trusted_installation_refuses_an_existing_symlink_child_without_replacing_it() {
    let owned = OwnedRoot::new();
    let target = owned.container.join("owned-child-target");
    DirBuilder::new().mode(0o700).create(&target).unwrap();
    let existing = target.join("keep");
    actual_file(&existing, b"keep", 0o600);
    let child = owned.root.join("artifacts");
    symlink(&target, &child).unwrap();
    assert!(matches!(
        open_trusted_installation_artifact_root(&owned.root),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert!(
        fs::symlink_metadata(child)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(existing).unwrap(), b"keep");
}

#[test]
fn trusted_installation_refuses_an_existing_nonprivate_child_without_changing_mode() {
    let owned = OwnedRoot::new();
    let child = owned.root.join("artifacts");
    DirBuilder::new().mode(0o755).create(&child).unwrap();
    assert!(matches!(
        open_trusted_installation_artifact_root(&owned.root),
        Err(ArtifactStoreError::UnsafeRoot)
    ));
    assert_eq!(fs::metadata(child).unwrap().mode() & 0o7777, 0o755);
}

fn guarded_root_owned_inode_fds(identities: &[(u64, u64)]) -> BTreeSet<(u64, u64, u32)> {
    let sample = || {
        #[cfg(target_os = "linux")]
        {
            let mut found = BTreeSet::new();
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                let entry = entry.unwrap();
                let Ok(fd) = entry.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if identities.contains(&(metadata.dev(), metadata.ino())) {
                    found.insert((metadata.dev(), metadata.ino(), fd));
                }
            }
            found
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Read as _;
            use std::process::{Command, Stdio};
            let pid = std::process::id();
            let mut child = Command::new("/usr/sbin/lsof")
                .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("own-PID FD observation unavailable (Unproven)");
            let child_pid = child.id();
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let output = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
            });
            let errors = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            // Join both original pipe owners before interpreting either result or panicking.
            let output = output.join();
            let errors = errors.join();
            let output = output.unwrap().unwrap();
            let errors = errors.unwrap().unwrap();
            assert!(
                status
                    .as_ref()
                    .is_some_and(std::process::ExitStatus::success)
            );
            assert!(output.len() <= 65_536 && output.ends_with(b"\n"));
            assert!(
                errors.is_empty(),
                "own-PID FD observation stderr (Unproven)"
            );
            let text = std::str::from_utf8(&output).unwrap();
            let mut own_pid = false;
            let (mut fd, mut device, mut inode) = (None, None, None);
            let mut found = BTreeSet::new();
            for line in text.lines().chain(std::iter::once("f")) {
                let (kind, value) = line.split_at_checked(1).unwrap();
                match kind {
                    "p" => {
                        assert_eq!(value.parse::<u32>().unwrap(), pid);
                        own_pid = true;
                    }
                    "f" => {
                        if let Some(&(original_device, original_inode)) =
                            identities
                                .iter()
                                .find(|&&(original_device, original_inode)| {
                                    device == Some(original_device & u64::from(u32::MAX))
                                        && inode == Some(original_inode)
                                })
                        {
                            found.insert((original_device, original_inode, fd.unwrap()));
                        }
                        fd = value.parse::<u32>().ok();
                        device = None;
                        inode = None;
                    }
                    "D" => {
                        device = Some(if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16).unwrap()
                        } else {
                            value.parse::<u64>().unwrap()
                        });
                    }
                    "i" => inode = Some(value.parse::<u64>().unwrap()),
                    _ => panic!("own-PID FD observation unknown field (Unproven)"),
                }
            }
            assert!(own_pid, "own-PID FD observation missing PID (Unproven)");
            eprintln!(
                "ARTIFACT_GUARDED_FD_ORACLE child_pid={child_pid} natural_zero=true reaped=true pipe_workers_joined=true matching_fds={}",
                found.len()
            );
            found
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            panic!("actual owned FD oracle unsupported (Unproven)")
        }
    };
    let first = sample();
    let second = sample();
    assert_eq!(first, second, "owned original inode FD inventory unstable");
    first
}

fn guarded_prepared_root_is_current(prepared: &super::PreparedRoot) -> bool {
    ArtifactRootPhysicalBinding::observe(&prepared.root.0) == Ok(prepared.physical.clone())
        && read_marker(&prepared.root.0) == Ok(Some(prepared.marker_bytes.clone()))
}

// Genuine PreparedRoot/kernel and ByteStore on the original root. No PG-installed Store,
// actor/Host witness or DatasetBoundArtifactStore is constructed or certified here.
#[test]
fn prepared_root_kernel_marker_and_bound_byte_directory_currentness_are_rechecked() {
    for leg in [
        "current",
        "marker-bytes",
        "marker-mode",
        "marker-link",
        "marker-symlink",
        "root-mode",
        "fixed-child",
    ] {
        let owned = OwnedRoot::new();
        let prepared = prepare_root(owned.open(), namespace()).unwrap();
        assert!(guarded_prepared_root_is_current(&prepared));
        let original_root = prepared.root.0.metadata().unwrap();
        let root_identity = (original_root.dev(), original_root.ino());
        let root_fd = u32::try_from(prepared.root.0.as_raw_fd()).unwrap();
        assert!(matches!(
            prepare_root(owned.open(), namespace()),
            Err(ArtifactStoreError::Busy)
        ));
        let byte_root = prepared.root.0.try_clone().unwrap();
        let byte_root_fd = u32::try_from(byte_root.as_raw_fd()).unwrap();
        let bytes =
            crate::artifact_bytes::ArtifactByteStore::bind_private_root(byte_root, 4096).unwrap();
        assert_ne!(root_fd, byte_root_fd);
        let id = Uuid::now_v7();
        let actual = b"real prepared-root byte object";
        let path = owned.root.join("objects").join(id.to_string());
        actual_file(&path, actual, 0o400);
        let tuple = |path: &Path| {
            let metadata = fs::symlink_metadata(path).unwrap();
            (metadata.dev(), metadata.ino())
        };
        let leaf_identity = tuple(&path);
        let mut identities = vec![
            root_identity,
            tuple(&owned.root.join("objects")),
            tuple(&owned.root.join("staging")),
            tuple(&owned.marker_path()),
            leaf_identity,
        ];
        let initial_fds = guarded_root_owned_inode_fds(&identities);
        assert_eq!(initial_fds.len(), 4);
        assert!(initial_fds.contains(&(root_identity.0, root_identity.1, root_fd)));
        assert!(initial_fds.contains(&(root_identity.0, root_identity.1, byte_root_fd)));
        let backup = owned.container.join("original-marker");
        let target = owned.container.join("owned-marker-target");
        let mut leaf_seen = false;
        let mut changed = false;
        let result = bytes.probe_actual_guarded_before(
            id,
            Instant::now() + Duration::from_secs(30),
            &mut |phase| {
                if phase == crate::artifact_bytes::ArtifactProbePhase::AfterHashSegment
                    && !leaf_seen
                {
                    assert_eq!(guarded_root_owned_inode_fds(&[leaf_identity]).len(), 1);
                    leaf_seen = true;
                }
                if phase == crate::artifact_bytes::ArtifactProbePhase::AfterHashSegment
                    && leg != "current"
                    && !changed
                {
                    match leg {
                        "marker-bytes" => {
                            let changed_marker = StoreMarker {
                                schema: prepared.marker.schema,
                                deployment_id: prepared.marker.deployment_id.clone(),
                                tenant_id: prepared.marker.tenant_id.clone(),
                                dataset_id: prepared.marker.dataset_id.clone(),
                                store_id: Uuid::now_v7().to_string(),
                            };
                            fs::set_permissions(owned.marker_path(), Permissions::from_mode(0o600))
                                .unwrap();
                            let mut file = OpenOptions::new()
                                .write(true)
                                .truncate(true)
                                .open(owned.marker_path())
                                .unwrap();
                            file.write_all(&serde_json::to_vec(&changed_marker).unwrap())
                                .unwrap();
                            file.sync_all().unwrap();
                            fs::set_permissions(owned.marker_path(), Permissions::from_mode(0o400))
                                .unwrap();
                            file.sync_all().unwrap();
                        }
                        "marker-mode" => {
                            fs::set_permissions(owned.marker_path(), Permissions::from_mode(0o600))
                                .unwrap();
                        }
                        "marker-link" => {
                            fs::hard_link(owned.marker_path(), &backup).unwrap();
                            assert_eq!(fs::metadata(owned.marker_path()).unwrap().nlink(), 2);
                        }
                        "marker-symlink" => {
                            fs::rename(owned.marker_path(), &backup).unwrap();
                            actual_file(&target, &prepared.marker_bytes, 0o400);
                            identities.push(tuple(&target));
                            symlink(&target, owned.marker_path()).unwrap();
                        }
                        "root-mode" => {
                            fs::set_permissions(&owned.root, Permissions::from_mode(0o755))
                                .unwrap();
                        }
                        "fixed-child" => {
                            let objects = owned.root.join("objects");
                            fs::rename(&objects, owned.root.join("retired-objects")).unwrap();
                            DirBuilder::new().mode(0o700).create(&objects).unwrap();
                            identities.push(tuple(&objects));
                        }
                        _ => unreachable!(),
                    }
                    changed = true;
                }
                // This real private physical predicate can only refuse. It is not a Host
                // observation or proof that the PG-installed Store wrapper ran in this test.
                !guarded_prepared_root_is_current(&prepared)
            },
        );
        assert!(leaf_seen);
        if leg == "current" {
            match result {
                crate::artifact_bytes::ArtifactByteProbe::Retained {
                    location,
                    byte_length,
                    sha256,
                } => {
                    assert_eq!(
                        location,
                        crate::artifact_bytes::ArtifactByteStorageLocation::Object
                    );
                    assert_eq!(byte_length, actual.len() as u64);
                    assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(actual)));
                }
                _ => panic!("actual prepared-root stable bytes were not retained"),
            }
            let absent_id = Uuid::now_v7();
            assert!(matches!(
                bytes.probe_actual_guarded_before(
                    absent_id,
                    Instant::now() + Duration::from_secs(30),
                    &mut |_| !guarded_prepared_root_is_current(&prepared)
                ),
                crate::artifact_bytes::ArtifactByteProbe::Absent
            ));
            assert_eq!(
                fs::read(owned.marker_path()).unwrap(),
                prepared.marker_bytes
            );
        } else {
            assert!(
                changed
                    && matches!(
                        result,
                        crate::artifact_bytes::ArtifactByteProbe::Indeterminate
                    )
            );
        }
        let original_leaf = if leg == "fixed-child" {
            owned.root.join("retired-objects").join(id.to_string())
        } else {
            path
        };
        assert_eq!(fs::read(original_leaf).unwrap(), actual);
        if leg == "root-mode" {
            fs::set_permissions(&owned.root, Permissions::from_mode(0o700)).unwrap();
        }
        // A syntactically matching marker on another real root cannot match this physical tuple.
        if leg == "current" {
            let copied = OwnedRoot::new();
            actual_file(&copied.marker_path(), &prepared.marker_bytes, 0o400);
            let other = prepare_root(copied.open(), namespace()).unwrap();
            assert_eq!(other.marker_bytes, prepared.marker_bytes);
            assert_ne!(other.physical, prepared.physical);
            let other_identity = tuple(&copied.root);
            assert_eq!(guarded_root_owned_inode_fds(&[other_identity]).len(), 1);
            drop(other);
            assert!(guarded_root_owned_inode_fds(&[other_identity]).is_empty());
            let copied_container = copied.container.clone();
            drop(copied);
            assert!(matches!(fs::symlink_metadata(copied_container),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        }
        assert_eq!(
            guarded_root_owned_inode_fds(&identities),
            initial_fds,
            "probe kept an original leaf/marker or temporary reopened child FD"
        );
        drop(bytes);
        assert_eq!(
            guarded_root_owned_inode_fds(&identities),
            BTreeSet::from([(root_identity.0, root_identity.1, root_fd)])
        );
        drop(prepared);
        assert!(guarded_root_owned_inode_fds(&identities).is_empty());
        let reacquired = owned.open();
        reacquired
            .try_lock()
            .expect("original root kernel owner did not actually end");
        reacquired.unlock().unwrap();
        drop(reacquired);
        assert!(guarded_root_owned_inode_fds(&identities).is_empty());
        let container = owned.container.clone();
        drop(owned);
        assert!(matches!(fs::symlink_metadata(container),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        eprintln!(
            "ARTIFACT_GUARDED_PREPARED_ROOT_TAIL leg={leg} actual_leaf_fd_seen=true byte_store_fds_absent=true original_root_fd_absent=true kernel_reacquired_and_unlocked=true scratch_removed=true"
        );
    }
}
