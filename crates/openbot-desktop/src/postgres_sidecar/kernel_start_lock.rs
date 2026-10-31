//! Persistent per-instance kernel lock used to distinguish a live startup owner from residue.

use super::{PostgresSidecarError, encode_hex, sync_directory, valid_instance_id};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

const GUARD_HEADER: &str = "openbot-postgres-owner-guard-v1";
const CANDIDATE_NONCE_BYTES: usize = 16;
const MAX_CREATE_ATTEMPTS: usize = 8;

/// A live exclusive lock on the persistent inode for one installation instance.
pub(super) struct KernelStartLock {
    root: PathBuf,
    path: PathBuf,
    bytes: Vec<u8>,
    file: File,
    #[cfg(unix)]
    root_file: File,
}

impl KernelStartLock {
    pub(super) fn acquire(
        app_data_root: &Path,
        instance_id: &str,
    ) -> Result<Self, PostgresSidecarError> {
        if !app_data_root.is_absolute() || !valid_instance_id(instance_id) {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        validate_root(app_data_root)?;
        #[cfg(unix)]
        let root_file = secure_open_directory(app_data_root)
            .map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
        #[cfg(unix)]
        if !path_matches_open_directory(app_data_root, &root_file) {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }

        let path = app_data_root.join(format!(".postgresql-17-{instance_id}.owner-guard-v1"));
        let bytes = format!("{GUARD_HEADER}\ninstance={instance_id}\n").into_bytes();
        let file = match fs::symlink_metadata(&path) {
            Ok(_) => open_existing(&path, &bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                publish_or_open(app_data_root, instance_id, &path, &bytes)?
            }
            Err(_) => return Err(PostgresSidecarError::StartLockGuardInvalid),
        };

        let lock = Self {
            root: app_data_root.to_owned(),
            path,
            bytes,
            file,
            #[cfg(unix)]
            root_file,
        };
        if !lock.is_current() {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        Ok(lock)
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn is_current(&self) -> bool {
        if validate_root(&self.root).is_err() {
            return false;
        }
        #[cfg(unix)]
        if !path_matches_open_directory(&self.root, &self.root_file) {
            return false;
        }
        path_matches_open_file(&self.path, &self.file, &self.bytes, true)
    }
}

impl Drop for KernelStartLock {
    fn drop(&mut self) {
        // Closing the fd alone keeps the flock while a concurrently spawned child that has not
        // reached exec holds a copy of this open file description; LOCK_UN releases it for all.
        let _ = self.file.unlock();
    }
}

fn publish_or_open(
    root: &Path,
    instance_id: &str,
    guard_path: &Path,
    expected: &[u8],
) -> Result<File, PostgresSidecarError> {
    for _ in 0..MAX_CREATE_ATTEMPTS {
        let candidate_path = candidate_path(root, instance_id)?;
        let mut candidate = match private_create_new(&candidate_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(PostgresSidecarError::StartLockGuardInvalid),
        };
        if candidate
            .write_all(expected)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            remove_owned_candidate(&candidate_path, &candidate, expected, false);
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        if !path_matches_open_file(&candidate_path, &candidate, expected, true) {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        match candidate.try_lock() {
            Ok(()) => {}
            Err(_) => return Err(PostgresSidecarError::StartLockGuardInvalid),
        }
        match fs::hard_link(&candidate_path, guard_path) {
            Ok(()) => {
                if sync_directory(root).is_err()
                    || !path_matches_open_file(guard_path, &candidate, expected, false)
                    || !remove_owned_candidate(&candidate_path, &candidate, expected, true)
                    || sync_directory(root).is_err()
                    || !path_matches_open_file(guard_path, &candidate, expected, true)
                {
                    return Err(PostgresSidecarError::StartLockGuardInvalid);
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !remove_owned_candidate(&candidate_path, &candidate, expected, false)
                    || sync_directory(root).is_err()
                {
                    return Err(PostgresSidecarError::StartLockGuardInvalid);
                }
                return open_existing(guard_path, expected);
            }
            Err(_) => {
                remove_owned_candidate(&candidate_path, &candidate, expected, false);
                return Err(PostgresSidecarError::StartLockGuardInvalid);
            }
        }
    }
    Err(PostgresSidecarError::StartLockGuardInvalid)
}

fn open_existing(path: &Path, expected: &[u8]) -> Result<File, PostgresSidecarError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    if !valid_guard_metadata(&metadata, expected.len()) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    let file =
        secure_open_read_write(path).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    if !path_matches_open_file(path, &file, expected, false) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(PostgresSidecarError::StartLockHeld);
        }
        Err(std::fs::TryLockError::Error(_)) => {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
    }
    if !path_matches_open_file(path, &file, expected, true) {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    Ok(file)
}

fn candidate_path(root: &Path, instance_id: &str) -> Result<PathBuf, PostgresSidecarError> {
    let mut nonce = [0_u8; CANDIDATE_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    Ok(root.join(format!(
        ".postgresql-17-{instance_id}.owner-guard-v1.candidate-{}",
        encode_hex(&nonce)
    )))
}

fn private_create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    add_secure_open_flags(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn secure_open_read_write(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    add_secure_open_flags(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn secure_open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    add_secure_open_flags(&mut options);
    options.open(path)
}

fn add_secure_open_flags(options: &mut OpenOptions) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Darwin O_NOFOLLOW | O_NONBLOCK.
        options.custom_flags(0x100 | 0x4);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Linux O_NOFOLLOW | O_NONBLOCK.
        options.custom_flags(0x2_0000 | 0x800);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT; contenders may open for read/write but not delete.
        options.custom_flags(0x0020_0000).share_mode(0x3);
    }
}

fn remove_owned_candidate(path: &Path, file: &File, expected: &[u8], published: bool) -> bool {
    let expected_links = if published { 2 } else { 1 };
    if !path_matches_open_file_with_links(path, file, expected, expected_links) {
        return false;
    }
    fs::remove_file(path).is_ok()
}

fn validate_root(root: &Path) -> Result<(), PostgresSidecarError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| PostgresSidecarError::StartLockGuardInvalid)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
    }
    Ok(())
}

pub(super) fn path_matches_open_file(
    path: &Path,
    file: &File,
    expected: &[u8],
    require_single_link: bool,
) -> bool {
    let links = if require_single_link { Some(1) } else { None };
    path_matches_open_file_inner(path, file, expected, links)
}

fn path_matches_open_file_with_links(
    path: &Path,
    file: &File,
    expected: &[u8],
    links: u64,
) -> bool {
    path_matches_open_file_inner(path, file, expected, Some(links))
}

fn path_matches_open_file_inner(
    path: &Path,
    file: &File,
    expected: &[u8],
    links: Option<u64>,
) -> bool {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_metadata) = file.metadata() else {
        return false;
    };
    if !valid_guard_metadata(&path_metadata, expected.len())
        || !same_file(&path_metadata, &file_metadata)
        || links.is_some_and(|expected_links| link_count(&file_metadata) != Some(expected_links))
    {
        return false;
    }
    if !positioned_bytes_equal(file, expected) {
        return false;
    }
    let Ok(path_after) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_after) = file.metadata() else {
        return false;
    };
    valid_guard_metadata(&path_after, expected.len())
        && same_file(&path_after, &file_after)
        && links.is_none_or(|expected_links| link_count(&file_after) == Some(expected_links))
}

#[cfg(unix)]
fn positioned_bytes_equal(file: &File, expected: &[u8]) -> bool {
    use std::os::unix::fs::FileExt as _;

    let Some(read_len) = expected.len().checked_add(1) else {
        return false;
    };
    let mut actual = vec![0_u8; read_len];
    let mut read = 0_usize;
    while read < actual.len() {
        let Ok(offset) = u64::try_from(read) else {
            return false;
        };
        match file.read_at(&mut actual[read..], offset) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    read == expected.len() && &actual[..read] == expected
}

#[cfg(windows)]
fn positioned_bytes_equal(file: &File, expected: &[u8]) -> bool {
    use std::os::windows::fs::FileExt as _;

    let Some(read_len) = expected.len().checked_add(1) else {
        return false;
    };
    let mut actual = vec![0_u8; read_len];
    let mut read = 0_usize;
    while read < actual.len() {
        let Ok(offset) = u64::try_from(read) else {
            return false;
        };
        match file.seek_read(&mut actual[read..], offset) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    read == expected.len() && &actual[..read] == expected
}

#[cfg(not(any(unix, windows)))]
fn positioned_bytes_equal(_file: &File, _expected: &[u8]) -> bool {
    false
}

fn valid_guard_metadata(metadata: &fs::Metadata, expected_len: usize) -> bool {
    let Ok(expected_len) = u64::try_from(expected_len) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != expected_len
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return false;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    // Stable Rust 1.98 exposes no Windows file ID. Reparse, timestamps, size and attributes are
    // insufficient identity evidence, so the Windows owner path remains fail-closed.
    false
}

#[cfg(not(any(unix, windows)))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn link_count(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Some(metadata.nlink())
}

#[cfg(windows)]
fn link_count(_metadata: &fs::Metadata) -> Option<u64> {
    // Stable Rust 1.98 does not expose Windows file identity or link count. Fail closed wherever
    // the contract requires single-link proof; Windows runtime evidence remains a later gate.
    None
}

#[cfg(not(any(unix, windows)))]
fn link_count(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn path_matches_open_directory(path: &Path, file: &File) -> bool {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_metadata) = file.metadata() else {
        return false;
    };
    path_metadata.file_type().is_dir()
        && !path_metadata.file_type().is_symlink()
        && same_file(&path_metadata, &file_metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    const PROCESS_TEST: &str =
        "postgres_sidecar::kernel_start_lock::tests::real_process_guard_is_instance_scoped";
    const CHILD_ROLE: &str = "WROK_V6_KERNEL_GUARD_CHILD_ROLE";
    const CHILD_ROOT: &str = "WROK_V6_KERNEL_GUARD_CHILD_ROOT";
    const CHILD_INSTANCE: &str = "WROK_V6_KERNEL_GUARD_CHILD_INSTANCE";
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn root(label: &str) -> PathBuf {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "wrok-v6-kernel-guard-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    fn private_root(label: &str) -> PathBuf {
        let root = root(label);
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    fn guard_path(root: &Path, instance: &str) -> PathBuf {
        root.join(format!(".postgresql-17-{instance}.owner-guard-v1"))
    }

    fn run_child(root: &Path, instance: &str, role: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PROCESS_TEST, "--nocapture"])
            .env(CHILD_ROLE, role)
            .env(CHILD_ROOT, root)
            .env(CHILD_INSTANCE, instance)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn real_process_guard_is_instance_scoped() {
        if let Some(role) = std::env::var_os(CHILD_ROLE) {
            let root = PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
            let instance = std::env::var(CHILD_INSTANCE).unwrap();
            let result = KernelStartLock::acquire(&root, &instance);
            match role.to_str().unwrap() {
                "held" => assert!(matches!(result, Err(PostgresSidecarError::StartLockHeld))),
                "acquired" => assert!(result.is_ok()),
                _ => panic!("unknown child role"),
            }
            return;
        }

        let root = private_root("process");
        let first_instance = "a".repeat(64);
        let second_instance = "b".repeat(64);
        let owner = KernelStartLock::acquire(&root, &first_instance).unwrap();
        run_child(&root, &first_instance, "held");
        run_child(&root, &second_instance, "acquired");
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn guard_is_persistent_exact_and_reacquirable_after_release() {
        let root = private_root("persistent");
        let instance = "c".repeat(64);
        let path = guard_path(&root, &instance);
        let first = KernelStartLock::acquire(&root, &instance).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            format!("{GUARD_HEADER}\ninstance={instance}\n").as_bytes()
        );
        assert!(
            !fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().contains("candidate"))
        );
        drop(first);
        assert!(path.is_file());
        let second = KernelStartLock::acquire(&root, &instance).unwrap();
        drop(second);
        assert!(path.is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn release_is_not_delayed_by_a_concurrent_spawn() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        let root = private_root("spawn-release");
        let instance = "e".repeat(64);
        let stop = AtomicBool::new(false);
        let mut cycles = 0_u64;
        let failure = std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        Command::new("/bin/sleep")
                            .arg("0")
                            .spawn()
                            .unwrap()
                            .wait()
                            .unwrap();
                    }
                });
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut lock = KernelStartLock::acquire(&root, &instance);
            while lock.is_ok() && Instant::now() < deadline {
                drop(lock);
                lock = KernelStartLock::acquire(&root, &instance);
                cycles += 1;
            }
            stop.store(true, Ordering::Relaxed);
            lock.err()
        });
        fs::remove_dir_all(root).unwrap();
        assert!(
            failure.is_none(),
            "re-acquire after release failed on cycle {cycles}: {failure:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_permission_multilink_symlink_and_fifo_guards_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let instance = "d".repeat(64);
        let expected = format!("{GUARD_HEADER}\ninstance={instance}\n");
        for shape in ["malformed", "permission", "multilink", "symlink", "fifo"] {
            let root = private_root(shape);
            let path = guard_path(&root, &instance);
            match shape {
                "malformed" => fs::write(&path, b"wrong").unwrap(),
                "permission" => {
                    fs::write(&path, &expected).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "multilink" => {
                    fs::write(&path, &expected).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::hard_link(&path, root.join("external-link")).unwrap();
                }
                "symlink" => symlink(root.join("missing-target"), &path).unwrap(),
                "fifo" => {
                    assert!(
                        Command::new("mkfifo")
                            .arg(&path)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                KernelStartLock::acquire(&root, &instance),
                Err(PostgresSidecarError::StartLockGuardInvalid)
            ));
            fs::remove_dir_all(root).unwrap();
        }
    }
}
