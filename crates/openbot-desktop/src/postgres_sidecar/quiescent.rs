//! Sealed VerifiedQuiescentInstance minting and cleanup-only start-lock reclaim.

use super::helper_journal::{self, HelperJournalError};
use super::kernel_start_lock::KernelStartLock;
use super::startup_journal::{self, StartupJournalError};
use super::{PostgresSidecarError, path_matches_open_file, sync_directory, valid_instance_id};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use wrok_bot_macos_process::{
    DataDirectoryOpenerObservation, ProcessIdentity, observe_data_directory_openers,
};

const LOCK_HEADER: &str = "openbot-postgres-start-lock-v1";
// Header+LF, pid=+nonzero unpadded u32+LF, instance/manifest=+64 hex+LF, nonce=+32 hex+LF.
const MAX_LOCK_BYTES: usize =
    LOCK_HEADER.len() + 1 + (4 + 10 + 1) + (9 + 64 + 1) + (9 + 64 + 1) + (6 + 32 + 1);

fn read_bounded_start_lock_bytes(file: &mut File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(MAX_LOCK_BYTES + 1);
    file.take((MAX_LOCK_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_LOCK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid start-lock record length",
        ));
    }
    Ok(bytes)
}

/// Exact closed start-lock observed before any recovery effect; no recovery authority itself.
pub(super) struct StartLockEvidence {
    root: PathBuf,
    instance_id: String,
    path: PathBuf,
    bytes: Vec<u8>,
    file: File,
}

impl core::fmt::Debug for StartLockEvidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StartLockEvidence(<sealed>)")
    }
}

impl StartLockEvidence {
    pub(super) fn inspect(
        owner: &KernelStartLock,
        app_data_root: &Path,
        instance_id: &str,
    ) -> Result<Self, PostgresSidecarError> {
        if !owner.is_current() || owner.root() != app_data_root || !valid_instance_id(instance_id) {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        let path = app_data_root.join(format!(".postgresql-17-{instance_id}.start-lock-v1"));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        if !metadata.is_file() {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
                return Err(PostgresSidecarError::StartLockRecoveryRequired);
            }
        }
        let mut file =
            secure_open_read(&path).map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        let bytes = read_bounded_start_lock_bytes(&mut file)
            .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        if !lock_bytes_match_instance(&bytes, instance_id) {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        let observed = Self {
            root: app_data_root.to_owned(),
            instance_id: instance_id.to_owned(),
            path,
            bytes,
            file,
        };
        if !observed.is_current(owner) {
            return Err(PostgresSidecarError::StartLockRecoveryRequired);
        }
        Ok(observed)
    }

    pub(super) fn is_current(&self, owner: &KernelStartLock) -> bool {
        owner.is_current()
            && owner.root() == self.root
            && path_matches_open_file(&self.path, &self.file, &self.bytes, true)
    }
}

/// Proof that one instance is quiescent enough to reclaim its dynamic start-lock evidence.
///
/// Not serializable, not a wire type, and not recovery/epoch authority.
pub(super) struct VerifiedQuiescentInstance<'a> {
    evidence: &'a StartLockEvidence,
}

impl core::fmt::Debug for VerifiedQuiescentInstance<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedQuiescentInstance(<sealed>)")
    }
}

impl<'a> VerifiedQuiescentInstance<'a> {
    /// Mint only when owner, empty openers, and cleanup-eligible journals all hold.
    pub(super) fn try_verify(
        owner: &KernelStartLock,
        app_data_root: &Path,
        instance_id: &str,
        data_dir: &Path,
        data_dir_name: &str,
        evidence: &'a StartLockEvidence,
    ) -> Result<Self, PostgresSidecarError> {
        if !evidence.is_current(owner)
            || evidence.root != app_data_root
            || evidence.instance_id != instance_id
        {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        if data_dir.parent() != Some(app_data_root)
            || data_dir.file_name().and_then(|name| name.to_str()) != Some(data_dir_name)
        {
            return Err(PostgresSidecarError::DataDirectoryInvalid);
        }
        let metadata =
            fs::metadata(data_dir).map_err(|_| PostgresSidecarError::DataDirectoryInvalid)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if !metadata.is_dir() || metadata.ino() == 0 {
                return Err(PostgresSidecarError::DataDirectoryInvalid);
            }
            let self_identity = ProcessIdentity::capture(std::process::id())
                .map_err(|_| PostgresSidecarError::ProcessIdentityInvalid)?;
            match observe_data_directory_openers(
                data_dir,
                metadata.dev(),
                metadata.ino(),
                std::slice::from_ref(&self_identity),
            ) {
                Ok(DataDirectoryOpenerObservation::Empty) => {}
                Ok(DataDirectoryOpenerObservation::Observed) => {
                    return Err(PostgresSidecarError::StartupJournalRecoveryRequired);
                }
                Err(_) => return Err(PostgresSidecarError::ProcessIdentityInvalid),
            }
        }
        startup_journal::allows_quiescent_cleanup(app_data_root, instance_id, data_dir, data_dir_name).map_err(
            |error| match error {
                StartupJournalError::RecoveryRequired => {
                    PostgresSidecarError::StartupJournalRecoveryRequired
                }
                StartupJournalError::ReconciliationRequired => {
                    PostgresSidecarError::StartLockGuardInvalid
                }
                StartupJournalError::Invalid => PostgresSidecarError::StartLockGuardInvalid,
            },
        )?;
        helper_journal::allows_quiescent_cleanup(app_data_root, instance_id, data_dir, data_dir_name).map_err(
            |error| match error {
                HelperJournalError::RecoveryRequired => {
                    PostgresSidecarError::HelperJournalRecoveryRequired
                }
                HelperJournalError::ReconciliationRequired | HelperJournalError::Invalid => {
                    PostgresSidecarError::StartLockGuardInvalid
                }
            },
        )?;
        if !evidence.is_current(owner) {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        Ok(Self { evidence })
    }

    /// Delete this instance's dynamic start-lock evidence only.
    pub(super) fn reclaim_start_lock_evidence(
        self,
        owner: &KernelStartLock,
        app_data_root: &Path,
    ) -> Result<(), PostgresSidecarError> {
        if !self.evidence.is_current(owner) || self.evidence.root != app_data_root {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        fs::remove_file(&self.evidence.path)
            .map_err(|_| PostgresSidecarError::StartLockRecoveryRequired)?;
        sync_directory(app_data_root)?;
        if !owner.is_current() {
            return Err(PostgresSidecarError::StartLockGuardInvalid);
        }
        Ok(())
    }
}

/// One-shot mid-phase journal retirement under a held kernel owner and Empty openers.
pub(super) fn recover_mid_phase_journals(
    owner: &KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
    data_dir_name: &str,
) -> Result<(), PostgresSidecarError> {
    if !owner.is_current() || owner.root() != app_data_root {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    if data_dir.parent() != Some(app_data_root)
        || data_dir.file_name().and_then(|name| name.to_str()) != Some(data_dir_name)
    {
        return Err(PostgresSidecarError::DataDirectoryInvalid);
    }
    let metadata =
        fs::metadata(data_dir).map_err(|_| PostgresSidecarError::DataDirectoryInvalid)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_dir() || metadata.ino() == 0 {
            return Err(PostgresSidecarError::DataDirectoryInvalid);
        }
        let self_identity = ProcessIdentity::capture(std::process::id())
            .map_err(|_| PostgresSidecarError::ProcessIdentityInvalid)?;
        match observe_data_directory_openers(
            data_dir,
            metadata.dev(),
            metadata.ino(),
            std::slice::from_ref(&self_identity),
        ) {
            Ok(DataDirectoryOpenerObservation::Empty) => {}
            Ok(DataDirectoryOpenerObservation::Observed) => {
                return Err(PostgresSidecarError::StartupJournalRecoveryRequired);
            }
            Err(_) => return Err(PostgresSidecarError::ProcessIdentityInvalid),
        }
    }
    startup_journal::recover_mid_phase(owner, app_data_root, instance_id, data_dir, data_dir_name).map_err(
        |error| match error {
            StartupJournalError::RecoveryRequired => {
                PostgresSidecarError::StartupJournalRecoveryRequired
            }
            StartupJournalError::ReconciliationRequired => {
                PostgresSidecarError::StartLockGuardInvalid
            }
            StartupJournalError::Invalid => PostgresSidecarError::StartLockGuardInvalid,
        },
    )?;
    helper_journal::recover_mid_phase(owner, app_data_root, instance_id, data_dir, data_dir_name).map_err(
        |error| match error {
            HelperJournalError::RecoveryRequired => {
                PostgresSidecarError::HelperJournalRecoveryRequired
            }
            HelperJournalError::ReconciliationRequired | HelperJournalError::Invalid => {
                PostgresSidecarError::StartLockGuardInvalid
            }
        },
    )?;
    if !owner.is_current() {
        return Err(PostgresSidecarError::StartLockGuardInvalid);
    }
    Ok(())
}

fn lock_bytes_match_instance(bytes: &[u8], instance_id: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.split('\n');
    if lines.next() != Some(LOCK_HEADER) {
        return false;
    }
    let Some(pid) = lines.next().and_then(|line| line.strip_prefix("pid=")) else {
        return false;
    };
    if pid.starts_with('0')
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !pid.parse::<u32>().is_ok_and(|value| value != 0)
    {
        return false;
    }
    let Some(instance) = lines.next().and_then(|line| line.strip_prefix("instance=")) else {
        return false;
    };
    let Some(manifest) = lines.next().and_then(|line| line.strip_prefix("manifest=")) else {
        return false;
    };
    let Some(nonce) = lines.next().and_then(|line| line.strip_prefix("nonce=")) else {
        return false;
    };
    instance == instance_id
        && valid_instance_id(instance)
        && valid_instance_id(manifest)
        && nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && lines.next() == Some("")
        && lines.next().is_none()
}

fn secure_open_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x100 | 0x4);
    }
    options.open(path)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use crate::postgres_sidecar::kernel_start_lock::KernelStartLock;
    use crate::postgres_sidecar::{PostgresBundleDigest, PostgresSidecarError, PostgresStartLock};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Seek as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;
    use wrok_bot_macos_process::ProcessIdentity;

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }

    fn owner_observation_hex() -> String {
        let identity = ProcessIdentity::capture(std::process::id()).expect("self");
        encode_hex(&identity.evidence_bytes().expect("evidence"))
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let parent = path.parent().unwrap();
        File::open(parent).unwrap().sync_all().unwrap();
    }

    fn plant_stale_lock(root: &Path, instance: &str) -> PathBuf {
        let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
        fs::write(
            &lock_path,
            format!(
                "openbot-postgres-start-lock-v1\npid=1\ninstance={instance}\nmanifest={}\nnonce={}\n",
                "11".repeat(32),
                "22".repeat(16)
            ),
        )
        .unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        lock_path
    }

    fn data_dir_ids(data_dir: &Path) -> (u64, u64) {
        let metadata = fs::metadata(data_dir).unwrap();
        (metadata.dev(), metadata.ino())
    }

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wrok-v6-pr-012-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    fn canonical_lock(instance: &str, pid: &str) -> String {
        format!(
            "{header}\npid={pid}\ninstance={instance}\nmanifest={}\nnonce={}\n",
            "ab".repeat(32),
            "cd".repeat(16),
            header = super::LOCK_HEADER
        )
    }

    #[test]
    fn bounded_start_lock_read_enforces_empty_233_and_234_byte_boundaries() {
        assert_eq!(super::MAX_LOCK_BYTES, 233);
        for length in [0, super::MAX_LOCK_BYTES, super::MAX_LOCK_BYTES + 1] {
            let root = temp_root("068-read-boundary");
            let path = root.join("record");
            let expected = vec![b'x'; length];
            write_private(&path, &expected);
            let mut file = super::secure_open_read(&path).unwrap();
            let result = super::read_bounded_start_lock_bytes(&mut file);
            assert_eq!(file.stream_position().unwrap(), length as u64);
            if length == super::MAX_LOCK_BYTES {
                assert_eq!(result.unwrap(), expected);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
            eprintln!("bounded-lock-read boundary length={length} actual_read={length}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn bounded_start_lock_read_rejects_growth_after_open_with_only_234_bytes_read() {
        let root = temp_root("068-read-growth");
        let instance = "ab".repeat(32);
        let path = root.join("record");
        let canonical = canonical_lock(&instance, &u32::MAX.to_string());
        assert_eq!(canonical.len(), super::MAX_LOCK_BYTES);
        assert!(super::lock_bytes_match_instance(
            canonical.as_bytes(),
            &instance
        ));
        write_private(&path, canonical.as_bytes());
        let mut file = super::secure_open_read(&path).unwrap();
        let observed = file.metadata().unwrap();
        assert_eq!(observed.len(), super::MAX_LOCK_BYTES as u64);
        assert_eq!(observed.mode() & 0o777, 0o600);
        assert_eq!(observed.nlink(), 1);
        let appended = vec![b'x'; 1024 * 1024];
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&appended).unwrap();
        writer.sync_all().unwrap();
        let grown = file.metadata().unwrap();
        assert_eq!(grown.len(), (super::MAX_LOCK_BYTES + appended.len()) as u64);
        assert_eq!(grown.dev(), observed.dev());
        assert_eq!(grown.ino(), observed.ino());
        assert_eq!(
            super::read_bounded_start_lock_bytes(&mut file)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            file.stream_position().unwrap(),
            (super::MAX_LOCK_BYTES + 1) as u64
        );
        eprintln!(
            "bounded-lock-read growth observed_length={} grown_length={} actual_read={}",
            observed.len(),
            grown.len(),
            file.stream_position().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_start_lock_canonical_pid_bounds_inspect_recheck_and_reclaim() {
        let instance = "ab".repeat(32);
        for (pid, length) in [("1", 224), ("4294967295", 233)] {
            let root = temp_root("068-canonical-inspect");
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
            let canonical = canonical_lock(&instance, pid);
            assert_eq!(canonical.len(), length);
            write_private(&lock_path, canonical.as_bytes());
            let mut file = super::secure_open_read(&lock_path).unwrap();
            let bytes = super::read_bounded_start_lock_bytes(&mut file).unwrap();
            assert_eq!(bytes, canonical.as_bytes());
            assert!(super::lock_bytes_match_instance(&bytes, &instance));
            let owner = KernelStartLock::acquire(&root, &instance).unwrap();
            let evidence = super::StartLockEvidence::inspect(&owner, &root, &instance).unwrap();
            assert_eq!(evidence.bytes, bytes);
            assert!(evidence.is_current(&owner));
            let data = data_dir.join("owned-data-sentinel");
            write_private(&data, b"owned data stays");
            let before = evidence_snapshots(std::slice::from_ref(&data));
            let verified = super::VerifiedQuiescentInstance::try_verify(
                &owner, &root, &instance, &data_dir, &format!("postgresql-17-{instance}"), &evidence,
            )
            .unwrap();
            assert!(evidence.is_current(&owner));
            verified.reclaim_start_lock_evidence(&owner, &root).unwrap();
            assert!(!lock_path.exists());
            assert_eq!(evidence_snapshots(std::slice::from_ref(&data)), before);
            assert!(owner.is_current());
            assert!(
                !root
                    .join(format!(".postgresql-17-{instance}.recovery-epoch-v1"))
                    .exists()
            );
            eprintln!(
                "bounded-lock canonical pid={pid} length={length} inspect_recheck_reclaim=true"
            );
            drop(owner);
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn malformed_locks(instance: &str) -> Vec<(&'static str, Vec<u8>)> {
        let canonical = canonical_lock(instance, "1");
        let manifest = "ab".repeat(32);
        let nonce = "cd".repeat(16);
        vec![
            (
                "only-instance",
                format!("{}\ninstance={instance}\n", super::LOCK_HEADER).into_bytes(),
            ),
            ("missing-pid", canonical.replace("pid=1\n", "").into_bytes()),
            (
                "missing-manifest",
                canonical
                    .replace(&format!("manifest={manifest}\n"), "")
                    .into_bytes(),
            ),
            (
                "missing-nonce",
                canonical
                    .replace(&format!("nonce={nonce}\n"), "")
                    .into_bytes(),
            ),
            (
                "reversed",
                format!(
                    "{}\ninstance={instance}\npid=1\nmanifest={manifest}\nnonce={nonce}\n",
                    super::LOCK_HEADER
                )
                .into_bytes(),
            ),
            ("duplicate-pid", format!("{canonical}pid=1\n").into_bytes()),
            (
                "duplicate-manifest",
                format!("{canonical}manifest={manifest}\n").into_bytes(),
            ),
            (
                "duplicate-nonce",
                format!("{canonical}nonce={nonce}\n").into_bytes(),
            ),
            (
                "duplicate-instance",
                format!("{canonical}instance={instance}\n").into_bytes(),
            ),
            ("crlf", canonical.replace('\n', "\r\n").into_bytes()),
            (
                "missing-final-lf",
                canonical.trim_end_matches('\n').as_bytes().to_vec(),
            ),
            ("unknown", format!("{canonical}other=value\n").into_bytes()),
            ("empty-pid", canonical_lock(instance, "").into_bytes()),
            ("zero-pid", canonical_lock(instance, "0").into_bytes()),
            ("negative-pid", canonical_lock(instance, "-1").into_bytes()),
            ("plus-pid", canonical_lock(instance, "+1").into_bytes()),
            ("padded-pid", canonical_lock(instance, "01").into_bytes()),
            (
                "overflow-pid",
                canonical_lock(instance, "4294967296").into_bytes(),
            ),
            (
                "uppercase-manifest",
                canonical
                    .replace(
                        &format!("manifest={manifest}"),
                        &format!("manifest={}", manifest.to_uppercase()),
                    )
                    .into_bytes(),
            ),
            (
                "short-manifest",
                canonical
                    .replace(
                        &format!("manifest={manifest}"),
                        &format!("manifest={}", &manifest[..63]),
                    )
                    .into_bytes(),
            ),
            (
                "nonhex-manifest",
                canonical
                    .replace(
                        &format!("manifest={manifest}"),
                        &format!("manifest={}", "g".repeat(64)),
                    )
                    .into_bytes(),
            ),
            (
                "uppercase-nonce",
                canonical
                    .replace(&nonce, &nonce.to_uppercase())
                    .into_bytes(),
            ),
            (
                "short-nonce",
                canonical.replace(&nonce, &nonce[..31]).into_bytes(),
            ),
            (
                "nonhex-nonce",
                canonical.replace(&nonce, &"g".repeat(32)).into_bytes(),
            ),
            (
                "wrong-instance",
                canonical
                    .replace(
                        &format!("instance={instance}"),
                        &format!("instance={}", "ef".repeat(32)),
                    )
                    .into_bytes(),
            ),
            (
                "uppercase-instance",
                canonical
                    .replace(
                        &format!("instance={instance}"),
                        &format!("instance={}", instance.to_uppercase()),
                    )
                    .into_bytes(),
            ),
            (
                "truncated",
                b"openbot-postgres-start-lock-v1\npid=".to_vec(),
            ),
            ("invalid-utf8", vec![0xff]),
        ]
    }

    #[test]
    fn closed_start_lock_records_accept_canonical_pid_bounds() {
        let instance = "ab".repeat(32);
        for pid in ["1", "4294967295"] {
            assert!(super::lock_bytes_match_instance(
                canonical_lock(&instance, pid).as_bytes(),
                &instance
            ));
        }
    }

    #[test]
    fn closed_start_lock_records_reject_malformed() {
        let instance = "ab".repeat(32);
        let mut accepted = Vec::new();
        for (name, bytes) in malformed_locks(&instance) {
            let valid = super::lock_bytes_match_instance(&bytes, &instance);
            eprintln!("start-lock case={name} accepted={valid}");
            if valid {
                accepted.push(name);
            }
        }
        assert!(
            accepted.is_empty(),
            "malformed start-lock records accepted: {accepted:?}"
        );
    }

    #[test]
    fn malformed_start_lock_reclaim_has_no_evidence_effect() {
        let instance = "ab".repeat(32);
        let mut violations = Vec::new();
        for (name, bytes) in malformed_locks(&instance) {
            let root = temp_root(name);
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
            write_private(&lock_path, &bytes);
            let epoch_path = root.join(format!(".postgresql-17-{instance}.recovery-epoch-v1"));
            let epoch_bytes = format!(
                "openbot-postgres-recovery-epoch-v1\ninstance={instance}\nepoch={}\n",
                "12".repeat(32)
            );
            write_private(&epoch_path, epoch_bytes.as_bytes());
            let before_epoch = fs::symlink_metadata(&epoch_path).unwrap();
            let before_lock = fs::symlink_metadata(&lock_path).unwrap();
            let acquired = PostgresStartLock::acquire_with_data_dir(
                &root,
                &instance,
                PostgresBundleDigest([0x11; 32]),
                &data_dir,
            );
            let rejected = matches!(
                acquired,
                Err(PostgresSidecarError::StartLockRecoveryRequired)
            );
            let epoch_unchanged = fs::read(&epoch_path).unwrap() == epoch_bytes.as_bytes()
                && fs::symlink_metadata(&epoch_path).unwrap().ino() == before_epoch.ino();
            let lock_unchanged = fs::read(&lock_path).unwrap() == bytes
                && fs::symlink_metadata(&lock_path).unwrap().ino() == before_lock.ino();
            eprintln!(
                "start-lock-reclaim case={name} rejected={rejected} epoch_unchanged={epoch_unchanged} lock_unchanged={lock_unchanged}"
            );
            if !(rejected && epoch_unchanged && lock_unchanged) {
                violations.push(name);
            }
            drop(acquired);
            fs::remove_dir_all(root).unwrap();
        }
        assert!(
            violations.is_empty(),
            "start-lock rejection changed evidence or accepted: {violations:?}"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EvidenceSnapshot {
        path: PathBuf,
        bytes: Vec<u8>,
        mode: u32,
        device: u64,
        inode: u64,
        links: u64,
    }

    fn evidence_snapshots(paths: &[PathBuf]) -> Vec<EvidenceSnapshot> {
        paths
            .iter()
            .map(|path| {
                let metadata = fs::symlink_metadata(path).unwrap();
                EvidenceSnapshot {
                    path: path.clone(),
                    bytes: fs::read(path).unwrap(),
                    mode: metadata.mode(),
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    links: metadata.nlink(),
                }
            })
            .collect()
    }

    fn plant_boundary_preservation_evidence(
        root: &Path,
        instance: &str,
        data_dir: &Path,
    ) -> Vec<PathBuf> {
        let (device, inode) = data_dir_ids(data_dir);
        let startup = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let helper = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let startup_record = serde_json::json!({"schema":"openbot-postgres-startup","schemaVersion":1,"instanceId":instance,"dataDirName":format!("postgresql-17-{instance}"),"dataDirDevice":device,"dataDirInode":inode,"attemptId":"34".repeat(16),"startEvidenceSha256":"12".repeat(32),"ownerObservation":owner_observation_hex(),"childObservation":null,"phase":"spawn_entered"});
        let helper_record = serde_json::json!({"schema":"openbot-postgres-helper","schemaVersion":1,"instanceId":instance,"dataDirName":format!("postgresql-17-{instance}"),"dataDirDevice":device,"dataDirInode":inode,"attemptId":"56".repeat(16),"startEvidenceSha256":"12".repeat(32),"ownerObservation":owner_observation_hex(),"helperKind":"version_postgres","childObservation":null,"phase":"spawn_entered"});
        write_private(&startup, &serde_json::to_vec(&startup_record).unwrap());
        write_private(&helper, &serde_json::to_vec(&helper_record).unwrap());
        let mut paths = vec![startup, helper];
        for (suffix, header) in [
            ("recovery-epoch-v1", "openbot-postgres-recovery-epoch-v1"),
            (
                "consumed-recovery-epoch-v1",
                "openbot-postgres-consumed-recovery-epoch-v1",
            ),
            (
                "auth-invalidation-required-v1",
                "openbot-postgres-auth-invalidation-required-v1",
            ),
            (
                "auth-invalidation-applied-v1",
                "openbot-postgres-auth-invalidation-applied-v1",
            ),
        ] {
            let path = root.join(format!(".postgresql-17-{instance}.{suffix}"));
            write_private(
                &path,
                format!("{header}\ninstance={instance}\nepoch={}\n", "12".repeat(32)).as_bytes(),
            );
            paths.push(path);
        }
        for (name, bytes) in [
            ("owned-data-sentinel", b"owned data stays".as_slice()),
            ("owned-wal-sentinel", b"owned WAL stays".as_slice()),
        ] {
            let path = data_dir.join(name);
            write_private(&path, bytes);
            paths.push(path);
        }
        paths
    }

    fn root_entry_paths(root: &Path) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn bounded_start_lock_inspect_and_acquire_reject_bad_records_without_effect() {
        let instance = "ab".repeat(32);
        for length in [
            0,
            super::MAX_LOCK_BYTES,
            super::MAX_LOCK_BYTES + 1,
            super::MAX_LOCK_BYTES + 1024 * 1024,
        ] {
            let root = temp_root("068-boundary-inspect");
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
            let bytes = if length > super::MAX_LOCK_BYTES {
                let mut canonical = canonical_lock(&instance, &u32::MAX.to_string()).into_bytes();
                canonical.resize(length, b'x');
                canonical
            } else {
                vec![b'x'; length]
            };
            write_private(&lock_path, &bytes);
            let mut paths = plant_boundary_preservation_evidence(&root, &instance, &data_dir);
            paths.push(lock_path);
            let owner = KernelStartLock::acquire(&root, &instance).unwrap();
            paths.push(root.join(format!(".postgresql-17-{instance}.owner-guard-v1")));
            let before = evidence_snapshots(&paths);
            let before_entries = root_entry_paths(&root);
            assert!(matches!(
                super::StartLockEvidence::inspect(&owner, &root, &instance),
                Err(PostgresSidecarError::StartLockRecoveryRequired)
            ));
            assert_eq!(evidence_snapshots(&paths), before);
            assert_eq!(root_entry_paths(&root), before_entries);
            assert!(owner.is_current());
            drop(owner);
            let acquired = PostgresStartLock::acquire_with_data_dir(
                &root,
                &instance,
                PostgresBundleDigest([0x11; 32]),
                &data_dir,
            );
            assert!(
                matches!(
                    acquired,
                    Err(PostgresSidecarError::StartLockRecoveryRequired)
                ),
                "length={length}: {acquired:?}"
            );
            assert_eq!(evidence_snapshots(&paths), before);
            assert_eq!(root_entry_paths(&root), before_entries);
            eprintln!(
                "bounded-lock production length={length} inspect_acquire=StartLockRecoveryRequired records_and_entries_unchanged=true"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn bounded_start_lock_growth_blocks_verify_and_reclaim_after_inspect() {
        let instance = "ab".repeat(32);
        for after_verify in [false, true] {
            let root = temp_root("068-post-inspect-growth");
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
            write_private(
                &lock_path,
                canonical_lock(&instance, &u32::MAX.to_string()).as_bytes(),
            );
            let owner = KernelStartLock::acquire(&root, &instance).unwrap();
            let evidence = super::StartLockEvidence::inspect(&owner, &root, &instance).unwrap();
            let observed = fs::symlink_metadata(&lock_path).unwrap();
            let verified = after_verify.then(|| {
                super::VerifiedQuiescentInstance::try_verify(
                    &owner, &root, &instance, &data_dir, &format!("postgresql-17-{instance}"), &evidence,
                )
                .unwrap()
            });
            let mut writer = OpenOptions::new().append(true).open(&lock_path).unwrap();
            writer.write_all(&vec![b'x'; 1024 * 1024]).unwrap();
            writer.sync_all().unwrap();
            assert_eq!(
                fs::symlink_metadata(&lock_path).unwrap().dev(),
                observed.dev()
            );
            assert_eq!(
                fs::symlink_metadata(&lock_path).unwrap().ino(),
                observed.ino()
            );
            let before = evidence_snapshots(std::slice::from_ref(&lock_path));
            let before_entries = root_entry_paths(&root);
            assert!(!evidence.is_current(&owner));
            assert!(matches!(
                super::VerifiedQuiescentInstance::try_verify(
                    &owner, &root, &instance, &data_dir, &format!("postgresql-17-{instance}"), &evidence
                ),
                Err(PostgresSidecarError::StartLockGuardInvalid)
            ));
            if let Some(verified) = verified {
                assert!(matches!(
                    verified.reclaim_start_lock_evidence(&owner, &root),
                    Err(PostgresSidecarError::StartLockGuardInvalid)
                ));
            }
            assert_eq!(evidence_snapshots(std::slice::from_ref(&lock_path)), before);
            assert_eq!(root_entry_paths(&root), before_entries);
            assert!(owner.is_current());
            assert!(
                !root
                    .join(format!(".postgresql-17-{instance}.recovery-epoch-v1"))
                    .exists()
            );
            eprintln!(
                "bounded-lock revalidation growth after_verify={after_verify} guard_invalid=true records_and_entries_unchanged=true"
            );
            drop(owner);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn bounded_start_lock_inspect_keeps_guard_invalid_on_owner_root_mismatch() {
        let root = temp_root("068-owner-root");
        let other_root = temp_root("068-other-root");
        let instance = "ab".repeat(32);
        let lock_path = plant_stale_lock(&root, &instance);
        let owner = KernelStartLock::acquire(&root, &instance).unwrap();
        let before = evidence_snapshots(std::slice::from_ref(&lock_path));
        assert!(matches!(
            super::StartLockEvidence::inspect(&owner, &other_root, &instance),
            Err(PostgresSidecarError::StartLockGuardInvalid)
        ));
        assert_eq!(evidence_snapshots(std::slice::from_ref(&lock_path)), before);
        assert!(root_entry_paths(&other_root).is_empty());
        assert!(owner.is_current());
        drop(owner);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(other_root).unwrap();
    }

    #[test]
    fn malformed_lock_never_retires_mid_phase_journal_or_changes_other_evidence() {
        for bad_mode in [false, true] {
            let root = temp_root("067-preflight-journal");
            let instance = "ef".repeat(32);
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = plant_stale_lock(&root, &instance);
            if bad_mode {
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
            } else {
                write_private(
                    &lock_path,
                    format!("{}\ninstance={instance}\n", super::LOCK_HEADER).as_bytes(),
                );
            }
            let (device, inode) = data_dir_ids(&data_dir);
            let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
            let record = serde_json::json!({"schema":"openbot-postgres-startup","schemaVersion":1,"instanceId":instance,"dataDirName":format!("postgresql-17-{instance}"),"dataDirDevice":device,"dataDirInode":inode,"attemptId":"34".repeat(16),"startEvidenceSha256":"12".repeat(32),"ownerObservation":owner_observation_hex(),"childObservation":null,"phase":"spawn_entered"});
            write_private(&journal, &serde_json::to_vec(&record).unwrap());
            let mut paths = vec![lock_path, journal];
            for (suffix, header) in [
                ("recovery-epoch-v1", "openbot-postgres-recovery-epoch-v1"),
                (
                    "consumed-recovery-epoch-v1",
                    "openbot-postgres-consumed-recovery-epoch-v1",
                ),
                (
                    "auth-invalidation-required-v1",
                    "openbot-postgres-auth-invalidation-required-v1",
                ),
                (
                    "auth-invalidation-applied-v1",
                    "openbot-postgres-auth-invalidation-applied-v1",
                ),
            ] {
                let path = root.join(format!(".postgresql-17-{instance}.{suffix}"));
                write_private(
                    &path,
                    format!("{header}\ninstance={instance}\nepoch={}\n", "12".repeat(32))
                        .as_bytes(),
                );
                paths.push(path);
            }
            let data = data_dir.join("owned-data-sentinel");
            let wal = data_dir.join("owned-wal-sentinel");
            write_private(&data, b"owned data stays");
            write_private(&wal, b"owned WAL stays");
            paths.extend([data, wal]);
            drop(KernelStartLock::acquire(&root, &instance).unwrap());
            let before = evidence_snapshots(&paths);
            let rejected = PostgresStartLock::acquire_with_data_dir(
                &root,
                &instance,
                PostgresBundleDigest([0x11; 32]),
                &data_dir,
            );
            assert!(
                matches!(
                    rejected,
                    Err(PostgresSidecarError::StartLockRecoveryRequired)
                ),
                "{rejected:?}"
            );
            assert_eq!(evidence_snapshots(&paths), before);
            assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn observed_lock_rejects_replacement_and_same_inode_rewrite_before_mint() {
        for replace in [false, true] {
            let root = temp_root("067-observed-replace");
            let instance = "ef".repeat(32);
            let data_dir = root.join(format!("postgresql-17-{instance}"));
            fs::create_dir(&data_dir).unwrap();
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let lock_path = plant_stale_lock(&root, &instance);
            let owner = KernelStartLock::acquire(&root, &instance).unwrap();
            let evidence = super::StartLockEvidence::inspect(&owner, &root, &instance).unwrap();
            if replace {
                let candidate = root.join("owned-replacement");
                write_private(&candidate, &fs::read(&lock_path).unwrap());
                fs::rename(candidate, &lock_path).unwrap();
            } else {
                write_private(&lock_path, canonical_lock(&instance, "2").as_bytes());
            }
            let before = evidence_snapshots(std::slice::from_ref(&lock_path));
            assert!(!evidence.is_current(&owner));
            assert!(matches!(
                super::VerifiedQuiescentInstance::try_verify(
                    &owner, &root, &instance, &data_dir, &format!("postgresql-17-{instance}"), &evidence
                ),
                Err(PostgresSidecarError::StartLockGuardInvalid)
            ));
            assert_eq!(evidence_snapshots(std::slice::from_ref(&lock_path)), before);
            assert!(
                !root
                    .join(format!(".postgresql-17-{instance}.recovery-epoch-v1"))
                    .exists()
            );
            drop(owner);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn observed_lock_replacement_after_mint_cannot_be_deleted() {
        let root = temp_root("067-after-mint-replace");
        let instance = "ef".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let owner = KernelStartLock::acquire(&root, &instance).unwrap();
        let evidence = super::StartLockEvidence::inspect(&owner, &root, &instance).unwrap();
        let verified = super::VerifiedQuiescentInstance::try_verify(
            &owner, &root, &instance, &data_dir, &format!("postgresql-17-{instance}"), &evidence,
        )
        .unwrap();
        let epoch = crate::postgres_sidecar::recovery_epoch::mint_or_replace_for_reclaim(
            &owner, &root, &instance,
        )
        .unwrap();
        let candidate = root.join("owned-replacement");
        write_private(&candidate, &fs::read(&lock_path).unwrap());
        fs::rename(candidate, &lock_path).unwrap();
        let paths = [
            lock_path,
            root.join(format!(".postgresql-17-{instance}.recovery-epoch-v1")),
        ];
        let before = evidence_snapshots(&paths);
        assert!(matches!(
            verified.reclaim_start_lock_evidence(&owner, &root),
            Err(PostgresSidecarError::StartLockGuardInvalid)
        ));
        assert_eq!(evidence_snapshots(&paths), before);
        assert!(epoch.is_current());
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_state_reclaims_stale_start_lock_then_acquire_succeeds() {
        let root = temp_root("reclaim");
        let instance = "a".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        write!(
            file,
            "openbot-postgres-start-lock-v1\npid=1\ninstance={instance}\nmanifest={}\nnonce={}\n",
            "11".repeat(32),
            "22".repeat(16)
        )
        .unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            PostgresStartLock::acquire(&root, &instance, PostgresBundleDigest([0x11; 32])),
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        ));

        let reclaimed = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(reclaimed.is_ok(), "{reclaimed:?}");
        assert!(!lock_path.exists() || reclaimed.is_ok());
        drop(reclaimed.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mid_phase_startup_journal_blocks_reclaim() {
        let root = temp_root("midphase");
        let instance = "b".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock_path = root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
        fs::write(
            &lock_path,
            format!(
                "openbot-postgres-start-lock-v1\npid=1\ninstance={instance}\nmanifest={}\nnonce={}\n",
                "11".repeat(32),
                "22".repeat(16)
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        // Minimal invalid/mid marker file that fails closed as RecoveryRequired or Invalid.
        fs::write(
            &journal,
            b"{\"schema\":\"openbot-postgres-startup\",\"phase\":\"spawn_entered\"}",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(lock_path.is_file());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn spawn_entered_null_child_deletes_and_reclaims_start_lock() {
        let root = temp_root("013-spawn-delete");
        let instance = "c".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "34".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": null,
            "phase": "spawn_entered"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(!journal.exists(), "spawn_entered journal should be deleted");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn child_observed_absent_child_advances_to_exit_confirmed_and_reclaims() {
        let root = temp_root("013-child-exit");
        let instance = "d".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "56".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let bytes = fs::read(&journal).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["phase"], "exit_confirmed");
        assert_eq!(value["childObservation"], child_hex);
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn crash_after_mid_phase_durable_write_restarts_from_files() {
        let root = temp_root("036-crash-during-recovery");
        let instance = "f".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "56".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let kernel = KernelStartLock::acquire(&root, &instance).unwrap();
        super::recover_mid_phase_journals(&kernel, &root, &instance, &data_dir, &format!("postgresql-17-{instance}")).unwrap();
        let after_crash_point: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after_crash_point["phase"], "exit_confirmed");
        assert!(
            lock_path.is_file(),
            "start-lock must remain when recovery crashes before reclaim"
        );
        drop(kernel);
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let after_restart: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after_restart["phase"], "exit_confirmed");
        assert_eq!(after_restart["childObservation"], child_hex);
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn live_child_observed_refuses_write_and_keeps_start_lock() {
        let root = temp_root("013-live-child");
        let instance = "e".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let journal = root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
        let before = serde_json::json!({
            "schema": "openbot-postgres-startup",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "78".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "childObservation": child_hex,
            "phase": "child_observed"
        });
        let before_bytes = serde_json::to_vec(&before).unwrap();
        write_private(&journal, &before_bytes);
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(matches!(
            rejected,
            Err(PostgresSidecarError::StartLockRecoveryRequired)
        ));
        assert_eq!(fs::read(&journal).unwrap(), before_bytes);
        assert!(lock_path.is_file());
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn helper_spawn_entered_null_child_deletes_and_reclaims() {
        let root = temp_root("013-helper-delete");
        let instance = "f".repeat(64);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "9a".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_postgres",
            "childObservation": null,
            "phase": "spawn_entered"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(!journal.exists());
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn existing_version_pg_ctl_exit_confirmed_completes_helpers_and_reclaims() {
        let root = temp_root("015-pgctl-complete");
        let instance = "17".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data_dir.join("PG_VERSION"), b"17\n").unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "ab".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_pg_ctl",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(value["phase"], "helpers_complete");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }

    #[test]
    fn version_postgres_exit_confirmed_does_not_complete_or_reclaim() {
        let root = temp_root("015-version-incomplete");
        let instance = "18".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(data_dir.join("PG_VERSION"), b"17\n").unwrap();
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let before = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "cd".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "version_postgres",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        let before_bytes = serde_json::to_vec(&before).unwrap();
        write_private(&journal, &before_bytes);
        let rejected = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(rejected.is_err(), "{rejected:?}");
        assert!(lock_path.is_file());
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(after["phase"], "exit_confirmed");
        assert_eq!(after["helperKind"], "version_postgres");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn fresh_initdb_exit_confirmed_completes_helpers_and_reclaims() {
        let root = temp_root("015-initdb-complete");
        let instance = "19".repeat(32);
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        // Fresh: empty data dir, no PG_VERSION
        let lock_path = plant_stale_lock(&root, &instance);
        let (device, inode) = data_dir_ids(&data_dir);
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(80));
        let child_identity = ProcessIdentity::capture(child.id()).unwrap();
        let child_hex = encode_hex(&child_identity.evidence_bytes().unwrap());
        let _ = child.kill();
        let _ = child.wait();
        thread::sleep(Duration::from_millis(40));
        let journal = root.join(format!(".postgresql-17-{instance}.helper-v1.json"));
        let record = serde_json::json!({
            "schema": "openbot-postgres-helper",
            "schemaVersion": 1,
            "instanceId": instance,
            "dataDirName": format!("postgresql-17-{instance}"),
            "dataDirDevice": device,
            "dataDirInode": inode,
            "attemptId": "ef".repeat(16),
            "startEvidenceSha256": "12".repeat(32),
            "ownerObservation": owner_observation_hex(),
            "helperKind": "initdb",
            "childObservation": child_hex,
            "phase": "exit_confirmed"
        });
        write_private(&journal, &serde_json::to_vec(&record).unwrap());
        let acquired = PostgresStartLock::acquire_with_data_dir(
            &root,
            &instance,
            PostgresBundleDigest([0x11; 32]),
            &data_dir,
        );
        assert!(acquired.is_ok(), "{acquired:?}");
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(value["phase"], "helpers_complete");
        drop(acquired.unwrap());
        let _ = fs::remove_dir_all(&root);
        let _ = lock_path;
    }
}
