//! Durable intent for the SCRAM-secret creation substep of Desktop PostgreSQL initialization.
//!
//! This deliberately does not model `initdb`, the application master key, a dataset canary, or
//! crash recovery. A persisted `write_entered` is an ambiguous terminal observation for this API.

use super::{PostgresDataDisposition, PostgresStartLock, encode_hex};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

const JOURNAL_SCHEMA: &str = "openbot-postgres-scram-creation";
const JOURNAL_SCHEMA_VERSION: u64 = 1;
const JOURNAL_MAX_BYTES: usize = 1024;
const RANDOM_ID_BYTES: usize = 16;
const MAX_CANDIDATE_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScramJournalPhase {
    Prepared,
    WriteEntered,
    ReadbackConfirmed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ScramJournalRecord {
    schema: String,
    schema_version: u64,
    instance_id: String,
    data_dir_name: String,
    attempt_id: String,
    key_id: String,
    phase: ScramJournalPhase,
}

pub(super) struct ScramCreationJournal {
    path: PathBuf,
    bytes: Vec<u8>,
    file: File,
    record: ScramJournalRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScramJournalError {
    DispositionInvalid,
    ReconciliationRequired,
    Unavailable,
}

impl ScramCreationJournal {
    pub(super) fn load(
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<Option<Self>, ScramJournalError> {
        let (root, path, data_dir_name) = journal_identity(owner, disposition)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ScramJournalError::ReconciliationRequired),
        }
        let file =
            secure_open_read_write(&path).map_err(|_| ScramJournalError::ReconciliationRequired)?;
        let bytes = read_bound_file(&path, &file)?;
        let record: ScramJournalRecord = serde_json::from_slice(&bytes)
            .map_err(|_| ScramJournalError::ReconciliationRequired)?;
        validate_record(&record, &owner.instance_id, &data_dir_name)?;
        ensure_bound(owner, disposition, root, &path, &file, &bytes)?;
        Ok(Some(Self {
            path,
            bytes,
            file,
            record,
        }))
    }

    pub(super) fn prepare(
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<Self, ScramJournalError> {
        if !disposition.is_fresh() {
            return Err(ScramJournalError::DispositionInvalid);
        }
        let (root, path, data_dir_name) = journal_identity(owner, disposition)?;
        let record = ScramJournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            schema_version: JOURNAL_SCHEMA_VERSION,
            instance_id: owner.instance_id.to_string(),
            data_dir_name,
            attempt_id: random_id()?,
            key_id: random_id()?,
            phase: ScramJournalPhase::Prepared,
        };
        let bytes = encode_record(&record)?;
        let (candidate_path, mut candidate) = create_candidate(root, &owner.instance_id)?;
        if candidate
            .write_all(&bytes)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            return Err(ScramJournalError::ReconciliationRequired);
        }
        ensure_bound(
            owner,
            disposition,
            root,
            &candidate_path,
            &candidate,
            &bytes,
        )?;
        match fs::hard_link(&candidate_path, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                remove_exact_candidate(&candidate_path, &candidate, &bytes, 1);
                return Err(ScramJournalError::ReconciliationRequired);
            }
            Err(_) => {
                remove_exact_candidate(&candidate_path, &candidate, &bytes, 1);
                return Err(ScramJournalError::ReconciliationRequired);
            }
        }
        if sync_directory(root).is_err()
            || !path_matches_open_file(&path, &candidate, &bytes, Some(2))
            || !remove_exact_candidate(&candidate_path, &candidate, &bytes, 2)
            || sync_directory(root).is_err()
            || !path_matches_open_file(&path, &candidate, &bytes, Some(1))
            || !disposition.is_current_for(owner)
        {
            return Err(ScramJournalError::ReconciliationRequired);
        }
        Ok(Self {
            path,
            bytes,
            file: candidate,
            record,
        })
    }

    #[must_use]
    pub(super) const fn phase(&self) -> ScramJournalPhase {
        self.record.phase
    }

    pub(super) fn revalidate(
        &self,
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<(), ScramJournalError> {
        let (root, expected_path, data_dir_name) = journal_identity(owner, disposition)?;
        if self.path != expected_path
            || self.record.instance_id != owner.instance_id.as_ref()
            || self.record.data_dir_name != data_dir_name
        {
            return Err(ScramJournalError::ReconciliationRequired);
        }
        ensure_bound(
            owner,
            disposition,
            root,
            &self.path,
            &self.file,
            &self.bytes,
        )
    }

    pub(super) fn revalidate_absent(
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<(), ScramJournalError> {
        let (_, path, _) = journal_identity(owner, disposition)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(ScramJournalError::ReconciliationRequired),
        }
        if !disposition.is_current_for(owner) {
            return Err(ScramJournalError::DispositionInvalid);
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(ScramJournalError::ReconciliationRequired),
        }
    }

    pub(super) fn enter_write(
        &mut self,
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<(), ScramJournalError> {
        self.advance(
            owner,
            disposition,
            ScramJournalPhase::Prepared,
            ScramJournalPhase::WriteEntered,
        )
    }

    pub(super) fn confirm_readback(
        &mut self,
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
    ) -> Result<(), ScramJournalError> {
        self.advance(
            owner,
            disposition,
            ScramJournalPhase::WriteEntered,
            ScramJournalPhase::ReadbackConfirmed,
        )
    }

    fn advance(
        &mut self,
        owner: &PostgresStartLock,
        disposition: &PostgresDataDisposition<'_>,
        expected: ScramJournalPhase,
        next: ScramJournalPhase,
    ) -> Result<(), ScramJournalError> {
        if self.record.phase != expected {
            return Err(ScramJournalError::ReconciliationRequired);
        }
        let (root, expected_path, data_dir_name) = journal_identity(owner, disposition)?;
        if self.path != expected_path
            || self.record.instance_id != owner.instance_id.as_ref()
            || self.record.data_dir_name != data_dir_name
        {
            return Err(ScramJournalError::ReconciliationRequired);
        }
        ensure_bound(
            owner,
            disposition,
            root,
            &self.path,
            &self.file,
            &self.bytes,
        )?;
        self.record.phase = next;
        let next_bytes = encode_record(&self.record)?;
        let (candidate_path, mut candidate) = create_candidate(root, &owner.instance_id)?;
        if candidate
            .write_all(&next_bytes)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            self.record.phase = expected;
            return Err(ScramJournalError::ReconciliationRequired);
        }
        if ensure_bound(
            owner,
            disposition,
            root,
            &self.path,
            &self.file,
            &self.bytes,
        )
        .is_err()
            || !path_matches_open_file(&candidate_path, &candidate, &next_bytes, Some(1))
        {
            self.record.phase = expected;
            remove_exact_candidate(&candidate_path, &candidate, &next_bytes, 1);
            return Err(ScramJournalError::ReconciliationRequired);
        }
        if fs::rename(&candidate_path, &self.path).is_err()
            || sync_directory(root).is_err()
            || !path_matches_open_file(&self.path, &candidate, &next_bytes, Some(1))
            || !disposition.is_current_for(owner)
        {
            self.record.phase = expected;
            return Err(ScramJournalError::ReconciliationRequired);
        }
        self.bytes = next_bytes;
        self.file = candidate;
        Ok(())
    }
}

fn journal_identity<'a>(
    owner: &'a PostgresStartLock,
    disposition: &PostgresDataDisposition<'_>,
) -> Result<(&'a Path, PathBuf, String), ScramJournalError> {
    if !disposition.is_current_for(owner) {
        return Err(ScramJournalError::DispositionInvalid);
    }
    let root = owner
        .path
        .parent()
        .ok_or(ScramJournalError::DispositionInvalid)?;
    let expected_data_dir = root.join(&*owner.data_dir_name);
    if disposition.data_dir() != expected_data_dir {
        return Err(ScramJournalError::DispositionInvalid);
    }
    let data_dir_name = expected_data_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ScramJournalError::DispositionInvalid)?
        .to_owned();
    let path = root.join(format!(
        ".postgresql-17-{}.scram-init-v1.json",
        owner.instance_id
    ));
    Ok((root, path, data_dir_name))
}

fn validate_record(
    record: &ScramJournalRecord,
    instance_id: &str,
    data_dir_name: &str,
) -> Result<(), ScramJournalError> {
    if record.schema != JOURNAL_SCHEMA
        || record.schema_version != JOURNAL_SCHEMA_VERSION
        || record.instance_id != instance_id
        || record.data_dir_name != data_dir_name
        || !valid_random_id(&record.attempt_id)
        || !valid_random_id(&record.key_id)
    {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    Ok(())
}

fn encode_record(record: &ScramJournalRecord) -> Result<Vec<u8>, ScramJournalError> {
    let bytes =
        serde_json::to_vec(record).map_err(|_| ScramJournalError::ReconciliationRequired)?;
    if bytes.len() > JOURNAL_MAX_BYTES {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    Ok(bytes)
}

fn random_id() -> Result<String, ScramJournalError> {
    let mut value = [0_u8; RANDOM_ID_BYTES];
    getrandom::fill(&mut value).map_err(|_| ScramJournalError::Unavailable)?;
    Ok(encode_hex(&value))
}

fn valid_random_id(value: &str) -> bool {
    value.len() == RANDOM_ID_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn candidate_path(root: &Path, instance_id: &str) -> Result<PathBuf, ScramJournalError> {
    Ok(root.join(format!(
        ".postgresql-17-{instance_id}.scram-init-v1.json.candidate-{}",
        random_id()?
    )))
}

fn create_candidate(root: &Path, instance_id: &str) -> Result<(PathBuf, File), ScramJournalError> {
    for _ in 0..MAX_CANDIDATE_ATTEMPTS {
        let path = candidate_path(root, instance_id)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        add_secure_open_flags(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ScramJournalError::ReconciliationRequired),
        }
    }
    Err(ScramJournalError::ReconciliationRequired)
}

fn secure_open_read_write(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    add_secure_open_flags(&mut options);
    options.open(path)
}

fn add_secure_open_flags(options: &mut OpenOptions) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x100 | 0x4);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(0x2_0000 | 0x800);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000).share_mode(0x3);
    }
}

fn read_bound_file(path: &Path, file: &File) -> Result<Vec<u8>, ScramJournalError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ScramJournalError::ReconciliationRequired)?;
    let length =
        usize::try_from(metadata.len()).map_err(|_| ScramJournalError::ReconciliationRequired)?;
    if length == 0 || length > JOURNAL_MAX_BYTES {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    let mut bytes = vec![0_u8; length + 1];
    let read = positioned_read(file, &mut bytes)?;
    if read != length {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    bytes.truncate(read);
    if !path_matches_open_file(path, file, &bytes, Some(1)) {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    Ok(bytes)
}

fn ensure_bound(
    owner: &PostgresStartLock,
    disposition: &PostgresDataDisposition<'_>,
    root: &Path,
    path: &Path,
    file: &File,
    expected: &[u8],
) -> Result<(), ScramJournalError> {
    if owner.path.parent() != Some(root)
        || !disposition.is_current_for(owner)
        || !path_matches_open_file(path, file, expected, Some(1))
    {
        return Err(ScramJournalError::ReconciliationRequired);
    }
    Ok(())
}

fn path_matches_open_file(
    path: &Path,
    file: &File,
    expected: &[u8],
    expected_links: Option<u64>,
) -> bool {
    let Ok(path_before) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_before) = file.metadata() else {
        return false;
    };
    if !valid_metadata(&path_before, expected.len())
        || !same_file(&path_before, &file_before)
        || expected_links.is_some_and(|links| link_count(&file_before) != Some(links))
        || !positioned_equal(file, expected)
    {
        return false;
    }
    let Ok(path_after) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_after) = file.metadata() else {
        return false;
    };
    valid_metadata(&path_after, expected.len())
        && same_file(&path_after, &file_after)
        && expected_links.is_none_or(|links| link_count(&file_after) == Some(links))
}

fn valid_metadata(metadata: &fs::Metadata, expected_len: usize) -> bool {
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

#[cfg(not(unix))]
fn same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn link_count(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Some(metadata.nlink())
}

#[cfg(not(unix))]
fn link_count(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn positioned_read(file: &File, buffer: &mut [u8]) -> Result<usize, ScramJournalError> {
    use std::os::unix::fs::FileExt as _;

    let mut read = 0_usize;
    while read < buffer.len() {
        let offset = u64::try_from(read).map_err(|_| ScramJournalError::ReconciliationRequired)?;
        match file.read_at(&mut buffer[read..], offset) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ScramJournalError::ReconciliationRequired),
        }
    }
    Ok(read)
}

#[cfg(not(unix))]
fn positioned_read(_file: &File, _buffer: &mut [u8]) -> Result<usize, ScramJournalError> {
    Err(ScramJournalError::ReconciliationRequired)
}

fn positioned_equal(file: &File, expected: &[u8]) -> bool {
    let Some(length) = expected.len().checked_add(1) else {
        return false;
    };
    let mut actual = vec![0_u8; length];
    let Ok(read) = positioned_read(file, &mut actual) else {
        return false;
    };
    read == expected.len() && &actual[..read] == expected
}

fn remove_exact_candidate(path: &Path, file: &File, expected: &[u8], links: u64) -> bool {
    path_matches_open_file(path, file, expected, Some(links)) && fs::remove_file(path).is_ok()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
