//! Durable five-phase Desktop master/canary initialization intent.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::desktop_local_bootstrap::PreparedDesktopLocalDataPlane;

const SCHEMA: &str = "openbot-desktop-master-creation";
const VERSION: u64 = 1;
const MAX_BYTES: usize = 2048;
const ID_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MasterJournalPhase {
    Prepared,
    WriteEntered,
    ReadbackConfirmed,
    CanaryWriteEntered,
    CanaryConfirmed,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Record {
    schema: String,
    schema_version: u64,
    instance_id: String,
    data_dir_name: String,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    attempt_id: String,
    key_id: String,
    key_version: u32,
    phase: MasterJournalPhase,
}

pub(crate) struct MasterInitializationJournal {
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    record: Record,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum JournalError {
    ReconciliationRequired,
    Unavailable,
}

impl MasterInitializationJournal {
    pub(super) fn load(
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<Option<Self>, JournalError> {
        owner_current(owner)?;
        let path = journal_path(owner)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) => {}
            Err(_) => return Err(JournalError::ReconciliationRequired),
        }
        let file = secure_open(&path).map_err(|_| JournalError::ReconciliationRequired)?;
        let bytes = read_bounded(&path, &file)?;
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::ReconciliationRequired)?;
        validate_record(owner, &record)?;
        ensure_current(owner, &path, &file, &bytes)?;
        Ok(Some(Self {
            path,
            file,
            bytes,
            record,
        }))
    }

    pub(super) fn prepare(owner: &PreparedDesktopLocalDataPlane) -> Result<Self, JournalError> {
        owner_current(owner)?;
        let instance = owner.authority().instance_id();
        let record = Record {
            schema: SCHEMA.to_owned(),
            schema_version: VERSION,
            instance_id: instance.to_owned(),
            data_dir_name: format!("postgresql-17-{instance}"),
            dataset_id: random_id()?,
            deployment_id: owner
                .authority()
                .auth_context()
                .deployment()
                .as_str()
                .to_owned(),
            tenant_id: owner
                .authority()
                .auth_context()
                .tenant()
                .as_str()
                .to_owned(),
            attempt_id: random_id()?,
            key_id: random_id()?,
            key_version: 1,
            phase: MasterJournalPhase::Prepared,
        };
        let bytes = encode(&record)?;
        let root = root(owner)?;
        let path = journal_path(owner)?;
        let (candidate_path, mut file) = candidate(root, instance)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| JournalError::ReconciliationRequired)?;
        ensure_current(owner, &candidate_path, &file, &bytes)?;
        match fs::hard_link(&candidate_path, &path) {
            Ok(()) => {}
            Err(_) => {
                remove_candidate(&candidate_path, &file, &bytes, 1);
                return Err(JournalError::ReconciliationRequired);
            }
        }
        if sync_dir(root).is_err()
            || !matches_file(&path, &file, &bytes, 2)
            || !remove_candidate(&candidate_path, &file, &bytes, 2)
            || sync_dir(root).is_err()
            || !matches_file(&path, &file, &bytes, 1)
        {
            return Err(JournalError::ReconciliationRequired);
        }
        owner_current(owner)?;
        Ok(Self {
            path,
            file,
            bytes,
            record,
        })
    }

    pub(super) fn revalidate(
        &self,
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        validate_record(owner, &self.record)?;
        ensure_current(owner, &self.path, &self.file, &self.bytes)
    }

    /// Check the exact original file after the normal database owner has closed.
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn revalidate_retained(&self) -> Result<(), JournalError> {
        if self.record.phase != MasterJournalPhase::CanaryConfirmed
            || !matches_file(&self.path, &self.file, &self.bytes, 1)
        {
            return Err(JournalError::ReconciliationRequired);
        }
        Ok(())
    }

    /// Runtime validation of the same confirmed journal; no reopen or duplicate.
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn revalidate_retained_before(
        &self,
        clock: &dyn openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        use std::os::unix::fs::{FileExt as _, MetadataExt as _};
        clock.require_effect()?;
        if self.record.phase != MasterJournalPhase::CanaryConfirmed
            || self.bytes.is_empty() || self.bytes.len() > MAX_BYTES
        {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()?;
        let observed_named = fs::symlink_metadata(&self.path);
        clock.require_effect()?;
        let before = observed_named.map_err(|_| Fault::IoFailure)?;
        clock.require_effect()?;
        let observed_held = self.file.metadata();
        clock.require_effect()?;
        let held = observed_held.map_err(|_| Fault::IoFailure)?;
        let identity = |m: &fs::Metadata| {
            (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len(),
                m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
        };
        if !shape(&before, self.bytes.len()) || !shape(&held, self.bytes.len())
            || !same(&before, &held) || nlink(&held) != Some(1)
            || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o7777 != 0o600
            || identity(&before) != identity(&held)
        {
            return Err(Fault::SourceChanged);
        }
        // A fixed bounded buffer replaces the startup matcher's unclocked temporary Vec.
        let mut value = [0_u8; MAX_BYTES];
        let mut offset = 0;
        while offset < self.bytes.len() {
            clock.require_effect()?;
            let observed = self.file.read_at(&mut value[offset..self.bytes.len()], offset as u64);
            clock.require_effect()?;
            match observed {
                Ok(0) => return Err(Fault::SourceChanged),
                Ok(n) => offset = offset.checked_add(n).ok_or(Fault::BoundsOverflow)?,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Fault::IoFailure),
            }
        }
        let mut tail = [0_u8; 1];
        loop {
            clock.require_effect()?;
            let observed = self.file.read_at(&mut tail, self.bytes.len() as u64);
            clock.require_effect()?;
            match observed {
                Ok(0) => break,
                Ok(_) => return Err(Fault::SourceChanged),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Fault::IoFailure),
            }
        }
        if value[..self.bytes.len()] != self.bytes[..] {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()?;
        let observed_named = fs::symlink_metadata(&self.path);
        clock.require_effect()?;
        let after = observed_named.map_err(|_| Fault::IoFailure)?;
        clock.require_effect()?;
        let observed_held = self.file.metadata();
        clock.require_effect()?;
        let held_after = observed_held.map_err(|_| Fault::IoFailure)?;
        if !shape(&after, self.bytes.len()) || !shape(&held_after, self.bytes.len())
            || !same(&after, &held_after) || nlink(&held_after) != Some(1)
            || identity(&after) != identity(&held_after)
            || identity(&held) != identity(&held_after)
        {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn retained_material(&self) -> Result<(File, Vec<u8>), JournalError> {
        self.revalidate_retained()?;
        let file = self
            .file
            .try_clone()
            .map_err(|_| JournalError::Unavailable)?;
        self.revalidate_retained()?;
        Ok((file, self.bytes.clone()))
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn into_retained_material(self) -> (File, Vec<u8>) {
        // The unique parent validates immediately before this pure, infallible ownership move.
        (self.file, self.bytes)
    }

    pub(super) fn revalidate_absent(
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        owner_current(owner)?;
        let path = journal_path(owner)?;
        for _ in 0..2 {
            if !matches!(fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            {
                return Err(JournalError::ReconciliationRequired);
            }
            owner_current(owner)?;
        }
        Ok(())
    }

    pub(super) const fn phase(&self) -> MasterJournalPhase {
        self.record.phase
    }
    pub(super) fn dataset_id(&self) -> &str {
        &self.record.dataset_id
    }
    pub(super) fn deployment_id(&self) -> &str {
        &self.record.deployment_id
    }
    pub(super) fn tenant_id(&self) -> &str {
        &self.record.tenant_id
    }
    pub(super) fn key_id(&self) -> &str {
        &self.record.key_id
    }

    pub(super) fn enter_write(
        &mut self,
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        self.advance(
            owner,
            MasterJournalPhase::Prepared,
            MasterJournalPhase::WriteEntered,
        )
    }
    pub(super) fn confirm_readback(
        &mut self,
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        self.advance(
            owner,
            MasterJournalPhase::WriteEntered,
            MasterJournalPhase::ReadbackConfirmed,
        )
    }
    pub(super) fn enter_canary_write(
        &mut self,
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        self.advance(
            owner,
            MasterJournalPhase::ReadbackConfirmed,
            MasterJournalPhase::CanaryWriteEntered,
        )
    }
    pub(super) fn confirm_canary(
        &mut self,
        owner: &PreparedDesktopLocalDataPlane,
    ) -> Result<(), JournalError> {
        self.advance(
            owner,
            MasterJournalPhase::CanaryWriteEntered,
            MasterJournalPhase::CanaryConfirmed,
        )
    }

    fn advance(
        &mut self,
        owner: &PreparedDesktopLocalDataPlane,
        expected: MasterJournalPhase,
        next: MasterJournalPhase,
    ) -> Result<(), JournalError> {
        if self.record.phase != expected {
            return Err(JournalError::ReconciliationRequired);
        }
        self.revalidate(owner)?;
        self.record.phase = next;
        let next_bytes = encode(&self.record)?;
        let root = root(owner)?;
        let (candidate_path, mut candidate) = candidate(root, &self.record.instance_id)?;
        if candidate
            .write_all(&next_bytes)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            self.record.phase = expected;
            return Err(JournalError::ReconciliationRequired);
        }
        if self.revalidate(owner).is_err()
            || !matches_file(&candidate_path, &candidate, &next_bytes, 1)
        {
            self.record.phase = expected;
            remove_candidate(&candidate_path, &candidate, &next_bytes, 1);
            return Err(JournalError::ReconciliationRequired);
        }
        if fs::rename(&candidate_path, &self.path).is_err()
            || sync_dir(root).is_err()
            || !matches_file(&self.path, &candidate, &next_bytes, 1)
        {
            self.record.phase = expected;
            return Err(JournalError::ReconciliationRequired);
        }
        owner_current(owner)?;
        self.file = candidate;
        self.bytes = next_bytes;
        Ok(())
    }
}

fn validate_record(
    owner: &PreparedDesktopLocalDataPlane,
    record: &Record,
) -> Result<(), JournalError> {
    let instance = owner.authority().instance_id();
    if record.schema != SCHEMA
        || record.schema_version != VERSION
        || record.instance_id != instance
        || record.data_dir_name != format!("postgresql-17-{instance}")
        || record.deployment_id != owner.authority().auth_context().deployment().as_str()
        || record.tenant_id != owner.authority().auth_context().tenant().as_str()
        || !id(&record.dataset_id)
        || !id(&record.attempt_id)
        || !id(&record.key_id)
        || record.key_version != 1
    {
        return Err(JournalError::ReconciliationRequired);
    }
    Ok(())
}

fn owner_current(owner: &PreparedDesktopLocalDataPlane) -> Result<(), JournalError> {
    owner
        .ensure_owner_current()
        .map_err(|_| JournalError::ReconciliationRequired)
}

fn root(owner: &PreparedDesktopLocalDataPlane) -> Result<&Path, JournalError> {
    owner
        .data_dir()
        .parent()
        .ok_or(JournalError::ReconciliationRequired)
}

fn journal_path(owner: &PreparedDesktopLocalDataPlane) -> Result<PathBuf, JournalError> {
    Ok(root(owner)?.join(format!(
        ".desktop-vault-{}.master-init-v1.json",
        owner.authority().instance_id()
    )))
}

fn random_id() -> Result<String, JournalError> {
    let mut bytes = [0_u8; ID_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| JournalError::Unavailable)?;
    Ok(hex(&bytes))
}

fn candidate(root: &Path, instance: &str) -> Result<(PathBuf, File), JournalError> {
    for _ in 0..8 {
        let path = root.join(format!(
            ".desktop-vault-{instance}.master-init-v1.json.candidate-{}",
            random_id()?
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        secure_flags(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(JournalError::ReconciliationRequired),
        }
    }
    Err(JournalError::ReconciliationRequired)
}

fn encode(record: &Record) -> Result<Vec<u8>, JournalError> {
    let bytes = serde_json::to_vec(record).map_err(|_| JournalError::ReconciliationRequired)?;
    if bytes.len() > MAX_BYTES {
        Err(JournalError::ReconciliationRequired)
    } else {
        Ok(bytes)
    }
}

fn read_bounded(path: &Path, file: &File) -> Result<Vec<u8>, JournalError> {
    let length = usize::try_from(
        fs::symlink_metadata(path)
            .map_err(|_| JournalError::ReconciliationRequired)?
            .len(),
    )
    .map_err(|_| JournalError::ReconciliationRequired)?;
    if length == 0 || length > MAX_BYTES {
        return Err(JournalError::ReconciliationRequired);
    }
    let mut bytes = vec![0_u8; length + 1];
    let read = read_at(file, &mut bytes)?;
    if read != length {
        return Err(JournalError::ReconciliationRequired);
    }
    bytes.truncate(read);
    if !matches_file(path, file, &bytes, 1) {
        return Err(JournalError::ReconciliationRequired);
    }
    Ok(bytes)
}

fn ensure_current(
    owner: &PreparedDesktopLocalDataPlane,
    path: &Path,
    file: &File,
    bytes: &[u8],
) -> Result<(), JournalError> {
    owner_current(owner)?;
    if matches_file(path, file, bytes, 1) {
        Ok(())
    } else {
        Err(JournalError::ReconciliationRequired)
    }
}

fn matches_file(path: &Path, file: &File, bytes: &[u8], links: u64) -> bool {
    let (Ok(before), Ok(held)) = (fs::symlink_metadata(path), file.metadata()) else {
        return false;
    };
    if !shape(&before, bytes.len())
        || !same(&before, &held)
        || nlink(&held) != Some(links)
        || !equal_at(file, bytes)
    {
        return false;
    }
    let (Ok(after), Ok(held_after)) = (fs::symlink_metadata(path), file.metadata()) else {
        return false;
    };
    shape(&after, bytes.len()) && same(&after, &held_after) && nlink(&held_after) == Some(links)
}

fn shape(metadata: &fs::Metadata, length: usize) -> bool {
    let Ok(length) = u64::try_from(length) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != length
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
    true
}

#[cfg(unix)]
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
}
#[cfg(unix)]
fn nlink(m: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Some(m.nlink())
}
#[cfg(not(unix))]
fn nlink(_: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn read_at(file: &File, bytes: &mut [u8]) -> Result<usize, JournalError> {
    use std::os::unix::fs::FileExt as _;
    let mut read = 0;
    while read < bytes.len() {
        match file.read_at(&mut bytes[read..], read as u64) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(JournalError::ReconciliationRequired),
        }
    }
    Ok(read)
}
#[cfg(not(unix))]
fn read_at(_: &File, _: &mut [u8]) -> Result<usize, JournalError> {
    Err(JournalError::ReconciliationRequired)
}
fn equal_at(file: &File, expected: &[u8]) -> bool {
    let mut value = vec![0; expected.len() + 1];
    matches!(read_at(file,&mut value),Ok(n) if n==expected.len() && &value[..n]==expected)
}

fn secure_open(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    secure_flags(&mut o);
    o.open(path)
}
fn secure_flags(options: &mut OpenOptions) {
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
fn remove_candidate(path: &Path, file: &File, bytes: &[u8], links: u64) -> bool {
    matches_file(path, file, bytes, links) && fs::remove_file(path).is_ok()
}
#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_dir(_: &Path) -> std::io::Result<()> {
    Ok(())
}
fn id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(H[usize::from(b >> 4)]));
        s.push(char::from(H[usize::from(b & 15)]));
    }
    s
}
