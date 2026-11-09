//! Durable intent and confirmed-exit record for version and initdb helper children.
//!
//! This journal is additional fail-closed helper evidence. It does not discover foreign
//! processes, prove a data directory quiescent, remove stale evidence, or grant recovery authority.

mod record;

pub(crate) use self::record::HelperKind;
use self::record::{HelperJournalPhase, HelperJournalRecord};
use super::{PostgresStartLock, encode_hex};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use wrok_bot_macos_process::ProcessIdentity;

const JOURNAL_SCHEMA: &str = "openbot-postgres-helper";
const JOURNAL_SCHEMA_VERSION: u64 = 1;
const JOURNAL_MAX_BYTES: usize = 2048;
const PG_VERSION_MAX_BYTES: usize = 16;
const RANDOM_ID_BYTES: usize = 16;
const OBSERVATION_BYTES: usize = 32;
const OBSERVATION_HEX_BYTES: usize = OBSERVATION_BYTES * 2;
const SHA256_HEX_BYTES: usize = 64;
const MAX_CANDIDATE_ATTEMPTS: usize = 8;

/// Read-only preflight bound to one current owner and one opened data directory.
pub(super) struct HelperJournalPreparation {
    root: PathBuf,
    path: PathBuf,
    data_dir_path: PathBuf,
    data_dir_file: File,
    data_dir_device: u64,
    data_dir_inode: u64,
    root_uid: u32,
    owner_identity: ProcessIdentity,
    owner_observation: [u8; OBSERVATION_BYTES],
    previous: PreviousJournal,
}

enum PreviousJournal {
    Absent,
    Retired {
        file: File,
        bytes: Vec<u8>,
        record: Box<HelperJournalRecord>,
    },
}

/// One live startup attempt whose exact file and directory identities remain held.
pub(super) struct HelperJournal {
    root: PathBuf,
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    record: HelperJournalRecord,
    data_dir_path: PathBuf,
    data_dir_file: File,
    data_dir_device: u64,
    data_dir_inode: u64,
    root_uid: u32,
    owner_identity: ProcessIdentity,
    owner_observation: [u8; OBSERVATION_BYTES],
}

/// Closed failure classes for startup-journal inspection and mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HelperJournalError {
    /// A valid record exists in a non-retired phase and requires a later recovery protocol.
    RecoveryRequired,
    /// A record, path, owner, observation, or directory has invalid identity or shape.
    Invalid,
    /// A write, replacement, or later recheck could not establish its exact committed result.
    ReconciliationRequired,
}

impl fmt::Debug for HelperJournalPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperJournalPreparation")
            .field(
                "state",
                &match &self.previous {
                    PreviousJournal::Absent => "Absent",
                    PreviousJournal::Retired { .. } => "Retired",
                },
            )
            .finish()
    }
}

impl fmt::Debug for HelperJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperJournal")
            .field("phase", &self.record.phase)
            .field("kind", &self.record.helper_kind)
            .finish()
    }
}

impl HelperJournalPreparation {
    /// Inspect without writing before any version helper spawn.
    pub(super) fn inspect(
        owner: &PostgresStartLock,
        data_dir: &Path,
    ) -> Result<Self, HelperJournalError> {
        owner
            .ensure_current()
            .map_err(|_| HelperJournalError::Invalid)?;
        let (root, path, data_dir_name) = journal_identity(owner, data_dir)?;
        let directory = open_data_directory(owner, root, data_dir)?;
        let owner_identity = ProcessIdentity::capture(std::process::id())
            .map_err(|_| HelperJournalError::Invalid)?;
        let owner_observation = owner_identity
            .evidence_bytes()
            .map_err(|_| HelperJournalError::Invalid)?;

        let previous = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure_journal_absent(owner, &directory, &path)?;
                PreviousJournal::Absent
            }
            Ok(metadata) => {
                if !valid_journal_metadata(&metadata, directory.root_uid, None) {
                    return Err(HelperJournalError::Invalid);
                }
                let file = secure_open_file(&path).map_err(|_| HelperJournalError::Invalid)?;
                let bytes = read_bounded_file(&path, &file, directory.root_uid)?;
                let record: HelperJournalRecord =
                    serde_json::from_slice(&bytes).map_err(|_| HelperJournalError::Invalid)?;
                let validated = validate_record(&record, &owner.instance_id, &data_dir_name)?;
                if record.phase != HelperJournalPhase::HelpersComplete {
                    return Err(HelperJournalError::RecoveryRequired);
                }
                ensure_retired_bound(owner, &directory, &path, &file, &bytes)?;
                if validated.owner.boot_session == current_boot(&owner_observation)
                    && (record.data_dir_device != directory.device
                        || record.data_dir_inode != directory.inode)
                {
                    return Err(HelperJournalError::Invalid);
                }
                PreviousJournal::Retired {
                    file,
                    bytes,
                    record: Box::new(record),
                }
            }
            Err(_) => return Err(HelperJournalError::ReconciliationRequired),
        };
        let preparation = Self {
            root: root.to_owned(),
            path,
            data_dir_path: data_dir.to_owned(),
            data_dir_file: directory.file,
            data_dir_device: directory.device,
            data_dir_inode: directory.inode,
            root_uid: directory.root_uid,
            owner_identity,
            owner_observation,
            previous,
        };
        preparation.revalidate(owner)?;
        Ok(preparation)
    }

    /// Recheck the exact owner, data-directory handle, and absent/retired preflight observation.
    pub(super) fn revalidate(&self, owner: &PostgresStartLock) -> Result<(), HelperJournalError> {
        validate_owner_and_directory(
            owner,
            &self.root,
            DirectoryObservation {
                path: &self.data_dir_path,
                file: &self.data_dir_file,
                device: self.data_dir_device,
                inode: self.data_dir_inode,
                root_uid: self.root_uid,
            },
            &self.owner_identity,
            &self.owner_observation,
        )?;
        match &self.previous {
            PreviousJournal::Absent => ensure_journal_absent_parts(
                owner,
                &self.data_dir_path,
                &self.data_dir_file,
                self.data_dir_device,
                self.data_dir_inode,
                self.root_uid,
                &self.path,
            ),
            PreviousJournal::Retired {
                file,
                bytes,
                record,
            } => {
                let validated = validate_record(
                    record,
                    &owner.instance_id,
                    &*owner.data_dir_name,
                )?;
                if record.phase != HelperJournalPhase::HelpersComplete {
                    return Err(HelperJournalError::ReconciliationRequired);
                }
                if validated.owner.boot_session == current_boot(&self.owner_observation)
                    && (record.data_dir_device != self.data_dir_device
                        || record.data_dir_inode != self.data_dir_inode)
                {
                    return Err(HelperJournalError::Invalid);
                }
                if !path_matches_open_file(&self.path, file, bytes, self.root_uid, Some(1)) {
                    return Err(HelperJournalError::ReconciliationRequired);
                }
                Ok(())
            }
        }
    }

    /// Commit `spawn_entered` for the first version helper before spawning it.
    ///
    /// The caller must first set this exact `PostgresStartLock` to preserve-on-drop. This method
    /// verifies that precondition; it neither spawns nor authorizes a process. The first kind must
    /// be `version_postgres`.
    pub(super) fn begin_helper(
        self,
        owner: &PostgresStartLock,
        kind: HelperKind,
    ) -> Result<HelperJournal, HelperJournalError> {
        self.revalidate(owner)?;
        if owner.remove_on_drop {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        if kind != HelperKind::VersionPostgres {
            return Err(HelperJournalError::Invalid);
        }
        self.owner_identity
            .revalidate()
            .map_err(|_| HelperJournalError::Invalid)?;
        let owner_observation = self
            .owner_identity
            .evidence_bytes()
            .map_err(|_| HelperJournalError::Invalid)?;
        if owner_observation != self.owner_observation {
            return Err(HelperJournalError::Invalid);
        }
        let record = HelperJournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            schema_version: JOURNAL_SCHEMA_VERSION,
            instance_id: owner.instance_id.to_string(),
            data_dir_name: owner.data_dir_name.to_string(),
            data_dir_device: self.data_dir_device,
            data_dir_inode: self.data_dir_inode,
            attempt_id: random_id()?,
            start_evidence_sha256: start_evidence_sha256(owner),
            owner_observation: encode_hex(&owner_observation),
            helper_kind: kind,
            child_observation: None,
            phase: HelperJournalPhase::SpawnEntered,
        };
        let bytes = encode_record(&record)?;
        let (file, committed_bytes) = match &self.previous {
            PreviousJournal::Absent => publish_absent(owner, &self, &record, bytes)?,
            PreviousJournal::Retired {
                file: old_file,
                bytes: old_bytes,
                ..
            } => replace_exact(owner, &self, old_file, old_bytes, &record, bytes)?,
        };
        Ok(HelperJournal {
            root: self.root,
            path: self.path,
            file,
            bytes: committed_bytes,
            record,
            data_dir_path: self.data_dir_path,
            data_dir_file: self.data_dir_file,
            data_dir_device: self.data_dir_device,
            data_dir_inode: self.data_dir_inode,
            root_uid: self.root_uid,
            owner_identity: self.owner_identity,
            owner_observation,
        })
    }
}

impl HelperJournal {
    /// Recheck the live owner, process observation, directory handle, and exact journal bytes.
    pub(super) fn revalidate(&self, owner: &PostgresStartLock) -> Result<(), HelperJournalError> {
        validate_owner_and_directory(
            owner,
            &self.root,
            DirectoryObservation {
                path: &self.data_dir_path,
                file: &self.data_dir_file,
                device: self.data_dir_device,
                inode: self.data_dir_inode,
                root_uid: self.root_uid,
            },
            &self.owner_identity,
            &self.owner_observation,
        )?;
        if self.record.start_evidence_sha256 != start_evidence_sha256(owner)
            || self.record.owner_observation != encode_hex(&self.owner_observation)
            || self.record.data_dir_device != self.data_dir_device
            || self.record.data_dir_inode != self.data_dir_inode
            || !path_matches_open_file(&self.path, &self.file, &self.bytes, self.root_uid, Some(1))
        {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        validate_record(
            &self.record,
            &owner.instance_id,
            &*owner.data_dir_name,
        )?;
        Ok(())
    }

    /// Persist the observation of the same current helper child held by the Supervisor.
    pub(super) fn record_child(
        &mut self,
        owner: &PostgresStartLock,
        child: &ProcessIdentity,
    ) -> Result<(), HelperJournalError> {
        if self.record.phase != HelperJournalPhase::SpawnEntered {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        self.revalidate(owner)?;
        let child_observation = child
            .evidence_bytes()
            .map_err(|_| HelperJournalError::Invalid)?;
        let owner_decoded =
            decode_observation(&self.owner_observation).ok_or(HelperJournalError::Invalid)?;
        let child_decoded =
            decode_observation(&child_observation).ok_or(HelperJournalError::Invalid)?;
        if child_decoded.pid == owner_decoded.pid
            || child_decoded.boot_session != owner_decoded.boot_session
        {
            return Err(HelperJournalError::Invalid);
        }
        let mut next = self.record.clone();
        next.child_observation = Some(encode_hex(&child_observation));
        next.phase = HelperJournalPhase::ChildObserved;
        self.commit(owner, next)
    }

    /// Persist confirmed exit after the trusted Supervisor has proved the same owned Child exited.
    ///
    /// The internal caller must already have obtained a successful result from `wait`, `try_wait`,
    /// or the existing `terminate_child` for the exact `Child` whose observation was recorded. This
    /// method deliberately accepts no PID or boolean and cannot establish that prerequisite itself.
    pub(super) fn confirm_exit(
        &mut self,
        owner: &PostgresStartLock,
    ) -> Result<(), HelperJournalError> {
        if self.record.phase != HelperJournalPhase::ChildObserved {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        let mut next = self.record.clone();
        next.phase = HelperJournalPhase::ExitConfirmed;
        self.commit(owner, next)
    }

    /// Persist the next helper spawn intent after the current helper's owned wait confirmed exit.
    pub(super) fn begin_next_helper(
        &mut self,
        owner: &PostgresStartLock,
        kind: HelperKind,
    ) -> Result<(), HelperJournalError> {
        if self.record.phase != HelperJournalPhase::ExitConfirmed
            || Some(kind) != self.record.helper_kind.next()
        {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        self.owner_identity
            .revalidate()
            .map_err(|_| HelperJournalError::Invalid)?;
        let owner_observation = self
            .owner_identity
            .evidence_bytes()
            .map_err(|_| HelperJournalError::Invalid)?;
        if owner_observation != self.owner_observation {
            return Err(HelperJournalError::Invalid);
        }
        let mut next = self.record.clone();
        next.helper_kind = kind;
        next.child_observation = None;
        next.phase = HelperJournalPhase::SpawnEntered;
        next.start_evidence_sha256 = start_evidence_sha256(owner);
        next.owner_observation = encode_hex(&owner_observation);
        next.data_dir_device = self.data_dir_device;
        next.data_dir_inode = self.data_dir_inode;
        self.commit(owner, next)
    }

    /// Persist helpers_complete after the last required helper of this attempt confirmed exit.
    pub(super) fn mark_complete(
        &mut self,
        owner: &PostgresStartLock,
    ) -> Result<(), HelperJournalError> {
        if self.record.phase != HelperJournalPhase::ExitConfirmed
            || !matches!(
                self.record.helper_kind,
                HelperKind::VersionPgCtl | HelperKind::Initdb
            )
        {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        let mut next = self.record.clone();
        next.phase = HelperJournalPhase::HelpersComplete;
        self.commit(owner, next)
    }

    fn commit(
        &mut self,
        owner: &PostgresStartLock,
        next: HelperJournalRecord,
    ) -> Result<(), HelperJournalError> {
        self.revalidate(owner)?;
        let next_bytes = encode_record(&next)?;
        let (candidate_path, mut candidate) = create_candidate(&self.root, &owner.instance_id)?;
        if candidate
            .write_all(&next_bytes)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            cleanup_candidate(&self.root, &candidate_path, &candidate, &next_bytes, 1);
            return Err(HelperJournalError::ReconciliationRequired);
        }
        if self.revalidate(owner).is_err()
            || !path_matches_open_file(
                &candidate_path,
                &candidate,
                &next_bytes,
                self.root_uid,
                Some(1),
            )
        {
            cleanup_candidate(&self.root, &candidate_path, &candidate, &next_bytes, 1);
            return Err(HelperJournalError::ReconciliationRequired);
        }
        if fs::rename(&candidate_path, &self.path).is_err()
            || sync_directory(&self.root).is_err()
            || !path_matches_open_file(&self.path, &candidate, &next_bytes, self.root_uid, Some(1))
            || validate_owner_and_directory(
                owner,
                &self.root,
                DirectoryObservation {
                    path: &self.data_dir_path,
                    file: &self.data_dir_file,
                    device: self.data_dir_device,
                    inode: self.data_dir_inode,
                    root_uid: self.root_uid,
                },
                &self.owner_identity,
                &self.owner_observation,
            )
            .is_err()
        {
            return Err(HelperJournalError::ReconciliationRequired);
        }
        self.file = candidate;
        self.bytes = next_bytes;
        self.record = next;
        Ok(())
    }
}

fn publish_absent(
    owner: &PostgresStartLock,
    preparation: &HelperJournalPreparation,
    record: &HelperJournalRecord,
    bytes: Vec<u8>,
) -> Result<(File, Vec<u8>), HelperJournalError> {
    validate_record(
        record,
        &owner.instance_id,
        &*owner.data_dir_name,
    )?;
    let (candidate_path, mut candidate) = create_candidate(&preparation.root, &owner.instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    if preparation.revalidate(owner).is_err()
        || !path_matches_open_file(
            &candidate_path,
            &candidate,
            &bytes,
            preparation.root_uid,
            Some(1),
        )
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    match fs::hard_link(&candidate_path, &preparation.path) {
        Ok(()) => {}
        Err(_) => {
            cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
            return Err(HelperJournalError::ReconciliationRequired);
        }
    }
    if sync_directory(&preparation.root).is_err()
        || !path_matches_open_file(
            &preparation.path,
            &candidate,
            &bytes,
            preparation.root_uid,
            Some(2),
        )
        || !remove_exact_candidate(&candidate_path, &candidate, &bytes, preparation.root_uid, 2)
        || sync_directory(&preparation.root).is_err()
        || !path_matches_open_file(
            &preparation.path,
            &candidate,
            &bytes,
            preparation.root_uid,
            Some(1),
        )
        || validate_owner_and_directory(
            owner,
            &preparation.root,
            DirectoryObservation {
                path: &preparation.data_dir_path,
                file: &preparation.data_dir_file,
                device: preparation.data_dir_device,
                inode: preparation.data_dir_inode,
                root_uid: preparation.root_uid,
            },
            &preparation.owner_identity,
            &preparation.owner_observation,
        )
        .is_err()
    {
        return Err(HelperJournalError::ReconciliationRequired);
    }
    Ok((candidate, bytes))
}

fn replace_exact(
    owner: &PostgresStartLock,
    preparation: &HelperJournalPreparation,
    old_file: &File,
    old_bytes: &[u8],
    record: &HelperJournalRecord,
    bytes: Vec<u8>,
) -> Result<(File, Vec<u8>), HelperJournalError> {
    validate_record(
        record,
        &owner.instance_id,
        &*owner.data_dir_name,
    )?;
    let (candidate_path, mut candidate) = create_candidate(&preparation.root, &owner.instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    if preparation.revalidate(owner).is_err()
        || !path_matches_open_file(
            &preparation.path,
            old_file,
            old_bytes,
            preparation.root_uid,
            Some(1),
        )
        || !path_matches_open_file(
            &candidate_path,
            &candidate,
            &bytes,
            preparation.root_uid,
            Some(1),
        )
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    if fs::rename(&candidate_path, &preparation.path).is_err()
        || sync_directory(&preparation.root).is_err()
        || !path_matches_open_file(
            &preparation.path,
            &candidate,
            &bytes,
            preparation.root_uid,
            Some(1),
        )
        || validate_owner_and_directory(
            owner,
            &preparation.root,
            DirectoryObservation {
                path: &preparation.data_dir_path,
                file: &preparation.data_dir_file,
                device: preparation.data_dir_device,
                inode: preparation.data_dir_inode,
                root_uid: preparation.root_uid,
            },
            &preparation.owner_identity,
            &preparation.owner_observation,
        )
        .is_err()
    {
        return Err(HelperJournalError::ReconciliationRequired);
    }
    Ok((candidate, bytes))
}

fn journal_identity<'a>(
    owner: &'a PostgresStartLock,
    data_dir: &Path,
) -> Result<(&'a Path, PathBuf, String), HelperJournalError> {
    let root = owner.path.parent().ok_or(HelperJournalError::Invalid)?;
    let expected_name = owner.data_dir_name.to_string();
    if !root.is_absolute() || data_dir != root.join(&expected_name) {
        return Err(HelperJournalError::Invalid);
    }
    let path = root.join(format!(
        ".postgresql-17-{}.helper-v1.json",
        owner.instance_id
    ));
    Ok((root, path, expected_name))
}

struct DirectoryBinding {
    file: File,
    device: u64,
    inode: u64,
    root_uid: u32,
}

fn open_data_directory(
    owner: &PostgresStartLock,
    root: &Path,
    data_dir: &Path,
) -> Result<DirectoryBinding, HelperJournalError> {
    owner
        .ensure_current()
        .map_err(|_| HelperJournalError::Invalid)?;
    let root_metadata = fs::symlink_metadata(root).map_err(|_| HelperJournalError::Invalid)?;
    let path_metadata = fs::symlink_metadata(data_dir).map_err(|_| HelperJournalError::Invalid)?;
    if !valid_root_metadata(&root_metadata)
        || !valid_data_dir_metadata(&path_metadata, root_metadata.uid())
    {
        return Err(HelperJournalError::Invalid);
    }
    let file = secure_open_directory(data_dir).map_err(|_| HelperJournalError::Invalid)?;
    let file_metadata = file.metadata().map_err(|_| HelperJournalError::Invalid)?;
    if !valid_data_dir_metadata(&file_metadata, root_metadata.uid())
        || !same_file(&path_metadata, &file_metadata)
    {
        return Err(HelperJournalError::Invalid);
    }
    let binding = DirectoryBinding {
        file,
        device: file_metadata.dev(),
        inode: file_metadata.ino(),
        root_uid: root_metadata.uid(),
    };
    if binding.inode == 0 || !directory_binding_is_current(owner, root, data_dir, &binding) {
        return Err(HelperJournalError::Invalid);
    }
    Ok(binding)
}

/// Borrowed directory identity; validation still rechecks every component against the owner.
struct DirectoryObservation<'a> {
    path: &'a Path,
    file: &'a File,
    device: u64,
    inode: u64,
    root_uid: u32,
}

fn validate_owner_and_directory(
    owner: &PostgresStartLock,
    root: &Path,
    directory: DirectoryObservation<'_>,
    owner_identity: &ProcessIdentity,
    owner_observation: &[u8; OBSERVATION_BYTES],
) -> Result<(), HelperJournalError> {
    let DirectoryObservation {
        path: data_dir_path,
        file: data_dir_file,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    } = directory;
    if owner.path.parent() != Some(root)
        || !owner.ownership_is_current()
        || data_dir_path != root.join(&*owner.data_dir_name)
    {
        return Err(HelperJournalError::Invalid);
    }
    let binding = DirectoryBinding {
        file: data_dir_file
            .try_clone()
            .map_err(|_| HelperJournalError::Invalid)?,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    };
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(HelperJournalError::Invalid);
    }
    owner_identity
        .revalidate()
        .map_err(|_| HelperJournalError::Invalid)?;
    let current = owner_identity
        .evidence_bytes()
        .map_err(|_| HelperJournalError::Invalid)?;
    if &current != owner_observation {
        return Err(HelperJournalError::Invalid);
    }
    Ok(())
}

fn directory_binding_is_current(
    owner: &PostgresStartLock,
    root: &Path,
    data_dir: &Path,
    binding: &DirectoryBinding,
) -> bool {
    if !owner.ownership_is_current() {
        return false;
    }
    let Ok(root_before) = fs::symlink_metadata(root) else {
        return false;
    };
    let Ok(path_before) = fs::symlink_metadata(data_dir) else {
        return false;
    };
    let Ok(file_before) = binding.file.metadata() else {
        return false;
    };
    if !valid_root_metadata(&root_before)
        || root_before.uid() != binding.root_uid
        || !valid_data_dir_metadata(&path_before, binding.root_uid)
        || !valid_data_dir_metadata(&file_before, binding.root_uid)
        || !same_file(&path_before, &file_before)
        || file_before.dev() != binding.device
        || file_before.ino() != binding.inode
    {
        return false;
    }
    let Ok(path_after) = fs::symlink_metadata(data_dir) else {
        return false;
    };
    let Ok(file_after) = binding.file.metadata() else {
        return false;
    };
    valid_data_dir_metadata(&path_after, binding.root_uid)
        && valid_data_dir_metadata(&file_after, binding.root_uid)
        && same_file(&path_after, &file_after)
        && file_after.dev() == binding.device
        && file_after.ino() == binding.inode
        && owner.ownership_is_current()
}

fn ensure_journal_absent(
    owner: &PostgresStartLock,
    directory: &DirectoryBinding,
    path: &Path,
) -> Result<(), HelperJournalError> {
    let root = owner.path.parent().ok_or(HelperJournalError::Invalid)?;
    let data_dir = root.join(&*owner.data_dir_name);
    ensure_journal_absent_parts(
        owner,
        &data_dir,
        &directory.file,
        directory.device,
        directory.inode,
        directory.root_uid,
        path,
    )
}

fn ensure_journal_absent_parts(
    owner: &PostgresStartLock,
    data_dir_path: &Path,
    data_dir_file: &File,
    data_dir_device: u64,
    data_dir_inode: u64,
    root_uid: u32,
    path: &Path,
) -> Result<(), HelperJournalError> {
    let root = owner.path.parent().ok_or(HelperJournalError::Invalid)?;
    let binding = DirectoryBinding {
        file: data_dir_file
            .try_clone()
            .map_err(|_| HelperJournalError::Invalid)?,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    };
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(HelperJournalError::Invalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(HelperJournalError::ReconciliationRequired),
    }
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(HelperJournalError::Invalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(HelperJournalError::ReconciliationRequired),
    }
}

fn ensure_retired_bound(
    owner: &PostgresStartLock,
    directory: &DirectoryBinding,
    path: &Path,
    file: &File,
    bytes: &[u8],
) -> Result<(), HelperJournalError> {
    let root = owner.path.parent().ok_or(HelperJournalError::Invalid)?;
    let data_dir = root.join(&*owner.data_dir_name);
    if !directory_binding_is_current(owner, root, &data_dir, directory)
        || !path_matches_open_file(path, file, bytes, directory.root_uid, Some(1))
    {
        return Err(HelperJournalError::Invalid);
    }
    Ok(())
}

fn validate_record(
    record: &HelperJournalRecord,
    instance_id: &str,
    expected_data_dir_name: &str,
) -> Result<ValidatedRecord, HelperJournalError> {
    if record.schema != JOURNAL_SCHEMA
        || record.schema_version != JOURNAL_SCHEMA_VERSION
        || record.instance_id != instance_id
        || record.data_dir_name != expected_data_dir_name
        || record.data_dir_inode == 0
        || !valid_lower_hex(&record.instance_id, 64)
        || !valid_lower_hex(&record.attempt_id, RANDOM_ID_BYTES * 2)
        || !valid_lower_hex(&record.start_evidence_sha256, SHA256_HEX_BYTES)
        || !valid_lower_hex(&record.owner_observation, OBSERVATION_HEX_BYTES)
    {
        return Err(HelperJournalError::Invalid);
    }
    let owner =
        decode_observation_hex(&record.owner_observation).ok_or(HelperJournalError::Invalid)?;
    let child = match record.child_observation.as_deref() {
        Some(value) => Some(decode_observation_hex(value).ok_or(HelperJournalError::Invalid)?),
        None => None,
    };
    match (record.phase, child) {
        (HelperJournalPhase::SpawnEntered, None) => {}
        (HelperJournalPhase::SpawnEntered, Some(_))
        | (
            HelperJournalPhase::ChildObserved
            | HelperJournalPhase::ExitConfirmed
            | HelperJournalPhase::HelpersComplete,
            None,
        ) => return Err(HelperJournalError::Invalid),
        (_, Some(child)) => {
            if child.pid == owner.pid || child.boot_session != owner.boot_session {
                return Err(HelperJournalError::Invalid);
            }
        }
    }
    Ok(ValidatedRecord { owner })
}

struct ValidatedRecord {
    owner: DecodedObservation,
}

#[derive(Clone, Copy)]
struct DecodedObservation {
    pid: u32,
    boot_session: [u8; 16],
}

fn decode_observation_hex(value: &str) -> Option<DecodedObservation> {
    if !valid_lower_hex(value, OBSERVATION_HEX_BYTES) {
        return None;
    }
    let mut bytes = [0_u8; OBSERVATION_BYTES];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    decode_observation(&bytes)
}

fn decode_observation(bytes: &[u8; OBSERVATION_BYTES]) -> Option<DecodedObservation> {
    let pid = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
    let start_seconds = u64::from_be_bytes(bytes[4..12].try_into().ok()?);
    let start_microseconds = u32::from_be_bytes(bytes[12..16].try_into().ok()?);
    let boot_session: [u8; 16] = bytes[16..32].try_into().ok()?;
    if pid == 0
        || pid > i32::MAX as u32
        || start_seconds == 0
        || start_microseconds >= 1_000_000
        || boot_session.iter().all(|byte| *byte == 0)
    {
        return None;
    }
    Some(DecodedObservation { pid, boot_session })
}

fn current_boot(observation: &[u8; OBSERVATION_BYTES]) -> [u8; 16] {
    let mut boot = [0_u8; 16];
    boot.copy_from_slice(&observation[16..]);
    boot
}

fn encode_record(record: &HelperJournalRecord) -> Result<Vec<u8>, HelperJournalError> {
    let bytes = serde_json::to_vec(record).map_err(|_| HelperJournalError::Invalid)?;
    if bytes.is_empty() || bytes.len() > JOURNAL_MAX_BYTES {
        return Err(HelperJournalError::Invalid);
    }
    Ok(bytes)
}

fn random_id() -> Result<String, HelperJournalError> {
    let mut value = [0_u8; RANDOM_ID_BYTES];
    getrandom::fill(&mut value).map_err(|_| HelperJournalError::ReconciliationRequired)?;
    Ok(encode_hex(&value))
}

fn start_evidence_sha256(owner: &PostgresStartLock) -> String {
    let digest: [u8; 32] = Sha256::digest(&owner.bytes).into();
    encode_hex(&digest)
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn create_candidate(root: &Path, instance_id: &str) -> Result<(PathBuf, File), HelperJournalError> {
    for _ in 0..MAX_CANDIDATE_ATTEMPTS {
        let path = root.join(format!(
            ".postgresql-17-{instance_id}.helper-v1.json.candidate-{}",
            random_id()?
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        add_secure_open_flags(&mut options);
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(HelperJournalError::ReconciliationRequired),
        }
    }
    Err(HelperJournalError::ReconciliationRequired)
}

fn secure_open_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    add_secure_open_flags(&mut options);
    options.open(path)
}

fn secure_open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    add_secure_open_flags(&mut options);
    options.open(path)
}

fn add_secure_open_flags(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    // Darwin O_NOFOLLOW | O_NONBLOCK. This mirrors the existing kernel/evidence open boundary.
    options.custom_flags(0x100 | 0x4);
}

fn read_bounded_file(
    path: &Path,
    file: &File,
    root_uid: u32,
) -> Result<Vec<u8>, HelperJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HelperJournalError::Invalid)?;
    let length = usize::try_from(metadata.len()).map_err(|_| HelperJournalError::Invalid)?;
    if !valid_journal_metadata(&metadata, root_uid, None)
        || length == 0
        || length > JOURNAL_MAX_BYTES
    {
        return Err(HelperJournalError::Invalid);
    }
    let mut bytes = vec![0_u8; length + 1];
    let read = positioned_read(file, &mut bytes).map_err(|_| HelperJournalError::Invalid)?;
    if read != length {
        return Err(HelperJournalError::Invalid);
    }
    bytes.truncate(read);
    if !path_matches_open_file(path, file, &bytes, root_uid, Some(1)) {
        return Err(HelperJournalError::Invalid);
    }
    Ok(bytes)
}

fn path_matches_open_file(
    path: &Path,
    file: &File,
    expected: &[u8],
    root_uid: u32,
    expected_links: Option<u64>,
) -> bool {
    let Ok(path_before) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_before) = file.metadata() else {
        return false;
    };
    if !valid_journal_metadata(&path_before, root_uid, Some(expected.len()))
        || !valid_journal_metadata(&file_before, root_uid, Some(expected.len()))
        || !same_file(&path_before, &file_before)
        || expected_links.is_some_and(|links| file_before.nlink() != links)
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
    valid_journal_metadata(&path_after, root_uid, Some(expected.len()))
        && valid_journal_metadata(&file_after, root_uid, Some(expected.len()))
        && same_file(&path_after, &file_after)
        && expected_links.is_none_or(|links| file_after.nlink() == links)
}

fn valid_journal_metadata(metadata: &fs::Metadata, root_uid: u32, length: Option<usize>) -> bool {
    let expected_length = length.and_then(|length| u64::try_from(length).ok());
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == root_uid
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.len() >= 1
        && metadata.len() <= JOURNAL_MAX_BYTES as u64
        && expected_length.is_none_or(|length| metadata.len() == length)
}

fn valid_root_metadata(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.permissions().mode() & 0o077 == 0
}

fn valid_data_dir_metadata(metadata: &fs::Metadata, root_uid: u32) -> bool {
    metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.permissions().mode() & 0o777 == 0o700
        && metadata.uid() == root_uid
        && metadata.ino() > 0
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn positioned_read(file: &File, buffer: &mut [u8]) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt as _;
    let mut read = 0_usize;
    while read < buffer.len() {
        let offset = u64::try_from(read).map_err(|_| std::io::ErrorKind::InvalidData)?;
        match file.read_at(&mut buffer[read..], offset) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(read)
}

fn positioned_equal(file: &File, expected: &[u8]) -> bool {
    let Some(length) = expected.len().checked_add(1) else {
        return false;
    };
    let mut actual = vec![0_u8; length];
    positioned_read(file, &mut actual)
        .is_ok_and(|read| read == expected.len() && &actual[..read] == expected)
}

fn remove_exact_candidate(
    path: &Path,
    file: &File,
    expected: &[u8],
    root_uid: u32,
    links: u64,
) -> bool {
    path_matches_open_file(path, file, expected, root_uid, Some(links))
        && fs::remove_file(path).is_ok()
}

fn cleanup_candidate(root: &Path, path: &Path, file: &File, expected: &[u8], links: u64) {
    let Ok(root_metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if remove_exact_candidate(path, file, expected, root_metadata.uid(), links) {
        let _ = sync_directory(root);
    }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    secure_open_directory(path)?.sync_all()
}

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

/// Controlled mid-phase retirement for helper journals (V6-PR-013).
///
/// `spawn_entered` with null child deletes back to Absent. A mid-phase with a full child advances
/// to `exit_confirmed` after absent evidence, or to `helpers_complete` when disposition proves a terminal helper kind (V6-PR-015).
pub(super) fn recover_mid_phase(
    owner: &super::kernel_start_lock::KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
    data_dir_name: &str,
) -> Result<(), HelperJournalError> {
    if !owner.is_current() || owner.root() != app_data_root {
        return Err(HelperJournalError::Invalid);
    }
    if !app_data_root.is_absolute() || data_dir.parent() != Some(app_data_root) {
        return Err(HelperJournalError::Invalid);
    }
    if data_dir.file_name().and_then(|n| n.to_str()) != Some(data_dir_name) {
        return Err(HelperJournalError::Invalid);
    }
    let root_meta = fs::symlink_metadata(app_data_root).map_err(|_| HelperJournalError::Invalid)?;
    let path_meta = fs::symlink_metadata(data_dir).map_err(|_| HelperJournalError::Invalid)?;
    if !valid_root_metadata(&root_meta) || !valid_data_dir_metadata(&path_meta, root_meta.uid()) {
        return Err(HelperJournalError::Invalid);
    }
    let data_dir_file = secure_open_directory(data_dir).map_err(|_| HelperJournalError::Invalid)?;
    let file_meta = data_dir_file
        .metadata()
        .map_err(|_| HelperJournalError::Invalid)?;
    if !valid_data_dir_metadata(&file_meta, root_meta.uid()) || !same_file(&path_meta, &file_meta) {
        return Err(HelperJournalError::Invalid);
    }
    let device = file_meta.dev();
    let inode = file_meta.ino();
    let root_uid = root_meta.uid();
    let path = app_data_root.join(format!(".postgresql-17-{instance_id}.helper-v1.json"));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !owner.is_current() {
                return Err(HelperJournalError::Invalid);
            }
            Ok(())
        }
        Ok(metadata) => {
            if !valid_journal_metadata(&metadata, root_uid, None) {
                return Err(HelperJournalError::Invalid);
            }
            let file = secure_open_file(&path).map_err(|_| HelperJournalError::Invalid)?;
            let bytes = read_bounded_file(&path, &file, root_uid)?;
            let record: HelperJournalRecord =
                serde_json::from_slice(&bytes).map_err(|_| HelperJournalError::Invalid)?;
            let _ = validate_record(&record, instance_id, &data_dir_name)?;
            if record.data_dir_device != device || record.data_dir_inode != inode {
                return Err(HelperJournalError::Invalid);
            }
            match (record.phase, record.child_observation.as_deref()) {
                (HelperJournalPhase::HelpersComplete, Some(_)) => {
                    if !owner.is_current() {
                        return Err(HelperJournalError::Invalid);
                    }
                    Ok(())
                }
                (HelperJournalPhase::ExitConfirmed, Some(child_hex)) => {
                    // V6-PR-015: complete only when disposition proves the 010 terminal kind.
                    maybe_complete_helpers(
                        owner,
                        app_data_root,
                        instance_id,
                        data_dir,
                        JournalFileObservation {
                            path: &path,
                            file: &file,
                            bytes: &bytes,
                            root_uid,
                        },
                        &record,
                        child_hex,
                    )
                }
                (HelperJournalPhase::SpawnEntered, None) => {
                    delete_exact_journal(app_data_root, &path, &file, &bytes, root_uid)?;
                    if !owner.is_current() {
                        return Err(HelperJournalError::ReconciliationRequired);
                    }
                    Ok(())
                }
                (HelperJournalPhase::ChildObserved, Some(child_hex)) => {
                    let evidence =
                        decode_evidence_hex(child_hex).ok_or(HelperJournalError::Invalid)?;
                    prove_child_absent(&evidence)?;
                    let mut next = record.clone();
                    next.phase = if helpers_complete_allowed(record.helper_kind, data_dir)? {
                        HelperJournalPhase::HelpersComplete
                    } else {
                        HelperJournalPhase::ExitConfirmed
                    };
                    let next_bytes = encode_record(&next)?;
                    replace_exact_mid_phase(
                        owner,
                        app_data_root,
                        instance_id,
                        JournalFileObservation {
                            path: &path,
                            file: &file,
                            bytes: &bytes,
                            root_uid,
                        },
                        &next,
                        next_bytes,
                    )?;
                    Ok(())
                }
                _ => Err(HelperJournalError::RecoveryRequired),
            }
        }
        Err(_) => Err(HelperJournalError::ReconciliationRequired),
    }
}

fn prove_child_absent(evidence: &[u8; OBSERVATION_BYTES]) -> Result<(), HelperJournalError> {
    wrok_bot_macos_process::evidence_process_is_absent(evidence).map_err(|error| match error {
        wrok_bot_macos_process::ProcessObservationError::ObservationChanged => {
            HelperJournalError::RecoveryRequired
        }
        _ => HelperJournalError::Invalid,
    })
}

fn helpers_complete_allowed(kind: HelperKind, data_dir: &Path) -> Result<bool, HelperJournalError> {
    // Mirror `data_directory_origin` without the bundle reader (same PG_VERSION / empty-dir rules).
    let origin = read_data_directory_origin(data_dir)?;
    Ok(match (kind, origin) {
        (HelperKind::VersionPgCtl, DataDirOrigin::Existing) => true,
        (HelperKind::Initdb, DataDirOrigin::Fresh) => true,
        (HelperKind::Initdb, DataDirOrigin::Existing) => return Err(HelperJournalError::Invalid),
        (HelperKind::VersionPostgres | HelperKind::VersionInitdb | HelperKind::VersionPgCtl, _) => {
            false
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataDirOrigin {
    Fresh,
    Existing,
}

fn pg_version_metadata_matches(metadata: &fs::Metadata, observed: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() <= PG_VERSION_MAX_BYTES as u64
        && metadata.len() == observed.len()
        && same_file(metadata, observed)
}

fn read_pg_version_probe(file: &File) -> Result<Vec<u8>, HelperJournalError> {
    let mut buffer = [0_u8; PG_VERSION_MAX_BYTES + 1];
    let read = positioned_read(file, &mut buffer).map_err(|_| HelperJournalError::Invalid)?;
    if read > PG_VERSION_MAX_BYTES {
        return Err(HelperJournalError::Invalid);
    }
    Ok(buffer[..read].to_vec())
}

fn read_pg_version_bytes(
    path: &Path,
    file: &File,
    observed: &fs::Metadata,
) -> Result<Vec<u8>, HelperJournalError> {
    let path_before = fs::symlink_metadata(path).map_err(|_| HelperJournalError::Invalid)?;
    let file_before = file.metadata().map_err(|_| HelperJournalError::Invalid)?;
    if !pg_version_metadata_matches(observed, observed)
        || !pg_version_metadata_matches(&path_before, observed)
        || !pg_version_metadata_matches(&file_before, observed)
    {
        return Err(HelperJournalError::Invalid);
    }
    let bytes = read_pg_version_probe(file)?;
    if bytes.len() as u64 != observed.len() || !positioned_equal(file, &bytes) {
        return Err(HelperJournalError::Invalid);
    }
    // Final path/handle checks follow the second bounded byte observation.
    let path_after = fs::symlink_metadata(path).map_err(|_| HelperJournalError::Invalid)?;
    let file_after = file.metadata().map_err(|_| HelperJournalError::Invalid)?;
    if !pg_version_metadata_matches(&path_after, observed)
        || !pg_version_metadata_matches(&file_after, observed)
    {
        return Err(HelperJournalError::Invalid);
    }
    Ok(bytes)
}

fn read_data_directory_origin(data_dir: &Path) -> Result<DataDirOrigin, HelperJournalError> {
    let version = data_dir.join("PG_VERSION");
    match fs::symlink_metadata(&version) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > PG_VERSION_MAX_BYTES as u64
            {
                return Err(HelperJournalError::Invalid);
            }
            let file = secure_open_file(&version).map_err(|_| HelperJournalError::Invalid)?;
            let bytes = read_pg_version_bytes(&version, &file, &metadata)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| HelperJournalError::Invalid)?;
            if text.trim() != "17" {
                return Err(HelperJournalError::Invalid);
            }
            Ok(DataDirOrigin::Existing)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut entries = fs::read_dir(data_dir).map_err(|_| HelperJournalError::Invalid)?;
            if entries.next().is_some() {
                return Err(HelperJournalError::Invalid);
            }
            Ok(DataDirOrigin::Fresh)
        }
        Err(_) => Err(HelperJournalError::Invalid),
    }
}

fn maybe_complete_helpers(
    owner: &super::kernel_start_lock::KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
    previous: JournalFileObservation<'_>,
    record: &HelperJournalRecord,
    child_hex: &str,
) -> Result<(), HelperJournalError> {
    let allowed = helpers_complete_allowed(record.helper_kind, data_dir)?;
    if !allowed {
        if !owner.is_current() {
            return Err(HelperJournalError::Invalid);
        }
        return Ok(());
    }
    let evidence = decode_evidence_hex(child_hex).ok_or(HelperJournalError::Invalid)?;
    prove_child_absent(&evidence)?;
    let mut next = record.clone();
    next.phase = HelperJournalPhase::HelpersComplete;
    let next_bytes = encode_record(&next)?;
    replace_exact_mid_phase(
        owner,
        app_data_root,
        instance_id,
        previous,
        &next,
        next_bytes,
    )?;
    Ok(())
}

fn decode_evidence_hex(value: &str) -> Option<[u8; OBSERVATION_BYTES]> {
    if !valid_lower_hex(value, OBSERVATION_HEX_BYTES) {
        return None;
    }
    let mut bytes = [0_u8; OBSERVATION_BYTES];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    let _ = decode_observation(&bytes)?;
    Some(bytes)
}

fn delete_exact_journal(
    root: &Path,
    path: &Path,
    file: &File,
    expected: &[u8],
    root_uid: u32,
) -> Result<(), HelperJournalError> {
    if !path_matches_open_file(path, file, expected, root_uid, Some(1)) {
        return Err(HelperJournalError::ReconciliationRequired);
    }
    fs::remove_file(path).map_err(|_| HelperJournalError::ReconciliationRequired)?;
    sync_directory(root).map_err(|_| HelperJournalError::ReconciliationRequired)?;
    if path.exists() {
        return Err(HelperJournalError::ReconciliationRequired);
    }
    Ok(())
}

/// Exact prior file observation, borrowed without granting replacement authority.
struct JournalFileObservation<'a> {
    path: &'a Path,
    file: &'a File,
    bytes: &'a [u8],
    root_uid: u32,
}

fn replace_exact_mid_phase(
    owner: &super::kernel_start_lock::KernelStartLock,
    root: &Path,
    instance_id: &str,
    previous: JournalFileObservation<'_>,
    record: &HelperJournalRecord,
    bytes: Vec<u8>,
) -> Result<(), HelperJournalError> {
    let JournalFileObservation {
        path,
        file: old_file,
        bytes: old_bytes,
        root_uid,
    } = previous;
    validate_record(record, instance_id, &record.data_dir_name)?;
    if !owner.is_current() {
        return Err(HelperJournalError::Invalid);
    }
    let (candidate_path, mut candidate) = create_candidate(root, instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    if !path_matches_open_file(path, old_file, old_bytes, root_uid, Some(1))
        || !path_matches_open_file(&candidate_path, &candidate, &bytes, root_uid, Some(1))
        || !owner.is_current()
    {
        cleanup_candidate(root, &candidate_path, &candidate, &bytes, 1);
        return Err(HelperJournalError::ReconciliationRequired);
    }
    if fs::rename(&candidate_path, path).is_err()
        || sync_directory(root).is_err()
        || !path_matches_open_file(path, &candidate, &bytes, root_uid, Some(1))
        || !owner.is_current()
    {
        return Err(HelperJournalError::ReconciliationRequired);
    }
    Ok(())
}

/// Read-only check used by Quiescent minting: Absent or helpers_complete only.
pub(super) fn allows_quiescent_cleanup(
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
    data_dir_name: &str,
) -> Result<(), HelperJournalError> {
    if !app_data_root.is_absolute() || data_dir.parent() != Some(app_data_root) {
        return Err(HelperJournalError::Invalid);
    }
    let path = app_data_root.join(format!(".postgresql-17-{instance_id}.helper-v1.json"));
    if data_dir.file_name().and_then(|n| n.to_str()) != Some(data_dir_name) {
        return Err(HelperJournalError::Invalid);
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) => {
            let root_meta = fs::metadata(app_data_root).map_err(|_| HelperJournalError::Invalid)?;
            if !valid_journal_metadata(&metadata, root_meta.uid(), None) {
                return Err(HelperJournalError::Invalid);
            }
            let file = secure_open_file(&path).map_err(|_| HelperJournalError::Invalid)?;
            let bytes = read_bounded_file(&path, &file, root_meta.uid())?;
            let record: HelperJournalRecord =
                serde_json::from_slice(&bytes).map_err(|_| HelperJournalError::Invalid)?;
            let _ = validate_record(&record, instance_id, &data_dir_name)?;
            if record.phase != HelperJournalPhase::HelpersComplete {
                return Err(HelperJournalError::RecoveryRequired);
            }
            Ok(())
        }
        Err(_) => Err(HelperJournalError::ReconciliationRequired),
    }
}

#[cfg(test)]
mod tests;
