//! Durable intent and confirmed-exit record for the one owned PostgreSQL server child.
//!
//! This journal is additional fail-closed startup evidence. It does not discover foreign
//! processes, prove a data directory quiescent, remove stale evidence, or grant recovery authority.

mod record;

use self::record::{StartupJournalPhase, StartupJournalRecord};
use super::{PostgresSidecarOrigin, PostgresStartLock, encode_hex};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use wrok_bot_macos_process::{
    DataDirectoryOpenerObservation, ProcessIdentity, observe_data_directory_openers,
};

const JOURNAL_SCHEMA: &str = "openbot-postgres-startup";
const JOURNAL_SCHEMA_VERSION: u64 = 1;
const JOURNAL_MAX_BYTES: usize = 2048;
const RANDOM_ID_BYTES: usize = 16;
const OBSERVATION_BYTES: usize = 32;
const OBSERVATION_HEX_BYTES: usize = OBSERVATION_BYTES * 2;
const SHA256_HEX_BYTES: usize = 64;
const MAX_CANDIDATE_ATTEMPTS: usize = 8;

/// Read-only preflight bound to one current owner and one opened data directory.
pub(super) struct StartupJournalPreparation {
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
        record: Box<StartupJournalRecord>,
    },
}

/// One live startup attempt whose exact file and directory identities remain held.
pub(super) struct StartupJournal {
    root: PathBuf,
    path: PathBuf,
    file: File,
    bytes: Vec<u8>,
    record: StartupJournalRecord,
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
pub(super) enum StartupJournalError {
    /// A valid record exists in a non-retired phase and requires a later recovery protocol.
    RecoveryRequired,
    /// A record, path, owner, observation, or directory has invalid identity or shape.
    Invalid,
    /// A write, replacement, or later recheck could not establish its exact committed result.
    ReconciliationRequired,
}

impl fmt::Debug for StartupJournalPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupJournalPreparation")
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

impl fmt::Debug for StartupJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartupJournal")
            .field("phase", &self.record.phase)
            .finish()
    }
}

impl StartupJournalPreparation {
    /// Inspect without writing before any secret acquisition or creation.
    pub(super) fn inspect(
        owner: &PostgresStartLock,
        data_dir: &Path,
    ) -> Result<Self, StartupJournalError> {
        owner
            .ensure_current()
            .map_err(|_| StartupJournalError::Invalid)?;
        let (root, path, data_dir_name) = journal_identity(owner, data_dir)?;
        let directory = open_data_directory(owner, root, data_dir)?;
        let owner_identity = ProcessIdentity::capture(std::process::id())
            .map_err(|_| StartupJournalError::Invalid)?;
        let owner_observation = owner_identity
            .evidence_bytes()
            .map_err(|_| StartupJournalError::Invalid)?;

        let previous = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure_journal_absent(owner, &directory, &path)?;
                PreviousJournal::Absent
            }
            Ok(metadata) => {
                if !valid_journal_metadata(&metadata, directory.root_uid, None) {
                    return Err(StartupJournalError::Invalid);
                }
                let file = secure_open_file(&path).map_err(|_| StartupJournalError::Invalid)?;
                let bytes = read_bounded_file(&path, &file, directory.root_uid)?;
                let record: StartupJournalRecord =
                    serde_json::from_slice(&bytes).map_err(|_| StartupJournalError::Invalid)?;
                let validated = validate_record(&record, &owner.instance_id, &data_dir_name)?;
                if record.phase != StartupJournalPhase::ExitConfirmed {
                    return Err(StartupJournalError::RecoveryRequired);
                }
                ensure_retired_bound(owner, &directory, &path, &file, &bytes)?;
                if validated.owner.boot_session == current_boot(&owner_observation)
                    && (record.data_dir_device != directory.device
                        || record.data_dir_inode != directory.inode)
                {
                    return Err(StartupJournalError::Invalid);
                }
                PreviousJournal::Retired {
                    file,
                    bytes,
                    record: Box::new(record),
                }
            }
            Err(_) => return Err(StartupJournalError::ReconciliationRequired),
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
    pub(super) fn revalidate(&self, owner: &PostgresStartLock) -> Result<(), StartupJournalError> {
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
                    data_dir_name(&owner.instance_id).as_str(),
                )?;
                if record.phase != StartupJournalPhase::ExitConfirmed {
                    return Err(StartupJournalError::ReconciliationRequired);
                }
                if validated.owner.boot_session == current_boot(&self.owner_observation)
                    && (record.data_dir_device != self.data_dir_device
                        || record.data_dir_inode != self.data_dir_inode)
                {
                    return Err(StartupJournalError::Invalid);
                }
                if !path_matches_open_file(&self.path, file, bytes, self.root_uid, Some(1)) {
                    return Err(StartupJournalError::ReconciliationRequired);
                }
                Ok(())
            }
        }
    }

    /// A retired journal always requires the caller's independently verified Existing disposition.
    #[must_use]
    pub(super) const fn requires_existing_data(&self) -> bool {
        matches!(&self.previous, PreviousJournal::Retired { .. })
    }

    /// Fail closed when a non-ignored process still holds the data directory open.
    ///
    /// `Empty` does not authorize recovery or evidence deletion; it only allows the existing
    /// startup path to continue. Journal absence or an intermediate phase remains non-authoritative.
    pub(super) fn ensure_no_foreign_openers(&self) -> Result<(), StartupJournalError> {
        self.owner_identity
            .revalidate()
            .map_err(|_| StartupJournalError::Invalid)?;
        match observe_data_directory_openers(
            &self.data_dir_path,
            self.data_dir_device,
            self.data_dir_inode,
            std::slice::from_ref(&self.owner_identity),
        ) {
            Ok(DataDirectoryOpenerObservation::Empty) => Ok(()),
            Ok(DataDirectoryOpenerObservation::Observed) => {
                Err(StartupJournalError::RecoveryRequired)
            }
            Err(_) => Err(StartupJournalError::Invalid),
        }
    }

    /// Commit `spawn_entered` before spawning the PostgreSQL server.
    ///
    /// The caller must first set this exact `PostgresStartLock` to preserve-on-drop. This method
    /// verifies that precondition; it neither spawns nor authorizes a process.
    pub(super) fn begin_spawn(
        self,
        owner: &PostgresStartLock,
    ) -> Result<StartupJournal, StartupJournalError> {
        self.revalidate(owner)?;
        if owner.remove_on_drop {
            return Err(StartupJournalError::ReconciliationRequired);
        }
        if self.requires_existing_data()
            && !matches!(
                super::data_directory_origin(&self.data_dir_path),
                Ok(PostgresSidecarOrigin::Existing)
            )
        {
            return Err(StartupJournalError::RecoveryRequired);
        }
        self.owner_identity
            .revalidate()
            .map_err(|_| StartupJournalError::Invalid)?;
        let owner_observation = self
            .owner_identity
            .evidence_bytes()
            .map_err(|_| StartupJournalError::Invalid)?;
        if owner_observation != self.owner_observation {
            return Err(StartupJournalError::Invalid);
        }
        let record = StartupJournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            schema_version: JOURNAL_SCHEMA_VERSION,
            instance_id: owner.instance_id.to_string(),
            data_dir_name: data_dir_name(&owner.instance_id),
            data_dir_device: self.data_dir_device,
            data_dir_inode: self.data_dir_inode,
            attempt_id: random_id()?,
            start_evidence_sha256: start_evidence_sha256(owner),
            owner_observation: encode_hex(&owner_observation),
            child_observation: None,
            phase: StartupJournalPhase::SpawnEntered,
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
        Ok(StartupJournal {
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

impl StartupJournal {
    /// Recheck the live owner, process observation, directory handle, and exact journal bytes.
    pub(super) fn revalidate(&self, owner: &PostgresStartLock) -> Result<(), StartupJournalError> {
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
            return Err(StartupJournalError::ReconciliationRequired);
        }
        validate_record(
            &self.record,
            &owner.instance_id,
            data_dir_name(&owner.instance_id).as_str(),
        )?;
        Ok(())
    }

    /// Borrow only the original confirmed-exit journal; does not discover or stop a process.
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn capture_exit_material(
        &self,
        owner: &PostgresStartLock,
    ) -> Result<(File, Vec<u8>), StartupJournalError> {
        self.revalidate(owner)?;
        if self.record.phase != StartupJournalPhase::ExitConfirmed {
            return Err(StartupJournalError::ReconciliationRequired);
        }
        let file = self
            .file
            .try_clone()
            .map_err(|_| StartupJournalError::Invalid)?;
        self.revalidate(owner)?;
        Ok((file, self.bytes.clone()))
    }

    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    pub(super) fn capture_original_data_directory_matches(
        &self, retained: &File,
        clock: &dyn openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        use std::os::unix::fs::MetadataExt as _;
        clock.require_effect()?;
        let original = self.data_dir_file.metadata();
        clock.require_effect()?;
        let original = original.map_err(|_| Fault::IoFailure)?;
        clock.require_effect()?;
        let other = retained.metadata();
        clock.require_effect()?;
        let other = other.map_err(|_| Fault::IoFailure)?;
        if !original.is_dir() || !other.is_dir()
            || original.mode() & 0o777 != 0o700 || other.mode() & 0o777 != 0o700
            || (original.dev(), original.ino(), original.uid())
                != (self.data_dir_device, self.data_dir_inode, self.root_uid)
            || (other.dev(), other.ino(), other.uid())
                != (self.data_dir_device, self.data_dir_inode, self.root_uid) {
            return Err(Fault::SourceChanged);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(super) fn capture_data_directory(&self) -> Result<File, StartupJournalError> {
        let file = self
            .data_dir_file
            .try_clone()
            .map_err(|_| StartupJournalError::Invalid)?;
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().map_err(|_| StartupJournalError::Invalid)?;
        if metadata.dev() != self.data_dir_device
            || metadata.ino() != self.data_dir_inode
            || metadata.uid() != self.root_uid
            || !metadata.is_dir()
        {
            return Err(StartupJournalError::Invalid);
        }
        Ok(file)
    }

    /// Persist the observation of the same current child held by the Supervisor.
    pub(super) fn record_child(
        &mut self,
        owner: &PostgresStartLock,
        child: &ProcessIdentity,
    ) -> Result<(), StartupJournalError> {
        if self.record.phase != StartupJournalPhase::SpawnEntered {
            return Err(StartupJournalError::ReconciliationRequired);
        }
        self.revalidate(owner)?;
        let child_observation = child
            .evidence_bytes()
            .map_err(|_| StartupJournalError::Invalid)?;
        let owner_decoded =
            decode_observation(&self.owner_observation).ok_or(StartupJournalError::Invalid)?;
        let child_decoded =
            decode_observation(&child_observation).ok_or(StartupJournalError::Invalid)?;
        if child_decoded.pid == owner_decoded.pid
            || child_decoded.boot_session != owner_decoded.boot_session
        {
            return Err(StartupJournalError::Invalid);
        }
        let mut next = self.record.clone();
        next.child_observation = Some(encode_hex(&child_observation));
        next.phase = StartupJournalPhase::ChildObserved;
        self.commit(owner, next)
    }

    /// Persist SCRAM readiness after revalidating all held evidence.
    pub(super) fn mark_ready(
        &mut self,
        owner: &PostgresStartLock,
    ) -> Result<(), StartupJournalError> {
        self.advance(
            owner,
            StartupJournalPhase::ChildObserved,
            StartupJournalPhase::Ready,
        )
    }

    /// Persist shutdown intent before executing the existing path-bound `pg_ctl stop`.
    pub(super) fn mark_stop(
        &mut self,
        owner: &PostgresStartLock,
    ) -> Result<(), StartupJournalError> {
        self.advance(
            owner,
            StartupJournalPhase::Ready,
            StartupJournalPhase::StopEntered,
        )
    }

    /// Persist confirmed exit after the trusted Supervisor has proved the same owned Child exited.
    ///
    /// The internal caller must already have obtained a successful result from `wait`, `try_wait`,
    /// or the existing `terminate_child` for the exact `Child` whose observation was recorded. This
    /// method deliberately accepts no PID or boolean and cannot establish that prerequisite itself.
    pub(super) fn confirm_exit(
        &mut self,
        owner: &PostgresStartLock,
    ) -> Result<(), StartupJournalError> {
        if !matches!(
            self.record.phase,
            StartupJournalPhase::ChildObserved
                | StartupJournalPhase::Ready
                | StartupJournalPhase::StopEntered
        ) {
            return Err(StartupJournalError::ReconciliationRequired);
        }
        let mut next = self.record.clone();
        next.phase = StartupJournalPhase::ExitConfirmed;
        self.commit(owner, next)
    }

    fn advance(
        &mut self,
        owner: &PostgresStartLock,
        expected: StartupJournalPhase,
        next_phase: StartupJournalPhase,
    ) -> Result<(), StartupJournalError> {
        if self.record.phase != expected {
            return Err(StartupJournalError::ReconciliationRequired);
        }
        let mut next = self.record.clone();
        next.phase = next_phase;
        self.commit(owner, next)
    }

    fn commit(
        &mut self,
        owner: &PostgresStartLock,
        next: StartupJournalRecord,
    ) -> Result<(), StartupJournalError> {
        self.revalidate(owner)?;
        let next_bytes = encode_record(&next)?;
        let (candidate_path, mut candidate) = create_candidate(&self.root, &owner.instance_id)?;
        if candidate
            .write_all(&next_bytes)
            .and_then(|()| candidate.sync_all())
            .is_err()
        {
            cleanup_candidate(&self.root, &candidate_path, &candidate, &next_bytes, 1);
            return Err(StartupJournalError::ReconciliationRequired);
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
            return Err(StartupJournalError::ReconciliationRequired);
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
            return Err(StartupJournalError::ReconciliationRequired);
        }
        self.file = candidate;
        self.bytes = next_bytes;
        self.record = next;
        Ok(())
    }
}

fn publish_absent(
    owner: &PostgresStartLock,
    preparation: &StartupJournalPreparation,
    record: &StartupJournalRecord,
    bytes: Vec<u8>,
) -> Result<(File, Vec<u8>), StartupJournalError> {
    validate_record(
        record,
        &owner.instance_id,
        data_dir_name(&owner.instance_id).as_str(),
    )?;
    let (candidate_path, mut candidate) = create_candidate(&preparation.root, &owner.instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(StartupJournalError::ReconciliationRequired);
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
        return Err(StartupJournalError::ReconciliationRequired);
    }
    match fs::hard_link(&candidate_path, &preparation.path) {
        Ok(()) => {}
        Err(_) => {
            cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
            return Err(StartupJournalError::ReconciliationRequired);
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
        return Err(StartupJournalError::ReconciliationRequired);
    }
    Ok((candidate, bytes))
}

fn replace_exact(
    owner: &PostgresStartLock,
    preparation: &StartupJournalPreparation,
    old_file: &File,
    old_bytes: &[u8],
    record: &StartupJournalRecord,
    bytes: Vec<u8>,
) -> Result<(File, Vec<u8>), StartupJournalError> {
    validate_record(
        record,
        &owner.instance_id,
        data_dir_name(&owner.instance_id).as_str(),
    )?;
    let (candidate_path, mut candidate) = create_candidate(&preparation.root, &owner.instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(&preparation.root, &candidate_path, &candidate, &bytes, 1);
        return Err(StartupJournalError::ReconciliationRequired);
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
        return Err(StartupJournalError::ReconciliationRequired);
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
        return Err(StartupJournalError::ReconciliationRequired);
    }
    Ok((candidate, bytes))
}

fn journal_identity<'a>(
    owner: &'a PostgresStartLock,
    data_dir: &Path,
) -> Result<(&'a Path, PathBuf, String), StartupJournalError> {
    let root = owner.path.parent().ok_or(StartupJournalError::Invalid)?;
    let expected_name = data_dir_name(&owner.instance_id);
    if !root.is_absolute() || data_dir != root.join(&expected_name) {
        return Err(StartupJournalError::Invalid);
    }
    let path = root.join(format!(
        ".postgresql-17-{}.startup-v1.json",
        owner.instance_id
    ));
    Ok((root, path, expected_name))
}

fn data_dir_name(instance_id: &str) -> String {
    format!("postgresql-17-{instance_id}")
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
) -> Result<DirectoryBinding, StartupJournalError> {
    owner
        .ensure_current()
        .map_err(|_| StartupJournalError::Invalid)?;
    let root_metadata = fs::symlink_metadata(root).map_err(|_| StartupJournalError::Invalid)?;
    let path_metadata = fs::symlink_metadata(data_dir).map_err(|_| StartupJournalError::Invalid)?;
    if !valid_root_metadata(&root_metadata)
        || !valid_data_dir_metadata(&path_metadata, root_metadata.uid())
    {
        return Err(StartupJournalError::Invalid);
    }
    let file = secure_open_directory(data_dir).map_err(|_| StartupJournalError::Invalid)?;
    let file_metadata = file.metadata().map_err(|_| StartupJournalError::Invalid)?;
    if !valid_data_dir_metadata(&file_metadata, root_metadata.uid())
        || !same_file(&path_metadata, &file_metadata)
    {
        return Err(StartupJournalError::Invalid);
    }
    let binding = DirectoryBinding {
        file,
        device: file_metadata.dev(),
        inode: file_metadata.ino(),
        root_uid: root_metadata.uid(),
    };
    if binding.inode == 0 || !directory_binding_is_current(owner, root, data_dir, &binding) {
        return Err(StartupJournalError::Invalid);
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
) -> Result<(), StartupJournalError> {
    let DirectoryObservation {
        path: data_dir_path,
        file: data_dir_file,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    } = directory;
    if owner.path.parent() != Some(root)
        || !owner.ownership_is_current()
        || data_dir_path != root.join(data_dir_name(&owner.instance_id))
    {
        return Err(StartupJournalError::Invalid);
    }
    let binding = DirectoryBinding {
        file: data_dir_file
            .try_clone()
            .map_err(|_| StartupJournalError::Invalid)?,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    };
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(StartupJournalError::Invalid);
    }
    owner_identity
        .revalidate()
        .map_err(|_| StartupJournalError::Invalid)?;
    let current = owner_identity
        .evidence_bytes()
        .map_err(|_| StartupJournalError::Invalid)?;
    if &current != owner_observation {
        return Err(StartupJournalError::Invalid);
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
) -> Result<(), StartupJournalError> {
    let root = owner.path.parent().ok_or(StartupJournalError::Invalid)?;
    let data_dir = root.join(data_dir_name(&owner.instance_id));
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
) -> Result<(), StartupJournalError> {
    let root = owner.path.parent().ok_or(StartupJournalError::Invalid)?;
    let binding = DirectoryBinding {
        file: data_dir_file
            .try_clone()
            .map_err(|_| StartupJournalError::Invalid)?,
        device: data_dir_device,
        inode: data_dir_inode,
        root_uid,
    };
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(StartupJournalError::Invalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(StartupJournalError::ReconciliationRequired),
    }
    if !directory_binding_is_current(owner, root, data_dir_path, &binding) {
        return Err(StartupJournalError::Invalid);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(StartupJournalError::ReconciliationRequired),
    }
}

fn ensure_retired_bound(
    owner: &PostgresStartLock,
    directory: &DirectoryBinding,
    path: &Path,
    file: &File,
    bytes: &[u8],
) -> Result<(), StartupJournalError> {
    let root = owner.path.parent().ok_or(StartupJournalError::Invalid)?;
    let data_dir = root.join(data_dir_name(&owner.instance_id));
    if !directory_binding_is_current(owner, root, &data_dir, directory)
        || !path_matches_open_file(path, file, bytes, directory.root_uid, Some(1))
    {
        return Err(StartupJournalError::Invalid);
    }
    Ok(())
}

fn validate_record(
    record: &StartupJournalRecord,
    instance_id: &str,
    expected_data_dir_name: &str,
) -> Result<ValidatedRecord, StartupJournalError> {
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
        return Err(StartupJournalError::Invalid);
    }
    let owner =
        decode_observation_hex(&record.owner_observation).ok_or(StartupJournalError::Invalid)?;
    let child = match record.child_observation.as_deref() {
        Some(value) => Some(decode_observation_hex(value).ok_or(StartupJournalError::Invalid)?),
        None => None,
    };
    match (record.phase, child) {
        (StartupJournalPhase::SpawnEntered, None) => {}
        (StartupJournalPhase::SpawnEntered, Some(_))
        | (
            StartupJournalPhase::ChildObserved
            | StartupJournalPhase::Ready
            | StartupJournalPhase::StopEntered
            | StartupJournalPhase::ExitConfirmed,
            None,
        ) => return Err(StartupJournalError::Invalid),
        (_, Some(child)) => {
            if child.pid == owner.pid || child.boot_session != owner.boot_session {
                return Err(StartupJournalError::Invalid);
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

fn encode_record(record: &StartupJournalRecord) -> Result<Vec<u8>, StartupJournalError> {
    let bytes = serde_json::to_vec(record).map_err(|_| StartupJournalError::Invalid)?;
    if bytes.is_empty() || bytes.len() > JOURNAL_MAX_BYTES {
        return Err(StartupJournalError::Invalid);
    }
    Ok(bytes)
}

fn random_id() -> Result<String, StartupJournalError> {
    let mut value = [0_u8; RANDOM_ID_BYTES];
    getrandom::fill(&mut value).map_err(|_| StartupJournalError::ReconciliationRequired)?;
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

fn create_candidate(
    root: &Path,
    instance_id: &str,
) -> Result<(PathBuf, File), StartupJournalError> {
    for _ in 0..MAX_CANDIDATE_ATTEMPTS {
        let path = root.join(format!(
            ".postgresql-17-{instance_id}.startup-v1.json.candidate-{}",
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
            Err(_) => return Err(StartupJournalError::ReconciliationRequired),
        }
    }
    Err(StartupJournalError::ReconciliationRequired)
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
) -> Result<Vec<u8>, StartupJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupJournalError::Invalid)?;
    let length = usize::try_from(metadata.len()).map_err(|_| StartupJournalError::Invalid)?;
    if !valid_journal_metadata(&metadata, root_uid, None)
        || length == 0
        || length > JOURNAL_MAX_BYTES
    {
        return Err(StartupJournalError::Invalid);
    }
    let mut bytes = vec![0_u8; length + 1];
    let read = positioned_read(file, &mut bytes).map_err(|_| StartupJournalError::Invalid)?;
    if read != length {
        return Err(StartupJournalError::Invalid);
    }
    bytes.truncate(read);
    if !path_matches_open_file(path, file, &bytes, root_uid, Some(1)) {
        return Err(StartupJournalError::Invalid);
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

/// Controlled mid-phase retirement for Quiescent reclaim (V6-PR-013).
///
/// `spawn_entered` with null child deletes back to Absent. Mid-phases with a full child observation
/// advance to `exit_confirmed` only after [`wrok_bot_macos_process::evidence_process_is_absent`].
/// Does not claim `Child::wait` and does not delete data/WAL.
pub(super) fn recover_mid_phase(
    owner: &super::kernel_start_lock::KernelStartLock,
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
) -> Result<(), StartupJournalError> {
    if !owner.is_current() || owner.root() != app_data_root {
        return Err(StartupJournalError::Invalid);
    }
    if !app_data_root.is_absolute() || data_dir.parent() != Some(app_data_root) {
        return Err(StartupJournalError::Invalid);
    }
    let data_dir_name = data_dir_name(instance_id);
    if data_dir.file_name().and_then(|n| n.to_str()) != Some(data_dir_name.as_str()) {
        return Err(StartupJournalError::Invalid);
    }
    let root_meta =
        fs::symlink_metadata(app_data_root).map_err(|_| StartupJournalError::Invalid)?;
    let path_meta = fs::symlink_metadata(data_dir).map_err(|_| StartupJournalError::Invalid)?;
    if !valid_root_metadata(&root_meta) || !valid_data_dir_metadata(&path_meta, root_meta.uid()) {
        return Err(StartupJournalError::Invalid);
    }
    let data_dir_file =
        secure_open_directory(data_dir).map_err(|_| StartupJournalError::Invalid)?;
    let file_meta = data_dir_file
        .metadata()
        .map_err(|_| StartupJournalError::Invalid)?;
    if !valid_data_dir_metadata(&file_meta, root_meta.uid()) || !same_file(&path_meta, &file_meta) {
        return Err(StartupJournalError::Invalid);
    }
    let device = file_meta.dev();
    let inode = file_meta.ino();
    let root_uid = root_meta.uid();
    let path = app_data_root.join(format!(".postgresql-17-{instance_id}.startup-v1.json"));
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !owner.is_current() {
                return Err(StartupJournalError::Invalid);
            }
            Ok(())
        }
        Ok(metadata) => {
            if !valid_journal_metadata(&metadata, root_uid, None) {
                return Err(StartupJournalError::Invalid);
            }
            let file = secure_open_file(&path).map_err(|_| StartupJournalError::Invalid)?;
            let bytes = read_bounded_file(&path, &file, root_uid)?;
            let record: StartupJournalRecord =
                serde_json::from_slice(&bytes).map_err(|_| StartupJournalError::Invalid)?;
            let _ = validate_record(&record, instance_id, &data_dir_name)?;
            if record.data_dir_device != device || record.data_dir_inode != inode {
                return Err(StartupJournalError::Invalid);
            }
            match (record.phase, record.child_observation.as_deref()) {
                (StartupJournalPhase::ExitConfirmed, Some(_)) => {
                    if !owner.is_current() {
                        return Err(StartupJournalError::Invalid);
                    }
                    Ok(())
                }
                (StartupJournalPhase::SpawnEntered, None) => {
                    delete_exact_journal(app_data_root, &path, &file, &bytes, root_uid)?;
                    if !owner.is_current() {
                        return Err(StartupJournalError::ReconciliationRequired);
                    }
                    Ok(())
                }
                (
                    StartupJournalPhase::ChildObserved
                    | StartupJournalPhase::Ready
                    | StartupJournalPhase::StopEntered,
                    Some(child_hex),
                ) => {
                    let evidence =
                        decode_evidence_hex(child_hex).ok_or(StartupJournalError::Invalid)?;
                    wrok_bot_macos_process::evidence_process_is_absent(&evidence).map_err(
                        |error| match error {
                            wrok_bot_macos_process::ProcessObservationError::ObservationChanged => {
                                StartupJournalError::RecoveryRequired
                            }
                            _ => StartupJournalError::Invalid,
                        },
                    )?;
                    let mut next = record.clone();
                    next.phase = StartupJournalPhase::ExitConfirmed;
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
                _ => Err(StartupJournalError::RecoveryRequired),
            }
        }
        Err(_) => Err(StartupJournalError::ReconciliationRequired),
    }
}

fn decode_evidence_hex(value: &str) -> Option<[u8; OBSERVATION_BYTES]> {
    if !valid_lower_hex(value, OBSERVATION_HEX_BYTES) {
        return None;
    }
    let mut bytes = [0_u8; OBSERVATION_BYTES];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    // Reject obviously invalid evidence shapes before asking the process crate.
    let _ = decode_observation(&bytes)?;
    Some(bytes)
}

fn delete_exact_journal(
    root: &Path,
    path: &Path,
    file: &File,
    expected: &[u8],
    root_uid: u32,
) -> Result<(), StartupJournalError> {
    if !path_matches_open_file(path, file, expected, root_uid, Some(1)) {
        return Err(StartupJournalError::ReconciliationRequired);
    }
    fs::remove_file(path).map_err(|_| StartupJournalError::ReconciliationRequired)?;
    sync_directory(root).map_err(|_| StartupJournalError::ReconciliationRequired)?;
    if path.exists() {
        return Err(StartupJournalError::ReconciliationRequired);
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
    record: &StartupJournalRecord,
    bytes: Vec<u8>,
) -> Result<(), StartupJournalError> {
    let JournalFileObservation {
        path,
        file: old_file,
        bytes: old_bytes,
        root_uid,
    } = previous;
    validate_record(record, instance_id, data_dir_name(instance_id).as_str())?;
    if !owner.is_current() {
        return Err(StartupJournalError::Invalid);
    }
    let (candidate_path, mut candidate) = create_candidate(root, instance_id)?;
    if candidate
        .write_all(&bytes)
        .and_then(|()| candidate.sync_all())
        .is_err()
    {
        cleanup_candidate(root, &candidate_path, &candidate, &bytes, 1);
        return Err(StartupJournalError::ReconciliationRequired);
    }
    if !path_matches_open_file(path, old_file, old_bytes, root_uid, Some(1))
        || !path_matches_open_file(&candidate_path, &candidate, &bytes, root_uid, Some(1))
        || !owner.is_current()
    {
        cleanup_candidate(root, &candidate_path, &candidate, &bytes, 1);
        return Err(StartupJournalError::ReconciliationRequired);
    }
    if fs::rename(&candidate_path, path).is_err()
        || sync_directory(root).is_err()
        || !path_matches_open_file(path, &candidate, &bytes, root_uid, Some(1))
        || !owner.is_current()
    {
        return Err(StartupJournalError::ReconciliationRequired);
    }
    Ok(())
}

/// Read-only check used by Quiescent minting: Absent or exit_confirmed only.
pub(super) fn allows_quiescent_cleanup(
    app_data_root: &Path,
    instance_id: &str,
    data_dir: &Path,
) -> Result<(), StartupJournalError> {
    if !app_data_root.is_absolute() || data_dir.parent() != Some(app_data_root) {
        return Err(StartupJournalError::Invalid);
    }
    let path = app_data_root.join(format!(".postgresql-17-{instance_id}.startup-v1.json"));
    let data_dir_name = format!("postgresql-17-{instance_id}");
    if data_dir.file_name().and_then(|n| n.to_str()) != Some(data_dir_name.as_str()) {
        return Err(StartupJournalError::Invalid);
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) => {
            let root_meta =
                fs::metadata(app_data_root).map_err(|_| StartupJournalError::Invalid)?;
            if !valid_journal_metadata(&metadata, root_meta.uid(), None) {
                return Err(StartupJournalError::Invalid);
            }
            let file = secure_open_file(&path).map_err(|_| StartupJournalError::Invalid)?;
            let bytes = read_bounded_file(&path, &file, root_meta.uid())?;
            let record: StartupJournalRecord =
                serde_json::from_slice(&bytes).map_err(|_| StartupJournalError::Invalid)?;
            let _ = validate_record(&record, instance_id, &data_dir_name)?;
            if record.phase != StartupJournalPhase::ExitConfirmed {
                return Err(StartupJournalError::RecoveryRequired);
            }
            Ok(())
        }
        Err(_) => Err(StartupJournalError::ReconciliationRequired),
    }
}

#[cfg(test)]
mod tests;
