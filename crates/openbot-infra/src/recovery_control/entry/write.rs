//! Control write primitives: the activation descriptor, the operation journal
//! and immutable runtime records. Every raw result stays resident before its
//! clock check; an unknown temp or tail is left in place, never repaired.

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::time::Instant;

use rustix::fs::{Mode, OFlags};

use super::super::activation::{ActivationRecord, JournalReference, OpId};
use super::super::journal::{JournalData, digest_hex};
use super::super::{RecoveryControlError, RecoveryControlFault, before, hex};
use super::{ControlFiles, Directory, OwnedRecord};

/// The held tail of the one operation journal this owner is appending to.
pub(in super::super) struct JournalTail {
    operation: OpId,
    control_id: String,
    epoch: String,
    pub(super) file: File,
    sequence: u64,
    digest: [u8; 32],
    length: u64,
}

fn io_failure() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::IoFailure)
}

fn capacity() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
}

fn invalid() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
}

impl ControlFiles {
    /// Temp → write/file-fsync/readback → same-root rename onto
    /// `activation-v1` → parent fsync → held/named final readback. The
    /// returned record is the held published file and its exact bytes.
    pub(in super::super) fn publish_activation(
        &mut self,
        record: &ActivationRecord,
        deadline: Instant,
    ) -> Result<OwnedRecord, RecoveryControlError> {
        let (bytes, digest) = record.encoded()?;
        if u64::try_from(bytes.len()).map_or(true, |n| n > self.limits.max_activation_bytes) {
            return Err(capacity());
        }
        // The temp name carries the descriptor digest its PublishIntent names.
        let temporary = format!("activation-v1.pending-{digest}");
        let original = self.write_new_file(Directory::Root, &temporary, &bytes, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::renameat(
                self.directory(Directory::Root)?,
                temporary.as_str(),
                self.directory(Directory::Root)?,
                "activation-v1",
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(io_failure());
        }
        self.sync_directory(Directory::Root, deadline)?;
        if self.check_opened(false, deadline)? != original {
            return Err(invalid());
        }
        self.verify_raw_bytes(&bytes, deadline)?;
        self.named_matches(Directory::Root, "activation-v1", original, deadline)?;
        let cap = self.limits.max_activation_bytes;
        let published = self.read_record(Directory::Root, "activation-v1", cap, deadline)?;
        if published.identity != original || published.bytes != bytes {
            return Err(invalid());
        }
        self.post(deadline)?;
        Ok(published)
    }

    /// Reserve → held-file EOF check → append one frame → file fsync →
    /// readback, on the journal opened by `begin_journal`. The first frame
    /// also fsyncs the new operation directory.
    pub(in super::super) fn append_journal(
        &mut self,
        operation: &OpId,
        entry: &JournalData,
        deadline: Instant,
    ) -> Result<JournalReference, RecoveryControlError> {
        let tail = self
            .journal_tail
            .as_ref()
            .filter(|tail| tail.operation == *operation)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        let opened = tail.sequence == 0;
        let sequence = tail.sequence.checked_add(1).ok_or_else(capacity)?;
        let previous = (tail.sequence != 0).then_some(&tail.digest);
        let frame = entry.frame(
            &tail.control_id,
            tail.operation.as_str(),
            &tail.epoch,
            sequence,
            previous,
            &self.limits,
        )?;
        let frame_length = u64::try_from(frame.bytes.len()).map_err(|_| capacity())?;
        if let Some(allowance) = &self.closing_observation {
            if allowance.journal_written.is_some() || frame_length > allowance.journal_reserved { return Err(capacity()); }
        } else if let Some(original) = &mut self.restore_operation {
            original.ledger.admit(super::super::RestoreCapacityResource::JournalBytes, frame_length)?;
            original.ledger.admit(super::super::RestoreCapacityResource::JournalRecords, 1)?;
        }
        let length = tail.length.checked_add(frame_length).ok_or_else(capacity)?;
        if length > self.limits.max_journal_bytes || sequence > self.limits.max_journal_records {
            return Err(capacity());
        }
        let offset = tail.length;
        self.prepay(frame_length, 0)?;
        // The held file must still end exactly where this owner left it.
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(self.journal_file()?.metadata());
        self.post(deadline)?;
        let held = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(io_failure)?;
        self.valid_meta(held, false)?;
        if held.len() != offset {
            return Err(invalid());
        }
        let mut written = 0usize;
        while written < frame.bytes.len() {
            self.reserve_io(0)?;
            before(deadline)?;
            let at = offset
                .checked_add(u64::try_from(written).map_err(|_| capacity())?)
                .ok_or_else(capacity)?;
            self.raw.count = Some(self.journal_file()?.write_at(&frame.bytes[written..], at));
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(io_failure)?;
            if n == 0 {
                return Err(io_failure());
            }
            written = written.checked_add(n).ok_or_else(capacity)?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(self.journal_file()?.sync_all());
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(io_failure());
        }
        let mut readback = vec![0u8; frame.bytes.len()];
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(self.journal_file()?.read_exact_at(&mut readback, offset));
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) || readback != frame.bytes {
            return Err(invalid());
        }
        if opened {
            self.sync_directory(Directory::OperationWork, deadline)?;
        }
        let tail = self.journal_tail.as_mut().ok_or_else(invalid)?;
        tail.sequence = sequence;
        tail.digest = frame.digest;
        tail.length = length;
        if let Some(allowance) = &mut self.closing_observation { allowance.journal_written = Some(frame_length); }
        Ok(JournalReference {
            context_id: operation.as_str().to_owned(),
            sequence,
            digest: digest_hex(&frame.digest),
        })
    }

    /// The sequence the next appended frame of the open journal takes.
    pub(in super::super) fn next_journal_sequence(
        &self,
    ) -> Result<std::num::NonZeroU64, RecoveryControlError> {
        self.journal_tail
            .as_ref()
            .and_then(|tail| tail.sequence.checked_add(1))
            .and_then(std::num::NonZeroU64::new)
            .ok_or_else(invalid)
    }

    fn journal_file(&self) -> Result<&File, RecoveryControlError> {
        self.journal_tail
            .as_ref()
            .map(|tail| &tail.file)
            .ok_or_else(invalid)
    }

    /// Create the new operation directory and its empty journal without
    /// replacement; an existing name is another owner's operation. The
    /// envelope's control id and epoch are fixed here for every later frame.
    pub(in super::super) fn begin_journal(
        &mut self,
        operation: &OpId,
        control_id: &OpId,
        epoch: &str,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        hex(epoch, 64, true)?;
        let name = operation.as_str();
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::mkdirat(
                self.directory(Directory::Operations)?,
                name,
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => (),
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            _ => return Err(io_failure()),
        }
        self.sync_directory(Directory::Operations, deadline)?;
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(Directory::Operations)?,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let directory = self.check_opened(true, deadline)?;
        self.named_matches(Directory::Operations, name, directory, deadline)?;
        self.operation_work = Some(self.take_opened()?);
        let (journal, _) = self.create_file(Directory::OperationWork, "journal-v1", deadline)?;
        self.journal_tail = Some(JournalTail {
            operation: *operation,
            control_id: control_id.as_str().to_owned(),
            epoch: epoch.to_owned(),
            file: journal,
            sequence: 0,
            digest: [0; 32],
            length: 0,
        });
        Ok(())
    }

    /// `create_new` 0600 under `dir`, checked held-versus-named.
    fn create_file(
        &mut self,
        dir: Directory,
        name: &str,
        deadline: Instant,
    ) -> Result<(File, super::RecoveryFileIdentity), RecoveryControlError> {
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(dir)?,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let created = self.check_opened(false, deadline)?;
        self.named_matches(dir, name, created, deadline)?;
        Ok((self.take_opened()?, created))
    }

    /// Create, write, fsync and read back one new file; the held FD stays in
    /// `raw.file` for the caller's publication step.
    fn write_new_file(
        &mut self,
        dir: Directory,
        name: &str,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<super::RecoveryFileIdentity, RecoveryControlError> {
        let (file, original) = self.create_file(dir, name, deadline)?;
        self.raw.file = Some(Ok(file));
        let mut offset = 0usize;
        while offset < bytes.len() {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(match self.raw.file.as_ref() {
                Some(Ok(f)) => {
                    let mut f = f;
                    f.write(&bytes[offset..])
                }
                _ => return Err(io_failure()),
            });
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(io_failure)?;
            if n == 0 {
                return Err(io_failure());
            }
            offset = offset.checked_add(n).ok_or_else(capacity)?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            self.raw
                .file
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(io_failure)?
                .sync_all(),
        );
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(io_failure());
        }
        self.verify_raw_bytes(bytes, deadline)?;
        self.named_matches(dir, name, original, deadline)?;
        Ok(original)
    }
}
