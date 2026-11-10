//! One complete read of the activation head: its descriptor, the journal its
//! publication names. Raw results stay resident in `ControlFiles` for the later
//! held/named head recheck.

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use rustix::fs::{AtFlags, Mode, OFlags};

use super::super::activation::{ActivationPhase, PublishedActivation};
use super::super::{RecoveryControlError, RecoveryControlFault};
use super::{ControlFiles, Directory, OwnedRecord};

/// What the activation head holds. Only `Published` is a verified publication.
pub(in super::super) enum Head {
    Absent,
    Unpublished,
    Published(PublishedActivation),
}

fn invalid() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
}

impl ControlFiles {
    #[cfg(feature = "desktop-local")]
    pub(super) fn read_original_restore_before(
        &mut self,
        operation: super::super::activation::Hex32,
        deadline: Instant,
    ) -> Result<super::RestoreOriginalObservation, RecoveryControlError> {
        self.read_head_before(deadline)?;
        // Both identity strings are fixed closed hex (32/64); admit their backing before clone.
        self.prepay(2 * (32 + 64), 0)?;
        let observation = self.activation_observation.as_ref().and_then(|raw| raw.as_ref().ok()).cloned().ok_or_else(invalid)?;
        if self.publication_chain.is_none() {
            let fee = self.limits.max_journal_frame_bytes.checked_mul(4).ok_or_else(invalid)?;
            let journal = self.read_journal(operation.as_str(), fee, deadline)?;
            self.publication_journal = Some(Arc::clone(&journal));
            let metadata = super::super::journal::read_metadata_reservation(&journal.bytes, &self.limits)?;
            self.prepay(metadata, 0)?;
            self.publication_chain = Some(super::super::journal::observe_chain(&journal.bytes, &self.limits));
            self.post(deadline)?;
        }
        let chain = match self.publication_chain.as_ref() {
            Some(Ok(chain)) => chain,
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            None => return Err(invalid()),
        };
        let (control, observed_operation, epoch) = chain.first_context().ok_or_else(invalid)?;
        if !chain.is_restore() || observed_operation != operation.as_str() || control != observation.record.control_id { return Err(invalid()); }
        match observation.record.data() {
            super::super::activation::ActivationPayload::Pending(pending) => chain.matches_restore_pending(pending)?,
            super::super::activation::ActivationPayload::Current(current) => {
                if current.operation_id != observed_operation || current.epoch != epoch { return Err(invalid()); }
            }
            super::super::activation::ActivationPayload::Switched(switched) => {
                if switched.publish_intent.context_id.as_str() != observed_operation || switched.binding.authorization_epoch() != epoch { return Err(invalid()); }
                chain.publication_for(control, &observation.digest, &switched.publish_intent, self.activation_source.as_ref().ok_or_else(invalid)?.identity, observation.record.phase)?;
            }
            _ => return Err(invalid()),
        }
        let epoch = epoch.to_owned();
        let control_id = control.to_owned();
        self.post(deadline)?;
        Ok(super::RestoreOriginalObservation { operation, epoch, control_id, phase: observation.record.phase })
    }

    pub(in super::super) fn read_head_before(
        &mut self,
        deadline: Instant,
    ) -> Result<Head, RecoveryControlError> {
        self.activation_source = None;
        self.activation_observation = None;
        self.publication_journal = None;
        self.publication_operation = None;
        self.publication_chain = None;
        self.publication_seal = None;
        self.reserve_io(0)?;
        self.raw.named = Some(rustix::fs::statat(
            self.directory(Directory::Root)?,
            "activation-v1",
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        if matches!(self.raw.named, Some(Err(rustix::io::Errno::NOENT))) {
            return Ok(Head::Absent);
        }
        let record = std::mem::size_of::<OwnedRecord>()
            + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + 2 * std::mem::align_of::<OwnedRecord>();
        self.prepay(record as u64, 0)?;
        let cap = self.limits.max_activation_bytes;
        let actual = Arc::new(self.read_record(Directory::Root, "activation-v1", cap, deadline)?);
        self.activation_source = Some(Arc::clone(&actual));
        let fee = super::super::activation::read_metadata_reservation(&actual.bytes)?
            .checked_add(
                (2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
                    + 2 * std::mem::align_of::<super::super::activation::ActivationObservation>())
                    as u64,
            )
            .ok_or_else(invalid)?;
        self.prepay(fee, 0)?;
        self.activation_observation =
            Some(super::super::activation::observe(&actual.bytes, &self.limits).map(Arc::new));
        self.post(deadline)?;
        let observation = match self.activation_observation.as_ref() {
            Some(Ok(observation)) => Arc::clone(observation),
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            None => return Err(invalid()),
        };
        let phase = observation.record.phase;
        if !matches!(
            phase,
            ActivationPhase::OrdinaryActive | ActivationPhase::RestoreCurrent
        ) {
            return Ok(Head::Unpublished);
        }
        let reference = observation.publication_reference()?.clone();
        let context = reference.context_id.as_str();
        if phase == ActivationPhase::RestoreCurrent {
            let fee = self.limits.max_component_bytes.checked_mul(2)
                .and_then(|n| n.checked_add(self.limits.max_id_bytes.checked_mul(4)?))
                .and_then(|n| n.checked_add(std::mem::size_of::<super::super::activation::CandidatePlan>() as u64))
                .ok_or_else(invalid)?;
            self.prepay(fee, 0)?;
        }
        let mut restore_plan = None;
        // A Current republished by a known-site adoption names that operation;
        // its original restore journal is read and checked first.
        let adopted_current = match observation.record.data() {
            super::super::activation::ActivationPayload::Current(current)
                if current.operation_id != context =>
            {
                let restore = self.read_journal(&current.operation_id, record as u64, deadline)?;
                let fee =
                    super::super::journal::read_metadata_reservation(&restore.bytes, &self.limits)?;
                self.prepay(fee, 0)?;
                let chain = super::super::journal::observe_chain(&restore.bytes, &self.limits);
                self.post(deadline)?;
                let chain = chain?;
                chain.verify_current_evidence(&observation)?;
                restore_plan = Some(chain.restore_candidate_plan().ok_or_else(invalid)?.clone());
                true
            }
            _ => false,
        };
        let journal = self.read_journal(context, record as u64, deadline)?;
        self.publication_journal = Some(Arc::clone(&journal));
        let fee = super::super::journal::read_metadata_reservation(&journal.bytes, &self.limits)?;
        self.prepay(fee, 0)?;
        self.publication_chain = Some(super::super::journal::observe_chain(
            &journal.bytes,
            &self.limits,
        ));
        self.post(deadline)?;
        let chain = match self.publication_chain.as_ref() {
            Some(Ok(chain)) => chain,
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            None => return Err(invalid()),
        };
        if phase == ActivationPhase::OrdinaryActive {
            chain.verify_ordinary_evidence(&observation)?;
        } else if adopted_current {
            chain.verify_adopted_current(&observation)?;
        } else {
            chain.verify_current_evidence(&observation)?;
            restore_plan = Some(chain.restore_candidate_plan().ok_or_else(invalid)?.clone());
        }
        self.publication_seal = Some(chain.publication_for(
            &observation.record.control_id,
            &observation.digest,
            &reference,
            actual.identity,
            phase,
        ));
        self.post(deadline)?;
        let publication = match self.publication_seal.take() {
            Some(Ok(publication)) => publication,
            other => {
                let fault = other
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map_or(
                        RecoveryControlFault::ControlInvalid,
                        RecoveryControlError::fault,
                    );
                self.publication_seal = other;
                return Err(RecoveryControlError::new(fault));
            }
        };
        PublishedActivation::bind(observation, publication, restore_plan).map(Head::Published)
    }

    /// Open `operations/<context>` as the held operation directory and read
    /// its complete journal.
    pub(super) fn read_journal(
        &mut self,
        context: &str,
        record: u64,
        deadline: Instant,
    ) -> Result<Arc<OwnedRecord>, RecoveryControlError> {
        self.reserve_io(1)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(Directory::Operations)?,
                context,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let identity = self.check_opened(true, deadline)?;
        self.named_matches(Directory::Operations, context, identity, deadline)?;
        let mut operation = [0u8; 32];
        operation.copy_from_slice(context.as_bytes());
        self.publication_operation = Some((operation, identity));
        self.operation_work = Some(self.take_opened()?);
        self.prepay(record, 0)?;
        let cap = self.limits.max_journal_bytes;
        Ok(Arc::new(self.read_record(
            Directory::OperationWork,
            "journal-v1",
            cap,
            deadline,
        )?))
    }
}
