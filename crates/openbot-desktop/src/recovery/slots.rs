//! The original restore owner's two fixed target-slot native results.

use openbot_domain::vault::SecretBytes;
use openbot_infra::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging;
use openbot_infra::recovery_control::{RecoveryControlError, RestoreCapacityReservation, RestoreCapacityResource, RestoreControlSession, RestoreTargetSlotOutcome};
use std::time::Instant;

use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
use crate::postgres_sidecar::{PostgresScramSecret, PostgresSecretStoreError};
use super::DesktopRestoreError;

enum OriginalStoreWrite {
    Entered,
    Returned(Result<(), OsSecretStoreError>),
}

struct TargetSlot {
    service: String,
    account: String,
    effect: Instant,
    absence: Option<Result<Option<SecretBytes>, OsSecretStoreError>>,
    write: Option<OriginalStoreWrite>,
    readback: Option<Result<Option<SecretBytes>, OsSecretStoreError>>,
    observation: Option<Result<(), RecoveryControlError>>,
}

/// Concrete private custody, not a root/clock, Current, candidate or public
/// secret proof. Every returned native result remains resident on failure.
pub(super) struct RestoreTargetSlotWork {
    operation: String,
    generation: String,
    slots: [Option<Box<TargetSlot>>; 2],
    master: Option<SecretBytes>,
    scram: Option<Result<PostgresScramSecret, PostgresSecretStoreError>>,
    control_error: Option<RecoveryControlError>,
    result: Option<Result<(), DesktopRestoreError>>,
    metadata: Option<RestoreCapacityReservation>,
    secrets: Option<RestoreCapacityReservation>,
    structures: Option<RestoreCapacityReservation>,
    slot_metadata: [Option<RestoreCapacityReservation>; 2],
}

pub(super) fn install_target_slots_before(
    retained: &mut Option<Box<RestoreTargetSlotWork>>,
    source: &VerifiedWholePgRestoreStaging,
    session: &mut RestoreControlSession,
    store: &dyn OsSecretStore,
) -> Result<(), DesktopRestoreError> {
    if let Some(work) = retained {
        if work.operation != session.operation_id() || work.operation != source.candidate_plan().operation_id()
            || work.generation != source.candidate_plan().generation_id() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        return work.result.unwrap_or(Err(DesktopRestoreError::KeyStoreUnknown));
    }
    let body = std::mem::size_of::<RestoreTargetSlotWork>()
        .checked_add(session.operation_id().len()).and_then(|bytes| bytes.checked_add(source.candidate_plan().generation_id().len()))
        .ok_or(DesktopRestoreError::CapacityExceeded)?;
    let metadata = session.admit_capacity(RestoreCapacityResource::MetadataBytes, body as u64)
        .map_err(|error| DesktopRestoreError::from_control(&error))?;
    *retained = Some(Box::new(RestoreTargetSlotWork {
        operation: session.operation_id().to_owned(), generation: source.candidate_plan().generation_id().to_owned(),
        slots: [None, None], master: None, scram: None, control_error: None,
        result: None, metadata: Some(metadata), secrets: None, structures: None, slot_metadata: [None, None],
    }));
    let work = retained.as_mut().expect("original concrete slot work retained");
    let result = install_once(work, source, session, store);
    work.result = Some(result);
    result
}

fn install_once(work: &mut RestoreTargetSlotWork, source: &VerifiedWholePgRestoreStaging, session: &mut RestoreControlSession, store: &dyn OsSecretStore) -> Result<(), DesktopRestoreError> {
    let memory = work.metadata.take().expect("original work allocation admission");
    let actual = std::mem::size_of::<RestoreTargetSlotWork>().checked_add(work.operation.capacity())
        .and_then(|bytes| bytes.checked_add(work.generation.capacity())).ok_or(DesktopRestoreError::CapacityExceeded)?;
    session.settle_capacity(memory, actual as u64).map_err(|error| work.keep_control(error))?;
    let convergence = session.restore_slot_convergence_deadline().map_err(|error| work.keep_control(error))?;
    for index in 0..2 {
        // The original entry pays the moved tuple's body and backing. Only the
        // additional concrete native-result fields are paid here.
        let additional = std::mem::size_of::<TargetSlot>().checked_sub(std::mem::size_of::<(String, String, Instant)>())
            .ok_or(DesktopRestoreError::CapacityExceeded)?;
        work.slot_metadata[index] = Some(session.admit_capacity(RestoreCapacityResource::MetadataBytes, additional as u64).map_err(|error| work.keep_control(error))?);
        let (service, account, effect) = if index == 0 { session.begin_restore_master_slot_before(source, convergence) }
            else { session.begin_restore_scram_slot_before(source, convergence) }.map_err(|error| work.keep_control(error))?;
        work.slots[index] = Some(Box::new(TargetSlot { service, account, effect,
            absence: None, write: None, readback: None, observation: None }));
        session.settle_capacity(work.slot_metadata[index].take().expect("slot outcome admission"), additional as u64).map_err(|error| work.keep_control(error))?;
        if index == 0 { prepare_secrets(work, source, session)?; }
        read_slot(work, index, false, session, store)?;
        if !matches!(work.slots[index].as_ref().expect("fixed slot").absence, Some(Ok(None))) {
            return Err(DesktopRestoreError::KeyStoreUnknown);
        }
        session.check_restore_slot_effect_before(effect).map_err(|error| work.keep_control(error))?;
        work.slots[index].as_mut().expect("original slot").write = Some(OriginalStoreWrite::Entered);
        let returned = {
            let slot = work.slots[index].as_ref().expect("fixed original service/account");
            store.write(&slot.service, &slot.account, work.expected(index).expose())
        };
        work.slots[index].as_mut().expect("original write custody").write = Some(OriginalStoreWrite::Returned(returned));
        if !matches!(work.slots[index].as_ref().expect("original slot").write, Some(OriginalStoreWrite::Returned(Ok(())))) {
            let _recorded = observe_slot(work, index, session, RestoreTargetSlotOutcome::WriteUnknown, convergence);
            return Err(DesktopRestoreError::KeyStoreUnknown);
        }
        if let Err(error) = session.check_restore_slot_effect_before(effect) {
            let fault = work.keep_control(error);
            let _recorded = observe_slot(work, index, session, RestoreTargetSlotOutcome::ReadbackUnknown, convergence);
            return Err(fault);
        }
        if let Err(fault) = read_slot(work, index, true, session, store) {
            let _recorded = observe_slot(work, index, session, RestoreTargetSlotOutcome::ReadbackUnknown, convergence);
            return Err(fault);
        }
        let actual = work.slots[index].as_ref().expect("original slot").readback.as_ref()
            .and_then(|result| result.as_ref().ok()).and_then(Option::as_ref);
        if !actual.is_some_and(|actual| work.expected(index).ct_eq(actual)) {
            let _recorded = observe_slot(work, index, session, RestoreTargetSlotOutcome::ReadbackUnknown, convergence);
            return Err(DesktopRestoreError::KeyStoreUnknown);
        }
        observe_slot(work, index, session, RestoreTargetSlotOutcome::ReadbackMatched, convergence)?;
    }
    Ok(())
}

impl RestoreTargetSlotWork {
    #[cfg(test)]
    pub(super) fn returned_write(&self, index: usize) -> Option<&Result<(), OsSecretStoreError>> {
        match self.slots.get(index)?.as_ref()?.write.as_ref()? {
            OriginalStoreWrite::Entered => None,
            OriginalStoreWrite::Returned(result) => Some(result),
        }
    }

    #[cfg(test)]
    pub(super) fn returned_absence(&self, index: usize) -> Option<&Result<Option<SecretBytes>, OsSecretStoreError>> {
        self.slots.get(index)?.as_ref()?.absence.as_ref()
    }

    #[cfg(test)]
    pub(super) fn returned_readback(&self, index: usize) -> Option<&Result<Option<SecretBytes>, OsSecretStoreError>> {
        self.slots.get(index)?.as_ref()?.readback.as_ref()
    }

    fn keep_control(&mut self, error: RecoveryControlError) -> DesktopRestoreError {
        let fault = DesktopRestoreError::from_control(&error);
        if self.control_error.is_none() { self.control_error = Some(error); }
        fault
    }
    fn expected(&self, index: usize) -> &SecretBytes {
        if index == 0 {
            self.master.as_ref().expect("original authenticated master frame retained")
        } else {
            self.scram.as_ref().and_then(|result| result.as_ref().ok())
                .expect("original newly generated SCRAM retained").secret_bytes()
        }
    }
}

fn prepare_secrets(work: &mut RestoreTargetSlotWork, source: &VerifiedWholePgRestoreStaging, session: &mut RestoreControlSession) -> Result<(), DesktopRestoreError> {
    work.secrets = Some(session.admit_capacity(RestoreCapacityResource::SecretMemoryBytes, 33 + 64 + 32).map_err(|error| work.keep_control(error))?);
    work.structures = Some(session.admit_capacity(RestoreCapacityResource::SecretStructureBytes,
        (3 * std::mem::size_of::<SecretBytes>() + 2 * std::mem::size_of::<usize>()) as u64).map_err(|error| work.keep_control(error))?);
    work.master = Some(crate::desktop_vault::frame_stored(source.authenticated_secrets().historical_master()));
    work.scram = Some(PostgresScramSecret::generate());
    let actual = work.master.as_ref().expect("original master frame returned").allocation_capacity()
        .checked_add(work.scram.as_ref().and_then(|result| result.as_ref().ok()).map_or(0, |secret| secret.secret_bytes().allocation_capacity()))
        .ok_or(DesktopRestoreError::CapacityExceeded)?;
    session.settle_capacity(work.secrets.take().expect("original secret admission"), actual as u64).map_err(|error| work.keep_control(error))?;
    let structures = std::mem::size_of::<SecretBytes>() + if work.scram.as_ref().is_some_and(Result::is_ok) {
        std::mem::size_of::<SecretBytes>() + 2 * std::mem::size_of::<usize>()
    } else { 0 };
    session.settle_capacity(work.structures.take().expect("original structure admission"), structures as u64).map_err(|error| work.keep_control(error))?;
    if !work.scram.as_ref().is_some_and(Result::is_ok) { return Err(DesktopRestoreError::KeyStoreUnknown); }
    Ok(())
}

fn read_slot(work: &mut RestoreTargetSlotWork, index: usize, readback: bool, session: &mut RestoreControlSession, store: &dyn OsSecretStore) -> Result<(), DesktopRestoreError> {
    let effect = work.slots[index].as_ref().expect("original fixed slot").effect;
    session.check_restore_slot_effect_before(effect).map_err(|error| work.keep_control(error))?;
    // An original ledger reservation is not a limit on the native port's
    // internal to_vec. Oversized returned values remain retained on failure;
    // this component does not claim that production boundary is repaired.
    let available = session.restore_slot_secret_capacity_before(effect).map_err(|error| work.keep_control(error))?;
    let reservation = session.admit_capacity(RestoreCapacityResource::SecretMemoryBytes, available).map_err(|error| work.keep_control(error))?;
    let returned = {
        let slot = work.slots[index].as_ref().expect("original fixed service/account");
        store.read(&slot.service, &slot.account)
    };
    let slot = work.slots[index].as_mut().expect("original returned-read custody");
    let retained = if readback { &mut slot.readback } else { &mut slot.absence };
    *retained = Some(returned);
    // None/error has no returned SecretBytes payload; Some is charged by its
    // actual allocation, never silently replaced with an invented zero.
    let allocation = retained.as_ref().and_then(|result| result.as_ref().ok()).and_then(Option::as_ref)
        .map_or(0, SecretBytes::allocation_capacity);
    session.settle_capacity(reservation, allocation as u64).map_err(|error| work.keep_control(error))?;
    session.check_restore_slot_effect_before(effect).map_err(|error| work.keep_control(error))?;
    Ok(())
}

fn observe_slot(work: &mut RestoreTargetSlotWork, index: usize, session: &mut RestoreControlSession, outcome: RestoreTargetSlotOutcome, convergence: Instant) -> Result<(), DesktopRestoreError> {
    let returned = if index == 0 { session.observe_restore_master_slot_before(outcome, convergence) }
        else { session.observe_restore_scram_slot_before(outcome, convergence) };
    work.slots[index].as_mut().expect("original stage observation").observation = Some(returned);
    match work.slots[index].as_ref().expect("original slot").observation.as_ref().expect("original observation returned") {
        Ok(()) => Ok(()),
        Err(error) => Err(DesktopRestoreError::from_control(error)),
    }
}
