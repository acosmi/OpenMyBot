//! One registration execute joined with its original local guarded PG owner.

use super::super::{DispatchedInitialOwner, InitialError, reply, transfer_registration_request};
use super::{
    Ack, CreatedAttemptOwner, EnrollmentReservation, Error, GatewayAuthorizationJournal, Kind,
    RegisteredAttemptOwner, RegistrationAdmissionReceipt, RegistrationDispatchBinding,
    RegistrationDispatchError, RegistrationDispatchKind, Row, authority_sql,
    canonical_microseconds, current, observation_error, registered_row,
};
use crate::gateway_transport::{
    GatewayAttempt, GatewayAttemptSnapshot, GatewayFailure, GatewayFenceError,
    GatewayHttpAuthority, GatewayHttpOutcomes, GatewayHttpPermit, GatewayRequestDescriptor,
    GatewayRequestKind, GatewayTransportFactory,
};
use acosmi::core::TransportError;
use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(test)]
mod tests;

struct OperationOutcomes {
    attempt: Mutex<Option<GatewayAttempt>>,
    duplicate: AtomicBool,
}
impl OperationOutcomes {
    fn new() -> Self {
        Self {
            attempt: Mutex::new(None),
            duplicate: AtomicBool::new(false),
        }
    }
    fn snapshot(&self) -> Option<GatewayAttemptSnapshot> {
        self.attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(GatewayAttempt::snapshot)
    }
    fn is_duplicate(&self) -> bool {
        self.duplicate.load(Ordering::Acquire)
    }
}
impl GatewayHttpOutcomes for OperationOutcomes {
    fn started(&self, attempt: GatewayAttempt) {
        let mut original = self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if original.is_some() {
            self.duplicate.store(true, Ordering::Release);
        } else {
            *original = Some(attempt);
        }
    }
}

struct RegistrationAcquireControl {
    request: GatewayRequestDescriptor,
    cancel: CancellationToken,
    reply: oneshot::Sender<Result<RegistrationPermitControl, GatewayFenceError>>,
}
struct RegistrationPermitControl {
    release: oneshot::Sender<()>,
    ack: oneshot::Receiver<Result<(), GatewayFenceError>>,
}
struct RegistrationFenceControl {
    acquire: oneshot::Receiver<RegistrationAcquireControl>,
    call_end: oneshot::Receiver<RegistrationFenceEnd>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistrationFenceEnd {
    HeadersRelease,
    RequestEnded,
    Cancelled,
    Deadline,
    CallAbandoned,
}
struct RegistrationFenceResult {
    rollback: Ack,
    end: RegistrationFenceEnd,
    failure: Option<GatewayFenceError>,
}
impl RegistrationFenceResult {
    fn idle(end: RegistrationFenceEnd) -> Self {
        Self {
            rollback: Ack::NotAttempted,
            end,
            failure: None,
        }
    }
}
struct RegistrationAuthority {
    acquire: Mutex<Option<oneshot::Sender<RegistrationAcquireControl>>>,
}
impl RegistrationAuthority {
    fn new(acquire: oneshot::Sender<RegistrationAcquireControl>) -> Self {
        Self {
            acquire: Mutex::new(Some(acquire)),
        }
    }
}
#[async_trait]
impl GatewayHttpAuthority for RegistrationAuthority {
    async fn before_request(
        &self,
        request: GatewayRequestDescriptor,
        cancel: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        let sender = self
            .acquire
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(GatewayFenceError::Refused)?;
        if request.kind() != GatewayRequestKind::OAuthRegistration
            || request.streaming()
            || cancel.is_cancelled()
        {
            return Err(GatewayFenceError::Refused);
        }
        let (reply, receive) = oneshot::channel();
        sender
            .send(RegistrationAcquireControl {
                request,
                cancel: cancel.clone(),
                reply,
            })
            .map_err(|_| GatewayFenceError::Unavailable)?;
        let control = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(GatewayFenceError::CleanupUnknown),
            result = receive => result.map_err(|_| GatewayFenceError::CleanupUnknown)??,
        };
        Ok(Box::new(RegistrationPermit {
            control: Some(control),
        }))
    }
}
struct RegistrationPermit {
    control: Option<RegistrationPermitControl>,
}
#[async_trait]
impl GatewayHttpPermit for RegistrationPermit {
    async fn release_after_headers(mut self: Box<Self>) -> Result<(), GatewayFenceError> {
        let control = self
            .control
            .take()
            .ok_or(GatewayFenceError::CleanupUnknown)?;
        control
            .release
            .send(())
            .map_err(|_| GatewayFenceError::CleanupUnknown)?;
        control
            .ack
            .await
            .map_err(|_| GatewayFenceError::CleanupUnknown)?
    }
}
// Dropping an unconsumed permit drops its unique release sender. No async
// cleanup, ACK, background runner or fresh budget is fabricated by this Drop.

struct CallEndSignal(Mutex<Option<oneshot::Sender<RegistrationFenceEnd>>>);
impl CallEndSignal {
    fn send(&self, end: RegistrationFenceEnd) {
        if let Some(sender) = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = sender.send(end);
        }
    }
}
struct CallEndGuard {
    signal: Arc<CallEndSignal>,
    armed: bool,
}
impl CallEndGuard {
    fn finish(mut self, end: RegistrationFenceEnd) {
        self.armed = false;
        self.signal.send(end);
    }
}
impl Drop for CallEndGuard {
    fn drop(&mut self) {
        if self.armed {
            self.signal.send(RegistrationFenceEnd::CallAbandoned);
        }
    }
}

fn fence_error(error: &Error) -> GatewayFenceError {
    match error.kind {
        Kind::Unavailable
        | Kind::ObservationUnknown
        | Kind::SchemaInvalid
        | Kind::LedgerInvalid => GatewayFenceError::Unavailable,
        Kind::CommitUnknown | Kind::RollbackUnproven | Kind::RollbackAcknowledgedAfterDeadline => {
            GatewayFenceError::CleanupUnknown
        }
        _ => GatewayFenceError::Refused,
    }
}
fn gate_end(error: &Error) -> RegistrationFenceEnd {
    match error.kind {
        Kind::Cancelled => RegistrationFenceEnd::Cancelled,
        Kind::Deadline => RegistrationFenceEnd::Deadline,
        _ => RegistrationFenceEnd::RequestEnded,
    }
}
fn admitted_prefix(row: &Row) -> bool {
    row.phase == "registration_admitted"
        && row.registration_admitted_at.is_some()
        && row.client_id.is_none()
        && row.enrollment_id.is_none()
        && row.code_admitted_at.is_none()
        && row.finished_at.is_none()
        && row.outcome_code.is_none()
}

async fn run_registration_fence(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    binding: &RegistrationDispatchBinding,
    dispatched: &DispatchedInitialOwner,
    mut control: RegistrationFenceControl,
) -> RegistrationFenceResult {
    let gate = match journal.dispatched_gate(auth, binding, dispatched) {
        Ok(gate) => gate,
        Err(error) => {
            return RegistrationFenceResult {
                rollback: Ack::NotAttempted,
                end: gate_end(&error),
                failure: Some(fence_error(&error)),
            };
        }
    };
    let acquire = tokio::select! {
        biased;
        result = &mut control.call_end => return RegistrationFenceResult::idle(result.unwrap_or(RegistrationFenceEnd::CallAbandoned)),
        () = binding.flow.original_parent.cancelled() => return RegistrationFenceResult::idle(RegistrationFenceEnd::Cancelled),
        () = tokio::time::sleep_until(gate.deadline()) => return RegistrationFenceResult::idle(RegistrationFenceEnd::Deadline),
        result = &mut control.acquire => match result {
            Ok(acquire) => acquire,
            Err(_) => return RegistrationFenceResult::idle(RegistrationFenceEnd::CallAbandoned),
        },
    };
    if acquire.request.kind() != GatewayRequestKind::OAuthRegistration
        || acquire.request.streaming()
        || acquire.cancel.is_cancelled()
        || acquire.reply.is_closed()
        || !admitted_prefix(&binding.expected)
    {
        let _ = acquire.reply.send(Err(GatewayFenceError::Refused));
        return RegistrationFenceResult {
            rollback: Ack::NotAttempted,
            end: RegistrationFenceEnd::RequestEnded,
            failure: Some(GatewayFenceError::Refused),
        };
    }
    let observation = match current::borrow_current(journal, auth, &gate).await {
        Ok(observation) if observation.identity().same_binding(&binding.identity) => observation,
        Ok(_) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::Refused));
            return RegistrationFenceResult {
                rollback: Ack::NotAttempted,
                end: RegistrationFenceEnd::RequestEnded,
                failure: Some(GatewayFenceError::Refused),
            };
        }
        Err(error) => {
            let failure = fence_error(&error);
            let _ = acquire.reply.send(Err(failure));
            return RegistrationFenceResult {
                rollback: Ack::NotAttempted,
                end: gate_end(&error),
                failure: Some(failure),
            };
        }
    };
    // Once checkout/BEGIN is attempted, a missing Tx is not a no-BEGIN proof.
    let mut client = match gate
        .io(journal.pool.get_guarded(gate.deadline().into_std()), |_| {
            Error::new(Kind::Unavailable)
        })
        .await
    {
        Ok(client) => client,
        Err(error) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::CleanupUnknown));
            return RegistrationFenceResult {
                rollback: Ack::Unknown,
                end: gate_end(&error),
                failure: Some(GatewayFenceError::CleanupUnknown),
            };
        }
    };
    let tx = match gate
        .io(client.begin_read_committed(), observation_error)
        .await
    {
        Ok(tx) => tx,
        Err(error) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::CleanupUnknown));
            return RegistrationFenceResult {
                rollback: Ack::Unknown,
                end: gate_end(&error),
                failure: Some(GatewayFenceError::CleanupUnknown),
            };
        }
    };
    let validation = async {
        gate.io(
            crate::db::native::validate_gateway_authorization_journal_in_transaction(
                tx.as_transaction(),
            ),
            authority_sql::native_error,
        )
        .await?;
        let tail = current::lock_actor(tx.as_transaction(), auth, &observation, &gate).await?;
        let locked =
            authority_sql::lock_attempt(tx.as_transaction(), binding.expected.attempt_id, &gate)
                .await?;
        if locked != binding.expected || !admitted_prefix(&locked) {
            return Err(Error::new(Kind::Refused));
        }
        current::verify_tail(tail.as_ref(), auth, &gate)?;
        journal.dispatched_gate(auth, binding, dispatched)?;
        Ok::<_, Error>(tail)
    }
    .await;
    let tail = match validation {
        Ok(tail) => tail,
        Err(error) => {
            let (rollback, failure, end) = match gate.terminal(tx.rollback(), false).await {
                Ok(ack) => (ack, fence_error(&error), gate_end(&error)),
                Err((terminal, ack)) => {
                    (ack, GatewayFenceError::CleanupUnknown, gate_end(&terminal))
                }
            };
            let _ = acquire.reply.send(Err(failure));
            return RegistrationFenceResult {
                rollback,
                end,
                failure: Some(failure),
            };
        }
    };
    let (release, mut release_receive) = oneshot::channel();
    let (ack, ack_receive) = oneshot::channel();
    // Send failure drops the actual permit controls and closes release_receive.
    let _ = acquire.reply.send(Ok(RegistrationPermitControl {
        release,
        ack: ack_receive,
    }));
    let end = tokio::select! {
        biased;
        result = &mut release_receive => if result.is_ok() { RegistrationFenceEnd::HeadersRelease } else { RegistrationFenceEnd::CallAbandoned },
        result = &mut control.call_end => result.unwrap_or(RegistrationFenceEnd::CallAbandoned),
        () = binding.flow.original_parent.cancelled() => RegistrationFenceEnd::Cancelled,
        () = tokio::time::sleep_until(gate.deadline()) => RegistrationFenceEnd::Deadline,
    };
    let before = current::verify_tail(tail.as_ref(), auth, &gate);
    let (rollback, terminal_failure) = match gate.terminal(tx.rollback(), false).await {
        Ok(ack) => (ack, None),
        Err((_, ack)) => (ack, Some(GatewayFenceError::CleanupUnknown)),
    };
    drop(client);
    let failure = terminal_failure
        .or_else(|| before.err().map(|error| fence_error(&error)))
        .or_else(|| {
            current::verify_tail(tail.as_ref(), auth, &gate)
                .err()
                .map(|error| fence_error(&error))
        });
    let released =
        rollback == Ack::Timely && failure.is_none() && end == RegistrationFenceEnd::HeadersRelease;
    let _ = ack.send(if released {
        Ok(())
    } else {
        Err(failure.unwrap_or(GatewayFenceError::CleanupUnknown))
    });
    // No receiver-consumption, execute completion or body future is awaited here.
    RegistrationFenceResult {
        rollback,
        end,
        failure,
    }
}

fn journal_dispatch_kind(error: &Error) -> RegistrationDispatchKind {
    match error.kind {
        Kind::Cancelled => RegistrationDispatchKind::Cancelled,
        Kind::Deadline => RegistrationDispatchKind::Deadline,
        Kind::Unavailable
        | Kind::LedgerInvalid
        | Kind::SchemaInvalid
        | Kind::ObservationUnknown => RegistrationDispatchKind::Unavailable,
        Kind::CommitUnknown => RegistrationDispatchKind::CommitUnknown,
        Kind::CommitAcknowledgedAfterDeadline => {
            RegistrationDispatchKind::CommitAcknowledgedAfterDeadline
        }
        Kind::RollbackAcknowledgedAfterDeadline => {
            RegistrationDispatchKind::RollbackAcknowledgedAfterDeadline
        }
        Kind::ReadbackUnproven => RegistrationDispatchKind::ReadbackUnproven,
        Kind::RollbackUnproven => RegistrationDispatchKind::CleanupUnknown,
        Kind::Refused => RegistrationDispatchKind::BeforeDispatchRefused,
    }
}
fn after_send_kind(error: &Error) -> RegistrationDispatchKind {
    match error.kind {
        Kind::Refused => RegistrationDispatchKind::RegistrationUnknown,
        _ => journal_dispatch_kind(error),
    }
}
fn readback_kind(error: &Error) -> RegistrationDispatchKind {
    match error.kind {
        Kind::Cancelled => RegistrationDispatchKind::Cancelled,
        Kind::Deadline => RegistrationDispatchKind::Deadline,
        Kind::RollbackAcknowledgedAfterDeadline => {
            RegistrationDispatchKind::RollbackAcknowledgedAfterDeadline
        }
        _ => RegistrationDispatchKind::ReadbackUnproven,
    }
}
fn initial_dispatch_kind(error: InitialError) -> RegistrationDispatchKind {
    match error {
        InitialError::Cancelled => RegistrationDispatchKind::Cancelled,
        InitialError::Deadline => RegistrationDispatchKind::Deadline,
        InitialError::HttpStatus(status) => RegistrationDispatchKind::HttpStatus(status),
        InitialError::RequestMismatch => RegistrationDispatchKind::FramingInvalid,
        InitialError::ProducerEnded => RegistrationDispatchKind::Unavailable,
        InitialError::ProtocolInvalid(_) | InitialError::BodyTransport => {
            RegistrationDispatchKind::RegistrationUnknown
        }
    }
}
fn operation_error(
    kind: RegistrationDispatchKind,
    outcomes: &OperationOutcomes,
    rollback: Ack,
) -> RegistrationDispatchError {
    let mut error = RegistrationDispatchError::new(kind);
    error.transport = outcomes.snapshot();
    error.send_guard_rollback = rollback;
    error
}
fn transport_kind(
    error: &TransportError,
    snapshot: Option<GatewayAttemptSnapshot>,
) -> RegistrationDispatchKind {
    match error {
        TransportError::Cancelled => RegistrationDispatchKind::Cancelled,
        TransportError::Timeout => RegistrationDispatchKind::Deadline,
        TransportError::InvalidRequest => RegistrationDispatchKind::FramingInvalid,
        _ => match snapshot.and_then(GatewayAttemptSnapshot::failure) {
            Some(GatewayFailure::Cancelled) => RegistrationDispatchKind::Cancelled,
            Some(GatewayFailure::Timeout) => RegistrationDispatchKind::Deadline,
            Some(GatewayFailure::Unavailable) => RegistrationDispatchKind::Unavailable,
            Some(GatewayFailure::InvalidRequest) => RegistrationDispatchKind::FramingInvalid,
            Some(GatewayFailure::CleanupUnknown) => RegistrationDispatchKind::CleanupUnknown,
            _ if snapshot.is_some_and(GatewayAttemptSnapshot::may_have_sent) => {
                RegistrationDispatchKind::RegistrationUnknown
            }
            _ => RegistrationDispatchKind::BeforeDispatchRefused,
        },
    }
}

pub(super) async fn dispatch_registration(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    receipt: RegistrationAdmissionReceipt,
    factory: &GatewayTransportFactory,
) -> Result<RegisteredAttemptOwner, RegistrationDispatchError> {
    {
        let gate = journal
            .owner_gate(auth, &receipt.owner)
            .map_err(|error| RegistrationDispatchError::new(journal_dispatch_kind(&error)))?;
        if !admitted_prefix(&receipt.owner.expected) {
            return Err(RegistrationDispatchError::new(
                RegistrationDispatchKind::BeforeDispatchRefused,
            ));
        }
        let observation = current::borrow_current(journal, auth, &gate)
            .await
            .map_err(|error| RegistrationDispatchError::new(journal_dispatch_kind(&error)))?;
        if !observation.identity().same_binding(&receipt.owner.identity) {
            return Err(RegistrationDispatchError::new(
                RegistrationDispatchKind::BeforeDispatchRefused,
            ));
        }
    }
    let CreatedAttemptOwner {
        prepared,
        flow,
        identity,
        expected,
        journal: original_journal,
        runtime,
    } = receipt.owner;
    let (request, dispatched) = transfer_registration_request(prepared)
        .map_err(|error| RegistrationDispatchError::new(initial_dispatch_kind(error)))?;
    let mut binding = RegistrationDispatchBinding {
        flow,
        identity,
        expected,
        journal: original_journal,
        runtime,
    };
    let gate = journal
        .dispatched_gate(auth, &binding, &dispatched)
        .map_err(|error| RegistrationDispatchError::new(journal_dispatch_kind(&error)))?;
    let deadline = gate.deadline();
    let stall = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| RegistrationDispatchError::new(RegistrationDispatchKind::Deadline))?;
    let (acquire, acquire_receive) = oneshot::channel();
    let (call_end, call_end_receive) = oneshot::channel();
    let authority = Arc::new(RegistrationAuthority::new(acquire));
    let outcomes = Arc::new(OperationOutcomes::new());
    let transport = factory
        .for_operation(authority, outcomes.clone(), deadline, stall)
        .map_err(|_| RegistrationDispatchError::new(RegistrationDispatchKind::Unavailable))?;
    let end_signal = Arc::new(CallEndSignal(Mutex::new(Some(call_end))));
    let (response, fence) = {
        let http = async {
            let end = CallEndGuard {
                signal: end_signal,
                armed: true,
            };
            let response = transport
                .execute(request, dispatched.budget.original_parent.clone())
                .await;
            let reason = match &response {
                Err(TransportError::Cancelled) => RegistrationFenceEnd::Cancelled,
                Err(TransportError::Timeout) => RegistrationFenceEnd::Deadline,
                _ => RegistrationFenceEnd::RequestEnded,
            };
            end.finish(reason);
            response
        };
        let runner = run_registration_fence(
            journal,
            auth,
            &binding,
            &dispatched,
            RegistrationFenceControl {
                acquire: acquire_receive,
                call_end: call_end_receive,
            },
        );
        tokio::join!(http, runner)
    };
    if outcomes.is_duplicate() {
        return Err(operation_error(
            RegistrationDispatchKind::BeforeDispatchRefused,
            &outcomes,
            fence.rollback,
        ));
    }
    if fence.rollback == Ack::Late {
        return Err(operation_error(
            RegistrationDispatchKind::RollbackAcknowledgedAfterDeadline,
            &outcomes,
            fence.rollback,
        ));
    }
    binding
        .flow
        .check_registration_reply(&dispatched.budget, &dispatched.clock)
        .map_err(|error| {
            operation_error(initial_dispatch_kind(error), &outcomes, fence.rollback)
        })?;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let kind = if fence.rollback == Ack::Unknown
                && fence.failure == Some(GatewayFenceError::CleanupUnknown)
                && !matches!(
                    fence.end,
                    RegistrationFenceEnd::Cancelled | RegistrationFenceEnd::Deadline
                ) {
                RegistrationDispatchKind::CleanupUnknown
            } else {
                transport_kind(&error, outcomes.snapshot())
            };
            return Err(operation_error(kind, &outcomes, fence.rollback));
        }
    };
    if fence.rollback != Ack::Timely || fence.failure.is_some() {
        return Err(operation_error(
            RegistrationDispatchKind::CleanupUnknown,
            &outcomes,
            fence.rollback,
        ));
    }
    journal
        .dispatched_gate(auth, &binding, &dispatched)
        .map_err(|error| operation_error(after_send_kind(&error), &outcomes, fence.rollback))?;
    // The scoped runner borrows are finished before this whole owner moves.
    let reply = reply::consume_dispatched_registration(dispatched, response, &binding.flow)
        .await
        .map_err(|error| {
            operation_error(initial_dispatch_kind(error), &outcomes, fence.rollback)
        })?;
    journal
        .registered_reply_gate(auth, &binding, &reply)
        .map_err(|error| operation_error(after_send_kind(&error), &outcomes, fence.rollback))?;
    let reservation = EnrollmentReservation { id: Uuid::now_v7() };
    let next = write_registered(journal, auth, &binding, &reply, &reservation)
        .await
        .map_err(|error| {
            let mut closed = operation_error(after_send_kind(&error), &outcomes, fence.rollback);
            closed.registered_write = error.write_ack;
            closed.registered_readback = error.readback_ack;
            closed
        })?;
    let gate = journal
        .registered_reply_gate(auth, &binding, &reply)
        .map_err(|error| {
            let mut closed =
                operation_error(journal_dispatch_kind(&error), &outcomes, fence.rollback);
            closed.registered_write = Ack::Timely;
            closed
        })?;
    authority_sql::readback_exact(journal, auth, &binding.identity, &next, &gate)
        .await
        .map_err(|error| {
            let mut closed = operation_error(readback_kind(&error), &outcomes, fence.rollback);
            // The prior write returned only after its original timely COMMIT.
            // A readback failure cannot replace that already-established fact.
            closed.registered_write = Ack::Timely;
            closed.registered_readback = error.readback_ack;
            closed
        })?;
    gate.check().map_err(|error| {
        let mut closed = operation_error(journal_dispatch_kind(&error), &outcomes, fence.rollback);
        closed.registered_write = Ack::Timely;
        closed.registered_readback = Ack::Timely;
        closed
    })?;
    // Expected advances only after both original timely terminals and exact RO
    // readback. The private reservation moves into the returned whole owner.
    binding.expected = next;
    Ok(RegisteredAttemptOwner {
        reply,
        binding,
        reservation,
    })
}

async fn write_registered(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    binding: &RegistrationDispatchBinding,
    reply: &super::super::OwnedRegistrationReply,
    reservation: &EnrollmentReservation,
) -> Result<Row, Error> {
    let gate = journal.registered_reply_gate(auth, binding, reply)?;
    let observation = current::borrow_current(journal, auth, &gate).await?;
    if !observation.identity().same_binding(&binding.identity) {
        return Err(Error::new(Kind::Refused));
    }
    let mut client = gate
        .io(journal.pool.get_guarded(gate.deadline().into_std()), |_| {
            Error::new(Kind::Unavailable)
        })
        .await?;
    let tx = gate
        .io(client.begin_read_committed(), observation_error)
        .await
        .map_err(|error| error.with_acks(Ack::Unknown, Ack::NotAttempted))?;
    let operation = async {
        gate.io(
            crate::db::native::validate_gateway_authorization_journal_in_transaction(
                tx.as_transaction(),
            ),
            authority_sql::native_error,
        )
        .await?;
        let tail = current::lock_actor(tx.as_transaction(), auth, &observation, &gate).await?;
        let locked =
            authority_sql::lock_attempt(tx.as_transaction(), binding.expected.attempt_id, &gate)
                .await?;
        if locked != binding.expected {
            return Err(Error::new(Kind::Refused));
        }
        let stamp = canonical_microseconds(gate.check()?.wall)?;
        let next = registered_row(&locked, &reply.client_id, reservation.id, stamp)?;
        current::verify_tail(tail.as_ref(), auth, &gate)?;
        authority_sql::cas_registered(tx.as_transaction(), &locked, &next, &gate).await?;
        authority_sql::append_registered_audit(
            tx.as_transaction(),
            auth,
            &next,
            &journal.audit_key,
            &gate,
        )
        .await?;
        current::verify_tail(tail.as_ref(), auth, &gate)?;
        Ok::<_, Error>((next, tail))
    }
    .await;
    let (next, tail) = match operation {
        Ok(result) => result,
        Err(error) => {
            return Err(match gate.terminal(tx.rollback(), false).await {
                Ok(ack) => error.with_acks(ack, Ack::NotAttempted),
                Err((terminal, ack)) => terminal.with_acks(ack, Ack::NotAttempted),
            });
        }
    };
    match gate.terminal(tx.commit(), true).await {
        Ok(_) => {}
        Err((error, ack)) => return Err(error.with_acks(ack, Ack::NotAttempted)),
    }
    drop(client);
    current::verify_tail(tail.as_ref(), auth, &gate)
        .map_err(|error| error.with_acks(Ack::Timely, Ack::NotAttempted))?;
    Ok(next)
}
