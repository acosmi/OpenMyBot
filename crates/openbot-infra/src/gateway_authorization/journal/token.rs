//! One original SDK code grant, its original current owner and three independent ACKs.

use super::super::{
    CodeDispatchedInitialOwner, InitialError, InitialReplyWitness, ReplyInvalidReason,
    ReplyResources, TokenSetGuard, prepare_initial, reply, retain_parent_budget, tokens,
    transfer_code_request,
};
use super::{
    Ack, EnrollmentReservation, Error, GatewayAuthorizationJournal,
    GatewayAuthorizationTokenError as TokenError, GatewayAuthorizationTokenKind as TokenKind,
    GatewayAuthorizationTokenOwner, GatewayAuthorizationTokenReplyReason as ReplyReason,
    GatewayAuthorizationTokenStage as Stage, GatewayAuthorizationVerifiedCodeOwner, Kind,
    OperationGate, RegistrationDispatchBinding, Row, TokenCaptureOwner, TokenGatePhase,
    authority_sql, callback, canonical_microseconds, code_admitted_row, current, host_error,
    observation_error,
};
use crate::db::pool::TransactionOwnerError;
use crate::gateway_transport::{
    GatewayAttempt, GatewayAttemptSnapshot, GatewayFailure, GatewayFenceError,
    GatewayHttpAuthority, GatewayHttpOutcomes, GatewayHttpPermit, GatewayRequestDescriptor,
    GatewayRequestKind, GatewayTransportFactory,
};
use acosmi::TransportError;
use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::request_binding::HostRequestBindingKind;
use std::{
    future::{Future, poll_fn},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

const BODY_LIMIT: usize = 64 * 1024;
const TOKEN_READBACK: &str = r"/* gateway_authorization_exact_readback */
 SELECT attempt_id,journal_schema,deployment_id,tenant_id,owner_user_id,auth_generation,
 installation_id,runtime_epoch,issuer,redirect_uri,phase,client_id,enrollment_id,
 registration_admitted_at,code_admitted_at,created_at,expires_at,updated_at,finished_at,outcome_code
 FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1";

struct OperationOutcomes {
    attempt: Mutex<Option<GatewayAttempt>>,
    duplicate: AtomicBool,
    execute_polled: AtomicBool,
}
impl OperationOutcomes {
    fn new() -> Self {
        Self {
            attempt: Mutex::new(None),
            duplicate: AtomicBool::new(false),
            execute_polled: AtomicBool::new(false),
        }
    }
    fn snapshot(&self) -> Option<GatewayAttemptSnapshot> {
        self.attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(GatewayAttempt::snapshot)
    }
    fn refused_kind(&self) -> TokenKind {
        refusal_kind(self.execute_polled.load(Ordering::Acquire), self.snapshot())
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
fn refusal_kind(execute_polled: bool, snapshot: Option<GatewayAttemptSnapshot>) -> TokenKind {
    if !execute_polled || snapshot.is_some_and(|s| !s.may_have_sent()) {
        TokenKind::BeforeDispatchRefused
    } else {
        TokenKind::TokenUnknown
    }
}
#[derive(Clone, Copy)]
struct History {
    write: Ack,
    readback: Ack,
    send: Ack,
}
impl History {
    const fn new() -> Self {
        Self {
            write: Ack::NotAttempted,
            readback: Ack::NotAttempted,
            send: Ack::NotAttempted,
        }
    }
    fn error(self, stage: Stage, kind: TokenKind, outcomes: &OperationOutcomes) -> TokenError {
        let mut error = TokenError::new(stage, kind);
        error.snapshot = outcomes.snapshot();
        error.code_write = self.write;
        error.code_readback = self.readback;
        error.token_send = self.send;
        error
    }
    fn journal(self, stage: Stage, error: &Error, outcomes: &OperationOutcomes) -> TokenError {
        self.error(stage, journal_kind(error, outcomes), outcomes)
    }
}
fn journal_kind(error: &Error, outcomes: &OperationOutcomes) -> TokenKind {
    match error.kind {
        Kind::Refused => outcomes.refused_kind(),
        Kind::Cancelled => TokenKind::Cancelled,
        Kind::Deadline => TokenKind::Deadline,
        Kind::Unavailable
        | Kind::LedgerInvalid
        | Kind::SchemaInvalid
        | Kind::ObservationUnknown => TokenKind::Unavailable,
        Kind::CommitUnknown => TokenKind::CommitUnknown,
        Kind::CommitAcknowledgedAfterDeadline => TokenKind::CommitAcknowledgedAfterDeadline,
        Kind::RollbackUnproven => TokenKind::CleanupUnknown,
        Kind::RollbackAcknowledgedAfterDeadline => TokenKind::RollbackAcknowledgedAfterDeadline,
        Kind::ReadbackUnproven => TokenKind::ReadbackUnproven,
    }
}
fn initial_kind(error: InitialError) -> TokenKind {
    match error {
        InitialError::Cancelled => TokenKind::Cancelled,
        InitialError::Deadline => TokenKind::Deadline,
        InitialError::ProducerEnded => TokenKind::ProducerEnded,
        InitialError::RequestMismatch => TokenKind::RequestMismatch,
        InitialError::HttpStatus(status) => TokenKind::HttpStatus(status),
        InitialError::BodyTransport => TokenKind::BodyTransport,
        InitialError::ProtocolInvalid(reason) => TokenKind::ProtocolInvalid(match reason {
            ReplyInvalidReason::JsonSyntax => ReplyReason::JsonSyntax,
            ReplyInvalidReason::UnknownKey => ReplyReason::UnknownKey,
            ReplyInvalidReason::DuplicateKey => ReplyReason::DuplicateKey,
            ReplyInvalidReason::ForbiddenSecretKey => ReplyReason::ForbiddenSecretKey,
            ReplyInvalidReason::FieldShape => ReplyReason::FieldShape,
            ReplyInvalidReason::HeaderLimit => ReplyReason::HeaderLimit,
            ReplyInvalidReason::MediaType => ReplyReason::MediaType,
            ReplyInvalidReason::BodyLimit => ReplyReason::BodyLimit,
            ReplyInvalidReason::FieldLimit => ReplyReason::FieldLimit,
            ReplyInvalidReason::ScopeShape => ReplyReason::ScopeShape,
            ReplyInvalidReason::TokenType => ReplyReason::TokenType,
            ReplyInvalidReason::ExpiryInteger => ReplyReason::ExpiryInteger,
            ReplyInvalidReason::ClockOrExpiry => ReplyReason::ClockOrExpiry,
            ReplyInvalidReason::ReplyBinding => ReplyReason::ReplyBinding,
        }),
    }
}
fn transport_kind(error: &TransportError, outcomes: &OperationOutcomes) -> TokenKind {
    match error {
        TransportError::Cancelled => TokenKind::Cancelled,
        TransportError::Timeout => TokenKind::Deadline,
        TransportError::InvalidRequest => TokenKind::FramingInvalid,
        _ => match outcomes
            .snapshot()
            .and_then(GatewayAttemptSnapshot::failure)
        {
            Some(GatewayFailure::Cancelled) => TokenKind::Cancelled,
            Some(GatewayFailure::Timeout) => TokenKind::Deadline,
            Some(GatewayFailure::Unavailable) => TokenKind::Unavailable,
            Some(GatewayFailure::InvalidRequest) => TokenKind::FramingInvalid,
            Some(GatewayFailure::CleanupUnknown) => TokenKind::CleanupUnknown,
            _ => outcomes.refused_kind(),
        },
    }
}

#[derive(Clone, Copy)]
enum Resources<'a> {
    Capture(&'a callback::TokenCaptureWitness),
    Dispatched(&'a CodeDispatchedInitialOwner, TokenGatePhase),
    Tokens(&'a TokenSetGuard),
}
struct Current<'a> {
    journal: &'a Arc<GatewayAuthorizationJournal>,
    auth: &'a AuthContext,
    binding: &'a RegistrationDispatchBinding,
    reservation: &'a EnrollmentReservation,
    resources: Resources<'a>,
}
impl<'a> Current<'a> {
    fn gate(&self) -> Result<OperationGate<'a>, Error> {
        match self.resources {
            Resources::Capture(capture) => {
                self.journal
                    .token_capture_gate(self.auth, self.binding, self.reservation, capture)
            }
            Resources::Dispatched(dispatched, phase) => self.journal.token_dispatched_gate(
                self.auth,
                self.binding,
                self.reservation,
                dispatched,
                phase,
            ),
            Resources::Tokens(tokens) => {
                self.journal
                    .token_owner_gate(self.auth, self.binding, self.reservation, tokens)
            }
        }
    }
    fn check(&self) -> Result<(), Error> {
        let gate = self.gate()?;
        let issuer = self
            .journal
            .issuer
            .get()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        let attached = self
            .auth
            .request_binding()
            .ok_or_else(|| Error::new(Kind::Refused))?;
        if !issuer.observation().is_current()
            || !issuer.owns_identity(attached.identity())
            || !attached.identity().same_binding(&self.binding.identity)
        {
            return Err(Error::new(Kind::Refused));
        }
        let observation = attached
            .borrow_gateway_authorization_host_before(self.auth, &gate, gate.deadline().into_std())
            .map_err(host_error)?;
        if !matches!(
            observation.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::ServerSingleUserOwner
        ) || observation.kind() != attached.kind()
            || !issuer.owns_identity(observation.identity())
            || !observation.identity().same_binding(&self.binding.identity)
            || !issuer.observation().is_current()
        {
            return Err(Error::new(Kind::Refused));
        }
        drop(observation);
        gate.check()?;
        Ok(())
    }
    async fn checked<T>(&self, future: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        let gate = self.gate()?;
        let mut future = std::pin::pin!(future);
        let checked = poll_fn(|cx| {
            poll_bookended(|| self.check(), || future.as_mut().poll(cx))
                .map(|result| result.and_then(std::convert::identity))
        });
        tokio::select! {
            biased;
            result = checked => result,
            () = self.binding.flow.original_parent.cancelled() => Err(Error::new(Kind::Cancelled)),
            () = tokio::time::sleep_until(gate.deadline()) => Err(Error::new(Kind::Deadline)),
        }
    }
    async fn io<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>>,
        map: impl FnOnce(E) -> Error,
    ) -> Result<T, Error> {
        self.checked(async { future.await.map_err(map) }).await
    }
    async fn terminal(
        &self,
        gate: &OperationGate<'_>,
        future: impl Future<Output = Result<(), TransactionOwnerError>>,
        commit: bool,
    ) -> Result<Ack, (Error, Ack)> {
        let mut terminal = std::pin::pin!(gate.terminal(future, commit));
        let mut refusal = None;
        let mut polled = false;
        poll_fn(|cx| {
            if let Err(error) = self.check() {
                // Refusal cannot authorize an unpolled COMMIT. Once the original
                // terminal was polled, poll its ACK before a timer on resume.
                if commit && !polled {
                    return Poll::Ready(Err((error, Ack::Unknown)));
                }
                refusal.get_or_insert(error);
            }
            polled = true;
            let result = terminal.as_mut().poll(cx);
            if let Err(error) = self.check() {
                refusal.get_or_insert(error);
            }
            match result {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(original)) => Poll::Ready(Err(original)),
                Poll::Ready(Ok(ack)) => Poll::Ready(match refusal {
                    Some(error) => Err((error, ack)),
                    None => Ok(ack),
                }),
            }
        })
        .await
    }
    async fn readback(&self, expected: &Row) -> Result<(), Error> {
        self.check()?;
        let gate = self.gate()?;
        let observation = self
            .checked(current::borrow_current(self.journal, self.auth, &gate))
            .await?;
        if !observation.identity().same_binding(&self.binding.identity) {
            return Err(Error::new(Kind::Refused));
        }
        let mut client = self
            .io(
                self.journal.pool.get_guarded(gate.deadline().into_std()),
                |_| Error::new(Kind::ReadbackUnproven),
            )
            .await?;
        let tx = self
            .io(client.begin_read_committed_read_only(), |_| {
                Error::new(Kind::ReadbackUnproven)
            })
            .await
            .map_err(|e| e.with_acks(Ack::NotAttempted, Ack::Unknown))?;
        let observation_result = async {
            self.io(
                crate::db::native::validate_gateway_authorization_journal_in_transaction(
                    tx.as_transaction(),
                ),
                authority_sql::native_error,
            )
            .await?;
            let tail = self
                .checked(current::observe_actor(
                    tx.as_transaction(),
                    self.auth,
                    &observation,
                    &gate,
                ))
                .await?;
            let raw = self
                .io(
                    tx.as_transaction()
                        .query_opt(TOKEN_READBACK, &[&expected.attempt_id]),
                    |_| Error::new(Kind::ReadbackUnproven),
                )
                .await?
                .ok_or_else(|| Error::new(Kind::ReadbackUnproven))?;
            let actual = Row::try_from(&raw).map_err(|_| Error::new(Kind::ReadbackUnproven))?;
            if actual != *expected {
                return Err(Error::new(Kind::ReadbackUnproven));
            }
            current::verify_tail(tail.as_ref(), self.auth, &gate)?;
            self.check()?;
            Ok::<_, Error>(tail)
        }
        .await;
        let ack = match self.terminal(&gate, tx.rollback(), false).await {
            Ok(ack) => ack,
            Err((error, ack)) => return Err(error.with_acks(Ack::NotAttempted, ack)),
        };
        drop(client);
        let tail = observation_result.map_err(|e| e.with_acks(Ack::NotAttempted, ack))?;
        current::verify_tail(tail.as_ref(), self.auth, &gate)
            .map_err(|e| e.with_acks(Ack::NotAttempted, ack))?;
        self.check()
            .map_err(|e| e.with_acks(Ack::NotAttempted, ack))?;
        Ok(())
    }
}

async fn write_code(current: &Current<'_>) -> Result<Row, Error> {
    current.check()?;
    let gate = current.gate()?;
    let observation = current
        .checked(current::borrow_current(
            current.journal,
            current.auth,
            &gate,
        ))
        .await?;
    if !observation
        .identity()
        .same_binding(&current.binding.identity)
    {
        return Err(Error::new(Kind::Refused));
    }
    let mut client = current
        .io(
            current.journal.pool.get_guarded(gate.deadline().into_std()),
            |_| Error::new(Kind::Unavailable),
        )
        .await?;
    let tx = current
        .io(client.begin_read_committed(), observation_error)
        .await
        .map_err(|e| e.with_acks(Ack::Unknown, Ack::NotAttempted))?;
    let operation = async {
        current
            .io(
                crate::db::native::validate_gateway_authorization_journal_in_transaction(
                    tx.as_transaction(),
                ),
                authority_sql::native_error,
            )
            .await?;
        let tail = current
            .checked(current::lock_actor(
                tx.as_transaction(),
                current.auth,
                &observation,
                &gate,
            ))
            .await?;
        let locked = current
            .checked(authority_sql::lock_attempt(
                tx.as_transaction(),
                current.binding.expected.attempt_id,
                &gate,
            ))
            .await?;
        if locked != current.binding.expected {
            return Err(Error::new(Kind::Refused));
        }
        let stamp = canonical_microseconds(gate.check()?.wall)?;
        let next = code_admitted_row(&locked, stamp)?;
        current::verify_tail(tail.as_ref(), current.auth, &gate)?;
        current
            .checked(authority_sql::cas_code_admitted(
                tx.as_transaction(),
                &locked,
                &next,
                &gate,
            ))
            .await?;
        current
            .checked(authority_sql::append_code_admitted_audit(
                tx.as_transaction(),
                current.auth,
                &next,
                &current.journal.audit_key,
                &gate,
            ))
            .await?;
        current::verify_tail(tail.as_ref(), current.auth, &gate)?;
        current.check()?;
        Ok::<_, Error>((next, tail))
    }
    .await;
    let (next, tail) = match operation {
        Ok(value) => value,
        Err(error) => {
            return Err(match current.terminal(&gate, tx.rollback(), false).await {
                Ok(ack) => error.with_acks(ack, Ack::NotAttempted),
                Err((terminal, ack)) => terminal.with_acks(ack, Ack::NotAttempted),
            });
        }
    };
    let ack = match current.terminal(&gate, tx.commit(), true).await {
        Ok(ack) => ack,
        Err((error, ack)) => return Err(error.with_acks(ack, Ack::NotAttempted)),
    };
    drop(client);
    current::verify_tail(tail.as_ref(), current.auth, &gate)
        .map_err(|e| e.with_acks(ack, Ack::NotAttempted))?;
    current
        .check()
        .map_err(|e| e.with_acks(ack, Ack::NotAttempted))?;
    Ok(next)
}

struct AcquireControl {
    request: GatewayRequestDescriptor,
    cancel: CancellationToken,
    reply: oneshot::Sender<Result<PermitControl, GatewayFenceError>>,
}
struct PermitControl {
    release: oneshot::Sender<()>,
    ack: oneshot::Receiver<Result<(), GatewayFenceError>>,
}
struct FenceControl {
    acquire: oneshot::Receiver<AcquireControl>,
    call_end: oneshot::Receiver<FenceEnd>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FenceEnd {
    HeadersRelease,
    RequestEnded,
    Cancelled,
    Deadline,
    CallAbandoned,
}
struct FenceResult {
    rollback: Ack,
    end: FenceEnd,
    failure: Option<GatewayFenceError>,
}
impl FenceResult {
    fn idle(end: FenceEnd) -> Self {
        Self {
            rollback: Ack::NotAttempted,
            end,
            failure: None,
        }
    }
}
struct TokenAuthority {
    acquire: Mutex<Option<oneshot::Sender<AcquireControl>>>,
}
impl TokenAuthority {
    fn new(acquire: oneshot::Sender<AcquireControl>) -> Self {
        Self {
            acquire: Mutex::new(Some(acquire)),
        }
    }
}
#[async_trait]
impl GatewayHttpAuthority for TokenAuthority {
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
        if request.kind() != GatewayRequestKind::OAuthToken
            || request.streaming()
            || cancel.is_cancelled()
        {
            return Err(GatewayFenceError::Refused);
        }
        let (reply, receive) = oneshot::channel();
        sender
            .send(AcquireControl {
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
        Ok(Box::new(TokenPermit {
            control: Some(control),
        }))
    }
}
struct TokenPermit {
    control: Option<PermitControl>,
}
#[async_trait]
impl GatewayHttpPermit for TokenPermit {
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
struct EndSignal(Mutex<Option<oneshot::Sender<FenceEnd>>>);
impl EndSignal {
    fn send(&self, end: FenceEnd) {
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
struct EndGuard {
    signal: Arc<EndSignal>,
    armed: bool,
}
impl EndGuard {
    fn finish(mut self, end: FenceEnd) {
        self.armed = false;
        self.signal.send(end);
    }
}
impl Drop for EndGuard {
    fn drop(&mut self) {
        if self.armed {
            self.signal.send(FenceEnd::CallAbandoned);
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
fn gate_end(error: &Error) -> FenceEnd {
    match error.kind {
        Kind::Cancelled => FenceEnd::Cancelled,
        Kind::Deadline => FenceEnd::Deadline,
        _ => FenceEnd::RequestEnded,
    }
}
async fn run_fence(current: &Current<'_>, mut control: FenceControl) -> FenceResult {
    let gate = match current.gate() {
        Ok(gate) => gate,
        Err(error) => {
            return FenceResult {
                rollback: Ack::NotAttempted,
                end: gate_end(&error),
                failure: Some(fence_error(&error)),
            };
        }
    };
    let acquire = current.checked(async {
        tokio::select! {
            biased;
            result = &mut control.call_end => Err(Error::new(match result.unwrap_or(FenceEnd::CallAbandoned) { FenceEnd::Cancelled => Kind::Cancelled, FenceEnd::Deadline => Kind::Deadline, _ => Kind::Refused })),
            result = &mut control.acquire => result.map_err(|_| Error::new(Kind::Refused)),
        }
    }).await;
    let acquire = match acquire {
        Ok(acquire) => acquire,
        Err(error) => return FenceResult::idle(gate_end(&error)),
    };
    if acquire.request.kind() != GatewayRequestKind::OAuthToken
        || acquire.request.streaming()
        || acquire.cancel.is_cancelled()
        || acquire.reply.is_closed()
    {
        let _ = acquire.reply.send(Err(GatewayFenceError::Refused));
        return FenceResult {
            rollback: Ack::NotAttempted,
            end: FenceEnd::RequestEnded,
            failure: Some(GatewayFenceError::Refused),
        };
    }
    let observation = match current
        .checked(current::borrow_current(
            current.journal,
            current.auth,
            &gate,
        ))
        .await
    {
        Ok(observation)
            if observation
                .identity()
                .same_binding(&current.binding.identity) =>
        {
            observation
        }
        Ok(_) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::Refused));
            return FenceResult {
                rollback: Ack::NotAttempted,
                end: FenceEnd::RequestEnded,
                failure: Some(GatewayFenceError::Refused),
            };
        }
        Err(error) => {
            let failure = fence_error(&error);
            let _ = acquire.reply.send(Err(failure));
            return FenceResult {
                rollback: Ack::NotAttempted,
                end: gate_end(&error),
                failure: Some(failure),
            };
        }
    };
    let mut client = match current
        .io(
            current.journal.pool.get_guarded(gate.deadline().into_std()),
            |_| Error::new(Kind::Unavailable),
        )
        .await
    {
        Ok(client) => client,
        Err(error) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::CleanupUnknown));
            return FenceResult {
                rollback: Ack::Unknown,
                end: gate_end(&error),
                failure: Some(GatewayFenceError::CleanupUnknown),
            };
        }
    };
    let tx = match current
        .io(client.begin_read_committed(), observation_error)
        .await
    {
        Ok(tx) => tx,
        Err(error) => {
            let _ = acquire.reply.send(Err(GatewayFenceError::CleanupUnknown));
            return FenceResult {
                rollback: Ack::Unknown,
                end: gate_end(&error),
                failure: Some(GatewayFenceError::CleanupUnknown),
            };
        }
    };
    let validation = async {
        current
            .io(
                crate::db::native::validate_gateway_authorization_journal_in_transaction(
                    tx.as_transaction(),
                ),
                authority_sql::native_error,
            )
            .await?;
        let tail = current
            .checked(current::lock_actor(
                tx.as_transaction(),
                current.auth,
                &observation,
                &gate,
            ))
            .await?;
        let locked = current
            .checked(authority_sql::lock_attempt(
                tx.as_transaction(),
                current.binding.expected.attempt_id,
                &gate,
            ))
            .await?;
        if locked != current.binding.expected
            || locked.phase != "code_admitted"
            || locked.code_admitted_at.is_none()
        {
            return Err(Error::new(Kind::Refused));
        }
        current::verify_tail(tail.as_ref(), current.auth, &gate)?;
        current.check()?;
        Ok::<_, Error>(tail)
    }
    .await;
    let tail = match validation {
        Ok(tail) => tail,
        Err(error) => {
            let (rollback, failure, end) = match current.terminal(&gate, tx.rollback(), false).await
            {
                Ok(ack) => (ack, fence_error(&error), gate_end(&error)),
                Err((terminal, ack)) => (ack, fence_error(&terminal), gate_end(&terminal)),
            };
            let _ = acquire.reply.send(Err(failure));
            return FenceResult {
                rollback,
                end,
                failure: Some(failure),
            };
        }
    };
    let (release, mut release_receive) = oneshot::channel();
    let (ack, ack_receive) = oneshot::channel();
    let _ = acquire.reply.send(Ok(PermitControl {
        release,
        ack: ack_receive,
    }));
    let ended = current.checked(async {
        tokio::select! {
            biased;
            result = &mut release_receive => Ok(if result.is_ok() { FenceEnd::HeadersRelease } else { FenceEnd::CallAbandoned }),
            result = &mut control.call_end => Ok(result.unwrap_or(FenceEnd::CallAbandoned)),
        }
    }).await;
    let end = ended.as_ref().copied().unwrap_or_else(gate_end);
    let before = current::verify_tail(tail.as_ref(), current.auth, &gate);
    let (rollback, terminal_failure) = match current.terminal(&gate, tx.rollback(), false).await {
        Ok(ack) => (ack, None),
        Err((error, ack)) => (ack, Some(fence_error(&error))),
    };
    drop(client);
    let failure = terminal_failure
        .or_else(|| ended.err().map(|e| fence_error(&e)))
        .or_else(|| before.err().map(|e| fence_error(&e)))
        .or_else(|| {
            current::verify_tail(tail.as_ref(), current.auth, &gate)
                .err()
                .map(|e| fence_error(&e))
        })
        .or_else(|| current.check().err().map(|e| fence_error(&e)));
    let released = rollback == Ack::Timely && failure.is_none() && end == FenceEnd::HeadersRelease;
    let _ = ack.send(if released {
        Ok(())
    } else {
        Err(failure.unwrap_or(GatewayFenceError::CleanupUnknown))
    });
    FenceResult {
        rollback,
        end,
        failure,
    }
}
enum ExecuteError {
    Journal(Error),
    Transport(TransportError),
}
async fn execute_once(
    current: &Current<'_>,
    outcomes: &OperationOutcomes,
    transport: &dyn acosmi::HttpTransport,
    request: acosmi::HttpRequest,
    original_parent: CancellationToken,
) -> Result<acosmi::HttpResponse, ExecuteError> {
    let gate = current.gate().map_err(ExecuteError::Journal)?;
    let mut original = std::pin::pin!(transport.execute(request, original_parent));
    let polled = poll_fn(|cx| {
        if let Err(error) = current.check() {
            return Poll::Ready(Err(ExecuteError::Journal(error)));
        }
        outcomes.execute_polled.store(true, Ordering::Release);
        let result = original.as_mut().poll(cx);
        if let Err(error) = current.check() {
            return Poll::Ready(Err(ExecuteError::Journal(error)));
        }
        result.map(|r| r.map_err(ExecuteError::Transport))
    });
    tokio::select! {
        biased;
        result = polled => result,
        () = current.binding.flow.original_parent.cancelled() => Err(ExecuteError::Journal(Error::new(Kind::Cancelled))),
        () = tokio::time::sleep_until(gate.deadline()) => Err(ExecuteError::Journal(Error::new(Kind::Deadline))),
    }
}
fn poll_bookended<T>(
    mut check: impl FnMut() -> Result<(), Error>,
    original: impl FnOnce() -> Poll<T>,
) -> Poll<Result<T, Error>> {
    if let Err(error) = check() {
        return Poll::Ready(Err(error));
    }
    let result = original();
    if let Err(error) = check() {
        return Poll::Ready(Err(error));
    }
    result.map(Ok)
}
fn append_chunk(body: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) -> Result<(), InitialError> {
    let length = body
        .len()
        .checked_add(chunk.len())
        .filter(|n| *n <= BODY_LIMIT)
        .ok_or(InitialError::ProtocolInvalid(ReplyInvalidReason::BodyLimit))?;
    if length > body.capacity() {
        return Err(InitialError::ProtocolInvalid(ReplyInvalidReason::BodyLimit));
    }
    body.extend_from_slice(chunk);
    Ok(())
}
fn token_response_headers(response: &acosmi::HttpResponse) -> Result<(), InitialError> {
    reply::header_limits(response)?;
    if response.status.as_u16() != 200 {
        return Err(InitialError::HttpStatus(response.status.as_u16()));
    }
    reply::success_media_type(response)
}

async fn owned_body(
    current: &Current<'_>,
    response: &mut acosmi::HttpResponse,
) -> Result<Zeroizing<Vec<u8>>, BodyError> {
    let mut body = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    loop {
        let next = current
            .checked(poll_fn(|cx| response.body.as_mut().poll_next(cx).map(Ok)))
            .await
            .map_err(BodyError::Journal)?;
        match next {
            Some(Ok(chunk)) => {
                append_chunk(&mut body, &chunk).map_err(BodyError::Initial)?;
            }
            Some(Err(_)) => return Err(BodyError::Initial(InitialError::BodyTransport)),
            None => return Ok(body),
        }
    }
}
enum BodyError {
    Journal(Error),
    Initial(InitialError),
}

pub(super) async fn dispatch_token(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    owner: GatewayAuthorizationVerifiedCodeOwner,
    factory: &GatewayTransportFactory,
) -> Result<GatewayAuthorizationTokenOwner, TokenError> {
    let outcomes = Arc::new(OperationOutcomes::new());
    let mut history = History::new();
    let TokenCaptureOwner {
        input,
        mut binding,
        reservation,
        capture,
    } = callback::take_verified_for_token(journal, auth, owner)?;
    let capture_current = Current {
        journal,
        auth,
        binding: &binding,
        reservation: &reservation,
        resources: Resources::Capture(&capture),
    };
    let prepared = capture_current
        .checked(async {
            Ok(prepare_initial(
                input,
                retain_parent_budget(binding.flow.original_parent.clone(), binding.flow.cap(None)),
            )
            .await)
        })
        .await
        .map_err(|e| history.journal(Stage::Capture, &e, &outcomes))?
        .map_err(|e| history.error(Stage::Capture, initial_kind(e), &outcomes))?;
    let (request, dispatched) = transfer_code_request(prepared)
        .map_err(|e| history.error(Stage::Capture, initial_kind(e), &outcomes))?;
    {
        let registered = Current {
            journal,
            auth,
            binding: &binding,
            reservation: &reservation,
            resources: Resources::Dispatched(&dispatched, TokenGatePhase::Registered),
        };
        let next = write_code(&registered).await.map_err(|e| {
            history.write = e.write_ack;
            history.journal(Stage::CodeAdmission, &e, &outcomes)
        })?;
        history.write = Ack::Timely;
        registered.readback(&next).await.map_err(|e| {
            // Only this original RO terminal populates readback; the prior code
            // write is retained independently and cannot be overwritten.
            history.readback = e.readback_ack;
            history.journal(Stage::CodeReadback, &e, &outcomes)
        })?;
        history.readback = Ack::Timely;
        registered
            .check()
            .map_err(|e| history.journal(Stage::CodeReadback, &e, &outcomes))?;
        binding.expected = next;
    }
    let current = Current {
        journal,
        auth,
        binding: &binding,
        reservation: &reservation,
        resources: Resources::Dispatched(&dispatched, TokenGatePhase::CodeAdmitted),
    };
    current
        .check()
        .map_err(|e| history.journal(Stage::TokenSend, &e, &outcomes))?;
    let gate = current
        .gate()
        .map_err(|e| history.journal(Stage::TokenSend, &e, &outcomes))?;
    let deadline = gate.deadline();
    let stall = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| history.error(Stage::TokenSend, TokenKind::Deadline, &outcomes))?;
    let (acquire, acquire_receive) = oneshot::channel();
    let (call_end, call_end_receive) = oneshot::channel();
    let transport = factory
        .for_operation(
            Arc::new(TokenAuthority::new(acquire)),
            outcomes.clone(),
            deadline,
            stall,
        )
        .map_err(|_| history.error(Stage::TokenSend, TokenKind::Unavailable, &outcomes))?;
    let end_signal = Arc::new(EndSignal(Mutex::new(Some(call_end))));
    let (response, fence) = {
        let http = async {
            let end = EndGuard {
                signal: end_signal,
                armed: true,
            };
            let response = execute_once(
                &current,
                &outcomes,
                transport.as_ref(),
                request,
                dispatched.budget.original_parent.clone(),
            )
            .await;
            let reason = match &response {
                Err(ExecuteError::Journal(error)) => gate_end(error),
                Err(ExecuteError::Transport(TransportError::Cancelled)) => FenceEnd::Cancelled,
                Err(ExecuteError::Transport(TransportError::Timeout)) => FenceEnd::Deadline,
                _ => FenceEnd::RequestEnded,
            };
            end.finish(reason);
            response
        };
        let runner = run_fence(
            &current,
            FenceControl {
                acquire: acquire_receive,
                call_end: call_end_receive,
            },
        );
        tokio::join!(http, runner)
    };
    history.send = fence.rollback;
    if outcomes.duplicate.load(Ordering::Acquire) {
        return Err(history.error(Stage::TokenSend, outcomes.refused_kind(), &outcomes));
    }
    if fence.rollback == Ack::Late {
        return Err(history.error(
            Stage::TokenSend,
            TokenKind::RollbackAcknowledgedAfterDeadline,
            &outcomes,
        ));
    }
    let mut response = match response {
        Ok(response) => response,
        Err(ExecuteError::Journal(error)) => {
            return Err(history.journal(Stage::TokenSend, &error, &outcomes));
        }
        Err(ExecuteError::Transport(error)) => {
            let kind = if fence.rollback == Ack::Unknown
                && fence.failure == Some(GatewayFenceError::CleanupUnknown)
                && !matches!(fence.end, FenceEnd::Cancelled | FenceEnd::Deadline)
            {
                TokenKind::CleanupUnknown
            } else {
                transport_kind(&error, &outcomes)
            };
            return Err(history.error(Stage::TokenSend, kind, &outcomes));
        }
    };
    if fence.rollback != Ack::Timely || fence.failure.is_some() {
        return Err(history.error(Stage::TokenSend, TokenKind::CleanupUnknown, &outcomes));
    }
    current
        .check()
        .map_err(|e| history.journal(Stage::TokenReply, &e, &outcomes))?;
    token_response_headers(&response)
        .map_err(|e| history.error(Stage::TokenReply, initial_kind(e), &outcomes))?;
    let body = owned_body(&current, &mut response)
        .await
        .map_err(|e| match e {
            BodyError::Journal(error) => history.journal(Stage::TokenReply, &error, &outcomes),
            BodyError::Initial(error) => {
                history.error(Stage::TokenReply, initial_kind(error), &outcomes)
            }
        })?;
    current
        .check()
        .map_err(|e| history.journal(Stage::TokenReply, &e, &outcomes))?;
    let fields = reply::parse_tokens(body.as_slice())
        .map_err(|e| history.error(Stage::TokenReply, initial_kind(e), &outcomes))?;
    let CodeDispatchedInitialOwner {
        witness,
        budget,
        clock,
        sdk_exit_child: _,
        transfer: _,
    } = dispatched;
    let InitialReplyWitness::Code {
        metadata,
        binding: token_binding,
        start,
        code: _,
        redirect_uri: _,
        code_verifier: _,
    } = witness
    else {
        return Err(history.error(Stage::TokenReply, TokenKind::RequestMismatch, &outcomes));
    };
    let tokens = tokens::assemble_tokens(
        fields,
        token_binding,
        start,
        ReplyResources {
            metadata,
            budget,
            clock,
        },
    )
    .map_err(|e| history.error(Stage::TokenReply, initial_kind(e), &outcomes))?;
    let owner = GatewayAuthorizationTokenOwner {
        tokens,
        binding,
        reservation,
    };
    let final_current = Current {
        journal,
        auth,
        binding: &owner.binding,
        reservation: &owner.reservation,
        resources: Resources::Tokens(&owner.tokens),
    };
    final_current
        .check()
        .map_err(|e| history.journal(Stage::FinalHandoff, &e, &outcomes))?;
    final_current
        .gate()
        .and_then(|g| g.check())
        .map_err(|e| history.journal(Stage::FinalHandoff, &e, &outcomes))?;
    Ok(owner)
}
