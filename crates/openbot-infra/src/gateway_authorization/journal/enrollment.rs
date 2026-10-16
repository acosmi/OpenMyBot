//! Consume the one original token owner into a bounded, same-ID R367 adoption.
//! All authorization/SQL owners stay borrowed in this scope; SDK Arcs carry only oneshots.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use openbot_contracts::auth::AuthContext;
use openbot_contracts::request_binding::{
    GatewayAuthorizationHostTailWitness, HostRequestBindingKind,
};
use openbot_domain::vault::SecretBytes;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    Ack, Error as JournalError, GatewayAuthorizationJournal, GatewayAuthorizationTokenOwner,
    Kind as JournalKind, OperationGate, Row, authority_sql, current, host_error,
};
use crate::db::pool::{GuardedClient, GuardedTransaction, PoolError, TransactionOwnerError};
use crate::gateway_account::{
    EnrollmentAccountReadError, GatewayAccountError, GatewayDesktopMetadata,
};
use crate::gateway_authority::{
    EnrollmentFenceControl, EnrollmentFenceEnd, EnrollmentPermitControl, EnrollmentRequestKind,
    GatewayAuthorityError, GatewayConnectionReceipt, PostgresGatewayAccounts,
    enrollment_headers_channel,
};
use crate::gateway_transport::{GatewayFenceError, GatewayHttpOutcomes, GatewayRequestKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationEnrollmentStage {
    Entry,
    Metadata,
    Profile,
    Write,
    Readback,
    FinalHandoff,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationEnrollmentAccountReason {
    Configuration,
    ContentType,
    BodyTooLarge,
    Body,
    MetadataInvalid,
    ProfileInvalid,
    LegacyProtocol,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationEnrollmentKind {
    BeforeAdoptionRefused,
    InvalidInput,
    Unavailable,
    Cancelled,
    Deadline,
    HttpStatus(u16),
    AccountProtocol(GatewayAuthorizationEnrollmentAccountReason),
    Conflict,
    Corrupt,
    CleanupUnknown,
    ClosureUnknown,
    CommitUnknown,
    CommitAcknowledgedAfterDeadline,
    ReadbackUnproven,
    RollbackAcknowledgedAfterDeadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationEnrollmentWriteTerminal {
    NotAttempted,
    Commit(Ack),
    Rollback(Ack),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationEnrollmentCleanupState {
    NotNeeded,
    OriginalResourcesDestroyed,
    Unknown,
}

type Stage = GatewayAuthorizationEnrollmentStage;
type Kind = GatewayAuthorizationEnrollmentKind;
type Reason = GatewayAuthorizationEnrollmentAccountReason;
type WriteTerminal = GatewayAuthorizationEnrollmentWriteTerminal;
type Cleanup = GatewayAuthorizationEnrollmentCleanupState;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GatewayAuthorizationEnrollmentError {
    stage: Stage,
    kind: Kind,
    reserved_connection_id: Option<Uuid>,
    metadata_headers_rollback_ack: Ack,
    profile_headers_rollback_ack: Ack,
    adoption_write_terminal: WriteTerminal,
    adoption_readback_rollback_ack: Ack,
    cleanup_state: Cleanup,
}
impl GatewayAuthorizationEnrollmentError {
    pub const fn stage(&self) -> Stage {
        self.stage
    }
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    pub const fn reserved_connection_id(&self) -> Option<Uuid> {
        self.reserved_connection_id
    }
    pub const fn metadata_headers_rollback_ack(&self) -> Ack {
        self.metadata_headers_rollback_ack
    }
    pub const fn profile_headers_rollback_ack(&self) -> Ack {
        self.profile_headers_rollback_ack
    }
    pub const fn adoption_write_terminal(&self) -> WriteTerminal {
        self.adoption_write_terminal
    }
    pub const fn adoption_readback_rollback_ack(&self) -> Ack {
        self.adoption_readback_rollback_ack
    }
    pub const fn cleanup_state(&self) -> Cleanup {
        self.cleanup_state
    }
}
impl fmt::Debug for GatewayAuthorizationEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAuthorizationEnrollmentError([redacted])")
    }
}
impl fmt::Display for GatewayAuthorizationEnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway_authorization_enrollment_failed")
    }
}
impl std::error::Error for GatewayAuthorizationEnrollmentError {}

#[derive(Clone, Copy)]
struct Facts {
    id: Option<Uuid>,
    metadata: Ack,
    profile: Ack,
    write: WriteTerminal,
    readback: Ack,
    cleanup: Cleanup,
}
impl Facts {
    fn new() -> Self {
        Self {
            id: None,
            metadata: Ack::NotAttempted,
            profile: Ack::NotAttempted,
            write: WriteTerminal::NotAttempted,
            readback: Ack::NotAttempted,
            cleanup: Cleanup::NotNeeded,
        }
    }
    fn observe(&mut self, next: Cleanup) {
        self.cleanup = match (self.cleanup, next) {
            (Cleanup::Unknown, _) | (_, Cleanup::Unknown) => Cleanup::Unknown,
            (Cleanup::OriginalResourcesDestroyed, _) | (_, Cleanup::OriginalResourcesDestroyed) => {
                Cleanup::OriginalResourcesDestroyed
            }
            _ => Cleanup::NotNeeded,
        };
    }
    fn error(self, stage: Stage, kind: Kind) -> GatewayAuthorizationEnrollmentError {
        GatewayAuthorizationEnrollmentError {
            stage,
            kind,
            reserved_connection_id: self.id,
            metadata_headers_rollback_ack: self.metadata,
            profile_headers_rollback_ack: self.profile,
            adoption_write_terminal: self.write,
            adoption_readback_rollback_ack: self.readback,
            cleanup_state: self.cleanup,
        }
    }
}

/// Only this module constructs this live borrow. No independent grant can escape it.
pub(crate) struct EnrollmentCurrent<'a> {
    journal: &'a Arc<GatewayAuthorizationJournal>,
    auth: &'a AuthContext,
    owner: &'a GatewayAuthorizationTokenOwner,
}
impl<'a> EnrollmentCurrent<'a> {
    fn new(
        journal: &'a Arc<GatewayAuthorizationJournal>,
        auth: &'a AuthContext,
        owner: &'a GatewayAuthorizationTokenOwner,
    ) -> Result<Self, JournalError> {
        let current = Self {
            journal,
            auth,
            owner,
        };
        current.check()?;
        Ok(current)
    }
    fn gate(&self) -> Result<OperationGate<'a>, JournalError> {
        self.journal.token_owner_gate(
            self.auth,
            &self.owner.binding,
            &self.owner.reservation,
            &self.owner.tokens,
        )
    }
    pub(crate) fn check(&self) -> Result<(), JournalError> {
        let gate = self.gate()?;
        let issuer = self
            .journal
            .issuer
            .get()
            .ok_or_else(|| JournalError::new(JournalKind::Unavailable))?;
        let attached = self
            .auth
            .request_binding()
            .ok_or_else(|| JournalError::new(JournalKind::Refused))?;
        if !issuer.observation().is_current()
            || !issuer.owns_identity(attached.identity())
            || !attached
                .identity()
                .same_binding(&self.owner.binding.identity)
        {
            return Err(JournalError::new(JournalKind::Refused));
        }
        let observation = attached
            .borrow_gateway_authorization_host_before(self.auth, &gate, gate.deadline().into_std())
            .map_err(host_error)?;
        if !matches!(
            observation.kind(),
            HostRequestBindingKind::ServerSession | HostRequestBindingKind::ServerSingleUserOwner
        ) || observation.kind() != attached.kind()
            || !issuer.owns_identity(observation.identity())
            || !observation
                .identity()
                .same_binding(&self.owner.binding.identity)
            || !issuer.observation().is_current()
        {
            return Err(JournalError::new(JournalKind::Refused));
        }
        drop(observation);
        gate.check()?;
        Ok(())
    }
    pub(crate) fn deadline(&self) -> Result<Instant, JournalError> {
        Ok(self.gate()?.deadline())
    }
    pub(crate) fn original_parent(&self) -> &CancellationToken {
        &self.owner.binding.flow.original_parent
    }
    pub(crate) fn check_adoption_inputs(
        &self,
        auth: &AuthContext,
        id: Uuid,
        tokens: &acosmi::TokenSet,
    ) -> Result<(), JournalError> {
        if !std::ptr::eq(self.auth, auth)
            || id != self.owner.reservation.id
            || !std::ptr::eq(tokens, &self.owner.tokens.sdk)
        {
            return Err(JournalError::new(JournalKind::Refused));
        }
        self.check()
    }
    async fn checked<T>(
        &self,
        future: impl Future<Output = Result<T, Kind>>,
        cap: Instant,
    ) -> Result<T, Kind> {
        let mut future = std::pin::pin!(future);
        let checked = poll_fn(|cx| {
            if let Err(error) = self.check() {
                return Poll::Ready(Err(map_journal(error, false)));
            }
            if Instant::now() >= cap {
                return Poll::Ready(Err(Kind::Deadline));
            }
            let result = future.as_mut().poll(cx);
            if let Err(error) = self.check() {
                return Poll::Ready(Err(map_journal(error, false)));
            }
            if Instant::now() >= cap {
                return Poll::Ready(Err(Kind::Deadline));
            }
            result
        });
        tokio::select! {
            biased;
            result = checked => result,
            () = self.original_parent().cancelled() => Err(Kind::Cancelled),
            () = tokio::time::sleep_until(cap) => Err(Kind::Deadline),
        }
    }
    async fn io<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>>,
        map: impl FnOnce(E) -> Kind,
        cap: Instant,
    ) -> Result<T, Kind> {
        self.checked(async { future.await.map_err(map) }, cap).await
    }
    async fn pg<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>>,
        map: impl FnOnce(E) -> Kind,
    ) -> Result<T, Kind> {
        let cap = child_cap(
            self.deadline().map_err(|e| map_journal(e, false))?,
            Duration::from_secs(5),
        );
        self.io(future, map, cap).await
    }
    // This directly polls the original cap-only owner future before any later check/timer.
    async fn terminal(
        &self,
        tx: GuardedTransaction<'_>,
        action: Action,
        cap: Instant,
        readback: bool,
    ) -> Terminal {
        let original = async move {
            match action {
                Action::Commit => tx.commit_before(cap.into_std()).await,
                Action::Rollback => tx.rollback_before(cap.into_std()).await,
            }
        };
        let mut original = std::pin::pin!(original);
        let mut attempted = false;
        let mut refusal = None;
        poll_fn(|cx| {
            if let Err(error) = self.check() {
                let failure = map_journal(error, readback);
                if action == Action::Commit && !attempted {
                    return Poll::Ready(Terminal {
                        ack: Ack::NotAttempted,
                        failure: Some(failure),
                    });
                }
                refusal.get_or_insert(failure);
            }
            let result = original.as_mut().poll(cx);
            // Capture original result before the postcheck can discard or mask an ACK.
            let captured = match result {
                Poll::Pending => {
                    attempted = true;
                    None
                }
                Poll::Ready(result) => Some(match result {
                    Ok(()) => Terminal {
                        ack: Ack::Timely,
                        failure: None,
                    },
                    Err(TransactionOwnerError::DeadlineExceeded) if !attempted => Terminal {
                        ack: Ack::NotAttempted,
                        failure: Some(Kind::Deadline),
                    },
                    Err(TransactionOwnerError::CommitAcknowledgedAfterDeadline) => Terminal {
                        ack: Ack::Late,
                        failure: Some(Kind::CommitAcknowledgedAfterDeadline),
                    },
                    Err(TransactionOwnerError::RollbackAcknowledgedAfterDeadline) => Terminal {
                        ack: Ack::Late,
                        failure: Some(Kind::RollbackAcknowledgedAfterDeadline),
                    },
                    Err(error) => Terminal {
                        ack: Ack::Unknown,
                        failure: Some(map_terminal(error, readback)),
                    },
                }),
            };
            if let Err(error) = self.check() {
                refusal.get_or_insert(map_journal(error, readback));
            }
            match captured {
                None => Poll::Pending,
                Some(mut result) => {
                    if result.failure.is_none() {
                        result.failure = refusal;
                    }
                    Poll::Ready(result)
                }
            }
        })
        .await
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Commit,
    Rollback,
}
struct Terminal {
    ack: Ack,
    failure: Option<Kind>,
}
fn write_fact(action: Action, ack: Ack) -> WriteTerminal {
    match (action, ack) {
        (_, Ack::NotAttempted) => WriteTerminal::NotAttempted,
        (Action::Commit, ack) => WriteTerminal::Commit(ack),
        (Action::Rollback, ack) => WriteTerminal::Rollback(ack),
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 100
}
fn child_cap(original: Instant, duration: Duration) -> Instant {
    original.min(Instant::now() + duration)
}
fn map_journal(error: JournalError, readback: bool) -> Kind {
    match error.kind() {
        JournalKind::Refused => Kind::BeforeAdoptionRefused,
        JournalKind::Cancelled => Kind::Cancelled,
        JournalKind::Deadline => Kind::Deadline,
        JournalKind::CommitUnknown => Kind::CommitUnknown,
        JournalKind::CommitAcknowledgedAfterDeadline => Kind::CommitAcknowledgedAfterDeadline,
        JournalKind::RollbackAcknowledgedAfterDeadline => Kind::RollbackAcknowledgedAfterDeadline,
        JournalKind::RollbackUnproven => {
            if readback {
                Kind::ReadbackUnproven
            } else {
                Kind::CleanupUnknown
            }
        }
        JournalKind::ReadbackUnproven => Kind::ReadbackUnproven,
        JournalKind::Unavailable
        | JournalKind::LedgerInvalid
        | JournalKind::SchemaInvalid
        | JournalKind::ObservationUnknown => Kind::Unavailable,
    }
}
fn map_terminal(error: TransactionOwnerError, readback: bool) -> Kind {
    match error {
        TransactionOwnerError::AlreadyStarted => Kind::Corrupt,
        TransactionOwnerError::BeginUnavailable => Kind::Unavailable,
        TransactionOwnerError::DeadlineExceeded => Kind::Deadline,
        TransactionOwnerError::CommitUnknown => Kind::CommitUnknown,
        TransactionOwnerError::RollbackUnproven => {
            if readback {
                Kind::ReadbackUnproven
            } else {
                Kind::CleanupUnknown
            }
        }
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            Kind::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            Kind::RollbackAcknowledgedAfterDeadline
        }
    }
}
fn map_pool(error: PoolError) -> Kind {
    match error {
        PoolError::Unavailable | PoolError::Closed => Kind::Unavailable,
        PoolError::OwnershipUnavailable
        | PoolError::IdentityCollision
        | PoolError::CreationLimit => Kind::Corrupt,
        PoolError::DeadlineExceeded => Kind::Deadline,
        PoolError::ObservationUnavailable => Kind::ClosureUnknown,
    }
}
fn map_authority(error: GatewayAuthorityError) -> Kind {
    match error {
        GatewayAuthorityError::InvalidInput => Kind::InvalidInput,
        GatewayAuthorityError::NotVisible => Kind::BeforeAdoptionRefused,
        GatewayAuthorityError::Conflict => Kind::Conflict,
        GatewayAuthorityError::Corrupt => Kind::Corrupt,
        GatewayAuthorityError::Unavailable => Kind::Unavailable,
        GatewayAuthorityError::Cancelled => Kind::Cancelled,
        GatewayAuthorityError::Timeout => Kind::Deadline,
        GatewayAuthorityError::CommitUnknown => Kind::CommitUnknown,
        GatewayAuthorityError::ReconciliationRequired => Kind::CleanupUnknown,
        GatewayAuthorityError::AccountProtocol => Kind::AccountProtocol(Reason::LegacyProtocol),
    }
}
fn map_account(error: EnrollmentAccountReadError) -> Kind {
    match error {
        EnrollmentAccountReadError::Current(error) => map_journal(error, false),
        EnrollmentAccountReadError::Account(error) => match error {
            GatewayAccountError::Configuration => Kind::AccountProtocol(Reason::Configuration),
            GatewayAccountError::Cancelled => Kind::Cancelled,
            GatewayAccountError::Timeout => Kind::Deadline,
            GatewayAccountError::Transport => Kind::Unavailable,
            GatewayAccountError::HttpStatus(status) => Kind::HttpStatus(status),
            GatewayAccountError::ContentType => Kind::AccountProtocol(Reason::ContentType),
            GatewayAccountError::BodyTooLarge => Kind::AccountProtocol(Reason::BodyTooLarge),
            GatewayAccountError::Body => Kind::AccountProtocol(Reason::Body),
            GatewayAccountError::MetadataInvalid => Kind::AccountProtocol(Reason::MetadataInvalid),
            GatewayAccountError::ProfileInvalid => Kind::AccountProtocol(Reason::ProfileInvalid),
        },
    }
}
fn fence_failure(kind: Kind) -> GatewayFenceError {
    match kind {
        Kind::Unavailable => GatewayFenceError::Unavailable,
        Kind::CleanupUnknown
        | Kind::ClosureUnknown
        | Kind::CommitUnknown
        | Kind::ReadbackUnproven
        | Kind::CommitAcknowledgedAfterDeadline
        | Kind::RollbackAcknowledgedAfterDeadline => GatewayFenceError::CleanupUnknown,
        _ => GatewayFenceError::Refused,
    }
}
fn end_for(kind: Option<Kind>) -> EnrollmentFenceEnd {
    match kind {
        Some(Kind::Cancelled) => EnrollmentFenceEnd::Cancelled,
        Some(Kind::Deadline) => EnrollmentFenceEnd::Deadline,
        _ => EnrollmentFenceEnd::RequestEnded,
    }
}

// The same acquisition cap covers permit, checkout and fixed session SET batch.
async fn checkout(
    current: &EnrollmentCurrent<'_>,
    accounts: &PostgresGatewayAccounts,
) -> Result<GuardedClient, (Kind, Cleanup)> {
    let original = current
        .deadline()
        .map_err(|e| (map_journal(e, false), Cleanup::NotNeeded))?;
    let acquisition = child_cap(original, Duration::from_secs(5));
    let permit = current
        .io(
            accounts.enrollment_session_permit(current, acquisition),
            map_authority,
            acquisition,
        )
        .await
        .map_err(|e| (e, Cleanup::NotNeeded))?;
    let mut polled = false;
    let result = {
        let get = current
            .journal
            .pool
            .get_guarded_with_session_permit(original.into_std(), permit);
        let mut get = std::pin::pin!(get);
        let tracked = poll_fn(|cx| {
            polled = true;
            get.as_mut().poll(cx)
        });
        current.io(tracked, map_pool, acquisition).await
    };
    let client = result.map_err(|e| {
        (
            e,
            if polled {
                Cleanup::Unknown
            } else {
                Cleanup::NotNeeded
            },
        )
    })?;
    let settings = current.io(client.as_client().batch_execute(
        "SET statement_timeout='5000ms';SET lock_timeout='5000ms';SET idle_in_transaction_session_timeout='15000ms'"),
        |_| Kind::Unavailable, acquisition).await;
    if let Err(error) = settings {
        let cleanup = retire(client, child_cap(original, Duration::from_secs(1))).await;
        return Err((error, cleanup));
    }
    Ok(client)
}
async fn retire(client: GuardedClient, cap: Instant) -> Cleanup {
    let original = client.retire_original();
    if original
        .wait_for_destruction_before(cap.into_std())
        .await
        .is_ok()
    {
        Cleanup::OriginalResourcesDestroyed
    } else {
        Cleanup::Unknown
    }
}
fn close_result<T>(result: Result<T, Kind>, cleanup: Cleanup) -> Result<T, Kind> {
    match result {
        Err(error) => Err(error),
        Ok(_) if cleanup != Cleanup::OriginalResourcesDestroyed => Err(Kind::ClosureUnknown),
        Ok(value) => Ok(value),
    }
}

// Observe the first poll of the original BEGIN, not just its outer checked wrapper.
// A returned Err may have dropped an inner Ok transaction during the current postcheck.
async fn begin_tracked<'a>(
    current: &EnrollmentCurrent<'_>,
    client: &'a mut GuardedClient,
    read_only: bool,
    begin_unknown: &mut bool,
) -> Result<GuardedTransaction<'a>, Kind> {
    let mut original_polled = false;
    let result = {
        let original = async move {
            if read_only {
                client.begin_read_committed_read_only().await
            } else {
                client.begin_read_committed().await
            }
        };
        let mut original = std::pin::pin!(original);
        let tracked = poll_fn(|cx| {
            original_polled = true;
            original.as_mut().poll(cx)
        });
        current
            .pg(tracked, |error| map_terminal(error, read_only))
            .await
    };
    if result.is_err() && original_polled {
        *begin_unknown = true;
    }
    result
}

// Consume the original pre-permit reply exactly once. A closed/cancelled reader
// cannot have its typed reason replaced by this later runner failure.
fn send_header_failure(
    reply: &mut Option<
        tokio::sync::oneshot::Sender<Result<EnrollmentPermitControl, GatewayFenceError>>,
    >,
    reader_cancel: &CancellationToken,
    failure: Kind,
) -> bool {
    let Some(sender) = reply.take() else {
        return false;
    };
    if reader_cancel.is_cancelled() {
        drop(sender);
        return false;
    }
    let delivered = sender.send(Err(fence_failure(failure))).is_ok();
    delivered && !reader_cancel.is_cancelled()
}

struct HeaderResult {
    ack: Ack,
    cleanup: Cleanup,
    failure: Option<Kind>,
    caused_reader: bool,
}
impl HeaderResult {
    fn idle() -> Self {
        Self {
            ack: Ack::NotAttempted,
            cleanup: Cleanup::NotNeeded,
            failure: None,
            caused_reader: false,
        }
    }
}
async fn run_headers(
    current: &EnrollmentCurrent<'_>,
    kind: EnrollmentRequestKind,
    mut control: EnrollmentFenceControl,
    accounts: &PostgresGatewayAccounts,
) -> HeaderResult {
    let original = match current.deadline() {
        Ok(cap) => cap,
        Err(error) => {
            return HeaderResult {
                failure: Some(map_journal(error, false)),
                ..HeaderResult::idle()
            };
        }
    };
    let acquire = current.checked(async {
        tokio::select! { biased;
            _ = &mut control.call_end => Err(Kind::BeforeAdoptionRefused),
            result = &mut control.acquire => result.map_err(|_| Kind::BeforeAdoptionRefused),
        }
    }, original).await;
    let acquire = match acquire {
        Ok(value) => value,
        Err(error) => {
            return HeaderResult {
                failure: Some(error),
                ..HeaderResult::idle()
            };
        }
    };
    let expected = match kind {
        EnrollmentRequestKind::Metadata => GatewayRequestKind::OAuthDiscovery,
        EnrollmentRequestKind::Profile => GatewayRequestKind::AccountProfile,
    };
    let request = acquire.request;
    let reader_cancel = acquire.cancel;
    let mut reply = Some(acquire.reply);
    if request.kind() != expected
        || request.streaming()
        || reader_cancel.is_cancelled()
        || reply
            .as_ref()
            .is_none_or(tokio::sync::oneshot::Sender::is_closed)
    {
        let caused_reader =
            send_header_failure(&mut reply, &reader_cancel, Kind::BeforeAdoptionRefused);
        return HeaderResult {
            failure: Some(Kind::BeforeAdoptionRefused),
            caused_reader,
            ..HeaderResult::idle()
        };
    }
    let mut client = match checkout(current, accounts).await {
        Ok(client) => client,
        Err((failure, cleanup)) => {
            let caused_reader = send_header_failure(&mut reply, &reader_cancel, failure);
            return HeaderResult {
                ack: Ack::NotAttempted,
                cleanup,
                failure: Some(failure),
                caused_reader,
            };
        }
    };
    let mut ack = Ack::NotAttempted;
    let mut cleanup_cap = None;
    let mut begin_unknown = false;
    let mut caused_reader = false;
    let result = async {
        let gate = current.gate().map_err(|e| map_journal(e, false))?;
        let observation = current.pg(current::borrow_current(current.journal, current.auth, &gate), |e| map_journal(e, false)).await?;
        let tx = begin_tracked(current, &mut client, false, &mut begin_unknown).await?;
        let validation = async {
            validate_attempt(current, &gate, &tx, &observation, false).await
        }.await;
        let tail = match validation {
            Ok(tail) => tail,
            Err(error) => {
                let cap = child_cap(original, Duration::from_secs(1)); cleanup_cap = Some(cap);
                let terminal = current.terminal(tx, Action::Rollback, cap, false).await;
                ack = terminal.ack; return Err(error);
            }
        };
        let (release, mut receive_release) = tokio::sync::oneshot::channel();
        let (send_ack, receive_ack) = tokio::sync::oneshot::channel();
        let delivered = reply.take().is_some_and(|sender| sender.send(Ok(EnrollmentPermitControl { release, ack: receive_ack })).is_ok());
        let ended = current.checked(async {
            tokio::select! { biased;
                result = &mut receive_release => Ok(if result.is_ok() { EnrollmentFenceEnd::HeadersRelease } else { EnrollmentFenceEnd::CallAbandoned }),
                result = &mut control.call_end => Ok(result.unwrap_or(EnrollmentFenceEnd::CallAbandoned)),
            }
        }, original).await;
        let end = ended.as_ref().copied().unwrap_or_else(|e| end_for(Some(*e)));
        caused_reader = delivered && end == EnrollmentFenceEnd::HeadersRelease;
        let before = current::verify_tail(tail.as_ref(), current.auth, &gate).map_err(|e| map_journal(e, false));
        let cap = if ended.is_err() || end != EnrollmentFenceEnd::HeadersRelease || before.is_err() {
            let cap = child_cap(original, Duration::from_secs(1)); cleanup_cap = Some(cap); cap
        } else { child_cap(original, Duration::from_secs(5)) };
        let terminal = current.terminal(tx, Action::Rollback, cap, false).await;
        ack = terminal.ack;
        let failure = ended.err().or_else(|| before.err()).or(terminal.failure)
            .or_else(|| current::verify_tail(tail.as_ref(), current.auth, &gate).err().map(|e| map_journal(e, false)))
            .or_else(|| current.check().err().map(|e| map_journal(e, false)));
        // Actual lease destruction is also required before releasing the SDK headers permit.
        Ok::<_, Kind>((send_ack, end, failure))
    }.await;
    let cleanup = retire(
        client,
        cleanup_cap.unwrap_or_else(|| child_cap(original, Duration::from_secs(1))),
    )
    .await;
    let cleanup = if begin_unknown {
        Cleanup::Unknown
    } else {
        cleanup
    };
    let failure = match result {
        Err(error) => {
            caused_reader = send_header_failure(&mut reply, &reader_cancel, error);
            Some(error)
        }
        Ok((send_ack, end, failure)) => {
            let failure = failure.or_else(|| {
                if cleanup != Cleanup::OriginalResourcesDestroyed {
                    Some(Kind::ClosureUnknown)
                } else {
                    None
                }
            });
            let released = ack == Ack::Timely
                && failure.is_none()
                && end == EnrollmentFenceEnd::HeadersRelease;
            let _ = send_ack.send(if released {
                Ok(())
            } else {
                Err(fence_failure(failure.unwrap_or(Kind::CleanupUnknown)))
            });
            failure.or_else(|| {
                if released {
                    None
                } else {
                    Some(Kind::BeforeAdoptionRefused)
                }
            })
        }
    };
    // A failure before PermitControl delivery must close its original reply channel.
    HeaderResult {
        ack,
        cleanup,
        failure,
        caused_reader,
    }
}

const ATTEMPT_READBACK: &str = "SELECT attempt_id,journal_schema,deployment_id,tenant_id,owner_user_id,auth_generation,installation_id,runtime_epoch,issuer,redirect_uri,phase,client_id,enrollment_id,registration_admitted_at,code_admitted_at,created_at,expires_at,updated_at,finished_at,outcome_code FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1";
async fn validate_attempt(
    current: &EnrollmentCurrent<'_>,
    gate: &OperationGate<'_>,
    tx: &GuardedTransaction<'_>,
    observation: &openbot_contracts::request_binding::GatewayAuthorizationHostObservation<'_>,
    read_only: bool,
) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, Kind> {
    current
        .pg(
            crate::db::native::validate_gateway_authorization_journal_in_transaction(
                tx.as_transaction(),
            ),
            |e| map_journal(authority_sql::native_error(e), read_only),
        )
        .await?;
    let tail = if read_only {
        current
            .pg(
                current::observe_actor(tx.as_transaction(), current.auth, observation, gate),
                |e| map_journal(e, true),
            )
            .await?
    } else {
        current
            .pg(
                current::lock_actor(tx.as_transaction(), current.auth, observation, gate),
                |e| map_journal(e, false),
            )
            .await?
    };
    let actual = if read_only {
        let raw = current
            .pg(
                tx.as_transaction().query_opt(
                    ATTEMPT_READBACK,
                    &[&current.owner.binding.expected.attempt_id],
                ),
                |_| Kind::ReadbackUnproven,
            )
            .await?
            .ok_or(Kind::ReadbackUnproven)?;
        Row::try_from(&raw).map_err(|_| Kind::ReadbackUnproven)?
    } else {
        current
            .pg(
                authority_sql::lock_attempt(
                    tx.as_transaction(),
                    current.owner.binding.expected.attempt_id,
                    gate,
                ),
                |e| map_journal(e, false),
            )
            .await?
    };
    if actual != current.owner.binding.expected
        || actual.phase != "code_admitted"
        || actual.code_admitted_at.is_none()
        || !observation
            .identity()
            .same_binding(&current.owner.binding.identity)
    {
        return Err(Kind::BeforeAdoptionRefused);
    }
    current::verify_tail(tail.as_ref(), current.auth, gate)
        .map_err(|e| map_journal(e, read_only))?;
    current.check().map_err(|e| map_journal(e, read_only))?;
    Ok(tail)
}

async fn write_adoption(
    current: &EnrollmentCurrent<'_>,
    accounts: &PostgresGatewayAccounts,
    adoption: &crate::gateway_authority::EnrollmentAdoption<'_>,
) -> (Result<Uuid, Kind>, WriteTerminal, Cleanup) {
    let original = match current.deadline() {
        Ok(cap) => cap,
        Err(e) => {
            return (
                Err(map_journal(e, false)),
                WriteTerminal::NotAttempted,
                Cleanup::NotNeeded,
            );
        }
    };
    let mut client = match checkout(current, accounts).await {
        Ok(client) => client,
        Err((error, cleanup)) => return (Err(error), WriteTerminal::NotAttempted, cleanup),
    };
    let mut write = WriteTerminal::NotAttempted;
    let mut cleanup_cap = None;
    let mut begin_unknown = false;
    let result = async {
        let gate = current.gate().map_err(|e| map_journal(e, false))?;
        let observation = current
            .pg(
                current::borrow_current(current.journal, current.auth, &gate),
                |e| map_journal(e, false),
            )
            .await?;
        let tx = begin_tracked(current, &mut client, false, &mut begin_unknown).await?;
        let operation = async {
            let tail = validate_attempt(current, &gate, &tx, &observation, false).await?;
            let secret = current
                .io(
                    adoption.insert(tx.as_transaction()),
                    map_authority,
                    original,
                )
                .await?;
            current::verify_tail(tail.as_ref(), current.auth, &gate)
                .map_err(|e| map_journal(e, false))?;
            current.check().map_err(|e| map_journal(e, false))?;
            Ok::<_, Kind>((secret, tail))
        }
        .await;
        let (secret, tail) = match operation {
            Ok(value) => value,
            Err(error) => {
                let cap = child_cap(original, Duration::from_secs(1));
                cleanup_cap = Some(cap);
                let terminal = current.terminal(tx, Action::Rollback, cap, false).await;
                write = write_fact(Action::Rollback, terminal.ack);
                return Err(error);
            }
        };
        let terminal = current
            .terminal(
                tx,
                Action::Commit,
                child_cap(original, Duration::from_secs(5)),
                false,
            )
            .await;
        write = write_fact(Action::Commit, terminal.ack);
        if let Some(error) = terminal.failure {
            return Err(error);
        }
        current::verify_tail(tail.as_ref(), current.auth, &gate)
            .map_err(|e| map_journal(e, false))?;
        current.check().map_err(|e| map_journal(e, false))?;
        Ok(secret)
    }
    .await;
    let cleanup = retire(
        client,
        cleanup_cap.unwrap_or_else(|| child_cap(original, Duration::from_secs(1))),
    )
    .await;
    let cleanup = if begin_unknown {
        Cleanup::Unknown
    } else {
        cleanup
    };
    (close_result(result, cleanup), write, cleanup)
}
async fn read_adoption(
    current: &EnrollmentCurrent<'_>,
    accounts: &PostgresGatewayAccounts,
    adoption: &crate::gateway_authority::EnrollmentAdoption<'_>,
    secret: Uuid,
) -> (Result<(), Kind>, Ack, Cleanup) {
    let original = match current.deadline() {
        Ok(cap) => cap,
        Err(e) => {
            return (
                Err(map_journal(e, true)),
                Ack::NotAttempted,
                Cleanup::NotNeeded,
            );
        }
    };
    let mut client = match checkout(current, accounts).await {
        Ok(client) => client,
        Err((error, cleanup)) => return (Err(error), Ack::NotAttempted, cleanup),
    };
    let mut ack = Ack::NotAttempted;
    let mut cleanup_cap = None;
    let mut begin_unknown = false;
    let result = async {
        let gate = current.gate().map_err(|e| map_journal(e, true))?;
        let observation = current
            .pg(
                current::borrow_current(current.journal, current.auth, &gate),
                |e| map_journal(e, true),
            )
            .await?;
        let tx = begin_tracked(current, &mut client, true, &mut begin_unknown).await?;
        let operation = async {
            let tail = validate_attempt(current, &gate, &tx, &observation, true).await?;
            current
                .io(
                    adoption.readback(tx.as_transaction(), secret),
                    map_authority,
                    original,
                )
                .await?;
            current::verify_tail(tail.as_ref(), current.auth, &gate)
                .map_err(|e| map_journal(e, true))?;
            current.check().map_err(|e| map_journal(e, true))?;
            Ok::<_, Kind>(tail)
        }
        .await;
        let cap = if operation.is_err() {
            let cap = child_cap(original, Duration::from_secs(1));
            cleanup_cap = Some(cap);
            cap
        } else {
            child_cap(original, Duration::from_secs(5))
        };
        let terminal = current.terminal(tx, Action::Rollback, cap, true).await;
        ack = terminal.ack;
        let tail = operation?;
        if let Some(error) = terminal.failure {
            return Err(error);
        }
        current::verify_tail(tail.as_ref(), current.auth, &gate)
            .map_err(|e| map_journal(e, true))?;
        current.check().map_err(|e| map_journal(e, true))?;
        Ok(())
    }
    .await;
    let cleanup = retire(
        client,
        cleanup_cap.unwrap_or_else(|| child_cap(original, Duration::from_secs(1))),
    )
    .await;
    let cleanup = if begin_unknown {
        Cleanup::Unknown
    } else {
        cleanup
    };
    (close_result(result, cleanup), ack, cleanup)
}
fn merge_reader<T>(reader: Result<T, Kind>, headers: &HeaderResult) -> Result<T, Kind> {
    if headers.caused_reader {
        if let Some(error) = headers.failure {
            return Err(error);
        }
    }
    match reader {
        Err(error) => Err(error),
        Ok(value) => match headers.failure {
            Some(error) => Err(error),
            None => Ok(value),
        },
    }
}

pub(super) async fn enroll(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    owner: GatewayAuthorizationTokenOwner,
    accounts: &PostgresGatewayAccounts,
    name: &str,
    outcomes: Arc<dyn GatewayHttpOutcomes>,
) -> Result<GatewayConnectionReceipt, GatewayAuthorizationEnrollmentError> {
    let mut facts = Facts::new();
    let current = EnrollmentCurrent::new(journal, auth, &owner)
        .map_err(|e| facts.error(Stage::Entry, map_journal(e, false)))?;
    if !valid_name(name) {
        return Err(facts.error(Stage::Entry, Kind::InvalidInput));
    }
    accounts
        .check_enrollment_scope(&current, &journal.pool, auth, &owner.tokens.sdk.server_url)
        .map_err(|e| facts.error(Stage::Entry, map_authority(e)))?;
    current
        .check()
        .map_err(|e| facts.error(Stage::Entry, map_journal(e, false)))?;
    facts.id = Some(owner.reservation.id);

    let (authority, control, end) = enrollment_headers_channel(EnrollmentRequestKind::Metadata);
    let client = accounts
        .enrollment_client(&current, authority, Arc::clone(&outcomes))
        .map_err(|e| facts.error(Stage::Metadata, map_authority(e)))?;
    let http = async {
        let result = client
            .fetch_metadata_for_enrollment(&current)
            .await
            .map_err(map_account);
        end.finish(end_for(result.as_ref().err().copied()));
        result
    };
    let (metadata, headers) = tokio::join!(
        http,
        run_headers(&current, EnrollmentRequestKind::Metadata, control, accounts)
    );
    facts.metadata = headers.ack;
    facts.observe(headers.cleanup);
    let metadata: GatewayDesktopMetadata =
        merge_reader(metadata, &headers).map_err(|e| facts.error(Stage::Metadata, e))?;

    let (authority, control, end) = enrollment_headers_channel(EnrollmentRequestKind::Profile);
    let client = accounts
        .enrollment_client(&current, authority, outcomes)
        .map_err(|e| facts.error(Stage::Profile, map_authority(e)))?;
    let access = SecretBytes::new(owner.tokens.sdk.access_token.as_bytes().to_vec());
    let http = async {
        let result = client
            .fetch_profile_for_enrollment(&metadata, &access, &current)
            .await
            .map_err(map_account);
        end.finish(end_for(result.as_ref().err().copied()));
        result
    };
    let (profile, headers) = tokio::join!(
        http,
        run_headers(&current, EnrollmentRequestKind::Profile, control, accounts)
    );
    facts.profile = headers.ack;
    facts.observe(headers.cleanup);
    let profile = merge_reader(profile, &headers).map_err(|e| facts.error(Stage::Profile, e))?;
    let adoption = accounts
        .prepare_token_adoption(
            &current,
            auth,
            owner.reservation.id,
            name,
            &owner.tokens.sdk,
            &profile,
        )
        .map_err(|e| facts.error(Stage::Write, map_authority(e)))?;
    let (written, write, cleanup) = write_adoption(&current, accounts, &adoption).await;
    facts.write = write;
    facts.observe(cleanup);
    let secret = written.map_err(|e| facts.error(Stage::Write, e))?;
    let (readback, ack, cleanup) = read_adoption(&current, accounts, &adoption, secret).await;
    facts.readback = ack;
    facts.observe(cleanup);
    readback.map_err(|e| facts.error(Stage::Readback, e))?;
    if facts.metadata != Ack::Timely
        || facts.profile != Ack::Timely
        || facts.write != WriteTerminal::Commit(Ack::Timely)
        || facts.readback != Ack::Timely
        || facts.cleanup != Cleanup::OriginalResourcesDestroyed
    {
        return Err(facts.error(Stage::FinalHandoff, Kind::ReadbackUnproven));
    }
    current
        .check()
        .map_err(|e| facts.error(Stage::FinalHandoff, map_journal(e, false)))?;
    let receipt = adoption
        .finish()
        .map_err(|e| facts.error(Stage::FinalHandoff, map_authority(e)))?;
    current
        .check()
        .map_err(|e| facts.error(Stage::FinalHandoff, map_journal(e, false)))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
