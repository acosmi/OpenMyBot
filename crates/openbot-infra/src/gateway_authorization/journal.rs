//! Current original Server Host authorization journal; receipts never permit dispatch.

use super::{
    ClockOwner, ClockSample, InitialBudget, InitialError, InitialReplyWitness, OwnedInitialKind,
    PreparedInitialOwner, owned_registration_input, prepare_initial, retain_parent_budget,
};
use crate::db::pool::{DatabasePool, TransactionOwnerError};
use crate::db::tables::gateway_authorization_attempts::Row;
use crate::gateway_account::GatewayDesktopMetadata;
use chrono::{DateTime, Utc};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    GatewayAuthorizationHostTarget, HostRequestBindingError, HostRequestBindingIdentity,
    RequestBindingIssuer,
};
use openbot_domain::vault::SecretBytes;
use std::{
    fmt,
    future::Future,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

mod authority_sql;
mod callback;
mod current;
mod registration;
#[cfg(test)]
mod tests;

pub use callback::{
    CallbackErrorKind, CallbackStage, GatewayAuthorizationCallbackError,
    GatewayAuthorizationCallbackWaitOwner, GatewayAuthorizationVerifiedCodeOwner,
};

/// Closed, payload-free journal failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationJournalErrorKind {
    /// Original facts or a closed input predicate did not match.
    Refused,
    /// The original source or pool is unavailable.
    Unavailable,
    /// The original caller cancelled.
    Cancelled,
    /// The saved absolute budget ended.
    Deadline,
    /// The exact native ledger did not match.
    LedgerInvalid,
    /// The registered journal schema did not match.
    SchemaInvalid,
    /// A query, decode or audit observation was not proven.
    ObservationUnknown,
    /// Original write COMMIT acknowledgement was not observed.
    CommitUnknown,
    /// Original COMMIT acknowledgement was observed after its cap.
    CommitAcknowledgedAfterDeadline,
    /// Original ROLLBACK acknowledgement was not observed.
    RollbackUnproven,
    /// Original ROLLBACK acknowledgement was observed after its cap.
    RollbackAcknowledgedAfterDeadline,
    /// The required exact readback was not proven.
    ReadbackUnproven,
}

/// Original transaction terminal acknowledgement fact, independent of later refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayAuthorizationJournalAck {
    /// This terminal operation was not attempted.
    NotAttempted,
    /// No original terminal acknowledgement was observed.
    Unknown,
    /// The original terminal acknowledgement was timely.
    Timely,
    /// The original terminal acknowledgement was late.
    Late,
}

/// Static failure facts; raw PG, SQL, SDK, payload and configuration are absent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GatewayAuthorizationJournalError {
    kind: GatewayAuthorizationJournalErrorKind,
    write_ack: GatewayAuthorizationJournalAck,
    readback_ack: GatewayAuthorizationJournalAck,
}

type Error = GatewayAuthorizationJournalError;
type Kind = GatewayAuthorizationJournalErrorKind;
type Ack = GatewayAuthorizationJournalAck;

impl Error {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            write_ack: Ack::NotAttempted,
            readback_ack: Ack::NotAttempted,
        }
    }
    fn with_acks(mut self, write_ack: Ack, readback_ack: Ack) -> Self {
        self.write_ack = write_ack;
        self.readback_ack = readback_ack;
        self
    }
    /// Closed failure classification; it is not permission to retry.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Original write-transaction terminal fact, including rollback on a failed write.
    #[must_use]
    pub const fn write_ack(&self) -> Ack {
        self.write_ack
    }
    /// Original readback-transaction terminal fact.
    #[must_use]
    pub const fn readback_ack(&self) -> Ack {
        self.readback_ack
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayAuthorizationJournalError")
            .field("kind", &self.kind)
            .field("write_ack", &self.write_ack)
            .field("readback_ack", &self.readback_ack)
            .finish()
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gateway_authorization_journal_{:?}", self.kind)
    }
}
impl std::error::Error for Error {}

/// One original boot runtime; requests observe it weakly and cannot prolong it.
pub struct GatewayAuthorizationJournalRuntimeOwner {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    installation_id: String,
    runtime_epoch: String,
    closed: AtomicBool,
}

impl GatewayAuthorizationJournalRuntimeOwner {
    /// Mint one OS-random runtime tag from the original boot configuration, without PG I/O.
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        installation_id: &str,
    ) -> Result<Self, Error> {
        if !canonical_hex64(installation_id)
            || !identifier(deployment.as_str())
            || !identifier(tenant.as_str())
            || pool.is_closed()
        {
            return Err(Error::new(Kind::Refused));
        }
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| Error::new(Kind::Unavailable))?;
        let mut runtime_epoch = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in random {
            runtime_epoch.push(char::from(HEX[usize::from(byte >> 4)]));
            runtime_epoch.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            installation_id: installation_id.to_owned(),
            runtime_epoch,
            closed: AtomicBool::new(false),
        })
    }
    /// Permanently end this original runtime; no later call can reopen it.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
    fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        !self.closed.load(Ordering::SeqCst)
            && !self.pool.is_closed()
            && !pool.is_closed()
            && std::ptr::eq(self.pool.manager(), pool.manager())
            && &self.deployment == deployment
            && &self.tenant == tenant
    }
}
impl Drop for GatewayAuthorizationJournalRuntimeOwner {
    fn drop(&mut self) {
        self.close();
    }
}

/// Dedicated original Pool/namespace/issuer enrollment and weak boot runtime.
pub struct GatewayAuthorizationJournal {
    pool: DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: SecretBytes,
    runtime: Weak<GatewayAuthorizationJournalRuntimeOwner>,
    authority: Arc<()>,
    issuer: OnceLock<RequestBindingIssuer>,
}

/// Whole captured registration input after created/audit/ACK/exact readback.
pub struct CreatedAttemptOwner {
    prepared: PreparedInitialOwner,
    flow: SavedFlow,
    identity: HostRequestBindingIdentity,
    expected: Row,
    journal: Weak<GatewayAuthorizationJournal>,
    runtime: Weak<GatewayAuthorizationJournalRuntimeOwner>,
}
/// Durable admission receipt holding the same whole owner; not a send grant.
pub struct RegistrationAdmissionReceipt {
    owner: CreatedAttemptOwner,
}
/// Descriptive completed closure; it owns no SDK or recoverable authority.
pub struct ClosedAttemptReceipt {
    _private: (),
}

/// Whole registered result retaining the original reply and one reservation.
pub struct RegisteredAttemptOwner {
    reply: super::OwnedRegistrationReply,
    binding: RegistrationDispatchBinding,
    reservation: EnrollmentReservation,
}
struct RegistrationDispatchBinding {
    flow: SavedFlow,
    identity: HostRequestBindingIdentity,
    expected: Row,
    journal: Weak<GatewayAuthorizationJournal>,
    runtime: Weak<GatewayAuthorizationJournalRuntimeOwner>,
}
struct EnrollmentReservation {
    id: Uuid,
}
/// Closed registration-dispatch failure facts; classification grants no retry authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationDispatchKind {
    /// The operation was refused before dispatch.
    BeforeDispatchRefused,
    /// The required registration-dispatch resource was unavailable.
    Unavailable,
    /// The original operation was cancelled.
    Cancelled,
    /// The original operation deadline was reached.
    Deadline,
    /// The registration request or reply framing was invalid.
    FramingInvalid,
    /// The registration response carried this rejected HTTP status.
    HttpStatus(u16),
    /// The registration result could not be proven.
    RegistrationUnknown,
    /// The original send-guard cleanup could not be proven.
    CleanupUnknown,
    /// The original registered write COMMIT acknowledgement was unknown.
    CommitUnknown,
    /// The original registered write COMMIT acknowledgement was late.
    CommitAcknowledgedAfterDeadline,
    /// The registered exact readback could not be proven.
    ReadbackUnproven,
    /// The original registered readback ROLLBACK acknowledgement was late.
    RollbackAcknowledgedAfterDeadline,
}
/// Closed operation facts preserving the three original transaction terminals.
pub struct RegistrationDispatchError {
    kind: RegistrationDispatchKind,
    transport: Option<crate::gateway_transport::GatewayAttemptSnapshot>,
    send_guard_rollback: Ack,
    registered_write: Ack,
    registered_readback: Ack,
}
impl RegistrationDispatchError {
    /// Closed failure classification; it is not permission to retry.
    #[must_use]
    pub const fn kind(&self) -> RegistrationDispatchKind {
        self.kind
    }
    /// Original transport-minted facts, preserving absence of an observed snapshot.
    #[must_use]
    pub const fn transport_snapshot(
        &self,
    ) -> Option<crate::gateway_transport::GatewayAttemptSnapshot> {
        self.transport
    }
    /// Original send-guard ROLLBACK acknowledgement fact.
    #[must_use]
    pub const fn send_guard_rollback_ack(&self) -> GatewayAuthorizationJournalAck {
        self.send_guard_rollback
    }
    /// Original registered write COMMIT acknowledgement fact.
    #[must_use]
    pub const fn registered_write_ack(&self) -> GatewayAuthorizationJournalAck {
        self.registered_write
    }
    /// Original registered readback ROLLBACK acknowledgement fact.
    #[must_use]
    pub const fn registered_readback_ack(&self) -> GatewayAuthorizationJournalAck {
        self.registered_readback
    }
    fn new(kind: RegistrationDispatchKind) -> Self {
        Self {
            kind,
            transport: None,
            send_guard_rollback: Ack::NotAttempted,
            registered_write: Ack::NotAttempted,
            registered_readback: Ack::NotAttempted,
        }
    }
}
impl fmt::Debug for RegistrationDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationDispatchError")
            .field("kind", &self.kind)
            .field("transport", &self.transport)
            .field("send_guard_rollback", &self.send_guard_rollback)
            .field("registered_write", &self.registered_write)
            .field("registered_readback", &self.registered_readback)
            .finish()
    }
}
impl fmt::Display for RegistrationDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistrationDispatchError({:?})", self.kind)
    }
}
impl std::error::Error for RegistrationDispatchError {}
impl fmt::Debug for RegisteredAttemptOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Each retained resource has static redacted Debug; no identities or
        // reply fields are exposed from this whole owner.
        f.debug_struct("RegisteredAttemptOwner")
            .field("reply", &self.reply)
            .field("binding", &self.binding)
            .field("reservation", &self.reservation)
            .finish()
    }
}

/// The two finite controlled-close reasons; expired/revoked cleanup is separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlledCloseReason {
    /// The current original owner declines this attempt.
    Refused,
    /// A dependency was not established while the original budget remained valid.
    DependencyUnknown,
}
impl ControlledCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::DependencyUnknown => "dependency_unknown",
        }
    }
}

pub(super) struct SavedFlow {
    clock: ClockOwner,
    start: ClockSample,
    original_parent: CancellationToken,
    original_caller_deadline: Instant,
    deadline: Instant,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}
impl SavedFlow {
    fn new(
        clock: ClockOwner,
        original_parent: CancellationToken,
        caller_deadline: std::time::Instant,
    ) -> Result<Self, Error> {
        if original_parent.is_cancelled() {
            return Err(Error::new(Kind::Cancelled));
        }
        let start = clock.sample();
        if original_parent.is_cancelled() {
            return Err(Error::new(Kind::Cancelled));
        }
        let original_caller_deadline = Instant::from_std(caller_deadline);
        let deadline = original_caller_deadline.min(
            start
                .mono
                .checked_add(Duration::from_secs(180))
                .ok_or_else(|| Error::new(Kind::Deadline))?,
        );
        let duration = deadline
            .checked_duration_since(start.mono)
            .filter(|v| !v.is_zero())
            .ok_or_else(|| Error::new(Kind::Deadline))?;
        let wall_delta =
            chrono::Duration::from_std(duration).map_err(|_| Error::new(Kind::Deadline))?;
        let wall_expiry = start
            .wall
            .checked_add_signed(wall_delta)
            .ok_or_else(|| Error::new(Kind::Deadline))?;
        let created_at = canonical_microseconds(start.wall)?;
        let expires_at = canonical_microseconds(wall_expiry)?;
        if expires_at <= created_at {
            return Err(Error::new(Kind::Deadline));
        }
        Ok(Self {
            clock,
            start,
            original_parent,
            original_caller_deadline,
            deadline,
            created_at,
            expires_at,
        })
    }
    fn check(&self, initial: Option<&InitialBudget>) -> Result<ClockSample, Error> {
        if self.original_parent.is_cancelled()
            || initial.is_some_and(|b| b.original_parent.is_cancelled())
        {
            return Err(Error::new(Kind::Cancelled));
        }
        let now = self.clock.sample();
        if self.original_parent.is_cancelled()
            || initial.is_some_and(|b| b.original_parent.is_cancelled())
        {
            return Err(Error::new(Kind::Cancelled));
        }
        let cap = self.cap(initial);
        if now.mono < self.start.mono
            || now.mono >= cap
            || now.wall < self.start.wall
            || canonical_microseconds(now.wall)? >= self.expires_at
            || initial.is_some_and(|b| now.mono < b.http_entered_at)
        {
            return Err(Error::new(Kind::Deadline));
        }
        Ok(now)
    }
    pub(super) fn check_registration_reply(
        &self,
        initial: &InitialBudget,
        clock: &ClockOwner,
    ) -> Result<ClockSample, InitialError> {
        if !Arc::ptr_eq(&self.clock, clock) {
            return Err(InitialError::ProtocolInvalid(
                super::ReplyInvalidReason::ReplyBinding,
            ));
        }
        initial.check(clock)?;
        self.check(Some(initial)).map_err(|error| match error.kind {
            Kind::Cancelled => InitialError::Cancelled,
            Kind::Deadline => InitialError::Deadline,
            _ => InitialError::ProtocolInvalid(super::ReplyInvalidReason::ReplyBinding),
        })
    }
    pub(super) fn registration_reply_cap(&self, initial: &InitialBudget) -> Instant {
        self.cap(Some(initial))
    }
    fn cap(&self, initial: Option<&InitialBudget>) -> Instant {
        let cap = self.deadline.min(self.original_caller_deadline);
        initial.map_or(cap, |b| cap.min(b.deadline).min(b.owner_deadline))
    }
}

/// A stack-borrowed gate is also the exact original invocation target.
struct OperationGate<'a> {
    journal: &'a GatewayAuthorizationJournal,
    auth: &'a AuthContext,
    flow: &'a SavedFlow,
    initial: Option<&'a InitialBudget>,
}
impl GatewayAuthorizationHostTarget for OperationGate<'_> {
    fn matches_authority(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.journal.authority, authority)
    }
    fn matches_auth(&self, auth: &AuthContext) -> bool {
        self.auth == auth
            && self
                .auth
                .request_binding()
                .zip(auth.request_binding())
                .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
    }
}
impl OperationGate<'_> {
    fn check(&self) -> Result<ClockSample, Error> {
        let sample = self.flow.check(self.initial)?;
        if !self.journal.is_current() {
            return Err(Error::new(Kind::Unavailable));
        }
        Ok(sample)
    }
    fn deadline(&self) -> Instant {
        self.flow.cap(self.initial)
    }
    async fn io<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>>,
        map: impl FnOnce(E) -> Error,
    ) -> Result<T, Error> {
        self.check()?;
        let result = tokio::select! {
            biased;
            result = future => result.map_err(map),
            () = self.flow.original_parent.cancelled() => Err(Error::new(Kind::Cancelled)),
            () = tokio::time::sleep_until(self.deadline()) => Err(Error::new(Kind::Deadline)),
        };
        self.check()?;
        result
    }
    // Poll the original terminal future before the timer on resume: a real late ACK
    // must remain a known ACK rather than being replaced by the outer timeout.
    async fn terminal(
        &self,
        future: impl Future<Output = Result<(), TransactionOwnerError>>,
        commit: bool,
    ) -> Result<Ack, (Error, Ack)> {
        self.check().map_err(|e| (e, Ack::Unknown))?;
        let result = tokio::select! {
            biased;
            result = future => result,
            () = self.flow.original_parent.cancelled() => return Err((Error::new(Kind::Cancelled), Ack::Unknown)),
            () = tokio::time::sleep_until(self.deadline()) => return Err((Error::new(if commit {Kind::CommitUnknown} else {Kind::RollbackUnproven}), Ack::Unknown)),
        };
        match result {
            Ok(()) => Ok(Ack::Timely),
            Err(TransactionOwnerError::CommitAcknowledgedAfterDeadline) => {
                Err((Error::new(Kind::CommitAcknowledgedAfterDeadline), Ack::Late))
            }
            Err(TransactionOwnerError::RollbackAcknowledgedAfterDeadline) => Err((
                Error::new(Kind::RollbackAcknowledgedAfterDeadline),
                Ack::Late,
            )),
            Err(TransactionOwnerError::CommitUnknown) => {
                Err((Error::new(Kind::CommitUnknown), Ack::Unknown))
            }
            Err(TransactionOwnerError::RollbackUnproven) => {
                Err((Error::new(Kind::RollbackUnproven), Ack::Unknown))
            }
            Err(_) => Err((
                Error::new(if commit {
                    Kind::CommitUnknown
                } else {
                    Kind::RollbackUnproven
                }),
                Ack::Unknown,
            )),
        }
    }
}

fn canonical_microseconds(wall: DateTime<Utc>) -> Result<OffsetDateTime, Error> {
    let micros = i128::from(wall.timestamp())
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(i128::from(wall.timestamp_subsec_micros())))
        .and_then(|v| v.checked_mul(1_000))
        .ok_or_else(|| Error::new(Kind::Deadline))?;
    OffsetDateTime::from_unix_timestamp_nanos(micros).map_err(|_| Error::new(Kind::Deadline))
}
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}
fn canonical_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn initial_error(error: InitialError) -> Error {
    Error::new(match error {
        InitialError::Cancelled => Kind::Cancelled,
        InitialError::Deadline => Kind::Deadline,
        InitialError::ProducerEnded => Kind::Unavailable,
        _ => Kind::Refused,
    })
}
fn host_error(error: HostRequestBindingError) -> Error {
    Error::new(match error {
        HostRequestBindingError::Unavailable => Kind::Unavailable,
        HostRequestBindingError::Missing | HostRequestBindingError::NotCurrent => Kind::Refused,
    })
}
fn observation_error<T>(_error: T) -> Error {
    Error::new(Kind::ObservationUnknown)
}

#[derive(Clone, Copy)]
enum JournalWrite {
    Create,
    Admit,
    Close,
}

impl GatewayAuthorizationJournal {
    /// Bind one original pool/runtime and audit key; no checkout or write occurs.
    pub fn new(
        pool: DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
        runtime: &Arc<GatewayAuthorizationJournalRuntimeOwner>,
    ) -> Result<Self, Error> {
        if !runtime.matches_pool_scope(&pool, &deployment, &tenant) || audit_key.expose().is_empty()
        {
            return Err(Error::new(Kind::Unavailable));
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            audit_key,
            runtime: Arc::downgrade(runtime),
            authority: Arc::new(()),
            issuer: OnceLock::new(),
        })
    }
    /// Compare the same manager and namespace and the original live runtime.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &DatabasePool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && &self.deployment == deployment
            && &self.tenant == tenant
            && self
                .runtime
                .upgrade()
                .is_some_and(|r| r.matches_pool_scope(pool, deployment, tenant))
    }
    /// Enroll one current original issuer, once, without creating Host authority.
    pub fn enroll_host_issuer(
        &self,
        issuer: &RequestBindingIssuer,
    ) -> Result<(), HostRequestBindingError> {
        if !self.is_current() || !issuer.observation().is_current() {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.issuer
            .set(issuer.clone())
            .map_err(|_| HostRequestBindingError::Unavailable)
    }
    /// The installed producer compares this original authority, not a caller label.
    #[must_use]
    pub fn matches_host_target(&self, target: &dyn GatewayAuthorizationHostTarget) -> bool {
        self.is_current() && target.matches_authority(&self.authority)
    }
    fn is_current(&self) -> bool {
        self.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
    }
    fn check_scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !identifier(auth.actor().as_str())
        {
            return Err(Error::new(Kind::Refused));
        }
        if !self.is_current() {
            return Err(Error::new(Kind::Unavailable));
        }
        Ok(())
    }
    /// Consume one original admission receipt for one registration dispatch.
    pub async fn register_admitted(
        self: &Arc<Self>,
        auth: &AuthContext,
        receipt: RegistrationAdmissionReceipt,
        factory: &crate::gateway_transport::GatewayTransportFactory,
    ) -> Result<RegisteredAttemptOwner, RegistrationDispatchError> {
        registration::dispatch_registration(self, auth, receipt, factory).await
    }
    /// Create/audit/ACK/read back before capturing the original registration request.
    pub async fn create_attempt(
        self: &Arc<Self>,
        auth: &AuthContext,
        metadata: GatewayDesktopMetadata,
        redirect: Zeroizing<String>,
        original_parent: CancellationToken,
        caller_deadline: std::time::Instant,
    ) -> Result<CreatedAttemptOwner, Error> {
        self.check_scope(auth)?;
        let input = owned_registration_input(metadata, redirect).map_err(initial_error)?;
        let flow = SavedFlow::new(Arc::clone(&input.clock), original_parent, caller_deadline)?;
        self.create_from_input_and_flow(auth, input, flow).await
    }
    async fn create_from_input_and_flow(
        self: &Arc<Self>,
        auth: &AuthContext,
        input: super::OwnedInitialInput,
        flow: SavedFlow,
    ) -> Result<CreatedAttemptOwner, Error> {
        if !Arc::ptr_eq(&input.clock, &flow.clock) {
            return Err(Error::new(Kind::Refused));
        }
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        let OwnedInitialKind::Registration(reg) = &input.kind else {
            return Err(Error::new(Kind::Refused));
        };
        let expected = Row {
            attempt_id: Uuid::now_v7(),
            journal_schema: 1,
            deployment_id: self.deployment.as_str().to_owned(),
            tenant_id: self.tenant.as_str().to_owned(),
            owner_user_id: auth.actor().as_str().to_owned(),
            auth_generation: i64::try_from(auth.auth_generation().get())
                .map_err(|_| Error::new(Kind::Refused))?,
            installation_id: runtime.installation_id.clone(),
            runtime_epoch: runtime.runtime_epoch.clone(),
            issuer: reg.metadata.sdk_metadata().issuer.clone(),
            redirect_uri: reg.original_redirect_uri.to_string(),
            phase: "created".to_owned(),
            client_id: None,
            enrollment_id: None,
            registration_admitted_at: None,
            code_admitted_at: None,
            created_at: flow.created_at,
            expires_at: flow.expires_at,
            updated_at: flow.created_at,
            finished_at: None,
            outcome_code: None,
        };
        drop(runtime);
        let identity = {
            let gate = OperationGate {
                journal: self,
                auth,
                flow: &flow,
                initial: None,
            };
            let observation = current::borrow_current(self, auth, &gate).await?;
            let identity = observation.identity().clone();
            drop(observation);
            self.write(auth, &expected, &expected, JournalWrite::Create, &gate)
                .await?;
            authority_sql::readback_exact(self, auth, &identity, &expected, &gate).await?;
            identity
        };
        let prepared = prepare_initial(
            input,
            retain_parent_budget(flow.original_parent.clone(), flow.deadline),
        )
        .await
        .map_err(|e| initial_error(e).with_acks(Ack::Timely, Ack::Timely))?;
        let owner = CreatedAttemptOwner {
            prepared,
            flow,
            identity,
            expected,
            journal: Arc::downgrade(self),
            runtime: self.runtime.clone(),
        };
        {
            let gate = self
                .owner_gate(auth, &owner)
                .map_err(|e| e.with_acks(Ack::Timely, Ack::Timely))?;
            let observation = current::borrow_current(self, auth, &gate)
                .await
                .map_err(|e| e.with_acks(Ack::Timely, Ack::Timely))?;
            if !observation.identity().same_binding(&owner.identity) {
                return Err(Error::new(Kind::Refused).with_acks(Ack::Timely, Ack::Timely));
            }
            gate.check()
                .map_err(|e| e.with_acks(Ack::Timely, Ack::Timely))?;
            drop(observation);
        }
        Ok(owner)
    }
    /// CAS/admit/audit/ACK/read back using the original whole prepared owner.
    pub async fn admit_registration(
        self: &Arc<Self>,
        auth: &AuthContext,
        mut owner: CreatedAttemptOwner,
    ) -> Result<RegistrationAdmissionReceipt, Error> {
        let next = {
            let gate = self.owner_gate(auth, &owner)?;
            let next = self
                .write(
                    auth,
                    &owner.expected,
                    &owner.expected,
                    JournalWrite::Admit,
                    &gate,
                )
                .await?;
            authority_sql::readback_exact(self, auth, &owner.identity, &next, &gate).await?;
            next
        };
        owner.expected = next;
        Ok(RegistrationAdmissionReceipt { owner })
    }
    /// Close a live created owner only within its saved original budgets.
    pub async fn close_created(
        self: &Arc<Self>,
        auth: &AuthContext,
        owner: CreatedAttemptOwner,
        reason: ControlledCloseReason,
    ) -> Result<ClosedAttemptReceipt, Error> {
        if owner.expected.phase != "created" {
            return Err(Error::new(Kind::Refused));
        }
        self.close_owner(auth, owner, reason).await
    }
    /// Close the original admitted owner without granting terminal management.
    pub async fn close_admitted(
        self: &Arc<Self>,
        auth: &AuthContext,
        receipt: RegistrationAdmissionReceipt,
        reason: ControlledCloseReason,
    ) -> Result<ClosedAttemptReceipt, Error> {
        if receipt.owner.expected.phase != "registration_admitted" {
            return Err(Error::new(Kind::Refused));
        }
        self.close_owner(auth, receipt.owner, reason).await
    }
    async fn close_owner(
        self: &Arc<Self>,
        auth: &AuthContext,
        owner: CreatedAttemptOwner,
        reason: ControlledCloseReason,
    ) -> Result<ClosedAttemptReceipt, Error> {
        {
            let gate = self.owner_gate(auth, &owner)?;
            let mut next = owner.expected.clone();
            next.outcome_code = Some(reason.as_str().to_owned());
            let next = self
                .write(auth, &owner.expected, &next, JournalWrite::Close, &gate)
                .await?;
            authority_sql::readback_exact(self, auth, &owner.identity, &next, &gate).await?;
        }
        drop(owner);
        Ok(ClosedAttemptReceipt { _private: () })
    }
    fn owner_gate<'a>(
        self: &'a Arc<Self>,
        auth: &'a AuthContext,
        owner: &'a CreatedAttemptOwner,
    ) -> Result<OperationGate<'a>, Error> {
        self.check_scope(auth)?;
        let original = owner
            .journal
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if !Arc::ptr_eq(self, &original)
            || !Weak::ptr_eq(&owner.runtime, &self.runtime)
            || !Arc::ptr_eq(&owner.flow.clock, &owner.prepared.clock)
        {
            return Err(Error::new(Kind::Refused));
        }
        let binding = auth
            .request_binding()
            .ok_or_else(|| Error::new(Kind::Refused))?;
        if !binding.identity().same_binding(&owner.identity) {
            return Err(Error::new(Kind::Refused));
        }
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if owner.expected.installation_id != runtime.installation_id
            || owner.expected.runtime_epoch != runtime.runtime_epoch
            || owner.expected.deployment_id != self.deployment.as_str()
            || owner.expected.tenant_id != self.tenant.as_str()
            || owner.expected.owner_user_id != auth.actor().as_str()
            || i64::try_from(auth.auth_generation().get()).ok()
                != Some(owner.expected.auth_generation)
            || owner.expected.created_at != owner.flow.created_at
            || owner.expected.expires_at != owner.flow.expires_at
            || owner.expected.journal_schema != 1
            || owner.prepared.request.is_none()
            || !owner.prepared.sdk_exit_child.is_cancelled()
        {
            return Err(Error::new(Kind::Refused));
        }
        match owner.prepared.witness.as_ref() {
            Some(InitialReplyWitness::Registration {
                metadata,
                original_redirect_uri,
            }) if metadata.sdk_metadata().issuer == owner.expected.issuer
                && original_redirect_uri.as_str() == owner.expected.redirect_uri => {}
            _ => return Err(Error::new(Kind::Refused)),
        }
        let initial = owner
            .prepared
            .budget
            .as_ref()
            .ok_or_else(|| Error::new(Kind::Refused))?;
        let gate = OperationGate {
            journal: self,
            auth,
            flow: &owner.flow,
            initial: Some(initial),
        };
        gate.check()?;
        Ok(gate)
    }
    fn registration_binding_gate<'a>(
        self: &'a Arc<Self>,
        auth: &'a AuthContext,
        binding: &'a RegistrationDispatchBinding,
        initial: &'a InitialBudget,
        clock: &ClockOwner,
    ) -> Result<OperationGate<'a>, Error> {
        self.check_scope(auth)?;
        let original = binding
            .journal
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if !Arc::ptr_eq(self, &original)
            || !Weak::ptr_eq(&binding.runtime, &self.runtime)
            || !Arc::ptr_eq(&binding.flow.clock, clock)
        {
            return Err(Error::new(Kind::Refused));
        }
        let request_binding = auth
            .request_binding()
            .ok_or_else(|| Error::new(Kind::Refused))?;
        if !request_binding.identity().same_binding(&binding.identity) {
            return Err(Error::new(Kind::Refused));
        }
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if binding.expected.installation_id != runtime.installation_id
            || binding.expected.runtime_epoch != runtime.runtime_epoch
            || binding.expected.deployment_id != self.deployment.as_str()
            || binding.expected.tenant_id != self.tenant.as_str()
            || binding.expected.owner_user_id != auth.actor().as_str()
            || i64::try_from(auth.auth_generation().get()).ok()
                != Some(binding.expected.auth_generation)
            || binding.expected.created_at != binding.flow.created_at
            || binding.expected.expires_at != binding.flow.expires_at
            || binding.expected.journal_schema != 1
        {
            return Err(Error::new(Kind::Refused));
        }
        initial.check(clock).map_err(initial_error)?;
        let gate = OperationGate {
            journal: self,
            auth,
            flow: &binding.flow,
            initial: Some(initial),
        };
        gate.check()?;
        Ok(gate)
    }
    fn dispatched_gate<'a>(
        self: &'a Arc<Self>,
        auth: &'a AuthContext,
        binding: &'a RegistrationDispatchBinding,
        dispatched: &'a super::DispatchedInitialOwner,
    ) -> Result<OperationGate<'a>, Error> {
        // The parent whole-transfer path alone mints this witness. Keep the old
        // captured-owner request.is_some() predicate unchanged above.
        let _transfer = &dispatched.transfer;
        if !dispatched.sdk_exit_child.is_cancelled() {
            return Err(Error::new(Kind::Refused));
        }
        match &dispatched.witness {
            InitialReplyWitness::Registration {
                metadata,
                original_redirect_uri,
            } if metadata.sdk_metadata().issuer == binding.expected.issuer
                && original_redirect_uri.as_str() == binding.expected.redirect_uri => {}
            _ => return Err(Error::new(Kind::Refused)),
        }
        self.registration_binding_gate(auth, binding, &dispatched.budget, &dispatched.clock)
    }
    fn registered_reply_gate<'a>(
        self: &'a Arc<Self>,
        auth: &'a AuthContext,
        binding: &'a RegistrationDispatchBinding,
        reply: &'a super::OwnedRegistrationReply,
    ) -> Result<OperationGate<'a>, Error> {
        if reply.resources.metadata.sdk_metadata().issuer != binding.expected.issuer
            || reply.original_redirect_uri.as_str() != binding.expected.redirect_uri
            || !super::initial::valid_client_id(&reply.client_id)
        {
            return Err(Error::new(Kind::Refused));
        }
        self.registration_binding_gate(
            auth,
            binding,
            &reply.resources.budget,
            &reply.resources.clock,
        )
    }
    /// Bind one original listener and hand off one SDK-built URL after registration.
    pub async fn start_callback(
        self: &Arc<Self>,
        auth: &AuthContext,
        metadata: GatewayDesktopMetadata,
        original_parent: CancellationToken,
        caller_deadline: std::time::Instant,
        factory: &crate::gateway_transport::GatewayTransportFactory,
    ) -> Result<GatewayAuthorizationCallbackWaitOwner, GatewayAuthorizationCallbackError> {
        callback::start_callback(
            self,
            auth,
            metadata,
            original_parent,
            caller_deadline,
            factory,
        )
        .await
    }
    /// Consume the same whole callback owner once, without granting code dispatch.
    pub async fn wait_callback(
        self: &Arc<Self>,
        auth: &AuthContext,
        owner: GatewayAuthorizationCallbackWaitOwner,
    ) -> Result<GatewayAuthorizationVerifiedCodeOwner, GatewayAuthorizationCallbackError> {
        callback::wait_callback(self, auth, owner).await
    }
    fn callback_registered_gate<'a>(
        self: &'a Arc<Self>,
        auth: &'a AuthContext,
        owner: &'a RegisteredAttemptOwner,
    ) -> Result<OperationGate<'a>, Error> {
        self.check_scope(auth)?;
        let binding = &owner.binding;
        let original = binding
            .journal
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if !Arc::ptr_eq(self, &original)
            || !Weak::ptr_eq(&binding.runtime, &self.runtime)
            || !Arc::ptr_eq(&binding.flow.clock, &owner.reply.resources.clock)
        {
            return Err(Error::new(Kind::Refused));
        }
        let attached = auth
            .request_binding()
            .ok_or_else(|| Error::new(Kind::Refused))?;
        let issuer = self
            .issuer
            .get()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        if !attached.identity().same_binding(&binding.identity)
            || !issuer.observation().is_current()
            || !issuer.owns_identity(&binding.identity)
        {
            return Err(Error::new(Kind::Refused));
        }
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| Error::new(Kind::Unavailable))?;
        let row = &binding.expected;
        if !runtime.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
            || row.attempt_id.get_version_num() != 7
            || row.journal_schema != 1
            || row.deployment_id != self.deployment.as_str()
            || row.tenant_id != self.tenant.as_str()
            || row.owner_user_id != auth.actor().as_str()
            || i64::try_from(auth.auth_generation().get()).ok() != Some(row.auth_generation)
            || row.installation_id != runtime.installation_id
            || row.runtime_epoch != runtime.runtime_epoch
            || row.issuer != owner.reply.resources.metadata.sdk_metadata().issuer
            || row.redirect_uri != owner.reply.original_redirect_uri.as_str()
            || row.phase != "registered"
            || row.client_id.as_deref() != Some(owner.reply.client_id.as_str())
            || !super::initial::valid_client_id(&owner.reply.client_id)
            || row.enrollment_id != Some(owner.reservation.id)
            || owner.reservation.id.get_version_num() != 7
            || row.registration_admitted_at.is_none()
            || row
                .registration_admitted_at
                .is_some_and(|t| t < row.created_at || t > row.updated_at)
            || row.code_admitted_at.is_some()
            || row.created_at != binding.flow.created_at
            || row.expires_at != binding.flow.expires_at
            || row.updated_at < row.created_at
            || row.updated_at >= row.expires_at
            || row.finished_at.is_some()
            || row.outcome_code.is_some()
        {
            return Err(Error::new(Kind::Refused));
        }
        drop(runtime);
        // The completed registration's 10s stage is historical; never check or renew it here.
        let gate = OperationGate {
            journal: self,
            auth,
            flow: &binding.flow,
            initial: None,
        };
        gate.check()?;
        Ok(gate)
    }
    async fn write(
        self: &Arc<Self>,
        auth: &AuthContext,
        old: &Row,
        template: &Row,
        action: JournalWrite,
        gate: &OperationGate<'_>,
    ) -> Result<Row, Error> {
        let observation = current::borrow_current(self, auth, gate).await?;
        let mut client = gate
            .io(self.pool.get_guarded(gate.deadline().into_std()), |_| {
                Error::new(Kind::Unavailable)
            })
            .await?;
        let tx = gate
            .io(client.begin_read_committed(), observation_error)
            .await?;
        let operation = async {
            gate.io(
                crate::db::native::validate_gateway_authorization_journal_in_transaction(
                    tx.as_transaction(),
                ),
                authority_sql::native_error,
            )
            .await?;
            let tail = current::lock_actor(tx.as_transaction(), auth, &observation, gate).await?;
            let next = match action {
                JournalWrite::Create => old.clone(),
                JournalWrite::Admit | JournalWrite::Close => {
                    let locked =
                        authority_sql::lock_attempt(tx.as_transaction(), old.attempt_id, gate)
                            .await?;
                    if locked != *old {
                        return Err(Error::new(Kind::Refused));
                    }
                    let stamp = canonical_microseconds(gate.check()?.wall)?;
                    match action {
                        JournalWrite::Admit => admitted_row(old, stamp)?,
                        JournalWrite::Close => closed_row(old, template, stamp)?,
                        JournalWrite::Create => unreachable!(),
                    }
                }
            };
            current::verify_tail(tail.as_ref(), auth, gate)?;
            match action {
                JournalWrite::Create => {
                    authority_sql::create(tx.as_transaction(), &next, gate).await?
                }
                JournalWrite::Admit => {
                    authority_sql::cas_admit(tx.as_transaction(), old, &next, gate).await?
                }
                JournalWrite::Close => {
                    authority_sql::cas_close(tx.as_transaction(), old, &next, gate).await?
                }
            }
            authority_sql::append_audit(
                tx.as_transaction(),
                auth,
                &next,
                action,
                &self.audit_key,
                gate,
            )
            .await?;
            current::verify_tail(tail.as_ref(), auth, gate)?;
            Ok::<_, Error>((next, tail))
        }
        .await;
        let (next, tail) = match operation {
            Ok(value) => value,
            Err(error) => {
                let terminal = gate.terminal(tx.rollback(), false).await;
                return Err(match terminal {
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
        current::verify_tail(tail.as_ref(), auth, gate)
            .map_err(|e| e.with_acks(Ack::Timely, Ack::NotAttempted))?;
        Ok(next)
    }
}

fn admitted_row(old: &Row, stamp: OffsetDateTime) -> Result<Row, Error> {
    if old.phase != "created"
        || old.client_id.is_some()
        || old.enrollment_id.is_some()
        || old.registration_admitted_at.is_some()
        || old.code_admitted_at.is_some()
        || old.finished_at.is_some()
        || old.outcome_code.is_some()
        || stamp < old.updated_at
        || stamp >= old.expires_at
    {
        return Err(Error::new(Kind::Refused));
    }
    let mut next = old.clone();
    next.phase = "registration_admitted".to_owned();
    next.registration_admitted_at = Some(stamp);
    next.updated_at = stamp;
    Ok(next)
}
fn registered_row(
    old: &Row,
    client_id: &str,
    enrollment_id: Uuid,
    stamp: OffsetDateTime,
) -> Result<Row, Error> {
    if old.phase != "registration_admitted"
        || old.registration_admitted_at.is_none()
        || old.client_id.is_some()
        || old.enrollment_id.is_some()
        || old.code_admitted_at.is_some()
        || old.finished_at.is_some()
        || old.outcome_code.is_some()
        || !super::initial::valid_client_id(client_id)
        || enrollment_id.get_version_num() != 7
        || stamp < old.updated_at
        || stamp >= old.expires_at
    {
        return Err(Error::new(Kind::Refused));
    }
    let mut next = old.clone();
    next.phase = "registered".to_owned();
    next.client_id = Some(client_id.to_owned());
    next.enrollment_id = Some(enrollment_id);
    next.updated_at = stamp;
    Ok(next)
}
fn closed_row(old: &Row, template: &Row, stamp: OffsetDateTime) -> Result<Row, Error> {
    if !matches!(old.phase.as_str(), "created" | "registration_admitted")
        || (old.phase == "created" && old.registration_admitted_at.is_some())
        || (old.phase == "registration_admitted" && old.registration_admitted_at.is_none())
        || old.client_id.is_some()
        || old.enrollment_id.is_some()
        || old.code_admitted_at.is_some()
        || old.finished_at.is_some()
        || old.outcome_code.is_some()
        || stamp < old.updated_at
        || stamp >= old.expires_at
        || !matches!(
            template.outcome_code.as_deref(),
            Some("refused" | "dependency_unknown")
        )
    {
        return Err(Error::new(Kind::Refused));
    }
    let mut next = old.clone();
    next.phase = "closed".to_owned();
    next.updated_at = stamp;
    next.finished_at = Some(stamp);
    next.outcome_code = template.outcome_code.clone();
    Ok(next)
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?)=>{$(impl fmt::Debug for $ty {
        fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(concat!(stringify!($ty),"([redacted])"))}
    })+};
}
redacted!(
    GatewayAuthorizationJournalRuntimeOwner,
    GatewayAuthorizationJournal,
    CreatedAttemptOwner,
    RegistrationAdmissionReceipt,
    ClosedAttemptReceipt,
    RegistrationDispatchBinding,
    EnrollmentReservation,
    SavedFlow,
    OperationGate<'_>
);
