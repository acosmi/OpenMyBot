//! Original whole callback rendezvous; local completion is never enrollment authority.

use super::super::{
    CallbackPkceMaterial, ClockOwner, SystemClock, callback_authorization_url,
    callback_pkce_material, callback_registration_input,
};
use super::{
    Ack, Error, GatewayAuthorizationJournal, Kind, OperationGate, RegisteredAttemptOwner,
    RegistrationDispatchError, RegistrationDispatchKind, SavedFlow, authority_sql, host_error,
    initial_error,
};
use crate::gateway_account::GatewayDesktopMetadata;
use crate::gateway_transport::GatewayTransportFactory;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::request_binding::HostRequestBindingKind;
use std::{
    fmt,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const HEAD_LIMIT: usize = 65_536;
const HEAD_CAPACITY: usize = HEAD_LIMIT + 1;
const HEADER_LIMIT: usize = 64;
const HEADER_LINE_LIMIT: usize = 8_192;
const CODE_LIMIT: usize = 16_377;
const DESCRIPTION_LIMIT: usize = 1_024;
const CONNECTION_LIMIT: usize = 4;
const CONNECTION_BUDGET: Duration = Duration::from_secs(10);

const RESPONSE_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
const RESPONSE_NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
const RESPONSE_METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
const RESPONSE_CODE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nCallback received.";
const RESPONSE_ERROR: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nAuthorization was not completed.";

/// Original operation stage, independent of later callback refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackStage {
    /// Listener and original journal creation.
    Create,
    /// Original registration admission.
    Admission,
    /// Original registration dispatch.
    Registration,
    /// URL handoff and callback rendezvous.
    Callback,
}
/// Closed callback failure classification; it grants no retry permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackErrorKind {
    /// Original journal failure before callback.
    Journal(super::GatewayAuthorizationJournalErrorKind),
    /// Original registration failure.
    Registration(RegistrationDispatchKind),
    /// The same original attachment or input was refused.
    Refused,
    /// An original producer or resource was unavailable.
    Unavailable,
    /// The original parent was cancelled.
    Cancelled,
    /// The original absolute cap ended.
    Deadline,
    /// An owned callback I/O operation failed.
    CallbackIo,
    /// A fully matched callback denied authorization.
    AuthorizationDenied,
    /// A fully matched callback rejected authorization.
    AuthorizationRejected,
    /// The original callback readback was not proven.
    ReadbackUnproven,
    /// Original RO rollback acknowledgement arrived late.
    RollbackAcknowledgedAfterDeadline,
}
/// Payload-free callback facts with an independent original RO acknowledgement slot.
pub struct GatewayAuthorizationCallbackError {
    stage: CallbackStage,
    kind: CallbackErrorKind,
    journal: Option<Error>,
    registration: Option<RegistrationDispatchError>,
    callback_readback: Ack,
}
type CallbackError = GatewayAuthorizationCallbackError;
impl CallbackError {
    fn new(kind: CallbackErrorKind) -> Self {
        Self {
            stage: CallbackStage::Callback,
            kind,
            journal: None,
            registration: None,
            callback_readback: Ack::NotAttempted,
        }
    }
    fn journal(stage: CallbackStage, original: Error) -> Self {
        Self {
            stage,
            kind: CallbackErrorKind::Journal(original.kind()),
            journal: Some(original),
            registration: None,
            callback_readback: Ack::NotAttempted,
        }
    }
    fn registration(original: RegistrationDispatchError) -> Self {
        Self {
            stage: CallbackStage::Registration,
            kind: CallbackErrorKind::Registration(original.kind()),
            journal: None,
            registration: Some(original),
            callback_readback: Ack::NotAttempted,
        }
    }
    fn callback_journal(original: Error) -> Self {
        let kind = match original.kind() {
            Kind::Refused => CallbackErrorKind::Refused,
            Kind::Unavailable => CallbackErrorKind::Unavailable,
            Kind::Cancelled => CallbackErrorKind::Cancelled,
            Kind::Deadline => CallbackErrorKind::Deadline,
            other => CallbackErrorKind::Journal(other),
        };
        Self {
            journal: Some(original),
            ..Self::new(kind)
        }
    }
    fn readback(original: Error) -> Self {
        let kind = match original.kind() {
            Kind::Cancelled => CallbackErrorKind::Cancelled,
            Kind::Deadline => CallbackErrorKind::Deadline,
            Kind::RollbackAcknowledgedAfterDeadline => {
                CallbackErrorKind::RollbackAcknowledgedAfterDeadline
            }
            _ => CallbackErrorKind::ReadbackUnproven,
        };
        // write_ack belongs to the old preceding-write context, never to this callback.
        Self {
            journal: Some(original),
            callback_readback: original.readback_ack(),
            ..Self::new(kind)
        }
    }
    fn with_readback(mut self, ack: Ack) -> Self {
        self.callback_readback = ack;
        self
    }
    /// Original stage, with no raw payload.
    #[must_use]
    pub const fn stage(&self) -> CallbackStage {
        self.stage
    }
    /// Closed failure kind, never retry authority.
    #[must_use]
    pub const fn kind(&self) -> CallbackErrorKind {
        self.kind
    }
    /// Borrow the preserved original journal facts.
    #[must_use]
    pub const fn journal_error(&self) -> Option<&Error> {
        self.journal.as_ref()
    }
    /// Borrow the preserved original registration facts.
    #[must_use]
    pub const fn registration_error(&self) -> Option<&RegistrationDispatchError> {
        self.registration.as_ref()
    }
    /// Callback's own original RO terminal fact, independent of earlier transactions.
    #[must_use]
    pub const fn callback_readback_ack(&self) -> Ack {
        self.callback_readback
    }
}
impl fmt::Debug for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayAuthorizationCallbackError")
            .field("stage", &self.stage)
            .field("kind", &self.kind)
            .field("callback_readback_ack", &self.callback_readback)
            .finish()
    }
}
impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway_authorization_callback_failure")
    }
}
impl std::error::Error for CallbackError {}

/// Whole original registration, listener, PKCE and consumed URL offer; no raw parts escape.
pub struct GatewayAuthorizationCallbackWaitOwner {
    registered: RegisteredAttemptOwner,
    listener: TcpListener,
    material: CallbackPkceMaterial,
    url_offer: Option<Zeroizing<String>>,
}
/// Same original registered reservation and armed code/verifier; it grants no code dispatch.
pub struct GatewayAuthorizationVerifiedCodeOwner {
    _registered: RegisteredAttemptOwner,
    _code: Zeroizing<Vec<u8>>,
    _verifier: Zeroizing<String>,
}
impl fmt::Debug for GatewayAuthorizationCallbackWaitOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAuthorizationCallbackWaitOwner([redacted])")
    }
}
impl fmt::Debug for GatewayAuthorizationVerifiedCodeOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAuthorizationVerifiedCodeOwner([redacted])")
    }
}

#[derive(Clone, Copy)]
enum QueryKey {
    State,
    Code,
    Error,
    Description,
}
impl QueryKey {
    fn bit(self) -> u8 {
        match self {
            Self::State => 1,
            Self::Code => 2,
            Self::Error => 4,
            Self::Description => 8,
        }
    }
}
#[derive(Clone, Copy)]
struct RawField {
    key: QueryKey,
    value_start: usize,
    value_end: usize,
}
enum CallbackValue {
    Code(Zeroizing<Vec<u8>>),
    Error(CallbackErrorKind),
}
enum ProbeStatus {
    BadRequest,
    NotFound,
    MethodNotAllowed,
}
impl ProbeStatus {
    fn response(&self) -> &'static [u8] {
        match self {
            Self::BadRequest => RESPONSE_BAD_REQUEST,
            Self::NotFound => RESPONSE_NOT_FOUND,
            Self::MethodNotAllowed => RESPONSE_METHOD_NOT_ALLOWED,
        }
    }
}
enum RequestOutcome {
    Probe(ProbeStatus),
    Terminal(CallbackValue),
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn decode_bytes(raw: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut owner = Zeroizing::new(Vec::with_capacity(limit));
    let mut cursor = 0;
    while cursor < raw.len() {
        if owner.len() == limit {
            return Err(());
        }
        let byte = match raw[cursor] {
            b'%' => {
                let high = raw.get(cursor + 1).copied().and_then(hex).ok_or(())?;
                let low = raw.get(cursor + 2).copied().and_then(hex).ok_or(())?;
                cursor += 3;
                (high << 4) | low
            }
            b'+' => {
                cursor += 1;
                b' '
            }
            byte => {
                cursor += 1;
                byte
            }
        };
        owner.push(byte);
    }
    Ok(owner)
}
fn base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}
fn graphic(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}
fn parse_query(raw: &[u8], original_state: &[u8]) -> Result<CallbackValue, ()> {
    // First pass handles every key; no value is allocated or interpreted until all pass.
    let mut fields = [None; 4];
    let mut count = 0;
    let mut bits = 0_u8;
    let mut start = 0;
    while start < raw.len() {
        if count == fields.len() {
            return Err(());
        }
        let end = raw[start..]
            .iter()
            .position(|b| *b == b'&')
            .map_or(raw.len(), |n| start + n);
        if end == start {
            return Err(());
        }
        let equals = raw[start..end]
            .iter()
            .position(|b| *b == b'=')
            .map(|n| start + n)
            .ok_or(())?;
        if equals == start {
            return Err(());
        }
        let key = decode_bytes(&raw[start..equals], 17)?;
        let key = match key.as_slice() {
            b"state" => QueryKey::State,
            b"code" => QueryKey::Code,
            b"error" => QueryKey::Error,
            b"error_description" => QueryKey::Description,
            _ => return Err(()),
        };
        if bits & key.bit() != 0 {
            return Err(());
        }
        bits |= key.bit();
        fields[count] = Some(RawField {
            key,
            value_start: equals + 1,
            value_end: end,
        });
        count += 1;
        if end == raw.len() {
            break;
        }
        start = end + 1;
        if start == raw.len() {
            return Err(());
        }
    }
    if bits & 1 == 0
        || !matches!(bits & 6, 2 | 4)
        || (bits & 2 != 0 && bits & 8 != 0)
        || original_state.len() != 43
        || !original_state.iter().copied().all(base64url)
    {
        return Err(());
    }
    let mut code = None;
    let mut error = None;
    for field in fields[..count].iter().flatten() {
        let raw_value = &raw[field.value_start..field.value_end];
        match field.key {
            QueryKey::State => {
                let state = decode_bytes(raw_value, 43)?;
                if state.len() != 43
                    || !state.iter().copied().all(base64url)
                    || state.as_slice() != original_state
                {
                    return Err(());
                }
            }
            QueryKey::Code => {
                let value = decode_bytes(raw_value, CODE_LIMIT)?;
                if value.is_empty() || !value.iter().copied().all(graphic) {
                    return Err(());
                }
                code = Some(value);
            }
            QueryKey::Error => {
                let value = decode_bytes(raw_value, 128)?;
                if value.is_empty() || !value.iter().copied().all(graphic) {
                    return Err(());
                }
                error = Some(if value.as_slice() == b"access_denied" {
                    CallbackErrorKind::AuthorizationDenied
                } else {
                    CallbackErrorKind::AuthorizationRejected
                });
            }
            QueryKey::Description => {
                let value = decode_bytes(raw_value, DESCRIPTION_LIMIT)?;
                let text = std::str::from_utf8(&value).map_err(|_| ())?;
                if text
                    .chars()
                    .any(|c| matches!(u32::from(c), 0..=31 | 127..=159))
                {
                    return Err(());
                }
            }
        }
    }
    match (code, error) {
        (Some(value), None) => Ok(CallbackValue::Code(value)),
        (None, Some(kind)) => Ok(CallbackValue::Error(kind)),
        _ => Err(()),
    }
}
fn trim_header(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        value = &value[1..];
    }
    while value.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}
fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
fn head_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|b| b == b"\r\n\r\n").map(|n| n + 4)
}
fn broken_crlf(raw: &[u8]) -> bool {
    raw.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\n' && (index == 0 || raw[index - 1] != b'\r'))
            || (*byte == b'\r' && raw.get(index + 1).is_some_and(|next| *next != b'\n'))
    })
}
fn parse_head(raw: &[u8], actual_port: u16, original_state: &[u8]) -> RequestOutcome {
    let bad = || RequestOutcome::Probe(ProbeStatus::BadRequest);
    if raw.len() > HEAD_LIMIT || actual_port == 0 || head_end(raw) != Some(raw.len()) {
        return bad();
    }
    let Some(line_end) = raw.windows(2).position(|b| b == b"\r\n") else {
        return bad();
    };
    let line = &raw[..line_end];
    let Some(first) = line.iter().position(|b| *b == b' ') else {
        return bad();
    };
    let Some(second) = line[first + 1..]
        .iter()
        .position(|b| *b == b' ')
        .map(|n| first + 1 + n)
    else {
        return bad();
    };
    let method = &line[..first];
    let target = &line[first + 1..second];
    let version = &line[second + 1..];
    if method.is_empty()
        || !method.iter().copied().all(token)
        || target.is_empty()
        || !target.iter().copied().all(graphic)
        || version != b"HTTP/1.1"
        || target.first() != Some(&b'/')
        || target.contains(&b'#')
    {
        return bad();
    }
    let expected_host = format!("127.0.0.1:{actual_port}");
    let mut host_seen = false;
    let mut cl_seen = false;
    let mut headers = 0;
    let mut cursor = line_end + 2;
    while cursor < raw.len() - 2 {
        let Some(end) = raw[cursor..]
            .windows(2)
            .position(|b| b == b"\r\n")
            .map(|n| cursor + n)
        else {
            return bad();
        };
        let header = &raw[cursor..end];
        if header.is_empty() {
            return bad();
        }
        headers += 1;
        if headers > HEADER_LIMIT || end + 2 - cursor > HEADER_LINE_LIMIT {
            return bad();
        }
        let Some(colon) = header.iter().position(|b| *b == b':') else {
            return bad();
        };
        let name = &header[..colon];
        let value = &header[colon + 1..];
        if name.is_empty()
            || !name.iter().copied().all(token)
            || !value
                .iter()
                .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
        {
            return bad();
        }
        if name.eq_ignore_ascii_case(b"Host") {
            if host_seen || trim_header(value) != expected_host.as_bytes() {
                return bad();
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            return bad();
        } else if name.eq_ignore_ascii_case(b"Content-Length") {
            if cl_seen || trim_header(value) != b"0" {
                return bad();
            }
            cl_seen = true;
        }
        cursor = end + 2;
    }
    if cursor != raw.len() - 2 || !host_seen {
        return bad();
    }
    if method != b"GET" {
        return RequestOutcome::Probe(ProbeStatus::MethodNotAllowed);
    }
    let Some(question) = target.iter().position(|b| *b == b'?') else {
        return if target == b"/callback" {
            bad()
        } else {
            RequestOutcome::Probe(ProbeStatus::NotFound)
        };
    };
    if &target[..question] != b"/callback" {
        return RequestOutcome::Probe(ProbeStatus::NotFound);
    }
    match parse_query(&target[question + 1..], original_state) {
        Ok(value) => RequestOutcome::Terminal(value),
        Err(()) => bad(),
    }
}
fn accept_allowed(occupied: usize) -> bool {
    occupied < CONNECTION_LIMIT
}

fn current_sync(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    registered: &RegisteredAttemptOwner,
) -> Result<super::super::ClockSample, CallbackError> {
    let gate = journal
        .callback_registered_gate(auth, registered)
        .map_err(CallbackError::callback_journal)?;
    let issuer = journal
        .issuer
        .get()
        .ok_or_else(|| CallbackError::new(CallbackErrorKind::Unavailable))?;
    let binding = auth
        .request_binding()
        .ok_or_else(|| CallbackError::new(CallbackErrorKind::Refused))?;
    if !issuer.observation().is_current()
        || !issuer.owns_identity(binding.identity())
        || !binding
            .identity()
            .same_binding(&registered.binding.identity)
    {
        return Err(CallbackError::new(CallbackErrorKind::Refused));
    }
    let observation = binding
        .borrow_gateway_authorization_host_before(auth, &gate, gate.deadline().into_std())
        .map_err(|error| CallbackError::callback_journal(host_error(error)))?;
    if !matches!(
        observation.kind(),
        HostRequestBindingKind::ServerSession | HostRequestBindingKind::ServerSingleUserOwner
    ) || observation.kind() != binding.kind()
        || !issuer.owns_identity(observation.identity())
        || !observation
            .identity()
            .same_binding(&registered.binding.identity)
        || !issuer.observation().is_current()
    {
        return Err(CallbackError::new(CallbackErrorKind::Refused));
    }
    drop(observation);
    gate.check().map_err(CallbackError::callback_journal)
}
fn checked_poll<T>(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    registered: &RegisteredAttemptOwner,
    connection_cap: Option<Instant>,
    operation: impl FnOnce() -> Poll<T>,
) -> Result<Option<Poll<T>>, CallbackError> {
    let before = current_sync(journal, auth, registered)?;
    if connection_cap.is_some_and(|cap| before.mono >= cap) {
        return Ok(None);
    }
    let result = operation();
    // Include Pending; the actual observation is always borrowed anew and dropped.
    let after = current_sync(journal, auth, registered)?;
    if connection_cap.is_some_and(|cap| after.mono >= cap) {
        return Ok(None);
    }
    Ok(Some(result))
}

pub(super) async fn start_callback(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    metadata: GatewayDesktopMetadata,
    original_parent: CancellationToken,
    caller_deadline: std::time::Instant,
    factory: &GatewayTransportFactory,
) -> Result<GatewayAuthorizationCallbackWaitOwner, CallbackError> {
    journal
        .check_scope(auth)
        .map_err(|error| CallbackError::journal(CallbackStage::Create, error))?;
    let clock: ClockOwner = Arc::new(SystemClock);
    let flow = SavedFlow::new(clock, original_parent, caller_deadline)
        .map_err(|error| CallbackError::journal(CallbackStage::Create, error))?;
    let listener = {
        let gate = OperationGate {
            journal,
            auth,
            flow: &flow,
            initial: None,
        };
        gate.io(
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            |_| Error::new(Kind::Unavailable),
        )
        .await
        .map_err(|error| CallbackError::journal(CallbackStage::Create, error))?
    };
    let address = listener.local_addr().map_err(|_| {
        CallbackError::journal(CallbackStage::Create, Error::new(Kind::Unavailable))
    })?;
    let std::net::SocketAddr::V4(address) = address else {
        return Err(CallbackError::journal(
            CallbackStage::Create,
            Error::new(Kind::Refused),
        ));
    };
    if *address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(CallbackError::journal(
            CallbackStage::Create,
            Error::new(Kind::Refused),
        ));
    }
    let redirect = Zeroizing::new(format!("http://127.0.0.1:{}/callback", address.port()));
    let input = callback_registration_input(metadata, redirect, &flow.clock)
        .map_err(|error| CallbackError::journal(CallbackStage::Create, initial_error(error)))?;
    let created = journal
        .create_from_input_and_flow(auth, input, flow)
        .await
        .map_err(|error| CallbackError::journal(CallbackStage::Create, error))?;
    let admitted = journal
        .admit_registration(auth, created)
        .await
        .map_err(|error| CallbackError::journal(CallbackStage::Admission, error))?;
    let registered = journal
        .register_admitted(auth, admitted, factory)
        .await
        .map_err(CallbackError::registration)?;
    current_sync(journal, auth, &registered)?;
    let material = callback_pkce_material()
        .map_err(|error| CallbackError::callback_journal(initial_error(error)))?;
    let mut url_offer = Some(
        callback_authorization_url(&registered.reply, &material)
            .map_err(|error| CallbackError::callback_journal(initial_error(error)))?,
    );
    {
        // Take before any handoff attempt, including a missing port. There is no retry path.
        let url = url_offer
            .take()
            .ok_or_else(|| CallbackError::new(CallbackErrorKind::Refused))?;
        let gate = journal
            .callback_registered_gate(auth, &registered)
            .map_err(CallbackError::callback_journal)?;
        let issuer = journal
            .issuer
            .get()
            .ok_or_else(|| CallbackError::new(CallbackErrorKind::Unavailable))?;
        let binding = auth
            .request_binding()
            .ok_or_else(|| CallbackError::new(CallbackErrorKind::Refused))?;
        let observation = binding
            .borrow_gateway_authorization_host_before(auth, &gate, gate.deadline().into_std())
            .map_err(|error| CallbackError::callback_journal(host_error(error)))?;
        if observation.kind() != binding.kind()
            || !issuer.owns_identity(observation.identity())
            || !observation
                .identity()
                .same_binding(&registered.binding.identity)
            || !issuer.observation().is_current()
        {
            return Err(CallbackError::new(CallbackErrorKind::Refused));
        }
        let invocation = issuer
            .gateway_callback_url_invocation(&registered.binding.identity, url.as_str())
            .map_err(|error| CallbackError::callback_journal(host_error(error)))?;
        observation
            .handoff_callback_url(auth, &gate, invocation, gate.deadline().into_std())
            .map_err(|error| CallbackError::callback_journal(host_error(error)))?;
        drop(observation);
    }
    current_sync(journal, auth, &registered)?;
    Ok(GatewayAuthorizationCallbackWaitOwner {
        registered,
        listener,
        material,
        url_offer,
    })
}

enum ResponseStep {
    Write,
    Flush,
    Shutdown,
}
struct ResponseState {
    bytes: &'static [u8],
    offset: usize,
    step: ResponseStep,
}
impl ResponseState {
    fn new(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            step: ResponseStep::Write,
        }
    }
}
enum ConnectionPhase {
    Read,
    Response(ResponseState),
}
struct OwnedConnection {
    stream: TcpStream,
    head: Zeroizing<Vec<u8>>,
    filled: usize,
    cap: Instant,
    timer: Pin<Box<Sleep>>,
    phase: ConnectionPhase,
}
impl OwnedConnection {
    fn new(stream: TcpStream, cap: Instant) -> Self {
        let mut head = Zeroizing::new(Vec::with_capacity(HEAD_CAPACITY));
        head.resize(HEAD_CAPACITY, 0);
        Self {
            stream,
            head,
            filled: 0,
            cap,
            timer: Box::pin(tokio::time::sleep_until(cap)),
            phase: ConnectionPhase::Read,
        }
    }
}
enum ProbeProgress {
    Pending,
    Closed,
    Terminal(CallbackValue),
}
struct TerminalMatch {
    stream: TcpStream,
    cap: Instant,
    value: CallbackValue,
}

fn poll_response(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    registered: &RegisteredAttemptOwner,
    stream: &mut TcpStream,
    cap: Instant,
    state: &mut ResponseState,
    cx: &mut Context<'_>,
) -> Result<Option<Poll<Result<(), std::io::Error>>>, CallbackError> {
    loop {
        match state.step {
            ResponseStep::Write if state.offset == state.bytes.len() => {
                state.step = ResponseStep::Flush;
            }
            ResponseStep::Write => {
                let result = checked_poll(journal, auth, registered, Some(cap), || {
                    Pin::new(&mut *stream).poll_write(cx, &state.bytes[state.offset..])
                })?;
                return Ok(match result {
                    Some(Poll::Ready(Ok(written)))
                        if written != 0 && written <= state.bytes.len() - state.offset =>
                    {
                        state.offset += written;
                        checked_poll(journal, auth, registered, Some(cap), || {
                            cx.waker().wake_by_ref();
                            Poll::<Result<(), std::io::Error>>::Pending
                        })?
                    }
                    Some(Poll::Ready(Ok(_))) => Some(Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::WriteZero,
                    )))),
                    Some(Poll::Ready(Err(error))) => Some(Poll::Ready(Err(error))),
                    Some(Poll::Pending) => Some(Poll::Pending),
                    None => None,
                });
            }
            ResponseStep::Flush => {
                match checked_poll(journal, auth, registered, Some(cap), || {
                    Pin::new(&mut *stream).poll_flush(cx)
                })? {
                    Some(Poll::Ready(Ok(()))) => {
                        state.step = ResponseStep::Shutdown;
                    }
                    other => return Ok(other),
                }
            }
            ResponseStep::Shutdown => {
                return checked_poll(journal, auth, registered, Some(cap), || {
                    Pin::new(&mut *stream).poll_shutdown(cx)
                });
            }
        }
    }
}
fn poll_connection(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    registered: &RegisteredAttemptOwner,
    connection: &mut OwnedConnection,
    actual_port: u16,
    original_state: &[u8],
    cx: &mut Context<'_>,
) -> Result<ProbeProgress, CallbackError> {
    match checked_poll(journal, auth, registered, Some(connection.cap), || {
        connection.timer.as_mut().poll(cx)
    })? {
        None | Some(Poll::Ready(())) => return Ok(ProbeProgress::Closed),
        Some(Poll::Pending) => {}
    }
    match &mut connection.phase {
        ConnectionPhase::Read => {
            let mut read = ReadBuf::new(&mut connection.head[connection.filled..]);
            match checked_poll(journal, auth, registered, Some(connection.cap), || {
                Pin::new(&mut connection.stream).poll_read(cx, &mut read)
            })? {
                None | Some(Poll::Ready(Err(_))) => return Ok(ProbeProgress::Closed),
                Some(Poll::Pending) => return Ok(ProbeProgress::Pending),
                Some(Poll::Ready(Ok(()))) => {}
            }
            let size = read.filled().len();
            if size == 0 {
                return Ok(ProbeProgress::Closed);
            }
            connection.filled += size;
            let raw = &connection.head[..connection.filled];
            let outcome = if broken_crlf(raw) {
                Some(RequestOutcome::Probe(ProbeStatus::BadRequest))
            } else if head_end(raw).is_some() {
                Some(parse_head(raw, actual_port, original_state))
            } else if raw.len() >= HEAD_LIMIT {
                Some(RequestOutcome::Probe(ProbeStatus::BadRequest))
            } else {
                None
            };
            // Parsing cannot renew the accepted cap or reserve under a stale current observation.
            let after_parse = current_sync(journal, auth, registered)?;
            if after_parse.mono >= connection.cap {
                return Ok(ProbeProgress::Closed);
            }
            match outcome {
                Some(RequestOutcome::Terminal(value)) => return Ok(ProbeProgress::Terminal(value)),
                Some(RequestOutcome::Probe(status)) => {
                    connection.phase =
                        ConnectionPhase::Response(ResponseState::new(status.response()));
                }
                None => {}
            }
            match checked_poll(journal, auth, registered, Some(connection.cap), || {
                cx.waker().wake_by_ref();
                Poll::<()>::Pending
            })? {
                None => Ok(ProbeProgress::Closed),
                Some(_) => Ok(ProbeProgress::Pending),
            }
        }
        ConnectionPhase::Response(state) => {
            match poll_response(
                journal,
                auth,
                registered,
                &mut connection.stream,
                connection.cap,
                state,
                cx,
            )? {
                None | Some(Poll::Ready(_)) => Ok(ProbeProgress::Closed),
                Some(Poll::Pending) => Ok(ProbeProgress::Pending),
            }
        }
    }
}
async fn finish_response(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    registered: &RegisteredAttemptOwner,
    mut stream: TcpStream,
    cap: Instant,
    response: &'static [u8],
    ack: Ack,
) -> Result<(), CallbackError> {
    let cancel = registered.binding.flow.original_parent.cancelled();
    tokio::pin!(cancel);
    let mut timer = Box::pin(tokio::time::sleep_until(cap));
    let mut state = ResponseState::new(response);
    let result = poll_fn(|cx| {
        match checked_poll(journal, auth, registered, Some(cap), || {
            cancel.as_mut().poll(cx)
        }) {
            Err(error) => return Poll::Ready(Err(error.with_readback(ack))),
            Ok(None) => {
                return Poll::Ready(Err(
                    CallbackError::new(CallbackErrorKind::Deadline).with_readback(ack)
                ));
            }
            Ok(Some(Poll::Ready(()))) => {
                return Poll::Ready(Err(
                    CallbackError::new(CallbackErrorKind::Cancelled).with_readback(ack)
                ));
            }
            Ok(Some(Poll::Pending)) => {}
        }
        match checked_poll(journal, auth, registered, Some(cap), || {
            timer.as_mut().poll(cx)
        }) {
            Err(error) => return Poll::Ready(Err(error.with_readback(ack))),
            Ok(None | Some(Poll::Ready(()))) => {
                return Poll::Ready(Err(
                    CallbackError::new(CallbackErrorKind::Deadline).with_readback(ack)
                ));
            }
            Ok(Some(Poll::Pending)) => {}
        }
        match poll_response(journal, auth, registered, &mut stream, cap, &mut state, cx) {
            Err(error) => Poll::Ready(Err(error.with_readback(ack))),
            Ok(None) => Poll::Ready(Err(
                CallbackError::new(CallbackErrorKind::Deadline).with_readback(ack)
            )),
            Ok(Some(Poll::Ready(Err(_)))) => Poll::Ready(Err(CallbackError::new(
                CallbackErrorKind::CallbackIo,
            )
            .with_readback(ack))),
            Ok(Some(Poll::Ready(Ok(())))) => Poll::Ready(Ok(())),
            Ok(Some(Poll::Pending)) => Poll::Pending,
        }
    })
    .await;
    drop(stream);
    result
}

pub(super) async fn wait_callback(
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    owner: GatewayAuthorizationCallbackWaitOwner,
) -> Result<GatewayAuthorizationVerifiedCodeOwner, CallbackError> {
    let GatewayAuthorizationCallbackWaitOwner {
        registered,
        listener,
        material,
        url_offer,
    } = owner;
    if url_offer.is_some() {
        return Err(CallbackError::new(CallbackErrorKind::Refused));
    }
    current_sync(journal, auth, &registered)?;
    let address = listener
        .local_addr()
        .map_err(|_| CallbackError::new(CallbackErrorKind::CallbackIo))?;
    if !address.is_ipv4()
        || address.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        || address.port() == 0
    {
        return Err(CallbackError::new(CallbackErrorKind::Refused));
    }
    let port = address.port();
    let mut slots: [Option<OwnedConnection>; CONNECTION_LIMIT] = std::array::from_fn(|_| None);
    let terminal = {
        let cancel = registered.binding.flow.original_parent.cancelled();
        tokio::pin!(cancel);
        let flow_cap = registered.binding.flow.cap(None);
        let mut timer = Box::pin(tokio::time::sleep_until(flow_cap));
        poll_fn(|cx| {
            match checked_poll(journal, auth, &registered, None, || {
                cancel.as_mut().poll(cx)
            }) {
                Err(error) => return Poll::Ready(Err(error)),
                Ok(Some(Poll::Ready(()))) => {
                    return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::Cancelled)));
                }
                Ok(Some(Poll::Pending)) => {}
                Ok(None) => {
                    return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::Refused)));
                }
            }
            match checked_poll(journal, auth, &registered, None, || timer.as_mut().poll(cx)) {
                Err(error) => return Poll::Ready(Err(error)),
                Ok(Some(Poll::Ready(()))) => {
                    return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::Deadline)));
                }
                Ok(Some(Poll::Pending)) => {}
                Ok(None) => {
                    return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::Refused)));
                }
            }
            for index in 0..slots.len() {
                let progress = match slots[index].as_mut() {
                    Some(connection) => poll_connection(
                        journal,
                        auth,
                        &registered,
                        connection,
                        port,
                        material.state.as_bytes(),
                        cx,
                    ),
                    None => continue,
                };
                match progress {
                    Err(error) => return Poll::Ready(Err(error)),
                    Ok(ProbeProgress::Closed) => {
                        slots[index] = None;
                    }
                    Ok(ProbeProgress::Pending) => {}
                    Ok(ProbeProgress::Terminal(value)) => {
                        let Some(connection) = slots[index].take() else {
                            return Poll::Ready(Err(CallbackError::new(
                                CallbackErrorKind::Refused,
                            )));
                        };
                        let OwnedConnection {
                            stream,
                            cap,
                            head,
                            timer: connection_timer,
                            ..
                        } = connection;
                        drop(head);
                        drop(connection_timer);
                        // Local terminal reservation is this unique move; never poll accept again.
                        for slot in &mut slots {
                            *slot = None;
                        }
                        return Poll::Ready(Ok(TerminalMatch { stream, cap, value }));
                    }
                }
            }
            let occupied = slots.iter().filter(|slot| slot.is_some()).count();
            // At four this branch does not call poll_accept, even when kernel backlog is ready.
            if accept_allowed(occupied) {
                let mut accepted_mono = None;
                match checked_poll(journal, auth, &registered, None, || {
                    let result = listener.poll_accept(cx);
                    if matches!(&result, Poll::Ready(Ok(_))) {
                        accepted_mono = Some(registered.binding.flow.clock.sample().mono);
                    }
                    result
                }) {
                    Err(error) => return Poll::Ready(Err(error)),
                    Ok(Some(Poll::Ready(Err(_)))) => {
                        return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::CallbackIo)));
                    }
                    Ok(Some(Poll::Ready(Ok((stream, _))))) => {
                        let Some(accepted) = accepted_mono else {
                            return Poll::Ready(Err(CallbackError::new(
                                CallbackErrorKind::Refused,
                            )));
                        };
                        let Some(cap) = accepted
                            .checked_add(CONNECTION_BUDGET)
                            .map(|cap| cap.min(flow_cap))
                        else {
                            return Poll::Ready(Err(CallbackError::new(
                                CallbackErrorKind::Deadline,
                            )));
                        };
                        let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) else {
                            return Poll::Ready(Err(CallbackError::new(
                                CallbackErrorKind::Refused,
                            )));
                        };
                        *slot = Some(OwnedConnection::new(stream, cap));
                        match checked_poll(journal, auth, &registered, Some(cap), || {
                            cx.waker().wake_by_ref();
                            Poll::<()>::Pending
                        }) {
                            Err(error) => return Poll::Ready(Err(error)),
                            Ok(None) => *slot = None,
                            Ok(Some(_)) => {}
                        }
                    }
                    Ok(Some(Poll::Pending)) => {}
                    Ok(None) => {
                        return Poll::Ready(Err(CallbackError::new(CallbackErrorKind::Refused)));
                    }
                }
            }
            match current_sync(journal, auth, &registered) {
                Ok(_) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await?
    };
    drop(slots);
    drop(listener);
    let TerminalMatch { stream, cap, value } = terminal;
    match value {
        CallbackValue::Error(kind) => {
            finish_response(
                journal,
                auth,
                &registered,
                stream,
                cap,
                RESPONSE_ERROR,
                Ack::NotAttempted,
            )
            .await?;
            let final_sample = current_sync(journal, auth, &registered)?;
            if final_sample.mono >= cap {
                return Err(CallbackError::new(CallbackErrorKind::Deadline));
            }
            Err(CallbackError::new(kind))
        }
        CallbackValue::Code(code) => {
            let before_readback = current_sync(journal, auth, &registered)?;
            if before_readback.mono >= cap {
                return Err(CallbackError::new(CallbackErrorKind::Deadline));
            }
            {
                let gate = journal
                    .callback_registered_gate(auth, &registered)
                    .map_err(CallbackError::callback_journal)?;
                authority_sql::readback_exact(
                    journal,
                    auth,
                    &registered.binding.identity,
                    &registered.binding.expected,
                    &gate,
                )
                .await
                .map_err(CallbackError::readback)?;
            }
            // Only the original RO returned successfully; no callback write has occurred.
            let ack = Ack::Timely;
            finish_response(journal, auth, &registered, stream, cap, RESPONSE_CODE, ack).await?;
            enum CodeCompletion {
                YieldAfterStreamDrop,
                FinalDelivery,
            }
            let mut completion = CodeCompletion::YieldAfterStreamDrop;
            poll_fn(|cx| match completion {
                CodeCompletion::YieldAfterStreamDrop => {
                    // The original stream has been shut down and dropped. This
                    // one bounded wake stays inside the original current bookends.
                    match checked_poll(journal, auth, &registered, Some(cap), || {
                        completion = CodeCompletion::FinalDelivery;
                        cx.waker().wake_by_ref();
                        Poll::<Result<(), CallbackError>>::Pending
                    }) {
                        Ok(Some(result)) => result,
                        Ok(None) => Poll::Ready(Err(CallbackError::new(
                            CallbackErrorKind::Deadline,
                        )
                        .with_readback(ack))),
                        Err(error) => Poll::Ready(Err(error.with_readback(ack))),
                    }
                }
                CodeCompletion::FinalDelivery => {
                    // Both fresh checks belong to this resumed delivery phase.
                    // The armed original owner is not moved on this provisional decision.
                    let before = match current_sync(journal, auth, &registered) {
                        Ok(sample) => sample,
                        Err(error) => return Poll::Ready(Err(error.with_readback(ack))),
                    };
                    if before.mono >= cap {
                        return Poll::Ready(Err(
                            CallbackError::new(CallbackErrorKind::Deadline).with_readback(ack)
                        ));
                    }
                    let delivery = Ok(());
                    let after = match current_sync(journal, auth, &registered) {
                        Ok(sample) => sample,
                        Err(error) => return Poll::Ready(Err(error.with_readback(ack))),
                    };
                    if after.mono >= cap {
                        return Poll::Ready(Err(
                            CallbackError::new(CallbackErrorKind::Deadline).with_readback(ack)
                        ));
                    }
                    // This postcheck is authoritative; there is no later await,
                    // wake or I/O before the original whole-owner move.
                    Poll::Ready(delivery)
                }
            })
            .await?;
            let CallbackPkceMaterial {
                state,
                verifier,
                challenge,
            } = material;
            drop(state);
            drop(challenge);
            Ok(GatewayAuthorizationVerifiedCodeOwner {
                _registered: registered,
                _code: code,
                _verifier: verifier,
            })
        }
    }
}

#[cfg(test)]
mod tests;
