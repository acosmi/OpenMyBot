//! Fixed token core vectors. Synthetic clocks and closed controls prove no Host/PG grant.
use super::*;
use crate::gateway_account::{GatewayAccountClient, GatewayDesktopMetadata};
use crate::gateway_authorization::{
    ClockOwner, ClockSample, InitialClock, InitialError, InitialReplyWitness,
    PreparedInitialOwner, token_code_input_same_clock, owned_registration_input,
    transfer_code_request,
};
use crate::gateway_authorization::journal::SavedFlow;
use crate::gateway_transport::*;
use crate::net::safe_http::{CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_core::Stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE};
use std::{
    collections::VecDeque, net::SocketAddr, pin::Pin,
    sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}},
    task::{Context, Poll, Waker}, time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://unit.invalid";
const REDIRECT: &str = "http://127.0.0.1:43132/callback";
const TOKEN_JSON: &[u8] = br#"{"access_token":"access-vector","token_type":"Bearer","expires_in":59,"refresh_token":"refresh-vector","scope":"ai account"}"#;

struct Clock(Mutex<ClockSample>);
impl InitialClock for Clock {
    fn sample(&self) -> ClockSample { *self.0.lock().unwrap() }
}
impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(ClockSample {
            wall: DateTime::from_timestamp(1_000, 900_123_456).unwrap(),
            mono: Instant::now(),
        })))
    }
    fn set(&self, wall: DateTime<Utc>, mono: Instant) {
        *self.0.lock().unwrap() = ClockSample { wall, mono };
    }
}
#[derive(Default)]
struct Probe { polls: AtomicUsize, drops: AtomicUsize }
struct Body {
    chunks: VecDeque<Result<Bytes, TransportError>>,
    pending: bool,
    probe: Arc<Probe>,
}
impl Stream for Body {
    type Item = Result<Bytes, TransportError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if this.pending {
            this.pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else { Poll::Ready(this.chunks.pop_front()) }
    }
}
impl Drop for Body {
    fn drop(&mut self) { self.probe.drops.fetch_add(1, Ordering::SeqCst); }
}
fn response(status: u16, chunks: Vec<Result<Bytes, TransportError>>, pending: bool) -> (acosmi::HttpResponse, Arc<Probe>) {
    let probe = Arc::new(Probe::default());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    (acosmi::HttpResponse {
        status: StatusCode::from_u16(status).unwrap(), headers,
        body: Box::pin(Body { chunks: chunks.into(), pending, probe: probe.clone() }),
    }, probe)
}
struct Metadata;
#[async_trait]
impl acosmi::HttpTransport for Metadata {
    async fn execute(&self, request: acosmi::HttpRequest, parent: CancellationToken) -> Result<acosmi::HttpResponse, TransportError> {
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.url.as_str(), "https://unit.invalid/.well-known/oauth-authorization-server/desktop");
        assert!(!parent.is_cancelled());
        Ok(response(200, vec![Ok(Bytes::from_static(br#"{"issuer":"https://unit.invalid","authorization_endpoint":"https://unit.invalid/oauth/desktop/authorize","token_endpoint":"https://unit.invalid/oauth/desktop/token","registration_endpoint":"https://unit.invalid/oauth/desktop/register","revocation_endpoint":"https://unit.invalid/oauth/desktop/revoke","scopes_supported":["ai","account"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"grant_types_supported":["authorization_code","refresh_token"],"crabcode_auth_contract_version":2,"gateway_error_contract_version":1}"#))], false).0)
    }
}
async fn metadata() -> GatewayDesktopMetadata {
    GatewayAccountClient::new(ORIGIN, Arc::new(Metadata)).unwrap()
        .fetch_metadata(CancellationToken::new()).await.unwrap()
}
struct Core { prepared: PreparedInitialOwner, flow: SavedFlow, clock: Arc<Clock>, parent: CancellationToken }
async fn core(code: bool, duration: Duration) -> Core {
    let clock = Clock::new();
    let parent = CancellationToken::new();
    let flow = SavedFlow::new(clock.clone(), parent.clone(), (clock.sample().mono + duration).into_std()).unwrap();
    let original_clock: ClockOwner = clock.clone();
    let mut input = if code {
        token_code_input_same_clock(metadata().await, Zeroizing::new("original-client".into()),
            Zeroizing::new("synthetic-code".into()), Zeroizing::new(REDIRECT.into()),
            Zeroizing::new("v".repeat(43)), &original_clock).unwrap()
    } else { owned_registration_input(metadata().await, Zeroizing::new(REDIRECT.into())).unwrap() };
    input.clock = original_clock;
    let prepared = prepare_initial(input, retain_parent_budget(parent.clone(), flow.deadline)).await.unwrap();
    Core { prepared, flow, clock, parent }
}
fn registered() -> Row {
    let stamp = time::OffsetDateTime::from_unix_timestamp(1_000).unwrap();
    Row {
        attempt_id: Uuid::parse_str("019a0320-0000-7000-8abc-000000000032").unwrap(),
        journal_schema: 1, deployment_id: "unit-deployment".into(), tenant_id: "unit-tenant".into(),
        owner_user_id: "unit-owner".into(), auth_generation: 7,
        installation_id: "32".repeat(32), runtime_epoch: "33".repeat(32),
        issuer: ORIGIN.into(), redirect_uri: REDIRECT.into(), phase: "registered".into(),
        client_id: Some("original-client".into()),
        enrollment_id: Some(Uuid::parse_str("019a0320-0000-7000-8abc-000000000033").unwrap()),
        registration_admitted_at: Some(stamp), code_admitted_at: None,
        created_at: stamp, expires_at: stamp + time::Duration::seconds(180),
        updated_at: stamp, finished_at: None, outcome_code: None,
    }
}

#[test]
fn p01_token_alloc_move() {
    let mut valid = Zeroizing::new(Vec::with_capacity(96));
    valid.extend_from_slice(b"original-code");
    let original = (valid.as_ptr(), valid.len(), valid.capacity());
    let mut moved = callback::move_code_storage(valid).unwrap();
    assert_eq!((moved.as_ptr(), moved.len(), moved.capacity()), original);
    assert_eq!(moved.as_str(), "original-code");
    moved.as_mut_str().zeroize();
    assert!(moved.as_bytes().iter().all(|b| *b == 0));
    let mut invalid = Zeroizing::new(Vec::with_capacity(96));
    invalid.extend_from_slice(&[b'a', 0xff, b'z']);
    let original = (invalid.as_ptr(), invalid.len(), invalid.capacity());
    let mut rearmed = callback::move_code_storage(invalid).unwrap_err();
    assert_eq!((rearmed.as_ptr(), rearmed.len(), rearmed.capacity()), original);
    rearmed.as_mut_slice().zeroize();
    assert_eq!(rearmed.as_slice(), &[0, 0, 0]);
}

#[test]
fn p02_token_full20() {
    let old = registered();
    for stamp in [old.updated_at, old.updated_at + time::Duration::microseconds(11)] {
        let actual = code_admitted_row(&old, stamp).unwrap();
        let mut expected = registered();
        expected.phase = "code_admitted".into();
        expected.code_admitted_at = Some(stamp);
        expected.updated_at = stamp;
        assert_eq!(actual, expected);
        assert_eq!(old, registered());
    }
    for stamp in [old.updated_at - time::Duration::microseconds(1), old.expires_at] {
        assert!(code_admitted_row(&old, stamp).is_err());
    }
    for index in 0..12 {
        let mut wrong = registered();
        match index {
            0 => wrong.phase = "created".into(),
            1 => wrong.client_id = None,
            2 => wrong.enrollment_id = None,
            3 => wrong.client_id = Some("client\nbad".into()),
            4 => wrong.enrollment_id = Some(Uuid::nil()),
            5 => wrong.registration_admitted_at = None,
            6 => wrong.registration_admitted_at = Some(old.created_at - time::Duration::microseconds(1)),
            7 => wrong.code_admitted_at = Some(old.updated_at),
            8 => wrong.finished_at = Some(old.updated_at),
            9 => wrong.outcome_code = Some("refused".into()),
            10 => wrong.journal_schema = 2,
            _ => wrong.attempt_id = Uuid::nil(),
        }
        assert!(code_admitted_row(&wrong, old.updated_at).is_err());
    }
    // Full Row equality is the pre-CAS predicate; change each of twenty fields.
    for index in 0..20 {
        let mut wrong = registered();
        match index {
            0 => wrong.attempt_id = Uuid::parse_str("019a0320-0000-7000-8abc-000000000034").unwrap(),
            1 => wrong.journal_schema = 2,
            2 => wrong.deployment_id = "other-deployment".into(),
            3 => wrong.tenant_id = "other-tenant".into(),
            4 => wrong.owner_user_id = "other-owner".into(),
            5 => wrong.auth_generation = 8,
            6 => wrong.installation_id = "34".repeat(32),
            7 => wrong.runtime_epoch = "35".repeat(32),
            8 => wrong.issuer = "https://other.invalid".into(),
            9 => wrong.redirect_uri = "http://127.0.0.1:43132/other".into(),
            10 => wrong.phase = "code_admitted".into(),
            11 => wrong.client_id = Some("other-client".into()),
            12 => wrong.enrollment_id = Some(Uuid::parse_str("019a0320-0000-7000-8abc-000000000035").unwrap()),
            13 => wrong.registration_admitted_at = None,
            14 => wrong.code_admitted_at = Some(old.updated_at),
            15 => wrong.created_at -= time::Duration::microseconds(1),
            16 => wrong.expires_at -= time::Duration::seconds(1),
            17 => wrong.updated_at += time::Duration::microseconds(1),
            18 => wrong.finished_at = Some(old.updated_at),
            _ => wrong.outcome_code = Some("refused".into()),
        }
        assert_ne!(wrong, old, "independently changed field {index}");
    }
}

#[tokio::test]
async fn p03_token_caps() {
    let f = core(false, Duration::from_secs(500)).await;
    let old_budget = f.prepared.budget.as_ref().unwrap();
    assert_eq!(f.flow.deadline, f.flow.start.mono + Duration::from_secs(180));
    assert_eq!(old_budget.deadline, f.flow.start.mono + Duration::from_secs(10));
    let later = f.flow.start.mono + Duration::from_secs(11);
    let wall = f.flow.start.wall + chrono::Duration::seconds(11);
    f.clock.set(wall, later);
    assert_eq!(old_budget.check(&f.prepared.clock).err(), Some(InitialError::Deadline));
    assert!(f.flow.check(None).is_ok());
    let clock: ClockOwner = f.clock.clone();
    let input = token_code_input_same_clock(metadata().await, Zeroizing::new("original-client".into()),
        Zeroizing::new("synthetic-code".into()), Zeroizing::new(REDIRECT.into()),
        Zeroizing::new("v".repeat(43)), &clock).unwrap();
    let prepared = prepare_initial(input, retain_parent_budget(f.parent.clone(), f.flow.cap(None))).await.unwrap();
    assert!(Arc::ptr_eq(&clock, &prepared.clock));
    let budget = prepared.budget.as_ref().unwrap();
    assert_eq!(budget.http_entered_at, later);
    assert_eq!(budget.deadline, later + Duration::from_secs(10));
    let cap = f.flow.cap(Some(budget));
    assert_eq!(cap, f.flow.start.mono + Duration::from_secs(21));
    f.clock.set(wall, cap);
    assert_eq!(f.flow.check(Some(budget)).err().unwrap().kind(), Kind::Deadline);
    assert_eq!(f.flow.cap(Some(budget)), cap);
    f.clock.set(f.flow.start.wall - chrono::Duration::nanoseconds(1), later);
    assert_eq!(f.flow.check(None).err().unwrap().kind(), Kind::Deadline);
    f.clock.set(wall, f.flow.start.mono - Duration::from_nanos(1));
    assert_eq!(f.flow.check(None).err().unwrap().kind(), Kind::Deadline);
    assert_eq!(canonical_microseconds(DateTime::from_timestamp(-1, 999_999_999).unwrap()).unwrap().unix_timestamp_nanos(), -1_000);
    let overflow = Clock::new();
    overflow.set(DateTime::<Utc>::MAX_UTC, overflow.sample().mono);
    assert!(SavedFlow::new(overflow.clone(), CancellationToken::new(), (overflow.sample().mono + Duration::from_secs(180)).into_std()).is_err());
    for duration in [Duration::from_secs(1), Duration::from_secs(60)] {
        let f = core(true, duration).await;
        let budget = f.prepared.budget.as_ref().unwrap();
        assert_eq!(f.flow.cap(Some(budget)), f.flow.deadline.min(budget.deadline).min(budget.owner_deadline));
        f.parent.cancel();
        assert!(budget.original_parent.is_cancelled());
        assert_eq!(f.flow.check(Some(budget)).err().unwrap().kind(), Kind::Cancelled);
    }
}

#[tokio::test]
async fn p04_token_once_transfer() {
    let f = core(true, Duration::from_secs(60)).await;
    let address = f.prepared.request.as_ref().unwrap().body.as_ptr();
    let original_clock = f.prepared.clock.clone();
    let (request, dispatched) = transfer_code_request(f.prepared).unwrap();
    assert_eq!(request.body.as_ptr(), address);
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.url.as_str(), "https://unit.invalid/oauth/desktop/token");
    assert_eq!(request.context.purpose, acosmi::HttpPurpose::OAuthToken);
    assert!(Arc::ptr_eq(&original_clock, &dispatched.clock));
    let mut form: Vec<_> = url::form_urlencoded::parse(&request.body).into_owned().collect();
    form.sort();
    assert_eq!(form, vec![
        ("client_id".into(), "original-client".into()), ("code".into(), "synthetic-code".into()),
        ("code_verifier".into(), "v".repeat(43)), ("grant_type".into(), "authorization_code".into()),
        ("redirect_uri".into(), REDIRECT.into()),
    ]);
    for vector in 0..15 {
        let mut f = core(true, Duration::from_secs(60)).await;
        match vector {
            0 => f.prepared.request.as_mut().unwrap().method = Method::GET,
            1 => f.prepared.request.as_mut().unwrap().url = "https://unit.invalid/oauth/desktop/register".parse().unwrap(),
            2 => { f.prepared.request.as_mut().unwrap().headers.insert("x-extra", HeaderValue::from_static("poison")); },
            3 => { f.prepared.request.as_mut().unwrap().headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain")); },
            4 => f.prepared.request.as_mut().unwrap().context.purpose = acosmi::HttpPurpose::OAuthRegistration,
            5 => f.prepared.request.as_mut().unwrap().context.response_mode = acosmi::HttpResponseMode::Streaming,
            6 => f.prepared.request.as_mut().unwrap().context.timeout = Duration::from_secs(29),
            7 => f.prepared.request.as_mut().unwrap().body = b"grant_type=authorization_code".to_vec(),
            8 => f.prepared.request = None,
            9 => f.prepared.witness = None,
            10 => f.prepared.budget = None,
            11 => f.prepared.sdk_exit_child = CancellationToken::new(),
            12 => {
                let old = String::from_utf8(f.prepared.request.as_ref().unwrap().body.clone()).unwrap();
                f.prepared.request.as_mut().unwrap().body = old.replace("synthetic-code", "replacement-code").into_bytes();
            }
            13 => {
                let old = String::from_utf8(f.prepared.request.as_ref().unwrap().body.clone()).unwrap();
                f.prepared.request.as_mut().unwrap().body = format!("{old}&code=second").into_bytes();
            }
            _ => {
                let request = f.prepared.request.take().unwrap();
                drop(request);
                assert!(f.prepared.request.take().is_none());
            }
        }
        assert!(matches!(transfer_code_request(f.prepared), Err(InitialError::RequestMismatch)), "poison vector {vector}");
    }
    assert!(matches!(transfer_code_request(core(false, Duration::from_secs(60)).await.prepared), Err(InitialError::RequestMismatch)));
    let (acquire, receive) = oneshot::channel();
    let authority = Arc::new(TokenAuthority::new(acquire));
    let f = core(true, Duration::from_secs(60)).await;
    let (request, _) = transfer_code_request(f.prepared).unwrap();
    let sink = Arc::new(OperationOutcomes::new());
    let dns = Arc::new(AtomicUsize::new(0));
    let transport = factory(true, dns.clone()).for_operation(authority.clone(), sink, f.flow.cap(None), Duration::from_secs(1)).unwrap();
    let reject = async {
        let control = receive.await.unwrap();
        assert_eq!(control.request.kind(), GatewayRequestKind::OAuthToken);
        assert!(!control.request.streaming());
        assert!(control.reply.send(Err(GatewayFenceError::Refused)).is_ok());
    };
    let (first, ()) = tokio::join!(transport.execute(request, f.parent), reject);
    assert!(first.is_err());
    let second = core(true, Duration::from_secs(60)).await;
    let (request, _) = transfer_code_request(second.prepared).unwrap();
    let transport = factory(true, dns.clone()).for_operation(authority, Arc::new(OperationOutcomes::new()), second.flow.cap(None), Duration::from_secs(1)).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(200), transport.execute(request, second.parent)).await.unwrap().is_err());
    assert_eq!(dns.load(Ordering::SeqCst), 0);
}

struct NoDns(Arc<AtomicUsize>);
#[async_trait]
impl DnsResolver for NoDns {
    async fn resolve(&self, _: &str, _: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(DnsUnavailable)
    }
}
struct Refuse(AtomicUsize);
#[async_trait]
impl GatewayHttpAuthority for Refuse {
    async fn before_request(&self, _: GatewayRequestDescriptor, _: CancellationToken) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(GatewayFenceError::Refused)
    }
}
fn factory(oauth: bool, dns: Arc<AtomicUsize>) -> GatewayTransportFactory {
    let endpoints = oauth.then(|| GatewayOAuthEndpoints::new(
        GatewayOAuthProfile::Desktop, "https://unit.invalid/oauth/desktop/register",
        "https://unit.invalid/oauth/desktop/token", Some("https://unit.invalid/oauth/desktop/revoke"),
    ).unwrap());
    GatewayTransportFactory::new(
        SafeDialer::with_resolver(EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap()), Arc::new(NoDns(dns))),
        VerifiedGatewayEndpoints::new(ORIGIN, None, endpoints).unwrap(),
        GatewayTransportLimits::new(Duration::from_secs(10), BODY_LIMIT).unwrap(),
    )
}
async fn minted(after_permit: bool) -> Arc<OperationOutcomes> {
    let f = core(true, Duration::from_secs(60)).await;
    let (request, _) = transfer_code_request(f.prepared).unwrap();
    let (acquire, receive) = oneshot::channel();
    let sink = Arc::new(OperationOutcomes::new());
    let dns = Arc::new(AtomicUsize::new(0));
    let transport = factory(true, dns.clone()).for_operation(Arc::new(TokenAuthority::new(acquire)), sink.clone(), f.flow.cap(None), Duration::from_secs(1)).unwrap();
    let control = async {
        let control = receive.await.unwrap();
        if after_permit {
            let (release, _release_receive) = oneshot::channel();
            let (_ack, ack_receive) = oneshot::channel();
            assert!(control.reply.send(Ok(PermitControl { release, ack: ack_receive })).is_ok());
        } else { assert!(control.reply.send(Err(GatewayFenceError::Refused)).is_ok()); }
    };
    let (result, ()) = tokio::join!(transport.execute(request, f.parent), control);
    assert!(result.is_err());
    assert_eq!(dns.load(Ordering::SeqCst), usize::from(after_permit));
    sink.execute_polled.store(true, Ordering::Release);
    sink
}

#[tokio::test]
async fn p05_token_ack_error() {
    // The real Current::checked uses this same private per-poll bookend and
    // nested-result flattening. Closed predicates here test the typed capture
    // result boundary; they do not assert a Host or PostgreSQL grant.
    for (initial, expected) in [
        (InitialError::ProducerEnded, TokenKind::ProducerEnded),
        (InitialError::RequestMismatch, TokenKind::RequestMismatch),
    ] {
        let original_polls = AtomicUsize::new(0);
        let checks = AtomicUsize::new(0);
        let original = async {
            original_polls.fetch_add(1, Ordering::SeqCst);
            Ok::<Result<PreparedInitialOwner, InitialError>, Error>(Err(initial))
        };
        let mut original = std::pin::pin!(original);
        let capture = std::future::poll_fn(|cx| {
            poll_bookended(
                || { checks.fetch_add(1, Ordering::SeqCst); Ok(()) },
                || original.as_mut().poll(cx),
            ).map(|result| result.and_then(std::convert::identity))
        }).await;
        let outcomes = OperationOutcomes::new();
        let error = capture
            .map_err(|e| History::new().journal(Stage::Capture, &e, &outcomes))
            .and_then(|inner| inner.map_err(|e| History::new().error(Stage::Capture, initial_kind(e), &outcomes)))
            .err().expect("fixed initial capture error");
        assert_eq!(error.kind(), expected);
        assert_eq!(error.stage(), Stage::Capture);
        assert_eq!(error.transport_snapshot(), None);
        assert_eq!((error.code_write_ack(), error.code_readback_ack(), error.token_send_rollback_ack()),
            (Ack::NotAttempted, Ack::NotAttempted, Ack::NotAttempted));
        assert_eq!(original_polls.load(Ordering::SeqCst), 1);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }
    assert_eq!(refusal_kind(false, None), TokenKind::BeforeDispatchRefused);
    assert_eq!(refusal_kind(true, None), TokenKind::TokenUnknown);
    let before = minted(false).await;
    let after = minted(true).await;
    assert_eq!(before.refused_kind(), TokenKind::BeforeDispatchRefused);
    assert_eq!(after.refused_kind(), TokenKind::TokenUnknown);
    assert!(after.snapshot().unwrap().may_have_sent());
    for (write, readback, send) in [
        (Ack::Timely, Ack::Timely, Ack::Timely),
        (Ack::Unknown, Ack::NotAttempted, Ack::NotAttempted),
        (Ack::Timely, Ack::Late, Ack::NotAttempted),
        (Ack::Timely, Ack::Timely, Ack::Unknown),
        (Ack::Late, Ack::Unknown, Ack::Late),
    ] {
        let history = History { write, readback, send };
        for stage in [Stage::Capture, Stage::CodeAdmission, Stage::CodeReadback, Stage::TokenSend, Stage::TokenReply, Stage::FinalHandoff] {
            let error = history.journal(stage, &Error::new(Kind::Refused), &after);
            assert_eq!(error.stage(), stage);
            assert_eq!(error.kind(), TokenKind::TokenUnknown);
            assert_eq!(error.transport_snapshot(), after.snapshot());
            assert_eq!(error.code_write_ack(), write);
            assert_eq!(error.code_readback_ack(), readback);
            assert_eq!(error.token_send_rollback_ack(), send);
            assert_eq!(history.journal(stage, &Error::new(Kind::Cancelled), &after).kind(), TokenKind::Cancelled);
            assert_eq!(history.journal(stage, &Error::new(Kind::Deadline), &after).kind(), TokenKind::Deadline);
        }
    }
    for (input, expected) in [
        (Kind::Unavailable, TokenKind::Unavailable), (Kind::LedgerInvalid, TokenKind::Unavailable),
        (Kind::SchemaInvalid, TokenKind::Unavailable), (Kind::ObservationUnknown, TokenKind::Unavailable),
        (Kind::CommitUnknown, TokenKind::CommitUnknown),
        (Kind::CommitAcknowledgedAfterDeadline, TokenKind::CommitAcknowledgedAfterDeadline),
        (Kind::RollbackUnproven, TokenKind::CleanupUnknown),
        (Kind::RollbackAcknowledgedAfterDeadline, TokenKind::RollbackAcknowledgedAfterDeadline),
        (Kind::ReadbackUnproven, TokenKind::ReadbackUnproven),
    ] { assert_eq!(journal_kind(&Error::new(input), &after), expected); }
}

#[tokio::test]
async fn p06_token_reply_guards() {
    for (raw, expected) in [
        (b"[".as_slice(), ReplyInvalidReason::JsonSyntax),
        (br#"{"z":1}"#.as_slice(), ReplyInvalidReason::UnknownKey),
        (br#"{"access_token":"x","access_token":"y"}"#.as_slice(), ReplyInvalidReason::DuplicateKey),
        (br#"{"client_secret":"never-retained"}"#.as_slice(), ReplyInvalidReason::ForbiddenSecretKey),
        (br#"{"access_token":false}"#.as_slice(), ReplyInvalidReason::FieldShape),
        (br#"{"access_token":"contains space"}"#.as_slice(), ReplyInvalidReason::FieldLimit),
        (br#"{"scope":"ai ai"}"#.as_slice(), ReplyInvalidReason::ScopeShape),
        (br#"{"token_type":"bearer"}"#.as_slice(), ReplyInvalidReason::TokenType),
        (br#"{"expires_in":0}"#.as_slice(), ReplyInvalidReason::ExpiryInteger),
    ] {
        assert_eq!(reply::parse_tokens(raw).err(), Some(InitialError::ProtocolInvalid(expected)));
    }
    for length in [16_377, 16_378] {
        let access = "a".repeat(length);
        let refresh = "r".repeat(length);
        let raw = format!("{{\"access_token\":\"{access}\",\"token_type\":\"Bearer\",\"expires_in\":59,\"refresh_token\":\"{refresh}\",\"scope\":\"ai account\"}}");
        let result = reply::parse_tokens(raw.as_bytes());
        if length == 16_377 { assert!(result.is_ok()); }
        else { assert_eq!(result.err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::FieldLimit))); }
    }
    for length in [128, 129] {
        let scope = format!("ai account{}", " ".repeat(length - 10));
        let raw = format!("{{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":59,\"refresh_token\":\"r\",\"scope\":\"{scope}\"}}");
        let result = reply::parse_tokens(raw.as_bytes());
        if length == 128 { assert!(result.is_ok()); }
        else { assert_eq!(result.err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::FieldLimit))); }
    }
    for (reason, expected) in [
        (ReplyInvalidReason::JsonSyntax, ReplyReason::JsonSyntax),
        (ReplyInvalidReason::UnknownKey, ReplyReason::UnknownKey),
        (ReplyInvalidReason::DuplicateKey, ReplyReason::DuplicateKey),
        (ReplyInvalidReason::ForbiddenSecretKey, ReplyReason::ForbiddenSecretKey),
        (ReplyInvalidReason::FieldShape, ReplyReason::FieldShape),
        (ReplyInvalidReason::HeaderLimit, ReplyReason::HeaderLimit),
        (ReplyInvalidReason::MediaType, ReplyReason::MediaType),
        (ReplyInvalidReason::BodyLimit, ReplyReason::BodyLimit),
        (ReplyInvalidReason::FieldLimit, ReplyReason::FieldLimit),
        (ReplyInvalidReason::ScopeShape, ReplyReason::ScopeShape),
        (ReplyInvalidReason::TokenType, ReplyReason::TokenType),
        (ReplyInvalidReason::ExpiryInteger, ReplyReason::ExpiryInteger),
        (ReplyInvalidReason::ClockOrExpiry, ReplyReason::ClockOrExpiry),
        (ReplyInvalidReason::ReplyBinding, ReplyReason::ReplyBinding),
    ] { assert_eq!(initial_kind(InitialError::ProtocolInvalid(reason)), TokenKind::ProtocolInvalid(expected)); }
    let (mut headers, probe) = response(200, vec![Ok(Bytes::from_static(TOKEN_JSON))], false);
    headers.headers.insert("x-large", HeaderValue::from_str(&"x".repeat(8193)).unwrap());
    assert_eq!(token_response_headers(&headers).err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::HeaderLimit)));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    for media in ["text/plain", "application/json; charset=latin1"] {
        let (mut response, probe) = response(200, vec![Ok(Bytes::from_static(TOKEN_JSON))], false);
        response.headers.insert(CONTENT_TYPE, HeaderValue::from_str(media).unwrap());
        assert_eq!(token_response_headers(&response).err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::MediaType)));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    }
    for status in [201, 301, 302, 400, 401, 500] {
        let (response, probe) = response(status, vec![Ok(Bytes::from_static(TOKEN_JSON))], false);
        assert_eq!(token_response_headers(&response).err(), Some(InitialError::HttpStatus(status)));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    }
    let mut bounded = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    let original = (bounded.as_ptr(), bounded.capacity());
    append_chunk(&mut bounded, &vec![b'x'; BODY_LIMIT]).unwrap();
    assert_eq!((bounded.as_ptr(), bounded.capacity()), original);
    assert_eq!(append_chunk(&mut bounded, b"x").err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::BodyLimit)));
    assert_eq!((bounded.as_ptr(), bounded.capacity()), original);
    bounded.as_mut_slice().zeroize();
    assert!(bounded.iter().all(|b| *b == 0));

    // The private bookend primitive is used by the real Current wrapper. These
    // synthetic closed predicates exercise control mechanics, never a Host grant.
    let (mut body, probe) = response(200, vec![Ok(Bytes::from_static(b"chunk")), Err(TransportError::Cancelled)], true);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(poll_bookended(|| Ok(()), || body.body.as_mut().poll_next(&mut cx)), Poll::Pending));
    assert!(matches!(poll_bookended(|| Ok(()), || body.body.as_mut().poll_next(&mut cx)), Poll::Ready(Ok(Some(Ok(_))))));
    assert!(matches!(poll_bookended(|| Ok(()), || body.body.as_mut().poll_next(&mut cx)), Poll::Ready(Ok(Some(Err(TransportError::Cancelled))))));
    assert!(matches!(poll_bookended(|| Ok(()), || body.body.as_mut().poll_next(&mut cx)), Poll::Ready(Ok(None))));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 4);
    for pending in [false, true] {
        let (mut body, probe) = response(200, vec![Ok(Bytes::from_static(b"chunk"))], pending);
        let checks = AtomicUsize::new(0);
        let result = poll_bookended(
            || if checks.fetch_add(1, Ordering::SeqCst) == 1 { Err(Error::new(Kind::Refused)) } else { Ok(()) },
            || body.body.as_mut().poll_next(&mut cx),
        );
        assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == Kind::Refused));
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
    }
    let f = core(true, Duration::from_secs(60)).await;
    let (_, dispatched) = transfer_code_request(f.prepared).unwrap();
    let CodeDispatchedInitialOwner { witness, budget, clock, .. } = dispatched;
    let InitialReplyWitness::Code { metadata, binding, start, .. } = witness else { panic!("true code fixture"); };
    let fields = reply::parse_tokens(TOKEN_JSON).unwrap();
    let mut tokens = tokens::assemble_tokens(fields, binding, start, ReplyResources { metadata, budget, clock }).unwrap();
    assert_eq!(tokens.sdk.expires_at, "1970-01-01T00:17:39.900Z");
    assert_eq!(tokens.sdk.access_token, "access-vector");
    assert_eq!(tokens.sdk.refresh_token, "refresh-vector");
    assert_eq!(tokens.sdk.scope, "ai account");
    assert_eq!(tokens.sdk.client_id, "original-client");
    assert_eq!(tokens.sdk.server_url, ORIGIN);
    tokens.erase();
    assert!([&tokens.sdk.access_token, &tokens.sdk.refresh_token, &tokens.sdk.expires_at,
        &tokens.sdk.scope, &tokens.sdk.client_id, &tokens.sdk.server_url].iter().all(|s| s.is_empty()));

    // TTL=1 and millisecond truncation are checked from the original code start.
    let f = core(true, Duration::from_secs(60)).await;
    let (_, dispatched) = transfer_code_request(f.prepared).unwrap();
    let CodeDispatchedInitialOwner { witness, budget, clock, .. } = dispatched;
    let InitialReplyWitness::Code { metadata, binding, start, .. } = witness else { panic!("code fixture"); };
    let fields = reply::parse_tokens(br#"{"access_token":"a","token_type":"Bearer","expires_in":1,"refresh_token":"r","scope":"ai account"}"#).unwrap();
    let mut owner = tokens::assemble_tokens(fields, binding, start, ReplyResources { metadata, budget, clock }).unwrap();
    let mono = owner.expiry.original_start.mono + Duration::from_nanos(999_876_544);
    f.clock.set(DateTime::from_timestamp(1_001, 900_000_000).unwrap(), mono);
    let (result, erase) = tokens::test_final_check_and_erase(&mut owner);
    assert_eq!(result.err(), Some(InitialError::ProtocolInvalid(ReplyInvalidReason::ClockOrExpiry)));
    assert_eq!(erase, [true; 6]);
    for (server, seconds, expected) in [
        ("https://other.invalid", 59, ReplyInvalidReason::ReplyBinding),
        (ORIGIN, i64::MAX, ReplyInvalidReason::ClockOrExpiry),
    ] {
        let f = core(true, Duration::from_secs(60)).await;
        let (_, dispatched) = transfer_code_request(f.prepared).unwrap();
        let CodeDispatchedInitialOwner { witness, budget, clock, .. } = dispatched;
        let InitialReplyWitness::Code { metadata, mut binding, start, .. } = witness else { panic!("code fixture"); };
        *binding.server_url = server.into();
        let raw = format!("{{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":{seconds},\"refresh_token\":\"r\",\"scope\":\"ai account\"}}");
        let fields = reply::parse_tokens(raw.as_bytes()).unwrap();
        assert_eq!(tokens::assemble_tokens(fields, binding, start, ReplyResources { metadata, budget, clock }).err(),
            Some(InitialError::ProtocolInvalid(expected)));
    }
}

#[tokio::test]
async fn p07_token_end_controls() {
    let (sender, mut receive) = oneshot::channel();
    let signal = Arc::new(EndSignal(Mutex::new(Some(sender))));
    EndGuard { signal: signal.clone(), armed: true }.finish(FenceEnd::RequestEnded);
    signal.send(FenceEnd::Deadline);
    assert_eq!(receive.try_recv().unwrap(), FenceEnd::RequestEnded);
    let (sender, mut receive) = oneshot::channel();
    let signal = Arc::new(EndSignal(Mutex::new(Some(sender))));
    drop(EndGuard { signal: signal.clone(), armed: true });
    signal.send(FenceEnd::Cancelled);
    assert_eq!(receive.try_recv().unwrap(), FenceEnd::CallAbandoned);

    let (release, mut release_receive) = oneshot::channel();
    let (ack, ack_receive) = oneshot::channel();
    drop(TokenPermit { control: Some(PermitControl { release, ack: ack_receive }) });
    assert_eq!(release_receive.try_recv().err(), Some(oneshot::error::TryRecvError::Closed));
    assert!(ack.is_closed());

    let (release, release_receive) = oneshot::channel();
    let (ack, ack_receive) = oneshot::channel();
    let permit = Box::new(TokenPermit { control: Some(PermitControl { release, ack: ack_receive }) });
    let observed = async {
        assert_eq!(release_receive.await, Ok(()));
        assert!(ack.send(Ok(())).is_ok());
    };
    let (released, ()) = tokio::join!(permit.release_after_headers(), observed);
    assert!(released.is_ok());

    let (release, release_receive) = oneshot::channel();
    let (ack, ack_receive) = oneshot::channel::<Result<(), GatewayFenceError>>();
    drop(ack);
    let permit = Box::new(TokenPermit { control: Some(PermitControl { release, ack: ack_receive }) });
    let observed = async { assert_eq!(release_receive.await, Ok(())); };
    let (released, ()) = tokio::join!(permit.release_after_headers(), observed);
    assert_eq!(released.err(), Some(GatewayFenceError::CleanupUnknown));

    let (reply, receive) = oneshot::channel::<Result<PermitControl, GatewayFenceError>>();
    drop(receive);
    assert!(reply.is_closed());
    assert!(reply.send(Err(GatewayFenceError::Refused)).is_err());
    let (release, release_receive) = oneshot::channel::<()>();
    drop(release);
    assert!(release_receive.await.is_err());
    // These are finite synchronous/channel facts. No original PG ACK or driver
    // join was observed, and Drop never publishes either.
    assert_eq!(FenceResult::idle(FenceEnd::CallAbandoned).rollback, Ack::NotAttempted);
}

#[tokio::test]
async fn p08_token_outcomes() {
    let first = Arc::new(OperationOutcomes::new());
    let second = Arc::new(OperationOutcomes::new());
    let dns = Arc::new(AtomicUsize::new(0));
    let refuse = Arc::new(Refuse(AtomicUsize::new(0)));
    for (sink, oauth) in [(first.clone(), true), (second.clone(), false)] {
        let f = core(true, Duration::from_secs(60)).await;
        let (request, _) = transfer_code_request(f.prepared).unwrap();
        let transport = factory(oauth, dns.clone()).for_operation(refuse.clone(), sink.clone(), f.flow.cap(None), Duration::from_secs(1)).unwrap();
        assert!(transport.execute(request, f.parent).await.is_err());
        sink.execute_polled.store(true, Ordering::Release);
    }
    let original = first.snapshot().unwrap();
    let other = second.attempt.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(original.failure(), Some(GatewayFailure::Rejected));
    assert_eq!(other.snapshot().failure(), Some(GatewayFailure::InvalidRequest));
    assert!(!original.may_have_sent());
    assert!(!other.snapshot().may_have_sent());
    first.started(other);
    assert!(first.duplicate.load(Ordering::SeqCst));
    assert!(!second.duplicate.load(Ordering::SeqCst));
    assert_eq!(first.snapshot(), Some(original));
    assert_eq!(second.snapshot().unwrap().failure(), Some(GatewayFailure::InvalidRequest));
    assert_eq!(first.refused_kind(), TokenKind::BeforeDispatchRefused);
    assert_eq!(second.refused_kind(), TokenKind::BeforeDispatchRefused);
    assert_eq!(refuse.0.load(Ordering::SeqCst), 1);
    assert_eq!(dns.load(Ordering::SeqCst), 0);
}
