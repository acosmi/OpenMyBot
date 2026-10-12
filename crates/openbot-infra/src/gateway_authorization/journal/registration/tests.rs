//! New registration core vectors. No Host/PG/TLS acceptance is inferred here.
use super::*;
use crate::gateway_account::{GatewayAccountClient, GatewayDesktopMetadata};
use crate::gateway_authorization::journal::{SavedFlow, canonical_microseconds, registered_row};
use crate::gateway_authorization::{
    ClockSample, InitialClock, InitialError, InitialReplyWitness, OwnedInitialInput,
    PreparedInitialOwner, ReplyInvalidReason, owned_code_input, owned_registration_input,
    prepare_initial, retain_parent_budget, transfer_registration_request,
};
use crate::gateway_transport::*;
use crate::net::safe_http::{CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_core::Stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const ORIGIN: &str = "https://unit.invalid";
const REDIRECT: &str = "http://127.0.0.1:43129/callback?original=yes";
struct Clock(Mutex<ClockSample>);
impl InitialClock for Clock {
    fn sample(&self) -> ClockSample {
        *self.0.lock().unwrap()
    }
}
impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(ClockSample {
            wall: DateTime::from_timestamp(1_000, 123).unwrap(),
            mono: Instant::now(),
        })))
    }
    fn set(&self, wall: DateTime<Utc>, mono: Instant) {
        *self.0.lock().unwrap() = ClockSample { wall, mono };
    }
}
#[derive(Default)]
struct Probe {
    polls: AtomicUsize,
    drops: AtomicUsize,
}
struct Body {
    chunks: VecDeque<Result<Bytes, acosmi::TransportError>>,
    probe: Arc<Probe>,
    pending: bool,
    hook: Option<Box<dyn FnOnce() + Send>>,
}
impl Stream for Body {
    type Item = Result<Bytes, acosmi::TransportError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = this.hook.take() {
            hook();
        }
        if this.pending {
            this.pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(this.chunks.pop_front())
        }
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn response(
    raw: &[u8],
    pending: bool,
    hook: Option<Box<dyn FnOnce() + Send>>,
) -> (acosmi::HttpResponse, Arc<Probe>) {
    let probe = Arc::new(Probe::default());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    (
        acosmi::HttpResponse {
            status: StatusCode::OK,
            headers,
            body: Box::pin(Body {
                chunks: vec![Ok(Bytes::copy_from_slice(raw))].into(),
                probe: probe.clone(),
                pending,
                hook,
            }),
        },
        probe,
    )
}
struct Metadata;
#[async_trait]
impl acosmi::HttpTransport for Metadata {
    async fn execute(
        &self,
        request: acosmi::HttpRequest,
        parent: CancellationToken,
    ) -> Result<acosmi::HttpResponse, acosmi::TransportError> {
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.url.as_str(),
            "https://unit.invalid/.well-known/oauth-authorization-server/desktop"
        );
        assert!(!parent.is_cancelled());
        Ok(response(br#"{"issuer":"https://unit.invalid","authorization_endpoint":"https://unit.invalid/oauth/desktop/authorize","token_endpoint":"https://unit.invalid/oauth/desktop/token","registration_endpoint":"https://unit.invalid/oauth/desktop/register","revocation_endpoint":"https://unit.invalid/oauth/desktop/revoke","scopes_supported":["ai","account"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"grant_types_supported":["authorization_code","refresh_token"],"crabcode_auth_contract_version":2,"gateway_error_contract_version":1}"#,false,None).0)
    }
}
async fn metadata() -> GatewayDesktopMetadata {
    GatewayAccountClient::new(ORIGIN, Arc::new(Metadata))
        .unwrap()
        .fetch_metadata(CancellationToken::new())
        .await
        .unwrap()
}
struct Core {
    prepared: PreparedInitialOwner,
    flow: SavedFlow,
    clock: Arc<Clock>,
    parent: CancellationToken,
}
async fn core(code: bool, duration: Duration, redirect: &str) -> Core {
    let clock = Clock::new();
    let parent = CancellationToken::new();
    let mono = clock.sample().mono;
    let flow = SavedFlow::new(clock.clone(), parent.clone(), (mono + duration).into_std()).unwrap();
    let mut input: OwnedInitialInput = if code {
        owned_code_input(
            metadata().await,
            Zeroizing::new("original-client".into()),
            Zeroizing::new("synthetic-code".into()),
            Zeroizing::new(redirect.into()),
            Zeroizing::new("v".repeat(43)),
        )
        .unwrap()
    } else {
        owned_registration_input(metadata().await, Zeroizing::new(redirect.into())).unwrap()
    };
    input.clock = clock.clone();
    let prepared = prepare_initial(input, retain_parent_budget(parent.clone(), flow.deadline))
        .await
        .unwrap();
    Core {
        prepared,
        flow,
        clock,
        parent,
    }
}
fn admitted() -> Row {
    let stamp = time::OffsetDateTime::from_unix_timestamp(1_000).unwrap();
    Row {
        attempt_id: Uuid::parse_str("019a0300-0000-7000-8000-000000000029").unwrap(),
        journal_schema: 1,
        deployment_id: "unit-deployment".into(),
        tenant_id: "unit-tenant".into(),
        owner_user_id: "unit-owner".into(),
        auth_generation: 7,
        installation_id: "29".repeat(32),
        runtime_epoch: "2a".repeat(32),
        issuer: ORIGIN.into(),
        redirect_uri: REDIRECT.into(),
        phase: "registration_admitted".into(),
        client_id: None,
        enrollment_id: None,
        registration_admitted_at: Some(stamp + time::Duration::microseconds(1)),
        code_admitted_at: None,
        created_at: stamp,
        expires_at: stamp + time::Duration::seconds(180),
        updated_at: stamp + time::Duration::microseconds(1),
        finished_at: None,
        outcome_code: None,
    }
}

#[test]
fn p02_registered_successor_all_twenty_fields() {
    let old = admitted();
    let stamp = old.updated_at + time::Duration::microseconds(11);
    let id = Uuid::parse_str("019a0300-0000-7000-8abc-000000000039").unwrap();
    let next = registered_row(&old, "original-client", id, stamp).unwrap();
    let mut expected = old.clone();
    expected.phase = "registered".into();
    expected.client_id = Some("original-client".into());
    expected.enrollment_id = Some(id);
    expected.updated_at = stamp;
    assert_eq!(next, expected);
    assert_eq!(old, admitted());
    for invalid in [
        old.updated_at - time::Duration::microseconds(1),
        old.expires_at,
    ] {
        assert!(registered_row(&old, "original-client", id, invalid).is_err());
    }
    for client in ["", "client\npoison"] {
        assert!(registered_row(&old, client, id, stamp).is_err());
    }
    for invalid_id in [
        Uuid::nil(),
        Uuid::parse_str("019a0300-0000-4000-8abc-000000000039").unwrap(),
    ] {
        assert!(registered_row(&old, "original-client", invalid_id, stamp).is_err());
    }
    for index in 0..6 {
        let mut wrong = old.clone();
        match index {
            0 => wrong.phase = "created".into(),
            1 => wrong.client_id = Some("replacement".into()),
            2 => wrong.enrollment_id = Some(id),
            3 => wrong.code_admitted_at = Some(stamp),
            4 => wrong.finished_at = Some(stamp),
            _ => wrong.outcome_code = Some("refused".into()),
        };
        assert!(registered_row(&wrong, "original-client", id, stamp).is_err());
    }
}

#[tokio::test]
async fn p03_saved_caller_flow_capture_caps_never_renew() {
    for duration in [
        Duration::from_secs(1),
        Duration::from_secs(60),
        Duration::from_secs(500),
    ] {
        let f = core(false, duration, REDIRECT).await;
        let budget = f.prepared.budget.as_ref().unwrap();
        let expected = f
            .flow
            .deadline
            .min(budget.deadline)
            .min(budget.owner_deadline);
        assert_eq!(f.flow.registration_reply_cap(budget), expected);
        assert!(expected <= f.flow.start.mono + Duration::from_secs(10));
        assert!(f.flow.deadline <= f.flow.start.mono + Duration::from_secs(180));
        f.clock.set(f.flow.start.wall, expected);
        assert_eq!(
            f.flow
                .check_registration_reply(budget, &f.prepared.clock)
                .err(),
            Some(InitialError::Deadline)
        );
        assert_eq!(f.flow.registration_reply_cap(budget), expected);
    }
    for pending in [false, true] {
        let f = core(false, Duration::from_secs(60), REDIRECT).await;
        let (_, dispatched) = transfer_registration_request(f.prepared).unwrap();
        let clock = f.clock.clone();
        let start = f.flow.start;
        let cap = f.flow.registration_reply_cap(&dispatched.budget);
        let hook = Box::new(move || clock.set(start.wall + chrono::Duration::seconds(10), cap));
        let (reply, probe) = response(br#"{"client_id":"original-client"}"#, pending, Some(hook));
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            crate::gateway_authorization::reply::consume_dispatched_registration(
                dispatched, reply, &f.flow,
            ),
        )
        .await
        .expect("the post-poll gate must reject even an actual Pending poll immediately");
        assert_eq!(result.err(), Some(InitialError::Deadline));
        assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    let f = core(false, Duration::from_secs(60), REDIRECT).await;
    let budget = f.prepared.budget.as_ref().unwrap();
    let start = f.flow.start;
    f.clock
        .set(start.wall - chrono::Duration::nanoseconds(1), start.mono);
    assert_eq!(
        f.flow
            .check_registration_reply(budget, &f.prepared.clock)
            .err(),
        Some(InitialError::Deadline)
    );
    f.clock
        .set(start.wall, start.mono - Duration::from_nanos(1));
    assert_eq!(
        f.flow
            .check_registration_reply(budget, &f.prepared.clock)
            .err(),
        Some(InitialError::Deadline)
    );
    assert_eq!(
        canonical_microseconds(DateTime::from_timestamp(-1, 999_999_999).unwrap())
            .unwrap()
            .unix_timestamp_nanos(),
        -1_000
    );
    let clock = Clock::new();
    let mono = clock.sample().mono;
    clock.set(DateTime::<Utc>::MAX_UTC, mono);
    assert!(
        SavedFlow::new(
            clock,
            CancellationToken::new(),
            (mono + Duration::from_secs(180)).into_std()
        )
        .is_err()
    );
}

#[tokio::test]
async fn p04_dispatched_reply_requires_original_registration_resources() {
    let f = core(true, Duration::from_secs(60), REDIRECT).await;
    assert!(matches!(
        transfer_registration_request(f.prepared),
        Err(InitialError::RequestMismatch)
    ));
    for index in 0..4 {
        let mut f = core(false, Duration::from_secs(60), REDIRECT).await;
        match index {
            0 => f.prepared.request = None,
            1 => f.prepared.witness = None,
            2 => f.prepared.budget = None,
            _ => f.prepared.sdk_exit_child = CancellationToken::new(),
        };
        assert!(transfer_registration_request(f.prepared).is_err());
    }
    let mut f = core(false, Duration::from_secs(60), REDIRECT).await;
    let mut other = core(
        false,
        Duration::from_secs(60),
        "http://127.0.0.1:43129/rebuilt",
    )
    .await;
    f.prepared.request = other.prepared.request.take();
    assert!(matches!(
        transfer_registration_request(f.prepared),
        Err(InitialError::RequestMismatch)
    ));
    let f = core(false, Duration::from_secs(60), REDIRECT).await;
    let (_, mut dispatched) = transfer_registration_request(f.prepared).unwrap();
    dispatched.clock = Clock::new();
    let (reply, probe) = response(br#"{"client_id":"original-client"}"#, false, None);
    assert_eq!(
        crate::gateway_authorization::reply::consume_dispatched_registration(
            dispatched, reply, &f.flow
        )
        .await
        .err(),
        Some(InitialError::ProtocolInvalid(
            ReplyInvalidReason::ReplyBinding
        ))
    );
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    let f = core(false, Duration::from_secs(60), REDIRECT).await;
    let (_, mut dispatched) = transfer_registration_request(f.prepared).unwrap();
    dispatched.budget.original_parent = CancellationToken::new();
    f.parent.cancel();
    let (reply, probe) = response(br#"{"client_id":"original-client"}"#, false, None);
    assert_eq!(
        crate::gateway_authorization::reply::consume_dispatched_registration(
            dispatched, reply, &f.flow
        )
        .await
        .err(),
        Some(InitialError::Cancelled)
    );
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
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
    async fn before_request(
        &self,
        _: GatewayRequestDescriptor,
        _: CancellationToken,
    ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(GatewayFenceError::Refused)
    }
}
fn factory(oauth: bool, dns: Arc<AtomicUsize>) -> GatewayTransportFactory {
    let endpoints = if oauth {
        Some(
            GatewayOAuthEndpoints::new(
                GatewayOAuthProfile::Desktop,
                &format!("{ORIGIN}/oauth/desktop/register"),
                &format!("{ORIGIN}/oauth/desktop/token"),
                Some(&format!("{ORIGIN}/oauth/desktop/revoke")),
            )
            .unwrap(),
        )
    } else {
        None
    };
    GatewayTransportFactory::new(
        SafeDialer::with_resolver(
            EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap()),
            Arc::new(NoDns(dns)),
        ),
        VerifiedGatewayEndpoints::new(ORIGIN, None, endpoints).unwrap(),
        GatewayTransportLimits::new(Duration::from_secs(10), 65_536).unwrap(),
    )
}
fn outcomes() -> Arc<OperationOutcomes> {
    Arc::new(OperationOutcomes {
        attempt: Mutex::new(None),
        duplicate: AtomicBool::new(false),
    })
}
#[tokio::test]
async fn p06_operation_owned_outcomes_once_and_isolated() {
    let first = outcomes();
    let second = outcomes();
    let dns = Arc::new(AtomicUsize::new(0));
    let refuse = Arc::new(Refuse(AtomicUsize::new(0)));
    for (sink, oauth) in [(first.clone(), true), (second.clone(), false)] {
        let f = core(false, Duration::from_secs(60), REDIRECT).await;
        let (request, dispatched) = transfer_registration_request(f.prepared).unwrap();
        let transport = factory(oauth, dns.clone())
            .for_operation(
                refuse.clone(),
                sink,
                f.flow.registration_reply_cap(&dispatched.budget),
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(transport.execute(request, f.parent.clone()).await.is_err());
    }
    let original = first.attempt.lock().unwrap().as_ref().unwrap().snapshot();
    let other = second.attempt.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(original.failure(), Some(GatewayFailure::Rejected));
    assert_eq!(
        other.snapshot().failure(),
        Some(GatewayFailure::InvalidRequest)
    );
    assert!(!original.may_have_sent());
    assert!(!other.snapshot().may_have_sent());
    first.started(other);
    assert!(first.duplicate.load(Ordering::SeqCst));
    assert!(!second.duplicate.load(Ordering::SeqCst));
    assert_eq!(
        first.attempt.lock().unwrap().as_ref().unwrap().snapshot(),
        original
    );
    assert_eq!(
        second
            .attempt
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot()
            .failure(),
        Some(GatewayFailure::InvalidRequest)
    );
    assert_eq!(refuse.0.load(Ordering::SeqCst), 1);
    assert_eq!(dns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn p01_one_request_transfer_and_second_execute_refused() {
    for vector in 0..18 {
        let mut f = core(false, Duration::from_secs(60), REDIRECT).await;
        let request = f.prepared.request.as_mut().unwrap();
        match vector {
            0 => request.method = Method::GET,
            1 => request.url = "https://unit.invalid/oauth/desktop/token".parse().unwrap(),
            2 => {
                request.headers.insert(
                    http::header::AUTHORIZATION,
                    HeaderValue::from_static("synthetic-poison"),
                );
            }
            3 => {
                request.headers.insert(
                    http::header::ACCEPT,
                    HeaderValue::from_static("application/json"),
                );
            }
            4 => {
                request
                    .headers
                    .insert("x-extra", HeaderValue::from_static("synthetic-poison"));
            }
            5 => {
                request
                    .headers
                    .append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            6 => {
                request
                    .headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            }
            7..=13 => {
                let mut body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                match vector {
                    7 => body["extra"] = serde_json::json!(true),
                    8 => body["scope"] = serde_json::json!("ai"),
                    9 => {
                        body["redirect_uris"] =
                            serde_json::json!(["http://127.0.0.1:43129/changed"])
                    }
                    10 => {
                        body["grant_types"] =
                            serde_json::json!(["refresh_token", "authorization_code"])
                    }
                    11 => body["response_types"] = serde_json::json!([]),
                    12 => {
                        body["token_endpoint_auth_method"] =
                            serde_json::json!("client_secret_basic")
                    }
                    _ => body["client_name"] = serde_json::json!("replacement-client"),
                }
                request.body = serde_json::to_vec(&body).unwrap();
            }
            14 => request.context.purpose = acosmi::HttpPurpose::OAuthToken,
            15 => request.context.response_mode = acosmi::HttpResponseMode::Streaming,
            16 => request.context.timeout = Duration::from_secs(29),
            _ => request.body = b"{}".to_vec(),
        }
        assert!(
            matches!(
                transfer_registration_request(f.prepared),
                Err(InitialError::RequestMismatch)
            ),
            "raw vector {vector}"
        );
    }
    let f = core(false, Duration::from_secs(60), REDIRECT).await;
    let body_address = f.prepared.request.as_ref().unwrap().body.as_ptr();
    let original_clock = f.prepared.clock.clone();
    assert!(f.prepared.sdk_exit_child.is_cancelled());
    assert!(!f.parent.is_cancelled());
    let (request, dispatched) = transfer_registration_request(f.prepared).unwrap();
    assert_eq!(request.body.as_ptr(), body_address);
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.url.as_str(),
        "https://unit.invalid/oauth/desktop/register"
    );
    assert!(Arc::ptr_eq(&original_clock, &dispatched.clock));
    assert!(matches!(
        dispatched.witness,
        InitialReplyWitness::Registration { .. }
    ));
    assert!(dispatched.sdk_exit_child.is_cancelled());
    assert!(!dispatched.budget.original_parent.is_cancelled());

    let (acquire, receive) = tokio::sync::oneshot::channel();
    let authority = Arc::new(RegistrationAuthority::new(acquire));
    let dns = Arc::new(AtomicUsize::new(0));
    let first = outcomes();
    let transport = factory(true, dns.clone())
        .for_operation(
            authority.clone(),
            first.clone(),
            f.flow.registration_reply_cap(&dispatched.budget),
            Duration::from_secs(1),
        )
        .unwrap();
    let reject = async {
        let control = receive.await.unwrap();
        assert_eq!(
            control.request.kind(),
            GatewayRequestKind::OAuthRegistration
        );
        assert!(!control.request.streaming());
        assert!(!control.cancel.is_cancelled());
        assert!(control.reply.send(Err(GatewayFenceError::Refused)).is_ok());
    };
    let (result, ()) = tokio::join!(transport.execute(request, f.parent.clone()), reject);
    assert!(result.is_err());
    let second = outcomes();
    let f2 = core(false, Duration::from_secs(60), REDIRECT).await;
    let (request2, dispatched2) = transfer_registration_request(f2.prepared).unwrap();
    let transport2 = factory(true, dns.clone())
        .for_operation(
            authority,
            second.clone(),
            f2.flow.registration_reply_cap(&dispatched2.budget),
            Duration::from_secs(1),
        )
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            transport2.execute(request2, f2.parent)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert_eq!(
        first.snapshot().unwrap().failure(),
        Some(GatewayFailure::Rejected)
    );
    assert_eq!(
        second.snapshot().unwrap().failure(),
        Some(GatewayFailure::Rejected)
    );
    assert_eq!(dns.load(Ordering::SeqCst), 0);
    f.parent.cancel();
    assert!(dispatched.budget.original_parent.is_cancelled());
}

async fn real_observed_failure(after_permit: bool) -> Arc<OperationOutcomes> {
    let f = core(false, Duration::from_secs(60), REDIRECT).await;
    let (request, dispatched) = transfer_registration_request(f.prepared).unwrap();
    let (acquire, receive) = tokio::sync::oneshot::channel();
    let authority = Arc::new(RegistrationAuthority::new(acquire));
    let observed = outcomes();
    let transport = factory(true, Arc::new(AtomicUsize::new(0)))
        .for_operation(
            authority,
            observed.clone(),
            f.flow.registration_reply_cap(&dispatched.budget),
            Duration::from_secs(1),
        )
        .unwrap();
    let runner = async {
        let control = receive.await.unwrap();
        if after_permit {
            let (release, released) = tokio::sync::oneshot::channel();
            let (ack, ack_received) = tokio::sync::oneshot::channel();
            assert!(
                control
                    .reply
                    .send(Ok(RegistrationPermitControl {
                        release,
                        ack: ack_received
                    }))
                    .is_ok()
            );
            // The real DNS refusal drops the actual permit before headers.
            assert!(released.await.is_err());
            drop(ack);
        } else {
            assert!(control.reply.send(Err(GatewayFenceError::Refused)).is_ok());
        }
    };
    let (result, ()) = tokio::join!(transport.execute(request, f.parent), runner);
    assert!(result.is_err());
    assert_eq!(observed.snapshot().unwrap().may_have_sent(), after_permit);
    observed
}

#[tokio::test]
async fn p05_closed_failure_ack_history_not_upgraded() {
    let sent = real_observed_failure(true).await;
    let later = real_observed_failure(false).await;
    let original = sent.snapshot().unwrap();
    assert!(original.may_have_sent());
    assert!(!original.permit_released());
    assert!(!original.complete());
    for ack in [Ack::NotAttempted, Ack::Unknown, Ack::Timely, Ack::Late] {
        let mut failure =
            operation_error(RegistrationDispatchKind::RegistrationUnknown, &sent, ack);
        failure.registered_write = Ack::Late;
        failure.registered_readback = Ack::Unknown;
        assert_eq!(failure.transport, Some(original));
        assert_eq!(failure.send_guard_rollback, ack);
        assert_eq!(failure.registered_write, Ack::Late);
        assert_eq!(failure.registered_readback, Ack::Unknown);
        let unrelated = operation_error(
            RegistrationDispatchKind::BeforeDispatchRefused,
            &later,
            Ack::Timely,
        );
        assert!(!unrelated.transport.unwrap().may_have_sent());
        assert_eq!(failure.transport, Some(original));
        assert_eq!(failure.send_guard_rollback, ack);
        assert_eq!(failure.registered_write, Ack::Late);
        assert_eq!(failure.registered_readback, Ack::Unknown);
        assert!(std::error::Error::source(&failure).is_none());
        let debug = format!("{failure:?}");
        let display = failure.to_string();
        for secret in [
            ORIGIN,
            REDIRECT,
            "original-client",
            "unit-owner",
            "synthetic-poison",
            "SELECT ",
        ] {
            assert!(!debug.contains(secret));
            assert!(!display.contains(secret));
        }
    }
    assert_eq!(
        initial_dispatch_kind(InitialError::HttpStatus(429)),
        RegistrationDispatchKind::HttpStatus(429)
    );
    assert_eq!(
        initial_dispatch_kind(InitialError::ProtocolInvalid(
            ReplyInvalidReason::ReplyBinding
        )),
        RegistrationDispatchKind::RegistrationUnknown
    );
    assert_eq!(
        after_send_kind(&Error::new(Kind::Refused)),
        RegistrationDispatchKind::RegistrationUnknown
    );
    assert_eq!(
        readback_kind(&Error::new(Kind::RollbackAcknowledgedAfterDeadline)),
        RegistrationDispatchKind::RollbackAcknowledgedAfterDeadline
    );
    assert_eq!(
        journal_dispatch_kind(&Error::new(Kind::CommitUnknown)),
        RegistrationDispatchKind::CommitUnknown
    );
    assert_eq!(
        journal_dispatch_kind(&Error::new(Kind::CommitAcknowledgedAfterDeadline)),
        RegistrationDispatchKind::CommitAcknowledgedAfterDeadline
    );
    assert_eq!(
        RegistrationDispatchError::new(RegistrationDispatchKind::Unavailable).registered_write,
        Ack::NotAttempted
    );
}
