//! Handwritten callback vectors; no real Host, PG, browser, or erasure credit.
use super::*;
use crate::gateway_authorization::journal::{Kind, SavedFlow};
use crate::gateway_authorization::{
    ClockOwner, ClockSample, InitialBudget, InitialClock, callback_authorization_endpoint_allowed,
    callback_pkce_material,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_contracts::request_binding::{
    GatewayAuthorizationCallbackUrlReceiver, HostRequestBindingError, HostRequestBindingGuard,
    HostRequestBindingKind, RequestBindingOwnerLease, ServerSessionBindingIdentity,
};
use sha2::{Digest as _, Sha256};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const STATE: &[u8; 43] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PORT: u16 = 43129;

fn valid_query(code: &str) -> Vec<u8> {
    format!("state={}&code={code}", std::str::from_utf8(STATE).unwrap()).into_bytes()
}
fn frame(target: &[u8], headers: &[u8]) -> Vec<u8> {
    let mut bytes = b"GET ".to_vec();
    bytes.extend_from_slice(target);
    bytes.extend_from_slice(b" HTTP/1.1\r\nHost: 127.0.0.1:43129\r\n");
    bytes.extend_from_slice(headers);
    bytes.extend_from_slice(b"\r\n");
    bytes
}
fn target(query: &[u8]) -> Vec<u8> {
    let mut bytes = b"/callback?".to_vec();
    bytes.extend_from_slice(query);
    bytes
}
fn is_code(outcome: RequestOutcome) -> bool {
    matches!(outcome, RequestOutcome::Terminal(CallbackValue::Code(_)))
}
fn rejected(bytes: &[u8]) {
    assert!(matches!(
        parse_head(bytes, PORT, STATE),
        RequestOutcome::Probe(_)
    ));
}

#[test]
fn p01_query_decoded_keys_before_values() {
    let state = std::str::from_utf8(STATE).unwrap();
    let alias = format!("st%61te={state}&code=a=b");
    assert!(
        matches!(parse_query(alias.as_bytes(), STATE), Ok(CallbackValue::Code(code)) if &*code == b"a=b")
    );
    // All expected refusals are fixed before parsing. CODE separately verifies
    // that the entire decoded-key pass precedes any value interpretation.
    for raw in [
        format!("state={state}&st%61te={state}&code=x"),
        format!("state={state}&code=x&c%6fde=y"),
        format!("state={state}&x=%GG&code=x"),
        format!("state={state}&%=x&code=x"),
        format!("state={state}&%0=x&code=x"),
        format!("state={state}&%GG=x&code=x"),
        format!("state={state}&=x&code=x"),
        format!("state={state}&&code=x"),
        format!("state={state}&code=x&"),
        format!("state={state}&abcdefghijklmnopqr=x&code=x"),
        format!("state={state}&code=a+b"),
    ] {
        assert!(
            parse_query(raw.as_bytes(), STATE).is_err(),
            "closed key/segment/value predicate"
        );
    }
}

#[test]
fn p02_query_branches_and_bounds() {
    // This independent 94-byte ASCII graphic cycle and its hex expansion are
    // frozen before the production parser is called. No producer supplies it.
    let expected: Vec<u8> = (0..16_377).map(|i| 0x21 + (i % 94) as u8).collect();
    let encoded: String = expected.iter().map(|byte| format!("%{byte:02X}")).collect();
    assert_eq!(expected.len(), 16_377);
    assert_eq!(encoded.len(), 49_131);
    let state = std::str::from_utf8(STATE).unwrap();
    let raw = format!("state={state}&code={encoded}");
    match parse_query(raw.as_bytes(), STATE).unwrap() {
        CallbackValue::Code(actual) => assert_eq!(&*actual, &expected),
        CallbackValue::Error(_) => panic!("literal graphic code must be a code branch"),
    }
    assert!(parse_query(format!("{raw}%41").as_bytes(), STATE).is_err());
    assert!(matches!(
        parse_query(
            format!("state={state}&error=access_denied").as_bytes(),
            STATE
        ),
        Ok(CallbackValue::Error(CallbackErrorKind::AuthorizationDenied))
    ));
    assert!(matches!(
        parse_query(format!("state={state}&error=other").as_bytes(), STATE),
        Ok(CallbackValue::Error(
            CallbackErrorKind::AuthorizationRejected
        ))
    ));
    for n in [1, 128] {
        assert!(
            parse_query(
                format!("state={state}&error={}", "a".repeat(n)).as_bytes(),
                STATE
            )
            .is_ok()
        );
    }
    assert!(
        parse_query(
            format!("state={state}&error={}", "a".repeat(129)).as_bytes(),
            STATE
        )
        .is_err()
    );
    for description in [String::new(), "a".repeat(1024), "é".repeat(512)] {
        let raw = format!("state={state}&error=other&error_description={description}");
        assert!(parse_query(raw.as_bytes(), STATE).is_ok());
    }
    for raw in [
        format!(
            "state={state}&error=other&error_description={}",
            "a".repeat(1025)
        ),
        format!("state={state}&error=other&error_description=%00"),
        format!("state={state}&error=other&error_description=%7F"),
        format!("state={state}&error=other&error_description=%C2%80"),
        format!("state={state}&error=other&error_description=%FF"),
        format!("state={state}&code=x&error=other"),
        format!("state={state}&code=x&error_description=description"),
        format!("state={state}&error_description=description"),
        format!("state={state}&code="),
        format!("state={state}&error="),
        format!("state={}&code=x", "B".repeat(43)),
        format!("state={}&code=x", "A".repeat(42)),
        format!("state={state}!&code=x"),
        "code=x".into(),
    ] {
        assert!(
            parse_query(raw.as_bytes(), STATE).is_err(),
            "literal branch/bound refusal"
        );
    }
}

#[test]
fn p03_http_exact_framing() {
    let query = valid_query("owned-code");
    let callback_target = target(&query);
    assert!(is_code(parse_head(
        &frame(&callback_target, b""),
        PORT,
        STATE
    )));
    assert!(is_code(parse_head(
        &frame(&callback_target, b"Content-Length:\t0 \r\n"),
        PORT,
        STATE
    )));
    for headers in [
        &b"Host: 127.0.0.1:43129\r\n"[..],
        b"Transfer-Encoding: identity\r\n",
        b"Content-Length: 1\r\n",
        b"Content-Length: 00\r\n",
        b"Content-Length: 0\r\nContent-Length: 0\r\n",
        b" X: fold\r\n",
        b"X : value\r\n",
        b"X: \x80\r\n",
        b"X: bare\n",
    ] {
        rejected(&frame(&callback_target, headers));
    }
    let wrong_host = frame(&callback_target, b"");
    let wrong_host = String::from_utf8(wrong_host)
        .unwrap()
        .replace("127.0.0.1:43129", "localhost:43129");
    rejected(wrong_host.as_bytes());
    for raw in [
        frame(&callback_target, b"")
            .into_iter()
            .chain(b"x".iter().copied())
            .collect::<Vec<_>>(),
        frame(&callback_target, b"")
            .into_iter()
            .chain(b"GET / HTTP/1.1\r\n\r\n".iter().copied())
            .collect(),
        String::from_utf8(frame(&callback_target, b""))
            .unwrap()
            .replace("GET ", "GET  ")
            .into_bytes(),
        String::from_utf8(frame(&callback_target, b""))
            .unwrap()
            .replace("HTTP/1.1", "HTTP/1.0")
            .into_bytes(),
        frame(b"/callback/../callback?state=x&code=y", b""),
        frame(b"http://127.0.0.1:43129/callback?state=x&code=y", b""),
        frame(b"/callback?state=x&code=y#fragment", b""),
    ] {
        rejected(&raw);
    }
    let mut headers = Vec::new();
    for _ in 0..63 {
        headers.extend_from_slice(b"X: a\r\n");
    }
    assert!(is_code(parse_head(
        &frame(&callback_target, &headers),
        PORT,
        STATE
    )));
    headers.extend_from_slice(b"X: a\r\n");
    rejected(&frame(&callback_target, &headers));
    let line8192 = format!("X:{}\r\n", "a".repeat(8188));
    assert_eq!(line8192.len(), 8192);
    assert!(is_code(parse_head(
        &frame(&callback_target, line8192.as_bytes()),
        PORT,
        STATE
    )));
    rejected(&frame(
        &callback_target,
        format!("X:{}\r\n", "a".repeat(8189)).as_bytes(),
    ));
    let long_query = valid_query(&"a".repeat(10_000));
    assert!(
        is_code(parse_head(&frame(&target(&long_query), b""), PORT, STATE)),
        "request line is exempt from the ordinary header line bound"
    );
    // Exact total head boundary, with ordinary lines independently <=8192.
    let mut exact = frame(&callback_target, b"");
    exact.truncate(exact.len() - 2);
    for _ in 0..7 {
        exact.extend_from_slice(line8192.as_bytes());
    }
    let last_len = 65_536 - exact.len() - 2;
    assert!((4..=8192).contains(&last_len));
    exact.extend_from_slice(format!("X:{}\r\n", "b".repeat(last_len - 4)).as_bytes());
    exact.extend_from_slice(b"\r\n");
    assert_eq!(exact.len(), 65_536);
    assert!(is_code(parse_head(&exact, PORT, STATE)));
    exact.push(b'x');
    assert_eq!(exact.len(), 65_537);
    rejected(&exact);
    assert!(matches!(
        parse_head(&frame(b"/other", b""), PORT, STATE),
        RequestOutcome::Probe(ProbeStatus::NotFound)
    ));
    let method = String::from_utf8(frame(&callback_target, b""))
        .unwrap()
        .replacen("GET", "POST", 1);
    assert!(matches!(
        parse_head(method.as_bytes(), PORT, STATE),
        RequestOutcome::Probe(ProbeStatus::MethodNotAllowed)
    ));
}

struct SyntheticGuard;
impl HostRequestBindingGuard for SyntheticGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Err(HostRequestBindingError::Unavailable) })
    }
}
struct Receiver<'a> {
    calls: AtomicUsize,
    close: Option<&'a RequestBindingOwnerLease>,
}
impl GatewayAuthorizationCallbackUrlReceiver for Receiver<'_> {
    fn accept_url(&self, value: &str) -> Result<(), HostRequestBindingError> {
        assert_eq!(value, "https://unit.invalid/authorize?original=literal");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(lease) = self.close {
            lease.close();
        }
        Ok(())
    }
}

#[test]
fn p04_invocation_issuer_and_once() {
    // Nominal identity vectors only; SyntheticGuard grants no real Server Host.
    for single in [false, true] {
        let kind = if single {
            HostRequestBindingKind::ServerSingleUserOwner
        } else {
            HostRequestBindingKind::ServerSession
        };
        let auth = AuthContextBuilder::from_verified_session(
            DeploymentId::new("pure-deployment"),
            TenantId::new("pure-tenant"),
            ActorId::new("pure-actor"),
            AuthGeneration::new(7),
            single,
        )
        .build();
        let (lease, issuer) = RequestBindingOwnerLease::for_trusted_host(kind);
        let (_foreign_lease, foreign) = RequestBindingOwnerLease::for_trusted_host(kind);
        let binding = if single {
            issuer
                .bind_single_user_owner(&auth, Arc::new(SyntheticGuard))
                .unwrap()
        } else {
            issuer
                .bind_server_session(
                    &auth,
                    ServerSessionBindingIdentity::from_verified_row(
                        "pure-session".into(),
                        ActorId::new("pure-actor"),
                        "pure-token-column".into(),
                        time::OffsetDateTime::from_unix_timestamp(1000).unwrap(),
                        AuthGeneration::new(7),
                    ),
                    Arc::new(SyntheticGuard),
                )
                .unwrap()
        };
        let identity = binding.identity();
        let url = "https://unit.invalid/authorize?original=literal";
        if !single {
            // Same-issuer nominal full-epoch vectors, handwritten before delivery.
            // These do not prove genuine Server current/DB or future-lease refusal.
            for (session_id, token_column, created) in [
                ("pure-old-session", "pure-token-column", 1000),
                ("pure-session", "pure-old-token-column", 1000),
                ("pure-session", "pure-token-column", 900),
                ("pure-old-session", "pure-old-token-column", 900),
                ("pure-future-session", "pure-future-token-column", 1100),
            ] {
                let other_binding = issuer
                    .bind_server_session(
                        &auth,
                        ServerSessionBindingIdentity::from_verified_row(
                            session_id.into(),
                            ActorId::new("pure-actor"),
                            token_column.into(),
                            time::OffsetDateTime::from_unix_timestamp(created).unwrap(),
                            AuthGeneration::new(7),
                        ),
                        Arc::new(SyntheticGuard),
                    )
                    .unwrap();
                let other_identity = other_binding.identity();
                let epoch_receiver = Receiver {
                    calls: AtomicUsize::new(0),
                    close: None,
                };
                let invocation = issuer
                    .gateway_callback_url_invocation(identity, url)
                    .unwrap();
                assert_eq!(
                    invocation.deliver_to(&issuer, other_identity, &epoch_receiver),
                    Err(HostRequestBindingError::NotCurrent)
                );
                let invocation = issuer
                    .gateway_callback_url_invocation(other_identity, url)
                    .unwrap();
                assert_eq!(
                    invocation.deliver_to(&issuer, identity, &epoch_receiver),
                    Err(HostRequestBindingError::NotCurrent)
                );
                assert_eq!(epoch_receiver.calls.load(Ordering::SeqCst), 0);
            }
        }
        assert!(
            foreign
                .gateway_callback_url_invocation(identity, url)
                .is_err()
        );
        let receiver = Receiver {
            calls: AtomicUsize::new(0),
            close: None,
        };
        let invocation = issuer
            .gateway_callback_url_invocation(identity, url)
            .unwrap();
        assert!(
            invocation
                .deliver_to(&foreign, identity, &receiver)
                .is_err()
        );
        assert_eq!(receiver.calls.load(Ordering::SeqCst), 0);
        let invocation = issuer
            .gateway_callback_url_invocation(identity, url)
            .unwrap();
        invocation.deliver_to(&issuer, identity, &receiver).unwrap();
        assert_eq!(receiver.calls.load(Ordering::SeqCst), 1);
        let closing = Receiver {
            calls: AtomicUsize::new(0),
            close: Some(&lease),
        };
        let invocation = issuer
            .gateway_callback_url_invocation(identity, url)
            .unwrap();
        assert_eq!(
            invocation.deliver_to(&issuer, identity, &closing),
            Err(HostRequestBindingError::NotCurrent)
        );
        assert_eq!(closing.calls.load(Ordering::SeqCst), 1);
        assert!(
            issuer
                .gateway_callback_url_invocation(identity, url)
                .is_err()
        );
    }
}

struct Clock(Mutex<ClockSample>);
impl InitialClock for Clock {
    fn sample(&self) -> ClockSample {
        *self.0.lock().unwrap()
    }
}

#[test]
fn p05_completed_stage_flow_budget() {
    let mono = Instant::now();
    let wall = DateTime::<Utc>::from_timestamp(1000, 0).unwrap();
    let clock = Arc::new(Clock(Mutex::new(ClockSample { wall, mono })));
    let original: ClockOwner = clock.clone();
    let parent = CancellationToken::new();
    let flow = SavedFlow::new(
        original,
        parent.clone(),
        (mono + Duration::from_secs(60)).into_std(),
    )
    .unwrap();
    let registration_budget = InitialBudget {
        original_parent: parent.clone(),
        owner_deadline: flow.deadline,
        http_entered_at: mono,
        deadline: mono + Duration::from_secs(10),
    };
    *clock.0.lock().unwrap() = ClockSample {
        wall: wall + chrono::Duration::seconds(11),
        mono: mono + Duration::from_secs(11),
    };
    assert_eq!(
        flow.check(Some(&registration_budget)).err().unwrap().kind(),
        Kind::Deadline
    );
    assert!(
        flow.check(None).is_ok(),
        "callback uses the same original Flow without the completed registration budget"
    );
    assert_eq!(flow.deadline, mono + Duration::from_secs(60));
    *clock.0.lock().unwrap() = ClockSample {
        wall: wall + chrono::Duration::seconds(60),
        mono: mono + Duration::from_secs(60),
    };
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Deadline);
    parent.cancel();
    assert_eq!(flow.check(None).err().unwrap().kind(), Kind::Cancelled);
}

fn static_response(response: &[u8], expected_status: &[u8], body: &[u8]) {
    assert!(response.starts_with(expected_status));
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    assert_eq!(&response[split + 4..], body);
    let headers = std::str::from_utf8(&response[..split])
        .unwrap()
        .to_ascii_lowercase();
    assert!(headers.contains(&format!("\r\ncontent-length: {}", body.len())));
    assert!(headers.contains("\r\ncontent-type: text/plain"));
    assert!(headers.contains("\r\nconnection: close"));
    assert!(headers.contains("\r\ncache-control: no-store"));
}

#[test]
fn p06_owned_partial_drop_and_static_error() {
    let material = callback_pkce_material().unwrap();
    for bytes in [&material.state, &material.verifier, &material.challenge] {
        assert_eq!(bytes.len(), 43);
        assert!(
            bytes
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        );
    }
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(material.verifier.as_bytes()));
    assert_eq!(&*material.challenge, &expected);
    drop(material); // Local owned armed fields drop; allocator/RNG stack erasure is UNPROVEN.
    for (raw, allowed) in [
        ("https://unit.invalid/authorize", true),
        ("https://unit.invalid/authorize?", true),
        ("https://unit.invalid/authorize?q=x", false),
        ("https://unit.invalid/authorize#", false),
        ("https://unit.invalid/authorize#x", false),
    ] {
        assert_eq!(
            callback_authorization_endpoint_allowed(&url::Url::parse(raw).unwrap()),
            allowed
        );
    }
    for occupied in 0..=5 {
        assert_eq!(accept_allowed(occupied), occupied < 4);
    }
    static_response(RESPONSE_CODE, b"HTTP/1.1 200", b"Callback received.");
    static_response(
        RESPONSE_ERROR,
        b"HTTP/1.1 200",
        b"Authorization was not completed.",
    );
    for (response, status) in [
        (RESPONSE_BAD_REQUEST, &b"HTTP/1.1 400"[..]),
        (RESPONSE_NOT_FOUND, b"HTTP/1.1 404"),
        (RESPONSE_METHOD_NOT_ALLOWED, b"HTTP/1.1 405"),
    ] {
        static_response(response, status, b"");
    }
}
