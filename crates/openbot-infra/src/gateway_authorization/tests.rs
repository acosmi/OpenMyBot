use super::*;
use crate::gateway_account::GatewayAccountClient;
use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE};
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

const ORIGIN: &str = "https://unit.invalid";
const REDIRECT: &str = "http://127.0.0.1:43127/callback?original=yes";
const GOOD_TOKEN: &[u8] = br#"{"access_token":"access-synthetic","token_type":"Bearer","expires_in":60,"refresh_token":"refresh-synthetic","scope":"ai account"}"#;

struct TestClock {
    current: Mutex<ClockSample>,
    samples: AtomicUsize,
}
impl TestClock {
    fn new(wall: chrono::DateTime<chrono::Utc>) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(ClockSample {
                wall,
                mono: tokio::time::Instant::now(),
            }),
            samples: AtomicUsize::new(0),
        })
    }
    fn current(&self) -> ClockSample {
        let sample = self.current.lock().expect("clock lock");
        ClockSample {
            wall: sample.wall,
            mono: sample.mono,
        }
    }
    fn advance(&self, wall: chrono::TimeDelta, mono: Duration) {
        let mut sample = self.current.lock().expect("clock lock");
        sample.wall = sample
            .wall
            .checked_add_signed(wall)
            .expect("test wall range");
        sample.mono += mono;
    }
}
impl InitialClock for TestClock {
    fn sample(&self) -> ClockSample {
        self.samples.fetch_add(1, Ordering::SeqCst);
        self.current()
    }
}
fn clock() -> Arc<TestClock> {
    TestClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-10-09T20:00:00.123456Z")
            .expect("test time")
            .with_timezone(&chrono::Utc),
    )
}
#[derive(Default)]
struct BodyProbe {
    polls: AtomicUsize,
    drops: AtomicUsize,
}
struct ProbeBody {
    chunks: VecDeque<Result<Bytes, acosmi::TransportError>>,
    probe: Arc<BodyProbe>,
    before_first: Option<Box<dyn FnOnce() + Send>>,
}
impl Stream for ProbeBody {
    type Item = Result<Bytes, acosmi::TransportError>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.probe.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = this.before_first.take() {
            hook();
        }
        Poll::Ready(this.chunks.pop_front())
    }
}
impl Drop for ProbeBody {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}
fn response_with(
    status: u16,
    headers: HeaderMap,
    chunks: Vec<Result<Bytes, acosmi::TransportError>>,
    before_first: Option<Box<dyn FnOnce() + Send>>,
) -> (acosmi::HttpResponse, Arc<BodyProbe>) {
    let probe = Arc::new(BodyProbe::default());
    let body = ProbeBody {
        chunks: chunks.into(),
        probe: probe.clone(),
        before_first,
    };
    (
        acosmi::HttpResponse {
            status: StatusCode::from_u16(status).expect("test status"),
            headers,
            body: Box::pin(body),
        },
        probe,
    )
}
fn response(status: u16, raw: &[u8]) -> (acosmi::HttpResponse, Arc<BodyProbe>) {
    response_with(
        status,
        json_headers(),
        vec![Ok(Bytes::copy_from_slice(raw))],
        None,
    )
}
struct MetadataTransport;
#[async_trait]
impl acosmi::HttpTransport for MetadataTransport {
    async fn execute(
        &self,
        request: acosmi::HttpRequest,
        cancel: CancellationToken,
    ) -> Result<acosmi::HttpResponse, acosmi::TransportError> {
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.url.as_str(),
            "https://unit.invalid/.well-known/oauth-authorization-server/desktop"
        );
        assert!(!cancel.is_cancelled());
        assert!(request.body.is_empty());
        let body = br#"{"issuer":"https://unit.invalid","authorization_endpoint":"https://unit.invalid/oauth/desktop/authorize","token_endpoint":"https://unit.invalid/oauth/desktop/token","registration_endpoint":"https://unit.invalid/oauth/desktop/register","revocation_endpoint":"https://unit.invalid/oauth/desktop/revoke","scopes_supported":["ai","account"],"response_types_supported":["code"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"grant_types_supported":["authorization_code","refresh_token"],"crabcode_auth_contract_version":2,"gateway_error_contract_version":1}"#;
        Ok(response(200, body).0)
    }
}
async fn metadata() -> GatewayDesktopMetadata {
    GatewayAccountClient::new(ORIGIN, Arc::new(MetadataTransport))
        .expect("synthetic client")
        .fetch_metadata(CancellationToken::new())
        .await
        .expect("actual metadata reader")
}
async fn input(code: bool, clock: &Arc<TestClock>) -> OwnedInitialInput {
    let mut input = if code {
        owned_code_input(
            metadata().await,
            Zeroizing::new("client-original".to_owned()),
            Zeroizing::new("code-synthetic".to_owned()),
            Zeroizing::new(REDIRECT.to_owned()),
            Zeroizing::new("v".repeat(43)),
        )
        .expect("owned code input")
    } else {
        owned_registration_input(metadata().await, Zeroizing::new(REDIRECT.to_owned()))
            .expect("owned registration input")
    };
    input.clock = clock.clone();
    input
}
struct Fixture {
    prepared: PreparedInitialOwner,
    clock: Arc<TestClock>,
    parent: CancellationToken,
}
async fn fixture_with(code: bool, clock: Arc<TestClock>, budget: Duration) -> Fixture {
    let parent = CancellationToken::new();
    let deadline = clock.current().mono + budget;
    let prepared = prepare_initial(
        input(code, &clock).await,
        retain_parent_budget(parent.clone(), deadline),
    )
    .await
    .expect("actual helper captured");
    Fixture {
        prepared,
        clock,
        parent,
    }
}
async fn fixture(code: bool) -> Fixture {
    fixture_with(code, clock(), Duration::from_secs(50)).await
}
async fn check_reply(code: bool, status: u16, raw: &[u8]) -> Result<InitialReply, InitialError> {
    let f = fixture(code).await;
    consume_initial(f.prepared, response(status, raw).0).await
}
fn assert_reason(result: Result<InitialReply, InitialError>, reason: ReplyInvalidReason) {
    assert!(
        matches!(result, Err(InitialError::ProtocolInvalid(actual)) if actual == reason),
        "unexpected closed protocol category"
    );
}
fn token_with(field: &str, value: serde_json::Value) -> Vec<u8> {
    let mut token: serde_json::Value = serde_json::from_slice(GOOD_TOKEN).expect("test JSON");
    token[field] = value;
    serde_json::to_vec(&token).expect("test serialization")
}
fn token_ttl(lexeme: &str) -> Vec<u8> {
    format!("{{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":{lexeme},\"refresh_token\":\"r\",\"scope\":\"ai account\"}}").into_bytes()
}

#[tokio::test]
async fn c01() {
    for raw in [
        br#" {"client_id":"x"} "#.as_slice(),
        b"\r\n{\t\"client_id\" : \"x\"\n}\t",
    ] {
        assert!(matches!(
            check_reply(false, 200, raw).await,
            Ok(InitialReply::Registration(_))
        ));
    }
    for raw in [
        b"\xef\xbb\xbf{\"client_id\":\"x\"}".as_slice(),
        b"[]",
        b"null",
        b"0",
        b"{\"client_id\":\"x\"}x",
        b"{\"client_id\":\"\xff\"}",
        b"{\"client_id\":\"x\"}\x0b",
    ] {
        assert_reason(
            check_reply(false, 200, raw).await,
            ReplyInvalidReason::JsonSyntax,
        );
    }
}
#[tokio::test]
async fn c02() {
    for raw in [
        br#"{"client_id":"x","client_id":"y"}"#.as_slice(),
        b"{\"client_id\":\"x\",\"client_\\u0069d\":\xff}",
    ] {
        assert_reason(
            check_reply(false, 200, raw).await,
            ReplyInvalidReason::DuplicateKey,
        );
    }
}
#[tokio::test]
async fn c03() {
    for raw in [
        b"{\"unknown\":\xff}".as_slice(),
        b"{\"Client_id\":null}",
        b"{\"client_idxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\":null}",
    ] {
        assert_reason(
            check_reply(false, 200, raw).await,
            ReplyInvalidReason::UnknownKey,
        );
    }
    for key in ["client_id", "server_url", "response_types"] {
        let mut value: serde_json::Value = serde_json::from_slice(GOOD_TOKEN).expect("fixture");
        value[key] = serde_json::json!("synthetic");
        assert_reason(
            check_reply(true, 200, &serde_json::to_vec(&value).expect("fixture")).await,
            ReplyInvalidReason::UnknownKey,
        );
    }
}
#[tokio::test]
async fn c04() {
    for raw in [
        b"{\"client_secret\":null}".as_slice(),
        b"{\"client_secr\\u0065t\":\xff}",
        b"{\"client_secret\":{this is malformed}",
    ] {
        for code in [false, true] {
            assert_reason(
                check_reply(code, 200, raw).await,
                ReplyInvalidReason::ForbiddenSecretKey,
            );
        }
        let (result, position) = reply::test_token_cursor(raw);
        assert!(matches!(
            result,
            Err(InitialError::ProtocolInvalid(
                ReplyInvalidReason::ForbiddenSecretKey
            ))
        ));
        assert!(
            position
                <= raw
                    .iter()
                    .position(|byte| *byte == b':')
                    .expect("key delimiter")
        );
    }
}
#[tokio::test]
async fn c05() {
    for raw in [
        br#"{"client_id":"\uD83D\uDE00"}"#.as_slice(),
        br#"{"client_id":"a\"b\\c\/d"}"#,
    ] {
        assert!(check_reply(false, 200, raw).await.is_ok());
    }
    for raw in [
        br#"{"client_id":"\uD800"}"#.as_slice(),
        br#"{"client_id":"\uDC00"}"#,
        br#"{"client_id":"\uD800\u0041"}"#,
        br#"{"client_id":"\q"}"#,
        b"{\"client_id\":\"a\nb\"}",
    ] {
        assert_reason(
            check_reply(false, 200, raw).await,
            ReplyInvalidReason::JsonSyntax,
        );
    }
}
#[tokio::test]
async fn c06() {
    for media in [
        "application/json",
        " \tApplication/JSON\t ",
        "application/json; charset=utf-8",
        "application/json ; charset = \"UTF-8\"",
        "application/json;charset=UtF-8",
        "application/json; ChArSeT=\"uTf-8\"",
    ] {
        let f = fixture(false).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(media).expect("fixture header"),
        );
        assert!(
            consume_initial(
                f.prepared,
                response_with(
                    200,
                    headers,
                    vec![Ok(Bytes::from_static(br#"{"client_id":"x"}"#))],
                    None
                )
                .0
            )
            .await
            .is_ok()
        );
    }
    for boundary in 0..3 {
        let f = fixture(false).await;
        let mut headers = json_headers();
        match boundary {
            0 => {
                for _ in 0..63 {
                    headers.append("x", HeaderValue::from_static("x"));
                }
                assert_eq!(headers.iter().count(), 64);
            }
            1 => {
                headers.insert(
                    "x",
                    HeaderValue::from_str(&"x".repeat(8192)).expect("header"),
                );
            }
            _ => {
                for _ in 0..7 {
                    headers.append(
                        "x",
                        HeaderValue::from_str(&"x".repeat(8192)).expect("header"),
                    );
                }
                let total: usize = headers
                    .iter()
                    .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                    .sum();
                let remaining = 65536 - total - 1;
                headers.append(
                    "x",
                    HeaderValue::from_str(&"x".repeat(remaining)).expect("header"),
                );
                assert_eq!(
                    headers
                        .iter()
                        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                        .sum::<usize>(),
                    65536
                );
            }
        }
        assert!(
            consume_initial(
                f.prepared,
                response_with(
                    200,
                    headers,
                    vec![Ok(Bytes::from_static(br#"{"client_id":"x"}"#))],
                    None
                )
                .0
            )
            .await
            .is_ok()
        );
    }
    let f = fixture(true).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x",
        HeaderValue::from_str(&"x".repeat(8193)).expect("header"),
    );
    assert_reason(
        consume_initial(f.prepared, response_with(400, headers, vec![], None).0).await,
        ReplyInvalidReason::HeaderLimit,
    );
    let f = fixture(true).await;
    let (response, probe) = response_with(
        400,
        HeaderMap::new(),
        vec![Err(acosmi::TransportError::Body)],
        None,
    );
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::HttpStatus(400))
    ));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
    for media in [
        "text/json",
        "application/json, application/json",
        "application/json; charset=ascii",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; extra=1",
        "application/json; charset=\"utf-8\"x",
    ] {
        let f = fixture(false).await;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(media).expect("header"));
        assert_reason(
            consume_initial(
                f.prepared,
                response_with(200, headers, vec![Ok(Bytes::from_static(b"{}"))], None).0,
            )
            .await,
            ReplyInvalidReason::MediaType,
        );
    }
    for scenario in 0..5 {
        let f = fixture(false).await;
        let mut headers = json_headers();
        match scenario {
            0 => {
                headers.remove(CONTENT_TYPE);
            }
            1 => {
                headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            2 => {
                for _ in 0..64 {
                    headers.append("x-many", HeaderValue::from_static("x"));
                }
            }
            3 => {
                headers.insert(
                    "x-big",
                    HeaderValue::from_str(&"x".repeat(8193)).expect("header"),
                );
            }
            _ => {
                for _ in 0..8 {
                    headers.append(
                        "x-total",
                        HeaderValue::from_str(&"x".repeat(8192)).expect("header"),
                    );
                }
            }
        }
        let (response, probe) =
            response_with(200, headers, vec![Ok(Bytes::from_static(b"{}"))], None);
        assert_reason(
            consume_initial(f.prepared, response).await,
            if scenario < 2 {
                ReplyInvalidReason::MediaType
            } else {
                ReplyInvalidReason::HeaderLimit
            },
        );
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn c07() {
    let mut raw = br#"{"client_id":"x"}"#.to_vec();
    raw.resize(65536, b' ');
    assert!(check_reply(false, 200, &raw).await.is_ok());
    raw.push(b' ');
    assert_reason(
        check_reply(false, 200, &raw).await,
        ReplyInvalidReason::BodyLimit,
    );
    let f = fixture(false).await;
    let (response, probe) = response_with(
        200,
        json_headers(),
        vec![
            Ok(Bytes::from(vec![b' '; 32768])),
            Ok(Bytes::from(vec![b' '; 32768])),
            Ok(Bytes::from_static(b"x")),
            Ok(Bytes::from_static(b"never")),
        ],
        None,
    );
    assert_reason(
        consume_initial(f.prepared, response).await,
        ReplyInvalidReason::BodyLimit,
    );
    assert_eq!(probe.polls.load(Ordering::SeqCst), 3);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn c08() {
    for status in [199, 202, 204, 302, 400, 401, 429, 500] {
        let f = fixture(true).await;
        let (response, probe) = response(status, b"{vendor secrets malformed");
        assert!(
            matches!(consume_initial(f.prepared, response).await, Err(InitialError::HttpStatus(actual)) if actual == status)
        );
        assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    let f = fixture(true).await;
    let (response, probe) = response_with(
        200,
        json_headers(),
        vec![Err(acosmi::TransportError::Body)],
        None,
    );
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::BodyTransport)
    ));
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    let f = fixture(true).await;
    f.parent.cancel();
    let mut headers = json_headers();
    headers.insert(
        "x-limit",
        HeaderValue::from_str(&"x".repeat(8193)).expect("header"),
    );
    let (response, probe) =
        response_with(400, headers, vec![Err(acosmi::TransportError::Body)], None);
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::Cancelled)
    ));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn r01() {
    for status in [200, 201] {
        assert!(matches!(
            check_reply(false, status, br#"{"client_id":"x"}"#).await,
            Ok(InitialReply::Registration(_))
        ));
    }
    for status in [202, 204, 400] {
        assert!(
            matches!(check_reply(false, status, b"{}").await, Err(InitialError::HttpStatus(s)) if s == status)
        );
    }
}
#[tokio::test]
async fn r02() {
    for id in [
        "x".to_owned(),
        "x".repeat(256),
        "\u{2603}".repeat(85),
        format!("{}x", "\u{2603}".repeat(85)),
    ] {
        assert!(
            check_reply(
                false,
                200,
                &serde_json::to_vec(&serde_json::json!({"client_id":id})).expect("fixture")
            )
            .await
            .is_ok()
        );
    }
    for id in [
        String::new(),
        "x".repeat(257),
        "\u{2603}".repeat(86),
        " x".to_owned(),
        "x ".to_owned(),
        "\u{0000}".to_owned(),
        "\u{007f}".to_owned(),
        "\u{0085}".to_owned(),
        "\u{009f}".to_owned(),
    ] {
        assert!(
            check_reply(
                false,
                200,
                &serde_json::to_vec(&serde_json::json!({"client_id":id})).expect("fixture")
            )
            .await
            .is_err()
        );
    }
}
#[tokio::test]
async fn r03() {
    let result = check_reply(false, 201, br#"{"client_id":"client-returned"}"#)
        .await
        .expect("missing optional echoes allowed");
    match result {
        InitialReply::Registration(owner) => {
            assert_eq!(owner.client_id.as_str(), "client-returned");
            assert_eq!(owner.original_redirect_uri.as_str(), REDIRECT);
        }
        InitialReply::Tokens(_) => panic!("wrong reply kind"),
    }
}
#[tokio::test]
async fn r04() {
    let raw = serde_json::to_vec(&serde_json::json!({"token_endpoint_auth_method":"none","redirect_uris":[REDIRECT],"grant_types":["authorization_code","refresh_token"],"client_name":"Wrok Bot","client_id":"x"})).expect("fixture");
    assert!(check_reply(false, 200, &raw).await.is_ok());
    let reverse = format!(
        "{{\"token_endpoint_auth_method\":\"none\",\"redirect_uris\":[{}],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"client_name\":\"Wrok Bot\",\"client_id\":\"x\"}}",
        serde_json::to_string(REDIRECT).expect("fixture")
    );
    assert!(check_reply(false, 200, reverse.as_bytes()).await.is_ok());
    for key in ["scope", "response_types"] {
        let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("fixture");
        value[key] = serde_json::json!(["code"]);
        assert_reason(
            check_reply(false, 200, &serde_json::to_vec(&value).expect("fixture")).await,
            ReplyInvalidReason::UnknownKey,
        );
    }
}
#[tokio::test]
async fn r05() {
    for value in [
        serde_json::json!("wrok bot"),
        serde_json::json!("Wrok Bot "),
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::json!(["Wrok Bot"]),
    ] {
        let raw = serde_json::to_vec(&serde_json::json!({"client_id":"x","client_name":value}))
            .expect("fixture");
        assert!(check_reply(false, 200, &raw).await.is_err());
    }
}
#[tokio::test]
async fn r06() {
    for value in [
        serde_json::json!([]),
        serde_json::json!([REDIRECT, REDIRECT]),
        serde_json::json!(["http://127.0.0.1:43128/callback?original=yes"]),
        serde_json::json!(["http://127.0.0.1:43127/other?original=yes"]),
        serde_json::json!(REDIRECT),
        serde_json::Value::Null,
    ] {
        let raw = serde_json::to_vec(&serde_json::json!({"client_id":"x","redirect_uris":value}))
            .expect("fixture");
        assert!(check_reply(false, 200, &raw).await.is_err());
    }
}
#[tokio::test]
async fn r07() {
    for raw in [br#"{"client_id":"x","grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}"#.as_slice(), br#"{"client_id":"x"}"#] { assert!(check_reply(false, 200, raw).await.is_ok()); }
    for raw in [
        br#"{"client_id":"x","grant_types":["refresh_token","authorization_code"]}"#.as_slice(),
        br#"{"client_id":"x","grant_types":null}"#,
        br#"{"client_id":"x","grant_types":["authorization_code"]}"#,
        br#"{"client_id":"x","token_endpoint_auth_method":null}"#,
        br#"{"client_id":"x","token_endpoint_auth_method":"client_secret_post"}"#,
    ] {
        assert!(check_reply(false, 200, raw).await.is_err());
    }
}

#[tokio::test]
async fn t01() {
    assert!(matches!(
        check_reply(true, 200, GOOD_TOKEN).await,
        Ok(InitialReply::Tokens(_))
    ));
    assert!(matches!(
        check_reply(true, 201, GOOD_TOKEN).await,
        Err(InitialError::HttpStatus(201))
    ));
    assert!(matches!(
        check_reply(false, 200, GOOD_TOKEN).await,
        Err(InitialError::ProtocolInvalid(_))
    ));
}
#[tokio::test]
async fn t02() {
    for key in [
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "scope",
    ] {
        for value in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!([])),
            Some(serde_json::json!({})),
        ] {
            let mut token: serde_json::Value = serde_json::from_slice(GOOD_TOKEN).expect("fixture");
            if let Some(value) = value {
                token[key] = value;
            } else {
                token.as_object_mut().expect("object").remove(key);
            }
            assert!(
                check_reply(true, 200, &serde_json::to_vec(&token).expect("fixture"))
                    .await
                    .is_err()
            );
        }
    }
}
#[tokio::test]
async fn t03() {
    for key in ["access_token", "refresh_token"] {
        for token in [
            "x".to_owned(),
            "x".repeat(16377),
            "\\".repeat(16377),
            "!~".to_owned(),
            "a\"b\\c".to_owned(),
        ] {
            assert!(
                check_reply(true, 200, &token_with(key, serde_json::json!(token)))
                    .await
                    .is_ok()
            );
        }
        for token in [
            String::new(),
            "x".repeat(16378),
            "a b".to_owned(),
            "a\t".to_owned(),
            "\u{007f}".to_owned(),
            "\u{2603}".to_owned(),
        ] {
            assert!(
                check_reply(true, 200, &token_with(key, serde_json::json!(token)))
                    .await
                    .is_err()
            );
        }
    }
}
#[tokio::test]
async fn t04() {
    for kind in ["bearer", "BEARER", "Bearer ", " Bearer", "", "Basic"] {
        assert_reason(
            check_reply(
                true,
                200,
                &token_with("token_type", serde_json::json!(kind)),
            )
            .await,
            ReplyInvalidReason::TokenType,
        );
    }
    let reply = check_reply(true, 200, GOOD_TOKEN)
        .await
        .expect("token reply");
    match reply {
        InitialReply::Tokens(guard) => {
            assert_eq!(guard.sdk.access_token, "access-synthetic");
            assert_eq!(guard.sdk.refresh_token, "refresh-synthetic");
        }
        InitialReply::Registration(_) => panic!("wrong reply"),
    }
}
#[tokio::test]
async fn t05() {
    for scope in [
        "ai account",
        "account ai",
        "\tai\naccount\x0c\r ",
        "account\rai",
    ] {
        let reply = check_reply(true, 200, &token_with("scope", serde_json::json!(scope)))
            .await
            .expect("exact scope words");
        match reply {
            InitialReply::Tokens(guard) => assert_eq!(guard.sdk.scope, scope),
            InitialReply::Registration(_) => panic!("wrong reply"),
        }
    }
    for scope in [
        "ai",
        "account",
        "ai ai account",
        "ai account extra",
        "AI account",
        "ai\x0baccount",
        "ai\u{00a0}account",
        "",
        "a i account",
    ] {
        assert!(
            check_reply(true, 200, &token_with("scope", serde_json::json!(scope)))
                .await
                .is_err()
        );
    }
    let scope = format!("ai{}account", " ".repeat(119));
    assert_eq!(scope.len(), 128);
    assert!(
        check_reply(true, 200, &token_with("scope", serde_json::json!(scope)))
            .await
            .is_ok()
    );
    let scope = format!("ai{}account", " ".repeat(120));
    assert!(
        check_reply(true, 200, &token_with("scope", serde_json::json!(scope)))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn t06() {
    for ttl in ["1", "59", "60", "3601"] {
        assert!(check_reply(true, 200, &token_ttl(ttl)).await.is_ok());
    }
    for ttl in [
        "0",
        "-1",
        "+1",
        "1.0",
        "1e1",
        "\"1\"",
        "9223372036854775808",
        "01",
    ] {
        assert!(check_reply(true, 200, &token_ttl(ttl)).await.is_err());
    }
    assert_reason(
        check_reply(true, 200, &token_ttl("9223372036854775807")).await,
        ReplyInvalidReason::ClockOrExpiry,
    );
}
#[tokio::test]
async fn t07() {
    let result = check_reply(true, 200, GOOD_TOKEN).await.expect("tokens");
    match result {
        InitialReply::Tokens(guard) => {
            assert_eq!(guard.sdk.client_id, "client-original");
            assert_eq!(guard.sdk.server_url, ORIGIN);
        }
        InitialReply::Registration(_) => panic!("wrong reply"),
    }
    for key in ["client_id", "server_url", "id_token"] {
        assert_reason(
            check_reply(
                true,
                200,
                &token_with(key, serde_json::json!("reply-injection")),
            )
            .await,
            ReplyInvalidReason::UnknownKey,
        );
    }
}

#[tokio::test]
async fn x01() {
    for ttl in [1_i64, 59, 3601] {
        let f = fixture(true).await;
        let start = f.clock.current();
        f.clock.advance(
            chrono::TimeDelta::milliseconds(250),
            Duration::from_millis(250),
        );
        let reply = consume_initial(f.prepared, response(200, &token_ttl(&ttl.to_string())).0)
            .await
            .expect("short original TTL");
        match reply {
            InitialReply::Tokens(guard) => {
                assert_eq!(
                    guard.expiry.wall_expiry,
                    start.wall + chrono::TimeDelta::seconds(ttl)
                );
                assert_eq!(
                    guard.expiry.mono_expiry,
                    start.mono + Duration::from_secs(u64::try_from(ttl).expect("positive"))
                );
            }
            InitialReply::Registration(_) => panic!("wrong reply"),
        }
    }
}
#[tokio::test]
async fn x02() {
    assert_reason(
        check_reply(true, 200, &token_ttl("9223372036854775807")).await,
        ReplyInvalidReason::ClockOrExpiry,
    );
    let end = chrono::DateTime::parse_from_rfc3339("9999-12-31T23:59:59.500Z")
        .expect("end time")
        .with_timezone(&chrono::Utc);
    let f = fixture_with(true, TestClock::new(end), Duration::from_secs(50)).await;
    assert_reason(
        consume_initial(f.prepared, response(200, &token_ttl("1")).0).await,
        ReplyInvalidReason::ClockOrExpiry,
    );
}
#[tokio::test]
async fn x03() {
    for mode in 0..3 {
        let f = fixture(true).await;
        match mode {
            0 => f
                .clock
                .advance(chrono::TimeDelta::microseconds(-1), Duration::ZERO),
            1 => f
                .clock
                .advance(chrono::TimeDelta::seconds(1), Duration::ZERO),
            _ => f
                .clock
                .advance(chrono::TimeDelta::zero(), Duration::from_secs(1)),
        }
        assert_reason(
            consume_initial(f.prepared, response(200, &token_ttl("1")).0).await,
            ReplyInvalidReason::ClockOrExpiry,
        );
    }
}
#[tokio::test]
async fn x04() {
    let f = fixture(true).await;
    let parent = f.parent.clone();
    let (response, probe) = response_with(
        200,
        json_headers(),
        vec![Ok(Bytes::from_static(GOOD_TOKEN))],
        Some(Box::new(move || parent.cancel())),
    );
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::Cancelled)
    ));
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
    let f = fixture(true).await;
    let c = f.clock.clone();
    let (response, probe) = response_with(
        200,
        json_headers(),
        vec![
            Ok(Bytes::from_static(GOOD_TOKEN)),
            Ok(Bytes::from_static(b"never polled")),
        ],
        Some(Box::new(move || {
            c.advance(chrono::TimeDelta::zero(), Duration::from_secs(10))
        })),
    );
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::Deadline)
    ));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    let f = fixture(true).await;
    f.clock
        .advance(chrono::TimeDelta::zero(), Duration::from_secs(10));
    let (response, probe) = self::response(200, GOOD_TOKEN);
    assert!(matches!(
        consume_initial(f.prepared, response).await,
        Err(InitialError::Deadline)
    ));
    assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn x05() {
    let wall = chrono::DateTime::parse_from_rfc3339("2026-10-09T20:00:00.999500Z")
        .expect("time")
        .with_timezone(&chrono::Utc);
    let f = fixture_with(true, TestClock::new(wall), Duration::from_secs(50)).await;
    let reply = consume_initial(f.prepared, response(200, &token_ttl("1")).0)
        .await
        .expect("future down-ms expiry");
    match reply {
        InitialReply::Tokens(guard) => {
            assert_eq!(guard.sdk.expires_at, "2026-10-09T20:00:01.999Z");
            assert_eq!(guard.sdk.expires_at.len(), 24);
        }
        InitialReply::Registration(_) => panic!("wrong reply"),
    }
    let f = fixture_with(true, TestClock::new(wall), Duration::from_secs(50)).await;
    f.clock.advance(
        chrono::TimeDelta::microseconds(999500),
        Duration::from_micros(999500),
    );
    assert_reason(
        consume_initial(f.prepared, response(200, &token_ttl("1")).0).await,
        ReplyInvalidReason::ClockOrExpiry,
    );
}

#[tokio::test]
async fn p01() {
    let f = fixture(false).await;
    let request = f.prepared.request.as_ref().expect("whole actual request");
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.url.as_str(),
        "https://unit.invalid/oauth/desktop/register"
    );
    assert_eq!(
        request.headers.get(CONTENT_TYPE).expect("SDK media"),
        "application/json"
    );
    assert_eq!(
        request.context.purpose,
        acosmi::HttpPurpose::OAuthRegistration
    );
    assert_eq!(
        request.context.response_mode,
        acosmi::HttpResponseMode::Buffered
    );
    assert_eq!(request.context.timeout, Duration::from_secs(30));
    let actual: serde_json::Value =
        serde_json::from_slice(&request.body).expect("actual SDK registration JSON");
    assert_eq!(
        actual,
        serde_json::json!({"client_name":"Wrok Bot","redirect_uris":[REDIRECT],"response_types":["code"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"})
    );
}
#[tokio::test]
async fn p02() {
    let f = fixture(true).await;
    let request = f.prepared.request.as_ref().expect("whole actual request");
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.url.as_str(),
        "https://unit.invalid/oauth/desktop/token"
    );
    assert_eq!(
        request.headers.get(CONTENT_TYPE).expect("SDK media"),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(request.context.purpose, acosmi::HttpPurpose::OAuthToken);
    assert_eq!(
        request.context.response_mode,
        acosmi::HttpResponseMode::Buffered
    );
    assert_eq!(request.context.timeout, Duration::from_secs(30));
    let actual: std::collections::BTreeMap<_, _> = url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect();
    assert_eq!(actual.len(), 5);
    assert_eq!(actual["grant_type"], "authorization_code");
    assert_eq!(actual["client_id"], "client-original");
    assert_eq!(actual["code"], "code-synthetic");
    assert_eq!(actual["redirect_uri"], REDIRECT);
    assert_eq!(actual["code_verifier"], "v".repeat(43));
    match f.prepared.witness.as_ref().expect("original witness") {
        InitialReplyWitness::Code {
            metadata,
            binding,
            start,
            ..
        } => {
            assert_eq!(metadata.sdk_metadata().issuer, ORIGIN);
            assert_eq!(binding.client_id.as_str(), "client-original");
            assert_eq!(binding.server_url.as_str(), ORIGIN);
            let expected = f.clock.current();
            assert_eq!(start.original.wall, expected.wall);
            assert_eq!(start.original.mono, expected.mono);
        }
        InitialReplyWitness::Registration { .. } => panic!("wrong witness"),
    }
}
#[tokio::test]
async fn p04() {
    for code in [false, true] {
        let f = fixture(code).await;
        assert!(f.prepared.sdk_exit_child.is_cancelled());
        assert!(!f.parent.is_cancelled());
        assert!(
            !f.prepared
                .budget
                .as_ref()
                .expect("original budget")
                .original_parent
                .is_cancelled()
        );
        assert!(f.prepared.request.is_some());
        assert!(f.prepared.witness.is_some());
        let raw = if code {
            GOOD_TOKEN
        } else {
            br#"{"client_id":"x"}"#
        };
        assert!(
            consume_initial(f.prepared, response(200, raw).0)
                .await
                .is_ok()
        );
    }
}
#[tokio::test]
async fn p05() {
    let c = clock();
    let parent = CancellationToken::new();
    parent.cancel();
    assert!(matches!(
        prepare_initial(
            input(true, &c).await,
            retain_parent_budget(parent.clone(), c.current().mono + Duration::from_secs(50))
        )
        .await,
        Err(InitialError::Cancelled)
    ));
    assert!(matches!(
        prepare_initial(
            input(false, &c).await,
            retain_parent_budget(CancellationToken::new(), c.current().mono)
        )
        .await,
        Err(InitialError::Deadline)
    ));
    for owner_seconds in [7, 50] {
        let f = fixture_with(true, clock(), Duration::from_secs(owner_seconds)).await;
        let budget = f.prepared.budget.as_ref().expect("captured budget");
        assert_eq!(
            budget.deadline,
            (budget.http_entered_at + Duration::from_secs(10)).min(budget.owner_deadline)
        );
        f.clock.advance(
            chrono::TimeDelta::zero(),
            Duration::from_secs(owner_seconds.min(10)),
        );
        assert!(matches!(
            consume_initial(f.prepared, response(200, GOOD_TOKEN).0).await,
            Err(InitialError::Deadline)
        ));
    }
}
#[tokio::test]
async fn p06() {
    let f = fixture(true).await;
    let clock_owner: ClockOwner = f.clock.clone();
    assert!(Arc::ptr_eq(&f.prepared.clock, &clock_owner));
    let deadline = f.prepared.budget.as_ref().expect("budget").deadline;
    let reply = consume_initial(f.prepared, response(200, GOOD_TOKEN).0)
        .await
        .expect("whole owner moved once");
    match reply {
        InitialReply::Tokens(guard) => {
            assert!(Arc::ptr_eq(&guard.resources.clock, &clock_owner));
            assert_eq!(guard.resources.budget.deadline, deadline);
            assert_eq!(guard.resources.metadata.sdk_metadata().issuer, ORIGIN);
            f.parent.cancel();
            assert!(guard.resources.budget.original_parent.is_cancelled());
        }
        InitialReply::Registration(_) => panic!("wrong reply"),
    }
}

#[tokio::test]
async fn o01() {
    for raw in [b"{\"access_token\":\"partial-secret\",\"token_type\":\"Bearer\",\"refresh_token\":\"partial-refresh\",\"scope\":\"ai account\",\"expires_in\":0}".as_slice(), b"{\"access_token\":\"partial-secret\",\"client_secret\":null}", br#"{"access_token":"partial-secret","refresh_token":"\uD800"}"#] {
        let (result, wiped_live_storage) = reply::test_partial_erase(raw);
        assert!(result.is_err()); assert!(wiped_live_storage);
    }
}
#[tokio::test]
async fn o03() {
    let reply = check_reply(true, 200, GOOD_TOKEN)
        .await
        .expect("six-field owner");
    match reply {
        InitialReply::Tokens(mut guard) => {
            assert!(
                [
                    &guard.sdk.access_token,
                    &guard.sdk.refresh_token,
                    &guard.sdk.expires_at,
                    &guard.sdk.scope,
                    &guard.sdk.client_id,
                    &guard.sdk.server_url
                ]
                .iter()
                .all(|field| !field.is_empty())
            );
            guard.erase();
            assert!(
                [
                    &guard.sdk.access_token,
                    &guard.sdk.refresh_token,
                    &guard.sdk.expires_at,
                    &guard.sdk.scope,
                    &guard.sdk.client_id,
                    &guard.sdk.server_url
                ]
                .iter()
                .all(|field| field.is_empty())
            );
            guard.erase();
            assert!(guard.sdk.access_token.is_empty());
            // The live owner is checked; its later Drop follows the same erase path.
            drop(guard);
        }
        InitialReply::Registration(_) => panic!("wrong reply"),
    }
}
#[tokio::test]
async fn o04() {
    for mode in 0..3 {
        let f = fixture(true).await;
        let clock_weak = Arc::downgrade(&f.clock);
        drop(f.clock);
        let (response, probe) = match mode {
            0 => response(500, b"never polled"),
            1 => response_with(
                200,
                json_headers(),
                vec![Err(acosmi::TransportError::Connection)],
                None,
            ),
            _ => response(200, b"{\"access_token\":\"partial\",\"token_type\":null}"),
        };
        assert!(consume_initial(f.prepared, response).await.is_err());
        assert!(clock_weak.upgrade().is_none());
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        if mode == 0 {
            assert_eq!(probe.polls.load(Ordering::SeqCst), 0);
        }
    }
}
#[tokio::test]
async fn o06() {
    let f = fixture(true).await;
    let clock_weak = Arc::downgrade(&f.clock);
    drop(f.clock);
    let reply = consume_initial(f.prepared, response(200, GOOD_TOKEN).0)
        .await
        .expect("owned successful result");
    let InitialReply::Tokens(guard) = reply else {
        panic!("wrong reply")
    };
    async fn borrow_future(guard: &TokenSetGuard) {
        std::hint::black_box(guard);
        futures_util::future::pending::<()>().await;
    }
    let mut future = Box::pin(borrow_future(&guard));
    assert!(matches!(futures_util::poll!(&mut future), Poll::Pending));
    f.parent.cancel();
    assert!(clock_weak.upgrade().is_some());
    drop(future);
    assert!(clock_weak.upgrade().is_some());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = guard;
        panic!("synthetic unwind");
    }));
    assert!(result.is_err());
    assert!(clock_weak.upgrade().is_none());
}
#[tokio::test]
async fn o07() {
    let f = fixture(true).await;
    for tag in [
        format!("{:?}", f.prepared),
        format!("{:?}", f.prepared.witness),
        format!("{:?}", f.prepared.budget),
    ] {
        for secret in [
            "client-original",
            "code-synthetic",
            REDIRECT,
            ORIGIN,
            &"v".repeat(43),
        ] {
            assert!(!tag.contains(secret));
        }
    }
    let reply = consume_initial(f.prepared, response(200, GOOD_TOKEN).0)
        .await
        .expect("success");
    let tag = format!("{reply:?}");
    assert_eq!(tag, "InitialReply([redacted])");
    assert!(!tag.contains("access-synthetic"));
    for error in [
        InitialError::Cancelled,
        InitialError::Deadline,
        InitialError::ProducerEnded,
        InitialError::RequestMismatch,
        InitialError::BodyTransport,
        InitialError::HttpStatus(401),
        InitialError::ProtocolInvalid(ReplyInvalidReason::ForbiddenSecretKey),
    ] {
        let tag = format!("{error:?} {error}");
        for secret in ["access-synthetic", "refresh-synthetic", ORIGIN, REDIRECT] {
            assert!(!tag.contains(secret));
        }
    }
}

#[tokio::test]
async fn p03() {
    use acosmi::HttpTransport as _;
    let c = clock();
    let mut first_owner = fixture_with(true, c.clone(), Duration::from_secs(50)).await;
    let original_input = input(true, &c).await;
    let mut first_request = first_owner
        .prepared
        .request
        .take()
        .expect("actual SDK request");
    assert!(initial::validate_request(&first_request, &original_input.kind).is_ok());
    first_request.method = Method::GET;
    assert!(matches!(
        initial::validate_request(&first_request, &original_input.kind),
        Err(InitialError::RequestMismatch)
    ));
    first_request.method = Method::POST;
    let parent = retain_parent_budget(
        first_owner.parent.clone(),
        c.current().mono + Duration::from_secs(50),
    );
    let transport = initial::CaptureTransport::new(c.clone(), &parent);
    let mut first =
        Box::pin(transport.execute(first_request, parent.original_parent.child_token()));
    assert!(matches!(futures_util::poll!(first.as_mut()), Poll::Pending));
    assert_eq!(transport.state.lock().expect("capture lock").executions, 1);
    let mut second_owner = fixture_with(true, c, Duration::from_secs(50)).await;
    let second_request = second_owner
        .prepared
        .request
        .take()
        .expect("another actual SDK request");
    let mut second =
        Box::pin(transport.execute(second_request, parent.original_parent.child_token()));
    assert!(matches!(
        futures_util::poll!(second.as_mut()),
        Poll::Pending
    ));
    let state = transport.state.lock().expect("capture lock");
    assert_eq!(state.executions, 2);
    assert_eq!(state.error, Some(InitialError::RequestMismatch));
    drop(state);
    drop(second);
    drop(first);
}
#[tokio::test]
async fn o02() {
    let mut f = fixture(true).await;
    let fields = reply::parse_tokens(GOOD_TOKEN).expect("actual guarded parser");
    let access = fields.access_token.as_ptr();
    let refresh = fields.refresh_token.as_ptr();
    let scope = fields.scope.as_ptr();
    let InitialReplyWitness::Code {
        metadata,
        binding,
        start,
        ..
    } = f.prepared.witness.take().expect("original witness")
    else {
        panic!("wrong witness")
    };
    let client = binding.client_id.as_ptr();
    let server = binding.server_url.as_ptr();
    let resources = ReplyResources {
        metadata,
        budget: f.prepared.budget.take().expect("original completed budget"),
        clock: f.prepared.clock.clone(),
    };
    let mut guard =
        tokens::assemble_tokens(fields, binding, start, resources).expect("continuous SDK owner");
    assert_eq!(guard.sdk.access_token.as_ptr(), access);
    assert_eq!(guard.sdk.refresh_token.as_ptr(), refresh);
    assert_eq!(guard.sdk.scope.as_ptr(), scope);
    assert_eq!(guard.sdk.client_id.as_ptr(), client);
    assert_eq!(guard.sdk.server_url.as_ptr(), server);
    assert_eq!(guard.sdk.expires_at.len(), 24);
    guard.erase();
    assert!(guard.sdk.expires_at.is_empty());
    // Pointer equality is observed only while the moved allocation is still owned.
}
#[tokio::test]
async fn o05() {
    for mode in 0..3 {
        let f = fixture(true).await;
        let result = consume_initial(f.prepared, response(200, GOOD_TOKEN).0)
            .await
            .expect("actual assembled owner");
        let InitialReply::Tokens(mut guard) = result else {
            panic!("wrong reply")
        };
        match mode {
            0 => f
                .clock
                .advance(chrono::TimeDelta::microseconds(-1), Duration::ZERO),
            1 => f.parent.cancel(),
            _ => guard.sdk.server_url.push_str("/wrong-binding"),
        }
        let (result, all_six_empty) = tokens::test_final_check_and_erase(&mut guard);
        assert!(
            matches!(
                result,
                Err(InitialError::ProtocolInvalid(
                    ReplyInvalidReason::ClockOrExpiry
                ))
            ) && mode == 0
                || matches!(result, Err(InitialError::Cancelled)) && mode == 1
                || matches!(
                    result,
                    Err(InitialError::ProtocolInvalid(
                        ReplyInvalidReason::ReplyBinding
                    ))
                ) && mode == 2
        );
        assert!(all_six_empty.into_iter().all(|empty| empty));
        // Finite live-storage observation; automatic error Drop is checked in source.
    }
}
