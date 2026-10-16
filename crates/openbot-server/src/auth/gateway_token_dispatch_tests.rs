//! Genuine token consumer cases with original Server Host, owned PG/TLS and three ACK stages.
use super::*;
use base64::Engine as _;
use fixture::{ACTOR, DEP, Fixture, PgTerminalAckGate, TENANT, TerminalStage, harness};
use openbot_infra::db::tables::gateway_authorization_attempts::Row as AttemptRow;
use openbot_infra::{
    GatewayAuthorizationCallbackError, GatewayAuthorizationCallbackWaitOwner,
    GatewayAuthorizationCancellationToken as CancellationToken, GatewayAuthorizationJournal,
    GatewayAuthorizationJournalAck as Ack, GatewayAuthorizationJournalRuntimeOwner,
    GatewayAuthorizationTokenError, GatewayAuthorizationTokenKind as TokenKind,
    GatewayAuthorizationTokenOwner, GatewayAuthorizationTokenReplyReason as ReplyReason,
    GatewayAuthorizationTokenStage as TokenStage, GatewayAuthorizationVerifiedCodeOwner,
};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};
use zeroize::Zeroizing;

fn check(value: bool, message: &str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
struct CallbackInput {
    url: Zeroizing<String>,
    state: Zeroizing<String>,
    redirect: Zeroizing<String>,
    port: u16,
}
impl CallbackInput {
    fn from_sink(sink: &GatewayCallbackUrlSink) -> Result<Self, String> {
        let raw = sink.take_url().map_err(|e| format!("{e:?}"))?;
        check(raw.len() <= 2048, "whole SDK URL bound")?;
        let url = url::Url::parse(&raw).map_err(|e| e.to_string())?;
        let fields: Vec<_> = url.query_pairs().collect();
        let keys = [
            "response_type",
            "client_id",
            "redirect_uri",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
        ];
        check(
            fields.len() == keys.len(),
            "exact SDK authorization key set",
        )?;
        for key in keys {
            check(
                fields.iter().filter(|(k, _)| k == key).count() == 1,
                "SDK key present once",
            )?;
        }
        let value = |key: &str| fields.iter().find(|(k, _)| k == key).unwrap().1.as_ref();
        check(
            value("response_type") == "code" && value("client_id") == "owned-registration-client",
            "original SDK response/client",
        )?;
        check(
            value("scope") == "ai account" && value("code_challenge_method") == "S256",
            "fixed scopes and S256 method",
        )?;
        for key in ["state", "code_challenge"] {
            check(
                value(key).len() == 43
                    && value(key)
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
                "reachable original PKCE field shape",
            )?;
        }
        let state = Zeroizing::new(value("state").to_owned());
        let redirect = Zeroizing::new(value("redirect_uri").to_owned());
        let parsed = url::Url::parse(&redirect).map_err(|e| e.to_string())?;
        check(
            parsed.scheme() == "http"
                && parsed.host_str() == Some("127.0.0.1")
                && parsed.path() == "/callback"
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "original ephemeral IPv4 redirect",
        )?;
        let port = parsed.port().ok_or("original callback port missing")?;
        check(port != 0, "original callback port nonzero")?;
        Ok(Self {
            url: raw,
            state,
            redirect,
            port,
        })
    }
    fn query(&self, code: &str) -> String {
        format!("state={}&code={code}", *self.state)
    }
    fn request(&self, query: &str) -> Vec<u8> {
        format!(
            "GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            self.port
        )
        .into_bytes()
    }
}
async fn start_on(
    f: &Fixture,
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    sink: &GatewayCallbackUrlSink,
    parent: CancellationToken,
    deadline: Instant,
) -> Result<(GatewayAuthorizationCallbackWaitOwner, CallbackInput), String> {
    let metadata = f.metadata(parent.clone()).await?;
    let factory = f.factory(Some("/oauth/desktop/register"))?;
    let owner = journal
        .start_callback(auth, metadata, parent, deadline, &factory)
        .await
        .map_err(|e| e.to_string())?;
    let input = CallbackInput::from_sink(sink)?;
    let posts = f.posts()?;
    check(
        posts.len() == 1
            && posts[0]["path"] == "/oauth/desktop/register"
            && posts[0]["authorization"] == Value::Null,
        "one original registration POST, no bearer",
    )?;
    let body: Value = serde_json::from_str(
        posts[0]["body"]
            .as_str()
            .ok_or("registration body missing")?,
    )
    .map_err(|e| e.to_string())?;
    check(
        body == json!({"client_name":"Wrok Bot","redirect_uris":[&*input.redirect],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}),
        "original SDK registration body echoes that same listener redirect",
    )?;
    let rows = f.rows().await?;
    check(
        rows.len() == 1
            && rows[0].phase == "registered"
            && rows[0].client_id.as_deref() == Some("owned-registration-client")
            && rows[0].redirect_uri == *input.redirect
            && rows[0].enrollment_id.is_some()
            && rows[0].code_admitted_at.is_none()
            && rows[0].finished_at.is_none()
            && rows[0].outcome_code.is_none(),
        "whole registered row, no code admission or terminal write",
    )?;
    Ok((owner, input))
}
async fn exchange(port: u16, request: &[u8]) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(request).await.map_err(|e| e.to_string())?;
        let mut response = Vec::with_capacity(512);
        (&mut stream)
            .take(4097)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        check(response.len() <= 4096, "finite static response bound")?;
        drop(stream);
        Ok(response)
    })
    .await
    .map_err(|_| "owned TCP response timeout")?
}
fn response(raw: &[u8], status: u16, body: &[u8]) -> Result<(), String> {
    let split = raw
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("static response framing missing")?;
    let headers = std::str::from_utf8(&raw[..split])
        .map_err(|e| e.to_string())?
        .to_ascii_lowercase();
    check(
        headers.starts_with(&format!("http/1.1 {status} ")) && &raw[split + 4..] == body,
        "independent literal status and response body",
    )?;
    check(
        headers.contains(&format!("\r\ncontent-length: {}", body.len()))
            && headers.contains("\r\ncontent-type: text/plain")
            && headers.contains("\r\nconnection: close")
            && headers.contains("\r\ncache-control: no-store"),
        "fixed response length/type/close/no-store",
    )
}
type CallbackResult =
    Result<GatewayAuthorizationVerifiedCodeOwner, GatewayAuthorizationCallbackError>;
async fn finish_code<F: Future<Output = CallbackResult>>(
    call: &mut Pin<Box<F>>,
    input: &CallbackInput,
    code: &str,
) -> Result<GatewayAuthorizationVerifiedCodeOwner, String> {
    let bytes = input.request(&input.query(code));
    let (owner, peer) = tokio::join!(call, exchange(input.port, &bytes));
    response(&peer?, 200, b"Callback received.")?;
    owner.map_err(|e| e.to_string())
}

type TokenResult = Result<GatewayAuthorizationTokenOwner, GatewayAuthorizationTokenError>;
fn rejected(result: TokenResult) -> Result<GatewayAuthorizationTokenError, String> {
    result
        .err()
        .ok_or_else(|| "token unexpectedly returned an opaque owner".into())
}
fn token_posts(f: &Fixture) -> Result<Vec<Value>, String> {
    Ok(f.posts()?
        .into_iter()
        .filter(|v| v["path"] == "/oauth/desktop/token")
        .collect())
}
fn no_token(f: &Fixture) -> Result<(), String> {
    check(
        token_posts(f)?.is_empty(),
        "zero token POST, setup registration counted separately",
    )
}
fn history(
    error: &GatewayAuthorizationTokenError,
    write: Ack,
    readback: Ack,
    send: Ack,
) -> Result<(), String> {
    check(
        error.code_write_ack() == write
            && error.code_readback_ack() == readback
            && error.token_send_rollback_ack() == send,
        "three actual original terminal ACKs retain their independent histories",
    )
}
fn error_kind(error: &GatewayAuthorizationTokenError, expected: TokenKind) -> Result<(), String> {
    check(
        error.kind() == expected,
        &format!("closed token kind expected {expected:?}, got {error:?}"),
    )
}
async fn verified_on(
    f: &Fixture,
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    sink: &GatewayCallbackUrlSink,
    parent: CancellationToken,
    deadline: Instant,
) -> Result<(GatewayAuthorizationVerifiedCodeOwner, CallbackInput), String> {
    let (wait, input) = start_on(f, journal, auth, sink, parent, deadline).await?;
    let mut callback = Box::pin(journal.wait_callback(auth, wait));
    let owner = finish_code(&mut callback, &input, "owned-token-code").await?;
    Ok((owner, input))
}
async fn verified(
    f: &Fixture,
    parent: CancellationToken,
    deadline: Instant,
) -> Result<
    (
        AuthContext,
        GatewayAuthorizationVerifiedCodeOwner,
        CallbackInput,
    ),
    String,
> {
    let sink = GatewayCallbackUrlSink::new();
    f.resolver
        .install_gateway_callback_url_sink(Arc::clone(&sink))
        .map_err(|e| format!("{e:?}"))?;
    let auth = f.auth().await?;
    let (owner, input) = verified_on(f, &f.journal, &auth, &sink, parent, deadline).await?;
    Ok((auth, owner, input))
}
fn token_wire(f: &Fixture, input: &CallbackInput) -> Result<(), String> {
    let posts = token_posts(f)?;
    check(posts.len() == 1, "one actual original token POST")?;
    let wire = &posts[0];
    check(
        wire["authorization"] == Value::Null,
        "token POST has no bearer",
    )?;
    let raw = wire["body"].as_str().ok_or("missing actual SDK form")?;
    let form: Vec<_> = url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect();
    let expected = [
        "grant_type",
        "client_id",
        "code",
        "redirect_uri",
        "code_verifier",
    ];
    check(
        form.len() == 5
            && expected
                .iter()
                .all(|key| form.iter().filter(|(k, _)| k == key).count() == 1),
        "exact five original SDK form keys",
    )?;
    let get = |key: &str| form.iter().find(|(k, _)| k == key).unwrap().1.as_str();
    check(
        get("grant_type") == "authorization_code"
            && get("client_id") == "owned-registration-client"
            && get("code") == "owned-token-code"
            && get("redirect_uri") == *input.redirect,
        "independent fixed code/client/grant and original runtime-port redirect",
    )?;
    let verifier = get("code_verifier");
    check(
        verifier.len() == 43
            && verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "original verifier grammar, no replacement RNG",
    )?;
    let parsed = url::Url::parse(&input.url).map_err(|e| e.to_string())?;
    let challenge = parsed
        .query_pairs()
        .find(|(k, _)| k == "code_challenge")
        .ok_or("missing original challenge")?
        .1
        .into_owned();
    let independent = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    check(
        independent == challenge,
        "independent SHA256/base64url equals original URL challenge",
    )?;
    let headers = wire["headers"].as_array().ok_or("wire headers missing")?;
    let media: Vec<_> = headers
        .iter()
        .filter(|h| {
            h[0].as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("content-type"))
        })
        .collect();
    check(
        media.len() == 1 && media[0][1] == "application/x-www-form-urlencoded",
        "one actual original form media",
    )?;
    Ok(())
}
async fn code_success(
    f: &Fixture,
    old: &AttemptRow,
    owner: &GatewayAuthorizationTokenOwner,
    input: &CallbackInput,
) -> Result<(), String> {
    let next = f.row(old.attempt_id).await?;
    let stamp = next
        .code_admitted_at
        .ok_or("code admission timestamp missing")?;
    let mut expected = old.clone();
    expected.phase = "code_admitted".into();
    expected.code_admitted_at = Some(stamp);
    expected.updated_at = stamp;
    check(
        next == expected && stamp >= old.updated_at && stamp < old.expires_at,
        "three changed and seventeen original columns, original UUID/client pair and PG floor bound",
    )?;
    let audits = f.audits().await?;
    check(
        audits.len() == 4
            && audits[3]
                == json!({
                    "journal_schema":1,"attempt_id":old.attempt_id.to_string(),"phase":"code_admitted","outcome_code":null
                }),
        "original typed four-fact code admission audit",
    )?;
    token_wire(f, input)?;
    let debug = format!("{owner:?}");
    for secret in [
        ACTOR,
        "owned-access-token",
        "owned-refresh-token",
        "owned-token-code",
        "owned-registration-client",
        &f.issuer(),
    ] {
        check(
            !debug.contains(secret),
            "opaque six-guard owner has static redaction",
        )?;
    }
    check(
        debug.contains("GatewayAuthorizationTokenOwner"),
        "opaque owner retained",
    )?;
    Ok(())
}
async fn body_pending<F: Future<Output = TokenResult>>(
    f: &Fixture,
    call: &mut Pin<Box<F>>,
) -> Result<(), String> {
    let observed = async {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if f.events()?
                .iter()
                .any(|v| v["event"] == "headers_sent" && v["path"] == "/oauth/desktop/token")
                && token_posts(f)?.len() == 1
            {
                return Ok::<(), String>(());
            }
            if Instant::now() >= until {
                return Err("token headers event not observed".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! { biased; result = &mut *call => return Err(format!("token returned before owned body Pending: {result:?}")), result = observed => result?, }
    // Poll the same business future while the owned TLS body remains withheld.
    tokio::select! { biased; result = &mut *call => return Err(format!("token escaped withheld body: {result:?}")), () = tokio::task::yield_now() => {}, }
    Ok(())
}
async fn token_ack_case(
    cfg: openbot_infra::db::pool::DatabaseConfig,
    stage: TerminalStage,
    discard: bool,
    late: bool,
    tail: bool,
) -> Result<(), String> {
    let relay = PgTerminalAckGate::new(&cfg, stage, discard).await;
    let f = Fixture::new(relay.config.clone(), 1).await?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let (auth, verified, _input) = verified(&f, CancellationToken::new(), deadline).await?;
    let old = f.rows().await?.remove(0);
    relay.arm_original(&f).await;
    let factory = f.factory(Some("/oauth/desktop/register"))?;
    let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
    tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("token missed original ACK stage: {value:?}")), }
    if tail {
        f.disarm_host();
    }
    if late {
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(150),
        ))
        .await;
    }
    if !discard {
        relay.release_original_ack().await;
    }
    let error = rejected(call.await)?;
    let selected = if discard {
        Ack::Unknown
    } else if late {
        Ack::Late
    } else {
        Ack::Timely
    };
    match stage {
        TerminalStage::CodeCommit => {
            history(&error, selected, Ack::NotAttempted, Ack::NotAttempted)?;
            error_kind(
                &error,
                if discard {
                    TokenKind::CommitUnknown
                } else if late {
                    TokenKind::CommitAcknowledgedAfterDeadline
                } else {
                    TokenKind::BeforeDispatchRefused
                },
            )?;
            no_token(&f)?;
        }
        TerminalStage::CodeReadbackRollback => {
            history(&error, Ack::Timely, selected, Ack::NotAttempted)?;
            error_kind(
                &error,
                if discard {
                    TokenKind::CleanupUnknown
                } else if late {
                    TokenKind::RollbackAcknowledgedAfterDeadline
                } else {
                    TokenKind::BeforeDispatchRefused
                },
            )?;
            no_token(&f)?;
        }
        TerminalStage::TokenSendRollback => {
            history(&error, Ack::Timely, Ack::Timely, selected)?;
            error_kind(
                &error,
                if late {
                    TokenKind::RollbackAcknowledgedAfterDeadline
                } else if discard {
                    TokenKind::CleanupUnknown
                } else {
                    TokenKind::TokenUnknown
                },
            )?;
            check(
                token_posts(&f)?.len() == 1,
                "one actual token POST even when send ACK unknown",
            )?;
        }
    }
    let next = f.row(old.attempt_id).await?;
    check(
        next.phase == "code_admitted"
            && next.client_id == old.client_id
            && next.enrollment_id == old.enrollment_id,
        "later durable row never upgrades original ACK facts",
    )?;
    relay.assert_target(usize::from(!discard));
    f.finish().await?;
    relay.stop().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r01_token_session() {
    let admin = harness::admin_config("token-r01");
    harness::with_temp_database(&admin, "tok_r01", |cfg| async move {
        let commit = PgTerminalAckGate::new(&cfg, TerminalStage::CodeCommit, false).await;
        let readback = PgTerminalAckGate::new(&commit.config, TerminalStage::CodeReadbackRollback, false).await;
        let send = PgTerminalAckGate::new(&readback.config, TerminalStage::TokenSendRollback, false).await;
        let f = Fixture::new(send.config.clone(), 1).await?;
        let (auth, verified, input) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let old = f.rows().await?.remove(0);
        for relay in [&commit, &readback, &send] { relay.arm_original(&f).await; }
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        for relay in [&commit, &readback, &send] {
            tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("session flow skipped original ACK stage: {value:?}")), }
            relay.release_original_ack().await;
        }
        let owner = call.await.map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        for relay in [&commit, &readback, &send] { relay.assert_target(1); }
        drop(owner);
        f.finish().await?;
        send.stop().await;
        readback.stop().await;
        commit.stop().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r02_token_singleuser() {
    let admin = harness::admin_config("token-r02");
    harness::with_temp_database(&admin, "tok_r02", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (runtime, journal) = f.fresh_pair()?;
        let single = f.single(&journal).await?;
        let sink = GatewayCallbackUrlSink::new();
        single
            .install_gateway_callback_url_sink(Arc::clone(&sink))
            .map_err(|e| format!("{e:?}"))?;
        let auth = single
            .resolve(
                &http::Request::builder()
                    .uri("/owned-token")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())?;
        check(
            auth.actor().as_str() == "dev-local-user",
            "genuine verified local admin principal",
        )?;
        let (verified, input) = verified_on(
            &f,
            &journal,
            &auth,
            &sink,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let old = f.rows().await?.remove(0);
        check(
            old.owner_user_id == "dev-local-user",
            "same Pool single-user journal owner",
        )?;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = journal
            .dispatch_token(&auth, verified, &factory)
            .await
            .map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        drop(owner);
        single.close_request_bindings();
        runtime.close();
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r03_token_sdk_form() {
    let admin = harness::admin_config("token-r03");
    harness::with_temp_database(&admin, "tok_r03", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let parent = CancellationToken::new();
        let (auth, verified, input) =
            verified(&f, parent.clone(), Instant::now() + Duration::from_secs(60)).await?;
        check(
            !parent.is_cancelled(),
            "original SDK child exit did not cancel original parent",
        )?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = f
            .journal
            .dispatch_token(&auth, verified, &factory)
            .await
            .map_err(|e| e.to_string())?;
        token_wire(&f, &input)?;
        code_success(&f, &old, &owner, &input).await?;
        check(!parent.is_cancelled(), "token capture kept original parent")?;
        drop(owner);
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r04_token_foreign() {
    let admin = harness::admin_config("token-r04");
    for vector in 0..5 {
        harness::with_temp_database(&admin, &format!("tok_r04_{vector}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let (auth, verified, _input) = verified(
                &f,
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(60),
            )
            .await?;
            let baseline = f.network_point()?;
            let direct = f.direct().await?;
            let pool = if vector == 0 {
                direct.clone()
            } else {
                f.pool.clone()
            };
            let dep = if vector == 1 {
                "foreign-deployment"
            } else {
                DEP
            };
            let tenant = if vector == 2 {
                "foreign-tenant"
            } else {
                TENANT
            };
            let (runtime, foreign) =
                fixture::fresh_pair(pool, DeploymentId::new(dep), TenantId::new(tenant))?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = if vector == 4 {
                let resolver = Arc::new(
                    PostgresSessionAuthResolver::new(
                        f.pool.clone(),
                        b"owned-journal-session-hash-key",
                        openbot_infra::auth::config::default_session_lifetime(),
                        DeploymentId::new(DEP),
                        TenantId::new(TENANT),
                    )
                    .map_err(|e| e.to_string())?,
                );
                resolver
                    .install_gateway_authorization_journal(&foreign)
                    .map_err(|e| format!("{e:?}"))?;
                let replacement = resolver
                    .resolve(
                        &http::Request::builder()
                            .uri("/owned-token")
                            .header("cookie", format!("openbot_session={}", fixture::COOKIE))
                            .body(())
                            .unwrap()
                            .into_parts()
                            .0,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                rejected(
                    f.journal
                        .dispatch_token(&replacement, verified, &factory)
                        .await,
                )?
            } else {
                rejected(foreign.dispatch_token(&auth, verified, &factory).await)?
            };
            error_kind(&error, TokenKind::BeforeDispatchRefused)?;
            history(
                &error,
                Ack::NotAttempted,
                Ack::NotAttempted,
                Ack::NotAttempted,
            )?;
            check(
                f.network_point()? == baseline,
                "foreign original Pool/scope/issuer/runtime performs no new DNS/socket/POST",
            )?;
            no_token(&f)?;
            runtime.close();
            direct.close();
            f.finish().await
        })
        .await;
    }
    // A genuine Server verified owner still refuses the existing default Host
    // binding. This negative Desktop vector never creates another verified code.
    harness::with_temp_database(&admin, "tok_r04_default", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (auth, verified, _) = verified(
            &f,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let baseline = f.network_point()?;
        use openbot_contracts::request_binding::{
            HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
            RequestBindingOwnerLease,
        };
        struct DefaultGuard;
        impl HostRequestBindingGuard for DefaultGuard {
            fn verify_current<'a>(
                &'a self,
                _: &'a AuthContext,
            ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
            {
                Box::pin(async { Ok(()) })
            }
        }
        let (lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
        let binding = issuer
            .bind_desktop_window(
                &auth,
                "owned-token-default-desktop-negative".into(),
                1,
                Arc::new(DefaultGuard),
            )
            .map_err(|e| format!("{e:?}"))?;
        let replacement = auth
            .clone()
            .with_verified_request_binding(binding)
            .map_err(|e| format!("{e:?}"))?;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let error = rejected(
            f.journal
                .dispatch_token(&replacement, verified, &factory)
                .await,
        )?;
        error_kind(&error, TokenKind::BeforeDispatchRefused)?;
        history(
            &error,
            Ack::NotAttempted,
            Ack::NotAttempted,
            Ack::NotAttempted,
        )?;
        check(
            f.network_point()? == baseline,
            "default Host performs no new DNS/socket/POST",
        )?;
        no_token(&f)?;
        drop(lease);
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r05_token_revoked() {
    let admin = harness::admin_config("token-r05");
    for vector in 0..6 {
        harness::with_temp_database(&admin, &format!("tok_r05_{vector}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let (auth, verified, _) = verified(
                &f,
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(60),
            )
            .await?;
            let old = f.rows().await?.remove(0);
            if vector < 4 {
                let client = f.pool.get().await.map_err(|e| e.to_string())?;
                let sql = match vector {
                    0 => "UPDATE public.users SET auth_generation=8 WHERE id='owned-journal-owner'",
                    1 => "DELETE FROM public.user_roles WHERE user_id='owned-journal-owner'",
                    2 => "INSERT INTO public.revoked_access(email,revoked_by) VALUES('journal@example.test','owned-journal-owner')",
                    _ => "DELETE FROM public.sessions WHERE id='owned-journal-session'",
                };
                client.batch_execute(sql).await.map_err(|e| e.to_string())?;
            } else if vector == 4 {
                f.disarm_host();
            } else {
                f.runtime.as_ref().unwrap().close();
            }
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = rejected(f.journal.dispatch_token(&auth, verified, &factory).await)?;
            check(
                matches!(
                    error.kind(),
                    TokenKind::BeforeDispatchRefused | TokenKind::Unavailable
                ),
                "actual revocation closed refusal",
            )?;
            no_token(&f)?;
            check(
                f.row(old.attempt_id).await? == old,
                "preadmission revoked chain cannot write code or handoff",
            )?;
            f.finish().await
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r06_token_cas_drift() {
    let admin = harness::admin_config("token-r06");
    for sql in [
        "UPDATE openbot_internal.gateway_authorization_attempts SET updated_at=updated_at+interval '1 microsecond'",
        "UPDATE openbot_internal.gateway_authorization_attempts SET client_id='legal-drift-client'",
        "UPDATE openbot_internal.gateway_authorization_attempts SET redirect_uri='http://127.0.0.1:48282/callback'",
        "UPDATE openbot_internal.gateway_authorization_attempts SET runtime_epoch=repeat('ab',32)",
        "UPDATE openbot_internal.gateway_authorization_attempts SET issuer='https://foreign.invalid'",
    ] {
        harness::with_temp_database(&admin, "tok_r06_drift", |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let (auth, verified, _) = verified(
                &f,
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(60),
            )
            .await?;
            let old = f.rows().await?.remove(0);
            let client = f.pool.get().await.map_err(|e| e.to_string())?;
            client.batch_execute(sql).await.map_err(|e| e.to_string())?;
            drop(client);
            let drift = f.row(old.attempt_id).await?;
            let audit_before = f.audits().await?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = rejected(f.journal.dispatch_token(&auth, verified, &factory).await)?;
            error_kind(&error, TokenKind::BeforeDispatchRefused)?;
            history(&error, Ack::Timely, Ack::NotAttempted, Ack::NotAttempted)?;
            no_token(&f)?;
            check(
                f.row(old.attempt_id).await? == drift && f.audits().await? == audit_before,
                "legal actual full-row mismatch rolls back with no CAS or audit effect",
            )?;
            f.finish().await
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r07_token_locks() {
    let admin = harness::admin_config("token-r07");
    for actor_blocked in [true, false] {
        harness::with_temp_database(&admin, if actor_blocked { "tok_r07_actor" } else { "tok_r07_attempt" }, |cfg| async move {
            let f = Fixture::new(cfg, 4).await?;
            let (auth, verified, input) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
            let old = f.rows().await?.remove(0);
            let direct = f.direct().await?;
            let blocker = direct.get().await.map_err(|e| e.to_string())?;
            blocker.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            let blocker_pid: i32 = blocker.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            if actor_blocked { blocker.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE", &[&ACTOR]).await.map_err(|e| e.to_string())?; }
            else { blocker.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE", &[&old.attempt_id]).await.map_err(|e| e.to_string())?; }
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
            let observe = async {
                let observer = f.pool.get().await.map_err(|e| e.to_string())?;
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    let rows = observer.query("SELECT pid,query FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))", &[&blocker_pid]).await.map_err(|e| e.to_string())?;
                    if let Some(row) = rows.iter().find(|r| {
                        let sql: String = r.get(1);
                        if actor_blocked { sql.to_ascii_lowercase().contains("for share") } else { sql.contains("gateway_authorization_attempt_lock") }
                    }) { return Ok::<i32, String>(row.get(0)); }
                    if Instant::now() >= until { return Err("actual token lock waiter not observed".into()); }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let waiter = tokio::select! { result = observe => result?, result = &mut call => return Err(format!("token escaped blocker: {result:?}")), };
            no_token(&f)?;
            let probe = f.pool.get().await.map_err(|e| e.to_string())?;
            probe.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
            if actor_blocked { probe.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE NOWAIT", &[&old.attempt_id]).await.map_err(|e| e.to_string())?; }
            else {
                let error = probe.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT", &[&ACTOR]).await.err().ok_or("actor SHARE missing before attempt UPDATE")?;
                check(error.as_db_error().is_some_and(|e| e.code().code() == "55P03"), "real independent NOWAIT confirms actor SHARE")?;
            }
            probe.batch_execute("ROLLBACK").await.map_err(|e| e.to_string())?;
            drop(probe);
            blocker.batch_execute("ROLLBACK").await.map_err(|e| e.to_string())?;
            drop(blocker);
            let owner = call.await.map_err(|e| e.to_string())?;
            code_success(&f, &old, &owner, &input).await?;
            let lock_evidence = if actor_blocked { "attempt_unlocked=true actor_share_NOWAIT55P03=not_observed" }
                else { "attempt_unlocked=not_observed actor_share_NOWAIT55P03=true" };
            eprintln!("GATEWAY_TOKEN_LOCK_ORDER actual_waiter={waiter} original_blocker={blocker_pid} actor_blocked={actor_blocked} query_and_blocking_pids=true {lock_evidence}");
            drop(owner);
            direct.close();
            f.finish().await
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r08_token_audit_fail() {
    let admin = harness::admin_config("token-r08");
    harness::with_temp_database(&admin, "tok_r08", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let old = f.rows().await?.remove(0);
        let audits = f.audits().await?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        client.batch_execute("CREATE FUNCTION public.owned_token_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='gateway_authorization_code_admitted' THEN RAISE EXCEPTION 'owned_code_audit_reject'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_token_audit_reject BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_token_audit_reject();").await.map_err(|e| e.to_string())?;
        drop(client);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let error = rejected(f.journal.dispatch_token(&auth, verified, &factory).await)?;
        error_kind(&error, TokenKind::Unavailable)?;
        history(&error, Ack::Timely, Ack::NotAttempted, Ack::NotAttempted)?;
        no_token(&f)?;
        check(f.row(old.attempt_id).await? == old && f.audits().await? == audits,
            "original CAS/audit whole transaction rolled back without resend")?;
        f.finish().await
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r09_token_commit_ack() {
    let admin = harness::admin_config("token-r09");
    for (discard, late, tail) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        harness::with_temp_database(&admin, "tok_r09", |cfg| {
            token_ack_case(cfg, TerminalStage::CodeCommit, discard, late, tail)
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r10_token_ro_ack() {
    let admin = harness::admin_config("token-r10");
    for (discard, late, tail) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        harness::with_temp_database(&admin, "tok_r10_ack", |cfg| {
            token_ack_case(
                cfg,
                TerminalStage::CodeReadbackRollback,
                discard,
                late,
                tail,
            )
        })
        .await;
    }
    for vector in 0..3 {
        harness::with_temp_database(&admin, &format!("tok_r10_drift_{vector}"), |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::CodeCommit, false).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
            let old = f.rows().await?.remove(0);
            relay.arm_original(&f).await;
            let direct = f.direct().await?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
            tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("missed original code COMMIT before RO drift: {value:?}")), }
            let client = direct.get().await.map_err(|e| e.to_string())?;
            let sql = match vector {
                0 => "UPDATE openbot_internal.gateway_authorization_attempts SET updated_at=updated_at+interval '1 microsecond'",
                1 => "UPDATE public.users SET auth_generation=8 WHERE id='owned-journal-owner'",
                _ => "UPDATE public.sessions SET token='abababababababababababababababababababababababababababababababab' WHERE id='owned-journal-session'",
            };
            client.batch_execute(sql).await.map_err(|e| e.to_string())?;
            drop(client);
            relay.release_original_ack().await;
            let error = rejected(call.await)?;
            check(error.stage() == TokenStage::CodeReadback, "actual row/actor/session drift rejected in original RO")?;
            history(&error, Ack::Timely, Ack::Timely, Ack::NotAttempted)?;
            error_kind(&error, if vector == 0 { TokenKind::ReadbackUnproven } else { TokenKind::BeforeDispatchRefused })?;
            no_token(&f)?;
            check(f.row(old.attempt_id).await?.phase == "code_admitted", "confirmed write kept even when RO rejects")?;
            relay.assert_target(1);
            direct.close();
            f.finish().await?;
            relay.stop().await;
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r11_token_old10_done() {
    let admin = harness::admin_config("token-r11");
    harness::with_temp_database(&admin, "tok_r11", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let sink = GatewayCallbackUrlSink::new();
        f.resolver
            .install_gateway_callback_url_sink(Arc::clone(&sink))
            .map_err(|e| format!("{e:?}"))?;
        let auth = f.auth().await?;
        let (wait, input) = start_on(
            &f,
            &f.journal,
            &auth,
            &sink,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let old = f.rows().await?.remove(0);
        let completed = Instant::now();
        tokio::time::sleep(Duration::from_secs(11)).await;
        check(
            completed.elapsed() > Duration::from_secs(10),
            "actual completed registration stage exceeds original ten seconds",
        )?;
        let mut callback = Box::pin(f.journal.wait_callback(&auth, wait));
        let verified = finish_code(&mut callback, &input, "owned-token-code").await?;
        drop(callback);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = f
            .journal
            .dispatch_token(&auth, verified, &factory)
            .await
            .map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        drop(owner);
        f.finish().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r12_token_code10_sql() {
    let admin = harness::admin_config("token-r12");
    harness::with_temp_database(&admin, "tok_r12", |cfg| async move {
        let f = Fixture::new(cfg, 3).await?;
        let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let old = f.rows().await?.remove(0);
        let direct = f.direct().await?;
        let blocker = direct.get().await.map_err(|e| e.to_string())?;
        blocker.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        blocker.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE", &[&ACTOR]).await.map_err(|e| e.to_string())?;
        let pid: i32 = blocker.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let entered_before_first_poll = Instant::now();
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        let observed = async {
            let client = f.pool.get().await.map_err(|e| e.to_string())?;
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                let rows = client.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND lower(query) LIKE '%for share%'", &[&pid]).await.map_err(|e| e.to_string())?;
                if !rows.is_empty() { return Ok::<(), String>(()); }
                if Instant::now() >= until { return Err("code SQL original lock blocker absent".into()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::select! { result = observed => result?, value = &mut call => return Err(format!("escaped token SQL blocker: {value:?}")), }
        no_token(&f)?;
        // Keep the same original business future unpolled after the genuine SQL
        // lock observation. Its first ten-second absolute cap remains in force
        // even if the independent PostgreSQL statement timeout fires sooner.
        tokio::time::sleep_until(tokio::time::Instant::from_std(entered_before_first_poll + Duration::from_millis(10150))).await;
        let error = rejected(call.await)?;
        check(entered_before_first_poll.elapsed() >= Duration::from_secs(10), "actual first token stage ten-second cap includes SQL wait")?;
        error_kind(&error, TokenKind::Deadline)?;
        no_token(&f)?;
        blocker.batch_execute("ROLLBACK").await.map_err(|e| e.to_string())?;
        drop(blocker);
        check(f.row(old.attempt_id).await? == old, "expired original code cap does not admit or POST")?;
        direct.close();
        f.finish().await
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r13_token_send_ack() {
    let admin = harness::admin_config("token-r13");
    harness::with_temp_database(&admin, "tok_r13", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::TokenSendRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        f.configure(&json!({"hold_body":true}))?;
        let (auth, verified, input) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let old = f.rows().await?.remove(0);
        relay.arm_original(&f).await;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("token became visible before original send ACK: {value:?}")), }
        let observer = f.direct().await?;
        let client = observer.get().await.map_err(|e| e.to_string())?;
        let row = client.query_one("SELECT * FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1", &[&old.attempt_id]).await.map_err(|e| e.to_string())?;
        let held_row = AttemptRow::try_from(&row).map_err(|e| e.to_string())?;
        check(token_posts(&f)?.len() == 1 && held_row.phase == "code_admitted", "one actual POST with confirmed code write/readback")?;
        drop(client);
        relay.release_original_ack().await;
        body_pending(&f, &mut call).await?;
        let client = observer.get().await.map_err(|e| e.to_string())?;
        let activity = client.query_opt("SELECT state FROM pg_stat_activity WHERE pid=$1", &[&relay.original_pid()]).await.map_err(|e| e.to_string())?;
        check(activity.is_none_or(|r| r.get::<_, String>(0) != "idle in transaction"), "original send transaction ended before lazy body release")?;
        drop(client);
        f.release_body()?;
        let owner = call.await.map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        relay.assert_target(1);
        drop(owner);
        observer.close();
        f.finish().await?;
        relay.stop().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r14_token_send_unknown() {
    let admin = harness::admin_config("token-r14");
    for (discard, late, tail) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        harness::with_temp_database(&admin, "tok_r14", |cfg| {
            token_ack_case(cfg, TerminalStage::TokenSendRollback, discard, late, tail)
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r15_token_current_pending() {
    let admin = harness::admin_config("token-r15");
    harness::with_temp_database(&admin, "tok_r15", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::TokenSendRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        f.configure(&json!({"hold_body":true}))?;
        let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        relay.arm_original(&f).await;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("pending-body case missed original send ACK: {value:?}")), }
        relay.release_original_ack().await;
        body_pending(&f, &mut call).await?;
        f.disarm_host();
        f.release_body()?;
        let error = rejected(call.await)?;
        error_kind(&error, TokenKind::TokenUnknown)?;
        history(&error, Ack::Timely, Ack::Timely, Ack::Timely)?;
        check(error.stage() == TokenStage::TokenReply, "true post-dial lazy body current refusal remains reply-stage Unknown")?;
        let snapshot = error.transport_snapshot().ok_or("actual transport snapshot missing")?;
        check(snapshot.may_have_sent() && snapshot.response_status() == Some(200) && snapshot.permit_released(),
            "original true POST/headers/release facts retained; no NotSent inference")?;
        check(token_posts(&f)?.len() == 1, "no second POST after current refusal")?;
        relay.assert_target(1);
        f.finish().await?;
        relay.stop().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r16_token_parent_caps() {
    let admin = harness::admin_config("token-r16");
    for cause in ["parent", "caller", "code"] {
        for phase in ["send", "release", "body"] {
            harness::with_temp_database(&admin, &format!("tok_r16_{cause}_{phase}"), |cfg| async move {
                let relay = if phase == "release" {
                    Some(PgTerminalAckGate::new(&cfg, TerminalStage::TokenSendRollback, false).await)
                } else { None };
                let routed = relay.as_ref().map_or(cfg, |relay| relay.config.clone());
                let f = Fixture::new(routed, if relay.is_some() { 1 } else { 2 }).await?;
                f.configure(&json!({"hold_headers":phase == "send", "hold_body":phase != "send"}))?;
                let parent = CancellationToken::new();
                // Only caller vectors deliberately have a caller cap shorter
                // than the original SDK code stage. Code vectors retain a
                // genuine sixty-second caller cap and its original Flow.
                let deadline = Instant::now() + Duration::from_secs(if cause == "caller" { 3 } else { 60 });
                let (auth, verified, _) = verified(&f, parent.clone(), deadline).await?;
                let old = f.rows().await?.remove(0);
                if let Some(relay) = &relay { relay.arm_original(&f).await; }
                let factory = f.factory(Some("/oauth/desktop/register"))?;
                let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
                match phase {
                    "send" => {
                        let observed = async {
                            let until = Instant::now() + Duration::from_secs(5);
                            loop {
                                if token_posts(&f)?.len() == 1 {
                                    check(!f.events()?.iter().any(|v| v["event"] == "headers_sent" && v["path"] == "/oauth/desktop/token"),
                                        "actual token POST captured while owned original headers are withheld")?;
                                    return Ok::<(), String>(());
                                }
                                if Instant::now() >= until { return Err("original token POST not observed before header hold".into()); }
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                        };
                        tokio::select! { biased; value = &mut call => return Err(format!("send cap escaped original withheld headers: {value:?}")), result = observed => result?, }
                    }
                    "release" => {
                        let relay = relay.as_ref().ok_or("original release relay absent")?;
                        tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("release cap missed original send C/Z: {value:?}")), }
                        check(f.events()?.iter().any(|v| v["event"] == "headers_sent" && v["path"] == "/oauth/desktop/token"),
                            "original real headers preceded withheld original send rollback C/Z")?;
                    }
                    "body" => body_pending(&f, &mut call).await?,
                    _ => return Err("closed cap phase".into()),
                }
                check(token_posts(&f)?.len() == 1, "one actual token POST before original cap control")?;
                let observed_phase = Instant::now();
                match cause {
                    "parent" => parent.cancel(),
                    "caller" => {
                        // Keep this same original business future unpolled.
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline + Duration::from_millis(150))).await;
                        check(Instant::now() >= deadline && !parent.is_cancelled(), "actual original caller expiry")?;
                    }
                    "code" => {
                        check(deadline.checked_duration_since(observed_phase).is_some_and(|d| d >= Duration::from_secs(30)),
                            "original caller cap leaves thirty seconds beyond this genuine code-stage phase")?;
                        // The original SDK code first poll already preceded
                        // this observed phase. Ten seconds after this point is
                        // strictly beyond that same original ten-second cap;
                        // this wait neither repolls nor renews the business cap.
                        tokio::time::sleep_until(tokio::time::Instant::from_std(observed_phase + Duration::from_millis(10150))).await;
                        check(observed_phase.elapsed() >= Duration::from_secs(10) && Instant::now() < deadline && !parent.is_cancelled(),
                            "actual original code10 expiry with caller and parent still valid")?;
                    }
                    _ => return Err("closed cap cause".into()),
                }
                if let Some(relay) = &relay {
                    // Forward the genuine original C/Z while the exact same
                    // business future remains unpolled. Native ACK receipt is
                    // independent of its later original cap/current bookend.
                    relay.release_original_ack().await;
                }
                let error = rejected(call.await)?;
                let late_release = phase == "release" && cause != "parent";
                let expected_kind = if late_release {
                    TokenKind::RollbackAcknowledgedAfterDeadline
                } else if cause == "parent" { TokenKind::Cancelled } else { TokenKind::Deadline };
                let expected_send_ack = if phase == "send" { Ack::Unknown }
                    else if late_release { Ack::Late } else { Ack::Timely };
                error_kind(&error, expected_kind)?;
                history(&error, Ack::Timely, Ack::Timely, expected_send_ack)?;
                check(error.stage() == (if phase == "body" { TokenStage::TokenReply } else { TokenStage::TokenSend }),
                    "original cancellation/expiry preserves actual send or reply stage")?;
                let snapshot = error.transport_snapshot().ok_or("original cap vector transport snapshot absent")?;
                check(snapshot.may_have_sent()
                    && snapshot.response_status() == (if phase == "send" { None } else { Some(200) })
                    && snapshot.permit_released() == (phase == "body"),
                    "original POST, headers and release facts remain distinct across cap phases")?;
                check(token_posts(&f)?.len() == 1, "original parent/caller/code cap never renews or resends")?;
                let next = f.row(old.attempt_id).await?;
                let stamp = next.code_admitted_at.ok_or("original code admission missing after cap")?;
                let mut expected = old;
                expected.phase = "code_admitted".into();
                expected.code_admitted_at = Some(stamp);
                expected.updated_at = stamp;
                check(next == expected, "cap failure keeps only original three-field code admission, no final write")?;
                if phase == "send" { f.release_headers()?; } else { f.release_body()?; }
                if let Some(relay) = &relay { relay.assert_target(1); }
                eprintln!("GATEWAY_TOKEN_ORIGINAL_CAP cause={cause} phase={phase} kind={expected_kind:?} send_ack={expected_send_ack:?} actual_POST=1 original_future_retained=true cap_renewed=false");
                f.finish().await?;
                if let Some(relay) = relay { relay.stop().await; }
                Ok(())
            }).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r17_token_status() {
    let admin = harness::admin_config("token-r17");
    for status in [201, 301, 302, 400, 401, 500] {
        harness::with_temp_database(&admin, &format!("tok_r17_{status}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            f.configure(&json!({"status":status,"raw":"untrusted status body","headers":[["Content-Type","application/json"],["Location","https://foreign.invalid/second"]]}))?;
            let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = rejected(f.journal.dispatch_token(&auth, verified, &factory).await)?;
            error_kind(&error, TokenKind::HttpStatus(status))?;
            history(&error, Ack::Timely, Ack::Timely, Ack::Timely)?;
            check(token_posts(&f)?.len() == 1, "status refusal keeps one POST and zero second endpoint")?;
            // Actual wire cannot count lazy body polls. The fixed pure p06 and
            // product CODE establish zero bodypoll on this status branch.
            f.finish().await
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r18_token_reply_bounds() {
    let admin = harness::admin_config("token-r18");
    let vectors = [
        (
            json!({"headers":[["Content-Type","text/plain"]]}),
            TokenKind::ProtocolInvalid(ReplyReason::MediaType),
        ),
        (
            json!({"headers":[["Content-Type","application/json"],["Content-Type","application/json"]]}),
            TokenKind::ProtocolInvalid(ReplyReason::MediaType),
        ),
        (
            json!({"raw":"{\"access_token\":\"a\",\"access_token\":\"b\"}"}),
            TokenKind::ProtocolInvalid(ReplyReason::DuplicateKey),
        ),
        (
            json!({"raw":"{\"access_token\":\"a\",\"client_secret\":\"owned-forbidden-secret\"}"}),
            TokenKind::ProtocolInvalid(ReplyReason::ForbiddenSecretKey),
        ),
        (json!({"raw":" ".repeat(65537)}), TokenKind::TokenUnknown),
    ];
    for (index, (settings, expected)) in vectors.into_iter().enumerate() {
        harness::with_temp_database(&admin, &format!("tok_r18_{index}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            f.configure(&settings)?;
            let (auth, verified, _) = verified(
                &f,
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(60),
            )
            .await?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = rejected(f.journal.dispatch_token(&auth, verified, &factory).await)?;
            error_kind(&error, expected)?;
            history(&error, Ack::Timely, Ack::Timely, Ack::Timely)?;
            check(
                token_posts(&f)?.len() == 1
                    && !format!("{error:?}").contains("owned-forbidden-secret"),
                "reachable closed rejection retains no secret body",
            )?;
            if index == 4 {
                // Content-Length=65537 is refused by original SafeHttp before
                // headers return. It proves that boundary, not reply-cursor polls.
                check(
                    error
                        .transport_snapshot()
                        .is_some_and(|s| s.may_have_sent() && s.response_status().is_none()),
                    "original over-limit transport facts",
                )?;
            }
            f.finish().await
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r19_token_ttl_tail() {
    let admin = harness::admin_config("token-r19");
    harness::with_temp_database(&admin, "tok_r19_59", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        f.configure(&json!({"raw":"{\"access_token\":\"owned-access-token\",\"token_type\":\"Bearer\",\"expires_in\":59,\"refresh_token\":\"owned-refresh-token\",\"scope\":\"ai account\"}"}))?;
        let (auth, verified, input) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = f.journal.dispatch_token(&auth, verified, &factory).await.map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        // Actual opaque handoff for a literal 59-second reply proves no SDK
        // sixty-second admission floor. Original expiry math is fixed pure p06.
        drop(owner);
        f.finish().await
    }).await;
    harness::with_temp_database(&admin, "tok_r19_tail", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::TokenSendRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        f.configure(&json!({"hold_body":true}))?;
        let (auth, verified, _) = verified(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        relay.arm_original(&f).await;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        tokio::select! { biased; () = relay.held() => {}, value = &mut call => return Err(format!("tail missed original send ACK: {value:?}")), }
        relay.release_original_ack().await;
        body_pending(&f, &mut call).await?;
        f.release_body()?;
        let until = Instant::now() + Duration::from_secs(5);
        while !f.response_finished()? {
            if Instant::now() >= until { return Err("owned complete body tail absent".into()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Keep the same business future unpolled while the entire owned body is
        // written. Revoke its actual original lease before its next true poll.
        f.disarm_host();
        let error = rejected(call.await)?;
        error_kind(&error, TokenKind::TokenUnknown)?;
        history(&error, Ack::Timely, Ack::Timely, Ack::Timely)?;
        check(error.stage() == TokenStage::TokenReply, "fixed reachable post-body current bookend refuses in TokenReply")?;
        check(error.transport_snapshot().is_some_and(|s| s.may_have_sent() && s.response_status() == Some(200) && s.permit_released()), "true POST original facts kept at last reachable reply bookend")?;
        check(token_posts(&f)?.len() == 1, "no retry after post-body current refusal")?;
        // No claim of a synchronized lease revocation after assemble_tokens;
        // the real final owner gate remains a separate product CODE obligation.
        relay.assert_target(1);
        f.finish().await?;
        relay.stop().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL, TLS and original ACK runtime"]
async fn r20_token_drop_isolate() {
    let admin = harness::admin_config("token-r20");
    harness::with_temp_database(&admin, "tok_r20_drop", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        f.configure(&json!({"hold_body":true}))?;
        let (auth, verified, _) = verified(
            &f,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let mut call = Box::pin(f.journal.dispatch_token(&auth, verified, &factory));
        body_pending(&f, &mut call).await?;
        check(
            token_posts(&f)?.len() == 1,
            "active partial caller has one actual POST",
        )?;
        drop(call);
        f.release_body()?;
        let until = Instant::now() + Duration::from_secs(5);
        while !f.response_finished()? {
            if Instant::now() >= until {
                return Err("dropped original owned peer did not end".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        f.finish().await
    })
    .await;
    for (index, raw) in [
        (
            0,
            "{\"access_token\":\"owned-access-token\",\"token_type\":\"Bearer\",\"expires_in\":59,\"refresh_token\":\"owned-refresh-token\",\"scope\":\"ai account\"}",
        ),
        (
            1,
            "{\"access_token\":\"owned-second-access\",\"token_type\":\"Bearer\",\"expires_in\":59,\"refresh_token\":\"owned-second-refresh\",\"scope\":\"ai account\"}",
        ),
    ] {
        harness::with_temp_database(
            &admin,
            &format!("tok_r20_chain_{index}"),
            |cfg| async move {
                let f = Fixture::new(cfg, 2).await?;
                f.configure(&json!({"raw":raw}))?;
                let (auth, verified, input) = verified(
                    &f,
                    CancellationToken::new(),
                    Instant::now() + Duration::from_secs(60),
                )
                .await?;
                let old = f.rows().await?.remove(0);
                let factory = f.factory(Some("/oauth/desktop/register"))?;
                let owner = f
                    .journal
                    .dispatch_token(&auth, verified, &factory)
                    .await
                    .map_err(|e| e.to_string())?;
                code_success(&f, &old, &owner, &input).await?;
                drop(owner);
                f.finish().await
            },
        )
        .await;
    }
    // Each real chain has its own transport-owned outcomes and bounded controls.
    // Caller Drop does not publish asynchronous ACKs or individual driver joins.
}

mod fixture {
    //! Own genuine token fixture. Original registration/discovery setup is counted separately.
    use super::super::*;
    use super::{GatewayAuthorizationJournal, GatewayAuthorizationJournalRuntimeOwner};
    use openbot_domain::vault::SecretBytes;
    use openbot_infra::GatewayAuthorizationCancellationToken as CancellationToken;
    use openbot_infra::db::tables::gateway_authorization_attempts::Row as AttemptRow;
    use openbot_infra::db::{
        fresh,
        pool::{self, DatabaseConfig},
    };
    use openbot_infra::gateway_account::{GatewayAccountClient, GatewayDesktopMetadata};
    use openbot_infra::gateway_transport::*;
    use openbot_infra::net::safe_http::{
        CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
    };
    use serde_json::Value;
    use std::{
        io::{BufRead as _, Read as _, Write as _},
        net::SocketAddr,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, oneshot},
        task::{JoinHandle, JoinSet},
    };

    pub(super) mod harness {
        use std::future::Future;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/postgres_harness.rs"
        ));
    }
    pub(super) const DEP: &str = "owned-journal-deployment";
    pub(super) const TENANT: &str = "owned-journal-tenant";
    pub(super) const ACTOR: &str = "owned-journal-owner";
    pub(super) const COOKIE: &str = "owned-journal-cookie-00000000000001";
    pub(super) const NEXT_COOKIE: &str = "owned-journal-cookie-00000000000002";
    pub(super) const INSTALLATION: &str =
        "2828282828282828282828282828282828282828282828282828282828282828";
    const SESSION_KEY: &[u8] = b"owned-journal-session-hash-key";

    pub(super) struct Fixture {
        pub(super) config: DatabaseConfig,
        pub(super) pool: pool::DatabasePool,
        pub(super) runtime: Option<Arc<GatewayAuthorizationJournalRuntimeOwner>>,
        pub(super) journal: Arc<GatewayAuthorizationJournal>,
        pub(super) resolver: Arc<PostgresSessionAuthResolver>,
        tls: Option<OwnedTls>,
    }
    impl Fixture {
        pub(super) async fn new(config: DatabaseConfig, size: usize) -> Result<Self, String> {
            let config = config.with_max_pool_size(size);
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut client).await.map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('owned-journal-owner','journal@example.test',7),('owned-journal-other','other@example.test',7),('dev-local-user','dev@openbot.local',7); INSERT INTO public.user_roles(user_id,role) VALUES('owned-journal-owner','user'),('owned-journal-other','user'),('dev-local-user','admin');").await.map_err(|e|e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, cookie) in [
                ("owned-journal-session", COOKIE),
                ("owned-journal-next-session", NEXT_COOKIE),
            ] {
                let hash = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,7)",&[&id,&ACTOR,&hash,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e|e.to_string())?;
            }
            drop(client);
            let env = crate::config::EnvMap::from([(
                "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
                INSTALLATION.to_owned(),
            )]);
            let config_value =
                crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
            let (runtime, journal) = assemble_gateway_authorization_journal(
                &config_value,
                pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![0x28; 32]),
            )
            .map_err(|e| e.to_string())?
            .ok_or("configured journal missing")?;
            let resolver = Arc::new(
                PostgresSessionAuthResolver::new(
                    pool.clone(),
                    SESSION_KEY,
                    openbot_infra::auth::config::default_session_lifetime(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )
                .map_err(|e| e.to_string())?,
            );
            resolver
                .install_gateway_authorization_journal(&journal)
                .map_err(|e| format!("{e:?}"))?;
            Ok(Self {
                config,
                pool,
                runtime: Some(runtime),
                journal,
                resolver,
                tls: Some(OwnedTls::new("journal")?),
            })
        }
        pub(super) async fn new_enrollment(
            config: DatabaseConfig,
            size: usize,
        ) -> Result<Self, String> {
            let fixture = Self::new(config, size).await?;
            let root = &fixture.tls.as_ref().ok_or("owned TLS absent")?.root;
            std::fs::write(root.join("enrollment-mode"), b"owned-enrollment")
                .map_err(|error| error.to_string())?;
            Ok(fixture)
        }
        pub(super) fn enrollment_accounts(
            &self,
            pool: pool::DatabasePool,
            vault: openbot_infra::vault::CredentialRecordVault,
        ) -> Result<openbot_infra::gateway_authority::PostgresGatewayAccounts, String> {
            let tls = self.tls.as_ref().ok_or("owned TLS absent")?;
            if !tls.root.join("enrollment-mode").is_file() {
                return Err("enrollment mode was not explicitly enabled".into());
            }
            openbot_infra::gateway_authority::PostgresGatewayAccounts::new(
                pool,
                vault,
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![0x28; 32]),
                tls.dialer()?,
                &tls.endpoint(),
            )
            .map_err(|error| error.to_string())
        }
        pub(super) fn configure_profile(&self, value: &Value) -> Result<(), String> {
            let root = &self.tls.as_ref().ok_or("owned TLS absent")?.root;
            if !root.join("enrollment-mode").is_file() {
                return Err("profile settings require explicit enrollment mode".into());
            }
            let fields = value
                .as_object()
                .ok_or("profile settings must be an object")?;
            if fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "status" | "headers" | "raw" | "hold_headers" | "hold_body"
                )
            }) {
                return Err("profile settings contain an unknown key".into());
            }
            let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
            if bytes.len() > 131072 {
                return Err("owned profile settings exceeded budget".into());
            }
            let temporary = root.join("profile-settings.tmp");
            std::fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
            std::fs::rename(temporary, root.join("profile-settings.json"))
                .map_err(|error| error.to_string())
        }
        pub(super) fn release_profile_headers(&self) -> Result<(), String> {
            let root = &self.tls.as_ref().ok_or("owned TLS absent")?.root;
            std::fs::write(root.join("release-profile-headers"), b"owned")
                .map_err(|error| error.to_string())
        }
        pub(super) fn release_profile_body(&self) -> Result<(), String> {
            let root = &self.tls.as_ref().ok_or("owned TLS absent")?.root;
            std::fs::write(root.join("release-profile-body"), b"owned")
                .map_err(|error| error.to_string())
        }
        pub(super) async fn finish_enrollment(mut self) -> Result<(), String> {
            self.resolver.close_request_bindings();
            if let Some(runtime) = self.runtime.take() {
                runtime.close();
            }
            let tls = self.tls.take().ok_or("owned TLS absent")?;
            if !tls.root.join("enrollment-mode").is_file() {
                return Err("enrollment finish requires explicit enrollment mode".into());
            }
            let captures = tls.captures()?;
            for capture in &captures {
                let method = capture["method"].as_str().ok_or("owned method absent")?;
                let path = capture["path"].as_str().ok_or("owned path absent")?;
                let profile = method == "GET" && path == "/api/oauth/profile";
                let allowed = profile
                    || (method == "GET"
                        && path == "/.well-known/oauth-authorization-server/desktop")
                    || (method == "POST"
                        && matches!(path, "/oauth/desktop/register" | "/oauth/desktop/token"));
                let expected_authorization = if profile {
                    Value::String("Bearer owned-access-token".into())
                } else {
                    Value::Null
                };
                if !allowed || capture["authorization"] != expected_authorization {
                    return Err("unexpected enrollment TLS dispatch".into());
                }
            }
            let closed = tls.finish();
            self.pool.close();
            eprintln!(
                "GATEWAY_ENROLLMENT_FIXTURE metadata_gets={} registration_posts={} token_posts={} profile_gets={} pool_closed={} individual_production_driver_join=UNPROVEN",
                captures
                    .iter()
                    .filter(|v| v["path"] == "/.well-known/oauth-authorization-server/desktop")
                    .count(),
                captures
                    .iter()
                    .filter(|v| v["path"] == "/oauth/desktop/register")
                    .count(),
                captures
                    .iter()
                    .filter(|v| v["path"] == "/oauth/desktop/token")
                    .count(),
                captures
                    .iter()
                    .filter(|v| v["path"] == "/api/oauth/profile")
                    .count(),
                self.pool.is_closed(),
            );
            closed
        }
        pub(super) async fn auth(&self) -> Result<AuthContext, String> {
            self.auth_cookie(COOKIE).await
        }
        pub(super) async fn auth_cookie(&self, cookie: &str) -> Result<AuthContext, String> {
            self.resolver
                .resolve(
                    &http::Request::builder()
                        .uri("/owned-journal")
                        .header("cookie", format!("openbot_session={cookie}"))
                        .body(())
                        .map_err(|e| e.to_string())?
                        .into_parts()
                        .0,
                )
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn fresh_pair(
            &self,
        ) -> Result<
            (
                Arc<GatewayAuthorizationJournalRuntimeOwner>,
                Arc<GatewayAuthorizationJournal>,
            ),
            String,
        > {
            fresh_pair(
                self.pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
        }
        pub(super) async fn single(
            &self,
            journal: &Arc<GatewayAuthorizationJournal>,
        ) -> Result<SingleUserAuthResolver, String> {
            let principal = openbot_infra::auth::single_user::load_single_user_principal(
                &self.pool,
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .await
            .map_err(|e| e.to_string())?;
            let resolver = SingleUserAuthResolver::from_verified_principal(
                principal,
                openbot_infra::auth::config::default_session_lifetime(),
            );
            resolver
                .install_gateway_authorization_journal(journal, &self.pool)
                .map_err(|e| format!("{e:?}"))?;
            Ok(resolver)
        }
        pub(super) fn factory(
            &self,
            registration: Option<&str>,
        ) -> Result<GatewayTransportFactory, String> {
            let tls = self.tls.as_ref().ok_or("owned TLS closed")?;
            let origin = tls.endpoint();
            let oauth = registration
                .map(|path| {
                    GatewayOAuthEndpoints::new(
                        GatewayOAuthProfile::Desktop,
                        &format!("{origin}{path}"),
                        &format!("{origin}/oauth/desktop/token"),
                        Some(&format!("{origin}/oauth/desktop/revoke")),
                    )
                })
                .transpose()
                .map_err(|e| e.to_string())?;
            Ok(GatewayTransportFactory::new(
                tls.dialer()?,
                VerifiedGatewayEndpoints::new(&origin, None, oauth).map_err(|e| e.to_string())?,
                GatewayTransportLimits::new(Duration::from_secs(10), 65536)
                    .map_err(|e| e.to_string())?,
            ))
        }
        pub(super) fn configure(&self, value: &Value) -> Result<(), String> {
            let tls = self.tls.as_ref().ok_or("owned TLS absent")?;
            let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
            if bytes.len() > 131072 {
                return Err("owned TLS settings exceeded budget".into());
            }
            let temp = tls.root.join("token-settings.tmp");
            std::fs::write(&temp, bytes).map_err(|e| e.to_string())?;
            std::fs::rename(temp, tls.root.join("token-settings.json")).map_err(|e| e.to_string())
        }
        pub(super) fn release_headers(&self) -> Result<(), String> {
            std::fs::write(
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .root
                    .join("release_headers"),
                b"owned",
            )
            .map_err(|e| e.to_string())
        }
        pub(super) fn release_body(&self) -> Result<(), String> {
            std::fs::write(
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .root
                    .join("release_body"),
                b"owned",
            )
            .map_err(|e| e.to_string())
        }
        fn records(&self, file: &str) -> Result<Vec<Value>, String> {
            let path = self.tls.as_ref().ok_or("owned TLS absent")?.root.join(file);
            if !path.exists() {
                return Ok(Vec::new());
            }
            if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1048576 {
                return Err("owned peer records exceeded budget".into());
            }
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let values = text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|e| e.to_string())?;
            if values.len() > 256 {
                return Err("owned peer record count exceeded budget".into());
            }
            Ok(values)
        }
        pub(super) fn response_finished(&self) -> Result<bool, String> {
            let root = &self.tls.as_ref().ok_or("owned TLS absent")?.root;
            if root.join("unexpected-handler-error").exists() {
                return Err("owned handler failed before response proof".into());
            }
            // Published only after complete event writes, so a partial JSON append cannot pass.
            Ok(root.join("token-response-finished").exists())
        }
        pub(super) fn events(&self) -> Result<Vec<Value>, String> {
            self.records("events.jsonl")
        }
        pub(super) fn posts(&self) -> Result<Vec<Value>, String> {
            Ok(self
                .captures()?
                .into_iter()
                .filter(|v| v["method"] == "POST")
                .collect())
        }
        pub(super) fn network_point(&self) -> Result<(usize, usize, usize), String> {
            Ok((
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .dns_count
                    .load(Ordering::SeqCst),
                self.records("connections.jsonl")?.len(),
                self.posts()?.len(),
            ))
        }
        pub(super) async fn metadata(
            &self,
            parent: CancellationToken,
        ) -> Result<GatewayDesktopMetadata, String> {
            let factory = self.factory(Some("/oauth/desktop/register"))?;
            let transport = factory
                .for_operation(
                    Arc::new(DiscoveryOnly),
                    Arc::new(DiscoveryObserved),
                    tokio::time::Instant::now() + Duration::from_secs(15),
                    Duration::from_secs(2),
                )
                .map_err(|e| e.to_string())?;
            let origin = self.issuer();
            let client =
                GatewayAccountClient::new(&origin, transport).map_err(|e| e.to_string())?;
            client
                .fetch_metadata(parent)
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn issuer(&self) -> String {
            self.tls.as_ref().unwrap().endpoint()
        }
        pub(super) async fn rows(&self) -> Result<Vec<AttemptRow>, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            client.query("SELECT * FROM openbot_internal.gateway_authorization_attempts ORDER BY created_at,attempt_id",&[]).await.map_err(|e|e.to_string())?.iter().map(|row|AttemptRow::try_from(row).map_err(|e|e.to_string())).collect()
        }
        pub(super) async fn row(&self, id: uuid::Uuid) -> Result<AttemptRow, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            let row = client
            .query_one(
                "SELECT * FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1",
                &[&id],
            )
            .await
            .map_err(|e| e.to_string())?;
            AttemptRow::try_from(&row).map_err(|e| e.to_string())
        }
        pub(super) async fn audits(&self) -> Result<Vec<Value>, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            Ok(client.query("SELECT payload FROM public.audit_events WHERE event_type LIKE 'gateway_authorization_%' ORDER BY created_at,id",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect())
        }
        pub(super) async fn direct(&self) -> Result<pool::DatabasePool, String> {
            pool::connect(&self.config.clone().with_max_pool_size(2))
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn disarm_host(&self) {
            self.resolver.close_request_bindings();
        }
        pub(super) fn captures(&self) -> Result<Vec<Value>, String> {
            self.tls.as_ref().ok_or("owned TLS absent")?.captures()
        }
        pub(super) async fn finish(mut self) -> Result<(), String> {
            self.resolver.close_request_bindings();
            if let Some(runtime) = self.runtime.take() {
                runtime.close();
            }
            let tls = self.tls.take().ok_or("owned TLS absent")?;
            let captures = tls.captures()?;
            if captures.iter().any(|x| {
                !matches!(x["method"].as_str(), Some("GET" | "POST"))
                    || x["authorization"] != Value::Null
                    || (x["method"] == "POST"
                        && x["path"] != "/oauth/desktop/register"
                        && x["path"] != "/oauth/desktop/token")
            }) {
                return Err("unexpected journal TLS dispatch".into());
            }
            let closed = tls.finish();
            self.pool.close();
            eprintln!(
                "GATEWAY_TOKEN_FIXTURE setup_discovery_gets={} registration_posts={} token_posts={} pool_closed={} individual_production_driver_join=UNPROVEN",
                captures.iter().filter(|v| v["method"] == "GET").count(),
                captures
                    .iter()
                    .filter(|v| v["method"] == "POST" && v["path"] == "/oauth/desktop/register")
                    .count(),
                captures
                    .iter()
                    .filter(|v| v["method"] == "POST" && v["path"] == "/oauth/desktop/token")
                    .count(),
                self.pool.is_closed()
            );
            closed
        }
    }
    pub(super) fn fresh_pair(
        pool: pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<
        (
            Arc<GatewayAuthorizationJournalRuntimeOwner>,
            Arc<GatewayAuthorizationJournal>,
        ),
        String,
    > {
        let env = crate::config::EnvMap::from([(
            "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
            INSTALLATION.to_owned(),
        )]);
        let config = crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
        assemble_gateway_authorization_journal(
            &config,
            pool,
            deployment,
            tenant,
            SecretBytes::new(vec![0x28; 32]),
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "configured journal missing".to_owned())
    }
    struct DiscoveryOnly;
    struct DiscoveryPermit;
    struct DiscoveryObserved;
    #[async_trait::async_trait]
    impl GatewayHttpAuthority for DiscoveryOnly {
        async fn before_request(
            &self,
            request: GatewayRequestDescriptor,
            cancel: CancellationToken,
        ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
            if request.kind() != GatewayRequestKind::OAuthDiscovery || cancel.is_cancelled() {
                return Err(GatewayFenceError::Refused);
            }
            Ok(Box::new(DiscoveryPermit))
        }
    }
    #[async_trait::async_trait]
    impl GatewayHttpPermit for DiscoveryPermit {
        async fn release_after_headers(self: Box<Self>) -> Result<(), GatewayFenceError> {
            Ok(())
        }
    }
    impl GatewayHttpOutcomes for DiscoveryObserved {
        fn started(&self, _: GatewayAttempt) {}
    }

    // The Python interpreter is an explicit Root-frozen test input. It only owns this fixture's
    // random temporary directory, listener and child process; it never changes system trust.
    struct OwnedTls {
        root: PathBuf,
        child: Option<Child>,
        address: SocketAddr,
        ca: Vec<u8>,
        stdout_reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
        root_removed: bool,
        dns_count: Arc<AtomicUsize>,
    }

    impl OwnedTls {
        fn new(label: &str) -> Result<Self, String> {
            let interpreter = PathBuf::from(
                std::env::var_os("OPENBOT_TEST_TLS_PYTHON")
                    .ok_or("Root-pinned Python TLS interpreter missing")?,
            );
            if !interpreter.is_absolute() {
                return Err("TLS interpreter must be an absolute pinned input".to_owned());
            }
            let root = std::env::temp_dir().join(format!(
                "openbot-registration-owned-tls-{label}-{}",
                uuid::Uuid::now_v7()
            ));
            std::fs::create_dir(&root).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| e.to_string())?;
            }
            let child = Command::new(interpreter)
                .args(["-I", "-u", "-c", PYTHON_TLS])
                .arg(&root)
                .args([TEST_CA, TEST_LEAF, TEST_KEY])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| e.to_string())?;
            let mut fixture = Self {
                root,
                child: Some(child),
                address: "127.0.0.1:0".parse().unwrap(),
                ca: Vec::new(),
                stdout_reader: None,
                root_removed: false,
                dns_count: Arc::new(AtomicUsize::new(0)),
            };
            let stdout = fixture
                .child
                .as_mut()
                .unwrap()
                .stdout
                .take()
                .ok_or("owned TLS stdout missing")?;
            let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
            fixture.stdout_reader = Some(std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stdout);
                let mut line = String::new();
                let bytes = reader
                    .by_ref()
                    .take(8193)
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?;
                if bytes == 0 || bytes > 8192 {
                    return Err("owned TLS startup output missing or unbounded".to_owned());
                }
                ready_send.send(line).map_err(|e| e.to_string())?;
                let mut tail = Vec::new();
                reader
                    .take(65537)
                    .read_to_end(&mut tail)
                    .map_err(|e| e.to_string())?;
                if tail.len() > 65536 {
                    return Err("owned TLS stdout tail exceeded budget".to_owned());
                }
                Ok(tail)
            }));
            let line = ready_receive
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| format!("owned TLS startup not acknowledged: {e}"))?;
            let ready: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            let port = ready["port"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("owned TLS port invalid")?;
            if port == 0 || [39025, 39027].contains(&port) {
                return Err("owned TLS port is outside fixture policy".to_owned());
            }
            fixture.address = SocketAddr::from(([127, 0, 0, 1], port));
            fixture.ca = serde_json::from_value(ready["ca"].clone()).map_err(|e| e.to_string())?;
            eprintln!(
                "GATEWAY_TOKEN_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
                fixture.child.as_ref().unwrap().id(),
                fixture.root.display()
            );
            Ok(fixture)
        }
        fn endpoint(&self) -> String {
            format!("https://idp.test:{}", self.address.port())
        }
        fn dialer(&self) -> Result<SafeDialer, String> {
            SafeDialer::with_extra_roots(
                EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|e| e.to_string())?,
                ),
                Arc::new(OwnedDns {
                    address: self.address,
                    count: self.dns_count.clone(),
                }),
                [self.ca.clone().into()],
            )
            .map_err(|e| e.to_string())
        }
        fn release(&self) -> Result<(), String> {
            std::fs::write(self.root.join("release_headers"), b"owned")
                .map_err(|e| e.to_string())?;
            std::fs::write(self.root.join("release_body"), b"owned").map_err(|e| e.to_string())
        }
        fn captures(&self) -> Result<Vec<Value>, String> {
            let path = self.root.join("captures.jsonl");
            if !path.exists() {
                return Ok(Vec::new());
            }
            if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
                return Err("owned TLS captures exceeded budget".to_owned());
            }
            let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let captures: Vec<Value> = contents
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            if captures.len() > 64 {
                return Err("owned TLS capture count exceeded budget".to_owned());
            }
            Ok(captures)
        }
        fn finish(mut self) -> Result<(), String> {
            self.release()?;
            let child = self.child.as_mut().ok_or("owned TLS child absent")?;
            child
                .stdin
                .as_mut()
                .ok_or("owned TLS stop channel absent")?
                .write_all(b"x")
                .map_err(|e| e.to_string())?;
            drop(child.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    if !status.success() {
                        return Err("owned TLS child did not exit naturally with zero".to_owned());
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("owned TLS child did not acknowledge stop".to_owned());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid = child.id();
            drop(self.child.take());
            let tail = self
                .stdout_reader
                .take()
                .ok_or("owned TLS stdout reader absent")?
                .join()
                .map_err(|_| "owned TLS stdout reader panicked")??;
            let stopped: Value = serde_json::from_slice(&tail).map_err(|e| e.to_string())?;
            if stopped["stopped"] != true || stopped["fatal"] != false {
                return Err("owned TLS stop output missing".to_owned());
            }
            let count = self.captures()?.len();
            std::fs::remove_dir_all(&self.root).map_err(|e| e.to_string())?;
            if self.root.exists() {
                return Err("owned TLS root survived cleanup".to_owned());
            }
            self.root_removed = true;
            eprintln!(
                "GATEWAY_TOKEN_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
                self.root.display()
            );
            Ok(())
        }
    }
    impl Drop for OwnedTls {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("GATEWAY_TOKEN_OWNED_TLS fallback_kill=true natural_stop_unproven=true");
            }
            if let Some(reader) = self.stdout_reader.take() {
                let _ = reader.join();
            }
            if !self.root_removed {
                eprintln!(
                    "GATEWAY_TOKEN_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
                    self.root.display()
                );
            }
        }
    }
    struct OwnedDns {
        address: SocketAddr,
        count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl DnsResolver for OwnedDns {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if host == "idp.test" && port == self.address.port() {
                Ok(vec![self.address])
            } else {
                Err(DnsUnavailable)
            }
        }
    }

    const PYTHON_TLS: &str = r#"
import base64,http.server,json,os,pathlib,ssl,sys,threading,time
root=pathlib.Path(sys.argv[1]); os.umask(0o077)
ca,leaf,key=[base64.b64decode(x,validate=True) for x in sys.argv[2:5]]
def pem(kind,data): return ('-----BEGIN '+kind+'-----\n'+base64.encodebytes(data).decode()+'-----END '+kind+'-----\n')
(root/'leaf.pem').write_text(pem('CERTIFICATE',leaf)); (root/'key.pem').write_text(pem('PRIVATE KEY',key))
stop=threading.Event(); fatal=threading.Event(); count=0; connections=0
def record(file,data):
    path=root/file
    if path.exists() and path.stat().st_size>1048576: raise RuntimeError('owned capture byte budget')
    with path.open('a') as f: f.write(json.dumps(data,separators=(',',':'))+'\n'); f.flush()
def stopping(): sys.stdin.buffer.read(1); stop.set()
thread=threading.Thread(target=stopping); thread.start()
def wait_owned(name):
    deadline=time.monotonic()+13
    while not (root/name).exists() and not stop.is_set():
        if time.monotonic()>=deadline: raise RuntimeError('owned release deadline')
        time.sleep(.005)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def capture(self,body):
        global count
        if count>=64: raise RuntimeError('owned request count budget')
        count+=1
        record('captures.jsonl',{'method':self.command,'path':self.path,'authorization':self.headers.get('Authorization'),'headers':list(self.headers.raw_items()),'body':body.decode('utf8')})
    def send_owned(self,status,headers,data):
        self.send_response(status)
        for name,value in headers: self.send_header(name,value)
        self.send_header('Content-Length',str(len(data))); self.send_header('Connection','close'); self.end_headers(); self.wfile.flush()
        record('events.jsonl',{'event':'headers_sent','path':self.path,'method':self.command,'status':status,'headers':headers,'body_bytes':len(data),'content_length':str(len(data))})
        return data
    def do_profile(self):
        self.connection.settimeout(6)
        if not (root/'enrollment-mode').is_file() or self.path!='/api/oauth/profile': raise RuntimeError('owned enrollment profile path')
        if self.headers.get_all('Authorization',[])!=['Bearer owned-access-token']: raise RuntimeError('owned profile bearer mismatch')
        self.capture(b'')
        record('events.jsonl',{'event':'profile_request_received','path':self.path,'method':'GET'})
        settings=root/'profile-settings.json'
        if settings.exists() and settings.stat().st_size>131072: raise RuntimeError('owned profile settings bound')
        config=json.loads(settings.read_text()) if settings.exists() else {}
        if not isinstance(config,dict) or set(config)-{'status','headers','raw','hold_headers','hold_body'}: raise RuntimeError('owned profile settings keys')
        data=config.get('raw','{"id":"owned-account","uuid":"owned-account","account":{"uuid":"owned-account"},"organization":{"uuid":"owned-org"}}').encode('utf8')
        if len(data)>131072: raise RuntimeError('owned profile response byte bound')
        headers=config.get('headers',[['Content-Type','application/json']])
        if len(headers)>128 or any(len(n)+len(v)>16384 for n,v in headers): raise RuntimeError('owned profile header budget')
        status=config.get('status',200)
        if type(status) is not int or not 100<=status<=599: raise RuntimeError('owned profile status')
        outcome='stopped'
        try:
            if config.get('hold_headers'): wait_owned('release-profile-headers')
            if not stop.is_set():
                self.send_owned(status,headers,data)
                if config.get('hold_body'):
                    record('events.jsonl',{'event':'profile_body_pending','path':self.path,'method':'GET'})
                    wait_owned('release-profile-body')
                if not stop.is_set():
                    self.wfile.write(data); self.wfile.flush(); record('events.jsonl',{'event':'body_sent','path':self.path,'method':'GET','bytes':len(data),'body_hex':data.hex()}); outcome='body_sent'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as closed:
            record('events.jsonl',{'event':'peer_closed','path':self.path,'method':'GET','kind':type(closed).__name__}); outcome='peer_closed'
        self.close_connection=True
        record('events.jsonl',{'event':'response_finished','path':self.path,'method':'GET','outcome':outcome})
        (root/'profile-response-finished').write_bytes(b'owned')
    def do_GET(self):
        if (root/'enrollment-mode').is_file() and self.path=='/api/oauth/profile': self.do_profile(); return
        self.connection.settimeout(6)
        if self.path!='/.well-known/oauth-authorization-server/desktop': raise RuntimeError('owned discovery path')
        if self.headers.get('Authorization') is not None: raise RuntimeError('owned discovery carried bearer')
        origin='https://idp.test:'+str(self.server.server_port)
        data=json.dumps({'issuer':origin,'authorization_endpoint':origin+'/oauth/desktop/authorize','token_endpoint':origin+'/oauth/desktop/token','registration_endpoint':origin+'/oauth/desktop/register','revocation_endpoint':origin+'/oauth/desktop/revoke','scopes_supported':['ai','account'],'response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'grant_types_supported':['authorization_code','refresh_token'],'crabcode_auth_contract_version':2,'gateway_error_contract_version':1},separators=(',',':')).encode()
        self.capture(b''); self.send_owned(200,[['Content-Type','application/json']],data); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
    def do_POST(self):
        self.connection.settimeout(6)
        if self.path not in ['/oauth/desktop/register','/oauth/desktop/token']: raise RuntimeError('owned POST path denies other endpoints')
        length=int(self.headers.get('Content-Length','-1'))
        if not 0<=length<=65536: raise RuntimeError('owned request byte bound')
        body=self.rfile.read(length)
        if len(body)!=length: raise RuntimeError('owned request EOF')
        self.capture(body)
        settings=root/('token-settings.json' if self.path=='/oauth/desktop/token' else 'settings.json')
        if settings.exists() and settings.stat().st_size>131072: raise RuntimeError('owned settings bound')
        config=json.loads(settings.read_text()) if settings.exists() else {}
        if config.get('close_before_headers'): self.close_connection=True; return
        if config.get('hold_headers'): wait_owned('release_headers')
        if stop.is_set(): self.close_connection=True; return
        default='{"access_token":"owned-access-token","token_type":"Bearer","expires_in":59,"refresh_token":"owned-refresh-token","scope":"ai account"}' if self.path=='/oauth/desktop/token' else '{"client_id":"owned-registration-client"}'
        data=config.get('raw',default).encode('utf8')
        if len(data)>131072: raise RuntimeError('owned response byte bound')
        headers=config.get('headers',[['Content-Type','application/json']])
        if len(headers)>128 or any(len(n)+len(v)>16384 for n,v in headers): raise RuntimeError('owned header budget')
        outcome='stopped'
        try:
            self.send_owned(config.get('status',200),headers,data)
            if config.get('hold_body'): wait_owned('release_body')
            if not stop.is_set():
                self.wfile.write(data); self.wfile.flush(); record('events.jsonl',{'event':'body_sent','path':self.path,'method':'POST','bytes':len(data),'body_hex':data.hex()}); outcome='body_sent'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as closed:
            record('events.jsonl',{'event':'peer_closed','method':'POST','kind':type(closed).__name__}); outcome='peer_closed'
        self.close_connection=True
        record('events.jsonl',{'event':'response_finished','path':self.path,'method':'POST','outcome':outcome})
        if self.path=='/oauth/desktop/token': (root/'token-response-finished').write_bytes(b'owned')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'leaf.pem',root/'key.pem')
class Server(http.server.HTTPServer):
    def handle_error(self,request,client_address):
        # BaseServer must not swallow an unexpected owned handler failure into exit zero.
        fatal.set(); stop.set()
        (root/'unexpected-handler-error').write_bytes(b'UnexpectedHandler')
        record('events.jsonl',{'event':'unexpected_handler_error','failure':'UnexpectedHandler'})
    def get_request(self):
        global connections
        raw,address=self.socket.accept(); raw.settimeout(3); connections+=1
        if connections>64: raw.close(); raise RuntimeError('owned socket count budget')
        record('connections.jsonl',{'accepted':connections})
        try: return context.wrap_socket(raw,server_side=True),address
        except BaseException: raw.close(); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=.2
print(json.dumps({'port':server.server_port,'ca':list(ca)}),flush=True)
try:
    while not stop.is_set(): server.handle_request()
finally: server.server_close(); stop.set(); thread.join(timeout=2)
print(json.dumps({'stopped':not fatal.is_set(),'fatal':fatal.is_set(),'requests':count,'connections':connections}),flush=True)
if thread.is_alive(): raise RuntimeError('owned stop reader did not join')
if fatal.is_set(): raise RuntimeError('owned handler failed')
"#;

    // Existing repository non-production W7 CA/leaf/key, SAN=idp.test. Never installed in OS trust.
    const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
    const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
    const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

    // Select only the original journal transaction on its real backend, never a v2 classifier.
    #[derive(Clone, Copy, Debug)]
    pub(super) enum TerminalStage {
        TokenSendRollback,
        CodeCommit,
        CodeReadbackRollback,
        EnrollmentMetadataRollback,
        EnrollmentProfileRollback,
        EnrollmentCommit,
        EnrollmentReadbackRollback,
    }
    impl TerminalStage {
        fn is_enrollment(self) -> bool {
            matches!(
                self,
                Self::EnrollmentMetadataRollback
                    | Self::EnrollmentProfileRollback
                    | Self::EnrollmentCommit
                    | Self::EnrollmentReadbackRollback
            )
        }
        fn enrollment_read_only(self) -> bool {
            matches!(self, Self::EnrollmentReadbackRollback)
        }
        fn enrollment_sql_bits(self, body: &str) -> u8 {
            match self {
                Self::EnrollmentMetadataRollback | Self::EnrollmentProfileRollback => u8::from(
                    body.starts_with("select ")
                        && body.contains("from openbot_internal.gateway_authorization_attempts")
                        && body.contains("for update"),
                ),
                Self::EnrollmentCommit => {
                    u8::from(body.starts_with("insert into public.sdk_gateway_connections"))
                        | (u8::from(body.starts_with("insert into public.sdk_gateway_secrets"))
                            << 1)
                        | (u8::from(body.starts_with("insert into public.audit_events")) << 2)
                }
                Self::EnrollmentReadbackRollback => {
                    if !body.starts_with("select ")
                        || body.contains("for update")
                        || body.contains("for share")
                    {
                        return 0;
                    }
                    u8::from(body.contains("from public.sdk_gateway_connections"))
                        | (u8::from(body.contains("from public.sdk_gateway_secrets")) << 1)
                }
                _ => 0,
            }
        }
        fn command(self) -> &'static [u8] {
            if matches!(self, Self::EnrollmentCommit) {
                return b"COMMIT\0";
            }
            if matches!(self, Self::CodeCommit) {
                b"COMMIT\0"
            } else {
                b"ROLLBACK\0"
            }
        }
        fn sql_bits(self, sql: &[u8]) -> u8 {
            let Ok(sql) = std::str::from_utf8(sql) else {
                return 0;
            };
            let canonical = sql
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase();
            let (marker, body) = if let Some(comment) = canonical.strip_prefix("/* ") {
                let Some((marker, body)) = comment.split_once(" */") else {
                    return 0;
                };
                (Some(marker), body.trim_start())
            } else {
                (None, canonical.as_str())
            };
            let assignments = body.split(" where ").next().unwrap_or(body);
            let journal = match self {
                Self::TokenSendRollback => {
                    marker == Some("gateway_authorization_attempt_lock")
                        && body.starts_with("select ")
                        && body.contains("from openbot_internal.gateway_authorization_attempts")
                        && body.contains("for update")
                }
                Self::CodeCommit => {
                    marker == Some("gateway_authorization_code_admitted")
                        && assignments
                            .starts_with("update openbot_internal.gateway_authorization_attempts")
                        && assignments.contains("code_admitted_at")
                        && assignments.contains("updated_at")
                }
                Self::CodeReadbackRollback => {
                    marker == Some("gateway_authorization_exact_readback")
                        && body.starts_with("select ")
                        && body.contains("from openbot_internal.gateway_authorization_attempts")
                        && !body.contains("for update")
                }
                Self::EnrollmentMetadataRollback | Self::EnrollmentProfileRollback => {
                    return if marker == Some("gateway_authorization_attempt_lock") {
                        self.enrollment_sql_bits(body)
                    } else {
                        0
                    };
                }
                Self::EnrollmentCommit | Self::EnrollmentReadbackRollback => {
                    return self.enrollment_sql_bits(body);
                }
            };
            let audit = body.starts_with("insert into public.audit_events");
            u8::from(journal) | (u8::from(audit) << 1)
        }
        fn complete_bits(self) -> u8 {
            match self {
                Self::EnrollmentCommit => return 7,
                Self::EnrollmentReadbackRollback => return 3,
                Self::EnrollmentMetadataRollback | Self::EnrollmentProfileRollback => return 1,
                _ => {}
            }
            if matches!(self, Self::CodeCommit) {
                3
            } else {
                1
            }
        }
    }

    struct TerminalGateState {
        stage: TerminalStage,
        discard: bool,
        armed: std::sync::atomic::AtomicBool,
        claimed: std::sync::atomic::AtomicBool,
        original_backend_pid: AtomicUsize,
        selected_backend_pid: AtomicUsize,
        stage_seen: AtomicUsize,
        begins: AtomicUsize,
        all_begins_after_arm: AtomicUsize,
        enrollment_header_transactions: AtomicUsize,
        commits: AtomicUsize,
        rollbacks: AtomicUsize,
        command_acks: AtomicUsize,
        ready_acks: AtomicUsize,
        forwarded_acks: AtomicUsize,
        accepted: AtomicUsize,
        joined: AtomicUsize,
        held: Semaphore,
        release: Semaphore,
        forwarded: Semaphore,
    }
    pub(super) struct PgTerminalAckGate {
        pub(super) config: DatabaseConfig,
        state: Arc<TerminalGateState>,
        stop: Option<oneshot::Sender<()>>,
        task: Option<JoinHandle<Result<(), String>>>,
    }
    impl PgTerminalAckGate {
        pub(super) async fn new(
            config: &DatabaseConfig,
            stage: TerminalStage,
            discard: bool,
        ) -> Self {
            assert_eq!(config.host, "127.0.0.1");
            let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut routed = config.clone();
            routed.port = listener.local_addr().unwrap().port();
            assert!(![39025, 39027].contains(&routed.port));
            let state = Arc::new(TerminalGateState {
                stage,
                discard,
                armed: std::sync::atomic::AtomicBool::new(false),
                claimed: std::sync::atomic::AtomicBool::new(false),
                original_backend_pid: AtomicUsize::new(0),
                selected_backend_pid: AtomicUsize::new(0),
                stage_seen: AtomicUsize::new(0),
                begins: AtomicUsize::new(0),
                all_begins_after_arm: AtomicUsize::new(0),
                enrollment_header_transactions: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                rollbacks: AtomicUsize::new(0),
                command_acks: AtomicUsize::new(0),
                ready_acks: AtomicUsize::new(0),
                forwarded_acks: AtomicUsize::new(0),
                accepted: AtomicUsize::new(0),
                joined: AtomicUsize::new(0),
                held: Semaphore::new(0),
                release: Semaphore::new(0),
                forwarded: Semaphore::new(0),
            });
            eprintln!(
                "GATEWAY_TOKEN_TERMINAL_RELAY_START owned_process_pid={} stage={stage:?} relay_port={} upstream_port={}",
                std::process::id(),
                routed.port,
                config.port
            );
            let shared = state.clone();
            let (stop, mut stopped) = oneshot::channel();
            let task = tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        accepted = listener.accept() => {
                            let (downstream, _) = accepted.map_err(|_| "terminal relay accept")?;
                            let count = shared.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                            if count > 64 || children.len() >= 32 {
                                return Err("terminal relay bounded connection limit".into());
                            }
                            children.spawn(terminal_relay_connection(downstream, upstream, shared.clone()));
                        },
                        Some(child) = children.join_next(), if !children.is_empty() => {
                            child.map_err(|_| "terminal relay child join")??;
                            shared.joined.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                drop(listener);
                // The Pool/assembly are closed before stop. Normal success must reap
                // every owned relay child, without abort_all or a synthetic join ACK.
                tokio::time::timeout(Duration::from_secs(8), async {
                    while let Some(child) = children.join_next().await {
                        child.map_err(|_| "terminal relay tail child join")??;
                        shared.joined.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok::<(), String>(())
                })
                .await
                .map_err(|_| "terminal relay normal tail deadline")??;
                Ok(())
            });
            Self {
                config: routed,
                state,
                stop: Some(stop),
                task: Some(task),
            }
        }
        pub(super) fn arm_enrollment(&self) {
            assert!(self.state.stage.is_enrollment());
            assert_eq!(self.state.original_backend_pid.load(Ordering::SeqCst), 0);
            assert!(!self.state.claimed.load(Ordering::SeqCst));
            self.state.armed.store(true, Ordering::SeqCst);
        }
        pub(super) async fn arm_original(&self, f: &Fixture) -> pool::ConnectionObservation {
            assert_eq!(f.pool.status().max_size, 1);
            let client = f.pool.get().await.unwrap();
            let backend: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            assert!(backend > 0);
            let original = client.observation();
            assert!(!original.snapshot().retirement_requested);
            assert!(!original.snapshot().connection_destroyed);
            self.state
                .original_backend_pid
                .store(backend as usize, Ordering::SeqCst);
            drop(client);
            self.state.armed.store(true, Ordering::SeqCst);
            original
        }
        pub(super) async fn held(&self) {
            tokio::time::timeout(Duration::from_secs(6), self.state.held.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        pub(super) fn original_pid(&self) -> i32 {
            i32::try_from(self.state.original_backend_pid.load(Ordering::SeqCst)).unwrap()
        }
        pub(super) async fn release_original_ack(&self) {
            assert!(!self.state.discard);
            self.state.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(2), self.state.forwarded.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            // A successful socket write is not driver receipt or join. Allow the
            // real driver to run while the original business future stays unpolled;
            // only its later real owner result can establish known-late state.
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        pub(super) fn assert_target(&self, expected_forwarded: usize) {
            assert_eq!(
                self.state.selected_backend_pid.load(Ordering::SeqCst),
                self.state.original_backend_pid.load(Ordering::SeqCst)
            );
            assert_ne!(self.state.selected_backend_pid.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 1);
            assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 1);
            assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 1);
            assert_eq!(
                self.state.forwarded_acks.load(Ordering::SeqCst),
                expected_forwarded
            );
            assert_eq!(self.state.begins.load(Ordering::SeqCst), 1);
            match self.state.stage {
                TerminalStage::EnrollmentCommit => {
                    assert_eq!(self.state.commits.load(Ordering::SeqCst), 1);
                    assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 0);
                }
                TerminalStage::CodeCommit => {
                    assert_eq!(self.state.commits.load(Ordering::SeqCst), 1);
                    assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 0);
                }
                _ => {
                    assert_eq!(self.state.commits.load(Ordering::SeqCst), 0);
                    assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 1);
                }
            }
        }
        pub(super) async fn stop(mut self) {
            self.state.armed.store(false, Ordering::SeqCst);
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            let mut task = self.task.take().unwrap();
            match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                Ok(result) => result.unwrap().unwrap(),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    panic!("terminal relay did not naturally join");
                }
            }
            let accepted = self.state.accepted.load(Ordering::SeqCst);
            let joined = self.state.joined.load(Ordering::SeqCst);
            assert_eq!(accepted, joined);
            eprintln!(
                "GATEWAY_TOKEN_TERMINAL_RELAY stage={:?} backend_pid={} accepted={} naturally_joined={} command_ack={} ready_ack={} forwarded_ack={} listener_closed=true",
                self.state.stage,
                self.state.selected_backend_pid.load(Ordering::SeqCst),
                accepted,
                joined,
                self.state.command_acks.load(Ordering::SeqCst),
                self.state.ready_acks.load(Ordering::SeqCst),
                self.state.forwarded_acks.load(Ordering::SeqCst)
            );
        }
    }
    impl Drop for PgTerminalAckGate {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(task) = self.task.take() {
                eprintln!(
                    "GATEWAY_TOKEN_TERMINAL_RELAY fallback_abort=true normal_join_unproven=true"
                );
                task.abort();
            }
        }
    }
    fn pg_statement(tag: u8, bytes: &[u8]) -> Option<&[u8]> {
        let sql = match tag {
            b'Q' => bytes,
            b'P' => &bytes[bytes.iter().position(|b| *b == 0)? + 1..],
            _ => return None,
        };
        Some(&sql[..sql.iter().position(|b| *b == 0)?])
    }
    async fn terminal_relay_connection(
        mut downstream: TcpStream,
        upstream_address: SocketAddr,
        state: Arc<TerminalGateState>,
    ) -> Result<(), String> {
        let mut upstream = TcpStream::connect(upstream_address)
            .await
            .map_err(|_| "terminal upstream connect")?;
        let len = downstream
            .read_u32()
            .await
            .map_err(|_| "terminal startup length")?;
        if !(8..=65536).contains(&len) {
            return Err("terminal startup bound".into());
        }
        let mut startup = vec![0; len as usize - 4];
        downstream
            .read_exact(&mut startup)
            .await
            .map_err(|_| "terminal startup read")?;
        upstream
            .write_u32(len)
            .await
            .map_err(|_| "terminal startup header")?;
        upstream
            .write_all(&startup)
            .await
            .map_err(|_| "terminal startup forwarding")?;
        if len == 16 && startup[..4] == 80877102_u32.to_be_bytes() {
            // Forward the actual cancellation packet without inventing a terminal ACK.
            upstream
                .shutdown()
                .await
                .map_err(|_| "terminal cancel forwarding shutdown")?;
            return Ok(());
        }
        if startup[..4] != 196608_u32.to_be_bytes() {
            return Err("terminal relay requires original NoTls protocol3 startup".into());
        }
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();
        let backend = Arc::new(AtomicUsize::new(0));
        let selected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_state = state.clone();
        let client_backend = backend.clone();
        let client_selected = selected.clone();
        let client = async move {
            let mut stage_bits = 0;
            let mut seen_stage = false;
            let mut skipped_enrollment_stage = false;
            let mut original_begin = false;
            let mut original_read_only = false;
            let mut token_code_seen = false;
            let mut token_code_committed = false;
            let mut token_readback_finished = false;
            while let Some((tag, bytes)) = terminal_frame(&mut down_read).await? {
                if client_state.armed.load(Ordering::SeqCst)
                    && (if client_state.stage.is_enrollment() {
                        !client_state.claimed.load(Ordering::SeqCst)
                    } else {
                        client_backend.load(Ordering::SeqCst)
                            == client_state.original_backend_pid.load(Ordering::SeqCst)
                    })
                    && client_backend.load(Ordering::SeqCst) != 0
                {
                    if tag == b'Q'
                        && (bytes.starts_with(b"START TRANSACTION") || bytes.starts_with(b"BEGIN"))
                    {
                        client_state
                            .all_begins_after_arm
                            .fetch_add(1, Ordering::SeqCst);
                        stage_bits = 0;
                        seen_stage = false;
                        skipped_enrollment_stage = false;
                        let query =
                            std::str::from_utf8(&bytes).map_err(|_| "terminal BEGIN UTF8")?;
                        original_begin = query.contains("ISOLATION LEVEL READ COMMITTED");
                        original_read_only = query.contains("READ ONLY");
                    }
                    if let Some(sql) = pg_statement(tag, &bytes) {
                        if std::str::from_utf8(sql)
                            .is_ok_and(|s| s.contains("/* gateway_authorization_code_admitted */"))
                        {
                            token_code_seen = true;
                        }
                        let bits = if matches!(client_state.stage, TerminalStage::TokenSendRollback)
                            && !token_readback_finished
                        {
                            0
                        } else {
                            client_state.stage.sql_bits(sql)
                        };
                        stage_bits |= bits;
                        if stage_bits == client_state.stage.complete_bits()
                            && !seen_stage
                            && !skipped_enrollment_stage
                        {
                            if !original_begin
                                || original_read_only
                                    != (if client_state.stage.is_enrollment() {
                                        client_state.stage.enrollment_read_only()
                                    } else {
                                        matches!(
                                            client_state.stage,
                                            TerminalStage::CodeReadbackRollback
                                        )
                                    })
                            {
                                return Err(
                                    "terminal original business RC/read-only mode mismatch".into(),
                                );
                            }
                            let header_ordinal = if matches!(
                                client_state.stage,
                                TerminalStage::EnrollmentMetadataRollback
                                    | TerminalStage::EnrollmentProfileRollback
                            ) {
                                Some(
                                    client_state
                                        .enrollment_header_transactions
                                        .fetch_add(1, Ordering::SeqCst)
                                        + 1,
                                )
                            } else {
                                None
                            };
                            skipped_enrollment_stage = matches!((client_state.stage, header_ordinal),
                                (TerminalStage::EnrollmentMetadataRollback, Some(n)) if n != 1)
                                || matches!((client_state.stage, header_ordinal),
                                (TerminalStage::EnrollmentProfileRollback, Some(n)) if n != 2);
                            if !skipped_enrollment_stage {
                                if client_state.stage.is_enrollment() {
                                    let pid = client_backend.load(Ordering::SeqCst);
                                    match client_state.original_backend_pid.compare_exchange(
                                        0,
                                        pid,
                                        Ordering::SeqCst,
                                        Ordering::SeqCst,
                                    ) {
                                        Ok(_) => {}
                                        Err(original) if original == pid => {}
                                        Err(_) => return Err(
                                            "enrollment selector matched a second original backend"
                                                .into(),
                                        ),
                                    }
                                }
                                seen_stage = true;
                                client_state.begins.fetch_add(1, Ordering::SeqCst);
                                client_state.stage_seen.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    if tag == b'Q' && bytes.eq_ignore_ascii_case(b"COMMIT\0") && token_code_seen {
                        token_code_committed = true;
                    }
                    if tag == b'Q'
                        && bytes.eq_ignore_ascii_case(b"ROLLBACK\0")
                        && original_read_only
                        && token_code_committed
                    {
                        token_readback_finished = true;
                    }
                    if tag == b'Q' && seen_stage {
                        if bytes.eq_ignore_ascii_case(b"COMMIT\0") {
                            client_state.commits.fetch_add(1, Ordering::SeqCst);
                        }
                        if bytes.eq_ignore_ascii_case(b"ROLLBACK\0") {
                            client_state.rollbacks.fetch_add(1, Ordering::SeqCst);
                        }
                        if seen_stage
                            && bytes.eq_ignore_ascii_case(client_state.stage.command())
                            && client_state
                                .claimed
                                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                        {
                            client_state
                                .selected_backend_pid
                                .store(client_backend.load(Ordering::SeqCst), Ordering::SeqCst);
                            client_selected.store(true, Ordering::SeqCst);
                        }
                    }
                }
                up_write
                    .write_u8(tag)
                    .await
                    .map_err(|_| "terminal frontend tag write")?;
                up_write
                    .write_u32(bytes.len() as u32 + 4)
                    .await
                    .map_err(|_| "terminal frontend length write")?;
                up_write
                    .write_all(&bytes)
                    .await
                    .map_err(|_| "terminal frontend body write")?;
                if tag == b'Q'
                    && (bytes.eq_ignore_ascii_case(b"COMMIT\0")
                        || bytes.eq_ignore_ascii_case(b"ROLLBACK\0"))
                {
                    stage_bits = 0;
                    seen_stage = false;
                    original_begin = false;
                    original_read_only = false;
                }
            }
            Ok::<(), String>(())
        };
        let server = async move {
            let mut command_complete = None;
            while let Some((tag, bytes)) = terminal_frame(&mut up_read).await? {
                if tag == b'K' {
                    if bytes.len() != 8 {
                        return Err("terminal BackendKeyData shape".into());
                    }
                    backend.store(
                        u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
                        Ordering::SeqCst,
                    );
                }
                if selected.load(Ordering::SeqCst) {
                    if tag == b'C' && bytes == state.stage.command() {
                        if command_complete.is_some() {
                            return Err("terminal original CommandComplete mismatch".into());
                        }
                        state.command_acks.fetch_add(1, Ordering::SeqCst);
                        command_complete = Some(bytes);
                        continue;
                    }
                    if tag == b'Z' && command_complete.is_some() {
                        let completion = command_complete
                            .take()
                            .ok_or("terminal ReadyForQuery without original C")?;
                        if bytes != b"I" {
                            return Err("terminal original ACK did not leave idle".into());
                        }
                        state.ready_acks.fetch_add(1, Ordering::SeqCst);
                        state.held.add_permits(1);
                        if state.discard {
                            return Ok(());
                        }
                        tokio::time::timeout(Duration::from_secs(13), state.release.acquire())
                            .await
                            .map_err(|_| "terminal original ACK release deadline")?
                            .map_err(|_| "terminal original ACK release closed")?
                            .forget();
                        down_write
                            .write_u8(b'C')
                            .await
                            .map_err(|_| "terminal C write")?;
                        down_write
                            .write_u32(completion.len() as u32 + 4)
                            .await
                            .map_err(|_| "terminal C length")?;
                        down_write
                            .write_all(&completion)
                            .await
                            .map_err(|_| "terminal C body")?;
                        down_write
                            .write_u8(b'Z')
                            .await
                            .map_err(|_| "terminal Z write")?;
                        down_write
                            .write_u32(bytes.len() as u32 + 4)
                            .await
                            .map_err(|_| "terminal Z length")?;
                        down_write
                            .write_all(&bytes)
                            .await
                            .map_err(|_| "terminal Z body")?;
                        state.forwarded_acks.fetch_add(1, Ordering::SeqCst);
                        state.forwarded.add_permits(1);
                        state.armed.store(false, Ordering::SeqCst);
                        selected.store(false, Ordering::SeqCst);
                        continue;
                    }
                    // An earlier prepared Statement Drop can still have CloseComplete/
                    // ReadyForQuery on this same socket. Forward those until the exact
                    // target C is seen; they never count as the target terminal ACK.
                    if tag == b'E' || (command_complete.is_some() && tag != b'N') {
                        return Err("terminal unexpected backend frame around original ACK".into());
                    }
                }
                down_write
                    .write_u8(tag)
                    .await
                    .map_err(|_| "terminal backend tag write")?;
                down_write
                    .write_u32(bytes.len() as u32 + 4)
                    .await
                    .map_err(|_| "terminal backend length write")?;
                down_write
                    .write_all(&bytes)
                    .await
                    .map_err(|_| "terminal backend body write")?;
            }
            Ok::<(), String>(())
        };
        tokio::select! { result = client => result, result = server => result }
    }
    async fn terminal_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Option<(u8, Vec<u8>)>, String> {
        let tag = match reader.read_u8().await {
            Ok(tag) => tag,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => return Err("terminal frame tag IO".into()),
        };
        let len = reader
            .read_u32()
            .await
            .map_err(|_| "terminal partial frame length")?;
        if !(4..=8 * 1024 * 1024).contains(&len) {
            return Err("terminal frame bound".into());
        }
        let mut bytes = vec![0; len as usize - 4];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "terminal partial frame body")?;
        Ok(Some((tag, bytes)))
    }
}

#[path = "gateway_enrollment_tests.rs"]
mod enrollment;
