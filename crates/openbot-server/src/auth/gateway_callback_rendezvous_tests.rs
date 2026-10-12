//! Owned callback TCP, real Server Host, and independent PostgreSQL/TLS fixtures.
use super::*;
use fixture::{Fixture, PgTerminalAckGate, TerminalStage, harness};
use openbot_infra::{
    CallbackErrorKind, CallbackStage, GatewayAuthorizationCallbackError,
    GatewayAuthorizationCallbackWaitOwner,
    GatewayAuthorizationCancellationToken as CancellationToken, GatewayAuthorizationJournal,
    GatewayAuthorizationJournalAck as Ack, GatewayAuthorizationJournalRuntimeOwner,
    GatewayAuthorizationVerifiedCodeOwner,
};
use serde_json::{Value, json};
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
        format!("state={}&code={code}", &*self.state)
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
async fn start(
    f: &Fixture,
) -> Result<
    (
        AuthContext,
        GatewayAuthorizationCallbackWaitOwner,
        CallbackInput,
    ),
    String,
> {
    let sink = GatewayCallbackUrlSink::new();
    f.resolver
        .install_gateway_callback_url_sink(Arc::clone(&sink))
        .map_err(|e| format!("{e:?}"))?;
    let auth = f.auth().await?;
    let (owner, input) = start_on(
        f,
        &f.journal,
        &auth,
        &sink,
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(60),
    )
    .await?;
    Ok((auth, owner, input))
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
async fn finish_code_ack<F: Future<Output = CallbackResult>>(
    call: &mut Pin<Box<F>>,
    input: &CallbackInput,
    code: &str,
    relay: &PgTerminalAckGate,
) -> Result<GatewayAuthorizationVerifiedCodeOwner, String> {
    let bytes = input.request(&input.query(code));
    let mut peer = Box::pin(exchange(input.port, &bytes));
    tokio::select! { biased;
        () = relay.held() => {},
        value = &mut *call => return Err(format!("callback completed before original RO ACK: {value:?}")),
        value = &mut peer => return Err(format!("peer completed before original RO ACK: {value:?}")),
    }
    relay.release_original_ack().await;
    let (owner, raw) = tokio::join!(call, peer);
    response(&raw?, 200, b"Callback received.")?;
    relay.assert_target(1);
    relay.end_callback_sql_window(1);
    owner.map_err(|e| e.to_string())
}
async fn probe<F: Future<Output = CallbackResult>>(
    call: &mut Pin<Box<F>>,
    input: &CallbackInput,
    raw: &[u8],
    status: u16,
) -> Result<(), String> {
    let peer = exchange(input.port, raw);
    tokio::pin!(peer);
    let bytes = tokio::select! {
        value = &mut peer => value?,
        value = &mut *call => return Err(format!("nonterminal probe consumed whole callback: {value:?}")),
    };
    response(&bytes, status, b"")
}
async fn prebuffered_probe<F: Future<Output = CallbackResult>>(
    call: &mut Pin<Box<F>>,
    input: &CallbackInput,
    raw: &[u8],
) -> Result<(), String> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port))
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(raw).await.map_err(|e| e.to_string())?;
    // Write the entire finite request before repolling the same callback owner.
    // A resulting 400 is an actual observation; no future unread-byte claim.
    let peer = async {
        let mut response_bytes = Vec::with_capacity(512);
        (&mut stream)
            .take(4097)
            .read_to_end(&mut response_bytes)
            .await
            .map_err(|e| e.to_string())?;
        check(response_bytes.len() <= 4096, "finite owned probe reply")?;
        Ok::<_, String>(response_bytes)
    };
    tokio::pin!(peer);
    let bytes = tokio::time::timeout(Duration::from_secs(12), async {
        tokio::select! {
            value = &mut peer => value,
            value = &mut *call => Err(format!("framing probe consumed callback owner: {value:?}")),
        }
    })
    .await
    .map_err(|_| "owned prebuffered probe timeout")??;
    response(&bytes, 400, b"")
}
async fn absent(port: u16) -> Result<(), String> {
    for _ in 0..50 {
        match TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(()),
            Err(error) => return Err(format!("owned listener absence unproven: {error}")),
            Ok(stream) => drop(stream),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("owned listener still accepts connections at finite tail".into())
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r01_listener_before_any_create() {
    let admin = harness::admin_config("callback-r01");
    harness::with_temp_database(&admin, "cb_r01", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (_auth, wait, input) = start(&f).await?;
        let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port))
            .await
            .map_err(|e| e.to_string())?;
        check(
            stream.peer_addr().map_err(|e| e.to_string())?.port() == input.port,
            "positive original nonzero IPv4 listener",
        )?;
        drop(stream);
        drop(wait);
        absent(input.port).await?;
        f.finish().await
    })
    .await;
    harness::with_temp_database(&admin, "cb_r01_bind_refusal", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = match Fixture::new(relay.config.clone(), 1).await {
            Ok(f) => f,
            Err(error) => {
                relay.stop().await;
                return Err(error);
            }
        };
        let parent = CancellationToken::new();
        // This original cap covers all negative controls and the direct product
        // call. The private launcher changes only this exact r01 child's limit.
        let deadline = Instant::now() + Duration::from_secs(60);
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let sink = GatewayCallbackUrlSink::new();
            f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
            let auth = f.auth().await?;
            auth.request_binding().ok_or("r01 genuine Host binding absent")?
                .verify_current_before(&auth, deadline).await.map_err(|e| format!("r01 genuine current-positive control: {e:?}"))?;
            let metadata = f.metadata(parent.clone()).await?;
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let rows_before = f.rows().await?;
            let audits_before = f.audits().await?;
            let network_before = f.network_point()?;
            let posts_before = f.posts()?;
            check(rows_before.is_empty() && audits_before.is_empty() && posts_before.is_empty()
                && sink.take_url().is_err(), "separate owned negative fixture has no attempts/audits/registration POST/URL before controls")?;
            // arm's own backend query and every real auth/metadata/TLS/pool
            // control precede this callback-only SQL measurement window.
            relay.arm_original(&f).await;
            check(!parent.is_cancelled() && Instant::now() < deadline, "original negative parent/cap remains current before FD controls")?;
            let sentinel_path = std::env::temp_dir().join(format!("wrokbot-owned-callback-r01-sentinel-{}", std::process::id()));
            let sentinel = std::fs::OpenOptions::new().read(true).write(true).create_new(true)
                .open(&sentinel_path).map_err(|e| format!("owned r01 sentinel create_new: {e}"))?;
            // Unlink only our successfully create_new'd file while retaining
            // its owned File. Every exit then releases its last handles by Drop.
            std::fs::remove_file(&sentinel_path).map_err(|e| format!("owned r01 sentinel unlink: {e}"))?;
            let mut fillers = Vec::with_capacity(512);
            let mut exhaustion_errno = None;
            for _ in 0..512 {
                match sentinel.try_clone() {
                    Ok(file) => fillers.push(file),
                    Err(error) => {
                        exhaustion_errno = error.raw_os_error();
                        break;
                    }
                }
            }
            check(exhaustion_errno == Some(24), "bounded owned try_clone must reach original EMFILE24; another errno or no refusal earns no credit")?;
            let held_fillers = fillers.len();
            let control_errno = match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
                Ok(listener) => {
                    drop(listener);
                    None
                }
                Err(error) => error.raw_os_error(),
            };
            check(control_errno == Some(24), "real direct IPv4 ephemeral listener control must fail with original EMFILE24 while own fillers stay held")?;
            check(!parent.is_cancelled() && Instant::now() < deadline, "same original negative parent/cap before direct product bind")?;
            // Do not call start()/start_on(): all genuine inputs are already
            // prepared. Both control and original product retain all fillers.
            let original = f.journal.start_callback(&auth, metadata, parent.clone(), deadline, &factory).await;
            drop(fillers);
            drop(sentinel);
            let error = match original {
                Ok(wait) => {
                    drop(wait);
                    return Err("original callback unexpectedly returned Wait under actual owned FD exhaustion".into());
                }
                Err(error) => error,
            };
            check(error.stage() == CallbackStage::Create
                && error.kind() == CallbackErrorKind::Journal(JournalKind::Unavailable)
                && error.registration_error().is_none()
                && error.callback_readback_ack() == Ack::NotAttempted,
                "exact original bind refusal Create/Journal(Unavailable), no registration or callback RO ACK")?;
            let journal_error = error.journal_error().ok_or("original bind refusal journal error reference absent")?;
            check(journal_error.kind() == JournalKind::Unavailable
                && journal_error.write_ack() == Ack::NotAttempted
                && journal_error.readback_ack() == Ack::NotAttempted,
                "original bind refusal preserves independent NotAttempted journal write/readback facts")?;
            relay.assert_idle();
            relay.end_callback_sql_window(0);
            check(f.rows().await? == rows_before && f.audits().await? == audits_before
                && f.network_point()? == network_before && f.posts()? == posts_before
                && sink.take_url().is_err(),
                "bind refusal precedes every create/row/reservation/audit/QPE/BEGIN/registration POST/URL; whole owned baseline unchanged")?;
            eprintln!("CALLBACK_BIND_REFUSAL owned_filler_handles={held_fillers} bound=512 actual_try_clone_errno=24 actual_direct_IPv4_bind_errno=24 fillers_held_through_original_product=true original_stage=Create original_kind=Journal_Unavailable journal_write_ACK=NotAttempted journal_readback_ACK=NotAttempted callback_RO_ACK=NotAttempted callback_QPE=0 callback_BEGIN=0 create_row_audit_reservation_delta=0 registration_POST_delta=0 URL=none Wait=none Verified=none; other_J55_debts_not_claimed=true");
            Ok::<(), String>(())
        }).await.map_err(|_| "same original r01 caller cap ended; owned FD resources dropped, bind refusal unproven".to_owned()).and_then(|result| result);
        // Failure also releases all inner owned Files before original fixture
        // and relay tails. Preserve both product/control and cleanup failures.
        let cleanup = f.finish().await;
        relay.stop().await;
        match (result, cleanup) {
            (Err(error), Err(tail)) => Err(format!("{error}; original owned fixture cleanup: {tail}")),
            (Err(error), _) => Err(error),
            (Ok(()), tail) => tail,
        }
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r02_session_whole_registered_handoff() {
    let admin = harness::admin_config("callback-r02");
    harness::with_temp_database(&admin, "cb_r02", |cfg| async move {
        let relay =
            PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        let original = f.rows().await?.remove(0);
        relay.arm_original(&f).await;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        let verified = finish_code_ack(&mut call, &input, "owned-session-code", &relay).await?;
        check(
            f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
            "same original twenty facts/reservation; no callback write or resend",
        )?;
        drop(verified);
        drop(call);
        absent(input.port).await?;
        f.finish().await?;
        relay.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r03_singleuser_whole_registered_handoff() {
    let admin = harness::admin_config("callback-r03");
    harness::with_temp_database(&admin, "cb_r03", |cfg| async move {
        let relay =
            PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (runtime, journal) = f.fresh_pair()?;
        let single = f.single(&journal).await?;
        let sink = GatewayCallbackUrlSink::new();
        single
            .install_gateway_callback_url_sink(Arc::clone(&sink))
            .map_err(|e| format!("{e:?}"))?;
        let auth = single
            .resolve(
                &http::Request::builder()
                    .uri("/owned-callback")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())?;
        let (wait, input) = start_on(
            &f,
            &journal,
            &auth,
            &sink,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let original = f.rows().await?.remove(0);
        relay.arm_original(&f).await;
        let mut call = Box::pin(journal.wait_callback(&auth, wait));
        let verified = finish_code_ack(&mut call, &input, "owned-single-user-code", &relay).await?;
        check(
            original.owner_user_id == "dev-local-user"
                && f.row(original.attempt_id).await? == original,
            "genuine original SingleUser and unchanged whole row",
        )?;
        drop(verified);
        drop(call);
        absent(input.port).await?;
        single.close_request_bindings();
        runtime.close();
        f.finish().await?;
        relay.stop().await;
        Ok(())
    })
    .await;
    for (close_original, successor_generation) in [(false, false), (true, false), (false, true)] {
        harness::with_temp_database(&admin, "cb_r03_postowner", |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let parent = CancellationToken::new();
            // This single original cap covers A start and all later B setup,
            // resolve and genuine current controls; no new now+5s verifier.
            let deadline = Instant::now() + Duration::from_secs(60);
            let (runtime_a, journal_a) = f.fresh_pair()?;
            let sink_a = GatewayCallbackUrlSink::new();
            let (single_a, auth_a, wait_a, input) = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let single_a = f.single(&journal_a).await?;
                single_a.install_gateway_callback_url_sink(Arc::clone(&sink_a)).map_err(|e| format!("{e:?}"))?;
                let auth_a = single_a.resolve(&http::Request::builder().uri("/owned-callback").body(()).map_err(|e| e.to_string())?.into_parts().0).await.map_err(|e| e.to_string())?;
                let (wait_a, input) = start_on(&f, &journal_a, &auth_a, &sink_a, parent.clone(), deadline).await?;
                Ok::<_, String>((single_a, auth_a, wait_a, input))
            }).await.map_err(|_| "original caller cap ended during original SingleUser A start")??;
            // Wait_A and its consumed SDK URL exist before the real B owner is
            // constructed. Separate fixtures provide separate by-value Waits.
            let (runtime_b, journal_b, single_b, auth_b) = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                if close_original {
                    single_a.close_request_bindings();
                } else {
                    auth_a.request_binding().ok_or("original SingleUser A binding absent")?
                        .verify_current_before(&auth_a, deadline).await.map_err(|e| format!("original A current control: {e:?}"))?;
                }
                if successor_generation {
                    // A and its by-value Wait already came from the genuine
                    // canonical generation7 principal. Advance only this owned
                    // test user, outside the callback SQL measurement window.
                    check(auth_a.auth_generation().get() == 7, "original SingleUser A genuinely holds canonical generation7")?;
                    let control = f.pool.get().await.map_err(|e| e.to_string())?;
                    let changed = control.execute(
                        "UPDATE public.users SET auth_generation=8 WHERE id=$1 AND email=$2 AND auth_generation=7",
                        &[&openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID,
                          &openbot_infra::auth::single_user::SINGLE_USER_EMAIL],
                    ).await.map_err(|e| e.to_string())?;
                    check(changed == 1, "one owned canonical SingleUser generation7 to generation8 update")?;
                    drop(control);
                }
                // The normal issuer OnceLock belongs to each own journal. B
                // never replaces A's issuer, runtime, journal or original Wait.
                let (runtime_b, journal_b) = f.fresh_pair()?;
                let single_b = f.single(&journal_b).await?;
                let auth_b = single_b.resolve(&http::Request::builder().uri("/owned-callback").body(()).map_err(|e| e.to_string())?.into_parts().0).await.map_err(|e| e.to_string())?;
                auth_b.request_binding().ok_or("posterior SingleUser B binding absent")?
                    .verify_current_before(&auth_b, deadline).await.map_err(|e| format!("genuine posterior B current control: {e:?}"))?;
                if successor_generation {
                    check(auth_a.auth_generation().get() == 7 && auth_b.auth_generation().get() == 8
                        && auth_a.actor() == auth_b.actor(),
                        "original generation7 A and real canonical generation8 B; original A snapshot never upgraded")?;
                }
                Ok::<_, String>((runtime_b, journal_b, single_b, auth_b))
            }).await.map_err(|_| "same original caller cap ended during posterior B setup/current control")??;
            check(Instant::now() < deadline, "genuine posterior B control completed inside original caller cap")?;
            let original = f.rows().await?.remove(0);
            let audits_before = f.audits().await?;
            let network_before = f.network_point()?;
            check(original.owner_user_id == "dev-local-user" && f.posts()?.len() == 1
                && sink_a.take_url().is_err(), "same original SingleUser row and exactly one already consumed SDK URL/POST")?;
            // All A/B setup and canonical current-control SQL is outside this
            // callback-only measurement window, including arm's own PID query.
            relay.arm_original(&f).await;
            check(Instant::now() < deadline, "original A Wait refusal starts inside the same original caller cap")?;
            let error = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), journal_a.wait_callback(&auth_b, wait_a))
                .await.map_err(|_| "same original caller cap ended during original A Wait refusal")?
                .err().ok_or("posterior SingleUser B inherited original A Wait as Verified")?;
            callback_refusal(&error, CallbackErrorKind::Refused, Ack::NotAttempted)?;
            let current_error = error.journal_error().ok_or("original A/B full-binding refusal reference missing")?;
            check(current_error.kind() == JournalKind::Refused
                && current_error.write_ack() == Ack::NotAttempted && current_error.readback_ack() == Ack::NotAttempted
                && error.registration_error().is_none(), "fresh exact original binding refusal has no journal or registration ACK")?;
            relay.assert_idle();
            relay.end_callback_sql_window(0);
            absent(input.port).await?;
            check(f.row(original.attempt_id).await? == original && f.audits().await? == audits_before
                && f.network_point()? == network_before && f.posts()?.len() == 1 && sink_a.take_url().is_err(),
                "posterior-owner refusal preserves full20/audit/reservation and one consumed URL/POST; no callback dispatch or ControlledClose")?;
            eprintln!("CALLBACK_SINGLEUSER_POSTERIOR_OWNER original_A_closed={close_original} B_created_after_original_Wait=true genuine_B_current_before_original_cap=true callback_RO_ACK=NotAttempted callback_SQL=0 no_Verified=true; future_clock_issued_lease=UNPROVEN finite_owned_listener_absence_only=true");
            if successor_generation {
                eprintln!("CALLBACK_SINGLEUSER_SUCCESSOR_GENERATION original_A_auth_generation=7 actual_B_auth_generation=8 original_Wait_A_preserved=true genuine_B_current_before_same_original_cap=true callback_FreshSomeRefused=true callback_RO_ACK=NotAttempted journal_write_ACK=NotAttempted journal_readback_ACK=NotAttempted callback_SQL=0 no_Verified=true; future_wall_clock_issuance=NOT_CLAIMED finite_owned_listener_absence_only=true");
            }
            single_b.close_request_bindings(); runtime_b.close();
            single_a.close_request_bindings(); runtime_a.close();
            drop(auth_b); drop(journal_b); drop(auth_a); drop(journal_a);
            f.finish().await?; relay.stop().await; Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r04_sdk_pkce_url_and_original_echo() {
    let admin = harness::admin_config("callback-r04");
    harness::with_temp_database(&admin, "cb_r04", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let boundary = GatewayCallbackUrlSink::new();
        let oversized = "x".repeat(2049);
        check(boundary.accept_url(&oversized).is_err() && boundary.take_url().is_err(), "2049-byte sink refusal, no truncated or second offer")?;
        let exact = "x".repeat(2048);
        boundary.accept_url(&exact).map_err(|e| format!("{e:?}"))?;
        check(*boundary.take_url().map_err(|e| format!("{e:?}"))? == exact && boundary.take_url().is_err()
            && boundary.accept_url("again").is_err(), "exact bounded sink take once and permanent offer consumption")?;
        let (_auth, wait, input) = start(&f).await?;
        let parsed = url::Url::parse(&input.url).map_err(|e| e.to_string())?;
        check(parsed.as_str().starts_with(&format!("{}/oauth/desktop/authorize?", f.issuer())) && parsed.fragment().is_none(), "original metadata authorization endpoint")?;
        eprintln!("CALLBACK_PKCE reachable state/challenge/URL bounds observed; verifier and independent S256 math belong to Infra pure p06; malformed metadata remains old-reader credit; OS browser consumption UNPROVEN");
        drop(wait); absent(input.port).await?; f.finish().await
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r05_state_probes_never_terminate() {
    let admin = harness::admin_config("callback-r05");
    harness::with_temp_database(&admin, "cb_r05", |cfg| async move {
        let relay =
            PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        let original = f.rows().await?.remove(0);
        relay.arm_original(&f).await;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        for query in [
            "code=x".to_owned(),
            format!("state={}&code=x", "A".repeat(43)),
            "state=%GG&code=x".to_owned(),
            format!("state={}&error=access_denied", "B".repeat(43)),
        ] {
            probe(&mut call, &input, &input.request(&query), 400).await?;
            relay.assert_idle();
        }
        let owner = finish_code_ack(
            &mut call,
            &input,
            "same-original-state-after-probes",
            &relay,
        )
        .await?;
        check(
            f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
            "probes did not close row, renew epoch, reserve again, or resend",
        )?;
        drop(owner);
        drop(call);
        f.finish().await?;
        relay.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r06_query_reject_then_success() {
    let admin = harness::admin_config("callback-r06");
    harness::with_temp_database(&admin, "cb_r06", |cfg| async move {
        let relay =
            PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        relay.arm_original(&f).await;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        let base = format!("state={}", &*input.state);
        for query in [
            format!("{base}&st%61te={}&code=x", &*input.state),
            format!("{base}&x=unknown&code=x"),
            format!("{base}&code=%GG"),
            format!("{base}&code=x&error=other"),
            format!("{base}&error=other&error_description=%C2%80"),
        ] {
            probe(&mut call, &input, &input.request(&query), 400).await?;
            relay.assert_idle();
        }
        drop(finish_code_ack(&mut call, &input, "original-flow-still-valid", &relay).await?);
        drop(call);
        check(f.posts()?.len() == 1, "no second registration").and(f.finish().await)?;
        relay.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r07_http_host_and_framing_reject() {
    let admin = harness::admin_config("callback-r07");
    harness::with_temp_database(&admin, "cb_r07", |cfg| async move {
        let relay =
            PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        relay.arm_original(&f).await;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        let normal = String::from_utf8(input.request(&input.query("owned-code"))).unwrap();
        let host = format!("Host: 127.0.0.1:{}\r\n", input.port);
        let mut requests = vec![
            normal.replace(&host, "Host: localhost:1\r\n").into_bytes(),
            normal.replace(&host, &format!("{host}{host}")).into_bytes(),
            normal
                .replace("\r\n\r\n", "\r\nTransfer-Encoding: identity\r\n\r\n")
                .into_bytes(),
            normal
                .replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n")
                .into_bytes(),
            normal
                .replace(
                    "\r\n\r\n",
                    "\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                )
                .into_bytes(),
            normal
                .replace("\r\n\r\n", "\r\n X: fold\r\n\r\n")
                .into_bytes(),
            normal.replace("\r\n\r\n", "\r\nX: bare\n\r\n").into_bytes(),
            normal
                .replace("\r\n\r\n", &format!("\r\nX:{}\r\n\r\n", "a".repeat(8189)))
                .into_bytes(),
        ];
        let mut obs_text = normal.replace("\r\n\r\n", "\r\nX: ").into_bytes();
        obs_text.extend_from_slice(b"\xff\r\n\r\n");
        requests.push(obs_text);
        let mut body = normal.as_bytes().to_vec();
        body.extend_from_slice(b"buffered-body");
        requests.push(body);
        let mut pipeline = normal.as_bytes().to_vec();
        pipeline.extend_from_slice(normal.as_bytes());
        requests.push(pipeline);
        for raw in requests {
            prebuffered_probe(&mut call, &input, &raw).await?;
            relay.assert_idle();
        }
        drop(finish_code_ack(&mut call, &input, "original-after-http-probes", &relay).await?);
        drop(call);
        f.finish().await?;
        relay.stop().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r08_max_code_percent_expansion() {
    let admin = harness::admin_config("callback-r08");
    // These literal byte counts/expansions precede setup and any actual parser.
    let max_code = "%41".repeat(16_377);
    let too_long = "%41".repeat(16_378);
    assert_eq!(max_code.len(), 49_131);
    assert_eq!(too_long.len(), 49_134);
    harness::with_temp_database(&admin, "cb_r08", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?; relay.arm_original(&f).await;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        let rejected_request = input.request(&input.query(&too_long));
        check(rejected_request.len() <= 65_536, "decoded oversize fits raw head")?;
        probe(&mut call, &input, &rejected_request, 400).await?; relay.assert_idle();
        check(input.request(&input.query(&max_code)).len() <= 65_536, "49131 encoded code plus full frame fits head")?;
        drop(finish_code_ack(&mut call, &input, &max_code, &relay).await?);
        eprintln!("CALLBACK_MAX_CODE opaque Verified plus genuine original RO ACK; exact decoded bytes belong to independent Infra p02");
        drop(call); f.finish().await?; relay.stop().await; Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r09_matched_error_static_and_no_close() {
    let admin = harness::admin_config("callback-r09");
    for (vendor, expected) in [
        ("access_denied", CallbackErrorKind::AuthorizationDenied),
        ("other", CallbackErrorKind::AuthorizationRejected),
    ] {
        harness::with_temp_database(&admin, "cb_r09", |cfg| async move {
            let relay =
                PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false)
                    .await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let (auth, wait, input) = start(&f).await?;
            let original = f.rows().await?.remove(0);
            // Callback-only window begins after registration AND whole URL handoff.
            relay.arm_original(&f).await;
            let bytes = input.request(&format!(
                "state={}&error={vendor}&error_description=vendor-detail",
                &*input.state
            ));
            let (owner, raw) = tokio::join!(
                f.journal.wait_callback(&auth, wait),
                exchange(input.port, &bytes)
            );
            let error = owner.err().ok_or("matched denial returned Verified")?;
            check(
                error.stage() == CallbackStage::Callback
                    && error.kind() == expected
                    && error.callback_readback_ack() == Ack::NotAttempted
                    && error.journal_error().is_none()
                    && error.registration_error().is_none(),
                "independent typed callback denial with no inherited ACK",
            )?;
            response(&raw?, 200, b"Authorization was not completed.")?;
            relay.assert_idle();
            relay.end_callback_sql_window(0); // Subsequent row reads are outside this window.
            absent(input.port).await?;
            check(
                f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                "registered facts preserved; no ControlledClose or resend",
            )?;
            f.finish().await?;
            relay.stop().await;
            Ok(())
        })
        .await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r11_original_parent_cancel_and_caller_cap() {
    let admin = harness::admin_config("callback-r11");
    for expires in [false, true] {
        for partial in [false, true] {
            harness::with_temp_database(&admin, "cb_r11", |cfg| async move {
                let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
                let f = Fixture::new(relay.config.clone(), 1).await?;
                let sink = GatewayCallbackUrlSink::new();
                f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
                let auth = f.auth().await?;
                let parent = CancellationToken::new();
                // The same original cap is supplied once before metadata/start;
                // neither setup nor the later callback renews it.
                let deadline = Instant::now() + Duration::from_secs(if expires { 8 } else { 60 });
                let (wait, input) = start_on(&f, &f.journal, &auth, &sink, parent.clone(), deadline).await?;
                let original = f.rows().await?.remove(0);
                relay.arm_original(&f).await;
                let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
                let mut peer = if partial {
                    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
                    stream.write_all(b"GET /callback?").await.map_err(|e| e.to_string())?;
                    Some(stream)
                } else { None };
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                    value = &mut call => return Err(format!("owned pending accept/read ended before original refusal: {value:?}")),
                }
                if !expires { parent.cancel(); }
                let remaining = deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(2);
                let error = tokio::time::timeout(remaining, &mut call).await.map_err(|_| "callback ignored original parent/cap")?
                    .err().ok_or("cancelled/expired original flow returned Verified")?;
                let expected = if expires { CallbackErrorKind::Deadline } else { CallbackErrorKind::Cancelled };
                check(error.stage() == CallbackStage::Callback && error.kind() == expected
                    && error.callback_readback_ack() == Ack::NotAttempted
                    && error.registration_error().is_none(), "typed original cancel/deadline; no inherited callback ACK")?;
                if expires { check(Instant::now() >= deadline, "the originally supplied absolute caller cap elapsed")?; }
                else { check(parent.is_cancelled() && Instant::now() < deadline, "same original parent cancelled within same cap")?; }
                relay.assert_idle();
                drop(call);
                if let Some(mut stream) = peer.take() {
                    let mut byte = [0_u8; 1];
                    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await.map_err(|_| "owned partial peer remained live after refusal")?;
                    check(matches!(read, Ok(0)) || read.as_ref().is_err_and(|e| matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)), "owned partial peer finite EOF/reset after refusal")?;
                    drop(stream);
                }
                absent(input.port).await?;
                relay.end_callback_sql_window(0);
                check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                    "original registered row/reservation retained; no ControlledClose or registration retry")?;
                eprintln!("CALLBACK_ORIGINAL_REFUSAL expires={expires} partial_read={partial} callback_RO_not_attempted=true; accept/read Pending only; actual write controlled-Pending branches separately measured below; exact flush/shutdown cancellation interleavings UNPROVEN");
                f.finish().await?; relay.stop().await; Ok(())
            }).await;
        }
    }
    for expires in [false, true] {
        harness::with_temp_database(&admin, "cb_r11_write", |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let sink = GatewayCallbackUrlSink::new();
            f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
            let auth = f.auth().await?;
            let parent = CancellationToken::new();
            // One original caller cap, supplied before metadata/setup/start.
            let deadline = Instant::now() + Duration::from_secs(if expires { 8 } else { 60 });
            let (wait, input) = start_on(&f, &f.journal, &auth, &sink, parent.clone(), deadline).await?;
            let original = f.rows().await?.remove(0);
            relay.arm_original(&f).await;
            let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
            let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
            let request = input.request(&input.query("same-original-write-pending-code"));
            peer.write_all(&request).await.map_err(|e| e.to_string())?;
            tokio::select! { biased;
                () = relay.held() => {},
                value = &mut call => return Err(format!("write-boundary callback ended before original RO ACK: {value:?}")),
            }
            // This yields the real driver while business stays unpolled; it is
            // not by itself proof that the original RO ACK reached its owner.
            relay.release_original_ack().await;
            // Exactly one original business poll. No second poll is allowed to
            // repair a driver-not-ready or partial-write boundary observation.
            match std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await {
                std::task::Poll::Pending => {},
                std::task::Poll::Ready(value) => return Err(format!("original write boundary not Pending: {value:?}")),
            }
            // Keep business unpolled. The independent own peer reads a bounded
            // handwritten complete static200, without waiting for EOF/shutdown.
            // Only these actual bytes establish successful write->Pending.
            let raw = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let mut raw = Vec::with_capacity(4096);
                loop {
                    check(raw.len() < 4096, "write-boundary static header bound")?;
                    let mut byte = [0_u8; 1];
                    peer.read_exact(&mut byte).await.map_err(|e| format!("write-boundary own header: {e}"))?;
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") { break; }
                }
                let mut body = [0_u8; 18]; // Literal Callback received. byte count.
                peer.read_exact(&mut body).await.map_err(|e| format!("write-boundary own literal body: {e}"))?;
                raw.extend_from_slice(&body);
                response(&raw, 200, b"Callback received.")?;
                Ok::<_, String>(raw)
            }).await.map_err(|_| "one original poll did not establish full write boundary before original cap")??;
            check(!raw.is_empty(), "actual independent write-boundary bytes")?;
            if expires {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                check(Instant::now() >= deadline, "same originally supplied caller cap elapsed at write Pending")?;
            } else {
                check(Instant::now() < deadline, "same parent cancellation remains within original caller cap")?;
                parent.cancel();
            }
            // A single post-refusal poll must terminate the same original owner.
            // Pending is a real failure, not a reason to create another budget.
            let error = match std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await {
                std::task::Poll::Ready(Err(error)) => error,
                std::task::Poll::Ready(Ok(_)) => return Err("write-Pending cancelled/expired original returned Verified".into()),
                std::task::Poll::Pending => return Err("write-Pending original refusal stayed Pending".into()),
            };
            let expected = if expires { CallbackErrorKind::Deadline } else { CallbackErrorKind::Cancelled };
            callback_refusal(&error, expected, Ack::Timely)?;
            drop(call);
            no_callback_reply(&mut peer).await?; // The complete literal response was already consumed.
            drop(peer);
            absent(input.port).await?;
            relay.assert_target(1);
            relay.end_callback_sql_window(1);
            check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                "write-Pending refusal retains original full row/reservation; no retry or ControlledClose")?;
            eprintln!("CALLBACK_ORIGINAL_WRITE_PENDING_REFUSAL expires={expires} original_RO_ACK=Timely independent_literal_static200=true business_poll_once=true final_refusal_poll_once=true; exact flush/shutdown cancellation interleavings UNPROVEN");
            f.finish().await?; relay.stop().await; Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r12_callback_after_completed_registration10s() {
    let admin = harness::admin_config("callback-r12");
    harness::with_temp_database(&admin, "cb_r12", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let (auth, wait, input) = start(&f).await?;
        let completed = Instant::now();
        let original = f.rows().await?.remove(0);
        tokio::time::sleep(Duration::from_millis(10_200)).await;
        check(completed.elapsed() > Duration::from_secs(10), "real time after that same registration completion")?;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        drop(finish_code(&mut call, &input, "same-flow-after-completed-stage", ).await?);
        check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1, "same full row, cap and reservation, no registration reuse or renewal")?;
        eprintln!("CALLBACK_COMPLETED_REGISTRATION elapsed_millis={} old completed-stage rejection belongs to pure p05 and unchanged-source CODE", completed.elapsed().as_millis());
        drop(call); f.finish().await
    }).await;
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r13_future_and_owner_drop_close_ports() {
    let admin = harness::admin_config("callback-r13");
    // Four lifecycle branches remain one unique registered r13 function.
    for branch in 0u8..4 {
        harness::with_temp_database(&admin, "cb_r13", |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let (auth, wait, input) = start(&f).await?;
            let original = f.rows().await?.remove(0);
            relay.arm_original(&f).await;
            match branch {
                0 => drop(wait),
                1 => {
                    // Construct and drop the exact consuming future without polling it.
                    let call = f.journal.wait_callback(&auth, wait);
                    drop(call);
                }
                2 => {
                    let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
                    let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
                    peer.write_all(b"GET /callback?").await.map_err(|e| e.to_string())?;
                    tokio::select! { _ = tokio::time::sleep(Duration::from_millis(50)) => {}, value = &mut call => return Err(format!("partial callback unexpectedly completed: {value:?}")) }
                    drop(call);
                    let mut tail = [0; 1];
                    let read = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut tail)).await.map_err(|_| "owned partial stream still live after Drop")?;
                    check(matches!(read, Ok(0)) || read.as_ref().is_err_and(|e| matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)), "owned partial stream finite EOF/reset after Drop")?;
                    drop(peer);
                }
                3 => {
                    let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
                    let verified = finish_code_ack(&mut call, &input, "same-original-verified-drop", &relay).await?;
                    drop(verified);
                    drop(call);
                }
                _ => unreachable!(),
            }
            if branch != 3 {
                relay.assert_idle();
                relay.end_callback_sql_window(0);
            }
            absent(input.port).await?;
            check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                "Drop preserves original full row/reservation; no SQL terminal close or registration resend")?;
            eprintln!("CALLBACK_DROP branch={branch} finite local listener/stream observation; genuine Verified branch original RO Timely separately measured; asynchronous production-driver joins and complete allocator erasure UNPROVEN");
            f.finish().await?; relay.stop().await; Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r14_foreign_oldruntime_and_duplicate_offer() {
    let admin = harness::admin_config("callback-r14");
    harness::with_temp_database(&admin, "cb_r14_none", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let parent = CancellationToken::new();
        let metadata = f.metadata(parent.clone()).await?;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let value = f
            .journal
            .start_callback(
                &auth,
                metadata,
                parent,
                Instant::now() + Duration::from_secs(60),
                &factory,
            )
            .await;
        let error = value.err().ok_or("missing sink returned callback owner")?;
        check(
            error.stage() == CallbackStage::Callback
                && error.kind() == CallbackErrorKind::Unavailable
                && error.callback_readback_ack() == Ack::NotAttempted,
            "missing sink refused only at callback handoff",
        )?;
        check(
            f.rows().await?.len() == 1
                && f.rows().await?[0].phase == "registered"
                && f.posts()?.len() == 1,
            "old admission/registration preserved despite default no port destination",
        )?;
        f.finish().await
    })
    .await;
    harness::with_temp_database(&admin, "cb_r14_once", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let sink = GatewayCallbackUrlSink::new();
        f.resolver
            .install_gateway_callback_url_sink(Arc::clone(&sink))
            .map_err(|e| format!("{e:?}"))?;
        check(
            f.resolver
                .install_gateway_callback_url_sink(GatewayCallbackUrlSink::new())
                .is_err(),
            "fixed slot cannot install twice",
        )?;
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
        check(
            sink.take_url().is_err() && sink.accept_url(&input.url).is_err(),
            "one whole take and permanent once offer",
        )?;
        let original = f.rows().await?.remove(0);
        let network_before = f.network_point()?;
        let (_foreign_runtime, foreign_journal) = f.fresh_pair()?;
        let error = foreign_journal
            .wait_callback(&auth, wait)
            .await
            .err()
            .ok_or("foreign journal returned Verified")?;
        check(
            error.stage() == CallbackStage::Callback
                && error.kind() == CallbackErrorKind::Refused
                && error.callback_readback_ack() == Ack::NotAttempted,
            "foreign original issuer refused, no callback readback grant",
        )?;
        absent(input.port).await?;
        check(
            f.row(original.attempt_id).await? == original && f.network_point()? == network_before,
            "foreign journal refusal preserves original full20 and network counts",
        )?;
        f.finish().await
    })
    .await;
    harness::with_temp_database(&admin, "cb_r14_old", |cfg| async move {
        let mut f = Fixture::new(cfg, 2).await?;
        let (auth, wait, input) = start(&f).await?;
        let original = f.rows().await?.remove(0);
        let network_before = f.network_point()?;
        drop(f.runtime.take());
        let error = f
            .journal
            .wait_callback(&auth, wait)
            .await
            .err()
            .ok_or("old runtime returned Verified")?;
        check(
            error.stage() == CallbackStage::Callback
                && error.kind() == CallbackErrorKind::Unavailable
                && error.callback_readback_ack() == Ack::NotAttempted,
            "old weak runtime unavailable, no callback readback",
        )?;
        absent(input.port).await?;
        check(
            f.row(original.attempt_id).await? == original && f.network_point()? == network_before,
            "old weak runtime refusal preserves original full20 and network counts",
        )?;
        f.finish().await
    })
    .await;
}

use openbot_infra::GatewayAuthorizationJournalErrorKind as JournalKind;

async fn no_callback_reply(peer: &mut TcpStream) -> Result<(), String> {
    let mut raw = Vec::with_capacity(512);
    match tokio::time::timeout(
        Duration::from_secs(2),
        (&mut *peer).take(4097).read_to_end(&mut raw),
    )
    .await
    {
        Ok(Ok(_)) => check(
            raw.is_empty(),
            "no callback success/error response after RO refusal",
        ),
        Ok(Err(e))
            if raw.is_empty()
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
        {
            Ok(())
        }
        Ok(Err(e)) => Err(format!("owned callback tail: {e}")),
        Err(_) => Err("owned callback stream remained open after refusal".into()),
    }
}
fn callback_refusal(
    error: &GatewayAuthorizationCallbackError,
    kind: CallbackErrorKind,
    ack: Ack,
) -> Result<(), String> {
    check(
        error.stage() == CallbackStage::Callback
            && error.kind() == kind
            && error.callback_readback_ack() == ack
            && error.registration_error().is_none(),
        "exact typed callback kind/stage/independent RO ACK",
    )
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r15_callback_ro_row_actor_session_drift() {
    let admin = harness::admin_config("callback-r15");
    for branch in 0u8..4 {
        harness::with_temp_database(&admin, "cb_r15", |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let (auth, wait, input) = start(&f).await?;
            let old = f.rows().await?.remove(0);
            let audit_before = f.audits().await?;
            let mut expected = old.clone();
            // Only this task's synthetic database/known actor/session/row is changed.
            // These durable changes do not close the in-memory Host, so the real RO
            // actor/session or complete row observation is what refuses the owner.
            let direct = f.direct().await?;
            let client = direct.get().await.map_err(|e| e.to_string())?;
            let changed = match branch {
                0 => client.execute("UPDATE public.users SET auth_generation=8 WHERE id=$1 AND auth_generation=7", &[&fixture::ACTOR]).await,
                1 => client.execute("DELETE FROM public.sessions WHERE id='owned-journal-session' AND user_id=$1", &[&fixture::ACTOR]).await,
                2 => {
                    expected.updated_at += time::Duration::microseconds(1);
                    client.execute("UPDATE openbot_internal.gateway_authorization_attempts SET updated_at=updated_at+interval '1 microsecond' WHERE attempt_id=$1", &[&old.attempt_id]).await
                }
                _ => {
                    let replacement = uuid::Uuid::now_v7();
                    expected.enrollment_id = Some(replacement);
                    client.execute("UPDATE openbot_internal.gateway_authorization_attempts SET enrollment_id=$2 WHERE attempt_id=$1", &[&old.attempt_id, &replacement]).await
                }
            }.map_err(|e| e.to_string())?;
            check(changed == 1, "one actual owned actor/session/fullrow mutation")?;
            drop(client);
            check(f.row(old.attempt_id).await? == expected, "independent full20 before callback")?;
            relay.arm_original(&f).await;
            let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
            peer.write_all(&input.request(&input.query("owned-drift-code"))).await.map_err(|e| e.to_string())?;
            let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
            if branch >= 2 {
                tokio::select! { biased;
                    () = relay.held() => {},
                    value = &mut call => return Err(format!("full20 refusal missed original RO ROLLBACK ACK: {value:?}")),
                }
                relay.release_original_ack().await;
            }
            // Actor/session decoding legitimately fails before exact-row SELECT.
            // Do not wait for relay.held() or assert_target(1) in those two cases.
            let (value, tail) = tokio::join!(&mut call, no_callback_reply(&mut peer));
            let error = value.err().ok_or("drift returned a Verified owner")?;
            callback_refusal(&error, CallbackErrorKind::ReadbackUnproven, Ack::Timely)?;
            let original = error.journal_error().ok_or("original RO error missing")?;
            check(original.kind() == if branch < 2 { JournalKind::Refused } else { JournalKind::ReadbackUnproven }
                && original.readback_ack() == Ack::Timely,
                "actual original observation refusal and original rollback ACK")?;
            tail?;
            drop(peer); drop(call);
            if branch >= 2 { relay.assert_target(1); }
            else { relay.assert_before_exact_refusal(); }
            relay.end_callback_sql_window(1);
            check(f.row(old.attempt_id).await? == expected && f.audits().await? == audit_before
                && f.posts()?.len() == 1, "no callback write/audit/new reservation or second POST")?;
            callback_refusal(&error, CallbackErrorKind::ReadbackUnproven, Ack::Timely)?;
            direct.close();
            f.finish().await?;
            relay.stop().await;
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r16_callback_ro_ack_loss_late_tail() {
    let admin = harness::admin_config("callback-r16");
    for discard in [true, false] {
        harness::with_temp_database(&admin, if discard { "cb_r16_loss" } else { "cb_r16_late" }, |cfg| async move {
            let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, discard).await;
            let f = Fixture::new(relay.config.clone(), 1).await?;
            let sink = GatewayCallbackUrlSink::new();
            f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
            let auth = f.auth().await?;
            let deadline = Instant::now() + Duration::from_secs(4);
            let (wait, input) = start_on(&f, &f.journal, &auth, &sink, CancellationToken::new(), deadline).await?;
            let old = f.rows().await?.remove(0);
            let audit_before = f.audits().await?;
            let _original_connection = relay.arm_original(&f).await;
            let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
            peer.write_all(&input.request(&input.query("owned-ack-code"))).await.map_err(|e| e.to_string())?;
            let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
            tokio::select! { biased;
                () = relay.held() => {},
                value = &mut call => return Err(format!("callback missed actual original RO ACK: {value:?}")),
            }
            if !discard {
                // Original ROLLBACK future has already been polled and sent.
                // Leave this same business future unpolled, let the absolute caller
                // cap expire, then deliver the real original C+Z and repoll it.
                // The biased original terminal can preserve the known-late result.
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline + Duration::from_millis(150))).await;
                relay.release_original_ack().await;
            }
            let (value, tail) = tokio::join!(&mut call, no_callback_reply(&mut peer));
            let error = value.err().ok_or("unproven/late RO returned Verified")?;
            let kind = if discard { CallbackErrorKind::ReadbackUnproven } else { CallbackErrorKind::RollbackAcknowledgedAfterDeadline };
            let ack = if discard { Ack::Unknown } else { Ack::Late };
            callback_refusal(&error, kind, ack)?;
            let original = error.journal_error().ok_or("original terminal error missing")?;
            check(original.readback_ack() == ack && original.kind() == if discard { JournalKind::RollbackUnproven } else { JournalKind::RollbackAcknowledgedAfterDeadline }, "original terminal reason retained")?;
            tail?; drop(peer); drop(call);
            relay.assert_target(usize::from(!discard));
            relay.end_callback_sql_window(1);
            // This later row query is separately attributed and cannot upgrade ACK.
            check(f.row(old.attempt_id).await? == old && f.audits().await? == audit_before
                && f.posts()?.len() == 1, "registered original full20 preserved and zero callback write/resend")?;
            callback_refusal(&error, kind, ack)?;
            f.finish().await?; relay.stop().await;
            Ok(())
        }).await;
    }
    harness::with_temp_database(&admin, "cb_r16_response_rst", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        let old = f.rows().await?.remove(0);
        let audit_before = f.audits().await?;
        relay.arm_original(&f).await;
        let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
        peer.write_all(&input.request(&input.query("owned-response-reset"))).await.map_err(|e| e.to_string())?;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        tokio::select! { biased;
            () = relay.held() => {},
            value = &mut call => return Err(format!("response failure missed original RO ACK: {value:?}")),
        }
        // Exact Tokio1.53.1 safe, non-deprecated API. No socket2 direct dependency,
        // unsafe, allow(deprecated), public hook or product timing change.
        // Holding the real RO C+Z proves valid matching bytes were already consumed
        // and prevents a premature response before this peer's abortive close.
        peer.set_zero_linger().map_err(|e| e.to_string())?;
        drop(peer);
        relay.release_original_ack().await; // includes original 80ms driver/OS yield
        let error = (&mut call).await.err().ok_or("RST peer returned Verified")?;
        callback_refusal(&error, CallbackErrorKind::CallbackIo, Ack::Timely)?;
        check(error.journal_error().is_none(), "response IO failure retains known RO ACK independently")?;
        drop(call); relay.assert_target(1);
        relay.end_callback_sql_window(1);
        check(f.row(old.attempt_id).await? == old && f.audits().await? == audit_before
            && f.posts()?.len() == 1, "RST did not write/close/readmit/resend original attempt")?;
        callback_refusal(&error, CallbackErrorKind::CallbackIo, Ack::Timely)?;
        f.finish().await?; relay.stop().await;
        Ok(())
    }).await;
    harness::with_temp_database(&admin, "cb_r16_ro_host_tail", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let (auth, wait, input) = start(&f).await?;
        let old = f.rows().await?.remove(0);
        let audits_before = f.audits().await?;
        relay.arm_original(&f).await;
        let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
        peer.write_all(&input.request(&input.query("owned-ro-host-tail"))).await.map_err(|e| e.to_string())?;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        tokio::select! { biased;
            () = relay.held() => {},
            value = &mut call => return Err(format!("Host tail missed original RO ACK: {value:?}")),
        }
        // Neither of these awaits/pure actions polls the business call.
        // held proves the original rollback was already polled, not a fresh terminal.
        relay.release_original_ack().await;
        f.disarm_host();
        let (value, tail) = tokio::join!(&mut call, no_callback_reply(&mut peer));
        let error = value.err().ok_or("closed original Host returned Verified")?;
        callback_refusal(&error, CallbackErrorKind::ReadbackUnproven, Ack::Timely)?;
        let original = error.journal_error().ok_or("original RO Host-tail refusal missing")?;
        check(original.kind() == JournalKind::Refused && original.readback_ack() == Ack::Timely,
            "original Host current-tail refusal preserves original timely RO rollback")?;
        // original.write_ack()==Timely is only preceding-write historical context.
        // Do not call it a new callback write or parse any Debug string.
        tail?; drop(peer); drop(call);
        relay.assert_target(1);
        relay.end_callback_sql_window(1);
        // Independent later observations are outside the measurement window and
        // cannot replace the original ACK or the already closed measurement window.
        check(f.row(old.attempt_id).await? == old && f.audits().await? == audits_before
            && f.posts()?.len() == 1, "RO tail refusal has no callback write/reservation/resend")?;
        callback_refusal(&error, CallbackErrorKind::ReadbackUnproven, Ack::Timely)?;
        eprintln!("CALLBACK_RO_CURRENT_TAIL original_rollback_ACK=Timely original_host_tail=Refused readback_exact_success_return=false response_stage_not_entered=true; completed_RO_final_response_tail=UNPROVEN");
        f.finish().await?; relay.stop().await;
        Ok(())
    }).await;
    harness::with_temp_database(&admin, "cb_r16_done_ro_host", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let sink = GatewayCallbackUrlSink::new();
        f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
        let auth = f.auth().await?;
        let parent = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        let (wait, input) = start_on(&f, &f.journal, &auth, &sink, parent.clone(), deadline).await?;
        let old = f.rows().await?.remove(0);
        let audits_before = f.audits().await?;
        let posts_before = f.posts()?;
        relay.arm_original(&f).await;
        // Taken once before connect/accept; this conservative observation cap is
        // no later than the original accepted connection's ten-second cap.
        let proof_cap = (Instant::now() + Duration::from_secs(10)).min(deadline);
        let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
        let peer_port = peer.local_addr().map_err(|e| e.to_string())?.port();
        peer.write_all(&input.request(&input.query("owned-completed-ro-response-host"))).await.map_err(|e| e.to_string())?;
        let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
        tokio::select! { biased;
            () = relay.held() => {},
            value = &mut call => return Err(format!("completed-RO response missed original ACK: {value:?}")),
        }
        // Listener/other slots were dropped before the real RO. Do not poll the
        // business call while its original accepted server socket is observed.
        let before = r10_lsof(input.port, [peer_port], proof_cap, "r16-A-heldRO-server-owned").await?;
        check(before.listener.is_none() && before.servers.len() == 1 && before.reverse_clients.len() == 1,
            "r16 exact original server/client pair and no listener before RO ACK")?;
        let original_server = before.servers.get(&peer_port).ok_or("r16 original server tuple missing")?;
        let original_client = before.reverse_clients.get(&peer_port).ok_or("r16 original retained peer tuple missing")?;
        relay.release_original_ack().await;
        // First single business poll reaches the unchanged write->Pending path.
        match std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await {
            std::task::Poll::Pending => {},
            std::task::Poll::Ready(value) => return Err(format!("completed-RO write boundary was not Pending: {value:?}")),
        }
        let raw = tokio::time::timeout_at(tokio::time::Instant::from_std(proof_cap), async {
            let mut raw = Vec::with_capacity(4096);
            loop {
                check(raw.len() < 4096, "completed-RO response header bound")?;
                let mut byte = [0_u8; 1];
                peer.read_exact(&mut byte).await.map_err(|e| format!("completed-RO own header: {e}"))?;
                raw.push(byte[0]);
                if raw.ends_with(b"\r\n\r\n") { break; }
            }
            let mut body = [0_u8; 18];
            peer.read_exact(&mut body).await.map_err(|e| format!("completed-RO own literal body: {e}"))?;
            raw.extend_from_slice(&body);
            response(&raw, 200, b"Callback received.")?;
            Ok::<_, String>(raw)
        }).await.map_err(|_| "first single poll did not establish full static200 before original proof cap")??;
        check(!raw.is_empty() && !parent.is_cancelled() && Instant::now() < proof_cap,
            "original parent/cap still current after full static200")?;
        // The unchanged response now flushes/shuts down and drops its stream.
        // The new delivery phase yields once. Ready or another unproved boundary
        // is a failure; no additional poll or sleep repairs this observation.
        match std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await {
            std::task::Poll::Pending => {},
            std::task::Poll::Ready(value) => return Err(format!("post-shutdown delivery boundary was not Pending: {value:?}")),
        }
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout_at(tokio::time::Instant::from_std(proof_cap), peer.read(&mut byte))
            .await.map_err(|_| "original proof cap ended before graceful response EOF")?
            .map_err(|e| format!("original peer graceful response EOF: {e}"))?;
        check(read == 0, "original retained peer must observe graceful EOF without extra response bytes")?;
        // Business remains unpolled and the original peer owner remains alive.
        // Observe the complete original server tuple, not a reusable FD number.
        let after = r10_lsof(input.port, [peer_port], proof_cap, "r16-B-after-shutdown-drop-unpolled").await?;
        check(after.listener.is_none() && after.servers.is_empty() && after.reverse_clients.len() == 1
            && !after.servers.values().any(|socket| r10_same_socket(socket, original_server))
            && r10_same_socket(after.reverse_clients.get(&peer_port).ok_or("r16 retained peer tuple missing after EOF")?, original_client),
            "finite original server FD/endpoint tuple absent; same original peer tuple retained")?;
        check(!parent.is_cancelled() && Instant::now() < proof_cap,
            "unchanged original parent and conservative connection cap before final delivery revoke")?;
        f.disarm_host();
        // Third single original poll enters FinalDelivery itself after the real
        // shutdown/drop interval. This proves stage refusal, not cancellation
        // inside its second synchronous current check.
        let error = match std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await {
            std::task::Poll::Ready(Err(error)) => error,
            std::task::Poll::Ready(Ok(_)) => return Err("closed post-shutdown original Host returned Verified".into()),
            std::task::Poll::Pending => return Err("closed post-shutdown original Host stayed Pending".into()),
        };
        callback_refusal(&error, CallbackErrorKind::Refused, Ack::Timely)?;
        let current_error = error.journal_error().ok_or("original synchronous Host current error missing")?;
        check(current_error.kind() == JournalKind::Refused
            && current_error.write_ack() == Ack::NotAttempted && current_error.readback_ack() == Ack::NotAttempted
            && error.registration_error().is_none(),
            "fresh synchronous current refusal has no journal ACK; independent completed callback RO remains Timely")?;
        drop(call); drop(peer); absent(input.port).await?;
        relay.assert_target(1); relay.end_callback_sql_window(1);
        check(f.row(old.attempt_id).await? == old && f.audits().await? == audits_before && f.posts()? == posts_before,
            "post-shutdown Host refusal preserves full20/audit/reservation and original POST")?;
        {
            let state = sink.state.try_lock().map_err(|_| "original URL sink observation unavailable")?;
            check(state.offered && state.url.is_none(), "original one-shot URL remains offered and consumed")?;
        }
        callback_refusal(&error, CallbackErrorKind::Refused, Ack::Timely)?;
        eprintln!("CALLBACK_POST_SHUTDOWN_FINALDELIVERY_HOST_REVOKE original_RO_ACK=Timely independent_literal_static200=true graceful_EOF=true finite_original_server_FD_endpoint_tuple_absent=true original_peer_tuple_retained=true business_unpolled_between_second_and_third=true same_original_Host_closed=true no_Verified=true; numeric_FD_EBADF_continuous_identity_sync_flush_shutdown_interiors=UNPROVEN");
        f.finish().await?; relay.stop().await; Ok(())
    }).await;
}

#[derive(Debug, serde::Serialize)]
struct R10Socket {
    fd: u32,
    raw_fd: String,
    local: std::net::SocketAddrV4,
    peer: Option<std::net::SocketAddrV4>,
    state: String,
    tcp_fields: Vec<String>,
}
#[derive(Debug, serde::Serialize)]
struct R10Inventory {
    listener: Option<R10Socket>,
    servers: std::collections::BTreeMap<u16, R10Socket>,
    reverse_clients: std::collections::BTreeMap<u16, R10Socket>,
}
fn r10_same_socket(a: &R10Socket, b: &R10Socket) -> bool {
    a.fd == b.fd && a.local == b.local && a.peer == b.peer
}
fn r10_inventory<const N: usize>(
    raw: &[u8],
    pid: u32,
    port: u16,
    peers: &[u16; N],
) -> Result<R10Inventory, String> {
    use std::collections::{BTreeMap, BTreeSet};
    check(
        raw.ends_with(b"\0\n"),
        "r10 lsof field/set terminators incomplete",
    )?;
    check(
        matches!(N, 1 | 5),
        "only original five-peer or owned one-peer observation",
    )?;
    let known: BTreeSet<_> = peers.iter().copied().collect();
    check(
        known.len() == N && !known.contains(&0) && !known.contains(&port),
        "exact distinct actual peer ports",
    )?;
    let mut sets = raw.split(|b| *b == b'\n').peekable();
    let process = sets.next().ok_or("r10 PID set missing")?;
    check(
        process == format!("p{pid}\0").as_bytes(),
        "r10 exact own PID, no extra process fields",
    )?;
    let callback = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
    let mut listener = None;
    let mut servers = BTreeMap::new();
    let mut reverse_clients = BTreeMap::new();
    let mut fds = BTreeSet::new();
    while let Some(set) = sets.next() {
        if set.is_empty() {
            check(sets.peek().is_none(), "r10 unexpected empty set")?;
            break;
        }
        let body = set.strip_suffix(b"\0").ok_or("r10 file set missing NUL")?;
        let mut fields = body.split(|b| *b == 0);
        let first = fields.next().ok_or("r10 file FD missing")?;
        let raw_fd = std::str::from_utf8(
            first
                .strip_prefix(b"f")
                .ok_or("r10 file set must start f")?,
        )
        .map_err(|_| "r10 FD not ASCII")?
        .to_owned();
        let digits = if raw_fd
            .as_bytes()
            .last()
            .is_some_and(|b| matches!(b, b'r' | b'w' | b'u'))
        {
            &raw_fd[..raw_fd.len() - 1]
        } else {
            &raw_fd
        };
        check(
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
            "r10 nonnumeric/ambiguous FD",
        )?;
        let fd: u32 = digits.parse().map_err(|_| "r10 FD overflow")?;
        check(fds.insert(fd), "r10 duplicate original FD")?;
        let (mut kind, mut name, mut state) = (None, None, None);
        let mut tcp_fields = Vec::new();
        let mut tcp_keys = BTreeSet::new();
        for field in fields {
            let (&tag, value) = field.split_first().ok_or("r10 empty field")?;
            check(
                value.iter().all(|b| b.is_ascii() && !b.is_ascii_control()),
                "r10 unexpected field bytes",
            )?;
            let value = std::str::from_utf8(value).map_err(|_| "r10 field decoding")?;
            match tag {
                b't' => check(kind.replace(value).is_none(), "r10 duplicate type")?,
                b'n' => check(name.replace(value).is_none(), "r10 duplicate endpoint")?,
                b'T' => {
                    let (key, data) = value.split_once('=').ok_or("r10 TCP prefix missing")?;
                    check(
                        matches!(key, "ST" | "QR" | "QS" | "SO" | "SS" | "TF" | "WR" | "WW")
                            && tcp_keys.insert(key),
                        "r10 unknown/duplicate TCP item",
                    )?;
                    if key == "ST" {
                        check(!data.is_empty(), "r10 TCP state missing")?;
                        state = Some(data.to_owned());
                    }
                    tcp_fields.push(value.to_owned());
                }
                _ => return Err("r10 unknown lsof field".into()),
            }
        }
        check(kind == Some("IPv4"), "r10 original IPv4 type missing")?;
        let state = state.ok_or("r10 original TST missing")?;
        let name = name.ok_or("r10 original numeric endpoints missing")?;
        let (local, peer) = if let Some((left, right)) = name.split_once("->") {
            (
                left.parse::<std::net::SocketAddrV4>()
                    .map_err(|_| "r10 local endpoint")?,
                Some(
                    right
                        .parse::<std::net::SocketAddrV4>()
                        .map_err(|_| "r10 peer endpoint")?,
                ),
            )
        } else {
            (
                name.parse::<std::net::SocketAddrV4>()
                    .map_err(|_| "r10 listener endpoint")?,
                None,
            )
        };
        let record = R10Socket {
            fd,
            raw_fd,
            local,
            peer,
            state,
            tcp_fields,
        };
        if record.state == "LISTEN" {
            check(
                local == callback && peer.is_none() && listener.replace(record).is_none(),
                "r10 exact one listener",
            )?;
        } else if local == callback {
            let peer = peer.ok_or("r10 server peer missing")?;
            check(
                *peer.ip() == std::net::Ipv4Addr::LOCALHOST
                    && known.contains(&peer.port())
                    && servers.insert(peer.port(), record).is_none(),
                "r10 unknown/duplicate server peer",
            )?;
        } else {
            check(
                *local.ip() == std::net::Ipv4Addr::LOCALHOST
                    && known.contains(&local.port())
                    && peer == Some(callback)
                    && reverse_clients.insert(local.port(), record).is_none(),
                "r10 unknown/reverse client endpoint",
            )?;
        }
    }
    let listener = if N == 5 {
        Some(listener.ok_or("r10 listener absent")?)
    } else {
        check(
            listener.is_none(),
            "r16 matched callback listener must already be absent",
        )?;
        None
    };
    Ok(R10Inventory {
        listener,
        servers,
        reverse_clients,
    })
}

struct R10Child {
    child: tokio::process::Child,
    pid: Option<u32>,
    reaped: bool,
    tail_recorded: bool,
}
impl Drop for R10Child {
    fn drop(&mut self) {
        if !self.tail_recorded {
            eprintln!(
                "R10_LSOF_DROP pid={:?} reaped={} pipe_close=UNKNOWN observer_acceptance=false",
                self.pid, self.reaped
            );
        }
        // kill_on_drop is a last resort; it is never asserted to prove wait/reap.
    }
}
fn r10_stdout_fd(pipe: &tokio::process::ChildStdout) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Some(pipe.as_raw_fd())
    }
    #[cfg(not(unix))]
    {
        let _ = pipe;
        None
    }
}
fn r10_stderr_fd(pipe: &tokio::process::ChildStderr) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Some(pipe.as_raw_fd())
    }
    #[cfg(not(unix))]
    {
        let _ = pipe;
        None
    }
}
async fn r10_read_pipe<R: tokio::io::AsyncRead + Unpin>(
    pipe: &mut R,
    raw: &mut Vec<u8>,
    cap: usize,
) -> Result<(), String> {
    loop {
        let mut buffer = [0; 4096];
        let n = pipe
            .read(&mut buffer)
            .await
            .map_err(|e| format!("r10 own pipe read: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        let left = (cap + 1).saturating_sub(raw.len());
        raw.extend_from_slice(&buffer[..n.min(left)]);
        check(raw.len() <= cap, "r10 own pipe truncated at original bound")?;
    }
}
async fn r10_lsof<const N: usize>(
    port: u16,
    peers: [u16; N],
    deadline: Instant,
    point: &str,
) -> Result<R10Inventory, String> {
    use std::process::Stdio;
    check(
        Instant::now() < deadline,
        "r10 original observer cap already expired",
    )?;
    let pid = std::process::id();
    let argv = [
        "-nP".to_owned(),
        "-a".to_owned(),
        "-p".to_owned(),
        pid.to_string(),
        format!("-i4TCP:{port}"),
        "-F0pftnT".to_owned(),
    ];
    let started = Instant::now();
    let child = tokio::process::Command::new("/usr/sbin/lsof")
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("r10 observer spawn UNPROVEN: {e}"))?;
    // Register the original successful spawn before any fallible metadata/read operation.
    let mut owned = R10Child {
        pid: child.id(),
        child,
        reaped: false,
        tail_recorded: false,
    };
    let mut stdout = owned.child.stdout.take();
    let mut stderr = owned.child.stderr.take();
    let stdout_fd = stdout.as_ref().and_then(r10_stdout_fd);
    let stderr_fd = stderr.as_ref().and_then(r10_stderr_fd);
    eprintln!(
        "R10_LSOF_BORN {}",
        json!({"point":point,"PID":owned.pid,"argv":argv,"stdoutFD":stdout_fd,"stderrFD":stderr_fd})
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut status = None;
    let mut faults = Vec::new();
    let mut killed = false;
    let mut action_complete = false;
    if let (Some(out_pipe), Some(err_pipe)) = (stdout.as_mut(), stderr.as_mut()) {
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            tokio::join!(
                r10_read_pipe(out_pipe, &mut out, 65_536),
                r10_read_pipe(err_pipe, &mut err, 8_192),
                owned.child.wait()
            )
        })
        .await
        {
            Ok((a, b, waited)) => {
                action_complete = a.is_ok() && b.is_ok();
                if let Err(e) = a {
                    faults.push(e);
                }
                if let Err(e) = b {
                    faults.push(e);
                }
                match waited {
                    Ok(s) => {
                        status = Some(s);
                        owned.reaped = true;
                    }
                    Err(e) => faults.push(format!("r10 original wait: {e}")),
                }
            }
            Err(_) => {
                faults.push("r10 original observer cap expired; no snapshot acceptance".to_owned())
            }
        }
    } else {
        faults.push("r10 original stdout/stderr pipe missing".to_owned());
    }
    // All action branches close the two original pipe owners independently before cleanup wait.
    drop(stdout.take());
    drop(stderr.take());
    if !owned.reaped {
        match owned.child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                owned.reaped = true;
            }
            Ok(None) => {}
            Err(e) => faults.push(format!("r10 original try_wait: {e}")),
        }
        if !owned.reaped {
            killed = true;
            if let Err(e) = owned.child.start_kill() {
                faults.push(format!("r10 own observer kill: {e}"));
            }
            // Reap only within the same original observer cap; never extend it.
            // A requested kill or kill_on_drop is not natural0 or a reap proof.
            if Instant::now() < deadline {
                match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    owned.child.wait(),
                )
                .await
                {
                    Ok(Ok(s)) => {
                        status = Some(s);
                        owned.reaped = true;
                    }
                    Ok(Err(e)) => faults.push(format!("r10 own observer reap UNKNOWN: {e}")),
                    Err(_) => faults.push(
                        "r10 original observer cap expired during reap; reap UNKNOWN".to_owned(),
                    ),
                }
            }
            if !owned.reaped {
                match owned.child.try_wait() {
                    Ok(Some(s)) => {
                        status = Some(s);
                        owned.reaped = true;
                    }
                    Ok(None) => faults.push(
                        "r10 original observer unreaped at original cap; reap UNKNOWN".to_owned(),
                    ),
                    Err(e) => faults.push(format!("r10 final original try_wait/reap UNKNOWN: {e}")),
                }
            }
        }
    }
    let accepted = owned.pid.is_some()
        && owned.reaped
        && action_complete
        && !killed
        && faults.is_empty()
        && status.is_some_and(|s| s.success())
        && err.is_empty();
    owned.tail_recorded = true;
    eprintln!(
        "R10_LSOF_FINAL {}",
        json!({"point":point,"PID":owned.pid,"argv":argv,
        "elapsed_us":started.elapsed().as_micros(),"wait_status":status.map(|s|format!("{s:?}")),
        "native":status.and_then(|s|s.code()),"kill_requested":killed,"reaped":owned.reaped,
        "stdoutFD":stdout_fd,"stderrFD":stderr_fd,"stdout_owner_dropped":true,"stderr_owner_dropped":true,
        "EBADF_verification":"NOT_CLAIMED","faults":faults,"stdout":out,"stderr":err,"original_child_IO_accepted":accepted})
    );
    check(
        accepted,
        "r10 observer nonzero/timeout/diagnostic/closure UNKNOWN; inspect exact raw final",
    )?;
    let parsed = r10_inventory(&out, pid, port, &peers)?;
    eprintln!(
        "R10_LSOF_SNAPSHOT {}",
        json!({"point":point,"finite_snapshot_parsed":true,"inventory":parsed})
    );
    Ok(parsed)
}

// Even an unexpected callback terminal cannot select-away an in-flight observer tail.
async fn r10_drive<F, G, T>(call: &mut Pin<Box<F>>, operation: G) -> Result<T, String>
where
    F: Future<Output = CallbackResult>,
    G: Future<Output = Result<T, String>>,
{
    let mut operation = Box::pin(operation);
    let mut early = None;
    let result = std::future::poll_fn(|cx| {
        if early.is_none()
            && let std::task::Poll::Ready(value) = call.as_mut().poll(cx)
        {
            early = Some(format!(
                "r10 callback completed before observation: {value:?}"
            ));
        }
        operation.as_mut().poll(cx)
    })
    .await;
    if let Some(error) = early {
        return Err(error);
    }
    result
}
async fn r10_settle<F: Future<Output = CallbackResult>>(
    call: &mut Pin<Box<F>>,
) -> Result<(), String> {
    r10_drive(call, async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        Ok(())
    })
    .await
}
async fn r10_peer_tail(mut peer: TcpStream, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    let result = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        (&mut peer).take(4097).read_to_end(&mut raw),
    )
    .await;
    drop(peer);
    match result {
        Ok(Ok(_)) => check(raw.len() <= 4096, "r10 response overflow")?,
        Ok(Err(e))
            if raw.is_empty()
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) => {}
        Ok(Err(e)) => return Err(format!("r10 owned peer tail: {e}")),
        Err(_) => return Err("r10 original peer cap expired".into()),
    }
    Ok(raw)
}

// Test-only synchronous waker interleaving: retain the original Tokio waker
// and original parent. No synthetic Host, owner, or production hook is used.
struct R10CancelOnControlledWake {
    original_waker: std::task::Waker,
    original_parent: CancellationToken,
    poll_thread: std::thread::ThreadId,
    active: std::sync::atomic::AtomicBool,
    armed: std::sync::atomic::AtomicBool,
    hits: std::sync::atomic::AtomicUsize,
}
impl R10CancelOnControlledWake {
    fn cancel_and_forward(&self) {
        use std::sync::atomic::Ordering;
        if std::thread::current().id() == self.poll_thread
            && self.active.load(Ordering::SeqCst)
            && self
                .armed
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // Disarm before cancellation: the original cancelled future can
            // synchronously wake this same wrapper again.
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.original_parent.cancel();
        }
        self.original_waker.wake_by_ref();
    }
}
impl std::task::Wake for R10CancelOnControlledWake {
    fn wake(self: Arc<Self>) {
        self.cancel_and_forward();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.cancel_and_forward();
    }
}
struct R10BusinessPollGuard<'a> {
    wake: &'a R10CancelOnControlledWake,
}
impl Drop for R10BusinessPollGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.wake.active.store(false, Ordering::SeqCst);
        self.wake.armed.store(false, Ordering::SeqCst);
    }
}

#[tokio::test]
#[ignore = "requires Root-frozen owned PostgreSQL and TLS runtimes"]
async fn r10_bounded_slow_and_concurrent_terminal() {
    let admin = harness::admin_config("callback-r10");
    harness::with_temp_database(&admin, "cb_r10", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = match Fixture::new(relay.config.clone(), 1).await {
            Ok(value) => value,
            Err(error) => { relay.stop().await; return Err(error); }
        };
        let result = async {
            let sink = GatewayCallbackUrlSink::new();
            f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
            let auth = f.auth().await?;
            let original_caller_cap = Instant::now() + Duration::from_secs(60);
            let (wait, input) = start_on(&f, &f.journal, &auth, &sink, CancellationToken::new(), original_caller_cap).await?;
            let original = f.rows().await?.remove(0);
            relay.arm_original(&f).await;
            let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
            // Conservative observer cap starts before any accept, never renews an accepted cap.
            let proof_cap = (Instant::now() + Duration::from_secs(10)).min(original_caller_cap);
            let prefix = b"GET /callback?";
            let mut clients: Vec<Option<TcpStream>> = Vec::new();
            let mut peers = [0; 5];
            for (index, peer_port) in peers.iter_mut().enumerate() {
                let mut client = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
                *peer_port = client.local_addr().map_err(|e| e.to_string())?.port();
                client.write_all(prefix).await.map_err(|e| e.to_string())?;
                clients.push(Some(client));
                if index == 3 { r10_settle(&mut call).await?; }
            }
            r10_settle(&mut call).await?;
            let first = r10_drive(&mut call, r10_lsof(input.port, peers, proof_cap, "A-full-four")).await?;
            relay.assert_idle();
            check(first.servers.len() == 4 && peers[..4].iter().all(|p| first.servers.contains_key(p))
                && !first.servers.contains_key(&peers[4]), "r10 finite A: four owned servers, fifth not owned")?;
            drop(clients[0].take());
            r10_settle(&mut call).await?;
            let second = r10_drive(&mut call, r10_lsof(input.port, peers, proof_cap, "B-released-one")).await?;
            relay.assert_idle();
            let released = first.servers.get(&peers[0]).ok_or("r10 original released tuple missing")?;
            check(second.servers.len() == 4 && !second.servers.contains_key(&peers[0])
                && second.servers.contains_key(&peers[4])
                && !second.servers.values().any(|s| r10_same_socket(s, released)), "r10 finite B: released tuple gone, fifth owned")?;
            for peer in &peers[1..4] {
                check(r10_same_socket(first.servers.get(peer).ok_or("r10 first retained socket")?,
                    second.servers.get(peer).ok_or("r10 second retained socket")?), "r10 original three FD/endpoint tuples retained")?;
            }
            // Both complete matching requests are queued before the next business poll.
            for (index, code) in [(1, "r10-original-first-match"), (4, "r10-original-fifth-match")] {
                let request = input.request(&input.query(code));
                check(request.starts_with(prefix), "r10 same original partial prefix")?;
                clients[index].as_mut().ok_or("r10 matching client missing")?
                    .write_all(&request[prefix.len()..]).await.map_err(|e| e.to_string())?;
            }
            let a = clients[1].take().ok_or("r10 first matching client absent")?;
            let b = clients[4].take().ok_or("r10 second matching client absent")?;
            tokio::select! { biased;
                () = relay.held() => {},
                value = &mut call => return Err(format!("r10 callback escaped original RO ACK: {value:?}")),
            }
            relay.release_original_ack().await;
            let (owner, a_raw, b_raw) = tokio::join!(&mut call, r10_peer_tail(a, proof_cap), r10_peer_tail(b, proof_cap));
            let verified = owner.map_err(|e| e.to_string())?;
            let (a_raw, b_raw) = (a_raw?, b_raw?);
            match (a_raw.is_empty(), b_raw.is_empty()) {
                (false, true) => response(&a_raw, 200, b"Callback received.")?,
                (true, false) => response(&b_raw, 200, b"Callback received.")?,
                _ => return Err("r10 expected one complete static response and one dropped matching peer".into()),
            }
            relay.assert_target(1); // Existing real relay checks one BEGIN, one rollback and original ACK.
            relay.end_callback_sql_window(1); // Later row/POST verification is outside the callback SQL window.
            drop(verified); drop(call); drop(clients);
            absent(input.port).await?;
            check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                "r10 no callback write/close/re-registration/reservation renewal")?;
            eprintln!("R10_FINITE two snapshots only; all socket states preserved; pure capacity/CODE no-poll lemma separate; continuous negative/backlog/production driver joins UNPROVEN");
            Ok(())
        }.await;
        let cleanup = f.finish().await;
        relay.stop().await;
        result.and(cleanup)
    }).await;
    harness::with_temp_database(&admin, "cb_r10_wake", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::RegisteredReadbackRollback, false).await;
        let f = match Fixture::new(relay.config.clone(), 1).await {
            Ok(value) => value,
            Err(error) => { relay.stop().await; return Err(error); }
        };
        let result = async {
            use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
            let sink = GatewayCallbackUrlSink::new();
            f.resolver.install_gateway_callback_url_sink(Arc::clone(&sink)).map_err(|e| format!("{e:?}"))?;
            let auth = f.auth().await?;
            let parent = CancellationToken::new();
            // One original parent/caller cap, supplied once before setup/start.
            let original_caller_cap = Instant::now() + Duration::from_secs(60);
            let (wait, input) = start_on(&f, &f.journal, &auth, &sink, parent.clone(), original_caller_cap).await?;
            let original = f.rows().await?.remove(0);
            relay.arm_original(&f).await;
            let mut call = Box::pin(f.journal.wait_callback(&auth, wait));
            let proof_cap = (Instant::now() + Duration::from_secs(10)).min(original_caller_cap);
            let mut peer = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, input.port)).await.map_err(|e| e.to_string())?;
            peer.write_all(&input.request(&input.query("r10-original-synchronous-write-wake"))).await.map_err(|e| e.to_string())?;
            tokio::select! { biased;
                () = relay.held() => {},
                value = &mut call => return Err(format!("r10 wake callback escaped original RO ACK: {value:?}")),
            }
            // Forwarded ACK and this driver yield do not prove owner consumption.
            relay.release_original_ack().await;
            check(!parent.is_cancelled() && Instant::now() < proof_cap,
                "r10 wake original parent/cap live before the only armed poll")?;
            // Exactly one business poll. The wrapper is armed only inside it;
            // no later poll may repair an ACK-not-ready or write-boundary miss.
            let (poll, wake) = std::future::poll_fn(|cx| {
                let wake = Arc::new(R10CancelOnControlledWake {
                    original_waker: cx.waker().clone(),
                    original_parent: parent.clone(),
                    poll_thread: std::thread::current().id(),
                    active: AtomicBool::new(true),
                    armed: AtomicBool::new(true),
                    hits: AtomicUsize::new(0),
                });
                let waker = std::task::Waker::from(Arc::clone(&wake));
                let mut context = std::task::Context::from_waker(&waker);
                let guard = R10BusinessPollGuard { wake: &wake };
                let poll = call.as_mut().poll(&mut context);
                drop(guard);
                std::task::Poll::Ready((poll, wake))
            }).await;
            check(wake.hits.load(Ordering::SeqCst) == 1 && parent.is_cancelled()
                && !wake.active.load(Ordering::SeqCst) && !wake.armed.load(Ordering::SeqCst)
                && Instant::now() < proof_cap,
                "r10 wake same-thread active poll cancelled original parent once within original cap")?;
            // Keep the business future unpolled. Independent full literal bytes
            // distinguish an actual successful write wake from an earlier wake.
            let raw = tokio::time::timeout_at(tokio::time::Instant::from_std(proof_cap), async {
                let mut raw = Vec::with_capacity(4096);
                loop {
                    check(raw.len() < 4096, "r10 wake independent static header bound")?;
                    let mut byte = [0_u8; 1];
                    peer.read_exact(&mut byte).await.map_err(|e| format!("r10 wake own header: {e}"))?;
                    raw.push(byte[0]);
                    if raw.ends_with(b"\r\n\r\n") { break; }
                }
                let mut body = [0_u8; 18]; // Handwritten Callback received. byte count.
                peer.read_exact(&mut body).await.map_err(|e| format!("r10 wake own literal body: {e}"))?;
                raw.extend_from_slice(&body);
                response(&raw, 200, b"Callback received.")?;
                Ok::<_, String>(raw)
            }).await.map_err(|_| "r10 single armed poll did not establish full literal write boundary within original cap")??;
            check(!raw.is_empty() && Instant::now() < proof_cap,
                "r10 wake independent full static200 established while original cap live")?;
            let error = match poll {
                std::task::Poll::Ready(Err(error)) => error,
                std::task::Poll::Ready(Ok(_)) => return Err("r10 synchronous write wake returned Verified after original cancellation".into()),
                std::task::Poll::Pending => return Err("r10 synchronous write wake stayed Pending in the same original poll after full literal static200".into()),
            };
            callback_refusal(&error, CallbackErrorKind::Cancelled, Ack::Timely)?;
            drop(call);
            no_callback_reply(&mut peer).await?;
            drop(peer);
            absent(input.port).await?;
            relay.assert_target(1);
            relay.end_callback_sql_window(1);
            check(f.row(original.attempt_id).await? == original && f.posts()?.len() == 1,
                "r10 synchronous wake retains original full row/reservation and one POST; no retry or ControlledClose")?;
            eprintln!("R10_SYNCHRONOUS_WRITE_WAKE original_parent_cancel_hits=1 same_business_poll=ReadyErr_Callback_Cancelled original_RO_ACK=Timely independent_literal_static200_18B=true original_cap_live=true; no_second_business_poll=true positive_and_old_negative_execution_separately_attributed=true");
            Ok(())
        }.await;
        let cleanup = f.finish().await;
        relay.stop().await;
        result.and(cleanup)
    }).await;
}

mod fixture {
    //! Own callback test fixture; reused production assembly and original PG ACK relay. Setup discovery/registration remain separately attributed.
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
                    || (x["method"] == "POST" && x["path"] != "/oauth/desktop/register")
            }) {
                return Err("unexpected journal TLS dispatch".into());
            }
            let closed = tls.finish();
            self.pool.close();
            eprintln!(
                "GATEWAY_CALLBACK_OWNED_FIXTURE setup_discovery_gets={} registration_posts={} token_posts=0 pool_closed={} individual_production_driver_join=UNPROVEN",
                captures.iter().filter(|v| v["method"] == "GET").count(),
                captures.iter().filter(|v| v["method"] == "POST").count(),
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
                "openbot-callback-owned-tls-{label}-{}",
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
                "GATEWAY_CALLBACK_OWNED_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
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
                "GATEWAY_CALLBACK_OWNED_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
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
                eprintln!(
                    "GATEWAY_CALLBACK_OWNED_OWNED_TLS fallback_kill=true natural_stop_unproven=true"
                );
            }
            if let Some(reader) = self.stdout_reader.take() {
                let _ = reader.join();
            }
            if !self.root_removed {
                eprintln!(
                    "GATEWAY_CALLBACK_OWNED_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
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
    deadline=time.monotonic()+6
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
        record('events.jsonl',{'event':'headers_sent','method':self.command,'status':status,'headers':headers,'body_bytes':len(data),'content_length':str(len(data))})
        return data
    def do_GET(self):
        self.connection.settimeout(6)
        if self.path!='/.well-known/oauth-authorization-server/desktop': raise RuntimeError('owned discovery path')
        if self.headers.get('Authorization') is not None: raise RuntimeError('owned discovery carried bearer')
        origin='https://idp.test:'+str(self.server.server_port)
        data=json.dumps({'issuer':origin,'authorization_endpoint':origin+'/oauth/desktop/authorize','token_endpoint':origin+'/oauth/desktop/token','registration_endpoint':origin+'/oauth/desktop/register','revocation_endpoint':origin+'/oauth/desktop/revoke','scopes_supported':['ai','account'],'response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'grant_types_supported':['authorization_code','refresh_token'],'crabcode_auth_contract_version':2,'gateway_error_contract_version':1},separators=(',',':')).encode()
        self.capture(b''); self.send_owned(200,[['Content-Type','application/json']],data); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
    def do_POST(self):
        self.connection.settimeout(6)
        if self.path!='/oauth/desktop/register': raise RuntimeError('owned POST path denies tokens/other endpoints')
        length=int(self.headers.get('Content-Length','-1'))
        if not 0<=length<=65536: raise RuntimeError('owned request byte bound')
        body=self.rfile.read(length)
        if len(body)!=length: raise RuntimeError('owned request EOF')
        self.capture(body)
        settings=root/'settings.json'
        if settings.exists() and settings.stat().st_size>131072: raise RuntimeError('owned settings bound')
        config=json.loads(settings.read_text()) if settings.exists() else {}
        if config.get('close_before_headers'): self.close_connection=True; return
        if config.get('hold_headers'): wait_owned('release_headers')
        if stop.is_set(): self.close_connection=True; return
        data=config.get('raw','{"client_id":"owned-registration-client"}').encode('utf8')
        if len(data)>131072: raise RuntimeError('owned response byte bound')
        headers=config.get('headers',[['Content-Type','application/json']])
        if len(headers)>128 or any(len(n)+len(v)>16384 for n,v in headers): raise RuntimeError('owned header budget')
        outcome='stopped'
        try:
            self.send_owned(config.get('status',200),headers,data)
            if config.get('hold_body'): wait_owned('release_body')
            if not stop.is_set():
                self.wfile.write(data); self.wfile.flush(); record('events.jsonl',{'event':'body_sent','method':'POST','bytes':len(data),'body_hex':data.hex()}); outcome='body_sent'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as closed:
            record('events.jsonl',{'event':'peer_closed','method':'POST','kind':type(closed).__name__}); outcome='peer_closed'
        self.close_connection=True
        record('events.jsonl',{'event':'response_finished','method':'POST','outcome':outcome})
        (root/'response-finished').write_bytes(b'owned')
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
        RegisteredReadbackRollback,
    }
    impl TerminalStage {
        fn command(self) -> &'static [u8] {
            b"ROLLBACK\0"
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
            u8::from(
                marker == Some("gateway_authorization_exact_readback")
                    && body.starts_with("select ")
                    && body.contains("from openbot_internal.gateway_authorization_attempts")
                    && !body.contains("for update"),
            )
        }
        fn complete_bits(self) -> u8 {
            1
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
        readonly_begins_after_arm: AtomicUsize,
        all_sql_frames_after_arm: AtomicUsize,
        callback_sql_window: std::sync::atomic::AtomicBool,
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
                readonly_begins_after_arm: AtomicUsize::new(0),
                all_sql_frames_after_arm: AtomicUsize::new(0),
                callback_sql_window: std::sync::atomic::AtomicBool::new(false),
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
                "GATEWAY_CALLBACK_OWNED_TERMINAL_RELAY_START owned_process_pid={} stage={stage:?} relay_port={} upstream_port={}",
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
            self.state.callback_sql_window.store(true, Ordering::SeqCst);
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
        pub(super) fn end_callback_sql_window(&self, expected_begins: usize) {
            assert!(self.state.callback_sql_window.swap(false, Ordering::SeqCst));
            assert_eq!(
                self.state.all_begins_after_arm.load(Ordering::SeqCst),
                expected_begins
            );
            let sql = self.state.all_sql_frames_after_arm.load(Ordering::SeqCst);
            if expected_begins == 0 {
                assert_eq!(sql, 0);
            } else {
                assert!(sql > 0);
            }
            eprintln!(
                "CALLBACK_SQL_WINDOW_END original_backend={} actual_Q_P_E_frames={} actual_BEGIN={} window_excludes_setup_registration_and_later_verification=true",
                self.original_pid(),
                sql,
                expected_begins
            );
        }
        pub(super) fn assert_before_exact_refusal(&self) {
            assert_eq!(self.state.all_begins_after_arm.load(Ordering::SeqCst), 1);
            assert_eq!(
                self.state.readonly_begins_after_arm.load(Ordering::SeqCst),
                1
            );
            assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.begins.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.forwarded_acks.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.selected_backend_pid.load(Ordering::SeqCst), 0);
            assert!(!self.state.claimed.load(Ordering::SeqCst));
            eprintln!(
                "CALLBACK_ORIGINAL_RO_ACTOR_SESSION_REFUSAL actual_RC_READ_ONLY_BEGIN=1 exact_row_stage=0 target_ACK=0; typed_error_retains_original_RO_terminal full20_not_reached=true"
            );
        }
        pub(super) fn assert_idle(&self) {
            assert!(self.state.callback_sql_window.load(Ordering::SeqCst));
            assert_eq!(
                self.state.all_sql_frames_after_arm.load(Ordering::SeqCst),
                0
            );
            assert_eq!(self.state.all_begins_after_arm.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 0);
            eprintln!(
                "GATEWAY_CALLBACK_OWNED_IDLE_SEND original_backend={} actual_Q_P_E_frames=0 actual_BEGIN_after_arm=0 target_terminal_ACK=0",
                self.original_pid()
            );
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
            assert_eq!(self.state.commits.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 1);
        }
        pub(super) async fn stop(mut self) {
            self.state
                .callback_sql_window
                .store(false, Ordering::SeqCst);
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
                "GATEWAY_CALLBACK_OWNED_TERMINAL_RELAY stage={:?} backend_pid={} accepted={} naturally_joined={} command_ack={} ready_ack={} forwarded_ack={} listener_closed=true",
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
                    "GATEWAY_CALLBACK_OWNED_TERMINAL_RELAY fallback_abort=true normal_join_unproven=true"
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
            let mut original_begin = false;
            let mut original_read_only = false;
            while let Some((tag, bytes)) = terminal_frame(&mut down_read).await? {
                if client_state.callback_sql_window.load(Ordering::SeqCst) {
                    if matches!(tag, b'Q' | b'P' | b'E') {
                        client_state
                            .all_sql_frames_after_arm
                            .fetch_add(1, Ordering::SeqCst);
                    }
                    if tag == b'Q'
                        && (bytes.starts_with(b"START TRANSACTION") || bytes.starts_with(b"BEGIN"))
                    {
                        client_state
                            .all_begins_after_arm
                            .fetch_add(1, Ordering::SeqCst);
                        let sql = std::str::from_utf8(&bytes)
                            .map_err(|_| "callback measured BEGIN UTF8")?;
                        if sql.contains("ISOLATION LEVEL READ COMMITTED")
                            && sql.contains("READ ONLY")
                        {
                            client_state
                                .readonly_begins_after_arm
                                .fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                if client_state.armed.load(Ordering::SeqCst)
                    && client_backend.load(Ordering::SeqCst)
                        == client_state.original_backend_pid.load(Ordering::SeqCst)
                    && client_backend.load(Ordering::SeqCst) != 0
                {
                    if tag == b'Q'
                        && (bytes.starts_with(b"START TRANSACTION") || bytes.starts_with(b"BEGIN"))
                    {
                        stage_bits = 0;
                        seen_stage = false;
                        let query =
                            std::str::from_utf8(&bytes).map_err(|_| "terminal BEGIN UTF8")?;
                        original_begin = query.contains("ISOLATION LEVEL READ COMMITTED");
                        original_read_only = query.contains("READ ONLY");
                    }
                    if let Some(sql) = pg_statement(tag, &bytes) {
                        stage_bits |= client_state.stage.sql_bits(sql);
                        if stage_bits == client_state.stage.complete_bits() && !seen_stage {
                            if !original_begin || !original_read_only {
                                return Err(
                                    "terminal original business RC/read-only mode mismatch".into(),
                                );
                            }
                            seen_stage = true;
                            client_state.begins.fetch_add(1, Ordering::SeqCst);
                            client_state.stage_seen.fetch_add(1, Ordering::SeqCst);
                        }
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
                        tokio::time::timeout(Duration::from_secs(8), state.release.acquire())
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
