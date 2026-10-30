use super::*;
use crate::ServerBuilder;
use crate::auth::AuthResolver;
use crate::config::ServerConfig;
use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request};
use http::{HeaderValue, StatusCode};
use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use std::net::SocketAddr;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tower::ServiceExt as _;

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CODE: &str = "single_user_remote_transport_refused";
const PROXY_HEADERS: [&str; 7] = [
    "x-wrok-bot-proxy-secret",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-port",
    "x-real-ip",
];

fn config(url: Option<&str>, secret: Option<&str>) -> ServerConfig {
    let mut env = EnvMap::new();
    if let Some(url) = url {
        env.insert("OPENBOT_PUBLIC_URL".into(), url.into());
    }
    if let Some(secret) = secret {
        env.insert("OPENBOT_TLS_PROXY_SECRET".into(), secret.into());
    }
    ServerConfig::from_env_map(&env).unwrap()
}

fn refused(config: &ServerConfig) {
    let error = config.startup_transport_policy(true).unwrap_err();
    assert_eq!(error.to_string(), CODE);
    assert_eq!(format!("{error:?}"), CODE);
}

#[test]
fn startup_single_user_accepts_only_unconfigured_or_http_loopback_without_proxy() {
    for url in [
        None,
        Some("http://localhost:3001"),
        Some("http://API.LOCALHOST/path"),
        Some("http://127.0.0.1"),
        Some("http://127.0.0.2:3010"),
        Some("http://127.255.255.255"),
        Some("http://[::1]:3001"),
        Some("http://[0:0:0:0:0:0:0:1]:3001"),
    ] {
        let config = config(url, None);
        assert!(matches!(
            config.startup_transport_policy(true).unwrap().mode,
            TrustedTransportMode::LoopbackSingleUser
        ));
        assert!(!config.public_transport().cookie_secure());
        assert!(!config.public_transport().insecure_transport());
        assert_eq!(
            config.public_transport().startup_warning().is_some(),
            url.is_none()
        );
    }
}

#[test]
fn startup_single_user_rejects_https_and_non_loopback_with_fixed_code() {
    for url in [
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://public.example",
        "http://public.example",
        "http://10.0.0.1",
        "http://192.168.1.10",
        "http://172.16.0.1",
        "http://128.0.0.1",
        "http://127.0.0.1.evil.test",
        "http://localhost.evil.test",
    ] {
        refused(&config(Some(url), None));
    }
}

#[test]
fn startup_single_user_rejects_every_present_secret_in_direct_configuration() {
    // Direct typed-field mutation is distinct from the environment parser's valid inputs.
    for url in [
        None,
        Some("http://localhost"),
        Some("http://public.example"),
        Some("https://localhost"),
        Some("https://public.example"),
    ] {
        for value in ["", "bad-secret", SECRET] {
            let mut config = config(url, None);
            config.tls_proxy_secret = Some(Secret::new(value));
            refused(&config);
            assert!(matches!(
                config.transport_policy(true).mode,
                TrustedTransportMode::Deny
            ));
        }
    }
}

#[test]
fn single_user_policy_never_selects_proxy_even_with_valid_https_proof() {
    let config = config(Some("https://public.example:443"), Some(SECRET));
    assert!(matches!(
        TrustedTransportPolicy::from_configuration(
            config.public_url.as_ref(),
            config.tls_proxy_secret.clone(),
            true
        )
        .mode,
        TrustedTransportMode::Deny
    ));
    assert!(matches!(
        config.transport_policy(true).mode,
        TrustedTransportMode::Deny
    ));
    refused(&config);
    assert!(
        matches!(config.startup_transport_policy(false).unwrap().mode,
        TrustedTransportMode::LoopbackHttpsProxy { ref authority, .. } if authority == "public.example:443")
    );
}

#[test]
fn startup_multi_user_preserves_proxy_authority_secret_and_deny_modes() {
    for url in [
        None,
        Some("http://localhost:3001"),
        Some("http://public.example"),
        Some("https://public.example"),
    ] {
        assert!(matches!(
            config(url, None)
                .startup_transport_policy(false)
                .unwrap()
                .mode,
            TrustedTransportMode::Deny
        ));
    }
    for url in [
        "https://public.example:443",
        "https://public.example:8443/path",
    ] {
        let config = config(Some(url), Some(SECRET));
        let policy = config.startup_transport_policy(false).unwrap();
        let TrustedTransportMode::LoopbackHttpsProxy { authority, secret } = policy.mode else {
            panic!("valid multi-user proxy must remain selected");
        };
        assert_eq!(
            authority,
            url.split_once("://").unwrap().1.split('/').next().unwrap()
        );
        assert_eq!(secret.expose(), SECRET);
        assert!(config.public_transport().cookie_secure());
        assert!(!config.public_transport().insecure_transport());
        assert_eq!(config.public_transport().startup_warning(), None);
    }
    let config = config(Some("http://public.example"), None);
    assert!(!config.public_transport().cookie_secure());
    assert!(config.public_transport().insecure_transport());
    assert!(config.public_transport().startup_warning().is_some());
}

#[test]
fn startup_transport_error_has_fixed_redacted_display_debug_and_no_source() {
    fn copied<T: Copy + Eq>(value: T) -> T {
        value
    }
    assert_eq!(std::mem::size_of::<SingleUserRemoteTransportRefused>(), 0);
    let config = config(Some("https://private-url-canary.example:443"), Some(SECRET));
    let error = config.startup_transport_policy(true).unwrap_err();
    assert_eq!(copied(error), error);
    assert_eq!(error.to_string(), CODE);
    assert_eq!(format!("{error:?}"), CODE);
    assert!(std::error::Error::source(&error).is_none());
    let boxed: Box<dyn std::error::Error> = Box::new(error);
    // Result<(), Box<dyn Error>> uses this Debug channel when main reports failure.
    let rendered = format!("{boxed:?}");
    assert_eq!(rendered, CODE);
    assert_eq!(boxed.to_string(), CODE);
    assert!(boxed.source().is_none());
    assert!(!rendered.contains(SECRET));
    assert!(!rendered.contains("private-url-canary"));
}

#[test]
fn single_user_checked_policy_rechecks_mutable_public_transport_fields() {
    let mut config = config(None, None);
    assert!(config.startup_transport_policy(true).is_ok());
    config.public_url = Some(DeploymentAddress::parse("https://localhost").unwrap());
    refused(&config);
    config.public_url = Some(DeploymentAddress::parse("http://127.0.0.2").unwrap());
    assert!(config.startup_transport_policy(true).is_ok());
    config.tls_proxy_secret = Some(Secret::new(SECRET));
    refused(&config);
    config.tls_proxy_secret = None;
    assert!(config.startup_transport_policy(true).is_ok());
    config.public_url = Some(DeploymentAddress::parse("http://10.0.0.1").unwrap());
    refused(&config);
}

#[test]
fn malformed_proxy_and_retired_node_env_keep_existing_parse_errors() {
    for (url, secret) in [
        (None, SECRET),
        (Some("http://localhost"), SECRET),
        (Some("https://public.example"), ""),
        (Some("https://public.example"), "secret-canary-malformed"),
    ] {
        let mut env = EnvMap::from([("OPENBOT_TLS_PROXY_SECRET".into(), secret.into())]);
        if let Some(url) = url {
            env.insert("OPENBOT_PUBLIC_URL".into(), url.into());
        }
        let error = ServerConfig::from_env_map(&env).unwrap_err();
        assert!(
            error
                .problems()
                .iter()
                .all(|p| p.code() == "malformed_env_var")
        );
        let text = format!("{error} {error:?}");
        assert!(!text.contains("secret-canary-malformed"));
        assert!(!text.contains(SECRET));
        assert!(!text.contains(CODE));
    }
    for value in ["development", "production"] {
        let error = ServerConfig::from_env_map(&EnvMap::from([
            ("NODE_ENV".into(), value.into()),
            ("OPENBOT_SINGLE_USER".into(), "true".into()),
        ]))
        .unwrap_err();
        assert_eq!(error.problems()[0].code(), "renamed_env_var");
        assert_eq!(error.problems()[0].variable(), "NODE_ENV");
    }
    refused(&config(Some("https://public.example"), Some(SECRET)));
}

#[derive(Default)]
struct Spy {
    auth: AtomicUsize,
    application: AtomicUsize,
    leaked_header: AtomicBool,
}
#[async_trait]
impl AuthResolver for Spy {
    async fn resolve(&self, parts: &http::request::Parts) -> Result<AuthContext, AppError> {
        self.auth.fetch_add(1, Ordering::SeqCst);
        if PROXY_HEADERS
            .iter()
            .any(|name| parts.headers.contains_key(*name))
        {
            self.leaked_header.store(true, Ordering::SeqCst);
        }
        Err(AppError::Unauthenticated)
    }
}
#[async_trait]
impl ApplicationService for Spy {
    async fn execute(&self, _: AuthContext, _: AppCommand) -> Result<AppReply, AppError> {
        self.application.fetch_add(1, Ordering::SeqCst);
        Err(AppError::Unauthenticated)
    }
    async fn subscribe(
        &self,
        _: AuthContext,
        _: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        self.application.fetch_add(1, Ordering::SeqCst);
        Err(AppError::Unauthenticated)
    }
}
fn router(policy: TrustedTransportPolicy, spy: Arc<Spy>) -> axum::Router {
    ServerBuilder::new(spy.clone(), spy)
        .with_transport_policy(policy)
        .into_router()
}
fn request(peer: Option<&str>, proof: bool) -> Request {
    let mut request = Request::builder()
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    }
    if proof {
        for (name, value) in [
            (PROXY_HEADERS[0], SECRET),
            (PROXY_HEADERS[1], "https"),
            (PROXY_HEADERS[2], "public.example:443"),
            (PROXY_HEADERS[3], "for=127.0.0.1;proto=https"),
            (PROXY_HEADERS[4], "127.0.0.1"),
            (PROXY_HEADERS[5], "443"),
            (PROXY_HEADERS[6], "127.0.0.1"),
        ] {
            request
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }
    }
    request
}
async fn rejected(app: axum::Router, request: Request) {
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(http::header::SET_COOKIE));
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), br#"{"code":"transport_untrusted"}"#);
}

#[tokio::test]
async fn loopback_policy_rejects_missing_or_remote_peer_before_auth_and_application() {
    let spy = Arc::new(Spy::default());
    let app = router(
        config(None, None).startup_transport_policy(true).unwrap(),
        spy.clone(),
    );
    for peer in [
        None,
        Some("192.168.1.2:3210"),
        Some("203.0.113.2:3210"),
        Some("[2001:db8::1]:3210"),
    ] {
        rejected(app.clone(), request(peer, true)).await;
    }
    assert_eq!(spy.auth.load(Ordering::SeqCst), 0);
    assert_eq!(spy.application.load(Ordering::SeqCst), 0);
    for peer in ["127.0.0.1:3210", "[::1]:3210"] {
        let response = app
            .clone()
            .oneshot(request(Some(peer), true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(spy.auth.load(Ordering::SeqCst), 2);
    assert_eq!(spy.application.load(Ordering::SeqCst), 0);
    assert!(!spy.leaked_header.load(Ordering::SeqCst));
}

#[tokio::test]
async fn single_user_real_loopback_socket_needs_no_proxy_and_reclaims_server() {
    let spy = Arc::new(Spy::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(
        config(None, None).startup_transport_policy(true).unwrap(),
        spy.clone(),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
    });
    // Collect I/O results before assertions so every ordinary failure still reaches shutdown/join.
    let outcome: Result<Vec<String>, String> = async {
        let mut responses = Vec::new();
        for proof in [false, true] {
            let exchange = async {
                let mut stream = tokio::net::TcpStream::connect(address).await.map_err(|e| e.to_string())?;
                let headers = if proof {
                    "x-wrok-bot-proxy-secret: forged-secret\r\nx-forwarded-proto: https\r\nx-forwarded-host: forged.example\r\nforwarded: for=203.0.113.2\r\nx-forwarded-for: 203.0.113.2\r\nx-forwarded-port: 443\r\nx-real-ip: 203.0.113.2\r\n"
                } else { "" };
                stream.write_all(format!("GET /api/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n").as_bytes()).await.map_err(|e| e.to_string())?;
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.map_err(|e| e.to_string())?;
                String::from_utf8(bytes).map_err(|e| e.to_string())
            };
            responses.push(tokio::time::timeout(Duration::from_secs(2), exchange).await
                .map_err(|e| e.to_string())??);
        }
        Ok(responses)
    }.await;
    let _ = stop.send(());
    let closed = match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
        Ok(result) => result
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string())),
        Err(error) => {
            server.abort();
            let reaped = tokio::time::timeout(Duration::from_secs(2), &mut server).await;
            assert!(
                matches!(reaped, Ok(Err(ref error)) if error.is_cancelled()),
                "aborted server must be joined"
            );
            Err(error.to_string())
        }
    };
    closed.unwrap();
    let responses = outcome.unwrap();
    assert_eq!(responses.len(), 2);
    for response in responses {
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(!response.contains(SECRET));
        assert!(!response.contains("forged-secret"));
    }
    assert_eq!(spy.auth.load(Ordering::SeqCst), 2);
    assert_eq!(spy.application.load(Ordering::SeqCst), 0);
    assert!(!spy.leaked_header.load(Ordering::SeqCst));
}

#[tokio::test]
async fn multi_user_proxy_still_requires_exact_headers_and_real_loopback_peer() {
    let spy = Arc::new(Spy::default());
    let app = router(
        config(Some("https://public.example:443"), Some(SECRET))
            .startup_transport_policy(false)
            .unwrap(),
        spy.clone(),
    );
    for peer in [None, Some("192.168.1.2:3210"), Some("[2001:db8::1]:3210")] {
        rejected(app.clone(), request(peer, true)).await;
    }
    for name in &PROXY_HEADERS[..3] {
        let mut missing = request(Some("127.0.0.1:3210"), true);
        missing.headers_mut().remove(*name);
        rejected(app.clone(), missing).await;
        let mut duplicate = request(Some("127.0.0.1:3210"), true);
        let value = duplicate.headers().get(*name).unwrap().clone();
        duplicate.headers_mut().append(*name, value);
        rejected(app.clone(), duplicate).await;
    }
    for (name, value) in [
        (PROXY_HEADERS[0], "bad"),
        (PROXY_HEADERS[1], "http"),
        (PROXY_HEADERS[2], "public.example"),
        (PROXY_HEADERS[2], "public.example:443 "),
    ] {
        let mut bad = request(Some("127.0.0.1:3210"), true);
        bad.headers_mut()
            .insert(name, HeaderValue::from_static(value));
        rejected(app.clone(), bad).await;
    }
    assert_eq!(spy.auth.load(Ordering::SeqCst), 0);
    assert_eq!(spy.application.load(Ordering::SeqCst), 0);
    let response = app
        .oneshot(request(Some("127.0.0.1:3210"), true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    assert_eq!(spy.auth.load(Ordering::SeqCst), 1);
    assert_eq!(spy.application.load(Ordering::SeqCst), 0);
    assert!(!spy.leaked_header.load(Ordering::SeqCst));
}

#[test]
fn ten_round_mode_checks_remain_isolated_without_shared_environment() {
    for _ in 0..10 {
        let barrier = Arc::new(Barrier::new(3));
        let tasks: Vec<_> = (0..3)
            .map(|mode| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    match mode {
                        0 => matches!(
                            config(Some("http://localhost"), None)
                                .startup_transport_policy(true)
                                .unwrap()
                                .mode,
                            TrustedTransportMode::LoopbackSingleUser
                        ),
                        1 => config(Some("https://public.example"), Some(SECRET))
                            .startup_transport_policy(true)
                            .is_err(),
                        _ => matches!(
                            config(Some("https://public.example"), Some(SECRET))
                                .startup_transport_policy(false)
                                .unwrap()
                                .mode,
                            TrustedTransportMode::LoopbackHttpsProxy { .. }
                        ),
                    }
                })
            })
            .collect();
        let outcomes: Vec<_> = tasks.into_iter().map(|task| task.join()).collect();
        for outcome in outcomes {
            assert!(outcome.unwrap());
        }
    }
}
