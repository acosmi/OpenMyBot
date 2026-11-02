//! An admitted MCP/Drive refresh may send one token POST, even when its endpoint redirects.
//! These tests use the production broker, store and exchangers with real PostgreSQL and HTTP.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use base64::Engine as _;
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::google_drive::{
    GOOGLE_DRIVE_API_BASE, GOOGLE_DRIVE_READONLY_SCOPE, GOOGLE_DRIVE_SERVER_ID,
};
use openbot_infra::google_drive_oauth::{GoogleDriveOAuthClient, GoogleDriveOAuthEndpoints};
use openbot_infra::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use openbot_infra::vault::CredentialRecordVault;
use serde_json::json;
use url::Url;

const ACTOR: &str = "redirect-owner";
const CLIENT_ID: &str = "redirect-client";
const CLIENT_SECRET: &str = "redirect-client-secret";
const REFRESH: &str = "redirect-consumed-refresh";
const AUDIT_KEY: &[u8] = b"oauth-redirect-audit-key-at-least-32";

// Return an error through the fixture so its listener is stopped and awaited, and the harness
// drops the temporary database, before a regression is reported as a failed test.
macro_rules! ensure {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message.to_owned());
        }
    };
}

#[derive(Clone, Copy)]
enum Adapter {
    Mcp,
    Drive,
}

impl Adapter {
    fn server(self) -> &'static str {
        match self {
            Self::Mcp => "redirect-mcp",
            Self::Drive => GOOGLE_DRIVE_SERVER_ID,
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Mcp => "notes:read",
            Self::Drive => GOOGLE_DRIVE_READONLY_SCOPE,
        }
    }

    fn client_auth(self) -> &'static str {
        match self {
            Self::Mcp => "client_secret_basic",
            Self::Drive => "client_secret_post",
        }
    }
}

#[derive(Clone)]
struct EndpointState {
    origin: String,
    adapter: Adapter,
    redirect: StatusCode,
    all_requests: Arc<AtomicUsize>,
    token_posts: Arc<AtomicUsize>,
    redirected_requests: Arc<AtomicUsize>,
}

async fn count_requests(
    State(state): State<EndpointState>,
    request: Request,
    next: Next,
) -> Response {
    state.all_requests.fetch_add(1, Ordering::SeqCst);
    next.run(request).await
}

async fn resource_probe(State(state): State<EndpointState>) -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        [(
            http::header::WWW_AUTHENTICATE,
            format!(
                "Bearer resource_metadata=\"{}/resource-metadata\"",
                state.origin
            ),
        )],
    )
}

async fn resource_metadata(State(state): State<EndpointState>) -> impl IntoResponse {
    axum::Json(json!({
        "resource":format!("{}/mcp",state.origin),
        "authorization_servers":[state.origin],
        "scopes_supported":[state.adapter.scope()]
    }))
}

async fn issuer_metadata(State(state): State<EndpointState>) -> impl IntoResponse {
    axum::Json(json!({
        "issuer":state.origin,
        "authorization_endpoint":format!("{}/authorize",state.origin),
        "token_endpoint":format!("{}/token",state.origin),
        "code_challenge_methods_supported":["S256"],
        "token_endpoint_auth_methods_supported":[state.adapter.client_auth()],
        "scopes_supported":[state.adapter.scope(),"offline_access"]
    }))
}

async fn token_endpoint(
    State(state): State<EndpointState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.token_posts.fetch_add(1, Ordering::SeqCst);
    let form = url::form_urlencoded::parse(&body)
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let authenticated = match state.adapter {
        Adapter::Mcp => {
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
            );
            headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some(expected.as_str())
                && form.get("resource").map(String::as_str)
                    == Some(format!("{}/mcp", state.origin).as_str())
        }
        Adapter::Drive => {
            form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
        }
    };
    if !authenticated
        || form.get("grant_type").map(String::as_str) != Some("refresh_token")
        || form.get("refresh_token").map(String::as_str) != Some(REFRESH)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // The first POST may already have consumed the refresh token. The error and grant-shaped
    // body must neither mark it auth_required nor release access. Location is deliberately
    // same-origin: ordinary 307/308 handling would resend the complete sensitive POST body.
    (
        state.redirect,
        [(
            http::header::LOCATION,
            format!("{}/redirected-token", state.origin),
        )],
        axum::Json(json!({
            "error":"invalid_grant", "access_token":"redirect-body-access",
            "token_type":"Bearer", "refresh_token":"redirect-body-refresh",
            "scope":state.adapter.scope()
        })),
    )
        .into_response()
}

async fn redirected_token(State(state): State<EndpointState>) -> impl IntoResponse {
    // Both GET and POST are accepted so a 303 conversion cannot hide behind a 405 response.
    state.redirected_requests.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({
        "access_token":"redirect-target-access", "token_type":"Bearer",
        "refresh_token":"redirect-target-refresh", "scope":state.adapter.scope()
    }))
}

async fn assert_refresh_redirect_is_unresolved(adapter: Adapter, redirect: StatusCode) {
    let admin = harness::admin_config("oauth_refresh_redirect");
    harness::with_temp_database(&admin, "oauthredirect", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let origin = format!(
            "http://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        let state = EndpointState {
            origin: origin.clone(),
            adapter,
            redirect,
            all_requests: Arc::new(AtomicUsize::new(0)),
            token_posts: Arc::new(AtomicUsize::new(0)),
            redirected_requests: Arc::new(AtomicUsize::new(0)),
        };
        let router = axum::Router::new()
            .route("/mcp", post(resource_probe))
            .route("/resource-metadata", get(resource_metadata))
            .route(
                "/.well-known/oauth-authorization-server",
                get(issuer_metadata),
            )
            .route("/token", post(token_endpoint))
            .route("/redirected-token", any(redirected_token))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                count_requests,
            ))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let outcome = async {
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation)
                   VALUES('redirect-owner','redirect@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES('redirect-owner','user');",
            )
            .await
            .map_err(|error| error.to_string())?;
            let vault = CredentialRecordVault::single_key(
                TenantId::new("redirect-tenant"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x39; 32]).map_err(|error| error.to_string())?,
            );
            let client_id = uuid::Uuid::now_v7();
            let credential_id = uuid::Uuid::now_v7();
            let client = serde_json::to_vec(&json!({
                "clientId":CLIENT_ID, "clientSecret":CLIENT_SECRET, "issuer":origin,
                "tokenEndpointAuthMethod":adapter.client_auth()
            }))
            .map_err(|error| error.to_string())?;
            let sealed_client = vault
                .seal(
                    &client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(adapter.server())),
                    &SecretBytes::new(client),
                )
                .map_err(|error| error.to_string())?;
            let sealed_refresh = vault
                .seal(
                    &credential_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(ActorId::new(ACTOR)),
                    SecretPrincipal::Service(ServiceId::new(adapter.server())),
                    &SecretBytes::new(REFRESH.as_bytes().to_vec()),
                )
                .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.credentials(id,kind,provider,key_id,encrypted_value,metadata)
                   VALUES($1,'mcp_oauth_client',$2,'redirect-client',$3,'{}'),
                         ($4,'mcp_user_token',$2,$5,$6,'{}')",
                &[
                    &client_id,
                    &adapter.server(),
                    &sealed_client,
                    &credential_id,
                    &ACTOR,
                    &sealed_refresh,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
            let (resource, transport, cidrs) = match adapter {
                Adapter::Mcp => (format!("{origin}/mcp"), "mcp", vec!["127.0.0.1/32"]),
                Adapter::Drive => (
                    GOOGLE_DRIVE_API_BASE.trim_end_matches('/').to_owned(),
                    "google_drive_rest",
                    Vec::new(),
                ),
            };
            pg.execute(
                "INSERT INTO public.mcp_servers(id,title,vendor,url,provenance,transport,
                    credential_id,egress_allow_cidrs)
                   VALUES($1,'Redirect fixture','test',$2,'custom',$3,$4,$5)",
                &[&adapter.server(), &resource, &transport, &client_id, &cidrs],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_user_credentials(server_id,user_id,credential_id,scope)
                   VALUES($1,$2,$3,$4)",
                &[&adapter.server(), &ACTOR, &credential_id, &adapter.scope()],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            let mut broker = PostgresMcpCredentialBroker::new(
                pool.clone(),
                vault,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &pool,
                    &openbot_contracts::ids::DeploymentId::new("outside"),
                    &openbot_contracts::ids::TenantId::new("outside"),
                ),
            )
            .with_user_oauth(
                SafeDialer::new(EgressPolicy::default()),
                SchemePolicy::HttpOrHttps,
                AUDIT_KEY.to_vec(),
            )
            .map_err(|error| error.to_string())?;
            if matches!(adapter, Adapter::Drive) {
                let endpoints = GoogleDriveOAuthEndpoints {
                    resource: Url::parse(GOOGLE_DRIVE_API_BASE).unwrap(),
                    authorization: Url::parse(&format!("{origin}/authorize")).unwrap(),
                    token: Url::parse(&format!("{origin}/token")).unwrap(),
                    revocation: Url::parse(&format!("{origin}/revoke")).unwrap(),
                    issuer: origin.clone(),
                };
                let policy =
                    EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap());
                let oauth = GoogleDriveOAuthClient::new_with_endpoints(
                    SafeDialer::new(policy),
                    endpoints,
                    SchemePolicy::HttpOrHttps,
                )
                .map_err(|error| error.to_string())?;
                broker = broker.with_google_drive_oauth(oauth);
            }
            ensure!(
                matches!(
                    broker
                        .bearer_for(adapter.server(), &ActorId::new(ACTOR))
                        .await,
                    Err(McpCredentialError::Unavailable)
                ),
                "3xx must not return access or terminal auth_required"
            );
            ensure!(
                state.token_posts.load(Ordering::SeqCst) == 1,
                "the refresh did not send exactly one token POST"
            );
            ensure!(
                state.redirected_requests.load(Ordering::SeqCst) == 0,
                "an admitted refresh must not follow even a same-origin redirect"
            );
            let wire_requests = state.all_requests.load(Ordering::SeqCst);
            let other_replica = broker.clone();
            for replica in [&broker, &other_replica] {
                ensure!(
                    matches!(
                        replica
                            .bearer_for(adapter.server(), &ActorId::new(ACTOR))
                            .await,
                        Err(McpCredentialError::CommitUnknown)
                    ),
                    "the unresolved refresh allowed a subsequent attempt"
                );
            }
            ensure!(
                state.all_requests.load(Ordering::SeqCst) == wire_requests,
                "the unresolved receipt must deny every subsequent network attempt"
            );
            ensure!(
                state.token_posts.load(Ordering::SeqCst) == 1,
                "a subsequent call retransmitted the token POST"
            );
            ensure!(
                state.redirected_requests.load(Ordering::SeqCst) == 0,
                "a subsequent call reached the redirect target"
            );
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let rows = pg
                .query(
                    "SELECT state,admitted_at IS NOT NULL,completed_at IS NOT NULL
                   FROM public.oauth_refresh_operations WHERE credential_id=$1",
                    &[&credential_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            ensure!(
                rows.len() == 1,
                "the durable refresh receipt was lost or duplicated"
            );
            ensure!(
                rows[0].get::<_, String>(0) == "unknown",
                "redirect did not retain Unknown"
            );
            ensure!(
                rows[0].get::<_, bool>(1) && rows[0].get::<_, bool>(2),
                "Unknown lost its admitted/completed coordinates"
            );
            let row = pg
                .query_one(
                    "SELECT encrypted_value,(SELECT count(*)::bigint FROM public.audit_events
                    WHERE event_type IN ('credential.rotated','mcp.token_refreshed'))
                   FROM public.credentials WHERE id=$1",
                    &[&credential_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            ensure!(
                row.get::<_, String>(0) == sealed_refresh,
                "redirect altered the stored refresh credential"
            );
            ensure!(
                row.get::<_, i64>(1) == 0,
                "redirect emitted a successful refresh audit event"
            );
            Ok(())
        }
        .await;
        server.abort();
        let _ = server.await;
        pool.close();
        outcome
    })
    .await;
}

macro_rules! redirect_case {
    ($name:ident, $adapter:expr, $status:expr) => {
        #[tokio::test]
        #[ignore = "requires isolated PostgreSQL and loopback sockets; set OPENBOT_TEST_DATABASE_URL"]
        async fn $name() {
            assert_refresh_redirect_is_unresolved($adapter, $status).await;
        }
    };
}

redirect_case!(
    mcp_refresh_303_sends_once_and_stays_unknown,
    Adapter::Mcp,
    StatusCode::SEE_OTHER
);
redirect_case!(
    mcp_refresh_307_sends_once_and_stays_unknown,
    Adapter::Mcp,
    StatusCode::TEMPORARY_REDIRECT
);
redirect_case!(
    mcp_refresh_308_sends_once_and_stays_unknown,
    Adapter::Mcp,
    StatusCode::PERMANENT_REDIRECT
);
redirect_case!(
    drive_refresh_303_sends_once_and_stays_unknown,
    Adapter::Drive,
    StatusCode::SEE_OTHER
);
redirect_case!(
    drive_refresh_307_sends_once_and_stays_unknown,
    Adapter::Drive,
    StatusCode::TEMPORARY_REDIRECT
);
redirect_case!(
    drive_refresh_308_sends_once_and_stays_unknown,
    Adapter::Drive,
    StatusCode::PERMANENT_REDIRECT
);
