//! Real loopback-wire conformance for the Google Drive v3 REST transport.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use openbot_agent::{AgentToolInvoker, AuthorizedAgentToolGateway};
use openbot_application::{
    ApplicationService, McpConnectionAdministration, McpConnectionError, McpOAuthCallback,
    McpOAuthCallbackInput, OpenBotApplication, RunExecutionLease,
};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::mcp::{
    McpOAuthClientAuthMethod, McpOAuthClientRegistration, McpOAuthReturnTo,
    McpVendorRevocationStatus,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::thread::FencingToken;
use openbot_domain::tool::metadata::Effect;
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::agent_tools::{
    PostgresAgentAuthorizationSource, PostgresAgentToolSequence, PostgresBuiltInToolControlPlane,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::google_drive::{
    GOOGLE_DRIVE_API_BASE, GOOGLE_DRIVE_AUTHORIZATION_ENDPOINT, GOOGLE_DRIVE_READONLY_SCOPE,
    GOOGLE_DRIVE_REVOCATION_ENDPOINT, GOOGLE_DRIVE_SERVER_ID, GOOGLE_DRIVE_TOKEN_ENDPOINT,
    GoogleDriveCatalogueAuthentication, GoogleDriveRestTransport, google_drive_catalogue_entry,
    google_drive_effect, google_drive_tools,
};
use openbot_infra::google_drive_oauth::{GoogleDriveOAuthClient, GoogleDriveOAuthEndpoints};
use openbot_infra::mcp::{McpBearerToken, SafeRmcpClient};
use openbot_infra::mcp_catalog::{McpAuthentication, PostgresMcpCatalog, VendorTransportKind};
use openbot_infra::mcp_connections::PostgresMcpConnections;
use openbot_infra::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use openbot_infra::mcp_oauth::McpOAuthClient;
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::tools::PostgresToolJournal;
use openbot_infra::vault::CredentialRecordVault;
use serde_json::json;
use sha2::Digest as _;
use url::Url;

#[derive(Clone, Debug)]
struct ObservedRequest {
    uri: String,
    authorization: Option<String>,
}

#[derive(Clone)]
struct StubReply {
    status: StatusCode,
    body: Vec<u8>,
    headers: HeaderMap,
}

impl StubReply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            status: StatusCode::OK,
            body: serde_json::to_vec(&value).unwrap(),
            headers: HeaderMap::new(),
        }
    }

    fn text(value: &str) -> Self {
        Self {
            status: StatusCode::OK,
            body: value.as_bytes().to_vec(),
            headers: HeaderMap::new(),
        }
    }

    fn refused(status: StatusCode, value: serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            headers: HeaderMap::new(),
        }
    }
}

#[derive(Clone)]
struct DriveStub {
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    replies: Arc<Mutex<VecDeque<StubReply>>>,
}

async fn drive_stub(State(state): State<DriveStub>, request: Request) -> Response {
    state.requests.lock().unwrap().push(ObservedRequest {
        uri: request.uri().to_string(),
        authorization: request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    });
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| StubReply::json(json!({"files":[]})));
    let mut response = (reply.status, Body::from(reply.body)).into_response();
    response.headers_mut().extend(reply.headers);
    response
}

async fn transport(
    replies: impl IntoIterator<Item = StubReply>,
) -> (
    GoogleDriveRestTransport,
    Arc<Mutex<Vec<ObservedRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = DriveStub {
        requests: requests.clone(),
        replies: Arc::new(Mutex::new(replies.into_iter().collect())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().fallback(drive_stub).with_state(state),
        )
        .await;
    });
    let dialer = SafeDialer::new(EgressPolicy::new(
        CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
    ));
    let base = Url::parse(&format!("http://{address}/drive/v3")).unwrap();
    (
        GoogleDriveRestTransport::new_with_endpoint(dialer, base, SchemePolicy::HttpOrHttps)
            .unwrap(),
        requests,
        task,
    )
}

fn bearer() -> McpBearerToken {
    McpBearerToken::new("test-token".to_owned()).unwrap()
}

fn parsed(uri: &str) -> Url {
    Url::parse(&format!("http://drive.test{uri}")).unwrap()
}

const DRIVE_ACTOR: &str = "drive-owner";
const DRIVE_OTHER: &str = "drive-other";
const DRIVE_BOT: &str = "drive-bot";
const DRIVE_CLIENT_ID: &str = "drive-client-id";
const DRIVE_CLIENT_SECRET: &str = "drive-client-secret";
const DRIVE_AUDIT_KEY: &[u8] = b"drive-runtime-audit-key-at-least-32";
const DRIVE_CONTENT_CANARY: &str = "DRIVE-DOCUMENT-CONTENT-CANARY";

#[derive(Clone)]
struct OAuthDriveState {
    issuer: Arc<str>,
    callback: Arc<str>,
    expected_challenge: Arc<Mutex<Option<String>>>,
    token_forms: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    code_calls: Arc<AtomicUsize>,
    refresh_calls: Arc<AtomicUsize>,
    drive_calls: Arc<AtomicUsize>,
    revoke_calls: Arc<AtomicUsize>,
    revoke_failure: Arc<AtomicBool>,
}

async fn google_token(State(state): State<OAuthDriveState>, body: Bytes) -> Response {
    let form = url::form_urlencoded::parse(&body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    state.token_forms.lock().unwrap().push(form.clone());
    let client_ok = form.get("client_id").map(String::as_str) == Some(DRIVE_CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(DRIVE_CLIENT_SECRET);
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let verifier = form.get("code_verifier").map_or("", String::as_str);
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes()));
            if !client_ok
                || form.get("code").map(String::as_str) != Some("drive-code")
                || form.get("redirect_uri").map(String::as_str) != Some(state.callback.as_ref())
                || state.expected_challenge.lock().unwrap().as_deref() != Some(challenge.as_str())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error":"invalid_grant"})),
                )
                    .into_response();
            }
            state.code_calls.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({
                "access_token":"drive-code-access",
                "token_type":"Bearer",
                "refresh_token":"drive-refresh-fixed",
                "scope":GOOGLE_DRIVE_READONLY_SCOPE
            }))
            .into_response()
        }
        Some("refresh_token") => {
            if !client_ok
                || form.get("refresh_token").map(String::as_str) != Some("drive-refresh-fixed")
            {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error":"invalid_grant"})),
                )
                    .into_response();
            }
            let call = state.refresh_calls.fetch_add(1, Ordering::SeqCst) + 1;
            // Google normally reuses the refresh token and omits it from refresh responses.
            axum::Json(json!({
                "access_token":format!("drive-access-{call}"),
                "token_type":"Bearer",
                "scope":GOOGLE_DRIVE_READONLY_SCOPE
            }))
            .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error":"unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn google_revoke(State(state): State<OAuthDriveState>, body: Bytes) -> Response {
    let form = url::form_urlencoded::parse(&body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    state.revoke_calls.fetch_add(1, Ordering::SeqCst);
    if form.get("token").map(String::as_str) != Some("drive-refresh-fixed") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if state.revoke_failure.load(Ordering::SeqCst) {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    } else {
        StatusCode::OK.into_response()
    }
}

async fn google_drive_api(State(state): State<OAuthDriveState>, request: Request) -> Response {
    state.drive_calls.fetch_add(1, Ordering::SeqCst);
    let authorization = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if authorization == Some("Bearer drive-access-1") {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if authorization != Some("Bearer drive-access-2") || request.uri().path() != "/drive/v3/files" {
        return StatusCode::FORBIDDEN.into_response();
    }
    axum::Json(json!({"files":[{
        "id":"drive-file-1",
        "name":DRIVE_CONTENT_CANARY,
        "mimeType":"text/plain",
        "modifiedTime":"2026-08-25T00:00:00Z",
        "webViewLink":"https://drive.google.com/file/d/drive-file-1/view"
    }]}))
    .into_response()
}

async fn spawn_google_runtime() -> Result<
    (
        String,
        OAuthDriveState,
        GoogleDriveOAuthClient,
        GoogleDriveRestTransport,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let origin = format!("http://{address}");
    let callback = format!("{origin}/api/plugins/oauth/callback");
    let state = OAuthDriveState {
        issuer: Arc::from(origin.as_str()),
        callback: Arc::from(callback.as_str()),
        expected_challenge: Arc::new(Mutex::new(None)),
        token_forms: Arc::new(Mutex::new(Vec::new())),
        code_calls: Arc::new(AtomicUsize::new(0)),
        refresh_calls: Arc::new(AtomicUsize::new(0)),
        drive_calls: Arc::new(AtomicUsize::new(0)),
        revoke_calls: Arc::new(AtomicUsize::new(0)),
        revoke_failure: Arc::new(AtomicBool::new(false)),
    };
    let router = Router::new()
        .route("/oauth/token", post(google_token))
        .route("/oauth/revoke", post(google_revoke))
        .route("/drive/v3/{*path}", get(google_drive_api))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let policy = EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap());
    let endpoints = GoogleDriveOAuthEndpoints {
        resource: Url::parse(GOOGLE_DRIVE_API_BASE).unwrap(),
        authorization: Url::parse(&format!("{origin}/oauth/authorize")).unwrap(),
        token: Url::parse(&format!("{origin}/oauth/token")).unwrap(),
        revocation: Url::parse(&format!("{origin}/oauth/revoke")).unwrap(),
        issuer: origin.clone(),
    };
    let oauth = GoogleDriveOAuthClient::new_with_endpoints(
        SafeDialer::new(policy.clone()),
        endpoints,
        SchemePolicy::HttpOrHttps,
    )
    .map_err(|error| error.to_string())?;
    let drive = GoogleDriveRestTransport::new_with_endpoint(
        SafeDialer::new(policy),
        Url::parse(&format!("{origin}/drive/v3")).unwrap(),
        SchemePolicy::HttpOrHttps,
    )
    .map_err(|error| error.to_string())?;
    Ok((origin, state, oauth, drive, task))
}

fn loopback_rmcp() -> SafeRmcpClient {
    SafeRmcpClient::new(
        SafeDialer::new(EgressPolicy::new(
            CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
        )),
        SchemePolicy::HttpOrHttps,
        Some(std::time::Duration::from_secs(2)),
    )
}

#[test]
fn a_pinned_host_matches_only_itself() {
    let entry = google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID).unwrap();
    assert_eq!(entry.api_base, GOOGLE_DRIVE_API_BASE);
    assert_ne!(entry.api_base, "https://www.googleapis.com.evil/drive/v3");
    assert_ne!(entry.api_base, "https://evil.example/drive/v3");
}

#[test]
fn an_entry_whose_pattern_this_build_never_compiled_is_refused() {
    assert!(google_drive_catalogue_entry("tenant.google-drive").is_none());
}

#[test]
fn a_server_not_in_the_catalogue_resolves_to_nothing() {
    assert!(google_drive_catalogue_entry("not-a-vendor").is_none());
}

#[test]
fn the_path_is_the_catalogues_never_the_callers() {
    let entry = google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID).unwrap();
    assert_eq!(Url::parse(entry.api_base).unwrap().path(), "/drive/v3");
    assert!(google_drive_catalogue_entry("google-drive/other-path").is_none());
}

#[test]
fn every_catalogue_entry_pins_a_host_or_an_anchored_pattern() {
    let endpoint = Url::parse(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .api_base,
    )
    .unwrap();
    assert_eq!(endpoint.host_str(), Some("www.googleapis.com"));
    assert!(endpoint.username().is_empty() && endpoint.password().is_none());
}

#[test]
fn every_entry_says_which_credential_principal_it_uses() {
    assert_eq!(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .authentication,
        GoogleDriveCatalogueAuthentication::UserOAuth
    );
}

#[test]
fn a_user_oauth_entry_pins_its_own_endpoints_over_https_and_asks_for_a_scope() {
    for endpoint in [
        GOOGLE_DRIVE_AUTHORIZATION_ENDPOINT,
        GOOGLE_DRIVE_TOKEN_ENDPOINT,
        GOOGLE_DRIVE_REVOCATION_ENDPOINT,
    ] {
        assert_eq!(Url::parse(endpoint).unwrap().scheme(), "https");
    }
    assert_eq!(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .scope,
        GOOGLE_DRIVE_READONLY_SCOPE
    );
}

#[test]
fn a_vendor_this_build_has_never_heard_of_is_not_an_entry() {
    assert!(google_drive_catalogue_entry("community-drive-wrapper").is_none());
}

#[test]
fn resolves_to_the_one_address_google_publishes_for_it() {
    assert_eq!(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .api_base,
        "https://www.googleapis.com/drive/v3"
    );
}

#[test]
fn is_reached_as_the_person_asking_not_as_the_deployment() {
    assert_eq!(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .authentication,
        GoogleDriveCatalogueAuthentication::UserOAuth
    );
}

#[test]
fn asks_only_to_read() {
    assert_eq!(
        google_drive_catalogue_entry(GOOGLE_DRIVE_SERVER_ID)
            .unwrap()
            .scope,
        "https://www.googleapis.com/auth/drive.readonly"
    );
}

#[test]
fn still_calls_its_writes_writes_and_lets_google_be_the_one_to_refuse_them() {
    assert_eq!(google_drive_effect("create_file", true), Effect::Write);
    assert_eq!(google_drive_effect("copy_file", true), Effect::Write);
}

#[test]
fn a_named_write_is_a_write() {
    assert_eq!(google_drive_effect("copy_file", true), Effect::Write);
}

#[test]
fn an_advertised_tool_that_is_not_a_named_write_is_a_read() {
    assert_eq!(google_drive_effect("search_files", true), Effect::Read);
}

#[test]
fn a_tool_the_server_never_advertised_is_a_write() {
    assert_eq!(google_drive_effect("unknown", false), Effect::Write);
}

#[test]
fn copying_is_a_write_and_reading_a_files_content_is_not() {
    assert_eq!(google_drive_effect("copy_file", true), Effect::Write);
    assert_eq!(google_drive_effect("read_file_content", true), Effect::Read);
}

#[test]
fn the_drive_entry_resolves_to_this_adapter_not_to_mcp() {
    assert_eq!(
        VendorTransportKind::parse("google_drive_rest").unwrap(),
        VendorTransportKind::GoogleDriveRest
    );
    assert_ne!(
        VendorTransportKind::GoogleDriveRest,
        VendorTransportKind::Mcp
    );
}

#[test]
fn a_server_with_no_catalogue_entry_falls_back_to_mcp() {
    assert_eq!(
        VendorTransportKind::parse("mcp").unwrap(),
        VendorTransportKind::Mcp
    );
    assert!(VendorTransportKind::parse("unreviewed").is_err());
}

#[tokio::test]
async fn every_advertised_tool_is_one_the_dispatcher_handles() {
    let (drive, requests, task) = transport([]).await;
    for tool in google_drive_tools() {
        let result = drive.call_tool(&bearer(), &tool.name, &json!({})).await;
        assert!(
            result.is_ok(),
            "advertised tool {} lacked a dispatcher",
            tool.name
        );
    }
    assert_eq!(requests.lock().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn the_query_is_sent_as_a_drive_q_clause_with_the_callers_token() {
    let (drive, requests, task) = transport([]).await;
    drive
        .call_tool(&bearer(), "search_files", &json!({"query":"roadmap"}))
        .await
        .unwrap();
    let request = requests.lock().unwrap()[0].clone();
    let url = parsed(&request.uri);
    assert_eq!(url.path(), "/drive/v3/files");
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "q").unwrap().1,
        "name contains 'roadmap' or fullText contains 'roadmap'"
    );
    assert_eq!(request.authorization.as_deref(), Some("Bearer test-token"));
    task.abort();
}

#[tokio::test]
async fn an_apostrophe_in_the_query_cannot_break_out_of_the_clause() {
    let (drive, requests, task) = transport([]).await;
    drive
        .call_tool(&bearer(), "search_files", &json!({"query":"don't ship"}))
        .await
        .unwrap();
    let url = parsed(&requests.lock().unwrap()[0].uri);
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "q").unwrap().1,
        "name contains 'don\\'t ship' or fullText contains 'don\\'t ship'"
    );
    task.abort();
}

#[tokio::test]
async fn recent_files_are_ordered_by_drive_rather_than_filtered() {
    let (drive, requests, task) = transport([]).await;
    drive
        .call_tool(&bearer(), "list_recent_files", &json!({}))
        .await
        .unwrap();
    let url = parsed(&requests.lock().unwrap()[0].uri);
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "orderBy")
            .unwrap()
            .1,
        "modifiedTime desc"
    );
    assert!(!url.query_pairs().any(|(key, _)| key == "q"));
    task.abort();
}

#[tokio::test]
async fn a_search_with_nothing_to_search_for_is_refused_before_the_network() {
    let (drive, requests, task) = transport([]).await;
    let outcome = drive
        .call_tool(&bearer(), "search_files", &json!({}))
        .await
        .unwrap();
    assert!(outcome.is_error);
    assert!(requests.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn a_match_is_named_with_the_id_it_needs_to_read_it() {
    let (drive, _, task) = transport([StubReply::json(json!({"files":[{
        "id":"abc123","name":"Roadmap",
        "mimeType":"application/vnd.google-apps.document",
        "modifiedTime":"2026-08-21T10:00:00Z",
        "webViewLink":"https://docs.google.com/document/d/abc123"
    }]}))])
    .await;
    let outcome = drive
        .call_tool(&bearer(), "search_files", &json!({"query":"roadmap"}))
        .await
        .unwrap();
    assert!(!outcome.is_error);
    assert!(outcome.text.contains("Roadmap"));
    assert!(outcome.text.contains("abc123"));
    assert!(
        outcome
            .text
            .contains("https://docs.google.com/document/d/abc123")
    );
    task.abort();
}

#[tokio::test]
async fn nothing_found_says_so_and_is_not_an_error() {
    let (drive, _, task) = transport([]).await;
    let outcome = drive
        .call_tool(&bearer(), "search_files", &json!({"query":"absent"}))
        .await
        .unwrap();
    assert!(!outcome.is_error);
    assert!(outcome.text.contains("Nothing was found"));
    task.abort();
}

#[tokio::test]
async fn googles_own_refusal_is_passed_through_not_replaced() {
    let (drive, _, task) = transport([StubReply::refused(
        StatusCode::FORBIDDEN,
        json!({"error":{"message":"Google Drive API has not been used in project 1"}}),
    )])
    .await;
    let outcome = drive
        .call_tool(&bearer(), "search_files", &json!({"query":"x"}))
        .await
        .unwrap();
    assert!(outcome.is_error);
    assert!(outcome.text.contains("has not been used in project 1"));
    assert!(outcome.text.contains("403"));
    task.abort();
}

#[tokio::test]
async fn a_google_doc_is_exported_as_text_never_downloaded() {
    let (drive, requests, task) = transport([
        StubReply::json(json!({
            "id":"doc1","name":"Notes",
            "mimeType":"application/vnd.google-apps.document",
            "webViewLink":"https://docs.google.com/document/d/doc1"
        })),
        StubReply::text("document text"),
    ])
    .await;
    let outcome = drive
        .call_tool(&bearer(), "read_file_content", &json!({"fileId":"doc1"}))
        .await
        .unwrap();
    assert!(!outcome.is_error);
    assert!(
        outcome
            .text
            .contains("https://docs.google.com/document/d/doc1")
    );
    assert!(
        outcome
            .text
            .contains("Source: Google Drive REST · first-party")
    );
    let observed = requests.lock().unwrap();
    assert_eq!(observed.len(), 2);
    let url = parsed(&observed[1].uri);
    assert_eq!(url.path(), "/drive/v3/files/doc1/export");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "mimeType")
            .unwrap()
            .1,
        "text/plain"
    );
    drop(observed);
    task.abort();
}

#[tokio::test]
async fn an_ordinary_text_file_is_downloaded() {
    let (drive, requests, task) = transport([
        StubReply::json(json!({
            "id":"txt1","name":"notes.txt","mimeType":"text/plain",
            "webViewLink":"https://drive.google.com/file/d/txt1/view"
        })),
        StubReply::text("plain text"),
    ])
    .await;
    drive
        .call_tool(&bearer(), "read_file_content", &json!({"fileId":"txt1"}))
        .await
        .unwrap();
    let observed = requests.lock().unwrap();
    let url = parsed(&observed[1].uri);
    assert_eq!(url.path(), "/drive/v3/files/txt1");
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "alt").unwrap().1,
        "media"
    );
    drop(observed);
    task.abort();
}

#[tokio::test]
async fn a_binary_file_is_declined_instead_of_being_read_as_text() {
    let (drive, requests, task) = transport([StubReply::json(json!({
        "id":"pdf1","name":"Contract.pdf","mimeType":"application/pdf",
        "webViewLink":"https://drive.google.com/file/d/pdf1/view"
    }))])
    .await;
    let outcome = drive
        .call_tool(&bearer(), "read_file_content", &json!({"fileId":"pdf1"}))
        .await
        .unwrap();
    assert!(outcome.is_error);
    assert!(outcome.text.contains("application/pdf"));
    assert!(
        outcome
            .text
            .contains("https://drive.google.com/file/d/pdf1/view")
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn a_file_id_is_required_and_no_request_is_made_without_one() {
    let (drive, requests, task) = transport([]).await;
    let outcome = drive
        .call_tool(&bearer(), "read_file_content", &json!({}))
        .await
        .unwrap();
    assert!(outcome.is_error);
    assert!(requests.lock().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL 与 loopback socket：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn drive_oauth_catalog_grant_agent_retry_disconnect_and_revoke_are_one_real_boundary() {
    let admin = harness::admin_config(
        "drive_oauth_catalog_grant_agent_retry_disconnect_and_revoke_are_one_real_boundary",
    );
    harness::with_temp_database(&admin, "driveruntime", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,auth_generation) VALUES
                   ('drive-owner','drive-owner@example.test',0),
                   ('drive-other','drive-other@example.test',0);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('drive-owner','user'),('drive-owner','admin'),('drive-other','user');
                 INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                   VALUES('drive-tenant','/drive-fixture',repeat('d',64));
                 INSERT INTO public.agents(id,name,type,configuration,package_id)
                   SELECT 'drive-bot','Drive Bot','built_in',
                          '{\"systemPrompt\":\"Use the connected Drive.\",\"providerSource\":\"package\"}',id
                     FROM public.deployment_packages WHERE tenant_id='drive-tenant';
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                 ) VALUES('drive-bot',NULL,'Drive Bot','role','drive-seed','public',NULL);
                 INSERT INTO public.threads(
                   thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                   next_message_seq,next_event_seq,created_at,updated_at
                 ) VALUES('drive-thread','drive-tenant','drive-deployment','drive-owner',
                          'direct_bot','drive-bot','active',1,0,clock_timestamp(),clock_timestamp());
                 INSERT INTO public.thread_memberships(thread_id,user_id)
                   VALUES('drive-thread','drive-owner');
                 INSERT INTO public.runs(
                   run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                   next_event_seq,created_at,started_at
                 ) VALUES('drive-run','drive-thread','drive-bot','drive-owner',true,'running',1,
                          0,clock_timestamp(),clock_timestamp());
                 INSERT INTO public.thread_leases(
                   thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                 ) VALUES('drive-thread','drive-runtime',1,clock_timestamp(),
                          clock_timestamp()+interval '10 minutes',clock_timestamp());
                 INSERT INTO public.messages(
                   message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at
                 ) VALUES('drive-message','drive-thread',0,'user',
                          '{\"text\":\"Search my Drive.\"}','Search my Drive.',
                          'drive-run','drive-owner',clock_timestamp());",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let (origin, vendor, google_oauth, drive_transport, handle) =
                spawn_google_runtime().await?;
            let vault = CredentialRecordVault::single_key(
                TenantId::new("drive-tenant"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x7d; 32]).map_err(|error| error.to_string())?,
            );
            let rmcp = loopback_rmcp();
            let catalog = Arc::new(
                PostgresMcpCatalog::new(pool.clone(), rmcp.clone(), DRIVE_AUDIT_KEY.to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let connections = PostgresMcpConnections::new(
                pool.clone(),
                vault.clone(),
                McpOAuthClient::new(
                    SafeDialer::new(EgressPolicy::new(
                        CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
                    )),
                    SchemePolicy::HttpOrHttps,
                ),
                catalog.clone(),
                DeploymentId::new("drive-deployment"),
                TenantId::new("drive-tenant"),
                vec![0x6d; 32],
                DRIVE_AUDIT_KEY.to_vec(),
                Some(&origin),
                Some("http://app.example.test"),
                SchemePolicy::HttpOrHttps,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?
            .with_google_drive_oauth(google_oauth.clone());
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new("drive-deployment"),
                TenantId::new("drive-tenant"),
                ActorId::new(DRIVE_ACTOR),
                AuthGeneration::new(0),
                false,
            )
            .with_roles([Role::User, Role::Admin])
            .build();

            let unavailable = connections
                .list_connections(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if !unavailable.available_server_ids.is_empty()
                || !unavailable.connections.is_empty()
            {
                return Err("Drive appeared before admin enabled its reviewed row".to_owned());
            }

            let added = connections
                .add_curated_server(&auth, GOOGLE_DRIVE_SERVER_ID)
                .await
                .map_err(|error| error.to_string())?;
            if added.server_id != GOOGLE_DRIVE_SERVER_ID
                || added.tool_count != 4
                || added.catalog_generation == 0
                || added.suspended_grants != 0
            {
                return Err(format!("curated Drive add drift: {added:?}"));
            }
            let admin_page = connections
                .list_admin_page(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if admin_page.servers.len() != 1
                || admin_page.servers[0].authentication
                    != openbot_contracts::mcp::McpAdminAuthentication::UserOAuth
                || admin_page.servers[0].has_credential
            {
                return Err("Drive OAuth presentation depended on an existing client secret".to_owned());
            }
            connections
                .register_oauth_client(
                    &auth,
                    GOOGLE_DRIVE_SERVER_ID,
                    &McpOAuthClientRegistration::new(
                        DRIVE_CLIENT_ID.to_owned(),
                        DRIVE_CLIENT_SECRET.to_owned(),
                        vendor.issuer.to_string(),
                        McpOAuthClientAuthMethod::ClientSecretPost,
                        None,
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await
                .map_err(|error| error.to_string())?;
            let begin = connections
                .begin_oauth(
                    &auth,
                    GOOGLE_DRIVE_SERVER_ID,
                    McpOAuthReturnTo::Settings,
                )
                .await
                .map_err(|error| error.to_string())?;
            let authorization = Url::parse(&begin.authorization_url)
                .map_err(|error| error.to_string())?;
            let params = authorization
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<BTreeMap<_, _>>();
            let state = params
                .get("state")
                .cloned()
                .ok_or_else(|| "Drive state missing".to_owned())?;
            let challenge = params
                .get("code_challenge")
                .cloned()
                .ok_or_else(|| "Drive PKCE challenge missing".to_owned())?;
            if authorization.path() != "/oauth/authorize"
                || params.get("client_id").map(String::as_str) != Some(DRIVE_CLIENT_ID)
                || params.get("scope").map(String::as_str) != Some(GOOGLE_DRIVE_READONLY_SCOPE)
                || params.get("access_type").map(String::as_str) != Some("offline")
                || params.get("prompt").map(String::as_str) != Some("consent")
                || params.get("code_challenge_method").map(String::as_str) != Some("S256")
                || params.contains_key("client_secret")
                || params.contains_key("code_verifier")
            {
                return Err("Drive authorization URL contract drift".to_owned());
            }
            *vendor.expected_challenge.lock().unwrap() = Some(challenge);
            let callback = connections
                .complete(McpOAuthCallbackInput::new(
                    b"drive-code".to_vec(),
                    state.as_bytes().to_vec(),
                    Some(vendor.issuer.to_string()),
                ))
                .await;
            if callback.redirect_to
                != "http://app.example.test/settings/connected-accounts/google-drive"
                || vendor.code_calls.load(Ordering::SeqCst) != 1
            {
                return Err("Drive code callback drift".to_owned());
            }
            let forms = vendor.token_forms.lock().unwrap().clone();
            let code_form = forms
                .first()
                .ok_or_else(|| "Drive code form missing".to_owned())?;
            if code_form.get("client_secret").map(String::as_str) != Some(DRIVE_CLIENT_SECRET)
                || code_form.get("redirect_uri").map(String::as_str)
                    != Some(vendor.callback.as_ref())
                || code_form.get("grant_type").map(String::as_str)
                    != Some("authorization_code")
            {
                return Err("Drive confidential code exchange drift".to_owned());
            }
            drop(forms);
            let page = connections
                .list_connections(&auth)
                .await
                .map_err(|error| error.to_string())?;
            if page.connections.len() != 1
                || page.available_server_ids.as_slice() != [GOOGLE_DRIVE_SERVER_ID]
                || page.connections[0].server_id != GOOGLE_DRIVE_SERVER_ID
                || page.connections[0].scope != GOOGLE_DRIVE_READONLY_SCOPE
            {
                return Err("Drive connected-account projection drift".to_owned());
            }

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.plugin_grants(
                   kind,ref,agent_id,granted_by,state,catalog_generation,schema_hash,effect,
                   transport_fingerprint,credential_generation
                 ) SELECT 'mcp','google-drive/search_files','drive-bot','drive-owner','active',
                          s.catalog_generation,t.schema_hash,t.effect,
                          s.catalog_transport_fingerprint,coalesce(s.credential_generation,0)
                     FROM public.mcp_servers s JOIN public.mcp_tools t ON t.server_id=s.id
                    WHERE s.id='google-drive' AND t.name='search_files'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            let encrypted_before: String = pg
                .query_one(
                    "SELECT c.encrypted_value FROM public.mcp_user_credentials uc
                       JOIN public.credentials c ON c.id=uc.credential_id
                      WHERE uc.server_id='google-drive' AND uc.user_id='drive-owner'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(pg);

            let broker = Arc::new(
                PostgresMcpCredentialBroker::new(pool.clone(), vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")))
                    .with_user_oauth(
                        SafeDialer::new(EgressPolicy::new(
                            CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
                        )),
                        SchemePolicy::HttpOrHttps,
                        DRIVE_AUDIT_KEY.to_vec(),
                    )
                    .map_err(|error| error.to_string())?
                    .with_google_drive_oauth(google_oauth),
            );
            if !matches!(
                broker
                    .bearer_for(GOOGLE_DRIVE_SERVER_ID, &ActorId::new(DRIVE_OTHER))
                    .await,
                Err(McpCredentialError::AuthRequired)
            ) || vendor.refresh_calls.load(Ordering::SeqCst) != 0
            {
                return Err("unconnected Drive actor reached Google's token endpoint".to_owned());
            }
            let owner_tools = catalog
                .granted_tools(&BotId::new(DRIVE_BOT), &ActorId::new(DRIVE_ACTOR))
                .await
                .map_err(|error| error.to_string())?;
            if owner_tools.len() != 1
                || owner_tools[0].transport != VendorTransportKind::GoogleDriveRest
                || owner_tools[0].authentication != McpAuthentication::UserOAuth
                || !catalog
                    .granted_tools(&BotId::new(DRIVE_BOT), &ActorId::new(DRIVE_OTHER))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_empty()
            {
                return Err("Drive actor-scoped catalog visibility drift".to_owned());
            }

            let policy = PolicyStore::postgres(pool.clone(), None);
            policy.load().await.map_err(|error| error.to_string())?;
            policy
                .set(
                    ActionPolicy {
                        mode: PolicyMode::Enforce,
                        deny: Vec::new(),
                        allow: vec!["true".to_owned()],
                    },
                    Some(DRIVE_ACTOR),
                )
                .await
                .map_err(|error| error.to_string())?;
            let memory = PostgresMemoryAdministration::new(pool.clone());
            let control = PostgresBuiltInToolControlPlane::new(
                pool.clone(),
                DeploymentId::new("drive-deployment"),
                TenantId::new("drive-tenant"),
                policy.clone(),
                Arc::new(memory.clone()),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .with_mcp(catalog.clone(), rmcp)
            .with_google_drive(drive_transport)
            .with_mcp_credentials(broker.clone());
            let application: Arc<dyn ApplicationService> = Arc::new(
                OpenBotApplication::new(ChannelRepo::new(pool.clone()))
                    .with_policy(policy)
                    .with_tools(
                        control,
                        PostgresToolJournal::new(pool.clone(), DRIVE_AUDIT_KEY.to_vec())
                            .map_err(|error| error.to_string())?,
                    )
                    .with_memory(memory),
            );
            let gateway = AuthorizedAgentToolGateway::with_sequence(
                application,
                Arc::new(PostgresAgentAuthorizationSource::new(
                    pool.clone(),
                    DeploymentId::new("drive-deployment"),
                    TenantId::new("drive-tenant"),
                    false,
                )),
                Arc::new(PostgresAgentToolSequence::new(pool.clone())),
            );
            let lease = RunExecutionLease::new(
                RunId::new("drive-run"),
                ThreadId::new("drive-thread"),
                BotId::new(DRIVE_BOT),
                ActorId::new(DRIVE_ACTOR),
                FencingToken::new(1).map_err(|error| error.to_string())?,
                0,
            )
            .map_err(|error| error.to_string())?;
            let reply = gateway
                .invoke(
                    &lease,
                    "provider-drive-search",
                    "mcp__google-drive__search_files",
                    json!({"query":"roadmap"}),
                )
                .await
                .map_err(|error| error.to_string())?;
            if reply.error_code().is_some()
                || !reply.content().contains(DRIVE_CONTENT_CANARY)
                || !reply.content().contains("Google Drive REST (first-party provenance)")
                || !reply
                    .content()
                    .contains("https://drive.google.com/file/d/drive-file-1/view")
                || vendor.refresh_calls.load(Ordering::SeqCst) != 2
                || vendor.drive_calls.load(Ordering::SeqCst) != 2
            {
                return Err(format!("governed Drive retry call drift: {reply:?}"));
            }

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let evidence = pg
                .query_one(
                    "SELECT c.encrypted_value,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='credential.rotated'
                                AND actor_user_id='drive-owner'),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='mcp.call_succeeded'
                                AND target_id='google-drive/search_files'
                                AND actor_user_id='drive-owner'),
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE payload::text LIKE '%'||$1||'%'),
                            (SELECT count(*)::bigint FROM pg_class c2
                              JOIN pg_namespace n ON n.oid=c2.relnamespace
                              WHERE n.nspname='public' AND c2.relname ILIKE '%drive%')
                       FROM public.mcp_user_credentials uc
                       JOIN public.credentials c ON c.id=uc.credential_id
                      WHERE uc.server_id='google-drive' AND uc.user_id='drive-owner'",
                    &[&DRIVE_CONTENT_CANARY],
                )
                .await
                .map_err(|error| error.to_string())?;
            let encrypted_after: String = evidence
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let rotations: i64 = evidence.try_get(1).map_err(|error| error.to_string())?;
            let successes: i64 = evidence.try_get(2).map_err(|error| error.to_string())?;
            let cached_body: i64 = evidence.try_get(3).map_err(|error| error.to_string())?;
            let drive_relations: i64 =
                evidence.try_get(4).map_err(|error| error.to_string())?;
            drop(pg);
            if encrypted_after != encrypted_before
                || rotations != 0
                || successes != 1
                || cached_body != 0
                || drive_relations != 0
            {
                return Err("Drive no-rotation/audit/no-body-cache/no-index evidence drift".to_owned());
            }

            vendor.revoke_failure.store(true, Ordering::SeqCst);
            let pending = connections
                .disconnect(&auth, GOOGLE_DRIVE_SERVER_ID)
                .await
                .map_err(|error| error.to_string())?;
            if pending.vendor_revocation != McpVendorRevocationStatus::Pending
                || !connections
                    .list_connections(&auth)
                    .await
                    .map_err(|error| error.to_string())?
                    .connections
                    .is_empty()
                || vendor.revoke_calls.load(Ordering::SeqCst) != 1
                || !matches!(
                    broker
                        .bearer_for(GOOGLE_DRIVE_SERVER_ID, &ActorId::new(DRIVE_ACTOR))
                        .await,
                    Err(McpCredentialError::AuthRequired)
                )
            {
                return Err("Drive local-first disconnect restored access".to_owned());
            }
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.credentials SET updated_at=clock_timestamp()-interval '31 seconds'
                      WHERE kind='mcp_user_token' AND key_id='drive-owner'
                        AND metadata->>'revocation_status'='pending'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            vendor.revoke_failure.store(false, Ordering::SeqCst);
            let sweep = connections
                .reconcile_pending_revocations()
                .await
                .map_err(|error| error.to_string())?;
            if sweep.attempted != 1
                || sweep.revoked != 1
                || sweep.pending != 0
                || vendor.revoke_calls.load(Ordering::SeqCst) != 2
            {
                return Err("Drive revocation reconciliation drift".to_owned());
            }
            pool.get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "UPDATE public.mcp_servers SET url='https://attacker.invalid/drive'
                      WHERE id='google-drive'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            if !matches!(
                connections.list_connections(&auth).await,
                Err(McpConnectionError::Corrupt {
                    field: "reviewed_server_identity"
                })
            ) {
                return Err("tampered reviewed Drive identity remained available".to_owned());
            }
            handle.abort();
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
