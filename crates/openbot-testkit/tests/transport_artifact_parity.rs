//! R424/R425 framing through one ApplicationService with a recording repository port.
//! Actual PG authority, authenticated host carriers and physical bytes require integration evidence.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::request::Parts;
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, ChannelCursor,
    ChannelReader, OpenBotApplication, PortError,
};
use openbot_contracts::artifacts::{
    ArtifactGoneStatus, ArtifactMetadata, ArtifactRecordMetadata, ArtifactRegistrationReceipt,
    ArtifactRetentionClass, ArtifactWorkspace, GetArtifactMetadata, SaveRunMessageTextArtifact,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId};
use openbot_contracts::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    RequestBindingOwnerLease, ServerSessionBindingIdentity,
};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::{
    SessionLifetimePolicy, SessionState, TrustedOrigins, evaluate_session,
};
use openbot_server::auth::{AuthResolver, ResolvedAuth, SensitiveWriteSecurity};
use openbot_server::{ServerBuilder, router};
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt as _;

const REQUEST_ID: &str = "019a7777-abcd-7abc-8abc-0123456789ab";
const ARTIFACT_ID: &str = "019a7778-abcd-7abc-8abc-0123456789ab";
const OPERATION_ID: &str = "019a7779-abcd-7abc-8abc-0123456789ab";

#[derive(Clone, Copy)]
struct EmptyChannels;

#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _actor: &ActorId,
        _limit: u32,
        _cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        Ok(Vec::new())
    }
}

/// Hands the HTTP carrier exactly the prepared identity. Unlike `FixedAuthResolver`, it never
/// attaches a synthetic host binding, so an unbound context reaches the route unbound.
struct ExactAuth(ResolvedAuth);

#[async_trait]
impl AuthResolver for ExactAuth {
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        Ok(self.0.context().clone())
    }

    async fn resolve_with_assurance(&self, _parts: &Parts) -> Result<ResolvedAuth, AppError> {
        Ok(self.0.clone())
    }
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-artifact-parity"),
        TenantId::new("tenant-artifact-parity"),
        ActorId::new("actor-artifact-parity"),
        [Role::User],
        AuthGeneration::new(19),
        false,
    )
}

fn input() -> SaveRunMessageTextArtifact {
    SaveRunMessageTextArtifact {
        request_id: REQUEST_ID.to_owned(),
        source_thread_id: ThreadIdentity::new(auth().deployment()).mint_from_entropy([9; 16]),
        source_run_id: RunId::new("來源Run  A "),
        source_message_id: String::from("訊息 ID大小寫保持"),
        expected_sha256: "b".repeat(64),
    }
}

fn receipt(auth: &AuthContext, input: SaveRunMessageTextArtifact) -> ArtifactRegistrationReceipt {
    ArtifactRegistrationReceipt {
        operation_id: OPERATION_ID.into(),
        artifact_id: ARTIFACT_ID.into(),
        request_id: input.request_id,
        owner_actor_id: auth.actor().clone(),
        source_thread_id: input.source_thread_id,
        source_run_id: input.source_run_id,
        source_message_id: input.source_message_id,
        source_call_seq: None,
        source_attempt_seq: None,
    }
}

fn record(auth: &AuthContext) -> ArtifactRecordMetadata {
    let source = input();
    ArtifactRecordMetadata {
        artifact_id: ARTIFACT_ID.into(),
        deployment_id: auth.deployment().clone(),
        tenant_id: auth.tenant().clone(),
        dataset_id: "dataset-parity".into(),
        owner_actor_id: auth.actor().clone(),
        workspace: ArtifactWorkspace::Thread {
            id: source.source_thread_id.as_str().to_owned(),
        },
        source_thread_id: source.source_thread_id,
        source_run_id: source.source_run_id,
        source_call_seq: None,
        source_attempt_seq: None,
        media_type: "text/plain; charset=utf-8".into(),
        byte_length: 12,
        sha256: "b".repeat(64),
        retention_class: ArtifactRetentionClass::ExplicitSaved,
        saved_by: Some(auth.actor().clone()),
        saved_at: Some(OffsetDateTime::UNIX_EPOCH),
    }
}

#[derive(Default)]
struct RecordingArtifacts {
    saves: Mutex<Vec<(AuthContext, SaveRunMessageTextArtifact)>>,
    reads: Mutex<Vec<(AuthContext, String)>>,
    error: Option<ArtifactAdministrationError>,
}

#[async_trait]
impl ArtifactAdministration for RecordingArtifacts {
    async fn save_run_message_text(
        &self,
        auth: &AuthContext,
        input: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.saves
            .lock()
            .unwrap()
            .push((auth.clone(), input.clone()));
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(receipt(auth, input))
    }

    async fn get_metadata(
        &self,
        auth: &AuthContext,
        artifact_id: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.reads
            .lock()
            .unwrap()
            .push((auth.clone(), artifact_id.to_owned()));
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(ArtifactMetadata::Available(record(auth)))
    }
}

struct Fixture {
    service: Arc<dyn ApplicationService>,
    transport: InProcessTransport,
    port: Arc<RecordingArtifacts>,
    context: AuthContext,
    _binding_owner: RequestBindingOwnerLease,
}

/// Synthetic recording-port framing only; this guard makes no PostgreSQL/current-host claim.
struct SyntheticFramingBinding;

impl HostRequestBindingGuard for SyntheticFramingBinding {
    fn verify_current<'a>(
        &'a self,
        _auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

impl Fixture {
    fn new(error: Option<ArtifactAdministrationError>) -> Self {
        let context = auth();
        let (binding_owner, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let key = ServerSessionBindingIdentity::from_verified_row(
            "synthetic-framing-session".to_owned(),
            context.actor().clone(),
            "synthetic-framing-token-column".to_owned(),
            OffsetDateTime::UNIX_EPOCH,
            context.auth_generation(),
        );
        let binding = issuer
            .bind_server_session(&context, key, Arc::new(SyntheticFramingBinding))
            .unwrap();
        let context = context.with_verified_request_binding(binding).unwrap();
        let port = Arc::new(RecordingArtifacts {
            error,
            ..Default::default()
        });
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_artifacts(port.clone()));
        let transport = InProcessTransport::new(Arc::clone(&service));
        Self {
            service,
            transport,
            port,
            context,
            _binding_owner: binding_owner,
        }
    }

    fn server(&self) -> axum::Router {
        self.server_with_session(true)
    }

    fn server_with_session(&self, live: bool) -> axum::Router {
        let lifetime = SessionLifetimePolicy::new(
            time::Duration::minutes(30),
            time::Duration::hours(8),
            time::Duration::minutes(5),
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        let context = self.context.clone();
        let session = evaluate_session(
            lifetime,
            SessionState::rehydrate(now, now, context.auth_generation()),
            context.auth_generation(),
            now,
        )
        .unwrap();
        let resolved = if live {
            ResolvedAuth::from_live_session(context, session, None)
        } else {
            ResolvedAuth::without_session(context)
        };
        let state = ServerBuilder::new(Arc::clone(&self.service), Arc::new(ExactAuth(resolved)))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                lifetime,
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .build();
        assert!(core::ptr::addr_eq(
            Arc::as_ptr(&self.service),
            state.application()
        ));
        router(state)
    }

    async fn http(
        &self,
        method: Method,
        uri: &str,
        body: String,
        origin: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = self
            .server()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn save_http(&self, input: &SaveRunMessageTextArtifact) -> (StatusCode, Value) {
        self.http(
            Method::POST,
            "/api/artifacts/save-run-message-text",
            serde_json::to_string(input).unwrap(),
            Some("https://app.example.test"),
        )
        .await
    }

    async fn metadata_http(&self, artifact_id: &str) -> (StatusCode, Value) {
        self.http(
            Method::GET,
            &format!("/api/artifacts/{artifact_id}"),
            String::new(),
            None,
        )
        .await
    }
}

#[tokio::test]
async fn typed_and_axum_save_return_same_content_free_receipt_from_shared_service() {
    let fixture = Fixture::new(None);
    assert!(Arc::ptr_eq(&fixture.service, fixture.transport.service()));
    let input = input();
    let typed = fixture
        .transport
        .execute(
            auth(),
            AppCommand::SaveRunMessageTextArtifact(input.clone()),
        )
        .await
        .unwrap();
    let (status, wire) = fixture.save_http(&input).await;
    assert!(matches!(status, StatusCode::OK | StatusCode::CREATED));
    let http = AppReply::ArtifactRegistrationReceipt(serde_json::from_value(wire.clone()).unwrap());
    assert_eq!(typed, http);
    let keys: std::collections::BTreeSet<_> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "operationId",
            "artifactId",
            "requestId",
            "ownerActorId",
            "sourceThreadId",
            "sourceRunId",
            "sourceMessageId",
            "sourceCallSeq",
            "sourceAttemptSeq"
        ]
        .into_iter()
        .collect()
    );
    assert!(wire["sourceCallSeq"].is_null());
    assert!(wire["sourceAttemptSeq"].is_null());
    let calls = fixture.port.saves.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, calls[1].1);
    assert_eq!(calls[0].0.actor(), calls[1].0.actor());
    assert_eq!(calls[0].0.auth_generation(), calls[1].0.auth_generation());
}

#[tokio::test]
async fn uuid_aliases_share_canonical_selector_while_opaque_source_bytes_stay_exact() {
    let fixture = Fixture::new(None);
    let mut input = input();
    input.request_id = REQUEST_ID.to_uppercase();
    input.source_run_id = RunId::new(format!("{}  Abc", "界".repeat(169)));
    assert_eq!(input.source_run_id.as_str().len(), 512);
    fixture
        .transport
        .execute(
            auth(),
            AppCommand::SaveRunMessageTextArtifact(input.clone()),
        )
        .await
        .unwrap();
    assert!(fixture.save_http(&input).await.0.is_success());
    {
        let calls = fixture.port.saves.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for (_, actual) in calls.iter() {
            assert_eq!(actual.request_id, REQUEST_ID);
            assert_eq!(actual.source_run_id, input.source_run_id);
            assert_eq!(actual.source_message_id, input.source_message_id);
        }
    }
    let typed = fixture
        .transport
        .execute(
            fixture.context.clone(),
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: ARTIFACT_ID.to_uppercase(),
            }),
        )
        .await
        .unwrap();
    let (status, wire) = fixture.metadata_http(&ARTIFACT_ID.to_uppercase()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        typed,
        AppReply::ArtifactMetadata(serde_json::from_value(wire).unwrap())
    );
    let reads = fixture.port.reads.lock().unwrap();
    assert_eq!(reads.len(), 2);
    assert!(reads.iter().all(|(_, id)| id == ARTIFACT_ID));
}

#[tokio::test]
async fn missing_binding_rejects_each_carrier_without_a_recording_repository_call() {
    let mut fixture = Fixture::new(None);
    // This fixture intentionally carries only the original identity, with no host binding.
    fixture.context = auth();
    let error = fixture
        .transport
        .execute(
            fixture.context.clone(),
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: ARTIFACT_ID.into(),
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        openbot_contracts::error::AppError::DependencyUnavailable {
            dependency: "host_request_binding"
        }
    ));
    let (status, wire) = fixture.metadata_http(ARTIFACT_ID).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(status.as_u16(), error.http_status());
    assert_eq!(wire, serde_json::json!({"code":error.code().as_str()}));
    assert!(fixture.port.reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn closed_fixture_owner_rejects_retained_context_on_each_carrier_before_repository() {
    let fixture = Fixture::new(None);
    let retained = fixture.context.clone();
    fixture._binding_owner.close();
    let error = fixture
        .transport
        .execute(
            retained,
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: ARTIFACT_ID.into(),
            }),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        openbot_contracts::error::AppError::Unauthenticated
    ));
    let (status, wire) = fixture.metadata_http(ARTIFACT_ID).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(status.as_u16(), error.http_status());
    assert_eq!(wire, serde_json::json!({"code":error.code().as_str()}));
    assert!(fixture.port.reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn repository_failures_keep_typed_and_http_code_status_rule_and_gone_state_in_agreement() {
    for (error, expected_body) in [
        (
            ArtifactAdministrationError::InvalidInput {
                field: "artifactId",
            },
            serde_json::json!({"code":"malformed_payload"}),
        ),
        (
            ArtifactAdministrationError::NotVisible,
            serde_json::json!({"code":"not_visible"}),
        ),
        (
            ArtifactAdministrationError::RequestConflict,
            serde_json::json!({"code":"request_conflict"}),
        ),
        (
            ArtifactAdministrationError::PolicyRefused {
                rule: "artifact_quota",
            },
            serde_json::json!({"code":"policy_refused","rule":"artifact_quota"}),
        ),
        (
            ArtifactAdministrationError::Gone {
                status: ArtifactGoneStatus::Deleted,
            },
            serde_json::json!({"code":"artifact_gone","status":"deleted"}),
        ),
        (
            ArtifactAdministrationError::Gone {
                status: ArtifactGoneStatus::Expired,
            },
            serde_json::json!({"code":"artifact_gone","status":"expired"}),
        ),
        (
            ArtifactAdministrationError::Unavailable,
            serde_json::json!({"code":"dependency_unavailable"}),
        ),
        (
            ArtifactAdministrationError::Corrupt { field: "store" },
            serde_json::json!({"code":"dependency_unavailable"}),
        ),
        (
            ArtifactAdministrationError::CommitUnknown,
            serde_json::json!({"code":"dependency_unavailable"}),
        ),
    ] {
        let fixture = Fixture::new(Some(error));
        let typed = fixture
            .transport
            .execute(
                fixture.context.clone(),
                AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                    artifact_id: ARTIFACT_ID.into(),
                }),
            )
            .await
            .unwrap_err();
        let (status, wire) = fixture.metadata_http(ARTIFACT_ID).await;
        assert_eq!(status.as_u16(), typed.http_status());
        assert_eq!(wire, expected_body);
        assert_eq!(wire["code"], typed.code().as_str());
        assert!(!wire.to_string().contains("store"));
        assert!(!wire.to_string().contains(ARTIFACT_ID));
        assert!(!wire.to_string().contains("dependency\""));
    }
}

#[tokio::test]
async fn both_command_failures_preserve_unknown_503_without_positive_receipt() {
    let fixture = Fixture::new(Some(ArtifactAdministrationError::CommitUnknown));
    let typed = fixture
        .transport
        .execute(auth(), AppCommand::SaveRunMessageTextArtifact(input()))
        .await
        .unwrap_err();
    let (status, wire) = fixture.save_http(&input()).await;
    assert_eq!(status.as_u16(), typed.http_status());
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(wire, serde_json::json!({"code":"dependency_unavailable"}));
    assert!(wire.get("operationId").is_none());
}

#[tokio::test]
async fn extra_authority_fields_and_untrusted_write_origin_are_refused_before_repository() {
    let fixture = Fixture::new(None);
    let mut wire = serde_json::to_value(input()).unwrap();
    wire["ownerActorId"] = Value::String("renderer-owner".into());
    let (status, body) = fixture
        .http(
            Method::POST,
            "/api/artifacts/save-run-message-text",
            wire.to_string(),
            Some("https://app.example.test"),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, serde_json::json!({"code":"malformed_payload"}));
    let (status, _) = fixture
        .http(
            Method::POST,
            "/api/artifacts/save-run-message-text",
            serde_json::to_string(&input()).unwrap(),
            Some("https://other.example.test"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(fixture.port.saves.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_uuid_selector_is_400_in_both_transports_without_repository_lookup() {
    let fixture = Fixture::new(None);
    let typed = fixture
        .transport
        .execute(
            auth(),
            AppCommand::GetArtifactMetadata(GetArtifactMetadata {
                artifact_id: "private-selector".into(),
            }),
        )
        .await
        .unwrap_err();
    let (status, wire) = fixture.metadata_http("private-selector").await;
    assert_eq!(status.as_u16(), typed.http_status());
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(wire, serde_json::json!({"code":"malformed_payload"}));
    assert!(fixture.port.reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn save_requires_a_live_session_in_addition_to_trusted_origin_before_dispatch() {
    let fixture = Fixture::new(None);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/artifacts/save-run-message-text")
        .header("content-type", "application/json")
        .header("origin", "https://app.example.test")
        .body(Body::from(serde_json::to_string(&input()).unwrap()))
        .unwrap();
    let response = fixture
        .server_with_session(false)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        serde_json::json!({"code":"identity_sensitive_write_session_not_fresh"})
    );
    assert!(fixture.port.saves.lock().unwrap().is_empty());
}
