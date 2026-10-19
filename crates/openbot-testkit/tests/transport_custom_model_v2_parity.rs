//! Transport-only parity. The shared service below is deliberately a recording fake.
//! Genuine PostgreSQL, Vault and actual Server/Prepared Local Agent hosts are tested in their
//! own host modules; none of those capabilities is established by this file.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use openbot_application::{AppEventStream, ApplicationService};
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::begin_thread_run_wire::{
    DecodedBeginThreadRunBody, decode_begin_thread_run_body,
};
use openbot_contracts::command::{
    AppCommand, AppReply, BeginThreadRun, BeginThreadRunV2, SubscriptionRequest, ThreadRunStarted,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId, ThreadId};
use openbot_desktop::InProcessTransport;
use openbot_domain::identity::session::TrustedOrigins;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_server::ServerBuilder;
use openbot_server::auth::{FixedAuthResolver, SensitiveWriteSecurity};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const THREAD: &str = "550e8400-e29b-41d4-a716-446655440000";
const CONNECTION: &str = "01234567-89AB-CDEF-0123-456789ABCDEF";
const ORIGIN: &str = "https://v2-parity.example.test";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Recorded {
    Legacy(BeginThreadRun),
    V2(BeginThreadRunV2),
}

type RecordedCall = (String, String, String, u64, Recorded);

#[derive(Default)]
struct RecordingApplication {
    calls: Mutex<Vec<RecordedCall>>,
    failure: Mutex<Option<AppError>>,
}

#[async_trait]
impl ApplicationService for RecordingApplication {
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        let (thread_id, run_id, recorded) = match command {
            AppCommand::BeginThreadRun(command) => (
                command.thread_id.clone(),
                command.run_id.clone(),
                Recorded::Legacy(command),
            ),
            AppCommand::BeginThreadRunV2(command) => (
                command.thread_id.clone(),
                command.run_id.clone(),
                Recorded::V2(command),
            ),
            _ => panic!("the runs route dispatched an unrelated command"),
        };
        self.calls.lock().unwrap().push((
            auth.deployment().as_str().to_owned(),
            auth.tenant().as_str().to_owned(),
            auth.actor().as_str().to_owned(),
            auth.auth_generation().get(),
            recorded,
        ));
        if let Some(error) = self.failure.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(AppReply::ThreadRunStarted(ThreadRunStarted {
            thread_id,
            run_id,
            message_sequence: 3,
            event_sequence: 9,
            replayed: false,
        }))
    }

    async fn subscribe(
        &self,
        _: AuthContext,
        _: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "unused_parity_subscription",
        })
    }
}

fn auth() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("v2-parity-deployment"),
        TenantId::new("v2-parity-tenant"),
        ActorId::new("v2-parity-owner"),
        [Role::User],
        AuthGeneration::new(17),
        false,
    )
}

fn command(raw: &[u8]) -> AppCommand {
    match decode_begin_thread_run_body(raw).unwrap() {
        DecodedBeginThreadRunBody::Legacy(body) => AppCommand::BeginThreadRun(BeginThreadRun {
            artifact_refs: Vec::new(),
            model_selection: body.model_selection,
            thread_id: ThreadId::new(THREAD),
            run_id: body.run_id,
            bot_id: body.bot_id,
            anchor: body.anchor,
            message: body.message,
            selected_skill_slugs: body.selected_skill_slugs,
        }),
        DecodedBeginThreadRunBody::V2(body) => AppCommand::BeginThreadRunV2(BeginThreadRunV2 {
            artifact_refs: Vec::new(),
            model_selection: body.model_selection,
            thread_id: ThreadId::new(THREAD),
            run_id: body.run_id,
            bot_id: body.bot_id,
            anchor: body.anchor,
            message: body.message,
            selected_skill_slugs: body.selected_skill_slugs,
        }),
    }
}

fn v2_selection() -> String {
    json!({
        "schemaVersion": 2, "source": "custom", "connectionId": CONNECTION,
        "expectedConnectionRevision": 7, "modelId": "owned-model",
        "expectedCatalogRevision": 13,
    })
    .to_string()
}

fn body(selection: &str) -> Vec<u8> {
    format!(
        "{{\"runId\":\"parity-run\",\"botId\":\"parity-bot\",\"anchor\":{{\"kind\":\"direct_bot\"}},\"message\":\"exact é input\",\"selectedSkillSlugs\":[\"second\",\"first\"],\"modelSelection\":{selection}}}"
    )
    .into_bytes()
}

async fn http(application: Arc<dyn ApplicationService>, raw: Vec<u8>) -> (StatusCode, Value) {
    let router = ServerBuilder::new(application, Arc::new(FixedAuthResolver::granting(auth())))
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            default_session_lifetime(),
            TrustedOrigins::from_configured([ORIGIN]).unwrap(),
        ))
        .into_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/threads/{THREAD}/runs"))
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(raw))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn v2_and_legacy_use_one_service_and_preserve_distinct_typed_commands() {
    for (raw, v2) in [
        (body(&v2_selection()), true),
        (
            body(&format!(
                "{{\"connectionId\":\"{CONNECTION}\",\"expectedRevision\":7}}"
            )),
            false,
        ),
        (body("null"), false),
    ] {
        let recording = Arc::new(RecordingApplication::default());
        let application: Arc<dyn ApplicationService> = recording.clone();
        let in_process = InProcessTransport::new(Arc::clone(&application));
        assert!(Arc::ptr_eq(in_process.service(), &application));
        let (status, wire) = http(Arc::clone(&application), raw.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        let expected: ThreadRunStarted = serde_json::from_value(wire).unwrap();
        let reply = in_process.execute(auth(), command(&raw)).await.unwrap();
        assert!(matches!(reply, AppReply::ThreadRunStarted(actual) if actual == expected));
        let calls = recording.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert_eq!(calls[0].0, "v2-parity-deployment");
        assert_eq!(calls[0].1, "v2-parity-tenant");
        assert_eq!(calls[0].2, "v2-parity-owner");
        assert_eq!(calls[0].3, 17);
        match &calls[0].4 {
            Recorded::V2(input) => {
                assert!(v2);
                assert_eq!(input.model_selection.connection_id(), CONNECTION);
                assert_eq!(input.model_selection.expected_catalog_revision(), 13);
                assert_eq!(input.selected_skill_slugs, ["second", "first"]);
                assert_eq!(input.message, "exact é input");
            }
            Recorded::Legacy(_) => assert!(!v2),
        }
    }
}

#[tokio::test]
async fn original_v2_span_limit_and_malformed_union_never_reach_the_service() {
    let selection = v2_selection();
    let exact = body(&format!(
        "{}{}",
        " ".repeat(4096 - selection.len()),
        selection
    ));
    let recording = Arc::new(RecordingApplication::default());
    let application: Arc<dyn ApplicationService> = recording.clone();
    assert_eq!(
        http(Arc::clone(&application), exact).await.0,
        StatusCode::CREATED
    );
    recording.calls.lock().unwrap().clear();
    let mut malformed = vec![
        body(&format!(
            "{}{}",
            " ".repeat(4097 - selection.len()),
            selection
        )),
        body(&selection.replace("\"schemaVersion\":2", "\"schemaVersion\":3")),
        body(&selection.replace("\"source\":\"custom\"", "\"source\":\"future\"")),
        body(&format!(
            "{{\"schemaVersion\":2,\"connectionId\":\"{CONNECTION}\",\"expectedRevision\":7}}"
        )),
        body(&selection.replacen('{', "{\"owner\":\"forged\",", 1)),
    ];
    // Duplicate escaped keys are decoded as the same key and must not select legacy fallback.
    malformed.push(body(&selection.replacen(
        '{',
        "{\"\\u0073ource\":\"custom\",",
        1,
    )));
    for raw in malformed {
        assert!(decode_begin_thread_run_body(&raw).is_err());
        assert_eq!(
            http(Arc::clone(&application), raw).await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(recording.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn v2_application_error_keeps_the_same_stable_code_across_transports() {
    for failure in [
        AppError::ForbiddenRole {
            required: Role::Admin,
        },
        AppError::DependencyUnavailable {
            dependency: "model_dataset",
        },
        AppError::RequestConflict { resource: "thread" },
    ] {
        let recording = Arc::new(RecordingApplication::default());
        *recording.failure.lock().unwrap() = Some(failure.clone());
        let application: Arc<dyn ApplicationService> = recording.clone();
        let in_process = InProcessTransport::new(Arc::clone(&application));
        let raw = body(&v2_selection());
        let (_, wire) = http(application, raw.clone()).await;
        let typed = in_process.execute(auth(), command(&raw)).await.unwrap_err();
        assert_eq!(wire["code"], typed.code().as_str());
        let calls = recording.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert!(matches!(calls[0].4, Recorded::V2(_)));
    }
}
