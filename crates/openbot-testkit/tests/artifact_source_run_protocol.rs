//! One-service framing parity only. These controlled witnesses do not prove a real host/PG source.
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::request::Parts;
use axum::http::{Method, Request, StatusCode};
use openbot_application::{
    ApplicationService, ArtifactAdministration, ArtifactAdministrationError, ChannelCursor,
    ChannelReader, NoArtifactAdministration, OpenBotApplication, PortError,
};
use openbot_contracts::artifacts::*;
use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
use openbot_contracts::command::{AppCommand, AppReply, ChannelSummary};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::request_binding::*;
use openbot_desktop::InProcessTransport;
use openbot_server::auth::AuthResolver;
use openbot_server::{ServerBuilder, router};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ID: &str = "019a0000-0000-7000-8000-000000000010";
struct EmptyChannels;
#[async_trait]
impl ChannelReader for EmptyChannels {
    async fn list_visible_channels(
        &self,
        _: &ActorId,
        _: u32,
        _: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        panic!("source IDs must not use channel enumeration")
    }
}
/// Hands the HTTP carrier exactly the prepared identity. Unlike `FixedAuthResolver`, it never
/// attaches a synthetic host binding, so an unbound context reaches the route unbound.
struct ExactAuth(AuthContext);
#[async_trait]
impl AuthResolver for ExactAuth {
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        Ok(self.0.clone())
    }
}
fn plain() -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("source-ids-parity"),
        TenantId::new("source-ids-tenant"),
        ActorId::new("source-ids-actor"),
        [Role::User],
        AuthGeneration::new(0),
        false,
    )
}
fn input() -> GetSourceRunArtifactIds {
    GetSourceRunArtifactIds {
        source_thread_id: ThreadId::new("source/%thread 成果"),
        source_run_id: RunId::new("run/%原件  "),
    }
}
struct ControlledBinding;
impl HostRequestBindingGuard for ControlledBinding {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn bound() -> (RequestBindingOwnerLease, AuthContext) {
    let (owner, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = plain();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "controlled-framing-session".into(),
        auth.actor().clone(),
        "controlled-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(ControlledBinding))
        .unwrap();
    (owner, auth.with_verified_request_binding(binding).unwrap())
}
struct ControlledTail(AuthContext);
impl ArtifactReadTailWitness for ControlledTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        if Instant::now() >= deadline {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        if !auth
            .request_binding()
            .zip(self.0.request_binding())
            .is_some_and(|(a, b)| a.identity().same_binding(b.identity()))
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        Ok(())
    }
}
struct RecordingPort {
    error: Option<ArtifactReadCurrentError>,
    calls: Mutex<Vec<GetSourceRunArtifactIds>>,
    old_calls: AtomicUsize,
}
#[async_trait]
impl ArtifactAdministration for RecordingPort {
    async fn observe_source_run_artifact_ids_current(
        &self,
        auth: &AuthContext,
        input: &GetSourceRunArtifactIds,
        _: Instant,
    ) -> SourceRunArtifactIdsCurrentOutcome {
        self.calls.lock().unwrap().push(input.clone());
        let source = self.error.map_or_else(
            || {
                Ok(SourceRunArtifactIds {
                    source_thread_id: input.source_thread_id.clone(),
                    source_run_id: input.source_run_id.clone(),
                    artifact_ids: vec![ID.into()],
                })
            },
            Err,
        );
        Ok((Box::new(ControlledTail(auth.clone())), source))
    }
    async fn save_run_message_text(
        &self,
        _: &AuthContext,
        _: SaveRunMessageTextArtifact,
    ) -> Result<ArtifactRegistrationReceipt, ArtifactAdministrationError> {
        self.old_calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactAdministrationError::Unavailable)
    }
    async fn get_metadata(
        &self,
        _: &AuthContext,
        _: &str,
    ) -> Result<ArtifactMetadata, ArtifactAdministrationError> {
        self.old_calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactAdministrationError::Unavailable)
    }
}
fn segment(raw: &str) -> String {
    let mut encoded = String::new();
    for byte in raw.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}
async fn http(
    service: Arc<dyn ApplicationService>,
    auth: AuthContext,
    input: &GetSourceRunArtifactIds,
    method: Method,
    suffix: &str,
    body: &str,
) -> (StatusCode, Value) {
    let state = ServerBuilder::new(service, Arc::new(ExactAuth(auth))).build();
    let uri = format!(
        "/api/artifacts/source-runs/{}/{}{}",
        segment(input.source_thread_id.as_str()),
        segment(input.source_run_id.as_str()),
        suffix
    );
    let response = router(state)
        .oneshot(
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let wire = if method == Method::HEAD {
        assert!(bytes.is_empty());
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, wire)
}

#[tokio::test]
async fn typed_and_http_source_run_id_replies_share_closed_error_and_selector_mapping() {
    for error in [
        None,
        Some(ArtifactReadCurrentError::NotVisible),
        Some(ArtifactReadCurrentError::Unavailable),
        Some(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent,
        )),
    ] {
        let (_owner, auth) = bound();
        let port = Arc::new(RecordingPort {
            error,
            calls: Mutex::new(Vec::new()),
            old_calls: AtomicUsize::new(0),
        });
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(EmptyChannels).with_artifacts(port.clone()));
        let transport = InProcessTransport::new(service.clone());
        assert!(Arc::ptr_eq(transport.service(), &service));
        let typed = transport
            .execute(auth.clone(), AppCommand::GetSourceRunArtifactIds(input()))
            .await;
        let (status, wire) =
            http(service.clone(), auth.clone(), &input(), Method::GET, "", "").await;
        match typed {
            Ok(reply) => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(
                    reply,
                    AppReply::SourceRunArtifactIds(serde_json::from_value(wire.clone()).unwrap())
                );
                assert_eq!(wire.as_object().unwrap().len(), 3);
                for field in [
                    "body",
                    "sha256",
                    "byteLength",
                    "status",
                    "handle",
                    "authority",
                ] {
                    assert!(wire.get(field).is_none());
                }
            }
            Err(error) => {
                assert_eq!(status.as_u16(), error.http_status());
                assert_eq!(wire, json!({"code":error.code().as_str()}));
            }
        }
        assert_eq!(*port.calls.lock().unwrap(), vec![input(), input()]);
        assert_eq!(port.old_calls.load(Ordering::SeqCst), 0);
        let mut bad = input();
        bad.source_run_id = RunId::new("bad\u{85}");
        let typed = transport
            .execute(
                auth.clone(),
                AppCommand::GetSourceRunArtifactIds(bad.clone()),
            )
            .await
            .unwrap_err();
        let (status, wire) = http(service.clone(), auth.clone(), &bad, Method::GET, "", "").await;
        assert_eq!(
            typed,
            AppError::MalformedPayload {
                field: "sourceRunId"
            }
        );
        assert_eq!(status.as_u16(), typed.http_status());
        assert_eq!(wire, json!({"code":typed.code().as_str()}));
        for (method, suffix, body, status) in [
            (Method::GET, "?forged=1", "", StatusCode::BAD_REQUEST),
            (Method::GET, "", "{}", StatusCode::BAD_REQUEST),
            (Method::HEAD, "", "", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            assert_eq!(
                http(
                    service.clone(),
                    auth.clone(),
                    &input(),
                    method,
                    suffix,
                    body
                )
                .await
                .0,
                status
            );
        }
        assert_eq!(port.calls.lock().unwrap().len(), 2);
    }
    let (owner, auth) = bound();
    let port = Arc::new(RecordingPort {
        error: None,
        calls: Mutex::new(Vec::new()),
        old_calls: AtomicUsize::new(0),
    });
    let service: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(EmptyChannels).with_artifacts(port.clone()));
    let transport = InProcessTransport::new(service.clone());
    owner.close();
    let typed = transport
        .execute(auth.clone(), AppCommand::GetSourceRunArtifactIds(input()))
        .await
        .unwrap_err();
    let (status, wire) = http(service.clone(), auth, &input(), Method::GET, "", "").await;
    assert_eq!(typed, AppError::Unauthenticated);
    assert_eq!(status.as_u16(), typed.http_status());
    assert_eq!(wire, json!({"code":typed.code().as_str()}));
    assert!(port.calls.lock().unwrap().is_empty());
    // This is actual original binding closure, not a generic transport.shutdown claim.
    let typed = transport
        .execute(plain(), AppCommand::GetSourceRunArtifactIds(input()))
        .await
        .unwrap_err();
    let (status, wire) = http(service, plain(), &input(), Method::GET, "", "").await;
    assert_eq!(
        typed,
        AppError::DependencyUnavailable {
            dependency: "host_request_binding"
        }
    );
    assert_eq!(status.as_u16(), typed.http_status());
    assert_eq!(wire, json!({"code":typed.code().as_str()}));
    assert!(port.calls.lock().unwrap().is_empty());
    let (_owner, auth) = bound();
    let service: Arc<dyn ApplicationService> = Arc::new(
        OpenBotApplication::new(EmptyChannels).with_artifacts(Arc::new(NoArtifactAdministration)),
    );
    let transport = InProcessTransport::new(service.clone());
    let typed = transport
        .execute(auth.clone(), AppCommand::GetSourceRunArtifactIds(input()))
        .await
        .unwrap_err();
    let (status, wire) = http(service, auth, &input(), Method::GET, "", "").await;
    assert_eq!(
        typed,
        AppError::DependencyUnavailable {
            dependency: "artifacts"
        }
    );
    assert_eq!(status.as_u16(), typed.http_status());
    assert_eq!(wire, json!({"code":typed.code().as_str()}));
}
