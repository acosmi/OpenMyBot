//! Human tool-approval HTTP framing; all binding/decision rules stay behind typed ApplicationService.

use core::future::poll_fn;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Path, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use openbot_contracts::command::{AppCommand, AppEvent, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::tool::{PendingToolApprovals, ToolApprovalDecision, ToolApprovalResolved};
use serde::Deserialize;

use crate::auth::{Authenticated, OriginAuthenticated, SensitiveAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// Closed read-only approval activity protocol.
pub const TOOL_APPROVAL_ACTIVITY_PROTOCOL: &str = "openbot.tool-approvals.v1";
const TOOL_APPROVAL_INPUT_LIMIT: usize = 1024;

/// `GET /api/tool-approvals`; current actor only, no-store.
pub async fn pending_get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<(HeaderMap, Json<PendingToolApprovals>), HttpError> {
    let approvals = match state
        .application()
        .execute(auth, AppCommand::ListPendingToolApprovals)
        .await?
    {
        AppReply::PendingToolApprovals(approvals) => approvals,
        _ => return Err(application_contract_error()),
    };
    Ok((no_store(), Json(approvals)))
}

/// `GET /api/tool-approvals/events`; actor-scoped, same-origin, read-only WebSocket.
pub async fn events(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if !ws
        .requested_protocols()
        .any(|protocol| protocol == TOOL_APPROVAL_ACTIVITY_PROTOCOL)
    {
        return Err(AppError::MalformedPayload {
            field: "websocket_protocol",
        }
        .into());
    }
    let (stream, authority) =
        super::realtime::subscribe(&state, auth, SubscriptionRequest::ToolApprovalActivity).await?;
    Ok(ws
        .protocols([TOOL_APPROVAL_ACTIVITY_PROTOCOL])
        .max_message_size(TOOL_APPROVAL_INPUT_LIMIT)
        .max_frame_size(TOOL_APPROVAL_INPUT_LIMIT)
        .on_failed_upgrade(|error| {
            tracing::debug!(error = %error, "tool approval websocket upgrade failed");
        })
        .on_upgrade(move |socket| drive_activity_socket(socket, stream, authority)))
}

async fn drive_activity_socket(
    mut socket: WebSocket,
    mut stream: openbot_application::AppEventStream,
    authority: super::realtime::RealtimeAuthority,
) {
    loop {
        tokio::select! {
            event = poll_fn(|cx| stream.as_mut().poll_next(cx)) => {
                let Some(event) = event else {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: close_code::NORMAL,
                        reason: "stream_complete".into(),
                    }))).await;
                    return;
                };
                let (text, terminal) = match event {
                    AppEvent::ToolApprovalActivity(event) => match serde_json::to_string(&event) {
                        Ok(text) => (text, false),
                        Err(error) => {
                            tracing::error!(error = %error, "typed tool approval activity encoding failed");
                            let _ = socket.send(Message::Close(Some(CloseFrame {
                                code: close_code::ERROR,
                                reason: "event_encoding_failed".into(),
                            }))).await;
                            return;
                        }
                    },
                    AppEvent::ToolApprovalStreamError { code } => {
                        (serde_json::json!({"error":{"code":code}}).to_string(), true)
                    }
                    AppEvent::Heartbeat { .. }
                    | AppEvent::ThreadRunEvent(_)
                    | AppEvent::ThreadStreamError { .. }
                    | AppEvent::ChannelActivity(_)
                    | AppEvent::ChannelStreamError { .. } => {
                        tracing::error!("approval subscription emitted non-approval event");
                        let _ = socket.send(Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "application_contract_failed".into(),
                        }))).await;
                        return;
                    }
                };
                if super::realtime::send(&mut socket, Message::Text(text.into()), &authority).await.is_err() {
                    return;
                }
                if terminal {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: close_code::ERROR,
                        reason: "approval_stream_failed".into(),
                    }))).await;
                    return;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return,
                Some(Ok(Message::Text(_) | Message::Binary(_))) => {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: close_code::POLICY,
                        reason: "tool_approval_activity_read_only".into(),
                    }))).await;
                    return;
                }
                Some(Err(error)) => {
                    tracing::debug!(error = %error, "tool approval websocket input failed");
                    return;
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// Closed decision body; actor/binding/expiry cannot be supplied by the renderer.
pub struct ApprovalDecisionBody {
    decision: ToolApprovalDecision,
}

/// `POST /api/tool-approvals/{approval_id}`; fresh same-origin proof before body parse.
pub async fn decision_post(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    headers: HeaderMap,
    Path(approval_id): Path<String>,
    body: Result<Json<ApprovalDecisionBody>, JsonRejection>,
) -> Result<(HeaderMap, Json<ToolApprovalResolved>), HttpError> {
    state
        .authorize_fresh_origin_write(&resolved, request_origin(&headers))
        .await?;
    let Json(body) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "tool approval decision body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    let receipt = match state
        .application()
        .execute(
            resolved.into_context(),
            AppCommand::DecideToolApproval {
                approval_id,
                decision: body.decision,
            },
        )
        .await?
    {
        AppReply::ToolApprovalResolved(receipt) => receipt,
        _ => return Err(application_contract_error()),
    };
    Ok((no_store(), Json(receipt)))
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::ORIGIN)
        .map(|value| value.to_str().unwrap_or(""))
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn application_contract_error() -> HttpError {
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::response::Response;
    use http::{Method, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::{
        AppEventStream, ApplicationService, ChannelReader, OpenBotApplication, PortError,
        ToolApprovalAdministration, ToolApprovalAdministrationError,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::AppEvent;
    use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ToolCallId};
    use openbot_contracts::tool::{
        PendingToolApproval, ToolApprovalActivityEvent, ToolApprovalClass, ToolApprovalEffect,
    };
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use crate::auth::{FixedAuthResolver, ResolvedAuth, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

    struct EmptyChannels;

    #[async_trait]
    impl ChannelReader for EmptyChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<openbot_contracts::command::ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        List(ActorId),
        Decide(ActorId, String, ToolApprovalDecision),
        Subscribe(ActorId),
    }

    #[derive(Clone, Default)]
    struct FakeApprovals {
        calls: Arc<Mutex<Vec<Call>>>,
        events: Arc<Vec<AppEvent>>,
    }

    impl FakeApprovals {
        fn with_events(events: Vec<AppEvent>) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(events),
            }
        }
    }

    #[async_trait]
    impl ToolApprovalAdministration for FakeApprovals {
        async fn list_pending(
            &self,
            auth: &AuthContext,
        ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError> {
            self.calls
                .lock()
                .unwrap()
                .push(Call::List(auth.actor().clone()));
            Ok(PendingToolApprovals {
                approvals: vec![PendingToolApproval {
                    approval_id: "approval-1".to_owned(),
                    call_id: ToolCallId::new("call-1"),
                    run_id: RunId::new("run-1"),
                    bot_id: BotId::new("bot-1"),
                    tool_name: "mcp__notes__delete".to_owned(),
                    target_kind: "mcp_tool".to_owned(),
                    target_id: "notes/delete".to_owned(),
                    effect: ToolApprovalEffect::Write,
                    approval_class: ToolApprovalClass::EveryCall,
                    arguments_summary: serde_json::json!({"id":"note-1"}),
                    change_summary: None,
                    requested_at: OffsetDateTime::UNIX_EPOCH,
                    expires_at: OffsetDateTime::UNIX_EPOCH + Duration::minutes(5),
                }],
            })
        }

        async fn decide(
            &self,
            auth: &AuthContext,
            approval_id: &str,
            decision: ToolApprovalDecision,
        ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError> {
            self.calls.lock().unwrap().push(Call::Decide(
                auth.actor().clone(),
                approval_id.to_owned(),
                decision,
            ));
            Ok(ToolApprovalResolved {
                approval_id: approval_id.to_owned(),
                decision,
            })
        }

        async fn subscribe_activity(
            &self,
            auth: &AuthContext,
        ) -> Result<AppEventStream, ToolApprovalAdministrationError> {
            use futures_util::StreamExt as _;

            self.calls
                .lock()
                .unwrap()
                .push(Call::Subscribe(auth.actor().clone()));
            Ok(Box::pin(
                futures_util::stream::iter(self.events.as_ref().clone())
                    .chain(futures_util::stream::pending()),
            ))
        }
    }

    fn router(approvals: FakeApprovals) -> Router {
        let generation = AuthGeneration::new(1);
        let context = AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            generation,
            false,
        );
        let now = OffsetDateTime::now_utc();
        let lifetime = default_session_lifetime();
        let live = evaluate_session(
            lifetime,
            SessionState::rehydrate(now - Duration::minutes(1), now, generation),
            generation,
            now,
        )
        .unwrap();
        let resolver = FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(
            context, live, None,
        ));
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels).with_tool_approvals(Arc::new(approvals)),
        );
        crate::router(
            ServerBuilder::new(application, Arc::new(resolver))
                .with_sensitive_write_security(SensitiveWriteSecurity::new(
                    lifetime,
                    TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
                ))
                .build(),
        )
    }

    async fn send(
        router: Router,
        method: Method,
        uri: &str,
        origin: Option<&str>,
        body: &'static str,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(uri);
        if !body.is_empty() {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
        }
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        router
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn pending_and_decision_routes_are_no_store_typed_and_guard_before_parse() {
        let approvals = FakeApprovals::default();
        let pending = send(
            router(approvals.clone()),
            Method::GET,
            "/api/tool-approvals",
            None,
            "",
        )
        .await;
        assert_eq!(pending.status(), StatusCode::OK);
        assert_eq!(pending.headers()[CACHE_CONTROL], "no-store");
        let body = to_bytes(pending.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["approvals"][0]["argumentsSummary"]
                ["id"],
            "note-1"
        );

        let before_parse = send(
            router(approvals.clone()),
            Method::POST,
            "/api/tool-approvals/approval-1",
            None,
            "{",
        )
        .await;
        assert_eq!(before_parse.status(), StatusCode::FORBIDDEN);
        assert_eq!(approvals.calls.lock().unwrap().len(), 1);

        let extra = send(
            router(approvals.clone()),
            Method::POST,
            "/api/tool-approvals/approval-1",
            Some("https://app.example.test"),
            r#"{"decision":"grant","actor":"admin"}"#,
        )
        .await;
        assert_eq!(extra.status(), StatusCode::BAD_REQUEST);
        assert_eq!(approvals.calls.lock().unwrap().len(), 1);

        let granted = send(
            router(approvals.clone()),
            Method::POST,
            "/api/tool-approvals/approval-1",
            Some("https://app.example.test"),
            r#"{"decision":"grant"}"#,
        )
        .await;
        assert_eq!(granted.status(), StatusCode::OK);
        assert_eq!(granted.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            approvals.calls.lock().unwrap().as_slice(),
            [
                Call::List(ActorId::new("actor")),
                Call::Decide(
                    ActorId::new("actor"),
                    "approval-1".to_owned(),
                    ToolApprovalDecision::Grant
                )
            ]
        );
    }

    #[tokio::test]
    async fn approval_activity_websocket_is_actor_scoped_typed_and_read_only() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let approvals = FakeApprovals::with_events(vec![AppEvent::ToolApprovalActivity(
            ToolApprovalActivityEvent { pending_count: 1 },
        )]);
        let observed = approvals.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind approval websocket test");
        let address = listener.local_addr().expect("approval test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(approvals))
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        let (mut socket, _) = approval_websocket(address, true, true)
            .await
            .expect("trusted approval websocket handshake");
        let event = socket
            .next()
            .await
            .expect("approval event")
            .expect("valid approval event");
        let ClientMessage::Text(text) = event else {
            panic!("approval event must be text: {event:?}");
        };
        assert_eq!(
            serde_json::from_str::<ToolApprovalActivityEvent>(text.as_str()).unwrap(),
            ToolApprovalActivityEvent { pending_count: 1 }
        );
        assert_eq!(
            observed.calls.lock().unwrap().as_slice(),
            [Call::Subscribe(ActorId::new("actor"))]
        );

        socket
            .send(ClientMessage::Text("forged client event".into()))
            .await
            .expect("send read-only violation");
        let close = socket
            .next()
            .await
            .expect("policy close")
            .expect("valid policy close");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy)
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn approval_activity_handshake_requires_trusted_origin_and_exact_protocol() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind approval websocket test");
        let address = listener.local_addr().expect("approval test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(FakeApprovals::default()))
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        assert!(approval_websocket(address, false, true).await.is_err());
        assert!(approval_websocket(address, true, false).await.is_err());
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn approval_activity_terminal_error_is_a_stable_frame_then_error_close() {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let approvals = FakeApprovals::with_events(vec![AppEvent::ToolApprovalStreamError {
            code: "not_visible".to_owned(),
        }]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind approval websocket test");
        let address = listener.local_addr().expect("approval test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(approvals))
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        let (mut socket, _) = approval_websocket(address, true, true)
            .await
            .expect("trusted approval websocket handshake");
        let event = socket
            .next()
            .await
            .expect("approval error frame")
            .expect("valid approval error frame");
        let ClientMessage::Text(text) = event else {
            panic!("approval error must be text: {event:?}");
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(text.as_str()).unwrap(),
            serde_json::json!({"error":{"code":"not_visible"}})
        );
        let close = socket
            .next()
            .await
            .expect("approval error close")
            .expect("valid approval error close");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Error)
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    type ClientSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
    type ClientHandshake = Result<
        (ClientSocket, http::Response<Option<Vec<u8>>>),
        tokio_tungstenite::tungstenite::Error,
    >;

    async fn approval_websocket(
        address: std::net::SocketAddr,
        origin: bool,
        protocol: bool,
    ) -> ClientHandshake {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

        let mut request = format!("ws://{address}/api/tool-approvals/events")
            .into_client_request()
            .expect("approval websocket request");
        if origin {
            request.headers_mut().insert(
                http::header::ORIGIN,
                http::HeaderValue::from_static("https://app.example.test"),
            );
        }
        if protocol {
            request.headers_mut().insert(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(TOOL_APPROVAL_ACTIVITY_PROTOCOL),
            );
        }
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect approval websocket test");
        tokio_tungstenite::client_async(request, stream).await
    }
}
