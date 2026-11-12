//! Server same-origin ScreenSession issuance and read-only binary WebSocket framing.

mod budget;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{OriginalUri, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use openbot_computer::screen::{
    SCREEN_VIEWER_MAX_BINARY_BYTES, SCREEN_VIEWER_PROTOCOL, ScreenHubError, ScreenViewer,
    ScreenViewerBinding, ScreenViewerFrame,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::recovery::RecoveryAdmissionLease;
use openbot_contracts::request_binding::VerifiedHostRequestBinding;
use openbot_contracts::screen::{
    ScreenSessionRequest, ScreenSessionTarget, ScreenSessionTicket, ScreenViewerBindingRequest,
};
use time::OffsetDateTime;
use tokio::time::{Instant, sleep_until, timeout};

use self::budget::{CLOSE_TIMEOUT, DeliveryBudget, SOCKET_LIMITS, SocketLimits};

use crate::auth::OriginBoundAuthenticated;
use crate::error::HttpError;
use crate::http::ServerState;

const SCREEN_WS_INPUT_LIMIT: usize = 1024;

#[cfg(test)]
const SERVER_SCREEN_FIXTURE: &str =
    include_str!("../../../../fixtures/computer/server-screen-websocket-v1.json");

/// `POST /api/screen/sessions`: issue one ticket after same-origin auth, never from body identity.
pub async fn issue_session(
    State(state): State<ServerState>,
    bound: OriginBoundAuthenticated,
    body: Result<Json<ScreenSessionTarget>, JsonRejection>,
) -> Result<(HeaderMap, Json<ScreenSessionTicket>), HttpError> {
    let Json(target) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "screen session body rejected");
        AppError::MalformedPayload { field: "body" }
    })?;
    let (auth, origin) = bound.into_parts();
    let reply = state
        .application()
        .execute(
            auth,
            AppCommand::IssueScreenSession(ScreenSessionRequest {
                target,
                binding: ScreenViewerBindingRequest::Server { origin },
            }),
        )
        .await?;
    let AppReply::ScreenSession(ticket) = reply else {
        tracing::error!("IssueScreenSession received a non-ScreenSession application reply");
        return Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into());
    };
    Ok((no_store(), Json(ticket)))
}

/// `GET /api/screen`: consume one ticket from requested subprotocols and stream binary latest-frame.
pub async fn websocket(
    State(state): State<ServerState>,
    bound: OriginBoundAuthenticated,
    OriginalUri(uri): OriginalUri,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    websocket_with_limits(state, bound, uri, ws, SOCKET_LIMITS).await
}

async fn websocket_with_limits(
    state: ServerState,
    bound: OriginBoundAuthenticated,
    uri: http::Uri,
    ws: WebSocketUpgrade,
    limits: SocketLimits,
) -> Result<Response, HttpError> {
    if uri.query().is_some() {
        return Err(AppError::MalformedPayload {
            field: "websocket_query",
        }
        .into());
    }
    let ticket_protocol = requested_ticket(&ws)?;
    let (auth, origin) = bound.into_parts();
    let binding = ScreenViewerBinding::verified_server(origin)
        .map_err(|_| AppError::MalformedPayload { field: "origin" })?;
    let hub = state.screen_hub().ok_or(AppError::DependencyUnavailable {
        dependency: "screen_hub",
    })?;
    let mut viewer = hub
        .consume_ticket(
            &auth,
            &binding,
            ticket_protocol.as_str(),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(screen_error)?;
    let first = viewer.current().map_err(screen_error)?;
    Ok(ws
        .protocols([SCREEN_VIEWER_PROTOCOL])
        .max_message_size(SCREEN_WS_INPUT_LIMIT)
        .max_frame_size(SCREEN_WS_INPUT_LIMIT)
        .write_buffer_size(0)
        .max_write_buffer_size(SCREEN_VIEWER_MAX_BINARY_BYTES + SCREEN_WS_INPUT_LIMIT)
        .on_failed_upgrade(|error| {
            tracing::debug!(error = %error, "screen websocket upgrade failed");
        })
        .on_upgrade(move |socket| async move {
            drive_screen_socket(socket, viewer, first, limits, &auth).await;
        }))
}

fn requested_ticket(ws: &WebSocketUpgrade) -> Result<String, AppError> {
    let mut count = 0_u8;
    let mut base_seen = false;
    let mut ticket = None;
    for protocol in ws.requested_protocols() {
        count = count.saturating_add(1);
        if count > 2 {
            return Err(AppError::MalformedPayload {
                field: "websocket_protocol",
            });
        }
        if protocol == SCREEN_VIEWER_PROTOCOL {
            if base_seen {
                return Err(AppError::MalformedPayload {
                    field: "websocket_protocol",
                });
            }
            base_seen = true;
        } else {
            let value = protocol.to_str().map_err(|_| AppError::MalformedPayload {
                field: "websocket_protocol",
            })?;
            if ticket.replace(value.to_owned()).is_some() {
                return Err(AppError::MalformedPayload {
                    field: "websocket_protocol",
                });
            }
        }
    }
    if count != 2 || !base_seen {
        return Err(AppError::MalformedPayload {
            field: "websocket_protocol",
        });
    }
    ticket.ok_or(AppError::MalformedPayload {
        field: "websocket_protocol",
    })
}

async fn drive_screen_socket(
    mut socket: WebSocket,
    mut viewer: ScreenViewer,
    first: std::sync::Arc<ScreenViewerFrame>,
    limits: SocketLimits,
    auth: &AuthContext,
) {
    let Some(binding) = auth.request_binding() else {
        close(&mut socket, close_code::POLICY, "screen_revoked").await;
        return;
    };
    let mut admission = None;
    let mut budget = DeliveryBudget::new(limits, Instant::now());
    if !admitted(&mut admission, binding, auth).await {
        close(&mut socket, close_code::POLICY, "screen_revoked").await;
        return;
    }
    if send_frame(&mut socket, &first, &mut budget, limits)
        .await
        .is_err()
    {
        return;
    }
    // Release the initial frame before waiting: the viewer never retains a second stale image.
    drop(first);
    loop {
        tokio::select! {
            biased;
            () = sleep_until(budget.wake_at()) => {
                let now = Instant::now();
                if budget.idle(now) {
                    close(&mut socket, close_code::POLICY, "screen_idle").await;
                    return;
                }
                if let Some(challenge) = budget.ping(now)
                    && send_bounded(&mut socket, Message::Ping(challenge.to_vec().into()), limits.write).await.is_err() {
                    return;
                }
            },
            incoming = socket.recv() => {
                if !budget.incoming(Instant::now()) {
                    close(&mut socket, close_code::POLICY, "screen_control_rate").await;
                    return;
                }
                match incoming {
                    // Tungstenite replaces its queued automatic reply with this same exact Pong
                    // before flushing. No second frame or unbounded flush task is created.
                    Some(Ok(Message::Ping(payload))) => {
                        if send_bounded(&mut socket, Message::Pong(payload), limits.write).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Pong(payload))) => budget.pong(&payload, Instant::now()),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                    Some(Ok(Message::Text(_) | Message::Binary(_))) => {
                        close(&mut socket, close_code::POLICY, "screen_input_not_enabled").await;
                        return;
                    }
                }
            },
            frame = viewer.next() => match frame {
                Ok(frame) => {
                    if !admitted(&mut admission, binding, auth).await {
                        close(&mut socket, close_code::POLICY, "screen_revoked").await;
                        return;
                    }
                    if send_frame(&mut socket, &frame, &mut budget, limits).await.is_err() {
                        return;
                    }
                }
                Err(_) => {
                    close(&mut socket, close_code::POLICY, "screen_revoked").await;
                    return;
                }
            }
        }
    }
}

/// The original request's recovery admission, held across frame sends. Each
/// lease is bounded by the 5 s precedent; an elapsed one is dropped and
/// borrowed again, and a refused borrow ends the stream.
async fn admitted<'a>(
    held: &mut Option<(RecoveryAdmissionLease<'a>, std::time::Instant)>,
    binding: &'a VerifiedHostRequestBinding,
    auth: &'a AuthContext,
) -> bool {
    if let Some((lease, deadline)) = held
        && lease
            .verify_current_before(binding, auth, *deadline)
            .is_ok()
    {
        return true;
    }
    *held = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    match binding
        .borrow_recovery_admission_before(auth, deadline)
        .await
    {
        Ok(lease) => {
            *held = Some((lease, deadline));
            true
        }
        Err(_) => false,
    }
}

async fn send_frame(
    socket: &mut WebSocket,
    frame: &ScreenViewerFrame,
    budget: &mut DeliveryBudget,
    limits: SocketLimits,
) -> Result<(), ()> {
    if frame.binary().len() > SCREEN_VIEWER_MAX_BINARY_BYTES {
        close(socket, close_code::ERROR, "screen_frame_too_large").await;
        return Err(());
    }
    if !budget.frame(frame.binary().len(), Instant::now()) {
        close(socket, close_code::POLICY, "screen_bandwidth").await;
        return Err(());
    }
    send_bounded(
        socket,
        Message::Binary(frame.binary().to_vec().into()),
        limits.write,
    )
    .await
}

async fn send_bounded(
    socket: &mut WebSocket,
    message: Message,
    limit: std::time::Duration,
) -> Result<(), ()> {
    bounded_write(socket.send(message), limit).await
}

async fn bounded_write<E>(
    write: impl std::future::Future<Output = Result<(), E>>,
    limit: std::time::Duration,
) -> Result<(), ()> {
    match timeout(limit, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = send_bounded(
        socket,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        CLOSE_TIMEOUT,
    )
    .await;
}

fn screen_error(error: ScreenHubError) -> AppError {
    match error {
        ScreenHubError::NotVisible
        | ScreenHubError::SourceClosed
        | ScreenHubError::TicketInvalid
        | ScreenHubError::TicketExpired
        | ScreenHubError::ViewerRevoked => AppError::NotVisible,
        ScreenHubError::InvalidBinding | ScreenHubError::InvalidViewerLimit => {
            AppError::MalformedPayload { field: "screen" }
        }
        ScreenHubError::ViewerLimit => AppError::RequestConflict {
            resource: "screen_viewers",
        },
        ScreenHubError::DuplicateStream
        | ScreenHubError::RandomFailed
        | ScreenHubError::RandomCollision
        | ScreenHubError::ClockOverflow
        | ScreenHubError::Frame => AppError::DependencyUnavailable {
            dependency: "screen_hub",
        },
    }
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use futures_util::{SinkExt as _, StreamExt as _};
    use openbot_application::{
        ApplicationService, ChannelCursor, ChannelReader, OpenBotApplication, PortError,
    };
    use openbot_computer::screen::testing::attach_test_stream;
    use openbot_computer::screen::{SCREEN_VIEWER_PROTOCOL, ScreenHub, ScreenSessionService};
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{
        ActorId, ComputerGeneration, ComputerId, DeploymentId, TabId, TenantId,
    };
    use openbot_contracts::screen::{ScreenSessionTarget, ScreenSessionTicket};
    use openbot_domain::identity::session::{SessionState, TrustedOrigins, evaluate_session};
    use openbot_infra::auth::config::default_session_lifetime;
    use time::{Duration, OffsetDateTime};
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tower::ServiceExt as _;

    use super::SERVER_SCREEN_FIXTURE;
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
        ) -> Result<Vec<ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(4),
            false,
        )
    }

    fn router(hub: ScreenHub, auth: AuthContext) -> Router {
        crate::router(server_state(hub, auth))
    }

    fn server_state(hub: ScreenHub, auth: AuthContext) -> crate::http::ServerState {
        let now = OffsetDateTime::now_utc();
        let lifetime = default_session_lifetime();
        let live = evaluate_session(
            lifetime,
            SessionState::rehydrate(now - Duration::minutes(1), now, auth.auth_generation()),
            auth.auth_generation(),
            now,
        )
        .expect("live session");
        let resolver =
            FixedAuthResolver::granting_resolved(ResolvedAuth::from_live_session(auth, live, None));
        let application: Arc<dyn ApplicationService> = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_screen_sessions(Arc::new(ScreenSessionService::new(hub.clone()))),
        );
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                lifetime,
                TrustedOrigins::from_configured(["https://app.example.test"])
                    .expect("trusted origin"),
            ))
            .with_screen_hub(hub)
            .build()
    }

    async fn issue(
        router: Router,
        target: &ScreenSessionTarget,
    ) -> (StatusCode, ScreenSessionTicket) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/screen/sessions")
                    .header(http::header::ORIGIN, "https://app.example.test")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(target).expect("screen target wire"),
                    ))
                    .expect("screen session request"),
            )
            .await
            .expect("screen session response");
        let status = response.status();
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096)
            .await
            .expect("screen session body");
        let ticket = serde_json::from_slice(&bytes).expect("screen ticket");
        (status, ticket)
    }

    type ClientSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    async fn connect(
        address: std::net::SocketAddr,
        protocols: &str,
    ) -> Result<
        (ClientSocket, http::Response<Option<Vec<u8>>>),
        tokio_tungstenite::tungstenite::Error,
    > {
        connect_path(address, "/api/screen", protocols).await
    }

    async fn connect_path(
        address: std::net::SocketAddr,
        path: &str,
        protocols: &str,
    ) -> Result<
        (ClientSocket, http::Response<Option<Vec<u8>>>),
        tokio_tungstenite::tungstenite::Error,
    > {
        let mut request = format!("ws://{address}{path}")
            .into_client_request()
            .expect("screen websocket request");
        request.headers_mut().insert(
            http::header::ORIGIN,
            http::HeaderValue::from_static("https://app.example.test"),
        );
        request.headers_mut().insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_str(protocols).expect("protocol header"),
        );
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect screen websocket");
        tokio_tungstenite::client_async(request, stream).await
    }

    #[tokio::test]
    async fn same_origin_ticket_streams_binary_selects_only_base_and_replay_fails() {
        let auth = auth();
        let hub = ScreenHub::new(3).expect("hub");
        let target = ScreenSessionTarget {
            computer_id: ComputerId::new("computer"),
            computer_generation: ComputerGeneration::new(3),
            tab_id: TabId::new("tab"),
        };
        let feed = attach_test_stream(
            &hub,
            &auth,
            target.computer_id.clone(),
            target.computer_generation,
            target.tab_id.clone(),
        )
        .await
        .expect("test stream");
        let router = router(hub.clone(), auth.clone());
        let (status, ticket) = issue(router.clone(), &target).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ticket.base_protocol(), SCREEN_VIEWER_PROTOCOL);
        assert!(!format!("{ticket:?}").contains(ticket.ticket_protocol()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind screen websocket");
        let address = listener.local_addr().expect("screen address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        let requested = format!("{}, {}", ticket.base_protocol(), ticket.ticket_protocol());
        let (mut socket, response) = connect(address, requested.as_str())
            .await
            .expect("screen handshake");
        assert_eq!(
            response.headers()[http::header::SEC_WEBSOCKET_PROTOCOL],
            SCREEN_VIEWER_PROTOCOL
        );
        assert!(
            !response.headers()[http::header::SEC_WEBSOCKET_PROTOCOL]
                .to_str()
                .expect("selected protocol")
                .contains(ticket.ticket_protocol())
        );
        let first = socket.next().await.expect("first frame").expect("frame");
        assert!(matches!(first, ClientMessage::Binary(bytes) if bytes.starts_with(b"OBSCRN01")));

        feed.publish(2, 20.0);
        let next = socket.next().await.expect("next frame").expect("frame");
        assert!(matches!(next, ClientMessage::Binary(bytes) if bytes.starts_with(b"OBSCRN01")));
        socket
            .send(ClientMessage::Text("forged input".into()))
            .await
            .expect("send rejected input");
        let close = socket.next().await.expect("policy close").expect("close");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy)
        );

        assert!(connect(address, requested.as_str()).await.is_err());
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn handshake_rejects_protocol_shape_and_generation_invalidation_closes_viewer() {
        let auth = auth();
        let hub = ScreenHub::new(2).expect("hub");
        let target = ScreenSessionTarget {
            computer_id: ComputerId::new("computer-generation"),
            computer_generation: ComputerGeneration::new(8),
            tab_id: TabId::new("tab-generation"),
        };
        let _feed = attach_test_stream(
            &hub,
            &auth,
            target.computer_id.clone(),
            target.computer_generation,
            target.tab_id.clone(),
        )
        .await
        .expect("test stream");
        let router = router(hub.clone(), auth.clone());
        let (_, ticket) = issue(router.clone(), &target).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind screen websocket");
        let address = listener.local_addr().expect("screen address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        assert!(connect(address, SCREEN_VIEWER_PROTOCOL).await.is_err());
        assert!(
            connect(
                address,
                format!(
                    "{}, {}, extra",
                    SCREEN_VIEWER_PROTOCOL,
                    ticket.ticket_protocol()
                )
                .as_str(),
            )
            .await
            .is_err()
        );
        let requested = format!("{}, {}", SCREEN_VIEWER_PROTOCOL, ticket.ticket_protocol());
        assert!(
            connect_path(
                address,
                "/api/screen?ticket=must-not-be-read",
                requested.as_str(),
            )
            .await
            .is_err()
        );
        let (mut socket, _) = connect(address, requested.as_str())
            .await
            .expect("valid screen handshake");
        let _ = socket.next().await.expect("initial frame").expect("frame");
        assert_eq!(
            hub.invalidate_actor(auth.tenant(), auth.actor(), AuthGeneration::new(5))
                .await,
            1
        );
        let close = socket
            .next()
            .await
            .expect("revocation close")
            .expect("close");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy)
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn session_issue_rejects_origin_before_parsing_an_attacker_body() {
        let response = router(ScreenHub::new(1).expect("hub"), auth())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/screen/sessions")
                    .header(http::header::ORIGIN, "https://evil.example.test")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .expect("wrong-origin request"),
            )
            .await
            .expect("wrong-origin response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("error body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("error JSON"),
            serde_json::json!({"code":"identity_sensitive_write_origin_untrusted"})
        );
    }

    struct BudgetTransport {
        hub: ScreenHub,
        target: ScreenSessionTarget,
        feed: openbot_computer::screen::testing::TestScreenFeed,
        router: Router,
        address: std::net::SocketAddr,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for BudgetTransport {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl BudgetTransport {
        async fn start(limits: super::SocketLimits) -> Self {
            let hub = ScreenHub::new(1).expect("one viewer slot");
            let target = ScreenSessionTarget {
                computer_id: ComputerId::new("budget-computer"),
                computer_generation: ComputerGeneration::new(1),
                tab_id: TabId::new("budget-tab"),
            };
            let feed = attach_test_stream(
                &hub,
                &auth(),
                target.computer_id.clone(),
                target.computer_generation,
                target.tab_id.clone(),
            )
            .await
            .expect("source");
            // Only durations/byte ceiling differ. The production Origin/ticket/upgrade/driver
            // path is identical, and no configuration seam is available from HTTP or renderer.
            let router = Router::new()
                .route(
                    "/api/screen/sessions",
                    axum::routing::post(super::issue_session),
                )
                .route(
                    "/api/screen",
                    axum::routing::get(
                        move |axum::extract::State(state),
                              bound,
                              axum::extract::OriginalUri(uri),
                              ws| {
                            super::websocket_with_limits(state, bound, uri, ws, limits)
                        },
                    ),
                )
                .with_state(server_state(hub.clone(), auth()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let address = listener.local_addr().expect("address");
            let app = router.clone();
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            Self {
                hub,
                target,
                feed,
                router,
                address,
                server,
            }
        }

        async fn socket(&self) -> ClientSocket {
            let (_, ticket) = issue(self.router.clone(), &self.target).await;
            connect(
                self.address,
                &format!("{}, {}", ticket.base_protocol(), ticket.ticket_protocol()),
            )
            .await
            .expect("connect")
            .0
        }

        async fn slot_released(&self) {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    match self
                        .hub
                        .issue_ticket_for_target(
                            &auth(),
                            &self.target.computer_id,
                            self.target.computer_generation,
                            &self.target.tab_id,
                            openbot_computer::screen::ScreenViewerBinding::verified_server(
                                "https://app.example.test",
                            )
                            .expect("binding"),
                            OffsetDateTime::now_utc(),
                        )
                        .await
                    {
                        Ok(_) => break,
                        Err(openbot_computer::screen::ScreenHubError::ViewerLimit) => {
                            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        }
                        Err(error) => panic!("unexpected slot error: {error:?}"),
                    }
                }
            })
            .await
            .expect("viewer permit released");
        }
    }

    async fn policy_close(socket: &mut ClientSocket, reason: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match socket.next().await.expect("server message").expect("valid message") {
                    ClientMessage::Close(Some(frame)) => {
                        assert_eq!(frame.code, tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy);
                        assert_eq!(frame.reason, reason);
                        break;
                    }
                    ClientMessage::Binary(_) | ClientMessage::Ping(_) | ClientMessage::Pong(_) => {}
                    other => panic!("unexpected budget message: {other:?}"),
                }
            }
        }).await.expect("bounded policy close");
    }

    #[tokio::test]
    async fn bandwidth_and_control_flood_close_real_sockets_and_release_viewer_slots() {
        const TEST_BURST_BYTES: u64 = 256;
        let transport = BudgetTransport::start(super::SocketLimits {
            // Fits one valid synthetic JPEG plus its wire header, but not two frames.
            burst_bytes: TEST_BURST_BYTES,
            bytes_per_second: 1,
            ..super::SOCKET_LIMITS
        })
        .await;
        let mut socket = transport.socket().await;
        let Some(Ok(ClientMessage::Binary(first))) = socket.next().await else {
            panic!("one frame must fit the test burst");
        };
        let first_bytes = u64::try_from(first.len()).expect("frame bytes");
        assert!(first_bytes <= TEST_BURST_BYTES && first_bytes * 2 > TEST_BURST_BYTES);
        // The consumed ticket has become the sole active slot, so another issue must fail.
        let denied = transport
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/screen/sessions")
                    .header(http::header::ORIGIN, "https://app.example.test")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&transport.target).expect("target"),
                    ))
                    .expect("issue while full"),
            )
            .await
            .expect("capacity response");
        assert_eq!(denied.status(), StatusCode::CONFLICT);
        transport.feed.publish(2, 1.0);
        policy_close(&mut socket, "screen_bandwidth").await;
        transport.slot_released().await;

        let transport = BudgetTransport::start(super::SOCKET_LIMITS).await;
        let mut socket = transport.socket().await;
        let _ = socket.next().await.expect("initial").expect("frame");
        for _ in 0..21 {
            socket
                .feed(ClientMessage::Pong(vec![0; 8].into()))
                .await
                .expect("queue unsolicited pong");
        }
        socket.flush().await.expect("send flood in one write");
        policy_close(&mut socket, "screen_control_rate").await;
        transport.slot_released().await;
    }

    #[tokio::test]
    async fn idle_peer_expires_despite_outgoing_frames_and_live_pong_keeps_static_screen() {
        use std::time::Duration as StdDuration;
        let limits = super::SocketLimits {
            ping_interval: StdDuration::from_millis(60),
            idle: StdDuration::from_millis(240),
            ..super::SOCKET_LIMITS
        };
        let transport = BudgetTransport::start(limits).await;
        let mut socket = transport.socket().await;
        let _ = socket.next().await.expect("initial").expect("frame");
        // Deliberately never read/respond to the challenge while the source keeps changing.
        for seq in 2..=17 {
            transport.feed.publish(seq, 1.0);
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        policy_close(&mut socket, "screen_idle").await;
        transport.slot_released().await;

        let transport = BudgetTransport::start(limits).await;
        let mut socket = transport.socket().await;
        let _ = socket.next().await.expect("initial").expect("frame");
        let mut previous = None;
        for _ in 0..6 {
            let message = tokio::time::timeout(StdDuration::from_millis(180), socket.next())
                .await
                .expect("ping deadline")
                .expect("ping")
                .expect("valid ping");
            let ClientMessage::Ping(payload) = message else {
                panic!("expected ping");
            };
            assert_eq!(payload.len(), 8);
            assert_ne!(previous.as_ref(), Some(&payload));
            // Client's own RFC6455 implementation queues the matching Pong automatically.
            socket.flush().await.expect("flush matching pong");
            previous = Some(payload);
        }
        socket.close(None).await.expect("close healthy client");
        transport.slot_released().await;
    }

    #[tokio::test]
    async fn stalled_write_is_cancelled_and_write_failures_are_not_success() {
        let stalled = std::future::pending::<Result<(), ()>>();
        assert!(
            super::bounded_write(stalled, std::time::Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(
            super::bounded_write(async { Err(()) }, super::SOCKET_LIMITS.write)
                .await
                .is_err()
        );
        assert!(
            super::bounded_write(async { Ok::<_, ()>(()) }, super::SOCKET_LIMITS.write)
                .await
                .is_ok()
        );
    }

    #[test]
    fn delivery_fixture_locks_defaults_and_keeps_engine_lifecycle_unfinished() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/computer/screen-delivery-budget-v1.json"
        ))
        .expect("delivery fixture");
        let defaults = &fixture["serverDefaults"];
        assert_eq!(
            defaults["imageBytesPerSecond"],
            super::SOCKET_LIMITS.bytes_per_second
        );
        assert_eq!(
            defaults["imageBurstBytes"],
            super::SOCKET_LIMITS.burst_bytes
        );
        assert_eq!(
            defaults["pingIntervalMs"],
            super::SOCKET_LIMITS.ping_interval.as_millis() as u64
        );
        assert_eq!(
            defaults["idleMs"],
            super::SOCKET_LIMITS.idle.as_millis() as u64
        );
        assert_eq!(
            defaults["writeTimeoutMs"],
            super::SOCKET_LIMITS.write.as_millis() as u64
        );
        assert_eq!(
            defaults["closeTimeoutMs"],
            super::CLOSE_TIMEOUT.as_millis() as u64
        );
        assert_eq!(
            defaults["maxWriteBufferBytes"],
            super::SCREEN_VIEWER_MAX_BINARY_BYTES + super::SCREEN_WS_INPUT_LIMIT
        );
        for unfinished in [
            "kernelSendBufferSaturation",
            "productionManagerAttachesEngineSource",
            "lastViewerStopsScreencastWithinTwoSeconds",
            "productionAuthInvalidationHook",
            "desktopLoopback",
            "fpsAndCaptureToPaintLatency",
            "windowsRuntime",
            "linuxRunscRuntime",
        ] {
            assert_eq!(fixture["evidenceBoundary"][unfinished], false);
        }
    }

    #[test]
    fn fixture_locks_server_transport_and_remaining_production_boundary() {
        let fixture = serde_json::from_str::<serde_json::Value>(SERVER_SCREEN_FIXTURE)
            .expect("server screen fixture");
        assert_eq!(fixture["schema"], "openbot-server-screen-websocket-v1");
        assert_eq!(fixture["application"]["bindingFromJsonBody"], false);
        assert_eq!(fixture["server"]["ticketInUrlOrQuery"], false);
        assert_eq!(fixture["server"]["queryRejected"], true);
        assert_eq!(
            fixture["server"]["selectedProtocol"],
            SCREEN_VIEWER_PROTOCOL
        );
        assert_eq!(fixture["server"]["selectedProtocolContainsTicket"], false);
        assert_eq!(fixture["server"]["ticketSingleUse"], true);
        assert_eq!(fixture["server"]["defaultViewersPerStream"], 8);
        assert_eq!(
            fixture["server"]["outputFrameLimitBytes"],
            super::SCREEN_VIEWER_MAX_BINARY_BYTES
        );
        for completed in [
            "typedApplicationTicket",
            "serverSameOriginWebSocket",
            "realEngineToServerBinaryFrame",
            "productionServerHubAndPortComposition",
        ] {
            assert_eq!(fixture["evidenceBoundary"][completed], true);
        }
        for unfinished in [
            "productionManagerAttachesEngineSource",
            "postgresSessionCookieBrowser",
            "externalTlsTermination",
            "desktopLoopbackWebSocket",
            "viewerInputOverWebSocket",
            "bandwidthOrIdleLimit",
            "lastViewerStopsScreencastWithinTwoSeconds",
            "windowsRuntime",
            "linuxRunscRuntime",
        ] {
            assert_eq!(fixture["evidenceBoundary"][unfinished], false);
        }
    }
}
