//! Native thread mint/status HTTP framing（parity API T-API-0035/0036）。
//!
//! 两条路由都只做认证、path framing、typed command 与错误投影。状态真源固定为 PostgreSQL；
//! 不存在任何 Intelligence client、条件挂载或 fallback。

use core::convert::Infallible;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::future::poll_fn;

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Path, Query, Request, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive};
use axum::response::{IntoResponse, Response, Sse};
use futures_core::Stream;
use openbot_application::AppEventStream;
use openbot_contracts::begin_thread_run_wire::DecodedBeginThreadRunBody;
use openbot_contracts::command::{
    AppCommand, AppEvent, AppReply, BeginThreadRun, BeginThreadRunV2, CancelThreadRun,
    SubscriptionRequest, ThreadConversationSnapshot, ThreadHistory, ThreadMinted,
    ThreadRunCancellation, ThreadRunCancellationState, ThreadRunStarted, ThreadStatus,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{RunId, ThreadId};
use openbot_contracts::reconciliation::{
    MAX_RUN_RECONCILIATION_RESPONSE_BYTES, RunReconciliationQuery,
};
use serde::Deserialize;

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

const THREAD_EVENTS_WS_PROTOCOL: &str = "openbot.thread-events.v1";
const THREAD_EVENTS_WS_INPUT_LIMIT: usize = 1024;

/// Apply the read-only endpoint's cache policy even to extractor, method and outer body-limit
/// rejections. The transport admission middleware remains responsible for TLS/peer authority.
pub(super) async fn reconciliation_response_policy(
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let reconciliation_path = request
        .uri()
        .path()
        .strip_prefix("/api/threads/")
        .is_some_and(|suffix| {
            let parts = suffix.split('/').collect::<Vec<_>>();
            matches!(parts.as_slice(), [thread, "runs", run, "reconciliation"] | [thread, "runs", run, "reconciliation", "receipts"] if !thread.is_empty() && !run.is_empty())
        });
    let get = request.method() == axum::http::Method::GET;
    let mut response = next.run(request).await;
    if reconciliation_path {
        // A nonempty GET body is malformed regardless of whether the shared body cap caught it
        // before the handler. This does not change any other route's 413 contract.
        if get && response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            response =
                HttpError::from(AppError::MalformedPayload { field: "body" }).into_response();
        }
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Read the current persisted Unknown facts through the one Application entry point (R398).
pub async fn reconciliation(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<RunReconciliationQuery>, QueryRejection>,
    request: Request,
) -> Result<Response, HttpError> {
    reconciliation_read(
        state,
        auth,
        path,
        query,
        request,
        ReconciliationRead::Attempts,
    )
    .await
}

/// Read positive business receipts through the same authority and bounded framing as attempts.
pub async fn effect_receipts(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<RunReconciliationQuery>, QueryRejection>,
    request: Request,
) -> Result<Response, HttpError> {
    reconciliation_read(
        state,
        auth,
        path,
        query,
        request,
        ReconciliationRead::Receipts,
    )
    .await
}

#[derive(Clone, Copy)]
enum ReconciliationRead {
    Attempts,
    Receipts,
}

async fn reconciliation_read(
    state: ServerState,
    auth: openbot_contracts::auth::AuthContext,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    query: Result<Query<RunReconciliationQuery>, QueryRejection>,
    request: Request,
    kind: ReconciliationRead,
) -> Result<Response, HttpError> {
    // Axum performs the one actual path decode. Its percent decoder preserves malformed
    // escapes, so reject those raw triplets here to match the controlled Desktop protocol.
    if !valid_reconciliation_percent_escapes(request.uri().path()) {
        return Err(AppError::MalformedPayload { field: "path" }.into());
    }
    if request
        .uri()
        .query()
        .is_some_and(|raw| !valid_reconciliation_percent_escapes(raw))
    {
        return Err(AppError::MalformedPayload { field: "query" }.into());
    }
    let Path((thread_id, run_id)) =
        path.map_err(|_| AppError::MalformedPayload { field: "path" })?;
    let Query(query) = query.map_err(|_| AppError::MalformedPayload { field: "query" })?;
    let (after, limit) = query.into_parts()?;
    let body = axum::body::to_bytes(request.into_body(), 1)
        .await
        .map_err(|_| AppError::MalformedPayload { field: "body" })?;
    if !body.is_empty() {
        return Err(AppError::MalformedPayload { field: "body" }.into());
    }
    let thread_id = ThreadId::new(thread_id);
    let run_id = RunId::new(run_id);
    let command = match kind {
        ReconciliationRead::Attempts => AppCommand::GetRunReconciliation {
            thread_id,
            run_id,
            after,
            limit,
        },
        ReconciliationRead::Receipts => AppCommand::GetRunEffectReceipts {
            thread_id,
            run_id,
            after,
            limit,
        },
    };
    let reply = state.application().execute(auth, command).await?;
    let body = match (kind, reply) {
        (ReconciliationRead::Attempts, AppReply::RunReconciliation(snapshot)) => {
            serde_json::to_vec(&snapshot)
        }
        (ReconciliationRead::Receipts, AppReply::RunEffectReceipts(snapshot)) => {
            serde_json::to_vec(&snapshot)
        }
        _ => return Err(application_contract_error()),
    }
    .map_err(|_| application_contract_error())?;
    if body.len() > MAX_RUN_RECONCILIATION_RESPONSE_BYTES {
        return Err(application_contract_error());
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

fn valid_reconciliation_percent_escapes(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// `POST /api/threads/mint`：为已认证 actor 铸造当前 deployment 的 UUIDv8。
pub async fn mint(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
) -> Result<Json<ThreadMinted>, HttpError> {
    match state
        .application()
        .execute(auth, AppCommand::MintThreadId)
        .await?
    {
        AppReply::ThreadMinted(reply) => Ok(Json(reply)),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/threads/{thread_id}`：返回当前 actor scope 的 `known` 投影。
///
/// 非 UUID 由 application 返回 400；不存在、已删除、scope/membership 不符统一 200 false。
pub async fn status(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(thread_id): Path<String>,
) -> Result<Json<ThreadStatus>, HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetThreadStatus {
                thread_id: ThreadId::new(thread_id),
            },
        )
        .await?
    {
        AppReply::ThreadStatus(reply) => Ok(Json(reply)),
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/threads/{thread_id}/runs`; native durable first-turn framing.
pub async fn begin_run(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(thread_id): Path<String>,
    body: Result<Json<DecodedBeginThreadRunBody>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<ThreadRunStarted>), HttpError> {
    let Json(body) = body.map_err(|rejection| {
        let _ = rejection;
        AppError::MalformedPayload { field: "body" }
    })?;
    // Keep the original Json extractor's exact media-type and global body-limit behavior.
    // Its borrowed RawValue decoder checks the original selection lexeme before this dispatch.
    let thread_id = ThreadId::new(thread_id);
    let command = match body {
        DecodedBeginThreadRunBody::Legacy(body) => AppCommand::BeginThreadRun(BeginThreadRun {
            artifact_refs: body.artifact_refs,
            model_selection: body.model_selection,
            selected_skill_slugs: body.selected_skill_slugs,
            thread_id,
            run_id: body.run_id,
            bot_id: body.bot_id,
            anchor: body.anchor,
            message: body.message,
        }),
        DecodedBeginThreadRunBody::V2(body) => AppCommand::BeginThreadRunV2(BeginThreadRunV2 {
            artifact_refs: body.artifact_refs,
            model_selection: body.model_selection,
            selected_skill_slugs: body.selected_skill_slugs,
            thread_id,
            run_id: body.run_id,
            bot_id: body.bot_id,
            anchor: body.anchor,
            message: body.message,
        }),
    };
    match state.application().execute(auth, command).await? {
        AppReply::ThreadRunStarted(started) => {
            let status = if started.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((status, headers, Json(started)))
        }
        _ => Err(application_contract_error()),
    }
}

/// `POST /api/threads/{thread_id}/runs/{run_id}/cancel`; durable control request framing.
pub async fn cancel_run(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path((thread_id, run_id)): Path<(String, String)>,
) -> Result<(StatusCode, HeaderMap, Json<ThreadRunCancellation>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::CancelThreadRun(CancelThreadRun {
                thread_id: ThreadId::new(thread_id),
                run_id: RunId::new(run_id),
            }),
        )
        .await?
    {
        AppReply::ThreadRunCancellation(reply) => {
            let outcome = match reply.state {
                ThreadRunCancellationState::Requested => "requested",
                ThreadRunCancellationState::AlreadyRequested => "already_requested",
                ThreadRunCancellationState::AlreadyTerminal => "already_terminal",
            };
            metrics::counter!(
                "openbot_agent_run_cancel_requests_total",
                "outcome" => outcome
            )
            .increment(1);
            let status = if reply.state == ThreadRunCancellationState::AlreadyTerminal {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((status, headers, Json(reply)))
        }
        _ => Err(application_contract_error()),
    }
}

/// 固定上游 compatibility query；`agentId` 只维持 wire，不参与 native ACL/过滤。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryQuery {
    /// 上游 runtime agent id；native thread 自身已是唯一 history 真源。
    pub agent_id: String,
}

/// `GET /api/copilotkit/threads/{thread_id}/messages` compatibility history。
///
/// unknown/new/invisible/deleted 全部 200 + `{"messages":[]}`；坏 UUID/query 400，数据库故障
/// 503。`agentId` 不得覆盖 AuthContext scope。
pub async fn history(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(thread_id): Path<String>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Json<ThreadHistory>, HttpError> {
    let Query(query) = query.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "thread history query 解析失败");
        AppError::MalformedPayload { field: "query" }
    })?;
    if query.agent_id.is_empty() {
        return Err(AppError::MalformedPayload { field: "agent_id" }.into());
    }
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetThreadHistory {
                thread_id: ThreadId::new(thread_id),
            },
        )
        .await?
    {
        AppReply::ThreadHistory(history) => Ok(Json(history)),
        _ => Err(application_contract_error()),
    }
}

/// `GET /api/threads/{thread_id}/conversation`; atomic native history/run/cursor snapshot.
pub async fn conversation(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(thread_id): Path<String>,
) -> Result<(HeaderMap, Json<ThreadConversationSnapshot>), HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetThreadConversation {
                thread_id: ThreadId::new(thread_id),
            },
        )
        .await?
    {
        AppReply::ThreadConversation(snapshot) => {
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok((headers, Json(snapshot)))
        }
        _ => Err(application_contract_error()),
    }
}

/// WebSocket reconnect query；cursor 是客户端最后完整接收的 thread-global sequence。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventWebSocketQuery {
    /// `None` 从第一条 durable event replay。
    pub cursor: Option<u64>,
}

/// `GET /api/threads/{thread_id}/ws`：与 SSE 共用同一 ApplicationService durable stream。
pub async fn websocket(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    Path(thread_id): Path<String>,
    query: Result<Query<EventWebSocketQuery>, QueryRejection>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    let Query(query) = query.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "thread websocket query 解析失败");
        AppError::MalformedPayload { field: "query" }
    })?;
    if !ws
        .requested_protocols()
        .any(|protocol| protocol == THREAD_EVENTS_WS_PROTOCOL)
    {
        return Err(AppError::MalformedPayload {
            field: "websocket_protocol",
        }
        .into());
    }
    let (stream, authority) = super::realtime::subscribe(
        &state,
        auth,
        SubscriptionRequest::ThreadEvents {
            thread_id: ThreadId::new(thread_id),
            after_event_sequence: query.cursor,
        },
    )
    .await?;
    Ok(ws
        .protocols([THREAD_EVENTS_WS_PROTOCOL])
        .max_message_size(THREAD_EVENTS_WS_INPUT_LIMIT)
        .max_frame_size(THREAD_EVENTS_WS_INPUT_LIMIT)
        .on_failed_upgrade(|error| {
            tracing::debug!(error = %error, "thread websocket upgrade 失败");
        })
        .on_upgrade(move |socket| drive_thread_websocket(socket, stream, authority)))
}

async fn drive_thread_websocket(
    mut socket: WebSocket,
    mut stream: AppEventStream,
    authority: super::realtime::RealtimeAuthority,
) {
    loop {
        tokio::select! {
            event = poll_fn(|cx| stream.as_mut().poll_next(cx)) => {
                let Some(event) = event else {
                    super::realtime::close(&mut socket, stream, close_code::NORMAL, "stream_complete").await;
                    return;
                };
                let terminal = matches!(&event, AppEvent::ThreadStreamError { .. });
                let text = match serde_json::to_string(&event) {
                    Ok(text) => text,
                    Err(error) => {
                        tracing::error!(error = %error, "typed thread event 序列化失败");
                        super::realtime::close(&mut socket, stream, close_code::ERROR, "event_encoding_failed").await;
                        return;
                    }
                };
                if super::realtime::send(&mut socket, Message::Text(text.into()), &authority).await.is_err() {
                    return;
                }
                if terminal {
                    super::realtime::close(&mut socket, stream, close_code::ERROR, "thread_stream_failed").await;
                    return;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return,
                Some(Ok(Message::Text(_) | Message::Binary(_))) => {
                    super::realtime::close(&mut socket, stream, close_code::POLICY, "thread_events_read_only").await;
                    return;
                }
                Some(Err(error)) => {
                    tracing::debug!(error = %error, "thread websocket 输入失败");
                    return;
                }
            }
        }
    }
}

/// `GET /api/threads/{thread_id}/events`：SSE durable replay→live。
///
/// reconnect cursor 只认标准 `Last-Event-ID` 十进制值；身份仍由 session 构造。依赖/ACL 在
/// response headers 发出前失败时返回普通 `AppError`；流建立后的撤权/依赖失败成为
/// `thread_stream_error` frame 后断流。
pub async fn events(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(thread_id): Path<String>,
    query: Result<Query<EventWebSocketQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, HttpError> {
    let Query(query) = query.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "thread SSE query 解析失败");
        AppError::MalformedPayload { field: "query" }
    })?;
    // Standard Last-Event-ID on reconnect overrides the one-time native bootstrap cursor.
    let after_event_sequence = last_event_id(&headers)?.or(query.cursor);
    let (stream, _) = super::realtime::subscribe(
        &state,
        auth,
        SubscriptionRequest::ThreadEvents {
            thread_id: ThreadId::new(thread_id),
            after_event_sequence,
        },
    )
    .await?;
    Ok(Sse::new(ThreadSseStream { inner: stream }).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// 把 typed [`AppEventStream`] frame 成 SSE；不实现任何业务判定。
pub struct ThreadSseStream {
    inner: AppEventStream,
}

impl Stream for ThreadSseStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner
            .as_mut()
            .poll_next(cx)
            .map(|item| item.map(|event| Ok(sse_event(event))))
    }
}

fn last_event_id(headers: &HeaderMap) -> Result<Option<u64>, AppError> {
    let Some(value) = headers.get("last-event-id") else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| AppError::MalformedPayload {
        field: "last_event_id",
    })?;
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse::<u64>()
        .map(Some)
        .map_err(|_| AppError::MalformedPayload {
            field: "last_event_id",
        })
}

fn sse_event(event: AppEvent) -> Event {
    let (name, id) = match &event {
        AppEvent::Heartbeat { seq } => ("heartbeat", Some(*seq)),
        AppEvent::ThreadRunEvent(event) => ("thread_run_event", Some(event.event_sequence)),
        AppEvent::ThreadStreamError { .. } => ("thread_stream_error", None),
        AppEvent::ChannelActivity(_) => ("channel_activity", None),
        AppEvent::ChannelStreamError { .. } => ("channel_stream_error", None),
        AppEvent::ToolApprovalActivity(_) => ("tool_approval_activity", None),
        AppEvent::ToolApprovalStreamError { .. } => ("tool_approval_stream_error", None),
    };
    let data = serde_json::to_string(&event).unwrap_or_else(|_| {
        r#"{"kind":"thread_stream_error","code":"dependency_unavailable"}"#.to_owned()
    });
    let frame = Event::default().event(name).data(data);
    match id {
        Some(id) => frame.id(id.to_string()),
        None => frame,
    }
}

fn application_contract_error() -> HttpError {
    tracing::error!("thread command 收到不匹配 reply");
    AppError::DependencyUnavailable {
        dependency: "application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use futures_util::{SinkExt as _, StreamExt as _};
    use http::{Method, Request, StatusCode};
    use openbot_application::ports::{
        BeginThreadRunRequest, CancelThreadRunRequest, ChannelReader, PortError,
        ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError, ThreadEventSubscription,
        ThreadHistoryRequest,
    };
    use openbot_application::{ChannelCursor, OpenBotApplication};
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::command::{
        ThreadHistoryMessage, ThreadHistoryRole, ThreadRunEvent, ThreadRunEventKind,
    };
    use openbot_contracts::ids::thread::ThreadIdentity;
    use openbot_contracts::ids::{ActorId, DeploymentId, RunId, TenantId};
    use openbot_domain::identity::session::TrustedOrigins;
    use openbot_infra::auth::config::default_session_lifetime;
    use serde_json::Value;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tokio_tungstenite::tungstenite::{Error as ClientWebSocketError, Message as ClientMessage};
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::{FixedAuthResolver, SensitiveWriteSecurity};
    use crate::http::ServerBuilder;

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

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct KnownCall {
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        thread: ThreadId,
    }

    #[derive(Clone)]
    struct FakeThreadDirectory {
        inner: Arc<FakeThreadDirectoryInner>,
    }

    struct FakeThreadDirectoryInner {
        next_entropy: AtomicU64,
        mint_calls: AtomicU64,
        known: Result<bool, ThreadDirectoryError>,
        known_calls: Mutex<Vec<KnownCall>>,
        subscription_calls: Mutex<Vec<ThreadEventSubscription>>,
        events: Mutex<Vec<AppEvent>>,
        hold_stream_open: AtomicBool,
        history: Mutex<Result<ThreadHistory, ThreadDirectoryError>>,
        history_calls: Mutex<Vec<ThreadHistoryRequest>>,
        begin: Mutex<Result<ThreadRunStarted, ThreadDirectoryError>>,
        begin_calls: Mutex<Vec<BeginThreadRunRequest>>,
        cancel: Mutex<Result<ThreadRunCancellation, ThreadDirectoryError>>,
        cancel_calls: Mutex<Vec<CancelThreadRunRequest>>,
        conversation: Mutex<Result<ThreadConversationSnapshot, ThreadDirectoryError>>,
        conversation_calls: Mutex<Vec<ThreadConversationRequest>>,
    }

    impl FakeThreadDirectory {
        fn new(known: Result<bool, ThreadDirectoryError>) -> Self {
            Self {
                inner: Arc::new(FakeThreadDirectoryInner {
                    next_entropy: AtomicU64::new(1),
                    mint_calls: AtomicU64::new(0),
                    known,
                    known_calls: Mutex::new(Vec::new()),
                    subscription_calls: Mutex::new(Vec::new()),
                    events: Mutex::new(Vec::new()),
                    hold_stream_open: AtomicBool::new(false),
                    history: Mutex::new(Ok(ThreadHistory::default())),
                    history_calls: Mutex::new(Vec::new()),
                    begin: Mutex::new(Err(ThreadDirectoryError::Unavailable)),
                    begin_calls: Mutex::new(Vec::new()),
                    cancel: Mutex::new(Err(ThreadDirectoryError::Unavailable)),
                    cancel_calls: Mutex::new(Vec::new()),
                    conversation: Mutex::new(Ok(ThreadConversationSnapshot::default())),
                    conversation_calls: Mutex::new(Vec::new()),
                }),
            }
        }

        fn with_events(self, events: Vec<AppEvent>) -> Self {
            *self.inner.events.lock().expect("fake lock") = events;
            self
        }

        fn holding_stream_open(self) -> Self {
            self.inner.hold_stream_open.store(true, Ordering::SeqCst);
            self
        }

        fn with_history(self, history: Result<ThreadHistory, ThreadDirectoryError>) -> Self {
            *self.inner.history.lock().expect("fake lock") = history;
            self
        }

        fn with_begin(self, begin: Result<ThreadRunStarted, ThreadDirectoryError>) -> Self {
            *self.inner.begin.lock().expect("fake lock") = begin;
            self
        }

        fn with_cancel(self, cancel: Result<ThreadRunCancellation, ThreadDirectoryError>) -> Self {
            *self.inner.cancel.lock().expect("fake lock") = cancel;
            self
        }

        fn with_conversation(
            self,
            conversation: Result<ThreadConversationSnapshot, ThreadDirectoryError>,
        ) -> Self {
            *self.inner.conversation.lock().expect("fake lock") = conversation;
            self
        }

        fn mint_calls(&self) -> u64 {
            self.inner.mint_calls.load(Ordering::SeqCst)
        }

        fn known_calls(&self) -> Vec<KnownCall> {
            self.inner.known_calls.lock().expect("fake lock").clone()
        }

        fn subscription_calls(&self) -> Vec<ThreadEventSubscription> {
            self.inner
                .subscription_calls
                .lock()
                .expect("fake lock")
                .clone()
        }

        fn history_calls(&self) -> Vec<ThreadHistoryRequest> {
            self.inner.history_calls.lock().expect("fake lock").clone()
        }

        fn begin_calls(&self) -> Vec<BeginThreadRunRequest> {
            self.inner.begin_calls.lock().expect("fake lock").clone()
        }

        fn cancel_calls(&self) -> Vec<CancelThreadRunRequest> {
            self.inner.cancel_calls.lock().expect("fake lock").clone()
        }

        fn conversation_calls(&self) -> Vec<ThreadConversationRequest> {
            self.inner
                .conversation_calls
                .lock()
                .expect("fake lock")
                .clone()
        }
    }

    #[async_trait]
    impl ThreadDirectory for FakeThreadDirectory {
        async fn mint_thread_id(
            &self,
            deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            self.inner.mint_calls.fetch_add(1, Ordering::SeqCst);
            let sequence = self.inner.next_entropy.fetch_add(1, Ordering::SeqCst);
            let mut entropy = [0_u8; 16];
            entropy[8..].copy_from_slice(&sequence.to_be_bytes());
            Ok(ThreadIdentity::new(deployment).mint_from_entropy(entropy))
        }

        async fn thread_known(
            &self,
            deployment: &DeploymentId,
            tenant: &TenantId,
            actor: &ActorId,
            thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            self.inner
                .known_calls
                .lock()
                .expect("fake lock")
                .push(KnownCall {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    thread: thread.clone(),
                });
            self.inner.known
        }

        async fn begin_thread_run(
            &self,
            request: BeginThreadRunRequest,
        ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
            self.inner
                .begin_calls
                .lock()
                .expect("fake lock")
                .push(request);
            self.inner.begin.lock().expect("fake lock").clone()
        }

        async fn cancel_thread_run(
            &self,
            request: CancelThreadRunRequest,
        ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
            self.inner
                .cancel_calls
                .lock()
                .expect("fake lock")
                .push(request);
            self.inner.cancel.lock().expect("fake lock").clone()
        }

        async fn thread_conversation(
            &self,
            request: ThreadConversationRequest,
        ) -> Result<ThreadConversationSnapshot, ThreadDirectoryError> {
            self.inner
                .conversation_calls
                .lock()
                .expect("fake lock")
                .push(request);
            self.inner.conversation.lock().expect("fake lock").clone()
        }

        async fn subscribe_thread_events(
            &self,
            request: ThreadEventSubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.inner
                .subscription_calls
                .lock()
                .expect("fake lock")
                .push(request);
            if self.inner.hold_stream_open.load(Ordering::SeqCst) {
                Ok(Box::pin(PendingEvents))
            } else {
                Ok(Box::pin(FiniteEvents(
                    self.inner.events.lock().expect("fake lock").clone().into(),
                )))
            }
        }

        async fn thread_history(
            &self,
            request: ThreadHistoryRequest,
        ) -> Result<ThreadHistory, ThreadDirectoryError> {
            self.inner
                .history_calls
                .lock()
                .expect("fake lock")
                .push(request);
            self.inner.history.lock().expect("fake lock").clone()
        }
    }

    struct FiniteEvents(VecDeque<AppEvent>);

    impl Stream for FiniteEvents {
        type Item = AppEvent;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct PendingEvents;

    impl Stream for PendingEvents {
        type Item = AppEvent;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    fn auth(actor: &str) -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("openbot-test"),
            TenantId::new("tenant-test"),
            ActorId::new(actor),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    fn app(directory: FakeThreadDirectory, resolver: FixedAuthResolver) -> Router {
        let application = Arc::new(OpenBotApplication::new(EmptyChannels).with_threads(directory));
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .into_router()
    }

    async fn send(router: Router, method: Method, uri: &str) -> (StatusCode, Value) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("test request"),
            )
            .await
            .expect("router response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("bounded response");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON response")
        };
        (status, body)
    }

    async fn begin_request(
        router: Router,
        origin: Option<&str>,
        thread_id: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/threads/{thread_id}/runs"))
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router
            .oneshot(
                request
                    .body(Body::from(body.to_owned()))
                    .expect("begin request"),
            )
            .await
            .expect("begin response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("begin body");
        let body = serde_json::from_slice(&bytes).expect("begin json");
        (status, headers, body)
    }

    async fn cancel_request(
        router: Router,
        origin: Option<&str>,
        thread_id: &str,
        run_id: &str,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/threads/{thread_id}/runs/{run_id}/cancel"));
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router
            .oneshot(request.body(Body::empty()).expect("cancel request"))
            .await
            .expect("cancel response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("cancel body");
        let body = serde_json::from_slice(&bytes).expect("cancel json");
        (status, headers, body)
    }

    #[tokio::test]
    async fn native_conversation_is_one_no_store_snapshot_scoped_only_by_auth_and_path() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let directory =
            FakeThreadDirectory::new(Ok(true)).with_conversation(Ok(ThreadConversationSnapshot {
                messages: vec![ThreadHistoryMessage {
                    selected_skill_slugs: Vec::new(),
                    id: "message-1".to_owned(),
                    role: ThreadHistoryRole::User,
                    content: "hello".to_owned(),
                    agent_id: None,
                    tool_call_id: None,
                    tool_name: None,
                    tool_error_code: None,
                    tool_calls: None,
                }],
                active_run_id: Some(RunId::new("run-1")),
                active_run_state: Some(
                    openbot_contracts::command::ThreadForegroundRunState::Running,
                ),
                active_run_cancellable: true,
                active_run_text: "partial".to_owned(),
                last_event_sequence: Some(7),
            }));
        let visible = directory.clone();
        let response = app(directory, FixedAuthResolver::granting(auth("u1")))
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/threads/{thread}/conversation"))
                    .body(Body::empty())
                    .expect("conversation request"),
            )
            .await
            .expect("conversation response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("conversation body"),
        )
        .expect("conversation JSON");
        assert_eq!(
            body,
            serde_json::json!({
                "messages":[{"id":"message-1","role":"user","content":"hello"}],
                "activeRunId":"run-1","activeRunState":"running",
                "activeRunCancellable":true,"activeRunText":"partial","lastEventSequence":7
            })
        );
        assert_eq!(
            visible.conversation_calls(),
            [ThreadConversationRequest {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
                thread: ThreadId::new(thread),
            }]
        );
    }

    #[tokio::test]
    async fn native_conversation_auth_and_thread_shape_fail_before_the_port() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, _) = send(
            app(
                directory,
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            Method::GET,
            &format!("/api/threads/{thread}/conversation"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(visible.conversation_calls().is_empty());

        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, body) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::GET,
            "/api/threads/not-a-uuid/conversation",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, serde_json::json!({"code":"malformed_payload"}));
        assert!(visible.conversation_calls().is_empty());
    }

    #[tokio::test]
    async fn begin_run_uses_path_and_authoritative_scope_then_distinguishes_create_from_replay() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        for (replayed, expected) in [(false, StatusCode::CREATED), (true, StatusCode::OK)] {
            let directory = FakeThreadDirectory::new(Ok(true)).with_begin(Ok(ThreadRunStarted {
                thread_id: ThreadId::new(thread),
                run_id: RunId::new("run-1"),
                message_sequence: 1,
                event_sequence: 1,
                replayed,
            }));
            let visible = directory.clone();
            let (status, headers, body) = begin_request(
                app(directory, FixedAuthResolver::granting(auth("u1"))),
                Some("https://app.example.test"),
                thread,
                r#"{"runId":"run-1","botId":"agent-1","anchor":{"kind":"channel","channel_id":"channel-1"},"message":"hello","selectedSkillSlugs":["skill-one"],"modelSelection":{"connectionId":"01234567-89ab-cdef-0123-456789abcdef","expectedRevision":7}}"#,
            )
            .await;
            assert_eq!(status, expected);
            assert_eq!(headers[CACHE_CONTROL], "no-store");
            assert_eq!(body["threadId"], thread);
            assert_eq!(body["runId"], "run-1");
            assert_eq!(body["replayed"], replayed);
            assert_eq!(
                visible.begin_calls(),
                [BeginThreadRunRequest {
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(1),
                    deployment: DeploymentId::new("openbot-test"),
                    tenant: TenantId::new("tenant-test"),
                    actor: ActorId::new("u1"),
                    command: BeginThreadRun {
                        artifact_refs: Vec::new(),
                        model_selection: Some(
                            openbot_contracts::model_connections::RunModelSelection {
                                connection_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
                                expected_revision: 7,
                            }
                        ),
                        selected_skill_slugs: vec!["skill-one".to_owned()],
                        thread_id: ThreadId::new(thread),
                        run_id: RunId::new("run-1"),
                        bot_id: openbot_contracts::ids::BotId::new("agent-1"),
                        anchor: openbot_contracts::command::ThreadRunAnchor::Channel {
                            channel_id: openbot_contracts::ids::ChannelId::new("channel-1"),
                        },
                        message: "hello".to_owned(),
                    },
                }]
            );
        }
    }

    #[tokio::test]
    async fn artifact_refs_v1_v2_body_mapping_reaches_the_original_shape_guard() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        for selection in [
            serde_json::Value::Null,
            serde_json::json!({
                "schemaVersion": 2, "source": "custom",
                "connectionId": "0196ea23-b506-73c8-8153-213383fdc24a",
                "expectedConnectionRevision": 1, "modelId": "model",
                "expectedCatalogRevision": 1
            }),
        ] {
            let directory = FakeThreadDirectory::new(Ok(true));
            let visible = directory.clone();
            let wire = serde_json::json!({
                "runId": "artifact-forwarding", "botId": "agent-1",
                "anchor": {"kind": "direct_bot"}, "message": "unchanged",
                "modelSelection": selection, "artifactRefs": ["not-a-uuid-v7"]
            });
            let (status, _, body) = begin_request(
                app(directory, FixedAuthResolver::granting(auth("u1"))),
                Some("https://app.example.test"),
                thread,
                &wire.to_string(),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["code"], "malformed_payload");
            assert!(visible.begin_calls().is_empty());
        }
    }

    #[tokio::test]
    async fn begin_run_auth_and_origin_precede_json_and_no_port_call_occurs_on_rejection() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, _, _) = begin_request(
            app(
                directory,
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            None,
            thread,
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(visible.begin_calls().is_empty());

        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, _, _) = begin_request(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            None,
            thread,
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(visible.begin_calls().is_empty());

        for body in [
            "null",
            r#"{"runId":"","botId":"agent-1","anchor":{"kind":"channel","channel_id":"channel-1"},"message":"hello"}"#,
            r#"{"runId":"run-1","botId":"agent-1","anchor":{"kind":"channel","channel_id":"channel-1"},"message":"hello","actor":"forged"}"#,
        ] {
            let directory = FakeThreadDirectory::new(Ok(true));
            let visible = directory.clone();
            let (status, _, response) = begin_request(
                app(directory, FixedAuthResolver::granting(auth("u1"))),
                Some("https://app.example.test"),
                thread,
                body,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
            assert!(visible.begin_calls().is_empty(), "{body}");
        }
    }

    #[tokio::test]
    async fn cancel_run_is_origin_guarded_and_returns_only_durable_request_state() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        for (state_value, expected) in [
            (ThreadRunCancellationState::Requested, StatusCode::ACCEPTED),
            (
                ThreadRunCancellationState::AlreadyRequested,
                StatusCode::ACCEPTED,
            ),
            (ThreadRunCancellationState::AlreadyTerminal, StatusCode::OK),
        ] {
            let directory =
                FakeThreadDirectory::new(Ok(true)).with_cancel(Ok(ThreadRunCancellation {
                    thread_id: ThreadId::new(thread),
                    run_id: RunId::new("run-1"),
                    state: state_value,
                }));
            let visible = directory.clone();
            let (status, headers, body) = cancel_request(
                app(directory, FixedAuthResolver::granting(auth("u1"))),
                Some("https://app.example.test"),
                thread,
                "run-1",
            )
            .await;
            assert_eq!(status, expected);
            assert_eq!(headers[CACHE_CONTROL], "no-store");
            assert_eq!(body["threadId"], thread);
            assert_eq!(body["runId"], "run-1");
            assert_eq!(
                visible.cancel_calls(),
                [CancelThreadRunRequest {
                    deployment: DeploymentId::new("openbot-test"),
                    tenant: TenantId::new("tenant-test"),
                    actor: ActorId::new("u1"),
                    command: CancelThreadRun {
                        thread_id: ThreadId::new(thread),
                        run_id: RunId::new("run-1"),
                    },
                }]
            );
        }

        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, _, _) = cancel_request(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            None,
            thread,
            "run-1",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(visible.cancel_calls().is_empty());
    }

    #[tokio::test]
    async fn returns_one_this_deployment_can_recognise_later() {
        let directory = FakeThreadDirectory::new(Ok(false));
        let (status, body) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::POST,
            "/api/threads/mint",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let thread = ThreadId::new(body["threadId"].as_str().expect("threadId"));
        assert!(ThreadIdentity::new(&DeploymentId::new("openbot-test")).owns(&thread));
    }

    #[tokio::test]
    async fn returns_a_different_one_every_time() {
        let directory = FakeThreadDirectory::new(Ok(false));
        let router = app(directory, FixedAuthResolver::granting(auth("u1")));
        let (_, first) = send(router.clone(), Method::POST, "/api/threads/mint").await;
        let (_, second) = send(router, Method::POST, "/api/threads/mint").await;
        assert_ne!(first["threadId"], second["threadId"]);
    }

    #[tokio::test]
    async fn does_not_answer_a_caller_with_no_session() {
        let directory = FakeThreadDirectory::new(Ok(false));
        let visible = directory.clone();
        let (status, body) = send(
            app(
                directory,
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            Method::POST,
            "/api/threads/mint",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, serde_json::json!({"code":"unauthenticated"}));
        assert_eq!(visible.mint_calls(), 0);
    }

    #[tokio::test]
    async fn answers_known_when_the_native_store_can_produce_the_thread() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let (status, body) = send(
            app(
                FakeThreadDirectory::new(Ok(true)),
                FixedAuthResolver::granting(auth("u1")),
            ),
            Method::GET,
            &format!("/api/threads/{thread}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"known":true}));
    }

    #[tokio::test]
    async fn answers_unknown_when_the_native_store_has_never_heard_of_it() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let (status, body) = send(
            app(
                FakeThreadDirectory::new(Ok(false)),
                FixedAuthResolver::granting(auth("u1")),
            ),
            Method::GET,
            &format!("/api/threads/{thread}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"known":false}));
    }

    #[tokio::test]
    async fn native_store_failure_is_503_and_never_leaks_its_own_error() {
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let (status, body) = send(
            app(
                FakeThreadDirectory::new(Err(ThreadDirectoryError::Unavailable)),
                FixedAuthResolver::granting(auth("u1")),
            ),
            Method::GET,
            &format!("/api/threads/{thread}"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({"code":"dependency_unavailable"}));
        assert!(!body.to_string().contains("database"));
    }

    #[tokio::test]
    async fn status_is_always_registered_without_intelligence_and_mint_keeps_working() {
        let router = app(
            FakeThreadDirectory::new(Ok(false)),
            FixedAuthResolver::granting(auth("u1")),
        );
        let (status, body) = send(
            router.clone(),
            Method::GET,
            "/api/threads/550e8400-e29b-41d4-a716-446655440000",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"known":false}));

        let (mint_status, minted) = send(router, Method::POST, "/api/threads/mint").await;
        assert_eq!(mint_status, StatusCode::OK);
        assert!(minted["threadId"].is_string());
    }

    #[tokio::test]
    async fn asks_about_the_session_actor_not_one_smuggled_in_the_query() {
        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let thread = "550e8400-e29b-41d4-a716-446655440000";
        let (status, _) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::GET,
            &format!("/api/threads/{thread}?userId=someone-else"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            visible.known_calls(),
            vec![KnownCall {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
                thread: ThreadId::new(thread),
            }]
        );
    }

    #[tokio::test]
    async fn malformed_thread_id_is_400_before_the_store_is_touched() {
        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let (status, body) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::GET,
            "/api/threads/not-a-uuid",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, serde_json::json!({"code":"malformed_payload"}));
        assert!(visible.known_calls().is_empty());
    }

    #[tokio::test]
    async fn empty_or_unknown_history_is_200_with_an_empty_messages_array() {
        let directory = FakeThreadDirectory::new(Ok(false));
        let (status, body) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::GET,
            "/api/copilotkit/threads/550e8400-e29b-41d4-a716-446655440099/messages?agentId=runtime-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"messages":[]}));
    }

    #[tokio::test]
    async fn history_ignores_smuggled_agent_id_and_uses_only_session_scope() {
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let directory = FakeThreadDirectory::new(Ok(true)).with_history(Ok(ThreadHistory {
            messages: vec![ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "m-1".to_owned(),
                role: ThreadHistoryRole::User,
                content: "hello".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            }],
        }));
        let visible = directory.clone();
        let (status, body) = send(
            app(directory, FixedAuthResolver::granting(auth("u1"))),
            Method::GET,
            &format!(
                "/api/copilotkit/threads/{thread}/messages?agentId=someone-elses-private-agent"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["messages"][0]["content"], "hello");
        assert_eq!(
            visible.history_calls(),
            vec![ThreadHistoryRequest {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
                thread,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_history_query_is_400_before_the_port() {
        for uri in [
            "/api/copilotkit/threads/550e8400-e29b-41d4-a716-446655440000/messages",
            "/api/copilotkit/threads/550e8400-e29b-41d4-a716-446655440000/messages?agentId=",
            "/api/copilotkit/threads/550e8400-e29b-41d4-a716-446655440000/messages?agentId=a&principal=admin",
        ] {
            let directory = FakeThreadDirectory::new(Ok(true));
            let visible = directory.clone();
            let (status, _) = send(
                app(directory, FixedAuthResolver::granting(auth("u1"))),
                Method::GET,
                uri,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert!(visible.history_calls().is_empty(), "{uri}");
        }
    }

    #[tokio::test]
    async fn sse_uses_last_event_id_and_frames_typed_events_without_a_second_business_path() {
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let directory = FakeThreadDirectory::new(Ok(true)).with_events(vec![
            AppEvent::ThreadRunEvent(ThreadRunEvent {
                thread_id: thread.clone(),
                run_id: RunId::new("run-1"),
                event_sequence: 7,
                event_type: ThreadRunEventKind::SemanticChunk,
                payload: serde_json::json!({"text":"hello"}),
                terminal: false,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
            }),
            AppEvent::ThreadStreamError {
                code: "not_visible".to_owned(),
            },
        ]);
        let visible = directory.clone();
        let router = app(directory, FixedAuthResolver::granting(auth("u1")));
        // A live HTTP server retains its resolver while streaming the response body.
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/threads/{thread}/events?cursor=4"))
                    .header("last-event-id", "6")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "text/event-stream"
        );
        let body = String::from_utf8(
            to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("bounded SSE")
                .to_vec(),
        )
        .expect("UTF-8 SSE");
        assert!(body.contains("id: 7\n"), "{body}");
        assert!(body.contains("event: thread_run_event\n"), "{body}");
        assert!(body.contains(r#""eventSequence":7"#), "{body}");
        assert!(body.contains("event: thread_stream_error\n"), "{body}");
        assert_eq!(
            visible.subscription_calls(),
            vec![ThreadEventSubscription {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
                thread,
                after_event_sequence: Some(6),
            }]
        );
    }

    #[tokio::test]
    async fn websocket_requires_origin_and_protocol_then_reuses_the_typed_cursor_stream() {
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let directory =
            FakeThreadDirectory::new(Ok(true)).with_events(vec![AppEvent::ThreadRunEvent(
                ThreadRunEvent {
                    thread_id: thread.clone(),
                    run_id: RunId::new("run-ws"),
                    event_sequence: 8,
                    event_type: ThreadRunEventKind::SemanticChunk,
                    payload: serde_json::json!({"channel":"text","delta":"hello"}),
                    terminal: false,
                    created_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            )]);
        let visible = directory.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket test");
        let address = listener.local_addr().expect("test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app(directory, FixedAuthResolver::granting(auth("u1"))),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });

        let untrusted = websocket_request(
            address,
            &thread,
            Some("https://evil.example.test"),
            Some(THREAD_EVENTS_WS_PROTOCOL),
            Some(7),
        )
        .await;
        assert_http_handshake_error(untrusted, StatusCode::FORBIDDEN);

        let missing_protocol = websocket_request(
            address,
            &thread,
            Some("https://app.example.test"),
            None,
            Some(7),
        )
        .await;
        assert_http_handshake_error(missing_protocol, StatusCode::BAD_REQUEST);

        let (mut socket, response) = websocket_request(
            address,
            &thread,
            Some("https://app.example.test"),
            Some(THREAD_EVENTS_WS_PROTOCOL),
            Some(7),
        )
        .await
        .expect("trusted websocket handshake");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers()[http::header::SEC_WEBSOCKET_PROTOCOL],
            THREAD_EVENTS_WS_PROTOCOL
        );
        let frame = socket
            .next()
            .await
            .expect("event frame")
            .expect("valid event frame");
        let ClientMessage::Text(text) = frame else {
            panic!("首帧必须是 typed JSON text：{frame:?}");
        };
        let event: AppEvent = serde_json::from_str(text.as_str()).expect("typed AppEvent");
        assert!(matches!(
            event,
            AppEvent::ThreadRunEvent(ThreadRunEvent {
                event_sequence: 8,
                ..
            })
        ));
        let close = socket
            .next()
            .await
            .expect("close frame")
            .expect("valid close frame");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal)
        );
        assert_eq!(
            visible.subscription_calls(),
            vec![ThreadEventSubscription {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
                thread,
                after_event_sequence: Some(7),
            }]
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn websocket_is_read_only_and_closes_client_data_with_policy_code() {
        let thread = ThreadId::new("550e8400-e29b-41d4-a716-446655440000");
        let directory = FakeThreadDirectory::new(Ok(true)).holding_stream_open();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket test");
        let address = listener.local_addr().expect("test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app(directory, FixedAuthResolver::granting(auth("u1"))),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });
        let (mut socket, _) = websocket_request(
            address,
            &thread,
            Some("https://app.example.test"),
            Some(THREAD_EVENTS_WS_PROTOCOL),
            None,
        )
        .await
        .expect("trusted websocket handshake");
        socket
            .send(ClientMessage::Text("forged client event".into()))
            .await
            .expect("send policy violation");
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

    type ClientSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
    type ClientHandshake =
        Result<(ClientSocket, http::Response<Option<Vec<u8>>>), ClientWebSocketError>;

    async fn websocket_request(
        address: std::net::SocketAddr,
        thread: &ThreadId,
        origin: Option<&str>,
        protocol: Option<&str>,
        cursor: Option<u64>,
    ) -> ClientHandshake {
        let suffix = cursor.map_or_else(String::new, |value| format!("?cursor={value}"));
        let mut request = format!("ws://{address}/api/threads/{thread}/ws{suffix}")
            .into_client_request()
            .expect("websocket request");
        if let Some(origin) = origin {
            request.headers_mut().insert(
                http::header::ORIGIN,
                http::HeaderValue::from_str(origin).expect("origin"),
            );
        }
        if let Some(protocol) = protocol {
            request.headers_mut().insert(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_str(protocol).expect("protocol"),
            );
        }
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect websocket test");
        tokio_tungstenite::client_async(request, stream).await
    }

    fn assert_http_handshake_error(result: ClientHandshake, expected: StatusCode) {
        let Err(ClientWebSocketError::Http(response)) = result else {
            panic!("应为 HTTP handshake 拒绝，实际：{result:?}");
        };
        assert_eq!(response.status(), expected);
    }

    #[tokio::test]
    async fn invalid_last_event_id_is_400_before_subscribe() {
        let directory = FakeThreadDirectory::new(Ok(true));
        let visible = directory.clone();
        let response = app(directory, FixedAuthResolver::granting(auth("u1")))
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/threads/550e8400-e29b-41d4-a716-446655440000/events")
                    .header("last-event-id", "not-a-cursor")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(visible.subscription_calls().is_empty());
    }
}
