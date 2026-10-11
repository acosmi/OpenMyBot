//! `GET /api/channels` —— parity ledger `api-channels-list-get`。
//!
//! 台账原文把落点钉成 `openbot-server::http::channels::list (GET /api/channels)`，
//! `migration_rule: preserve`，`notes` 里列的错误码是「401 未登录 / 404 不可见 / 400
//! malformed」。本模块逐字兑现那一行。
//!
//! # 这个 handler 里没有一条业务判定
//!
//! v3 §5.2 逐字：transport 只做认证、framing、输入大小限制和错误映射。对照着看它做了什么：
//!
//! | 动作 | 归属 |
//! | --- | --- |
//! | 解析 `?limit=&cursor=` | framing |
//! | 拒绝畸形查询串 | framing（400） |
//! | 把身份换成 `AuthContext` | 认证（由 [`Authenticated`] 提取器完成） |
//! | 组装 `AppCommand::ListVisibleChannels` | framing |
//! | 序列化 `ChannelPage` | framing |
//! | 把 `AppError` 投影成状态码 + 稳定码 | 错误映射 |
//!
//! **可见性、分页、`limit` 钳制、游标解析全在 application**，这里一行都没有。三件具体的事
//! 由测试钉住：
//!
//! - `out_of_range_limit_is_clamped_by_the_application_not_the_transport` —— `?limit=999999`
//!   会**原样**变成 `AppCommand::ListVisibleChannels { limit: Some(999_999) }`。transport
//!   自己钳到 200 看起来无害，实际是它在替 application 决定分页上限；等哪天上限改了，
//!   就有两个真源。
//! - `valid_cursor_round_trips_through_the_transport_untouched` —— 游标是**不透明字符串**，
//!   transport 不解析、不校验、不重编码。一旦 transport 开始解析它，游标格式就变成公开
//!   契约，之后换排序键会成为破坏性变更（`openbot_contracts::command` 的字段文档逐字写着
//!   这条）。
//! - `tampered_cursor_is_four_hundred_with_a_stable_code` —— 坏游标由 application 判 400，
//!   transport 只负责把它渲染出去。
//!
//! # 响应体没有信封
//!
//! 顶层就是 `ChannelPage` 本身：`{"channels":[…],"nextCursor":…}`。它已经是 camelCase，
//! 与上游 `channelSummaryDto` 逐键对齐（v3 §15.1 把 `/api/channels` 的 input/output schema
//! 纳入 parity 面，所以字段名是契约不是风格）。再包一层 `{"data":…}` 会立刻破 parity。

use std::future::poll_fn;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Path, Query, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use openbot_contracts::command::{
    AppCommand, AppReply, ChannelDetailResponse, ChannelPage, CreateChannelRequest,
};
use openbot_contracts::command::{AppEvent, SubscriptionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ChannelId;
use serde::Deserialize;

use crate::auth::{Authenticated, OriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// 查询串解析失败时报给调用方的静态字段名。
///
/// 不是 `"limit"` 也不是 `"cursor"`：`QueryRejection` 不告诉我们是哪个键坏了，而
/// `AppError::MalformedPayload::field` 是 `&'static str`（contracts 用类型堵死"把用户输入
/// 回显进错误"这条路）。猜一个具体键名比给一个诚实的粗粒度名字更糟 —— 它会让客户端去改
/// 一个根本没错的参数。
const QUERY_FIELD: &str = "query";
const CHANNEL_ACTIVITY_PROTOCOL: &str = "openbot.channel-activity.v1";
const CHANNEL_ACTIVITY_INPUT_LIMIT: usize = 1024;

/// `GET /api/channels` 的查询串。
///
/// # `deny_unknown_fields` 是**相对上游的刻意收紧**
///
/// 上游用 zod 解析 query，未声明的键被静默丢掉。这里改成当场 400，理由与
/// `openbot_contracts::command::AppCommand` 上那条 `deny_unknown_fields` 逐字相同：
/// 静默忽略未知字段等于允许调用方以为自己传了个参数而实际没有 —— 那是一类特别难查的
/// 行为分歧。§5.2 那条「不得接受 renderer 自报 `principal=admin`」在查询串上同样成立：
/// `?principal=admin` 应当是 400，而不是被无声吞掉之后让人以为它"生效了但没用"。
///
/// **这是一次行为变更，不是 parity。** 记在这里供reviewer复核；如果它挡住了真实客户端，
/// 正确的回退是给那个客户端一条 ledger 条目，而不是改回静默忽略。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListChannelsQuery {
    /// 本页最多返回多少条。`None` = 由 application 取默认值；超过
    /// `openbot_contracts::command::MAX_CHANNEL_PAGE` 由 **application** 截断。
    ///
    /// 类型是 `Option<u32>`：负数与非数字在**反序列化阶段**就被拒成 400，压根到不了
    /// application（上游那句 `Math.max(…, 1)` 里防负数的那一半，在 Rust 侧由类型承担）。
    pub limit: Option<u32>,
    /// keyset 游标，**不透明字符串**，原样透传。
    pub cursor: Option<String>,
}

/// 列出当前 actor 可见的 channel。
///
/// # Errors
///
/// - 未认证 → 401（由 [`Authenticated`] 经 [`crate::auth::AuthResolver`] 产出）。
/// - 查询串畸形 → 400 `malformed_payload`。
/// - 游标解不开 → 400 `malformed_payload`（判定在 application，见模块文档）。
/// - 依赖不可用 → 503 `dependency_unavailable`。
///
/// **空结果不是错误**：200 + `{"channels":[],"nextCursor":null}`（§15.3 末条）。
pub async fn list(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    query: Result<Query<ListChannelsQuery>, QueryRejection>,
) -> Result<Json<ChannelPage>, HttpError> {
    let Query(query) = query.map_err(|rejection| {
        // rejection 的文案带着 serde 的内部细节（"Failed to deserialize query string…"），
        // 那是**日志**内容，不是响应体内容。
        tracing::debug!(rejection = %rejection, "查询串解析失败");
        AppError::MalformedPayload { field: QUERY_FIELD }
    })?;

    let reply = state
        .application()
        .execute(
            auth,
            AppCommand::ListVisibleChannels {
                limit: query.limit,
                cursor: query.cursor,
            },
        )
        .await?;

    // 穷举 match 无通配：`AppReply` 新增变体会在这里编译失败，逼作者当场决定这条路由
    // 拿到它该怎么办，而不是让它落进一个静默的 `_ =>` 分支。
    match reply {
        AppReply::Channels(page) => Ok(Json(page)),
        // 走到这里说明 application 拿 `ListVisibleChannels` 回了别的命令应答 —— 契约破了。
        // 不 `unreachable!()`：一条不该发生的路径该以可诊断的失败收场，而不是把整个
        // 进程打死；也不伪装成 200 空列表，那会把一次契约破损洗成"没有数据"。
        AppReply::Health(_)
        | AppReply::Channel(_)
        | AppReply::ChannelRouting(_)
        | AppReply::Agents(_)
        | AppReply::Agent(_)
        | AppReply::AgentLifecycle(_)
        | AppReply::AgentConnectionVerdict(_)
        | AppReply::Components(_)
        | AppReply::ComponentCatalogueAdded(_)
        | AppReply::ComponentGovernanceUpdated(_)
        | AppReply::GrantedComponents(_)
        | AppReply::ComponentDecision(_)
        | AppReply::ComponentDataFunctions(_)
        | AppReply::ComponentFunctionCall(_)
        | AppReply::PendingComponentHumanDecisions(_)
        | AppReply::ComponentHumanDecisionResolved(_)
        | AppReply::SandboxedComponents(_)
        | AppReply::PublishedSandboxedComponents(_)
        | AppReply::SandboxedComponent(_)
        | AppReply::SandboxedComponentDeleted(_)
        | AppReply::CurrentUser(_)
        | AppReply::AdminStatus(_)
        | AppReply::People(_)
        | AppReply::Person(_)
        | AppReply::AuditEvents(_)
        | AppReply::ActionPolicy { .. }
        | AppReply::Tool(_)
        | AppReply::ThreadMinted(_)
        | AppReply::ThreadStatus(_)
        | AppReply::ThreadRunStarted(_)
        | AppReply::ThreadRunCancellation(_)
        | AppReply::RunReconciliation(_)
        | AppReply::RunEffectReceipts(_)
        | AppReply::ThreadHistory(_)
        | AppReply::ThreadConversation(_)
        | AppReply::Memory(_)
        | AppReply::MemoryControl(_)
        | AppReply::Memories(_)
        | AppReply::MemoryRecall(_)
        | AppReply::AgentCallbackToken(_)
        | AppReply::AgentCallbackTokenRevoked(_)
        | AppReply::Credentials(_)
        | AppReply::CredentialWritten(_)
        | AppReply::CredentialRevoked(_)
        | AppReply::McpConnections(_)
        | AppReply::McpAdminPage(_)
        | AppReply::McpOAuthAuthorization(_)
        | AppReply::McpConnectionDisconnected(_)
        | AppReply::McpOAuthClientRegistered(_)
        | AppReply::McpServerMutation(_)
        | AppReply::McpServerRemoved(_)
        | AppReply::ModelConnections(_)
        | AppReply::ModelConnection(_)
        | AppReply::ModelConnectionDeleted(_)
        | AppReply::PluginSkills(_)
        | AppReply::PluginMutationAcknowledged(_)
        | AppReply::GrantedPlugins(_)
        | AppReply::PendingToolApprovals(_)
        | AppReply::ToolApprovalResolved(_)
        | AppReply::UiPreferences(_)
        | AppReply::ArtifactRegistrationReceipt(_)
        | AppReply::ArtifactMetadata(_)
        | AppReply::SourceRunArtifactIds(_)
        | AppReply::ArtifactReadOpened(_)
        | AppReply::ArtifactReadChunkDescriptor(_)
        | AppReply::ArtifactReadAcknowledged(_)
        | AppReply::ArtifactReadClosed(_)
        | AppReply::RuntimeCapabilities(_)
        | AppReply::CustomModelCatalog(_)
        | AppReply::RunCostBudget(_)
        | AppReply::ScreenSession(_)
        | AppReply::PendingRemoteInterrupts(_)
        | AppReply::RemoteInterruptResolved(_) => {
            tracing::error!(
                "ListVisibleChannels 收到非 Channels 应答 —— ApplicationService 契约破损"
            );
            Err(AppError::DependencyUnavailable {
                dependency: "application",
            }
            .into())
        }
    }
}

/// `GET /api/channels/{channel_id}`; current membership and native thread scope stay in application.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(channel_id): Path<String>,
) -> Result<Json<ChannelDetailResponse>, HttpError> {
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetVisibleChannel {
                channel_id: ChannelId::new(channel_id),
            },
        )
        .await?
    {
        AppReply::Channel(channel) => Ok(Json(ChannelDetailResponse { channel })),
        AppReply::Health(_)
        | AppReply::Channels(_)
        | AppReply::ChannelRouting(_)
        | AppReply::Agents(_)
        | AppReply::Agent(_)
        | AppReply::AgentLifecycle(_)
        | AppReply::AgentConnectionVerdict(_)
        | AppReply::Components(_)
        | AppReply::ComponentCatalogueAdded(_)
        | AppReply::ComponentGovernanceUpdated(_)
        | AppReply::GrantedComponents(_)
        | AppReply::ComponentDecision(_)
        | AppReply::ComponentDataFunctions(_)
        | AppReply::ComponentFunctionCall(_)
        | AppReply::PendingComponentHumanDecisions(_)
        | AppReply::ComponentHumanDecisionResolved(_)
        | AppReply::SandboxedComponents(_)
        | AppReply::PublishedSandboxedComponents(_)
        | AppReply::SandboxedComponent(_)
        | AppReply::SandboxedComponentDeleted(_)
        | AppReply::CurrentUser(_)
        | AppReply::AdminStatus(_)
        | AppReply::People(_)
        | AppReply::Person(_)
        | AppReply::AuditEvents(_)
        | AppReply::ActionPolicy { .. }
        | AppReply::Tool(_)
        | AppReply::ThreadMinted(_)
        | AppReply::ThreadStatus(_)
        | AppReply::ThreadRunStarted(_)
        | AppReply::ThreadRunCancellation(_)
        | AppReply::RunReconciliation(_)
        | AppReply::RunEffectReceipts(_)
        | AppReply::ThreadHistory(_)
        | AppReply::ThreadConversation(_)
        | AppReply::Memory(_)
        | AppReply::MemoryControl(_)
        | AppReply::Memories(_)
        | AppReply::MemoryRecall(_)
        | AppReply::AgentCallbackToken(_)
        | AppReply::AgentCallbackTokenRevoked(_)
        | AppReply::Credentials(_)
        | AppReply::CredentialWritten(_)
        | AppReply::CredentialRevoked(_)
        | AppReply::McpConnections(_)
        | AppReply::McpAdminPage(_)
        | AppReply::McpOAuthAuthorization(_)
        | AppReply::McpConnectionDisconnected(_)
        | AppReply::McpOAuthClientRegistered(_)
        | AppReply::McpServerMutation(_)
        | AppReply::McpServerRemoved(_)
        | AppReply::ModelConnections(_)
        | AppReply::ModelConnection(_)
        | AppReply::ModelConnectionDeleted(_)
        | AppReply::PluginSkills(_)
        | AppReply::PluginMutationAcknowledged(_)
        | AppReply::GrantedPlugins(_)
        | AppReply::PendingToolApprovals(_)
        | AppReply::ToolApprovalResolved(_)
        | AppReply::UiPreferences(_)
        | AppReply::ArtifactRegistrationReceipt(_)
        | AppReply::ArtifactMetadata(_)
        | AppReply::SourceRunArtifactIds(_)
        | AppReply::ArtifactReadOpened(_)
        | AppReply::ArtifactReadChunkDescriptor(_)
        | AppReply::ArtifactReadAcknowledged(_)
        | AppReply::ArtifactReadClosed(_)
        | AppReply::RuntimeCapabilities(_)
        | AppReply::CustomModelCatalog(_)
        | AppReply::RunCostBudget(_)
        | AppReply::ScreenSession(_)
        | AppReply::PendingRemoteInterrupts(_)
        | AppReply::RemoteInterruptResolved(_) => {
            tracing::error!("GetVisibleChannel received a non-Channel application reply");
            Err(AppError::DependencyUnavailable {
                dependency: "application",
            }
            .into())
        }
    }
}

/// `POST /api/channels`; authentication and same-origin validation precede body parsing.
pub async fn create(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    body: Result<Json<CreateChannelRequest>, JsonRejection>,
) -> Result<(StatusCode, HeaderMap, Json<ChannelDetailResponse>), HttpError> {
    let Json(body) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "channel create body parsing failed");
        AppError::MalformedPayload { field: "body" }
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::CreateChannel {
                agent_ids: body.agent_ids,
            },
        )
        .await?
    {
        AppReply::Channel(channel) => Ok((
            StatusCode::CREATED,
            no_store(),
            Json(ChannelDetailResponse { channel }),
        )),
        AppReply::Health(_)
        | AppReply::Channels(_)
        | AppReply::ChannelRouting(_)
        | AppReply::Agents(_)
        | AppReply::Agent(_)
        | AppReply::AgentLifecycle(_)
        | AppReply::AgentConnectionVerdict(_)
        | AppReply::Components(_)
        | AppReply::ComponentCatalogueAdded(_)
        | AppReply::ComponentGovernanceUpdated(_)
        | AppReply::GrantedComponents(_)
        | AppReply::ComponentDecision(_)
        | AppReply::ComponentDataFunctions(_)
        | AppReply::ComponentFunctionCall(_)
        | AppReply::PendingComponentHumanDecisions(_)
        | AppReply::ComponentHumanDecisionResolved(_)
        | AppReply::SandboxedComponents(_)
        | AppReply::PublishedSandboxedComponents(_)
        | AppReply::SandboxedComponent(_)
        | AppReply::SandboxedComponentDeleted(_)
        | AppReply::CurrentUser(_)
        | AppReply::AdminStatus(_)
        | AppReply::People(_)
        | AppReply::Person(_)
        | AppReply::AuditEvents(_)
        | AppReply::ActionPolicy { .. }
        | AppReply::Tool(_)
        | AppReply::ThreadMinted(_)
        | AppReply::ThreadStatus(_)
        | AppReply::ThreadRunStarted(_)
        | AppReply::ThreadRunCancellation(_)
        | AppReply::RunReconciliation(_)
        | AppReply::RunEffectReceipts(_)
        | AppReply::ThreadHistory(_)
        | AppReply::ThreadConversation(_)
        | AppReply::Memory(_)
        | AppReply::MemoryControl(_)
        | AppReply::Memories(_)
        | AppReply::MemoryRecall(_)
        | AppReply::AgentCallbackToken(_)
        | AppReply::AgentCallbackTokenRevoked(_)
        | AppReply::Credentials(_)
        | AppReply::CredentialWritten(_)
        | AppReply::CredentialRevoked(_)
        | AppReply::McpConnections(_)
        | AppReply::McpAdminPage(_)
        | AppReply::McpOAuthAuthorization(_)
        | AppReply::McpConnectionDisconnected(_)
        | AppReply::McpOAuthClientRegistered(_)
        | AppReply::McpServerMutation(_)
        | AppReply::McpServerRemoved(_)
        | AppReply::ModelConnections(_)
        | AppReply::ModelConnection(_)
        | AppReply::ModelConnectionDeleted(_)
        | AppReply::PluginSkills(_)
        | AppReply::PluginMutationAcknowledged(_)
        | AppReply::GrantedPlugins(_)
        | AppReply::PendingToolApprovals(_)
        | AppReply::ToolApprovalResolved(_)
        | AppReply::UiPreferences(_)
        | AppReply::ArtifactRegistrationReceipt(_)
        | AppReply::ArtifactMetadata(_)
        | AppReply::SourceRunArtifactIds(_)
        | AppReply::ArtifactReadOpened(_)
        | AppReply::ArtifactReadChunkDescriptor(_)
        | AppReply::ArtifactReadAcknowledged(_)
        | AppReply::ArtifactReadClosed(_)
        | AppReply::RuntimeCapabilities(_)
        | AppReply::CustomModelCatalog(_)
        | AppReply::RunCostBudget(_)
        | AppReply::ScreenSession(_)
        | AppReply::PendingRemoteInterrupts(_)
        | AppReply::RemoteInterruptResolved(_) => {
            tracing::error!("CreateChannel received a non-Channel application reply");
            Err(AppError::DependencyUnavailable {
                dependency: "application",
            }
            .into())
        }
    }
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

/// `GET /api/channels/events`; same-origin, read-only channel activity WebSocket.
pub async fn events(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if !ws
        .requested_protocols()
        .any(|protocol| protocol == CHANNEL_ACTIVITY_PROTOCOL)
    {
        return Err(AppError::MalformedPayload {
            field: "websocket_protocol",
        }
        .into());
    }
    let stream = state
        .application()
        .subscribe(auth, SubscriptionRequest::ChannelActivity)
        .await?;
    Ok(ws
        .protocols([CHANNEL_ACTIVITY_PROTOCOL])
        .max_message_size(CHANNEL_ACTIVITY_INPUT_LIMIT)
        .max_frame_size(CHANNEL_ACTIVITY_INPUT_LIMIT)
        .on_failed_upgrade(|error| {
            tracing::debug!(error = %error, "channel activity websocket upgrade failed");
        })
        .on_upgrade(move |socket| drive_channel_websocket(socket, stream)))
}

async fn drive_channel_websocket(
    mut socket: WebSocket,
    mut stream: openbot_application::AppEventStream,
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
                    AppEvent::ChannelActivity(event) => match serde_json::to_string(&event) {
                        Ok(text) => (text, false),
                        Err(error) => {
                            tracing::error!(error = %error, "typed channel activity encoding failed");
                            let _ = socket.send(Message::Close(Some(CloseFrame {
                                code: close_code::ERROR,
                                reason: "event_encoding_failed".into(),
                            }))).await;
                            return;
                        }
                    },
                    AppEvent::ChannelStreamError { code } => {
                        (serde_json::json!({"error":{"code":code}}).to_string(), true)
                    }
                    AppEvent::Heartbeat { .. }
                    | AppEvent::ThreadRunEvent(_)
                    | AppEvent::ThreadStreamError { .. }
                    | AppEvent::ToolApprovalActivity(_)
                    | AppEvent::ToolApprovalStreamError { .. } => {
                        tracing::error!("channel subscription emitted non-channel event");
                        let _ = socket.send(Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "application_contract_failed".into(),
                        }))).await;
                        return;
                    }
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    return;
                }
                if terminal {
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: close_code::ERROR,
                        reason: "channel_stream_failed".into(),
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
                        reason: "channel_activity_read_only".into(),
                    }))).await;
                    return;
                }
                Some(Err(error)) => {
                    tracing::debug!(error = %error, "channel activity websocket input failed");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use futures_core::Stream;
    use futures_util::{SinkExt as _, StreamExt as _};
    use http::{Method, Request, StatusCode};
    use openbot_application::ports::{
        ChannelActivitySubscription, ChannelAdministration, ChannelAdministrationError,
        ChannelCreateRequest, ChannelReadScope, ChannelReader, PortError, ThreadDirectory,
        ThreadDirectoryError,
    };
    use openbot_application::{AppEventStream, ChannelCursor, OpenBotApplication};
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::{ChannelActivityEvent, ChannelDetail, ChannelSummary};
    use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, TenantId, ThreadId};
    use openbot_domain::identity::session::TrustedOrigins;
    use openbot_infra::auth::config::default_session_lifetime;
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

    #[derive(Clone)]
    struct FakeChannelAdministration {
        result: Result<ChannelDetail, ChannelAdministrationError>,
        calls: Arc<Mutex<Vec<ChannelCreateRequest>>>,
    }

    impl FakeChannelAdministration {
        fn new(result: Result<ChannelDetail, ChannelAdministrationError>) -> Self {
            Self {
                result,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<ChannelCreateRequest> {
            self.calls.lock().expect("channel admin lock").clone()
        }
    }

    #[async_trait]
    impl ChannelAdministration for FakeChannelAdministration {
        async fn create_channel(
            &self,
            request: ChannelCreateRequest,
        ) -> Result<ChannelDetail, ChannelAdministrationError> {
            self.calls.lock().expect("channel admin lock").push(request);
            self.result.clone()
        }
    }

    #[derive(Clone)]
    struct DetailChannels {
        result: Result<Option<ChannelSummary>, PortError>,
        calls: Arc<Mutex<Vec<(ChannelReadScope, ChannelId)>>>,
    }

    impl DetailChannels {
        fn new(result: Result<Option<ChannelSummary>, PortError>) -> Self {
            Self {
                result,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<(ChannelReadScope, ChannelId)> {
            self.calls.lock().expect("detail lock").clone()
        }
    }

    #[async_trait]
    impl ChannelReader for DetailChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            Ok(Vec::new())
        }

        async fn get_visible_channel(
            &self,
            scope: &ChannelReadScope,
            channel_id: &ChannelId,
        ) -> Result<Option<ChannelSummary>, PortError> {
            self.calls
                .lock()
                .expect("detail lock")
                .push((scope.clone(), channel_id.clone()));
            self.result.clone()
        }
    }

    #[derive(Clone)]
    struct FakeChannelDirectory {
        inner: Arc<FakeChannelDirectoryInner>,
    }

    struct FakeChannelDirectoryInner {
        calls: Mutex<Vec<ChannelActivitySubscription>>,
        events: Mutex<Vec<AppEvent>>,
        hold_stream_open: AtomicBool,
    }

    impl FakeChannelDirectory {
        fn with_events(events: Vec<AppEvent>) -> Self {
            Self {
                inner: Arc::new(FakeChannelDirectoryInner {
                    calls: Mutex::new(Vec::new()),
                    events: Mutex::new(events),
                    hold_stream_open: AtomicBool::new(false),
                }),
            }
        }

        fn holding_stream_open() -> Self {
            let directory = Self::with_events(Vec::new());
            directory
                .inner
                .hold_stream_open
                .store(true, Ordering::SeqCst);
            directory
        }

        fn calls(&self) -> Vec<ChannelActivitySubscription> {
            self.inner.calls.lock().expect("fake lock").clone()
        }
    }

    #[async_trait]
    impl ThreadDirectory for FakeChannelDirectory {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, ThreadDirectoryError> {
            Err(ThreadDirectoryError::Unavailable)
        }

        async fn subscribe_channel_activity(
            &self,
            request: ChannelActivitySubscription,
        ) -> Result<AppEventStream, ThreadDirectoryError> {
            self.inner.calls.lock().expect("fake lock").push(request);
            if self.inner.hold_stream_open.load(Ordering::SeqCst) {
                Ok(Box::pin(PendingEvents))
            } else {
                Ok(Box::pin(FiniteEvents(
                    self.inner.events.lock().expect("fake lock").clone().into(),
                )))
            }
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

    fn app(directory: FakeChannelDirectory, resolver: FixedAuthResolver) -> Router {
        app_with_channels(EmptyChannels, directory, resolver)
    }

    fn app_with_channels<R>(
        channels: R,
        directory: FakeChannelDirectory,
        resolver: FixedAuthResolver,
    ) -> Router
    where
        R: ChannelReader + 'static,
    {
        let application = Arc::new(OpenBotApplication::new(channels).with_threads(directory));
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .into_router()
    }

    fn app_with_administration(
        administration: FakeChannelAdministration,
        resolver: FixedAuthResolver,
    ) -> Router {
        let application = Arc::new(
            OpenBotApplication::new(EmptyChannels)
                .with_channel_administration(Arc::new(administration)),
        );
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .into_router()
    }

    fn app_without_administration(resolver: FixedAuthResolver) -> Router {
        let application = Arc::new(OpenBotApplication::new(EmptyChannels));
        ServerBuilder::new(application, Arc::new(resolver))
            .with_sensitive_write_security(SensitiveWriteSecurity::new(
                default_session_lifetime(),
                TrustedOrigins::from_configured(["https://app.example.test"]).unwrap(),
            ))
            .into_router()
    }

    async fn post_channel(
        router: Router,
        origin: Option<&str>,
        body: &str,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/channels")
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router
            .oneshot(
                request
                    .body(Body::from(body.to_owned()))
                    .expect("create request"),
            )
            .await
            .expect("create response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("create body");
        let body = serde_json::from_slice(&bytes).expect("create json");
        (status, headers, body)
    }

    #[tokio::test]
    async fn create_authenticates_before_body_and_rejects_every_malformed_shape_without_a_write() {
        let administration =
            FakeChannelAdministration::new(Err(ChannelAdministrationError::Unavailable));
        let visible = administration.clone();
        let (status, _, _) = post_channel(
            app_with_administration(
                administration,
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            None,
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(visible.calls().is_empty());

        let administration =
            FakeChannelAdministration::new(Err(ChannelAdministrationError::Unavailable));
        let visible = administration.clone();
        let (status, _, _) = post_channel(
            app_with_administration(administration, FixedAuthResolver::granting(auth("u1"))),
            None,
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(visible.calls().is_empty());

        for body in [
            "null",
            "[]",
            r#"{"agentIds":null}"#,
            r#"{"agentIds":[]}"#,
            r#"{"agentIds":[1]}"#,
            r#"{"agentIds":[""]}"#,
            r#"{"agentIds":["agent-1"," agent-1 "]}"#,
            r#"{"agentIds":["agent-1"],"name":"forged"}"#,
        ] {
            let administration =
                FakeChannelAdministration::new(Err(ChannelAdministrationError::Unavailable));
            let visible = administration.clone();
            let (status, _, response) = post_channel(
                app_with_administration(administration, FixedAuthResolver::granting(auth("u1"))),
                Some("https://app.example.test"),
                body,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
            assert_eq!(response, serde_json::json!({"code":"malformed_payload"}));
            assert!(visible.calls().is_empty(), "{body}");
        }
    }

    #[tokio::test]
    async fn create_uses_auth_scope_canonical_ids_and_returns_only_the_channel_dto() {
        let administration = FakeChannelAdministration::new(Ok(ChannelDetail {
            id: ChannelId::new("channel-1"),
            name: "Alpha, Zeta".to_owned(),
            agent_ids: vec![BotId::new("agent-a"), BotId::new("agent-z")],
            thread_id: Some(ThreadId::new("thread-1")),
            active: true,
        }));
        let visible = administration.clone();
        let (status, headers, body) = post_channel(
            app_with_administration(administration, FixedAuthResolver::granting(auth("u1"))),
            Some("https://app.example.test"),
            r#"{"agentIds":[" agent-z ","agent-a"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert_eq!(
            body,
            serde_json::json!({"channel":{
                "id":"channel-1","name":"Alpha, Zeta",
                "agentIds":["agent-a","agent-z"],"threadId":"thread-1","active":true
            }})
        );
        assert_eq!(body["channel"].as_object().unwrap().len(), 5);
        assert_eq!(
            visible.calls(),
            [ChannelCreateRequest {
                scope: openbot_application::ChannelCreateScope {
                    deployment: DeploymentId::new("openbot-test"),
                    tenant: TenantId::new("tenant-test"),
                    actor: ActorId::new("u1"),
                    auth_generation: openbot_contracts::auth::AuthGeneration::new(1),
                    admin: false,
                },
                agent_ids: vec![BotId::new("agent-a"), BotId::new("agent-z")],
            }]
        );
    }

    #[tokio::test]
    async fn create_maps_the_closed_error_domain_and_absent_store_is_mounted_fail_closed() {
        for (error, expected) in [
            (
                ChannelAdministrationError::NotVisible,
                StatusCode::NOT_FOUND,
            ),
            (
                ChannelAdministrationError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                ChannelAdministrationError::Corrupt { field: "fixture" },
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (status, _, _) = post_channel(
                app_with_administration(
                    FakeChannelAdministration::new(Err(error)),
                    FixedAuthResolver::granting(auth("u1")),
                ),
                Some("https://app.example.test"),
                r#"{"agentIds":["agent-1"]}"#,
            )
            .await;
            assert_eq!(status, expected);
        }

        let (status, _, body) = post_channel(
            app_without_administration(FixedAuthResolver::granting(auth("u1"))),
            Some("https://app.example.test"),
            r#"{"agentIds":["agent-1"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({"code":"dependency_unavailable"}));
    }

    #[tokio::test]
    async fn get_channel_uses_authoritative_scope_and_exact_response_envelope() {
        let channels = DetailChannels::new(Ok(Some(ChannelSummary {
            id: ChannelId::new("channel-1"),
            name: "Finance".to_owned(),
            agent_ids: vec![BotId::new("bot-1")],
            last_message: Some("private preview excluded".to_owned()),
            last_message_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            last_message_agent_id: Some(BotId::new("bot-1")),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            thread_id: Some(ThreadId::new("thread-1")),
            active: true,
        })));
        let visible = channels.clone();
        let (status, body) = get_json(
            app_with_channels(
                channels,
                FakeChannelDirectory::with_events(Vec::new()),
                FixedAuthResolver::granting(auth("u1")),
            ),
            "/api/channels/channel-1",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({"channel":{
                "id":"channel-1",
                "name":"Finance",
                "agentIds":["bot-1"],
                "threadId":"thread-1",
                "active":true
            }})
        );
        assert_eq!(
            visible.calls(),
            vec![(
                ChannelReadScope {
                    deployment: DeploymentId::new("openbot-test"),
                    tenant: TenantId::new("tenant-test"),
                    actor: ActorId::new("u1"),
                },
                ChannelId::new("channel-1"),
            )]
        );
    }

    #[tokio::test]
    async fn get_channel_collapses_missing_and_outsider_to_404_and_auth_runs_first() {
        let missing = DetailChannels::new(Ok(None));
        let visible = missing.clone();
        let (status, body) = get_json(
            app_with_channels(
                missing,
                FakeChannelDirectory::with_events(Vec::new()),
                FixedAuthResolver::granting(auth("u1")),
            ),
            "/api/channels/missing",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"code":"not_visible"}));
        assert_eq!(visible.calls().len(), 1);

        let protected = DetailChannels::new(Ok(None));
        let untouched = protected.clone();
        let (status, _) = get_json(
            app_with_channels(
                protected,
                FakeChannelDirectory::with_events(Vec::new()),
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
            ),
            "/api/channels/channel-1",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(untouched.calls().is_empty());
    }

    async fn get_json(router: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("detail request"),
            )
            .await
            .expect("detail response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("detail body");
        let body = serde_json::from_slice(&bytes).expect("detail json");
        (status, body)
    }

    #[tokio::test]
    async fn websocket_rejects_unauthenticated_before_upgrade_or_subscription() {
        let directory = FakeChannelDirectory::with_events(Vec::new());
        let visible = directory.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind channel websocket test");
        let address = listener.local_addr().expect("test address");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app(
                    directory,
                    FixedAuthResolver::rejecting(AppError::Unauthenticated),
                ),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
        });
        let unauthenticated = websocket_request(
            address,
            Some("https://app.example.test"),
            Some(CHANNEL_ACTIVITY_PROTOCOL),
        )
        .await;
        assert_http_handshake_error(unauthenticated, StatusCode::UNAUTHORIZED);
        assert!(visible.calls().is_empty());
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn websocket_requires_origin_and_protocol_then_streams_only_typed_activity() {
        let activity = ChannelActivityEvent {
            channel_id: ChannelId::new("channel-1"),
            last_message: Some("hello".to_owned()),
            last_message_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            last_message_agent_id: Some(BotId::new("bot-1")),
        };
        let directory =
            FakeChannelDirectory::with_events(vec![AppEvent::ChannelActivity(activity.clone())]);
        let visible = directory.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind channel websocket test");
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
            Some("https://evil.example.test"),
            Some(CHANNEL_ACTIVITY_PROTOCOL),
        )
        .await;
        assert_http_handshake_error(untrusted, StatusCode::FORBIDDEN);

        let missing_protocol =
            websocket_request(address, Some("https://app.example.test"), None).await;
        assert_http_handshake_error(missing_protocol, StatusCode::BAD_REQUEST);

        let (mut socket, response) = websocket_request(
            address,
            Some("https://app.example.test"),
            Some(CHANNEL_ACTIVITY_PROTOCOL),
        )
        .await
        .expect("trusted channel websocket handshake");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers()[http::header::SEC_WEBSOCKET_PROTOCOL],
            CHANNEL_ACTIVITY_PROTOCOL
        );
        let frame = socket
            .next()
            .await
            .expect("activity frame")
            .expect("valid activity frame");
        let ClientMessage::Text(text) = frame else {
            panic!("首帧必须是 channel activity JSON text：{frame:?}");
        };
        assert_eq!(
            serde_json::from_str::<ChannelActivityEvent>(text.as_str())
                .expect("typed channel activity"),
            activity
        );
        let close = socket
            .next()
            .await
            .expect("close frame")
            .expect("valid close frame");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal)
        );
        assert_eq!(
            visible.calls(),
            vec![ChannelActivitySubscription {
                deployment: DeploymentId::new("openbot-test"),
                tenant: TenantId::new("tenant-test"),
                actor: ActorId::new("u1"),
            }]
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    #[tokio::test]
    async fn websocket_is_read_only_and_closes_client_data_with_policy_code() {
        let directory = FakeChannelDirectory::holding_stream_open();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind channel websocket test");
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
            Some("https://app.example.test"),
            Some(CHANNEL_ACTIVITY_PROTOCOL),
        )
        .await
        .expect("trusted channel websocket handshake");
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

    #[tokio::test]
    async fn post_upgrade_dependency_failure_is_a_stable_frame_then_error_close() {
        let directory = FakeChannelDirectory::with_events(vec![AppEvent::ChannelStreamError {
            code: "dependency_unavailable".to_owned(),
        }]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind channel websocket test");
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
            Some("https://app.example.test"),
            Some(CHANNEL_ACTIVITY_PROTOCOL),
        )
        .await
        .expect("trusted channel websocket handshake");
        let frame = socket
            .next()
            .await
            .expect("error frame")
            .expect("valid error frame");
        let ClientMessage::Text(text) = frame else {
            panic!("依赖错误必须先发稳定 JSON text：{frame:?}");
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(text.as_str()).expect("error JSON"),
            serde_json::json!({"error":{"code":"dependency_unavailable"}})
        );
        let close = socket
            .next()
            .await
            .expect("error close")
            .expect("valid error close");
        assert!(
            matches!(close, ClientMessage::Close(Some(frame)) if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Error)
        );
        let _ = stop.send(());
        server.await.expect("server task").expect("server result");
    }

    type ClientSocket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
    type ClientHandshake =
        Result<(ClientSocket, http::Response<Option<Vec<u8>>>), ClientWebSocketError>;

    async fn websocket_request(
        address: std::net::SocketAddr,
        origin: Option<&str>,
        protocol: Option<&str>,
    ) -> ClientHandshake {
        let mut request = format!("ws://{address}/api/channels/events")
            .into_client_request()
            .expect("channel websocket request");
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
            .expect("connect channel websocket test");
        tokio_tungstenite::client_async(request, stream).await
    }

    fn assert_http_handshake_error(result: ClientHandshake, expected: StatusCode) {
        let Err(ClientWebSocketError::Http(response)) = result else {
            panic!("应为 HTTP handshake 拒绝，实际：{result:?}");
        };
        assert_eq!(response.status(), expected);
    }
}
