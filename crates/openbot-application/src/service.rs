//! [`ApplicationService`] —— v3 §5.2 逐字定死的唯一业务入口，以及它的事件流类型。
//!
//! 本模块只有 trait、类型别名与 span 字段台账；具体实现在 [`crate::app`]。

use core::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppEvent, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;

/// 订阅返回的事件流。
///
/// # 为什么是 `Stream` 而不是 `tokio::sync::mpsc::Receiver`
///
/// 三条理由，按权重排：
///
/// 1. **取消是构造性的**。`Stream` 的生产者就是这个流自己：调用方 drop 掉它，生产未来
///    随之被 drop，工作立即停止。换成 `Receiver`，生产者必须是另一个 spawn 出去的任务，
///    它的存活不由接收端决定 —— 接收端 drop 之后那个任务照跑，直到下一次 `send` 才发现
///    没人要了。于是「取消」从类型属性退化成一件必须由运行时纪律保证的事，而 §17.2 条 6
///    那一整族「旧代际立即全失效」的不变量恰恰最怕这种"还在跑一会儿"。
/// 2. **它不强加一个任务**。心跳这种流没有任何需要并发的工作，`Receiver` 方案会为它凭空
///    要一个 `tokio::spawn`（以及一个运行时句柄、一条 spawn 失败路径）。
/// 3. 契约文档已经这么写了：`openbot_contracts::command` 的模块注释原文是
///    「`AppEventStream` 是 `Stream<Item = AppEvent>` 的别名」。
///
/// `futures_core::Stream` 是这条 trait 在 std 收编之前的事实标准，且它**此刻已经在
/// `Cargo.lock` 的依赖图里**（经 tokio-util ← tokio-postgres），直接依赖它不新增任何
/// crate。`Pin<Box<dyn …>>` 而不是 `impl Stream`：trait 必须对象安全，transport 持有的
/// 是 `dyn ApplicationService`。
pub type AppEventStream = Pin<Box<dyn Stream<Item = AppEvent> + Send>>;

/// 唯一业务入口（v3 §5.2）。
///
/// 签名逐字来自 §5.2，不得增删参数。特别是：**没有** `method: String`、没有
/// `params: serde_json::Value`、没有让调用方自报身份的位置 —— [`AuthContext`] 由 Rust
/// 的认证层铸造，[`AppCommand`] 是封闭 enum。
///
/// # 与 transport 的分工
///
/// transport（Axum / Tauri）做四件事：认证、framing、输入大小限制、错误到 HTTP/IPC 的
/// 映射。它**不做**业务判定。反过来，本 trait 的实现不碰 HTTP 状态码、不碰 socket、
/// 不生成用户可见文案 —— 错误以 `AppError` 的稳定 code 穿越边界，由 GUI 本地化。
#[async_trait]
pub trait ApplicationService: Send + Sync {
    /// 一次消费原目录应答及其原 key；未装配默认关闭。
    fn take_custom_model_catalog_delivery(
        &self,
        _auth: AuthContext,
        _reply: AppReply,
    ) -> Result<crate::PublicCustomModelCatalogDelivery, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "custom_model_catalog",
        })
    }

    /// Consume one real pending body selected by the original closed read command.
    fn take_artifact_read_delivery(
        &self,
        _auth: AuthContext,
        _input: openbot_contracts::artifact_read_protocol::ReadArtifactReadBlock,
    ) -> Result<crate::PublicArtifactReadDelivery, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Consume the actual current witness retained for this original scalar control reply.
    fn take_artifact_read_control_delivery(
        &self,
        _auth: AuthContext,
        _reply: AppReply,
    ) -> Result<crate::PublicArtifactReadControlDelivery, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Permanently stop this application instance's public reader admission and owners.
    fn close_public_artifact_reads(&self) -> Result<(), AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Stop only original readers belonging to this genuine host issuer.
    fn close_public_artifact_reads_for_issuer(
        &self,
        _issuer: &openbot_contracts::request_binding::RequestBindingIssuer,
    ) -> Result<(), AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// Stop only original readers with this exact opaque host binding identity.
    fn close_public_artifact_reads_for_binding(
        &self,
        _binding: &openbot_contracts::request_binding::HostRequestBindingIdentity,
    ) -> Result<(), AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// 原宿主Rust-only连续读取，不新增公开command或wire。
    async fn open_current_artifact_read(
        &self,
        _auth: AuthContext,
        _artifact_id: String,
    ) -> Result<crate::CurrentArtifactReadOperation, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// 当前原宿主的私有首块读取；未实现的真实transport组合默认不可用。
    async fn read_current_artifact_chunk(
        &self,
        _auth: AuthContext,
        _artifact_id: String,
    ) -> Result<crate::artifacts::CurrentArtifactReadChunk, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "artifacts",
        })
    }
    /// 执行一条命令。
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError>;

    /// 打开一条事件订阅。
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError>;
}

/// [`ApplicationService::execute`] 的 span 名。
pub const EXECUTE_SPAN_NAME: &str = "application.execute";

/// [`ApplicationService::subscribe`] 的 span 名。
pub const SUBSCRIBE_SPAN_NAME: &str = "application.subscribe";

/// 本 crate 在两个入口 span 上记录的字段名全集。
///
/// 它是一份**台账**，不是装饰：`span_fields_are_exactly_the_declared_ledger` 用捕获到的
/// 真实字段集与它逐项比对，多记一个或少记一个都会判红。加字段就必须来改这里，而改这里
/// 会立刻撞上下面 [`TRACE_ONLY_SPAN_FIELDS`] 那条基数论证。
pub const APPLICATION_SPAN_FIELDS: &[&str] = &[
    "deployment_id",
    "tenant_id",
    "actor_id",
    "operation",
    "error.code",
];

/// [`APPLICATION_SPAN_FIELDS`] 中**只进受控 trace/log、绝不进 metrics label** 的那些。
///
/// §16.4 逐字：「高基数 actor/thread 不进入 metrics label，只进入受控 trace/log。」
/// 这里把它做成可判定的：`APPLICATION_SPAN_FIELDS` 里的每一项，要么在
/// `openbot_contracts::telemetry::METRICS_LABEL_ALLOWLIST` 里（附带过基数论证），要么
/// 出现在本清单里（= 有人显式认定它高基数）。两边都不在 = 判红。
///
/// 逐项理由：
///
/// - `actor_id`：§16.4 点名的高基数字段。
/// - `operation`：值域 = [`command_kind`] 与 [`subscription_kind`] 的返回值，都是封闭
///   enum 上的穷举 match，基数其实**有界**。它仍列在这里，是因为它不是 §16.4 那份关联
///   字段清单里的名字 —— 把一个清单外的名字塞进 metrics label 是另一次未经论证的扩张，
///   要进得单独论证。
/// - `error.code`：同上，`ErrorCode` 的取值有界，但它不在 §16.4 的关联字段清单里。
pub const TRACE_ONLY_SPAN_FIELDS: &[&str] = &["actor_id", "operation", "error.code"];

/// 命令的低基数种类名，用作 span 的 `operation` 字段。
///
/// 穷举 match 无通配：新增 [`AppCommand`] 变体会在这里编译失败，逼作者当场给它一个
/// 稳定的 span 名字，而不是让它以 `Debug` 形态（含 `cursor` 这类不透明载荷）漏进日志。
#[must_use]
pub const fn command_kind(command: &AppCommand) -> &'static str {
    match command {
        AppCommand::GetRuntimeCapabilities => "get_runtime_capabilities",
        AppCommand::SaveRunMessageTextArtifact(_) => "save_run_message_text_artifact",
        AppCommand::GetArtifactSaveReceipt(_) => "get_artifact_save_receipt",
        AppCommand::GetArtifactMetadata(_) => "get_artifact_metadata",
        AppCommand::GetSourceRunArtifactIds(_) => "get_source_run_artifact_ids",
        AppCommand::OpenArtifactRead(_) => "open_artifact_read",
        AppCommand::ReadArtifactReadBlock(_) => "read_artifact_read_block",
        AppCommand::AcknowledgeArtifactReadBlock(_) => "acknowledge_artifact_read_block",
        AppCommand::CloseArtifactRead(_) => "close_artifact_read",
        AppCommand::Health => "health",
        AppCommand::ListVisibleChannels { .. } => "list_visible_channels",
        AppCommand::GetVisibleChannel { .. } => "get_visible_channel",
        AppCommand::CreateChannel { .. } => "create_channel",
        AppCommand::RouteChannelMessage { .. } => "route_channel_message",
        AppCommand::ListVisibleAgents { .. } => "list_visible_agents",
        AppCommand::GetVisibleAgent { .. } => "get_visible_agent",
        AppCommand::CreateAgent(_) => "create_agent",
        AppCommand::UpdateAgent { .. } => "update_agent",
        AppCommand::DuplicateAgent { .. } => "duplicate_agent",
        AppCommand::SetAgentHidden { .. } => "set_agent_hidden",
        AppCommand::DeleteAgent { .. } => "delete_agent",
        AppCommand::TestAgentConnection(_) => "test_agent_connection",
        AppCommand::ListComponents => "list_components",
        AppCommand::SyncComponentCatalogue(_) => "sync_component_catalogue",
        AppCommand::UpdateComponentGovernance(_) => "update_component_governance",
        AppCommand::ListComponentsForAgent { .. } => "list_components_for_agent",
        AppCommand::DecideComponent { .. } => "decide_component",
        AppCommand::ListComponentDataFunctions => "list_component_data_functions",
        AppCommand::CallComponentFunction { .. } => "call_component_function",
        AppCommand::AwaitComponentHumanDecision(_) => "await_component_human_decision",
        AppCommand::ListPendingComponentHumanDecisions => "list_pending_component_human_decisions",
        AppCommand::ResolveComponentHumanDecision { .. } => "resolve_component_human_decision",
        AppCommand::ListSandboxedComponents => "list_sandboxed_components",
        AppCommand::ListPublishedSandboxedComponents => "list_published_sandboxed_components",
        AppCommand::SaveSandboxedComponent(_) => "save_sandboxed_component",
        AppCommand::PublishSandboxedComponent { .. } => "publish_sandboxed_component",
        AppCommand::DeleteSandboxedComponent { .. } => "delete_sandboxed_component",
        AppCommand::AuthorizeSandboxedComponent { .. } => "authorize_sandboxed_component",
        AppCommand::GetCurrentUser => "get_current_user",
        AppCommand::AdminStatus => "admin_status",
        AppCommand::ListPeople { .. } => "list_people",
        AppCommand::ChangePersonRole { .. } => "change_person_role",
        AppCommand::ChangePersonAccess { .. } => "change_person_access",
        AppCommand::ListAuditEvents { .. } => "list_audit_events",
        AppCommand::GetActionPolicy => "get_action_policy",
        AppCommand::SetActionPolicy { .. } => "set_action_policy",
        AppCommand::InvokeTool(_) => "invoke_tool",
        AppCommand::MintThreadId => "mint_thread_id",
        AppCommand::GetThreadStatus { .. } => "get_thread_status",
        AppCommand::BeginThreadRun(_) => "begin_thread_run",
        AppCommand::BeginThreadRunV2(_) => "begin_thread_run_v2",
        AppCommand::CancelThreadRun(_) => "cancel_thread_run",
        AppCommand::GetThreadHistory { .. } => "get_thread_history",
        AppCommand::GetThreadConversation { .. } => "get_thread_conversation",
        AppCommand::GetRunReconciliation { .. } => "get_run_reconciliation",
        AppCommand::GetRunEffectReceipts { .. } => "get_run_effect_receipts",
        AppCommand::ListPendingRemoteInterrupts => "list_pending_remote_interrupts",
        AppCommand::ResolveRemoteInterrupt { .. } => "resolve_remote_interrupt",
        AppCommand::RememberMemory(_) => "remember_memory",
        AppCommand::GetMemoryControl => "get_memory_control",
        AppCommand::UpdateMemoryControl(_) => "update_memory_control",
        AppCommand::ListMemories { .. } => "list_memories",
        AppCommand::CorrectMemory { .. } => "correct_memory",
        AppCommand::MutateMemory { .. } => "mutate_memory",
        AppCommand::RecallMemories(_) => "recall_memories",
        AppCommand::IssueAgentCallbackToken { .. } => "issue_agent_callback_token",
        AppCommand::RevokeAgentCallbackToken { .. } => "revoke_agent_callback_token",
        AppCommand::ListMcpConnections => "list_mcp_connections",
        AppCommand::ListModelConnections(_) => "list_model_connections",
        AppCommand::ListCustomModelCatalog(_) => "list_custom_model_catalog",
        AppCommand::GetModelConnection { .. } => "get_model_connection",
        AppCommand::CreateModelConnection(_) => "create_model_connection",
        AppCommand::UpdateModelConnection { .. } => "update_model_connection",
        AppCommand::DeleteModelConnection { .. } => "delete_model_connection",
        AppCommand::ListCredentials(_) => "list_credentials",
        AppCommand::CreateCredential(_) => "create_credential",
        AppCommand::RotateCredential { .. } => "rotate_credential",
        AppCommand::RevokeCredential { .. } => "revoke_credential",
        AppCommand::ListMcpAdminPage => "list_mcp_admin_page",
        AppCommand::BeginMcpOAuth { .. } => "begin_mcp_oauth",
        AppCommand::DisconnectMcpConnection { .. } => "disconnect_mcp_connection",
        AppCommand::RegisterMcpOAuthClient { .. } => "register_mcp_oauth_client",
        AppCommand::AddCuratedMcpServer { .. } => "add_curated_mcp_server",
        AppCommand::AddCustomMcpServer(_) => "add_custom_mcp_server",
        AppCommand::RemoveMcpServer { .. } => "remove_mcp_server",
        AppCommand::RefreshMcpServer { .. } => "refresh_mcp_server",
        AppCommand::SavePluginSkill(_) => "save_plugin_skill",
        AppCommand::RemovePluginSkill { .. } => "remove_plugin_skill",
        AppCommand::GrantPlugin(_) => "grant_plugin",
        AppCommand::RevokePlugin(_) => "revoke_plugin",
        AppCommand::ListPluginsForAgent { .. } => "list_plugins_for_agent",
        AppCommand::ListPendingToolApprovals => "list_pending_tool_approvals",
        AppCommand::DecideToolApproval { .. } => "decide_tool_approval",
        AppCommand::GetUiPreferences => "get_ui_preferences",
        AppCommand::UpdateUiPreferences(_) => "update_ui_preferences",
        AppCommand::GetRunCostBudget => "get_run_cost_budget",
        AppCommand::ReplaceRunCostBudget(_) => "replace_run_cost_budget",
        AppCommand::IssueScreenSession(_) => "issue_screen_session",
    }
}

/// 订阅请求的低基数种类名，用作 span 的 `operation` 字段。理由同 [`command_kind`]。
#[must_use]
pub const fn subscription_kind(request: &SubscriptionRequest) -> &'static str {
    match request {
        SubscriptionRequest::Health => "health",
        SubscriptionRequest::ThreadEvents { .. } => "thread_events",
        SubscriptionRequest::ChannelActivity => "channel_activity",
        SubscriptionRequest::ToolApprovalActivity => "tool_approval_activity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::auth::Role;
    use openbot_contracts::ids::{ActorId, BotId, RunId, ToolCallId};
    use openbot_contracts::telemetry::is_allowed_metrics_label;
    use openbot_contracts::tool::ToolInvocation;
    use serde_json::json;

    /// §16.4 的可判定形式：span 上的每个字段，要么被论证过可以进 metrics label，
    /// 要么被显式登记为 trace-only。**两边都不在 = 有人加了字段却没做基数论证。**
    #[test]
    fn every_span_field_has_a_cardinality_verdict() {
        for field in APPLICATION_SPAN_FIELDS {
            let allowlisted = is_allowed_metrics_label(field);
            let trace_only = TRACE_ONLY_SPAN_FIELDS.contains(field);
            assert!(
                allowlisted != trace_only,
                "字段 {field} 必须恰好落在一边：白名单（有基数论证）或 trace-only（显式认定高基数）"
            );
        }
    }

    /// 负向对照：§16.4 逐字点名的两个高基数字段确实进不了 metrics label。
    ///
    /// 正向对照在同一条里 —— 白名单里的字段确实返回 true，否则本断言在
    /// 「`is_allowed_metrics_label` 恒返回 false」的世界里同样通过。
    #[test]
    fn high_cardinality_fields_are_not_metrics_labels() {
        assert!(!is_allowed_metrics_label("actor_id"));
        assert!(!is_allowed_metrics_label("thread_id"));
        assert!(is_allowed_metrics_label("deployment_id"));
        assert!(is_allowed_metrics_label("tenant_id"));
    }

    #[test]
    fn operation_names_are_closed_and_stable() {
        let commands = [
            (
                AppCommand::SaveRunMessageTextArtifact(openbot_contracts::artifacts::SaveRunMessageTextArtifact {
                    request_id: "019a7777-abcd-7abc-8abc-0123456789ab".into(),
                    source_thread_id: openbot_contracts::ids::ThreadId::new("00000000-0000-8000-8000-000000000000"),
                    source_run_id: RunId::new("source-run"),
                    source_message_id: "source-message".to_owned(),
                    expected_sha256: "a".repeat(64),
                }),
                "save_run_message_text_artifact",
            ),
            (
                AppCommand::GetArtifactMetadata(openbot_contracts::artifacts::GetArtifactMetadata {
                    artifact_id: "019a7778-abcd-7abc-8abc-0123456789ab".into(),
                }),
                "get_artifact_metadata",
            ),
            (AppCommand::GetRuntimeCapabilities, "get_runtime_capabilities"),
            (
                AppCommand::GetArtifactSaveReceipt(openbot_contracts::artifacts::GetArtifactSaveReceipt {
                    request_id: "019a7778-abcd-7abc-8abc-0123456789ab".into(),
                }),
                "get_artifact_save_receipt",
            ),
            (AppCommand::Health, "health"),
            (
                AppCommand::ListVisibleChannels {
                    limit: None,
                    cursor: None,
                },
                "list_visible_channels",
            ),
            (
                AppCommand::GetVisibleChannel {
                    channel_id: openbot_contracts::ids::ChannelId::new("channel-1"),
                },
                "get_visible_channel",
            ),
            (AppCommand::GetCurrentUser, "get_current_user"),
            (AppCommand::AdminStatus, "admin_status"),
            (
                AppCommand::ListPeople {
                    search: None,
                    cursor: None,
                    limit: None,
                },
                "list_people",
            ),
            (
                AppCommand::ChangePersonRole {
                    user_id: ActorId::new("u"),
                    role: Role::User,
                },
                "change_person_role",
            ),
            (
                AppCommand::ChangePersonAccess {
                    user_id: ActorId::new("u"),
                    revoked: true,
                },
                "change_person_access",
            ),
            (
                AppCommand::ListAuditEvents {
                    cursor: None,
                    event_type: None,
                    actor_user_id: None,
                    target_type: None,
                    target_id: None,
                    from: None,
                    to: None,
                    limit: None,
                },
                "list_audit_events",
            ),
            (AppCommand::GetActionPolicy, "get_action_policy"),
            (
                AppCommand::SetActionPolicy {
                    policy: openbot_contracts::policy::ActionPolicyDocument {
                        mode: openbot_contracts::policy::ActionPolicyMode::Enforce,
                        deny: Vec::new(),
                        allow: vec!["true".to_owned()],
                    },
                },
                "set_action_policy",
            ),
            (
                AppCommand::InvokeTool(ToolInvocation {
                    call_id: ToolCallId::new("c"),
                    run_id: RunId::new("r"),
                    bot_id: BotId::new("b"),
                    call_seq: 0,
                    tool_name: "t".to_owned(),
                    arguments: json!({}),
                }),
                "invoke_tool",
            ),
            (AppCommand::MintThreadId, "mint_thread_id"),
            (
                AppCommand::GetThreadStatus {
                    thread_id: openbot_contracts::ids::ThreadId::new(
                        "550e8400-e29b-41d4-a716-446655440000",
                    ),
                },
                "get_thread_status",
            ),
            (
                AppCommand::BeginThreadRun(openbot_contracts::command::BeginThreadRun {
                    artifact_refs: Vec::new(),
                    model_selection: None,
                    selected_skill_slugs: Vec::new(),
                    thread_id: openbot_contracts::ids::ThreadId::new(
                        "550e8400-e29b-81d4-a716-446655440000",
                    ),
                    run_id: RunId::new("r2"),
                    bot_id: BotId::new("b2"),
                    anchor: openbot_contracts::command::ThreadRunAnchor::DirectBot,
                    message: "hello".to_owned(),
                }),
                "begin_thread_run",
            ),
            (
                AppCommand::GetThreadHistory {
                    thread_id: openbot_contracts::ids::ThreadId::new(
                        "550e8400-e29b-81d4-a716-446655440000",
                    ),
                },
                "get_thread_history",
            ),
            (
                AppCommand::RememberMemory(openbot_contracts::memory::RememberMemory {
                    memory_kind: openbot_contracts::memory::MemoryKind::Preference,
                    scope: openbot_contracts::memory::MemoryScope::User,
                    content: "tea".to_owned(),
                    tags: Vec::new(),
                    sensitivity: openbot_contracts::memory::MemorySensitivity::Normal,
                    source: None,
                    expires_at: None,
                }),
                "remember_memory",
            ),
            (
                AppCommand::ListMemories {
                    cursor: None,
                    limit: None,
                },
                "list_memories",
            ),
            (
                AppCommand::CorrectMemory {
                    memory_id: "m".to_owned(),
                    correction: openbot_contracts::memory::CorrectMemory {
                        content: "coffee".to_owned(),
                        tags: Vec::new(),
                        sensitivity: openbot_contracts::memory::MemorySensitivity::Normal,
                        expires_at: None,
                    },
                },
                "correct_memory",
            ),
            (
                AppCommand::MutateMemory {
                    memory_id: "m".to_owned(),
                    mutation: openbot_contracts::memory::MemoryMutation::Delete,
                },
                "mutate_memory",
            ),
            (
                AppCommand::RecallMemories(openbot_contracts::memory::RecallMemories {
                    query: "office".to_owned(),
                    tags: Vec::new(),
                    bot_id: None,
                    thread_id: None,
                    limit: None,
                }),
                "recall_memories",
            ),
            (
                AppCommand::IssueAgentCallbackToken {
                    agent_id: BotId::new("remote"),
                },
                "issue_agent_callback_token",
            ),
            (
                AppCommand::RevokeAgentCallbackToken {
                    agent_id: BotId::new("remote"),
                },
                "revoke_agent_callback_token",
            ),
            (AppCommand::ListMcpConnections, "list_mcp_connections"),
            (AppCommand::ListMcpAdminPage, "list_mcp_admin_page"),
            (
                AppCommand::BeginMcpOAuth {
                    server_id: "notes".to_owned(),
                    return_to: openbot_contracts::mcp::McpOAuthReturnTo::Settings,
                },
                "begin_mcp_oauth",
            ),
            (
                AppCommand::DisconnectMcpConnection {
                    server_id: "notes".to_owned(),
                },
                "disconnect_mcp_connection",
            ),
            (
                AppCommand::RegisterMcpOAuthClient {
                    server_id: "notes".to_owned(),
                    registration: openbot_contracts::mcp::McpOAuthClientRegistration::new(
                        "client".to_owned(),
                        "secret".to_owned(),
                        "https://issuer.example".to_owned(),
                        openbot_contracts::mcp::McpOAuthClientAuthMethod::ClientSecretBasic,
                        None,
                    )
                    .unwrap(),
                },
                "register_mcp_oauth_client",
            ),
            (
                AppCommand::AddCuratedMcpServer {
                    key: "google-drive".to_owned(),
                },
                "add_curated_mcp_server",
            ),
            (
                AppCommand::AddCustomMcpServer(
                    openbot_contracts::mcp::McpCustomServerRegistration {
                        id: "notes".to_owned(),
                        title: "Notes".to_owned(),
                        url: "https://notes.example/mcp".to_owned(),
                        credential_id: None,
                        egress_allow_cidrs: Vec::new(),
                    },
                ),
                "add_custom_mcp_server",
            ),
            (
                AppCommand::RemoveMcpServer {
                    server_id: "notes".to_owned(),
                },
                "remove_mcp_server",
            ),
            (
                AppCommand::RefreshMcpServer {
                    server_id: "google-drive".to_owned(),
                },
                "refresh_mcp_server",
            ),
            (
                AppCommand::SavePluginSkill(openbot_contracts::mcp::PluginSkillMutation {
                    slug: "review-notes".to_owned(),
                    title: "Review notes".to_owned(),
                    summary: "Review".to_owned(),
                    instructions: "Review the notes.".to_owned(),
                    deployment_wide: false,
                    expected_revision: None,
                }),
                "save_plugin_skill",
            ),
            (
                AppCommand::RemovePluginSkill {
                    slug: "review-notes".to_owned(),
                    expected_revision: 1,
                },
                "remove_plugin_skill",
            ),
            (
                AppCommand::GrantPlugin(openbot_contracts::mcp::PluginGrantMutation {
                    kind: openbot_contracts::mcp::PluginGrantKind::Skill,
                    reference: "review-notes".to_owned(),
                    agent_id: "agent-one".to_owned(),
                }),
                "grant_plugin",
            ),
            (
                AppCommand::RevokePlugin(openbot_contracts::mcp::PluginGrantMutation {
                    kind: openbot_contracts::mcp::PluginGrantKind::Skill,
                    reference: "review-notes".to_owned(),
                    agent_id: "agent-one".to_owned(),
                }),
                "revoke_plugin",
            ),
            (
                AppCommand::ListPluginsForAgent {
                    agent_id: BotId::new("agent-one"),
                },
                "list_plugins_for_agent",
            ),
            (
                AppCommand::ListPendingToolApprovals,
                "list_pending_tool_approvals",
            ),
            (
                AppCommand::DecideToolApproval {
                    approval_id: "approval-1".to_owned(),
                    decision: openbot_contracts::tool::ToolApprovalDecision::Grant,
                },
                "decide_tool_approval",
            ),
            (AppCommand::GetUiPreferences, "get_ui_preferences"),
            (
                AppCommand::UpdateUiPreferences(openbot_contracts::ui::UpdateUiPreferences {
                    theme: Some(openbot_contracts::ui::UiTheme::Dark),
                    locale: None,
                    expected_revision: None,
                }),
                "update_ui_preferences",
            ),
            (AppCommand::GetRunCostBudget, "get_run_cost_budget"),
            (
                AppCommand::ReplaceRunCostBudget(
                    openbot_contracts::budget::RunCostBudgetPreference::default(),
                ),
                "replace_run_cost_budget",
            ),
            (
                AppCommand::ListPendingRemoteInterrupts,
                "list_pending_remote_interrupts",
            ),
            (
                AppCommand::ResolveRemoteInterrupt {
                    request_id: "018f6f8a-5f4b-7c2d-8a31-111111111111".to_owned(),
                    answer: openbot_contracts::remote_interrupt::RemoteInterruptAnswer {
                        status: openbot_contracts::remote_interrupt::RemoteInterruptAnswerStatus::Cancelled,
                        payload: None,
                    },
                },
                "resolve_remote_interrupt",
            ),
        ];
        for (command, expected) in commands {
            assert_eq!(command_kind(&command), expected);
        }
        assert_eq!(subscription_kind(&SubscriptionRequest::Health), "health");
        assert_eq!(
            subscription_kind(&SubscriptionRequest::ThreadEvents {
                thread_id: openbot_contracts::ids::ThreadId::new(
                    "550e8400-e29b-81d4-a716-446655440000",
                ),
                after_event_sequence: Some(3),
            }),
            "thread_events"
        );
        assert_eq!(
            subscription_kind(&SubscriptionRequest::ChannelActivity),
            "channel_activity"
        );
        assert_eq!(
            subscription_kind(&SubscriptionRequest::ToolApprovalActivity),
            "tool_approval_activity"
        );
    }

    /// `AppEventStream` 必须是 `Send` 的 boxed stream：transport 会把它挪进另一个任务。
    /// 这条在编译期成立，测试只固定「它确实是那个形状」。
    #[test]
    fn app_event_stream_is_a_sendable_boxed_stream() {
        fn assert_send<T: Send>() {}
        assert_send::<AppEventStream>();
    }
}
