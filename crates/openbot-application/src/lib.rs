//! `openbot-application` —— **唯一业务入口**：所有 use case 的收口点。
//!
//! # 所有权边界（v3 §5.2 Hexagonal ownership / repository contract §4）
//!
//! 负责：
//!
//! - 暴露 typed service [`ApplicationService`]，两个方法：
//!   `execute(auth, command) -> Result<AppReply, AppError>` 与
//!   `subscribe(auth, request) -> Result<AppEventStream, AppError>`。
//! - 编排 use case：调 `openbot-domain` 做纯判定，调 `openbot-infra` / `openbot-agent` /
//!   `openbot-computer` 的 port 执行 effect，划事务边界。
//! - 工具执行管线（v3 §8.1）的顺序保证：validation → 权威 actor/target → effect 分类 →
//!   CEL + 内容策略 → 审批 → **事务写 decision + attempt** → 单次 capability → 执行 →
//!   outcome + commit_state。decision 写失败即不执行；执行了但 outcome 写不进去 →
//!   `ReconciliationRequired`，不自动重试。
//!
//! 明确**不**负责：
//!
//! - 认证本身、传输 framing、输入大小限制、错误到 HTTP/IPC 的映射 —— 那是 `openbot-server`
//!   与 `openbot-desktop` 这两个 transport 的活。
//! - 反过来：**任何 transport 都不得各自实现业务规则**（v3 §5.2）。Axum、Tauri、测试和迁移
//!   工具都只能穿过本 crate。
//! - 接受自由 method string、renderer 自报角色、renderer 自报 `principal=admin` 或任意数据库
//!   query —— 这四条在 v3 §5.2 是逐字禁止项。
//! - 用户可见文案与本地化（repository contract §4a：文案不进 domain / application）。
//!
//! # 当前状态（G1 + people/tool/audit + G3 thread/history/memory/run-runtime boundary）
//!
//! Phase 0 本 crate 刻意为空；G1 起它承载一个垂直切片所需的全部四层：
//!
//! | 模块 | 内容 | 方案出处 |
//! | --- | --- | --- |
//! | [`service`] | [`ApplicationService`] trait 与 [`AppEventStream`] | §5.2 |
//! | [`ports`] + [`components`] | channel / people / credential / audit / thread / memory / compiled component typed ports | §5.2 / §3.3 / §4.1–§4.3 / R40 / R56 / R59 / R64–R66 / R103 |
//! | [`cursor`] | keyset 游标 [`ChannelCursor`] 的铸造与 fail-closed 解析 | §15.3 |
//! | [`tenant`] | Tenant Package 五 YAML、audience 校验与 PostgreSQL 同步 port | §3.2 / §6.5 / R60 |
//! | [`use_cases`] | health/channel、people/audit、thread/history、remember/list/correct/forbid/delete/recall | §4.1–§4.3 / R56 / R64–R66 |
//! | [`chunk`] | 50ms/8KiB UTF-8 semantic chunk accumulator；真实 provider 接线仍待 G4 | §4.3 / R65 |
//! | [`run_runtime`] | 非 serde dispatch/lease、expected-sequence writer 与 accumulator→durable journal | §4.3 / §7.2 / R67 |
//! | [`screen_sessions`] | 经唯一ApplicationService发放actor/generation/host-bound viewer ticket | §12.4 / R188 |
//! | [`intelligence_import`] | verified neutral bundle、mapping/claim、ordered checksum、cursor resume | §20.3 / R68 |
//! | [`tool`] | metadata→scope→policy→approval→journal→capability→execute→outcome/audit | §8.1 / R41 |
//!
//! 具体实现 [`OpenBotApplication`] 把上面四层接起来，是 transport 唯一需要构造的类型。
//!
//! # 端口在这里定义，不在 infra 定义
//!
//! 六边形架构的方向盘：`openbot-application` **定义** [`ChannelReader`]，`openbot-infra`
//! **实现**它。所以依赖箭头是 `infra -> application`，application 对数据库一无所知。
//! 反过来（application 依赖 infra 的具体类型）会让「换一个数据源」变成改业务代码，
//! 也会让本 crate 的测试必须有一个真库 —— 本 crate 的全部测试都用内存 fake，一行 SQL
//! 都不需要，这正是方向盘朝对了的可观察后果。
//!
//! # 401 留在认证 transport，403 已由 application 生产
//!
//! `AppError::Unauthenticated`（401）在本 crate 里没有生产者，而
//! `AppError::ForbiddenRole`（403）从 W-3a 起有 admin people、W-5 起有 admin audit 真实生产者：
//!
//! - **401**：`AuthContext` 无法由外部字节铸造（contracts 里它既不 `Serialize` 也不
//!   `Deserialize`），所以「拿到了一个 `AuthContext`」本身就是「已认证」的证据。未登录
//!   请求在 transport 的认证层就被挡下，根本走不到 [`ApplicationService::execute`]。
//!   在这里再写一次 401 检查，就是给一个类型系统已经排除的世界写分支。
//! - **403**：health 与 channel list 仍不要求角色；admin status/people/audit 在调用各自 port
//!   之前统一检查权威 `AuthContext` 的 `Role::Admin`。所以同一个 roleless actor
//!   对前两类成功、对后一类得到稳定 `forbidden_role`，不是 transport 自己复制一道门。
//!
//! `app::a_roleless_authenticated_actor_is_not_rejected` 把两侧一起钉住。W-3b 已把通用 tool
//! boundary 接到 Agent gateway/PostgreSQL journal；真实 browser/MCP 等 executor 仍属 G4。

// 本 crate 是 transport 与 domain 之间的唯一门，公开面即契约面：一个没有文档的公开条目
// 等于一个只有作者知道语义的契约。用 deny 而不是 warn —— warn 会被 `cargo test` 的输出
// 淹没，只有 clippy 的 `-D warnings` 拦得住，那是半道闸门。
#![deny(missing_docs)]

pub mod agent_admin;
mod app;
pub mod approval_admin;
pub mod approval_preferences;
mod artifact_save_receipt;
pub mod artifacts;
pub mod builtin_tools;
pub mod chunk;
pub mod components;
pub mod credential_admin;
pub mod cursor;
pub mod custom_model_catalog;
mod custom_model_catalog_delivery;
pub mod intelligence_import;
pub mod mcp_connections;
pub mod model_connections;
pub mod ports;
pub mod provider;
pub mod remote_interrupt;
pub mod run_cost_budget;
pub mod run_runtime;
pub mod runtime_capabilities;
pub mod sandboxed_components;
pub mod screen_sessions;
pub mod service;
pub mod tenant;
pub mod tool;
pub mod ui_preferences;
pub mod use_cases;

#[cfg(test)]
mod fakes;

pub use agent_admin::{
    AgentCallbackTokenAdministration, AgentCallbackTokenError, NoAgentCallbackTokenAdministration,
    RemoteCallbackAuthError, RemoteCallbackAuthenticator, RemoteCallbackAuthorization,
    issue_agent_callback_token, revoke_agent_callback_token,
};
pub use app::OpenBotApplication;
pub use approval_admin::{
    NoToolApprovalAdministration, ToolApprovalAdministration, ToolApprovalAdministrationError,
    decide_tool_approval, list_pending_tool_approvals, subscribe_tool_approval_activity,
};
pub use artifact_save_receipt::get_artifact_save_receipt;
pub use artifacts::{
    ArtifactAdministration, ArtifactAdministrationError, CurrentArtifactReadChunk,
    NoArtifactAdministration, RunInputArtifactMetadataObservation, get_artifact_metadata,
    get_source_run_artifact_ids, save_run_message_text_artifact,
};
pub mod artifact_read_lifecycle;
pub mod artifact_read_protocol;
pub use artifact_read_lifecycle::{
    ArtifactReadOperation, CurrentArtifactReadBlock, CurrentArtifactReadOperation,
};
pub use artifact_read_protocol::{
    PublicArtifactReadControlDelivery, PublicArtifactReadDelivery, PublicArtifactReadTransportBlock,
};
pub use builtin_tools::{
    BUILTIN_TOOL_CATALOG_GENERATION, CommittedMemoryEffect, REMEMBER_TOOL_NAME,
    RememberToolArguments, RememberToolMemory, RememberToolMemoryRequest, RememberToolScope,
    parse_remember_tool_arguments, remember_provider_tool, remember_tool_metadata,
};
pub use chunk::{SEMANTIC_CHUNK_MAX_BYTES, SEMANTIC_CHUNK_MAX_DELAY, SemanticChunkAccumulator};
pub use components::{
    COMPONENT_HUMAN_DECISION_TTL, ComponentAdministration, ComponentAdministrationError,
    ComponentFunctionArguments, ComponentFunctionCallPlan, ComponentHumanDecisionDraft,
    ComponentHumanDecisionScope, ComponentRuntimeScope, NoComponentAdministration,
    await_component_human_decision, call_component_function, decide_component,
    list_component_data_functions, list_components, list_components_for_agent,
    list_pending_component_human_decisions, resolve_component_human_decision,
    sync_component_catalogue, update_component_governance, validate_manifest_entries,
};
pub use cursor::{ChannelCursor, channel_recency};
pub use custom_model_catalog::{
    CurrentCustomModelCatalogPage, CustomModelCatalogError, CustomModelCatalogInventory,
    NoCustomModelCatalogInventory,
};
pub use custom_model_catalog_delivery::PublicCustomModelCatalogDelivery;
pub use intelligence_import::{
    INTELLIGENCE_SOURCE_COMMIT, IntelligenceImportCursorStatus, IntelligenceImportError,
    IntelligenceImportProgress, IntelligenceImportReport, IntelligenceImportReportStatus,
    IntelligenceImportStore, IntelligenceThreadImportReceipt, IntelligenceThreadImportRequest,
    IntelligenceToolRunFkReport, VerifiedIntelligenceBundle, compute_intelligence_thread_checksum,
    import_intelligence_bundle, intelligence_import_kinds, validate_intelligence_tool_run_fk,
};
pub use mcp_connections::{
    McpConnectionAdministration, McpConnectionError, McpOAuthCallback, McpOAuthCallbackInput,
    McpOAuthCallbackOutcome, NoMcpConnectionAdministration, add_curated_mcp_server,
    add_custom_mcp_server, begin_mcp_oauth, disconnect_mcp_connection, grant_plugin,
    list_mcp_admin_page, list_mcp_connections, list_plugins_for_agent, refresh_mcp_server,
    register_mcp_oauth_client, remove_mcp_server, remove_plugin_skill, revoke_plugin,
    save_plugin_skill,
};
pub use ports::{
    AgentAdministration, AgentAdministrationError, AgentAdministrationScope, AgentDirectory,
    AgentReachability, AgentReadScope, AuditPageRequest, AuditReadError, AuditReader,
    BeginThreadRunRequest, BeginThreadRunV2Request, CancelThreadRunRequest,
    ChannelActivitySubscription, ChannelAdministration, ChannelAdministrationError,
    ChannelCreateRequest, ChannelCreateScope, ChannelReadScope, ChannelReader,
    ChannelRoutingBackend, ChannelRoutingBackendError, CorrectMemoryRequest, MemoryAdministration,
    MemoryAdministrationError, MemoryControlRequest, MemoryPageRequest, MutateMemoryRequest,
    NoAgentAdministration, NoAgentDirectory, NoAuditReader, NoChannelAdministration,
    NoChannelRoutingBackend, NoMemoryAdministration, NoPeopleAdministration,
    NoPolicyAdministration, NoThreadDirectory, OwnedCredentialRetirementError,
    OwnedCredentialRetirer, PeopleAdministration, PeoplePageRequest, PeoplePortError,
    PolicyAdministration, PolicyAdministrationError, PortError, RecallMemoriesRequest,
    RememberMemoryRequest, RoutingAuditRecord, RunEffectReceiptsRequest, RunInputArtifactMaterial,
    RunReconciliationRequest, ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError,
    ThreadEventSubscription, ThreadHistoryRequest, UpdateMemoryControlRequest,
};
pub use provider::{
    AgentAudit, AgentAuditError, AgentAuditKind, AgentAuthorizationError, AgentAuthorizationSource,
    AgentContextError, AgentContextSource, NoAgentAudit, NoRemoteInterruptCoordinator,
    PROVIDER_REMOTE_INTERRUPT_MAX_ITEMS, PROVIDER_REMOTE_PROJECTION_MAX_BYTES,
    PROVIDER_REMOTE_RESUME_PAYLOAD_MAX_BYTES, ProviderAdapter, ProviderBillingFamily,
    ProviderCostUpperBound, ProviderEvent, ProviderFailure, ProviderMessage, ProviderMessageRole,
    ProviderOutputKind, ProviderPortError, ProviderRateCard, ProviderRateCardError,
    ProviderRateCardInput, ProviderRemoteInterrupt, ProviderRemoteInterruptBatch,
    ProviderRemoteInterruptInput, ProviderRemoteProjection, ProviderRemoteProjectionError,
    ProviderRemoteProjectionKind, ProviderRemoteResume, ProviderRemoteResumeEntry,
    ProviderRemoteResumeStatus, ProviderRequest, ProviderRoute, ProviderSession, ProviderToolCall,
    ProviderToolDefinition, ProviderUsage, RemoteAguiAuthorization, RemoteAguiEventStream,
    RemoteAguiRoute, RemoteAguiTransport, RemoteAguiTransportError, RemoteInterruptCoordinator,
    RemoteInterruptError, RemoteInterruptPending, RemoteInterruptPendingInput,
    RemoteInterruptResolutionReceipt, RunModelBinding, RunModelCredentialPolicy,
    RunModelDatasetInitialOrigin, RunModelDatasetSnapshot, RunModelV2Snapshot,
};
pub use run_cost_budget::{
    NoRunCostBudgetAdministration, RunCostBudgetAdministration, RunCostBudgetAdministrationError,
    RunCostCap, get_run_cost_budget, replace_run_cost_budget,
};
pub use run_runtime::{
    ClaimedRunCancellation, ClaimedRunDispatch, DurableTextRun, NoRunDispatchConsumer,
    RunCancellationDisposition, RunDispatchConsumer, RunDispatchDecision, RunExecutionLease,
    RunFailureCode, RunRuntime, RunRuntimeError, RunSemanticChannel, RunTerminal, RunTokenUsage,
    RunTokenUsageReceipt, RunToolExchange, RunWriteReceipt,
};
pub use sandboxed_components::{
    GrantedSandboxedComponent, GrantedSandboxedComponents, MAX_SANDBOXED_COMPONENT_DRAFT_BYTES,
    NoSandboxedComponentAdministration, SandboxedComponentAdministration,
    SandboxedComponentAdministrationError, SandboxedComponentDraft, authorize_sandboxed_component,
    delete_sandboxed_component, list_published_sandboxed_components, list_sandboxed_components,
    publish_sandboxed_component, save_sandboxed_component,
};
pub use screen_sessions::{
    NoScreenSessionAdministration, ScreenSessionAdministration, ScreenSessionAdministrationError,
    issue_screen_session,
};
pub use service::{
    APPLICATION_SPAN_FIELDS, AppEventStream, ApplicationService, EXECUTE_SPAN_NAME,
    SUBSCRIBE_SPAN_NAME, TRACE_ONLY_SPAN_FIELDS, command_kind, subscription_kind,
};
pub use tool::{
    AuthorizedToolCall, ExecutableToolCall, NoToolControlPlane, NoToolJournal, ResolvedToolScope,
    ToolApprovalPresentation, ToolApprovalRequest, ToolAuditDraftError, ToolCallSequence,
    ToolCallSequenceError, ToolCancellationHandle, ToolCancellationReason,
    ToolCancellationRegistration, ToolCancellationRegistry, ToolControlPlane, ToolDecisionDraft,
    ToolExecutionCancellation, ToolExecutionReport, ToolJournal, ToolOutcomeDraft,
    ToolPolicyEvaluation, ToolPortError, ToolPreflightRefusal, ToolRefusalDraft, invoke_tool,
    tool_execution_cancellation,
};
pub use ui_preferences::{
    NoUiPreferenceAdministration, UiPreferenceAdministration, UiPreferenceAdministrationError,
    get_ui_preferences, update_ui_preferences,
};
pub use use_cases::thread::begin_thread_run_v2;
pub use use_cases::{
    DEFAULT_AUDIT_PAGE, DEFAULT_CHANNEL_PAGE, DEFAULT_MEMORY_PAGE, DEFAULT_PEOPLE_PAGE,
    MAX_AUDIT_PAGE, MAX_MEMORY_CONTENT_BYTES, MAX_MEMORY_QUERY_BYTES, MAX_MEMORY_TAG_BYTES,
    MAX_MEMORY_TAGS, MAX_PEOPLE_PAGE, MAX_ROUTING_CANDIDATES, admin_status, begin_thread_run,
    cancel_thread_run, change_person_access, change_person_role, correct_memory, create_agent,
    create_channel, current_user, delete_agent, duplicate_agent, get_action_policy,
    get_memory_control, get_thread_conversation, get_thread_history, get_thread_status,
    get_visible_agent, get_visible_channel, health, list_audit_events, list_memories, list_people,
    list_visible_agents, list_visible_channels, mint_thread_id, mutate_memory, recall_memories,
    remember_memory, route_channel_message, set_action_policy, set_agent_hidden,
    subscribe_channel_activity, subscribe_thread_events, test_agent_connection, update_agent,
    update_memory_control,
};
