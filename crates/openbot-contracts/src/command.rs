//! 唯一业务入口的 typed 命令 / 应答 / 订阅 / 事件（v3 §5.2）。
//!
//! §5.2 固定了 `openbot-application::ApplicationService` 的两个签名：
//!
//! ```text
//! async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError>;
//! async fn subscribe(&self, auth: AuthContext, request: SubscriptionRequest) -> Result<AppEventStream, AppError>;
//! ```
//!
//! trait 本身住在 `openbot-application`（它需要 `async_trait` 与 `Stream`，那是 native 侧的
//! 依赖）；本模块只定义穿越边界的**类型**，因为它们必须同时编到 wasm 给 `openbot-ui` 用。
//!
//! # 为什么这些 enum 是封闭的
//!
//! §5.2 逐字禁止：「任何 transport 都不得接受自由 method string、renderer 自报角色、renderer
//! 自报 `principal=admin` 或任意数据库 query。」
//!
//! 一个 `{ method: String, params: Value }` 形状的命令**就是**自由 method string —— 它把
//! 「有哪些用例」这件事从编译期推到了运行期的一次字符串匹配，于是 dispatcher 必然长出一个
//! `_ => Err(unknown_method)` 分支，而那个分支是 transport 在替 application 做业务判定。
//! 封闭 enum 让「不存在的用例」在**反序列化阶段**就变成 400 malformed payload（§15.3），
//! 根本到不了 application。
//!
//! # 用例随已闭合 slice 扩展
//!
//! 没有 parity ledger/第一真源条目背书的用例不能进（repository contract §4）。G1 从 channel/health
//! 起步，W-3a 追加 people，W-3b 追加 tool pipeline；R64 追加 thread mint/status，R65 同批
//! 追加 BeginThreadRun 与 durable ThreadEvents subscription/event。

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentLifecycleReceipt,
    AgentMutationRequest, AgentProfile, CallbackTokenIssued, CallbackTokenRevoked,
};
use crate::audit::AuditPage;
use crate::auth::Role;
use crate::budget::RunCostBudgetPreference;
use crate::components::{
    ComponentCatalogueAdded, ComponentCatalogueRequest, ComponentDataFunctions, ComponentDecision,
    ComponentDecisionRequest, ComponentFunctionCall, ComponentFunctionCallRequest,
    ComponentGovernanceMutation, ComponentGovernanceReceipt, ComponentHumanDecisionAnswer,
    ComponentHumanDecisionRequest, ComponentHumanDecisionResolved, ComponentRecords,
    GrantedCompiledComponents, PendingComponentHumanDecisions,
};
use crate::custom_model_catalog::{CustomModelCatalogPageRequest, CustomModelCatalogReply};
use crate::ids::{ActorId, BotId, ChannelId, RunId, ThreadId};
use crate::mcp::{
    GrantedPlugins, McpAdminPage, McpConnectionDisconnected, McpConnections,
    McpCustomServerRegistration, McpOAuthAuthorization, McpOAuthClientRegistered,
    McpOAuthClientRegistration, McpOAuthReturnTo, McpServerMutation, McpServerRemoved,
    PluginGrantMutation, PluginMutationAcknowledged, PluginSkillMutation, PluginSkills,
};
use crate::memory::{
    CorrectMemory, MemoryControl, MemoryMutation, MemoryPage, MemoryRecall, MemoryRecord,
    RecallMemories, RememberMemory, UpdateMemoryControl,
};
use crate::people::{AdminStatus, CurrentUser, PeoplePage, Person};
use crate::policy::ActionPolicyDocument;
use crate::remote_interrupt::{
    PendingRemoteInterrupts, RemoteInterruptAnswer, RemoteInterruptResolved,
};
use crate::sandboxed::{
    PublishedSandboxedComponents, SandboxedComponentDeleted, SandboxedComponentResponse,
    SandboxedComponents, SaveSandboxedComponentRequest,
};
use crate::screen::{ScreenSessionRequest, ScreenSessionTicket};
use crate::tool::{
    PendingToolApprovals, ToolApprovalActivityEvent, ToolApprovalDecision, ToolApprovalResolved,
    ToolInvocation, ToolResult,
};
use crate::ui::{UiPreferences, UpdateUiPreferences};

/// 单页 channel 的条数上限。
///
/// **parity 值**（不是新增）：出处是上游 `server/src/routes/channels/routes.ts` 的
/// `MAX_CHANNEL_PAGE` 常量。这里逐字沿用它，不擅自放大或收紧 —— 改动分页上限会改变
/// 既有客户端的翻页轮次，属于行为变更，需要单独的 ledger 条目。
///
/// 语义：[`AppCommand::ListVisibleChannels::limit`] 为 `None` 或大于本值时，application
/// 按本值截断；本 crate 只定义常量，不在这里做钳制 —— 钳制是 use case 的职责。
pub const MAX_CHANNEL_PAGE: u32 = 200;

/// 单条 initial user message 的 application 级字节上限。
///
/// 与 Server 全局 request body 1 MiB 上限取同一值；typed in-process 不经过 HTTP body layer，
/// 所以 application 必须自己守住同一资源边界。JSON framing 会让 HTTP 实际可用文本略小，
/// 但绝不能让 Desktop 绕过全局数量级。
pub const MAX_THREAD_MESSAGE_BYTES: usize = 1024 * 1024;
/// New per-turn selection budget; skills remain instructions, never tool capabilities.
pub const MAX_SELECTED_SKILLS: usize = 16;

/// Validate an ordered, bounded selection without silently dropping invalid or duplicate slugs.
#[must_use]
pub fn valid_selected_skill_slugs(slugs: &[String]) -> bool {
    slugs.len() <= MAX_SELECTED_SKILLS
        && slugs.iter().enumerate().all(|(index, slug)| {
            crate::mcp::valid_skill_slug(slug) && !slugs[..index].contains(slug)
        })
}
/// Maximum Unicode scalar count in one public create-time routing explanation.
pub const MAX_CHANNEL_ROUTING_REASON_CODE_POINTS: usize = 500;
/// Memory 管理页上限。
pub const MAX_MEMORY_PAGE: u32 = 100;

// Internally tagged unit variants otherwise ignore their remaining map fields.
// Apply this closed empty-map check only to the new input-free capability command.
fn deserialize_runtime_capabilities_input<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NoRuntimeCapabilitiesInput {}
    NoRuntimeCapabilitiesInput::deserialize(deserializer).map(|_| ())
}

/// 应用层命令。封闭 enum。
///
/// 线上表示是 internally tagged（`kind` 字段），并且 `deny_unknown_fields`：多送一个字段
/// 就是 400，不静默忽略。静默忽略未知字段等于允许调用方以为自己传了个参数而实际没有 ——
/// 那是一类特别难查的行为分歧。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppCommand {
    /// Read the actual current host's closed capability projection without inputs.
    #[serde(deserialize_with = "deserialize_runtime_capabilities_input")]
    GetRuntimeCapabilities,
    /// Explicit save of the current actor's real PG user message.
    SaveRunMessageTextArtifact(crate::artifacts::SaveRunMessageTextArtifact),
    /// Current-source-authorized metadata selector, never byte access.
    GetArtifactMetadata(crate::artifacts::GetArtifactMetadata),
    /// Observe current materialized identities for the exact source Run.
    GetSourceRunArtifactIds(crate::artifacts::GetSourceRunArtifactIds),
    /// Observe the original positive save receipt without retrying the save operation.
    GetArtifactSaveReceipt(crate::artifacts::GetArtifactSaveReceipt),
    /// Prepare an original current-host-bound memory-only artifact reader.
    OpenArtifactRead(crate::artifact_read_protocol::OpenArtifactRead),
    /// Select one sequential block; serialized control metadata never includes bytes.
    ReadArtifactReadBlock(crate::artifact_read_protocol::ReadArtifactReadBlock),
    /// Acknowledge an actually handed-off original block without byte replay.
    AcknowledgeArtifactReadBlock(crate::artifact_read_protocol::AcknowledgeArtifactReadBlock),
    /// Close only this original reader, with a truthful physical completion result.
    CloseArtifactRead(crate::artifact_read_protocol::CloseArtifactRead),
    /// 最小只读用例：探活。不读任何租户数据，也不产生 audit 事件。
    Health,

    /// List the current actor's custom-model connections.
    ListModelConnections(crate::model_connections::ModelConnectionPageRequest),
    /// 当前 actor 的版本化 custom 库存；原响应交付见证不可由 DTO 重建。
    ListCustomModelCatalog(CustomModelCatalogPageRequest),
    /// Read one current actor-owned connection.
    GetModelConnection {
        /// Opaque actor-owned connection identifier.
        connection_id: String,
    },
    /// Create a server-minted actor-owned connection and write-only key.
    CreateModelConnection(crate::model_connections::CreateModelConnection),
    /// Replace connection metadata under its current revision.
    UpdateModelConnection {
        /// Opaque actor-owned connection identifier.
        connection_id: String,
        /// Closed metadata and revision replacement.
        input: crate::model_connections::UpdateModelConnection,
    },
    /// Soft-delete a connection and retire its key under its current revision.
    DeleteModelConnection {
        /// Opaque actor-owned connection identifier.
        connection_id: String,
        /// Required concurrency revision.
        input: crate::model_connections::DeleteModelConnection,
    },

    /// 列出**当前 actor 可见的** channel。
    ///
    /// 「可见」由 application 依据 materialized membership 判定（§6.5 条 5），不由调用方
    /// 传入任何过滤条件决定 —— 那会把访问控制的判定权交给调用方。
    ListVisibleChannels {
        /// 本页最多返回多少条。`None` = 由 application 取默认值；超过
        /// [`MAX_CHANNEL_PAGE`] 由 application 截断。
        limit: Option<u32>,
        /// keyset 游标，**不透明字符串**。
        ///
        /// 上游的排序键是 `(coalesce(last_message_at, created_at) DESC, id DESC)`，游标
        /// 编码的是 `{recency, id}` 二元组。transport **不解释**它：一旦 transport 开始
        /// 解析游标，游标格式就变成了公开契约，之后换排序键会变成破坏性变更。
        /// 它由 application 铸造、由 application 解析，中间任何一层原样搬运。
        cursor: Option<String>,
    },

    /// Read one channel visible through current materialized membership.
    GetVisibleChannel {
        /// Untrusted path identity; authority still comes only from `AuthContext`.
        channel_id: ChannelId,
    },

    /// Create one private user channel and its native channel-anchored thread.
    CreateChannel {
        /// Untrusted selected Agent identities; application canonicalizes and validates them.
        agent_ids: Vec<BotId>,
    },

    /// Choose or validate the recipient for a first channel message and append routing audit.
    RouteChannelMessage {
        /// User message used only for model routing; audit never stores it.
        text: String,
        /// Explicit recipient from an `@`/picker, or `None` for inference.
        agent_id: Option<BotId>,
    },

    /// List current-actor-visible coworkers in visible or hidden roster state.
    ListVisibleAgents {
        /// False for default roster; true for per-user hidden roster.
        hidden: bool,
    },

    /// Read one current-actor-visible coworker.
    GetVisibleAgent {
        /// Untrusted path identity.
        agent_id: BotId,
    },

    /// Create one caller-owned managed or remote Agent.
    CreateAgent(AgentMutationRequest),

    /// Replace one manageable Agent's editable fields and optionally rotate remote auth.
    UpdateAgent {
        /// Untrusted path identity.
        agent_id: BotId,
        /// Full canonical form; Server-owned fields cannot fit.
        request: AgentMutationRequest,
    },

    /// Copy presentation into a new private managed-slot Agent.
    DuplicateAgent {
        /// Visible source Agent candidate.
        agent_id: BotId,
    },

    /// Set only the current actor's hidden preference.
    SetAgentHidden {
        /// Visible Agent candidate.
        agent_id: BotId,
        /// True hides; false restores to the default roster.
        hidden: bool,
    },

    /// Soft-delete one manageable non-package Agent.
    DeleteAgent {
        /// Untrusted path identity.
        agent_id: BotId,
    },

    /// Real bounded remote AG-UI probe before saving a form.
    TestAgentConnection(AgentConnectionTestRequest),

    /// List durable compiled-component governance rows for any authenticated actor.
    ListComponents,

    /// Add build-owned compiled-component catalogue entries without changing existing governance.
    SyncComponentCatalogue(ComponentCatalogueRequest),

    /// Apply one fresh-admin compiled-component governance mutation.
    UpdateComponentGovernance(ComponentGovernanceMutation),

    /// List only the published compiled components one current-actor-usable Agent actually holds.
    ListComponentsForAgent {
        /// Untrusted Agent identity; current session authority remains the only actor source.
        agent_id: BotId,
    },

    /// Re-authorize one compiled component immediately before its tool call is accepted.
    DecideComponent {
        /// Untrusted path identity for the compiled renderer/tool.
        component_name: String,
        /// Agent and declared data reads for this exact invocation.
        request: ComponentDecisionRequest,
    },

    /// List the build-owned component data functions available for administration.
    ListComponentDataFunctions,

    /// Execute one component-owned data read after all runtime checks are repeated.
    CallComponentFunction {
        /// Untrusted path identity for the compiled renderer/tool.
        component_name: String,
        /// Agent, function and bounded arguments for this exact read.
        request: ComponentFunctionCallRequest,
    },

    /// Internal Agent-host command that blocks on one durable surface/HITL answer.
    AwaitComponentHumanDecision(ComponentHumanDecisionRequest),

    /// List pending surface/HITL decisions owned by the authenticated actor.
    ListPendingComponentHumanDecisions,

    /// Resolve one pending surface/HITL decision; all binding fields come from storage.
    ResolveComponentHumanDecision {
        /// Server-minted durable decision identity.
        decision_id: String,
        /// Closed answer matched against the stored component/arguments.
        answer: ComponentHumanDecisionAnswer,
    },

    /// List every administrator-editable sandboxed component draft.
    ListSandboxedComponents,

    /// List published sandbox source for an authenticated renderer.
    ListPublishedSandboxedComponents,

    /// Save one administrator-authored sandboxed draft without publishing it.
    SaveSandboxedComponent(SaveSandboxedComponentRequest),

    /// Atomically promote one sandboxed draft to the next published revision.
    PublishSandboxedComponent {
        /// Untrusted path identity; application requires the server-owned namespace.
        component_name: String,
        /// Known editing version; publication version is a separate sequence.
        expected_revision: i64,
    },

    /// Delete one sandboxed source and its shared governance row atomically.
    DeleteSandboxedComponent {
        /// Untrusted path identity; compiled component names are never accepted.
        component_name: String,
        /// Known editing version consumed by the delete action.
        expected_revision: i64,
    },

    /// Internal Agent-host call-time authorization for one published sandboxed renderer.
    AuthorizeSandboxedComponent {
        /// Untrusted namespaced provider tool identity.
        component_name: String,
        /// Current run's authoritative Agent identity.
        agent_id: BotId,
        /// Provider arguments validated again against the current published schema.
        arguments: serde_json::Value,
    },

    /// 返回当前已验证 actor 的公开资料。
    GetCurrentUser,

    /// 管理员 gate 探针；非 admin 由 application 返回 403。
    AdminStatus,

    /// 管理员 people keyset 页。
    ListPeople {
        /// email/name 的大小写不敏感子串；空白等价未设置。
        search: Option<String>,
        /// opaque keyset cursor。
        cursor: Option<String>,
        /// 页大小；application 钳制到 1..=200。
        limit: Option<i64>,
    },

    /// 修改一个人的角色。
    ChangePersonRole {
        /// 被管理者 id。
        user_id: crate::ids::ActorId,
        /// 目标角色。
        role: Role,
    },

    /// 移除或恢复一个人的访问。
    ChangePersonAccess {
        /// 被管理者 id。
        user_id: crate::ids::ActorId,
        /// `true`=移除，`false`=恢复。
        revoked: bool,
    },

    /// 管理员审计 keyset 页；全部过滤条件由 application 归一并绑定到 typed port。
    ListAuditEvents {
        /// opaque cursor。
        cursor: Option<String>,
        /// 一个或逗号分隔的多个 event type。
        event_type: Option<String>,
        /// actor 过滤。
        actor_user_id: Option<ActorId>,
        /// target type 过滤。
        target_type: Option<String>,
        /// target id 过滤。
        target_id: Option<String>,
        /// RFC3339 开区间下界。
        from: Option<String>,
        /// RFC3339 开区间上界。
        to: Option<String>,
        /// 页长；application 钳制到 1..=100。
        limit: Option<i64>,
    },

    /// 读取 deployment-wide action policy；不带 Bot id。
    GetActionPolicy,

    /// 保存 deployment-wide action policy；actor 只能来自 `AuthContext`。
    SetActionPolicy {
        /// 已过 wire shape 校验的原始 policy 文档。
        policy: ActionPolicyDocument,
    },

    /// 由 Rust Agent gateway 铸造的一次工具调用；仍须在 application 里走完整 §8.1 管线。
    InvokeTool(ToolInvocation),

    /// 为一次 direct Bot 对话铸造带 deployment fingerprint 的 thread ID。
    ///
    /// 没有 deployment/actor 输入字段：二者只能来自权威 [`crate::auth::AuthContext`]。
    MintThreadId,

    /// 查询当前 actor 是否仍可见一条 native thread。
    GetThreadStatus {
        /// 兼容端接受任意既有 [`ThreadId`] 字符串；application 再按固定路由契约检查 UUID
        /// 外形，不能用“是否由本 deployment 铸造”替代可见性查询。
        thread_id: ThreadId,
    },

    /// 原子创建/恢复 thread 并开始一次 foreground run。
    ///
    /// actor、tenant、deployment、fencing、时间与 sequence 均不在输入面；只能由权威
    /// `AuthContext` / PostgreSQL transaction 铸造。`run_id` 同时是幂等键。
    BeginThreadRun(BeginThreadRun),
    /// 按完整 v2 选择意图接受一次 custom foreground turn。
    BeginThreadRunV2(BeginThreadRunV2),

    /// Persist an actor-owned foreground-run cancellation request.
    ///
    /// The request is durable before any in-process child is signalled. Thread/run identities are
    /// untrusted candidates; deployment, tenant and actor still come only from `AuthContext`.
    CancelThreadRun(CancelThreadRun),

    /// 读取当前 actor 可见的完整 native thread history。
    GetThreadHistory {
        /// Thread id；未知/空/不可见统一成功空列表，非 UUID 外形仍是 400。
        thread_id: ThreadId,
    },

    /// Read one atomic native conversation snapshot before attaching realtime replay.
    GetThreadConversation {
        /// Thread id; authority remains in `AuthContext` and PostgreSQL anchor membership.
        thread_id: ThreadId,
    },

    /// 读取当前 actor 拥有的 Unknown run 的持久事实；不解除占用或重试效果。
    GetRunReconciliation {
        /// 原 thread 身份。
        thread_id: ThreadId,
        /// 原 opaque run 身份。
        run_id: RunId,
        /// 原 run 内的分页位置，不携带权限。
        after: Option<crate::reconciliation::RunReconciliationCursor>,
        /// 省略为50，显式1–100。
        limit: Option<u32>,
    },

    /// 读取当前 owner 的原 Unknown run 正向业务提交回执。
    GetRunEffectReceipts {
        /// 原 thread 身份。
        thread_id: ThreadId,
        /// 原 opaque run 身份。
        run_id: RunId,
        /// 同一原 run 内的二元分页位置。
        after: Option<crate::reconciliation::RunReconciliationCursor>,
        /// 省略为50，显式1–100。
        limit: Option<u32>,
    },

    /// List current-actor pending remote AG-UI interrupts.
    ListPendingRemoteInterrupts,

    /// Resolve one server-minted remote AG-UI interrupt handle.
    ResolveRemoteInterrupt {
        /// Opaque server-minted handle; remote interrupt ids are not control authority.
        request_id: String,
        /// Closed status and bounded optional JSON payload.
        answer: RemoteInterruptAnswer,
    },

    /// GUI “记住这条”；application 固定 origin=user_action。
    RememberMemory(RememberMemory),

    /// Read the current actor's runtime memory write control.
    GetMemoryControl,

    /// Update the current actor's runtime memory write control.
    UpdateMemoryControl(UpdateMemoryControl),

    /// 当前 actor 的 memory keyset 页。
    ListMemories {
        /// 上一页最后一条 memory id；opaque。
        cursor: Option<String>,
        /// Application 钳制到 1..=100。
        limit: Option<u32>,
    },

    /// Correct 创建一条新 memory 并 supersede 旧记录。
    CorrectMemory {
        /// 当前 actor 拥有的 memory id。
        memory_id: String,
        /// 新内容字段。
        correction: CorrectMemory,
    },

    /// Forbid/delete 擦除内容并写 lifecycle event。
    MutateMemory {
        /// 当前 actor 拥有的 memory id。
        memory_id: String,
        /// 目标动作。
        mutation: MemoryMutation,
    },

    /// Scope-aware FTS recall；owner 只取 AuthContext。
    RecallMemories(RecallMemories),

    /// Issue/rotate one remote Agent's callback credential; cleartext is returned once.
    IssueAgentCallbackToken {
        /// Agent id; visibility/manageability is resolved authoritatively.
        agent_id: BotId,
    },

    /// Revoke one remote Agent's callback credential.
    RevokeAgentCallbackToken {
        /// Agent id; visibility/manageability is resolved authoritatively.
        agent_id: BotId,
    },

    /// List only the authenticated actor's per-user MCP connections.
    ListMcpConnections,

    /// Read bounded safe deployment credential metadata as an administrator.
    ListCredentials(crate::credential_admin::CredentialPageRequest),
    /// Create an encrypted manual credential; no managed identity can be supplied.
    CreateCredential(crate::credential_admin::CredentialWrite),
    /// Replace a credential and retire its predecessor atomically.
    RotateCredential {
        /// Existing credential identity.
        credential_id: String,
        /// Closed replacement input; actor comes only from AuthContext.
        input: crate::credential_admin::CredentialWrite,
    },
    /// Retire one credential locally and schedule applicable external cleanup.
    RevokeCredential {
        /// Existing credential identity.
        credential_id: String,
    },

    /// Read the deployment-wide Plugins administration projection visible to this actor.
    ListMcpAdminPage,

    /// Begin an OAuth authorization-code flow for the authenticated actor.
    BeginMcpOAuth {
        /// Stable server id; endpoint and client are resolved authoritatively.
        server_id: String,
        /// Closed in-app destination, never a caller-provided URL.
        return_to: McpOAuthReturnTo,
    },

    /// Tombstone the actor's local connection before attempting vendor revocation.
    DisconnectMcpConnection {
        /// Stable server id owned by the current connection.
        server_id: String,
    },

    /// Register/rotate a deployment OAuth client after admin authorization.
    RegisterMcpOAuthClient {
        /// Stable server id whose resource metadata is validated before storage.
        server_id: String,
        /// Redacted, zeroizing registration input.
        registration: McpOAuthClientRegistration,
    },

    /// Add a server from the compile-time reviewed catalogue; callers provide no URL.
    AddCuratedMcpServer {
        /// Exact catalogue key.
        key: String,
    },

    /// Register a custom Streamable HTTP server under explicit administrator authority.
    AddCustomMcpServer(McpCustomServerRegistration),

    /// Remove one configured server and its cascading catalog/connection rows.
    RemoveMcpServer {
        /// Stable configured server id.
        server_id: String,
    },

    /// Refresh one configured server catalogue under admin authority.
    RefreshMcpServer {
        /// Stable configured server id.
        server_id: String,
    },

    /// Create or update one actor/deployment-owned skill.
    SavePluginSkill(PluginSkillMutation),

    /// Remove one skill the actor may manage.
    RemovePluginSkill {
        /// Stable skill slug.
        slug: String,
        /// Editing revision known when the skill was opened.
        expected_revision: i64,
    },

    /// Grant one current MCP tool or skill to one authorized Agent.
    GrantPlugin(PluginGrantMutation),

    /// Revoke one MCP tool or skill from one authorized Agent.
    RevokePlugin(PluginGrantMutation),

    /// List current actor-specific plugins for one visible Agent.
    ListPluginsForAgent {
        /// Agent whose visibility is re-evaluated authoritatively.
        agent_id: BotId,
    },

    /// List pending proof-of-intent requests for the authenticated actor.
    ListPendingToolApprovals,

    /// Resolve one exact stored approval; binding fields cannot be supplied by the caller.
    DecideToolApproval {
        /// Server-minted approval id.
        approval_id: String,
        /// Grant or deny.
        decision: ToolApprovalDecision,
    },

    /// Read the authenticated actor's independently optional theme/locale preferences.
    GetUiPreferences,

    /// Atomically update one or both UI preferences; actor/scope come only from `AuthContext`.
    UpdateUiPreferences(UpdateUiPreferences),

    /// Read the authenticated actor's per-run provider cost cap.
    GetRunCostBudget,

    /// Fully replace the authenticated actor's per-run provider cost cap.
    ReplaceRunCostBudget(RunCostBudgetPreference),

    /// Issue one actor/generation/host-bound ScreenSession ticket.
    IssueScreenSession(ScreenSessionRequest),
}

/// 应用层应答。封闭 enum，与 [`AppCommand`] 一一对应。
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppReply {
    /// Current-authenticated closed runtime capability projection.
    RuntimeCapabilities(crate::runtime_capabilities::RuntimeCapabilitiesResponse),
    /// Content-free positive local registration fact.
    ArtifactRegistrationReceipt(crate::artifacts::ArtifactRegistrationReceipt),
    /// Current-authorized artifact metadata with distinct live/tombstone shapes.
    ArtifactMetadata(crate::artifacts::ArtifactMetadata),
    /// Current IDs-only source observation; no body or read handle.
    SourceRunArtifactIds(crate::artifacts::SourceRunArtifactIds),
    /// Actual prepared artifact facts and a bound memory locator.
    ArtifactReadOpened(crate::artifact_read_protocol::ArtifactReadOpened),
    /// Finite block control metadata; bytes use the trusted non-Serde delivery port.
    ArtifactReadChunkDescriptor(crate::artifact_read_protocol::ArtifactReadChunkDescriptor),
    /// Original accepted block acknowledgment, with no new IO or retry permission.
    ArtifactReadAcknowledged(crate::artifact_read_protocol::ArtifactReadAcknowledged),
    /// Actual completion of this reader's original physical resources.
    ArtifactReadClosed(crate::artifact_read_protocol::ArtifactReadClosed),
    /// [`AppCommand::Health`] 的应答。
    Health(HealthReport),
    /// [`AppCommand::ListVisibleChannels`] 的应答。
    Channels(ChannelPage),
    /// [`AppCommand::GetVisibleChannel`] 的应答。
    Channel(ChannelDetail),
    /// [`AppCommand::RouteChannelMessage`] response.
    ChannelRouting(ChannelRoutingDecision),
    /// [`AppCommand::ListVisibleAgents`] response.
    Agents(Vec<AgentProfile>),
    /// [`AppCommand::GetVisibleAgent`] response.
    Agent(AgentProfile),
    /// Hide/unhide/delete authoritative acknowledgement.
    AgentLifecycle(AgentLifecycleReceipt),
    /// Pre-save remote endpoint probe verdict.
    AgentConnectionVerdict(AgentConnectionVerdict),
    /// [`AppCommand::ListComponents`] response.
    Components(ComponentRecords),
    /// [`AppCommand::SyncComponentCatalogue`] response.
    ComponentCatalogueAdded(ComponentCatalogueAdded),
    /// [`AppCommand::UpdateComponentGovernance`] response.
    ComponentGovernanceUpdated(ComponentGovernanceReceipt),
    /// [`AppCommand::ListComponentsForAgent`] response.
    GrantedComponents(GrantedCompiledComponents),
    /// [`AppCommand::DecideComponent`] response.
    ComponentDecision(ComponentDecision),
    /// [`AppCommand::ListComponentDataFunctions`] response.
    ComponentDataFunctions(ComponentDataFunctions),
    /// [`AppCommand::CallComponentFunction`] response.
    ComponentFunctionCall(ComponentFunctionCall),
    /// [`AppCommand::ListPendingComponentHumanDecisions`] response.
    PendingComponentHumanDecisions(PendingComponentHumanDecisions),
    /// Await/resolve response carrying the exact provider tool result.
    ComponentHumanDecisionResolved(ComponentHumanDecisionResolved),
    /// [`AppCommand::ListSandboxedComponents`] response.
    SandboxedComponents(SandboxedComponents),
    /// [`AppCommand::ListPublishedSandboxedComponents`] response.
    PublishedSandboxedComponents(PublishedSandboxedComponents),
    /// Save/publish response carrying the committed authoritative row.
    SandboxedComponent(SandboxedComponentResponse),
    /// [`AppCommand::DeleteSandboxedComponent`] response.
    SandboxedComponentDeleted(SandboxedComponentDeleted),
    /// [`AppCommand::GetCurrentUser`] 应答。
    CurrentUser(CurrentUser),
    /// [`AppCommand::AdminStatus`] 应答。
    AdminStatus(AdminStatus),
    /// [`AppCommand::ListPeople`] 应答。
    People(PeoplePage),
    /// role/access 变更后的最新 person。
    Person(Person),
    /// [`AppCommand::ListAuditEvents`] 应答。
    AuditEvents(AuditPage),
    /// 当前 action policy；`None` = 尚未首次配置，default-deny。
    ActionPolicy {
        /// 当前文档；`None` = 尚未首次配置。
        policy: Option<ActionPolicyDocument>,
    },
    /// [`AppCommand::InvokeTool`] 的已持久化、已脱敏结果。
    Tool(ToolResult),
    /// [`AppCommand::MintThreadId`] 的应答。
    ThreadMinted(ThreadMinted),
    /// [`AppCommand::GetThreadStatus`] 的应答。
    ThreadStatus(ThreadStatus),
    /// [`AppCommand::BeginThreadRun`] 的 durable receipt。
    ThreadRunStarted(ThreadRunStarted),
    /// [`AppCommand::CancelThreadRun`] durable acknowledgement.
    ThreadRunCancellation(ThreadRunCancellation),
    /// [`AppCommand::GetThreadHistory`] 的应答。
    ThreadHistory(ThreadHistory),
    /// Unknown run 的受权只读事实页。
    RunReconciliation(crate::reconciliation::RunReconciliationSnapshot),
    /// 原 Unknown run 的受权历史业务回执页。
    RunEffectReceipts(crate::reconciliation::RunEffectReceiptsSnapshot),
    /// [`AppCommand::GetThreadConversation`] response.
    ThreadConversation(ThreadConversationSnapshot),
    /// [`AppCommand::ListPendingRemoteInterrupts`] response.
    PendingRemoteInterrupts(PendingRemoteInterrupts),
    /// [`AppCommand::ResolveRemoteInterrupt`] response.
    RemoteInterruptResolved(RemoteInterruptResolved),
    /// Remember/correct/mutate 后的记录。
    Memory(MemoryRecord),
    /// Actor-scoped runtime memory write control.
    MemoryControl(MemoryControl),
    /// [`AppCommand::ListMemories`] 的页。
    Memories(MemoryPage),
    /// [`AppCommand::RecallMemories`] 的结果。
    MemoryRecall(MemoryRecall),
    /// [`AppCommand::IssueAgentCallbackToken`] 的一次性明文结果。
    AgentCallbackToken(CallbackTokenIssued),
    /// [`AppCommand::RevokeAgentCallbackToken`] 的无 secret acknowledgement。
    AgentCallbackTokenRevoked(CallbackTokenRevoked),
    /// [`AppCommand::ListMcpConnections`] response.
    McpConnections(McpConnections),
    /// [`AppCommand::ListCredentials`] safe inventory page.
    Credentials(crate::credential_admin::CredentialPage),
    /// Current owner's bounded model inventory.
    ModelConnections(crate::model_connections::ModelConnectionPage),
    /// 当前 owner 的原请求目录应答，必须经过 Application 一次交付消费。
    CustomModelCatalog(CustomModelCatalogReply),
    /// Safe connection read/write receipt.
    ModelConnection(crate::model_connections::ModelConnection),
    /// Confirmed local connection retirement.
    ModelConnectionDeleted(crate::model_connections::ModelConnectionDeleted),
    /// [`AppCommand::CreateCredential`] / [`AppCommand::RotateCredential`] receipt.
    CredentialWritten(crate::credential_admin::CredentialWritten),
    /// [`AppCommand::RevokeCredential`] local retirement receipt.
    CredentialRevoked(crate::credential_admin::CredentialRevoked),
    /// [`AppCommand::ListMcpAdminPage`] response.
    McpAdminPage(McpAdminPage),
    /// [`AppCommand::BeginMcpOAuth`] response.
    McpOAuthAuthorization(McpOAuthAuthorization),
    /// [`AppCommand::DisconnectMcpConnection`] response.
    McpConnectionDisconnected(McpConnectionDisconnected),
    /// [`AppCommand::RegisterMcpOAuthClient`] response.
    McpOAuthClientRegistered(McpOAuthClientRegistered),
    /// [`AppCommand::AddCuratedMcpServer`] or [`AppCommand::RefreshMcpServer`] response.
    McpServerMutation(McpServerMutation),
    /// [`AppCommand::RemoveMcpServer`] response.
    McpServerRemoved(McpServerRemoved),
    /// Skill save response carrying the current visible list.
    PluginSkills(PluginSkills),
    /// Skill removal or grant/revoke acknowledgement.
    PluginMutationAcknowledged(PluginMutationAcknowledged),
    /// Current actor-specific plugin set for one visible Agent.
    GrantedPlugins(GrantedPlugins),
    /// [`AppCommand::ListPendingToolApprovals`] response.
    PendingToolApprovals(PendingToolApprovals),
    /// [`AppCommand::DecideToolApproval`] response.
    ToolApprovalResolved(ToolApprovalResolved),
    /// UI preference read/update response.
    UiPreferences(UiPreferences),
    /// Per-run cost budget read/replacement response.
    RunCostBudget(RunCostBudgetPreference),
    /// One-time screen viewer ticket; its `Debug` implementation redacts the secret protocol.
    ScreenSession(ScreenSessionTicket),
}

/// 探活结果。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    /// 进程是否可服务。
    ///
    /// 刻意只有一个布尔：readiness 的细节（数据库池、sidecar 版本、engine 状态）属于
    /// §16.4 的 metrics 与 `openbot-server` 的 `/readyz`，不是跨边界 DTO 的内容。把依赖
    /// 明细放进公开应答会顺带泄漏部署拓扑。
    pub ok: bool,
}

/// `POST /api/threads/mint` 的稳定应答形状。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadMinted {
    /// 带 deployment fingerprint 的 UUIDv8。
    pub thread_id: ThreadId,
}

/// `GET /api/threads/{thread_id}` 的稳定应答形状。
///
/// `false` 同时覆盖“不存在、已删除、对当前 actor 不可见”，避免用状态接口枚举别人的 thread。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadStatus {
    /// 当前权威 scope 能否产生这条 thread。
    pub known: bool,
}

/// 一次新 thread/run 的 anchor；不能同时自报 channel 与 direct Bot。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ThreadRunAnchor {
    /// Channel transcript；application/infra 仍须验证 actor membership 与 Bot attachment。
    Channel {
        /// 权威 channel 候选。
        channel_id: ChannelId,
    },
    /// Direct Bot chat；anchor id 等于 [`BeginThreadRun::bot_id`]。
    DirectBot,
}

/// 开始一次 native foreground turn 的最小输入。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginThreadRun {
    /// Optional personal model selection; scope and credential are resolved by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_selection: Option<crate::model_connections::RunModelSelection>,
    /// 由 `/api/threads/mint` 或迁移输入得到的 thread id。
    pub thread_id: ThreadId,
    /// 调用方铸造的 durable 幂等键；相同 ID + 相同内容返回同一 receipt。
    pub run_id: RunId,
    /// 要运行的 Bot；可见性由权威存储验证。
    pub bot_id: BotId,
    /// Channel/direct 互斥 anchor。
    pub anchor: ThreadRunAnchor,
    /// initial user message；原样保存，不做 Unicode normalization。
    pub message: String,
    /// Explicitly selected granted skills, in invocation order. Rust resolves instruction bodies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_skill_slugs: Vec<String>,
    /// Referenced artifacts, in caller order; authority is checked during admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_refs: Vec<String>,
}

/// Native HTTP body for beginning a run on the thread identified by the route path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginThreadRunBody {
    /// Optional connection ID/revision for this run; omission preserves the existing route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_selection: Option<crate::model_connections::RunModelSelection>,
    /// Caller-minted durable idempotency key.
    pub run_id: RunId,
    /// Selected Agent; authority is rechecked against the anchor.
    pub bot_id: BotId,
    /// Channel/direct anchor; the stored thread must match it exactly.
    pub anchor: ThreadRunAnchor,
    /// Initial user message.
    pub message: String,
    /// Explicit skill selection; omitted/empty preserves the original no-skill request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_skill_slugs: Vec<String>,
    /// Referenced artifacts, in caller order; authority is checked during admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_refs: Vec<String>,
}

/// v2 foreground 输入；模型、凭据、scope 和 dataset 权限由原事务重新核验。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginThreadRunV2 {
    /// 必需的原 v2 选择意图；其值不授予使用权限。
    pub model_selection: crate::versioned_model_selection::RunModelSelectionV2,
    /// 原 thread 身份。
    pub thread_id: ThreadId,
    /// 调用方的 durable 幂等键。
    pub run_id: RunId,
    /// 目标 Bot，由数据库核其当前可见性。
    pub bot_id: BotId,
    /// 原 channel/direct anchor。
    pub anchor: ThreadRunAnchor,
    /// 原样保存的用户消息。
    pub message: String,
    /// 有序技能选择，省略表示空集合。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_skill_slugs: Vec<String>,
    /// Referenced artifacts, in caller order; authority is checked during admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_refs: Vec<String>,
}

impl core::fmt::Debug for BeginThreadRunV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BeginThreadRunV2([redacted])")
    }
}

/// 同一 runs URI 的 v2 body；不接受 owner、dataset、endpoint 或 secret。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginThreadRunV2Body {
    /// 必需的完整 v2 选择意图。
    pub model_selection: crate::versioned_model_selection::RunModelSelectionV2,
    /// 调用方的 durable 幂等键。
    pub run_id: RunId,
    /// 原目标 Bot。
    pub bot_id: BotId,
    /// 原 channel/direct anchor。
    pub anchor: ThreadRunAnchor,
    /// 原样保存的用户消息。
    pub message: String,
    /// 有序技能选择，省略表示空集合。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_skill_slugs: Vec<String>,
    /// Referenced artifacts, in caller order; authority is checked during admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_refs: Vec<String>,
}

impl core::fmt::Debug for BeginThreadRunV2Body {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BeginThreadRunV2Body([redacted])")
    }
}

/// thread/message/run/event/outbox 同事务提交后的 receipt。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadRunStarted {
    /// Thread id。
    pub thread_id: ThreadId,
    /// Run id / 幂等键。
    pub run_id: RunId,
    /// initial user message 的 thread-local sequence。
    pub message_sequence: u64,
    /// `started` semantic event 的 thread-global reconnect cursor。
    pub event_sequence: u64,
    /// `true` 表示完全相同的 run_id 请求已提交过，本次没有新增行/通知。
    pub replayed: bool,
}

/// Minimal input for durable foreground-run cancellation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelThreadRun {
    /// Native thread bound by the route/application scope.
    pub thread_id: ThreadId,
    /// Current foreground run candidate.
    pub run_id: RunId,
}

/// Durable request outcome. A stale Stop racing a terminal is a successful closed observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadRunCancellationState {
    /// This call inserted the replay-safe internal control request.
    Requested,
    /// The same exact request already exists and remains authoritative.
    AlreadyRequested,
    /// The run was already terminal; no cancellation request was added.
    AlreadyTerminal,
}

/// Durable cancellation acknowledgement; it never claims that children have stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadRunCancellation {
    /// Bound native thread.
    pub thread_id: ThreadId,
    /// Bound foreground run.
    pub run_id: RunId,
    /// Request persistence outcome, not the eventual terminal state.
    pub state: ThreadRunCancellationState,
}

/// AG-UI history 可观察的 message role 子集。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreadHistoryRole {
    /// 人类输入。
    User,
    /// Agent 文本/工具调用。
    Assistant,
    /// System/summary 上下文。
    System,
    /// Tool result。
    Tool,
}

/// compatibility facade 与 native GUI 共用的 history message。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadHistoryMessage {
    /// Original explicit skill selection for a user turn; independent of later grant changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_skill_slugs: Vec<String>,
    /// Durable message id。
    pub id: String,
    /// AG-UI role。
    pub role: ThreadHistoryRole,
    /// 文本 content；assistant tool-only message 可为空。
    pub content: String,
    /// Server-derived Agent identity for messages attached to a run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<BotId>,
    /// Tool result 指向的 call id；只对 role=tool 存在。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool result's authoritative catalog name; only role=tool may carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Stable tool/component refusal code; only role=tool may carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_error_code: Option<String>,
    /// Assistant tool calls 的结构化 AG-UI 值；当前 begin slice 为空，G4 writer 接入后使用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<serde_json::Value>>,
}

/// 完整 thread history；空列表是成功值而不是错误。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadHistory {
    /// Durable sequence 顺序的 messages。
    pub messages: Vec<ThreadHistoryMessage>,
}

/// Current foreground state projected from durable run + cancellation outbox facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadForegroundRunState {
    /// Durable row exists but execution has not begun.
    Queued,
    /// Provider/tool child may be active and no cancellation has been requested.
    Running,
    /// A durable cancellation request exists; terminal still waits for children-stopped facts.
    Cancelling,
    /// External commit state is unknown and the foreground slot remains blocked.
    ReconciliationRequired,
}

/// Atomic PostgreSQL snapshot used to join durable history to realtime replay without a gap.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadConversationSnapshot {
    /// Durable messages ordered by thread-local sequence.
    pub messages: Vec<ThreadHistoryMessage>,
    /// Current foreground run that blocks another send, if any.
    pub active_run_id: Option<RunId>,
    /// Closed foreground state; `None` exactly when `active_run_id` is `None`.
    pub active_run_state: Option<ThreadForegroundRunState>,
    /// Whether this actor may issue the first cancellation request for the active run.
    pub active_run_cancellable: bool,
    /// Already committed text chunks for the active run; empty when no text/run exists.
    pub active_run_text: String,
    /// Last committed thread-global event cursor; `None` means the thread has no events.
    pub last_event_sequence: Option<u64>,
}

/// 一页 channel。
///
/// **空列表是合法值**（§15.3 末条：「空、新 thread history 200 + empty list」）：
/// `items` 为空时序列化成 `[]` 而不是 `null`，`next_cursor` 为 `None` 时序列化成 `null`
/// 而不是被省略。上游缺陷 #72「空 history 500」正是把「空」当成错误的结果（§2.4），
/// 本类型在序列化形状上就把这条堵死，并由 `empty_page_serializes_as_empty_list` 钉住。
///
/// # 字段名为什么是 camelCase
///
/// v3 §15.1 把现有 `/api/channels` 的 **input/output schema** 纳入 canonical inventory 的
/// parity 面，所以线上字段名是契约的一部分，不是风格问题。上游 `channelSummaryDto` 发出的
/// 是 `channels` / `nextCursor` / `agentIds` / `threadId` / `lastMessageAt` 这一组 camelCase
/// 名字。这里用 `rename_all` 让**同一个类型**既是内部 typed 边界又是线上形状 —— 另建一层
/// HTTP DTO 做改名同样能对齐，但那是两份必须手工保持同步的真源，改一处忘另一处不会有人发现。
/// 由 `channel_page_json_keys_match_upstream_wire` 与 `channel_summary_json_keys_match_upstream_wire`
/// 两条测试逐键钉死。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPage {
    /// 本页条目，可能为空。上游键名是 `channels`（不是 `items`）。
    pub channels: Vec<ChannelSummary>,
    /// 下一页游标；`None` 表示已到末页。不透明，见
    /// [`AppCommand::ListVisibleChannels::cursor`]。
    pub next_cursor: Option<String>,
}

/// One authenticated channel detail, excluding roster-only activity fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDetail {
    /// Channel identity.
    pub id: ChannelId,
    /// Display name from PostgreSQL.
    pub name: String,
    /// Canonically sorted linked Bots.
    pub agent_ids: Vec<BotId>,
    /// Current native thread for this deployment/tenant/member, if one has started.
    pub thread_id: Option<ThreadId>,
    /// False when at least one linked Bot profile is soft-deleted.
    pub active: bool,
}

/// Exact `GET /api/channels/{channel_id}` response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelDetailResponse {
    /// Authenticated detail.
    pub channel: ChannelDetail,
}

/// Closed `POST /api/channels` request; every other channel field is server-minted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateChannelRequest {
    /// One or more selected Agent identities.
    pub agent_ids: Vec<BotId>,
}

/// Closed `POST /api/route` request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteChannelRequest {
    /// First-message text; trimmed for routing but never written to audit.
    pub text: String,
    /// Optional explicit recipient.
    pub agent_id: Option<BotId>,
}

/// Exact recipient-decision response used by the native GUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelRoutingDecision {
    /// Chosen Agent identity.
    pub agent_id: BotId,
    /// Chosen Agent display name.
    pub name: String,
    /// Bounded explanation suitable for presentation.
    pub reason: String,
    /// True when deterministic defaulting replaced inference.
    pub fallback: bool,
    /// True when the person explicitly selected the Agent.
    pub via_mention: bool,
}

/// channel 列表项。
///
/// 这是 **DTO，不是行结构**：真实 `channels` 表有 12 列，这里只投影上游 channel `list`
/// 路由实际返回的那几项。两条刻意的排除：
///
/// - **`allowed_groups` 绝不进 DTO**。§6.5 条 5 定死「group 只负责 provision channel
///   membership，所有运行时 channel route 仍检查 materialized membership」。把它发给
///   transport 会诱导下游拿它做访问判定 —— 那正是上游 `allowed_groups` 长期是 no-op 的
///   同一枚硬币的反面（§2.4）。可见性判定已经在服务端做完了，客户端拿到这一行就等于有权看。
/// - `package_id` / `override` / `description` / `suggested_prompts` / `updated_at` 属于
///   channel 详情或 provisioning 面，不属于列表投影；需要时随各自的 ledger 条目单独加。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelSummary {
    /// channel 身份。
    pub id: ChannelId,
    /// 展示名。它是**数据**不是文案：不进本地化表，原样来自数据库。
    pub name: String,
    /// 该 channel 上挂载的 bot。
    pub agent_ids: Vec<BotId>,
    /// 最近一条消息的文本预览；从未有过消息时为 `None`。
    pub last_message: Option<String>,
    /// 最近一条消息的时间；从未有过消息时为 `None`。
    ///
    /// 它同时是 keyset 排序键的第一项（`coalesce(last_message_at, created_at) DESC`）。
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_message_at: Option<OffsetDateTime>,
    /// 发出最近一条消息的 bot；人类发出或从未有过消息时为 `None`。
    pub last_message_agent_id: Option<BotId>,
    /// 创建时间。`last_message_at` 缺失时它是排序键的回落项。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// 该 channel 关联的 thread；尚未开出 thread 时为 `None`。
    ///
    /// # 为什么是 `Option`，而上游那一项非空
    ///
    /// 上游 `channels/routes.ts` 的 `channelDto` 里 `threadId` 是必填 `string`，但那个
    /// 非空**是 join 造出来的假象**：`list` 与 `get` 都对 `intelligence_channel_mappings`
    /// 做 INNER JOIN，没有 mapping 行的 channel 根本不会出现在结果里 —— 于是"每个可见
    /// channel 都有 thread"在上游恒真。
    ///
    /// 那个 join 必须删（§28.1 R22）：Intelligence 已按 §4.1 退役、该表按 §14.2 降级为
    /// 只读 legacy provenance，继续 join 会把 §6.5 刚补上 membership 的包 channel 原样
    /// 过滤回不可达。join 一删，"可见但还没有 thread"就成了合法状态（例如刚 provision、
    /// 还没有人打开过的包 channel），所以这里必须是 `Option`。
    ///
    /// 它的数据源随之改为 §4.3 的 native `threads`，**不是** `intelligence_channel_mappings`。
    /// G1 还没有 native thread 表，本字段恒 `None`；G3 接上真源。
    pub thread_id: Option<ThreadId>,
    /// 该 channel 当前是否可用。
    pub active: bool,
}

/// One committed channel-roster activity projection; membership is never serialized in the frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelActivityEvent {
    /// Channel whose authoritative summary changed.
    pub channel_id: ChannelId,
    /// Bounded one-line preview, or `None` when cleared.
    pub last_message: Option<String>,
    /// Authoritative activity timestamp.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_message_at: Option<OffsetDateTime>,
    /// Bot that produced the preview; user messages use `None`.
    pub last_message_agent_id: Option<BotId>,
}

/// 订阅请求。封闭 enum，理由同 [`AppCommand`]。
///
/// R65 后有探活与 durable thread events 两项；后者必须由 PostgreSQL replay→live producer 承担。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubscriptionRequest {
    /// 订阅心跳流。
    Health,

    /// 订阅一条可见 thread 的 durable semantic events。
    ThreadEvents {
        /// Thread id；scope 仍只取 AuthContext。
        thread_id: ThreadId,
        /// 客户端最后完整接收的 thread-global cursor；`None` 从第一条开始。
        after_event_sequence: Option<u64>,
    },
    /// Subscribe to low-latency channel roster activity for the authenticated actor.
    ChannelActivity,
    /// Subscribe to actor-scoped approval refresh hints; durable state remains the typed list.
    ToolApprovalActivity,
}

/// 订阅流上的事件。封闭 enum。
///
/// 注意 `AppEventStream` 本身**不在**本 crate：它是 `Stream<Item = AppEvent>` 的别名，
/// 需要 `futures`/`async` 机制，属于 `openbot-application`。本 crate 只承载帧的内容。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppEvent {
    /// 心跳。`seq` 单调递增，供 viewer 判断是否丢帧。
    Heartbeat {
        /// 序号。
        seq: u64,
    },
    /// 从 PostgreSQL durable journal replay/live 得到的一条 semantic event。
    ThreadRunEvent(ThreadRunEvent),
    /// 订阅建立后依赖失败；只携带稳定 code，随后流结束，客户端按 cursor 重连。
    ThreadStreamError {
        /// 稳定错误码；不携带数据库/网络原文。
        code: String,
    },
    /// Committed channel roster activity; clients refetch on every reconnect.
    ChannelActivity(ChannelActivityEvent),
    /// Channel LISTEN/membership dependency failed; the socket closes after this frame.
    ChannelStreamError {
        /// Stable error code; no database/network text.
        code: String,
    },
    /// Approval state changed for this authenticated actor; clients refetch the durable list.
    ToolApprovalActivity(ToolApprovalActivityEvent),
    /// Approval activity dependency failed; socket closes after this stable error.
    ToolApprovalStreamError {
        /// Stable error code; no database/network text or approval identity.
        code: String,
    },
}

/// 跨 transport 的封闭 semantic run event 类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadRunEventKind {
    /// Run 开始。
    Started,
    /// 50ms/8KiB 合并后的文本/推理 chunk。
    SemanticChunk,
    /// Operational checkpoint；不是 memory。
    Checkpoint,
    /// 正常 terminal。
    Completed,
    /// 确定失败 terminal。
    Failed,
    /// 取消 terminal。
    Cancelled,
    /// 未知提交 terminal。
    ReconciliationRequired,
}

impl ThreadRunEventKind {
    /// 从 PostgreSQL 封闭值解析；未知值返回 `None`，不能降级成 custom。
    #[must_use]
    pub const fn from_database(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"started" => Some(Self::Started),
            b"semantic_chunk" => Some(Self::SemanticChunk),
            b"checkpoint" => Some(Self::Checkpoint),
            b"completed" => Some(Self::Completed),
            b"failed" => Some(Self::Failed),
            b"cancelled" => Some(Self::Cancelled),
            b"reconciliation_required" => Some(Self::ReconciliationRequired),
            _ => None,
        }
    }

    /// terminal 属性由 kind 决定，不能由 payload 自报。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::ReconciliationRequired
        )
    }
}

/// 一条可重放的 thread-global semantic event。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadRunEvent {
    /// Thread。
    pub thread_id: ThreadId,
    /// Run。
    pub run_id: RunId,
    /// thread-global cursor，严格递增。
    pub event_sequence: u64,
    /// 封闭 event kind。
    pub event_type: ThreadRunEventKind,
    /// 已结构验证的 semantic payload。
    pub payload: serde_json::Value,
    /// 必须与 [`ThreadRunEventKind::is_terminal`] 相等。
    pub terminal: bool,
    /// PostgreSQL commit timestamp。
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn artifact_refs_dtos_preserve_omitted_empty_and_ordered_wire() {
        macro_rules! check {
            ($dto:ty, $original:expr) => {{
                let original = $original;
                let omitted: $dto = serde_json::from_value(original.clone()).unwrap();
                assert!(omitted.artifact_refs.is_empty());
                assert_eq!(serde_json::to_value(&omitted).unwrap(), original);
                let original_bytes = serde_json::to_vec(&omitted).unwrap();

                let mut empty_wire = original.clone();
                empty_wire["artifactRefs"] = serde_json::json!([]);
                let empty: $dto = serde_json::from_value(empty_wire).unwrap();
                assert_eq!(empty, omitted);
                assert_eq!(serde_json::to_vec(&empty).unwrap(), original_bytes);

                let refs = vec![
                    "0196ea23-b507-73c8-8153-213383fdc24a".to_owned(),
                    "0196ea23-b506-73c8-8153-213383fdc24a".to_owned(),
                ];
                let mut populated = omitted;
                populated.artifact_refs = refs.clone();
                let wire = serde_json::to_value(&populated).unwrap();
                assert_eq!(wire["artifactRefs"], serde_json::json!(refs));
                let round_trip: $dto = serde_json::from_value(wire).unwrap();
                assert_eq!(round_trip, populated);

                let mut unknown = original.clone();
                unknown["artifactRef"] = serde_json::json!([]);
                assert!(serde_json::from_value::<$dto>(unknown).is_err());
                for malformed in [
                    serde_json::Value::Null,
                    serde_json::json!("not-an-array"),
                    serde_json::json!([1]),
                ] {
                    let mut value = original.clone();
                    value["artifactRefs"] = malformed;
                    assert!(serde_json::from_value::<$dto>(value).is_err());
                }
            }};
        }

        let body = serde_json::json!({
            "runId": "run-1", "botId": "bot-1",
            "anchor": {"kind": "direct_bot"}, "message": "unchanged"
        });
        check!(BeginThreadRunBody, body.clone());
        let mut command = body.clone();
        command["threadId"] = serde_json::json!("thread-1");
        check!(BeginThreadRun, command);

        let mut v2_body = body;
        v2_body["modelSelection"] = serde_json::json!({
            "schemaVersion": 2, "source": "custom",
            "connectionId": "0196ea23-b506-73c8-8153-213383fdc24a",
            "expectedConnectionRevision": 1, "modelId": "model",
            "expectedCatalogRevision": 1
        });
        check!(BeginThreadRunV2Body, v2_body.clone());
        v2_body["threadId"] = serde_json::json!("thread-1");
        check!(BeginThreadRunV2, v2_body);
    }

    fn sample_summary() -> ChannelSummary {
        ChannelSummary {
            id: ChannelId::new("legacy-channel-42"),
            name: "General".to_owned(),
            agent_ids: vec![BotId::new("bot-1")],
            // 有 thread 的常态；与下面 channel_summary_without_messages_round_trips 里的
            // None 构成两向对照 —— 只测一侧的话，Option 序列化成 null 还是被整键省略
            // 这个差别照不出来。
            thread_id: Some(ThreadId::new("thread-1")),
            last_message: Some("hi".to_owned()),
            last_message_at: Some(datetime!(2026-08-22 04:05:06 UTC)),
            last_message_agent_id: Some(BotId::new("bot-1")),
            created_at: datetime!(2026-08-01 00:00:00 UTC),
            active: true,
        }
    }

    #[test]
    fn selected_skill_wire_is_optional_ordered_and_cannot_carry_instructions() {
        let legacy = serde_json::json!({"runId":"run-1","botId":"bot-1",
            "anchor":{"kind":"direct_bot"},"message":"unchanged"});
        let mut command: BeginThreadRunBody = serde_json::from_value(legacy.clone()).unwrap();
        assert!(command.selected_skill_slugs.is_empty());
        assert_eq!(serde_json::to_value(&command).unwrap(), legacy);
        command.selected_skill_slugs = vec!["z-last".to_owned(), "a-first".to_owned()];
        let wire = serde_json::to_value(&command).unwrap();
        assert_eq!(
            wire["selectedSkillSlugs"],
            serde_json::json!(["z-last", "a-first"])
        );
        assert_eq!(
            serde_json::from_value::<BeginThreadRunBody>(wire).unwrap(),
            command
        );
        let mut forged = legacy;
        forged["skillInstructions"] = serde_json::json!(["arbitrary system text"]);
        assert!(serde_json::from_value::<BeginThreadRunBody>(forged).is_err());
        for slug in ["a", "Bad", "a/skill", "-bad", "bad-", "bad\0"] {
            assert!(!valid_selected_skill_slugs(&[slug.to_owned()]));
        }
        assert!(!valid_selected_skill_slugs(&["x".repeat(41)]));
        assert!(valid_selected_skill_slugs(&["a".repeat(40)]));
        assert!(valid_selected_skill_slugs(
            &(0..16).map(|i| format!("skill-{i}")).collect::<Vec<_>>()
        ));
    }

    /// §15.3 末条的机械兑现：空页必须是 `{"items":[],"next_cursor":null}`。
    ///
    /// `[]` 与 `null` 在客户端是两种东西 —— 后者会让「没有 channel」和「字段缺失」不可
    /// 区分，那正是上游 #72 空 history 崩掉的同一类形状问题。
    #[test]
    fn empty_page_serializes_as_empty_list_not_null() {
        let page = ChannelPage::default();
        let json = serde_json::to_string(&page).unwrap();
        assert_eq!(json, r#"{"channels":[],"nextCursor":null}"#);

        // 反向也必须成立：这段 JSON 读回来是一个合法的空页，不是错误。
        let back: ChannelPage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, page);
        assert!(back.channels.is_empty());
        assert!(back.next_cursor.is_none());
    }

    /// 线上字段名与上游逐键相等（v3 §15.1 把 `/api/channels` 的 output schema 纳入 parity）。
    ///
    /// 期望值不是我抄来的，是上游 `channels/routes.ts` 里 `channelDto` 与
    /// `channelSummaryDto` 两个函数返回对象的字面键，合起来九个。改名会当场判红。
    #[test]
    fn channel_summary_json_keys_match_upstream_wire() {
        let json = serde_json::to_string(&sample_summary()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut got: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        got.sort_unstable();

        // 上游 channelDto: id / name / agentIds / threadId / active
        // 上游 channelSummaryDto 追加: lastMessage / lastMessageAt / lastMessageAgentId / createdAt
        let mut want = [
            "id",
            "name",
            "agentIds",
            "threadId",
            "active",
            "lastMessage",
            "lastMessageAt",
            "lastMessageAgentId",
            "createdAt",
        ];
        want.sort_unstable();
        assert_eq!(got, want, "线上字段集与上游不一致：{json}");
    }

    /// 同上，页信封那一层。上游 `list` 返回 `{ channels, nextCursor }`。
    #[test]
    fn channel_page_json_keys_match_upstream_wire() {
        let json = serde_json::to_string(&ChannelPage::default()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut got: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        got.sort_unstable();
        let mut want = ["channels", "nextCursor"];
        want.sort_unstable();
        assert_eq!(got, want, "页信封字段集与上游不一致：{json}");

        // 负向对照：确认这条断言不是在「随便什么键集都过」的世界里成立。
        assert_ne!(
            got,
            ["items", "next_cursor"],
            "旧的 snake_case 形状不应再通过"
        );
    }

    #[test]
    fn channel_detail_response_is_the_exact_single_channel_envelope() {
        let response = ChannelDetailResponse {
            channel: ChannelDetail {
                id: ChannelId::new("channel-1"),
                name: "Finance".to_owned(),
                agent_ids: vec![BotId::new("bot-1")],
                thread_id: None,
                active: true,
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"channel":{"id":"channel-1","name":"Finance","agentIds":["bot-1"],"threadId":null,"active":true}}"#
        );
        assert_eq!(
            serde_json::from_str::<ChannelDetailResponse>(&json).unwrap(),
            response
        );
    }

    #[test]
    fn channel_create_routing_and_native_begin_http_bodies_are_closed() {
        let create = CreateChannelRequest {
            agent_ids: vec![BotId::new("bot-2"), BotId::new("bot-1")],
        };
        assert_eq!(
            serde_json::to_string(&create).unwrap(),
            r#"{"agentIds":["bot-2","bot-1"]}"#
        );
        assert!(
            serde_json::from_str::<CreateChannelRequest>(
                r#"{"agentIds":["bot-1"],"name":"forged"}"#
            )
            .is_err()
        );

        let route = RouteChannelRequest {
            text: "hello".to_owned(),
            agent_id: Some(BotId::new("bot-1")),
        };
        assert_eq!(
            serde_json::to_string(&route).unwrap(),
            r#"{"text":"hello","agentId":"bot-1"}"#
        );
        let decision = ChannelRoutingDecision {
            agent_id: BotId::new("bot-1"),
            name: "Bot One".to_owned(),
            reason: "named by the person asking".to_owned(),
            fallback: false,
            via_mention: true,
        };
        assert_eq!(
            serde_json::to_string(&decision).unwrap(),
            r#"{"agentId":"bot-1","name":"Bot One","reason":"named by the person asking","fallback":false,"viaMention":true}"#
        );

        let begin = BeginThreadRunBody {
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            artifact_refs: Vec::new(),
            run_id: RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::Channel {
                channel_id: ChannelId::new("channel-1"),
            },
            message: "hello".to_owned(),
        };
        let json = serde_json::to_string(&begin).unwrap();
        assert_eq!(
            json,
            r#"{"runId":"run-1","botId":"bot-1","anchor":{"kind":"channel","channel_id":"channel-1"},"message":"hello"}"#
        );
        assert_eq!(
            serde_json::from_str::<BeginThreadRunBody>(&json).unwrap(),
            begin
        );

        let create_command = AppCommand::CreateChannel {
            agent_ids: vec![BotId::new("bot-1")],
        };
        let wire = serde_json::to_string(&create_command).unwrap();
        assert_eq!(
            serde_json::from_str::<AppCommand>(&wire).unwrap(),
            create_command
        );
        let route_command = AppCommand::RouteChannelMessage {
            text: "hello".to_owned(),
            agent_id: None,
        };
        let wire = serde_json::to_string(&route_command).unwrap();
        assert_eq!(
            serde_json::from_str::<AppCommand>(&wire).unwrap(),
            route_command
        );
    }

    #[test]
    fn native_conversation_snapshot_is_closed_and_cursor_explicit() {
        let snapshot = ThreadConversationSnapshot {
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
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            active_run_text: "partial".to_owned(),
            last_event_sequence: Some(7),
        };
        assert_eq!(
            serde_json::to_string(&snapshot).unwrap(),
            r#"{"messages":[{"id":"message-1","role":"user","content":"hello"}],"activeRunId":"run-1","activeRunState":"running","activeRunCancellable":true,"activeRunText":"partial","lastEventSequence":7}"#
        );
        assert!(
            serde_json::from_str::<ThreadConversationSnapshot>(
                r#"{"messages":[],"activeRunId":null,"activeRunState":null,"activeRunCancellable":false,"activeRunText":"","lastEventSequence":null,"actor":"forged"}"#
            )
            .is_err()
        );

        let cancellation = ThreadRunCancellation {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: RunId::new("run-1"),
            state: ThreadRunCancellationState::Requested,
        };
        let wire = serde_json::to_string(&cancellation).unwrap();
        assert_eq!(
            wire,
            r#"{"threadId":"550e8400-e29b-81d4-a716-446655440000","runId":"run-1","state":"requested"}"#
        );
        assert_eq!(
            serde_json::from_str::<ThreadRunCancellation>(&wire).unwrap(),
            cancellation
        );
    }

    /// 正向对照：同一个类型在**非空**时确实序列化出条目 —— 证明上一条不是靠
    /// 「这个类型序列化出来永远是空的」蒙混过关。
    #[test]
    fn non_empty_page_actually_carries_items() {
        let page = ChannelPage {
            channels: vec![sample_summary()],
            next_cursor: Some("opaque-cursor".to_owned()),
        };
        let json = serde_json::to_string(&page).unwrap();
        assert!(json.contains(r#""id":"legacy-channel-42""#), "{json}");
        assert!(json.contains(r#""nextCursor":"opaque-cursor""#), "{json}");
        let back: ChannelPage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn channel_summary_timestamps_are_rfc3339() {
        let json = serde_json::to_string(&sample_summary()).unwrap();
        assert!(
            json.contains(r#""createdAt":"2026-08-01T00:00:00Z""#),
            "{json}"
        );
        assert!(
            json.contains(r#""lastMessageAt":"2026-08-22T04:05:06Z""#),
            "{json}"
        );
    }

    #[test]
    fn channel_summary_without_messages_round_trips() {
        let summary = ChannelSummary {
            id: ChannelId::new("c-2"),
            name: "Empty".to_owned(),
            agent_ids: Vec::new(),
            // 可见但还没有 thread：join 删掉之后的合法状态（见 thread_id 字段文档）。
            thread_id: None,
            last_message: None,
            last_message_at: None,
            last_message_agent_id: None,
            created_at: datetime!(2026-08-01 00:00:00 UTC),
            active: false,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains(r#""lastMessageAt":null"#), "{json}");
        let back: ChannelSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    /// `allowed_groups` 不在 DTO 里（§6.5 条 5）。
    ///
    /// 负向断言配正向对照：同一手法在**确实存在**的字段上命中，证明这不是一条
    /// 「反正 JSON 里什么都没有」的空断言。
    #[test]
    fn allowed_groups_never_crosses_the_boundary() {
        let json = serde_json::to_string(&sample_summary()).unwrap();
        assert!(
            !json.contains("allowed_groups"),
            "allowed_groups 不得进 DTO：运行时可见性只认 materialized membership"
        );
        assert!(!json.contains("packageId"), "{json}");
        assert!(!json.contains("package_id"), "{json}");
        assert!(!json.contains("override"), "{json}");
        // 正向对照：确实被投影的字段都在。
        assert!(json.contains("agentIds"), "{json}");
        assert!(json.contains("active"), "{json}");
    }

    #[test]
    fn command_is_internally_tagged_and_closed() {
        let listed = AppCommand::ListVisibleChannels {
            limit: Some(50),
            cursor: None,
        };
        let json = serde_json::to_string(&listed).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"list_visible_channels","limit":50,"cursor":null}"#
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&json).unwrap(), listed);

        assert_eq!(
            serde_json::to_string(&AppCommand::Health).unwrap(),
            r#"{"kind":"health"}"#
        );

        let tool = AppCommand::InvokeTool(ToolInvocation {
            call_id: crate::ids::ToolCallId::new("call-1"),
            run_id: crate::ids::RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            call_seq: 2,
            tool_name: "computer.write".to_owned(),
            arguments: serde_json::json!({"x":1}),
        });
        let wire = serde_json::to_string(&tool).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"invoke_tool","callId":"call-1","runId":"run-1","botId":"bot-1","callSeq":2,"toolName":"computer.write","arguments":{"x":1}}"#,
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), tool);

        let mint = AppCommand::MintThreadId;
        let wire = serde_json::to_string(&mint).unwrap();
        assert_eq!(wire, r#"{"kind":"mint_thread_id"}"#);
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), mint);

        let status = AppCommand::GetThreadStatus {
            thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
        };
        let wire = serde_json::to_string(&status).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"get_thread_status","thread_id":"550e8400-e29b-41d4-a716-446655440000"}"#
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), status);

        let begin = AppCommand::BeginThreadRun(BeginThreadRun {
            model_selection: None,
            selected_skill_slugs: Vec::new(),
            artifact_refs: Vec::new(),
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello".to_owned(),
        });
        let wire = serde_json::to_string(&begin).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"begin_thread_run","threadId":"550e8400-e29b-81d4-a716-446655440000","runId":"run-1","botId":"bot-1","anchor":{"kind":"direct_bot"},"message":"hello"}"#
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), begin);

        let cancel = AppCommand::CancelThreadRun(CancelThreadRun {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: RunId::new("run-1"),
        });
        let wire = serde_json::to_string(&cancel).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"cancel_thread_run","threadId":"550e8400-e29b-81d4-a716-446655440000","runId":"run-1"}"#
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), cancel);

        let history = AppCommand::GetThreadHistory {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
        };
        let wire = serde_json::to_string(&history).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"get_thread_history","thread_id":"550e8400-e29b-81d4-a716-446655440000"}"#
        );
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), history);

        let remember = AppCommand::RememberMemory(RememberMemory {
            memory_kind: crate::memory::MemoryKind::Preference,
            scope: crate::memory::MemoryScope::User,
            content: "tea".to_owned(),
            tags: vec!["drink".to_owned()],
            sensitivity: crate::memory::MemorySensitivity::Normal,
            source: None,
            expires_at: None,
        });
        let wire = serde_json::to_string(&remember).unwrap();
        assert!(wire.contains(r#""kind":"remember_memory""#), "{wire}");
        assert!(!wire.contains("origin"), "{wire}");
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), remember);

        let audit = AppCommand::ListAuditEvents {
            cursor: Some("opaque".to_owned()),
            event_type: Some("one,two".to_owned()),
            actor_user_id: Some(crate::ids::ActorId::new("admin")),
            target_type: Some("connector".to_owned()),
            target_id: None,
            from: None,
            to: None,
            limit: Some(10),
        };
        let wire = serde_json::to_string(&audit).unwrap();
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), audit);

        let policy = AppCommand::SetActionPolicy {
            policy: ActionPolicyDocument {
                mode: crate::policy::ActionPolicyMode::DryRun,
                deny: vec!["false".to_owned()],
                allow: vec!["true".to_owned()],
            },
        };
        let wire = serde_json::to_string(&policy).unwrap();
        assert_eq!(serde_json::from_str::<AppCommand>(&wire).unwrap(), policy);
        assert_eq!(
            serde_json::from_str::<AppCommand>(r#"{"kind":"get_action_policy"}"#).unwrap(),
            AppCommand::GetActionPolicy,
        );
    }

    /// 自由 method string 走不通：未知 `kind` 与未知字段都在反序列化阶段就失败，
    /// 到不了 application（§5.2 + §15.3「malformed payload 400，不产生 acting decision」）。
    #[test]
    fn unknown_command_kind_and_unknown_fields_are_rejected() {
        assert!(
            serde_json::from_str::<AppCommand>(r#"{"kind":"drop_all_tables"}"#).is_err(),
            "未知 kind 必须拒绝，而不是落进 dispatcher 的通配分支"
        );
        assert!(
            serde_json::from_str::<AppCommand>(
                r#"{"kind":"list_visible_channels","limit":1,"cursor":null,"principal":"admin"}"#
            )
            .is_err(),
            "renderer 自报 principal 必须被 deny_unknown_fields 当场拒绝（§5.2）"
        );
        // 正向对照：合法载荷确实能解析 —— 否则上面两条在「什么都解析不了」的世界里同样通过。
        assert!(
            serde_json::from_str::<AppCommand>(
                r#"{"kind":"list_visible_channels","limit":1,"cursor":null}"#
            )
            .is_ok()
        );
        assert_eq!(
            serde_json::from_str::<AppCommand>(
                r#"{"kind":"get_visible_channel","channel_id":"channel-1"}"#
            )
            .unwrap(),
            AppCommand::GetVisibleChannel {
                channel_id: ChannelId::new("channel-1")
            }
        );
    }

    #[test]
    fn reply_subscription_and_event_round_trip() {
        let reply = AppReply::Health(HealthReport { ok: true });
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(json, r#"{"kind":"health","ok":true}"#);
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), reply);

        let channels = AppReply::Channels(ChannelPage::default());
        let json = serde_json::to_string(&channels).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"channels","channels":[],"nextCursor":null}"#
        );
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), channels);

        let channel = AppReply::Channel(ChannelDetail {
            id: ChannelId::new("channel-1"),
            name: "Finance".to_owned(),
            agent_ids: vec![BotId::new("bot-1")],
            thread_id: None,
            active: true,
        });
        let json = serde_json::to_string(&channel).unwrap();
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), channel);

        let audit = AppReply::AuditEvents(AuditPage::default());
        let json = serde_json::to_string(&audit).unwrap();
        assert_eq!(json, r#"{"kind":"audit_events","events":[]}"#);
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), audit);

        let policy = AppReply::ActionPolicy { policy: None };
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, r#"{"kind":"action_policy","policy":null}"#);
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), policy);

        let tool = AppReply::Tool(ToolResult {
            call_id: crate::ids::ToolCallId::new("call-1"),
            content: "ok".to_owned(),
            error_code: None,
            commit_state: crate::tool::ToolCommitState::Committed,
            visible_bytes: 2,
            truncated: false,
        });
        let json = serde_json::to_string(&tool).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"tool","callId":"call-1","content":"ok","errorCode":null,"commitState":"committed","visibleBytes":2,"truncated":false}"#,
        );
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), tool);

        let minted = AppReply::ThreadMinted(ThreadMinted {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
        });
        let json = serde_json::to_string(&minted).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"thread_minted","threadId":"550e8400-e29b-81d4-a716-446655440000"}"#
        );
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), minted);

        let status = AppReply::ThreadStatus(ThreadStatus { known: false });
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#"{"kind":"thread_status","known":false}"#);
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), status);

        let started = AppReply::ThreadRunStarted(ThreadRunStarted {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: RunId::new("run-1"),
            message_sequence: 3,
            event_sequence: 7,
            replayed: false,
        });
        let json = serde_json::to_string(&started).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"thread_run_started","threadId":"550e8400-e29b-81d4-a716-446655440000","runId":"run-1","messageSequence":3,"eventSequence":7,"replayed":false}"#
        );
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), started);

        let history = AppReply::ThreadHistory(ThreadHistory {
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
        });
        let json = serde_json::to_string(&history).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"thread_history","messages":[{"id":"m-1","role":"user","content":"hello"}]}"#
        );
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), history);

        assert_eq!(
            serde_json::to_string(&ThreadHistory::default()).unwrap(),
            r#"{"messages":[]}"#
        );

        let memory = AppReply::Memory(MemoryRecord {
            memory_id: "memory-1".to_owned(),
            owner_user_id: "u1".to_owned(),
            scope: crate::memory::MemoryScope::User,
            memory_kind: crate::memory::MemoryKind::Preference,
            content: Some("tea".to_owned()),
            tags: Vec::new(),
            sensitivity: crate::memory::MemorySensitivity::Normal,
            source: None,
            source_run_id: None,
            source_authorization_snapshot: None,
            origin: crate::memory::MemoryOrigin::UserAction,
            created_by: "u1".to_owned(),
            supersedes_id: None,
            status: crate::memory::MemoryStatus::Active,
            expires_at: None,
            created_at: datetime!(2026-08-24 00:00:00 UTC),
            updated_at: datetime!(2026-08-24 00:00:00 UTC),
        });
        let json = serde_json::to_string(&memory).unwrap();
        assert!(json.contains(r#""kind":"memory""#), "{json}");
        assert_eq!(serde_json::from_str::<AppReply>(&json).unwrap(), memory);

        let request = SubscriptionRequest::Health;
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"kind":"health"}"#
        );

        let request = SubscriptionRequest::ThreadEvents {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            after_event_sequence: Some(7),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"thread_events","thread_id":"550e8400-e29b-81d4-a716-446655440000","after_event_sequence":7}"#
        );
        assert_eq!(
            serde_json::from_str::<SubscriptionRequest>(&json).unwrap(),
            request
        );

        let request = SubscriptionRequest::ChannelActivity;
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"kind":"channel_activity"}"#
        );

        let request = SubscriptionRequest::ToolApprovalActivity;
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"kind":"tool_approval_activity"}"#
        );

        let event = AppEvent::ToolApprovalActivity(crate::tool::ToolApprovalActivityEvent {
            pending_count: 2,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"tool_approval_activity","pendingCount":2}"#
        );
        assert_eq!(serde_json::from_str::<AppEvent>(&json).unwrap(), event);

        let event = AppEvent::Heartbeat { seq: 7 };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"kind":"heartbeat","seq":7}"#);
        assert_eq!(serde_json::from_str::<AppEvent>(&json).unwrap(), event);

        let event = AppEvent::ChannelActivity(ChannelActivityEvent {
            channel_id: ChannelId::new("channel-1"),
            last_message: Some("hello".to_owned()),
            last_message_at: Some(datetime!(2026-08-26 12:00:00 UTC)),
            last_message_agent_id: Some(BotId::new("bot-1")),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"channel_activity","channelId":"channel-1","lastMessage":"hello","lastMessageAt":"2026-08-26T12:00:00Z","lastMessageAgentId":"bot-1"}"#
        );
        assert_eq!(serde_json::from_str::<AppEvent>(&json).unwrap(), event);

        let event = AppEvent::ThreadRunEvent(ThreadRunEvent {
            thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
            run_id: RunId::new("run-1"),
            event_sequence: 8,
            event_type: ThreadRunEventKind::SemanticChunk,
            payload: serde_json::json!({"text":"hello"}),
            terminal: false,
            created_at: datetime!(2026-08-24 12:00:00 UTC),
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""kind":"thread_run_event""#), "{json}");
        assert!(json.contains(r#""eventSequence":8"#), "{json}");
        assert_eq!(serde_json::from_str::<AppEvent>(&json).unwrap(), event);

        for (kind, terminal) in [
            (ThreadRunEventKind::Started, false),
            (ThreadRunEventKind::SemanticChunk, false),
            (ThreadRunEventKind::Checkpoint, false),
            (ThreadRunEventKind::Completed, true),
            (ThreadRunEventKind::Failed, true),
            (ThreadRunEventKind::Cancelled, true),
            (ThreadRunEventKind::ReconciliationRequired, true),
        ] {
            assert_eq!(kind.is_terminal(), terminal);
        }
        assert!(ThreadRunEventKind::from_database("unknown").is_none());
    }

    /// parity 常量固定为上游 `channels/routes.ts::MAX_CHANNEL_PAGE` 的取值。
    #[test]
    fn max_channel_page_is_the_upstream_parity_value() {
        assert_eq!(MAX_CHANNEL_PAGE, 200);
    }
}
