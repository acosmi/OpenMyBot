//! [`OpenBotApplication`] —— [`ApplicationService`] 的具体实现，把端口与 use case 接起来。
//!
//! # tracing 从第一个垂直切片就生效（v3 §24 G1 判据第四条）
//!
//! 两个入口各挂一个 `#[tracing::instrument]` span，字段取 §16.4 的关联字段。三条纪律
//! 在这里是**代码形态**不是注释：
//!
//! 1. `skip_all` —— 参数一个都不自动记录。没有它，`#[instrument]` 会把 `auth` 与
//!    `command` 用 `Debug` 打出去，于是 `AuthContext` 的角色集合与 auth generation、
//!    以及不透明游标，全都进了日志。contracts 刻意不给 `AuthContext` 实现 `Serialize`，
//!    而 `Debug` 是那道防线上的缺口 —— `skip_all` 把它堵上。
//! 2. 身份只取**需要的 ID 字段**（deployment / tenant / actor），逐个用 `Display` 写入。
//! 3. 字段名全集登记在 [`APPLICATION_SPAN_FIELDS`]，每一项都必须有基数裁决
//!    （见 [`crate::service::TRACE_ONLY_SPAN_FIELDS`]）。

use core::time::Duration;

use async_trait::async_trait;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply, SubscriptionRequest};
use openbot_contracts::error::AppError;
use tracing::Span;

use crate::agent_admin::{
    AgentCallbackTokenAdministration, NoAgentCallbackTokenAdministration,
    issue_agent_callback_token, revoke_agent_callback_token,
};
use crate::approval_admin::{
    NoToolApprovalAdministration, ToolApprovalAdministration, decide_tool_approval,
    list_pending_tool_approvals, subscribe_tool_approval_activity,
};
use crate::artifacts::{
    ArtifactAdministration, NoArtifactAdministration, get_artifact_metadata,
    save_run_message_text_artifact,
};
use crate::components::{
    ComponentAdministration, NoComponentAdministration, await_component_human_decision,
    call_component_function, decide_component, list_component_data_functions, list_components,
    list_components_for_agent, list_pending_component_human_decisions,
    resolve_component_human_decision, sync_component_catalogue, update_component_governance,
};
use crate::mcp_connections::{
    McpConnectionAdministration, NoMcpConnectionAdministration, add_curated_mcp_server,
    add_custom_mcp_server, begin_mcp_oauth, disconnect_mcp_connection, grant_plugin,
    list_mcp_admin_page, list_mcp_connections, list_plugins_for_agent, refresh_mcp_server,
    register_mcp_oauth_client, remove_mcp_server, remove_plugin_skill, revoke_plugin,
    save_plugin_skill,
};
use crate::ports::{
    AgentAdministration, AgentDirectory, AuditReader, ChannelAdministration, ChannelReader,
    ChannelRoutingBackend, MemoryAdministration, NoAgentAdministration, NoAgentDirectory,
    NoAuditReader, NoChannelAdministration, NoChannelRoutingBackend, NoMemoryAdministration,
    NoPeopleAdministration, NoPolicyAdministration, NoThreadDirectory, PeopleAdministration,
    PolicyAdministration, ThreadDirectory,
};
use crate::provider::{NoRemoteInterruptCoordinator, RemoteInterruptCoordinator};
use crate::remote_interrupt::{list_pending_remote_interrupts, resolve_remote_interrupt};
use crate::run_cost_budget::{
    NoRunCostBudgetAdministration, RunCostBudgetAdministration, get_run_cost_budget,
    replace_run_cost_budget,
};
use crate::sandboxed_components::{
    NoSandboxedComponentAdministration, SandboxedComponentAdministration,
    authorize_sandboxed_component, delete_sandboxed_component, list_published_sandboxed_components,
    list_sandboxed_components, publish_sandboxed_component, save_sandboxed_component,
};
use crate::screen_sessions::{
    NoScreenSessionAdministration, ScreenSessionAdministration, issue_screen_session,
};
use crate::service::{AppEventStream, ApplicationService, command_kind, subscription_kind};
use crate::tool::{NoToolControlPlane, NoToolJournal, ToolControlPlane, ToolJournal, invoke_tool};
use crate::ui_preferences::{
    NoUiPreferenceAdministration, UiPreferenceAdministration, get_ui_preferences,
    update_ui_preferences,
};
use crate::use_cases::thread::begin_thread_run_v2;
use crate::use_cases::{
    DEFAULT_HEARTBEAT_PERIOD, admin_status, begin_thread_run, cancel_thread_run,
    change_person_access, change_person_role, correct_memory, create_agent, create_channel,
    current_user, delete_agent, duplicate_agent, get_action_policy, get_memory_control,
    get_thread_conversation, get_thread_history, get_thread_status, get_visible_agent,
    get_visible_channel, health, health_stream, list_audit_events, list_memories, list_people,
    list_visible_agents, list_visible_channels, mint_thread_id, mutate_memory, recall_memories,
    remember_memory, route_channel_message, set_action_policy, set_agent_hidden,
    subscribe_channel_activity, subscribe_thread_events, test_agent_connection, update_agent,
    update_memory_control,
};

/// [`ApplicationService`] 的生产实现。
///
/// 它对具体数据源一无所知：`R` 是任何满足 [`ChannelReader`] 的类型。`openbot-server` 与
/// `openbot-desktop` 各自注入 `openbot-infra` 的实现，测试注入内存 fake —— 三条路径穿的
/// 是同一份业务代码，这正是 §24 G1「ApplicationService 经 Axum/Tauri 结果一致」的前提。
pub struct OpenBotApplication<
    R,
    P = NoPeopleAdministration,
    A = NoAuditReader,
    K = NoPolicyAdministration,
    C = NoToolControlPlane,
    J = NoToolJournal,
    T = NoThreadDirectory,
    M = NoMemoryAdministration,
    B = NoAgentCallbackTokenAdministration,
> {
    channels: R,
    people: P,
    audit: A,
    policies: K,
    tool_control: C,
    tool_journal: J,
    threads: T,
    memory: M,
    callback_tokens: B,
    agents: std::sync::Arc<dyn AgentDirectory>,
    agent_administration: std::sync::Arc<dyn AgentAdministration>,
    components: std::sync::Arc<dyn ComponentAdministration>,
    sandboxed_components: std::sync::Arc<dyn SandboxedComponentAdministration>,
    channel_administration: std::sync::Arc<dyn ChannelAdministration>,
    channel_routing: std::sync::Arc<dyn ChannelRoutingBackend>,
    mcp_connections: std::sync::Arc<dyn McpConnectionAdministration>,
    credentials: std::sync::Arc<dyn crate::credential_admin::CredentialAdministration>,
    model_connections: std::sync::Arc<dyn crate::model_connections::ModelConnectionAdministration>,
    custom_model_catalog: std::sync::Arc<dyn crate::CustomModelCatalogInventory>,
    custom_model_catalog_deliveries:
        std::sync::Arc<crate::custom_model_catalog_delivery::CustomModelCatalogRegistry>,
    tool_approvals: std::sync::Arc<dyn ToolApprovalAdministration>,
    ui_preferences: std::sync::Arc<dyn UiPreferenceAdministration>,
    run_cost_budgets: std::sync::Arc<dyn RunCostBudgetAdministration>,
    remote_interrupts: std::sync::Arc<dyn RemoteInterruptCoordinator>,
    screen_sessions: std::sync::Arc<dyn ScreenSessionAdministration>,
    artifacts: std::sync::Arc<dyn ArtifactAdministration>,
    public_artifact_reads:
        std::sync::Arc<crate::artifact_read_protocol::PublicArtifactReadRegistry>,
    runtime_capabilities:
        Option<std::sync::Arc<dyn crate::runtime_capabilities::RuntimeCapabilitiesCollector>>,
    heartbeat_period: Duration,
}

impl<R>
    OpenBotApplication<
        R,
        NoPeopleAdministration,
        NoAuditReader,
        NoPolicyAdministration,
        NoToolControlPlane,
        NoToolJournal,
        NoThreadDirectory,
        NoMemoryAdministration,
        NoAgentCallbackTokenAdministration,
    >
{
    /// 注入端口实现。
    pub fn new(channels: R) -> Self {
        Self {
            channels,
            people: NoPeopleAdministration,
            audit: NoAuditReader,
            policies: NoPolicyAdministration,
            tool_control: NoToolControlPlane,
            tool_journal: NoToolJournal,
            threads: NoThreadDirectory,
            memory: NoMemoryAdministration,
            callback_tokens: NoAgentCallbackTokenAdministration,
            agents: std::sync::Arc::new(NoAgentDirectory),
            agent_administration: std::sync::Arc::new(NoAgentAdministration),
            components: std::sync::Arc::new(NoComponentAdministration),
            sandboxed_components: std::sync::Arc::new(NoSandboxedComponentAdministration),
            channel_administration: std::sync::Arc::new(NoChannelAdministration),
            channel_routing: std::sync::Arc::new(NoChannelRoutingBackend),
            mcp_connections: std::sync::Arc::new(NoMcpConnectionAdministration),
            credentials: std::sync::Arc::new(crate::credential_admin::NoCredentialAdministration),
            model_connections: std::sync::Arc::new(
                crate::model_connections::NoModelConnectionAdministration,
            ),
            custom_model_catalog: std::sync::Arc::new(crate::NoCustomModelCatalogInventory),
            custom_model_catalog_deliveries: std::sync::Arc::new(
                crate::custom_model_catalog_delivery::CustomModelCatalogRegistry::new(),
            ),
            tool_approvals: std::sync::Arc::new(NoToolApprovalAdministration),
            ui_preferences: std::sync::Arc::new(NoUiPreferenceAdministration),
            run_cost_budgets: std::sync::Arc::new(NoRunCostBudgetAdministration),
            remote_interrupts: std::sync::Arc::new(NoRemoteInterruptCoordinator),
            screen_sessions: std::sync::Arc::new(NoScreenSessionAdministration),
            artifacts: std::sync::Arc::new(NoArtifactAdministration),
            public_artifact_reads: std::sync::Arc::new(
                crate::artifact_read_protocol::PublicArtifactReadRegistry::new(),
            ),
            runtime_capabilities: None,
            heartbeat_period: DEFAULT_HEARTBEAT_PERIOD,
        }
    }
}

impl<R, P, A, K, C, J, T, M, B> OpenBotApplication<R, P, A, K, C, J, T, M, B> {
    /// 注入 people/auth 原子端口。
    #[must_use]
    pub fn with_people<Q>(self, people: Q) -> OpenBotApplication<R, Q, A, K, C, J, T, M, B> {
        OpenBotApplication {
            channels: self.channels,
            people,
            audit: self.audit,
            policies: self.policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads: self.threads,
            memory: self.memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// 注入管理员 audit keyset reader。
    #[must_use]
    pub fn with_audit<Q>(self, audit: Q) -> OpenBotApplication<R, P, Q, K, C, J, T, M, B> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit,
            policies: self.policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads: self.threads,
            memory: self.memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// 注入 deployment-wide action policy 管理端口。
    #[must_use]
    pub fn with_policy<Q>(self, policies: Q) -> OpenBotApplication<R, P, A, Q, C, J, T, M, B> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit: self.audit,
            policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads: self.threads,
            memory: self.memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// 注入 tool control plane 与 durable journal；二者分开，application 才能掌握固定顺序。
    #[must_use]
    pub fn with_tools<Q, L>(
        self,
        control: Q,
        journal: L,
    ) -> OpenBotApplication<R, P, A, K, Q, L, T, M, B> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit: self.audit,
            policies: self.policies,
            tool_control: control,
            tool_journal: journal,
            threads: self.threads,
            memory: self.memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// 注入 native thread ID / scope-aware directory；未注入时绝不回退 Intelligence。
    #[must_use]
    pub fn with_threads<Q>(self, threads: Q) -> OpenBotApplication<R, P, A, K, C, J, Q, M, B> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit: self.audit,
            policies: self.policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads,
            memory: self.memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// 注入 explicit memory administration；未注入时 fail-closed。
    #[must_use]
    pub fn with_memory<Q>(self, memory: Q) -> OpenBotApplication<R, P, A, K, C, J, T, Q, B> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit: self.audit,
            policies: self.policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads: self.threads,
            memory,
            callback_tokens: self.callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// Inject callback-token administration; absence remains fail-closed.
    #[must_use]
    pub fn with_agent_callback_tokens<Q>(
        self,
        callback_tokens: Q,
    ) -> OpenBotApplication<R, P, A, K, C, J, T, M, Q> {
        OpenBotApplication {
            channels: self.channels,
            people: self.people,
            audit: self.audit,
            policies: self.policies,
            tool_control: self.tool_control,
            tool_journal: self.tool_journal,
            threads: self.threads,
            memory: self.memory,
            callback_tokens,
            agents: self.agents,
            agent_administration: self.agent_administration,
            components: self.components,
            sandboxed_components: self.sandboxed_components,
            channel_administration: self.channel_administration,
            channel_routing: self.channel_routing,
            mcp_connections: self.mcp_connections,
            credentials: self.credentials,
            model_connections: self.model_connections,
            custom_model_catalog: self.custom_model_catalog,
            custom_model_catalog_deliveries: self.custom_model_catalog_deliveries,
            tool_approvals: self.tool_approvals,
            ui_preferences: self.ui_preferences,
            run_cost_budgets: self.run_cost_budgets,
            remote_interrupts: self.remote_interrupts,
            screen_sessions: self.screen_sessions,
            artifacts: self.artifacts,
            public_artifact_reads: self.public_artifact_reads,
            runtime_capabilities: self.runtime_capabilities,
            heartbeat_period: self.heartbeat_period,
        }
    }

    /// Attach current-schema Agent roster/detail reads.
    #[must_use]
    pub fn with_agent_directory(mut self, agents: std::sync::Arc<dyn AgentDirectory>) -> Self {
        self.agents = agents;
        self
    }

    /// Attach Agent lifecycle, credential, audit, and connection-probe administration.
    #[must_use]
    pub fn with_agent_administration(
        mut self,
        administration: std::sync::Arc<dyn AgentAdministration>,
    ) -> Self {
        self.agent_administration = administration;
        self
    }

    /// Attach authenticated component governance reads and additive build catalogue sync.
    #[must_use]
    pub fn with_component_administration(
        mut self,
        components: std::sync::Arc<dyn ComponentAdministration>,
    ) -> Self {
        self.components = components;
        self
    }

    /// Attach sandboxed source lifecycle governance; the port exposes no data-function channel.
    #[must_use]
    pub fn with_sandboxed_component_administration(
        mut self,
        components: std::sync::Arc<dyn SandboxedComponentAdministration>,
    ) -> Self {
        self.sandboxed_components = components;
        self
    }

    /// Attach the atomic user-channel creation transaction.
    #[must_use]
    pub fn with_channel_administration(
        mut self,
        administration: std::sync::Arc<dyn ChannelAdministration>,
    ) -> Self {
        self.channel_administration = administration;
        self
    }

    /// Attach deployment-model completion, reach hints, and hash-chained routing audit.
    #[must_use]
    pub fn with_channel_routing(
        mut self,
        routing: std::sync::Arc<dyn ChannelRoutingBackend>,
    ) -> Self {
        self.channel_routing = routing;
        self
    }

    /// Attach the authenticated MCP connection service used by Server and Desktop.
    #[must_use]
    pub fn with_mcp_connections(
        mut self,
        connections: std::sync::Arc<dyn McpConnectionAdministration>,
    ) -> Self {
        self.mcp_connections = connections;
        self
    }

    /// Attach the durable human proof-of-intent administration surface.
    #[must_use]
    pub fn with_tool_approvals(
        mut self,
        approvals: std::sync::Arc<dyn ToolApprovalAdministration>,
    ) -> Self {
        self.tool_approvals = approvals;
        self
    }

    /// Attach authenticated UI preference storage shared by Server and Desktop.
    #[must_use]
    pub fn with_ui_preferences(
        mut self,
        preferences: std::sync::Arc<dyn UiPreferenceAdministration>,
    ) -> Self {
        self.ui_preferences = preferences;
        self
    }

    /// Attach the same credential administration and audit boundary to both transports.
    #[must_use]
    pub fn with_credentials(
        mut self,
        credentials: std::sync::Arc<dyn crate::credential_admin::CredentialAdministration>,
    ) -> Self {
        self.credentials = credentials;
        self
    }

    /// Attach personal custom-model connection authority.
    #[must_use]
    pub fn with_model_connections(
        mut self,
        connections: std::sync::Arc<dyn crate::model_connections::ModelConnectionAdministration>,
    ) -> Self {
        self.model_connections = connections;
        self
    }

    /// 注入原宿主已安装的 custom 库存；同 Application 保留同一个配额/交付 registry。
    #[must_use]
    pub fn with_custom_model_catalog_inventory(
        mut self,
        inventory: std::sync::Arc<dyn crate::CustomModelCatalogInventory>,
    ) -> Self {
        self.custom_model_catalog = inventory;
        self
    }

    /// Attach authenticated run-cost budget storage shared by Server and Desktop.
    #[must_use]
    pub fn with_run_cost_budgets(
        mut self,
        budgets: std::sync::Arc<dyn RunCostBudgetAdministration>,
    ) -> Self {
        self.run_cost_budgets = budgets;
        self
    }

    /// Attach durable remote AG-UI interrupt administration shared by runtime and transports.
    #[must_use]
    pub fn with_remote_interrupts(
        mut self,
        remote_interrupts: std::sync::Arc<dyn RemoteInterruptCoordinator>,
    ) -> Self {
        self.remote_interrupts = remote_interrupts;
        self
    }

    /// Attach the shared Computer-owned ScreenSession ticket authority.
    #[must_use]
    pub fn with_screen_sessions(
        mut self,
        screen_sessions: std::sync::Arc<dyn ScreenSessionAdministration>,
    ) -> Self {
        self.screen_sessions = screen_sessions;
        self
    }

    /// Attach the authoritative dataset-bound artifact repository.
    #[must_use]
    pub fn with_artifacts(mut self, artifacts: std::sync::Arc<dyn ArtifactAdministration>) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Attach the real current host's non-Serde capability collector.
    #[must_use]
    pub fn with_runtime_capabilities(
        mut self,
        collector: std::sync::Arc<dyn crate::runtime_capabilities::RuntimeCapabilitiesCollector>,
    ) -> Self {
        self.runtime_capabilities = Some(collector);
        self
    }

    /// 覆盖心跳间隔。
    ///
    /// 存在的理由只有一个：让测试不必与 30 秒的默认节拍赛跑。生产侧应当用默认值 ——
    /// 改它会改变客户端与中间设备看到的保活频率，属于产品决定。
    #[must_use]
    pub const fn with_heartbeat_period(mut self, period: Duration) -> Self {
        self.heartbeat_period = period;
        self
    }
}

impl<R, P, A, K, C, J, T, M, B> OpenBotApplication<R, P, A, K, C, J, T, M, B>
where
    R: ChannelReader,
    P: PeopleAdministration,
    A: AuditReader,
    K: PolicyAdministration,
    C: ToolControlPlane,
    J: ToolJournal,
    T: ThreadDirectory,
    M: MemoryAdministration,
    B: AgentCallbackTokenAdministration,
{
    /// 命令派发。**穷举 match 无通配** —— 新增 `AppCommand` 变体会在这里编译失败，
    /// 而不是落进一个 `_ => Err(unknown_method)` 分支。那个分支正是 §5.2 逐字禁止的
    /// 「自由 method string」在 Rust 侧的形态。
    async fn dispatch(
        &self,
        auth: &AuthContext,
        command: AppCommand,
    ) -> Result<AppReply, AppError> {
        match command {
            AppCommand::ListCustomModelCatalog(input) => Ok(AppReply::CustomModelCatalog(
                self.custom_model_catalog_deliveries
                    .list_current(self.custom_model_catalog.as_ref(), auth, input)
                    .await?,
            )),
            AppCommand::OpenArtifactRead(input) => Ok(AppReply::ArtifactReadOpened(
                self.public_artifact_reads
                    .open(self.artifacts.as_ref(), auth, input)
                    .await?,
            )),
            AppCommand::ReadArtifactReadBlock(input) => Ok(AppReply::ArtifactReadChunkDescriptor(
                self.public_artifact_reads.next(auth, input).await?,
            )),
            AppCommand::AcknowledgeArtifactReadBlock(input) => {
                Ok(AppReply::ArtifactReadAcknowledged(
                    self.public_artifact_reads.acknowledge(auth, input).await?,
                ))
            }
            AppCommand::CloseArtifactRead(input) => Ok(AppReply::ArtifactReadClosed(
                self.public_artifact_reads.close(auth, input).await?,
            )),
            AppCommand::GetRuntimeCapabilities => Ok(AppReply::RuntimeCapabilities(
                crate::runtime_capabilities::get_runtime_capabilities(
                    self.runtime_capabilities.as_deref(),
                    auth,
                )
                .await?,
            )),
            AppCommand::SaveRunMessageTextArtifact(input) => {
                Ok(AppReply::ArtifactRegistrationReceipt(
                    save_run_message_text_artifact(self.artifacts.as_ref(), auth, input).await?,
                ))
            }
            AppCommand::GetArtifactSaveReceipt(input) => Ok(AppReply::ArtifactRegistrationReceipt(
                crate::get_artifact_save_receipt(self.artifacts.as_ref(), auth, input).await?,
            )),
            AppCommand::GetSourceRunArtifactIds(input) => Ok(AppReply::SourceRunArtifactIds(
                crate::artifacts::get_source_run_artifact_ids(self.artifacts.as_ref(), auth, input)
                    .await?,
            )),
            AppCommand::GetArtifactMetadata(input) => Ok(AppReply::ArtifactMetadata(
                get_artifact_metadata(self.artifacts.as_ref(), auth, input).await?,
            )),
            AppCommand::Health => Ok(AppReply::Health(health())),
            AppCommand::ListVisibleChannels { limit, cursor } => {
                let page =
                    list_visible_channels(&self.channels, auth, limit, cursor.as_deref()).await?;
                Ok(AppReply::Channels(page))
            }
            AppCommand::GetVisibleChannel { channel_id } => Ok(AppReply::Channel(
                get_visible_channel(&self.channels, auth, channel_id).await?,
            )),
            AppCommand::CreateChannel { agent_ids } => Ok(AppReply::Channel(
                create_channel(self.channel_administration.as_ref(), auth, agent_ids).await?,
            )),
            AppCommand::RouteChannelMessage { text, agent_id } => Ok(AppReply::ChannelRouting(
                route_channel_message(
                    self.agents.as_ref(),
                    self.channel_routing.as_ref(),
                    auth,
                    text,
                    agent_id,
                )
                .await?,
            )),
            AppCommand::ListVisibleAgents { hidden } => Ok(AppReply::Agents(
                list_visible_agents(self.agents.as_ref(), auth, hidden).await?,
            )),
            AppCommand::GetVisibleAgent { agent_id } => Ok(AppReply::Agent(
                get_visible_agent(self.agents.as_ref(), auth, agent_id).await?,
            )),
            AppCommand::CreateAgent(request) => Ok(AppReply::Agent(
                create_agent(self.agent_administration.as_ref(), auth, request).await?,
            )),
            AppCommand::UpdateAgent { agent_id, request } => Ok(AppReply::Agent(
                update_agent(self.agent_administration.as_ref(), auth, agent_id, request).await?,
            )),
            AppCommand::DuplicateAgent { agent_id } => Ok(AppReply::Agent(
                duplicate_agent(self.agent_administration.as_ref(), auth, agent_id).await?,
            )),
            AppCommand::SetAgentHidden { agent_id, hidden } => Ok(AppReply::AgentLifecycle(
                set_agent_hidden(self.agent_administration.as_ref(), auth, agent_id, hidden)
                    .await?,
            )),
            AppCommand::DeleteAgent { agent_id } => Ok(AppReply::AgentLifecycle(
                delete_agent(self.agent_administration.as_ref(), auth, agent_id).await?,
            )),
            AppCommand::TestAgentConnection(request) => Ok(AppReply::AgentConnectionVerdict(
                test_agent_connection(self.agent_administration.as_ref(), auth, request).await?,
            )),
            AppCommand::ListComponents => Ok(AppReply::Components(
                list_components(self.components.as_ref(), auth).await?,
            )),
            AppCommand::SyncComponentCatalogue(request) => Ok(AppReply::ComponentCatalogueAdded(
                sync_component_catalogue(self.components.as_ref(), auth, request).await?,
            )),
            AppCommand::UpdateComponentGovernance(mutation) => {
                Ok(AppReply::ComponentGovernanceUpdated(
                    update_component_governance(self.components.as_ref(), auth, mutation).await?,
                ))
            }
            AppCommand::ListComponentsForAgent { agent_id } => Ok(AppReply::GrantedComponents(
                list_components_for_agent(self.components.as_ref(), auth, agent_id).await?,
            )),
            AppCommand::DecideComponent {
                component_name,
                request,
            } => Ok(AppReply::ComponentDecision(
                decide_component(self.components.as_ref(), auth, component_name, request).await?,
            )),
            AppCommand::ListComponentDataFunctions => Ok(AppReply::ComponentDataFunctions(
                list_component_data_functions(),
            )),
            AppCommand::CallComponentFunction {
                component_name,
                request,
            } => Ok(AppReply::ComponentFunctionCall(
                call_component_function(self.components.as_ref(), auth, component_name, request)
                    .await?,
            )),
            AppCommand::AwaitComponentHumanDecision(request) => {
                Ok(AppReply::ComponentHumanDecisionResolved(
                    await_component_human_decision(self.components.as_ref(), auth, request).await?,
                ))
            }
            AppCommand::ListPendingComponentHumanDecisions => {
                Ok(AppReply::PendingComponentHumanDecisions(
                    list_pending_component_human_decisions(self.components.as_ref(), auth).await?,
                ))
            }
            AppCommand::ResolveComponentHumanDecision {
                decision_id,
                answer,
            } => Ok(AppReply::ComponentHumanDecisionResolved(
                resolve_component_human_decision(
                    self.components.as_ref(),
                    auth,
                    decision_id,
                    answer,
                )
                .await?,
            )),
            AppCommand::ListSandboxedComponents => Ok(AppReply::SandboxedComponents(
                list_sandboxed_components(self.sandboxed_components.as_ref(), auth).await?,
            )),
            AppCommand::ListPublishedSandboxedComponents => {
                Ok(AppReply::PublishedSandboxedComponents(
                    list_published_sandboxed_components(self.sandboxed_components.as_ref(), auth)
                        .await?,
                ))
            }
            AppCommand::SaveSandboxedComponent(request) => Ok(AppReply::SandboxedComponent(
                save_sandboxed_component(self.sandboxed_components.as_ref(), auth, request).await?,
            )),
            AppCommand::PublishSandboxedComponent {
                component_name,
                expected_revision,
            } => Ok(AppReply::SandboxedComponent(
                publish_sandboxed_component(
                    self.sandboxed_components.as_ref(),
                    auth,
                    component_name,
                    expected_revision,
                )
                .await?,
            )),
            AppCommand::DeleteSandboxedComponent {
                component_name,
                expected_revision,
            } => Ok(AppReply::SandboxedComponentDeleted(
                delete_sandboxed_component(
                    self.sandboxed_components.as_ref(),
                    auth,
                    component_name,
                    expected_revision,
                )
                .await?,
            )),
            AppCommand::AuthorizeSandboxedComponent {
                component_name,
                agent_id,
                arguments,
            } => Ok(AppReply::ComponentDecision(
                authorize_sandboxed_component(
                    self.sandboxed_components.as_ref(),
                    auth,
                    component_name,
                    agent_id,
                    arguments,
                )
                .await?,
            )),
            AppCommand::GetCurrentUser => Ok(AppReply::CurrentUser(
                current_user(&self.people, auth).await?,
            )),
            AppCommand::AdminStatus => Ok(AppReply::AdminStatus(admin_status(auth)?)),
            AppCommand::ListPeople {
                search,
                cursor,
                limit,
            } => Ok(AppReply::People(
                list_people(&self.people, auth, search, cursor, limit).await?,
            )),
            AppCommand::ChangePersonRole { user_id, role } => Ok(AppReply::Person(
                change_person_role(&self.people, auth, &user_id, role).await?,
            )),
            AppCommand::ChangePersonAccess { user_id, revoked } => Ok(AppReply::Person(
                change_person_access(&self.people, auth, &user_id, revoked).await?,
            )),
            AppCommand::ListAuditEvents {
                cursor,
                event_type,
                actor_user_id,
                target_type,
                target_id,
                from,
                to,
                limit,
            } => Ok(AppReply::AuditEvents(
                list_audit_events(
                    &self.audit,
                    auth,
                    cursor,
                    event_type,
                    actor_user_id,
                    target_type,
                    target_id,
                    from,
                    to,
                    limit,
                )
                .await?,
            )),
            AppCommand::GetActionPolicy => Ok(AppReply::ActionPolicy {
                policy: get_action_policy(&self.policies, auth).await?,
            }),
            AppCommand::SetActionPolicy { policy } => Ok(AppReply::ActionPolicy {
                policy: Some(set_action_policy(&self.policies, auth, policy).await?),
            }),
            AppCommand::InvokeTool(invocation) => Ok(AppReply::Tool(
                invoke_tool(&self.tool_control, &self.tool_journal, auth, invocation).await?,
            )),
            AppCommand::MintThreadId => Ok(AppReply::ThreadMinted(
                mint_thread_id(&self.threads, auth).await?,
            )),
            AppCommand::GetThreadStatus { thread_id } => Ok(AppReply::ThreadStatus(
                get_thread_status(&self.threads, auth, &thread_id).await?,
            )),
            AppCommand::BeginThreadRun(command) => Ok(AppReply::ThreadRunStarted(
                begin_thread_run(&self.threads, self.artifacts.as_ref(), auth, command).await?,
            )),
            AppCommand::BeginThreadRunV2(command) => Ok(AppReply::ThreadRunStarted(
                begin_thread_run_v2(&self.threads, self.artifacts.as_ref(), auth, command).await?,
            )),
            AppCommand::CancelThreadRun(command) => Ok(AppReply::ThreadRunCancellation(
                cancel_thread_run(&self.threads, auth, command).await?,
            )),
            AppCommand::GetThreadHistory { thread_id } => Ok(AppReply::ThreadHistory(
                get_thread_history(&self.threads, auth, thread_id).await?,
            )),
            AppCommand::GetThreadConversation { thread_id } => Ok(AppReply::ThreadConversation(
                get_thread_conversation(&self.threads, auth, thread_id).await?,
            )),
            AppCommand::GetRunReconciliation {
                thread_id,
                run_id,
                after,
                limit,
            } => Ok(AppReply::RunReconciliation(
                crate::use_cases::thread::get_run_reconciliation(
                    &self.threads,
                    auth,
                    thread_id,
                    run_id,
                    after,
                    limit,
                )
                .await?,
            )),
            AppCommand::GetRunEffectReceipts {
                thread_id,
                run_id,
                after,
                limit,
            } => Ok(AppReply::RunEffectReceipts(
                crate::use_cases::thread::get_run_effect_receipts(
                    &self.threads,
                    auth,
                    thread_id,
                    run_id,
                    after,
                    limit,
                )
                .await?,
            )),
            AppCommand::ListPendingRemoteInterrupts => Ok(AppReply::PendingRemoteInterrupts(
                list_pending_remote_interrupts(self.remote_interrupts.as_ref(), auth).await?,
            )),
            AppCommand::ResolveRemoteInterrupt { request_id, answer } => {
                Ok(AppReply::RemoteInterruptResolved(
                    resolve_remote_interrupt(
                        self.remote_interrupts.as_ref(),
                        auth,
                        request_id,
                        answer,
                    )
                    .await?,
                ))
            }
            AppCommand::RememberMemory(input) => Ok(AppReply::Memory(
                remember_memory(&self.memory, auth, input).await?,
            )),
            AppCommand::GetMemoryControl => Ok(AppReply::MemoryControl(
                get_memory_control(&self.memory, auth).await?,
            )),
            AppCommand::UpdateMemoryControl(update) => Ok(AppReply::MemoryControl(
                update_memory_control(&self.memory, auth, update).await?,
            )),
            AppCommand::ListMemories { cursor, limit } => Ok(AppReply::Memories(
                list_memories(&self.memory, auth, cursor, limit).await?,
            )),
            AppCommand::CorrectMemory {
                memory_id,
                correction,
            } => Ok(AppReply::Memory(
                correct_memory(&self.memory, auth, memory_id, correction).await?,
            )),
            AppCommand::MutateMemory {
                memory_id,
                mutation,
            } => Ok(AppReply::Memory(
                mutate_memory(&self.memory, auth, memory_id, mutation).await?,
            )),
            AppCommand::RecallMemories(input) => Ok(AppReply::MemoryRecall(
                recall_memories(&self.memory, auth, input).await?,
            )),
            AppCommand::IssueAgentCallbackToken { agent_id } => Ok(AppReply::AgentCallbackToken(
                issue_agent_callback_token(&self.callback_tokens, auth, &agent_id).await?,
            )),
            AppCommand::RevokeAgentCallbackToken { agent_id } => {
                Ok(AppReply::AgentCallbackTokenRevoked(
                    revoke_agent_callback_token(&self.callback_tokens, auth, &agent_id).await?,
                ))
            }
            AppCommand::ListModelConnections(request) => {
                crate::model_connections::require_model_connection_actor(auth)?;
                Ok(AppReply::ModelConnections(
                    self.model_connections
                        .list(auth, &request)
                        .await
                        .map_err(crate::model_connections::ModelConnectionError::into_app_error)?,
                ))
            }
            AppCommand::GetModelConnection { connection_id } => {
                crate::model_connections::require_model_connection_actor(auth)?;
                Ok(AppReply::ModelConnection(
                    self.model_connections
                        .get(auth, &connection_id)
                        .await
                        .map_err(crate::model_connections::ModelConnectionError::into_app_error)?,
                ))
            }
            AppCommand::CreateModelConnection(input) => {
                crate::model_connections::require_model_connection_actor(auth)?;
                crate::model_connections::normalize_model_configuration(
                    &input.name,
                    input.protocol,
                    &input.endpoint,
                    &input.model,
                    input.enabled,
                )
                .map_err(crate::model_connections::ModelConnectionError::into_app_error)?;
                Ok(AppReply::ModelConnection(
                    self.model_connections
                        .create(auth, &input)
                        .await
                        .map_err(crate::model_connections::ModelConnectionError::into_app_error)?,
                ))
            }
            AppCommand::UpdateModelConnection {
                connection_id,
                input,
            } => {
                crate::model_connections::require_model_connection_actor(auth)?;
                if input.expected_revision <= 0 {
                    return Err(AppError::MalformedPayload {
                        field: "expectedRevision",
                    });
                }
                crate::model_connections::normalize_model_configuration(
                    &input.name,
                    input.protocol,
                    &input.endpoint,
                    &input.model,
                    input.enabled,
                )
                .map_err(crate::model_connections::ModelConnectionError::into_app_error)?;
                Ok(AppReply::ModelConnection(
                    self.model_connections
                        .update(auth, &connection_id, &input)
                        .await
                        .map_err(crate::model_connections::ModelConnectionError::into_app_error)?,
                ))
            }
            AppCommand::DeleteModelConnection {
                connection_id,
                input,
            } => {
                crate::model_connections::require_model_connection_actor(auth)?;
                if input.expected_revision <= 0 {
                    return Err(AppError::MalformedPayload {
                        field: "expectedRevision",
                    });
                }
                Ok(AppReply::ModelConnectionDeleted(
                    self.model_connections
                        .delete(auth, &connection_id, &input)
                        .await
                        .map_err(crate::model_connections::ModelConnectionError::into_app_error)?,
                ))
            }
            AppCommand::ListCredentials(request) => Ok(AppReply::Credentials(
                crate::credential_admin::list_credentials(
                    self.credentials.as_ref(),
                    auth,
                    &request,
                )
                .await?,
            )),
            AppCommand::CreateCredential(input) => Ok(AppReply::CredentialWritten(
                crate::credential_admin::create_credential(self.credentials.as_ref(), auth, &input)
                    .await?,
            )),
            AppCommand::RotateCredential {
                credential_id,
                input,
            } => Ok(AppReply::CredentialWritten(
                crate::credential_admin::rotate_credential(
                    self.credentials.as_ref(),
                    auth,
                    &credential_id,
                    &input,
                )
                .await?,
            )),
            AppCommand::RevokeCredential { credential_id } => Ok(AppReply::CredentialRevoked(
                crate::credential_admin::revoke_credential(
                    self.credentials.as_ref(),
                    auth,
                    &credential_id,
                )
                .await?,
            )),
            AppCommand::ListMcpConnections => Ok(AppReply::McpConnections(
                list_mcp_connections(self.mcp_connections.as_ref(), auth).await?,
            )),
            AppCommand::ListMcpAdminPage => Ok(AppReply::McpAdminPage(
                list_mcp_admin_page(self.mcp_connections.as_ref(), auth).await?,
            )),
            AppCommand::BeginMcpOAuth {
                server_id,
                return_to,
            } => Ok(AppReply::McpOAuthAuthorization(
                begin_mcp_oauth(self.mcp_connections.as_ref(), auth, &server_id, return_to).await?,
            )),
            AppCommand::DisconnectMcpConnection { server_id } => {
                Ok(AppReply::McpConnectionDisconnected(
                    disconnect_mcp_connection(self.mcp_connections.as_ref(), auth, &server_id)
                        .await?,
                ))
            }
            AppCommand::RegisterMcpOAuthClient {
                server_id,
                registration,
            } => Ok(AppReply::McpOAuthClientRegistered(
                register_mcp_oauth_client(
                    self.mcp_connections.as_ref(),
                    auth,
                    &server_id,
                    &registration,
                )
                .await?,
            )),
            AppCommand::AddCuratedMcpServer { key } => Ok(AppReply::McpServerMutation(
                add_curated_mcp_server(self.mcp_connections.as_ref(), auth, &key).await?,
            )),
            AppCommand::AddCustomMcpServer(registration) => Ok(AppReply::McpServerMutation(
                add_custom_mcp_server(self.mcp_connections.as_ref(), auth, &registration).await?,
            )),
            AppCommand::RemoveMcpServer { server_id } => Ok(AppReply::McpServerRemoved(
                remove_mcp_server(self.mcp_connections.as_ref(), auth, &server_id).await?,
            )),
            AppCommand::RefreshMcpServer { server_id } => Ok(AppReply::McpServerMutation(
                refresh_mcp_server(self.mcp_connections.as_ref(), auth, &server_id).await?,
            )),
            AppCommand::SavePluginSkill(mutation) => Ok(AppReply::PluginSkills(
                save_plugin_skill(self.mcp_connections.as_ref(), auth, &mutation).await?,
            )),
            AppCommand::RemovePluginSkill {
                slug,
                expected_revision,
            } => Ok(AppReply::PluginMutationAcknowledged(
                remove_plugin_skill(
                    self.mcp_connections.as_ref(),
                    auth,
                    &slug,
                    expected_revision,
                )
                .await?,
            )),
            AppCommand::GrantPlugin(mutation) => Ok(AppReply::PluginMutationAcknowledged(
                grant_plugin(self.mcp_connections.as_ref(), auth, &mutation).await?,
            )),
            AppCommand::RevokePlugin(mutation) => Ok(AppReply::PluginMutationAcknowledged(
                revoke_plugin(self.mcp_connections.as_ref(), auth, &mutation).await?,
            )),
            AppCommand::ListPluginsForAgent { agent_id } => Ok(AppReply::GrantedPlugins(
                list_plugins_for_agent(self.mcp_connections.as_ref(), auth, &agent_id).await?,
            )),
            AppCommand::ListPendingToolApprovals => Ok(AppReply::PendingToolApprovals(
                list_pending_tool_approvals(self.tool_approvals.as_ref(), auth).await?,
            )),
            AppCommand::DecideToolApproval {
                approval_id,
                decision,
            } => Ok(AppReply::ToolApprovalResolved(
                decide_tool_approval(self.tool_approvals.as_ref(), auth, &approval_id, decision)
                    .await?,
            )),
            AppCommand::GetUiPreferences => Ok(AppReply::UiPreferences(
                get_ui_preferences(self.ui_preferences.as_ref(), auth).await?,
            )),
            AppCommand::UpdateUiPreferences(update) => Ok(AppReply::UiPreferences(
                update_ui_preferences(self.ui_preferences.as_ref(), auth, update).await?,
            )),
            AppCommand::GetRunCostBudget => Ok(AppReply::RunCostBudget(
                get_run_cost_budget(self.run_cost_budgets.as_ref(), auth).await?,
            )),
            AppCommand::ReplaceRunCostBudget(preference) => Ok(AppReply::RunCostBudget(
                replace_run_cost_budget(self.run_cost_budgets.as_ref(), auth, preference).await?,
            )),
            AppCommand::IssueScreenSession(request) => Ok(AppReply::ScreenSession(
                issue_screen_session(self.screen_sessions.as_ref(), auth, request).await?,
            )),
        }
    }
}

#[async_trait]
impl<R, P, A, K, C, J, T, M, B> ApplicationService for OpenBotApplication<R, P, A, K, C, J, T, M, B>
where
    R: ChannelReader + 'static,
    P: PeopleAdministration + 'static,
    A: AuditReader + 'static,
    K: PolicyAdministration + 'static,
    C: ToolControlPlane + 'static,
    J: ToolJournal + 'static,
    T: ThreadDirectory + 'static,
    M: MemoryAdministration + 'static,
    B: AgentCallbackTokenAdministration + 'static,
{
    fn take_custom_model_catalog_delivery(
        &self,
        auth: AuthContext,
        reply: AppReply,
    ) -> Result<crate::PublicCustomModelCatalogDelivery, AppError> {
        self.custom_model_catalog_deliveries.take(auth, reply)
    }

    fn take_artifact_read_delivery(
        &self,
        auth: AuthContext,
        input: openbot_contracts::artifact_read_protocol::ReadArtifactReadBlock,
    ) -> Result<crate::PublicArtifactReadDelivery, AppError> {
        self.public_artifact_reads.take_delivery(&auth, input)
    }
    fn take_artifact_read_control_delivery(
        &self,
        auth: AuthContext,
        reply: AppReply,
    ) -> Result<crate::PublicArtifactReadControlDelivery, AppError> {
        self.public_artifact_reads.take_control(&auth, reply)
    }
    fn close_public_artifact_reads(&self) -> Result<(), AppError> {
        self.public_artifact_reads.close_all()
    }
    fn close_public_artifact_reads_for_issuer(
        &self,
        issuer: &openbot_contracts::request_binding::RequestBindingIssuer,
    ) -> Result<(), AppError> {
        self.public_artifact_reads.close_for_issuer(issuer)
    }
    fn close_public_artifact_reads_for_binding(
        &self,
        binding: &openbot_contracts::request_binding::HostRequestBindingIdentity,
    ) -> Result<(), AppError> {
        self.public_artifact_reads.close_for_binding(binding)
    }
    async fn read_current_artifact_chunk(
        &self,
        auth: AuthContext,
        artifact_id: String,
    ) -> Result<crate::artifacts::CurrentArtifactReadChunk, AppError> {
        let artifact_id = openbot_contracts::artifacts::canonical_artifact_uuid_v7(&artifact_id)
            .ok_or(AppError::MalformedPayload {
                field: "artifactId",
            })?;
        if auth.request_binding().is_none() {
            return Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            });
        }
        // The final own-Pool joint predicate checks the current role/source, host first.
        // Do not add an early role response or return an older separate auth observation.
        let chunk = self
            .artifacts
            .read_host_bound_chunk(&auth, &artifact_id)
            .await?;
        chunk.verify_current(&auth)?;
        Ok(chunk)
    }
    async fn open_current_artifact_read(
        &self,
        auth: AuthContext,
        artifact_id: String,
    ) -> Result<crate::CurrentArtifactReadOperation, AppError> {
        let artifact_id = openbot_contracts::artifacts::canonical_artifact_uuid_v7(&artifact_id)
            .ok_or(AppError::MalformedPayload {
                field: "artifactId",
            })?;
        if auth.request_binding().is_none() {
            return Err(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            });
        }
        self.artifacts
            .open_host_bound_read_operation(&auth, &artifact_id)
            .await
    }
    #[tracing::instrument(
        name = "application.execute",
        skip_all,
        fields(
            deployment_id = %auth.deployment(),
            tenant_id = %auth.tenant(),
            actor_id = %auth.actor(),
            operation = command_kind(&command),
            error.code = tracing::field::Empty,
        )
    )]
    async fn execute(&self, auth: AuthContext, command: AppCommand) -> Result<AppReply, AppError> {
        let result = self.dispatch(&auth, command).await;
        if let Err(error) = &result {
            // 只记**稳定码**，不记 `Display`：`AppError` 的 Display 会带上 policy rule id
            // 与 lease holder 这类上下文，那些属于受控诊断，不该由一条恒开的 span 字段
            // 无差别带出去。code 是 §15.3 定死的、与文案解耦的那一样东西。
            Span::current().record("error.code", error.code().as_str());
        }
        result
    }

    #[tracing::instrument(
        name = "application.subscribe",
        skip_all,
        fields(
            deployment_id = %auth.deployment(),
            tenant_id = %auth.tenant(),
            actor_id = %auth.actor(),
            operation = subscription_kind(&request),
            error.code = tracing::field::Empty,
        )
    )]
    async fn subscribe(
        &self,
        auth: AuthContext,
        request: SubscriptionRequest,
    ) -> Result<AppEventStream, AppError> {
        // 穷举 match，理由同 `dispatch`。
        match request {
            SubscriptionRequest::Health => Ok(health_stream(self.heartbeat_period)),
            SubscriptionRequest::ThreadEvents {
                thread_id,
                after_event_sequence,
            } => {
                subscribe_thread_events(&self.threads, &auth, thread_id, after_event_sequence).await
            }
            SubscriptionRequest::ChannelActivity => {
                subscribe_channel_activity(&self.threads, &auth).await
            }
            SubscriptionRequest::ToolApprovalActivity => {
                subscribe_tool_approval_activity(self.tool_approvals.as_ref(), &auth).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::{
        FakeChannelReader, FakePeopleAdministration, SENTINEL_AUTH_GENERATION, auth_for,
        sample_person, summary_at,
    };
    use crate::service::{APPLICATION_SPAN_FIELDS, EXECUTE_SPAN_NAME, SUBSCRIBE_SPAN_NAME};
    use core::fmt;
    use core::future::Future;
    use openbot_contracts::auth::{AuthContext, Role};
    use openbot_contracts::command::{AppEvent, BeginThreadRun, ThreadRunAnchor, ThreadRunStarted};
    use openbot_contracts::error::ErrorCode;
    use openbot_contracts::ids::{
        ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId, ToolCallId,
    };
    use openbot_contracts::memory::{
        CorrectMemory, MemoryKind, MemoryMutation, MemoryScope, MemorySensitivity, RecallMemories,
        RememberMemory,
    };
    use openbot_contracts::policy::{ActionPolicyDocument, ActionPolicyMode};
    use openbot_contracts::tool::ToolInvocation;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::Registry;

    // -----------------------------------------------------------------------
    // span 捕获层
    // -----------------------------------------------------------------------

    /// 捕获到的 span：名字 + 全部被记录的字段。
    #[derive(Clone, Debug, Default)]
    struct Captured {
        names: Vec<String>,
        fields: Vec<(String, String)>,
    }

    impl Captured {
        fn names_of_fields(&self) -> Vec<&str> {
            self.fields.iter().map(|(k, _)| k.as_str()).collect()
        }

        fn value_of(&self, key: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    /// 把 span 字段收进一个 `Vec`。
    ///
    /// `record_str` 与 `record_debug` 都实现：`Display` 值（`%expr`）走 `record_debug`，
    /// `&'static str` 值走 `record_str`。只实现一个会漏掉另一半 —— 那会让"span 里没有
    /// 敏感字段"这条断言在"我根本没看见任何字段"的情况下也成立。
    struct Collector<'a>(&'a mut Vec<(String, String)>);

    impl Visit for Collector<'_> {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.push((field.name().to_owned(), value.to_owned()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0.push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    #[derive(Clone, Default)]
    struct CaptureLayer(Arc<Mutex<Captured>>);

    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
            let mut captured = self.0.lock().expect("捕获层的互斥锁不会中毒");
            captured.names.push(attrs.metadata().name().to_owned());
            let mut fields = core::mem::take(&mut captured.fields);
            attrs.record(&mut Collector(&mut fields));
            captured.fields = fields;
        }

        fn on_record(&self, _id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            let mut captured = self.0.lock().expect("捕获层的互斥锁不会中毒");
            let mut fields = core::mem::take(&mut captured.fields);
            values.record(&mut Collector(&mut fields));
            captured.fields = fields;
        }
    }

    /// 在捕获层下跑一段 async 工作，返回工作结果与捕获到的 span。
    fn capture<F, T>(work: F) -> (T, Captured)
    where
        F: Future<Output = T>,
    {
        let layer = CaptureLayer::default();
        let sink = Arc::clone(&layer.0);
        let subscriber = Registry::default().with(layer);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("构建当前线程运行时");
        let out = tracing::subscriber::with_default(subscriber, || runtime.block_on(work));
        let captured = sink.lock().expect("捕获层的互斥锁不会中毒").clone();
        (out, captured)
    }

    fn app() -> OpenBotApplication<FakeChannelReader, FakePeopleAdministration> {
        OpenBotApplication::new(
            FakeChannelReader::empty()
                .with_visible("actor-1", vec![summary_at("c-1", "2026-08-22T04:00:00Z")]),
        )
        .with_people(FakePeopleAdministration::seeded([
            sample_person("actor-1", Role::Admin),
            sample_person("actor-2", Role::User),
        ]))
        .with_heartbeat_period(Duration::from_millis(1))
    }

    // -----------------------------------------------------------------------
    // 派发
    // -----------------------------------------------------------------------

    #[test]
    fn execute_dispatches_every_command_variant() {
        let service = app();
        let auth = auth_for("actor-1");

        let (health_reply, _) = capture(service.execute(auth.clone(), AppCommand::Health));
        assert_eq!(
            health_reply.expect("探活必须成功"),
            AppReply::Health(openbot_contracts::command::HealthReport { ok: true })
        );

        let (channels_reply, _) = capture(service.execute(
            auth.clone(),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: None,
            },
        ));
        match channels_reply.expect("列表必须成功") {
            AppReply::Channels(page) => {
                assert_eq!(page.channels.len(), 1);
                assert!(page.next_cursor.is_none());
            }
            other => panic!("命令与应答必须一一对应，拿到 {other:?}"),
        }

        let (channel_reply, _) = capture(service.execute(
            auth.clone(),
            AppCommand::GetVisibleChannel {
                channel_id: openbot_contracts::ids::ChannelId::new("c-1"),
            },
        ));
        assert!(matches!(channel_reply, Ok(AppReply::Channel(_))));

        let (me, _) = capture(service.execute(auth.clone(), AppCommand::GetCurrentUser));
        assert!(matches!(me, Ok(AppReply::CurrentUser(_))));

        let (status, _) = capture(service.execute(auth.clone(), AppCommand::AdminStatus));
        assert!(matches!(status, Ok(AppReply::AdminStatus(_))));

        let (people, _) = capture(service.execute(
            auth.clone(),
            AppCommand::ListPeople {
                search: None,
                cursor: None,
                limit: None,
            },
        ));
        assert!(matches!(people, Ok(AppReply::People(_))));

        let (role, _) = capture(service.execute(
            auth.clone(),
            AppCommand::ChangePersonRole {
                user_id: ActorId::new("actor-2"),
                role: Role::Admin,
            },
        ));
        assert!(matches!(role, Ok(AppReply::Person(_))));

        let (access, _) = capture(service.execute(
            auth.clone(),
            AppCommand::ChangePersonAccess {
                user_id: ActorId::new("actor-2"),
                revoked: true,
            },
        ));
        assert!(matches!(access, Ok(AppReply::Person(_))));

        let (audit, _) = capture(service.execute(
            auth.clone(),
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
        ));
        assert!(matches!(
            audit,
            Err(AppError::DependencyUnavailable {
                dependency: "database"
            })
        ));

        let (get_policy, _) = capture(service.execute(auth.clone(), AppCommand::GetActionPolicy));
        assert!(matches!(
            get_policy,
            Err(AppError::DependencyUnavailable {
                dependency: "policy_store"
            })
        ));
        let (set_policy, _) = capture(service.execute(
            auth.clone(),
            AppCommand::SetActionPolicy {
                policy: ActionPolicyDocument {
                    mode: ActionPolicyMode::Enforce,
                    deny: Vec::new(),
                    allow: vec!["true".to_owned()],
                },
            },
        ));
        assert!(matches!(
            set_policy,
            Err(AppError::DependencyUnavailable {
                dependency: "policy_store"
            })
        ));

        let (tool, _) = capture(service.execute(
            auth.clone(),
            AppCommand::InvokeTool(ToolInvocation {
                call_id: ToolCallId::new("call-1"),
                run_id: RunId::new("run-1"),
                bot_id: BotId::new("bot-1"),
                call_seq: 0,
                tool_name: "computer.write".to_owned(),
                arguments: json!({}),
            }),
        ));
        assert!(matches!(
            tool,
            Err(AppError::DependencyUnavailable {
                dependency: "tool_catalog"
            })
        ));

        for command in [
            AppCommand::MintThreadId,
            AppCommand::GetThreadStatus {
                thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
            },
            AppCommand::BeginThreadRun(BeginThreadRun {
                model_selection: None,
                selected_skill_slugs: Vec::new(),
                artifact_refs: Vec::new(),
                thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                run_id: RunId::new("run-thread"),
                bot_id: BotId::new("bot-1"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "hello".to_owned(),
            }),
            AppCommand::GetThreadHistory {
                thread_id: ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
            },
        ] {
            let (reply, _) = capture(service.execute(auth.clone(), command));
            assert!(matches!(
                reply,
                Err(AppError::DependencyUnavailable {
                    dependency: "thread_directory"
                })
            ));
        }

        for command in [
            AppCommand::RememberMemory(RememberMemory {
                memory_kind: MemoryKind::Preference,
                scope: MemoryScope::User,
                content: "tea".to_owned(),
                tags: Vec::new(),
                sensitivity: MemorySensitivity::Normal,
                source: None,
                expires_at: None,
            }),
            AppCommand::ListMemories {
                cursor: None,
                limit: None,
            },
            AppCommand::CorrectMemory {
                memory_id: "memory-1".to_owned(),
                correction: CorrectMemory {
                    content: "coffee".to_owned(),
                    tags: Vec::new(),
                    sensitivity: MemorySensitivity::Normal,
                    expires_at: None,
                },
            },
            AppCommand::MutateMemory {
                memory_id: "memory-1".to_owned(),
                mutation: MemoryMutation::Delete,
            },
            AppCommand::RecallMemories(RecallMemories {
                query: "office".to_owned(),
                tags: Vec::new(),
                bot_id: None,
                thread_id: None,
                limit: None,
            }),
        ] {
            let (reply, _) = capture(service.execute(auth.clone(), command));
            assert!(matches!(
                reply,
                Err(AppError::DependencyUnavailable {
                    dependency: "memory_store"
                })
            ));
        }

        for command in [
            AppCommand::IssueAgentCallbackToken {
                agent_id: BotId::new("remote-1"),
            },
            AppCommand::RevokeAgentCallbackToken {
                agent_id: BotId::new("remote-1"),
            },
        ] {
            let (reply, _) = capture(service.execute(auth.clone(), command));
            assert!(matches!(
                reply,
                Err(AppError::DependencyUnavailable {
                    dependency: "agent_callback_tokens"
                })
            ));
        }
    }

    /// 订阅回来的流是**活的**：拿到就能取到第一拍。
    ///
    /// 订阅与轮询必须在**同一个运行时**里完成 —— `tokio::time::Interval` 把定时器注册在
    /// 创建它的那个运行时上，换一个运行时去 poll 会撞上
    /// "A Tokio 1.x context was found, but it is being shutdown"。这不是测试技巧，
    /// 而是这条流对宿主的真实要求，transport 侧同样适用。
    #[test]
    fn subscribe_returns_a_live_heartbeat_stream() {
        let service = app();
        let (first, captured) = capture(async {
            let mut stream = service
                .subscribe(auth_for("actor-1"), SubscriptionRequest::Health)
                .await
                .expect("订阅必须成功");
            core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
        });
        assert_eq!(first, Some(AppEvent::Heartbeat { seq: 0 }));
        assert_eq!(captured.names, vec![SUBSCRIBE_SPAN_NAME.to_owned()]);
    }

    // -----------------------------------------------------------------------
    // tracing
    // -----------------------------------------------------------------------

    /// 正向对照（同时是 §16.4 关联字段确实落地的证据）：span 名与四个字段都在。
    ///
    /// 没有这一条，下面那条"没有敏感字段"的断言在"捕获层什么都没看见"的世界里恒真。
    #[test]
    fn execute_span_carries_the_declared_correlation_fields() {
        let service = app();
        let (_, captured) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: None,
            },
        ));

        assert_eq!(captured.names, vec![EXECUTE_SPAN_NAME.to_owned()]);
        assert_eq!(captured.value_of("deployment_id"), Some("dep-g1"));
        assert_eq!(captured.value_of("tenant_id"), Some("tenant-g1"));
        assert_eq!(captured.value_of("actor_id"), Some("actor-1"));
        assert_eq!(
            captured.value_of("operation"),
            Some("list_visible_channels")
        );
    }

    /// 负向：`AuthContext` 整体、角色集合、auth generation 一个都不进 span。
    #[test]
    fn span_never_carries_the_auth_context_or_its_credentials() {
        let service = app();
        let (_, captured) = capture(service.execute(auth_for("actor-1"), AppCommand::Health));

        let tool_secret = "SENTINEL-TOOL-ARGUMENT-SECRET";
        let (_, tool_captured) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::InvokeTool(ToolInvocation {
                call_id: ToolCallId::new("call-secret"),
                run_id: RunId::new("run-1"),
                bot_id: BotId::new("bot-1"),
                call_seq: 0,
                tool_name: "computer.write".to_owned(),
                arguments: json!({"password":tool_secret}),
            }),
        ));

        let sentinel = SENTINEL_AUTH_GENERATION.to_string();
        for (name, value) in captured.fields.iter().chain(&tool_captured.fields) {
            assert!(
                !value.contains(&sentinel),
                "auth_generation 不得出现在 span 里：{name}={value}"
            );
            assert!(
                !value.contains(tool_secret),
                "tool arguments 不得出现在 span 里：{name}={value}"
            );
            for forbidden in ["AuthContext", "roles", "Admin", "single_user"] {
                assert!(
                    !value.contains(forbidden),
                    "span 字段 {name} 泄漏了 {forbidden}：{value}"
                );
                assert!(
                    !name.contains(forbidden),
                    "span 字段名本身就不该是 {forbidden}"
                );
            }
        }

        // 正向对照：捕获层确实看见了字段（否则上面的循环体一次都不执行）。
        assert!(!captured.fields.is_empty(), "捕获层必须真的看到字段");
        assert_eq!(captured.value_of("actor_id"), Some("actor-1"));
        assert_eq!(tool_captured.value_of("operation"), Some("invoke_tool"));
    }

    /// span 字段集合恰好是登记过的那些 —— 多记一个就判红，逼作者去做基数裁决。
    #[test]
    fn span_fields_are_exactly_the_declared_ledger() {
        let service = app();

        // 成功路径：`error.code` 是 Empty，不会被记录。
        let (_, ok) = capture(service.execute(auth_for("actor-1"), AppCommand::Health));
        for name in ok.names_of_fields() {
            assert!(
                APPLICATION_SPAN_FIELDS.contains(&name),
                "未登记的 span 字段：{name}"
            );
        }

        // 失败路径：`error.code` 被记录，于是并集恰好覆盖整份台账。
        let (_, err) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: Some("@@@bad".to_owned()),
            },
        ));
        let mut union: Vec<&str> = ok.names_of_fields();
        union.extend(err.names_of_fields());
        union.sort_unstable();
        union.dedup();
        let mut expected: Vec<&str> = APPLICATION_SPAN_FIELDS.to_vec();
        expected.sort_unstable();
        assert_eq!(union, expected, "span 字段集合必须与台账逐项相等");
    }

    /// 失败时把**稳定码**记到 span 上（不是 Display，不是内部细节）。
    #[test]
    fn failed_execute_records_the_stable_error_code() {
        let service = app();
        let (result, captured) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: Some("@@@bad".to_owned()),
            },
        ));

        let err = result.expect_err("坏游标必须失败");
        assert_eq!(err.code(), ErrorCode::MALFORMED_PAYLOAD);
        assert_eq!(captured.value_of("error.code"), Some("malformed_payload"));

        // 负向：policy rule / holder 这类 Display 上下文不得随之进来。
        assert!(
            captured.value_of("error").is_none(),
            "只记 code，不记整条 Display"
        );
    }

    #[test]
    fn subscribe_is_instrumented_too() {
        let service = app();
        let (_, captured) =
            capture(service.subscribe(auth_for("actor-1"), SubscriptionRequest::Health));
        assert_eq!(captured.names, vec![SUBSCRIBE_SPAN_NAME.to_owned()]);
        assert_eq!(captured.value_of("operation"), Some("health"));
        assert_eq!(captured.value_of("actor_id"), Some("actor-1"));
    }

    // -----------------------------------------------------------------------
    // G1 没有生产者的两个错误变体（见 crate 文档）
    // -----------------------------------------------------------------------

    /// 零角色的**已认证** actor 不被拒绝：G1 的两个用例都不设角色门（parity）。
    ///
    /// 同一个 roleless actor：普通读取不凭空加角色门，admin 用例则必须产出 403。
    #[test]
    fn a_roleless_authenticated_actor_is_not_rejected() {
        let roleless = AuthContext::for_test(
            DeploymentId::new("dep-g1"),
            TenantId::new("tenant-g1"),
            ActorId::new("actor-1"),
            [],
            openbot_contracts::auth::AuthGeneration::new(1),
            false,
        );
        assert!(roleless.roles().is_empty());

        let service = app();
        let (health_reply, _) = capture(service.execute(roleless.clone(), AppCommand::Health));
        assert!(health_reply.is_ok(), "探活不看角色");

        let (list_reply, _) = capture(service.execute(
            roleless.clone(),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: None,
            },
        ));
        assert!(list_reply.is_ok(), "列表只看 membership，不看角色");

        let (admin_reply, _) = capture(service.execute(roleless, AppCommand::AdminStatus));
        assert!(matches!(
            admin_reply,
            Err(AppError::ForbiddenRole {
                required: Role::Admin
            })
        ));
    }

    /// 正向对照：本 crate **确实**会返回错误 —— 上一条的 `is_ok()` 不是靠
    /// 「这个入口永远成功」成立的。
    #[test]
    fn the_service_does_produce_errors_on_other_paths() {
        let service = app();
        let (result, _) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::ListVisibleChannels {
                limit: None,
                cursor: Some("@@@bad".to_owned()),
            },
        ));
        assert!(result.is_err());
    }

    struct FixedThreadBegin;

    #[async_trait]
    impl ThreadDirectory for FixedThreadBegin {
        async fn mint_thread_id(
            &self,
            _deployment: &DeploymentId,
        ) -> Result<ThreadId, crate::ports::ThreadDirectoryError> {
            Err(crate::ports::ThreadDirectoryError::Unavailable)
        }

        async fn thread_known(
            &self,
            _deployment: &DeploymentId,
            _tenant: &TenantId,
            _actor: &ActorId,
            _thread: &ThreadId,
        ) -> Result<bool, crate::ports::ThreadDirectoryError> {
            Err(crate::ports::ThreadDirectoryError::Unavailable)
        }

        async fn begin_thread_run(
            &self,
            request: crate::ports::BeginThreadRunRequest,
        ) -> Result<ThreadRunStarted, crate::ports::ThreadDirectoryError> {
            Ok(ThreadRunStarted {
                thread_id: request.command.thread_id,
                run_id: request.command.run_id,
                message_sequence: 4,
                event_sequence: 9,
                replayed: false,
            })
        }

        async fn subscribe_thread_events(
            &self,
            _request: crate::ports::ThreadEventSubscription,
        ) -> Result<AppEventStream, crate::ports::ThreadDirectoryError> {
            Ok(health_stream(core::time::Duration::from_secs(1)))
        }

        async fn subscribe_channel_activity(
            &self,
            _request: crate::ports::ChannelActivitySubscription,
        ) -> Result<AppEventStream, crate::ports::ThreadDirectoryError> {
            Ok(health_stream(core::time::Duration::from_secs(1)))
        }
    }

    #[test]
    fn begin_thread_run_reaches_the_port_through_application_service_execute() {
        let service =
            OpenBotApplication::new(FakeChannelReader::empty()).with_threads(FixedThreadBegin);
        let thread_id = ThreadId::new("550e8400-e29b-81d4-a716-446655440000");
        let run_id = RunId::new("run-through-service");
        let (reply, _) = capture(service.execute(
            auth_for("actor-1"),
            AppCommand::BeginThreadRun(BeginThreadRun {
                model_selection: None,
                selected_skill_slugs: Vec::new(),
                artifact_refs: Vec::new(),
                thread_id: thread_id.clone(),
                run_id: run_id.clone(),
                bot_id: BotId::new("bot-1"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "hello".to_owned(),
            }),
        ));
        assert_eq!(
            reply,
            Ok(AppReply::ThreadRunStarted(ThreadRunStarted {
                thread_id,
                run_id,
                message_sequence: 4,
                event_sequence: 9,
                replayed: false,
            }))
        );
    }

    #[test]
    fn thread_subscription_reaches_the_port_through_application_service_subscribe() {
        let service =
            OpenBotApplication::new(FakeChannelReader::empty()).with_threads(FixedThreadBegin);
        let (result, captured) = capture(service.subscribe(
            auth_for("actor-1"),
            SubscriptionRequest::ThreadEvents {
                thread_id: ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
                after_event_sequence: Some(0),
            },
        ));
        assert!(result.is_ok());
        assert_eq!(captured.value_of("operation"), Some("thread_events"));
    }

    #[test]
    fn channel_subscription_reaches_the_port_through_application_service_subscribe() {
        let service =
            OpenBotApplication::new(FakeChannelReader::empty()).with_threads(FixedThreadBegin);
        let (result, captured) =
            capture(service.subscribe(auth_for("actor-1"), SubscriptionRequest::ChannelActivity));
        assert!(result.is_ok());
        assert_eq!(captured.value_of("operation"), Some("channel_activity"));
    }

    #[test]
    fn approval_subscription_is_typed_and_fail_closed_without_the_production_port() {
        let service = OpenBotApplication::new(FakeChannelReader::empty());
        let (result, captured) = capture(service.subscribe(
            auth_for("actor-1"),
            SubscriptionRequest::ToolApprovalActivity,
        ));
        assert!(matches!(
            result,
            Err(AppError::DependencyUnavailable {
                dependency: "tool_approval"
            })
        ));
        assert_eq!(
            captured.value_of("operation"),
            Some("tool_approval_activity")
        );
    }

    /// `dyn ApplicationService` 必须可用：transport 持有的是 trait 对象。
    #[test]
    fn the_service_is_object_safe() {
        let service: Box<dyn ApplicationService> = Box::new(app());
        let (reply, _) = capture(service.execute(auth_for("actor-1"), AppCommand::Health));
        assert!(reply.is_ok());
    }
}
