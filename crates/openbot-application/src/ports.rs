//! 端口（port）—— application **定义**，infra **实现**。
//!
//! 这是六边形架构里那根决定依赖方向的轴：依赖箭头是 `openbot-infra -> openbot-application`。
//! 本模块不 import 任何 I/O crate，也不出现任何 SQL —— 出现了就说明抽象漏了。

use async_trait::async_trait;
use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentLifecycleReceipt,
    AgentMutationRequest, AgentProfile,
};
use openbot_contracts::audit::AuditPage;
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::command::{
    BeginThreadRun, BeginThreadRunV2, CancelThreadRun, ChannelDetail, ChannelSummary,
    ThreadHistory, ThreadRunCancellation, ThreadRunStarted,
};
use openbot_contracts::error::{AppError, IdentityConflictReason};
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_contracts::memory::{
    CorrectMemory, MemoryControl, MemoryMutation, MemoryPage, MemoryRecall, MemoryRecord,
    RecallMemories, RememberMemory, UpdateMemoryControl,
};
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use openbot_domain::policy::ActionPolicy;
use openbot_domain::routing::RoutingReasonCode;
use time::OffsetDateTime;

use crate::cursor::ChannelCursor;
use crate::service::AppEventStream;

/// 端口失败。**恰两类**，因为 application 对它们只有两种正确反应。
///
/// 刻意全是 `&'static str` 字段：数据库返回的原值是不可信数据，把它塞进错误就是日志
/// 注入面，也会让错误文本变成事实上的用户文案（repository contract §4a 禁止）。需要细节的地方
/// 由实现侧自己 `tracing::error!` 记录，那是受控 trace。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PortError {
    /// 依赖此刻不能服务：连不上、池满、超时、被拒。
    #[error("port_unavailable dependency={dependency}")]
    Unavailable {
        /// 依赖的静态名，与 `AppError::DependencyUnavailable::dependency` 同域。
        dependency: &'static str,
    },

    /// 依赖回了东西，但那东西解不开：列类型不符、枚举取值不在域内、NOT NULL 却是 NULL。
    #[error("port_corrupt dependency={dependency} field={field}")]
    Corrupt {
        /// 依赖的静态名。
        dependency: &'static str,
        /// 解不开的**字段名**（不是值）。
        field: &'static str,
    },
}

impl PortError {
    /// 映射成 `AppError`（§15.3）。
    ///
    /// # 两类都落 `DependencyUnavailable`（503），这是一次有意的裁决
    ///
    /// `Unavailable` 落 503 没有争议。`Corrupt` 有两个候选，选择理由如下：
    ///
    /// - **不能落 400**。`MalformedPayload` 说的是「调用方送来的载荷坏了」，而这里坏的是
    ///   我们自己的存储。用 400 回一次服务端缺陷，等于让客户端去修一个它改不动的东西，
    ///   而且会污染「malformed payload 不产生 acting decision」这条判据的统计口径。
    /// - **不落 502 `VendorFailure`**，尽管 HTTP 语义上 502（上游回了无效响应）比 503
    ///   更贴。理由是稳定码是契约：§15.3 把 `vendor_failure` 绑定在「上游 vendor」上，
    ///   contracts 的类型文档也这么写。把自家 PostgreSQL 记成 vendor 失败，会让运维在
    ///   排查 provider 抖动时捞到一堆数据库故障 —— audit 侧更明显，`AuditKind::VendorFailure`
    ///   与 `AuditKind::DependencyFailure` 是两个不同的查询桶。**扭曲一个既有稳定码的含义，
    ///   比状态码差一格更贵。**
    ///
    /// 代价要说清楚：503 隐含「稍后重试可能好」，而损坏的行不会自愈。这条差异记在这里
    /// 供reviewer复核；真要区分，正确做法是给 `AppError` 加一个变体（那是改 contracts 的
    /// 独立决定，不能由本 crate 顺手做）。
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable { dependency } | Self::Corrupt { dependency, .. } => {
                AppError::DependencyUnavailable { dependency }
            }
        }
    }
}

/// 读取「当前 actor 可见的 channel」。
///
/// # 可见性判据只有一个：materialized membership（§6.5 条 5 / §28.1 R22）
///
/// 实现**必须**只 join `channel_memberships`，**绝不**再 join
/// `intelligence_channel_mappings`。两条独立理由，缺任一条这个 join 都还是错的：
///
/// 1. **它会静默撤销 §6.5 的修复**。Intelligence 已按 §4.1 退役，
///    `intelligence_channel_mappings` 按 §14.2 降级为只读 legacy provenance —— 不会再有
///    新的 mapping 行。于是 §6.5 刚给包 channel 补上的 membership，会被这个 join 原样
///    过滤回「对所有人不可达」，回到上游 issue #82 的状态。
/// 2. **上游两段判据不一致本身就是缺陷**：`channels/routes.ts::list` 的分页段只 join
///    membership，hydration 段额外 join mapping，于是 `nextCursor` 可以非空而本页为空 ——
///    客户端看到「还有下一页」，翻过去却什么都没有。
///
/// 推论，请在实现与复核时一起守：**分页与 hydration 必须共用同一个可见性判据**。
/// 这个 port 的存在形式本身就在兑现它 —— 它只有一次调用，一次判据，返回的行直接就是
/// 应答的行，application 侧不做任何二次过滤（由
/// `rows_are_never_post_filtered_after_the_visibility_query` 钉住）。这也是 G1 最容易被
/// 后人「顺手改回去」的地方：任何在这条链路上引入第二次过滤的改动都必须先推翻上面两条。
///
/// # `limit` 的语义：调用方已经把 `+1` 算好了
///
/// 传进来的 `limit` 就是**要读的行数**，实现照读即可，不要再自己加一。
/// application 侧按上游 `channels/routes.ts::list` 的写法多要一行来探测「还有没有下一页」，
/// 避免第二次 `count(*)` 查询；探测与截断都留在 application（见
/// [`crate::use_cases::list_visible_channels`]），port 不必知道这个技巧。
///
/// # 排序与游标
///
/// 返回的行必须已经按 `coalesce(last_message_at, created_at) DESC, id DESC` 排好序；
/// `cursor` 为 `Some` 时只返回严格小于该二元组的行：
/// `(coalesce(last_message_at, created_at), id) < (cursor.recency, cursor.id)`。
/// application **不会**重排 —— 它没有能力在时间戳相同的行之间复现数据库的定序。
///
/// # scope
///
/// `actor` 是权威身份，来自 `AuthContext`，**不是**调用方传来的过滤条件。固定 0012 的
/// `channels/channel_memberships` 没有 deployment/tenant 列，所以 roster 可见性只能诚实地按
/// materialized actor membership 表达；不能假装物理列存在。G3 native thread 有两列，故
/// [`ChannelReadScope`] 的 deployment/tenant 只用于 thread projection，防止同 channel id 的
/// foreign scope thread 被带进 DTO。
#[async_trait]
pub trait ChannelReader: Send + Sync {
    /// 列出 actor 通过 **materialized membership** 可见的 channel。
    ///
    /// # Errors
    ///
    /// 依赖不可用或返回了解不开的行时返回 [`PortError`]；**空结果不是错误**，
    /// 返回空 `Vec`（§15.3 末条）。
    async fn list_visible_channels(
        &self,
        actor: &ActorId,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError>;

    /// Scope-aware production list. Legacy/fake implementations may delegate to actor-only
    /// visibility; PostgreSQL overrides this to project only a matching native thread.
    async fn list_visible_channels_scoped(
        &self,
        scope: &ChannelReadScope,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        self.list_visible_channels(&scope.actor, limit, cursor)
            .await
    }

    /// Read one channel through current membership and project only a scope-matching native thread.
    async fn get_visible_channel(
        &self,
        _scope: &ChannelReadScope,
        _channel_id: &ChannelId,
    ) -> Result<Option<ChannelSummary>, PortError> {
        Err(PortError::Unavailable {
            dependency: "channel_reader",
        })
    }
}

/// Authoritative scope for channel reads that may project native thread state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelReadScope {
    /// Verified deployment.
    pub deployment: DeploymentId,
    /// Verified tenant.
    pub tenant: TenantId,
    /// Verified actor.
    pub actor: ActorId,
}

/// Authoritative scope for creating a user channel and native thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCreateScope {
    /// Verified deployment used to mint the thread fingerprint.
    pub deployment: DeploymentId,
    /// Verified tenant used to exclude another package's Agents.
    pub tenant: TenantId,
    /// Verified creator and sole initial channel member.
    pub actor: ActorId,
    /// Original authenticated generation, rechecked by the native creation transaction.
    pub auth_generation: AuthGeneration,
    /// Whether verified roles include administrator for private-Agent access.
    pub admin: bool,
}

/// Canonical channel creation request passed to the single PostgreSQL transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCreateRequest {
    /// Verified scope.
    pub scope: ChannelCreateScope,
    /// Non-empty, unique, lexicographically sorted Agent identities.
    pub agent_ids: Vec<BotId>,
}

/// Channel creation failure without database or input payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelAdministrationError {
    /// Any selected Agent is missing, inaccessible, deleted, or cross-tenant.
    #[error("channel_agent_not_visible")]
    NotVisible,
    /// Pool/query/transaction/random source failed.
    #[error("channel_administration_unavailable")]
    Unavailable,
    /// A stored row could not be decoded or violated a structural invariant.
    #[error("channel_administration_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
}

impl ChannelAdministrationError {
    /// Map to stable application semantics.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::NotVisible => AppError::NotVisible,
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "channel_administration",
            },
        }
    }
}

/// User-channel write port; implementation owns profile locks and the complete transaction.
#[async_trait]
pub trait ChannelAdministration: Send + Sync {
    /// Create channel, membership, links, and native thread atomically.
    async fn create_channel(
        &self,
        request: ChannelCreateRequest,
    ) -> Result<ChannelDetail, ChannelAdministrationError>;
}

/// Fail-closed channel write port until production PostgreSQL is injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoChannelAdministration;

#[async_trait]
impl ChannelAdministration for NoChannelAdministration {
    async fn create_channel(
        &self,
        _request: ChannelCreateRequest,
    ) -> Result<ChannelDetail, ChannelAdministrationError> {
        Err(ChannelAdministrationError::Unavailable)
    }
}

/// Current Agent-to-system reach hints. They influence routing only and confer no permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReachability {
    /// Candidate Agent.
    pub agent_id: BotId,
    /// Stable system/server names, sorted and unique.
    pub systems: Vec<String>,
}

/// Durable routing audit input; deliberately contains no user message or model prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingAuditRecord {
    /// Verified tenant used to re-read the candidate set at commit time.
    pub tenant: TenantId,
    /// Verified actor.
    pub actor: ActorId,
    /// Verified administrator role used by the same roster predicate.
    pub admin: bool,
    /// Full ordered visible roster snapshot used solely for commit-time conflict detection.
    pub roster: Vec<BotId>,
    /// Chosen Agent.
    pub chosen: BotId,
    /// Stable reason classification.
    pub reason: RoutingReasonCode,
    /// Whether deterministic fallback was used.
    pub fallback: bool,
    /// Whether the person explicitly selected the recipient.
    pub via_mention: bool,
    /// Ordered authoritative candidates considered.
    pub candidates: Vec<BotId>,
}

/// Routing backend failure. Completion/reach failures are soft; audit failure is hard in use case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelRoutingBackendError {
    /// The visible non-hidden roster no longer equals the set used for the decision.
    #[error("channel_routing_candidate_set_changed")]
    CandidateSetChanged,
    /// Provider/database/audit dependency unavailable.
    #[error("channel_routing_backend_unavailable")]
    Unavailable,
    /// Stored or provider projection was structurally invalid.
    #[error("channel_routing_backend_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
}

/// Model/reach/audit adapter for create-time routing; business decisions remain in application/domain.
#[async_trait]
pub trait ChannelRoutingBackend: Send + Sync {
    /// Complete the domain-built routing prompt through the deployment package model.
    async fn complete(&self, prompt: &str) -> Result<String, ChannelRoutingBackendError>;

    /// Resolve current reach hints in one bounded query.
    async fn reachable_systems(
        &self,
        agents: &[BotId],
    ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError>;

    /// Append one hash-chained routing event.
    async fn record_routing(
        &self,
        record: RoutingAuditRecord,
    ) -> Result<(), ChannelRoutingBackendError>;
}

/// Fail-closed routing backend. Completion falls back; audit prevents an unrecorded success.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoChannelRoutingBackend;

#[async_trait]
impl ChannelRoutingBackend for NoChannelRoutingBackend {
    async fn complete(&self, _prompt: &str) -> Result<String, ChannelRoutingBackendError> {
        Err(ChannelRoutingBackendError::Unavailable)
    }

    async fn reachable_systems(
        &self,
        agents: &[BotId],
    ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
        Ok(agents
            .iter()
            .cloned()
            .map(|agent_id| AgentReachability {
                agent_id,
                systems: Vec::new(),
            })
            .collect())
    }

    async fn record_routing(
        &self,
        _record: RoutingAuditRecord,
    ) -> Result<(), ChannelRoutingBackendError> {
        Err(ChannelRoutingBackendError::Unavailable)
    }
}

/// Authority already resolved for Agent roster reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReadScope {
    /// Verified tenant; package-backed profiles from another tenant are never roster candidates.
    pub tenant: TenantId,
    /// Verified actor.
    pub actor: ActorId,
    /// Whether current verified roles include administrator.
    pub admin: bool,
}

/// Fresh authority snapshot required by every Agent lifecycle write/probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAdministrationScope {
    /// Verified tenant scope.
    pub tenant: TenantId,
    /// Verified actor identity.
    pub actor: ActorId,
    /// Whether the verified role snapshot includes administrator.
    pub admin: bool,
    /// Session/user generation that PostgreSQL must revalidate before authority or network work.
    pub auth_generation: AuthGeneration,
}

impl AgentAdministrationScope {
    /// Borrow the read-policy projection without duplicating authority derivation.
    #[must_use]
    pub fn read_scope(&self) -> AgentReadScope {
        AgentReadScope {
            tenant: self.tenant.clone(),
            actor: self.actor.clone(),
            admin: self.admin,
        }
    }
}

/// Stable Agent lifecycle adapter failure without SQL, URL, credential, or remote body values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentAdministrationError {
    /// Missing, deleted, cross-tenant, or inaccessible Agent.
    #[error("agent_administration_not_visible")]
    NotVisible,
    /// Visible Agent is not manageable by the current actor.
    #[error("agent_administration_forbidden")]
    Forbidden,
    /// Package-backed Agent is immutable outside package sync.
    #[error("agent_administration_protected")]
    Protected,
    /// Canonical input or stored endpoint cannot be accepted.
    #[error("agent_administration_invalid field={field}")]
    InvalidInput {
        /// Static field only.
        field: &'static str,
    },
    /// PostgreSQL, Vault, audit chain, or safe transport is unavailable.
    #[error("agent_administration_unavailable")]
    Unavailable,
    /// Stored row/configuration/credential violates the closed schema.
    #[error("agent_administration_corrupt field={field}")]
    Corrupt {
        /// Static field only.
        field: &'static str,
    },
    /// Transaction outcome is not knowable and must be reconciled.
    #[error("agent_administration_commit_unknown")]
    CommitUnknown,
}

impl AgentAdministrationError {
    /// Map lifecycle errors into the stable application taxonomy.
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::NotVisible => AppError::NotVisible,
            Self::Forbidden | Self::Protected => AppError::ForbiddenRole {
                required: Role::User,
            },
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "agent_administration",
            },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
        }
    }
}

/// Agent create/edit/copy/preference/delete and pre-save remote connection probe port.
#[async_trait]
pub trait AgentAdministration: Send + Sync {
    /// Create one caller-owned profile; ID, owner, type, avatar and configuration are authoritative.
    async fn create_agent(
        &self,
        scope: &AgentAdministrationScope,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError>;

    /// Replace the editable profile fields and optionally rotate the write-only remote credential.
    async fn update_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError>;

    /// Copy presentation into a new private managed-slot profile; no credential or membership copies.
    async fn duplicate_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentProfile, AgentAdministrationError>;

    /// Set only the current actor's hidden preference.
    async fn set_agent_hidden(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
        hidden: bool,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError>;

    /// Soft-delete one manageable non-package Agent and retire its credentials.
    async fn delete_agent(
        &self,
        scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError>;

    /// Perform a bounded real AG-UI POST through the same SafeDialer used at runtime.
    async fn test_agent_connection(
        &self,
        scope: &AgentAdministrationScope,
        request: AgentConnectionTestRequest,
    ) -> Result<AgentConnectionVerdict, AgentAdministrationError>;
}

/// Fail-closed lifecycle default until production assembly injects PostgreSQL/Vault/SafeDialer.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAgentAdministration;

#[async_trait]
impl AgentAdministration for NoAgentAdministration {
    async fn create_agent(
        &self,
        _scope: &AgentAdministrationScope,
        _request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }

    async fn update_agent(
        &self,
        _scope: &AgentAdministrationScope,
        _agent_id: &BotId,
        _request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }

    async fn duplicate_agent(
        &self,
        _scope: &AgentAdministrationScope,
        _agent_id: &BotId,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }

    async fn set_agent_hidden(
        &self,
        _scope: &AgentAdministrationScope,
        _agent_id: &BotId,
        _hidden: bool,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }

    async fn delete_agent(
        &self,
        _scope: &AgentAdministrationScope,
        _agent_id: &BotId,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }

    async fn test_agent_connection(
        &self,
        _scope: &AgentAdministrationScope,
        _request: AgentConnectionTestRequest,
    ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
        Err(AgentAdministrationError::Unavailable)
    }
}

/// Current-schema Agent roster/detail read port.
#[async_trait]
pub trait AgentDirectory: Send + Sync {
    /// List either visible or per-user-hidden profiles after access filtering.
    async fn list_visible_agents(
        &self,
        scope: &AgentReadScope,
        hidden: bool,
    ) -> Result<Vec<AgentProfile>, PortError>;

    /// Read one accessible, non-deleted profile.
    async fn get_visible_agent(
        &self,
        scope: &AgentReadScope,
        agent_id: &BotId,
    ) -> Result<Option<AgentProfile>, PortError>;
}

/// Fail-closed Agent directory until a host injects production PostgreSQL.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAgentDirectory;

#[async_trait]
impl AgentDirectory for NoAgentDirectory {
    async fn list_visible_agents(
        &self,
        _scope: &AgentReadScope,
        _hidden: bool,
    ) -> Result<Vec<AgentProfile>, PortError> {
        Err(PortError::Unavailable {
            dependency: "agent_directory",
        })
    }

    async fn get_visible_agent(
        &self,
        _scope: &AgentReadScope,
        _agent_id: &BotId,
    ) -> Result<Option<AgentProfile>, PortError> {
        Err(PortError::Unavailable {
            dependency: "agent_directory",
        })
    }
}

/// Native thread 目录端口错误；不携带随机源或数据库的原始错误文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadDirectoryError {
    /// OS CSPRNG 或 PostgreSQL 当前不可用。
    #[error("thread_directory_unavailable")]
    Unavailable,
    /// 持久化行无法按封闭 schema 解码。
    #[error("thread_directory_corrupt field={field}")]
    Corrupt {
        /// 出问题的静态字段名，不含数据库原值。
        field: &'static str,
    },
    /// 只有事务读到现状后才能判定的输入错误（例如尝试以 foreign UUID 创建新 thread）。
    #[error("thread_input_invalid field={field}")]
    InvalidInput {
        /// 静态字段名。
        field: &'static str,
    },
    /// Thread/Bot/channel 对当前 actor 不可见；与不存在统一 404。
    #[error("thread_target_not_visible")]
    NotVisible,
    /// 另一个 owner/run 正占用 foreground slot 或 thread lease。
    #[error("thread_lease_conflict")]
    LeaseConflict,
    /// 同一个 run id 已绑定到不同请求内容。
    #[error("thread_request_conflict")]
    RequestConflict,
    /// PostgreSQL commit 返回前连接中断，不能猜提交是否发生。
    #[error("thread_commit_unknown")]
    CommitUnknown,
    /// 新 run 的 COMMIT 或既有 exact receipt 的 ROLLBACK 已 ACK，但超过原期限。
    #[error("thread_acknowledged_after_deadline")]
    AcknowledgedAfterDeadline,
    /// 已核同 durable receipt，但本次只读 replay 没有及时关闭证明。
    #[error("thread_replay_closure_unproven")]
    ReplayClosureUnproven,
}

impl ThreadDirectoryError {
    /// 映射为 §15.3 稳定语义；数据库/随机源细节只收敛到同一个 503。
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "thread_directory",
            },
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::NotVisible => AppError::NotVisible,
            Self::LeaseConflict => AppError::LeaseConflict { holder: None },
            Self::RequestConflict => AppError::RequestConflict { resource: "run" },
            Self::CommitUnknown | Self::AcknowledgedAfterDeadline | Self::ReplayClosureUnproven => {
                AppError::ReconciliationRequired { accepted: true }
            }
        }
    }
}

/// application 已把权威 scope 与封闭 command 合并后的事务请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginThreadRunRequest {
    /// Rust-resolved session generation, never accepted from the renderer.
    pub auth_generation: AuthGeneration,
    /// 权威 deployment。
    pub deployment: DeploymentId,
    /// 权威 tenant。
    pub tenant: TenantId,
    /// 权威 actor。
    pub actor: ActorId,
    /// 不含 scope/fencing/time/sequence 的调用输入。
    pub command: BeginThreadRun,
}

/// 原入口认证 scope 与 v2 选择输入；自由值不能替代当前数据库权限。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginThreadRunV2Request {
    /// 入口实际认证代次。
    pub auth_generation: AuthGeneration,
    /// 入口实际 deployment。
    pub deployment: DeploymentId,
    /// 入口实际 tenant。
    pub tenant: TenantId,
    /// 入口实际 actor。
    pub actor: ActorId,
    /// 必需 v2 意图与原消息输入。
    pub command: BeginThreadRunV2,
}

/// Ordered, non-wire input facts; the original begin transaction must recheck their authority.
///
/// Body text is deliberately excluded from Debug and serde implementations.
pub struct RunInputArtifactMaterial {
    /// Canonical UUIDv7 in the original reference order.
    pub artifact_id: String,
    /// Actual preread registry dataset.
    pub dataset_id: String,
    /// Actual full-object lowercase SHA-256.
    pub sha256: String,
    /// Actual observed media type.
    pub media_type: String,
    /// Actual full-object length, never a truncated body length.
    pub byte_length: u64,
    /// Original source Thread.
    pub source_thread_id: ThreadId,
    /// Original source Run.
    pub source_run_id: RunId,
    /// Complete verified UTF-8 text, or no body for a nontext reference.
    pub body: Option<String>,
}

/// Authoritative scope combined with one durable cancellation candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelThreadRunRequest {
    /// Authoritative deployment.
    pub deployment: DeploymentId,
    /// Authoritative tenant.
    pub tenant: TenantId,
    /// Authoritative actor; the port must also bind this to the run owner.
    pub actor: ActorId,
    /// Untrusted thread/run identities after application shape validation.
    pub command: CancelThreadRun,
}

/// 权威 scope 与 durable cursor 合并后的 thread event 订阅请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadEventSubscription {
    /// 权威 deployment。
    pub deployment: DeploymentId,
    /// 权威 tenant。
    pub tenant: TenantId,
    /// 权威 actor。
    pub actor: ActorId,
    /// 要订阅的 thread。
    pub thread: ThreadId,
    /// 最后一条已完整接收的 cursor；`None` 从第一条开始。
    pub after_event_sequence: Option<u64>,
}

/// Authority-scoped channel activity subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelActivitySubscription {
    /// Authoritative deployment.
    pub deployment: DeploymentId,
    /// Authoritative tenant.
    pub tenant: TenantId,
    /// Authoritative actor whose current memberships filter every notification.
    pub actor: ActorId,
}

/// 权威 scope 合并后的 thread history 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadHistoryRequest {
    /// 权威 deployment。
    pub deployment: DeploymentId,
    /// 权威 tenant。
    pub tenant: TenantId,
    /// 权威 actor。
    pub actor: ActorId,
    /// Thread。
    pub thread: ThreadId,
}

/// Authority-scoped atomic conversation snapshot request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadConversationRequest {
    /// Verified deployment.
    pub deployment: DeploymentId,
    /// Verified tenant.
    pub tenant: TenantId,
    /// Verified actor.
    pub actor: ActorId,
    /// Native thread.
    pub thread: ThreadId,
}

/// Unknown 原运行事实的只读请求；权限由 Application 从当前 AuthContext 注入。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReconciliationRequest {
    /// 当前可信部署。
    pub deployment: DeploymentId,
    /// 当前可信租户。
    pub tenant: TenantId,
    /// 当前可信用户，必须仍是原 run owner。
    pub actor: ActorId,
    /// 当前可信认证代次，由PG重核。
    pub auth_generation: AuthGeneration,
    /// 原 thread。
    pub thread: ThreadId,
    /// 原 run。
    pub run: openbot_contracts::ids::RunId,
    /// 已通过非负边界检查的分页位置。
    pub after: Option<openbot_contracts::reconciliation::RunReconciliationCursor>,
    /// 已通过1–100边界检查的页大小。
    pub limit: u32,
}

/// 正向回执与原运行事实共享当前权限和分页输入；各自的 port 决定只读投影。
pub type RunEffectReceiptsRequest = RunReconciliationRequest;

/// Native thread ID 铸造与 scope-aware 可见性查询。
///
/// 查询同时接收 deployment、tenant 与 actor，三者都来自权威 [`AuthContext`](openbot_contracts::auth::AuthContext)，
/// transport 没有自报 scope 的入口。`false` 必须合并“不存在、已删除、无 membership、scope
/// 不同”，防止状态接口枚举别人的 thread。
#[async_trait]
pub trait ThreadDirectory: Send + Sync {
    /// 以 OS CSPRNG 铸造当前 deployment 的 UUIDv8 thread ID。
    async fn mint_thread_id(
        &self,
        deployment: &DeploymentId,
    ) -> Result<ThreadId, ThreadDirectoryError>;

    /// 当前权威 scope 是否能产生这条 native thread。
    async fn thread_known(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        actor: &ActorId,
        thread: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError>;

    /// 在同一个 PostgreSQL transaction 中写 thread/membership/message/running run/started
    /// event/replay-safe outbox，并只在 commit 后返回 receipt。
    async fn begin_thread_run(
        &self,
        _request: BeginThreadRunRequest,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// 接受一次 v2 custom turn；未装配原 dataset factory 的实现保持关闭。
    async fn begin_thread_run_v2(
        &self,
        _request: BeginThreadRunV2Request,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// Observe only an exact original receipt, closing the read transaction on both hit and miss.
    async fn observe_begin_replay(
        &self,
        _request: BeginThreadRunRequest,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// Observe the original v2 receipt without calling either begin producer.
    async fn observe_begin_replay_v2(
        &self,
        _request: BeginThreadRunV2Request,
    ) -> Result<Option<ThreadRunStarted>, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// Admit ordered preread material only through an implementation of the original transaction.
    async fn begin_thread_run_with_artifacts(
        &self,
        request: BeginThreadRunRequest,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        if request.command.artifact_refs.is_empty() && materials.is_empty() {
            self.begin_thread_run(request).await
        } else {
            Err(ThreadDirectoryError::Unavailable)
        }
    }

    /// Keep v2 admission separate, with compatibility only when both reference inputs are empty.
    async fn begin_thread_run_with_artifacts_v2(
        &self,
        request: BeginThreadRunV2Request,
        materials: Vec<RunInputArtifactMaterial>,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        if request.command.artifact_refs.is_empty() && materials.is_empty() {
            self.begin_thread_run_v2(request).await
        } else {
            Err(ThreadDirectoryError::Unavailable)
        }
    }

    /// Persist a replay-safe internal cancellation request before signalling any local child.
    async fn cancel_thread_run(
        &self,
        _request: CancelThreadRunRequest,
    ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// 先建立 LISTEN，再从 durable cursor replay，之后每次唤醒继续补取。
    async fn subscribe_thread_events(
        &self,
        _request: ThreadEventSubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// Subscribe to committed channel activity, filtering every frame by current membership.
    async fn subscribe_channel_activity(
        &self,
        _request: ChannelActivitySubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// 读取完整 durable history；不存在/不可见/已删除统一成功空列表。
    async fn thread_history(
        &self,
        _request: ThreadHistoryRequest,
    ) -> Result<ThreadHistory, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// Read messages, current foreground run, and last event cursor from one database statement.
    async fn thread_conversation(
        &self,
        _request: ThreadConversationRequest,
    ) -> Result<openbot_contracts::command::ThreadConversationSnapshot, ThreadDirectoryError> {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// 一条PG快照读取Unknown事实，当前权限每页重核；不改变占用或审计。
    async fn run_reconciliation(
        &self,
        _request: RunReconciliationRequest,
    ) -> Result<openbot_contracts::reconciliation::RunReconciliationSnapshot, ThreadDirectoryError>
    {
        Err(ThreadDirectoryError::Unavailable)
    }

    /// 同一PG statement核当前权限、全部原绑定和有界正向回执，不解锁Unknown。
    async fn run_effect_receipts(
        &self,
        _request: RunEffectReceiptsRequest,
    ) -> Result<openbot_contracts::reconciliation::RunEffectReceiptsSnapshot, ThreadDirectoryError>
    {
        Err(ThreadDirectoryError::Unavailable)
    }
}

/// 未注入 native thread 适配器时 fail-closed；不回退到 Intelligence。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoThreadDirectory;

#[async_trait]
impl ThreadDirectory for NoThreadDirectory {
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
}

/// Explicit memory application port 错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MemoryAdministrationError {
    /// PostgreSQL/随机源不可用。
    #[error("memory_administration_unavailable")]
    Unavailable,
    /// 持久化状态损坏。
    #[error("memory_administration_corrupt field={field}")]
    Corrupt {
        /// 静态字段名。
        field: &'static str,
    },
    /// 当前 actor 不可见该 memory/source/scope target。
    #[error("memory_not_visible")]
    NotVisible,
    /// 事务内才能判定的坏输入。
    #[error("memory_input_invalid field={field}")]
    InvalidInput {
        /// 静态字段名。
        field: &'static str,
    },
    /// 非 active correction 或 cursor/id binding 冲突。
    #[error("memory_request_conflict")]
    Conflict,
    /// Commit 结果未知。
    #[error("memory_commit_unknown")]
    CommitUnknown,
    /// Actor disabled runtime writes through the authoritative memory control.
    #[error("memory_writes_disabled")]
    WritesDisabled,
}

impl MemoryAdministrationError {
    /// 稳定 AppError 投影。
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "memory_store",
            },
            Self::NotVisible => AppError::NotVisible,
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::Conflict => AppError::RequestConflict { resource: "memory" },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: true },
            Self::WritesDisabled => AppError::PolicyRefused {
                rule: "memory_writes_disabled".to_owned(),
                decision: None,
            },
        }
    }
}

/// Authoritative scope for reading one actor's memory control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryControlRequest {
    /// Rust-resolved generation, rechecked while holding the actor through the transaction.
    pub auth_generation: AuthGeneration,
    /// Tenant matching the memory data plane.
    pub tenant: TenantId,
    /// Current actor/owner.
    pub actor: ActorId,
}

/// Authoritative scope plus one closed memory-control update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateMemoryControlRequest {
    /// Rust-resolved generation; never a renderer field.
    pub auth_generation: AuthGeneration,
    /// Tenant matching the memory data plane.
    pub tenant: TenantId,
    /// Current actor/owner.
    pub actor: ActorId,
    /// Closed renderer input with no identity fields.
    pub update: UpdateMemoryControl,
}

/// GUI remember 的权威 scope 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberMemoryRequest {
    /// Deployment resolved from the authenticated host, never accepted from memory input.
    pub deployment: DeploymentId,
    /// Rust-resolved generation; checked before any memory mutation.
    pub auth_generation: AuthGeneration,
    /// Tenant。
    pub tenant: TenantId,
    /// Owner/created_by。
    pub actor: ActorId,
    /// 无 owner/origin 字段的 wire input。
    pub input: RememberMemory,
}

/// Memory list keyset 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryPageRequest {
    /// Rust-resolved generation; checked before cursor or content reads.
    pub auth_generation: AuthGeneration,
    /// Tenant。
    pub tenant: TenantId,
    /// Owner。
    pub actor: ActorId,
    /// Opaque memory-id cursor。
    pub cursor: Option<String>,
    /// Application 已钳制。
    pub limit: u32,
}

/// Correct 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectMemoryRequest {
    /// Current deployment; only retention scope is revalidated, not an old source permission.
    pub deployment: DeploymentId,
    /// Rust-resolved generation; checked before locking the old memory.
    pub auth_generation: AuthGeneration,
    /// Tenant。
    pub tenant: TenantId,
    /// Owner/created_by。
    pub actor: ActorId,
    /// 旧 memory id。
    pub memory_id: String,
    /// 新内容。
    pub correction: CorrectMemory,
}

/// Forbid/delete 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutateMemoryRequest {
    /// Rust-resolved generation; checked before erase/event writes.
    pub auth_generation: AuthGeneration,
    /// Tenant。
    pub tenant: TenantId,
    /// Owner/actor。
    pub actor: ActorId,
    /// Memory id。
    pub memory_id: String,
    /// Mutation。
    pub mutation: MemoryMutation,
}

/// Scope-aware recall 请求。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallMemoriesRequest {
    /// Rust-resolved generation, rechecked inside the recall transaction; never a wire field.
    pub auth_generation: AuthGeneration,
    /// Authoritative deployment for an explicitly selected thread context.
    pub deployment: DeploymentId,
    /// Tenant。
    pub tenant: TenantId,
    /// Owner。
    pub actor: ActorId,
    /// 无 owner 的 wire input。
    pub input: RecallMemories,
}

/// Explicit memory 的唯一 GUI application port；remember tool 必须经工具管线另接。
#[async_trait]
pub trait MemoryAdministration: Send + Sync {
    /// Read the actor's runtime memory write control; absent rows default enabled.
    async fn memory_control(
        &self,
        request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError>;
    /// Persist the actor's runtime memory write control.
    async fn update_memory_control(
        &self,
        request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError>;
    /// Create origin=user_action。
    async fn remember(
        &self,
        request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError>;
    /// List all statuses；deleted/forbidden content 为 None。
    async fn list_memories(
        &self,
        request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError>;
    /// Correct + supersede 同事务。
    async fn correct(
        &self,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError>;
    /// Forbid/delete + content erase + event 同事务。
    async fn mutate(
        &self,
        request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError>;
    /// User + exact Bot/thread scope FTS recall。
    async fn recall(
        &self,
        request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError>;
}

/// 未注入 memory store 时 fail-closed。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMemoryAdministration;

#[async_trait]
impl MemoryAdministration for NoMemoryAdministration {
    async fn memory_control(
        &self,
        _request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn update_memory_control(
        &self,
        _request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn remember(
        &self,
        _request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn list_memories(
        &self,
        _request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn correct(
        &self,
        _request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn mutate(
        &self,
        _request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }

    async fn recall(
        &self,
        _request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError> {
        Err(MemoryAdministrationError::Unavailable)
    }
}

/// 管理员审计页的 typed 查询；自由 SQL/列名无法穿越此边界。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPageRequest {
    /// keyset cursor。
    pub cursor: Option<String>,
    /// 零个、一个或多个 event type。
    pub event_types: Vec<String>,
    /// actor 过滤。
    pub actor_user_id: Option<ActorId>,
    /// target type 过滤。
    pub target_type: Option<String>,
    /// target id 过滤。
    pub target_id: Option<String>,
    /// created_at 开区间下界。
    pub from: Option<OffsetDateTime>,
    /// created_at 开区间上界。
    pub to: Option<OffsetDateTime>,
    /// application 已钳制到 1..=100。
    pub limit: u32,
}

/// 审计读端口错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditReadError {
    /// PostgreSQL 不可用。
    #[error("audit_reader_unavailable")]
    Unavailable,
    /// 持久化行违反 schema/domain 边界。
    #[error("audit_reader_corrupt field={field}")]
    Corrupt {
        /// 静态字段名，不带数据库原值。
        field: &'static str,
    },
    /// opaque cursor 无法验证。
    #[error("audit_cursor_invalid")]
    InvalidCursor,
}

impl AuditReadError {
    /// 映射为稳定 application 错误。
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "database",
            },
            Self::InvalidCursor => AppError::MalformedPayload { field: "cursor" },
        }
    }
}

/// 管理员 audit keyset 读端口。
#[async_trait]
pub trait AuditReader: Send + Sync {
    /// 读取一页已脱敏事件。
    async fn list_audit_events(
        &self,
        request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError>;
}

/// 未注入 audit reader 时 fail-closed 503。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAuditReader;

#[async_trait]
impl AuditReader for NoAuditReader {
    async fn list_audit_events(
        &self,
        _request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError> {
        Err(AuditReadError::Unavailable)
    }
}

/// Action policy 持久化/热缓存端口错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyAdministrationError {
    /// 数据库或 listener 依赖不可用。
    #[error("policy_administration_unavailable")]
    Unavailable,
    /// 持久化状态违反 current-row/schema 约束。
    #[error("policy_administration_corrupt")]
    Corrupt,
}

impl PolicyAdministrationError {
    /// 稳定 application 映射。
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        AppError::DependencyUnavailable {
            dependency: "policy_store",
        }
    }
}

/// Deployment-wide action policy 管理端口。
#[async_trait]
pub trait PolicyAdministration: Send + Sync {
    /// 当前 raw policy；`None` = 未配置/default-deny。
    async fn current_policy(&self) -> Result<Option<ActionPolicy>, PolicyAdministrationError>;

    /// 持久化后更新预编译热缓存；`updated_by` 必须来自权威 `AuthContext`。
    async fn set_policy(
        &self,
        updated_by: &ActorId,
        policy: ActionPolicy,
    ) -> Result<(), PolicyAdministrationError>;
}

/// 未注入 policy store 时 fail-closed 503。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPolicyAdministration;

#[async_trait]
impl PolicyAdministration for NoPolicyAdministration {
    async fn current_policy(&self) -> Result<Option<ActionPolicy>, PolicyAdministrationError> {
        Err(PolicyAdministrationError::Unavailable)
    }

    async fn set_policy(
        &self,
        _updated_by: &ActorId,
        _policy: ActionPolicy,
    ) -> Result<(), PolicyAdministrationError> {
        Err(PolicyAdministrationError::Unavailable)
    }
}

/// people 页端口的 keyset 请求；字段均由 typed command 投影，不含自由 SQL。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeoplePageRequest {
    /// email/name 子串；`None` = 不搜索。
    pub search: Option<String>,
    /// opaque cursor。
    pub cursor: Option<String>,
    /// 已由 application 钳制到 1..=200。
    pub limit: u32,
}

/// people role/access 原子端口错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeoplePortError {
    /// 数据库/审计依赖不可用。
    #[error("people_port_unavailable")]
    Unavailable,
    /// 权威数据损坏。
    #[error("people_port_corrupt field={field}")]
    Corrupt {
        /// 静态字段名。
        field: &'static str,
    },
    /// subject 不存在；对外统一 404 防枚举。
    #[error("people_not_found")]
    NotFound,
    /// domain floor/self/last-admin 拒绝。
    #[error("people_identity_conflict reason={reason}")]
    IdentityConflict {
        /// 稳定拒绝原因。
        reason: IdentityConflictReason,
    },
}

/// 人员移除后，退役其仍由部署持有的个人凭据时可能出现的端口失败。
///
/// 这一步刻意发生在 deny/session/generation 的 people 事务提交之后：凭据库或审计链故障
/// 不能把已经生效的人员移除回滚掉。错误只说明依赖状态，不携带凭据、数据库原值或远端文案。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OwnedCredentialRetirementError {
    /// 凭据持久化或审计依赖当前不可用。
    #[error("owned_credential_retirement_unavailable")]
    Unavailable,
    /// 持久化状态不满足封闭不变量。
    #[error("owned_credential_retirement_corrupt field={field}")]
    Corrupt {
        /// 出问题的静态字段名，不含字段值。
        field: &'static str,
    },
}

/// 人员移除后的个人凭据退役端口。
///
/// `owner` 与 `retired_by` 都来自权威 Rust 身份；transport 不得把请求体里的同名字段传进来。
/// 实现必须按 vault owner 事实查找，不能只沿已可能被 `ON DELETE CASCADE` 删除的连接表查找，
/// 否则用户行消失后会留下不可见但仍可用的孤儿 refresh token。
#[async_trait]
pub trait OwnedCredentialRetirer: Send + Sync {
    /// 退役 `owner` 的全部个人凭据；重复调用与空 owner 都返回 `0`。
    async fn retire_owned_credentials(
        &self,
        owner: &ActorId,
        retired_by: &ActorId,
    ) -> Result<u64, OwnedCredentialRetirementError>;
}

impl PeoplePortError {
    /// 映射 §15.3 AppError。
    #[must_use]
    pub const fn into_app_error(self) -> AppError {
        match self {
            Self::Unavailable | Self::Corrupt { .. } => AppError::DependencyUnavailable {
                dependency: "database",
            },
            Self::NotFound => AppError::NotVisible,
            Self::IdentityConflict { reason } => AppError::IdentityConflict { reason },
        }
    }
}

/// people/auth application 端口。
///
/// role/access 方法必须在实现侧同一事务读取 subject、其他有效 admin 与 auth generation，调用
/// domain 判定，写角色/deny/session/generation，并追加 audit；拆成多个端口调用会产生竞态。
#[async_trait]
pub trait PeopleAdministration: Send + Sync {
    /// 当前 actor 的公开 `/api/me` 投影。
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError>;

    /// 管理员 people 页。
    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError>;

    /// 原子角色变更。
    async fn change_role(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        desired: Role,
    ) -> Result<Person, PeoplePortError>;

    /// 原子访问移除/恢复。
    async fn change_access(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        revoked: bool,
    ) -> Result<Person, PeoplePortError>;
}

/// 未注入 people 适配器时的构造性 503，供现有 G1 宿主平滑升级。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPeopleAdministration;

#[async_trait]
impl PeopleAdministration for NoPeopleAdministration {
    async fn current_user(&self, _actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        Err(PeoplePortError::Unavailable)
    }

    async fn list_people(
        &self,
        _request: PeoplePageRequest,
    ) -> Result<PeoplePage, PeoplePortError> {
        Err(PeoplePortError::Unavailable)
    }

    async fn change_role(
        &self,
        _actor: &ActorId,
        _subject: &ActorId,
        _desired: Role,
    ) -> Result<Person, PeoplePortError> {
        Err(PeoplePortError::Unavailable)
    }

    async fn change_access(
        &self,
        _actor: &ActorId,
        _subject: &ActorId,
        _revoked: bool,
    ) -> Result<Person, PeoplePortError> {
        Err(PeoplePortError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::error::{AuditKind, ErrorCode};

    #[test]
    fn both_port_failures_map_to_dependency_unavailable_503() {
        let unavailable = PortError::Unavailable {
            dependency: "database",
        }
        .into_app_error();
        assert_eq!(unavailable.code(), ErrorCode::DEPENDENCY_UNAVAILABLE);
        assert_eq!(unavailable.http_status(), 503);
        assert_eq!(unavailable.audit_kind(), AuditKind::DependencyFailure);

        let corrupt = PortError::Corrupt {
            dependency: "database",
            field: "last_message_at",
        }
        .into_app_error();
        assert_eq!(corrupt.code(), ErrorCode::DEPENDENCY_UNAVAILABLE);
        assert_eq!(corrupt.http_status(), 503);
        assert_eq!(corrupt.audit_kind(), AuditKind::DependencyFailure);
    }

    /// 负向对照：损坏的行**不会**被映射成「调用方的锅」。
    ///
    /// 正向对照在同一条里 —— 400 这个码确实存在且能被别的路径产出（游标解析），
    /// 所以本断言不是在「没有 400 这个东西」的世界里成立的。
    #[test]
    fn corrupt_row_is_never_blamed_on_the_caller() {
        let corrupt = PortError::Corrupt {
            dependency: "database",
            field: "role",
        }
        .into_app_error();
        assert_ne!(corrupt.code(), ErrorCode::MALFORMED_PAYLOAD);
        assert_ne!(corrupt.http_status(), 400);

        let caller_fault = crate::cursor::ChannelCursor::decode("!!!").unwrap_err();
        assert_eq!(caller_fault.code(), ErrorCode::MALFORMED_PAYLOAD);
        assert_eq!(caller_fault.http_status(), 400);
    }

    /// 依赖名原样穿过映射，不被改写 —— 运维靠它区分是数据库还是别的依赖。
    #[test]
    fn dependency_name_survives_the_mapping() {
        let err = PortError::Unavailable {
            dependency: "browser_engine",
        }
        .into_app_error();
        assert_eq!(
            err,
            AppError::DependencyUnavailable {
                dependency: "browser_engine"
            }
        );
    }
}
