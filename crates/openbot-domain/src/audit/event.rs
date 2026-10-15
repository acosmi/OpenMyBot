//! 审计事件的领域类型，以及事件类型的封闭目录。
//!
//! # 与上游表的对应关系
//!
//! `audit_events`（上游 `server/src/db/schema/core.ts::auditEvents`，本仓类型化行在
//! `openbot-infra::db::tables::audit_events`）有七列：`id` / `actor_user_id` /
//! `event_type` / `target_type` / `target_id` / `payload` / `created_at`。
//! [`AuditEvent`] 是它们的领域投影，一一对应，**不多不少**：
//!
//! | 列 | 领域字段 | 说明 |
//! | --- | --- | --- |
//! | `id` | [`AuditEvent::id`] | `AuditEventId`，不校验 UUID（§5.3） |
//! | `actor_user_id` | [`AuditEvent::actor`] | 可空。系统自身产生的事件没有 actor |
//! | `event_type` | [`AuditEvent::event_type`] | 封闭目录，见 [`AuditEventType`] |
//! | `target_type` | [`AuditEvent::target_kind`] | 封闭词汇（`AuditLabel`） |
//! | `target_id` | [`AuditEvent::target_id`] | 可空 |
//! | `payload` | [`AuditEvent::payload`] | 字段 allowlist，见 [`super::payload`] |
//! | `created_at` | [`AuditEvent::created_at`] | **由调用方传入**，领域层没有时钟 |
//!
//! §8.6 明说表语义保持上游、不重建，所以这里不新增列、不改列义；hash chain 的两列是
//! **追加的 nullable 列**，落在 [`super::chain`]，与本类型分开表达 —— 因为一条事件在被
//! 写进链之前就已经是一条完整的事件（旧行 hash 为 NULL，正是这个形态）。
//!
//! # `created_at` 为什么是入参
//!
//! repository contract §4 与 v3 §5.1：领域层没有时钟。这不是洁癖 —— 审计行的时间戳决定 retention
//! 窗口判定与 hash chain 的内容，一旦领域层自己去读墙钟，同一条事件在重放时就会得到不同的
//! `row_hash`，"确定性重放"（§20.1）当场失效。

use core::fmt;

use openbot_contracts::ids::{ActorId, AuditEventId};
use time::OffsetDateTime;

use super::hash::CanonicalWriter;
use super::payload::{AuditIdentifier, AuditLabel, AuditPayload};

/// 审计事件类型。
///
/// # 为什么是"newtype + 封闭目录"而不是 60 个变体的 enum
///
/// 上游 `server/src/audit.ts::auditEventTypes` 是一个 `as const` 字符串数组，**57 项**
/// （复算：`sed -n '/^export const auditEventTypes = \[/,/^\] as const;/p' server/src/audit.ts
/// | grep -cE '^\s+"'`，在 commit `891df72f1827454d8b353d108fe5dd2313b7e30d` 上得 57）。
/// 这些字面量是**跨系统契约**：它们进数据库、进管理页的筛选下拉、进上游既有数据。把它们
/// 搬成 57 个 Rust 变体会得到一张两侧都要人工维护的映射表，而映射表漂了没有任何东西会红。
/// 本项目新增的 deadline、explicit-memory tool 三事件与 MCP stale-grant suspension 单列在
/// 相邻项后，并在 parity/events 标为新增；它们不冒充上游目录成员。
///
/// 所以取值集合直接由 [`AUDIT_EVENT_TYPES`] 承载，类型本身只保证**封闭性**：
/// [`AuditEventType::parse`] 只接受目录里的字面量，没有从任意 `String` 构造的入口。
/// 于是"事件类型是有限集合"是构造性事实，而"集合的内容"是一份可以被一条命令复算的台账。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditEventType(&'static str);

impl AuditEventType {
    /// A new encrypted credential row became authoritative.
    pub const CREDENTIAL_CREATED: Self = Self("credential.created");
    /// One encrypted credential replaced another without exposing either value.
    pub const CREDENTIAL_ROTATED: Self = Self("credential.rotated");
    /// An encrypted credential was locally retired.
    pub const CREDENTIAL_REVOKED: Self = Self("credential.revoked");
    /// Caller-owned Agent profile was created.
    pub const BOT_CREATED: Self = Self("bot.created");
    /// Manageable Agent profile/configuration was updated.
    pub const BOT_UPDATED: Self = Self("bot.updated");
    /// A visible Agent's presentation was copied into a new private managed Agent.
    pub const BOT_DUPLICATED: Self = Self("bot.duplicated");
    /// Current actor hid one visible Agent.
    pub const BOT_HIDDEN: Self = Self("bot.hidden");
    /// Current actor restored one hidden Agent.
    pub const BOT_UNHIDDEN: Self = Self("bot.unhidden");
    /// Manageable Agent was soft-deleted and its credentials retired.
    pub const BOT_DELETED: Self = Self("bot.deleted");
    /// A create-time channel recipient was explicitly chosen or inferred.
    pub const CHANNEL_ROUTED: Self = Self("channel.routed");
    /// Built-in/remote Agent run 已 durable activate。
    pub const AGENT_INVOKED: Self = Self("agent.invoked");
    /// Provider/remote Agent 真实 body read gap 超时。
    pub const AGENT_STREAM_STALLED: Self = Self("agent.stream_stalled");
    /// 新增 absolute run deadline 到点且 child 已停止。
    pub const AGENT_RUN_DEADLINE_EXCEEDED: Self = Self("agent.run_deadline_exceeded");
    /// Actor-scoped run cost budget refused before or after a provider sampling.
    pub const AGENT_RUN_COST_BUDGET_REFUSED: Self = Self("agent.run_cost_budget_refused");
    /// A remote AG-UI interrupt batch became durable before the run waited for a person.
    pub const AGENT_REMOTE_INTERRUPT_REQUESTED: Self = Self("agent.remote_interrupt_requested");
    /// The current actor resolved one durable remote AG-UI interrupt.
    pub const AGENT_REMOTE_INTERRUPT_RESOLVED: Self = Self("agent.remote_interrupt_resolved");
    /// The current actor cancelled one durable remote AG-UI interrupt.
    pub const AGENT_REMOTE_INTERRUPT_CANCELLED: Self = Self("agent.remote_interrupt_cancelled");
    /// The local bounded wait expired one remote AG-UI interrupt.
    pub const AGENT_REMOTE_INTERRUPT_EXPIRED: Self = Self("agent.remote_interrupt_expired");
    /// Explicit remember tool was refused before execution.
    pub const MEMORY_REMEMBER_REFUSED: Self = Self("memory.remember_refused");
    /// Explicit remember tool committed a memory record.
    pub const MEMORY_REMEMBER_SUCCEEDED: Self = Self("memory.remember_succeeded");
    /// A remember business mutation and its immutable receipt committed together.
    pub const MEMORY_EFFECT_COMMITTED: Self = Self("memory.effect_committed");
    /// One artifact registration and its content-free receipt committed together.
    pub const ARTIFACT_SAVED: Self = Self("artifact.saved");
    /// The current original saved owner durably armed one cleanup intent.
    pub const ARTIFACT_CLEANUP_ARMED: Self = Self("artifact.cleanup_armed");
    /// The original armed pair and its one quota refund committed together.
    pub const ARTIFACT_CLEANUP_COMPLETED: Self = Self("artifact.cleanup_completed");
    /// Explicit remember tool finished with a definite non-success outcome.
    pub const MEMORY_REMEMBER_FAILED: Self = Self("memory.remember_failed");
    /// Human proof-of-intent request became durable.
    pub const TOOL_APPROVAL_REQUESTED: Self = Self("tool.approval_requested");
    /// Human granted the exact stored binding.
    pub const TOOL_APPROVAL_GRANTED: Self = Self("tool.approval_granted");
    /// Human denied the request.
    pub const TOOL_APPROVAL_DENIED: Self = Self("tool.approval_denied");
    /// Pending request expired before a decision.
    pub const TOOL_APPROVAL_EXPIRED: Self = Self("tool.approval_expired");
    /// Run/scope cancellation retired a pending request.
    pub const TOOL_APPROVAL_CANCELLED: Self = Self("tool.approval_cancelled");
    /// A compiled decision component began waiting for its actor.
    pub const COMPONENT_HUMAN_REQUESTED: Self = Self("component.human_requested");
    /// The actor answered one durable compiled decision.
    pub const COMPONENT_HUMAN_ANSWERED: Self = Self("component.human_answered");
    /// A durable compiled decision reached its wait bound.
    pub const COMPONENT_HUMAN_EXPIRED: Self = Self("component.human_expired");
    /// Run/scope invalidation retired a durable compiled decision.
    pub const COMPONENT_HUMAN_CANCELLED: Self = Self("component.human_cancelled");
    /// Bot 在其 computer 上执行的动作被放行。
    pub const COMPUTER_ACTION_ALLOWED: Self = Self("computer.action_allowed");
    /// Bot 在其 computer 上执行的动作被策略拒绝。
    pub const COMPUTER_ACTION_REFUSED: Self = Self("computer.action_refused");
    /// 放行并尝试过，但没有成功。与 `allowed` 分开，因为"allowed"读起来像"发生了"。
    pub const COMPUTER_ACTION_FAILED: Self = Self("computer.action_failed");
    /// Bot 请求人接管。
    pub const COMPUTER_HELP_REQUESTED: Self = Self("computer.help_requested");
    /// 人已接管。
    pub const COMPUTER_CONTROL_TAKEN: Self = Self("computer.control_taken");
    /// 人已交还。
    pub const COMPUTER_CONTROL_RELEASED: Self = Self("computer.control_released");
    /// 向人索要一条凭据。
    pub const COMPUTER_SECRET_REQUESTED: Self = Self("computer.secret_requested");
    /// 人填入了一条凭据（记 id / 用途 / 目标字段 / 长度，不记值）。
    pub const COMPUTER_SECRET_SUPPLIED: Self = Self("computer.secret_supplied");
    /// MCP 调用被本部署拒绝。
    pub const MCP_CALL_REJECTED: Self = Self("mcp.call_rejected");
    /// MCP 调用被放行且 vendor 完成。
    pub const MCP_CALL_SUCCEEDED: Self = Self("mcp.call_succeeded");
    /// MCP 调用被放行但 vendor 没完成。
    pub const MCP_CALL_FAILED: Self = Self("mcp.call_failed");
    /// Catalog refresh suspended a stale/missing/changed MCP grant.
    pub const MCP_TOOL_SUSPENDED_MISSING: Self = Self("mcp.tool_suspended_missing");

    /// An initial gateway authorization attempt was committed with its original audit.
    pub const GATEWAY_AUTHORIZATION_ATTEMPT_CREATED: Self =
        Self("gateway_authorization_attempt_created");
    /// The original created attempt was admitted for registration; this is no send receipt.
    pub const GATEWAY_AUTHORIZATION_REGISTRATION_ADMITTED: Self =
        Self("gateway_authorization_registration_admitted");
    /// A live original owner closed its attempt within the saved caller and flow budgets.
    pub const GATEWAY_AUTHORIZATION_ATTEMPT_CLOSED: Self =
        Self("gateway_authorization_attempt_closed");
    /// The original registration reply was committed and read back before handoff.
    pub const GATEWAY_AUTHORIZATION_REGISTERED: Self = Self("gateway_authorization_registered");
    /// The original code admission was committed with its original typed audit.
    pub const GATEWAY_AUTHORIZATION_CODE_ADMITTED: Self =
        Self("gateway_authorization_code_admitted");
    /// History clearing and its durable completion committed in the original transaction.
    pub const THREAD_HISTORY_CLEAR_COMPLETED: Self = Self("thread_history.clear_completed");

    /// 从字符串解析。**只接受 [`AUDIT_EVENT_TYPES`] 里的字面量。**
    ///
    /// 返回 `Option` 而不是"不认识就原样收下"：一个拼错的事件类型会让所有按类型筛选的
    /// 查询悄悄漏掉这条记录，而写入侧不会有任何征兆。
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        AUDIT_EVENT_TYPES
            .iter()
            .find(|candidate| candidate.0 == value)
            .copied()
    }

    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// 事件类型全集：上游 57 项 + 本项目新增 deadline/budget/memory/catalog/approval/component/interrupt/artifact/gateway/history 30 项。
///
/// 顺序也照抄上游，方便逐行对拍。
pub const AUDIT_EVENT_TYPES: &[AuditEventType] = &[
    AuditEventType("configuration.changed"),
    AuditEventType("credential.created"),
    AuditEventType("credential.rotated"),
    AuditEventType("credential.revoked"),
    AuditEventType("connector.sync_succeeded"),
    AuditEventType("connector.sync_failed"),
    AuditEventType("knowledge.searched"),
    AuditEventType("channel.routed"),
    AuditEventType("agent.invoked"),
    AuditEventType("agent.stream_stalled"),
    AuditEventType("agent.run_deadline_exceeded"),
    AuditEventType("agent.run_cost_budget_refused"),
    AuditEventType("agent.remote_interrupt_requested"),
    AuditEventType("agent.remote_interrupt_resolved"),
    AuditEventType("agent.remote_interrupt_cancelled"),
    AuditEventType("agent.remote_interrupt_expired"),
    AuditEventType("memory.remember_refused"),
    AuditEventType("memory.remember_succeeded"),
    AuditEventType("memory.effect_committed"),
    AuditEventType("artifact.saved"),
    AuditEventType("artifact.cleanup_armed"),
    AuditEventType("artifact.cleanup_completed"),
    AuditEventType("memory.remember_failed"),
    AuditEventType("tool.approval_requested"),
    AuditEventType("tool.approval_granted"),
    AuditEventType("tool.approval_denied"),
    AuditEventType("tool.approval_expired"),
    AuditEventType("tool.approval_cancelled"),
    AuditEventType("mcp.call_succeeded"),
    AuditEventType("mcp.call_rejected"),
    AuditEventType("mcp.call_failed"),
    AuditEventType("mcp.callback_refused"),
    AuditEventType("mcp.oauth_client_registered"),
    AuditEventType("mcp.account_connected"),
    AuditEventType("mcp.token_refreshed"),
    AuditEventType("mcp.account_disconnected"),
    AuditEventType("mcp.tool_suspended_missing"),
    AuditEventType("computer.action_allowed"),
    AuditEventType("computer.action_refused"),
    AuditEventType("computer.action_failed"),
    AuditEventType("computer.help_requested"),
    AuditEventType("computer.control_taken"),
    AuditEventType("computer.control_released"),
    AuditEventType("computer.secret_requested"),
    AuditEventType("computer.secret_supplied"),
    AuditEventType("computer.stopped"),
    AuditEventType("computer.reset"),
    AuditEventType("computer.policy_loaded"),
    AuditEventType("computer.isolation_loaded"),
    AuditEventType("bot.declined"),
    AuditEventType("component.granted"),
    AuditEventType("component.revoked"),
    AuditEventType("component.published"),
    AuditEventType("component.unpublished"),
    AuditEventType("component.draft_saved"),
    AuditEventType("component.refused"),
    AuditEventType("component.function_granted"),
    AuditEventType("component.function_revoked"),
    AuditEventType("component.function_called"),
    AuditEventType("component.function_refused"),
    AuditEventType("component.function_failed"),
    AuditEventType("component.human_requested"),
    AuditEventType("component.human_answered"),
    AuditEventType("component.human_expired"),
    AuditEventType("component.human_cancelled"),
    AuditEventType("person.role_changed"),
    AuditEventType("person.access_revoked"),
    AuditEventType("person.access_restored"),
    AuditEventType("session.signed_in"),
    AuditEventType("session.refused"),
    AuditEventType("person.admin_by_configuration"),
    AuditEventType("identity_provider.registered"),
    AuditEventType("identity_provider.removed"),
    AuditEventType("bot.created"),
    AuditEventType("bot.updated"),
    AuditEventType("bot.duplicated"),
    AuditEventType("bot.hidden"),
    AuditEventType("bot.unhidden"),
    AuditEventType("bot.deleted"),
    AuditEventType("bot.callback_token_issued"),
    AuditEventType("bot.callback_token_revoked"),
    AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CREATED,
    AuditEventType::GATEWAY_AUTHORIZATION_REGISTRATION_ADMITTED,
    AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CLOSED,
    AuditEventType::GATEWAY_AUTHORIZATION_REGISTERED,
    AuditEventType::GATEWAY_AUTHORIZATION_CODE_ADMITTED,
    AuditEventType::THREAD_HISTORY_CLEAR_COMPLETED,
];

/// 一条审计事件。
///
/// 字段全部公开：本类型是一条已经发生的事实的**记录**，没有需要用构造函数维护的跨字段
/// 不变量 —— 有不变量的是 payload（allowlist）与链（[`super::chain`]），两者各自成型。
/// 刻意不实现 `Default`：一条没有事件类型、没有时间戳的审计事件不是"默认值"，是缺陷。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// 事件 id，对应 `audit_events.id`。
    pub id: AuditEventId,
    /// 行动者，对应 `actor_user_id`。
    ///
    /// `None` 是合法值且**含义明确**：这条事件不是任何人发起的（boot 时记录的
    /// `computer.policy_loaded`、retention sweep 等）。上游注释还给了另一条理由 ——
    /// 认证尚未通过的调用只能记"发生了一次尝试"，把未经证实的身份写进审计表，等于在
    /// 唯一应当被相信的地方记录一个未经证实的断言。
    pub actor: Option<ActorId>,
    /// 事件类型，对应 `event_type`。
    pub event_type: AuditEventType,
    /// 目标类别，对应 `target_type`。
    pub target_kind: AuditLabel,
    /// 目标标识，对应 `target_id`。
    pub target_id: Option<AuditIdentifier>,
    /// 事实集合，对应 `payload`。
    pub payload: AuditPayload,
    /// 写入时刻，对应 `created_at`。**由调用方传入**，理由见模块文档。
    pub created_at: OffsetDateTime,
}

impl AuditEvent {
    /// 把事件写进规范编码。
    ///
    /// 字段顺序 = 上游列序（`pg_attribute.attnum`）。选它而不是别的顺序没有技术上的必要，
    /// 但它让"这份编码覆盖了表的哪些列"可以被一眼核对 —— 少写一列就是给篡改留一个不进
    /// 摘要的字段，而那种缺陷从代码上看不出来。
    ///
    /// 时间戳编码成 **Unix 纳秒（`i128`）**而不是 RFC 3339 文本，两条理由：
    ///
    /// 1. 文本有多种等价写法（`+00:00` / `Z`、小数位数、`T` 的大小写），而"多种等价写法"
    ///    正是规范编码要消灭的东西。
    /// 2. `timestamptz` 在 PostgreSQL 里**不保存时区**，它就是一个时刻。用纳秒表达时，
    ///    同一时刻无论以哪个偏移量读出来都编成同一串字节；用文本表达就不是。
    pub(super) fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.str(self.id.as_str());
        writer.option_str(self.actor.as_ref().map(ActorId::as_str));
        writer.str(self.event_type.as_str());
        writer.str(self.target_kind.as_str());
        writer.option_str(self.target_id.as_ref().map(AuditIdentifier::as_str));
        self.payload.write_canonical(writer);
        writer.i128(self.created_at.unix_timestamp_nanos());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_is_upstream_fifty_seven_plus_thirty_new_and_has_no_duplicates() {
        assert_eq!(AUDIT_EVENT_TYPES.len(), 87);
        let unique: BTreeSet<&str> = AUDIT_EVENT_TYPES.iter().map(|t| t.0).collect();
        assert_eq!(unique.len(), 87, "目录里有重复的事件类型");
    }

    #[test]
    fn history_clear_event_appends_without_changing_the_existing_catalog() {
        let old_catalog = AUDIT_EVENT_TYPES[..86]
            .iter()
            .map(|event| event.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            super::super::hash::Sha256Digest::of(old_catalog.as_bytes()).to_hex(),
            "6361c89679fd68a574b12326e4abdb1e0da805600734fc88c9f9aa8e95d060e1"
        );
        assert_eq!(
            AUDIT_EVENT_TYPES.last(),
            Some(&AuditEventType::THREAD_HISTORY_CLEAR_COMPLETED)
        );
        assert_eq!(
            AuditEventType::parse("thread_history.clear_completed"),
            Some(AuditEventType::THREAD_HISTORY_CLEAR_COMPLETED)
        );
        for unknown in [
            "thread_history.clear_completed ",
            "thread_history.clear_completed_unknown",
            "thread_history.clear_started",
        ] {
            assert_eq!(AuditEventType::parse(unknown), None);
        }
    }

    #[test]
    fn gateway_authorization_catalog_is_closed() {
        let values = [
            (
                "gateway_authorization_attempt_created",
                AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CREATED,
            ),
            (
                "gateway_authorization_registration_admitted",
                AuditEventType::GATEWAY_AUTHORIZATION_REGISTRATION_ADMITTED,
            ),
            (
                "gateway_authorization_attempt_closed",
                AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CLOSED,
            ),
            (
                "gateway_authorization_registered",
                AuditEventType::GATEWAY_AUTHORIZATION_REGISTERED,
            ),
            (
                "gateway_authorization_code_admitted",
                AuditEventType::GATEWAY_AUTHORIZATION_CODE_ADMITTED,
            ),
        ];
        for (value, event) in values {
            assert_eq!(AuditEventType::parse(value), Some(event));
            assert_eq!(event.as_str(), value);
        }
        assert_eq!(AUDIT_EVENT_TYPES.len(), 87);
        assert_eq!(
            AUDIT_EVENT_TYPES
                .iter()
                .map(|t| t.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            87
        );
        assert_eq!(&AUDIT_EVENT_TYPES[81..86], &values.map(|(_, event)| event));
        for invalid in [
            "gateway_authorization_attempt_created ",
            "Gateway_authorization_attempt_created",
            "gateway_authorization_registered ",
            "gateway_authorization_registered_unknown",
            "gateway_authorization_attempt_closed_unknown",
            "Gateway_authorization_code_admitted",
            "gateway_authorization_code_admitted ",
            "gateway_authorization_code_admitted_unknown",
        ] {
            assert_eq!(AuditEventType::parse(invalid), None);
        }
    }

    #[test]
    fn parse_accepts_only_catalog_members() {
        for event_type in AUDIT_EVENT_TYPES {
            assert_eq!(
                AuditEventType::parse(event_type.as_str()),
                Some(*event_type)
            );
        }
        // 负向：拼错、大小写不同、前后缀、空串一律不接受。
        assert_eq!(AuditEventType::parse("computer.action_allow"), None);
        assert_eq!(AuditEventType::parse("Computer.action_allowed"), None);
        assert_eq!(AuditEventType::parse("computer.action_allowed "), None);
        assert_eq!(AuditEventType::parse(""), None);
        assert_eq!(AuditEventType::parse("anything.at.all"), None);
        assert_eq!(
            AuditEventType::parse("gateway_authorization_code_admitted "),
            None
        );
    }

    #[test]
    fn associated_constants_are_all_catalog_members() {
        for constant in [
            AuditEventType::AGENT_INVOKED,
            AuditEventType::AGENT_STREAM_STALLED,
            AuditEventType::AGENT_RUN_DEADLINE_EXCEEDED,
            AuditEventType::AGENT_RUN_COST_BUDGET_REFUSED,
            AuditEventType::MEMORY_REMEMBER_REFUSED,
            AuditEventType::MEMORY_REMEMBER_SUCCEEDED,
            AuditEventType::MEMORY_EFFECT_COMMITTED,
            AuditEventType::ARTIFACT_SAVED,
            AuditEventType::ARTIFACT_CLEANUP_ARMED,
            AuditEventType::ARTIFACT_CLEANUP_COMPLETED,
            AuditEventType::MEMORY_REMEMBER_FAILED,
            AuditEventType::COMPONENT_HUMAN_REQUESTED,
            AuditEventType::COMPONENT_HUMAN_ANSWERED,
            AuditEventType::COMPONENT_HUMAN_EXPIRED,
            AuditEventType::COMPONENT_HUMAN_CANCELLED,
            AuditEventType::COMPUTER_ACTION_ALLOWED,
            AuditEventType::COMPUTER_ACTION_REFUSED,
            AuditEventType::COMPUTER_ACTION_FAILED,
            AuditEventType::COMPUTER_HELP_REQUESTED,
            AuditEventType::COMPUTER_CONTROL_TAKEN,
            AuditEventType::COMPUTER_CONTROL_RELEASED,
            AuditEventType::COMPUTER_SECRET_REQUESTED,
            AuditEventType::COMPUTER_SECRET_SUPPLIED,
            AuditEventType::MCP_CALL_REJECTED,
            AuditEventType::MCP_CALL_SUCCEEDED,
            AuditEventType::MCP_CALL_FAILED,
            AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CREATED,
            AuditEventType::GATEWAY_AUTHORIZATION_REGISTRATION_ADMITTED,
            AuditEventType::GATEWAY_AUTHORIZATION_ATTEMPT_CLOSED,
            AuditEventType::GATEWAY_AUTHORIZATION_REGISTERED,
            AuditEventType::GATEWAY_AUTHORIZATION_CODE_ADMITTED,
        ] {
            assert!(
                AUDIT_EVENT_TYPES.contains(&constant),
                "关联常量 {constant} 不在目录里 —— 它会绕过封闭性"
            );
        }
    }
}
