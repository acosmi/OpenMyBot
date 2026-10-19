//! `AppError`、稳定错误码与 audit 类型（v3 §15.3）。
//!
//! §15.3 逐条：
//!
//! - 未登录 401；已登录但角色不足 403；Bot/channel 不可见统一 404；
//! - malformed payload 400，不产生 acting decision；
//! - policy refusal 403 + stable error code/rule ID；
//! - unavailable dependency 503；vendor failure 502/normalized tool error；
//! - stale snapshot/generation 409；request/idempotency conflict 409；lease conflict 409；
//! - unknown commit 202/409 对应 reconciliation，不伪装 500 或 success；
//! - 空、新 thread history 200 + empty list。
//!
//! 以及：「错误给用户的文本可本地化，但 stable code、HTTP status 和 audit event 类型不能
//! 随文案变化。」
//!
//! # 本模块里没有一个字是用户文案
//!
//! repository contract §4a 规定文案不进 domain / application，错误以 **code** 穿越边界后在 GUI 本地化。
//! 这里把它做成构造性事实而不是纪律：
//!
//! - [`ErrorCode`] 是 `&'static str` 的 newtype，取值集合由本文件的关联常量穷举；
//! - 携带上下文的变体里，只有 policy rule id 是 `String`（它来自管理员编写的 policy，必然是
//!   运行期值），其余标识类字段一律 `&'static str` —— 这在**类型层面**堵死了「把用户输入
//!   或一句中文提示塞进错误」这条路，而不是靠 review 发现；
//! - [`AppError`] 的 `Display` 只输出稳定码与结构化上下文，供日志用，**不供 UI 直接显示**。
//!
//! 最后一条要点：`ChannelPage` 的空列表是合法值（§15.3 末条），空 history 不是错误 ——
//! 所以本 enum 里**没有** `Empty` / `NoResult` 之类的变体，这是刻意的。

use core::fmt;

use crate::artifacts::ArtifactGoneStatus;
use crate::auth::Role;
use crate::ids::{ActorId, ComputerGeneration, DocumentGeneration, PolicyDecisionId};

/// 稳定错误码。
///
/// newtype 而非裸 `&str`：稳定码是**契约**（§15.3「stable code 不能随文案变化」），
/// 裸字符串允许任何调用点当场发明一个新码。取值集合由 [`AppError::code`] 的穷举 match
/// 决定，本类型的关联常量是它的唯一字面量落点。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// 未登录（401）。
    pub const UNAUTHENTICATED: Self = Self("unauthenticated");
    /// 已登录但角色不足（403）。
    pub const FORBIDDEN_ROLE: Self = Self("forbidden_role");
    /// 资源对当前 actor 不可见（404，统一码，防枚举）。
    pub const NOT_VISIBLE: Self = Self("not_visible");
    /// Authorized artifact metadata is deleted or expired (410).
    pub const ARTIFACT_GONE: Self = Self("artifact_gone");
    /// 请求体畸形（400），不产生 acting decision。
    pub const MALFORMED_PAYLOAD: Self = Self("malformed_payload");
    /// policy 拒绝（403），必带 rule id。
    pub const POLICY_REFUSED: Self = Self("policy_refused");
    /// 依赖不可用（503）。
    pub const DEPENDENCY_UNAVAILABLE: Self = Self("dependency_unavailable");
    /// 上游 vendor 失败（502），已规范化。
    pub const VENDOR_FAILURE: Self = Self("vendor_failure");
    /// snapshot / generation 陈旧（409）。
    pub const STALE_GENERATION: Self = Self("stale_generation");
    /// 同一个请求/幂等 ID 已绑定到不同内容（409）。
    pub const REQUEST_CONFLICT: Self = Self("request_conflict");
    /// lease 冲突（409）。
    pub const LEASE_CONFLICT: Self = Self("lease_conflict");
    /// 配置 admin floor 阻止降权。
    pub const IDENTITY_ROLE_CONFIGURED_ADMIN: Self = Self("identity_role_change_configured_admin");
    /// 管理员不能给自己降权。
    pub const IDENTITY_ROLE_SELF_DEMOTION: Self = Self("identity_role_change_self_demotion");
    /// 不能移除最后一个有效管理员角色。
    pub const IDENTITY_ROLE_LAST_ADMIN: Self = Self("identity_role_change_last_admin");
    /// 配置 admin floor 阻止撤权。
    pub const IDENTITY_ACCESS_CONFIGURED_ADMIN: Self =
        Self("identity_access_change_configured_admin");
    /// 管理员不能移除自己的访问。
    pub const IDENTITY_ACCESS_SELF_REVOCATION: Self =
        Self("identity_access_change_self_revocation");
    /// 不能撤销最后一个有效管理员的访问。
    pub const IDENTITY_ACCESS_LAST_ADMIN: Self = Self("identity_access_change_last_admin");
    /// 敏感写要求 admin。
    pub const SENSITIVE_WRITE_ROLE_INSUFFICIENT: Self =
        Self("identity_sensitive_write_role_insufficient");
    /// 敏感写缺 Origin。
    pub const SENSITIVE_WRITE_ORIGIN_MISSING: Self =
        Self("identity_sensitive_write_origin_missing");
    /// 敏感写 Origin 不可信。
    pub const SENSITIVE_WRITE_ORIGIN_UNTRUSTED: Self =
        Self("identity_sensitive_write_origin_untrusted");
    /// 敏感写 session 不再 fresh。
    pub const SENSITIVE_WRITE_SESSION_NOT_FRESH: Self =
        Self("identity_sensitive_write_session_not_fresh");
    /// commit 状态未知，需要和解（202 或 409）。
    pub const RECONCILIATION_REQUIRED: Self = Self("reconciliation_required");

    /// 借出稳定码字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// audit event 类型。
///
/// §15.3：「stable code、HTTP status 和 audit event 类型不能随文案变化。」封闭 enum 让
/// 「audit 类型」成为可穷举的域，而不是又一个自由字符串。
///
/// 注意它与 [`ErrorCode`] **不是一一对应**：`StaleGeneration` 与 `LeaseConflict` 是两个
/// 不同的稳定码，但在 audit 上同属并发冲突。code 面向调用方，audit kind 面向审计查询，
/// 两者粒度本就不同。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditKind {
    /// 认证失败。
    AuthFailure,
    /// 已认证但授权不足。
    AuthorizationDenied,
    /// 资源不可见。
    ResourceNotVisible,
    /// Authorized resource has a content-free gone state.
    ResourceGone,
    /// 输入被拒（未产生 acting decision）。
    InputRejected,
    /// policy 拒绝。
    PolicyRefusal,
    /// 依赖不可用。
    DependencyFailure,
    /// 上游 vendor 失败。
    VendorFailure,
    /// 并发冲突（陈旧代际 / lease 冲突）。
    ConcurrencyConflict,
    /// commit 未知，进入和解流程。
    ReconciliationRequired,
}

impl AuditKind {
    /// 稳定的 audit 类型字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthFailure => "auth_failure",
            Self::AuthorizationDenied => "authorization_denied",
            Self::ResourceNotVisible => "resource_not_visible",
            Self::ResourceGone => "resource_gone",
            Self::InputRejected => "input_rejected",
            Self::PolicyRefusal => "policy_refusal",
            Self::DependencyFailure => "dependency_failure",
            Self::VendorFailure => "vendor_failure",
            Self::ConcurrencyConflict => "concurrency_conflict",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

impl fmt::Display for AuditKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 陈旧代际的具体对象（§15.3「stale snapshot/generation 409」）。
///
/// 用两个 generation newtype 而不是裸 `u64`，是裁决 D7 的直接受益点：`expected` 与
/// `observed` 的比较是**数值序**，不会出现字典序把 `10` 判成小于 `9` 的情形。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleGenerationSubject {
    /// Current authorized configuration snapshot after a revision conflict.
    Configuration {
        /// Closed current revision, public digest and database timestamp.
        snapshot: crate::revision::RevisionSnapshot,
    },
    /// computer 代际陈旧（engine restart/reset 之后，§17.2 条 6）。
    Computer {
        /// 权威方当前的代际。
        expected: ComputerGeneration,
        /// 请求方带来的代际。
        observed: ComputerGeneration,
    },
    /// document 代际陈旧（snapshot ref 绑定的页面已换代，§17.2 条 4）。
    Document {
        /// 权威方当前的代际。
        expected: DocumentGeneration,
        /// 请求方带来的代际。
        observed: DocumentGeneration,
    },
}

impl fmt::Display for StaleGenerationSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration { snapshot } => write!(
                f,
                "subject=configuration revision={}",
                snapshot.current_revision()
            ),
            Self::Computer { expected, observed } => {
                write!(
                    f,
                    "subject=computer expected={expected} observed={observed}"
                )
            }
            Self::Document { expected, observed } => {
                write!(
                    f,
                    "subject=document expected={expected} observed={observed}"
                )
            }
        }
    }
}

/// people role/access 变更的六种稳定冲突原因（上游前四项 parity，last-admin 两项新增）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityConflictReason {
    /// 地址在 configured admin floor，不能降权。
    RoleConfiguredAdmin,
    /// 不能给自己降 admin。
    RoleSelfDemotion,
    /// 会留下零有效 admin。
    RoleLastAdmin,
    /// 地址在 configured admin floor，不能撤权。
    AccessConfiguredAdmin,
    /// 不能撤销自己的访问。
    AccessSelfRevocation,
    /// 会留下零有效 admin。
    AccessLastAdmin,
}

impl IdentityConflictReason {
    /// 对应领域 rejection 的稳定码。
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::RoleConfiguredAdmin => ErrorCode::IDENTITY_ROLE_CONFIGURED_ADMIN,
            Self::RoleSelfDemotion => ErrorCode::IDENTITY_ROLE_SELF_DEMOTION,
            Self::RoleLastAdmin => ErrorCode::IDENTITY_ROLE_LAST_ADMIN,
            Self::AccessConfiguredAdmin => ErrorCode::IDENTITY_ACCESS_CONFIGURED_ADMIN,
            Self::AccessSelfRevocation => ErrorCode::IDENTITY_ACCESS_SELF_REVOCATION,
            Self::AccessLastAdmin => ErrorCode::IDENTITY_ACCESS_LAST_ADMIN,
        }
    }
}

impl fmt::Display for IdentityConflictReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code().as_str())
    }
}

/// 敏感 admin 写的四种稳定拒绝原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SensitiveWriteReason {
    /// 角色不足。
    RoleInsufficient,
    /// 缺 Origin。
    OriginMissing,
    /// Origin 不可信。
    OriginUntrusted,
    /// session 不 fresh。
    SessionNotFresh,
}

impl SensitiveWriteReason {
    /// 稳定错误码。
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::RoleInsufficient => ErrorCode::SENSITIVE_WRITE_ROLE_INSUFFICIENT,
            Self::OriginMissing => ErrorCode::SENSITIVE_WRITE_ORIGIN_MISSING,
            Self::OriginUntrusted => ErrorCode::SENSITIVE_WRITE_ORIGIN_UNTRUSTED,
            Self::SessionNotFresh => ErrorCode::SENSITIVE_WRITE_SESSION_NOT_FRESH,
        }
    }
}

impl fmt::Display for SensitiveWriteReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code().as_str())
    }
}

/// 应用层错误。封闭 enum，恰好覆盖 §15.3 列举的每一条语义。
///
/// # 三样东西必须与文案解耦
///
/// [`Self::code`] / [`Self::http_status`] / [`Self::audit_kind`] 都是**无通配 `_` 的穷举
/// match**：新增一个变体会在这三处同时编译失败，逼作者当场决定它的稳定码、状态码和
/// audit 类型。这比任何「记得同步更新」的注释都可靠 —— 漏一处就编译不过。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AppError {
    /// 未登录（401）。
    #[error("unauthenticated")]
    Unauthenticated,

    /// 已登录但角色不足（403）。
    #[error("forbidden_role required_role={required}")]
    ForbiddenRole {
        /// 该操作要求的角色。
        required: Role,
    },

    /// 资源对当前 actor 不可见（404）。
    ///
    /// **刻意不带资源类型或 id**：§15.3 要求 Bot/channel 不可见统一 404，目的就是让
    /// 「不存在」与「存在但无权」不可区分。带上资源信息等于把这道防枚举的墙自己拆了。
    #[error("not_visible")]
    NotVisible,

    /// Authorized artifact deletion/expiration, with no resource ID or content facts.
    #[error("artifact_gone status={status}")]
    ArtifactGone {
        /// Only the closed gone state may leave the application boundary.
        status: ArtifactGoneStatus,
    },

    /// 请求体畸形（400）。不产生 acting decision（§15.3）。
    #[error("malformed_payload field={field}")]
    MalformedPayload {
        /// 出错字段的**静态**名字。
        ///
        /// `&'static str` 不是吝啬，是约束：它在类型层面堵死「把用户输入原样回显进错误」
        /// 这条路（日志注入 / PII 外溢 / 文案混入）。`AppCommand` 是封闭 enum，字段名本
        /// 就是有限静态集合；整体解析失败时调用点给 `"body"` 即可。
        field: &'static str,
    },

    /// policy 拒绝（403 + stable rule id，§15.3）。
    #[error("policy_refused rule={rule}")]
    PolicyRefused {
        /// 触发拒绝的规则 ID。
        ///
        /// 这是本 enum 里唯一的 `String`：规则由管理员编写，必然是运行期值。它仍然是
        /// **标识符**不是文案 —— 判据：它不随 locale 变化（§15.3）。
        rule: String,
        /// 对应的 durable decision（§17.2 条 2）。拒绝也可能已经写了 decision 行。
        decision: Option<PolicyDecisionId>,
    },

    /// 依赖不可用（503）。
    #[error("dependency_unavailable dependency={dependency}")]
    DependencyUnavailable {
        /// 依赖的静态名（如 `"database"` / `"vault"` / `"browser_engine"`）。
        dependency: &'static str,
    },

    /// 上游 vendor 失败（502 / normalized tool error，§15.3）。
    #[error("vendor_failure vendor={vendor}")]
    VendorFailure {
        /// vendor 的静态名。上游返回体**不**进这里：它是不可信外部数据。
        vendor: &'static str,
    },

    /// snapshot / generation 陈旧（409）。
    #[error("stale_generation {subject}")]
    StaleGeneration {
        /// 陈旧的具体对象与两侧代际值。
        subject: StaleGenerationSubject,
    },

    /// 一个 durable request/idempotency ID 已绑定到不同内容（409）。
    ///
    /// `resource` 只能是静态类别名，绝不携带冲突 ID 或原始请求内容。
    #[error("request_conflict resource={resource}")]
    RequestConflict {
        /// 冲突资源类别，例如 `"run"`。
        resource: &'static str,
    },

    /// lease 冲突（409）。human lease 期间 Agent acting 立即拒绝、不排队（§17.2 条 7）。
    #[error("lease_conflict")]
    LeaseConflict {
        /// 当前持有者（若权威方知道）。**transport 不得把它回给调用方** —— 那会泄漏
        /// 同租户内其他 actor 的存在；它只进受控日志。
        holder: Option<ActorId>,
    },

    /// people role/access 变更被 floor/self/last-admin 不变量拒绝（409）。
    #[error("{reason}")]
    IdentityConflict {
        /// 稳定拒绝原因。
        reason: IdentityConflictReason,
    },

    /// fresh-session / CSRF / admin role 敏感写闸门拒绝。
    #[error("{reason}")]
    SensitiveWriteRefused {
        /// 稳定拒绝原因。
        reason: SensitiveWriteReason,
    },

    /// commit 状态未知，需要和解（§15.3「unknown commit 202/409 对应 reconciliation，
    /// 不伪装 500 或 success」）。
    #[error("reconciliation_required accepted={accepted}")]
    ReconciliationRequired {
        /// 是否已受理待和解。
        ///
        /// `true` → 202：权威方已把这次未知 commit 记入和解队列，调用方无需重试。
        /// `false` → 409：尚未受理（例如非幂等操作，§17.2 条 9 禁止自动重放），调用方
        /// 必须停下来等人 / 等和解流程，**不得**自行重试。
        accepted: bool,
    },
}

impl AppError {
    /// 稳定错误码。穷举 match，无通配。
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Unauthenticated => ErrorCode::UNAUTHENTICATED,
            Self::ForbiddenRole { .. } => ErrorCode::FORBIDDEN_ROLE,
            Self::NotVisible => ErrorCode::NOT_VISIBLE,
            Self::ArtifactGone { .. } => ErrorCode::ARTIFACT_GONE,
            Self::MalformedPayload { .. } => ErrorCode::MALFORMED_PAYLOAD,
            Self::PolicyRefused { .. } => ErrorCode::POLICY_REFUSED,
            Self::DependencyUnavailable { .. } => ErrorCode::DEPENDENCY_UNAVAILABLE,
            Self::VendorFailure { .. } => ErrorCode::VENDOR_FAILURE,
            Self::StaleGeneration { .. } => ErrorCode::STALE_GENERATION,
            Self::RequestConflict { .. } => ErrorCode::REQUEST_CONFLICT,
            Self::LeaseConflict { .. } => ErrorCode::LEASE_CONFLICT,
            Self::IdentityConflict { reason } => reason.code(),
            Self::SensitiveWriteRefused { reason } => reason.code(),
            Self::ReconciliationRequired { .. } => ErrorCode::RECONCILIATION_REQUIRED,
        }
    }

    /// HTTP 状态码。穷举 match，无通配。
    ///
    /// 值域由 §15.3 固定，见 [`HTTP_STATUS_DOMAIN`]。
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::Unauthenticated
            | Self::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            } => 401,
            Self::ForbiddenRole { .. } | Self::PolicyRefused { .. } => 403,
            Self::NotVisible => 404,
            Self::ArtifactGone { .. } => 410,
            Self::MalformedPayload { .. } => 400,
            Self::DependencyUnavailable { .. } => 503,
            Self::VendorFailure { .. } => 502,
            Self::StaleGeneration { .. }
            | Self::RequestConflict { .. }
            | Self::LeaseConflict { .. }
            | Self::IdentityConflict { .. } => 409,
            Self::SensitiveWriteRefused { .. } => 403,
            // 「不伪装 500 或 success」：已受理 → 202（Accepted，明说还没定），
            // 未受理 → 409（Conflict，明说现在不能继续）。两个都不是 2xx 成功语义里的 200。
            Self::ReconciliationRequired { accepted } => {
                if *accepted {
                    202
                } else {
                    409
                }
            }
        }
    }

    /// audit event 类型。穷举 match，无通配。
    #[must_use]
    pub const fn audit_kind(&self) -> AuditKind {
        match self {
            Self::Unauthenticated => AuditKind::AuthFailure,
            Self::ForbiddenRole { .. } => AuditKind::AuthorizationDenied,
            Self::NotVisible => AuditKind::ResourceNotVisible,
            Self::ArtifactGone { .. } => AuditKind::ResourceGone,
            Self::MalformedPayload { .. } => AuditKind::InputRejected,
            Self::PolicyRefused { .. } => AuditKind::PolicyRefusal,
            Self::DependencyUnavailable { .. } => AuditKind::DependencyFailure,
            Self::VendorFailure { .. } => AuditKind::VendorFailure,
            Self::StaleGeneration { .. }
            | Self::RequestConflict { .. }
            | Self::LeaseConflict { .. } => AuditKind::ConcurrencyConflict,
            Self::IdentityConflict { .. } => AuditKind::AuthorizationDenied,
            Self::SensitiveWriteRefused { reason } => match reason {
                SensitiveWriteReason::SessionNotFresh => AuditKind::AuthFailure,
                SensitiveWriteReason::RoleInsufficient
                | SensitiveWriteReason::OriginMissing
                | SensitiveWriteReason::OriginUntrusted => AuditKind::AuthorizationDenied,
            },
            Self::ReconciliationRequired { .. } => AuditKind::ReconciliationRequired,
        }
    }
}

/// §15.3 允许出现的全部 HTTP 状态码（含成功侧的 200：空 thread history 是 200 + 空列表）。
///
/// 任何落在此集合之外的状态码都说明有人在错误映射里发明了新语义。
pub const HTTP_STATUS_DOMAIN: &[u16] = &[200, 202, 400, 401, 403, 404, 409, 410, 502, 503];

impl From<crate::request_binding::ArtifactReadCurrentError> for AppError {
    fn from(error: crate::request_binding::ArtifactReadCurrentError) -> Self {
        use crate::request_binding::{ArtifactReadCurrentError as Error, HostRequestBindingError};
        match error {
            Error::Host(HostRequestBindingError::NotCurrent) => Self::Unauthenticated,
            Error::Host(
                HostRequestBindingError::Missing | HostRequestBindingError::Unavailable,
            ) => Self::DependencyUnavailable {
                dependency: "host_request_binding",
            },
            Error::NotVisible => Self::NotVisible,
            Error::Gone(status) => Self::ArtifactGone { status },
            Error::Unavailable => Self::DependencyUnavailable {
                dependency: "artifacts",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ComputerGeneration, DocumentGeneration};
    use std::collections::BTreeSet;

    #[test]
    fn gone_status_is_closed_and_keeps_stable_410_code_and_audit_kind() {
        for status in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
            let error = AppError::ArtifactGone { status };
            assert_eq!(error.http_status(), 410);
            assert_eq!(error.code().as_str(), "artifact_gone");
            assert_eq!(error.audit_kind().as_str(), "resource_gone");
            assert!(HTTP_STATUS_DOMAIN.contains(&410));
        }
        assert!(serde_json::from_str::<ArtifactGoneStatus>("\"available\"").is_err());
    }

    /// 变体总数。新增变体必须同 PR 改这里 —— 它与 [`variant_index`] 和
    /// [`all_variants_for_test`] 三者互相咬合，见下方三条测试。
    const VARIANT_COUNT: usize = 14;

    /// 无通配 `_` 的穷举 match：**新增变体在这里编译失败**，逼作者同 PR 更新下面的变体台账。
    ///
    /// 生产代码里的 [`AppError::code`] / [`AppError::http_status`] / [`AppError::audit_kind`]
    /// 已经是同样的穷举闸门（这是首要防线）；本函数额外把「测试台账覆盖全部变体」这件事
    /// 也钉成编译期 + 断言双重约束。
    fn variant_index(error: &AppError) -> usize {
        match error {
            AppError::Unauthenticated => 0,
            AppError::ForbiddenRole { .. } => 1,
            AppError::NotVisible => 2,
            AppError::MalformedPayload { .. } => 3,
            AppError::PolicyRefused { .. } => 4,
            AppError::DependencyUnavailable { .. } => 5,
            AppError::VendorFailure { .. } => 6,
            AppError::StaleGeneration { .. } => 7,
            AppError::RequestConflict { .. } => 8,
            AppError::LeaseConflict { .. } => 9,
            AppError::IdentityConflict { .. } => 10,
            AppError::SensitiveWriteRefused { .. } => 11,
            AppError::ReconciliationRequired { .. } => 12,
            AppError::ArtifactGone { .. } => 13,
        }
    }

    /// 全部变体的样例实例 —— **新增变体必须同 PR 加进这里**。
    ///
    /// 用函数而不是 `const` 数组：`PolicyRefused.rule` 是 `String`，`String` 不能出现在
    /// `const` 里。改成 `&'static str` 只为了凑一个 const 数组是本末倒置 —— 规则 ID 来自
    /// 管理员编写的 policy，运行期值这件事是需求，不是实现细节。
    ///
    /// `ReconciliationRequired` 出现两次（`accepted` 两态），因为它是唯一一个状态码取决于
    /// 载荷的变体，两个分支都必须被断言覆盖。
    fn all_variants_for_test() -> Vec<AppError> {
        vec![
            AppError::Unauthenticated,
            AppError::ForbiddenRole {
                required: Role::Admin,
            },
            AppError::NotVisible,
            AppError::ArtifactGone {
                status: ArtifactGoneStatus::Deleted,
            },
            AppError::MalformedPayload { field: "body" },
            AppError::PolicyRefused {
                rule: "browser.navigate.deny_private_hosts".to_owned(),
                decision: Some(PolicyDecisionId::new("pd-1")),
            },
            AppError::DependencyUnavailable {
                dependency: "database",
            },
            AppError::VendorFailure { vendor: "provider" },
            AppError::StaleGeneration {
                subject: StaleGenerationSubject::Computer {
                    expected: ComputerGeneration::new(3),
                    observed: ComputerGeneration::new(2),
                },
            },
            AppError::RequestConflict { resource: "run" },
            AppError::LeaseConflict {
                holder: Some(ActorId::new("actor-9")),
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::RoleConfiguredAdmin,
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::RoleSelfDemotion,
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::RoleLastAdmin,
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::AccessConfiguredAdmin,
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::AccessSelfRevocation,
            },
            AppError::IdentityConflict {
                reason: IdentityConflictReason::AccessLastAdmin,
            },
            AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::RoleInsufficient,
            },
            AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginMissing,
            },
            AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginUntrusted,
            },
            AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            },
            AppError::ReconciliationRequired { accepted: true },
            AppError::ReconciliationRequired { accepted: false },
        ]
    }

    /// 台账必须覆盖全部变体：`variant_index` 的返回值集合恰好是 `0..VARIANT_COUNT`。
    #[test]
    fn variant_ledger_covers_every_variant_exactly_once() {
        let indices: BTreeSet<usize> = all_variants_for_test().iter().map(variant_index).collect();
        let expected: BTreeSet<usize> = (0..VARIANT_COUNT).collect();
        assert_eq!(
            indices, expected,
            "all_variants_for_test 没有覆盖全部变体，或 VARIANT_COUNT 与 variant_index 不一致"
        );
    }

    /// 稳定码两两不重复。
    ///
    /// 重复的码 = 调用方无法区分两种语义，而 §15.3 要求 code 是稳定契约。
    /// 例外：同一变体的两个 `accepted` 取值共享同一个码（那是同一语义的两个阶段），
    /// 所以按 `variant_index` 去重后再比。
    #[test]
    fn stable_codes_are_pairwise_distinct_per_variant() {
        let mut codes: BTreeSet<&'static str> = BTreeSet::new();
        for error in all_variants_for_test() {
            if matches!(error, AppError::ReconciliationRequired { accepted: false }) {
                continue;
            }
            assert!(
                codes.insert(error.code().as_str()),
                "稳定码重复：{} 与已有变体撞码",
                error.code()
            );
        }
        assert_eq!(
            codes.len(),
            VARIANT_COUNT + 8,
            "IdentityConflict 多 5 个码，SensitiveWriteRefused 多 3 个码",
        );
    }

    /// 每个变体的 HTTP 状态码逐条对齐 §15.3，且全部落在 [`HTTP_STATUS_DOMAIN`] 内。
    #[test]
    fn http_status_matches_plan_section_15_3() {
        let cases: Vec<(AppError, u16)> = vec![
            (AppError::Unauthenticated, 401),
            (
                AppError::ForbiddenRole {
                    required: Role::Admin,
                },
                403,
            ),
            (AppError::NotVisible, 404),
            (
                AppError::ArtifactGone {
                    status: ArtifactGoneStatus::Deleted,
                },
                410,
            ),
            (AppError::MalformedPayload { field: "body" }, 400),
            (
                AppError::PolicyRefused {
                    rule: "r".to_owned(),
                    decision: None,
                },
                403,
            ),
            (
                AppError::DependencyUnavailable {
                    dependency: "database",
                },
                503,
            ),
            (AppError::VendorFailure { vendor: "provider" }, 502),
            (
                AppError::StaleGeneration {
                    subject: StaleGenerationSubject::Document {
                        expected: DocumentGeneration::new(2),
                        observed: DocumentGeneration::new(1),
                    },
                },
                409,
            ),
            (AppError::RequestConflict { resource: "run" }, 409),
            (AppError::LeaseConflict { holder: None }, 409),
            (
                AppError::IdentityConflict {
                    reason: IdentityConflictReason::RoleLastAdmin,
                },
                409,
            ),
            (
                AppError::SensitiveWriteRefused {
                    reason: SensitiveWriteReason::OriginUntrusted,
                },
                403,
            ),
            (
                AppError::SensitiveWriteRefused {
                    reason: SensitiveWriteReason::SessionNotFresh,
                },
                401,
            ),
            (AppError::ReconciliationRequired { accepted: true }, 202),
            (AppError::ReconciliationRequired { accepted: false }, 409),
        ];
        for (error, expected) in cases {
            assert_eq!(
                error.http_status(),
                expected,
                "{} 的状态码与 §15.3 不符",
                error.code()
            );
        }
    }

    #[test]
    fn every_variant_status_is_inside_the_plan_domain() {
        for error in all_variants_for_test() {
            assert!(
                HTTP_STATUS_DOMAIN.contains(&error.http_status()),
                "{} 的状态码 {} 不在 §15.3 值域内",
                error.code(),
                error.http_status()
            );
        }
    }

    /// 正向对照：值域检查不是恒真的 —— 一个 §15.3 从未允许的状态码确实不在集合里。
    /// 没有这条，上一条测试在「`HTTP_STATUS_DOMAIN` 是全体 u16」的世界里同样通过。
    #[test]
    fn plan_domain_actually_excludes_unlisted_statuses() {
        assert!(
            !HTTP_STATUS_DOMAIN.contains(&500),
            "500 必须不在值域内：§15.3 明说 unknown commit 不得伪装 500"
        );
        assert!(!HTTP_STATUS_DOMAIN.contains(&418));
        assert!(!HTTP_STATUS_DOMAIN.contains(&201));
        // 正向：确实允许的两个都在。
        assert!(HTTP_STATUS_DOMAIN.contains(&200));
        assert!(HTTP_STATUS_DOMAIN.contains(&202));
    }

    #[test]
    fn audit_kind_is_stable_per_variant() {
        assert_eq!(
            AppError::Unauthenticated.audit_kind(),
            AuditKind::AuthFailure
        );
        assert_eq!(
            AppError::ForbiddenRole {
                required: Role::User
            }
            .audit_kind(),
            AuditKind::AuthorizationDenied
        );
        assert_eq!(
            AppError::MalformedPayload { field: "limit" }.audit_kind(),
            AuditKind::InputRejected,
            "malformed payload 不得产生 acting decision，audit 类型必须是输入被拒"
        );
        assert_eq!(
            AppError::LeaseConflict { holder: None }.audit_kind(),
            AuditKind::ConcurrencyConflict
        );
        assert_eq!(
            AppError::StaleGeneration {
                subject: StaleGenerationSubject::Computer {
                    expected: ComputerGeneration::new(1),
                    observed: ComputerGeneration::new(0),
                }
            }
            .audit_kind(),
            AuditKind::ConcurrencyConflict
        );
    }

    /// `Display` 只输出稳定码与结构化上下文，不含任何用户可见文案。
    ///
    /// 机械判据：每个变体的 `Display` 输出必须以自己的稳定码开头。这条既固定了格式，
    /// 也顺带保证「日志里一眼能 grep 到码」。
    #[test]
    fn display_starts_with_stable_code_and_carries_no_user_copy() {
        for error in all_variants_for_test() {
            let rendered = error.to_string();
            assert!(
                rendered.starts_with(error.code().as_str()),
                "Display 必须以稳定码开头，实际是 {rendered}"
            );
        }

        assert_eq!(
            AppError::PolicyRefused {
                rule: "browser.navigate.deny_private_hosts".to_owned(),
                decision: None,
            }
            .to_string(),
            "policy_refused rule=browser.navigate.deny_private_hosts"
        );
        assert_eq!(
            AppError::StaleGeneration {
                subject: StaleGenerationSubject::Computer {
                    expected: ComputerGeneration::new(3),
                    observed: ComputerGeneration::new(2),
                }
            }
            .to_string(),
            "stale_generation subject=computer expected=3 observed=2"
        );
    }

    /// `NotVisible` 不携带任何资源信息 —— 防枚举（§15.3「Bot/channel 不可见统一 404」）。
    #[test]
    fn not_visible_carries_no_resource_discriminator() {
        assert_eq!(AppError::NotVisible.to_string(), "not_visible");
        // 正向对照：同一断言手法在**确实**带上下文的变体上会失败，证明它不是恒真。
        assert_ne!(
            AppError::MalformedPayload { field: "cursor" }.to_string(),
            "malformed_payload"
        );
    }

    /// `AppError` 实现 `std::error::Error`（thiserror 提供），可以直接进 `?` 与日志链。
    #[test]
    fn app_error_is_a_std_error() {
        let error: Box<dyn std::error::Error> = Box::new(AppError::NotVisible);
        assert_eq!(error.to_string(), "not_visible");
    }
}
