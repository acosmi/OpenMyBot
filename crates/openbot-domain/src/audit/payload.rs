//! 审计 payload 的**字段 allowlist**，做成构造性事实而不是纪律。
//!
//! # 上游做的是黑名单，而黑名单在这个位置是结构性地不够
//!
//! 上游 `server/src/audit.ts::redactAuditPayload` 接受任意 `Record<string, unknown>`，
//! 递归遍历，把**键名**命中 `sensitiveKeys` 集合的值替换成 `"[REDACTED]"`。它对已知的键名
//! 有效，但它的失效面是构造性的，不是实现质量问题：
//!
//! 1. **值里的东西它一眼都没看。** `{ note: "用户口令是 hunter2" }` 的键名不敏感，整条
//!    原样落盘。而 payload 的调用方是几十处业务代码，"别把内容放进 note" 是一条只能靠
//!    人复核的约定。
//! 2. **新键名默认是安全的。** 加一个 `user_message` 字段不会命中任何黑名单条目，于是一次
//!    正常的功能开发就把整段对话内容写进了审计表，而没有任何闸门会红。
//! 3. **它只在写入路径上跑一次。** 绕过 `recordAuditEvent` 直接 `store.insert` 就完全不脱敏
//!    （上游 `createAuditStore` 返回的 `insert` 是公开的）。
//!
//! v3 §8.6 的要求是"payload 使用**字段 allowlist**，不保存原始 header/body、prompt、
//! tool full result、screen frame、文件内容、secret 或可验证的 secret hash"。本模块把它
//! 实现成：**payload 的唯一构造入口是一组封闭的 [`AuditFact`] 变体**。
//!
//! # 为什么这样就跑不掉
//!
//! - [`AuditPayload`] 没有任何接受 `serde_json::Value`、`HashMap<String, _>` 或自由键名的
//!   构造函数。它只能由 [`AuditFact`] 构造，而 `AuditFact` 是封闭 enum —— 加一个新的可记录
//!   事实必须改这个文件，那是一次**会被 review 看见**的动作，而不是在某个业务函数里多写
//!   一个键。
//! - 字段名不由调用方提供：每个变体的键名由 [`AuditFact::field`] 写死并汇总在
//!   [`AUDIT_FIELD_LEDGER`]。于是"payload 里可能出现哪些键"是一个**可穷举、可复算**的集合，
//!   而不是"所有业务代码历史上写过的键"。
//! - 值的类型被变体钉死。想记录一段自由文本的地方，找不到一个 `Text(String)` 变体可用；
//!   能装字符串的只有 [`AuditIdentifier`]（长度上限 + 拒绝控制字符）与 [`AuditLabel`]
//!   （`&'static str`，只能是编译期字面量，运行期数据无法成为它）。
//! - **刻意不存在**的东西同样是契约：没有 `SecretHash` 变体。低熵 secret 的 hash 是可以
//!   离线爆破验证的 —— 存 hash 等于存一个"能验证猜测对不对"的预言机，§8.6 因此把它与
//!   secret 原值列在同一条禁令里。[`AuditFact::SecretInput`] 只记 id、用途、目标字段和
//!   **长度**。
//!
//! 剩下的缺口要说清楚，不粉饰：[`AuditIdentifier`] 里塞什么最终仍由调用方决定，本模块只能
//! 把"能塞多少"和"能塞进哪种字段"限死（≤ [`AuditIdentifier::MAX_BYTES`] 字节、无控制
//! 字符、字段名是 `target_id` 这类标识语义）。它挡不住一个存心把 200 字节秘密写进
//! `target_id` 的调用方；它挡住的是"顺手把内容传进来"这条默认路径 —— 而后者才是上游那种
//! 泄漏实际发生的方式。

use core::fmt;
use std::collections::BTreeMap;

use openbot_contracts::approval_preferences::RememberPreferenceRevision;
use serde_json::{Map, Value};

use super::hash::{CanonicalWriter, Sha256Digest};

/// 标识符型字段值 —— **标识，不是内容**。
///
/// 三条构造性约束，逐条有理由：
///
/// - **非空**：空标识符在读侧与 NULL 不可区分，会让"这条事件到底有没有目标"变成猜测。
/// - **≤ [`Self::MAX_BYTES`] 字节**：标识符短，内容长。上限不是为了省空间，是为了让
///   "把一段 prompt 塞进 `target_id`"这条路在**构造时**就失败，而不是在某次泄漏事故的
///   复盘里才被发现。256 字节的取值理由：上游 `audit_events.target_id` 存的是 uuid（36）、
///   bot 名、组件名这类值，256 给了 7 倍余量，同时远小于任何一段有意义的自然语言内容。
/// - **无控制字符**：换行进日志就是日志注入面（一行伪造的日志记录），`\0` 会在若干下游
///   文本处理里截断字符串。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditIdentifier(String);

impl AuditIdentifier {
    /// 标识符的字节上限。
    pub const MAX_BYTES: usize = 256;

    /// 校验并构造。
    ///
    /// # Errors
    ///
    /// 空串、超长、含控制字符时返回 [`AuditFieldError`]。
    pub fn new(value: impl Into<String>) -> Result<Self, AuditFieldError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuditFieldError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(AuditFieldError::TooLong { found: value.len() });
        }
        if value.chars().any(char::is_control) {
            return Err(AuditFieldError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// 借出底层字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonical remote Agent endpoint origin recorded without path, query, userinfo, or fragment.
///
/// This is separate from [`AuditIdentifier`]: a valid DNS host may consume 253 bytes before the
/// scheme and optional port are added. The constructor accepts only the exact origin shape
/// produced by a URL parser, so an entire customer URL cannot be placed here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditEndpointOrigin(String);

impl AuditEndpointOrigin {
    /// `https://` + maximum DNS host + `:` + five-digit port, with conservative headroom.
    pub const MAX_BYTES: usize = 320;

    /// Validate one already-canonicalized HTTP(S) origin.
    ///
    /// # Errors
    ///
    /// Empty, oversized, non-HTTP(S), whitespace/control-bearing, userinfo, path, query, or
    /// fragment-bearing values are rejected.
    pub fn new(value: impl Into<String>) -> Result<Self, AuditFieldError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuditFieldError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(AuditFieldError::TooLong { found: value.len() });
        }
        if value.chars().any(char::is_whitespace) || value.chars().any(char::is_control) {
            return Err(AuditFieldError::ControlCharacter);
        }
        let authority = value
            .strip_prefix("https://")
            .or_else(|| value.strip_prefix("http://"))
            .ok_or(AuditFieldError::InvalidOrigin)?;
        if authority.is_empty()
            || authority
                .chars()
                .any(|character| matches!(character, '/' | '?' | '#' | '@'))
        {
            return Err(AuditFieldError::InvalidOrigin);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded ordered identifier list used for routing candidates, never content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditIdentifierList(Vec<AuditIdentifier>);

impl AuditIdentifierList {
    /// A routing decision never needs an unbounded model-facing roster in one audit row.
    pub const MAX_ITEMS: usize = 256;

    /// Validate a non-empty bounded list.
    pub fn new(values: Vec<AuditIdentifier>) -> Result<Self, AuditFieldError> {
        if values.is_empty() {
            return Err(AuditFieldError::EmptyList);
        }
        if values.len() > Self::MAX_ITEMS {
            return Err(AuditFieldError::TooManyItems {
                found: values.len(),
            });
        }
        Ok(Self(values))
    }

    /// Borrow the ordered identifiers.
    #[must_use]
    pub fn as_slice(&self) -> &[AuditIdentifier] {
        &self.0
    }
}

/// 封闭词汇型字段值 —— 只能是**编译期字面量**。
///
/// `&'static str` 在这里不是省一次分配，是一条准入判据：运行期得到的字符串（HTTP 体、
/// 模型输出、数据库列、MCP server 的自述）没有 `'static` 生命周期，因此**不可能**在不写
/// `Box::leak` 的情况下成为一个 `AuditLabel`。想把不可信数据记成 label 的代码会在类型
/// 检查这一步就停下来。
///
/// 用它承载 effect 分类、commit 状态、稳定错误码这类"取值来自代码里的封闭集合"的字段。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditLabel(&'static str);

impl AuditLabel {
    /// 由编译期字面量构造。
    #[must_use]
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// 借出字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for AuditLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// 字段值校验失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditFieldError {
    /// 空标识符。
    #[error("audit_field_empty")]
    Empty,
    /// 超过 [`AuditIdentifier::MAX_BYTES`]。
    #[error("audit_field_too_long found={found}")]
    TooLong {
        /// 实际字节数。**不回显内容本身** —— 那正是要挡住的东西。
        found: usize,
    },
    /// 含控制字符（换行 / 制表 / NUL 等）。
    #[error("audit_field_control_character")]
    ControlCharacter,
    /// An identifier list required at least one element.
    #[error("audit_field_list_empty")]
    EmptyList,
    /// An identifier list exceeded its fixed item bound.
    #[error("audit_field_list_too_long found={found}")]
    TooManyItems {
        /// Actual item count; values themselves are never echoed.
        found: usize,
    },
    /// Endpoint audit data was not a canonical HTTP(S) origin.
    #[error("audit_field_invalid_origin")]
    InvalidOrigin,
    /// A gateway attempt identifier was not a canonical lowercase UUIDv7.
    #[error("audit_field_invalid_gateway_authorization_attempt_id")]
    InvalidGatewayAuthorizationAttemptId,
}

/// Canonical UUIDv7 data for an existing authorization attempt, never a permission proof.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditGatewayAuthorizationAttemptId(String);

impl AuditGatewayAuthorizationAttemptId {
    /// Accept exactly the lowercase, hyphenated UUIDv7 representation.
    ///
    /// # Errors
    /// Reject wrong length, separators, version, variant or noncanonical bytes without echoing.
    pub fn new(value: impl Into<String>) -> Result<Self, AuditFieldError> {
        let value = value.into();
        let raw = value.as_bytes();
        if raw.len() != 36
            || raw.iter().enumerate().any(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte != b'-'
                } else {
                    !matches!(*byte, b'0'..=b'9' | b'a'..=b'f')
                }
            })
            || raw[14] != b'7'
            || !matches!(raw[19], b'8' | b'9' | b'a' | b'b')
        {
            return Err(AuditFieldError::InvalidGatewayAuthorizationAttemptId);
        }
        Ok(Self(value))
    }

    /// Borrow only the validated descriptive attempt identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed journal phases accepted by the original authorization owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditGatewayAuthorizationPhase {
    /// Original attempt creation committed.
    Created,
    /// Original registration admission committed; no registration was dispatched.
    RegistrationAdmitted,
    /// The original live owner closed within its original budget.
    Closed,
    /// The original registration reply was committed and exactly read back.
    Registered,
    /// The original code admission was committed with its original typed audit.
    CodeAdmitted,
}

impl AuditGatewayAuthorizationPhase {
    /// Exact durable phase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::RegistrationAdmitted => "registration_admitted",
            Self::Closed => "closed",
            Self::Registered => "registered",
            Self::CodeAdmitted => "code_admitted",
        }
    }
}

/// The two controlled close reasons accepted by the original live initial owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditGatewayAuthorizationOutcome {
    /// A controlled refusal while the original authority remained current.
    Refused,
    /// A dependency observation was not established; no later observation upgrades it.
    DependencyUnknown,
}

impl AuditGatewayAuthorizationOutcome {
    /// Exact durable outcome spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::DependencyUnknown => "dependency_unknown",
        }
    }
}

/// 人工接管的三个阶段。
///
/// §8.6 逐字：「human takeover 记录 request / taken / released，**不记录每个键鼠事件**。」
/// 所以这个枚举只有三个变体，而且**没有**任何携带坐标、按键码或时间序列的变体 —— 想记录
/// 逐事件轨迹的代码在这里找不到落点。上游 `server/src/audit.ts` 的注释给的理由同样成立：
/// 逐次点击会把"某人在这两个时刻之间开过这台浏览器"这条真正有用的事实埋掉。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TakeoverPhase {
    /// Bot 请求人接管。
    Requested,
    /// 人已接管。
    Taken,
    /// 人已交还。
    Released,
}

impl TakeoverPhase {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Taken => "taken",
            Self::Released => "released",
        }
    }
}

/// 一条可记录的审计事实。**封闭 enum：这是 payload 的唯一构造入口。**
///
/// 每个变体对应 payload JSON 里的一个键，键名由 [`Self::field`] 给出，全集见
/// [`AUDIT_FIELD_LEDGER`]。新增变体 = 新增一个审计字段，必须同 PR 更新台账，并且会被
/// `field_ledger_is_disjoint_from_upstream_sensitive_keys` 这条测试重新体检一遍。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditFact {
    /// The initial gateway authorization journal schema is fixed at integer one.
    GatewayAuthorizationJournalSchema,
    /// Existing original attempt identity; no client, token, redirect or content.
    GatewayAuthorizationAttemptId(AuditGatewayAuthorizationAttemptId),
    /// One of the three closed initial-path phases.
    GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase),
    /// Explicit NULL for an open prefix, or one of the two controlled close outcomes.
    GatewayAuthorizationOutcome(Option<AuditGatewayAuthorizationOutcome>),
    /// 被调用工具在 catalog 中的稳定名。
    ToolName(AuditIdentifier),
    /// Compiled component声明并被服务端复核的data-function稳定名。
    ComponentFunction(AuditIdentifier),
    /// Build-owned description of the data source read by a component function.
    ComponentReads(AuditLabel),
    /// Closed component implementation kind, such as `sandboxed`.
    ComponentKind(AuditLabel),
    /// Monotonic published source revision for a sandboxed component.
    ComponentRevision(u64),
    /// Monotonic editing version consumed by a sandbox draft, publish or delete action.
    ComponentEditingRevision(u64),
    /// Committed skill editing version; Agent grant changes are recorded separately.
    SkillRevision(u64),
    /// Committed actor-scoped UI preference editing version.
    UiPreferencesRevision(u64),
    /// remember 批准偏好的正版本；纯字段不证明业务与审计已原子提交。
    ApprovalPreferenceRevision(RememberPreferenceRevision),
    /// 该次工具调用的权威 Bot；绝不取自模型或 callback body。
    Bot(AuditIdentifier),
    /// Canonical remote Agent origin; path, query, fragment, userinfo, and credential are absent.
    AgentEndpointOrigin(AuditEndpointOrigin),
    /// 该次调用的 effect 分类结果。
    EffectClass(AuditLabel),
    /// 该分类是否由"无法识别的 effect 字符串"降级而来（§8.2）。
    ///
    /// 单独成字段而不是塞进 [`Self::EffectClass`] 的取值里：降级来的 `execute` 与声明就是
    /// `execute` 的调用在**风险来源**上完全不同，把它们记成同一个值等于把"这个工具的分类
    /// 根本没人说得清"这条信息删掉。
    EffectDowngraded(bool),
    /// 工具实参的规范化摘要（`crate::tool::args`）。**不记实参本身。**
    CanonicalArgsHash(Sha256Digest),
    /// 工具入参 schema 的摘要。
    SchemaHash(Sha256Digest),
    /// 目标对象的类别（封闭词汇，如 `"browser_tab"` / `"mcp_server"`）。
    TargetKind(AuditLabel),
    /// 目标对象的标识。
    TargetId(AuditIdentifier),
    /// Authoritative recipient duplicated in the upstream routing payload for compatibility.
    RoutingChosen(AuditIdentifier),
    /// Stable reason classification; raw model prose and the user message are excluded.
    RoutingReason(AuditLabel),
    /// Whether uncertainty selected the deterministic default.
    RoutingFallback(bool),
    /// Whether the person explicitly selected the recipient.
    RoutingViaMention(bool),
    /// Ordered authoritative roster identities considered by this decision.
    RoutingCandidates(AuditIdentifierList),
    /// 本次 acting 之前写下的 durable decision 的 id（§17.2 条 2 的锚点）。
    DecisionId(AuditIdentifier),
    /// Original tool attempt bound to a same-transaction business receipt.
    ToolAttemptId(AuditIdentifier),
    /// New artifact UUID only; source identities and content are excluded.
    ArtifactId(AuditIdentifier),
    /// Stable artifact operation UUID only; never an intent digest.
    ArtifactOperationId(AuditIdentifier),
    /// Original business memory event sequence, never current content.
    MemoryEventSequence(u64),
    /// 做出该 decision 时生效的 policy 版本（§8.3：多副本下用旧版本做出的 decision 必须可辨认）。
    PolicyVersion(AuditIdentifier),
    /// 触发拒绝的规则 id。
    RefusedByRule(AuditIdentifier),
    /// 稳定错误码（`openbot_contracts::error::ErrorCode`）。
    ErrorCode(AuditLabel),
    /// 执行结果的 commit 状态（`crate::tool::commit`）。
    CommitState(AuditLabel),
    /// people 角色变更前的角色。
    PreviousRole(AuditLabel),
    /// people 角色变更后的角色。
    NewRole(AuditLabel),
    /// people 访问状态变更后的 revoked 值。
    AccessRevoked(bool),
    /// Closed configuration mutation, such as `plugin_granted`; never remote or user prose.
    ConfigurationChange(AuditLabel),
    /// 被退役 credential 的权威 owner 标识；只记 owner id，不记 token/密文。
    CredentialOwner(AuditIdentifier),
    /// Closed credential storage kind, never caller prose.
    CredentialKind(AuditLabel),
    /// Public provider identifier from the validated credential row.
    CredentialProvider(AuditIdentifier),
    /// Public configuration reference; never key material.
    CredentialKeyReference(AuditIdentifier),
    /// Digest of a valid legacy/configuration reference too long for a plain audit identifier.
    CredentialKeyReferenceHash(Sha256Digest),
    /// Byte count paired with the long configuration-reference digest, never secret length.
    CredentialKeyReferenceBytes(u64),
    /// Retired predecessor identity in an atomic credential replacement.
    PreviousCredential(AuditIdentifier),
    /// credential 撤销原因的封闭分类。
    RevocationReason(AuditLabel),
    /// vendor 侧授权是否已经确认撤销；本地退役不能把 `false` 说成 `true`。
    VendorRevoked(bool),
    /// 判定所依据的 computer 代际（§17.2 条 6）。
    ComputerGeneration(u64),
    /// 判定所依据的 catalog 代际（§8.5）。
    CatalogGeneration(u64),
    /// 判定所依据的 document 代际（§17.2 条 4）。
    DocumentGeneration(u64),
    /// 工具声明的幂等性档位。
    Idempotency(AuditLabel),
    /// 工具声明的 approval 档位。
    ApprovalClass(AuditLabel),
    /// Durable human proof-of-intent row used by this decision.
    ApprovalId(AuditIdentifier),
    /// 工具声明的沙箱要求。
    SandboxRequirement(AuditLabel),
    /// 工具是否声明可并行。
    ParallelSafe(bool),
    /// 这是同一次调用的第几次尝试。
    AttemptNumber(u32),
    /// 执行耗时（毫秒）。
    DurationMs(u64),
    /// 入参字节数。**是长度，不是内容。**
    InputBytes(u64),
    /// 结果字节数。**是长度，不是内容。**
    OutputBytes(u64),
    /// 给模型看的结果是否被截断。
    OutputTruncated(bool),
    /// 人工接管的阶段（§8.6：只记 request / taken / released）。
    HumanTakeover(TakeoverPhase),
    /// 人工填入 secret 的记录。
    ///
    /// §8.6 逐字：「secret 输入只记录 secret ID、用途、目标字段和长度，**不记录值**。」
    /// 做成**结构体变体**而不是四个独立变体，是因为这四项是一组不可拆的事实：只记 id 不记
    /// 目标字段的行回答不了"这个口令被填到哪里去了"，而那正是事后调查要问的问题。
    ///
    /// 这里**没有**、并且永远不该有 `value` 或 `value_hash` 字段，理由见模块文档。
    SecretInput {
        /// 凭据在 vault 中的标识。
        secret_id: AuditIdentifier,
        /// 用途（封闭词汇）。
        purpose: AuditLabel,
        /// 被填入的目标字段名。
        target_field: AuditIdentifier,
        /// 值的**字节长度**。
        value_len: u32,
    },
}

impl AuditFact {
    /// 该事实在 payload JSON 里的键名。
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::GatewayAuthorizationJournalSchema => "journal_schema",
            Self::GatewayAuthorizationAttemptId(_) => "attempt_id",
            Self::GatewayAuthorizationPhase(_) => "phase",
            Self::GatewayAuthorizationOutcome(_) => "outcome_code",
            Self::ToolName(_) => "tool_name",
            Self::ComponentFunction(_) => "function",
            Self::ComponentReads(_) => "reads",
            Self::ComponentKind(_) => "component_kind",
            Self::ComponentRevision(_) => "component_revision",
            Self::ComponentEditingRevision(_) => "component_editing_revision",
            Self::SkillRevision(_) => "skill_revision",
            Self::UiPreferencesRevision(_) => "ui_preferences_revision",
            Self::ApprovalPreferenceRevision(_) => "approval_preference_revision",
            Self::Bot(_) => "bot",
            Self::AgentEndpointOrigin(_) => "agent_endpoint_origin",
            Self::EffectClass(_) => "effect_class",
            Self::EffectDowngraded(_) => "effect_downgraded",
            Self::CanonicalArgsHash(_) => "canonical_args_hash",
            Self::SchemaHash(_) => "schema_hash",
            Self::TargetKind(_) => "target_kind",
            Self::TargetId(_) => "target_id",
            Self::RoutingChosen(_) => "chosen",
            Self::RoutingReason(_) => "reason",
            Self::RoutingFallback(_) => "fallback",
            Self::RoutingViaMention(_) => "via_mention",
            Self::RoutingCandidates(_) => "candidates",
            Self::DecisionId(_) => "decision_id",
            Self::ToolAttemptId(_) => "tool_attempt_id",
            Self::ArtifactId(_) => "artifact_id",
            Self::ArtifactOperationId(_) => "artifact_operation_id",
            Self::MemoryEventSequence(_) => "memory_event_sequence",
            Self::PolicyVersion(_) => "policy_version",
            Self::RefusedByRule(_) => "refused_by_rule",
            Self::ErrorCode(_) => "error_code",
            Self::CommitState(_) => "commit_state",
            Self::PreviousRole(_) => "previous_role",
            Self::NewRole(_) => "new_role",
            Self::AccessRevoked(_) => "access_revoked",
            Self::ConfigurationChange(_) => "change",
            Self::CredentialOwner(_) => "credential_owner",
            Self::CredentialKind(_) => "kind",
            Self::CredentialProvider(_) => "provider",
            Self::CredentialKeyReference(_) => "keyId",
            Self::CredentialKeyReferenceHash(_) => "key_id_hash",
            Self::CredentialKeyReferenceBytes(_) => "key_id_bytes",
            Self::PreviousCredential(_) => "previousCredentialId",
            Self::RevocationReason(_) => "revocation_reason",
            Self::VendorRevoked(_) => "vendor_revoked",
            Self::ComputerGeneration(_) => "computer_generation",
            Self::CatalogGeneration(_) => "catalog_generation",
            Self::DocumentGeneration(_) => "document_generation",
            Self::Idempotency(_) => "idempotency",
            Self::ApprovalClass(_) => "approval_class",
            Self::ApprovalId(_) => "approval_id",
            Self::SandboxRequirement(_) => "sandbox_requirement",
            Self::ParallelSafe(_) => "parallel_safe",
            Self::AttemptNumber(_) => "attempt_number",
            Self::DurationMs(_) => "duration_ms",
            Self::InputBytes(_) => "input_bytes",
            Self::OutputBytes(_) => "output_bytes",
            Self::OutputTruncated(_) => "output_truncated",
            Self::HumanTakeover(_) => "human_takeover",
            Self::SecretInput { .. } => "secret_input",
        }
    }

    /// 该事实的 JSON 值。
    fn to_json(&self) -> Value {
        match self {
            Self::GatewayAuthorizationJournalSchema => Value::Number(1.into()),
            Self::GatewayAuthorizationAttemptId(value) => Value::String(value.as_str().to_owned()),
            Self::GatewayAuthorizationPhase(value) => Value::String(value.as_str().to_owned()),
            Self::GatewayAuthorizationOutcome(value) => value.map_or(Value::Null, |outcome| {
                Value::String(outcome.as_str().to_owned())
            }),
            Self::ToolName(value)
            | Self::ComponentFunction(value)
            | Self::Bot(value)
            | Self::TargetId(value)
            | Self::RoutingChosen(value)
            | Self::DecisionId(value)
            | Self::ToolAttemptId(value)
            | Self::ArtifactId(value)
            | Self::ArtifactOperationId(value)
            | Self::ApprovalId(value)
            | Self::PolicyVersion(value)
            | Self::RefusedByRule(value)
            | Self::CredentialOwner(value)
            | Self::CredentialProvider(value)
            | Self::CredentialKeyReference(value)
            | Self::PreviousCredential(value) => Value::String(value.as_str().to_owned()),
            Self::AgentEndpointOrigin(value) => Value::String(value.as_str().to_owned()),
            Self::EffectClass(label)
            | Self::CredentialKind(label)
            | Self::ComponentReads(label)
            | Self::ComponentKind(label)
            | Self::TargetKind(label)
            | Self::RoutingReason(label)
            | Self::ErrorCode(label)
            | Self::CommitState(label)
            | Self::PreviousRole(label)
            | Self::NewRole(label)
            | Self::ConfigurationChange(label)
            | Self::RevocationReason(label)
            | Self::Idempotency(label)
            | Self::ApprovalClass(label)
            | Self::SandboxRequirement(label) => Value::String(label.as_str().to_owned()),
            Self::CanonicalArgsHash(digest)
            | Self::SchemaHash(digest)
            | Self::CredentialKeyReferenceHash(digest) => Value::String(digest.to_hex()),
            Self::EffectDowngraded(value)
            | Self::ParallelSafe(value)
            | Self::AccessRevoked(value)
            | Self::VendorRevoked(value)
            | Self::RoutingFallback(value)
            | Self::RoutingViaMention(value)
            | Self::OutputTruncated(value) => Value::Bool(*value),
            Self::ComputerGeneration(value)
            | Self::MemoryEventSequence(value)
            | Self::CredentialKeyReferenceBytes(value)
            | Self::CatalogGeneration(value)
            | Self::DocumentGeneration(value)
            | Self::ComponentRevision(value)
            | Self::ComponentEditingRevision(value)
            | Self::SkillRevision(value)
            | Self::UiPreferencesRevision(value)
            | Self::DurationMs(value)
            | Self::InputBytes(value)
            | Self::OutputBytes(value) => Value::Number((*value).into()),
            Self::AttemptNumber(value) => Value::Number((*value).into()),
            Self::ApprovalPreferenceRevision(value) => Value::Number(value.get().into()),
            Self::HumanTakeover(phase) => Value::String(phase.as_str().to_owned()),
            Self::RoutingCandidates(values) => Value::Array(
                values
                    .as_slice()
                    .iter()
                    .map(|value| Value::String(value.as_str().to_owned()))
                    .collect(),
            ),
            Self::SecretInput {
                secret_id,
                purpose,
                target_field,
                value_len,
            } => {
                let mut object = Map::new();
                object.insert(
                    "secret_id".to_owned(),
                    Value::String(secret_id.as_str().to_owned()),
                );
                object.insert(
                    "purpose".to_owned(),
                    Value::String(purpose.as_str().to_owned()),
                );
                object.insert(
                    "target_field".to_owned(),
                    Value::String(target_field.as_str().to_owned()),
                );
                object.insert("value_len".to_owned(), Value::Number((*value_len).into()));
                Value::Object(object)
            }
        }
    }

    /// 把该事实写进规范编码。
    ///
    /// 先写**变体标签**再写值：不同变体的字段序列不同，没有这个标签，"schema 固定"这个
    /// 前提在枚举上就不成立（见 [`super::hash`] 模块文档）。标签取键名而不是判别式数字 ——
    /// 数字会随变体重排而漂移，而键名本身就是已经写进台账的稳定契约。
    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.str(self.field());
        match self {
            Self::GatewayAuthorizationJournalSchema => writer.u64(1),
            Self::GatewayAuthorizationAttemptId(value) => writer.str(value.as_str()),
            Self::GatewayAuthorizationPhase(value) => writer.str(value.as_str()),
            Self::GatewayAuthorizationOutcome(value) => {
                writer.option_str(value.map(AuditGatewayAuthorizationOutcome::as_str));
            }
            Self::ToolName(value)
            | Self::ComponentFunction(value)
            | Self::Bot(value)
            | Self::TargetId(value)
            | Self::RoutingChosen(value)
            | Self::DecisionId(value)
            | Self::ToolAttemptId(value)
            | Self::ArtifactId(value)
            | Self::ArtifactOperationId(value)
            | Self::ApprovalId(value)
            | Self::PolicyVersion(value)
            | Self::RefusedByRule(value)
            | Self::CredentialOwner(value)
            | Self::CredentialProvider(value)
            | Self::CredentialKeyReference(value)
            | Self::PreviousCredential(value) => writer.str(value.as_str()),
            Self::AgentEndpointOrigin(value) => writer.str(value.as_str()),
            Self::EffectClass(label)
            | Self::CredentialKind(label)
            | Self::ComponentReads(label)
            | Self::ComponentKind(label)
            | Self::TargetKind(label)
            | Self::RoutingReason(label)
            | Self::ErrorCode(label)
            | Self::CommitState(label)
            | Self::PreviousRole(label)
            | Self::NewRole(label)
            | Self::ConfigurationChange(label)
            | Self::RevocationReason(label)
            | Self::Idempotency(label)
            | Self::ApprovalClass(label)
            | Self::SandboxRequirement(label) => writer.str(label.as_str()),
            Self::CanonicalArgsHash(digest)
            | Self::SchemaHash(digest)
            | Self::CredentialKeyReferenceHash(digest) => writer.digest(digest),
            Self::EffectDowngraded(value)
            | Self::ParallelSafe(value)
            | Self::AccessRevoked(value)
            | Self::VendorRevoked(value)
            | Self::RoutingFallback(value)
            | Self::RoutingViaMention(value)
            | Self::OutputTruncated(value) => writer.bool(*value),
            Self::ComputerGeneration(value)
            | Self::MemoryEventSequence(value)
            | Self::CredentialKeyReferenceBytes(value)
            | Self::CatalogGeneration(value)
            | Self::DocumentGeneration(value)
            | Self::ComponentRevision(value)
            | Self::ComponentEditingRevision(value)
            | Self::SkillRevision(value)
            | Self::UiPreferencesRevision(value)
            | Self::DurationMs(value)
            | Self::InputBytes(value)
            | Self::OutputBytes(value) => writer.u64(*value),
            Self::AttemptNumber(value) => writer.u32(*value),
            Self::ApprovalPreferenceRevision(value) => {
                // 正 i64 纯类型保证该转换无损；沿用审计正计数的固定 8 字节编码。
                writer.u64(
                    u64::try_from(value.get()).expect("positive approval preference revision"),
                );
            }
            Self::HumanTakeover(phase) => writer.str(phase.as_str()),
            Self::RoutingCandidates(values) => {
                writer.u64(values.as_slice().len() as u64);
                for value in values.as_slice() {
                    writer.str(value.as_str());
                }
            }
            Self::SecretInput {
                secret_id,
                purpose,
                target_field,
                value_len,
            } => {
                writer.str(secret_id.as_str());
                writer.str(purpose.as_str());
                writer.str(target_field.as_str());
                writer.u32(*value_len);
            }
        }
    }
}

/// payload 里可能出现的**全部**键名，含嵌套键的点分路径。
///
/// 这是一份台账：它的用途是让"审计表里会出现哪些字段"成为一条可以被机械核对的断言，而不是
/// 一次需要通读全仓写入点的调查。三条测试咬合它 ——
/// `every_variant_field_is_in_the_ledger`（变体 → 台账）、
/// `ledger_has_no_orphan_entries`（台账 → 变体）、
/// `field_ledger_is_disjoint_from_upstream_sensitive_keys`（台账 → 上游敏感键黑名单）。
pub const AUDIT_FIELD_LEDGER: &[&str] = &[
    "kind",
    "provider",
    "keyId",
    "key_id_hash",
    "key_id_bytes",
    "previousCredentialId",
    "tool_name",
    "function",
    "reads",
    "component_kind",
    "component_revision",
    "component_editing_revision",
    "skill_revision",
    "ui_preferences_revision",
    "approval_preference_revision",
    "bot",
    "agent_endpoint_origin",
    "effect_class",
    "effect_downgraded",
    "canonical_args_hash",
    "schema_hash",
    "target_kind",
    "target_id",
    "chosen",
    "reason",
    "fallback",
    "via_mention",
    "candidates",
    "decision_id",
    "tool_attempt_id",
    "artifact_id",
    "artifact_operation_id",
    "memory_event_sequence",
    "policy_version",
    "refused_by_rule",
    "error_code",
    "commit_state",
    "previous_role",
    "new_role",
    "access_revoked",
    "change",
    "credential_owner",
    "revocation_reason",
    "vendor_revoked",
    "computer_generation",
    "catalog_generation",
    "document_generation",
    "idempotency",
    "approval_class",
    "approval_id",
    "sandbox_requirement",
    "parallel_safe",
    "attempt_number",
    "duration_ms",
    "input_bytes",
    "output_bytes",
    "output_truncated",
    "human_takeover",
    "secret_input",
    "secret_input.secret_id",
    "secret_input.purpose",
    "secret_input.target_field",
    "secret_input.value_len",
    "journal_schema",
    "attempt_id",
    "phase",
    "outcome_code",
];

/// 一条审计事件的 payload：一组互不重键的 [`AuditFact`]。
///
/// 内部用 `BTreeMap` 按键名排序保存，于是**同一组事实无论以什么顺序传入，规范编码逐字节
/// 相同**。这条性质是 hash chain 能工作的前提：调用方不该因为把两个 `push` 换了个位置就
/// 让整条链断掉。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditPayload {
    facts: BTreeMap<&'static str, AuditFact>,
}

impl AuditPayload {
    /// 空 payload。合法值 —— 有些事件（例如 `computer.reset`）除了事件本身没有别的事实。
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// 由一组事实构造。
    ///
    /// # Errors
    ///
    /// 同一字段出现两次时返回 [`AuditPayloadError::DuplicateField`]。
    ///
    /// **重键是错误而不是"后写覆盖先写"**：静默覆盖会把两条互相矛盾的事实压成一条，而读侧
    /// 永远看不出发生过这件事。审计数据宁可写入失败，也不能悄悄少一半。
    pub fn from_facts(
        facts: impl IntoIterator<Item = AuditFact>,
    ) -> Result<Self, AuditPayloadError> {
        let mut map = BTreeMap::new();
        for fact in facts {
            let field = fact.field();
            if map.insert(field, fact).is_some() {
                return Err(AuditPayloadError::DuplicateField { field });
            }
        }
        Ok(Self { facts: map })
    }

    /// 按字段名取一条事实。
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&AuditFact> {
        self.facts.get(field)
    }

    /// 事实条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// 按键名升序遍历。
    pub fn iter(&self) -> impl Iterator<Item = &AuditFact> {
        self.facts.values()
    }

    /// 投影成写入 `audit_events.payload`（jsonb）的 JSON 对象。
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        for fact in self.facts.values() {
            object.insert(fact.field().to_owned(), fact.to_json());
        }
        Value::Object(object)
    }

    /// 把 payload 写进规范编码（供 `row_hash` 使用）。
    ///
    /// 先写条数再逐条写，让"两条事实"与"一条事实"在字节层面不可能混淆。
    pub(super) fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.u64(self.facts.len() as u64);
        for fact in self.facts.values() {
            fact.write_canonical(writer);
        }
    }
}

/// payload 构造失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditPayloadError {
    /// 同一字段被写了两次。
    #[error("audit_payload_duplicate_field field={field}")]
    DuplicateField {
        /// 重复的字段名。它来自 [`AUDIT_FIELD_LEDGER`]，是静态字面量，不是调用方数据。
        field: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_preference_revision_payload_is_closed_and_numeric() {
        let payload = AuditPayload::from_facts([
            AuditFact::ConfigurationChange(AuditLabel::new("approval_preference_saved")),
            AuditFact::ApprovalPreferenceRevision(RememberPreferenceRevision::new(7).unwrap()),
        ])
        .unwrap();
        assert_eq!(
            payload.to_json(),
            serde_json::json!({
                "approval_preference_revision":7,
                "change":"approval_preference_saved",
            })
        );
        assert_eq!(payload.len(), 2);
        assert_eq!(
            payload.get("approval_preference_revision"),
            Some(&AuditFact::ApprovalPreferenceRevision(
                RememberPreferenceRevision::new(7).unwrap()
            ))
        );
        assert_eq!(
            AUDIT_FIELD_LEDGER
                .iter()
                .filter(|field| **field == "approval_preference_revision")
                .count(),
            1
        );
    }

    #[test]
    fn approval_preference_revision_canonical_encoding_matches_independent_digest() {
        let payload = AuditPayload::from_facts([AuditFact::ApprovalPreferenceRevision(
            RememberPreferenceRevision::new(i64::MAX).unwrap(),
        )])
        .unwrap();
        assert_eq!(
            payload.to_json(),
            serde_json::json!({"approval_preference_revision":i64::MAX})
        );
        let mut writer = CanonicalWriter::new("approval-preference-test");
        payload.write_canonical(&mut writer);
        // 独立字节：u64be(24)||domain||u64be(1)||u64be(28)||field||0x7fffffffffffffff。
        assert_eq!(
            Sha256Digest::of(&writer.finish()).to_hex(),
            "6c1ca94c74f5b5b56e6df4a1c9d9609f7914ff7ba28fca913fe4e154129eea58"
        );
        let mut different = CanonicalWriter::new("approval-preference-test");
        AuditPayload::from_facts([AuditFact::ApprovalPreferenceRevision(
            RememberPreferenceRevision::first(),
        )])
        .unwrap()
        .write_canonical(&mut different);
        assert_ne!(
            Sha256Digest::of(&different.finish()).to_hex(),
            "6c1ca94c74f5b5b56e6df4a1c9d9609f7914ff7ba28fca913fe4e154129eea58"
        );
    }

    #[test]
    fn artifact_saved_fact_shape_contains_only_two_new_object_id_fields() {
        let artifact = "019a0300-0000-7000-8000-000000000001";
        let operation = "019a0300-0000-7000-8000-000000000002";
        let payload = AuditPayload::from_facts([
            AuditFact::ArtifactId(AuditIdentifier::new(artifact).unwrap()),
            AuditFact::ArtifactOperationId(AuditIdentifier::new(operation).unwrap()),
        ])
        .unwrap();
        assert_eq!(
            payload.to_json(),
            serde_json::json!({"artifact_id":artifact,"artifact_operation_id":operation})
        );
        assert_eq!(payload.len(), 2);
        for key in [
            "source_run_id",
            "source_thread_id",
            "body",
            "sha256",
            "byte_length",
            "media_type",
            "path",
        ] {
            assert!(payload.get(key).is_none());
        }
    }
    use std::collections::BTreeSet;

    fn identifier(value: &str) -> AuditIdentifier {
        AuditIdentifier::new(value).expect("测试用标识符应当合法")
    }

    #[test]
    fn endpoint_origin_cannot_carry_customer_url_or_credentials() {
        assert_eq!(
            AuditEndpointOrigin::new("https://agent.example:8443")
                .unwrap()
                .as_str(),
            "https://agent.example:8443"
        );
        for invalid in [
            "ftp://agent.example",
            "https://user@agent.example",
            "https://agent.example/ag-ui",
            "https://agent.example?token=secret",
            "https://agent.example#fragment",
        ] {
            assert_eq!(
                AuditEndpointOrigin::new(invalid),
                Err(AuditFieldError::InvalidOrigin)
            );
        }
    }

    #[test]
    fn gateway_authorization_attempt_id_is_canonical_v7() {
        let valid = "019a0300-0000-7000-8abc-000000000003";
        assert_eq!(
            AuditGatewayAuthorizationAttemptId::new(valid)
                .unwrap()
                .as_str(),
            valid
        );
        for invalid in [
            "",
            "secret-synthetic",
            "019a0300-0000-7000-8ABC-000000000003",
            "019a0300-0000-4000-8abc-000000000003",
            "019a0300-0000-7000-7abc-000000000003",
            "019a0300_0000-7000-8abc-000000000003",
            "019a0300-0000-7000-8abc-000000000003 ",
            " 019a0300-0000-7000-8abc-000000000003",
            "019a0300-0000-7000-8abc-00000000000g",
        ] {
            let error = AuditGatewayAuthorizationAttemptId::new(invalid).unwrap_err();
            assert_eq!(error, AuditFieldError::InvalidGatewayAuthorizationAttemptId);
            assert_eq!(
                error.to_string(),
                "audit_field_invalid_gateway_authorization_attempt_id"
            );
        }
        for variant in ['8', '9', 'a', 'b'] {
            let mut value = valid.to_owned();
            value.replace_range(19..20, &variant.to_string());
            assert!(AuditGatewayAuthorizationAttemptId::new(value).is_ok());
        }
    }

    #[test]
    fn gateway_authorization_four_facts_are_typed() {
        let id = "019a0300-0000-7000-8000-000000000003";
        for (phase, expected) in [
            (AuditGatewayAuthorizationPhase::Created, "created"),
            (
                AuditGatewayAuthorizationPhase::RegistrationAdmitted,
                "registration_admitted",
            ),
            (AuditGatewayAuthorizationPhase::Closed, "closed"),
            (AuditGatewayAuthorizationPhase::Registered, "registered"),
            (AuditGatewayAuthorizationPhase::CodeAdmitted, "code_admitted"),
        ] {
            let payload = AuditPayload::from_facts([
                AuditFact::GatewayAuthorizationJournalSchema,
                AuditFact::GatewayAuthorizationAttemptId(
                    AuditGatewayAuthorizationAttemptId::new(id).unwrap(),
                ),
                AuditFact::GatewayAuthorizationPhase(phase),
                AuditFact::GatewayAuthorizationOutcome(None),
            ])
            .unwrap();
            assert_eq!(payload.len(), 4);
            assert_eq!(
                payload.to_json(),
                serde_json::json!({
                    "journal_schema":1,"attempt_id":id,"phase":expected,"outcome_code":null
                })
            );
        }
    }

    #[test]
    fn gateway_authorization_null_outcomes_and_duplicates() {
        let values = [
            None,
            Some(AuditGatewayAuthorizationOutcome::Refused),
            Some(AuditGatewayAuthorizationOutcome::DependencyUnknown),
        ];
        let expected = [
            Value::Null,
            Value::String("refused".to_owned()),
            Value::String("dependency_unknown".to_owned()),
        ];
        let mut encodings = Vec::new();
        for (outcome, json) in values.into_iter().zip(expected) {
            let fact = AuditFact::GatewayAuthorizationOutcome(outcome);
            let payload = AuditPayload::from_facts([fact.clone()]).unwrap();
            assert_eq!(payload.to_json(), serde_json::json!({"outcome_code":json}));
            let mut writer = CanonicalWriter::new("owned-gateway-audit-vector");
            fact.write_canonical(&mut writer);
            encodings.push(writer.finish());
            assert!(matches!(
                AuditPayload::from_facts([fact.clone(), fact]),
                Err(AuditPayloadError::DuplicateField {
                    field: "outcome_code"
                })
            ));
        }
        assert_ne!(encodings[0], encodings[1]);
        assert_ne!(encodings[0], encodings[2]);
        assert_ne!(encodings[1], encodings[2]);
        for fact in [
            AuditFact::GatewayAuthorizationJournalSchema,
            AuditFact::GatewayAuthorizationAttemptId(
                AuditGatewayAuthorizationAttemptId::new("019a0300-0000-7000-8000-000000000003")
                    .unwrap(),
            ),
            AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::Closed),
            AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::Registered),
            AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::CodeAdmitted),
        ] {
            let field = fact.field();
            assert_eq!(
                AuditPayload::from_facts([fact.clone(), fact]),
                Err(AuditPayloadError::DuplicateField { field })
            );
        }
    }

    /// 全部变体的样例 —— 新增变体必须同 PR 加进这里，否则下面两条台账测试会红。
    fn every_variant() -> Vec<AuditFact> {
        vec![
            AuditFact::GatewayAuthorizationJournalSchema,
            AuditFact::GatewayAuthorizationAttemptId(
                AuditGatewayAuthorizationAttemptId::new("019a0300-0000-7000-8000-000000000003")
                    .unwrap(),
            ),
            AuditFact::GatewayAuthorizationPhase(AuditGatewayAuthorizationPhase::Created),
            AuditFact::GatewayAuthorizationOutcome(None),
            AuditFact::ToolName(identifier("browser.click")),
            AuditFact::ComponentFunction(identifier("recentRefusals")),
            AuditFact::ComponentReads(AuditLabel::new("audit_trail")),
            AuditFact::ComponentKind(AuditLabel::new("sandboxed")),
            AuditFact::ComponentRevision(7),
            AuditFact::ComponentEditingRevision(9),
            AuditFact::SkillRevision(3),
            AuditFact::UiPreferencesRevision(2),
            AuditFact::ApprovalPreferenceRevision(RememberPreferenceRevision::first()),
            AuditFact::Bot(identifier("bot-1")),
            AuditFact::AgentEndpointOrigin(
                AuditEndpointOrigin::new("https://agent.example:8443").unwrap(),
            ),
            AuditFact::EffectClass(AuditLabel::new("execute")),
            AuditFact::EffectDowngraded(true),
            AuditFact::CanonicalArgsHash(Sha256Digest::of(b"args")),
            AuditFact::SchemaHash(Sha256Digest::of(b"schema")),
            AuditFact::TargetKind(AuditLabel::new("browser_tab")),
            AuditFact::TargetId(identifier("tab-1")),
            AuditFact::RoutingChosen(identifier("agent-1")),
            AuditFact::RoutingReason(AuditLabel::new("model_match")),
            AuditFact::RoutingFallback(false),
            AuditFact::RoutingViaMention(false),
            AuditFact::RoutingCandidates(
                AuditIdentifierList::new(vec![identifier("agent-1"), identifier("agent-2")])
                    .unwrap(),
            ),
            AuditFact::DecisionId(identifier("pd-1")),
            AuditFact::ToolAttemptId(identifier("attempt-1")),
            AuditFact::ArtifactId(identifier("019a0300-0000-7000-8000-000000000001")),
            AuditFact::ArtifactOperationId(identifier("019a0300-0000-7000-8000-000000000002")),
            AuditFact::MemoryEventSequence(0),
            AuditFact::PolicyVersion(identifier("pv-7")),
            AuditFact::RefusedByRule(identifier("deny.private_hosts")),
            AuditFact::ErrorCode(AuditLabel::new("policy_refused")),
            AuditFact::CommitState(AuditLabel::new("unknown")),
            AuditFact::PreviousRole(AuditLabel::new("user")),
            AuditFact::NewRole(AuditLabel::new("admin")),
            AuditFact::AccessRevoked(true),
            AuditFact::ConfigurationChange(AuditLabel::new("plugin_granted")),
            AuditFact::CredentialOwner(identifier("person-1")),
            AuditFact::CredentialKind(AuditLabel::new("model")),
            AuditFact::CredentialProvider(identifier("openai")),
            AuditFact::CredentialKeyReference(identifier("primary")),
            AuditFact::CredentialKeyReferenceHash(Sha256Digest::of(b"long-reference")),
            AuditFact::CredentialKeyReferenceBytes(1024),
            AuditFact::PreviousCredential(identifier("credential-old")),
            AuditFact::RevocationReason(AuditLabel::new("person_removed")),
            AuditFact::VendorRevoked(false),
            AuditFact::ComputerGeneration(3),
            AuditFact::CatalogGeneration(4),
            AuditFact::DocumentGeneration(5),
            AuditFact::Idempotency(AuditLabel::new("non_idempotent")),
            AuditFact::ApprovalClass(AuditLabel::new("every_call")),
            AuditFact::ApprovalId(identifier("approval-1")),
            AuditFact::SandboxRequirement(AuditLabel::new("required")),
            AuditFact::ParallelSafe(false),
            AuditFact::AttemptNumber(2),
            AuditFact::DurationMs(1200),
            AuditFact::InputBytes(64),
            AuditFact::OutputBytes(4096),
            AuditFact::OutputTruncated(true),
            AuditFact::HumanTakeover(TakeoverPhase::Taken),
            AuditFact::SecretInput {
                secret_id: identifier("vault-secret-9"),
                purpose: AuditLabel::new("site_login"),
                target_field: identifier("password"),
                value_len: 18,
            },
        ]
    }

    /// 上游 `server/src/audit.ts` 的 `sensitiveKeys` 集合，逐字照抄（commit
    /// `891df72f1827454d8b353d108fe5dd2313b7e30d`）。
    ///
    /// 它在这里的用途不是"我们也要脱敏"，而是**对拍**：上游认为一旦出现就必须打码的键名，
    /// 我们的 allowlist 里一个都不该有。allowlist 比黑名单强的地方正在于此 —— 强到可以拿
    /// 对方的黑名单当自己的体检项。
    const UPSTREAM_SENSITIVE_KEYS: &[&str] = &[
        "access_token",
        "accesstoken",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "clientsecret",
        "content",
        "credential",
        "credentials",
        "document_content",
        "documentcontent",
        "encrypted_value",
        "encryptedvalue",
        "id_token",
        "idtoken",
        "password",
        "prompt",
        "refresh_token",
        "refreshtoken",
        "result",
        "secret",
        "secrets",
        "token",
        "tokens",
        "tool_arguments",
        "tool_result",
    ];

    /// 上游 `normalizedKey` 的逐字移植：`key.replaceAll(/[^a-zA-Z0-9]/g, "").toLowerCase()`。
    fn upstream_normalized(key: &str) -> String {
        key.chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_lowercase()
    }

    #[test]
    fn every_variant_field_is_in_the_ledger() {
        let ledger: BTreeSet<&str> = AUDIT_FIELD_LEDGER.iter().copied().collect();
        for fact in every_variant() {
            assert!(
                ledger.contains(fact.field()),
                "字段 {} 不在 AUDIT_FIELD_LEDGER 里",
                fact.field()
            );
        }
    }

    /// 台账不许有孤儿条目：每一条要么是某个变体的键名，要么是 `secret_input` 的嵌套键。
    ///
    /// 没有这条，台账可以靠"多写几个安全的名字"来通过上面的对拍 —— 那就退化成一份自我
    /// 安慰的清单。
    #[test]
    fn ledger_has_no_orphan_entries() {
        let variant_fields: BTreeSet<&str> = every_variant().iter().map(AuditFact::field).collect();
        let nested = AuditFact::SecretInput {
            secret_id: identifier("s"),
            purpose: AuditLabel::new("p"),
            target_field: identifier("f"),
            value_len: 1,
        };
        let nested_keys: BTreeSet<String> = match nested.to_json() {
            Value::Object(map) => map
                .keys()
                .map(|key| format!("secret_input.{key}"))
                .collect(),
            other => panic!("secret_input 必须是 JSON 对象，实际是 {other}"),
        };

        for entry in AUDIT_FIELD_LEDGER {
            let known = variant_fields.contains(entry) || nested_keys.contains(*entry);
            assert!(known, "台账条目 {entry} 找不到对应的变体或嵌套键");
        }
        assert_eq!(
            AUDIT_FIELD_LEDGER.len(),
            variant_fields.len() + nested_keys.len(),
            "台账条数必须恰好等于 变体数 + 嵌套键数"
        );
    }

    /// allowlist 与上游黑名单**不相交**（按上游自己的归一化规则比）。
    #[test]
    fn field_ledger_is_disjoint_from_upstream_sensitive_keys() {
        let blocked: BTreeSet<String> = UPSTREAM_SENSITIVE_KEYS
            .iter()
            .map(|key| upstream_normalized(key))
            .collect();
        for entry in AUDIT_FIELD_LEDGER {
            assert!(
                !blocked.contains(&upstream_normalized(entry)),
                "allowlist 字段 {entry} 命中上游敏感键黑名单"
            );
        }
    }

    /// 上一条的正向对照。
    ///
    /// 没有它，`field_ledger_is_disjoint_from_upstream_sensitive_keys` 在"归一化函数写错、
    /// 恒不命中"的世界里同样全绿。这里证明同一个判据确实认得出敏感键：把上游黑名单自己
    /// 喂回去，**每一条**都必须被判为命中。
    #[test]
    fn the_disjointness_check_actually_flags_sensitive_names() {
        let blocked: BTreeSet<String> = UPSTREAM_SENSITIVE_KEYS
            .iter()
            .map(|key| upstream_normalized(key))
            .collect();
        for key in UPSTREAM_SENSITIVE_KEYS {
            assert!(
                blocked.contains(&upstream_normalized(key)),
                "判据认不出上游敏感键 {key}，说明它是恒真的"
            );
        }
        // 几个"如果哪天有人加进来"的具体名字，逐个点名。
        for forbidden in ["prompt", "toolResult", "document_content", "api-key"] {
            assert!(
                blocked.contains(&upstream_normalized(forbidden)),
                "{forbidden} 必须被判为敏感"
            );
        }
    }

    /// **没有** secret hash 字段。§8.6 把可验证的 secret hash 与 secret 原值列在同一条禁令里。
    ///
    /// 判据写成"台账里不存在同时含 secret 与 hash 语义的条目"，并配一条正向对照证明这个
    /// 判据认得出那种名字。
    #[test]
    fn no_field_can_carry_a_verifiable_secret_hash() {
        fn looks_like_a_secret_digest(field: &str) -> bool {
            let normalized = upstream_normalized(field);
            (normalized.contains("secret")
                || normalized.contains("password")
                || normalized.contains("token")
                || normalized.contains("credential"))
                && (normalized.contains("hash")
                    || normalized.contains("digest")
                    || normalized.contains("fingerprint"))
        }

        for entry in AUDIT_FIELD_LEDGER {
            assert!(
                !looks_like_a_secret_digest(entry),
                "台账条目 {entry} 会承载可验证的 secret 摘要"
            );
        }

        // 正向对照：判据确实认得出这几个名字，同时不会误伤已有的两个合法摘要字段。
        assert!(looks_like_a_secret_digest("secret_hash"));
        assert!(looks_like_a_secret_digest("passwordDigest"));
        assert!(!looks_like_a_secret_digest("canonical_args_hash"));
        assert!(!looks_like_a_secret_digest("schema_hash"));
    }

    #[test]
    fn identifier_rejects_content_shaped_values() {
        assert_eq!(AuditIdentifier::new(""), Err(AuditFieldError::Empty));
        assert_eq!(
            AuditIdentifier::new("a\nb"),
            Err(AuditFieldError::ControlCharacter)
        );
        let long = "x".repeat(AuditIdentifier::MAX_BYTES + 1);
        assert_eq!(
            AuditIdentifier::new(long),
            Err(AuditFieldError::TooLong {
                found: AuditIdentifier::MAX_BYTES + 1
            })
        );

        // 正向对照：真实形态的标识符照常通过，边界值恰好通过。
        assert!(AuditIdentifier::new("0199a4d1-6f2b-7c3e-8a11-0242ac120002").is_ok());
        assert!(AuditIdentifier::new("x".repeat(AuditIdentifier::MAX_BYTES)).is_ok());
    }

    #[test]
    fn routing_candidate_list_is_nonempty_and_bounded() {
        assert_eq!(
            AuditIdentifierList::new(Vec::new()),
            Err(AuditFieldError::EmptyList)
        );
        assert_eq!(
            AuditIdentifierList::new(
                (0..=AuditIdentifierList::MAX_ITEMS)
                    .map(|index| identifier(&format!("agent-{index}")))
                    .collect()
            ),
            Err(AuditFieldError::TooManyItems {
                found: AuditIdentifierList::MAX_ITEMS + 1
            })
        );
        let boundary = AuditIdentifierList::new(
            (0..AuditIdentifierList::MAX_ITEMS)
                .map(|index| identifier(&format!("agent-{index}")))
                .collect(),
        )
        .unwrap();
        assert_eq!(boundary.as_slice().len(), AuditIdentifierList::MAX_ITEMS);
    }

    #[test]
    fn duplicate_fields_are_rejected_rather_than_overwritten() {
        let error = AuditPayload::from_facts([AuditFact::DurationMs(1), AuditFact::DurationMs(2)])
            .expect_err("重键必须被拒绝");
        assert_eq!(
            error,
            AuditPayloadError::DuplicateField {
                field: "duration_ms"
            }
        );

        // 正向对照：不同字段可以共存。
        let payload =
            AuditPayload::from_facts([AuditFact::DurationMs(1), AuditFact::InputBytes(2)]).unwrap();
        assert_eq!(payload.len(), 2);
    }

    /// 事实的传入顺序不影响规范编码 —— 否则调用方换一次 `push` 顺序就会让整条链断掉。
    #[test]
    fn fact_order_does_not_change_the_canonical_encoding() {
        let forward = AuditPayload::from_facts([
            AuditFact::DurationMs(7),
            AuditFact::InputBytes(8),
            AuditFact::ParallelSafe(true),
        ])
        .unwrap();
        let backward = AuditPayload::from_facts([
            AuditFact::ParallelSafe(true),
            AuditFact::InputBytes(8),
            AuditFact::DurationMs(7),
        ])
        .unwrap();

        let mut a = CanonicalWriter::new("t");
        forward.write_canonical(&mut a);
        let mut b = CanonicalWriter::new("t");
        backward.write_canonical(&mut b);
        assert_eq!(a.finish(), b.finish());
    }

    /// 但**值**不同必须编出不同的字节。上一条在"编码器什么都不写"的世界里同样成立。
    #[test]
    fn different_values_produce_different_canonical_bytes() {
        let left = AuditPayload::from_facts([AuditFact::DurationMs(7)]).unwrap();
        let right = AuditPayload::from_facts([AuditFact::DurationMs(8)]).unwrap();
        let mut a = CanonicalWriter::new("t");
        left.write_canonical(&mut a);
        let mut b = CanonicalWriter::new("t");
        right.write_canonical(&mut b);
        assert_ne!(a.finish(), b.finish());

        // 同值不同字段也必须不同（变体标签在起作用）。
        let other = AuditPayload::from_facts([AuditFact::InputBytes(7)]).unwrap();
        let mut c = CanonicalWriter::new("t");
        other.write_canonical(&mut c);
        let mut d = CanonicalWriter::new("t");
        left.write_canonical(&mut d);
        assert_ne!(c.finish(), d.finish());
    }

    #[test]
    fn payload_json_uses_ledger_field_names() {
        let payload = AuditPayload::from_facts(every_variant()).unwrap();
        let Value::Object(object) = payload.to_json() else {
            panic!("payload 必须投影成 JSON 对象");
        };
        assert_eq!(object.len(), every_variant().len());
        for key in object.keys() {
            assert!(
                AUDIT_FIELD_LEDGER.contains(&key.as_str()),
                "JSON 里出现了台账外的键 {key}"
            );
        }
        assert_eq!(object["duration_ms"], Value::Number(1200u64.into()));
        assert_eq!(
            object["secret_input"]["value_len"],
            Value::Number(18u32.into())
        );
        assert_eq!(
            object["secret_input"]["secret_id"],
            Value::String("vault-secret-9".to_owned())
        );
    }

    /// `secret_input` 记录的是**长度**，绝不是值。
    ///
    /// 判据：把一个已知的口令喂进去，序列化后的整段 JSON 里不能出现它的任何片段。
    #[test]
    fn secret_input_records_length_but_never_the_value() {
        let payload = AuditPayload::from_facts([AuditFact::SecretInput {
            secret_id: identifier("vault-secret-9"),
            purpose: AuditLabel::new("site_login"),
            target_field: identifier("password_field"),
            value_len: u32::try_from("hunter2-correct-horse".len()).unwrap(),
        }])
        .unwrap();

        let rendered = payload.to_json().to_string();
        assert!(
            !rendered.contains("hunter2"),
            "payload 不得包含 secret 值，实际是 {rendered}"
        );
        assert!(rendered.contains("\"value_len\":21"), "长度必须被记下来");

        // 正向对照：同一条断言手法在**确实**含有该串的文本上会失败，证明它不是恒真。
        assert!("hunter2-correct-horse".contains("hunter2"));
    }
}
