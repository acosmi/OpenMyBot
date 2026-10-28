//! `AuthContext` 与角色（v3 §5.3）。
//!
//! §5.3 逐字：「`AuthContext` 只能由 Rust 根据 session、连接 peer、数据库 ACL 和资源映射
//! 构造。模型、renderer、MCP server、remote Agent 或 browser engine 传来的同名字段一律视为
//! 普通不可信输入。」§5.2 另有一条：「任何 transport 都不得接受自由 method string、renderer
//! 自报角色、renderer 自报 `principal=admin` 或任意数据库 query。」
//!
//! 这两条**由类型系统承载，不靠注释**。落实手法见 [`AuthContext`] 的类型文档。

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, DeploymentId, TenantId};

/// Maximum browser-authored email bytes accepted by the anonymous enterprise-SSO router.
///
/// This is a transport budget, not an email-address validator. The authoritative identity layer
/// still owns normalization and provider-domain routing.
pub const MAX_SSO_ROUTING_EMAIL_BYTES: usize = 512;

/// Environment-configured sign-in providers exposed before authentication.
///
/// The closed set comes from the fixed upstream sign-in journey and the Server startup parser.
/// Deployment-owned OIDC/SAML providers never enter this enum: the anonymous surface exposes only
/// the boolean [`AuthenticationCapabilities::sso_configured`].
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProviderId {
    /// Google OpenID Connect.
    Google,
    /// Microsoft Entra OpenID Connect.
    Microsoft,
    /// Deployment-configured Okta OpenID Connect.
    Okta,
}

impl AuthProviderId {
    /// Stable identifier used in the same-origin start route.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Okta => "okta",
        }
    }
}

impl fmt::Display for AuthProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Unknown environment sign-in provider identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown_auth_provider")]
pub struct UnknownAuthProvider;

impl FromStr for AuthProviderId {
    type Err = UnknownAuthProvider;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "google" => Ok(Self::Google),
            "microsoft" => Ok(Self::Microsoft),
            "okta" => Ok(Self::Okta),
            _ => Err(UnknownAuthProvider),
        }
    }
}

/// Runtime family reported by the anonymous capabilities endpoint.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationRuntimeMode {
    /// Native Rust Server and application runtime.
    Rust,
}

/// Complete anonymous capability response used to paint the sign-in page.
///
/// The shape cannot carry a dynamic provider ID, domain, issuer, or secret. Provider IDs must be
/// strictly sorted and unique; [`Self::is_canonical`] lets every consumer fail closed on a corrupt
/// or drifting response.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationCapabilities {
    /// Runtime implementation family.
    pub mode: ApplicationRuntimeMode,
    /// Whether durable native history is available.
    pub durable_history: bool,
    /// Environment providers, in stable identifier order.
    pub auth_providers: Vec<AuthProviderId>,
    /// Whether at least one deployment-owned email-routed provider exists.
    pub sso_configured: bool,
}

impl AuthenticationCapabilities {
    /// Whether the bounded provider list is strictly ordered and duplicate-free.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        self.auth_providers.len() <= 3
            && self.auth_providers.windows(2).all(|pair| pair[0] < pair[1])
    }
}

/// Successful environment OIDC start response.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationStartResponse {
    /// Authorization URL assembled by the trusted Server coordinator.
    pub url: String,
}

/// Anonymous enterprise-email routing request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseSsoStartRequest {
    /// Address used only for domain routing and keyed rate limiting.
    pub email: String,
}

/// Enumeration-resistant acceptance receipt for enterprise-email routing.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseSsoRoutingAccepted {
    /// Always true when a route ticket—matched or unmatched—was issued.
    pub accepted: bool,
}

/// 角色。封闭 enum，恰两个取值。
///
/// 取值来自上游真实迁移库里的 `role` enum（`('admin','user')`），不是猜的。新增角色是
/// 一次带 ledger 条目的产品变更，不能靠在这里加个变体悄悄发生。
///
/// # serde 的方向性
///
/// 本类型同时实现 `Serialize` 与 `Deserialize`，而 [`AuthContext`] 两个都不实现 —— 这不
/// 矛盾：`Role` 只是一个**值**，能造出一个 `Role::Admin` 并不能造出一个管理员上下文，
/// 因为权限判定的唯一入口是 [`AuthContext::has_role`]，而 `AuthContext` 无法由外部字节
/// 铸造。把 `Role` 也锁死只会逼 infra 层手抄一份字符串映射，不增加任何安全性。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// 管理员。
    Admin,
    /// 普通用户。
    User,
}

impl Role {
    /// 稳定的线上表示，与数据库 `role` enum 的取值逐字相同。
    ///
    /// 它是**标识符**不是文案：不随 locale 变化，不进本地化表（§15.3）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 解析 [`Role`] 失败。
///
/// 刻意是一个**错误**而不是「回落到 `User`」：repository contract §5 条 3 要求空 / 坏 / 未知
/// policy fail-closed，未知角色字符串同理 —— 把它静默降级成 `User` 会让一个拼错的
/// 数据库取值变成一次无声的权限判定。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown_role")]
pub struct UnknownRole;

impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(UnknownRole),
        }
    }
}

/// 一个权威 actor 的认证代际。
///
/// role / membership / access 变化时单调递增；旧 session、ticket、approval 与
/// capability 必须立即失效。本类型不 serde：外部输入不能自报代际铸造身份。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthGeneration(u64);

impl AuthGeneration {
    /// 从数据库/session 权威值构造。
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// 取出数值。
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// 铸造下一代；到顶饱和，绝不回绕让旧授权复活。
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// 从已验证上下文读取代际。
    #[must_use]
    pub const fn from_context(context: &AuthContext) -> Self {
        context.auth_generation
    }
}

impl fmt::Display for AuthGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// 已核验委托的来源；诊断输出省略标识符。
#[derive(Clone, PartialEq, Eq)]
pub enum DelegationSource {
    /// 持久自动化定义。
    AutomationDefinition {
        /// 已限定形状的来源标识符。
        definition_id: String,
    },
    /// 产品持有的外部绑定。
    ExternalBinding {
        /// 已限定形状的来源标识符。
        binding_id: String,
    },
}

impl fmt::Debug for DelegationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AutomationDefinition { .. } => "AutomationDefinition",
            Self::ExternalBinding { .. } => "ExternalBinding",
        })
    }
}

/// 保存已核验的委托事实；构造载体不判断当前有效性。
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    source: DelegationSource,
    revision: u64,
    trigger_id: String,
    granted_generation: AuthGeneration,
    expires_at: Option<SystemTime>,
}

/// 标识符形状不合法；错误不保留被拒绝的输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DelegationShapeError {
    /// 来源标识符不符合允许的 ASCII 形状。
    #[error("invalid_delegation_source_identifier")]
    InvalidSourceIdentifier,
    /// 触发标识符不符合允许的 ASCII 形状。
    #[error("invalid_delegation_trigger_identifier")]
    InvalidTriggerIdentifier,
}

impl VerifiedDelegation {
    /// 检查标识符形状后接收已核验的委托事实。
    ///
    /// 仅供受信 Application 代码调用。调用前须确认委托仍有效，并检查 owner 当前的
    /// 成员资格、角色、grant 和撤销状态；本载体不授予权限。
    #[doc(hidden)]
    #[must_use = "必须检查委托标识符的形状校验结果"]
    pub fn from_verified_grant(
        source: DelegationSource,
        revision: u64,
        trigger_id: String,
        granted_generation: AuthGeneration,
        expires_at: Option<SystemTime>,
    ) -> Result<Self, DelegationShapeError> {
        fn valid(value: &str) -> bool {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        }
        let identifier = match &source {
            DelegationSource::AutomationDefinition { definition_id } => definition_id,
            DelegationSource::ExternalBinding { binding_id } => binding_id,
        };
        if !valid(identifier) {
            return Err(DelegationShapeError::InvalidSourceIdentifier);
        }
        if !valid(&trigger_id) {
            return Err(DelegationShapeError::InvalidTriggerIdentifier);
        }
        Ok(Self {
            source,
            revision,
            trigger_id,
            granted_generation,
            expires_at,
        })
    }

    /// 已核验的来源事实。
    #[must_use]
    pub fn source(&self) -> &DelegationSource {
        &self.source
    }
    /// 委托修订号；不据此推断当前有效性。
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// 触发标识符。
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        &self.trigger_id
    }
    /// 授权事实记录的 owner 代次。
    #[must_use]
    pub const fn granted_generation(&self) -> AuthGeneration {
        self.granted_generation
    }
    /// 记录的到期时刻；`None` 表示用户明确选择“持续至撤销”，该授权不按时间到期（Run 绝对期限仍然适用）。
    #[must_use]
    pub const fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedDelegation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDelegation")
            .field("source", &self.source)
            .field("revision", &self.revision)
            .finish()
    }
}

/// 一次已认证调用的权威上下文。
///
/// # 它为什么既不 `Serialize` 也不 `Deserialize`
///
/// - 不实现 `Deserialize` 是**主约束**：只要它能被反序列化，任何 transport 都可以拿
///   renderer / 模型 / MCP server / remote Agent / browser engine 送来的字节直接造出一个
///   `AuthContext`，§5.3 与 §5.2 那两条就只剩注释效力了。类型层面拿掉这条路，误用就
///   不再是「要靠 review 发现」，而是**编译不过**。
/// - 不实现 `Serialize` 是**推论**：一个能序列化出去的鉴权上下文会诱导下游把它写进
///   请求体 / 缓存 / 日志再读回来，读回来那一步必然要求 `Deserialize`，主约束随即被
///   压力倒逼放开。同时它还直接违反 §17.2 条 8「secret 不进模型、GUI state、browser
///   event、普通日志、trace」的同类风险面。需要把身份写进日志时用
///   [`crate::telemetry::CorrelationFields`]，那是**投影**，不是上下文本身。
///
/// 字段全部私有，只读 getter，构造入口：
///
/// 1. [`AuthContextBuilder::from_verified_session`]（生产路径，`#[doc(hidden)]`）；
/// 2. [`AuthContext::for_test`]（`testkit` feature 或 `cfg(test)` 下才存在，默认关）。
///
/// 委托上下文由 [`AuthContextBuilder::from_verified_delegation`] 接收受信核验结果；
/// 测试另有 feature-gated 委托构造器。生产 transport 拿不到测试入口。
#[derive(Clone)]
pub struct AuthContext {
    deployment: DeploymentId,
    tenant: TenantId,
    actor: ActorId,
    roles: BTreeSet<Role>,
    auth_generation: AuthGeneration,
    single_user: bool,
    request_binding: Option<Arc<crate::request_binding::VerifiedHostRequestBinding>>,
    delegation: Option<Arc<VerifiedDelegation>>,
}

impl AuthContext {
    /// 委托事实；不证明存在当前已登记的 Run。
    #[must_use]
    pub fn delegation(&self) -> Option<&VerifiedDelegation> {
        self.delegation.as_deref()
    }

    /// 非 Serde 宿主绑定；getter 本身不证明当前权限。
    pub fn request_binding(&self) -> Option<&crate::request_binding::VerifiedHostRequestBinding> {
        self.request_binding.as_deref()
    }

    /// 受信 host 在 builder 完成后消费式附加，核原六项身份。
    #[doc(hidden)]
    pub fn with_verified_request_binding(
        mut self,
        binding: crate::request_binding::VerifiedHostRequestBinding,
    ) -> Result<Self, crate::request_binding::RequestBindingAttachError> {
        if !binding.matches_auth(&self) {
            return Err(crate::request_binding::RequestBindingAttachError::IdentityMismatch);
        }
        self.request_binding = Some(Arc::new(binding));
        Ok(self)
    }
    /// 部署身份。
    #[must_use]
    pub fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// 租户身份。一切 scope 判定的最外层（§17.2 条 12）。
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// 行动者身份。
    #[must_use]
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 已由数据库 ACL 解析出的角色集合。
    #[must_use]
    pub fn roles(&self) -> &BTreeSet<Role> {
        &self.roles
    }

    /// auth generation。session 失效 / 角色变更时递增；旧 generation 的 ticket 与 capability
    /// 全部失效（§12.4 校验项之一）。
    #[must_use]
    pub const fn auth_generation(&self) -> AuthGeneration {
        self.auth_generation
    }

    /// 是否处于单用户模式（`OPENBOT_SINGLE_USER`，§15.4 preserve）。
    ///
    /// 它是**部署形态**，不是权限判定的替身：单用户模式下仍然要走 [`Self::has_role`]。
    #[must_use]
    pub fn is_single_user(&self) -> bool {
        self.single_user
    }

    /// 是否持有某个角色。
    ///
    /// 刻意**不**提供 `is_admin()` 之类的便捷方法：调用点必须把它在检查什么写出来。
    /// `if auth.is_admin()` 读起来像一句结论，`if auth.has_role(Role::Admin)` 读起来是
    /// 一次可被 grep、可被 review、可被 audit 对照的具体判定。
    #[must_use]
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// 测试用构造器。
    ///
    /// 只在 `cfg(test)` 或显式打开 `testkit` feature 时存在（两者默认都不在生产
    /// feature 图里）。这是「受限构造入口」的另一半：生产 transport 即使想绕过
    /// [`AuthContextBuilder`] 也拿不到这个函数，因为它压根没被编译进去。
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn for_test(
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        roles: impl IntoIterator<Item = Role>,
        auth_generation: AuthGeneration,
        single_user: bool,
    ) -> Self {
        Self {
            deployment,
            tenant,
            actor,
            roles: roles.into_iter().collect(),
            auth_generation,
            single_user,
            request_binding: None,
            delegation: None,
        }
    }
    /// 测试用委托载体，身份和角色均由调用方明确提供。
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn for_test_delegated(
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        roles: impl IntoIterator<Item = Role>,
        auth_generation: AuthGeneration,
        single_user: bool,
        delegation: VerifiedDelegation,
    ) -> Self {
        Self {
            deployment,
            tenant,
            actor,
            roles: roles.into_iter().collect(),
            auth_generation,
            single_user,
            request_binding: None,
            delegation: Some(Arc::new(delegation)),
        }
    }
}

impl PartialEq for AuthContext {
    fn eq(&self, other: &Self) -> bool {
        self.deployment == other.deployment
            && self.tenant == other.tenant
            && self.actor == other.actor
            && self.roles == other.roles
            && self.auth_generation == other.auth_generation
            && self.single_user == other.single_user
            && self.delegation == other.delegation
    }
}
impl Eq for AuthContext {}
impl core::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthContext")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("actor", &self.actor)
            .field("roles", &self.roles)
            .field("auth_generation", &self.auth_generation)
            .field("single_user", &self.single_user)
            .field("request_binding_present", &self.request_binding.is_some())
            .field("delegation_present", &self.delegation.is_some())
            .finish()
    }
}

/// [`AuthContext`] 的受信生产构造入口。
///
/// Rust 没有 crate 外可见的「友元」，所以受限性由三件事叠加表达，而不是靠单一机制：
///
/// 1. 构造函数名 [`Self::from_verified_session`] 本身就是一句**断言**：调用点必须能指出
///    session、连接 peer、数据库 ACL 三者各自的来源。名字不叫 `new` 是刻意的 —— `new`
///    邀请任何人调用，`from_verified_session` 在 code review 里会立刻引出「verified by
///    what?」这个问题。
/// 2. 它标注 `#[doc(hidden)]`：不出现在生成的 API 文档里，不会被下游当成常规入口翻到。
/// 3. 参数表强制一次性交齐部署 / 租户 / actor / auth generation / 单用户形态 —— 拿不齐
///    这几样的调用点根本编译不过，而拿得齐就意味着它已经在认证层。
///
/// **只有 `openbot-application` 及其下游的认证实现可以调用它。** transport（Axum / Tauri）
/// 只做认证、framing、大小限制与错误映射（§5.2），它把凭据交给认证实现，不自己铸造上下文。
pub struct AuthContextBuilder {
    context: AuthContext,
}

impl AuthContextBuilder {
    /// 从**已验证**的 session / peer / ACL 结果开始构造。
    ///
    /// 调用点必须能指出：`deployment` / `tenant` / `actor` 来自哪次 session 校验或连接 peer
    /// 校验，角色来自哪次数据库 ACL 查询。renderer、模型、MCP server、remote Agent、browser
    /// engine 送来的同名字段**不是**这些来源 —— 它们是普通不可信输入（§5.3）。
    #[doc(hidden)]
    #[must_use]
    pub fn from_verified_session(
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        auth_generation: AuthGeneration,
        single_user: bool,
    ) -> Self {
        Self {
            context: AuthContext {
                deployment,
                tenant,
                actor,
                roles: BTreeSet::new(),
                auth_generation,
                single_user,
                request_binding: None,
                delegation: None,
            },
        }
    }

    /// 从已核验委托和 owner 当前事实开始构造；角色从空集合积累。
    ///
    /// 仅供受信 Application 代码调用。调用前须确认当前 `auth_generation` 与
    /// `delegation.granted_generation()` 相等，追加的角色只能取自当前数据库 ACL；
    /// 接收委托载体本身不产生授权。
    #[doc(hidden)]
    #[must_use]
    pub fn from_verified_delegation(
        deployment: DeploymentId,
        tenant: TenantId,
        owner: ActorId,
        auth_generation: AuthGeneration,
        single_user: bool,
        delegation: VerifiedDelegation,
    ) -> Self {
        Self {
            context: AuthContext {
                deployment,
                tenant,
                actor: owner,
                roles: BTreeSet::new(),
                auth_generation,
                single_user,
                request_binding: None,
                delegation: Some(Arc::new(delegation)),
            },
        }
    }

    /// 追加一个由数据库 ACL 解析出的角色。
    ///
    /// 角色是**逐个追加**而不是一次性传入的：ACL 查询往往分多步（租户成员资格、bot 授权、
    /// channel `allowed_groups`），逐个追加让每个角色都能追溯到一次具体查询。
    #[must_use]
    pub fn with_role(mut self, role: Role) -> Self {
        self.context.roles.insert(role);
        self
    }

    /// 批量追加角色。
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = Role>) -> Self {
        self.context.roles.extend(roles);
        self
    }

    /// 收口成 [`AuthContext`]。
    #[must_use]
    pub fn build(self) -> AuthContext {
        self.context
    }
}

#[cfg(test)]
#[path = "auth_delegation_tests.rs"]
mod delegation_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// 探测某类型是否实现了 `DeserializeOwned`。
    ///
    /// 手法：inherent 方法优先于 trait 方法，而 where 子句不满足的 inherent 候选会在方法
    /// 探测阶段被剔除，于是回落到 trait 的默认实现。这样「有没有实现某 trait」变成一个
    /// 可在测试里断言的运行期布尔值 —— 否则「没实现 Deserialize」这条契约只能靠人眼守。
    struct DeserializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> DeserializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait DeserializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> DeserializeProbeFallback for DeserializeProbe<T> {}

    /// 同上，探测 `Serialize`。
    struct SerializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> SerializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::Serialize> SerializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait SerializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> SerializeProbeFallback for SerializeProbe<T> {}

    fn sample() -> AuthContext {
        AuthContextBuilder::from_verified_session(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new("actor-1"),
            AuthGeneration::new(3),
            false,
        )
        .with_role(Role::User)
        .build()
    }

    /// 负向对照：`AuthContext` 两个方向都不可 serde —— transport 无法凭外部字节造出它。
    #[test]
    fn auth_context_implements_neither_serialize_nor_deserialize() {
        assert!(
            !DeserializeProbe::<AuthContext>::new().is_implemented(),
            "AuthContext 一旦可反序列化，§5.3 的构造约束就只剩注释效力"
        );
        assert!(
            !SerializeProbe::<AuthContext>::new().is_implemented(),
            "可序列化会诱导下游写出去再读回来，反过来逼着放开 Deserialize"
        );
        assert!(!DeserializeProbe::<AuthGeneration>::new().is_implemented());
        assert!(!SerializeProbe::<AuthGeneration>::new().is_implemented());
    }

    /// 正向对照：同一对探测器在**确实实现了** serde 的类型上返回 true。
    ///
    /// 没有这一条，上一条测试在「探测器恒返回 false」的世界里同样通过 —— 那是一个
    /// 什么都证明不了的断言。
    #[test]
    fn serde_probes_are_not_constant_false_detectors() {
        assert!(
            DeserializeProbe::<crate::command::ChannelPage>::new().is_implemented(),
            "DTO 确实可反序列化；否则探测器本身是坏的"
        );
        assert!(
            SerializeProbe::<crate::command::ChannelPage>::new().is_implemented(),
            "DTO 确实可序列化；否则探测器本身是坏的"
        );
        assert!(DeserializeProbe::<Role>::new().is_implemented());
        assert!(SerializeProbe::<Role>::new().is_implemented());
    }

    #[test]
    fn builder_starts_with_no_roles_and_accumulates() {
        let bare = AuthContextBuilder::from_verified_session(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new("actor-1"),
            AuthGeneration::new(0),
            true,
        )
        .build();
        assert!(
            bare.roles().is_empty(),
            "不给角色就是零角色，没有隐式 admin"
        );
        assert!(!bare.has_role(Role::Admin));
        assert!(!bare.has_role(Role::User));
        assert!(bare.is_single_user());

        let escalated = AuthContextBuilder::from_verified_session(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new("actor-1"),
            AuthGeneration::new(0),
            true,
        )
        .with_roles([Role::User, Role::Admin])
        .build();
        assert!(escalated.has_role(Role::Admin));
        assert!(escalated.has_role(Role::User));
        assert_eq!(escalated.roles().len(), 2);
    }

    #[test]
    fn getters_return_what_was_verified() {
        let auth = sample();
        assert_eq!(auth.deployment().as_str(), "dep-1");
        assert_eq!(auth.tenant().as_str(), "tenant-1");
        assert_eq!(auth.actor().as_str(), "actor-1");
        assert_eq!(auth.auth_generation(), AuthGeneration::new(3));
        assert!(!auth.is_single_user());
        assert!(auth.has_role(Role::User));
        assert!(!auth.has_role(Role::Admin));
    }

    #[test]
    fn for_test_constructor_is_available_under_cfg_test() {
        let auth = AuthContext::for_test(
            DeploymentId::new("dep-2"),
            TenantId::new("tenant-2"),
            ActorId::new("actor-2"),
            [Role::Admin],
            AuthGeneration::new(9),
            false,
        );
        assert!(auth.has_role(Role::Admin));
        assert_eq!(auth.auth_generation(), AuthGeneration::new(9));
    }

    /// 未知角色字符串 fail-closed，不静默降级成 `User`。
    #[test]
    fn unknown_role_string_is_rejected_not_downgraded() {
        assert_eq!("admin".parse::<Role>(), Ok(Role::Admin));
        assert_eq!("user".parse::<Role>(), Ok(Role::User));
        // 负向：拼错、大小写不符、空串一律拒绝。
        assert_eq!("Admin".parse::<Role>(), Err(UnknownRole));
        assert_eq!("superuser".parse::<Role>(), Err(UnknownRole));
        assert_eq!("".parse::<Role>(), Err(UnknownRole));
    }

    #[test]
    fn role_wire_representation_matches_database_enum() {
        assert_eq!(Role::Admin.as_str(), "admin");
        assert_eq!(Role::User.as_str(), "user");
        assert_eq!(serde_json::to_string(&Role::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&Role::User).unwrap(), "\"user\"");
    }

    #[test]
    fn anonymous_auth_contract_is_closed_canonical_and_contains_no_enterprise_identity() {
        let capabilities = AuthenticationCapabilities {
            mode: ApplicationRuntimeMode::Rust,
            durable_history: true,
            auth_providers: vec![
                AuthProviderId::Google,
                AuthProviderId::Microsoft,
                AuthProviderId::Okta,
            ],
            sso_configured: true,
        };
        assert!(capabilities.is_canonical());
        assert_eq!(
            serde_json::to_string(&capabilities).unwrap(),
            r#"{"mode":"rust","durableHistory":true,"authProviders":["google","microsoft","okta"],"ssoConfigured":true}"#
        );
        assert_eq!(
            serde_json::from_str::<AuthenticationCapabilities>(
                r#"{"mode":"rust","durableHistory":true,"authProviders":["google","microsoft","okta"],"ssoConfigured":true}"#
            )
            .unwrap(),
            capabilities
        );

        for noncanonical in [
            vec![AuthProviderId::Google, AuthProviderId::Google],
            vec![AuthProviderId::Okta, AuthProviderId::Google],
        ] {
            assert!(
                !AuthenticationCapabilities {
                    mode: ApplicationRuntimeMode::Rust,
                    durable_history: true,
                    auth_providers: noncanonical,
                    sso_configured: false,
                }
                .is_canonical()
            );
        }
        assert!(serde_json::from_str::<AuthenticationCapabilities>(
            r#"{"mode":"rust","durableHistory":true,"authProviders":["acme-saml"],"ssoConfigured":true}"#
        )
        .is_err());
        assert_eq!("google".parse(), Ok(AuthProviderId::Google));
        assert_eq!(
            "acme-saml".parse::<AuthProviderId>(),
            Err(UnknownAuthProvider)
        );
    }

    #[test]
    fn sign_in_start_and_enterprise_route_receipts_have_exact_wire_shapes() {
        assert_eq!(
            serde_json::to_string(&AuthenticationStartResponse {
                url: "https://idp.example/authorize?state=opaque".to_owned(),
            })
            .unwrap(),
            r#"{"url":"https://idp.example/authorize?state=opaque"}"#
        );
        assert_eq!(
            serde_json::to_string(&EnterpriseSsoStartRequest {
                email: "person@example.com".to_owned(),
            })
            .unwrap(),
            r#"{"email":"person@example.com"}"#
        );
        assert_eq!(
            serde_json::to_string(&EnterpriseSsoRoutingAccepted { accepted: true }).unwrap(),
            r#"{"accepted":true}"#
        );
    }
}
