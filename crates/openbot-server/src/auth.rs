//! 认证边界 —— [`AuthResolver`] port 与它在 Axum 侧的提取器 [`Authenticated`] /
//! [`OriginAuthenticated`]。
//!
//! # port 与 W-4 production 实现
//!
//! `openbot_contracts::auth::AuthContext` **刻意既不 `Serialize` 也不 `Deserialize`**
//! （§5.3）：只要它能被反序列化，任何 transport 都可以拿 renderer / 模型 / MCP server /
//! remote Agent 送来的字节直接铸造一个身份。生产构造入口因此只有一个 ——
//! `AuthContextBuilder::from_verified_session`，而它的名字本身就是一句断言：调用点必须
//! 能指出 session、连接 peer、数据库 ACL 三者各自的来源。
//!
//! [`PostgresSessionAuthResolver`] 是 W-4 production 实现：只认 `openbot_session` cookie，
//! HMAC-SHA256 后查库，要求 0015 session generation、当前 user generation、deny list、role、
//! absolute/idle 全通过；旧 plaintext/NULL-generation session 统一 401。
//!
//! # 没有默认放行
//!
//! 这是刻意的，不是"还没写"。一个默认可用的 `AuthResolver` 会在生产里变成后门：它一旦
//! 存在，接线层忘记注入真实实现就不会编译失败，只会静默地把每个请求当成合法用户。
//! 所以 [`ServerBuilder::new`](crate::http::ServerBuilder::new) 强制传入一个
//! `Arc<dyn AuthResolver>` —— 拿不出实现的宿主根本组装不出 router。
//!
//! [`FixedAuthResolver`] 与单用户固定身份测试构造器均被 `#[cfg(any(test, feature = "testkit"))]`
//! 挡在默认 feature 图之外（`testkit` 默认关）。它也不提供 `Default`：身份必须由调用方
//! 显式交出来，写不出 `FixedAuthResolver::default()` 这种"从哪来的身份？"的代码。
//!
//! # 组装链路
//!
//! ```text
//! openbot-server（本 crate）      定义 AuthResolver port
//!         ↑ 实现
//! PostgresSessionAuthResolver       把 keyed session + DB ACL 组装成权威身份，
//!                                 内部调用 AuthContextBuilder::from_verified_session
//!         ↓ 注入
//! ServerBuilder::new(app, auth)   router 拿到 Arc<dyn AuthResolver>
//! ```
//!
//! [`SingleUserAuthResolver`] 只由二进制在显式 `OPENBOT_SINGLE_USER=true` 且 loopback 绑定时构造。
//! OIDC/SAML 登录与 session 签发已由 W-7 接通；G2 仍因外审、KMS/HSM 与跨平台原生发行未闭合。

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use http::request::Parts;
use openbot_application::runtime_capabilities::{
    CapabilityDeadline, RuntimeCapabilitiesCollectionError, RuntimeCapabilitiesCollector,
    RuntimeCapabilitiesFuture, RuntimeCapabilityHostScope, RuntimeCapabilityObservationResult,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::error::{AppError, SensitiveWriteReason};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use openbot_contracts::request_binding::{
    ArtifactCleanupHostObservation, ArtifactCleanupHostTailFactory, ArtifactCleanupHostTailWitness,
    ArtifactCleanupHostTarget, ArtifactCleanupSessionFacts, ArtifactReadCurrentError,
    ArtifactReadCurrentTarget, ArtifactReadTailWitness, SourceRunArtifactIdsCurrentCheck,
    SourceRunArtifactIdsCurrentTarget,
};
use openbot_contracts::request_binding::{
    CustomModelCatalogHostObservation, CustomModelCatalogHostTailFactory,
    CustomModelCatalogHostTailWitness, CustomModelCatalogHostTarget,
    CustomModelCatalogSessionFacts,
};
use openbot_contracts::request_binding::{
    GatewayAuthorizationCallbackUrlInvocation, GatewayAuthorizationCallbackUrlPort,
    GatewayAuthorizationCallbackUrlReceiver, GatewayAuthorizationHostObservation,
    GatewayAuthorizationHostTailFactory, GatewayAuthorizationHostTailWitness,
    GatewayAuthorizationHostTarget, GatewayAuthorizationSessionFacts, HostRequestBindingIdentity,
};
use openbot_contracts::request_binding::{
    HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
    RememberPreferenceHostObservation, RememberPreferenceHostTailFactory,
    RememberPreferenceHostTailWitness, RememberPreferenceHostTarget,
    RememberPreferenceSessionFacts, RequestBindingIssuer, RequestBindingOwnerLease,
    RequestBindingOwnerObservation, ServerSessionBindingIdentity,
};
use openbot_domain::identity::roles::resolve_effective_role;
use openbot_domain::identity::session::{
    LiveSession, SensitiveWriteApproved, SensitiveWriteRejection, SensitiveWriteRequest,
    SessionHashKey, SessionLifetimePolicy, SessionState, SessionToken, SessionTokenHash,
    TrustedOrigins, authorize_fresh_origin_write, authorize_sensitive_write, evaluate_session,
};
use openbot_infra::approval_preferences::PostgresRememberPreferenceRepository;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use openbot_infra::artifact_read_authority::PostgresArtifactReadAuthority;
use openbot_infra::auth::sso::ReadOnlySsoCapabilitySource;
use openbot_infra::custom_model_catalog::PostgresCustomModelCatalogInventory;
use openbot_infra::runtime_capability_facts::{
    PostgresRuntimeCapabilityFacts, RuntimeCapabilityCollectorFactory,
    RuntimeCapabilityRevisionOwner,
};
use openbot_infra::{
    GatewayAuthorizationJournal, GatewayAuthorizationJournalError,
    GatewayAuthorizationJournalRuntimeOwner,
};
use std::sync::{Arc, Weak};
use time::OffsetDateTime;
use tracing::Span;

use crate::error::HttpError;
use crate::http::ServerState;
use crate::telemetry::ACTOR_ID_FIELD;

type GatewayAuthorizationJournalAssembly = (
    Arc<GatewayAuthorizationJournalRuntimeOwner>,
    Arc<GatewayAuthorizationJournal>,
);

/// Assemble the optional journal once from the original validated startup configuration and Pool.
/// The private installation label is borrowed only inside this Server crate; absence performs no RNG or I/O.
pub fn assemble_gateway_authorization_journal(
    server: &crate::config::ServerConfig,
    pool: openbot_infra::db::pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: openbot_domain::vault::SecretBytes,
) -> Result<Option<GatewayAuthorizationJournalAssembly>, GatewayAuthorizationJournalError> {
    let Some(installation) = server.gateway_authorization_installation_id.as_ref() else {
        return Ok(None);
    };
    let runtime = Arc::new(GatewayAuthorizationJournalRuntimeOwner::new(
        pool.clone(),
        deployment.clone(),
        tenant.clone(),
        installation.as_str(),
    )?);
    let journal = Arc::new(GatewayAuthorizationJournal::new(
        pool, deployment, tenant, audit_key, &runtime,
    )?);
    Ok(Some((runtime, journal)))
}

/// 把一次请求的认证材料解析成权威身份。
///
/// 实现必须只依据**服务端可验证**的东西：session cookie 对应的 session 行、连接 peer、
/// 数据库 ACL。请求头里自称的角色、`principal`、租户一律是普通不可信输入（§5.3）。
///
/// 入参是 `&Parts` 而不是整个 `Request`：认证只看头部与扩展，看不到 body。这条限制是
/// 构造性的 —— 一个拿不到 body 的实现不可能"从请求体里读身份"。
#[async_trait]
pub trait AuthResolver: Send + Sync {
    /// Only an actual resolver can issue a factory retaining its private owner provenance.
    fn runtime_capability_factory(
        &self,
        _sso: Option<ReadOnlySsoCapabilitySource>,
    ) -> Result<Arc<dyn RuntimeCapabilityCollectorFactory>, RuntimeCapabilitiesCollectionError>
    {
        Err(RuntimeCapabilitiesCollectionError::MissingHostSource)
    }
    /// 从请求的认证材料解析出权威身份。
    ///
    /// # Errors
    ///
    /// 无凭据 / 凭据无效 / session 已失效 → [`AppError::Unauthenticated`]（401）。
    /// 依赖（session store、目录服务）不可用 → [`AppError::DependencyUnavailable`]（503）；
    /// **不得**在依赖不可用时放行，也不得把它伪装成 401 —— 前者是后门，后者会让运维
    /// 在一堆"用户登录失败"里找不到真正的故障。
    async fn resolve(&self, parts: &Parts) -> Result<AuthContext, AppError>;

    /// 同一次认证附带 live-session assurance；普通实现缺省只有身份，敏感写会 fail-closed。
    async fn resolve_with_assurance(&self, parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.resolve(parts).await.map(ResolvedAuth::without_session)
    }

    /// 在相应认证/CSRF guard 已通过后推进 idle 活动时刻；无状态实现无需动作。
    async fn touch(&self, _resolved: &ResolvedAuth) -> Result<(), AppError> {
        Ok(())
    }

    /// Close actual host bindings before its graceful drain or resource teardown.
    /// Implementations without a real binding owner have nothing to close.
    fn close_request_bindings(&self) {}

    /// Revoke exactly the concrete session carried by this resolved request.
    ///
    /// Stateless/single-user implementations have no row to revoke and fail explicitly.
    async fn revoke_session(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let _ = resolved;
        Err(AppError::RequestConflict {
            resource: "session",
        })
    }
}

/// 一次已解析身份，以及敏感写所需的 live-session 证明。
#[derive(Clone, Debug)]
pub struct ResolvedAuth {
    context: AuthContext,
    live_session: Option<LiveSession>,
    session_id: Option<String>,
}

impl ResolvedAuth {
    /// 只有身份、没有 session assurance；敏感写必须拒绝。
    #[must_use]
    pub const fn without_session(context: AuthContext) -> Self {
        Self {
            context,
            live_session: None,
            session_id: None,
        }
    }

    /// 由已验证数据库 session 构造。
    #[must_use]
    pub fn from_live_session(
        context: AuthContext,
        live_session: LiveSession,
        session_id: Option<String>,
    ) -> Self {
        Self {
            context,
            live_session: Some(live_session),
            session_id,
        }
    }

    /// 权威上下文。
    #[must_use]
    pub const fn context(&self) -> &AuthContext {
        &self.context
    }

    /// live session；`None` 时敏感写 fail-closed。
    #[must_use]
    pub const fn live_session(&self) -> Option<&LiveSession> {
        self.live_session.as_ref()
    }

    /// Whether this request is backed by one concrete, individually revocable session row.
    #[must_use]
    pub const fn has_revocable_session(&self) -> bool {
        self.session_id.is_some()
    }

    /// 交出上下文。
    #[must_use]
    pub fn into_context(self) -> AuthContext {
        self.context
    }

    fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// 已认证请求的提取器。
///
/// 把认证做成**提取器**而不是 handler 里的一行调用，是为了让"这条路由要不要认证"
/// 出现在 handler 的签名里：`list(_, Authenticated(auth), _)` 一眼可见，
/// 而漏写一行 `let auth = resolve(...)` 不会有任何东西提醒你。
///
/// 它同时是 §16.4「只取需要的 ID 字段」的落点：解析成功后只把 `actor_id` 记进当前 span，
/// **绝不**把 `AuthContext` 整体（角色集合、auth generation）交给 tracing。
pub struct Authenticated(pub AuthContext);

impl FromRequestParts<ServerState> for Authenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        state.auth_resolver().touch(&resolved).await?;
        let auth = resolved.into_context();
        // 只记 ID，不记上下文本体。`AuthContext` 没有 `Serialize`，但它**有** `Debug`，
        // 而 `Debug` 会把角色集合与 auth generation 一起打出来 —— 那是那道防线上的缺口。
        // 这里用 `Display` 只投影一个 ID 字段，把缺口堵上。
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// 已认证且携带 session assurance 的请求；敏感 admin 写 handler 使用。
pub struct SensitiveAuthenticated(pub ResolvedAuth);

impl FromRequestParts<ServerState> for SensitiveAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        Span::current().record(
            ACTOR_ID_FIELD,
            tracing::field::display(resolved.context().actor()),
        );
        Ok(Self(resolved))
    }
}

/// Fresh administrator + trusted-Origin authority resolved before any request body is read.
///
/// Unlike [`SensitiveAuthenticated`], this extractor completes the sensitive-write decision inside
/// `FromRequestParts`. A following `Json` extractor therefore cannot parse an attacker-controlled
/// body when Origin/session/admin assurance has already failed.
pub struct SensitiveOriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for SensitiveOriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        state.authorize_sensitive_write(&resolved, origin).await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// Fresh authenticated + trusted-Origin authority resolved before any owner-managed secret/body.
/// Resource ownership remains an application/infra decision; unlike
/// [`SensitiveOriginAuthenticated`], ordinary members are not rejected for lacking admin role.
pub struct FreshOriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for FreshOriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        state
            .authorize_fresh_origin_write(&resolved, origin)
            .await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// 已认证的 same-origin 操作；trusted Origin 在任何 body/upgrade 业务运行前判定。
///
/// `FromRequestParts` 构造性拿不到 body，Memory 写与 thread WebSocket 共用它，避免 CSRF
/// 失败仍读取 body 或建立能外泄 durable thread 的 cross-origin socket。
pub struct OriginAuthenticated(pub AuthContext);

impl FromRequestParts<ServerState> for OriginAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .map(|value| value.to_str().unwrap_or(""));
        if parts.method == http::Method::GET
            && parts.uri.path() == crate::http::custom_model_catalog::PATH
        {
            state.authorize_custom_model_catalog_origin(origin)?;
        } else {
            state
                .authorize_authenticated_origin(&resolved, origin)
                .await?;
        }
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self(auth))
    }
}

/// Same-origin authenticated request retaining the exact verified Origin for ticket binding.
pub struct OriginBoundAuthenticated {
    auth: AuthContext,
    origin: String,
}

impl OriginBoundAuthenticated {
    /// Split the authority context and exact verified Origin.
    #[must_use]
    pub fn into_parts(self) -> (AuthContext, String) {
        (self.auth, self.origin)
    }
}

impl FromRequestParts<ServerState> for OriginBoundAuthenticated {
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = state.auth_resolver().resolve_with_assurance(parts).await?;
        let origin = parts
            .headers
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginMissing,
            })?
            .to_owned();
        state
            .authorize_authenticated_origin(&resolved, Some(origin.as_str()))
            .await?;
        let auth = resolved.into_context();
        Span::current().record(ACTOR_ID_FIELD, tracing::field::display(auth.actor()));
        Ok(Self { auth, origin })
    }
}

/// 敏感 admin 写的 session/origin 配置；未注入时 ServerState 会 fail-closed。
#[derive(Clone, Debug)]
pub struct SensitiveWriteSecurity {
    lifetime: SessionLifetimePolicy,
    trusted_origins: TrustedOrigins,
}

impl SensitiveWriteSecurity {
    /// 由启动期已验证配置构造。
    #[must_use]
    pub const fn new(lifetime: SessionLifetimePolicy, trusted_origins: TrustedOrigins) -> Self {
        Self {
            lifetime,
            trusted_origins,
        }
    }

    /// 判定一次写；specific domain 原因逐项映射到稳定 contracts code。
    pub fn authorize(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<SensitiveWriteApproved, AppError> {
        let Some(session) = resolved.live_session() else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        };
        let role = if resolved.context().has_role(Role::Admin) {
            Role::Admin
        } else {
            Role::User
        };
        authorize_sensitive_write(
            self.lifetime,
            &self.trusted_origins,
            &SensitiveWriteRequest {
                session,
                role,
                origin,
            },
        )
        .map_err(|rejection| AppError::SensitiveWriteRefused {
            reason: match rejection {
                SensitiveWriteRejection::RoleInsufficient => SensitiveWriteReason::RoleInsufficient,
                SensitiveWriteRejection::OriginMissing => SensitiveWriteReason::OriginMissing,
                SensitiveWriteRejection::OriginUntrusted => SensitiveWriteReason::OriginUntrusted,
                SensitiveWriteRejection::SessionNotFresh => SensitiveWriteReason::SessionNotFresh,
            },
        })
    }

    /// 普通已认证 same-origin 操作只要求可信 Origin，不要求 admin/fresh；用于 owner memory
    /// 写与 thread WebSocket，避免跨站带 cookie 读取 durable event。
    pub fn authorize_origin(&self, origin: Option<&str>) -> Result<(), AppError> {
        let Some(origin) = origin else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginMissing,
            });
        };
        if !self.trusted_origins.trusts(origin) {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::OriginUntrusted,
            });
        }
        Ok(())
    }

    /// Fresh same-origin credential write; resource ownership/admin is checked in application/DB.
    pub fn authorize_fresh_origin(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<(), AppError> {
        let Some(session) = resolved.live_session() else {
            return Err(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        };
        authorize_fresh_origin_write(self.lifetime, &self.trusted_origins, session, origin)
            .map(|_| ())
            .map_err(|rejection| AppError::SensitiveWriteRefused {
                reason: match rejection {
                    SensitiveWriteRejection::RoleInsufficient => {
                        SensitiveWriteReason::RoleInsufficient
                    }
                    SensitiveWriteRejection::OriginMissing => SensitiveWriteReason::OriginMissing,
                    SensitiveWriteRejection::OriginUntrusted => {
                        SensitiveWriteReason::OriginUntrusted
                    }
                    SensitiveWriteRejection::SessionNotFresh => {
                        SensitiveWriteReason::SessionNotFresh
                    }
                },
            })
    }
}

/// Rust multi-user session cookie 名；不复用 Better Auth cookie，切换时旧会话统一失效。
pub const SESSION_COOKIE_NAME: &str = "openbot_session";

/// PostgreSQL session + ACL 的生产 resolver。
#[derive(Clone)]
pub struct PostgresSessionAuthResolver {
    pool: openbot_infra::db::pool::DatabasePool,
    hash_key: std::sync::Arc<[u8]>,
    lifetime: SessionLifetimePolicy,
    deployment: DeploymentId,
    tenant: TenantId,
    binding_owner: Arc<ServerSessionBindingOwner>,
}

// Only the resolver owner owns the lifecycle lease. A current-check await may keep a probe
// allocated, but that independent probe cannot keep the real owner's lease running.
struct ServerSessionBindingOwner {
    lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    probe: Arc<ServerSessionProbeState>,
}

impl Drop for ServerSessionBindingOwner {
    fn drop(&mut self) {
        self.lease.close();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(authority) = self
            .probe
            .artifact_read_authority
            .get()
            .and_then(Weak::upgrade)
        {
            authority.read_lifecycle().close_issuer(&self.issuer);
        }
    }
}

struct ServerSessionProbeState {
    pool: openbot_infra::db::pool::DatabasePool,
    lifetime: SessionLifetimePolicy,
    deployment: DeploymentId,
    tenant: TenantId,
    capability_facts: std::sync::OnceLock<Weak<PostgresRuntimeCapabilityFacts>>,
    remember_preferences: std::sync::OnceLock<Weak<PostgresRememberPreferenceRepository>>,
    custom_model_catalog_inventory: std::sync::OnceLock<Weak<PostgresCustomModelCatalogInventory>>,
    gateway_authorization_journal: std::sync::OnceLock<Weak<GatewayAuthorizationJournal>>,
    callback_url_sink: std::sync::OnceLock<Arc<GatewayCallbackUrlSink>>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    artifact_read_authority: std::sync::OnceLock<Weak<PostgresArtifactReadAuthority>>,
}

// The destination is deliberately uninstalled in production main. This fixed
// bounded sink is the only installer input; callers cannot supply a trait or Fn.
struct GatewayCallbackUrlSink {
    state: std::sync::Mutex<GatewayCallbackUrlSinkState>,
}

struct GatewayCallbackUrlSinkState {
    url: Option<zeroize::Zeroizing<String>>,
    offered: bool,
}

impl GatewayCallbackUrlSink {
    #[allow(
        dead_code,
        reason = "The production callback URL destination remains disabled"
    )]
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(GatewayCallbackUrlSinkState {
                url: Some(zeroize::Zeroizing::new(String::with_capacity(2048))),
                offered: false,
            }),
        })
    }

    #[allow(
        dead_code,
        reason = "Only the owned synthetic destination consumes the URL"
    )]
    fn take_url(&self) -> Result<zeroize::Zeroizing<String>, HostRequestBindingError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        if !state.offered {
            return Err(HostRequestBindingError::Unavailable);
        }
        state.url.take().ok_or(HostRequestBindingError::Unavailable)
    }
}

impl GatewayAuthorizationCallbackUrlReceiver for GatewayCallbackUrlSink {
    fn accept_url(&self, url: &str) -> Result<(), HostRequestBindingError> {
        if url.len() > 2048 {
            return Err(HostRequestBindingError::Unavailable);
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        if state.offered {
            return Err(HostRequestBindingError::Unavailable);
        }
        let owned = state
            .url
            .as_mut()
            .ok_or(HostRequestBindingError::Unavailable)?;
        owned.push_str(url);
        state.offered = true;
        Ok(())
    }
}

impl core::fmt::Debug for GatewayCallbackUrlSink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GatewayCallbackUrlSink([redacted])")
    }
}

enum ServerGatewayCallbackSource {
    Session(Weak<ServerSessionProbeState>),
    SingleUser(Weak<SingleUserProbeState>),
}

struct ServerGatewayCallbackUrlPort {
    source: ServerGatewayCallbackSource,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    identity: HostRequestBindingIdentity,
    original: AuthContext,
}

impl ServerGatewayCallbackUrlPort {
    fn check(
        &self,
        auth: &AuthContext,
        target: &dyn GatewayAuthorizationHostTarget,
        deadline: std::time::Instant,
    ) -> Result<Arc<GatewayCallbackUrlSink>, HostRequestBindingError> {
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        if auth != &self.original || !self.owner.is_current() || !target.matches_auth(auth) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if !self.issuer.owns_identity(binding.identity())
            || !self.identity.same_binding(binding.identity())
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        match &self.source {
            ServerGatewayCallbackSource::Session(original_probe) => {
                let probe = original_probe
                    .upgrade()
                    .ok_or(HostRequestBindingError::NotCurrent)?;
                let journal = probe
                    .gateway_authorization_journal
                    .get()
                    .and_then(Weak::upgrade)
                    .ok_or(HostRequestBindingError::Unavailable)?;
                if binding.kind() != HostRequestBindingKind::ServerSession
                    || !journal.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
                    || !journal.matches_host_target(target)
                {
                    return Err(HostRequestBindingError::NotCurrent);
                }
                self.issuer
                    .borrow_server_session_epoch(binding.identity())?;
                probe
                    .callback_url_sink
                    .get()
                    .cloned()
                    .ok_or(HostRequestBindingError::Unavailable)
            }
            ServerGatewayCallbackSource::SingleUser(original_probe) => {
                let probe = original_probe
                    .upgrade()
                    .ok_or(HostRequestBindingError::NotCurrent)?;
                let enrollment = probe
                    .gateway_authorization_journal
                    .get()
                    .ok_or(HostRequestBindingError::Unavailable)?;
                let journal = enrollment
                    .journal
                    .upgrade()
                    .ok_or(HostRequestBindingError::Unavailable)?;
                if binding.kind() != HostRequestBindingKind::ServerSingleUserOwner
                    || probe.principal.auth_context() != auth
                    || !probe.principal.matches_pool_scope(&enrollment.pool)
                    || !journal.matches_pool_scope(
                        &enrollment.pool,
                        auth.deployment(),
                        auth.tenant(),
                    )
                    || !journal.matches_host_target(target)
                {
                    return Err(HostRequestBindingError::NotCurrent);
                }
                probe
                    .callback_url_sink
                    .get()
                    .cloned()
                    .ok_or(HostRequestBindingError::Unavailable)
            }
        }
    }
}

impl GatewayAuthorizationCallbackUrlPort for ServerGatewayCallbackUrlPort {
    fn handoff(
        &self,
        auth: &AuthContext,
        target: &dyn GatewayAuthorizationHostTarget,
        invocation: GatewayAuthorizationCallbackUrlInvocation<'_>,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        let sink = self.check(auth, target, deadline)?;
        let result = invocation.deliver_to(&self.issuer, &self.identity, sink.as_ref());
        self.check(auth, target, deadline)?;
        result
    }
}

struct ServerSessionRowTuple {
    id: String,
    user_id: String,
    token_column: String,
    created_at: OffsetDateTime,
    issued_generation: i64,
}

struct ServerSessionCurrentGuard {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    row: ServerSessionRowTuple,
}

const CURRENT_SESSION_SQL: &str = "SELECT s.id,s.user_id,s.token,s.expires_at,s.created_at,s.updated_at,s.auth_generation, \
    u.auth_generation AS current_generation, \
    EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS revoked, \
    ARRAY(SELECT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles \
    FROM public.sessions s JOIN public.users u ON u.id=s.user_id \
    WHERE s.id=$1 AND s.user_id=$2 AND s.token=$3 AND s.created_at=$4 AND s.auth_generation=$5";

impl HostRequestBindingGuard for ServerSessionCurrentGuard {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn borrow_artifact_cleanup_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactCleanupHostTarget,
        deadline: std::time::Instant,
    ) -> Result<ArtifactCleanupHostObservation<'a>, HostRequestBindingError> {
        if auth != &self.original || !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let authority = probe
            .artifact_read_authority
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !authority.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
            || !authority.matches_cleanup_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        let epoch = self
            .issuer
            .borrow_server_session_epoch(binding.identity())?;
        if !epoch.matches_raw_row(
            &self.row.id,
            &self.row.user_id,
            &self.row.token_column,
            self.row.created_at,
            self.row.issued_generation,
        ) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        ArtifactCleanupHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSession,
            binding.identity().clone(),
            Some(epoch),
            Box::new(ServerArtifactCleanupTailFactory {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                lifetime: probe.lifetime,
                created_at: self.row.created_at,
            }),
        )
    }
    fn borrow_gateway_authorization_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn GatewayAuthorizationHostTarget,
        deadline: std::time::Instant,
    ) -> Result<GatewayAuthorizationHostObservation<'a>, HostRequestBindingError> {
        if auth != &self.original || !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let repository = probe
            .gateway_authorization_journal
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !repository.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
            || !repository.matches_host_target(target)
            || !target.matches_auth(auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        let epoch = self
            .issuer
            .borrow_server_session_epoch(binding.identity())?;
        if !epoch.matches_raw_row(
            &self.row.id,
            &self.row.user_id,
            &self.row.token_column,
            self.row.created_at,
            self.row.issued_generation,
        ) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        GatewayAuthorizationHostObservation::with_callback_port(
            HostRequestBindingKind::ServerSession,
            binding.identity().clone(),
            Some(epoch),
            Box::new(ServerGatewayAuthorizationTailFactory {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                lifetime: probe.lifetime,
                created_at: self.row.created_at,
            }),
            Box::new(ServerGatewayCallbackUrlPort {
                source: ServerGatewayCallbackSource::Session(self.probe.clone()),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                identity: binding.identity().clone(),
                original: auth.clone(),
            }),
        )
    }
    fn borrow_custom_model_catalog_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn CustomModelCatalogHostTarget,
        deadline: std::time::Instant,
    ) -> Result<CustomModelCatalogHostObservation<'a>, HostRequestBindingError> {
        if auth != &self.original || !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let repository = probe
            .custom_model_catalog_inventory
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !repository.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
            || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        let epoch = self
            .issuer
            .borrow_server_session_epoch(binding.identity())?;
        if !epoch.matches_raw_row(
            &self.row.id,
            &self.row.user_id,
            &self.row.token_column,
            self.row.created_at,
            self.row.issued_generation,
        ) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSession,
            binding.identity().clone(),
            Some(epoch),
            Box::new(ServerCustomModelCatalogTailFactory {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                lifetime: probe.lifetime,
                created_at: self.row.created_at,
            }),
        )
    }
    fn borrow_remember_preference_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn RememberPreferenceHostTarget,
        deadline: std::time::Instant,
    ) -> Result<RememberPreferenceHostObservation<'a>, HostRequestBindingError> {
        if auth != &self.original || !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        if std::time::Instant::now() >= deadline {
            return Err(HostRequestBindingError::Unavailable);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let repository = probe
            .remember_preferences
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !repository.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
            || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        let epoch = self
            .issuer
            .borrow_server_session_epoch(binding.identity())?;
        if !epoch.matches_raw_row(
            &self.row.id,
            &self.row.user_id,
            &self.row.token_column,
            self.row.created_at,
            self.row.issued_generation,
        ) {
            return Err(HostRequestBindingError::NotCurrent);
        }
        RememberPreferenceHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSession,
            binding.identity().clone(),
            Some(epoch),
            Box::new(ServerRememberPreferenceTailFactory {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                lifetime: probe.lifetime,
                created_at: self.row.created_at,
            }),
        )
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn verify_source_run_artifact_ids_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn SourceRunArtifactIdsCurrentTarget,
        deadline: std::time::Instant,
    ) -> SourceRunArtifactIdsCurrentCheck<'a> {
        Box::pin(async move {
            if auth != &self.original || !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let probe = self.probe.upgrade().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))?;
            let authority = probe
                .artifact_read_authority
                .get()
                .and_then(Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_source_run_ids_server_session(
                    auth,
                    target,
                    epoch,
                    probe.lifetime,
                    deadline,
                ),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            if !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let (inner, source) = result??;
            let witness = ServerArtifactReadTail {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok((
                Box::new(witness) as Box<dyn ArtifactReadTailWitness>,
                source,
            ))
        })
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn verify_artifact_save_receipt_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn openbot_contracts::request_binding::ArtifactSaveReceiptCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactSaveReceiptCurrentCheck<'a> {
        Box::pin(async move {
            if auth != &self.original || !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let probe = self.probe.upgrade().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))?;
            let authority = probe
                .artifact_read_authority
                .get()
                .and_then(Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_artifact_save_receipt_server_session(
                    auth,
                    target,
                    epoch,
                    probe.lifetime,
                    deadline,
                ),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            if !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let (inner, source) = result??;
            let witness = ServerArtifactReadTail {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok((
                Box::new(witness) as Box<dyn ArtifactReadTailWitness>,
                source,
            ))
        })
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactReadCurrentCheck<'a> {
        Box::pin(async move {
            if auth != &self.original || !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let probe = self.probe.upgrade().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))?;
            let authority = probe
                .artifact_read_authority
                .get()
                .and_then(Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())
                .map_err(ArtifactReadCurrentError::Host)?;
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                authority.observe_server_session(auth, target, epoch, probe.lifetime, deadline),
            )
            .await
            .map_err(|_| ArtifactReadCurrentError::Host(HostRequestBindingError::Unavailable));
            if !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let witness = ServerArtifactReadTail {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                inner: result??,
            };
            witness.verify_current(auth, deadline)?;
            Ok(Box::new(witness) as Box<dyn ArtifactReadTailWitness>)
        })
    }

    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        self.verify_current_before(
            auth,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
    }

    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if auth != &self.original || !self.owner.is_current() {
                return Err(HostRequestBindingError::NotCurrent);
            }
            let probe = self
                .probe
                .upgrade()
                .ok_or(HostRequestBindingError::NotCurrent)?;
            if deadline <= std::time::Instant::now() {
                return Err(HostRequestBindingError::Unavailable);
            }
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.observe_current(&probe, deadline),
            )
            .await
            .map_err(|_| HostRequestBindingError::Unavailable);
            if !self.owner.is_current() {
                return Err(HostRequestBindingError::NotCurrent);
            }
            result?
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone)]
struct ServerArtifactCleanupTailFactory {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    lifetime: SessionLifetimePolicy,
    created_at: OffsetDateTime,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ArtifactCleanupHostTailFactory for ServerArtifactCleanupTailFactory {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<ArtifactCleanupSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn ArtifactCleanupHostTailWitness>, HostRequestBindingError> {
        let session = session.ok_or(HostRequestBindingError::NotCurrent)?;
        if session.created_at != self.created_at {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let witness = ServerArtifactCleanupTail {
            source: self.clone(),
            session,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct ServerArtifactCleanupTail {
    source: ServerArtifactCleanupTailFactory,
    session: ArtifactCleanupSessionFacts,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ArtifactCleanupHostTailWitness for ServerArtifactCleanupTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )?;
        if self.source.probe.upgrade().is_none() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let now = OffsetDateTime::now_utc();
        if now < self.session.observed_wall
            || std::time::Instant::now() < self.session.observed_monotonic
            || now >= self.session.expires_at
            || evaluate_session(
                self.source.lifetime,
                SessionState::rehydrate(
                    self.session.created_at,
                    self.session.updated_at,
                    auth.auth_generation(),
                ),
                auth.auth_generation(),
                now,
            )
            .is_err()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )
    }
}

#[derive(Clone)]
struct ServerGatewayAuthorizationTailFactory {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    lifetime: SessionLifetimePolicy,
    created_at: OffsetDateTime,
}
impl GatewayAuthorizationHostTailFactory for ServerGatewayAuthorizationTailFactory {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<GatewayAuthorizationSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, HostRequestBindingError> {
        let session = session.ok_or(HostRequestBindingError::NotCurrent)?;
        if session.created_at != self.created_at {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let witness = ServerGatewayAuthorizationTail {
            source: self.clone(),
            session,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}
struct ServerGatewayAuthorizationTail {
    source: ServerGatewayAuthorizationTailFactory,
    session: GatewayAuthorizationSessionFacts,
}
impl GatewayAuthorizationHostTailWitness for ServerGatewayAuthorizationTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )?;
        let probe = self
            .source
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let journal = probe
            .gateway_authorization_journal
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !journal.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant) {
            return Err(HostRequestBindingError::Unavailable);
        }
        let now = OffsetDateTime::now_utc();
        if now < self.session.observed_wall
            || std::time::Instant::now() < self.session.observed_monotonic
            || now >= self.session.expires_at
            || evaluate_session(
                self.source.lifetime,
                SessionState::rehydrate(
                    self.session.created_at,
                    self.session.updated_at,
                    auth.auth_generation(),
                ),
                auth.auth_generation(),
                now,
            )
            .is_err()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )
    }
}

#[derive(Clone)]
struct ServerCustomModelCatalogTailFactory {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    lifetime: SessionLifetimePolicy,
    created_at: OffsetDateTime,
}
impl CustomModelCatalogHostTailFactory for ServerCustomModelCatalogTailFactory {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<CustomModelCatalogSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn CustomModelCatalogHostTailWitness>, HostRequestBindingError> {
        let session = session.ok_or(HostRequestBindingError::NotCurrent)?;
        if session.created_at != self.created_at {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let witness = ServerCustomModelCatalogTail {
            source: self.clone(),
            session,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}
struct ServerCustomModelCatalogTail {
    source: ServerCustomModelCatalogTailFactory,
    session: CustomModelCatalogSessionFacts,
}
impl CustomModelCatalogHostTailWitness for ServerCustomModelCatalogTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )?;
        if self.source.probe.upgrade().is_none() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let now = OffsetDateTime::now_utc();
        if now < self.session.observed_wall
            || std::time::Instant::now() < self.session.observed_monotonic
            || now >= self.session.expires_at
            || evaluate_session(
                self.source.lifetime,
                SessionState::rehydrate(
                    self.session.created_at,
                    self.session.updated_at,
                    auth.auth_generation(),
                ),
                auth.auth_generation(),
                now,
            )
            .is_err()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )
    }
}

#[derive(Clone)]
struct ServerRememberPreferenceTailFactory {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    lifetime: SessionLifetimePolicy,
    created_at: OffsetDateTime,
}
fn verify_repository_host_attachment(
    owner: &RequestBindingOwnerObservation,
    issuer: &RequestBindingIssuer,
    original: &AuthContext,
    auth: &AuthContext,
    deadline: std::time::Instant,
) -> Result<(), HostRequestBindingError> {
    if !owner.is_current()
        || auth != original
        || !original
            .request_binding()
            .zip(auth.request_binding())
            .is_some_and(|(a, b)| {
                a.identity().same_binding(b.identity()) && issuer.owns_identity(b.identity())
            })
    {
        return Err(HostRequestBindingError::NotCurrent);
    }
    if std::time::Instant::now() >= deadline {
        return Err(HostRequestBindingError::Unavailable);
    }
    Ok(())
}
impl RememberPreferenceHostTailFactory for ServerRememberPreferenceTailFactory {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<RememberPreferenceSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn RememberPreferenceHostTailWitness>, HostRequestBindingError> {
        let session = session.ok_or(HostRequestBindingError::NotCurrent)?;
        if session.created_at != self.created_at {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let witness = ServerRememberPreferenceTail {
            source: self.clone(),
            session,
        };
        witness.verify_current(auth, deadline)?;
        Ok(Box::new(witness))
    }
}
struct ServerRememberPreferenceTail {
    source: ServerRememberPreferenceTailFactory,
    session: RememberPreferenceSessionFacts,
}
impl RememberPreferenceHostTailWitness for ServerRememberPreferenceTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )?;
        if self.source.probe.upgrade().is_none() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let now = OffsetDateTime::now_utc();
        if now < self.session.observed_wall
            || std::time::Instant::now() < self.session.observed_monotonic
            || now >= self.session.expires_at
            || evaluate_session(
                self.source.lifetime,
                SessionState::rehydrate(
                    self.session.created_at,
                    self.session.updated_at,
                    auth.auth_generation(),
                ),
                auth.auth_generation(),
                now,
            )
            .is_err()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        verify_repository_host_attachment(
            &self.source.owner,
            &self.source.issuer,
            &self.source.original,
            auth,
            deadline,
        )
    }
}

/// The pending read keeps only observations; it cannot keep the resolver owner's lease alive.
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct ServerArtifactReadTail {
    probe: Weak<ServerSessionProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    inner: Box<dyn ArtifactReadTailWitness>,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ArtifactReadTailWitness for ServerArtifactReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        let original = self
            .original
            .request_binding()
            .ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Missing,
            ))?;
        if auth != &self.original
            || !self.owner.is_current()
            || self.probe.upgrade().is_none()
            || !auth.request_binding().is_some_and(|current| {
                original.identity().same_binding(current.identity())
                    && self.issuer.owns_identity(current.identity())
            })
        {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        if deadline <= std::time::Instant::now() {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        self.inner.verify_current(auth, deadline)?;
        if !self.owner.is_current() || self.probe.upgrade().is_none() {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        if deadline <= std::time::Instant::now() {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::Unavailable,
            ));
        }
        Ok(())
    }
}

impl ServerSessionCurrentGuard {
    async fn observe_current(
        &self,
        probe: &ServerSessionProbeState,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        let mut client = probe
            .pool
            .get()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .read_only(true)
            .start()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let observation = async {
            let remaining = deadline.checked_duration_since(std::time::Instant::now()).ok_or(HostRequestBindingError::Unavailable)?;
            let milliseconds = remaining.as_millis().min(5_000);
            if milliseconds == 0 { return Err(HostRequestBindingError::Unavailable); }
            transaction
                .batch_execute(&format!("SET LOCAL statement_timeout='{milliseconds}ms'; SET LOCAL lock_timeout='{milliseconds}ms'"))
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = transaction
                .query_opt(
                    CURRENT_SESSION_SQL,
                    &[
                        &self.row.id,
                        &self.row.user_id,
                        &self.row.token_column,
                        &self.row.created_at,
                        &self.row.issued_generation,
                    ],
                )
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            self.check_row(probe, row)
        }
        .await;
        transaction
            .rollback()
            .await
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        observation
    }

    fn check_row(
        &self,
        probe: &ServerSessionProbeState,
        row: Option<tokio_postgres::Row>,
    ) -> Result<(), HostRequestBindingError> {
        let row = row.ok_or(HostRequestBindingError::NotCurrent)?;
        let issued: Option<i64> = row
            .try_get("auth_generation")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let current: Option<i64> = row
            .try_get("current_generation")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let issued = issued
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let current = current
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(HostRequestBindingError::NotCurrent)?;
        let revoked: bool = row
            .try_get("revoked")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let created: OffsetDateTime = row
            .try_get("created_at")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let updated: OffsetDateTime = row
            .try_get("updated_at")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let expires: OffsetDateTime = row
            .try_get("expires_at")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let now = OffsetDateTime::now_utc();
        if revoked
            || now >= expires
            || issued != current
            || current != self.original.auth_generation().get()
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let _current_session = evaluate_session(
            probe.lifetime,
            SessionState::rehydrate(created, updated, AuthGeneration::new(issued)),
            AuthGeneration::new(current),
            now,
        )
        .map_err(|_| HostRequestBindingError::NotCurrent)?;
        let role_values: Vec<String> = row
            .try_get("roles")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let roles = role_values
            .iter()
            .map(|value| value.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let effective = resolve_effective_role(roles.iter().copied())
            .map_err(|_| HostRequestBindingError::NotCurrent)?;
        let user: String = row
            .try_get("user_id")
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        let current_auth = AuthContextBuilder::from_verified_session(
            probe.deployment.clone(),
            probe.tenant.clone(),
            ActorId::new(user),
            AuthGeneration::new(current),
            false,
        )
        .with_role(effective)
        .build();
        if current_auth != self.original {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }
}

impl PostgresSessionAuthResolver {
    #[allow(
        dead_code,
        reason = "The production callback URL destination remains disabled"
    )]
    fn install_gateway_callback_url_sink(
        &self,
        sink: Arc<GatewayCallbackUrlSink>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = &self.binding_owner;
        let probe = &owner.probe;
        let journal = probe
            .gateway_authorization_journal
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || probe.callback_url_sink.get().is_some()
            || !journal.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        probe
            .callback_url_sink
            .set(sink)
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || !journal.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }

    /// Install one journal against this exact original Session Host Pool and namespace.
    pub fn install_gateway_authorization_journal(
        &self,
        journal: &Arc<GatewayAuthorizationJournal>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = &self.binding_owner;
        let probe = &owner.probe;
        if !owner.issuer.observation().is_current()
            || probe.gateway_authorization_journal.get().is_some()
            || !journal.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        journal.enroll_host_issuer(&owner.issuer)?;
        probe
            .gateway_authorization_journal
            .set(Arc::downgrade(journal))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Install one actual same-Pool inventory before serving any request.
    pub fn install_custom_model_catalog_inventory(
        &self,
        repository: &Arc<PostgresCustomModelCatalogInventory>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = &self.binding_owner;
        let probe = &owner.probe;
        if !owner.issuer.observation().is_current()
            || probe.custom_model_catalog_inventory.get().is_some()
            || !repository.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(&owner.issuer)?;
        probe
            .custom_model_catalog_inventory
            .set(Arc::downgrade(repository))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// 构造。session hash key 为空会使所有 token 共享无密钥摘要，直接拒绝。
    pub fn new(
        pool: openbot_infra::db::pool::DatabasePool,
        hash_key: impl Into<Vec<u8>>,
        lifetime: SessionLifetimePolicy,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Self, AppError> {
        let hash_key = hash_key.into();
        if hash_key.is_empty() {
            return Err(AppError::DependencyUnavailable {
                dependency: "session_hash_key",
            });
        }
        let (lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let probe = Arc::new(ServerSessionProbeState {
            pool: pool.clone(),
            lifetime,
            deployment: deployment.clone(),
            tenant: tenant.clone(),
            capability_facts: std::sync::OnceLock::new(),
            remember_preferences: std::sync::OnceLock::new(),
            custom_model_catalog_inventory: std::sync::OnceLock::new(),
            gateway_authorization_journal: std::sync::OnceLock::new(),
            callback_url_sink: std::sync::OnceLock::new(),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            artifact_read_authority: std::sync::OnceLock::new(),
        });
        Ok(Self {
            pool,
            hash_key: hash_key.into(),
            lifetime,
            deployment,
            tenant,
            binding_owner: Arc::new(ServerSessionBindingOwner {
                lease,
                issuer,
                probe,
            }),
        })
    }

    /// Enroll the concrete actual same-Pool artifact owner once, without owning its lease.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn install_artifact_read_authority(
        &self,
        authority: &Arc<PostgresArtifactReadAuthority>,
    ) -> Result<(), HostRequestBindingError> {
        if !self.binding_owner.issuer.observation().is_current()
            || !authority.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        self.binding_owner
            .probe
            .artifact_read_authority
            .set(Arc::downgrade(authority))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Enroll this actual resolver's same-Pool repository and original issuer once.
    pub fn install_remember_preference_repository(
        &self,
        repository: &Arc<PostgresRememberPreferenceRepository>,
    ) -> Result<(), HostRequestBindingError> {
        if !self.binding_owner.issuer.observation().is_current()
            || !repository.matches_pool_scope(&self.pool, &self.deployment, &self.tenant)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(&self.binding_owner.issuer)?;
        self.binding_owner
            .probe
            .remember_preferences
            .set(Arc::downgrade(repository))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Permanently close this actual resolver owner's bindings before shutdown.
    pub fn close_request_bindings(&self) {
        self.binding_owner.lease.close();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(authority) = self
            .binding_owner
            .probe
            .artifact_read_authority
            .get()
            .and_then(Weak::upgrade)
        {
            authority
                .read_lifecycle()
                .close_issuer(&self.binding_owner.issuer);
        }
        if let Some(facts) = self
            .binding_owner
            .probe
            .capability_facts
            .get()
            .and_then(Weak::upgrade)
        {
            facts.close();
        }
    }

    async fn resolve_token(&self, token: &str) -> Result<ResolvedAuth, AppError> {
        if token.len() < 16 || token.len() > 512 || !token.is_ascii() {
            return Err(AppError::Unauthenticated);
        }
        let token_hash = SessionTokenHash::compute(
            SessionToken::new(token.as_bytes()),
            SessionHashKey::new(&self.hash_key),
        )
        .to_column_value();
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session resolver 获取数据库连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        let row = client
            .query_opt(
                "SELECT s.id,s.user_id,s.token,s.expires_at,s.created_at,s.updated_at,s.auth_generation, \
                        coalesce(u.auth_generation,0) AS current_generation, \
                        coalesce(bool_or(ra.email IS NOT NULL),false) AS revoked, \
                        coalesce(array_agg(distinct ur.role::text) \
                          FILTER (WHERE ur.role IS NOT NULL),'{}') AS roles \
                 FROM public.sessions s \
                 JOIN public.users u ON u.id=s.user_id \
                 LEFT JOIN public.user_roles ur ON ur.user_id=u.id \
                 LEFT JOIN public.revoked_access ra ON ra.email=lower(u.email) \
                 WHERE s.token=$1 \
                 GROUP BY s.id,u.id",
                &[&token_hash],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session resolver 查询失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        let Some(row) = row else {
            return Err(AppError::Unauthenticated);
        };
        let revoked: bool = row.try_get("revoked").map_err(auth_row_error)?;
        if revoked {
            return Err(AppError::Unauthenticated);
        }
        let issued_generation: Option<i64> =
            row.try_get("auth_generation").map_err(auth_row_error)?;
        let Some(issued_generation) = issued_generation else {
            // 0015 前旧 Better Auth session，按方案统一重新登录，不猜 generation。
            return Err(AppError::Unauthenticated);
        };
        let current_generation: i64 = row.try_get("current_generation").map_err(auth_row_error)?;
        let issued_generation =
            u64::try_from(issued_generation).map_err(|_| AppError::Unauthenticated)?;
        let current_generation =
            u64::try_from(current_generation).map_err(|_| AppError::Unauthenticated)?;
        let created_at: OffsetDateTime = row.try_get("created_at").map_err(auth_row_error)?;
        let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(auth_row_error)?;
        let expires_at: OffsetDateTime = row.try_get("expires_at").map_err(auth_row_error)?;
        let now = OffsetDateTime::now_utc();
        if now >= expires_at {
            return Err(AppError::Unauthenticated);
        }
        let live = evaluate_session(
            self.lifetime,
            SessionState::rehydrate(
                created_at,
                updated_at,
                AuthGeneration::new(issued_generation),
            ),
            AuthGeneration::new(current_generation),
            now,
        )
        .map_err(|_| AppError::Unauthenticated)?;
        let role_values: Vec<String> = row.try_get("roles").map_err(auth_row_error)?;
        let roles = role_values
            .iter()
            .map(|value| value.parse::<Role>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "database_acl",
            })?;
        let effective =
            resolve_effective_role(roles.iter().copied()).map_err(|_| AppError::ForbiddenRole {
                required: Role::User,
            })?;
        let user_id: String = row.try_get("user_id").map_err(auth_row_error)?;
        let session_id: String = row.try_get("id").map_err(auth_row_error)?;
        let token_column: String = row.try_get("token").map_err(auth_row_error)?;
        let context = AuthContextBuilder::from_verified_session(
            self.deployment.clone(),
            self.tenant.clone(),
            ActorId::new(user_id),
            AuthGeneration::new(current_generation),
            false,
        )
        .with_role(effective)
        .build();
        let guard = Arc::new(ServerSessionCurrentGuard {
            probe: Arc::downgrade(&self.binding_owner.probe),
            owner: self.binding_owner.issuer.observation(),
            issuer: self.binding_owner.issuer.clone(),
            original: context.clone(),
            row: ServerSessionRowTuple {
                id: session_id.clone(),
                user_id: context.actor().as_str().to_owned(),
                token_column: token_column.clone(),
                created_at,
                issued_generation: i64::try_from(issued_generation)
                    .map_err(|_| AppError::Unauthenticated)?,
            },
        });
        let binding = self
            .binding_owner
            .issuer
            .bind_server_session(
                &context,
                ServerSessionBindingIdentity::from_verified_row(
                    session_id.clone(),
                    context.actor().clone(),
                    token_column,
                    created_at,
                    AuthGeneration::new(issued_generation),
                ),
                guard,
            )
            .map_err(|_| AppError::Unauthenticated)?;
        let context = context
            .with_verified_request_binding(binding)
            .map_err(|_| AppError::Unauthenticated)?;
        Ok(ResolvedAuth::from_live_session(
            context,
            live,
            Some(session_id),
        ))
    }
}

impl core::fmt::Debug for PostgresSessionAuthResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresSessionAuthResolver")
            .field("hash_key", &"<redacted>")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthResolver for PostgresSessionAuthResolver {
    fn runtime_capability_factory(
        &self,
        sso: Option<ReadOnlySsoCapabilitySource>,
    ) -> Result<Arc<dyn RuntimeCapabilityCollectorFactory>, RuntimeCapabilitiesCollectionError>
    {
        Ok(Arc::new(ServerRuntimeCapabilityFactory {
            source: ServerCapabilitySource::Session(Arc::downgrade(&self.binding_owner.probe)),
            issuer: self.binding_owner.issuer.clone(),
            revision: Arc::new(RuntimeCapabilityRevisionOwner::new()?),
            sso,
        }))
    }
    fn close_request_bindings(&self) {
        Self::close_request_bindings(self);
    }
    async fn resolve(&self, parts: &Parts) -> Result<AuthContext, AppError> {
        self.resolve_with_assurance(parts)
            .await
            .map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, parts: &Parts) -> Result<ResolvedAuth, AppError> {
        let token = session_cookie(parts).ok_or(AppError::Unauthenticated)?;
        self.resolve_token(token).await
    }

    async fn touch(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let Some(session_id) = resolved.session_id() else {
            return Ok(());
        };
        let evaluated_at = resolved
            .live_session()
            .map(|session| session.evaluated_at())
            .ok_or(AppError::Unauthenticated)?;
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session touch 获取连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        client
            .execute(
                "UPDATE public.sessions SET updated_at=greatest(updated_at,$2) WHERE id=$1",
                &[&session_id, &evaluated_at],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session touch 失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        Ok(())
    }

    async fn revoke_session(&self, resolved: &ResolvedAuth) -> Result<(), AppError> {
        let Some(session_id) = resolved.session_id() else {
            return Err(AppError::RequestConflict {
                resource: "session",
            });
        };
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "session revoke 获取连接失败");
            AppError::DependencyUnavailable {
                dependency: "database",
            }
        })?;
        client
            .execute(
                "DELETE FROM public.sessions WHERE id=$1 AND user_id=$2",
                &[&session_id, &resolved.context().actor().as_str()],
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "session revoke 失败");
                AppError::DependencyUnavailable {
                    dependency: "database",
                }
            })?;
        Ok(())
    }
}

/// 显式单用户部署的 production resolver。绑定范围必须在启动组装前已通过 §6.1 判定。
#[derive(Clone)]
pub struct SingleUserAuthResolver {
    context: AuthContext,
    lifetime: SessionLifetimePolicy,
    binding_owner: Option<Arc<SingleUserBindingOwner>>,
}

struct SingleUserBindingOwner {
    lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    probe: Arc<SingleUserProbeState>,
}

impl Drop for SingleUserBindingOwner {
    fn drop(&mut self) {
        self.lease.close();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(authority) = self
            .probe
            .artifact_read_authority
            .get()
            .and_then(Weak::upgrade)
        {
            authority.read_lifecycle().close_issuer(&self.issuer);
        }
    }
}

struct SingleUserProbeState {
    principal: openbot_infra::auth::single_user::VerifiedSingleUserPrincipal,
    capability_facts: std::sync::OnceLock<Weak<PostgresRuntimeCapabilityFacts>>,
    remember_preferences: std::sync::OnceLock<Weak<PostgresRememberPreferenceRepository>>,
    custom_model_catalog_inventory: std::sync::OnceLock<SingleUserCustomCatalogEnrollment>,
    gateway_authorization_journal: std::sync::OnceLock<SingleUserGatewayAuthorizationEnrollment>,
    callback_url_sink: std::sync::OnceLock<Arc<GatewayCallbackUrlSink>>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    artifact_read_authority: std::sync::OnceLock<Weak<PostgresArtifactReadAuthority>>,
}

struct SingleUserGatewayAuthorizationEnrollment {
    journal: Weak<GatewayAuthorizationJournal>,
    pool: openbot_infra::db::pool::DatabasePool,
}

struct SingleUserCustomCatalogEnrollment {
    repository: Weak<PostgresCustomModelCatalogInventory>,
    pool: openbot_infra::db::pool::DatabasePool,
}

struct SingleUserCurrentGuard {
    probe: Weak<SingleUserProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
}

impl HostRequestBindingGuard for SingleUserCurrentGuard {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: std::time::Instant,
    ) -> openbot_contracts::request_binding::ArtifactReadCurrentCheck<'a> {
        Box::pin(async move {
            if !self.owner.is_current() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let probe = self.probe.upgrade().ok_or(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ))?;
            if probe.principal.auth_context() != auth {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let binding = auth
                .request_binding()
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Missing,
                ))?;
            if binding.kind() != HostRequestBindingKind::ServerSingleUserOwner
                || !self.issuer.owns_identity(binding.identity())
            {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::NotCurrent,
                ));
            }
            let authority = probe
                .artifact_read_authority
                .get()
                .and_then(Weak::upgrade)
                .ok_or(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ))?;
            if !probe.principal.matches_artifact_read_authority(&authority) {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            if deadline <= std::time::Instant::now() {
                return Err(ArtifactReadCurrentError::Host(
                    HostRequestBindingError::Unavailable,
                ));
            }
            let inner = authority
                .observe_server_single_user(auth, target, &probe.principal, deadline)
                .await?;
            let witness = SingleUserArtifactReadTail {
                probe: self.probe.clone(),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                original: auth.clone(),
                inner,
            };
            witness.verify_current(auth, deadline)?;
            Ok(Box::new(witness) as Box<dyn ArtifactReadTailWitness>)
        })
    }

    fn borrow_gateway_authorization_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn GatewayAuthorizationHostTarget,
        deadline: std::time::Instant,
    ) -> Result<GatewayAuthorizationHostObservation<'a>, HostRequestBindingError> {
        if !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let enrollment = probe
            .gateway_authorization_journal
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let repository = enrollment
            .journal
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !probe.principal.matches_pool_scope(&enrollment.pool)
            || !repository.matches_pool_scope(&enrollment.pool, auth.deployment(), auth.tenant())
            || !repository.matches_host_target(target)
            || !target.matches_auth(auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::ServerSingleUserOwner
            || !self.issuer.owns_identity(binding.identity())
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = SingleUserGatewayAuthorizationTail {
            probe: self.probe.clone(),
            owner: self.owner.clone(),
            issuer: self.issuer.clone(),
            original: auth.clone(),
            observed_wall: OffsetDateTime::now_utc(),
            observed_monotonic: std::time::Instant::now(),
        };
        factory.verify_current(auth, deadline)?;
        GatewayAuthorizationHostObservation::with_callback_port(
            HostRequestBindingKind::ServerSingleUserOwner,
            binding.identity().clone(),
            None,
            Box::new(factory),
            Box::new(ServerGatewayCallbackUrlPort {
                source: ServerGatewayCallbackSource::SingleUser(self.probe.clone()),
                owner: self.owner.clone(),
                issuer: self.issuer.clone(),
                identity: binding.identity().clone(),
                original: auth.clone(),
            }),
        )
    }
    fn borrow_custom_model_catalog_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn CustomModelCatalogHostTarget,
        deadline: std::time::Instant,
    ) -> Result<CustomModelCatalogHostObservation<'a>, HostRequestBindingError> {
        if !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let enrollment = probe
            .custom_model_catalog_inventory
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let repository = enrollment
            .repository
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !probe.principal.matches_pool_scope(&enrollment.pool)
            || !repository.matches_pool_scope(&enrollment.pool, auth.deployment(), auth.tenant())
            || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::ServerSingleUserOwner
            || !self.issuer.owns_identity(binding.identity())
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = SingleUserCustomModelCatalogTail {
            probe: self.probe.clone(),
            owner: self.owner.clone(),
            issuer: self.issuer.clone(),
            original: auth.clone(),
            observed_wall: OffsetDateTime::now_utc(),
            observed_monotonic: std::time::Instant::now(),
        };
        factory.verify_current(auth, deadline)?;
        CustomModelCatalogHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSingleUserOwner,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn borrow_remember_preference_host_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn RememberPreferenceHostTarget,
        deadline: std::time::Instant,
    ) -> Result<RememberPreferenceHostObservation<'a>, HostRequestBindingError> {
        if !self.owner.is_current() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let repository = probe
            .remember_preferences
            .get()
            .and_then(Weak::upgrade)
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !probe
            .principal
            .matches_remember_preference_repository(&repository)
            || !repository.matches_host_target(target, auth)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        let binding = auth
            .request_binding()
            .ok_or(HostRequestBindingError::Missing)?;
        if binding.kind() != HostRequestBindingKind::ServerSingleUserOwner
            || !self.issuer.owns_identity(binding.identity())
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let factory = SingleUserRememberPreferenceTail {
            probe: self.probe.clone(),
            owner: self.owner.clone(),
            issuer: self.issuer.clone(),
            original: auth.clone(),
        };
        factory.verify_current(auth, deadline)?;
        RememberPreferenceHostObservation::from_trusted_host(
            HostRequestBindingKind::ServerSingleUserOwner,
            binding.identity().clone(),
            None,
            Box::new(factory),
        )
    }
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        self.verify_current_before(
            auth,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
    }

    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if !self.owner.is_current() {
                return Err(HostRequestBindingError::NotCurrent);
            }
            let probe = self
                .probe
                .upgrade()
                .ok_or(HostRequestBindingError::NotCurrent)?;
            if probe.principal.auth_context() != auth {
                return Err(HostRequestBindingError::NotCurrent);
            }
            let result = probe.principal.verify_current_before(deadline).await;
            if !self.owner.is_current() {
                return Err(HostRequestBindingError::NotCurrent);
            }
            result.map_err(|error| match error {
                openbot_infra::auth::single_user::SingleUserPrincipalCurrentError::NotCurrent => {
                    HostRequestBindingError::NotCurrent
                }
                openbot_infra::auth::single_user::SingleUserPrincipalCurrentError::Unavailable => {
                    HostRequestBindingError::Unavailable
                }
            })
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct SingleUserArtifactReadTail {
    probe: Weak<SingleUserProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    inner: Box<dyn ArtifactReadTailWitness>,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl ArtifactReadTailWitness for SingleUserArtifactReadTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), ArtifactReadCurrentError> {
        verify_repository_host_attachment(
            &self.owner,
            &self.issuer,
            &self.original,
            auth,
            deadline,
        )
        .map_err(ArtifactReadCurrentError::Host)?;
        let probe = self.probe.upgrade().ok_or(ArtifactReadCurrentError::Host(
            HostRequestBindingError::NotCurrent,
        ))?;
        if probe.principal.auth_context() != auth {
            return Err(ArtifactReadCurrentError::Host(
                HostRequestBindingError::NotCurrent,
            ));
        }
        self.inner.verify_current(auth, deadline)?;
        verify_repository_host_attachment(&self.owner, &self.issuer, &self.original, auth, deadline)
            .map_err(ArtifactReadCurrentError::Host)
    }
}

#[derive(Clone)]
struct SingleUserGatewayAuthorizationTail {
    probe: Weak<SingleUserProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    observed_wall: OffsetDateTime,
    observed_monotonic: std::time::Instant,
}
impl GatewayAuthorizationHostTailFactory for SingleUserGatewayAuthorizationTail {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<GatewayAuthorizationSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn GatewayAuthorizationHostTailWitness>, HostRequestBindingError> {
        if session.is_some() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.verify_current(auth, deadline)?;
        Ok(Box::new(self.clone()))
    }
}
impl GatewayAuthorizationHostTailWitness for SingleUserGatewayAuthorizationTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.owner,
            &self.issuer,
            &self.original,
            auth,
            deadline,
        )?;
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth
            || OffsetDateTime::now_utc() < self.observed_wall
            || std::time::Instant::now() < self.observed_monotonic
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let enrollment = probe
            .gateway_authorization_journal
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let repository = enrollment
            .journal
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !probe.principal.matches_pool_scope(&enrollment.pool)
            || !repository.matches_pool_scope(&enrollment.pool, auth.deployment(), auth.tenant())
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        verify_repository_host_attachment(&self.owner, &self.issuer, &self.original, auth, deadline)
    }
}

#[derive(Clone)]
struct SingleUserCustomModelCatalogTail {
    probe: Weak<SingleUserProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
    observed_wall: OffsetDateTime,
    observed_monotonic: std::time::Instant,
}
impl CustomModelCatalogHostTailFactory for SingleUserCustomModelCatalogTail {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<CustomModelCatalogSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn CustomModelCatalogHostTailWitness>, HostRequestBindingError> {
        if session.is_some() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.verify_current(auth, deadline)?;
        Ok(Box::new(self.clone()))
    }
}
impl CustomModelCatalogHostTailWitness for SingleUserCustomModelCatalogTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.owner,
            &self.issuer,
            &self.original,
            auth,
            deadline,
        )?;
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth
            || OffsetDateTime::now_utc() < self.observed_wall
            || std::time::Instant::now() < self.observed_monotonic
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        let enrollment = probe
            .custom_model_catalog_inventory
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let repository = enrollment
            .repository
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !probe.principal.matches_pool_scope(&enrollment.pool)
            || !repository.matches_pool_scope(&enrollment.pool, auth.deployment(), auth.tenant())
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        verify_repository_host_attachment(&self.owner, &self.issuer, &self.original, auth, deadline)
    }
}

#[derive(Clone)]
struct SingleUserRememberPreferenceTail {
    probe: Weak<SingleUserProbeState>,
    owner: RequestBindingOwnerObservation,
    issuer: RequestBindingIssuer,
    original: AuthContext,
}
impl RememberPreferenceHostTailFactory for SingleUserRememberPreferenceTail {
    fn witness(
        &self,
        auth: &AuthContext,
        session: Option<RememberPreferenceSessionFacts>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn RememberPreferenceHostTailWitness>, HostRequestBindingError> {
        if session.is_some() {
            return Err(HostRequestBindingError::NotCurrent);
        }
        self.verify_current(auth, deadline)?;
        Ok(Box::new(self.clone()))
    }
}
impl RememberPreferenceHostTailWitness for SingleUserRememberPreferenceTail {
    fn verify_current(
        &self,
        auth: &AuthContext,
        deadline: std::time::Instant,
    ) -> Result<(), HostRequestBindingError> {
        verify_repository_host_attachment(
            &self.owner,
            &self.issuer,
            &self.original,
            auth,
            deadline,
        )?;
        let probe = self
            .probe
            .upgrade()
            .ok_or(HostRequestBindingError::NotCurrent)?;
        if probe.principal.auth_context() != auth {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }
}

impl core::fmt::Debug for SingleUserAuthResolver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SingleUserAuthResolver")
            .field("context", &self.context)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl SingleUserAuthResolver {
    #[allow(
        dead_code,
        reason = "The production callback URL destination remains disabled"
    )]
    fn install_gateway_callback_url_sink(
        &self,
        sink: Arc<GatewayCallbackUrlSink>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let original = owner.probe.principal.auth_context();
        let enrollment = owner
            .probe
            .gateway_authorization_journal
            .get()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let journal = enrollment
            .journal
            .upgrade()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || owner.probe.callback_url_sink.get().is_some()
            || !owner.probe.principal.matches_pool_scope(&enrollment.pool)
            || !journal.matches_pool_scope(
                &enrollment.pool,
                original.deployment(),
                original.tenant(),
            )
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        owner
            .probe
            .callback_url_sink
            .set(sink)
            .map_err(|_| HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || !journal.matches_pool_scope(
                &enrollment.pool,
                original.deployment(),
                original.tenant(),
            )
        {
            return Err(HostRequestBindingError::NotCurrent);
        }
        Ok(())
    }

    /// Enroll only the genuine principal and its original actual Pool once.
    pub fn install_gateway_authorization_journal(
        &self,
        journal: &Arc<GatewayAuthorizationJournal>,
        actual_pool: &openbot_infra::db::pool::DatabasePool,
    ) -> Result<(), HostRequestBindingError> {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let original = owner.probe.principal.auth_context();
        if !owner.issuer.observation().is_current()
            || owner.probe.gateway_authorization_journal.get().is_some()
            || !owner.probe.principal.matches_pool_scope(actual_pool)
            || !journal.matches_pool_scope(actual_pool, original.deployment(), original.tenant())
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        journal.enroll_host_issuer(&owner.issuer)?;
        owner
            .probe
            .gateway_authorization_journal
            .set(SingleUserGatewayAuthorizationEnrollment {
                journal: Arc::downgrade(journal),
                pool: actual_pool.clone(),
            })
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Only the verified principal and the original actual Pool can enroll this inventory.
    pub fn install_custom_model_catalog_inventory(
        &self,
        repository: &Arc<PostgresCustomModelCatalogInventory>,
        actual_pool: &openbot_infra::db::pool::DatabasePool,
    ) -> Result<(), HostRequestBindingError> {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        let original = owner.probe.principal.auth_context();
        if !owner.issuer.observation().is_current()
            || owner.probe.custom_model_catalog_inventory.get().is_some()
            || !owner.probe.principal.matches_pool_scope(actual_pool)
            || !repository.matches_pool_scope(actual_pool, original.deployment(), original.tenant())
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(&owner.issuer)?;
        owner
            .probe
            .custom_model_catalog_inventory
            .set(SingleUserCustomCatalogEnrollment {
                repository: Arc::downgrade(repository),
                pool: actual_pool.clone(),
            })
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Construct only from the fixed Server principal verified against its business database.
    #[must_use]
    pub fn from_verified_principal(
        principal: openbot_infra::auth::single_user::VerifiedSingleUserPrincipal,
        lifetime: SessionLifetimePolicy,
    ) -> Self {
        let context = principal.auth_context().clone();
        let (lease, issuer) = RequestBindingOwnerLease::for_trusted_host(
            HostRequestBindingKind::ServerSingleUserOwner,
        );
        Self {
            context,
            lifetime,
            binding_owner: Some(Arc::new(SingleUserBindingOwner {
                lease,
                issuer,
                probe: Arc::new(SingleUserProbeState {
                    principal,
                    capability_facts: std::sync::OnceLock::new(),
                    remember_preferences: std::sync::OnceLock::new(),
                    custom_model_catalog_inventory: std::sync::OnceLock::new(),
                    gateway_authorization_journal: std::sync::OnceLock::new(),
                    callback_url_sink: std::sync::OnceLock::new(),
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    artifact_read_authority: std::sync::OnceLock::new(),
                }),
            })),
        }
    }

    /// Enroll the actual canonical principal's read owner once; no synthetic Session or Pool.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn install_artifact_read_authority(
        &self,
        authority: &Arc<PostgresArtifactReadAuthority>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || !owner
                .probe
                .principal
                .matches_artifact_read_authority(authority)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        owner
            .probe
            .artifact_read_authority
            .set(Arc::downgrade(authority))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Enroll only the real canonical principal's same-Pool repository; no synthetic Session.
    pub fn install_remember_preference_repository(
        &self,
        repository: &Arc<PostgresRememberPreferenceRepository>,
    ) -> Result<(), HostRequestBindingError> {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(HostRequestBindingError::Unavailable)?;
        if !owner.issuer.observation().is_current()
            || !owner
                .probe
                .principal
                .matches_remember_preference_repository(repository)
        {
            return Err(HostRequestBindingError::Unavailable);
        }
        repository.enroll_host_issuer(&owner.issuer)?;
        owner
            .probe
            .remember_preferences
            .set(Arc::downgrade(repository))
            .map_err(|_| HostRequestBindingError::Unavailable)
    }

    /// Permanently close the actual runtime owner; synthetic test identities have no owner.
    pub fn close_request_bindings(&self) {
        if let Some(owner) = &self.binding_owner {
            owner.lease.close();
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(authority) = owner
                .probe
                .artifact_read_authority
                .get()
                .and_then(Weak::upgrade)
            {
                authority.read_lifecycle().close_issuer(&owner.issuer);
            }
            if let Some(facts) = owner.probe.capability_facts.get().and_then(Weak::upgrade) {
                facts.close();
            }
        }
    }

    /// Test-only fixed identity; excluded from the default production feature graph.
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn new(
        deployment: DeploymentId,
        tenant: TenantId,
        actor: ActorId,
        lifetime: SessionLifetimePolicy,
    ) -> Self {
        Self {
            context: AuthContextBuilder::from_verified_session(
                deployment,
                tenant,
                actor,
                AuthGeneration::new(0),
                true,
            )
            .with_roles([Role::Admin, Role::User])
            .build(),
            lifetime,
            binding_owner: None,
        }
    }

    fn resolved(&self) -> Result<ResolvedAuth, AppError> {
        let now = OffsetDateTime::now_utc();
        let generation = self.context.auth_generation();
        let live = evaluate_session(
            self.lifetime,
            SessionState::rehydrate(now, now, generation),
            generation,
            now,
        )
        .map_err(|_| AppError::Unauthenticated)?;
        let mut context = self.context.clone();
        if let Some(owner) = &self.binding_owner {
            let guard = Arc::new(SingleUserCurrentGuard {
                probe: Arc::downgrade(&owner.probe),
                owner: owner.issuer.observation(),
                issuer: owner.issuer.clone(),
            });
            let binding = owner
                .issuer
                .bind_single_user_owner(&context, guard)
                .map_err(|_| AppError::Unauthenticated)?;
            context = context
                .with_verified_request_binding(binding)
                .map_err(|_| AppError::Unauthenticated)?;
        }
        Ok(ResolvedAuth::from_live_session(context, live, None))
    }
}

#[async_trait]
impl AuthResolver for SingleUserAuthResolver {
    fn runtime_capability_factory(
        &self,
        sso: Option<ReadOnlySsoCapabilitySource>,
    ) -> Result<Arc<dyn RuntimeCapabilityCollectorFactory>, RuntimeCapabilitiesCollectionError>
    {
        let owner = self
            .binding_owner
            .as_ref()
            .ok_or(RuntimeCapabilitiesCollectionError::MissingHostSource)?;
        Ok(Arc::new(ServerRuntimeCapabilityFactory {
            source: ServerCapabilitySource::SingleUser(Arc::downgrade(&owner.probe)),
            issuer: owner.issuer.clone(),
            revision: Arc::new(RuntimeCapabilityRevisionOwner::new()?),
            sso,
        }))
    }
    fn close_request_bindings(&self) {
        Self::close_request_bindings(self);
    }
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        self.resolved().map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, _parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.resolved()
    }
}

enum ServerCapabilitySource {
    Session(Weak<ServerSessionProbeState>),
    SingleUser(Weak<SingleUserProbeState>),
}

struct ServerRuntimeCapabilityFactory {
    source: ServerCapabilitySource,
    issuer: RequestBindingIssuer,
    revision: Arc<RuntimeCapabilityRevisionOwner>,
    sso: Option<ReadOnlySsoCapabilitySource>,
}

struct ServerRuntimeCapabilitiesCollector {
    factory: ServerRuntimeCapabilityFactory,
    facts: Arc<PostgresRuntimeCapabilityFacts>,
}

impl RuntimeCapabilityCollectorFactory for ServerRuntimeCapabilityFactory {
    fn build(
        &self,
        facts: Arc<PostgresRuntimeCapabilityFacts>,
    ) -> Result<Arc<dyn RuntimeCapabilitiesCollector>, RuntimeCapabilitiesCollectionError> {
        use RuntimeCapabilitiesCollectionError as Error;
        if !self.issuer.observation().is_current() {
            return Err(Error::NotCurrent);
        }
        let source = match &self.source {
            ServerCapabilitySource::Session(weak) => {
                let probe = weak.upgrade().ok_or(Error::NotCurrent)?;
                if !facts.matches_pool_scope(&probe.pool, &probe.deployment, &probe.tenant) {
                    return Err(Error::MissingHostSource);
                }
                probe
                    .capability_facts
                    .set(Arc::downgrade(&facts))
                    .map_err(|_| Error::MissingHostSource)?;
                ServerCapabilitySource::Session(weak.clone())
            }
            ServerCapabilitySource::SingleUser(weak) => {
                let probe = weak.upgrade().ok_or(Error::NotCurrent)?;
                if !probe.principal.matches_capability_facts(&facts) {
                    return Err(Error::MissingHostSource);
                }
                probe
                    .capability_facts
                    .set(Arc::downgrade(&facts))
                    .map_err(|_| Error::MissingHostSource)?;
                ServerCapabilitySource::SingleUser(weak.clone())
            }
        };
        Ok(Arc::new(ServerRuntimeCapabilitiesCollector {
            factory: ServerRuntimeCapabilityFactory {
                source,
                issuer: self.issuer.clone(),
                revision: self.revision.clone(),
                sso: self.sso.clone(),
            },
            facts,
        }))
    }
}

impl ServerRuntimeCapabilitiesCollector {
    async fn current_facts(
        &self,
        auth: &AuthContext,
        deadline: CapabilityDeadline,
    ) -> Result<
        openbot_infra::runtime_capability_facts::RuntimeCapabilityJointSnapshot,
        RuntimeCapabilitiesCollectionError,
    > {
        use RuntimeCapabilitiesCollectionError as Error;
        deadline.check()?;
        let binding = auth.request_binding().ok_or(Error::MissingHostSource)?;
        if !self.factory.issuer.owns_identity(binding.identity())
            || !self.factory.issuer.observation().is_current()
        {
            return Err(Error::NotCurrent);
        }
        let scope = RuntimeCapabilityHostScope::for_server(
            &self.factory.issuer,
            auth,
            self.factory.revision.runtime_epoch(),
        )?;
        match &self.factory.source {
            ServerCapabilitySource::Session(weak) => {
                let probe = weak.upgrade().ok_or(Error::NotCurrent)?;
                let epoch = self
                    .factory
                    .issuer
                    .borrow_server_session_epoch(binding.identity())
                    .map_err(|error| match error {
                        HostRequestBindingError::NotCurrent => Error::NotCurrent,
                        HostRequestBindingError::Missing => Error::MissingHostSource,
                        HostRequestBindingError::Unavailable => Error::Unavailable,
                    })?;
                self.facts
                    .observe_server_session(
                        auth,
                        epoch,
                        probe.lifetime,
                        &scope,
                        self.factory.sso.as_ref(),
                        deadline,
                    )
                    .await
            }
            ServerCapabilitySource::SingleUser(weak) => {
                let probe = weak.upgrade().ok_or(Error::NotCurrent)?;
                self.facts
                    .observe_single_user(
                        auth,
                        &probe.principal,
                        &scope,
                        self.factory.sso.as_ref(),
                        deadline,
                    )
                    .await
            }
        }
    }
}

impl RuntimeCapabilitiesCollector for ServerRuntimeCapabilitiesCollector {
    fn observe<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        Box::pin(async move {
            let scope = RuntimeCapabilityHostScope::for_server(
                &self.factory.issuer,
                auth,
                self.factory.revision.runtime_epoch(),
            )?;
            let facts = self.current_facts(auth, deadline).await?;
            facts.into_observation(scope, &self.factory.revision.next()?)
        })
    }
    fn finalize<'a>(
        &'a self,
        auth: &'a AuthContext,
        observed: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilitiesFuture<'a> {
        Box::pin(async move {
            // Authenticate the original concrete epoch even if the first observation failed.
            let current = self.current_facts(auth, deadline).await?;
            let observed = observed?;
            if !observed.scope().matches_auth(auth) {
                return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
            }
            Ok(current.apply(observed))
        })
    }
    fn tail_current(
        &self,
        auth: &AuthContext,
        finalized: RuntimeCapabilityObservationResult,
        deadline: CapabilityDeadline,
    ) -> RuntimeCapabilityObservationResult {
        if !self.factory.issuer.observation().is_current() || !self.facts.is_current() {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        deadline.check()?;
        let binding = auth
            .request_binding()
            .ok_or(RuntimeCapabilitiesCollectionError::MissingHostSource)?;
        if !self.factory.issuer.owns_identity(binding.identity()) {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        match &self.factory.source {
            ServerCapabilitySource::Session(source) if source.strong_count() == 0 => {
                return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
            }
            ServerCapabilitySource::SingleUser(source) if source.strong_count() == 0 => {
                return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
            }
            _ => {}
        }
        let observation = finalized?;
        if !observation.scope().matches_auth(auth) {
            return Err(RuntimeCapabilitiesCollectionError::NotCurrent);
        }
        deadline.check()?;
        Ok(observation)
    }
}

fn session_cookie(parts: &Parts) -> Option<&str> {
    let mut found = None;
    for header in parts.headers.get_all(http::header::COOKIE) {
        let value = header.to_str().ok()?;
        for pair in value.split(';') {
            let (name, value) = pair.trim().split_once('=')?;
            if name == SESSION_COOKIE_NAME && found.replace(value).is_some() {
                return None;
            }
        }
    }
    found
}

fn auth_row_error(error: tokio_postgres::Error) -> AppError {
    tracing::error!(error = %error, "session resolver 行解码失败");
    AppError::DependencyUnavailable {
        dependency: "database",
    }
}

/// 固定身份 / 固定拒绝的 [`AuthResolver`]，**只在测试与 `testkit` feature 下存在**。
///
/// 它没有 `Default`，也没有 `new()`：两个构造器 [`Self::granting`] 与 [`Self::rejecting`]
/// 都要求调用方明确说出"放行成谁"或"以什么理由拒绝"。
#[cfg(any(test, feature = "testkit"))]
pub struct FixedAuthResolver {
    outcome: Result<ResolvedAuth, AppError>,
}

#[cfg(any(test, feature = "testkit"))]
impl FixedAuthResolver {
    /// 恒定放行成给定身份。
    #[must_use]
    pub const fn granting(auth: AuthContext) -> Self {
        Self {
            outcome: Ok(ResolvedAuth::without_session(auth)),
        }
    }

    /// 恒定放行成调用方已构造的 live-session 结果；只供敏感写测试。
    #[must_use]
    pub const fn granting_resolved(resolved: ResolvedAuth) -> Self {
        Self {
            outcome: Ok(resolved),
        }
    }

    /// 恒定拒绝，理由由调用方给出。
    #[must_use]
    pub const fn rejecting(error: AppError) -> Self {
        Self {
            outcome: Err(error),
        }
    }
}

#[cfg(any(test, feature = "testkit"))]
#[async_trait]
impl AuthResolver for FixedAuthResolver {
    async fn resolve(&self, _parts: &Parts) -> Result<AuthContext, AppError> {
        self.outcome.clone().map(ResolvedAuth::into_context)
    }

    async fn resolve_with_assurance(&self, _parts: &Parts) -> Result<ResolvedAuth, AppError> {
        self.outcome.clone()
    }
}

#[cfg(test)]
mod gateway_authorization_journal_tests;

#[cfg(test)]
mod gateway_callback_rendezvous_tests;
#[cfg(test)]
mod gateway_registration_dispatch_tests;
