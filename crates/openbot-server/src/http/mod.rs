//! HTTP 路由表与 handler。
//!
//! # 落点逐字对齐 parity ledger
//!
//! `parity/api.yaml` 把路由落点写死到**模块路径**这一级；W-4 在 G1 四条之上追加
//! `/api/me`、admin status/people 与 W-5 audit 读面。
//!
//! ```text
//! health-get              target: "openbot-server::http::health (GET /health)"
//! readiness-get           target: "openbot-server::http::readiness (GET /readiness)"
//! metrics-get             target: "openbot-server::http::metrics (GET /metrics)"
//! api-channels-list-get   target: "openbot-server::http::channels::list (GET /api/channels)"
//! api-threads-mint-post   target: "openbot-server::http::threads::mint (POST /api/threads/mint)"
//! api-threads-get         target: "openbot-server::http::threads::status (GET /api/threads/{thread_id})"
//! thread-events-sse-get   target: "openbot-server::http::threads::events (GET /api/threads/{thread_id}/events)"
//! thread-events-ws-get    target: "openbot-server::http::threads::websocket (GET /api/threads/{thread_id}/ws)"
//! screen-session/ws       target: "openbot-server::http::screen (POST /api/screen/sessions + GET /api/screen)"
//! memory-list/remember/correct/delete/forbid/recall —— R66 新增 explicit memory API
//! components list/catalogue —— R103 compiled component治理读面与exact additive build sync
//! sandboxed draft/published/save/publish/delete —— R112 sandboxed source原子治理
//! ```
//!
//! 所以 [`health`] / [`channels`] / [`metrics`] 这几个模块名、[`channels::list`] 这个函数名
//! 都不是随手起的 —— 它们是台账里那一行的另一半。改名会让 `cargo xtask parity-check` 与
//! 人工复核同时失去锚点。（`readiness-get` 的 target 写的是 `http::readiness`，而实现落在
//! [`health::readiness`]：health 与 readiness 是同一件事的两半，拆成两个文件只会让那份
//! 「两条路由的身份不同」的对照文档没地方写。函数路径 `http::health::readiness` 与台账里的
//! `http::readiness` 只差一个中间模块名，复核时按函数名锚定。）
//!
//! # 层序
//!
//! [`router`] 从内到外是：
//!
//! ```text
//! handler
//!   ← DefaultBodyLimit::disable()        Axum 默认 2 MiB 让位
//!   ← RequestBodyLimitLayer(1 MiB)       §5.2 的输入大小限制，唯一真源
//!   ← record_http_metrics                §16.4 的 latency / status / 在飞数
//!   ← trace_request                      §16.4 的请求 span（最外层）
//! ```
//!
//! span 在最外层，是为了让 413 与 404 也留下记录 —— 一条"什么都没记"的日志和一条
//! "记了但被拒"的日志，在排障时是完全不同的证据。metrics 紧贴其内，同样在体积上限
//! **之外**：一次 413 也是一次真实请求，不计进延迟分布就等于把被拒流量藏起来。

pub mod admin;
pub mod agent_tools;
pub mod agents;
pub mod approvals;
pub mod artifact_reads;
pub mod artifact_save_receipts;
pub mod artifacts;
pub mod auth_oidc;
pub mod auth_sso;
pub mod channels;
pub mod components;
pub mod computers;
pub mod custom_model_catalog;
pub mod health;
pub mod memories;
pub mod metrics;
pub mod model_connections;
pub mod plugins;
mod realtime;
#[cfg(test)]
mod reconciliation_tests;
pub mod remote_interrupts;
pub mod routing;
pub mod run_cost_budget;
pub mod runtime_capabilities;
pub mod sandbox_runner;
pub mod sandboxed;
pub mod screen;
pub mod session;
pub mod static_app;
pub mod threads;
mod transport_gate;
pub mod ui_preferences;

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::MatchedPath;
use axum::extract::{DefaultBodyLimit, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{delete, get, post};
use openbot_agent::RemoteAgentToolInvoker;
use openbot_application::{ApplicationService, McpOAuthCallback, RemoteCallbackAuthenticator};
use openbot_computer::screen::ScreenHub;
use openbot_domain::identity::session::TrustedOrigins;
use openbot_infra::auth::oidc::{OidcLoginCoordinator, PreAuthSurface};
use openbot_infra::auth::sso::DynamicSsoService;
use tower_http::limit::RequestBodyLimitLayer;

use crate::auth::{AuthResolver, ResolvedAuth, SensitiveWriteSecurity};
use crate::config::transport::TrustedTransportPolicy;
use crate::limits::REQUEST_BODY_LIMIT_BYTES;
use crate::metrics::MetricsHandle;
use crate::readiness::ReadinessProbe;
use crate::telemetry::trace_request;

use self::static_app::StaticApp;

/// router 的共享状态。
///
/// 五样东西对应 transport 的受控外部接缝：业务入口、认证边界、readiness 判据、metrics
/// 渲染句柄，以及已经由启动配置裁决好的 `insecure_transport` 布尔事实。数据库连接、原始
/// 配置和密钥都不在这里，因为 transport 不该碰它们。
#[derive(Clone)]
pub struct ServerState {
    inner: Arc<StateInner>,
}

/// A trusted Rust consumer retains the original resolved session for every block.
pub struct ServerArtifactReadOperation {
    auth: openbot_contracts::auth::AuthContext,
    operation: openbot_application::CurrentArtifactReadOperation,
}

impl ServerArtifactReadOperation {
    /// Read and hand off the next original-session block, or verified EOF.
    pub async fn next_block(
        &mut self,
    ) -> Result<
        Option<openbot_contracts::artifact_read::LeasedArtifactReadBlock>,
        openbot_contracts::error::AppError,
    > {
        self.operation
            .next_block(&self.auth)
            .await?
            .handoff(&self.auth)
    }
}

struct StateInner {
    application: Arc<dyn ApplicationService>,
    auth: Arc<dyn AuthResolver>,
    readiness: Vec<Arc<dyn ReadinessProbe>>,
    metrics: Option<MetricsHandle>,
    sensitive_write: Option<SensitiveWriteSecurity>,
    insecure_transport: bool,
    transport_policy: TrustedTransportPolicy,
    oidc: Option<Arc<OidcLoginCoordinator>>,
    preauth: PreAuthSurface,
    login_origins: Option<TrustedOrigins>,
    secure_session_cookie: bool,
    dynamic_sso: Option<Arc<DynamicSsoService>>,
    remote_callback_auth: Option<Arc<dyn RemoteCallbackAuthenticator>>,
    remote_callback_tools: Option<Arc<dyn RemoteAgentToolInvoker>>,
    mcp_oauth_callback: Option<Arc<dyn McpOAuthCallback>>,
    static_app: Option<StaticApp>,
    screen_hub: Option<ScreenHub>,
}

impl ServerState {
    /// 唯一业务入口（v3 §5.2）。
    #[must_use]
    pub fn application(&self) -> &dyn ApplicationService {
        self.inner.application.as_ref()
    }

    /// 认证边界。
    #[must_use]
    pub fn auth_resolver(&self) -> &dyn AuthResolver {
        self.inner.auth.as_ref()
    }

    /// Read one current first chunk for a trusted Rust consumer; no HTTP route is added.
    pub async fn read_current_artifact_chunk(
        &self,
        parts: &http::request::Parts,
        artifact_id: String,
    ) -> Result<Vec<u8>, openbot_contracts::error::AppError> {
        let auth = self.auth_resolver().resolve(parts).await?;
        let pending = self
            .application()
            .read_current_artifact_chunk(auth.clone(), artifact_id)
            .await?;
        pending.handoff(&auth)
    }

    /// Open a sequential read with the actual resolver and the same application service.
    pub async fn open_current_artifact_read(
        &self,
        parts: &http::request::Parts,
        artifact_id: String,
    ) -> Result<ServerArtifactReadOperation, openbot_contracts::error::AppError> {
        let auth = self.auth_resolver().resolve(parts).await?;
        let operation = self
            .application()
            .open_current_artifact_read(auth.clone(), artifact_id)
            .await?;
        Ok(ServerArtifactReadOperation { auth, operation })
    }

    /// 已声明的 readiness 判据。**可以是空的，而空 = not ready**（见
    /// [`crate::readiness`] 模块文档）。
    #[must_use]
    pub fn readiness_probes(&self) -> &[Arc<dyn ReadinessProbe>] {
        &self.inner.readiness
    }

    /// metrics 渲染句柄。`None` 时 `/metrics` fail-closed 回 503（见
    /// [`metrics`] 模块文档）。
    #[must_use]
    pub fn metrics_handle(&self) -> Option<&MetricsHandle> {
        self.inner.metrics.as_ref()
    }

    /// 非 loopback 明文 HTTP 是否正在承载会话；只投影到 readiness 元数据。
    #[must_use]
    pub fn insecure_transport(&self) -> bool {
        self.inner.insecure_transport
    }

    /// OIDC 协调器；单用户模式为 `None`，handler 必须 fail-closed 503。
    #[must_use]
    pub fn oidc_login(&self) -> Option<&OidcLoginCoordinator> {
        self.inner.oidc.as_deref()
    }

    /// 匿名能力投影；类型本身装不下动态 provider/domain。
    #[must_use]
    pub fn preauth_surface(&self) -> &PreAuthSurface {
        &self.inner.preauth
    }

    /// 登录 start POST 的 Origin 是否属于配置集合。
    #[must_use]
    pub fn trusts_login_origin(&self, origin: &str) -> bool {
        self.inner
            .login_origins
            .as_ref()
            .is_some_and(|trusted| trusted.trusts(origin))
    }

    /// `Secure` iff OPENBOT_PUBLIC_URL 是 https；与 resolver/cookie 共用同一配置事实。
    #[must_use]
    pub fn secure_session_cookie(&self) -> bool {
        self.inner.secure_session_cookie
    }

    /// deployment-owned OIDC/SAML；未注入时管理写面与 email routing fail-closed。
    #[must_use]
    pub fn dynamic_sso(&self) -> Option<&DynamicSsoService> {
        self.inner.dynamic_sso.as_deref()
    }

    /// Remote machine-to-machine callback verifier; absent means the public route returns 503.
    #[must_use]
    pub fn remote_callback_authenticator(&self) -> Option<&dyn RemoteCallbackAuthenticator> {
        self.inner.remote_callback_auth.as_deref()
    }

    /// Governed callback executor; absent means authenticated calls fail closed with 503.
    #[must_use]
    pub fn remote_callback_tools(&self) -> Option<&dyn RemoteAgentToolInvoker> {
        self.inner.remote_callback_tools.as_deref()
    }

    /// Public MCP OAuth callback authenticator/coordinator.
    #[must_use]
    pub fn mcp_oauth_callback(&self) -> Option<&dyn McpOAuthCallback> {
        self.inner.mcp_oauth_callback.as_deref()
    }

    /// Validated static GUI bundle, when `APP_DIST_DIR` is configured.
    #[must_use]
    pub fn static_app(&self) -> Option<&StaticApp> {
        self.inner.static_app.as_ref()
    }

    /// ScreenHub used by the binary data plane; absence makes screen routes fail closed.
    #[must_use]
    pub fn screen_hub(&self) -> Option<&ScreenHub> {
        self.inner.screen_hub.as_ref()
    }

    /// 敏感写 guard；未注入时 fail-closed 503，不给 handler 任何“暂时跳过”路径。
    pub async fn authorize_sensitive_write(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<(), openbot_contracts::error::AppError> {
        let Some(security) = &self.inner.sensitive_write else {
            return Err(openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "sensitive_write_security",
            });
        };
        let _approved = security.authorize(resolved, origin)?;
        self.inner.auth.touch(resolved).await
    }

    /// Same-origin authenticated operation：Memory owner 写与 thread WebSocket 共用；
    /// 不额外要求 admin/fresh，但 Origin 失败不得 touch session idle。
    pub async fn authorize_authenticated_origin(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<(), openbot_contracts::error::AppError> {
        let Some(security) = &self.inner.sensitive_write else {
            return Err(openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "sensitive_write_security",
            });
        };
        security.authorize_origin(origin)?;
        self.inner.auth.touch(resolved).await
    }

    /// Catalogue observation preserves the original session idle/touch facts.
    pub(crate) fn authorize_custom_model_catalog_origin(
        &self,
        origin: Option<&str>,
    ) -> Result<(), openbot_contracts::error::AppError> {
        let Some(security) = &self.inner.sensitive_write else {
            return Err(openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "sensitive_write_security",
            });
        };
        security.authorize_origin(origin)
    }

    /// Fresh same-origin write whose per-resource authorization remains in application/infra.
    pub async fn authorize_fresh_origin_write(
        &self,
        resolved: &ResolvedAuth,
        origin: Option<&str>,
    ) -> Result<(), openbot_contracts::error::AppError> {
        let Some(security) = &self.inner.sensitive_write else {
            return Err(openbot_contracts::error::AppError::DependencyUnavailable {
                dependency: "sensitive_write_security",
            });
        };
        security.authorize_fresh_origin(resolved, origin)?;
        self.inner.auth.touch(resolved).await
    }
}

/// [`ServerState`] 的构造器。
///
/// 存在的理由是**让"什么都没声明"变成一次显式选择**：`new` 强制交出业务入口与
/// `AuthResolver`（两者都拿不出默认值，见 [`crate::auth`] 模块文档"不提供默认放行"），
/// readiness 判据则由 [`Self::with_readiness_probe`] 逐个加。一个探针都不加不会报错，
/// 但 `/readiness` 会诚实地回 503 —— 沉默地宣称 ready 才是那个不该存在的选项。
pub struct ServerBuilder {
    application: Arc<dyn ApplicationService>,
    auth: Arc<dyn AuthResolver>,
    readiness: Vec<Arc<dyn ReadinessProbe>>,
    metrics: Option<MetricsHandle>,
    sensitive_write: Option<SensitiveWriteSecurity>,
    insecure_transport: bool,
    transport_policy: TrustedTransportPolicy,
    oidc: Option<Arc<OidcLoginCoordinator>>,
    preauth: PreAuthSurface,
    login_origins: Option<TrustedOrigins>,
    secure_session_cookie: bool,
    dynamic_sso: Option<Arc<DynamicSsoService>>,
    remote_callback_auth: Option<Arc<dyn RemoteCallbackAuthenticator>>,
    remote_callback_tools: Option<Arc<dyn RemoteAgentToolInvoker>>,
    mcp_oauth_callback: Option<Arc<dyn McpOAuthCallback>>,
    static_app: Option<StaticApp>,
    screen_hub: Option<ScreenHub>,
}

impl ServerBuilder {
    /// 注入业务入口与认证实现。两者都没有默认值。
    #[must_use]
    pub fn new(application: Arc<dyn ApplicationService>, auth: Arc<dyn AuthResolver>) -> Self {
        Self {
            application,
            auth,
            readiness: Vec::new(),
            metrics: None,
            sensitive_write: None,
            insecure_transport: false,
            transport_policy: TrustedTransportPolicy::builder_default(),
            oidc: None,
            preauth: PreAuthSurface::default(),
            login_origins: None,
            secure_session_cookie: false,
            dynamic_sso: None,
            remote_callback_auth: None,
            remote_callback_tools: None,
            mcp_oauth_callback: None,
            static_app: None,
            screen_hub: None,
        }
    }

    /// 追加一条 readiness 判据。
    ///
    /// 逐条追加而不是一次性传一个 `Vec`：每一条都该在接线层留下一次可 grep 的调用，
    /// 与 `AuthContextBuilder::with_role` 逐个追加角色是同一个理由 —— 让"这个判据是谁
    /// 加的、依据什么"在代码里有落点。
    #[must_use]
    pub fn with_readiness_probe(mut self, probe: Arc<dyn ReadinessProbe>) -> Self {
        self.readiness.push(probe);
        self
    }

    /// 交出 metrics 渲染句柄，让 `/metrics` 能出数。
    ///
    /// 句柄由宿主调 [`crate::metrics::install_recorder`] 拿到 —— **安装全局 recorder 是
    /// 宿主的动作，不是本 crate 的**（与 [`crate::telemetry::init`] 同一条纪律）。不交
    /// 句柄时 `/metrics` 回 503，而记录路径本身仍然是 `metrics` 门面的 no-op，不报错、
    /// 不建连。
    #[must_use]
    pub fn with_metrics_handle(mut self, handle: MetricsHandle) -> Self {
        self.metrics = Some(handle);
        self
    }

    /// 注入 fresh-session + trusted-origin 敏感写配置。
    #[must_use]
    pub fn with_sensitive_write_security(mut self, security: SensitiveWriteSecurity) -> Self {
        self.sensitive_write = Some(security);
        self
    }

    /// 注入由 [`crate::config::PublicTransport`] 单点裁决出的明文暴露事实。
    #[must_use]
    pub const fn with_insecure_transport(mut self, insecure: bool) -> Self {
        self.insecure_transport = insecure;
        self
    }

    /// Require the explicit configuration-derived connection policy before any business route.
    /// The production default denies; a declared HTTPS public URL alone grants no access.
    #[must_use]
    pub fn with_transport_policy(mut self, policy: TrustedTransportPolicy) -> Self {
        self.transport_policy = policy;
        self
    }

    /// 注入所有登录协议共用的 Origin 与 cookie 策略。
    ///
    /// 它不能附着在 OIDC coordinator 上：只有数据库动态 SAML/OIDC 的部署同样需要这两项，
    /// 否则匿名 email routing 会在配置正确时仍恒定拒绝。
    #[must_use]
    pub fn with_login_security(
        mut self,
        trusted_origins: TrustedOrigins,
        secure_cookie: bool,
    ) -> Self {
        self.login_origins = Some(trusted_origins);
        self.secure_session_cookie = secure_cookie;
        self
    }

    /// 注入环境配置的 OIDC coordinator 与其公开投影。
    #[must_use]
    pub fn with_oidc_login(
        mut self,
        coordinator: Arc<OidcLoginCoordinator>,
        preauth: PreAuthSurface,
    ) -> Self {
        self.oidc = Some(coordinator);
        self.preauth = preauth;
        self
    }

    /// 注入跨 replica 的 deployment-owned OIDC/SAML 服务。
    #[must_use]
    pub fn with_dynamic_sso(mut self, service: Arc<DynamicSsoService>) -> Self {
        self.dynamic_sso = Some(service);
        self
    }

    /// Attach the production per-Agent token + signed-run callback verifier.
    #[must_use]
    pub fn with_remote_callback_authenticator(
        mut self,
        authenticator: Arc<dyn RemoteCallbackAuthenticator>,
    ) -> Self {
        self.remote_callback_auth = Some(authenticator);
        self
    }

    /// Attach the callback side of the same governed Agent tool gateway used by built-in runs.
    #[must_use]
    pub fn with_remote_callback_tools(mut self, tools: Arc<dyn RemoteAgentToolInvoker>) -> Self {
        self.remote_callback_tools = Some(tools);
        self
    }

    /// Attach the one-time-state MCP OAuth callback coordinator.
    #[must_use]
    pub fn with_mcp_oauth_callback(mut self, callback: Arc<dyn McpOAuthCallback>) -> Self {
        self.mcp_oauth_callback = Some(callback);
        self
    }

    /// Attach a validated static Leptos bundle.
    #[must_use]
    pub fn with_static_app(mut self, app: StaticApp) -> Self {
        self.static_app = Some(app);
        self
    }

    /// Attach the exact ScreenHub shared with the ApplicationService ticket port.
    #[must_use]
    pub fn with_screen_hub(mut self, screen_hub: ScreenHub) -> Self {
        self.screen_hub = Some(screen_hub);
        self
    }

    /// 收口成 [`ServerState`]。
    #[must_use]
    pub fn build(self) -> ServerState {
        ServerState {
            inner: Arc::new(StateInner {
                application: self.application,
                auth: self.auth,
                readiness: self.readiness,
                metrics: self.metrics,
                sensitive_write: self.sensitive_write,
                insecure_transport: self.insecure_transport,
                transport_policy: self.transport_policy,
                oidc: self.oidc,
                preauth: self.preauth,
                login_origins: self.login_origins,
                secure_session_cookie: self.secure_session_cookie,
                dynamic_sso: self.dynamic_sso,
                remote_callback_auth: self.remote_callback_auth,
                remote_callback_tools: self.remote_callback_tools,
                mcp_oauth_callback: self.mcp_oauth_callback,
                static_app: self.static_app,
                screen_hub: self.screen_hub,
            }),
        }
    }

    /// 直接组装出可用的 [`Router`]。
    pub fn into_router(self) -> Router {
        router(self.build())
    }
}

/// 请求级 metrics 中间件。
///
/// 只做三件事：在飞数 +1（守卫到期自动 -1）、量墙钟、把耗时与状态记进直方图。
/// **不看 body、不看 header、不看路径** —— 它没有任何机会把不可信字节变成 label
/// （基数论证见 [`crate::metrics`] 模块文档）。
async fn record_http_metrics(request: Request, next: Next) -> Response {
    let _in_flight = crate::metrics::track_in_flight();
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or(crate::metrics::ROUTE_UNMATCHED, MatchedPath::as_str)
        .to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    crate::metrics::record_http_request(&method, response.status(), started.elapsed(), &route);
    response
}

/// 组装当前 Server 路由表。
///
/// 每条路由的 ledger 出处见 crate 文档。层序见模块文档。
///
/// # 未匹配的路径
///
/// 刻意保留 Axum 默认的 404（空体），**不**套用 [`crate::error`] 的错误信封。理由：
/// §15.3 那个"统一 404"说的是**资源**不可见（防枚举），而"这个路径上没有路由"是另一件
/// 事。把两者渲染成同一个 `not_visible`，会让客户端把"接口拼错了"读成"这条资源你看不
/// 到"，也会让防枚举那条判据的含义变得含混。
pub fn router(state: ServerState) -> Router {
    let static_app = state.static_app().cloned();
    let transport_policy = state.inner.transport_policy.clone();
    let router = Router::new()
        .route("/health", get(health::health))
        .route("/readiness", get(health::readiness))
        .route("/metrics", get(metrics::render))
        .route("/api/capabilities", get(auth_oidc::capabilities))
        .route("/api/auth/oidc/{provider_id}/start", post(auth_oidc::start))
        .route(
            "/api/auth/oidc/{provider_id}/callback",
            get(auth_oidc::callback),
        )
        .route("/api/auth/sso/start", post(auth_sso::route_email))
        .route("/api/auth/sso/continue", get(auth_sso::continue_route))
        .route("/api/auth/sso/register", post(auth_sso::register))
        .route("/api/auth/sso/update-provider", post(auth_sso::update))
        .route(
            "/api/auth/sso/delete-provider",
            post(auth_sso::remove_compat),
        )
        .route(
            "/api/auth/sso/saml2/sp/acs/{provider_id}",
            post(auth_sso::saml_acs),
        )
        .route(
            "/api/auth/sso/saml2/sp/metadata/{provider_id}",
            get(auth_sso::saml_metadata),
        )
        .route("/api/channels", get(channels::list).post(channels::create))
        .route("/api/channels/events", get(channels::events))
        .route("/api/channels/{channel_id}", get(channels::get))
        .route("/api/route", post(routing::choose))
        .route(
            "/api/agents",
            get(agents::list_get).post(agents::create_post),
        )
        .route(
            "/api/agents/test-connection",
            post(agents::test_connection_post),
        )
        .route(
            "/api/agents/{agent_id}",
            get(agents::get)
                .patch(agents::update_patch)
                .delete(agents::delete_agent),
        )
        .route(
            "/api/agents/{agent_id}/duplicate",
            post(agents::duplicate_post),
        )
        .route("/api/agents/{agent_id}/hide", post(agents::hide_post))
        .route("/api/agents/{agent_id}/unhide", post(agents::unhide_post))
        .route("/api/components", get(components::list_get))
        .route(
            "/api/components/catalogue",
            axum::routing::put(components::catalogue_put),
        )
        .route(
            "/api/components/for-agent/{agent_id}",
            get(components::for_agent_get),
        )
        .route(
            "/api/components/{name}/decision",
            post(components::decision_post),
        )
        .route("/api/components/functions", get(components::functions_get))
        .route(
            "/api/components/{name}/functions",
            post(components::functions_post),
        )
        .route(
            "/api/components/{name}/functions/{function}",
            delete(components::functions_delete),
        )
        .route(
            "/api/components/{name}/grants",
            post(components::grants_post),
        )
        .route(
            "/api/components/{name}/grants/{agent_id}",
            delete(components::grants_delete),
        )
        .route(
            "/api/components/{name}/publication",
            post(components::publication_post),
        )
        .route(
            "/api/components/{name}/draft",
            axum::routing::put(components::draft_put),
        )
        .route(
            "/api/components/human-decisions",
            get(components::human_decisions_get),
        )
        .route(
            "/api/components/human-decisions/{decision_id}/answer",
            post(components::human_decision_answer_post),
        )
        .route("/api/components/{name}/call", post(components::call_post))
        .route(
            "/api/sandboxed",
            get(sandboxed::list_get).post(sandboxed::create_post),
        )
        .route("/api/sandboxed/published", get(sandboxed::published_get))
        .route(
            "/api/sandboxed/{name}/publish",
            post(sandboxed::publish_post),
        )
        .route("/api/sandboxed/{name}", delete(sandboxed::delete))
        .route("/sandbox/runner", get(sandbox_runner::document))
        .route("/api/tool-approvals", get(approvals::pending_get))
        .route("/api/tool-approvals/events", get(approvals::events))
        .route(
            "/api/tool-approvals/{approval_id}",
            post(approvals::decision_post),
        )
        .route("/api/plugins/connections", get(plugins::connections_get))
        .route("/api/plugins", get(plugins::list_get))
        .route("/api/plugins/servers", post(plugins::servers_post))
        .route(
            "/api/plugins/servers/custom",
            post(plugins::servers_custom_post),
        )
        .route(
            "/api/plugins/servers/{server_id}",
            delete(plugins::servers_delete),
        )
        .route(
            "/api/plugins/connections/{server_id}",
            delete(plugins::connections_delete),
        )
        .route(
            "/api/plugins/servers/{server_id}/connect",
            post(plugins::servers_connect_post),
        )
        .route(
            "/api/plugins/servers/{server_id}/oauth-client",
            post(plugins::servers_oauth_client_post),
        )
        .route(
            "/api/plugins/servers/{server_id}/refresh",
            post(plugins::servers_refresh_post),
        )
        .route("/api/plugins/skills", post(plugins::skills_post))
        .route("/api/plugins/skills/{slug}", delete(plugins::skills_delete))
        .route(
            "/api/plugins/grants",
            post(plugins::grants_post).delete(plugins::grants_delete),
        )
        .route("/api/plugins/for/{agent_id}", get(plugins::for_agent_get))
        .route(
            "/api/plugins/oauth/callback",
            get(plugins::oauth_callback_get),
        )
        .route(
            "/api/memories",
            get(memories::list).post(memories::remember),
        )
        .route(
            "/api/memories/control",
            get(memories::control_get).put(memories::control_put),
        )
        .route("/api/memories/recall", post(memories::recall))
        .route(
            "/api/memories/{memory_id}",
            axum::routing::put(memories::correct).delete(memories::delete),
        )
        .route("/api/memories/{memory_id}/forbid", post(memories::forbid))
        .route("/api/artifact-reads", post(artifact_reads::open))
        .route(
            "/api/artifact-reads/{handle_id}/next",
            post(artifact_reads::next),
        )
        .route(
            "/api/artifact-reads/{handle_id}/ack",
            post(artifact_reads::acknowledge),
        )
        .route(
            "/api/artifact-reads/{handle_id}",
            delete(artifact_reads::close),
        )
        .route(
            "/api/artifacts/save-run-message-text",
            post(artifacts::save),
        )
        .route(
            artifact_save_receipts::SAVE_REQUESTS_PATH,
            get(artifact_save_receipts::get).head(artifact_save_receipts::reject_head),
        )
        .route(
            "/api/artifacts/save-requests/",
            get(artifact_save_receipts::get).head(artifact_save_receipts::reject_head),
        )
        .route(
            "/api/artifacts/save-requests/{*request_path}",
            get(artifact_save_receipts::get).head(artifact_save_receipts::reject_head),
        )
        .route(
            "/api/artifacts/source-runs/{source_thread_id}/{source_run_id}",
            get(artifacts::source_run_ids).head(|| async {
                (
                    axum::http::StatusCode::METHOD_NOT_ALLOWED,
                    [(axum::http::header::CACHE_CONTROL, "no-store")],
                )
            }),
        )
        .route(
            "/api/artifacts/{artifact_id}",
            get(artifacts::metadata)
                .head(|| async {
                    (
                        axum::http::StatusCode::METHOD_NOT_ALLOWED,
                        [(axum::http::header::CACHE_CONTROL, "no-store")],
                    )
                })
                .delete(artifacts::delete),
        )
        .route("/api/threads/mint", post(threads::mint))
        .route(
            "/api/threads/{thread_id}/conversation",
            get(threads::conversation),
        )
        .route("/api/threads/{thread_id}/runs", post(threads::begin_run))
        .route(
            "/api/threads/{thread_id}/runs/{run_id}/cancel",
            post(threads::cancel_run),
        )
        .route(
            "/api/threads/{thread_id}/runs/{run_id}/reconciliation",
            get(threads::reconciliation)
                .head(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route(
            "/api/threads/{thread_id}/runs/{run_id}/reconciliation/receipts",
            get(threads::effect_receipts)
                .head(|| async { axum::http::StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route(
            "/api/threads/{thread_id}/history/deletions",
            post(threads::delete_history),
        )
        .route("/api/threads/{thread_id}/ws", get(threads::websocket))
        .route("/api/threads/{thread_id}/events", get(threads::events))
        .route("/api/threads/{thread_id}", get(threads::status))
        .route(
            "/api/copilotkit/threads/{thread_id}/messages",
            get(threads::history),
        )
        .route("/api/me", get(admin::me))
        .route(
            custom_model_catalog::PATH,
            get(custom_model_catalog::list).head(custom_model_catalog::reject_head),
        )
        .route(
            runtime_capabilities::RUNTIME_CAPABILITIES_PATH,
            get(runtime_capabilities::get).head(runtime_capabilities::reject_head),
        )
        .route(
            "/api/me/model-connections",
            get(model_connections::list).post(model_connections::create),
        )
        .route(
            "/api/me/model-connections/{connection_id}",
            get(model_connections::get)
                .put(model_connections::update)
                .delete(model_connections::delete),
        )
        .route("/api/me/session", get(session::status))
        .route("/api/auth/sign-out", post(session::sign_out))
        .route(
            "/api/me/preferences",
            get(ui_preferences::get).put(ui_preferences::put),
        )
        .route(
            "/api/me/run-cost-budget",
            get(run_cost_budget::get).put(run_cost_budget::put),
        )
        .route("/api/me/remote-interrupts", get(remote_interrupts::get))
        .route("/api/screen/sessions", post(screen::issue_session))
        .route("/api/screen", get(screen::websocket))
        .route(
            "/api/me/remote-interrupts/{request_id}",
            axum::routing::put(remote_interrupts::put),
        )
        .route("/api/admin/status", get(admin::status))
        .route("/api/admin/identity-providers", get(auth_sso::list))
        .route(
            "/api/admin/identity-providers/{provider_id}",
            delete(auth_sso::remove_admin),
        )
        .route("/api/admin/people", get(admin::people_list))
        .route(
            "/api/admin/credentials",
            get(admin::credentials_list).post(admin::credentials_create),
        )
        .route(
            "/api/admin/credentials/{credential_id}/rotate",
            post(admin::credentials_rotate),
        )
        .route(
            "/api/admin/credentials/{credential_id}/revoke",
            post(admin::credentials_revoke),
        )
        .route("/api/agent-tools/call", post(agent_tools::call))
        .route(
            "/api/agents/{agent_id}/callback-token",
            post(agents::callback_token_post).delete(agents::callback_token_delete),
        )
        .route("/api/admin/audit-events", get(admin::audit_events))
        .route(
            "/api/computers/policy",
            get(computers::policy_get).put(computers::policy_put),
        )
        .route("/api/admin/people/{user_id}/role", post(admin::people_role))
        .route(
            "/api/admin/people/{user_id}/access",
            post(admin::people_access),
        )
        .with_state(state);
    let router = match static_app {
        Some(app) => static_app::mount(router, app),
        None => router,
    };
    // Static routes are mounted before these layers so GUI HTML/assets and their 404/405 paths
    // retain the same request-id, tracing, metrics and bounded-body transport contract as APIs.
    // Axum only applies `Router::layer` to routes already present at the call site.
    router
        // Axum 自带一个 2 MiB 的默认上限，且只对消费 body 的提取器生效。关掉它，让
        // `REQUEST_BODY_LIMIT_BYTES` 成为唯一真源 —— 两个上限就是两个答案。
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            transport_policy,
            transport_gate::enforce,
        ))
        .layer(axum::middleware::from_fn(
            threads::reconciliation_response_policy,
        ))
        .layer(axum::middleware::from_fn(
            runtime_capabilities::response_policy,
        ))
        .layer(axum::middleware::from_fn(artifact_reads::response_policy))
        .layer(axum::middleware::from_fn(
            artifact_save_receipts::response_policy,
        ))
        .layer(axum::middleware::from_fn(
            custom_model_catalog::response_policy,
        ))
        .layer(axum::middleware::from_fn(record_http_metrics))
        .layer(axum::middleware::from_fn(trace_request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::FixedAuthResolver;
    use crate::metrics::{
        HTTP_METRIC_LABELS, HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_IN_FLIGHT, LABEL_METHOD,
        LABEL_ROUTE, LABEL_STATUS, LABEL_TRANSPORT, METHOD_OTHER, ROUTE_UNMATCHED,
    };
    use crate::readiness::{ReadinessStatus, ReadinessVerdict};
    use crate::telemetry::{
        ACTOR_ID_FIELD, HTTP_ROUTE_FIELD, REQUEST_ID_HEADER, REQUEST_SPAN_FIELDS, REQUEST_SPAN_NAME,
    };
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::collections::BTreeSet;

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use core::fmt;
    use core::future::Future;
    use http::{HeaderName, HeaderValue, Request, StatusCode};
    use openbot_application::cursor::ChannelCursor;
    use openbot_application::ports::{ChannelReader, PortError};
    use openbot_application::{AppEventStream, OpenBotApplication};
    use openbot_contracts::auth::{AuthContext, Role};
    use openbot_contracts::command::{
        AppCommand, AppReply, ChannelSummary, MAX_CHANNEL_PAGE, SubscriptionRequest,
    };
    use openbot_contracts::error::AppError;
    use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, TenantId};
    use std::sync::Mutex;
    use time::OffsetDateTime;
    use time::macros::datetime;
    use tower::ServiceExt as _;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
    use tracing_subscriber::registry::Registry;

    // -----------------------------------------------------------------------
    // 测试替身
    // -----------------------------------------------------------------------

    /// `auth_generation` 的哨兵值。tracing 测试要断言它**没有**出现在 span 里，
    /// 显眼的值让那条断言不会被别的数字偶然满足。
    const SENTINEL_AUTH_GENERATION: u64 = 424_242;

    const ACTOR: &str = "actor-g1";

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-g1"),
            TenantId::new("tenant-g1"),
            ActorId::new(ACTOR),
            [Role::Admin, Role::User],
            openbot_contracts::auth::AuthGeneration::new(SENTINEL_AUTH_GENERATION),
            false,
        )
    }

    fn summary(id: &str, last_message_at: OffsetDateTime) -> ChannelSummary {
        ChannelSummary {
            id: ChannelId::new(id),
            name: format!("channel {id}"),
            agent_ids: vec![BotId::new("bot-1")],
            last_message: Some("hi".to_owned()),
            last_message_at: Some(last_message_at),
            last_message_agent_id: Some(BotId::new("bot-1")),
            created_at: last_message_at - time::Duration::days(1),
            thread_id: None,
            active: true,
        }
    }

    /// 内存版 [`ChannelReader`]。
    ///
    /// 它**模拟数据库该有的行为**（按排序键定序、按 keyset 裁剪、按 limit 截断），
    /// 而不是"返回我准备好的那几行" —— 后者会让分页断言在翻页逻辑写反时照样绿。
    /// 这份替身是本 crate 自己的：`openbot-application` 的同名 fake 是 `pub(crate)` +
    /// `cfg(test)`，跨 crate 借不到。
    struct FakeChannelReader {
        rows: Vec<ChannelSummary>,
        failure: Option<PortError>,
    }

    impl FakeChannelReader {
        fn with_rows(rows: Vec<ChannelSummary>) -> Self {
            Self {
                rows,
                failure: None,
            }
        }

        fn failing(failure: PortError) -> Self {
            Self {
                rows: Vec::new(),
                failure: Some(failure),
            }
        }
    }

    #[async_trait]
    impl ChannelReader for FakeChannelReader {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            limit: u32,
            cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            if let Some(failure) = self.failure {
                return Err(failure);
            }
            let mut rows = self.rows.clone();
            rows.sort_by(|a, b| {
                let ra = openbot_application::channel_recency(a);
                let rb = openbot_application::channel_recency(b);
                rb.cmp(&ra).then_with(|| b.id.as_str().cmp(a.id.as_str()))
            });
            if let Some(cursor) = cursor {
                rows.retain(|row| {
                    let recency = openbot_application::channel_recency(row);
                    (recency, row.id.as_str()) < (cursor.recency, cursor.id.as_str())
                });
            }
            rows.truncate(limit as usize);
            Ok(rows)
        }
    }

    /// 记录 transport 递下来的 `AppCommand`，再原样转交真实 application。
    ///
    /// 这是"transport 没有自己做业务判定"这条断言的**唯一**可靠观察点：只看端口收到的
    /// `limit` 是分不清"transport 截断了"还是"application 截断了"的 —— 两条路径给出
    /// 同一个数字（`min(999999, 200) + 1` 与 `min(200, 200) + 1` 都是 201）。
    struct RecordingApplication {
        inner: OpenBotApplication<FakeChannelReader>,
        commands: Mutex<Vec<AppCommand>>,
    }

    impl RecordingApplication {
        fn new(reader: FakeChannelReader) -> Self {
            Self {
                inner: OpenBotApplication::new(reader),
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<AppCommand> {
            self.commands.lock().expect("记录锁不会中毒").clone()
        }
    }

    #[async_trait]
    impl ApplicationService for RecordingApplication {
        async fn execute(
            &self,
            auth: AuthContext,
            command: AppCommand,
        ) -> Result<AppReply, AppError> {
            self.commands
                .lock()
                .expect("记录锁不会中毒")
                .push(command.clone());
            self.inner.execute(auth, command).await
        }

        async fn subscribe(
            &self,
            auth: AuthContext,
            request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            self.inner.subscribe(auth, request).await
        }
    }

    /// 固定判定的 readiness 探针。
    struct StaticProbe(&'static str, ReadinessVerdict);

    #[async_trait]
    impl ReadinessProbe for StaticProbe {
        fn dependency(&self) -> &'static str {
            self.0
        }

        async fn check(&self) -> ReadinessVerdict {
            self.1
        }
    }

    // -----------------------------------------------------------------------
    // 组装
    // -----------------------------------------------------------------------

    fn state_with(
        application: Arc<dyn ApplicationService>,
        auth_resolver: FixedAuthResolver,
        probes: Vec<Arc<dyn ReadinessProbe>>,
    ) -> ServerState {
        let mut builder = ServerBuilder::new(application, Arc::new(auth_resolver));
        for probe in probes {
            builder = builder.with_readiness_probe(probe);
        }
        builder.build()
    }

    fn app_with_rows(rows: Vec<ChannelSummary>) -> Arc<RecordingApplication> {
        Arc::new(RecordingApplication::new(FakeChannelReader::with_rows(
            rows,
        )))
    }

    fn router_for(application: Arc<RecordingApplication>) -> Router {
        router(state_with(
            application,
            FixedAuthResolver::granting(auth()),
            Vec::new(),
        ))
    }

    #[tokio::test]
    async fn anonymous_capabilities_exposes_no_dynamic_provider_shape_and_is_no_store() {
        let captured = send(
            router_for(app_with_rows(Vec::new())),
            get("/api/capabilities"),
        )
        .await;
        assert_eq!(captured.status, StatusCode::OK);
        assert_eq!(captured.headers.get("cache-control").unwrap(), "no-store");
        assert_eq!(
            captured.json(),
            serde_json::json!({
                "mode": "rust",
                "durableHistory": true,
                "authProviders": [],
                "ssoConfigured": false,
            })
        );
    }

    struct Captured {
        status: StatusCode,
        headers: http::HeaderMap,
        body: String,
    }

    impl Captured {
        fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{}: {e}", self.body))
        }
    }

    async fn send(router: Router, request: Request<Body>) -> Captured {
        let response = router
            .oneshot(request)
            .await
            .expect("Axum service 不会失败");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("响应体读得完");
        Captured {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).expect("响应体是 UTF-8"),
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("请求构造合法")
    }

    // -----------------------------------------------------------------------
    // GET /api/channels
    // -----------------------------------------------------------------------

    /// 正常列表：200 + camelCase body，逐键与上游 `channelSummaryDto` 对齐。
    #[tokio::test]
    async fn list_returns_camel_case_channel_page() {
        let application = app_with_rows(vec![summary("c-1", datetime!(2026-08-22 04:05:06 UTC))]);
        let captured = send(router_for(Arc::clone(&application)), get("/api/channels")).await;

        assert_eq!(captured.status, StatusCode::OK);
        let value = captured.json();
        assert_eq!(value["channels"][0]["id"], "c-1");
        assert_eq!(
            value["channels"][0]["lastMessageAt"],
            "2026-08-22T04:05:06Z"
        );
        assert_eq!(value["channels"][0]["agentIds"][0], "bot-1");
        assert_eq!(value["channels"][0]["lastMessageAgentId"], "bot-1");
        assert_eq!(value["channels"][0]["createdAt"], "2026-08-21T04:05:06Z");
        assert_eq!(value["channels"][0]["threadId"], serde_json::Value::Null);
        assert_eq!(value["channels"][0]["active"], true);
        assert_eq!(value["nextCursor"], serde_json::Value::Null);

        // 没有信封：顶层就是 `ChannelPage` 本身，不是 `{"data": …}` 或 `{"kind": …}`。
        let keys: Vec<&str> = value
            .as_object()
            .expect("顶层是对象")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, vec!["channels", "nextCursor"]);
    }

    /// 空列表是 200 + `{"channels":[],"nextCursor":null}`，不是 404 也不是 500。
    ///
    /// §15.3 末条 + 上游缺陷 #72（空 history 500）的同族。
    #[tokio::test]
    async fn empty_list_is_two_hundred_with_an_empty_array() {
        let captured = send(router_for(app_with_rows(Vec::new())), get("/api/channels")).await;
        assert_eq!(captured.status, StatusCode::OK);
        assert_eq!(captured.body, r#"{"channels":[],"nextCursor":null}"#);
    }

    /// 篡改的 cursor → 400 + 稳定码，且 body 不含被篡改的原值。
    #[tokio::test]
    async fn tampered_cursor_is_four_hundred_with_a_stable_code() {
        let application = app_with_rows(vec![summary("c-1", datetime!(2026-08-22 04:05:06 UTC))]);
        let captured = send(
            router_for(Arc::clone(&application)),
            get("/api/channels?cursor=not-a-real-cursor"),
        )
        .await;

        assert_eq!(captured.status, StatusCode::BAD_REQUEST);
        assert_eq!(captured.json()["code"], "malformed_payload");
        // 不回显调用方送来的字节。
        assert!(
            !captured.body.contains("not-a-real-cursor"),
            "{}",
            captured.body
        );

        // transport 确实把游标**原样**递下去了 —— 它不解释游标，报 400 的是 application。
        assert_eq!(
            application.commands(),
            vec![AppCommand::ListVisibleChannels {
                limit: None,
                cursor: Some("not-a-real-cursor".to_owned()),
            }]
        );
    }

    /// 合法游标原样穿过 transport（正向对照：上一条不是"任何 cursor 都 400"）。
    #[tokio::test]
    async fn valid_cursor_round_trips_through_the_transport_untouched() {
        let rows = vec![
            summary("c-1", datetime!(2026-08-22 04:00:00 UTC)),
            summary("c-2", datetime!(2026-08-22 03:00:00 UTC)),
        ];
        let application = app_with_rows(rows);
        let first = send(
            router_for(Arc::clone(&application)),
            get("/api/channels?limit=1"),
        )
        .await;
        assert_eq!(first.status, StatusCode::OK);
        let cursor = first.json()["nextCursor"]
            .as_str()
            .expect("有下一页就必须有游标")
            .to_owned();

        let second = send(
            router_for(Arc::clone(&application)),
            get(&format!("/api/channels?limit=1&cursor={cursor}")),
        )
        .await;
        assert_eq!(second.status, StatusCode::OK);
        assert_eq!(second.json()["channels"][0]["id"], "c-2");

        assert_eq!(
            application.commands()[1],
            AppCommand::ListVisibleChannels {
                limit: Some(1),
                cursor: Some(cursor),
            },
            "transport 必须原样搬运游标，不做任何解释"
        );
    }

    /// **越界的 limit 由 application 截断，transport 一个字都不改。**
    ///
    /// 判据落在递下去的 `AppCommand` 上：只看端口收到的行数分不清是谁截断的
    /// （见 [`RecordingApplication`] 的类型文档）。
    #[tokio::test]
    async fn out_of_range_limit_is_clamped_by_the_application_not_the_transport() {
        let rows: Vec<ChannelSummary> = (0..250)
            .map(|i| {
                summary(
                    &format!("c-{i:03}"),
                    datetime!(2026-08-22 04:00:00 UTC) - time::Duration::minutes(i),
                )
            })
            .collect();
        let application = app_with_rows(rows);
        let captured = send(
            router_for(Arc::clone(&application)),
            get("/api/channels?limit=999999"),
        )
        .await;

        assert_eq!(captured.status, StatusCode::OK);
        assert_eq!(
            application.commands(),
            vec![AppCommand::ListVisibleChannels {
                limit: Some(999_999),
                cursor: None,
            }],
            "transport 擅自钳制 limit = 它在做业务判定（§5.2 禁止）"
        );
        // 而结果确实被 application 按 MAX_CHANNEL_PAGE 截断了。
        assert_eq!(
            captured.json()["channels"]
                .as_array()
                .expect("channels 是数组")
                .len(),
            MAX_CHANNEL_PAGE as usize
        );
    }

    /// 非法 limit（不是 u32）→ 400 稳定码，而不是 Axum 默认那段带内部细节的纯文本。
    #[tokio::test]
    async fn non_numeric_limit_is_a_stable_four_hundred() {
        let application = app_with_rows(Vec::new());
        let captured = send(
            router_for(Arc::clone(&application)),
            get("/api/channels?limit=abc"),
        )
        .await;
        assert_eq!(captured.status, StatusCode::BAD_REQUEST);
        assert_eq!(captured.json()["code"], "malformed_payload");
        assert!(
            !captured.body.to_lowercase().contains("deserialize"),
            "Axum 的默认 rejection 文案泄漏了内部细节：{}",
            captured.body
        );
        // 负数同理，由类型在反序列化阶段拒掉（application 侧那条 `Math.max(…, 1)` 的
        // 防负数一半，在 Rust 里由 `Option<u32>` 承担）。
        let negative = send(router_for(application), get("/api/channels?limit=-1")).await;
        assert_eq!(negative.status, StatusCode::BAD_REQUEST);
    }

    /// 未知查询参数当场拒绝，不静默忽略。
    ///
    /// 与 `AppCommand` 的 `deny_unknown_fields` 同一条理由：静默忽略会让调用方以为自己
    /// 传了个参数而实际没有。**这是相对上游的刻意收紧**，见 [`channels::ListChannelsQuery`]。
    #[tokio::test]
    async fn unknown_query_parameters_are_rejected() {
        let application = app_with_rows(Vec::new());
        let captured = send(
            router_for(Arc::clone(&application)),
            get("/api/channels?principal=admin"),
        )
        .await;
        assert_eq!(captured.status, StatusCode::BAD_REQUEST);
        assert_eq!(captured.json()["code"], "malformed_payload");
        assert!(
            application.commands().is_empty(),
            "malformed payload 不得产生 acting decision（§15.3）"
        );
    }

    /// `AuthResolver` 拒绝 → 401，且**一次都没打到 application**。
    #[tokio::test]
    async fn rejected_auth_is_unauthorized() {
        let application = app_with_rows(vec![summary("c-1", datetime!(2026-08-22 04:00:00 UTC))]);
        let state = state_with(
            application.clone(),
            FixedAuthResolver::rejecting(AppError::Unauthenticated),
            Vec::new(),
        );
        let captured = send(router(state), get("/api/channels")).await;

        assert_eq!(captured.status, StatusCode::UNAUTHORIZED);
        assert_eq!(captured.json()["code"], "unauthenticated");
        assert!(
            application.commands().is_empty(),
            "未认证的请求不得到达 application"
        );
    }

    /// 端口故障 → 503 稳定码，body 里没有依赖名（正向对照：稳定码在）。
    #[tokio::test]
    async fn port_failure_is_five_zero_three_without_leaking_the_dependency() {
        let application = Arc::new(RecordingApplication::new(FakeChannelReader::failing(
            PortError::Unavailable {
                dependency: "database",
            },
        )));
        let captured = send(router_for(application), get("/api/channels")).await;
        assert_eq!(captured.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(captured.json()["code"], "dependency_unavailable");
        assert!(!captured.body.contains("database"), "{}", captured.body);
    }

    // -----------------------------------------------------------------------
    // /health 与 /readiness
    // -----------------------------------------------------------------------

    /// `/health` 恒 200、public（不经 `AuthResolver`）、不碰 application。
    ///
    /// parity ledger `health-get`：`migration_rule: preserve`，上游返回 `{status:"ok"}`。
    #[tokio::test]
    async fn health_is_public_and_always_ok() {
        let application = app_with_rows(Vec::new());
        // 用一个**恒拒绝**的 AuthResolver：`/health` 仍然必须 200，这就是"public"的判据。
        let state = state_with(
            application.clone(),
            FixedAuthResolver::rejecting(AppError::Unauthenticated),
            Vec::new(),
        );
        let captured = send(router(state), get("/health")).await;
        assert_eq!(captured.status, StatusCode::OK);
        assert_eq!(captured.body, r#"{"status":"ok"}"#);
        assert!(
            application.commands().is_empty(),
            "探活不碰业务入口，更不碰数据库"
        );
    }

    /// **三态两两不同 —— 判据落在 body 上**。
    ///
    /// 2026-08-22 裁决把 `unverified` 从 200 改成 503（未知即 fail-closed），于是
    /// `unverified` 与 `not_ready` **状态码相同**。所以「三态可分」这件事的唯一承载面
    /// 是 body 的 `status` 字段：这条测试先比三个 body 两两不等，再逐个钉死取值。
    /// 只比状态码的版本会在 `Unverified` 被合并进 `NotReady` 之后照样绿。
    #[tokio::test]
    async fn readiness_renders_three_pairwise_distinct_outcomes() {
        async fn probe_outcome(verdict: ReadinessVerdict) -> (StatusCode, String) {
            let state = state_with(
                app_with_rows(Vec::new()),
                FixedAuthResolver::rejecting(AppError::Unauthenticated),
                vec![Arc::new(StaticProbe("probe-under-test", verdict))],
            );
            let captured = send(router(state), get("/readiness")).await;
            (captured.status, captured.body)
        }

        let ready = probe_outcome(ReadinessVerdict::Ready).await;
        let unverified = probe_outcome(ReadinessVerdict::Unverified).await;
        let not_ready = probe_outcome(ReadinessVerdict::NotReady).await;

        // 三个 **body** 两两不等 —— 这是三态可分的真判据。
        assert_ne!(ready.1, unverified.1, "Unverified 被折叠成了 ready");
        assert_ne!(
            unverified.1, not_ready.1,
            "Unverified 被折叠成了 not_ready —— 同状态码不代表可以同 body"
        );
        assert_ne!(ready.1, not_ready.1);

        assert_eq!(ready, (StatusCode::OK, r#"{"status":"ready"}"#.to_owned()));
        assert_eq!(
            unverified,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"status":"unverified"}"#.to_owned()
            ),
            "未知即 fail-closed（repository contract §5 条 3）"
        );
        assert_eq!(
            not_ready,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"status":"not_ready"}"#.to_owned()
            )
        );

        // 状态码这一维**确实**只分成两档 —— 把上面那条"body 必须可分"的必要性钉住：
        // 状态码已经区分不了后两态了。
        assert_eq!(unverified.0, not_ready.0);
        assert_ne!(ready.0, unverified.0);
    }

    /// 一条判据都没声明 = not ready（fail-closed）。
    ///
    /// 正向对照就在上一条：同一个端点在有一条通过的判据时确实回 ready，
    /// 所以这不是一条"永远 503"的死端点。
    #[tokio::test]
    async fn readiness_with_no_probes_is_not_ready() {
        let state = state_with(
            app_with_rows(Vec::new()),
            FixedAuthResolver::granting(auth()),
            Vec::new(),
        );
        let captured = send(router(state), get("/readiness")).await;
        assert_eq!(captured.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            captured.json()["status"],
            ReadinessStatus::NotReady.as_str()
        );
    }

    /// 非 loopback 明文暴露必须在线上 readiness 里可见；安全档位不能多一个 false 字段。
    #[tokio::test]
    async fn readiness_projects_only_a_real_insecure_transport_flag() {
        let application: Arc<dyn ApplicationService> = app_with_rows(Vec::new());
        let state = ServerBuilder::new(
            Arc::clone(&application),
            Arc::new(FixedAuthResolver::granting(auth())),
        )
        .with_readiness_probe(Arc::new(StaticProbe("database", ReadinessVerdict::Ready)))
        .with_insecure_transport(true)
        .build();
        let exposed = send(router(state), get("/readiness")).await;
        assert_eq!(exposed.status, StatusCode::OK);
        assert_eq!(exposed.json()["insecure_transport"], true);

        let safe = state_with(
            application,
            FixedAuthResolver::granting(auth()),
            vec![Arc::new(StaticProbe("database", ReadinessVerdict::Ready))],
        );
        let safe = send(router(safe), get("/readiness")).await;
        assert!(safe.json().get("insecure_transport").is_none());
    }

    /// 依赖名进日志、不进响应体。
    #[tokio::test]
    async fn readiness_body_never_names_the_dependency() {
        let state = state_with(
            app_with_rows(Vec::new()),
            FixedAuthResolver::granting(auth()),
            vec![
                Arc::new(StaticProbe(
                    "database_migration_ledger",
                    ReadinessVerdict::Unverified,
                )),
                Arc::new(StaticProbe("supervisor", ReadinessVerdict::Ready)),
            ],
        );
        let captured = send(router(state), get("/readiness")).await;
        assert_eq!(captured.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !captured.body.contains("database_migration_ledger"),
            "依赖明细泄漏部署拓扑：{}",
            captured.body
        );
        assert!(!captured.body.contains("supervisor"), "{}", captured.body);
        // 正向对照：三态里的那一态确实呈现出来了。
        assert_eq!(captured.json()["status"], "unverified");
    }

    // -----------------------------------------------------------------------
    // 输入大小限制
    // -----------------------------------------------------------------------

    fn sized_request(uri: &str, len: usize) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(http::header::CONTENT_LENGTH, len)
            .body(Body::from(vec![b'x'; len]))
            .expect("请求构造合法")
    }

    /// 超过上限一个字节就 413。
    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let captured = send(
            router_for(app_with_rows(Vec::new())),
            sized_request("/api/channels", REQUEST_BODY_LIMIT_BYTES + 1),
        )
        .await;
        assert_eq!(captured.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// 正向对照：**恰好等于**上限的 body 不被拒。
    ///
    /// 没有它，上一条在"任何带 body 的请求都被拒"的世界里同样通过。
    #[tokio::test]
    async fn body_exactly_at_the_limit_is_accepted() {
        let captured = send(
            router_for(app_with_rows(Vec::new())),
            sized_request("/api/channels", REQUEST_BODY_LIMIT_BYTES),
        )
        .await;
        assert_eq!(captured.status, StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // request_id
    // -----------------------------------------------------------------------

    /// 合格的 request id 被沿用并回写响应头。
    #[tokio::test]
    async fn well_formed_request_id_is_echoed_back() {
        let request = Request::builder()
            .uri("/health")
            .header(REQUEST_ID_HEADER, "upstream-req-7")
            .body(Body::empty())
            .expect("请求构造合法");
        let captured = send(router_for(app_with_rows(Vec::new())), request).await;
        assert_eq!(
            captured
                .headers
                .get(REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("upstream-req-7")
        );
    }

    /// 不合格的 request id 被丢弃并换成新铸的 —— **不是截断后使用**。
    #[tokio::test]
    async fn hostile_request_id_is_replaced_not_reused() {
        let hostile = "a b\"c";
        let request = Request::builder()
            .uri("/health")
            .header(
                HeaderName::from_static(REQUEST_ID_HEADER),
                HeaderValue::from_static("a b\"c"),
            )
            .body(Body::empty())
            .expect("请求构造合法");
        let captured = send(router_for(app_with_rows(Vec::new())), request).await;
        let echoed = captured
            .headers
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .expect("响应必须带 request id");
        assert_ne!(echoed, hostile);
        assert!(!echoed.contains(' '));
        assert!(!echoed.contains('"'));
    }

    // -----------------------------------------------------------------------
    // span 捕获
    // -----------------------------------------------------------------------

    /// 一条被捕获的 span。
    ///
    /// **按 span id 分开存**，不是把所有字段倒进一个池子：`application.execute` 也记
    /// `actor_id`，倒进一个池子之后就分不清那是 transport 记的还是 application 记的 ——
    /// 于是"transport 记了 actor_id"这条断言会被别人的字段满足。
    #[derive(Clone, Debug)]
    struct CapturedSpan {
        id: u64,
        name: String,
        fields: Vec<(String, String)>,
    }

    impl CapturedSpan {
        fn field_names(&self) -> Vec<&str> {
            self.fields.iter().map(|(k, _)| k.as_str()).collect()
        }

        fn value_of(&self, key: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Clone, Debug, Default)]
    struct CapturedSpans(Vec<CapturedSpan>);

    impl CapturedSpans {
        fn names(&self) -> Vec<&str> {
            self.0.iter().map(|span| span.name.as_str()).collect()
        }

        /// 取唯一一条叫这个名字的 span。多于一条就是测试自己的前提坏了。
        fn only(&self, name: &str) -> &CapturedSpan {
            let mut matching = self.0.iter().filter(|span| span.name == name);
            let found = matching
                .next()
                .unwrap_or_else(|| panic!("没有名为 {name} 的 span，实际有 {:?}", self.names()));
            assert!(matching.next().is_none(), "名为 {name} 的 span 不止一条");
            found
        }

        /// 全部 span 的全部字段 —— "凭据不进任何 span"那条断言要扫的就是这个全集。
        fn all_fields(&self) -> Vec<(&str, &str)> {
            self.0
                .iter()
                .flat_map(|span| span.fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .collect()
        }
    }

    /// 把 span 字段收进 `Vec`。
    ///
    /// `record_str` / `record_debug` / `record_u64` 三个都实现：`Display` 值（`%expr`）走
    /// `record_debug`，`&'static str` 走 `record_str`，`u16` 会被提升成 `record_u64`。
    /// 只实现一部分会漏掉另一部分 —— 那会让"span 里没有凭据"这条断言在"我根本没看见
    /// 任何字段"的情况下也成立。
    struct FieldCollector<'a>(&'a mut Vec<(String, String)>);

    impl Visit for FieldCollector<'_> {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.push((field.name().to_owned(), value.to_owned()));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.push((field.name().to_owned(), value.to_string()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0.push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    #[derive(Clone, Default)]
    struct CaptureLayer(Arc<Mutex<CapturedSpans>>);

    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
            let mut fields = Vec::new();
            attrs.record(&mut FieldCollector(&mut fields));
            self.0.lock().expect("捕获锁不会中毒").0.push(CapturedSpan {
                id: id.into_u64(),
                name: attrs.metadata().name().to_owned(),
                fields,
            });
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
            let mut fields = Vec::new();
            values.record(&mut FieldCollector(&mut fields));
            let mut captured = self.0.lock().expect("捕获锁不会中毒");
            if let Some(span) = captured.0.iter_mut().find(|span| span.id == id.into_u64()) {
                span.fields.extend(fields);
            }
        }
    }

    fn capture<F, T>(work: F) -> (T, CapturedSpans)
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
        let captured = sink.lock().expect("捕获锁不会中毒").clone();
        (out, captured)
    }

    /// 正向对照：请求 span 确实带着台账里的字段，值也对。
    ///
    /// 没有这一条，下面"span 里没有凭据"的断言在"捕获层什么都没看见"的世界里恒真。
    #[test]
    fn request_span_carries_the_declared_fields() {
        let (captured_response, spans) = capture(async {
            let application =
                app_with_rows(vec![summary("c-1", datetime!(2026-08-22 04:00:00 UTC))]);
            send(router_for(application), get("/api/channels")).await
        });
        assert_eq!(captured_response.status, StatusCode::OK);

        let request_span = spans.only(REQUEST_SPAN_NAME);
        // UUIDv7 的字符串形态是 36 字符（没有请求头时铸造一个新的）。
        assert_eq!(request_span.value_of("request_id").map(str::len), Some(36));
        assert_eq!(request_span.value_of("http.method"), Some("GET"));
        assert_eq!(request_span.value_of("http.status_code"), Some("200"));
        assert_eq!(
            request_span.value_of(HTTP_ROUTE_FIELD),
            Some("/api/channels")
        );
        // 身份**只**取 ID 字段，而且确实取到了（§16.4）。
        assert_eq!(request_span.value_of(ACTOR_ID_FIELD), Some(ACTOR));

        // 顺带证明 application 的 span 确实是另一条 —— 两条 span 各记各的。
        assert!(
            spans.names().contains(&"application.execute"),
            "{:?}",
            spans.names()
        );
    }

    /// span 名与常量一致 —— `info_span!` 的名字必须是字面量，这条把它和常量绑起来。
    #[test]
    fn request_span_name_matches_the_constant() {
        let (_, spans) =
            capture(async { send(router_for(app_with_rows(Vec::new())), get("/health")).await });
        assert_eq!(spans.only(REQUEST_SPAN_NAME).name, REQUEST_SPAN_NAME);
    }

    /// 请求 span 的字段集**恰好**是台账。多记一个或少记一个都判红。
    #[test]
    fn request_span_fields_are_exactly_the_declared_ledger() {
        // 用 `/api/channels`：`/health` 不经认证，`actor_id` 会保持 Empty（Empty 字段
        // 在没被 record 之前不会被 visit），拿不到全集。
        let (_, spans) = capture(async {
            send(router_for(app_with_rows(Vec::new())), get("/api/channels")).await
        });

        let mut got = spans.only(REQUEST_SPAN_NAME).field_names();
        got.sort_unstable();
        let mut want: Vec<&str> = REQUEST_SPAN_FIELDS.to_vec();
        want.sort_unstable();
        assert_eq!(got, want, "请求 span 的字段集与台账不符");
    }

    /// **凭据不进任何 span。**
    ///
    /// `AuthContext` 没有 `Serialize`，但它**有** `Debug` —— 一个 `%auth` 或漏掉
    /// `skip_all` 就会把角色集合与 auth generation 打进日志。这条断言盯的正是那个缺口，
    /// 而且扫的是**全部** span 的字段（transport 与 application 两条都在内）。
    #[test]
    fn spans_never_carry_the_auth_context_itself() {
        let (_, spans) = capture(async {
            send(router_for(app_with_rows(Vec::new())), get("/api/channels")).await
        });

        let sentinel = SENTINEL_AUTH_GENERATION.to_string();
        for (name, value) in spans.all_fields() {
            assert!(
                !value.contains(&sentinel),
                "字段 {name} 里出现了 auth generation：{value}"
            );
            assert!(
                !value.contains("AuthContext"),
                "字段 {name} 里出现了 AuthContext 的 Debug：{value}"
            );
            assert!(
                !value.contains("roles"),
                "字段 {name} 里出现了角色集合：{value}"
            );
            assert!(
                !value.contains("Admin"),
                "字段 {name} 里出现了角色：{value}"
            );
        }

        // 正向对照：这次捕获**确实**看见了字段（而且看见了身份 ID），
        // 所以上面那一圈不是在空集合上跑。
        assert_eq!(
            spans.only(REQUEST_SPAN_NAME).value_of(ACTOR_ID_FIELD),
            Some(ACTOR)
        );
        assert!(spans.all_fields().len() >= REQUEST_SPAN_FIELDS.len());
    }

    // -----------------------------------------------------------------------
    // GET /metrics
    // -----------------------------------------------------------------------

    /// 在一个**局部** recorder 下跑一段请求，返回渲染出来的 Prometheus 文本。
    ///
    /// 用 `with_local_recorder` 而不是装全局：全局 recorder 一个进程只能装一次，
    /// 测试之间会互相抢。局部 recorder 是线程本地的，而 `block_on` 在当前线程 poll，
    /// 与 `capture` 里那个 `with_default` 是同一个手法。
    fn with_metrics<F>(work: impl FnOnce(MetricsHandle) -> F) -> String
    where
        F: Future<Output = ()>,
    {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = MetricsHandle::new(recorder.handle());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("构建当前线程运行时");
        ::metrics::with_local_recorder(&recorder, || {
            runtime.block_on(work(handle.clone()));
            handle.render()
        })
    }

    /// 从渲染文本里取出某个 series 上的 label 名集合。
    ///
    /// 只解析 `_count` 与 gauge 这两种行：它们携带的**恰好**是我们打上去的 label。
    /// 直方图/摘要的分位数行会被曝露格式自己追加一个 `quantile`（或 `le`）label ——
    /// 那是格式的产物不是我们的 label，把它算进来会让台账断言测的是 exporter 的实现。
    fn label_names_of(rendered: &str, series: &str) -> BTreeSet<String> {
        let prefix = format!("{series}{{");
        rendered
            .lines()
            .filter_map(|line| line.strip_prefix(prefix.as_str()))
            .filter_map(|rest| rest.split_once('}'))
            .flat_map(|(labels, _)| {
                labels
                    .split(',')
                    .filter_map(|pair| pair.split_once('='))
                    .map(|(name, _)| name.to_owned())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// 没交句柄时 `/metrics` fail-closed 回 503，而不是回一段空文本。
    #[tokio::test]
    async fn metrics_without_a_recorder_handle_is_fail_closed() {
        let captured = send(router_for(app_with_rows(Vec::new())), get("/metrics")).await;
        assert_eq!(captured.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(captured.json()["code"], "dependency_unavailable");
        // 依赖名照旧不出边界。
        assert!(
            !captured.body.contains("metrics_recorder"),
            "{}",
            captured.body
        );
    }

    /// 交了句柄就出数：200 + Prometheus 文本的 content type。
    ///
    /// 这是上一条的**正向对照** —— 否则 `/metrics` 在"这条路由永远 503"的世界里
    /// 也算"fail-closed 正确"。快照**内容**由
    /// `http_latency_and_status_are_actually_recorded` 断言（那条挂了局部 recorder，
    /// 这条刻意没挂，所以这里只该断言路由通了）。
    #[tokio::test]
    async fn metrics_endpoint_serves_the_prometheus_snapshot() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = MetricsHandle::new(recorder.handle());
        let state = ServerBuilder::new(
            app_with_rows(Vec::new()),
            Arc::new(FixedAuthResolver::granting(auth())),
        )
        .with_metrics_handle(handle)
        .build();

        let captured = send(router(state), get("/metrics")).await;
        assert_eq!(captured.status, StatusCode::OK);
        assert_eq!(
            captured
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(metrics::PROMETHEUS_CONTENT_TYPE)
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_uses_the_same_session_auth_boundary() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let state = ServerBuilder::new(
            app_with_rows(Vec::new()),
            Arc::new(FixedAuthResolver::rejecting(AppError::Unauthenticated)),
        )
        .with_metrics_handle(MetricsHandle::new(recorder.handle()))
        .build();
        let captured = send(router(state), get("/metrics")).await;
        assert_eq!(captured.status, StatusCode::UNAUTHORIZED);
        assert_eq!(captured.json()["code"], "unauthenticated");
    }

    /// §16.4 点名的两组指标确实被记下来了：**latency 与 status**、在飞数。
    ///
    /// 判据是渲染出来的文本，不是"我调用了 histogram!" —— 后者在 recorder 从未被接上
    /// 的世界里也能写出来。
    #[test]
    fn http_latency_and_status_are_actually_recorded() {
        let rendered = with_metrics(|handle| async move {
            let state = ServerBuilder::new(
                app_with_rows(Vec::new()),
                Arc::new(FixedAuthResolver::granting(auth())),
            )
            .with_metrics_handle(handle)
            .build();
            let captured = send(router(state), get("/api/channels")).await;
            assert_eq!(captured.status, StatusCode::OK);
        });

        assert!(
            rendered.contains(HTTP_REQUEST_DURATION_SECONDS),
            "延迟直方图没出现在快照里：{rendered}"
        );
        assert!(
            rendered.contains(HTTP_REQUESTS_IN_FLIGHT),
            "在飞数没出现在快照里：{rendered}"
        );
        // status 是真实状态码，不是常量。
        assert!(rendered.contains(r#"status="200""#), "{rendered}");
        assert!(rendered.contains(r#"method="GET""#), "{rendered}");
        assert!(rendered.contains(r#"transport="http""#), "{rendered}");
        assert!(rendered.contains(r#"route="/api/channels""#), "{rendered}");
        // 请求结束后在飞数回到 0（守卫真的执行了）。
        assert!(
            rendered.contains(&format!(
                "{HTTP_REQUESTS_IN_FLIGHT}{{transport=\"http\"}} 0"
            )),
            "{rendered}"
        );
    }

    /// **status label 跟着真实结果走** —— 两个不同结局产出两个不同的 status series。
    ///
    /// 没有这一条，上一条在"status 恒为 200 这个字面量"的世界里同样通过。
    #[test]
    fn status_label_follows_the_real_outcome() {
        let rendered = with_metrics(|handle| async move {
            let ok_state = ServerBuilder::new(
                app_with_rows(Vec::new()),
                Arc::new(FixedAuthResolver::granting(auth())),
            )
            .with_metrics_handle(handle.clone())
            .build();
            assert_eq!(
                send(router(ok_state), get("/api/channels")).await.status,
                StatusCode::OK
            );

            let denied_state = ServerBuilder::new(
                app_with_rows(Vec::new()),
                Arc::new(FixedAuthResolver::rejecting(AppError::Unauthenticated)),
            )
            .with_metrics_handle(handle)
            .build();
            assert_eq!(
                send(router(denied_state), get("/api/channels"))
                    .await
                    .status,
                StatusCode::UNAUTHORIZED
            );
        });

        assert!(rendered.contains(r#"status="200""#), "{rendered}");
        assert!(rendered.contains(r#"status="401""#), "{rendered}");
    }

    /// 未知 HTTP 方法在**端到端**路径上也收敛到一个桶，不制造新 series。
    #[test]
    fn hostile_method_does_not_create_new_series_end_to_end() {
        let rendered = with_metrics(|handle| async move {
            for i in 0..5 {
                let state = ServerBuilder::new(
                    app_with_rows(Vec::new()),
                    Arc::new(FixedAuthResolver::granting(auth())),
                )
                .with_metrics_handle(handle.clone())
                .build();
                let request = Request::builder()
                    .method(http::Method::from_bytes(format!("FOOBAR{i}").as_bytes()).unwrap())
                    .uri("/api/channels")
                    .body(Body::empty())
                    .expect("请求构造合法");
                send(router(state), request).await;
            }
        });

        for i in 0..5 {
            assert!(
                !rendered.contains(&format!("FOOBAR{i}")),
                "对端发明的方法名进了 label：{rendered}"
            );
        }
        assert!(
            rendered.contains(&format!(r#"method="{METHOD_OTHER}""#)),
            "未知方法必须落进 other 桶：{rendered}"
        );
    }

    /// **实际打上去的 label 名恰好是台账**（`HTTP_METRIC_LABELS`），一个不多一个不少。
    ///
    /// 判据是渲染文本反解出来的真实 label 名，不是那个常量数组自己 —— 后者是被测对象，
    /// 拿它跟自己比什么都证明不了。
    #[test]
    fn http_labels_are_exactly_the_declared_ledger() {
        let rendered = with_metrics(|handle| async move {
            let state = ServerBuilder::new(
                app_with_rows(Vec::new()),
                Arc::new(FixedAuthResolver::granting(auth())),
            )
            .with_metrics_handle(handle)
            .build();
            send(router(state), get("/api/channels")).await;
        });

        let duration_labels =
            label_names_of(&rendered, &format!("{HTTP_REQUEST_DURATION_SECONDS}_count"));
        let want: BTreeSet<String> = HTTP_METRIC_LABELS.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            duration_labels, want,
            "延迟直方图的 label 集与台账不符：{rendered}"
        );

        // 在飞数只带 transport（在飞时状态码还不存在，硬凑一个就是造假）。
        let in_flight_labels = label_names_of(&rendered, HTTP_REQUESTS_IN_FLIGHT);
        assert_eq!(
            in_flight_labels,
            BTreeSet::from([LABEL_TRANSPORT.to_owned()])
        );

        // 负向：§16.4 点名的高基数字段一个都没在**渲染出来的字节里**当过 label。
        for forbidden in ["actor_id", "thread_id", "request_id", "tenant_id"] {
            assert!(
                !rendered.contains(&format!("{forbidden}=")),
                "{forbidden} 出现在 metrics label 里：{rendered}"
            );
        }
        // 正向对照：台账里的四个确实都在渲染文本里出现过。
        for label in [LABEL_TRANSPORT, LABEL_METHOD, LABEL_STATUS, LABEL_ROUTE] {
            assert!(rendered.contains(&format!("{label}=")), "{rendered}");
        }
    }

    // -----------------------------------------------------------------------
    // 未匹配路由
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unmatched_route_is_a_plain_404() {
        let captured = send(router_for(app_with_rows(Vec::new())), get("/nope")).await;
        assert_eq!(captured.status, StatusCode::NOT_FOUND);
        // 刻意不套 §15.3 的错误信封：路由不存在 ≠ 资源不可见（见 `router` 的文档）。
        assert!(!captured.body.contains("not_visible"), "{}", captured.body);
    }

    #[test]
    fn unmatched_paths_collapse_to_one_safe_route_label() {
        let hostile = "/attacker-controlled-unique-path-987654";
        let rendered = with_metrics(|handle| async move {
            let state = ServerBuilder::new(
                app_with_rows(Vec::new()),
                Arc::new(FixedAuthResolver::granting(auth())),
            )
            .with_metrics_handle(handle)
            .build();
            let captured = send(router(state), get(hostile)).await;
            assert_eq!(captured.status, StatusCode::NOT_FOUND);
        });
        assert!(
            rendered.contains(&format!(r#"route="{ROUTE_UNMATCHED}""#)),
            "{rendered}"
        );
        assert!(
            !rendered.contains(hostile),
            "原始 path 泄漏进 label：{rendered}"
        );
    }
}
