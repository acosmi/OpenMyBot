//! 唯一 HTTP safe dialer（v3 §6.2 / §7.5 / §10.5）。
//!
//! 这里把 SSRF 防线做成连接结构，而不是 URL 检查纪律：每一跳先解析 DNS，把所有候选地址
//! 过 [`EgressPolicy`]，随后 `TcpStream::connect` **直接接收选中的 `SocketAddr`**。TLS 的 SNI 与
//! HTTP `Host` 仍使用原始主机名，因此既验证正确证书，又不会在检查之后重新查询 DNS。
//!
//! 固定边界：
//!
//! - 最多 [`MAX_REDIRECTS`]（3）次 redirect，每一跳重新解析、校验并绑定；
//! - 默认拒绝 IANA 特殊用途、非全局单播、metadata、loopback、link-local、private/reserved；
//! - 唯一放行例外是管理员给出的**数值 CIDR** [`CidrAllowlist`]，不接受 hostname；
//! - 所有 credential header 只在同 origin redirect 保留，跨 origin 构造性删除；
//! - 带 secret body 的 POST 不跨 origin 做 307/308，301/302 的含混 POST 语义直接拒绝；
//! - 总墙钟与响应体大小在读取时执行，不先把无界 body 收进内存；
//! - HTTP/1 only，出网端无上游/系统代理、无自动 retry、无自动 redirect、无自动解压。
//!
//! TLS 使用 rustls 0.23 + ring provider + lockfile 固定的 Mozilla roots。ring **不是纯 Rust**：
//! 它的 C/汇编 build.rs 与 Windows 预生成对象见 W-7 delta audit；本模块只说明运行时边界，
//! 不用“Rust API”掩盖构建面的 C/FFI 事实。

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::header::{
    ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, HeaderName, HeaderValue, LOCATION,
};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use url::{Position, Url};

/// 第一真源固定的 redirect 上限。
pub const MAX_REDIRECTS: usize = 3;

/// 单个受控 POST 的 request body 硬上限。
///
/// OIDC token form 远小于此值；先固定上限可防止未来消费者把本 dialer 当无界上传客户端。
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
/// Provider JSON prompt/tool schema request 上限；与 OIDC form 的 64KiB 分开。
pub const MAX_JSON_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

const JSON_ACCEPT: &str = "application/json";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";
const STREAM_ACCEPT: &str = "text/event-stream, application/json";

/// safe dialer 的稳定、无载荷失败分类。
///
/// 不携带 URL、host、IP、header 或远端响应字节；协议 adapter 可把全部变体继续压成单一
/// `transport_unavailable`，避免把内网可达性暴露给 pre-auth 请求方。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SafeHttpError {
    #[error("safe_http_invalid_url")]
    InvalidUrl,
    #[error("safe_http_scheme_rejected")]
    SchemeRejected,
    #[error("safe_http_invalid_budget")]
    InvalidBudget,
    #[error("safe_http_invalid_header")]
    InvalidHeader,
    #[error("safe_http_invalid_allowlist")]
    InvalidAllowlist,
    #[error("safe_http_dns_unavailable")]
    DnsUnavailable,
    #[error("safe_http_destination_denied")]
    DestinationDenied,
    #[error("safe_http_connect_failed")]
    ConnectFailed,
    #[error("safe_http_peer_mismatch")]
    PeerMismatch,
    #[error("safe_http_tls_failed")]
    TlsFailed,
    #[error("safe_http_protocol_failed")]
    ProtocolFailed,
    #[error("safe_http_deadline_exceeded")]
    DeadlineExceeded,
    #[error("safe_http_response_too_large")]
    ResponseTooLarge,
    #[error("safe_http_stream_stalled")]
    StreamStalled,
    #[error("safe_http_redirect_invalid")]
    RedirectInvalid,
    #[error("safe_http_redirect_limit")]
    RedirectLimit,
    #[error("safe_http_redirect_method_rejected")]
    RedirectMethodRejected,
    #[error("safe_http_sensitive_redirect_rejected")]
    SensitiveRedirectRejected,
}

/// 允许的 URL scheme 面。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemePolicy {
    /// OIDC discovery/JWKS/token 等凭据路径只许 HTTPS。
    HttpsOnly,
    /// 允许 HTTP 或 HTTPS；给受控内网 endpoint 与确定性网络测试使用。
    HttpOrHttps,
}

impl SchemePolicy {
    pub(crate) fn accepts(self, scheme: &str) -> bool {
        match self {
            Self::HttpsOnly => scheme == "https",
            Self::HttpOrHttps => matches!(scheme, "http" | "https"),
        }
    }
}

/// 一次请求的两项资源预算。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeHttpBudget {
    max_response_bytes: usize,
    timeout: Duration,
}

impl SafeHttpBudget {
    /// 建预算；零字节或零时长没有可兑现语义，直接拒绝。
    pub fn new(max_response_bytes: usize, timeout: Duration) -> Result<Self, SafeHttpError> {
        if max_response_bytes == 0 || timeout.is_zero() {
            return Err(SafeHttpError::InvalidBudget);
        }
        Ok(Self {
            max_response_bytes,
            timeout,
        })
    }

    #[must_use]
    pub const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }

    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }
}

/// 只允许数值网络的 CIDR allowlist。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CidrAllowlist {
    networks: Arc<[IpNet]>,
}

impl CidrAllowlist {
    /// 从规范形 CIDR 构造；拒绝裸 IP、hostname 与带 host bits 的非规范网络。
    pub fn parse_exact<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, SafeHttpError> {
        let mut networks = BTreeSet::new();
        for raw in entries {
            if raw.is_empty() || raw.trim() != raw || raw.matches('/').count() != 1 {
                return Err(SafeHttpError::InvalidAllowlist);
            }
            let network = IpNet::from_str(raw).map_err(|_| SafeHttpError::InvalidAllowlist)?;
            if network.addr() != network.network() {
                return Err(SafeHttpError::InvalidAllowlist);
            }
            networks.insert(network);
        }
        Ok(Self {
            networks: networks.into_iter().collect(),
        })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let canonical = ip.to_canonical();
        self.networks
            .iter()
            .any(|network| network.contains(&ip) || network.contains(&canonical))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

/// 默认拒绝特殊地址，只有精确 CIDR 可显式覆盖。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    allowlist: CidrAllowlist,
}

impl EgressPolicy {
    #[must_use]
    pub const fn new(allowlist: CidrAllowlist) -> Self {
        Self { allowlist }
    }

    #[must_use]
    pub fn permits(&self, ip: IpAddr) -> bool {
        self.allowlist.contains(ip) || is_default_global(ip.to_canonical())
    }
}

/// DNS 解析失败；无字段，防止把 resolver 原文跨边界传播。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("safe_http_dns_unavailable")]
pub struct DnsUnavailable;

/// 可替换 resolver。生产实现只负责解析；IP 判定与端口覆盖永远由 [`SafeDialer`] 自己做。
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable>;
}

/// 系统 resolver；每次 redirect 都由 dialer 重新调用。
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        lookup_host((host, port))
            .await
            .map(|addresses| addresses.collect())
            .map_err(|_| DnsUnavailable)
    }
}

/// `Authorization` 的不可打印容器。
pub struct AuthorizationValue(HeaderValue);

impl AuthorizationValue {
    /// HeaderValue 自身负责拒绝 CR/LF 与非法字节。
    pub fn parse(raw: &str) -> Result<Self, SafeHttpError> {
        let mut value = HeaderValue::from_str(raw).map_err(|_| SafeHttpError::InvalidHeader)?;
        value.set_sensitive(true);
        Ok(Self(value))
    }
}

/// Provider API key 的不可打印 header value；header 名由封闭方法决定，不接受调用方自由输入。
pub struct ProviderApiKeyValue(HeaderValue);

impl ProviderApiKeyValue {
    /// HeaderValue 拒绝 CR/LF/非法字节；空 key 由 provider config/source 在更早处拒绝。
    pub fn parse(raw: &str) -> Result<Self, SafeHttpError> {
        let mut value = HeaderValue::from_str(raw).map_err(|_| SafeHttpError::InvalidHeader)?;
        value.set_sensitive(true);
        Ok(Self(value))
    }
}

impl fmt::Debug for ProviderApiKeyValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderApiKeyValue([REDACTED])")
    }
}

enum ProviderAuthentication {
    Anthropic(HeaderValue),
    Google(HeaderValue),
}

impl fmt::Debug for AuthorizationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationValue([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeMethod {
    Get,
    PostForm,
    PostJson,
    McpGet,
    McpPost,
    McpDelete,
}

impl SafeMethod {
    const fn as_http(self) -> Method {
        match self {
            Self::Get | Self::McpGet => Method::GET,
            Self::PostForm | Self::PostJson | Self::McpPost => Method::POST,
            Self::McpDelete => Method::DELETE,
        }
    }
}

/// MCP's closed HTTP method subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum McpHttpMethod {
    Get,
    Post,
    Delete,
}

#[derive(Clone, Copy)]
pub(crate) enum GatewayHttpMethod {
    GetJson,
    PostJson,
    PostForm,
}
#[derive(Clone, Copy)]
pub(crate) enum GatewayAccept {
    Json,
    EventStream,
}

/// 封闭请求计划。没有自由 method/header 名；敏感字段的 Debug 永远只显示长度。
pub struct SafeHttpRequest {
    url: Url,
    scheme_policy: SchemePolicy,
    method: SafeMethod,
    body: Bytes,
    authorization: Option<AuthorizationValue>,
    provider_authentication: Option<ProviderAuthentication>,
    protocol_headers: HeaderMap,
    gateway_accept: Option<GatewayAccept>,
    follow_redirects: bool,
    budget: SafeHttpBudget,
}

impl SafeHttpRequest {
    /// Closed SDK framing: HTTPS, no redirects, zeroizing body owner, two fixed Accept values.
    pub(crate) fn gateway(
        url: Url,
        method: GatewayHttpMethod,
        body: zeroize::Zeroizing<Vec<u8>>,
        authorization: Option<AuthorizationValue>,
        accept: GatewayAccept,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        validate_url(&url, SchemePolicy::HttpsOnly)?;
        let (method, cap) = match method {
            GatewayHttpMethod::GetJson => (SafeMethod::Get, 0),
            GatewayHttpMethod::PostJson => (SafeMethod::PostJson, MAX_JSON_REQUEST_BODY_BYTES),
            GatewayHttpMethod::PostForm => (SafeMethod::PostForm, MAX_REQUEST_BODY_BYTES),
        };
        if body.len() > cap {
            return Err(SafeHttpError::InvalidBudget);
        }
        Ok(Self {
            url,
            scheme_policy: SchemePolicy::HttpsOnly,
            method,
            body: Bytes::from_owner(body),
            authorization,
            provider_authentication: None,
            protocol_headers: HeaderMap::new(),
            gateway_accept: Some(accept),
            follow_redirects: false,
            budget,
        })
    }

    /// JSON GET（discovery/JWKS 与后续 provider metadata）。
    pub fn get(
        url: Url,
        scheme_policy: SchemePolicy,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        validate_url(&url, scheme_policy)?;
        Ok(Self {
            url,
            scheme_policy,
            method: SafeMethod::Get,
            body: Bytes::new(),
            authorization: None,
            provider_authentication: None,
            protocol_headers: HeaderMap::new(),
            gateway_accept: None,
            follow_redirects: true,
            budget,
        })
    }

    /// `application/x-www-form-urlencoded` POST（OIDC token endpoint）。
    pub fn post_form(
        url: Url,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        Self::post_form_with_scheme(url, SchemePolicy::HttpsOnly, body, authorization, budget)
    }

    /// Scheme-explicit form POST. Production OAuth always passes `HttpsOnly`; the wider policy is
    /// reserved for loopback conformance servers reached through an explicit CIDR allowlist.
    pub(crate) fn post_form_with_scheme(
        url: Url,
        scheme_policy: SchemePolicy,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        validate_url(&url, scheme_policy)?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(SafeHttpError::InvalidBudget);
        }
        Ok(Self {
            url,
            scheme_policy,
            method: SafeMethod::PostForm,
            body: Bytes::from(body),
            authorization,
            provider_authentication: None,
            protocol_headers: HeaderMap::new(),
            gateway_accept: None,
            follow_redirects: true,
            budget,
        })
    }

    /// One admitted OAuth refresh is one token POST. A redirect response is returned to the
    /// adapter without a second request, including same-origin 307/308 or a 303 GET conversion.
    pub(crate) fn oauth_refresh_form(
        url: Url,
        scheme_policy: SchemePolicy,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        let mut request =
            Self::post_form_with_scheme(url, scheme_policy, body, authorization, budget)?;
        request.follow_redirects = false;
        Ok(request)
    }

    /// HTTPS JSON POST；provider stream 与 remote protocol request 使用。
    pub fn post_json(
        url: Url,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        Self::post_json_with_scheme(url, SchemePolicy::HttpsOnly, body, authorization, budget)
    }

    /// 生产调用方传 `HttpsOnly`；`HttpOrHttps` 只供经出站策略白名单到达的回环服务器（渠道一致性测试）。
    pub fn post_json_with_scheme(
        url: Url,
        scheme_policy: SchemePolicy,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        validate_url(&url, scheme_policy)?;
        if body.len() > MAX_JSON_REQUEST_BODY_BYTES {
            return Err(SafeHttpError::InvalidBudget);
        }
        Ok(Self {
            url,
            scheme_policy,
            method: SafeMethod::PostJson,
            body: Bytes::from(body),
            authorization,
            provider_authentication: None,
            protocol_headers: HeaderMap::new(),
            gateway_accept: None,
            follow_redirects: true,
            budget,
        })
    }

    /// MCP Streamable HTTP request. Only protocol-defined headers are accepted.
    pub(crate) fn mcp(
        url: Url,
        scheme_policy: SchemePolicy,
        method: McpHttpMethod,
        body: Vec<u8>,
        authorization: Option<AuthorizationValue>,
        mut protocol_headers: HeaderMap,
        budget: SafeHttpBudget,
    ) -> Result<Self, SafeHttpError> {
        validate_url(&url, scheme_policy)?;
        if protocol_headers.len() > 64
            || protocol_headers.iter().any(|(name, value)| {
                !is_allowed_mcp_header(name)
                    || value.as_bytes().len() > 8 * 1024
                    || value.as_bytes().contains(&0)
            })
        {
            return Err(SafeHttpError::InvalidHeader);
        }
        for value in protocol_headers.values_mut() {
            value.set_sensitive(true);
        }
        let safe_method = match method {
            McpHttpMethod::Get => SafeMethod::McpGet,
            McpHttpMethod::Post => SafeMethod::McpPost,
            McpHttpMethod::Delete => SafeMethod::McpDelete,
        };
        if (safe_method == SafeMethod::McpPost && body.len() > MAX_JSON_REQUEST_BODY_BYTES)
            || (safe_method != SafeMethod::McpPost && !body.is_empty())
        {
            return Err(SafeHttpError::InvalidBudget);
        }
        Ok(Self {
            url,
            scheme_policy,
            method: safe_method,
            body: Bytes::from(body),
            authorization,
            provider_authentication: None,
            protocol_headers,
            gateway_accept: None,
            follow_redirects: true,
            budget,
        })
    }

    /// 给需要 bearer/basic auth 的 GET；header 名固定为 `Authorization`。
    #[must_use]
    pub fn with_authorization(mut self, authorization: AuthorizationValue) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// Anthropic Messages 固定 `x-api-key` + stable API version；跨 origin redirect 同时删除。
    #[must_use]
    pub(crate) fn with_anthropic_api_key(mut self, api_key: ProviderApiKeyValue) -> Self {
        self.provider_authentication = Some(ProviderAuthentication::Anthropic(api_key.0));
        self
    }

    /// Google Generative AI 固定 `x-goog-api-key`；不把 key 放 query/URL/log。
    #[must_use]
    pub(crate) fn with_google_api_key(mut self, api_key: ProviderApiKeyValue) -> Self {
        self.provider_authentication = Some(ProviderAuthentication::Google(api_key.0));
        self
    }
}

impl fmt::Debug for SafeHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeHttpRequest")
            .field("origin", &RedactedOrigin::from_url(&self.url))
            .field("method", &self.method)
            .field("body_bytes", &self.body.len())
            .field("has_authorization", &self.authorization.is_some())
            .field(
                "has_provider_authentication",
                &self.provider_authentication.is_some(),
            )
            .field("protocol_header_count", &self.protocol_headers.len())
            .field("budget", &self.budget)
            .finish()
    }
}

/// 最终（非 redirect）响应。Debug 不打印 headers/body。
pub struct SafeHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl SafeHttpResponse {
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn into_parts(self) -> (StatusCode, HeaderMap, Vec<u8>) {
        (self.status, self.headers, self.body)
    }
}

impl fmt::Debug for SafeHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeHttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// 最终 streaming response；body 只能经 bounded/stall-aware `next_chunk` 读取。
pub struct SafeHttpStreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    _driver: AbortOnDrop,
    read_bytes: usize,
    max_bytes: usize,
}

impl SafeHttpStreamResponse {
    /// Move the complete map, retaining duplicate security/billing header values.
    pub(crate) fn take_headers(&mut self) -> HeaderMap {
        std::mem::take(&mut self.headers)
    }

    /// Narrow cancellation control for the gateway's unpolled-body deadline watcher.
    /// Aborting this handle drops only this response's HTTP/1 driver; it never reads the body.
    pub(crate) fn abort_handle(&self) -> tokio::task::AbortHandle {
        self._driver.0.abort_handle()
    }

    /// HTTP status。
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// 受控读取 response header。
    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    /// 下一 data frame；每次等待按真实 body read 间隔执行 stall timeout。
    pub async fn next_chunk(
        &mut self,
        stall_timeout: Option<Duration>,
    ) -> Result<Option<Bytes>, SafeHttpError> {
        if stall_timeout.is_some_and(|value| value.is_zero()) {
            return Err(SafeHttpError::InvalidBudget);
        }
        loop {
            let frame = match stall_timeout {
                Some(timeout) => tokio::time::timeout(timeout, self.body.frame())
                    .await
                    .map_err(|_| SafeHttpError::StreamStalled)?,
                None => self.body.frame().await,
            };
            let Some(frame) = frame else {
                return Ok(None);
            };
            let frame = frame.map_err(|_| SafeHttpError::ProtocolFailed)?;
            let Ok(chunk) = frame.into_data() else {
                continue;
            };
            self.read_bytes = self
                .read_bytes
                .checked_add(chunk.len())
                .ok_or(SafeHttpError::ResponseTooLarge)?;
            if self.read_bytes > self.max_bytes {
                return Err(SafeHttpError::ResponseTooLarge);
            }
            return Ok(Some(chunk));
        }
    }
}

impl fmt::Debug for SafeHttpStreamResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeHttpStreamResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("read_bytes", &self.read_bytes)
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

/// 唯一网络实现。
#[derive(Clone)]
pub struct SafeDialer {
    resolver: Arc<dyn DnsResolver>,
    policy: EgressPolicy,
    tls: Arc<ClientConfig>,
}

impl fmt::Debug for SafeDialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeDialer")
            .field("policy", &self.policy)
            .field("tls", &"rustls-ring/webpki-roots")
            .finish_non_exhaustive()
    }
}

impl SafeDialer {
    /// Clone this transport with a different explicit destination policy while preserving the
    /// resolver and TLS roots. This is used for per-resource policy, never caller-controlled
    /// request state; every redirect still resolves and re-checks through the cloned policy.
    #[must_use]
    pub(crate) fn with_egress_policy(&self, policy: EgressPolicy) -> Self {
        Self {
            resolver: self.resolver.clone(),
            policy,
            tls: self.tls.clone(),
        }
    }

    /// Resolve one URL and apply the exact current destination policy without opening a socket.
    /// Callers use this only as an early registration verdict; execute re-resolves every hop.
    pub async fn validate_destination(
        &self,
        url: &Url,
        scheme_policy: SchemePolicy,
    ) -> Result<(), SafeHttpError> {
        validate_url(url, scheme_policy)?;
        self.resolve_and_filter(url).await.map(|_| ())
    }

    /// Open a proxy hop only after the same fresh DNS/IP validation used by every protocol
    /// adapter. The returned socket is pinned to a vetted SocketAddr; no proxy resolver exists.
    /// Scope authentication, host/port policy, lifetimes and byte limits belong to scope_gateway.
    pub(super) async fn connect_proxy_hop(&self, url: &Url) -> Result<ProxyHop, SafeHttpError> {
        validate_url(url, SchemePolicy::HttpOrHttps)?;
        let addresses = self.resolve_and_filter(url).await?;
        connect_validated(&addresses)
            .await
            .map(|(stream, _peer)| ProxyHop(stream))
    }

    /// 生产构造：系统 DNS + lockfile 固定的 Mozilla roots。
    #[must_use]
    pub fn new(policy: EgressPolicy) -> Self {
        Self::with_resolver(policy, Arc::new(SystemDnsResolver))
    }

    /// 注入 resolver；用于确定性重绑定/redirect 测试，也允许未来受控 resolver adapter。
    #[must_use]
    pub fn with_resolver(policy: EgressPolicy, resolver: Arc<dyn DnsResolver>) -> Self {
        Self {
            resolver,
            policy,
            tls: Arc::new(default_tls_config()),
        }
    }

    /// 增加显式 DER root。默认 roots 仍保留；调用方必须把证书配置当独立受审输入。
    pub fn with_extra_roots(
        policy: EgressPolicy,
        resolver: Arc<dyn DnsResolver>,
        roots: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, SafeHttpError> {
        let mut root_store = default_root_store();
        for root in roots {
            root_store.add(root).map_err(|_| SafeHttpError::TlsFailed)?;
        }
        Ok(Self {
            resolver,
            policy,
            tls: Arc::new(tls_config(root_store)),
        })
    }

    /// 执行整个 request + redirect chain；一个总 timeout 包住 DNS、connect、TLS、headers 与 body。
    pub async fn execute(
        &self,
        request: SafeHttpRequest,
    ) -> Result<SafeHttpResponse, SafeHttpError> {
        match tokio::time::timeout(request.budget.timeout(), self.execute_inner(request)).await {
            Ok(result) => result,
            Err(_) => Err(SafeHttpError::DeadlineExceeded),
        }
    }

    /// 打开 streaming body；budget timeout 只包 DNS/connect/TLS/redirect/headers，之后每个
    /// body read 由 `SafeHttpStreamResponse::next_chunk` 的真实 read 间隔 watchdog 负责。
    pub async fn execute_stream(
        &self,
        request: SafeHttpRequest,
    ) -> Result<SafeHttpStreamResponse, SafeHttpError> {
        match tokio::time::timeout(request.budget.timeout(), self.execute_stream_inner(request))
            .await
        {
            Ok(result) => result,
            Err(_) => Err(SafeHttpError::DeadlineExceeded),
        }
    }

    async fn execute_inner(
        &self,
        request: SafeHttpRequest,
    ) -> Result<SafeHttpResponse, SafeHttpError> {
        let (raw, budget) = self.follow_redirects(request).await?;
        let body = read_bounded_body(raw.body, budget.max_response_bytes()).await?;
        Ok(SafeHttpResponse {
            status: raw.status,
            headers: raw.headers,
            body,
        })
    }

    async fn execute_stream_inner(
        &self,
        request: SafeHttpRequest,
    ) -> Result<SafeHttpStreamResponse, SafeHttpError> {
        let (raw, budget) = self.follow_redirects(request).await?;
        if let Some(upper) = raw.body.size_hint().upper()
            && upper > budget.max_response_bytes() as u64
        {
            return Err(SafeHttpError::ResponseTooLarge);
        }
        Ok(SafeHttpStreamResponse {
            status: raw.status,
            headers: raw.headers,
            body: raw.body,
            _driver: raw._driver,
            read_bytes: 0,
            max_bytes: budget.max_response_bytes(),
        })
    }

    async fn follow_redirects(
        &self,
        mut request: SafeHttpRequest,
    ) -> Result<(RawResponse, SafeHttpBudget), SafeHttpError> {
        let mut redirects = 0usize;

        loop {
            validate_url(&request.url, request.scheme_policy)?;
            let resolved = self.resolve_and_filter(&request.url).await?;
            let raw = self.send_one(&request, &resolved).await?;

            if !request.follow_redirects || !is_redirect(raw.status) {
                return Ok((raw, request.budget));
            }

            if redirects >= MAX_REDIRECTS {
                return Err(SafeHttpError::RedirectLimit);
            }
            redirects += 1;

            let location = raw
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(SafeHttpError::RedirectInvalid)?;
            let next = request
                .url
                .join(location)
                .map_err(|_| SafeHttpError::RedirectInvalid)?;
            validate_url(&next, request.scheme_policy)?;

            let same_origin = Origin::from_url(&request.url)? == Origin::from_url(&next)?;
            if !same_origin {
                request.authorization = None;
                request.provider_authentication = None;
                request.protocol_headers.clear();
            }

            match (request.method, raw.status) {
                (SafeMethod::Get | SafeMethod::McpGet, _) => {}
                (SafeMethod::PostForm | SafeMethod::PostJson, StatusCode::SEE_OTHER) => {
                    request.method = SafeMethod::Get;
                    request.body = Bytes::new();
                }
                (
                    SafeMethod::PostForm | SafeMethod::PostJson,
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT,
                ) => {
                    if !same_origin {
                        return Err(SafeHttpError::SensitiveRedirectRejected);
                    }
                }
                (
                    SafeMethod::PostForm | SafeMethod::PostJson,
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND,
                ) => {
                    return Err(SafeHttpError::RedirectMethodRejected);
                }
                (SafeMethod::PostForm | SafeMethod::PostJson, _) => {
                    return Err(SafeHttpError::RedirectInvalid);
                }
                (SafeMethod::McpPost, StatusCode::SEE_OTHER) => {
                    request.method = SafeMethod::McpGet;
                    request.body = Bytes::new();
                }
                (
                    SafeMethod::McpPost,
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT,
                ) => {
                    if !same_origin {
                        return Err(SafeHttpError::SensitiveRedirectRejected);
                    }
                }
                (SafeMethod::McpPost, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND) => {
                    return Err(SafeHttpError::RedirectMethodRejected);
                }
                (SafeMethod::McpPost, _) => return Err(SafeHttpError::RedirectInvalid),
                (
                    SafeMethod::McpDelete,
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT,
                ) if same_origin => {}
                (SafeMethod::McpDelete, _) => {
                    return Err(SafeHttpError::RedirectMethodRejected);
                }
            }

            request.url = next;
        }
    }

    async fn resolve_and_filter(&self, url: &Url) -> Result<Vec<SocketAddr>, SafeHttpError> {
        let port = url
            .port_or_known_default()
            .ok_or(SafeHttpError::InvalidUrl)?;

        // URL host_str keeps the brackets around IPv6. Match the typed host instead of treating
        // `[::1]` as a DNS name; numeric IPs never enter an alternate resolver path.
        let raw = match url.host().ok_or(SafeHttpError::InvalidUrl)? {
            url::Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
            url::Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
            url::Host::Domain(host) => self
                .resolver
                .resolve(host, port)
                .await
                .map_err(|_| SafeHttpError::DnsUnavailable)?,
        };

        let mut unique = BTreeSet::new();
        for address in raw {
            let normalized = SocketAddr::new(address.ip(), port);
            if self.policy.permits(normalized.ip()) {
                unique.insert(normalized);
            }
        }
        if unique.is_empty() {
            return Err(SafeHttpError::DestinationDenied);
        }
        Ok(unique.into_iter().collect())
    }

    async fn send_one(
        &self,
        request: &SafeHttpRequest,
        addresses: &[SocketAddr],
    ) -> Result<RawResponse, SafeHttpError> {
        let (stream, peer) = connect_validated(addresses).await?;
        let http_request = build_http_request(request)?;

        match request.url.scheme() {
            "http" => send_http1(stream, http_request).await,
            "https" => {
                let server_name = match request.url.host().ok_or(SafeHttpError::InvalidUrl)? {
                    url::Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(ip).into()),
                    url::Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(ip).into()),
                    url::Host::Domain(host) => ServerName::try_from(host.to_owned())
                        .map_err(|_| SafeHttpError::InvalidUrl)?,
                };
                let tls = TlsConnector::from(Arc::clone(&self.tls))
                    .connect(server_name, stream)
                    .await
                    .map_err(|_| SafeHttpError::TlsFailed)?;
                // 正向对照连接绑定：TLS 包装后底层 peer 仍必须等于刚才实际连接的地址。
                if tls.get_ref().0.peer_addr().ok() != Some(peer) {
                    return Err(SafeHttpError::PeerMismatch);
                }
                send_http1(tls, http_request).await
            }
            _ => Err(SafeHttpError::SchemeRejected),
        }
    }
}

/// A freshly vetted, already connected hop. Only the sibling scope gateway consumes this type;
/// it cannot substitute a downstream socket or resolve the target for a second time.
pub(super) struct ProxyHop(TcpStream);

impl ProxyHop {
    pub(super) fn into_tunnel(self) -> TcpStream {
        self.0
    }

    pub(super) async fn http<B>(
        self,
    ) -> Result<
        (
            http1::SendRequest<B>,
            impl Future<Output = Result<(), hyper::Error>> + Send,
        ),
        SafeHttpError,
    >
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut builder = http1::Builder::new();
        builder.max_headers(64).max_buf_size(32 * 1024);
        let (sender, connection) = builder
            .handshake(TokioIo::new(self.0))
            .await
            .map_err(|_| SafeHttpError::ProtocolFailed)?;
        Ok((sender, connection.with_upgrades()))
    }
}

struct RawResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    _driver: AbortOnDrop,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect_validated(
    addresses: &[SocketAddr],
) -> Result<(TcpStream, SocketAddr), SafeHttpError> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            stream
                .set_nodelay(true)
                .map_err(|_| SafeHttpError::ConnectFailed)?;
            let peer = stream
                .peer_addr()
                .map_err(|_| SafeHttpError::ConnectFailed)?;
            if peer != *address {
                return Err(SafeHttpError::PeerMismatch);
            }
            return Ok((stream, peer));
        }
    }
    Err(SafeHttpError::ConnectFailed)
}

async fn send_http1<I>(io: I, request: Request<Full<Bytes>>) -> Result<RawResponse, SafeHttpError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| SafeHttpError::ProtocolFailed)?;
    let driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| SafeHttpError::ProtocolFailed)?;
    let (parts, body) = response.into_parts();
    Ok(RawResponse {
        status: parts.status,
        headers: parts.headers,
        body,
        _driver: driver,
    })
}

fn build_http_request(request: &SafeHttpRequest) -> Result<Request<Full<Bytes>>, SafeHttpError> {
    let path = match request.url.query() {
        Some(query) => format!("{}?{query}", request.url.path()),
        None => request.url.path().to_owned(),
    };
    let authority = &request.url[Position::BeforeHost..Position::AfterPort];
    let accept = if let Some(accept) = request.gateway_accept {
        match accept {
            GatewayAccept::Json => JSON_ACCEPT,
            GatewayAccept::EventStream => "text/event-stream",
        }
    } else if matches!(
        request.method,
        SafeMethod::PostJson | SafeMethod::McpGet | SafeMethod::McpPost | SafeMethod::McpDelete
    ) {
        STREAM_ACCEPT
    } else {
        JSON_ACCEPT
    };

    let mut builder = Request::builder()
        .method(request.method.as_http())
        .uri(path)
        .header(HOST, authority)
        .header(CONNECTION, "close")
        .header(ACCEPT, accept);
    if request.method == SafeMethod::PostForm {
        builder = builder.header(CONTENT_TYPE, FORM_CONTENT_TYPE);
    } else if matches!(request.method, SafeMethod::PostJson | SafeMethod::McpPost) {
        builder = builder.header(CONTENT_TYPE, JSON_CONTENT_TYPE);
    }
    if let Some(authorization) = &request.authorization {
        builder = builder.header(AUTHORIZATION, authorization.0.clone());
    }
    match &request.provider_authentication {
        Some(ProviderAuthentication::Anthropic(api_key)) => {
            builder = builder
                .header("x-api-key", api_key.clone())
                .header("anthropic-version", "2023-06-01");
        }
        Some(ProviderAuthentication::Google(api_key)) => {
            builder = builder.header("x-goog-api-key", api_key.clone());
        }
        None => {}
    }
    for (name, value) in &request.protocol_headers {
        builder = builder.header(name, value.clone());
    }
    builder
        .body(Full::new(request.body.clone()))
        .map_err(|_| SafeHttpError::ProtocolFailed)
}

fn is_allowed_mcp_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "mcp-session-id" | "mcp-protocol-version" | "last-event-id" | "mcp-method" | "mcp-name"
    ) || name.as_str().starts_with("mcp-param-")
}

async fn read_bounded_body(mut body: Incoming, max_bytes: usize) -> Result<Vec<u8>, SafeHttpError> {
    if let Some(upper) = body.size_hint().upper()
        && upper > max_bytes as u64
    {
        return Err(SafeHttpError::ResponseTooLarge);
    }

    let mut output =
        BytesMut::with_capacity(body.size_hint().lower().min(max_bytes as u64) as usize);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| SafeHttpError::ProtocolFailed)?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        if chunk.len() > max_bytes.saturating_sub(output.len()) {
            return Err(SafeHttpError::ResponseTooLarge);
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output.to_vec())
}

fn default_root_store() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn default_tls_config() -> ClientConfig {
    tls_config(default_root_store())
}

fn tls_config(roots: RootCertStore) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider 必须支持 rustls 安全默认协议版本")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config
}

fn validate_url(url: &Url, policy: SchemePolicy) -> Result<(), SafeHttpError> {
    if !policy.accepts(url.scheme()) {
        return Err(SafeHttpError::SchemeRejected);
    }
    if url.cannot_be_a_base()
        || url.host_str().is_none()
        || url.port_or_known_default().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(SafeHttpError::InvalidUrl);
    }
    Ok(())
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn from_url(url: &Url) -> Result<Self, SafeHttpError> {
        Ok(Self {
            scheme: url.scheme().to_owned(),
            host: url
                .host_str()
                .ok_or(SafeHttpError::InvalidUrl)?
                .to_ascii_lowercase(),
            port: url
                .port_or_known_default()
                .ok_or(SafeHttpError::InvalidUrl)?,
        })
    }
}

struct RedactedOrigin(Option<Origin>);

impl RedactedOrigin {
    fn from_url(url: &Url) -> Self {
        Self(Origin::from_url(url).ok())
    }
}

impl fmt::Debug for RedactedOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(origin) => formatter
                .debug_struct("Origin")
                .field("scheme", &origin.scheme)
                .field("host", &origin.host)
                .field("port", &origin.port)
                .finish(),
            None => formatter.write_str("Origin([INVALID])"),
        }
    }
}

/// 当前 IANA registry 口径下默认可直接出网的地址。
///
/// Rust 1.98 的 `IpAddr::is_global` 仍是 unstable（本轮编译探针 E0658），不能把 nightly API
/// 当闸门。这里显式编码 IANA 非 global 特殊段，并给 192.0.0.0/24、2001::/23 内的 global
/// 例外更具体优先级。未来 IANA 表变化必须同批改测试与 W-7 delta audit。
fn is_default_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_default_global_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_default_global_v4(mapped);
            }
            is_default_global_v6(ip)
        }
    }
}

fn is_default_global_v4(ip: Ipv4Addr) -> bool {
    // IANA 对 192.0.0.0/24 的两个更具体 global 例外。
    if ip == Ipv4Addr::new(192, 0, 0, 9) || ip == Ipv4Addr::new(192, 0, 0, 10) {
        return true;
    }

    const DENIED: &[(u32, u8)] = &[
        (0x0000_0000, 8),  // 0.0.0.0/8 this network
        (0x0a00_0000, 8),  // RFC1918
        (0x6440_0000, 10), // shared 100.64/10
        (0x7f00_0000, 8),  // loopback
        (0xa9fe_0000, 16), // link-local + cloud metadata
        (0xac10_0000, 12), // RFC1918
        (0xc000_0000, 24), // IETF protocol assignments
        (0xc000_0200, 24), // TEST-NET-1
        (0xc058_6300, 24), // deprecated 6to4 relay anycast
        (0xc0a8_0000, 16), // RFC1918
        (0xc612_0000, 15), // benchmarking
        (0xc633_6400, 24), // TEST-NET-2
        (0xcb00_7100, 24), // TEST-NET-3
        (0xe000_0000, 4),  // multicast
        (0xf000_0000, 4),  // reserved + limited broadcast
    ];
    !DENIED.iter().any(|(network, prefix)| {
        let mask = prefix_mask_v4(*prefix);
        u32::from(ip) & mask == *network & mask
    })
}

fn is_default_global_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);

    // IANA global special-purpose exception outside 2000::/3.
    if in_v6(
        bits,
        u128::from(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0)),
        96,
    ) {
        return true;
    }

    // 2001::/23 默认 non-global，但 IANA 登记了这些更具体 global 例外。
    const GLOBAL_2001_EXCEPTIONS: &[(u128, u8)] = &[
        (0x2001_0001_0000_0000_0000_0000_0000_0001, 128),
        (0x2001_0001_0000_0000_0000_0000_0000_0002, 128),
        (0x2001_0001_0000_0000_0000_0000_0000_0003, 128),
        (0x2001_0003_0000_0000_0000_0000_0000_0000, 32),
        (0x2001_0004_0112_0000_0000_0000_0000_0000, 48),
        (0x2001_0020_0000_0000_0000_0000_0000_0000, 28),
        (0x2001_0030_0000_0000_0000_0000_0000_0000, 28),
    ];
    if GLOBAL_2001_EXCEPTIONS
        .iter()
        .any(|(network, prefix)| in_v6(bits, *network, *prefix))
    {
        return true;
    }

    if !in_v6(bits, 0x2000_0000_0000_0000_0000_0000_0000_0000, 3) {
        return false;
    }

    const DENIED: &[(u128, u8)] = &[
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // IETF assignments
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // documentation
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4 / N/A global
        (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // documentation
    ];
    !DENIED
        .iter()
        .any(|(network, prefix)| in_v6(bits, *network, *prefix))
}

const fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn in_v6(address: u128, network: u128, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    address & mask == network & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use rustls::ServerConfig;
    use rustls::pki_types::PrivateKeyDer;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    // 非生产、无权利价值的确定性 TLS 测试夹具。Ed25519 leaf key 只用于本模块本机
    // listener；leaf SAN=idp.test，有效期 2026-08-23..2126-07-30。DER SHA-256：
    // CA   =970905ad73afdd141288d1514fe7a3fad797175d76b9b441b4d7bc676e7c2831
    // leaf =556c31a229840bdbf65f9dc61d57b5fef0d78d6d964c1d44045ca0c4ab85e404
    // key  =030f6b90183f789c7b9c51fc57622f3e8d35e06e0a608f91c467c9e91877cea8
    const TEST_CA_DER_BASE64: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
    const TEST_LEAF_DER_BASE64: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
    const TEST_KEY_DER_BASE64: &str =
        "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

    fn budget(max: usize) -> SafeHttpBudget {
        SafeHttpBudget::new(max, Duration::from_secs(2)).unwrap()
    }

    fn loopback_policy() -> EgressPolicy {
        EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32", "::1/128"]).unwrap())
    }

    #[test]
    fn iana_global_examples_are_allowed() {
        for raw in [
            "1.1.1.1",
            "8.8.8.8",
            "192.0.0.9",
            "192.0.0.10",
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
            "64:ff9b::1",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2001:4860:4860::8888",
            "2620:4f:8000::1",
        ] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(is_default_global(ip), "{raw} 应按 IANA 为 global");
        }
    }

    #[test]
    fn every_relevant_iana_non_global_family_is_denied() {
        for raw in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.8",
            "192.0.0.170",
            "192.0.2.1",
            "192.88.99.2",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(!is_default_global(ip), "{raw} 必须默认拒绝");
        }
    }

    #[test]
    fn exact_cidr_is_the_only_override_and_mapped_ipv4_cannot_bypass_it() {
        let allowlist =
            CidrAllowlist::parse_exact(["10.0.0.0/24", "::ffff:127.0.0.1/128"]).unwrap();
        let policy = EgressPolicy::new(allowlist);
        assert!(policy.permits("10.0.0.7".parse().unwrap()));
        assert!(!policy.permits("10.0.1.7".parse().unwrap()));
        assert!(policy.permits("::ffff:127.0.0.1".parse().unwrap()));

        for invalid in ["localhost", "127.0.0.1", " 127.0.0.1/32", "10.0.0.7/24"] {
            assert_eq!(
                CidrAllowlist::parse_exact([invalid]),
                Err(SafeHttpError::InvalidAllowlist)
            );
        }
    }

    #[test]
    fn request_shape_rejects_credentials_fragments_and_wrong_scheme() {
        let b = budget(1024);
        for raw in [
            "https://user@example.com/",
            "https://example.com/#fragment",
            "file:///etc/passwd",
            "mailto:admin@example.com",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(SafeHttpRequest::get(url, SchemePolicy::HttpsOnly, b).is_err());
        }
        let http = Url::parse("http://example.com/").unwrap();
        assert_eq!(
            SafeHttpRequest::get(http, SchemePolicy::HttpsOnly, b).unwrap_err(),
            SafeHttpError::SchemeRejected
        );
    }

    #[tokio::test]
    async fn loopback_is_denied_without_exact_allowlist_and_works_with_it() {
        let (url, server) = one_response_server("200 OK", &[], b"ok", Duration::ZERO).await;
        let request =
            SafeHttpRequest::get(url.clone(), SchemePolicy::HttpOrHttps, budget(32)).unwrap();
        let denied = SafeDialer::new(EgressPolicy::default())
            .execute(request)
            .await;
        assert_eq!(denied.unwrap_err(), SafeHttpError::DestinationDenied);

        let request = SafeHttpRequest::get(url, SchemePolicy::HttpOrHttps, budget(32)).unwrap();
        let response = SafeDialer::new(loopback_policy())
            .execute(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn body_limit_is_enforced_while_reading() {
        let (url, server) = one_response_server("200 OK", &[], &[b'x'; 65], Duration::ZERO).await;
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpOrHttps, budget(64)).unwrap();
        let result = SafeDialer::new(loopback_policy()).execute(request).await;
        assert_eq!(result.unwrap_err(), SafeHttpError::ResponseTooLarge);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn total_deadline_includes_waiting_for_response_headers() {
        let (url, server) =
            one_response_server("200 OK", &[], b"late", Duration::from_millis(150)).await;
        let request = SafeHttpRequest::get(
            url,
            SchemePolicy::HttpOrHttps,
            SafeHttpBudget::new(32, Duration::from_millis(30)).unwrap(),
        )
        .unwrap();
        let result = SafeDialer::new(loopback_policy()).execute(request).await;
        assert_eq!(result.unwrap_err(), SafeHttpError::DeadlineExceeded);
        server.await.unwrap();
    }

    #[derive(Default)]
    struct ScriptedResolver {
        answers: Mutex<BTreeMap<String, VecDeque<Vec<SocketAddr>>>>,
        calls: Mutex<Vec<String>>,
    }

    impl ScriptedResolver {
        fn push(&self, host: &str, answer: Vec<SocketAddr>) {
            self.answers
                .lock()
                .unwrap()
                .entry(host.to_owned())
                .or_default()
                .push_back(answer);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DnsResolver for ScriptedResolver {
        async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
            self.calls.lock().unwrap().push(host.to_owned());
            self.answers
                .lock()
                .unwrap()
                .get_mut(host)
                .and_then(VecDeque::pop_front)
                .ok_or(DnsUnavailable)
        }
    }

    #[tokio::test]
    async fn tls_uses_the_original_hostname_for_verification_while_connecting_the_vetted_ip() {
        let (address, certificate, server) = tls_response_server().await;
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.push("idp.test", vec![address]);
        let url = Url::parse(&format!("https://idp.test:{}/metadata", address.port())).unwrap();
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpsOnly, budget(32)).unwrap();
        let dialer =
            SafeDialer::with_extra_roots(loopback_policy(), resolver.clone(), [certificate])
                .unwrap();
        let response = dialer.execute(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"tls-ok");
        assert_eq!(resolver.calls(), vec!["idp.test"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_trusted_certificate_for_another_hostname_is_still_rejected() {
        let (address, certificate, server) = tls_response_server().await;
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.push("other.test", vec![address]);
        let url = Url::parse(&format!("https://other.test:{}/metadata", address.port())).unwrap();
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpsOnly, budget(32)).unwrap();
        let dialer =
            SafeDialer::with_extra_roots(loopback_policy(), resolver.clone(), [certificate])
                .unwrap();
        let result = dialer.execute(request).await;
        assert_eq!(result.unwrap_err(), SafeHttpError::TlsFailed);
        assert_eq!(resolver.calls(), vec!["other.test"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn every_redirect_reresolves_and_rebinding_to_private_is_denied() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let resolver = Arc::new(ScriptedResolver::default());
        resolver.push("rebind.test", vec![address]);
        resolver.push(
            "rebind.test",
            vec![SocketAddr::new("10.0.0.9".parse().unwrap(), address.port())],
        );
        let url = Url::parse(&format!("http://rebind.test:{}/start", address.port())).unwrap();
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpOrHttps, budget(32)).unwrap();
        let result = SafeDialer::with_resolver(loopback_policy(), resolver.clone())
            .execute(request)
            .await;
        assert_eq!(result.unwrap_err(), SafeHttpError::DestinationDenied);
        assert_eq!(resolver.calls(), vec!["rebind.test", "rebind.test"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn every_sensitive_header_is_stripped_on_cross_origin_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let first_request = read_request(&mut first).await;
            assert!(
                first_request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer secret")
            );
            assert!(first_request.contains("x-api-key: anthropic-secret"));
            assert!(first_request.contains("anthropic-version: 2023-06-01"));
            let location = format!("http://beta.test:{}/final", address.port());
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            first.write_all(response.as_bytes()).await.unwrap();

            let (mut second, _) = listener.accept().await.unwrap();
            let second_request = read_request(&mut second).await;
            assert!(
                !second_request
                    .to_ascii_lowercase()
                    .contains("authorization:")
            );
            assert!(!second_request.contains("x-api-key:"));
            assert!(!second_request.contains("anthropic-version:"));
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let resolver = Arc::new(ScriptedResolver::default());
        resolver.push("alpha.test", vec![address]);
        resolver.push("beta.test", vec![address]);
        let url = Url::parse(&format!("http://alpha.test:{}/start", address.port())).unwrap();
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpOrHttps, budget(32))
            .unwrap()
            .with_authorization(AuthorizationValue::parse("Bearer secret").unwrap())
            .with_anthropic_api_key(ProviderApiKeyValue::parse("anthropic-secret").unwrap());
        let response = SafeDialer::with_resolver(loopback_policy(), resolver.clone())
            .execute(request)
            .await
            .unwrap();
        assert_eq!(response.body(), b"ok");
        assert_eq!(resolver.calls(), vec!["alpha.test", "beta.test"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_fourth_redirect_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for index in 0..=MAX_REDIRECTS {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: /{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    index + 1
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/0", address.port())).unwrap();
        let request = SafeHttpRequest::get(url, SchemePolicy::HttpOrHttps, budget(32)).unwrap();
        let result = SafeDialer::new(loopback_policy()).execute(request).await;
        assert_eq!(result.unwrap_err(), SafeHttpError::RedirectLimit);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn streaming_json_post_preserves_headers_and_reads_real_body_chunks() {
        let (url, server) = chunked_stream_server(vec![
            (Duration::ZERO, b"data: one\n\n".as_slice()),
            (Duration::from_millis(20), b"data: two\n\n".as_slice()),
        ])
        .await;
        let request = SafeHttpRequest::post_json_with_scheme(
            url,
            SchemePolicy::HttpOrHttps,
            br#"{"stream":true}"#.to_vec(),
            Some(AuthorizationValue::parse("Bearer provider-secret").unwrap()),
            budget(1024),
        )
        .unwrap();
        let mut response = SafeDialer::new(loopback_policy())
            .execute_stream(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut output = Vec::new();
        while let Some(chunk) = response
            .next_chunk(Some(Duration::from_millis(100)))
            .await
            .unwrap()
        {
            output.extend(chunk);
        }
        assert_eq!(output, b"data: one\n\ndata: two\n\n");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn streaming_body_stall_and_total_size_are_distinct_fail_closed_errors() {
        let (stall_url, stall_server) = chunked_stream_server(vec![(
            Duration::from_millis(100),
            b"data: late\n\n".as_slice(),
        )])
        .await;
        let request = SafeHttpRequest::post_json_with_scheme(
            stall_url,
            SchemePolicy::HttpOrHttps,
            b"{}".to_vec(),
            None,
            budget(1024),
        )
        .unwrap();
        let mut response = SafeDialer::new(loopback_policy())
            .execute_stream(request)
            .await
            .unwrap();
        assert_eq!(
            response.next_chunk(Some(Duration::from_millis(20))).await,
            Err(SafeHttpError::StreamStalled)
        );
        drop(response);
        stall_server.await.unwrap();

        let (large_url, large_server) =
            chunked_stream_server(vec![(Duration::ZERO, b"12345".as_slice())]).await;
        let request = SafeHttpRequest::post_json_with_scheme(
            large_url,
            SchemePolicy::HttpOrHttps,
            b"{}".to_vec(),
            None,
            budget(4),
        )
        .unwrap();
        let mut response = SafeDialer::new(loopback_policy())
            .execute_stream(request)
            .await
            .unwrap();
        assert_eq!(
            response.next_chunk(Some(Duration::from_secs(1))).await,
            Err(SafeHttpError::ResponseTooLarge)
        );
        large_server.await.unwrap();
    }

    async fn chunked_stream_server(
        chunks: Vec<(Duration, &'static [u8])>,
    ) -> (Url, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.to_ascii_lowercase();
            assert!(request.starts_with("post "));
            assert!(request.contains("content-type: application/json"));
            assert!(request.contains("accept: text/event-stream, application/json"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            for (delay, chunk) in chunks {
                tokio::time::sleep(delay).await;
                let header = format!("{:x}\r\n", chunk.len());
                if let Err(error) = stream.write_all(header.as_bytes()).await {
                    assert_peer_closed_after_client_outcome(error);
                    return;
                }
                if let Err(error) = stream.write_all(chunk).await {
                    assert_peer_closed_after_client_outcome(error);
                    return;
                }
                if let Err(error) = stream.write_all(b"\r\n").await {
                    assert_peer_closed_after_client_outcome(error);
                    return;
                }
                if let Err(error) = stream.flush().await {
                    assert_peer_closed_after_client_outcome(error);
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });
        (
            Url::parse(&format!("http://127.0.0.1:{}/v1/responses", address.port())).unwrap(),
            server,
        )
    }

    async fn one_response_server(
        status: &'static str,
        headers: &'static [(&'static str, &'static str)],
        body: &'static [u8],
        delay: Duration,
    ) -> (Url, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            tokio::time::sleep(delay).await;
            let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
            for (name, value) in headers {
                response.push_str(name);
                response.push_str(": ");
                response.push_str(value);
                response.push_str("\r\n");
            }
            response.push_str("Connection: close\r\n\r\n");
            if let Err(error) = stream.write_all(response.as_bytes()).await {
                assert_peer_closed_after_client_outcome(error);
                return;
            }
            if let Err(error) = stream.write_all(body).await {
                assert_peer_closed_after_client_outcome(error);
            }
        });
        (
            Url::parse(&format!("http://127.0.0.1:{}/", address.port())).unwrap(),
            server,
        )
    }

    fn assert_peer_closed_after_client_outcome(error: std::io::Error) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ),
            "测试服务端只允许客户端先完成/超时后的对端关闭，实际：{error}"
        );
    }

    async fn tls_response_server() -> (SocketAddr, CertificateDer<'static>, JoinHandle<()>) {
        let root = CertificateDer::from(BASE64_STANDARD.decode(TEST_CA_DER_BASE64).unwrap());
        let certificate =
            CertificateDer::from(BASE64_STANDARD.decode(TEST_LEAF_DER_BASE64).unwrap());
        let key =
            PrivateKeyDer::try_from(BASE64_STANDARD.decode(TEST_KEY_DER_BASE64).unwrap()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            read_tls_request(&mut tls).await;
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok",
            )
            .await
            .unwrap();
        });
        (address, root, server)
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    async fn read_tls_request<S>(stream: &mut S) -> String
    where
        S: AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn post_json_with_scheme_accepts_http_url_under_http_or_https() {
        let request = SafeHttpRequest::post_json_with_scheme(
            Url::parse("http://127.0.0.1:1/x").unwrap(),
            SchemePolicy::HttpOrHttps,
            b"{}".to_vec(),
            None,
            budget(1024),
        )
        .unwrap();
        assert_eq!(request.method, SafeMethod::PostJson);
        assert!(request.follow_redirects);
        assert_eq!(request.scheme_policy, SchemePolicy::HttpOrHttps);
    }

    #[test]
    fn post_json_with_scheme_rejects_http_url_under_https_only() {
        let result = SafeHttpRequest::post_json_with_scheme(
            Url::parse("http://127.0.0.1:1/x").unwrap(),
            SchemePolicy::HttpsOnly,
            b"{}".to_vec(),
            None,
            budget(1024),
        );
        assert_eq!(result.unwrap_err(), SafeHttpError::SchemeRejected);
    }

    #[test]
    fn post_json_remains_https_only() {
        let http = SafeHttpRequest::post_json(
            Url::parse("http://127.0.0.1:1/x").unwrap(),
            b"{}".to_vec(),
            None,
            budget(1024),
        );
        assert_eq!(http.unwrap_err(), SafeHttpError::SchemeRejected);
        let https = SafeHttpRequest::post_json(
            Url::parse("https://127.0.0.1:1/x").unwrap(),
            b"{}".to_vec(),
            None,
            budget(1024),
        )
        .unwrap();
        assert_eq!(https.scheme_policy, SchemePolicy::HttpsOnly);
    }

    #[tokio::test]
    async fn http_json_post_with_scheme_reaches_loopback_server() {
        const BODY: &[u8] = br#"{"chat_id":42,"text":"hello"}"#;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 1024];
            let header_end = loop {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            while bytes.len() < header_end + BODY.len() {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let head = String::from_utf8(bytes[..header_end].to_vec())
                .unwrap()
                .to_ascii_lowercase();
            assert!(head.starts_with("post /bot/sendmessage "));
            assert!(head.contains("content-type: application/json"));
            assert_eq!(&bytes[header_end..], BODY);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .await
                .unwrap();
        });
        let request = SafeHttpRequest::post_json_with_scheme(
            Url::parse(&format!(
                "http://127.0.0.1:{}/bot/sendMessage",
                address.port()
            ))
            .unwrap(),
            SchemePolicy::HttpOrHttps,
            BODY.to_vec(),
            None,
            budget(1024),
        )
        .unwrap();
        let response = SafeDialer::new(loopback_policy())
            .execute(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), br#"{"ok":true}"#);
        server.await.unwrap();
    }
}
