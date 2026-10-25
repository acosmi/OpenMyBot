//! OIDC 登录的唯一协调顺序。
//!
//! Server transport 只负责 query/cookie framing；协议和业务顺序在这里固定：
//! `consume state → redirect/provider → token POST → JWKS rotation → claims/groups → session tx`。
//! state 在任何昂贵网络动作之前烧掉；`kid` 只作为 JWKS 缓存提示；token 与 metadata 都走同一
//! [`SafeDialer`]；明文 session 只可能来自 [`PostgresOidcSessionIssuer`] commit 后返回值。

use std::collections::BTreeMap;
use std::sync::Arc;

use openbot_domain::identity::groups::IdpGroupMapping;
use openbot_domain::vault::SecretBytes;
use openidconnect::core::CoreProviderMetadata;
use openidconnect::{AuthorizationCode, ClientSecret};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use super::attempt::{CallbackLoginAttempt, ProviderIncarnationBinding};
use super::attempt_postgres::{PostgresAttemptError, PostgresLoginAttemptStore};
use super::authorize::{DEFAULT_SCOPES, authorization_url};
use super::claims::{
    DEFAULT_ID_TOKEN_SIGNING_ALGS, build_verifier_at, validate_entra_token_issuer,
    verify_with_group_mapping,
};
use super::discovery::{FetchBudget, discover_with_expected_issuer};
use super::error::OidcError;
use super::jwks::{JwksCache, JwksRefreshPolicy};
use super::provider::{OidcProviderConfig, ProviderId, ProviderKind, ProviderOrigin};
use super::ratelimit::RateLimitPolicy;
use super::ratelimit_postgres::{
    OidcRateLimitBucket, PostgresOidcRateLimiter, PostgresRateLimitError,
};
use super::session_issuer::{IssuedSession, PostgresOidcSessionIssuer, SessionIssueError};
use super::token::{exchange_authorization_code, untrusted_key_id};
use super::token_transport::SafeOauthHttpClient;
use crate::net::safe_http::{SafeDialer, SafeHttpBudget, SafeHttpRequest, SchemePolicy};

pub const DEFAULT_ATTEMPT_TTL: Duration = Duration::minutes(10);
pub const DEFAULT_JWKS_COOLDOWN: Duration = Duration::minutes(1);
pub const DEFAULT_METADATA_MAX_BYTES: usize = 256 * 1024;
pub const DEFAULT_TOKEN_MAX_BYTES: usize = 64 * 1024;
pub const DEFAULT_IDP_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);
const MAX_AUTHORIZATION_CODE_BYTES: usize = 8 * 1024;
const LOGIN_START_RATE: RateLimitPolicy = RateLimitPolicy::new(20, Duration::minutes(1));
const CALLBACK_RATE: RateLimitPolicy = RateLimitPolicy::new(60, Duration::minutes(1));

/// 协调器失败；全部内层类型都是无远端载荷的稳定分类。
#[derive(Debug, thiserror::Error)]
pub enum OidcLoginError {
    #[error(transparent)]
    Protocol(#[from] OidcError),
    #[error(transparent)]
    Attempt(#[from] PostgresAttemptError),
    #[error(transparent)]
    Session(#[from] SessionIssueError),
    #[error(transparent)]
    RateLimitStore(#[from] PostgresRateLimitError),
    #[error("oidc_rate_limited")]
    RateLimited,
}

impl OidcLoginError {
    #[must_use]
    pub fn dependency_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Protocol(OidcError::TransportUnavailable)
                | Self::Attempt(
                    PostgresAttemptError::DependencyUnavailable | PostgresAttemptError::Corrupt
                )
                | Self::Session(
                    SessionIssueError::DependencyUnavailable
                        | SessionIssueError::Corrupt
                        | SessionIssueError::RandomUnavailable
                )
                | Self::RateLimitStore(_)
        )
    }

    #[must_use]
    pub fn rate_limited(&self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Attempt(PostgresAttemptError::Full)
        )
    }

    /// IdP 回了限流/5xx 或无法解析的元数据/token 响应；HTTP 层映射为 502。
    #[must_use]
    pub fn provider_failure(&self) -> bool {
        matches!(
            self,
            Self::Protocol(
                OidcError::ProviderResponseInvalid
                    | OidcError::MetadataStatusNotOk
                    | OidcError::MetadataTooLarge
                    | OidcError::MetadataContentTypeInvalid
                    | OidcError::MetadataMalformed
            )
        )
    }

    #[must_use]
    pub fn access_revoked(&self) -> bool {
        matches!(self, Self::Session(SessionIssueError::AccessRevoked))
    }
}

/// 一家已完成 discovery 预验证的运行时 provider。
pub struct OidcProviderRuntime {
    config: OidcProviderConfig,
    incarnation: ProviderIncarnationBinding,
    client_secret: Option<SecretBytes>,
    metadata: CoreProviderMetadata,
    jwks: Mutex<JwksCache>,
    group_mapping: Option<IdpGroupMapping>,
}

impl OidcProviderRuntime {
    /// 通过真实 safe dialer 拉 discovery，并在接收登录前验证三个 endpoint 的 HTTPS 形态。
    pub async fn discover(
        config: OidcProviderConfig,
        client_secret: Option<SecretBytes>,
        group_mapping: Option<IdpGroupMapping>,
        dialer: &SafeDialer,
        budget: FetchBudget,
    ) -> Result<Self, OidcError> {
        if config.origin() != ProviderOrigin::EnvironmentConfigured {
            return Err(OidcError::ProviderUnknown);
        }
        Self::discover_with_binding(
            config,
            client_secret,
            group_mapping,
            ProviderIncarnationBinding::Configured {},
            dialer,
            budget,
        )
        .await
    }

    /// The row incarnation is configuration DATA, not a Current provider admission.
    pub(crate) async fn discover_bound(
        config: OidcProviderConfig,
        client_secret: Option<SecretBytes>,
        group_mapping: Option<IdpGroupMapping>,
        provider_internal_id: Uuid,
        dialer: &SafeDialer,
        budget: FetchBudget,
    ) -> Result<Self, OidcError> {
        if config.origin() != ProviderOrigin::DynamicallyRegistered || provider_internal_id.is_nil() {
            return Err(OidcError::ProviderUnknown);
        }
        Self::discover_with_binding(
            config,
            client_secret,
            group_mapping,
            ProviderIncarnationBinding::Dynamic {
                provider_internal_id,
            },
            dialer,
            budget,
        )
        .await
    }

    /// Registration has no stored row incarnation yet; validate metadata without minting a runtime.
    pub(crate) async fn validate_registration(
        config: &OidcProviderConfig,
        group_mapping: Option<IdpGroupMapping>,
        dialer: &SafeDialer,
        budget: FetchBudget,
    ) -> Result<(), OidcError> {
        if config.origin() != ProviderOrigin::DynamicallyRegistered {
            return Err(OidcError::ProviderUnknown);
        }
        Self::discover_metadata(config, group_mapping.as_ref(), dialer, budget)
            .await
            .map(|_| ())
    }

    async fn discover_with_binding(
        config: OidcProviderConfig,
        client_secret: Option<SecretBytes>,
        group_mapping: Option<IdpGroupMapping>,
        incarnation: ProviderIncarnationBinding,
        dialer: &SafeDialer,
        budget: FetchBudget,
    ) -> Result<Self, OidcError> {
        let metadata =
            Self::discover_metadata(&config, group_mapping.as_ref(), dialer, budget).await?;
        let jwks = JwksCache::from_metadata(&metadata);
        Ok(Self {
            config,
            incarnation,
            client_secret,
            metadata,
            jwks: Mutex::new(jwks),
            group_mapping,
        })
    }

    async fn discover_metadata(
        config: &OidcProviderConfig,
        group_mapping: Option<&IdpGroupMapping>,
        dialer: &SafeDialer,
        budget: FetchBudget,
    ) -> Result<CoreProviderMetadata, OidcError> {
        if group_mapping.is_some_and(|mapping| mapping.provider().as_str() != config.id().as_str())
        {
            return Err(OidcError::GroupMappingMismatch);
        }
        let metadata = discover_with_expected_issuer(
            &config.discovery_issuer(),
            &config.issuer(),
            dialer,
            budget,
        )
        .await?;
        validate_metadata_endpoints(&metadata, budget)?;
        Ok(metadata)
    }

    #[must_use]
    pub const fn config(&self) -> &OidcProviderConfig {
        &self.config
    }
}

impl core::fmt::Debug for OidcProviderRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OidcProviderRuntime")
            .field("provider", self.config.id())
            .field("issuer", &self.config.issuer())
            .field("has_client_secret", &self.client_secret.is_some())
            .field("has_group_mapping", &self.group_mapping.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct OidcLoginCoordinator {
    providers: Arc<BTreeMap<ProviderId, Arc<OidcProviderRuntime>>>,
    attempts: PostgresLoginAttemptStore,
    sessions: PostgresOidcSessionIssuer,
    dialer: SafeDialer,
    fetch_budget: FetchBudget,
    token_budget: SafeHttpBudget,
    jwks_policy: JwksRefreshPolicy,
    attempt_ttl: Duration,
    rate_limiter: PostgresOidcRateLimiter,
}

impl OidcLoginCoordinator {
    pub fn new(
        providers: impl IntoIterator<Item = OidcProviderRuntime>,
        attempts: PostgresLoginAttemptStore,
        sessions: PostgresOidcSessionIssuer,
        rate_limiter: PostgresOidcRateLimiter,
        dialer: SafeDialer,
    ) -> Result<Self, OidcError> {
        let mut by_id = BTreeMap::new();
        for runtime in providers {
            let id = runtime.config.id().clone();
            if by_id.insert(id, Arc::new(runtime)).is_some() {
                return Err(OidcError::ProviderIdConflict);
            }
        }
        let token_budget = SafeHttpBudget::new(DEFAULT_TOKEN_MAX_BYTES, DEFAULT_IDP_TIMEOUT)
            .map_err(|_| OidcError::MetadataEndpointRejected)?;
        Ok(Self {
            providers: Arc::new(by_id),
            attempts,
            sessions,
            dialer,
            fetch_budget: FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT),
            token_budget,
            jwks_policy: JwksRefreshPolicy::new(DEFAULT_JWKS_COOLDOWN),
            attempt_ttl: DEFAULT_ATTEMPT_TTL,
            rate_limiter,
        })
    }

    /// 建 attempt、先持久化，再交出浏览器跳转 URL。
    pub async fn start(
        &self,
        provider_id: &ProviderId,
        now: OffsetDateTime,
        peer_ip: &str,
    ) -> Result<Url, OidcLoginError> {
        if !self
            .rate_limiter
            .evaluate(
                OidcRateLimitBucket::LoginStartIp,
                peer_ip,
                LOGIN_START_RATE,
                now,
            )
            .await?
            .allowed()
        {
            return Err(OidcLoginError::RateLimited);
        }
        let runtime = self
            .providers
            .get(provider_id)
            .ok_or(OidcError::ProviderUnknown)?;
        let attempt = super::attempt::LoginAttempt::begin_bound(
            provider_id.clone(),
            runtime.config.redirect_uri().clone(),
            now,
            self.attempt_ttl,
            runtime.incarnation,
        );
        let url = authorization_url(&runtime.metadata, &runtime.config, &attempt, DEFAULT_SCOPES)?;
        self.attempts.insert(attempt, now).await?;
        Ok(url)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn callback(
        &self,
        provider_id: &ProviderId,
        state: &str,
        code: &str,
        received_redirect_uri: &str,
        now: OffsetDateTime,
        peer_ip: &str,
        user_agent: Option<&str>,
    ) -> Result<IssuedSession, OidcLoginError> {
        let attempt = self
            .begin_callback(provider_id, state, now, peer_ip)
            .await?;
        let runtime = self
            .providers
            .get(provider_id)
            .ok_or(OidcError::ProviderUnknown)?;
        self.finish_callback(
            runtime,
            attempt,
            code,
            received_redirect_uri,
            now,
            peer_ip,
            user_agent,
        )
        .await
    }

    /// callback 的唯一前半：限速后立即烧 state，不做任何 IdP 网络动作。
    pub(crate) async fn begin_callback(
        &self,
        provider_id: &ProviderId,
        state: &str,
        now: OffsetDateTime,
        peer_ip: &str,
    ) -> Result<CallbackLoginAttempt, OidcLoginError> {
        if !self
            .rate_limiter
            .evaluate(OidcRateLimitBucket::CallbackIp, peer_ip, CALLBACK_RATE, now)
            .await?
            .allowed()
        {
            return Err(OidcLoginError::RateLimited);
        }
        // 必须先烧 state。后面的 redirect/code/IdP 任何失败都不得给攻击者重试同一 state。
        self.attempts
            .consume(state, provider_id, now)
            .await
            .map_err(Into::into)
    }

    /// 已烧 state 后完成 redirect/code/token/JWKS/claims/session；动态 IdP 复用这一半。
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_callback(
        &self,
        runtime: &OidcProviderRuntime,
        attempt: CallbackLoginAttempt,
        code: &str,
        received_redirect_uri: &str,
        now: OffsetDateTime,
        peer_ip: &str,
        user_agent: Option<&str>,
    ) -> Result<IssuedSession, OidcLoginError> {
        if attempt.provider() != runtime.config.id() || attempt.incarnation() != runtime.incarnation {
            return Err(PostgresAttemptError::ProviderMismatch.into());
        }
        attempt
            .redirect_uri()
            .assert_exact_match(received_redirect_uri)?;
        runtime
            .config
            .redirect_uri()
            .assert_exact_match(received_redirect_uri)?;
        if code.is_empty() || code.len() > MAX_AUTHORIZATION_CODE_BYTES || !code.is_ascii() {
            return Err(OidcError::TokenExchangeRejected.into());
        }
        let (nonce, verifier) = attempt.into_nonce_and_verifier();
        let token_endpoint = runtime
            .metadata
            .token_endpoint()
            .ok_or(OidcError::TokenEndpointMissing)?;
        let http = SafeOauthHttpClient::new(self.dialer.clone(), token_endpoint, self.token_budget)
            .map_err(|_| OidcError::MetadataEndpointRejected)?;
        // 长寿命 runtime 只持有会 zeroize 且不可 Clone 的 SecretBytes；协议库要求的
        // ClientSecret 仅在这一次 callback 栈帧内临时物化。
        let client_secret = materialize_client_secret(runtime.client_secret.as_ref())?;
        let raw_id_token = exchange_authorization_code(
            &runtime.metadata,
            &runtime.config,
            client_secret.as_ref(),
            AuthorizationCode::new(code.to_owned()),
            verifier,
            &http,
        )
        .await?;
        let kid = untrusted_key_id(&raw_id_token)?;
        let (keys, key_issuer) = {
            let mut cache = runtime.jwks.lock().await;
            let keys = cache
                .key_set_for(
                    kid.as_ref(),
                    &self.dialer,
                    self.fetch_budget,
                    self.jwks_policy,
                    now,
                )
                .await?
                .clone();
            let key_issuer = kid
                .as_ref()
                .and_then(|kid| cache.key_issuer(kid))
                .map(str::to_owned);
            (keys, key_issuer)
        };
        let verified_provider =
            bind_entra_token_issuer(&runtime.config, &raw_id_token, key_issuer.as_deref())?;
        let verifier = build_verifier_at(
            &verified_provider,
            client_secret.as_ref(),
            keys,
            DEFAULT_ID_TOKEN_SIGNING_ALGS,
            now,
        )?;
        let identity = verify_with_group_mapping(
            &raw_id_token,
            &verifier,
            &verified_provider,
            &nonce,
            runtime.group_mapping.as_ref(),
        )?;
        self.sessions
            .issue(
                &identity,
                &verified_provider,
                now,
                Some(peer_ip),
                user_agent,
            )
            .await
            .map_err(Into::into)
    }

    pub fn provider_ids(&self) -> impl Iterator<Item = &ProviderId> {
        self.providers.keys()
    }

    /// transport 用来把**配置值**传回 exact redirect 检查；绝不从 Host header 重建。
    #[must_use]
    pub fn callback_uri(&self, provider: &ProviderId) -> Option<&str> {
        self.providers
            .get(provider)
            .map(|runtime| runtime.config.redirect_uri().as_str())
    }
}

fn materialize_client_secret(
    secret: Option<&SecretBytes>,
) -> Result<Option<ClientSecret>, OidcError> {
    secret
        .map(|secret| {
            core::str::from_utf8(secret.expose())
                .map(|value| ClientSecret::new(value.to_owned()))
                .map_err(|_| OidcError::TokenExchangeRejected)
        })
        .transpose()
}

fn bind_entra_token_issuer(
    provider: &OidcProviderConfig,
    raw_id_token: &str,
    signing_key_issuer: Option<&str>,
) -> Result<OidcProviderConfig, OidcError> {
    let ProviderKind::Entra { tenants, .. } = provider.kind() else {
        return Ok(provider.clone());
    };
    if !tenants.is_tenant_independent() {
        // GUID/consumers authority 的 issuer 已经是固定值；后续 verifier 对 `iss` 做逐字节
        // 校验。JWK 的 `issuer` 是 Microsoft 扩展字段而非标准必填，不能让固定租户依赖它。
        return Ok(provider.clone());
    }
    let signing_key_issuer = signing_key_issuer.ok_or(OidcError::IdTokenRejected)?;
    let concrete = validate_entra_token_issuer(raw_id_token, provider, signing_key_issuer)?;
    provider.with_entra_token_issuer(concrete)
}

impl core::fmt::Debug for OidcLoginCoordinator {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OidcLoginCoordinator")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .field("attempts", &self.attempts)
            .field("sessions", &self.sessions)
            .field("rate_limiter", &self.rate_limiter)
            .field("dialer", &self.dialer)
            .finish_non_exhaustive()
    }
}

fn validate_metadata_endpoints(
    metadata: &CoreProviderMetadata,
    budget: FetchBudget,
) -> Result<(), OidcError> {
    let authorization = Url::parse(metadata.authorization_endpoint().as_str())
        .map_err(|_| OidcError::MetadataEndpointRejected)?;
    let safe_budget = SafeHttpBudget::new(budget.max_bytes(), budget.timeout())
        .map_err(|_| OidcError::MetadataEndpointRejected)?;
    SafeHttpRequest::get(authorization, SchemePolicy::HttpsOnly, safe_budget)
        .map_err(|_| OidcError::MetadataEndpointRejected)?;
    let token = metadata
        .token_endpoint()
        .ok_or(OidcError::TokenEndpointMissing)?;
    SafeHttpRequest::post_form(
        token.url().clone(),
        Vec::new(),
        None,
        SafeHttpBudget::new(DEFAULT_TOKEN_MAX_BYTES, DEFAULT_IDP_TIMEOUT)
            .map_err(|_| OidcError::MetadataEndpointRejected)?,
    )
    .map_err(|_| OidcError::MetadataEndpointRejected)?;
    SafeHttpRequest::get(
        metadata.jwks_uri().url().clone(),
        SchemePolicy::HttpsOnly,
        safe_budget,
    )
    .map_err(|_| OidcError::MetadataEndpointRejected)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::discovery::fixtures::discovery_document;
    use crate::auth::oidc::provider::fixtures::{config, entra_kind, okta_kind};
    use crate::auth::oidc::provider::{EntraTenantPolicy, ProviderOrigin};
    use std::collections::BTreeSet;

    #[test]
    fn discovery_endpoints_are_all_https_and_token_is_mandatory() {
        let valid: CoreProviderMetadata = serde_json::from_str(&discovery_document(
            "https://idp.example",
            "https://keys.example/jwks",
        ))
        .unwrap();
        assert!(
            validate_metadata_endpoints(
                &valid,
                FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT)
            )
            .is_ok()
        );

        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut json: serde_json::Value = serde_json::from_str(&discovery_document(
                "https://idp.example",
                "https://keys.example/jwks",
            ))
            .unwrap();
            json[field] = serde_json::Value::String("http://127.0.0.1/internal".to_owned());
            let metadata: CoreProviderMetadata = serde_json::from_value(json).unwrap();
            assert_eq!(
                validate_metadata_endpoints(
                    &metadata,
                    FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT)
                ),
                Err(OidcError::MetadataEndpointRejected),
                "{field} 必须判红"
            );
        }
    }

    #[test]
    fn dependency_classification_does_not_turn_client_rejections_into_503() {
        assert!(OidcLoginError::Protocol(OidcError::TransportUnavailable).dependency_unavailable());
        assert!(
            OidcLoginError::Attempt(PostgresAttemptError::DependencyUnavailable)
                .dependency_unavailable()
        );
        assert!(!OidcLoginError::Protocol(OidcError::IdTokenRejected).dependency_unavailable());
        assert!(!OidcLoginError::Attempt(PostgresAttemptError::Unknown).dependency_unavailable());
        assert!(OidcLoginError::Protocol(OidcError::ProviderResponseInvalid).provider_failure());
        assert!(!OidcLoginError::Protocol(OidcError::IdTokenRejected).provider_failure());
    }

    #[test]
    fn fixed_entra_issuer_does_not_depend_on_the_nonstandard_jwk_issuer_extension() {
        let tenant = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
        let fixed = config(
            "microsoft",
            entra_kind(
                &issuer,
                EntraTenantPolicy::AllowList(BTreeSet::from([tenant.to_owned()])),
            ),
            ProviderOrigin::EnvironmentConfigured,
            &[],
        );
        let bound = bind_entra_token_issuer(&fixed, "not-yet-parsed", None).unwrap();
        assert_eq!(bound.issuer(), fixed.issuer());

        let tenant_independent = config(
            "microsoft-common",
            entra_kind(
                "https://login.microsoftonline.com/{tenantid}/v2.0",
                EntraTenantPolicy::TenantIndependent {
                    allow_personal: true,
                },
            ),
            ProviderOrigin::EnvironmentConfigured,
            &[],
        );
        assert_eq!(
            bind_entra_token_issuer(&tenant_independent, "not-yet-parsed", None),
            Err(OidcError::IdTokenRejected),
            "tenant-independent token 必须绑定选中 JWK 的 issuer 扩展"
        );

        let ordinary = config(
            "okta",
            okta_kind("https://idp.example"),
            ProviderOrigin::EnvironmentConfigured,
            &[],
        );
        assert_eq!(
            bind_entra_token_issuer(&ordinary, "not-yet-parsed", None)
                .unwrap()
                .issuer(),
            ordinary.issuer()
        );
    }
}
