//! 动态 SSO 的唯一 application-facing 协调器；数据库每次重读保证跨 replica 新鲜。

use crate::db::pool::DatabasePool as Pool;
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::identity::groups::{IdentityProviderId, IdpGroupMapping};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::identity::session::SessionLifetimePolicy;
use openbot_domain::vault::{KeyVersion, SecretBytes, WrappingKey};
use openidconnect::ClientId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::config::{
    DecodedSecretConfig, RegisterIdentityProviderInput, RegisteredIdentityProvider,
    RegistrationPlan, SsoConfigError, SsoProtocol, validated_issuer,
};
use super::ephemeral::{PostgresSamlAttemptStore, PostgresSsoRouteTicketStore, SsoEphemeralError};
use super::saml::{SamlError, SamlRuntime, SamlStart};
use super::store::{DynamicSsoStore, DynamicSsoStoreError, LoadedDynamicProvider};
use super::vault::SsoConfigVault;
use crate::auth::oidc::attempt::ProviderIncarnationBinding;
use crate::auth::oidc::coordinator::{DEFAULT_IDP_TIMEOUT, DEFAULT_METADATA_MAX_BYTES};
use crate::auth::oidc::redirect::HTTPS_OR_HTTP;
use crate::auth::oidc::{
    CanonicalRedirectUri, FetchBudget, OidcLoginCoordinator, OidcLoginError, OidcProviderConfig,
    OidcProviderRuntime, PostgresLoginAttemptStore, PostgresOidcRateLimiter,
    PostgresOidcSessionIssuer, ProviderId, ProviderKind, ProviderOrigin, RateLimitPolicy,
};
use crate::net::safe_http::SafeDialer;

const ROUTE_TTL: Duration = Duration::minutes(2);
const SAML_ATTEMPT_TTL: Duration = Duration::minutes(10);
const EMAIL_ROUTE_RATE: RateLimitPolicy = RateLimitPolicy::new(20, Duration::minutes(1));
const SAML_CALLBACK_RATE: RateLimitPolicy = RateLimitPolicy::new(60, Duration::minutes(1));
const EPHEMERAL_CAPACITY: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum DynamicSsoError {
    #[error(transparent)]
    Config(#[from] SsoConfigError),
    #[error(transparent)]
    Store(#[from] DynamicSsoStoreError),
    #[error(transparent)]
    Ephemeral(#[from] SsoEphemeralError),
    #[error(transparent)]
    Oidc(#[from] OidcLoginError),
    #[error(transparent)]
    Saml(#[from] SamlError),
    #[error("dynamic_sso_provider_unknown")]
    ProviderUnknown,
    #[error("dynamic_sso_protocol_mismatch")]
    ProtocolMismatch,
    #[error("dynamic_sso_route_not_found")]
    RouteNotFound,
    #[error("dynamic_sso_rate_limited")]
    RateLimited,
}

impl DynamicSsoError {
    pub fn dependency_unavailable(&self) -> bool {
        match self {
            Self::Store(
                DynamicSsoStoreError::DependencyUnavailable
                | DynamicSsoStoreError::VaultUnavailable
                | DynamicSsoStoreError::Corrupt,
            )
            | Self::Ephemeral(
                SsoEphemeralError::DependencyUnavailable
                | SsoEphemeralError::Corrupt
                | SsoEphemeralError::RandomUnavailable,
            ) => true,
            Self::Oidc(error) => error.dependency_unavailable(),
            _ => false,
        }
    }

    pub fn provider_failure(&self) -> bool {
        matches!(self, Self::Oidc(error) if error.provider_failure())
    }

    pub fn conflict(&self) -> bool {
        matches!(
            self,
            Self::Store(
                DynamicSsoStoreError::ProviderConflict | DynamicSsoStoreError::DomainConflict
            )
        )
    }

    pub fn unknown(&self) -> bool {
        matches!(
            self,
            Self::ProviderUnknown
                | Self::Store(DynamicSsoStoreError::ProviderUnknown)
                | Self::RouteNotFound
        )
    }

    pub fn rate_limited(&self) -> bool {
        match self {
            Self::RateLimited | Self::Ephemeral(SsoEphemeralError::Full) => true,
            Self::Oidc(error) => error.rate_limited(),
            _ => false,
        }
    }

    /// SAML assertion ID 已在本 deployment/provider/issuer 作用域烧过。
    pub fn assertion_replayed(&self) -> bool {
        matches!(self, Self::Ephemeral(SsoEphemeralError::AssertionReplayed))
    }
}

pub enum DynamicSsoStart {
    Oidc(Url),
    Saml(SamlStart),
}

pub struct SsoRouteReceipt {
    ticket: String,
    expires_at: OffsetDateTime,
}

impl SsoRouteReceipt {
    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl core::fmt::Debug for SsoRouteReceipt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SsoRouteReceipt")
            .field("ticket", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

// The loaded row incarnation is DATA only; it does not replace Current/GuardedRC admission.
struct LoadedSamlRuntime {
    runtime: SamlRuntime,
    internal_id: Uuid,
}

#[derive(Clone)]
pub struct DynamicSsoService {
    store: DynamicSsoStore,
    routes: PostgresSsoRouteTicketStore,
    saml_attempts: PostgresSamlAttemptStore,
    oidc_attempts: PostgresLoginAttemptStore,
    sessions: PostgresOidcSessionIssuer,
    rate_limiter: PostgresOidcRateLimiter,
    dialer: SafeDialer,
    public_url: String,
}

impl DynamicSsoService {
    /// Borrow the actual immutable environment identities and pure Vault/configuration reader.
    /// This does not call discovery, the migrating loader, or a protocol health probe.
    #[must_use]
    pub fn capability_source(&self) -> super::store::ReadOnlySsoCapabilitySource {
        super::store::ReadOnlySsoCapabilitySource {
            store: self.store.clone(),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: Pool,
        tenant: &TenantId,
        ephemeral_key: impl Into<Vec<u8>>,
        session_key: impl Into<Vec<u8>>,
        audit_key: impl Into<Vec<u8>>,
        wrapping_key: WrappingKey,
        wrapping_key_version: KeyVersion,
        session_lifetime: SessionLifetimePolicy,
        admin_floor: AdminFloor,
        environment_provider_ids: impl IntoIterator<Item = String>,
        dialer: SafeDialer,
        public_url: String,
    ) -> Result<Self, DynamicSsoError> {
        let ephemeral_key = ephemeral_key.into();
        let session_key = session_key.into();
        let audit_key = audit_key.into();
        let vault = SsoConfigVault::single_key(tenant.clone(), wrapping_key_version, wrapping_key);
        let store = DynamicSsoStore::new(
            pool.clone(),
            vault,
            audit_key.clone(),
            environment_provider_ids,
        )?;
        Ok(Self {
            routes: PostgresSsoRouteTicketStore::new(
                pool.clone(),
                ephemeral_key.clone(),
                tenant,
                EPHEMERAL_CAPACITY,
                ROUTE_TTL,
            )?,
            saml_attempts: PostgresSamlAttemptStore::new(
                pool.clone(),
                ephemeral_key.clone(),
                tenant,
                EPHEMERAL_CAPACITY,
                SAML_ATTEMPT_TTL,
            )?,
            oidc_attempts: PostgresLoginAttemptStore::new(
                pool.clone(),
                ephemeral_key.clone(),
                tenant,
                EPHEMERAL_CAPACITY,
            )
            .map_err(OidcLoginError::from)?,
            sessions: PostgresOidcSessionIssuer::new(
                pool.clone(),
                session_key,
                session_lifetime,
                admin_floor,
                audit_key,
            )
            .map_err(OidcLoginError::from)?,
            rate_limiter: PostgresOidcRateLimiter::new(pool, ephemeral_key, tenant)
                .map_err(OidcLoginError::from)?,
            store,
            dialer,
            public_url,
        })
    }

    pub async fn has_any_provider(&self) -> Result<bool, DynamicSsoError> {
        Ok(!self.store.list().await?.is_empty())
    }

    /// 启动期逐条解密/迁移并执行协议 preflight；坏一条就拒绝宣称认证可用。
    pub async fn preflight_all(&self, now: OffsetDateTime) -> Result<(), DynamicSsoError> {
        for provider in self.store.list().await? {
            let id = ProviderId::parse(&provider.provider_id)
                .map_err(|_| DynamicSsoError::ProviderUnknown)?;
            match provider.protocol {
                SsoProtocol::Oidc => {
                    self.load_oidc_runtime(&id)
                        .await?
                        .ok_or(DynamicSsoError::ProviderUnknown)?;
                }
                SsoProtocol::Saml => {
                    self.load_saml_runtime(&id, now)
                        .await?
                        .ok_or(DynamicSsoError::ProviderUnknown)?;
                }
            }
        }
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<RegisteredIdentityProvider>, DynamicSsoError> {
        self.store.list().await.map_err(Into::into)
    }

    /// Tenant Package audience 校验所需的非 secret provider/mapping 投影。
    pub async fn group_audience_inputs(
        &self,
    ) -> Result<(Vec<IdentityProviderId>, Vec<IdpGroupMapping>), DynamicSsoError> {
        let mut providers = Vec::new();
        let mut mappings = Vec::new();
        for provider in self.store.list().await? {
            let id = ProviderId::parse(&provider.provider_id)
                .map_err(|_| DynamicSsoError::ProviderUnknown)?;
            let loaded = self
                .store
                .load(&id)
                .await?
                .ok_or(DynamicSsoError::ProviderUnknown)?;
            let mapping = match loaded.config {
                DecodedSecretConfig::Oidc(config) => config.mapping(&id)?,
                DecodedSecretConfig::Saml(config) => config.mapping(&id)?,
            };
            providers.push(IdentityProviderId::new(id.as_str()));
            mappings.extend(mapping);
        }
        providers.sort_unstable();
        providers.dedup();
        mappings.sort_by(|left, right| left.provider().cmp(right.provider()));
        mappings.dedup_by(|left, right| left.provider() == right.provider());
        Ok((providers, mappings))
    }

    pub async fn register(
        &self,
        input: RegisterIdentityProviderInput,
        actor: &ActorId,
        now: OffsetDateTime,
    ) -> Result<RegisteredIdentityProvider, DynamicSsoError> {
        let plan = RegistrationPlan::parse(input)?;
        self.preflight(&plan, actor, now).await?;
        self.store.register(&plan, actor).await.map_err(Into::into)
    }

    pub async fn update(
        &self,
        input: RegisterIdentityProviderInput,
        actor: &ActorId,
        now: OffsetDateTime,
    ) -> Result<RegisteredIdentityProvider, DynamicSsoError> {
        let plan = RegistrationPlan::parse(input)?;
        self.preflight(&plan, actor, now).await?;
        self.store.update(&plan, actor).await.map_err(Into::into)
    }

    pub async fn remove(
        &self,
        provider: &ProviderId,
        actor: &ActorId,
    ) -> Result<(), DynamicSsoError> {
        self.store.remove(provider, actor).await.map_err(Into::into)
    }

    /// IP/email 两桶都先推进；命中/未命中都只返回同长度一次性 ticket。
    pub async fn route_email(
        &self,
        email: &str,
        peer_ip: &str,
        now: OffsetDateTime,
    ) -> Result<SsoRouteReceipt, DynamicSsoError> {
        let normalized_email = (email.len() <= 512)
            .then(|| openbot_domain::identity::email::NormalizedEmail::normalize(email).ok())
            .flatten();
        let email_bucket = normalized_email
            .as_ref()
            .map_or("<invalid-email>", |value| value.as_str());
        let ip_allowed = self
            .rate_limiter
            .evaluate(
                crate::auth::oidc::OidcRateLimitBucket::EmailRouteIp,
                peer_ip,
                EMAIL_ROUTE_RATE,
                now,
            )
            .await
            .map_err(OidcLoginError::from)?
            .allowed();
        let email_allowed = self
            .rate_limiter
            .evaluate(
                crate::auth::oidc::OidcRateLimitBucket::EmailRouteEmail,
                email_bucket,
                EMAIL_ROUTE_RATE,
                now,
            )
            .await
            .map_err(OidcLoginError::from)?
            .allowed();
        let routed = if ip_allowed && email_allowed {
            if let Some(domain) = normalized_email
                .as_ref()
                .and_then(|email| crate::auth::oidc::email::domain_of(email.as_str()))
            {
                match self.store.find_provider_for_domain(&domain).await? {
                    Some(provider) => self
                        .store
                        .load(&provider)
                        .await?
                        .map(|loaded| {
                            (provider, protocol_of(&loaded.config), loaded.internal_id)
                        }),
                    None => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        let ticket = self
            .routes
            .issue(
                routed
                    .as_ref()
                    .map(|(provider, protocol, internal_id)| (provider, *protocol, *internal_id)),
                now,
            )
            .await?;
        Ok(SsoRouteReceipt {
            ticket,
            expires_at: now + ROUTE_TTL,
        })
    }

    pub async fn continue_route(
        &self,
        ticket: &str,
        peer_ip: &str,
        now: OffsetDateTime,
    ) -> Result<DynamicSsoStart, DynamicSsoError> {
        let routed = self
            .routes
            .consume(ticket, now)
            .await?
            .ok_or(DynamicSsoError::RouteNotFound)?;
        match routed.protocol {
            SsoProtocol::Oidc => {
                let runtime = self
                    .load_oidc_runtime_bound(&routed.provider_id, routed.internal_id)
                    .await?
                    .ok_or(DynamicSsoError::ProviderUnknown)?;
                let coordinator = self.oidc_coordinator([runtime])?;
                coordinator
                    .start(&routed.provider_id, now, peer_ip)
                    .await
                    .map(DynamicSsoStart::Oidc)
                    .map_err(Into::into)
            }
            SsoProtocol::Saml => {
                let runtime = self
                    .load_saml_runtime(&routed.provider_id, now)
                    .await?
                    .ok_or(DynamicSsoError::ProviderUnknown)?;
                if runtime.internal_id != routed.internal_id {
                    return Err(SsoEphemeralError::Mismatch.into());
                }
                let request_id = SamlRuntime::fresh_request_id();
                let relay_state = self
                    .saml_attempts
                    .issue(
                        &routed.provider_id,
                        runtime.internal_id,
                        &request_id,
                        runtime.runtime.acs_url(),
                        now,
                    )
                    .await?;
                runtime
                    .runtime
                    .begin(request_id, relay_state, now)
                    .map(DynamicSsoStart::Saml)
                    .map_err(Into::into)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oidc_callback(
        &self,
        provider: &ProviderId,
        state: &str,
        code: &str,
        now: OffsetDateTime,
        peer_ip: &str,
        user_agent: Option<&str>,
    ) -> Result<crate::auth::oidc::IssuedSession, DynamicSsoError> {
        let coordinator = self.oidc_coordinator([])?;
        let attempt = coordinator
            .begin_callback(provider, state, now, peer_ip)
            .await?;
        let ProviderIncarnationBinding::Dynamic {
            provider_internal_id,
        } = attempt.incarnation()
        else {
            return Err(SsoEphemeralError::Mismatch.into());
        };
        let runtime = self
            .load_oidc_runtime_bound(provider, provider_internal_id)
            .await?
            .ok_or(DynamicSsoError::ProviderUnknown)?;
        let callback = dynamic_oidc_callback(&self.public_url, provider)?;
        coordinator
            .finish_callback(
                &runtime,
                attempt,
                code,
                callback.as_str(),
                now,
                peer_ip,
                user_agent,
            )
            .await
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn saml_callback(
        &self,
        provider: &ProviderId,
        relay_state: &str,
        encoded_response: &str,
        now: OffsetDateTime,
        peer_ip: &str,
        user_agent: Option<&str>,
    ) -> Result<crate::auth::oidc::IssuedSession, DynamicSsoError> {
        if !self
            .rate_limiter
            .evaluate(
                crate::auth::oidc::OidcRateLimitBucket::CallbackIp,
                peer_ip,
                SAML_CALLBACK_RATE,
                now,
            )
            .await
            .map_err(OidcLoginError::from)?
            .allowed()
        {
            return Err(DynamicSsoError::RateLimited);
        }
        // RelayState 必须先烧；provider 删除、metadata 坏、签名错都不允许重试同一 request。
        let attempt = self
            .saml_attempts
            .consume(relay_state, provider, now)
            .await?;
        let runtime = self
            .load_saml_runtime(provider, now)
            .await?
            .ok_or(DynamicSsoError::ProviderUnknown)?;
        if runtime.internal_id != attempt.internal_id {
            return Err(SsoEphemeralError::Mismatch.into());
        }
        let verified = runtime.runtime.verify_response(
            encoded_response,
            &attempt.request_id,
            &attempt.acs_url,
            now,
        )?;
        self.saml_attempts
            .burn_assertion(
                provider,
                &verified.issuer,
                &verified.assertion_id,
                verified.assertion_expires_at,
                now,
            )
            .await?;
        self.sessions
            .issue_federated(
                &verified.identity,
                &verified.provider,
                now,
                Some(peer_ip),
                user_agent,
            )
            .await
            .map_err(OidcLoginError::from)
            .map_err(Into::into)
    }

    pub async fn saml_metadata(
        &self,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Result<String, DynamicSsoError> {
        self.load_saml_runtime(provider, now)
            .await?
            .ok_or(DynamicSsoError::ProviderUnknown)?
            .runtime
            .metadata_xml()
            .map_err(Into::into)
    }

    async fn preflight(
        &self,
        plan: &RegistrationPlan,
        actor: &ActorId,
        now: OffsetDateTime,
    ) -> Result<(), DynamicSsoError> {
        match plan {
            RegistrationPlan::Oidc {
                provider_id,
                issuer,
                domains,
                config,
            } => {
                let public = OidcProviderConfig::new(
                    provider_id.clone(),
                    ProviderKind::DeploymentOwned {
                        issuer: issuer.clone(),
                    },
                    ProviderOrigin::DynamicallyRegistered,
                    ClientId::new(config.client_id.clone()),
                    dynamic_oidc_callback(&self.public_url, provider_id)?,
                    domains.clone(),
                    Some(actor.as_str().to_owned()),
                );
                // Registration has no committed row incarnation and returns no login runtime.
                OidcProviderRuntime::validate_registration(
                    &public,
                    config.mapping(provider_id)?,
                    &self.dialer,
                    FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT),
                )
                .await
                .map_err(OidcLoginError::from)?;
            }
            RegistrationPlan::Saml {
                provider_id,
                issuer,
                domains,
                config,
            } => {
                SamlRuntime::build(
                    provider_id.clone(),
                    issuer.as_str(),
                    domains.clone(),
                    SamlSecretConfigCopy::copy(config),
                    &self.public_url,
                    now,
                )?;
            }
        }
        Ok(())
    }

    async fn load_oidc_runtime(
        &self,
        provider: &ProviderId,
    ) -> Result<Option<OidcProviderRuntime>, DynamicSsoError> {
        let Some(loaded) = self.store.load(provider).await? else {
            return Ok(None);
        };
        self.discover_loaded_oidc(loaded).await.map(Some)
    }

    async fn load_oidc_runtime_bound(
        &self,
        provider: &ProviderId,
        expected_incarnation: Uuid,
    ) -> Result<Option<OidcProviderRuntime>, DynamicSsoError> {
        if expected_incarnation.is_nil() {
            return Err(SsoEphemeralError::Mismatch.into());
        }
        let Some(loaded) = self.store.load(provider).await? else {
            return Ok(None);
        };
        // This DATA comparison precedes discovery; the same-transaction Current gate is separate.
        if loaded.internal_id != expected_incarnation {
            return Err(SsoEphemeralError::Mismatch.into());
        }
        self.discover_loaded_oidc(loaded).await.map(Some)
    }

    async fn discover_loaded_oidc(
        &self,
        loaded: LoadedDynamicProvider,
    ) -> Result<OidcProviderRuntime, DynamicSsoError> {
        let DecodedSecretConfig::Oidc(config) = loaded.config else {
            return Err(DynamicSsoError::ProtocolMismatch);
        };
        let mapping = config.mapping(&loaded.provider_id)?;
        let issuer = validated_issuer(&loaded.issuer)?;
        let public = OidcProviderConfig::new(
            loaded.provider_id.clone(),
            ProviderKind::DeploymentOwned { issuer },
            ProviderOrigin::DynamicallyRegistered,
            ClientId::new(config.client_id.clone()),
            dynamic_oidc_callback(&self.public_url, &loaded.provider_id)?,
            loaded.domains,
            loaded.registered_by,
        );
        OidcProviderRuntime::discover_bound(
            public,
            Some(config.client_secret),
            mapping,
            loaded.internal_id,
            &self.dialer,
            FetchBudget::new(DEFAULT_METADATA_MAX_BYTES, DEFAULT_IDP_TIMEOUT),
        )
        .await
        .map_err(OidcLoginError::from)
        .map_err(Into::into)
    }

    async fn load_saml_runtime(
        &self,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Result<Option<LoadedSamlRuntime>, DynamicSsoError> {
        let Some(loaded) = self.store.load(provider).await? else {
            return Ok(None);
        };
        let DecodedSecretConfig::Saml(config) = loaded.config else {
            return Err(DynamicSsoError::ProtocolMismatch);
        };
        let internal_id = loaded.internal_id;
        SamlRuntime::build(
            loaded.provider_id,
            loaded.issuer.as_str(),
            loaded.domains,
            config,
            &self.public_url,
            now,
        )
        .map(|runtime| {
            Some(LoadedSamlRuntime {
                runtime,
                internal_id,
            })
        })
        .map_err(|_| DynamicSsoStoreError::Corrupt.into())
    }

    fn oidc_coordinator(
        &self,
        runtimes: impl IntoIterator<Item = OidcProviderRuntime>,
    ) -> Result<OidcLoginCoordinator, DynamicSsoError> {
        OidcLoginCoordinator::new(
            runtimes,
            self.oidc_attempts.clone(),
            self.sessions.clone(),
            self.rate_limiter.clone(),
            self.dialer.clone(),
        )
        .map_err(OidcLoginError::from)
        .map_err(Into::into)
    }
}

impl core::fmt::Debug for DynamicSsoService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DynamicSsoService")
            .field("store", &self.store)
            .field("routes", &"PostgresSsoRouteTicketStore")
            .field("saml_attempts", &"PostgresSamlAttemptStore")
            .field("oidc_attempts", &self.oidc_attempts)
            .field("sessions", &self.sessions)
            .field("rate_limiter", &self.rate_limiter)
            .field("dialer", &self.dialer)
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

fn dynamic_oidc_callback(
    public_url: &str,
    provider: &ProviderId,
) -> Result<CanonicalRedirectUri, DynamicSsoError> {
    CanonicalRedirectUri::parse(
        &format!(
            "{}/api/auth/oidc/{}/callback",
            public_url.trim_end_matches('/'),
            provider.as_str()
        ),
        HTTPS_OR_HTTP,
    )
    .map_err(|_| SsoConfigError::EndpointRejected)
    .map_err(Into::into)
}

fn protocol_of(config: &DecodedSecretConfig) -> SsoProtocol {
    match config {
        DecodedSecretConfig::Oidc(_) => SsoProtocol::Oidc,
        DecodedSecretConfig::Saml(_) => SsoProtocol::Saml,
    }
}

/// preflight 不能取得计划内 secret 的所有权；SAML 配置没有 secret，显式复制可审计。
struct SamlSecretConfigCopy;

impl SamlSecretConfigCopy {
    fn copy(config: &super::config::SamlSecretConfig) -> super::config::SamlSecretConfig {
        super::config::SamlSecretConfig {
            entry_point: config.entry_point.clone(),
            metadata: config.metadata.clone(),
            email_attribute: config.email_attribute.clone(),
            group_attribute: config.group_attribute.clone(),
            group_normalization: config.group_normalization,
        }
    }
}
