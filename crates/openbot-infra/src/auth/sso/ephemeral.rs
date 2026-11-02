//! email routing ticket、SAML RelayState/AuthnRequest 与 assertion replay 的 PG 一次性状态。

use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use openbot_contracts::ids::TenantId;
use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::config::SsoProtocol;
use crate::auth::oidc::ProviderId;

type HmacSha256 = Hmac<Sha256>;
const STORAGE_VERSION: u8 = 2;
const ROUTE_LOCK: i64 = 0x4f50_5353_4f52_5431; // `OPSSORT1`
const SAML_LOCK: i64 = 0x4f50_5341_4d4c_4131; // `OPSAMLA1`
const MAX_VALUE_BYTES: usize = 16 * 1024;
// SAML profile 最长 10 分钟，加 IdP future skew 与 expiry grace 各 2 分钟。
const MAX_ASSERTION_REPLAY_RETENTION: Duration = Duration::minutes(14);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SsoEphemeralError {
    #[error("sso_ephemeral_dependency_unavailable")]
    DependencyUnavailable,
    #[error("sso_ephemeral_state_corrupt")]
    Corrupt,
    #[error("sso_ephemeral_state_unknown")]
    Unknown,
    #[error("sso_ephemeral_state_expired")]
    Expired,
    #[error("sso_ephemeral_state_mismatch")]
    Mismatch,
    #[error("sso_ephemeral_store_full")]
    Full,
    #[error("sso_ephemeral_random_unavailable")]
    RandomUnavailable,
    #[error("saml_assertion_replayed")]
    AssertionReplayed,
}

#[derive(Clone)]
struct EphemeralCore {
    pool: Pool,
    hash_key: Arc<SecretBytes>,
    tenant_scope: String,
}

impl EphemeralCore {
    fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        tenant: &TenantId,
    ) -> Result<Self, SsoEphemeralError> {
        let hash_key = hash_key.into();
        if hash_key.is_empty() {
            return Err(SsoEphemeralError::Corrupt);
        }
        let tenant_scope = hex(&Sha256::digest(
            [
                b"openbot-sso-ephemeral-tenant-v1\0".as_slice(),
                tenant.as_str().as_bytes(),
            ]
            .concat(),
        ));
        Ok(Self {
            pool,
            hash_key: Arc::new(SecretBytes::new(hash_key)),
            tenant_scope,
        })
    }

    fn identifier(&self, purpose: &str, raw: &str) -> Result<String, SsoEphemeralError> {
        if raw.is_empty() || raw.len() > 2048 || !raw.is_ascii() {
            return Err(SsoEphemeralError::Unknown);
        }
        let digest = self.mac(purpose, &[raw.as_bytes()])?;
        Ok(format!("{purpose}:{}:{}", self.tenant_scope, hex(&digest)))
    }

    fn mac(&self, purpose: &str, values: &[&[u8]]) -> Result<[u8; 32], SsoEphemeralError> {
        let mut mac = HmacSha256::new_from_slice(self.hash_key.expose())
            .map_err(|_| SsoEphemeralError::Corrupt)?;
        mac.update(b"openbot-sso-ephemeral-v1\0");
        mac.update(self.tenant_scope.as_bytes());
        mac.update(b"\0");
        mac.update(purpose.as_bytes());
        for value in values {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value);
        }
        Ok(mac.finalize().into_bytes().into())
    }
}

impl core::fmt::Debug for EphemeralCore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EphemeralCore")
            .field("hash_key", &"[REDACTED]")
            .field("tenant_scope", &self.tenant_scope)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRoute {
    version: u8,
    routing: StoredRouting,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredRouting {
    Unmatched {},
    Matched {
        provider_id: String,
        protocol: String,
        provider_internal_id: Uuid,
    },
}

pub(crate) struct RoutedProvider {
    pub provider_id: ProviderId,
    pub protocol: SsoProtocol,
    pub internal_id: Uuid,
}

#[derive(Clone)]
pub(crate) struct PostgresSsoRouteTicketStore {
    core: EphemeralCore,
    capacity: usize,
    ttl: Duration,
}

impl PostgresSsoRouteTicketStore {
    pub(crate) fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        tenant: &TenantId,
        capacity: usize,
        ttl: Duration,
    ) -> Result<Self, SsoEphemeralError> {
        if capacity == 0 || ttl <= Duration::ZERO {
            return Err(SsoEphemeralError::Corrupt);
        }
        Ok(Self {
            core: EphemeralCore::new(pool, hash_key, tenant)?,
            capacity,
            ttl,
        })
    }

    /// 命中与未命中都铸造同长度 ticket，外部响应无法携带 routing bit。
    pub(crate) async fn issue(
        &self,
        routed: Option<(&ProviderId, SsoProtocol, Uuid)>,
        now: OffsetDateTime,
    ) -> Result<String, SsoEphemeralError> {
        let routing = match routed {
            None => StoredRouting::Unmatched {},
            Some((provider, protocol, provider_internal_id)) => {
                if provider_internal_id.is_nil() {
                    return Err(SsoEphemeralError::Corrupt);
                }
                StoredRouting::Matched {
                    provider_id: provider.as_str().to_owned(),
                    protocol: protocol_name(protocol).to_owned(),
                    provider_internal_id,
                }
            }
        };
        let ticket = random_token()?;
        let identifier = self.core.identifier("sso-route", &ticket)?;
        let expires_at = now + self.ttl;
        let value = serde_json::to_string(&StoredRoute {
            version: STORAGE_VERSION,
            routing,
            expires_at: expires_at.unix_timestamp(),
        })
        .map_err(|_| SsoEphemeralError::Corrupt)?;
        insert_bounded(
            &self.core,
            ROUTE_LOCK,
            "sso-route:",
            &identifier,
            &value,
            expires_at,
            now,
            self.capacity,
        )
        .await?;
        Ok(ticket)
    }

    pub(crate) async fn consume(
        &self,
        ticket: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RoutedProvider>, SsoEphemeralError> {
        let identifier = self.core.identifier("sso-route", ticket)?;
        let value = consume_value(&self.core, &identifier).await?;
        let stored: StoredRoute = decode(&value)?;
        if stored.version != STORAGE_VERSION {
            return Err(SsoEphemeralError::Corrupt);
        }
        if now.unix_timestamp() >= stored.expires_at {
            return Err(SsoEphemeralError::Expired);
        }
        match stored.routing {
            StoredRouting::Unmatched {} => Ok(None),
            StoredRouting::Matched {
                provider_id,
                protocol,
                provider_internal_id,
            } => {
                if provider_internal_id.is_nil() {
                    return Err(SsoEphemeralError::Corrupt);
                }
                Ok(Some(RoutedProvider {
                    provider_id: ProviderId::parse(&provider_id)
                        .map_err(|_| SsoEphemeralError::Corrupt)?,
                    protocol: parse_protocol(&protocol)?,
                    internal_id: provider_internal_id,
                }))
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSamlAttempt {
    version: u8,
    provider_id: String,
    provider_internal_id: Uuid,
    request_id: String,
    acs_url: String,
    expires_at: i64,
}

pub(crate) struct ConsumedSamlAttempt {
    pub internal_id: Uuid,
    pub request_id: String,
    pub acs_url: String,
}

#[derive(Clone)]
pub(crate) struct PostgresSamlAttemptStore {
    core: EphemeralCore,
    capacity: usize,
    ttl: Duration,
}

impl PostgresSamlAttemptStore {
    pub(crate) fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        tenant: &TenantId,
        capacity: usize,
        ttl: Duration,
    ) -> Result<Self, SsoEphemeralError> {
        if capacity == 0 || ttl <= Duration::ZERO {
            return Err(SsoEphemeralError::Corrupt);
        }
        Ok(Self {
            core: EphemeralCore::new(pool, hash_key, tenant)?,
            capacity,
            ttl,
        })
    }

    pub(crate) async fn issue(
        &self,
        provider: &ProviderId,
        provider_internal_id: Uuid,
        request_id: &str,
        acs_url: &str,
        now: OffsetDateTime,
    ) -> Result<String, SsoEphemeralError> {
        if provider_internal_id.is_nil()
            || request_id.is_empty()
            || request_id.len() > 512
            || !request_id.is_ascii()
        {
            return Err(SsoEphemeralError::Corrupt);
        }
        let relay_state = random_token()?;
        let identifier = self.core.identifier("saml-attempt", &relay_state)?;
        let expires_at = now + self.ttl;
        let value = serde_json::to_string(&StoredSamlAttempt {
            version: STORAGE_VERSION,
            provider_id: provider.as_str().to_owned(),
            provider_internal_id,
            request_id: request_id.to_owned(),
            acs_url: acs_url.to_owned(),
            expires_at: expires_at.unix_timestamp(),
        })
        .map_err(|_| SsoEphemeralError::Corrupt)?;
        insert_bounded(
            &self.core,
            SAML_LOCK,
            "saml-attempt:",
            &identifier,
            &value,
            expires_at,
            now,
            self.capacity,
        )
        .await?;
        Ok(relay_state)
    }

    pub(crate) async fn consume(
        &self,
        relay_state: &str,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Result<ConsumedSamlAttempt, SsoEphemeralError> {
        let identifier = self.core.identifier("saml-attempt", relay_state)?;
        let value = consume_value(&self.core, &identifier).await?;
        let stored: StoredSamlAttempt = decode(&value)?;
        if stored.version != STORAGE_VERSION {
            return Err(SsoEphemeralError::Corrupt);
        }
        if now.unix_timestamp() >= stored.expires_at {
            return Err(SsoEphemeralError::Expired);
        }
        if stored.provider_id != provider.as_str() {
            return Err(SsoEphemeralError::Mismatch);
        }
        if stored.provider_internal_id.is_nil() {
            return Err(SsoEphemeralError::Corrupt);
        }
        Ok(ConsumedSamlAttempt {
            internal_id: stored.provider_internal_id,
            request_id: stored.request_id,
            acs_url: stored.acs_url,
        })
    }

    /// 签名/issuer/profile 全过后、签 session 前占用 assertion ID；失败同样保持已烧状态。
    pub(crate) async fn burn_assertion(
        &self,
        provider: &ProviderId,
        issuer: &str,
        assertion_id: &str,
        assertion_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), SsoEphemeralError> {
        if assertion_id.is_empty()
            || assertion_id.len() > 1024
            || assertion_id.chars().any(char::is_control)
        {
            return Err(SsoEphemeralError::Corrupt);
        }
        if assertion_expires_at <= now {
            return Err(SsoEphemeralError::Expired);
        }
        if assertion_expires_at > now + MAX_ASSERTION_REPLAY_RETENTION {
            return Err(SsoEphemeralError::Corrupt);
        }
        let digest = self.core.mac(
            "saml-assertion",
            &[
                provider.as_str().as_bytes(),
                issuer.as_bytes(),
                assertion_id.as_bytes(),
            ],
        )?;
        let id = format!("saml-replay:{}:{}", self.core.tenant_scope, hex(&digest));
        let expires_at = assertion_expires_at;
        let client = self
            .core
            .pool
            .get()
            .await
            .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
        client
            .execute(
                "DELETE FROM public.verifications WHERE id IN ( \
                   SELECT id FROM public.verifications \
                   WHERE identifier='saml-assertion-replay' AND expires_at <= $1 LIMIT 100)",
                &[&now],
            )
            .await
            .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
        let inserted = client
            .execute(
                "INSERT INTO public.verifications(id,identifier,value,expires_at,created_at,updated_at) \
                 VALUES($1,'saml-assertion-replay','burned',$2,$3,$3) ON CONFLICT(id) DO NOTHING",
                &[&id, &expires_at, &now],
            )
            .await
            .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
        if inserted == 1 {
            Ok(())
        } else {
            Err(SsoEphemeralError::AssertionReplayed)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_bounded(
    core: &EphemeralCore,
    lock: i64,
    prefix: &str,
    identifier: &str,
    value: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
    capacity: usize,
) -> Result<(), SsoEphemeralError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(SsoEphemeralError::Corrupt);
    }
    let mut client = core
        .pool
        .get()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    let transaction = client
        .transaction()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock])
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    let like = format!("{prefix}{}:%", core.tenant_scope);
    transaction
        .execute(
            "DELETE FROM public.verifications WHERE identifier LIKE $1 AND expires_at <= $2",
            &[&like, &now],
        )
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    let count: i64 = transaction
        .query_one(
            "SELECT count(*)::bigint FROM public.verifications WHERE identifier LIKE $1",
            &[&like],
        )
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?
        .try_get(0)
        .map_err(|_| SsoEphemeralError::Corrupt)?;
    if usize::try_from(count).map_err(|_| SsoEphemeralError::Corrupt)? >= capacity {
        return Err(SsoEphemeralError::Full);
    }
    let id = Uuid::now_v7().to_string();
    transaction
        .execute(
            "INSERT INTO public.verifications(id,identifier,value,expires_at,created_at,updated_at) \
             VALUES($1,$2,$3,$4,$5,$5)",
            &[&id, &identifier, &value, &expires_at, &now],
        )
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)
}

async fn consume_value(
    core: &EphemeralCore,
    identifier: &str,
) -> Result<String, SsoEphemeralError> {
    let mut client = core
        .pool
        .get()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    let transaction = client
        .transaction()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    let rows = transaction
        .query(
            "DELETE FROM public.verifications WHERE identifier=$1 RETURNING value",
            &[&identifier],
        )
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| SsoEphemeralError::DependencyUnavailable)?;
    match rows.as_slice() {
        [] => Err(SsoEphemeralError::Unknown),
        [row] => row.try_get(0).map_err(|_| SsoEphemeralError::Corrupt),
        _ => Err(SsoEphemeralError::Corrupt),
    }
}

fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, SsoEphemeralError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(SsoEphemeralError::Corrupt);
    }
    serde_json::from_str(value).map_err(|_| SsoEphemeralError::Corrupt)
}

fn random_token() -> Result<String, SsoEphemeralError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| SsoEphemeralError::RandomUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

const fn protocol_name(protocol: SsoProtocol) -> &'static str {
    match protocol {
        SsoProtocol::Oidc => "oidc",
        SsoProtocol::Saml => "saml",
    }
}

fn parse_protocol(value: &str) -> Result<SsoProtocol, SsoEphemeralError> {
    match value {
        "oidc" => Ok(SsoProtocol::Oidc),
        "saml" => Ok(SsoProtocol::Saml),
        _ => Err(SsoEphemeralError::Corrupt),
    }
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names_are_closed_and_tokens_have_fixed_entropy_shape() {
        assert_eq!(protocol_name(SsoProtocol::Oidc), "oidc");
        assert_eq!(parse_protocol("saml").unwrap(), SsoProtocol::Saml);
        assert_eq!(parse_protocol("SAML"), Err(SsoEphemeralError::Corrupt));
        let token = random_token().unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}
