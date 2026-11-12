//! PostgreSQL-backed OIDC login attempt store。
//!
//! `verifications` 是 0012 已有的短期一次性 secret 表。本 adapter 用 keyed state hash 做
//! identifier，value 只存私有 JSON 形态（表行 Debug 已全量脱敏），并以 `DELETE … RETURNING`
//! **先烧 state、再解析/校验**。因此 callback 落到任意 replica 都能继续；进程重启不丢；同一
//! state 并发最多一个成功；坏/过期/provider mismatch 同样不会留下可重试口子。

use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use hmac::{Hmac, Mac};
use openbot_contracts::ids::TenantId;
use openbot_domain::vault::SecretBytes;
use openidconnect::{Nonce, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::attempt::{
    CallbackLoginAttempt, LoginAttempt, LoginAttemptStorageRecord, PKCE_METHOD_S256,
    ProviderIncarnationBinding,
};
use super::provider::ProviderId;
use super::redirect::{CanonicalRedirectUri, HTTPS_OR_HTTP};

type HmacSha256 = Hmac<Sha256>;

const ATTEMPT_LOCK_KEY: i64 = 0x4f50_4f49_4443_4131; // `OPOIDCA1`
const STORAGE_VERSION: u8 = 2;
const MAX_STORED_VALUE_BYTES: usize = 16 * 1024;

/// 持久化失败；无 URL/state/DB 原值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PostgresAttemptError {
    #[error("oidc_attempt_store_dependency_unavailable")]
    DependencyUnavailable,
    #[error("oidc_attempt_store_corrupt")]
    Corrupt,
    #[error("oidc_attempt_unknown")]
    Unknown,
    #[error("oidc_attempt_expired")]
    Expired,
    #[error("oidc_attempt_provider_mismatch")]
    ProviderMismatch,
    #[error("oidc_attempt_store_full")]
    Full,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttempt {
    version: u8,
    provider: String,
    binding: ProviderIncarnationBinding,
    nonce: String,
    pkce_verifier: String,
    pkce_method: String,
    redirect_uri: String,
    expires_at_unix_seconds: i64,
}

/// 多 replica 共用的一次性 store。
#[derive(Clone)]
pub struct PostgresLoginAttemptStore {
    pool: Pool,
    hash_key: Arc<SecretBytes>,
    tenant_scope: String,
    capacity: usize,
}

impl PostgresLoginAttemptStore {
    pub fn new(
        pool: Pool,
        hash_key: impl Into<Vec<u8>>,
        tenant: &TenantId,
        capacity: usize,
    ) -> Result<Self, PostgresAttemptError> {
        let hash_key = hash_key.into();
        if hash_key.is_empty() || capacity == 0 {
            return Err(PostgresAttemptError::Corrupt);
        }
        let tenant_scope = hex(&Sha256::digest(
            [
                b"openbot-oidc-attempt-tenant-v1\0".as_slice(),
                tenant.as_str().as_bytes(),
            ]
            .concat(),
        ));
        Ok(Self {
            pool,
            hash_key: Arc::new(SecretBytes::new(hash_key)),
            tenant_scope,
            capacity,
        })
    }

    /// 插入前在事务锁下清过期并执行容量上限。
    pub async fn insert(
        &self,
        attempt: LoginAttempt,
        now: OffsetDateTime,
    ) -> Result<(), PostgresAttemptError> {
        let record = attempt.into_storage_record();
        let identifier = self.identifier(&record.state)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(record.expires_at.unix_timestamp())
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        let value = encode_record(record)?;

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&ATTEMPT_LOCK_KEY])
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        let prefix = format!("oidc-attempt:{}:%", self.tenant_scope);
        transaction
            .execute(
                "DELETE FROM public.verifications WHERE identifier LIKE $1 AND expires_at <= $2",
                &[&prefix, &now],
            )
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        let count: i64 = transaction
            .query_one(
                "SELECT count(*)::bigint FROM public.verifications WHERE identifier LIKE $1",
                &[&prefix],
            )
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?
            .try_get(0)
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        let count = usize::try_from(count).map_err(|_| PostgresAttemptError::Corrupt)?;
        if count >= self.capacity {
            return Err(PostgresAttemptError::Full);
        }
        let id = Uuid::now_v7().to_string();
        transaction
            .execute(
                "INSERT INTO public.verifications(id,identifier,value,expires_at,created_at,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$5)",
                &[&id, &identifier, &value, &expires_at, &now],
            )
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)
    }

    /// 删除命中行并 commit 后才解析；任何后续失败都已经烧掉 state。
    pub async fn consume(
        &self,
        state: &str,
        provider: &ProviderId,
        now: OffsetDateTime,
    ) -> Result<CallbackLoginAttempt, PostgresAttemptError> {
        let identifier = self.identifier(state)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        let rows = transaction
            .query(
                "DELETE FROM public.verifications WHERE identifier=$1 RETURNING value,expires_at",
                &[&identifier],
            )
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| PostgresAttemptError::DependencyUnavailable)?;

        if rows.is_empty() {
            return Err(PostgresAttemptError::Unknown);
        }
        if rows.len() != 1 {
            return Err(PostgresAttemptError::Corrupt);
        }
        let value: String = rows[0]
            .try_get("value")
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        let column_expiry: OffsetDateTime = rows[0]
            .try_get("expires_at")
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        let stored = decode_record(&value)?;
        if stored.expires_at_unix_seconds != column_expiry.unix_timestamp() {
            return Err(PostgresAttemptError::Corrupt);
        }
        if now.unix_timestamp() >= stored.expires_at_unix_seconds {
            return Err(PostgresAttemptError::Expired);
        }
        let stored_provider =
            ProviderId::parse(&stored.provider).map_err(|_| PostgresAttemptError::Corrupt)?;
        if &stored_provider != provider {
            return Err(PostgresAttemptError::ProviderMismatch);
        }
        if stored.pkce_method != PKCE_METHOD_S256 || !valid_verifier(&stored.pkce_verifier) {
            return Err(PostgresAttemptError::Corrupt);
        }
        if stored.nonce.is_empty() || stored.nonce.len() > 512 || !stored.nonce.is_ascii() {
            return Err(PostgresAttemptError::Corrupt);
        }
        let redirect = CanonicalRedirectUri::parse(&stored.redirect_uri, HTTPS_OR_HTTP)
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        Ok(CallbackLoginAttempt::restore_bound(
            stored_provider,
            Nonce::new(stored.nonce),
            PkceCodeVerifier::new(stored.pkce_verifier),
            redirect,
            stored.binding,
        ))
    }

    fn identifier(&self, state: &str) -> Result<String, PostgresAttemptError> {
        if state.is_empty() || state.len() > 512 || !state.is_ascii() {
            return Err(PostgresAttemptError::Unknown);
        }
        let mut mac = HmacSha256::new_from_slice(self.hash_key.expose())
            .map_err(|_| PostgresAttemptError::Corrupt)?;
        mac.update(b"openbot-oidc-attempt-state-v1\0");
        mac.update(self.tenant_scope.as_bytes());
        mac.update(b"\0");
        mac.update(state.as_bytes());
        Ok(format!(
            "oidc-attempt:{}:{}",
            self.tenant_scope,
            hex(&mac.finalize().into_bytes())
        ))
    }
}

impl core::fmt::Debug for PostgresLoginAttemptStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresLoginAttemptStore")
            .field("hash_key", &"[REDACTED]")
            .field("tenant_scope", &self.tenant_scope)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

fn encode_record(record: LoginAttemptStorageRecord) -> Result<String, PostgresAttemptError> {
    if !record.incarnation.valid() {
        return Err(PostgresAttemptError::Corrupt);
    }
    let value = serde_json::to_string(&StoredAttempt {
        version: STORAGE_VERSION,
        provider: record.provider,
        binding: record.incarnation,
        nonce: record.nonce,
        pkce_verifier: record.pkce_verifier,
        pkce_method: record.pkce_method.to_owned(),
        redirect_uri: record.redirect_uri,
        expires_at_unix_seconds: record.expires_at.unix_timestamp(),
    })
    .map_err(|_| PostgresAttemptError::Corrupt)?;
    if value.len() > MAX_STORED_VALUE_BYTES {
        return Err(PostgresAttemptError::Corrupt);
    }
    Ok(value)
}

fn decode_record(value: &str) -> Result<StoredAttempt, PostgresAttemptError> {
    if value.len() > MAX_STORED_VALUE_BYTES {
        return Err(PostgresAttemptError::Corrupt);
    }
    let stored: StoredAttempt =
        serde_json::from_str(value).map_err(|_| PostgresAttemptError::Corrupt)?;
    if stored.version != STORAGE_VERSION || !stored.binding.valid() {
        return Err(PostgresAttemptError::Corrupt);
    }
    Ok(stored)
}

fn valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::redirect::HTTPS_ONLY;
    use time::Duration;

    #[test]
    fn stored_json_is_bounded_versioned_and_not_debuggable_through_public_types() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let attempt = LoginAttempt::begin(
            ProviderId::parse("okta").unwrap(),
            CanonicalRedirectUri::parse("https://app.example/callback", HTTPS_ONLY).unwrap(),
            now,
            Duration::minutes(10),
        );
        let record = attempt.into_storage_record();
        let value = encode_record(record).unwrap();
        let parsed = decode_record(&value).unwrap();
        assert_eq!(parsed.version, STORAGE_VERSION);
        assert_eq!(parsed.pkce_method, PKCE_METHOD_S256);
        assert!(valid_verifier(&parsed.pkce_verifier));
        assert!(!format!("{:?}", PostgresAttemptError::Corrupt).contains(&parsed.pkce_verifier));
    }

    #[test]
    fn verifier_shape_has_positive_and_negative_controls() {
        assert!(valid_verifier(&"a".repeat(43)));
        assert!(valid_verifier(&"Z-._~".repeat(10)));
        for bad in ["a".repeat(42), "a".repeat(129), "a/b".repeat(20)] {
            assert!(!valid_verifier(&bad));
        }
    }
}
