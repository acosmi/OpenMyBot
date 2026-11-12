//! Vault credential repository（v3 §6.4）。
//!
//! 与普通表 CRUD 不同，本类型刻意没有物理 delete：撤销只写 `revoked_at`，轮换走
//! `(id, expected_key_id)` compare-and-swap，防止两个轮换者互相覆盖。密文本体仍由
//! `db::tables::credentials::Row` 的手写 Debug 脱敏；本层的错误只保留 SQLSTATE/标识符。

use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use openbot_contracts::ids::TenantId;
use openbot_domain::vault::{
    ColumnShape, DATA_KEY_BYTES, DataKey, EnvelopeV1, EnvelopeV2, KeyVersion, NONCE_BYTES, Nonce,
    RecordBinding, SecretBytes, SecretId, SecretKind, SecretPrincipal, WrappingKey,
    classify_column, decrypt_v1, open_v2, seal_v2,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::tables::credentials;
use crate::db::{InfraError, tables};
use crate::repo::common::{RepoCore, columns_sql};

/// `credentials.encrypted_value` 的 v1 兼容读与 v2 record-AEAD 写失败。
///
/// 错误刻意不保留密文、明文或底层密码库文案；调用方只需要知道是缺少密钥、密文被拒，
/// 还是 OS 随机源不可用。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CredentialVaultError {
    /// v2 信封声明的 KEK 版本不在当前进程可用集合中。
    #[error("credential_vault_key_unavailable")]
    KeyUnavailable,
    /// 信封结构、AAD 或认证标签不成立。
    #[error("credential_vault_ciphertext_rejected")]
    CiphertextRejected,
    /// `credentials` 表不允许历史明文；只有 SSO 配置列有该兼容形态。
    #[error("credential_vault_plaintext_rejected")]
    PlaintextRejected,
    /// OS CSPRNG 无法铸造 DEK/nonce。
    #[error("credential_vault_random_unavailable")]
    RandomUnavailable,
}

/// 一条已经解封、仍由 zeroize 容器持有的 credential。
#[derive(Debug)]
pub struct OpenedCredential {
    secret: SecretBytes,
    needs_migration: bool,
}

impl OpenedCredential {
    /// 是否来自 v1 信封，需要按 v3 §6.4 的有序迁移链转为 v2。
    #[must_use]
    pub const fn needs_migration(&self) -> bool {
        self.needs_migration
    }

    /// 把 zeroize 明文所有权交给唯一消费方。
    #[must_use]
    pub fn into_secret(self) -> SecretBytes {
        self.secret
    }
}

/// 单租户 credential record vault。
///
/// 当前构造器只接一代 KEK，忠实反映 Server KMS/HSM key ring 尚未闭合的事实；v2 信封若声明
/// 另一代密钥会明确返回 [`CredentialVaultError::KeyUnavailable`]，绝不尝试错误密钥或降级到
/// v1。`Arc` 只共享同一份受 zeroize 管理的 allocation，不复制密钥字节。
#[derive(Clone)]
pub struct CredentialRecordVault {
    tenant: TenantId,
    current_version: KeyVersion,
    key: Arc<WrappingKey>,
    #[cfg(test)]
    open_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl CredentialRecordVault {
    #[cfg(feature = "server-runtime")]
    pub(crate) fn matches_tenant(&self, tenant: &TenantId) -> bool {
        &self.tenant == tenant
    }
    /// 以当前单版本 KEK 构造；同一把 key 同时承担上游 v1 兼容读。
    #[must_use]
    pub fn single_key(tenant: TenantId, current_version: KeyVersion, key: WrappingKey) -> Self {
        Self {
            tenant,
            current_version,
            key: Arc::new(key),
            #[cfg(test)]
            open_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(crate) fn open_calls(&self) -> usize {
        self.open_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 以 v2 record AEAD 封装 credential 明文。
    ///
    /// # Errors
    ///
    /// OS 随机源不可用或领域 AEAD 拒绝输入时返回稳定、无载荷错误。
    pub fn seal(
        &self,
        secret_id: &Uuid,
        kind: SecretKind,
        owner: SecretPrincipal,
        consumer: SecretPrincipal,
        plaintext: &SecretBytes,
    ) -> Result<String, CredentialVaultError> {
        let data_key = random_data_key()?;
        let envelope = seal_v2(
            &self.key,
            &data_key,
            &self.binding(secret_id, kind, owner, consumer, self.current_version),
            random_nonce()?,
            random_nonce()?,
            plaintext.expose(),
        )
        .map_err(|_| CredentialVaultError::CiphertextRejected)?;
        Ok(envelope.to_column_value())
    }

    /// 解开上游 v1 或本项目 v2 credential 信封；credentials 历史明文一律拒绝。
    ///
    /// # Errors
    ///
    /// 信封结构/认证/AAD 不成立，或 v2 所需 KEK 版本不可用时返回稳定错误。
    pub fn open(
        &self,
        secret_id: &Uuid,
        kind: SecretKind,
        owner: SecretPrincipal,
        consumer: SecretPrincipal,
        stored: &str,
    ) -> Result<OpenedCredential, CredentialVaultError> {
        #[cfg(test)]
        self.open_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match classify_column(stored) {
            ColumnShape::Plaintext => Err(CredentialVaultError::PlaintextRejected),
            ColumnShape::LegacyEnvelope => {
                let envelope = EnvelopeV1::parse(stored)
                    .map_err(|_| CredentialVaultError::CiphertextRejected)?;
                let secret = decrypt_v1(&self.key, &envelope)
                    .map_err(|_| CredentialVaultError::CiphertextRejected)?;
                Ok(OpenedCredential {
                    secret,
                    needs_migration: true,
                })
            }
            ColumnShape::RecordEnvelope => {
                let envelope = EnvelopeV2::parse(stored)
                    .map_err(|_| CredentialVaultError::CiphertextRejected)?;
                let version = envelope.key_version();
                if version != self.current_version {
                    return Err(CredentialVaultError::KeyUnavailable);
                }
                let binding = self.binding(secret_id, kind, owner, consumer, version);
                let secret = open_v2(&self.key, &binding, &envelope)
                    .map_err(|_| CredentialVaultError::CiphertextRejected)?;
                Ok(OpenedCredential {
                    secret,
                    needs_migration: false,
                })
            }
        }
    }

    fn binding(
        &self,
        secret_id: &Uuid,
        kind: SecretKind,
        owner: SecretPrincipal,
        consumer: SecretPrincipal,
        version: KeyVersion,
    ) -> RecordBinding {
        RecordBinding::new(
            self.tenant.clone(),
            SecretId::new(secret_id.to_string()),
            kind,
            owner,
            consumer,
            version,
        )
    }
}

impl core::fmt::Debug for CredentialRecordVault {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialRecordVault")
            .field("tenant", &self.tenant)
            .field("current_version", &self.current_version)
            .field("key_material", &"<redacted>")
            .finish()
    }
}

fn random_data_key() -> Result<DataKey, CredentialVaultError> {
    let mut bytes = vec![0_u8; DATA_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| CredentialVaultError::RandomUnavailable)?;
    DataKey::from_bytes(bytes).map_err(|_| CredentialVaultError::RandomUnavailable)
}

fn random_nonce() -> Result<Nonce, CredentialVaultError> {
    let mut bytes = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| CredentialVaultError::RandomUnavailable)?;
    Ok(Nonce::from_array(bytes))
}

/// `credentials` 的行级 repository；跨 join/audit 的复合事务在 `crate::store` 收口。
#[derive(Clone)]
pub struct CredentialRepo {
    core: RepoCore<credentials::Row>,
}

impl CredentialRepo {
    /// 用调用方提供的池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            core: RepoCore::new(pool),
        }
    }

    /// 插入一份已经由领域 Vault 封装好的密文行。
    pub async fn insert(&self, row: &credentials::Row) -> Result<credentials::Row, InfraError> {
        self.core.insert(row).await
    }

    /// 按 id 读取（含已撤销，供审计/轮换恢复）。
    pub async fn find_by_id(&self, id: &Uuid) -> Result<Option<credentials::Row>, InfraError> {
        self.core.find("\"id\" = $1", &[&id]).await
    }

    /// 只读取未撤销凭据；已撤销与不存在对普通消费方同为 `None`。
    pub async fn find_active_by_id(
        &self,
        id: &Uuid,
    ) -> Result<Option<credentials::Row>, InfraError> {
        self.core
            .find("\"id\" = $1 AND \"revoked_at\" IS NULL", &[&id])
            .await
    }

    /// 稳定列出全部凭据元数据/密文行（Debug 仍脱敏）。
    pub async fn list_all(&self) -> Result<Vec<credentials::Row>, InfraError> {
        self.core.list("\"id\"").await
    }

    /// 撤销一次；不存在或已撤销返回 `None`，不会改写首次撤销时刻。
    pub async fn revoke(
        &self,
        id: &Uuid,
        revoked_at: OffsetDateTime,
    ) -> Result<Option<credentials::Row>, InfraError> {
        let sql = format!(
            "UPDATE public.credentials SET revoked_at=$2, updated_at=$2 \
             WHERE id=$1 AND revoked_at IS NULL RETURNING {}",
            columns_sql::<credentials::Row>(),
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 CredentialRepo 撤销获取连接", source))?;
        let row = client
            .query_opt(&sql, &[&id, &revoked_at])
            .await
            .map_err(|source| InfraError::query("撤销 credential", source))?;
        row.as_ref()
            .map(credentials::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }

    /// 用旧 key id 做 compare-and-swap 轮换；竞争失败返回 `None`，调用方必须重读后裁决。
    pub async fn rotate_if_current(
        &self,
        id: &Uuid,
        expected_key_id: &str,
        encrypted_value: &str,
        new_key_id: &str,
        metadata: &serde_json::Value,
        updated_at: OffsetDateTime,
    ) -> Result<Option<credentials::Row>, InfraError> {
        let sql = format!(
            "UPDATE public.credentials \
             SET encrypted_value=$3, key_id=$4, metadata=$5, updated_at=$6 \
             WHERE id=$1 AND key_id=$2 AND revoked_at IS NULL RETURNING {}",
            columns_sql::<tables::credentials::Row>(),
        );
        let client = self
            .core
            .pool()
            .get()
            .await
            .map_err(|source| InfraError::connect("为 CredentialRepo 轮换获取连接", source))?;
        let row = client
            .query_opt(
                &sql,
                &[
                    &id,
                    &expected_key_id,
                    &encrypted_value,
                    &new_key_id,
                    &metadata,
                    &updated_at,
                ],
            )
            .await
            .map_err(|source| InfraError::query("compare-and-swap 轮换 credential", source))?;
        row.as_ref()
            .map(credentials::Row::try_from)
            .transpose()
            .map_err(Into::into)
    }
}

impl core::fmt::Debug for CredentialRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialRepo").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::ActorId;
    use openbot_domain::vault::ServiceId;

    use super::*;

    fn vault() -> CredentialRecordVault {
        CredentialRecordVault::single_key(
            TenantId::new("tenant-1"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
        )
    }

    fn principals() -> (SecretPrincipal, SecretPrincipal) {
        (
            SecretPrincipal::Actor(ActorId::new("person-1")),
            SecretPrincipal::Service(ServiceId::new("drive")),
        )
    }

    #[test]
    fn v2_credential_is_bound_to_tenant_owner_consumer_kind_and_id() {
        let vault = vault();
        assert_eq!(vault.open_calls(), 0);
        let id = Uuid::new_v4();
        let (owner, consumer) = principals();
        let plaintext = SecretBytes::new(b"refresh-person-1".to_vec());
        let sealed = vault
            .seal(
                &id,
                SecretKind::McpUserToken,
                owner.clone(),
                consumer.clone(),
                &plaintext,
            )
            .unwrap();
        let opened = vault
            .open(
                &id,
                SecretKind::McpUserToken,
                owner.clone(),
                consumer.clone(),
                &sealed,
            )
            .unwrap();
        assert!(!opened.needs_migration());
        assert!(opened.into_secret().ct_eq(&plaintext));
        let cloned = vault.clone();
        let reopened = cloned
            .open(
                &id,
                SecretKind::McpUserToken,
                owner.clone(),
                consumer.clone(),
                &sealed,
            )
            .unwrap();
        assert!(reopened.into_secret().ct_eq(&plaintext));
        assert_eq!(vault.open_calls(), 2);
        assert_eq!(cloned.open_calls(), 2);

        for (candidate_id, candidate_owner, candidate_consumer, candidate_kind) in [
            (
                Uuid::new_v4(),
                owner.clone(),
                consumer.clone(),
                SecretKind::McpUserToken,
            ),
            (
                id,
                SecretPrincipal::Actor(ActorId::new("person-2")),
                consumer.clone(),
                SecretKind::McpUserToken,
            ),
            (
                id,
                owner.clone(),
                SecretPrincipal::Service(ServiceId::new("other")),
                SecretKind::McpUserToken,
            ),
            (id, owner.clone(), consumer.clone(), SecretKind::Mcp),
        ] {
            assert_eq!(
                vault
                    .open(
                        &candidate_id,
                        candidate_kind,
                        candidate_owner,
                        candidate_consumer,
                        &sealed,
                    )
                    .unwrap_err(),
                CredentialVaultError::CiphertextRejected,
            );
        }
    }

    #[test]
    fn credential_v1_is_compatible_but_plaintext_is_never_accepted() {
        const UPSTREAM_V1: &str = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
        let key: Vec<u8> = (0_u8..32).collect();
        let vault = CredentialRecordVault::single_key(
            TenantId::new("tenant-1"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(key).unwrap(),
        );
        let (owner, consumer) = principals();
        let opened = vault
            .open(
                &Uuid::new_v4(),
                SecretKind::McpUserToken,
                owner.clone(),
                consumer.clone(),
                UPSTREAM_V1,
            )
            .unwrap();
        assert!(opened.needs_migration());
        assert_eq!(opened.into_secret().expose(), b"sk-test-model-key-0001");
        assert_eq!(
            vault
                .open(
                    &Uuid::new_v4(),
                    SecretKind::McpUserToken,
                    owner,
                    consumer,
                    "refresh-in-plaintext",
                )
                .unwrap_err(),
            CredentialVaultError::PlaintextRejected,
        );
    }
}
