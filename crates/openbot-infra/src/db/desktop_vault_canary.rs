//! Read-only preflight and one-shot persistence for the Desktop dataset Vault canary.

use std::sync::Arc;
use std::time::Duration;

use crate::db::pool::DatabasePool as Pool;
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::vault::{
    DesktopVaultCanaryBinding, DesktopVaultCanaryEnvelope, KeyVersion, SecretBytes,
    open_desktop_vault_canary,
};

use super::desktop_local::DesktopLocalDatabase;
use super::schema_facts::SchemaFacts;
use super::{InfraError, RowDecodeError, native, schema_facts};

const TABLE: &str = "openbot_internal.desktop_vault_canaries";
const TIMEOUT: Duration = Duration::from_secs(10);
const PUBLIC_0031: &str = include_str!("../../../../fixtures/db/schema-0031.json");
const PUBLIC_0033: &str = include_str!("../../../../fixtures/db/schema-0033.json");
const PUBLIC_0034: &str = include_str!("../../../../fixtures/db/schema-0034.json");
const PUBLIC_0035: &str = include_str!("../../../../fixtures/db/schema-0035.json");
const PUBLIC_0036: &str = include_str!("../../../../fixtures/db/schema-0036.json");
const PUBLIC_0037: &str = include_str!("../../../../fixtures/db/schema-0037.json");
const PUBLIC_0039: &str = include_str!("../../../../fixtures/db/schema-0039.json");
const PUBLIC_0040: &str = include_str!("../../../../fixtures/db/schema-0040.json");
const PUBLIC_0046: &str = include_str!("../../../../fixtures/db/schema-0046.json");
const PUBLIC_0050: &str = include_str!("../../../../fixtures/db/schema-0050.json");
const PUBLIC_0051: &str = include_str!("../../../../fixtures/db/schema-0051.json");
const PUBLIC_0052: &str = include_str!("../../../../fixtures/db/schema-0052.json");
const PUBLIC_0038: &str = include_str!("../../../../fixtures/db/schema-0038.json");

#[derive(Debug, thiserror::Error)]
pub enum DesktopVaultCanaryError {
    #[error("desktop_vault_canary_database_unavailable")]
    Infra(#[source] InfraError),
    #[error("desktop_vault_canary_reconciliation_required")]
    ReconciliationRequired,
    #[error("desktop_vault_canary_material_invalid")]
    MaterialInvalid,
}

impl From<InfraError> for DesktopVaultCanaryError {
    fn from(error: InfraError) -> Self {
        Self::Infra(error)
    }
}

/// Exact immutable row stored for one dataset/master version.
pub struct DesktopVaultCanaryRow {
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    canary_schema: i16,
    encrypted_canary: String,
}

/// Cryptographic proof required by Desktop principal/package bootstrap.
pub struct VerifiedDesktopVaultCanary {
    database_owner: Arc<()>,
    system_identifier: String,
    database_oid: u32,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    encrypted_canary_digest: Sha256Digest,
}

/// Opaque catalogue enrollment from a verified canary and its actual Local DB owner.
#[cfg(feature = "server-runtime")]
pub struct VerifiedDesktopCustomModelCatalogProvenance {
    pool: Pool,
    system_identifier: String,
    database_oid: u32,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    encrypted_canary_digest: Sha256Digest,
}

#[cfg(feature = "server-runtime")]
impl VerifiedDesktopCustomModelCatalogProvenance {
    /// Compare the original actual manager and both verified namespace keys.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &openbot_contracts::ids::DeploymentId,
        tenant: &openbot_contracts::ids::TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && self.deployment_id == deployment.as_str()
            && self.tenant_id == tenant.as_str()
    }

    /// Installation equality alone does not grant current window or DB authority.
    #[must_use]
    pub fn matches_installation(
        &self,
        installation: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> bool {
        let auth = installation.auth_context();
        self.deployment_id == auth.deployment().as_str() && self.tenant_id == auth.tenant().as_str()
    }

    /// Compare the physical and cryptographic tuple decoded by the final actual SQL.
    pub(crate) fn matches_current_row(
        &self,
        row: &tokio_postgres::Row,
    ) -> Result<bool, RowDecodeError> {
        fn column<T: for<'a> tokio_postgres::types::FromSql<'a>>(
            row: &tokio_postgres::Row,
            name: &'static str,
        ) -> Result<Option<T>, RowDecodeError> {
            row.try_get(name)
                .map_err(|source| RowDecodeError::column(TABLE, name, source))
        }
        let encrypted: Option<String> = column(row, "catalog_canary_encrypted")?;
        Ok(
            column::<String>(row, "catalog_database_system_identifier")?.as_deref()
                == Some(self.system_identifier.as_str())
                && column::<u32>(row, "catalog_database_oid")? == Some(self.database_oid)
                && column::<String>(row, "catalog_canary_dataset")?.as_deref()
                    == Some(self.dataset_id.as_str())
                && column::<String>(row, "catalog_canary_deployment")?.as_deref()
                    == Some(self.deployment_id.as_str())
                && column::<String>(row, "catalog_canary_tenant")?.as_deref()
                    == Some(self.tenant_id.as_str())
                && column::<String>(row, "catalog_canary_key")?.as_deref()
                    == Some(self.key_id.as_str())
                && column::<i32>(row, "catalog_canary_key_version")? == Some(self.key_version)
                && column::<i16>(row, "catalog_canary_schema")? == Some(1)
                && encrypted.as_ref().is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 4096
                        && Sha256Digest::of(value.as_bytes()) == self.encrypted_canary_digest
                }),
        )
    }
}

/// Sealed same-database facts copied only from a verified canary and its actual Local DB owner.
/// This is neither an installation-string constructor nor an artifact authority.
pub struct VerifiedDesktopRememberPreferenceProvenance {
    pool: Pool,
    system_identifier: String,
    database_oid: u32,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    encrypted_canary_digest: Sha256Digest,
}
impl VerifiedDesktopRememberPreferenceProvenance {
    /// Exact original Pool manager and cryptographically verified namespace enrollment.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &openbot_contracts::ids::DeploymentId,
        tenant: &openbot_contracts::ids::TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && self.deployment_id == deployment.as_str()
            && self.tenant_id == tenant.as_str()
    }
    /// Compare the actual Local installation's namespace; this alone is not current authority.
    #[must_use]
    pub fn matches_installation(
        &self,
        installation: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> bool {
        let scope = installation.auth_context();
        self.deployment_id == scope.deployment().as_str()
            && self.tenant_id == scope.tenant().as_str()
    }
    /// Decode one actual repository statement and compare the original physical/canary tuple.
    pub fn matches_current_row(&self, row: &tokio_postgres::Row) -> Result<bool, RowDecodeError> {
        fn column<T: for<'a> tokio_postgres::types::FromSql<'a>>(
            row: &tokio_postgres::Row,
            name: &'static str,
        ) -> Result<Option<T>, RowDecodeError> {
            row.try_get(name)
                .map_err(|source| RowDecodeError::column(TABLE, name, source))
        }
        let encrypted: Option<String> = column(row, "preference_canary_encrypted")?;
        Ok(
            column::<String>(row, "preference_database_system_identifier")?.as_deref()
                == Some(self.system_identifier.as_str())
                && column::<u32>(row, "preference_database_oid")? == Some(self.database_oid)
                && column::<String>(row, "preference_canary_dataset")?.as_deref()
                    == Some(self.dataset_id.as_str())
                && column::<String>(row, "preference_canary_deployment")?.as_deref()
                    == Some(self.deployment_id.as_str())
                && column::<String>(row, "preference_canary_tenant")?.as_deref()
                    == Some(self.tenant_id.as_str())
                && column::<String>(row, "preference_canary_key")?.as_deref()
                    == Some(self.key_id.as_str())
                && column::<i32>(row, "preference_canary_key_version")? == Some(self.key_version)
                && column::<i16>(row, "preference_canary_schema")? == Some(1)
                && encrypted.as_ref().is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 4096
                        && Sha256Digest::of(value.as_bytes()) == self.encrypted_canary_digest
                }),
        )
    }
}

/// Sealed facts copied only from a cryptographically verified real Desktop database.
/// This is not a second proof constructor or a live host-owner lease.
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) struct VerifiedDesktopArtifactReadProvenance {
    system_identifier: String,
    database_oid: u32,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
    encrypted_canary_digest: Sha256Digest,
}

#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
impl VerifiedDesktopArtifactReadProvenance {
    pub(crate) fn matches_installation(
        &self,
        installation: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> bool {
        let scope = installation.auth_context();
        self.deployment_id == scope.deployment().as_str()
            && self.tenant_id == scope.tenant().as_str()
    }

    pub(crate) fn matches_current_row(
        &self,
        row: &tokio_postgres::Row,
    ) -> Result<bool, super::RowDecodeError> {
        fn column<T: for<'a> tokio_postgres::types::FromSql<'a>>(
            row: &tokio_postgres::Row,
            name: &'static str,
        ) -> Result<Option<T>, super::RowDecodeError> {
            row.try_get(name).map_err(|source| {
                super::RowDecodeError::column("desktop_vault_canaries", name, source)
            })
        }
        let encrypted: Option<String> = column(row, "read_canary_encrypted")?;
        Ok(
            column::<String>(row, "read_database_system_identifier")?.as_deref()
                == Some(self.system_identifier.as_str())
                && column::<u32>(row, "read_database_oid")? == Some(self.database_oid)
                && column::<String>(row, "read_canary_dataset")?.as_deref()
                    == Some(self.dataset_id.as_str())
                && column::<String>(row, "read_canary_deployment")?.as_deref()
                    == Some(self.deployment_id.as_str())
                && column::<String>(row, "read_canary_tenant")?.as_deref()
                    == Some(self.tenant_id.as_str())
                && column::<String>(row, "read_canary_key")?.as_deref()
                    == Some(self.key_id.as_str())
                && column::<i32>(row, "read_canary_key_version")? == Some(self.key_version)
                && column::<i16>(row, "read_canary_schema")? == Some(1)
                && encrypted.as_ref().is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 4096
                        && Sha256Digest::of(value.as_bytes()) == self.encrypted_canary_digest
                }),
        )
    }
}

/// Exact native/public layout observed before an existing Desktop dataset may verify its canary.
/// This read-only fact is not a migration, key-store, or business authority.
pub struct ValidatedDesktopVaultLayout {
    native_version: i32,
}

impl ValidatedDesktopVaultLayout {
    /// Highest native version whose ledger and registered public schema were verified exactly.
    #[must_use]
    pub const fn native_version(&self) -> i32 {
        self.native_version
    }
}

impl VerifiedDesktopVaultCanary {
    /// Copy sealed facts only for the exact original verified database owner token.
    #[cfg(feature = "server-runtime")]
    #[must_use]
    pub fn custom_model_catalog_provenance(
        &self,
        database: &DesktopLocalDatabase,
    ) -> Option<VerifiedDesktopCustomModelCatalogProvenance> {
        database.owns_token(&self.database_owner).then(|| {
            VerifiedDesktopCustomModelCatalogProvenance {
                pool: database.clone_pool(),
                system_identifier: self.system_identifier.clone(),
                database_oid: self.database_oid,
                dataset_id: self.dataset_id.clone(),
                deployment_id: self.deployment_id.clone(),
                tenant_id: self.tenant_id.clone(),
                key_id: self.key_id.clone(),
                key_version: self.key_version,
                encrypted_canary_digest: self.encrypted_canary_digest,
            }
        })
    }

    /// Copy only after this exact verified proof is bound to the actual Local database owner.
    /// Runtime repository observations must still recheck the tuple in their own transaction.
    #[doc(hidden)]
    #[must_use]
    pub fn remember_preference_provenance(
        &self,
        database: &DesktopLocalDatabase,
    ) -> Option<VerifiedDesktopRememberPreferenceProvenance> {
        database.owns_token(&self.database_owner).then(|| {
            VerifiedDesktopRememberPreferenceProvenance {
                pool: database.clone_pool(),
                system_identifier: self.system_identifier.clone(),
                database_oid: self.database_oid,
                dataset_id: self.dataset_id.clone(),
                deployment_id: self.deployment_id.clone(),
                tenant_id: self.tenant_id.clone(),
                key_id: self.key_id.clone(),
                key_version: self.key_version,
                encrypted_canary_digest: self.encrypted_canary_digest,
            }
        })
    }
    #[cfg(all(
        feature = "server-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    pub(crate) fn artifact_read_provenance(&self) -> VerifiedDesktopArtifactReadProvenance {
        VerifiedDesktopArtifactReadProvenance {
            system_identifier: self.system_identifier.clone(),
            database_oid: self.database_oid,
            dataset_id: self.dataset_id.clone(),
            deployment_id: self.deployment_id.clone(),
            tenant_id: self.tenant_id.clone(),
            key_id: self.key_id.clone(),
            key_version: self.key_version,
            encrypted_canary_digest: self.encrypted_canary_digest,
        }
    }
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn key_version(&self) -> i32 {
        self.key_version
    }

    pub(crate) async fn matches_database(
        &self,
        database: &DesktopLocalDatabase,
    ) -> Result<bool, DesktopVaultCanaryError> {
        if !database.owns_token(&self.database_owner) {
            return Ok(false);
        }
        let (system_identifier, database_oid) = database_identity(database.pool()).await?;
        if self.system_identifier != system_identifier || self.database_oid != database_oid {
            return Ok(false);
        }
        let Some(row) = read(database.pool(), &self.deployment_id, &self.tenant_id).await? else {
            return Ok(false);
        };
        Ok(row.dataset_id == self.dataset_id
            && row.deployment_id == self.deployment_id
            && row.tenant_id == self.tenant_id
            && row.key_id == self.key_id
            && row.key_version == self.key_version
            && row.canary_schema == 1
            && Sha256Digest::of(row.encrypted_canary.as_bytes()) == self.encrypted_canary_digest)
    }

    /// Recheck this already verified proof on the registry's owned Desktop transaction.
    /// The caller retains the current canary lock; no SQL value can construct this proof.
    pub(crate) async fn matches_transaction(
        &self,
        database: &DesktopLocalDatabase,
        transaction: &tokio_postgres::Transaction<'_>,
    ) -> Result<bool, DesktopVaultCanaryError> {
        if !database.owns_token(&self.database_owner) {
            return Ok(false);
        }
        let identity = transaction
            .query_one(
                "SELECT pcs.system_identifier::text,d.oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("核验成果 Desktop canary 数据库身份", source))?;
        let system_identifier: String = identity.try_get(0).map_err(|source| {
            InfraError::from(RowDecodeError::column(
                "(pg_control_system)",
                "system_identifier",
                source,
            ))
        })?;
        let database_oid: u32 = identity.try_get(1).map_err(|source| {
            InfraError::from(RowDecodeError::column("(pg_database)", "oid", source))
        })?;
        if system_identifier != self.system_identifier || database_oid != self.database_oid {
            return Ok(false);
        }
        let Some(row) = transaction
            .query_opt(
                "SELECT dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",
                &[&self.deployment_id, &self.tenant_id],
            )
            .await
            .map_err(|source| InfraError::query("核验成果当前 Desktop canary", source))?
        else {
            return Ok(false);
        };
        let row = decode_row(row)?;
        Ok(row.dataset_id == self.dataset_id
            && row.deployment_id == self.deployment_id
            && row.tenant_id == self.tenant_id
            && row.key_id == self.key_id
            && row.key_version == self.key_version
            && row.canary_schema == 1
            && Sha256Digest::of(row.encrypted_canary.as_bytes()) == self.encrypted_canary_digest)
    }
}

impl core::fmt::Debug for VerifiedDesktopVaultCanary {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedDesktopVaultCanary(<verified>)")
    }
}

impl core::fmt::Debug for ValidatedDesktopVaultLayout {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ValidatedDesktopVaultLayout")
            .field("native_version", &self.native_version)
            .finish()
    }
}

impl DesktopVaultCanaryRow {
    pub fn new(
        dataset_id: impl Into<String>,
        deployment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
        encrypted_canary: impl Into<String>,
    ) -> Result<Self, DesktopVaultCanaryError> {
        let row = Self {
            dataset_id: dataset_id.into(),
            deployment_id: deployment_id.into(),
            tenant_id: tenant_id.into(),
            key_id: key_id.into(),
            key_version: 1,
            canary_schema: 1,
            encrypted_canary: encrypted_canary.into(),
        };
        if !hex_id(&row.dataset_id)
            || !identity(&row.deployment_id)
            || !identity(&row.tenant_id)
            || !hex_id(&row.key_id)
            || row.encrypted_canary.is_empty()
            || row.encrypted_canary.len() > 4096
        {
            return Err(DesktopVaultCanaryError::ReconciliationRequired);
        }
        Ok(row)
    }

    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub const fn key_version(&self) -> i32 {
        self.key_version
    }
    pub const fn canary_schema(&self) -> i16 {
        self.canary_schema
    }
    pub fn encrypted_canary(&self) -> &str {
        &self.encrypted_canary
    }
}

impl core::fmt::Debug for DesktopVaultCanaryRow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DesktopVaultCanaryRow(<redacted>)")
    }
}

fn verify(
    database_owner: Arc<()>,
    system_identifier: String,
    database_oid: u32,
    master: &SecretBytes,
    row: &DesktopVaultCanaryRow,
) -> Result<VerifiedDesktopVaultCanary, DesktopVaultCanaryError> {
    let binding = DesktopVaultCanaryBinding::new(
        row.dataset_id.clone(),
        row.deployment_id.clone(),
        row.tenant_id.clone(),
        row.key_id.clone(),
        KeyVersion::new(1),
    )
    .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    let envelope = DesktopVaultCanaryEnvelope::parse(&row.encrypted_canary)
        .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    open_desktop_vault_canary(master, &binding, &envelope)
        .map_err(|_| DesktopVaultCanaryError::MaterialInvalid)?;
    Ok(VerifiedDesktopVaultCanary {
        database_owner,
        system_identifier,
        database_oid,
        dataset_id: row.dataset_id.clone(),
        deployment_id: row.deployment_id.clone(),
        tenant_id: row.tenant_id.clone(),
        key_id: row.key_id.clone(),
        key_version: row.key_version,
        encrypted_canary_digest: Sha256Digest::of(row.encrypted_canary.as_bytes()),
    })
}

pub async fn verify_persisted(
    database: &DesktopLocalDatabase,
    master: &SecretBytes,
    dataset_id: &str,
    deployment_id: &str,
    tenant_id: &str,
    key_id: &str,
) -> Result<VerifiedDesktopVaultCanary, DesktopVaultCanaryError> {
    let pool = database.pool();
    let row = read(pool, deployment_id, tenant_id)
        .await?
        .ok_or(DesktopVaultCanaryError::ReconciliationRequired)?;
    if row.dataset_id != dataset_id
        || row.deployment_id != deployment_id
        || row.tenant_id != tenant_id
        || row.key_id != key_id
        || row.key_version != 1
        || row.canary_schema != 1
    {
        return Err(DesktopVaultCanaryError::ReconciliationRequired);
    }
    let (system_identifier, database_oid) = database_identity(pool).await?;
    verify(
        database.owner_token(),
        system_identifier,
        database_oid,
        master,
        &row,
    )
}

async fn database_identity(pool: &Pool) -> Result<(String, u32), DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        let row = client
            .query_one(
                "SELECT pcs.system_identifier::text,d.oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
                &[],
            )
            .await
            .map_err(|source| InfraError::query("核验 Desktop Vault canary 数据库身份", source))?;
        let system_identifier = row
            .try_get(0)
            .map_err(|source| RowDecodeError::column("(pg_control_system)", "system_identifier", source))?;
        let database_oid = row
            .try_get(1)
            .map_err(|source| RowDecodeError::column("(pg_database)", "oid", source))?;
        Ok((system_identifier, database_oid))
    })
    .await
}

pub async fn table_exists(pool: &Pool) -> Result<bool, DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&TABLE])
            .await
            .map_err(|source| InfraError::query("只读探测 Desktop Vault canary 表", source))?
            .try_get(0)
            .map_err(|source| RowDecodeError::column("(to_regclass)", "exists", source).into())
    })
    .await
}

/// Verify an exact, registered Desktop Vault layout at native 0032 or a later known prefix.
/// Missing known tail migrations are permitted here so an existing canary can be checked first.
pub async fn verify_pre_upgrade_layout(
    pool: &Pool,
) -> Result<ValidatedDesktopVaultLayout, DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        verify_pre_upgrade_layout_on(&client).await
    }).await
}

/// Same original authenticated readonly client. The original startup owner
/// retains the complete result and supplies its unchanged admission deadline.
pub(crate) async fn verify_pre_upgrade_layout_on(
    client: &tokio_postgres::Client,
) -> Result<ValidatedDesktopVaultLayout, InfraError> {
    let ledger = native::validate_known_prefix(&client, native::NATIVE_0032_VERSION).await?;
    verify_internal_shape(client).await?;
    let expected = registered_public_schema(ledger.latest_version())?;
    if schema_facts::fetch(client).await? != expected {
        return Err(InfraError::repository_invariant(
            "desktop_vault_public_schema_invalid",
        ));
    }
    let unknown_views: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('v','m','p','f'))",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 public 未知关系", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column("(pg_class)", "exists", source))?;
    if unknown_views {
        return Err(InfraError::repository_invariant(
            "desktop_vault_public_relation_unknown",
        ));
    }
    if ledger.latest_version() >= native::NATIVE_0046_VERSION {
        super::custom_model_catalog_schema::verify(client)
            .await
            .map_err(|_| {
                InfraError::repository_invariant("custom_model_catalog_schema_invalid")
            })?;
    }
    if ledger.latest_version() >= native::NATIVE_0047_VERSION {
        super::custom_model_v2_schema::verify(client).await?;
    }
    if ledger.latest_version() >= native::NATIVE_0048_VERSION {
        super::gateway_authorization_schema::verify(client).await?;
    }
    if ledger.latest_version() == native::NATIVE_0049_VERSION {
        super::thread_origin_schema::verify_legacy0049(client).await?;
    }
    if ledger.latest_version()==native::NATIVE_0050_VERSION {
        super::thread_origin_schema::verify_legacy0050(client).await?;
    } else if ledger.latest_version()==native::NATIVE_0051_VERSION {
        super::thread_origin_schema::verify_legacy0051(client).await?;
    } else if ledger.latest_version()==native::NATIVE_0052_VERSION {
        super::thread_origin_schema::verify_legacy0052(client).await?;
    } else if ledger.latest_version()==native::NATIVE_0053_VERSION {
        super::thread_origin_schema::verify(client).await?;
    }
    Ok(ValidatedDesktopVaultLayout {
        native_version: ledger.latest_version(),
    })
}

/// Require the exact latest layout known to this binary. Ordinary current-schema callers retain
/// the prior strict behavior; only the explicit pre-upgrade entry point accepts a known prefix.
pub async fn verify_current_layout(pool: &Pool) -> Result<(), DesktopVaultCanaryError> {
    let layout = verify_pre_upgrade_layout(pool).await?;
    if layout.native_version() != native::NATIVE_LATEST_VERSION {
        return Err(
            InfraError::repository_invariant("desktop_vault_native_schema_not_current").into(),
        );
    }
    Ok(())
}

fn registered_public_schema(native_version: i32) -> Result<SchemaFacts, InfraError> {
    let bytes = match native_version {
        native::NATIVE_0032_VERSION => PUBLIC_0031,
        native::NATIVE_0033_VERSION => PUBLIC_0033,
        native::NATIVE_0034_VERSION => PUBLIC_0034,
        native::NATIVE_0035_VERSION => PUBLIC_0035,
        native::NATIVE_0036_VERSION => PUBLIC_0036,
        native::NATIVE_0037_VERSION => PUBLIC_0037,
        native::NATIVE_0038_VERSION => PUBLIC_0038,
        native::NATIVE_0039_VERSION => PUBLIC_0039,
        native::NATIVE_0040_VERSION => PUBLIC_0040,
        //0041 adds only the internal dataset registry; public facts remain exactly0040.
        native::NATIVE_0041_VERSION => PUBLIC_0040,
        //0042 registers real artifacts only in the internal schema.
        native::NATIVE_0042_VERSION => PUBLIC_0040,
        //0043 adds only internal approval preference objects.
        native::NATIVE_0043_VERSION => PUBLIC_0040,
        //0044 adds only internal cleanup fence objects.
        native::NATIVE_0044_VERSION => PUBLIC_0040,
        //0045 adds only the internal saved-receipt completion guard.
        native::NATIVE_0045_VERSION => PUBLIC_0040,
        native::NATIVE_0046_VERSION => PUBLIC_0046,
        //0047 adds only internal immutable V2 snapshots; public facts remain0046.
        native::NATIVE_0047_VERSION => PUBLIC_0046,
        //0048 adds only the internal attempt journal; the public oracle stays0046.
        native::NATIVE_0048_VERSION => PUBLIC_0046,
        //0049 adds only historical internal origin facts; public remains0046.
        native::NATIVE_0049_VERSION => PUBLIC_0046,
        //0050 retains public columns and adds four Thread identity/admission triggers.
        native::NATIVE_0050_VERSION => PUBLIC_0050,
        native::NATIVE_0051_VERSION => PUBLIC_0051,
        native::NATIVE_0052_VERSION => PUBLIC_0052,
        //0053 adds only internal restore facts; its actual additive catalog is checked separately.
        native::NATIVE_0053_VERSION => PUBLIC_0052,
        _ => {
            return Err(InfraError::repository_invariant(
                "desktop_vault_native_schema_unregistered",
            ));
        }
    };
    serde_json::from_str(bytes)
        .map_err(|_| InfraError::repository_invariant("schema_0031_fixture_invalid"))
}

async fn verify_internal_shape(client: &tokio_postgres::Client) -> Result<(), InfraError> {
    verify_internal_shape_on(client).await
}

/// Observe the original0032 shape on the model wrapper's original transaction only.
#[cfg(feature = "server-runtime")]
pub(crate) async fn verify_model_dataset_shape_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    verify_internal_shape_on(tx).await
}

async fn verify_internal_shape_on<C: tokio_postgres::GenericClient + Sync>(
    client: &C,
) -> Result<(), InfraError> {
    let relation = client
        .query_opt(
            "SELECT c.relkind::text,c.relpersistence::text,c.relispartition,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='openbot_internal' AND c.relname='desktop_vault_canaries'",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary relation", source))?
        .ok_or_else(|| InfraError::repository_invariant("desktop_vault_canary_table_missing"))?;
    let relation_shape: (String, String, bool, bool, bool) = (
        relation
            .try_get(0)
            .map_err(|source| RowDecodeError::column(TABLE, "relkind", source))?,
        relation
            .try_get(1)
            .map_err(|source| RowDecodeError::column(TABLE, "relpersistence", source))?,
        relation
            .try_get(2)
            .map_err(|source| RowDecodeError::column(TABLE, "relispartition", source))?,
        relation
            .try_get(3)
            .map_err(|source| RowDecodeError::column(TABLE, "relrowsecurity", source))?,
        relation
            .try_get(4)
            .map_err(|source| RowDecodeError::column(TABLE, "relforcerowsecurity", source))?,
    );
    if relation_shape != ("r".to_owned(), "p".to_owned(), false, false, false) {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_table_shape_invalid",
        ));
    }
    let executable_hooks: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='openbot_internal.desktop_vault_canaries'::regclass AND NOT tgisinternal) OR EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class='openbot_internal.desktop_vault_canaries'::regclass)",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary hooks", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column(TABLE, "hooks", source))?;
    if executable_hooks {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_hooks_invalid",
        ));
    }

    let columns = client
        .query(
            "SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attnum FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='openbot_internal.desktop_vault_canaries'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary columns", source))?;
    let expected_columns = [
        ("dataset_id", "text", true, None, 1_i16),
        ("deployment_id", "text", true, None, 2_i16),
        ("tenant_id", "text", true, None, 3_i16),
        ("key_id", "text", true, None, 4_i16),
        ("key_version", "integer", true, None, 5_i16),
        ("canary_schema", "smallint", true, None, 6_i16),
        ("encrypted_canary", "text", true, None, 7_i16),
        (
            "created_at",
            "timestamp with time zone",
            true,
            Some("now()"),
            8_i16,
        ),
    ];
    if columns.len() != expected_columns.len() {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_columns_invalid",
        ));
    }
    for (row, expected) in columns.iter().zip(expected_columns) {
        let actual: (String, String, bool, Option<String>, i16) = (
            row.try_get(0)
                .map_err(|source| RowDecodeError::column(TABLE, "attname", source))?,
            row.try_get(1)
                .map_err(|source| RowDecodeError::column(TABLE, "format_type", source))?,
            row.try_get(2)
                .map_err(|source| RowDecodeError::column(TABLE, "attnotnull", source))?,
            row.try_get(3)
                .map_err(|source| RowDecodeError::column(TABLE, "default", source))?,
            row.try_get(4)
                .map_err(|source| RowDecodeError::column(TABLE, "attnum", source))?,
        );
        let expected = (
            expected.0.to_owned(),
            expected.1.to_owned(),
            expected.2,
            expected.3.map(str::to_owned),
            expected.4,
        );
        if actual != expected {
            return Err(InfraError::repository_invariant(
                "desktop_vault_canary_columns_invalid",
            ));
        }
    }

    let mut constraints: Vec<(String, String)> = client
        .query(
            "SELECT con.contype::text,pg_get_constraintdef(con.oid) FROM pg_constraint con WHERE con.conrelid='openbot_internal.desktop_vault_canaries'::regclass",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary constraints", source))?
        .into_iter()
        .map(|row| Ok((
            row.try_get(0).map_err(|source| RowDecodeError::column(TABLE,"contype",source))?,
            row.try_get(1).map_err(|source| RowDecodeError::column(TABLE,"constraintdef",source))?,
        )))
        .collect::<Result<_, InfraError>>()?;
    constraints.sort();
    let mut expected_constraints: Vec<_> = [
        ("c", "CHECK ((dataset_id ~ '^[0-9a-f]{32}$'::text))"),
        ("c", "CHECK (((octet_length(deployment_id) >= 1) AND (octet_length(deployment_id) <= 256)))"),
        ("c", "CHECK (((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 256)))"),
        ("c", "CHECK ((key_id ~ '^[0-9a-f]{32}$'::text))"),
        ("c", "CHECK ((key_version > 0))"),
        ("c", "CHECK ((canary_schema = 1))"),
        ("c", "CHECK (((octet_length(encrypted_canary) >= 1) AND (octet_length(encrypted_canary) <= 4096)))"),
        ("p", "PRIMARY KEY (dataset_id, key_version)"),
        ("u", "UNIQUE (deployment_id, tenant_id, key_version)"),
        ("u", "UNIQUE (dataset_id, key_id)"),
    ]
    .into_iter()
    .map(|(kind, definition)| (kind.to_owned(), definition.to_owned()))
    .collect();
    expected_constraints.sort();
    if constraints != expected_constraints {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_constraints_invalid",
        ));
    }

    let mut indexes: Vec<(bool, bool, String)> = client
        .query(
            "SELECT i.indisprimary,i.indisunique,i.indkey::text FROM pg_index i WHERE i.indrelid='openbot_internal.desktop_vault_canaries'::regclass",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 Desktop Vault canary indexes", source))?
        .into_iter()
        .map(|row| Ok((
            row.try_get(0).map_err(|source| RowDecodeError::column(TABLE,"indisprimary",source))?,
            row.try_get(1).map_err(|source| RowDecodeError::column(TABLE,"indisunique",source))?,
            row.try_get(2).map_err(|source| RowDecodeError::column(TABLE,"indkey",source))?,
        )))
        .collect::<Result<_, InfraError>>()?;
    indexes.sort();
    let mut expected_indexes: Vec<_> = [
        (true, true, "1 5".to_owned()),
        (false, true, "1 4".to_owned()),
        (false, true, "2 3 5".to_owned()),
    ]
    .into_iter()
    .collect();
    expected_indexes.sort();
    if indexes != expected_indexes {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_indexes_invalid",
        ));
    }
    Ok(())
}

pub async fn verify_empty_initializing(pool: &Pool) -> Result<(), DesktopVaultCanaryError> {
    let layout = verify_pre_upgrade_layout(pool).await?;
    bounded(async {
        let client = client(pool).await?;
        let expected = registered_public_schema(layout.native_version())?;
        for table in expected.tables {
            if !table
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(InfraError::repository_invariant(
                    "schema_0031_table_name_invalid",
                ));
            }
            let statement = format!(
                "SELECT EXISTS(SELECT 1 FROM public.\"{}\" LIMIT 1)",
                table.name
            );
            let has_rows: bool = client
                .query_one(&statement, &[])
                .await
                .map_err(|source| InfraError::query("只读核验初始化业务表为空", source))?
                .try_get(0)
                .map_err(|source| RowDecodeError::column("(public table)", "exists", source))?;
            if has_rows {
                return Err(InfraError::repository_invariant(
                    "desktop_vault_business_rows_present",
                ));
            }
        }
        let canaries: i64 = client
            .query_one(&format!("SELECT count(*)::bigint FROM {TABLE}"), &[])
            .await
            .map_err(|source| InfraError::query("只读核验 canary 尚未写入", source))?
            .try_get(0)
            .map_err(|source| RowDecodeError::column(TABLE, "count", source))?;
        if canaries != 0 {
            return Err(InfraError::repository_invariant(
                "desktop_vault_canary_already_present",
            ));
        }
        Ok(())
    })
    .await
}

pub async fn read(
    pool: &Pool,
    deployment_id: &str,
    tenant_id: &str,
) -> Result<Option<DesktopVaultCanaryRow>, DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        let row = client
            .query_opt(
                "SELECT dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1",
                &[&deployment_id, &tenant_id],
            )
            .await
            .map_err(|source| InfraError::query("只读读取 Desktop Vault canary", source))?;
        row.map(decode_row).transpose()
    })
    .await
}

pub async fn insert_once(
    pool: &Pool,
    row: &DesktopVaultCanaryRow,
) -> Result<(), DesktopVaultCanaryError> {
    bounded(async {
        let client = client(pool).await?;
        client
            .execute(
                "INSERT INTO openbot_internal.desktop_vault_canaries(dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary) VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[&row.dataset_id,&row.deployment_id,&row.tenant_id,&row.key_id,&row.key_version,&row.canary_schema,&row.encrypted_canary],
            )
            .await
            .map_err(|source| InfraError::query("写入 Desktop Vault canary", source))
            .map(|_| ())
    })
    .await
}

fn decode_row(row: tokio_postgres::Row) -> Result<DesktopVaultCanaryRow, InfraError> {
    let key_version: i32 = row
        .try_get(4)
        .map_err(|source| RowDecodeError::column(TABLE, "key_version", source))?;
    let canary_schema: i16 = row
        .try_get(5)
        .map_err(|source| RowDecodeError::column(TABLE, "canary_schema", source))?;
    if key_version != 1 || canary_schema != 1 {
        return Err(InfraError::repository_invariant(
            "desktop_vault_canary_row_invalid",
        ));
    }
    DesktopVaultCanaryRow::new(
        row.try_get::<_, String>(0)
            .map_err(|source| RowDecodeError::column(TABLE, "dataset_id", source))?,
        row.try_get::<_, String>(1)
            .map_err(|source| RowDecodeError::column(TABLE, "deployment_id", source))?,
        row.try_get::<_, String>(2)
            .map_err(|source| RowDecodeError::column(TABLE, "tenant_id", source))?,
        row.try_get::<_, String>(3)
            .map_err(|source| RowDecodeError::column(TABLE, "key_id", source))?,
        row.try_get::<_, String>(6)
            .map_err(|source| RowDecodeError::column(TABLE, "encrypted_canary", source))?,
    )
    .map_err(|error| match error {
        DesktopVaultCanaryError::Infra(error) => error,
        DesktopVaultCanaryError::ReconciliationRequired => {
            InfraError::repository_invariant("desktop_vault_canary_row_invalid")
        }
        DesktopVaultCanaryError::MaterialInvalid => {
            InfraError::repository_invariant("desktop_vault_canary_material_invalid")
        }
    })
}

async fn client(pool: &Pool) -> Result<crate::db::pool::PooledClient, InfraError> {
    pool.get()
        .await
        .map_err(|source| InfraError::connect("取 Desktop Vault canary 连接", source))
}

async fn bounded<T>(
    future: impl std::future::Future<Output = Result<T, InfraError>>,
) -> Result<T, DesktopVaultCanaryError> {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .map_err(|_| DesktopVaultCanaryError::ReconciliationRequired)?
        .map_err(DesktopVaultCanaryError::Infra)
}

fn hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identity(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|ch| ch == '\0' || ch.is_control())
}
