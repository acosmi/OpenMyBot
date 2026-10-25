//! Shared fresh / legacy / Rust-managed database initialization.
//!
//! Server and Desktop Local use one PostgreSQL schema and therefore must use one origin detector
//! and migration path. Keeping this in a transport binary would let the Desktop setup silently
//! diverge from Server at the most security-sensitive bootstrap boundary.

use crate::db::pool::DatabasePool as Pool;

use super::compat::{DataMigrationVerdict, check_migration_boundary_on};
use super::{InfraError, fresh, native};

/// Actual readonly startup resources and full results. This is neither a Fresh
/// proof nor a constructor from a Pool/DatabaseOrigin. The original control
/// owner keeps this packet before any postcheck and throughout runtime.
pub(crate) struct OwnedExistingServerDatabase {
    pub(crate) master: openbot_domain::vault::SecretBytes,
    pub(crate) pool: Option<Result<Pool, InfraError>>,
    pub(crate) client: Option<Result<super::pool::PooledClient, super::pool::PoolError>>,
    pub(crate) identity: Option<Result<tokio_postgres::Row, tokio_postgres::Error>>,
    pub(crate) canary: Option<Result<tokio_postgres::Row, tokio_postgres::Error>>,
    pub(crate) known_restore: Option<Result<tokio_postgres::Row, tokio_postgres::Error>>,
    pub(crate) native: Option<Result<(), InfraError>>,
    pub(crate) writer_schema: Option<Result<(), InfraError>>,
    pub(crate) layout: Option<Result<super::desktop_vault_canary::ValidatedDesktopVaultLayout, super::desktop_vault_canary::DesktopVaultCanaryError>>,
    pub(crate) crypto: Option<Result<(), openbot_domain::vault::VaultError>>,
}

impl OwnedExistingServerDatabase {
    pub(crate) fn new(master: openbot_domain::vault::SecretBytes) -> Self {
        Self { master, pool: None, client: None, identity: None, canary: None,
            known_restore: None, native: None, writer_schema: None, layout: None, crypto: None }
    }

    pub(crate) fn pool(&self) -> Result<&Pool, crate::recovery_control::RecoveryControlError> {
        self.pool.as_ref().and_then(|value| value.as_ref().ok()).ok_or_else(||
            crate::recovery_control::RecoveryControlError::new(crate::recovery_control::RecoveryControlFault::ClosureUnproven))
    }
}

pub(crate) const EXISTING_SERVER_IDENTITY_SQL: &str = "SELECT pcs.system_identifier::text AS system_identifier, d.oid AS database_oid, pg_catalog.current_setting('server_version_num')::integer / 10000 AS pg_major, session_user::text AS authenticated_principal, current_user::text AS current_principal, pg_catalog.pg_get_userbyid(d.datdba)::text AS database_owner FROM pg_catalog.pg_control_system() pcs JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()";

// Bounds are enforced by PG before the row can allocate a large ciphertext or
// caller-selected text. NULL is rejection, never an empty/missing canary.
pub(crate) const EXISTING_SERVER_CANARY_SQL: &str = "SELECT CASE WHEN pg_catalog.octet_length(dataset_id)<=$3 THEN dataset_id ELSE NULL END AS dataset_id, CASE WHEN pg_catalog.octet_length(deployment_id)<=$3 THEN deployment_id ELSE NULL END AS deployment_id, CASE WHEN pg_catalog.octet_length(tenant_id)<=$3 THEN tenant_id ELSE NULL END AS tenant_id, CASE WHEN pg_catalog.octet_length(key_id)<=64 THEN key_id ELSE NULL END AS key_id, key_version, canary_schema, CASE WHEN pg_catalog.octet_length(encrypted_canary)<=4096 THEN encrypted_canary ELSE NULL END AS encrypted_canary FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2 AND key_version=1";


/// The database origin recognized during this startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseOrigin {
    /// The public schema was empty and received the atomic Rust baseline plus native migrations.
    Fresh,
    /// A trusted Rust native migration ledger already existed.
    RustManaged,
    /// A legacy database had a complete Drizzle ledger and then received native migrations.
    LegacyUpgraded,
}

/// Stable database initialization failure without row values or connection secrets.
#[derive(Debug)]
pub enum DatabaseInitializationError {
    /// A redacted connection/schema/migration error from the infra database layer.
    Infra(InfraError),
    /// A nonempty public schema had neither a complete Drizzle ledger nor a trusted native ledger.
    LegacyDataMigrationUnverifiable,
}

impl core::fmt::Display for DatabaseInitializationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Infra(error) => core::fmt::Display::fmt(error, formatter),
            Self::LegacyDataMigrationUnverifiable => {
                formatter.write_str("legacy_data_migration_unverifiable")
            }
        }
    }
}

impl std::error::Error for DatabaseInitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Infra(error) => Some(error),
            Self::LegacyDataMigrationUnverifiable => None,
        }
    }
}

impl From<InfraError> for DatabaseInitializationError {
    fn from(error: InfraError) -> Self {
        Self::Infra(error)
    }
}

/// Initialize or verify one OpenBot PostgreSQL database and apply current native migrations.
///
/// Rust fresh databases use the native ledger as their restart provenance. Unknown nonempty
/// legacy databases remain fail-closed; schema similarity cannot prove that data-only migration
/// `0003` ran.
///
/// # Errors
///
/// Returns [`DatabaseInitializationError`] when origin evidence, baseline, or a native migration
/// cannot be verified and committed.
pub async fn initialize(pool: &Pool) -> Result<DatabaseOrigin, DatabaseInitializationError> {
    let mut client = pool
        .get()
        .await
        .map_err(|source| InfraError::connect("取数据库初始化连接", source))?;
    let public_tables: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM information_schema.tables \
             WHERE table_schema='public' AND table_type='BASE TABLE'",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("检查 public schema 是否为空", source))?
        .try_get(0)
        .map_err(|source| {
            super::RowDecodeError::column("(information_schema.tables)", "count", source)
        })
        .map_err(InfraError::from)?;

    if public_tables == 0 {
        match fresh::apply(&mut client).await? {
            fresh::FreshApplyOutcome::Applied(_) => return Ok(DatabaseOrigin::Fresh),
            fresh::FreshApplyOutcome::AlreadyInitialized => {}
        }
    }

    let rust_managed = native::ledger_exists(&client).await?;
    let report = check_migration_boundary_on(&client).await?;
    if matches!(
        report.data_migrations,
        DataMigrationVerdict::Unverifiable { .. }
    ) && !rust_managed
    {
        return Err(DatabaseInitializationError::LegacyDataMigrationUnverifiable);
    }

    native::apply(&mut client).await?;
    Ok(if rust_managed {
        DatabaseOrigin::RustManaged
    } else {
        DatabaseOrigin::LegacyUpgraded
    })
}
