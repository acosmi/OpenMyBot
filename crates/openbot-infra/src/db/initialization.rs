//! Shared fresh / legacy / Rust-managed database initialization.
//!
//! Server and Desktop Local use one PostgreSQL schema and therefore must use one origin detector
//! and migration path. Keeping this in a transport binary would let the Desktop setup silently
//! diverge from Server at the most security-sensitive bootstrap boundary.

use crate::db::pool::DatabasePool as Pool;

use super::compat::{DataMigrationVerdict, check_migration_boundary_on};
use super::{InfraError, fresh, native};
#[cfg(feature = "server-runtime")]
use crate::recovery_control::{Hex32, RecoveryControlError, RecoveryControlFault};

/// The Server bootstrap Pool and its first client, kept by the original
/// control owner for the runtime's read gate. This is not a Fresh proof.
pub(crate) struct OwnedExistingServerDatabase {
    pub(crate) pool: Option<Result<Pool, InfraError>>,
    pub(crate) client: Option<Result<super::pool::PooledClient, super::pool::PoolError>>,
}

impl OwnedExistingServerDatabase {
    pub(crate) fn new() -> Self {
        Self {
            pool: None,
            client: None,
        }
    }

    pub(crate) fn pool(&self) -> Result<&Pool, crate::recovery_control::RecoveryControlError> {
        self.pool
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(|| {
                crate::recovery_control::RecoveryControlError::new(
                    crate::recovery_control::RecoveryControlFault::IoFailure,
                )
            })
    }
}

pub(crate) const EXISTING_SERVER_IDENTITY_SQL: &str = "SELECT pcs.system_identifier::text AS system_identifier, d.oid AS database_oid, pg_catalog.current_setting('server_version_num')::integer / 10000 AS pg_major, session_user::text AS authenticated_principal, current_user::text AS current_principal, pg_catalog.pg_get_userbyid(d.datdba)::text AS database_owner FROM pg_catalog.pg_control_system() pcs JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()";

/// Plaintext sealed under the configured Server KEK in its site canary row.
#[cfg(feature = "server-runtime")]
pub(crate) const SERVER_KEY_CANARY_PLAINTEXT: &[u8] = b"wrokbot.server.key-canary.v1";

// One row per site, by primary key. PG bounds the selected text before the row
// can allocate it; NULL is rejection, never an empty canary.
#[cfg(feature = "server-runtime")]
const SERVER_KEY_CANARY_SQL: &str = "SELECT CASE WHEN pg_catalog.octet_length(dataset_id)<=32 THEN dataset_id ELSE NULL END AS dataset_id, CASE WHEN pg_catalog.octet_length(key_id)<=32 THEN key_id ELSE NULL END AS key_id, CASE WHEN pg_catalog.octet_length(encrypted_canary)<=4096 THEN encrypted_canary ELSE NULL END AS encrypted_canary FROM openbot_internal.server_kek_canaries WHERE deployment_id=$1 AND tenant_id=$2";

/// The AAD of one Server KEK canary: a Connector record whose prefixed
/// secret id cannot be AAD-equivalent to a credential UUID.
#[cfg(feature = "server-runtime")]
fn server_canary_binding(
    tenant: &openbot_contracts::ids::TenantId,
    dataset: &Hex32,
    key_id: &Hex32,
) -> openbot_domain::vault::RecordBinding {
    use openbot_domain::vault::{KeyVersion, RecordBinding, SecretId, SecretKind, SecretPrincipal};
    RecordBinding::new(
        tenant.clone(),
        SecretId::new(format!(
            "server-key-canary/{}/{}",
            dataset.as_str(),
            key_id.as_str()
        )),
        SecretKind::Connector,
        SecretPrincipal::Deployment,
        SecretPrincipal::Deployment,
        KeyVersion::new(1),
    )
}

/// Seal and insert this site's one KEK canary inside the caller's transaction.
#[cfg(feature = "server-runtime")]
pub(crate) async fn insert_server_canary(
    transaction: &tokio_postgres::Transaction<'_>,
    key: &crate::auth::config::KeyEncryptionKey,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    dataset: &Hex32,
    key_id: &Hex32,
) -> Result<(), DatabaseInitializationError> {
    use openbot_domain::vault::{DATA_KEY_BYTES, DataKey, NONCE_BYTES, Nonce, seal_v2};
    let rejected = || InfraError::repository_invariant("server_key_canary_seal_failed");
    let mut dek = vec![0_u8; DATA_KEY_BYTES];
    let mut dek_nonce = [0_u8; NONCE_BYTES];
    let mut record_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut dek).map_err(|_| rejected())?;
    getrandom::fill(&mut dek_nonce).map_err(|_| rejected())?;
    getrandom::fill(&mut record_nonce).map_err(|_| rejected())?;
    let dek = DataKey::from_bytes(dek).map_err(|_| rejected())?;
    let envelope = seal_v2(
        key.wrapping_key(),
        &dek,
        &server_canary_binding(tenant, dataset, key_id),
        Nonce::from_array(dek_nonce),
        Nonce::from_array(record_nonce),
        SERVER_KEY_CANARY_PLAINTEXT,
    )
    .map_err(|_| rejected())?;
    transaction
        .execute(
            "INSERT INTO openbot_internal.server_kek_canaries \
             (deployment_id, tenant_id, dataset_id, key_id, encrypted_canary) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &deployment.as_str(),
                &tenant.as_str(),
                &dataset.as_str(),
                &key_id.as_str(),
                &envelope.to_column_value(),
            ],
        )
        .await
        .map_err(|source| InfraError::query("insert the Server KEK canary", source))?;
    Ok(())
}

/// The site's canary key id after the configured KEK opens its exact
/// plaintext; `None` when the site has no row. The table exists on every
/// database a Server head was published for (046 version or later).
#[cfg(feature = "server-runtime")]
pub(crate) async fn verify_server_canary(
    client: &tokio_postgres::Client,
    key: &crate::auth::config::KeyEncryptionKey,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    dataset: &Hex32,
) -> Result<Option<Hex32>, RecoveryControlError> {
    use openbot_domain::vault::{ColumnShape, EnvelopeV2, classify_column, open_v2};
    let unverified = || RecoveryControlError::new(RecoveryControlFault::KeyUnverified);
    let Some(row) = client
        .query_opt(
            SERVER_KEY_CANARY_SQL,
            &[&deployment.as_str(), &tenant.as_str()],
        )
        .await
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
    else {
        return Ok(None);
    };
    let text = |column: &str| row.try_get::<_, Option<String>>(column).ok().flatten();
    let key_id = text("key_id")
        .and_then(|value| Hex32::parse(&value).ok())
        .ok_or_else(unverified)?;
    let encrypted = text("encrypted_canary").ok_or_else(unverified)?;
    if text("dataset_id").as_deref() != Some(dataset.as_str())
        || !matches!(classify_column(&encrypted), ColumnShape::RecordEnvelope)
    {
        return Err(unverified());
    }
    let envelope = EnvelopeV2::parse(&encrypted).map_err(|_| unverified())?;
    let plaintext = open_v2(
        key.wrapping_key(),
        &server_canary_binding(tenant, dataset, &key_id),
        &envelope,
    )
    .map_err(|_| unverified())?;
    if plaintext.expose() != SERVER_KEY_CANARY_PLAINTEXT {
        return Err(unverified());
    }
    Ok(Some(key_id))
}

/// The one original Server Fresh request of an ordinary writer session.
#[cfg(feature = "server-runtime")]
pub struct OriginalInitializationRequest<'a> {
    pub(crate) session: &'a mut crate::recovery_control::OrdinaryInitializationSession,
    pub(crate) key: &'a crate::auth::config::KeyEncryptionKey,
}

/// The resident result of one owned initialization: its connection, the full
/// COMMIT result and, only for a timely verified Fresh, its proof.
#[cfg(feature = "server-runtime")]
pub struct OwnedDatabaseInitialization {
    _client: super::pool::PooledClient,
    commit: Option<Result<(), tokio_postgres::Error>>,
    proof: Option<crate::recovery_control::OrdinaryDatabaseInitializationProof>,
}

#[cfg(feature = "server-runtime")]
impl OwnedDatabaseInitialization {
    /// The proof, or why there is none: no COMMIT means the database was not
    /// empty or not the expected site; a COMMIT without proof stays unproven.
    pub(crate) fn into_proof(
        self,
    ) -> Result<crate::recovery_control::OrdinaryDatabaseInitializationProof, RecoveryControlError>
    {
        match (self.proof, self.commit) {
            (Some(proof), _) => Ok(proof),
            (None, None) => Err(RecoveryControlError::new(
                RecoveryControlFault::InitializationRequired,
            )),
            (None, Some(_)) => Err(RecoveryControlError::new(
                RecoveryControlFault::ClosureUnproven,
            )),
        }
    }
}

// Rechecked under the migration lock: an empty public schema, no native ledger
// and no restore operation table.
#[cfg(feature = "server-runtime")]
const FRESH_PRECONDITION_SQL: &str = "SELECT (SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE')::bigint = 0 AND to_regclass('openbot_internal.schema_migrations') IS NULL AND to_regclass('openbot_internal.restore_pg_operations') IS NULL";

/// Server Fresh inside the original migration transaction (spec 8075-8082):
/// the Initializing head is sealed before any DDL, and only a timely COMMIT
/// with a matching readback yields a proof.
///
/// # Errors
///
/// Connection, DDL or journal failures; the transaction rolls back when it is
/// dropped before COMMIT.
#[cfg(feature = "server-runtime")]
pub async fn initialize_owned_before(
    pool: &Pool,
    request: OriginalInitializationRequest<'_>,
) -> Result<OwnedDatabaseInitialization, DatabaseInitializationError> {
    use crate::recovery_control::OrdinaryStage;
    use native::BootstrapTransactionClient as _;
    let OriginalInitializationRequest { session, key } = request;
    let (deployment, tenant, dataset, effect) = session
        .server_scope()
        .map_err(DatabaseInitializationError::Recovery)?;
    let mut client = pool
        .get()
        .await
        .map_err(|source| InfraError::connect("check out the Server initialization connection", source))?;
    let transaction = client
        .bootstrap_transaction_builder()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|source| InfraError::query("begin the Server initialization transaction", source))?;
    native::lock_migrations(&transaction).await?;
    let empty: bool = transaction
        .query_one(FRESH_PRECONDITION_SQL, &[])
        .await
        .and_then(|row| row.try_get(0))
        .map_err(|source| InfraError::query("recheck the Server Fresh precondition under the lock", source))?;
    let identity = transaction
        .query_one(EXISTING_SERVER_IDENTITY_SQL, &[])
        .await
        .map_err(|source| InfraError::query("read the Server database identity", source))?;
    let text = |column: &str| identity.try_get::<_, String>(column).ok();
    let site = (|| {
        let principal = text("authenticated_principal")?;
        (Some(&principal) == text("current_principal").as_ref()
            && identity.try_get::<_, i32>("pg_major").ok()? == 17)
            .then_some(())?;
        Some(crate::recovery_control::ServerDatabaseSite {
            pg_system_id: text("system_identifier")?.parse().ok()?,
            database_oid: identity.try_get("database_oid").ok()?,
            pg_major: 17,
            authenticated_principal: principal,
            database_owner: text("database_owner")?,
        })
    })();
    let Some(site) = site.filter(|_| empty) else {
        transaction
            .rollback()
            .await
            .map_err(|source| InfraError::query("end the Server transaction that cannot initialize", source))?;
        return Ok(OwnedDatabaseInitialization {
            _client: client,
            commit: None,
            proof: None,
        });
    };
    session
        .seal_initializing(site.clone())
        .and_then(|()| session.intend(OrdinaryStage::Initialize))
        .map_err(DatabaseInitializationError::Recovery)?;
    fresh::apply_in_transaction(&transaction).await?;
    let mut entropy = [0_u8; 16];
    getrandom::fill(&mut entropy)
        .map_err(|_| InfraError::repository_invariant("server_key_canary_seal_failed"))?;
    let key_id = Hex32::mint(&entropy).map_err(DatabaseInitializationError::Recovery)?;
    insert_server_canary(&transaction, key, &deployment, &tenant, &dataset, &key_id).await?;
    let commit = transaction.commit().await;
    let returned = std::time::Instant::now();
    let timely = session
        .observe_commit(commit.is_ok(), returned)
        .map_err(DatabaseInitializationError::Recovery)?;
    let mut owned = OwnedDatabaseInitialization {
        _client: client,
        commit: Some(commit),
        proof: None,
    };
    if !timely {
        return Ok(owned);
    }
    native::validate_current(&owned._client).await?;
    let layout = super::desktop_vault_canary::verify_pre_upgrade_layout_on(&owned._client).await?;
    let canary = verify_server_canary(&owned._client, key, &deployment, &tenant, &dataset)
        .await
        .map_err(DatabaseInitializationError::Recovery)?;
    let migration_digest: String = owned
        ._client
        .query_one(
            "SELECT checksum FROM openbot_internal.schema_migrations WHERE version = $1",
            &[&native::NATIVE_LATEST_VERSION],
        )
        .await
        .and_then(|row| row.try_get(0))
        .map_err(|source| InfraError::query("read the latest native migration checksum", source))?;
    if layout.native_version() == native::NATIVE_LATEST_VERSION
        && canary == Some(key_id)
        && std::time::Instant::now() <= effect
    {
        owned.proof = Some(
            crate::recovery_control::OrdinaryDatabaseInitializationProof {
                site,
                key_id,
                migration_digest,
            },
        );
    }
    Ok(owned)
}

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
    /// The ordinary recovery control refused or could not record the step.
    #[cfg(feature = "server-runtime")]
    Recovery(RecoveryControlError),
}

impl core::fmt::Display for DatabaseInitializationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Infra(error) => core::fmt::Display::fmt(error, formatter),
            Self::LegacyDataMigrationUnverifiable => {
                formatter.write_str("legacy_data_migration_unverifiable")
            }
            #[cfg(feature = "server-runtime")]
            Self::Recovery(error) => core::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for DatabaseInitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Infra(error) => Some(error),
            Self::LegacyDataMigrationUnverifiable => None,
            #[cfg(feature = "server-runtime")]
            Self::Recovery(error) => Some(error),
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
