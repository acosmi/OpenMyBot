//! Fixed numeric-loopback database assembly for the Desktop Local PostgreSQL sidecar.
//!
//! The sidecar first becomes SCRAM-ready on the administrative `postgres` database. This module
//! creates or verifies the one fixed `openbot` business database, then returns a probed pool for
//! the shared schema/principal/package bootstrap. It accepts a zeroizing password owner; there is
//! no second public [`super::pool::DatabaseConfig`] containing a long-lived password `String`.

use std::sync::Arc;
use std::time::Duration;

use openbot_contracts::desktop::DESKTOP_LOCAL_POSTGRES_ADMIN_USER;
use openbot_domain::vault::SecretBytes;
use tokio_postgres::{Client, Config};

use super::InfraError;
#[cfg(feature = "desktop-local-vault")]
use super::pool::connect_config_retained;
#[cfg(feature = "desktop-local-vault")]
pub use super::pool::owner::{
    DesktopCaptureDrivers, DesktopLocalDriverCustody, DesktopPoolJoinBounds,
    OriginalDriverJoinFact, OriginalDriverJoinOutcome, OriginalDriverRetirement,
};
use super::pool::{DatabasePool, connect_config};

const HOST: &str = "127.0.0.1";
const ADMIN_DATABASE: &str = "postgres";
const APPLICATION_DATABASE: &str = "openbot";
const APPLICATION_NAME: &str = "openbot-desktop-local";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const APPLICATION_POOL_SIZE: usize = 16;
const SCRAM_SECRET_LEN: usize = 64;

const DATABASE_FACTS_SQL: &str = "SELECT pg_get_userbyid(datdba)::text, pg_encoding_to_char(encoding)::text, \
            datcollate::text, datctype::text, datistemplate, datallowconn, datconnlimit \
     FROM pg_catalog.pg_database WHERE datname=$1";
const CREATE_APPLICATION_DATABASE_SQL: &str = "CREATE DATABASE openbot WITH OWNER=desktop_admin TEMPLATE=template0 ENCODING='UTF8' \
     LC_COLLATE='C' LC_CTYPE='C' CONNECTION LIMIT=-1";

/// How the fixed Desktop Local business database became available during this start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopLocalDatabaseOrigin {
    /// This start executed and then verified the fixed `CREATE DATABASE` statement.
    Created,
    /// The exact fixed database already existed and passed every shape check.
    Existing,
    /// `CREATE DATABASE` returned an error, but an immediate authoritative re-read found the exact
    /// database. This is explicit unknown-commit reconciliation, not a fabricated success.
    ReconciledAfterCreateError,
}

/// A verified Desktop Local business pool plus its startup origin.
pub struct DesktopLocalDatabase {
    pool: DatabasePool,
    origin: DesktopLocalDatabaseOrigin,
    owner: Arc<()>,
    #[cfg(feature = "desktop-local-vault")]
    retention: Option<DesktopLocalDriverCustody>,
}

/// Non-transferable proof that this attested owner created the fixed business database now.
pub struct FreshDesktopDatabaseProof {
    owner: Arc<()>,
}

/// Administrative pool that can only be used for the R153 live-sidecar attestation.
///
/// The password is one startup-only [`SecretBytes`] owner. Only
/// [`crate::auth::single_user::desktop_local::DesktopLocalInstallation`] can convert this value to
/// the attested state that exposes database creation.
pub struct UnattestedDesktopLocalAdmin {
    pool: DatabasePool,
    port: u16,
    password: SecretBytes,
    #[cfg(feature = "desktop-local-vault")]
    retention: Option<DesktopLocalDriverCustody>,
}

impl UnattestedDesktopLocalAdmin {
    /// Borrow the administrative pool solely for the shared sidecar attestation query.
    #[must_use]
    pub(crate) const fn pool(&self) -> &DatabasePool {
        &self.pool
    }

    pub(crate) fn close(&self) {
        self.pool.close();
    }

    pub(crate) fn into_attested(self) -> AttestedDesktopLocalAdmin {
        AttestedDesktopLocalAdmin {
            pool: self.pool,
            port: self.port,
            password: self.password,
            #[cfg(feature = "desktop-local-vault")]
            retention: self.retention,
        }
    }
}

impl core::fmt::Debug for UnattestedDesktopLocalAdmin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UnattestedDesktopLocalAdmin(<redacted>)")
    }
}

/// Administrative pool after the exact instance path/version/loopback/SCRAM attestation passed.
pub struct AttestedDesktopLocalAdmin {
    pool: DatabasePool,
    port: u16,
    password: SecretBytes,
    #[cfg(feature = "desktop-local-vault")]
    retention: Option<DesktopLocalDriverCustody>,
}

impl AttestedDesktopLocalAdmin {
    /// Create/reconcile the fixed business database, close the admin pool, and return its probed
    /// application pool. No durable database write is reachable on the unattested type.
    pub async fn connect_application(
        self,
        allow_create: bool,
    ) -> Result<DesktopLocalDatabase, DesktopLocalDatabaseError> {
        let client = self.pool.get().await.map_err(|source| {
            DesktopLocalDatabaseError::Connect(InfraError::connect(
                "取 Desktop Local PostgreSQL 管理连接",
                source,
            ))
        })?;
        let origin = tokio::time::timeout(
            CONNECT_TIMEOUT,
            ensure_application_database(&client, allow_create),
        )
        .await
        .map_err(|_| {
            DesktopLocalDatabaseError::Inspect(InfraError::repository_invariant(
                "desktop_local_database_inspection_timeout",
            ))
        })?;
        drop(client);
        self.pool.close();
        let origin = origin?;

        let configuration = local_config(
            self.port,
            self.password.expose(),
            LocalDatabase::Application,
        );
        #[cfg(feature = "desktop-local-vault")]
        let pool = match self.retention.as_ref() {
            Some(custody) => {
                connect_config_retained(
                    configuration,
                    APPLICATION_POOL_SIZE,
                    CONNECT_TIMEOUT,
                    "Desktop Local OpenBot 数据库",
                    custody,
                    true,
                )
                .await
            }
            None => {
                connect_config(
                    configuration,
                    APPLICATION_POOL_SIZE,
                    CONNECT_TIMEOUT,
                    "Desktop Local OpenBot 数据库",
                )
                .await
            }
        }
        .map_err(DesktopLocalDatabaseError::Connect)?;
        #[cfg(not(feature = "desktop-local-vault"))]
        let pool = connect_config(
            configuration,
            APPLICATION_POOL_SIZE,
            CONNECT_TIMEOUT,
            "Desktop Local OpenBot 数据库",
        )
        .await
        .map_err(DesktopLocalDatabaseError::Connect)?;
        Ok(DesktopLocalDatabase {
            pool,
            origin,
            owner: Arc::new(()),
            #[cfg(feature = "desktop-local-vault")]
            retention: self.retention,
        })
    }
}

impl core::fmt::Debug for AttestedDesktopLocalAdmin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AttestedDesktopLocalAdmin(<redacted>)")
    }
}

impl DesktopLocalDatabase {
    /// Borrow the pool consumed by shared database initialization and application adapters.
    #[must_use]
    pub const fn pool(&self) -> &DatabasePool {
        &self.pool
    }

    /// Borrow the pool as an owned clone for an adapter that must retain it.
    #[must_use]
    pub fn clone_pool(&self) -> DatabasePool {
        self.pool.clone()
    }

    /// Mechanical fixed-database origin for startup evidence.
    #[must_use]
    pub const fn origin(&self) -> DesktopLocalDatabaseOrigin {
        self.origin
    }

    pub fn fresh_initialization_proof(&self) -> Option<FreshDesktopDatabaseProof> {
        (self.origin == DesktopLocalDatabaseOrigin::Created).then(|| FreshDesktopDatabaseProof {
            owner: Arc::clone(&self.owner),
        })
    }

    pub(crate) fn owner_token(&self) -> Arc<()> {
        Arc::clone(&self.owner)
    }

    pub(crate) fn owns_token(&self, token: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.owner, token)
    }

    /// Stop admitting new checkouts before the owning sidecar is shut down.
    pub fn close(&self) {
        self.pool.close();
    }
}

impl FreshDesktopDatabaseProof {
    pub(crate) fn matches(&self, database: &DesktopLocalDatabase) -> bool {
        database.owns_token(&self.owner)
    }
}

impl core::fmt::Debug for DesktopLocalDatabase {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopLocalDatabase")
            .field("origin", &self.origin)
            .field("pool", &"<redacted>")
            .finish()
    }
}

/// Stable local database assembly failures; no endpoint, path or credential value is retained.
#[derive(Debug, thiserror::Error)]
pub enum DesktopLocalDatabaseError {
    /// The caller did not provide the exact 64-byte lowercase-hex SCRAM shape or a usable port.
    #[error("desktop_local_database_endpoint_invalid")]
    EndpointInvalid,
    /// The fixed administrative or business pool could not be established.
    #[error("desktop_local_database_connection_failed")]
    Connect(#[source] InfraError),
    /// The authoritative `pg_database` facts could not be read.
    #[error("desktop_local_database_inspection_failed")]
    Inspect(#[source] InfraError),
    /// The fixed create statement failed and reconciliation found no committed database.
    #[error("desktop_local_database_create_failed")]
    Create(#[source] InfraError),
    /// An existing/reconciled database had an unexpected owner, encoding, locale or access shape.
    #[error("desktop_local_database_shape_invalid")]
    ShapeInvalid,
    /// Existing sidecar data had no fixed business database; ordinary startup may not create it.
    #[error("desktop_local_database_missing")]
    Missing,
}

/// Connect through exact numeric loopback for the pre-write live-sidecar attestation.
///
/// The supplied [`SecretBytes`] becomes the typestate owner's startup secret; only the PostgreSQL
/// driver/pool receives the authenticated-connection copies it needs. This function cannot create
/// a database; the attested state returned by the instance-bound authority is required for that
/// operation.
pub async fn connect_for_attestation(
    port: u16,
    password: SecretBytes,
) -> Result<UnattestedDesktopLocalAdmin, DesktopLocalDatabaseError> {
    if port == 0 || !valid_scram_secret(password.expose()) {
        return Err(DesktopLocalDatabaseError::EndpointInvalid);
    }

    let admin = connect_config(
        local_config(port, password.expose(), LocalDatabase::Admin),
        1,
        CONNECT_TIMEOUT,
        "Desktop Local PostgreSQL 管理库",
    )
    .await
    .map_err(DesktopLocalDatabaseError::Connect)?;
    Ok(UnattestedDesktopLocalAdmin {
        pool: admin,
        port,
        password,
        #[cfg(feature = "desktop-local-vault")]
        retention: None,
    })
}

/// Retain the actual administrative driver before its first connect poll. This is not a live
/// attestation or capture capability; the existing attestation and business bootstrap still run.
#[cfg(feature = "desktop-local-vault")]
pub async fn connect_for_attestation_retained(
    port: u16,
    password: SecretBytes,
    custody: &DesktopLocalDriverCustody,
) -> Result<UnattestedDesktopLocalAdmin, DesktopLocalDatabaseError> {
    if port == 0 || !valid_scram_secret(password.expose()) {
        return Err(DesktopLocalDatabaseError::EndpointInvalid);
    }
    let pool = connect_config_retained(
        local_config(port, password.expose(), LocalDatabase::Admin),
        1,
        CONNECT_TIMEOUT,
        "Desktop Local PostgreSQL 管理库",
        custody,
        false,
    )
    .await
    .map_err(DesktopLocalDatabaseError::Connect)?;
    Ok(UnattestedDesktopLocalAdmin {
        pool,
        port,
        password,
        retention: Some(custody.shared()),
    })
}

#[derive(Clone, Copy)]
enum LocalDatabase {
    Admin,
    Application,
}

impl LocalDatabase {
    const fn name(self) -> &'static str {
        match self {
            Self::Admin => ADMIN_DATABASE,
            Self::Application => APPLICATION_DATABASE,
        }
    }
}

fn local_config(port: u16, password: &[u8], database: LocalDatabase) -> Config {
    let password = std::str::from_utf8(password)
        .expect("valid_scram_secret already proved lowercase ASCII hex");
    let mut config = Config::new();
    config
        .host(HOST)
        .port(port)
        .user(DESKTOP_LOCAL_POSTGRES_ADMIN_USER)
        .dbname(database.name())
        .connect_timeout(CONNECT_TIMEOUT);
    config.password(password).application_name(APPLICATION_NAME);
    config
}

fn valid_scram_secret(secret: &[u8]) -> bool {
    secret.len() == SCRAM_SECRET_LEN
        && secret
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

async fn ensure_application_database(
    client: &Client,
    allow_create: bool,
) -> Result<DesktopLocalDatabaseOrigin, DesktopLocalDatabaseError> {
    if let Some(facts) = read_database_facts(client).await? {
        return facts
            .is_exact()
            .then_some(DesktopLocalDatabaseOrigin::Existing)
            .ok_or(DesktopLocalDatabaseError::ShapeInvalid);
    }

    if !allow_create {
        return Err(DesktopLocalDatabaseError::Missing);
    }

    let create_error = client
        .batch_execute(CREATE_APPLICATION_DATABASE_SQL)
        .await
        .err()
        .map(|source| InfraError::query("创建 Desktop Local 固定 OpenBot 数据库", source));
    let Some(facts) = read_database_facts(client).await? else {
        return Err(create_error.map_or(
            DesktopLocalDatabaseError::ShapeInvalid,
            DesktopLocalDatabaseError::Create,
        ));
    };
    if !facts.is_exact() {
        return Err(DesktopLocalDatabaseError::ShapeInvalid);
    }
    Ok(if create_error.is_some() {
        DesktopLocalDatabaseOrigin::ReconciledAfterCreateError
    } else {
        DesktopLocalDatabaseOrigin::Created
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DatabaseFacts {
    owner: String,
    encoding: String,
    collate: String,
    ctype: String,
    is_template: bool,
    allow_connections: bool,
    connection_limit: i32,
}

impl DatabaseFacts {
    fn is_exact(&self) -> bool {
        self.owner == DESKTOP_LOCAL_POSTGRES_ADMIN_USER
            && self.encoding == "UTF8"
            && self.collate == "C"
            && self.ctype == "C"
            && !self.is_template
            && self.allow_connections
            && self.connection_limit == -1
    }
}

async fn read_database_facts(
    client: &Client,
) -> Result<Option<DatabaseFacts>, DesktopLocalDatabaseError> {
    let row = client
        .query_opt(DATABASE_FACTS_SQL, &[&APPLICATION_DATABASE])
        .await
        .map_err(|source| {
            DesktopLocalDatabaseError::Inspect(InfraError::query(
                "读取 Desktop Local 固定数据库事实",
                source,
            ))
        })?;
    let Some(row) = row else {
        return Ok(None);
    };
    let decode = || {
        Some(DatabaseFacts {
            owner: row.try_get(0).ok()?,
            encoding: row.try_get(1).ok()?,
            collate: row.try_get(2).ok()?,
            ctype: row.try_get(3).ok()?,
            is_template: row.try_get(4).ok()?,
            allow_connections: row.try_get(5).ok()?,
            connection_limit: row.try_get(6).ok()?,
        })
    };
    decode()
        .map(Some)
        .ok_or(DesktopLocalDatabaseError::ShapeInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_config_and_secret_shape_are_closed() {
        let secret = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let config = local_config(54321, secret, LocalDatabase::Application);
        let reference = super::super::pool::DatabaseConfig::new(
            HOST,
            54321,
            DESKTOP_LOCAL_POSTGRES_ADMIN_USER,
            APPLICATION_DATABASE,
        )
        .with_password(std::str::from_utf8(secret).unwrap())
        .with_application_name(APPLICATION_NAME)
        .to_pg_config();
        assert_eq!(config, reference);
        assert_eq!(
            config.get_hosts(),
            &[tokio_postgres::config::Host::Tcp(HOST.to_owned())]
        );
        assert_eq!(config.get_ports(), &[54321]);
        assert_eq!(config.get_user(), Some(DESKTOP_LOCAL_POSTGRES_ADMIN_USER));
        assert_eq!(config.get_dbname(), Some(APPLICATION_DATABASE));
        assert_eq!(config.get_password(), Some(secret.as_slice()));
        assert_eq!(config.get_application_name(), Some(APPLICATION_NAME));
        assert_eq!(config.get_connect_timeout(), Some(&CONNECT_TIMEOUT));
        assert!(
            CREATE_APPLICATION_DATABASE_SQL
                .contains(&format!("OWNER={DESKTOP_LOCAL_POSTGRES_ADMIN_USER}"))
        );
        assert!(valid_scram_secret(secret));
        assert!(!valid_scram_secret(&secret[..63]));
        assert!(!valid_scram_secret(
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF"
        ));
    }

    #[test]
    fn exact_database_shape_rejects_each_widening() {
        let exact = DatabaseFacts {
            owner: DESKTOP_LOCAL_POSTGRES_ADMIN_USER.to_owned(),
            encoding: "UTF8".to_owned(),
            collate: "C".to_owned(),
            ctype: "C".to_owned(),
            is_template: false,
            allow_connections: true,
            connection_limit: -1,
        };
        assert!(exact.is_exact());
        for changed in [
            DatabaseFacts {
                owner: "other".to_owned(),
                ..exact.clone()
            },
            DatabaseFacts {
                encoding: "LATIN1".to_owned(),
                ..exact.clone()
            },
            DatabaseFacts {
                collate: "en_US.UTF-8".to_owned(),
                ..exact.clone()
            },
            DatabaseFacts {
                is_template: true,
                ..exact.clone()
            },
            DatabaseFacts {
                allow_connections: false,
                ..exact.clone()
            },
            DatabaseFacts {
                connection_limit: 0,
                ..exact.clone()
            },
        ] {
            assert!(!changed.is_exact());
        }
    }
}
