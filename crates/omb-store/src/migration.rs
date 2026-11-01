use crate::{StoreError, command, finish, rows, timely};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tokio_postgres::Client;
/// Embedded migrations in ascending version order, numbered from 1 without gaps.
const MIGRATIONS: &[(i32, &str, &[u8])] = &[
    (
        1,
        "omb_0001_initial.sql",
        include_bytes!("../migrations/omb_0001_initial.sql"),
    ),
    (
        2,
        "omb_0002_open_channel_kind.sql",
        include_bytes!("../migrations/omb_0002_open_channel_kind.sql"),
    ),
];
const BOOTSTRAP: &str = "CREATE SCHEMA IF NOT EXISTS openmybot; CREATE TABLE IF NOT EXISTS openmybot.omb_migrations(version integer PRIMARY KEY,name text NOT NULL,sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),applied_at timestamptz NOT NULL)";
#[derive(Debug, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied_count: u32,
    pub current_version: i32,
}
fn lock_key() -> i64 {
    let digest = Sha256::digest(b"openmybot.migrations");
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes)
}
async fn lock(client: &Client, deadline: Instant) -> Result<(), StoreError> {
    rows(
        client,
        "SELECT pg_advisory_xact_lock($1)",
        &[&lock_key()],
        deadline,
        StoreError::MigrationFailed,
    )
    .await
    .map(|_| ())
}
pub async fn migrate(
    client: &mut Client,
    deadline: Instant,
) -> Result<MigrationReport, StoreError> {
    let error = StoreError::MigrationFailed;
    // The exclusive mutable client loan prevents another operation sharing these transactions.
    let bootstrap = async {
        command(client, "BEGIN", deadline, error).await?;
        lock(client, deadline).await?;
        command(client, BOOTSTRAP, deadline, error).await
    }
    .await;
    finish(client, deadline, bootstrap, error).await?;
    let history = async {
        command(client, "BEGIN", deadline, error).await?;
        lock(client, deadline).await?;
        let history = rows(
            client,
            "SELECT version,name,sha256 FROM openmybot.omb_migrations ORDER BY version",
            &[],
            deadline,
            error,
        )
        .await?;
        for (index, row) in history.iter().enumerate() {
            let version: i32 = row.try_get(0).map_err(|_| error)?;
            let Some(&(_, name, sql)) = MIGRATIONS.iter().find(|m| m.0 == version) else {
                return Err(StoreError::SchemaNewer);
            };
            let stored_name: String = row.try_get(1).map_err(|_| error)?;
            let stored: Vec<u8> = row.try_get(2).map_err(|_| error)?;
            if MIGRATIONS[index].0 != version
                || stored_name != name
                || stored != Sha256::digest(sql).as_slice()
            {
                return Err(StoreError::MigrationDrift);
            }
        }
        Ok(history.len())
    }
    .await;
    let applied = finish(client, deadline, history, error).await?;
    let mut applied_count = 0;
    for &(version, name, sql) in &MIGRATIONS[applied..] {
        let result = async {
            command(client, "BEGIN", deadline, error).await?;
            lock(client, deadline).await?;
            // A concurrent migrator may have applied this file after the history was read.
            let done = rows(
                client,
                "SELECT 1 FROM openmybot.omb_migrations WHERE version=$1",
                &[&version],
                deadline,
                error,
            )
            .await?;
            if !done.is_empty() {
                return Ok(0);
            }
            command(client, std::str::from_utf8(sql).map_err(|_| error)?, deadline, error).await?;
            rows(client, "INSERT INTO openmybot.omb_migrations(version,name,sha256,applied_at) VALUES ($1,$2,$3,statement_timestamp()) RETURNING version", &[&version, &name, &Sha256::digest(sql).to_vec()], deadline, error).await?;
            timely(deadline, Ok(1), error)
        }
        .await;
        applied_count += finish(client, deadline, result, error).await?;
    }
    Ok(MigrationReport {
        applied_count,
        current_version: MIGRATIONS[MIGRATIONS.len() - 1].0,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_lock_key_matches_big_endian_sha256() {
        assert_eq!(lock_key(), 8752007243381909980_i64);
    }
    #[test]
    fn embedded_initial_migration_hash_is_exact_file_bytes() {
        for &(_, name, sql) in MIGRATIONS {
            let file = std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("migrations")
                    .join(name),
            )
            .unwrap();
            assert_eq!(sql, file);
            assert_eq!(Sha256::digest(sql), Sha256::digest(file));
        }
    }
}
