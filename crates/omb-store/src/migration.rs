use crate::{StoreError, command, finish, rows, timely};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tokio_postgres::Client;
const INITIAL: &[u8] = include_bytes!("../migrations/omb_0001_initial.sql");
const NAME: &str = "omb_0001_initial.sql";
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
    let result=async {
        command(client,"BEGIN",deadline,error).await?;
        lock(client,deadline).await?;
        let history=rows(client,"SELECT version,name,sha256 FROM openmybot.omb_migrations ORDER BY version",&[],deadline,error).await?;
        let digest=Sha256::digest(INITIAL).to_vec();let mut applied=false;
        for row in history {
            let version:i32=row.try_get(0).map_err(|_|error)?;
            if version!=1 {return Err(StoreError::SchemaNewer);}
            let name:String=row.try_get(1).map_err(|_|error)?;
            let stored:Vec<u8>=row.try_get(2).map_err(|_|error)?;
            if name!=NAME || stored!=digest {return Err(StoreError::MigrationDrift);}
            applied=true;
        }
        let applied_count=if applied {0} else {
            let sql=std::str::from_utf8(INITIAL).map_err(|_|error)?;
            command(client,sql,deadline,error).await?;
            rows(client,"INSERT INTO openmybot.omb_migrations(version,name,sha256,applied_at) VALUES (1,$1,$2,statement_timestamp()) RETURNING version",&[&NAME,&digest],deadline,error).await?;
            1
        };
        timely(deadline,Ok(MigrationReport{applied_count,current_version:1}),error)
    }.await;
    finish(client, deadline, result, error).await
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
        let file = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("migrations/omb_0001_initial.sql"),
        )
        .unwrap();
        assert_eq!(INITIAL, file);
        assert_eq!(Sha256::digest(INITIAL), Sha256::digest(file));
    }
}
