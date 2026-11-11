//! Exact current automation catalog; the registered snapshot is never learned at runtime.

use crate::db::{InfraError, RowDecodeError};
use serde_json::Value;
use tokio_postgres::GenericClient;

const CAPTURE_SQL: &str = include_str!("schema.sql");
const REGISTERED_SCHEMA: &str = include_str!("schema-0054.json");

/// Read the exact automation relations and their structural dependencies without changing them.
///
/// # Errors
/// Database or catalog decoding failure returns a redacted infrastructure error.
pub async fn capture(client: &impl GenericClient) -> Result<Value, InfraError> {
    let row = client
        .query_one(CAPTURE_SQL, &[])
        .await
        .map_err(|source| InfraError::query("observe automation schema", source))?;
    row.try_get(0).map_err(|source| {
        RowDecodeError::column("(automation schema)", "jsonb_build_object", source).into()
    })
}

/// Reject any deviation from the frozen current catalog, including extra objects and ACLs.
///
/// # Errors
/// A missing, changed or unreadable catalog is never accepted as current.
pub async fn verify(client: &impl GenericClient) -> Result<(), InfraError> {
    let expected: Value = serde_json::from_str(REGISTERED_SCHEMA)
        .map_err(|_| InfraError::repository_invariant("automation_schema_oracle_invalid"))?;
    if capture(client).await? != expected {
        return Err(InfraError::repository_invariant(
            "automation_schema_invalid",
        ));
    }
    Ok(())
}

/// Registered oracle text length; [`verify`] holds at most one parsed tree at a time.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) const ORACLE_BYTES: u64 = REGISTERED_SCHEMA.len() as u64;

/// Payload text length one [`verify`] observes, measured on the same transaction before it runs.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) async fn observation_bytes_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<u64, InfraError> {
    let row = tx
        .query_one(
            &format!(
                "SELECT coalesce(octet_length(observed.facts::text),0)::bigint FROM ({}) observed(facts)",
                CAPTURE_SQL.trim_end().trim_end_matches(';')
            ),
            &[],
        )
        .await
        .map_err(|source| InfraError::query("measure automation schema observation", source))?;
    let payload: i64 = row
        .try_get(0)
        .map_err(|source| RowDecodeError::column("(automation schema)", "bytes", source))?;
    u64::try_from(payload)
        .map_err(|_| InfraError::repository_invariant("automation_schema_invalid"))
}
