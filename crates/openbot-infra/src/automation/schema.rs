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
