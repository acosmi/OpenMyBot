//! Product-owned PostgreSQL migrations, control-token records, pairing and binding lifecycle.
mod bindings;
mod control_tokens;
mod migration;
mod pairing;

pub use bindings::{
    AuthorityRow, GrantKind, HostBinding, IdentityKey, RunDeadline, activate_host, authority_row,
    reconfirm_binding, revoke_binding,
};
pub use control_tokens::{
    ControlTokenRecord, ControlTokenStart, start_control_token, stop_control_token,
};
pub use migration::{MigrationReport, migrate};
pub use pairing::{
    AcceptedEvent, Channel, PairAttempt, PairCode, PairOutcome, PairStart, PairStarted,
    pair_attempt, pair_start,
};

pub const KEY_MAX: usize = 128;
pub const PAIR_CODE_LEN: usize = 8;
pub const PAIR_TTL: std::time::Duration = std::time::Duration::from_secs(600);
pub const PAIR_FAIL_LIMIT: i64 = 5;
/// Lock duration after the limit is reached; also the window the failures must fall within.
pub const PAIR_LOCK: std::time::Duration = std::time::Duration::from_secs(3600);
pub const RUN_DEADLINE_MAX: u32 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("omb_migration_drift")]
    MigrationDrift,
    #[error("omb_schema_newer")]
    SchemaNewer,
    #[error("omb_migration_failed")]
    MigrationFailed,
    #[error("control_token_failed")]
    ControlTokenFailed,
    #[error("channel_already_bound")]
    ChannelAlreadyBound,
    #[error("receiver_not_active")]
    ReceiverNotActive,
    #[error("binding_not_found")]
    BindingNotFound,
    #[error("binding_state_invalid")]
    BindingStateInvalid,
    #[error("binding_failed")]
    BindingFailed,
}

pub(crate) fn timely<T>(
    deadline: tokio::time::Instant,
    result: Result<T, StoreError>,
    error: StoreError,
) -> Result<T, StoreError> {
    match result {
        Err(original) => Err(original),
        Ok(_) if tokio::time::Instant::now() >= deadline => Err(error),
        Ok(value) => Ok(value),
    }
}
pub(crate) async fn command(
    client: &tokio_postgres::Client,
    sql: &str,
    deadline: tokio::time::Instant,
    error: StoreError,
) -> Result<(), StoreError> {
    timely(deadline, Ok(()), error)?;
    let result = tokio::time::timeout_at(deadline, client.batch_execute(sql))
        .await
        .map_err(|_| error)?
        .map_err(|_| error);
    timely(deadline, result, error)
}
pub(crate) async fn finish<T>(
    client: &tokio_postgres::Client,
    deadline: tokio::time::Instant,
    result: Result<T, StoreError>,
    error: StoreError,
) -> Result<T, StoreError> {
    let result = match result {
        Ok(value) => command(client, "COMMIT", deadline, error)
            .await
            .map(|()| value),
        Err(error) => Err(error),
    };
    if result.is_err() {
        // The caller still owns Client/driver. Even a lost COMMIT reply is a failure; a bounded
        // rollback acknowledgement does not turn it into a retry or claim that commit did not occur.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.batch_execute("ROLLBACK"),
        )
        .await;
    }
    timely(deadline, result, error)
}
pub(crate) async fn rows(
    client: &tokio_postgres::Client,
    sql: &str,
    parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    deadline: tokio::time::Instant,
    error: StoreError,
) -> Result<Vec<tokio_postgres::Row>, StoreError> {
    timely(deadline, Ok(()), error)?;
    let result = tokio::time::timeout_at(deadline, client.query(sql, parameters))
        .await
        .map_err(|_| error)?
        .map_err(|_| error);
    timely(deadline, result, error)
}
/// Like [`rows`], but a unique-constraint violation becomes `conflict`.
pub(crate) async fn unique_rows(
    client: &tokio_postgres::Client,
    sql: &str,
    parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    deadline: tokio::time::Instant,
    conflict: StoreError,
    error: StoreError,
) -> Result<Vec<tokio_postgres::Row>, StoreError> {
    timely(deadline, Ok(()), error)?;
    let result = tokio::time::timeout_at(deadline, client.query(sql, parameters))
        .await
        .map_err(|_| error)?
        .map_err(|failure| {
            if failure.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                conflict
            } else {
                error
            }
        });
    timely(deadline, result, error)
}
