//! Same-transaction persistent admission for history body writers.
//!
//! This storage observation grants no user, creator, lease or clear authority.

use openbot_contracts::ids::ThreadId;
use tokio_postgres::{Transaction, error::SqlState};

use crate::db::{InfraError, RowDecodeError, native};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenOrClosed {
    Open,
    Closed,
}

/// Proof that the strict current native prefix and the complete writer schema were
/// observed by an earlier statement of one original transaction.
///
/// The observation takes no row lock, so a writer obtains it before its first row
/// lock and every later admission on the same transaction consumes it. It is a
/// point-in-time catalog fact; enabled database guards still check every DML.
pub(crate) struct CurrentWriterSchema<'t, 'c> {
    tx: &'t Transaction<'c>,
}

impl<'t, 'c> CurrentWriterSchema<'t, 'c> {
    pub(crate) async fn observe(tx: &'t Transaction<'c>) -> Result<Self, InfraError> {
        verify_current_in_transaction(tx).await?;
        Ok(Self { tx })
    }

    /// The physical Thread joint and H SHARE on the same original transaction.
    pub(crate) async fn lock_thread_write_disposition(
        &self,
        tx: &Transaction<'_>,
        thread_id: &ThreadId,
    ) -> Result<OpenOrClosed, InfraError> {
        // A proof from another transaction never admits this one.
        if !std::ptr::eq(
            std::ptr::from_ref(self.tx).cast::<()>(),
            std::ptr::from_ref(tx).cast::<()>(),
        ) {
            return Err(InfraError::repository_invariant(
                "thread_history_writer_schema_unbound",
            ));
        }
        // The checked function obtains the actual physical Thread joint, lazily
        // registers only its open metadata and retains H SHARE on this original Tx.
        // Its original unique wait is followed by a separate RC observation; it
        // leaves SERIALIZABLE unchanged and preserves natural serialization errors.
        let row = tx
            .query_one(
                "SELECT openbot_internal.thread_history_lock_joint($1,NULL::text) AS is_open",
                &[&thread_id.as_str()],
            )
            .await
            .map_err(|source| query_error("锁定历史正文写入准入", source))?;
        let open: bool = row.try_get("is_open").map_err(|source| {
            RowDecodeError::column("(thread_history_writer)", "is_open", source)
        })?;
        Ok(if open {
            OpenOrClosed::Open
        } else {
            OpenOrClosed::Closed
        })
    }

    pub(crate) async fn require_open(
        &self,
        tx: &Transaction<'_>,
        thread_id: &ThreadId,
    ) -> Result<(), InfraError> {
        match self.lock_thread_write_disposition(tx, thread_id).await? {
            OpenOrClosed::Open => Ok(()),
            OpenOrClosed::Closed => Err(InfraError::repository_invariant(
                "thread_history_writer_closed",
            )),
        }
    }
}

/// Observe and admit in one call, for a writer that holds no row lock yet.
#[cfg(feature = "server-runtime")]
pub(crate) async fn require_open(
    tx: &Transaction<'_>,
    thread_id: &ThreadId,
) -> Result<(), InfraError> {
    CurrentWriterSchema::observe(tx)
        .await?
        .require_open(tx, thread_id)
        .await
}

async fn verify_current_in_transaction(tx: &Transaction<'_>) -> Result<(), InfraError> {
    native::validate_thread_origin_in_transaction(tx).await
}

/// Only the one frozen, payload-free database refusal is classified as closed.
pub(crate) fn is_closed_query(error: &tokio_postgres::Error) -> bool {
    error.as_db_error().is_some_and(|db| {
        db.code() == &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE
            && db.message() == "thread_history_writer_closed"
    })
}

pub(crate) fn query_error(context: &'static str, error: tokio_postgres::Error) -> InfraError {
    if is_closed_query(&error) {
        InfraError::repository_invariant("thread_history_writer_closed")
    } else {
        InfraError::query(context, error)
    }
}

#[cfg(feature = "server-runtime")]
pub(crate) fn is_closed(error: &InfraError) -> bool {
    matches!(
        error,
        InfraError::RepositoryInvariant {
            code: "thread_history_writer_closed"
        }
    )
}
