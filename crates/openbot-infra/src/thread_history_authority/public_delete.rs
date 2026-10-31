//! Public deletion of one Thread's history by its current creator. Every call starts with the
//! stop/clear intent producer (ACK1, first call or exact replay), then drains once, clears in
//! bounded batches until the clearing completes or must wait, and only after completion soft
//! deletes the Thread under the same operation. A call never sleeps or polls: an unfinished step
//! is answered `Pending`, and the caller resumes it by resending the same request id. The
//! resumption is authorised again by that call's own ACK1 replay; nothing here runs without it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::ThreadHistoryDeletion;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{ThreadHistoryDeletionReceipt, ThreadHistoryDeletionState};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::ThreadId;
use openbot_contracts::request_binding::HostRequestBindingError;
use time::OffsetDateTime;

use super::{
    PostgresThreadHistoryAuthority, ThreadHistoryClearProgress,
    ThreadHistoryStopClearError as StopError,
};
use crate::db::pool::TransactionOwnerError;

/// The whole budget of one call. ACK1, the drain and each clearing batch keep their own 5 s caps
/// inside it.
const DELETION_BUDGET: Duration = Duration::from_secs(10);

/// This request's own stop/clear intent on the exact J, and the stop/clear completion of its
/// operation. Parameters: deployment, tenant, thread, request, actor.
macro_rules! cleared_by_this_request {
    () => {
        "EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_intents q \
         JOIN openbot_internal.thread_history_clear_completions c \
         ON c.operation_id=q.operation_id AND c.source='stop_clear' \
         WHERE q.deployment_id=$1 AND q.tenant_id=$2 AND q.thread_id=$3 \
         AND q.request_id=$4 AND q.actor_id=$5 AND q.intent_kind='stop_clear')"
    };
}

/// The column assignments of `ThreadRepo::soft_delete`, on the full J and only behind the gate.
const SOFT_DELETE: &str = concat!(
    "UPDATE public.threads SET status='deleted',deleted_at=coalesce(deleted_at,$6),\
     updated_at=CASE WHEN status='deleted' THEN updated_at ELSE $6 END \
     WHERE deployment_id=$1 AND tenant_id=$2 AND thread_id=$3 AND status<>'deleted' AND ",
    cleared_by_this_request!()
);
/// After zero updated rows: whether an identical call already soft deleted J behind the gate.
const ALREADY_DELETED: &str = concat!(
    "SELECT status='deleted' AND ",
    cleared_by_this_request!(),
    " AS cleared FROM public.threads WHERE deployment_id=$1 AND tenant_id=$2 AND thread_id=$3"
);

#[async_trait]
impl ThreadHistoryDeletion for PostgresThreadHistoryAuthority {
    async fn delete_thread_history_before(
        self: Arc<Self>,
        auth: &AuthContext,
        thread_id: &ThreadId,
        request_id: &str,
    ) -> Result<ThreadHistoryDeletionReceipt, AppError> {
        let state = self.delete_history(auth, thread_id, request_id).await?;
        Ok(ThreadHistoryDeletionReceipt {
            thread_id: thread_id.clone(),
            request_id: request_id.to_owned(),
            state,
        })
    }
}

impl PostgresThreadHistoryAuthority {
    async fn delete_history(
        self: &Arc<Self>,
        auth: &AuthContext,
        thread_id: &ThreadId,
        request_id: &str,
    ) -> Result<ThreadHistoryDeletionState, AppError> {
        let deadline =
            Instant::now()
                .checked_add(DELETION_BUDGET)
                .ok_or(AppError::DependencyUnavailable {
                    dependency: "thread_history",
                })?;
        if let Err(error) = self
            .close_for_stop_clear_before(auth, thread_id.as_str(), request_id, deadline)
            .await
        {
            return deletion_outcome(error, false);
        }
        self.advance_deletion(auth, thread_id, request_id, deadline)
            .await
            .or_else(|error| deletion_outcome(error, true))
    }

    /// Everything after an acknowledged ACK1 of this call. The intent is durable here, so only
    /// corruption is final; every other stop is resumed by the same request id.
    async fn advance_deletion(
        self: &Arc<Self>,
        auth: &AuthContext,
        thread_id: &ThreadId,
        request_id: &str,
        deadline: Instant,
    ) -> Result<ThreadHistoryDeletionState, StopError> {
        let thread = thread_id.as_str();
        self.drain_closed_history_runs_before(thread, deadline)
            .await?;
        loop {
            match self.clear_closed_history_before(thread, deadline).await? {
                ThreadHistoryClearProgress::BatchCommitted { .. } if Instant::now() < deadline => {}
                ThreadHistoryClearProgress::BatchCommitted { .. }
                | ThreadHistoryClearProgress::AwaitingDrain
                | ThreadHistoryClearProgress::AwaitingReaders => {
                    return Ok(ThreadHistoryDeletionState::Pending);
                }
                ThreadHistoryClearProgress::Completed { .. } => break,
            }
        }
        self.soft_delete_cleared(auth, thread, request_id, deadline)
            .await
    }

    /// One short transaction with one gated UPDATE. Zero rows is `Cleared` only when an identical
    /// call already soft deleted J behind the same gate; anything else is a broken binding.
    async fn soft_delete_cleared(
        &self,
        auth: &AuthContext,
        thread: &str,
        request_id: &str,
        deadline: Instant,
    ) -> Result<ThreadHistoryDeletionState, StopError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| StopError::Unavailable)?;
        let original = client.begin_read_committed().await.map_err(owner)?;
        let tx = original.as_transaction();
        let (deployment, tenant, actor) = (
            self.deployment.as_str(),
            self.tenant.as_str(),
            auth.actor().as_str(),
        );
        let now = OffsetDateTime::now_utc();
        let at = tokio::time::Instant::from_std(deadline);
        let result = async {
            let updated = tokio::time::timeout_at(
                at,
                tx.execute(
                    SOFT_DELETE,
                    &[&deployment, &tenant, &thread, &request_id, &actor, &now],
                ),
            )
            .await
            .map_err(|_| StopError::Unavailable)?
            .map_err(|_| StopError::Unavailable)?;
            if updated == 1 {
                return Ok(());
            }
            let row = tokio::time::timeout_at(
                at,
                tx.query_opt(
                    ALREADY_DELETED,
                    &[&deployment, &tenant, &thread, &request_id, &actor],
                ),
            )
            .await
            .map_err(|_| StopError::Unavailable)?
            .map_err(|_| StopError::Unavailable)?;
            let cleared = row
                .map(|row| row.try_get::<_, bool>("cleared"))
                .transpose()
                .map_err(|_| StopError::Corrupt {
                    field: "row_decode",
                })?;
            if cleared == Some(true) {
                Ok(())
            } else {
                Err(StopError::Corrupt {
                    field: "history_binding",
                })
            }
        }
        .await;
        match result {
            Ok(()) => original.commit().await.map_err(owner)?,
            Err(error) => {
                original.rollback().await.map_err(owner)?;
                return Err(error);
            }
        }
        Ok(ThreadHistoryDeletionState::Cleared)
    }
}

fn owner(error: TransactionOwnerError) -> StopError {
    match error {
        TransactionOwnerError::AlreadyStarted => StopError::AlreadyStarted,
        TransactionOwnerError::DeadlineExceeded => StopError::DeadlineExceeded,
        TransactionOwnerError::BeginUnavailable => StopError::BeginUnavailable,
        TransactionOwnerError::CommitUnknown => StopError::CommitUnknown,
        TransactionOwnerError::RollbackUnproven => StopError::RollbackUnproven,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            StopError::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            StopError::RollbackAcknowledgedAfterDeadline
        }
    }
}

/// The public outcome of a refused step. `stored` is whether this call's ACK1 was acknowledged:
/// then the intent is durable, only corruption is final and every other stop is `Pending`.
fn deletion_outcome(
    error: StopError,
    stored: bool,
) -> Result<ThreadHistoryDeletionState, AppError> {
    let unavailable = AppError::DependencyUnavailable {
        dependency: "thread_history",
    };
    match error {
        StopError::Corrupt { .. } => Err(unavailable),
        _ if stored => Ok(ThreadHistoryDeletionState::Pending),
        StopError::InvalidInput {
            field: "request_id",
        } => Err(AppError::MalformedPayload { field: "requestId" }),
        StopError::InvalidInput { .. } => Err(AppError::MalformedPayload { field: "threadId" }),
        // The existing Host binding projection: a closed Host is unauthenticated, a missing or
        // unavailable binding is an unavailable dependency.
        StopError::Host(HostRequestBindingError::NotCurrent) => Err(AppError::Unauthenticated),
        StopError::Host(
            HostRequestBindingError::Missing | HostRequestBindingError::Unavailable,
        ) => Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        }),
        StopError::NotVisible => Err(AppError::NotVisible),
        StopError::Conflict => Err(AppError::RequestConflict {
            resource: "thread_history",
        }),
        StopError::CommitUnknown => Err(AppError::ReconciliationRequired { accepted: true }),
        // The intent is stored; this call stops here and a resend resumes it.
        StopError::CommitAcknowledgedAfterDeadline => Ok(ThreadHistoryDeletionState::Pending),
        // No write of these paths is retained, so a resend is safe.
        StopError::Unavailable
        | StopError::BeginUnavailable
        | StopError::DeadlineExceeded
        | StopError::AlreadyStarted
        | StopError::RollbackUnproven
        | StopError::RollbackAcknowledgedAfterDeadline => Err(unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant of the closed producer error, each Host reason separately.
    const EVERY_ERROR: [StopError; 16] = [
        StopError::InvalidInput { field: "thread_id" },
        StopError::InvalidInput {
            field: "request_id",
        },
        StopError::Host(HostRequestBindingError::Missing),
        StopError::Host(HostRequestBindingError::NotCurrent),
        StopError::Host(HostRequestBindingError::Unavailable),
        StopError::NotVisible,
        StopError::Conflict,
        StopError::Unavailable,
        StopError::Corrupt {
            field: "history_binding",
        },
        StopError::AlreadyStarted,
        StopError::DeadlineExceeded,
        StopError::BeginUnavailable,
        StopError::CommitUnknown,
        StopError::RollbackUnproven,
        StopError::CommitAcknowledgedAfterDeadline,
        StopError::RollbackAcknowledgedAfterDeadline,
    ];

    fn unavailable() -> Result<ThreadHistoryDeletionState, AppError> {
        Err(AppError::DependencyUnavailable {
            dependency: "thread_history",
        })
    }

    #[test]
    fn ack1_refusals_map_to_the_public_outcome_table() {
        let host_unavailable = Err(AppError::DependencyUnavailable {
            dependency: "host_request_binding",
        });
        let expected = [
            Err(AppError::MalformedPayload { field: "threadId" }),
            Err(AppError::MalformedPayload { field: "requestId" }),
            host_unavailable.clone(),
            Err(AppError::Unauthenticated),
            host_unavailable,
            Err(AppError::NotVisible),
            Err(AppError::RequestConflict {
                resource: "thread_history",
            }),
            unavailable(),
            unavailable(),
            unavailable(),
            unavailable(),
            unavailable(),
            Err(AppError::ReconciliationRequired { accepted: true }),
            unavailable(),
            Ok(ThreadHistoryDeletionState::Pending),
            unavailable(),
        ];
        for (error, expected) in EVERY_ERROR.into_iter().zip(expected) {
            assert_eq!(deletion_outcome(error, false), expected, "{error:?}");
        }
        let statuses = EVERY_ERROR
            .into_iter()
            .map(|error| match deletion_outcome(error, false) {
                Ok(_) => 202,
                Err(error) => error.http_status(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            [
                400, 400, 503, 401, 503, 404, 409, 503, 503, 503, 503, 503, 202, 503, 202, 503
            ]
        );
    }

    #[test]
    fn after_a_stored_intent_only_corruption_is_final() {
        for error in EVERY_ERROR {
            let expected = if matches!(error, StopError::Corrupt { .. }) {
                unavailable()
            } else {
                Ok(ThreadHistoryDeletionState::Pending)
            };
            assert_eq!(deletion_outcome(error, true), expected, "{error:?}");
        }
    }
}
