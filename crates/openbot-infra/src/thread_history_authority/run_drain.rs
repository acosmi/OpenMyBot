//! Trusted system drain of a closed Thread history's in-flight Runs. It only requests the stop:
//! one durable cancellation acceptance per non-terminal Run of the Thread. The existing
//! cancellation consumer settles each accepted Run through the existing closed-history finish,
//! which ends it cancelled and writes no body. Nothing here stops a worker itself, clears or
//! deletes any copy, expires any output, or writes a thread history, quota or artifact fact.
//!
//! H is the Thread's history admission head row and Q its immutable intent row. The drain carries
//! no Auth context and no Host binding: like the cancellation claim, the dispatch claim and the
//! lease recovery it is a system action. It trusts only this authority's own pool, deployment and
//! tenant, and the closed H and its Q read from the database.

use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_contracts::ids::ThreadId;
use openbot_contracts::ids::thread::ThreadIdentity;
use serde_json::Value;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::{FromSqlOwned, ToSql};
use tokio_postgres::{Row, Transaction};

use super::{PostgresThreadHistoryAuthority, ThreadHistoryStopClearError};
use crate::db::pool::TransactionOwnerError;
use crate::run_runtime::{
    RUN_CANCEL_DESTINATION, RUN_CONTROL_TOPIC, RunCancelAcceptance, run_cancel_acceptance,
    run_cancel_outbox_id, thread_history_closed_cancel_payload,
};

type DrainError = ThreadHistoryStopClearError;

/// The longest the drain waits for a lock, and the initial budget of one call.
const BUDGET: Duration = Duration::from_secs(5);

/// What one call did. It is neither a lease nor an ACK2, clearing, deletion or Ready fact, and it
/// has no public constructor. [`Self::is_complete`] is the only completion criterion: the Thread
/// had no queued or running Run when the call last counted them.
pub struct ThreadHistoryRunDrain {
    operation_id: String,
    newly_requested: usize,
    already_requested: usize,
    outstanding_nonterminal: usize,
}
impl ThreadHistoryRunDrain {
    /// The stored intent's operation id that every system acceptance of this Thread names.
    #[must_use]
    pub const fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }
    /// Runs whose acceptance this call wrote and committed.
    #[must_use]
    pub const fn newly_requested(&self) -> usize {
        self.newly_requested
    }
    /// Non-terminal Runs that already had their one pending or delivering acceptance, of either
    /// lawful shape. A user's own request is satisfied as it is and is never overwritten.
    #[must_use]
    pub const fn already_requested(&self) -> usize {
        self.already_requested
    }
    /// Queued or running Runs of the Thread counted after the last Run was handled. Accepted Runs
    /// stay counted until the consumer, or a writer that committed first, ends them.
    #[must_use]
    pub const fn outstanding_nonterminal(&self) -> usize {
        self.outstanding_nonterminal
    }
    /// Whether the Thread had no queued or running Run at that last count.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.outstanding_nonterminal == 0
    }
}
impl core::fmt::Debug for ThreadHistoryRunDrain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ThreadHistoryRunDrain(<one-J-run-drain:{}>)",
            if self.is_complete() {
                "complete"
            } else {
                "incomplete"
            }
        )
    }
}

/// What one Run's short transaction decided; only `Requested` ends in COMMIT.
enum Outcome {
    /// This transaction inserted the system acceptance.
    Requested,
    /// The Run already had its one pending or delivering acceptance.
    AlreadyRequested,
    /// The Run was gone or already terminal when its row was locked: the first committer won.
    Settled,
}

/// H closed by its own Q, for this Thread in this deployment and tenant. It takes no lock.
const CLOSED_INTENT: &str = "SELECT q.operation_id FROM openbot_internal.thread_history_heads h \
    JOIN openbot_internal.thread_history_clear_intents q \
      ON q.deployment_id=h.deployment_id AND q.tenant_id=h.tenant_id AND q.thread_id=h.thread_id \
     AND q.operation_id=h.closure_operation_id \
    WHERE h.deployment_id=$1 AND h.tenant_id=$2 AND h.thread_id=$3 AND h.phase='closed'";
/// Every Run of the Thread that can still act: production writes `running` directly, so a `queued`
/// row is a broken one that the per-Run step refuses. Reconciliation-required is terminal.
const NONTERMINAL_RUNS: &str = "SELECT r.run_id FROM public.runs r WHERE r.thread_id=$1 \
    AND r.status IN ('queued','running') ORDER BY r.created_at,r.run_id";
const COUNT_NONTERMINAL: &str = "SELECT count(*) AS outstanding FROM public.runs r \
    WHERE r.thread_id=$1 AND r.status IN ('queued','running')";
/// The only row lock of the drain. It never waits and takes no other row.
const LOCK_RUN: &str = "SELECT run_id,actor_id,status FROM public.runs \
    WHERE run_id=$1 AND thread_id=$2 FOR UPDATE NOWAIT";
/// The Run's one acceptance by its identifier and by its unique delivery key, read without a lock.
const READ_ACCEPTANCE: &str = "SELECT outbox_id,aggregate_kind,aggregate_id,seq,destination,\
    delivery_class,payload,status FROM public.outbox \
    WHERE outbox_id=$1 OR (aggregate_id=$2 AND seq=0 AND destination=$3)";
/// The columns, class, destination and sequence the user's cancellation producer writes.
const INSERT_ACCEPTANCE: &str = "INSERT INTO public.outbox( \
    outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload \
    ) VALUES($1,'run',$2,0,$3,'internal',$4)";

impl PostgresThreadHistoryAuthority {
    /// Request the stop of every in-flight Run of a Thread whose history is closed, by writing
    /// each Run's one durable system cancellation acceptance. Call it after the acknowledged
    /// stop/clear intent; it is safe to call again after any result, and it resumes.
    ///
    /// The acceptance is `{runId,threadId,source:"thread_history_closed",operationId}` with the
    /// intent's operation id and no requester. It grants no user the right to cancel another
    /// member's Run, and it never replaces an existing acceptance: a Run the user already asked
    /// to cancel stays that user's request and only counts as already requested. The existing
    /// consumer later ends each accepted Run as cancelled on the closed-history path. A Run that
    /// another writer ended first keeps the terminal it has. The result separates the Runs
    /// written now, the Runs that were already accepted and the Runs still not terminal.
    ///
    /// Only this authority's pool, deployment and tenant bind the call, and the closed head and
    /// its intent are read from the database; no Auth context, Host or registry is involved and
    /// no writer schema proof is taken, because nothing of Thread history is written. The
    /// deadline is the earlier of `original_deadline` and five seconds from entry, shared by the
    /// whole call.
    ///
    /// # Concurrency
    /// Each Run has its own short READ COMMITTED transaction. Its lock wait limit is the time left
    /// of the shared deadline, never more than five seconds. Its first row lock is `FOR UPDATE
    /// NOWAIT` on the Run row alone, in the same direction as the user's cancellation producer
    /// (Run, then acceptance). The head and the intent are read, and the existing acceptance is
    /// read by the next statement, without any lock, and an existing acceptance row is never
    /// locked: the consumer takes the acceptance first and the Run second, and this adds no
    /// reverse edge and no wait. A custom v2 start that still holds its shared Run lock is
    /// therefore reported as `Unavailable` and is stopped by a later call. A refused lock, a
    /// deadlock, a serialization failure, a lock wait that ran out of time and every other
    /// database failure roll the current Run back and return `Unavailable`; the Runs committed
    /// before it keep their acceptance and nothing is retried here. None of them is `Conflict`
    /// or a closed answer.
    ///
    /// # Errors
    /// Refuses a malformed Thread id, a Thread whose head is not closed in this deployment and
    /// tenant, a `queued` Run or a Run whose acceptance is not a lawful pending or delivering
    /// one (`Corrupt`, never retried into an endless loop), an unavailable or contended database
    /// and every unproven or late transaction acknowledgement.
    pub async fn drain_closed_history_runs_before(
        self: &Arc<Self>,
        thread_id: &str,
        original_deadline: Instant,
    ) -> Result<ThreadHistoryRunDrain, ThreadHistoryStopClearError> {
        let entry = Instant::now();
        let cap = entry.checked_add(BUDGET).ok_or(DrainError::Unavailable)?;
        let deadline = original_deadline.min(cap);
        if thread_id.len() != 36 {
            return Err(DrainError::InvalidInput { field: "thread_id" });
        }
        let thread = ThreadId::new(thread_id);
        if !ThreadIdentity::is_plausible(&thread) {
            return Err(DrainError::InvalidInput { field: "thread_id" });
        }
        remaining(deadline)?;
        if self.pool.is_closed() {
            return Err(DrainError::Unavailable);
        }
        let (operation_id, runs) = self.closed_nonterminal_runs(&thread, deadline).await?;
        let (mut newly_requested, mut already_requested) = (0, 0);
        for run_id in &runs {
            match self
                .request_run_stop(&thread, &operation_id, run_id, deadline)
                .await?
            {
                Outcome::Requested => newly_requested += 1,
                Outcome::AlreadyRequested => already_requested += 1,
                Outcome::Settled => {}
            }
        }
        let outstanding_nonterminal = self.count_nonterminal_runs(&thread, deadline).await?;
        Ok(ThreadHistoryRunDrain {
            operation_id,
            newly_requested,
            already_requested,
            outstanding_nonterminal,
        })
    }

    /// The intent that closed the Thread's head and the Thread's non-terminal Runs, in one
    /// lock-free read-only transaction. A head that is open, absent or not of this namespace is
    /// `NotVisible`, whatever the reason.
    async fn closed_nonterminal_runs(
        &self,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<(String, Vec<String>), DrainError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| DrainError::Unavailable)?;
        let transaction = client.begin_read_committed().await.map_err(owner)?;
        let tx = transaction.as_transaction();
        let result = async {
            let operation_id = self.closed_operation(tx, thread, deadline).await?;
            let runs = rows(tx, deadline, NONTERMINAL_RUNS, &[&thread.as_str()]).await?;
            let runs = runs
                .iter()
                .map(|row| field::<String>(row, "run_id"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((operation_id, runs))
        }
        .await;
        // Even a refusal retains its real terminal acknowledgement before it is returned.
        transaction.rollback().await.map_err(owner)?;
        result
    }

    /// The Thread's non-terminal Runs counted by a last lock-free statement.
    async fn count_nonterminal_runs(
        &self,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<usize, DrainError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| DrainError::Unavailable)?;
        let transaction = client.begin_read_committed().await.map_err(owner)?;
        let result = async {
            let counted = rows(
                transaction.as_transaction(),
                deadline,
                COUNT_NONTERMINAL,
                &[&thread.as_str()],
            )
            .await?;
            let [row] = counted.as_slice() else {
                return Err(corrupt("row_decode"));
            };
            usize::try_from(field::<i64>(row, "outstanding")?).map_err(|_| corrupt("row_decode"))
        }
        .await;
        transaction.rollback().await.map_err(owner)?;
        result
    }

    /// One Run's short transaction. It commits only when it wrote the acceptance; every other
    /// result rolls back, and each waits for its real original acknowledgement.
    async fn request_run_stop(
        &self,
        thread: &ThreadId,
        operation_id: &str,
        run_id: &str,
        deadline: Instant,
    ) -> Result<Outcome, DrainError> {
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| DrainError::Unavailable)?;
        let transaction = client.begin_read_committed().await.map_err(owner)?;
        let result = self
            .stop_one_run(
                transaction.as_transaction(),
                thread,
                operation_id,
                run_id,
                deadline,
            )
            .await;
        if matches!(result, Ok(Outcome::Requested)) {
            transaction.commit().await.map_err(owner)?;
        } else {
            transaction.rollback().await.map_err(owner)?;
        }
        result
    }

    /// The statements of one Run's transaction, in this order and no other: the lock wait limit;
    /// the head and the intent, lock-free; the Run row, `FOR UPDATE NOWAIT`; the Run's acceptance,
    /// lock-free by a new statement after that lock; and only if it is absent, its insert and
    /// notification. The terminal state is decided under the Run lock, so a Run that another
    /// writer ended first keeps the terminal it has.
    async fn stop_one_run(
        &self,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        operation_id: &str,
        run_id: &str,
        deadline: Instant,
    ) -> Result<Outcome, DrainError> {
        // PostgreSQL reads a limit of 0 as no limit at all: the smallest value is one millisecond.
        let left = deadline.saturating_duration_since(Instant::now());
        let millis = left.as_millis().clamp(1, BUDGET.as_millis());
        bounded(
            deadline,
            tx.batch_execute(&format!("SET LOCAL lock_timeout='{millis}ms'")),
        )
        .await?
        .map_err(|_| DrainError::Unavailable)?;
        if self.closed_operation(tx, thread, deadline).await? != operation_id {
            return Err(corrupt("history_binding"));
        }
        let locked = rows(tx, deadline, LOCK_RUN, &[&run_id, &thread.as_str()]).await?;
        let Some(run) = locked.first() else {
            return Ok(Outcome::Settled);
        };
        match field::<String>(run, "status")?.as_str() {
            "completed" | "failed" | "cancelled" | "reconciliation_required" => {
                return Ok(Outcome::Settled);
            }
            "running" => {}
            // Production begins a Run directly as running: a queued row has no proven lease or
            // child and is never made cancellable here. A status no constraint allows is no better.
            _ => return Err(corrupt("run_status")),
        }
        let actor: String = field(run, "actor_id")?;
        let outbox_id = run_cancel_outbox_id(run_id);
        let found = rows(
            tx,
            deadline,
            READ_ACCEPTANCE,
            &[&outbox_id, &run_id, &RUN_CANCEL_DESTINATION],
        )
        .await?;
        match found.as_slice() {
            [] => {}
            [stored] => {
                return existing_acceptance(
                    stored,
                    &outbox_id,
                    run_id,
                    thread.as_str(),
                    &actor,
                    operation_id,
                );
            }
            // Two rows can only be two different identifiers on one delivery key.
            _ => return Err(corrupt("run_cancel_outbox")),
        }
        let payload = thread_history_closed_cancel_payload(run_id, thread.as_str(), operation_id);
        bounded(
            deadline,
            tx.execute(
                INSERT_ACCEPTANCE,
                &[&outbox_id, &run_id, &RUN_CANCEL_DESTINATION, &payload],
            ),
        )
        .await?
        .map_err(|error| insert_error(&error))?;
        rows(
            tx,
            deadline,
            "SELECT pg_notify($1,'')",
            &[&RUN_CONTROL_TOPIC],
        )
        .await?;
        Ok(Outcome::Requested)
    }

    /// The intent that closed this Thread's head, read without a lock. An open head, a missing
    /// head or intent, and a head of another deployment or tenant are all not visible.
    async fn closed_operation(
        &self,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        deadline: Instant,
    ) -> Result<String, DrainError> {
        let found = rows(
            tx,
            deadline,
            CLOSED_INTENT,
            &[
                &self.deployment.as_str(),
                &self.tenant.as_str(),
                &thread.as_str(),
            ],
        )
        .await?;
        match found.as_slice() {
            [row] => field(row, "operation_id"),
            _ => Err(DrainError::NotVisible),
        }
    }
}

/// An acceptance that already exists for a running Run. A lawful one in either shape that is
/// still pending or delivering means the stop is already requested and is left as it is. Anything
/// else is a broken binding: another identifier, a foreign requester, an intent of another
/// operation, or an acceptance that was delivered or dead-lettered while its Run still runs.
fn existing_acceptance(
    stored: &Row,
    outbox_id: &str,
    run_id: &str,
    thread_id: &str,
    actor: &str,
    operation_id: &str,
) -> Result<Outcome, DrainError> {
    let lawful = field::<String>(stored, "outbox_id")? == outbox_id
        && field::<String>(stored, "aggregate_kind")? == "run"
        && field::<String>(stored, "aggregate_id")? == run_id
        && field::<i64>(stored, "seq")? == 0
        && field::<String>(stored, "destination")? == RUN_CANCEL_DESTINATION
        && field::<String>(stored, "delivery_class")? == "internal"
        && match run_cancel_acceptance(&field::<Value>(stored, "payload")?, run_id, thread_id) {
            Some(RunCancelAcceptance::Actor(requested_by)) => requested_by == actor,
            Some(RunCancelAcceptance::ThreadHistoryClosed {
                operation_id: stored_operation,
            }) => stored_operation == operation_id,
            None => false,
        };
    if !lawful {
        return Err(corrupt("run_cancel_outbox"));
    }
    match field::<String>(stored, "status")?.as_str() {
        "pending" | "delivering" => Ok(Outcome::AlreadyRequested),
        _ => Err(corrupt("run_cancel_outbox")),
    }
}

const fn corrupt(field: &'static str) -> DrainError {
    DrainError::Corrupt { field }
}

fn field<T: FromSqlOwned>(row: &Row, name: &'static str) -> Result<T, DrainError> {
    row.try_get(name).map_err(|_| corrupt("row_decode"))
}

fn remaining(deadline: Instant) -> Result<(), DrainError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(DrainError::Unavailable)
    }
}

async fn bounded<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, DrainError> {
    remaining(deadline)?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| DrainError::Unavailable)?;
    remaining(deadline)?;
    Ok(result)
}

async fn rows(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Row>, DrainError> {
    bounded(deadline, tx.query(sql, params))
        .await?
        .map_err(|_| DrainError::Unavailable)
}

/// A refused lock (55P03, which includes the lock wait limit), a deadlock (40P01), a
/// serialization failure (40001) and every other transport or database failure stay unavailable
/// and are never retried. Only a unique violation on the one acceptance key is a broken binding:
/// no valid writer can hold that key without also holding the Run row this transaction locked.
fn insert_error(error: &tokio_postgres::Error) -> DrainError {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        corrupt("run_cancel_outbox")
    } else {
        DrainError::Unavailable
    }
}

fn owner(error: TransactionOwnerError) -> DrainError {
    match error {
        TransactionOwnerError::AlreadyStarted => DrainError::AlreadyStarted,
        TransactionOwnerError::DeadlineExceeded => DrainError::DeadlineExceeded,
        TransactionOwnerError::BeginUnavailable => DrainError::BeginUnavailable,
        TransactionOwnerError::CommitUnknown => DrainError::CommitUnknown,
        TransactionOwnerError::RollbackUnproven => DrainError::RollbackUnproven,
        TransactionOwnerError::CommitAcknowledgedAfterDeadline => {
            DrainError::CommitAcknowledgedAfterDeadline
        }
        TransactionOwnerError::RollbackAcknowledgedAfterDeadline => {
            DrainError::RollbackAcknowledgedAfterDeadline
        }
    }
}
