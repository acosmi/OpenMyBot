//! One-J stop/clear intent producer. It is ACK1 only: the immutable intent and the closure of
//! history body-writer admission. In-flight Runs are neither cancelled nor drained, and no
//! artifact, byte or quota fact is touched. Nothing here is ACK2, deletion or Ready.
//!
//! H is the Thread's history admission head row, Q its immutable intent row, and J0 and J2 the
//! first and last fresh current joint statements of the one original transaction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use openbot_contracts::artifacts::canonical_artifact_uuid_v7;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{DeploymentId, TenantId, ThreadId};
use openbot_contracts::request_binding::HostRequestBindingError;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::{
    CurrentSnapshot, CurrentThreadHistoryRequest, Error, OriginalInvocation,
    PostgresThreadHistoryAuthority, ThreadHistoryTransaction, bounded, column, owner_error,
    remaining, schema_error,
};
use crate::db::{InfraError, thread_origin_schema};
use crate::thread_history_writer::{CurrentWriterSchema, OpenOrClosed};

/// Closed stop/clear failures. No runtime SQL, row, locator or secret is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThreadHistoryStopClearError {
    #[error("thread_history_stop_clear_invalid_input")]
    InvalidInput { field: &'static str },
    #[error("thread_history_stop_clear_host_refused")]
    Host(HostRequestBindingError),
    #[error("thread_history_stop_clear_not_visible")]
    NotVisible,
    /// Closed by another request or actor, or this request id belongs to another Thread.
    /// Nothing was written and the real original ROLLBACK ACK was observed.
    #[error("thread_history_stop_clear_conflict")]
    Conflict,
    #[error("thread_history_stop_clear_unavailable")]
    Unavailable,
    #[error("thread_history_stop_clear_corrupt")]
    Corrupt { field: &'static str },
    #[error("thread_history_stop_clear_transaction_already_started")]
    AlreadyStarted,
    #[error("thread_history_stop_clear_transaction_deadline_exceeded")]
    DeadlineExceeded,
    #[error("thread_history_stop_clear_transaction_begin_unavailable")]
    BeginUnavailable,
    /// COMMIT was sent but never acknowledged. The same request id later replays or refuses.
    #[error("thread_history_stop_clear_transaction_commit_unknown")]
    CommitUnknown,
    #[error("thread_history_stop_clear_transaction_rollback_unproven")]
    RollbackUnproven,
    /// The real COMMIT ACK arrived after the deadline; the intent is stored.
    #[error("thread_history_stop_clear_transaction_commit_ack_after_deadline")]
    CommitAcknowledgedAfterDeadline,
    #[error("thread_history_stop_clear_transaction_rollback_ack_after_deadline")]
    RollbackAcknowledgedAfterDeadline,
}

type StopError = ThreadHistoryStopClearError;

/// Which real original terminal ACK was observed before the intent was published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadHistoryStopClearConfirmation {
    /// This call stored the intent and closed admission; the original COMMIT was acknowledged.
    CommitAcknowledged,
    /// An earlier identical call already did; nothing was written and the original ROLLBACK
    /// was acknowledged after this call's own current-eligibility recheck.
    ExactReplayRollbackAcknowledged,
}

/// One acknowledged stop/clear intent for one J. It is neither a lease nor an ACK2, drain,
/// deletion or Ready fact, and it has no public constructor.
pub struct ThreadHistoryStopClearIntent {
    deployment: DeploymentId,
    tenant: TenantId,
    thread: ThreadId,
    operation_id: String,
    request_id: String,
    confirmation: ThreadHistoryStopClearConfirmation,
}
impl ThreadHistoryStopClearIntent {
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant
    }
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread
    }
    /// The stored intent's operation id: the original one on an exact replay.
    #[must_use]
    pub const fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }
    #[must_use]
    pub const fn request_id(&self) -> &str {
        self.request_id.as_str()
    }
    #[must_use]
    pub const fn confirmation(&self) -> ThreadHistoryStopClearConfirmation {
        self.confirmation
    }
}
impl core::fmt::Debug for ThreadHistoryStopClearIntent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ThreadHistoryStopClearIntent(<one-J-ack1:{:?}>)",
            self.confirmation
        )
    }
}

/// What the original transaction decided; only `Closed` ends in COMMIT.
enum Decision {
    /// This transaction inserted the intent and closed the head.
    Closed(String),
    /// The head was already closed by this exact request and actor.
    Replay(String),
    Conflict,
}

/// A terminal ACK was observed and the Host is still current.
enum Acknowledged {
    Intent {
        operation_id: String,
        confirmation: ThreadHistoryStopClearConfirmation,
    },
    Conflict,
}

/// Exclusive H boundary. It upgrades the SHARE taken by the writer disposition and never waits.
const LOCK_HEAD: &str = "SELECT thread_id FROM openbot_internal.thread_history_heads \
    WHERE deployment_id=$1 AND tenant_id=$2 AND thread_id=$3 AND phase='open' FOR UPDATE NOWAIT";
const REQUEST_OWNER: &str = "SELECT thread_id FROM openbot_internal.thread_history_clear_intents \
    WHERE deployment_id=$1 AND tenant_id=$2 AND request_id=$3";
/// `recorded_at` is omitted so the database `clock_timestamp()` default applies.
const INSERT_INTENT: &str = "INSERT INTO openbot_internal.thread_history_clear_intents \
    (deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,\
     auth_generation,anchor_kind,anchor_id,thread_created_at) \
    SELECT h.deployment_id,h.tenant_id,h.thread_id,1,'stop_clear',$4::text,$5::text,$6::text,\
     $7::bigint,h.anchor_kind,h.anchor_id,h.thread_created_at \
    FROM openbot_internal.thread_history_heads h \
    WHERE h.deployment_id=$1 AND h.tenant_id=$2 AND h.thread_id=$3 AND h.phase='open' \
    ON CONFLICT DO NOTHING RETURNING operation_id";
/// Every closure field, including `closed_at`, comes from the inserted intent row.
const CLOSE_HEAD: &str = "UPDATE openbot_internal.thread_history_heads hh SET phase='closed',\
    closure_operation_id=q.operation_id,closure_request_id=q.request_id,\
    closure_actor_id=q.actor_id,closure_auth_generation=q.auth_generation,closed_at=q.recorded_at \
    FROM openbot_internal.thread_history_clear_intents q \
    WHERE q.operation_id=$4 AND hh.deployment_id=q.deployment_id AND hh.tenant_id=q.tenant_id \
    AND hh.thread_id=q.thread_id AND hh.deployment_id=$1 AND hh.tenant_id=$2 \
    AND hh.thread_id=$3 AND hh.phase='open'";
/// The H/Q pair is checked as ordinary statements, not inside COMMIT where any failure is Unknown.
const SETTLE_PAIR: &str = "SET CONSTRAINTS \
    openbot_internal.thread_history_clear_intents_head_base_fkey,\
    openbot_internal.thread_history_heads_closed_intent_fkey,\
    openbot_internal.thread_history_clear_intents_require_closed_head IMMEDIATE";
const CLOSED_INTENT: &str = "SELECT operation_id,request_id,actor_id,intent_kind \
    FROM openbot_internal.thread_history_clear_intents \
    WHERE deployment_id=$1 AND tenant_id=$2 AND thread_id=$3";

impl PostgresThreadHistoryAuthority {
    /// Record one stop/clear intent for one J and close its body-writer admission in one original
    /// READ COMMITTED transaction that repeats the full current single-Thread management check.
    ///
    /// A new intent is published only after the real original COMMIT ACK, and an exact replay of
    /// the same request and actor only after a current recheck and the real original ROLLBACK ACK.
    /// Every refusal also waits for its ROLLBACK ACK. After a COMMIT ACK a later Host failure is
    /// still reported as that failure; it never becomes Unknown and never undoes the stored
    /// intent. This is ACK1 only: in-flight Runs are not cancelled or drained.
    ///
    /// # Errors
    /// Refuses a malformed Thread or request id, a foreign or no longer current Host, an actor
    /// that is not the current creator with live access, a Thread already closed by another
    /// request or actor, a request id used by another Thread, an unavailable or contended
    /// database and every unproven or late transaction acknowledgement.
    pub async fn close_for_stop_clear_before(
        self: &Arc<Self>,
        auth: &AuthContext,
        thread_id: &str,
        request_id: &str,
        original_deadline: Instant,
    ) -> Result<ThreadHistoryStopClearIntent, ThreadHistoryStopClearError> {
        let entry = Instant::now();
        let cap = entry
            .checked_add(Duration::from_secs(5))
            .ok_or(StopError::Unavailable)?;
        let deadline = original_deadline.min(cap);
        if thread_id.len() != 36 {
            return Err(StopError::InvalidInput { field: "thread_id" });
        }
        let thread = ThreadId::new(thread_id);
        if !ThreadIdentity::is_plausible(&thread) {
            return Err(StopError::InvalidInput { field: "thread_id" });
        }
        // Only the stored canonical lowercase UUIDv7 text is accepted; nothing is normalised.
        if canonical_artifact_uuid_v7(request_id).as_deref() != Some(request_id) {
            return Err(StopError::InvalidInput {
                field: "request_id",
            });
        }
        match self
            .stop_clear_acknowledged(auth, &thread, request_id, deadline)
            .await
            .map_err(from_observation)?
        {
            Acknowledged::Intent {
                operation_id,
                confirmation,
            } => Ok(ThreadHistoryStopClearIntent {
                deployment: self.deployment.clone(),
                tenant: self.tenant.clone(),
                thread,
                operation_id,
                request_id: request_id.to_owned(),
                confirmation,
            }),
            Acknowledged::Conflict => Err(StopError::Conflict),
        }
    }

    async fn stop_clear_acknowledged(
        &self,
        auth: &AuthContext,
        thread: &ThreadId,
        request_id: &str,
        deadline: Instant,
    ) -> Result<Acknowledged, Error> {
        remaining(deadline)?;
        self.scope(auth)?;
        let target = OriginalInvocation {
            authority: &self.authority,
            auth,
        };
        let current = CurrentThreadHistoryRequest::borrow(self, auth, &target, deadline)?;
        let mut client = self
            .pool
            .get_guarded(deadline)
            .await
            .map_err(|_| Error::Unavailable)?;
        // Same actual client before BEGIN; no second Pool or Client performs validation.
        bounded(deadline, thread_origin_schema::verify(client.as_client()))
            .await?
            .map_err(schema_error)?;
        current.check_attachment(deadline)?;
        let transaction = client.begin_read_committed().await.map_err(owner_error)?;
        let transaction = ThreadHistoryTransaction {
            authority: self,
            transaction,
        };
        let result = self
            .stop_clear_original(&current, &transaction, thread, request_id, deadline)
            .await;
        let (decision, snapshot) = match result {
            Ok(decided) => decided,
            Err(error) => {
                // Even an ordinary refusal retains its real terminal ACK before it is returned.
                transaction
                    .transaction
                    .rollback()
                    .await
                    .map_err(owner_error)?;
                return Err(error);
            }
        };
        let committed = matches!(decision, Decision::Closed(_));
        if committed {
            transaction
                .transaction
                .commit()
                .await
                .map_err(owner_error)?;
        } else {
            transaction
                .transaction
                .rollback()
                .await
                .map_err(owner_error)?;
        }
        // The Host may close while the original ACK is in flight; recheck the same witness. After
        // a known COMMIT only the exhausted deadline is left, and it keeps the stored fact.
        verify_after_ack(&current, &snapshot, auth, deadline).map_err(|error| {
            if committed && error == Error::Unavailable {
                Error::CommitAcknowledgedAfterDeadline
            } else {
                error
            }
        })?;
        Ok(match decision {
            Decision::Closed(operation_id) => Acknowledged::Intent {
                operation_id,
                confirmation: ThreadHistoryStopClearConfirmation::CommitAcknowledged,
            },
            Decision::Replay(operation_id) => Acknowledged::Intent {
                operation_id,
                confirmation: ThreadHistoryStopClearConfirmation::ExactReplayRollbackAcknowledged,
            },
            Decision::Conflict => Acknowledged::Conflict,
        })
    }

    /// The transaction body. The writer schema proof precedes the first row lock. After it the
    /// actor row is the only wait before J0; the lazy H insert and the Q insert may then wait on
    /// their unique keys. Every other lock is NOWAIT and J2 follows every possible wait.
    async fn stop_clear_original(
        &self,
        current: &CurrentThreadHistoryRequest<'_>,
        original: &ThreadHistoryTransaction<'_>,
        thread: &ThreadId,
        request_id: &str,
        deadline: Instant,
    ) -> Result<(Decision, CurrentSnapshot), Error> {
        if !std::ptr::eq(original.authority, self) {
            return Err(Error::Corrupt {
                field: "host_binding",
            });
        }
        let tx = original.transaction.as_transaction();
        // This is the one in-transaction native and origin validation of this producer.
        let schema = bounded(deadline, CurrentWriterSchema::observe(tx))
            .await?
            .map_err(schema_error)?;
        current.check_attachment(deadline)?;
        self.lock_current_positive(current, tx, thread, deadline)
            .await?;
        // J0: nothing below touches H unless the Thread is currently managed by this creator.
        self.observe_current_joint(current, tx, thread, deadline)
            .await?;
        let disposition = bounded(deadline, schema.lock_thread_write_disposition(tx, thread))
            .await?
            .map_err(history_error)?;
        current.check_attachment(deadline)?;
        let decision = match disposition {
            OpenOrClosed::Open => {
                self.record_intent(current, tx, thread, request_id, deadline)
                    .await?
            }
            OpenOrClosed::Closed => {
                self.classify_closed(current, tx, thread, request_id, deadline)
                    .await?
            }
        };
        current.check_attachment(deadline)?;
        // J2: a new statement after the lazy H and Q unique waits and every write, before the
        // terminal. It covers rows these locks do not hold, such as a new deny.
        let snapshot = self
            .observe_current_joint(current, tx, thread, deadline)
            .await?;
        Ok((decision, snapshot))
    }

    /// H is open under SHARE: take the exclusive boundary, insert Q, close H from that row.
    async fn record_intent(
        &self,
        current: &CurrentThreadHistoryRequest<'_>,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        request_id: &str,
        deadline: Instant,
    ) -> Result<Decision, Error> {
        let deployment = self.deployment.as_str();
        let tenant = self.tenant.as_str();
        let locked = rows(
            tx,
            deadline,
            LOCK_HEAD,
            &[&deployment, &tenant, &thread.as_str()],
        )
        .await?;
        if locked.len() != 1 {
            return Err(history_binding());
        }
        // Read first: a used request id is classified without waiting on its unique key.
        if request_used_elsewhere(tx, deadline, deployment, tenant, request_id, thread).await? {
            return Ok(Decision::Conflict);
        }
        let generation =
            i64::try_from(current.auth.auth_generation().get()).map_err(|_| history_binding())?;
        let operation_id = Uuid::now_v7().to_string();
        let inserted = rows(
            tx,
            deadline,
            INSERT_INTENT,
            &[
                &deployment,
                &tenant,
                &thread.as_str(),
                &operation_id,
                &request_id,
                &current.auth.actor().as_str(),
                &generation,
            ],
        )
        .await?;
        if inserted.is_empty() {
            // Not a swallowed unique error: classify the committed winner by reading it. A
            // conflict that names no other Thread's request is never guessed to be benign.
            return if request_used_elsewhere(tx, deadline, deployment, tenant, request_id, thread)
                .await?
            {
                Ok(Decision::Conflict)
            } else {
                Err(history_binding())
            };
        }
        if inserted.len() != 1 || column::<String>(&inserted[0], "operation_id")? != operation_id {
            return Err(history_binding());
        }
        let closed = execute(
            tx,
            deadline,
            CLOSE_HEAD,
            &[&deployment, &tenant, &thread.as_str(), &operation_id],
        )
        .await?;
        if closed != 1 {
            return Err(history_binding());
        }
        bounded(deadline, tx.batch_execute(SETTLE_PAIR))
            .await?
            .map_err(|error| settle_error(&error))?;
        Ok(Decision::Closed(operation_id))
    }

    /// H is already closed and its exact intent was verified by the writer disposition.
    async fn classify_closed(
        &self,
        current: &CurrentThreadHistoryRequest<'_>,
        tx: &Transaction<'_>,
        thread: &ThreadId,
        request_id: &str,
        deadline: Instant,
    ) -> Result<Decision, Error> {
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
        let [row] = found.as_slice() else {
            return Err(history_binding());
        };
        let operation_id: String = column(row, "operation_id")?;
        let same = column::<String>(row, "request_id")? == request_id
            && column::<String>(row, "actor_id")? == current.auth.actor().as_str()
            && column::<String>(row, "intent_kind")? == "stop_clear";
        // The stored generation is not compared: a replay needs this call's own current check.
        Ok(if same {
            Decision::Replay(operation_id)
        } else {
            Decision::Conflict
        })
    }
}

/// Whether another Thread of this deployment and tenant already stored this request id. The same
/// Thread storing it while its H is open is a broken pair, never a conflict.
async fn request_used_elsewhere(
    tx: &Transaction<'_>,
    deadline: Instant,
    deployment: &str,
    tenant: &str,
    request_id: &str,
    thread: &ThreadId,
) -> Result<bool, Error> {
    let found = rows(
        tx,
        deadline,
        REQUEST_OWNER,
        &[&deployment, &tenant, &request_id],
    )
    .await?;
    match found.as_slice() {
        [] => Ok(false),
        [row] if column::<String>(row, "thread_id")? != thread.as_str() => Ok(true),
        _ => Err(history_binding()),
    }
}

fn verify_after_ack(
    current: &CurrentThreadHistoryRequest<'_>,
    snapshot: &CurrentSnapshot,
    auth: &AuthContext,
    deadline: Instant,
) -> Result<(), Error> {
    current.check_attachment(deadline)?;
    snapshot
        .witness
        .verify_current(auth, deadline)
        .map_err(Error::Host)?;
    current.check_attachment(deadline)
}

async fn rows(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Row>, Error> {
    bounded(deadline, tx.query(sql, params))
        .await?
        .map_err(|error| statement_error(&error))
}

async fn execute(
    tx: &Transaction<'_>,
    deadline: Instant,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<u64, Error> {
    bounded(deadline, tx.execute(sql, params))
        .await?
        .map_err(|error| statement_error(&error))
}

const fn history_binding() -> Error {
    Error::Corrupt {
        field: "history_binding",
    }
}

/// A refused NOWAIT lock (55P03), a deadlock (40P01) and every other transport or database failure
/// stay unavailable and are never retried. Only the writer guard's own payload-free refusal
/// (55000) is a broken binding. Nothing here is a closed or conflicting answer.
fn statement_error(error: &tokio_postgres::Error) -> Error {
    match error.code().map(tokio_postgres::error::SqlState::code) {
        Some("55000") => history_binding(),
        _ => Error::Unavailable,
    }
}

/// The deferred pair checks run here as ordinary statements. A violated one is a broken binding.
fn settle_error(error: &tokio_postgres::Error) -> Error {
    match error.code().map(tokio_postgres::error::SqlState::code) {
        Some("23503" | "23514" | "23505" | "55000") => history_binding(),
        _ => Error::Unavailable,
    }
}

fn history_error(error: InfraError) -> Error {
    match error {
        InfraError::RowDecode(_) => Error::Corrupt {
            field: "row_decode",
        },
        InfraError::RepositoryInvariant { .. } => history_binding(),
        InfraError::IncompatibleDatabase(_) | InfraError::NativeMigration(_) => {
            Error::Corrupt { field: "schema" }
        }
        InfraError::Connect { .. } | InfraError::Query { .. } => match error.sqlstate() {
            Some("55000") => history_binding(),
            _ => Error::Unavailable,
        },
    }
}

fn from_observation(error: Error) -> StopError {
    match error {
        Error::InvalidInput { field } => StopError::InvalidInput { field },
        Error::Host(error) => StopError::Host(error),
        Error::NotVisible => StopError::NotVisible,
        Error::Unavailable => StopError::Unavailable,
        Error::Corrupt { field } => StopError::Corrupt { field },
        Error::AlreadyStarted => StopError::AlreadyStarted,
        Error::DeadlineExceeded => StopError::DeadlineExceeded,
        Error::BeginUnavailable => StopError::BeginUnavailable,
        Error::CommitUnknown => StopError::CommitUnknown,
        Error::RollbackUnproven => StopError::RollbackUnproven,
        Error::CommitAcknowledgedAfterDeadline => StopError::CommitAcknowledgedAfterDeadline,
        Error::RollbackAcknowledgedAfterDeadline => StopError::RollbackAcknowledgedAfterDeadline,
    }
}
