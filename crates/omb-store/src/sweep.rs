//! The cleaner: content cleared after the content retention, rows deleted after the tombstone
//! retention. Every statement has its own two-second deadline.
use crate::{StoreError, rows};
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::{Client, types::ToSql};

const ERROR: StoreError = StoreError::SweepFailed;
const STATEMENT_BUDGET: Duration = Duration::from_secs(2);

/// Clears message text, delivery bodies, session summaries and tails, and permission input
/// summaries once their row ended `retention` ago; returns the rows cleared.
pub async fn clear_content(client: &Client, retention: Duration) -> Result<u64, StoreError> {
    let seconds = retention.as_secs_f64();
    let mut cleared = 0;
    for sql in [
        "UPDATE openmybot.channel_events SET text='', content_cleared_at=now() WHERE record_kind='event' AND disposition='accepted_message' AND content_cleared_at IS NULL AND COALESCE(terminal_at, CASE WHEN dispatch_status IN ('conflict','expired','cancelled') THEN accepted_at END) <= now() - make_interval(secs=>$1) RETURNING 1",
        "UPDATE openmybot.deliveries SET body=NULL, content_cleared_at=now() WHERE content_cleared_at IS NULL AND finished_at IS NOT NULL AND finished_at <= now() - make_interval(secs=>$1) RETURNING 1",
        "UPDATE openmybot.host_driver_sessions SET result_summary=NULL, stderr_tail=NULL, content_cleared_at=now() WHERE record_kind='session' AND content_cleared_at IS NULL AND ended_at <= now() - make_interval(secs=>$1) RETURNING 1",
        "UPDATE openmybot.host_driver_sessions SET input_summary=NULL, content_cleared_at=now() WHERE record_kind='permission' AND content_cleared_at IS NULL AND decided_at <= now() - make_interval(secs=>$1) RETURNING 1",
    ] {
        cleared += rows(
            client,
            sql,
            &[&seconds],
            Instant::now() + STATEMENT_BUDGET,
            ERROR,
        )
        .await?
        .len() as u64;
    }
    Ok(cleared)
}

/// Deletes rows older than `retention` in batches of 500: events and gaps (an event of a
/// dispatched run without a terminal stays), finished deliveries, permissions with their ended
/// session or by request time, ended sessions, then every control token that is neither the
/// newest nor referenced by a decision; returns the rows deleted.
pub async fn delete_expired(client: &Client, retention: Duration) -> Result<u64, StoreError> {
    let seconds = retention.as_secs_f64();
    let aged: &[&(dyn ToSql + Sync)] = &[&seconds];
    let mut deleted = 0;
    for (sql, parameters) in [
        (
            "DELETE FROM openmybot.channel_events WHERE record_id IN (SELECT record_id FROM openmybot.channel_events WHERE record_kind='event' AND accepted_at <= now() - make_interval(secs=>$1) AND NOT (run_id IS NOT NULL AND dispatch_status='dispatched' AND terminal_kind IS NULL) LIMIT 500) RETURNING 1",
            aged,
        ),
        (
            "DELETE FROM openmybot.channel_events WHERE record_id IN (SELECT record_id FROM openmybot.channel_events WHERE record_kind='gap' AND gap_ended_at <= now() - make_interval(secs=>$1) LIMIT 500) RETURNING 1",
            aged,
        ),
        (
            "DELETE FROM openmybot.deliveries WHERE delivery_id IN (SELECT delivery_id FROM openmybot.deliveries WHERE finished_at <= now() - make_interval(secs=>$1) LIMIT 500) RETURNING 1",
            aged,
        ),
        (
            "DELETE FROM openmybot.host_driver_sessions WHERE record_id IN (SELECT p.record_id FROM openmybot.host_driver_sessions p LEFT JOIN openmybot.host_driver_sessions s ON s.record_kind='session' AND s.run_id=p.run_id WHERE p.record_kind='permission' AND CASE WHEN s.record_id IS NULL THEN p.requested_at ELSE s.ended_at END <= now() - make_interval(secs=>$1) LIMIT 500) RETURNING 1",
            aged,
        ),
        (
            "DELETE FROM openmybot.host_driver_sessions WHERE record_id IN (SELECT record_id FROM openmybot.host_driver_sessions WHERE record_kind='session' AND ended_at <= now() - make_interval(secs=>$1) LIMIT 500) RETURNING 1",
            aged,
        ),
        (
            "DELETE FROM openmybot.control_tokens WHERE token_id IN (SELECT token_id FROM openmybot.control_tokens WHERE token_id <> (SELECT token_id FROM openmybot.control_tokens ORDER BY created_at DESC, token_id DESC LIMIT 1) AND NOT EXISTS (SELECT 1 FROM openmybot.host_driver_sessions h WHERE h.decided_by_token = control_tokens.token_id) LIMIT 500) RETURNING 1",
            &[],
        ),
    ] {
        loop {
            let batch = rows(
                client,
                sql,
                parameters,
                Instant::now() + STATEMENT_BUDGET,
                ERROR,
            )
            .await?
            .len() as u64;
            deleted += batch;
            if batch == 0 {
                break;
            }
        }
    }
    Ok(deleted)
}
