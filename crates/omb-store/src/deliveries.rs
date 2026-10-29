//! Outbound delivery rows: the atomic claim, the send target, the run result facts and the end of
//! one attempt.
use crate::{Channel, ReceiverRow, StoreError, TerminalKind, rows};
use std::time::Duration;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

const ERROR: StoreError = StoreError::DeliveryFailed;

/// The closed set of `last_error_code` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Unreachable,
    RateLimited,
    ServerError,
    ClientError,
    BindingInactive,
    ReceiverInactive,
    RetriesExhausted,
    ResultUnknown,
    DaemonRestart,
}
impl ErrorCode {
    pub const ALL: [ErrorCode; 9] = [
        Self::Unreachable,
        Self::RateLimited,
        Self::ServerError,
        Self::ClientError,
        Self::BindingInactive,
        Self::ReceiverInactive,
        Self::RetriesExhausted,
        Self::ResultUnknown,
        Self::DaemonRestart,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
            Self::ClientError => "client_error",
            Self::BindingInactive => "binding_inactive",
            Self::ReceiverInactive => "receiver_inactive",
            Self::RetriesExhausted => "retries_exhausted",
            Self::ResultUnknown => "result_unknown",
            Self::DaemonRestart => "daemon_restart",
        }
    }
}

/// What a claimed row sends: a stored body, or the result of a run composed at send time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryContent {
    Text(String),
    RunResult { run_id: String },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub delivery_id: Uuid,
    pub binding_id: Uuid,
    pub channel: Channel,
    pub chat_key: String,
    pub idempotency_key: String,
    /// The count after this claim; the first claim is 1.
    pub attempts: u32,
    pub content: DeliveryContent,
}
/// Claims the oldest due pending row of either channel as `sending` in one statement.
pub async fn claim_delivery(
    client: &Client,
    deadline: Instant,
) -> Result<Option<Claimed>, StoreError> {
    let claimed = rows(client, "UPDATE openmybot.deliveries SET status='sending', attempts=attempts+1, first_attempt_at=COALESCE(first_attempt_at, now()) WHERE delivery_id = (SELECT delivery_id FROM openmybot.deliveries WHERE status='pending' AND channel_kind IN ('telegram','feishu') AND (next_attempt_at IS NULL OR next_attempt_at <= now()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING delivery_id, binding_id, chat_key, kind, idempotency_key, body, attempts, channel_kind", &[], deadline, ERROR).await?;
    let Some(row) = claimed.first() else {
        return Ok(None);
    };
    let content = match row.try_get::<_, &str>(3).map_err(|_| ERROR)? {
        "run_result" => DeliveryContent::RunResult {
            run_id: row
                .try_get::<_, &str>(4)
                .map_err(|_| ERROR)?
                .strip_prefix("result:")
                .ok_or(ERROR)?
                .to_owned(),
        },
        _ => DeliveryContent::Text(
            row.try_get::<_, Option<String>>(5)
                .map_err(|_| ERROR)?
                .ok_or(ERROR)?,
        ),
    };
    Ok(Some(Claimed {
        delivery_id: row.try_get(0).map_err(|_| ERROR)?,
        binding_id: row.try_get(1).map_err(|_| ERROR)?,
        channel: Channel::parse(row.try_get::<_, &str>(7).map_err(|_| ERROR)?).ok_or(ERROR)?,
        chat_key: row.try_get(2).map_err(|_| ERROR)?,
        idempotency_key: row.try_get(4).map_err(|_| ERROR)?,
        attempts: u32::try_from(row.try_get::<_, i32>(6).map_err(|_| ERROR)?).map_err(|_| ERROR)?,
        content,
    }))
}

/// Whether the row's sender binding is active, and the active receiver of the row's channel if any.
pub struct SendTarget {
    pub sender_active: bool,
    /// The receiver row and its revision, the credential version a cached token is keyed by.
    pub receiver: Option<(ReceiverRow, u64)>,
}
pub async fn send_target(
    client: &Client,
    binding_id: Uuid,
    channel: Channel,
    deadline: Instant,
) -> Result<SendTarget, StoreError> {
    let found = rows(client, "SELECT (SELECT status='active' FROM openmybot.channel_bindings WHERE binding_id=$1),r.binding_id,r.source_key,r.credential_envelope,r.revision FROM (SELECT 1) one LEFT JOIN openmybot.channel_bindings r ON r.binding_kind='receiver' AND r.channel_kind=$2 AND r.status='active'", &[&binding_id, &channel.as_str()], deadline, ERROR).await?;
    let row = found.first().ok_or(ERROR)?;
    let receiver = match row.try_get::<_, Option<Uuid>>(1).map_err(|_| ERROR)? {
        Some(binding_id) => Some((
            ReceiverRow {
                binding_id,
                channel,
                source_key: row.try_get(2).map_err(|_| ERROR)?,
                credential_envelope: row.try_get(3).map_err(|_| ERROR)?,
            },
            u64::try_from(
                row.try_get::<_, Option<i64>>(4)
                    .map_err(|_| ERROR)?
                    .ok_or(ERROR)?,
            )
            .map_err(|_| ERROR)?,
        )),
        None => None,
    };
    Ok(SendTarget {
        sender_active: row
            .try_get::<_, Option<bool>>(0)
            .map_err(|_| ERROR)?
            .unwrap_or(false),
        receiver,
    })
}

/// The stored facts a run result message is composed from; never the standard error tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResultFacts {
    pub terminal: TerminalKind,
    pub result_summary: Option<String>,
    pub artifact_paths: Vec<String>,
}
/// The run's terminal and its session's summary and artifact paths; a run without a recorded
/// terminal is a failure.
pub async fn run_result_facts(
    client: &Client,
    run_id: &str,
    deadline: Instant,
) -> Result<RunResultFacts, StoreError> {
    let found = rows(client, "SELECT e.terminal_kind,s.result_summary,s.artifact_paths FROM openmybot.channel_events e LEFT JOIN openmybot.host_driver_sessions s ON s.record_kind='session' AND s.run_id=e.run_id WHERE e.run_id=$1", &[&run_id], deadline, ERROR).await?;
    let row = found.first().ok_or(ERROR)?;
    let terminal = match row.try_get::<_, Option<&str>>(0).map_err(|_| ERROR)? {
        Some("succeeded") => TerminalKind::Succeeded,
        Some("failed") => TerminalKind::Failed,
        Some("cancelled") => TerminalKind::Cancelled,
        Some("reconciliation_required") => TerminalKind::ReconciliationRequired,
        _ => return Err(ERROR),
    };
    Ok(RunResultFacts {
        terminal,
        result_summary: row.try_get(1).map_err(|_| ERROR)?,
        artifact_paths: row
            .try_get::<_, Option<Vec<String>>>(2)
            .map_err(|_| ERROR)?
            .unwrap_or_default(),
    })
}

/// How one attempt of a `sending` row ended.
pub enum Finish<'a> {
    Sent { platform_message_id: &'a str },
    Retry { after: Duration, code: ErrorCode },
    Failed { code: ErrorCode },
    Unknown { code: ErrorCode },
}
/// Ends the attempt of a row that is `sending`; any other row is refused unchanged.
pub async fn finish_delivery(
    client: &Client,
    delivery_id: Uuid,
    finish: Finish<'_>,
    deadline: Instant,
) -> Result<(), StoreError> {
    let changed = match finish {
        Finish::Sent { platform_message_id } => rows(client, "UPDATE openmybot.deliveries SET status='sent',platform_message_id=$2,finished_at=now(),next_attempt_at=NULL WHERE delivery_id=$1 AND status='sending' RETURNING delivery_id", &[&delivery_id, &platform_message_id], deadline, ERROR).await?,
        Finish::Retry { after, code } => rows(client, "UPDATE openmybot.deliveries SET status='pending',next_attempt_at=now()+make_interval(secs=>$2),last_error_code=$3 WHERE delivery_id=$1 AND status='sending' RETURNING delivery_id", &[&delivery_id, &after.as_secs_f64(), &code.as_str()], deadline, ERROR).await?,
        Finish::Failed { code } => rows(client, "UPDATE openmybot.deliveries SET status='failed',finished_at=now(),next_attempt_at=NULL,last_error_code=$2 WHERE delivery_id=$1 AND status='sending' RETURNING delivery_id", &[&delivery_id, &code.as_str()], deadline, ERROR).await?,
        Finish::Unknown { code } => rows(client, "UPDATE openmybot.deliveries SET status='unknown',finished_at=now(),next_attempt_at=NULL,last_error_code=$2 WHERE delivery_id=$1 AND status='sending' RETURNING delivery_id", &[&delivery_id, &code.as_str()], deadline, ERROR).await?,
    };
    match changed.len() {
        1 => Ok(()),
        _ => Err(ERROR),
    }
}
/// At daemon start: rows left `sending` by a previous process end `unknown`, never resent.
pub async fn mark_sending_unknown(client: &Client, deadline: Instant) -> Result<u64, StoreError> {
    rows(client, "UPDATE openmybot.deliveries SET status='unknown', finished_at=now(), last_error_code='daemon_restart', next_attempt_at=NULL WHERE status='sending' RETURNING delivery_id", &[], deadline, ERROR).await.map(|ended| ended.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn error_codes_are_the_nine_ruled_strings() {
        let texts: Vec<_> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(
            texts,
            [
                "unreachable",
                "rate_limited",
                "server_error",
                "client_error",
                "binding_inactive",
                "receiver_inactive",
                "retries_exhausted",
                "result_unknown",
                "daemon_restart",
            ]
        );
        let mut unique = texts.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 9);
    }
}
