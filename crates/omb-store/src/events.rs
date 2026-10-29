use crate::{
    ACCEPT_TX_BUDGET, AcceptedEvent, Channel, DISPATCH_QUEUE_MAX, EVENT_FUTURE_WINDOW,
    EVENT_PAST_WINDOW, GAP_DISPLAY, IdentityKey, MSG_TEXT_MAX, OpenRun, PairAttempt, PairOutcome,
    READ_BUDGET, StoreError, command, finish, pair_attempt, rows, timely,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Client;
use uuid::Uuid;

/// UUIDv5(NAMESPACE_URL, `urn:openmybot:v1`).
const OMB_NS: Uuid = Uuid::from_u128(0xb09a90b8_a527_5aa1_be6d_0645747da37f);

fn uuid_v5(namespace: Uuid, name: &str) -> Uuid {
    let digest = sha1::Sha1::new()
        .chain_update(namespace.as_bytes())
        .chain_update(name.as_bytes())
        .finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_sha1_bytes(bytes).into_uuid()
}
/// Deterministic run identity of one accepted event: the same source and trigger always mint it.
fn run_id(binding_id: Uuid, trigger_id: Uuid) -> Uuid {
    uuid_v5(OMB_NS, &format!("run:{binding_id}:{trigger_id}"))
}
fn rfc3339(at: OffsetDateTime, error: StoreError) -> Result<String, StoreError> {
    at.to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| error)
}
fn count(row: &tokio_postgres::Row, index: usize, error: StoreError) -> Result<u64, StoreError> {
    u64::try_from(row.try_get::<_, i64>(index).map_err(|_| error)?).map_err(|_| error)
}

/// One platform event after boundary parsing; the receiver owns every value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedEvent {
    pub channel: Channel,
    pub source_key: String,
    pub event_key: String,
    pub event_type: String,
    pub occurred_at: Option<OffsetDateTime>,
    pub private: bool,
    pub sender: Option<IdentityKey>,
    pub chat: Option<IdentityKey>,
    /// `None` only for `Content::Malformed`.
    pub fingerprint: Option<[u8; 32]>,
    pub content: Content,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    Text {
        text: String,
        command: Option<Command>,
        pair_code: Option<String>,
    },
    Other,
    Malformed,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command {
    Help,
    Start,
    Status,
    Cancel,
    Pair,
    Unknown,
}
impl Command {
    fn as_str(self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::Start => "start",
            Self::Status => "status",
            Self::Cancel => "cancel",
            Self::Pair => "pair",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    AcceptedMessage,
    ControlCommand,
    PairingSucceeded,
    PairingFailed,
    PairingLocked,
    DroppedUnbound,
    DroppedNotPrivate,
    DroppedInactive,
    RejectedOutsideWindow,
    RejectedTooLong,
    RejectedUnsupported,
    RejectedMalformed,
    RejectedQueueFull,
}
impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedMessage => "accepted_message",
            Self::ControlCommand => "control_command",
            Self::PairingSucceeded => "pairing_succeeded",
            Self::PairingFailed => "pairing_failed",
            Self::PairingLocked => "pairing_locked",
            Self::DroppedUnbound => "dropped_unbound",
            Self::DroppedNotPrivate => "dropped_not_private",
            Self::DroppedInactive => "dropped_inactive",
            Self::RejectedOutsideWindow => "rejected_outside_window",
            Self::RejectedTooLong => "rejected_too_long",
            Self::RejectedUnsupported => "rejected_unsupported",
            Self::RejectedMalformed => "rejected_malformed",
            Self::RejectedQueueFull => "rejected_queue_full",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcceptOutcome {
    /// The key was already recorded with the same or no fingerprint; nothing written.
    Duplicate,
    /// The key was already recorded with a different fingerprint; nothing written.
    Conflict,
    Recorded(Disposition),
    /// A `/cancel` control command of the bound sender, already committed with its reply row.
    Cancel(Uuid),
}
/// `/status` labels of the binding's latest accepted message.
pub struct StateLabels<'a> {
    pub none: &'a str,
    pub queued: &'a str,
    pub running: &'a str,
    pub conflict: &'a str,
    pub expired: &'a str,
    pub cancelled: &'a str,
    pub succeeded: &'a str,
    pub failed: &'a str,
    pub reconciliation: &'a str,
}
/// Fixed reply bodies; none of them echoes the incoming text.
pub struct ReplyTexts<'a> {
    pub help: &'a str,
    pub already_bound: &'a str,
    pub unknown_command: &'a str,
    /// `/cancel` while the binding has a dispatched run without a terminal.
    pub cancel_requested: &'a str,
    pub cancel_none: &'a str,
    /// Template with `{channel}`, `{dir}`, `{state}`, `{pending}` and `{gap}`.
    pub status: &'a str,
    pub states: StateLabels<'a>,
    pub outside_window: &'a str,
    pub too_long: &'a str,
    pub unsupported: &'a str,
    pub queue_full: &'a str,
}

/// Accepts one platform event in one transaction: dedupe, routing, rejection and the reply row,
/// or the `/pair` evaluation, commit together.
pub async fn accept_event(
    client: &mut Client,
    receiver_binding_id: Uuid,
    event: &NormalizedEvent,
    replies: &ReplyTexts<'_>,
    deadline: Instant,
) -> Result<AcceptOutcome, StoreError> {
    let error = StoreError::EventFailed;
    let channel = event.channel.as_str();
    timely(deadline, Ok(()), error)?;
    let tx = timeout_at(deadline, client.transaction())
        .await
        .map_err(|_| error)?
        .map_err(|_| error)?;
    let outcome = async {
        timeout_at(deadline, tx.batch_execute(&format!("SET LOCAL statement_timeout={}", ACCEPT_TX_BUDGET.as_millis())))
            .await
            .map_err(|_| error)?
            .map_err(|_| error)?;
        let receiver = rows(&tx, "SELECT source_key FROM openmybot.channel_bindings WHERE binding_id=$1 AND binding_kind='receiver' AND status='active' FOR SHARE", &[&receiver_binding_id], deadline, error).await?;
        let receiver_source_key: String = receiver.first().ok_or(StoreError::ReceiverNotActive)?.try_get(0).map_err(|_| error)?;
        // Serializes concurrent deliveries of one key; the next statement sees the winner's row.
        let identity = format!("{channel}\n{}\n{}", event.source_key, event.event_key);
        rows(&tx, "SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1,0))", &[&identity], deadline, error).await?;
        let seen = rows(&tx, "SELECT fingerprint FROM openmybot.channel_events WHERE channel_kind=$1 AND source_key=$2 AND event_key=$3", &[&channel, &event.source_key, &event.event_key], deadline, error).await?;
        if let Some(row) = seen.first() {
            let stored: Option<Vec<u8>> = row.try_get(0).map_err(|_| error)?;
            return Ok(match stored {
                Some(stored) if event.fingerprint.is_none_or(|new| new[..] != stored[..]) => {
                    AcceptOutcome::Conflict
                }
                _ => AcceptOutcome::Duplicate,
            });
        }
        let record_id = Uuid::now_v7();
        struct Record {
            disposition: Disposition,
            binding: Option<Uuid>,
            identity: bool,
            command: Option<Command>,
            message: Option<(String, String)>,
            reply: Option<(&'static str, String, String)>,
        }
        let bare = |disposition| Record { disposition, binding: None, identity: false, command: None, message: None, reply: None };
        let record = 'decide: {
            let normal = match (&event.content, &event.sender, &event.chat, event.fingerprint) {
                (Content::Malformed, ..) => None,
                (content, Some(sender), Some(chat), Some(fingerprint)) => Some((content, sender, chat, fingerprint)),
                _ => None,
            };
            let Some((content, sender, chat, fingerprint)) = normal else {
                break 'decide Record { identity: true, ..bare(Disposition::RejectedMalformed) };
            };
            if !event.private {
                break 'decide bare(Disposition::DroppedNotPrivate);
            }
            let found = rows(&tx, "SELECT b.binding_id,b.status='active',b.chat_key,b.workspace_dir,b.thread_id,$4::timestamptz BETWEEN statement_timestamp()-make_interval(secs=>$5) AND statement_timestamp()+make_interval(secs=>$6),(SELECT count(*) FROM openmybot.channel_events e WHERE e.binding_id=b.binding_id AND e.dispatch_status='pending') FROM openmybot.channel_bindings b WHERE b.binding_kind='sender' AND b.channel_kind=$1 AND b.source_key=$2 AND b.sender_key=$3 AND b.status IN ('active','suspended') FOR SHARE OF b", &[&channel, &event.source_key, &sender.as_str(), &event.occurred_at, &EVENT_PAST_WINDOW.as_secs_f64(), &EVENT_FUTURE_WINDOW.as_secs_f64()], deadline, error).await?;
            let Some(binding) = found.first() else {
                let Content::Text { pair_code: Some(code), .. } = content else {
                    break 'decide bare(Disposition::DroppedUnbound);
                };
                let outcome = pair_attempt(&tx, PairAttempt { channel: event.channel, receiver_source_key: &receiver_source_key, sender_key: sender, chat_key: chat, code_text: code, event: AcceptedEvent { event_key: &event.event_key, source_key: &event.source_key, fingerprint, occurred_at: event.occurred_at, event_type: Some(&event.event_type) } }, deadline).await?;
                return Ok(AcceptOutcome::Recorded(match outcome {
                    PairOutcome::Succeeded { .. } => Disposition::PairingSucceeded,
                    PairOutcome::Failed => Disposition::PairingFailed,
                    PairOutcome::Locked => Disposition::PairingLocked,
                }));
            };
            let binding_id: Uuid = binding.try_get(0).map_err(|_| error)?;
            let bound = |disposition| Record { binding: Some(binding_id), identity: true, ..bare(disposition) };
            if !binding.try_get::<_, bool>(1).map_err(|_| error)? {
                break 'decide bound(Disposition::DroppedInactive);
            }
            let chat_key: String = binding.try_get(2).map_err(|_| error)?;
            let reject = |disposition, body: &str| Record { reply: Some(("reject_reply", body.to_owned(), chat_key.clone())), ..bound(disposition) };
            if !binding.try_get::<_, Option<bool>>(5).map_err(|_| error)?.unwrap_or(false) {
                break 'decide reject(Disposition::RejectedOutsideWindow, replies.outside_window);
            }
            let Content::Text { text, command, .. } = content else {
                break 'decide reject(Disposition::RejectedUnsupported, replies.unsupported);
            };
            if text.len() > MSG_TEXT_MAX {
                break 'decide reject(Disposition::RejectedTooLong, replies.too_long);
            }
            if let Some(command) = *command {
                let body = match command {
                    Command::Help | Command::Start => replies.help.to_owned(),
                    Command::Cancel => {
                        let open = rows(&tx, "SELECT EXISTS (SELECT 1 FROM openmybot.channel_events WHERE binding_id=$1 AND dispatch_status='dispatched' AND terminal_kind IS NULL)", &[&binding_id], deadline, error).await?;
                        match open.first().ok_or(error)?.try_get::<_, bool>(0).map_err(|_| error)? {
                            true => replies.cancel_requested.to_owned(),
                            false => replies.cancel_none.to_owned(),
                        }
                    }
                    Command::Pair => replies.already_bound.to_owned(),
                    Command::Unknown => replies.unknown_command.to_owned(),
                    Command::Status => {
                        let workspace: String = binding.try_get(3).map_err(|_| error)?;
                        let pending: i64 = binding.try_get(6).map_err(|_| error)?;
                        let latest = rows(&tx, "SELECT s.dispatch_status,s.terminal_kind,g.gap_reason,g.gap_started_at,g.gap_ended_at FROM (SELECT 1) one LEFT JOIN LATERAL (SELECT dispatch_status,terminal_kind FROM openmybot.channel_events WHERE binding_id=$1 AND disposition='accepted_message' ORDER BY accepted_at DESC,record_id DESC LIMIT 1) s ON true LEFT JOIN LATERAL (SELECT gap_reason,gap_started_at,gap_ended_at FROM openmybot.channel_events WHERE binding_id=$2 AND record_kind='gap' ORDER BY gap_started_at DESC,record_id DESC LIMIT 1) g ON true", &[&binding_id, &receiver_binding_id], deadline, error).await?;
                        let latest = latest.first().ok_or(error)?;
                        let states = &replies.states;
                        let status: Option<String> = latest.try_get(0).map_err(|_| error)?;
                        let terminal: Option<String> = latest.try_get(1).map_err(|_| error)?;
                        let state = match (status.as_deref(), terminal.as_deref()) {
                            (_, Some("succeeded")) => states.succeeded,
                            (_, Some("failed")) => states.failed,
                            (_, Some("cancelled")) | (Some("cancelled"), _) => states.cancelled,
                            (_, Some(_)) => states.reconciliation,
                            (Some("pending"), _) => states.queued,
                            (Some("dispatched"), _) => states.running,
                            (Some("conflict"), _) => states.conflict,
                            (Some(_), _) => states.expired,
                            (None, _) => states.none,
                        };
                        let gap = match latest.try_get::<_, Option<String>>(2).map_err(|_| error)? {
                            None => states.none.to_owned(),
                            Some(reason) => {
                                let started = rfc3339(latest.try_get(3).map_err(|_| error)?, error)?;
                                let ended = match latest.try_get::<_, Option<OffsetDateTime>>(4).map_err(|_| error)? {
                                    Some(ended) => rfc3339(ended, error)?,
                                    None => states.running.to_owned(),
                                };
                                format!("{reason} {started}–{ended}")
                            }
                        };
                        replies
                            .status
                            .replace("{channel}", channel)
                            .replace("{dir}", workspace.rsplit('/').next().unwrap_or_default())
                            .replace("{state}", state)
                            .replace("{pending}", &pending.to_string())
                            .replace("{gap}", &gap)
                    }
                };
                break 'decide Record { command: Some(command), reply: Some(("control_reply", body, chat_key.clone())), ..bound(Disposition::ControlCommand) };
            }
            if binding.try_get::<_, i64>(6).map_err(|_| error)? >= DISPATCH_QUEUE_MAX {
                break 'decide reject(Disposition::RejectedQueueFull, replies.queue_full);
            }
            let thread_id: String = binding.try_get(4).map_err(|_| error)?;
            Record { message: Some((text.clone(), thread_id)), ..bound(Disposition::AcceptedMessage) }
        };
        let (sender, chat, fingerprint) = match record.identity {
            true => (event.sender.as_ref().map(IdentityKey::as_str), event.chat.as_ref().map(IdentityKey::as_str), event.fingerprint.map(|f| f.to_vec())),
            false => (None, None, None),
        };
        let (text, text_sha256, run, thread, dispatch) = match &record.message {
            Some((text, thread)) => (Some(text.as_str()), Some(Sha256::digest(text.as_bytes()).to_vec()), record.binding.map(|binding| run_id(binding, record_id).to_string()), Some(thread.as_str()), Some("pending")),
            None => (None, None, None, None, None),
        };
        rows(&tx, "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,event_type,occurred_at,accepted_at,fingerprint,sender_key,chat_key,binding_id,disposition,command,text,text_sha256,run_id,thread_id,dispatch_status) VALUES ($1,'event',$2,$3,$4,$5,$6,statement_timestamp(),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING record_id", &[&record_id, &channel, &event.source_key, &event.event_key, &event.event_type, &event.occurred_at, &fingerprint, &sender, &chat, &record.binding, &record.disposition.as_str(), &record.command.map(Command::as_str), &text, &text_sha256, &run, &thread, &dispatch], deadline, error).await?;
        if let Some((kind, body, chat_key)) = &record.reply {
            rows(&tx, "INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,body,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',statement_timestamp()) RETURNING delivery_id", &[&Uuid::now_v7(), &record.binding, &channel, chat_key, kind, &format!("{kind}:{record_id}"), body], deadline, error).await?;
        }
        Ok(match (record.command, record.binding) {
            (Some(Command::Cancel), Some(binding)) => AcceptOutcome::Cancel(binding),
            _ => AcceptOutcome::Recorded(record.disposition),
        })
    }
    .await?;
    timeout_at(deadline, tx.commit())
        .await
        .map_err(|_| error)?
        .map_err(|_| error)?;
    timely(deadline, Ok(outcome), error)
}

/// The newest event row of a source by acceptance time, as `(update_id, accepted_at)`.
pub async fn latest_update_id(
    client: &Client,
    channel: Channel,
    source_key: &str,
) -> Result<Option<(u64, OffsetDateTime)>, StoreError> {
    let error = StoreError::EventFailed;
    let found = rows(client, "SELECT event_key,accepted_at FROM openmybot.channel_events WHERE record_kind='event' AND channel_kind=$1 AND source_key=$2 ORDER BY accepted_at DESC,record_id DESC LIMIT 1", &[&channel.as_str(), &source_key], Instant::now() + READ_BUDGET, error).await?;
    found
        .first()
        .map(|row| {
            let key: String = row.try_get(0).map_err(|_| error)?;
            Ok((
                key.parse().map_err(|_| error)?,
                row.try_get(1).map_err(|_| error)?,
            ))
        })
        .transpose()
}

pub struct ReceiverRow {
    pub binding_id: Uuid,
    pub source_key: String,
    pub credential_envelope: String,
}
impl core::fmt::Debug for ReceiverRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceiverRow")
            .field("binding_id", &self.binding_id)
            .field("source_key", &self.source_key)
            .field("credential_envelope", &"[REDACTED]")
            .finish()
    }
}
pub async fn list_active_receivers(
    client: &Client,
    channel: Channel,
) -> Result<Vec<ReceiverRow>, StoreError> {
    let error = StoreError::EventFailed;
    rows(client, "SELECT binding_id,source_key,credential_envelope FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND channel_kind=$1 AND status='active' ORDER BY created_at,binding_id", &[&channel.as_str()], Instant::now() + READ_BUDGET, error)
        .await?
        .iter()
        .map(|row| {
            Ok(ReceiverRow {
                binding_id: row.try_get(0).map_err(|_| error)?,
                source_key: row.try_get(1).map_err(|_| error)?,
                credential_envelope: row.try_get(2).map_err(|_| error)?,
            })
        })
        .collect()
}

/// The active or suspended receiver row with its sealed envelope.
pub async fn receiver_row(
    client: &Client,
    binding_id: Uuid,
    deadline: Instant,
) -> Result<Option<ReceiverRow>, StoreError> {
    let error = StoreError::EventFailed;
    rows(client, "SELECT binding_id,source_key,credential_envelope FROM openmybot.channel_bindings WHERE binding_id=$1 AND binding_kind='receiver' AND status IN ('active','suspended')", &[&binding_id], deadline, error)
        .await?
        .first()
        .map(|row| {
            Ok(ReceiverRow {
                binding_id: row.try_get(0).map_err(|_| error)?,
                source_key: row.try_get(1).map_err(|_| error)?,
                credential_envelope: row.try_get(2).map_err(|_| error)?,
            })
        })
        .transpose()
}
/// The binding's dispatched run without a terminal; dispatch keeps at most one.
pub async fn open_run(client: &Client, binding_id: Uuid) -> Result<Option<OpenRun>, StoreError> {
    let error = StoreError::EventFailed;
    rows(client, "SELECT thread_id,run_id FROM openmybot.channel_events WHERE binding_id=$1 AND dispatch_status='dispatched' AND terminal_kind IS NULL AND run_id IS NOT NULL ORDER BY dispatched_at,record_id LIMIT 1", &[&binding_id], Instant::now() + READ_BUDGET, error)
        .await?
        .first()
        .map(|row| {
            Ok(OpenRun {
                thread_id: row.try_get(0).map_err(|_| error)?,
                run_id: row.try_get(1).map_err(|_| error)?,
            })
        })
        .transpose()
}

pub struct DispatchItem {
    pub record_id: Uuid,
    pub binding_id: Uuid,
    pub revision: u64,
    pub thread_id: String,
    pub run_id: String,
    pub text: String,
    pub attempts: u32,
}
pub enum Claim {
    Item(DispatchItem),
    /// Nothing is due; `wake_at` is the nearest scheduled retry, if any.
    Idle {
        wake_at: Option<OffsetDateTime>,
    },
}
/// Reads the oldest dispatchable event: per active binding only its oldest pending event, and only
/// while the binding has no dispatched event without a terminal and the latest dispatched event of
/// its current thread did not end in reconciliation (a host binding has no thread to pause).
pub async fn claim_dispatch(client: &Client) -> Result<Claim, StoreError> {
    let error = StoreError::DispatchFailed;
    let heads = rows(client, "SELECT e.record_id,e.binding_id,b.revision,e.thread_id,e.run_id,e.text,e.dispatch_attempts,e.next_dispatch_at,e.next_dispatch_at IS NULL OR e.next_dispatch_at<=statement_timestamp() FROM openmybot.channel_events e JOIN openmybot.channel_bindings b ON b.binding_id=e.binding_id WHERE e.dispatch_status='pending' AND b.status='active' AND NOT EXISTS (SELECT 1 FROM openmybot.channel_events p WHERE p.binding_id=e.binding_id AND p.dispatch_status='pending' AND (p.accepted_at,p.record_id)<(e.accepted_at,e.record_id)) AND NOT EXISTS (SELECT 1 FROM openmybot.channel_events d WHERE d.binding_id=e.binding_id AND d.dispatch_status='dispatched' AND d.terminal_kind IS NULL) AND (SELECT d.terminal_kind FROM openmybot.channel_events d WHERE d.binding_id=e.binding_id AND d.thread_id=b.thread_id AND d.dispatch_status='dispatched' ORDER BY d.dispatched_at DESC,d.record_id DESC LIMIT 1) IS DISTINCT FROM 'reconciliation_required' ORDER BY e.accepted_at,e.record_id", &[], Instant::now() + READ_BUDGET, error).await?;
    let mut wake_at = None;
    for row in &heads {
        if row.try_get::<_, bool>(8).map_err(|_| error)? {
            return Ok(Claim::Item(DispatchItem {
                record_id: row.try_get(0).map_err(|_| error)?,
                binding_id: row.try_get(1).map_err(|_| error)?,
                revision: count(row, 2, error)?,
                thread_id: row.try_get(3).map_err(|_| error)?,
                run_id: row.try_get(4).map_err(|_| error)?,
                text: row.try_get(5).map_err(|_| error)?,
                attempts: u32::try_from(row.try_get::<_, i32>(6).map_err(|_| error)?)
                    .map_err(|_| error)?,
            }));
        }
        // A head that is not due has a scheduled retry time.
        let at: OffsetDateTime = row.try_get(7).map_err(|_| error)?;
        wake_at = Some(wake_at.map_or(at, |earliest: OffsetDateTime| earliest.min(at)));
    }
    Ok(Claim::Idle { wake_at })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    Dispatched,
    Conflict,
    RetryAfter(Duration),
    GrantStale,
}
/// Records one `begin` receipt; an event that is no longer pending is left unchanged.
pub async fn record_dispatch(
    client: &mut Client,
    record_id: Uuid,
    outcome: DispatchOutcome,
    deadline: Instant,
) -> Result<(), StoreError> {
    let error = StoreError::DispatchFailed;
    match outcome {
        DispatchOutcome::Dispatched => rows(client, "UPDATE openmybot.channel_events SET dispatch_status='dispatched',dispatched_at=statement_timestamp(),dispatch_attempts=dispatch_attempts+1 WHERE record_id=$1 AND dispatch_status='pending' RETURNING record_id", &[&record_id], deadline, error).await,
        DispatchOutcome::Conflict => rows(client, "UPDATE openmybot.channel_events SET dispatch_status='conflict',dispatch_attempts=dispatch_attempts+1 WHERE record_id=$1 AND dispatch_status='pending' RETURNING record_id", &[&record_id], deadline, error).await,
        DispatchOutcome::RetryAfter(delay) => rows(client, "UPDATE openmybot.channel_events SET dispatch_attempts=dispatch_attempts+1,next_dispatch_at=statement_timestamp()+make_interval(secs=>$2) WHERE record_id=$1 AND dispatch_status='pending' RETURNING record_id", &[&record_id, &delay.as_secs_f64()], deadline, error).await,
        // One statement: the event is cancelled and its still-active binding suspended together.
        DispatchOutcome::GrantStale => rows(client, "WITH e AS (UPDATE openmybot.channel_events SET dispatch_status='cancelled',dispatch_attempts=dispatch_attempts+1 WHERE record_id=$1 AND dispatch_status='pending' RETURNING binding_id) UPDATE openmybot.channel_bindings b SET status='suspended',status_reason='grant_stale',suspended_at=statement_timestamp() FROM e WHERE b.binding_id=e.binding_id AND b.status='active' RETURNING b.binding_id", &[&record_id], deadline, error).await,
    }
    .map(drop)
}

pub struct Expired {
    pub count: u64,
    /// When the oldest remaining pending event reaches the TTL.
    pub next_due: Option<OffsetDateTime>,
}
/// Expires pending events older than `ttl` and queues one expiry notice for each.
pub async fn expire_pending(
    client: &mut Client,
    ttl: Duration,
    notice: &str,
    deadline: Instant,
) -> Result<Expired, StoreError> {
    let error = StoreError::DispatchFailed;
    let found = rows(client, "WITH x AS (UPDATE openmybot.channel_events SET dispatch_status='expired' WHERE dispatch_status='pending' AND accepted_at<=statement_timestamp()-make_interval(secs=>$1) RETURNING record_id,binding_id,channel_kind), d AS (INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,body,status,created_at) SELECT gen_random_uuid(),x.binding_id,x.channel_kind,b.chat_key,'expiry_notice','expiry_notice:'||x.record_id,$2,'pending',statement_timestamp() FROM x JOIN openmybot.channel_bindings b ON b.binding_id=x.binding_id RETURNING 1) SELECT (SELECT count(*) FROM x),(SELECT min(accepted_at)+make_interval(secs=>$1) FROM openmybot.channel_events WHERE dispatch_status='pending' AND accepted_at>statement_timestamp()-make_interval(secs=>$1))", &[&ttl.as_secs_f64(), &notice], deadline, error).await?;
    let row = found.first().ok_or(error)?;
    Ok(Expired {
        count: count(row, 0, error)?,
        next_due: row.try_get(1).map_err(|_| error)?,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PollGapReason {
    ConnectFailed,
    StreamBroken,
}
/// Opens a polling gap unless one of either polling reason is already open for the receiver.
pub async fn open_poll_gap(
    client: &mut Client,
    receiver: Uuid,
    reason: PollGapReason,
    deadline: Instant,
) -> Result<(), StoreError> {
    let reason = match reason {
        PollGapReason::ConnectFailed => "connect_failed",
        PollGapReason::StreamBroken => "stream_broken",
    };
    let record_id = Uuid::now_v7();
    rows(client, "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_reason) SELECT $1,'gap',b.channel_kind,b.source_key,$2,statement_timestamp(),b.binding_id,'gap',statement_timestamp(),$4 FROM openmybot.channel_bindings b WHERE b.binding_id=$3 AND NOT EXISTS (SELECT 1 FROM openmybot.channel_events g WHERE g.binding_id=b.binding_id AND g.record_kind='gap' AND g.gap_reason IN ('connect_failed','stream_broken') AND g.gap_ended_at IS NULL) RETURNING record_id", &[&record_id, &format!("gap:{record_id}"), &receiver, &reason], deadline, StoreError::GapFailed).await.map(drop)
}
/// Closes the receiver's open polling gaps; other gap reasons stay open.
pub async fn close_poll_gaps(
    client: &mut Client,
    receiver: Uuid,
    deadline: Instant,
) -> Result<u64, StoreError> {
    rows(client, "UPDATE openmybot.channel_events SET gap_ended_at=statement_timestamp() WHERE binding_id=$1 AND record_kind='gap' AND gap_reason IN ('connect_failed','stream_broken') AND gap_ended_at IS NULL RETURNING record_id", &[&receiver], deadline, StoreError::GapFailed).await.map(|closed| closed.len() as u64)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suspension {
    CredentialRejected,
    WebhookConflict,
}
/// Suspends an active receiver and opens its `receiver_suspended` gap in one statement.
pub async fn suspend_receiver(
    client: &mut Client,
    receiver: Uuid,
    why: Suspension,
    deadline: Instant,
) -> Result<(), StoreError> {
    let why = match why {
        Suspension::CredentialRejected => "credential_rejected",
        Suspension::WebhookConflict => "webhook_conflict",
    };
    let record_id = Uuid::now_v7();
    rows(client, "WITH s AS (UPDATE openmybot.channel_bindings SET status='suspended',status_reason=$2,suspended_at=statement_timestamp() WHERE binding_id=$1 AND binding_kind='receiver' AND status='active' RETURNING binding_id,channel_kind,source_key,suspended_at) INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_reason) SELECT $3,'gap',channel_kind,source_key,$4,statement_timestamp(),binding_id,'gap',suspended_at,'receiver_suspended' FROM s RETURNING record_id", &[&receiver, &why, &record_id, &format!("gap:{record_id}")], deadline, StoreError::GapFailed).await.map(drop)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StartupGaps {
    pub daemon_down: u64,
    pub receiver_suspended: u64,
}
/// At daemon start: one `daemon_down` gap per active receiver from the previous token's stop or
/// last heartbeat, and a `receiver_suspended` gap for each suspended receiver lacking an open one.
pub async fn record_startup_gaps(
    client: &mut Client,
    token_id: Uuid,
    deadline: Instant,
) -> Result<StartupGaps, StoreError> {
    let error = StoreError::GapFailed;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let down = rows(client, "WITH p AS (SELECT CASE WHEN revoke_reason='daemon_stop' THEN revoked_at ELSE last_heartbeat_at END started FROM openmybot.control_tokens WHERE token_id<>$1 ORDER BY created_at DESC,token_id DESC LIMIT 1) INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_ended_at,gap_reason) SELECT r.id,'gap',r.channel_kind,r.source_key,'gap:'||r.id,statement_timestamp(),r.binding_id,'gap',p.started,statement_timestamp(),'daemon_down' FROM p CROSS JOIN (SELECT gen_random_uuid() id,binding_id,channel_kind,source_key FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND status='active') r RETURNING record_id", &[&token_id], deadline, error).await?;
        let suspended = rows(client, "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,gap_started_at,gap_reason) SELECT r.id,'gap',r.channel_kind,r.source_key,'gap:'||r.id,statement_timestamp(),r.binding_id,'gap',r.suspended_at,'receiver_suspended' FROM (SELECT gen_random_uuid() id,b.binding_id,b.channel_kind,b.source_key,b.suspended_at FROM openmybot.channel_bindings b WHERE b.binding_kind='receiver' AND b.status='suspended' AND NOT EXISTS (SELECT 1 FROM openmybot.channel_events g WHERE g.binding_id=b.binding_id AND g.record_kind='gap' AND g.gap_reason='receiver_suspended' AND g.gap_ended_at IS NULL)) r RETURNING record_id", &[], deadline, error).await?;
        timely(deadline, Ok(StartupGaps { daemon_down: down.len() as u64, receiver_suspended: suspended.len() as u64 }), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

pub struct GapView {
    pub reason: String,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
}
pub struct ReceiverStatus {
    pub channel: Channel,
    pub binding_id: Uuid,
    pub status: String,
    pub status_reason: Option<String>,
    pub pending_dispatch: u64,
    /// Open gaps and gaps ended within `GAP_DISPLAY`, newest first.
    pub gaps: Vec<GapView>,
}
/// Active and suspended receivers with their pending dispatch count and recent gaps.
pub async fn channel_status(client: &Client) -> Result<Vec<ReceiverStatus>, StoreError> {
    let error = StoreError::GapFailed;
    let deadline = Instant::now() + READ_BUDGET;
    let receivers = rows(client, "SELECT b.binding_id,b.channel_kind,b.status,b.status_reason,(SELECT count(*) FROM openmybot.channel_events e WHERE e.channel_kind=b.channel_kind AND e.source_key=b.source_key AND e.dispatch_status='pending') FROM openmybot.channel_bindings b WHERE b.binding_kind='receiver' AND b.status IN ('active','suspended') ORDER BY b.channel_kind,b.created_at", &[], deadline, error).await?;
    let gaps = rows(client, "SELECT g.binding_id,g.gap_reason,g.gap_started_at,g.gap_ended_at FROM openmybot.channel_events g JOIN openmybot.channel_bindings b ON b.binding_id=g.binding_id WHERE g.record_kind='gap' AND b.binding_kind='receiver' AND b.status IN ('active','suspended') AND (g.gap_ended_at IS NULL OR g.gap_ended_at>=statement_timestamp()-make_interval(secs=>$1)) ORDER BY g.gap_started_at DESC,g.record_id DESC", &[&GAP_DISPLAY.as_secs_f64()], deadline, error).await?;
    receivers
        .iter()
        .map(|row| {
            let binding_id: Uuid = row.try_get(0).map_err(|_| error)?;
            let channel = match row.try_get::<_, &str>(1).map_err(|_| error)? {
                "telegram" => Channel::Telegram,
                "feishu" => Channel::Feishu,
                _ => return Err(error),
            };
            Ok(ReceiverStatus {
                channel,
                binding_id,
                status: row.try_get(2).map_err(|_| error)?,
                status_reason: row.try_get(3).map_err(|_| error)?,
                pending_dispatch: count(row, 4, error)?,
                gaps: gaps
                    .iter()
                    .filter(|gap| gap.try_get::<_, Uuid>(0).ok() == Some(binding_id))
                    .map(|gap| {
                        Ok(GapView {
                            reason: gap.try_get(1).map_err(|_| error)?,
                            started_at: gap.try_get(2).map_err(|_| error)?,
                            ended_at: gap.try_get(3).map_err(|_| error)?,
                        })
                    })
                    .collect::<Result<_, StoreError>>()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Vectors computed independently with Python's `uuid.uuid5`.
    #[test]
    fn run_id_is_uuidv5_with_independently_computed_vector() {
        assert_eq!(
            uuid_v5(uuid::Uuid::NAMESPACE_URL, "urn:openmybot:v1"),
            OMB_NS
        );
        assert_eq!(OMB_NS.to_string(), "b09a90b8-a527-5aa1-be6d-0645747da37f");
        let binding = Uuid::parse_str("0192f1a2-3b4c-7d5e-8f60-718293a4b5c6").unwrap();
        let trigger = Uuid::parse_str("0192f1a2-3b4c-7d5e-8f60-000000000001").unwrap();
        let minted = run_id(binding, trigger);
        assert_eq!(minted.to_string(), RUN_VECTOR);
        assert_eq!(minted.get_version_num(), 5);
    }
    #[test]
    fn run_id_name_is_run_binding_colon_trigger_in_lowercase_hyphenated_text() {
        let binding = Uuid::parse_str("0192F1A2-3B4C-7D5E-8F60-718293A4B5C6").unwrap();
        let trigger = Uuid::parse_str("0192F1A2-3B4C-7D5E-8F60-000000000001").unwrap();
        let name = "run:0192f1a2-3b4c-7d5e-8f60-718293a4b5c6:0192f1a2-3b4c-7d5e-8f60-000000000001";
        assert_eq!(run_id(binding, trigger), uuid_v5(OMB_NS, name));
        assert_ne!(
            run_id(binding, trigger),
            uuid_v5(OMB_NS, &name.to_uppercase())
        );
        assert_ne!(run_id(trigger, binding), run_id(binding, trigger));
    }
    const RUN_VECTOR: &str = "3b5a3661-5a30-58d9-9995-50796e16f538";
}
