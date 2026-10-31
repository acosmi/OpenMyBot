use crate::{
    Channel, KEY_MAX, RUN_DEADLINE_MAX, StoreError, command, finish, rows, timely, unique_rows,
};
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

/// External identity key: printable ASCII, 1..=`KEY_MAX` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityKey(String);
impl IdentityKey {
    pub fn parse(text: &str) -> Option<Self> {
        ((1..=KEY_MAX).contains(&text.len()) && text.bytes().all(|b| (b' '..=b'~').contains(&b)))
            .then(|| Self(text.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Run duration granted to a binding: 1..=`RUN_DEADLINE_MAX` seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunDeadline(u32);
impl RunDeadline {
    pub fn parse(seconds: u32) -> Option<Self> {
        (1..=RUN_DEADLINE_MAX)
            .contains(&seconds)
            .then_some(Self(seconds))
    }
    pub fn get(self) -> u32 {
        self.0
    }
}

pub struct HostBinding<'a> {
    pub workspace_dir: &'a str,
    pub granted_generation: u64,
    pub run_deadline: Option<RunDeadline>,
}
/// Activates the single local host binding.
pub async fn activate_host(
    client: &mut Client,
    input: HostBinding<'_>,
    deadline: Instant,
) -> Result<Uuid, StoreError> {
    let error = StoreError::BindingFailed;
    let generation = i64::try_from(input.granted_generation).map_err(|_| error)?;
    let run_deadline = input
        .run_deadline
        .map(|value| i32::try_from(value.get()).map_err(|_| error))
        .transpose()?;
    let binding_id = Uuid::now_v7();
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        unique_rows(client, "INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,workspace_dir,granted_generation,run_deadline_seconds,revision,status,created_at,activated_at) VALUES ($1,'host','host','crabcode','host:crabcode',$2,$3,$4,1,'active',statement_timestamp(),statement_timestamp()) RETURNING binding_id", &[&binding_id, &input.workspace_dir, &generation, &run_deadline], deadline, StoreError::ChannelAlreadyBound, error).await?;
        timely(deadline, Ok(binding_id), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

/// Distinguishes a missing binding from one whose state forbids the transition.
async fn refusal(client: &Client, binding_id: Uuid, deadline: Instant) -> StoreError {
    match rows(
        client,
        "SELECT 1 FROM openmybot.channel_bindings WHERE binding_id=$1",
        &[&binding_id],
        deadline,
        StoreError::BindingFailed,
    )
    .await
    {
        Ok(found) if found.is_empty() => StoreError::BindingNotFound,
        Ok(_) => StoreError::BindingStateInvalid,
        Err(error) => error,
    }
}

/// A run of a binding by thread and run id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRun {
    pub thread_id: String,
    pub run_id: String,
}
/// The runs an ended binding may still have: dispatched runs without a terminal, and the runs
/// of the pending messages it cancelled, which an earlier begin attempt may have started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    pub dispatched: Vec<OpenRun>,
    pub pending: Vec<OpenRun>,
}
/// Ends the channel's live sender for `reason` when `senders_of` names a channel, then settles
/// every ended binding: pending events cancelled, undecided permissions denied as `run_stopped`;
/// returns the runs of the cancelled events in acceptance order and the dispatched runs without
/// a terminal in dispatch order.
async fn settle(
    client: &Client,
    mut ended: Vec<Uuid>,
    senders_of: Option<&str>,
    reason: &str,
    deadline: Instant,
) -> Result<Settled, StoreError> {
    let error = StoreError::BindingFailed;
    if let Some(channel) = senders_of {
        for row in rows(client, "UPDATE openmybot.channel_bindings SET status=CASE WHEN status='pending' THEN 'expired' ELSE 'revoked' END,status_reason=$2,ended_at=statement_timestamp(),pairing_code_hash=NULL WHERE binding_kind='sender' AND channel_kind=$1 AND status IN ('pending','active','suspended') RETURNING binding_id", &[&channel, &reason], deadline, error).await? {
            ended.push(row.try_get(0).map_err(|_| error)?);
        }
    }
    let pending = rows(client, "WITH c AS (UPDATE openmybot.channel_events SET dispatch_status='cancelled' WHERE binding_id=ANY($1) AND dispatch_status='pending' RETURNING thread_id,run_id,accepted_at,record_id) SELECT thread_id,run_id FROM c ORDER BY accepted_at,record_id", &[&ended], deadline, error).await?;
    rows(client, "UPDATE openmybot.host_driver_sessions SET decision='deny',decided_via='run_stopped',decided_at=statement_timestamp() WHERE record_kind='permission' AND binding_id=ANY($1) AND decision IS NULL RETURNING record_id", &[&ended], deadline, error).await?;
    let dispatched = rows(client, "SELECT thread_id,run_id FROM openmybot.channel_events WHERE binding_id=ANY($1) AND dispatch_status='dispatched' AND terminal_kind IS NULL AND run_id IS NOT NULL ORDER BY dispatched_at,record_id", &[&ended], deadline, error).await?;
    let runs = |found: &[tokio_postgres::Row]| {
        found
            .iter()
            .map(|row| {
                Ok(OpenRun {
                    thread_id: row.try_get(0).map_err(|_| error)?,
                    run_id: row.try_get(1).map_err(|_| error)?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()
    };
    Ok(Settled {
        dispatched: runs(&dispatched)?,
        pending: runs(&pending)?,
    })
}

/// Owner revocation: terminal, clears secrets, and settles the binding and, for a receiver, its
/// channel's sender; returns the settled runs to cancel.
pub async fn revoke_binding(
    client: &mut Client,
    binding_id: Uuid,
    deadline: Instant,
) -> Result<Settled, StoreError> {
    let error = StoreError::BindingFailed;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        // A receiver row must keep a non-null envelope column, so its envelope is emptied instead.
        let revoked = rows(client, "UPDATE openmybot.channel_bindings SET status='revoked',status_reason='owner_revoked',ended_at=statement_timestamp(),pairing_code_hash=NULL,credential_envelope=CASE WHEN binding_kind='receiver' THEN '' END WHERE binding_id=$1 AND status IN ('pending','active','suspended') RETURNING binding_kind='receiver',channel_kind", &[&binding_id], deadline, error).await?;
        let Some(row) = revoked.first() else {
            return Err(refusal(client, binding_id, deadline).await);
        };
        let channel: String = row.try_get(1).map_err(|_| error)?;
        let senders_of = row.try_get::<_, bool>(0).map_err(|_| error)?.then_some(channel.as_str());
        let settled = settle(client, vec![binding_id], senders_of, "owner_revoked", deadline).await?;
        timely(deadline, Ok(settled), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

/// Reactivates a suspended binding with a new revision and the owner's current generation.
pub async fn reconfirm_binding(
    client: &mut Client,
    binding_id: Uuid,
    granted_generation: u64,
    deadline: Instant,
) -> Result<u64, StoreError> {
    let error = StoreError::BindingFailed;
    let generation = i64::try_from(granted_generation).map_err(|_| error)?;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let updated = rows(client, "UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL,revision=revision+1,granted_generation=$2,reconfirmed_at=statement_timestamp() WHERE binding_id=$1 AND status='suspended' RETURNING revision", &[&binding_id, &generation], deadline, error).await?;
        let Some(row) = updated.first() else {
            return Err(refusal(client, binding_id, deadline).await);
        };
        let revision = u64::try_from(row.try_get::<_, i64>(0).map_err(|_| error)?).map_err(|_| error)?;
        rows(client, "UPDATE openmybot.channel_events SET gap_ended_at=(SELECT reconfirmed_at FROM openmybot.channel_bindings WHERE binding_id=$1) WHERE binding_id=$1 AND record_kind='gap' AND gap_reason='receiver_suspended' AND gap_ended_at IS NULL RETURNING record_id", &[&binding_id], deadline, error).await?;
        timely(deadline, Ok(revision), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrantKind {
    Sender,
    Host,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthorityRow {
    pub kind: GrantKind,
    pub revision: u64,
    pub granted_generation: u64,
    pub run_deadline_seconds: Option<u32>,
}
/// Reads an active sender or host binding in one statement; any other row, or any value that
/// does not convert to the unsigned domain, is absent.
pub async fn authority_row(
    client: &Client,
    binding_id: Uuid,
) -> Result<Option<AuthorityRow>, StoreError> {
    let found = client
        .query("SELECT binding_kind='host',revision,granted_generation,run_deadline_seconds FROM openmybot.channel_bindings WHERE binding_id=$1 AND status='active' AND binding_kind IN ('sender','host')", &[&binding_id])
        .await
        .map_err(|_| StoreError::BindingFailed)?;
    let Some(row) = found.first() else {
        return Ok(None);
    };
    let convert = || -> Option<AuthorityRow> {
        Some(AuthorityRow {
            kind: if row.try_get::<_, bool>(0).ok()? {
                GrantKind::Host
            } else {
                GrantKind::Sender
            },
            revision: u64::try_from(row.try_get::<_, i64>(1).ok()?).ok()?,
            granted_generation: u64::try_from(row.try_get::<_, i64>(2).ok()?).ok()?,
            run_deadline_seconds: row
                .try_get::<_, Option<i32>>(3)
                .ok()?
                .map(u32::try_from)
                .transpose()
                .ok()?,
        })
    };
    Ok(convert())
}

/// The live host binding; `binding_live_kind` keeps at most one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostBindingState {
    NotBound,
    Suspended,
    Active(Uuid),
}
pub async fn host_binding_state(
    client: &Client,
    deadline: Instant,
) -> Result<HostBindingState, StoreError> {
    let error = StoreError::BindingFailed;
    let found = rows(client, "SELECT binding_id,status FROM openmybot.channel_bindings WHERE binding_kind='host' AND status IN ('active','suspended')", &[], deadline, error).await?;
    let Some(row) = found.first() else {
        return Ok(HostBindingState::NotBound);
    };
    Ok(match row.try_get::<_, &str>(1).map_err(|_| error)? {
        "active" => HostBindingState::Active(row.try_get(0).map_err(|_| error)?),
        _ => HostBindingState::Suspended,
    })
}

/// One live binding as the owner lists it; secret and pairing columns are never read.
pub struct BindingView {
    pub binding_id: Uuid,
    pub binding_kind: String,
    pub channel_kind: String,
    pub source_key: String,
    pub sender_key: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub revision: u64,
    pub thread_generation: u32,
    pub workspace_dir: Option<String>,
    pub thread_id: Option<String>,
    pub run_deadline_seconds: Option<u32>,
    pub created_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
    pub suspended_at: Option<OffsetDateTime>,
    pub reconfirmed_at: Option<OffsetDateTime>,
}
/// The pending, active and suspended bindings by kind, channel and creation time.
pub async fn list_bindings(
    client: &Client,
    deadline: Instant,
) -> Result<Vec<BindingView>, StoreError> {
    let error = StoreError::BindingFailed;
    rows(client, "SELECT binding_id,binding_kind,channel_kind,source_key,sender_key,status,status_reason,revision,thread_generation,workspace_dir,thread_id,run_deadline_seconds,created_at,activated_at,suspended_at,reconfirmed_at FROM openmybot.channel_bindings WHERE status IN ('pending','active','suspended') ORDER BY binding_kind,channel_kind,created_at", &[], deadline, error)
        .await?
        .iter()
        .map(|row| {
            Ok(BindingView {
                binding_id: row.try_get(0).map_err(|_| error)?,
                binding_kind: row.try_get(1).map_err(|_| error)?,
                channel_kind: row.try_get(2).map_err(|_| error)?,
                source_key: row.try_get(3).map_err(|_| error)?,
                sender_key: row.try_get(4).map_err(|_| error)?,
                status: row.try_get(5).map_err(|_| error)?,
                status_reason: row.try_get(6).map_err(|_| error)?,
                revision: u64::try_from(row.try_get::<_, i64>(7).map_err(|_| error)?)
                    .map_err(|_| error)?,
                thread_generation: u32::try_from(row.try_get::<_, i32>(8).map_err(|_| error)?)
                    .map_err(|_| error)?,
                workspace_dir: row.try_get(9).map_err(|_| error)?,
                thread_id: row.try_get(10).map_err(|_| error)?,
                run_deadline_seconds: row
                    .try_get::<_, Option<i32>>(11)
                    .map_err(|_| error)?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| error)?,
                created_at: row.try_get(12).map_err(|_| error)?,
                activated_at: row.try_get(13).map_err(|_| error)?,
                suspended_at: row.try_get(14).map_err(|_| error)?,
                reconfirmed_at: row.try_get(15).map_err(|_| error)?,
            })
        })
        .collect()
}

pub struct NewReceiver<'a> {
    pub binding_id: Uuid,
    pub channel: Channel,
    pub source_key: &'a str,
    pub credential_envelope: &'a str,
}
/// Replaces the channel's live receiver, settling it and its sender as `receiver_replaced`, and
/// inserts the verified receiver as active with revision 1; returns the settled runs to cancel.
pub async fn activate_receiver(
    client: &mut Client,
    input: NewReceiver<'_>,
    deadline: Instant,
) -> Result<Settled, StoreError> {
    let error = StoreError::BindingFailed;
    let channel = input.channel.as_str();
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let replaced = rows(client, "UPDATE openmybot.channel_bindings SET status='revoked',status_reason='receiver_replaced',ended_at=statement_timestamp(),credential_envelope='' WHERE binding_kind='receiver' AND channel_kind=$1 AND status IN ('active','suspended') RETURNING binding_id", &[&channel], deadline, error).await?;
        let ended = replaced
            .iter()
            .map(|row| row.try_get(0).map_err(|_| error))
            .collect::<Result<Vec<Uuid>, StoreError>>()?;
        let settled = settle(client, ended, Some(channel), "receiver_replaced", deadline).await?;
        rows(client, "INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,credential_envelope,status,revision,created_at,activated_at) VALUES ($1,'receiver',$2,$3,$4,'active',1,statement_timestamp(),statement_timestamp()) RETURNING binding_id", &[&input.binding_id, &channel, &input.source_key, &input.credential_envelope], deadline, error).await?;
        timely(deadline, Ok(settled), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetDone {
    pub thread_generation: u32,
    pub revision: u64,
}
/// Moves a live sender to a new thread after the owner acknowledged the unknown outcome of the
/// latest dispatched run of its current thread; the old thread and its events stay unchanged.
pub async fn reset_thread(
    client: &mut Client,
    binding_id: Uuid,
    ack_run_id: &str,
    new_thread_id: &str,
    deadline: Instant,
) -> Result<ResetDone, StoreError> {
    let error = StoreError::BindingFailed;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let target = rows(client, "SELECT binding_kind='sender' AND status IN ('active','suspended') FROM openmybot.channel_bindings WHERE binding_id=$1 FOR UPDATE", &[&binding_id], deadline, error).await?;
        let live = target.first().ok_or(StoreError::BindingNotFound)?;
        if !live.try_get::<_, bool>(0).map_err(|_| error)? {
            return Err(StoreError::BindingStateInvalid);
        }
        // A new statement after the lock sees a concurrent reset that committed meanwhile.
        let acknowledged = rows(client, "SELECT (SELECT d.terminal_kind='reconciliation_required' AND d.run_id=$2 FROM openmybot.channel_events d WHERE d.binding_id=b.binding_id AND d.thread_id=b.thread_id AND d.dispatch_status='dispatched' ORDER BY d.dispatched_at DESC,d.record_id DESC LIMIT 1) IS TRUE FROM openmybot.channel_bindings b WHERE b.binding_id=$1", &[&binding_id, &ack_run_id], deadline, error).await?;
        if !acknowledged.first().ok_or(error)?.try_get::<_, bool>(0).map_err(|_| error)? {
            return Err(StoreError::BindingStateInvalid);
        }
        let updated = rows(client, "UPDATE openmybot.channel_bindings SET thread_id=$2,thread_generation=thread_generation+1,revision=revision+1 WHERE binding_id=$1 RETURNING thread_generation,revision", &[&binding_id, &new_thread_id], deadline, error).await?;
        let row = updated.first().ok_or(error)?;
        let done = ResetDone {
            thread_generation: u32::try_from(row.try_get::<_, i32>(0).map_err(|_| error)?)
                .map_err(|_| error)?,
            revision: u64::try_from(row.try_get::<_, i64>(1).map_err(|_| error)?)
                .map_err(|_| error)?,
        };
        rows(client, "UPDATE openmybot.channel_events SET thread_id=$2 WHERE binding_id=$1 AND dispatch_status='pending' RETURNING record_id", &[&binding_id, &new_thread_id], deadline, error).await?;
        timely(deadline, Ok(done), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_key_rejects_non_ascii_and_over_128_bytes() {
        assert_eq!(
            IdentityKey::parse(&"a".repeat(128)).map(|k| k.as_str().len()),
            Some(128)
        );
        assert!(IdentityKey::parse("telegram:42").is_some());
        assert!(IdentityKey::parse(&"a".repeat(129)).is_none());
        assert!(IdentityKey::parse("telegram:é").is_none());
        assert!(IdentityKey::parse("").is_none());
        assert!(IdentityKey::parse("telegram:\n1").is_none());
    }
    #[test]
    fn run_deadline_accepts_1_and_86400_only() {
        assert_eq!(RunDeadline::parse(1).map(RunDeadline::get), Some(1));
        assert_eq!(
            RunDeadline::parse(86_400).map(RunDeadline::get),
            Some(86_400)
        );
        assert!(RunDeadline::parse(0).is_none());
        assert!(RunDeadline::parse(86_401).is_none());
    }
}
