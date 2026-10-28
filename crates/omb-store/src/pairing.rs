use crate::{
    IdentityKey, PAIR_CODE_LEN, PAIR_FAIL_LIMIT, PAIR_LOCK, PAIR_TTL, RunDeadline, StoreError,
    command, finish, rows, timely, unique_rows,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channel {
    Telegram,
    Feishu,
}
impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Telegram => "telegram",
            Self::Feishu => "feishu",
        }
    }
}

/// Plaintext pairing code; shown once and never stored.
pub struct PairCode(String);
impl PairCode {
    fn generate() -> Result<Self, StoreError> {
        let mut bytes = [0; PAIR_CODE_LEN];
        getrandom::fill(&mut bytes).map_err(|_| StoreError::BindingFailed)?;
        // 256 is a multiple of 32, so masking keeps every symbol equally likely.
        Ok(Self(
            bytes
                .iter()
                .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
                .collect(),
        ))
    }
    pub fn display(&self) -> String {
        format!("{}-{}", &self.0[..4], &self.0[4..])
    }
}
impl core::fmt::Debug for PairCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairCode([REDACTED])")
    }
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}
fn code_hash(binding_id: Uuid, code: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(binding_id.as_bytes());
    digest.update(code.as_bytes());
    digest.finalize().into()
}

pub struct PairStart<'a> {
    pub channel: Channel,
    /// Already verified real path.
    pub workspace_dir: &'a str,
    pub thread_id: &'a str,
    pub granted_generation: u64,
    pub run_deadline: Option<RunDeadline>,
}
#[derive(Debug)]
pub struct PairStarted {
    pub binding_id: Uuid,
    pub code: PairCode,
    pub expires_at: time::OffsetDateTime,
}

/// Creates a pending sender binding, superseding any earlier pending one on the channel.
pub async fn pair_start(
    client: &mut Client,
    input: PairStart<'_>,
    deadline: Instant,
) -> Result<PairStarted, StoreError> {
    let error = StoreError::BindingFailed;
    let channel = input.channel.as_str();
    let generation = i64::try_from(input.granted_generation).map_err(|_| error)?;
    let run_deadline = input
        .run_deadline
        .map(|value| i32::try_from(value.get()).map_err(|_| error))
        .transpose()?;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let receiver = rows(client, "SELECT source_key FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND channel_kind=$1 AND status='active'", &[&channel], deadline, error).await?;
        let source_key: String = receiver
            .first()
            .ok_or(StoreError::ReceiverNotActive)?
            .try_get(0)
            .map_err(|_| error)?;
        let live = rows(client, "SELECT status FROM openmybot.channel_bindings WHERE binding_kind='sender' AND channel_kind=$1 AND status IN ('pending','active','suspended') FOR UPDATE", &[&channel], deadline, error).await?;
        if let Some(row) = live.first() {
            let status: String = row.try_get(0).map_err(|_| error)?;
            if status != "pending" {
                return Err(StoreError::ChannelAlreadyBound);
            }
            rows(client, "UPDATE openmybot.channel_bindings SET status='expired',status_reason='superseded',ended_at=statement_timestamp(),pairing_code_hash=NULL WHERE binding_kind='sender' AND channel_kind=$1 AND status='pending' RETURNING binding_id", &[&channel], deadline, error).await?;
        }
        let binding_id = Uuid::now_v7();
        let code = PairCode::generate()?;
        let hash = code_hash(binding_id, &code.0).to_vec();
        let inserted = unique_rows(client, "INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,workspace_dir,thread_id,granted_generation,run_deadline_seconds,pairing_code_hash,pairing_expires_at,status,created_at) VALUES ($1,'sender',$2,$3,$4,$5,$6,$7,$8,statement_timestamp()+make_interval(secs=>$9),'pending',statement_timestamp()) RETURNING pairing_expires_at", &[&binding_id, &channel, &source_key, &input.workspace_dir, &input.thread_id, &generation, &run_deadline, &hash, &PAIR_TTL.as_secs_f64()], deadline, StoreError::ChannelAlreadyBound, error).await?;
        let expires_at = inserted
            .first()
            .ok_or(error)?
            .try_get(0)
            .map_err(|_| error)?;
        timely(deadline, Ok(PairStarted { binding_id, code, expires_at }), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

/// Accepted channel event identity; message text is never stored for pairing events.
pub struct AcceptedEvent<'a> {
    pub event_key: &'a str,
    pub source_key: &'a str,
    pub fingerprint: [u8; 32],
}
pub struct PairAttempt<'a> {
    pub channel: Channel,
    pub receiver_binding_id: Uuid,
    pub sender_key: &'a IdentityKey,
    pub chat_key: &'a IdentityKey,
    pub code_text: &'a str,
    pub event: AcceptedEvent<'a>,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairOutcome {
    Succeeded { binding_id: Uuid },
    Failed,
    Locked,
    Duplicate,
}

/// Evaluates one `/pair` message and records its event in the same transaction.
pub async fn pair_attempt(
    client: &mut Client,
    input: PairAttempt<'_>,
    deadline: Instant,
) -> Result<PairOutcome, StoreError> {
    let error = StoreError::BindingFailed;
    let channel = input.channel.as_str();
    let sender = input.sender_key.as_str();
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        let seen = rows(client, "SELECT 1 FROM openmybot.channel_events WHERE channel_kind=$1 AND source_key=$2 AND event_key=$3", &[&channel, &input.event.source_key, &input.event.event_key], deadline, error).await?;
        if !seen.is_empty() {
            return Ok(PairOutcome::Duplicate);
        }
        let receiver = rows(client, "SELECT source_key FROM openmybot.channel_bindings WHERE binding_id=$1 AND binding_kind='receiver' AND channel_kind=$2 AND status='active'", &[&input.receiver_binding_id, &channel], deadline, error).await?;
        let source_key: String = receiver
            .first()
            .ok_or(StoreError::ReceiverNotActive)?
            .try_get(0)
            .map_err(|_| error)?;
        let lock = rows(client, "SELECT count(*)=$2 AND max(a)-min(a)<=make_interval(secs=>$3) AND statement_timestamp()<max(a)+make_interval(secs=>$3) FROM (SELECT accepted_at a FROM openmybot.channel_events WHERE sender_key=$1 AND disposition='pairing_failed' ORDER BY accepted_at DESC LIMIT $2) recent", &[&sender, &PAIR_FAIL_LIMIT, &PAIR_LOCK.as_secs_f64()], deadline, error).await?;
        let locked: bool = lock.first().ok_or(error)?.try_get(0).map_err(|_| error)?;
        let (outcome, binding_id) = if locked {
            (PairOutcome::Locked, None)
        } else {
            let pending = rows(client, "SELECT binding_id,pairing_code_hash,workspace_dir,pairing_expires_at<=statement_timestamp() FROM openmybot.channel_bindings WHERE binding_kind='sender' AND channel_kind=$1 AND source_key=$2 AND status='pending' FOR UPDATE", &[&channel, &source_key], deadline, error).await?;
            match pending.first() {
                None => (PairOutcome::Failed, None),
                Some(row) => {
                    let binding_id: Uuid = row.try_get(0).map_err(|_| error)?;
                    let stored: Vec<u8> = row.try_get(1).map_err(|_| error)?;
                    let workspace: String = row.try_get(2).map_err(|_| error)?;
                    let expired: bool = row.try_get(3).map_err(|_| error)?;
                    if expired {
                        rows(client, "UPDATE openmybot.channel_bindings SET status='expired',status_reason='pairing_expired',ended_at=statement_timestamp(),pairing_code_hash=NULL WHERE binding_id=$1 RETURNING binding_id", &[&binding_id], deadline, error).await?;
                        (PairOutcome::Failed, Some(binding_id))
                    } else if bool::from(
                        code_hash(binding_id, &normalize(input.code_text))
                            .as_slice()
                            .ct_eq(&stored),
                    ) {
                        rows(client, "UPDATE openmybot.channel_bindings SET status='active',sender_key=$2,chat_key=$3,activated_at=statement_timestamp(),revision=1,pairing_code_hash=NULL WHERE binding_id=$1 RETURNING binding_id", &[&binding_id, &sender, &input.chat_key.as_str()], deadline, error).await?;
                        let name = workspace.rsplit('/').next().unwrap_or_default();
                        let body = format!("绑定成功，工作区 {name}；发送 /help 查看命令");
                        rows(client, "INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,body,status,created_at) VALUES ($1,$2,$3,$4,'pairing_reply',$5,$6,'pending',statement_timestamp()) RETURNING delivery_id", &[&Uuid::now_v7(), &binding_id, &channel, &input.chat_key.as_str(), &format!("pair:{binding_id}"), &body], deadline, error).await?;
                        (PairOutcome::Succeeded { binding_id }, Some(binding_id))
                    } else {
                        (PairOutcome::Failed, Some(binding_id))
                    }
                }
            }
        };
        let disposition = match outcome {
            PairOutcome::Succeeded { .. } => "pairing_succeeded",
            PairOutcome::Locked => "pairing_locked",
            PairOutcome::Failed | PairOutcome::Duplicate => "pairing_failed",
        };
        let fingerprint = input.event.fingerprint.to_vec();
        rows(client, "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,fingerprint,sender_key,chat_key,binding_id,disposition,command) VALUES ($1,'event',$2,$3,$4,statement_timestamp(),$5,$6,$7,$8,$9,'pair') RETURNING record_id", &[&Uuid::now_v7(), &channel, &input.event.source_key, &input.event.event_key, &fingerprint, &sender, &input.chat_key.as_str(), &binding_id, &disposition], deadline, error).await?;
        timely(deadline, Ok(outcome), error)
    }
    .await;
    finish(client, deadline, result, error).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_code_has_eight_crockford_chars() {
        for _ in 0..64 {
            let code = PairCode::generate().unwrap();
            assert_eq!(code.0.len(), PAIR_CODE_LEN);
            assert!(code.0.bytes().all(|b| ALPHABET.contains(&b)));
            assert_eq!(format!("{code:?}"), "PairCode([REDACTED])");
        }
    }
    #[test]
    fn display_groups_four_dash_four() {
        let code = PairCode("ABCD2345".into());
        assert_eq!(code.display(), "ABCD-2345");
    }
    #[test]
    fn normalization_strips_separators_uppercases_and_maps_ilo() {
        assert_eq!(normalize(" ab-cd 23-45 "), "ABCD2345");
        assert_eq!(normalize("iIlL-oO"), "111100");
        assert_eq!(normalize("xyz9"), "XYZ9");
    }
    #[test]
    fn stored_hash_binds_binding_id_bytes_and_code_ascii() {
        let id = Uuid::now_v7();
        let mut expected = Sha256::new();
        expected.update(id.as_bytes());
        expected.update(b"ABCD2345");
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(code_hash(id, "ABCD2345"), expected);
        assert_ne!(code_hash(Uuid::now_v7(), "ABCD2345"), expected);
    }
}
