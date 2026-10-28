use crate::{KEY_MAX, RUN_DEADLINE_MAX, StoreError, command, finish, rows, timely, unique_rows};
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

/// Owner revocation: terminal, clears secrets and cancels the binding's pending events.
pub async fn revoke_binding(
    client: &mut Client,
    binding_id: Uuid,
    deadline: Instant,
) -> Result<(), StoreError> {
    let error = StoreError::BindingFailed;
    let result = async {
        command(client, "BEGIN", deadline, error).await?;
        // A receiver row must keep a non-null envelope column, so its envelope is emptied instead.
        let revoked = rows(client, "UPDATE openmybot.channel_bindings SET status='revoked',status_reason='owner_revoked',ended_at=statement_timestamp(),pairing_code_hash=NULL,credential_envelope=CASE WHEN binding_kind='receiver' THEN '' END WHERE binding_id=$1 AND status IN ('pending','active','suspended') RETURNING binding_id", &[&binding_id], deadline, error).await?;
        if revoked.is_empty() {
            return Err(refusal(client, binding_id, deadline).await);
        }
        rows(client, "UPDATE openmybot.channel_events SET dispatch_status='cancelled' WHERE binding_id=$1 AND dispatch_status='pending' RETURNING record_id", &[&binding_id], deadline, error).await?;
        timely(deadline, Ok(()), error)
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
