use crate::{StoreError, command, finish, rows, timely};
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

pub struct ControlTokenStart<'a> {
    pub token_id: Uuid,
    pub token_sha256: [u8; 32],
    pub daemon_pid: i32,
    pub engine_pin: &'a str,
    pub omb_version: &'a str,
}
impl core::fmt::Debug for ControlTokenStart<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlTokenStart")
            .field("token_id", &self.token_id)
            .field("token_sha256", &"[REDACTED]")
            .field("daemon_pid", &self.daemon_pid)
            .field("engine_pin", &self.engine_pin)
            .field("omb_version", &self.omb_version)
            .finish()
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ControlTokenRecord {
    pub token_id: Uuid,
    pub restore_detected: bool,
}

pub async fn start_control_token(
    client: &mut Client,
    input: ControlTokenStart<'_>,
    deadline: Instant,
) -> Result<ControlTokenRecord, StoreError> {
    let error = StoreError::ControlTokenFailed;
    let result=async {
        command(client,"BEGIN",deadline,error).await?;
        // The table lock serializes first-row creation as well as subsequent rotations.
        command(client,"LOCK TABLE openmybot.control_tokens IN EXCLUSIVE MODE",deadline,error).await?;
        let current=rows(client,"SELECT s.system_identifier::text,c.timeline_id FROM pg_control_system() s CROSS JOIN pg_control_checkpoint() c",&[],deadline,error).await?;
        let current=current.first().ok_or(error)?;
        let system:String=current.try_get(0).map_err(|_|error)?;let timeline:i32=current.try_get(1).map_err(|_|error)?;
        let previous=rows(client,"SELECT pg_system_identifier,pg_timeline_id FROM openmybot.control_tokens ORDER BY created_at DESC,token_id DESC LIMIT 1",&[],deadline,error).await?;
        let restore_detected=match previous.first(){None=>false,Some(row)=>row.try_get::<_,String>(0).map_err(|_|error)?!=system || row.try_get::<_,i32>(1).map_err(|_|error)?!=timeline};
        rows(client,"UPDATE openmybot.control_tokens SET revoked_at=statement_timestamp(),revoke_reason='daemon_restart' WHERE revoked_at IS NULL RETURNING token_id",&[],deadline,error).await?;
        if restore_detected {
            // A restored cluster cannot prove its bindings are still current: stop them until reconfirmed.
            command(client,"UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE status='active'; UPDATE openmybot.channel_bindings SET status='expired',status_reason='restore_detected',ended_at=statement_timestamp(),pairing_code_hash=NULL WHERE status='pending'; UPDATE openmybot.channel_events SET dispatch_status='expired' WHERE dispatch_status='pending'",deadline,error).await?;
        }
        let hash=input.token_sha256.to_vec();
        rows(client,"INSERT INTO openmybot.control_tokens(token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier,pg_timeline_id,restore_detected,created_at,last_heartbeat_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,statement_timestamp(),statement_timestamp()) RETURNING token_id",&[&input.token_id,&hash,&input.daemon_pid,&input.engine_pin,&input.omb_version,&system,&timeline,&restore_detected],deadline,error).await?;
        timely(deadline,Ok(ControlTokenRecord{token_id:input.token_id,restore_detected}),error)
    }.await;
    finish(client, deadline, result, error).await
}
pub async fn stop_control_token(
    client: &mut Client,
    token_id: Uuid,
    deadline: Instant,
) -> Result<(), StoreError> {
    let error = StoreError::ControlTokenFailed;
    let result=async {
        command(client,"BEGIN",deadline,error).await?;
        rows(client,"UPDATE openmybot.control_tokens SET revoked_at=statement_timestamp(),revoke_reason='daemon_stop' WHERE token_id=$1 AND revoked_at IS NULL RETURNING token_id",&[&token_id],deadline,error).await?;
        Ok(())
    }.await;
    finish(client, deadline, result, error).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_and_debug_exclude_plaintext() {
        let sentinel = "private-token-sentinel";
        let value = ControlTokenStart {
            token_id: Uuid::now_v7(),
            token_sha256: [0xab; 32],
            daemon_pid: 1,
            engine_pin: "0123456789012345678901234567890123456789",
            omb_version: "0.0.0",
        };
        let text = format!("{value:?} {:?}", StoreError::ControlTokenFailed);
        assert!(!text.contains(sentinel));
        assert!(!text.contains("abababab"));
        for (error, code) in [
            (StoreError::MigrationDrift, "omb_migration_drift"),
            (StoreError::SchemaNewer, "omb_schema_newer"),
            (StoreError::MigrationFailed, "omb_migration_failed"),
            (StoreError::ControlTokenFailed, "control_token_failed"),
        ] {
            assert_eq!(error.to_string(), code);
        }
    }
}
