//! Durable PostgreSQL authority for remote AG-UI interrupt/resume.

use core::time::Duration;

use async_trait::async_trait;
use openbot_application::{
    ProviderRemoteInterruptBatch, ProviderRemoteResume, ProviderRemoteResumeEntry,
    ProviderRemoteResumeStatus, RemoteInterruptCoordinator, RemoteInterruptError,
    RemoteInterruptPending, RemoteInterruptPendingInput, RemoteInterruptResolutionReceipt,
    RunExecutionLease,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::ids::ActorId;
use openbot_contracts::remote_interrupt::is_remote_interrupt_request_id;
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::SecretBytes;
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row, Transaction};
use uuid::Uuid;

use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

/// Local authority TTL. A remote `expiresAt` remains untrusted presentation metadata.
pub const REMOTE_INTERRUPT_TTL: Duration = Duration::from_secs(30 * 60);
/// Durable polling closes notification-loss and cross-replica gaps.
pub const REMOTE_INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Production coordinator. The audit key is kept in one zeroizing allocation.
pub struct PostgresRemoteInterruptCoordinator {
    pool: crate::db::pool::DatabasePool,
    owner: String,
    checkpoint_key: SecretBytes,
}

impl PostgresRemoteInterruptCoordinator {
    /// Construct for the same process identity that owns [`crate::run_runtime::PostgresRunRuntime`].
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        owner: String,
        checkpoint_key: Vec<u8>,
    ) -> Result<Self, RemoteInterruptError> {
        if owner.is_empty()
            || owner.len() > 256
            || owner.chars().any(char::is_control)
            || checkpoint_key.is_empty()
        {
            return Err(RemoteInterruptError::Corrupt {
                field: "remote_interrupt_configuration",
            });
        }
        Ok(Self {
            pool,
            owner,
            checkpoint_key: SecretBytes::new(checkpoint_key),
        })
    }

    async fn persist_batch(
        &self,
        lease: &RunExecutionLease,
        batch: &ProviderRemoteInterruptBatch,
    ) -> Result<(), RemoteInterruptError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let scope = load_active_scope(&transaction, &self.owner, lease).await?;
        let ttl = time::Duration::try_from(REMOTE_INTERRUPT_TTL).map_err(|_| {
            RemoteInterruptError::Corrupt {
                field: "interrupt_ttl",
            }
        })?;
        let expires_at = scope
            .now
            .checked_add(ttl)
            .ok_or(RemoteInterruptError::Corrupt {
                field: "interrupt_expiry",
            })?;
        let generation = scope.auth_generation;
        let mut created = false;
        for (position, interrupt) in batch.interrupts().iter().enumerate() {
            let position = i16::try_from(position).map_err(|_| RemoteInterruptError::Corrupt {
                field: "interrupt_position",
            })?;
            let request_id = Uuid::now_v7().to_string();
            let inserted = transaction
                .execute(
                    "INSERT INTO public.remote_agent_interrupts( \
                       request_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id, \
                       auth_generation,protocol_run_id,interrupt_id,position,descriptor,state, \
                       response_status,response_payload,resume_protocol_run_id,requested_at, \
                       expires_at,resolved_at,resolved_by,created_at,updated_at \
                     ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NULL,NULL,NULL, \
                              $13,$14,NULL,NULL,$13,$13) \
                     ON CONFLICT (run_id,protocol_run_id,interrupt_id) DO NOTHING",
                    &[
                        &request_id,
                        &scope.deployment,
                        &scope.tenant,
                        &lease.thread_id().as_str(),
                        &lease.run_id().as_str(),
                        &lease.actor_id().as_str(),
                        &lease.bot_id().as_str(),
                        &generation,
                        &batch.protocol_run_id(),
                        &interrupt.id(),
                        &position,
                        &interrupt.untrusted_payload(),
                        &scope.now,
                        &expires_at,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            created |= inserted == 1;
        }
        let rows = transaction
            .query(
                "SELECT deployment_id,tenant_id,thread_id,actor_id,bot_id,auth_generation, \
                        interrupt_id,position,descriptor,state,requested_at,expires_at \
                   FROM public.remote_agent_interrupts \
                  WHERE run_id=$1 AND protocol_run_id=$2 ORDER BY position FOR UPDATE",
                &[&lease.run_id().as_str(), &batch.protocol_run_id()],
            )
            .await
            .map_err(query_unavailable)?;
        verify_batch_rows(&rows, lease, batch, &scope, created, expires_at)?;
        if created {
            append_interrupt_audit(
                &transaction,
                lease.actor_id(),
                lease.run_id().as_str(),
                AuditEventType::AGENT_REMOTE_INTERRUPT_REQUESTED,
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        transaction.commit().await.map_err(commit_unknown)
    }

    async fn poll_resume(
        &self,
        lease: &RunExecutionLease,
        batch: &ProviderRemoteInterruptBatch,
    ) -> Result<Option<ProviderRemoteResume>, RemoteInterruptError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let scope = load_active_scope(&transaction, &self.owner, lease).await?;
        let rows = transaction
            .query(
                "SELECT request_id,interrupt_id,position,descriptor,state,response_status, \
                        response_payload,resume_protocol_run_id,requested_at,expires_at \
                   FROM public.remote_agent_interrupts \
                  WHERE run_id=$1 AND protocol_run_id=$2 ORDER BY position FOR UPDATE",
                &[&lease.run_id().as_str(), &batch.protocol_run_id()],
            )
            .await
            .map_err(query_unavailable)?;
        if rows.len() != batch.interrupts().len() {
            return Err(RemoteInterruptError::Corrupt {
                field: "interrupt_batch",
            });
        }
        verify_wait_rows(&rows, batch)?;
        if rows.iter().any(|row| {
            row.try_get::<_, String>("state")
                .is_ok_and(|state| state == "retired")
        }) {
            return Err(RemoteInterruptError::Stale);
        }
        let expired = rows
            .iter()
            .filter(|row| {
                row.try_get::<_, String>("state")
                    .is_ok_and(|state| state == "pending")
                    && row
                        .try_get::<_, OffsetDateTime>("expires_at")
                        .is_ok_and(|expires_at| expires_at <= scope.now)
            })
            .count();
        if expired > 0 {
            let updated = transaction
                .execute(
                    "UPDATE public.remote_agent_interrupts \
                        SET state='expired',response_status='cancelled',response_payload=NULL, \
                            resolved_at=$3,resolved_by=NULL,updated_at=$3 \
                      WHERE run_id=$1 AND protocol_run_id=$2 AND state='pending' \
                        AND expires_at<=$3",
                    &[
                        &lease.run_id().as_str(),
                        &batch.protocol_run_id(),
                        &scope.now,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            if usize::try_from(updated).ok() != Some(expired) {
                return Err(RemoteInterruptError::Conflict);
            }
            append_interrupt_audit(
                &transaction,
                lease.actor_id(),
                lease.run_id().as_str(),
                AuditEventType::AGENT_REMOTE_INTERRUPT_EXPIRED,
                self.checkpoint_key.expose(),
            )
            .await?;
            notify_interrupt(&transaction, lease.run_id().as_str()).await?;
            transaction.commit().await.map_err(commit_unknown)?;
            return Ok(None);
        }
        if rows.iter().any(|row| {
            row.try_get::<_, String>("state")
                .is_ok_and(|state| state == "pending")
        }) {
            transaction.commit().await.map_err(commit_unknown)?;
            return Ok(None);
        }

        let stored_resume_ids = rows
            .iter()
            .map(|row| {
                row.try_get::<_, Option<String>>("resume_protocol_run_id")
                    .map_err(|_| corrupt("resume_protocol_run_id"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let resume_protocol_run_id = if stored_resume_ids.iter().all(Option::is_none) {
            let next = Uuid::now_v7().to_string();
            let updated = transaction
                .execute(
                    "UPDATE public.remote_agent_interrupts SET resume_protocol_run_id=$3, \
                            updated_at=$4 \
                      WHERE run_id=$1 AND protocol_run_id=$2 \
                        AND state IN ('resolved','cancelled','expired') \
                        AND resume_protocol_run_id IS NULL",
                    &[
                        &lease.run_id().as_str(),
                        &batch.protocol_run_id(),
                        &next,
                        &scope.now,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            if usize::try_from(updated).ok() != Some(rows.len()) {
                return Err(RemoteInterruptError::Conflict);
            }
            next
        } else {
            let Some(first) = stored_resume_ids.first().and_then(Option::as_ref) else {
                return Err(corrupt("resume_protocol_run_id"));
            };
            if stored_resume_ids
                .iter()
                .any(|value| value.as_deref() != Some(first.as_str()))
            {
                return Err(corrupt("resume_protocol_run_id"));
            }
            first.clone()
        };
        let entries = rows
            .iter()
            .map(decode_resume_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let resume = ProviderRemoteResume::new(
            batch.protocol_run_id().to_owned(),
            resume_protocol_run_id,
            entries,
        )
        .map_err(|_| corrupt("resume_batch"))?;
        transaction.commit().await.map_err(commit_unknown)?;
        Ok(Some(resume))
    }
}

#[async_trait]
impl RemoteInterruptCoordinator for PostgresRemoteInterruptCoordinator {
    async fn list_pending(
        &self,
        auth: &AuthContext,
    ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT d.request_id,d.run_id,d.bot_id,d.protocol_run_id,d.interrupt_id, \
                        d.descriptor,d.requested_at,d.expires_at \
                   FROM public.remote_agent_interrupts d \
                   JOIN public.runs r ON r.run_id=d.run_id AND r.thread_id=d.thread_id \
                   JOIN public.threads t ON t.thread_id=d.thread_id \
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id \
                   JOIN public.users u ON u.id=d.actor_id \
                  WHERE d.actor_id=$1 AND d.deployment_id=$2 AND d.tenant_id=$3 \
                    AND d.auth_generation=$4 AND d.state='pending' \
                    AND d.expires_at>clock_timestamp() AND r.actor_id=d.actor_id \
                    AND r.bot_id=d.bot_id AND r.status='running' AND t.status<>'deleted' \
                    AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp() \
                    AND coalesce(u.auth_generation,0)=$4 \
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) \
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra \
                                    WHERE ra.email=lower(u.email)) \
                    AND ((t.anchor_kind='direct_bot' AND EXISTS( \
                           SELECT 1 FROM public.thread_memberships tm \
                            WHERE tm.thread_id=t.thread_id AND tm.user_id=d.actor_id \
                         )) OR (t.anchor_kind='channel' AND EXISTS( \
                           SELECT 1 FROM public.channel_memberships cm \
                            WHERE cm.channel_id=t.anchor_id AND cm.user_id=d.actor_id \
                         ))) \
                  ORDER BY d.requested_at,d.request_id LIMIT 100",
                &[
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        rows.iter().map(decode_pending).collect()
    }

    async fn resolve(
        &self,
        auth: &AuthContext,
        request_id: &str,
        status: ProviderRemoteResumeStatus,
        payload: Option<Value>,
    ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
        if !is_remote_interrupt_request_id(request_id)
            || (status == ProviderRemoteResumeStatus::Cancelled && payload.is_some())
        {
            return Err(RemoteInterruptError::Corrupt {
                field: "interrupt_answer",
            });
        }
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        // Take the original positive Run/lease/user locks before the interrupt row.
        // The next statement re-observes the full authority and answer after this wait.
        transaction
            .query_opt(
                "SELECT r.run_id \
                   FROM public.remote_agent_interrupts d \
                   JOIN public.runs r ON r.run_id=d.run_id AND r.thread_id=d.thread_id \
                   JOIN public.threads t ON t.thread_id=d.thread_id \
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id \
                   JOIN public.users u ON u.id=d.actor_id \
                  WHERE d.request_id=$1 AND d.actor_id=$2 AND d.deployment_id=$3 \
                    AND d.tenant_id=$4 AND d.auth_generation=$5 \
                    AND r.actor_id=d.actor_id AND r.bot_id=d.bot_id AND r.status='running' \
                    AND t.status<>'deleted' AND l.fencing_token=r.fencing_token \
                    AND l.expires_at>clock_timestamp() AND coalesce(u.auth_generation,0)=$5 \
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) \
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra \
                                    WHERE ra.email=lower(u.email)) \
                    AND ((t.anchor_kind='direct_bot' AND EXISTS( \
                           SELECT 1 FROM public.thread_memberships tm \
                            WHERE tm.thread_id=t.thread_id AND tm.user_id=d.actor_id \
                         )) OR (t.anchor_kind='channel' AND EXISTS( \
                           SELECT 1 FROM public.channel_memberships cm \
                            WHERE cm.channel_id=t.anchor_id AND cm.user_id=d.actor_id \
                         ))) \
                  FOR UPDATE OF r,l,u",
                &[
                    &request_id,
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(RemoteInterruptError::Stale)?;
        let row = transaction
            .query_opt(
                "SELECT d.run_id,d.thread_id,d.interrupt_id,d.state,d.response_status,d.response_payload, \
                        d.expires_at,clock_timestamp() AS now \
                   FROM public.remote_agent_interrupts d \
                   JOIN public.runs r ON r.run_id=d.run_id AND r.thread_id=d.thread_id \
                   JOIN public.threads t ON t.thread_id=d.thread_id \
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id \
                   JOIN public.users u ON u.id=d.actor_id \
                  WHERE d.request_id=$1 AND d.actor_id=$2 AND d.deployment_id=$3 \
                    AND d.tenant_id=$4 AND d.auth_generation=$5 \
                    AND r.actor_id=d.actor_id AND r.bot_id=d.bot_id AND r.status='running' \
                    AND t.status<>'deleted' AND l.fencing_token=r.fencing_token \
                    AND l.expires_at>clock_timestamp() AND coalesce(u.auth_generation,0)=$5 \
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) \
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra \
                                    WHERE ra.email=lower(u.email)) \
                    AND ((t.anchor_kind='direct_bot' AND EXISTS( \
                           SELECT 1 FROM public.thread_memberships tm \
                            WHERE tm.thread_id=t.thread_id AND tm.user_id=d.actor_id \
                         )) OR (t.anchor_kind='channel' AND EXISTS( \
                           SELECT 1 FROM public.channel_memberships cm \
                            WHERE cm.channel_id=t.anchor_id AND cm.user_id=d.actor_id \
                         ))) \
                  FOR UPDATE OF d,r,l,u",
                &[
                    &request_id,
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(RemoteInterruptError::Stale)?;
        let state: String = decode(&row, "state")?;
        let interrupt_id: String = decode(&row, "interrupt_id")?;
        ProviderRemoteResumeEntry::new(interrupt_id, status, payload.clone())
            .map_err(|_| corrupt("interrupt_answer"))?;
        if matches!(state.as_str(), "resolved" | "cancelled") {
            let stored_status: Option<String> = decode(&row, "response_status")?;
            let stored_payload: Option<Value> = decode(&row, "response_payload")?;
            if stored_status.as_deref() != Some(status.as_str()) || stored_payload != payload {
                return Err(RemoteInterruptError::Conflict);
            }
            transaction.commit().await.map_err(commit_unknown)?;
            return RemoteInterruptResolutionReceipt::new(request_id.to_owned(), status, true);
        }
        if state != "pending" {
            return Err(RemoteInterruptError::Stale);
        }
        let now: OffsetDateTime = decode(&row, "now")?;
        let expires_at: OffsetDateTime = decode(&row, "expires_at")?;
        let run_id: String = decode(&row, "run_id")?;
        if expires_at <= now {
            transaction
                .execute(
                    "UPDATE public.remote_agent_interrupts \
                        SET state='expired',response_status='cancelled',response_payload=NULL, \
                            resolved_at=$2,resolved_by=NULL,updated_at=$2 \
                      WHERE request_id=$1 AND state='pending'",
                    &[&request_id, &now],
                )
                .await
                .map_err(query_unavailable)?;
            append_interrupt_audit(
                &transaction,
                auth.actor(),
                &run_id,
                AuditEventType::AGENT_REMOTE_INTERRUPT_EXPIRED,
                self.checkpoint_key.expose(),
            )
            .await?;
            notify_interrupt(&transaction, &run_id).await?;
            transaction.commit().await.map_err(commit_unknown)?;
            return Err(RemoteInterruptError::Stale);
        }
        if payload.is_some() {
            let thread: String = decode(&row, "thread_id")?;
            crate::thread_history_writer::require_open(
                &transaction,
                &openbot_contracts::ids::ThreadId::new(thread),
            )
            .await
            .map_err(remote_writer_error)?;
        }
        let state = match status {
            ProviderRemoteResumeStatus::Resolved => "resolved",
            ProviderRemoteResumeStatus::Cancelled => "cancelled",
        };
        let updated = transaction
            .execute(
                "UPDATE public.remote_agent_interrupts \
                    SET state=$2,response_status=$3,response_payload=$4,resolved_at=$5, \
                        resolved_by=$6,updated_at=$5 \
                  WHERE request_id=$1 AND state='pending'",
                &[
                    &request_id,
                    &state,
                    &status.as_str(),
                    &payload,
                    &now,
                    &auth.actor().as_str(),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if updated != 1 {
            return Err(RemoteInterruptError::Conflict);
        }
        let event_type = match status {
            ProviderRemoteResumeStatus::Resolved => AuditEventType::AGENT_REMOTE_INTERRUPT_RESOLVED,
            ProviderRemoteResumeStatus::Cancelled => {
                AuditEventType::AGENT_REMOTE_INTERRUPT_CANCELLED
            }
        };
        append_interrupt_audit(
            &transaction,
            auth.actor(),
            &run_id,
            event_type,
            self.checkpoint_key.expose(),
        )
        .await?;
        notify_interrupt(&transaction, &run_id).await?;
        transaction.commit().await.map_err(commit_unknown)?;
        RemoteInterruptResolutionReceipt::new(request_id.to_owned(), status, false)
    }

    async fn persist_and_wait(
        &self,
        lease: &RunExecutionLease,
        batch: &ProviderRemoteInterruptBatch,
    ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
        self.persist_batch(lease, batch).await?;
        loop {
            if let Some(resume) = self.poll_resume(lease, batch).await? {
                return Ok(resume);
            }
            tokio::time::sleep(REMOTE_INTERRUPT_POLL_INTERVAL).await;
        }
    }
}

struct ActiveScope {
    deployment: String,
    tenant: String,
    auth_generation: i64,
    now: OffsetDateTime,
}

async fn load_active_scope(
    transaction: &Transaction<'_>,
    owner: &str,
    lease: &RunExecutionLease,
) -> Result<ActiveScope, RemoteInterruptError> {
    let actual=transaction.query_opt(
        "SELECT t.thread_id FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id WHERE r.run_id=$1 FOR SHARE OF r,t NOWAIT",
        &[&lease.run_id().as_str()],
    ).await.map_err(query_unavailable)?.ok_or(RemoteInterruptError::Stale)?;
    let actual_thread: String = decode(&actual, "thread_id")?;
    if actual_thread != lease.thread_id().as_str() {
        return Err(RemoteInterruptError::Stale);
    }
    crate::thread_history_writer::require_open(
        transaction,
        &openbot_contracts::ids::ThreadId::new(actual_thread),
    )
    .await
    .map_err(remote_writer_error)?;
    // Original SERIALIZABLE isolation is retained. Full current authority and
    // lease facts below are re-observed in a distinct statement after admission.
    let row = transaction
        .query_opt(
            "SELECT r.thread_id,r.bot_id,r.actor_id,r.fencing_token,r.status, \
                    t.deployment_id,t.tenant_id,t.status AS thread_status, \
                    l.owner_id,l.fencing_token AS lease_fencing,l.expires_at, \
                    coalesce(u.auth_generation,0) AS auth_generation, \
                    EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id) AS has_role, \
                    NOT EXISTS(SELECT 1 FROM public.revoked_access ra \
                                WHERE ra.email=lower(u.email)) AS not_revoked, \
                    ((t.anchor_kind='direct_bot' AND EXISTS( \
                       SELECT 1 FROM public.thread_memberships tm \
                        WHERE tm.thread_id=t.thread_id AND tm.user_id=r.actor_id \
                     )) OR (t.anchor_kind='channel' AND EXISTS( \
                       SELECT 1 FROM public.channel_memberships cm \
                        WHERE cm.channel_id=t.anchor_id AND cm.user_id=r.actor_id \
                     ))) AS member,clock_timestamp() AS now \
               FROM public.runs r \
               JOIN public.threads t ON t.thread_id=r.thread_id \
               JOIN public.thread_leases l ON l.thread_id=t.thread_id \
               JOIN public.users u ON u.id=r.actor_id \
              WHERE r.run_id=$1 FOR UPDATE OF r,t,l,u",
            &[&lease.run_id().as_str()],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(RemoteInterruptError::Stale)?;
    let now: OffsetDateTime = decode(&row, "now")?;
    let auth_generation: i64 = decode(&row, "auth_generation")?;
    if auth_generation < 0
        || decode::<String>(&row, "thread_id")? != lease.thread_id().as_str()
        || decode::<String>(&row, "bot_id")? != lease.bot_id().as_str()
        || decode::<String>(&row, "actor_id")? != lease.actor_id().as_str()
        || decode::<i64>(&row, "fencing_token")? != lease.fencing().get()
        || decode::<String>(&row, "status")? != "running"
        || decode::<String>(&row, "thread_status")? == "deleted"
        || decode::<String>(&row, "owner_id")? != owner
        || decode::<i64>(&row, "lease_fencing")? != lease.fencing().get()
        || decode::<OffsetDateTime>(&row, "expires_at")? <= now
        || !decode::<bool>(&row, "has_role")?
        || !decode::<bool>(&row, "not_revoked")?
        || !decode::<bool>(&row, "member")?
    {
        return Err(RemoteInterruptError::Stale);
    }
    Ok(ActiveScope {
        deployment: decode(&row, "deployment_id")?,
        tenant: decode(&row, "tenant_id")?,
        auth_generation,
        now,
    })
}

fn verify_batch_rows(
    rows: &[Row],
    lease: &RunExecutionLease,
    batch: &ProviderRemoteInterruptBatch,
    scope: &ActiveScope,
    created: bool,
    expires_at: OffsetDateTime,
) -> Result<(), RemoteInterruptError> {
    if rows.len() != batch.interrupts().len() {
        return Err(RemoteInterruptError::Conflict);
    }
    for (position, (row, interrupt)) in rows.iter().zip(batch.interrupts()).enumerate() {
        let expected_position = i16::try_from(position).map_err(|_| corrupt("position"))?;
        let requested_at = decode::<OffsetDateTime>(row, "requested_at")?;
        let stored_expires_at = decode::<OffsetDateTime>(row, "expires_at")?;
        if decode::<String>(row, "deployment_id")? != scope.deployment
            || decode::<String>(row, "tenant_id")? != scope.tenant
            || decode::<String>(row, "thread_id")? != lease.thread_id().as_str()
            || decode::<String>(row, "actor_id")? != lease.actor_id().as_str()
            || decode::<String>(row, "bot_id")? != lease.bot_id().as_str()
            || decode::<i64>(row, "auth_generation")? != scope.auth_generation
            || decode::<String>(row, "interrupt_id")? != interrupt.id()
            || decode::<i16>(row, "position")? != expected_position
            || decode::<Option<Value>>(row, "descriptor")?.as_ref()
                != Some(interrupt.untrusted_payload())
            || decode::<String>(row, "state")? == "retired"
            || stored_expires_at <= requested_at
            || (created && requested_at != scope.now)
            || (created && stored_expires_at != expires_at)
        {
            return Err(RemoteInterruptError::Conflict);
        }
    }
    Ok(())
}

fn verify_wait_rows(
    rows: &[Row],
    batch: &ProviderRemoteInterruptBatch,
) -> Result<(), RemoteInterruptError> {
    for (position, (row, interrupt)) in rows.iter().zip(batch.interrupts()).enumerate() {
        if decode::<String>(row, "interrupt_id")? != interrupt.id()
            || decode::<i16>(row, "position")?
                != i16::try_from(position).map_err(|_| corrupt("position"))?
            || (decode::<String>(row, "state")? != "retired"
                && decode::<Option<Value>>(row, "descriptor")?.as_ref()
                    != Some(interrupt.untrusted_payload()))
        {
            return Err(RemoteInterruptError::Conflict);
        }
    }
    Ok(())
}

fn decode_resume_entry(row: &Row) -> Result<ProviderRemoteResumeEntry, RemoteInterruptError> {
    let state: String = decode(row, "state")?;
    let status = match decode::<Option<String>>(row, "response_status")?.as_deref() {
        Some("resolved") if state == "resolved" => ProviderRemoteResumeStatus::Resolved,
        Some("cancelled") if matches!(state.as_str(), "cancelled" | "expired") => {
            ProviderRemoteResumeStatus::Cancelled
        }
        _ => return Err(corrupt("interrupt_response")),
    };
    ProviderRemoteResumeEntry::new(
        decode(row, "interrupt_id")?,
        status,
        decode(row, "response_payload")?,
    )
    .map_err(|_| corrupt("interrupt_response"))
}

fn decode_pending(row: &Row) -> Result<RemoteInterruptPending, RemoteInterruptError> {
    RemoteInterruptPending::new(RemoteInterruptPendingInput {
        request_id: decode(row, "request_id")?,
        run_id: decode(row, "run_id")?,
        bot_id: decode(row, "bot_id")?,
        protocol_run_id: decode(row, "protocol_run_id")?,
        interrupt_id: decode(row, "interrupt_id")?,
        untrusted_payload: decode::<Option<Value>>(row, "descriptor")?
            .ok_or_else(|| corrupt("interrupt_payload"))?,
        requested_at: decode(row, "requested_at")?,
        expires_at: decode(row, "expires_at")?,
    })
}

async fn append_interrupt_audit(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    run_id: &str,
    event_type: AuditEventType,
    checkpoint_key: &[u8],
) -> Result<(), RemoteInterruptError> {
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(|_| RemoteInterruptError::Unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type,
        target_kind: AuditLabel::new("run"),
        target_id: Some(AuditIdentifier::new(run_id).map_err(|_| corrupt("run_id"))?),
        payload: AuditPayload::empty(),
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(|_| RemoteInterruptError::Unavailable)
}

async fn notify_interrupt(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<(), RemoteInterruptError> {
    transaction
        .execute(
            "SELECT pg_notify('openbot_remote_interrupts',$1)",
            &[&run_id],
        )
        .await
        .map(|_| ())
        .map_err(query_unavailable)
}

fn decode<T>(row: &Row, field: &'static str) -> Result<T, RemoteInterruptError>
where
    T: tokio_postgres::types::FromSqlOwned,
{
    row.try_get(field).map_err(|_| corrupt(field))
}

fn unavailable(error: crate::db::pool::PoolError) -> RemoteInterruptError {
    tracing::warn!(error = %error, "remote interrupt pool unavailable");
    RemoteInterruptError::Unavailable
}

fn remote_writer_error(error: crate::db::InfraError) -> RemoteInterruptError {
    if crate::thread_history_writer::is_closed(&error) {
        return RemoteInterruptError::Stale;
    }
    tracing::warn!(error=%error,"Remote interrupt history writer admission failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            RemoteInterruptError::Unavailable
        }
        _ => RemoteInterruptError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn query_unavailable(error: tokio_postgres::Error) -> RemoteInterruptError {
    if crate::thread_history_writer::is_closed_query(&error) {
        return RemoteInterruptError::Stale;
    }
    tracing::warn!(error = %error, "remote interrupt query unavailable");
    RemoteInterruptError::Unavailable
}

fn commit_unknown(error: tokio_postgres::Error) -> RemoteInterruptError {
    tracing::warn!(error = %error, "remote interrupt commit result unknown");
    RemoteInterruptError::CommitUnknown
}

const fn corrupt(field: &'static str) -> RemoteInterruptError {
    RemoteInterruptError::Corrupt { field }
}

impl core::fmt::Debug for PostgresRemoteInterruptCoordinator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresRemoteInterruptCoordinator")
            .field("owner", &self.owner)
            .field("checkpoint_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}
