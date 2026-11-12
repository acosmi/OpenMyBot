//! PostgreSQL-backed durable human proof-of-intent for acting tools (v3 §8.5).

use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{
    AppEventStream, ToolApprovalAdministration, ToolApprovalAdministrationError,
    ToolApprovalRequest, ToolPortError,
};
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::AppEvent;
use openbot_contracts::ids::{ActorId, BotId, RunId, ToolCallId};
use openbot_contracts::tool::{
    MAX_PENDING_TOOL_APPROVALS, PendingToolApproval, PendingToolApprovals,
    ToolApprovalActivityEvent, ToolApprovalClass, ToolApprovalDecision, ToolApprovalEffect,
    ToolApprovalResolved,
};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::tool::metadata::ApprovalClass;
use openbot_domain::vault::SecretBytes;
use time::{Duration, OffsetDateTime};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

const APPROVAL_TTL: Duration = Duration::minutes(5);
const CROSS_REPLICA_POLL: StdDuration = StdDuration::from_secs(1);
const MAX_PENDING_APPROVALS: i64 = MAX_PENDING_TOOL_APPROVALS as i64;
const MAX_PRESENTATION_BYTES: usize = 16 * 1024;

/// Durable decision returned to the tool control plane after waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableHumanDecision {
    /// Exact binding was granted until this database timestamp.
    Granted {
        /// Durable approval row identity.
        approval_id: String,
        /// Inclusive expiry boundary.
        expires_at: OffsetDateTime,
    },
    /// Human denial, expiry, cancellation or invalid scope. No effect may start.
    Denied,
}

/// Multi-replica approval coordinator. Cleartext argument summaries exist only while pending.
#[derive(Clone)]
pub struct PostgresToolApprovalCoordinator {
    pool: Pool,
    deployment: openbot_contracts::ids::DeploymentId,
    tenant: openbot_contracts::ids::TenantId,
    checkpoint_key: Arc<SecretBytes>,
    wake: Arc<Notify>,
    recovery_gate: crate::recovery_control::RecoveryReadGate,
}

impl PostgresToolApprovalCoordinator {
    /// Bind deployment/tenant scope and the existing audit hash-chain key.
    pub fn new(
        pool: Pool,
        deployment: openbot_contracts::ids::DeploymentId,
        tenant: openbot_contracts::ids::TenantId,
        checkpoint_key: Vec<u8>,
        recovery_gate: crate::recovery_control::RecoveryReadGate,
    ) -> Result<Self, ToolPortError> {
        if checkpoint_key.is_empty() {
            return Err(ToolPortError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            checkpoint_key: Arc::new(SecretBytes::new(checkpoint_key)),
            wake: Arc::new(Notify::new()),
            recovery_gate,
        })
    }

    /// Persist or exactly reuse a request, then wait for a human/cancellation/expiry decision.
    pub async fn request_and_wait(
        &self,
        request: &ToolApprovalRequest,
    ) -> Result<DurableHumanDecision, ToolPortError> {
        validate_request(request)?;
        let start = self.ensure_request(request).await?;
        match start.state {
            StoredApprovalState::Granted => {
                return Ok(DurableHumanDecision::Granted {
                    approval_id: start.approval_id,
                    expires_at: start.expires_at,
                });
            }
            StoredApprovalState::Denied
            | StoredApprovalState::Expired
            | StoredApprovalState::Cancelled => return Ok(DurableHumanDecision::Denied),
            StoredApprovalState::Pending => {}
        }

        loop {
            match self.poll(&start.approval_id, request).await? {
                StoredApprovalState::Granted => {
                    let expires_at = self
                        .load_expiry(&start.approval_id)
                        .await?
                        .ok_or(ToolPortError::NotVisible)?;
                    return Ok(DurableHumanDecision::Granted {
                        approval_id: start.approval_id,
                        expires_at,
                    });
                }
                StoredApprovalState::Denied
                | StoredApprovalState::Expired
                | StoredApprovalState::Cancelled => return Ok(DurableHumanDecision::Denied),
                StoredApprovalState::Pending => {
                    tokio::select! {
                        () = self.wake.notified() => {}
                        () = tokio::time::sleep(CROSS_REPLICA_POLL) => {}
                    }
                }
            }
        }
    }

    async fn ensure_request(
        &self,
        request: &ToolApprovalRequest,
    ) -> Result<StoredApproval, ToolPortError> {
        // The run's request has no host binding: a worker admission, held through
        // the INSERT and COMMIT (5 s precedent).
        let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
        let admission = self
            .recovery_gate
            .borrow_worker_before(deadline)
            .await
            .map_err(|_| ToolPortError::Unavailable {
                dependency: "tool_approval",
            })?;
        let current = || {
            admission
                .verify_current_before(deadline)
                .map_err(|_| ToolPortError::Unavailable {
                    dependency: "tool_approval",
                })
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let now: OffsetDateTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(query_unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("clock"))?;
        if !request_scope_current(&transaction, &self.deployment, &self.tenant, request).await? {
            return Err(ToolPortError::NotVisible);
        }

        if request.approval_class == ApprovalClass::OncePerRun
            && let Some(row) = transaction
                .query_opt(
                    "SELECT approval_id,expires_at FROM public.tool_approvals
                      WHERE state='granted' AND approval_class='once_per_run'
                        AND deployment_id=$1 AND tenant_id=$2 AND actor_id=$3
                        AND auth_generation=$4 AND bot_id=$5 AND run_id=$6 AND tool_name=$7
                        AND args_hash=$8 AND target_kind=$9 AND target_id=$10 AND effect=$11
                        AND computer_generation=$12 AND catalog_generation=$13
                        AND document_generation IS NOT DISTINCT FROM $14
                        AND policy_version=$15 AND expires_at>$16
                      ORDER BY decided_at DESC,approval_id DESC LIMIT 1",
                    &[
                        &self.deployment.as_str(),
                        &self.tenant.as_str(),
                        &request.actor.as_str(),
                        &to_i64(request.auth_generation.get(), "auth_generation")?,
                        &request.bot.as_str(),
                        &request.run.as_str(),
                        &request.tool.as_str(),
                        &request.args_hash.to_hex(),
                        &request.target.kind,
                        &request.target.id,
                        &request.effect.as_str(),
                        &to_i64(request.computer_generation.get(), "computer_generation")?,
                        &to_i64(request.catalog_generation.get(), "catalog_generation")?,
                        &optional_generation(request.target_document_generation)?,
                        &request.policy_version.as_str(),
                        &now,
                    ],
                )
                .await
                .map_err(query_unavailable)?
        {
            return Ok(StoredApproval {
                approval_id: row
                    .try_get("approval_id")
                    .map_err(|_| corrupt("approval_id"))?,
                state: StoredApprovalState::Granted,
                expires_at: row
                    .try_get("expires_at")
                    .map_err(|_| corrupt("expires_at"))?,
            });
        }

        if let Some(row) = transaction
            .query_opt(
                "SELECT approval_id,state,expires_at,
                        deployment_id=$2 AND tenant_id=$3 AND actor_id=$4
                        AND auth_generation=$5 AND bot_id=$6 AND run_id=$7 AND thread_id=$8
                        AND tool_name=$9 AND args_hash=$10 AND target_kind=$11 AND target_id=$12
                        AND effect=$13 AND approval_class=$14 AND computer_generation=$15
                        AND catalog_generation=$16 AND document_generation IS NOT DISTINCT FROM $17
                        AND policy_version=$18 AS binding_matches
                   FROM public.tool_approvals WHERE tool_call_id=$1 FOR UPDATE",
                &[
                    &request.call_id.as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &request.actor.as_str(),
                    &to_i64(request.auth_generation.get(), "auth_generation")?,
                    &request.bot.as_str(),
                    &request.run.as_str(),
                    &request.thread.as_str(),
                    &request.tool.as_str(),
                    &request.args_hash.to_hex(),
                    &request.target.kind,
                    &request.target.id,
                    &request.effect.as_str(),
                    &request.approval_class.as_str(),
                    &to_i64(request.computer_generation.get(), "computer_generation")?,
                    &to_i64(request.catalog_generation.get(), "catalog_generation")?,
                    &optional_generation(request.target_document_generation)?,
                    &request.policy_version.as_str(),
                ],
            )
            .await
            .map_err(query_unavailable)?
        {
            let matches: bool = row
                .try_get("binding_matches")
                .map_err(|_| corrupt("approval_binding"))?;
            if !matches {
                return Err(ToolPortError::Corrupt {
                    field: "approval_binding",
                });
            }
            return decode_stored(&row);
        }

        crate::thread_history_writer::require_open(&transaction, &request.thread)
            .await
            .map_err(approval_writer_error)?;
        if !request_scope_current(&transaction, &self.deployment, &self.tenant, request).await? {
            return Err(ToolPortError::NotVisible);
        }
        let approval_id = Uuid::now_v7().to_string();
        let expires_at = now + APPROVAL_TTL;
        current()?;
        transaction
            .execute(
                "INSERT INTO public.tool_approvals(
                   approval_id,tool_call_id,deployment_id,tenant_id,thread_id,run_id,actor_id,
                   bot_id,auth_generation,tool_name,args_hash,target_kind,target_id,effect,
                   approval_class,computer_generation,catalog_generation,document_generation,
                   policy_version,arguments_summary,change_summary,state,requested_at,expires_at,
                   created_at,updated_at
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                          $19,$20,$21,'pending',$22,$23,$22,$22)",
                &[
                    &approval_id,
                    &request.call_id.as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &request.thread.as_str(),
                    &request.run.as_str(),
                    &request.actor.as_str(),
                    &request.bot.as_str(),
                    &to_i64(request.auth_generation.get(), "auth_generation")?,
                    &request.tool.as_str(),
                    &request.args_hash.to_hex(),
                    &request.target.kind,
                    &request.target.id,
                    &request.effect.as_str(),
                    &request.approval_class.as_str(),
                    &to_i64(request.computer_generation.get(), "computer_generation")?,
                    &to_i64(request.catalog_generation.get(), "catalog_generation")?,
                    &optional_generation(request.target_document_generation)?,
                    &request.policy_version.as_str(),
                    &request.presentation.arguments_summary,
                    &request.presentation.change_summary,
                    &now,
                    &expires_at,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        append_approval_audit(
            &transaction,
            &request.actor,
            AuditEventType::TOOL_APPROVAL_REQUESTED,
            &approval_id,
            self.checkpoint_key.expose(),
        )
        .await?;
        current()?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "tool approval request commit 结果未知");
            ToolPortError::CommitUnknown
        })?;
        self.wake.notify_waiters();
        Ok(StoredApproval {
            approval_id,
            state: StoredApprovalState::Pending,
            expires_at,
        })
    }

    async fn poll(
        &self,
        approval_id: &str,
        request: &ToolApprovalRequest,
    ) -> Result<StoredApprovalState, ToolPortError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                "SELECT a.state,a.expires_at,clock_timestamp() AS now,
                        EXISTS(
                          SELECT 1 FROM public.runs r
                          JOIN public.threads t ON t.thread_id=r.thread_id
                          JOIN public.thread_memberships tm ON tm.thread_id=t.thread_id
                          JOIN public.thread_leases l ON l.thread_id=t.thread_id
                          JOIN public.users u ON u.id=r.actor_id
                          WHERE r.run_id=a.run_id AND r.thread_id=a.thread_id
                            AND r.bot_id=a.bot_id AND r.actor_id=a.actor_id AND r.status='running'
                            AND t.deployment_id=a.deployment_id AND t.tenant_id=a.tenant_id
                            AND t.status<>'deleted' AND tm.user_id=a.actor_id
                            AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()
                            AND coalesce(u.auth_generation,0)=a.auth_generation
                            AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                            AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                            WHERE ra.email=lower(u.email))
                        ) AS scope_current
                   FROM public.tool_approvals a
                  WHERE a.approval_id=$1 AND a.tool_call_id=$2 AND a.actor_id=$3",
                &[
                    &approval_id,
                    &request.call_id.as_str(),
                    &request.actor.as_str(),
                ],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(ToolPortError::NotVisible)?;
        let state = parse_state(
            &row.try_get::<_, String>("state")
                .map_err(|_| corrupt("approval_state"))?,
        )?;
        if state != StoredApprovalState::Pending {
            return Ok(state);
        }
        let expires_at: OffsetDateTime = row
            .try_get("expires_at")
            .map_err(|_| corrupt("expires_at"))?;
        let now: OffsetDateTime = row.try_get("now").map_err(|_| corrupt("clock"))?;
        let scope_current: bool = row
            .try_get("scope_current")
            .map_err(|_| corrupt("approval_scope"))?;
        drop(client);
        if now >= expires_at {
            self.retire_pending(approval_id, request, StoredApprovalState::Expired)
                .await?;
            return Ok(StoredApprovalState::Expired);
        }
        if !scope_current {
            self.retire_pending(approval_id, request, StoredApprovalState::Cancelled)
                .await?;
            return Ok(StoredApprovalState::Cancelled);
        }
        Ok(StoredApprovalState::Pending)
    }

    async fn retire_pending(
        &self,
        approval_id: &str,
        request: &ToolApprovalRequest,
        state: StoredApprovalState,
    ) -> Result<(), ToolPortError> {
        let (state_text, event_type) = match state {
            StoredApprovalState::Expired => ("expired", AuditEventType::TOOL_APPROVAL_EXPIRED),
            StoredApprovalState::Cancelled => {
                ("cancelled", AuditEventType::TOOL_APPROVAL_CANCELLED)
            }
            _ => return Err(corrupt("approval_state")),
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let updated = transaction
            .execute(
                "UPDATE public.tool_approvals SET state=$4,decided_at=clock_timestamp(),
                   arguments_summary=NULL,change_summary=NULL,updated_at=clock_timestamp()
                  WHERE approval_id=$1 AND tool_call_id=$2 AND actor_id=$3 AND state='pending'",
                &[
                    &approval_id,
                    &request.call_id.as_str(),
                    &request.actor.as_str(),
                    &state_text,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        if updated == 1 {
            append_approval_audit(
                &transaction,
                &request.actor,
                event_type,
                approval_id,
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "tool approval retirement commit 结果未知");
            ToolPortError::CommitUnknown
        })?;
        self.wake.notify_waiters();
        Ok(())
    }

    async fn load_expiry(
        &self,
        approval_id: &str,
    ) -> Result<Option<OffsetDateTime>, ToolPortError> {
        self.pool
            .get()
            .await
            .map_err(unavailable)?
            .query_opt(
                "SELECT expires_at FROM public.tool_approvals
                  WHERE approval_id=$1 AND state='granted'",
                &[&approval_id],
            )
            .await
            .map_err(query_unavailable)?
            .map(|row| row.try_get(0).map_err(|_| corrupt("expires_at")))
            .transpose()
    }

    async fn append_admin_audit(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
        actor: &ActorId,
        event_type: AuditEventType,
        approval_id: &str,
    ) -> Result<(), ToolApprovalAdministrationError> {
        append_approval_audit(
            transaction,
            actor,
            event_type,
            approval_id,
            self.checkpoint_key.expose(),
        )
        .await
        .map_err(map_tool_port_admin)
    }

    async fn activity_scope_current(
        &self,
        auth: &AuthContext,
    ) -> Result<bool, ToolApprovalAdministrationError> {
        ensure_auth_scope(self, auth)?;
        let generation = to_i64_admin(auth.auth_generation().get(), "auth_generation")?;
        // No step here has its own bound, so the 5 s precedent.
        let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
        let binding = auth
            .request_binding()
            .ok_or(ToolApprovalAdministrationError::Unavailable)?;
        let admission = binding
            .borrow_recovery_admission_before(auth, deadline)
            .await
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)?;
        let client = self.pool.get().await.map_err(admin_unavailable)?;
        let current = client
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.users u
                    WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
                      AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                      AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                      WHERE ra.email=lower(u.email)))",
                &[&auth.actor().as_str(), &generation],
            )
            .await
            .map_err(admin_query)?
            .try_get(0)
            .map_err(|_| admin_corrupt("approval_activity_scope"))?;
        admission
            .verify_current_before(binding, auth, deadline)
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)?;
        Ok(current)
    }
}

#[async_trait]
impl ToolApprovalAdministration for PostgresToolApprovalCoordinator {
    async fn list_pending(
        &self,
        auth: &AuthContext,
    ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError> {
        ensure_auth_scope(self, auth)?;
        let generation = to_i64_admin(auth.auth_generation().get(), "auth_generation")?;
        let client = self.pool.get().await.map_err(admin_unavailable)?;
        let rows = client
            .query(
                "SELECT a.approval_id,a.tool_call_id,a.run_id,a.bot_id,a.tool_name,
                        a.target_kind,a.target_id,a.effect,a.approval_class,
                        a.arguments_summary,a.change_summary,a.requested_at,a.expires_at
                   FROM public.tool_approvals a
                   JOIN public.runs r ON r.run_id=a.run_id AND r.thread_id=a.thread_id
                   JOIN public.threads t ON t.thread_id=a.thread_id
                   JOIN public.thread_memberships tm ON tm.thread_id=t.thread_id
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id
                   JOIN public.users u ON u.id=a.actor_id
                  WHERE a.actor_id=$1 AND a.deployment_id=$2 AND a.tenant_id=$3
                    AND a.auth_generation=$4 AND a.state='pending'
                    AND a.expires_at>clock_timestamp() AND r.actor_id=$1 AND r.bot_id=a.bot_id
                    AND r.status='running' AND t.status<>'deleted' AND tm.user_id=$1
                    AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()
                    AND coalesce(u.auth_generation,0)=$4
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                    WHERE ra.email=lower(u.email))
                  ORDER BY a.requested_at,a.approval_id LIMIT $5",
                &[
                    &auth.actor().as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &generation,
                    &MAX_PENDING_APPROVALS,
                ],
            )
            .await
            .map_err(admin_query)?;
        let approvals = rows
            .iter()
            .map(decode_pending)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PendingToolApprovals { approvals })
    }

    async fn decide(
        &self,
        auth: &AuthContext,
        approval_id: &str,
        decision: ToolApprovalDecision,
    ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError> {
        ensure_auth_scope(self, auth)?;
        if !valid_approval_id(approval_id) {
            return Err(ToolApprovalAdministrationError::InvalidInput {
                field: "approvalId",
            });
        }
        let generation = to_i64_admin(auth.auth_generation().get(), "auth_generation")?;
        let mut client = self.pool.get().await.map_err(admin_unavailable)?;
        let transaction = client.transaction().await.map_err(admin_query)?;
        let current: bool = transaction
            .query_one(
                "SELECT EXISTS(
                    SELECT 1 FROM public.tool_approvals a
                    JOIN public.runs r ON r.run_id=a.run_id AND r.thread_id=a.thread_id
                    JOIN public.threads t ON t.thread_id=a.thread_id
                    JOIN public.thread_memberships tm ON tm.thread_id=t.thread_id
                    JOIN public.thread_leases l ON l.thread_id=t.thread_id
                    JOIN public.users u ON u.id=a.actor_id
                    WHERE a.approval_id=$1 AND a.actor_id=$2 AND a.deployment_id=$3
                      AND a.tenant_id=$4 AND a.auth_generation=$5 AND a.state='pending'
                      AND a.expires_at>clock_timestamp() AND r.actor_id=$2 AND r.bot_id=a.bot_id
                      AND r.status='running' AND t.status<>'deleted' AND tm.user_id=$2
                      AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()
                      AND coalesce(u.auth_generation,0)=$5
                      AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                      AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                      WHERE ra.email=lower(u.email)))",
                &[
                    &approval_id,
                    &auth.actor().as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(admin_query)?
            .try_get(0)
            .map_err(|_| admin_corrupt("approval_scope"))?;
        if !current {
            return Err(ToolApprovalAdministrationError::NotVisible);
        }
        let (state, event_type) = match decision {
            ToolApprovalDecision::Grant => ("granted", AuditEventType::TOOL_APPROVAL_GRANTED),
            ToolApprovalDecision::Deny => ("denied", AuditEventType::TOOL_APPROVAL_DENIED),
        };
        let updated = transaction
            .execute(
                "UPDATE public.tool_approvals SET state=$3,decided_at=clock_timestamp(),
                   decided_by=$2,arguments_summary=NULL,change_summary=NULL,
                   updated_at=clock_timestamp()
                  WHERE approval_id=$1 AND actor_id=$2 AND state='pending'",
                &[&approval_id, &auth.actor().as_str(), &state],
            )
            .await
            .map_err(admin_query)?;
        if updated != 1 {
            return Err(ToolApprovalAdministrationError::Conflict);
        }
        self.append_admin_audit(&transaction, auth.actor(), event_type, approval_id)
            .await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "tool approval decision commit 结果未知");
            ToolApprovalAdministrationError::CommitUnknown
        })?;
        self.wake.notify_waiters();
        Ok(ToolApprovalResolved {
            approval_id: approval_id.to_owned(),
            decision,
        })
    }

    async fn subscribe_activity(
        &self,
        auth: &AuthContext,
    ) -> Result<AppEventStream, ToolApprovalAdministrationError> {
        if !self.activity_scope_current(auth).await? {
            return Err(ToolApprovalAdministrationError::NotVisible);
        }
        // Validate current authority before any transport headers are committed.
        let initial = self.list_pending(auth).await?;
        let state = ApprovalActivityState {
            coordinator: self.clone(),
            auth: auth.clone(),
            previous: None,
            next: Some(initial),
            terminal: false,
        };
        Ok(Box::pin(futures_util::stream::unfold(
            state,
            next_approval_activity,
        )))
    }
}

struct ApprovalActivityState {
    coordinator: PostgresToolApprovalCoordinator,
    auth: AuthContext,
    previous: Option<PendingToolApprovals>,
    next: Option<PendingToolApprovals>,
    terminal: bool,
}

async fn next_approval_activity(
    mut state: ApprovalActivityState,
) -> Option<(AppEvent, ApprovalActivityState)> {
    if state.terminal {
        return None;
    }
    loop {
        let current = if let Some(initial) = state.next.take() {
            Ok(initial)
        } else {
            tokio::select! {
                () = state.coordinator.wake.notified() => {}
                () = tokio::time::sleep(CROSS_REPLICA_POLL) => {}
            }
            match state.coordinator.activity_scope_current(&state.auth).await {
                Ok(true) => state.coordinator.list_pending(&state.auth).await,
                Ok(false) => Err(ToolApprovalAdministrationError::NotVisible),
                Err(error) => Err(error),
            }
        };
        match current {
            Ok(current) if state.previous.as_ref() != Some(&current) => {
                let pending_count = match u32::try_from(current.approvals.len()) {
                    Ok(count) => count,
                    Err(_) => {
                        state.terminal = true;
                        return Some((
                            AppEvent::ToolApprovalStreamError {
                                code: ToolApprovalAdministrationError::Corrupt {
                                    field: "pending_count",
                                }
                                .into_app_error()
                                .code()
                                .as_str()
                                .to_owned(),
                            },
                            state,
                        ));
                    }
                };
                state.previous = Some(current);
                return Some((
                    AppEvent::ToolApprovalActivity(ToolApprovalActivityEvent { pending_count }),
                    state,
                ));
            }
            Ok(_) => {}
            Err(error) => {
                state.terminal = true;
                return Some((
                    AppEvent::ToolApprovalStreamError {
                        code: error.into_app_error().code().as_str().to_owned(),
                    },
                    state,
                ));
            }
        }
    }
}

impl core::fmt::Debug for PostgresToolApprovalCoordinator {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresToolApprovalCoordinator")
            .field("deployment", &self.deployment)
            .field("tenant", &self.tenant)
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredApprovalState {
    Pending,
    Granted,
    Denied,
    Expired,
    Cancelled,
}

struct StoredApproval {
    approval_id: String,
    state: StoredApprovalState,
    expires_at: OffsetDateTime,
}

fn decode_stored(row: &tokio_postgres::Row) -> Result<StoredApproval, ToolPortError> {
    Ok(StoredApproval {
        approval_id: row
            .try_get("approval_id")
            .map_err(|_| corrupt("approval_id"))?,
        state: parse_state(
            &row.try_get::<_, String>("state")
                .map_err(|_| corrupt("approval_state"))?,
        )?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| corrupt("expires_at"))?,
    })
}

fn parse_state(value: &str) -> Result<StoredApprovalState, ToolPortError> {
    match value {
        "pending" => Ok(StoredApprovalState::Pending),
        "granted" => Ok(StoredApprovalState::Granted),
        "denied" => Ok(StoredApprovalState::Denied),
        "expired" => Ok(StoredApprovalState::Expired),
        "cancelled" => Ok(StoredApprovalState::Cancelled),
        _ => Err(corrupt("approval_state")),
    }
}

async fn request_scope_current(
    transaction: &tokio_postgres::Transaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    request: &ToolApprovalRequest,
) -> Result<bool, ToolPortError> {
    transaction
        .query_one(
            "SELECT EXISTS(
                SELECT 1 FROM public.runs r
                JOIN public.threads t ON t.thread_id=r.thread_id
                JOIN public.thread_memberships tm ON tm.thread_id=t.thread_id
                JOIN public.thread_leases l ON l.thread_id=t.thread_id
                JOIN public.agent_profiles ap ON ap.agent_id=r.bot_id
                JOIN public.users u ON u.id=r.actor_id
                WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4
                  AND r.status='running' AND t.deployment_id=$5 AND t.tenant_id=$6
                  AND t.status<>'deleted' AND tm.user_id=$4 AND ap.deleted_at IS NULL
                  AND (ap.visibility='public' OR ap.owner_user_id=$4)
                  AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()
                  AND coalesce(u.auth_generation,0)=$7
                  AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                  AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                  WHERE ra.email=lower(u.email))
                  AND NOT EXISTS(SELECT 1 FROM public.tool_calls tc
                                  WHERE tc.tool_call_id=$8))",
            &[
                &request.run.as_str(),
                &request.thread.as_str(),
                &request.bot.as_str(),
                &request.actor.as_str(),
                &deployment.as_str(),
                &tenant.as_str(),
                &to_i64(request.auth_generation.get(), "auth_generation")?,
                &request.call_id.as_str(),
            ],
        )
        .await
        .map_err(query_unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("approval_scope"))
}

async fn append_approval_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    actor: &ActorId,
    event_type: AuditEventType,
    approval_id: &str,
    checkpoint_key: &[u8],
) -> Result<(), ToolPortError> {
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(query_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor.clone()),
        event_type,
        target_kind: AuditLabel::new("tool_approval"),
        target_id: Some(AuditIdentifier::new(approval_id).map_err(|_| corrupt("approval_id"))?),
        payload: AuditPayload::empty(),
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(query_unavailable)
}

fn decode_pending(
    row: &tokio_postgres::Row,
) -> Result<PendingToolApproval, ToolApprovalAdministrationError> {
    let effect = match row
        .try_get::<_, String>("effect")
        .map_err(|_| admin_corrupt("effect"))?
        .as_str()
    {
        "write" => ToolApprovalEffect::Write,
        "execute" => ToolApprovalEffect::Execute,
        "network" => ToolApprovalEffect::Network,
        "credential" => ToolApprovalEffect::Credential,
        _ => return Err(admin_corrupt("effect")),
    };
    let approval_class = match row
        .try_get::<_, String>("approval_class")
        .map_err(|_| admin_corrupt("approval_class"))?
        .as_str()
    {
        "once_per_run" => ToolApprovalClass::OncePerRun,
        "every_call" => ToolApprovalClass::EveryCall,
        _ => return Err(admin_corrupt("approval_class")),
    };
    Ok(PendingToolApproval {
        approval_id: row
            .try_get("approval_id")
            .map_err(|_| admin_corrupt("approval_id"))?,
        call_id: ToolCallId::new(
            row.try_get::<_, String>("tool_call_id")
                .map_err(|_| admin_corrupt("tool_call_id"))?,
        ),
        run_id: RunId::new(
            row.try_get::<_, String>("run_id")
                .map_err(|_| admin_corrupt("run_id"))?,
        ),
        bot_id: BotId::new(
            row.try_get::<_, String>("bot_id")
                .map_err(|_| admin_corrupt("bot_id"))?,
        ),
        tool_name: row
            .try_get("tool_name")
            .map_err(|_| admin_corrupt("tool_name"))?,
        target_kind: row
            .try_get("target_kind")
            .map_err(|_| admin_corrupt("target_kind"))?,
        target_id: row
            .try_get("target_id")
            .map_err(|_| admin_corrupt("target_id"))?,
        effect,
        approval_class,
        arguments_summary: row
            .try_get::<_, Option<serde_json::Value>>("arguments_summary")
            .map_err(|_| admin_corrupt("arguments_summary"))?
            .ok_or_else(|| admin_corrupt("arguments_summary"))?,
        change_summary: row
            .try_get("change_summary")
            .map_err(|_| admin_corrupt("change_summary"))?,
        requested_at: row
            .try_get("requested_at")
            .map_err(|_| admin_corrupt("requested_at"))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| admin_corrupt("expires_at"))?,
    })
}

fn validate_request(request: &ToolApprovalRequest) -> Result<(), ToolPortError> {
    if !request.effect.is_acting()
        || request.approval_class == ApprovalClass::NotRequired
        || request.target.id.is_empty()
        || request.target.id.len() > 4 * 1024
        || request.target.id.as_bytes().contains(&0)
        || serde_json::to_vec(&request.presentation.arguments_summary)
            .map_or(true, |value| value.len() > MAX_PRESENTATION_BYTES)
        || request
            .presentation
            .change_summary
            .as_ref()
            .is_some_and(|summary| {
                serde_json::to_vec(summary)
                    .map_or(true, |value| value.len() > MAX_PRESENTATION_BYTES)
            })
    {
        return Err(ToolPortError::Corrupt {
            field: "approval_request",
        });
    }
    Ok(())
}

fn ensure_auth_scope(
    coordinator: &PostgresToolApprovalCoordinator,
    auth: &AuthContext,
) -> Result<(), ToolApprovalAdministrationError> {
    if auth.deployment() != &coordinator.deployment || auth.tenant() != &coordinator.tenant {
        Err(ToolApprovalAdministrationError::NotVisible)
    } else {
        Ok(())
    }
}

fn optional_generation(
    value: Option<openbot_contracts::ids::DocumentGeneration>,
) -> Result<Option<i64>, ToolPortError> {
    value
        .map(|generation| to_i64(generation.get(), "document_generation"))
        .transpose()
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, ToolPortError> {
    i64::try_from(value).map_err(|_| ToolPortError::Corrupt { field })
}

fn to_i64_admin(value: u64, field: &'static str) -> Result<i64, ToolApprovalAdministrationError> {
    i64::try_from(value).map_err(|_| ToolApprovalAdministrationError::Corrupt { field })
}

fn valid_approval_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.as_bytes().contains(&0)
}

fn unavailable(error: crate::db::pool::PoolError) -> ToolPortError {
    tracing::error!(error = %error, "tool approval 获取 PostgreSQL 连接失败");
    ToolPortError::Unavailable {
        dependency: "tool_approval",
    }
}

fn approval_writer_error(error: crate::db::InfraError) -> ToolPortError {
    if crate::thread_history_writer::is_closed(&error) {
        return ToolPortError::NotVisible;
    }
    tracing::warn!(error=%error,"Tool approval history writer admission failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            ToolPortError::Unavailable {
                dependency: "tool_approval",
            }
        }
        _ => ToolPortError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn query_unavailable(error: impl core::fmt::Display) -> ToolPortError {
    tracing::error!(error = %error, "tool approval PostgreSQL 操作失败");
    ToolPortError::Unavailable {
        dependency: "tool_approval",
    }
}

const fn corrupt(field: &'static str) -> ToolPortError {
    ToolPortError::Corrupt { field }
}

fn admin_unavailable(error: crate::db::pool::PoolError) -> ToolApprovalAdministrationError {
    tracing::error!(error = %error, "tool approval admin 获取 PostgreSQL 连接失败");
    ToolApprovalAdministrationError::Unavailable
}

fn admin_query(error: impl core::fmt::Display) -> ToolApprovalAdministrationError {
    tracing::error!(error = %error, "tool approval admin PostgreSQL 操作失败");
    ToolApprovalAdministrationError::Unavailable
}

const fn admin_corrupt(field: &'static str) -> ToolApprovalAdministrationError {
    ToolApprovalAdministrationError::Corrupt { field }
}

fn map_tool_port_admin(error: ToolPortError) -> ToolApprovalAdministrationError {
    match error {
        ToolPortError::NotVisible => ToolApprovalAdministrationError::NotVisible,
        ToolPortError::InvalidInput { field } => {
            ToolApprovalAdministrationError::InvalidInput { field }
        }
        ToolPortError::Conflict => ToolApprovalAdministrationError::Conflict,
        ToolPortError::CommitUnknown => ToolApprovalAdministrationError::CommitUnknown,
        ToolPortError::Unavailable { .. } => ToolApprovalAdministrationError::Unavailable,
        ToolPortError::Corrupt { field } => ToolApprovalAdministrationError::Corrupt { field },
    }
}
