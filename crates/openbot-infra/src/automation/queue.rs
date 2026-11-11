//! Durable scan, expiry and authority lifecycle; no remembered interactive session is used.

use super::{
    PostgresAutomations,
    store::{adjust_pending, column, lock_workspace, unavailable},
};
use async_trait::async_trait;
use openbot_application::{
    BeginDelegatedThreadRun, DelegatedUntrustedMaterial, automation::AutomationDispatchQueue,
};
use openbot_contracts::{
    auth::DelegationSource,
    automation::{AutomationId, AutomationOccurrenceReason},
    error::AppError,
    ids::{BotId, RunId, ThreadId},
};

#[async_trait]
impl AutomationDispatchQueue for PostgresAutomations {
    async fn maintain(&self) -> Result<(), AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        crate::thread_history_writer::CurrentWriterSchema::observe(&tx)
            .await
            .map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        crate::automation_budget::settle_acknowledged_tool(&tx, &self.deployment, &self.tenant)
            .await?;
        let rows=tx.query("SELECT d.*,v.delegation_revision FROM openbot_internal.automation_definitions d
            JOIN openbot_internal.automation_definition_revisions v ON (v.deployment_id,v.tenant_id,v.automation_id,v.revision)=(d.deployment_id,d.tenant_id,d.automation_id,d.current_revision)
            WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND (d.pending_count>0 OR d.active_count>0) ORDER BY d.automation_id FOR UPDATE OF d",
            &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
        for definition in &rows {
            let id = AutomationId::try_from(column::<String>(definition, "automation_id")?)?;
            let expired=tx.execute("UPDATE openbot_internal.automation_occurrences SET state='expired',reason_code='automation_queue_expired',terminal_at=statement_timestamp()
                WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND state IN ('pending','blocked_budget','blocked_model') AND expires_at<=statement_timestamp()",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?;
            adjust_pending(
                &tx,
                &self.deployment,
                &self.tenant,
                &id,
                -i64::try_from(expired).map_err(|_| unavailable())?,
            )
            .await?;
            if expired > 0 {
                self.audit(&tx, None, &id, "automation_occurrence_expired")
                    .await?;
            }
            if column::<i64>(definition, "active_count")? > 0 {
                let runs=tx.query("SELECT o.run_id FROM openbot_internal.automation_occurrences o JOIN public.runs r ON r.run_id=o.run_id
                    WHERE o.deployment_id=$1 AND o.tenant_id=$2 AND o.automation_id=$3 AND r.status='running'",
                    &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?;
                for row in runs {
                    let run = RunId::new(column::<String>(&row, "run_id")?);
                    match crate::automation_budget::execution_grant(
                        &tx,
                        &self.deployment,
                        &self.tenant,
                        definition,
                        run.as_str(),
                    )
                    .await
                    {
                        Ok(_) => {}
                        Err(AppError::AutomationDelegationInvalid) => {
                            crate::thread_directory::cancel_automation_run(
                                &tx,
                                &self.deployment,
                                &self.tenant,
                                definition,
                                &run,
                            )
                            .await
                            .map_err(|e| e.into_app_error())?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        // Delivery bodies are cleared seven days after their acceptance transaction; the
        // permanent key, fingerprint and receipt remain for exact replay and conflict checks.
        let cleared = tx.query("UPDATE openbot_internal.automation_deliveries SET normalized_data=NULL,data_cleared_at=statement_timestamp()
            WHERE deployment_id=$1 AND tenant_id=$2 AND normalized_data IS NOT NULL AND terminal_at<=statement_timestamp()-interval '7 days'
            RETURNING automation_id",
            &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
        let cleared = cleared
            .iter()
            .map(|row| column::<String>(row, "automation_id"))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        for id in cleared {
            self.audit(
                &tx,
                None,
                &AutomationId::try_from(id)?,
                "automation_event_data_cleared",
            )
            .await?;
        }
        tx.execute("UPDATE public.outbox o SET status='delivered',delivered_at=statement_timestamp(),updated_at=statement_timestamp()
            FROM openbot_internal.automation_occurrences a WHERE o.aggregate_id=a.occurrence_id AND o.destination='automation.dispatch' AND o.status='pending'
              AND a.deployment_id=$1 AND a.tenant_id=$2 AND a.state NOT IN ('pending','blocked_budget','blocked_model')",
            &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(())
    }
    async fn pending(&self) -> Result<Vec<BeginDelegatedThreadRun>, AppError> {
        let client = self.pool.get().await.map_err(|_| unavailable())?;
        let rows=client.query("SELECT DISTINCT ON (a.automation_id) a.automation_id,a.occurrence_id,a.definition_revision,d.thread_id,d.bot_id,
                a.delivery_receipt_id,v.normalized_data
            FROM openbot_internal.automation_occurrences a JOIN openbot_internal.automation_definitions d
              ON (d.deployment_id,d.tenant_id,d.automation_id)=(a.deployment_id,a.tenant_id,a.automation_id)
            LEFT JOIN openbot_internal.automation_deliveries v
              ON (v.deployment_id,v.tenant_id,v.receipt_id)=(a.deployment_id,a.tenant_id,a.delivery_receipt_id)
            WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.state='enabled' AND d.current_revision=a.definition_revision
              AND a.trigger_kind IN ('manual','event') AND a.state IN ('pending','blocked_budget','blocked_model') AND a.expires_at>statement_timestamp()
            ORDER BY a.automation_id,a.accepted_at,a.occurrence_id LIMIT 1000",
            &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
        rows.iter()
            .map(|row| {
                let id = AutomationId::try_from(column::<String>(row, "automation_id")?)?;
                let occurrence: String = column(row, "occurrence_id")?;
                Ok(BeginDelegatedThreadRun {
                    source: DelegationSource::AutomationDefinition {
                        definition_id: id.as_str().to_owned(),
                    },
                    revision: u64::try_from(column::<i64>(row, "definition_revision")?)
                        .map_err(|_| unavailable())?,
                    run_id: super::dispatch::run_id(&id, &occurrence)?,
                    trigger_id: occurrence,
                    thread_id: ThreadId::new(column::<String>(row, "thread_id")?),
                    bot_id: BotId::new(column::<String>(row, "bot_id")?),
                    // Event data is a separate untrusted user-role message, never the template.
                    untrusted_material: column::<Option<String>>(row, "delivery_receipt_id")?
                        .map(|receipt| {
                            let data: serde_json::Value =
                                column::<Option<_>>(row, "normalized_data")?
                                    .ok_or_else(unavailable)?;
                            Ok::<_, AppError>(DelegatedUntrustedMaterial {
                                source_ref: receipt,
                                text: data.to_string(),
                            })
                        })
                        .transpose()?,
                })
            })
            .collect()
    }
    async fn deferred(
        &self,
        request: &BeginDelegatedThreadRun,
        error: &AppError,
    ) -> Result<(), AppError> {
        let DelegationSource::AutomationDefinition { definition_id } = &request.source else {
            return Err(AppError::AutomationDelegationInvalid);
        };
        let id = AutomationId::try_from(definition_id.clone())?;
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        tx.query_one("SELECT automation_id FROM openbot_internal.automation_definitions WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 FOR UPDATE",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?;
        let (state, reason) = match error {
            AppError::PolicyRefused { rule, .. } if rule == "automation_budget_exceeded" => {
                (Some("blocked_budget"), Some("automation_budget_exceeded"))
            }
            AppError::PolicyRefused { rule, .. }
                if rule == AutomationOccurrenceReason::ModelUnavailable.as_str() =>
            {
                (
                    Some("blocked_model"),
                    Some(AutomationOccurrenceReason::ModelUnavailable.as_str()),
                )
            }
            AppError::PolicyRefused { rule, .. } if rule == "delegation_not_current" => {
                (None, Some("authority_unavailable"))
            }
            AppError::AutomationDelegationInvalid => (None, Some("authority_unavailable")),
            AppError::AutomationCapacityExceeded | AppError::LeaseConflict { .. } => {
                let occupied=tx.query_opt("SELECT r.status FROM public.thread_run_occupancy p JOIN public.runs r ON r.run_id=p.run_id WHERE p.thread_id=$1",&[&request.thread_id.as_str()]).await.map_err(|_|unavailable())?;
                let reason = occupied.map(|r| {
                    if r.get::<_, String>(0) == "reconciliation_required" {
                        "reconciliation_required"
                    } else {
                        "thread_busy"
                    }
                });
                (None, reason)
            }
            // DB/COMMIT uncertainty never proves rejection or changes an accepted input's state.
            _ => return Ok(()),
        };
        tx.execute("UPDATE openbot_internal.automation_occurrences SET state=COALESCE($5,state),reason_code=$6
            WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND occurrence_id=$4 AND state='pending'",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&request.trigger_id,&state,&reason]).await.map_err(|_|unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(())
    }
}
