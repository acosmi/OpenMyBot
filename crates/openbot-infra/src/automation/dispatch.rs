//! Automation admission and association inside the original delegated Run transaction.

use super::store::{adjust_pending, column, lock_workspace, unavailable, valid_grant};
use openbot_application::DelegatedBegin;
use openbot_contracts::{
    auth::DelegationSource,
    automation::{AutomationId, AutomationOccurrenceReason},
    error::AppError,
    ids::{DeploymentId, RunId, TenantId},
};
use tokio_postgres::{Row, Transaction};

/// Only the original transaction can obtain this witness for an empty dedicated native Thread.
pub(crate) struct AutomationBeginAdmission {
    definition: Row,
    id: AutomationId,
    plan: Option<crate::automation_budget::AutomationBudgetPlan>,
    replay: bool,
}
impl AutomationBeginAdmission {
    pub(crate) fn allows_empty_thread(&self) -> bool {
        !self.replay
    }

    pub(crate) async fn observe(
        tx: &Transaction<'_>,
        request: &DelegatedBegin,
    ) -> Result<Option<Self>, AppError> {
        let DelegationSource::AutomationDefinition { definition_id } = &request.request.source
        else {
            return Ok(None);
        };
        let id = AutomationId::try_from(definition_id.clone())?;
        lock_workspace(tx, &request.deployment, &request.tenant).await?;
        let definition=tx.query_opt("SELECT d.*,v.delegation_revision,v.config_snapshot FROM openbot_internal.automation_definitions d
            JOIN openbot_internal.automation_definition_revisions v ON (v.deployment_id,v.tenant_id,v.automation_id,v.revision)=(d.deployment_id,d.tenant_id,d.automation_id,d.current_revision)
            WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.automation_id=$3 FOR UPDATE OF d",
            &[&request.deployment.as_str(),&request.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?.ok_or(AppError::AutomationDelegationInvalid)?;
        if column::<String>(&definition, "state")? != "enabled" {
            return Err(AppError::AutomationNotAccepting);
        }
        if u64::try_from(column::<i64>(&definition, "current_revision")?)
            .map_err(|_| unavailable())?
            != request.request.revision
            || column::<String>(&definition, "thread_id")? != request.request.thread_id.as_str()
            || column::<String>(&definition, "owner_id")? != request.grant.owner().as_str()
            || column::<String>(&definition, "bot_id")? != request.request.bot_id.as_str()
            || request.request.run_id != run_id(&id, &request.request.trigger_id)?
        {
            return Err(AppError::AutomationDelegationInvalid);
        }
        let grant = valid_grant(tx, &request.deployment, &request.tenant, &definition).await?;
        if grant.auth_generation
            != i64::try_from(request.grant.granted_generation().get()).map_err(|_| unavailable())?
            || grant.definition_revision.get() != column::<i64>(&definition, "current_revision")?
        {
            return Err(AppError::AutomationDelegationInvalid);
        }
        // The definition lock serializes all its occurrence transitions. Read before taking the
        // final occurrence lock so budget rows retain the frozen workspace/definition/grant order.
        let occurrence=tx.query_opt("SELECT *,expires_at<=statement_timestamp() AS expired FROM openbot_internal.automation_occurrences
            WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND occurrence_id=$4",
            &[&request.deployment.as_str(),&request.tenant.as_str(),&id.as_str(),&request.request.trigger_id]).await.map_err(|_|unavailable())?.ok_or(AppError::AutomationDelegationInvalid)?;
        if column::<i64>(&occurrence, "definition_revision")?
            != column::<i64>(&definition, "current_revision")?
        {
            return Err(AppError::AutomationRevisionConflict);
        }
        if column::<String>(&occurrence, "trigger_kind")? != "manual" {
            return Err(AppError::AutomationTriggerUnavailable);
        }
        let replay = column::<String>(&occurrence, "state")? == "run_created";
        let plan = if replay {
            if column::<Option<String>>(&occurrence, "run_id")?.as_deref()
                != Some(request.request.run_id.as_str())
            {
                return Err(AppError::AutomationOperationConflict);
            }
            None
        } else {
            if !matches!(
                column::<String>(&occurrence, "state")?.as_str(),
                "pending" | "blocked_budget" | "blocked_model"
            ) || column::<bool>(&occurrence, "expired")?
            {
                return Err(AppError::AutomationNotAccepting);
            }
            let earlier:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM openbot_internal.automation_occurrences WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND state IN ('pending','blocked_budget','blocked_model') AND (accepted_at,occurrence_id)<($4,$5))",
                &[&request.deployment.as_str(),&request.tenant.as_str(),&id.as_str(),&column::<time::OffsetDateTime>(&occurrence,"accepted_at")?,&request.request.trigger_id]).await.map_err(|_|unavailable())?.get(0);
            let capacity:i64=tx.query_one("SELECT active_count FROM openbot_internal.automation_workspace_capacity WHERE deployment_id=$1 AND tenant_id=$2",&[&request.deployment.as_str(),&request.tenant.as_str()]).await.map_err(|_|unavailable())?.get(0);
            if earlier || capacity >= 4 || column::<i64>(&definition, "active_count")? >= 1 {
                return Err(AppError::AutomationCapacityExceeded);
            }
            let bot = tx
                .query_one(
                    "SELECT configuration FROM public.agents WHERE id=$1",
                    &[&request.request.bot_id.as_str()],
                )
                .await
                .map_err(|_| unavailable())?;
            if crate::provider::context::provider_route(&column(&bot, "configuration")?).is_err() {
                return Err(AppError::PolicyRefused {
                    rule: AutomationOccurrenceReason::ModelUnavailable
                        .as_str()
                        .to_owned(),
                    decision: None,
                });
            }
            Some(
                crate::automation_budget::AutomationBudgetPlan::prepare_start(
                    tx,
                    &request.deployment,
                    &request.tenant,
                    &definition,
                )
                .await?,
            )
        };
        tx.query_one("SELECT occurrence_id FROM openbot_internal.automation_occurrences WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND occurrence_id=$4 FOR UPDATE",
            &[&request.deployment.as_str(),&request.tenant.as_str(),&id.as_str(),&request.request.trigger_id]).await.map_err(|_|unavailable())?;
        Ok(Some(Self {
            definition,
            id,
            plan,
            replay,
        }))
    }

    pub(crate) async fn associate(
        self,
        tx: &Transaction<'_>,
        request: &DelegatedBegin,
    ) -> Result<(), AppError> {
        crate::automation_budget::verify_core_run(
            tx,
            &request.deployment,
            &request.tenant,
            &self.definition,
            request.request.run_id.as_str(),
        )
        .await?;
        if self.replay {
            return Ok(());
        }
        self.plan
            .ok_or_else(unavailable)?
            .reserve_start(tx, &self.definition, &request.request.run_id)
            .await?;
        let changed=tx.execute("UPDATE openbot_internal.automation_occurrences SET run_id=$5,state='run_created',reason_code=NULL,terminal_at=statement_timestamp() WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND occurrence_id=$4 AND state IN ('pending','blocked_budget','blocked_model')",
            &[&request.deployment.as_str(),&request.tenant.as_str(),&self.id.as_str(),&request.request.trigger_id,&request.request.run_id.as_str()]).await.map_err(|_|unavailable())?;
        if changed != 1 {
            return Err(unavailable());
        }
        adjust_pending(tx, &request.deployment, &request.tenant, &self.id, -1).await?;
        tx.execute("UPDATE openbot_internal.automation_definitions SET active_count=active_count+1 WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3",
            &[&request.deployment.as_str(),&request.tenant.as_str(),&self.id.as_str()]).await.map_err(|_|unavailable())?;
        tx.execute("UPDATE openbot_internal.automation_workspace_capacity SET active_count=active_count+1 WHERE deployment_id=$1 AND tenant_id=$2",
            &[&request.deployment.as_str(),&request.tenant.as_str()]).await.map_err(|_|unavailable())?;
        tx.execute("UPDATE public.outbox SET status='delivered',delivered_at=statement_timestamp(),updated_at=statement_timestamp() WHERE outbox_id=$1 AND status='pending'",
            &[&format!("{}:automation_dispatch",request.request.trigger_id)]).await.map_err(|_|unavailable())?;
        Ok(())
    }
}

pub(crate) fn run_id(automation: &AutomationId, occurrence: &str) -> Result<RunId, AppError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&(automation, occurrence)).map_err(|_| unavailable())?;
    Ok(RunId::new(format!("arun:{:x}", Sha256::digest(bytes))))
}

/// Acquire automation locks before the original core Run/Thread locks, including terminal/recovery.
pub(crate) async fn lock_existing_run(
    tx: &Transaction<'_>,
    run: &str,
) -> Result<Option<(DeploymentId, TenantId, AutomationId)>, AppError> {
    let scope=tx.query_opt("SELECT deployment_id,tenant_id,automation_id FROM openbot_internal.automation_occurrences WHERE run_id=$1",&[&run]).await.map_err(|_|unavailable())?;
    let Some(scope) = scope else {
        return Ok(None);
    };
    let deployment = DeploymentId::new(column::<String>(&scope, "deployment_id")?);
    let tenant = TenantId::new(column::<String>(&scope, "tenant_id")?);
    let automation = AutomationId::try_from(column::<String>(&scope, "automation_id")?)?;
    lock_workspace(tx, &deployment, &tenant).await?;
    tx.query_one("SELECT automation_id FROM openbot_internal.automation_definitions WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 FOR UPDATE",
        &[&deployment.as_str(),&tenant.as_str(),&automation.as_str()]).await.map_err(|_|unavailable())?;
    Ok(Some((deployment, tenant, automation)))
}

/// The original definite terminal transaction invokes this only after it has released foreground.
pub(crate) async fn release_capacity(tx: &Transaction<'_>, run: &str) -> Result<(), AppError> {
    let Some((deployment, tenant, automation)) = lock_existing_run(tx, run).await? else {
        return Ok(());
    };
    let occupied: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.thread_run_occupancy WHERE run_id=$1)",
            &[&run],
        )
        .await
        .map_err(|_| unavailable())?
        .get(0);
    if occupied {
        return Ok(());
    }
    let released=tx.execute("UPDATE openbot_internal.automation_definitions SET active_count=active_count-1 WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND active_count=1",
        &[&deployment.as_str(),&tenant.as_str(),&automation.as_str()]).await.map_err(|_|unavailable())?;
    if released != 1 {
        return Err(unavailable());
    }
    tx.execute("UPDATE openbot_internal.automation_workspace_capacity SET active_count=active_count-1 WHERE deployment_id=$1 AND tenant_id=$2",
        &[&deployment.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?;
    crate::automation_budget::release_unsent(tx, &deployment, &tenant, run).await?;
    Ok(())
}
