//! Current AutomationDefinition authority from the original scoped PostgreSQL facts.

use super::store::{column, stored, unavailable};
use async_trait::async_trait;
use openbot_application::{DelegationAuthority, DelegationAuthorityError, DelegationGrant};
use openbot_contracts::{
    auth::{AuthGeneration, DelegationSource},
    automation::{AutomationDelegationV1, AutomationGrantValidity},
    ids::{DeploymentId, TenantId},
};
use std::time::Duration;

/// Server-only resolver. External binding registrations belong to their own product assembly.
#[derive(Clone, Debug)]
pub struct PostgresAutomationAuthority {
    pool: crate::db::pool::DatabasePool,
    deployment: DeploymentId,
    tenant: TenantId,
}
impl PostgresAutomationAuthority {
    /// Use the exact original Pool and workspace that also own management and cumulative budgets.
    #[must_use]
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Self {
        Self {
            pool,
            deployment,
            tenant,
        }
    }
}
#[async_trait]
impl DelegationAuthority for PostgresAutomationAuthority {
    async fn verify_current(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        source: &DelegationSource,
        revision: u64,
    ) -> Result<DelegationGrant, DelegationAuthorityError> {
        let DelegationSource::AutomationDefinition { definition_id } = source else {
            return Err(DelegationAuthorityError::NotCurrent);
        };
        if deployment != &self.deployment || tenant != &self.tenant {
            return Err(DelegationAuthorityError::NotCurrent);
        }
        let revision = i64::try_from(revision).map_err(|_| DelegationAuthorityError::NotCurrent)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| DelegationAuthorityError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| DelegationAuthorityError::Unavailable)?;
        let result=async{
            let row=tx.query_opt("SELECT d.*,v.delegation_revision,g.grant_snapshot,g.granted_auth_generation,g.expires_at,g.validity
                FROM openbot_internal.automation_definitions d
                JOIN openbot_internal.automation_definition_revisions v ON (v.deployment_id,v.tenant_id,v.automation_id,v.revision)=(d.deployment_id,d.tenant_id,d.automation_id,d.current_revision)
                JOIN openbot_internal.automation_delegations g ON (g.deployment_id,g.tenant_id,g.automation_id,g.delegation_revision)=(d.deployment_id,d.tenant_id,d.automation_id,v.delegation_revision)
                WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.automation_id=$3 AND g.delegation_revision=$4
                  AND d.state<>'tombstoned' AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>statement_timestamp())",
                &[&deployment.as_str(),&tenant.as_str(),&definition_id,&revision]).await.map_err(|_|unavailable())?;
            let Some(row)=row else{return Ok::<_,openbot_contracts::error::AppError>(None);};
            let snapshot:AutomationDelegationV1=stored(column(&row,"grant_snapshot")?)?;
            if snapshot.deployment_id!=*deployment || snapshot.tenant_id!=*tenant
                || snapshot.owner_id.as_str()!=column::<String>(&row,"owner_id")?
                || snapshot.bot_id.as_str()!=column::<String>(&row,"bot_id")?
                || snapshot.thread_id.as_str()!=column::<String>(&row,"thread_id")?
                || snapshot.definition_revision.get()!=revision || snapshot.budget_policy_revision.get()!=revision
                || snapshot.auth_generation!=column::<i64>(&row,"granted_auth_generation")? {return Ok(None);}
            let expires=match snapshot.validity {
                AutomationGrantValidity::UntilRevoked{} if column::<String>(&row,"validity")?=="until_revoked" && column::<Option<time::OffsetDateTime>>(&row,"expires_at")?.is_none()=>None,
                AutomationGrantValidity::Expires{expires_at} if column::<String>(&row,"validity")?=="expires" && column::<Option<time::OffsetDateTime>>(&row,"expires_at")?==Some(expires_at)=>Some(expires_at.into()),
                _=>return Ok(None),
            };
            match super::store::verify_thread(&tx,deployment,tenant,&row).await {
                Ok(())=>{}, Err(openbot_contracts::error::AppError::AutomationDelegationInvalid)=>return Ok(None),
                Err(error)=>return Err(error),
            }
            let facts=crate::delegation::owner_snapshot(&tx,deployment,tenant,&snapshot.owner_id,&snapshot.bot_id).await?;
            let generation=AuthGeneration::new(u64::try_from(snapshot.auth_generation).map_err(|_|unavailable())?);
            if facts.revoked || !facts.bot_visible || facts.auth_generation!=generation{return Ok(None);}
            Ok(Some(DelegationGrant::new(snapshot.owner_id,snapshot.bot_id,u64::try_from(revision).map_err(|_|unavailable())?,generation,expires,Some(Duration::from_secs(u64::from(snapshot.run_deadline_seconds))),snapshot.template)))
        }.await;
        tx.rollback()
            .await
            .map_err(|_| DelegationAuthorityError::Unavailable)?;
        result
            .map_err(|_| DelegationAuthorityError::Unavailable)?
            .ok_or(DelegationAuthorityError::NotCurrent)
    }
}
