//! PostgreSQL facts for Application-owned delegated authority; no authority is minted here.

use crate::thread_directory::PostgresThreadDirectory;
use async_trait::async_trait;
use openbot_application::{
    DelegatedBegin, DelegatedContextIssuer, DelegatedCurrentRequest, DelegatedOwnerSnapshot,
    DelegatedRunRecord, DelegatedRunStore,
};
use openbot_contracts::auth::{AuthContext, AuthGeneration, DelegationSource, Role};
use openbot_contracts::command::ThreadRunStarted;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::thread::FencingToken;
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, UNIX_EPOCH};
use tokio_postgres::{Row, Transaction};

pub(crate) struct PostgresDelegatedRunStore {
    pool: crate::db::pool::DatabasePool,
    directory: PostgresThreadDirectory,
    deployment: DeploymentId,
    tenant: TenantId,
    callback_runtime: OnceLock<Weak<crate::run_runtime::PostgresRunRuntime>>,
}
impl PostgresDelegatedRunStore {
    pub(crate) fn new(
        pool: crate::db::pool::DatabasePool,
        directory: PostgresThreadDirectory,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Self {
        Self {
            pool,
            directory,
            deployment,
            tenant,
            callback_runtime: OnceLock::new(),
        }
    }
    pub(crate) fn bind_callback_runtime(
        &self,
        runtime: &Arc<crate::run_runtime::PostgresRunRuntime>,
    ) -> Result<(), AppError> {
        self.callback_runtime
            .set(Arc::downgrade(runtime))
            .map_err(|_| not_current())
    }
}
#[async_trait]
impl DelegatedRunStore for PostgresDelegatedRunStore {
    async fn begin(
        &self,
        request: DelegatedBegin,
        issuer: &dyn DelegatedContextIssuer,
    ) -> Result<ThreadRunStarted, AppError> {
        if request.deployment != self.deployment || request.tenant != self.tenant {
            return Err(not_current());
        }
        self.directory.begin_delegated(request, issuer).await
    }
    async fn load_run(
        &self,
        deployment: &DeploymentId,
        tenant: &TenantId,
        run: &RunId,
    ) -> Result<Option<DelegatedRunRecord>, AppError> {
        if deployment != &self.deployment || tenant != &self.tenant {
            return Err(not_current());
        }
        let client = self.pool.get().await.map_err(|_| unavailable())?;
        client
            .query_opt(
                RECORD_SQL,
                &[&run.as_str(), &deployment.as_str(), &tenant.as_str()],
            )
            .await
            .map_err(|_| unavailable())?
            .as_ref()
            .map(decode_record)
            .transpose()
            .map(Option::flatten)
    }
    async fn remint(
        &self,
        request: DelegatedCurrentRequest,
        issuer: &dyn DelegatedContextIssuer,
    ) -> Result<AuthContext, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        tx.batch_execute("SET LOCAL lock_timeout='5s'")
            .await
            .map_err(|_| unavailable())?;
        crate::thread_history_writer::CurrentWriterSchema::observe(&tx)
            .await
            .map_err(|_| unavailable())?;
        let row = tx
            .query_opt(
                &format!("{RECORD_SQL} FOR SHARE OF r,t,l"),
                &[
                    &request.record.run_id.as_str(),
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                ],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(not_current)?;
        let record = decode_record(&row)?.ok_or_else(not_current)?;
        let expected = &request.expected_lease;
        if record.run_id != *expected.run_id()
            || record.thread_id != *expected.thread_id()
            || record.bot_id != *expected.bot_id()
            || record.actor_id != *expected.actor_id()
            || record.fencing != expected.fencing()
            || record.source != request.record.source
            || record.revision != request.record.revision
            || record.trigger_id != request.record.trigger_id
            || record.granted_generation != request.record.granted_generation
            || record.expires_at != request.record.expires_at
            || record.absolute_deadline != request.record.absolute_deadline
        {
            return Err(not_current());
        }
        let facts = owner_snapshot(
            &tx,
            &self.deployment,
            &self.tenant,
            &record.actor_id,
            &record.bot_id,
        )
        .await?;
        if record.lease_expires_at <= facts.database_now
            || record.absolute_deadline <= facts.database_now
        {
            return Err(not_current());
        }
        let auth = issuer.issue(facts)?;
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(auth)
    }
    async fn fail_confirmed_callback(
        &self,
        record: &DelegatedRunRecord,
        lease: &openbot_application::RunExecutionLease,
    ) -> Result<openbot_application::RunWriteReceipt, openbot_application::RunRuntimeError> {
        if record.deployment != self.deployment
            || record.tenant != self.tenant
            || record.run_id != *lease.run_id()
            || record.thread_id != *lease.thread_id()
            || record.bot_id != *lease.bot_id()
            || record.actor_id != *lease.actor_id()
            || record.fencing != lease.fencing()
        {
            return Err(openbot_application::RunRuntimeError::StaleLease);
        }
        let runtime = self
            .callback_runtime
            .get()
            .and_then(Weak::upgrade)
            .ok_or(openbot_application::RunRuntimeError::Unavailable)?;
        runtime
            .fail_confirmed_delegated_callback(lease, Some(record))
            .await
    }
}
pub(crate) const RECORD_SQL: &str = "SELECT r.run_id,r.thread_id,r.bot_id,r.actor_id,r.fencing_token,r.next_event_seq, t.deployment_id,t.tenant_id,l.expires_at AS lease_expires_at,m.content->'delegation' AS delegation,m.content->'delegationSnapshot' AS delegation_snapshot FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id JOIN public.thread_leases l ON l.thread_id=r.thread_id JOIN public.messages m ON m.message_id=r.run_id||':input' AND m.run_id=r.run_id WHERE r.run_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 AND r.status='running' AND t.status='active' AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads h WHERE h.deployment_id=t.deployment_id AND h.tenant_id=t.tenant_id AND h.thread_id=t.thread_id AND h.phase='closed') AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=r.actor_id)";
/// The engine-written `delegation` object; its shape was validated once at `begin`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredDelegation {
    source: StoredSource,
    revision: u64,
    trigger_id: String,
}
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum StoredSource {
    ExternalBinding { binding_id: String },
    AutomationDefinition { definition_id: String },
}
/// The engine-written `delegationSnapshot`; the absolute deadline is authoritative.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSnapshot {
    grant_generation: u64,
    expires_at: Option<u64>,
    absolute_deadline: u64,
}
pub(crate) fn decode_record(row: &Row) -> Result<Option<DelegatedRunRecord>, AppError> {
    let Some(delegation) = row
        .try_get::<_, Option<Value>>("delegation")
        .map_err(|_| not_current())?
    else {
        return Ok(None);
    };
    let delegation: StoredDelegation =
        serde_json::from_value(delegation).map_err(|_| not_current())?;
    let snapshot: StoredSnapshot = serde_json::from_value(
        row.try_get("delegation_snapshot")
            .map_err(|_| not_current())?,
    )
    .map_err(|_| not_current())?;
    let millis = |v: u64| {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(v))
            .ok_or_else(not_current)
    };
    let lease: time::OffsetDateTime = row.try_get("lease_expires_at").map_err(|_| not_current())?;
    Ok(Some(DelegatedRunRecord {
        deployment: DeploymentId::new(
            row.try_get::<_, String>("deployment_id")
                .map_err(|_| not_current())?,
        ),
        tenant: TenantId::new(
            row.try_get::<_, String>("tenant_id")
                .map_err(|_| not_current())?,
        ),
        run_id: RunId::new(
            row.try_get::<_, String>("run_id")
                .map_err(|_| not_current())?,
        ),
        thread_id: ThreadId::new(
            row.try_get::<_, String>("thread_id")
                .map_err(|_| not_current())?,
        ),
        bot_id: BotId::new(
            row.try_get::<_, String>("bot_id")
                .map_err(|_| not_current())?,
        ),
        actor_id: ActorId::new(
            row.try_get::<_, String>("actor_id")
                .map_err(|_| not_current())?,
        ),
        fencing: FencingToken::new(row.try_get("fencing_token").map_err(|_| not_current())?)
            .map_err(|_| not_current())?,
        source: match delegation.source {
            StoredSource::ExternalBinding { binding_id } => {
                DelegationSource::ExternalBinding { binding_id }
            }
            StoredSource::AutomationDefinition { definition_id } => {
                DelegationSource::AutomationDefinition { definition_id }
            }
        },
        revision: delegation.revision,
        trigger_id: delegation.trigger_id,
        granted_generation: AuthGeneration::new(snapshot.grant_generation),
        expires_at: snapshot.expires_at.map(millis).transpose()?,
        absolute_deadline: millis(snapshot.absolute_deadline)?,
        lease_expires_at: lease.into(),
    }))
}
pub(crate) async fn owner_snapshot(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    owner: &ActorId,
    bot: &BotId,
) -> Result<DelegatedOwnerSnapshot, AppError> {
    let row=tx.query_opt("SELECT u.auth_generation,EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS revoked,ARRAY(SELECT DISTINCT ur.role::text FROM public.user_roles ur WHERE ur.user_id=u.id ORDER BY ur.role::text) AS roles,EXISTS(SELECT 1 FROM public.agent_profiles p JOIN public.agents a ON a.id=p.agent_id LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id WHERE p.agent_id=$2 AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3) AND (p.visibility='public' OR p.owner_user_id=$1 OR EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$1 AND ur.role='admin'))) AS bot_visible,clock_timestamp() AS database_now FROM public.users u WHERE u.id=$1 FOR SHARE OF u",&[&owner.as_str(),&bot.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?.ok_or_else(not_current)?;
    let generation: i64 = row.try_get("auth_generation").map_err(|_| not_current())?;
    let roles: Vec<String> = row.try_get("roles").map_err(|_| not_current())?;
    let roles = roles
        .iter()
        .map(|r| Role::from_str(r).map_err(|_| not_current()))
        .collect::<Result<Vec<_>, _>>()?;
    let now: time::OffsetDateTime = row.try_get("database_now").map_err(|_| not_current())?;
    Ok(DelegatedOwnerSnapshot {
        deployment: deployment.clone(),
        tenant: tenant.clone(),
        owner: owner.clone(),
        bot_id: bot.clone(),
        roles,
        auth_generation: AuthGeneration::new(u64::try_from(generation).map_err(|_| not_current())?),
        revoked: row.try_get("revoked").map_err(|_| not_current())?,
        bot_visible: row.try_get("bot_visible").map_err(|_| not_current())?,
        database_now: now.into(),
    })
}
pub(crate) fn source_json(source: &DelegationSource) -> Value {
    match source {
        DelegationSource::ExternalBinding { binding_id } => {
            json!({"kind":"external_binding","bindingId":binding_id})
        }
        DelegationSource::AutomationDefinition { definition_id } => {
            json!({"kind":"automation_definition","definitionId":definition_id})
        }
    }
}
pub(crate) fn not_current() -> AppError {
    AppError::PolicyRefused {
        rule: "delegation_not_current".into(),
        decision: None,
    }
}
fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "delegation_store",
    }
}
