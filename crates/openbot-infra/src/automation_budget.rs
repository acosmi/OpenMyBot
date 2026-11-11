//! Atomic three-scope cumulative policies, reservations and original-attempt settlement.

use crate::automation::store::{column, lock_workspace, stored, unavailable};
use openbot_contracts::{
    automation::*,
    error::AppError,
    ids::{DeploymentId, TenantId},
};
use openbot_domain::automation::AutomationBudgets;
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction};

/// Startup rejection does not expose a path, policy body or database error.
#[derive(Debug, thiserror::Error)]
pub enum AutomationBudgetStartupError {
    /// A previously accepted current file revision cannot be replaced by an older one.
    #[error("automation_budget_revision_regressed")]
    RevisionRegressed,
    /// The immutable policy or original database cannot be used.
    #[error("automation_budgets_invalid")]
    Invalid,
}

impl crate::automation::PostgresAutomations {
    /// Install the one trusted startup snapshot under the same workspace lock as every attempt.
    pub async fn install_budgets(
        &self,
        budgets: Option<&AutomationBudgets>,
    ) -> Result<(), AutomationBudgetStartupError> {
        let apply=async {
            let mut client=self.pool.get().await.map_err(|_|unavailable())?;
            let tx=client.transaction().await.map_err(|_|unavailable())?;
            lock_workspace(&tx,&self.deployment,&self.tenant).await?;
            let current:Option<i64>=tx.query_one("SELECT max(revision) FROM openbot_internal.automation_budget_policies WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind IN ('owner','workspace')",
                &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?.get(0);
            if budgets.is_some_and(|b|current.is_some_and(|v|b.wire().revision.get()<v)) {
                return Ok::<_,AppError>(false);
            }
            tx.execute("UPDATE openbot_internal.automation_budget_policies SET current=false WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind IN ('owner','workspace') AND current",
                &[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
            if let Some(budgets)=budgets {
                let revision=budgets.wire().revision.get();
                let stored:i64=tx.query_one("SELECT count(*) FROM openbot_internal.automation_budget_policies WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind IN ('owner','workspace') AND revision=$3",
                    &[&self.deployment.as_str(),&self.tenant.as_str(),&revision]).await.map_err(|_|unavailable())?.get(0);
                for entry in &budgets.wire().workspaces {
                    if entry.deployment_id==self.deployment && entry.tenant_id==self.tenant {
                        install_policy(&tx,&self.deployment,&self.tenant,"workspace","workspace",revision,&entry.budget).await?;
                    }
                }
                for entry in &budgets.wire().owners {
                    if entry.deployment_id==self.deployment && entry.tenant_id==self.tenant {
                        install_policy(&tx,&self.deployment,&self.tenant,"owner",entry.owner_id.as_str(),revision,&entry.budget).await?;
                    }
                }
                if stored>0 {
                    // An installed revision is read-only: the file must restate exactly its rows.
                    let row=tx.query_one("SELECT count(*),count(*) FILTER (WHERE current) FROM openbot_internal.automation_budget_policies WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind IN ('owner','workspace') AND revision=$3",
                        &[&self.deployment.as_str(),&self.tenant.as_str(),&revision]).await.map_err(|_|unavailable())?;
                    if row.get::<_,i64>(0)!=stored || row.get::<_,i64>(1)!=stored {
                        return Err(unavailable());
                    }
                }
                refresh_current(&tx,&self.deployment,&self.tenant).await?;
            }
            tx.commit().await.map_err(|_|unavailable())?;
            Ok(true)
        }.await;
        match apply {
            Ok(true) => Ok(()),
            Ok(false) => Err(AutomationBudgetStartupError::RevisionRegressed),
            Err(_) => Err(AutomationBudgetStartupError::Invalid),
        }
    }
}

pub(crate) async fn replace_automation_policy(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    id: &AutomationId,
    revision: i64,
    rules: &[AutomationBudgetRule],
) -> Result<(), AppError> {
    install_policy(
        tx,
        deployment,
        tenant,
        "automation",
        id.as_str(),
        revision,
        rules,
    )
    .await?;
    refresh_current(tx, deployment, tenant).await
}

async fn install_policy(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    kind: &str,
    id: &str,
    revision: i64,
    rules: &[AutomationBudgetRule],
) -> Result<(), AppError> {
    tx.execute("UPDATE openbot_internal.automation_budget_policies SET current=false WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND current",
        &[&deployment.as_str(),&tenant.as_str(),&kind,&id]).await.map_err(|_|unavailable())?;
    for rule in rules {
        let metric = metric_name(rule.metric);
        let origin = rule.window.as_ref().map(|v| v.origin);
        let seconds = rule
            .window
            .as_ref()
            .map(|v| i64::try_from(v.seconds))
            .transpose()
            .map_err(|_| unavailable())?;
        let window_limit = rule.window.as_ref().map(|v| v.limit.get());
        let total_limit = rule.total_limit.map(AutomationAmount::get);
        if let Some(old)=tx.query_opt("SELECT window_origin IS NOT DISTINCT FROM $7 AS same_origin,window_seconds,window_limit,total_limit,currency FROM openbot_internal.automation_budget_policies
            WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND revision=$5 AND metric=$6",
            &[&deployment.as_str(),&tenant.as_str(),&kind,&id,&revision,&metric,&origin]).await.map_err(|_|unavailable())? {
            if !column::<bool>(&old,"same_origin")? || column::<Option<i64>>(&old,"window_seconds")?!=seconds
                || column::<Option<i64>>(&old,"window_limit")?!=window_limit || column::<Option<i64>>(&old,"total_limit")?!=total_limit
                || column::<Option<String>>(&old,"currency")?!=rule.currency {return Err(unavailable());}
            tx.execute("UPDATE openbot_internal.automation_budget_policies SET current=true WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND revision=$5 AND metric=$6",
                &[&deployment.as_str(),&tenant.as_str(),&kind,&id,&revision,&metric]).await.map_err(|_|unavailable())?;
        }else{
            tx.execute("INSERT INTO openbot_internal.automation_budget_policies(deployment_id,tenant_id,scope_kind,scope_id,revision,metric,window_origin,window_seconds,window_limit,total_limit,currency,current) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)",
                &[&deployment.as_str(),&tenant.as_str(),&kind,&id,&revision,&metric,&origin,&seconds,&window_limit,&total_limit,&rule.currency]).await.map_err(|_|unavailable())?;
        }
    }
    Ok(())
}

pub(crate) async fn ensure_configured(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    owner: &str,
    automation: &str,
    rules: &[AutomationBudgetRule],
) -> Result<(), AppError> {
    let rows = policies(tx, deployment, tenant, owner, automation).await?;
    for kind in ["owner", "workspace"] {
        if !rows
            .iter()
            .any(|r| r.get::<_, String>("scope_kind") == kind)
        {
            return Err(AppError::AutomationBudgetUnconfigured);
        }
    }
    if rules
        .iter()
        .any(|r| r.metric == AutomationBudgetMetric::MoneyMicrounits)
        || rows
            .iter()
            .any(|r| r.get::<_, String>("metric") == "money_microunits")
    {
        return Err(AppError::AutomationBudgetUnconfigured);
    }
    Ok(())
}

async fn policies(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    owner: &str,
    automation: &str,
) -> Result<Vec<Row>, AppError> {
    tx.query("SELECT p.* FROM openbot_internal.automation_budget_policies p WHERE deployment_id=$1 AND tenant_id=$2 AND current
        AND ((scope_kind='owner' AND scope_id=$3) OR (scope_kind='workspace' AND scope_id='workspace') OR (scope_kind='automation' AND scope_id=$4))
        ORDER BY scope_kind,scope_id,metric",&[&deployment.as_str(),&tenant.as_str(),&owner,&automation]).await.map_err(|_|unavailable())
}

/// Time is drawn only from prior/current trusted PG observations. A rollback cannot reopen a bucket.
async fn budget_time(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
) -> Result<OffsetDateTime, AppError> {
    tx.query_one(
        "SELECT GREATEST(
            statement_timestamp(),
            max((reserved_bound->>'chargeAt')::timestamptz),
            max(settled_at),
            (SELECT max(b.bucket_start) FROM openbot_internal.automation_budget_balances b
             WHERE b.deployment_id=$1 AND b.tenant_id=$2 AND NOT b.is_total)
         ) FROM openbot_internal.automation_budget_attempts
         WHERE deployment_id=$1 AND tenant_id=$2",
        &[&deployment.as_str(), &tenant.as_str()],
    )
    .await
    .map_err(|_| unavailable())
    .and_then(|row| row.try_get(0).map_err(|_| unavailable()))
}

#[derive(Clone)]
struct Bucket {
    deployment: String,
    tenant: String,
    kind: String,
    id: String,
    revision: i64,
    metric: String,
    start: OffsetDateTime,
    total: bool,
    limit: i64,
    end: Option<OffsetDateTime>,
    currency: Option<String>,
}
impl Bucket {
    fn from_policy(row: &Row, start: OffsetDateTime, total: bool) -> Result<Self, AppError> {
        let seconds: Option<i64> = column(row, "window_seconds")?;
        Ok(Self {
            deployment: column(row, "deployment_id")?,
            tenant: column(row, "tenant_id")?,
            kind: column(row, "scope_kind")?,
            id: column(row, "scope_id")?,
            revision: column(row, "revision")?,
            metric: column(row, "metric")?,
            start,
            total,
            limit: if total {
                column::<Option<i64>>(row, "total_limit")?
            } else {
                column::<Option<i64>>(row, "window_limit")?
            }
            .ok_or_else(unavailable)?,
            end: if total {
                None
            } else {
                Some(
                    start
                        .checked_add(time::Duration::seconds(seconds.ok_or_else(unavailable)?))
                        .ok_or_else(unavailable)?,
                )
            },
            currency: column(row, "currency")?,
        })
    }
    // Full recompute from the original attempt ledger; only a policy install pays this scan.
    async fn sync(&self, tx: &Transaction<'_>) -> Result<(), AppError> {
        let row=tx.query_one("SELECT
            COALESCE(sum(CASE WHEN a.state='settled' THEN COALESCE((a.actual_usage->>$5)::bigint,0) ELSE 0 END),0)::bigint AS used,
            COALESCE(sum(CASE WHEN a.state<>'settled' THEN COALESCE((a.reserved_bound->>$5)::bigint,0) ELSE 0 END),0)::bigint AS reserved
            FROM openbot_internal.automation_budget_attempts a JOIN openbot_internal.automation_definitions d
              ON (d.deployment_id,d.tenant_id,d.automation_id)=(a.deployment_id,a.tenant_id,a.automation_id)
            WHERE a.deployment_id=$1 AND a.tenant_id=$2
              AND ($3='workspace' OR ($3='owner' AND d.owner_id=$4) OR ($3='automation' AND a.automation_id=$4))
              AND EXISTS(SELECT 1 FROM openbot_internal.automation_budget_reservations q
                  WHERE q.attempt_id=a.attempt_id AND q.deployment_id=a.deployment_id AND q.tenant_id=a.tenant_id
                    AND q.scope_kind=$3 AND q.scope_id=$4 AND q.policy_revision<=$9)
              AND ($6 OR ((a.reserved_bound->>'chargeAt')::timestamptz >=$7 AND (a.reserved_bound->>'chargeAt')::timestamptz <$8))",
            &[&self.deployment,&self.tenant,&self.kind,&self.id,&self.metric,&self.total,&self.start,&self.end,&self.revision]).await.map_err(|_|unavailable())?;
        let (used, reserved): (i64, i64) = (column(&row, "used")?, column(&row, "reserved")?);
        tx.execute("INSERT INTO openbot_internal.automation_budget_balances(deployment_id,tenant_id,scope_kind,scope_id,policy_revision,metric,bucket_start,is_total,used,reserved)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(deployment_id,tenant_id,scope_kind,scope_id,policy_revision,metric,bucket_start,is_total) DO UPDATE SET used=excluded.used,reserved=excluded.reserved",
            &[&self.deployment,&self.tenant,&self.kind,&self.id,&self.revision,&self.metric,&self.start,&self.total,&used,&reserved]).await.map_err(|_|unavailable())?;
        Ok(())
    }
    /// Apply one attempt's change to its stored balance, exactly as a ledger recompute would.
    async fn add(&self, tx: &Transaction<'_>, used: i64, reserved: i64) -> Result<(), AppError> {
        tx.execute("UPDATE openbot_internal.automation_budget_balances SET used=used+$9,reserved=reserved+$10
            WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND policy_revision=$5 AND metric=$6 AND bucket_start=$7 AND is_total=$8",
            &[&self.deployment,&self.tenant,&self.kind,&self.id,&self.revision,&self.metric,&self.start,&self.total,&used,&reserved]).await.map_err(|_|unavailable())?;
        Ok(())
    }
}

async fn buckets(
    tx: &Transaction<'_>,
    rows: &[Row],
    at: OffsetDateTime,
) -> Result<Vec<Bucket>, AppError> {
    let mut out = Vec::new();
    for row in rows {
        if column::<Option<i64>>(row, "window_limit")?.is_some() {
            let origin: OffsetDateTime =
                column::<Option<OffsetDateTime>>(row, "window_origin")?.ok_or_else(unavailable)?;
            let seconds: i64 =
                column::<Option<i64>>(row, "window_seconds")?.ok_or_else(unavailable)?;
            let start:OffsetDateTime=tx.query_one("SELECT $1::timestamptz + floor(extract(epoch FROM ($2::timestamptz-$1::timestamptz))/$3::bigint)*$3::bigint*interval '1 second'",&[&origin,&at,&seconds]).await.map_err(|_|unavailable())?.get(0);
            out.push(Bucket::from_policy(row, start, false)?);
        }
        if column::<Option<i64>>(row, "total_limit")?.is_some() {
            out.push(Bucket::from_policy(row, OffsetDateTime::UNIX_EPOCH, true)?);
        }
    }
    out.sort_by(|a, b| {
        (&a.kind, &a.id, &a.metric, a.start, a.total)
            .cmp(&(&b.kind, &b.id, &b.metric, b.start, b.total))
    });
    Ok(out)
}

// Each revision starts from the original attempt ledger, not another revision's carried sums.
async fn refresh_current(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
) -> Result<(), AppError> {
    let rows=tx.query("SELECT * FROM openbot_internal.automation_budget_policies WHERE deployment_id=$1 AND tenant_id=$2 AND current ORDER BY scope_kind,scope_id,metric",
        &[&deployment.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?;
    let at = budget_time(tx, deployment, tenant).await?;
    for bucket in buckets(tx, &rows, at).await? {
        bucket.sync(tx).await?;
    }
    Ok(())
}

pub(crate) async fn projection(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    owner: &str,
    automation: &str,
) -> Result<Vec<AutomationBudgetProjection>, AppError> {
    let rows = policies(tx, deployment, tenant, owner, automation).await?;
    let at = budget_time(tx, deployment, tenant).await?;
    let mut items = Vec::new();
    for bucket in buckets(tx, &rows, at).await? {
        let (used, reserved) = match tx.query_opt("SELECT used,reserved FROM openbot_internal.automation_budget_balances WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND policy_revision=$5 AND metric=$6 AND bucket_start=$7 AND is_total=$8",
            &[&bucket.deployment,&bucket.tenant,&bucket.kind,&bucket.id,&bucket.revision,&bucket.metric,&bucket.start,&bucket.total]).await.map_err(|_|unavailable())? {
            Some(row) => (column(&row, "used")?, column(&row, "reserved")?),
            None => (0, 0),
        };
        items.push(AutomationBudgetProjection {
            scope: stored(serde_json::Value::String(bucket.kind))?,
            scope_id: bucket.id,
            policy_revision: bucket.revision.try_into()?,
            metric: stored(serde_json::Value::String(bucket.metric))?,
            bucket_start: bucket.start,
            is_total: bucket.total,
            limit: bucket.limit.try_into()?,
            used: used.try_into()?,
            reserved: reserved.try_into()?,
            currency: bucket.currency,
        });
    }
    Ok(items)
}

fn metric_name(metric: AutomationBudgetMetric) -> &'static str {
    match metric {
        AutomationBudgetMetric::Tokens => "tokens",
        AutomationBudgetMetric::SamplingCalls => "sampling_calls",
        AutomationBudgetMetric::ToolCalls => "tool_calls",
        AutomationBudgetMetric::ComputeMillis => "compute_millis",
        AutomationBudgetMetric::MoneyMicrounits => "money_microunits",
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bound {
    schema_version: AutomationSchemaVersion,
    #[serde(with = "time::serde::rfc3339")]
    charge_at: OffsetDateTime,
    #[serde(rename = "sampling_calls")]
    sampling_calls: i64,
    #[serde(rename = "tool_calls")]
    tool_calls: i64,
}
impl Bound {
    fn amount(&self, metric: &str) -> Result<i64, AppError> {
        match metric {
            "sampling_calls" => Ok(self.sampling_calls),
            "tool_calls" => Ok(self.tool_calls),
            // No existing model/tool contract proves a token, duration or monetary upper bound.
            "tokens" | "compute_millis" | "money_microunits" => Err(budget_blocked()),
            _ => Err(unavailable()),
        }
    }
}

/// Held only inside the original begin transaction; it carries no user/session authority.
pub(crate) struct AutomationBudgetPlan {
    bound: Bound,
    buckets: Vec<Bucket>,
}
impl AutomationBudgetPlan {
    pub(crate) async fn prepare_start(
        tx: &Transaction<'_>,
        deployment: &DeploymentId,
        tenant: &TenantId,
        definition: &Row,
    ) -> Result<Self, AppError> {
        let owner: String = column(definition, "owner_id")?;
        let id: String = column(definition, "automation_id")?;
        Self::prepare(tx, deployment, tenant, &owner, &id, true).await
    }
    async fn prepare(
        tx: &Transaction<'_>,
        deployment: &DeploymentId,
        tenant: &TenantId,
        owner: &str,
        automation: &str,
        sampling: bool,
    ) -> Result<Self, AppError> {
        let policies = policies(tx, deployment, tenant, owner, automation).await?;
        for kind in ["owner", "workspace", "automation"] {
            if !policies
                .iter()
                .any(|r| r.get::<_, String>("scope_kind") == kind)
            {
                return Err(budget_blocked());
            }
        }
        let at = budget_time(tx, deployment, tenant).await?;
        let bound = Bound {
            schema_version: AutomationSchemaVersion,
            charge_at: at,
            sampling_calls: i64::from(sampling),
            tool_calls: i64::from(!sampling),
        };
        let buckets = buckets(tx, &policies, at).await?;
        for bucket in &buckets {
            let amount = bound.amount(&bucket.metric)?;
            // A current bucket without a row has no attempt yet: every reservation creates its row
            // and a newly current revision is seeded from the ledger by refresh_current.
            tx.execute("INSERT INTO openbot_internal.automation_budget_balances(deployment_id,tenant_id,scope_kind,scope_id,policy_revision,metric,bucket_start,is_total)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING",
                &[&bucket.deployment,&bucket.tenant,&bucket.kind,&bucket.id,&bucket.revision,&bucket.metric,&bucket.start,&bucket.total]).await.map_err(|_|unavailable())?;
            let row=tx.query_one("SELECT used,reserved FROM openbot_internal.automation_budget_balances WHERE deployment_id=$1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 AND policy_revision=$5 AND metric=$6 AND bucket_start=$7 AND is_total=$8 FOR UPDATE",
                &[&bucket.deployment,&bucket.tenant,&bucket.kind,&bucket.id,&bucket.revision,&bucket.metric,&bucket.start,&bucket.total]).await.map_err(|_|unavailable())?;
            if column::<i64>(&row, "used")?
                .checked_add(column(&row, "reserved")?)
                .and_then(|v| v.checked_add(amount))
                .is_none_or(|v| v > bucket.limit)
            {
                return Err(budget_blocked());
            }
        }
        Ok(Self { bound, buckets })
    }

    pub(crate) async fn reserve_start(
        self,
        tx: &Transaction<'_>,
        definition: &Row,
        run: &openbot_contracts::ids::RunId,
    ) -> Result<(), AppError> {
        self.insert(
            tx,
            definition,
            run.as_str(),
            "sampling",
            "sampling:0",
            "reserved",
        )
        .await
    }
    async fn insert(
        self,
        tx: &Transaction<'_>,
        definition: &Row,
        run: &str,
        kind: &str,
        source: &str,
        state: &str,
    ) -> Result<(), AppError> {
        use sha2::{Digest, Sha256};
        let deployment: String = column(definition, "deployment_id")?;
        let tenant: String = column(definition, "tenant_id")?;
        let automation: String = column(definition, "automation_id")?;
        let digest = Sha256::digest(
            serde_json::to_vec(&(&deployment, &tenant, run, kind, source))
                .map_err(|_| unavailable())?,
        );
        let attempt = format!("abud:{digest:x}");
        let bound = serde_json::to_value(&self.bound).map_err(|_| unavailable())?;
        tx.execute("INSERT INTO openbot_internal.automation_budget_attempts(attempt_id,deployment_id,tenant_id,automation_id,root_run_id,run_id,usage_kind,source_attempt_ref,state,reserved_bound)
            VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,$9)",
            &[&attempt,&deployment,&tenant,&automation,&run,&kind,&source,&state,&bound]).await.map_err(|_|unavailable())?;
        self.reserve_buckets(tx, &attempt).await
    }

    async fn reserve_buckets(self, tx: &Transaction<'_>, attempt: &str) -> Result<(), AppError> {
        for bucket in &self.buckets {
            let amount = self.bound.amount(&bucket.metric)?;
            tx.execute("INSERT INTO openbot_internal.automation_budget_reservations(deployment_id,tenant_id,attempt_id,scope_kind,scope_id,policy_revision,metric,bucket_start,is_total,reserved)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[&bucket.deployment,&bucket.tenant,&attempt,&bucket.kind,&bucket.id,&bucket.revision,&bucket.metric,&bucket.start,&bucket.total,&amount]).await.map_err(|_|unavailable())?;
            bucket.add(tx, 0, amount).await?;
        }
        Ok(())
    }
}

/// A core FK alone never proves the definition's owner, Bot, Thread or workspace.
pub(crate) async fn verify_core_run(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    definition: &Row,
    run: &str,
) -> Result<(), AppError> {
    if column::<String>(definition, "deployment_id")? != deployment.as_str()
        || column::<String>(definition, "tenant_id")? != tenant.as_str()
    {
        return Err(AppError::AutomationDelegationInvalid);
    }
    let valid:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.actor_id=$3 AND r.bot_id=$4 AND t.deployment_id=$5 AND t.tenant_id=$6
          AND t.created_by=$3 AND t.anchor_kind='direct_bot' AND t.anchor_id=$4)",
        &[&run,&column::<String>(definition,"thread_id")?,&column::<String>(definition,"owner_id")?,&column::<String>(definition,"bot_id")?,&deployment.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?.get(0);
    if !valid {
        return Err(AppError::AutomationDelegationInvalid);
    }
    Ok(())
}

async fn locked_definition_for_run(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    run: &str,
) -> Result<Option<Row>, AppError> {
    let row=tx.query_opt("SELECT d.*,v.delegation_revision FROM openbot_internal.automation_occurrences o
        JOIN openbot_internal.automation_definitions d ON (d.deployment_id,d.tenant_id,d.automation_id)=(o.deployment_id,o.tenant_id,o.automation_id)
        JOIN openbot_internal.automation_definition_revisions v ON (v.deployment_id,v.tenant_id,v.automation_id,v.revision)=(d.deployment_id,d.tenant_id,d.automation_id,d.current_revision)
        WHERE o.run_id=$1 FOR UPDATE OF d",&[&run]).await.map_err(|_|unavailable())?;
    if let Some(row) = &row {
        if column::<String>(row, "deployment_id")? != deployment.as_str()
            || column::<String>(row, "tenant_id")? != tenant.as_str()
        {
            return Err(AppError::AutomationDelegationInvalid);
        }
        verify_core_run(tx, deployment, tenant, row, run).await?;
    }
    Ok(row)
}

impl crate::automation::PostgresAutomations {
    pub(crate) async fn before_sampling(
        &self,
        lease: &openbot_application::RunExecutionLease,
        index: u32,
    ) -> Result<bool, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let Some(definition) =
            locked_definition_for_run(&tx, &self.deployment, &self.tenant, lease.run_id().as_str())
                .await?
        else {
            return Ok(false);
        };
        verify_lease(&tx, lease, &definition).await?;
        execution_grant(
            &tx,
            &self.deployment,
            &self.tenant,
            &definition,
            lease.run_id().as_str(),
        )
        .await?;
        let source = format!("sampling:{index}");
        let existing=tx.query_opt("SELECT attempt_id,state,reserved_bound,(reserved_bound->>'chargeAt')::timestamptz AS charge_at FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3 AND usage_kind='sampling' AND source_attempt_ref=$4",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&lease.run_id().as_str(),&source]).await.map_err(|_|unavailable())?;
        if let Some(existing) = &existing {
            if column::<String>(existing, "state")? != "reserved" {
                return Err(AppError::ReconciliationRequired { accepted: true });
            }
            let attempt: String = column(existing, "attempt_id")?;
            // Move only the unsent start reservation. A refusal rolls this back, and the
            // original attempt stays bound to its old buckets until a send is permitted.
            let bound: serde_json::Value = column(existing, "reserved_bound")?;
            for bucket in attempt_buckets(
                &tx,
                &self.deployment,
                &self.tenant,
                &attempt,
                column(existing, "charge_at")?,
            )
            .await?
            {
                let amount = bound
                    .get(&bucket.metric)
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                bucket.add(&tx, 0, -amount).await?;
            }
            tx.execute("DELETE FROM openbot_internal.automation_budget_reservations WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&attempt]).await.map_err(|_|unavailable())?;
        }
        let plan = AutomationBudgetPlan::prepare(
            &tx,
            &self.deployment,
            &self.tenant,
            &column::<String>(&definition, "owner_id")?,
            &column::<String>(&definition, "automation_id")?,
            true,
        )
        .await?;
        if let Some(existing) = existing {
            let attempt: String = column(&existing, "attempt_id")?;
            let bound = serde_json::to_value(&plan.bound).map_err(|_| unavailable())?;
            tx.execute("UPDATE openbot_internal.automation_budget_attempts SET state='unknown',reserved_bound=$4 WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3 AND state='reserved'",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&attempt,&bound]).await.map_err(|_|unavailable())?;
            plan.reserve_buckets(&tx, &attempt).await?;
        } else {
            plan.insert(
                &tx,
                &definition,
                lease.run_id().as_str(),
                "sampling",
                &source,
                "unknown",
            )
            .await?;
        }
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(true)
    }
}

async fn verify_lease(
    tx: &Transaction<'_>,
    lease: &openbot_application::RunExecutionLease,
    definition: &Row,
) -> Result<(), AppError> {
    if column::<String>(definition, "thread_id")? != lease.thread_id().as_str()
        || column::<String>(definition, "owner_id")? != lease.actor_id().as_str()
        || column::<String>(definition, "bot_id")? != lease.bot_id().as_str()
    {
        return Err(AppError::AutomationDelegationInvalid);
    }
    let valid:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM public.runs r JOIN public.thread_leases l ON l.thread_id=r.thread_id
        WHERE r.run_id=$1 AND r.status='running' AND r.fencing_token=$2 AND l.fencing_token=$2 AND l.expires_at>statement_timestamp())",
        &[&lease.run_id().as_str(),&lease.fencing().get()]).await.map_err(|_|unavailable())?.get(0);
    if !valid {
        return Err(AppError::AutomationDelegationInvalid);
    }
    Ok(())
}

/// Called only alongside the real normalized usage row in its original runtime transaction.
pub(crate) async fn settle_sampling(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    run: &str,
    index: u32,
    tokens: Option<i64>,
) -> Result<(), AppError> {
    lock_workspace(tx, deployment, tenant).await?;
    let Some(definition) = locked_definition_for_run(tx, deployment, tenant, run).await? else {
        return Ok(());
    };
    let source = format!("sampling:{index}");
    let row=tx.query_opt("SELECT attempt_id FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3 AND usage_kind='sampling' AND source_attempt_ref=$4",
        &[&deployment.as_str(),&tenant.as_str(),&run,&source]).await.map_err(|_|unavailable())?.ok_or_else(unavailable)?;
    let mut actual = serde_json::json!({"sampling_calls":1,"tool_calls":0});
    if let Some(tokens) = tokens {
        actual["tokens"] = serde_json::json!(tokens);
    }
    settle(
        tx,
        deployment,
        tenant,
        &definition,
        run,
        &column::<String>(&row, "attempt_id")?,
        actual,
    )
    .await
}

async fn settle(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    definition: &Row,
    run: &str,
    attempt: &str,
    actual: serde_json::Value,
) -> Result<(), AppError> {
    let row=tx.query_one("SELECT state,actual_usage,reserved_bound,automation_id,run_id,root_run_id,(reserved_bound->>'chargeAt')::timestamptz AS charge_at FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3 FOR UPDATE",
        &[&deployment.as_str(),&tenant.as_str(),&attempt]).await.map_err(|_|unavailable())?;
    if column::<String>(&row, "run_id")? != run
        || column::<String>(&row, "root_run_id")? != run
        || column::<String>(&row, "automation_id")?
            != column::<String>(definition, "automation_id")?
    {
        return Err(AppError::AutomationDelegationInvalid);
    }
    if column::<String>(&row, "state")? == "settled" {
        if column::<Option<serde_json::Value>>(&row, "actual_usage")?.as_ref() != Some(&actual) {
            return Err(unavailable());
        }
        return Ok(());
    }
    let rows=tx.query("SELECT metric,reserved FROM openbot_internal.automation_budget_reservations WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3 ORDER BY scope_kind,scope_id,metric,bucket_start,is_total FOR UPDATE",
        &[&deployment.as_str(),&tenant.as_str(),&attempt]).await.map_err(|_|unavailable())?;
    for row in &rows {
        let metric: String = column(row, "metric")?;
        let amount = actual
            .get(&metric)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(unavailable)?;
        if amount < 0 || amount > column::<i64>(row, "reserved")? {
            return Err(budget_blocked());
        }
    }
    tx.execute("UPDATE openbot_internal.automation_budget_attempts SET state='settled',actual_usage=$4,settled_at=statement_timestamp() WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3",
        &[&deployment.as_str(),&tenant.as_str(),&attempt,&actual]).await.map_err(|_|unavailable())?;
    tx.execute("UPDATE openbot_internal.automation_budget_reservations SET settled=($4::jsonb->>metric)::bigint,released=reserved-($4::jsonb->>metric)::bigint WHERE deployment_id=$1 AND tenant_id=$2 AND attempt_id=$3",
        &[&deployment.as_str(),&tenant.as_str(),&attempt,&actual]).await.map_err(|_|unavailable())?;
    let bound: serde_json::Value = column(&row, "reserved_bound")?;
    for bucket in
        attempt_buckets(tx, deployment, tenant, attempt, column(&row, "charge_at")?).await?
    {
        let amount = |value: &serde_json::Value| {
            value
                .get(&bucket.metric)
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
        };
        bucket.add(tx, amount(&actual), -amount(&bound)).await?;
    }
    Ok(())
}

// A later revision may have carried this attempt. Every stored interval that counts it follows
// from reservation ancestry; future revisions cannot charge older ones.
async fn attempt_buckets(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    attempt: &str,
    charge_at: OffsetDateTime,
) -> Result<Vec<Bucket>, AppError> {
    let balances=tx.query("SELECT p.*,b.bucket_start,b.is_total FROM openbot_internal.automation_budget_balances b
        JOIN openbot_internal.automation_budget_policies p ON (p.deployment_id,p.tenant_id,p.scope_kind,p.scope_id,p.revision,p.metric)=(b.deployment_id,b.tenant_id,b.scope_kind,b.scope_id,b.policy_revision,b.metric)
        WHERE b.deployment_id=$1 AND b.tenant_id=$2
          AND EXISTS(SELECT 1 FROM openbot_internal.automation_budget_reservations q
            WHERE (q.deployment_id,q.tenant_id,q.scope_kind,q.scope_id)=(b.deployment_id,b.tenant_id,b.scope_kind,b.scope_id)
              AND q.attempt_id=$3 AND q.policy_revision<=b.policy_revision)
          AND (b.is_total OR (b.bucket_start<=$4 AND b.bucket_start + p.window_seconds*interval '1 second'>$4))
        ORDER BY b.scope_kind,b.scope_id,b.metric,b.bucket_start,b.is_total",
        &[&deployment.as_str(),&tenant.as_str(),&attempt,&charge_at]).await.map_err(|_|unavailable())?;
    balances
        .iter()
        .map(|row| Bucket::from_policy(row, column(row, "bucket_start")?, column(row, "is_total")?))
        .collect()
}

/// Only reservations that never crossed the pre-send boundary may be released at a real terminal.
pub(crate) async fn release_unsent(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    run: &str,
) -> Result<(), AppError> {
    lock_workspace(tx, deployment, tenant).await?;
    let Some(definition) = locked_definition_for_run(tx, deployment, tenant, run).await? else {
        return Ok(());
    };
    let rows=tx.query("SELECT attempt_id FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3 AND state='reserved'",
        &[&deployment.as_str(),&tenant.as_str(),&run]).await.map_err(|_|unavailable())?;
    for row in rows {
        settle(
            tx,
            deployment,
            tenant,
            &definition,
            run,
            &column::<String>(&row, "attempt_id")?,
            serde_json::json!({"sampling_calls":0,"tool_calls":0}),
        )
        .await?;
    }
    Ok(())
}

fn budget_blocked() -> AppError {
    AppError::PolicyRefused {
        rule: "automation_budget_exceeded".to_owned(),
        decision: None,
    }
}

pub(crate) async fn execution_grant(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    definition: &Row,
    run: &str,
) -> Result<AutomationDelegationV1, AppError> {
    let current = crate::automation::store::valid_grant(tx, deployment, tenant, definition).await?;
    let row=tx.query_opt("SELECT (m.content->'delegation'->>'revision')::bigint AS revision,
        m.content->'delegation'->'source'->>'kind' AS kind,m.content->'delegation'->'source'->>'definitionId' AS definition_id
        FROM public.messages m WHERE m.message_id=$1||':input' AND m.run_id=$1",&[&run]).await.map_err(|_|unavailable())?.ok_or(AppError::AutomationDelegationInvalid)?;
    let automation: String = column(definition, "automation_id")?;
    if column::<Option<String>>(&row, "kind")?.as_deref() != Some("automation_definition")
        || column::<Option<String>>(&row, "definition_id")?.as_deref() != Some(automation.as_str())
    {
        return Err(AppError::AutomationDelegationInvalid);
    }
    let revision: i64 =
        column::<Option<i64>>(&row, "revision")?.ok_or(AppError::AutomationDelegationInvalid)?;
    if revision == current.definition_revision.get() {
        return Ok(current);
    }
    // A Run admitted before a re-grant keeps its own grant only while it is still valid, and
    // only what the current grant also allows.
    let original=tx.query_opt("SELECT g.grant_snapshot FROM openbot_internal.automation_delegations g JOIN public.users u ON u.id=g.owner_id
        WHERE g.deployment_id=$1 AND g.tenant_id=$2 AND g.automation_id=$3 AND g.delegation_revision=$4 AND g.revoked_at IS NULL
          AND (g.expires_at IS NULL OR g.expires_at>statement_timestamp())
          AND g.granted_auth_generation=COALESCE(u.auth_generation,0)
        FOR SHARE OF g",
        &[&deployment.as_str(),&tenant.as_str(),&automation,&revision]).await.map_err(|_|unavailable())?.ok_or(AppError::AutomationDelegationInvalid)?;
    let mut original: AutomationDelegationV1 = stored(column(&original, "grant_snapshot")?)?;
    original.tool_ids.retain(|id| current.tool_ids.contains(id));
    original
        .data_scopes
        .retain(|id| current.data_scopes.contains(id));
    Ok(original)
}

#[async_trait::async_trait]
impl openbot_application::automation::AutomationExecutionBudgets
    for crate::automation::PostgresAutomations
{
    async fn reserve_sampling(
        &self,
        lease: &openbot_application::RunExecutionLease,
        index: u32,
    ) -> Result<bool, AppError> {
        self.before_sampling(lease, index).await
    }

    async fn allows_tool(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        scope: &openbot_application::tool::ResolvedToolScope,
        metadata: &openbot_domain::tool::metadata::ToolMetadata,
    ) -> Result<bool, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let definition =
            locked_definition_for_run(&tx, &self.deployment, &self.tenant, scope.run_id.as_str())
                .await?
                .ok_or(AppError::AutomationDelegationInvalid)?;
        let grant = execution_grant(
            &tx,
            &self.deployment,
            &self.tenant,
            &definition,
            scope.run_id.as_str(),
        )
        .await?;
        if grant.owner_id != *auth.actor()
            || grant.bot_id != scope.bot_id
            || grant.thread_id != scope.thread_id
            || grant.deployment_id != *auth.deployment()
            || grant.tenant_id != *auth.tenant()
            || grant.auth_generation
                != i64::try_from(auth.auth_generation().get()).map_err(|_| unavailable())?
        {
            return Err(AppError::AutomationDelegationInvalid);
        }
        let allowed = grant.tool_ids.iter().any(|id| id == metadata.name.as_str())
            && grant.data_scopes.iter().any(|id| id == &scope.target.id);
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(allowed)
    }
    async fn reserve_tool(
        &self,
        auth: &openbot_contracts::auth::AuthContext,
        identity: &openbot_application::automation::AutomationToolIdentity,
    ) -> Result<(), AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let definition = locked_definition_for_run(
            &tx,
            &self.deployment,
            &self.tenant,
            identity.run_id.as_str(),
        )
        .await?
        .ok_or(AppError::AutomationDelegationInvalid)?;
        let grant = execution_grant(
            &tx,
            &self.deployment,
            &self.tenant,
            &definition,
            identity.run_id.as_str(),
        )
        .await?;
        if grant.owner_id != *auth.actor()
            || grant.bot_id != identity.bot_id
            || grant.deployment_id != *auth.deployment()
            || grant.tenant_id != *auth.tenant()
            || grant.auth_generation
                != i64::try_from(auth.auth_generation().get()).map_err(|_| unavailable())?
        {
            return Err(AppError::AutomationDelegationInvalid);
        }
        let attempt=tx.query_opt("SELECT a.attempt_id FROM public.tool_calls c JOIN public.tool_attempts a ON a.tool_call_id=c.tool_call_id
            WHERE c.tool_call_id=$1 AND c.run_id=$2 AND c.actor_id=$3 AND c.bot_id=$4 AND a.status='executing' AND a.capability_id IS NOT NULL
            ORDER BY a.attempt_seq DESC LIMIT 1 FOR SHARE OF a",
            &[&identity.call_id.as_str(),&identity.run_id.as_str(),&auth.actor().as_str(),&identity.bot_id.as_str()]).await.map_err(|_|unavailable())?.ok_or_else(budget_blocked)?;
        let source: String = column(&attempt, "attempt_id")?;
        let exists:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3 AND usage_kind='tool' AND source_attempt_ref=$4)",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&identity.run_id.as_str(),&source]).await.map_err(|_|unavailable())?.get(0);
        if exists {
            return Err(AppError::ReconciliationRequired { accepted: true });
        }
        let plan = AutomationBudgetPlan::prepare(
            &tx,
            &self.deployment,
            &self.tenant,
            grant.owner_id.as_str(),
            &column::<String>(&definition, "automation_id")?,
            false,
        )
        .await?;
        plan.insert(
            &tx,
            &definition,
            identity.run_id.as_str(),
            "tool",
            &source,
            "unknown",
        )
        .await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(())
    }
    async fn settle_tool_outcome(
        &self,
        draft: &openbot_application::tool::ToolOutcomeDraft,
    ) -> Result<(), AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let Some(definition) = locked_definition_for_run(
            &tx,
            &self.deployment,
            &self.tenant,
            draft.decision.run_id.as_str(),
        )
        .await?
        else {
            return Ok(());
        };
        let journal=tx.query_opt("SELECT a.commit_state,a.error_code FROM public.tool_calls c JOIN public.tool_attempts a ON a.tool_call_id=c.tool_call_id
            WHERE a.attempt_id=$1 AND c.tool_call_id=$2 AND c.run_id=$3 AND c.actor_id=$4 AND c.bot_id=$5 AND a.capability_id=$6 AND a.status IN ('completed','reconciliation_required')",
            &[&draft.receipt.attempt().as_str(),&draft.decision.call_id.as_str(),&draft.decision.run_id.as_str(),&draft.decision.actor.as_str(),&draft.decision.bot.as_str(),&draft.capability_id.as_str()]).await.map_err(|_|unavailable())?.ok_or_else(unavailable)?;
        if column::<Option<String>>(&journal, "commit_state")?.as_deref()
            != Some(draft.outcome.commit_state.as_str())
            || column::<Option<String>>(&journal, "error_code")?.as_deref()
                != draft.outcome.error_code
        {
            return Err(unavailable());
        }
        if draft.outcome.commit_state.requires_reconciliation() {
            return Ok(());
        }
        let attempt=tx.query_opt("SELECT attempt_id FROM openbot_internal.automation_budget_attempts WHERE deployment_id=$1 AND tenant_id=$2 AND run_id=$3 AND usage_kind='tool' AND source_attempt_ref=$4",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&draft.decision.run_id.as_str(),&draft.receipt.attempt().as_str()]).await.map_err(|_|unavailable())?;
        if let Some(attempt) = attempt {
            settle(
                &tx,
                &self.deployment,
                &self.tenant,
                &definition,
                draft.decision.run_id.as_str(),
                &column::<String>(&attempt, "attempt_id")?,
                tool_usage(draft.outcome.error_code),
            )
            .await?;
        }
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(())
    }
}

fn tool_usage(error_code: Option<&str>) -> serde_json::Value {
    let unsent = matches!(
        error_code,
        Some("automation_budget_exceeded" | "automation_budget_admission_unavailable")
    );
    serde_json::json!({"sampling_calls":0,"tool_calls":i64::from(!unsent)})
}

/// Recover a definite original journal outcome after a crash between its commit and settlement.
/// The caller holds the workspace lock. An uncertain or absent outcome leaves the reservation intact.
pub(crate) async fn settle_acknowledged_tool(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
) -> Result<(), AppError> {
    let candidate = tx.query_opt(
        "SELECT b.attempt_id,b.run_id,a.error_code
         FROM openbot_internal.automation_budget_attempts b
         JOIN openbot_internal.automation_definitions d
           ON (b.deployment_id,b.tenant_id,b.automation_id)=(d.deployment_id,d.tenant_id,d.automation_id)
         JOIN public.tool_attempts a ON a.attempt_id=b.source_attempt_ref
         JOIN public.tool_calls c ON c.tool_call_id=a.tool_call_id AND c.run_id=b.run_id
           AND c.actor_id=d.owner_id AND c.bot_id=d.bot_id
         WHERE b.deployment_id=$1 AND b.tenant_id=$2 AND b.usage_kind='tool' AND b.state='unknown'
           AND a.capability_id IS NOT NULL AND a.status='completed'
           AND a.commit_state IN ('committed','not_committed')
         ORDER BY b.attempt_id LIMIT 1",
        &[&deployment.as_str(), &tenant.as_str()],
    ).await.map_err(|_| unavailable())?;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let run: String = column(&candidate, "run_id")?;
    let definition = locked_definition_for_run(tx, deployment, tenant, &run)
        .await?
        .ok_or(AppError::AutomationDelegationInvalid)?;
    let error: Option<String> = column(&candidate, "error_code")?;
    settle(
        tx,
        deployment,
        tenant,
        &definition,
        &run,
        &column::<String>(&candidate, "attempt_id")?,
        tool_usage(error.as_deref()),
    )
    .await
}
