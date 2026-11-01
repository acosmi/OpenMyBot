//! Requests originate in the real capability pipeline. Capture-only mode creates no effect;
//! every effect assertion invokes the production PostgreSQL memory adapter.

use async_trait::async_trait;
use openbot_application::{
    CommittedMemoryEffect, MemoryAdministrationError, RememberToolMemory,
    RememberToolMemoryRequest, ToolDecisionDraft, ToolJournal, ToolOutcomeDraft, ToolPortError,
    ToolRefusalDraft, invoke_tool,
};
use openbot_contracts::{
    auth::AuthContext,
    error::AppError,
    ids::{CapabilityId, ToolCallId},
    tool::{ToolInvocation, ToolResult},
};
use openbot_domain::{
    policy::{ActionPolicy, PolicyMode},
    tool::pipeline::DurableDecisionReceipt,
};
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::{
    agent_tools::PostgresBuiltInToolControlPlane, memory_admin::PostgresMemoryAdministration,
    policy::PolicyStore, repo::tools::PostgresToolJournal,
};
use std::sync::{Arc, Mutex};

pub const KEY: &[u8] = b"owned-remember-effect-postgres-test-audit-key";

pub struct CapturingMemory {
    pub request: Mutex<Option<RememberToolMemoryRequest>>,
    pub inner: Option<PostgresMemoryAdministration>,
}

#[async_trait]
impl RememberToolMemory for CapturingMemory {
    async fn remember_from_tool(
        &self,
        request: RememberToolMemoryRequest,
    ) -> Result<CommittedMemoryEffect, MemoryAdministrationError> {
        *self.request.lock().unwrap() = Some(request.clone());
        match &self.inner {
            Some(inner) => inner.remember_from_tool(request).await,
            None => Err(MemoryAdministrationError::CommitUnknown),
        }
    }
}

pub struct CapturingJournal {
    pub inner: PostgresToolJournal,
    pub outcome: Mutex<Option<ToolOutcomeDraft>>,
    pub fail_outcome: bool,
    pool: Pool,
    legacy_ids: JournalIds,
}

/// Negative-only fixture: substitute persisted legacy identifiers before capability issuance.
#[derive(Default)]
pub struct JournalIds {
    pub attempt: Option<String>,
    pub decision: Option<String>,
}

#[async_trait]
impl ToolJournal for CapturingJournal {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        let original = self.inner.record_decision(draft).await?;
        if self.legacy_ids.attempt.is_none() && self.legacy_ids.decision.is_none() {
            return Ok(original);
        }
        let unavailable = |_| ToolPortError::Unavailable {
            dependency: "owned_legacy_fixture",
        };
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ToolPortError::Unavailable {
                dependency: "owned_legacy_fixture",
            })?;
        let tx = client.transaction().await.map_err(unavailable)?;
        let decision = self
            .legacy_ids
            .decision
            .as_deref()
            .unwrap_or(original.decision().as_str());
        let attempt = self
            .legacy_ids
            .attempt
            .as_deref()
            .unwrap_or(original.attempt().as_str());
        let calls = tx
            .execute(
                "UPDATE public.tool_calls SET decision_id=$2 WHERE tool_call_id=$1",
                &[&draft.call_id.as_str(), &decision],
            )
            .await
            .map_err(unavailable)?;
        let attempts=tx.execute("UPDATE public.tool_attempts SET attempt_id=$3 WHERE tool_call_id=$1 AND attempt_id=$2",&[&draft.call_id.as_str(),&original.attempt().as_str(),&attempt]).await.map_err(unavailable)?;
        if calls != 1 || attempts != 1 {
            return Err(ToolPortError::Corrupt {
                field: "owned_legacy_fixture",
            });
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(DurableDecisionReceipt::issued_by_repository(
            openbot_contracts::ids::PolicyDecisionId::new(decision),
            openbot_contracts::ids::AttemptId::new(attempt),
        ))
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.inner.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        *self.outcome.lock().unwrap() = Some(draft.clone());
        if self.fail_outcome {
            Err(ToolPortError::Unavailable {
                dependency: "owned_test_outcome_failure",
            })
        } else {
            self.inner.record_outcome(draft).await
        }
    }
}

pub fn store(pool: &Pool) -> PostgresMemoryAdministration {
    PostgresMemoryAdministration::new(pool.clone())
        .with_effect_audit_key(KEY.to_vec())
        .unwrap()
}

pub async fn pipeline(
    pool: &Pool,
    auth: &AuthContext,
    invocation: ToolInvocation,
    inner: Option<PostgresMemoryAdministration>,
    fail_outcome: bool,
) -> Result<
    (
        Result<ToolResult, AppError>,
        RememberToolMemoryRequest,
        ToolOutcomeDraft,
    ),
    String,
> {
    pipeline_with_journal_ids(
        pool,
        auth,
        invocation,
        inner,
        fail_outcome,
        JournalIds::default(),
    )
    .await
}

pub async fn pipeline_with_journal_ids(
    pool: &Pool,
    auth: &AuthContext,
    invocation: ToolInvocation,
    inner: Option<PostgresMemoryAdministration>,
    fail_outcome: bool,
    legacy_ids: JournalIds,
) -> Result<
    (
        Result<ToolResult, AppError>,
        RememberToolMemoryRequest,
        ToolOutcomeDraft,
    ),
    String,
> {
    let policy = PolicyStore::postgres(pool.clone(), None);
    policy.load().await.map_err(|e| e.to_string())?;
    policy
        .set(
            ActionPolicy {
                mode: PolicyMode::Enforce,
                deny: vec![],
                allow: vec!["tool.name == \"remember\"".into()],
            },
            Some(auth.actor().as_str()),
        )
        .await
        .map_err(|e| e.to_string())?;
    let memory = Arc::new(CapturingMemory {
        request: Mutex::new(None),
        inner,
    });
    let control = PostgresBuiltInToolControlPlane::new(
        pool.clone(),
        auth.deployment().clone(),
        auth.tenant().clone(),
        policy,
        memory.clone(),
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
            &pool,
            &openbot_contracts::ids::DeploymentId::new("outside"),
            &openbot_contracts::ids::TenantId::new("outside"),
        ),
    );
    let journal = CapturingJournal {
        inner: PostgresToolJournal::new(pool.clone(), KEY.to_vec()).map_err(|e| e.to_string())?,
        outcome: Mutex::new(None),
        fail_outcome,
        pool: pool.clone(),
        legacy_ids,
    };
    let result = invoke_tool(&control, &journal, auth, invocation).await;
    let request = memory
        .request
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| format!("request did not reach capture: {result:?}"))?;
    let outcome = journal
        .outcome
        .lock()
        .unwrap()
        .clone()
        .ok_or("outcome did not reach journal")?;
    Ok((result, request, outcome))
}

pub async fn capture(
    pool: &Pool,
    auth: &AuthContext,
    invocation: ToolInvocation,
) -> Result<RememberToolMemoryRequest, String> {
    let (result, request, _) = pipeline(pool, auth, invocation, None, true).await?;
    if !matches!(result, Err(AppError::ReconciliationRequired { .. })) {
        return Err("capture must leave outcome unresolved".into());
    }
    Ok(request)
}
