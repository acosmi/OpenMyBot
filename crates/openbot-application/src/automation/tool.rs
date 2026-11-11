//! Intersect automation ceilings at the original resolved scope and original executor boundary.

use super::{AutomationDefinitions, AutomationToolIdentity};
use crate::tool::*;
use async_trait::async_trait;
use openbot_contracts::{
    auth::AuthContext,
    ids::{CapabilityId, ToolCallId},
    tool::{ToolInvocation, ToolResult},
};
use openbot_domain::{
    policy::PolicyContext,
    tool::{
        args::ToolArguments,
        commit::CommitState,
        metadata::{ToolMetadata, ToolName},
        pipeline::{ApprovalOutcome, DurableDecisionReceipt},
    },
};
use std::time::Duration;

pub(crate) async fn invoke_automation_tool<C: ToolControlPlane, J: ToolJournal>(
    control: &C,
    journal: &J,
    budgets: &dyn AutomationDefinitions,
    auth: &AuthContext,
    invocation: ToolInvocation,
    guard: Option<&crate::delegation::DelegatedEffectGuard>,
) -> Result<ToolResult, openbot_contracts::error::AppError> {
    let identity = AutomationToolIdentity {
        run_id: invocation.run_id.clone(),
        call_id: invocation.call_id.clone(),
        bot_id: invocation.bot_id.clone(),
    };
    let control = Control {
        inner: control,
        budgets,
        auth,
        identity,
    };
    let journal = Journal {
        inner: journal,
        budgets,
    };
    invoke_tool_guarded(&control, &journal, auth, invocation, guard).await
}

struct Control<'a, C> {
    inner: &'a C,
    budgets: &'a dyn AutomationDefinitions,
    auth: &'a AuthContext,
    identity: AutomationToolIdentity,
}
#[async_trait]
impl<C: ToolControlPlane> ToolControlPlane for Control<'_, C> {
    async fn metadata(&self, name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        self.inner.metadata(name).await
    }
    async fn resolve_scope(
        &self,
        auth: &AuthContext,
        invocation: &ToolInvocation,
        arguments: &ToolArguments,
        metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        let mut scope = self
            .inner
            .resolve_scope(auth, invocation, arguments, metadata)
            .await?;
        if !self
            .budgets
            .allows_tool(auth, &scope, metadata)
            .await
            .map_err(|_| unavailable())?
            && scope.preflight_refusal.is_none()
        {
            scope.preflight_refusal = Some(ToolPreflightRefusal::new(
                "automation_permission_ceiling",
                "automation_permission_ceiling",
            ));
        }
        Ok(scope)
    }
    async fn evaluate_policy(
        &self,
        context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        self.inner.evaluate_policy(context).await
    }
    async fn approval(
        &self,
        request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        self.inner.approval(request).await
    }
    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        match self.budgets.reserve_tool(self.auth, &self.identity).await {
            Ok(()) => self.inner.execute(call).await,
            Err(error) => {
                let (_unsent, redeemed) = call.redeem();
                let (state, code) = match error {
                    openbot_contracts::error::AppError::ReconciliationRequired { .. } => {
                        (CommitState::Unknown, "automation_budget_attempt_unknown")
                    }
                    openbot_contracts::error::AppError::PolicyRefused { .. } => {
                        (CommitState::NotCommitted, "automation_budget_exceeded")
                    }
                    _ => (
                        CommitState::NotCommitted,
                        "automation_budget_admission_unavailable",
                    ),
                };
                ToolExecutionReport::new(
                    redeemed,
                    "Automation budget could not admit this tool attempt.".to_owned(),
                    state,
                    Duration::ZERO,
                    Some(code),
                )
            }
        }
    }
}
struct Journal<'a, J> {
    inner: &'a J,
    budgets: &'a dyn AutomationDefinitions,
}
#[async_trait]
impl<J: ToolJournal> ToolJournal for Journal<'_, J> {
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        self.inner.record_refusal(draft).await
    }
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        self.inner.record_decision(draft).await
    }
    async fn attach_capability(
        &self,
        call: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        self.inner.attach_capability(call, capability).await
    }
    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        self.inner.record_outcome(draft).await?;
        self.budgets
            .settle_tool_outcome(draft)
            .await
            .map_err(|_| unavailable())
    }
}
fn unavailable() -> ToolPortError {
    ToolPortError::Unavailable {
        dependency: "automation_budget",
    }
}
