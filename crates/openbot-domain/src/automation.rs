//! Validated automation intent; current authority is checked separately on every use.

use std::collections::BTreeSet;

use openbot_contracts::automation::{
    AutomationBudgetMetric, AutomationBudgetRule, AutomationBudgetsFile, AutomationConfigV1,
    AutomationContractError,
};
use time::UtcOffset;

use crate::tool::metadata::ToolName;

/// A bounded exact data resource intent, never a wildcard or a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationDataScope(String);

impl AutomationDataScope {
    /// Borrow the exact resource identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AutomationDataScope {
    type Error = AutomationContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 256 || value.contains('*') {
            return Err(AutomationContractError::MalformedPayload);
        }
        Ok(Self(value))
    }
}

/// Immutable intent after the single admission boundary.
///
/// The wire value is retained for the immutable snapshot and direct idempotency comparison.
/// Parsed resource identities are reused by execution rather than reparsed on each effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationConfig {
    wire: AutomationConfigV1,
    tools: Vec<ToolName>,
    data_scopes: Vec<AutomationDataScope>,
}

impl AutomationConfig {
    /// Read the validated original intent without exposing a mutation path.
    #[must_use]
    pub fn wire(&self) -> &AutomationConfigV1 {
        &self.wire
    }

    /// Tool intents; these still require intersection with current owner/Bot/CEL authority.
    #[must_use]
    pub fn tools(&self) -> &[ToolName] {
        &self.tools
    }

    /// Exact data intents; an empty set grants no data access.
    #[must_use]
    pub fn data_scopes(&self) -> &[AutomationDataScope] {
        &self.data_scopes
    }
}

impl TryFrom<AutomationConfigV1> for AutomationConfig {
    type Error = AutomationContractError;

    fn try_from(mut wire: AutomationConfigV1) -> Result<Self, Self::Error> {
        if wire.prompt_template.len() > 16 * 1024 {
            return Err(AutomationContractError::PayloadTooLarge);
        }
        if wire.title.is_empty()
            || wire.title.len() > 512
            || wire.title.chars().count() > 128
            || wire.prompt_template.is_empty()
            || !(1..=1800).contains(&wire.run_deadline_seconds)
            || wire.permission_ceiling.tool_ids.len() > 128
            || wire.permission_ceiling.data_scopes.len() > 128
        {
            return Err(AutomationContractError::MalformedPayload);
        }
        let mut tools = Vec::with_capacity(wire.permission_ceiling.tool_ids.len());
        for tool in &wire.permission_ceiling.tool_ids {
            tools.push(
                ToolName::new(tool.clone())
                    .map_err(|_| AutomationContractError::MalformedPayload)?,
            );
        }
        let data_scopes = wire
            .permission_ceiling
            .data_scopes
            .iter()
            .cloned()
            .map(AutomationDataScope::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        validate_budget(&mut wire.budget)?;
        Ok(Self {
            wire,
            tools,
            data_scopes,
        })
    }
}

fn validate_budget(rules: &mut [AutomationBudgetRule]) -> Result<(), AutomationContractError> {
    if !(1..=5).contains(&rules.len()) {
        return Err(AutomationContractError::MalformedPayload);
    }
    let mut metrics = BTreeSet::new();
    for rule in rules {
        if !metrics.insert(rule.metric) || (rule.window.is_none() && rule.total_limit.is_none()) {
            return Err(AutomationContractError::MalformedPayload);
        }
        match (rule.metric, rule.currency.as_deref()) {
            (AutomationBudgetMetric::MoneyMicrounits, Some(currency)) if !currency.is_empty() => {}
            (AutomationBudgetMetric::MoneyMicrounits, _) | (_, Some(_)) => {
                return Err(AutomationContractError::MalformedPayload);
            }
            (_, None) => {}
        }
        if let Some(window) = &mut rule.window {
            if !(1..=31_536_000).contains(&window.seconds) {
                return Err(AutomationContractError::MalformedPayload);
            }
            window.origin = window.origin.to_offset(UtcOffset::UTC);
        }
    }
    Ok(())
}

/// Startup policies after the sole shape, bounds and duplicate-scope admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationBudgets {
    wire: AutomationBudgetsFile,
}

impl AutomationBudgets {
    /// Immutable trusted policies, ready for monotonic persistence in the startup transaction.
    #[must_use]
    pub fn wire(&self) -> &AutomationBudgetsFile {
        &self.wire
    }
}

impl TryFrom<AutomationBudgetsFile> for AutomationBudgets {
    type Error = AutomationContractError;

    fn try_from(mut wire: AutomationBudgetsFile) -> Result<Self, Self::Error> {
        if wire.workspaces.len() > 10_000 || wire.owners.len() > 10_000 {
            return Err(AutomationContractError::MalformedPayload);
        }
        let mut workspaces = BTreeSet::new();
        for scope in &mut wire.workspaces {
            if scope.deployment_id.as_str().is_empty()
                || scope.tenant_id.as_str().is_empty()
                || !workspaces.insert((scope.deployment_id.clone(), scope.tenant_id.clone()))
            {
                return Err(AutomationContractError::MalformedPayload);
            }
            validate_budget(&mut scope.budget)?;
        }
        let mut owners = BTreeSet::new();
        for scope in &mut wire.owners {
            if scope.deployment_id.as_str().is_empty()
                || scope.tenant_id.as_str().is_empty()
                || scope.owner_id.as_str().is_empty()
                || !owners.insert((
                    scope.deployment_id.clone(),
                    scope.tenant_id.clone(),
                    scope.owner_id.clone(),
                ))
            {
                return Err(AutomationContractError::MalformedPayload);
            }
            validate_budget(&mut scope.budget)?;
        }
        Ok(Self { wire })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input() -> AutomationConfigV1 {
        serde_json::from_value(json!({
            "schemaVersion":1,"title":"manual","botId":"bot","promptTemplate":"Check the input",
            "trigger":{"kind":"manual"},"modelPolicy":"bot_current",
            "permissionCeiling":{"toolIds":["browser.click"],"dataScopes":["source-one"]},
            "budget":[{"metric":"sampling_calls","totalLimit":"2"}],"runDeadlineSeconds":60
        }))
        .unwrap()
    }

    #[test]
    fn bounds_and_permissions_are_checked_once_at_admission() {
        let mut wire = input();
        wire.title = "界".repeat(128);
        let config = AutomationConfig::try_from(wire).unwrap();
        assert_eq!(config.tools()[0].as_str(), "browser.click");
        assert_eq!(config.data_scopes()[0].as_str(), "source-one");
        for count in [0, 129] {
            let mut wire = input();
            wire.title = "界".repeat(count);
            assert!(AutomationConfig::try_from(wire).is_err());
        }
        let mut too_large = input();
        too_large.prompt_template = "x".repeat(16 * 1024 + 1);
        assert_eq!(
            AutomationConfig::try_from(too_large),
            Err(AutomationContractError::PayloadTooLarge)
        );
        let mut wire = input();
        wire.permission_ceiling.tool_ids = vec!["*".to_owned()];
        assert!(AutomationConfig::try_from(wire).is_err());
        let mut wire = input();
        wire.permission_ceiling.data_scopes = vec!["*".to_owned()];
        assert!(AutomationConfig::try_from(wire).is_err());
        let mut wire = input();
        wire.permission_ceiling.tool_ids.clear();
        wire.permission_ceiling.data_scopes.clear();
        let config = AutomationConfig::try_from(wire).unwrap();
        assert!(config.tools().is_empty() && config.data_scopes().is_empty());
    }

    #[test]
    fn configured_budget_scopes_are_exact_and_finite() {
        let value = json!({"schemaVersion":1,"revision":1,
            "workspaces":[{"deploymentId":"dep","tenantId":"tenant","budget":[{"metric":"sampling_calls","totalLimit":"9"}]}],
            "owners":[{"deploymentId":"dep","tenantId":"tenant","ownerId":"owner","budget":[{"metric":"tool_calls","totalLimit":"4"}]}]
        });
        let wire: AutomationBudgetsFile = serde_json::from_value(value).unwrap();
        assert!(AutomationBudgets::try_from(wire.clone()).is_ok());
        let mut duplicate = wire.clone();
        duplicate.workspaces.push(duplicate.workspaces[0].clone());
        assert!(AutomationBudgets::try_from(duplicate).is_err());
        let mut duplicate = wire.clone();
        duplicate.owners.push(duplicate.owners[0].clone());
        assert!(AutomationBudgets::try_from(duplicate).is_err());
        let mut unbounded = wire.clone();
        unbounded.owners[0].budget[0].total_limit = None;
        assert!(AutomationBudgets::try_from(unbounded).is_err());
        let mut duplicate_metric = wire;
        let repeated = duplicate_metric.workspaces[0].budget[0].clone();
        duplicate_metric.workspaces[0].budget.push(repeated);
        assert!(AutomationBudgets::try_from(duplicate_metric).is_err());
    }

    #[test]
    fn budgets_require_unique_finite_metrics_and_exact_currency_roles() {
        let mut wire = input();
        wire.budget.push(wire.budget[0].clone());
        assert!(AutomationConfig::try_from(wire).is_err());
        let mut wire = input();
        wire.budget[0].total_limit = None;
        assert!(AutomationConfig::try_from(wire).is_err());
        let mut wire = input();
        wire.budget[0].currency = Some("USD".to_owned());
        assert!(AutomationConfig::try_from(wire).is_err());
        let mut wire = input();
        wire.budget[0].metric = AutomationBudgetMetric::MoneyMicrounits;
        assert!(AutomationConfig::try_from(wire.clone()).is_err());
        wire.budget[0].currency = Some("USD".to_owned());
        assert!(AutomationConfig::try_from(wire).is_ok());
    }
}
