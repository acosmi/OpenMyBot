//! Closed automation identities and cumulative-budget values (spec revision R485).

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use time::OffsetDateTime;

use crate::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};

/// An automation boundary value did not satisfy the registered contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AutomationContractError {
    /// A closed shape, identity or finite value was invalid.
    #[error("malformed_payload")]
    MalformedPayload,
    /// The registered template byte budget was exceeded.
    #[error("payload_too_large")]
    PayloadTooLarge,
}

/// The sole registered snapshot schema version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AutomationSchemaVersion;

impl Serialize for AutomationSchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for AutomationSchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self),
            _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
        }
    }
}

/// A positive PostgreSQL bigint revision, never a floating-point value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct AutomationRevision(i64);

impl AutomationRevision {
    /// Return the checked revision.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for AutomationRevision {
    type Error = AutomationContractError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 1 {
            return Err(AutomationContractError::MalformedPayload);
        }
        Ok(Self(value))
    }
}

impl From<AutomationRevision> for i64 {
    fn from(value: AutomationRevision) -> Self {
        value.0
    }
}

macro_rules! automation_ids {
    ($($(#[$doc:meta])* $name:ident),+ $(,)?) => {$(
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Borrow the identity already checked at its input boundary.
            #[must_use]
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl TryFrom<String> for $name {
            type Error = AutomationContractError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte|
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')) {
                    return Err(AutomationContractError::MalformedPayload);
                }
                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self { value.0 }
        }
    )+};
}

automation_ids! {
    /// A definition identity, scoped by deployment and tenant.
    AutomationId,
    /// One permanent receiver namespace.
    AutomationReceiverId,
    /// One manual operation identity, scoped to its definition.
    AutomationOperationId,
    /// One cumulative-budget attempt identity.
    AutomationAttemptId,
}

/// A finite nonnegative budget amount, kept outside JavaScript floating-point numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AutomationAmount(i64);

impl AutomationAmount {
    /// Parse the external decimal string once, without accepting a sign or a float.
    ///
    /// # Errors
    /// Returns an error for non-digits or values outside PostgreSQL's nonnegative bigint range.
    pub fn parse(value: &str) -> Result<Self, AutomationContractError> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AutomationContractError::MalformedPayload);
        }
        value
            .parse::<i64>()
            .map(Self)
            .map_err(|_| AutomationContractError::MalformedPayload)
    }

    /// Return the exact integer for a typed database write or budget comparison.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for AutomationAmount {
    type Error = AutomationContractError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            return Err(AutomationContractError::MalformedPayload);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for AutomationAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl Serialize for AutomationAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AutomationAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// One of the five registered cumulative-budget metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationBudgetMetric {
    /// Actual input and output tokens.
    Tokens,
    /// Provider sampling attempts.
    SamplingCalls,
    /// Tool attempts through the existing tool pipeline.
    ToolCalls,
    /// Metered compute time.
    ComputeMillis,
    /// Whole micro currency units from an authoritative price card.
    MoneyMicrounits,
}

impl<'de> Deserialize<'de> for AutomationBudgetMetric {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "tokens" => Ok(Self::Tokens),
            "sampling_calls" => Ok(Self::SamplingCalls),
            "tool_calls" => Ok(Self::ToolCalls),
            "compute_millis" => Ok(Self::ComputeMillis),
            "money_microunits" => Ok(Self::MoneyMicrounits),
            _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
        }
    }
}

/// A definition's persisted lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationDefinitionState {
    /// No new occurrence may be accepted or dispatched.
    Paused,
    /// Current authority and capacity still govern each operation.
    Enabled,
    /// The namespace is permanently retired, while receipts remain readable.
    Tombstoned,
}

impl<'de> Deserialize<'de> for AutomationDefinitionState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "paused" => Ok(Self::Paused),
            "enabled" => Ok(Self::Enabled),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
        }
    }
}

/// The seven occurrence states; these do not extend Run status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationOccurrenceState {
    /// Waiting for the same definition and dedicated Thread.
    Pending,
    /// Durable input lacks its required cumulative budget.
    BlockedBudget,
    /// Durable input lacks its required current Bot model.
    BlockedModel,
    /// Exactly one Run was associated in the original begin transaction.
    RunCreated,
    /// A newer revision replaced this unexecuted intent.
    Superseded,
    /// Pause or tombstone ended the unexecuted intent.
    TerminatedByPause,
    /// Its original 24-hour acceptance window elapsed.
    Expired,
}

impl<'de> Deserialize<'de> for AutomationOccurrenceState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "pending" => Ok(Self::Pending),
            "blocked_budget" => Ok(Self::BlockedBudget),
            "blocked_model" => Ok(Self::BlockedModel),
            "run_created" => Ok(Self::RunCreated),
            "superseded" => Ok(Self::Superseded),
            "terminated_by_pause" => Ok(Self::TerminatedByPause),
            "expired" => Ok(Self::Expired),
            _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
        }
    }
}

/// The first automation cut uses only the Bot's current authoritative model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationModelPolicy {
    /// No transport-supplied v2 model selection is accepted.
    BotCurrent,
}

impl<'de> Deserialize<'de> for AutomationModelPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "bot_current" => Ok(Self::BotCurrent),
            _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
        }
    }
}

/// Closed trigger configuration; enabling still requires its delivered consumer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutomationTrigger {
    /// Current-owner manual acceptance.
    Manual {},
    /// Five-field cron and an IANA time zone, consumed only after the cron task is delivered.
    Cron {
        /// The registered five-field expression.
        expression: String,
        /// IANA time-zone identity.
        timezone: String,
        /// Whether the latest eligible missed slot may be caught up.
        #[serde(rename = "catchUpLatest")]
        catch_up_latest: bool,
    },
    /// Source input is bound to a separately authenticated receiver.
    Event {},
}

/// Permission resource intents, resolved to the existing authorized resource types at admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationPermissionCeiling {
    /// Explicit tool resource identities; empty grants no tool authority.
    pub tool_ids: Vec<String>,
    /// Explicit data resource scopes; empty grants no data authority.
    pub data_scopes: Vec<String>,
}

/// One fixed UTC budget window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationBudgetWindow {
    /// Fixed origin; admission checks the registered UTC/window limits once.
    #[serde(with = "time::serde::rfc3339")]
    pub origin: OffsetDateTime,
    /// Fixed duration in whole seconds.
    pub seconds: u64,
    /// Finite window quota.
    pub limit: AutomationAmount,
}

// Optional fields may be absent, but an explicitly present null is not a budget value.
fn present_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A finite per-metric definition budget; policy admission checks the metric/currency relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationBudgetRule {
    /// One metric, unique within the enclosing budget.
    pub metric: AutomationBudgetMetric,
    /// An optional fixed-window quota.
    #[serde(
        default,
        deserialize_with = "present_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub window: Option<AutomationBudgetWindow>,
    /// An optional permanent total quota.
    #[serde(
        default,
        deserialize_with = "present_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_limit: Option<AutomationAmount>,
    /// Authoritative monetary unit, accepted only for the money metric.
    #[serde(
        default,
        deserialize_with = "present_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub currency: Option<String>,
}

/// Closed definition intent. Resource, text and collection bounds are checked at admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationConfigV1 {
    /// Exactly version one.
    pub schema_version: AutomationSchemaVersion,
    /// Human-readable title.
    pub title: String,
    /// Existing Bot identity; a replacement cannot change it.
    pub bot_id: BotId,
    /// Owner-controlled instructions, separate from any future source data.
    pub prompt_template: String,
    /// Registered trigger intent.
    pub trigger: AutomationTrigger,
    /// Only the current Bot model is allowed.
    pub model_policy: AutomationModelPolicy,
    /// Explicit permissions intersected with current owner/Bot authority on every use.
    pub permission_ceiling: AutomationPermissionCeiling,
    /// One to five distinct finite metric budgets.
    pub budget: Vec<AutomationBudgetRule>,
    /// Explicit deadline, narrowed to the registered 1–1800-second range at admission.
    pub run_deadline_seconds: u64,
}

/// Explicit grant lifetime; a session or OS consent never supplies a default here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutomationGrantValidity {
    /// Retained until a real revocation or authentication-generation change.
    UntilRevoked {},
    /// Explicit future expiration, compared against PostgreSQL transaction time.
    Expires {
        /// Owner-selected expiration.
        #[serde(rename = "expiresAt", with = "time::serde::rfc3339")]
        expires_at: OffsetDateTime,
    },
}

/// Fresh-session enable consent, distinct from the frozen server-derived delegation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationGrantConsent {
    /// No implicit continuing authorization.
    pub validity: AutomationGrantValidity,
}

/// Frozen server-derived delegation facts, not a caller-created execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationDelegationV1 {
    /// The registered persisted snapshot schema.
    pub schema_version: AutomationSchemaVersion,
    /// Current owner at explicit grant admission.
    pub owner_id: ActorId,
    /// Server-derived deployment.
    pub deployment_id: DeploymentId,
    /// Server-derived tenant.
    pub tenant_id: TenantId,
    /// The definition's immutable Bot.
    pub bot_id: BotId,
    /// The definition's exclusive DirectBot Thread.
    pub thread_id: ThreadId,
    /// Exact immutable definition revision.
    pub definition_revision: AutomationRevision,
    /// Explicit tool ceiling, intersected with current authority on execution.
    pub tool_ids: Vec<String>,
    /// Explicit data ceiling, never an independent grant.
    pub data_scopes: Vec<String>,
    /// Frozen definition budget policy revision.
    pub budget_policy_revision: AutomationRevision,
    /// Generation observed in the original grant transaction.
    pub auth_generation: i64,
    /// Explicit continuing or expiring authorization.
    pub validity: AutomationGrantValidity,
    /// The same revision's prompt template.
    pub template: String,
    /// The same revision's bounded Run deadline.
    pub run_deadline_seconds: u16,
}

/// Stable manual receipt intent; actor and generation are filled by the admission transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriggerAutomationDefinition {
    /// Idempotency identity within this definition.
    pub operation_id: AutomationOperationId,
    /// Owner-observed current definition revision.
    pub expected_revision: AutomationRevision,
}

/// Owner create request; scope and dedicated Thread identity are server-derived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAutomationDefinition {
    /// Client operation's stable definition identity.
    pub automation_id: AutomationId,
    /// Immutable initial intent for revision one and idempotent retries.
    pub config: AutomationConfigV1,
}

/// Closed CAS actions; each accepted action creates a new definition revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpdateAutomationDefinition {
    /// Replace the intent and revoke any enabled grant before requiring new consent.
    Replace {
        /// Current revision observed by the owner.
        #[serde(rename = "expectedRevision")]
        expected_revision: AutomationRevision,
        /// Replacement for the same Bot.
        config: AutomationConfigV1,
    },
    /// Enable or explicitly re-grant, under the current fresh session.
    Enable {
        /// Current revision observed by the owner.
        #[serde(rename = "expectedRevision")]
        expected_revision: AutomationRevision,
        /// Explicit continuing or expiring consent.
        #[serde(rename = "grantConsent")]
        grant_consent: AutomationGrantConsent,
    },
    /// End unexecuted occurrences without revoking the active Run's grant.
    Pause {
        /// Current revision observed by the owner.
        #[serde(rename = "expectedRevision")]
        expected_revision: AutomationRevision,
    },
    /// Revoke authority and request the existing stop-confirmation flow.
    Revoke {
        /// Current revision observed by the owner.
        #[serde(rename = "expectedRevision")]
        expected_revision: AutomationRevision,
    },
}

/// Retire a definition namespace without deleting its receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TombstoneAutomationDefinition {
    /// Current revision observed by the owner.
    pub expected_revision: AutomationRevision,
}

/// One configured workspace ceiling; the scope is supplied by the trusted startup file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationWorkspaceBudget {
    /// Exact deployment identity.
    pub deployment_id: DeploymentId,
    /// Exact tenant identity.
    pub tenant_id: TenantId,
    /// Distinct finite metrics, validated once at startup admission.
    pub budget: Vec<AutomationBudgetRule>,
}

/// One configured owner ceiling within an exact workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationOwnerBudget {
    /// Exact deployment identity.
    pub deployment_id: DeploymentId,
    /// Exact tenant identity.
    pub tenant_id: TenantId,
    /// Real owner identity; no role or session is supplied by this file.
    pub owner_id: ActorId,
    /// Distinct finite metrics, validated once at startup admission.
    pub budget: Vec<AutomationBudgetRule>,
}

/// Closed startup snapshot for the owner and workspace cumulative ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationBudgetsFile {
    /// Exactly the registered schema version one.
    pub schema_version: AutomationSchemaVersion,
    /// Monotonic configuration revision; startup cannot regress persisted policy.
    pub revision: AutomationRevision,
    /// At most ten thousand unique workspace policies.
    pub workspaces: Vec<AutomationWorkspaceBudget>,
    /// At most ten thousand unique scoped owner policies.
    pub owners: Vec<AutomationOwnerBudget>,
}

/// Current-owner definition list filter; it never changes visibility.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AutomationDefinitionFilter {
    /// Paused and enabled definitions; the default.
    #[default]
    Active,
    /// Enabled definitions only.
    Enabled,
    /// Paused definitions only.
    Paused,
    /// Retired namespaces only.
    Tombstoned,
    /// Every visible state, including retired namespaces.
    All,
}

impl AutomationDefinitionFilter {
    /// Stable query spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Tombstoned => "tombstoned",
            Self::All => "all",
        }
    }
}

impl TryFrom<String> for AutomationDefinitionFilter {
    type Error = AutomationContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "active" => Ok(Self::Active),
            "enabled" => Ok(Self::Enabled),
            "paused" => Ok(Self::Paused),
            "tombstoned" => Ok(Self::Tombstoned),
            "all" => Ok(Self::All),
            _ => Err(AutomationContractError::MalformedPayload),
        }
    }
}

impl From<AutomationDefinitionFilter> for String {
    fn from(value: AutomationDefinitionFilter) -> Self {
        value.as_str().to_owned()
    }
}

/// Closed owner-scoped keyset list input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListAutomationDefinitions {
    /// Omission selects active definitions.
    pub status: Option<AutomationDefinitionFilter>,
    /// Opaque cursor bound to the current owner, workspace and filter.
    pub cursor: Option<String>,
    /// One through one hundred; omission selects twenty.
    pub limit: Option<u32>,
}

/// Closed keyset input shared by occurrence and external-delivery reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationPageQuery {
    /// Opaque scoped cursor, at most 512 bytes at admission.
    pub cursor: Option<String>,
    /// One through one hundred; omission selects twenty.
    pub limit: Option<u32>,
}

/// A receipt identity whose prefix locates a delivery or occurrence without granting access.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AutomationReceiptId(String);

impl AutomationReceiptId {
    /// Borrow the already checked receipt identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for AutomationReceiptId {
    type Error = AutomationContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > 128
            || !(value.starts_with("adel:") || value.starts_with("aocc:"))
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        {
            return Err(AutomationContractError::MalformedPayload);
        }
        Ok(Self(value))
    }
}
impl From<AutomationReceiptId> for String {
    fn from(value: AutomationReceiptId) -> Self {
        value.0
    }
}

// These closed string families share exact SQL/JSON spelling and reject object forms.
macro_rules! closed_strings {
    ($(#[$doc:meta])* $name:ident { $($(#[$item_doc:meta])* $variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name { $($(#[$item_doc])* $variant),+ }
        impl $name {
            /// Stable database and JSON spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> { s.serialize_str(self.as_str()) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self,D::Error> {
                match String::deserialize(d)?.as_str() {
                    $($wire => Ok(Self::$variant)),+,
                    _ => Err(de::Error::custom(AutomationContractError::MalformedPayload)),
                }
            }
        }
    };
}

closed_strings! {
    /// One of the three intersected cumulative scopes.
    AutomationBudgetScope {
        /// Real current owner within its workspace.
        Owner => "owner",
        /// The deployment and tenant pair.
        Workspace => "workspace",
        /// The immutable definition namespace.
        Automation => "automation",
    }
}
closed_strings! {
    /// Accepted input source; source content never becomes authority.
    AutomationTriggerKind {
        /// Current-owner manual intent.
        Manual => "manual",
        /// A registered UTC slot.
        Cron => "cron",
        /// A verified external delivery.
        Event => "event",
    }
}
closed_strings! {
    /// Closed delivery outcomes, all terminal at durable receipt creation.
    AutomationDeliveryStatus {
        /// An accepted execution input.
        Accepted => "accepted",
        /// A verified source probe without an occurrence.
        VerificationOnly => "verification_only",
        /// A source alias of one original logical delivery.
        Alias => "alias",
    }
}
closed_strings! {
    /// Registered occurrence reasons; these do not extend Run status.
    AutomationOccurrenceReason {
        /// The dedicated Thread is occupied.
        ThreadBusy => "thread_busy",
        /// The existing effect requires reconciliation.
        ReconciliationRequired => "reconciliation_required",
        /// Its persisted delegation is no longer current.
        AuthorityUnavailable => "authority_unavailable",
        /// A finite cumulative ceiling cannot admit execution.
        BudgetExceeded => "automation_budget_exceeded",
        /// The current Bot model cannot be used.
        ModelUnavailable => "automation_model_unavailable",
        /// A newer definition revision superseded this unexecuted intent.
        RevisionSuperseded => "automation_revision_superseded",
        /// Pause terminated the unexecuted queue.
        Paused => "automation_paused",
        /// Retirement terminated the unexecuted queue.
        Tombstoned => "automation_tombstoned",
        /// The original acceptance window ended.
        QueueExpired => "automation_queue_expired",
    }
}

/// Current validity projection, without any token, session or grant authority snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationGrantProjection {
    /// Last explicit grant revision, absent before the first enable.
    pub revision: Option<AutomationRevision>,
    /// Current owner/generation, revocation and expiration all permit the grant.
    pub valid: bool,
    /// Explicit expiry; null means no expiry or no grant, distinguished by revision.
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// One finite current policy bucket with exact integer accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationBudgetProjection {
    /// The charged cumulative scope.
    pub scope: AutomationBudgetScope,
    /// Exact scope identity; workspace uses the fixed identity workspace.
    pub scope_id: String,
    /// Immutable policy revision.
    pub policy_revision: AutomationRevision,
    /// The finite metric this bucket constrains.
    pub metric: AutomationBudgetMetric,
    /// Original fixed window start or the permanent epoch bucket.
    #[serde(with = "time::serde::rfc3339")]
    pub bucket_start: OffsetDateTime,
    /// Distinguishes permanent totals from a fixed time window.
    pub is_total: bool,
    /// Finite exact quota.
    pub limit: AutomationAmount,
    /// Known settled consumption, never a floating-point currency value.
    pub used: AutomationAmount,
    /// Outstanding upper-bound reservations, including unknown usage.
    pub reserved: AutomationAmount,
    /// Attested currency unit only for the money metric.
    pub currency: Option<String>,
}

closed_strings! {
    /// The only registered unavailable timezone reason.
    AutomationTimezoneUnavailableReason {
        /// The configured IANA identity is absent from the actual timezone database.
        TimezoneUnavailable => "timezone_unavailable",
    }
}

/// Runtime timezone facts, without changing the accepted definition intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationTimezoneSnapshot {
    /// Configured IANA identity.
    pub timezone_id: String,
    /// Actually used timezone database revision.
    pub tzdb_version: String,
    /// Present only when the configured timezone is unavailable.
    pub unavailable_reason: Option<AutomationTimezoneUnavailableReason>,
}

/// Owner-visible current definition, containing no credentials or authority token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationDefinition {
    /// Permanent definition namespace.
    pub id: AutomationId,
    /// Current immutable revision.
    pub revision: AutomationRevision,
    /// Current lifecycle state.
    pub state: AutomationDefinitionState,
    /// Current closed intent snapshot.
    pub config: AutomationConfigV1,
    /// Its one dedicated native Thread.
    pub thread_id: ThreadId,
    /// Current authorization validity facts.
    pub grant: AutomationGrantProjection,
    /// Exact current policy usage and outstanding reservations.
    pub budget: Vec<AutomationBudgetProjection>,
    /// Unknown monetary pricing is explicit, never represented as zero money.
    pub unpriced: bool,
    /// Latest accepted occurrence, if any.
    pub latest_occurrence_id: Option<AutomationReceiptId>,
    /// Latest real associated Run, if any.
    pub latest_run_id: Option<crate::ids::RunId>,
    /// Runtime cron facts, absent before that consumer is delivered.
    pub timezone: Option<AutomationTimezoneSnapshot>,
    /// Original PG creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Current PG revision time, also used by list keysets.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Current-owner definition page in descending updatedAt/id order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationDefinitionPage {
    /// Visible definitions only.
    pub items: Vec<AutomationDefinition>,
    /// An opaque cursor bound to the original caller, workspace and filter.
    pub next_cursor: Option<String>,
}

closed_strings! {
    /// Existing Run states, without adding any automation-specific Run status.
    AutomationRunStatus {
        /// Accepted but not executing.
        Queued => "queued",
        /// Existing executing Run.
        Running => "running",
        /// Definite successful terminal.
        Completed => "completed",
        /// Definite failed terminal.
        Failed => "failed",
        /// Cancellation confirmed by the original runtime.
        Cancelled => "cancelled",
        /// Unknown external effects keep foreground occupancy.
        ReconciliationRequired => "reconciliation_required",
    }
}

/// Closed receipt origin; a sender's identity never becomes a user actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutomationReceiptSource {
    /// Current-owner intent accepted at the manual boundary.
    Manual {
        /// Original operation identity, retained across retries.
        #[serde(rename = "operationId")]
        operation_id: AutomationOperationId,
    },
    /// One accepted UTC slot.
    Cron {
        /// Original scheduled UTC instant.
        #[serde(rename = "plannedAt", with = "time::serde::rfc3339")]
        planned_at: OffsetDateTime,
    },
    /// Authenticated external source namespace and event.
    Event {
        /// Fixed receiver namespace.
        #[serde(rename = "receiverId")]
        receiver_id: AutomationReceiverId,
        /// Source key, never interpreted as an actor or tool.
        #[serde(rename = "eventId")]
        event_id: AutomationOperationId,
    },
}

/// Content-free occurrence projection; Run results come only from existing terminal events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationOccurrence {
    /// Stable aocc identity.
    pub id: AutomationReceiptId,
    /// Closed occurrence lifecycle, distinct from Run status.
    pub state: AutomationOccurrenceState,
    /// Registered reason, null for pending without a reason and run_created.
    pub reason_code: Option<AutomationOccurrenceReason>,
    /// Original twenty-four-hour queue deadline.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The definition's sole dedicated Thread.
    pub thread_id: ThreadId,
    /// Real Run association, absent until the begin transaction commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<crate::ids::RunId>,
    /// Existing six-valued Run status, absent before a Run exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_status: Option<AutomationRunStatus>,
    /// Existing terminal result message identity; no synthetic result is created here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
}

/// Exact receipt projection for manual, cron and external accepted input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationReceipt {
    /// The exact identity queried or returned by acceptance.
    pub receipt_id: AutomationReceiptId,
    /// Owning definition.
    pub automation_id: AutomationId,
    /// Definition revision frozen when accepted.
    pub definition_revision: AutomationRevision,
    /// Original source metadata without body or authority.
    pub source: AutomationReceiptSource,
    /// Manual and cron always project accepted, without manufacturing a Delivery row.
    pub status: AutomationDeliveryStatus,
    /// Original trusted PG receipt time.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    /// Present only when the accepted receipt has an occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<AutomationOccurrence>,
    /// Canonical original receipt for an alias only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<AutomationReceiptId>,
    /// Whether a previously retained external body was actually cleared.
    pub data_cleared: bool,
}

/// Current-owner occurrence keyset page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationOccurrencePage {
    /// Durable occurrence projections only.
    pub items: Vec<AutomationOccurrence>,
    /// Opaque cursor for the same definition and owner.
    pub next_cursor: Option<String>,
}

/// Current-owner external-delivery keyset page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AutomationDeliveryPage {
    /// Only actual external deliveries, never manual or cron aliases.
    pub items: Vec<AutomationReceipt>,
    /// Opaque cursor for the same definition and owner.
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receipt_projection_matches_the_closed_origin_and_result_contract() {
        let value = json!({
            "receiptId":"aocc:one","automationId":"automation","definitionRevision":1,
            "source":{"kind":"manual","operationId":"manual:one"},"status":"accepted",
            "receivedAt":"2026-11-08T00:00:00Z","dataCleared":false,
            "occurrence":{"id":"aocc:one","state":"run_created","reasonCode":null,
                "expiresAt":"2026-11-09T00:00:00Z","threadId":"thread","runId":"run",
                "runStatus":"failed","resultRef":"run:assistant"}
        });
        let receipt: AutomationReceipt = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&receipt).unwrap(), value);
        for field in [
            "threadId",
            "delivery",
            "actorId",
            "normalizedData",
            "session",
        ] {
            let mut unknown = value.clone();
            unknown[field] = json!("unregistered");
            assert!(
                serde_json::from_value::<AutomationReceipt>(unknown).is_err(),
                "{field}"
            );
        }
        for status in [
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            "reconciliation_required",
        ] {
            let mut current = value.clone();
            current["occurrence"]["runStatus"] = json!(status);
            assert!(serde_json::from_value::<AutomationReceipt>(current).is_ok());
        }
        let mut blocked = value;
        blocked["occurrence"]["runStatus"] = json!("blocked_budget");
        assert!(serde_json::from_value::<AutomationReceipt>(blocked).is_err());
    }

    #[test]
    fn closed_config_and_integer_amounts() {
        assert!(serde_json::from_value::<AutomationBudgetMetric>(json!({"tokens":null})).is_err());
        assert!(
            serde_json::from_value::<AutomationModelPolicy>(json!({"bot_current":null})).is_err()
        );
        for digits in ["0", "9007199254740993", "9223372036854775807"] {
            let amount: AutomationAmount = serde_json::from_value(json!(digits)).unwrap();
            assert_eq!(serde_json::to_value(amount).unwrap(), json!(digits));
        }
        for value in [
            json!(1),
            json!(-1),
            json!(1.5),
            json!("-1"),
            json!("1.0"),
            json!("9223372036854775808"),
            json!(null),
        ] {
            assert!(serde_json::from_value::<AutomationAmount>(value).is_err());
        }
        let config = json!({
            "schemaVersion":1,"title":"manual","botId":"bot","promptTemplate":"Check the input",
            "trigger":{"kind":"manual"},"modelPolicy":"bot_current",
            "permissionCeiling":{"toolIds":[],"dataScopes":[]},
            "budget":[{"metric":"sampling_calls","totalLimit":"0"}],"runDeadlineSeconds":1
        });
        assert!(serde_json::from_value::<AutomationConfigV1>(config.clone()).is_ok());
        for (field, value) in [
            ("schemaVersion", json!(2)),
            ("modelPolicy", json!("custom")),
            ("ownerId", json!("attacker")),
        ] {
            let mut changed = config.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<AutomationConfigV1>(changed).is_err());
        }
        for field in ["window", "totalLimit", "currency"] {
            let mut changed = config.clone();
            changed["budget"][0][field] = json!(null);
            assert!(serde_json::from_value::<AutomationConfigV1>(changed).is_err());
        }
    }

    #[test]
    fn startup_budget_and_list_inputs_reject_unknown_authority() {
        let value = json!({"schemaVersion":1,"revision":1,"workspaces":[],"owners":[]});
        assert!(serde_json::from_value::<AutomationBudgetsFile>(value.clone()).is_ok());
        let mut forged = value;
        forged["session"] = json!("caller-session");
        assert!(serde_json::from_value::<AutomationBudgetsFile>(forged).is_err());
        assert!(serde_json::from_value::<AutomationDefinitionFilter>(json!({"all":null})).is_err());
        assert!(
            serde_json::from_value::<ListAutomationDefinitions>(
                json!({"status":"all","ownerId":"other"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<AutomationPageQuery>(json!({"status":"all"})).is_err());
    }

    #[test]
    fn manual_intent_and_grant_consent_are_closed() {
        assert!(serde_json::from_value::<AutomationTrigger>(json!({"kind":"manual"})).is_ok());
        assert!(
            serde_json::from_value::<AutomationTrigger>(json!({"kind":"manual","data":{}}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<AutomationGrantConsent>(
                json!({"validity":{"kind":"until_revoked"}})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<AutomationGrantConsent>(
                json!({"validity":{"kind":"until_revoked"},"session":"token"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<AutomationGrantConsent>(
                json!({"validity":{"kind":"until_revoked","expiresAt":"2030-01-01T00:00:00Z"}})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<AutomationGrantConsent>(json!({})).is_err());
        assert!(
            serde_json::from_value::<TriggerAutomationDefinition>(json!({
                "operationId":"manual:1","expectedRevision":1
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<TriggerAutomationDefinition>(json!({
                "operationId":"manual:1","expectedRevision":1,"actorId":"attacker"
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<AutomationRevision>(json!(0)).is_err());
        assert!(serde_json::from_value::<AutomationRevision>(json!(1.5)).is_err());
        assert!(serde_json::from_value::<UpdateAutomationDefinition>(json!({"action":"pause","expectedRevision":1,"grantConsent":{"validity":{"kind":"until_revoked"}}})).is_err());
    }
}
