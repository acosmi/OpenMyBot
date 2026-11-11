//! Sole application-owned automation management port and typed admission plans.

use async_trait::async_trait;
use openbot_contracts::{auth::AuthContext, automation::*, error::AppError};
use openbot_domain::automation::AutomationConfig;

/// Bounded keyset request after its one external admission.
#[derive(Clone, Debug)]
pub struct AutomationPageRequest {
    limit: u32,
    cursor: Option<String>,
}
impl AutomationPageRequest {
    /// Requested number of rows, already bounded to one through one hundred.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }
    /// Original opaque cursor; the store binds its decoded position to current owner scope.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}
impl TryFrom<AutomationPageQuery> for AutomationPageRequest {
    type Error = AppError;
    fn try_from(input: AutomationPageQuery) -> Result<Self, Self::Error> {
        let limit = input.limit.unwrap_or(20);
        if !(1..=100).contains(&limit) || input.cursor.as_ref().is_some_and(|v| v.len() > 512) {
            return Err(AppError::MalformedPayload { field: "query" });
        }
        Ok(Self {
            limit,
            cursor: input.cursor,
        })
    }
}

/// Immutable filter and bounded current-owner page intent.
#[derive(Clone, Debug)]
pub struct AutomationListRequest {
    /// Closed state filter; it never changes owner visibility.
    pub status: AutomationDefinitionFilter,
    /// Bounded original cursor/limit.
    pub page: AutomationPageRequest,
}
impl TryFrom<ListAutomationDefinitions> for AutomationListRequest {
    type Error = AppError;
    fn try_from(input: ListAutomationDefinitions) -> Result<Self, Self::Error> {
        Ok(Self {
            status: input.status.unwrap_or_default(),
            page: AutomationPageRequest::try_from(AutomationPageQuery {
                limit: input.limit,
                cursor: input.cursor,
            })?,
        })
    }
}

/// Validated owner mutation; only replace contains a newly parsed configuration.
#[derive(Clone, Debug)]
pub enum AutomationUpdate {
    /// Replace the same Bot's intent and pause it pending explicit new consent.
    Replace {
        /// Owner-observed current revision.
        expected_revision: AutomationRevision,
        /// Parsed exactly once at this application admission.
        config: Box<AutomationConfig>,
    },
    /// Enable or explicitly re-grant the current configuration.
    Enable {
        /// Owner-observed current revision.
        expected_revision: AutomationRevision,
        /// Explicit lifetime, whose deadline is checked against PG transaction time.
        grant_consent: AutomationGrantConsent,
    },
    /// End the unexecuted queue without revoking an active Run's grant.
    Pause {
        /// Owner-observed current revision.
        expected_revision: AutomationRevision,
    },
    /// Revoke authority and apply the existing cancellation/Unknown boundary.
    Revoke {
        /// Owner-observed current revision.
        expected_revision: AutomationRevision,
    },
}
impl TryFrom<UpdateAutomationDefinition> for AutomationUpdate {
    type Error = AppError;
    fn try_from(input: UpdateAutomationDefinition) -> Result<Self, Self::Error> {
        Ok(match input {
            UpdateAutomationDefinition::Replace {
                expected_revision,
                config,
            } => Self::Replace {
                expected_revision,
                config: Box::new(AutomationConfig::try_from(config)?),
            },
            UpdateAutomationDefinition::Enable {
                expected_revision,
                grant_consent,
            } => Self::Enable {
                expected_revision,
                grant_consent,
            },
            UpdateAutomationDefinition::Pause { expected_revision } => {
                Self::Pause { expected_revision }
            }
            UpdateAutomationDefinition::Revoke { expected_revision } => {
                Self::Revoke { expected_revision }
            }
        })
    }
}

/// Creation/replay are distinct internal facts, with the same public definition DTO.
#[derive(Clone, Debug)]
pub enum AutomationCreation {
    /// This transaction created revision one and its exclusive Thread.
    Created(AutomationDefinition),
    /// The exact original creation already committed.
    Replayed(AutomationDefinition),
}
/// Manual acceptance/replay never implies that a Run has started or completed.
#[derive(Clone, Debug)]
pub enum AutomationAcceptance {
    /// This transaction durably accepted the original manual intent.
    Accepted(AutomationReceipt),
    /// Exact original operation and revision, without additional capacity or work.
    Replayed(AutomationReceipt),
}

/// Same-PG definition and receipt storage; absent on hosts that do not own automation.
#[async_trait]
pub trait AutomationDefinitions: AutomationExecutionBudgets + Send + Sync {
    /// Current owner only; admin does not widen enumeration.
    async fn list(
        &self,
        auth: &AuthContext,
        input: AutomationListRequest,
    ) -> Result<AutomationDefinitionPage, AppError>;
    /// Create paused/revision one and its dedicated native Thread in the original transaction.
    async fn create(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        config: AutomationConfig,
    ) -> Result<AutomationCreation, AppError>;
    /// Read current owner/generation-scoped facts.
    async fn get(
        &self,
        auth: &AuthContext,
        id: AutomationId,
    ) -> Result<AutomationDefinition, AppError>;
    /// Persist one exact CAS mutation and its queue/grant consequences.
    async fn update(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        input: AutomationUpdate,
    ) -> Result<AutomationDefinition, AppError>;
    /// Retire permanently without removing durable idempotency or unknown usage.
    async fn tombstone(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        revision: AutomationRevision,
    ) -> Result<AutomationDefinition, AppError>;
    /// Current owner session is checked only at acceptance; dispatch uses the definition grant.
    async fn trigger(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        input: TriggerAutomationDefinition,
    ) -> Result<AutomationAcceptance, AppError>;
    /// Read real manual/cron/event occurrences.
    async fn occurrences(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        page: AutomationPageRequest,
    ) -> Result<AutomationOccurrencePage, AppError>;
    /// Read real external deliveries without source bodies.
    async fn deliveries(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        page: AutomationPageRequest,
    ) -> Result<AutomationDeliveryPage, AppError>;
    /// Resolve an original receipt under current owner visibility.
    async fn receipt(
        &self,
        auth: &AuthContext,
        id: AutomationReceiptId,
    ) -> Result<AutomationReceipt, AppError>;
    /// Create a sender-key receiver on an event definition without advancing its revision.
    async fn create_receiver(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        receiver: AutomationReceiverId,
        expected_revision: AutomationRevision,
        filter: AutomationEventFilter,
    ) -> Result<AutomationReceiverSecret, AppError>;
    /// Replace the current sender key; the previous key stops authenticating immediately.
    async fn rotate_receiver_key(
        &self,
        auth: &AuthContext,
        receiver: AutomationReceiverId,
        expected_key_revision: AutomationRevision,
    ) -> Result<AutomationReceiverSecret, AppError>;
    /// Revoke the receiver and its current key, keeping receipts and the key namespace.
    async fn revoke_receiver(
        &self,
        auth: &AuthContext,
        receiver: AutomationReceiverId,
        expected_key_revision: AutomationRevision,
    ) -> Result<AutomationReceiver, AppError>;
}

/// Same-PG source admission behind the Server ingress boundary; it carries no actor authority.
#[async_trait]
pub trait AutomationDeliveries: Send + Sync {
    /// Open the receiver's current Vault record and compare the presented key in constant time.
    async fn authenticate(
        &self,
        receiver: &AutomationReceiverId,
        presented: &openbot_domain::vault::SecretBytes,
    ) -> Result<AutomationRevision, AppError>;
    /// The acceptance transaction: recheck, replay, filter, window, limits and durable writes.
    async fn admit(
        &self,
        delivery: VerifiedAutomationDelivery,
    ) -> Result<AutomationIngressOutcome, AppError>;
    /// Count one content-free refusal for a known receiver; unknown receivers are not recorded.
    async fn record_refusal(
        &self,
        receiver: &AutomationReceiverId,
        reason: AutomationRefusalReason,
    ) -> Result<(), AppError>;
}

/// Third assembly output: Server holds Some, Desktop None. Not an `AppCommand`.
#[derive(Clone)]
pub struct AutomationDeliveryEntry {
    port: std::sync::Arc<dyn AutomationDeliveries>,
}
impl AutomationDeliveryEntry {
    /// Wrap the Server's same-PG admission port.
    #[must_use]
    pub fn new(port: std::sync::Arc<dyn AutomationDeliveries>) -> Self {
        Self { port }
    }
    /// Authenticate a sender key before any replay read.
    pub async fn authenticate(
        &self,
        receiver: &AutomationReceiverId,
        presented: &openbot_domain::vault::SecretBytes,
    ) -> Result<AutomationRevision, AppError> {
        self.port.authenticate(receiver, presented).await
    }
    /// Durably accept verified source input or return its original receipt.
    pub async fn accept(
        &self,
        delivery: VerifiedAutomationDelivery,
    ) -> Result<AutomationIngressOutcome, AppError> {
        self.port.admit(delivery).await
    }
    /// Count a refusal for a known receiver.
    pub async fn record_refusal(
        &self,
        receiver: &AutomationReceiverId,
        reason: AutomationRefusalReason,
    ) -> Result<(), AppError> {
        self.port.record_refusal(receiver, reason).await
    }
}

/// Same-PG durable queue used only by the application-owned background dispatcher.
#[async_trait]
pub trait AutomationDispatchQueue: Send + Sync {
    /// Expire original queue deadlines and converge revoked/expired active work without replay.
    async fn maintain(&self) -> Result<(), AppError>;
    /// One oldest unexecuted occurrence per enabled definition, bounded by workspace capacity.
    async fn pending(&self) -> Result<Vec<crate::BeginDelegatedThreadRun>, AppError>;
    /// Persist only an allowed pending reason or blocked state; a committed Run is never reverted.
    async fn deferred(
        &self,
        request: &crate::BeginDelegatedThreadRun,
        error: &AppError,
    ) -> Result<(), AppError>;
}

/// Polling is authoritative; notifications may only shorten the next scan delay.
#[derive(Clone)]
pub struct AutomationDispatcher {
    queue: std::sync::Arc<dyn AutomationDispatchQueue>,
    entry: crate::DelegatedRunEntry,
}
impl AutomationDispatcher {
    /// Reuse the original delegated entry instead of constructing a session or alternate runtime.
    #[must_use]
    pub fn new(
        queue: std::sync::Arc<dyn AutomationDispatchQueue>,
        entry: crate::DelegatedRunEntry,
    ) -> Self {
        Self { queue, entry }
    }
    /// Scan original durable state once; the host owns cancellation and the scheduling interval.
    pub async fn scan(&self) -> Result<usize, AppError> {
        self.queue.maintain().await?;
        let mut started = 0;
        for request in self.queue.pending().await? {
            match self.entry.begin(request.clone()).await {
                Ok(_) => started += 1,
                Err(error) => self.queue.deferred(&request, &error).await?,
            }
        }
        Ok(started)
    }
}

/// Existing Rust-minted control identities; arguments and external authority are absent.
#[derive(Clone, Debug)]
pub struct AutomationToolIdentity {
    /// Existing actual Run identity.
    pub run_id: openbot_contracts::ids::RunId,
    /// Existing durable control-plane call identity.
    pub call_id: openbot_contracts::ids::ToolCallId,
    /// Current authoritative Bot.
    pub bot_id: openbot_contracts::ids::BotId,
}

/// Execution consumers share the management adapter's original Pool and persisted grant facts.
#[async_trait]
pub trait AutomationExecutionBudgets: Send + Sync {
    /// Reserve one provider start. True permits one automation send; false leaves other Runs
    /// on their original path. A repeated uncertain attempt must not be sent again.
    async fn reserve_sampling(
        &self,
        lease: &crate::RunExecutionLease,
        index: u32,
    ) -> Result<bool, AppError>;
    /// Intersect frozen intents with the existing pipeline's resolved actual resource.
    async fn allows_tool(
        &self,
        auth: &AuthContext,
        scope: &crate::tool::ResolvedToolScope,
        metadata: &openbot_domain::tool::metadata::ToolMetadata,
    ) -> Result<bool, AppError>;
    /// Resolve the already-written real journal attempt and reserve before its original executor.
    async fn reserve_tool(
        &self,
        auth: &AuthContext,
        identity: &AutomationToolIdentity,
    ) -> Result<(), AppError>;
    /// Settle only after the original tool outcome journal has acknowledged its write.
    async fn settle_tool_outcome(
        &self,
        draft: &crate::tool::ToolOutcomeDraft,
    ) -> Result<(), AppError>;
}

mod tool;
pub(crate) use tool::invoke_automation_tool;
