//! §8.1 唯一工具管线的 application 编排与出向端口。

use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use openbot_contracts::auth::{AuthContext, AuthGeneration};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{
    ActorId, BotId, CapabilityId, CatalogGeneration, ComputerGeneration, DocumentGeneration, RunId,
    TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::tool::{ToolCommitState, ToolInvocation, ToolResult};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::policy::{PolicyContext, PolicyDecision};
use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
use openbot_domain::tool::args::{ToolArguments, ToolArgumentsError};
use openbot_domain::tool::commit::{CommitState, IdempotencyKey};
use openbot_domain::tool::metadata::{ApprovalClass, Effect, ToolMetadata, ToolName};
use openbot_domain::tool::pipeline::{
    AbortReason, ApprovalOutcome, ApprovalSettled, AuthoritativeActor, DecisionWriteFailed,
    DurableDecisionReceipt, OutcomeWriteFailed, PolicyRuleId, PolicyVerdict, RedeemedCapability,
    RefusalReason, Requested, RequestedToolCall, SingleUseCapability, ToolCallTerminal,
    ToolOutcome, ValidationRejection,
};
use tokio::sync::watch;

/// Tool port 的封闭失败分类；不携带 vendor/数据库原文。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolPortError {
    /// 依赖不可用。
    #[error("tool_port_unavailable dependency={dependency}")]
    Unavailable {
        /// 静态依赖名。
        dependency: &'static str,
    },
    /// tool/run/bot 对当前 actor 不可见。
    #[error("tool_scope_not_visible")]
    NotVisible,
    /// 权威 catalog/scope 数据损坏。
    #[error("tool_port_corrupt field={field}")]
    Corrupt {
        /// 静态字段名。
        field: &'static str,
    },
    /// Arguments failed a first-party schema/shape validation before any acting decision.
    #[error("tool_input_invalid field={field}")]
    InvalidInput {
        /// Static field name.
        field: &'static str,
    },
    /// journal CAS 没命中或发生并发冲突。
    #[error("tool_journal_conflict")]
    Conflict,
    /// Approval/request mutation commit result is unknown; no tool effect may start.
    #[error("tool_port_commit_unknown")]
    CommitUnknown,
}

/// Cross-replica run-local tool-sequence allocation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolCallSequenceError {
    /// Durable allocator or active run is unavailable.
    #[error("tool_call_sequence_unavailable")]
    Unavailable,
    /// The signed 64-bit PostgreSQL sequence space has been exhausted.
    #[error("tool_call_sequence_exhausted")]
    Exhausted,
}

/// Durable allocator for the control identity of Agent-originated tool calls.
#[async_trait]
pub trait ToolCallSequence: Send + Sync {
    /// Atomically allocate the next run-local sequence across all Server replicas.
    async fn next(&self, run: &RunId) -> Result<u64, ToolCallSequenceError>;

    /// Release implementation-local state after terminal cleanup; durable implementations no-op.
    fn release(&self, _run: &RunId) {}
}

/// Stable host reason propagated to an already-authorized tool effect.
///
/// This enum is deliberately not serde. A transport, model, renderer, or remote Agent cannot
/// manufacture cancellation authority; only the Rust run host owns the sender half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolCancellationReason {
    /// The authoritative actor requested cancellation through the run control plane.
    User,
    /// The Rust-owned absolute run deadline elapsed.
    Deadline,
    /// The host could no longer renew the authoritative execution lease.
    LeaseLost,
    /// The Rust host disappeared without publishing a more specific reason.
    HostDropped,
}

impl ToolCancellationReason {
    /// Stable protocol-safe reason; never contains user or vendor prose.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::User => "run_cancelled",
            Self::Deadline => "run_deadline_exceeded",
            Self::LeaseLost => "run_lease_lost",
            Self::HostDropped => "run_host_dropped",
        }
    }
}

/// Rust-host-only sender for one tool invocation's cancellation signal.
#[derive(Clone)]
pub struct ToolCancellationHandle {
    sender: watch::Sender<Option<ToolCancellationReason>>,
}

impl ToolCancellationHandle {
    /// Publish the first cancellation reason exactly once. Later races cannot rewrite it.
    pub fn cancel(&self, reason: ToolCancellationReason) -> bool {
        self.sender.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason);
                true
            }
        })
    }
}

impl fmt::Debug for ToolCancellationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCancellationHandle")
            .field("requested", &self.sender.borrow().is_some())
            .finish()
    }
}

/// Private receiver made available only to the exact Rust-minted tool call while it executes.
#[derive(Clone)]
pub struct ToolExecutionCancellation {
    receiver: watch::Receiver<Option<ToolCancellationReason>>,
}

impl ToolExecutionCancellation {
    /// Return an already-published reason without waiting.
    #[must_use]
    pub fn requested(&self) -> Option<ToolCancellationReason> {
        *self.receiver.borrow()
    }

    /// Wait for cancellation. Losing the only sender fails closed as `HostDropped`.
    pub async fn cancelled(&mut self) -> ToolCancellationReason {
        loop {
            if let Some(reason) = *self.receiver.borrow_and_update() {
                return reason;
            }
            if self.receiver.changed().await.is_err() {
                return ToolCancellationReason::HostDropped;
            }
        }
    }
}

impl fmt::Debug for ToolExecutionCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutionCancellation")
            .field("requested", &self.requested().is_some())
            .finish()
    }
}

/// Create one private host→executor cancellation channel.
#[must_use]
pub fn tool_execution_cancellation() -> (ToolCancellationHandle, ToolExecutionCancellation) {
    let (sender, receiver) = watch::channel(None);
    (
        ToolCancellationHandle { sender },
        ToolExecutionCancellation { receiver },
    )
}

struct ToolCancellationRegistryInner {
    next_registration: AtomicU64,
    entries: Mutex<HashMap<ToolCallId, (u64, ToolExecutionCancellation)>>,
}

/// Process-local bridge between the Agent-owned run signal and the exact application tool call.
///
/// Lookup is by the Rust-minted [`ToolCallId`]. External callers may serialize the same DTO field,
/// but cannot insert a receiver into this registry, so the value never grants cancellation
/// authority. Server and Desktop assembly must share one instance between the Agent gateway and
/// the production tool control plane.
#[derive(Clone)]
pub struct ToolCancellationRegistry {
    inner: Arc<ToolCancellationRegistryInner>,
}

impl Default for ToolCancellationRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(ToolCancellationRegistryInner {
                next_registration: AtomicU64::new(1),
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl ToolCancellationRegistry {
    /// Register one receiver for one Rust-minted call. Duplicate IDs and counter exhaustion fail.
    pub fn register(
        &self,
        call_id: ToolCallId,
        cancellation: ToolExecutionCancellation,
    ) -> Option<ToolCancellationRegistration> {
        let registration = self
            .inner
            .next_registration
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?;
        let mut entries = self.inner.entries.lock().ok()?;
        if entries.contains_key(&call_id) {
            return None;
        }
        entries.insert(call_id.clone(), (registration, cancellation));
        Some(ToolCancellationRegistration {
            inner: Arc::downgrade(&self.inner),
            call_id,
            registration,
        })
    }

    /// Clone the receiver for the exact active call, or return `None` for external/unregistered IDs.
    #[must_use]
    pub fn cancellation_for(&self, call_id: &ToolCallId) -> Option<ToolExecutionCancellation> {
        self.inner
            .entries
            .lock()
            .ok()?
            .get(call_id)
            .map(|(_, cancellation)| cancellation.clone())
    }
}

impl fmt::Debug for ToolCancellationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCancellationRegistry")
            .field(
                "active",
                &self
                    .inner
                    .entries
                    .lock()
                    .map_or(usize::MAX, |entries| entries.len()),
            )
            .finish()
    }
}

/// RAII registration removed when the local application invocation completes or is dropped.
pub struct ToolCancellationRegistration {
    inner: Weak<ToolCancellationRegistryInner>,
    call_id: ToolCallId,
    registration: u64,
}

impl Drop for ToolCancellationRegistration {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let Ok(mut entries) = inner.entries.lock() else {
            return;
        };
        if entries
            .get(&self.call_id)
            .is_some_and(|(registration, _)| *registration == self.registration)
        {
            entries.remove(&self.call_id);
        }
    }
}

impl fmt::Debug for ToolCancellationRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCancellationRegistration")
            .field("call_id", &self.call_id)
            .finish_non_exhaustive()
    }
}

impl ToolPortError {
    const fn into_app_error(self) -> AppError {
        match self {
            Self::NotVisible => AppError::NotVisible,
            Self::Unavailable { dependency } => AppError::DependencyUnavailable { dependency },
            Self::InvalidInput { field } => AppError::MalformedPayload { field },
            Self::CommitUnknown => AppError::ReconciliationRequired { accepted: false },
            Self::Corrupt { .. } | Self::Conflict => AppError::DependencyUnavailable {
                dependency: "tool_runtime",
            },
        }
    }

    const fn dependency(self) -> &'static str {
        match self {
            Self::Unavailable { dependency } => dependency,
            Self::NotVisible
            | Self::Corrupt { .. }
            | Self::InvalidInput { .. }
            | Self::Conflict
            | Self::CommitUnknown => "tool_runtime",
        }
    }
}

/// Catalog 校验后由权威 runtime 解析出的 scope。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedToolScope {
    /// Authoritative tenant.
    pub tenant_id: TenantId,
    /// 权威 run。
    pub run_id: RunId,
    /// Authoritative thread.
    pub thread_id: ThreadId,
    /// 权威 Bot。
    pub bot_id: BotId,
    /// 权威 run 内序号。
    pub call_seq: u64,
    /// 权威 target。
    pub target: ApprovalTarget,
    /// Computer generation bound into approval; non-computer tools use generation zero.
    pub computer_generation: ComputerGeneration,
    /// Browser document generation bound into approval; non-browser targets use `None`.
    pub target_document_generation: Option<DocumentGeneration>,
    /// Redacted, bounded UI presentation supplied by the first-party resolver. It is required only
    /// when metadata requires human approval.
    pub approval_presentation: Option<ToolApprovalPresentation>,
    /// 由快照/ACL 构造、不可反序列化的 policy context。
    pub policy_context: PolicyContext,
    /// keyed 工具实际携带的幂等键。
    pub idempotency_key: Option<IdempotencyKey>,
    /// Structural/content governance refusal computed from authoritative scope plus validated
    /// arguments. It uses the same durable refusal/audit path as CEL and never reaches execution.
    pub preflight_refusal: Option<ToolPreflightRefusal>,
}

/// Redacted approval presentation. Raw tool arguments remain in the private execution envelope;
/// this projection is the only argument-shaped value the approval store/UI may receive.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolApprovalPresentation {
    /// Bounded redacted JSON summary shown to the person deciding.
    pub arguments_summary: serde_json::Value,
    /// Optional first-party diff/change projection. Vendor/model prose cannot populate it.
    pub change_summary: Option<serde_json::Value>,
}

impl fmt::Debug for ToolApprovalPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolApprovalPresentation")
            .field("arguments_summary", &"<redacted>")
            .field("change_summary", &self.change_summary.is_some())
            .finish()
    }
}

/// Closed structural/content refusal supplied by a first-party control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolPreflightRefusal {
    rule: PolicyRuleId,
    error_code: &'static str,
}

impl ToolPreflightRefusal {
    /// Construct from a stable first-party rule/code pair; neither may contain request content.
    #[must_use]
    pub fn new(rule: &'static str, error_code: &'static str) -> Self {
        Self {
            rule: PolicyRuleId::new(rule),
            error_code,
        }
    }
}

/// 由真实 domain policy decision 投影出的窄结论。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolPolicyEvaluation {
    version: PolicyVersionTag,
    forward: bool,
    refused_rule: Option<PolicyRuleId>,
}

impl ToolPolicyEvaluation {
    /// 从 deny-first/default-deny/dry-run 的领域结论构造；规则原文只做摘要，不进 audit/log。
    #[must_use]
    pub fn from_domain(decision: &PolicyDecision<'_>) -> Self {
        let refused_rule = (!decision.allowed).then(|| {
            let id = decision.matched.map_or_else(
                || "policy.default_deny".to_owned(),
                |rule| format!("policy.rule.{}", Sha256Digest::of(rule.as_bytes()).to_hex()),
            );
            PolicyRuleId::new(id)
        });
        Self {
            version: PolicyVersionTag::new(decision.policy_version.to_hex()),
            forward: decision.forward,
            refused_rule,
        }
    }

    fn verdict(&self) -> PolicyVerdict {
        match (&self.refused_rule, self.forward) {
            (Some(rule), false) => PolicyVerdict::Deny {
                policy_version: self.version.clone(),
                rule: rule.clone(),
            },
            _ => PolicyVerdict::Allow {
                policy_version: self.version.clone(),
            },
        }
    }

    fn refused_rule(&self) -> Option<&PolicyRuleId> {
        self.refused_rule.as_ref()
    }
}

/// 审批存储查询所需的、全部来自权威 scope 的字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolApprovalRequest {
    /// Rust-minted call identity.
    pub call_id: ToolCallId,
    /// actor。
    pub actor: ActorId,
    /// Auth generation at request time.
    pub auth_generation: AuthGeneration,
    /// Bot。
    pub bot: BotId,
    /// run。
    pub run: RunId,
    /// Authoritative thread containing the run.
    pub thread: ThreadId,
    /// tool。
    pub tool: ToolName,
    /// canonical args hash。
    pub args_hash: Sha256Digest,
    /// target。
    pub target: ApprovalTarget,
    /// First-party effect shown in the approval UI.
    pub effect: Effect,
    /// Catalog approval reuse class.
    pub approval_class: ApprovalClass,
    /// Computer generation at request time.
    pub computer_generation: ComputerGeneration,
    /// Browser document generation at request time.
    pub target_document_generation: Option<DocumentGeneration>,
    /// catalog generation。
    pub catalog_generation: CatalogGeneration,
    /// policy version。
    pub policy_version: PolicyVersionTag,
    /// Redacted bounded arguments/diff presentation.
    pub presentation: ToolApprovalPresentation,
}

/// 在执行之前必须同事务持久化的 decision 事实；不含原始参数。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolDecisionDraft {
    /// 调用 ID。
    pub call_id: ToolCallId,
    /// run。
    pub run_id: RunId,
    /// run 内序号。
    pub call_seq: u64,
    /// actor。
    pub actor: ActorId,
    /// Bot。
    pub bot: BotId,
    /// 权威 metadata。
    pub metadata: ToolMetadata,
    /// canonical args hash。
    pub args_hash: Sha256Digest,
    /// target。
    pub target: ApprovalTarget,
    /// policy version。
    pub policy_version: PolicyVersionTag,
    /// Durable approval row identity for acting tools; absent only when approval is not required.
    pub approval_id: Option<String>,
    /// 实际幂等键。
    pub idempotency_key: Option<IdempotencyKey>,
}

/// policy/approval 拒绝的审计草稿；拒绝时不创建 attempt。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolRefusalDraft {
    /// 共同 decision 事实。
    pub decision: ToolDecisionDraft,
    /// 稳定规则/拒绝 ID。
    pub rule: PolicyRuleId,
    /// 封闭错误码。
    pub error_code: &'static str,
}

/// 已执行 outcome 的 journal 草稿。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutcomeDraft {
    /// 原 decision 事实。
    pub decision: ToolDecisionDraft,
    /// durable receipt。
    pub receipt: DurableDecisionReceipt,
    /// capability ID。
    pub capability_id: CapabilityId,
    /// 无内容 outcome。
    pub outcome: ToolOutcome,
}

/// Tool audit 草稿投影失败；只表示权威 ID 不满足 audit identifier 约束或字段重复。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolAuditDraftError {
    /// 标识符无效。
    #[error("tool_audit_identifier_invalid")]
    Identifier(#[from] openbot_domain::audit::payload::AuditFieldError),
    /// payload 字段重复/无效。
    #[error("tool_audit_payload_invalid")]
    Payload(#[from] openbot_domain::audit::payload::AuditPayloadError),
}

impl ToolRefusalDraft {
    /// 只用 allowlist 字段构造拒绝审计，不包含参数或 policy 表达式原文。
    pub fn audit_payload(&self) -> Result<AuditPayload, ToolAuditDraftError> {
        let mut facts = common_audit_facts(&self.decision)?;
        facts.push(AuditFact::RefusedByRule(AuditIdentifier::new(
            self.rule.as_str(),
        )?));
        facts.push(AuditFact::ErrorCode(AuditLabel::new(self.error_code)));
        Ok(AuditPayload::from_facts(facts)?)
    }
}

impl ToolOutcomeDraft {
    /// 只用 allowlist 字段构造 outcome 审计。
    pub fn audit_payload(&self) -> Result<AuditPayload, ToolAuditDraftError> {
        let mut facts = common_audit_facts(&self.decision)?;
        facts.extend([
            AuditFact::DecisionId(AuditIdentifier::new(self.receipt.decision().as_str())?),
            AuditFact::CommitState(AuditLabel::new(self.outcome.commit_state.as_str())),
            AuditFact::OutputBytes(u64::from(self.outcome.output_bytes)),
            AuditFact::OutputTruncated(
                self.outcome.output_bytes > self.decision.metadata.limits.max_model_visible_bytes,
            ),
            AuditFact::DurationMs(
                u64::try_from(self.outcome.duration.as_millis()).unwrap_or(u64::MAX),
            ),
        ]);
        if let Some(code) = self.outcome.error_code {
            facts.push(AuditFact::ErrorCode(AuditLabel::new(code)));
        }
        Ok(AuditPayload::from_facts(facts)?)
    }
}

fn common_audit_facts(
    decision: &ToolDecisionDraft,
) -> Result<Vec<AuditFact>, openbot_domain::audit::payload::AuditFieldError> {
    let mut facts = vec![
        AuditFact::ToolName(AuditIdentifier::new(decision.metadata.name.as_str())?),
        AuditFact::Bot(AuditIdentifier::new(decision.bot.as_str())?),
        AuditFact::EffectClass(AuditLabel::new(decision.metadata.effect.effect().as_str())),
        AuditFact::EffectDowngraded(decision.metadata.effect.was_downgraded()),
        AuditFact::CanonicalArgsHash(decision.args_hash),
        AuditFact::SchemaHash(decision.metadata.schema_hash),
        AuditFact::TargetKind(AuditLabel::new(decision.target.kind)),
        AuditFact::TargetId(AuditIdentifier::new(decision.target.id.as_str())?),
        AuditFact::PolicyVersion(AuditIdentifier::new(decision.policy_version.as_str())?),
        AuditFact::CatalogGeneration(decision.metadata.catalog_generation.get()),
        AuditFact::Idempotency(AuditLabel::new(decision.metadata.idempotency.as_str())),
        AuditFact::ApprovalClass(AuditLabel::new(decision.metadata.approval_class.as_str())),
        AuditFact::SandboxRequirement(AuditLabel::new(decision.metadata.sandbox.as_str())),
        AuditFact::ParallelSafe(decision.metadata.parallel_safe),
    ];
    if let Some(approval_id) = &decision.approval_id {
        facts.push(AuditFact::ApprovalId(AuditIdentifier::new(approval_id)?));
    }
    Ok(facts)
}

/// 真正交给 executor 的调用；字段私有，唯一构造点在本模块的管线末端。
pub struct AuthorizedToolCall {
    call_id: ToolCallId,
    metadata: ToolMetadata,
    arguments: ToolArguments,
    tenant: TenantId,
    run: RunId,
    thread: ThreadId,
    auth_generation: openbot_contracts::auth::AuthGeneration,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
    capability: SingleUseCapability,
}

impl fmt::Debug for AuthorizedToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedToolCall")
            .field("call_id", &self.call_id)
            .field("tool", &self.metadata.name)
            .field("actor", self.actor.actor())
            .field("bot", self.actor.bot())
            .field("run", &self.run)
            .field("thread", &self.thread)
            .field("target", &self.target)
            .field("arguments", &"<redacted>")
            .field("capability", &"<redacted>")
            .finish()
    }
}

impl AuthorizedToolCall {
    /// 消费单次 capability，得到 executor 可读参数与必须交回的 redeemed proof。
    #[must_use]
    pub fn redeem(self) -> (ExecutableToolCall, RedeemedCapability) {
        let attempt_id = self.capability.attempt().clone();
        let decision_id = self.capability.decision().clone();
        let capability_id = self.capability.id().clone();
        let redeemed = self.capability.redeem();
        (
            ExecutableToolCall {
                call_id: self.call_id,
                attempt_id,
                decision_id,
                capability_id,
                metadata: self.metadata,
                arguments: self.arguments,
                tenant: self.tenant,
                run: self.run,
                thread: self.thread,
                auth_generation: self.auth_generation,
                actor: self.actor,
                target: self.target,
            },
            redeemed,
        )
    }
}

/// 已兑券、只能由 executor 按值消费的具体调用。
pub struct ExecutableToolCall {
    call_id: ToolCallId,
    attempt_id: openbot_contracts::ids::AttemptId,
    decision_id: openbot_contracts::ids::PolicyDecisionId,
    capability_id: CapabilityId,
    metadata: ToolMetadata,
    arguments: ToolArguments,
    tenant: TenantId,
    run: RunId,
    thread: ThreadId,
    auth_generation: openbot_contracts::auth::AuthGeneration,
    actor: AuthoritativeActor,
    target: ApprovalTarget,
}

impl ExecutableToolCall {
    /// Rust-minted call identity used only to join process-local execution controls.
    #[must_use]
    pub const fn call_id(&self) -> &ToolCallId {
        &self.call_id
    }

    /// Original durable attempt bound into the redeemed capability.
    #[must_use]
    pub const fn attempt_id(&self) -> &openbot_contracts::ids::AttemptId {
        &self.attempt_id
    }

    /// Original durable decision, not a newly minted authority.
    #[must_use]
    pub const fn decision_id(&self) -> &openbot_contracts::ids::PolicyDecisionId {
        &self.decision_id
    }

    /// Identity retained only for matching the separately consumed proof.
    #[must_use]
    pub const fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    /// metadata。
    #[must_use]
    pub const fn metadata(&self) -> &ToolMetadata {
        &self.metadata
    }

    /// 经过 validation 且与 decision hash 同源的参数。
    #[must_use]
    pub const fn arguments(&self) -> &ToolArguments {
        &self.arguments
    }

    /// Authoritative tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Authoritative run.
    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// Authoritative thread.
    #[must_use]
    pub const fn thread(&self) -> &ThreadId {
        &self.thread
    }

    /// Auth generation observed immediately before the pipeline.
    #[must_use]
    pub const fn auth_generation(&self) -> openbot_contracts::auth::AuthGeneration {
        self.auth_generation
    }

    /// 权威 actor/Bot。
    #[must_use]
    pub const fn actor(&self) -> &AuthoritativeActor {
        &self.actor
    }

    /// 权威 target。
    #[must_use]
    pub const fn target(&self) -> &ApprovalTarget {
        &self.target
    }
}

impl fmt::Debug for ExecutableToolCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutableToolCall")
            .field("tool", &self.metadata.name)
            .field("arguments", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// executor 必须交回 redeemed proof、脱敏文本与 commit 三态。
pub struct ToolExecutionReport {
    redeemed: RedeemedCapability,
    redacted_output: String,
    outcome: ToolOutcome,
}

impl ToolExecutionReport {
    /// 构造；输出字节数由文本实算，调用方不能自报。
    #[must_use]
    pub fn new(
        redeemed: RedeemedCapability,
        redacted_output: String,
        commit_state: CommitState,
        duration: Duration,
        error_code: Option<&'static str>,
    ) -> Self {
        Self {
            redeemed,
            outcome: ToolOutcome {
                commit_state,
                output_bytes: u32::try_from(redacted_output.len()).unwrap_or(u32::MAX),
                duration,
                error_code,
            },
            redacted_output,
        }
    }
}

/// Catalog/scope/policy/approval/executor 控制面。它提供权威事实，application 决定调用顺序。
#[async_trait]
pub trait ToolControlPlane: Send + Sync {
    /// 按 catalog key 读取权威 metadata。
    async fn metadata(&self, name: &ToolName) -> Result<ToolMetadata, ToolPortError>;

    /// validation 之后解析 run/Bot/target/policy context。
    async fn resolve_scope(
        &self,
        auth: &AuthContext,
        invocation: &ToolInvocation,
        arguments: &ToolArguments,
        metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError>;

    /// 用 domain policy evaluator 给出结论。
    async fn evaluate_policy(
        &self,
        context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError>;

    /// 只有 metadata 要求人审时才调用。
    async fn approval(
        &self,
        request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError>;

    /// 按值消费授权信封并执行；所有执行错误都必须规范化进 commit_state/error_code，不能以
    /// `Err` 丢失“请求是否已发出”这一事实。
    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport;
}

/// Durable journal。每个方法的成功都表示对应数据库事务已经 commit。
#[async_trait]
pub trait ToolJournal: Send + Sync {
    /// 记录不执行的 policy/approval 拒绝审计。
    async fn record_refusal(&self, draft: &ToolRefusalDraft) -> Result<(), ToolPortError>;

    /// decision + attempt #0 同事务，commit 后才返回 receipt。
    async fn record_decision(
        &self,
        draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError>;

    /// capability CAS 绑定到 durable attempt；成功后才允许调用 executor。
    async fn attach_capability(
        &self,
        call_id: &ToolCallId,
        capability: &CapabilityId,
    ) -> Result<(), ToolPortError>;

    /// outcome + 对应 audit 同事务。
    async fn record_outcome(&self, draft: &ToolOutcomeDraft) -> Result<(), ToolPortError>;
}

/// 未注入 tool runtime 时 fail-closed。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoToolControlPlane;

#[async_trait]
impl ToolControlPlane for NoToolControlPlane {
    async fn metadata(&self, _name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_catalog",
        })
    }

    async fn resolve_scope(
        &self,
        _auth: &AuthContext,
        _invocation: &ToolInvocation,
        _arguments: &ToolArguments,
        _metadata: &ToolMetadata,
    ) -> Result<ResolvedToolScope, ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_scope",
        })
    }

    async fn evaluate_policy(
        &self,
        _context: &PolicyContext,
    ) -> Result<ToolPolicyEvaluation, ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "policy",
        })
    }

    async fn approval(
        &self,
        _request: &ToolApprovalRequest,
    ) -> Result<ApprovalOutcome, ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "approval",
        })
    }

    async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
        let (_call, redeemed) = call.redeem();
        ToolExecutionReport::new(
            redeemed,
            String::new(),
            CommitState::NotCommitted,
            Duration::ZERO,
            Some("dependency_unavailable"),
        )
    }
}

/// 未注入 journal 时所有写失败，因而永远拿不到 capability。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoToolJournal;

#[async_trait]
impl ToolJournal for NoToolJournal {
    async fn record_refusal(&self, _draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_journal",
        })
    }

    async fn record_decision(
        &self,
        _draft: &ToolDecisionDraft,
    ) -> Result<DurableDecisionReceipt, ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_journal",
        })
    }

    async fn attach_capability(
        &self,
        _call_id: &ToolCallId,
        _capability: &CapabilityId,
    ) -> Result<(), ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_journal",
        })
    }

    async fn record_outcome(&self, _draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
        Err(ToolPortError::Unavailable {
            dependency: "tool_journal",
        })
    }
}

/// 执行一次完整 tool pipeline。
pub async fn invoke_tool<C: ToolControlPlane, J: ToolJournal>(
    control: &C,
    journal: &J,
    auth: &AuthContext,
    invocation: ToolInvocation,
) -> Result<ToolResult, AppError> {
    invoke_tool_guarded(control, journal, auth, invocation, None).await
}

/// Same pipeline; a delegated Run passes its effect guard.
pub(crate) async fn invoke_tool_guarded<C: ToolControlPlane, J: ToolJournal>(
    control: &C,
    journal: &J,
    auth: &AuthContext,
    invocation: ToolInvocation,
    guard: Option<&crate::delegation::DelegatedEffectGuard>,
) -> Result<ToolResult, AppError> {
    let tool = ToolName::new(invocation.tool_name.clone())
        .map_err(|_| AppError::MalformedPayload { field: "toolName" })?;
    let arguments = ToolArguments::new(invocation.arguments.clone()).map_err(
        |ToolArgumentsError::NotAnObject| AppError::MalformedPayload { field: "arguments" },
    )?;
    let metadata = control
        .metadata(&tool)
        .await
        .map_err(ToolPortError::into_app_error)?;
    let validated = Requested::new(RequestedToolCall {
        call_id: invocation.call_id.clone(),
        run: invocation.run_id.clone(),
        tool,
        arguments: arguments.clone(),
    })
    .validate(&metadata)
    .map_err(validation_error)?;
    let args_hash = *validated.args_hash();
    let scope = control
        .resolve_scope(auth, &invocation, &arguments, &metadata)
        .await
        .map_err(ToolPortError::into_app_error)?;
    if scope.tenant_id != *auth.tenant()
        || scope.run_id != invocation.run_id
        || scope.bot_id != invocation.bot_id
        || scope.call_seq != invocation.call_seq
    {
        return Err(AppError::NotVisible);
    }
    let actor = AuthoritativeActor::from_auth_context(auth.actor().clone(), scope.bot_id.clone());
    let auth_generation = auth.auth_generation();
    let classified = validated
        .resolve(actor.clone(), scope.target.clone())
        .classify_effect();
    let policy = control
        .evaluate_policy(&scope.policy_context)
        .await
        .map_err(ToolPortError::into_app_error)?;
    let base_draft = ToolDecisionDraft {
        call_id: invocation.call_id.clone(),
        run_id: scope.run_id.clone(),
        call_seq: scope.call_seq,
        actor: auth.actor().clone(),
        bot: scope.bot_id.clone(),
        metadata: metadata.clone(),
        args_hash,
        target: scope.target.clone(),
        policy_version: policy.version.clone(),
        approval_id: None,
        idempotency_key: scope.idempotency_key.clone(),
    };

    if let Some(refusal) = &scope.preflight_refusal {
        journal
            .record_refusal(&ToolRefusalDraft {
                decision: base_draft.clone(),
                rule: refusal.rule.clone(),
                error_code: refusal.error_code,
            })
            .await
            .map_err(ToolPortError::into_app_error)?;
        return Err(AppError::PolicyRefused {
            rule: refusal.rule.as_str().to_owned(),
            decision: None,
        });
    }

    if let Some(rule) = policy.refused_rule() {
        journal
            .record_refusal(&ToolRefusalDraft {
                decision: base_draft.clone(),
                rule: rule.clone(),
                error_code: "policy_refused",
            })
            .await
            .map_err(ToolPortError::into_app_error)?;
    }

    let passed = match classified.apply_policy(policy.verdict()) {
        Ok(passed) => passed,
        Err(refused) => {
            let RefusalReason::PolicyDenied { rule } = refused.reason else {
                return Err(AppError::DependencyUnavailable {
                    dependency: "tool_pipeline",
                });
            };
            return Err(AppError::PolicyRefused {
                rule: rule.as_str().to_owned(),
                decision: None,
            });
        }
    };

    let approval = if metadata.approval_class.requires_human_approval() {
        let presentation =
            scope
                .approval_presentation
                .clone()
                .ok_or(AppError::DependencyUnavailable {
                    dependency: "approval_presentation",
                })?;
        control
            .approval(&ToolApprovalRequest {
                call_id: invocation.call_id.clone(),
                actor: auth.actor().clone(),
                auth_generation,
                bot: scope.bot_id.clone(),
                run: scope.run_id.clone(),
                thread: scope.thread_id.clone(),
                tool: metadata.name.clone(),
                args_hash,
                target: scope.target.clone(),
                effect: metadata.effect.effect(),
                approval_class: metadata.approval_class,
                computer_generation: scope.computer_generation,
                target_document_generation: scope.target_document_generation,
                catalog_generation: metadata.catalog_generation,
                policy_version: policy.version.clone(),
                presentation,
            })
            .await
            .map_err(ToolPortError::into_app_error)?
    } else {
        ApprovalOutcome::NotRequired
    };
    let settled = match passed.settle_approval(approval) {
        Ok(settled) => settled,
        Err(refused) => {
            let (rule, error_code) = approval_refusal(&refused.reason);
            journal
                .record_refusal(&ToolRefusalDraft {
                    decision: base_draft,
                    rule: rule.clone(),
                    error_code,
                })
                .await
                .map_err(ToolPortError::into_app_error)?;
            return Err(AppError::PolicyRefused {
                rule: rule.as_str().to_owned(),
                decision: None,
            });
        }
    };

    let mut decision = base_draft;
    decision.approval_id = settled.approval_id().map(str::to_owned);

    let execution_scope = ToolExecutionScope {
        tenant: scope.tenant_id,
        run: scope.run_id,
        thread: scope.thread_id,
        auth_generation,
        actor,
    };
    execute_after_approval(
        control,
        journal,
        settled,
        decision,
        arguments,
        execution_scope,
        guard,
    )
    .await
}

struct ToolExecutionScope {
    tenant: TenantId,
    run: RunId,
    thread: ThreadId,
    auth_generation: openbot_contracts::auth::AuthGeneration,
    actor: AuthoritativeActor,
}

async fn execute_after_approval<C: ToolControlPlane, J: ToolJournal>(
    control: &C,
    journal: &J,
    settled: ApprovalSettled,
    decision: ToolDecisionDraft,
    arguments: ToolArguments,
    scope: ToolExecutionScope,
    guard: Option<&crate::delegation::DelegatedEffectGuard>,
) -> Result<ToolResult, AppError> {
    if let Some(guard) = guard {
        guard.recheck().await?;
    }
    let written = journal.record_decision(&decision).await;
    let recorded = settled
        .record_decision(written.clone().map_err(|error| DecisionWriteFailed {
            dependency: error.dependency(),
        }))
        .map_err(|terminal| match *terminal {
            ToolCallTerminal::Aborted(aborted) => match aborted.reason {
                AbortReason::DecisionNotDurable { dependency } => {
                    AppError::DependencyUnavailable { dependency }
                }
                AbortReason::CapabilityMismatch => AppError::DependencyUnavailable {
                    dependency: "tool_pipeline",
                },
            },
            _ => AppError::DependencyUnavailable {
                dependency: "tool_pipeline",
            },
        })?;
    let receipt = recorded.receipt().clone();
    let ready = recorded.mint_capability();
    let (executing, capability) = ready.start();
    let capability_id = capability.id().clone();
    journal
        .attach_capability(&decision.call_id, &capability_id)
        .await
        .map_err(ToolPortError::into_app_error)?;

    let report = control
        .execute(AuthorizedToolCall {
            call_id: decision.call_id.clone(),
            metadata: decision.metadata.clone(),
            arguments,
            tenant: scope.tenant,
            run: scope.run,
            thread: scope.thread,
            auth_generation: scope.auth_generation,
            actor: scope.actor,
            target: decision.target.clone(),
            capability,
        })
        .await;
    let ToolExecutionReport {
        redeemed,
        mut redacted_output,
        outcome,
    } = report;
    truncate_utf8(
        &mut redacted_output,
        decision.metadata.limits.max_output_bytes,
    );
    let draft = ToolOutcomeDraft {
        decision: decision.clone(),
        receipt,
        capability_id,
        outcome: outcome.clone(),
    };
    let persisted = journal.record_outcome(&draft).await;
    let terminal = executing.record_outcome(
        redeemed,
        persisted
            .as_ref()
            .map(|()| outcome)
            .map_err(|error| OutcomeWriteFailed {
                dependency: error.dependency(),
            }),
    );
    match terminal {
        ToolCallTerminal::Completed(completed) => {
            let projected = completed.project();
            let visible = projected.model_visible();
            truncate_utf8(&mut redacted_output, visible.visible_bytes);
            let commit_state = match projected.completed().outcome().commit_state {
                CommitState::Committed => ToolCommitState::Committed,
                CommitState::NotCommitted => ToolCommitState::NotCommitted,
                CommitState::Unknown => {
                    return Err(AppError::ReconciliationRequired { accepted: true });
                }
            };
            let visible_bytes = u32::try_from(redacted_output.len()).unwrap_or(u32::MAX);
            Ok(ToolResult {
                call_id: decision.call_id,
                content: redacted_output,
                error_code: projected
                    .completed()
                    .outcome()
                    .error_code
                    .map(str::to_owned),
                commit_state,
                visible_bytes,
                truncated: visible.truncated,
            })
        }
        ToolCallTerminal::ReconciliationRequired(_) => Err(AppError::ReconciliationRequired {
            accepted: persisted.is_ok(),
        }),
        ToolCallTerminal::Aborted(_) | ToolCallTerminal::Refused(_) => {
            Err(AppError::DependencyUnavailable {
                dependency: "tool_pipeline",
            })
        }
    }
}

fn validation_error(error: ValidationRejection) -> AppError {
    match error {
        ValidationRejection::InputTooLarge { .. } => {
            AppError::MalformedPayload { field: "arguments" }
        }
        ValidationRejection::ToolNameMismatch | ValidationRejection::MetadataInvalid(_) => {
            AppError::DependencyUnavailable {
                dependency: "tool_catalog",
            }
        }
    }
}

fn approval_refusal(reason: &RefusalReason) -> (PolicyRuleId, &'static str) {
    match reason {
        RefusalReason::HumanDenied => (
            PolicyRuleId::new("approval.human_denied"),
            "approval_denied",
        ),
        RefusalReason::ApprovalMissing => {
            (PolicyRuleId::new("approval.missing"), "approval_missing")
        }
        RefusalReason::ApprovalInvalid(reason) => (
            PolicyRuleId::new(format!("approval.invalid.{}", reason.as_str())),
            "approval_invalid",
        ),
        RefusalReason::PolicyDenied { rule } => (rule.clone(), "policy_refused"),
    }
}

fn truncate_utf8(value: &mut String, max_bytes: u32) {
    let mut end = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use openbot_contracts::auth::Role;
    use openbot_contracts::ids::{
        AttemptId, CatalogGeneration, DeploymentId, PolicyDecisionId, TenantId,
    };
    use openbot_domain::policy::context::{ActorRef, BotRef, PageRef, ToolRef};
    use openbot_domain::policy::{ActionPolicy, CompiledActionPolicy, PolicyMode, evaluate};
    use openbot_domain::tool::approval::ApprovalInvalidation;
    use openbot_domain::tool::metadata::{
        ApprovalClass, Effect, EffectClassification, Idempotency, SandboxRequirement, ToolLimits,
    };
    use serde_json::json;

    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    struct FailureMode {
        decision: bool,
        attach: bool,
        outcome: bool,
    }

    #[derive(Clone)]
    struct FakeControl {
        trace: Arc<Mutex<Vec<&'static str>>>,
        policy: ActionPolicy,
        approval: ApprovalOutcome,
        commit_state: CommitState,
        scope_matches: bool,
    }

    #[derive(Clone)]
    struct FakeJournal {
        trace: Arc<Mutex<Vec<&'static str>>>,
        failures: FailureMode,
    }

    fn metadata(approval_class: ApprovalClass) -> ToolMetadata {
        ToolMetadata {
            name: ToolName::new("computer.write").unwrap(),
            schema_hash: Sha256Digest::of(b"schema"),
            catalog_generation: CatalogGeneration::new(7),
            effect: EffectClassification::declared(Effect::Write),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(5),
            approval_class,
            sandbox: SandboxRequirement::RequiredNoEgress,
            limits: ToolLimits {
                max_input_bytes: 256,
                max_output_bytes: 8,
                max_model_visible_bytes: 5,
            },
            resource_locks: Vec::new(),
        }
    }

    fn context(actor: &str, bot: &str) -> PolicyContext {
        PolicyContext {
            tool: ToolRef {
                name: "computer.write".to_owned(),
            },
            bot: BotRef { id: bot.to_owned() },
            page: PageRef {
                url: "https://example.test/".to_owned(),
                host: "example.test".to_owned(),
            },
            actor: ActorRef {
                id: actor.to_owned(),
            },
            element: None,
            key: None,
            intent: None,
            file: None,
            mcp: None,
            command: None,
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep-1"),
            TenantId::new("tenant-1"),
            ActorId::new("actor-1"),
            [Role::User],
            openbot_contracts::auth::AuthGeneration::new(9),
            false,
        )
    }

    fn invocation() -> ToolInvocation {
        ToolInvocation {
            call_id: ToolCallId::new("call-1"),
            run_id: RunId::new("run-1"),
            bot_id: BotId::new("bot-1"),
            call_seq: 4,
            tool_name: "computer.write".to_owned(),
            arguments: json!({"text":"safe"}),
        }
    }

    fn allow_policy() -> ActionPolicy {
        ActionPolicy {
            mode: PolicyMode::Enforce,
            deny: Vec::new(),
            allow: vec!["true".to_owned()],
        }
    }

    fn fixture(
        policy: ActionPolicy,
        approval: ApprovalOutcome,
        commit_state: CommitState,
        failures: FailureMode,
    ) -> (FakeControl, FakeJournal, Arc<Mutex<Vec<&'static str>>>) {
        let trace = Arc::new(Mutex::new(Vec::new()));
        (
            FakeControl {
                trace: Arc::clone(&trace),
                policy,
                approval,
                commit_state,
                scope_matches: true,
            },
            FakeJournal {
                trace: Arc::clone(&trace),
                failures,
            },
            trace,
        )
    }

    #[async_trait]
    impl ToolControlPlane for FakeControl {
        async fn metadata(&self, _name: &ToolName) -> Result<ToolMetadata, ToolPortError> {
            self.trace.lock().unwrap().push("metadata");
            Ok(metadata(match self.approval {
                ApprovalOutcome::NotRequired => ApprovalClass::NotRequired,
                ApprovalOutcome::Granted(_) | ApprovalOutcome::Denied => ApprovalClass::EveryCall,
            }))
        }

        async fn resolve_scope(
            &self,
            auth: &AuthContext,
            invocation: &ToolInvocation,
            _arguments: &ToolArguments,
            metadata: &ToolMetadata,
        ) -> Result<ResolvedToolScope, ToolPortError> {
            self.trace.lock().unwrap().push("scope");
            Ok(ResolvedToolScope {
                tenant_id: auth.tenant().clone(),
                run_id: if self.scope_matches {
                    invocation.run_id.clone()
                } else {
                    RunId::new("other-run")
                },
                thread_id: ThreadId::new("thread-1"),
                bot_id: invocation.bot_id.clone(),
                call_seq: invocation.call_seq,
                target: ApprovalTarget {
                    kind: "computer",
                    id: "computer-1".to_owned(),
                },
                computer_generation: ComputerGeneration::new(1),
                target_document_generation: None,
                approval_presentation: metadata.approval_class.requires_human_approval().then(
                    || ToolApprovalPresentation {
                        arguments_summary: serde_json::json!({"ref":"element-1"}),
                        change_summary: None,
                    },
                ),
                policy_context: context(auth.actor().as_str(), invocation.bot_id.as_str()),
                idempotency_key: None,
                preflight_refusal: None,
            })
        }

        async fn evaluate_policy(
            &self,
            context: &PolicyContext,
        ) -> Result<ToolPolicyEvaluation, ToolPortError> {
            self.trace.lock().unwrap().push("policy");
            let compiled = CompiledActionPolicy::compile(&self.policy);
            Ok(ToolPolicyEvaluation::from_domain(&evaluate(
                &compiled, context,
            )))
        }

        async fn approval(
            &self,
            _request: &ToolApprovalRequest,
        ) -> Result<ApprovalOutcome, ToolPortError> {
            self.trace.lock().unwrap().push("approval");
            Ok(self.approval.clone())
        }

        async fn execute(&self, call: AuthorizedToolCall) -> ToolExecutionReport {
            self.trace.lock().unwrap().push("execute");
            let (call, redeemed) = call.redeem();
            assert_eq!(call.actor().actor().as_str(), "actor-1");
            assert_eq!(call.arguments().as_value(), &json!({"text":"safe"}));
            ToolExecutionReport::new(
                redeemed,
                "ééééé".to_owned(),
                self.commit_state,
                Duration::from_millis(12),
                None,
            )
        }
    }

    #[async_trait]
    impl ToolJournal for FakeJournal {
        async fn record_refusal(&self, _draft: &ToolRefusalDraft) -> Result<(), ToolPortError> {
            self.trace.lock().unwrap().push("refusal");
            Ok(())
        }

        async fn record_decision(
            &self,
            _draft: &ToolDecisionDraft,
        ) -> Result<DurableDecisionReceipt, ToolPortError> {
            self.trace.lock().unwrap().push("decision");
            if self.failures.decision {
                return Err(ToolPortError::Unavailable {
                    dependency: "database",
                });
            }
            Ok(DurableDecisionReceipt::issued_by_repository(
                PolicyDecisionId::new("decision-1"),
                AttemptId::new("attempt-1"),
            ))
        }

        async fn attach_capability(
            &self,
            _call_id: &ToolCallId,
            _capability: &CapabilityId,
        ) -> Result<(), ToolPortError> {
            self.trace.lock().unwrap().push("attach");
            if self.failures.attach {
                Err(ToolPortError::Conflict)
            } else {
                Ok(())
            }
        }

        async fn record_outcome(&self, _draft: &ToolOutcomeDraft) -> Result<(), ToolPortError> {
            self.trace.lock().unwrap().push("outcome");
            if self.failures.outcome {
                Err(ToolPortError::Unavailable {
                    dependency: "database",
                })
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn happy_path_orders_every_boundary_and_never_splits_utf8() {
        let (control, journal, trace) = fixture(
            allow_policy(),
            ApprovalOutcome::NotRequired,
            CommitState::Committed,
            FailureMode::default(),
        );
        let result = invoke_tool(&control, &journal, &auth(), invocation())
            .await
            .unwrap();
        assert_eq!(result.content, "éé");
        assert_eq!(result.visible_bytes, 4);
        assert!(result.truncated);
        assert_eq!(result.commit_state, ToolCommitState::Committed);
        assert_eq!(
            *trace.lock().unwrap(),
            [
                "metadata", "scope", "policy", "decision", "attach", "execute", "outcome"
            ],
        );
    }

    #[tokio::test]
    async fn decision_or_capability_write_failure_proves_executor_was_never_called() {
        for failures in [
            FailureMode {
                decision: true,
                ..FailureMode::default()
            },
            FailureMode {
                attach: true,
                ..FailureMode::default()
            },
        ] {
            let (control, journal, trace) = fixture(
                allow_policy(),
                ApprovalOutcome::NotRequired,
                CommitState::Committed,
                failures,
            );
            let error = invoke_tool(&control, &journal, &auth(), invocation())
                .await
                .expect_err("durable 前置写失败必须停止");
            assert_eq!(error.http_status(), 503);
            assert!(!trace.lock().unwrap().contains(&"execute"));
        }
    }

    #[tokio::test]
    async fn outcome_write_failure_executes_once_then_halts_unaccepted_reconciliation() {
        let (control, journal, trace) = fixture(
            allow_policy(),
            ApprovalOutcome::NotRequired,
            CommitState::Committed,
            FailureMode {
                outcome: true,
                ..FailureMode::default()
            },
        );
        assert_eq!(
            invoke_tool(&control, &journal, &auth(), invocation()).await,
            Err(AppError::ReconciliationRequired { accepted: false }),
        );
        assert_eq!(
            trace
                .lock()
                .unwrap()
                .iter()
                .filter(|step| **step == "execute")
                .count(),
            1,
        );
    }

    #[tokio::test]
    async fn durably_recorded_unknown_halts_as_accepted_reconciliation() {
        let (control, journal, trace) = fixture(
            allow_policy(),
            ApprovalOutcome::NotRequired,
            CommitState::Unknown,
            FailureMode::default(),
        );
        assert_eq!(
            invoke_tool(&control, &journal, &auth(), invocation()).await,
            Err(AppError::ReconciliationRequired { accepted: true }),
        );
        assert_eq!(trace.lock().unwrap().last(), Some(&"outcome"));
    }

    #[tokio::test]
    async fn enforce_refusal_is_audited_without_attempt_but_dry_run_still_executes() {
        let deny = ActionPolicy {
            mode: PolicyMode::Enforce,
            deny: vec!["true".to_owned()],
            allow: Vec::new(),
        };
        let (control, journal, trace) = fixture(
            deny,
            ApprovalOutcome::NotRequired,
            CommitState::Committed,
            FailureMode::default(),
        );
        let error = invoke_tool(&control, &journal, &auth(), invocation())
            .await
            .expect_err("enforce deny 必须拒绝");
        let AppError::PolicyRefused { rule, decision } = error else {
            panic!("拒绝映射不符");
        };
        assert!(rule.starts_with("policy.rule."));
        assert!(!rule.contains("true"));
        assert!(decision.is_none());
        assert_eq!(
            *trace.lock().unwrap(),
            ["metadata", "scope", "policy", "refusal"],
        );

        let dry_run = ActionPolicy {
            mode: PolicyMode::DryRun,
            deny: vec!["true".to_owned()],
            allow: Vec::new(),
        };
        let (control, journal, trace) = fixture(
            dry_run,
            ApprovalOutcome::NotRequired,
            CommitState::Committed,
            FailureMode::default(),
        );
        invoke_tool(&control, &journal, &auth(), invocation())
            .await
            .unwrap();
        assert_eq!(
            *trace.lock().unwrap(),
            [
                "metadata", "scope", "policy", "refusal", "decision", "attach", "execute",
                "outcome"
            ],
        );
    }

    #[tokio::test]
    async fn human_denial_is_audited_and_never_reaches_decision() {
        let (control, journal, trace) = fixture(
            allow_policy(),
            ApprovalOutcome::Denied,
            CommitState::Committed,
            FailureMode::default(),
        );
        let error = invoke_tool(&control, &journal, &auth(), invocation())
            .await
            .expect_err("human deny 必须停止");
        assert!(matches!(error, AppError::PolicyRefused { .. }));
        assert_eq!(
            *trace.lock().unwrap(),
            ["metadata", "scope", "policy", "approval", "refusal"],
        );
    }

    #[tokio::test]
    async fn malformed_arguments_and_scope_mismatch_stop_at_their_exact_boundaries() {
        let (control, journal, trace) = fixture(
            allow_policy(),
            ApprovalOutcome::NotRequired,
            CommitState::Committed,
            FailureMode::default(),
        );
        let mut malformed = invocation();
        malformed.arguments = json!(["not", "object"]);
        assert_eq!(
            invoke_tool(&control, &journal, &auth(), malformed).await,
            Err(AppError::MalformedPayload { field: "arguments" }),
        );
        assert!(trace.lock().unwrap().is_empty());

        let mut control = control;
        control.scope_matches = false;
        assert_eq!(
            invoke_tool(&control, &journal, &auth(), invocation()).await,
            Err(AppError::NotVisible),
        );
        assert_eq!(*trace.lock().unwrap(), ["metadata", "scope"]);
    }

    #[test]
    fn approval_invalidation_keeps_the_specific_remediation_code() {
        let (rule, error_code) = approval_refusal(&RefusalReason::ApprovalInvalid(
            ApprovalInvalidation::DocumentGenerationChanged,
        ));
        assert_eq!(
            rule.as_str(),
            "approval.invalid.document_generation_changed"
        );
        assert_eq!(error_code, "approval_invalid");
    }

    #[tokio::test]
    async fn tool_cancellation_registry_is_exact_first_reason_wins_and_raii_scoped() {
        let registry = ToolCancellationRegistry::default();
        let call_id = ToolCallId::new("call-cancel");
        let (handle, cancellation) = tool_execution_cancellation();
        let registration = registry
            .register(call_id.clone(), cancellation)
            .expect("first exact registration");
        let (_, duplicate) = tool_execution_cancellation();
        assert!(registry.register(call_id.clone(), duplicate).is_none());

        let mut observed = registry
            .cancellation_for(&call_id)
            .expect("registered cancellation");
        assert_eq!(observed.requested(), None);
        assert!(handle.cancel(ToolCancellationReason::Deadline));
        assert!(!handle.cancel(ToolCancellationReason::User));
        assert_eq!(observed.cancelled().await, ToolCancellationReason::Deadline);
        assert_eq!(
            ToolCancellationReason::Deadline.stable_code(),
            "run_deadline_exceeded"
        );

        drop(registration);
        assert!(registry.cancellation_for(&call_id).is_none());

        let (orphaned, mut orphan_receiver) = tool_execution_cancellation();
        drop(orphaned);
        assert_eq!(
            orphan_receiver.cancelled().await,
            ToolCancellationReason::HostDropped
        );
    }
}
