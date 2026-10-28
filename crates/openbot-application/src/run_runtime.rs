//! Built-in/remote Agent 共用的 durable run 写入边界（v3 §4.3 / §7.2）。
//!
//! 本模块的 lease/claim 类型不实现 serde，不能从 HTTP、renderer 或 remote Agent 字节铸造。
//! PostgreSQL adapter 仍逐次验证 owner + fencing + expiry；类型私有字段不是授权替代品。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use async_trait::async_trait;
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId, ToolCallId};
use openbot_domain::thread::FencingToken;
use serde_json::Value;

use crate::chunk::{SEMANTIC_CHUNK_MAX_BYTES, SemanticChunkAccumulator};
use crate::provider::{ProviderRateCard, ProviderRemoteProjection, ProviderUsage};
use crate::run_cost_budget::RunCostCap;

/// Run runtime 的稳定内部错误域；不得携带数据库/provider 原文。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RunRuntimeError {
    /// PostgreSQL/runtime 依赖不可用。
    #[error("run_runtime_unavailable")]
    Unavailable,
    /// Durable 行结构损坏。
    #[error("run_runtime_corrupt field={field}")]
    Corrupt {
        /// 静态字段名。
        field: &'static str,
    },
    /// 输入不满足内部 typed boundary。
    #[error("run_runtime_input_invalid field={field}")]
    InvalidInput {
        /// 静态字段名。
        field: &'static str,
    },
    /// owner/fencing/expiry 已失效；旧 writer 不能提交。
    #[error("run_runtime_stale_lease")]
    StaleLease,
    /// expected sequence 已被不同内容占用，或 terminal 目标冲突。
    #[error("run_runtime_request_conflict")]
    Conflict,
    /// Commit 结果未知；调用方必须以相同 expected sequence 重试核对。
    #[error("run_runtime_commit_unknown")]
    CommitUnknown,
}

/// Terminal/recovery 可落库的封闭稳定错误码。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunFailureCode {
    /// G4 Agent runtime 尚不可用或永久拒绝 dispatch。
    AgentRuntimeUnavailable,
    /// Current delegated registration or owner authority is no longer valid.
    DelegationNotCurrent,
    /// 已被 runtime 接受的 run 失去 lease，外部 effect 状态未知。
    RuntimeLeaseExpired,
    /// 内部 outbox payload 与 durable run 不一致。
    DispatchPayloadCorrupt,
    /// Dispatch 经过有界重试仍不能被 runtime 接受。
    DispatchDeadLetter,
    /// Provider key/auth rejected。
    ProviderAuthentication,
    /// Provider rate limit exhausted for this run。
    ProviderRateLimited,
    /// Provider transport/5xx unavailable。
    ProviderUnavailable,
    /// Provider request may have left the process before acknowledgement。
    ProviderCommitUnknown,
    /// Provider 停止请求的结果未获确认。
    ProviderStopUnknown,
    /// Provider SSE/schema/sequence invalid。
    ProviderInvalidResponse,
    /// Provider real body read gap exceeded watchdog。
    ProviderStreamStalled,
    /// Provider reported failed/incomplete generation。
    ProviderGenerationFailed,
    /// Provider output token usage exceeded configured cap。
    ProviderTokenBudgetExceeded,
    /// Cumulative output usage across this run exceeded its derived run-wide ceiling.
    RunTokenBudgetExceeded,
    /// User cap exists but this provider/model run has no attested price snapshot.
    RunCostBudgetUnpriced,
    /// User cap and provider price snapshot use different currencies.
    RunCostBudgetCurrencyMismatch,
    /// Durable cost upper bound exceeded the immutable user cap.
    RunCostBudgetExceeded,
    /// Built-in Agent tool sampling step cap reached。
    ToolStepLimit,
    /// G4 tool loop not yet available for this requested call。
    ToolLoopUnavailable,
    /// Tool approval/policy denial。
    ToolDenied,
    /// Absolute run deadline elapsed。
    RunDeadlineExceeded,
    /// Run journal commit result unknown after provider/tool effect。
    JournalCommitUnknown,
}

impl RunFailureCode {
    /// PostgreSQL/semantic event 的稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelegationNotCurrent => "delegation_not_current",
            Self::AgentRuntimeUnavailable => "agent_runtime_unavailable",
            Self::RuntimeLeaseExpired => "runtime_lease_expired",
            Self::DispatchPayloadCorrupt => "dispatch_payload_corrupt",
            Self::DispatchDeadLetter => "dispatch_dead_letter",
            Self::ProviderAuthentication => "provider_authentication",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderCommitUnknown => "provider_commit_unknown",
            Self::ProviderStopUnknown => "provider_stop_unknown",
            Self::ProviderInvalidResponse => "provider_invalid_response",
            Self::ProviderStreamStalled => "agent_stream_stalled",
            Self::ProviderGenerationFailed => "provider_generation_failed",
            Self::ProviderTokenBudgetExceeded => "provider_token_budget_exceeded",
            Self::RunTokenBudgetExceeded => "run_token_budget_exceeded",
            Self::RunCostBudgetUnpriced => "run_cost_budget_unpriced",
            Self::RunCostBudgetCurrencyMismatch => "run_cost_budget_currency_mismatch",
            Self::RunCostBudgetExceeded => "run_cost_budget_exceeded",
            Self::ToolStepLimit => "tool_step_limit",
            Self::ToolLoopUnavailable => "tool_loop_unavailable",
            Self::ToolDenied => "tool_denied",
            Self::RunDeadlineExceeded => "run_deadline_exceeded",
            Self::JournalCommitUnknown => "journal_commit_unknown",
        }
    }
}

/// Run terminal 目标；terminal 属性与错误码要求不能由自由布尔值/字符串自报。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTerminal {
    /// 正常完成。
    Completed,
    /// 确定失败。
    Failed(RunFailureCode),
    /// 已确认所有子任务停止后的取消。
    Cancelled,
    /// 可能已有外部 effect，必须人工 reconciliation。
    ReconciliationRequired(RunFailureCode),
}

impl RunTerminal {
    /// Runs/event 共用的封闭状态字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired(_) => "reconciliation_required",
        }
    }

    /// 失败/reconciliation 的稳定码。
    #[must_use]
    pub const fn error_code(self) -> Option<RunFailureCode> {
        match self {
            Self::Failed(code) | Self::ReconciliationRequired(code) => Some(code),
            Self::Completed | Self::Cancelled => None,
        }
    }
}

/// PostgreSQL 已验证的一次 run writer lease；不实现 serde。
#[derive(Clone)]
pub struct RunExecutionLease {
    run_id: RunId,
    thread_id: ThreadId,
    bot_id: BotId,
    actor_id: ActorId,
    fencing: FencingToken,
    next_event_sequence: u64,
    delegation_required: bool,
    delegation_runtime: Option<Arc<crate::DelegationRuntime>>,
    absolute_deadline: Option<SystemTime>,
}

impl RunExecutionLease {
    /// Adapter 从同一事务读出的 durable facts 构造。
    pub fn new(
        run_id: RunId,
        thread_id: ThreadId,
        bot_id: BotId,
        actor_id: ActorId,
        fencing: FencingToken,
        next_event_sequence: u64,
    ) -> Result<Self, RunRuntimeError> {
        if [
            run_id.as_str(),
            thread_id.as_str(),
            bot_id.as_str(),
            actor_id.as_str(),
        ]
        .into_iter()
        .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || i64::try_from(next_event_sequence).is_err()
        {
            return Err(RunRuntimeError::Corrupt {
                field: "run_execution_lease",
            });
        }
        Ok(Self {
            run_id,
            thread_id,
            bot_id,
            actor_id,
            fencing,
            next_event_sequence,
            delegation_required: false,
            delegation_runtime: None,
            absolute_deadline: None,
        })
    }

    /// Frozen delegated deadline, absent on legacy Runs.
    pub fn absolute_deadline(&self) -> Option<SystemTime> {
        self.absolute_deadline
    }
    #[doc(hidden)]
    pub fn with_delegated_run_binding(
        mut self,
        runtime: Option<Arc<crate::DelegationRuntime>>,
        absolute_deadline: SystemTime,
    ) -> Self {
        self.delegation_required = true;
        self.delegation_runtime = runtime;
        self.absolute_deadline = Some(absolute_deadline);
        self
    }
    #[doc(hidden)]
    pub fn delegation_required(&self) -> bool {
        self.delegation_required
    }
    #[doc(hidden)]
    pub async fn check_delegated_sampling(&self) -> Result<(), openbot_contracts::error::AppError> {
        if !self.delegation_required {
            return Ok(());
        }
        self.delegation_runtime
            .as_ref()
            .ok_or_else(|| openbot_contracts::error::AppError::PolicyRefused {
                rule: "delegation_not_current".into(),
                decision: None,
            })?
            .check_sampling(self)
            .await
    }
    #[doc(hidden)]
    pub async fn remint_delegated_auth(
        &self,
    ) -> Result<Option<openbot_contracts::auth::AuthContext>, openbot_contracts::error::AppError>
    {
        if !self.delegation_required {
            return Ok(None);
        }
        self.delegation_runtime
            .as_ref()
            .ok_or_else(|| openbot_contracts::error::AppError::PolicyRefused {
                rule: "delegation_not_current".into(),
                decision: None,
            })?
            .remint_lease(self)
            .await
            .map(Some)
    }
    /// Run id。
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Thread id。
    #[must_use]
    pub const fn thread_id(&self) -> &ThreadId {
        &self.thread_id
    }

    /// Bot id。
    #[must_use]
    pub const fn bot_id(&self) -> &BotId {
        &self.bot_id
    }

    /// Authoritative actor。
    #[must_use]
    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    /// 当前 fencing token。
    #[must_use]
    pub const fn fencing(&self) -> FencingToken {
        self.fencing
    }

    /// Dispatch 时权威 next run-local event sequence。
    #[must_use]
    pub const fn next_event_sequence(&self) -> u64 {
        self.next_event_sequence
    }
}

impl core::fmt::Debug for RunExecutionLease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RunExecutionLease")
            .field("run_id", &self.run_id)
            .field("thread_id", &self.thread_id)
            .field("bot_id", &self.bot_id)
            .field("actor_id", &self.actor_id)
            .field("fencing", &self.fencing)
            .field("next_event_sequence", &self.next_event_sequence)
            .field("delegation_required", &self.delegation_required)
            .field("absolute_deadline", &self.absolute_deadline)
            .finish()
    }
}
// The attached delegation runtime is a process-local handle, not part of the lease identity:
// a cancellation lease read back from the database must match the dispatched one.
impl PartialEq for RunExecutionLease {
    fn eq(&self, other: &Self) -> bool {
        self.run_id == other.run_id
            && self.thread_id == other.thread_id
            && self.bot_id == other.bot_id
            && self.actor_id == other.actor_id
            && self.fencing == other.fencing
            && self.next_event_sequence == other.next_event_sequence
            && self.delegation_required == other.delegation_required
            && self.absolute_deadline == other.absolute_deadline
    }
}
impl Eq for RunExecutionLease {}

/// 一个已被 PostgreSQL 原子 claim 的 replay-safe dispatch。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedRunDispatch {
    outbox_id: String,
    attempt: u32,
    lease: RunExecutionLease,
}

/// One replay-safe cancellation control record claimed by the current lease owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedRunCancellation {
    outbox_id: String,
    attempt: u32,
    lease: RunExecutionLease,
}

impl ClaimedRunCancellation {
    /// Adapter constructor; empty identity or zero attempt is durable corruption.
    pub fn new(
        outbox_id: String,
        attempt: u32,
        lease: RunExecutionLease,
    ) -> Result<Self, RunRuntimeError> {
        if outbox_id.is_empty() || outbox_id.as_bytes().contains(&0) {
            return Err(RunRuntimeError::Corrupt { field: "outbox_id" });
        }
        if attempt == 0 {
            return Err(RunRuntimeError::Corrupt {
                field: "attempt_count",
            });
        }
        Ok(Self {
            outbox_id,
            attempt,
            lease,
        })
    }

    /// Durable outbox identity.
    #[must_use]
    pub fn outbox_id(&self) -> &str {
        &self.outbox_id
    }

    /// Current claim attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Fenced run lease owned by this relay process.
    #[must_use]
    pub const fn lease(&self) -> &RunExecutionLease {
        &self.lease
    }
}

impl ClaimedRunDispatch {
    /// Adapter 构造；空 ID/零 attempt 是 durable corruption。
    pub fn new(
        outbox_id: String,
        attempt: u32,
        lease: RunExecutionLease,
    ) -> Result<Self, RunRuntimeError> {
        if outbox_id.is_empty() || outbox_id.as_bytes().contains(&0) {
            return Err(RunRuntimeError::Corrupt { field: "outbox_id" });
        }
        if attempt == 0 {
            return Err(RunRuntimeError::Corrupt {
                field: "attempt_count",
            });
        }
        Ok(Self {
            outbox_id,
            attempt,
            lease,
        })
    }

    /// Outbox id。
    #[must_use]
    pub fn outbox_id(&self) -> &str {
        &self.outbox_id
    }

    /// 当前 claim attempt；旧 attempt 不能 ack 新 claim。
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Run lease facts。
    #[must_use]
    pub const fn lease(&self) -> &RunExecutionLease {
        &self.lease
    }
}

/// 一次 durable event write 的 receipt。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunWriteReceipt {
    /// Run-local sequence。
    pub run_event_sequence: u64,
    /// Thread-global reconnect cursor。
    pub thread_event_sequence: u64,
    /// Terminal materialize assistant message 时的 sequence。
    pub message_sequence: Option<u64>,
    /// 相同 expected sequence + 相同 payload 的精确 replay。
    pub replayed: bool,
}

/// Normalized provider semantic channel；raw vendor event 不进入 journal。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunSemanticChannel {
    /// User-visible assistant text；terminal 时物化到 messages。
    Text,
    /// Provider reasoning；active-run durable/replayable，terminal时清除，且绝不拼进assistant text。
    Reasoning,
}

/// A complete, redacted tool pair ready for durable message history.
#[derive(Clone, PartialEq, Eq)]
pub struct RunToolExchange {
    internal_call_id: ToolCallId,
    provider_call_id: String,
    name: String,
    arguments: Value,
    result: String,
    error_code: Option<String>,
}

impl RunToolExchange {
    /// Construct a closed exchange. Raw execution output must already be redacted by the tool pipe.
    pub fn new(
        internal_call_id: ToolCallId,
        provider_call_id: String,
        name: String,
        arguments: Value,
        result: String,
        error_code: Option<String>,
    ) -> Result<Self, RunRuntimeError> {
        if internal_call_id.as_str().is_empty()
            || provider_call_id.is_empty()
            || name.is_empty()
            || !arguments.is_object()
            || [
                provider_call_id.as_bytes(),
                name.as_bytes(),
                result.as_bytes(),
            ]
            .into_iter()
            .any(|value| value.contains(&0))
            || error_code
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.as_bytes().contains(&0))
        {
            return Err(RunRuntimeError::InvalidInput {
                field: "tool_exchange",
            });
        }
        Ok(Self {
            internal_call_id,
            provider_call_id,
            name,
            arguments,
            result,
            error_code,
        })
    }

    /// Rust-minted control-plane call id.
    #[must_use]
    pub const fn internal_call_id(&self) -> &ToolCallId {
        &self.internal_call_id
    }

    /// Vendor pairing id. It is never used as authority.
    #[must_use]
    pub fn provider_call_id(&self) -> &str {
        &self.provider_call_id
    }

    /// Authoritative catalog name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Validated arguments retained for the assistant tool-call message.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Redacted model-visible result.
    #[must_use]
    pub fn result(&self) -> &str {
        &self.result
    }

    /// Stable tool error code, if any.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
}

impl core::fmt::Debug for RunToolExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RunToolExchange")
            .field("internal_call_id", &self.internal_call_id)
            .field("provider_call_id", &self.provider_call_id)
            .field("name", &self.name)
            .field("arguments", &"[redacted]")
            .field("result_bytes", &self.result.len())
            .field("error_code", &self.error_code)
            .finish()
    }
}

impl RunSemanticChannel {
    /// Journal payload 的稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Reasoning => "reasoning",
        }
    }
}

/// Relay 对 dispatch consumer 的封闭结论。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunDispatchDecision {
    /// 已按 `(run_id,fencing)` 幂等接受；relay 才可 ack outbox。
    Accepted,
    /// 本机有界队列暂满；outbox 回 pending 并按 attempt 退避。
    RetryableBusy,
    /// 永久拒绝，run 以确定失败收口。
    Rejected(RunFailureCode),
}

/// What the local consumer could prove when a durable cancellation reached this replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunCancellationDisposition {
    /// A locally owned reservation/child was signalled; terminal must wait for its stopped fact.
    ChildSignalled,
    /// This process never owned a child for the fenced lease; runtime may terminalize directly.
    NoLocalChild,
}

/// Durable aggregate after one normalized provider usage record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunTokenUsage {
    /// Sum of normalized provider input tokens across committed samplings.
    pub input_tokens: u64,
    /// Sum of normalized provider output tokens across committed samplings.
    pub output_tokens: u64,
    /// Sum of provider-reported total tokens across committed samplings.
    pub total_tokens: u64,
}

/// Idempotent result of recording one sampling's normalized usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTokenUsageReceipt {
    /// New sampling usage was added to the durable aggregate.
    Recorded(RunTokenUsage),
    /// The exact last sampling was replayed after an unknown commit.
    Replayed(RunTokenUsage),
    /// This sampling was recorded and made the aggregate exceed the immutable run ceiling.
    BudgetExceeded(RunTokenUsage),
    /// This sampling was recorded and made the cost upper bound exceed the immutable user cap.
    CostBudgetExceeded(RunTokenUsage),
}

/// Built-in/remote Agent 的 in-process dispatch 边界。
#[async_trait]
pub trait RunDispatchConsumer: Send + Sync {
    /// 预留/幂等 enqueue；不得在 durable outbox ack 前启动 provider/tool effect。
    async fn dispatch(&self, lease: RunExecutionLease) -> RunDispatchDecision;

    /// Outbox 已 durable ack 后启动该 reservation；必须幂等，队列关闭须显式失败。
    async fn activate(&self, lease: &RunExecutionLease) -> Result<(), RunFailureCode>;

    /// 撤销尚未取得 durable outbox ack 的 enqueue；必须幂等并传播 cancel。
    async fn revoke(&self, lease: &RunExecutionLease) -> RunCancellationDisposition;
}

/// G4 Agent 尚未接线时的 production fail-closed consumer；它明确失败，不执行、不伪造回复。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRunDispatchConsumer;

#[async_trait]
impl RunDispatchConsumer for NoRunDispatchConsumer {
    async fn dispatch(&self, _lease: RunExecutionLease) -> RunDispatchDecision {
        RunDispatchDecision::Rejected(RunFailureCode::AgentRuntimeUnavailable)
    }

    async fn activate(&self, _lease: &RunExecutionLease) -> Result<(), RunFailureCode> {
        Ok(())
    }

    async fn revoke(&self, _lease: &RunExecutionLease) -> RunCancellationDisposition {
        RunCancellationDisposition::NoLocalChild
    }
}

/// Run journal/outbox/lease 的唯一 application port。
#[async_trait]
pub trait RunRuntime: Send + Sync {
    /// Claim a durable cancellation only when this process owns or may fence-take the run lease.
    async fn claim_cancellation(&self) -> Result<Option<ClaimedRunCancellation>, RunRuntimeError> {
        Ok(None)
    }

    /// Record that a local child received cancellation; outbox remains undelivered until terminal.
    async fn mark_cancellation_signalled(
        &self,
        _claim: &ClaimedRunCancellation,
    ) -> Result<(), RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }

    /// No local child existed: write Cancelled terminal and deliver control in one transaction.
    async fn finish_unstarted_cancellation(
        &self,
        _claim: &ClaimedRunCancellation,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }

    /// Claim 当前 worker 可合法接管的一条 `agent_run_dispatch`。
    async fn claim_dispatch(&self) -> Result<Option<ClaimedRunDispatch>, RunRuntimeError>;

    /// Consumer 已幂等接收后确认 outbox delivered。
    async fn acknowledge_dispatch(
        &self,
        claim: &ClaimedRunDispatch,
    ) -> Result<RunExecutionLease, RunRuntimeError>;

    /// 暂时无法 enqueue；回 pending，退避由 adapter 按 attempt 封闭计算。
    async fn retry_dispatch(&self, claim: &ClaimedRunDispatch) -> Result<(), RunRuntimeError>;

    /// 永久拒绝；同事务 terminalize run + deliver/dead-letter outbox。
    async fn reject_dispatch(
        &self,
        claim: &ClaimedRunDispatch,
        code: RunFailureCode,
    ) -> Result<RunWriteReceipt, RunRuntimeError>;

    /// 续租；只有 owner/fencing/status 都仍匹配时成功。
    async fn renew_lease(&self, lease: &RunExecutionLease) -> Result<(), RunRuntimeError>;

    /// 精确 expected-sequence append；commit unknown 可安全重试同一输入。
    async fn append_semantic_chunk(
        &self,
        lease: &RunExecutionLease,
        expected_sequence: u64,
        channel: RunSemanticChannel,
        chunk: &str,
    ) -> Result<RunWriteReceipt, RunRuntimeError>;

    /// Persist one bounded, explicitly untrusted remote UI projection as an operational checkpoint.
    async fn append_remote_projection(
        &self,
        _lease: &RunExecutionLease,
        _expected_sequence: u64,
        _projection: &ProviderRemoteProjection,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }

    /// Persist assistant tool-call + tool-result messages and a checkpoint in one transaction.
    async fn append_tool_exchange(
        &self,
        _lease: &RunExecutionLease,
        _expected_sequence: u64,
        _exchange: &RunToolExchange,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }

    /// Record one sampling's normalized usage with exact-index replay and a fixed run ceiling.
    async fn record_provider_usage(
        &self,
        _lease: &RunExecutionLease,
        _sampling_index: u32,
        _usage: ProviderUsage,
        _max_run_output_tokens: Option<u64>,
        _rate_card: Option<&ProviderRateCard>,
        _cost_cap: Option<&RunCostCap>,
    ) -> Result<RunTokenUsageReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }

    /// 精确 expected-sequence terminal；同事务 materialize assistant text 并 notify。
    async fn finish_run(
        &self,
        lease: &RunExecutionLease,
        expected_sequence: u64,
        terminal: RunTerminal,
    ) -> Result<RunWriteReceipt, RunRuntimeError>;

    /// 对已 delivered 且 lease 过期的 running run 做一次 fencing takeover + reconciliation。
    async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError>;
}

/// 把 50ms/8KiB accumulator 真正接到 durable writer；provider adapter 后续只喂 delta。
pub struct DurableTextRun {
    runtime: Arc<dyn RunRuntime>,
    lease: RunExecutionLease,
    expected_sequence: u64,
    accumulator: SemanticChunkAccumulator,
    pending_durable: VecDeque<(RunSemanticChannel, String)>,
}

impl core::fmt::Debug for DurableTextRun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DurableTextRun")
            .field("run_id", self.lease.run_id())
            .field("expected_sequence", &self.expected_sequence)
            .field("pending_durable", &self.pending_durable.len())
            .finish_non_exhaustive()
    }
}

impl DurableTextRun {
    /// 从已 acknowledge 的 lease 构造。
    #[must_use]
    pub fn new(runtime: Arc<dyn RunRuntime>, lease: RunExecutionLease) -> Self {
        let expected_sequence = lease.next_event_sequence();
        Self {
            runtime,
            lease,
            expected_sequence,
            accumulator: SemanticChunkAccumulator::new(),
            pending_durable: VecDeque::new(),
        }
    }

    /// 推入 provider text delta；达到 50ms/8KiB 的 chunk 立即顺序持久化。
    pub async fn push(&mut self, delta: &str, now: Instant) -> Result<(), RunRuntimeError> {
        if delta.as_bytes().contains(&0) {
            return Err(RunRuntimeError::InvalidInput { field: "delta" });
        }
        self.pending_durable.extend(
            self.accumulator
                .push(delta, now)
                .into_iter()
                .map(|chunk| (RunSemanticChannel::Text, chunk)),
        );
        self.drain_pending().await
    }

    /// 持久化 normalized reasoning delta。先冲刷此前 text，再按同一 8KiB UTF-8 边界切片，
    /// 因而 journal 的跨 channel 顺序与 provider 事件顺序一致。
    pub async fn push_reasoning(
        &mut self,
        delta: &str,
        now: Instant,
    ) -> Result<(), RunRuntimeError> {
        if delta.as_bytes().contains(&0) {
            return Err(RunRuntimeError::InvalidInput {
                field: "reasoning_delta",
            });
        }
        self.pending_durable.extend(
            self.accumulator
                .finish()
                .map(|chunk| (RunSemanticChannel::Text, chunk)),
        );
        let mut reasoning = SemanticChunkAccumulator::new();
        self.pending_durable.extend(
            reasoning
                .push(delta, now)
                .into_iter()
                .chain(reasoning.finish())
                .map(|chunk| (RunSemanticChannel::Reasoning, chunk)),
        );
        self.drain_pending().await
    }

    /// Timer 到点时持久化 pending chunk。
    pub async fn flush_due(&mut self, now: Instant) -> Result<(), RunRuntimeError> {
        self.pending_durable.extend(
            self.accumulator
                .flush_due(now)
                .map(|chunk| (RunSemanticChannel::Text, chunk)),
        );
        self.drain_pending().await
    }

    /// Flush every pending text byte without terminalizing the run.
    pub async fn flush(&mut self) -> Result<(), RunRuntimeError> {
        self.pending_durable.extend(
            self.accumulator
                .finish()
                .map(|chunk| (RunSemanticChannel::Text, chunk)),
        );
        self.drain_pending().await
    }

    /// Flush the current sampling text, then durably append one complete tool pair.
    pub async fn append_tool_exchange(
        &mut self,
        exchange: &RunToolExchange,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.flush().await?;
        let receipt = self
            .runtime
            .append_tool_exchange(&self.lease, self.expected_sequence, exchange)
            .await?;
        self.expected_sequence =
            receipt
                .run_event_sequence
                .checked_add(1)
                .ok_or(RunRuntimeError::Corrupt {
                    field: "next_event_sequence",
                })?;
        Ok(receipt)
    }

    /// Flush preceding text, then append one remote projection at the same expected-sequence edge.
    pub async fn append_remote_projection(
        &mut self,
        projection: &ProviderRemoteProjection,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.flush().await?;
        let receipt = self
            .runtime
            .append_remote_projection(&self.lease, self.expected_sequence, projection)
            .await?;
        self.expected_sequence =
            receipt
                .run_event_sequence
                .checked_add(1)
                .ok_or(RunRuntimeError::Corrupt {
                    field: "next_event_sequence",
                })?;
        Ok(receipt)
    }

    /// Pending 的最迟 flush 时刻；provider loop 应把它放入同一个 `select!`。
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.accumulator.next_deadline()
    }

    /// Flush 最后一块并写唯一 terminal；相同 expected sequence 可在 commit unknown 后重试。
    pub async fn finish(
        &mut self,
        terminal: RunTerminal,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.flush().await?;
        let receipt = self
            .runtime
            .finish_run(&self.lease, self.expected_sequence, terminal)
            .await?;
        self.expected_sequence =
            receipt
                .run_event_sequence
                .checked_add(1)
                .ok_or(RunRuntimeError::Corrupt {
                    field: "next_event_sequence",
                })?;
        Ok(receipt)
    }

    async fn drain_pending(&mut self) -> Result<(), RunRuntimeError> {
        while let Some((channel, chunk)) = self.pending_durable.front() {
            if chunk.is_empty() || chunk.len() > SEMANTIC_CHUNK_MAX_BYTES {
                return Err(RunRuntimeError::Corrupt {
                    field: "semantic_chunk",
                });
            }
            let receipt = self
                .runtime
                .append_semantic_chunk(&self.lease, self.expected_sequence, *channel, chunk)
                .await?;
            self.expected_sequence =
                receipt
                    .run_event_sequence
                    .checked_add(1)
                    .ok_or(RunRuntimeError::Corrupt {
                        field: "next_event_sequence",
                    })?;
            self.pending_durable.pop_front();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId};
    use openbot_domain::thread::FencingToken;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Chunk(u64, RunSemanticChannel, String),
        Projection(u64, crate::ProviderRemoteProjectionKind),
        Finish(u64, RunTerminal),
    }

    #[derive(Default)]
    struct FakeRuntime {
        calls: Mutex<Vec<Call>>,
        fail_first_chunk: Mutex<bool>,
    }

    impl FakeRuntime {
        fn failing_once() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_first_chunk: Mutex::new(true),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().expect("fake lock").clone()
        }
    }

    #[async_trait]
    impl RunRuntime for FakeRuntime {
        async fn claim_dispatch(&self) -> Result<Option<ClaimedRunDispatch>, RunRuntimeError> {
            Err(RunRuntimeError::Unavailable)
        }

        async fn acknowledge_dispatch(
            &self,
            _claim: &ClaimedRunDispatch,
        ) -> Result<RunExecutionLease, RunRuntimeError> {
            Err(RunRuntimeError::Unavailable)
        }

        async fn retry_dispatch(&self, _claim: &ClaimedRunDispatch) -> Result<(), RunRuntimeError> {
            Err(RunRuntimeError::Unavailable)
        }

        async fn reject_dispatch(
            &self,
            _claim: &ClaimedRunDispatch,
            _code: RunFailureCode,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            Err(RunRuntimeError::Unavailable)
        }

        async fn renew_lease(&self, _lease: &RunExecutionLease) -> Result<(), RunRuntimeError> {
            Ok(())
        }

        async fn append_semantic_chunk(
            &self,
            _lease: &RunExecutionLease,
            expected_sequence: u64,
            channel: RunSemanticChannel,
            chunk: &str,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            self.calls.lock().expect("fake lock").push(Call::Chunk(
                expected_sequence,
                channel,
                chunk.to_owned(),
            ));
            let mut fail = self.fail_first_chunk.lock().expect("fake lock");
            if *fail {
                *fail = false;
                return Err(RunRuntimeError::CommitUnknown);
            }
            Ok(receipt(expected_sequence))
        }

        async fn append_remote_projection(
            &self,
            _lease: &RunExecutionLease,
            expected_sequence: u64,
            projection: &ProviderRemoteProjection,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Projection(expected_sequence, projection.kind()));
            Ok(receipt(expected_sequence))
        }

        async fn finish_run(
            &self,
            _lease: &RunExecutionLease,
            expected_sequence: u64,
            terminal: RunTerminal,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(Call::Finish(expected_sequence, terminal));
            Ok(receipt(expected_sequence))
        }

        async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError> {
            Ok(None)
        }
    }

    fn lease() -> RunExecutionLease {
        RunExecutionLease::new(
            RunId::new("run-1"),
            ThreadId::new("thread-1"),
            BotId::new("bot-1"),
            ActorId::new("actor-1"),
            FencingToken::new(7).unwrap(),
            1,
        )
        .unwrap()
    }

    const fn receipt(sequence: u64) -> RunWriteReceipt {
        RunWriteReceipt {
            run_event_sequence: sequence,
            thread_event_sequence: sequence + 10,
            message_sequence: None,
            replayed: false,
        }
    }

    #[tokio::test]
    async fn eight_kib_chunks_reach_the_port_in_order_before_terminal() {
        let runtime = Arc::new(FakeRuntime::default());
        let mut run = DurableTextRun::new(runtime.clone(), lease());
        let input = "a".repeat(SEMANTIC_CHUNK_MAX_BYTES + 1);
        run.push(&input, Instant::now()).await.unwrap();
        let terminal = run.finish(RunTerminal::Completed).await.unwrap();
        assert_eq!(terminal.run_event_sequence, 3);
        assert_eq!(runtime.calls().len(), 3);
        assert_eq!(
            runtime.calls(),
            [
                Call::Chunk(
                    1,
                    RunSemanticChannel::Text,
                    "a".repeat(SEMANTIC_CHUNK_MAX_BYTES)
                ),
                Call::Chunk(2, RunSemanticChannel::Text, "a".to_owned()),
                Call::Finish(3, RunTerminal::Completed),
            ]
        );
    }

    #[tokio::test]
    async fn remote_projection_flushes_preceding_text_and_advances_the_shared_sequence() {
        let runtime = Arc::new(FakeRuntime::default());
        let mut run = DurableTextRun::new(runtime.clone(), lease());
        run.push("before projection", Instant::now()).await.unwrap();
        let projection = ProviderRemoteProjection::new(
            crate::ProviderRemoteProjectionKind::State,
            None,
            None,
            serde_json::json!({"phase":"working"}),
        )
        .unwrap();
        run.append_remote_projection(&projection).await.unwrap();
        run.finish(RunTerminal::Completed).await.unwrap();
        assert_eq!(
            runtime.calls(),
            [
                Call::Chunk(1, RunSemanticChannel::Text, "before projection".to_owned()),
                Call::Projection(2, crate::ProviderRemoteProjectionKind::State),
                Call::Finish(3, RunTerminal::Completed),
            ]
        );
    }

    #[tokio::test]
    async fn commit_unknown_keeps_the_same_chunk_and_expected_sequence_for_reconciliation() {
        let runtime = Arc::new(FakeRuntime::failing_once());
        let mut run = DurableTextRun::new(runtime.clone(), lease());
        let start = Instant::now();
        run.push("durable", start).await.unwrap();
        assert_eq!(
            run.flush_due(start + crate::chunk::SEMANTIC_CHUNK_MAX_DELAY)
                .await,
            Err(RunRuntimeError::CommitUnknown)
        );
        run.push("", start + crate::chunk::SEMANTIC_CHUNK_MAX_DELAY)
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [
                Call::Chunk(1, RunSemanticChannel::Text, "durable".to_owned()),
                Call::Chunk(1, RunSemanticChannel::Text, "durable".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn reasoning_keeps_provider_order_but_uses_a_distinct_channel() {
        let runtime = Arc::new(FakeRuntime::default());
        let start = Instant::now();
        let mut run = DurableTextRun::new(runtime.clone(), lease());
        run.push("before", start).await.unwrap();
        run.push_reasoning("internal", start + std::time::Duration::from_millis(1))
            .await
            .unwrap();
        run.push("after", start + std::time::Duration::from_millis(2))
            .await
            .unwrap();
        run.finish(RunTerminal::Completed).await.unwrap();
        assert_eq!(
            runtime.calls(),
            [
                Call::Chunk(1, RunSemanticChannel::Text, "before".to_owned()),
                Call::Chunk(2, RunSemanticChannel::Reasoning, "internal".to_owned()),
                Call::Chunk(3, RunSemanticChannel::Text, "after".to_owned()),
                Call::Finish(4, RunTerminal::Completed),
            ]
        );
    }

    #[tokio::test]
    async fn nul_delta_is_rejected_before_the_runtime_port() {
        let runtime = Arc::new(FakeRuntime::default());
        let mut run = DurableTextRun::new(runtime.clone(), lease());
        assert_eq!(
            run.push("bad\0delta", Instant::now()).await,
            Err(RunRuntimeError::InvalidInput { field: "delta" })
        );
        assert!(runtime.calls().is_empty());
    }
}
