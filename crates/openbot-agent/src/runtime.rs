//! Built-in Agent dispatch consumer/host；pure decisions remain in `openbot-domain::agent`。

use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, pending, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use openbot_application::{
    AgentAudit, AgentAuditKind, AgentContextError, AgentContextSource, DurableTextRun,
    NoRemoteInterruptCoordinator, ProviderAdapter, ProviderEvent, ProviderFailure,
    ProviderPortError, ProviderRateCard, ProviderRemoteInterruptBatch, ProviderRemoteResume,
    ProviderRoute, ProviderSession, RemoteInterruptCoordinator, RemoteInterruptError,
    RunCancellationDisposition, RunCostCap, RunDispatchConsumer, RunDispatchDecision,
    RunExecutionLease, RunFailureCode, RunRuntime, RunRuntimeError, RunTerminal,
    RunTokenUsageReceipt, RunToolExchange, StopOutcome, ToolCancellationHandle,
    ToolCancellationReason, tool_execution_cancellation,
};
use openbot_contracts::components::is_component_human_decision_name;
use openbot_domain::agent::{
    AgentEffect, AgentEvent, AgentFailure, AgentState, AgentTerminal, AgentToolCall, reduce,
};
use openbot_domain::tool::metadata::ResourceLockKey;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::gateway::{AgentToolInvokeError, AgentToolInvoker, AgentToolReply, AgentToolScheduling};

/// Upstream parity tool sampling step cap。
pub const TOOL_STEP_CAP: u8 = 8;
/// New absolute run deadline default（v3 §7.2）。
pub const DEFAULT_RUN_DEADLINE: Duration = Duration::from_millis(1_800_000);
/// Thread lease 30s 的三分之一。
pub const DEFAULT_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
/// Bounded shutdown（v3 §13.2）。
pub const AGENT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
/// Default reservation queue。
pub const DEFAULT_AGENT_QUEUE_CAPACITY: usize = 256;
/// Default simultaneous provider runs；独立于 per-thread foreground unique index。
pub const DEFAULT_AGENT_CONCURRENCY: usize = 8;
/// Default process-wide simultaneous tool invocations across all built-in runs.
pub const DEFAULT_AGENT_TOOL_CONCURRENCY: usize = 8;
/// Hard configuration ceiling for process-wide tool concurrency.
pub const MAX_AGENT_TOOL_CONCURRENCY: usize = 256;
/// Bounded grace for a protocol-aware tool to transmit cancellation and stop its child.
const TOOL_CANCELLATION_GRACE: Duration = Duration::from_secs(5);
const PROVIDER_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Built-in runtime configuration。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltInAgentConfig {
    /// Reserved + active runs cap。
    pub queue_capacity: usize,
    /// Provider concurrency。
    pub max_concurrency: usize,
    /// Process-wide active tool invocation cap across every run.
    pub max_tool_concurrency: usize,
    /// Lease heartbeat。
    pub lease_renew_interval: Duration,
    /// `None` = explicitly disabled by OPENBOT_RUN_DEADLINE_MS=0。
    pub run_deadline: Option<Duration>,
}

impl Default for BuiltInAgentConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_AGENT_QUEUE_CAPACITY,
            max_concurrency: DEFAULT_AGENT_CONCURRENCY,
            max_tool_concurrency: DEFAULT_AGENT_TOOL_CONCURRENCY,
            lease_renew_interval: DEFAULT_LEASE_RENEW_INTERVAL,
            run_deadline: Some(DEFAULT_RUN_DEADLINE),
        }
    }
}

impl BuiltInAgentConfig {
    fn validate(self) -> Result<Self, RunFailureCode> {
        if self.queue_capacity == 0
            || self.queue_capacity > 4096
            || self.max_concurrency == 0
            || self.max_concurrency > self.queue_capacity
            || self.max_tool_concurrency == 0
            || self.max_tool_concurrency > MAX_AGENT_TOOL_CONCURRENCY
            || self.lease_renew_interval.is_zero()
            || self.run_deadline.is_some_and(|value| value.is_zero())
        {
            Err(RunFailureCode::AgentRuntimeUnavailable)
        } else {
            Ok(self)
        }
    }
}

/// Lifecycle owner；consumer clone is injected into RunRelay，handle stays in Server main。
pub struct BuiltInAgentRuntime {
    consumer: Arc<BuiltInAgentConsumer>,
    stop: watch::Sender<bool>,
    supervisor: JoinHandle<()>,
}

impl core::fmt::Debug for BuiltInAgentRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuiltInAgentRuntime")
            .finish_non_exhaustive()
    }
}

impl BuiltInAgentRuntime {
    /// Start bounded supervisor。
    pub fn start(
        runtime: Arc<dyn RunRuntime>,
        context: Arc<dyn AgentContextSource>,
        provider: Arc<dyn ProviderAdapter>,
        tools: Arc<dyn AgentToolInvoker>,
        audit: Arc<dyn AgentAudit>,
        config: BuiltInAgentConfig,
    ) -> Result<Self, RunFailureCode> {
        Self::start_with_remote_interrupts(
            runtime,
            context,
            provider,
            tools,
            audit,
            Arc::new(NoRemoteInterruptCoordinator),
            config,
        )
    }

    /// Start with a durable remote AG-UI interrupt coordinator.
    pub fn start_with_remote_interrupts(
        runtime: Arc<dyn RunRuntime>,
        context: Arc<dyn AgentContextSource>,
        provider: Arc<dyn ProviderAdapter>,
        tools: Arc<dyn AgentToolInvoker>,
        audit: Arc<dyn AgentAudit>,
        remote_interrupts: Arc<dyn RemoteInterruptCoordinator>,
        config: BuiltInAgentConfig,
    ) -> Result<Self, RunFailureCode> {
        let config = config.validate()?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let (stop, stop_rx) = watch::channel(false);
        let inner = Arc::new(Inner {
            runtime,
            context,
            provider,
            tools,
            audit,
            remote_interrupts,
            config,
            sender,
            reservations: Mutex::new(BTreeMap::new()),
            semaphore: Arc::new(Semaphore::new(config.max_concurrency)),
            tool_semaphore: Arc::new(Semaphore::new(config.max_tool_concurrency)),
            tool_resources: Arc::new(ToolResourceLocks::default()),
            stopped: AtomicBool::new(false),
        });
        let consumer = Arc::new(BuiltInAgentConsumer {
            inner: inner.clone(),
        });
        let supervisor = tokio::spawn(supervise(inner, receiver, stop_rx));
        Ok(Self {
            consumer,
            stop,
            supervisor,
        })
    }

    /// Consumer for production RunRelay。
    #[must_use]
    pub fn consumer(&self) -> Arc<dyn RunDispatchConsumer> {
        self.consumer.clone()
    }

    /// Cancel every active run and wait at most 5 seconds。
    pub async fn stop(self) {
        self.consumer.inner.stopped.store(true, Ordering::SeqCst);
        self.stop.send_replace(true);
        let _ = self.supervisor.await;
    }
}

/// Idempotent reserve/activate/revoke implementation。
pub struct BuiltInAgentConsumer {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for BuiltInAgentConsumer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuiltInAgentConsumer")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RunDispatchConsumer for BuiltInAgentConsumer {
    async fn dispatch(&self, lease: RunExecutionLease) -> RunDispatchDecision {
        if self.inner.stopped.load(Ordering::SeqCst) {
            return RunDispatchDecision::Rejected(RunFailureCode::AgentRuntimeUnavailable);
        }
        let mut reservations = self.inner.reservations.lock().await;
        let key = lease.run_id().as_str().to_owned();
        if let Some(existing) = reservations.get(&key) {
            return if existing.lease == lease {
                RunDispatchDecision::Accepted
            } else {
                RunDispatchDecision::Rejected(RunFailureCode::DispatchPayloadCorrupt)
            };
        }
        if reservations.len() >= self.inner.config.queue_capacity {
            return RunDispatchDecision::RetryableBusy;
        }
        let (cancel, _) = watch::channel(false);
        reservations.insert(
            key,
            Reservation {
                lease,
                cancel,
                active: false,
            },
        );
        RunDispatchDecision::Accepted
    }

    async fn activate(&self, lease: &RunExecutionLease) -> Result<(), RunFailureCode> {
        let mut reservations = self.inner.reservations.lock().await;
        let Some(reservation) = reservations.get_mut(lease.run_id().as_str()) else {
            return Err(RunFailureCode::AgentRuntimeUnavailable);
        };
        if reservation.lease != *lease {
            return Err(RunFailureCode::DispatchPayloadCorrupt);
        }
        if reservation.active {
            return Ok(());
        }
        let activation = Activation {
            lease: lease.clone(),
            cancel: reservation.cancel.subscribe(),
        };
        if self.inner.sender.try_send(activation).is_err() {
            reservations.remove(lease.run_id().as_str());
            return Err(RunFailureCode::AgentRuntimeUnavailable);
        }
        reservation.active = true;
        Ok(())
    }

    async fn revoke(&self, lease: &RunExecutionLease) -> RunCancellationDisposition {
        let mut reservations = self.inner.reservations.lock().await;
        if reservations
            .get(lease.run_id().as_str())
            .is_some_and(|reservation| reservation.lease == *lease)
            && let Some(reservation) = reservations.remove(lease.run_id().as_str())
        {
            reservation.cancel.send_replace(true);
            return RunCancellationDisposition::ChildSignalled;
        }
        RunCancellationDisposition::NoLocalChild
    }
}

struct Inner {
    runtime: Arc<dyn RunRuntime>,
    context: Arc<dyn AgentContextSource>,
    provider: Arc<dyn ProviderAdapter>,
    tools: Arc<dyn AgentToolInvoker>,
    audit: Arc<dyn AgentAudit>,
    remote_interrupts: Arc<dyn RemoteInterruptCoordinator>,
    config: BuiltInAgentConfig,
    sender: mpsc::Sender<Activation>,
    reservations: Mutex<BTreeMap<String, Reservation>>,
    semaphore: Arc<Semaphore>,
    tool_semaphore: Arc<Semaphore>,
    tool_resources: Arc<ToolResourceLocks>,
    stopped: AtomicBool,
}

struct Reservation {
    lease: RunExecutionLease,
    cancel: watch::Sender<bool>,
    active: bool,
}

struct Activation {
    lease: RunExecutionLease,
    cancel: watch::Receiver<bool>,
}

#[derive(Default)]
struct ToolResourceLocks {
    entries: std::sync::Mutex<BTreeMap<ResourceLockKey, Weak<Semaphore>>>,
}

impl ToolResourceLocks {
    async fn acquire(
        &self,
        keys: &[ResourceLockKey],
    ) -> Result<Vec<OwnedSemaphorePermit>, AgentToolInvokeError> {
        let semaphores = {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| AgentToolInvokeError::Unavailable)?;
            entries.retain(|_, semaphore| semaphore.strong_count() > 0);
            let mut semaphores = Vec::with_capacity(keys.len());
            for key in keys {
                let semaphore = entries.get(key).and_then(Weak::upgrade).unwrap_or_else(|| {
                    let semaphore = Arc::new(Semaphore::new(1));
                    entries.insert(key.clone(), Arc::downgrade(&semaphore));
                    semaphore
                });
                semaphores.push(semaphore);
            }
            semaphores
        };
        let mut permits = Vec::with_capacity(semaphores.len());
        for semaphore in semaphores {
            permits.push(
                semaphore
                    .acquire_owned()
                    .await
                    .map_err(|_| AgentToolInvokeError::Unavailable)?,
            );
        }
        Ok(permits)
    }
}

struct ToolBudgetPermit {
    _resources: Vec<OwnedSemaphorePermit>,
    _concurrency: OwnedSemaphorePermit,
}

async fn acquire_tool_budget(
    semaphore: Arc<Semaphore>,
    resources: Arc<ToolResourceLocks>,
    scheduling: AgentToolScheduling,
) -> Result<ToolBudgetPermit, AgentToolInvokeError> {
    let resource_permits = resources.acquire(scheduling.resource_locks()).await?;
    let concurrency = semaphore
        .acquire_owned()
        .await
        .map_err(|_| AgentToolInvokeError::Unavailable)?;
    Ok(ToolBudgetPermit {
        _resources: resource_permits,
        _concurrency: concurrency,
    })
}

struct ScheduledToolCall {
    call: AgentToolCall,
    scheduling: AgentToolScheduling,
}

struct ToolWave {
    parallel: bool,
    calls: Vec<ScheduledToolCall>,
}

struct ToolRunControl<'a> {
    cancel: &'a mut watch::Receiver<bool>,
    lease: &'a RunExecutionLease,
    renew: &'a mut tokio::time::Interval,
    deadline: Option<tokio::time::Instant>,
}

fn schedule_tool_waves(tools: &dyn AgentToolInvoker, calls: Vec<AgentToolCall>) -> Vec<ToolWave> {
    let mut waves = Vec::new();
    let mut parallel_calls = Vec::new();
    let mut held_resources = BTreeSet::new();
    let flush_parallel = |waves: &mut Vec<ToolWave>, calls: &mut Vec<ScheduledToolCall>| {
        if !calls.is_empty() {
            waves.push(ToolWave {
                parallel: true,
                calls: core::mem::take(calls),
            });
        }
    };

    for call in calls {
        let scheduling = tools.scheduling(&call.name);
        let human = is_component_human_decision_name(&call.name);
        if human || !scheduling.is_parallel_safe() {
            flush_parallel(&mut waves, &mut parallel_calls);
            held_resources.clear();
            waves.push(ToolWave {
                parallel: false,
                calls: vec![ScheduledToolCall { call, scheduling }],
            });
            continue;
        }
        let conflicts = scheduling
            .resource_locks()
            .iter()
            .any(|key| held_resources.contains(key));
        if conflicts {
            flush_parallel(&mut waves, &mut parallel_calls);
            held_resources.clear();
        }
        held_resources.extend(scheduling.resource_locks().iter().cloned());
        parallel_calls.push(ScheduledToolCall { call, scheduling });
    }
    flush_parallel(&mut waves, &mut parallel_calls);
    waves
}

#[derive(Clone, Copy)]
enum CancellationSource {
    User,
    Deadline,
}

enum ControlledChild<T> {
    Ready(T),
    Cancelled(CancellationSource),
    LeaseLost,
}

enum SamplingOutcome {
    Tools(Vec<AgentToolCall>),
    Interrupted(ProviderRemoteInterruptBatch),
}

async fn supervise(
    inner: Arc<Inner>,
    mut receiver: mpsc::Receiver<Activation>,
    mut stop: watch::Receiver<bool>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            activation = receiver.recv() => match activation {
                Some(activation) => {
                    let inner = inner.clone();
                    tasks.spawn(async move {
                        execute_activation(inner.clone(), activation).await;
                    });
                }
                None => break,
            },
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::error!(error = %error, "built-in Agent task panic/cancel");
                }
            }
        }
    }
    inner.stopped.store(true, Ordering::SeqCst);
    {
        let reservations = inner.reservations.lock().await;
        for reservation in reservations.values() {
            reservation.cancel.send_replace(true);
        }
    }
    let deadline = tokio::time::Instant::now() + AGENT_SHUTDOWN_DEADLINE;
    while !tasks.is_empty() {
        if tokio::time::timeout_at(deadline, tasks.join_next())
            .await
            .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            break;
        }
    }
    inner.reservations.lock().await.clear();
}

async fn execute_activation(inner: Arc<Inner>, mut activation: Activation) {
    if *activation.cancel.borrow() {
        cancel_before_execution(&inner, &activation.lease).await;
        return;
    }
    let permit = tokio::select! {
        changed = activation.cancel.changed() => {
            if changed.is_err() || *activation.cancel.borrow() {
                cancel_before_execution(&inner, &activation.lease).await;
                return;
            }
            return;
        }
        permit = inner.semaphore.clone().acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(_) => {
                cleanup(&inner, &activation.lease).await;
                return;
            }
        }
    };
    let _permit = permit;
    execute_run(&inner, &mut activation).await;
    inner.tools.release(activation.lease.run_id());
    cleanup(&inner, &activation.lease).await;
}

async fn cancel_before_execution(inner: &Inner, lease: &RunExecutionLease) {
    let mut state = AgentState::queued(lease.run_id().clone());
    let mut journal = DurableTextRun::new(inner.runtime.clone(), lease.clone());
    cancel_and_commit(
        &mut state,
        &mut journal,
        inner.audit.as_ref(),
        lease,
        CancellationSource::User,
    )
    .await;
    inner.tools.release(lease.run_id());
    cleanup(inner, lease).await;
}

async fn cleanup(inner: &Inner, lease: &RunExecutionLease) {
    let mut reservations = inner.reservations.lock().await;
    if reservations
        .get(lease.run_id().as_str())
        .is_some_and(|reservation| reservation.lease == *lease)
    {
        reservations.remove(lease.run_id().as_str());
    }
}

async fn execute_run(inner: &Inner, activation: &mut Activation) {
    let lease = &activation.lease;
    let mut state = AgentState::queued(lease.run_id().clone());
    let Ok((next, effects)) = reduce(&state, AgentEvent::DispatchActivated) else {
        return;
    };
    state = next;
    if !matches!(effects.as_slice(), [AgentEffect::LoadContext]) {
        return;
    }
    let mut journal = DurableTextRun::new(inner.runtime.clone(), lease.clone());
    let mut sampling_index = 0_u32;
    let mut run_output_ceiling = None::<Option<u64>>;
    let mut run_rate_card = None::<Option<ProviderRateCard>>;
    let mut run_cost_cap = None::<Option<RunCostCap>>;
    let mut current_protocol_run_id = lease.run_id().as_str().to_owned();
    let mut pending_remote_resume = None::<ProviderRemoteResume>;
    let mut bound_remote_endpoint = None::<String>;
    // The outer option distinguishes the first sampling from a marker-free run. Once a run
    // starts custom, no later load may change its identity/configuration or return a legacy route.
    let mut bound_custom_model = None::<Option<openbot_application::RunModelBinding>>;
    if inner
        .audit
        .record(lease, AgentAuditKind::Invoked)
        .await
        .is_err()
    {
        drive_terminal_event(&mut state, &mut journal, AgentEvent::JournalCommitUnknown).await;
        return;
    }
    let mut renew = tokio::time::interval(inner.config.lease_renew_interval);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renew.tick().await;
    let deadline = inner
        .config
        .run_deadline
        .map(|duration| tokio::time::Instant::now() + duration);
    loop {
        // The run-wide output ceiling is derived from at most nine provider invocations
        // (initial + eight continuations). Interrupt resumes consume the same continuation
        // budget as tool-result resampling, so disabling the wall-clock deadline cannot create
        // an unbounded remote human loop or an unbounded native interrupt table.
        if sampling_index > u32::from(TOOL_STEP_CAP) {
            drive_terminal_event(
                &mut state,
                &mut journal,
                AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
            )
            .await;
            return;
        }
        let mut request = match await_run_child(
            inner.context.load(lease),
            &mut activation.cancel,
            &mut renew,
            deadline,
            inner.runtime.as_ref(),
            lease,
        )
        .await
        {
            ControlledChild::Ready(Ok(request)) => request,
            ControlledChild::Ready(Err(error)) => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(context_failure(error)),
                )
                .await;
                return;
            }
            ControlledChild::Cancelled(source) => {
                cancel_and_commit(
                    &mut state,
                    &mut journal,
                    inner.audit.as_ref(),
                    lease,
                    source,
                )
                .await;
                return;
            }
            ControlledChild::LeaseLost => {
                drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                return;
            }
        };
        if !bind_custom_model(&mut bound_custom_model, &request, lease) {
            drive_terminal_event(
                &mut state,
                &mut journal,
                AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
            )
            .await;
            return;
        }
        if let Some(resume) = pending_remote_resume.take() {
            let next_protocol_run_id = resume.protocol_run_id().to_owned();
            let fresh_route = match &request.route {
                ProviderRoute::RemoteAgUi(route)
                    if route.local_run_id() == lease.run_id().as_str() =>
                {
                    route
                        .clone()
                        .with_fresh_resume(&current_protocol_run_id, resume)
                }
                _ => Err(AgentContextError::Corrupt {
                    field: "remote_resume_route",
                }),
            };
            let route = match fresh_route {
                Ok(route) => route,
                Err(error) => {
                    drive_terminal_event(
                        &mut state,
                        &mut journal,
                        AgentEvent::ContextFailed(context_failure(error)),
                    )
                    .await;
                    return;
                }
            };
            request.route = ProviderRoute::RemoteAgUi(route);
            current_protocol_run_id = next_protocol_run_id;
        }
        match &request.route {
            ProviderRoute::RemoteAgUi(route)
                if route.local_run_id() != lease.run_id().as_str()
                    || route.thread_id() != lease.thread_id().as_str()
                    || route.bot_id() != lease.bot_id().as_str() =>
            {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return;
            }
            ProviderRoute::RemoteAgUi(route) => match &bound_remote_endpoint {
                None => bound_remote_endpoint = Some(route.endpoint().to_owned()),
                Some(endpoint) if endpoint == route.endpoint() => {}
                Some(_) => {
                    drive_terminal_event(
                        &mut state,
                        &mut journal,
                        AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                    )
                    .await;
                    return;
                }
            },
            _ if bound_remote_endpoint.is_some() => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return;
            }
            _ => {}
        }
        let max_output_tokens = request.max_output_tokens;
        let candidate_rate_card = request.rate_card.clone();
        let candidate_cost_cap = request.cost_cap.clone();
        if let Some(cap) = &candidate_cost_cap {
            match &candidate_rate_card {
                None => {
                    reject_cost_budget_before_provider(
                        &mut state,
                        &mut journal,
                        inner.audit.as_ref(),
                        lease,
                        AgentFailure::RunCostBudgetUnpriced,
                        AgentAuditKind::RunCostBudgetUnpriced,
                    )
                    .await;
                    return;
                }
                Some(rate) if rate.currency() != cap.currency() => {
                    reject_cost_budget_before_provider(
                        &mut state,
                        &mut journal,
                        inner.audit.as_ref(),
                        lease,
                        AgentFailure::RunCostBudgetCurrencyMismatch,
                        AgentAuditKind::RunCostBudgetCurrencyMismatch,
                    )
                    .await;
                    return;
                }
                Some(_) => {}
            }
        }
        let candidate_run_output_ceiling =
            max_output_tokens.map(|limit| u64::from(limit) * (u64::from(TOOL_STEP_CAP) + 1));
        match run_output_ceiling {
            None => run_output_ceiling = Some(candidate_run_output_ceiling),
            Some(existing) if existing == candidate_run_output_ceiling => {}
            Some(_) => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return;
            }
        }
        match &run_rate_card {
            None => run_rate_card = Some(candidate_rate_card),
            Some(existing) if *existing == candidate_rate_card => {}
            Some(_) => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return;
            }
        }
        match &run_cost_cap {
            None => run_cost_cap = Some(candidate_cost_cap),
            Some(existing) if *existing == candidate_cost_cap => {}
            Some(_) => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ContextFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return;
            }
        }
        let Ok((next, effects)) = reduce(&state, AgentEvent::ContextPrepared) else {
            return;
        };
        state = next;
        if !matches!(effects.as_slice(), [AgentEffect::StartProvider]) {
            return;
        }
        let session = match await_run_child(
            inner.provider.start(request),
            &mut activation.cancel,
            &mut renew,
            deadline,
            inner.runtime.as_ref(),
            lease,
        )
        .await
        {
            ControlledChild::Ready(result) => result,
            ControlledChild::Cancelled(source) => {
                cancel_and_commit(
                    &mut state,
                    &mut journal,
                    inner.audit.as_ref(),
                    lease,
                    source,
                )
                .await;
                return;
            }
            ControlledChild::LeaseLost => {
                drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                return;
            }
        };
        let mut session = match session {
            Ok(session) => session,
            Err(error) => {
                drive_terminal_event(
                    &mut state,
                    &mut journal,
                    AgentEvent::ProviderFailed(provider_port_failure(error)),
                )
                .await;
                return;
            }
        };
        let mut usage_seen = false;
        // Context, reasoning and earlier provider invocations cannot supply this answer.
        let mut current_text_seen = false;
        let mut pending_tools = BTreeMap::<u32, AgentToolCall>::new();
        let calls = loop {
            let chunk_deadline = journal.next_deadline().map(tokio::time::Instant::from_std);
            tokio::select! {
                changed = activation.cancel.changed() => {
                    if changed.is_err() || *activation.cancel.borrow() {
                        let stopped = request_provider_stop(session.as_mut(), deadline, &mut renew,
                            inner.runtime.as_ref(), lease, false).await;
                        drop(session);
                        if stopped.lease_lost {
                            drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                        } else if stopped.outcome == StopOutcome::Unknown {
                            commit_provider_stop_unknown(&mut state, &mut journal, inner.audit.as_ref(),
                                lease, None).await;
                        } else {
                            cancel_and_commit(
                                &mut state,
                                &mut journal,
                                inner.audit.as_ref(),
                                lease,
                                CancellationSource::User,
                            ).await;
                        }
                        return;
                    }
                }
                () = wait_optional(deadline) => {
                    let stopped = request_provider_stop(session.as_mut(), deadline, &mut renew,
                        inner.runtime.as_ref(), lease, false).await;
                    drop(session);
                    if stopped.lease_lost {
                        drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                    } else if stopped.outcome == StopOutcome::Unknown {
                        commit_provider_stop_unknown(&mut state, &mut journal, inner.audit.as_ref(),
                            lease, Some(AgentAuditKind::RunDeadlineExceeded)).await;
                    } else {
                        cancel_and_commit(
                            &mut state,
                            &mut journal,
                            inner.audit.as_ref(),
                            lease,
                            CancellationSource::Deadline,
                        ).await;
                    }
                    return;
                }
                _ = renew.tick() => {
                    if inner.runtime.renew_lease(lease).await.is_err() {
                        request_provider_stop(session.as_mut(), deadline, &mut renew,
                            inner.runtime.as_ref(), lease, true).await;
                        drop(session);
                        drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                        return;
                    }
                }
                () = wait_optional(chunk_deadline) => {
                    if let Err(error) = journal.flush_due(Instant::now()).await {
                        drop(session);
                        journal_failure(&mut state, &mut journal, error).await;
                        return;
                    }
                }
                event = session.next_event() => match event {
                    Ok(Some(ProviderEvent::ToolCallCompleted {
                        index,
                        call_id,
                        name,
                        arguments,
                    })) => {
                        if pending_tools.values().any(|call| call.call_id == call_id)
                            || pending_tools
                                .insert(index, AgentToolCall { call_id, name, arguments })
                                .is_some()
                        {
                            drive_terminal_event(
                                &mut state,
                                &mut journal,
                                AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                            ).await;
                            return;
                        }
                    }
                    Ok(Some(ProviderEvent::Completed)) if !pending_tools.is_empty() => {
                        if max_output_tokens.is_some() && !usage_seen {
                            drive_terminal_event(
                                &mut state,
                                &mut journal,
                                AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                            ).await;
                            return;
                        }
                        break SamplingOutcome::Tools(
                            pending_tools.into_values().collect::<Vec<_>>(),
                        );
                    }
                    Ok(Some(ProviderEvent::Interrupted(batch))) => {
                        if !pending_tools.is_empty()
                            || (max_output_tokens.is_some() && !usage_seen)
                            || batch.protocol_run_id() != current_protocol_run_id
                        {
                            drive_terminal_event(
                                &mut state,
                                &mut journal,
                                AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                            ).await;
                            return;
                        }
                        break SamplingOutcome::Interrupted(batch);
                    }
                    Ok(Some(ProviderEvent::Failed(ProviderFailure::StreamStalled))) => {
                        let stopped = request_provider_stop(session.as_mut(), deadline, &mut renew,
                            inner.runtime.as_ref(), lease, false).await;
                        drop(session);
                        if stopped.lease_lost {
                            drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                        } else if stopped.outcome == StopOutcome::Unknown {
                            commit_provider_stop_unknown(&mut state, &mut journal, inner.audit.as_ref(),
                                lease, Some(AgentAuditKind::StreamStalled)).await;
                        } else {
                            let sampling = ProviderSamplingContext {
                                max_output_tokens, usage_seen: &mut usage_seen,
                                current_text_seen: &mut current_text_seen,
                                runtime: inner.runtime.as_ref(), lease, sampling_index,
                                max_run_output_tokens: run_output_ceiling.flatten(),
                                rate_card: run_rate_card.as_ref().and_then(Option::as_ref),
                                cost_cap: run_cost_cap.as_ref().and_then(Option::as_ref),
                                audit: inner.audit.as_ref(),
                            };
                            handle_provider_event(&mut state, &mut journal,
                                ProviderEvent::Failed(ProviderFailure::StreamStalled), sampling).await;
                        }
                        return;
                    }
                    Ok(Some(event)) => {
                        let sampling = ProviderSamplingContext {
                            max_output_tokens,
                            usage_seen: &mut usage_seen,
                            current_text_seen: &mut current_text_seen,
                            runtime: inner.runtime.as_ref(),
                            lease,
                            sampling_index,
                            max_run_output_tokens: run_output_ceiling.flatten(),
                            rate_card: run_rate_card.as_ref().and_then(Option::as_ref),
                            cost_cap: run_cost_cap.as_ref().and_then(Option::as_ref),
                            audit: inner.audit.as_ref(),
                        };
                        if handle_provider_event(
                            &mut state,
                            &mut journal,
                            event,
                            sampling,
                        ).await {
                            return;
                        }
                    }
                    Ok(None) => {
                        drive_terminal_event(
                            &mut state,
                            &mut journal,
                            AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                        ).await;
                        return;
                    }
                    Err(error) => {
                        drive_terminal_event(
                            &mut state,
                            &mut journal,
                            AgentEvent::ProviderFailed(provider_port_failure(error)),
                        ).await;
                        return;
                    }
                }
            }
        };
        drop(session);
        let calls = match calls {
            SamplingOutcome::Tools(calls) => calls,
            SamplingOutcome::Interrupted(batch) => {
                let Ok((next, effects)) = reduce(&state, AgentEvent::HumanRequired) else {
                    return;
                };
                state = next;
                if !matches!(effects.as_slice(), [AgentEffect::AwaitHuman]) {
                    return;
                }
                let resume = match await_run_child(
                    inner.remote_interrupts.persist_and_wait(lease, &batch),
                    &mut activation.cancel,
                    &mut renew,
                    deadline,
                    inner.runtime.as_ref(),
                    lease,
                )
                .await
                {
                    ControlledChild::Ready(Ok(resume)) => resume,
                    ControlledChild::Ready(Err(RemoteInterruptError::Stale)) => {
                        drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                        return;
                    }
                    ControlledChild::Ready(Err(RemoteInterruptError::CommitUnknown)) => {
                        drive_terminal_event(
                            &mut state,
                            &mut journal,
                            AgentEvent::JournalCommitUnknown,
                        )
                        .await;
                        return;
                    }
                    ControlledChild::Ready(Err(RemoteInterruptError::Unavailable)) => {
                        drive_terminal_event(
                            &mut state,
                            &mut journal,
                            AgentEvent::RemoteResumeFailed(AgentFailure::ProviderUnavailable),
                        )
                        .await;
                        return;
                    }
                    ControlledChild::Ready(Err(
                        RemoteInterruptError::Conflict | RemoteInterruptError::Corrupt { .. },
                    )) => {
                        drive_terminal_event(
                            &mut state,
                            &mut journal,
                            AgentEvent::RemoteResumeFailed(AgentFailure::ProviderInvalidResponse),
                        )
                        .await;
                        return;
                    }
                    ControlledChild::Cancelled(source) => {
                        cancel_and_commit(
                            &mut state,
                            &mut journal,
                            inner.audit.as_ref(),
                            lease,
                            source,
                        )
                        .await;
                        return;
                    }
                    ControlledChild::LeaseLost => {
                        drive_terminal_event(&mut state, &mut journal, AgentEvent::LeaseLost).await;
                        return;
                    }
                };
                if resume.parent_protocol_run_id() != batch.protocol_run_id() {
                    drive_terminal_event(
                        &mut state,
                        &mut journal,
                        AgentEvent::RemoteResumeFailed(AgentFailure::ProviderInvalidResponse),
                    )
                    .await;
                    return;
                }
                let Ok((next, effects)) = reduce(&state, AgentEvent::RemoteResumeReady) else {
                    return;
                };
                state = next;
                if !matches!(effects.as_slice(), [AgentEffect::LoadContext]) {
                    return;
                }
                pending_remote_resume = Some(resume);
                let Some(next_sampling_index) = sampling_index.checked_add(1) else {
                    drive_terminal_event(
                        &mut state,
                        &mut journal,
                        AgentEvent::ContextFailed(AgentFailure::RunTokenBudgetExceeded),
                    )
                    .await;
                    return;
                };
                sampling_index = next_sampling_index;
                continue;
            }
        };
        let Ok((next, effects)) = reduce(&state, AgentEvent::ProviderToolCalls(calls)) else {
            return;
        };
        state = next;
        let mut effects = effects.into_iter();
        let Some(AgentEffect::InvokeTools(calls)) = effects.next() else {
            return;
        };
        if effects.next().is_some() {
            return;
        }
        {
            let mut control = ToolRunControl {
                cancel: &mut activation.cancel,
                lease,
                renew: &mut renew,
                deadline,
            };
            for wave in schedule_tool_waves(inner.tools.as_ref(), calls) {
                if !execute_tool_wave(inner, &mut state, &mut journal, &mut control, wave).await {
                    return;
                }
            }
        }
        let Ok((next, effects)) = reduce(&state, AgentEvent::ToolResultCommitted) else {
            return;
        };
        state = next;
        if !matches!(effects.as_slice(), [AgentEffect::LoadContext]) {
            return;
        }
        let Some(next_sampling_index) = sampling_index.checked_add(1) else {
            drive_terminal_event(
                &mut state,
                &mut journal,
                AgentEvent::ProviderFailed(AgentFailure::RunTokenBudgetExceeded),
            )
            .await;
            return;
        };
        sampling_index = next_sampling_index;
    }
}

async fn execute_tool_wave(
    inner: &Inner,
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    control: &mut ToolRunControl<'_>,
    wave: ToolWave,
) -> bool {
    if !wave.parallel {
        for scheduled in wave.calls {
            let Some((call, reply)) =
                invoke_serial_tool(inner, state, journal, control, scheduled).await
            else {
                return false;
            };
            if !append_tool_reply(state, journal, call, reply).await {
                return false;
            }
        }
        return true;
    }
    if wave.calls.len() == 1 {
        let scheduled = wave.calls.into_iter().next().expect("one tool call");
        let Some((call, reply)) =
            invoke_serial_tool(inner, state, journal, control, scheduled).await
        else {
            return false;
        };
        return append_tool_reply(state, journal, call, reply).await;
    }

    let Some(outputs) = invoke_parallel_tool_wave(inner, state, journal, control, wave.calls).await
    else {
        return false;
    };
    for (call, outcome) in outputs {
        let reply = match outcome {
            Ok(reply) => reply,
            Err(AgentToolInvokeError::ReconciliationRequired) => {
                drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
                return false;
            }
            Err(AgentToolInvokeError::Unavailable) => {
                drive_terminal_event(state, journal, AgentEvent::ToolRuntimeUnavailable).await;
                return false;
            }
        };
        if !append_tool_reply(state, journal, call, reply).await {
            return false;
        }
    }
    true
}

async fn invoke_serial_tool(
    inner: &Inner,
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    control: &mut ToolRunControl<'_>,
    scheduled: ScheduledToolCall,
) -> Option<(AgentToolCall, AgentToolReply)> {
    let lease = control.lease;
    let waits_for_human = is_component_human_decision_name(&scheduled.call.name);
    if waits_for_human {
        let Ok((next, effects)) = reduce(state, AgentEvent::HumanRequired) else {
            return None;
        };
        *state = next;
        if !matches!(effects.as_slice(), [AgentEffect::AwaitHuman]) {
            return None;
        }
    }

    let budget = match await_run_child(
        acquire_tool_budget(
            inner.tool_semaphore.clone(),
            inner.tool_resources.clone(),
            scheduled.scheduling,
        ),
        control.cancel,
        control.renew,
        control.deadline,
        inner.runtime.as_ref(),
        lease,
    )
    .await
    {
        ControlledChild::Ready(Ok(budget)) => budget,
        ControlledChild::Ready(Err(_)) => {
            drive_terminal_event(state, journal, AgentEvent::ToolRuntimeUnavailable).await;
            return None;
        }
        ControlledChild::Cancelled(source) => {
            cancel_and_commit(state, journal, inner.audit.as_ref(), lease, source).await;
            return None;
        }
        ControlledChild::LeaseLost => {
            drive_terminal_event(state, journal, AgentEvent::LeaseLost).await;
            return None;
        }
    };

    let call = scheduled.call;
    let arguments = call.arguments.clone();
    let tools = inner.tools.clone();
    let invocation_lease = lease.clone();
    let provider_call_id = call.call_id.clone();
    let tool_name = call.name.clone();
    let (tool_cancel, tool_cancellation) = tool_execution_cancellation();
    let invocation = async move {
        let _budget = budget;
        tools
            .invoke_cancellable(
                &invocation_lease,
                &provider_call_id,
                &tool_name,
                arguments,
                tool_cancellation,
            )
            .await
    };
    let outcome = if waits_for_human {
        // The permit moves into the detached task as well: a cancelled human waiter remains inside
        // the global tool budget until PostgreSQL reports terminal retirement.
        match await_run_child(
            tokio::spawn(invocation),
            control.cancel,
            control.renew,
            control.deadline,
            inner.runtime.as_ref(),
            lease,
        )
        .await
        {
            ControlledChild::Ready(Ok(result)) => ControlledChild::Ready(result),
            ControlledChild::Ready(Err(error)) => {
                tracing::error!(
                    cancelled = error.is_cancelled(),
                    "component human-decision task ended without a result"
                );
                ControlledChild::Ready(Err(AgentToolInvokeError::Unavailable))
            }
            ControlledChild::Cancelled(source) => ControlledChild::Cancelled(source),
            ControlledChild::LeaseLost => ControlledChild::LeaseLost,
        }
    } else {
        match await_cancellable_tool_task(
            tokio::spawn(invocation),
            &tool_cancel,
            control.cancel,
            control.renew,
            control.deadline,
            inner.runtime.as_ref(),
            lease,
        )
        .await
        {
            ControlledChild::Ready(Ok(result)) => ControlledChild::Ready(result),
            ControlledChild::Ready(Err(error)) => {
                tracing::error!(
                    cancelled = error.is_cancelled(),
                    "tool invocation task ended without a result"
                );
                ControlledChild::Ready(Err(AgentToolInvokeError::Unavailable))
            }
            ControlledChild::Cancelled(source) => ControlledChild::Cancelled(source),
            ControlledChild::LeaseLost => ControlledChild::LeaseLost,
        }
    };
    if waits_for_human && matches!(&outcome, ControlledChild::Ready(_)) {
        let Ok((next, effects)) = reduce(state, AgentEvent::HumanReleased) else {
            return None;
        };
        *state = next;
        if !effects.is_empty() {
            return None;
        }
    }
    match outcome {
        ControlledChild::Ready(Ok(reply)) => Some((call, reply)),
        ControlledChild::Ready(Err(AgentToolInvokeError::ReconciliationRequired)) => {
            drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
            None
        }
        ControlledChild::Ready(Err(AgentToolInvokeError::Unavailable)) => {
            drive_terminal_event(state, journal, AgentEvent::ToolRuntimeUnavailable).await;
            None
        }
        ControlledChild::Cancelled(source) => {
            if waits_for_human {
                cancel_and_commit(state, journal, inner.audit.as_ref(), lease, source).await;
            } else {
                tool_interrupted(state, journal, inner.audit.as_ref(), lease, source).await;
            }
            None
        }
        ControlledChild::LeaseLost => {
            drive_terminal_event(state, journal, AgentEvent::LeaseLost).await;
            None
        }
    }
}

type ParallelToolOutcome = (
    usize,
    AgentToolCall,
    Result<AgentToolReply, AgentToolInvokeError>,
);

async fn invoke_parallel_tool_wave(
    inner: &Inner,
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    control: &mut ToolRunControl<'_>,
    calls: Vec<ScheduledToolCall>,
) -> Option<Vec<(AgentToolCall, Result<AgentToolReply, AgentToolInvokeError>)>> {
    let lease = control.lease;
    let ever_started = Arc::new(AtomicBool::new(false));
    let mut tasks = JoinSet::<ParallelToolOutcome>::new();
    let count = calls.len();
    for (position, scheduled) in calls.into_iter().enumerate() {
        let tools = inner.tools.clone();
        let invocation_lease = lease.clone();
        let tool_semaphore = inner.tool_semaphore.clone();
        let tool_resources = inner.tool_resources.clone();
        let started = ever_started.clone();
        tasks.spawn(async move {
            let call = scheduled.call;
            let arguments = call.arguments.clone();
            let budget =
                acquire_tool_budget(tool_semaphore, tool_resources, scheduled.scheduling).await;
            let outcome = match budget {
                Ok(budget) => {
                    started.store(true, Ordering::Release);
                    let _budget = budget;
                    tools
                        .invoke(&invocation_lease, &call.call_id, &call.name, arguments)
                        .await
                }
                Err(error) => Err(error),
            };
            (position, call, outcome)
        });
    }

    let mut outputs = core::iter::repeat_with(|| None)
        .take(count)
        .collect::<Vec<Option<(AgentToolCall, Result<AgentToolReply, AgentToolInvokeError>)>>>();
    while !tasks.is_empty() {
        tokio::select! {
            changed = control.cancel.changed() => {
                if changed.is_err() || *control.cancel.borrow() {
                    abort_tool_tasks(&mut tasks).await;
                    if ever_started.load(Ordering::Acquire) {
                        tool_interrupted(
                            state,
                            journal,
                            inner.audit.as_ref(),
                            lease,
                            CancellationSource::User,
                        ).await;
                    } else {
                        cancel_and_commit(
                            state,
                            journal,
                            inner.audit.as_ref(),
                            lease,
                            CancellationSource::User,
                        ).await;
                    }
                    return None;
                }
            }
            () = wait_optional(control.deadline) => {
                abort_tool_tasks(&mut tasks).await;
                if ever_started.load(Ordering::Acquire) {
                    tool_interrupted(
                        state,
                        journal,
                        inner.audit.as_ref(),
                        lease,
                        CancellationSource::Deadline,
                    ).await;
                } else {
                    cancel_and_commit(
                        state,
                        journal,
                        inner.audit.as_ref(),
                        lease,
                        CancellationSource::Deadline,
                    ).await;
                }
                return None;
            }
            _ = control.renew.tick() => {
                if inner.runtime.renew_lease(lease).await.is_err() {
                    abort_tool_tasks(&mut tasks).await;
                    drive_terminal_event(state, journal, AgentEvent::LeaseLost).await;
                    return None;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((position, call, outcome))) if position < outputs.len() => {
                        outputs[position] = Some((call, outcome));
                    }
                    Some(Ok(_)) | Some(Err(_)) | None => {
                        abort_tool_tasks(&mut tasks).await;
                        drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
                        return None;
                    }
                }
            }
        }
    }

    if *control.cancel.borrow() {
        tool_interrupted(
            state,
            journal,
            inner.audit.as_ref(),
            lease,
            CancellationSource::User,
        )
        .await;
        return None;
    }
    if control
        .deadline
        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    {
        tool_interrupted(
            state,
            journal,
            inner.audit.as_ref(),
            lease,
            CancellationSource::Deadline,
        )
        .await;
        return None;
    }
    outputs.into_iter().collect()
}

async fn abort_tool_tasks(tasks: &mut JoinSet<ParallelToolOutcome>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn append_tool_reply(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    call: AgentToolCall,
    reply: AgentToolReply,
) -> bool {
    let exchange = match RunToolExchange::new(
        reply.call_id().clone(),
        call.call_id,
        call.name,
        call.arguments,
        reply.content().to_owned(),
        reply.error_code().map(str::to_owned),
    ) {
        Ok(exchange) => exchange,
        Err(error) => {
            journal_failure(state, journal, error).await;
            return false;
        }
    };
    if let Err(error) = journal.append_tool_exchange(&exchange).await {
        journal_failure(state, journal, error).await;
        return false;
    }
    true
}

async fn wait_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

async fn await_run_child<F, T>(
    child: F,
    cancel: &mut watch::Receiver<bool>,
    renew: &mut tokio::time::Interval,
    deadline: Option<tokio::time::Instant>,
    runtime: &dyn RunRuntime,
    lease: &RunExecutionLease,
) -> ControlledChild<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(child);
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    return ControlledChild::Cancelled(CancellationSource::User);
                }
            }
            () = wait_optional(deadline) => {
                return ControlledChild::Cancelled(CancellationSource::Deadline);
            }
            _ = renew.tick() => {
                if runtime.renew_lease(lease).await.is_err() {
                    return ControlledChild::LeaseLost;
                }
            }
            result = &mut child => return ControlledChild::Ready(result),
        }
    }
}

async fn await_cancellable_tool_task<T>(
    mut child: JoinHandle<T>,
    tool_cancel: &ToolCancellationHandle,
    cancel: &mut watch::Receiver<bool>,
    renew: &mut tokio::time::Interval,
    deadline: Option<tokio::time::Instant>,
    runtime: &dyn RunRuntime,
    lease: &RunExecutionLease,
) -> ControlledChild<Result<T, tokio::task::JoinError>> {
    loop {
        tokio::select! {
            biased;
            result = &mut child => return ControlledChild::Ready(result),
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    tool_cancel.cancel(ToolCancellationReason::User);
                    stop_cancellable_tool_task(&mut child, renew, runtime, lease).await;
                    return ControlledChild::Cancelled(CancellationSource::User);
                }
            }
            () = wait_optional(deadline) => {
                tool_cancel.cancel(ToolCancellationReason::Deadline);
                stop_cancellable_tool_task(&mut child, renew, runtime, lease).await;
                return ControlledChild::Cancelled(CancellationSource::Deadline);
            }
            _ = renew.tick() => {
                if runtime.renew_lease(lease).await.is_err() {
                    tool_cancel.cancel(ToolCancellationReason::LeaseLost);
                    stop_cancellable_tool_task(&mut child, renew, runtime, lease).await;
                    return ControlledChild::LeaseLost;
                }
            }
        }
    }
}

async fn stop_cancellable_tool_task<T>(
    child: &mut JoinHandle<T>,
    renew: &mut tokio::time::Interval,
    runtime: &dyn RunRuntime,
    lease: &RunExecutionLease,
) {
    let stop_deadline = tokio::time::Instant::now() + TOOL_CANCELLATION_GRACE;
    loop {
        tokio::select! {
            _ = &mut *child => return,
            () = tokio::time::sleep_until(stop_deadline) => {
                child.abort();
                let _ = child.await;
                return;
            }
            _ = renew.tick() => {
                if runtime.renew_lease(lease).await.is_err() {
                    child.abort();
                    let _ = child.await;
                    return;
                }
            }
        }
    }
}

struct ProviderSamplingContext<'a> {
    max_output_tokens: Option<u32>,
    usage_seen: &'a mut bool,
    current_text_seen: &'a mut bool,
    runtime: &'a dyn RunRuntime,
    lease: &'a RunExecutionLease,
    sampling_index: u32,
    max_run_output_tokens: Option<u64>,
    rate_card: Option<&'a ProviderRateCard>,
    cost_cap: Option<&'a RunCostCap>,
    audit: &'a dyn AgentAudit,
}

async fn handle_provider_event(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    event: ProviderEvent,
    sampling: ProviderSamplingContext<'_>,
) -> bool {
    match event {
        ProviderEvent::ResponseStarted { .. }
        | ProviderEvent::OutputItemAdded { .. }
        | ProviderEvent::ToolCallStarted { .. }
        | ProviderEvent::ToolArgumentsDelta { .. } => false,
        ProviderEvent::TextDelta { delta, .. } => {
            if delta.is_empty() {
                return false;
            }
            *sampling.current_text_seen |= !delta.trim().is_empty();
            let Ok((next, effects)) = reduce(state, AgentEvent::ProviderTextDelta(delta)) else {
                return true;
            };
            *state = next;
            let [AgentEffect::PersistText(delta)] = effects.as_slice() else {
                return true;
            };
            if let Err(error) = journal.push(delta, Instant::now()).await {
                journal_failure(state, journal, error).await;
                return true;
            }
            false
        }
        ProviderEvent::ReasoningDelta { delta, .. } => {
            let Ok((next, effects)) = reduce(state, AgentEvent::ProviderReasoningDelta(delta))
            else {
                return true;
            };
            *state = next;
            let [AgentEffect::PersistReasoning(delta)] = effects.as_slice() else {
                return true;
            };
            if let Err(error) = journal.push_reasoning(delta, Instant::now()).await {
                journal_failure(state, journal, error).await;
                return true;
            }
            false
        }
        ProviderEvent::RemoteProjection(projection) => {
            if let Err(error) = journal.append_remote_projection(&projection).await {
                journal_failure(state, journal, error).await;
                true
            } else {
                false
            }
        }
        ProviderEvent::Interrupted(_) => {
            // The provider boundary preserves the fixed interrupt contract. Until the durable
            // human coordinator consumes it, retain the previous fail-closed run behavior.
            drive_terminal_event(
                state,
                journal,
                AgentEvent::ProviderFailed(AgentFailure::ProviderGenerationFailed),
            )
            .await;
            true
        }
        ProviderEvent::ToolCallCompleted { .. } => {
            drive_terminal_event(
                state,
                journal,
                AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
            )
            .await;
            true
        }
        ProviderEvent::Usage(usage) => {
            let usage_is_invalid = *sampling.usage_seen
                || usage
                    .input_tokens
                    .checked_add(usage.output_tokens)
                    .is_none_or(|known| usage.total_tokens < known);
            if usage_is_invalid {
                drive_terminal_event(
                    state,
                    journal,
                    AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                true
            } else {
                let sampling_budget_exceeded = sampling
                    .max_output_tokens
                    .is_some_and(|limit| usage.output_tokens > u64::from(limit));
                match sampling
                    .runtime
                    .record_provider_usage(
                        sampling.lease,
                        sampling.sampling_index,
                        usage,
                        sampling.max_run_output_tokens,
                        sampling.rate_card,
                        sampling.cost_cap,
                    )
                    .await
                {
                    Ok(RunTokenUsageReceipt::Recorded(_) | RunTokenUsageReceipt::Replayed(_)) => {
                        *sampling.usage_seen = true;
                        if sampling_budget_exceeded {
                            drive_terminal_event(
                                state,
                                journal,
                                AgentEvent::ProviderFailed(
                                    AgentFailure::ProviderTokenBudgetExceeded,
                                ),
                            )
                            .await;
                            true
                        } else {
                            false
                        }
                    }
                    Ok(RunTokenUsageReceipt::BudgetExceeded(_)) => {
                        *sampling.usage_seen = true;
                        drive_terminal_event(
                            state,
                            journal,
                            AgentEvent::ProviderFailed(AgentFailure::RunTokenBudgetExceeded),
                        )
                        .await;
                        true
                    }
                    Ok(RunTokenUsageReceipt::CostBudgetExceeded(_)) => {
                        *sampling.usage_seen = true;
                        if sampling
                            .audit
                            .record(sampling.lease, AgentAuditKind::RunCostBudgetExceeded)
                            .await
                            .is_err()
                        {
                            drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown)
                                .await;
                        } else {
                            drive_terminal_event(
                                state,
                                journal,
                                AgentEvent::ProviderFailed(AgentFailure::RunCostBudgetExceeded),
                            )
                            .await;
                        }
                        true
                    }
                    Err(RunRuntimeError::StaleLease) => {
                        drive_terminal_event(state, journal, AgentEvent::LeaseLost).await;
                        true
                    }
                    Err(_) => {
                        drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown)
                            .await;
                        true
                    }
                }
            }
        }
        ProviderEvent::Completed => {
            if !*sampling.current_text_seen
                || (sampling.max_output_tokens.is_some() && !*sampling.usage_seen)
            {
                drive_terminal_event(
                    state,
                    journal,
                    AgentEvent::ProviderFailed(AgentFailure::ProviderInvalidResponse),
                )
                .await;
                return true;
            }
            let Ok((next, effects)) = reduce(state, AgentEvent::ProviderCompleted) else {
                return true;
            };
            *state = next;
            let [AgentEffect::CommitTerminal(terminal)] = effects.as_slice() else {
                return true;
            };
            commit_terminal(state, journal, *terminal).await;
            true
        }
        ProviderEvent::Failed(failure) => {
            if failure == ProviderFailure::StreamStalled && {
                metrics::counter!("openbot_agent_stream_stalled_total").increment(1);
                sampling
                    .audit
                    .record(sampling.lease, AgentAuditKind::StreamStalled)
                    .await
                    .is_err()
            } {
                drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
                return true;
            }
            let failure = provider_failure(failure);
            let Ok((next, effects)) = reduce(state, AgentEvent::ProviderFailed(failure)) else {
                return true;
            };
            *state = next;
            let [AgentEffect::CommitTerminal(terminal)] = effects.as_slice() else {
                return true;
            };
            commit_terminal(state, journal, *terminal).await;
            true
        }
    }
}

async fn commit_terminal(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    terminal: AgentTerminal,
) {
    if journal.finish(run_terminal(terminal)).await.is_ok()
        && let Ok((next, _)) = reduce(state, AgentEvent::TerminalCommitted)
    {
        *state = next;
    }
}

async fn drive_terminal_event(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    event: AgentEvent,
) {
    let Ok((next, effects)) = reduce(state, event) else {
        return;
    };
    *state = next;
    let [AgentEffect::CommitTerminal(terminal)] = effects.as_slice() else {
        return;
    };
    commit_terminal(state, journal, *terminal).await;
}

async fn reject_cost_budget_before_provider(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    audit: &dyn AgentAudit,
    lease: &RunExecutionLease,
    failure: AgentFailure,
    audit_kind: AgentAuditKind,
) {
    if audit.record(lease, audit_kind).await.is_err() {
        drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
    } else {
        drive_terminal_event(state, journal, AgentEvent::ContextFailed(failure)).await;
    }
}

struct ProviderStopObservation {
    outcome: StopOutcome,
    lease_lost: bool,
}

fn stop_result(
    result: Result<StopOutcome, ProviderPortError>,
    deadline: tokio::time::Instant,
    first_poll: bool,
) -> StopOutcome {
    match result {
        Ok(StopOutcome::Unsupported) if first_poll => StopOutcome::Unsupported,
        Ok(outcome) if tokio::time::Instant::now() < deadline => {
            if let StopOutcome::Confirmed { at } = outcome {
                tracing::debug!(stop_confirmed_at = ?at, "provider stop confirmed");
            }
            outcome
        }
        _ => StopOutcome::Unknown,
    }
}

async fn request_provider_stop(
    session: &mut dyn ProviderSession,
    run_deadline: Option<tokio::time::Instant>,
    renew: &mut tokio::time::Interval,
    runtime: &dyn RunRuntime,
    lease: &RunExecutionLease,
    mut lease_lost: bool,
) -> ProviderStopObservation {
    let cap = tokio::time::Instant::now() + PROVIDER_STOP_TIMEOUT;
    let deadline = run_deadline.map_or(cap, |run| run.min(cap));
    let mut stop = session.request_stop();
    // Poll once even at an expired deadline: the default Unsupported has no wait or I/O.
    // A blocking adapter poll cannot be preempted; late confirmation still earns no proof.
    let first = poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await;
    if let Poll::Ready(result) = first {
        return ProviderStopObservation {
            outcome: stop_result(result, deadline, true),
            lease_lost,
        };
    }
    loop {
        if tokio::time::Instant::now() >= deadline {
            return ProviderStopObservation {
                outcome: StopOutcome::Unknown,
                lease_lost,
            };
        }
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => {
                return ProviderStopObservation { outcome: StopOutcome::Unknown, lease_lost };
            }
            result = &mut stop => {
                return ProviderStopObservation { outcome: stop_result(result, deadline, false), lease_lost };
            }
            _ = renew.tick(), if !lease_lost => {
                match tokio::time::timeout_at(deadline, runtime.renew_lease(lease)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => lease_lost = true,
                    Err(_) => return ProviderStopObservation { outcome: StopOutcome::Unknown, lease_lost },
                }
            }
        }
    }
}

async fn commit_provider_stop_unknown(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    audit: &dyn AgentAudit,
    lease: &RunExecutionLease,
    audit_kind: Option<AgentAuditKind>,
) {
    if let Some(kind) = audit_kind {
        match kind {
            AgentAuditKind::RunDeadlineExceeded => {
                metrics::counter!("openbot_agent_run_deadline_total").increment(1)
            }
            AgentAuditKind::StreamStalled => {
                metrics::counter!("openbot_agent_stream_stalled_total").increment(1)
            }
            _ => {}
        }
        if audit.record(lease, kind).await.is_err() {
            tracing::warn!("provider stop remains unknown after lifecycle audit failure");
        }
    }
    drive_terminal_event(
        state,
        journal,
        AgentEvent::ProviderFailed(AgentFailure::ProviderStopUnknown),
    )
    .await;
}

async fn cancel_and_commit(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    audit: &dyn AgentAudit,
    lease: &RunExecutionLease,
    source: CancellationSource,
) {
    if matches!(source, CancellationSource::Deadline) && {
        metrics::counter!("openbot_agent_run_deadline_total").increment(1);
        audit
            .record(lease, AgentAuditKind::RunDeadlineExceeded)
            .await
            .is_err()
    } {
        drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
        return;
    }
    let Ok((next, effects)) = reduce(state, AgentEvent::CancelRequested) else {
        return;
    };
    if !matches!(effects.as_slice(), [AgentEffect::CancelChildren]) {
        return;
    }
    *state = next;
    drive_terminal_event(state, journal, AgentEvent::ChildrenStopped).await;
}

async fn tool_interrupted(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    audit: &dyn AgentAudit,
    lease: &RunExecutionLease,
    source: CancellationSource,
) {
    if matches!(source, CancellationSource::Deadline) {
        metrics::counter!("openbot_agent_run_deadline_total").increment(1);
        if audit
            .record(lease, AgentAuditKind::RunDeadlineExceeded)
            .await
            .is_err()
        {
            drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
            return;
        }
    }
    // Dropping an in-flight tool future cannot prove whether its non-idempotent effect committed.
    drive_terminal_event(state, journal, AgentEvent::JournalCommitUnknown).await;
}

async fn journal_failure(
    state: &mut AgentState,
    journal: &mut DurableTextRun,
    error: RunRuntimeError,
) {
    let event = match error {
        RunRuntimeError::StaleLease => AgentEvent::LeaseLost,
        RunRuntimeError::CommitUnknown => AgentEvent::JournalCommitUnknown,
        RunRuntimeError::Unavailable
        | RunRuntimeError::Corrupt { .. }
        | RunRuntimeError::InvalidInput { .. }
        | RunRuntimeError::Conflict => AgentEvent::JournalCommitUnknown,
    };
    drive_terminal_event(state, journal, event).await;
}

const fn provider_failure(failure: ProviderFailure) -> AgentFailure {
    match failure {
        ProviderFailure::Authentication => AgentFailure::ProviderAuthentication,
        ProviderFailure::RateLimited { .. } => AgentFailure::ProviderRateLimited,
        ProviderFailure::ServerUnavailable { .. } | ProviderFailure::Transport => {
            AgentFailure::ProviderUnavailable
        }
        ProviderFailure::InvalidResponse => AgentFailure::ProviderInvalidResponse,
        ProviderFailure::StreamStalled => AgentFailure::ProviderStreamStalled,
        ProviderFailure::GenerationFailed => AgentFailure::ProviderGenerationFailed,
    }
}

const fn provider_port_failure(error: ProviderPortError) -> AgentFailure {
    match error {
        ProviderPortError::InvalidRequest { .. } => AgentFailure::ProviderInvalidResponse,
        ProviderPortError::Unavailable => AgentFailure::ProviderUnavailable,
        ProviderPortError::CommitUnknown => AgentFailure::ProviderCommitUnknown,
    }
}

const fn context_failure(error: AgentContextError) -> AgentFailure {
    match error {
        AgentContextError::Stale => AgentFailure::RuntimeLeaseLost,
        AgentContextError::ToolHistoryUnsupported => AgentFailure::ToolLoopUnavailable,
        AgentContextError::Unavailable
        | AgentContextError::Corrupt { .. }
        | AgentContextError::TooLarge => AgentFailure::ProviderInvalidResponse,
    }
}

const fn run_terminal(terminal: AgentTerminal) -> RunTerminal {
    match terminal {
        AgentTerminal::Succeeded => RunTerminal::Completed,
        AgentTerminal::Cancelled => RunTerminal::Cancelled,
        AgentTerminal::Failed(failure) => RunTerminal::Failed(failure_code(failure)),
        AgentTerminal::ReconciliationRequired(failure) => {
            RunTerminal::ReconciliationRequired(failure_code(failure))
        }
    }
}

const fn failure_code(failure: AgentFailure) -> RunFailureCode {
    match failure {
        AgentFailure::ProviderAuthentication => RunFailureCode::ProviderAuthentication,
        AgentFailure::ProviderRateLimited => RunFailureCode::ProviderRateLimited,
        AgentFailure::ProviderUnavailable => RunFailureCode::ProviderUnavailable,
        AgentFailure::ProviderCommitUnknown => RunFailureCode::ProviderCommitUnknown,
        AgentFailure::ProviderStopUnknown => RunFailureCode::ProviderStopUnknown,
        AgentFailure::ProviderInvalidResponse => RunFailureCode::ProviderInvalidResponse,
        AgentFailure::ProviderStreamStalled => RunFailureCode::ProviderStreamStalled,
        AgentFailure::ProviderGenerationFailed => RunFailureCode::ProviderGenerationFailed,
        AgentFailure::ProviderTokenBudgetExceeded => RunFailureCode::ProviderTokenBudgetExceeded,
        AgentFailure::RunTokenBudgetExceeded => RunFailureCode::RunTokenBudgetExceeded,
        AgentFailure::RunCostBudgetUnpriced => RunFailureCode::RunCostBudgetUnpriced,
        AgentFailure::RunCostBudgetCurrencyMismatch => {
            RunFailureCode::RunCostBudgetCurrencyMismatch
        }
        AgentFailure::RunCostBudgetExceeded => RunFailureCode::RunCostBudgetExceeded,
        AgentFailure::ToolStepLimit => RunFailureCode::ToolStepLimit,
        AgentFailure::ToolLoopUnavailable => RunFailureCode::ToolLoopUnavailable,
        AgentFailure::ToolDenied => RunFailureCode::ToolDenied,
        AgentFailure::RuntimeLeaseLost => RunFailureCode::RuntimeLeaseExpired,
        AgentFailure::JournalCommitUnknown => RunFailureCode::JournalCommitUnknown,
    }
}

// Bind the first sampling route, including absence. No later context may promote, remove or
// mutate a custom binding; journal sequence alone is allowed to advance after a tool exchange.
fn bind_custom_model(
    bound: &mut Option<Option<openbot_application::RunModelBinding>>,
    request: &openbot_application::ProviderRequest,
    lease: &RunExecutionLease,
) -> bool {
    let current = match &request.route {
        ProviderRoute::CustomModel(binding) => Some(binding),
        _ => None,
    };
    if current.is_some_and(|binding| !binding.matches_lease(lease))
        || (current.is_some() && request.rate_card.is_some())
        || bound
            .as_ref()
            .is_some_and(|value| value.as_ref() != current)
    {
        return false;
    }
    if bound.is_none() {
        *bound = Some(current.cloned());
    }
    true
}

#[cfg(test)]
#[path = "runtime_stop_tests.rs"]
mod stop_tests;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use openbot_application::{
        AgentAuditError, ClaimedRunDispatch, NoAgentAudit, ProviderBillingFamily, ProviderMessage,
        ProviderMessageRole, ProviderPortError, ProviderRateCardInput, ProviderRemoteInterrupt,
        ProviderRemoteInterruptInput, ProviderRemoteResumeEntry, ProviderRemoteResumeStatus,
        ProviderRequest, ProviderSession, ProviderUsage, RemoteAguiRoute, RemoteInterruptPending,
        RemoteInterruptResolutionReceipt, RunSemanticChannel, RunTokenUsage, RunToolExchange,
        RunWriteReceipt,
    };
    use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId, ToolCallId};
    use openbot_domain::thread::FencingToken;
    use time::macros::datetime;
    use tokio::sync::{Barrier, Notify};

    use super::*;
    use crate::NoAgentToolInvoker;

    struct FakeRuntime {
        calls: StdMutex<Vec<RuntimeCall>>,
        usage: StdMutex<FakeUsage>,
        force_budget_exceeded: bool,
        force_cost_budget_exceeded: bool,
        terminal: Notify,
    }

    #[derive(Default)]
    struct FakeUsage {
        ceiling_initialized: bool,
        ceiling: Option<u64>,
        rate_card_initialized: bool,
        rate_card: Option<ProviderRateCard>,
        cost_cap_initialized: bool,
        cost_cap: Option<RunCostCap>,
        next_sampling: u32,
        aggregate: RunTokenUsage,
        last: Option<(u32, ProviderUsage)>,
    }

    #[derive(Default)]
    struct FakeAudit {
        kinds: StdMutex<Vec<AgentAuditKind>>,
    }

    #[async_trait]
    impl AgentAudit for FakeAudit {
        async fn record(
            &self,
            _lease: &RunExecutionLease,
            kind: AgentAuditKind,
        ) -> Result<(), AgentAuditError> {
            self.kinds.lock().expect("audit lock").push(kind);
            Ok(())
        }
    }

    impl FakeAudit {
        fn kinds(&self) -> Vec<AgentAuditKind> {
            self.kinds.lock().expect("audit lock").clone()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RuntimeCall {
        Chunk(u64, RunSemanticChannel, String),
        ToolExchange(u64, String, String, String),
        Finish(u64, RunTerminal),
        Renew,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                usage: StdMutex::new(FakeUsage::default()),
                force_budget_exceeded: false,
                force_cost_budget_exceeded: false,
                terminal: Notify::new(),
            }
        }

        fn rejecting_usage_budget() -> Self {
            Self {
                force_budget_exceeded: true,
                ..Self::new()
            }
        }

        fn rejecting_cost_budget() -> Self {
            Self {
                force_cost_budget_exceeded: true,
                ..Self::new()
            }
        }

        fn calls(&self) -> Vec<RuntimeCall> {
            self.calls.lock().expect("fake lock").clone()
        }

        fn usage(&self) -> (Option<u64>, u32, RunTokenUsage) {
            let usage = self.usage.lock().expect("usage lock");
            (usage.ceiling, usage.next_sampling, usage.aggregate)
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
            self.calls
                .lock()
                .expect("fake lock")
                .push(RuntimeCall::Renew);
            Ok(())
        }

        async fn append_semantic_chunk(
            &self,
            _lease: &RunExecutionLease,
            expected_sequence: u64,
            channel: RunSemanticChannel,
            chunk: &str,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(RuntimeCall::Chunk(
                    expected_sequence,
                    channel,
                    chunk.to_owned(),
                ));
            Ok(receipt(expected_sequence))
        }

        async fn append_tool_exchange(
            &self,
            _lease: &RunExecutionLease,
            expected_sequence: u64,
            exchange: &RunToolExchange,
        ) -> Result<RunWriteReceipt, RunRuntimeError> {
            self.calls
                .lock()
                .expect("fake lock")
                .push(RuntimeCall::ToolExchange(
                    expected_sequence,
                    exchange.provider_call_id().to_owned(),
                    exchange.name().to_owned(),
                    exchange.result().to_owned(),
                ));
            Ok(receipt(expected_sequence))
        }

        async fn record_provider_usage(
            &self,
            _lease: &RunExecutionLease,
            sampling_index: u32,
            usage: ProviderUsage,
            max_run_output_tokens: Option<u64>,
            rate_card: Option<&ProviderRateCard>,
            cost_cap: Option<&RunCostCap>,
        ) -> Result<RunTokenUsageReceipt, RunRuntimeError> {
            let mut state = self.usage.lock().expect("usage lock");
            if state.ceiling_initialized {
                if state.ceiling != max_run_output_tokens {
                    return Err(RunRuntimeError::Conflict);
                }
            } else {
                state.ceiling_initialized = true;
                state.ceiling = max_run_output_tokens;
            }
            if state.rate_card_initialized {
                if state.rate_card.as_ref() != rate_card {
                    return Err(RunRuntimeError::Conflict);
                }
            } else {
                state.rate_card_initialized = true;
                state.rate_card = rate_card.cloned();
            }
            if state.cost_cap_initialized {
                if state.cost_cap.as_ref() != cost_cap {
                    return Err(RunRuntimeError::Conflict);
                }
            } else {
                state.cost_cap_initialized = true;
                state.cost_cap = cost_cap.cloned();
            }
            if self.force_budget_exceeded {
                return Ok(RunTokenUsageReceipt::BudgetExceeded(state.aggregate));
            }
            if self.force_cost_budget_exceeded {
                return Ok(RunTokenUsageReceipt::CostBudgetExceeded(state.aggregate));
            }
            if sampling_index < state.next_sampling {
                return if state.last == Some((sampling_index, usage))
                    && sampling_index.checked_add(1) == Some(state.next_sampling)
                {
                    if state
                        .ceiling
                        .is_some_and(|limit| state.aggregate.output_tokens > limit)
                    {
                        Ok(RunTokenUsageReceipt::BudgetExceeded(state.aggregate))
                    } else {
                        Ok(RunTokenUsageReceipt::Replayed(state.aggregate))
                    }
                } else {
                    Err(RunRuntimeError::Conflict)
                };
            }
            if sampling_index != state.next_sampling {
                return Err(RunRuntimeError::Conflict);
            }
            let next = RunTokenUsage {
                input_tokens: state
                    .aggregate
                    .input_tokens
                    .checked_add(usage.input_tokens)
                    .ok_or(RunRuntimeError::InvalidInput {
                        field: "provider_usage",
                    })?,
                output_tokens: state
                    .aggregate
                    .output_tokens
                    .checked_add(usage.output_tokens)
                    .ok_or(RunRuntimeError::InvalidInput {
                        field: "provider_usage",
                    })?,
                total_tokens: state
                    .aggregate
                    .total_tokens
                    .checked_add(usage.total_tokens)
                    .ok_or(RunRuntimeError::InvalidInput {
                        field: "provider_usage",
                    })?,
            };
            if max_run_output_tokens.is_some_and(|limit| next.output_tokens > limit) {
                state.aggregate = next;
                state.last = Some((sampling_index, usage));
                state.next_sampling =
                    sampling_index
                        .checked_add(1)
                        .ok_or(RunRuntimeError::InvalidInput {
                            field: "sampling_index",
                        })?;
                return Ok(RunTokenUsageReceipt::BudgetExceeded(next));
            }
            state.aggregate = next;
            state.last = Some((sampling_index, usage));
            state.next_sampling =
                sampling_index
                    .checked_add(1)
                    .ok_or(RunRuntimeError::InvalidInput {
                        field: "sampling_index",
                    })?;
            Ok(RunTokenUsageReceipt::Recorded(next))
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
                .push(RuntimeCall::Finish(expected_sequence, terminal));
            self.terminal.notify_one();
            Ok(receipt(expected_sequence))
        }

        async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError> {
            Ok(None)
        }
    }

    struct FakeContext;

    #[async_trait]
    impl AgentContextSource for FakeContext {
        async fn load(
            &self,
            _lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            Ok(ProviderRequest {
                route: openbot_application::ProviderRoute::PackageOpenAi,
                messages: vec![ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "hello".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                }],
                tools: Vec::new(),
                max_output_tokens: Some(32),
                rate_card: None,
                cost_cap: None,
            })
        }
    }

    struct HoldingContext;

    struct NotifyingHoldingContext {
        started: Notify,
    }

    #[derive(Default)]
    struct CountingContext {
        loads: AtomicUsize,
    }

    #[derive(Default)]
    struct DriftingRateContext {
        loads: AtomicUsize,
    }

    struct CostBudgetContext {
        rate_currency: Option<&'static str>,
        cap_currency: &'static str,
    }

    #[async_trait]
    impl AgentContextSource for CountingContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            self.loads.fetch_add(1, AtomicOrdering::SeqCst);
            FakeContext.load(lease).await
        }
    }

    #[async_trait]
    impl AgentContextSource for DriftingRateContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            let index = self.loads.fetch_add(1, AtomicOrdering::SeqCst);
            let mut request = FakeContext.load(lease).await?;
            request.rate_card = Some(
                ProviderRateCard::new(ProviderRateCardInput {
                    family: ProviderBillingFamily::OpenAiCompatible,
                    model: "model-1".to_owned(),
                    currency: "USD".to_owned(),
                    max_input_micro_units_per_million_tokens: if index == 0 {
                        1_500_000
                    } else {
                        1_500_001
                    },
                    max_output_micro_units_per_million_tokens: 2_000_000,
                    source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
                    source_sha256: if index == 0 {
                        "a".repeat(64)
                    } else {
                        "b".repeat(64)
                    },
                    observed_at: datetime!(2026-08-30 12:00 UTC),
                })
                .expect("test rate card"),
            );
            Ok(request)
        }
    }

    #[async_trait]
    impl AgentContextSource for CostBudgetContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            let mut request = FakeContext.load(lease).await?;
            request.rate_card = self.rate_currency.map(|currency| {
                ProviderRateCard::new(ProviderRateCardInput {
                    family: ProviderBillingFamily::OpenAiCompatible,
                    model: "model-budget".to_owned(),
                    currency: currency.to_owned(),
                    max_input_micro_units_per_million_tokens: 1_500_000,
                    max_output_micro_units_per_million_tokens: 2_000_000,
                    source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
                    source_sha256: "c".repeat(64),
                    observed_at: datetime!(2026-08-30 12:00 UTC),
                })
                .expect("test rate card")
            });
            request.cost_cap = Some(
                RunCostCap::new(self.cap_currency.to_owned(), 2_000_000).expect("test cost cap"),
            );
            Ok(request)
        }
    }

    #[async_trait]
    impl AgentContextSource for HoldingContext {
        async fn load(
            &self,
            _lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            pending().await
        }
    }

    #[async_trait]
    impl AgentContextSource for NotifyingHoldingContext {
        async fn load(
            &self,
            _lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            self.started.notify_one();
            pending().await
        }
    }

    struct FakeProvider {
        events: Vec<ProviderEvent>,
        hold: bool,
    }

    struct FailingStartProvider(ProviderPortError);

    struct SequencedProvider {
        sessions: StdMutex<VecDeque<Vec<ProviderEvent>>>,
        starts: AtomicUsize,
    }

    struct RemoteResumeContext;

    #[derive(Default)]
    struct DriftingRemoteResumeContext {
        loads: AtomicUsize,
    }

    #[async_trait]
    impl AgentContextSource for RemoteResumeContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            Ok(ProviderRequest {
                route: ProviderRoute::RemoteAgUi(RemoteAguiRoute::new(
                    "https://agent.example.test/run".to_owned(),
                    lease.thread_id().as_str().to_owned(),
                    lease.run_id().as_str().to_owned(),
                    lease.bot_id().as_str().to_owned(),
                    None,
                )?),
                messages: vec![ProviderMessage {
                    role: ProviderMessageRole::User,
                    content: "hello".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                }],
                tools: Vec::new(),
                max_output_tokens: None,
                rate_card: None,
                cost_cap: None,
            })
        }
    }

    #[async_trait]
    impl AgentContextSource for DriftingRemoteResumeContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            let endpoint = if self.loads.fetch_add(1, AtomicOrdering::SeqCst) == 0 {
                "https://agent.example.test/run"
            } else {
                "https://replacement.example.test/run"
            };
            Ok(ProviderRequest {
                route: ProviderRoute::RemoteAgUi(RemoteAguiRoute::new(
                    endpoint.to_owned(),
                    lease.thread_id().as_str().to_owned(),
                    lease.run_id().as_str().to_owned(),
                    lease.bot_id().as_str().to_owned(),
                    None,
                )?),
                messages: Vec::new(),
                tools: Vec::new(),
                max_output_tokens: None,
                rate_card: None,
                cost_cap: None,
            })
        }
    }

    #[derive(Default)]
    struct RecordingRemoteProvider {
        routes: StdMutex<Vec<RemoteAguiRoute>>,
    }

    #[async_trait]
    impl ProviderAdapter for RecordingRemoteProvider {
        async fn start(
            &self,
            request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            let ProviderRoute::RemoteAgUi(route) = request.route else {
                return Err(ProviderPortError::InvalidRequest {
                    field: "test_remote_route",
                });
            };
            let first = self.routes.lock().expect("remote routes").is_empty();
            self.routes
                .lock()
                .expect("remote routes")
                .push(route.clone());
            let events = if first {
                vec![ProviderEvent::Interrupted(
                    ProviderRemoteInterruptBatch::new(
                        route.run_id().to_owned(),
                        vec![
                            ProviderRemoteInterrupt::new(ProviderRemoteInterruptInput {
                                id: "interrupt-1".to_owned(),
                                reason: "human_input".to_owned(),
                                message: Some("Choose".to_owned()),
                                tool_call_id: None,
                                response_schema: Some(serde_json::json!({"type":"string"})),
                                expires_at: None,
                                metadata: None,
                            })
                            .expect("test interrupt"),
                        ],
                    )
                    .expect("test batch"),
                )]
            } else {
                vec![
                    ProviderEvent::TextDelta {
                        index: 0,
                        delta: "resumed answer".to_owned(),
                    },
                    ProviderEvent::Completed,
                ]
            };
            Ok(Box::new(FakeSession {
                events: events.into(),
                hold: false,
            }))
        }
    }

    #[derive(Default)]
    struct ImmediateRemoteCoordinator {
        waits: AtomicUsize,
    }

    #[async_trait]
    impl RemoteInterruptCoordinator for ImmediateRemoteCoordinator {
        async fn list_pending(
            &self,
            _auth: &openbot_contracts::auth::AuthContext,
        ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
            Ok(Vec::new())
        }

        async fn resolve(
            &self,
            _auth: &openbot_contracts::auth::AuthContext,
            _request_id: &str,
            _status: ProviderRemoteResumeStatus,
            _payload: Option<serde_json::Value>,
        ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
            Err(RemoteInterruptError::Unavailable)
        }

        async fn persist_and_wait(
            &self,
            _lease: &RunExecutionLease,
            batch: &ProviderRemoteInterruptBatch,
        ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
            self.waits.fetch_add(1, AtomicOrdering::SeqCst);
            ProviderRemoteResume::new(
                batch.protocol_run_id().to_owned(),
                "protocol-resumed-1".to_owned(),
                vec![
                    ProviderRemoteResumeEntry::new(
                        "interrupt-1".to_owned(),
                        ProviderRemoteResumeStatus::Resolved,
                        Some(serde_json::json!("yes")),
                    )
                    .map_err(|_| RemoteInterruptError::Corrupt {
                        field: "test_resume",
                    })?,
                ],
            )
            .map_err(|_| RemoteInterruptError::Corrupt {
                field: "test_resume",
            })
        }
    }

    #[async_trait]
    impl ProviderAdapter for SequencedProvider {
        async fn start(
            &self,
            _request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            self.starts.fetch_add(1, AtomicOrdering::SeqCst);
            let events = self
                .sessions
                .lock()
                .expect("provider sessions")
                .pop_front()
                .ok_or(ProviderPortError::InvalidRequest {
                    field: "test_sessions",
                })?;
            Ok(Box::new(FakeSession {
                events: events.into(),
                hold: false,
            }))
        }
    }

    #[derive(Default)]
    struct FakeToolInvoker {
        calls: AtomicUsize,
        releases: AtomicUsize,
    }

    #[async_trait]
    impl AgentToolInvoker for FakeToolInvoker {
        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            tool_name: &str,
            arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            assert_eq!(tool_name, "remember");
            assert_eq!(arguments, serde_json::json!({"content":"tea"}));
            let index = self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            crate::AgentToolReply::new(
                ToolCallId::new(format!("internal-{index}")),
                r#"{"status":"remembered"}"#.to_owned(),
                None,
            )
        }

        fn release(&self, _run_id: &RunId) {
            self.releases.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    #[derive(Default)]
    struct OrderedToolInvoker {
        seen: StdMutex<Vec<u64>>,
    }

    struct ParallelToolInvoker {
        active: AtomicUsize,
        max_active: AtomicUsize,
        completed: StdMutex<Vec<u64>>,
        pair_barrier: Barrier,
    }

    impl ParallelToolInvoker {
        fn new() -> Self {
            Self {
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                completed: StdMutex::new(Vec::new()),
                pair_barrier: Barrier::new(2),
            }
        }
    }

    struct BudgetBlockingToolInvoker {
        scheduled: AtomicUsize,
        started: AtomicUsize,
        first_started: Notify,
        second_scheduled: Notify,
    }

    struct CooperativeCancellationToolInvoker {
        started: Notify,
        stopped: Arc<AtomicBool>,
        reason: StdMutex<Option<ToolCancellationReason>>,
    }

    struct StopAwareDeadlineAudit {
        stopped: Arc<AtomicBool>,
        observed: AtomicBool,
    }

    impl CooperativeCancellationToolInvoker {
        fn new() -> Self {
            Self {
                started: Notify::new(),
                stopped: Arc::new(AtomicBool::new(false)),
                reason: StdMutex::new(None),
            }
        }
    }

    #[async_trait]
    impl AgentAudit for StopAwareDeadlineAudit {
        async fn record(
            &self,
            _lease: &RunExecutionLease,
            kind: AgentAuditKind,
        ) -> Result<(), AgentAuditError> {
            if kind == AgentAuditKind::RunDeadlineExceeded {
                assert!(
                    self.stopped.load(AtomicOrdering::SeqCst),
                    "deadline audit must follow cooperative child stop"
                );
                self.observed.store(true, AtomicOrdering::SeqCst);
            } else {
                assert_eq!(kind, AgentAuditKind::Invoked);
            }
            Ok(())
        }
    }

    impl BudgetBlockingToolInvoker {
        fn new() -> Self {
            Self {
                scheduled: AtomicUsize::new(0),
                started: AtomicUsize::new(0),
                first_started: Notify::new(),
                second_scheduled: Notify::new(),
            }
        }
    }

    struct SchedulingOnlyInvoker;

    struct HumanToolInvoker {
        started: Notify,
        answer: Notify,
        provider_calls: StdMutex<Vec<String>>,
        completed: AtomicUsize,
    }

    impl HumanToolInvoker {
        fn new() -> Self {
            Self {
                started: Notify::new(),
                answer: Notify::new(),
                provider_calls: StdMutex::new(Vec::new()),
                completed: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl AgentToolInvoker for HumanToolInvoker {
        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            provider_call_id: &str,
            tool_name: &str,
            arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            assert_eq!(tool_name, "askApproval");
            assert_eq!(
                arguments,
                serde_json::json!({"title":"Refund?","summary":"Duplicate"})
            );
            self.provider_calls
                .lock()
                .expect("human provider calls")
                .push(provider_call_id.to_owned());
            self.started.notify_one();
            self.answer.notified().await;
            self.completed.fetch_add(1, AtomicOrdering::SeqCst);
            crate::AgentToolReply::new(
                ToolCallId::new("decision-1"),
                r#"{"decision":"approved"}"#.to_owned(),
                None,
            )
        }
    }

    #[async_trait]
    impl AgentToolInvoker for OrderedToolInvoker {
        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            _tool_name: &str,
            arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            let order = arguments
                .get("order")
                .and_then(serde_json::Value::as_u64)
                .expect("test order");
            self.seen.lock().expect("ordered tools").push(order);
            crate::AgentToolReply::new(
                ToolCallId::new(format!("internal-{order}")),
                format!("result-{order}"),
                None,
            )
        }
    }

    #[async_trait]
    impl AgentToolInvoker for ParallelToolInvoker {
        fn scheduling(&self, _tool_name: &str) -> AgentToolScheduling {
            AgentToolScheduling::parallel(Vec::new())
        }

        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            _tool_name: &str,
            arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            let order = arguments
                .get("order")
                .and_then(serde_json::Value::as_u64)
                .expect("test order");
            let active = self.active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            self.max_active.fetch_max(active, AtomicOrdering::SeqCst);
            self.pair_barrier.wait().await;
            if order.is_multiple_of(2) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.completed
                .lock()
                .expect("parallel completion")
                .push(order);
            self.active.fetch_sub(1, AtomicOrdering::SeqCst);
            crate::AgentToolReply::new(
                ToolCallId::new(format!("internal-{order}")),
                format!("result-{order}"),
                None,
            )
        }
    }

    #[async_trait]
    impl AgentToolInvoker for BudgetBlockingToolInvoker {
        fn scheduling(&self, _tool_name: &str) -> AgentToolScheduling {
            if self.scheduled.fetch_add(1, AtomicOrdering::SeqCst) + 1 == 2 {
                self.second_scheduled.notify_one();
            }
            AgentToolScheduling::parallel(Vec::new())
        }

        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            _tool_name: &str,
            _arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            let started = self.started.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            if started == 1 {
                self.first_started.notify_one();
            }
            pending().await
        }
    }

    #[async_trait]
    impl AgentToolInvoker for CooperativeCancellationToolInvoker {
        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            _tool_name: &str,
            _arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            pending().await
        }

        async fn invoke_cancellable(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            tool_name: &str,
            arguments: serde_json::Value,
            mut cancellation: openbot_application::ToolExecutionCancellation,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            assert_eq!(tool_name, "remember");
            assert_eq!(arguments, serde_json::json!({"content":"tea"}));
            self.started.notify_one();
            let reason = cancellation.cancelled().await;
            *self.reason.lock().expect("cancellation reason") = Some(reason);
            self.stopped.store(true, AtomicOrdering::SeqCst);
            Err(AgentToolInvokeError::ReconciliationRequired)
        }
    }

    #[async_trait]
    impl AgentToolInvoker for SchedulingOnlyInvoker {
        fn scheduling(&self, tool_name: &str) -> AgentToolScheduling {
            let lock = match tool_name {
                "parallel-a-1" | "parallel-a-2" => Some("resource:a"),
                "parallel-b" => Some("resource:b"),
                _ => None,
            };
            match lock {
                Some(lock) => AgentToolScheduling::parallel(vec![
                    ResourceLockKey::new(lock).expect("test lock"),
                ]),
                None => AgentToolScheduling::serial(),
            }
        }

        async fn invoke(
            &self,
            _lease: &RunExecutionLease,
            _provider_call_id: &str,
            _tool_name: &str,
            _arguments: serde_json::Value,
        ) -> Result<crate::AgentToolReply, AgentToolInvokeError> {
            Err(AgentToolInvokeError::Unavailable)
        }
    }

    #[async_trait]
    impl ProviderAdapter for FailingStartProvider {
        async fn start(
            &self,
            _request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            Err(self.0)
        }
    }

    #[async_trait]
    impl ProviderAdapter for FakeProvider {
        async fn start(
            &self,
            _request: ProviderRequest,
        ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
            Ok(Box::new(FakeSession {
                events: self.events.clone().into(),
                hold: self.hold,
            }))
        }
    }

    struct FakeSession {
        events: VecDeque<ProviderEvent>,
        hold: bool,
    }

    #[async_trait]
    impl ProviderSession for FakeSession {
        async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
            if let Some(event) = self.events.pop_front() {
                Ok(Some(event))
            } else if self.hold {
                pending().await
            } else {
                Ok(None)
            }
        }
    }

    fn lease(run: &str) -> RunExecutionLease {
        RunExecutionLease::new(
            RunId::new(run),
            ThreadId::new("550e8400-e29b-41d4-a716-446655440000"),
            BotId::new("bot-1"),
            ActorId::new("actor-1"),
            FencingToken::new(1).unwrap(),
            1,
        )
        .unwrap()
    }

    fn test_tool_call(name: &str, order: u64) -> AgentToolCall {
        AgentToolCall {
            call_id: format!("provider-{order}"),
            name: name.to_owned(),
            arguments: serde_json::json!({"order":order}),
        }
    }

    const fn receipt(sequence: u64) -> RunWriteReceipt {
        RunWriteReceipt {
            run_event_sequence: sequence,
            thread_event_sequence: sequence,
            message_sequence: None,
            replayed: false,
        }
    }

    fn test_config() -> BuiltInAgentConfig {
        BuiltInAgentConfig {
            queue_capacity: 4,
            max_concurrency: 2,
            max_tool_concurrency: 2,
            lease_renew_interval: Duration::from_secs(1),
            run_deadline: Some(Duration::from_secs(2)),
        }
    }

    #[test]
    fn tool_concurrency_budget_rejects_zero_and_unbounded_configuration() {
        assert!(
            BuiltInAgentConfig {
                max_tool_concurrency: 0,
                ..BuiltInAgentConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            BuiltInAgentConfig {
                max_tool_concurrency: MAX_AGENT_TOOL_CONCURRENCY + 1,
                ..BuiltInAgentConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(BuiltInAgentConfig::default().validate().is_ok());
    }

    #[tokio::test]
    async fn current_sampling_cannot_complete_from_history_reasoning_or_blank_text() {
        for current in [None, Some(""), Some(" \n\t")] {
            let runtime = Arc::new(FakeRuntime::new());
            let mut events = vec![ProviderEvent::ReasoningDelta {
                index: 0,
                delta: "reasoning is not an answer".to_owned(),
            }];
            if let Some(delta) = current {
                events.push(ProviderEvent::TextDelta {
                    index: 0,
                    delta: delta.to_owned(),
                });
            }
            events.extend([
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                }),
                ProviderEvent::Completed,
            ]);
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                Arc::new(HistoricalAnswerContext),
                Arc::new(FakeProvider {
                    events,
                    hold: false,
                }),
                Arc::new(NoAgentToolInvoker),
                Arc::new(NoAgentAudit),
                test_config(),
            )
            .unwrap();
            let consumer = agent.consumer();
            let lease = lease("run-with-only-old-answer");
            assert_eq!(
                consumer.dispatch(lease.clone()).await,
                RunDispatchDecision::Accepted
            );
            consumer.activate(&lease).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
                .await
                .unwrap();
            assert!(matches!(
                runtime.calls().last(),
                Some(RuntimeCall::Finish(
                    _,
                    RunTerminal::Failed(RunFailureCode::ProviderInvalidResponse)
                ))
            ));
            assert!(!runtime.calls().iter().any(
                |call| matches!(call, RuntimeCall::Chunk(_, _, text) if text == "old answer")
            ));
            agent.stop().await;
        }
    }

    struct HistoricalAnswerContext;

    #[async_trait]
    impl AgentContextSource for HistoricalAnswerContext {
        async fn load(
            &self,
            lease: &RunExecutionLease,
        ) -> Result<ProviderRequest, AgentContextError> {
            let mut request = FakeContext.load(lease).await?;
            request.messages.insert(
                0,
                ProviderMessage {
                    role: ProviderMessageRole::Assistant,
                    content: "old answer".to_owned(),
                    tool_call_id: None,
                    tool_name: None,
                    tool_calls: Vec::new(),
                },
            );
            Ok(request)
        }
    }

    #[tokio::test]
    async fn earlier_sampling_text_and_committed_tools_do_not_hide_empty_or_failed_answer() {
        for failure in [None, Some(ProviderFailure::GenerationFailed)] {
            let runtime = Arc::new(FakeRuntime::new());
            let usage = ProviderEvent::Usage(ProviderUsage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
            });
            let ending = failure.map_or(ProviderEvent::Completed, ProviderEvent::Failed);
            let provider = Arc::new(SequencedProvider {
                sessions: StdMutex::new(
                    vec![
                        vec![
                            ProviderEvent::TextDelta {
                                index: 0,
                                delta: "working".to_owned(),
                            },
                            ProviderEvent::ToolCallCompleted {
                                index: 0,
                                call_id: "once".to_owned(),
                                name: "remember".to_owned(),
                                arguments: serde_json::json!({"order":1}),
                            },
                            usage.clone(),
                            ProviderEvent::Completed,
                        ],
                        vec![usage, ending],
                    ]
                    .into(),
                ),
                starts: AtomicUsize::new(0),
            });
            let tools = Arc::new(OrderedToolInvoker::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                Arc::new(HistoricalAnswerContext),
                provider.clone(),
                tools.clone(),
                Arc::new(NoAgentAudit),
                test_config(),
            )
            .unwrap();
            let consumer = agent.consumer();
            let lease = lease("run-empty-after-effect");
            assert_eq!(
                consumer.dispatch(lease.clone()).await,
                RunDispatchDecision::Accepted
            );
            consumer.activate(&lease).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
                .await
                .unwrap();
            let code = if failure.is_some() {
                RunFailureCode::ProviderGenerationFailed
            } else {
                RunFailureCode::ProviderInvalidResponse
            };
            assert_eq!(
                runtime.calls(),
                [
                    RuntimeCall::Chunk(1, RunSemanticChannel::Text, "working".to_owned()),
                    RuntimeCall::ToolExchange(
                        2,
                        "once".to_owned(),
                        "remember".to_owned(),
                        "result-1".to_owned()
                    ),
                    RuntimeCall::Finish(3, RunTerminal::Failed(code)),
                ]
            );
            assert_eq!(*tools.seen.lock().unwrap(), [1]);
            assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 2);
            agent.stop().await;
        }
    }

    #[tokio::test]
    async fn accepted_text_stream_reaches_durable_chunk_and_completed_terminal() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(HistoricalAnswerContext),
            Arc::new(FakeProvider {
                events: vec![
                    ProviderEvent::ResponseStarted {
                        response_id: "response-1".to_owned(),
                    },
                    ProviderEvent::TextDelta {
                        index: 0,
                        delta: "hello".to_owned(),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    }),
                    ProviderEvent::Completed,
                ],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-text");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::Chunk(1, RunSemanticChannel::Text, "hello".to_owned()),
                RuntimeCall::Finish(2, RunTerminal::Completed),
            ]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn remote_interrupt_waits_then_reloads_fresh_context_with_new_protocol_lineage() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(RecordingRemoteProvider::default());
        let coordinator = Arc::new(ImmediateRemoteCoordinator::default());
        let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
            runtime.clone(),
            Arc::new(RemoteResumeContext),
            provider.clone(),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            coordinator.clone(),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-remote-resume");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();

        assert_eq!(coordinator.waits.load(AtomicOrdering::SeqCst), 1);
        {
            let routes = provider.routes.lock().expect("remote routes");
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].local_run_id(), "run-remote-resume");
            assert_eq!(routes[0].run_id(), "run-remote-resume");
            assert!(routes[0].resume().is_none());
            assert_eq!(routes[1].local_run_id(), "run-remote-resume");
            assert_eq!(routes[1].run_id(), "protocol-resumed-1");
            assert_eq!(
                routes[1].parent_protocol_run_id(),
                Some("run-remote-resume")
            );
            let resume = routes[1].resume().expect("second route resume");
            assert_eq!(resume.entries().len(), 1);
            assert_eq!(resume.entries()[0].interrupt_id(), "interrupt-1");
        }
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::Chunk(1, RunSemanticChannel::Text, "resumed answer".to_owned()),
                RuntimeCall::Finish(2, RunTerminal::Completed),
            ]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn remote_resume_refuses_endpoint_drift_before_a_second_provider_effect() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(RecordingRemoteProvider::default());
        let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
            runtime.clone(),
            Arc::new(DriftingRemoteResumeContext::default()),
            provider.clone(),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            Arc::new(ImmediateRemoteCoordinator::default()),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-remote-drift");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(provider.routes.lock().expect("remote routes").len(), 1);
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::ProviderInvalidResponse)
            )]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn complete_tool_turn_is_durable_then_reloads_context_and_resamples() {
        let runtime = Arc::new(FakeRuntime::new());
        let context = Arc::new(CountingContext::default());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 0,
                            call_id: "provider-call-1".to_owned(),
                            name: "remember".to_owned(),
                            arguments: serde_json::json!({"content":"tea"}),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 3,
                            output_tokens: 2,
                            total_tokens: 5,
                        }),
                        ProviderEvent::Completed,
                    ],
                    vec![
                        ProviderEvent::TextDelta {
                            index: 0,
                            delta: "remembered".to_owned(),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 5,
                            output_tokens: 1,
                            total_tokens: 6,
                        }),
                        ProviderEvent::Completed,
                    ],
                ]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(FakeToolInvoker::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            context.clone(),
            provider.clone(),
            tools.clone(),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-tool-loop");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::ToolExchange(
                    1,
                    "provider-call-1".to_owned(),
                    "remember".to_owned(),
                    r#"{"status":"remembered"}"#.to_owned(),
                ),
                RuntimeCall::Chunk(2, RunSemanticChannel::Text, "remembered".to_owned()),
                RuntimeCall::Finish(3, RunTerminal::Completed),
            ]
        );
        assert_eq!(context.loads.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(tools.calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            runtime.usage(),
            (
                Some(288),
                2,
                RunTokenUsage {
                    input_tokens: 8,
                    output_tokens: 3,
                    total_tokens: 11,
                },
            )
        );
        agent.stop().await;
        assert_eq!(tools.releases.load(AtomicOrdering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provider_rate_snapshot_cannot_drift_between_tool_samplings() {
        let runtime = Arc::new(FakeRuntime::new());
        let context = Arc::new(DriftingRateContext::default());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "provider-call-priced".to_owned(),
                        name: "remember".to_owned(),
                        arguments: serde_json::json!({"content":"tea"}),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 3,
                        output_tokens: 2,
                        total_tokens: 5,
                    }),
                    ProviderEvent::Completed,
                ]]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(FakeToolInvoker::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            context.clone(),
            provider.clone(),
            tools,
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-price-drift");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(context.loads.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::ToolExchange(
                    1,
                    "provider-call-priced".to_owned(),
                    "remember".to_owned(),
                    r#"{"status":"remembered"}"#.to_owned(),
                ),
                RuntimeCall::Finish(
                    2,
                    RunTerminal::Failed(RunFailureCode::ProviderInvalidResponse),
                ),
            ]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn run_wide_usage_budget_exhaustion_commits_stable_terminal() {
        let runtime = Arc::new(FakeRuntime::rejecting_usage_budget());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 3,
                    output_tokens: 2,
                    total_tokens: 5,
                })],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-wide-budget");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::RunTokenBudgetExceeded),
            )]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn user_cost_cap_rejects_unpriced_or_wrong_currency_before_provider_effect() {
        for (rate_currency, expected, audit_kind, run_id) in [
            (
                None,
                RunFailureCode::RunCostBudgetUnpriced,
                AgentAuditKind::RunCostBudgetUnpriced,
                "run-cost-unpriced",
            ),
            (
                Some("EUR"),
                RunFailureCode::RunCostBudgetCurrencyMismatch,
                AgentAuditKind::RunCostBudgetCurrencyMismatch,
                "run-cost-currency",
            ),
        ] {
            let runtime = Arc::new(FakeRuntime::new());
            let provider = Arc::new(SequencedProvider {
                sessions: StdMutex::new(VecDeque::new()),
                starts: AtomicUsize::new(0),
            });
            let audit = Arc::new(FakeAudit::default());
            let agent = BuiltInAgentRuntime::start(
                runtime.clone(),
                Arc::new(CostBudgetContext {
                    rate_currency,
                    cap_currency: "USD",
                }),
                provider.clone(),
                Arc::new(NoAgentToolInvoker),
                audit.clone(),
                test_config(),
            )
            .unwrap();
            let consumer = agent.consumer();
            let lease = lease(run_id);
            assert_eq!(
                consumer.dispatch(lease.clone()).await,
                RunDispatchDecision::Accepted
            );
            consumer.activate(&lease).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
                .await
                .unwrap();
            assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 0);
            assert_eq!(
                runtime.calls(),
                [RuntimeCall::Finish(1, RunTerminal::Failed(expected))]
            );
            assert_eq!(audit.kinds(), [AgentAuditKind::Invoked, audit_kind]);
            agent.stop().await;
        }
    }

    #[tokio::test]
    async fn user_cost_cap_exhaustion_commits_its_stable_terminal() {
        let runtime = Arc::new(FakeRuntime::rejecting_cost_budget());
        let audit = Arc::new(FakeAudit::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(CostBudgetContext {
                rate_currency: Some("USD"),
                cap_currency: "USD",
            }),
            Arc::new(FakeProvider {
                events: vec![ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 3,
                    output_tokens: 2,
                    total_tokens: 5,
                })],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            audit.clone(),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-cost-budget");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::RunCostBudgetExceeded),
            )]
        );
        assert_eq!(
            audit.kinds(),
            [
                AgentAuditKind::Invoked,
                AgentAuditKind::RunCostBudgetExceeded,
            ]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn human_decision_waits_before_exchange_then_resamples_only_after_commit() {
        let runtime = Arc::new(FakeRuntime::new());
        let context = Arc::new(CountingContext::default());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 0,
                            call_id: "provider-human-1".to_owned(),
                            name: "askApproval".to_owned(),
                            arguments: serde_json::json!({
                                "title":"Refund?",
                                "summary":"Duplicate"
                            }),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 3,
                            output_tokens: 2,
                            total_tokens: 5,
                        }),
                        ProviderEvent::Completed,
                    ],
                    vec![
                        ProviderEvent::TextDelta {
                            index: 0,
                            delta: "approved".to_owned(),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 5,
                            output_tokens: 1,
                            total_tokens: 6,
                        }),
                        ProviderEvent::Completed,
                    ],
                ]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(HumanToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            context.clone(),
            provider.clone(),
            tools.clone(),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-human");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.started.notified())
            .await
            .unwrap();
        assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 1);
        assert!(runtime.calls().is_empty());
        tools.answer.notify_one();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::ToolExchange(
                    1,
                    "provider-human-1".to_owned(),
                    "askApproval".to_owned(),
                    r#"{"decision":"approved"}"#.to_owned(),
                ),
                RuntimeCall::Chunk(2, RunSemanticChannel::Text, "approved".to_owned()),
                RuntimeCall::Finish(3, RunTerminal::Completed),
            ]
        );
        assert_eq!(
            tools.provider_calls.lock().unwrap().as_slice(),
            ["provider-human-1"]
        );
        assert_eq!(tools.completed.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(context.loads.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(provider.starts.load(AtomicOrdering::SeqCst), 2);
        agent.stop().await;
    }

    #[tokio::test]
    async fn cancelled_human_wait_is_detached_long_enough_for_durable_retirement() {
        let runtime = Arc::new(FakeRuntime::new());
        let tools = Arc::new(HumanToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "provider-human-cancel".to_owned(),
                        name: "askApproval".to_owned(),
                        arguments: serde_json::json!({
                            "title":"Refund?",
                            "summary":"Duplicate"
                        }),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 3,
                        output_tokens: 2,
                        total_tokens: 5,
                    }),
                    ProviderEvent::Completed,
                ],
                hold: false,
            }),
            tools.clone(),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-human-cancel");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.started.notified())
            .await
            .unwrap();
        assert_eq!(
            consumer.revoke(&lease).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert!(
            runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::Finish(_, RunTerminal::Cancelled)))
        );
        tools.answer.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while tools.completed.load(AtomicOrdering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tools.completed.load(AtomicOrdering::SeqCst), 1);
        agent.stop().await;
    }

    #[tokio::test]
    async fn non_parallel_tool_batch_executes_by_stable_output_index_and_reinjects_in_order() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 5,
                            call_id: "provider-five".to_owned(),
                            name: "remember".to_owned(),
                            arguments: serde_json::json!({"order":5}),
                        },
                        ProviderEvent::ToolCallCompleted {
                            index: 1,
                            call_id: "provider-one".to_owned(),
                            name: "remember".to_owned(),
                            arguments: serde_json::json!({"order":1}),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 3,
                            output_tokens: 2,
                            total_tokens: 5,
                        }),
                        ProviderEvent::Completed,
                    ],
                    vec![
                        ProviderEvent::TextDelta {
                            index: 0,
                            delta: "fresh result".to_owned(),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 5,
                            output_tokens: 1,
                            total_tokens: 6,
                        }),
                        ProviderEvent::Completed,
                    ],
                ]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(OrderedToolInvoker::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-tool-order");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(*tools.seen.lock().expect("ordered tools"), [1, 5]);
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::ToolExchange(
                    1,
                    "provider-one".to_owned(),
                    "remember".to_owned(),
                    "result-1".to_owned(),
                ),
                RuntimeCall::ToolExchange(
                    2,
                    "provider-five".to_owned(),
                    "remember".to_owned(),
                    "result-5".to_owned(),
                ),
                RuntimeCall::Chunk(3, RunSemanticChannel::Text, "fresh result".to_owned()),
                RuntimeCall::Finish(4, RunTerminal::Completed),
            ]
        );
        agent.stop().await;
    }

    #[test]
    fn scheduler_only_groups_parallel_safe_calls_with_disjoint_resource_locks() {
        let waves = schedule_tool_waves(
            &SchedulingOnlyInvoker,
            vec![
                test_tool_call("parallel-a-1", 0),
                test_tool_call("parallel-b", 1),
                test_tool_call("parallel-a-2", 2),
                test_tool_call("serial", 3),
            ],
        );
        assert_eq!(waves.len(), 3);
        assert!(waves[0].parallel);
        assert_eq!(waves[0].calls.len(), 2);
        assert!(waves[1].parallel);
        assert_eq!(waves[1].calls.len(), 1);
        assert!(!waves[2].parallel);
        assert_eq!(waves[2].calls.len(), 1);

        let forced_human_serial = schedule_tool_waves(
            &ParallelToolInvoker::new(),
            vec![test_tool_call("askApproval", 4)],
        );
        assert_eq!(forced_human_serial.len(), 1);
        assert!(!forced_human_serial[0].parallel);
    }

    #[tokio::test]
    async fn resource_lock_budget_serializes_same_key_but_not_disjoint_keys() {
        let resources = ToolResourceLocks::default();
        let key_a = ResourceLockKey::new("resource:a").expect("test key");
        let key_b = ResourceLockKey::new("resource:b").expect("test key");
        let first_keys = vec![key_a.clone()];
        let first = resources.acquire(&first_keys).await.unwrap();

        let other_keys = vec![key_b];
        let other = tokio::time::timeout(Duration::from_millis(50), resources.acquire(&other_keys))
            .await
            .expect("disjoint resource must not wait")
            .unwrap();
        drop(other);

        let waiting_keys = vec![key_a];
        let mut waiting = Box::pin(resources.acquire(&waiting_keys));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), waiting.as_mut())
                .await
                .is_err(),
            "same resource lock must stay blocked"
        );
        drop(first);
        tokio::time::timeout(Duration::from_millis(50), waiting)
            .await
            .expect("same resource proceeds after release")
            .unwrap();
    }

    #[tokio::test]
    async fn parallel_safe_batch_obeys_global_budget_and_commits_results_in_provider_order() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 3,
                            call_id: "provider-3".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":3}),
                        },
                        ProviderEvent::ToolCallCompleted {
                            index: 0,
                            call_id: "provider-0".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":0}),
                        },
                        ProviderEvent::ToolCallCompleted {
                            index: 2,
                            call_id: "provider-2".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":2}),
                        },
                        ProviderEvent::ToolCallCompleted {
                            index: 1,
                            call_id: "provider-1".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":1}),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 4,
                            output_tokens: 4,
                            total_tokens: 8,
                        }),
                        ProviderEvent::Completed,
                    ],
                    vec![
                        ProviderEvent::TextDelta {
                            index: 0,
                            delta: "fresh result".to_owned(),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 2,
                            output_tokens: 1,
                            total_tokens: 3,
                        }),
                        ProviderEvent::Completed,
                    ],
                ]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(ParallelToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            Arc::new(NoAgentAudit),
            BuiltInAgentConfig {
                max_tool_concurrency: 2,
                ..test_config()
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-parallel-tools");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();

        assert_eq!(tools.max_active.load(AtomicOrdering::SeqCst), 2);
        let mut completed = tools.completed.lock().expect("parallel completion").clone();
        completed.sort_unstable();
        assert_eq!(completed, [0, 1, 2, 3]);
        assert_eq!(
            runtime.calls(),
            [
                RuntimeCall::ToolExchange(
                    1,
                    "provider-0".to_owned(),
                    "parallel".to_owned(),
                    "result-0".to_owned(),
                ),
                RuntimeCall::ToolExchange(
                    2,
                    "provider-1".to_owned(),
                    "parallel".to_owned(),
                    "result-1".to_owned(),
                ),
                RuntimeCall::ToolExchange(
                    3,
                    "provider-2".to_owned(),
                    "parallel".to_owned(),
                    "result-2".to_owned(),
                ),
                RuntimeCall::ToolExchange(
                    4,
                    "provider-3".to_owned(),
                    "parallel".to_owned(),
                    "result-3".to_owned(),
                ),
                RuntimeCall::Chunk(5, RunSemanticChannel::Text, "fresh result".to_owned()),
                RuntimeCall::Finish(6, RunTerminal::Completed),
            ]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_tool_budget_never_starts_the_queued_tool() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 0,
                            call_id: "provider-first".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":0}),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 1,
                            output_tokens: 1,
                            total_tokens: 2,
                        }),
                        ProviderEvent::Completed,
                    ],
                    vec![
                        ProviderEvent::ToolCallCompleted {
                            index: 0,
                            call_id: "provider-second".to_owned(),
                            name: "parallel".to_owned(),
                            arguments: serde_json::json!({"order":1}),
                        },
                        ProviderEvent::Usage(ProviderUsage {
                            input_tokens: 1,
                            output_tokens: 1,
                            total_tokens: 2,
                        }),
                        ProviderEvent::Completed,
                    ],
                ]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(BudgetBlockingToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            Arc::new(NoAgentAudit),
            BuiltInAgentConfig {
                queue_capacity: 2,
                max_concurrency: 2,
                max_tool_concurrency: 1,
                lease_renew_interval: Duration::from_secs(1),
                run_deadline: Some(Duration::from_secs(2)),
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let first = lease("run-tool-budget-first");
        let second = lease("run-tool-budget-second");
        assert_eq!(
            consumer.dispatch(first.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&first).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.first_started.notified())
            .await
            .unwrap();

        assert_eq!(
            consumer.dispatch(second.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&second).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.second_scheduled.notified())
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            consumer.revoke(&second).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .expect("tool budget waiter must commit a terminal");
        assert_eq!(tools.started.load(AtomicOrdering::SeqCst), 1);
        assert!(
            runtime
                .calls()
                .iter()
                .any(|call| { matches!(call, RuntimeCall::Finish(1, RunTerminal::Cancelled)) })
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn cancelling_started_parallel_tools_aborts_children_then_requires_reconciliation() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "provider-first".to_owned(),
                        name: "parallel".to_owned(),
                        arguments: serde_json::json!({"order":0}),
                    },
                    ProviderEvent::ToolCallCompleted {
                        index: 1,
                        call_id: "provider-second".to_owned(),
                        name: "parallel".to_owned(),
                        arguments: serde_json::json!({"order":1}),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 2,
                        output_tokens: 2,
                        total_tokens: 4,
                    }),
                    ProviderEvent::Completed,
                ]]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(BudgetBlockingToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            Arc::new(NoAgentAudit),
            BuiltInAgentConfig {
                max_tool_concurrency: 2,
                ..test_config()
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-started-parallel-cancel");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while tools.started.load(AtomicOrdering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            consumer.revoke(&lease).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert!(runtime.calls().iter().any(|call| {
            matches!(
                call,
                RuntimeCall::Finish(
                    1,
                    RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
                )
            )
        }));
        assert!(
            !runtime
                .calls()
                .iter()
                .any(|call| { matches!(call, RuntimeCall::Finish(_, RunTerminal::Cancelled)) })
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn reported_output_above_authoritative_token_cap_fails_before_completed() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![
                    ProviderEvent::ResponseStarted {
                        response_id: "response-budget".to_owned(),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 10,
                        output_tokens: 33,
                        total_tokens: 43,
                    }),
                    ProviderEvent::Completed,
                ],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-token-budget");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::ProviderTokenBudgetExceeded)
            )]
        );
        assert_eq!(
            runtime.usage(),
            (
                Some(288),
                1,
                RunTokenUsage {
                    input_tokens: 10,
                    output_tokens: 33,
                    total_tokens: 43,
                },
            )
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn completed_without_usage_cannot_bypass_authoritative_token_cap() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![
                    ProviderEvent::ResponseStarted {
                        response_id: "response-no-usage".to_owned(),
                    },
                    ProviderEvent::Completed,
                ],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-no-usage");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::ProviderInvalidResponse)
            )]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn serial_tool_receives_run_cancel_and_stops_before_reconciliation_terminal() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "provider-cooperative-cancel".to_owned(),
                        name: "remember".to_owned(),
                        arguments: serde_json::json!({"content":"tea"}),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    }),
                    ProviderEvent::Completed,
                ]]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(CooperativeCancellationToolInvoker::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-cooperative-tool-cancel");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.started.notified())
            .await
            .expect("tool invocation starts");

        assert_eq!(
            consumer.revoke(&lease).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .expect("reconciliation terminal");
        assert!(tools.stopped.load(AtomicOrdering::SeqCst));
        assert_eq!(
            *tools.reason.lock().expect("cancellation reason"),
            Some(ToolCancellationReason::User)
        );
        assert!(runtime.calls().iter().any(|call| {
            matches!(
                call,
                RuntimeCall::Finish(
                    1,
                    RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
                )
            )
        }));
        assert!(
            !runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::ToolExchange(..)))
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn serial_tool_receives_deadline_reason_before_reconciliation_terminal() {
        let runtime = Arc::new(FakeRuntime::new());
        let provider = Arc::new(SequencedProvider {
            sessions: StdMutex::new(
                vec![vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "provider-cooperative-deadline".to_owned(),
                        name: "remember".to_owned(),
                        arguments: serde_json::json!({"content":"tea"}),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    }),
                    ProviderEvent::Completed,
                ]]
                .into(),
            ),
            starts: AtomicUsize::new(0),
        });
        let tools = Arc::new(CooperativeCancellationToolInvoker::new());
        let audit = Arc::new(StopAwareDeadlineAudit {
            stopped: tools.stopped.clone(),
            observed: AtomicBool::new(false),
        });
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            provider,
            tools.clone(),
            audit.clone(),
            BuiltInAgentConfig {
                run_deadline: Some(Duration::from_millis(100)),
                ..test_config()
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-cooperative-tool-deadline");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), tools.started.notified())
            .await
            .expect("tool invocation starts before deadline");
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .expect("deadline reconciliation terminal");

        assert!(tools.stopped.load(AtomicOrdering::SeqCst));
        assert_eq!(
            *tools.reason.lock().expect("deadline reason"),
            Some(ToolCancellationReason::Deadline)
        );
        assert!(audit.observed.load(AtomicOrdering::SeqCst));
        assert!(runtime.calls().iter().any(|call| {
            matches!(
                call,
                RuntimeCall::Finish(
                    1,
                    RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
                )
            )
        }));
        agent.stop().await;
    }

    #[tokio::test]
    async fn tool_call_fails_closed_until_unique_tool_loop_is_connected() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![
                    ProviderEvent::ToolCallCompleted {
                        index: 0,
                        call_id: "call-1".to_owned(),
                        name: "remember".to_owned(),
                        arguments: serde_json::json!({"content":"x"}),
                    },
                    ProviderEvent::Usage(ProviderUsage {
                        input_tokens: 1,
                        output_tokens: 1,
                        total_tokens: 2,
                    }),
                    ProviderEvent::Completed,
                ],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-tool");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::ToolLoopUnavailable)
            )]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn revoke_active_provider_waits_for_drop_then_commits_cancelled() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: Vec::new(),
                hold: true,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-cancel");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            consumer.revoke(&lease).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(1, RunTerminal::Cancelled)]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn revoke_activated_run_waiting_for_concurrency_commits_cancelled() {
        let runtime = Arc::new(FakeRuntime::new());
        let context = Arc::new(NotifyingHoldingContext {
            started: Notify::new(),
        });
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            context.clone(),
            Arc::new(FakeProvider {
                events: Vec::new(),
                hold: true,
            }),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            BuiltInAgentConfig {
                queue_capacity: 2,
                max_concurrency: 1,
                max_tool_concurrency: 1,
                lease_renew_interval: Duration::from_secs(1),
                run_deadline: Some(Duration::from_secs(2)),
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let active = lease("run-active");
        let queued = lease("run-queued-cancel");
        assert_eq!(
            consumer.dispatch(active.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&active).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), context.started.notified())
            .await
            .unwrap();
        assert_eq!(
            consumer.dispatch(queued.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&queued).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            consumer.revoke(&queued).await,
            RunCancellationDisposition::ChildSignalled
        );
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .expect("等待并发许可的 run 也必须提交 durable terminal");
        assert!(
            runtime
                .calls()
                .iter()
                .any(|call| { matches!(call, RuntimeCall::Finish(1, RunTerminal::Cancelled)) })
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn absolute_deadline_and_lease_heartbeat_start_before_context_finishes() {
        let runtime = Arc::new(FakeRuntime::new());
        let audit = Arc::new(FakeAudit::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(HoldingContext),
            Arc::new(FakeProvider {
                events: Vec::new(),
                hold: true,
            }),
            Arc::new(NoAgentToolInvoker),
            audit.clone(),
            BuiltInAgentConfig {
                queue_capacity: 4,
                max_concurrency: 2,
                max_tool_concurrency: 2,
                lease_renew_interval: Duration::from_millis(5),
                run_deadline: Some(Duration::from_millis(30)),
            },
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-context-deadline");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        let calls = runtime.calls();
        assert!(calls.iter().any(|call| call == &RuntimeCall::Renew));
        assert_eq!(
            calls.last(),
            Some(&RuntimeCall::Finish(1, RunTerminal::Cancelled))
        );
        assert_eq!(
            audit.kinds(),
            [AgentAuditKind::Invoked, AgentAuditKind::RunDeadlineExceeded]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn stream_stall_is_audited_before_failed_terminal() {
        let runtime = Arc::new(FakeRuntime::new());
        let audit = Arc::new(FakeAudit::default());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FakeProvider {
                events: vec![ProviderEvent::Failed(ProviderFailure::StreamStalled)],
                hold: false,
            }),
            Arc::new(NoAgentToolInvoker),
            audit.clone(),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-stall-audit");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::Failed(RunFailureCode::ProviderStreamStalled)
            )]
        );
        assert_eq!(
            audit.kinds(),
            [AgentAuditKind::Invoked, AgentAuditKind::StreamStalled]
        );
        agent.stop().await;
    }

    #[tokio::test]
    async fn provider_start_commit_unknown_is_reconciliation_not_retry_or_failure() {
        let runtime = Arc::new(FakeRuntime::new());
        let agent = BuiltInAgentRuntime::start(
            runtime.clone(),
            Arc::new(FakeContext),
            Arc::new(FailingStartProvider(ProviderPortError::CommitUnknown)),
            Arc::new(NoAgentToolInvoker),
            Arc::new(NoAgentAudit),
            test_config(),
        )
        .unwrap();
        let consumer = agent.consumer();
        let lease = lease("run-provider-unknown");
        assert_eq!(
            consumer.dispatch(lease.clone()).await,
            RunDispatchDecision::Accepted
        );
        consumer.activate(&lease).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime.terminal.notified())
            .await
            .unwrap();
        assert_eq!(
            runtime.calls(),
            [RuntimeCall::Finish(
                1,
                RunTerminal::ReconciliationRequired(RunFailureCode::ProviderCommitUnknown)
            )]
        );
        agent.stop().await;
    }
    #[tokio::test]
    async fn custom_sampling_binding_rejects_promotion_fallback_and_identity_or_revision_drift() {
        use openbot_contracts::{
            auth::AuthGeneration,
            ids::{DeploymentId, TenantId},
            model_connections::{CustomModelProtocol, RunModelSelection},
        };
        let run = lease("custom-consistency");
        let custom = |revision, generation, model: &str| {
            openbot_application::RunModelBinding::from_verified_snapshot(
                &run,
                DeploymentId::new("deployment"),
                TenantId::new("tenant"),
                AuthGeneration::new(generation),
                RunModelSelection {
                    connection_id: "11111111-1111-1111-1111-111111111111".into(),
                    expected_revision: revision,
                },
                "22222222-2222-2222-2222-222222222222".into(),
                openbot_application::model_connections::normalize_model_configuration(
                    "name",
                    CustomModelProtocol::OpenaiResponses,
                    "https://models.example.test/v1",
                    model,
                    true,
                )
                .unwrap(),
            )
            .unwrap()
        };
        let mut request = FakeContext.load(&run).await.unwrap();
        let legacy = request.clone();
        request.route = ProviderRoute::CustomModel(custom(1, 7, "one"));
        let mut bound = None;
        assert!(bind_custom_model(&mut bound, &request, &run));
        let later = RunExecutionLease::new(
            run.run_id().clone(),
            run.thread_id().clone(),
            run.bot_id().clone(),
            run.actor_id().clone(),
            run.fencing(),
            42,
        )
        .unwrap();
        assert!(bind_custom_model(&mut bound, &request, &later));
        assert!(!bind_custom_model(&mut bound, &legacy, &run));
        for changed in [
            custom(2, 7, "one"),
            custom(1, 8, "one"),
            custom(1, 7, "two"),
        ] {
            let mut drift = request.clone();
            drift.route = ProviderRoute::CustomModel(changed);
            assert!(!bind_custom_model(&mut bound, &drift, &run));
        }
        assert!(!bind_custom_model(
            &mut bound,
            &request,
            &lease("another-run")
        ));
        let mut first_legacy = None;
        assert!(bind_custom_model(&mut first_legacy, &legacy, &run));
        assert!(!bind_custom_model(&mut first_legacy, &request, &run));
    }

    #[tokio::test]
    async fn custom_v2_sampling_sticks_to_full_selection_dataset_policy_and_version() {
        use openbot_application::{
            RunModelBinding, RunModelCredentialPolicy, RunModelDatasetInitialOrigin,
            RunModelDatasetSnapshot, RunModelV2Snapshot,
        };
        use openbot_contracts::{
            auth::AuthGeneration,
            ids::{DeploymentId, TenantId},
            model_connections::{CustomModelProtocol, RunModelSelection},
            versioned_model_selection::{ModelSelectionIntentSource, RunModelSelectionV2},
        };
        let run = lease("custom-v2-consistency");
        let configuration = || {
            openbot_application::model_connections::normalize_model_configuration(
                "name",
                CustomModelProtocol::OpenaiResponses,
                "https://models.example.test/v1",
                "one",
                true,
            )
            .unwrap()
        };
        let v2 = |catalog_revision, dataset: &str, origin, created_seconds, connection: &str| {
            let snapshot = RunModelV2Snapshot::new(
                RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    connection.to_owned(),
                    1,
                    "custom:abcdef12-abcd-4bcd-8abc-abcdef123456".to_owned(),
                    catalog_revision,
                )
                .unwrap(),
                RunModelDatasetSnapshot::new(
                    dataset.to_owned(),
                    1,
                    origin,
                    time::OffsetDateTime::from_unix_timestamp(created_seconds).unwrap(),
                )
                .unwrap(),
                RunModelCredentialPolicy::CustomFixedSecretRevisionV1,
            )
            .unwrap();
            RunModelBinding::from_verified_v2_snapshot(
                &run,
                DeploymentId::new("deployment"),
                TenantId::new("tenant"),
                AuthGeneration::new(7),
                snapshot,
                "22222222-2222-2222-2222-222222222222".to_owned(),
                configuration(),
            )
            .unwrap()
        };
        let connection = "abcdef12-abcd-4bcd-8abc-abcdef123456";
        let origin = RunModelDatasetInitialOrigin::ServerFirstAdoption;
        let original = v2(2, "dataset-original", origin, 1, connection);
        let mut request = FakeContext.load(&run).await.unwrap();
        request.route = ProviderRoute::CustomModel(original.clone());
        let mut bound = None;
        assert!(bind_custom_model(&mut bound, &request, &run));
        assert!(bind_custom_model(&mut bound, &request, &run));
        let legacy = RunModelBinding::from_verified_snapshot(
            &run,
            DeploymentId::new("deployment"),
            TenantId::new("tenant"),
            AuthGeneration::new(7),
            RunModelSelection {
                connection_id: connection.to_owned(),
                expected_revision: 1,
            },
            "22222222-2222-2222-2222-222222222222".to_owned(),
            configuration(),
        )
        .unwrap();
        let changed_definition = |model_id: &str, model: &str| {
            let snapshot = RunModelV2Snapshot::new(
                RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    connection.to_owned(),
                    1,
                    model_id.to_owned(),
                    2,
                )
                .unwrap(),
                original.v2_snapshot().unwrap().dataset().clone(),
                RunModelCredentialPolicy::CustomFixedSecretRevisionV1,
            )
            .unwrap();
            let changed_configuration =
                openbot_application::model_connections::normalize_model_configuration(
                    "name",
                    CustomModelProtocol::OpenaiResponses,
                    "https://models.example.test/v1",
                    model,
                    true,
                )
                .unwrap();
            RunModelBinding::from_verified_v2_snapshot(
                &run,
                DeploymentId::new("deployment"),
                TenantId::new("tenant"),
                AuthGeneration::new(7),
                snapshot,
                "22222222-2222-2222-2222-222222222222".to_owned(),
                changed_configuration,
            )
            .unwrap()
        };
        for drift in [
            v2(3, "dataset-original", origin, 1, connection),
            v2(2, "dataset-other", origin, 1, connection),
            v2(
                2,
                "dataset-original",
                RunModelDatasetInitialOrigin::DesktopCanary,
                1,
                connection,
            ),
            v2(2, "dataset-original", origin, 2, connection),
            v2(
                2,
                "dataset-original",
                origin,
                1,
                "ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456",
            ),
            changed_definition("custom:different-intent", "one"),
            changed_definition("custom:abcdef12-abcd-4bcd-8abc-abcdef123456", "two"),
            legacy,
        ] {
            assert_eq!(original.connection_id(), drift.connection_id());
            assert_eq!(original.connection_revision(), drift.connection_revision());
            let mut changed = request.clone();
            changed.route = ProviderRoute::CustomModel(drift);
            assert!(!bind_custom_model(&mut bound, &changed, &run));
        }
        request.rate_card = Some(
            openbot_application::ProviderRateCard::new(
                openbot_application::ProviderRateCardInput {
                    family: openbot_application::ProviderBillingFamily::OpenAiCompatible,
                    model: "one".to_owned(),
                    currency: "USD".to_owned(),
                    max_input_micro_units_per_million_tokens: 1,
                    max_output_micro_units_per_million_tokens: 1,
                    source_url: "https://prices.example.test/attestation".to_owned(),
                    source_sha256: "a".repeat(64),
                    observed_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            )
            .unwrap(),
        );
        assert!(!bind_custom_model(&mut bound, &request, &run));
    }
}
