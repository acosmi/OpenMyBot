use super::*;
use crate::{NoAgentToolInvoker, RetryingProvider, RetryingProviderConfig};
use openbot_application::{
    AgentAuditError, ClaimedRunDispatch, ProviderMessage, ProviderMessageRole, ProviderRequest,
    RunSemanticChannel, RunWriteReceipt,
};
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId};
use openbot_domain::agent::AgentPhase;
use openbot_domain::thread::FencingToken;
use std::collections::VecDeque;
use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

const AT: SystemTime = UNIX_EPOCH;
#[derive(Clone, Copy)]
enum Plan {
    Ready(Result<StopOutcome, ProviderPortError>),
    Pending,
    Release(StopOutcome),
    Late(Duration),
    PendingThenLate(tokio::time::Instant),
}
#[derive(Clone, Copy)]
enum Stream {
    Hold,
    Stall,
    Text,
    Tools,
}
#[derive(Clone, Copy)]
enum Renewal {
    Ok,
    Lost,
    LostWhileStopping,
    PendingWhileStopping,
}
#[derive(Clone, Debug, PartialEq)]
enum Seen {
    Context,
    Start,
    Stream,
    Stop,
    StopDrop,
    SessionDrop,
    Renew,
    RenewDrop,
    Audit(AgentAuditKind),
    Finish(RunTerminal),
    Ack,
    Chunk(String),
}
struct Control {
    id: String,
    plan: Plan,
    stream: Stream,
    default_stop: bool,
    renewal: Renewal,
    audit_error: Option<AgentAuditKind>,
    finish_error: Option<RunRuntimeError>,
    context_pending: bool,
    start_pending: bool,
    log: StdMutex<Vec<Seen>>,
    writes: StdMutex<Vec<(u64, &'static str)>>,
    stream_started: AtomicBool,
    stop_calls: AtomicUsize,
    stop_polls: AtomicUsize,
    late_pending: AtomicBool,
    late_ready: StdMutex<Option<(tokio::time::Instant, tokio::time::Instant)>>,
    entered: Notify,
    context_entered: Notify,
    start_entered: Notify,
    stopping: Notify,
    release: Notify,
    renewal_failed: Notify,
    finished: Notify,
}
impl Control {
    fn new(id: &str, plan: Plan) -> Self {
        Self {
            id: id.into(),
            plan,
            stream: Stream::Hold,
            default_stop: false,
            renewal: Renewal::Ok,
            audit_error: None,
            finish_error: None,
            context_pending: false,
            start_pending: false,
            log: StdMutex::new(vec![]),
            writes: StdMutex::new(vec![]),
            stream_started: AtomicBool::new(false),
            stop_calls: AtomicUsize::new(0),
            stop_polls: AtomicUsize::new(0),
            late_pending: AtomicBool::new(false),
            late_ready: StdMutex::new(None),
            entered: Notify::new(),
            context_entered: Notify::new(),
            start_entered: Notify::new(),
            stopping: Notify::new(),
            release: Notify::new(),
            renewal_failed: Notify::new(),
            finished: Notify::new(),
        }
    }
    fn push(&self, seen: Seen) {
        self.log.lock().unwrap().push(seen);
    }
    fn events(&self) -> Vec<Seen> {
        self.log.lock().unwrap().clone()
    }
    fn calls(&self) -> usize {
        self.stop_calls.load(AtomicOrdering::SeqCst)
    }
}
struct Mark(Arc<Control>, Seen);
impl Drop for Mark {
    fn drop(&mut self) {
        self.0.push(self.1.clone());
    }
}
struct Session {
    control: Arc<Control>,
    events: VecDeque<ProviderEvent>,
}
impl Session {
    fn new(control: Arc<Control>) -> Self {
        let events = match control.stream {
            Stream::Hold => vec![],
            Stream::Stall => vec![ProviderEvent::Failed(ProviderFailure::StreamStalled)],
            Stream::Text => vec![
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "original".into(),
                },
                ProviderEvent::Completed,
            ],
            Stream::Tools => vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-call".into(),
                    name: "fixture".into(),
                    arguments: serde_json::json!({}),
                },
                ProviderEvent::Completed,
            ],
        }
        .into();
        Self { control, events }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.control.push(Seen::SessionDrop);
    }
}
#[async_trait]
impl ProviderSession for Session {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        self.control
            .stream_started
            .store(true, AtomicOrdering::SeqCst);
        self.control.push(Seen::Stream);
        self.control.entered.notify_one();
        if let Some(event) = self.events.pop_front() {
            Ok(Some(event))
        } else {
            pending().await
        }
    }
    async fn request_stop(&mut self) -> Result<StopOutcome, ProviderPortError> {
        let control = self.control.clone();
        let plan = control.plan;
        control.stop_calls.fetch_add(1, AtomicOrdering::SeqCst);
        control.push(Seen::Stop);
        control.stopping.notify_one();
        let _guard = Mark(control.clone(), Seen::StopDrop);
        let release = control.release.notified();
        tokio::pin!(release);
        poll_fn(|cx| {
            let poll = control.stop_polls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            match plan {
                Plan::Ready(result) => Poll::Ready(result),
                Plan::Pending => Poll::Pending,
                Plan::Release(outcome) => release.as_mut().poll(cx).map(|()| Ok(outcome)),
                Plan::Late(delay) => {
                    std::thread::sleep(delay);
                    Poll::Ready(Ok(StopOutcome::Confirmed { at: AT }))
                }
                Plan::PendingThenLate(ready_at) => {
                    if poll == 1 {
                        control.late_pending.store(true, AtomicOrdering::SeqCst);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        let started = tokio::time::Instant::now();
                        std::thread::sleep(ready_at.saturating_duration_since(started));
                        let returned = tokio::time::Instant::now();
                        *control.late_ready.lock().unwrap() = Some((started, returned));
                        Poll::Ready(Ok(StopOutcome::Confirmed { at: AT }))
                    }
                }
            }
        })
        .await
    }
}
struct DefaultSession(Session);
#[async_trait]
impl ProviderSession for DefaultSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        self.0.next_event().await
    }
}
struct Lab {
    controls: Vec<Arc<Control>>,
}
impl Lab {
    fn control(&self, id: &str) -> Arc<Control> {
        self.controls.iter().find(|c| c.id == id).unwrap().clone()
    }
}
fn lease(id: &str) -> RunExecutionLease {
    RunExecutionLease::new(
        RunId::new(id),
        ThreadId::new(format!("stop-thread-{id}")),
        BotId::new("bot"),
        ActorId::new("owner"),
        FencingToken::new(1).unwrap(),
        1,
    )
    .unwrap()
}
fn receipt(sequence: u64) -> RunWriteReceipt {
    RunWriteReceipt {
        run_event_sequence: sequence,
        thread_event_sequence: sequence,
        message_sequence: None,
        replayed: false,
    }
}
#[async_trait]
impl RunRuntime for Lab {
    async fn claim_dispatch(&self) -> Result<Option<ClaimedRunDispatch>, RunRuntimeError> {
        panic!("relay not used")
    }
    async fn acknowledge_dispatch(
        &self,
        _: &ClaimedRunDispatch,
    ) -> Result<RunExecutionLease, RunRuntimeError> {
        panic!("relay not used")
    }
    async fn retry_dispatch(&self, _: &ClaimedRunDispatch) -> Result<(), RunRuntimeError> {
        panic!("relay not used")
    }
    async fn reject_dispatch(
        &self,
        _: &ClaimedRunDispatch,
        _: RunFailureCode,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        panic!("relay not used")
    }
    async fn renew_lease(&self, lease: &RunExecutionLease) -> Result<(), RunRuntimeError> {
        let c = self.control(lease.run_id().as_str());
        c.push(Seen::Renew);
        let _guard = Mark(c.clone(), Seen::RenewDrop);
        match c.renewal {
            Renewal::Lost if c.stream_started.load(AtomicOrdering::SeqCst) => {
                c.renewal_failed.notify_one();
                Err(RunRuntimeError::StaleLease)
            }
            Renewal::LostWhileStopping if c.calls() > 0 => {
                c.renewal_failed.notify_one();
                Err(RunRuntimeError::Unavailable)
            }
            Renewal::PendingWhileStopping if c.calls() > 0 => pending().await,
            _ => Ok(()),
        }
    }
    async fn append_semantic_chunk(
        &self,
        lease: &RunExecutionLease,
        sequence: u64,
        _: RunSemanticChannel,
        chunk: &str,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        let control = self.control(lease.run_id().as_str());
        control.writes.lock().unwrap().push((sequence, "chunk"));
        control.push(Seen::Chunk(chunk.into()));
        Ok(receipt(sequence))
    }
    async fn finish_run(
        &self,
        lease: &RunExecutionLease,
        sequence: u64,
        terminal: RunTerminal,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        let c = self.control(lease.run_id().as_str());
        c.writes.lock().unwrap().push((sequence, "finish"));
        c.push(Seen::Finish(terminal));
        let result = match &c.finish_error {
            Some(error) => Err(*error),
            None => {
                c.push(Seen::Ack);
                Ok(receipt(sequence))
            }
        };
        c.finished.notify_one();
        result
    }
    async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError> {
        panic!("recovery not exercised")
    }
}
#[async_trait]
impl AgentContextSource for Lab {
    async fn load(&self, lease: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError> {
        let c = self.control(lease.run_id().as_str());
        c.push(Seen::Context);
        c.context_entered.notify_one();
        if c.context_pending {
            return pending().await;
        }
        Ok(ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: c.id.clone(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            }],
            tools: vec![],
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        })
    }
}
#[async_trait]
impl ProviderAdapter for Lab {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let c = self.control(&request.messages[0].content);
        c.push(Seen::Start);
        c.start_entered.notify_one();
        if c.start_pending {
            return pending().await;
        }
        let session = Session::new(c.clone());
        Ok(if c.default_stop {
            Box::new(DefaultSession(session))
        } else {
            Box::new(session)
        })
    }
}
#[async_trait]
impl AgentAudit for Lab {
    async fn record(
        &self,
        lease: &RunExecutionLease,
        kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError> {
        let c = self.control(lease.run_id().as_str());
        c.push(Seen::Audit(kind));
        if c.audit_error == Some(kind) {
            Err(AgentAuditError::Unavailable)
        } else {
            Ok(())
        }
    }
}
fn config(deadline: Option<Duration>) -> BuiltInAgentConfig {
    BuiltInAgentConfig {
        queue_capacity: 8,
        max_concurrency: 4,
        max_tool_concurrency: 2,
        lease_renew_interval: Duration::from_millis(5),
        run_deadline: deadline,
    }
}
async fn activate(agent: &BuiltInAgentRuntime, id: &str) -> Result<(), RunFailureCode> {
    let consumer = agent.consumer();
    let lease = lease(id);
    if consumer.dispatch(lease.clone()).await != RunDispatchDecision::Accepted {
        return Err(RunFailureCode::AgentRuntimeUnavailable);
    }
    consumer.activate(&lease).await
}
#[derive(Clone, Copy)]
enum Trigger {
    User,
    Deadline,
    Stall,
    Lease,
    Normal,
}
async fn case(mut c: Control, trigger: Trigger) -> Arc<Control> {
    c.stream = match trigger {
        Trigger::Stall => Stream::Stall,
        Trigger::Normal => c.stream,
        _ => Stream::Hold,
    };
    let c = Arc::new(c);
    let lab = Arc::new(Lab {
        controls: vec![c.clone()],
    });
    let deadline = if matches!(trigger, Trigger::Deadline | Trigger::Lease)
        || matches!(c.plan, Plan::Pending)
    {
        Duration::from_millis(250)
    } else {
        Duration::from_secs(2)
    };
    let agent = BuiltInAgentRuntime::start(
        lab.clone(),
        lab.clone(),
        lab.clone(),
        Arc::new(NoAgentToolInvoker),
        lab,
        config(Some(deadline)),
    )
    .unwrap();
    let activation = activate(&agent, &c.id).await;
    let entered = if matches!(trigger, Trigger::User) {
        tokio::time::timeout(Duration::from_secs(1), c.entered.notified())
            .await
            .is_ok()
    } else {
        true
    };
    let revoked = if entered && matches!(trigger, Trigger::User) {
        Some(agent.consumer().revoke(&lease(&c.id)).await)
    } else {
        None
    };
    let finished = tokio::time::timeout(Duration::from_secs(4), c.finished.notified()).await;
    agent.stop().await;
    assert!(activation.is_ok());
    assert!(entered);
    assert!(finished.is_ok());
    if let Some(revoked) = revoked {
        assert_eq!(revoked, RunCancellationDisposition::ChildSignalled);
    }
    c
}
fn terminal(c: &Control) -> RunTerminal {
    c.events()
        .into_iter()
        .find_map(|e| {
            if let Seen::Finish(t) = e {
                Some(t)
            } else {
                None
            }
        })
        .unwrap()
}
fn unknown() -> RunTerminal {
    RunTerminal::ReconciliationRequired(RunFailureCode::ProviderStopUnknown)
}
fn ordered(c: &Control, before: Seen, after: Seen) {
    let events = c.events();
    let a = events.iter().position(|e| *e == before).unwrap();
    let b = events.iter().position(|e| *e == after).unwrap();
    assert!(a < b, "{events:?}");
}
fn stopped_before_finish(c: &Control) {
    assert_eq!(c.calls(), 1);
    ordered(c, Seen::Stop, Seen::StopDrop);
    ordered(c, Seen::StopDrop, Seen::SessionDrop);
    ordered(c, Seen::SessionDrop, Seen::Finish(terminal(c)));
    let events = c.events();
    let stop = events.iter().position(|e| *e == Seen::Stop).unwrap();
    assert!(!events[stop + 1..].contains(&Seen::Stream));
}
fn direct(c: Arc<Control>) -> (Box<dyn ProviderSession>, Arc<Lab>) {
    let lab = Arc::new(Lab {
        controls: vec![c.clone()],
    });
    let session: Box<dyn ProviderSession> = if c.default_stop {
        Box::new(DefaultSession(Session::new(c)))
    } else {
        Box::new(Session::new(c))
    };
    (session, lab)
}
async fn helper(
    c: Arc<Control>,
    deadline: Option<tokio::time::Instant>,
    interval: Duration,
) -> ProviderStopObservation {
    let (mut session, lab) = direct(c.clone());
    let mut renew = tokio::time::interval(interval);
    let result = request_provider_stop(
        session.as_mut(),
        deadline,
        &mut renew,
        lab.as_ref(),
        &lease(&c.id),
        false,
    )
    .await;
    drop(session);
    result
}

#[tokio::test]
async fn user_cancel_confirmed_precedes_drop_and_cancelled_with_original_trace_time() {
    let c = case(
        Control::new(
            "confirmed",
            Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
        ),
        Trigger::User,
    )
    .await;
    assert_eq!(terminal(&c), RunTerminal::Cancelled);
    stopped_before_finish(&c);
    assert_eq!(c.events().iter().filter(|e| **e == Seen::Ack).count(), 1);
    assert_eq!(
        c.events()
            .iter()
            .filter(|e| matches!(e, Seen::Audit(_)))
            .cloned()
            .collect::<Vec<_>>(),
        vec![Seen::Audit(AgentAuditKind::Invoked)]
    );
}
#[tokio::test]
async fn user_cancel_unknown_and_errors_require_stop_unknown_reconciliation() {
    for plan in [
        Plan::Ready(Ok(StopOutcome::Unknown)),
        Plan::Ready(Err(ProviderPortError::Unavailable)),
        Plan::Ready(Err(ProviderPortError::CommitUnknown)),
        Plan::Ready(Err(ProviderPortError::InvalidRequest { field: "fixture" })),
        Plan::Pending,
    ] {
        let c = case(Control::new("unknown", plan), Trigger::User).await;
        assert_eq!(terminal(&c), unknown());
        stopped_before_finish(&c);
    }
}
#[tokio::test]
async fn absolute_deadline_zero_budget_refuses_confirmed_unknown_error_and_pending() {
    for plan in [
        Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
        Plan::Ready(Ok(StopOutcome::Unknown)),
        Plan::Ready(Err(ProviderPortError::Unavailable)),
        Plan::Pending,
    ] {
        let c = case(Control::new("deadline", plan), Trigger::Deadline).await;
        assert_eq!(terminal(&c), unknown());
        stopped_before_finish(&c);
        ordered(
            &c,
            Seen::SessionDrop,
            Seen::Audit(AgentAuditKind::RunDeadlineExceeded),
        );
    }
}
#[tokio::test]
async fn stall_stop_results_precede_audit_and_preserve_failed_or_unknown_terminal() {
    for (plan, expected) in [
        (
            Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
            RunTerminal::Failed(RunFailureCode::ProviderStreamStalled),
        ),
        (
            Plan::Ready(Ok(StopOutcome::Unsupported)),
            RunTerminal::Failed(RunFailureCode::ProviderStreamStalled),
        ),
        (Plan::Ready(Ok(StopOutcome::Unknown)), unknown()),
        (Plan::Ready(Err(ProviderPortError::Unavailable)), unknown()),
        (Plan::Pending, unknown()),
    ] {
        let c = case(Control::new("stall", plan), Trigger::Stall).await;
        assert_eq!(terminal(&c), expected);
        stopped_before_finish(&c);
        ordered(
            &c,
            Seen::SessionDrop,
            Seen::Audit(AgentAuditKind::StreamStalled),
        );
    }
}
#[tokio::test]
async fn lease_loss_stop_results_never_restore_writer_or_change_lease_failure() {
    for plan in [
        Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
        Plan::Ready(Ok(StopOutcome::Unsupported)),
        Plan::Ready(Ok(StopOutcome::Unknown)),
        Plan::Ready(Err(ProviderPortError::Unavailable)),
        Plan::Pending,
    ] {
        let mut control = Control::new("lost", plan);
        control.renewal = Renewal::Lost;
        control.finish_error = Some(RunRuntimeError::StaleLease);
        let c = case(control, Trigger::Lease).await;
        assert_eq!(
            terminal(&c),
            RunTerminal::ReconciliationRequired(RunFailureCode::RuntimeLeaseExpired)
        );
        stopped_before_finish(&c);
        assert_eq!(c.events().iter().filter(|e| **e == Seen::Renew).count(), 1);
        assert!(!c.events().contains(&Seen::Ack));
        assert_eq!(
            c.events()
                .iter()
                .filter(|e| matches!(e, Seen::Audit(_)))
                .cloned()
                .collect::<Vec<_>>(),
            vec![Seen::Audit(AgentAuditKind::Invoked)]
        );
    }
}
#[tokio::test]
async fn default_unsupported_keeps_original_cancel_deadline_stall_and_completion_sequences() {
    for (trigger, expected, audit) in [
        (Trigger::User, RunTerminal::Cancelled, None),
        (
            Trigger::Deadline,
            RunTerminal::Cancelled,
            Some(AgentAuditKind::RunDeadlineExceeded),
        ),
        (
            Trigger::Stall,
            RunTerminal::Failed(RunFailureCode::ProviderStreamStalled),
            Some(AgentAuditKind::StreamStalled),
        ),
        (Trigger::Normal, RunTerminal::Completed, None),
    ] {
        let mut control = Control::new("default", Plan::Pending);
        control.default_stop = true;
        control.stream = Stream::Text;
        let c = case(control, trigger).await;
        assert_eq!(terminal(&c), expected);
        assert_eq!(c.calls(), 0);
        if matches!(trigger, Trigger::Normal) {
            ordered(&c, Seen::Finish(expected), Seen::SessionDrop);
        } else {
            ordered(&c, Seen::SessionDrop, Seen::Finish(expected));
        }
        let mut expected_audits = vec![Seen::Audit(AgentAuditKind::Invoked)];
        if let Some(a) = audit {
            expected_audits.push(Seen::Audit(a));
        }
        assert_eq!(
            c.events()
                .iter()
                .filter(|e| matches!(e, Seen::Audit(_)))
                .cloned()
                .collect::<Vec<_>>(),
            expected_audits
        );
        if matches!(trigger, Trigger::Normal) {
            assert!(c.events().contains(&Seen::Chunk("original".into())));
            assert_eq!(*c.writes.lock().unwrap(), [(1, "chunk"), (2, "finish")]);
        } else {
            assert_eq!(*c.writes.lock().unwrap(), [(1, "finish")]);
        }
    }
}
#[tokio::test]
async fn stop_helper_without_run_deadline_uses_real_thirty_second_cap() {
    assert_eq!(PROVIDER_STOP_TIMEOUT, Duration::from_secs(30));
    let c = Arc::new(Control::new("cap", Plan::Pending));
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(40),
        helper(c.clone(), None, Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert!(!result.lease_lost);
    assert!(start.elapsed() >= Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(40));
    assert_eq!(c.calls(), 1);
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
}
#[tokio::test]
async fn stop_helper_short_run_budget_bounds_pending_and_reclaims_borrowed_future() {
    let c = Arc::new(Control::new("short", Plan::Pending));
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        helper(
            c.clone(),
            Some(start + Duration::from_millis(40)),
            Duration::from_secs(1),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert!(start.elapsed() >= Duration::from_millis(40));
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
}
#[tokio::test]
async fn stop_helper_zero_budget_polls_once_and_only_preserves_default_unsupported() {
    let mut default = Control::new("zero-default", Plan::Pending);
    default.default_stop = true;
    let default = Arc::new(default);
    let result = helper(
        default.clone(),
        Some(tokio::time::Instant::now()),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.outcome, StopOutcome::Unsupported);
    assert_eq!(default.calls(), 0);
    assert!(!default.events().contains(&Seen::Renew));
    for plan in [
        Plan::Pending,
        Plan::Ready(Err(ProviderPortError::Unavailable)),
        Plan::Ready(Ok(StopOutcome::Unknown)),
        Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
    ] {
        let c = Arc::new(Control::new("zero", plan));
        let result = helper(
            c.clone(),
            Some(tokio::time::Instant::now()),
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(result.outcome, StopOutcome::Unknown);
        assert_eq!(c.stop_polls.load(AtomicOrdering::SeqCst), 1);
        ordered(&c, Seen::StopDrop, Seen::SessionDrop);
    }
}
#[tokio::test]
async fn stop_helper_rejects_late_ready_confirmation_without_budget_reset() {
    let c = Arc::new(Control::new("late", Plan::Late(Duration::from_millis(15))));
    let result = helper(
        c.clone(),
        Some(tokio::time::Instant::now() + Duration::from_millis(2)),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.outcome, StopOutcome::Unknown);
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    let ready_at = deadline + Duration::from_millis(20);
    let c = Arc::new(Control::new("late-repoll", Plan::PendingThenLate(ready_at)));
    let result = helper(c.clone(), Some(deadline), Duration::from_secs(1)).await;
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert!(c.late_pending.load(AtomicOrdering::SeqCst));
    assert_eq!(c.stop_polls.load(AtomicOrdering::SeqCst), 2);
    let (started, returned) = c.late_ready.lock().unwrap().expect("second poll returned");
    assert!(started < deadline);
    assert!(returned >= ready_at);
    assert!(returned > deadline);
    assert_eq!(c.calls(), 1);
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
}
#[tokio::test]
async fn stop_wait_renews_lease_without_duplicate_stop_or_deadline_restart() {
    let c = Arc::new(Control::new("renew", Plan::Pending));
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        helper(
            c.clone(),
            Some(start + Duration::from_millis(45)),
            Duration::from_millis(5),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert!(!result.lease_lost);
    assert_eq!(c.calls(), 1);
    assert!(c.events().iter().filter(|e| **e == Seen::Renew).count() >= 2);
}
#[tokio::test]
async fn stop_wait_actual_renew_error_preserves_original_lease_lost_priority() {
    let mut c = Control::new(
        "renew-lost",
        Plan::Release(StopOutcome::Confirmed { at: AT }),
    );
    c.renewal = Renewal::LostWhileStopping;
    let c = Arc::new(c);
    let (mut session, lab) = direct(c.clone());
    let mut renew = tokio::time::interval(Duration::from_millis(5));
    let release = async {
        c.renewal_failed.notified().await;
        c.release.notify_one();
    };
    let run_lease = lease(&c.id);
    let joined = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            request_provider_stop(
                session.as_mut(),
                Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                &mut renew,
                lab.as_ref(),
                &run_lease,
                false
            ),
            release
        )
    })
    .await;
    drop(session);
    let (result, ()) = joined.unwrap();
    assert!(result.lease_lost);
    assert_eq!(result.outcome, StopOutcome::Confirmed { at: AT });
    assert_eq!(c.events().iter().filter(|e| **e == Seen::Renew).count(), 1);
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
    // Also drive the user-cancel branch after a renewal fails during this stop.
    let mut c = Control::new(
        "renew-lost-runtime",
        Plan::Release(StopOutcome::Confirmed { at: AT }),
    );
    c.renewal = Renewal::LostWhileStopping;
    c.finish_error = Some(RunRuntimeError::StaleLease);
    let c = Arc::new(c);
    let lab = Arc::new(Lab {
        controls: vec![c.clone()],
    });
    let agent = BuiltInAgentRuntime::start(
        lab.clone(),
        lab.clone(),
        lab.clone(),
        Arc::new(NoAgentToolInvoker),
        lab,
        config(Some(Duration::from_secs(2))),
    )
    .unwrap();
    let activation = activate(&agent, &c.id).await;
    let entered = tokio::time::timeout(Duration::from_secs(1), c.entered.notified()).await;
    if entered.is_ok() {
        agent.consumer().revoke(&lease(&c.id)).await;
    }
    let lost = tokio::time::timeout(Duration::from_secs(1), c.renewal_failed.notified()).await;
    c.release.notify_one();
    let finished = tokio::time::timeout(Duration::from_secs(3), c.finished.notified()).await;
    agent.stop().await;
    assert!(activation.is_ok() && entered.is_ok() && lost.is_ok() && finished.is_ok());
    assert_eq!(
        terminal(&c),
        RunTerminal::ReconciliationRequired(RunFailureCode::RuntimeLeaseExpired)
    );
    assert!(!c.events().contains(&Seen::Ack));
    assert_eq!(
        c.events()
            .iter()
            .filter(|e| matches!(e, Seen::Audit(_)))
            .cloned()
            .collect::<Vec<_>>(),
        vec![Seen::Audit(AgentAuditKind::Invoked)]
    );
    stopped_before_finish(&c);
}
#[tokio::test]
async fn stop_wait_pending_renewal_shares_deadline_without_faking_success_or_loss() {
    let mut c = Control::new("renew-pending", Plan::Pending);
    c.renewal = Renewal::PendingWhileStopping;
    let c = Arc::new(c);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        helper(
            c.clone(),
            Some(tokio::time::Instant::now() + Duration::from_millis(35)),
            Duration::from_millis(5),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert!(!result.lease_lost);
    assert_eq!(c.calls(), 1);
    assert_eq!(c.events().iter().filter(|e| **e == Seen::Renew).count(), 1);
    ordered(&c, Seen::RenewDrop, Seen::StopDrop);
}
#[tokio::test]
async fn stop_unknown_keeps_its_code_when_deadline_or_stall_audit_fails() {
    for (trigger, kind) in [
        (Trigger::Deadline, AgentAuditKind::RunDeadlineExceeded),
        (Trigger::Stall, AgentAuditKind::StreamStalled),
    ] {
        for plan in [
            Plan::Ready(Ok(StopOutcome::Unknown)),
            Plan::Ready(Err(ProviderPortError::Unavailable)),
            Plan::Pending,
        ] {
            let mut c = Control::new("audit-unknown", plan);
            c.audit_error = Some(kind);
            let c = case(c, trigger).await;
            assert_eq!(terminal(&c), unknown());
            stopped_before_finish(&c);
        }
    }
}
#[tokio::test]
async fn confirmed_and_unsupported_keep_existing_audit_failure_reason() {
    for (trigger, kind, default) in [
        (Trigger::Stall, AgentAuditKind::StreamStalled, false),
        (Trigger::Stall, AgentAuditKind::StreamStalled, true),
        (Trigger::Deadline, AgentAuditKind::RunDeadlineExceeded, true),
    ] {
        let mut c = Control::new(
            "audit-old",
            Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
        );
        c.audit_error = Some(kind);
        c.default_stop = default;
        let c = case(c, trigger).await;
        assert_eq!(
            terminal(&c),
            RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
        );
        ordered(&c, Seen::SessionDrop, Seen::Audit(kind));
    }
}
#[tokio::test]
async fn pre_session_context_start_and_retry_prefetch_cancel_claim_no_remote_stop() {
    for stage in 0..3 {
        let mut c = Control::new(
            "pre-session",
            Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
        );
        c.context_pending = stage == 0;
        c.start_pending = stage == 1;
        let c = Arc::new(c);
        let lab = Arc::new(Lab {
            controls: vec![c.clone()],
        });
        let provider: Arc<dyn ProviderAdapter> = if stage == 2 {
            Arc::new(
                RetryingProvider::new(
                    lab.clone(),
                    RetryingProviderConfig {
                        max_retries: 0,
                        base_delay: Duration::from_millis(1),
                        max_delay: Duration::from_millis(1),
                        jitter: false,
                    },
                )
                .unwrap(),
            )
        } else {
            lab.clone()
        };
        let agent = BuiltInAgentRuntime::start(
            lab.clone(),
            lab.clone(),
            provider,
            Arc::new(NoAgentToolInvoker),
            lab,
            config(Some(Duration::from_secs(2))),
        )
        .unwrap();
        let activation = activate(&agent, &c.id).await;
        let reached = tokio::time::timeout(Duration::from_secs(1), async {
            match stage {
                0 => c.context_entered.notified().await,
                1 => c.start_entered.notified().await,
                _ => c.entered.notified().await,
            }
        })
        .await;
        if reached.is_ok() {
            agent.consumer().revoke(&lease(&c.id)).await;
        }
        let finished = tokio::time::timeout(Duration::from_secs(3), c.finished.notified()).await;
        agent.stop().await;
        assert!(activation.is_ok() && reached.is_ok() && finished.is_ok());
        assert_eq!(terminal(&c), RunTerminal::Cancelled);
        assert_eq!(c.calls(), 0);
        assert_eq!(
            c.events()
                .iter()
                .filter(|e| **e == Seen::SessionDrop)
                .count(),
            usize::from(stage == 2)
        );
    }
}
#[tokio::test]
async fn shutdown_retains_original_five_second_abort_join_boundary() {
    assert_eq!(AGENT_SHUTDOWN_DEADLINE, Duration::from_secs(5));
    let c = Arc::new(Control::new("shutdown", Plan::Pending));
    let lab = Arc::new(Lab {
        controls: vec![c.clone()],
    });
    let agent = BuiltInAgentRuntime::start(
        lab.clone(),
        lab.clone(),
        lab.clone(),
        Arc::new(NoAgentToolInvoker),
        lab,
        config(None),
    )
    .unwrap();
    let activation = activate(&agent, &c.id).await;
    let entered = tokio::time::timeout(Duration::from_secs(1), c.entered.notified()).await;
    let start = tokio::time::Instant::now();
    agent.stop().await;
    assert!(activation.is_ok() && entered.is_ok());
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(c.calls(), 1);
    ordered(&c, Seen::StopDrop, Seen::SessionDrop);
    assert!(
        !c.events()
            .iter()
            .any(|e| matches!(e, Seen::Finish(_) | Seen::Ack))
    );
}
#[tokio::test]
async fn normal_completion_and_completed_tool_sampling_never_request_stop() {
    for stream in [Stream::Text, Stream::Tools] {
        let mut c = Control::new("normal", Plan::Pending);
        c.stream = stream;
        let c = case(c, Trigger::Normal).await;
        assert_eq!(c.calls(), 0);
        if matches!(stream, Stream::Text) {
            ordered(&c, Seen::Finish(terminal(&c)), Seen::SessionDrop);
        } else {
            ordered(&c, Seen::SessionDrop, Seen::Finish(terminal(&c)));
        }
        assert_eq!(
            terminal(&c),
            if matches!(stream, Stream::Text) {
                RunTerminal::Completed
            } else {
                RunTerminal::Failed(RunFailureCode::ToolLoopUnavailable)
            }
        );
    }
}

#[derive(Clone)]
struct Capture(Arc<StdMutex<Vec<(String, String)>>>);
struct Fields(Arc<StdMutex<Vec<(String, String)>>>);
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.0
            .lock()
            .unwrap()
            .push((field.name().into(), format!("{value:?}")));
    }
}
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(self.0.clone()));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut Fields(self.0.clone()));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
#[tokio::test]
async fn confirmation_timestamp_is_trace_only_and_never_audit_or_terminal_payload() {
    let fields = Arc::new(StdMutex::new(vec![]));
    let _subscriber = tracing::subscriber::set_default(Capture(fields.clone()));
    let c = case(
        Control::new("trace", Plan::Ready(Ok(StopOutcome::Confirmed { at: AT }))),
        Trigger::User,
    )
    .await;
    let expected = format!("{AT:?}");
    let confirmed = fields
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, _)| name == "stop_confirmed_at")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(confirmed, vec![("stop_confirmed_at".into(), expected)]);
    assert_eq!(terminal(&c), RunTerminal::Cancelled);
    assert!(!format!("{:?}", c.events()).contains("SystemTime"));
    let before = confirmed.len();
    let late = Arc::new(Control::new(
        "trace-late",
        Plan::Ready(Ok(StopOutcome::Confirmed { at: AT })),
    ));
    let result = helper(
        late,
        Some(tokio::time::Instant::now()),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(result.outcome, StopOutcome::Unknown);
    assert_eq!(
        fields
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == "stop_confirmed_at")
            .count(),
        before
    );
}
fn sampling(id: &str) -> AgentState {
    let s = AgentState::queued(RunId::new(id));
    let s = reduce(&s, AgentEvent::DispatchActivated).unwrap().0;
    reduce(&s, AgentEvent::ContextPrepared).unwrap().0
}
#[tokio::test]
async fn fenced_or_unknown_finish_failure_never_fakes_durable_stop_terminal() {
    for error in [
        RunRuntimeError::StaleLease,
        RunRuntimeError::CommitUnknown,
        RunRuntimeError::Unavailable,
    ] {
        let mut c = Control::new("fenced", Plan::Ready(Ok(StopOutcome::Unknown)));
        c.finish_error = Some(error);
        let c = Arc::new(c);
        let lab = Arc::new(Lab {
            controls: vec![c.clone()],
        });
        let mut state = sampling(&c.id);
        let mut journal = DurableTextRun::new(lab.clone(), lease(&c.id));
        commit_provider_stop_unknown(&mut state, &mut journal, lab.as_ref(), &lease(&c.id), None)
            .await;
        assert_eq!(state.phase(), AgentPhase::CommittingResults);
        assert_eq!(terminal(&c), unknown());
        assert!(!c.events().contains(&Seen::Ack));
        assert_eq!(
            c.events()
                .iter()
                .filter(|e| matches!(e, Seen::Finish(_)))
                .count(),
            1
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_round_cancel_ready_and_deadline_races_keep_runs_isolated_and_joined() {
    for round in 0..10 {
        let a = Arc::new(Control::new(
            &format!("{round}-unknown"),
            Plan::Release(StopOutcome::Unknown),
        ));
        let b = Arc::new(Control::new(
            &format!("{round}-confirmed"),
            Plan::Release(StopOutcome::Confirmed { at: AT }),
        ));
        let mut default = Control::new(&format!("{round}-deadline"), Plan::Pending);
        default.default_stop = true;
        let c = Arc::new(default);
        let lab = Arc::new(Lab {
            controls: vec![a.clone(), b.clone(), c.clone()],
        });
        let agent = BuiltInAgentRuntime::start(
            lab.clone(),
            lab.clone(),
            lab.clone(),
            Arc::new(NoAgentToolInvoker),
            lab,
            config(Some(Duration::from_secs(2))),
        )
        .unwrap();
        let activations = tokio::join!(
            activate(&agent, &a.id),
            activate(&agent, &b.id),
            activate(&agent, &c.id)
        );
        let entered = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                a.entered.notified(),
                b.entered.notified(),
                c.entered.notified()
            );
        })
        .await;
        let mut released = false;
        if entered.is_ok() {
            let consumer = agent.consumer();
            let lease_a = lease(&a.id);
            let lease_b = lease(&b.id);
            tokio::join!(consumer.revoke(&lease_a), consumer.revoke(&lease_b));
            let ready = async {
                tokio::join!(a.stopping.notified(), b.stopping.notified());
                a.release.notify_one();
                b.release.notify_one();
            };
            released = tokio::time::timeout(Duration::from_secs(1), ready)
                .await
                .is_ok();
        }
        let finished = tokio::time::timeout(Duration::from_secs(4), async {
            tokio::join!(
                a.finished.notified(),
                b.finished.notified(),
                c.finished.notified()
            );
        })
        .await;
        agent.stop().await;
        assert!(
            activations.0.is_ok()
                && activations.1.is_ok()
                && activations.2.is_ok()
                && entered.is_ok()
                && released
                && finished.is_ok()
        );
        assert_eq!(terminal(&a), unknown());
        assert_eq!(terminal(&b), RunTerminal::Cancelled);
        assert_eq!(terminal(&c), RunTerminal::Cancelled);
        assert_eq!((a.calls(), b.calls(), c.calls()), (1, 1, 0));
        stopped_before_finish(&a);
        stopped_before_finish(&b);
        assert!(
            c.events()
                .contains(&Seen::Audit(AgentAuditKind::RunDeadlineExceeded))
        );
    }
}
