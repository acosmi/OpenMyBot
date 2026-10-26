use super::*;
use openbot_application::{
    AgentAuditError, ClaimedRunDispatch, ProviderMessage, ProviderMessageRole, ProviderRequest,
    ProviderUsage, RunSemanticChannel, RunTokenUsage, RunWriteReceipt,
};
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId, ToolCallId};
use openbot_domain::thread::FencingToken;
use std::collections::VecDeque;
use std::sync::{Mutex as StdMutex, atomic::AtomicUsize};
#[derive(Default)]
struct RecordingAudit(StdMutex<Vec<AgentAuditKind>>);
#[async_trait]
impl AgentAudit for RecordingAudit {
    async fn record(
        &self,
        _: &RunExecutionLease,
        kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError> {
        self.0.lock().unwrap().push(kind);
        Ok(())
    }
}
struct Journal {
    terminal: StdMutex<Option<RunTerminal>>,
    terminal_writes: AtomicUsize,
    exchanges: AtomicUsize,
    done: tokio::sync::Notify,
}
fn receipt(n: u64) -> RunWriteReceipt {
    RunWriteReceipt {
        run_event_sequence: n,
        thread_event_sequence: n,
        message_sequence: None,
        replayed: false,
    }
}
#[async_trait]
impl RunRuntime for Journal {
    async fn claim_dispatch(&self) -> Result<Option<ClaimedRunDispatch>, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn acknowledge_dispatch(
        &self,
        _: &ClaimedRunDispatch,
    ) -> Result<RunExecutionLease, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn retry_dispatch(&self, _: &ClaimedRunDispatch) -> Result<(), RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn reject_dispatch(
        &self,
        _: &ClaimedRunDispatch,
        _: RunFailureCode,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Err(RunRuntimeError::Unavailable)
    }
    async fn renew_lease(&self, _: &RunExecutionLease) -> Result<(), RunRuntimeError> {
        Ok(())
    }
    async fn append_semantic_chunk(
        &self,
        _: &RunExecutionLease,
        n: u64,
        _: RunSemanticChannel,
        _: &str,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        Ok(receipt(n))
    }
    async fn append_tool_exchange(
        &self,
        _: &RunExecutionLease,
        n: u64,
        _: &RunToolExchange,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(receipt(n))
    }
    async fn record_provider_usage(
        &self,
        _: &RunExecutionLease,
        _: u32,
        u: ProviderUsage,
        _: Option<u64>,
        _: Option<&ProviderRateCard>,
        _: Option<&RunCostCap>,
    ) -> Result<RunTokenUsageReceipt, RunRuntimeError> {
        Ok(RunTokenUsageReceipt::Recorded(RunTokenUsage {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            total_tokens: u.total_tokens,
        }))
    }
    async fn finish_run(
        &self,
        _: &RunExecutionLease,
        n: u64,
        t: RunTerminal,
    ) -> Result<RunWriteReceipt, RunRuntimeError> {
        self.terminal_writes.fetch_add(1, Ordering::SeqCst);
        let mut slot = self.terminal.lock().unwrap();
        assert!(slot.is_none());
        *slot = Some(t);
        drop(slot);
        self.done.notify_one();
        Ok(receipt(n))
    }
    async fn recover_one_stale_run(&self) -> Result<Option<RunWriteReceipt>, RunRuntimeError> {
        Ok(None)
    }
}
struct Context {
    loads: AtomicUsize,
}
#[async_trait]
impl AgentContextSource for Context {
    async fn load(&self, _: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError> {
        if self.loads.fetch_add(1, Ordering::SeqCst) > 0 {
            return Err(AgentContextError::DelegationNotCurrent);
        }
        Ok(ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "template".into(),
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
struct Provider {
    starts: AtomicUsize,
    tool_names: Vec<String>,
}
struct Session(VecDeque<ProviderEvent>);
#[async_trait]
impl ProviderSession for Session {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.0.pop_front())
    }
}
#[async_trait]
impl ProviderAdapter for Provider {
    async fn start(
        &self,
        _: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        let mut events = self
            .tool_names
            .iter()
            .enumerate()
            .map(|(index, name)| ProviderEvent::ToolCallCompleted {
                index: u32::try_from(index).unwrap(),
                call_id: format!("provider-call-{index}"),
                name: name.clone(),
                arguments: serde_json::json!({"index": index}),
            })
            .collect::<Vec<_>>();
        events.push(ProviderEvent::Usage(ProviderUsage {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
        }));
        events.push(ProviderEvent::Completed);
        Ok(Box::new(Session(events.into())))
    }
}
struct Tools {
    modes: Vec<u8>,
    parallel: bool,
    pair_barrier: Option<tokio::sync::Barrier>,
    invocations: AtomicUsize,
    human_invocations: AtomicUsize,
    effects: AtomicUsize,
}
#[async_trait]
impl AgentToolInvoker for Tools {
    fn scheduling(&self, _: &str) -> AgentToolScheduling {
        if self.parallel {
            AgentToolScheduling::parallel(Vec::new())
        } else {
            AgentToolScheduling::serial()
        }
    }

    async fn invoke(
        &self,
        _: &RunExecutionLease,
        _: &str,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        let index = arguments["index"].as_u64().unwrap() as usize;
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if is_component_human_decision_name(name) {
            self.human_invocations.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(barrier) = &self.pair_barrier {
            // Neither child can complete unless the entire wave actually starts concurrently.
            barrier.wait().await;
        }
        if self.modes[index] == 1 {
            return Err(AgentToolInvokeError::DelegationNotCurrent);
        }
        self.effects.fetch_add(1, Ordering::SeqCst);
        if self.modes[index] == 2 {
            return Err(AgentToolInvokeError::ReconciliationRequired);
        }
        AgentToolReply::new(
            ToolCallId::new(format!("effect-call-{index}")),
            "stored".into(),
            None,
        )
    }
}

fn lease() -> RunExecutionLease {
    RunExecutionLease::new(
        RunId::new("delegation-unit-run"),
        ThreadId::new("550e8400-e29b-81d4-a716-446655440000"),
        BotId::new("bot"),
        ActorId::new("actor"),
        FencingToken::new(1).unwrap(),
        1,
    )
    .unwrap()
}
struct Observation {
    terminal: RunTerminal,
    starts: usize,
    effects: usize,
    loads: usize,
    invocations: usize,
    human_invocations: usize,
    terminal_writes: usize,
    exchanges: usize,
    audits: Vec<AgentAuditKind>,
}
async fn run_case(calls: &[(&str, u8)], parallel: bool, expired: bool) -> Observation {
    let journal = Arc::new(Journal {
        terminal: StdMutex::new(None),
        terminal_writes: AtomicUsize::new(0),
        exchanges: AtomicUsize::new(0),
        done: tokio::sync::Notify::new(),
    });
    let context = Arc::new(Context {
        loads: AtomicUsize::new(0),
    });
    let provider = Arc::new(Provider {
        starts: AtomicUsize::new(0),
        tool_names: calls.iter().map(|(name, _)| (*name).to_owned()).collect(),
    });
    let tools = Arc::new(Tools {
        modes: calls.iter().map(|(_, mode)| *mode).collect(),
        parallel,
        pair_barrier: (parallel && calls.len() > 1).then(|| tokio::sync::Barrier::new(calls.len())),
        invocations: AtomicUsize::new(0),
        human_invocations: AtomicUsize::new(0),
        effects: AtomicUsize::new(0),
    });
    let audit = Arc::new(RecordingAudit::default());
    let agent = BuiltInAgentRuntime::start(
        journal.clone(),
        context.clone(),
        provider.clone(),
        tools.clone(),
        audit.clone(),
        BuiltInAgentConfig {
            queue_capacity: 2,
            max_concurrency: 1,
            max_tool_concurrency: calls.len().max(1),
            lease_renew_interval: Duration::from_millis(20),
            run_deadline: Some(Duration::from_secs(5)),
        },
    )
    .unwrap();
    let lease = if expired {
        lease()
            .with_delegated_run_binding(None, std::time::SystemTime::now() - Duration::from_secs(1))
    } else {
        lease()
    };
    let consumer = agent.consumer();
    assert_eq!(
        consumer.dispatch(lease.clone()).await,
        RunDispatchDecision::Accepted
    );
    consumer.activate(&lease).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), journal.done.notified())
        .await
        .unwrap();
    agent.stop().await;
    let terminal = journal.terminal.lock().unwrap().unwrap();
    let audits = audit.0.lock().unwrap().clone();
    Observation {
        terminal,
        starts: provider.starts.load(Ordering::SeqCst),
        effects: tools.effects.load(Ordering::SeqCst),
        loads: context.loads.load(Ordering::SeqCst),
        invocations: tools.invocations.load(Ordering::SeqCst),
        human_invocations: tools.human_invocations.load(Ordering::SeqCst),
        terminal_writes: journal.terminal_writes.load(Ordering::SeqCst),
        exchanges: journal.exchanges.load(Ordering::SeqCst),
        audits,
    }
}
async fn run(mode: u8, expired: bool) -> (RunTerminal, usize, usize, usize) {
    let observed = run_case(&[("remember", mode)], false, expired).await;
    (
        observed.terminal,
        observed.starts,
        observed.effects,
        observed.loads,
    )
}
#[tokio::test]
async fn delegation_refusal_before_resampling_stops_provider() {
    let (terminal, starts, effects, loads) = run(0, false).await;
    assert_eq!(
        terminal,
        RunTerminal::Failed(RunFailureCode::DelegationNotCurrent)
    );
    assert_eq!(starts, 1);
    assert_eq!(effects, 1);
    assert_eq!(loads, 2);
}
#[tokio::test]
async fn delegation_refusal_before_effect_is_failed() {
    for (calls, parallel) in [
        (vec![("remember", 1)], false),
        (vec![("showCard", 1), ("showQuote", 1)], true),
        // The actual serial invocation takes HumanRequired -> HumanReleased before the refusal.
        (vec![("askApproval", 1)], false),
    ] {
        let observed = run_case(&calls, parallel, false).await;
        assert_eq!(
            observed.terminal,
            RunTerminal::Failed(RunFailureCode::DelegationNotCurrent)
        );
        assert_eq!(observed.terminal_writes, 1);
        assert_eq!(observed.starts, 1);
        assert_eq!(observed.loads, 1, "refusal must stop resampling");
        assert_eq!(observed.effects, 0);
        assert_eq!(observed.invocations, calls.len());
        assert_eq!(observed.exchanges, 0);
        assert_eq!(
            observed.human_invocations,
            usize::from(calls[0].0 == "askApproval")
        );
    }

    let positive = run_case(&[("showCard", 0), ("showQuote", 0)], true, false).await;
    assert_eq!(positive.effects, 2);
    assert_eq!(positive.invocations, 2);
    assert_eq!(positive.exchanges, 2);
    assert_eq!(positive.loads, 2, "a committed wave can resample");
    assert_eq!(positive.starts, 1);
    assert_eq!(positive.terminal_writes, 1);
    assert_eq!(
        positive.terminal,
        RunTerminal::Failed(RunFailureCode::DelegationNotCurrent)
    );

    // Document the exact accepted phase and keep other context failures closed in that phase.
    let state = AgentState::queued(RunId::new("human-phase-check"));
    let (state, _) = reduce(&state, AgentEvent::DispatchActivated).unwrap();
    let (state, _) = reduce(&state, AgentEvent::ContextPrepared).unwrap();
    let (state, _) = reduce(
        &state,
        AgentEvent::ProviderToolCalls(vec![AgentToolCall {
            call_id: "human-call".into(),
            name: "askApproval".into(),
            arguments: serde_json::json!({}),
        }]),
    )
    .unwrap();
    let (state, _) = reduce(&state, AgentEvent::HumanRequired).unwrap();
    let (state, _) = reduce(&state, AgentEvent::HumanReleased).unwrap();
    assert_eq!(
        state.phase(),
        openbot_domain::agent::AgentPhase::ExecutingTools
    );
    assert!(
        reduce(
            &state,
            AgentEvent::ContextFailed(AgentFailure::ToolLoopUnavailable)
        )
        .is_err()
    );
    let (_, effects) = reduce(
        &state,
        AgentEvent::ContextFailed(AgentFailure::DelegationNotCurrent),
    )
    .unwrap();
    assert_eq!(
        effects,
        [AgentEffect::CommitTerminal(AgentTerminal::Failed(
            AgentFailure::DelegationNotCurrent
        ))]
    );
}
#[tokio::test]
async fn started_effect_unknown_is_not_overwritten_by_revocation() {
    for _ in 0..10 {
        let observed = run_case(&[("remember", 2)], false, false).await;
        assert_eq!(
            observed.terminal,
            RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
        );
        assert_eq!(observed.terminal_writes, 1);
        assert_eq!(observed.starts, 1);
        assert_eq!(observed.effects, 1);
        assert_eq!(observed.loads, 1);
        assert_eq!(observed.exchanges, 0);

        for calls in [
            vec![("showCard", 1), ("showQuote", 2)],
            vec![("showCard", 2), ("showQuote", 1)],
            // A successful child before the unknown child must not append a partial reply wave.
            vec![("showCard", 0), ("showQuote", 1), ("showRecord", 2)],
            vec![("showCard", 2), ("showQuote", 1), ("showRecord", 0)],
        ] {
            let observed = run_case(&calls, true, false).await;
            assert_eq!(
                observed.terminal,
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
            );
            assert_eq!(observed.terminal_writes, 1, "no Failed before or after RR");
            assert_eq!(observed.starts, 1);
            assert_eq!(observed.loads, 1, "unknown must stop resampling");
            assert_eq!(observed.invocations, calls.len(), "the full wave joined");
            assert_eq!(
                observed.effects,
                calls.iter().filter(|(_, mode)| *mode != 1).count()
            );
            assert_eq!(observed.exchanges, 0, "RR precedes every reply append");
        }
    }
}
#[tokio::test]
async fn persisted_delegated_deadline_survives_dispatch_delay() {
    let observed = run_case(&[("remember", 0)], false, true).await;
    assert_eq!(observed.terminal, RunTerminal::Cancelled);
    assert_eq!(observed.loads, 0);
    assert_eq!(observed.starts, 0);
    assert_eq!(observed.invocations, 0);
    assert_eq!(observed.human_invocations, 0);
    assert_eq!(observed.effects, 0);
    assert_eq!(observed.exchanges, 0);
    assert_eq!(observed.terminal_writes, 1);
    assert_eq!(
        observed.audits,
        vec![AgentAuditKind::Invoked, AgentAuditKind::RunDeadlineExceeded]
    );
    assert!(lease().absolute_deadline().is_none());
}
