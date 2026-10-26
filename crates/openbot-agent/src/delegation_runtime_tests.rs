use super::*;
use openbot_application::{
    ClaimedRunDispatch, NoAgentAudit, ProviderMessage, ProviderMessageRole, ProviderRequest,
    ProviderUsage, RunSemanticChannel, RunTokenUsage, RunWriteReceipt,
};
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId, ToolCallId};
use openbot_domain::thread::FencingToken;
use std::collections::VecDeque;
use std::sync::{Mutex as StdMutex, atomic::AtomicUsize};
struct Journal {
    terminal: StdMutex<Option<RunTerminal>>,
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
        Ok(Box::new(Session(
            vec![
                ProviderEvent::ToolCallCompleted {
                    index: 0,
                    call_id: "provider-call".into(),
                    name: "remember".into(),
                    arguments: serde_json::json!({}),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                }),
                ProviderEvent::Completed,
            ]
            .into(),
        )))
    }
}
struct Tools {
    mode: u8,
    effects: AtomicUsize,
}
#[async_trait]
impl AgentToolInvoker for Tools {
    async fn invoke(
        &self,
        _: &RunExecutionLease,
        _: &str,
        _: &str,
        _: serde_json::Value,
    ) -> Result<AgentToolReply, AgentToolInvokeError> {
        if self.mode == 1 {
            return Err(AgentToolInvokeError::DelegationNotCurrent);
        }
        self.effects.fetch_add(1, Ordering::SeqCst);
        if self.mode == 2 {
            return Err(AgentToolInvokeError::ReconciliationRequired);
        }
        AgentToolReply::new(ToolCallId::new("effect-call"), "stored".into(), None)
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
async fn run(mode: u8, expired: bool) -> (RunTerminal, usize, usize, usize) {
    let journal = Arc::new(Journal {
        terminal: StdMutex::new(None),
        done: tokio::sync::Notify::new(),
    });
    let context = Arc::new(Context {
        loads: AtomicUsize::new(0),
    });
    let provider = Arc::new(Provider {
        starts: AtomicUsize::new(0),
    });
    let tools = Arc::new(Tools {
        mode,
        effects: AtomicUsize::new(0),
    });
    let agent = BuiltInAgentRuntime::start(
        journal.clone(),
        context.clone(),
        provider.clone(),
        tools.clone(),
        Arc::new(NoAgentAudit),
        BuiltInAgentConfig {
            queue_capacity: 2,
            max_concurrency: 1,
            max_tool_concurrency: 1,
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
    (
        terminal,
        provider.starts.load(Ordering::SeqCst),
        tools.effects.load(Ordering::SeqCst),
        context.loads.load(Ordering::SeqCst),
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
    let (terminal, starts, effects, _) = run(1, false).await;
    assert_eq!(
        terminal,
        RunTerminal::Failed(RunFailureCode::DelegationNotCurrent)
    );
    assert_eq!(starts, 1);
    assert_eq!(effects, 0);
}
#[tokio::test]
async fn started_effect_unknown_is_not_overwritten_by_revocation() {
    for _ in 0..10 {
        let (terminal, starts, effects, _) = run(2, false).await;
        assert_eq!(
            terminal,
            RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)
        );
        assert_eq!(starts, 1);
        assert_eq!(effects, 1);
    }
}
#[tokio::test]
async fn persisted_delegated_deadline_survives_dispatch_delay() {
    let (terminal, starts, effects, _) = run(0, true).await;
    assert_eq!(
        terminal,
        RunTerminal::Failed(RunFailureCode::RunDeadlineExceeded)
    );
    assert_eq!(starts, 0);
    assert_eq!(effects, 0);
    assert!(lease().absolute_deadline().is_none());
}
