use super::*;

fn sampling() -> AgentState {
    let state = AgentState::queued(RunId::new("stop-run"));
    let (state, _) = reduce(&state, AgentEvent::DispatchActivated).unwrap();
    reduce(&state, AgentEvent::ContextPrepared).unwrap().0
}

#[test]
fn stop_unknown_enters_reconciliation_through_single_terminal_commit() {
    let state = sampling();
    let (state, effects) = reduce(
        &state,
        AgentEvent::ProviderFailed(AgentFailure::ProviderStopUnknown),
    )
    .unwrap();
    assert_eq!(state.phase(), AgentPhase::CommittingResults);
    assert_eq!(
        effects,
        vec![AgentEffect::CommitTerminal(
            AgentTerminal::ReconciliationRequired(AgentFailure::ProviderStopUnknown)
        )]
    );
    assert!(reduce(&state, AgentEvent::ProviderCompleted).is_err());
    let (state, effects) = reduce(&state, AgentEvent::TerminalCommitted).unwrap();
    assert_eq!(state.phase(), AgentPhase::ReconciliationRequired);
    assert!(effects.is_empty());
    assert!(reduce(&state, AgentEvent::CancelRequested).is_err());
}

#[test]
fn stop_unknown_does_not_reclassify_existing_provider_failures() {
    use AgentFailure::*;
    let cases = [
        (ProviderAuthentication, false),
        (ProviderRateLimited, false),
        (ProviderUnavailable, false),
        (ProviderCommitUnknown, true),
        (ProviderStopUnknown, true),
        (ProviderInvalidResponse, false),
        (ProviderStreamStalled, false),
        (ProviderGenerationFailed, false),
        (ProviderTokenBudgetExceeded, false),
        (RunTokenBudgetExceeded, false),
        (RunCostBudgetUnpriced, false),
        (RunCostBudgetCurrencyMismatch, false),
        (RunCostBudgetExceeded, false),
        (ToolStepLimit, false),
        (ToolLoopUnavailable, false),
        (ToolDenied, false),
        (RuntimeLeaseLost, true),
        (JournalCommitUnknown, true),
    ];
    for (reason, unknown) in cases {
        let (_, effects) = reduce(&sampling(), AgentEvent::ProviderFailed(reason)).unwrap();
        let expected = if unknown {
            AgentTerminal::ReconciliationRequired(reason)
        } else {
            AgentTerminal::Failed(reason)
        };
        assert_eq!(effects, vec![AgentEffect::CommitTerminal(expected)]);
    }
}

#[test]
fn lease_and_journal_facts_preserve_their_own_reconciliation_reason() {
    for cancelling in [false, true] {
        for (event, reason) in [
            (AgentEvent::LeaseLost, AgentFailure::RuntimeLeaseLost),
            (
                AgentEvent::JournalCommitUnknown,
                AgentFailure::JournalCommitUnknown,
            ),
        ] {
            let mut state = sampling();
            if cancelling {
                state = reduce(&state, AgentEvent::CancelRequested).unwrap().0;
            }
            let (state, effects) = reduce(&state, event).unwrap();
            assert_eq!(
                effects,
                vec![AgentEffect::CommitTerminal(
                    AgentTerminal::ReconciliationRequired(reason)
                )]
            );
            assert!(
                reduce(
                    &state,
                    AgentEvent::ProviderFailed(AgentFailure::ProviderStopUnknown)
                )
                .is_err()
            );
            let (state, _) = reduce(&state, AgentEvent::TerminalCommitted).unwrap();
            assert_eq!(state.phase(), AgentPhase::ReconciliationRequired);
            assert!(reduce(&state, AgentEvent::ChildrenStopped).is_err());
        }
    }
}
