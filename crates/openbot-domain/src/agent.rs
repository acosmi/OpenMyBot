//! Pure built-in Agent reducer（v3 §7.2 / §7.4）。

use openbot_contracts::ids::RunId;
use serde_json::Value;

/// Pure Agent profile access policy shared by roster and runtime adapters.
pub mod profile_policy {
    use openbot_contracts::agent::AgentVisibility;

    /// Verified actor facts needed by the profile policy.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AgentActor<'a> {
        /// Verified actor identity.
        pub id: &'a str,
        /// Whether verified roles include administrator.
        pub admin: bool,
    }

    /// Persistence-independent profile facts needed by the policy.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AgentProfileFacts<'a> {
        /// Creator, or `None` for a package-backed profile.
        pub owner_user_id: Option<&'a str>,
        /// Public/private visibility.
        pub visibility: AgentVisibility,
        /// Package-backed profiles cannot be managed through user lifecycle APIs.
        pub system_owned: bool,
        /// Soft-deleted profiles deny every current action while old channels remain readable.
        pub deleted: bool,
    }

    /// Access one active public profile, or an active private profile as owner/admin.
    #[must_use]
    pub fn can_access_agent(actor: &AgentActor<'_>, profile: &AgentProfileFacts<'_>) -> bool {
        !profile.deleted
            && (profile.visibility == AgentVisibility::Public
                || profile.owner_user_id == Some(actor.id)
                || actor.admin)
    }

    /// Manage only an active non-system profile as its owner or an administrator.
    #[must_use]
    pub fn can_manage_agent(actor: &AgentActor<'_>, profile: &AgentProfileFacts<'_>) -> bool {
        !profile.deleted
            && !profile.system_owned
            && (profile.owner_user_id == Some(actor.id) || actor.admin)
    }

    /// Running uses exactly the same permission function as reading; this is an alias, not a copy.
    pub use can_access_agent as can_run_agent;

    #[cfg(test)]
    mod tests {
        use super::*;

        const CREATOR: AgentActor<'static> = AgentActor {
            id: "user-1",
            admin: false,
        };
        const OTHER: AgentActor<'static> = AgentActor {
            id: "user-2",
            admin: false,
        };
        const ADMIN: AgentActor<'static> = AgentActor {
            id: "admin-1",
            admin: true,
        };

        fn profile(visibility: AgentVisibility) -> AgentProfileFacts<'static> {
            AgentProfileFacts {
                owner_user_id: Some(CREATOR.id),
                visibility,
                system_owned: false,
                deleted: false,
            }
        }

        #[test]
        fn allows_every_actor_to_access_and_run_an_active_public_pr() {
            let profile = profile(AgentVisibility::Public);
            for actor in [CREATOR, OTHER, ADMIN] {
                assert!(can_access_agent(&actor, &profile));
                assert!(can_run_agent(&actor, &profile));
            }
        }

        #[test]
        fn limits_active_private_profile_access_and_runs_to_its_cre() {
            let profile = profile(AgentVisibility::Private);
            assert!(can_access_agent(&CREATOR, &profile));
            assert!(!can_access_agent(&OTHER, &profile));
            assert!(can_access_agent(&ADMIN, &profile));
            assert!(can_run_agent(&CREATOR, &profile));
            assert!(!can_run_agent(&OTHER, &profile));
            assert!(can_run_agent(&ADMIN, &profile));
        }

        #[test]
        fn allows_only_the_creator_and_admins_to_manage_active_user() {
            for visibility in [AgentVisibility::Public, AgentVisibility::Private] {
                let profile = profile(visibility);
                assert!(can_manage_agent(&CREATOR, &profile));
                assert!(!can_manage_agent(&OTHER, &profile));
                assert!(can_manage_agent(&ADMIN, &profile));
            }
        }

        #[test]
        fn allows_all_actors_to_access_and_run_a_system_public_prof() {
            let profile = AgentProfileFacts {
                owner_user_id: None,
                visibility: AgentVisibility::Public,
                system_owned: true,
                deleted: false,
            };
            for actor in [CREATOR, OTHER, ADMIN] {
                assert!(can_access_agent(&actor, &profile));
                assert!(can_run_agent(&actor, &profile));
                assert!(!can_manage_agent(&actor, &profile));
            }
        }

        #[test]
        fn denies_every_permission_for_deleted_profiles() {
            let profile = AgentProfileFacts {
                deleted: true,
                ..profile(AgentVisibility::Public)
            };
            for actor in [CREATOR, OTHER, ADMIN] {
                assert!(!can_access_agent(&actor, &profile));
                assert!(!can_manage_agent(&actor, &profile));
                assert!(!can_run_agent(&actor, &profile));
            }
        }

        #[test]
        fn exports_canrunagent_as_the_canaccessagent_alias() {
            type AccessCheck = for<'a, 'b> fn(&AgentActor<'a>, &AgentProfileFacts<'b>) -> bool;
            assert!(core::ptr::fn_addr_eq(
                can_run_agent as AccessCheck,
                can_access_agent as AccessCheck
            ));
        }
    }
}

/// Reducer phase；terminal phases 不能再产生 effect。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentPhase {
    /// Durable run 等待 runtime activation。
    Queued,
    /// Loading authoritative context/catalog。
    Preparing,
    /// Provider sampling。
    Sampling,
    /// Tool pipeline 正在等待 approval。
    AwaitingApproval,
    /// Human tool result / handover is pending.
    AwaitingHuman,
    /// Tool effect/outcome 正在执行/提交。
    ExecutingTools,
    /// 唯一 terminal transaction 正在提交。
    CommittingResults,
    /// Cancel 已传播，等待所有 child stopped facts。
    Cancelling,
    /// Normal terminal。
    Succeeded,
    /// Deterministic failure terminal。
    Failed,
    /// Cancelled terminal。
    Cancelled,
    /// Unknown effect terminal。
    ReconciliationRequired,
}

impl AgentPhase {
    /// 是否 terminal。
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::ReconciliationRequired
        )
    }
}

/// Stable terminal reason；vendor 原文不进入 domain。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentFailure {
    /// The current delegated authority check refused new sampling or effects.
    DelegationNotCurrent,
    /// Provider authentication。
    ProviderAuthentication,
    /// Provider rate limit exhausted for this run。
    ProviderRateLimited,
    /// Provider 5xx/transport unavailable。
    ProviderUnavailable,
    /// Provider request may have been sent but no response headers became knowable。
    ProviderCommitUnknown,
    /// Provider 停止请求的结果未获确认。
    ProviderStopUnknown,
    /// Provider schema/sequence invalid。
    ProviderInvalidResponse,
    /// Real read gap exceeded watchdog。
    ProviderStreamStalled,
    /// Provider reported failed/incomplete generation。
    ProviderGenerationFailed,
    /// Provider reported output beyond the authoritative per-sampling cap。
    ProviderTokenBudgetExceeded,
    /// Cumulative normalized output exceeded the run-wide token ceiling.
    RunTokenBudgetExceeded,
    /// A frozen user cost cap has no operator-attested rate snapshot.
    RunCostBudgetUnpriced,
    /// A frozen user cost cap and provider rate snapshot use different currencies.
    RunCostBudgetCurrencyMismatch,
    /// Durable provider cost upper bound exceeded the frozen user cap.
    RunCostBudgetExceeded,
    /// Tool step cap 8。
    ToolStepLimit,
    /// Tool loop implementation unavailable。
    ToolLoopUnavailable,
    /// Human/policy approval denied after tool pipeline audit。
    ToolDenied,
    /// Lease/fencing lost after dispatch accepted。
    RuntimeLeaseLost,
    /// Journal commit unknown after an effect may have happened。
    JournalCommitUnknown,
}

/// Reducer terminal target。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentTerminal {
    /// Completed。
    Succeeded,
    /// Failed。
    Failed(AgentFailure),
    /// Cancelled after child stop facts。
    Cancelled,
    /// Manual reconciliation required。
    ReconciliationRequired(AgentFailure),
}

/// One complete provider tool call, ordered by the host's stable output index.
#[derive(Clone, PartialEq)]
pub struct AgentToolCall {
    /// Vendor pairing id; never used as the control-plane call id.
    pub call_id: String,
    /// Catalog name, revalidated by ApplicationService.
    pub name: String,
    /// Parsed object arguments.
    pub arguments: Value,
}

impl core::fmt::Debug for AgentToolCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentToolCall")
            .field("call_id", &self.call_id)
            .field("name", &self.name)
            .field("arguments", &"[redacted]")
            .finish()
    }
}

/// Pure state。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentState {
    run_id: RunId,
    phase: AgentPhase,
    tool_steps: u8,
    pending_terminal: Option<AgentTerminal>,
}

impl AgentState {
    /// New queued reducer。
    #[must_use]
    pub fn queued(run_id: RunId) -> Self {
        Self {
            run_id,
            phase: AgentPhase::Queued,
            tool_steps: 0,
            pending_terminal: None,
        }
    }

    /// Run id。
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Phase。
    #[must_use]
    pub const fn phase(&self) -> AgentPhase {
        self.phase
    }

    /// Tool sampling steps used。
    #[must_use]
    pub const fn tool_steps(&self) -> u8 {
        self.tool_steps
    }
}

/// Reducer input facts；外部 effect 完成后必须显式回送 fact。
#[derive(Clone, PartialEq)]
pub enum AgentEvent {
    /// Durable outbox ack 后 runtime activation。
    DispatchActivated,
    /// Context/catalog loaded。
    ContextPrepared,
    /// Context load failed before provider start。
    ContextFailed(AgentFailure),
    /// Provider text delta。
    ProviderTextDelta(String),
    /// Provider reasoning delta。
    ProviderReasoningDelta(String),
    /// Provider completed one sampling turn with an ordered non-empty tool-call batch.
    ProviderToolCalls(Vec<AgentToolCall>),
    /// Provider normal terminal。
    ProviderCompleted,
    /// Provider normalized failure。
    ProviderFailed(AgentFailure),
    /// Tool result/outcome durably committed and ready for next sample。
    ToolResultCommitted,
    /// Tool host cannot execute this complete call。
    ToolRuntimeUnavailable,
    /// Approval required fact from tool pipeline。
    ApprovalRequired,
    /// Approval granted。
    ApprovalGranted,
    /// Approval/user denied; deterministic failure is already audited by tool pipeline。
    ApprovalDenied,
    /// Human handover requested。
    HumanRequired,
    /// Human released; the host must durably commit the waiting tool result before resampling.
    HumanReleased,
    /// A remote AG-UI interrupt batch was durably resolved and a fresh invocation may load context.
    RemoteResumeReady,
    /// Durable remote interrupt coordination failed with a closed local failure.
    RemoteResumeFailed(AgentFailure),
    /// User/deadline cancellation request。
    CancelRequested,
    /// Provider/tool/computer/process children all confirmed stopped。
    ChildrenStopped,
    /// Terminal transaction committed。
    TerminalCommitted,
    /// Lease/fencing lost。
    LeaseLost,
    /// Journal write failed after unknown external commit。
    JournalCommitUnknown,
}

impl core::fmt::Debug for AgentEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DispatchActivated => f.write_str("DispatchActivated"),
            Self::ContextPrepared => f.write_str("ContextPrepared"),
            Self::ContextFailed(value) => f.debug_tuple("ContextFailed").field(value).finish(),
            Self::ProviderTextDelta(value) => f
                .debug_tuple("ProviderTextDelta")
                .field(&format_args!("{} bytes", value.len()))
                .finish(),
            Self::ProviderReasoningDelta(value) => f
                .debug_tuple("ProviderReasoningDelta")
                .field(&format_args!("{} bytes", value.len()))
                .finish(),
            Self::ProviderToolCalls(calls) => f
                .debug_tuple("ProviderToolCalls")
                .field(&format_args!("{} calls", calls.len()))
                .finish(),
            Self::ProviderCompleted => f.write_str("ProviderCompleted"),
            Self::ProviderFailed(value) => f.debug_tuple("ProviderFailed").field(value).finish(),
            Self::ToolResultCommitted => f.write_str("ToolResultCommitted"),
            Self::ToolRuntimeUnavailable => f.write_str("ToolRuntimeUnavailable"),
            Self::ApprovalRequired => f.write_str("ApprovalRequired"),
            Self::ApprovalGranted => f.write_str("ApprovalGranted"),
            Self::ApprovalDenied => f.write_str("ApprovalDenied"),
            Self::HumanRequired => f.write_str("HumanRequired"),
            Self::HumanReleased => f.write_str("HumanReleased"),
            Self::RemoteResumeReady => f.write_str("RemoteResumeReady"),
            Self::RemoteResumeFailed(value) => {
                f.debug_tuple("RemoteResumeFailed").field(value).finish()
            }
            Self::CancelRequested => f.write_str("CancelRequested"),
            Self::ChildrenStopped => f.write_str("ChildrenStopped"),
            Self::TerminalCommitted => f.write_str("TerminalCommitted"),
            Self::LeaseLost => f.write_str("LeaseLost"),
            Self::JournalCommitUnknown => f.write_str("JournalCommitUnknown"),
        }
    }
}

/// Runtime effect；content/arguments Debug redacted by AgentEvent/host discipline。
#[derive(Clone, PartialEq)]
pub enum AgentEffect {
    /// Load context/catalog。
    LoadContext,
    /// Start/restart provider sampling with current context。
    StartProvider,
    /// Feed delta into 50ms/8KiB durable text sink。
    PersistText(String),
    /// Persist normalized reasoning semantic event。
    PersistReasoning(String),
    /// Invoke an ordered batch through the unique application tool pipeline.
    InvokeTools(Vec<AgentToolCall>),
    /// Ask UI/human approval surface。
    AwaitApproval,
    /// Suspend for human handover。
    AwaitHuman,
    /// Propagate cancellation to every child。
    CancelChildren,
    /// Commit exactly one terminal event。
    CommitTerminal(AgentTerminal),
}

impl core::fmt::Debug for AgentEffect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LoadContext => f.write_str("LoadContext"),
            Self::StartProvider => f.write_str("StartProvider"),
            Self::PersistText(value) => f
                .debug_tuple("PersistText")
                .field(&format_args!("{} bytes", value.len()))
                .finish(),
            Self::PersistReasoning(value) => f
                .debug_tuple("PersistReasoning")
                .field(&format_args!("{} bytes", value.len()))
                .finish(),
            Self::InvokeTools(calls) => f
                .debug_tuple("InvokeTools")
                .field(&format_args!("{} calls", calls.len()))
                .finish(),
            Self::AwaitApproval => f.write_str("AwaitApproval"),
            Self::AwaitHuman => f.write_str("AwaitHuman"),
            Self::CancelChildren => f.write_str("CancelChildren"),
            Self::CommitTerminal(value) => f.debug_tuple("CommitTerminal").field(value).finish(),
        }
    }
}

/// Invalid state/event pair。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("agent_reducer_invariant")]
pub struct AgentInvariantViolation;

/// Pure reducer。
pub fn reduce(
    state: &AgentState,
    event: AgentEvent,
) -> Result<(AgentState, Vec<AgentEffect>), AgentInvariantViolation> {
    if state.phase.is_terminal() {
        return Err(AgentInvariantViolation);
    }
    let mut next = state.clone();
    let effects = match (state.phase, event) {
        (AgentPhase::Queued, AgentEvent::DispatchActivated) => {
            next.phase = AgentPhase::Preparing;
            vec![AgentEffect::LoadContext]
        }
        (AgentPhase::Preparing, AgentEvent::ContextPrepared) => {
            next.phase = AgentPhase::Sampling;
            vec![AgentEffect::StartProvider]
        }
        (AgentPhase::Preparing, AgentEvent::ContextFailed(failure)) => {
            begin_terminal(&mut next, failure_terminal(failure))
        }
        (
            AgentPhase::ExecutingTools,
            AgentEvent::ContextFailed(AgentFailure::DelegationNotCurrent),
        ) => begin_terminal(
            &mut next,
            failure_terminal(AgentFailure::DelegationNotCurrent),
        ),
        (AgentPhase::Sampling, AgentEvent::ProviderTextDelta(delta)) if !delta.is_empty() => {
            vec![AgentEffect::PersistText(delta)]
        }
        (AgentPhase::Sampling, AgentEvent::ProviderReasoningDelta(delta)) if !delta.is_empty() => {
            vec![AgentEffect::PersistReasoning(delta)]
        }
        (AgentPhase::Sampling, AgentEvent::ProviderToolCalls(calls))
            if !calls.is_empty()
                && calls.iter().all(|call| {
                    !call.call_id.is_empty() && !call.name.is_empty() && call.arguments.is_object()
                })
                && calls.iter().enumerate().all(|(index, call)| {
                    calls[..index]
                        .iter()
                        .all(|prior| prior.call_id != call.call_id)
                }) =>
        {
            let count = u8::try_from(calls.len()).map_err(|_| AgentInvariantViolation)?;
            if state
                .tool_steps
                .checked_add(count)
                .is_none_or(|steps| steps > 8)
            {
                begin_terminal(
                    &mut next,
                    AgentTerminal::Failed(AgentFailure::ToolStepLimit),
                )
            } else {
                next.tool_steps += count;
                next.phase = AgentPhase::ExecutingTools;
                vec![AgentEffect::InvokeTools(calls)]
            }
        }
        (AgentPhase::ExecutingTools, AgentEvent::ApprovalRequired) => {
            next.phase = AgentPhase::AwaitingApproval;
            vec![AgentEffect::AwaitApproval]
        }
        (AgentPhase::AwaitingApproval, AgentEvent::ApprovalGranted) => {
            next.phase = AgentPhase::ExecutingTools;
            Vec::new()
        }
        (AgentPhase::AwaitingApproval, AgentEvent::ApprovalDenied) => {
            begin_terminal(&mut next, AgentTerminal::Failed(AgentFailure::ToolDenied))
        }
        (AgentPhase::ExecutingTools, AgentEvent::ToolResultCommitted) => {
            next.phase = AgentPhase::Preparing;
            vec![AgentEffect::LoadContext]
        }
        (AgentPhase::ExecutingTools, AgentEvent::ToolRuntimeUnavailable) => begin_terminal(
            &mut next,
            AgentTerminal::Failed(AgentFailure::ToolLoopUnavailable),
        ),
        (AgentPhase::Sampling, AgentEvent::ProviderCompleted) => {
            begin_terminal(&mut next, AgentTerminal::Succeeded)
        }
        (AgentPhase::Sampling, AgentEvent::ProviderFailed(failure)) => {
            begin_terminal(&mut next, failure_terminal(failure))
        }
        (AgentPhase::Sampling | AgentPhase::ExecutingTools, AgentEvent::HumanRequired) => {
            next.phase = AgentPhase::AwaitingHuman;
            vec![AgentEffect::AwaitHuman]
        }
        (AgentPhase::AwaitingHuman, AgentEvent::HumanReleased) => {
            next.phase = AgentPhase::ExecutingTools;
            Vec::new()
        }
        (AgentPhase::AwaitingHuman, AgentEvent::RemoteResumeReady) => {
            next.phase = AgentPhase::Preparing;
            vec![AgentEffect::LoadContext]
        }
        (AgentPhase::AwaitingHuman, AgentEvent::RemoteResumeFailed(failure)) => {
            begin_terminal(&mut next, failure_terminal(failure))
        }
        (
            AgentPhase::Queued
            | AgentPhase::Preparing
            | AgentPhase::Sampling
            | AgentPhase::AwaitingApproval
            | AgentPhase::AwaitingHuman
            | AgentPhase::ExecutingTools,
            AgentEvent::CancelRequested,
        ) => {
            next.phase = AgentPhase::Cancelling;
            vec![AgentEffect::CancelChildren]
        }
        (AgentPhase::Cancelling, AgentEvent::ChildrenStopped) => {
            begin_terminal(&mut next, AgentTerminal::Cancelled)
        }
        (
            AgentPhase::Preparing
            | AgentPhase::Sampling
            | AgentPhase::AwaitingApproval
            | AgentPhase::AwaitingHuman
            | AgentPhase::ExecutingTools
            | AgentPhase::Cancelling,
            AgentEvent::LeaseLost,
        ) => begin_terminal(
            &mut next,
            AgentTerminal::ReconciliationRequired(AgentFailure::RuntimeLeaseLost),
        ),
        (
            AgentPhase::Preparing
            | AgentPhase::Sampling
            | AgentPhase::AwaitingApproval
            | AgentPhase::AwaitingHuman
            | AgentPhase::ExecutingTools
            | AgentPhase::Cancelling,
            AgentEvent::JournalCommitUnknown,
        ) => begin_terminal(
            &mut next,
            AgentTerminal::ReconciliationRequired(AgentFailure::JournalCommitUnknown),
        ),
        (AgentPhase::CommittingResults, AgentEvent::TerminalCommitted) => {
            next.phase = match next
                .pending_terminal
                .take()
                .ok_or(AgentInvariantViolation)?
            {
                AgentTerminal::Succeeded => AgentPhase::Succeeded,
                AgentTerminal::Failed(_) => AgentPhase::Failed,
                AgentTerminal::Cancelled => AgentPhase::Cancelled,
                AgentTerminal::ReconciliationRequired(_) => AgentPhase::ReconciliationRequired,
            };
            Vec::new()
        }
        _ => return Err(AgentInvariantViolation),
    };
    Ok((next, effects))
}

fn begin_terminal(state: &mut AgentState, terminal: AgentTerminal) -> Vec<AgentEffect> {
    state.phase = AgentPhase::CommittingResults;
    state.pending_terminal = Some(terminal);
    vec![AgentEffect::CommitTerminal(terminal)]
}

const fn failure_terminal(failure: AgentFailure) -> AgentTerminal {
    match failure {
        AgentFailure::ProviderCommitUnknown
        | AgentFailure::ProviderStopUnknown
        | AgentFailure::RuntimeLeaseLost
        | AgentFailure::JournalCommitUnknown => AgentTerminal::ReconciliationRequired(failure),
        _ => AgentTerminal::Failed(failure),
    }
}

#[cfg(test)]
#[path = "agent_stop_tests.rs"]
mod stop_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn step(state: &AgentState, event: AgentEvent) -> (AgentState, Vec<AgentEffect>) {
        reduce(state, event).unwrap()
    }

    #[test]
    fn text_run_moves_only_on_explicit_effect_facts_and_commits_one_terminal() {
        let state = AgentState::queued(RunId::new("run-1"));
        let (state, effects) = step(&state, AgentEvent::DispatchActivated);
        assert_eq!(effects, [AgentEffect::LoadContext]);
        let (state, effects) = step(&state, AgentEvent::ContextPrepared);
        assert_eq!(effects, [AgentEffect::StartProvider]);
        let (state, effects) = step(&state, AgentEvent::ProviderTextDelta("hello".to_owned()));
        assert_eq!(effects, [AgentEffect::PersistText("hello".to_owned())]);
        let (state, effects) = step(&state, AgentEvent::ProviderCompleted);
        assert_eq!(
            effects,
            [AgentEffect::CommitTerminal(AgentTerminal::Succeeded)]
        );
        let (state, effects) = step(&state, AgentEvent::TerminalCommitted);
        assert_eq!(state.phase(), AgentPhase::Succeeded);
        assert!(effects.is_empty());
        assert_eq!(
            reduce(&state, AgentEvent::ProviderCompleted),
            Err(AgentInvariantViolation)
        );
    }

    #[test]
    fn cancel_waits_for_children_and_unknown_journal_never_becomes_success() {
        let state = AgentState::queued(RunId::new("run-2"));
        let (state, _) = step(&state, AgentEvent::DispatchActivated);
        let (state, _) = step(&state, AgentEvent::ContextPrepared);
        let (state, effects) = step(&state, AgentEvent::CancelRequested);
        assert_eq!(state.phase(), AgentPhase::Cancelling);
        assert_eq!(effects, [AgentEffect::CancelChildren]);
        assert!(reduce(&state, AgentEvent::TerminalCommitted).is_err());
        let (state, effects) = step(&state, AgentEvent::ChildrenStopped);
        assert_eq!(
            effects,
            [AgentEffect::CommitTerminal(AgentTerminal::Cancelled)]
        );
        let (state, _) = step(&state, AgentEvent::TerminalCommitted);
        assert_eq!(state.phase(), AgentPhase::Cancelled);

        let state = AgentState::queued(RunId::new("run-3"));
        let (state, _) = step(&state, AgentEvent::DispatchActivated);
        let (state, effects) = step(&state, AgentEvent::JournalCommitUnknown);
        assert!(matches!(
            effects.as_slice(),
            [AgentEffect::CommitTerminal(
                AgentTerminal::ReconciliationRequired(AgentFailure::JournalCommitUnknown)
            )]
        ));
        let (state, _) = step(&state, AgentEvent::TerminalCommitted);
        assert_eq!(state.phase(), AgentPhase::ReconciliationRequired);
    }

    #[test]
    fn ninth_tool_step_is_refused_before_another_invoke_effect() {
        let mut state = AgentState::queued(RunId::new("run-tools"));
        (state, _) = step(&state, AgentEvent::DispatchActivated);
        (state, _) = step(&state, AgentEvent::ContextPrepared);
        for index in 0..8 {
            let (next, effects) = step(
                &state,
                AgentEvent::ProviderToolCalls(vec![AgentToolCall {
                    call_id: format!("call-{index}"),
                    name: "tool".to_owned(),
                    arguments: serde_json::json!({}),
                }]),
            );
            assert!(matches!(effects.as_slice(), [AgentEffect::InvokeTools(_)]));
            let (next, effects) = step(&next, AgentEvent::ToolResultCommitted);
            assert_eq!(effects, [AgentEffect::LoadContext]);
            (state, _) = step(&next, AgentEvent::ContextPrepared);
        }
        let (state, effects) = step(
            &state,
            AgentEvent::ProviderToolCalls(vec![AgentToolCall {
                call_id: "call-9".to_owned(),
                name: "tool".to_owned(),
                arguments: serde_json::json!({}),
            }]),
        );
        assert_eq!(state.phase(), AgentPhase::CommittingResults);
        assert_eq!(
            effects,
            [AgentEffect::CommitTerminal(AgentTerminal::Failed(
                AgentFailure::ToolStepLimit
            ))]
        );
    }

    #[test]
    fn human_tool_result_returns_to_execution_until_the_exchange_is_committed() {
        let mut state = AgentState::queued(RunId::new("run-human"));
        (state, _) = step(&state, AgentEvent::DispatchActivated);
        (state, _) = step(&state, AgentEvent::ContextPrepared);
        let (next, effects) = step(
            &state,
            AgentEvent::ProviderToolCalls(vec![AgentToolCall {
                call_id: "provider-human-1".to_owned(),
                name: "askApproval".to_owned(),
                arguments: serde_json::json!({}),
            }]),
        );
        assert_eq!(next.phase(), AgentPhase::ExecutingTools);
        assert!(matches!(effects.as_slice(), [AgentEffect::InvokeTools(_)]));
        let (waiting, effects) = step(&next, AgentEvent::HumanRequired);
        assert_eq!(waiting.phase(), AgentPhase::AwaitingHuman);
        assert_eq!(effects, [AgentEffect::AwaitHuman]);
        let (executing, effects) = step(&waiting, AgentEvent::HumanReleased);
        assert_eq!(executing.phase(), AgentPhase::ExecutingTools);
        assert!(effects.is_empty());
        let (preparing, effects) = step(&executing, AgentEvent::ToolResultCommitted);
        assert_eq!(preparing.phase(), AgentPhase::Preparing);
        assert_eq!(effects, [AgentEffect::LoadContext]);
    }

    #[test]
    fn remote_interrupt_resume_reloads_context_without_faking_a_tool_exchange() {
        let mut state = AgentState::queued(RunId::new("run-remote-human"));
        (state, _) = step(&state, AgentEvent::DispatchActivated);
        (state, _) = step(&state, AgentEvent::ContextPrepared);
        let (waiting, effects) = step(&state, AgentEvent::HumanRequired);
        assert_eq!(waiting.phase(), AgentPhase::AwaitingHuman);
        assert_eq!(effects, [AgentEffect::AwaitHuman]);

        let (preparing, effects) = step(&waiting, AgentEvent::RemoteResumeReady);
        assert_eq!(preparing.phase(), AgentPhase::Preparing);
        assert_eq!(preparing.tool_steps(), 0);
        assert_eq!(effects, [AgentEffect::LoadContext]);

        let (failed, effects) = step(
            &waiting,
            AgentEvent::RemoteResumeFailed(AgentFailure::ProviderGenerationFailed),
        );
        assert_eq!(failed.phase(), AgentPhase::CommittingResults);
        assert_eq!(
            effects,
            [AgentEffect::CommitTerminal(AgentTerminal::Failed(
                AgentFailure::ProviderGenerationFailed
            ))]
        );
    }
}
