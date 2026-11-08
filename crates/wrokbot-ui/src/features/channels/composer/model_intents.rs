//! Frozen per-run intent and an app-owned unknown-write barrier.

use leptos::prelude::*;
use openbot_contracts::command::{ChannelDetail, ThreadRunAnchor};
use openbot_contracts::ids::{BotId, RunId, ThreadId};
use openbot_contracts::model_connections::RunModelSelection;
use openbot_contracts::versioned_model_selection::RunModelSelectionV2;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
use crate::api::{bot_chat_href, channel_new_href, channel_route_href};

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_definite_rejection(error: ApiError) -> bool {
    matches!(
        error,
        ApiError::Unauthorized
            | ApiError::Forbidden
            | ApiError::NotFound
            | ApiError::Conflict
            | ApiError::PendingInputLimit
            | ApiError::PendingInputState
            | ApiError::AnchorUnsupported
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionSource {
    Home,
    ChannelNew,
    #[cfg(any(target_arch = "wasm32", test))]
    Conversation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreateIntent {
    pub(crate) source: SubmissionSource,
    pub(crate) run_id: RunId,
    pub(crate) agent_id: BotId,
    pub(crate) message: String,
    pub(crate) selected_skill_slugs: Vec<String>,
    pub(crate) model_selection: Option<RunModelSelection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunIntent {
    pub(crate) thread_id: Option<ThreadId>,
    pub(crate) run_id: RunId,
    pub(crate) agent_id: BotId,
    pub(crate) anchor: ThreadRunAnchor,
    pub(crate) message: String,
    pub(crate) selected_skill_slugs: Vec<String>,
    pub(crate) model_selection: Option<RunModelSelection>,
    /// The frozen v2 selection a direct-Bot submission carries.
    ///
    /// The direct-Bot entry accepts only a v2 body whose selection is `custom`, so the intent
    /// keeps that selection next to the v1 one instead of replacing it. The channel entry leaves
    /// it empty and keeps using `BeginThreadRun`.
    pub(crate) model_selection_v2: Option<RunModelSelectionV2>,
}

impl RunIntent {
    pub(crate) fn queue_id(&self) -> &str {
        self.run_id.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunRecovery {
    pub(crate) source: SubmissionSource,
    pub(crate) intent: RunIntent,
    pub(crate) channel: Option<ChannelDetail>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionBarrier {
    Create(CreateIntent),
    Run(Box<RunRecovery>),
}

impl SubmissionBarrier {
    pub(crate) fn href(&self) -> Option<String> {
        match self {
            Self::Create(intent) => match intent.source {
                SubmissionSource::Home => Some("/".to_owned()),
                SubmissionSource::ChannelNew => channel_new_href(intent.agent_id.as_str()).ok(),
                #[cfg(any(target_arch = "wasm32", test))]
                SubmissionSource::Conversation => None,
            },
            Self::Run(recovery) => recovery.channel.as_ref().map_or_else(
                || match &recovery.intent.anchor {
                    ThreadRunAnchor::DirectBot => {
                        bot_chat_href(recovery.intent.agent_id.as_str()).ok()
                    }
                    ThreadRunAnchor::Channel { channel_id } => {
                        channel_route_href(channel_id.as_str()).ok()
                    }
                },
                |channel| channel_route_href(channel.id.as_str()).ok(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmissionPhase {
    #[cfg(any(target_arch = "wasm32", test))]
    InFlight,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCreate {
    intent: CreateIntent,
    phase: SubmissionPhase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingRun {
    recovery: RunRecovery,
    phase: SubmissionPhase,
}

#[derive(Clone, Copy)]
pub(crate) struct RunSubmissionActions {
    create: RwSignal<Option<PendingCreate>>,
    run: RwSignal<Option<PendingRun>>,
}

impl RunSubmissionActions {
    pub(crate) fn new() -> Self {
        Self {
            create: RwSignal::new(None),
            run: RwSignal::new(None),
        }
    }

    /// Channel creation has no idempotency key. Any existing in-flight/unknown write blocks every
    /// later create, including one carrying the same run id.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn start_create(self, intent: &CreateIntent) -> Option<CreateTicket> {
        if self.run.with_untracked(Option::is_some) {
            return None;
        }
        let admitted = self
            .create
            .try_update(|pending| {
                if pending.is_some() {
                    return false;
                }
                *pending = Some(PendingCreate {
                    intent: intent.clone(),
                    phase: SubmissionPhase::InFlight,
                });
                true
            })
            .unwrap_or(false);
        admitted.then(|| CreateTicket {
            actions: self,
            intent: intent.clone(),
            finished: false,
        })
    }

    /// A retained BeginRun may transition Unknown -> InFlight only for an explicit user retry of
    /// the byte-for-byte same UI intent. A second caller cannot join an in-flight request.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn start_run(
        self,
        recovery: &RunRecovery,
        retry_unknown: bool,
    ) -> Option<RunTicket> {
        if self.create.with_untracked(Option::is_some) {
            return None;
        }
        let admitted = self
            .run
            .try_update(|pending| match pending {
                None => {
                    *pending = Some(PendingRun {
                        recovery: recovery.clone(),
                        phase: SubmissionPhase::InFlight,
                    });
                    true
                }
                Some(existing)
                    if retry_unknown
                        && existing.phase == SubmissionPhase::Unknown
                        && existing.recovery == *recovery =>
                {
                    existing.phase = SubmissionPhase::InFlight;
                    true
                }
                Some(_) => false,
            })
            .unwrap_or(false);
        admitted.then(|| RunTicket {
            actions: self,
            recovery: recovery.clone(),
            finished: false,
        })
    }

    pub(crate) fn create_unknown(self, source: SubmissionSource) -> Option<CreateIntent> {
        self.create.with(|pending| {
            pending
                .as_ref()
                .filter(|pending| {
                    pending.phase == SubmissionPhase::Unknown && pending.intent.source == source
                })
                .map(|pending| pending.intent.clone())
        })
    }

    pub(crate) fn run_unknown_for_source(self, source: SubmissionSource) -> Option<RunRecovery> {
        self.run.with(|pending| {
            pending
                .as_ref()
                .filter(|pending| {
                    pending.phase == SubmissionPhase::Unknown && pending.recovery.source == source
                })
                .map(|pending| pending.recovery.clone())
        })
    }

    pub(crate) fn run_unknown_for_scope(
        self,
        thread_id: Option<&ThreadId>,
        anchor: &ThreadRunAnchor,
        agent_id: Option<&BotId>,
    ) -> Option<RunRecovery> {
        self.run.with(|pending| {
            pending
                .as_ref()
                .filter(|pending| {
                    let intent = &pending.recovery.intent;
                    pending.phase == SubmissionPhase::Unknown
                        && intent.thread_id.as_ref() == thread_id
                        && &intent.anchor == anchor
                        && Some(&intent.agent_id) == agent_id
                })
                .map(|pending| pending.recovery.clone())
        })
    }

    /// An authoritative snapshot/SSE projection for the exact scope and run resolves a lost Begin
    /// acknowledgement. A run with the same id in another thread/anchor/Agent cannot clear it.
    pub(crate) fn acknowledge_observed(
        self,
        thread_id: &ThreadId,
        anchor: &ThreadRunAnchor,
        agent_id: &BotId,
        run_id: &RunId,
    ) -> bool {
        self.run
            .try_update(|pending| {
                let matches = pending.as_ref().is_some_and(|pending| {
                    let intent = &pending.recovery.intent;
                    intent.thread_id.as_ref() == Some(thread_id)
                        && &intent.anchor == anchor
                        && &intent.agent_id == agent_id
                        && &intent.run_id == run_id
                });
                if matches {
                    *pending = None;
                }
                matches
            })
            .unwrap_or(false)
    }

    pub(crate) fn has_barrier(self) -> bool {
        self.create.with(Option::is_some) || self.run.with(Option::is_some)
    }

    pub(crate) fn barrier(self) -> Option<SubmissionBarrier> {
        self.create
            .with(|pending| {
                pending
                    .as_ref()
                    .map(|pending| SubmissionBarrier::Create(pending.intent.clone()))
            })
            .or_else(|| {
                self.run.with(|pending| {
                    pending
                        .as_ref()
                        .map(|pending| SubmissionBarrier::Run(Box::new(pending.recovery.clone())))
                })
            })
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn finish_create(self, intent: &CreateIntent, error: Option<ApiError>) {
        self.create.try_update(|pending| {
            let Some(existing) = pending.as_mut().filter(|pending| pending.intent == *intent)
            else {
                return;
            };
            if error.is_none_or(is_definite_rejection) {
                *pending = None;
            } else {
                existing.phase = SubmissionPhase::Unknown;
            }
        });
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn abandon_create(self, intent: &CreateIntent) {
        self.create.try_update(|pending| {
            if let Some(existing) = pending.as_mut().filter(|pending| pending.intent == *intent) {
                existing.phase = SubmissionPhase::Unknown;
            }
        });
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn finish_run(self, recovery: &RunRecovery, error: Option<ApiError>) {
        self.run.try_update(|pending| {
            let Some(existing) = pending
                .as_mut()
                .filter(|pending| pending.recovery == *recovery)
            else {
                return;
            };
            if error.is_none_or(is_definite_rejection) {
                *pending = None;
            } else {
                existing.phase = SubmissionPhase::Unknown;
            }
        });
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn abandon_run(self, recovery: &RunRecovery) {
        self.run.try_update(|pending| {
            if let Some(existing) = pending
                .as_mut()
                .filter(|pending| pending.recovery == *recovery)
            {
                existing.phase = SubmissionPhase::Unknown;
            }
        });
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) struct CreateTicket {
    actions: RunSubmissionActions,
    intent: CreateIntent,
    finished: bool,
}

#[cfg(any(target_arch = "wasm32", test))]
impl CreateTicket {
    pub(crate) fn accepted(mut self) {
        self.actions.finish_create(&self.intent, None);
        self.finished = true;
    }

    pub(crate) fn failed(mut self, error: ApiError) {
        self.actions.finish_create(&self.intent, Some(error));
        self.finished = true;
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl Drop for CreateTicket {
    fn drop(&mut self) {
        if !self.finished {
            self.actions.abandon_create(&self.intent);
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) struct RunTicket {
    actions: RunSubmissionActions,
    recovery: RunRecovery,
    finished: bool,
}

#[cfg(any(target_arch = "wasm32", test))]
impl RunTicket {
    pub(crate) fn accepted(mut self) {
        self.actions.finish_run(&self.recovery, None);
        self.finished = true;
    }

    pub(crate) fn failed(mut self, error: ApiError) {
        self.actions.finish_run(&self.recovery, Some(error));
        self.finished = true;
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl Drop for RunTicket {
    fn drop(&mut self) {
        if !self.finished {
            self.actions.abandon_run(&self.recovery);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(revision: i64) -> RunIntent {
        RunIntent {
            thread_id: Some(ThreadId::new("thread")),
            run_id: RunId::new("run"),
            agent_id: BotId::new("agent"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "hello".into(),
            selected_skill_slugs: vec!["review".into()],
            model_selection: Some(RunModelSelection {
                connection_id: "01991389-7380-7000-8000-000000000001".into(),
                expected_revision: revision,
            }),
            model_selection_v2: None,
        }
    }

    fn recovery(revision: i64) -> RunRecovery {
        RunRecovery {
            source: SubmissionSource::Conversation,
            intent: intent(revision),
            channel: None,
        }
    }

    fn create() -> CreateIntent {
        CreateIntent {
            source: SubmissionSource::Home,
            run_id: RunId::new("run"),
            agent_id: BotId::new("agent"),
            message: "hello".into(),
            selected_skill_slugs: vec!["review".into()],
            model_selection: None,
        }
    }

    fn create_with_run(run_id: &str) -> CreateIntent {
        let mut value = create();
        value.run_id = RunId::new(run_id);
        value
    }

    fn recovery_with_run(run_id: &str) -> RunRecovery {
        let mut value = recovery(1);
        value.intent.run_id = RunId::new(run_id);
        value
    }

    #[test]
    fn acknowledged_or_definitely_rejected_create_releases_the_next_intent() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            actions
                .start_create(&create_with_run("accepted"))
                .unwrap()
                .accepted();
            actions
                .start_create(&create_with_run("rejected"))
                .unwrap()
                .failed(ApiError::Conflict);
            actions
                .start_create(&create_with_run("next"))
                .unwrap()
                .accepted();
            assert!(!actions.has_barrier());
        });
    }

    #[test]
    fn acknowledged_or_definitely_rejected_run_releases_the_next_intent() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            actions
                .start_run(&recovery_with_run("accepted"), false)
                .unwrap()
                .accepted();
            actions
                .start_run(&recovery_with_run("rejected"), false)
                .unwrap()
                .failed(ApiError::Forbidden);
            actions
                .start_run(&recovery_with_run("next"), false)
                .unwrap()
                .accepted();
            assert!(!actions.has_barrier());
        });
    }

    #[test]
    fn unknown_create_never_admits_a_second_create_even_with_the_same_identity() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            let ticket = actions.start_create(&create()).unwrap();
            assert!(actions.start_create(&create()).is_none());
            assert!(actions.create_unknown(SubmissionSource::Home).is_none());
            drop(ticket);
            assert_eq!(
                actions.create_unknown(SubmissionSource::Home),
                Some(create())
            );
            assert!(actions.start_create(&create()).is_none());
            let mut different = create();
            different.run_id = RunId::new("different");
            assert!(actions.start_create(&different).is_none());
        });
    }

    #[test]
    fn unknown_begin_requires_an_explicit_exact_retry_and_blocks_concurrent_duplicates() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            let first = actions.start_run(&recovery(1), false).unwrap();
            assert!(actions.start_run(&recovery(1), true).is_none());
            drop(first);
            assert!(actions.start_run(&recovery(1), false).is_none());
            assert!(actions.start_run(&recovery(2), true).is_none());
            let mut wrong_source = recovery(1);
            wrong_source.source = SubmissionSource::Home;
            assert!(actions.start_run(&wrong_source, true).is_none());
            let retry = actions.start_run(&recovery(1), true).unwrap();
            retry.failed(ApiError::Network);
            assert_eq!(
                actions
                    .run_unknown_for_scope(
                        Some(&ThreadId::new("thread")),
                        &ThreadRunAnchor::DirectBot,
                        Some(&BotId::new("agent")),
                    )
                    .unwrap()
                    .intent,
                intent(1)
            );
        });
    }

    #[test]
    fn exact_authoritative_readback_clears_only_the_matching_barrier() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            drop(actions.start_run(&recovery(1), false).unwrap());
            assert!(!actions.acknowledge_observed(
                &ThreadId::new("other"),
                &ThreadRunAnchor::DirectBot,
                &BotId::new("agent"),
                &RunId::new("run"),
            ));
            assert!(actions.has_barrier());
            assert!(actions.acknowledge_observed(
                &ThreadId::new("thread"),
                &ThreadRunAnchor::DirectBot,
                &BotId::new("agent"),
                &RunId::new("run"),
            ));
            assert!(!actions.has_barrier());
        });
    }
}
