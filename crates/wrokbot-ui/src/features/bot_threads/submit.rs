//! The direct-Bot entry's durable submission path.
//!
//! The direct assistant accepts an input through `SubmitThreadInput`, not `BeginThreadRun`. The
//! Server either starts the Run or retains the frozen input durably; the receipt decides which of
//! the two the user sees. Nothing here guesses the outcome: a `queued` receipt is shown as
//! "accepted, waiting to be handled", and the retained row is read back from the Server.

use openbot_contracts::command::{BeginThreadRunV2Body, ThreadInputOutcome, ThreadRunAnchor};
use openbot_contracts::ids::{BotId, RunId};
use openbot_contracts::versioned_model_selection::RunModelSelectionV2;

#[cfg(any(target_arch = "wasm32", test))]
use crate::{
    api::ApiError,
    features::channels::composer::model_intents::{
        RunRecovery, RunSubmissionActions, is_definite_rejection,
    },
};

/// The result of a direct input, including refusal by the shared submission barrier.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectSubmissionOutcome {
    Accepted(AcceptedInput),
    Failed(ApiError),
    Blocked,
}

/// Keep the shared write barrier through submission and readback; cancellation retains Unknown.
///
/// Only an unknown receipt is read back by its run id. A definite refusal accepted nothing, so
/// it releases the barrier without another read.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) async fn submit_direct_input(
    submissions: RunSubmissionActions,
    recovery: &RunRecovery,
    retry_unknown: bool,
    submit: impl std::future::Future<Output = Result<AcceptedInput, ApiError>>,
    read_back: impl std::future::Future<Output = Option<AcceptedInput>>,
) -> DirectSubmissionOutcome {
    let Some(ticket) = submissions.start_run(recovery, retry_unknown) else {
        return DirectSubmissionOutcome::Blocked;
    };
    match submit.await {
        Ok(accepted) => {
            ticket.accepted();
            DirectSubmissionOutcome::Accepted(accepted)
        }
        Err(error) if is_definite_rejection(error) => {
            ticket.failed(error);
            DirectSubmissionOutcome::Failed(error)
        }
        Err(error) => match read_back.await {
            Some(accepted) => {
                ticket.accepted();
                DirectSubmissionOutcome::Accepted(accepted)
            }
            None => {
                ticket.failed(error);
                DirectSubmissionOutcome::Failed(error)
            }
        },
    }
}

/// What the Server's acceptance receipt means for the conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AcceptedInput {
    /// The Run started; the conversation subscribes to it.
    Started {
        /// The started Run's identity.
        run_id: RunId,
    },
    /// The input is durably retained; no Run has started.
    Queued {
        /// The retained input's identity.
        run_id: RunId,
        /// One plus the number of earlier pending inputs, as the receipt or the read-back list
        /// reported it; a read-back row that is held has no queue position.
        position: Option<u32>,
    },
}

impl AcceptedInput {
    /// Read the Server's own receipt.
    pub(crate) fn from_outcome(outcome: &ThreadInputOutcome) -> Self {
        match outcome {
            ThreadInputOutcome::Started(started) => Self::Started {
                run_id: started.run_id.clone(),
            },
            ThreadInputOutcome::Queued { run_id, position } => Self::Queued {
                run_id: run_id.clone(),
                position: Some(*position),
            },
        }
    }
}

/// Build the v2 body one direct-Bot submission must carry.
///
/// The Server accepts only a v2 body whose selection is `custom`, and it compares all four
/// frozen values against the durable connection and catalog rows. The selection therefore comes
/// from the owner's catalog entry and is never repaired here.
pub(crate) fn v2_body(
    run_id: &RunId,
    agent_id: &BotId,
    message: &str,
    selected_skill_slugs: &[String],
    model_selection: &RunModelSelectionV2,
) -> BeginThreadRunV2Body {
    BeginThreadRunV2Body {
        model_selection: model_selection.clone(),
        run_id: run_id.clone(),
        bot_id: agent_id.clone(),
        anchor: ThreadRunAnchor::DirectBot,
        message: message.to_owned(),
        selected_skill_slugs: selected_skill_slugs.to_vec(),
        artifact_refs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::channels::composer::model_intents::{RunIntent, SubmissionSource};
    use leptos::prelude::*;
    use openbot_contracts::ids::ThreadId;
    use openbot_contracts::versioned_model_selection::ModelSelectionIntentSource;
    use std::{
        future::{Future, pending, ready},
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    fn selection() -> RunModelSelectionV2 {
        RunModelSelectionV2::new(
            ModelSelectionIntentSource::Custom,
            "01991389-7380-7000-8000-000000000004".to_owned(),
            3,
            "custom:01991389-7380-7000-8000-000000000004".to_owned(),
            7,
        )
        .expect("catalog selection assembles")
    }

    fn recovery() -> RunRecovery {
        RunRecovery {
            source: SubmissionSource::Conversation,
            intent: RunIntent {
                thread_id: Some(ThreadId::new("thread")),
                run_id: RunId::new("original"),
                agent_id: BotId::new("bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "original message".to_owned(),
                selected_skill_slugs: vec!["review".to_owned()],
                model_selection: None,
                model_selection_v2: Some(selection()),
            },
            channel: None,
        }
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn direct_input_blocks_new_submissions_through_readback_and_route_cancellation() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            let original = recovery();
            let mut request = Box::pin(submit_direct_input(
                actions,
                &original,
                false,
                ready(Err(ApiError::Network)),
                pending(),
            ));
            assert!(poll(request.as_mut()).is_pending());
            assert!(actions.has_barrier());
            let mut another = original.clone();
            another.intent.run_id = RunId::new("new-id");
            assert!(actions.start_run(&another, false).is_none());
            assert!(actions.start_run(&original, true).is_none());
            // Unmounting the conversation drops its request; app-owned recovery survives it.
            drop(request);
            assert_eq!(
                actions.run_unknown_for_scope(
                    original.intent.thread_id.as_ref(),
                    &original.intent.anchor,
                    Some(&original.intent.agent_id),
                ),
                Some(original)
            );
        });
    }

    #[test]
    fn direct_input_unknown_receipt_allows_only_an_explicit_unchanged_retry() {
        Owner::new().with(|| {
            let actions = RunSubmissionActions::new();
            let original = recovery();
            let mut request = Box::pin(submit_direct_input(
                actions,
                &original,
                false,
                ready(Err(ApiError::Network)),
                ready(None),
            ));
            assert_eq!(
                poll(request.as_mut()),
                Poll::Ready(DirectSubmissionOutcome::Failed(ApiError::Network))
            );
            let mut changed = vec![original.clone(); 3];
            changed[0].intent.run_id = RunId::new("new-id");
            changed[1].intent.message.push_str(" changed");
            changed[2].intent.model_selection_v2 = Some(
                RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    selection().connection_id().to_owned(),
                    3,
                    selection().model_id().to_owned(),
                    8,
                )
                .expect("new catalog revision"),
            );
            for intent in changed {
                let mut blocked = Box::pin(submit_direct_input(
                    actions,
                    &intent,
                    true,
                    async { panic!("a changed intent must never reach the transport") },
                    ready(None),
                ));
                assert_eq!(
                    poll(blocked.as_mut()),
                    Poll::Ready(DirectSubmissionOutcome::Blocked)
                );
            }
            assert!(actions.start_run(&original, false).is_none());
            let accepted = AcceptedInput::Queued {
                run_id: original.intent.run_id.clone(),
                position: Some(1),
            };
            let mut retry = Box::pin(submit_direct_input(
                actions,
                &original,
                true,
                ready(Ok(accepted.clone())),
                pending(),
            ));
            assert_eq!(
                poll(retry.as_mut()),
                Poll::Ready(DirectSubmissionOutcome::Accepted(accepted))
            );
            assert!(!actions.has_barrier());
        });
    }

    #[test]
    fn direct_input_authoritative_readback_resolves_both_acceptance_outcomes() {
        Owner::new().with(|| {
            for accepted in [
                AcceptedInput::Queued {
                    run_id: RunId::new("original"),
                    position: None,
                },
                AcceptedInput::Started {
                    run_id: RunId::new("original"),
                },
            ] {
                let actions = RunSubmissionActions::new();
                let original = recovery();
                let mut request = Box::pin(submit_direct_input(
                    actions,
                    &original,
                    false,
                    ready(Err(ApiError::Network)),
                    ready(Some(accepted.clone())),
                ));
                assert_eq!(
                    poll(request.as_mut()),
                    Poll::Ready(DirectSubmissionOutcome::Accepted(accepted))
                );
                assert!(!actions.has_barrier());
            }
        });
    }

    #[test]
    fn direct_input_definite_rejections_release_the_barrier() {
        Owner::new().with(|| {
            for error in [
                ApiError::PendingInputLimit,
                ApiError::PendingInputState,
                ApiError::AnchorUnsupported,
            ] {
                let actions = RunSubmissionActions::new();
                let original = recovery();
                let mut request = Box::pin(submit_direct_input(
                    actions,
                    &original,
                    false,
                    ready(Err(error)),
                    async { panic!("a definite rejection is never read back") },
                ));
                assert_eq!(
                    poll(request.as_mut()),
                    Poll::Ready(DirectSubmissionOutcome::Failed(error))
                );
                assert!(
                    !actions.has_barrier(),
                    "definite rejection {error:?} must release the barrier"
                );
            }
        });
    }

    #[test]
    fn a_queued_receipt_is_not_a_started_run() {
        let outcome = ThreadInputOutcome::Queued {
            run_id: RunId::new("run-1"),
            position: 2,
        };
        assert_eq!(
            AcceptedInput::from_outcome(&outcome),
            AcceptedInput::Queued {
                run_id: RunId::new("run-1"),
                position: Some(2)
            }
        );
    }

    #[test]
    fn a_started_receipt_keeps_the_runs_own_identity() {
        let outcome = ThreadInputOutcome::Started(openbot_contracts::command::ThreadRunStarted {
            thread_id: ThreadId::new("01991389-7380-7000-8000-000000000001"),
            run_id: RunId::new("run-2"),
            message_sequence: 1,
            event_sequence: 1,
            replayed: false,
        });
        assert_eq!(
            AcceptedInput::from_outcome(&outcome),
            AcceptedInput::Started {
                run_id: RunId::new("run-2")
            }
        );
    }

    #[test]
    fn the_body_carries_the_direct_bot_anchor_and_the_frozen_selection() {
        let body = v2_body(
            &RunId::new("run-3"),
            &BotId::new("bot-1"),
            "hello",
            &["review".to_owned()],
            &selection(),
        );
        assert_eq!(body.anchor, ThreadRunAnchor::DirectBot);
        assert_eq!(body.model_selection, selection());
        assert_eq!(body.run_id, RunId::new("run-3"));
        assert_eq!(body.bot_id, BotId::new("bot-1"));
        assert_eq!(body.message, "hello");
        assert_eq!(body.selected_skill_slugs, vec!["review".to_owned()]);
        assert!(body.artifact_refs.is_empty());
    }
}
