//! Transient in-mount FIFO for exact frozen run intents.

#![cfg_attr(not(test), allow(dead_code))]

use std::borrow::Cow;

use super::model_intents::RunIntent;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueuedMessage {
    pub(crate) id: String,
    pub(crate) intent: RunIntent,
}

pub(crate) enum QueueAction<'a> {
    Submit { intent: &'a RunIntent, busy: bool },
    Settle,
    Remove { id: &'a str },
}

pub(crate) struct QueueTransition<'a> {
    pub(crate) queue: Cow<'a, [QueuedMessage]>,
    pub(crate) run: Option<Cow<'a, RunIntent>>,
    /// The submitted intent remains frozen in `queue` instead of being dispatched by this step.
    pub(crate) submitted_queued: bool,
}

pub(crate) fn reduce_queue<'a>(
    queue: &'a [QueuedMessage],
    action: QueueAction<'a>,
) -> QueueTransition<'a> {
    match action {
        QueueAction::Submit {
            intent,
            busy: false,
        } if queue.is_empty() => QueueTransition {
            queue: Cow::Borrowed(queue),
            run: Some(Cow::Borrowed(intent)),
            submitted_queued: false,
        },
        QueueAction::Submit {
            intent,
            busy: false,
        } => {
            let mut waiting = queue.to_vec();
            waiting.push(queued(intent));
            let next = waiting.remove(0).intent;
            QueueTransition {
                queue: Cow::Owned(waiting),
                run: Some(Cow::Owned(next)),
                submitted_queued: true,
            }
        }
        QueueAction::Submit { intent, busy: true } => {
            let mut waiting = queue.to_vec();
            waiting.push(queued(intent));
            QueueTransition {
                queue: Cow::Owned(waiting),
                run: None,
                submitted_queued: true,
            }
        }
        QueueAction::Settle if queue.is_empty() => QueueTransition {
            queue: Cow::Borrowed(queue),
            run: None,
            submitted_queued: false,
        },
        QueueAction::Settle => QueueTransition {
            queue: Cow::Owned(queue[1..].to_vec()),
            run: Some(Cow::Owned(queue[0].intent.clone())),
            submitted_queued: false,
        },
        QueueAction::Remove { id } => {
            let kept = queue
                .iter()
                .filter(|message| message.id != id)
                .cloned()
                .collect::<Vec<_>>();
            QueueTransition {
                queue: if kept.len() == queue.len() {
                    Cow::Borrowed(queue)
                } else {
                    Cow::Owned(kept)
                },
                run: None,
                submitted_queued: false,
            }
        }
    }
}

fn queued(intent: &RunIntent) -> QueuedMessage {
    QueuedMessage {
        id: intent.queue_id().to_owned(),
        intent: intent.clone(),
    }
}

#[cfg(test)]
mod tests {
    use openbot_contracts::command::ThreadRunAnchor;
    use openbot_contracts::ids::{BotId, RunId, ThreadId};
    use openbot_contracts::model_connections::RunModelSelection;

    use super::*;

    fn intent(id: &str, text: &str, revision: i64, skills: &[&str]) -> RunIntent {
        RunIntent {
            thread_id: Some(ThreadId::new("thread")),
            run_id: RunId::new(id),
            agent_id: BotId::new("agent"),
            anchor: ThreadRunAnchor::DirectBot,
            message: text.to_owned(),
            selected_skill_slugs: skills.iter().map(|skill| (*skill).to_owned()).collect(),
            model_selection: Some(RunModelSelection {
                connection_id: "01991389-7380-7000-8000-000000000001".into(),
                expected_revision: revision,
            }),
            model_selection_v2: None,
        }
    }

    fn park(queue: &[QueuedMessage], value: &RunIntent) -> Vec<QueuedMessage> {
        reduce_queue(
            queue,
            QueueAction::Submit {
                intent: value,
                busy: true,
            },
        )
        .queue
        .into_owned()
    }

    #[test]
    fn idle_send_goes_out_without_entering_the_queue() {
        let value = intent("one", "first", 1, &["review"]);
        let result = reduce_queue(
            &[],
            QueueAction::Submit {
                intent: &value,
                busy: false,
            },
        );
        assert_eq!(result.run.as_deref(), Some(&value));
        assert!(result.queue.is_empty());
        assert!(!result.submitted_queued);
    }

    #[test]
    fn settle_drains_exactly_one_fifo_item_without_merging_intent() {
        let first = intent("one", "first", 1, &["review"]);
        let second = intent("two", "second", 2, &["summarize"]);
        let mut queue = park(&[], &first);
        queue = park(&queue, &second);
        let result = reduce_queue(&queue, QueueAction::Settle);
        assert_eq!(result.run.as_deref(), Some(&first));
        assert_eq!(result.queue.as_ref(), [queued(&second)]);
        assert!(!result.submitted_queued);
    }

    #[test]
    fn idle_submit_after_prior_failure_clears_new_composer_and_preserves_fifo_identity() {
        let first_waiting = intent("old-one", "old first", 1, &["review"]);
        let second_waiting = intent("old-two", "old second", 2, &["summarize"]);
        let new = intent("new", "new draft", 3, &["review", "summarize"]);
        let mut queue = park(&[], &first_waiting);
        queue = park(&queue, &second_waiting);

        // The prior dispatched run failed definitely, leaving this waiting queue while idle.
        let submit = reduce_queue(
            &queue,
            QueueAction::Submit {
                intent: &new,
                busy: false,
            },
        );
        assert!(submit.submitted_queued);
        assert_eq!(submit.run.as_deref(), Some(&first_waiting));
        assert_eq!(
            submit.queue.as_ref(),
            [queued(&second_waiting), queued(&new)]
        );
        assert_eq!(submit.queue[1].intent.run_id, RunId::new("new"));
        assert_eq!(
            submit.queue[1].intent.selected_skill_slugs,
            vec!["review".to_owned(), "summarize".to_owned()]
        );
        assert_eq!(
            submit.queue[1]
                .intent
                .model_selection
                .as_ref()
                .map(|selection| selection.expected_revision),
            Some(3)
        );

        let after_first = reduce_queue(submit.queue.as_ref(), QueueAction::Settle);
        assert_eq!(after_first.run.as_deref(), Some(&second_waiting));
        assert_eq!(after_first.queue.as_ref(), [queued(&new)]);
        assert!(!after_first.submitted_queued);

        let after_second = reduce_queue(after_first.queue.as_ref(), QueueAction::Settle);
        assert_eq!(after_second.run.as_deref(), Some(&new));
        assert!(after_second.queue.is_empty());
        assert!(!after_second.submitted_queued);
    }

    #[test]
    fn menu_or_directory_changes_cannot_rebind_waiting_revision_or_run_id() {
        let original = intent("one", "first", 1, &[]);
        let mut changed = original.clone();
        changed.model_selection.as_mut().unwrap().expected_revision = 2;
        let queue = park(&[], &original);
        assert_ne!(queue[0].intent, changed);
        assert_eq!(queue[0].intent, original);
    }

    #[test]
    fn idle_submit_behind_waiting_work_runs_oldest_and_retains_new_item() {
        let first = intent("one", "first", 1, &[]);
        let second = intent("two", "second", 1, &[]);
        let queue = park(&[], &first);
        let result = reduce_queue(
            &queue,
            QueueAction::Submit {
                intent: &second,
                busy: false,
            },
        );
        assert_eq!(result.run.as_deref(), Some(&first));
        assert_eq!(result.queue.as_ref(), [queued(&second)]);
        assert!(result.submitted_queued);
    }

    #[test]
    fn remove_only_affects_the_named_unsent_item() {
        let first = intent("one", "same", 1, &[]);
        let second = intent("two", "same", 1, &[]);
        let mut queue = park(&[], &first);
        queue = park(&queue, &second);
        let result = reduce_queue(&queue, QueueAction::Remove { id: "one" });
        assert_eq!(result.queue.as_ref(), [queued(&second)]);
        assert!(result.run.is_none());
    }

    #[test]
    fn empty_settle_is_a_noop() {
        let result = reduce_queue(&[], QueueAction::Settle);
        assert!(result.queue.is_empty());
        assert!(result.run.is_none());
    }
}
