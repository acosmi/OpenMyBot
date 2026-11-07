//! The conversation's durable pending and held inputs.
//!
//! Every row here comes from `GET /api/threads/{thread_id}/inputs`. The panel never keeps its own
//! copy of an input's state: the owner reads the list back from the Server after every reply,
//! because a withdrawn or dispatched input leaves the list and a held input may have been
//! dispatched by the dispatcher in the meantime.

use leptos::prelude::*;
use openbot_contracts::command::{PendingInput, PendingInputHeldReason, PendingInputState};
use openbot_contracts::ids::{RunId, ThreadId};

use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::{release_pending_input, withdraw_pending_input};
use crate::i18n::{Locale, t, t_string, td_string, use_i18n};
use crate::primitives::{Badge, BadgeTone, Button, ButtonSize, ButtonVariant};

/// The two actions a retained input offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingAction {
    /// `WithdrawPendingInput`: any input that has not become a Run.
    Withdraw,
    /// `ReleasePendingInput`: a held input goes back to the tail of the queue.
    Release,
}

/// What the last withdraw or release left for the user to read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingNotice {
    /// The Server withdrew the input with this message; the list no longer shows it.
    Withdrawn(String),
    /// The input already became a Run, so only Stop can still affect it.
    AlreadyRun,
    /// The input was no longer held when the release arrived.
    StateChanged,
    /// The reply did not confirm the action.
    Failed,
}

/// The pending and held inputs of one conversation.
///
/// The panel presents the rows the owner read from the Server. It never decides an input's
/// state on its own: every reply, including a refusal, asks the owner to read the list again.
#[component]
pub fn PendingInputsPanel(
    /// The conversation whose retained inputs are shown.
    thread: ThreadId,
    /// The assistant every retained input of this conversation belongs to.
    assistant: String,
    /// The retained inputs the owner read from the Server.
    items: Signal<Vec<PendingInput>>,
    /// Whether the owner is reading the list.
    loading: Signal<bool>,
    /// Whether the last read failed.
    failed: Signal<bool>,
    /// Ask the owner to read the list again.
    on_changed: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let notice = RwSignal::new(None::<PendingNotice>);
    let busy = RwSignal::new(false);
    let act = UnsyncCallback::new(move |(action, input): (PendingAction, PendingInput)| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        notice.set(None);
        #[cfg(target_arch = "wasm32")]
        {
            let thread = thread.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let result = match action {
                    PendingAction::Withdraw => withdraw_pending_input(&thread, &input.run_id).await,
                    PendingAction::Release => release_pending_input(&thread, &input.run_id).await,
                };
                busy.set(false);
                notice.set(action_notice(action, result, input.message));
                on_changed.run(());
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&thread, action, input);
            busy.set(false);
            notice.set(Some(PendingNotice::Failed));
        }
    });

    view! {
        <section class="ob-bot-pending" aria-label=move || t_string!(i18n, bot_work.pending_label).to_owned()>
            <header class="ob-bot-pending-header">
                <h3>{move || t!(i18n, bot_work.pending_label)}</h3>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=on_changed>
                    {move || t!(i18n, common.refresh)}
                </Button>
            </header>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || failed.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, bot_work.pending_load_error)}</p>
            </Show>
            <Show when=move || !loading.get() && !failed.get() && items.get().is_empty()>
                <p class="ob-page-empty">{move || t!(i18n, bot_work.pending_empty)}</p>
            </Show>
            <Show when=move || notice.get().is_some()>
                <p class="ob-alert" role="status">
                    {move || notice.get().map(|notice| pending_notice_text(i18n.get_locale(), &notice))}
                </p>
            </Show>
            <ul class="ob-bot-pending-rows">
                <For
                    each=move || {
                        let items = items.get();
                        items
                            .iter()
                            .map(|item| (pending_position(&items, &item.run_id), item.clone()))
                            .collect::<Vec<_>>()
                    }
                    // The row shows the input's state, queue position and last code, so it is
                    // rebuilt whenever one of them changes rather than keeping a stale copy.
                    key=|(position, item)| format!(
                        "{}|{:?}|{position:?}|{:?}",
                        item.run_id.as_str(),
                        item.held_reason,
                        item.last_error
                    )
                    children=move |(position, item)| {
                        let held = item.held_reason.is_some();
                        let status_input = item.clone();
                        let withdraw_input = item.clone();
                        let release_input = item.clone();
                        let connection = item.model_selection.connection_id().to_owned();
                        let revision = item.model_selection.expected_connection_revision();
                        let skills = item
                            .selected_skill_slugs
                            .iter()
                            .map(|slug| format!("/{slug}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let submitted_at = item
                            .submitted_at
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default();
                        let submitted_label = submitted_at.clone();
                        view! {
                            <li class="ob-bot-pending-row">
                                <div class="ob-bot-pending-head">
                                    <Badge tone=if held { BadgeTone::Caution } else { BadgeTone::Info }>
                                        {move || input_status_text(i18n.get_locale(), &status_input)}
                                    </Badge>
                                </div>
                                <p class="ob-bot-pending-message">{item.message}</p>
                                <p class="ob-bot-pending-meta">
                                    <span class="ob-bot-pending-assistant">{assistant.clone()}</span>
                                    <span>
                                        {move || t_string!(i18n, bot_work.pending_model_snapshot, connection = connection.as_str(), revision = revision).to_owned()}
                                    </span>
                                    {(!skills.is_empty()).then(|| view! {
                                        <span class="ob-bot-pending-skills">{skills}</span>
                                    })}
                                    {position.map(|position| view! {
                                        <span class="ob-bot-pending-position">
                                            {move || t_string!(i18n, bot_work.pending_position, position = position).to_owned()}
                                        </span>
                                    })}
                                    <time datetime=submitted_at>{submitted_label}</time>
                                </p>
                                <div class="ob-bot-pending-actions">
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Small
                                        disabled=busy
                                        on_activate=move |_| act.run((PendingAction::Withdraw, withdraw_input.clone()))
                                    >
                                        {move || t!(i18n, bot_work.pending_withdraw)}
                                    </Button>
                                    {held.then(|| view! {
                                        <Button
                                            variant=ButtonVariant::Ghost
                                            size=ButtonSize::Small
                                            disabled=busy
                                            on_activate=move |_| act.run((PendingAction::Release, release_input.clone()))
                                        >
                                            {move || t!(i18n, bot_work.pending_release)}
                                        </Button>
                                    })}
                                </div>
                            </li>
                        }
                    }
                />
            </ul>
        </section>
    }
}

/// The notice one withdraw or release reply leaves.
///
/// A withdrawn input leaves the list, so its own notice names it. A release needs none: the row
/// reappears at the tail with its new position. The Server's 409 means "already a Run" only for a
/// withdraw; for a release it means the input is no longer held.
fn action_notice(
    action: PendingAction,
    result: Result<(), ApiError>,
    message: String,
) -> Option<PendingNotice> {
    match (action, result) {
        (PendingAction::Withdraw, Ok(())) => Some(PendingNotice::Withdrawn(message)),
        (PendingAction::Release, Ok(())) => None,
        (PendingAction::Withdraw, Err(ApiError::PendingInputState)) => {
            Some(PendingNotice::AlreadyRun)
        }
        (PendingAction::Release, Err(ApiError::PendingInputState)) => {
            Some(PendingNotice::StateChanged)
        }
        (_, Err(_)) => Some(PendingNotice::Failed),
    }
}

/// The one-based queue position of a pending input.
///
/// The Server lists the inputs by `queued_at`. Held inputs are not queued, so they neither have
/// a position nor advance one; a released input is queued again at the tail.
pub(crate) fn pending_position(items: &[PendingInput], run_id: &RunId) -> Option<u32> {
    items
        .iter()
        .filter(|item| item.state == PendingInputState::Pending)
        .position(|item| &item.run_id == run_id)
        .map(|index| index as u32 + 1)
}

/// The status line of one retained input, with its last stable code when the Server kept one.
///
/// `held_reason` is present exactly for a held input, so it alone decides between the two
/// listed states.
fn input_status_text(locale: Locale, input: &PendingInput) -> String {
    let status = match input.held_reason {
        None => td_string!(locale, bot_work.pending_accepted).to_owned(),
        Some(reason) => {
            let reason = match reason {
                PendingInputHeldReason::StoppedByUser => {
                    td_string!(locale, bot_work.held_stopped_by_user)
                }
                PendingInputHeldReason::AuthorityStale => {
                    td_string!(locale, bot_work.held_authority_stale)
                }
                PendingInputHeldReason::AuthorityUnavailable => {
                    td_string!(locale, bot_work.held_authority_unavailable)
                }
                PendingInputHeldReason::DispatchRejected => {
                    td_string!(locale, bot_work.held_dispatch_rejected)
                }
            };
            td_string!(locale, bot_work.pending_held, reason = reason).to_owned()
        }
    };
    match &input.last_error {
        Some(code) => td_string!(
            locale,
            bot_work.status_with_code,
            status = status,
            code = code
        )
        .to_owned(),
        None => status,
    }
}

/// Closed text of one pending-input notice.
fn pending_notice_text(locale: Locale, notice: &PendingNotice) -> String {
    match notice {
        PendingNotice::Withdrawn(message) => {
            td_string!(locale, bot_work.withdrawn, message = message).to_owned()
        }
        PendingNotice::AlreadyRun => td_string!(locale, bot_work.already_run).to_owned(),
        PendingNotice::StateChanged => td_string!(locale, bot_work.state_changed).to_owned(),
        PendingNotice::Failed => td_string!(locale, bot_work.action_failed).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::versioned_model_selection::{
        ModelSelectionIntentSource, RunModelSelectionV2,
    };
    use time::OffsetDateTime;

    fn input(
        run: &str,
        state: PendingInputState,
        held_reason: Option<PendingInputHeldReason>,
    ) -> PendingInput {
        PendingInput {
            run_id: RunId::new(run),
            state,
            held_reason,
            last_error: None,
            submitted_at: OffsetDateTime::UNIX_EPOCH,
            queued_at: OffsetDateTime::UNIX_EPOCH,
            message: "text".to_owned(),
            selected_skill_slugs: Vec::new(),
            model_selection: RunModelSelectionV2::new(
                ModelSelectionIntentSource::Custom,
                "01991389-7380-7000-8000-000000000004".to_owned(),
                3,
                "custom:01991389-7380-7000-8000-000000000004".to_owned(),
                7,
            )
            .expect("catalog selection assembles"),
            artifact_refs: Vec::new(),
        }
    }

    #[test]
    fn a_released_input_shows_its_new_position_at_the_tail() {
        let pending = |run| input(run, PendingInputState::Pending, None);
        let held = input(
            "b",
            PendingInputState::Held,
            Some(PendingInputHeldReason::StoppedByUser),
        );
        let before = [pending("a"), held, pending("c")];
        assert_eq!(pending_position(&before, &RunId::new("a")), Some(1));
        // A held input neither has a position nor advances the ones behind it.
        assert_eq!(pending_position(&before, &RunId::new("b")), None);
        assert_eq!(pending_position(&before, &RunId::new("c")), Some(2));
        // After the release the Server lists it again by its new `queued_at`, at the tail.
        let after = [pending("a"), pending("c"), pending("b")];
        assert_eq!(pending_position(&after, &RunId::new("b")), Some(3));
    }

    #[test]
    fn each_held_reason_has_its_own_text_and_a_rejection_keeps_its_stable_code() {
        let held = |reason| {
            input_status_text(
                Locale::en,
                &input("a", PendingInputState::Held, Some(reason)),
            )
        };
        assert_eq!(
            input_status_text(Locale::en, &input("a", PendingInputState::Pending, None)),
            "Accepted, waiting to be handled"
        );
        assert_eq!(
            held(PendingInputHeldReason::StoppedByUser),
            "Paused: you stopped this work"
        );
        assert_eq!(
            held(PendingInputHeldReason::AuthorityStale),
            "Paused: needs confirmation again (the sign-in state changed)"
        );
        assert_eq!(
            held(PendingInputHeldReason::AuthorityUnavailable),
            "Paused: the assistant or materials are currently unavailable"
        );
        assert_eq!(
            held(PendingInputHeldReason::DispatchRejected),
            "Paused: rejected"
        );
        let mut rejected = input(
            "a",
            PendingInputState::Held,
            Some(PendingInputHeldReason::DispatchRejected),
        );
        rejected.last_error = Some("policy_refused".to_owned());
        assert_eq!(
            input_status_text(Locale::en, &rejected),
            "Paused: rejected (policy_refused)"
        );
    }

    #[test]
    fn withdrawing_a_dispatched_input_says_to_use_stop_and_a_late_release_says_the_state_changed() {
        let notice = |action, result| {
            action_notice(action, result, "hello".to_owned())
                .map(|notice| pending_notice_text(Locale::en, &notice))
        };
        assert_eq!(
            notice(PendingAction::Withdraw, Err(ApiError::PendingInputState)).as_deref(),
            Some("This input already became a Run. Use Stop instead.")
        );
        assert_eq!(
            notice(PendingAction::Release, Err(ApiError::PendingInputState)).as_deref(),
            Some("This input's state changed; the list was read again.")
        );
        assert_eq!(
            notice(PendingAction::Withdraw, Ok(())).as_deref(),
            Some("Withdrawn: hello")
        );
        assert_eq!(notice(PendingAction::Release, Ok(())), None);
        assert_eq!(
            notice(PendingAction::Withdraw, Err(ApiError::Network)),
            notice(PendingAction::Release, Err(ApiError::Forbidden))
        );
    }
}
