//! Direct-Bot work list: the Server's conversation directory and the work actions on it.
//!
//! Every value shown here comes from the Server's own closed DTOs. The browser remembers only
//! which conversation was opened most recently; the Server's list remains the only work identity.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) mod attention;
pub(crate) mod model;
pub(crate) mod pending;
pub(crate) mod submit;

use leptos::prelude::*;
use openbot_contracts::command::{BotThreadSummary, ThreadForegroundRunState, ThreadStatusFilter};
use openbot_contracts::ids::{BotId, ThreadId};

#[cfg(target_arch = "wasm32")]
use crate::api::{ApiError, complete_thread, list_bot_threads, set_thread_title};
use crate::i18n::{Locale, t, t_string, td_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Badge, BadgeTone, Button, ButtonSize, ButtonVariant, Field, IconSize, IconView, Input,
};

use self::attention::AttentionIndex;

/// Why a work-list action did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkNotice {
    /// The reply did not confirm the action.
    Failed,
    /// The conversation still holds foreground work or retained inputs.
    NotIdle {
        /// Foreground projection the Server reported.
        foreground: Option<ThreadForegroundRunState>,
        /// Pending and held input count the Server reported.
        pending_inputs: u32,
    },
}

/// The work list of one assistant.
#[component]
pub fn BotWorkList(
    /// The assistant whose conversations are listed.
    agent_id: BotId,
    /// The conversation the canvas currently shows.
    selected: Signal<Option<ThreadId>>,
    /// Open the conversation the user picked in the list.
    on_select: UnsyncCallback<ThreadId>,
    /// Changes whenever the open conversation changed its work; the first page is read again.
    #[prop(into)]
    refresh: Signal<u64>,
) -> impl IntoView {
    let i18n = use_i18n();
    let status = RwSignal::new(ThreadStatusFilter::Active);
    let rows = RwSignal::new(Vec::<BotThreadSummary>::new());
    let next_cursor = RwSignal::new(None::<String>);
    // Set only by "load more": the next read continues after this cursor. Every other read
    // starts again from the first page.
    let continue_after = RwSignal::new(None::<String>);
    let reread = RwSignal::new(0_u64);
    let loading = RwSignal::new(true);
    let failed = RwSignal::new(false);
    let attention = RwSignal::new(AttentionIndex::default());

    // A newer read reruns this Effect, which cancels the previous task: a late page never lands.
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        refresh.track();
        reread.track();
        let status = status.get();
        let after = continue_after.get_untracked();
        continue_after.set(None);
        let agent_id = agent_id.clone();
        loading.set(true);
        failed.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let page = list_bot_threads(&agent_id, status, after.as_deref()).await;
            let index = attention::read_attention_index().await;
            match page {
                Ok(page) if after.is_some() => {
                    // A conversation updated between two pages moves up; it is listed once.
                    rows.update(|rows| {
                        for row in page.threads {
                            if !rows.iter().any(|known| known.thread_id == row.thread_id) {
                                rows.push(row);
                            }
                        }
                    });
                    next_cursor.set(page.next_cursor);
                    attention.set(index);
                }
                Ok(page) => {
                    rows.set(page.threads);
                    next_cursor.set(page.next_cursor);
                    attention.set(index);
                }
                Err(_) => failed.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (agent_id, refresh);

    let read_again = UnsyncCallback::new(move |_| {
        reread.update(|value| *value = value.saturating_add(1));
    });
    let load_more = UnsyncCallback::new(move |_| {
        continue_after.set(next_cursor.get_untracked());
        reread.update(|value| *value = value.saturating_add(1));
    });

    view! {
        <section
            class="ob-bot-work"
            aria-label=move || t_string!(i18n, bot_work.list_label).to_owned()
        >
            <header class="ob-bot-work-header">
                <div
                    class="ob-bot-work-filters"
                    role="group"
                    aria-label=move || t_string!(i18n, bot_work.filter_label).to_owned()
                >
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        selected=Signal::derive(move || status.get() == ThreadStatusFilter::Active)
                        on_activate=move |_| status.set(ThreadStatusFilter::Active)
                    >
                        {move || t!(i18n, bot_work.filter_active)}
                    </Button>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        selected=Signal::derive(move || status.get() == ThreadStatusFilter::Archived)
                        on_activate=move |_| status.set(ThreadStatusFilter::Archived)
                    >
                        {move || t!(i18n, bot_work.filter_archived)}
                    </Button>
                </div>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=read_again>
                    <IconView icon=Icon::RefreshCw size=IconSize::Inline />
                    <span>{move || t!(i18n, common.refresh)}</span>
                </Button>
            </header>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || failed.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, bot_work.list_error)}</p>
            </Show>
            <Show when=move || !loading.get() && !failed.get() && rows.get().is_empty()>
                <p class="ob-page-empty">{move || t!(i18n, bot_work.list_empty)}</p>
            </Show>
            <ul class="ob-bot-work-rows">
                // Every visible fact is part of the key, so a renamed, completed or newly busy
                // conversation is shown again rather than keeping its earlier copy.
                <For
                    each=move || rows.get()
                    key=|row| format!("{row:?}")
                    children=move |row| view! {
                        <BotWorkRow row selected attention on_select on_changed=read_again />
                    }
                />
            </ul>
            <Show when=move || next_cursor.get().is_some()>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=load_more>
                    {move || t!(i18n, bot_work.load_more)}
                </Button>
            </Show>
        </section>
    }
}

/// One visible conversation row.
#[component]
fn BotWorkRow(
    row: BotThreadSummary,
    selected: Signal<Option<ThreadId>>,
    attention: RwSignal<AttentionIndex>,
    on_select: UnsyncCallback<ThreadId>,
    on_changed: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let thread = StoredValue::new(row.thread_id.clone());
    let notice = RwSignal::new(None::<WorkNotice>);
    let renaming = RwSignal::new(false);
    let title = RwSignal::new(row.title.clone().unwrap_or_default());
    let busy = RwSignal::new(false);

    let complete = UnsyncCallback::new(move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        notice.set(None);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = complete_thread(&thread.get_value()).await;
            busy.set(false);
            match result {
                Ok(()) => on_changed.run(()),
                Err(ApiError::ThreadNotIdle {
                    foreground,
                    pending_inputs,
                }) => notice.set(Some(WorkNotice::NotIdle {
                    foreground,
                    pending_inputs,
                })),
                Err(_) => notice.set(Some(WorkNotice::Failed)),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = on_changed;
            busy.set(false);
            notice.set(Some(WorkNotice::Failed));
        }
    });
    let rename = UnsyncCallback::new(move |_| {
        let Some(candidate) = rename_title(&title.get_untracked()).map(str::to_owned) else {
            return;
        };
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        notice.set(None);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = set_thread_title(&thread.get_value(), &candidate).await;
            busy.set(false);
            match result {
                Ok(()) => {
                    renaming.set(false);
                    on_changed.run(());
                }
                Err(_) => notice.set(Some(WorkNotice::Failed)),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = candidate;
            busy.set(false);
            notice.set(Some(WorkNotice::Failed));
        }
    });

    let foreground = row.foreground.as_ref().map(|foreground| foreground.state);
    let state_tone = match foreground {
        None => BadgeTone::Neutral,
        Some(ThreadForegroundRunState::Queued | ThreadForegroundRunState::Running) => {
            BadgeTone::Info
        }
        Some(ThreadForegroundRunState::Cancelling) => BadgeTone::Caution,
        Some(ThreadForegroundRunState::ReconciliationRequired) => BadgeTone::Danger,
    };
    let foreground_run = row.foreground.map(|foreground| foreground.run_id);
    let attention_count =
        Signal::derive(move || attention.with(|index| index.count_for(foreground_run.as_ref())));
    let row_title = row.title;
    let pending_inputs = row.pending_inputs;
    let updated_at = row
        .updated_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let updated_label = updated_at.clone();
    let control_id = format!("bot-work-title-{}", row.thread_id.as_str());

    view! {
        <li class="ob-bot-work-row">
            <button
                type="button"
                class="ob-bot-work-open"
                aria-current=move || {
                    thread.with_value(|thread| {
                        (selected.get().as_ref() == Some(thread)).then_some("page")
                    })
                }
                on:click=move |_| on_select.run(thread.get_value())
            >
                <span class="ob-bot-work-title">
                    {move || title_text(i18n.get_locale(), row_title.as_deref())}
                </span>
                <span class="ob-bot-work-meta">
                    <Badge tone=state_tone>
                        {move || foreground.map_or_else(
                            || t_string!(i18n, bot_work.state_idle).to_owned(),
                            |state| foreground_label(i18n.get_locale(), state),
                        )}
                    </Badge>
                    {(pending_inputs > 0).then(|| view! {
                        <span class="ob-bot-work-pending">
                            {move || t_string!(i18n, bot_work.pending_count, count = pending_inputs).to_owned()}
                        </span>
                    })}
                    <Show when=move || attention_count.get() != 0>
                        <Badge tone=BadgeTone::Caution>
                            {move || t_string!(i18n, bot_work.attention_count, count = attention_count.get()).to_owned()}
                        </Badge>
                    </Show>
                    <time class="ob-bot-work-updated" datetime=updated_at>{updated_label}</time>
                </span>
            </button>
            <div class="ob-bot-work-actions">
                <Button
                    variant=ButtonVariant::Ghost
                    size=ButtonSize::Small
                    disabled=busy
                    on_activate=move |_| renaming.set(true)
                >
                    {move || t!(i18n, bot_work.rename)}
                </Button>
                // An archived conversation is already complete.
                {(row.status == ThreadStatusFilter::Active).then(|| view! {
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        disabled=busy
                        on_activate=complete
                    >
                        {move || t!(i18n, bot_work.complete)}
                    </Button>
                })}
            </div>
            <Show when=move || notice.get().is_some()>
                <p class="ob-alert" role="alert">
                    {move || notice.get().map(|notice| work_notice_text(i18n.get_locale(), notice))}
                </p>
            </Show>
            <Show when=move || renaming.get()>
                <div class="ob-bot-work-rename">
                    <Field
                        control_id=control_id.clone()
                        label=move || t_string!(i18n, bot_work.rename).to_owned()
                    >
                        <Input
                            value=title
                            placeholder=move || t_string!(i18n, bot_work.title_placeholder).to_owned()
                            on_submit=rename
                        />
                    </Field>
                    <div class="ob-bot-work-rename-actions">
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Small
                            disabled=busy
                            on_activate=rename
                        >
                            {move || t!(i18n, common.save)}
                        </Button>
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Small
                            on_activate=move |_| renaming.set(false)
                        >
                            {move || t!(i18n, common.cancel)}
                        </Button>
                    </div>
                </div>
            </Show>
        </li>
    }
}

/// The visible title of a conversation; one that was never renamed has the default title.
fn title_text(locale: Locale, title: Option<&str>) -> String {
    title.map_or_else(
        || td_string!(locale, bot_work.default_title).to_owned(),
        str::to_owned,
    )
}

/// The title a rename sends: the Server trims and checks it again, so the page only refuses to
/// send a blank one.
fn rename_title(input: &str) -> Option<&str> {
    let title = input.trim();
    (!title.is_empty()).then_some(title)
}

/// §7.5 label of one foreground state.
fn foreground_label(locale: Locale, state: ThreadForegroundRunState) -> String {
    match state {
        ThreadForegroundRunState::Queued => td_string!(locale, bot_work.state_queued),
        ThreadForegroundRunState::Running => td_string!(locale, bot_work.state_running),
        ThreadForegroundRunState::Cancelling => td_string!(locale, bot_work.state_cancelling),
        ThreadForegroundRunState::ReconciliationRequired => {
            td_string!(locale, bot_work.state_reconciliation)
        }
    }
    .to_owned()
}

/// Closed text of one work-list notice. A refused completion names exactly what the Server
/// reported: the foreground state when there is one, and the retained input count.
fn work_notice_text(locale: Locale, notice: WorkNotice) -> String {
    match notice {
        WorkNotice::NotIdle {
            foreground: Some(state),
            pending_inputs,
        } => td_string!(
            locale,
            bot_work.not_idle,
            state = foreground_label(locale, state),
            count = pending_inputs
        )
        .to_owned(),
        WorkNotice::NotIdle {
            foreground: None,
            pending_inputs,
        } => td_string!(locale, bot_work.not_idle_pending, count = pending_inputs).to_owned(),
        WorkNotice::Failed => td_string!(locale, bot_work.action_failed).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untitled_conversation_shows_the_default_title_and_a_blank_rename_sends_nothing() {
        assert_eq!(title_text(Locale::en, None), "Untitled conversation");
        assert_eq!(title_text(Locale::en, Some("Weekly")), "Weekly");
        assert_eq!(rename_title(" \t "), None);
        assert_eq!(rename_title("  Weekly "), Some("Weekly"));
    }

    #[test]
    fn foreground_states_use_the_closed_status_vocabulary() {
        let label = |state| foreground_label(Locale::en, state);
        assert_eq!(label(ThreadForegroundRunState::Queued), "Accepted");
        assert_eq!(label(ThreadForegroundRunState::Running), "Running");
        assert_eq!(label(ThreadForegroundRunState::Cancelling), "Cancelling");
        assert_eq!(
            label(ThreadForegroundRunState::ReconciliationRequired),
            "Needs reconciliation"
        );
    }

    #[test]
    fn a_refused_completion_shows_the_reported_foreground_and_count_and_invents_neither() {
        assert_eq!(
            work_notice_text(
                Locale::en,
                WorkNotice::NotIdle {
                    foreground: Some(ThreadForegroundRunState::Running),
                    pending_inputs: 2,
                }
            ),
            "This conversation still has a foreground run (Running) and waiting inputs (2), \
             so it cannot be completed yet."
        );
        // Without a foreground the text names no state at all, never an idle one.
        let without_foreground = work_notice_text(
            Locale::en,
            WorkNotice::NotIdle {
                foreground: None,
                pending_inputs: 1,
            },
        );
        assert_eq!(
            without_foreground,
            "This conversation still has unfinished work (waiting inputs: 1), \
             so it cannot be completed yet."
        );
        assert!(!without_foreground.contains("Idle"));
    }
}
