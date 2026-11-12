//! Direct-assistant work list: the Server's conversation directory and the work actions on it.
//!
//! Every value shown here comes from the Server's own closed DTOs. The browser remembers only
//! which conversation was opened most recently; the Server's list remains the only work identity.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) mod attention;
pub(crate) mod model;
pub(crate) mod pending;
mod remembered;
pub(crate) mod submit;
pub(crate) mod work;

use leptos::prelude::*;
use openbot_contracts::command::{BotThreadSummary, ThreadForegroundRunState, ThreadStatusFilter};
use openbot_contracts::ids::{BotId, ThreadId};

#[cfg(target_arch = "wasm32")]
use crate::api::{ApiError, complete_thread, list_bot_threads, set_thread_title};
use crate::i18n::{Locale, t, t_string, td_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Field, IconSize, IconView, Input, Menu, MenuAlign,
    MenuContent, MenuItem, MenuTrigger, Notice, NoticePresentation, NoticeTone, SidebarRow,
};

use self::attention::AttentionIndex;
pub(crate) use self::work::{BotWork, use_bot_work};

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

/// The work list of the assistant the `/bot` canvas shows, beneath its sidebar row.
#[component]
pub fn BotWorkList(
    /// The assistant whose conversations are listed.
    agent_id: BotId,
) -> impl IntoView {
    let i18n = use_i18n();
    let work = use_bot_work();
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
    let selected = Signal::derive(move || work.thread.get().map(|thread| thread.id));

    // A newer read reruns this Effect, which cancels the previous task: a late page never lands.
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        work.changes.track();
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
    let _ = agent_id;
    // The top bar names the open conversation as this list reports it.
    Effect::new(move |_| {
        let open = selected.get();
        let title = rows.with(|rows| {
            rows.iter()
                .find(|row| Some(&row.thread_id) == open.as_ref())
                .map(|row| title_text(i18n.get_locale(), row.title.as_deref()))
        });
        if title.is_some() {
            work.thread_title.set(title);
        }
    });

    let read_again = UnsyncCallback::new(move |_| {
        reread.update(|value| *value = value.saturating_add(1));
    });
    let load_more = move |_| {
        continue_after.set(next_cursor.get_untracked());
        reread.update(|value| *value = value.saturating_add(1));
    };
    let toggle_archived = move |_| {
        status.update(|status| {
            *status = match status {
                ThreadStatusFilter::Active => ThreadStatusFilter::Archived,
                ThreadStatusFilter::Archived => ThreadStatusFilter::Active,
            }
        });
    };

    view! {
        <ul
            class="ob-sidebar-list ob-sidebar-work"
            aria-label=move || t_string!(i18n, bot_work.list_label).to_owned()
        >
            // Every visible fact is part of the key, so a renamed, completed or newly busy
            // conversation is shown again rather than keeping its earlier copy.
            <For
                each=move || rows.get()
                key=|row| format!("{row:?}")
                children=move |row| view! {
                    <BotWorkRow row selected attention on_changed=read_again />
                }
            />
        </ul>
        <Show when=move || loading.get()>
            <p class="ob-sidebar-loading" role="status">{move || t!(i18n, common.loading)}</p>
        </Show>
        <Show when=move || failed.get()>
            <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                <span>{move || t!(i18n, bot_work.list_error)}</span>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| read_again.run(())>
                    {move || t!(i18n, common.retry)}
                </Button>
            </Notice>
        </Show>
        <Show when=move || !loading.get() && !failed.get() && rows.get().is_empty()>
            <p class="ob-sidebar-search-empty">{move || t!(i18n, bot_work.list_empty)}</p>
        </Show>
        <div class="ob-sidebar-work-footer">
            <Show when=move || next_cursor.get().is_some()>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=load_more>
                    {move || t!(i18n, bot_work.load_more)}
                </Button>
            </Show>
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=toggle_archived>
                {move || match status.get() {
                    ThreadStatusFilter::Active => t_string!(i18n, bot_work.show_archived),
                    ThreadStatusFilter::Archived => t_string!(i18n, bot_work.show_active),
                }}
            </Button>
        </div>
    }
}

/// One visible conversation row with its rename and complete actions in the row menu.
#[component]
fn BotWorkRow(
    row: BotThreadSummary,
    selected: Signal<Option<ThreadId>>,
    attention: RwSignal<AttentionIndex>,
    on_changed: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let work = use_bot_work();
    let thread = StoredValue::new(row.thread_id.clone());
    let notice = RwSignal::new(None::<WorkNotice>);
    let renaming = RwSignal::new(false);
    let menu_open = RwSignal::new(false);
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
    let foreground_run = row.foreground.map(|foreground| foreground.run_id);
    let attention_count =
        Signal::derive(move || attention.with(|index| index.count_for(foreground_run.as_ref())));
    let row_title = row.title;
    let pending_inputs = row.pending_inputs;
    let archived = row.status == ThreadStatusFilter::Archived;
    let id_token = row.thread_id.as_str().to_owned();
    let control_id = format!("bot-work-title-{id_token}");
    let menu_id = format!("bot-work-menu-{id_token}");

    view! {
        <SidebarRow
            on_activate=UnsyncCallback::new(move |_| work.open(thread.get_value()))
            label=move || title_text(i18n.get_locale(), row_title.as_deref())
            secondary=Signal::derive(move || {
                let locale = i18n.get_locale();
                let state = foreground.map_or_else(
                    || td_string!(locale, bot_work.state_idle).to_owned(),
                    |state| foreground_label(locale, state),
                );
                if pending_inputs > 0 {
                    format!("{state} · {}", td_string!(locale, bot_work.pending_count, count = pending_inputs))
                } else {
                    state
                }
            })
            time=Some(row.updated_at)
            badge=Signal::derive(move || {
                let count = attention_count.get();
                (count != 0).then(|| t_string!(i18n, bot_work.attention_count, count = count).to_string())
            })
            current=Signal::derive(move || thread.with_value(|thread| selected.get().as_ref() == Some(thread)))
            actions=move || view! {
                <Menu id=menu_id.as_str() open=menu_open align=MenuAlign::End>
                    <MenuTrigger disabled=busy>
                        <IconView icon=Icon::Ellipsis size=IconSize::Inline />
                        <span class="ob-visually-hidden">{move || t!(i18n, common.more_actions)}</span>
                    </MenuTrigger>
                    <MenuContent>
                        <MenuItem disabled=busy on_select=move |_| renaming.set(true)>
                            {move || t!(i18n, bot_work.rename)}
                        </MenuItem>
                        // An archived conversation is already complete.
                        {(!archived).then(|| view! {
                            <MenuItem disabled=busy on_select=complete>
                                {move || t!(i18n, bot_work.complete)}
                            </MenuItem>
                        })}
                    </MenuContent>
                </Menu>
            }
            below=move || {
                let control_id = control_id.clone();
                view! {
                <Show when=move || notice.get().is_some()>
                    <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                        {move || notice.get().map(|notice| work_notice_text(i18n.get_locale(), notice))}
                    </Notice>
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
                }
            }
        />
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
