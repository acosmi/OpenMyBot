//! Direct-assistant chat route. The URL names the assistant (`?agent=`); the shell's `BotWork`
//! state resolves the conversation, and the sidebar lists the assistant's work beneath its row.

#![cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, unused_variables)
)]

use leptos::prelude::*;
use leptos_router::hooks::use_query_map;

#[cfg(target_arch = "wasm32")]
use crate::api::load_agent;
use crate::features::agents::{AgentDirectory, use_agent_directory};
use crate::features::bot_threads::{BotWork, use_bot_work};
use crate::features::channels::conversation::DirectBotConversation;
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{Button, ButtonSize, ButtonVariant, Notice, NoticeTone};
use crate::shell::layout::set_shell_title;

/// Authenticated direct-assistant chat with URL-owned assistant selection.
#[component]
pub fn BotChatPage() -> impl IntoView {
    let i18n = use_i18n();
    let query = use_query_map();
    let directory = use_agent_directory();
    let work = use_bot_work();
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);

    install_bot_agent_resolver(query, directory, work, loading, load_error);
    on_cleanup(move || {
        let _ = work.agent.try_set(None);
    });
    set_shell_title(move || {
        let mut segments = vec![work.agent.with(|agent| {
            agent.as_ref().map_or_else(
                || t_string!(i18n, shell.nav_agents).to_owned(),
                |agent| agent.name.clone(),
            )
        })];
        segments.extend(work.thread_title.get());
        segments
    });

    let retry = move |_| directory.refresh();
    let retry_thread = move |_| work.retry();

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-bot-chat">
            <Show when=move || loading.get() || (work.agent.with(Option::is_some) && work.resolving.get())>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, bot_chat.agent_load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || !loading.get() && !load_error.get() && work.agent.with(Option::is_none)>
                <p class="ob-page-empty">{move || t!(i18n, bot_chat.no_agents)}</p>
            </Show>
            <Show when=move || work.history_unavailable.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, bot_chat.history_unavailable)}</Notice>
            </Show>
            <Show when=move || work.thread_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, bot_chat.thread_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry_thread>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || work.new_error.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, bot_chat.new_chat_error)}</Notice>
            </Show>
            <For
                each=move || work.thread.get().into_iter()
                key=|thread| thread.id.clone()
                children=move |thread| view! {
                    {work.agent.get_untracked().map(|agent| view! {
                        <DirectBotConversation
                            thread=thread.id.clone()
                            agent
                            fresh=thread.fresh
                            on_work_changed=UnsyncCallback::new(move |_| work.work_changed())
                        />
                    })}
                }
            />
            </div>
        </PageShell>
    }
}

/// Name the shown assistant from the URL: the listed profile, an unlisted one read on its own,
/// or the directory's first row when the URL names none.
fn install_bot_agent_resolver(
    query: Memo<leptos_router::params::ParamsMap>,
    directory: AgentDirectory,
    work: BotWork,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let requested = query.get().get("agent");
        let directory_loading = directory.loading.get();
        loading.set(true);
        load_error.set(false);
        if directory_loading {
            return;
        }
        let listed = directory
            .agents
            .with_untracked(|agents| match requested.as_deref() {
                Some(requested) => agents
                    .iter()
                    .find(|agent| agent.id.as_str() == requested)
                    .cloned(),
                None => agents.first().cloned(),
            });
        match (listed, requested) {
            (Some(profile), _) => {
                work.agent.set(Some(profile));
                loading.set(false);
            }
            (None, None) => {
                work.agent.set(None);
                load_error.set(directory.failed.get_untracked());
                loading.set(false);
            }
            (None, Some(requested)) => {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    match load_agent(&requested).await {
                        Ok(profile) => work.agent.set(Some(profile)),
                        Err(_) => {
                            work.agent.set(None);
                            load_error.set(true);
                        }
                    }
                    loading.set(false);
                });
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (query, directory, work, loading, load_error);
}
