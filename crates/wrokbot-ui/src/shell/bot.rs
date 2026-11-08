//! Direct-Bot chat route with per-Agent remembered native thread identity.

#![cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, unused_variables)
)]

mod bot_thread;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::ids::{BotId, ThreadId};

#[cfg(target_arch = "wasm32")]
use self::bot_thread::{
    RememberedThreadDecision, bot_thread_key, plausible_remembered_thread, remembered_entry,
    thread_to_use,
};
use crate::api::bot_chat_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{list_agents, load_agent, load_thread_status, mint_thread_id};
use crate::features::bot_threads::BotWorkList;
use crate::features::channels::RecipientField;
use crate::features::channels::conversation::DirectBotConversation;
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonSize, ButtonVariant, IconSize, IconView};

/// Authenticated direct-Bot chat with URL-owned Agent selection.
#[component]
pub fn BotChatPage() -> impl IntoView {
    let i18n = use_i18n();
    let query = use_query_map();
    let navigate = use_navigate();
    let agents = RwSignal::new(Vec::<AgentProfile>::new());
    let selected = RwSignal::new(None::<String>);
    let selected_profile = RwSignal::new(None::<AgentProfile>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);

    install_bot_agent_loader(
        query,
        agents,
        selected,
        selected_profile,
        loading,
        load_error,
        reload_generation,
    );

    let select_navigate = navigate;
    let select = UnsyncCallback::new(move |agent_id: Option<String>| {
        let Some(agent_id) = agent_id else {
            return;
        };
        if let Ok(href) = bot_chat_href(&agent_id) {
            select_navigate(&href, Default::default());
        }
    });
    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-bot-chat">
            <a class="ob-conversation-back" href="/agents">{move || t!(i18n, common.back)}</a>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <div class="ob-alert" role="alert">
                    <span>{move || t!(i18n, bot_chat.agent_load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                        {move || t!(i18n, common.retry)}
                    </Button>
                </div>
            </Show>
            <Show when=move || !loading.get() && !load_error.get() && selected_profile.get().is_none()>
                <p class="ob-page-empty">{move || t!(i18n, bot_chat.no_agents)}</p>
            </Show>
            <Show when=move || selected_profile.get().is_some()>
                <div class="ob-bot-chat-selector">
                    <RecipientField
                        agents=Signal::derive(move || agents.get())
                        selected
                        aria_label=move || t_string!(i18n, bot_chat.agent_label).to_owned()
                        placeholder=move || t_string!(i18n, bot_chat.agent_placeholder).to_owned()
                        empty_label=move || t_string!(i18n, bot_chat.no_agents).to_owned()
                        on_select=select
                    />
                </div>
                <For
                    each=move || selected_profile.get().into_iter()
                    key=|agent| agent.id.clone()
                    children=move |agent| view! { <BotThreadPane agent /> }
                />
            </Show>
            </div>
        </PageShell>
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedBotThread {
    id: ThreadId,
    fresh: bool,
}

#[component]
fn BotThreadPane(agent: AgentProfile) -> impl IntoView {
    let i18n = use_i18n();
    let agent_id = StoredValue::new(agent.id.clone());
    let agent_for_conversation = StoredValue::new(agent);
    let thread = RwSignal::new(None::<ResolvedBotThread>);
    let loading = RwSignal::new(true);
    let history_unavailable = RwSignal::new(false);
    let thread_error = RwSignal::new(false);
    let new_pending = RwSignal::new(false);
    let new_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    // Bumped by the open conversation whenever its work changed, so the list reads it again.
    let work_changes = RwSignal::new(0_u64);

    install_bot_thread_resolver(
        agent_id.get_value(),
        thread,
        loading,
        history_unavailable,
        thread_error,
        reload_generation,
    );

    let retry = move |_| {
        loading.set(true);
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };
    // Opening a row writes the remembered thread: the browser keeps only the most recently
    // opened conversation, and the Server's list stays the work identity.
    let open_work = UnsyncCallback::new(move |selected: ThreadId| {
        #[cfg(target_arch = "wasm32")]
        remember_thread(&agent_id.get_value(), &selected);
        thread.set(Some(ResolvedBotThread {
            id: selected,
            fresh: false,
        }));
        history_unavailable.set(false);
        thread_error.set(false);
    });
    let start_new = move |_| {
        if new_pending.get_untracked() {
            return;
        }
        new_pending.set(true);
        new_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match mint_and_remember(&agent_id.get_value()).await {
                Ok(next) => {
                    thread.set(Some(ResolvedBotThread {
                        id: next,
                        fresh: true,
                    }));
                    history_unavailable.set(false);
                    thread_error.set(false);
                }
                Err(()) => new_error.set(true),
            }
            new_pending.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            new_pending.set(false);
            new_error.set(true);
        }
    };

    view! {
        <BotWorkList
            agent_id=agent_id.get_value()
            selected=Signal::derive(move || thread.get().map(|thread| thread.id))
            on_select=open_work
            refresh=work_changes
        />
        <div class="ob-bot-thread-toolbar">
            <Button
                variant=ButtonVariant::Ghost
                size=ButtonSize::Medium
                disabled=loading
                loading=new_pending
                on_activate=start_new
            >
                <IconView icon=Icon::Plus size=IconSize::Inline />
                <span>{move || t!(i18n, bot_chat.new_chat)}</span>
            </Button>
        </div>
        <Show when=move || history_unavailable.get()>
            <p class="ob-alert" role="alert">{move || t!(i18n, bot_chat.history_unavailable)}</p>
        </Show>
        <Show when=move || thread_error.get()>
            <div class="ob-alert" role="alert">
                <span>{move || t!(i18n, bot_chat.thread_error)}</span>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>
                    {move || t!(i18n, common.retry)}
                </Button>
            </div>
        </Show>
        <Show when=move || new_error.get()>
            <p class="ob-alert" role="alert">{move || t!(i18n, bot_chat.new_chat_error)}</p>
        </Show>
        <Show when=move || loading.get()>
            <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
        </Show>
        <For
            each=move || thread.get().into_iter()
            key=|thread| thread.id.clone()
            children=move |thread| view! {
                <DirectBotConversation
                    thread=thread.id
                    agent=agent_for_conversation.get_value()
                    fresh=thread.fresh
                    on_work_changed=UnsyncCallback::new(move |_| {
                        work_changes.update(|value| *value = value.saturating_add(1));
                    })
                />
            }
        />
    }
}

fn install_bot_agent_loader(
    query: Memo<leptos_router::params::ParamsMap>,
    agents: RwSignal<Vec<AgentProfile>>,
    selected: RwSignal<Option<String>>,
    selected_profile: RwSignal<Option<AgentProfile>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    reload_generation: RwSignal<u64>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let requested = query.get().get("agent");
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        selected.set(None);
        selected_profile.set(None);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = async {
                let mut roster = list_agents(false).await?;
                let profile = match requested.as_deref() {
                    Some(requested) => match roster
                        .iter()
                        .find(|agent| agent.id.as_str() == requested)
                        .cloned()
                    {
                        Some(profile) => profile,
                        None => {
                            let profile = load_agent(requested).await?;
                            roster.push(profile.clone());
                            profile
                        }
                    },
                    None => roster
                        .first()
                        .cloned()
                        .ok_or(crate::api::ApiError::NotFound)?,
                };
                Ok::<_, crate::api::ApiError>((roster, profile))
            }
            .await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match result {
                Ok((roster, profile)) => {
                    selected.set(Some(profile.id.as_str().to_owned()));
                    selected_profile.set(Some(profile));
                    agents.set(roster);
                }
                Err(crate::api::ApiError::NotFound) if requested.is_none() => {
                    agents.set(Vec::new())
                }
                Err(_) => load_error.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        query,
        agents,
        selected,
        selected_profile,
        loading,
        load_error,
        reload_generation,
    );
}

fn install_bot_thread_resolver(
    agent_id: BotId,
    thread: RwSignal<Option<ResolvedBotThread>>,
    loading: RwSignal<bool>,
    history_unavailable: RwSignal<bool>,
    thread_error: RwSignal<bool>,
    reload_generation: RwSignal<u64>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        let agent_id = agent_id.clone();
        loading.set(true);
        history_unavailable.set(false);
        thread_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let remembered = remembered_thread(&agent_id);
            let (known, check_unavailable) = match remembered.as_ref() {
                Some(remembered) => match load_thread_status(remembered).await {
                    Ok(known) => (Some(known), false),
                    Err(_) => (None, true),
                },
                None => (None, false),
            };
            let decision = thread_to_use(remembered.as_ref(), known);
            let resolved = match (decision, remembered) {
                (RememberedThreadDecision::Remembered, Some(thread)) => {
                    Ok((thread, false, check_unavailable))
                }
                (RememberedThreadDecision::Fresh, _) => mint_and_remember(&agent_id)
                    .await
                    .map(|thread| (thread, true, false)),
                _ => Err(()),
            };
            if reload_generation.get_untracked() != generation {
                return;
            }
            match resolved {
                Ok((resolved, fresh, unavailable)) => {
                    thread.set(Some(ResolvedBotThread {
                        id: resolved,
                        fresh,
                    }));
                    history_unavailable.set(unavailable);
                }
                Err(()) => thread_error.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        agent_id,
        thread,
        loading,
        history_unavailable,
        thread_error,
        reload_generation,
    );
}

#[cfg(target_arch = "wasm32")]
async fn mint_and_remember(agent_id: &BotId) -> Result<ThreadId, ()> {
    let thread = mint_thread_id().await.map_err(|_| ())?;
    remember_thread(agent_id, &thread);
    Ok(thread)
}

#[cfg(target_arch = "wasm32")]
fn remembered_thread(agent_id: &BotId) -> Option<ThreadId> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let key = bot_thread_key(agent_id.as_str());
    let raw = storage.get_item(&key).ok()??;
    match plausible_remembered_thread(&raw) {
        Some(thread) => Some(thread),
        None => {
            _ = storage.remove_item(&key);
            None
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn remember_thread(agent_id: &BotId, thread: &ThreadId) {
    let Some(storage) = web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    else {
        return;
    };
    let (key, value) = remembered_entry(agent_id.as_str(), thread);
    _ = storage.set_item(&key, &value);
}
