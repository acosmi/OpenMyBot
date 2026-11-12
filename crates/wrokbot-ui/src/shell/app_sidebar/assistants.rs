//! The assistant group: one row per visible assistant from the shell directory, the shown
//! assistant's work list beneath its row, and its new-conversation control (UI spec v5.2 §5.2).

use leptos::prelude::*;

use crate::features::agents::use_agent_directory;
use crate::features::bot_threads::{BotWorkList, use_bot_work};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Notice, NoticePresentation, NoticeTone,
    SidebarGroup, SidebarGroupLabel, SidebarNavList, SidebarRow,
};

/// Read only the authorized assistant directory, never selecting a fallback recipient.
#[component]
pub(super) fn SidebarAssistants() -> impl IntoView {
    let i18n = use_i18n();
    let directory = use_agent_directory();
    let work = use_bot_work();
    view! {
        <SidebarGroup>
            <div class="ob-sidebar-group-heading">
                <SidebarGroupLabel>{move || t!(i18n, shell.nav_agents)}</SidebarGroupLabel>
                <a class="ob-sidebar-row-action" href="/agents"
                    aria-label=move || t_string!(i18n, shell.manage_agents).to_owned()
                    title=move || t_string!(i18n, shell.manage_agents).to_owned()>
                    <IconView icon=Icon::Settings size=IconSize::Inline />
                </a>
            </div>
            <Show when=move || directory.loading.get() && directory.agents.with(Vec::is_empty)>
                <p class="ob-sidebar-loading" role="status">{move || t!(i18n, common.loading)}</p>
            </Show>
            <Show when=move || directory.failed.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                    <span>{move || t!(i18n, agents.load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| directory.refresh()>{move || t!(i18n, common.retry)}</Button>
                </Notice>
            </Show>
            <Show when=move || !directory.loading.get() && !directory.failed.get() && directory.agents.with(Vec::is_empty)>
                <p class="ob-sidebar-search-empty">{move || t!(i18n, agents.empty_title)}</p>
            </Show>
            <SidebarNavList>
                <For each=move || directory.agents.get() key=|agent| agent.id.clone() children=move |agent| {
                    let href = crate::api::bot_chat_href(agent.id.as_str()).ok()?;
                    let id = agent.id.clone();
                    let shown = Memo::new(move |_| work.agent_id().as_ref() == Some(&id));
                    let remote = agent.endpoint.is_some();
                    let list_agent = agent.id.clone();
                    Some(view! {
                        <SidebarRow
                            href
                            avatar=agent.avatar_seed
                            label=agent.name
                            current=shown
                            actions=move || view! {
                                {remote.then(|| view! {
                                    <span class="ob-sidebar-row-marker" title=move || t_string!(i18n, shell.remote_agent).to_owned()>
                                        <IconView icon=Icon::Globe size=IconSize::Inline />
                                        <span class="ob-visually-hidden">{move || t!(i18n, shell.remote_agent)}</span>
                                    </span>
                                })}
                                <Show when=move || shown.get()>
                                    <button class="ob-sidebar-row-action" type="button"
                                        aria-label=move || t_string!(i18n, bot_chat.new_chat).to_owned()
                                        title=move || t_string!(i18n, bot_chat.new_chat).to_owned()
                                        disabled=move || work.resolving.get() || work.new_pending.get()
                                        on:click=move |_| work.start_new()>
                                        <IconView icon=Icon::Plus size=IconSize::Inline />
                                    </button>
                                </Show>
                            }
                            below=move || {
                                let list_agent = list_agent.clone();
                                view! {
                                    <Show when=move || shown.get()>
                                        <BotWorkList agent_id=list_agent.clone() />
                                    </Show>
                                }
                            }
                        />
                    })
                } />
            </SidebarNavList>
        </SidebarGroup>
    }
}
