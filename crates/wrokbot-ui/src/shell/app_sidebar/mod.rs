//! Production sidebar content inside the shared Sidebar primitive. In UI spec v5.2 §5.2 order:
//! wordmark and filter, new conversation and approvals, assistants with the shown assistant's
//! work, channel history, reusable capabilities, then settings and account at the foot.

mod account;
mod assistants;
mod channels;

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    IconSize, IconView, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel,
    SidebarHeader, SidebarNavList, SidebarRow,
};

use self::account::SidebarAccount;
use self::assistants::SidebarAssistants;
use self::channels::SidebarChannels;

/// Production sidebar composition.
#[component]
pub fn AppSidebar() -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let search_open = RwSignal::new(false);
    let starts_location = location.clone();
    let path_is = move |path: &'static str| {
        let location = location.clone();
        Signal::derive(move || location.pathname.get() == path)
    };
    let path_starts = move |path: &'static str| {
        let location = starts_location.clone();
        Signal::derive(move || location.pathname.get().starts_with(path))
    };
    view! {
        <SidebarHeader>
            <a class="ob-sidebar-brand" href="/" aria-label=move || t_string!(i18n, common.app_name).to_owned()>
                <crate::primitives::BrandMark/>
                <span class="ob-brand-wordmark" aria-hidden="true"></span>
            </a>
            <button class="ob-sidebar-search-toggle" type="button"
                aria-label=move || t_string!(i18n, shell.search_toggle).to_owned()
                aria-expanded=move || search_open.get().to_string()
                aria-controls="sidebar-search-panel"
                on:click=move |_| search_open.update(|open| *open = !*open)>
                <IconView icon=Icon::Search size=IconSize::Navigation />
            </button>
        </SidebarHeader>
        <SidebarContent>
            <SidebarNavList>
                <SidebarRow href="/" icon=Icon::Pencil
                    label=move || t_string!(i18n, shell.nav_chat).to_owned()
                    current=path_is("/") />
                <SidebarRow href="/approvals" icon=Icon::Clock
                    label=move || t_string!(i18n, admin.nav_approvals).to_owned()
                    current=path_is("/approvals") />
            </SidebarNavList>
            <SidebarAssistants />
            <SidebarChannels search_open />
            <SidebarGroup>
                <SidebarGroupLabel>{move || t!(i18n, shell.tier_capabilities)}</SidebarGroupLabel>
                <SidebarNavList>
                    <SidebarRow href="/skills" icon=Icon::FileText
                        label=move || t_string!(i18n, shell.nav_skills).to_owned()
                        current=path_starts("/skills") />
                    <SidebarRow href="/settings/memory" icon=Icon::Brain
                        label=move || t_string!(i18n, shell.nav_memory).to_owned()
                        current=path_starts("/settings/memory") />
                </SidebarNavList>
            </SidebarGroup>
        </SidebarContent>
        <SidebarFooter>
            <SidebarAccount />
        </SidebarFooter>
    }
}
