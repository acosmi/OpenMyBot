//! Settings section navigation for the implemented `/settings` destinations.

use leptos::prelude::*;

use crate::features::layout::{SectionTab, SectionTabs};
use crate::i18n::{t_string, use_i18n};
use crate::icons::Icon;
use crate::shell::layout::set_shell_title;

/// Settings secondary shell. The global App shell remains the only owner of `<main>`.
#[component]
pub fn SettingsShell(children: Children) -> impl IntoView {
    let i18n = use_i18n();
    set_shell_title(move || vec![t_string!(i18n, settings.title).to_owned()]);
    view! {
        <div class="ob-section-shell">
            <SectionTabs label=move || t_string!(i18n, settings.title).to_owned()>
                <SectionTab href="/settings" icon=Icon::Settings
                    label=move || t_string!(i18n, settings.nav_general).to_owned() />
                <SectionTab href="/settings/connected-accounts" icon=Icon::Plug nested=true
                    label=move || t_string!(i18n, settings.nav_connected_accounts).to_owned() />
                <SectionTab href="/settings/components-gallery" icon=Icon::LayoutGrid nested=true
                    label=move || t_string!(i18n, settings.nav_gallery).to_owned() />
                <SectionTab href="/settings/memory" icon=Icon::Brain
                    label=move || t_string!(i18n, shell.nav_memory).to_owned() />
                <SectionTab href="/settings/models" icon=Icon::Plug
                    label=move || t_string!(i18n, models.title).to_owned() />
            </SectionTabs>
            <div class="ob-section-content">
                {children()}
            </div>
        </div>
    }
}
