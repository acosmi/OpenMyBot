//! The account disclosure at the sidebar foot: settings, the administrator entry for
//! administrators, theme and language, and sign-out for a revocable session.

use leptos::prelude::*;
use leptos_router::hooks::use_location;
use openbot_contracts::people::CurrentUser;

#[cfg(target_arch = "wasm32")]
use crate::api::{
    load_current_user, load_session_status, require_admin_status, sign_out_current_session,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::preferences::PreferenceSaveStatus;
use crate::primitives::{
    Avatar, AvatarSize, Button, ButtonSize, ButtonVariant, IconSize, IconView, LocaleSwitch,
    Notice, NoticePresentation, NoticeTone, SidebarNavList, SidebarRow, ThemeToggle,
};

/// Account and preferences disclosure.
#[component]
pub(super) fn SidebarAccount() -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let current_user = RwSignal::new(None::<CurrentUser>);
    let revocable = RwSignal::new(false);
    let account_error = RwSignal::new(false);
    let admin_visible = RwSignal::new(false);
    let sign_out_pending = RwSignal::new(false);
    let sign_out_error = RwSignal::new(false);

    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let (user, session, admin) = futures_util::join!(
            load_current_user(),
            load_session_status(),
            require_admin_status()
        );
        match user {
            Ok(user) => current_user.set(Some(user)),
            Err(_) => account_error.set(true),
        }
        match session {
            Ok(session) => revocable.set(session.revocable),
            Err(_) => account_error.set(true),
        }
        admin_visible.set(admin.is_ok());
    });

    let sign_out = move |_| {
        if sign_out_pending.get_untracked() {
            return;
        }
        sign_out_pending.set(true);
        sign_out_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match sign_out_current_session().await {
                Ok(()) => {
                    if let Some(window) = web_sys::window() {
                        _ = window.location().set_href("/sign");
                    }
                }
                Err(_) => {
                    sign_out_pending.set(false);
                    sign_out_error.set(true);
                }
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            sign_out_pending.set(false);
            sign_out_error.set(true);
        }
    };
    view! {
        <details class="ob-account-disclosure" on:keydown=crate::primitives::dismiss_disclosure on:click=crate::primitives::dismiss_disclosure_link>
            <summary aria-label=move || t_string!(i18n, shell.account_menu).to_owned()>
                <Show when=move || current_user.get().is_some()
                    fallback=move || view! { <IconView icon=Icon::User size=IconSize::Navigation /><span class="ob-account-name">{move || t!(i18n, shell.account)}</span> }>
                    {move || current_user.get().map(|user| {
                        let display = user.name.clone().unwrap_or_else(|| user.email.clone());
                        view! {
                            <Avatar principal_id=user.id.as_str().to_owned() name=display.clone() size=AvatarSize::Medium />
                            <span class="ob-account-name">{display}</span>
                        }
                    })}
                </Show>
                <span class="ob-account-chevron"><IconView icon=Icon::ChevronsUpDown size=IconSize::Inline /></span>
            </summary>
            <div class="ob-account-panel">
                <SidebarNavList>
                    <SidebarRow href="/settings" icon=Icon::Settings
                        label=move || t_string!(i18n, shell.nav_settings).to_owned() />
                    <Show when=move || admin_visible.get()>
                        {
                            let admin_location = location.clone();
                            view! {
                                <SidebarRow href="/admin" icon=Icon::ShieldLock
                                    label=move || t_string!(i18n, shell.nav_admin).to_owned()
                                    current=Signal::derive(move || is_section_path(&admin_location.pathname.get(), "/admin")) />
                            }
                        }
                    </Show>
                </SidebarNavList>
                <div class="ob-sidebar-preferences"><ThemeToggle /><LocaleSwitch id="sidebar-locale-switch" /><PreferenceSaveStatus id_prefix="sidebar-preferences-editor"/></div>
                <Show when=move || revocable.get()>
                    <Button variant=ButtonVariant::DangerText size=ButtonSize::Medium loading=sign_out_pending on_activate=sign_out>
                        <IconView icon=Icon::LogOut size=IconSize::Inline /><span>{move || t!(i18n, auth.sign_out)}</span>
                    </Button>
                </Show>
            </div>
        </details>
        <Show when=move || sign_out_error.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, auth.sign_out_error)}</Notice></Show>
        <Show when=move || account_error.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, account.load_failed)}</Notice></Show>
    }
}

/// The section root itself or any page beneath it, never a sibling that only shares the prefix.
fn is_section_path(pathname: &str, root: &str) -> bool {
    pathname == root
        || pathname
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::is_section_path;

    #[test]
    fn a_section_is_current_on_its_root_and_pages_beneath_it_only() {
        assert!(is_section_path("/admin", "/admin"));
        assert!(is_section_path("/admin/audit", "/admin"));
        assert!(!is_section_path("/admin-old", "/admin"));
        assert!(!is_section_path("/settings", "/admin"));
        assert!(is_section_path("/settings/memory", "/settings"));
    }
}
