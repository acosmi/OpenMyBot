//! Administrator gate and library section navigation for implemented admin destinations.

use leptos::prelude::*;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::require_admin_status;
use crate::features::layout::{SectionTab, SectionTabs};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{IconSize, IconView, Notice, NoticeTone};
use crate::shell::layout::set_shell_title;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminGateState {
    Loading,
    Authorized,
    #[cfg(any(target_arch = "wasm32", test))]
    NotFound,
    Failed,
}

/// Fail-closed administrator shell. Child pages are not constructed before the admin probe passes.
#[component]
pub fn AdminShell(children: ChildrenFn) -> impl IntoView {
    let i18n = use_i18n();
    let gate = RwSignal::new(AdminGateState::Loading);
    let children = StoredValue::new(children);
    set_shell_title(move || vec![t_string!(i18n, admin.title).to_owned()]);

    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        gate.set(admin_gate_state(require_admin_status().await));
    });
    #[cfg(not(target_arch = "wasm32"))]
    gate.set(AdminGateState::Failed);

    view! {
        <Show
            when=move || gate.get() == AdminGateState::Authorized
            fallback=move || admin_gate_fallback(i18n, gate.get())
        >
            {move || admin_shell_view(i18n, children.get_value())}
        </Show>
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn admin_gate_state(result: Result<(), ApiError>) -> AdminGateState {
    match result {
        Ok(()) => AdminGateState::Authorized,
        Err(ApiError::Unauthorized | ApiError::Forbidden | ApiError::NotFound) => {
            AdminGateState::NotFound
        }
        Err(_) => AdminGateState::Failed,
    }
}

fn admin_shell_view(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    children: ChildrenFn,
) -> impl IntoView {
    view! {
        <div class="ob-section-shell">
            <SectionTabs label=move || t_string!(i18n, admin.title).to_owned()>
                <SectionTab href="/admin/computers" icon=Icon::LayoutGrid
                    label=move || t_string!(i18n, computer.admin_title).to_owned() />
                <SectionTab href="/admin" icon=Icon::Landmark
                    label=move || t_string!(i18n, admin.nav_overview).to_owned() />
                <SectionTab href="/admin/boundaries" icon=Icon::ShieldCheck
                    label=move || t_string!(i18n, boundaries.title).to_owned() />
                <SectionTab href="/admin/components" icon=Icon::LayoutGrid nested=true
                    label=move || t_string!(i18n, admin.nav_components).to_owned() />
                <SectionTab href="/admin/identity-providers" icon=Icon::Landmark
                    label=move || t_string!(i18n, admin.nav_identity_providers).to_owned() />
                <SectionTab href="/admin/audit" icon=Icon::ListChecks
                    label=move || t_string!(i18n, admin.nav_audit).to_owned() />
                <SectionTab href="/admin/people" icon=Icon::Users
                    label=move || t_string!(i18n, admin.nav_people).to_owned() />
                <SectionTab href="/admin/playground" icon=Icon::Code
                    label=move || t_string!(i18n, admin.playground_title).to_owned() />
                <SectionTab href="/admin/skills" icon=Icon::FileText
                    label=move || t_string!(i18n, skills.deployment_title).to_owned() />
                <SectionTab href="/admin/credentials" icon=Icon::Key
                    label=move || t_string!(i18n, credentials.title).to_owned() />
                <SectionTab href="/admin/plugins" icon=Icon::Plug nested=true
                    label=move || t_string!(i18n, plugins.title).to_owned() />
            </SectionTabs>
            <div class="ob-section-content">{children()}</div>
        </div>
    }
}

fn admin_gate_fallback(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    state: AdminGateState,
) -> AnyView {
    match state {
        AdminGateState::Loading => view! {
            <div class="ob-loading" role="status">
                <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                <span>{move || t!(i18n, common.loading)}</span>
            </div>
        }
        .into_any(),
        #[cfg(any(target_arch = "wasm32", test))]
        AdminGateState::NotFound => view! {
            <section class="ob-page">
                <h1 class="ob-page-title">{move || t!(i18n, errors.not_found_title)}</h1>
                <p class="ob-page-intro">{move || t!(i18n, errors.not_found_body)}</p>
            </section>
        }
        .into_any(),
        AdminGateState::Failed | AdminGateState::Authorized => view! {
            <Notice tone=NoticeTone::Error>
                <span>{move || t!(i18n, admin.gate_error)}</span>
            </Notice>
        }
        .into_any(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_confirmed_administrator_is_authorized() {
        assert_eq!(admin_gate_state(Ok(())), AdminGateState::Authorized);
        assert_eq!(
            admin_gate_state(Err(ApiError::Forbidden)),
            AdminGateState::NotFound
        );
    }
}
