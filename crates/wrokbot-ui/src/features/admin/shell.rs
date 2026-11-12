//! Administrator gate and library section navigation for implemented admin destinations.

use leptos::prelude::*;
use leptos_router::hooks::use_location;
use leptos_router::location::Location;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
#[cfg(target_arch = "wasm32")]
use crate::api::require_admin_status;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{IconSize, IconView, Notice, NoticeTone};

const ADMIN_HOME_PATH: &str = "/admin";
const ADMIN_AUDIT_PATH: &str = "/admin/audit";
const ADMIN_BOUNDARIES_PATH: &str = "/admin/boundaries";
const ADMIN_COMPONENTS_PATH: &str = "/admin/components";
const ADMIN_IDENTITY_PROVIDERS_PATH: &str = "/admin/identity-providers";
const ADMIN_PEOPLE_PATH: &str = "/admin/people";
const ADMIN_PLAYGROUND_PATH: &str = "/admin/playground";

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
    let location = StoredValue::new(use_location());

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
            {move || admin_shell_view(i18n, location.get_value(), children.get_value())}
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
    location: Location,
    children: ChildrenFn,
) -> impl IntoView {
    let home_location = location.clone();
    let audit_location = location.clone();
    let boundaries_location = location.clone();
    let components_location = location.clone();
    let identity_providers_location = location.clone();
    let people_location = location.clone();
    let plugins_location = location.clone();
    let credentials_location = location.clone();
    let skills_location = location.clone();
    let computers_location = location.clone();
    let playground_location = location;
    view! {
        <div class="ob-section-shell">
            <div class="ob-section-navigation">
                <nav aria-label=move || t_string!(i18n, admin.title).to_owned()>
                    <a class="ob-section-back" href="/">
                        <IconView icon=Icon::ArrowLeft size=IconSize::Inline />
                        <span>{move || t!(i18n, admin.back_to_app)}</span>
                    </a>
                    <ul class="ob-section-links">
                        <AdminNavItem href="/admin/computers" current=Signal::derive(move || is_exact(&computers_location.pathname.get(), "/admin/computers")) icon=Icon::LayoutGrid label=move || t_string!(i18n, computer.admin_title).to_owned()/>

                        <AdminNavItem
                            href=ADMIN_HOME_PATH
                            current=Signal::derive(move || {
                                is_exact(&home_location.pathname.get(), ADMIN_HOME_PATH)
                            })
                            icon=Icon::Landmark
                            label=move || t_string!(i18n, admin.nav_overview).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_BOUNDARIES_PATH
                            current=Signal::derive(move || {
                                is_exact(
                                    &boundaries_location.pathname.get(),
                                    ADMIN_BOUNDARIES_PATH,
                                )
                            })
                            icon=Icon::ShieldCheck
                            label=move || t_string!(i18n, boundaries.title).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_COMPONENTS_PATH
                            current=Signal::derive(move || {
                                let path = components_location.pathname.get();
                                path == ADMIN_COMPONENTS_PATH
                                    || path.starts_with("/admin/components/")
                            })
                            icon=Icon::LayoutGrid
                            label=move || t_string!(i18n, admin.nav_components).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_IDENTITY_PROVIDERS_PATH
                            current=Signal::derive(move || {
                                is_exact(
                                    &identity_providers_location.pathname.get(),
                                    ADMIN_IDENTITY_PROVIDERS_PATH,
                                )
                            })
                            icon=Icon::Landmark
                            label=move || t_string!(i18n, admin.nav_identity_providers).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_AUDIT_PATH
                            current=Signal::derive(move || {
                                is_exact(&audit_location.pathname.get(), ADMIN_AUDIT_PATH)
                            })
                            icon=Icon::ListChecks
                            label=move || t_string!(i18n, admin.nav_audit).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_PEOPLE_PATH
                            current=Signal::derive(move || {
                                is_exact(&people_location.pathname.get(), ADMIN_PEOPLE_PATH)
                            })
                            icon=Icon::Users
                            label=move || t_string!(i18n, admin.nav_people).to_owned()
                        />
                        <AdminNavItem
                            href=ADMIN_PLAYGROUND_PATH
                            current=Signal::derive(move || {
                                is_exact(
                                    &playground_location.pathname.get(),
                                    ADMIN_PLAYGROUND_PATH,
                                )
                            })
                            icon=Icon::Code
                            label=move || t_string!(i18n, admin.playground_title).to_owned()
                        />
                        <AdminNavItem href="/admin/skills" current=Signal::derive(move || skills_location.pathname.get() == "/admin/skills") icon=Icon::FileText label=move || t_string!(i18n, skills.deployment_title).to_owned() />
                        <AdminNavItem href="/admin/credentials"
                            current=Signal::derive(move || credentials_location.pathname.get() == "/admin/credentials")
                            icon=Icon::Key label=move || t_string!(i18n, credentials.title).to_owned() />
                        <AdminNavItem href="/admin/plugins"
                            current=Signal::derive(move || {
                                let path = plugins_location.pathname.get();
                                path == "/admin/plugins" || path.starts_with("/admin/plugins/")
                            })
                            icon=Icon::Plug
                            label=move || t_string!(i18n, plugins.title).to_owned()
                        />
                    </ul>
                </nav>
            </div>
            <div class="ob-section-content">{children()}</div>
        </div>
    }
}

#[component]
fn AdminNavItem(
    href: &'static str,
    current: Signal<bool>,
    icon: Icon,
    #[prop(into)] label: TextProp,
) -> impl IntoView {
    view! {
        <li>
            <a
                class="ob-section-link"
                href=href
                data-state=move || current.get().then_some("current")
                aria-current=move || current.get().then_some("page")
            >
                <IconView icon size=IconSize::Inline />
                <span>{move || label.get()}</span>
            </a>
        </li>
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

fn is_exact(pathname: &str, destination: &str) -> bool {
    pathname == destination
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_sidebar_exposes_only_real_destinations_and_exact_current_state() {
        assert_eq!(
            [
                ADMIN_HOME_PATH,
                ADMIN_BOUNDARIES_PATH,
                ADMIN_COMPONENTS_PATH,
                ADMIN_IDENTITY_PROVIDERS_PATH,
                ADMIN_AUDIT_PATH,
                ADMIN_PEOPLE_PATH,
                ADMIN_PLAYGROUND_PATH,
            ],
            [
                "/admin",
                "/admin/boundaries",
                "/admin/components",
                "/admin/identity-providers",
                "/admin/audit",
                "/admin/people",
                "/admin/playground",
            ]
        );
        assert!(is_exact("/admin", ADMIN_HOME_PATH));
        assert!(!is_exact("/admin/audit", ADMIN_HOME_PATH));
        assert!(is_exact("/admin/audit", ADMIN_AUDIT_PATH));
        assert!(!is_exact("/admin/audit-old", ADMIN_AUDIT_PATH));
        assert!(is_exact("/admin/boundaries", ADMIN_BOUNDARIES_PATH));
        assert!(is_exact("/admin/components", ADMIN_COMPONENTS_PATH));
        assert!(is_exact(
            "/admin/identity-providers",
            ADMIN_IDENTITY_PROVIDERS_PATH
        ));
        assert!(is_exact("/admin/people", ADMIN_PEOPLE_PATH));
        assert_eq!(admin_gate_state(Ok(())), AdminGateState::Authorized);
        assert_eq!(
            admin_gate_state(Err(ApiError::Forbidden)),
            AdminGateState::NotFound
        );
    }
}
