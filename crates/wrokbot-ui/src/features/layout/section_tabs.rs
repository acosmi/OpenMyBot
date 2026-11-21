//! Section navigation of the settings and administration families (UI spec v5.2 §6.2): one row
//! of tabs under the top bar; the current tab carries `aria-current="page"`.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::icons::Icon;
use crate::primitives::{IconSize, IconView};

/// The tab row.
#[component]
pub fn SectionTabs(
    /// Accessible name of the navigation landmark.
    #[prop(into)]
    label: TextProp,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="ob-section-navigation">
            <nav aria-label=move || label.get()>
                <ul class="ob-section-links">{children()}</ul>
            </nav>
        </div>
    }
}

/// One tab. A `nested` tab stays current on the pages beneath its destination.
#[component]
pub(crate) fn SectionTab(
    href: &'static str,
    icon: Icon,
    #[prop(into)] label: TextProp,
    #[prop(optional)] nested: bool,
) -> impl IntoView {
    let location = use_location();
    view! {
        <li>
            <a
                class="ob-section-link"
                href=href
                aria-current=move || tab_current(&location.pathname.get(), href, nested).then_some("page")
            >
                <IconView icon size=IconSize::Inline />
                <span>{move || label.get()}</span>
            </a>
        </li>
    }
}

fn tab_current(pathname: &str, href: &str, nested: bool) -> bool {
    pathname == href
        || (nested
            && pathname
                .strip_prefix(href)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::tab_current;

    #[test]
    fn exact_tabs_match_only_themselves_and_nested_tabs_keep_their_pages() {
        assert!(tab_current("/settings", "/settings", false));
        assert!(!tab_current("/settings/memory", "/settings", false));
        assert!(tab_current("/admin/audit", "/admin/audit", false));
        assert!(!tab_current("/admin/audit-old", "/admin/audit", false));
        assert!(tab_current(
            "/settings/connected-accounts/google-drive",
            "/settings/connected-accounts",
            true
        ));
        assert!(!tab_current(
            "/settings/connected-accounts-legacy",
            "/settings/connected-accounts",
            true
        ));
        assert!(tab_current(
            "/admin/plugins/a/tools/b",
            "/admin/plugins",
            true
        ));
    }
}
