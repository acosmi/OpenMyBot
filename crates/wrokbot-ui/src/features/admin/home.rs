//! Administrator landing page with only implemented destinations.

use leptos::prelude::*;

use crate::features::layout::{PageHeader, PageRows, PageShell, PageWidth};
use crate::i18n::{t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    IconSize, IconView, Item, ItemAction, ItemDescription, ItemMedia, ItemTitle,
};

/// Grouped administrator landing page. Broken future destinations are intentionally absent.
#[component]
pub fn AdminHomePage() -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="admin-home-title"
                title=move || t_string!(i18n, admin.title).to_owned()
                title_in_top_bar=true
                description=move || t_string!(i18n, admin.overview_intro).to_owned()
            />
            <PageRows>
                <Item action=ItemAction::Link("/admin/computers".to_owned())>
                    <ItemMedia><IconView icon=Icon::LayoutGrid size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, computer.admin_title).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, computer.admin_description).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/skills".to_owned())>
                    <ItemMedia><IconView icon=Icon::Code size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, skills.deployment_title).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, skills.deployment_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/boundaries".to_owned())>
                    <ItemMedia><IconView icon=Icon::ShieldCheck size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, boundaries.title).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, boundaries.intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/people".to_owned())>
                    <ItemMedia><IconView icon=Icon::Users size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.nav_people).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.people_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/components".to_owned())>
                    <ItemMedia><IconView icon=Icon::LayoutGrid size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.nav_components).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.components_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/identity-providers".to_owned())>
                    <ItemMedia><IconView icon=Icon::Landmark size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.nav_identity_providers).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.identity_providers_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/audit".to_owned())>
                    <ItemMedia><IconView icon=Icon::ListChecks size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.nav_audit).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.audit_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/approvals".to_owned())>
                    <ItemMedia><IconView icon=Icon::ShieldCheck size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.nav_approvals).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.approvals_intro).to_owned()}</ItemDescription>
                </Item>
                <Item action=ItemAction::Link("/admin/playground".to_owned())>
                    <ItemMedia><IconView icon=Icon::Code size=IconSize::Navigation /></ItemMedia>
                    <ItemTitle>{move || t_string!(i18n, admin.playground_title).to_owned()}</ItemTitle>
                    <ItemDescription>{move || t_string!(i18n, admin.playground_intro).to_owned()}</ItemDescription>
                </Item>
            </PageRows>
        </PageShell>
    }
}
