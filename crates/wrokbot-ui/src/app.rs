//! Shared Server Web/Desktop Leptos application shell and route root.

use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::features::admin::{
    AdminAuditPage, AdminBoundariesPage, AdminCredentialsPage, AdminHomePage,
    AdminIdentityProvidersPage, AdminPeoplePage, AdminPluginsPage, AdminShell,
    SandboxPlaygroundPage,
};
use crate::features::agents::AgentsPage;
use crate::features::approvals::ApprovalPage;
use crate::features::channels::{ChannelDetailPage, ChannelNewPage};
use crate::features::memory::MemoryPage;
use crate::features::settings::{
    ComponentGalleryDetailPage, ComponentsGalleryPage, ConnectedAccountDetailPage,
    ConnectedAccountsPage, ModelServicesPage, SettingsPage, SettingsShell,
};
use crate::features::skills::{DeploymentSkillsPage, PersonalSkillsPage};
use crate::i18n::{I18nContextProvider, t, use_i18n};
use crate::shell::{
    AdminComponentDetailPage, AdminComponentsPage, AppLayout, AuthenticatedBoundary, BotChatPage,
    HomePage, RootLayout,
};

/// Single CSR application root used by both supported hosts.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    crate::locale_policy::provide_startup_locale();
    view! {
        <I18nContextProvider set_lang_attr_on_html=true enable_cookie=false>
            <Title text="Wrok Bot" />
            <Router>
                <RootLayout>
                    <AuthenticatedBoundary>
                        <AuthenticatedWorkspace />
                    </AuthenticatedBoundary>
                </RootLayout>
            </Router>
        </I18nContextProvider>
    }
}

/// Authenticated-mount-owned projections cannot survive a session boundary or accept its late reads.
#[component]
fn AuthenticatedWorkspace() -> impl IntoView {
    provide_context(crate::configuration_writes::ConfigurationWrites::new());
    provide_context(crate::features::channels::run_observation::ObservedRunDirectory::new());
    provide_context(crate::features::approvals::ToolApprovalActions::new());
    provide_context(crate::features::approvals::attention::ComponentDecisionActions::new());
    provide_context(crate::features::approvals::attention::RemoteInterruptActions::new());
    provide_context(crate::features::admin::plugins::PluginActions::new());
    provide_context(crate::features::memory::remember::RememberActions::new());
    provide_context(crate::features::channels::artifacts::ArtifactActions::new());
    let model_actions = crate::features::settings::models::ModelActions::new();
    provide_context(model_actions);
    provide_context(
        crate::features::channels::composer::models::ModelDirectory::new(model_actions),
    );
    provide_context(
        crate::features::channels::composer::model_intents::RunSubmissionActions::new(),
    );
    view! {
        <AppLayout>
            <crate::configuration_writes::ConfigurationWriteNotice />
            <crate::features::channels::artifacts::ArtifactUnknownNotice />
            <AppRoutes />
        </AppLayout>
    }
}

#[component]
fn AppRoutes() -> impl IntoView {
    #[cfg(feature = "design-gallery")]
    {
        view! {
            <Routes fallback=NotFound>
                <Route path=path!("/_design") view=crate::design_gallery::DesignGallery />
                <Route path=path!("/") view=HomePage />
                <Route path=path!("/approvals") view=ApprovalPage />
                <Route path=path!("/agents") view=AgentsPage />
                <Route path=path!("/skills") view=PersonalSkillsPage />
                <Route path=path!("/admin/skills") view=AdminSkillsRoute />
                <Route path=path!("/admin/computers") view=AdminComputersRoute />
                <Route path=path!("/bot") view=BotChatPage />
                <Route path=path!("/admin") view=AdminHomeRoute />
                <Route path=path!("/admin/audit") view=AdminAuditRoute />
                <Route path=path!("/admin/boundaries") view=AdminBoundariesRoute />
                <Route path=path!("/admin/components/:name") view=AdminComponentDetailRoute />
                <Route path=path!("/admin/components") view=AdminComponentsRoute />
                <Route path=path!("/admin/identity-providers") view=AdminIdentityProvidersRoute />
                <Route path=path!("/admin/credentials") view=AdminCredentialsRoute />
                <Route path=path!("/admin/people") view=AdminPeopleRoute />
                <Route path=path!("/admin/playground") view=AdminPlaygroundRoute />
                <Route path=path!("/admin/plugins/:key/tools/:tool") view=AdminPluginsRoute />
                <Route path=path!("/admin/plugins/:key") view=AdminPluginsRoute />
                <Route path=path!("/admin/plugins") view=AdminPluginsRoute />
                <Route path=path!("/channel/new") view=ChannelNewPage />
                <Route path=path!("/channel/:channel_id") view=ChannelDetailPage />
                <Route path=path!("/settings/connected-accounts/:server_id") view=SettingsConnectedAccountDetailRoute />
                <Route path=path!("/settings/connected-accounts") view=SettingsConnectedAccountsRoute />
                <Route path=path!("/settings/components-gallery/:name") view=SettingsComponentGalleryDetailRoute />
                <Route path=path!("/settings/components-gallery") view=SettingsComponentsGalleryRoute />
                <Route path=path!("/settings/memory") view=SettingsMemoryRoute />
                <Route path=path!("/settings/models") view=SettingsModelsRoute />
                <Route path=path!("/settings") view=SettingsPreferencesRoute />
            </Routes>
        }
    }
    #[cfg(not(feature = "design-gallery"))]
    {
        view! {
            <Routes fallback=NotFound>
                <Route path=path!("/") view=HomePage />
                <Route path=path!("/approvals") view=ApprovalPage />
                <Route path=path!("/agents") view=AgentsPage />
                <Route path=path!("/skills") view=PersonalSkillsPage />
                <Route path=path!("/admin/skills") view=AdminSkillsRoute />
                <Route path=path!("/admin/computers") view=AdminComputersRoute />
                <Route path=path!("/bot") view=BotChatPage />
                <Route path=path!("/admin") view=AdminHomeRoute />
                <Route path=path!("/admin/audit") view=AdminAuditRoute />
                <Route path=path!("/admin/boundaries") view=AdminBoundariesRoute />
                <Route path=path!("/admin/components/:name") view=AdminComponentDetailRoute />
                <Route path=path!("/admin/components") view=AdminComponentsRoute />
                <Route path=path!("/admin/identity-providers") view=AdminIdentityProvidersRoute />
                <Route path=path!("/admin/credentials") view=AdminCredentialsRoute />
                <Route path=path!("/admin/people") view=AdminPeopleRoute />
                <Route path=path!("/admin/playground") view=AdminPlaygroundRoute />
                <Route path=path!("/admin/plugins/:key/tools/:tool") view=AdminPluginsRoute />
                <Route path=path!("/admin/plugins/:key") view=AdminPluginsRoute />
                <Route path=path!("/admin/plugins") view=AdminPluginsRoute />
                <Route path=path!("/channel/new") view=ChannelNewPage />
                <Route path=path!("/channel/:channel_id") view=ChannelDetailPage />
                <Route path=path!("/settings/connected-accounts/:server_id") view=SettingsConnectedAccountDetailRoute />
                <Route path=path!("/settings/connected-accounts") view=SettingsConnectedAccountsRoute />
                <Route path=path!("/settings/components-gallery/:name") view=SettingsComponentGalleryDetailRoute />
                <Route path=path!("/settings/components-gallery") view=SettingsComponentsGalleryRoute />
                <Route path=path!("/settings/memory") view=SettingsMemoryRoute />
                <Route path=path!("/settings/models") view=SettingsModelsRoute />
                <Route path=path!("/settings") view=SettingsPreferencesRoute />
            </Routes>
        }
    }
}

#[component]
fn AdminCredentialsRoute() -> impl IntoView {
    view! { <AdminShell><AdminCredentialsPage /></AdminShell> }
}

#[component]
fn AdminPluginsRoute() -> impl IntoView {
    view! { <AdminShell><AdminPluginsPage /></AdminShell> }
}

#[component]
fn AdminHomeRoute() -> impl IntoView {
    view! { <AdminShell><AdminHomePage /></AdminShell> }
}

#[component]
fn AdminAuditRoute() -> impl IntoView {
    view! { <AdminShell><AdminAuditPage /></AdminShell> }
}

#[component]
fn AdminBoundariesRoute() -> impl IntoView {
    view! { <AdminShell><AdminBoundariesPage /></AdminShell> }
}

#[component]
fn AdminComponentsRoute() -> impl IntoView {
    view! { <AdminShell><AdminComponentsPage /></AdminShell> }
}

#[component]
fn AdminComponentDetailRoute() -> impl IntoView {
    view! { <AdminShell><AdminComponentDetailPage /></AdminShell> }
}

#[component]
fn AdminIdentityProvidersRoute() -> impl IntoView {
    view! { <AdminShell><AdminIdentityProvidersPage /></AdminShell> }
}

#[component]
fn AdminPeopleRoute() -> impl IntoView {
    view! { <AdminShell><AdminPeoplePage /></AdminShell> }
}

#[component]
fn AdminPlaygroundRoute() -> impl IntoView {
    view! { <AdminShell><SandboxPlaygroundPage /></AdminShell> }
}

#[component]
fn SettingsPreferencesRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <SettingsPage />
        </SettingsShell>
    }
}

#[component]
fn SettingsModelsRoute() -> impl IntoView {
    view! { <SettingsShell><ModelServicesPage/></SettingsShell> }
}

#[component]
fn SettingsMemoryRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <MemoryPage />
        </SettingsShell>
    }
}

#[component]
fn SettingsConnectedAccountsRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <ConnectedAccountsPage />
        </SettingsShell>
    }
}

#[component]
fn SettingsConnectedAccountDetailRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <ConnectedAccountDetailPage />
        </SettingsShell>
    }
}

#[component]
fn SettingsComponentsGalleryRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <ComponentsGalleryPage />
        </SettingsShell>
    }
}

#[component]
fn SettingsComponentGalleryDetailRoute() -> impl IntoView {
    view! {
        <SettingsShell>
            <ComponentGalleryDetailPage />
        </SettingsShell>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <section class="ob-page">
            <h1 class="ob-page-title">{move || t!(i18n, errors.not_found_title)}</h1>
            <p class="ob-page-intro">{move || t!(i18n, errors.not_found_body)}</p>
        </section>
    }
}

#[component]
fn AdminSkillsRoute() -> impl IntoView {
    view! { <AdminShell><DeploymentSkillsPage /></AdminShell> }
}

#[component]
fn AdminComputersRoute() -> impl IntoView {
    view! { <AdminShell><crate::features::computer::admin::AdminComputersPage/></AdminShell> }
}
