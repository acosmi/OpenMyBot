//! Deployment Plugins management through the existing typed application APIs.

mod forms;
mod state;

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::mcp::{
    McpAdminAuthentication, McpAdminServer, McpAdminTool, McpAdminToolEffect,
};

use crate::api::plugins as api;
use crate::features::layout::{
    DetailPanelLayout, DetailPanelMain, PageBackLink, PageEmpty, PageHeader, PageRows, PageSection,
    PageShell, PageTopbar, editor_location::EditorLocation,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonVariant, IconSize, IconView, Notice, NoticeTone, Switch};
use forms::{PluginDialog, PluginDialogs};
pub(crate) use state::PluginActions;
use state::{PluginData, PluginPageState};

/// Deployment plugin catalogue, server configuration, and per-Agent tool grants.
#[component]
pub fn AdminPluginsPage() -> impl IntoView {
    let i18n = use_i18n();
    let params = use_params_map();
    let state = PluginPageState::new();
    let actions = expect_context::<PluginActions>();
    let dialog = RwSignal::new(None::<PluginDialog>);
    let editor = EditorLocation::new(&["plugin-new", "plugin-oauth", "plugin-delete"]);
    let scope = Memo::new(move |_| (params.read().get("key"), params.read().get("tool")));
    Effect::new(move |_| {
        let (path_target, tool) = scope.get();
        let current = state.data.get();
        let selected = editor
            .selection
            .get()
            .and_then(|selected| match selected.kind {
                "plugin-new" if path_target.is_none() && tool.is_none() => {
                    Some(PluginDialog::Custom)
                }
                "plugin-oauth" | "plugin-delete" if tool.is_none() => {
                    let target = selected.target?;
                    if path_target.as_ref() != Some(&target) {
                        return None;
                    }
                    let current = current.as_ref()?;
                    if !current
                        .page
                        .servers
                        .iter()
                        .any(|server| server.id == target)
                    {
                        return None;
                    }
                    if selected.kind == "plugin-oauth" {
                        current.page.redirect_uri.as_ref()?;
                        Some(PluginDialog::OAuth(target))
                    } else {
                        Some(PluginDialog::Remove(target))
                    }
                }
                _ => None,
            });
        if dialog.get_untracked() != selected {
            dialog.set(selected);
        }
    });
    let page_open = Signal::derive(move || {
        dialog
            .get()
            .is_some_and(|dialog| !matches!(dialog, PluginDialog::Remove(_)))
    });
    Effect::new(move |_| {
        let _ = (scope.get(), actions.revision.get());
        state.reload();
    });
    Effect::new(move |previous: Option<(Option<String>, Option<String>)>| {
        let current = scope.get();
        if previous.is_some() {
            editor.close();
        }
        current
    });
    view! {
        <DetailPanelLayout open=page_open>
        <DetailPanelMain>
        <PageShell>
            {move || {
                let (server, tool) = scope.get();
                let heading = state.data.get().and_then(|data| {
                    tool.clone().or_else(|| server.as_ref().and_then(|key|
                        data.page.servers.iter().find(|row| &row.id == key).map(|row| row.title.clone())
                            .or_else(|| data.page.catalogue.iter().find(|row| &row.key == key).map(|row| row.title.clone()))))
                }).unwrap_or_else(|| t_string!(i18n, plugins.title).to_owned());
                view! {
                    <Show when=move || server.is_some()>
                        <PageTopbar><PageBackLink href="/admin/plugins" label=move || t_string!(i18n, plugins.title).to_owned() /></PageTopbar>
                    </Show>
                    <PageHeader heading_id="plugins-title" title=heading description=move || t_string!(i18n, plugins.intro).to_owned() />
                }
            }}
            <Show when=move || actions.busy.get() && !actions.unknown.get()><p class="ob-loading" role="status">{move || t!(i18n, plugins.saving)}</p></Show>
            <Show when=move || actions.unknown.get()><Notice tone=NoticeTone::Error>{move || t!(i18n, plugins.write_unknown)}</Notice></Show>
            <Show when=move || actions.failed.get() && !actions.unknown.get() && scope.get().0.is_none_or(|id| actions.target.get().as_deref() == Some(&id))>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, plugins.write_error)}</Notice>
            </Show>
            <Show when=move || state.loading.get()><p class="ob-loading" role="status">{move || t!(i18n, common.loading)}</p></Show>
            <Show when=move || state.error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, plugins.load_error)}</span>
                    <Button variant=ButtonVariant::Ghost on_activate=move |_| state.reload()>{move || t!(i18n, common.retry)}</Button>
                </Notice>
            </Show>
            {move || state.data.get().map(|data| {
                let (server, tool) = scope.get();
                match (server, tool) {
                    (None, None) => view! { <PluginIndex data editor /> }.into_any(),
                    (Some(key), None) if api::plugin_href(&key).is_ok() => view! { <PluginDetail data server_id=key editor /> }.into_any(),
                    (Some(key), Some(tool)) if api::tool_href(&key, &tool).is_ok() => view! { <PluginTool data server_id=key tool_name=tool /> }.into_any(),
                    _ => view! { <PageEmpty>{move || t!(i18n, plugins.not_found)}</PageEmpty> }.into_any(),
                }
            })}
        </PageShell>
        </DetailPanelMain>
        <PluginDialogs dialog editor />
        </DetailPanelLayout>
    }
}

#[component]
fn PluginIndex(data: PluginData, editor: EditorLocation) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let connected = data.page.servers;
    let explore = data
        .page
        .catalogue
        .into_iter()
        .filter(|entry| !connected.iter().any(|server| server.id == entry.key))
        .collect::<Vec<_>>();
    view! {
        <div class="ob-page-primary-action"><Button id="plugin-add" variant=ButtonVariant::Primary disabled=actions.busy
            on_activate=move |_| editor.open("plugin-new", None)>{move || t!(i18n, plugins.custom_add)}</Button></div>
        <PageSection heading_id="plugins-connected" title=move || t_string!(i18n, plugins.connected).to_owned()>
            {if connected.is_empty() { view! { <PageEmpty>{move || t!(i18n, plugins.empty)}</PageEmpty> }.into_any() }
            else { view! { <PageRows>{connected.into_iter().map(|server| {
                let count = server.tools.len();
                view! { <PluginLink href=api::plugin_href(&server.id).expect("validated id") title=server.title
                    description=server.summary suffix=move || t_string!(i18n, plugins.tool_count, count=count).to_owned() /> }
            }).collect_view()}</PageRows> }.into_any() }}
        </PageSection>
        <PageSection heading_id="plugins-explore" title=move || t_string!(i18n, plugins.explore).to_owned()>
            {if explore.is_empty() { view! { <PageEmpty>{move || t!(i18n, plugins.catalogue_empty)}</PageEmpty> }.into_any() }
            else { view! { <PageRows>{explore.into_iter().map(|entry| view! {
                <PluginLink href=api::plugin_href(&entry.key).expect("validated id") title=entry.title description=entry.summary suffix=String::new() />
            }).collect_view()}</PageRows> }.into_any() }}
        </PageSection>
    }
}

#[component]
fn PluginLink(
    href: String,
    title: String,
    description: String,
    #[prop(into)] suffix: TextProp,
) -> impl IntoView {
    view! { <a class="ob-plugin-link" href=href>
        <IconView icon=Icon::Plug size=IconSize::Navigation />
        <span class="ob-plugin-copy"><strong>{title}</strong><span class="text-fg-secondary">{description}</span></span>
        <span class="text-fg-muted">{move || suffix.get()}</span><IconView icon=Icon::ChevronRight size=IconSize::Inline />
    </a> }
}

#[component]
fn PluginDetail(data: PluginData, server_id: String, editor: EditorLocation) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let server = data
        .page
        .servers
        .iter()
        .find(|row| row.id == server_id)
        .cloned();
    let entry = data
        .page
        .catalogue
        .iter()
        .find(|row| row.key == server_id)
        .cloned();
    if server.is_none() && entry.is_none() {
        return view! { <PageEmpty>{move || t!(i18n, plugins.not_found)}</PageEmpty> }.into_any();
    }
    let key = StoredValue::new(server_id.clone());
    let enabled = server.is_some();
    let authentication = server
        .as_ref()
        .map(|row| row.authentication)
        .or_else(|| entry.as_ref().map(|row| row.auth))
        .unwrap_or(McpAdminAuthentication::None);
    let has_client = server.as_ref().is_some_and(|row| row.has_credential);
    let oauth = authentication == McpAdminAuthentication::UserOAuth;
    let personal_connected = data
        .connections
        .connections
        .iter()
        .any(|row| row.server_id == server_id);
    let callback = data.page.redirect_uri.clone();
    let callback_available = callback.is_some();
    let callback = StoredValue::new(callback);
    let connecting = RwSignal::new(false);
    let connect_error = RwSignal::new(false);
    let server = StoredValue::new(server);
    let add = move |_| {
        let id = key.get_value();
        actions.launch(
            id.clone(),
            async move { api::add_curated(&id).await },
            |_| {},
        );
    };
    let refresh = move |_| {
        let id = key.get_value();
        actions.launch(id.clone(), async move { api::refresh(&id).await }, |_| {});
    };
    view! {
        <section class="ob-plugin-controls">
            <h2 class="text-lg">{move || t!(i18n, plugins.deployment)}</h2>
            <p class="text-fg-secondary">{move || if enabled { t_string!(i18n, plugins.enabled).to_owned() } else { t_string!(i18n, plugins.disabled).to_owned() }}</p>
            <Show when=move || !enabled>
                <Button id="plugin-enable" variant=ButtonVariant::Primary disabled=actions.busy on_activate=add>{move || t!(i18n, plugins.enable)}</Button>
            </Show>
            <Show when=move || enabled>
                <Button id="plugin-remove" variant=ButtonVariant::DangerText disabled=actions.busy
                    on_activate=move |_| editor.open("plugin-delete", Some(key.get_value()))>{move || t!(i18n, plugins.remove)}</Button>
            </Show>
        </section>
        <Show when=move || enabled>
            <PageSection heading_id="plugin-connection" title=move || t_string!(i18n, plugins.connection).to_owned()>
                <p class="text-fg-secondary">{move || match authentication {
                    McpAdminAuthentication::UserOAuth => t_string!(i18n, plugins.auth_personal).to_owned(),
                    McpAdminAuthentication::DeploymentBearer => t_string!(i18n, plugins.auth_bearer).to_owned(),
                    McpAdminAuthentication::None => t_string!(i18n, plugins.auth_none).to_owned(),
                }}</p>
                <Button id="plugin-oauth-client" disabled=Signal::derive(move || actions.busy.get() || !callback_available) on_activate=move |_| editor.open("plugin-oauth", Some(key.get_value()))>
                    {move || t!(i18n, plugins.oauth_client)}
                </Button>
                <Show when=move || oauth && has_client>
                    <p class="text-fg-secondary">{move || if personal_connected { t_string!(i18n, plugins.personal_connected).to_owned() } else { t_string!(i18n, plugins.personal_separate).to_owned() }}</p>
                    <Show when=move || !personal_connected>
                        <Button disabled=Signal::derive(move || actions.busy.get() || connecting.get() || !callback_available)
                            on_activate=move |_| connect_own_account(key.get_value(), connecting, connect_error)>{move || t!(i18n, plugins.personal_connect)}</Button>
                    </Show>
                    <Show when=move || key.get_value() == "google-drive">
                        <div class="ob-plugin-controls">
                            <a class="ob-button" data-size="md" data-variant="secondary" href=api::account_href(&key.get_value()).expect("validated server")>{move || t!(i18n, plugins.personal_manage)}</a>
                        </div>
                    </Show>
                    <Show when=move || connect_error.get()><Notice tone=NoticeTone::Error>{move || t!(i18n, plugins.connect_error)}</Notice></Show>
                </Show>
                <Show when=move || !callback_available><Notice tone=NoticeTone::Caution>{move || t!(i18n, plugins.callback_unavailable)}</Notice></Show>
                {callback.get_value().map(|uri| view! { <div class="ob-plugin-value"><span>{move || t!(i18n, plugins.redirect_uri)}</span><code>{uri}</code></div> })}
            </PageSection>
            {server.get_value().map(|server| view! { <ServerFacts server /> })}
            <PageSection heading_id="plugin-tools" title=move || t_string!(i18n, plugins.tools).to_owned()>
                <Button id="plugin-refresh" disabled=actions.busy on_activate=refresh>{move || t!(i18n, plugins.refresh)}</Button>
                {server.get_value().map(|server| {
                    if server.tools.is_empty() { view! { <PageEmpty>{move || t!(i18n, plugins.no_tools)}</PageEmpty> }.into_any() }
                    else { view! { <PageRows>{server.tools.into_iter().map(|tool| { let count=tool.granted_to.len(); view! {
                        <PluginLink href=api::tool_href(&tool.server_id, &tool.name).expect("validated tool")
                            title=tool.name description=tool.description suffix=move || t_string!(i18n, plugins.grant_count, count=count).to_owned() />
                    }}).collect_view()}</PageRows> }.into_any() }
                })}
            </PageSection>
        </Show>
    }.into_any()
}

#[component]
fn ServerFacts(server: McpAdminServer) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <div class="ob-plugin-value"><span>{move || t!(i18n, plugins.endpoint)}</span><code>{server.url}</code></div>
        <div class="ob-plugin-value"><span>{move || t!(i18n, plugins.private_egress)}</span><code>{if server.egress_allow_cidrs.is_empty() { "—".to_owned() } else { server.egress_allow_cidrs.join(", ") }}</code></div>
        {server.last_error.map(|_| view! { <Notice tone=NoticeTone::Error>{move || t!(i18n, plugins.catalog_error)}</Notice> })}
    }
}

#[component]
fn PluginTool(data: PluginData, server_id: String, tool_name: String) -> impl IntoView {
    let i18n = use_i18n();
    let tool = data
        .page
        .servers
        .iter()
        .find(|server| server.id == server_id)
        .and_then(|server| server.tools.iter().find(|tool| tool.name == tool_name))
        .cloned();
    let Some(tool) = tool else {
        return view! { <PageEmpty>{move || t!(i18n, plugins.tool_missing)}</PageEmpty> }
            .into_any();
    };
    let effect = tool.effect;
    let description = tool.description.clone();
    view! {
        <PageTopbar><PageBackLink href=api::plugin_href(&server_id).expect("validated id") label=server_id /></PageTopbar>
        <PageSection heading_id="plugin-tool-effect" title=move || t_string!(i18n, plugins.effect).to_owned()>
            <p>{description}</p><p class="text-fg-secondary">{move || effect_label(i18n, effect)}</p>
        </PageSection>
        <PageSection heading_id="plugin-tool-agents" title=move || t_string!(i18n, plugins.agents).to_owned()
            description=move || t_string!(i18n, plugins.grants_intro).to_owned()>
            {if data.agents.is_empty() { view! { <PageEmpty>{move || t!(i18n, plugins.no_agents)}</PageEmpty> }.into_any() }
            else { view! { <PageRows>{data.agents.into_iter().map(|agent| view! { <ToolGrantRow agent tool=tool.clone() /> }).collect_view()}</PageRows> }.into_any() }}
        </PageSection>
    }.into_any()
}

fn effect_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    effect: McpAdminToolEffect,
) -> String {
    match effect {
        McpAdminToolEffect::Read => t_string!(i18n, plugins.effect_read).to_owned(),
        McpAdminToolEffect::Write => t_string!(i18n, plugins.effect_write).to_owned(),
        McpAdminToolEffect::Execute => t_string!(i18n, plugins.effect_execute).to_owned(),
        McpAdminToolEffect::Network => t_string!(i18n, plugins.effect_network).to_owned(),
        McpAdminToolEffect::Credential => t_string!(i18n, plugins.effect_credential).to_owned(),
    }
}

fn connect_own_account(id: String, pending: RwSignal<bool>, error: RwSignal<bool>) {
    if pending.get_untracked() {
        return;
    }
    pending.set(true);
    error.set(false);
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        let result = api::begin_connection(&id).await;
        match result {
            Ok(url) => {
                let navigated = web_sys::window()
                    .is_some_and(|window| window.location().set_href(&url).is_ok());
                if !navigated {
                    error.set(true);
                    pending.set(false);
                }
            }
            Err(_) => {
                error.set(true);
                pending.set(false);
            }
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = id;
        error.set(true);
        pending.set(false);
    }
}

#[component]
fn ToolGrantRow(agent: AgentProfile, tool: McpAdminTool) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let granted = tool.granted_to.iter().any(|id| id == agent.id.as_str());
    let checked = RwSignal::new(granted);
    let label = StoredValue::new(format!("{} · {}", agent.name, tool.name));
    let remote_missing_callback = agent.endpoint.is_some() && !agent.has_callback_token;
    let target = tool.server_id;
    let agent_id = agent.id.as_str().to_owned();
    let control_id = format!("plugin-grant-{agent_id}");
    let reference = tool.reference;
    let on_change = UnsyncCallback::new(move |enabled| {
        checked.set(granted); // Authority receipt/refetch, never an optimistic grant.
        let (reference, agent_id) = (reference.clone(), agent_id.clone());
        actions.launch(
            target.clone(),
            async move { api::set_grant(&reference, &agent_id, enabled).await },
            |_| {},
        );
    });
    view! { <div class="ob-plugin-grant">
        <div class="ob-plugin-copy"><strong>{agent.name}</strong><span class="text-fg-secondary">{move || {
            if !granted { t_string!(i18n, plugins.not_granted).to_owned() }
            else if remote_missing_callback { t_string!(i18n, plugins.callback_missing).to_owned() }
            else { t_string!(i18n, plugins.granted).to_owned() }
        }}</span></div>
        <Switch id=control_id checked aria_label=move || label.get_value() disabled=actions.busy on_change />
    </div> }
}
