//! Reviewed actor-owned OAuth connections at `/settings/connected-accounts`.

#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]

use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_query_map};
#[cfg(target_arch = "wasm32")]
use openbot_contracts::mcp::McpVendorRevocationStatus;
use openbot_contracts::mcp::{McpConnection, McpConnections};

#[cfg(target_arch = "wasm32")]
use crate::api::{begin_mcp_connection, disconnect_mcp_connection, load_mcp_connections};
use crate::features::layout::{
    PageEmpty, PageHeader, PageRows, PageSection, PageShell, PageWidth, RowMark,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Badge, BadgeTone, Button, ButtonSize, ButtonVariant, IconSize, IconView, Item, ItemAction,
    ItemActions, ItemDescription, ItemMedia, ItemTitle, Menu, MenuContent, MenuItem, MenuTrigger,
    Notice, NoticeTone, Timestamp,
};

const GOOGLE_DRIVE_SERVER_ID: &str = "google-drive";
const CONNECT_BUTTON_ID: &str = "connected-account-connect";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReviewedAccount {
    server_id: String,
    connection: Option<McpConnection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallbackNotice {
    Connected,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum DisconnectNotice {
    Revoked,
    Pending,
}

#[derive(Clone, Copy)]
struct ConnectionActionState {
    page: RwSignal<Option<McpConnections>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
    action_pending: RwSignal<bool>,
    action_error: RwSignal<bool>,
    notice: RwSignal<Option<DisconnectNotice>>,
    worker_owner: StoredValue<Option<Owner>>,
}

/// List only compile-time reviewed user-OAuth servers enabled by deployment administration.
#[component]
pub fn ConnectedAccountsPage() -> impl IntoView {
    let i18n = use_i18n();
    let query = use_query_map();
    let page = RwSignal::new(None::<McpConnections>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    install_connections_loader(reload_generation, page, loading, load_error);

    let accounts = Memo::new(move |_| {
        page.get()
            .as_ref()
            .map(reviewed_accounts)
            .unwrap_or_default()
    });
    let callback_notice = Memo::new(move |_| {
        let outcome = query.read().get("connected");
        resolve_callback_notice(outcome.as_deref(), &accounts.get())
    });
    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };

    view! {
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="connected-accounts-title"
                title=move || t_string!(i18n, settings.connected_accounts_title).to_owned()
                description=move || t_string!(i18n, settings.connected_accounts_description).to_owned()
            />
            <Show when=move || callback_notice.get() == Some(CallbackNotice::Failed)>
                <Notice tone=NoticeTone::Error>
                    {move || t!(i18n, settings.connect_failed)}
                </Notice>
            </Show>
            <Show when=move || callback_notice.get() == Some(CallbackNotice::Connected)>
                <Notice tone=NoticeTone::Success>
                    {move || t_string!(
                        i18n,
                        settings.connect_success,
                        account = t_string!(i18n, settings.google_drive_title),
                    ).to_owned()}
                </Notice>
            </Show>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, settings.connected_accounts_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || !loading.get() && !load_error.get()>
                <PageSection
                    heading_id="connected-accounts-section"
                    title=move || t_string!(i18n, settings.connector).to_owned()
                >
                    <Show
                        when=move || !accounts.get().is_empty()
                        fallback=move || view! {
                            <PageEmpty>
                                {move || t!(i18n, settings.connected_accounts_unavailable)}
                            </PageEmpty>
                        }
                    >
                        <PageRows>
                            <For
                                each=move || accounts.get()
                                key=|account| account.server_id.clone()
                                children=move |account| {
                                    let connected = account.connection.is_some();
                                    let href = connected_account_href(&account.server_id)
                                        .expect("reviewed connector id is a valid route segment");
                                    view! {
                                        <Item action=ItemAction::Link(href)>
                                            <ItemMedia>
                                                <RowMark>
                                                    <IconView icon=Icon::Plug size=IconSize::Navigation />
                                                </RowMark>
                                            </ItemMedia>
                                            <ItemTitle>
                                                {move || t!(i18n, settings.google_drive_title)}
                                            </ItemTitle>
                                            <ItemDescription>
                                                {move || t!(i18n, settings.google_drive_description)}
                                            </ItemDescription>
                                            <ItemActions>
                                                <Badge tone=if connected {
                                                    BadgeTone::Success
                                                } else {
                                                    BadgeTone::Neutral
                                                }>
                                                    {move || if connected {
                                                        t_string!(i18n, settings.connected).to_owned()
                                                    } else {
                                                        t_string!(i18n, settings.not_connected).to_owned()
                                                    }}
                                                </Badge>
                                            </ItemActions>
                                        </Item>
                                    }
                                }
                            />
                        </PageRows>
                    </Show>
                </PageSection>
            </Show>
        </PageShell>
    }
}

/// Detail, full-page OAuth launch, scope facts and local-first disconnect for one reviewed server.
#[component]
pub fn ConnectedAccountDetailPage() -> impl IntoView {
    let i18n = use_i18n();
    let params = use_params_map();
    let page = RwSignal::new(None::<McpConnections>);
    let loading = RwSignal::new(true);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    let action_pending = RwSignal::new(false);
    let action_error = RwSignal::new(false);
    let disconnect_notice = RwSignal::new(None::<DisconnectNotice>);
    let menu_open = RwSignal::new(false);
    let worker_owner = StoredValue::new(Owner::current());
    let action_state = ConnectionActionState {
        page,
        loading,
        load_error,
        action_pending,
        action_error,
        notice: disconnect_notice,
        worker_owner,
    };
    install_connections_loader(reload_generation, page, loading, load_error);

    let server_id = Memo::new(move |_| params.read().get("server_id"));
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::ToolConnections,
        move || server_id.get().unwrap_or_default(),
    );
    let account = Memo::new(move |_| {
        let server_id = server_id.get()?;
        reviewed_account(page.get().as_ref()?, &server_id)
    });
    let oauth_available = Memo::new(move |_| {
        page.get()
            .as_ref()
            .is_some_and(|page| page.redirect_uri.is_some())
    });
    let retry = move |_| {
        reload_generation.update(|generation| *generation = generation.saturating_add(1));
    };
    let connect = move |_| {
        let Some(server_id) = server_id.get_untracked() else {
            action_error.set(true);
            return;
        };
        dispatch_connect(server_id, action_pending, action_error, worker_owner);
    };
    let disconnect = move |_| {
        let Some(server_id) = server_id.get_untracked() else {
            action_error.set(true);
            return;
        };
        dispatch_disconnect(server_id, action_state);
    };

    view! {
        <PageShell width=PageWidth::Content>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error>
                    <span>{move || t!(i18n, settings.connected_accounts_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry
                    >
                        {move || t!(i18n, common.retry)}
                    </Button>
                </Notice>
            </Show>
            <Show when=move || !loading.get() && !load_error.get() && account.get().is_none()>
                <PageHeader
                    heading_id="connected-account-not-found"
                    title=move || t_string!(i18n, errors.not_found_title).to_owned()
                    description=move || t_string!(i18n, errors.not_found_body).to_owned()
                />
            </Show>
            <Show when=move || account.get().is_some()>
                <PageHeader
                    heading_id="connected-account-title"
                    title=move || t_string!(i18n, settings.google_drive_title).to_owned()
                    description=move || t_string!(i18n, settings.google_drive_description).to_owned()
                />
                <Show when=move || action_error.get()>
                    <Notice tone=NoticeTone::Error>
                        {move || t!(i18n, settings.connection_action_error)}
                    </Notice>
                </Show>
                <Show when=move || disconnect_notice.get() == Some(DisconnectNotice::Revoked)>
                    <Notice tone=NoticeTone::Success>
                        {move || t!(i18n, settings.disconnect_revoked)}
                    </Notice>
                </Show>
                <Show when=move || disconnect_notice.get() == Some(DisconnectNotice::Pending)>
                    <Notice tone=NoticeTone::Status>
                        {move || t!(i18n, settings.disconnect_pending)}
                    </Notice>
                </Show>
                <PageSection
                    heading_id="connected-account-access"
                    title=move || t_string!(i18n, settings.account_access).to_owned()
                >
                    <div class="ob-connected-account-card">
                        <Show
                            when=move || account.get().and_then(|account| account.connection).is_some()
                            fallback=move || view! {
                                <div class="ob-connected-account-disconnected">
                                    <div>
                                        <Badge tone=BadgeTone::Neutral>
                                            {move || t!(i18n, settings.not_connected)}
                                        </Badge>
                                        <p>{move || t!(i18n, settings.connect_description)}</p>
                                    </div>
                                    <Button
                                        id=CONNECT_BUTTON_ID
                                        variant=ButtonVariant::Primary
                                        size=ButtonSize::Medium
                                        disabled=Signal::derive(move || {
                                            action_pending.get() || write_lock.get() || !oauth_available.get()
                                        })
                                        loading=action_pending
                                        on_activate=connect
                                    >
                                        {move || t!(i18n, settings.connect)}
                                    </Button>
                                    <Show when=move || !oauth_available.get()>
                                        <p class="ob-connected-account-unavailable">
                                            {move || t!(i18n, settings.connect_unavailable)}
                                        </p>
                                    </Show>
                                </div>
                            }
                        >
                            {move || account.get().and_then(|account| account.connection).map(|connection| {
                                let connected_at = connection.connected_at;
                                let scope = connection.scope;
                                view! {
                                    <div class="ob-connected-account-card-header">
                                        <Badge tone=BadgeTone::Success>
                                            {move || t!(i18n, settings.connected)}
                                        </Badge>
                                        <div class="ob-connected-account-menu">
                                            <Menu id="connected-account-actions" open=menu_open>
                                                <MenuTrigger disabled=Signal::derive(move || action_pending.get() || write_lock.get())>
                                                    <IconView icon=Icon::Ellipsis size=IconSize::Inline />
                                                    <span class="ob-visually-hidden">
                                                        {move || t!(i18n, common.more_actions)}
                                                    </span>
                                                </MenuTrigger>
                                                <MenuContent>
                                                    <MenuItem
                                                        id="connected-account-disconnect"
                                                        disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                                                        on_select=disconnect
                                                    >
                                                        {move || t!(i18n, settings.disconnect)}
                                                    </MenuItem>
                                                </MenuContent>
                                            </Menu>
                                        </div>
                                    </div>
                                    <dl class="ob-connected-account-facts">
                                        <div>
                                            <dt>{move || t!(i18n, settings.scope)}</dt>
                                            <dd><code>{scope}</code></dd>
                                        </div>
                                        <div>
                                            <dt>{move || t!(i18n, settings.connection_time)}</dt>
                                            <dd><Timestamp at=connected_at /></dd>
                                        </div>
                                    </dl>
                                }
                            })}
                        </Show>
                    </div>
                </PageSection>
            </Show>
        </PageShell>
    }
}

fn install_connections_loader(
    reload_generation: RwSignal<u64>,
    page: RwSignal<Option<McpConnections>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = load_mcp_connections().await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match outcome {
                Ok(loaded) => page.set(Some(loaded)),
                Err(_) => {
                    page.set(None);
                    load_error.set(true);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (reload_generation, page, loading, load_error);
}

fn dispatch_connect(
    server_id: String,
    action_pending: RwSignal<bool>,
    action_error: RwSignal<bool>,
    worker_owner: StoredValue<Option<Owner>>,
) {
    if action_pending.get_untracked() {
        return;
    }
    action_pending.set(true);
    action_error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match begin_mcp_connection(&server_id).await {
                    Ok(authorization) => {
                        let navigated = web_sys::window().is_some_and(|window| {
                            window
                                .location()
                                .assign(&authorization.authorization_url)
                                .is_ok()
                        });
                        if navigated {
                            return;
                        }
                        action_error.set(true);
                    }
                    Err(_) => action_error.set(true),
                }
                action_pending.set(false);
            });
        };
        match worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (server_id, worker_owner);
        action_pending.set(false);
        action_error.set(true);
    }
}

fn dispatch_disconnect(server_id: String, state: ConnectionActionState) {
    let ConnectionActionState {
        page,
        loading,
        load_error,
        action_pending,
        action_error,
        notice,
        worker_owner,
    } = state;
    if action_pending.get_untracked() {
        return;
    }
    action_pending.set(true);
    action_error.set(false);
    notice.set(None);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match disconnect_mcp_connection(&server_id).await {
                    Ok(receipt) => {
                        notice.set(Some(match receipt.vendor_revocation {
                            McpVendorRevocationStatus::Revoked => DisconnectNotice::Revoked,
                            McpVendorRevocationStatus::Pending => DisconnectNotice::Pending,
                        }));
                        loading.set(true);
                        load_error.set(false);
                        let focus_connect = match load_mcp_connections().await {
                            Ok(loaded) => {
                                page.set(Some(loaded));
                                true
                            }
                            Err(_) => {
                                page.set(None);
                                load_error.set(true);
                                false
                            }
                        };
                        loading.set(false);
                        action_pending.set(false);
                        if focus_connect {
                            restore_focus(CONNECT_BUTTON_ID);
                        }
                    }
                    Err(_) => {
                        action_error.set(true);
                        action_pending.set(false);
                    }
                }
            });
        };
        match worker_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (server_id, page, loading, load_error, worker_owner);
        action_pending.set(false);
        action_error.set(true);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn restore_focus(id: &'static str) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use wasm_bindgen::JsCast as _;

        leptos::task::tick().await;
        if let Some(element) = web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id(id))
            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
        {
            _ = element.focus();
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = id;
}

fn reviewed_accounts(page: &McpConnections) -> Vec<ReviewedAccount> {
    page.available_server_ids
        .iter()
        .filter(|server_id| server_id.as_str() == GOOGLE_DRIVE_SERVER_ID)
        .map(|server_id| ReviewedAccount {
            server_id: server_id.clone(),
            connection: page
                .connections
                .iter()
                .find(|connection| connection.server_id == *server_id)
                .cloned(),
        })
        .collect()
}

fn reviewed_account(page: &McpConnections, server_id: &str) -> Option<ReviewedAccount> {
    reviewed_accounts(page)
        .into_iter()
        .find(|account| account.server_id == server_id)
}

fn resolve_callback_notice(
    outcome: Option<&str>,
    accounts: &[ReviewedAccount],
) -> Option<CallbackNotice> {
    match outcome {
        Some("failed") => Some(CallbackNotice::Failed),
        Some(server_id)
            if accounts
                .iter()
                .any(|account| account.server_id == server_id && account.connection.is_some()) =>
        {
            Some(CallbackNotice::Connected)
        }
        _ => None,
    }
}

fn connected_account_href(server_id: &str) -> Option<String> {
    (server_id == GOOGLE_DRIVE_SERVER_ID)
        .then(|| format!("/settings/connected-accounts/{server_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn page() -> McpConnections {
        McpConnections {
            available_server_ids: vec![
                GOOGLE_DRIVE_SERVER_ID.to_owned(),
                "unreviewed-custom".to_owned(),
            ],
            connections: vec![
                McpConnection {
                    server_id: GOOGLE_DRIVE_SERVER_ID.to_owned(),
                    scope: "drive.readonly".to_owned(),
                    connected_at: OffsetDateTime::UNIX_EPOCH,
                },
                McpConnection {
                    server_id: "unreviewed-custom".to_owned(),
                    scope: "custom".to_owned(),
                    connected_at: OffsetDateTime::UNIX_EPOCH,
                },
            ],
            redirect_uri: None,
        }
    }

    #[test]
    fn projection_joins_actor_connection_but_never_surfaces_unknown_servers() {
        let accounts = reviewed_accounts(&page());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].server_id, GOOGLE_DRIVE_SERVER_ID);
        assert!(accounts[0].connection.is_some());
        assert!(reviewed_account(&page(), "unreviewed-custom").is_none());
        assert_eq!(
            connected_account_href(GOOGLE_DRIVE_SERVER_ID).as_deref(),
            Some("/settings/connected-accounts/google-drive")
        );
        assert!(connected_account_href("unreviewed-custom").is_none());
    }

    #[test]
    fn callback_success_requires_the_authoritative_connection_projection() {
        let accounts = reviewed_accounts(&page());
        assert_eq!(
            resolve_callback_notice(Some(GOOGLE_DRIVE_SERVER_ID), &accounts),
            Some(CallbackNotice::Connected)
        );
        assert_eq!(
            resolve_callback_notice(Some("failed"), &accounts),
            Some(CallbackNotice::Failed)
        );
        assert_eq!(
            resolve_callback_notice(Some("unreviewed-custom"), &accounts),
            None
        );
    }
}
