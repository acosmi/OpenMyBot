//! Channel history in the sidebar: the loaded channel list, its filter, paging and the live
//! activity subscription that reads it again.

#[cfg(any(target_arch = "wasm32", test))]
use std::collections::HashSet;

use leptos::prelude::*;
use leptos_router::hooks::use_location;
#[cfg(any(target_arch = "wasm32", test))]
use openbot_contracts::command::ChannelPage;
use openbot_contracts::command::ChannelSummary;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest};

use crate::api::channel_route_href;
#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
#[cfg(target_arch = "wasm32")]
use crate::api::list_channels;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Input, InputType, Notice,
    NoticePresentation, NoticeTone, SidebarGroup, SidebarGroupLabel, SidebarNavList, SidebarRow,
};

#[cfg(any(target_arch = "wasm32", test))]
const FIRST_RETRY_MS: u32 = 500;
#[cfg(any(target_arch = "wasm32", test))]
const MAX_RETRY_MS: u32 = 30_000;

/// The channel group. `search_open` is toggled by the sidebar header's filter button.
#[component]
pub(super) fn SidebarChannels(search_open: RwSignal<bool>) -> impl IntoView {
    let i18n = use_i18n();
    let location = use_location();
    let channels = RwSignal::new(Vec::<ChannelSummary>::new());
    let next_cursor = RwSignal::new(None::<String>);
    let search = RwSignal::new(String::new());
    let loading = RwSignal::new(true);
    let loading_more = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);

    install_roster_loader(
        reload_generation,
        channels,
        next_cursor,
        loading,
        load_error,
    );
    install_channel_socket(reload_generation);

    let visible_channels = Memo::new(move |_| filter_channels(&channels.get(), &search.get()));
    let retry =
        move |_| reload_generation.update(|generation| *generation = generation.saturating_add(1));
    let load_more = move |_| {
        let Some(cursor) = next_cursor.get_untracked() else {
            return;
        };
        if loading_more.get_untracked() {
            return;
        }
        loading_more.set(true);
        load_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match list_channels(Some(&cursor)).await {
                Ok(page) => match append_page(&channels.get_untracked(), page) {
                    Ok((merged, cursor)) => {
                        channels.set(merged);
                        next_cursor.set(cursor);
                    }
                    Err(()) => {
                        // Activity can reorder a row across a keyset boundary while paging.
                        // Recover from the authoritative first page instead of showing duplicates.
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    }
                },
                Err(_) => load_error.set(true),
            }
            loading_more.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = cursor;
            loading_more.set(false);
        }
    };

    view! {
        <SidebarGroup>
            <span hidden aria-hidden="true" data-roster-generation=move || reload_generation.get().to_string()></span>
            <div id="sidebar-history" class="ob-sidebar-group-heading" tabindex="-1">
                <SidebarGroupLabel>{move || t!(i18n, shell.nav_channels)}</SidebarGroupLabel>
                <a class="ob-sidebar-row-action" href="/channel/new" aria-label=move || t_string!(i18n, shell.new_channel).to_owned()>
                    <IconView icon=Icon::Plus size=IconSize::Inline />
                </a>
            </div>
            <div id="sidebar-search-panel" hidden=move || !search_open.get()>
                <Input value=search input_type=InputType::Search
                    aria_label=move || t_string!(i18n, channels.search_label).to_owned()
                    placeholder=move || t_string!(i18n, channels.search_placeholder) />
            </div>
            <Show when=move || loading.get()>
                <p class="ob-sidebar-loading" role="status">{move || t!(i18n, common.loading)}</p>
            </Show>
            <Show when=move || load_error.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                    <span>{move || t!(i18n, channels.load_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry>{move || t!(i18n, common.retry)}</Button>
                </Notice>
            </Show>
            <Show when=move || !search.get().trim().is_empty() && !loading.get() && visible_channels.get().is_empty()>
                <p class="ob-sidebar-search-empty" role="status">{move || t!(i18n, channels.no_match_title)}</p>
            </Show>
            <SidebarNavList>
                <For each=move || visible_channels.get() key=|channel| channel.id.clone()
                    children=move |channel| {
                        let href = channel_route_href(channel.id.as_str()).expect("server channel id is route-safe");
                        let row_location = location.clone();
                        let current_href = href.clone();
                        view! {
                            <SidebarRow
                                href
                                label=channel.name
                                secondary=channel.last_message
                                time=channel.last_message_at
                                current=Signal::derive(move || row_location.pathname.get() == current_href)
                            />
                        }
                    } />
            </SidebarNavList>
            <Show when=move || next_cursor.get().is_some() && search.get().trim().is_empty()>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Medium loading=loading_more on_activate=load_more>{move || t!(i18n, channels.load_more)}</Button>
            </Show>
        </SidebarGroup>
    }
}

fn filter_channels(channels: &[ChannelSummary], query: &str) -> Vec<ChannelSummary> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return channels.to_vec();
    }
    channels
        .iter()
        .filter(|channel| {
            channel.name.to_lowercase().contains(&needle)
                || channel
                    .last_message
                    .as_deref()
                    .is_some_and(|message| message.to_lowercase().contains(&needle))
        })
        .cloned()
        .collect()
}

#[cfg(any(target_arch = "wasm32", test))]
fn append_page(
    existing: &[ChannelSummary],
    page: ChannelPage,
) -> Result<(Vec<ChannelSummary>, Option<String>), ()> {
    let mut ids = HashSet::with_capacity(existing.len() + page.channels.len());
    let mut merged = Vec::with_capacity(existing.len() + page.channels.len());
    for channel in existing.iter().chain(&page.channels) {
        if !ids.insert(channel.id.clone()) {
            return Err(());
        }
        merged.push(channel.clone());
    }
    Ok((merged, page.next_cursor))
}

fn install_roster_loader(
    reload_generation: RwSignal<u64>,
    channels: RwSignal<Vec<ChannelSummary>>,
    next_cursor: RwSignal<Option<String>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let generation = reload_generation.get();
        loading.set(true);
        load_error.set(false);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = list_channels(None).await;
            if reload_generation.get_untracked() != generation {
                return;
            }
            match outcome {
                Ok(page) => match append_page(&[], page) {
                    Ok((loaded, cursor)) => {
                        channels.set(loaded);
                        next_cursor.set(cursor);
                    }
                    Err(()) => {
                        channels.set(Vec::new());
                        next_cursor.set(None);
                        load_error.set(true);
                    }
                },
                Err(_) => {
                    channels.set(Vec::new());
                    next_cursor.set(None);
                    load_error.set(true);
                }
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        reload_generation,
        channels,
        next_cursor,
        loading,
        load_error,
    );
}

fn install_channel_socket(reload_generation: RwSignal<u64>) {
    #[cfg(target_arch = "wasm32")]
    leptos::task::spawn_local_scoped_with_cancellation(async move {
        use futures_util::StreamExt as _;
        use gloo_net::websocket::{Message, futures::WebSocket};
        use openbot_contracts::command::ChannelActivityEvent;

        let mut retry = FIRST_RETRY_MS;
        loop {
            // Refetch first: the socket is an optimisation and has no replay cursor.
            reload_generation.update(|generation| *generation = generation.saturating_add(1));
            if is_tauri_host() {
                let handlers = DesktopStructuredHandlers::new(
                    move |event| match event {
                        AppEvent::ChannelActivity(_) => {
                            reload_generation
                                .update(|generation| *generation = generation.saturating_add(1));
                            true
                        }
                        AppEvent::ChannelStreamError { .. } => {
                            reload_generation
                                .update(|generation| *generation = generation.saturating_add(1));
                            false
                        }
                        AppEvent::Heartbeat { .. }
                        | AppEvent::ThreadRunEvent(_)
                        | AppEvent::ThreadStreamError { .. }
                        | AppEvent::ToolApprovalActivity(_)
                        | AppEvent::ToolApprovalStreamError { .. } => false,
                    },
                    move |_| {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    },
                    move || {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    },
                );
                match open_desktop_structured(SubscriptionRequest::ChannelActivity, handlers) {
                    Ok(connection) => {
                        retry = FIRST_RETRY_MS;
                        connection.finished().await;
                    }
                    Err(()) => {
                        wait_ms(retry).await;
                        retry = next_retry(retry);
                        continue;
                    }
                }
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            }
            let Some(url) = channel_socket_url() else {
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            let Ok(mut socket) = WebSocket::open_with_protocol(&url, "openbot.channel-activity.v1")
            else {
                wait_ms(retry).await;
                retry = next_retry(retry);
                continue;
            };
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text))
                        if serde_json::from_str::<ChannelActivityEvent>(&text).is_ok() =>
                    {
                        retry = FIRST_RETRY_MS;
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                    }
                    Ok(Message::Text(_) | Message::Bytes(_)) | Err(_) => {
                        reload_generation
                            .update(|generation| *generation = generation.saturating_add(1));
                        break;
                    }
                }
            }
            wait_ms(retry).await;
            retry = next_retry(retry);
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = reload_generation;
}

#[cfg(target_arch = "wasm32")]
fn channel_socket_url() -> Option<String> {
    let location = web_sys::window()?.location();
    let protocol = match location.protocol().ok()?.as_str() {
        "https:" => "wss:",
        "http:" => "ws:",
        _ => return None,
    };
    Some(format!(
        "{protocol}//{}/api/channels/events",
        location.host().ok()?
    ))
}

#[cfg(target_arch = "wasm32")]
async fn wait_ms(milliseconds: u32) {
    use wasm_bindgen_futures::JsFuture;

    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                &resolve,
                i32::try_from(milliseconds).unwrap_or(i32::MAX),
            );
        } else {
            _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    _ = JsFuture::from(promise).await;
}

#[cfg(any(target_arch = "wasm32", test))]
fn next_retry(current: u32) -> u32 {
    current.saturating_mul(2).min(MAX_RETRY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::ids::ChannelId;
    use time::macros::datetime;

    fn channel(id: &str, name: &str, message: Option<&str>) -> ChannelSummary {
        ChannelSummary {
            id: ChannelId::new(id),
            name: name.to_owned(),
            agent_ids: Vec::new(),
            last_message: message.map(str::to_owned),
            last_message_at: None,
            last_message_agent_id: None,
            created_at: datetime!(2026-08-26 00:00 UTC),
            thread_id: None,
            active: true,
        }
    }

    #[test]
    fn search_only_matches_visible_name_or_preview_and_empty_keeps_order() {
        let rows = vec![
            channel("a", "Finance", Some("Categorized expenses")),
            channel("b", "Research", Some("Read the report")),
        ];
        assert_eq!(filter_channels(&rows, " "), rows);
        assert_eq!(filter_channels(&rows, "FIN")[0].id.as_str(), "a");
        assert_eq!(filter_channels(&rows, "report")[0].id.as_str(), "b");
        assert!(filter_channels(&rows, "hidden history").is_empty());
    }

    #[test]
    fn page_append_rejects_duplicate_ids_and_retry_is_bounded() {
        let first = channel("a", "A", None);
        let second = channel("b", "B", None);
        let (merged, cursor) = append_page(
            std::slice::from_ref(&first),
            ChannelPage {
                channels: vec![second],
                next_cursor: Some("next".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(merged.len(), 2);
        assert_eq!(cursor.as_deref(), Some("next"));
        assert!(
            append_page(
                std::slice::from_ref(&first),
                ChannelPage {
                    channels: vec![first.clone()],
                    next_cursor: None,
                }
            )
            .is_err()
        );
        assert_eq!(FIRST_RETRY_MS, 500);
        assert_eq!(next_retry(500), 1_000);
        assert_eq!(next_retry(20_000), MAX_RETRY_MS);
        assert_eq!(next_retry(MAX_RETRY_MS), MAX_RETRY_MS);
    }
}
