//! One channel roster row with bounded same-origin navigation.

use leptos::prelude::*;
use openbot_contracts::command::ChannelSummary;

use crate::api::channel_route_href;
use crate::primitives::Timestamp;

/// Rich channel navigation row used inside the shared Sidebar children.
#[component]
pub fn ChannelRow(
    /// Authoritative roster projection.
    channel: ChannelSummary,
    /// Whether its destination is the current route.
    #[prop(into)]
    current: MaybeProp<bool>,
) -> impl IntoView {
    let href = channel_route_href(channel.id.as_str()).expect("server channel id is route-safe");
    let visible_name = channel.name;
    let last_message = channel.last_message.unwrap_or_default();
    let timestamp = channel.last_message_at;
    let description = format!("{visible_name} — {last_message}");
    view! {
        <li class="ob-sidebar-list-item">
            <a
                class="ob-channel-row"
                href=href
                title=description
                aria-current=move || current.get().unwrap_or(false).then_some("page")
                data-state=move || current.get().unwrap_or(false).then_some("current")
            >
                <span class="ob-channel-copy">
                    <span class="ob-channel-heading">
                        <span class="ob-channel-name">{visible_name}</span>
                        {timestamp.map(|at| view! {
                            <span class="ob-channel-time"><Timestamp at /></span>
                        })}
                    </span>
                    <span class="ob-channel-preview">{last_message}</span>
                </span>
            </a>
        </li>
    }
}
