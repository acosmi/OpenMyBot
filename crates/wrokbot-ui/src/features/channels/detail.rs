//! Real channel detail destination shell; full transcript/composer remains independently gated.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use openbot_contracts::command::ChannelDetail;

#[cfg(target_arch = "wasm32")]
use crate::api::load_channel;
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, use_i18n};
use crate::primitives::{Notice, NoticeTone};

use super::ChannelConversation;

/// Authenticated `/channel/:channel_id` destination backed by real channel detail data.
#[component]
pub fn ChannelDetailPage() -> impl IntoView {
    let i18n = use_i18n();
    let params = use_params_map();
    let channel = RwSignal::new(None::<ChannelDetail>);
    let loading = RwSignal::new(true);
    let failed = RwSignal::new(false);
    install_detail_loader(params, channel, loading, failed);

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-channel-page">
            <a class="ob-conversation-back" href="/">{move || t!(i18n, common.back)}</a>
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || failed.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, channels.load_error)}</Notice>
            </Show>
            <Show when=move || channel.get().is_some()>
                {move || channel.get().map(|detail| view! {
                    <p class="ob-conversation-context" role="note">{detail.name.clone()}</p>
                    <ChannelConversation channel=detail />
                })}
            </Show>
            </div>
        </PageShell>
    }
}

fn install_detail_loader(
    params: Memo<leptos_router::params::ParamsMap>,
    channel: RwSignal<Option<ChannelDetail>>,
    loading: RwSignal<bool>,
    failed: RwSignal<bool>,
) {
    #[cfg(target_arch = "wasm32")]
    Effect::new(move |_| {
        let channel_id = params.read().get("channel_id");
        loading.set(true);
        failed.set(false);
        channel.set(None);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let Some(channel_id) = channel_id else {
                loading.set(false);
                failed.set(true);
                return;
            };
            match load_channel(&channel_id).await {
                Ok(detail) => channel.set(Some(detail)),
                Err(_) => failed.set(true),
            }
            loading.set(false);
        });
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (params, channel, loading, failed);
}
