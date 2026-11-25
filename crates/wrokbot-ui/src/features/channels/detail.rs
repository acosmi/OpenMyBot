//! Real channel detail destination shell; full transcript/composer remains independently gated.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use openbot_contracts::command::ChannelDetail;

#[cfg(target_arch = "wasm32")]
use crate::api::load_channel;
use crate::features::agents::use_agent_directory;
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, use_i18n};
use crate::primitives::{Notice, NoticeTone};
use crate::shell::layout::set_shell_title;

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
    let directory = use_agent_directory();
    // The conversation signs replies with the assistant's name from the directory, so it waits
    // for the first directory read to finish. A failed read also mounts it, with the generic
    // assistant name, and once mounted no later read or retry unmounts it.
    let directory_settled = Memo::new(move |settled: Option<&bool>| {
        settled.copied().unwrap_or(false)
            || !directory.loading.get()
            || directory.agents.with(|agents| !agents.is_empty())
    });
    set_shell_title(move || {
        channel
            .with(|detail| detail.as_ref().map(|detail| detail.name.clone()))
            .into_iter()
            .collect()
    });

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-channel-page">
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || failed.get()>
                <Notice tone=NoticeTone::Error>{move || t!(i18n, channels.load_error)}</Notice>
            </Show>
            <Show when=move || channel.with(Option::is_some) && directory_settled.get()>
                {move || channel.get().map(|detail| view! { <ChannelConversation channel=detail /> })}
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
