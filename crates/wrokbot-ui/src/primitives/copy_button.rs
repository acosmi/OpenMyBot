//! Copy-to-clipboard button shared by code blocks and technical details.

use leptos::prelude::*;

use super::{Button, ButtonSize, ButtonVariant, Notice, NoticePresentation, NoticeTone};
use crate::i18n::{t, t_string, use_i18n};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyStatus {
    Ready,
    Pending,
    Copied,
    Failed,
}

/// Copy fixed text and report the real clipboard receipt; nothing copied is ever logged.
#[component]
pub fn CopyButton(
    /// Text placed on the clipboard.
    #[prop(into)]
    text: String,
) -> impl IntoView {
    let i18n = use_i18n();
    let status = RwSignal::new(CopyStatus::Ready);
    let source = StoredValue::new(text);
    let copy = move |_| {
        if status.get_untracked() == CopyStatus::Pending {
            return;
        }
        status.set(CopyStatus::Pending);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = copy_to_clipboard(&source.get_value()).await;
            status.try_set(if result.is_ok() {
                CopyStatus::Copied
            } else {
                CopyStatus::Failed
            });
        });
    };
    view! {
        <Button
            variant=ButtonVariant::Ghost
            size=ButtonSize::Small
            disabled=Signal::derive(move || status.get() == CopyStatus::Pending)
            on_activate=copy
        >
            {move || if status.get() == CopyStatus::Copied {
                t_string!(i18n, common.copied).to_owned()
            } else {
                t_string!(i18n, common.copy).to_owned()
            }}
        </Button>
        <Show when=move || status.get() == CopyStatus::Failed>
            <Notice tone=NoticeTone::Caution presentation=NoticePresentation::Inline>
                {move || t!(i18n, common.copy_error)}
            </Notice>
        </Show>
    }
}

/// Clipboard failure intentionally carries no browser error or copied content.
struct ClipboardUnavailable;

/// Await the actual clipboard receipt without logging copied content or browser errors.
async fn copy_to_clipboard(text: &str) -> Result<(), ClipboardUnavailable> {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;

        let window = web_sys::window().ok_or(ClipboardUnavailable)?;
        let clipboard = js_sys::Reflect::get(
            &window.navigator(),
            &wasm_bindgen::JsValue::from_str("clipboard"),
        )
        .map_err(|_| ClipboardUnavailable)?;
        if clipboard.is_null() || clipboard.is_undefined() {
            return Err(ClipboardUnavailable);
        }
        let write_text =
            js_sys::Reflect::get(&clipboard, &wasm_bindgen::JsValue::from_str("writeText"))
                .map_err(|_| ClipboardUnavailable)?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| ClipboardUnavailable)?;
        let promise = write_text
            .call1(&clipboard, &wasm_bindgen::JsValue::from_str(text))
            .map_err(|_| ClipboardUnavailable)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| ClipboardUnavailable)?;
        wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| ClipboardUnavailable)?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = text;
        Err(ClipboardUnavailable)
    }
}
