//! Collapsed technical details: raw identifiers, error codes and request ids stay available
//! without standing in for the human sentence next to them (UI spec v5.2 §7.5, §13.4).

use leptos::prelude::*;

use super::CopyButton;
use crate::i18n::{t, use_i18n};

/// Render a closed "Technical details" disclosure around raw values.
#[component]
pub fn TechnicalDetails(
    /// Plain text for the copy button; omitted when nothing in the details is worth copying.
    #[prop(optional, into)]
    copy: Option<String>,
    /// Raw values, usually `<code>` elements.
    children: Children,
) -> impl IntoView {
    let i18n = use_i18n();
    view! {
        <details class="ob-technical-details">
            <summary>{move || t!(i18n, common.technical_details)}</summary>
            <div class="ob-technical-details-body">
                {children()}
                {copy.map(|text| view! { <CopyButton text /> })}
            </div>
        </details>
    }
}
