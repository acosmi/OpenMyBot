//! One action area per transcript message. An action this message cannot use is not rendered
//! (UI spec v5.2 §7.5).

use leptos::prelude::*;

use super::artifacts::{ArtifactMessageActions, ArtifactSourceObserver};
use crate::i18n::{t, use_i18n};
use crate::primitives::{Button, ButtonSize, ButtonVariant, MessageFooter};

/// The message footer with its actions, or nothing when the message offers none.
#[component]
pub(crate) fn MessageActions(
    /// Review this message for memory; absent when it cannot be remembered.
    #[prop(optional_no_strip)]
    on_remember: Option<UnsyncCallback<()>>,
    /// The message and its conversation, for "save as artifact"; the action shows only while
    /// this message can be saved or has a save in progress.
    #[prop(optional_no_strip)]
    artifact: Option<(String, ArtifactSourceObserver)>,
) -> impl IntoView {
    let i18n = use_i18n();
    let artifact = StoredValue::new(artifact);
    let saving_offered = Signal::derive(move || {
        artifact.with_value(|artifact| {
            artifact
                .as_ref()
                .is_some_and(|(message, source)| source.offers_save(message))
        })
    });
    view! {
        <Show when=move || on_remember.is_some() || saving_offered.get()>
            <MessageFooter>
                {on_remember.map(|run| view! {
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=run>
                        {move || t!(i18n, memory.remember_action)}
                    </Button>
                })}
                <Show when=move || saving_offered.get()>
                    {move || artifact.get_value().map(|(message_id, source)| view! {
                        <ArtifactMessageActions message_id source/>
                    })}
                </Show>
            </MessageFooter>
        </Show>
    }
}
