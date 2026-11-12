//! The composer's control row shared by the four send entries (UI spec v5.2 §7.2, §7.3): small
//! buttons for the assistant, the model and the skills, each opening the one popup surface, and the
//! send/stop actions. Status never renders in this row; it goes to the `StatusSlot` above the
//! composer. Only DOM and feedback live here: what is sent stays with each entry.

use leptos::prelude::*;

use super::models::{ModelComposer, ModelPicker};
use super::skills::{SkillComposer, SkillPicker};
use super::status::SlotNotice;
use crate::features::bot_threads::model::{ModelComposerV2, ModelPickerV2};
use crate::i18n::{Locale, t_string};
use crate::icons::Icon;
use crate::primitives::{Button, ButtonSize, ButtonVariant, IconSize, IconView, NoticeTone};

/// Which model choice the entry submits with.
#[derive(Clone, Copy)]
pub(crate) enum ComposerModel {
    /// Channel entries: the v1 run model selection.
    Run(ModelComposer),
    /// The direct assistant: the v2 custom catalog selection of `SubmitThreadInput`.
    Direct(ModelComposerV2),
}

/// One composer action button.
#[derive(Clone, Copy)]
pub(crate) struct ComposerAction {
    pub(crate) disabled: Signal<bool>,
    pub(crate) loading: Signal<bool>,
    /// Accessible name; the send and stop buttons show only an icon.
    pub(crate) label: Signal<String>,
    pub(crate) run: UnsyncCallback<()>,
}

/// Notices the model and skill choices add to the entry's status slot, in this order.
pub(crate) fn choice_notices(
    i18n: leptos_i18n::I18nContext<Locale>,
    model: ComposerModel,
    skills: SkillComposer,
    locked: bool,
) -> Vec<SlotNotice> {
    let mut notices = match model {
        ComposerModel::Run(model) => model.status_notices(i18n, locked),
        ComposerModel::Direct(model) => (!model.supports_explicit.get())
            .then(|| {
                SlotNotice::new(
                    NoticeTone::Caution,
                    t_string!(i18n, bot_work.remote_assistant_unsupported),
                )
                .blocking()
            })
            .into_iter()
            .collect(),
    };
    if skills.invalid.get() {
        notices.push(SlotNotice::new(
            NoticeTone::Error,
            t_string!(i18n, skills.selection_invalid),
        ));
    }
    notices
}

/// The control row. Children, when given, are the assistant control.
#[component]
pub(crate) fn ComposerControls(
    model: ComposerModel,
    skills: SkillComposer,
    /// The entry's inputs are locked.
    disabled: Signal<bool>,
    send: ComposerAction,
    /// Replaces the send button while `visible` (channel run stop).
    #[prop(optional)]
    stop: Option<(Signal<bool>, ComposerAction)>,
    /// The direct assistant's "stop and take over", shown while `visible`.
    #[prop(optional)]
    take_over: Option<(Signal<bool>, ComposerAction)>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    let send_button = move || {
        view! {
            <Button
                variant=ButtonVariant::Primary
                size=ButtonSize::Medium
                disabled=send.disabled
                loading=send.loading
                on_activate=send.run
            >
                <IconView icon=Icon::ArrowUp size=IconSize::Navigation />
                <span class="ob-visually-hidden">{move || send.label.get()}</span>
            </Button>
        }
    };
    let action = match stop {
        Some((visible, stop)) => view! {
            <Show when=move || visible.get() fallback=send_button>
                <Button
                    variant=ButtonVariant::Ghost
                    size=ButtonSize::Medium
                    disabled=stop.disabled
                    loading=stop.loading
                    on_activate=stop.run
                >
                    <IconView icon=Icon::CircleStop size=IconSize::Inline />
                    <span class="ob-visually-hidden">{move || stop.label.get()}</span>
                </Button>
            </Show>
        }
        .into_any(),
        None => send_button().into_any(),
    };
    view! {
        <div class="ob-chat-controls">
            {children.map(|assistant| assistant())}
            {match model {
                ComposerModel::Run(model) => view! { <ModelPicker state=model disabled/> }.into_any(),
                ComposerModel::Direct(model) => view! { <ModelPickerV2 state=model disabled/> }.into_any(),
            }}
            <SkillPicker state=skills disabled/>
            {take_over.map(|(visible, take_over)| view! {
                <Show when=move || visible.get()>
                    <span class="ob-chat-takeover">
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Small
                            disabled=take_over.disabled
                            loading=take_over.loading
                            on_activate=take_over.run
                        >
                            <IconView icon=Icon::CircleStop size=IconSize::Inline />
                            <span>{move || take_over.label.get()}</span>
                        </Button>
                    </span>
                </Show>
            })}
            <span class="ob-chat-send">{action}</span>
        </div>
    }
}
