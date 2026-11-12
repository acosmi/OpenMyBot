//! Native human-in-the-loop Approval and Choice renderers.

use leptos::prelude::*;
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME,
    COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES, ComponentApprovalAnswer, ComponentApprovalDecision,
    ComponentChoiceAnswer, ComponentHumanDecisionAnswer, validate_component_human_decision_answer,
    validate_component_human_decision_arguments,
};
use openbot_contracts::text::trim_ecmascript;
use serde_json::{Map, Value};

use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, IconSize, IconView, Input, Notice, NoticePresentation,
    NoticeTone,
};

use super::{GalleryBadge, GalleryFrame, GalleryTone, RefusedCard};

#[derive(Clone)]
struct ApprovalDetail {
    key: usize,
    label: String,
    value: String,
}

#[derive(Clone)]
struct ChoiceOption {
    id: String,
    label: String,
    description: Option<String>,
}

/// Render one validated pending or completed human-decision component.
#[component]
pub fn HumanDecisionCard(
    name: String,
    arguments: Value,
    answer: Signal<Option<ComponentHumanDecisionAnswer>>,
    submitting: Signal<bool>,
    error: Signal<bool>,
    #[prop(default=Signal::derive(|| false))] blocked: Signal<bool>,
    #[prop(optional)] on_answer: Option<UnsyncCallback<ComponentHumanDecisionAnswer>>,
) -> AnyView {
    let i18n = use_i18n();
    if validate_component_human_decision_arguments(&name, &arguments).is_err()
        || answer.get_untracked().is_some_and(|answer| {
            validate_component_human_decision_answer(&name, &arguments, &answer).is_err()
        })
    {
        return view! {
            <RefusedCard
                title=t_string!(i18n, gallery.decisions).to_owned()
                reason=t_string!(i18n, gallery.runtime_refused).to_owned()
            />
        }
        .into_any();
    }
    let object = arguments
        .as_object()
        .expect("validated decision arguments are an object");
    match name.as_str() {
        ASK_APPROVAL_COMPONENT_NAME => {
            approval_card(object, answer, submitting, error, blocked, on_answer)
        }
        ASK_CHOICE_COMPONENT_NAME => {
            choice_card(object, answer, submitting, error, blocked, on_answer)
        }
        _ => view! {
            <RefusedCard
                title=t_string!(i18n, gallery.decisions).to_owned()
                reason=t_string!(i18n, gallery.runtime_refused).to_owned()
            />
        }
        .into_any(),
    }
}

fn approval_card(
    object: &Map<String, Value>,
    answer: Signal<Option<ComponentHumanDecisionAnswer>>,
    submitting: Signal<bool>,
    error: Signal<bool>,
    blocked: Signal<bool>,
    on_answer: Option<UnsyncCallback<ComponentHumanDecisionAnswer>>,
) -> AnyView {
    let i18n = use_i18n();
    let title = string(object, "title");
    let summary = string(object, "summary");
    let details = object
        .get("details")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .enumerate()
        .map(|(key, detail)| ApprovalDetail {
            key,
            label: string(detail, "label"),
            value: string(detail, "value"),
        })
        .collect::<Vec<_>>();
    let details = StoredValue::new(details);
    let approve_label = StoredValue::new(optional_string(object, "approveLabel"));
    let decline_label = StoredValue::new(optional_string(object, "rejectLabel"));
    let note = RwSignal::new(String::new());
    let sending_decision = RwSignal::new(None::<ComponentApprovalDecision>);
    Effect::new(move |_| {
        if answer.get().is_some() || (error.get() && !submitting.get()) {
            sending_decision.set(None);
        }
    });
    let note_too_long = Signal::derive(move || {
        trim_ecmascript(&note.get()).len() > COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES
    });
    let disabled = Signal::derive(move || {
        blocked.get() || submitting.get() || answer.get().is_some() || note_too_long.get()
    });
    let answer_for_badge = answer;
    let action = view! {
        <div>
            {move || match answer_for_badge.get() {
                Some(ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {
                    decision: ComponentApprovalDecision::Approved,
                    ..
                })) => view! {
                    <GalleryBadge tone=GalleryTone::Positive>
                        {t!(i18n, gallery.decision_approved)}
                    </GalleryBadge>
                }.into_any(),
                Some(ComponentHumanDecisionAnswer::Approval(_)) => view! {
                    <GalleryBadge tone=GalleryTone::Negative>
                        {t!(i18n, gallery.decision_declined)}
                    </GalleryBadge>
                }.into_any(),
                _ => view! {
                    <GalleryBadge tone=GalleryTone::Caution>
                        {t!(i18n, gallery.decision_waiting)}
                    </GalleryBadge>
                }.into_any(),
            }}
        </div>
    }
    .into_any();
    let approve = on_answer;
    let decline = on_answer;
    view! {
        <GalleryFrame title=title action=action>
            <p class="ob-gallery-decision-summary">{summary}</p>
            <Show when=move || !details.get_value().is_empty()>
                <dl class="ob-gallery-decision-details">
                    <For
                        each=move || details.get_value()
                        key=|detail| detail.key
                        children=move |detail| view! {
                            <div class="ob-gallery-decision-detail">
                                <dt>{detail.label}</dt>
                                <dd>{detail.value}</dd>
                            </div>
                        }
                    />
                </dl>
            </Show>
            <Show when=move || answer.get().is_none()>
                <div class="ob-gallery-decision-controls">
                    <Input
                        value=note
                        aria_label=move || t_string!(i18n, gallery.decision_note_label).to_owned()
                        placeholder=move || t_string!(i18n, gallery.decision_note_placeholder).to_owned()
                        disabled
                        invalid=note_too_long
                    />
                    <Show when=move || note_too_long.get()>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            {move || t!(i18n, gallery.decision_note_too_long)}
                        </Notice>
                    </Show>
                    <Show when=move || error.get()>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            {move || t!(i18n, gallery.decision_answer_error)}
                        </Notice>
                    </Show>
                    <div class="ob-gallery-decision-actions">
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Small
                            disabled
                            on_activate=move |_| {
                                let Some(callback) = approve.as_ref() else { return; };
                                let note = trim_ecmascript(&note.get_untracked()).to_owned();
                                sending_decision.set(Some(ComponentApprovalDecision::Approved));
                                callback.run(ComponentHumanDecisionAnswer::Approval(
                                    ComponentApprovalAnswer {
                                        decision: ComponentApprovalDecision::Approved,
                                        note: (!note.is_empty()).then_some(note),
                                    },
                                ));
                            }
                        >
                            {move || if submitting.get()
                                && sending_decision.get()
                                    == Some(ComponentApprovalDecision::Approved)
                            {
                                t_string!(i18n, gallery.decision_sending).to_owned()
                            } else {
                                approve_label.get_value().unwrap_or_else(|| {
                                    t_string!(i18n, gallery.decision_approve).to_owned()
                                })
                            }}
                        </Button>
                        <Button
                            variant=ButtonVariant::DangerText
                            size=ButtonSize::Small
                            disabled
                            on_activate=move |_| {
                                let Some(callback) = decline.as_ref() else { return; };
                                let note = trim_ecmascript(&note.get_untracked()).to_owned();
                                sending_decision.set(Some(ComponentApprovalDecision::Declined));
                                callback.run(ComponentHumanDecisionAnswer::Approval(
                                    ComponentApprovalAnswer {
                                        decision: ComponentApprovalDecision::Declined,
                                        note: (!note.is_empty()).then_some(note),
                                    },
                                ));
                            }
                        >{move || if submitting.get()
                            && sending_decision.get()
                                == Some(ComponentApprovalDecision::Declined)
                        {
                            t_string!(i18n, gallery.decision_sending).to_owned()
                        } else {
                            decline_label.get_value().unwrap_or_else(|| {
                                t_string!(i18n, gallery.decision_decline).to_owned()
                            })
                        }}</Button>
                    </div>
                </div>
            </Show>
        </GalleryFrame>
    }
    .into_any()
}

fn choice_card(
    object: &Map<String, Value>,
    answer: Signal<Option<ComponentHumanDecisionAnswer>>,
    submitting: Signal<bool>,
    error: Signal<bool>,
    blocked: Signal<bool>,
    on_answer: Option<UnsyncCallback<ComponentHumanDecisionAnswer>>,
) -> AnyView {
    let i18n = use_i18n();
    let title = string(object, "title");
    let summary = optional_string(object, "summary").unwrap_or_default();
    let options = object
        .get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|option| ChoiceOption {
            id: string(option, "id"),
            label: string(option, "label"),
            description: optional_string(option, "description"),
        })
        .collect::<Vec<_>>();
    let selected = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        if error.get() && !submitting.get() {
            selected.set(None);
        }
    });
    let answer_for_badge = answer;
    let action = view! {
        <div>
            {move || if answer_for_badge.get().is_some() {
                view! {
                    <GalleryBadge tone=GalleryTone::Positive>
                        {t!(i18n, gallery.decision_answered)}
                    </GalleryBadge>
                }.into_any()
            } else {
                view! {
                    <GalleryBadge tone=GalleryTone::Caution>
                        {t!(i18n, gallery.decision_waiting)}
                    </GalleryBadge>
                }.into_any()
            }}
        </div>
    }
    .into_any();
    view! {
        <GalleryFrame title=title caption=summary action=action>
            <ul class="ob-gallery-choice-list">
                <For
                    each=move || options.clone()
                    key=|option| option.id.clone()
                    children=move |option| {
                        let answer_value = answer;
                        let selected_id = option.id.clone();
                        let callback = on_answer;
                        let callback_id = option.id.clone();
                        let callback_label = option.label.clone();
                        let keyboard_callback = on_answer;
                        let keyboard_id = option.id.clone();
                        let keyboard_label = option.label.clone();
                        view! {
                            <li>
                                <button
                                    type="button"
                                    class="ob-gallery-choice-option"
                                    data-selected=move || {
                                        let recorded = match answer_value.get() {
                                            Some(ComponentHumanDecisionAnswer::Choice(choice)) => {
                                                Some(choice.choice)
                                            }
                                            _ => None,
                                        };
                                        (recorded.as_deref() == Some(selected_id.as_str())
                                            || selected.get().as_deref() == Some(selected_id.as_str()))
                                            .then_some("true")
                                    }
                                    disabled=move || blocked.get() || answer_value.get().is_some() || submitting.get()
                                    on:click=move |_| {
                                        let Some(callback) = callback.as_ref() else { return; };
                                        selected.set(Some(callback_id.clone()));
                                        callback.run(ComponentHumanDecisionAnswer::Choice(
                                            ComponentChoiceAnswer {
                                                choice: callback_id.clone(),
                                                label: callback_label.clone(),
                                            },
                                        ));
                                    }
                                    on:keydown=move |event| {
                                        if !matches!(event.key().as_str(), "Enter" | " ")
                                            || answer_value.get_untracked().is_some()
                                            || submitting.get_untracked()
                                            || blocked.get_untracked()
                                        {
                                            return;
                                        }
                                        let Some(callback) = keyboard_callback.as_ref() else { return; };
                                        event.prevent_default();
                                        selected.set(Some(keyboard_id.clone()));
                                        callback.run(ComponentHumanDecisionAnswer::Choice(
                                            ComponentChoiceAnswer {
                                                choice: keyboard_id.clone(),
                                                label: keyboard_label.clone(),
                                            },
                                        ));
                                    }
                                >
                                    <span class="ob-gallery-choice-mark" aria-hidden="true">
                                        <IconView icon=Icon::Check size=IconSize::Inline />
                                    </span>
                                    <span class="ob-gallery-choice-copy">
                                        <strong>{option.label}</strong>
                                        {option.description.map(|description| view! {
                                            <span>{description}</span>
                                        })}
                                    </span>
                                </button>
                            </li>
                        }
                    }
                />
            </ul>
            <Show when=move || error.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                    {move || t!(i18n, gallery.decision_answer_error)}
                </Notice>
            </Show>
        </GalleryFrame>
    }
    .into_any()
}

fn string(object: &Map<String, Value>, field: &str) -> String {
    object
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Option<String> {
    object.get(field).and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_arguments_project_without_reordering_or_guessing() {
        let arguments = serde_json::json!({
            "title":"Choose",
            "summary":"Exact order",
            "options":[
                {"id":"b","label":"Beta"},
                {"id":"a","label":"Alpha","description":"Second"}
            ]
        });
        validate_component_human_decision_arguments(ASK_CHOICE_COMPONENT_NAME, &arguments).unwrap();
        let options = arguments["options"].as_array().unwrap();
        assert_eq!(options[0]["id"], "b");
        assert_eq!(options[1]["id"], "a");
        assert_eq!(COMPONENT_HUMAN_DECISION_NOTE_MAX_BYTES, 4096);
    }
}
