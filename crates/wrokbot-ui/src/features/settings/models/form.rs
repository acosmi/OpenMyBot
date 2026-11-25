//! Explicit personal model edits, with fresh row reads and DOM-owned write-only credentials.
use super::{ModelActions, Status};
use crate::{
    api::{
        ApiError,
        model_connections::{self as api, Write, WriteError},
    },
    i18n::{t, t_string, use_i18n},
    primitives::{
        Button, ButtonVariant, Dialog, DialogContent, Field, Input, InputType, Label, Notice,
        NoticePresentation, NoticeTone, SecretInput, SecretInputController, SecretInputPolicy,
        Select, SelectContent, SelectItem, SelectTrigger, Switch,
    },
};
use leptos::prelude::*;
use openbot_contracts::model_connections::*;

#[derive(Clone, PartialEq, Eq)]
pub(super) enum EditTarget {
    Create,
    Edit(String),
    Delete(String),
}

#[component]
pub(super) fn ModelDeleteDialog(target: EditTarget, close: UnsyncCallback<()>) -> impl IntoView {
    let i18n = use_i18n();
    let open = RwSignal::new(true);
    view! {
        <Dialog id="model-delete-dialog" open on_close=close>
            <DialogContent title=move ||t_string!(i18n, models.remove).to_owned()>
                <ModelEditor target close/>
            </DialogContent>
        </Dialog>
    }
}

#[component]
pub(super) fn ModelEditor(target: EditTarget, close: UnsyncCallback<()>) -> impl IntoView {
    let i18n = use_i18n();
    // The authenticated action can finish later, but a disposed editor cannot close its successor.
    let close = UnsyncCallback::new(move |_| close.run(()));
    let deleting = matches!(target, EditTarget::Delete(_));
    let current = LocalResource::new(move || {
        let target = target.clone();
        async move {
            match target {
                EditTarget::Create => Ok(None),
                EditTarget::Edit(id) | EditTarget::Delete(id) => api::get(&id).await.map(Some),
            }
        }
    });
    view! {
                <Suspense fallback=move || view! {<div class="ob-library-form"><p role="status">{move ||t!(i18n, common.loading)}</p></div>}>
                    {move || current.get().map(|result| match result {
                        Ok(Some(base)) if !deleting && base.has_credential => view! { <super::revision::ModelRevisionEditor base close/> }.into_any(),
                        Ok(base) => view! { <ModelForm base deleting close/> }.into_any(),
                        Err(_) => view! { <div class="ob-library-form"><Notice tone=NoticeTone::Error>{move ||t!(i18n, models.load_failed)}</Notice><Button on_activate=move |_| current.refetch()>{move ||t!(i18n, models.refresh)}</Button><Button on_activate=move |_|close.run(())>{move ||t!(i18n, common.close)}</Button></div> }.into_any()
                    })}
                </Suspense>
    }
}

#[component]
pub(super) fn ModelForm(
    base: Option<ModelConnection>,
    deleting: bool,
    close: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ModelActions>();
    let original = StoredValue::new(base.clone());
    let name = RwSignal::new(base.as_ref().map(|v| v.name.clone()).unwrap_or_default());
    let endpoint = RwSignal::new(
        base.as_ref()
            .map(|v| v.endpoint.clone())
            .unwrap_or_default(),
    );
    let model = RwSignal::new(base.as_ref().map(|v| v.model.clone()).unwrap_or_default());
    let protocol = RwSignal::new(Some(
        base.as_ref()
            .map(|v| v.protocol)
            .unwrap_or(CustomModelProtocol::OpenaiChatCompletions)
            .as_str()
            .to_owned(),
    ));
    let enabled = RwSignal::new(base.as_ref().is_none_or(|v| v.enabled));
    let select_open = RwSignal::new(false);
    let key = SecretInputController::new(16 * 1024, SecretInputPolicy::Authorization);
    let invalid = RwSignal::new(false);
    let blocked = Signal::derive(move || {
        actions.status.get().locked()
            || original.with_value(|row| {
                row.as_ref()
                    .is_some_and(|row| actions.metadata_hold(&row.id).is_some())
            })
            || matches!(
                actions.status.get(),
                Status::Failed(WriteError::Rejected(_))
            )
    });
    let key_required = Signal::derive(move || {
        original.with_value(|v| {
            v.as_ref().is_none_or(|v| {
                v.endpoint != endpoint.get()
                    || Some(v.protocol.as_str()) != protocol.get().as_deref()
                    || !v.has_credential
            })
        })
    });
    let save = move |_| {
        if blocked.get_untracked() {
            return;
        }
        let secret = key.take();
        let original = original.get_value();
        let input = if deleting {
            let Some(row) = original else {
                return;
            };
            Write::Delete(
                row.id,
                DeleteModelConnection {
                    expected_revision: row.revision,
                },
            )
        } else {
            let name = name.get_untracked().trim().to_owned();
            let endpoint = endpoint.get_untracked().trim().to_owned();
            let model = model.get_untracked().trim().to_owned();
            let protocol = match protocol.get_untracked().as_deref() {
                Some("openai_chat_completions") => CustomModelProtocol::OpenaiChatCompletions,
                Some("openai_responses") => CustomModelProtocol::OpenaiResponses,
                Some("anthropic_messages") => CustomModelProtocol::AnthropicMessages,
                _ => {
                    invalid.set(true);
                    return;
                }
            };
            if !api::valid_metadata(&name, &endpoint, &model) {
                invalid.set(true);
                return;
            }
            let api_key = if secret.is_empty() && !key_required.get_untracked() {
                None
            } else {
                match ModelApiKey::new(secret) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        invalid.set(true);
                        return;
                    }
                }
            };
            if let Some(row) = original {
                Write::Update(
                    row.id,
                    UpdateModelConnection {
                        expected_revision: row.revision,
                        name,
                        protocol,
                        endpoint,
                        model,
                        enabled: enabled.get_untracked(),
                        api_key,
                    },
                )
            } else {
                let Some(api_key) = api_key else {
                    invalid.set(true);
                    return;
                };
                Write::Create(CreateModelConnection {
                    name,
                    protocol,
                    endpoint,
                    model,
                    enabled: enabled.get_untracked(),
                    api_key,
                })
            }
        };
        invalid.set(false);
        actions.launch(input, move |ok| {
            if ok {
                let _ = close.try_run(());
            }
        });
    };
    view! {
        <div class="ob-library-form" class:ob-modal-body=deleting>
            <Show when=move || invalid.get() || matches!(actions.status.get(), Status::Failed(WriteError::InvalidInput))><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n, models.invalid)}</Notice></Show>
            <Show when=move || matches!(actions.status.get(), Status::Failed(WriteError::Rejected(ApiError::Conflict|ApiError::NotFound)))><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n, models.conflict)}</Notice></Show>
            <Show when=move || matches!(actions.status.get(), Status::Failed(WriteError::Rejected(ApiError::Unauthorized|ApiError::Forbidden)))><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n, models.authentication)}</Notice></Show>
            <Show when=move || matches!(actions.status.get(), Status::Failed(WriteError::Unknown))><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move ||t!(i18n, models.unknown)}</Notice></Show>
            <Show when=move || deleting fallback=move || view! {
                <Field control_id="model-name" label=move ||t_string!(i18n, models.name).to_owned() disabled=blocked><Input value=name/></Field>
                <div class="ob-field ob-model-protocol"><Label for_id="model-protocol">{move ||t!(i18n, models.protocol)}</Label>
                <Select id="model-protocol" value=protocol open=select_open disabled=blocked>
                    <SelectTrigger aria_label=move ||t_string!(i18n, models.protocol).to_owned() placeholder=move ||t_string!(i18n, models.protocol).to_owned()/>
                    <SelectContent>
                        <SelectItem id="model-chat-protocol" value="openai_chat_completions" label="OpenAI · Chat Completions">"OpenAI · Chat Completions"</SelectItem>
                        <SelectItem id="model-responses-protocol" value="openai_responses" label="OpenAI · Responses">"OpenAI · Responses"</SelectItem>
                        <SelectItem id="model-anthropic-protocol" value="anthropic_messages" label="Anthropic · Messages">"Anthropic · Messages"</SelectItem>
                    </SelectContent>
                </Select></div>
                <Field control_id="model-endpoint" label=move ||t_string!(i18n, models.endpoint).to_owned() description=move ||t_string!(i18n, models.endpoint_help).to_owned() disabled=blocked><Input value=endpoint input_type=InputType::Url/></Field>
                <Field control_id="model-identifier" label=move ||t_string!(i18n, models.identifier).to_owned() disabled=blocked><Input value=model/></Field>
                <Field control_id="model-api-key" label=move ||t_string!(i18n, models.key).to_owned() description=move ||if key_required.get() {t_string!(i18n, models.key_required).to_owned()} else {t_string!(i18n, models.key_keep).to_owned()} disabled=blocked><SecretInput controller=key/></Field>
                <Field control_id="model-enabled" label=move ||t_string!(i18n, models.enable_connection).to_owned() disabled=blocked><Switch checked=enabled/></Field>
                <p class="ob-page-intro">{move ||t!(i18n, models.saved_boundary)}</p>
            }>
                <p>{move || name.get()}</p><p class="ob-page-intro">{move ||t!(i18n, models.remove_help)}</p>
            </Show>
        </div>
        <div class="ob-library-form-actions" class:ob-modal-footer=deleting>
            <Button on_activate=move |_| {key.clear();close.run(());} >{move ||t!(i18n, common.close)}</Button>
            <Button id="model-confirm" variant=if deleting {ButtonVariant::DangerText} else {ButtonVariant::Primary} disabled=blocked loading=Signal::derive(move ||actions.status.get()==Status::Pending) on_activate=save>{move ||if deleting {t_string!(i18n, models.remove).to_owned()} else {t_string!(i18n, common.save).to_owned()}}</Button>
        </div>
    }
}
