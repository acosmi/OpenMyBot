//! Model-service settings. Personal custom inventory uses the authoritative management API.
mod form;
mod revision;
mod state;
use crate::api::model_connections::WriteError;
use crate::features::channels::composer::models::{DirectoryStatus, ModelDirectory};
use crate::{
    features::layout::{
        DetailPanel, DetailPanelLayout, DetailPanelMain, PageHeader, PageSection, PageShell,
        editor_location::EditorLocation,
    },
    i18n::{t, t_string, use_i18n},
    primitives::{Button, ButtonVariant, Notice, NoticeTone},
};
use form::{EditTarget, ModelDeleteDialog, ModelEditor};
use leptos::prelude::*;
pub(crate) use state::ModelActions;
use state::Status;

/// Personal custom-model management and first-release gateway/account integration status.
#[component]
pub fn ModelServicesPage() -> impl IntoView {
    let i18n = use_i18n();
    let editor = EditorLocation::new(&["model-new", "model-edit", "model-delete"]);
    let target = Memo::new(move |_| {
        let selected = editor.selection.get()?;
        match selected.kind {
            "model-new" => Some(EditTarget::Create),
            "model-edit" => selected.target.map(EditTarget::Edit),
            "model-delete" => selected.target.map(EditTarget::Delete),
            _ => None,
        }
    });
    let page_open = Signal::derive(move || {
        target
            .get()
            .is_some_and(|target| !matches!(target, EditTarget::Delete(_)))
    });
    let close = UnsyncCallback::new(move |_| editor.close());
    view! {
        <DetailPanelLayout open=page_open>
        <DetailPanelMain>
        <div id="model-services-focus" tabindex="-1">
        <PageShell>
            <PageHeader heading_id="model-services-title" title=move || t_string!(i18n, models.title).to_owned() description=move || t_string!(i18n, models.description).to_owned()/>
            <PageSection heading_id="model-gateway" title=move || t_string!(i18n, models.gateway).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.gateway_description)}</p>
                <p class="ob-preference-saving" role="status">{move || t!(i18n, models.gateway_pending)}</p>
                <Button variant=ButtonVariant::Chip disabled=true on_activate=move |_| {}>{move || t!(i18n, models.gateway_connect)}</Button>
            </PageSection>
            <PageSection heading_id="model-custom" title=move || t_string!(i18n, models.custom).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.custom_description)}</p>
                <CustomConnections editor/>
            </PageSection>
            <PageSection heading_id="model-accounts" title=move || t_string!(i18n, models.bridge).to_owned()>
                <p class="ob-page-intro">{move || t!(i18n, models.bridge_description)}</p>
                <p class="ob-preference-saving" role="status">{move || t!(i18n, models.bridge_pending)}</p>
                <Button variant=ButtonVariant::Chip disabled=true on_activate=move |_| {}>{move || t!(i18n, models.bridge_connect)}</Button>
            </PageSection>
            <PageSection heading_id="model-local" title=move || t_string!(i18n, models.local_title).to_owned()
                description=move || t_string!(i18n, models.local_description).to_owned()>
                <p class="ob-page-empty">{move || t!(i18n, models.local_pending)}</p>
            </PageSection>
        </PageShell>
        </div>
        </DetailPanelMain>
        <DetailPanel id="model-dialog" open=page_open return_focus_id="model-services-focus" on_close=close
            title=move || if target.get()==Some(EditTarget::Create) {t_string!(i18n, models.custom_add).to_owned()} else {t_string!(i18n, models.edit).to_owned()}>
            {move || target.get().filter(|target| !matches!(target, EditTarget::Delete(_)))
                .map(|target| view! { <ModelEditor target close/> })}
        </DetailPanel>
        {move || target.get().filter(|target| matches!(target, EditTarget::Delete(_)))
            .map(|target| view! { <ModelDeleteDialog target close/> })}
        </DetailPanelLayout>
    }
}

#[component]
fn CustomConnections(editor: EditorLocation) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ModelActions>();
    let directory = expect_context::<ModelDirectory>();
    if directory.status.get_untracked() == DirectoryStatus::Idle {
        directory.reload();
    }
    let reading = Signal::derive(move || {
        matches!(
            directory.status.get(),
            DirectoryStatus::Idle | DirectoryStatus::Loading
        )
    });
    let directory_ready = Signal::derive(move || directory.status.get() == DirectoryStatus::Ready);
    let locked = Signal::derive(move || !directory_ready.get() || actions.status.get().locked());
    let open = UnsyncCallback::new(move |selection| {
        if locked.get_untracked() {
            return;
        }
        actions.status.set(Status::Idle);
        match selection {
            EditTarget::Create => editor.open("model-new", None),
            EditTarget::Edit(id) => editor.open("model-edit", Some(id)),
            EditTarget::Delete(id) => editor.open("model-delete", Some(id)),
        }
    });
    view! {
        <p class="ob-page-intro">{move ||t!(i18n, models.saved_boundary)}</p>
        <Show when=move || actions.status.get()==Status::Pending><p role="status">{move ||t!(i18n, models.saving)}</p></Show>
        <Show when=move || actions.status.get()==Status::Saved><p role="status">{move ||t!(i18n, models.saved)}</p></Show>
        <Show when=move || matches!(actions.status.get(),Status::Failed(WriteError::Unknown))><Notice tone=NoticeTone::Error>{move ||t!(i18n, models.unknown)}</Notice></Show>
        <Button disabled=Signal::derive(move || reading.get() || actions.status.get()==Status::Pending) on_activate=move |_|directory.reload()>{move ||t!(i18n, models.refresh)}</Button>
        <Show when=move ||reading.get()><p role="status">{move ||t!(i18n, common.loading)}</p></Show>
        <Show when=move ||directory.status.get()==DirectoryStatus::Failed><Notice tone=NoticeTone::Error>{move ||t!(i18n, models.load_failed)}</Notice></Show>
        <Show when=move ||directory.status.get()==DirectoryStatus::Ready || !directory.rows.get().is_empty()>
            <Show when=move ||directory.status.get()==DirectoryStatus::Ready>
                <Button id="model-create" disabled=locked on_activate=move |_|open.run(EditTarget::Create)>{move ||t!(i18n, models.custom_add)}</Button>
            </Show>
            <Show when=move ||directory.rows.get().is_empty()><p class="ob-page-empty">{move ||t!(i18n, models.empty)}</p></Show>
            <div class="ob-page-rows">
                <For each=move ||directory.rows.get() key=|row| (row.id.clone(),row.revision) children=move |row| {
                    let edit_id=row.id.clone();let delete_id=row.id;
                    let label=match row.protocol {openbot_contracts::model_connections::CustomModelProtocol::OpenaiChatCompletions=>"OpenAI · Chat Completions",openbot_contracts::model_connections::CustomModelProtocol::OpenaiResponses=>"OpenAI · Responses",openbot_contracts::model_connections::CustomModelProtocol::AnthropicMessages=>"Anthropic · Messages"};
                    view! {<div class="ob-plugin-grant"><div class="ob-plugin-copy">
                        <strong>{row.name}</strong><span>{row.model}</span><span class="text-fg-secondary">{label}</span><span class="text-fg-muted">{row.endpoint}</span>
                        <span class="text-fg-secondary">{move || if row.enabled {t_string!(i18n,models.enabled).to_owned()} else {t_string!(i18n,models.disabled).to_owned()}}</span>
                        <span class="text-fg-muted">{move || if row.has_credential {t_string!(i18n,models.key_stored).to_owned()} else {t_string!(i18n,models.key_missing).to_owned()}}</span>
                        <div><Button disabled=locked on_activate=move |_|open.run(EditTarget::Edit(edit_id.clone()))>{move ||t!(i18n,models.edit)}</Button><Button variant=ButtonVariant::DangerText disabled=locked on_activate=move |_|open.run(EditTarget::Delete(delete_id.clone()))>{move ||t!(i18n,models.remove)}</Button></div>
                    </div></div>}
                }/>
            </div>
        </Show>
    }
}
