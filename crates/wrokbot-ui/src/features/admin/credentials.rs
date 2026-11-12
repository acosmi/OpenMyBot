//! Write-only credential inventory and lifecycle with bounded page state and shared admin writes.

use crate::api::credentials as api;
use crate::features::admin::plugins::PluginActions;
use crate::features::layout::{PageEmpty, PageHeader, PageRows, PageSection, PageShell};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonVariant, Dialog, DialogBody, DialogContent, DialogFooter, Field, Input, Notice,
    NoticePresentation, NoticeTone, SecretInput, SecretInputController, SecretInputPolicy,
    SecretInputStatus, Select, SelectContent, SelectItem, SelectTrigger, TechnicalDetails,
};
use leptos::prelude::*;
use openbot_contracts::credential_admin::{
    CredentialExternalRevocation, CredentialModelReference, CredentialPage, CredentialRecordKind,
    CredentialStatus, CredentialWrite, MAX_CREDENTIAL_SECRET_BYTES, ManualCredentialKind,
};

#[derive(Clone)]
enum CredentialDialog {
    Create(Option<CredentialModelReference>),
    Rotate(CredentialStatus),
    Revoke(CredentialStatus),
}

#[derive(Clone, Copy)]
struct PageState {
    #[cfg(target_arch = "wasm32")]
    owner: StoredValue<Option<Owner>>,
    page: RwSignal<Option<CredentialPage>>,
    cursor: RwSignal<Option<String>>,
    history: RwSignal<Vec<Option<String>>>,
    loading: RwSignal<bool>,
    failed: RwSignal<bool>,
    serial: RwSignal<u64>,
}

impl PageState {
    fn new() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            owner: StoredValue::new(Owner::current()),
            page: RwSignal::new(None),
            cursor: RwSignal::new(None),
            history: RwSignal::new(Vec::new()),
            loading: RwSignal::new(true),
            failed: RwSignal::new(false),
            serial: RwSignal::new(0),
        }
    }
    fn load(self) {
        self.serial.update(|value| *value = value.saturating_add(1));
        let serial = self.serial.get_untracked();
        self.loading.set(true);
        self.failed.set(false);
        self.page.set(None);
        let cursor = self.cursor.get_untracked();
        #[cfg(target_arch = "wasm32")]
        let actions = expect_context::<PluginActions>();
        #[cfg(target_arch = "wasm32")]
        if let Some(owner) = self.owner.try_get_value().flatten() {
            owner.with(|| {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let result = api::load(cursor.as_deref()).await;
                    if self.serial.try_get_untracked() != Some(serial) {
                        return;
                    }
                    match result {
                        Ok(page) => self.page.set(Some(page)),
                        Err(_) => self.failed.set(true),
                    }
                    self.loading.set(false);
                    if !actions.busy.get_untracked() {
                        actions.restore_focus();
                    }
                })
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (serial, cursor);
            self.failed.set(true);
            self.loading.set(false);
        }
    }
}

/// Deployment-admin credential configuration, rotation and honest local/vendor retirement state.
#[component]
pub fn AdminCredentialsPage() -> impl IntoView {
    let i18n = use_i18n();
    let state = PageState::new();
    let actions = expect_context::<PluginActions>();
    let dialog = RwSignal::new(None::<CredentialDialog>);
    let saved = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        let _ = actions.revision.get();
        state.load();
    });
    let next = move |_| {
        if let Some(cursor) = state.page.get_untracked().and_then(|p| p.next_cursor) {
            state.history.update(|history| {
                history.push(state.cursor.get_untracked());
                if history.len() > 32 {
                    history.remove(0);
                }
            });
            state.cursor.set(Some(cursor));
            state.load();
        }
    };
    let previous = move |_| {
        let mut history = state.history.get_untracked();
        if let Some(cursor) = history.pop() {
            state.history.set(history);
            state.cursor.set(cursor);
            state.load();
        }
    };
    view! {
        <PageShell>
            <PageHeader heading_id="credentials-title" title=move||t_string!(i18n,credentials.title).to_owned() description=move||t_string!(i18n,credentials.intro).to_owned()/>
            <div class="ob-page-primary-action"><Button id="credentials-add" variant=ButtonVariant::Primary disabled=actions.busy
                on_activate=move|_|dialog.set(Some(CredentialDialog::Create(state.page.get_untracked().and_then(|p|p.model_reference))))>{move||t!(i18n,credentials.add)}</Button></div>
            <Show when=move||actions.busy.get()&&!actions.unknown.get()><p role="status" class="ob-loading">{move||t!(i18n,plugins.saving)}</p></Show>
            <Show when=move||actions.failed.get()&&!actions.unknown.get()&&actions.target.get().is_some_and(|id|id.starts_with("credential:"))><Notice tone=NoticeTone::Error>{move||t!(i18n,plugins.write_error)}</Notice></Show>
            {move||saved.get().map(|id|view!{<Notice tone=NoticeTone::Status><span>{move||t!(i18n,credentials.saved)}</span><TechnicalDetails copy=id.clone()><code>{id}</code></TechnicalDetails></Notice>})}
            <Show when=move||state.loading.get()><p class="ob-loading" role="status">{move||t!(i18n,common.loading)}</p></Show>
            <Show when=move||state.failed.get()><Notice tone=NoticeTone::Error><span>{move||t!(i18n,credentials.load_error)}</span><Button on_activate=move|_|state.load()>{move||t!(i18n,common.retry)}</Button></Notice></Show>
            <PageSection heading_id="credentials-configured" title=move||t_string!(i18n,credentials.configured).to_owned()>
                {move||state.page.get().map(|page|if page.credentials.is_empty(){view!{<PageEmpty>{move||t!(i18n,credentials.empty)}</PageEmpty>}.into_any()}else{view!{<PageRows>{page.credentials.into_iter().map(|row|view!{<CredentialRow row dialog/>}).collect_view()}</PageRows>}.into_any()})}
            </PageSection>
            <div class="ob-plugin-controls">
                <Button disabled=Signal::derive(move||actions.busy.get()||state.loading.get()||state.cursor.get().is_none()) on_activate=move|_|{state.cursor.set(None);state.history.set(Vec::new());state.load();}>{move||t!(i18n,credentials.first_page)}</Button>
                <Button disabled=Signal::derive(move||actions.busy.get()||state.loading.get()||state.history.read().is_empty()) on_activate=previous>{move||t!(i18n,credentials.previous_page)}</Button>
                <Button disabled=Signal::derive(move||actions.busy.get()||state.loading.get()||state.page.get().and_then(|p|p.next_cursor).is_none()) on_activate=next>{move||t!(i18n,credentials.next_page)}</Button>
            </div>
        </PageShell>
        <CredentialForm dialog saved/>
    }
}

#[component]
fn CredentialRow(
    row: CredentialStatus,
    dialog: RwSignal<Option<CredentialDialog>>,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let row = StoredValue::new(row);
    let details = RwSignal::new(false);
    let active = row.with_value(|row| row.revoked_at.is_none());
    let manual = row.with_value(|row| row.kind.manual().is_some());
    let metadata =
        row.with_value(|row| serde_json::to_string_pretty(&row.metadata).unwrap_or_default());
    view! {
        <div class="ob-plugin-value">
            <strong>{row.with_value(|row|row.provider.clone())}</strong>
            <span>{move||kind_label(i18n,row.get_value().kind)}" · "{row.with_value(|row|row.key_id.clone())}" · "{move||if active{t_string!(i18n,credentials.active).to_owned()}else{t_string!(i18n,credentials.local_revoked).to_owned()}}</span>
            <code>{row.with_value(|row|row.id.clone())}</code>
            <span>{row.with_value(|row|format!("{} UTC",row.created_at.date()))}</span>
            <Show when=move||!active><p>{move||external_label(i18n,row.get_value().external_revocation)}</p></Show>
            <div class="ob-plugin-controls">
                <Show when=move||manual><Button id=row.with_value(|r|format!("credential-rotate-{}",r.id)) disabled=Signal::derive(move||actions.busy.get()||!active) on_activate=move|_|dialog.set(Some(CredentialDialog::Rotate(row.get_value())))>{move||t!(i18n,credentials.rotate)}</Button></Show>
                <Button id=row.with_value(|r|format!("credential-revoke-{}",r.id)) variant=ButtonVariant::DangerText disabled=Signal::derive(move||actions.busy.get()||!active) on_activate=move|_|dialog.set(Some(CredentialDialog::Revoke(row.get_value())))>{move||t!(i18n,credentials.revoke)}</Button>
                <Button open=details variant=ButtonVariant::Ghost on_activate=move|_|details.update(|value| *value = !*value)>{move||t!(i18n,credentials.metadata)}</Button>
            </div>
            <Show when=move||details.get()><pre class="ob-plugin-copy">{metadata.clone()}</pre></Show>
        </div>
    }
}

#[component]
fn CredentialForm(
    dialog: RwSignal<Option<CredentialDialog>>,
    saved: RwSignal<Option<String>>,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let open = RwSignal::new(false);
    let kind = RwSignal::new(Some("model".to_owned()));
    let kind_open = RwSignal::new(false);
    let provider = RwSignal::new(String::new());
    let key = RwSignal::new(String::new());
    let label = RwSignal::new(String::new());
    let secret =
        SecretInputController::new(MAX_CREDENTIAL_SECRET_BYTES, SecretInputPolicy::OpaqueToken);
    let invalid = RwSignal::new(false);
    let attempted = RwSignal::new(false);
    let authentication_needed = RwSignal::new(false);
    Effect::new(move |_| {
        let selected = dialog.get();
        open.set(selected.is_some());
        invalid.set(false);
        attempted.set(false);
        authentication_needed.set(false);
        secret.clear();
        kind_open.set(false);
        match selected {
            Some(CredentialDialog::Create(hint)) => {
                kind.set(Some("model".to_owned()));
                provider.set(
                    hint.as_ref()
                        .map_or("openai".to_owned(), |h| h.provider.clone()),
                );
                key.set(hint.map_or(String::new(), |h| h.key_id));
                label.set(String::new());
            }
            Some(CredentialDialog::Rotate(row) | CredentialDialog::Revoke(row)) => {
                kind.set(row.kind.manual().map(|k| k.as_str().to_owned()));
                provider.set(row.provider);
                key.set(row.key_id);
                label.set(
                    row.metadata
                        .get("label")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            None => {
                provider.set(String::new());
                key.set(String::new());
                label.set(String::new());
            }
        }
    });
    Effect::new(move |_| {
        kind.track();
        secret.clear();
    });
    let close = UnsyncCallback::new(move |_| {
        let id = match dialog.get_untracked() {
            Some(CredentialDialog::Rotate(row)) => format!("credential-rotate-{}", row.id),
            Some(CredentialDialog::Revoke(row)) => format!("credential-revoke-{}", row.id),
            _ => "credentials-add".to_owned(),
        };
        dialog.set(None);
        actions.return_to(&id);
    });
    let save = move |_| {
        if actions.busy.get_untracked() {
            return;
        }
        let secret_status = secret.validate();
        let secret_value = secret.take();
        invalid.set(false);
        attempted.set(true);
        authentication_needed.set(false);
        saved.set(None);
        let finish = move |ok| {
            if ok {
                dialog.try_set(None);
            }
        };
        let selected = dialog.get_untracked();
        if let Some(CredentialDialog::Revoke(row)) = selected {
            actions.launch(
                format!("credential:{}", row.id),
                async move {
                    let result = api::revoke(&row.id).await;
                    authentication_needed
                        .try_set(matches!(result, Err(crate::api::ApiError::Unauthorized)));
                    result
                },
                finish,
            );
            return;
        }
        let kind = match kind.get_untracked().as_deref() {
            Some("model") => ManualCredentialKind::Model,
            Some("connector") => ManualCredentialKind::Connector,
            Some("mcp") => ManualCredentialKind::Mcp,
            _ => {
                invalid.set(true);
                return;
            }
        };
        if secret_status != SecretInputStatus::Valid {
            invalid.set(true);
            return;
        }
        let (previous, mut metadata) = match selected {
            Some(CredentialDialog::Rotate(row)) => (Some(row.id), row.metadata),
            Some(CredentialDialog::Create(_)) => (None, serde_json::json!({})),
            _ => return,
        };
        let value = label.get_untracked();
        if let Some(meta) = metadata.as_object_mut() {
            if value.is_empty() {
                meta.remove("label");
            } else {
                meta.insert("label".to_owned(), serde_json::Value::String(value));
            }
        }
        let Ok(input) = CredentialWrite::new(
            kind,
            provider.get_untracked(),
            key.get_untracked(),
            metadata,
            secret_value,
        ) else {
            invalid.set(true);
            return;
        };
        let target = format!("credential:{}", previous.as_deref().unwrap_or("new"));
        actions.launch(
            target,
            async move {
                let result = api::save(previous.as_deref(), input).await;
                authentication_needed
                    .try_set(matches!(result, Err(crate::api::ApiError::Unauthorized)));
                let row = result?;
                saved.try_set(Some(row.id));
                Ok(())
            },
            finish,
        );
    };
    view! {
        <Dialog id="credential-dialog" open on_close=close>
            <DialogContent title=move||match dialog.get(){Some(CredentialDialog::Rotate(_))=>t_string!(i18n,credentials.rotate).to_owned(),Some(CredentialDialog::Revoke(_))=>t_string!(i18n,credentials.revoke).to_owned(),_=>t_string!(i18n,credentials.add).to_owned()}>
                <DialogBody>
                    <crate::configuration_writes::ConfigurationWriteNotice />
                    <Show when=move||invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move||t!(i18n,credentials.invalid)}</Notice></Show>
                    <Show when=move||attempted.get()&&actions.failed.get()&&!actions.unknown.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move||t!(i18n,plugins.write_error)}</Notice></Show>
                    <Show when=move||authentication_needed.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move||t!(i18n,credentials.authentication_needed)}</Notice></Show>
                    <Show when=move||matches!(dialog.get(),Some(CredentialDialog::Revoke(_))) fallback=move||view!{
                        <Select id="credential-kind" open=kind_open value=kind disabled=Signal::derive(move||actions.busy.get()||matches!(dialog.get(),Some(CredentialDialog::Rotate(_))))>
                            <SelectTrigger aria_label=move||t_string!(i18n,credentials.kind).to_owned() placeholder=move||t_string!(i18n,credentials.kind).to_owned()/>
                            <SelectContent>
                                <SelectItem id="credential-kind-model" value="model" label=move||t_string!(i18n,credentials.kind_model).to_owned()>{move||t!(i18n,credentials.kind_model)}</SelectItem>
                                <SelectItem id="credential-kind-connector" value="connector" label=move||t_string!(i18n,credentials.kind_connector).to_owned()>{move||t!(i18n,credentials.kind_connector)}</SelectItem>
                                <SelectItem id="credential-kind-mcp" value="mcp" label=move||t_string!(i18n,credentials.kind_mcp).to_owned()>{move||t!(i18n,credentials.kind_mcp)}</SelectItem>
                            </SelectContent>
                        </Select>
                        <Field control_id="credential-provider" label=move||t_string!(i18n,credentials.provider).to_owned() description=move||t_string!(i18n,credentials.provider_help).to_owned() disabled=Signal::derive(move||actions.busy.get()||matches!(dialog.get(),Some(CredentialDialog::Rotate(_))))><Input value=provider/></Field>
                        <Field control_id="credential-key" label=move||t_string!(i18n,credentials.key).to_owned() description=move||t_string!(i18n,credentials.key_help).to_owned() disabled=actions.busy><Input value=key/></Field>
                        <Field control_id="credential-label" label=move||t_string!(i18n,credentials.label).to_owned() disabled=actions.busy><Input value=label/></Field>
                        <Field control_id="credential-secret" label=move||t_string!(i18n,credentials.secret).to_owned() description=move||t_string!(i18n,common.secret_entry_help).to_owned() disabled=actions.busy><SecretInput controller=secret/></Field>
                    }><p>{move||t!(i18n,credentials.revoke_help)}</p></Show>
                </DialogBody>
                <DialogFooter><Button disabled=actions.busy on_activate=move|_|close.run(())>{move||t!(i18n,common.cancel)}</Button><Button id="credential-confirm" variant=ButtonVariant::Primary disabled=actions.busy on_activate=save>{move||t!(i18n,common.confirm)}</Button></DialogFooter>
            </DialogContent>
        </Dialog>
    }
}

fn kind_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    kind: CredentialRecordKind,
) -> String {
    match kind {
        CredentialRecordKind::Model => t_string!(i18n, credentials.kind_model).to_owned(),
        CredentialRecordKind::Connector => t_string!(i18n, credentials.kind_connector).to_owned(),
        CredentialRecordKind::Mcp => t_string!(i18n, credentials.kind_mcp).to_owned(),
        CredentialRecordKind::Agent => t_string!(i18n, credentials.kind_agent).to_owned(),
        CredentialRecordKind::McpOauthClient => {
            t_string!(i18n, credentials.kind_oauth_client).to_owned()
        }
        CredentialRecordKind::McpUserToken => {
            t_string!(i18n, credentials.kind_user_token).to_owned()
        }
    }
}
fn external_label(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    status: CredentialExternalRevocation,
) -> String {
    match status {
        CredentialExternalRevocation::NotRequested => String::new(),
        CredentialExternalRevocation::Pending => {
            t_string!(i18n, credentials.external_pending).to_owned()
        }
        CredentialExternalRevocation::Revoked => {
            t_string!(i18n, credentials.external_revoked).to_owned()
        }
        CredentialExternalRevocation::OperatorRequired => {
            t_string!(i18n, credentials.external_operator).to_owned()
        }
    }
}
