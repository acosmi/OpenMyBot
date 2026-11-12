//! Administrator-managed deployment-owned SAML/OIDC providers.

use leptos::prelude::*;
use openbot_contracts::identity_provider::{
    MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES, MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES,
    MAX_IDENTITY_PROVIDER_METADATA_BYTES, MAX_IDENTITY_PROVIDER_URL_BYTES,
    MAX_SAML_ENTITY_ID_BYTES, RegisterIdentityProviderRequest, RegisteredIdentityProvider,
    SsoProtocol,
};

use crate::api::{canonical_identity_provider_domains, valid_identity_provider_id};
#[cfg(target_arch = "wasm32")]
use crate::api::{load_identity_providers, register_identity_provider, remove_identity_provider};
use crate::features::layout::{
    DetailPanel, DetailPanelLayout, DetailPanelMain, PageEmpty, PageHeader, PageRows, PageSection,
    PageShell, PageWidth, editor_location::EditorLocation,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Field, IconSize, IconView, Input, InputType, Notice,
    NoticePresentation, NoticeTone, SecretInput, SecretInputController, SecretInputPolicy,
    SecretInputStatus, Textarea,
};

#[derive(Clone, Copy)]
struct DraftSignals {
    protocol: RwSignal<SsoProtocol>,
    provider_id: RwSignal<String>,
    domain: RwSignal<String>,
    issuer: RwSignal<String>,
    entry_point: RwSignal<String>,
    metadata: RwSignal<String>,
    client_id: RwSignal<String>,
    client_secret: SecretInputController,
}

struct RegistrationDraft {
    protocol: SsoProtocol,
    provider_id: String,
    domain: String,
    issuer: String,
    entry_point: String,
    metadata: String,
    client_id: String,
    client_secret: zeroize::Zeroizing<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DraftField {
    ProviderId,
    Domain,
    Issuer,
    EntryPoint,
    Metadata,
    ClientId,
    ClientSecret,
}

impl DraftSignals {
    fn new() -> Self {
        Self {
            protocol: RwSignal::new(SsoProtocol::Saml),
            provider_id: RwSignal::new(String::new()),
            domain: RwSignal::new(String::new()),
            issuer: RwSignal::new(String::new()),
            entry_point: RwSignal::new(String::new()),
            metadata: RwSignal::new(String::new()),
            client_id: RwSignal::new(String::new()),
            client_secret: SecretInputController::new(
                MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES,
                SecretInputPolicy::OpaqueToken,
            ),
        }
    }

    fn snapshot(self) -> RegistrationDraft {
        RegistrationDraft {
            protocol: self.protocol.get_untracked(),
            provider_id: self.provider_id.get_untracked(),
            domain: self.domain.get_untracked(),
            issuer: self.issuer.get_untracked(),
            entry_point: self.entry_point.get_untracked(),
            metadata: self.metadata.get_untracked(),
            client_id: self.client_id.get_untracked(),
            client_secret: self.client_secret.take(),
        }
    }

    fn clear(self) {
        self.protocol.set(SsoProtocol::Saml);
        self.provider_id.set(String::new());
        self.domain.set(String::new());
        self.issuer.set(String::new());
        self.entry_point.set(String::new());
        self.metadata.set(String::new());
        self.client_id.set(String::new());
        self.client_secret.clear();
    }
}

/// Dynamic provider list plus a route-owned SAML/OIDC registration page.
#[component]
pub fn AdminIdentityProvidersPage() -> impl IntoView {
    let i18n = use_i18n();
    let providers = RwSignal::new(Vec::<RegisteredIdentityProvider>::new());
    let loading = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let editor = EditorLocation::new(&["sso-register"]);
    let dialog_open = Signal::derive(move || editor.selection.get().is_some());
    let draft = DraftSignals::new();
    let submit_attempted = RwSignal::new(false);
    let registration_pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::IdentityProviders,
        move || draft.provider_id.get().trim().to_owned(),
    );
    let registration_error = RwSignal::new(false);
    let removing = RwSignal::new(None::<String>);
    let removal_error = RwSignal::new(false);
    let page_owner = StoredValue::new(Owner::current());
    let form_generation = RwSignal::new(0_u64);
    Effect::new(move |_| {
        editor.selection.track();
        form_generation.update(|generation| *generation = generation.wrapping_add(1));
        draft.clear();
        submit_attempted.set(false);
        registration_error.set(false);
    });
    on_cleanup(move || draft.client_secret.clear());

    request_providers(providers, loading, load_error, page_owner);

    let open_dialog = move |_| {
        draft.clear();
        submit_attempted.set(false);
        registration_error.set(false);
        editor.open("sso-register", None);
    };
    let close_dialog = UnsyncCallback::new(move |_| {
        if !registration_pending.get_untracked() {
            draft.clear();
            submit_attempted.set(false);
            registration_error.set(false);
            editor.close();
        }
    });
    let retry = move |_| request_providers(providers, loading, load_error, page_owner);
    let register = move |_| {
        if registration_pending.get_untracked() || write_lock.get_untracked() {
            return;
        }
        submit_attempted.set(true);
        registration_error.set(false);
        draft.client_secret.validate();
        if !draft_valid(draft) {
            draft.client_secret.clear();
            return;
        }
        let Ok(request) = build_registration_request(draft.snapshot()) else {
            return;
        };
        dispatch_registration(
            request,
            providers,
            editor,
            draft,
            submit_attempted,
            registration_pending,
            registration_error,
            page_owner,
            form_generation,
            loading,
            load_error,
        );
    };

    view! {
        <DetailPanelLayout open=dialog_open>
        <DetailPanelMain>
        <PageShell width=PageWidth::Content>
            <PageHeader
                heading_id="admin-identity-providers-title"
                title=move || t_string!(i18n, admin.identity_providers_title).to_owned()
                description=move || t_string!(i18n, admin.identity_providers_intro).to_owned()
            />
            <div class="ob-page-primary-action">
                <Button
                    id="identity-provider-add"
                    variant=ButtonVariant::Primary
                    size=ButtonSize::Large
                    on_activate=open_dialog
                >
                    {move || t!(i18n, admin.identity_providers_add)}
                </Button>
            </div>
            <PageSection
                heading_id="identity-providers-registered-title"
                title=move || t_string!(i18n, admin.identity_providers_registered).to_owned()
                description=move || t_string!(i18n, admin.identity_providers_environment_note).to_owned()
            >
                <Show when=move || removal_error.get()>
                    <Notice tone=NoticeTone::Error>
                        {move || t!(i18n, admin.identity_providers_remove_error)}
                    </Notice>
                </Show>
                <Show when=move || loading.get()>
                    <div class="ob-loading" role="status">
                        <IconView icon=Icon::LoaderCircle size=IconSize::Navigation />
                        <span>{move || t!(i18n, common.loading)}</span>
                    </div>
                </Show>
                <Show when=move || load_error.get()>
                    <Notice tone=NoticeTone::Error>
                        <span>{move || t!(i18n, admin.identity_providers_load_error)}</span>
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Small
                            on_activate=retry
                        >
                            {move || t!(i18n, common.retry)}
                        </Button>
                    </Notice>
                </Show>
                <Show when=move || {
                    !loading.get() && !load_error.get() && providers.get().is_empty()
                }>
                    <PageEmpty>{move || t!(i18n, admin.identity_providers_empty)}</PageEmpty>
                </Show>
                <Show when=move || !providers.get().is_empty()>
                    <PageRows>
                        <For
                            each=move || providers.get()
                            key=|provider| provider.provider_id.clone()
                            children=move |provider| {
                                let provider_id = provider.provider_id.clone();
                                let remove_id = provider_id.clone();
                                let pending_id = provider_id.clone();
                                let label_id = provider_id.clone();
                                let lock_id = provider_id.clone();
                                let removal_lock = crate::configuration_writes::resource_lock(
                                    crate::configuration_writes::ConfigurationKind::IdentityProviders,
                                    move || lock_id.clone());
                                let description = provider_description(&provider);
                                let remove = move |_| {
                                    dispatch_removal(
                                        remove_id.clone(),
                                        providers,
                                        removing,
                                        removal_error,
                                        page_owner,
                                        loading,
                                        load_error,
                                    );
                                };
                                view! {
                                    <div class="ob-identity-provider-row">
                                        <span class="ob-item-media">
                                            <IconView icon=Icon::Landmark size=IconSize::Navigation />
                                        </span>
                                        <span class="ob-identity-provider-copy">
                                            <strong>{provider_id}</strong>
                                            <span>{description}</span>
                                        </span>
                                        <Button
                                            aria_label=move || t_string!(
                                                i18n,
                                                admin.identity_providers_remove_label,
                                                provider = label_id.clone(),
                                            ).to_owned()
                                            variant=ButtonVariant::DangerText
                                            size=ButtonSize::Small
                                            loading=Signal::derive(move || {
                                                removing.get().as_deref() == Some(pending_id.as_str())
                                            })
                                            disabled=Signal::derive(move || removing.get().is_some() || removal_lock.get())
                                            on_activate=remove
                                        >
                                            <IconView icon=Icon::Trash2 size=IconSize::Inline />
                                            {move || t!(i18n, admin.identity_providers_remove)}
                                        </Button>
                                    </div>
                                }
                            }
                        />
                    </PageRows>
                </Show>
            </PageSection>
        </PageShell>
        </DetailPanelMain>
        <DetailPanel id="identity-provider-dialog" open=dialog_open on_close=close_dialog
                return_focus_id="identity-provider-add"
                title=move || t_string!(i18n, admin.identity_providers_dialog_title).to_owned()
            >
                <p class="ob-page-intro">{move || t!(i18n, admin.identity_providers_dialog_intro)}</p>
                <div class="ob-library-form">
                    <div class="ob-identity-provider-protocols" role="group" aria-label=move || {
                        t_string!(i18n, admin.identity_providers_protocol).to_owned()
                    }>
                        <Button
                            id="identity-provider-protocol-saml"
                            size=ButtonSize::Small
                            selected=Signal::derive(move || draft.protocol.get() == SsoProtocol::Saml)
                            disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            on_activate=move |_| {
                                draft.client_secret.clear();
                                draft.protocol.set(SsoProtocol::Saml);
                                submit_attempted.set(false);
                                registration_error.set(false);
                            }
                        >"SAML"</Button>
                        <Button
                            id="identity-provider-protocol-oidc"
                            size=ButtonSize::Small
                            selected=Signal::derive(move || draft.protocol.get() == SsoProtocol::Oidc)
                            disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            on_activate=move |_| {
                                draft.client_secret.clear();
                                draft.protocol.set(SsoProtocol::Oidc);
                                submit_attempted.set(false);
                                registration_error.set(false);
                            }
                        >"OIDC"</Button>
                    </div>

                    <div class="ob-identity-provider-fields">
                        <Field
                            control_id="identity-provider-id"
                            label=move || t_string!(i18n, admin.identity_providers_name).to_owned()
                            description=move || t_string!(i18n, admin.identity_providers_name_help).to_owned()
                            error=move || t_string!(i18n, admin.identity_providers_name_error).to_owned()
                            invalid=Signal::derive(move || {
                                submit_attempted.get()
                                    && !field_valid(DraftField::ProviderId, draft)
                            })
                            disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                        >
                            <Input
                                value=draft.provider_id
                                placeholder="acme-okta"
                            />
                        </Field>
                        <Field
                            control_id="identity-provider-domain"
                            label=move || t_string!(i18n, admin.identity_providers_domain).to_owned()
                            description=move || t_string!(i18n, admin.identity_providers_domain_help).to_owned()
                            error=move || t_string!(i18n, admin.identity_providers_domain_error).to_owned()
                            invalid=Signal::derive(move || {
                                submit_attempted.get() && !field_valid(DraftField::Domain, draft)
                            })
                            disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                        >
                            <Input value=draft.domain placeholder="acme.com" />
                        </Field>
                        <Field
                            control_id="identity-provider-issuer"
                            label=move || t_string!(i18n, admin.identity_providers_issuer).to_owned()
                            error=move || t_string!(i18n, admin.identity_providers_issuer_error).to_owned()
                            invalid=Signal::derive(move || {
                                submit_attempted.get() && !field_valid(DraftField::Issuer, draft)
                            })
                            disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                        >
                            <Input
                                value=draft.issuer
                                input_type=InputType::Url
                                placeholder="https://acme.okta.com"
                            />
                        </Field>

                        <Show when=move || draft.protocol.get() == SsoProtocol::Saml>
                            <Field
                                control_id="identity-provider-entry-point"
                                label=move || t_string!(i18n, admin.identity_providers_entry_point).to_owned()
                                error=move || t_string!(i18n, admin.identity_providers_entry_point_error).to_owned()
                                invalid=Signal::derive(move || {
                                    submit_attempted.get()
                                        && !field_valid(DraftField::EntryPoint, draft)
                                })
                                disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            >
                                <Input
                                    value=draft.entry_point
                                    input_type=InputType::Url
                                    placeholder="https://acme.okta.com/app/example/sso/saml"
                                />
                            </Field>
                            <Field
                                control_id="identity-provider-metadata"
                                label=move || t_string!(i18n, admin.identity_providers_metadata).to_owned()
                                description=move || t_string!(i18n, admin.identity_providers_metadata_help).to_owned()
                                error=move || t_string!(i18n, admin.identity_providers_metadata_error).to_owned()
                                invalid=Signal::derive(move || {
                                    submit_attempted.get()
                                        && !field_valid(DraftField::Metadata, draft)
                                })
                                disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            >
                                <Textarea
                                    value=draft.metadata
                                    placeholder="<EntityDescriptor ...>"
                                />
                            </Field>
                        </Show>

                        <Show when=move || draft.protocol.get() == SsoProtocol::Oidc>
                            <Field
                                control_id="identity-provider-client-id"
                                label=move || t_string!(i18n, admin.identity_providers_client_id).to_owned()
                                error=move || t_string!(i18n, admin.identity_providers_client_id_error).to_owned()
                                invalid=Signal::derive(move || {
                                    submit_attempted.get()
                                        && !field_valid(DraftField::ClientId, draft)
                                })
                                disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            >
                                <Input value=draft.client_id />
                            </Field>
                            <Field
                                control_id="identity-provider-client-secret"
                                label=move || t_string!(i18n, admin.identity_providers_client_secret).to_owned()
                                description=move || t_string!(i18n, common.secret_entry_help).to_owned()
                                error=move || t_string!(i18n, admin.identity_providers_client_secret_error).to_owned()
                                invalid=Signal::derive(move || {
                                    submit_attempted.get()
                                        && !field_valid(DraftField::ClientSecret, draft)
                                })
                                disabled=Signal::derive(move || registration_pending.get() || write_lock.get())
                            >
                                <SecretInput controller=draft.client_secret />
                            </Field>
                        </Show>
                    </div>

                    <Show when=move || {
                        submit_attempted.get() && !draft_valid(draft)
                    }>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            {move || t!(i18n, admin.identity_providers_form_error)}
                        </Notice>
                    </Show>
                    <Show when=move || registration_error.get()>
                        <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>
                            {move || t!(i18n, admin.identity_providers_register_error)}
                        </Notice>
                    </Show>
                </div>
                <div class="ob-library-form-actions">
                    <Button
                        variant=ButtonVariant::Ghost
                        disabled=registration_pending
                        on_activate=move |_| close_dialog.run(())
                    >
                        {move || t!(i18n, common.cancel)}
                    </Button>
                    <Button
                        id="identity-provider-submit"
                        variant=ButtonVariant::Primary
                        loading=registration_pending
                        disabled=write_lock
                        on_activate=register
                    >
                        {move || if registration_pending.get() {
                            t_string!(i18n, admin.identity_providers_adding).to_owned()
                        } else {
                            t_string!(i18n, admin.identity_providers_submit).to_owned()
                        }}
                    </Button>
                </div>
        </DetailPanel>
        </DetailPanelLayout>
    }
}

fn request_providers(
    providers: RwSignal<Vec<RegisteredIdentityProvider>>,
    loading: RwSignal<bool>,
    error: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
) {
    if loading.get_untracked() {
        return;
    }
    loading.set(true);
    error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match load_identity_providers().await {
                    Ok(loaded) => providers.set(loaded),
                    Err(_) => error.set(true),
                }
                loading.set(false);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (providers, page_owner);
        loading.set(false);
        error.set(true);
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_registration(
    request: RegisterIdentityProviderRequest,
    providers: RwSignal<Vec<RegisteredIdentityProvider>>,
    editor: EditorLocation,
    draft: DraftSignals,
    submit_attempted: RwSignal<bool>,
    pending: RwSignal<bool>,
    error: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
    form_generation: RwSignal<u64>,
    list_loading: RwSignal<bool>,
    list_error: RwSignal<bool>,
) {
    if pending.get_untracked() {
        return;
    }
    pending.set(true);
    error.set(false);
    // The DOM-owned secret has been consumed; its empty field is not a failed preflight.
    submit_attempted.set(false);
    let generation = form_generation.get_untracked();
    #[cfg(target_arch = "wasm32")]
    {
        let writes = expect_context::<crate::configuration_writes::ConfigurationWrites>();
        let provider_id = request.provider_id().to_owned();
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let outcome = register_identity_provider(request).await;
                match outcome {
                    Ok(_) => {
                        if form_generation.get_untracked() == generation {
                            draft.clear();
                            submit_attempted.set(false);
                            editor.close();
                        }
                        request_providers(providers, list_loading, list_error, page_owner);
                    }
                    Err(_) if form_generation.get_untracked() == generation => {
                        error.set(!writes.locked(
                            crate::configuration_writes::ConfigurationKind::IdentityProviders,
                            &provider_id,
                        ))
                    }
                    Err(_) => {}
                }
                pending.set(false);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (
            request,
            providers,
            editor,
            draft,
            submit_attempted,
            page_owner,
            form_generation,
            generation,
            list_loading,
            list_error,
        );
        pending.set(false);
        error.set(true);
    }
}

fn dispatch_removal(
    provider_id: String,
    providers: RwSignal<Vec<RegisteredIdentityProvider>>,
    removing: RwSignal<Option<String>>,
    error: RwSignal<bool>,
    page_owner: StoredValue<Option<Owner>>,
    list_loading: RwSignal<bool>,
    list_error: RwSignal<bool>,
) {
    if removing.get_untracked().is_some() {
        return;
    }
    removing.set(Some(provider_id.clone()));
    error.set(false);
    #[cfg(target_arch = "wasm32")]
    {
        let writes = expect_context::<crate::configuration_writes::ConfigurationWrites>();
        let start_worker = move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match remove_identity_provider(&provider_id).await {
                    Ok(()) => {
                        providers.update(|providers| {
                            providers.retain(|provider| provider.provider_id != provider_id);
                        });
                        list_loading.set(true);
                        list_error.set(false);
                        match load_identity_providers().await {
                            Ok(loaded) => providers.set(loaded),
                            Err(_) => list_error.set(true),
                        }
                        list_loading.set(false);
                    }
                    Err(_) => error.set(!writes.locked(
                        crate::configuration_writes::ConfigurationKind::IdentityProviders,
                        &provider_id,
                    )),
                }
                removing.set(None);
            });
        };
        match page_owner.get_value() {
            Some(owner) => owner.with(start_worker),
            None => start_worker(),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (provider_id, providers, page_owner, list_loading, list_error);
        removing.set(None);
        error.set(true);
    }
}

fn provider_description(provider: &RegisteredIdentityProvider) -> String {
    format!(
        "{} · {} · {}",
        match provider.protocol {
            SsoProtocol::Saml => "SAML",
            SsoProtocol::Oidc => "OIDC",
        },
        provider.domain,
        provider.issuer,
    )
}

fn build_registration_request(
    draft: RegistrationDraft,
) -> Result<RegisterIdentityProviderRequest, DraftField> {
    if !valid_identity_provider_id(&draft.provider_id) {
        return Err(DraftField::ProviderId);
    }
    canonical_identity_provider_domains(&draft.domain).map_err(|_| DraftField::Domain)?;
    if !valid_issuer(draft.protocol, &draft.issuer) {
        return Err(DraftField::Issuer);
    }
    match draft.protocol {
        SsoProtocol::Saml => {
            if !valid_https_url(&draft.entry_point) {
                return Err(DraftField::EntryPoint);
            }
            if draft.metadata.is_empty()
                || draft.metadata.len() > MAX_IDENTITY_PROVIDER_METADATA_BYTES
            {
                return Err(DraftField::Metadata);
            }
            Ok(RegisterIdentityProviderRequest::saml(
                draft.provider_id,
                draft.domain,
                draft.issuer,
                draft.entry_point,
                draft.metadata,
            ))
        }
        SsoProtocol::Oidc => {
            if !valid_bounded_text(&draft.client_id, MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES) {
                return Err(DraftField::ClientId);
            }
            if !valid_bounded_text(
                &draft.client_secret,
                MAX_IDENTITY_PROVIDER_CLIENT_SECRET_BYTES,
            ) {
                return Err(DraftField::ClientSecret);
            }
            Ok(RegisterIdentityProviderRequest::oidc_with_zeroizing_secret(
                draft.provider_id,
                draft.domain,
                draft.issuer,
                draft.client_id,
                draft.client_secret,
            ))
        }
    }
}

fn field_valid(field: DraftField, draft: DraftSignals) -> bool {
    match field {
        DraftField::ProviderId => valid_identity_provider_id(&draft.provider_id.get()),
        DraftField::Domain => canonical_identity_provider_domains(&draft.domain.get()).is_ok(),
        DraftField::Issuer => valid_issuer(draft.protocol.get(), &draft.issuer.get()),
        DraftField::EntryPoint => valid_https_url(&draft.entry_point.get()),
        DraftField::Metadata => {
            let value = draft.metadata.get();
            !value.is_empty() && value.len() <= MAX_IDENTITY_PROVIDER_METADATA_BYTES
        }
        DraftField::ClientId => valid_bounded_text(
            &draft.client_id.get(),
            MAX_IDENTITY_PROVIDER_CLIENT_ID_BYTES,
        ),
        DraftField::ClientSecret => draft.client_secret.status().get() == SecretInputStatus::Valid,
    }
}

fn draft_valid(draft: DraftSignals) -> bool {
    let common = [
        DraftField::ProviderId,
        DraftField::Domain,
        DraftField::Issuer,
    ]
    .into_iter()
    .all(|field| field_valid(field, draft));
    common
        && match draft.protocol.get() {
            SsoProtocol::Saml => [DraftField::EntryPoint, DraftField::Metadata]
                .into_iter()
                .all(|field| field_valid(field, draft)),
            SsoProtocol::Oidc => [DraftField::ClientId, DraftField::ClientSecret]
                .into_iter()
                .all(|field| field_valid(field, draft)),
        }
}

fn valid_issuer(protocol: SsoProtocol, value: &str) -> bool {
    match protocol {
        SsoProtocol::Oidc => valid_oidc_issuer(value),
        SsoProtocol::Saml => valid_saml_entity_id(value),
    }
}

fn valid_oidc_issuer(value: &str) -> bool {
    if !valid_bounded_text(value, MAX_IDENTITY_PROVIDER_URL_BYTES) {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && !url.cannot_be_a_base()
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn valid_saml_entity_id(value: &str) -> bool {
    if !valid_bounded_text(value, MAX_SAML_ENTITY_ID_BYTES) {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if !matches!(url.scheme(), "urn" | "http" | "https") || url.fragment().is_some() {
        return false;
    }
    !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_some() && url.username().is_empty() && url.password().is_none()
}

fn valid_https_url(value: &str) -> bool {
    if !valid_bounded_text(value, MAX_IDENTITY_PROVIDER_URL_BYTES) {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn valid_bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saml_draft() -> RegistrationDraft {
        RegistrationDraft {
            protocol: SsoProtocol::Saml,
            provider_id: "acme-saml".to_owned(),
            domain: "Second.Example, acme.example".to_owned(),
            issuer: "urn:acme:idp".to_owned(),
            entry_point: "https://idp.acme.example/sso".to_owned(),
            metadata: "<EntityDescriptor/>".to_owned(),
            client_id: String::new(),
            client_secret: zeroize::Zeroizing::new(String::new()),
        }
    }

    #[test]
    fn both_protocol_forms_build_exclusive_exact_requests() {
        let saml = serde_json::to_value(build_registration_request(saml_draft()).unwrap()).unwrap();
        assert!(saml.get("samlConfig").is_some());
        assert!(saml.get("oidcConfig").is_none());

        let mut oidc = saml_draft();
        oidc.protocol = SsoProtocol::Oidc;
        oidc.issuer = "https://idp.acme.example/oauth2/default".to_owned();
        oidc.client_id = "client-id".to_owned();
        oidc.client_secret = zeroize::Zeroizing::new("secret".to_owned());
        let oidc = serde_json::to_value(build_registration_request(oidc).unwrap()).unwrap();
        assert!(oidc.get("oidcConfig").is_some());
        assert!(oidc.get("samlConfig").is_none());
        assert_eq!(
            oidc.pointer("/oidcConfig/discoveryEndpoint")
                .and_then(serde_json::Value::as_str),
            Some("https://idp.acme.example/oauth2/default/.well-known/openid-configuration")
        );
    }

    #[test]
    fn invalid_authority_inputs_fail_before_transport() {
        let mut draft = saml_draft();
        draft.provider_id = "Acme/SSO".to_owned();
        assert_eq!(
            build_registration_request(draft).err(),
            Some(DraftField::ProviderId)
        );

        let mut draft = saml_draft();
        draft.domain = "acme.example,ACME.EXAMPLE".to_owned();
        assert_eq!(
            build_registration_request(draft).err(),
            Some(DraftField::Domain)
        );

        let mut draft = saml_draft();
        draft.entry_point = "http://idp.acme.example/sso".to_owned();
        assert_eq!(
            build_registration_request(draft).err(),
            Some(DraftField::EntryPoint)
        );

        let mut draft = saml_draft();
        draft.protocol = SsoProtocol::Oidc;
        draft.issuer = "https://user:secret@idp.acme.example?tenant=other".to_owned();
        draft.client_id = "client".to_owned();
        draft.client_secret = zeroize::Zeroizing::new("secret".to_owned());
        assert_eq!(
            build_registration_request(draft).err(),
            Some(DraftField::Issuer)
        );
    }

    #[test]
    fn public_row_description_never_has_private_material() {
        let provider = RegisteredIdentityProvider {
            provider_id: "acme-saml".to_owned(),
            issuer: "urn:acme:idp".to_owned(),
            domain: "acme.example".to_owned(),
            protocol: SsoProtocol::Saml,
            registered_by: Some("actor".to_owned()),
        };
        assert_eq!(
            provider_description(&provider),
            "SAML · acme.example · urn:acme:idp"
        );
    }
}
