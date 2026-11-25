use leptos::prelude::*;
use openbot_contracts::mcp::{
    McpCustomServerRegistration, McpOAuthClientAuthMethod, McpOAuthClientRegistration,
};

use crate::api::plugins as api;
use crate::features::layout::{
    editor_location::EditorLocation, library_editor::LibraryEditorFrame,
};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonVariant, Field, Input, InputType, Notice, NoticePresentation, NoticeTone,
    SecretInput, SecretInputController, SecretInputPolicy, Textarea,
};
use crate::primitives::{Select, SelectContent, SelectItem, SelectTrigger};

use super::PluginActions;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginDialog {
    Custom,
    OAuth(String),
    Remove(String),
}

#[component]
pub fn PluginDialogs(
    dialog: RwSignal<Option<PluginDialog>>,
    editor: EditorLocation,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<PluginActions>();
    let open = RwSignal::new(false);
    let id = RwSignal::new(String::new());
    let title = RwSignal::new(String::new());
    let endpoint = RwSignal::new(String::new());
    let credential = RwSignal::new(String::new());
    let cidrs = RwSignal::new(String::new());
    let client_id = RwSignal::new(String::new());
    let client_secret = SecretInputController::new(16 * 1024, SecretInputPolicy::OpaqueToken);
    let issuer = RwSignal::new(String::new());
    let resource_metadata = RwSignal::new(String::new());
    let invalid = RwSignal::new(false);
    let attempted = RwSignal::new(false);
    let auth_method = RwSignal::new(Some("basic".to_owned()));
    let method_open = RwSignal::new(false);
    let generation = RwSignal::new(0_u64);
    let return_focus = RwSignal::new("plugin-add".to_owned());
    Effect::new(move |_| {
        let selected = dialog.get();
        generation.update(|value| *value = value.wrapping_add(1));
        if let Some(selected) = &selected {
            return_focus.set(
                match selected {
                    PluginDialog::Custom => "plugin-add",
                    PluginDialog::OAuth(_) => "plugin-oauth-client",
                    PluginDialog::Remove(_) => "plugin-remove",
                }
                .to_owned(),
            );
        }
        open.set(selected.is_some());
        invalid.set(false);
        attempted.set(false);
        auth_method.set(Some("basic".to_owned()));
        method_open.set(false);
        for field in [
            id,
            title,
            endpoint,
            credential,
            cidrs,
            client_id,
            issuer,
            resource_metadata,
        ] {
            field.set(String::new());
        }
        client_secret.clear();
        if let Some(PluginDialog::OAuth(server)) = selected
            && server == "google-drive"
        {
            issuer.set("https://accounts.google.com".to_owned());
        }
    });
    let close = UnsyncCallback::new(move |_| {
        client_secret.clear();
        editor.close();
    });
    let save = move |_| {
        if actions.busy.get_untracked() {
            return;
        }
        invalid.set(false);
        let secret = client_secret.take();
        let selected = dialog.get_untracked();
        let started = generation.get_untracked();
        let finish = move |ok| {
            if ok && generation.try_get_untracked() == Some(started) {
                editor.close();
            }
        };
        match selected {
            Some(PluginDialog::Custom) => {
                let Some(registration) = custom_request(
                    &id.get_untracked(),
                    &title.get_untracked(),
                    &endpoint.get_untracked(),
                    &credential.get_untracked(),
                    &cidrs.get_untracked(),
                ) else {
                    invalid.set(true);
                    return;
                };
                attempted.set(true);
                actions.launch(
                    registration.id.clone(),
                    async move { api::add_custom(&registration).await },
                    finish,
                );
            }
            Some(PluginDialog::OAuth(server)) => {
                if !api::valid_https(&issuer.get_untracked())
                    || (!resource_metadata.get_untracked().is_empty()
                        && !api::valid_https(&resource_metadata.get_untracked()))
                {
                    invalid.set(true);
                    return;
                }
                let registration = McpOAuthClientRegistration::with_zeroizing_secret(
                    client_id.get_untracked(),
                    secret,
                    issuer.get_untracked(),
                    if auth_method.get_untracked().as_deref() == Some("post") {
                        McpOAuthClientAuthMethod::ClientSecretPost
                    } else {
                        McpOAuthClientAuthMethod::ClientSecretBasic
                    },
                    (!resource_metadata.get_untracked().is_empty())
                        .then(|| resource_metadata.get_untracked()),
                );
                let Ok(registration) = registration else {
                    invalid.set(true);
                    return;
                };
                attempted.set(true);
                actions.launch(
                    server.clone(),
                    async move { api::register_client(&server, registration).await },
                    finish,
                );
            }
            Some(PluginDialog::Remove(server)) => {
                attempted.set(true);
                actions.launch(
                    server.clone(),
                    async move { api::remove(&server).await },
                    finish,
                );
            }
            None => {}
        }
    };
    view! {
        <LibraryEditorFrame id="plugin-dialog" open=Signal::derive(move || open.get())
            confirm=Signal::derive(move || matches!(dialog.get(),Some(PluginDialog::Remove(_))))
            return_focus_id=move || return_focus.get() on_close=close
            title=move || match dialog.get() {
                Some(PluginDialog::Custom) => t_string!(i18n, plugins.custom_add).to_owned(),
                Some(PluginDialog::OAuth(_)) => t_string!(i18n, plugins.oauth_client).to_owned(),
                _ => t_string!(i18n, plugins.remove).to_owned(),
            }>
                <div class="ob-library-form">
                    <Show when=move || invalid.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, plugins.invalid)}</Notice></Show>
                    <Show when=move || attempted.get() && actions.failed.get() && !actions.unknown.get()><Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, plugins.write_error)}</Notice></Show>
                    {move || dialog.get().and_then(|selected| match selected {PluginDialog::OAuth(id)|PluginDialog::Remove(id)=>Some(view!{<p class="ob-page-intro"><code>{id}</code></p>}),PluginDialog::Custom=>None})}
                    <Show when=move || matches!(dialog.get(), Some(PluginDialog::Custom))>
                        <Field control_id="plugin-id" label=move || t_string!(i18n, plugins.id).to_owned() disabled=actions.busy><Input value=id /></Field>
                        <Field control_id="plugin-title" label=move || t_string!(i18n, plugins.name).to_owned() disabled=actions.busy><Input value=title /></Field>
                        <Field control_id="plugin-endpoint" label=move || t_string!(i18n, plugins.endpoint).to_owned() disabled=actions.busy><Input value=endpoint input_type=InputType::Url /></Field>
                        <Field control_id="plugin-credential" label=move || t_string!(i18n, plugins.credential_id).to_owned() disabled=actions.busy><Input value=credential /></Field>
                        <Field control_id="plugin-cidrs" label=move || t_string!(i18n, plugins.private_egress).to_owned() description=move || t_string!(i18n, plugins.egress_help).to_owned() disabled=actions.busy><Textarea value=cidrs /></Field>
                    </Show>
                    <Show when=move || matches!(dialog.get(), Some(PluginDialog::OAuth(_)))>
                        <p class="text-fg-secondary">{move || t!(i18n, plugins.client_help)}</p>
                        <Field control_id="plugin-client-id" label=move || t_string!(i18n, plugins.client_id).to_owned() disabled=actions.busy><Input value=client_id /></Field>
                        <Field control_id="plugin-client-secret" label=move || t_string!(i18n, plugins.client_secret).to_owned() description=move || t_string!(i18n, common.secret_entry_help).to_owned() disabled=actions.busy><SecretInput controller=client_secret /></Field>
                        <Field control_id="plugin-issuer" label=move || t_string!(i18n, plugins.issuer).to_owned() disabled=actions.busy><Input value=issuer input_type=InputType::Url /></Field>
                        <Select id="plugin-auth-method" open=method_open value=auth_method disabled=actions.busy>
                            <SelectTrigger aria_label=move || t_string!(i18n, plugins.auth_method).to_owned() placeholder=move || t_string!(i18n, plugins.auth_method).to_owned() />
                            <SelectContent>
                                <SelectItem id="plugin-auth-basic" value="basic" label="HTTP Basic">"HTTP Basic"</SelectItem>
                                <SelectItem id="plugin-auth-post" value="post" label=move || t_string!(i18n, plugins.auth_post).to_owned()>{move || t!(i18n, plugins.auth_post)}</SelectItem>
                            </SelectContent>
                        </Select>
                        <Field control_id="plugin-resource-metadata" label=move || t_string!(i18n, plugins.resource_metadata).to_owned() disabled=actions.busy><Input value=resource_metadata input_type=InputType::Url /></Field>
                    </Show>
                    <Show when=move || matches!(dialog.get(), Some(PluginDialog::Remove(_)))>
                        <p>{move || t!(i18n, plugins.remove_warning)}</p>
                    </Show>
                </div>
                <div class="ob-library-form-actions">
                    <Button disabled=actions.busy on_activate=move |_| close.run(())>{move || t!(i18n, common.cancel)}</Button>
                    <Button id="plugin-confirm" variant=ButtonVariant::Primary disabled=actions.busy on_activate=save>{move || t!(i18n, plugins.confirm)}</Button>
                </div>
        </LibraryEditorFrame>
    }
}

fn custom_request(
    id: &str,
    title: &str,
    url: &str,
    credential: &str,
    cidrs: &str,
) -> Option<McpCustomServerRegistration> {
    if id.len() < 2
        || id.len() > 40
        || id.starts_with('-')
        || id.ends_with('-')
        || id == "google-drive"
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || title.trim().is_empty()
        || title.len() > 256
        || title.chars().any(char::is_control)
        || !api::valid_https(url)
    {
        return None;
    }
    let credential_id = if credential.trim().is_empty() {
        None
    } else {
        Some(uuid::Uuid::parse_str(credential.trim()).ok()?.to_string())
    };
    let mut networks = Vec::new();
    for cidr in cidrs
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (ip, prefix) = cidr.split_once('/')?;
        let ip: std::net::IpAddr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        if prefix > if ip.is_ipv4() { 32 } else { 128 } {
            return None;
        }
        networks.push(cidr.to_owned());
    }
    networks.sort();
    networks.dedup();
    if networks.len() > 64 {
        return None;
    }
    Some(McpCustomServerRegistration {
        id: id.to_owned(),
        title: title.trim().to_owned(),
        url: url.to_owned(),
        credential_id,
        egress_allow_cidrs: networks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_registration_never_turns_credentials_or_hostnames_into_egress_authority() {
        let valid = custom_request(
            "internal-tools",
            "Tools",
            "https://tools.example.test/mcp",
            "",
            "10.0.0.0/8\n::1/128",
        )
        .expect("valid");
        assert_eq!(valid.credential_id, None);
        assert_eq!(valid.egress_allow_cidrs, ["10.0.0.0/8", "::1/128"]);
        assert!(
            custom_request(
                "google-drive",
                "Tools",
                "https://tools.example.test/mcp",
                "",
                ""
            )
            .is_none()
        );
        assert!(
            custom_request(
                "internal-tools",
                "Tools",
                "https://user:secret@tools.example.test/mcp",
                "",
                ""
            )
            .is_none()
        );
        assert!(
            custom_request(
                "internal-tools",
                "Tools",
                "https://tools.example.test/mcp",
                "secret",
                ""
            )
            .is_none()
        );
        assert!(
            custom_request(
                "internal-tools",
                "Tools",
                "https://tools.example.test/mcp",
                "",
                "tools.example.test/32"
            )
            .is_none()
        );
        assert!(
            custom_request(
                "internal-tools",
                "Tools",
                "https://tools.example.test/mcp",
                "",
                "127.0.0.1/33"
            )
            .is_none()
        );
    }
}
