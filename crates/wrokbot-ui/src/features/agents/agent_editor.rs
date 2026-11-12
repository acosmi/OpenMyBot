//! Shared create/edit Agent form backed only by typed lifecycle APIs.

use leptos::prelude::*;
use openbot_contracts::agent::{
    AgentAuthInput, AgentConnectionFailure, AgentConnectionTestRequest, AgentMutationRequest,
    AgentProfile, AgentVisibility, MAX_AGENT_AUTH_BYTES, MAX_AGENT_NAME_BYTES,
    MAX_AGENT_ROLE_DESCRIPTION_BYTES, MAX_AGENT_TITLE_BYTES,
};

#[cfg(target_arch = "wasm32")]
use crate::api::{create_agent, test_agent_connection, update_agent};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Field, Input, InputType, Notice, NoticePresentation,
    NoticeTone, SecretInput, SecretInputController, SecretInputPolicy, SecretInputStatus, Select,
    SelectContent, SelectItem, SelectTrigger, Textarea,
};

/// Create or edit one coworker. Password bytes stay in the DOM until an explicit request and are
/// cleared on submit/cancel; reactive state contains only validation metadata.
#[component]
pub fn AgentEditor(
    /// `None` creates; `Some` edits this authoritative profile.
    profile: Option<AgentProfile>,
    /// Receives the authoritative Server profile after success.
    on_saved: UnsyncCallback<AgentProfile>,
    /// Close without a mutation.
    on_cancel: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let editing = profile.is_some();
    let agent_id = StoredValue::new(profile.as_ref().map(|profile| profile.id.clone()));
    let name = RwSignal::new(
        profile
            .as_ref()
            .map_or_else(String::new, |profile| profile.name.clone()),
    );
    let title = RwSignal::new(
        profile
            .as_ref()
            .map_or_else(String::new, |profile| profile.title.clone()),
    );
    let role = RwSignal::new(
        profile
            .as_ref()
            .map_or_else(String::new, |profile| profile.role_description.clone()),
    );
    let endpoint = RwSignal::new(
        profile
            .as_ref()
            .and_then(|profile| profile.endpoint.clone())
            .unwrap_or_default(),
    );
    let auth = SecretInputController::new(MAX_AGENT_AUTH_BYTES, SecretInputPolicy::Authorization);
    let visibility = RwSignal::new(Some(
        match profile
            .as_ref()
            .map(|profile| profile.visibility)
            .unwrap_or(AgentVisibility::Private)
        {
            AgentVisibility::Public => "public",
            AgentVisibility::Private => "private",
        }
        .to_owned(),
    ));
    let visibility_open = RwSignal::new(false);
    let attempted = RwSignal::new(false);
    let pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Agents,
        move || {
            agent_id
                .get_value()
                .map(|id| id.as_str().to_owned())
                .unwrap_or_else(|| "$create".into())
        },
    );
    let save_error = RwSignal::new(false);
    let connection_pending = RwSignal::new(false);
    let connection = RwSignal::new(None::<ConnectionState>);
    let connection_generation = RwSignal::new(0_u64);

    Effect::new(move |_| {
        name.track();
        title.track();
        role.track();
        visibility.track();
        endpoint.track();
        auth.revision().track();
        connection.set(None);
        connection_pending.set(false);
        let _ = advance_connection_generation(connection_generation);
    });
    on_cleanup(move || {
        auth.clear();
        let _ = advance_connection_generation(connection_generation);
    });

    let build = move || {
        let secret = auth.take();
        build_agent_request(
            &name.get_untracked(),
            &title.get_untracked(),
            &role.get_untracked(),
            visibility.get_untracked().as_deref(),
            &endpoint.get_untracked(),
            &secret,
        )
    };

    let save = UnsyncCallback::new(move |_| {
        if pending.get_untracked() {
            return;
        }
        attempted.set(true);
        save_error.set(false);
        let Ok(request) = build() else {
            return;
        };
        pending.set(true);
        connection.set(None);
        connection_pending.set(false);
        let _ = advance_connection_generation(connection_generation);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = match agent_id.get_value() {
                Some(agent_id) => update_agent(agent_id.as_str(), request).await,
                None => create_agent(request).await,
            };
            pending.set(false);
            match outcome {
                Ok(profile) => on_saved.run(profile),
                Err(_) => save_error.set(true),
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = request;
            pending.set(false);
        }
    });

    let test = move |_| {
        let auth_raw = auth.take();
        connection.set(None);
        let Some(generation) = advance_connection_generation(connection_generation) else {
            connection.set(Some(ConnectionState::Rejected(
                AgentConnectionFailure::Inconclusive,
            )));
            return;
        };
        let endpoint_raw = endpoint.get_untracked();
        let endpoint_value = openbot_contracts::text::trim_ecmascript(&endpoint_raw);
        if endpoint_value.is_empty() {
            connection.set(Some(ConnectionState::Rejected(
                AgentConnectionFailure::DestinationRejected,
            )));
            return;
        }
        let auth_value = openbot_contracts::text::trim_ecmascript(&auth_raw);
        let request = AgentConnectionTestRequest {
            endpoint: endpoint_value.to_owned(),
            auth: if auth_value.is_empty() {
                None
            } else {
                match AgentAuthInput::new("Authorization".to_owned(), auth_value.to_owned()) {
                    Ok(auth) => Some(auth),
                    Err(_) => {
                        connection.set(Some(ConnectionState::Rejected(
                            AgentConnectionFailure::Authentication,
                        )));
                        return;
                    }
                }
            },
        };
        connection_pending.set(true);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let outcome = test_agent_connection(request).await;
            if connection_generation.get_untracked() != generation {
                return;
            }
            match outcome {
                Ok(verdict) if verdict.ok => {
                    connection.set(Some(ConnectionState::Working(verdict.events)))
                }
                Ok(verdict) => connection.set(Some(ConnectionState::Rejected(
                    verdict
                        .reason
                        .unwrap_or(AgentConnectionFailure::Inconclusive),
                ))),
                Err(_) => connection.set(Some(ConnectionState::Rejected(
                    AgentConnectionFailure::Inconclusive,
                ))),
            }
            connection_pending.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (request, generation);
            connection_pending.set(false);
        }
    };

    let cancel = move |_| {
        auth.clear();
        connection.set(None);
        let _ = advance_connection_generation(connection_generation);
        on_cancel.run(());
    };
    let invalid_name =
        Signal::derive(move || attempted.get() && !bounded_line(&name.get(), MAX_AGENT_NAME_BYTES));
    let invalid_title = Signal::derive(move || {
        attempted.get() && !bounded_line(&title.get(), MAX_AGENT_TITLE_BYTES)
    });
    let invalid_role = Signal::derive(move || {
        let raw = role.get();
        let value = openbot_contracts::text::trim_ecmascript(&raw);
        attempted.get()
            && (value.is_empty()
                || value.len() > MAX_AGENT_ROLE_DESCRIPTION_BYTES
                || value.as_bytes().contains(&0))
    });
    let form_invalid = agent_form_invalid_signal(
        attempted,
        name,
        title,
        role,
        visibility,
        endpoint,
        auth.status(),
    );
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (agent_id, on_saved);

    view! {
        <section class="ob-agent-editor" aria-labelledby="agent-editor-title">
            <h3 id="agent-editor-title">
                {move || if editing {
                    t_string!(i18n, agents.edit_title).to_owned()
                } else {
                    t_string!(i18n, agents.create_title).to_owned()
                }}
            </h3>
            <p class="ob-agent-editor-intro">
                {move || t!(i18n, agents.form_intro)}
            </p>
            <div class="ob-agent-editor-fields">
                <Field
                    control_id="agent-name"
                    label=move || t_string!(i18n, agents.name_label).to_owned()
                    error=move || t_string!(i18n, agents.name_error).to_owned()
                    invalid=invalid_name
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <Input
                        value=name
                        placeholder=move || t_string!(i18n, agents.name_placeholder).to_owned()
                    />
                </Field>
                <Field
                    control_id="agent-title"
                    label=move || t_string!(i18n, agents.title_label).to_owned()
                    error=move || t_string!(i18n, agents.title_error).to_owned()
                    invalid=invalid_title
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <Input
                        value=title
                        placeholder=move || t_string!(i18n, agents.title_placeholder).to_owned()
                    />
                </Field>
                <Field
                    control_id="agent-role"
                    label=move || t_string!(i18n, agents.role_label).to_owned()
                    error=move || t_string!(i18n, agents.role_error).to_owned()
                    invalid=invalid_role
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <Textarea
                        value=role
                        placeholder=move || t_string!(i18n, agents.role_placeholder).to_owned()
                    />
                </Field>
                <Field
                    control_id="agent-visibility"
                    label=move || t_string!(i18n, agents.visibility_label).to_owned()
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <Select
                        id="agent-visibility"
                        open=visibility_open
                        value=visibility
                    >
                        <SelectTrigger
                            aria_label=move || t_string!(i18n, agents.visibility_label).to_owned()
                            placeholder=move || t_string!(i18n, agents.visibility_private).to_owned()
                        />
                        <SelectContent>
                            <SelectItem
                                id="agent-visibility-private"
                                value="private"
                                label=move || t_string!(i18n, agents.visibility_private).to_owned()
                            >{move || t!(i18n, agents.visibility_private_help)}</SelectItem>
                            <SelectItem
                                id="agent-visibility-public"
                                value="public"
                                label=move || t_string!(i18n, agents.visibility_public).to_owned()
                            >{move || t!(i18n, agents.visibility_public_help)}</SelectItem>
                        </SelectContent>
                    </Select>
                </Field>
                <Field
                    control_id="agent-endpoint"
                    label=move || t_string!(i18n, agents.endpoint_label).to_owned()
                    description=move || t_string!(i18n, agents.endpoint_help).to_owned()
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <Input
                        value=endpoint
                        input_type=InputType::Url
                        placeholder="https://agent.example/ag-ui"
                    />
                </Field>
                <Field
                    control_id="agent-auth"
                    label=move || t_string!(i18n, agents.auth_label).to_owned()
                    description=move || {
                        let mode_help = if editing { t_string!(i18n, agents.auth_edit_help) }
                            else { t_string!(i18n, agents.auth_help) };
                        format!("{} {}", mode_help, t_string!(i18n, common.secret_entry_help))
                    }
                    invalid=Signal::derive(move || attempted.get() && auth.status().get() == SecretInputStatus::Invalid)
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                >
                    <SecretInput
                        controller=auth
                        placeholder="Bearer …"
                    />
                </Field>
                <div class="ob-agent-connection-row">
                    <Button
                        variant=ButtonVariant::Chip
                        size=ButtonSize::Small
                        disabled=Signal::derive(move || {
                            pending.get()
                                || connection_pending.get()
                                || openbot_contracts::text::trim_ecmascript(&endpoint.get()).is_empty()
                        })
                        on_activate=test
                    >
                        {move || if connection_pending.get() {
                            t_string!(i18n, agents.connection_testing).to_owned()
                        } else {
                            t_string!(i18n, agents.connection_test).to_owned()
                        }}
                    </Button>
                    {move || connection.get().map(|state| view! {
                        <p
                            class="ob-agent-connection-status"
                            data-state=state.token()
                            role="status"
                        >{connection_text(i18n, &state)}</p>
                    })}
                </div>
            </div>
            <Show when=move || form_invalid.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, agents.form_error)}</Notice>
            </Show>
            <Show when=move || save_error.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, agents.save_error)}</Notice>
            </Show>
            <div class="ob-agent-editor-actions">
                <Button
                    variant=ButtonVariant::Primary
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                    on_activate=move |_| save.run(())
                >
                    {move || if pending.get() {
                        t_string!(i18n, agents.saving).to_owned()
                    } else if editing {
                        t_string!(i18n, common.save).to_owned()
                    } else {
                        t_string!(i18n, agents.create_action).to_owned()
                    }}
                </Button>
                <Button
                    variant=ButtonVariant::Ghost
                    disabled=Signal::derive(move || pending.get() || write_lock.get())
                    on_activate=cancel
                >{move || t!(i18n, common.cancel)}</Button>
            </div>
        </section>
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum ConnectionState {
    Working(Vec<String>),
    Rejected(AgentConnectionFailure),
}

impl ConnectionState {
    const fn token(&self) -> &'static str {
        match self {
            Self::Working(_) => "working",
            Self::Rejected(_) => "rejected",
        }
    }
}

fn connection_text(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    state: &ConnectionState,
) -> String {
    match state {
        ConnectionState::Working(events) => {
            t_string!(i18n, agents.connection_working, events = events.join(", "),).to_owned()
        }
        ConnectionState::Rejected(AgentConnectionFailure::DestinationRejected) => {
            t_string!(i18n, agents.connection_destination).to_owned()
        }
        ConnectionState::Rejected(AgentConnectionFailure::Unreachable) => {
            t_string!(i18n, agents.connection_unreachable).to_owned()
        }
        ConnectionState::Rejected(AgentConnectionFailure::Authentication) => {
            t_string!(i18n, agents.connection_auth).to_owned()
        }
        ConnectionState::Rejected(AgentConnectionFailure::Protocol) => {
            t_string!(i18n, agents.connection_protocol).to_owned()
        }
        ConnectionState::Rejected(AgentConnectionFailure::Inconclusive) => {
            t_string!(i18n, agents.connection_inconclusive).to_owned()
        }
    }
}

fn build_agent_request(
    name: &str,
    title: &str,
    role: &str,
    visibility: Option<&str>,
    endpoint: &str,
    auth: &str,
) -> Result<AgentMutationRequest, ()> {
    let name = openbot_contracts::text::trim_ecmascript(name);
    let title = openbot_contracts::text::trim_ecmascript(title);
    let role = openbot_contracts::text::trim_ecmascript(role);
    let endpoint = openbot_contracts::text::trim_ecmascript(endpoint);
    let auth = openbot_contracts::text::trim_ecmascript(auth);
    if !bounded_line(name, MAX_AGENT_NAME_BYTES)
        || !bounded_line(title, MAX_AGENT_TITLE_BYTES)
        || role.is_empty()
        || role.len() > MAX_AGENT_ROLE_DESCRIPTION_BYTES
        || role.as_bytes().contains(&0)
    {
        return Err(());
    }
    let visibility = match visibility {
        Some("public") => AgentVisibility::Public,
        Some("private") => AgentVisibility::Private,
        _ => return Err(()),
    };
    let endpoint = (!endpoint.is_empty()).then(|| endpoint.to_owned());
    let auth = if auth.is_empty() {
        None
    } else {
        if endpoint.is_none() {
            return Err(());
        }
        Some(AgentAuthInput::new("Authorization".to_owned(), auth.to_owned()).map_err(|_| ())?)
    };
    Ok(AgentMutationRequest {
        name: name.to_owned(),
        title: title.to_owned(),
        role_description: role.to_owned(),
        visibility,
        endpoint,
        auth,
    })
}

fn bounded_line(value: &str, maximum: usize) -> bool {
    let value = openbot_contracts::text::trim_ecmascript(value);
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn agent_form_invalid_signal(
    attempted: RwSignal<bool>,
    name: RwSignal<String>,
    title: RwSignal<String>,
    role: RwSignal<String>,
    visibility: RwSignal<Option<String>>,
    endpoint: RwSignal<String>,
    auth: ReadSignal<SecretInputStatus>,
) -> Signal<bool> {
    Signal::derive(move || {
        attempted.get()
            && name.with(|name| {
                title.with(|title| {
                    role.with(|role| {
                        visibility.with(|visibility| {
                            endpoint.with(|endpoint| {
                                let auth_state = auth.get();
                                auth_state == SecretInputStatus::Invalid
                                    || (auth_state == SecretInputStatus::Valid
                                        && openbot_contracts::text::trim_ecmascript(endpoint)
                                            .is_empty())
                                    || build_agent_request(
                                        name,
                                        title,
                                        role,
                                        visibility.as_deref(),
                                        endpoint,
                                        "",
                                    )
                                    .is_err()
                            })
                        })
                    })
                })
            })
    })
}

fn advance_connection_generation(generation: RwSignal<u64>) -> Option<u64> {
    generation
        .try_update(|current| {
            let next = current.checked_add(1)?;
            *current = next;
            Some(next)
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempted_form_error_reacts_to_corrected_fields_and_endpoint() {
        let owner = Owner::new();
        owner.with(|| {
            let attempted = RwSignal::new(false);
            let name = RwSignal::new(String::new());
            let title = RwSignal::new(String::new());
            let role = RwSignal::new(String::new());
            let visibility = RwSignal::new(Some("private".to_owned()));
            let endpoint = RwSignal::new(String::new());
            let auth = RwSignal::new(SecretInputStatus::Empty);
            let invalid = agent_form_invalid_signal(
                attempted,
                name,
                title,
                role,
                visibility,
                endpoint,
                auth.read_only(),
            );

            assert!(!invalid.get());
            attempted.set(true);
            assert!(invalid.get());
            name.set("Agent".to_owned());
            title.set("Title".to_owned());
            role.set("Role".to_owned());
            assert!(!invalid.get());

            auth.set(SecretInputStatus::Valid);
            assert!(invalid.get());
            endpoint.set("https://agent.example/ag-ui".to_owned());
            assert!(!invalid.get());
        });
    }

    #[test]
    fn form_is_full_closed_and_never_allows_auth_without_remote_endpoint() {
        let managed =
            build_agent_request(" Agent ", " Title ", " Role ", Some("private"), "", "").unwrap();
        assert_eq!(managed.name, "Agent");
        assert!(managed.endpoint.is_none());
        assert!(managed.auth.is_none());
        assert!(
            build_agent_request(
                "Agent",
                "Title",
                "Role",
                Some("private"),
                "",
                "Bearer secret",
            )
            .is_err()
        );
        let remote = build_agent_request(
            "Agent",
            "Title",
            "Role",
            Some("public"),
            "https://agent.example/ag-ui",
            "Bearer secret",
        )
        .unwrap();
        assert_eq!(remote.visibility, AgentVisibility::Public);
        assert_eq!(
            remote.endpoint.as_deref(),
            Some("https://agent.example/ag-ui")
        );
        assert_eq!(remote.auth.unwrap().expose_value(), "Bearer secret");
    }
}
