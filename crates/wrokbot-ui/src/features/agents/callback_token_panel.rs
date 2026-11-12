//! One-time remote Agent callback credential presentation.

use leptos::prelude::*;
use openbot_contracts::agent::CallbackTokenIssued;
use openbot_contracts::ids::BotId;

#[cfg(target_arch = "wasm32")]
use crate::api::{issue_agent_callback_token, revoke_agent_callback_token};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Button, ButtonSize, ButtonVariant, Notice, NoticePresentation, NoticeTone,
};

/// Generate/rotate/revoke one remote Agent callback token. Cleartext lives only in this component.
#[component]
pub fn CallbackTokenPanel(
    /// Server-owned remote Agent identity.
    agent_id: BotId,
    /// Authoritative initial existence flag; never the credential value.
    has_token: bool,
) -> impl IntoView {
    let i18n = use_i18n();
    let agent_id = StoredValue::new(agent_id);
    let current_has_token = RwSignal::new(has_token);
    let token = StoredValue::new(None::<CallbackTokenIssued>);
    let token_visible = RwSignal::new(false);
    let pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Agents,
        move || agent_id.get_value().as_str().to_owned(),
    );
    let operation_error = RwSignal::new(false);

    let clear_token = move || {
        token.update_value(clear_one_time_token);
        token_visible.set(false);
    };
    on_cleanup(move || token.update_value(clear_one_time_token));

    let issue = move |_| {
        pending.set(true);
        operation_error.set(false);
        clear_token();
        #[cfg(target_arch = "wasm32")]
        {
            let id = agent_id.get_value();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match issue_agent_callback_token(id.as_str()).await {
                    Ok(issued) => {
                        token.update_value(|slot| replace_one_time_token(slot, issued));
                        current_has_token.set(true);
                        token_visible.set(true);
                    }
                    Err(_) => operation_error.set(true),
                }
                pending.set(false);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        pending.set(false);
    };

    let revoke = move |_| {
        pending.set(true);
        operation_error.set(false);
        clear_token();
        #[cfg(target_arch = "wasm32")]
        {
            let id = agent_id.get_value();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match revoke_agent_callback_token(id.as_str()).await {
                    Ok(()) => current_has_token.set(false),
                    Err(_) => operation_error.set(true),
                }
                pending.set(false);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        pending.set(false);
    };

    view! {
        <section class="ob-agent-callback" aria-labelledby="agent-callback-title">
            <h4 id="agent-callback-title">{move || t!(i18n, agents.callback_title)}</h4>
            <p class="ob-agent-callback-description">
                {move || if current_has_token.get() {
                    t_string!(i18n, agents.callback_present).to_owned()
                } else {
                    t_string!(i18n, agents.callback_absent).to_owned()
                }}
            </p>
            <Show
                when=move || token_visible.get()
                fallback=move || view! {
                    <div class="ob-agent-callback-actions">
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            disabled=Signal::derive(move || pending.get() || write_lock.get())
                            on_activate=issue
                        >
                            {move || if pending.get() {
                                t_string!(i18n, agents.callback_working).to_owned()
                            } else if current_has_token.get() {
                                t_string!(i18n, agents.callback_rotate).to_owned()
                            } else {
                                t_string!(i18n, agents.callback_generate).to_owned()
                            }}
                        </Button>
                        <Show when=move || current_has_token.get()>
                            <Button
                                variant=ButtonVariant::DangerText
                                size=ButtonSize::Small
                                disabled=Signal::derive(move || pending.get() || write_lock.get())
                                on_activate=revoke
                            >{move || t!(i18n, agents.callback_revoke)}</Button>
                        </Show>
                    </div>
                }
            >
                <div class="ob-agent-callback-once">
                    <p class="ob-agent-callback-warning">
                        {move || t!(i18n, agents.callback_once)}
                    </p>
                    <code
                        class="ob-agent-callback-token"
                        tabindex="0"
                        aria-label=move || t_string!(i18n, agents.callback_token_label).to_owned()
                    >
                        {move || token.with_value(|slot| {
                            slot.as_ref()
                                .map(|issued| issued.expose().to_owned())
                                .unwrap_or_default()
                        })}
                    </code>
                    <p class="ob-agent-callback-help">
                        {move || t!(i18n, agents.callback_once_help)}
                    </p>
                    <Button
                        variant=ButtonVariant::Chip
                        size=ButtonSize::Small
                        on_activate=move |_| clear_token()
                    >{move || t!(i18n, common.dismiss)}</Button>
                </div>
            </Show>
            <Show when=move || operation_error.get()>
                <Notice tone=NoticeTone::Error presentation=NoticePresentation::Inline>{move || t!(i18n, agents.callback_error)}</Notice>
            </Show>
        </section>
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn replace_one_time_token(slot: &mut Option<CallbackTokenIssued>, issued: CallbackTokenIssued) {
    *slot = Some(issued);
}

fn clear_one_time_token(slot: &mut Option<CallbackTokenIssued>) {
    *slot = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_slot_replaces_and_clears_the_visible_credential() {
        let mut slot = None;
        replace_one_time_token(
            &mut slot,
            CallbackTokenIssued::new("obot_agt_first".to_owned()).unwrap(),
        );
        assert_eq!(slot.as_ref().unwrap().expose(), "obot_agt_first");

        replace_one_time_token(
            &mut slot,
            CallbackTokenIssued::new("obot_agt_second".to_owned()).unwrap(),
        );
        assert_eq!(slot.as_ref().unwrap().expose(), "obot_agt_second");

        clear_one_time_token(&mut slot);
        assert!(slot.is_none());
    }
}
