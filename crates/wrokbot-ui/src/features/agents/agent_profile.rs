//! Agent profile panel with real lifecycle controls and authoritative reloads.

use leptos::prelude::*;
use openbot_contracts::agent::{AgentProfile as AgentProfileDto, AgentVisibility};

use crate::api::channel_new_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{delete_agent, duplicate_agent, load_agent_with_abort_signal, set_agent_hidden};
use crate::i18n::{t, t_string, use_i18n};
use crate::primitives::{
    Avatar, AvatarSize, Badge, Button, ButtonSize, ButtonVariant, Notice, NoticeTone,
};

use super::{AgentEditor, CallbackTokenPanel};

/// Load and render the selected coworker with Server-decided management controls.
#[component]
pub fn AgentProfilePanel(
    /// URL-owned selected Agent identity; `None` clears pending profile state.
    #[prop(into)]
    agent_id: Signal<Option<String>>,
    /// Roster owner receives authoritative created/updated/duplicated profiles.
    on_changed: UnsyncCallback<AgentProfileDto>,
    /// Hide/delete closes the panel and reloads both visible/hidden rosters.
    on_closed: UnsyncCallback<()>,
) -> impl IntoView {
    let i18n = use_i18n();
    let changed_callback = StoredValue::new(on_changed);
    let closed_callback = StoredValue::new(on_closed);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = closed_callback;
    let profile = RwSignal::new(None::<AgentProfileDto>);
    let loading = RwSignal::new(false);
    let load_error = RwSignal::new(false);
    let editing = RwSignal::new(false);
    let confirming_delete = RwSignal::new(false);
    let action_pending = RwSignal::new(false);
    let write_lock = crate::configuration_writes::resource_lock(
        crate::configuration_writes::ConfigurationKind::Agents,
        move || agent_id.get().unwrap_or_default(),
    );
    let action_error = RwSignal::new(false);
    let generation = RwSignal::new(0_u64);
    let reload_generation = RwSignal::new(0_u64);

    Effect::new(move |_| {
        let _ = reload_generation.get();
        let selected = agent_id.get();
        let Some(request_generation) = advance_generation(generation) else {
            profile.set(None);
            loading.set(false);
            load_error.set(true);
            return;
        };
        profile.set(None);
        editing.set(false);
        confirming_delete.set(false);
        action_pending.set(false);
        action_error.set(false);
        load_error.set(false);
        let Some(agent_id) = selected else {
            loading.set(false);
            return;
        };
        loading.set(true);
        #[cfg(target_arch = "wasm32")]
        {
            let Ok(cancellation) = AgentDetailReadAbort::new() else {
                loading.set(false);
                load_error.set(true);
                return;
            };
            let cancellation = std::rc::Rc::new(cancellation);
            let scope_cancellation = StoredValue::new_local(std::rc::Rc::downgrade(&cancellation));
            // Abort the browser read synchronously, before the scoped Rust task is cancelled.
            on_cleanup(move || {
                let _ = scope_cancellation.try_with_value(|pending| {
                    if let Some(pending) = pending.upgrade() {
                        pending.abort_pending();
                    }
                });
            });
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let outcome = load_agent_with_abort_signal(&agent_id, &cancellation.signal).await;
                if outcome.is_ok() {
                    cancellation.disarm();
                }
                if generation.get_untracked() != request_generation {
                    return;
                }
                match outcome {
                    Ok(agent) => profile.set(Some(agent)),
                    Err(_) => load_error.set(true),
                }
                loading.set(false);
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (agent_id, request_generation);
            loading.set(false);
        }
    });

    let saved = UnsyncCallback::new(move |saved: AgentProfileDto| {
        profile.set(Some(saved.clone()));
        editing.set(false);
        action_error.set(false);
        changed_callback.get_value().run(saved);
    });
    let cancel_edit = UnsyncCallback::new(move |_| {
        editing.set(false);
        action_error.set(false);
    });

    view! {
        <Show when=move || loading.get()>
            <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
        </Show>
        <Show when=move || load_error.get()>
            <Notice tone=NoticeTone::Error>
                <span>{move || t!(i18n, agents.detail_load_error)}</span>
                <Button
                    variant=ButtonVariant::Ghost
                    size=ButtonSize::Small
                    loading=Signal::derive(move || loading.get())
                    on_activate=move |_| {
                        if loading.get_untracked() {
                            return;
                        }
                        loading.set(true);
                        reload_generation.update(|generation| *generation = generation.saturating_add(1));
                    }
                >{move || t!(i18n, common.retry)}</Button>
            </Notice>
        </Show>
        {move || profile.get().map(|current| {
            if editing.get() {
                return view! {
                    <AgentEditor
                        profile=Some(current)
                        on_saved=saved
                        on_cancel=cancel_edit
                    />
                }.into_any();
            }
            let avatar_seed = current.avatar_seed.clone();
            let avatar_name = current.name.clone();
            let name = current.name.clone();
            let title = current.title.clone();
            let role_description = current.role_description.clone();
            let visibility = current.visibility;
            let system_owned = current.system_owned;
            let can_manage = current.can_manage;
            let hidden = current.hidden;
            let remote = current.endpoint.is_some();
            let has_callback_token = current.has_callback_token;
            let start_id = current.id.clone();
            let callback_id = current.id.clone();
            let duplicate_id = StoredValue::new(current.id.clone());
            let hide_id = StoredValue::new(current.id.clone());
            let delete_id = StoredValue::new(current.id.clone());
            #[cfg(not(target_arch = "wasm32"))]
            let _ = (duplicate_id, hide_id, delete_id);
            let start_href = channel_new_href(start_id.as_str())
                .expect("server Agent id must be route-safe");
            let delete_name = StoredValue::new(name.clone());
            view! {
                <article class="ob-agent-profile">
                    <header class="ob-agent-profile-header">
                        <span class="ob-agent-profile-avatar" aria-hidden="true">
                            <Avatar
                                principal_id=avatar_seed
                                name=avatar_name
                                size=AvatarSize::Large
                            />
                        </span>
                        <div class="ob-agent-profile-identity">
                            <h3>{name.clone()}</h3>
                            <p>{title}</p>
                        </div>
                        <div class="ob-agent-profile-badges">
                            <Badge>
                                {move || match visibility {
                                    AgentVisibility::Public => {
                                        t_string!(i18n, agents.visibility_public).to_owned()
                                    }
                                    AgentVisibility::Private => {
                                        t_string!(i18n, agents.visibility_private).to_owned()
                                    }
                                }}
                            </Badge>
                            <Show when=move || system_owned>
                                <Badge>{move || t!(i18n, agents.system_owned)}</Badge>
                            </Show>
                            <Show when=move || hidden>
                                <Badge>{move || t!(i18n, agents.hidden_badge)}</Badge>
                            </Show>
                        </div>
                    </header>
                    <section class="ob-agent-profile-role" aria-labelledby="agent-profile-role-title">
                        <h4 id="agent-profile-role-title">
                            {move || t!(i18n, agents.role_label)}
                        </h4>
                        <p>{role_description}</p>
                    </section>
                    <Show when=move || remote && can_manage>
                        <CallbackTokenPanel
                            agent_id=callback_id.clone()
                            has_token=has_callback_token
                        />
                    </Show>
                    <Show when=move || action_error.get()>
                        <Notice tone=NoticeTone::Error>{move || t!(i18n, agents.action_error)}</Notice>
                    </Show>
                    <div class="ob-agent-profile-actions">
                        <a
                            class="ob-button"
                            data-variant="primary"
                            data-size="md"
                            href=start_href
                        >{move || t!(i18n, agents.start_channel)}</a>
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                            on_activate=move |_| {
                                action_pending.set(true);
                                action_error.set(false);
                                let request_generation = generation.get_untracked();
                                #[cfg(target_arch = "wasm32")]
                                {
                                    let id = duplicate_id.get_value();
                                    leptos::task::spawn_local_scoped_with_cancellation(async move {
                                        let outcome = duplicate_agent(id.as_str()).await;
                                        if generation.get_untracked() != request_generation {
                                            return;
                                        }
                                        match outcome {
                                            Ok(copy) => changed_callback.get_value().run(copy),
                                            Err(_) => action_error.set(true),
                                        }
                                        action_pending.set(false);
                                    });
                                }
                                #[cfg(not(target_arch = "wasm32"))]
                                {
                                    let _ = request_generation;
                                    action_pending.set(false);
                                }
                            }
                        >{move || t!(i18n, agents.duplicate)}</Button>
                        <Button
                            variant=ButtonVariant::Chip
                            size=ButtonSize::Small
                            disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                            on_activate=move |_| {
                                action_pending.set(true);
                                action_error.set(false);
                                let request_generation = generation.get_untracked();
                                #[cfg(target_arch = "wasm32")]
                                {
                                    let id = hide_id.get_value();
                                    leptos::task::spawn_local_scoped_with_cancellation(async move {
                                        let outcome = set_agent_hidden(id.as_str(), !hidden).await;
                                        if generation.get_untracked() != request_generation {
                                            return;
                                        }
                                        match outcome {
                                            Ok(()) => closed_callback.get_value().run(()),
                                            Err(_) => action_error.set(true),
                                        }
                                        action_pending.set(false);
                                    });
                                }
                                #[cfg(not(target_arch = "wasm32"))]
                                {
                                    let _ = request_generation;
                                    action_pending.set(false);
                                }
                            }
                        >
                            {move || if hidden {
                                t_string!(i18n, agents.unhide).to_owned()
                            } else {
                                t_string!(i18n, agents.hide).to_owned()
                            }}
                        </Button>
                        <Show when=move || can_manage>
                            <Button
                                variant=ButtonVariant::Chip
                                size=ButtonSize::Small
                                disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                                on_activate=move |_| editing.set(true)
                            >{move || t!(i18n, common.edit)}</Button>
                            <Show
                                when=move || confirming_delete.get()
                                fallback=move || view! {
                                    <Button
                                        variant=ButtonVariant::DangerText
                                        size=ButtonSize::Small
                                        disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                                        on_activate=move |_| confirming_delete.set(true)
                                    >{move || t!(i18n, common.delete)}</Button>
                                }
                            >
                                <div class="ob-agent-delete-confirm" role="group" aria-label=move || {
                                    t_string!(i18n, agents.delete_confirm_label, name = delete_name.get_value()).to_owned()
                                }>
                                    <p>{move || t!(i18n, agents.delete_confirm, name = delete_name.get_value())}</p>
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Small
                                        disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                                        on_activate=move |_| confirming_delete.set(false)
                                    >{move || t!(i18n, common.cancel)}</Button>
                                    <Button
                                        variant=ButtonVariant::DangerText
                                        size=ButtonSize::Small
                                        disabled=Signal::derive(move || action_pending.get() || write_lock.get())
                                        on_activate=move |_| {
                                            action_pending.set(true);
                                            action_error.set(false);
                                            let request_generation = generation.get_untracked();
                                            #[cfg(target_arch = "wasm32")]
                                            {
                                                let id = delete_id.get_value();
                                                leptos::task::spawn_local_scoped_with_cancellation(async move {
                                                    let outcome = delete_agent(id.as_str()).await;
                                                    if generation.get_untracked() != request_generation {
                                                        return;
                                                    }
                                                    match outcome {
                                                        Ok(()) => closed_callback.get_value().run(()),
                                                        Err(_) => action_error.set(true),
                                                    }
                                                    action_pending.set(false);
                                                });
                                            }
                                            #[cfg(not(target_arch = "wasm32"))]
                                            {
                                                let _ = request_generation;
                                                action_pending.set(false);
                                            }
                                        }
                                    >{move || t!(i18n, agents.delete_action)}</Button>
                                </div>
                            </Show>
                        </Show>
                    </div>
                </article>
            }.into_any()
        })}
    }
}

// Only the selected profile read owns this controller; Agent mutations keep their existing owners.
#[cfg(target_arch = "wasm32")]
struct AgentDetailReadAbort {
    controller: wasm_bindgen::JsValue,
    signal: web_sys::AbortSignal,
    abort: js_sys::Function,
    pending: std::cell::Cell<bool>,
}

#[cfg(target_arch = "wasm32")]
impl AgentDetailReadAbort {
    fn new() -> Result<Self, crate::api::ApiError> {
        use wasm_bindgen::{JsCast, JsValue};

        let unavailable = |_| crate::api::ApiError::Unavailable;
        let constructor = js_sys::Reflect::get(&js_sys::global(), &"AbortController".into())
            .map_err(unavailable)?
            .dyn_into::<js_sys::Function>()
            .map_err(unavailable)?;
        let controller: JsValue = js_sys::Reflect::construct(&constructor, &js_sys::Array::new())
            .map_err(unavailable)?
            .into();
        let signal = js_sys::Reflect::get(&controller, &"signal".into())
            .map_err(unavailable)?
            .dyn_into::<web_sys::AbortSignal>()
            .map_err(unavailable)?;
        let abort = js_sys::Reflect::get(&controller, &"abort".into())
            .map_err(unavailable)?
            .dyn_into::<js_sys::Function>()
            .map_err(unavailable)?;
        Ok(Self {
            controller,
            signal,
            abort,
            pending: std::cell::Cell::new(true),
        })
    }

    fn abort_pending(&self) {
        if self.pending.replace(false) {
            let _ = self.abort.call0(&self.controller);
        }
    }

    fn disarm(&self) {
        self.pending.set(false);
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for AgentDetailReadAbort {
    fn drop(&mut self) {
        self.abort_pending();
    }
}

fn advance_generation(generation: RwSignal<u64>) -> Option<u64> {
    let next = generation.get_untracked().checked_add(1)?;
    generation.set(next);
    Some(next)
}
