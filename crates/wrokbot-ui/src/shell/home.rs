//! Root Home Composer: structured mention, confirmed routing, and durable first message.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use openbot_contracts::agent::AgentProfile;
#[cfg(test)]
use openbot_contracts::agent::AgentVisibility;
use openbot_contracts::ids::BotId;
use openbot_contracts::text::trim_ecmascript;

#[cfg(any(target_arch = "wasm32", test))]
use crate::api::ApiError;
use crate::api::channel_new_href;
#[cfg(target_arch = "wasm32")]
use crate::api::{channel_route_href, mint_run_id, route_channel_message};
use crate::features::agents::{AgentDirectory, use_agent_directory};
use crate::features::channels::composer::model_intents::{RunSubmissionActions, SubmissionSource};
use crate::features::channels::composer::models::{ModelComposer, ModelPicker};
use crate::features::channels::composer::presentation::{
    AssistantIdentity, ComposerFrame, DraftSuggestions,
};
use crate::features::channels::composer::skills::{SkillComposer, SkillPicker};
use crate::features::channels::new::{StartAttempt, SubmissionNotice, model_notice};
#[cfg(target_arch = "wasm32")]
use crate::features::channels::new::{
    StartFailure, StartFailureKind, definite_notice, execute_start_attempt,
};
use crate::features::layout::{PageShell, PageWidth};
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Avatar, AvatarSize, Button, ButtonSize, ButtonVariant, IconSize, IconView, Notice, NoticeTone,
    Select, SelectContent, SelectItem, SelectTrigger, Textarea,
};
use crate::shell::layout::set_shell_title;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MentionSelection {
    agent_id: BotId,
    display_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveMention {
    start: usize,
    query: String,
}

/// First-message Home route with confirmed automatic routing and explicit `@` choice.
#[component]
pub fn HomePage() -> impl IntoView {
    let i18n = use_i18n();
    let navigate = use_navigate();
    let directory = use_agent_directory();
    set_shell_title(move || vec![t_string!(i18n, shell.nav_chat).to_owned()]);
    let AgentDirectory {
        agents,
        loading,
        failed: load_error,
        ..
    } = directory;
    let draft = RwSignal::new(String::new());
    let agent_picker_open = RwSignal::new(false);
    let selected_mention = RwSignal::new(None::<MentionSelection>);
    let frozen_model_agent = RwSignal::new(None::<BotId>);
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || selected_mention.get().map(|s| s.agent_id)),
        "home-message",
    );
    let model_composer = ModelComposer::new(
        Signal::derive(move || {
            let agent_id = frozen_model_agent
                .get()
                .or_else(|| selected_mention.get().map(|selection| selection.agent_id));
            let Some(agent_id) = agent_id else {
                return false;
            };
            supports_explicit_model(&agents.get(), &agent_id)
        }),
        Signal::derive(move || {
            frozen_model_agent
                .get()
                .or_else(|| selected_mention.get().map(|selection| selection.agent_id))
        }),
    );
    let submitting = RwSignal::new(false);
    let notice = RwSignal::new(None::<SubmissionNotice>);
    let uncertain_create = RwSignal::new(false);
    let begin_unknown = RwSignal::new(false);
    let submission_blocked = RwSignal::new(false);
    let resumable = RwSignal::new(None::<StartAttempt>);
    let submissions = expect_context::<RunSubmissionActions>();

    Effect::new(move |_| {
        if let Some(intent) = submissions.create_unknown(SubmissionSource::Home) {
            uncertain_create.set(true);
            frozen_model_agent.set(Some(intent.agent_id.clone()));
            draft.set(intent.message);
            skill_composer.selected.set(intent.selected_skill_slugs);
            model_composer.restore_selection(intent.model_selection, Some(intent.agent_id.clone()));
            if let Some(agent) = agents
                .get()
                .into_iter()
                .find(|agent| agent.id == intent.agent_id)
            {
                selected_mention.set(Some(MentionSelection {
                    agent_id: agent.id,
                    display_text: agent.name,
                }));
            }
        }
        if resumable.get_untracked().is_none()
            && let Some(recovery) = submissions.run_unknown_for_source(SubmissionSource::Home)
            && let Some(channel) = recovery.channel
        {
            let intent = recovery.intent;
            frozen_model_agent.set(Some(intent.agent_id.clone()));
            draft.set(intent.message.clone());
            skill_composer
                .selected
                .set(intent.selected_skill_slugs.clone());
            model_composer.restore_selection(
                intent.model_selection.clone(),
                Some(intent.agent_id.clone()),
            );
            if let Some(agent) = agents
                .get()
                .into_iter()
                .find(|agent| agent.id == intent.agent_id)
            {
                selected_mention.set(Some(MentionSelection {
                    agent_id: agent.id,
                    display_text: agent.name,
                }));
            }
            resumable.set(Some(StartAttempt {
                source: SubmissionSource::Home,
                agent_id: intent.agent_id,
                message: intent.message,
                run_id: intent.run_id,
                channel: Some(channel),
                selected_skill_slugs: intent.selected_skill_slugs,
                model_selection: intent.model_selection,
            }));
            begin_unknown.set(true);
            notice.set(None);
        }
    });
    Effect::new(move |_| {
        if submitting.get() {
            return;
        }
        let owns_barrier = submissions.create_unknown(SubmissionSource::Home).is_some()
            || submissions
                .run_unknown_for_source(SubmissionSource::Home)
                .is_some();
        submission_blocked.set(!owns_barrier && submissions.has_barrier());
    });

    let has_agents = Memo::new(move |_| agents.get().iter().any(valid_home_agent));
    let active =
        Memo::new(move |_| unselected_mention(&draft.get(), selected_mention.get().as_ref()));
    let suggestions = Memo::new(move |_| {
        active.get().map_or_else(Vec::new, |active| {
            mention_candidates(&agents.get(), &active.query)
        })
    });
    Effect::new(move |_| {
        let text = draft.get();
        if selected_mention
            .get_untracked()
            .as_ref()
            .is_some_and(|selection| !selection_is_present(&text, selection))
        {
            selected_mention.set(None);
        }
    });

    let inputs_locked = Signal::derive(move || {
        submitting.get()
            || resumable.get().is_some()
            || uncertain_create.get()
            || submission_blocked.get()
    });
    let choose_mention = UnsyncCallback::new(move |agent: AgentProfile| {
        if inputs_locked.get_untracked() {
            return;
        }
        let current = draft.get_untracked();
        let previous = selected_mention.get_untracked();
        if let Some(updated) = insert_mention(&current, previous.as_ref(), &agent) {
            draft.set(updated);
            selected_mention.set(Some(MentionSelection {
                agent_id: agent.id,
                display_text: agent.name,
            }));
        }
    });

    let assistant_picker_value = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        assistant_picker_value.set(
            selected_mention
                .get()
                .map(|selected| selected.agent_id.as_str().to_owned()),
        );
        if inputs_locked.get() {
            agent_picker_open.set(false);
        }
    });
    let choose_assistant = UnsyncCallback::new(move |value: Option<String>| {
        if inputs_locked.get_untracked() {
            return;
        }
        if let Some(agent) = value.and_then(|id| {
            agents
                .get_untracked()
                .into_iter()
                .find(|agent| agent.id.as_str() == id && valid_home_agent(agent))
        }) {
            let text = draft.get_untracked();
            if active_mention(&text).is_none() {
                draft.set(format!("{text} @"));
            }
            choose_mention.run(agent);
        }
    });
    let send_disabled = Signal::derive(move || {
        submitting.get()
            || uncertain_create.get()
            || submission_blocked.get()
            || (resumable.get().is_none()
                && (!has_agents.get()
                    || !home_has_task(&draft.get(), selected_mention.get().as_ref())
                    || skill_composer.invalid.get()))
    });
    let mention_open = Signal::derive(move || active.get().is_some() && !inputs_locked.get());

    #[cfg(target_arch = "wasm32")]
    let send_navigate = navigate;
    #[cfg(not(target_arch = "wasm32"))]
    let _ = navigate;
    let send = UnsyncCallback::new(move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        let prior_attempt = resumable.get_untracked();
        if prior_attempt.is_none() {
            frozen_model_agent.set(None);
        }
        let fresh = if prior_attempt.is_none() {
            if !has_agents.get_untracked() {
                return;
            }
            let message = draft.get_untracked();
            if !home_has_task(&message, selected_mention.get_untracked().as_ref()) {
                return;
            }
            if let Some(model_notice) = model_notice(model_composer.selection_status()) {
                notice.set(Some(model_notice));
                return;
            }
            let model_selection = match model_composer.freeze() {
                Ok(selection) => selection,
                Err(_) => {
                    notice.set(Some(SubmissionNotice::ModelSelectionUnavailable));
                    return;
                }
            };
            let explicit = selected_agent_id(&message, selected_mention.get_untracked().as_ref());
            Some((
                message,
                skill_composer.selected.get_untracked(),
                model_selection,
                explicit,
                agents.get_untracked(),
            ))
        } else {
            None
        };
        submitting.set(true);
        notice.set(None);
        begin_unknown.set(false);
        submission_blocked.set(false);
        #[cfg(target_arch = "wasm32")]
        {
            let navigate_after_send = send_navigate.clone();
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let retry_unknown = prior_attempt.is_some();
                let attempt = match prior_attempt {
                    Some(attempt) => attempt,
                    None => {
                        let (message, selected_skill_slugs, model_selection, explicit, roster) =
                            fresh.expect("fresh attempt");
                        let recipient =
                            resolve_home_recipient(&message, explicit.as_ref(), &roster).await;
                        let agent_id = match recipient {
                            Ok(id) => id,
                            Err(_) => {
                                notice.set(Some(SubmissionNotice::RoutingFailed));
                                submitting.set(false);
                                return;
                            }
                        };
                        if model_selection.is_some() && !supports_explicit_model(&roster, &agent_id)
                        {
                            notice.set(Some(SubmissionNotice::ModelAgentConflict));
                            submitting.set(false);
                            return;
                        }
                        let attempt = StartAttempt {
                            source: SubmissionSource::Home,
                            agent_id,
                            message,
                            run_id: mint_run_id(),
                            channel: None,
                            selected_skill_slugs,
                            model_selection,
                        };
                        // Route selection and run identity are now fixed. Retries never reroute.
                        resumable.set(Some(attempt.clone()));
                        attempt
                    }
                };
                match execute_start_attempt(attempt, retry_unknown).await {
                    Ok(started) => {
                        let href = channel_route_href(started.channel.id.as_str());
                        resumable.set(Some(started.attempt));
                        submitting.set(false);
                        match href {
                            Ok(href) => navigate_after_send(&href, Default::default()),
                            Err(_) => notice.set(Some(SubmissionNotice::NavigationFailed)),
                        }
                    }
                    Err(failure) => {
                        let StartFailure {
                            attempt,
                            kind,
                            error,
                        } = *failure;
                        match kind {
                            StartFailureKind::CreateUncertain => {
                                uncertain_create.set(true);
                                resumable.set(Some(attempt));
                                notice.set(None);
                            }
                            StartFailureKind::BeginUnknown => {
                                resumable.set(Some(attempt));
                                begin_unknown.set(true);
                                notice.set(None);
                            }
                            StartFailureKind::CreateDefinite | StartFailureKind::BeginDefinite => {
                                resumable.set(None);
                                frozen_model_agent.set(None);
                                let rejected = definite_notice(error);
                                if rejected == SubmissionNotice::Conflict {
                                    model_composer.directory_reload();
                                }
                                notice.set(Some(rejected));
                            }
                            StartFailureKind::Blocked => submission_blocked.set(true),
                        }
                        submitting.set(false);
                    }
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (prior_attempt, fresh);
            submitting.set(false);
            notice.set(Some(SubmissionNotice::Rejected));
        }
    });
    let submit_or_choose = UnsyncCallback::new(move |_| {
        if active.get_untracked().is_some()
            && let Some(agent) = suggestions.get_untracked().into_iter().next()
        {
            choose_mention.run(agent);
            return;
        }
        send.run(());
    });
    let retry_agents = move |_| directory.refresh();

    let identity = Signal::derive(move || {
        let selected = frozen_model_agent
            .get()
            .or_else(|| selected_mention.get().map(|mention| mention.agent_id));
        selected.and_then(|id| agents.get().into_iter().find(|agent| agent.id == id))
    });
    let suggest = UnsyncCallback::new(move |text: String| {
        if !inputs_locked.get_untracked() {
            let prefix = selected_mention
                .get_untracked()
                .map_or_else(String::new, |selected| {
                    format!("@{} ", selected.display_text)
                });
            draft.set(format!("{prefix}{text}"));
        }
    });

    view! {
        <PageShell width=PageWidth::Chat>
            <div class="ob-home">
                <AssistantIdentity profile=identity title=move || t_string!(i18n, home.auto_assistant).to_owned() description=move || t_string!(i18n, home.auto_description).to_owned()/>
                <Show when=move || loading.get()>
                    <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
                </Show>
                <Show when=move || load_error.get()>
                    <Notice tone=NoticeTone::Error>
                        <span>{move || t!(i18n, home.agents_load_error)}</span>
                        <Button
                            size=ButtonSize::Small
                            variant=ButtonVariant::Ghost
                            on_activate=retry_agents
                        >
                            {move || t!(i18n, common.retry)}
                        </Button>
                    </Notice>
                </Show>
                <div class="ob-home-footer">
                <ComposerFrame busy=Signal::derive(move || submitting.get())>
                    <Textarea
                        value=draft
                        id="home-message"
                        aria_label=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                        placeholder=move || t_string!(i18n, home.placeholder).to_owned()
                        disabled=inputs_locked
                        combobox_controls=Signal::derive(move || if skill_composer.open.get() { "channel-skill-results".to_owned() } else { "home-mention-results".to_owned() })
                        combobox_open=Signal::derive(move || mention_open.get() || skill_composer.open.get())
                        active_descendant=skill_composer.active_descendant
                        on_keydown=UnsyncCallback::new(move |event| skill_composer.keyboard(event))
                        on_submit=submit_or_choose
                    />
                    <Show when=move || mention_open.get()>
                        <div
                            id="home-mention-results"
                            class="ob-home-mention-results"
                            role="listbox"
                            aria-label=move || t_string!(i18n, home.mention_results).to_owned()
                        >
                            <Show
                                when=move || !suggestions.get().is_empty()
                                fallback=move || view! {
                                    <p>{move || t!(i18n, home.mention_empty)}</p>
                                }
                            >
                                <For
                                    each=move || suggestions.get()
                                    key=|agent| agent.id.clone()
                                    children=move |agent| {
                                        let selected_id = agent.id.clone();
                                        let activate_agent = agent.clone();
                                        let avatar_seed = agent.avatar_seed.clone();
                                        let avatar_name = agent.name.clone();
                                        let name = agent.name;
                                        let role = agent.role_description;
                                        view! {
                                            <button
                                                type="button"
                                                role="option"
                                                aria-selected=move || selected_mention.get().as_ref().is_some_and(|selection| {
                                                    selection.agent_id == selected_id
                                                }).to_string()
                                                on:click=move |_| choose_mention.run(activate_agent.clone())
                                            >
                                                <span aria-hidden="true">
                                                    <Avatar
                                                        principal_id=avatar_seed.clone()
                                                        name=avatar_name.clone()
                                                        size=AvatarSize::Small
                                                    />
                                                </span>
                                                <span>
                                                    <strong>{name.clone()}</strong>
                                                    <small>{role.clone()}</small>
                                                </span>
                                            </button>
                                        }
                                    }
                                />
                            </Show>
                        </div>
                    </Show>
                    <div class="ob-chat-controls">
                        <Select id="home-agent-picker" open=agent_picker_open value=assistant_picker_value disabled=inputs_locked on_value_change=choose_assistant>
                            <SelectTrigger aria_label=move || t_string!(i18n, home.choose_agent).to_owned() placeholder=move || t_string!(i18n, home.auto_assistant).to_owned()/>
                            <SelectContent>
                                <For each=move || { agents.get().into_iter().filter(valid_home_agent).collect::<Vec<_>>() } key=|agent| agent.id.clone() children=move |agent| {
                                    let id = agent.id.as_str().to_owned();
                                    let label = agent.name.clone();
                                    view! { <SelectItem id=format!("home-assistant-{id}") value=id label=label disabled=inputs_locked>
                                        <strong>{agent.name}</strong><small>{agent.role_description}</small>
                                        {agent.endpoint.is_some().then(|| view! { <small>{move || t!(i18n, shell.remote_agent)}</small> })}
                                    </SelectItem> }
                                }/>
                                <a class="ob-home-agent-manage-link" href="/agents">{move || t!(i18n, home.explore_agents)}</a>
                            </SelectContent>
                        </Select>
                        <ModelPicker state=model_composer disabled=inputs_locked/>
                        <SkillPicker state=skill_composer disabled=inputs_locked/>
                        <span class="ob-chat-send">
                        <Button
                            id="home-send"
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            disabled=send_disabled
                            loading=submitting
                            on_activate=move |_| send.run(())
                        >
                            <IconView icon=Icon::ArrowUp size=IconSize::Navigation />
                            <span class="ob-visually-hidden">{move || if begin_unknown.get() {
                                t_string!(i18n, channels.retry_original).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                        </span>
                    </div>
                </ComposerFrame>
                <DraftSuggestions on_choose=suggest disabled=inputs_locked/>
                <p class="ob-home-model-preset-note" role="note">{move || t!(i18n, home.model_preset_note)}</p>
                <Show when=move || !loading.get() && !load_error.get() && !has_agents.get()>
                    <p class="ob-home-routing-hint" role="status">
                        <a href="/agents">{move || t!(i18n, home.no_agents)}</a>
                    </p>
                </Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::ModelAgentConflict) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelAgentConflict)><Notice tone=NoticeTone::Error>{move || t!(i18n, channels.model_agent_conflict)}</Notice></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::ModelSelectionUnavailable) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelSelectionUnavailable)><Notice tone=NoticeTone::Error>{move || t!(i18n, channels.model_selection_unavailable)}</Notice></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::Conflict)><Notice tone=NoticeTone::Error>{move || t!(i18n, channels.submit_conflict)}</Notice></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::Rejected)><Notice tone=NoticeTone::Error>{move || t!(i18n, channels.submit_rejected)}</Notice></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::NavigationFailed)><Notice tone=NoticeTone::Error>{move || t!(i18n, channels.navigation_failed)}</Notice></Show>
                <Show when=move || notice.get()==Some(SubmissionNotice::RoutingFailed)><Notice tone=NoticeTone::Error>{move || t!(i18n, home.routing_failed)}</Notice></Show>
                <Show when=move || uncertain_create.get()>
                    <Notice tone=NoticeTone::Error>
                        <p>{move || t!(i18n, channels.create_uncertain)}</p>
                        <a href="/">{move || t!(i18n, home.title)}</a>
                    </Notice>
                </Show>
                <Show when=move || begin_unknown.get()>
                    <Notice tone=NoticeTone::Error>{move || t!(i18n, channels.begin_unknown)}</Notice>
                </Show>
                <Show when=move || submission_blocked.get()>
                    <Notice tone=NoticeTone::Error><a href=move || submissions.barrier().and_then(|barrier| barrier.href()).unwrap_or_else(|| "/".to_owned())>
                        {move || t!(i18n, channels.submission_blocked)}
                    </a></Notice>
                </Show>

                </div>
            </div>
        </PageShell>
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_home_recipient(
    message: &str,
    explicit: Option<&BotId>,
    roster: &[AgentProfile],
) -> Result<BotId, ApiError> {
    if let Some(explicit) = explicit {
        // The person already chose. The request exists only to record that fact; fixed-upstream
        // behavior does not let an audit transport failure overturn their recipient choice.
        _ = route_channel_message(message, Some(explicit)).await;
        return confirmed_home_recipient(roster, explicit.clone());
    }
    match route_channel_message(message, None).await {
        Ok(decision) => confirmed_home_recipient(roster, decision.agent_id),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn confirmed_home_recipient(roster: &[AgentProfile], id: BotId) -> Result<BotId, ApiError> {
    roster
        .iter()
        .any(|agent| agent.id == id && valid_home_agent(agent))
        .then_some(id)
        .ok_or(ApiError::InvalidResponse)
}

fn supports_explicit_model(agents: &[AgentProfile], agent_id: &BotId) -> bool {
    agents
        .iter()
        .find(|agent| &agent.id == agent_id)
        .is_some_and(|agent| agent.endpoint.is_none())
}

fn valid_home_agent(agent: &AgentProfile) -> bool {
    !agent.name.is_empty()
        && agent.name.len() <= 512
        && !agent.name.chars().any(char::is_control)
        && channel_new_href(agent.id.as_str()).is_ok()
}

#[cfg(test)]
fn explore_agents(agents: &[AgentProfile]) -> Vec<AgentProfile> {
    agents
        .iter()
        .filter(|agent| {
            valid_home_agent(agent) && !agent.mine && agent.visibility == AgentVisibility::Public
        })
        .cloned()
        .collect()
}

#[cfg(test)]
fn fallback_agent(agents: &[AgentProfile]) -> Option<AgentProfile> {
    explore_agents(agents)
        .into_iter()
        .next()
        .or_else(|| agents.iter().find(|agent| valid_home_agent(agent)).cloned())
}

fn active_mention(value: &str) -> Option<ActiveMention> {
    let start = value.rfind('@')?;
    if value[..start]
        .chars()
        .next_back()
        .is_some_and(|character| !character.is_whitespace())
    {
        return None;
    }
    let query = &value[start + 1..];
    if query.contains('\n')
        || query.contains('\r')
        || query.chars().last().is_some_and(char::is_whitespace)
        || query.len() > 512
    {
        return None;
    }
    Some(ActiveMention {
        start,
        query: query.to_owned(),
    })
}

fn unselected_mention(value: &str, selected: Option<&MentionSelection>) -> Option<ActiveMention> {
    let active = active_mention(value)?;
    if let Some(selection) = selected {
        let marker = selection_marker(selection);
        if let Some(remainder) = value[active.start..].strip_prefix(&marker)
            && (remainder.is_empty() || remainder.chars().next().is_some_and(char::is_whitespace))
        {
            return None;
        }
    }
    Some(active)
}

fn mention_candidates(agents: &[AgentProfile], query: &str) -> Vec<AgentProfile> {
    let query = query.to_lowercase();
    agents
        .iter()
        .filter(|agent| {
            valid_home_agent(agent)
                && (query.is_empty()
                    || agent.name.to_lowercase().contains(&query)
                    || agent.id.as_str().to_lowercase().contains(&query))
        })
        .cloned()
        .collect()
}

fn selection_marker(selection: &MentionSelection) -> String {
    format!("@{}", selection.display_text)
}

fn selection_is_present(value: &str, selection: &MentionSelection) -> bool {
    value.contains(&selection_marker(selection))
}

/// The selected assistant marker is routing context, not a task description.
/// Skill candidates have already been removed by the shared composer; the original draft stays intact.
fn home_has_task(value: &str, selected: Option<&MentionSelection>) -> bool {
    let text = trim_ecmascript(value);
    if text.is_empty() {
        return false;
    }
    let Some(selected) = selected.filter(|selected| selection_is_present(value, selected)) else {
        return true;
    };
    text != trim_ecmascript(&selection_marker(selected))
}

fn selected_agent_id(value: &str, selection: Option<&MentionSelection>) -> Option<BotId> {
    selection
        .filter(|selection| selection_is_present(value, selection))
        .map(|selection| selection.agent_id.clone())
}

fn insert_mention(
    value: &str,
    previous: Option<&MentionSelection>,
    agent: &AgentProfile,
) -> Option<String> {
    if !valid_home_agent(agent) {
        return None;
    }
    let mut updated = value.to_owned();
    if let Some(previous) = previous {
        let marker = selection_marker(previous);
        if let Some(position) = updated.find(&marker) {
            updated.replace_range(position..position + marker.len(), "");
        }
    }
    let active = active_mention(&updated)?;
    updated.replace_range(active.start.., &format!("@{} ", agent.name));
    Some(updated)
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::BotId;

    use super::*;

    fn agent(id: &str, name: &str, mine: bool, visibility: AgentVisibility) -> AgentProfile {
        AgentProfile {
            id: BotId::new(id),
            name: name.to_owned(),
            title: "Title".to_owned(),
            role_description: format!("{name} role"),
            avatar_seed: id.to_owned(),
            visibility,
            endpoint: None,
            has_auth: false,
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: mine,
            mine,
        }
    }

    #[test]
    fn explicit_models_require_a_known_builtin_agent() {
        let builtin = agent("builtin", "Built in", true, AgentVisibility::Public);
        let mut remote = agent("remote", "Remote", false, AgentVisibility::Public);
        remote.endpoint = Some("https://example.test/agui".into());
        let roster = [builtin.clone(), remote.clone()];
        assert!(supports_explicit_model(&roster, &builtin.id));
        assert!(!supports_explicit_model(&roster, &remote.id));
        assert!(!supports_explicit_model(&roster, &BotId::new("missing")));
    }

    #[test]
    fn routing_result_never_substitutes_the_first_visible_agent() {
        let first = agent("first", "First", true, AgentVisibility::Public);
        let chosen = agent("chosen", "Chosen", false, AgentVisibility::Public);
        let roster = [first.clone(), chosen.clone()];
        assert!(matches!(
            confirmed_home_recipient(&roster, BotId::new("missing")),
            Err(ApiError::InvalidResponse)
        ));
        assert_eq!(
            confirmed_home_recipient(&roster, chosen.id.clone()).unwrap(),
            chosen.id
        );
        assert!(matches!(
            confirmed_home_recipient(&[], first.id),
            Err(ApiError::InvalidResponse)
        ));
    }

    #[test]
    fn a_selected_mention_does_not_reopen_when_typing_a_task_or_skill() {
        let selected = MentionSelection {
            agent_id: BotId::new("bot"),
            display_text: "Wrok Bot".into(),
        };
        assert!(unselected_mention("@Wrok Bot /review", Some(&selected)).is_none());
        assert!(unselected_mention("@Wrok Bot keep this task", Some(&selected)).is_none());
        assert_eq!(
            unselected_mention("@Wrok Bot ask @Ada", Some(&selected))
                .unwrap()
                .query,
            "Ada"
        );
    }

    #[test]
    fn home_chosen_assistant_and_skills_without_task_are_rejected() {
        let guide = agent("guide", "Operations Guide", true, AgentVisibility::Public);
        let raw = insert_mention(" @", None, &guide).unwrap();
        let selected = MentionSelection {
            agent_id: guide.id,
            display_text: guide.name,
        };
        let picked = crate::features::channels::composer::skills::selected_draft(
            raw.clone(),
            vec!["review".into(), "check".into()],
        );
        assert_eq!(raw, " @Operations Guide ");
        assert!(!home_has_task(&picked.text, Some(&selected)));
        assert_eq!(picked.text, raw);
        assert_eq!(picked.command_ids, ["review", "check"]);
    }

    #[test]
    fn home_blank_task_detection_uses_ecmascript_whitespace() {
        let selected = MentionSelection {
            agent_id: BotId::new("guide"),
            display_text: "Operations Guide".into(),
        };
        for raw in [
            "",
            " \t\r\n\u{3000}\u{00a0}\u{feff}",
            " @Operations Guide ",
            "\u{feff}@Operations Guide\u{00a0}\r\n",
        ] {
            assert!(!home_has_task(raw, Some(&selected)), "{raw:?}");
        }
    }

    #[test]
    fn home_task_detection_keeps_task_text_and_literal_at_content() {
        let selected = MentionSelection {
            agent_id: BotId::new("guide"),
            display_text: "Operations Guide".into(),
        };
        for raw in [
            "@Operations Guide review this material",
            "Review this material @Operations Guide",
            "  @Operations Guide\n保留我的原话  ",
            "user@example.test",
            "https://example.test/@Operations-Guide",
            "\"@Operations Guide\"",
            "@Operations Guidebook",
            "@Another Guide",
        ] {
            assert!(home_has_task(raw, Some(&selected)), "{raw:?}");
        }
        assert!(home_has_task("@Operations Guide", None));
    }

    #[test]
    fn fallback_and_explore_match_the_fixed_upstream_order() {
        let roster = [
            agent("mine", "Mine", true, AgentVisibility::Public),
            agent("private", "Private", false, AgentVisibility::Private),
            agent("explore-one", "Explore One", false, AgentVisibility::Public),
            agent("explore-two", "Explore Two", false, AgentVisibility::Public),
        ];
        assert_eq!(
            explore_agents(&roster)
                .iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["explore-one", "explore-two"]
        );
        assert_eq!(fallback_agent(&roster).unwrap().id.as_str(), "explore-one");
        assert_eq!(fallback_agent(&roster[..2]).unwrap().id.as_str(), "mine");
    }

    #[test]
    fn at_trigger_is_structured_and_replacing_it_keeps_only_the_latest_agent() {
        assert_eq!(
            active_mention("Please ask @know"),
            Some(ActiveMention {
                start: 11,
                query: "know".to_owned(),
            })
        );
        assert_eq!(active_mention("mail@example.test"), None);
        assert_eq!(active_mention("@Knowledge Desk "), None);

        let knowledge = agent(
            "knowledge",
            "Knowledge Desk",
            false,
            AgentVisibility::Public,
        );
        let risk = agent("risk", "Risk Analyst", false, AgentVisibility::Public);
        let first = insert_mention("Please ask @know", None, &knowledge).unwrap();
        let selected = MentionSelection {
            agent_id: knowledge.id.clone(),
            display_text: knowledge.name.clone(),
        };
        assert_eq!(first, "Please ask @Knowledge Desk ");
        assert_eq!(
            selected_agent_id(&first, Some(&selected)),
            Some(knowledge.id)
        );

        let second = insert_mention(&format!("{first}then @risk"), Some(&selected), &risk).unwrap();
        assert!(!second.contains("@Knowledge Desk"));
        assert!(second.contains("@Risk Analyst "));
    }

    #[test]
    fn mention_filter_matches_name_or_stable_id_and_rejects_bad_rows() {
        let candidates = [
            agent(
                "knowledge",
                "Knowledge Desk",
                false,
                AgentVisibility::Public,
            ),
            agent(
                "risk-analyst",
                "Risk Analyst",
                false,
                AgentVisibility::Public,
            ),
            agent("bad\nidentity", "Bad", false, AgentVisibility::Public),
        ];
        assert_eq!(
            mention_candidates(&candidates, "risk")
                .iter()
                .map(|agent| agent.id.as_str())
                .collect::<Vec<_>>(),
            ["risk-analyst"]
        );
        assert_eq!(mention_candidates(&candidates, "desk").len(), 1);
        assert_eq!(mention_candidates(&candidates, "").len(), 2);
    }
}
