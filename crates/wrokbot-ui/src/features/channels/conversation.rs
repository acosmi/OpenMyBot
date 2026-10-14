//! Native channel conversation: atomic snapshot, durable SSE replay/live, and idle sends.

#![cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, unused_variables)
)]

use core::fmt::Write as _;
use std::collections::BTreeMap;

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
#[cfg(target_arch = "wasm32")]
use openbot_contracts::command::{AppEvent, SubscriptionRequest, ThreadRunCancellationState};
use openbot_contracts::command::{
    ChannelDetail, ThreadConversationSnapshot, ThreadForegroundRunState, ThreadHistoryMessage,
    ThreadHistoryRole, ThreadRunAnchor, ThreadRunEvent, ThreadRunEventKind,
};
use openbot_contracts::components::compiled_component_parameter_schema;
#[cfg(test)]
use openbot_contracts::components::{ComponentHumanDecisionAnswer, PendingComponentHumanDecision};
use openbot_contracts::ids::{BotId, RunId, ThreadId};
use openbot_contracts::sandboxed::is_sandboxed_component_name;
use openbot_contracts::text::trim_ecmascript;
use sha2::{Digest, Sha256};

use super::artifacts::{ArtifactMessageActions, ArtifactSourceObserver};
use super::run_observation::{ObservedRunDirectory, OutputPhase, RunObservation};
#[cfg(target_arch = "wasm32")]
use crate::api::desktop_transport::{
    DesktopStructuredConnection, DesktopStructuredHandlers, is_tauri_host, open_desktop_structured,
};
use crate::api::mint_run_id;
#[cfg(target_arch = "wasm32")]
use crate::api::{
    begin_thread_run_with_skills_and_model, cancel_thread_run, load_agent,
    load_thread_conversation, mint_thread_id, thread_event_stream_path,
};
use crate::features::agents::{AgentPresence, AgentPresenceState};
#[cfg(target_arch = "wasm32")]
use crate::features::channels::composer::model_intents::SubmissionSource;
use crate::features::channels::composer::model_intents::{
    RunIntent, RunRecovery, RunSubmissionActions,
};
use crate::features::channels::composer::models::{ModelComposer, ModelPicker};
use crate::features::channels::composer::queue::{QueueAction, QueuedMessage, reduce_queue};
use crate::features::channels::composer::skills::{SkillComposer, SkillPicker};
use crate::features::channels::markdown::{MarkdownBody, StreamingMarkdownBody};
use crate::features::channels::new::{SubmissionNotice, model_notice};
use crate::features::computer::workspace::{
    ComputerWorkspace, ConversationWorkspace, WorkspaceActivity, WorkspaceControls, WorkspaceTab,
};
use crate::features::gallery::ConversationComponent;
use crate::features::memory::remember::{RememberDialog, RememberReview, RememberTarget};
use crate::features::threads::tool_name::read_tool_name;
use crate::features::threads::tool_result::for_display;
use crate::i18n::{t, t_string, use_i18n};
use crate::icons::Icon;
use crate::primitives::{
    Avatar, AvatarSize, Bubble, BubbleKind, Button, ButtonSize, ButtonVariant, IconSize, IconView,
    Message, MessageAlign, MessageAvatar, MessageContent, MessageFooter, MessageHeader,
    MessageScroller, MessageScrollerButton, MessageScrollerContent, MessageScrollerItem,
    MessageScrollerViewport, Textarea,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast as _;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use web_sys::{Event, EventSource, MessageEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TranscriptKind {
    User,
    Assistant,
    ToolCall,
    ToolResult,
    Component,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptComponent {
    name: String,
    provider_call_id: String,
    arguments: serde_json::Value,
    result: Option<String>,
    error_code: Option<String>,
    agent_id: Option<BotId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptLine {
    id: String,
    kind: TranscriptKind,
    content: String,
    component: Option<TranscriptComponent>,
    tool: Option<TranscriptTool>,
    selected_skill_slugs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptTool {
    name: String,
    call_id: Option<String>,
    agent_id: Option<BotId>,
    result: Option<String>,
    error_code: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalNotice {
    Failed,
    Cancelled,
    ReconciliationRequired,
}

impl TerminalNotice {
    #[cfg(test)]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConversationState {
    messages: Vec<TranscriptLine>,
    active_run_id: Option<RunId>,
    active_run_state: Option<ThreadForegroundRunState>,
    active_run_cancellable: bool,
    streaming_text: String,
    cursor: Option<u64>,
    terminal_notice: Option<TerminalNotice>,
    observed_run: Option<RunObservation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveEffect {
    None,
    ReloadSnapshot,
}

/// Closed composer Stop inputs. Every field is a fact this mount already holds; the control is
/// never derived from a raw provider/HTTP error or from an actor identity sent by the client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StopControl {
    /// A local send is in flight or awaiting retry, so no new control may be minted.
    input_locked: bool,
    /// A durable cancellation request minted by this mount is still unacknowledged.
    cancelling_request: bool,
    /// The current snapshot is being renewed or could not be read; retained facts cannot mint
    /// another cancellation until an authorized read succeeds.
    loading: bool,
    snapshot_error: bool,
    /// An empty draft is what turns the primary control from Send into Stop.
    draft_empty: bool,
    /// Snapshot fact: this actor may mint the **first** durable cancellation request.
    cancellable: bool,
    /// Durable foreground projection; `Cancelling` keeps Stop visible but inert.
    run_state: Option<ThreadForegroundRunState>,
}

impl StopControl {
    /// Stop replaces Send exactly while the durable facts show a stoppable or stopping foreground.
    const fn visible(self) -> bool {
        self.draft_empty
            && (self.cancellable
                || matches!(self.run_state, Some(ThreadForegroundRunState::Cancelling))
                || self.cancelling_request)
    }

    /// Stop is actionable only for the first request this actor is allowed to mint; a run already
    /// `Cancelling` (here or on another replica) is observable but not re-requestable from the GUI.
    const fn enabled(self) -> bool {
        !self.input_locked
            && !self.cancelling_request
            && !self.loading
            && !self.snapshot_error
            && self.draft_empty
            && self.cancellable
            && matches!(self.run_state, Some(ThreadForegroundRunState::Running))
    }
}

/// Facts captured when a user starts an authorized action read. A late reply is not permission
/// for a different mount, reload, foreground, or event position. The current run observation is
/// captured to preserve newer output; action reads never replace the transcript or current output.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConversationActionRead {
    thread: Option<ThreadId>,
    generation: u64,
    cursor: Option<u64>,
    run: Option<RunId>,
    run_state: Option<ThreadForegroundRunState>,
    cancellable: bool,
    observed_run: Option<RunObservation>,
}

impl ConversationActionRead {
    fn capture(thread: Option<ThreadId>, generation: u64, state: &ConversationState) -> Self {
        Self {
            thread,
            generation,
            cursor: state.cursor,
            run: state.active_run_id.clone(),
            run_state: state.active_run_state,
            cancellable: state.active_run_cancellable,
            observed_run: state.observed_run.clone(),
        }
    }

    fn is_current(
        &self,
        thread: Option<&ThreadId>,
        generation: u64,
        state: &ConversationState,
    ) -> bool {
        self.same_foreground(thread, generation, state) && self.cursor == state.cursor
    }

    fn same_foreground(
        &self,
        thread: Option<&ThreadId>,
        generation: u64,
        state: &ConversationState,
    ) -> bool {
        self.thread.as_ref() == thread
            && self.generation == generation
            && self.run == state.active_run_id
            && self.run_state == state.active_run_state
            && self.cancellable == state.active_run_cancellable
    }

    fn same_observed_foreground(&self, state: &ConversationState) -> bool {
        self.run == state.active_run_id
            && self.run_state == state.active_run_state
            && self.cancellable == state.active_run_cancellable
            && self.observed_run == state.observed_run
    }
}

fn action_read_allows_stop(snapshot: &ThreadConversationSnapshot, run: &RunId) -> bool {
    snapshot.active_run_id.as_ref() == Some(run)
        && snapshot.active_run_state == Some(ThreadForegroundRunState::Running)
        && snapshot.active_run_cancellable
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryReadFact {
    Original,
    Absent,
    Other,
}

fn retry_read_fact(snapshot: &ThreadConversationSnapshot, run: &RunId) -> RetryReadFact {
    match snapshot.active_run_id.as_ref() {
        Some(active) if active == run => RetryReadFact::Original,
        Some(_) => RetryReadFact::Other,
        None => RetryReadFact::Absent,
    }
}

/// A durable retry owns its Agent/message already, so an empty or now-unselected composer must not
/// disable the only button that can replay it. Editing remains locked separately by `input_locked`.
const fn send_control_disabled(
    submitting: bool,
    channel_active: bool,
    has_selected_agent: bool,
    snapshot_error: bool,
    loading: bool,
    draft_empty: bool,
    has_resumable: bool,
) -> bool {
    submitting
        || !channel_active
        || snapshot_error
        || loading
        || (!has_resumable && (!has_selected_agent || draft_empty))
}

/// Remember an authoritative foreground-run terminal edge until all local send gates are safe.
const fn queue_drain_pending(previous_active: bool, active: bool, pending: bool) -> bool {
    pending || (previous_active && !active)
}

const fn should_drain_queue(
    pending: bool,
    in_flight: bool,
    loading: bool,
    channel_active: bool,
    queue_empty: bool,
    submission_barrier: bool,
    has_resumable: bool,
) -> bool {
    pending
        && !in_flight
        && !loading
        && channel_active
        && !queue_empty
        && !submission_barrier
        && !has_resumable
}

impl ConversationState {
    #[cfg(any(target_arch = "wasm32", test))]
    fn accepted_run(&mut self, run: RunId) {
        self.active_run_id = Some(run.clone());
        self.active_run_state = Some(ThreadForegroundRunState::Running);
        self.active_run_cancellable = true;
        self.streaming_text.clear();
        self.terminal_notice = None;
        self.observed_run = Some(RunObservation::running(run, String::new()));
    }

    fn install_snapshot(&mut self, snapshot: ThreadConversationSnapshot) {
        if let Some(run) = snapshot.active_run_id.clone() {
            let mut observation = RunObservation::running(run, snapshot.active_run_text.clone());
            if snapshot.active_run_state == Some(ThreadForegroundRunState::ReconciliationRequired) {
                observation.phase = OutputPhase::Unknown;
                if let Some(previous) = self
                    .observed_run
                    .as_ref()
                    .filter(|previous| previous.run == observation.run)
                {
                    observation.terminal_sequence = previous.terminal_sequence;
                    if observation.text.is_empty() {
                        observation.text.clone_from(&previous.text);
                    }
                }
            }
            self.observed_run = Some(observation);
        } else if let Some(previous) = self
            .observed_run
            .as_mut()
            .filter(|previous| previous.phase == OutputPhase::Running)
        {
            previous.phase = OutputPhase::UnobservedTerminal;
        }
        self.messages = project_history(&snapshot.messages);
        self.active_run_id = snapshot.active_run_id;
        self.active_run_state = snapshot.active_run_state;
        self.active_run_cancellable = snapshot.active_run_cancellable;
        self.streaming_text = snapshot.active_run_text;
        self.cursor = snapshot.last_event_sequence;
        match self.active_run_state {
            Some(ThreadForegroundRunState::ReconciliationRequired) => {
                self.terminal_notice = Some(TerminalNotice::ReconciliationRequired);
            }
            Some(
                ThreadForegroundRunState::Queued
                | ThreadForegroundRunState::Running
                | ThreadForegroundRunState::Cancelling,
            ) => self.terminal_notice = None,
            None => {}
        }
    }
}

fn apply_live_event(
    state: &mut ConversationState,
    expected_thread: &ThreadId,
    event: &ThreadRunEvent,
) -> Result<LiveEffect, ()> {
    if &event.thread_id != expected_thread || event.terminal != event.event_type.is_terminal() {
        return Err(());
    }
    if state
        .cursor
        .is_some_and(|cursor| event.event_sequence <= cursor)
    {
        return Ok(LiveEffect::None);
    }
    if state
        .cursor
        .is_some_and(|cursor| cursor.checked_add(1) != Some(event.event_sequence))
    {
        return Ok(LiveEffect::ReloadSnapshot);
    }
    if event.terminal
        && state
            .active_run_id
            .as_ref()
            .is_some_and(|run| run != &event.run_id)
    {
        return Ok(LiveEffect::ReloadSnapshot);
    }
    state.cursor = Some(event.event_sequence);
    match event.event_type {
        ThreadRunEventKind::Started => {
            // 本 mount 已经从 durable begin receipt 学到过这个 run 的 cancellable 事实。若在这里
            // 抹掉再靠一次全量 reload 恢复，每个 turn 都要多拆一次 SSE、多闪一次 loading，并在
            // 那一帧里把 Send/Stop 一起禁用 —— 事实没变，不该有这次往返。
            let already_tracked = state.active_run_id.as_ref() == Some(&event.run_id);
            state.active_run_id = Some(event.run_id.clone());
            state.active_run_state = Some(ThreadForegroundRunState::Running);
            state.observed_run = Some(RunObservation::running(event.run_id.clone(), String::new()));
            state.streaming_text.clear();
            state.terminal_notice = None;
            if already_tracked {
                Ok(LiveEffect::None)
            } else {
                // 另一 tab / 另一副本发起的 run：本 mount 没有权威依据，cancellable 只能来自
                // durable snapshot，绝不沿用上一个 run 的值。
                state.active_run_cancellable = false;
                Ok(LiveEffect::ReloadSnapshot)
            }
        }
        ThreadRunEventKind::SemanticChunk => {
            if state.active_run_id.as_ref() != Some(&event.run_id) {
                return Ok(LiveEffect::ReloadSnapshot);
            }
            let Some(channel) = event
                .payload
                .get("channel")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(());
            };
            let Some(delta) = event
                .payload
                .get("delta")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(());
            };
            match channel {
                "text" => {
                    state.streaming_text.push_str(delta);
                    if state
                        .observed_run
                        .as_ref()
                        .is_none_or(|row| row.run != event.run_id)
                    {
                        state.observed_run =
                            Some(RunObservation::running(event.run_id.clone(), String::new()));
                    }
                    if let Some(observation) = state
                        .observed_run
                        .as_mut()
                        .filter(|row| row.run == event.run_id)
                    {
                        observation.text.push_str(delta);
                    }
                }
                "reasoning" => {}
                _ => return Err(()),
            }
            Ok(LiveEffect::None)
        }
        ThreadRunEventKind::Checkpoint => {
            if event
                .payload
                .get("kind")
                .and_then(serde_json::Value::as_str)
                == Some("remote_agui_projection")
            {
                if remote_projection_is_quarantined(&event.payload) {
                    Ok(LiveEffect::None)
                } else {
                    Err(())
                }
            } else {
                // A tool checkpoint materializes a durable assistant/tool pair. Reload so the
                // completed component replaces any pending surface before resampling finishes.
                Ok(LiveEffect::ReloadSnapshot)
            }
        }
        ThreadRunEventKind::Completed => {
            observe_terminal(state, event, OutputPhase::Succeeded);
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = None;
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::Failed => {
            observe_terminal(state, event, OutputPhase::Failed);
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::Failed);
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::Cancelled => {
            observe_terminal(state, event, OutputPhase::Cancelled);
            state.active_run_id = None;
            state.active_run_state = None;
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::Cancelled);
            Ok(LiveEffect::ReloadSnapshot)
        }
        ThreadRunEventKind::ReconciliationRequired => {
            observe_terminal(state, event, OutputPhase::Unknown);
            state.active_run_id = Some(event.run_id.clone());
            state.active_run_state = Some(ThreadForegroundRunState::ReconciliationRequired);
            state.active_run_cancellable = false;
            state.terminal_notice = Some(TerminalNotice::ReconciliationRequired);
            Ok(LiveEffect::ReloadSnapshot)
        }
    }
}

fn observe_terminal(state: &mut ConversationState, event: &ThreadRunEvent, phase: OutputPhase) {
    // History has no per-message run identity. Never obtain this output from the last answer.
    if state
        .observed_run
        .as_ref()
        .is_some_and(|row| row.run != event.run_id)
    {
        state.observed_run = None;
    }
    let observation = state
        .observed_run
        .get_or_insert_with(|| RunObservation::running(event.run_id.clone(), String::new()));
    if observation.run == event.run_id {
        observation.phase = phase;
        observation.terminal_sequence = Some(event.event_sequence);
    }
}

fn remote_projection_is_quarantined(payload: &serde_json::Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    if object.get("kind").and_then(serde_json::Value::as_str) != Some("remote_agui_projection")
        || object.get("source").and_then(serde_json::Value::as_str) != Some("remote_ag_ui")
        || object.get("untrusted").and_then(serde_json::Value::as_bool) != Some(true)
    {
        return false;
    }
    if object.get("retained").and_then(serde_json::Value::as_bool) == Some(false) {
        return object.len() == 4;
    }
    let family = object.get("family").and_then(serde_json::Value::as_str);
    let known_family = matches!(
        family,
        Some(
            "state"
                | "messages"
                | "activity"
                | "step_started"
                | "step_finished"
                | "tool_result"
                | "raw"
                | "custom"
        )
    );
    known_family
        && object.len() == 7
        && object.contains_key("untrustedKey")
        && object.contains_key("untrustedType")
        && object.contains_key("untrustedValue")
        && [object.get("untrustedKey"), object.get("untrustedType")]
            .into_iter()
            .flatten()
            .all(|value| {
                value.is_null()
                    || value
                        .as_str()
                        .is_some_and(|value| !value.is_empty() && !value.as_bytes().contains(&0))
            })
}

fn project_history(messages: &[ThreadHistoryMessage]) -> Vec<TranscriptLine> {
    let mut projected = Vec::<TranscriptLine>::new();
    let mut pending = BTreeMap::<String, usize>::new();
    let mut seen = std::collections::BTreeSet::new();
    for message in messages {
        match message.role {
            ThreadHistoryRole::System => {}
            ThreadHistoryRole::User => projected.push(TranscriptLine {
                id: message.id.clone(),
                kind: TranscriptKind::User,
                content: message.content.clone(),
                component: None,
                tool: None,
                selected_skill_slugs: message.selected_skill_slugs.clone(),
            }),
            ThreadHistoryRole::Assistant => {
                if !message.content.is_empty() {
                    projected.push(TranscriptLine {
                        id: message.id.clone(),
                        kind: TranscriptKind::Assistant,
                        content: message.content.clone(),
                        component: None,
                        tool: None,
                        selected_skill_slugs: Vec::new(),
                    });
                }
                for (ordinal, call) in message
                    .tool_calls
                    .as_ref()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    let index = projected.len();
                    let Some((call_id, name, arguments)) = durable_tool_call(call) else {
                        projected.push(TranscriptLine {
                            id: format!("{}:invalid:{ordinal}", message.id),
                            kind: TranscriptKind::ToolCall,
                            content: String::new(),
                            component: None,
                            tool: Some(TranscriptTool {
                                name: String::new(),
                                call_id: None,
                                agent_id: message.agent_id.clone(),
                                result: None,
                                error_code: Some("tool_payload_invalid".to_owned()),
                            }),
                            selected_skill_slugs: Vec::new(),
                        });
                        continue;
                    };
                    let duplicate = !seen.insert(call_id.clone());
                    if duplicate && let Some(original) = pending.remove(&call_id) {
                        if let Some(tool) = projected[original].tool.as_mut() {
                            tool.error_code = Some("tool_call_duplicate".to_owned());
                        }
                        if let Some(component) = projected[original].component.as_mut() {
                            component.error_code = Some("component_call_duplicate".to_owned());
                        }
                    }
                    if compiled_component_parameter_schema(&name).is_some()
                        || is_sandboxed_component_name(&name)
                    {
                        projected.push(TranscriptLine {
                            id: format!("{}:{call_id}:{ordinal}", message.id),
                            kind: TranscriptKind::Component,
                            content: name.clone(),
                            tool: None,
                            selected_skill_slugs: Vec::new(),
                            component: Some(TranscriptComponent {
                                name,
                                provider_call_id: call_id.clone(),
                                arguments,
                                result: None,
                                error_code: Some(
                                    if duplicate {
                                        "component_call_duplicate"
                                    } else {
                                        "component_result_missing"
                                    }
                                    .to_owned(),
                                ),
                                agent_id: message.agent_id.clone(),
                            }),
                        });
                    } else {
                        projected.push(TranscriptLine {
                            id: format!("{}:{call_id}:{ordinal}", message.id),
                            kind: TranscriptKind::ToolCall,
                            content: name.clone(),
                            component: None,
                            tool: Some(TranscriptTool {
                                name,
                                call_id: Some(call_id.clone()),
                                agent_id: message.agent_id.clone(),
                                result: None,
                                error_code: duplicate.then(|| "tool_call_duplicate".to_owned()),
                            }),
                            selected_skill_slugs: Vec::new(),
                        });
                    }
                    if !duplicate {
                        pending.insert(call_id, index);
                    }
                }
            }
            ThreadHistoryRole::Tool => {
                // Provider pairing identities are only unique among outstanding calls.
                // The durable history does not carry a global provider-call / Run namespace.
                if let Some(id) = message.tool_call_id.as_ref() {
                    seen.remove(id);
                }
                let mut paired = false;
                let mut mismatch = false;
                if let Some(index) = message
                    .tool_call_id
                    .as_ref()
                    .and_then(|id| pending.remove(id))
                {
                    if let Some(component) = projected[index].component.as_mut() {
                        if message.tool_name.as_deref() == Some(component.name.as_str())
                            && message.agent_id == component.agent_id
                        {
                            component.result = Some(message.content.clone());
                            component.error_code = message.tool_error_code.clone();
                            paired = true;
                        } else {
                            component.error_code = Some("component_result_mismatch".to_owned());
                            mismatch = true;
                        }
                    }
                    if let Some(tool) = projected[index].tool.as_mut() {
                        if message.tool_name.as_deref() == Some(tool.name.as_str())
                            && message.agent_id == tool.agent_id
                        {
                            tool.result = Some(for_display(&message.content));
                            tool.error_code = message.tool_error_code.clone();
                            paired = true;
                        } else {
                            tool.error_code = Some("tool_result_mismatch".to_owned());
                            mismatch = true;
                        }
                    }
                }
                if !paired {
                    projected.push(TranscriptLine {
                        id: message.id.clone(),
                        kind: TranscriptKind::ToolResult,
                        content: for_display(&message.content),
                        component: None,
                        tool: Some(TranscriptTool {
                            name: message.tool_name.clone().unwrap_or_default(),
                            call_id: message.tool_call_id.clone(),
                            agent_id: message.agent_id.clone(),
                            result: Some(for_display(&message.content)),
                            error_code: message.tool_error_code.clone().or_else(|| {
                                Some(
                                    if mismatch {
                                        "tool_result_mismatch"
                                    } else {
                                        "tool_result_unpaired"
                                    }
                                    .to_owned(),
                                )
                            }),
                        }),
                        selected_skill_slugs: Vec::new(),
                    });
                }
            }
        }
    }
    projected
}

fn durable_tool_call(call: &serde_json::Value) -> Option<(String, String, serde_json::Value)> {
    let call_id = call.get("id")?.as_str()?.to_owned();
    if call_id.is_empty() || call_id.len() > 512 || call_id.chars().any(char::is_control) {
        return None;
    }
    let function = call.get("function")?.as_object()?;
    let name = function.get("name")?.as_str()?.to_owned();
    if name.is_empty() || name.len() > 512 || name.chars().any(char::is_control) {
        return None;
    }
    let arguments = function.get("arguments")?.clone();
    Some((call_id, name, arguments))
}

type PendingTurn = RunIntent;

/// Data-backed channel transcript using the shared native thread conversation surface.
#[component]
pub fn ChannelConversation(
    /// Current membership-authorized channel projection from the Server.
    channel: ChannelDetail,
) -> impl IntoView {
    let selected_agent = channel.agent_ids.first().cloned();
    let agent_seed = selected_agent.as_ref().map_or_else(
        || channel.id.as_str().to_owned(),
        |id| id.as_str().to_owned(),
    );
    view! {
        <ConversationSurface
            thread=channel.thread_id
            agent_id=selected_agent
            agent_name=channel.name
            agent_seed
            channel_active=channel.active
            anchor=ThreadRunAnchor::Channel { channel_id: channel.id }
            fresh_thread=false
            agent_profile=None
        />
    }
}

/// Direct-Bot transcript/new-turn surface sharing the exact channel runtime state machine.
#[component]
pub fn DirectBotConversation(
    /// Server-minted thread selected by the per-Agent remembered-thread controller.
    thread: ThreadId,
    /// Current Server-authorized runnable Agent projection.
    agent: AgentProfile,
    /// The Server minted this identity, but no first run has persisted it yet.
    fresh: bool,
) -> impl IntoView {
    let agent_id = agent.id.clone();
    let agent_name = agent.name.clone();
    let agent_seed = agent.avatar_seed.clone();
    view! {
        <ConversationSurface
            thread=Some(thread)
            agent_id=Some(agent_id)
            agent_name
            agent_seed
            channel_active=true
            anchor=ThreadRunAnchor::DirectBot
            fresh_thread=fresh
            agent_profile=Some(agent)
        />
    }
}

#[component]
fn ConversationSurface(
    thread: Option<ThreadId>,
    agent_id: Option<BotId>,
    agent_name: String,
    agent_seed: String,
    channel_active: bool,
    anchor: ThreadRunAnchor,
    fresh_thread: bool,
    agent_profile: Option<AgentProfile>,
) -> impl IntoView {
    let i18n = use_i18n();
    let identity_profile = RwSignal::new(agent_profile.clone());
    let run_anchor = StoredValue::new(anchor);
    #[cfg(not(target_arch = "wasm32"))]
    let _ = run_anchor;
    let agent_id = StoredValue::new(agent_id);
    let model_support = RwSignal::new(agent_profile.as_ref().map(|agent| agent.endpoint.is_none()));
    #[cfg(target_arch = "wasm32")]
    let model_agent_epoch = RwSignal::new(0_u64);
    #[cfg(target_arch = "wasm32")]
    if model_support.get_untracked().is_none()
        && let Some(requested_agent) = agent_id.get_value()
    {
        let epoch = model_agent_epoch.get_untracked().saturating_add(1);
        model_agent_epoch.set(epoch);
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load_agent(requested_agent.as_str()).await;
            if model_agent_epoch.try_get_untracked() != Some(epoch) {
                return;
            }
            let profile = result.ok();
            model_support.set(profile.as_ref().map(|agent| agent.endpoint.is_none()));
            identity_profile.set(profile);
        });
    }
    let streaming_agent_seed = StoredValue::new(agent_seed.clone());
    let streaming_agent_name = StoredValue::new(agent_name.clone());
    let thread_id = RwSignal::new(thread);
    let artifact_source = ArtifactSourceObserver::new(thread_id, agent_id, run_anchor);
    let allow_missing_snapshot = RwSignal::new(fresh_thread);
    let observed_runs = expect_context::<ObservedRunDirectory>();
    let state = RwSignal::new(ConversationState {
        observed_run: observed_runs.latest(thread_id.get_untracked().as_ref()),
        ..Default::default()
    });
    let loading = RwSignal::new(true);
    let snapshot_error = RwSignal::new(false);
    let stream_error = RwSignal::new(false);
    let reload_generation = RwSignal::new(0_u64);
    Effect::new(move |_| {
        if !loading.get()
            && !snapshot_error.get()
            && let (Some(thread), Some(observation)) = (thread_id.get(), state.get().observed_run)
        {
            observed_runs.record(thread, observation);
        }
    });
    install_conversation_sync(
        thread_id,
        state,
        loading,
        snapshot_error,
        stream_error,
        reload_generation,
        allow_missing_snapshot,
        artifact_source,
    );
    let component_attention =
        expect_context::<crate::features::approvals::attention::ComponentDecisionActions>();
    let remote_attention =
        expect_context::<crate::features::approvals::attention::RemoteInterruptActions>();
    let tool_attention = expect_context::<crate::features::approvals::ToolApprovalActions>();
    let remember_review = RememberReview::new();
    let on_remember = UnsyncCallback::new(move |(message_id, content): (String, String)| {
        if let Some(thread) = thread_id.get_untracked() {
            remember_review.review(RememberTarget {
                thread,
                message_id,
                content,
            });
        }
    });
    let draft = RwSignal::new(String::new());
    let skill_composer = SkillComposer::new(
        draft,
        Signal::derive(move || agent_id.get_value()),
        "channel-message",
    );
    let model_composer = ModelComposer::new(
        Signal::derive(move || model_support.get() == Some(true)),
        Signal::derive(move || agent_id.get_value()),
    );
    let queued = RwSignal::new(Vec::<QueuedMessage>::new());
    let queue_skills_invalid = Signal::derive(move || {
        queued.get().iter().any(|item| {
            !openbot_contracts::command::valid_selected_skill_slugs(
                &item.intent.selected_skill_slugs,
            )
        })
    });
    let submitting = RwSignal::new(false);
    let cancelling_request = RwSignal::new(false);
    let send_notice = RwSignal::new(None::<SubmissionNotice>);
    let begin_unknown = RwSignal::new(false);
    let submission_blocked = RwSignal::new(false);
    let cancel_error = RwSignal::new(false);
    let resumable = RwSignal::new(None::<PendingTurn>);
    let resumable_recovery = RwSignal::new(None::<RunRecovery>);
    let submissions = expect_context::<RunSubmissionActions>();
    Effect::new(move |_| {
        if submitting.get() {
            return;
        }
        if resumable.get_untracked().is_some() {
            submission_blocked.set(false);
            return;
        }
        let recovery = submissions.run_unknown_for_scope(
            thread_id.get().as_ref(),
            &run_anchor.get_value(),
            agent_id.get_value().as_ref(),
        );
        let Some(recovery) = recovery else {
            submission_blocked.set(submissions.has_barrier());
            return;
        };
        submission_blocked.set(false);
        let intent = recovery.intent.clone();
        draft.set(intent.message.clone());
        skill_composer
            .selected
            .set(intent.selected_skill_slugs.clone());
        model_composer.restore_selection(
            intent.model_selection.clone(),
            Some(intent.agent_id.clone()),
        );
        resumable_recovery.set(Some(recovery));
        resumable.set(Some(intent));
        begin_unknown.set(true);
        send_notice.set(None);
    });
    Effect::new(move |_| {
        let Some(attempt) = resumable.get() else {
            return;
        };
        if state.get().active_run_id.as_ref() == Some(&attempt.run_id) {
            if let Some(thread) = attempt.thread_id.as_ref() {
                submissions.acknowledge_observed(
                    thread,
                    &attempt.anchor,
                    &attempt.agent_id,
                    &attempt.run_id,
                );
            }
            resumable.set(None);
            resumable_recovery.set(None);
            skill_composer.clear();
            begin_unknown.set(false);
            send_notice.set(None);
        }
    });
    let busy = Signal::derive(move || state.get().active_run_id.is_some() || submitting.get());
    let input_locked = Signal::derive(move || {
        submitting.get() || resumable.get().is_some() || submission_blocked.get()
    });
    let textarea_disabled = Signal::derive(move || input_locked.get() || !channel_active);
    let send_disabled = Signal::derive(move || {
        send_control_disabled(
            submitting.get(),
            channel_active,
            agent_id.get_value().is_some(),
            snapshot_error.get(),
            loading.get(),
            trim_ecmascript(&draft.get()).is_empty(),
            resumable.get().is_some(),
        ) || submission_blocked.get()
            || (resumable.get().is_none()
                && (skill_composer.invalid.get() || queue_skills_invalid.get()))
    });
    let stop_control = Signal::derive(move || {
        let snapshot = state.get();
        StopControl {
            input_locked: input_locked.get(),
            cancelling_request: cancelling_request.get(),
            loading: loading.get(),
            snapshot_error: snapshot_error.get(),
            draft_empty: trim_ecmascript(&draft.get()).is_empty(),
            cancellable: snapshot.active_run_cancellable,
            run_state: snapshot.active_run_state,
        }
    });
    let can_stop = Signal::derive(move || stop_control.get().enabled());
    let show_stop = Signal::derive(move || stop_control.get().visible());
    let stop_disabled = Signal::derive(move || !can_stop.get());
    let send_now = UnsyncCallback::new(move |requested: RunIntent| {
        if submitting.get_untracked()
            || state.get_untracked().active_run_id.is_some()
            || !channel_active
            || loading.get_untracked()
            || snapshot_error.get_untracked()
        {
            return;
        }
        if resumable.get_untracked().is_none() && trim_ecmascript(&requested.message).is_empty() {
            return;
        }
        let retry_unknown = resumable.get_untracked().is_some();
        submitting.set(true);
        send_notice.set(None);
        if !retry_unknown {
            begin_unknown.set(false);
        }
        submission_blocked.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let attempt = match resumable.get_untracked() {
                Some(attempt) => attempt,
                None => {
                    let resolved_thread = match requested.thread_id.clone() {
                        Some(thread) => thread,
                        None => match mint_thread_id().await {
                            Ok(thread) => thread,
                            Err(_) => {
                                send_notice.set(Some(SubmissionNotice::Rejected));
                                submitting.set(false);
                                return;
                            }
                        },
                    };
                    let mut attempt = requested;
                    attempt.thread_id = Some(resolved_thread);
                    resumable.set(Some(attempt.clone()));
                    attempt
                }
            };
            let Some(resolved_thread) = attempt.thread_id.as_ref() else {
                send_notice.set(Some(SubmissionNotice::Rejected));
                submitting.set(false);
                return;
            };
            let recovery = resumable_recovery
                .get_untracked()
                .unwrap_or_else(|| RunRecovery {
                    source: SubmissionSource::Conversation,
                    intent: attempt.clone(),
                    channel: None,
                });
            let action_read = ConversationActionRead::capture(
                thread_id.get_untracked(),
                reload_generation.get_untracked(),
                &state.get_untracked(),
            );
            if retry_unknown {
                // Only the exact retained Unknown owns this manual retry. A prior mount read,
                // empty history, or a different recovery cannot authorize another BeginRun.
                if attempt.thread_id != action_read.thread
                    || run_anchor.try_get_value().as_ref() != Some(&attempt.anchor)
                    || agent_id.try_get_value().flatten().as_ref() != Some(&attempt.agent_id)
                    || recovery.intent != attempt
                    || resumable_recovery.get_untracked().as_ref() != Some(&recovery)
                    || submissions
                        .run_unknown_for_scope(
                            Some(resolved_thread),
                            &attempt.anchor,
                            Some(&attempt.agent_id),
                        )
                        .as_ref()
                        != Some(&recovery)
                {
                    submission_blocked.set(true);
                    submitting.set(false);
                    return;
                }
                let result = load_thread_conversation(resolved_thread).await;
                let (Some(current_thread), Some(generation), Some(current)) = (
                    thread_id.try_get_untracked(),
                    reload_generation.try_get_untracked(),
                    state.try_get_untracked(),
                ) else {
                    return;
                };
                if !action_read.is_current(current_thread.as_ref(), generation, &current)
                    || loading.try_get_untracked() != Some(false)
                    || snapshot_error.try_get_untracked() != Some(false)
                    || run_anchor.try_get_value().as_ref() != Some(&attempt.anchor)
                    || agent_id.try_get_value().flatten().as_ref() != Some(&attempt.agent_id)
                    || resumable.try_get_untracked().flatten().as_ref() != Some(&attempt)
                    || resumable_recovery.try_get_untracked().flatten().as_ref() != Some(&recovery)
                    || submissions
                        .run_unknown_for_scope(
                            Some(resolved_thread),
                            &attempt.anchor,
                            Some(&attempt.agent_id),
                        )
                        .as_ref()
                        != Some(&recovery)
                {
                    submitting.set(false);
                    return;
                }
                let snapshot = match result {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        // A failed read says nothing about the original effect. Keep its frozen
                        // intent/Unknown and offer the existing authorized Read again recovery.
                        snapshot_error.set(true);
                        submitting.set(false);
                        return;
                    }
                };
                match retry_read_fact(&snapshot, &attempt.run_id) {
                    RetryReadFact::Original => {
                        if submissions.acknowledge_observed(
                            resolved_thread,
                            &attempt.anchor,
                            &attempt.agent_id,
                            &attempt.run_id,
                        ) {
                            resumable.set(None);
                            resumable_recovery.set(None);
                            skill_composer.clear();
                            begin_unknown.set(false);
                            allow_missing_snapshot.set(false);
                            // Do not install this action snapshot over live output or history.
                            // Renew the normal synchronization before enabling a new action.
                            loading.set(true);
                            reload_generation.update(|value| *value = value.saturating_add(1));
                        }
                        submitting.set(false);
                        return;
                    }
                    RetryReadFact::Other => {
                        send_notice.set(Some(SubmissionNotice::Conflict));
                        submitting.set(false);
                        return;
                    }
                    RetryReadFact::Absent => {}
                }
                // No active run is not proof of non-commit. The only continuation admitted
                // below is this explicit retry of the original run id and complete UI intent.
            }
            let Some(ticket) = submissions.start_run(&recovery, retry_unknown) else {
                if !retry_unknown {
                    resumable.set(None);
                }
                submission_blocked.set(true);
                submitting.set(false);
                return;
            };
            artifact_source.stage_begin(&attempt);
            let result = begin_thread_run_with_skills_and_model(
                resolved_thread,
                &attempt.agent_id,
                &attempt.run_id,
                attempt.anchor.clone(),
                &attempt.message,
                &attempt.selected_skill_slugs,
                attempt.model_selection.as_ref(),
            )
            .await;
            artifact_source.begin_reply(&attempt.run_id, result.as_ref().map_err(|_| ()));
            match &result {
                Ok(_) => ticket.accepted(),
                Err(error) => ticket.failed(*error),
            }
            let (Some(current_thread), Some(generation), Some(current)) = (
                thread_id.try_get_untracked(),
                reload_generation.try_get_untracked(),
                state.try_get_untracked(),
            ) else {
                return;
            };
            if !action_read.is_current(current_thread.as_ref(), generation, &current)
                || resumable.try_get_untracked().flatten().as_ref() != Some(&attempt)
            {
                // A snapshot/SSE may already have resolved this exact run while Begin was in
                // flight. Its newer foreground and output must survive the late HTTP reply.
                if current_thread == action_read.thread
                    && resumable.get_untracked().as_ref() == Some(&attempt)
                {
                    if result.is_ok() {
                        resumable.set(None);
                        resumable_recovery.set(None);
                        begin_unknown.set(false);
                        if draft.get_untracked() == attempt.message
                            && skill_composer.selected.get_untracked()
                                == attempt.selected_skill_slugs
                            && model_composer.selected.get_untracked() == attempt.model_selection
                        {
                            skill_composer.clear();
                            model_composer.clear();
                        }
                        if current.active_run_id.is_none()
                            && action_read.same_observed_foreground(&current)
                        {
                            // A reload alone did not observe the accepted run. Renew after this
                            // ACK, making even an older pending NoActive reply obsolete, without
                            // replacing any transcript or already-consumed current output.
                            allow_missing_snapshot.set(false);
                            thread_id.set(attempt.thread_id.clone());
                            loading.set(true);
                            reload_generation.update(|value| *value = value.saturating_add(1));
                        }
                    } else if submissions
                        .run_unknown_for_scope(
                            Some(resolved_thread),
                            &attempt.anchor,
                            Some(&attempt.agent_id),
                        )
                        .as_ref()
                        == Some(&recovery)
                    {
                        resumable_recovery.set(Some(recovery));
                        begin_unknown.set(true);
                    }
                }
                submitting.set(false);
                return;
            }
            match result {
                Ok(_) => {
                    allow_missing_snapshot.set(false);
                    thread_id.set(attempt.thread_id.clone());
                    state.update(|state| {
                        state.accepted_run(attempt.run_id.clone());
                    });
                    if draft.get_untracked() == attempt.message
                        && skill_composer.selected.get_untracked() == attempt.selected_skill_slugs
                        && model_composer.selected.get_untracked() == attempt.model_selection
                    {
                        skill_composer.clear();
                        model_composer.clear();
                    }
                    resumable.set(None);
                    resumable_recovery.set(None);
                    begin_unknown.set(false);
                    send_notice.set(None);
                    reload_generation.update(|value| *value = value.saturating_add(1));
                }
                Err(error) => {
                    let definite = matches!(
                        error,
                        crate::api::ApiError::NotFound
                            | crate::api::ApiError::Forbidden
                            | crate::api::ApiError::Unauthorized
                            | crate::api::ApiError::Conflict
                    );
                    if definite {
                        resumable.set(None);
                        resumable_recovery.set(None);
                        begin_unknown.set(false);
                        send_notice.set(Some(if error == crate::api::ApiError::Conflict {
                            SubmissionNotice::Conflict
                        } else {
                            SubmissionNotice::Rejected
                        }));
                        skill_composer.reload();
                        model_composer.directory_reload();
                    } else if submissions.has_barrier() {
                        resumable_recovery.set(Some(recovery));
                        begin_unknown.set(true);
                        send_notice.set(None);
                    } else {
                        // Snapshot/SSE may have confirmed this exact run before the HTTP future
                        // reported a lost response. Do not carry stale retry metadata forward.
                        resumable.set(None);
                        resumable_recovery.set(None);
                        begin_unknown.set(false);
                        send_notice.set(None);
                    }
                    reload_generation.update(|value| *value = value.saturating_add(1));
                }
            }
            submitting.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = requested;
            submitting.set(false);
            send_notice.set(Some(SubmissionNotice::Rejected));
        }
    });
    let component_ask_disabled = Signal::derive(move || {
        submitting.get()
            || resumable.get().is_some()
            || submissions.has_barrier()
            || state.get().active_run_id.is_some()
            || !channel_active
            || snapshot_error.get()
            || loading.get()
    });
    let ask_from_component = UnsyncCallback::new(move |(agent_id, message): (BotId, String)| {
        if component_ask_disabled.get_untracked() || trim_ecmascript(&message).is_empty() {
            return;
        }
        send_now.run(RunIntent {
            thread_id: thread_id.get_untracked(),
            run_id: mint_run_id(),
            agent_id,
            anchor: run_anchor.get_value(),
            message,
            selected_skill_slugs: Vec::new(),
            model_selection: None,
        });
    });
    let submit = UnsyncCallback::new(move |_| {
        if send_disabled.get_untracked() {
            return;
        }
        if let Some(attempt) = resumable.get_untracked() {
            send_now.run(attempt);
            return;
        }
        let composer_draft = skill_composer.compose();
        if composer_draft.is_empty {
            return;
        }
        let Some(requested_agent) = agent_id.get_value() else {
            return;
        };
        if let Some(model_notice) = model_notice(model_composer.selection_status()) {
            send_notice.set(Some(model_notice));
            return;
        }
        let model_selection = match model_composer.freeze() {
            Ok(selection) => selection,
            Err(_) => {
                send_notice.set(Some(SubmissionNotice::ModelSelectionUnavailable));
                return;
            }
        };
        let intent = RunIntent {
            thread_id: thread_id.get_untracked(),
            run_id: mint_run_id(),
            agent_id: requested_agent,
            anchor: run_anchor.get_value(),
            message: composer_draft.text,
            selected_skill_slugs: composer_draft.command_ids,
            model_selection,
        };
        let current = queued.get_untracked();
        let transition = reduce_queue(
            &current,
            QueueAction::Submit {
                intent: &intent,
                busy: busy.get_untracked(),
            },
        );
        let submitted_queued = transition.submitted_queued;
        let next_queue = transition.queue.into_owned();
        let run = transition.run.map(|run| run.into_owned());
        queued.set(next_queue);
        if submitted_queued {
            skill_composer.clear();
            model_composer.clear();
        }
        if let Some(run) = run {
            send_now.run(run);
        }
    });
    let stop = UnsyncCallback::new(move |_| {
        if !can_stop.get_untracked() {
            return;
        }
        let Some(thread) = thread_id.get_untracked() else {
            return;
        };
        let Some(run) = state.get_untracked().active_run_id else {
            return;
        };
        #[cfg(target_arch = "wasm32")]
        let action_read = ConversationActionRead::capture(
            Some(thread.clone()),
            reload_generation.get_untracked(),
            &state.get_untracked(),
        );
        cancelling_request.set(true);
        cancel_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let result = load_thread_conversation(&thread).await;
            let (Some(current_thread), Some(generation), Some(current)) = (
                thread_id.try_get_untracked(),
                reload_generation.try_get_untracked(),
                state.try_get_untracked(),
            ) else {
                return;
            };
            // Normal text/reasoning chunks do not revoke this original foreground's ability to
            // stop. Scope, generation, state and current permission still must all match.
            if !action_read.same_foreground(current_thread.as_ref(), generation, &current)
                || loading.try_get_untracked() != Some(false)
                || snapshot_error.try_get_untracked() != Some(false)
            {
                cancelling_request.set(false);
                return;
            }
            let snapshot = match result {
                Ok(snapshot) => snapshot,
                Err(_) => {
                    snapshot_error.set(true);
                    cancel_error.set(true);
                    cancelling_request.set(false);
                    return;
                }
            };
            if !action_read_allows_stop(&snapshot, &run) {
                // Cancelling/terminal/another foreground cannot authorize a second cancel.
                // Keep the current transcript and renew facts through the normal reader.
                loading.set(true);
                reload_generation.update(|value| *value = value.saturating_add(1));
                cancelling_request.set(false);
                return;
            }
            let result = cancel_thread_run(&thread, &run).await;
            let (Some(current_thread), Some(generation), Some(current)) = (
                thread_id.try_get_untracked(),
                reload_generation.try_get_untracked(),
                state.try_get_untracked(),
            ) else {
                return;
            };
            if !action_read.same_foreground(current_thread.as_ref(), generation, &current) {
                cancelling_request.set(false);
                return;
            }
            match result {
                Ok(reply) => {
                    if matches!(
                        reply.state,
                        ThreadRunCancellationState::Requested
                            | ThreadRunCancellationState::AlreadyRequested
                    ) {
                        state.update(|state| {
                            if state.active_run_id.as_ref() == Some(&run) {
                                state.active_run_state = Some(ThreadForegroundRunState::Cancelling);
                                state.active_run_cancellable = false;
                            }
                        });
                    }
                }
                Err(_) => {
                    cancel_error.set(true);
                }
            }
            // There is no frame in which the retained Running fact becomes actionable again
            // between a lost cancellation reply and its renewed pending/failed snapshot.
            loading.set(true);
            reload_generation.update(|value| *value = value.saturating_add(1));
            cancelling_request.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (thread, run);
            cancelling_request.set(false);
            cancel_error.set(true);
        }
    });
    // `send_now` 用 `spawn_local_scoped_with_cancellation`，任务绑定的是**调用时**的 reactive
    // owner。若从 Effect 体内调用，这个 owner 就是该 Effect 本次运行的 owner；而 send 本身会写
    // `submitting` 与 `state.active_run_id`，两者都被下面 Effect 追踪的 `busy` 依赖 —— Effect 立刻
    // 重跑并 dispose 上一次的 owner，把刚发出的 send 连同末尾的 `submitting.set(false)` 一起取消。
    // 结果是排队消息永远发不出去，且 `submitting` 卡在 true 让整个 Composer 死锁。改成在组件 owner
    // 里执行：它活过每一次 Effect 运行，与用户点击 Send 走的是同一个 owner。
    // A strong capture would keep the keyed conversation owner alive after a thread switch.
    let composer_owner = Owner::current().map(|owner| owner.downgrade());
    let was_active = RwSignal::new(false);
    let queue_drain_waiting = RwSignal::new(false);
    Effect::new(move |_| {
        let active = state.get().active_run_id.is_some();
        let previous = was_active.get_untracked();
        was_active.set(active);
        let pending = queue_drain_pending(previous, active, queue_drain_waiting.get_untracked());
        queue_drain_waiting.set(pending);
        if !should_drain_queue(
            pending,
            active || submitting.get(),
            loading.get() || snapshot_error.get(),
            channel_active,
            queued.get().is_empty(),
            submissions.has_barrier(),
            resumable.get().is_some(),
        ) {
            return;
        }
        let current = queued.get_untracked();
        let transition = reduce_queue(&current, QueueAction::Settle);
        let next_queue = transition.queue.into_owned();
        let run = transition.run.map(|run| run.into_owned());
        queued.set(next_queue);
        queue_drain_waiting.set(false);
        if let Some(run) = run {
            match composer_owner.as_ref() {
                Some(owner) => {
                    if let Some(owner) = owner.upgrade() {
                        owner.with(|| send_now.run(run));
                    }
                }
                None => send_now.run(run),
            }
        }
    });
    let retry_snapshot = move |_| {
        // An explicit read must also recover a fresh thread whose first Begin ACK was lost.
        allow_missing_snapshot.set(false);
        reload_generation.update(|value| *value = value.saturating_add(1));
    };

    view! {
        <ConversationWorkspace>
        <div class="ob-channel-conversation">
            <super::composer::presentation::AssistantIdentity
                profile=Signal::derive(move || identity_profile.get())
                title=agent_name.clone()
                compact=Signal::derive(move || !state.get().messages.is_empty() || !state.get().streaming_text.is_empty())
                description=move || if busy.get() { t_string!(i18n, channels.tool_running).to_owned() } else { t_string!(i18n, home.model_preset_note).to_owned() }
            />
            <Show when=move || loading.get()>
                <div class="ob-loading" role="status">{move || t!(i18n, common.loading)}</div>
            </Show>
            <Show when=move || snapshot_error.get()>
                <div class="ob-alert" role="alert">
                    <span>{move || t!(i18n, channels.conversation_load_error)}</span>
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Small
                        on_activate=retry_snapshot
                    >{move || t!(i18n, common.retry)}</Button>
                </div>
            </Show>
            <Show when=move || stream_error.get() && !snapshot_error.get()>
                <div class="ob-alert" role="status">
                    <span>{move || t!(i18n, channels.conversation_stream_error)}</span>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=retry_snapshot>{move || t!(i18n, channels.reread)}</Button>
                </div>
            </Show>
            <MessageScroller
                id="channel-transcript"
                aria_label=move || t_string!(i18n, channels.transcript_label).to_owned()
            >
                <MessageScrollerViewport>
                    <MessageScrollerContent busy=busy>
                        <crate::features::approvals::InlineToolApprovals run=Signal::derive(move || { let state = state.get(); state.active_run_id.or_else(||state.observed_run.map(|row| row.run)) }) />
                        <Show when=move || {
                            !loading.get()
                                && state.get().messages.is_empty()
                                && state.get().streaming_text.is_empty()
                                && !component_attention.has_for_run(state.get().active_run_id)
                                && !remote_attention.has_for_run(state.get().active_run_id)
                                && !tool_attention.has_for_run(state.get().active_run_id)
                        }>
                            <p class="ob-page-empty">{move || t!(i18n, channels.conversation_empty)}</p>
                        </Show>
                        <For
                            each=move || state.get().messages
                            key=|message| (message.id.clone(), message.content.clone(), message.component.as_ref().and_then(|c| c.result.clone()), message.component.as_ref().and_then(|c| c.error_code.clone()), message.tool.as_ref().map(|tool| (tool.call_id.clone(),tool.agent_id.clone(),tool.result.clone(),tool.error_code.clone())))
                            children={
                                let agent_seed = agent_seed.clone();
                                let agent_name = agent_name.clone();
                                move |message| view! {
                                    <TranscriptMessage
                                        message
                                        agent_seed=agent_seed.clone()
                                        agent_name=agent_name.clone()
                                        on_component_ask=ask_from_component
                                        component_ask_disabled
                                        on_remember
                                        memory_available=thread_id.get().is_some()
                                        artifact_source
                                    />
                                }
                            }
                        />
                        <crate::features::approvals::attention::DecisionAttention run=Signal::derive(move || { let state = state.get(); state.active_run_id.or_else(||state.observed_run.map(|row| row.run)) }) inline=true/>
                        <Show when=move || !state.get().streaming_text.is_empty()>
                            {move || state.get().active_run_id.map(|run_id| view! {
                                <MessageScrollerItem
                                    message_id=transcript_dom_id(run_id.as_str())
                                >
                                    <div data-streaming-message="">
                                        <Message
                                            aria_label=move || t_string!(i18n, channels.streaming_reply_label).to_owned()
                                        >
                                            <MessageAvatar>
                                                <span aria-hidden="true">
                                                    <Avatar
                                                        principal_id=streaming_agent_seed.get_value()
                                                        name=streaming_agent_name.get_value()
                                                        size=AvatarSize::Small
                                                    />
                                                </span>
                                            </MessageAvatar>
                                            <MessageContent>
                                                <MessageHeader>{streaming_agent_name.get_value()}</MessageHeader>
                                                <Bubble kind=BubbleKind::Assistant>
                                                    <StreamingMarkdownBody content=Signal::derive(move || state.get().streaming_text)/>
                                                </Bubble>
                                            </MessageContent>
                                        </Message>
                                    </div>
                                </MessageScrollerItem>
                            })}
                        </Show>
                        <Show when=move || {
                            busy.get()
                                && state.get().streaming_text.is_empty()
                                && !component_attention.has_for_run(state.get().active_run_id)
                                && !remote_attention.has_for_run(state.get().active_run_id)
                                && !tool_attention.has_for_run(state.get().active_run_id)
                                && !matches!(
                                    state.get().active_run_state,
                                    Some(
                                        ThreadForegroundRunState::Cancelling
                                            | ThreadForegroundRunState::ReconciliationRequired
                                    )
                                )
                        }>
                            <div class="ob-conversation-thinking" role="status">
                                <AgentPresence state=Signal::derive(move || AgentPresenceState::Thinking) />
                                <span>{move || t!(i18n, channels.tool_running)}</span>
                            </div>
                        </Show>
                        <Show when=move || {
                            cancelling_request.get()
                                || matches!(
                                    state.get().active_run_state,
                                    Some(ThreadForegroundRunState::Cancelling)
                                )
                        }>
                            <p class="ob-conversation-cancelling" role="status">
                                {move || t!(i18n, channels.cancelling)}
                            </p>
                        </Show>
                        <Show when=move || state.get().terminal_notice.is_some()>
                            <p class="ob-alert" role="status">{move || terminal_text(i18n, state.get().terminal_notice)}</p>
                        </Show>
                        <Show when=move || !queued.get().is_empty()><h2 class="ob-queue-heading">{move || t!(i18n, channels.queued_status)}</h2></Show>
                        <For
                            each=move || queued.get()
                            key=|message| message.id.clone()
                            children=move |message| {
                                let queue_id = message.id.clone();
                                let text = message.intent.message.clone();
                                let visible_text = text.clone();
                                let assistant = message.intent.agent_id.as_str().to_owned();
                                let model = message.intent.model_selection.as_ref().map_or_else(
                                    || t_string!(i18n, models.use_agent_default).to_owned(),
                                    |selection| t_string!(i18n, channels.queued_model_snapshot, connection=selection.connection_id.clone(), revision=selection.expected_revision).to_owned(),
                                );
                                let intent_summary = t_string!(i18n, channels.queued_intent_snapshot, assistant=assistant, model=model).to_owned();
                                let remove_label = t_string!(
                                    i18n,
                                    channels.queued_remove_label,
                                    message = text
                                )
                                .to_owned();
                                view! {
                                    <MessageScrollerItem
                                        message_id=transcript_dom_id(&format!("queue:{queue_id}"))
                                    >
                                        <div class="ob-queued-message" data-queued-message="">
                                            <Message
                                                align=MessageAlign::End
                                                aria_label=move || t_string!(i18n, channels.queued_message_label).to_owned()
                                            >
                                                <MessageContent>
                                                    <Bubble kind=BubbleKind::User>
                                                        <div class="ob-skill-chips">{message.intent.selected_skill_slugs.into_iter().map(|slug| view! { <code>{format!("/{slug}")}</code> }).collect_view()}</div>
                                                        <p class="ob-transcript-text">{visible_text}</p>
                                                    </Bubble>
                                                    <MessageFooter>
                                                        <span role="status">{move || t!(i18n, channels.queued_status)}</span>
                                                        <span class="ob-queue-snapshot">{intent_summary}</span>
                                                        <Button
                                                            variant=ButtonVariant::Ghost
                                                            size=ButtonSize::Small
                                                            aria_label=remove_label
                                                            on_activate=move |_| {
                                                                let current = queued.get_untracked();
                                                                let transition = reduce_queue(
                                                                    &current,
                                                                    QueueAction::Remove { id: &queue_id },
                                                                );
                                                                queued.set(transition.queue.into_owned());
                                                            }
                                                        >{move || t!(i18n, channels.queued_remove)}</Button>
                                                    </MessageFooter>
                                                </MessageContent>
                                            </Message>
                                        </div>
                                    </MessageScrollerItem>
                                }
                            }
                        />
                    </MessageScrollerContent>
                </MessageScrollerViewport>
                <MessageScrollerButton
                    aria_label=move || t_string!(i18n, channels.transcript_back_to_bottom).to_owned()
                />
            </MessageScroller>
            <ComputerWorkspace activity=Signal::derive(move || {
                state.get().messages.into_iter().filter(|m| matches!(m.kind, TranscriptKind::ToolCall | TranscriptKind::ToolResult | TranscriptKind::Component)).rev().take(100).map(|m| {
                    let label = if m.kind == TranscriptKind::ToolResult { t_string!(i18n, channels.tool_result_label).to_owned() } else { m.content.chars().take(160).collect() };
                    let output = m.tool.and_then(|tool|match (tool.error_code,tool.result) { (Some(code),result)=>Some(format!("{code}\n{}",result.unwrap_or_default())),(None,result)=>result }).or_else(||m.component.and_then(|c| c.result)).unwrap_or(m.content);
                    WorkspaceActivity { id: m.id, label, output }
                }).collect()
            }) observation=Signal::derive(move || state.get().observed_run) thread=thread_id.into()/>
            <RememberDialog review=remember_review/>
            <div class="ob-conversation-input">
                <super::composer::presentation::ComposerFrame active=true busy=Signal::derive(move || submitting.get())>
                <div class="ob-chat-draft">
                <Textarea
                    value=draft
                    id="channel-message"
                    aria_label=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                    placeholder=move || t_string!(i18n, channels.composer_placeholder).to_owned()
                    disabled=textarea_disabled
                    on_submit=submit
                    combobox_controls="channel-skill-results"
                    combobox_open=skill_composer.open
                    active_descendant=skill_composer.active_descendant
                    on_keydown=UnsyncCallback::new(move |event| skill_composer.keyboard(event))
                />
                <Show when=move || !skill_composer.selected.get().is_empty() && trim_ecmascript(&draft.get()).is_empty()>
                    <p class="ob-page-empty">{move || t!(i18n, skills.task_required)}</p>
                </Show>
                <Show when=move || queue_skills_invalid.get()><p class="ob-alert" role="alert">{move || t!(i18n, skills.selection_limit)}</p></Show>
                </div>
                <div class="ob-chat-controls">
                <ModelPicker state=model_composer disabled=textarea_disabled/>
                <SkillPicker state=skill_composer disabled=textarea_disabled/>
                <span class="ob-chat-send">
                <Show
                    when=move || show_stop.get()
                    fallback=move || view! {
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Medium
                            disabled=send_disabled
                            loading=submitting
                            on_activate=submit
                        >
                            <IconView icon=Icon::ArrowUp size=IconSize::Navigation />
                            <span class="ob-visually-hidden">{move || if begin_unknown.get() {
                                t_string!(i18n, common.retry).to_owned()
                            } else if busy.get() {
                                t_string!(i18n, channels.composer_queue).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_send).to_owned()
                            }}</span>
                        </Button>
                    }
                >
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Medium
                        disabled=stop_disabled
                        loading=cancelling_request
                        aria_label=move || t_string!(i18n, channels.composer_stop).to_owned()
                        on_activate=stop
                    >
                        <IconView icon=Icon::CircleStop size=IconSize::Inline />
                        <span class="ob-visually-hidden">{move || if cancelling_request.get()
                            || matches!(
                                state.get().active_run_state,
                                Some(ThreadForegroundRunState::Cancelling)
                            ) {
                                t_string!(i18n, channels.cancelling).to_owned()
                            } else {
                                t_string!(i18n, channels.composer_stop).to_owned()
                            }}</span>
                    </Button>
                </Show>
                </span>
                </div>
                </super::composer::presentation::ComposerFrame>
                <Show when=move || !loading.get() && state.get().messages.is_empty()>
                    <super::composer::presentation::DraftSuggestions disabled=textarea_disabled on_choose=UnsyncCallback::new(move |text| { if !textarea_disabled.get_untracked() { draft.set(text); } })/>
                </Show>
            </div>
            <Show when=move || send_notice.get()==Some(SubmissionNotice::ModelAgentConflict) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelAgentConflict)><p class="ob-alert" role="alert">{move || t!(i18n, channels.model_agent_conflict)}</p></Show>
            <Show when=move || send_notice.get()==Some(SubmissionNotice::ModelSelectionUnavailable) && model_notice(model_composer.selection_status())==Some(SubmissionNotice::ModelSelectionUnavailable)><p class="ob-alert" role="alert">{move || t!(i18n, channels.model_selection_unavailable)}</p></Show>
            <Show when=move || send_notice.get()==Some(SubmissionNotice::Conflict)><p class="ob-alert" role="alert">{move || t!(i18n, channels.submit_conflict)}</p></Show>
            <Show when=move || send_notice.get()==Some(SubmissionNotice::Rejected)><p class="ob-alert" role="alert">{move || t!(i18n, channels.submit_rejected)}</p></Show>
            <Show when=move || begin_unknown.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, channels.begin_unknown)}</p>
            </Show>
            <Show when=move || submission_blocked.get()>
                <a class="ob-alert" role="alert" href=move || submissions.barrier().and_then(|barrier| barrier.href()).unwrap_or_else(|| "/".to_owned())>
                    {move || t!(i18n, channels.submission_blocked)}
                </a>
            </Show>
            <Show when=move || cancel_error.get()>
                <p class="ob-alert" role="alert">{move || t!(i18n, channels.cancel_error)}</p>
            </Show>
            <Show when=move || !channel_active>
                <p class="ob-page-empty">{move || t!(i18n, channels.detail_inactive)}</p>
            </Show>
        </div>
        </ConversationWorkspace>
    }
}

#[component]
fn ToolTranscriptCard(tool: TranscriptTool) -> impl IntoView {
    let i18n = use_i18n();
    let display = read_tool_name(&tool.name);
    let controls = expect_context::<WorkspaceControls>();
    let recorded = tool.result.is_some();
    let error = tool.error_code.clone();
    let failed = error.is_some();
    let data_call = tool.call_id.clone();
    let computer = tool.name.starts_with("computer_");
    let unnamed = tool.name.is_empty();
    let label = display.label;
    view! { <article class="ob-tool-card" data-tool-call=data_call data-tool-state=if failed { "review" } else if recorded { "recorded" } else { "waiting" }>
        <header><strong>{move || if unnamed { t_string!(i18n, channels.tool_unrecognized).to_owned() } else { label.clone() }}</strong>{display.detail.map(|detail| view! { <span>{detail}</span> })}
            <span class="ob-tool-state">{move || if failed { t_string!(i18n, channels.tool_record_error).to_owned() } else if recorded { t_string!(i18n, channels.tool_result_recorded).to_owned() } else { t_string!(i18n, channels.tool_waiting_result).to_owned() }}</span>
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| controls.show(if computer { WorkspaceTab::Computer } else { WorkspaceTab::Results })>{move || t!(i18n, gallery.details)}</Button>
        </header>
        <p class="ob-tool-source">{tool.call_id.map(|id| view! { <code>{id}</code> })} " · " {tool.agent_id.map(|id| view! { <code>{id.as_str().to_owned()}</code> })}</p>
        {error.map(|code| view! { <p class="ob-tool-error" role="status"><code>{code}</code></p> })}
        {tool.result.map(|result| view! { <details><summary>{move || t!(i18n, channels.tool_result_label)}</summary><pre>{result}</pre></details> })}
    </article> }
}

#[component]
fn TranscriptMessage(
    message: TranscriptLine,
    agent_seed: String,
    agent_name: String,
    on_component_ask: UnsyncCallback<(BotId, String)>,
    component_ask_disabled: Signal<bool>,
    on_remember: UnsyncCallback<(String, String)>,
    memory_available: bool,
    artifact_source: ArtifactSourceObserver,
) -> impl IntoView {
    let i18n = use_i18n();
    let artifact_message_id = message.id.clone();
    let remember_source = (message.id.clone(), message.content.clone());
    let can_remember = memory_available
        && matches!(
            message.kind,
            TranscriptKind::User | TranscriptKind::Assistant
        )
        && !message.content.trim().is_empty();
    let user = message.kind == TranscriptKind::User;
    let kind = message.kind;
    let content = message.content;
    let tool = message.tool;
    let body = match message.component {
        Some(component) => view! {
            <ConversationComponent
                name=component.name
                arguments=component.arguments
                result=component.result
                error_code=component.error_code.or_else(|| {
                    component.agent_id.is_none().then(|| "component_agent_missing".to_owned())
                })
                agent_id=component.agent_id.unwrap_or_else(|| BotId::new("unavailable"))
                on_ask=on_component_ask
                ask_disabled=component_ask_disabled
            />
        }
        .into_any(),
        None if tool.is_some() => view! { <ToolTranscriptCard tool=tool.expect("present tool projection")/> }.into_any(),
        None => view! {
            <Bubble kind=if user { BubbleKind::User } else { BubbleKind::Assistant }>
                <div class="ob-skill-chips">{message.selected_skill_slugs.into_iter().map(|slug| view! { <code>{format!("/{slug}")}</code> }).collect_view()}</div>
                {if kind == TranscriptKind::Assistant { view! { <MarkdownBody content/> }.into_any() } else { view! { <p class="ob-transcript-text">{content}</p> }.into_any() }}
            </Bubble>
        }
        .into_any(),
    };
    let avatar_seed = StoredValue::new(agent_seed);
    let avatar_name = StoredValue::new(agent_name);
    let label = move || match kind {
        TranscriptKind::User => t_string!(i18n, channels.user_message_label).to_owned(),
        TranscriptKind::Assistant => t_string!(i18n, channels.assistant_message_label).to_owned(),
        TranscriptKind::ToolCall => t_string!(i18n, channels.tool_call_label).to_owned(),
        TranscriptKind::ToolResult => t_string!(i18n, channels.tool_result_label).to_owned(),
        TranscriptKind::Component => t_string!(i18n, channels.assistant_message_label).to_owned(),
    };
    view! {
        <MessageScrollerItem
            message_id=transcript_dom_id(&message.id)
            scroll_anchor=user
        >
            <Message
                align=if user { MessageAlign::End } else { MessageAlign::Start }
                aria_label=label
            >
                <MessageAvatar>
                    <span aria-hidden="true">
                        <Avatar
                            principal_id=if user { "current-user".to_owned() } else { avatar_seed.get_value() }
                            name=if user {
                                t_string!(i18n, channels.you).to_owned()
                            } else {
                                avatar_name.get_value()
                            }
                            size=AvatarSize::Small
                        />
                    </span>
                </MessageAvatar>
                <MessageContent>
                    <MessageHeader>{move || if user {
                        t_string!(i18n, channels.you).to_owned()
                    } else {
                        avatar_name.get_value()
                    }}</MessageHeader>
                    {body}
                    {can_remember.then(|| view! { <MessageFooter><Button variant=ButtonVariant::Ghost size=ButtonSize::Small on_activate=move |_| on_remember.run(remember_source.clone())>{move || t!(i18n, memory.remember_action)}</Button></MessageFooter> })}
                    {user.then(|| view! { <MessageFooter><ArtifactMessageActions message_id=artifact_message_id source=artifact_source/></MessageFooter> })}
                </MessageContent>
            </Message>
        </MessageScrollerItem>
    }
}

#[cfg(test)]
fn merge_component_human_decisions(
    current: &mut Vec<PendingComponentHumanDecision>,
    mut incoming: Vec<PendingComponentHumanDecision>,
    answers: &BTreeMap<String, ComponentHumanDecisionAnswer>,
) {
    for local in current.iter() {
        if answers.contains_key(&local.decision_id)
            && !incoming
                .iter()
                .any(|decision| decision.decision_id == local.decision_id)
        {
            incoming.push(local.clone());
        }
    }
    incoming.sort_by(|left, right| {
        (left.requested_at, &left.decision_id).cmp(&(right.requested_at, &right.decision_id))
    });
    *current = incoming;
}

fn transcript_dom_id(source: &str) -> String {
    let mut id = String::from("transcript-");
    for byte in Sha256::digest(source.as_bytes()) {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    id
}

fn terminal_text(
    i18n: leptos_i18n::I18nContext<crate::i18n::Locale>,
    notice: Option<TerminalNotice>,
) -> String {
    match notice {
        Some(TerminalNotice::Failed) => t_string!(i18n, channels.run_failed).to_owned(),
        Some(TerminalNotice::Cancelled) => t_string!(i18n, channels.run_cancelled).to_owned(),
        Some(TerminalNotice::ReconciliationRequired) => {
            t_string!(i18n, channels.run_reconciliation).to_owned()
        }
        None => String::new(),
    }
}

#[cfg(target_arch = "wasm32")]
struct EventConnection {
    source: EventSource,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _open: Closure<dyn FnMut(Event)>,
    _error: Closure<dyn FnMut(Event)>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for EventConnection {
    fn drop(&mut self) {
        for event in ["thread_run_event", "thread_stream_error"] {
            let _ = self
                .source
                .remove_event_listener_with_callback(event, self._message.as_ref().unchecked_ref());
        }
        let _ = self
            .source
            .remove_event_listener_with_callback("open", self._open.as_ref().unchecked_ref());
        let _ = self
            .source
            .remove_event_listener_with_callback("error", self._error.as_ref().unchecked_ref());
        self.source.close();
    }
}

#[allow(clippy::too_many_arguments)]
fn install_conversation_sync(
    thread_id: RwSignal<Option<ThreadId>>,
    state: RwSignal<ConversationState>,
    loading: RwSignal<bool>,
    snapshot_error: RwSignal<bool>,
    stream_error: RwSignal<bool>,
    generation: RwSignal<u64>,
    allow_missing_snapshot: RwSignal<bool>,
    artifact_source: ArtifactSourceObserver,
) {
    #[cfg(target_arch = "wasm32")]
    {
        let observed_runs = expect_context::<ObservedRunDirectory>();
        let connection = StoredValue::new_local(None::<EventConnection>);
        let desktop_connection = StoredValue::new_local(None::<DesktopStructuredConnection>);
        Effect::new(move |_| {
            let current_generation = generation.get();
            let current_thread = thread_id.get();
            connection.update_value(|current| {
                _ = current.take();
            });
            desktop_connection.update_value(|current| {
                _ = current.take();
            });
            snapshot_error.set(false);
            stream_error.set(false);
            let Some(thread) = current_thread else {
                state.set(ConversationState::default());
                loading.set(false);
                return;
            };
            if allow_missing_snapshot.get_untracked() {
                state.set(ConversationState::default());
                loading.set(false);
                return;
            }
            loading.set(true);
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let snapshot = load_thread_conversation(&thread).await;
                if generation.get_untracked() != current_generation
                    || thread_id.get_untracked().as_ref() != Some(&thread)
                {
                    return;
                }
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        if matches!(
                            error,
                            crate::api::ApiError::Unauthorized
                                | crate::api::ApiError::Forbidden
                                | crate::api::ApiError::NotFound
                        ) {
                            observed_runs.forget(&thread);
                            state.set(ConversationState::default());
                        }
                        loading.set(false);
                        snapshot_error.set(true);
                        return;
                    }
                };
                let cursor = snapshot.last_event_sequence;
                state.update(|state| state.install_snapshot(snapshot));
                loading.set(false);
                let handoff_thread = thread.clone();
                artifact_source.begin_channel_handoff(move || {
                    generation.try_get_untracked() == Some(current_generation)
                        && thread_id.try_get_untracked().flatten().as_ref() == Some(&handoff_thread)
                });
                if generation.get_untracked() != current_generation
                    || thread_id.get_untracked().as_ref() != Some(&thread)
                {
                    return;
                }
                let cursor = artifact_source.bootstrap_cursor(cursor);
                if is_tauri_host() {
                    let expected_thread = thread.clone();
                    let handlers = DesktopStructuredHandlers::new(
                        move |event| match apply_thread_stream_event(
                            event,
                            &expected_thread,
                            state,
                            artifact_source,
                        ) {
                            ThreadStreamOutcome::Keep => true,
                            ThreadStreamOutcome::Reload => false,
                            ThreadStreamOutcome::Error => {
                                stream_error.set(true);
                                false
                            }
                        },
                        move |_| stream_error.set(true),
                        move || stream_error.set(true),
                    );
                    match open_desktop_structured(
                        SubscriptionRequest::ThreadEvents {
                            thread_id: thread.clone(),
                            after_event_sequence: cursor,
                        },
                        handlers,
                    ) {
                        Ok(opened) => {
                            stream_error.set(false);
                            let finished = opened.finished_promise();
                            if generation.get_untracked() != current_generation
                                || thread_id.get_untracked().as_ref() != Some(&thread)
                            {
                                return;
                            }
                            desktop_connection.set_value(Some(opened));
                            _ = wasm_bindgen_futures::JsFuture::from(finished).await;
                        }
                        Err(()) => stream_error.set(true),
                    }
                    if generation.get_untracked() == current_generation
                        && thread_id.get_untracked().as_ref() == Some(&thread)
                    {
                        thread_reconnect_delay().await;
                        if generation.get_untracked() == current_generation {
                            generation.update(|value| *value = value.saturating_add(1));
                        }
                    }
                    return;
                }
                match open_event_source(
                    &thread,
                    cursor,
                    state,
                    stream_error,
                    generation,
                    artifact_source,
                ) {
                    Ok(opened) => {
                        if generation.get_untracked() == current_generation {
                            connection.set_value(Some(opened));
                        }
                    }
                    Err(()) => stream_error.set(true),
                }
            });
        });
        on_cleanup(move || {
            connection.update_value(|current| {
                _ = current.take();
            });
            desktop_connection.update_value(|current| {
                _ = current.take();
            });
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (
        thread_id,
        state,
        loading,
        snapshot_error,
        stream_error,
        generation,
        allow_missing_snapshot,
        artifact_source,
    );
}

#[cfg(target_arch = "wasm32")]
enum ThreadStreamOutcome {
    Keep,
    Reload,
    Error,
}

#[cfg(target_arch = "wasm32")]
fn apply_thread_stream_event(
    event: AppEvent,
    expected_thread: &ThreadId,
    state: RwSignal<ConversationState>,
    artifact_source: ArtifactSourceObserver,
) -> ThreadStreamOutcome {
    match event {
        AppEvent::ThreadRunEvent(event) => {
            let effect = state.try_update(|state| apply_live_event(state, expected_thread, &event));
            if matches!(&effect, Some(Ok(_))) {
                artifact_source.native_event(&event);
            }
            match effect {
                Some(Ok(LiveEffect::ReloadSnapshot)) | Some(Err(())) => ThreadStreamOutcome::Reload,
                Some(Ok(LiveEffect::None)) => ThreadStreamOutcome::Keep,
                None => ThreadStreamOutcome::Error,
            }
        }
        AppEvent::ThreadStreamError { .. }
        | AppEvent::Heartbeat { .. }
        | AppEvent::ChannelActivity(_)
        | AppEvent::ChannelStreamError { .. }
        | AppEvent::ToolApprovalActivity(_)
        | AppEvent::ToolApprovalStreamError { .. } => ThreadStreamOutcome::Error,
    }
}

#[cfg(target_arch = "wasm32")]
async fn thread_reconnect_delay() {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        web_sys::window()
            .expect("CSR Desktop thread reconnect requires Window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 500)
            .expect("browser rejected Desktop thread reconnect timer");
    });
    _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(target_arch = "wasm32")]
fn open_event_source(
    thread: &ThreadId,
    cursor: Option<u64>,
    state: RwSignal<ConversationState>,
    stream_error: RwSignal<bool>,
    generation: RwSignal<u64>,
    artifact_source: ArtifactSourceObserver,
) -> Result<EventConnection, ()> {
    let path = thread_event_stream_path(thread, cursor).map_err(|_| ())?;
    let source = EventSource::new(&path).map_err(|_| ())?;
    let expected_thread = thread.clone();
    let subscribed_generation = generation.get_untracked();
    let event_source = source.clone();
    let message = Closure::<dyn FnMut(MessageEvent)>::new(move |message: MessageEvent| {
        if generation.try_get_untracked() != Some(subscribed_generation) {
            return;
        }
        let Some(text) = message.data().as_string() else {
            stream_error.set(true);
            event_source.close();
            return;
        };
        let Ok(event) = serde_json::from_str::<AppEvent>(&text) else {
            stream_error.set(true);
            event_source.close();
            return;
        };
        match apply_thread_stream_event(event, &expected_thread, state, artifact_source) {
            ThreadStreamOutcome::Keep => {}
            ThreadStreamOutcome::Reload => {
                generation.update(|value| *value = value.saturating_add(1));
            }
            ThreadStreamOutcome::Error => {
                stream_error.set(true);
                event_source.close();
            }
        }
    });
    source
        .add_event_listener_with_callback("thread_run_event", message.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    source
        .add_event_listener_with_callback("thread_stream_error", message.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    let open = Closure::<dyn FnMut(Event)>::new(move |_| {
        if generation.try_get_untracked() == Some(subscribed_generation) {
            stream_error.try_set(false);
        }
    });
    source
        .add_event_listener_with_callback("open", open.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    let error = Closure::<dyn FnMut(Event)>::new(move |_| {
        if generation.try_get_untracked() == Some(subscribed_generation) {
            stream_error.try_set(true);
        }
    });
    source
        .add_event_listener_with_callback("error", error.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    Ok(EventConnection {
        source,
        _message: message,
        _open: open,
        _error: error,
    })
}

#[cfg(test)]
mod tests {
    use openbot_contracts::command::ThreadRunEvent;
    use time::OffsetDateTime;

    use super::*;

    fn current_snapshot(run: Option<RunId>, text: &str) -> ThreadConversationSnapshot {
        ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_state: run.as_ref().map(|_| ThreadForegroundRunState::Running),
            active_run_id: run,
            active_run_cancellable: true,
            active_run_text: text.into(),
            last_event_sequence: None,
        }
    }

    fn tool_history(id: &str, role: ThreadHistoryRole) -> ThreadHistoryMessage {
        ThreadHistoryMessage {
            id: id.into(),
            role,
            content: String::new(),
            selected_skill_slugs: Vec::new(),
            agent_id: Some(BotId::new("bot-1")),
            tool_call_id: None,
            tool_name: None,
            tool_error_code: None,
            tool_calls: None,
        }
    }

    #[test]
    fn all_tool_pairs_keep_results_and_reused_completed_provider_ids_are_legal() {
        let mut call = tool_history("call-message-1", ThreadHistoryRole::Assistant);
        call.tool_calls = Some(vec![
            serde_json::json!({"id":"provider-call","function":{"name":"mcp__files__write_file","arguments":{}}}),
        ]);
        let mut result = tool_history("result-message-1", ThreadHistoryRole::Tool);
        result.tool_call_id = Some("provider-call".into());
        result.tool_name = Some("mcp__files__write_file".into());
        result.content = "first result".into();
        let mut second_call = call.clone();
        second_call.id = "call-message-2".into();
        let mut second_result = result.clone();
        second_result.id = "result-message-2".into();
        second_result.content = "second refusal".into();
        second_result.tool_error_code = Some("write_refused".into());
        let projected = project_history(&[
            call.clone(),
            result.clone(),
            second_call.clone(),
            second_result,
        ]);
        assert_eq!(projected.len(), 2);
        assert_eq!(
            projected[0].tool.as_ref().unwrap().result.as_deref(),
            Some("first result")
        );
        assert_eq!(projected[0].tool.as_ref().unwrap().error_code, None);
        assert_eq!(
            projected[1].tool.as_ref().unwrap().result.as_deref(),
            Some("second refusal")
        );
        assert_eq!(
            projected[1].tool.as_ref().unwrap().error_code.as_deref(),
            Some("write_refused")
        );
        let duplicate = project_history(&[call.clone(), second_call, result.clone()]);
        assert_eq!(duplicate.len(), 3);
        assert_eq!(
            duplicate[0].tool.as_ref().unwrap().error_code.as_deref(),
            Some("tool_call_duplicate")
        );
        assert_eq!(
            duplicate[2].tool.as_ref().unwrap().error_code.as_deref(),
            Some("tool_result_unpaired")
        );
        result.agent_id = Some(BotId::new("other"));
        let mismatch = project_history(&[call, result]);
        assert_eq!(mismatch.len(), 2);
        assert_eq!(
            mismatch[0].tool.as_ref().unwrap().error_code.as_deref(),
            Some("tool_result_mismatch")
        );
    }

    #[test]
    fn new_accepted_run_excludes_previous_results_before_stream_or_snapshot() {
        let mut state = ConversationState {
            observed_run: Some(RunObservation {
                run: RunId::new("old"),
                phase: OutputPhase::Succeeded,
                text: "old answer".into(),
                terminal_sequence: Some(1),
            }),
            ..Default::default()
        };
        state.accepted_run(RunId::new("new"));
        assert_eq!(state.observed_run.as_ref().unwrap().run, RunId::new("new"));
        assert!(state.observed_run.as_ref().unwrap().text.is_empty());
        assert_eq!(
            state.active_run_id,
            state.observed_run.as_ref().map(|row| row.run.clone())
        );
    }

    #[test]
    fn missed_terminal_recovery_is_unobserved_and_never_guesses_rr_or_success() {
        let mut state = ConversationState::default();
        state.install_snapshot(current_snapshot(
            Some(RunId::new("run-1")),
            "current partial",
        ));
        state.install_snapshot(current_snapshot(None, ""));
        let observed = state.observed_run.as_ref().unwrap();
        assert_eq!(observed.phase, OutputPhase::UnobservedTerminal);
        assert_eq!(observed.text, "current partial");
        assert!(state.active_run_id.is_none());
        assert!(state.terminal_notice.is_none());
    }

    #[test]
    fn terminal_output_is_only_observed_current_run_and_partial_survives_rr_snapshot() {
        for kind in [
            ThreadRunEventKind::Completed,
            ThreadRunEventKind::Failed,
            ThreadRunEventKind::Cancelled,
            ThreadRunEventKind::ReconciliationRequired,
        ] {
            let mut state = ConversationState::default();
            assert_eq!(
                apply_live_event(
                    &mut state,
                    &ThreadId::new("thread-1"),
                    &event(1, kind, serde_json::json!({}))
                )
                .unwrap(),
                LiveEffect::ReloadSnapshot
            );
            assert!(state.observed_run.as_ref().unwrap().text.is_empty());
        }
        let mut state = ConversationState::default();
        state.install_snapshot(current_snapshot(
            Some(RunId::new("run-1")),
            "current partial",
        ));
        let mut snapshot = current_snapshot(Some(RunId::new("run-1")), "");
        snapshot.active_run_state = Some(ThreadForegroundRunState::ReconciliationRequired);
        state.install_snapshot(snapshot);
        assert_eq!(state.observed_run.as_ref().unwrap().text, "current partial");
        assert_eq!(
            state.observed_run.as_ref().unwrap().phase,
            OutputPhase::Unknown
        );
        let mut foreign = event(1, ThreadRunEventKind::Completed, serde_json::json!({}));
        foreign.run_id = RunId::new("other");
        assert_eq!(
            apply_live_event(&mut state, &ThreadId::new("thread-1"), &foreign).unwrap(),
            LiveEffect::ReloadSnapshot
        );
        assert_eq!(
            state.observed_run.as_ref().unwrap().run,
            RunId::new("run-1")
        );
    }

    fn event(
        sequence: u64,
        kind: ThreadRunEventKind,
        payload: serde_json::Value,
    ) -> ThreadRunEvent {
        ThreadRunEvent {
            thread_id: ThreadId::new("thread-1"),
            run_id: RunId::new("run-1"),
            event_sequence: sequence,
            event_type: kind,
            payload,
            terminal: kind.is_terminal(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn snapshot_carries_durable_history_active_text_and_cursor_without_a_seed() {
        let mut state = ConversationState::default();
        state.install_snapshot(ThreadConversationSnapshot {
            messages: vec![ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "user-1".to_owned(),
                role: ThreadHistoryRole::User,
                content: "hello".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            }],
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            active_run_text: "partial".to_owned(),
            last_event_sequence: Some(3),
        });
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.streaming_text, "partial");
        assert_eq!(state.cursor, Some(3));
        assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
    }

    #[test]
    fn history_projects_user_assistant_tool_activity_but_not_system_prompt() {
        let lines = project_history(&[
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "system".to_owned(),
                role: ThreadHistoryRole::System,
                content: "secret standing instruction".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "user".to_owned(),
                role: ThreadHistoryRole::User,
                content: "hello".to_owned(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "assistant".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: None,
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![
                    serde_json::json!({"id":"call-1","function":{"name":"mcp__notes__search_notes","arguments":{}}}),
                ]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "tool".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: serde_json::to_string("found it").unwrap(),
                agent_id: None,
                tool_call_id: Some("call-1".to_owned()),
                tool_name: Some("mcp__notes__search_notes".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].kind, TranscriptKind::User);
        assert_eq!(
            lines[1].tool.as_ref().unwrap().name,
            "mcp__notes__search_notes"
        );
        assert_eq!(
            lines[1].tool.as_ref().unwrap().result.as_deref(),
            Some("found it")
        );
        assert!(!format!("{lines:?}").contains("secret standing instruction"));
    }

    #[test]
    fn durable_component_call_and_result_pair_into_one_transcript_renderer() {
        let messages = [
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "component-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-call-1",
                    "type":"function",
                    "function":{
                        "name":"showQuote",
                        "arguments":{"quote":"Exact words","attribution":"the report"}
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "component-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: "The quotation is now on screen for the person.".to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-call-1".to_owned()),
                tool_name: Some("showQuote".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ];
        let lines = project_history(&messages);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].kind, TranscriptKind::Component);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "showQuote");
        assert_eq!(component.provider_call_id, "provider-call-1");
        assert_eq!(component.arguments["quote"], "Exact words");
        assert_eq!(
            component.result.as_deref(),
            Some("The quotation is now on screen for the person.")
        );
        assert_eq!(component.error_code, None);
        assert_eq!(component.agent_id, Some(BotId::new("bot-1")));

        let mut refused = messages;
        refused[1].tool_error_code = Some("component_withheld".to_owned());
        assert_eq!(
            project_history(&refused)[0]
                .component
                .as_ref()
                .unwrap()
                .error_code
                .as_deref(),
            Some("component_withheld")
        );

        refused[1].tool_error_code = None;
        refused[1].agent_id = Some(BotId::new("bot-2"));
        assert_eq!(
            project_history(&refused)[0]
                .component
                .as_ref()
                .unwrap()
                .error_code
                .as_deref(),
            Some("component_result_mismatch")
        );
    }

    #[test]
    fn durable_decision_result_is_retained_for_completed_renderer_replay() {
        let lines = project_history(&[
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "decision-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-choice-1",
                    "type":"function",
                    "function":{
                        "name":"askChoice",
                        "arguments":{
                            "title":"Where?",
                            "options":[{"id":"prod","label":"Production"}]
                        }
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "decision-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: r#"{"choice":"prod","label":"Production"}"#.to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-choice-1".to_owned()),
                tool_name: Some("askChoice".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ]);
        assert_eq!(lines.len(), 1);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "askChoice");
        assert_eq!(component.provider_call_id, "provider-choice-1");
        assert_eq!(
            component.result.as_deref(),
            Some(r#"{"choice":"prod","label":"Production"}"#)
        );
        assert_eq!(component.error_code, None);
    }

    #[test]
    fn durable_sandboxed_call_is_projected_by_exact_namespace_not_prefix_guess() {
        let messages = [
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "sandbox-call".to_owned(),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":"provider-sandbox-1",
                    "type":"function",
                    "function":{
                        "name":"custom_delivery_eta",
                        "arguments":{"title":"Tomorrow"}
                    }
                })]),
            },
            ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: "sandbox-result".to_owned(),
                role: ThreadHistoryRole::Tool,
                content: "It is now on screen for the person.".to_owned(),
                agent_id: Some(BotId::new("bot-1")),
                tool_call_id: Some("provider-sandbox-1".to_owned()),
                tool_name: Some("custom_delivery_eta".to_owned()),
                tool_error_code: None,
                tool_calls: None,
            },
        ];
        let lines = project_history(&messages);
        assert_eq!(lines.len(), 1);
        let component = lines[0].component.as_ref().unwrap();
        assert_eq!(component.name, "custom_delivery_eta");
        assert_eq!(component.arguments, serde_json::json!({"title":"Tomorrow"}));
        assert_eq!(
            component.result.as_deref(),
            Some("It is now on screen for the person.")
        );
    }

    #[test]
    fn polling_keeps_a_locally_answered_card_until_its_durable_pair_arrives() {
        let pending = PendingComponentHumanDecision {
            decision_id: "decision-1".to_owned(),
            run_id: RunId::new("run-1"),
            provider_call_id: "provider-1".to_owned(),
            agent_id: BotId::new("bot-1"),
            component_name: "askApproval".to_owned(),
            arguments: serde_json::json!({"title":"Approve?","summary":"Summary"}),
            requested_at: time::OffsetDateTime::UNIX_EPOCH,
            expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(30),
        };
        let mut current = vec![pending.clone()];
        let answers = BTreeMap::from([(
            pending.decision_id.clone(),
            ComponentHumanDecisionAnswer::Approval(
                openbot_contracts::components::ComponentApprovalAnswer {
                    decision: openbot_contracts::components::ComponentApprovalDecision::Approved,
                    note: None,
                },
            ),
        )]);
        merge_component_human_decisions(&mut current, Vec::new(), &answers);
        assert_eq!(current, [pending]);
        merge_component_human_decisions(&mut current, Vec::new(), &BTreeMap::new());
        assert!(current.is_empty());
    }

    #[test]
    fn durable_retry_keeps_its_agent_and_is_not_disabled_by_an_empty_composer() {
        assert!(!send_control_disabled(
            false, true, false, false, false, true, true,
        ));
        assert!(send_control_disabled(
            false, true, true, false, false, true, false,
        ));
        let pending = PendingTurn {
            thread_id: Some(ThreadId::new("thread-1")),
            run_id: RunId::new("run-1"),
            agent_id: BotId::new("bot-from-component"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "Exact follow-up".to_owned(),
            selected_skill_slugs: vec!["review".to_owned()],
            model_selection: None,
        };
        assert_eq!(pending.agent_id.as_str(), "bot-from-component");
        assert_eq!(pending.message, "Exact follow-up");
    }

    #[test]
    fn live_text_is_ordered_deduplicated_and_terminal_requests_snapshot_reload() {
        let mut state = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":"hel"})
                ),
            ),
            Ok(LiveEffect::None)
        );
        _ = apply_live_event(
            &mut state,
            &ThreadId::new("thread-1"),
            &event(
                1,
                ThreadRunEventKind::SemanticChunk,
                serde_json::json!({"channel":"text","delta":"duplicate"}),
            ),
        );
        _ = apply_live_event(
            &mut state,
            &ThreadId::new("thread-1"),
            &event(
                2,
                ThreadRunEventKind::SemanticChunk,
                serde_json::json!({"channel":"reasoning","delta":"hidden"}),
            ),
        );
        assert_eq!(state.streaming_text, "hel");
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    3,
                    ThreadRunEventKind::Checkpoint,
                    serde_json::json!({
                        "kind":"remote_agui_projection",
                        "source":"remote_ag_ui",
                        "family":"raw",
                        "untrusted":true,
                        "untrustedKey":"remote",
                        "untrustedType":null,
                        "untrustedValue":{"permission":"forged-admin","text":"not transcript"}
                    })
                ),
            ),
            Ok(LiveEffect::None)
        );
        assert_eq!(state.streaming_text, "hel");
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    4,
                    ThreadRunEventKind::Completed,
                    serde_json::json!({"status":"completed"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(state.active_run_id.is_none());
    }

    #[test]
    fn remote_projection_checkpoint_requires_closed_untrusted_wrapper() {
        for (sequence, payload, expected) in [
            (
                1,
                serde_json::json!({
                    "kind":"remote_agui_projection",
                    "source":"remote_ag_ui",
                    "family":"custom",
                    "untrusted":false,
                    "untrustedKey":"event",
                    "untrustedType":null,
                    "untrustedValue":{}
                }),
                Err(()),
            ),
            (
                2,
                serde_json::json!({
                    "kind":"remote_agui_projection",
                    "source":"remote_ag_ui",
                    "retained":false,
                    "untrusted":true
                }),
                Ok(LiveEffect::None),
            ),
        ] {
            let mut state = ConversationState {
                active_run_id: Some(RunId::new("run-1")),
                cursor: Some(sequence - 1),
                ..ConversationState::default()
            };
            assert_eq!(
                apply_live_event(
                    &mut state,
                    &ThreadId::new("thread-1"),
                    &event(sequence, ThreadRunEventKind::Checkpoint, payload),
                ),
                expected
            );
            assert!(state.streaming_text.is_empty());
            assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
        }
    }

    #[test]
    fn gap_wrong_thread_and_invalid_payload_never_become_visible_text() {
        let mut state = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    2,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":"gap"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        let mut wrong = event(
            1,
            ThreadRunEventKind::SemanticChunk,
            serde_json::json!({"channel":"text","delta":"wrong"}),
        );
        wrong.thread_id = ThreadId::new("thread-2");
        assert_eq!(
            apply_live_event(&mut state, &ThreadId::new("thread-1"), &wrong),
            Err(())
        );
        assert!(state.streaming_text.is_empty());
    }

    #[test]
    fn transcript_dom_identity_is_bounded_and_not_controlled_by_message_id() {
        let id = transcript_dom_id("message/one?x=1\n");
        assert_eq!(id, transcript_dom_id("message/one?x=1\n"));
        assert!(id.len() <= 128);
        assert!(
            id.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }

    #[test]
    fn terminal_notices_are_closed_codes_and_cannot_carry_raw_error_words() {
        assert_eq!(TerminalNotice::Failed.as_str(), "failed");
        assert_eq!(TerminalNotice::Cancelled.as_str(), "cancelled");
        assert_eq!(
            TerminalNotice::ReconciliationRequired.as_str(),
            "reconciliation_required"
        );
        assert_eq!(core::mem::size_of::<TerminalNotice>(), 1);
    }

    #[test]
    fn stop_is_visible_only_on_durable_facts_and_actionable_only_for_the_first_request() {
        let stoppable = StopControl {
            input_locked: false,
            cancelling_request: false,
            loading: false,
            snapshot_error: false,
            draft_empty: true,
            cancellable: true,
            run_state: Some(ThreadForegroundRunState::Running),
        };
        assert!(stoppable.visible() && stoppable.enabled());

        // 草稿非空时reviewer件仍是 Send，Stop 既不显示也不可点。
        let drafting = StopControl {
            draft_empty: false,
            ..stoppable
        };
        assert!(!drafting.visible() && !drafting.enabled());

        // 非 run 发起者拿到的 snapshot `cancellable=false`：GUI 不得给出可点的假 Stop，
        // 与 durable_cancel_is_scoped_idempotent_… 的 PostgreSQL 拒绝面一致。
        let bystander = StopControl {
            cancellable: false,
            ..stoppable
        };
        assert!(!bystander.visible() && !bystander.enabled());

        // 本地 send 在飞 / 本 mount 请求未确认：可见但 inert，不会重复铸造请求。
        for inert in [
            StopControl {
                input_locked: true,
                ..stoppable
            },
            StopControl {
                cancelling_request: true,
                ..stoppable
            },
            StopControl {
                loading: true,
                ..stoppable
            },
            StopControl {
                snapshot_error: true,
                ..stoppable
            },
        ] {
            assert!(inert.visible() && !inert.enabled());
        }

        // 已经 Cancelling（可能来自另一副本）：只观察，不再请求。
        let cancelling = StopControl {
            cancellable: false,
            run_state: Some(ThreadForegroundRunState::Cancelling),
            ..stoppable
        };
        assert!(cancelling.visible() && !cancelling.enabled());

        assert!(!StopControl::default().visible() && !StopControl::default().enabled());
    }

    #[test]
    fn stop_action_read_requires_the_original_running_cancellable_foreground() {
        let original = RunId::new("run-1");
        let mut snapshot = ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(original.clone()),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            active_run_text: "actual current output".to_owned(),
            last_event_sequence: Some(4),
        };
        assert!(action_read_allows_stop(&snapshot, &original));
        snapshot.active_run_id = Some(RunId::new("another-run"));
        assert!(!action_read_allows_stop(&snapshot, &original));
        snapshot.active_run_id = Some(original.clone());
        for run_state in [
            ThreadForegroundRunState::Queued,
            ThreadForegroundRunState::Cancelling,
            ThreadForegroundRunState::ReconciliationRequired,
        ] {
            snapshot.active_run_state = Some(run_state);
            assert!(!action_read_allows_stop(&snapshot, &original));
        }
        snapshot.active_run_state = Some(ThreadForegroundRunState::Running);
        snapshot.active_run_cancellable = false;
        assert!(!action_read_allows_stop(&snapshot, &original));
        snapshot.active_run_id = None;
        snapshot.active_run_state = None;
        snapshot.active_run_text.clear();
        assert!(!action_read_allows_stop(&snapshot, &original));
    }

    #[test]
    fn held_stop_read_preserves_streaming_but_rejects_changed_authority_or_foreground() {
        let thread = ThreadId::new("thread-1");
        let mut state = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            streaming_text: "already observed ".to_owned(),
            observed_run: Some(RunObservation::running(
                RunId::new("run-1"),
                "already observed ".to_owned(),
            )),
            cursor: Some(0),
            ..Default::default()
        };
        let read = ConversationActionRead::capture(Some(thread.clone()), 7, &state);
        assert!(read.is_current(Some(&thread), 7, &state));
        assert!(read.same_foreground(Some(&thread), 7, &state));
        assert!(!read.is_current(Some(&ThreadId::new("thread-2")), 7, &state));
        assert!(!read.same_foreground(Some(&ThreadId::new("thread-2")), 7, &state));
        assert!(!read.is_current(Some(&thread), 8, &state));
        assert!(!read.same_foreground(Some(&thread), 8, &state));
        let mut foreign = state.clone();
        foreign.active_run_id = Some(RunId::new("another-run"));
        assert!(!read.is_current(Some(&thread), 7, &foreign));
        assert!(!read.same_foreground(Some(&thread), 7, &foreign));
        let mut cancelling = state.clone();
        cancelling.active_run_state = Some(ThreadForegroundRunState::Cancelling);
        cancelling.active_run_cancellable = false;
        assert!(!read.is_current(Some(&thread), 7, &cancelling));
        assert!(!read.same_foreground(Some(&thread), 7, &cancelling));
        assert_eq!(
            apply_live_event(
                &mut state,
                &thread,
                &event(
                    1,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":"newer output"}),
                ),
            ),
            Ok(LiveEffect::None)
        );
        assert!(!read.is_current(Some(&thread), 7, &state));
        assert!(read.same_foreground(Some(&thread), 7, &state));
        assert!(!read.same_observed_foreground(&state));
        assert_eq!(state.streaming_text, "already observed newer output");
        assert_eq!(
            state.observed_run.as_ref().unwrap().text,
            "already observed newer output"
        );
        assert_eq!(state.cursor, Some(1));
    }

    #[test]
    fn late_accepted_run_needs_observation_after_a_non_output_checkpoint() {
        let thread = ThreadId::new("thread-1");
        let mut state = ConversationState {
            cursor: Some(0),
            ..Default::default()
        };
        let read = ConversationActionRead::capture(Some(thread.clone()), 7, &state);
        assert_eq!(
            apply_live_event(
                &mut state,
                &thread,
                &event(
                    1,
                    ThreadRunEventKind::Checkpoint,
                    serde_json::json!({"kind":"current_observation_barrier"}),
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(!read.is_current(Some(&thread), 8, &state));
        assert!(read.same_observed_foreground(&state));
        assert!(state.observed_run.is_none() && state.streaming_text.is_empty());

        assert_eq!(
            apply_live_event(
                &mut state,
                &thread,
                &event(2, ThreadRunEventKind::Started, serde_json::json!({})),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(!read.same_observed_foreground(&state));
        assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
        assert!(state.streaming_text.is_empty());
    }

    #[test]
    fn retry_action_read_distinguishes_exact_active_identity_without_installing_history() {
        let original = RunId::new("run-1");
        let mut snapshot = ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(original.clone()),
            active_run_state: Some(ThreadForegroundRunState::ReconciliationRequired),
            active_run_cancellable: false,
            active_run_text: "original unresolved output".to_owned(),
            last_event_sequence: Some(4),
        };
        let state = ConversationState {
            streaming_text: "newer retained output".to_owned(),
            cursor: Some(9),
            observed_run: Some(RunObservation {
                run: original.clone(),
                phase: OutputPhase::Unknown,
                text: "current positive facts are independent".to_owned(),
                terminal_sequence: Some(9),
            }),
            ..Default::default()
        };
        let before = state.clone();
        assert_eq!(
            retry_read_fact(&snapshot, &original),
            RetryReadFact::Original
        );
        snapshot.active_run_id = Some(RunId::new("another-run"));
        assert_eq!(retry_read_fact(&snapshot, &original), RetryReadFact::Other);
        snapshot.active_run_id = None;
        snapshot.active_run_state = None;
        snapshot.active_run_text.clear();
        // NoActive is only the manual same-intent retry branch, never a non-commit receipt.
        assert_eq!(retry_read_fact(&snapshot, &original), RetryReadFact::Absent);
        assert_eq!(state, before);
    }

    #[test]
    fn cancelling_snapshot_holds_the_foreground_without_claiming_children_stopped() {
        let mut state = ConversationState::default();
        state.install_snapshot(ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Cancelling),
            active_run_cancellable: false,
            active_run_text: "partial".to_owned(),
            last_event_sequence: Some(4),
        });
        // Cancelling 不是 terminal：foreground 仍被占，且不得提前投影 Cancelled。
        assert_eq!(state.active_run_id, Some(RunId::new("run-1")));
        assert!(!state.active_run_cancellable);
        assert_eq!(state.terminal_notice, None);

        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    5,
                    ThreadRunEventKind::Cancelled,
                    serde_json::json!({"status":"cancelled"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(state.active_run_id.is_none());
        assert_eq!(state.terminal_notice, Some(TerminalNotice::Cancelled));

        // commit 未知时 foreground 继续被占，Cancelled 不得抹掉不确定性。
        let mut unknown = ConversationState::default();
        unknown.install_snapshot(ThreadConversationSnapshot {
            messages: Vec::new(),
            active_run_id: Some(RunId::new("run-2")),
            active_run_state: Some(ThreadForegroundRunState::ReconciliationRequired),
            active_run_cancellable: false,
            active_run_text: String::new(),
            last_event_sequence: Some(9),
        });
        assert_eq!(unknown.active_run_id, Some(RunId::new("run-2")));
        assert_eq!(
            unknown.terminal_notice,
            Some(TerminalNotice::ReconciliationRequired)
        );
    }

    #[test]
    fn started_for_an_already_tracked_run_costs_no_reload_and_keeps_cancellable() {
        // 本地 send：begin receipt 先把 run 与 cancellable 落进 state，随后 SSE 才送到 Started。
        let mut local = ConversationState {
            active_run_id: Some(RunId::new("run-1")),
            active_run_state: Some(ThreadForegroundRunState::Running),
            active_run_cancellable: true,
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut local,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::Started,
                    serde_json::json!({"runId":"run-1"})
                ),
            ),
            Ok(LiveEffect::None)
        );
        assert!(local.active_run_cancellable);

        // 别处发起的 run：不得沿用上一个 run 的 cancellable，必须回 durable snapshot 取。
        let mut foreign = ConversationState {
            active_run_id: None,
            active_run_cancellable: true,
            cursor: Some(0),
            ..ConversationState::default()
        };
        assert_eq!(
            apply_live_event(
                &mut foreign,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::Started,
                    serde_json::json!({"runId":"run-1"})
                ),
            ),
            Ok(LiveEffect::ReloadSnapshot)
        );
        assert!(!foreign.active_run_cancellable);
        assert_eq!(foreign.active_run_id, Some(RunId::new("run-1")));
    }

    #[test]
    fn parked_queue_drains_only_after_an_authoritative_run_terminal_edge() {
        assert!(queue_drain_pending(true, false, false));
        assert!(!queue_drain_pending(false, false, false));
        // A definite Begin failure changes only local submitting state, so it cannot arm a drain.
        assert!(!should_drain_queue(
            queue_drain_pending(false, false, false),
            false,
            false,
            true,
            false,
            false,
            false,
        ));
        // A real terminal edge is retained while another local gate is busy, then drains once safe.
        assert!(!should_drain_queue(
            true, true, false, true, false, false, false,
        ));
        assert!(should_drain_queue(
            true, false, false, true, false, false, false,
        ));
        assert!(!should_drain_queue(
            true, false, false, true, false, true, false,
        ));
        assert!(!should_drain_queue(
            true, false, false, true, false, false, true,
        ));
        // A newer foreground run cannot consume the latched item. Its own terminal edge drains it.
        let pending = queue_drain_pending(true, false, false);
        assert!(!should_drain_queue(
            pending, true, false, true, false, false, false,
        ));
        let pending = queue_drain_pending(false, true, pending);
        let pending = queue_drain_pending(true, false, pending);
        assert!(should_drain_queue(
            pending, false, false, true, false, false, false,
        ));
    }

    #[test]
    fn channel_new_pending_replay_boundary_includes_zero_without_lowering_snapshot() {
        use super::super::artifacts::channel_handoff_replay_cursor;
        for (snapshot, started, expected) in [
            (Some(0), Some(0), None),
            (Some(9), Some(0), None),
            (Some(9), Some(7), Some(6)),
            (Some(3), Some(7), Some(3)),
            (None, Some(7), None),
            (Some(9), None, Some(9)),
        ] {
            let mut snapshot_state = ConversationState::default();
            let mut current = current_snapshot(Some(RunId::new("run-1")), "native output");
            current.last_event_sequence = snapshot;
            snapshot_state.install_snapshot(current);
            let before = snapshot_state.clone();
            assert_eq!(
                channel_handoff_replay_cursor(snapshot_state.cursor, started),
                expected
            );
            assert_eq!(snapshot_state, before);
        }
    }

    #[test]
    fn channel_new_original_started_replay_keeps_transcript_deduplicated() {
        let mut snapshot = current_snapshot(Some(RunId::new("run-1")), "native output");
        snapshot.last_event_sequence = Some(0);
        let mut state = ConversationState::default();
        state.install_snapshot(snapshot);
        let before = state.clone();
        let started = event(
            0,
            ThreadRunEventKind::Started,
            serde_json::json!({
                "runId": "run-1", "messageId": "run-1:input", "botId": "bot-1"
            }),
        );
        for _ in 0..2 {
            assert_eq!(
                apply_live_event(&mut state, &ThreadId::new("thread-1"), &started),
                Ok(LiveEffect::None)
            );
            assert_eq!(state, before);
        }
        let mut foreign = started.clone();
        foreign.thread_id = ThreadId::new("foreign-thread");
        assert_eq!(
            apply_live_event(&mut state, &ThreadId::new("thread-1"), &foreign),
            Err(())
        );
        assert_eq!(state, before);
    }

    #[test]
    fn pending_never_resolving_target_proof_does_not_block_native_transcript_progress() {
        use super::super::artifacts::channel_handoff_replay_cursor;
        let mut snapshot = current_snapshot(Some(RunId::new("run-1")), "existing output");
        snapshot.last_event_sequence = Some(0);
        let mut state = ConversationState::default();
        state.install_snapshot(snapshot);
        // This is the synchronous native-subscription input with a real pending ACK=0.
        // No optional target-proof future is awaited or completed to obtain it.
        assert_eq!(channel_handoff_replay_cursor(state.cursor, Some(0)), None);
        assert_eq!(
            apply_live_event(
                &mut state,
                &ThreadId::new("thread-1"),
                &event(
                    1,
                    ThreadRunEventKind::SemanticChunk,
                    serde_json::json!({"channel":"text","delta":" new actual output"})
                )
            ),
            Ok(LiveEffect::None)
        );
        assert_eq!(state.cursor, Some(1));
        assert_eq!(state.streaming_text, "existing output new actual output");
    }
}
