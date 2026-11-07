//! One selected native USER save and its read-only metadata. No history catalogue or byte reader.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use leptos::prelude::*;
use openbot_contracts::{
    artifacts::{
        ArtifactGoneStatus, ArtifactMetadata, ArtifactRegistrationReceipt,
        SaveRunMessageTextArtifact,
    },
    auth::Role,
    command::{
        MAX_THREAD_MESSAGE_BYTES, ThreadConversationSnapshot, ThreadHistoryRole, ThreadRunAnchor,
        ThreadRunEvent, ThreadRunEventKind, ThreadRunStarted,
    },
    ids::{ActorId, BotId, RunId, ThreadId, thread::ThreadIdentity},
    people::CurrentUser,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::composer::model_intents::RunIntent;
use crate::{
    api::artifacts::MetadataError,
    i18n::{t, use_i18n},
    primitives::{Button, ButtonSize, ButtonVariant},
};

#[cfg(target_arch = "wasm32")]
use crate::api::artifacts::SaveError;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActorObservation {
    actor: ActorId,
    role: Role,
}

impl From<CurrentUser> for ActorObservation {
    fn from(user: CurrentUser) -> Self {
        Self {
            actor: user.id,
            role: user.role,
        }
    }
}

fn text_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UserSource {
    // Local view identity only. The host/PG independently checks its real authorization scope.
    mount: u64,
    epoch: u64,
    scope_generation: u64,
    actor: ActorObservation,
    thread: ThreadId,
    run: RunId,
    bot: BotId,
    anchor: ThreadRunAnchor,
    message: String,
    sha256: String,
    byte_length: usize,
    started_sequence: u64,
}

impl UserSource {
    fn same_saved_source(&self, other: &Self) -> bool {
        self.actor.actor == other.actor.actor
            && self.thread == other.thread
            && self.run == other.run
            && self.bot == other.bot
            && self.anchor == other.anchor
            && self.message == other.message
            && self.sha256 == other.sha256
            && self.byte_length == other.byte_length
    }
}

#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartedPayload {
    run_id: RunId,
    message_id: String,
    bot_id: BotId,
}

// Exactly one waiting native intent per mount, at most the existing 1MiB native input budget.
// The original raw string moves into the one qualification read and is then zeroized.
struct SourceJoin {
    mount: u64,
    epoch: u64,
    scope_generation: u64,
    actor: ActorObservation,
    thread: ThreadId,
    run: RunId,
    bot: BotId,
    anchor: ThreadRunAnchor,
    text: Option<Zeroizing<String>>,
    target_fresh: bool,
    pending_charge: Option<usize>,
    ack: Option<ThreadRunStarted>,
    started: Option<(u64, StartedPayload)>,
    invalid: bool,
}

struct SourceRead {
    source: UserSource,
    original_text: Zeroizing<String>,
}

impl SourceJoin {
    fn new(
        mount: u64,
        epoch: u64,
        scope_generation: u64,
        actor: ActorObservation,
        intent: &RunIntent,
    ) -> Option<Self> {
        let thread = intent.thread_id.clone()?;
        if mount == 0
            || scope_generation == 0
            || !ThreadIdentity::is_plausible(&thread)
            || intent.message.is_empty()
            || intent.message.len() > MAX_THREAD_MESSAGE_BYTES
            || !openbot_contracts::artifacts::is_valid_artifact_identity(intent.run_id.as_str())
            || !openbot_contracts::artifacts::is_valid_artifact_identity(intent.agent_id.as_str())
            || !openbot_contracts::artifacts::is_valid_artifact_identity(actor.actor.as_str())
        {
            return None;
        }
        Some(Self {
            mount,
            epoch,
            scope_generation,
            actor,
            thread,
            run: intent.run_id.clone(),
            bot: intent.agent_id.clone(),
            anchor: intent.anchor.clone(),
            text: Some(Zeroizing::new(intent.message.clone())),
            target_fresh: true,
            pending_charge: None,
            ack: None,
            started: None,
            invalid: false,
        })
    }

    fn same_intent(&self, intent: &RunIntent) -> bool {
        intent.thread_id.as_ref() == Some(&self.thread)
            && intent.run_id == self.run
            && intent.agent_id == self.bot
            && intent.anchor == self.anchor
            && self
                .text
                .as_ref()
                .is_some_and(|text| text.as_str() == intent.message)
    }

    fn observe_ack(&mut self, ack: &ThreadRunStarted) {
        if ack.thread_id != self.thread
            || ack.run_id != self.run
            || self.ack.as_ref().is_some_and(|old| old != ack)
        {
            self.invalid = true;
            return;
        }
        self.ack = Some(ack.clone());
    }

    fn observe_started(&mut self, event: &ThreadRunEvent) {
        if event.thread_id != self.thread || event.run_id != self.run {
            return;
        }
        if event.event_type != ThreadRunEventKind::Started {
            return;
        }
        let payload = serde_json::from_value::<StartedPayload>(event.payload.clone());
        let Ok(payload) = payload else {
            self.invalid = true;
            return;
        };
        if event.terminal
            || payload.run_id != self.run
            || payload.bot_id != self.bot
            || !openbot_contracts::artifacts::is_valid_artifact_identity(&payload.message_id)
            || self
                .started
                .as_ref()
                .is_some_and(|old| old != &(event.event_sequence, payload.clone()))
        {
            self.invalid = true;
            return;
        }
        if let Some(base) = self.pending_charge {
            let total = base
                .checked_add(payload.run_id.as_str().len())
                .and_then(|bytes| bytes.checked_add(payload.bot_id.as_str().len()))
                .and_then(|bytes| bytes.checked_add(payload.message_id.len()));
            if total.is_none_or(|bytes| bytes > MAX_THREAD_MESSAGE_BYTES) {
                self.invalid = true;
                self.text = None;
                self.started = None;
                return;
            }
        }
        self.started = Some((event.event_sequence, payload));
    }

    fn take_read(&mut self) -> Option<SourceRead> {
        if self.invalid {
            self.text = None;
            return None;
        }
        if !self.target_fresh {
            return None;
        }
        let ack = self.ack.as_ref()?;
        let (sequence, started) = self.started.as_ref()?;
        if ack.event_sequence != *sequence {
            self.invalid = true;
            self.text = None;
            return None;
        }
        let text = self.text.take()?;
        Some(SourceRead {
            source: UserSource {
                mount: self.mount,
                epoch: self.epoch,
                scope_generation: self.scope_generation,
                actor: self.actor.clone(),
                thread: self.thread.clone(),
                run: self.run.clone(),
                bot: self.bot.clone(),
                anchor: self.anchor.clone(),
                message: started.message_id.clone(),
                sha256: text_digest(&text),
                byte_length: text.len(),
                started_sequence: *sequence,
            },
            original_text: text,
        })
    }
}

fn source_matches_snapshot(source: &UserSource, snapshot: &ThreadConversationSnapshot) -> bool {
    if snapshot
        .last_event_sequence
        .is_none_or(|seq| seq < source.started_sequence)
    {
        return false;
    }
    let mut matching = snapshot
        .messages
        .iter()
        .filter(|row| row.id == source.message);
    let Some(row) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && row.role == ThreadHistoryRole::User
        && row.agent_id.as_ref() == Some(&source.bot)
        && row.content.len() == source.byte_length
        && text_digest(&row.content) == source.sha256
}

fn source_read_matches(read: &SourceRead, snapshot: &ThreadConversationSnapshot) -> bool {
    source_matches_snapshot(&read.source, snapshot)
        && snapshot
            .messages
            .iter()
            .find(|row| row.id == read.source.message)
            .is_some_and(|row| row.content.as_bytes() == read.original_text.as_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChannelHandoffToken {
    token: u64,
    mount: u64,
    probe: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OriginIntent {
    run: RunId,
    bot: BotId,
    text_sha256: String,
    skills: Vec<String>,
    model: Option<openbot_contracts::model_connections::RunModelSelection>,
}

impl OriginIntent {
    fn new(
        run: &RunId,
        bot: &BotId,
        text: &str,
        skills: &[String],
        model: &Option<openbot_contracts::model_connections::RunModelSelection>,
    ) -> Option<Self> {
        if text.is_empty()
            || text.len() > MAX_THREAD_MESSAGE_BYTES
            || !openbot_contracts::artifacts::is_valid_artifact_identity(run.as_str())
            || !openbot_contracts::artifacts::is_valid_artifact_identity(bot.as_str())
            || !openbot_contracts::command::valid_selected_skill_slugs(skills)
            || model.as_ref().is_some_and(|model| !model.is_valid())
        {
            return None;
        }
        Some(Self {
            run: run.clone(),
            bot: bot.clone(),
            text_sha256: text_digest(text),
            skills: skills.to_vec(),
            model: model.clone(),
        })
    }

    fn matches(&self, intent: &RunIntent) -> bool {
        self.run == intent.run_id
            && self.bot == intent.agent_id
            && self.text_sha256 == text_digest(&intent.message)
            && self.skills == intent.selected_skill_slugs
            && self.model == intent.model_selection
    }
}

struct OriginProbe {
    id: ChannelHandoffToken,
    scope_at_start: u64,
    intent: OriginIntent,
    observed: Option<(ActorObservation, u64)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReceiverClaim {
    id: ChannelHandoffToken,
    mount: u64,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandoffPhase {
    Staged,
    Ready,
    Committed,
    Claimed(u64, u64),
}

// The additional provenance text is never Clone or raw Debug. Its one allocation moves to SourceJoin.

#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingTargetProbe {
    claim: ReceiverClaim,
    probe: u64,
}

struct NativeChannelHandoff {
    id: ChannelHandoffToken,
    intent: OriginIntent,
    target_path: String,
    join: SourceJoin,
    phase: HandoffPhase,
    charged_bytes: usize,
}

fn handoff_budget(
    intent: &RunIntent,
    actor: &ActorObservation,
    target_path: &str,
) -> Option<usize> {
    if intent.message.is_empty()
        || intent.message.len() > MAX_THREAD_MESSAGE_BYTES
        || !openbot_contracts::command::valid_selected_skill_slugs(&intent.selected_skill_slugs)
        || intent
            .model_selection
            .as_ref()
            .is_some_and(|model| !model.is_valid())
    {
        return None;
    }
    let thread = intent.thread_id.as_ref()?;
    let mut bytes = std::mem::size_of::<NativeChannelHandoff>()
        .checked_add(std::mem::size_of::<PendingTargetProbe>().checked_mul(2)?)?;
    for length in [
        intent.message.len(),
        actor.actor.as_str().len(),
        thread.as_str().len(),
        intent.run_id.as_str().len(),
        intent.agent_id.as_str().len(),
        target_path.len(),
        64, // One intent digest, not a second raw-message copy.
        intent.run_id.as_str().len(),
        intent.agent_id.as_str().len(),
        thread.as_str().len(), // Reserve the exact required ACK identifiers.
        intent.run_id.as_str().len(),
    ] {
        bytes = bytes.checked_add(length)?;
    }
    if let ThreadRunAnchor::Channel { channel_id } = &intent.anchor {
        bytes = bytes.checked_add(channel_id.as_str().len())?;
    } else {
        return None;
    }
    for skill in &intent.selected_skill_slugs {
        bytes = bytes.checked_add(std::mem::size_of::<String>())?;
        bytes = bytes.checked_add(skill.len())?;
    }
    if let Some(model) = &intent.model_selection {
        bytes = bytes.checked_add(model.connection_id.as_str().len())?;
    }
    (bytes <= MAX_THREAD_MESSAGE_BYTES).then_some(bytes)
}

pub(crate) fn channel_handoff_replay_cursor(
    snapshot_cursor: Option<u64>,
    pending_real_started: Option<u64>,
) -> Option<u64> {
    let Some(started) = pending_real_started else {
        return snapshot_cursor;
    };
    match (snapshot_cursor, started.checked_sub(1)) {
        (Some(snapshot), Some(before_started)) => Some(snapshot.min(before_started)),
        _ => None,
    }
}

#[derive(Default)]
struct SourceState {
    actor: Option<ActorObservation>,
    epoch: u64,
    handoff_epoch: Option<u64>,
    pending_target: Option<PendingTargetProbe>,
    join: Option<SourceJoin>,
    eligible: Option<UserSource>,
    qualifying: bool,
}

impl SourceState {
    fn clear_pending_target(&mut self, pending: PendingTargetProbe) {
        if self.pending_target == Some(pending) && self.epoch == pending.claim.epoch {
            self.pending_target = None;
            self.handoff_epoch = None;
            self.join = None;
            self.eligible = None;
        }
    }
    fn begin_handoff_adoption(&mut self) -> Option<u64> {
        if self.qualifying || self.join.is_some() {
            return None;
        }
        self.epoch = self.epoch.checked_add(1)?;
        self.eligible = None;
        self.handoff_epoch = None;
        self.pending_target = None;
        Some(self.epoch)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ArtifactSourceObserver {
    state: RwSignal<SourceState>,
    actions: ArtifactActions,
    owner: StoredValue<Option<WeakOwner>>,
    mount: u64,
    thread: RwSignal<Option<ThreadId>>,
    bot: StoredValue<Option<BotId>>,
    anchor: StoredValue<ThreadRunAnchor>,
}

impl ArtifactSourceObserver {
    pub(crate) fn new(
        thread: RwSignal<Option<ThreadId>>,
        bot: StoredValue<Option<BotId>>,
        anchor: StoredValue<ThreadRunAnchor>,
    ) -> Self {
        let actions = expect_context::<ArtifactActions>();
        let mount = actions
            .state
            .try_update(|state| {
                let next = state.next_mount.checked_add(1)?;
                state.next_mount = next;
                Some(next)
            })
            .flatten()
            .unwrap_or(0);
        let source = Self {
            state: RwSignal::new(SourceState::default()),
            actions,
            owner: StoredValue::new(Owner::current().map(|owner| owner.downgrade())),
            mount,
            thread,
            bot,
            anchor,
        };
        // A route's metadata projection never survives its owner. Its registration/Unknown does.
        on_cleanup(move || actions.close_route(mount));
        #[cfg(target_arch = "wasm32")]
        if !source.has_channel_handoff() {
            source.with_owner(move || {
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let _ = source.refresh_actor().await;
                });
            });
        }
        source
    }

    #[cfg(target_arch = "wasm32")]
    fn with_owner(self, work: impl FnOnce() + 'static) {
        if let Some(owner) = self
            .owner
            .try_get_value()
            .flatten()
            .and_then(|owner| owner.upgrade())
        {
            owner.with(work);
        }
    }

    fn has_channel_handoff(self) -> bool {
        let (Some(thread), Some(bot), Some(anchor)) = (
            self.thread.try_get_untracked().flatten(),
            self.bot.try_get_value().flatten(),
            self.anchor.try_get_value(),
        ) else {
            return false;
        };
        self.actions
            .state
            .try_with_untracked(|state| state.has_handoff(&thread, &bot, &anchor))
            .unwrap_or(false)
    }

    fn prepare_channel_handoff(self) -> Option<PendingTargetProbe> {
        if !self.has_channel_handoff() {
            return None;
        }
        let (Some(thread), Some(bot), Some(anchor)) = (
            self.thread.try_get_untracked().flatten(),
            self.bot.try_get_value().flatten(),
            self.anchor.try_get_value(),
        ) else {
            return None;
        };
        let epoch = self
            .state
            .try_update(SourceState::begin_handoff_adoption)
            .flatten()?;
        let claim = self
            .actions
            .state
            .try_update(|state| state.claim_handoff(self.mount, epoch, &thread, &bot, &anchor))
            .flatten()?;
        let join = self
            .actions
            .state
            .try_update(|state| state.take_pending_handoff(claim, &thread, &bot, &anchor))
            .flatten()?;
        let probe = self
            .actions
            .state
            .try_update(|state| state.start_actor_probe(self.mount))
            .flatten();
        let Some(probe) = probe else {
            return None; // The moved one raw buffer drops here; the native stream still opens.
        };
        let pending = PendingTargetProbe { claim, probe };
        let installed = self
            .state
            .try_update(|state| {
                if state.epoch != epoch || state.qualifying || state.join.is_some() {
                    return false;
                }
                state.handoff_epoch = Some(epoch);
                state.pending_target = Some(pending);
                state.eligible = None;
                state.join = Some(join);
                true
            })
            .unwrap_or(false);
        if !installed {
            self.actions
                .state
                .try_update(|state| state.cancel_target_probe(pending));
            return None;
        }
        Some(pending)
    }

    fn pending_target_current(self, pending: PendingTargetProbe) -> bool {
        self.owner
            .try_get_value()
            .flatten()
            .and_then(|owner| owner.upgrade())
            .is_some()
            && self
                .state
                .try_with_untracked(|state| {
                    state.pending_target == Some(pending)
                        && state.epoch == pending.claim.epoch
                        && state.handoff_epoch == Some(pending.claim.epoch)
                        && state.join.as_ref().is_some_and(|join| {
                            !join.invalid
                                && !join.target_fresh
                                && join.mount == self.mount
                                && join.epoch == pending.claim.epoch
                                && self.thread.try_get_untracked().flatten().as_ref()
                                    == Some(&join.thread)
                                && self.bot.try_get_value().flatten().as_ref() == Some(&join.bot)
                                && self.anchor.try_get_value().as_ref() == Some(&join.anchor)
                        })
                })
                .unwrap_or(false)
    }

    fn cancel_pending_target(self, pending: PendingTargetProbe) {
        self.state
            .try_update(|state| state.clear_pending_target(pending));
        self.actions
            .state
            .try_update(|state| state.cancel_target_probe(pending));
    }

    fn finish_pending_target(self, pending: PendingTargetProbe, actor: Option<ActorObservation>) {
        // Read-only token/owner/epoch/target checks precede every actor/probe state mutation.
        if !self.pending_target_current(pending) {
            self.cancel_pending_target(pending);
            return;
        }
        let expected = self
            .state
            .try_with_untracked(|state| {
                let join = state.join.as_ref()?;
                Some((join.actor.clone(), join.scope_generation))
            })
            .flatten();
        let Some((expected_actor, scope)) = expected else {
            self.cancel_pending_target(pending);
            return;
        };
        let accepted = self
            .actions
            .state
            .try_update(|state| {
                state.finish_target_probe(pending, &expected_actor, scope, actor.clone())
            })
            .unwrap_or(false);
        if !accepted {
            self.cancel_pending_target(pending);
            return;
        }
        let matched = actor.as_ref() == Some(&expected_actor)
            && self.actions.scope_generation(&expected_actor) == Some(scope);
        self.state.try_update(|state| {
            if state.pending_target != Some(pending) || state.epoch != pending.claim.epoch {
                return;
            }
            if !matched {
                state.clear_pending_target(pending);
                return;
            }
            if let Some(join) = state.join.as_mut()
                && join.epoch == pending.claim.epoch
                && !join.invalid
            {
                join.target_fresh = true;
                state.actor = actor;
                state.pending_target = None;
            }
        });
        self.qualify_if_joined();
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn begin_channel_handoff(self, current: impl Fn() -> bool + 'static) {
        if !current() {
            return;
        }
        let Some(pending) = self.prepare_channel_handoff() else {
            return;
        };
        self.with_owner(move || {
            // Parallel optional proof; it cannot delay the original SSE/IPC opener.
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let actor = crate::api::load_current_user()
                    .await
                    .ok()
                    .map(ActorObservation::from);
                if !current() {
                    self.cancel_pending_target(pending);
                    return;
                }
                self.finish_pending_target(pending, actor);
            });
        });
    }

    pub(crate) fn bootstrap_cursor(self, snapshot_cursor: Option<u64>) -> Option<u64> {
        let pending = self
            .state
            .try_with_untracked(|state| {
                let join = state.join.as_ref()?;
                let current_direct = state.handoff_epoch.is_none()
                    && join.target_fresh
                    && !state.qualifying
                    && join.mount == self.mount
                    && state.epoch == join.epoch
                    && matches!(&join.anchor, ThreadRunAnchor::DirectBot)
                    && self
                        .owner
                        .try_get_value()
                        .flatten()
                        .and_then(|owner| owner.upgrade())
                        .is_some()
                    && self.thread.try_get_untracked().flatten().as_ref() == Some(&join.thread)
                    && self.bot.try_get_value().flatten().as_ref() == Some(&join.bot)
                    && self.anchor.try_get_value().as_ref() == Some(&join.anchor);
                if (state.handoff_epoch != Some(join.epoch) && !current_direct)
                    || join.invalid
                    || (join.target_fresh && join.started.is_some())
                    || (join.target_fresh && state.actor.as_ref() != Some(&join.actor))
                    || self.actions.scope_generation(&join.actor) != Some(join.scope_generation)
                {
                    return None;
                }
                join.ack.as_ref().map(|ack| ack.event_sequence)
            })
            .flatten();
        channel_handoff_replay_cursor(snapshot_cursor, pending)
    }

    // Observations are side effects only in this separate source state, never in send/FIFO state.
    pub(crate) fn stage_begin(self, intent: &RunIntent) {
        self.state.try_update(|state| {
            if state
                .join
                .as_ref()
                .is_some_and(|join| join.same_intent(intent))
            {
                return;
            }
            state.eligible = None;
            state.join = None;
            state.handoff_epoch = None;
            state.pending_target = None;
            // One outstanding source read owns the only raw buffer. Native sends stay unaffected.
            if state.qualifying {
                state.epoch = state.epoch.saturating_add(1);
                return;
            }
            let Some(actor) = state.actor.clone() else {
                return;
            };
            let Some(scope_generation) = self.actions.scope_generation(&actor) else {
                return;
            };
            if self.bot.try_get_value().flatten().as_ref() != Some(&intent.agent_id)
                || self.anchor.try_get_value().as_ref() != Some(&intent.anchor)
            {
                return;
            }
            let Some(epoch) = state.epoch.checked_add(1) else {
                return;
            };
            state.epoch = epoch;
            state.join = SourceJoin::new(self.mount, epoch, scope_generation, actor, intent);
        });
    }

    pub(crate) fn begin_reply(self, run: &RunId, result: Result<&ThreadRunStarted, ()>) {
        self.state.try_update(|state| {
            let Some(join) = state.join.as_mut().filter(|join| &join.run == run) else {
                return;
            };
            match result {
                Ok(ack) => join.observe_ack(ack),
                Err(()) => {
                    join.invalid = true;
                    join.text = None;
                    state.eligible = None;
                }
            }
        });
        self.qualify_if_joined();
    }

    pub(crate) fn native_event(self, event: &ThreadRunEvent) {
        let cancelled = self
            .state
            .try_update(|state| {
                let invalid = state.join.as_mut().is_some_and(|join| {
                    join.observe_started(event);
                    join.invalid
                });
                if invalid {
                    state.eligible = None;
                    if let Some(pending) = state.pending_target {
                        state.clear_pending_target(pending);
                        return Some(pending);
                    }
                }
                None
            })
            .flatten();
        if let Some(pending) = cancelled {
            self.actions
                .state
                .try_update(|state| state.cancel_target_probe(pending));
        }
        self.qualify_if_joined();
    }

    fn qualify_if_joined(self) {
        let read = self
            .state
            .try_update(|state| {
                if state.qualifying {
                    return None;
                }
                let read = state.join.as_mut()?.take_read()?;
                state.qualifying = true;
                Some(read)
            })
            .flatten();
        let Some(read) = read else {
            return;
        };
        let qualification = QualificationTicket { state: self.state };
        #[cfg(target_arch = "wasm32")]
        self.with_owner(move || {
            // One independent authorized source read; it cannot replace the conversation snapshot.
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let _qualification = qualification;
                let Ok(current) = self.refresh_actor().await else {
                    return;
                };
                if current != read.source.actor || !self.waiting_for(&read.source) {
                    return;
                }
                let Ok(snapshot) = crate::api::load_thread_conversation(&read.source.thread).await
                else {
                    return;
                };
                if !self.waiting_for(&read.source) || !source_read_matches(&read, &snapshot) {
                    return;
                }
                self.state.try_update(|state| {
                    if state.epoch == read.source.epoch
                        && state.actor.as_ref() == Some(&read.source.actor)
                    {
                        state.eligible = Some(read.source.clone());
                    }
                });
            });
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (read, qualification);
    }

    fn waiting_for(self, source: &UserSource) -> bool {
        self.state
            .try_with_untracked(|state| {
                state.epoch == source.epoch
                    && state.actor.as_ref() == Some(&source.actor)
                    && state.join.as_ref().is_some_and(|join| {
                        !join.invalid && join.target_fresh && join.run == source.run
                    })
            })
            .unwrap_or(false)
            && self.actions.scope_current(source)
            && self.mount == source.mount
            && self.thread.try_get_untracked().flatten().as_ref() == Some(&source.thread)
            && self.bot.try_get_value().flatten().as_ref() == Some(&source.bot)
            && self.anchor.try_get_value().as_ref() == Some(&source.anchor)
    }

    fn selection(self, message: &str) -> Option<UserSource> {
        self.actions.state.with(|_| ());
        self.state.with(|state| {
            if state.join.as_ref().is_some_and(|join| !join.target_fresh) {
                return None;
            }
            state
                .eligible
                .as_ref()
                .filter(|source| source.message == message && self.actions.scope_current(source))
                .cloned()
        })
    }

    fn selection_current(self, source: &UserSource) -> bool {
        self.state
            .try_with_untracked(|state| state.eligible.as_ref() == Some(source))
            .unwrap_or(false)
            && self.waiting_for(source)
    }

    fn view_current(self, source: &UserSource) -> bool {
        // A registered ID may be observed after returning to its route, without requalifying Save.
        self.state
            .try_with_untracked(|state| state.actor.as_ref() == Some(&source.actor))
            .unwrap_or(false)
            && self.actions.scope_current(source)
            && self.thread.try_get_untracked().flatten().as_ref() == Some(&source.thread)
            && self.bot.try_get_value().flatten().as_ref() == Some(&source.bot)
            && self.anchor.try_get_value().as_ref() == Some(&source.anchor)
    }

    #[cfg(target_arch = "wasm32")]
    async fn refresh_actor(self) -> Result<ActorObservation, MetadataError> {
        let probe = self
            .actions
            .state
            .try_update(|state| state.start_actor_probe(self.mount))
            .flatten()
            .ok_or(MetadataError::Unavailable)?;
        let result = crate::api::load_current_user().await;
        let failure = result.as_ref().err().map(|error| actor_read_error(*error));
        let current = result.ok().map(ActorObservation::from);
        let accepted = self
            .actions
            .state
            .try_update(|state| state.finish_actor_probe(probe, self.mount, current.clone()))
            .unwrap_or(false);
        if !accepted {
            return Err(MetadataError::Unavailable);
        }
        self.state.try_update(|state| {
            if state.actor != current {
                state.join = None;
                state.eligible = None;
            }
            state.actor = current.clone();
        });
        current.ok_or(failure.unwrap_or(MetadataError::Unauthorized))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SavePhase {
    Saving,
    Unknown,
    NotSubmitted,
    Registered(ArtifactRegistrationReceipt),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Operation {
    token: u64,
    source: UserSource,
    packet: SaveRunMessageTextArtifact,
    phase: SavePhase,
}

impl Operation {
    fn packet_matches_source(&self) -> bool {
        self.packet.source_thread_id == self.source.thread
            && self.packet.source_run_id == self.source.run
            && self.packet.source_message_id == self.source.message
            && self.packet.expected_sha256 == self.source.sha256
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum MetadataState {
    #[default]
    Idle,
    Loading,
    Loaded(Box<ArtifactMetadata>),
    Failed(MetadataError),
}

#[derive(Default)]
struct ActionState {
    next_mount: u64,
    next_handoff: u64,
    origin_probe: Option<OriginProbe>,
    handoff: Option<NativeChannelHandoff>,
    next_action: u64,
    checking: Option<(u64, UserSource)>,
    operation: Option<Operation>,
    // Local response ownership only; these values are not Server auth/window tokens.
    receipt_read_generation: u64,
    receipt_read: Option<(u64, Operation)>,
    actor: Option<ActorObservation>,
    scope_generation: u64,
    auth_read_generation: u64,
    auth_probe: Option<(u64, u64)>,
    read_generation: u64,
    metadata_mount: Option<u64>,
    metadata: MetadataState,
}

impl ActionState {
    fn start_origin(&mut self, intent: OriginIntent) -> Option<ChannelHandoffToken> {
        self.origin_probe = None;
        self.handoff = None;
        let mount = self.next_mount.checked_add(1)?;
        let token = self.next_handoff.checked_add(1)?;
        let probe = self.start_actor_probe(mount)?;
        self.next_mount = mount;
        self.next_handoff = token;
        let id = ChannelHandoffToken {
            token,
            mount,
            probe,
        };
        self.origin_probe = Some(OriginProbe {
            id,
            scope_at_start: self.scope_generation,
            intent,
            observed: None,
        });
        Some(id)
    }

    fn origin_reply(
        &mut self,
        id: ChannelHandoffToken,
        intent: &OriginIntent,
        current: Option<ActorObservation>,
    ) {
        // Every check precedes finish_actor_probe: a late reply cannot change target actor/scope.
        let live = self.origin_probe.as_ref().is_some_and(|probe| {
            probe.id == id
                && probe.intent == *intent
                && probe.scope_at_start == self.scope_generation
                && probe.observed.is_none()
        }) && self.auth_probe == Some((id.probe, id.mount));
        if !live {
            return;
        }
        if !self.finish_actor_probe(id.probe, id.mount, current.clone()) {
            return;
        }
        if let Some(probe) = self.origin_probe.as_mut().filter(|probe| probe.id == id) {
            probe.observed = current.map(|actor| (actor, self.scope_generation));
        }
    }

    fn origin_probe_pending(&self, id: ChannelHandoffToken, intent: &RunIntent) -> bool {
        self.auth_read_generation == id.probe
            && self.auth_probe == Some((id.probe, id.mount))
            && self.origin_probe.as_ref().is_some_and(|probe| {
                probe.id == id
                    && probe.scope_at_start == self.scope_generation
                    && probe.intent.matches(intent)
                    && probe.observed.is_none()
            })
    }

    fn capture_origin(&mut self, id: ChannelHandoffToken, intent: &RunIntent) -> bool {
        if self.auth_read_generation != id.probe
            || !self
                .origin_probe
                .as_ref()
                .is_some_and(|probe| probe.id == id)
        {
            return false;
        }
        if self.origin_probe_pending(id, intent) {
            return false; // Keep this original read alive; Begin still dispatches immediately.
        }
        let Some(probe) = self.origin_probe.take() else {
            return false;
        };
        if self.auth_probe == Some((id.probe, id.mount)) {
            self.auth_probe = None;
        }
        let Some((actor, scope)) = probe.observed else {
            return false; // Optional GET pending/failed: original Begin does not wait.
        };
        if !probe.intent.matches(intent)
            || scope == 0
            || scope != self.scope_generation
            || self.actor.as_ref() != Some(&actor)
        {
            return false;
        }
        let ThreadRunAnchor::Channel { channel_id } = &intent.anchor else {
            return false;
        };
        let Ok(target_path) = crate::api::channel_route_href(channel_id.as_str()) else {
            return false;
        };
        let Some(charged_bytes) = handoff_budget(intent, &actor, &target_path) else {
            return false;
        };
        let Some(join) = SourceJoin::new(id.mount, id.token, scope, actor, intent) else {
            return false;
        };
        self.handoff = Some(NativeChannelHandoff {
            id,
            intent: probe.intent,
            target_path,
            join,
            phase: HandoffPhase::Staged,
            charged_bytes,
        });
        true
    }

    fn origin_ack(
        &mut self,
        id: ChannelHandoffToken,
        intent: &RunIntent,
        ack: &ThreadRunStarted,
    ) -> Option<ChannelHandoffToken> {
        let handoff = self.handoff.as_mut()?;
        if handoff.id != id
            || handoff.phase != HandoffPhase::Staged
            || handoff.join.scope_generation != self.scope_generation
            || self.actor.as_ref() != Some(&handoff.join.actor)
            || !handoff.intent.matches(intent)
            || !handoff.join.same_intent(intent)
        {
            return None;
        }
        handoff.join.observe_ack(ack);
        if handoff.join.invalid || handoff.join.ack.as_ref() != Some(ack) {
            return None;
        }
        handoff.phase = HandoffPhase::Ready;
        Some(id)
    }

    fn commit_handoff(&mut self, id: ChannelHandoffToken, target_path: &str) -> bool {
        let Some(handoff) = self.handoff.as_mut() else {
            return false;
        };
        if handoff.id != id
            || handoff.phase != HandoffPhase::Ready
            || handoff.target_path != target_path
            || handoff.join.scope_generation != self.scope_generation
            || self.actor.as_ref() != Some(&handoff.join.actor)
        {
            return false;
        }
        handoff.phase = HandoffPhase::Committed;
        true
    }

    fn target_matches(
        handoff: &NativeChannelHandoff,
        thread: &ThreadId,
        bot: &BotId,
        anchor: &ThreadRunAnchor,
    ) -> bool {
        handoff.join.thread == *thread
            && handoff.join.bot == *bot
            && handoff.join.anchor == *anchor
            && handoff.join.ack.is_some()
            && !handoff.join.invalid
    }

    fn has_handoff(&self, thread: &ThreadId, bot: &BotId, anchor: &ThreadRunAnchor) -> bool {
        self.handoff.as_ref().is_some_and(|handoff| {
            handoff.phase == HandoffPhase::Committed
                && handoff.join.scope_generation == self.scope_generation
                && self.actor.as_ref() == Some(&handoff.join.actor)
                && Self::target_matches(handoff, thread, bot, anchor)
        })
    }

    fn claim_handoff(
        &mut self,
        mount: u64,
        epoch: u64,
        thread: &ThreadId,
        bot: &BotId,
        anchor: &ThreadRunAnchor,
    ) -> Option<ReceiverClaim> {
        let reclaimable = self.handoff.as_ref().is_some_and(|handoff| {
            matches!(handoff.phase, HandoffPhase::Committed)
                || matches!(handoff.phase, HandoffPhase::Claimed(owner, _) if owner == mount)
        });
        let exact = self.handoff.as_ref().is_some_and(|handoff| {
            Self::target_matches(handoff, thread, bot, anchor)
                && handoff.join.scope_generation == self.scope_generation
                && self.actor.as_ref() == Some(&handoff.join.actor)
        });
        if mount == 0 || epoch == 0 || !reclaimable || !exact {
            return None;
        }
        let handoff = self.handoff.as_mut()?;
        handoff.phase = HandoffPhase::Claimed(mount, epoch);
        Some(ReceiverClaim {
            id: handoff.id,
            mount,
            epoch,
        })
    }

    fn adopt_handoff(
        &mut self,
        claim: ReceiverClaim,
        actor: &ActorObservation,
        thread: &ThreadId,
        bot: &BotId,
        anchor: &ThreadRunAnchor,
    ) -> Option<SourceJoin> {
        let valid = claim.mount != 0
            && claim.epoch != 0
            && self.handoff.as_ref().is_some_and(|handoff| {
                handoff.id == claim.id
                    && handoff.phase == HandoffPhase::Claimed(claim.mount, claim.epoch)
                    && handoff.join.scope_generation == self.scope_generation
                    && &handoff.join.actor == actor
                    && self.actor.as_ref() == Some(actor)
                    && Self::target_matches(handoff, thread, bot, anchor)
            });
        if !valid {
            self.cancel_claim(claim);
            return None;
        }
        let mut join = self.handoff.take()?.join;
        join.mount = claim.mount;
        join.epoch = claim.epoch;
        Some(join)
    }

    fn take_pending_handoff(
        &mut self,
        claim: ReceiverClaim,
        thread: &ThreadId,
        bot: &BotId,
        anchor: &ThreadRunAnchor,
    ) -> Option<SourceJoin> {
        let actor = self.actor.clone()?;
        let charge = self.handoff.as_ref()?.charged_bytes;
        let mut join = self.adopt_handoff(claim, &actor, thread, bot, anchor)?;
        join.target_fresh = false;
        join.pending_charge = Some(charge);
        Some(join)
    }

    fn cancel_target_probe(&mut self, pending: PendingTargetProbe) {
        if self.auth_probe == Some((pending.probe, pending.claim.mount)) {
            self.auth_probe = None;
        }
    }

    fn finish_target_probe(
        &mut self,
        pending: PendingTargetProbe,
        expected_actor: &ActorObservation,
        scope: u64,
        actor: Option<ActorObservation>,
    ) -> bool {
        if self.auth_probe != Some((pending.probe, pending.claim.mount))
            || self.scope_generation != scope
            || self.actor.as_ref() != Some(expected_actor)
        {
            return false;
        }
        self.finish_actor_probe(pending.probe, pending.claim.mount, actor)
    }

    fn cancel_claim(&mut self, claim: ReceiverClaim) {
        if self.handoff.as_ref().is_some_and(|handoff| {
            handoff.id == claim.id
                && handoff.phase == HandoffPhase::Claimed(claim.mount, claim.epoch)
        }) {
            self.handoff = None;
        }
    }

    fn cancel_handoff(&mut self, id: ChannelHandoffToken) {
        if self
            .origin_probe
            .as_ref()
            .is_some_and(|probe| probe.id == id)
        {
            self.origin_probe = None;
        }
        if self.auth_probe == Some((id.probe, id.mount)) {
            self.auth_probe = None;
        }
        if self
            .handoff
            .as_ref()
            .is_some_and(|handoff| handoff.id == id)
        {
            self.handoff = None;
        }
    }

    fn close_origin(&mut self, id: ChannelHandoffToken) {
        let transferred = self.handoff.as_ref().is_some_and(|handoff| {
            handoff.id == id
                && matches!(
                    handoff.phase,
                    HandoffPhase::Committed | HandoffPhase::Claimed(_, _)
                )
        });
        if !transferred {
            self.cancel_handoff(id);
        }
    }

    fn handoff_path_changed(&mut self, pathname: &str) {
        if pathname != "/channel/new"
            && let Some(id) = self.origin_probe.as_ref().map(|probe| probe.id)
        {
            self.cancel_handoff(id);
        }
        let invalid = self
            .handoff
            .as_ref()
            .is_some_and(|handoff| match handoff.phase {
                HandoffPhase::Staged | HandoffPhase::Ready => pathname != "/channel/new",
                HandoffPhase::Committed => {
                    pathname != "/channel/new" && pathname != handoff.target_path
                }
                HandoffPhase::Claimed(_, _) => pathname != handoff.target_path,
            });
        if invalid {
            self.handoff = None;
        }
    }
    // This is a local observation epoch, not a fabricated server/session authorization token.
    fn start_actor_probe(&mut self, mount: u64) -> Option<u64> {
        if mount == 0 {
            return None;
        }
        self.auth_read_generation = self.auth_read_generation.checked_add(1)?;
        self.auth_probe = Some((self.auth_read_generation, mount));
        Some(self.auth_read_generation)
    }

    fn finish_actor_probe(
        &mut self,
        generation: u64,
        mount: u64,
        actor: Option<ActorObservation>,
    ) -> bool {
        if self.auth_probe != Some((generation, mount)) {
            return false;
        }
        self.auth_probe = None;
        if self.actor != actor {
            let next = self.scope_generation.checked_add(1);
            self.scope_generation = next.unwrap_or(u64::MAX);
            self.actor = next.and(actor);
            self.handoff = None;
            self.checking = None;
            self.receipt_read = None;
            self.hide_metadata();
            if let Some(operation) = self.operation.as_mut()
                && operation.phase == SavePhase::Saving
            {
                operation.phase = SavePhase::Unknown;
            }
        }
        true
    }

    fn scope_current(&self, source: &UserSource) -> bool {
        self.scope_generation == source.scope_generation
            && self.actor.as_ref() == Some(&source.actor)
    }

    fn close_route(&mut self, mount: u64) {
        if self
            .receipt_read
            .as_ref()
            .is_some_and(|(_, operation)| operation.source.mount == mount)
        {
            self.receipt_read = None;
        }
        if self.auth_probe.is_some_and(|(_, owner)| owner == mount) {
            self.auth_probe = None;
        }
        if let Some(id) = self
            .origin_probe
            .as_ref()
            .filter(|probe| probe.id.mount == mount)
            .map(|probe| probe.id)
        {
            self.cancel_handoff(id);
        }
        let close_handoff = self.handoff.as_ref().is_some_and(|handoff| {
            matches!(handoff.phase, HandoffPhase::Claimed(owner, _) if owner == mount)
                || (handoff.id.mount == mount
                    && !matches!(
                        handoff.phase,
                        HandoffPhase::Committed | HandoffPhase::Claimed(_, _)
                    ))
        });
        if close_handoff {
            self.handoff = None;
        }
        if self.metadata_mount == Some(mount) {
            self.hide_metadata();
        }
    }

    fn may_check(&self, source: &UserSource) -> bool {
        self.scope_current(source)
            && self.checking.is_none()
            && self.operation.as_ref().is_none_or(|op| match op.phase {
                SavePhase::Saving | SavePhase::Unknown => false,
                SavePhase::NotSubmitted => op.source == *source,
                SavePhase::Registered(_) => !op.source.same_saved_source(source),
            })
    }

    fn check(&mut self, source: UserSource) -> Option<u64> {
        if !self.may_check(&source) {
            return None;
        }
        self.next_action = self.next_action.checked_add(1)?;
        self.checking = Some((self.next_action, source));
        Some(self.next_action)
    }

    fn start(
        &mut self,
        token: u64,
        source: &UserSource,
        mint: impl FnOnce() -> String,
    ) -> Option<Operation> {
        if !self.scope_current(source) || self.checking.as_ref() != Some(&(token, source.clone())) {
            return None;
        }
        let next_read = self.read_generation.checked_add(1)?;
        let old_packet = self.operation.as_ref().and_then(|op| {
            (op.source == *source && op.phase == SavePhase::NotSubmitted).then(|| op.packet.clone())
        });
        let packet = old_packet.unwrap_or_else(|| SaveRunMessageTextArtifact {
            request_id: mint(),
            source_thread_id: source.thread.clone(),
            source_run_id: source.run.clone(),
            source_message_id: source.message.clone(),
            expected_sha256: source.sha256.clone(),
        });
        self.checking = None;
        self.metadata = MetadataState::Idle;
        self.metadata_mount = None;
        self.read_generation = next_read;
        let operation = Operation {
            token,
            source: source.clone(),
            packet,
            phase: SavePhase::Saving,
        };
        self.operation = Some(operation.clone());
        Some(operation)
    }

    fn settle(&mut self, operation: &Operation, phase: SavePhase) {
        let phase = if phase != SavePhase::Unknown && !self.scope_current(&operation.source) {
            SavePhase::Unknown
        } else {
            phase
        };
        if let Some(current) = self.operation.as_mut()
            && current.token == operation.token
            && current.packet == operation.packet
            && current.source == operation.source
            && current.phase == SavePhase::Saving
        {
            current.phase = phase;
            self.metadata = MetadataState::Idle;
            self.metadata_mount = None;
        }
    }

    fn hide_metadata(&mut self) {
        // Overflow disables subsequent reads instead of recycling a stale generation.
        self.read_generation = self.read_generation.saturating_add(1);
        self.metadata = MetadataState::Idle;
        self.metadata_mount = None;
    }

    fn may_read_receipt(&self, operation: &Operation) -> bool {
        operation.phase == SavePhase::Unknown
            && operation.packet_matches_source()
            && self.scope_current(&operation.source)
            && self.operation.as_ref() == Some(operation)
            && self.checking.is_none()
            && self.receipt_read.is_none()
    }

    fn start_receipt_read(&mut self, operation: &Operation) -> Option<u64> {
        if !self.may_read_receipt(operation) {
            return None;
        }
        self.receipt_read_generation = self.receipt_read_generation.checked_add(1)?;
        self.receipt_read = Some((self.receipt_read_generation, operation.clone()));
        Some(self.receipt_read_generation)
    }

    fn finish_receipt_read(
        &mut self,
        operation: &Operation,
        generation: u64,
        receipt: Option<ArtifactRegistrationReceipt>,
    ) {
        if self.receipt_read.as_ref() != Some(&(generation, operation.clone())) {
            return;
        }
        self.receipt_read = None;
        if !self.scope_current(&operation.source)
            || self.operation.as_ref() != Some(operation)
            || operation.phase != SavePhase::Unknown
            || !operation.packet_matches_source()
        {
            return;
        }
        let Some(receipt) = receipt.filter(|receipt| {
            crate::api::artifacts::receipt_matches(
                receipt,
                &operation.packet,
                &operation.source.actor.actor,
            )
        }) else {
            return; // Missing/refused/invalid is still the same Unknown, never NotSubmitted.
        };
        if let Some(current) = self.operation.as_mut() {
            current.phase = SavePhase::Registered(receipt);
        }
        // This confirms only original registration. Metadata remains a separate explicit read.
        self.hide_metadata();
    }

    fn cancel_receipt_read(&mut self, generation: u64) {
        if self
            .receipt_read
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            self.receipt_read = None;
        }
    }

    fn start_read(&mut self, token: u64, mount: u64) -> Option<u64> {
        let operation = self.operation.as_ref()?;
        if mount == 0
            || !self.scope_current(&operation.source)
            || operation.token != token
            || !matches!(operation.phase, SavePhase::Registered(_))
            || matches!(
                self.metadata,
                MetadataState::Loading | MetadataState::Failed(MetadataError::Gone(_))
            )
        {
            return None;
        }
        self.read_generation = self.read_generation.checked_add(1)?;
        self.metadata = MetadataState::Loading;
        self.metadata_mount = Some(mount);
        Some(self.read_generation)
    }

    fn finish_read(
        &mut self,
        token: u64,
        generation: u64,
        result: Result<ArtifactMetadata, MetadataError>,
    ) {
        if self.read_generation == generation
            && self
                .operation
                .as_ref()
                .is_some_and(|op| op.token == token && matches!(op.phase, SavePhase::Registered(_)))
        {
            self.metadata = match result {
                Ok(metadata) => MetadataState::Loaded(Box::new(metadata)),
                Err(error) => MetadataState::Failed(error),
            };
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) struct ChannelOriginLease {
    actions: ArtifactActions,
    id: ChannelHandoffToken,
    owner: WeakOwner,
    captured: bool,
    ready: bool,
}

#[cfg(any(target_arch = "wasm32", test))]
impl ChannelOriginLease {
    pub(crate) fn capture(&mut self, intent: &RunIntent) {
        let live = self.owner.upgrade().is_some();
        self.captured = live
            && self
                .actions
                .state
                .try_update(|state| state.capture_origin(self.id, intent))
                .unwrap_or(false);
        let pending = live
            && self
                .actions
                .state
                .try_with_untracked(|state| state.origin_probe_pending(self.id, intent))
                .unwrap_or(false);
        if !self.captured && !pending {
            self.actions.cancel_channel_handoff(self.id);
        }
    }

    pub(crate) fn reply(
        &mut self,
        intent: &RunIntent,
        result: Result<&ThreadRunStarted, ()>,
    ) -> Option<ChannelHandoffToken> {
        drop(self.owner.upgrade()?);
        let Ok(ack) = result else {
            return None;
        };
        if !self.captured {
            // Recheck only the same original probe after the original Begin has returned.
            self.capture(intent);
        }
        if !self.captured {
            return None;
        }
        let accepted = self
            .actions
            .state
            .try_update(|state| state.origin_ack(self.id, intent, ack))
            .flatten();
        self.ready = accepted.is_some();
        accepted
    }
}

#[cfg(any(target_arch = "wasm32", test))]
impl Drop for ChannelOriginLease {
    fn drop(&mut self) {
        if !self.ready {
            self.actions.cancel_channel_handoff(self.id);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ArtifactActions {
    state: RwSignal<ActionState>,
}

impl ArtifactActions {
    pub(crate) fn new() -> Self {
        let actions = Self {
            state: RwSignal::new(ActionState::default()),
        };
        #[cfg(target_arch = "wasm32")]
        {
            let location = leptos_router::hooks::use_location();
            Effect::new(move |_| {
                let pathname = location.pathname.get();
                actions
                    .state
                    .try_update(|state| state.handoff_path_changed(&pathname));
            });
        }
        actions
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn start_channel_origin(
        self,
        run: &RunId,
        bot: &BotId,
        text: &str,
        skills: &[String],
        model: &Option<openbot_contracts::model_connections::RunModelSelection>,
    ) -> Option<ChannelOriginLease> {
        let owner = Owner::current()?.downgrade();
        let intent = OriginIntent::new(run, bot, text, skills, model)?;
        let id = self
            .state
            .try_update(|state| state.start_origin(intent.clone()))
            .flatten()?;
        on_cleanup(move || {
            self.state.try_update(|state| state.close_origin(id));
        });
        let probe_owner = owner.clone();
        // One optional read, parallel with the original Create. Begin never awaits this task.
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            let current = crate::api::load_current_user()
                .await
                .ok()
                .map(ActorObservation::from);
            if probe_owner.upgrade().is_none() {
                return;
            }
            self.state
                .try_update(|state| state.origin_reply(id, &intent, current));
        });
        Some(ChannelOriginLease {
            actions: self,
            id,
            owner,
            captured: false,
            ready: false,
        })
    }

    pub(crate) fn commit_channel_handoff(self, id: ChannelHandoffToken, target_path: &str) {
        let accepted = self
            .state
            .try_update(|state| state.commit_handoff(id, target_path))
            .unwrap_or(false);
        if !accepted {
            self.cancel_channel_handoff(id);
        }
    }

    pub(crate) fn cancel_channel_handoff(self, id: ChannelHandoffToken) {
        self.state.try_update(|state| state.cancel_handoff(id));
    }

    fn hide_metadata(self) {
        self.state.try_update(ActionState::hide_metadata);
    }

    fn close_route(self, mount: u64) {
        self.state.try_update(|state| state.close_route(mount));
    }

    fn scope_generation(self, actor: &ActorObservation) -> Option<u64> {
        self.state
            .try_with_untracked(|state| {
                (state.scope_generation != 0 && state.actor.as_ref() == Some(actor))
                    .then_some(state.scope_generation)
            })
            .flatten()
    }

    fn scope_current(self, source: &UserSource) -> bool {
        self.state
            .try_with_untracked(|state| state.scope_current(source))
            .unwrap_or(false)
    }

    fn has_unknown(self) -> bool {
        self.state.with(|state| {
            state
                .operation
                .as_ref()
                .is_some_and(|op| op.phase == SavePhase::Unknown)
        })
    }

    fn may_save(self, observer: ArtifactSourceObserver, source: &UserSource) -> bool {
        observer.selection_current(source) && self.state.with(|state| state.may_check(source))
    }

    fn may_check_receipt(self, observer: ArtifactSourceObserver, operation: &Operation) -> bool {
        observer.selection_current(&operation.source)
            && self.state.with(|state| state.may_read_receipt(operation))
    }

    fn receipt_reading(self, operation: &Operation) -> bool {
        self.state.with(|state| {
            state
                .receipt_read
                .as_ref()
                .is_some_and(|(_, current)| current == operation)
        })
    }

    fn read_disabled(self, mount: u64) -> bool {
        self.state.with(|state| {
            state.metadata_mount == Some(mount)
                && matches!(
                    state.metadata,
                    MetadataState::Loading | MetadataState::Failed(MetadataError::Gone(_))
                )
        })
    }

    fn visible_operation(self, source: ArtifactSourceObserver, message: &str) -> Option<Operation> {
        // Track actor/thread changes as well as the shared operation. The checks below remain local.
        source.state.with(|_| ());
        let _ = source.thread.get();
        let operation = self.state.with(|state| state.operation.clone());
        operation.filter(|op| op.source.message == message && source.view_current(&op.source))
    }

    fn save(self, observer: ArtifactSourceObserver, source: UserSource) {
        if !observer.selection_current(&source) {
            return;
        }
        let token = self
            .state
            .try_update(|state| state.check(source.clone()))
            .flatten();
        let Some(token) = token else {
            return;
        };
        let check = CheckTicket {
            actions: self,
            token,
        };
        #[cfg(target_arch = "wasm32")]
        observer.with_owner(move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let _check = check;
                // These reads only qualify this explicit click; neither read can resubmit Begin.
                let current = observer.refresh_actor().await;
                if current.as_ref().ok() != Some(&source.actor)
                    || !observer.selection_current(&source)
                {
                    self.hide_metadata();
                    observer.state.try_update(|state| state.eligible = None);
                    return;
                }
                let Ok(snapshot) = crate::api::load_thread_conversation(&source.thread).await
                else {
                    return;
                };
                if !observer.selection_current(&source)
                    || !source_matches_snapshot(&source, &snapshot)
                {
                    observer.state.try_update(|state| state.eligible = None);
                    return;
                }
                let operation = self
                    .state
                    .try_update(|state| {
                        state.start(token, &source, || uuid::Uuid::now_v7().to_string())
                    })
                    .flatten();
                let Some(operation) = operation else {
                    return;
                };
                let ticket = SaveTicket {
                    actions: self,
                    operation: operation.clone(),
                };
                let result =
                    crate::api::artifacts::save(&operation.packet, &source.actor.actor).await;
                match result {
                    Ok(receipt) => {
                        let current = observer.refresh_actor().await;
                        if observer.selection_current(&source)
                            && current.as_ref().ok() == Some(&source.actor)
                        {
                            ticket.settle(SavePhase::Registered(receipt));
                        } else {
                            self.hide_metadata();
                        }
                        // Otherwise Drop retains Unknown; the old ACK cannot populate another view.
                    }
                    Err(SaveError::NotSubmitted) => ticket.settle(SavePhase::NotSubmitted),
                    Err(SaveError::Unknown(_)) => ticket.settle(SavePhase::Unknown),
                }
            });
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = check;
    }

    fn check_receipt(self, observer: ArtifactSourceObserver, operation: Operation) {
        if !self.may_check_receipt(observer, &operation) {
            return;
        }
        let generation = self
            .state
            .try_update(|state| state.start_receipt_read(&operation))
            .flatten();
        let Some(generation) = generation else {
            return;
        };
        let ticket = ReceiptReadTicket {
            actions: self,
            operation: operation.clone(),
            generation,
        };
        #[cfg(target_arch = "wasm32")]
        observer.with_owner(move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let current = observer.refresh_actor().await;
                if current.as_ref().ok() != Some(&operation.source.actor)
                    || !observer.selection_current(&operation.source)
                {
                    return;
                }
                let Ok(snapshot) =
                    crate::api::load_thread_conversation(&operation.source.thread).await
                else {
                    return;
                };
                if !observer.selection_current(&operation.source)
                    || !source_matches_snapshot(&operation.source, &snapshot)
                {
                    return;
                }
                let result = crate::api::artifacts::save_receipt(
                    &operation.packet,
                    &operation.source.actor.actor,
                )
                .await;
                let Ok(receipt) = result else {
                    ticket.finish(None);
                    return;
                };
                let current = observer.refresh_actor().await;
                if current.as_ref().ok() != Some(&operation.source.actor)
                    || !observer.selection_current(&operation.source)
                {
                    return;
                }
                let Ok(snapshot) =
                    crate::api::load_thread_conversation(&operation.source.thread).await
                else {
                    return;
                };
                if !observer.selection_current(&operation.source)
                    || !source_matches_snapshot(&operation.source, &snapshot)
                {
                    return;
                }
                ticket.finish(Some(receipt));
            });
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = ticket;
    }

    fn read(self, observer: ArtifactSourceObserver, operation: Operation) {
        if !observer.view_current(&operation.source) {
            return;
        }
        let SavePhase::Registered(receipt) = operation.phase.clone() else {
            return;
        };
        let generation = self
            .state
            .try_update(|state| state.start_read(operation.token, observer.mount))
            .flatten();
        let Some(generation) = generation else {
            return;
        };
        let ticket = ReadTicket {
            actions: self,
            token: operation.token,
            generation,
        };
        #[cfg(target_arch = "wasm32")]
        observer.with_owner(move || {
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let current = observer.refresh_actor().await;
                if current.as_ref().ok() != Some(&operation.source.actor)
                    || !observer.view_current(&operation.source)
                {
                    ticket.finish(Err(current.err().unwrap_or(MetadataError::Unauthorized)));
                    return;
                };
                let result = crate::api::artifacts::metadata(
                    &receipt,
                    &operation.source.actor.actor,
                    &operation.source.anchor,
                )
                .await;
                let current = observer.refresh_actor().await;
                if !observer.view_current(&operation.source)
                    || current.as_ref().ok() != Some(&operation.source.actor)
                {
                    ticket.finish(Err(current.err().unwrap_or(MetadataError::Unauthorized)));
                    return;
                }
                ticket.finish(result);
            });
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (receipt, ticket);
    }
}

#[cfg(target_arch = "wasm32")]
fn actor_read_error(error: crate::api::ApiError) -> MetadataError {
    match error {
        crate::api::ApiError::Unauthorized => MetadataError::Unauthorized,
        crate::api::ApiError::Forbidden | crate::api::ApiError::NotFound => MetadataError::NotFound,
        crate::api::ApiError::InvalidResponse => MetadataError::InvalidResponse,
        _ => MetadataError::Unavailable,
    }
}

struct QualificationTicket {
    state: RwSignal<SourceState>,
}

impl Drop for QualificationTicket {
    fn drop(&mut self) {
        self.state.try_update(|state| state.qualifying = false);
    }
}

struct CheckTicket {
    actions: ArtifactActions,
    token: u64,
}

impl Drop for CheckTicket {
    fn drop(&mut self) {
        self.actions.state.try_update(|state| {
            if state
                .checking
                .as_ref()
                .is_some_and(|(token, _)| *token == self.token)
            {
                state.checking = None;
            }
        });
    }
}

struct SaveTicket {
    actions: ArtifactActions,
    operation: Operation,
}

impl SaveTicket {
    fn settle(&self, phase: SavePhase) {
        self.actions
            .state
            .try_update(|state| state.settle(&self.operation, phase));
    }
}

impl Drop for SaveTicket {
    fn drop(&mut self) {
        self.settle(SavePhase::Unknown);
    }
}

struct ReceiptReadTicket {
    actions: ArtifactActions,
    operation: Operation,
    generation: u64,
}

impl ReceiptReadTicket {
    fn finish(&self, receipt: Option<ArtifactRegistrationReceipt>) {
        self.actions.state.try_update(|state| {
            state.finish_receipt_read(&self.operation, self.generation, receipt);
        });
    }
}

impl Drop for ReceiptReadTicket {
    fn drop(&mut self) {
        self.actions
            .state
            .try_update(|state| state.cancel_receipt_read(self.generation));
    }
}

struct ReadTicket {
    actions: ArtifactActions,
    token: u64,
    generation: u64,
}

impl ReadTicket {
    fn finish(&self, result: Result<ArtifactMetadata, MetadataError>) {
        self.actions.state.try_update(|state| {
            state.finish_read(self.token, self.generation, result);
        });
    }
}

impl Drop for ReadTicket {
    fn drop(&mut self) {
        self.actions.state.try_update(|state| {
            if state.metadata == MetadataState::Loading {
                state.finish_read(self.token, self.generation, Err(MetadataError::Unavailable));
            }
        });
    }
}

#[component]
pub(crate) fn ArtifactUnknownNotice() -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ArtifactActions>();
    view! {
        <Show when=move || actions.has_unknown()>
            <p class="ob-alert" role="status" data-artifact-save-unknown="">
                {move || t!(i18n, artifacts.unknown)}
            </p>
        </Show>
    }
}

#[component]
pub(crate) fn ArtifactMessageActions(
    message_id: String,
    source: ArtifactSourceObserver,
) -> impl IntoView {
    let i18n = use_i18n();
    let actions = expect_context::<ArtifactActions>();
    let message = StoredValue::new(message_id);
    let eligible = Memo::new(move |_| source.selection(&message.get_value()));
    let operation = Memo::new(move |_| actions.visible_operation(source, &message.get_value()));
    let disabled = Signal::derive(move || {
        eligible
            .get()
            .is_none_or(|selection| !actions.may_save(source, &selection))
    });
    let save = move |_| {
        if let Some(source_selection) = eligible.get_untracked() {
            actions.save(source, source_selection);
        }
    };
    let read = move |_| {
        if let Some(operation) = operation.get_untracked() {
            actions.read(source, operation);
        }
    };
    let check_receipt = move |_| {
        if let Some(operation) = operation.get_untracked() {
            actions.check_receipt(source, operation);
        }
    };
    let receipt_disabled = Signal::derive(move || {
        operation
            .get()
            .is_none_or(|operation| !actions.may_check_receipt(source, &operation))
    });
    let receipt_reading = Signal::derive(move || {
        operation
            .get()
            .is_some_and(|operation| actions.receipt_reading(&operation))
    });
    let phase = Memo::new(move |_| operation.get().map(|op| op.phase));
    view! {
        <div data-artifact-message-actions="">
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=disabled on_activate=save>
                {move || t!(i18n, artifacts.save)}
            </Button>
            <Show when=move || eligible.get().is_none() && operation.get().is_none()>
                <span class="ob-tool-source">{move || t!(i18n, artifacts.source_unavailable)}</span>
            </Show>
            <Show when=move || phase.get() == Some(SavePhase::Saving)>
                <span role="status">{move || t!(i18n, artifacts.saving)}</span>
            </Show>
            <Show when=move || phase.get() == Some(SavePhase::NotSubmitted)>
                <span class="ob-alert" role="status">{move || t!(i18n, artifacts.not_submitted)}</span>
            </Show>
            <Show when=move || phase.get() == Some(SavePhase::Unknown)>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=receipt_disabled on_activate=check_receipt>
                    {move || t!(i18n, artifacts.check_result)}
                </Button>
                <Show when=move || receipt_reading.get()>
                    <span role="status">{move || t!(i18n, artifacts.checking_result)}</span>
                </Show>
            </Show>
            <Show when=move || phase.get().is_some_and(|phase| matches!(phase, SavePhase::Registered(_)))>
                <section class="ob-tool-card" aria-label=move || crate::i18n::t_string!(i18n, artifacts.title).to_owned()>
                    <p role="status">{move || t!(i18n, artifacts.registered)}</p>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small disabled=Signal::derive(move || actions.read_disabled(source.mount)) on_activate=read>
                        {move || t!(i18n, artifacts.refresh)}
                    </Button>
                    <ArtifactMetadataView actions mount=source.mount/>
                </section>
            </Show>
        </div>
    }
}

#[component]
fn ArtifactMetadataView(actions: ArtifactActions, mount: u64) -> impl IntoView {
    let i18n = use_i18n();
    let state = Memo::new(move |_| {
        actions.state.with(|state| {
            if state.metadata_mount == Some(mount) {
                state.metadata.clone()
            } else {
                MetadataState::Idle
            }
        })
    });
    view! {
        <Show when=move || state.get() == MetadataState::Loading>
            <p role="status">{move || t!(i18n, artifacts.loading)}</p>
        </Show>
        {move || match state.get() {
            MetadataState::Loaded(metadata) => {
                let (record, partial) = match *metadata {
                    ArtifactMetadata::Available(record) => (record, false),
                    ArtifactMetadata::FailedPartial(record) => (record, true),
                    // The API rejects these200 shapes. Keep the view closed as well.
                    ArtifactMetadata::Deleted(_) | ArtifactMetadata::Expired(_) => return ().into_any(),
                };
                view! {
                    <details open>
                        <summary>{move || t!(i18n, artifacts.details)}</summary>
                        <p>{move || if partial { t!(i18n, artifacts.failed_partial).into_any() } else { t!(i18n, artifacts.available).into_any() }}</p>
                        <dl>
                            <dt>{move || t!(i18n, artifacts.identifier)}</dt><dd><code>{record.artifact_id}</code></dd>
                            <dt>{move || t!(i18n, artifacts.media_type)}</dt><dd>{record.media_type}</dd>
                            <dt>{move || t!(i18n, artifacts.size)}</dt><dd>{record.byte_length.to_string()}</dd>
                            <dt>{move || t!(i18n, artifacts.digest)}</dt><dd><code>{record.sha256}</code></dd>
                            <dt>{move || t!(i18n, artifacts.source_thread)}</dt><dd><code>{record.source_thread_id.as_str().to_owned()}</code></dd>
                            <dt>{move || t!(i18n, artifacts.source_run)}</dt><dd><code>{record.source_run_id.as_str().to_owned()}</code></dd>
                        </dl>
                        <p class="ob-tool-source">{move || t!(i18n, artifacts.retention)}</p>
                        <p class="ob-tool-source">{move || t!(i18n, artifacts.limits)}</p>
                    </details>
                }.into_any()
            }
            MetadataState::Failed(error) => view! {
                <p class="ob-alert" role="status">{move || match error {
                    MetadataError::Unauthorized => t!(i18n, artifacts.unauthorized).into_any(),
                    MetadataError::Forbidden | MetadataError::NotFound => t!(i18n, artifacts.not_visible).into_any(),
                    MetadataError::Gone(ArtifactGoneStatus::Deleted) => t!(i18n, artifacts.deleted).into_any(),
                    MetadataError::Gone(ArtifactGoneStatus::Expired) => t!(i18n, artifacts.expired).into_any(),
                    MetadataError::Unavailable => t!(i18n, artifacts.unavailable).into_any(),
                    MetadataError::InvalidResponse => t!(i18n, artifacts.invalid_response).into_any(),
                }}</p>
            }.into_any(),
            MetadataState::Idle | MetadataState::Loading => ().into_any(),
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const REQUEST: &str = "019a7778-abcd-7abc-8abc-0123456789ab";

    fn intent() -> RunIntent {
        RunIntent {
            thread_id: Some(ThreadId::new("019a7778-abcd-8abc-8abc-0123456789ab")),
            run_id: RunId::new("opaque run"),
            agent_id: BotId::new("bot"),
            anchor: ThreadRunAnchor::DirectBot,
            message: " 你好\n".into(),
            selected_skill_slugs: Vec::new(),
            model_selection: None,
            model_selection_v2: None,
        }
    }

    fn join() -> SourceJoin {
        SourceJoin::new(
            1,
            1,
            1,
            ActorObservation {
                actor: ActorId::new("actor"),
                role: Role::User,
            },
            &intent(),
        )
        .unwrap()
    }

    fn ack() -> ThreadRunStarted {
        ThreadRunStarted {
            thread_id: intent().thread_id.unwrap(),
            run_id: intent().run_id,
            message_sequence: 3,
            event_sequence: 7,
            replayed: false,
        }
    }

    fn started() -> ThreadRunEvent {
        ThreadRunEvent {
            thread_id: ack().thread_id,
            run_id: ack().run_id,
            event_sequence: 7,
            event_type: ThreadRunEventKind::Started,
            payload: serde_json::json!({"runId":"opaque run","messageId":"exact-message","botId":"bot"}),
            terminal: false,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn read() -> SourceRead {
        let mut join = join();
        join.observe_ack(&ack());
        join.observe_started(&started());
        join.take_read().unwrap()
    }

    fn snapshot() -> ThreadConversationSnapshot {
        ThreadConversationSnapshot {
            messages: vec![openbot_contracts::command::ThreadHistoryMessage {
                id: "exact-message".into(),
                role: ThreadHistoryRole::User,
                content: intent().message,
                selected_skill_slugs: Vec::new(),
                agent_id: Some(BotId::new("bot")),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            }],
            last_event_sequence: Some(7),
            ..Default::default()
        }
    }

    fn operation(state: &mut ActionState, source: UserSource) -> Operation {
        if state.actor.is_none() {
            state.actor = Some(source.actor.clone());
            state.scope_generation = source.scope_generation;
        }
        let token = state.check(source.clone()).unwrap();
        state.start(token, &source, || REQUEST.into()).unwrap()
    }

    fn receipt(operation: &Operation) -> ArtifactRegistrationReceipt {
        ArtifactRegistrationReceipt {
            operation_id: "019a7778-abcd-7abc-8abc-0123456789ad".into(),
            artifact_id: "019a7778-abcd-7abc-8abc-0123456789ac".into(),
            request_id: operation.packet.request_id.clone(),
            owner_actor_id: operation.source.actor.actor.clone(),
            source_thread_id: operation.source.thread.clone(),
            source_run_id: operation.source.run.clone(),
            source_message_id: operation.source.message.clone(),
            source_call_seq: None,
            source_attempt_seq: None,
        }
    }

    #[test]
    fn begin_and_started_join_in_both_orders_once_and_keep_exact_utf8() {
        for started_first in [true, false] {
            let mut join = join();
            if started_first {
                join.observe_started(&started());
                assert!(join.take_read().is_none());
                join.observe_ack(&ack());
            } else {
                join.observe_ack(&ack());
                assert!(join.take_read().is_none());
                join.observe_started(&started());
            }
            let read = join.take_read().unwrap();
            assert!(source_read_matches(&read, &snapshot()));
            assert_eq!(read.source.sha256, text_digest(" 你好\n"));
            assert_ne!(read.source.sha256, text_digest("你好"));
            assert!(join.take_read().is_none());
        }
    }

    #[test]
    fn first_turn_zero_cursors_join_both_orders_and_keep_current_user_packet() {
        let mut first_ack = ack();
        first_ack.message_sequence = 0;
        first_ack.event_sequence = 0;
        let mut first_started = started();
        first_started.event_sequence = 0;
        first_started.payload["messageId"] = serde_json::json!("opaque run:input");
        let mut current = snapshot();
        current.messages[0].id = "opaque run:input".into();
        current.last_event_sequence = Some(0);

        for started_first in [true, false] {
            let mut join = join();
            if started_first {
                join.observe_started(&first_started);
                assert!(join.take_read().is_none());
                join.observe_ack(&first_ack);
            } else {
                join.observe_ack(&first_ack);
                assert!(join.take_read().is_none());
                join.observe_started(&first_started);
            }
            let read = join.take_read().unwrap();
            assert_eq!(read.original_text.as_bytes(), " 你好\n".as_bytes());
            assert!(source_read_matches(&read, &current));
            for change in 0..3 {
                let mut invalid = current.clone();
                match change {
                    0 => invalid.last_event_sequence = None,
                    1 => invalid.messages.push(invalid.messages[0].clone()),
                    _ => invalid.messages[0].content = "你好".into(),
                }
                assert!(!source_read_matches(&read, &invalid));
            }
            let mut state = ActionState::default();
            let saved = operation(&mut state, read.source);
            assert_eq!(
                serde_json::to_value(&saved.packet).unwrap(),
                serde_json::json!({
                    "requestId": REQUEST,
                    "sourceThreadId": "019a7778-abcd-8abc-8abc-0123456789ab",
                    "sourceRunId": "opaque run",
                    "sourceMessageId": "opaque run:input",
                    "expectedSha256": "e43dbe3a548f25dabf4b87968b82735de6cfaf353d6bdd1b9690cc76de5dd209"
                })
            );
            assert!(join.take_read().is_none());
        }
        for change in 0..3 {
            let mut join = join();
            let mut mismatched_ack = first_ack.clone();
            let mut mismatched_started = first_started.clone();
            match change {
                0 => mismatched_started.event_sequence = 1,
                1 => mismatched_ack.run_id = RunId::new("foreign"),
                _ => mismatched_started.payload["botId"] = serde_json::json!("foreign"),
            }
            join.observe_ack(&mismatched_ack);
            join.observe_started(&mismatched_started);
            assert!(join.take_read().is_none());
        }
    }

    #[test]
    fn started_requires_exact_envelope_run_bot_message_and_three_keys() {
        for field in ["runId", "botId", "messageId", "extra"] {
            let mut join = join();
            let mut event = started();
            event.payload[field] =
                serde_json::json!(if field == "messageId" { "" } else { "foreign" });
            join.observe_started(&event);
            join.observe_ack(&ack());
            assert!(join.take_read().is_none(), "{field}");
        }
        for change in 0..4 {
            let mut join = join();
            let mut event = started();
            match change {
                0 => event.run_id = RunId::new("foreign"),
                1 => event.thread_id = ThreadId::new("foreign"),
                2 => event.event_sequence += 1,
                _ => event.terminal = true,
            }
            join.observe_started(&event);
            join.observe_ack(&ack());
            assert!(join.take_read().is_none());
        }
    }

    #[test]
    fn fresh_source_is_unique_user_with_original_text_and_bot_not_last_run() {
        let read = read();
        for change in 0..6 {
            let mut snapshot = snapshot();
            match change {
                0 => snapshot.messages.clear(),
                1 => snapshot.messages.push(snapshot.messages[0].clone()),
                2 => snapshot.messages[0].role = ThreadHistoryRole::Assistant,
                3 => snapshot.messages[0].content = "你好".into(),
                4 => snapshot.messages[0].agent_id = None,
                _ => snapshot.last_event_sequence = Some(6),
            }
            assert!(!source_read_matches(&read, &snapshot));
        }
        let mut original = intent();
        original.message = "x".repeat(MAX_THREAD_MESSAGE_BYTES + 1);
        assert!(SourceJoin::new(1, 1, 1, read.source.actor, &original).is_none());
    }

    fn unknown_operation(state: &mut ActionState) -> Operation {
        let operation = operation(state, read().source);
        state.settle(&operation, SavePhase::Unknown);
        state.operation.as_ref().unwrap().clone()
    }

    #[test]
    fn explicit_receipt_read_keeps_unknown_until_exact_positive_and_never_resaves() {
        let mut state = ActionState::default();
        let original = unknown_operation(&mut state);
        let generation = state.start_receipt_read(&original).unwrap();
        assert_eq!(state.operation.as_ref(), Some(&original));
        assert!(state.start_receipt_read(&original).is_none());
        assert!(state.check(original.source.clone()).is_none());
        assert!(
            state
                .start_read(original.token, original.source.mount)
                .is_none()
        );
        state.finish_receipt_read(&original, generation, Some(receipt(&original)));
        let current = state.operation.as_ref().unwrap();
        assert_eq!(current.packet, original.packet);
        assert_eq!(current.source, original.source);
        assert_eq!(current.phase, SavePhase::Registered(receipt(&original)));
        assert_eq!(state.metadata, MetadataState::Idle);
        assert!(state.metadata_mount.is_none());
        assert!(state.check(original.source.clone()).is_none());
        assert!(state.start_receipt_read(&original).is_none());
    }

    #[test]
    fn receipt_read_absence_timeout_and_cancel_preserve_original_unknown_and_locator() {
        for cancelled in [false, true] {
            let mut state = ActionState::default();
            let original = unknown_operation(&mut state);
            let generation = state.start_receipt_read(&original).unwrap();
            if cancelled {
                state.cancel_receipt_read(generation);
            } else {
                state.finish_receipt_read(&original, generation, None);
            }
            assert_eq!(state.operation.as_ref(), Some(&original));
            assert!(state.receipt_read.is_none());
            assert!(state.check(original.source.clone()).is_none());
            assert!(
                state
                    .start_read(original.token, original.source.mount)
                    .is_none()
            );
            assert!(state.start_receipt_read(&original).is_some());
        }
    }

    #[test]
    fn late_receipt_cannot_cross_route_close_or_replace_a_newer_explicit_read() {
        let mut state = ActionState::default();
        let original = unknown_operation(&mut state);
        let old = state.start_receipt_read(&original).unwrap();
        state.close_route(original.source.mount);
        state.finish_receipt_read(&original, old, Some(receipt(&original)));
        assert_eq!(state.operation.as_ref(), Some(&original));
        let current = state.start_receipt_read(&original).unwrap();
        state.finish_receipt_read(&original, old, Some(receipt(&original)));
        assert_eq!(state.receipt_read, Some((current, original.clone())));
        assert_eq!(state.operation.as_ref(), Some(&original));
        state.finish_receipt_read(&original, current, Some(receipt(&original)));
        assert!(matches!(
            state.operation.as_ref().unwrap().phase,
            SavePhase::Registered(_)
        ));
    }

    #[test]
    fn actor_scope_change_during_receipt_get_cannot_promote_original_unknown() {
        let mut state = ActionState::default();
        let original = unknown_operation(&mut state);
        let generation = state.start_receipt_read(&original).unwrap();
        let probe = state.start_actor_probe(original.source.mount).unwrap();
        let mut other = original.source.actor.clone();
        other.actor = ActorId::new("other");
        assert!(state.finish_actor_probe(probe, original.source.mount, Some(other)));
        state.finish_receipt_read(&original, generation, Some(receipt(&original)));
        assert_eq!(state.operation.as_ref(), Some(&original));
        let probe = state.start_actor_probe(original.source.mount).unwrap();
        assert!(state.finish_actor_probe(
            probe,
            original.source.mount,
            Some(original.source.actor.clone())
        ));
        assert!(state.start_receipt_read(&original).is_none());
        assert_eq!(state.operation.as_ref(), Some(&original));
    }

    #[test]
    fn receipt_read_rejects_corrupted_original_packet_and_every_foreign_positive_identity() {
        for change in 0..4 {
            let mut state = ActionState::default();
            let mut original = unknown_operation(&mut state);
            match change {
                0 => original.packet.source_thread_id = ThreadId::new("other"),
                1 => original.packet.source_run_id = RunId::new("other"),
                2 => original.packet.source_message_id = "other".into(),
                _ => original.packet.expected_sha256 = "0".repeat(64),
            }
            state.operation = Some(original.clone());
            assert!(state.start_receipt_read(&original).is_none());
        }
        for change in 0..9 {
            let mut state = ActionState::default();
            let original = unknown_operation(&mut state);
            let generation = state.start_receipt_read(&original).unwrap();
            let mut foreign = receipt(&original);
            match change {
                0 => foreign.operation_id = "not-uuid".into(),
                1 => foreign.artifact_id = "not-uuid".into(),
                2 => foreign.request_id = "019a7778-abcd-7abc-8abc-0123456789af".into(),
                3 => foreign.owner_actor_id = ActorId::new("other"),
                4 => foreign.source_thread_id = ThreadId::new("other"),
                5 => foreign.source_run_id = RunId::new("other"),
                6 => foreign.source_message_id = "other".into(),
                7 => foreign.source_call_seq = Some(1),
                _ => foreign.source_attempt_seq = Some(1),
            }
            state.finish_receipt_read(&original, generation, Some(foreign));
            assert_eq!(state.operation.as_ref(), Some(&original));
            assert!(state.receipt_read.is_none());
            assert!(state.check(original.source.clone()).is_none());
        }
    }

    #[test]
    fn receipt_check_requires_original_view_epoch_mount_thread_and_live_owner() {
        let root = Owner::new();
        let (actions, route, observer) = direct_replay_observer(&root);
        let source = read().source;
        observer.state.update(|state| {
            state.eligible = Some(source.clone());
            state.epoch = source.epoch;
        });
        actions.state.update(|state| {
            let saving = operation(state, source.clone());
            state.settle(&saving, SavePhase::Unknown);
        });
        let original = actions.state.with(|state| state.operation.clone()).unwrap();
        assert!(actions.may_check_receipt(observer, &original));
        observer.state.update(|state| state.epoch += 1);
        assert!(!actions.may_check_receipt(observer, &original));
        observer.state.update(|state| state.epoch = source.epoch);
        observer.thread.set(Some(ThreadId::new("other")));
        assert!(!actions.may_check_receipt(observer, &original));
        observer.thread.set(Some(source.thread.clone()));
        let mut remounted = original.clone();
        remounted.source.mount += 1;
        assert!(!actions.may_check_receipt(observer, &remounted));
        drop(route);
        assert!(!actions.may_check_receipt(observer, &original));
        assert_eq!(
            actions.state.with(|state| state.operation.clone()),
            Some(original)
        );
    }

    #[test]
    fn checking_and_unknown_never_mint_a_second_packet() {
        let source = read().source;
        let mut state = ActionState {
            actor: Some(source.actor.clone()),
            scope_generation: source.scope_generation,
            ..Default::default()
        };
        let token = state.check(source.clone()).unwrap();
        assert!(state.check(source.clone()).is_none());
        let minted = Cell::new(0);
        let operation = state
            .start(token, &source, || {
                minted.set(minted.get() + 1);
                REQUEST.into()
            })
            .unwrap();
        state.settle(&operation, SavePhase::Unknown);
        assert!(state.check(source.clone()).is_none());
        assert!(
            state
                .start(token, &source, || panic!("must not mint"))
                .is_none()
        );
        state.hide_metadata();
        assert_eq!(state.operation.as_ref().unwrap().packet, operation.packet);
        assert_eq!(state.operation.as_ref().unwrap().phase, SavePhase::Unknown);
        assert_eq!(minted.get(), 1);
    }

    #[test]
    fn before_dispatch_failure_can_reuse_only_the_same_frozen_packet() {
        let source = read().source;
        let mut state = ActionState::default();
        let old = operation(&mut state, source.clone());
        state.settle(&old, SavePhase::NotSubmitted);
        let token = state.check(source.clone()).unwrap();
        let retried = state
            .start(token, &source, || panic!("reuse original request"))
            .unwrap();
        assert_eq!(retried.packet, old.packet);
        let mut other = source;
        other.run = RunId::new("other");
        assert!(state.check(other).is_none());
    }

    #[test]
    fn dropped_save_ticket_preserves_unknown_after_route_cleanup() {
        let root = Owner::new();
        let actions = root.with(ArtifactActions::new);
        let original = actions
            .state
            .try_update(|state| operation(state, read().source))
            .unwrap();
        let ticket = SaveTicket {
            actions,
            operation: original.clone(),
        };
        actions.hide_metadata();
        drop(ticket);
        assert_eq!(
            actions
                .state
                .with_untracked(|state| state.operation.as_ref().unwrap().phase.clone()),
            SavePhase::Unknown
        );
        root.cleanup();
        Owner::new().with(|| {
            let replacement = ArtifactActions::new();
            SaveTicket {
                actions,
                operation: original.clone(),
            }
            .settle(SavePhase::Registered(receipt(&original)));
            assert!(
                replacement
                    .state
                    .with_untracked(|state| state.operation.is_none())
            );
        });
    }

    #[test]
    fn metadata_generations_and_errors_preserve_ack_and_never_change_packet() {
        let mut state = ActionState::default();
        let operation = operation(&mut state, read().source);
        state.settle(&operation, SavePhase::Registered(receipt(&operation)));
        let first = state.start_read(operation.token, 1).unwrap();
        assert!(state.start_read(operation.token, 1).is_none());
        state.close_route(1);
        let latest = state.start_read(operation.token, 2).unwrap();
        state.close_route(1);
        assert_eq!(state.metadata, MetadataState::Loading);
        state.finish_read(operation.token, first, Err(MetadataError::NotFound));
        assert_eq!(state.metadata, MetadataState::Loading);
        state.finish_read(
            operation.token,
            latest,
            Err(MetadataError::Gone(ArtifactGoneStatus::Expired)),
        );
        assert_eq!(
            state.metadata,
            MetadataState::Failed(MetadataError::Gone(ArtifactGoneStatus::Expired))
        );
        assert!(state.start_read(operation.token, 2).is_none());
        state.hide_metadata();
        state.finish_read(operation.token, latest, Err(MetadataError::Unauthorized));
        assert_eq!(state.metadata, MetadataState::Idle);
        assert_eq!(state.operation.as_ref().unwrap().packet, operation.packet);
        assert!(matches!(
            state.operation.as_ref().unwrap().phase,
            SavePhase::Registered(_)
        ));
    }

    #[test]
    fn newer_actor_probe_and_route_owner_reject_old_role_observations() {
        let source = read().source;
        let mut state = ActionState::default();
        let old = state.start_actor_probe(1).unwrap();
        let current = state.start_actor_probe(2).unwrap();
        state.close_route(1);
        assert!(state.finish_actor_probe(current, 2, Some(source.actor.clone())));
        assert!(!state.finish_actor_probe(old, 1, None));
        assert!(state.scope_current(&source));
        let saving = operation(&mut state, source.clone());
        let changed = state.start_actor_probe(2).unwrap();
        let mut admin = source.actor.clone();
        admin.role = Role::Admin;
        assert!(state.finish_actor_probe(changed, 2, Some(admin)));
        assert!(!state.scope_current(&source));
        assert_eq!(state.operation.as_ref().unwrap().phase, SavePhase::Unknown);
        state.settle(&saving, SavePhase::Registered(receipt(&saving)));
        let returned = state.start_actor_probe(3).unwrap();
        assert!(state.finish_actor_probe(returned, 3, Some(source.actor.clone())));
        assert!(!state.scope_current(&source));
        assert!(state.check(source).is_none());
        assert_eq!(state.operation.as_ref().unwrap().packet, saving.packet);
        assert_eq!(state.operation.as_ref().unwrap().phase, SavePhase::Unknown);
    }

    fn direct_replay_observer(root: &Owner) -> (ArtifactActions, Owner, ArtifactSourceObserver) {
        let actions = root.with(|| {
            let actions = ArtifactActions::new();
            provide_context(actions);
            actions
        });
        let route = root.with(Owner::new);
        let observer = route.with(|| {
            ArtifactSourceObserver::new(
                RwSignal::new(intent().thread_id),
                StoredValue::new(Some(intent().agent_id)),
                StoredValue::new(intent().anchor),
            )
        });
        let actor = read().source.actor;
        actions.state.update(|state| {
            let probe = state.start_actor_probe(observer.mount).unwrap();
            assert!(state.finish_actor_probe(probe, observer.mount, Some(actor.clone())));
        });
        observer.state.update(|state| state.actor = Some(actor));
        observer.stage_begin(&intent());
        (actions, route, observer)
    }

    #[test]
    fn direct_first_turn_pending_ack_replays_zero_and_keeps_source_read_gated() {
        let root = Owner::new();
        let (actions, _route, observer) = direct_replay_observer(&root);
        let mut current = snapshot();
        current.last_event_sequence = Some(0);
        let original_snapshot = serde_json::to_vec(&current).unwrap();
        assert_eq!(
            observer.bootstrap_cursor(current.last_event_sequence),
            Some(0)
        );
        assert!(observer.state.with_untracked(|state| {
            state.join.as_ref().unwrap().ack.is_none() && state.eligible.is_none()
        }));
        let mut first_ack = ack();
        first_ack.message_sequence = 0;
        first_ack.event_sequence = 0;
        observer.begin_reply(&intent().run_id, Ok(&first_ack));
        assert_eq!(observer.bootstrap_cursor(current.last_event_sequence), None);
        assert_eq!(serde_json::to_vec(&current).unwrap(), original_snapshot);
        assert!(
            observer
                .state
                .try_update(|state| { state.join.as_mut().unwrap().take_read().is_none() })
                .unwrap()
        );
        assert!(observer.selection("exact-message").is_none());
        assert!(!actions.may_save(observer, &read().source));
        let mut first_started = started();
        first_started.event_sequence = 0;
        let raw = observer
            .state
            .try_update(|state| {
                let join = state.join.as_mut().unwrap();
                join.observe_started(&first_started);
                join.take_read().unwrap()
            })
            .unwrap();
        assert_eq!(raw.source.started_sequence, 0);
        assert_eq!(raw.original_text.as_str(), intent().message);
        assert_eq!(raw.source.sha256, text_digest(&intent().message));
        assert!(source_read_matches(&raw, &current));
        let mut duplicate = current.clone();
        duplicate.messages.push(current.messages[0].clone());
        assert!(!source_read_matches(&raw, &duplicate));
        let mut altered = current.clone();
        altered.messages[0].content.push(' ');
        assert!(!source_read_matches(&raw, &altered));
        assert_eq!(
            observer.bootstrap_cursor(current.last_event_sequence),
            Some(0)
        );
        assert!(observer.selection("exact-message").is_none());
        assert!(!actions.may_save(observer, &raw.source));
        assert!(
            actions
                .state
                .with_untracked(|state| state.operation.is_none())
        );
    }

    #[test]
    fn direct_pending_replay_requires_current_actor_scope_epoch_and_exact_route() {
        for invalid in [
            "failed-ack",
            "wrong-thread-ack",
            "wrong-run-ack",
            "actor",
            "role",
            "scope",
            "epoch",
            "thread",
            "bot",
            "anchor",
            "mount",
            "handoff-epoch",
            "older-read",
        ] {
            let root = Owner::new();
            let (actions, _route, observer) = direct_replay_observer(&root);
            let mut first_ack = ack();
            first_ack.message_sequence = 0;
            first_ack.event_sequence = 0;
            observer.begin_reply(&intent().run_id, Ok(&first_ack));
            assert_eq!(observer.bootstrap_cursor(Some(0)), None, "{invalid}");
            match invalid {
                "failed-ack" => observer.begin_reply(&intent().run_id, Err(())),
                "wrong-thread-ack" => {
                    first_ack.thread_id = ThreadId::new("other-thread");
                    observer.begin_reply(&intent().run_id, Ok(&first_ack));
                }
                "wrong-run-ack" => {
                    first_ack.run_id = RunId::new("other-run");
                    observer.begin_reply(&intent().run_id, Ok(&first_ack));
                }
                "actor" => observer.state.update(|state| {
                    state.actor.as_mut().unwrap().actor = ActorId::new("other-actor");
                }),
                "role" => observer.state.update(|state| {
                    state.actor.as_mut().unwrap().role = Role::Admin;
                }),
                "scope" => actions.state.update(|state| {
                    let actor = state.actor.clone().unwrap();
                    let mut admin = actor.clone();
                    admin.role = Role::Admin;
                    let probe = state.start_actor_probe(observer.mount).unwrap();
                    assert!(state.finish_actor_probe(probe, observer.mount, Some(admin)));
                    let probe = state.start_actor_probe(observer.mount).unwrap();
                    assert!(state.finish_actor_probe(probe, observer.mount, Some(actor)));
                }),
                "epoch" => observer.state.update(|state| {
                    state.epoch = state.epoch.checked_add(1).unwrap();
                }),
                "thread" => observer.thread.set(Some(ThreadId::new("other-thread"))),
                "bot" => observer.bot.set_value(Some(BotId::new("other-bot"))),
                "anchor" => observer.anchor.set_value(ThreadRunAnchor::Channel {
                    channel_id: openbot_contracts::ids::ChannelId::new("other-channel"),
                }),
                "mount" => observer.state.update(|state| {
                    let join = state.join.as_mut().unwrap();
                    join.mount = join.mount.checked_add(1).unwrap();
                }),
                "handoff-epoch" => observer.state.update(|state| {
                    state.handoff_epoch = Some(state.epoch.checked_add(1).unwrap());
                }),
                "older-read" => observer.state.update(|state| state.qualifying = true),
                _ => unreachable!(),
            }
            assert_eq!(observer.bootstrap_cursor(Some(0)), Some(0), "{invalid}");
            assert!(observer.selection("exact-message").is_none(), "{invalid}");
            assert!(!actions.may_save(observer, &read().source), "{invalid}");
            assert!(
                actions
                    .state
                    .with_untracked(|state| state.operation.is_none())
            );
        }
    }

    #[test]
    fn direct_seen_started_or_disposed_owner_cannot_request_replay_again() {
        let root = Owner::new();
        let (_, _route, observer) = direct_replay_observer(&root);
        let mut first_ack = ack();
        first_ack.message_sequence = 0;
        first_ack.event_sequence = 0;
        observer.begin_reply(&intent().run_id, Ok(&first_ack));
        assert_eq!(observer.bootstrap_cursor(Some(0)), None);
        let mut first_started = started();
        first_started.event_sequence = 0;
        observer.native_event(&first_started);
        assert_eq!(observer.bootstrap_cursor(Some(0)), Some(0));

        let root = Owner::new();
        let (actions, route, observer) = direct_replay_observer(&root);
        observer.begin_reply(&intent().run_id, Ok(&first_ack));
        assert_eq!(observer.bootstrap_cursor(Some(0)), None);
        let weak = observer.owner.get_value().unwrap();
        drop(route);
        assert!(weak.upgrade().is_none());
        assert_eq!(observer.bootstrap_cursor(Some(0)), Some(0));
        assert!(
            actions
                .state
                .with_untracked(|state| state.operation.is_none())
        );
    }

    #[test]
    fn route_source_keeps_one_raw_read_and_does_not_hold_a_strong_owner() {
        let root = Owner::new();
        let actions = root.with(|| {
            let actions = ArtifactActions::new();
            provide_context(actions);
            actions.state.update(|state| {
                state.actor = Some(read().source.actor);
                state.scope_generation = 1;
            });
            actions
        });
        let route = root.with(Owner::new);
        let observer = route.with(|| {
            ArtifactSourceObserver::new(
                RwSignal::new(intent().thread_id),
                StoredValue::new(Some(intent().agent_id)),
                StoredValue::new(intent().anchor),
            )
        });
        observer
            .state
            .update(|state| state.actor = Some(read().source.actor));
        observer.stage_begin(&intent());
        let raw = observer
            .state
            .try_update(|state| {
                let join = state.join.as_mut().unwrap();
                join.observe_ack(&ack());
                join.observe_started(&started());
                let read = join.take_read().unwrap();
                state.qualifying = true;
                read
            })
            .unwrap();
        let ticket = QualificationTicket {
            state: observer.state,
        };
        let mut next = intent();
        next.run_id = RunId::new("next-native-run");
        observer.stage_begin(&next);
        assert!(
            observer
                .state
                .with_untracked(|state| state.join.is_none() && state.qualifying)
        );
        assert!(!observer.waiting_for(&raw.source));
        drop(raw);
        drop(ticket);
        observer.stage_begin(&next);
        assert!(
            observer
                .state
                .with_untracked(|state| state.join.is_some() && !state.qualifying)
        );
        let weak = observer.owner.get_value().unwrap();
        drop(route);
        assert!(weak.upgrade().is_none());
        assert!(
            actions
                .state
                .with_untracked(|state| state.operation.is_none())
        );
    }

    fn channel_intent() -> RunIntent {
        let mut intent = intent();
        intent.anchor = ThreadRunAnchor::Channel {
            channel_id: openbot_contracts::ids::ChannelId::new("channel-1"),
        };
        intent.selected_skill_slugs = vec!["review".into(), "summarize".into()];
        intent.model_selection = Some(openbot_contracts::model_connections::RunModelSelection {
            connection_id: "01991389-7380-7000-8000-000000000001".into(),
            expected_revision: 1,
        });
        intent
    }

    fn origin_intent(intent: &RunIntent) -> OriginIntent {
        OriginIntent::new(
            &intent.run_id,
            &intent.agent_id,
            &intent.message,
            &intent.selected_skill_slugs,
            &intent.model_selection,
        )
        .unwrap()
    }

    fn channel_ack(intent: &RunIntent) -> ThreadRunStarted {
        ThreadRunStarted {
            thread_id: intent.thread_id.clone().unwrap(),
            run_id: intent.run_id.clone(),
            message_sequence: 0,
            event_sequence: 0,
            replayed: false,
        }
    }

    fn channel_started(intent: &RunIntent) -> ThreadRunEvent {
        ThreadRunEvent {
            thread_id: intent.thread_id.clone().unwrap(),
            run_id: intent.run_id.clone(),
            event_sequence: 0,
            event_type: ThreadRunEventKind::Started,
            payload: serde_json::json!({
                "runId": intent.run_id.as_str(),
                "messageId": "opaque run:input",
                "botId": intent.agent_id.as_str()
            }),
            terminal: false,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn prepared_channel_handoff(intent: &RunIntent) -> (ActionState, ChannelHandoffToken) {
        let mut state = ActionState::default();
        let observation = origin_intent(intent);
        let id = state.start_origin(observation.clone()).unwrap();
        state.origin_reply(id, &observation, Some(read().source.actor));
        assert!(state.capture_origin(id, intent));
        assert_eq!(state.origin_ack(id, intent, &channel_ack(intent)), Some(id));
        let ThreadRunAnchor::Channel { channel_id } = &intent.anchor else {
            panic!("channel fixture");
        };
        assert!(state.commit_handoff(
            id,
            &crate::api::channel_route_href(channel_id.as_str()).unwrap()
        ));
        (state, id)
    }

    fn adopted_channel_read(intent: &RunIntent) -> (ActionState, SourceRead) {
        let (mut state, _) = prepared_channel_handoff(intent);
        let actor = state.actor.clone().unwrap();
        let thread = intent.thread_id.as_ref().unwrap();
        let claim = state
            .claim_handoff(2, 1, thread, &intent.agent_id, &intent.anchor)
            .unwrap();
        let mut join = state
            .adopt_handoff(claim, &actor, thread, &intent.agent_id, &intent.anchor)
            .unwrap();
        assert!(join.take_read().is_none());
        join.observe_started(&channel_started(intent));
        let read = join.take_read().unwrap();
        assert!(join.take_read().is_none());
        (state, read)
    }

    fn channel_snapshot(intent: &RunIntent) -> ThreadConversationSnapshot {
        let mut snapshot = snapshot();
        snapshot.messages[0].id = "opaque run:input".into();
        snapshot.messages[0].content.clone_from(&intent.message);
        snapshot.messages[0].agent_id = Some(intent.agent_id.clone());
        snapshot.last_event_sequence = Some(0);
        snapshot
    }

    #[test]
    fn channel_new_first_zero_handoff_preserves_actual_ack_and_five_selectors() {
        let mut intent = channel_intent();
        intent.message = " First  首轮\nsecond  行 \n".into();
        let (mut state, read) = adopted_channel_read(&intent);
        assert_eq!(read.original_text.as_bytes(), intent.message.as_bytes());
        assert_eq!(read.source.started_sequence, 0);
        assert!(source_read_matches(&read, &channel_snapshot(&intent)));
        let operation = operation(&mut state, read.source);
        let packet = serde_json::to_value(&operation.packet).unwrap();
        assert_eq!(packet.as_object().unwrap().len(), 5);
        assert_eq!(
            packet,
            serde_json::json!({
                "requestId": REQUEST,
                "sourceThreadId": intent.thread_id.as_ref().unwrap().as_str(),
                "sourceRunId": intent.run_id.as_str(),
                "sourceMessageId": "opaque run:input",
                "expectedSha256": text_digest(&intent.message)
            })
        );
        assert_ne!(
            operation.packet.expected_sha256,
            text_digest(intent.message.trim())
        );
    }

    #[test]
    fn channel_new_handoff_exact_actor_role_scope_target_and_intent() {
        let intent = channel_intent();
        for change in 0..5 {
            let mut state = ActionState::default();
            let observation = origin_intent(&intent);
            let id = state.start_origin(observation.clone()).unwrap();
            state.origin_reply(id, &observation, Some(read().source.actor));
            let mut changed = intent.clone();
            match change {
                0 => changed.run_id = RunId::new("other-run"),
                1 => changed.agent_id = BotId::new("other-bot"),
                2 => changed.message.push(' '),
                3 => changed.selected_skill_slugs.reverse(),
                _ => changed.model_selection.as_mut().unwrap().expected_revision += 1,
            }
            assert!(!state.capture_origin(id, &changed));
            assert!(state.handoff.is_none());
        }
        for change in 0..3 {
            let (mut state, _) = prepared_channel_handoff(&intent);
            let mut thread = intent.thread_id.clone().unwrap();
            let mut bot = intent.agent_id.clone();
            let mut anchor = intent.anchor.clone();
            match change {
                0 => thread = ThreadId::new("019a7778-abcd-8abc-8abc-0123456789ac"),
                1 => bot = BotId::new("other-bot"),
                _ => {
                    anchor = ThreadRunAnchor::Channel {
                        channel_id: openbot_contracts::ids::ChannelId::new("other-channel"),
                    }
                }
            }
            assert!(state.claim_handoff(2, 1, &thread, &bot, &anchor).is_none());
        }
        for change_role in [false, true] {
            let (mut state, _) = prepared_channel_handoff(&intent);
            let probe = state.start_actor_probe(99).unwrap();
            let mut changed = read().source.actor;
            if change_role {
                changed.role = Role::Admin;
            } else {
                changed.actor = ActorId::new("other-actor");
            }
            assert!(state.finish_actor_probe(probe, 99, Some(changed)));
            assert!(state.handoff.is_none());
        }

        // A cancelled origin cannot accept a late reply or mutate actor/scope.
        let mut state = ActionState::default();
        let observation = origin_intent(&intent);
        let old = state.start_origin(observation.clone()).unwrap();
        assert!(!state.capture_origin(old, &intent));
        state.cancel_handoff(old);
        let scope = state.scope_generation;
        state.origin_reply(old, &observation, Some(read().source.actor));
        assert!(state.actor.is_none());
        assert_eq!(state.scope_generation, scope);
        let latest = state.start_origin(observation.clone()).unwrap();
        let latest_probe = state.auth_probe;
        state.origin_reply(old, &observation, Some(read().source.actor));
        assert_eq!(state.auth_probe, latest_probe);
        assert_eq!(state.origin_probe.as_ref().unwrap().id, latest);
        assert!(!state.capture_origin(old, &intent));
        assert_eq!(state.origin_probe.as_ref().unwrap().id, latest);
        state.origin_reply(latest, &observation, Some(read().source.actor));
        let replacement = state.start_actor_probe(99).unwrap();
        assert!(!state.capture_origin(latest, &intent));
        assert_eq!(state.auth_probe, Some((replacement, 99)));
    }

    #[test]
    fn channel_origin_pending_read_requires_same_live_lease_intent_and_original_ack() {
        for case in [
            "completed",
            "pending",
            "replaced",
            "revoked",
            "dead-owner",
            "changed-intent",
            "bad-ack",
        ] {
            let root = Owner::new();
            let actions = root.with(ArtifactActions::new);
            let mut origin = Some(root.with(Owner::new));
            let actor = read().source.actor;
            actions.state.update(|state| {
                state.actor = Some(actor.clone());
                state.scope_generation = 1;
            });
            let intent = channel_intent();
            let observation = origin_intent(&intent);
            let id = actions
                .state
                .try_update(|state| state.start_origin(observation.clone()))
                .flatten()
                .unwrap();
            let mut lease = ChannelOriginLease {
                actions,
                id,
                owner: origin.as_ref().unwrap().downgrade(),
                captured: false,
                ready: false,
            };
            lease.capture(&intent);
            assert!(!lease.captured, "{case}");
            actions.state.with_untracked(|state| {
                assert!(state.origin_probe_pending(id, &intent), "{case}");
                assert!(state.handoff.is_none(), "{case}");
            });

            let replacement = if case == "replaced" {
                actions
                    .state
                    .try_update(|state| state.start_origin(observation.clone()))
                    .flatten()
            } else {
                None
            };
            if case != "pending" {
                actions.state.update(|state| {
                    state.origin_reply(
                        id,
                        &observation,
                        (case != "revoked").then_some(actor.clone()),
                    );
                });
            }
            if case == "dead-owner" {
                drop(origin.take());
            }
            let mut supplied = intent.clone();
            if case == "changed-intent" {
                supplied.message.push(' ');
            }
            let mut ack = channel_ack(&intent);
            if case == "bad-ack" {
                ack.run_id = RunId::new("other-run");
            }
            let accepted = lease.reply(&supplied, Ok(&ack));
            if case == "completed" {
                assert_eq!(accepted, Some(id));
                assert!(lease.captured && lease.ready);
                actions.state.update(|state| {
                    let handoff = state.handoff.as_mut().unwrap();
                    assert_eq!(handoff.join.ack.as_ref(), Some(&ack));
                    assert!(handoff.join.started.is_none());
                    assert!(handoff.join.take_read().is_none());
                    assert!(state.commit_handoff(id, "/channel/channel-1"));
                    let thread = intent.thread_id.as_ref().unwrap();
                    let claim = state
                        .claim_handoff(2, 1, thread, &intent.agent_id, &intent.anchor)
                        .unwrap();
                    let mut join = state
                        .adopt_handoff(claim, &actor, thread, &intent.agent_id, &intent.anchor)
                        .unwrap();
                    assert!(join.take_read().is_none());
                    join.observe_started(&channel_started(&intent));
                    let proven = join.take_read().unwrap();
                    assert_eq!(proven.original_text.as_bytes(), intent.message.as_bytes());
                    assert_eq!(proven.source.actor, actor);
                    assert_eq!(proven.source.started_sequence, 0);
                    assert!(join.take_read().is_none());
                });
            } else {
                assert_eq!(accepted, None, "{case}");
                assert!(!lease.ready, "{case}");
            }
            drop(lease);
            actions.state.with_untracked(|state| {
                assert!(state.handoff.is_none(), "{case}");
                if let Some(replacement) = replacement {
                    assert_eq!(
                        state.auth_probe,
                        Some((replacement.probe, replacement.mount))
                    );
                    assert_eq!(state.origin_probe.as_ref().unwrap().id, replacement);
                }
                if case == "revoked" {
                    assert!(state.actor.is_none());
                    assert_eq!(state.scope_generation, 2);
                }
            });
        }
    }

    #[test]
    fn channel_new_handoff_owner_drop_transfer_and_once_adoption() {
        let root = Owner::new();
        let actions = root.with(|| {
            let actions = ArtifactActions::new();
            provide_context(actions);
            actions
        });
        let intent = channel_intent();
        let origin = root.with(Owner::new);
        let weak = origin.downgrade();
        let observation = origin_intent(&intent);
        let id = actions
            .state
            .try_update(|state| state.start_origin(observation))
            .flatten()
            .unwrap();
        let lease = ChannelOriginLease {
            actions,
            id,
            owner: weak.clone(),
            captured: false,
            ready: false,
        };
        drop(lease);
        assert!(
            actions
                .state
                .with_untracked(|state| state.origin_probe.is_none())
        );

        let (prepared, id) = prepared_channel_handoff(&intent);
        actions.state.update(|state| *state = prepared);
        origin.with(|| {
            on_cleanup(move || {
                actions.state.try_update(|state| state.close_origin(id));
            })
        });
        drop(ChannelOriginLease {
            actions,
            id,
            owner: weak.clone(),
            captured: true,
            ready: true,
        });
        drop(origin);
        assert!(weak.upgrade().is_none());
        assert!(
            actions
                .state
                .with_untracked(|state| state.handoff.is_some())
        );
        let receiver = root.with(Owner::new);
        let observer = receiver.with(|| {
            ArtifactSourceObserver::new(
                RwSignal::new(intent.thread_id.clone()),
                StoredValue::new(Some(intent.agent_id.clone())),
                StoredValue::new(intent.anchor.clone()),
            )
        });
        let thread = intent.thread_id.as_ref().unwrap();
        let old = actions
            .state
            .try_update(|state| {
                state.claim_handoff(observer.mount, 1, thread, &intent.agent_id, &intent.anchor)
            })
            .flatten()
            .unwrap();
        let latest = actions
            .state
            .try_update(|state| {
                state.claim_handoff(observer.mount, 2, thread, &intent.agent_id, &intent.anchor)
            })
            .flatten()
            .unwrap();
        actions.state.update(|state| state.cancel_claim(old));
        let actor = actions
            .state
            .with_untracked(|state| state.actor.clone().unwrap());
        let joined = actions
            .state
            .try_update(|state| {
                state.adopt_handoff(latest, &actor, thread, &intent.agent_id, &intent.anchor)
            })
            .flatten()
            .unwrap();
        assert_eq!(joined.mount, observer.mount);
        assert_eq!(joined.epoch, 2);
        assert!(
            actions
                .state
                .try_update(|state| {
                    state.adopt_handoff(latest, &actor, thread, &intent.agent_id, &intent.anchor)
                })
                .flatten()
                .is_none()
        );
        drop(joined);
        drop(receiver);
        assert!(
            actions
                .state
                .with_untracked(|state| state.handoff.is_none())
        );

        let (mut abandoned, _) = prepared_channel_handoff(&intent);
        abandoned.handoff_path_changed("/settings");
        assert!(abandoned.handoff.is_none());
        let (mut abandoned, _) = prepared_channel_handoff(&intent);
        let _ = abandoned
            .claim_handoff(2, 1, thread, &intent.agent_id, &intent.anchor)
            .unwrap();
        abandoned.close_route(2);
        assert!(abandoned.handoff.is_none());
    }

    #[test]
    fn channel_new_handoff_one_mebibyte_budget_and_checked_epochs() {
        let mut intent = channel_intent();
        let actor = read().source.actor;
        let target = "/channel/channel-1";
        intent.message = "x".into();
        let overhead = handoff_budget(&intent, &actor, target).unwrap() - 1;
        intent.message = "x".repeat(MAX_THREAD_MESSAGE_BYTES - overhead);
        assert_eq!(
            handoff_budget(&intent, &actor, target),
            Some(MAX_THREAD_MESSAGE_BYTES)
        );
        let (mut state, _) = prepared_channel_handoff(&intent);
        let pointer = state
            .handoff
            .as_ref()
            .unwrap()
            .join
            .text
            .as_ref()
            .unwrap()
            .as_ptr();
        let thread = intent.thread_id.as_ref().unwrap();
        let claim = state
            .claim_handoff(2, 1, thread, &intent.agent_id, &intent.anchor)
            .unwrap();
        let join = state
            .adopt_handoff(claim, &actor, thread, &intent.agent_id, &intent.anchor)
            .unwrap();
        assert_eq!(join.text.as_ref().unwrap().as_ptr(), pointer);
        drop(join);
        intent.message.push('x');
        assert!(handoff_budget(&intent, &actor, target).is_none());
        intent.message = "x".repeat(MAX_THREAD_MESSAGE_BYTES);
        let original = intent.message.clone();
        assert!(handoff_budget(&intent, &actor, target).is_none());
        assert_eq!(intent.message, original);
        intent.message.clear();
        assert!(handoff_budget(&intent, &actor, target).is_none());
        assert!(
            OriginIntent::new(
                &intent.run_id,
                &intent.agent_id,
                &intent.message,
                &intent.selected_skill_slugs,
                &intent.model_selection
            )
            .is_none()
        );
        let original = channel_intent();
        for field in 0..3 {
            let mut state = ActionState::default();
            match field {
                0 => state.next_mount = u64::MAX,
                1 => state.next_handoff = u64::MAX,
                _ => state.auth_read_generation = u64::MAX,
            }
            assert!(state.start_origin(origin_intent(&original)).is_none());
        }
        let mut source = SourceState {
            epoch: u64::MAX,
            ..Default::default()
        };
        assert!(source.begin_handoff_adoption().is_none());
        let mut source = SourceState {
            qualifying: true,
            ..Default::default()
        };
        assert!(source.begin_handoff_adoption().is_none());
    }

    #[test]
    fn channel_new_adopted_source_still_requires_unique_current_utf8_and_unknown_packet() {
        let intent = channel_intent();
        let (mut state, read) = adopted_channel_read(&intent);
        let current = channel_snapshot(&intent);
        for change in 0..5 {
            let mut invalid = current.clone();
            match change {
                0 => invalid.messages.push(invalid.messages[0].clone()),
                1 => invalid.messages[0].role = ThreadHistoryRole::Assistant,
                2 => invalid.messages[0].content = intent.message.trim().into(),
                3 => invalid.messages[0].agent_id = Some(BotId::new("other-bot")),
                _ => invalid.last_event_sequence = None,
            }
            assert!(!source_read_matches(&read, &invalid));
        }
        assert!(source_read_matches(&read, &current));
        let source = read.source.clone();
        let operation = operation(&mut state, source.clone());
        state.settle(&operation, SavePhase::Unknown);
        state.close_route(2);
        assert!(state.check(source.clone()).is_none());
        assert!(
            state
                .start(operation.token, &source, || panic!("no second packet"))
                .is_none()
        );
        assert_eq!(state.operation.as_ref().unwrap().packet, operation.packet);
        assert_eq!(state.operation.as_ref().unwrap().phase, SavePhase::Unknown);
        for changed in 0..3 {
            let (mut state, _) = prepared_channel_handoff(&intent);
            let actor = state.actor.clone().unwrap();
            let thread = intent.thread_id.as_ref().unwrap();
            let claim = state
                .claim_handoff(2, 1, thread, &intent.agent_id, &intent.anchor)
                .unwrap();
            let mut join = state
                .adopt_handoff(claim, &actor, thread, &intent.agent_id, &intent.anchor)
                .unwrap();
            let mut started = channel_started(&intent);
            match changed {
                0 => started.event_sequence = 1,
                1 => started.payload["runId"] = serde_json::json!("other-run"),
                _ => started.payload["botId"] = serde_json::json!("other-bot"),
            }
            join.observe_started(&started);
            assert!(join.take_read().is_none());
        }
    }

    fn pending_channel_observer(
        root: &Owner,
        intent: &RunIntent,
    ) -> (ArtifactActions, ArtifactSourceObserver, PendingTargetProbe) {
        root.with(|| {
            let actions = ArtifactActions::new();
            provide_context(actions);
            let (prepared, _) = prepared_channel_handoff(intent);
            actions.state.update(|state| *state = prepared);
            let observer = ArtifactSourceObserver::new(
                RwSignal::new(intent.thread_id.clone()),
                StoredValue::new(Some(intent.agent_id.clone())),
                StoredValue::new(intent.anchor.clone()),
            );
            let pending = observer.prepare_channel_handoff().unwrap();
            (actions, observer, pending)
        })
    }

    #[test]
    fn pending_target_never_completing_probe_keeps_replay_hint_but_cannot_read_select_or_save() {
        let root = Owner::new();
        let intent = channel_intent();
        let (actions, observer, _) = pending_channel_observer(&root, &intent);
        assert_eq!(observer.bootstrap_cursor(Some(0)), None);
        observer.native_event(&channel_started(&intent));
        observer.state.update(|state| {
            let join = state.join.as_mut().unwrap();
            assert!(!join.target_fresh);
            assert!(join.started.is_some());
            assert!(join.take_read().is_none());
            // Even an old eligible value cannot cross the explicit pending gate.
            state.eligible = Some(read().source);
        });
        assert!(observer.selection("exact-message").is_none());
        assert!(!actions.may_save(observer, &read().source));
        assert_eq!(observer.bootstrap_cursor(Some(0)), None);
        assert!(
            actions
                .state
                .with_untracked(|state| state.operation.is_none())
        );
        // No completion was supplied. The synchronous prepare/hint paths already returned.
    }

    #[test]
    fn pending_target_fresh_match_and_late_reply_require_exact_original_probe_and_epoch() {
        let root = Owner::new();
        let intent = channel_intent();
        let (actions, observer, pending) = pending_channel_observer(&root, &intent);
        let later = actions
            .state
            .try_update(|state| state.start_actor_probe(99))
            .flatten()
            .unwrap();
        let actor_before = actions.state.with_untracked(|state| state.actor.clone());
        observer.finish_pending_target(pending, None);
        assert_eq!(
            actions.state.with_untracked(|state| state.auth_probe),
            Some((later, 99))
        );
        assert_eq!(
            actions.state.with_untracked(|state| state.actor.clone()),
            actor_before
        );
        assert!(observer.state.with_untracked(|state| state.join.is_none()));

        let root = Owner::new();
        let (_, observer, pending) = pending_channel_observer(&root, &intent);
        observer.finish_pending_target(pending, Some(read().source.actor));
        observer.state.update(|state| {
            let join = state.join.as_mut().unwrap();
            assert!(join.target_fresh);
            join.observe_started(&channel_started(&intent));
            let source = join.take_read().unwrap();
            assert!(source_read_matches(&source, &channel_snapshot(&intent)));
        });
        assert_eq!(observer.bootstrap_cursor(Some(0)), Some(0));
        let original_actor = observer.state.with_untracked(|state| state.actor.clone());
        observer.finish_pending_target(pending, None);
        assert_eq!(
            observer.state.with_untracked(|state| state.actor.clone()),
            original_actor
        );
    }

    #[test]
    fn pending_started_metadata_overflow_releases_provenance_and_not_the_native_event() {
        let root = Owner::new();
        let intent = channel_intent();
        let (actions, observer, _) = pending_channel_observer(&root, &intent);
        observer.state.update(|state| {
            state.join.as_mut().unwrap().pending_charge = Some(MAX_THREAD_MESSAGE_BYTES);
        });
        let event = channel_started(&intent);
        let original = serde_json::to_value(&event).unwrap();
        observer.native_event(&event);
        assert_eq!(serde_json::to_value(&event).unwrap(), original);
        assert!(observer.state.with_untracked(|state| {
            state.join.is_none() && state.eligible.is_none() && state.pending_target.is_none()
        }));
        assert!(
            actions
                .state
                .with_untracked(|state| state.auth_probe.is_none())
        );
        assert!(
            actions
                .state
                .with_untracked(|state| state.operation.is_none())
        );
    }
}
