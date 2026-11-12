//! Direct-assistant work state shared by the sidebar work list and the `/bot` canvas.
//!
//! The `/bot` page names the assistant (from its URL); this state resolves which conversation the
//! canvas shows, opens the one picked in the sidebar list, mints a new one, and carries the signal
//! that makes the list read its first page again after the open conversation changed its work.

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;
use openbot_contracts::ids::{BotId, ThreadId};

#[cfg(target_arch = "wasm32")]
use super::remembered::{
    RememberedThreadDecision, bot_thread_key, plausible_remembered_thread, remembered_entry,
    thread_to_use,
};
#[cfg(target_arch = "wasm32")]
use crate::api::{load_thread_status, mint_thread_id};

/// The conversation the canvas shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenThread {
    /// Server conversation identity.
    pub(crate) id: ThreadId,
    /// Minted in this mount, so the canvas starts empty instead of reading history.
    pub(crate) fresh: bool,
}

/// Shell-owned direct-assistant work state.
#[derive(Clone, Copy)]
pub(crate) struct BotWork {
    /// The assistant the mounted `/bot` page shows; `None` while no `/bot` page is mounted.
    pub(crate) agent: RwSignal<Option<AgentProfile>>,
    agent_id: Memo<Option<BotId>>,
    /// The conversation the canvas shows.
    pub(crate) thread: RwSignal<Option<OpenThread>>,
    /// Title of the open conversation as the work list reports it.
    pub(crate) thread_title: RwSignal<Option<String>>,
    /// The remembered conversation is being checked or a first one minted.
    pub(crate) resolving: RwSignal<bool>,
    /// The remembered conversation could not be checked, so its history may be incomplete.
    pub(crate) history_unavailable: RwSignal<bool>,
    /// No conversation could be resolved.
    pub(crate) thread_error: RwSignal<bool>,
    /// A new conversation is being minted.
    pub(crate) new_pending: RwSignal<bool>,
    /// Minting a new conversation failed.
    pub(crate) new_error: RwSignal<bool>,
    /// Bumped whenever the open conversation changed its work.
    pub(crate) changes: RwSignal<u64>,
    resolve_generation: RwSignal<u64>,
}

impl BotWork {
    /// Install the state and its conversation resolver in the current (shell) owner.
    pub(crate) fn provide() {
        let agent = RwSignal::new(None::<AgentProfile>);
        let work = Self {
            agent,
            agent_id: Memo::new(move |_| {
                agent.with(|agent| agent.as_ref().map(|agent| agent.id.clone()))
            }),
            thread: RwSignal::new(None),
            thread_title: RwSignal::new(None),
            resolving: RwSignal::new(true),
            history_unavailable: RwSignal::new(false),
            thread_error: RwSignal::new(false),
            new_pending: RwSignal::new(false),
            new_error: RwSignal::new(false),
            changes: RwSignal::new(0),
            resolve_generation: RwSignal::new(0),
        };
        // A newer resolution reruns this Effect, which cancels the previous task.
        #[cfg(target_arch = "wasm32")]
        Effect::new(move |previous: Option<Option<BotId>>| {
            work.resolve_generation.track();
            let agent_id = work.agent_id.get();
            if previous.as_ref() != Some(&agent_id) {
                work.thread.set(None);
                work.thread_title.set(None);
                work.new_error.set(false);
            }
            let Some(resolving_for) = agent_id.clone() else {
                return agent_id;
            };
            work.resolving.set(true);
            work.history_unavailable.set(false);
            work.thread_error.set(false);
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                let remembered = remembered_thread(&resolving_for);
                let (known, check_unavailable) = match remembered.as_ref() {
                    Some(remembered) => match load_thread_status(remembered).await {
                        Ok(known) => (Some(known), false),
                        Err(_) => (None, true),
                    },
                    None => (None, false),
                };
                let decision = thread_to_use(remembered.as_ref(), known);
                let resolved = match (decision, remembered) {
                    (RememberedThreadDecision::Remembered, Some(thread)) => {
                        Ok((thread, false, check_unavailable))
                    }
                    (RememberedThreadDecision::Fresh, _) => mint_and_remember(&resolving_for)
                        .await
                        .map(|thread| (thread, true, false)),
                    _ => Err(()),
                };
                match resolved {
                    Ok((id, fresh, unavailable)) => {
                        work.thread.set(Some(OpenThread { id, fresh }));
                        work.history_unavailable.set(unavailable);
                    }
                    Err(()) => work.thread_error.set(true),
                }
                work.resolving.set(false);
            });
            agent_id
        });
        provide_context(work);
    }

    /// The assistant the canvas shows, tracked.
    pub(crate) fn agent_id(self) -> Option<BotId> {
        self.agent_id.get()
    }

    /// Resolve the conversation again after a failure.
    pub(crate) fn retry(self) {
        self.resolving.set(true);
        self.resolve_generation
            .update(|generation| *generation = generation.wrapping_add(1));
    }

    /// Open the conversation picked in the work list. The browser keeps only the most recently
    /// opened conversation; the Server's list stays the work identity.
    pub(crate) fn open(self, id: ThreadId) {
        #[cfg(target_arch = "wasm32")]
        if let Some(agent_id) = self.agent_id.get_untracked() {
            remember_thread(&agent_id, &id);
        }
        self.thread.set(Some(OpenThread { id, fresh: false }));
        self.history_unavailable.set(false);
        self.thread_error.set(false);
    }

    /// Mint and open a new conversation with the shown assistant.
    pub(crate) fn start_new(self) {
        let Some(agent_id) = self.agent_id.get_untracked() else {
            return;
        };
        if self.new_pending.get_untracked() {
            return;
        }
        self.new_pending.set(true);
        self.new_error.set(false);
        #[cfg(target_arch = "wasm32")]
        leptos::task::spawn_local_scoped_with_cancellation(async move {
            match mint_and_remember(&agent_id).await {
                Ok(id) => {
                    self.thread.set(Some(OpenThread { id, fresh: true }));
                    self.thread_title.set(None);
                    self.history_unavailable.set(false);
                    self.thread_error.set(false);
                }
                Err(()) => self.new_error.set(true),
            }
            self.new_pending.set(false);
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = agent_id;
            self.new_pending.set(false);
            self.new_error.set(true);
        }
    }

    /// The open conversation changed its work: the list reads its first page again.
    pub(crate) fn work_changed(self) {
        self.changes
            .update(|changes| *changes = changes.wrapping_add(1));
    }
}

/// The shell's direct-assistant work state.
pub(crate) fn use_bot_work() -> BotWork {
    expect_context::<BotWork>()
}

#[cfg(target_arch = "wasm32")]
async fn mint_and_remember(agent_id: &BotId) -> Result<ThreadId, ()> {
    let thread = mint_thread_id().await.map_err(|_| ())?;
    remember_thread(agent_id, &thread);
    Ok(thread)
}

#[cfg(target_arch = "wasm32")]
fn remembered_thread(agent_id: &BotId) -> Option<ThreadId> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let key = bot_thread_key(agent_id.as_str());
    let raw = storage.get_item(&key).ok()??;
    match plausible_remembered_thread(&raw) {
        Some(thread) => Some(thread),
        None => {
            _ = storage.remove_item(&key);
            None
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn remember_thread(agent_id: &BotId, thread: &ThreadId) {
    let Some(storage) = web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    else {
        return;
    };
    let (key, value) = remembered_entry(agent_id.as_str(), thread);
    _ = storage.set_item(&key, &value);
}
