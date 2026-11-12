//! The authenticated shell's one read of the visible assistant directory.
//!
//! The sidebar, the new-conversation pages, the direct-assistant page and the channel
//! conversation all read these rows and this one failure state; nothing else lists the visible
//! directory again. The directory is read once per shell mount and again only after a confirmed
//! change (`refresh`) or an explicit retry.

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;

/// Visible assistants and their read state.
#[derive(Clone, Copy)]
pub(crate) struct AgentDirectory {
    /// Rows of the last successful read; empty after a failed one.
    pub(crate) agents: RwSignal<Vec<AgentProfile>>,
    /// A read is in flight.
    pub(crate) loading: RwSignal<bool>,
    /// The last read failed.
    pub(crate) failed: RwSignal<bool>,
    generation: RwSignal<u64>,
}

impl AgentDirectory {
    /// Install the directory and its reader in the current (shell) owner.
    pub(crate) fn provide() {
        let directory = Self {
            agents: RwSignal::new(Vec::new()),
            loading: RwSignal::new(true),
            failed: RwSignal::new(false),
            generation: RwSignal::new(0),
        };
        // A newer read reruns this Effect, which cancels the previous task: a late read never lands.
        #[cfg(target_arch = "wasm32")]
        Effect::new(move |_| {
            directory.generation.track();
            directory.loading.set(true);
            directory.failed.set(false);
            leptos::task::spawn_local_scoped_with_cancellation(async move {
                match crate::api::list_agents(false).await {
                    Ok(rows) => directory.agents.set(rows),
                    Err(_) => {
                        directory.agents.set(Vec::new());
                        directory.failed.set(true);
                    }
                }
                directory.loading.set(false);
            });
        });
        provide_context(directory);
    }

    /// Read the directory again, after a confirmed change or when the user retries.
    pub(crate) fn refresh(self) {
        self.generation
            .update(|generation| *generation = generation.wrapping_add(1));
    }

    /// The listed profile with this id, tracked.
    pub(crate) fn profile(self, id: &str) -> Option<AgentProfile> {
        self.agents
            .with(|agents| agents.iter().find(|agent| agent.id.as_str() == id).cloned())
    }
}

/// The shell's assistant directory.
pub(crate) fn use_agent_directory() -> AgentDirectory {
    expect_context::<AgentDirectory>()
}
