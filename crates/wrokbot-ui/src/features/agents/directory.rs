//! The authenticated shell's one read of the visible assistant directory.
//!
//! The sidebar, the new-conversation pages, the direct-assistant page and the channel
//! conversation all read these rows and this one failure state; nothing else lists the visible
//! directory again. The directory is read when the shell mounts, after a confirmed change
//! (`refresh`) or an explicit retry, and quietly again on every route change: a route-change read
//! keeps the shown rows and `loading` as they are until its reply lands.

use leptos::prelude::*;
use openbot_contracts::agent::AgentProfile;

/// Visible assistants and their read state.
#[derive(Clone, Copy)]
pub(crate) struct AgentDirectory {
    /// Rows of the last successful read.
    pub(crate) agents: RwSignal<Vec<AgentProfile>>,
    /// A first read, retry or post-change read is in flight.
    pub(crate) loading: RwSignal<bool>,
    /// The last read failed and there are no rows to show.
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
        {
            let pathname = leptos_router::hooks::use_location().pathname;
            Effect::new(move |read: Option<u64>| {
                let generation = directory.generation.get();
                pathname.track();
                // Same generation: only the route changed, so this read stays quiet.
                if read != Some(generation) {
                    directory.loading.set(true);
                    directory.failed.set(false);
                }
                // Only real changes notify: the pages resolving their assistant track these
                // signals, and an unchanged quiet reply must not make them resolve again.
                leptos::task::spawn_local_scoped_with_cancellation(async move {
                    let failed = match crate::api::list_agents(false).await {
                        Ok(rows) => {
                            directory.agents.maybe_update(|agents| {
                                let changed = *agents != rows;
                                if changed {
                                    *agents = rows;
                                }
                                changed
                            });
                            false
                        }
                        Err(_) => directory.agents.with_untracked(Vec::is_empty),
                    };
                    directory
                        .failed
                        .maybe_update(|value| std::mem::replace(value, failed) != failed);
                    directory
                        .loading
                        .maybe_update(|value| std::mem::replace(value, false));
                });
                generation
            });
        }
        provide_context(directory);
    }

    /// Read the directory again, after a confirmed change or when the user retries.
    pub(crate) fn refresh(self) {
        self.generation
            .update(|generation| *generation = generation.wrapping_add(1));
    }
}

/// The shell's assistant directory.
pub(crate) fn use_agent_directory() -> AgentDirectory {
    expect_context::<AgentDirectory>()
}
