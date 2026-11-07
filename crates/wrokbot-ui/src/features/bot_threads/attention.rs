//! Client-side "needs attention" count over the three existing actor-scoped pending lists.
//!
//! §9.2 forbids a new aggregate API: the count is computed here by matching each listed item's
//! `run_id` against the foreground Run of a conversation.

use openbot_contracts::ids::RunId;

/// The Run identities the three existing pending lists mention, one entry per listed item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AttentionIndex(Vec<RunId>);

impl AttentionIndex {
    /// How many listed items mention the exact foreground Run of a conversation.
    ///
    /// Each item counts once. The same Run appearing in two lists counts twice because the user
    /// must answer each of them separately.
    pub(crate) fn count_for(&self, run: Option<&RunId>) -> usize {
        run.map_or(0, |run| self.0.iter().filter(|item| *item == run).count())
    }
}

/// Read the three existing pending lists and keep the Run identity of every listed item.
///
/// A list that cannot be read contributes nothing rather than a guess.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn read_attention_index() -> AttentionIndex {
    let mut runs = Vec::new();
    if let Ok(page) = crate::api::list_pending_tool_approvals().await {
        runs.extend(page.approvals.into_iter().map(|row| row.run_id));
    }
    if let Ok(page) = crate::api::list_pending_component_human_decisions().await {
        runs.extend(page.decisions.into_iter().map(|row| row.run_id));
    }
    if let Ok(page) = crate::api::list_pending_remote_interrupts().await {
        runs.extend(
            page.interrupts
                .into_iter()
                .map(|row| RunId::new(row.run_id)),
        );
    }
    AttentionIndex(runs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_counts_only_the_matching_foreground_run() {
        let run = RunId::new("01991389-7380-7000-8000-000000000002");
        let other = RunId::new("01991389-7380-7000-8000-000000000009");
        // One tool approval for the run, one component decision each for the run and the other
        // Run, and one remote interrupt for the other Run.
        let index = AttentionIndex(vec![run.clone(), run.clone(), other.clone(), other.clone()]);
        assert_eq!(index.count_for(Some(&run)), 2);
        assert_eq!(index.count_for(Some(&other)), 2);
        assert_eq!(
            index.count_for(Some(&RunId::new("01991389-7380-7000-8000-000000000008"))),
            0
        );
        assert_eq!(index.count_for(None), 0);
    }
}
