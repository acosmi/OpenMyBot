//! Pure direct-Bot thread identity and remembered-thread selection rules.

#![cfg_attr(not(any(test, target_arch = "wasm32")), allow(dead_code))]

use openbot_contracts::ids::ThreadId;

const BOT_THREAD_KEY_PREFIX: &str = "openbot.bot-thread";

/// Whether the direct-Bot controller must keep a remembered thread or mint a fresh one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RememberedThreadDecision {
    /// Reuse the per-Agent thread identity already held by the browser.
    Remembered,
    /// No history can be lost, or the Server authoritatively said the identity is unknown.
    Fresh,
}

/// One stable, namespaced local-storage key per Agent.
pub(super) fn bot_thread_key(agent_id: &str) -> String {
    format!("{BOT_THREAD_KEY_PREFIX}.{agent_id}")
}

/// The single browser entry written when a conversation is opened or minted. There is one key
/// per assistant, so opening another conversation replaces it: only the most recently opened one
/// is remembered, and its value is the identity the Server's list or mint returned.
pub(super) fn remembered_entry(agent_id: &str, opened: &ThreadId) -> (String, String) {
    (bot_thread_key(agent_id), opened.as_str().to_owned())
}

/// Reject damaged browser state before it can become a native thread authority input.
pub(super) fn plausible_remembered_thread(value: &str) -> Option<ThreadId> {
    (value.len() <= 64 && uuid::Uuid::parse_str(value).is_ok()).then(|| ThreadId::new(value))
}

/// Preserve history on an inconclusive check; only an authoritative `false` replaces it.
pub(super) fn thread_to_use(
    remembered: Option<&ThreadId>,
    known: Option<bool>,
) -> RememberedThreadDecision {
    if remembered.is_none() || known == Some(false) {
        RememberedThreadDecision::Fresh
    } else {
        RememberedThreadDecision::Remembered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(value: &str) -> ThreadId {
        ThreadId::new(value)
    }

    #[test]
    fn is_the_same_key_for_the_same_agent_every_time() {
        assert_eq!(bot_thread_key("bot-a"), bot_thread_key("bot-a"));
    }

    #[test]
    fn is_namespaced_rather_than_the_bare_agent_id() {
        let key = bot_thread_key("bot-a");
        assert_ne!(key, "bot-a");
        assert!(key.contains("bot-a"));
    }

    #[test]
    fn two_agents_never_collide() {
        assert_ne!(bot_thread_key("bot-a"), bot_thread_key("bot-b"));
    }

    #[test]
    fn a_remembered_thread_intelligence_confirms_it_has_is_kept() {
        let remembered = thread("550e8400-e29b-81d4-a716-446655440000");
        assert_eq!(
            thread_to_use(Some(&remembered), Some(true)),
            RememberedThreadDecision::Remembered
        );
    }

    #[test]
    fn a_remembered_thread_intelligence_says_it_does_not_have_i() {
        let remembered = thread("550e8400-e29b-81d4-a716-446655440000");
        assert_eq!(
            thread_to_use(Some(&remembered), Some(false)),
            RememberedThreadDecision::Fresh
        );
    }

    #[test]
    fn a_remembered_thread_is_kept_when_the_check_itself_could() {
        let remembered = thread("550e8400-e29b-81d4-a716-446655440000");
        assert_eq!(
            thread_to_use(Some(&remembered), None),
            RememberedThreadDecision::Remembered
        );
    }

    #[test]
    fn with_nothing_remembered_every_outcome_of_the_check_start() {
        assert_eq!(
            thread_to_use(None, Some(true)),
            RememberedThreadDecision::Fresh
        );
        assert_eq!(
            thread_to_use(None, Some(false)),
            RememberedThreadDecision::Fresh
        );
        assert_eq!(thread_to_use(None, None), RememberedThreadDecision::Fresh);
    }

    #[test]
    fn opening_a_row_remembers_only_that_row_under_the_single_assistant_key() {
        let first = remembered_entry("bot-a", &thread("550e8400-e29b-81d4-a716-446655440001"));
        let second = remembered_entry("bot-a", &thread("550e8400-e29b-81d4-a716-446655440002"));
        // One key per assistant: the later open replaces the earlier one.
        assert_eq!(first.0, second.0);
        assert_eq!(second.1, "550e8400-e29b-81d4-a716-446655440002");
        assert_ne!(
            remembered_entry("bot-b", &thread("550e8400-e29b-81d4-a716-446655440002")).0,
            second.0
        );
    }

    #[test]
    fn damaged_local_thread_identity_is_never_reused() {
        assert!(plausible_remembered_thread("not-a-uuid").is_none());
        assert!(plausible_remembered_thread(&"a".repeat(65)).is_none());
        assert_eq!(
            plausible_remembered_thread("550e8400-e29b-81d4-a716-446655440000")
                .expect("plausible UUID")
                .as_str(),
            "550e8400-e29b-81d4-a716-446655440000"
        );
    }
}
