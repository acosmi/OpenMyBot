//! `can_use_tool` relay: permission ids, the read-only rule, notices, responses and the
//! decision poll.
use crate::{OMB_NOTICE_PERMISSION_V1, protocol};
use omb_store::{DecidedVia, Decision, StoreError};
use serde_json::Value;
use std::path::Path;
use tokio::time::Instant;

/// Crockford base32 in lower case: no `i`, `l`, `o` or `u`.
const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// `hp` plus ten random lower-case Crockford characters.
pub(crate) fn permission_id() -> String {
    let mut bytes = [0; 10];
    getrandom::fill(&mut bytes).expect("operating system random source");
    let mut id = String::from("hp");
    id.extend(bytes.iter().map(|b| CROCKFORD[usize::from(b & 31)] as char));
    id
}

/// Allowed without the owner only for a read-only tool whose path field resolves inside the
/// workspace, and for `Glob`, whose pattern neither contains `..` nor starts with `/`.
pub(crate) fn readonly(tool_name: &str, input: &Value, workspace: &Path) -> bool {
    if !crate::CC_READONLY_TOOLS.contains(&tool_name) {
        return false;
    }
    if tool_name == "Glob"
        && input["pattern"]
            .as_str()
            .is_some_and(|pattern| pattern.contains("..") || pattern.starts_with('/'))
    {
        return false;
    }
    let path = match (
        tool_name,
        &input[if tool_name == "Read" {
            "file_path"
        } else {
            "path"
        }],
    ) {
        (_, Value::String(path)) => workspace.join(path),
        ("Read", _) => return false,
        (_, Value::Null) => workspace.to_path_buf(),
        _ => return false,
    };
    std::fs::canonicalize(path).is_ok_and(|real| real.starts_with(workspace))
}

pub(crate) fn notice(tool_name: &str, permission_id: &str) -> String {
    OMB_NOTICE_PERMISSION_V1
        .replace("{tool}", tool_name)
        .replace("{id}", permission_id)
}

/// The child's response for a persisted decision.
pub(crate) fn response(
    request_id: &str,
    decision: Decision,
    via: DecidedVia,
    input: &Value,
) -> Vec<u8> {
    match (decision, via) {
        (Decision::Allow, _) => protocol::allow(request_id, input),
        (Decision::Deny, DecidedVia::Timeout) => protocol::deny(request_id, "permission_timeout"),
        (Decision::Deny, DecidedVia::RunStopped) => protocol::deny(request_id, "run_stopped"),
        (Decision::Deny, _) => protocol::deny(request_id, "owner_denied"),
    }
}

/// A request waiting for the owner.
pub(crate) struct Pending {
    pub(crate) permission_id: String,
    pub(crate) request_id: String,
    pub(crate) input: Value,
    pub(crate) expires: Instant,
}
/// One poll of a waiting request: the owner's decision, or the timeout denial once expired.
pub(crate) async fn poll(
    store: &tokio_postgres::Client,
    pending: &Pending,
    deadline: Instant,
) -> Result<Option<(Decision, DecidedVia)>, StoreError> {
    if Instant::now() >= pending.expires {
        return omb_store::settle_permission(
            store,
            &pending.permission_id,
            DecidedVia::Timeout,
            deadline,
        )
        .await
        .map(Some);
    }
    omb_store::read_permission(store, &pending.permission_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{jcs, workspace::tests::temp};
    use serde_json::json;

    #[test]
    fn id_is_hp_plus_ten_lowercase_crockford_characters() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let id = permission_id();
            assert_eq!(id.len(), 12);
            assert!(id.starts_with("hp"));
            assert!(id[2..].bytes().all(|b| CROCKFORD.contains(&b)), "{id}");
            seen.extend(id[2..].chars());
        }
        assert!(!seen.iter().any(|c| "ilou".contains(*c)));
        assert!(seen.len() > 20);
    }

    #[test]
    fn summary_is_truncated_on_utf8_boundary_at_512_bytes() {
        let short = jcs::jcs(&json!({"a": "b"}));
        assert_eq!(jcs::summary(&short), "{\"a\":\"b\"}");
        // `{"k":"` is 6 bytes; 505 ASCII bytes put a 3-byte character across byte 512.
        let value = json!({"k": format!("{}€€", "x".repeat(505))});
        let summary = jcs::summary(&jcs::jcs(&value));
        assert_eq!(summary.len(), 511);
        assert_eq!(summary, format!("{{\"k\":\"{}", "x".repeat(505)));
    }

    #[test]
    fn input_sha256_is_over_the_full_jcs_bytes_before_truncation() {
        let value = json!({"content": "y".repeat(2000), "file_path": "a.txt"});
        let bytes = jcs::jcs(&value);
        assert!(bytes.len() > 512);
        use sha2::Digest;
        let expected: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        assert_eq!(jcs::input_sha256(&bytes), expected);
        let other =
            jcs::jcs(&json!({"content": format!("{}z", "y".repeat(1999)), "file_path": "a.txt"}));
        assert_eq!(jcs::summary(&bytes), jcs::summary(&other));
        assert_ne!(jcs::input_sha256(&bytes), jcs::input_sha256(&other));
    }

    #[test]
    fn readonly_rule_requires_tool_set_and_realpath_inside_workspace() {
        let root = temp("ro");
        let outside = temp("ro-out");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), "x").unwrap();
        std::fs::write(outside.join("secret"), "x").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), root.join("src/link")).unwrap();
        let workspace = std::fs::canonicalize(&root).unwrap();
        let file = workspace.join("src/a.rs");
        assert!(readonly("Read", &json!({"file_path": file}), &workspace));
        assert!(readonly(
            "Read",
            &json!({"file_path": "src/a.rs"}),
            &workspace
        ));
        assert!(readonly(
            "Grep",
            &json!({"pattern": "x", "path": "src"}),
            &workspace
        ));
        assert!(readonly("Grep", &json!({"pattern": "x"}), &workspace));
        assert!(readonly("Glob", &json!({"pattern": "**/*.rs"}), &workspace));
        assert!(readonly("LS", &json!({}), &workspace));
        assert!(!readonly("Write", &json!({"file_path": file}), &workspace));
        assert!(!readonly("Bash", &json!({"command": "ls"}), &workspace));
        assert!(!readonly("Read", &json!({}), &workspace));
        assert!(!readonly(
            "Read",
            &json!({"file_path": "src/missing.rs"}),
            &workspace
        ));
        assert!(!readonly(
            "Read",
            &json!({"file_path": "src/link"}),
            &workspace
        ));
        assert!(!readonly(
            "Read",
            &json!({"file_path": outside.join("secret")}),
            &workspace
        ));
        assert!(!readonly("LS", &json!({"path": "src/../.."}), &workspace));
        assert!(!readonly("Grep", &json!({"path": 7}), &workspace));
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn glob_pattern_with_dotdot_substring_or_leading_slash_waits_for_human() {
        let root = temp("glob");
        let workspace = std::fs::canonicalize(&root).unwrap();
        assert!(readonly(
            "Glob",
            &json!({"pattern": "src/*.rs"}),
            &workspace
        ));
        for pattern in ["../*", "a..b", "src/**/..", "/etc/*"] {
            assert!(
                !readonly("Glob", &json!({"pattern": pattern}), &workspace),
                "{pattern}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn responses_echo_input_on_allow_and_carry_codes_on_deny() {
        let input = json!({"file_path": "a.txt", "content": "z"});
        let decode = |bytes: Vec<u8>| serde_json::from_slice::<Value>(&bytes).unwrap();
        assert_eq!(
            decode(response("r1", Decision::Allow, DecidedVia::Cli, &input))["response"]["response"],
            json!({"behavior": "allow", "updatedInput": input})
        );
        for (via, code) in [
            (DecidedVia::Cli, "owner_denied"),
            (DecidedVia::Timeout, "permission_timeout"),
            (DecidedVia::RunStopped, "run_stopped"),
        ] {
            assert_eq!(
                decode(response("r1", Decision::Deny, via, &input))["response"]["response"],
                json!({"behavior": "deny", "message": code})
            );
        }
    }

    #[test]
    fn notice_text_fills_tool_and_id_into_the_constant() {
        assert_eq!(
            notice("Write", "hp0123456789"),
            "CrabCode 请求使用工具 Write。在本机执行 openmybot approve hp0123456789 放行，或 openmybot deny hp0123456789 拒绝。"
        );
    }
}
