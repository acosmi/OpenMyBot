//! The per-host parameter table: every host here speaks the SDK control protocol and differs
//! only in these values.
use omb_store::HostKind;

pub struct HostProfile {
    /// Used only in notice and template texts; the stable identifier is the `HostKind`.
    pub display_name: &'static str,
    /// The fixed arguments after the binary.
    pub(crate) prefix: &'static [&'static str],
    /// Refused anywhere after the prefix; `--x=y` is checked as `--x`.
    pub(crate) forbidden: &'static [&'static str],
    /// Refused as the start of any argument after the prefix.
    pub(crate) forbidden_prefixes: &'static [&'static str],
    /// Refused in a window entry's `extra_env`.
    pub(crate) forbidden_env: &'static [&'static str],
    pub(crate) readonly_tools: &'static [&'static str],
    /// The embedded `compat/<host>/accepted.json`.
    pub(crate) window: &'static str,
}

const CRABCODE: HostProfile = HostProfile {
    display_name: "wrok Code",
    prefix: &[
        "--print",
        "--",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--permission-mode",
        "default",
        "--permission-prompt-tool",
        "stdio",
    ],
    forbidden: &[
        "--sdk-url",
        "--dangerously-skip-permissions",
        "--allowedTools",
        "--allowed-tools",
        "bypassPermissions",
        "acceptEdits",
        "remote-control",
    ],
    forbidden_prefixes: &["account:"],
    forbidden_env: &["CRABCODE_PRINT_APP_SERVER"],
    readonly_tools: &crate::CC_READONLY_TOOLS,
    window: include_str!("../../../openmybot/compat/crabcode/accepted.json"),
};
const CLAUDE: HostProfile = HostProfile {
    display_name: "Claude Code",
    prefix: &[
        "--print",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--verbose",
        "--permission-mode",
        "default",
        "--permission-prompt-tool",
        "stdio",
        "--setting-sources=",
        "--strict-mcp-config",
    ],
    forbidden: &[
        "--permission-mode",
        "--permission-prompt-tool",
        "--permission-prompts",
        "--setting-sources",
        "--settings",
        "--managed-settings",
        "--sdk-url",
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "--allowedTools",
        "--allowed-tools",
        "--plugin-dir",
        "--plugin-url",
        "--remote-control",
        "--bg",
        "--background",
        "--cloud",
    ],
    forbidden_prefixes: &[],
    forbidden_env: &[],
    readonly_tools: &["Read", "Grep", "Glob"],
    window: include_str!("../../../openmybot/compat/claude/accepted.json"),
};

pub fn profile(kind: HostKind) -> &'static HostProfile {
    match kind {
        HostKind::Crabcode => &CRABCODE,
        HostKind::Claude => &CLAUDE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_names_follow_the_host_table() {
        assert_eq!(profile(HostKind::Crabcode).display_name, "wrok Code");
        assert_eq!(profile(HostKind::Claude).display_name, "Claude Code");
    }
    #[test]
    fn readonly_tools_follow_the_host_table() {
        assert_eq!(
            profile(HostKind::Crabcode).readonly_tools,
            ["Read", "Grep", "Glob", "LS"]
        );
        assert_eq!(
            profile(HostKind::Claude).readonly_tools,
            ["Read", "Grep", "Glob"]
        );
    }
}
