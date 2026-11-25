//! Syntax highlighting and token coloring for Markdown code blocks.
//!
//! Enforces GUI Design Specification §6.4:
//! - Closed 24-language SyntaxSet packed into an offline asset.
//! - Strict mapping from scopes to 6 design token colors:
//!   - `text-fg`: base text, variables, identifiers
//!   - `text-fg-secondary`: operators, punctuation, delimiters
//!   - `text-fg-muted`: comments, docstrings
//!   - `text-info`: keywords, storage, functions, types
//!   - `text-success`: strings, character literals
//!   - `text-caution`: numbers, constants, boolean literals
//! - Bounded fallback for unknown languages and plain text.

use std::sync::OnceLock;
use syntect::dumps::from_uncompressed_data;
use syntect::parsing::{ParseState, Scope, ScopeStack, SyntaxReference, SyntaxSet};

/// Statically cached 24-language SyntaxSet.
static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();

/// Prefix scopes for fast token category resolution.
struct ScopeMatcher {
    comment: Scope,
    string: Scope,
    constant: Scope,
    punctuation: Scope,
    operator: Scope,
    keyword: Scope,
    storage: Scope,
    entity_fn: Scope,
    entity_class: Scope,
    entity_type: Scope,
    support_fn: Scope,
    support_type: Scope,
}

static SCOPE_MATCHER: OnceLock<ScopeMatcher> = OnceLock::new();

fn matcher() -> &'static ScopeMatcher {
    SCOPE_MATCHER.get_or_init(|| ScopeMatcher {
        comment: Scope::new("comment").expect("valid scope"),
        string: Scope::new("string").expect("valid scope"),
        constant: Scope::new("constant").expect("valid scope"),
        punctuation: Scope::new("punctuation").expect("valid scope"),
        operator: Scope::new("keyword.operator").expect("valid scope"),
        keyword: Scope::new("keyword").expect("valid scope"),
        storage: Scope::new("storage").expect("valid scope"),
        entity_fn: Scope::new("entity.name.function").expect("valid scope"),
        entity_class: Scope::new("entity.name.class").expect("valid scope"),
        entity_type: Scope::new("entity.name.type").expect("valid scope"),
        support_fn: Scope::new("support.function").expect("valid scope"),
        support_type: Scope::new("support.type").expect("valid scope"),
    })
}

/// Returns a reference to the global 24-language SyntaxSet.
pub fn get_syntax_set() -> &'static SyntaxSet {
    SYNTAX_SET.get_or_init(|| {
        let dump_bytes = include_bytes!("../../../../design/markdown/openbot_syntaxes.packdump");
        from_uncompressed_data(dump_bytes).expect("corrupt openbot_syntaxes.packdump")
    })
}

/// Resolves a language identifier or fence token to a syntax reference in the 24-language set.
pub fn resolve_syntax(lang: &str) -> &'static SyntaxReference {
    let set = get_syntax_set();
    let trimmed = lang.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "text" || trimmed == "plaintext" || trimmed == "txt" {
        return set.find_syntax_plain_text();
    }

    // Direct token lookup or alias map for the 24 languages.
    let canonical = match trimmed.as_str() {
        "sh" | "bash" | "shell" | "zsh" => "bash",
        "powershell" | "pwsh" | "ps1" => "powershell",
        "rust" | "rs" => "rust",
        "toml" | "tml" => "toml",
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "sql" => "sql",
        "ts" | "typescript" => "ts",
        "tsx" => "tsx",
        "js" | "javascript" => "js",
        "jsx" => "jsx",
        "html" | "htm" => "html",
        "css" => "css",
        "md" | "markdown" => "md",
        "py" | "python" => "py",
        "go" | "golang" => "go",
        "java" => "java",
        "kotlin" | "kt" | "kts" => "kotlin",
        "swift" => "swift",
        "c" => "c",
        "cpp" | "c++" | "cc" | "cxx" => "cpp",
        "diff" | "patch" => "diff",
        "dockerfile" | "docker" | "containerfile" => "dockerfile",
        _ => return set.find_syntax_plain_text(),
    };

    set.find_syntax_by_token(canonical)
        .or_else(|| set.find_syntax_by_extension(canonical))
        .or_else(|| set.find_syntax_by_name(canonical))
        .unwrap_or_else(|| set.find_syntax_plain_text())
}

/// Highlighted token span within a line of code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighlightedSpan {
    /// Token text slice.
    pub text: String,
    /// Design token utility class (`text-fg`, `text-fg-secondary`, `text-fg-muted`, `text-info`, `text-success`, `text-caution`).
    pub class: &'static str,
}

/// Highlights one line while preserving parser and scope state across the complete code block.
fn highlight_line(
    line: &str,
    state: &mut ParseState,
    stack: &mut ScopeStack,
) -> Result<Vec<HighlightedSpan>, ()> {
    let set = get_syntax_set();
    let ops = state.parse_line(line, set).map_err(|_| ())?;
    let mut spans = Vec::new();
    let mut last_index = 0;

    for (index, op) in ops {
        if index > last_index {
            let text = line.get(last_index..index).ok_or(())?;
            if !text.is_empty() {
                spans.push(HighlightedSpan {
                    text: text.to_owned(),
                    class: scope_class(stack),
                });
            }
            last_index = index;
        }
        stack.apply(&op).map_err(|_| ())?;
    }

    if last_index < line.len() {
        let text = line.get(last_index..).ok_or(())?;
        if !text.is_empty() {
            spans.push(HighlightedSpan {
                text: text.to_owned(),
                class: scope_class(stack),
            });
        }
    }

    Ok(spans)
}

fn scope_class(stack: &ScopeStack) -> &'static str {
    let m = matcher();
    for &scope in stack.as_slice().iter().rev() {
        if m.comment.is_prefix_of(scope) {
            return "text-fg-muted";
        }
        if m.string.is_prefix_of(scope) {
            return "text-success";
        }
        if m.constant.is_prefix_of(scope) {
            return "text-caution";
        }
        if m.punctuation.is_prefix_of(scope) || m.operator.is_prefix_of(scope) {
            return "text-fg-secondary";
        }
        if m.keyword.is_prefix_of(scope)
            || m.storage.is_prefix_of(scope)
            || m.entity_fn.is_prefix_of(scope)
            || m.entity_class.is_prefix_of(scope)
            || m.entity_type.is_prefix_of(scope)
            || m.support_fn.is_prefix_of(scope)
            || m.support_type.is_prefix_of(scope)
        {
            return "text-info";
        }
    }
    "text-fg"
}

/// Highlights an entire multiline block of code.
pub fn highlight_code(code: &str, lang: &str) -> Vec<Vec<HighlightedSpan>> {
    // Preserve all text while bounding expensive grammar matching. Large blocks use one plain span.
    if code.len() > 64 * 1024
        || code.lines().any(|line| line.len() > 8 * 1024)
        || code.lines().count() > 2048
    {
        return vec![vec![HighlightedSpan {
            text: code.to_owned(),
            class: "text-fg",
        }]];
    }
    let syntax = resolve_syntax(lang);
    let mut state = ParseState::new(syntax);
    let mut scopes = ScopeStack::new();
    let mut lines = Vec::new();
    let mut failed = false;

    // Ensure proper newline handling per syntect requirements.
    for raw_line in code.split_inclusive('\n') {
        let highlighted = if failed {
            Err(())
        } else {
            highlight_line(raw_line, &mut state, &mut scopes)
        };
        match highlighted {
            Ok(spans) => lines.push(spans),
            Err(()) => {
                failed = true;
                lines.push(vec![HighlightedSpan {
                    text: raw_line.to_owned(),
                    class: "text-fg",
                }]);
            }
        }
    }

    if lines.is_empty() {
        lines.push(vec![HighlightedSpan {
            text: String::new(),
            class: "text-fg",
        }]);
    }

    lines
}
