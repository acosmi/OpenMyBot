//! Source inventory for privileged, non-wire authority constructors.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const CONSTRUCTORS: [&str; 4] = [
    "from_verified_source",
    "from_verified_grant",
    "from_verified_delegation",
    "from_verified_pending_input",
];

#[test]
fn authority_constructors_remain_at_registered_production_call_sites() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let test_modules = [
        (
            "crates/openbot-contracts/src/auth_delegation_tests.rs",
            "crates/openbot-contracts/src/auth.rs",
            "#[cfg(test)]\n#[path = \"auth_delegation_tests.rs\"]\nmod delegation_tests;",
        ),
        (
            "crates/openbot-application/src/delegated_authority_tests.rs",
            "crates/openbot-application/src/app.rs",
            "#[cfg(test)]\n#[path = \"delegated_authority_tests.rs\"]\nmod delegated_authority_tests;",
        ),
        (
            "crates/openbot-application/src/delegation_tests.rs",
            "crates/openbot-application/src/lib.rs",
            "#[cfg(test)]\nmod delegation_tests;",
        ),
    ];
    for (_, owner, registration) in &test_modules {
        assert!(
            fs::read_to_string(root.join(owner))
                .unwrap()
                .contains(registration),
            "test-only registration changed: {owner}"
        );
    }
    let allowed = [
        (
            "from_verified_source",
            "crates/openbot-server/src/http/automation_ingress.rs",
            1usize,
        ),
        (
            "from_verified_grant",
            "crates/openbot-application/src/delegation.rs",
            1,
        ),
        (
            "from_verified_delegation",
            "crates/openbot-application/src/delegation.rs",
            1,
        ),
        (
            "from_verified_pending_input",
            "crates/openbot-application/src/pending_input.rs",
            1,
        ),
    ];
    let mut found = BTreeMap::new();
    let mut accept_calls = BTreeMap::new();
    for entry in fs::read_dir(root.join("crates")).unwrap() {
        let source = entry.unwrap().path().join("src");
        if !source.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&source, &mut files);
        for path in files {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            if test_modules.iter().any(|(test, _, _)| relative == *test) {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = production_tokens(&source);
            // `accept` is a common method name; count it only where the ingress entry is named.
            if production.contains(&"AutomationDeliveryEntry") {
                let calls = production
                    .windows(3)
                    .filter(|tokens| *tokens == [".", "accept", "("])
                    .count();
                if calls > 0 {
                    accept_calls.insert(relative.clone(), calls);
                }
            }
            for constructor in production_references(&source) {
                assert!(
                    allowed
                        .iter()
                        .any(|(name, caller, _)| *name == constructor && *caller == relative),
                    "unregistered production authority reference: {relative}: {constructor}"
                );
                *found
                    .entry((constructor.to_owned(), relative.clone()))
                    .or_insert(0usize) += 1;
            }
        }
    }
    assert_eq!(
        accept_calls,
        BTreeMap::from([(
            "crates/openbot-server/src/http/automation_ingress.rs".to_owned(),
            1usize
        )]),
        "AutomationDeliveryEntry::accept call sites changed"
    );
    for (name, path, count) in allowed {
        assert_eq!(
            found
                .get(&(name.to_owned(), path.to_owned()))
                .copied()
                .unwrap_or(0),
            count,
            "inventory changed for {name} in {path}"
        );
    }
}

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            rust_files(&entry.path(), files);
        } else if kind.is_file() && entry.path().extension().is_some_and(|v| v == "rs") {
            files.push(entry.path());
        }
    }
}

fn production_references(source: &str) -> Vec<&str> {
    production_tokens(source)
        .windows(2)
        .filter_map(|pair| (pair[0] == "::" && CONSTRUCTORS.contains(&pair[1])).then_some(pair[1]))
        .collect()
}

fn production_tokens(source: &str) -> Vec<&str> {
    let tokens = tokens(source);
    let mut production = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at..].starts_with(&["#", "[", "cfg", "(", "test", ")", "]"]) {
            at += 7;
            while tokens.get(at) == Some(&"#") && tokens.get(at + 1) == Some(&"[") {
                at = after_group(&tokens, at + 1, "[", "]");
            }
            while at < tokens.len() && tokens[at] != "{" && tokens[at] != ";" {
                at += 1;
            }
            if tokens.get(at) == Some(&"{") {
                at = after_group(&tokens, at, "{", "}");
            } else {
                at += 1;
            }
        } else {
            production.push(tokens[at]);
            at += 1;
        }
    }
    production
}
fn after_group(tokens: &[&str], start: usize, open: &str, close: &str) -> usize {
    let mut depth = 0;
    for (at, token) in tokens.iter().enumerate().skip(start) {
        if *token == open {
            depth += 1;
        } else if *token == close {
            depth -= 1;
            if depth == 0 {
                return at + 1;
            }
        }
    }
    panic!("unbalanced source group");
}

// Only identifiers and delimiters matter. Strings and nested comments cannot contribute calls
// or braces, including SQL/raw strings inside a test module.
fn tokens(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    while at < bytes.len() {
        if bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if bytes[at..].starts_with(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if bytes[at..].starts_with(b"/*") {
            at += 2;
            let mut depth = 1;
            while at < bytes.len() && depth > 0 {
                if bytes[at..].starts_with(b"/*") {
                    depth += 1;
                    at += 2;
                } else if bytes[at..].starts_with(b"*/") {
                    depth -= 1;
                    at += 2;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        let mut quote = at;
        if bytes.get(quote) == Some(&b'b') || bytes.get(quote) == Some(&b'c') {
            quote += 1;
        }
        if bytes.get(quote) == Some(&b'r') {
            quote += 1;
            let hashes_start = quote;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let hashes = quote - hashes_start;
                at = quote + 1;
                while at < bytes.len() {
                    if bytes[at] == b'"'
                        && bytes
                            .get(at + 1..at + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|v| *v == b'#'))
                    {
                        at += 1 + hashes;
                        break;
                    }
                    at += 1;
                }
                continue;
            }
        }
        let quote = if matches!(bytes[at], b'b' | b'c') && bytes.get(at + 1) == Some(&b'"') {
            at + 1
        } else {
            at
        };
        if bytes.get(quote) == Some(&b'"') {
            at = quote + 1;
            while at < bytes.len() {
                if bytes[at] == b'\\' {
                    at = (at + 2).min(bytes.len());
                } else if bytes[at] == b'"' {
                    at += 1;
                    break;
                } else {
                    at += 1;
                }
            }
            continue;
        }
        // Recognize character literals without consuming ordinary lifetimes such as 'a.
        let quote = if bytes[at] == b'b' && bytes.get(at + 1) == Some(&b'\'') {
            at + 1
        } else {
            at
        };
        if bytes.get(quote) == Some(&b'\'') {
            let end = if bytes.get(quote + 1) == Some(&b'\\') {
                (quote + 2..bytes.len().min(quote + 16)).find(|i| bytes[*i] == b'\'')
            } else {
                source
                    .get(quote + 1..)
                    .and_then(|tail| tail.chars().next())
                    .map(|c| quote + 1 + c.len_utf8())
                    .filter(|i| bytes.get(*i) == Some(&b'\''))
            };
            if let Some(end) = end {
                at = end + 1;
                continue;
            }
        }
        let start = at;
        if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            at += 1;
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
        } else if bytes[at..].starts_with(b"::") {
            at += 2;
        } else {
            at += source[at..].chars().next().unwrap().len_utf8();
        }
        out.push(&source[start..at]);
    }
    out
}

#[test]
fn test_items_are_excluded_without_hiding_later_production_items() {
    let source = r####"
        #[cfg(test)] mod tests {
            fn fixture() { let sql = r#"SELECT '{'"#; Type::from_verified_grant(); }
        }
        #[cfg(test)]
        #[tokio::test] async fn fixture() { Type::from_verified_delegation(); }
        fn actual() { Type :: from_verified_pending_input (); }
    "####;
    assert_eq!(
        production_references(source),
        ["from_verified_pending_input"]
    );
}
#[test]
fn comments_and_rust_strings_cannot_forge_constructor_call_sites() {
    let source = r####"
        // Type::from_verified_grant()
        /* /* nested */ Type::from_verified_delegation() */
        const TEXT: &str = r###"Type::from_verified_source() { }"###;
        fn actual<'a>() { let c = '}'; let b = b'{'; Type::from_verified_grant(); }
    "####;
    assert_eq!(production_references(source), ["from_verified_grant"]);
}
