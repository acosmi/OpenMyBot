//! The version window: CrabCode versions accepted after a recorded real-host recheck.
use crate::spawn::SpawnSpec;
use omb_store::EndReason;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, time::Duration};
use tokio::io::AsyncReadExt;

/// One accepted version with the arguments and environment it was verified with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedVersion {
    pub version: String,
    pub extra_args: Vec<String>,
    pub extra_env: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WindowError {
    #[error("window_invalid")]
    Invalid,
}
/// Immutable after parsing.
#[derive(Clone, Debug)]
pub struct VersionWindow(Vec<AcceptedVersion>);

const ENTRY_FIELDS: [&str; 7] = [
    "version",
    "extra_args",
    "extra_env",
    "gates",
    "verified_at",
    "engine_commit",
    "record",
];
const GATES: [&str; 6] = ["G1", "G2", "G3", "G4", "G5", "G6"];

fn object(value: &Value, fields: &[&str]) -> Result<Map<String, Value>, WindowError> {
    let map = value.as_object().ok_or(WindowError::Invalid)?;
    if map.len() != fields.len() || !fields.iter().all(|field| map.contains_key(*field)) {
        return Err(WindowError::Invalid);
    }
    Ok(map.clone())
}
fn text(value: &Value) -> Result<String, WindowError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(WindowError::Invalid)
}

impl VersionWindow {
    /// The manifest compiled into this binary.
    pub fn embedded() -> Self {
        Self::parse(include_str!(
            "../../../openmybot/compat/crabcode/accepted.json"
        ))
        .expect("embedded version window parses")
    }
    /// Closed schema: unknown fields, a gate other than `pass` or a malformed commit refuse the
    /// whole manifest; `gates`, `verified_at`, `engine_commit` and `record` are dropped after
    /// validation.
    pub fn parse(json: &str) -> Result<Self, WindowError> {
        let root: Value = serde_json::from_str(json).map_err(|_| WindowError::Invalid)?;
        let root = object(&root, &["accepted"])?;
        root["accepted"]
            .as_array()
            .ok_or(WindowError::Invalid)?
            .iter()
            .map(|entry| {
                let entry = object(entry, &ENTRY_FIELDS)?;
                let gates = object(&entry["gates"], &GATES)?;
                if !gates.values().all(|gate| gate == "pass") {
                    return Err(WindowError::Invalid);
                }
                let commit = text(&entry["engine_commit"])?;
                if commit.len() != 40
                    || !commit
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(WindowError::Invalid);
                }
                text(&entry["verified_at"])?;
                text(&entry["record"])?;
                Ok(AcceptedVersion {
                    version: text(&entry["version"])?,
                    extra_args: entry["extra_args"]
                        .as_array()
                        .ok_or(WindowError::Invalid)?
                        .iter()
                        .map(text)
                        .collect::<Result<_, _>>()?,
                    extra_env: entry["extra_env"]
                        .as_object()
                        .ok_or(WindowError::Invalid)?
                        .iter()
                        .map(|(key, value)| Ok((key.clone(), text(value)?)))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
    /// Exact string match.
    pub fn lookup(&self, version: &str) -> Option<&AcceptedVersion> {
        self.0.iter().find(|accepted| accepted.version == version)
    }
    /// The entry whose arguments and environment a start probes with.
    pub(crate) fn first(&self) -> Option<&AcceptedVersion> {
        self.0.first()
    }
}

/// The first `X.Y.Z` of the first line.
pub(crate) fn parse_version_line(output: &str) -> Option<String> {
    let line = output.lines().next()?.as_bytes();
    let digits = |from: usize| {
        line[from..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count()
    };
    (0..line.len())
        .filter(|&start| {
            line[start].is_ascii_digit() && (start == 0 || !line[start - 1].is_ascii_digit())
        })
        .find_map(|start| {
            let mut end = start;
            for part in 0..3 {
                if part > 0 {
                    if line.get(end) != Some(&b'.') {
                        return None;
                    }
                    end += 1;
                }
                let count = digits(end);
                if count == 0 {
                    return None;
                }
                end += count;
            }
            Some(String::from_utf8_lossy(&line[start..end]).into_owned())
        })
}

/// Runs `<binary> --version` with the run's environment and working directory; the child gets
/// no input. Only `VersionRejected` and `SpawnFailed` are returned as errors.
pub(crate) async fn verify<'w>(
    spec: &SpawnSpec<'_>,
    window: &'w VersionWindow,
    timeout: Duration,
) -> Result<&'w AcceptedVersion, EndReason> {
    let mut child = spec
        .command(true)
        .spawn()
        .map_err(|_| EndReason::SpawnFailed)?;
    drop(child.stdin.take());
    let mut stdout = child.stdout.take().ok_or(EndReason::SpawnFailed)?;
    let mut output = Vec::new();
    let finished = tokio::time::timeout(timeout, async {
        let read = (&mut stdout)
            .take(crate::CC_LINE_MAX as u64)
            .read_to_end(&mut output)
            .await;
        (read, child.wait().await)
    })
    .await;
    let version = match finished {
        Ok((Ok(_), Ok(_))) => parse_version_line(&String::from_utf8_lossy(&output)),
        _ => {
            if let Some(pid) = child
                .id()
                .and_then(|id| rustix::process::Pid::from_raw(id as i32))
            {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = child.wait().await;
            None
        }
    };
    version
        .and_then(|version| window.lookup(&version))
        .ok_or(EndReason::VersionRejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    fn entry(commit: &str, gate: &str, extra: &str) -> String {
        format!(
            r#"{{"version":"1.1.16","extra_args":["--x"],"extra_env":{{"K":"V"}},"gates":{{"G1":"pass","G2":"pass","G3":"pass","G4":"pass","G5":"{gate}","G6":"pass"}},"verified_at":"2026-10-28T00:00:00Z","engine_commit":"{commit}","record":"compat/crabcode/1.1.16.md"{extra}}}"#
        )
    }
    fn manifest(entry: &str) -> String {
        format!(r#"{{"accepted":[{entry}]}}"#)
    }

    #[test]
    fn parse_accepts_closed_schema() {
        let window = VersionWindow::parse(&manifest(&entry(COMMIT, "pass", ""))).unwrap();
        assert_eq!(
            window.lookup("1.1.16"),
            Some(&AcceptedVersion {
                version: "1.1.16".into(),
                extra_args: vec!["--x".into()],
                extra_env: BTreeMap::from([("K".into(), "V".into())]),
            })
        );
        assert!(
            VersionWindow::parse(r#"{"accepted":[]}"#)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn parse_rejects_unknown_fields_failed_gate_short_commit() {
        let upper = COMMIT.to_uppercase();
        for json in [
            manifest(&entry(COMMIT, "pass", r#","extra":1"#)),
            r#"{"accepted":[],"other":1}"#.to_string(),
            manifest(&entry(COMMIT, "fail", "")),
            manifest(&entry(&COMMIT[..39], "pass", "")),
            manifest(&entry(&format!("{COMMIT}0"), "pass", "")),
            manifest(&entry(&upper, "pass", "")),
            manifest(
                &entry(COMMIT, "pass", "").replace(r#","record":"compat/crabcode/1.1.16.md""#, ""),
            ),
            manifest(
                &entry(COMMIT, "pass", "").replace(r#""G6":"pass""#, r#""G6":"pass","G7":"pass""#),
            ),
            manifest(&entry(COMMIT, "pass", "").replace(r#"["--x"]"#, "[1]")),
            "not json".into(),
        ] {
            assert_eq!(
                VersionWindow::parse(&json).unwrap_err(),
                WindowError::Invalid,
                "{json}"
            );
        }
    }

    #[test]
    fn version_line_takes_first_xyz_of_first_line() {
        assert_eq!(
            parse_version_line("crabcode 1.1.16\n").as_deref(),
            Some("1.1.16")
        );
        assert_eq!(
            parse_version_line("1.1.16 (CrabCode)").as_deref(),
            Some("1.1.16")
        );
        assert_eq!(
            parse_version_line("crabcode 1.1 build 7\n").as_deref(),
            None
        );
        assert_eq!(parse_version_line("crabcode\n1.1.16\n"), None);
        assert_eq!(parse_version_line(""), None);
    }

    #[test]
    fn lookup_is_exact() {
        let window = VersionWindow::parse(&manifest(&entry(COMMIT, "pass", ""))).unwrap();
        assert!(window.lookup("1.1.16").is_some());
        for version in ["1.1.17", "1.1", "01.1.16", "1.1.16 ", ""] {
            assert!(window.lookup(version).is_none(), "{version}");
        }
    }

    #[test]
    fn embedded_manifest_parses() {
        let window = VersionWindow::embedded();
        assert!(window.0.iter().all(|accepted| !accepted.version.is_empty()));
    }
}
