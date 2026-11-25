//! `cargo xtask release check`: layer-by-layer verification of an assembled `Wrok Bot.app`
//! (spec revision R485, V5-RELEASE-01) written as one evidence JSON.
//!
//! The evidence records the actual signature of every Mach-O, the Gatekeeper and stapler results
//! and the launcher's own `--check-release`. An ad-hoc signature is reported as
//! `not_release_identity` and never as passed. Engine and helper are not part of this bundle and
//! are recorded as `not_included`.
//!
//! `artifact_digest` algorithm `wrok-bot-app-tree-sha256-v1`: walk the `.app` directory without
//! following symlinks, depth first with entries sorted by file name; for each entry append one
//! line with its path relative to the directory containing the `.app` (so it starts with
//! `Wrok Bot.app`):
//! `d <mode> <path>\n` for a directory, `f <mode> <size> <sha256> <path>\n` for a regular file,
//! `l <target> <path>\n` for a symlink, where `<mode>` is the octal permission bits (`& 0o7777`)
//! and `<sha256>` lower-case hex of the content. The digest is the SHA-256 of the concatenation.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use walkdir::WalkDir;

use crate::release_app::EXECUTABLE;
use crate::release_sign::{self, OUTPUT_LIMIT, Options, run_bounded};

const DIGEST_ALGORITHM: &str = "wrok-bot-app-tree-sha256-v1";
const EVIDENCE_FILE: &str = "release-check-evidence.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Passed,
    Failed,
    NotReleaseIdentity,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    schema_version: u32,
    verdict: Verdict,
    artifact_digest: ArtifactDigest,
    declared_arch: String,
    expected_team: Option<String>,
    commands: Vec<CommandRecord>,
    mach_o: Vec<MachORecord>,
    not_evaluated: Vec<NotEvaluated>,
}

#[derive(Serialize)]
struct ArtifactDigest {
    algorithm: &'static str,
    sha256: String,
}

#[derive(Serialize)]
struct CommandRecord {
    name: &'static str,
    argv: Vec<String>,
    exit_code: Option<i32>,
    output_sha256: String,
    output: String,
    output_truncated: bool,
}

#[derive(Serialize)]
struct MachORecord {
    path: String,
    architectures: Vec<String>,
    signature: &'static str,
    authority: Option<String>,
    team: Option<String>,
    designated_requirement: Option<String>,
    hardened_runtime: bool,
    problems: Vec<String>,
}

#[derive(Serialize)]
struct NotEvaluated {
    component: &'static str,
    status: &'static str,
}

fn record(name: &'static str, argv: Vec<String>) -> Result<CommandRecord> {
    let output = run_bounded(Command::new(&argv[0]).args(&argv[1..]), OUTPUT_LIMIT)?;
    let bytes = [output.stdout, output.stderr].concat();
    Ok(CommandRecord {
        name,
        exit_code: output.status.code(),
        output_sha256: format!("{:x}", Sha256::digest(&bytes)),
        output: String::from_utf8_lossy(&bytes).into_owned(),
        output_truncated: output.truncated,
        argv,
    })
}

pub(crate) fn tree_digest(app: &Path) -> Result<String> {
    let base = app.parent().context("app has no parent directory")?;
    let mut hasher = Sha256::new();
    for entry in WalkDir::new(app).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path().strip_prefix(base)?.display().to_string();
        let metadata = entry.path().symlink_metadata()?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.is_dir() {
            writeln!(hasher, "d {mode:o} {path}")?;
        } else if metadata.is_file() {
            let mut content = Sha256::new();
            io::copy(&mut fs::File::open(entry.path())?, &mut content)?;
            let size = metadata.len();
            writeln!(hasher, "f {mode:o} {size} {:x} {path}", content.finalize())?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(entry.path())?;
            writeln!(hasher, "l {} {path}", target.display())?;
        } else {
            bail!("{path} is not a file, directory or symlink");
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn mach_o_record(app: &Path, path: &Path, declared_arch: &str) -> Result<MachORecord> {
    let lipo = run_bounded(
        Command::new("/usr/bin/lipo").arg("-archs").arg(path),
        OUTPUT_LIMIT,
    )?
    .require_success("lipo -archs")?;
    let architectures: Vec<String> = String::from_utf8_lossy(&lipo.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let mut problems = Vec::new();
    if architectures != [declared_arch] {
        problems.push(format!(
            "architectures differ from declared {declared_arch}"
        ));
    }
    let relative = path.strip_prefix(app)?.display().to_string();
    let Some(signature) = release_sign::inspect(path)? else {
        problems.push("unsigned".to_owned());
        return Ok(MachORecord {
            path: relative,
            architectures,
            signature: "unsigned",
            authority: None,
            team: None,
            designated_requirement: None,
            hardened_runtime: false,
            problems,
        });
    };
    let (ad_hoc, hardened_runtime) = (signature.ad_hoc(), signature.hardened_runtime());
    if !hardened_runtime {
        problems.push("hardened runtime missing".to_owned());
    }
    if !ad_hoc {
        let anchored = match (&signature.team, &signature.requirement) {
            (Some(team), Some(requirement)) => {
                requirement.starts_with("identifier ")
                    && requirement.contains("anchor apple generic")
                    && requirement.contains(team.as_str())
                    && !requirement.contains("cdhash")
            }
            _ => false,
        };
        if !anchored {
            problems.push("designated requirement is not identifier + anchor + Team ID".to_owned());
        }
    }
    Ok(MachORecord {
        path: relative,
        architectures,
        signature: if ad_hoc { "ad_hoc" } else { "developer_id" },
        authority: signature.authority,
        team: signature.team,
        designated_requirement: signature.requirement,
        hardened_runtime,
        problems,
    })
}

/// A bundle signed only ad-hoc is a development build whatever its other results; the command
/// records still show them. A release identity passes only when every command and Mach-O passes.
fn verdict(
    commands: &[CommandRecord],
    mach_o: &mut [MachORecord],
    expected_team: Option<&str>,
) -> Verdict {
    if mach_o.iter().all(|record| record.signature == "ad_hoc") {
        return Verdict::NotReleaseIdentity;
    }
    let teams: BTreeSet<_> = mach_o
        .iter()
        .filter_map(|record| record.team.clone())
        .collect();
    for record in mach_o.iter_mut() {
        if record.signature == "ad_hoc" {
            record
                .problems
                .push("ad-hoc component in a release identity bundle".to_owned());
        }
        if teams.len() > 1 {
            record
                .problems
                .push("Team IDs differ across Mach-O files".to_owned());
        }
        if let Some(expected) = expected_team
            && record.team.as_deref() != Some(expected)
        {
            record
                .problems
                .push(format!("Team ID is not the expected {expected}"));
        }
    }
    if commands.iter().all(|command| command.exit_code == Some(0))
        && mach_o.iter().all(|record| record.problems.is_empty())
    {
        Verdict::Passed
    } else {
        Verdict::Failed
    }
}

/// Run every check, write `<out>/release-check-evidence.json`, and fail unless the verdict is
/// `passed`; the evidence is written in every case.
pub(crate) fn check(app: &Path, expected_team: Option<&str>, out: &Path) -> Result<()> {
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(
        app.join("Contents/Resources/wrok-bot-release.json"),
    )?)
    .context("parse the bundled release manifest")?;
    let declared_arch = match manifest.get("arch").and_then(serde_json::Value::as_str) {
        Some("aarch64") => "arm64",
        Some("x86_64") => "x86_64",
        _ => bail!("bundled release manifest declares no supported arch"),
    };
    let app_arg = app.display().to_string();
    let launcher = app
        .join("Contents/MacOS")
        .join(EXECUTABLE)
        .display()
        .to_string();
    let mut commands = vec![record(
        "codesign_verify",
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=2",
            app_arg.as_str(),
        ]
        .map(str::to_owned)
        .to_vec(),
    )?];
    let mut mach_o = release_sign::mach_o_files(app)?
        .iter()
        .map(|path| mach_o_record(app, path, declared_arch))
        .collect::<Result<Vec<_>>>()?;
    for (name, argv) in [
        (
            "spctl_assess",
            vec![
                "/usr/sbin/spctl",
                "-a",
                "-vv",
                "-t",
                "exec",
                app_arg.as_str(),
            ],
        ),
        (
            "stapler_validate",
            vec!["/usr/bin/xcrun", "stapler", "validate", app_arg.as_str()],
        ),
        (
            "launcher_check_release",
            vec![launcher.as_str(), "--check-release"],
        ),
    ] {
        commands.push(record(name, argv.into_iter().map(str::to_owned).collect())?);
    }
    let verdict = verdict(&commands, &mut mach_o, expected_team);
    let evidence = Evidence {
        schema: "wrok-bot-release-check",
        schema_version: 1,
        verdict,
        artifact_digest: ArtifactDigest {
            algorithm: DIGEST_ALGORITHM,
            sha256: tree_digest(app)?,
        },
        declared_arch: declared_arch.to_owned(),
        expected_team: expected_team.map(str::to_owned),
        commands,
        mach_o,
        not_evaluated: Vec::from(["engine", "helper"].map(|component| NotEvaluated {
            component,
            status: "not_included",
        })),
    };
    fs::create_dir_all(out)?;
    let path = out.join(EVIDENCE_FILE);
    fs::write(&path, serde_json::to_vec_pretty(&evidence)?)?;
    let failing: Vec<_> = evidence
        .commands
        .iter()
        .filter(|command| command.exit_code != Some(0))
        .map(|command| command.name)
        .collect();
    println!(
        "release check: verdict {} artifact_digest {DIGEST_ALGORITHM}:{} failing commands {failing:?} evidence {}",
        serde_json::to_value(verdict)?.as_str().unwrap_or_default(),
        evidence.artifact_digest.sha256,
        path.display()
    );
    match verdict {
        Verdict::Passed => Ok(()),
        Verdict::NotReleaseIdentity => {
            bail!("ad-hoc signature is not a release identity; the bundle is a development build")
        }
        Verdict::Failed => bail!("release check failed; see {}", path.display()),
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &[])?;
    let app = release_sign::existing(&options.required("app")?)?;
    let expected_team = options.optional("expect-team")?;
    let out = std::path::PathBuf::from(options.required("out")?);
    options.finish()?;
    if !out.is_absolute() {
        bail!("release_absolute_path_required: --out");
    }
    check(&app, expected_team.as_deref(), &out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_sign::tests::temp_dir;

    fn command(name: &'static str, exit_code: i32) -> CommandRecord {
        CommandRecord {
            name,
            argv: vec![name.to_owned()],
            exit_code: Some(exit_code),
            output_sha256: String::new(),
            output: String::new(),
            output_truncated: false,
        }
    }

    fn mach_o(signature: &'static str, team: Option<&str>) -> MachORecord {
        MachORecord {
            path: "Contents/MacOS/wrok-bot".to_owned(),
            architectures: vec!["arm64".to_owned()],
            signature,
            authority: None,
            team: team.map(str::to_owned),
            designated_requirement: None,
            hardened_runtime: true,
            problems: Vec::new(),
        }
    }

    fn keys(value: &serde_json::Value) -> Vec<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn evidence_json_field_set_is_closed() {
        let evidence = Evidence {
            schema: "wrok-bot-release-check",
            schema_version: 1,
            verdict: Verdict::NotReleaseIdentity,
            artifact_digest: ArtifactDigest {
                algorithm: DIGEST_ALGORITHM,
                sha256: String::new(),
            },
            declared_arch: "arm64".to_owned(),
            expected_team: None,
            commands: vec![command("codesign_verify", 0)],
            mach_o: vec![mach_o("ad_hoc", None)],
            not_evaluated: vec![NotEvaluated {
                component: "engine",
                status: "not_included",
            }],
        };
        let value = serde_json::to_value(&evidence).unwrap();
        let mut top = keys(&value);
        top.sort_unstable();
        assert_eq!(
            top,
            [
                "artifact_digest",
                "commands",
                "declared_arch",
                "expected_team",
                "mach_o",
                "not_evaluated",
                "schema",
                "schema_version",
                "verdict",
            ]
        );
        let mut nested = [
            keys(&value["artifact_digest"]),
            keys(&value["commands"][0]),
            keys(&value["mach_o"][0]),
            keys(&value["not_evaluated"][0]),
        ];
        nested.iter_mut().for_each(|keys| keys.sort_unstable());
        assert_eq!(
            nested,
            [
                vec!["algorithm", "sha256"],
                vec![
                    "argv",
                    "exit_code",
                    "name",
                    "output",
                    "output_sha256",
                    "output_truncated"
                ],
                vec![
                    "architectures",
                    "authority",
                    "designated_requirement",
                    "hardened_runtime",
                    "path",
                    "problems",
                    "signature",
                    "team",
                ],
                vec!["component", "status"],
            ]
        );
        assert_eq!(value["verdict"], "not_release_identity");
    }

    #[test]
    fn ad_hoc_is_never_passed_and_teams_must_agree() {
        let commands = |failing: Option<usize>| {
            [
                "codesign_verify",
                "spctl_assess",
                "stapler_validate",
                "launcher_check_release",
            ]
            .into_iter()
            .enumerate()
            .map(|(index, name)| command(name, i32::from(failing == Some(index))))
            .collect::<Vec<_>>()
        };
        let team = Some("ABCDE12345");
        for failing in [None, Some(0), Some(3)] {
            assert_eq!(
                verdict(&commands(failing), &mut [mach_o("ad_hoc", None)], team),
                Verdict::NotReleaseIdentity
            );
        }
        assert_eq!(
            verdict(&commands(None), &mut [mach_o("developer_id", team)], team),
            Verdict::Passed
        );
        assert_eq!(
            verdict(
                &commands(None),
                &mut [mach_o("developer_id", team)],
                Some("OTHER")
            ),
            Verdict::Failed
        );
        assert_eq!(
            verdict(
                &commands(None),
                &mut [mach_o("developer_id", team), mach_o("ad_hoc", None)],
                team
            ),
            Verdict::Failed
        );
        assert_eq!(
            verdict(
                &commands(None),
                &mut [
                    mach_o("developer_id", team),
                    mach_o("developer_id", Some("OTHER"))
                ],
                None
            ),
            Verdict::Failed
        );
        for failing in 0..4 {
            assert_eq!(
                verdict(
                    &commands(Some(failing)),
                    &mut [mach_o("developer_id", team)],
                    team
                ),
                Verdict::Failed
            );
        }
    }

    #[test]
    fn tree_digest_is_deterministic_and_covers_content_and_mode() {
        let dir = temp_dir("digest");
        let app = dir.join("Wrok Bot.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(app.join("Contents/MacOS/wrok-bot"), b"a").unwrap();
        let first = tree_digest(&app).unwrap();
        assert_eq!(first, tree_digest(&app).unwrap());
        fs::write(app.join("Contents/MacOS/wrok-bot"), b"b").unwrap();
        let changed = tree_digest(&app).unwrap();
        assert_ne!(first, changed);
        fs::set_permissions(
            app.join("Contents/MacOS/wrok-bot"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_ne!(changed, tree_digest(&app).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
}
