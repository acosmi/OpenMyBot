//! `cargo xtask release sign-components | sign-app | notarize`: macOS code signing and
//! notarization of the Desktop release (spec revision R485, section 16.2 signing order).
//!
//! The signing identity and the notarytool keychain profile are names supplied by the release
//! operator. This module never reads, accepts or prints a password and never runs a keychain
//! command: `codesign` and `notarytool` resolve the named identity and profile themselves.
//! The default identity `-` is ad-hoc, which is never a release identity.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use walkdir::WalkDir;

/// Retained bytes per stream of every release subprocess; the rest is drained and dropped.
pub(crate) const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    AdHoc,
    /// The signing certificate's common name, as `codesign` reports it in its first `Authority=`.
    Named(String),
}

impl Identity {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value == "-" {
            return Ok(Self::AdHoc);
        }
        if value.trim() != value || value.starts_with('-') || value.chars().any(char::is_control) {
            bail!("release_identity_invalid");
        }
        Ok(Self::Named(value.to_owned()))
    }

    fn codesign_args(&self) -> [&str; 2] {
        match self {
            Self::AdHoc => ["-", "--timestamp=none"],
            Self::Named(name) => [name.as_str(), "--timestamp"],
        }
    }
}

/// Closed `--key value` option set of one release subcommand. `flags` take no value.
pub(crate) struct Options(BTreeMap<String, Vec<String>>);

impl Options {
    pub(crate) fn parse(args: &[String], flags: &[&str]) -> Result<Self> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let key = arg
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or_else(|| anyhow!("release_option_invalid: {arg}"))?;
            let value = if flags.contains(&key) {
                String::new()
            } else {
                args.next()
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .ok_or_else(|| anyhow!("release_option_value_required: --{key}"))?
            };
            map.entry(key.to_owned()).or_default().push(value);
        }
        Ok(Self(map))
    }

    pub(crate) fn all(&mut self, key: &str) -> Vec<String> {
        self.0.remove(key).unwrap_or_default()
    }

    pub(crate) fn optional(&mut self, key: &str) -> Result<Option<String>> {
        let mut values = self.all(key);
        if values.len() > 1 {
            bail!("release_option_duplicate: --{key}");
        }
        Ok(values.pop())
    }

    pub(crate) fn required(&mut self, key: &str) -> Result<String> {
        self.optional(key)?
            .ok_or_else(|| anyhow!("release_option_missing: --{key}"))
    }

    pub(crate) fn flag(&mut self, key: &str) -> bool {
        self.0.remove(key).is_some()
    }

    pub(crate) fn finish(self) -> Result<()> {
        match self.0.keys().next() {
            Some(key) => bail!("release_option_unknown: --{key}"),
            None => Ok(()),
        }
    }
}

/// An existing input path, canonicalised once so the launcher's canonical-root check holds.
pub(crate) fn existing(value: &str) -> Result<PathBuf> {
    fs::canonicalize(value).with_context(|| format!("release input {value} is not accessible"))
}

pub(crate) struct Bounded {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) truncated: bool,
}

impl Bounded {
    pub(crate) fn require_success(self, what: &str) -> Result<Self> {
        if !self.status.success() {
            bail!(
                "{what} failed with {}: {}",
                self.status,
                String::from_utf8_lossy(&self.stderr).trim()
            );
        }
        Ok(self)
    }
}

/// Run a subprocess keeping at most `limit` bytes of each stream; both pipes are drained to EOF
/// so a verbose tool can neither block nor grow memory.
pub(crate) fn run_bounded(command: &mut Command, limit: usize) -> Result<Bounded> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", command.get_program().to_string_lossy()))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stderr = std::thread::spawn(move || read_bounded(stderr, limit));
    let (stdout, stdout_cut) = read_bounded(stdout, limit)?;
    let (stderr, stderr_cut) = stderr.join().expect("stderr reader thread")?;
    Ok(Bounded {
        status: child.wait()?,
        stdout,
        stderr,
        truncated: stdout_cut || stderr_cut,
    })
}

fn read_bounded(mut pipe: impl Read, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    pipe.by_ref().take(limit as u64).read_to_end(&mut kept)?;
    let dropped = io::copy(&mut pipe, &mut io::sink())?;
    Ok((kept, dropped > 0))
}

pub(crate) fn is_mach_o(path: &Path) -> Result<bool> {
    let mut head = Vec::with_capacity(4);
    fs::File::open(path)?.take(4).read_to_end(&mut head)?;
    Ok(matches!(
        head.as_slice(),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf]
            | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
    ))
}

/// Regular Mach-O files under `root` in a deterministic order; symlinks are not followed.
pub(crate) fn mach_o_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_file() && is_mach_o(entry.path())? {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

/// The subset of `codesign -d -r- -vvv` that release signing and checking evaluate.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Signature {
    pub(crate) flags: u32,
    pub(crate) authority: Option<String>,
    pub(crate) team: Option<String>,
    pub(crate) requirement: Option<String>,
}

impl Signature {
    pub(crate) fn parse(info: &str, requirements: &str) -> Result<Self> {
        let mut signature = Self::default();
        let mut flags = None;
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("CodeDirectory ") {
                flags = rest
                    .split_once("flags=0x")
                    .and_then(|(_, rest)| rest.split_once('('))
                    .and_then(|(digits, _)| u32::from_str_radix(digits, 16).ok());
            } else if let Some(value) = line.strip_prefix("Authority=") {
                signature.authority.get_or_insert_with(|| value.to_owned());
            } else if let Some(value) = line.strip_prefix("TeamIdentifier=") {
                signature.team = (value != "not set").then(|| value.to_owned());
            }
        }
        signature.flags = flags.context("codesign CodeDirectory flags missing")?;
        signature.requirement = requirements
            .lines()
            .find_map(|line| line.trim_start_matches("# ").strip_prefix("designated => "))
            .map(str::to_owned);
        Ok(signature)
    }

    pub(crate) fn ad_hoc(&self) -> bool {
        self.flags & 0x2 != 0
    }

    pub(crate) fn hardened_runtime(&self) -> bool {
        self.flags & 0x1_0000 != 0
    }

    /// Hardened runtime under exactly the requested identity; linker-only ad-hoc stamps do not count.
    fn matches(&self, identity: &Identity) -> bool {
        self.hardened_runtime()
            && match identity {
                Identity::AdHoc => self.ad_hoc() && self.flags & 0x2_0000 == 0,
                Identity::Named(name) => !self.ad_hoc() && self.authority.as_deref() == Some(name),
            }
    }
}

/// `None` when `codesign -d` reports the code as unsigned.
pub(crate) fn inspect(path: &Path) -> Result<Option<Signature>> {
    let output = run_bounded(
        Command::new("/usr/bin/codesign")
            .args(["-d", "-r-", "-vvv"])
            .arg(path),
        OUTPUT_LIMIT,
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.truncated {
        bail!("codesign metadata of {} exceeded the bound", path.display());
    }
    Signature::parse(
        &String::from_utf8_lossy(&output.stderr),
        &String::from_utf8_lossy(&output.stdout),
    )
    .map(Some)
}

fn verify_strict(path: &Path) -> Result<()> {
    run_bounded(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(path),
        OUTPUT_LIMIT,
    )?
    .require_success(&format!("codesign --verify --strict {}", path.display()))
    .map(drop)
}

/// Sign with hardened runtime (secure timestamp for a real identity), then require that the
/// result verifies strictly and carries exactly the requested identity.
fn codesign(path: &Path, identity: &Identity, entitlements: Option<&Path>) -> Result<()> {
    let [name, timestamp] = identity.codesign_args();
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["--sign", name, "--force", "--options", "runtime", timestamp]);
    if let Some(entitlements) = entitlements {
        command.arg("--entitlements").arg(entitlements);
    }
    run_bounded(command.arg(path), OUTPUT_LIMIT)?
        .require_success(&format!("codesign {}", path.display()))?;
    verify_strict(path)?;
    if !inspect(path)?.is_some_and(|signature| signature.matches(identity)) {
        bail!(
            "{} is not signed with the requested identity",
            path.display()
        );
    }
    Ok(())
}

/// Sign every Mach-O found by its magic bytes under the inputs, innermost first, before any
/// digest of them is taken; no component path is hard-coded, so any nested directory is covered.
/// A file that already carries the requested hardened signature (for example from the
/// PostgreSQL bundle build) is only verified; `verify_only` turns any other file into an error.
pub(crate) fn sign_components(
    inputs: &[PathBuf],
    identity: &Identity,
    verify_only: bool,
) -> Result<usize> {
    let mut count = 0;
    for input in inputs {
        let mut files = mach_o_files(input)?;
        files.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in files {
            if inspect(&path)?.is_some_and(|signature| signature.matches(identity)) {
                verify_strict(&path)?;
                println!("verified {}", path.display());
            } else if verify_only {
                bail!(
                    "component {} is not signed with the requested identity",
                    path.display()
                );
            } else {
                codesign(&path, identity, None)?;
                println!("signed {}", path.display());
            }
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn run_sign_components(args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &["verify-only"])?;
    let inputs = options
        .all("root-inputs")
        .iter()
        .map(|value| existing(value))
        .collect::<Result<Vec<_>>>()?;
    let identity = Identity::parse(&options.optional("identity")?.unwrap_or_else(|| "-".into()))?;
    let verify_only = options.flag("verify-only");
    options.finish()?;
    if inputs.is_empty() {
        bail!("release_option_missing: --root-inputs");
    }
    let count = sign_components(&inputs, &identity, verify_only)?;
    println!("release sign-components: {count} Mach-O file(s) carry the requested identity");
    Ok(())
}

/// Sign every nested Mach-O under `Contents/Resources` (already signed release-root components
/// are only verified, so their digests hold), then the outer app last. Entitlements apply only to
/// the outer app and are an explicit reviewed input; none by default.
pub(crate) fn sign_app(app: &Path, identity: &Identity, entitlements: Option<&Path>) -> Result<()> {
    if let Some(entitlements) = entitlements
        && plist::Value::from_file(entitlements)?
            .as_dictionary()
            .is_none()
    {
        bail!(
            "entitlements {} is not a plist dictionary",
            entitlements.display()
        );
    }
    sign_components(&[app.join("Contents/Resources")], identity, false)?;
    codesign(app, identity, entitlements)
}

pub(crate) fn run_sign_app(args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &[])?;
    let app = existing(&options.required("app")?)?;
    let identity = Identity::parse(&options.optional("identity")?.unwrap_or_else(|| "-".into()))?;
    let entitlements = options
        .optional("entitlements")?
        .map(|value| existing(&value))
        .transpose()?;
    options.finish()?;
    sign_app(&app, &identity, entitlements.as_deref())?;
    println!("release sign-app: signed {}", app.display());
    Ok(())
}

/// Only a profile name is accepted; the stored credentials stay inside notarytool.
pub(crate) fn keychain_profile(value: &str) -> Result<String> {
    if value.starts_with('-') || value.chars().any(char::is_control) {
        bail!("release_keychain_profile_invalid");
    }
    Ok(value.to_owned())
}

/// The exact zip, submit and staple commands, in execution order.
pub(crate) fn notarize_commands(app: &Path, profile: &str, out: &Path) -> [Vec<String>; 3] {
    let app = app.display().to_string();
    let zip = out
        .join(format!(
            "{}.zip",
            Path::new(&app)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
        ))
        .display()
        .to_string();
    [
        [
            "/usr/bin/ditto",
            "-c",
            "-k",
            "--keepParent",
            app.as_str(),
            zip.as_str(),
        ]
        .map(str::to_owned)
        .to_vec(),
        [
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            zip.as_str(),
            "--keychain-profile",
            profile,
            "--wait",
            "--output-format",
            "json",
        ]
        .map(str::to_owned)
        .to_vec(),
        ["/usr/bin/xcrun", "stapler", "staple", app.as_str()]
            .map(str::to_owned)
            .to_vec(),
    ]
}

pub(crate) fn shell_words(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if !arg.is_empty()
                && arg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@+,".contains(&b))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Zip, submit with `--wait`, keep only the submission id and status, require `Accepted`, staple.
pub(crate) fn notarize(app: &Path, profile: &str, out: &Path, dry_run: bool) -> Result<()> {
    let [zip, submit, staple] = notarize_commands(app, profile, out);
    if dry_run {
        for argv in [&zip, &submit, &staple] {
            println!("{}", shell_words(argv));
        }
        return Ok(());
    }
    fs::create_dir_all(out)?;
    run_bounded(Command::new(&zip[0]).args(&zip[1..]), OUTPUT_LIMIT)?.require_success("ditto")?;
    let submitted = run_bounded(Command::new(&submit[0]).args(&submit[1..]), OUTPUT_LIMIT)?;
    let response: serde_json::Value = serde_json::from_slice(&submitted.stdout)
        .with_context(|| format!("notarytool submit returned {}", submitted.status))?;
    let record = serde_json::json!({
        "id": response.get("id"),
        "status": response.get("status"),
        "exit_code": submitted.status.code(),
    });
    let log = out.join("notarytool-submit.json");
    fs::write(&log, serde_json::to_vec_pretty(&record)?)?;
    if !submitted.status.success() || response.get("status") != Some(&"Accepted".into()) {
        bail!(
            "notarization was not accepted (see {}; `xcrun notarytool log <id>` shows Apple's report)",
            log.display()
        );
    }
    run_bounded(Command::new(&staple[0]).args(&staple[1..]), OUTPUT_LIMIT)?
        .require_success("stapler staple")?;
    println!("release notarize: accepted and stapled {}", app.display());
    Ok(())
}

pub(crate) fn run_notarize(args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &["dry-run"])?;
    let profile = keychain_profile(&options.required("keychain-profile")?)?;
    let app = existing(&options.required("app")?)?;
    let out = PathBuf::from(options.required("out")?);
    let dry_run = options.flag("dry-run");
    options.finish()?;
    if !out.is_absolute() {
        bail!("release_absolute_path_required: --out");
    }
    notarize(&app, &profile, &out, dry_run)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "release-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::canonicalize(dir).unwrap()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn subprocess_output_is_bounded_and_both_streams_drain() {
        let output = run_bounded(
            Command::new("/bin/sh").args([
                "-c",
                "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2; exit 3",
            ]),
            1024,
        )
        .unwrap();
        assert_eq!((output.stdout.len(), output.stderr.len()), (1024, 1024));
        assert!(output.truncated);
        assert_eq!(output.status.code(), Some(3));
        let small = run_bounded(Command::new("/bin/echo").arg("ok"), 1024).unwrap();
        assert_eq!(
            (small.stdout.as_slice(), small.truncated),
            (&b"ok\n"[..], false)
        );
    }

    #[test]
    fn signature_metadata_distinguishes_ad_hoc_linker_and_developer() {
        let ad_hoc = Signature::parse(
            "CodeDirectory v=20500 size=1 flags=0x10002(adhoc,runtime) hashes=2+2\n\
             Signature=adhoc\nTeamIdentifier=not set\n",
            "# designated => cdhash H\"00\"\n",
        )
        .unwrap();
        assert!(ad_hoc.matches(&Identity::AdHoc));
        assert_eq!(ad_hoc.requirement.as_deref(), Some("cdhash H\"00\""));
        let linker =
            Signature::parse("CodeDirectory v=1 flags=0x20002(adhoc,linker-signed)\n", "").unwrap();
        assert!(!linker.matches(&Identity::AdHoc));
        let name = "Developer ID Application: Example (ABCDE12345)";
        let developer = Signature::parse(
            &format!(
                "CodeDirectory v=1 flags=0x10000(runtime)\nAuthority={name}\n\
                 Authority=Developer ID Certification Authority\nTeamIdentifier=ABCDE12345\n"
            ),
            "designated => identifier \"x\" and anchor apple generic\n",
        )
        .unwrap();
        assert_eq!(developer.team.as_deref(), Some("ABCDE12345"));
        assert!(developer.matches(&Identity::Named(name.into())));
        assert!(!developer.matches(&Identity::AdHoc));
        assert!(!developer.matches(&Identity::Named("Other".into())));
        assert!(Signature::parse("Executable=/x\n", "").is_err());
    }

    #[test]
    fn components_are_signed_hardened_once_then_only_verified() {
        let dir = temp_dir("components");
        fs::create_dir(dir.join("bin")).unwrap();
        fs::copy("/usr/bin/true", dir.join("bin/tool")).unwrap();
        fs::write(dir.join("bin/README"), b"not code").unwrap();
        // Any later nested directory is found by content, not by a known path.
        fs::create_dir_all(dir.join("any-plugin/nested")).unwrap();
        fs::copy("/usr/bin/true", dir.join("any-plugin/nested/plugin")).unwrap();
        let inputs = [dir.clone()];
        assert!(sign_components(&inputs, &Identity::AdHoc, true).is_err());
        assert_eq!(
            sign_components(&inputs, &Identity::AdHoc, false).unwrap(),
            2
        );
        assert!(
            inspect(&dir.join("any-plugin/nested/plugin"))
                .unwrap()
                .unwrap()
                .matches(&Identity::AdHoc)
        );
        let signed = fs::read(dir.join("bin/tool")).unwrap();
        assert!(
            inspect(&dir.join("bin/tool"))
                .unwrap()
                .unwrap()
                .matches(&Identity::AdHoc)
        );
        assert_eq!(sign_components(&inputs, &Identity::AdHoc, true).unwrap(), 2);
        assert_eq!(fs::read(dir.join("bin/tool")).unwrap(), signed);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn notarize_accepts_only_a_profile_name_and_dry_runs_exact_commands() {
        let dir = temp_dir("notarize");
        let app = dir.join("Wrok Bot.app");
        fs::create_dir(&app).unwrap();
        let app_arg = app.display().to_string();
        let out = dir.join("out").display().to_string();
        let missing = run_notarize(&strings(&["--app", &app_arg, "--out", &out]));
        assert!(
            missing
                .unwrap_err()
                .to_string()
                .contains("--keychain-profile")
        );
        for secret in ["--password", "--apple-id", "--key"] {
            let args = strings(&[
                "--app",
                &app_arg,
                "--out",
                &out,
                "--keychain-profile",
                "p",
                secret,
                "x",
            ]);
            assert!(run_notarize(&args).is_err(), "{secret} must be rejected");
        }
        assert!(keychain_profile("--wait").is_err());
        let [zip, submit, staple] = notarize_commands(&app, "release-profile", &dir);
        assert_eq!(
            zip[..4],
            strings(&["/usr/bin/ditto", "-c", "-k", "--keepParent"])
        );
        assert_eq!(zip[5], dir.join("Wrok Bot.zip").display().to_string());
        assert_eq!(
            submit[1..],
            strings(&[
                "notarytool",
                "submit",
                &zip[5],
                "--keychain-profile",
                "release-profile",
                "--wait",
                "--output-format",
                "json",
            ])
        );
        assert_eq!(
            staple,
            strings(&["/usr/bin/xcrun", "stapler", "staple", &app_arg])
        );
        let args = strings(&[
            "--app",
            &app_arg,
            "--out",
            &out,
            "--keychain-profile",
            "p",
            "--dry-run",
        ]);
        run_notarize(&args).unwrap();
        assert!(!Path::new(&out).exists(), "dry run must not create output");
        assert_eq!(
            shell_words(&strings(&["/a b/c", "x'y", "--wait"])),
            r"'/a b/c' 'x'\''y' --wait"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
