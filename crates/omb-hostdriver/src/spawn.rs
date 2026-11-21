//! Child construction: argv, the forbidden-token check, the closed environment and the group.
use crate::host::HostProfile;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) struct SpawnSpec<'a> {
    pub profile: &'static HostProfile,
    pub binary: &'a Path,
    /// Already the workspace's real path.
    pub cwd: &'a Path,
    pub home: &'a Path,
    pub tmp_dir: &'a Path,
    pub extra_args: &'a [String],
    pub extra_env: &'a BTreeMap<String, String>,
    pub resume: Option<&'a str>,
}
impl SpawnSpec<'_> {
    /// `[binary, host prefix…, (--resume <id>)?, extra_args…]`; the binary is the configured
    /// absolute path, never searched on `PATH`.
    pub(crate) fn argv(&self) -> Vec<OsString> {
        let mut argv = vec![self.binary.as_os_str().to_owned()];
        argv.extend(self.profile.prefix.iter().map(OsString::from));
        if let Some(id) = self.resume {
            argv.push("--resume".into());
            argv.push(id.into());
        }
        argv.extend(self.extra_args.iter().map(OsString::from));
        argv
    }
    /// Any argument after the host prefix that is a forbidden word (`--x=y` checked as `--x`)
    /// or starts with a forbidden prefix.
    pub(crate) fn refused(&self) -> bool {
        let profile = self.profile;
        self.argv()[1 + profile.prefix.len()..]
            .iter()
            .any(|argument| {
                let argument = argument.to_string_lossy();
                let word = match argument.split_once('=') {
                    Some((flag, _)) if flag.starts_with("--") => flag,
                    _ => &argument,
                };
                profile.forbidden.contains(&word)
                    || profile
                        .forbidden_prefixes
                        .iter()
                        .any(|prefix| argument.starts_with(prefix))
            })
    }
    /// SHA-256 over the arguments after the binary, joined by NUL.
    pub(crate) fn args_sha256(&self) -> [u8; 32] {
        let argv = self.argv();
        let mut digest = Sha256::new();
        for (index, argument) in argv[1..].iter().enumerate() {
            if index > 0 {
                digest.update([0]);
            }
            digest.update(argument.as_encoded_bytes());
        }
        digest.finalize().into()
    }
    /// The run and the `--version` probe share this construction; only argv differs.
    pub(crate) fn command(&self, version_probe: bool) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(self.binary);
        if version_probe {
            command.arg("--version");
        } else {
            command.args(&self.argv()[1..]);
        }
        let mut path = OsString::from("/usr/bin:/bin:/usr/sbin:/sbin:");
        path.push(self.binary.parent().unwrap_or(Path::new("/")));
        command
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home)
            .env("LANG", "en_US.UTF-8")
            .env("TERM", "dumb")
            .env("TMPDIR", self.tmp_dir)
            .env("OPENMYBOT_HOST_DRIVER_CHILD", "1")
            .envs(self.extra_env)
            .current_dir(self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        command
    }
}

/// One reserved place among the driver's live children, released when dropped.
pub(crate) struct Slot(Arc<AtomicUsize>);
impl Slot {
    pub(crate) fn reserve(children: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        children
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                (live < max).then_some(live + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(children)))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::profile;
    use omb_store::HostKind;
    use std::path::PathBuf;

    struct Owned {
        kind: HostKind,
        binary: PathBuf,
        extra_args: Vec<String>,
        extra_env: BTreeMap<String, String>,
        resume: Option<String>,
    }
    impl Owned {
        fn new() -> Self {
            Self {
                kind: HostKind::Crabcode,
                binary: PathBuf::from("/opt/crab/bin/crabcode"),
                extra_args: Vec::new(),
                extra_env: BTreeMap::new(),
                resume: None,
            }
        }
        fn spec(&self) -> SpawnSpec<'_> {
            SpawnSpec {
                profile: profile(self.kind),
                binary: &self.binary,
                cwd: Path::new("/work"),
                home: Path::new("/home/owner"),
                tmp_dir: Path::new("/data/hosts/crabcode/tmp"),
                extra_args: &self.extra_args,
                extra_env: &self.extra_env,
                resume: self.resume.as_deref(),
            }
        }
    }
    fn strings(argv: Vec<OsString>) -> Vec<String> {
        argv.into_iter().map(|a| a.into_string().unwrap()).collect()
    }

    #[test]
    fn argv_is_binary_print_double_dash_then_closed_flags_then_resume_then_extra_args() {
        let mut owned = Owned::new();
        owned.extra_args = vec!["--model".into(), "m".into()];
        let base = [
            "/opt/crab/bin/crabcode",
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
        ];
        let mut expected: Vec<&str> = base.to_vec();
        expected.extend(["--model", "m"]);
        assert_eq!(strings(owned.spec().argv()), expected);
        owned.resume = Some("session-1".into());
        let mut expected: Vec<&str> = base.to_vec();
        expected.extend(["--resume", "session-1", "--model", "m"]);
        assert_eq!(strings(owned.spec().argv()), expected);
        let command = owned.spec().command(false);
        assert_eq!(command.as_std().get_program(), "/opt/crab/bin/crabcode");
        assert_eq!(
            command
                .as_std()
                .get_args()
                .map(|a| a.to_str().unwrap())
                .collect::<Vec<_>>(),
            expected[1..]
        );
        let probe = owned.spec().command(true);
        assert_eq!(
            probe.as_std().get_args().collect::<Vec<_>>(),
            vec!["--version"]
        );
    }

    #[test]
    fn claude_argv_has_no_double_dash_and_adds_verbose_and_isolated_sources() {
        let mut owned = Owned::new();
        owned.kind = HostKind::Claude;
        owned.binary = PathBuf::from("/opt/homebrew/bin/claude");
        owned.resume = Some("s1".into());
        owned.extra_args = vec!["--model".into(), "m".into()];
        assert_eq!(
            strings(owned.spec().argv()),
            [
                "/opt/homebrew/bin/claude",
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
                "--resume",
                "s1",
                "--model",
                "m",
            ]
        );
        // The prefix itself carries words that are forbidden after it.
        assert!(!owned.spec().refused());
    }

    #[test]
    fn forbidden_tokens_are_refused_in_every_argument_after_the_prefix() {
        for kind in HostKind::ALL {
            let mut owned = Owned::new();
            owned.kind = kind;
            assert!(!owned.spec().refused(), "{kind:?}");
            for token in profile(kind).forbidden {
                owned.extra_args = vec!["--verbose".into(), (*token).into()];
                owned.resume = None;
                assert!(owned.spec().refused(), "{kind:?} extra {token}");
                owned.extra_args = Vec::new();
                owned.resume = Some((*token).into());
                assert!(owned.spec().refused(), "{kind:?} resume {token}");
                if token.starts_with("--") {
                    owned.resume = None;
                    owned.extra_args = vec![format!("{token}=x")];
                    assert!(owned.spec().refused(), "{kind:?} {token}=x");
                }
            }
            owned.resume = Some("session".into());
            owned.extra_args = vec!["--allowedToolsX".into(), "acceptEdits2".into()];
            assert!(!owned.spec().refused(), "{kind:?}");
        }
        let mut owned = Owned::new();
        owned.extra_args = vec!["--model".into(), "account:work".into()];
        assert!(owned.spec().refused());
        owned.extra_args = vec!["--model".into(), "acct:work".into()];
        assert!(!owned.spec().refused());
        // `--settings` is CrabCode's verified extra argument and forbidden only for Claude Code.
        owned.extra_args = vec!["--settings".into(), "{}".into()];
        assert!(!owned.spec().refused());
        owned.kind = HostKind::Claude;
        assert!(owned.spec().refused());
        owned.extra_args = vec!["--model".into(), "account:work".into()];
        assert!(!owned.spec().refused());
    }

    #[test]
    fn environment_is_exactly_the_closed_set() {
        let mut owned = Owned::new();
        owned.extra_env = BTreeMap::from([("CRABCODE_CONFIG_DIR".into(), "cfg".into())]);
        for probe in [false, true] {
            let command = owned.spec().command(probe);
            let env: BTreeMap<String, Option<String>> = command
                .as_std()
                .get_envs()
                .map(|(k, v)| {
                    (
                        k.to_str().unwrap().to_owned(),
                        v.map(|v| v.to_str().unwrap().to_owned()),
                    )
                })
                .collect();
            let expected: BTreeMap<String, Option<String>> = [
                ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/crab/bin"),
                ("HOME", "/home/owner"),
                ("LANG", "en_US.UTF-8"),
                ("TERM", "dumb"),
                ("TMPDIR", "/data/hosts/crabcode/tmp"),
                ("OPENMYBOT_HOST_DRIVER_CHILD", "1"),
                ("CRABCODE_CONFIG_DIR", "cfg"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), Some(v.to_owned())))
            .collect();
            assert_eq!(env, expected);
            assert_eq!(command.as_std().get_current_dir(), Some(Path::new("/work")));
        }
    }

    #[test]
    fn args_sha256_is_over_argv_after_binary_joined_by_nul() {
        let mut owned = Owned::new();
        owned.resume = Some("s1".into());
        let joined = "--print\0--\0--input-format\0stream-json\0--output-format\0stream-json\0--permission-mode\0default\0--permission-prompt-tool\0stdio\0--resume\0s1";
        let expected: [u8; 32] = Sha256::digest(joined.as_bytes()).into();
        assert_eq!(owned.spec().args_sha256(), expected);
        owned.binary = PathBuf::from("/other/crabcode");
        assert_eq!(owned.spec().args_sha256(), expected);
    }
}
