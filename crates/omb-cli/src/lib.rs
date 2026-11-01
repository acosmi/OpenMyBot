//! Closed local command parsing; credentials never enter arguments. Channel kinds are free words
//! the daemon checks.
use omb_daemon::{DaemonError, ErrorClass};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fmt,
    io::{BufRead, Read},
    path::PathBuf,
};
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Init {
        pg_bin_dir: PathBuf,
    },
    Daemon,
    Status {
        run: Option<String>,
    },
    Pair {
        channel: String,
        workspace: PathBuf,
        run_deadline: Option<u32>,
    },
    BindingsList,
    BindingsRevoke {
        binding_id: String,
    },
    BindingsReconfirm {
        binding_id: String,
    },
    BindingsResetThread {
        binding_id: String,
        ack_unknown: String,
    },
    /// Reads one line of standard input per credential field the channel's plugin declares.
    BindingsReceiver {
        channel: String,
    },
    BindingsHost {
        workspace: PathBuf,
        run_deadline: Option<u32>,
    },
    Approve {
        permission_id: String,
    },
    Deny {
        permission_id: String,
    },
    Cancel {
        run_id: String,
    },
    PluginsList,
    PluginsAdd {
        dir: PathBuf,
    },
    PluginsRemove {
        name: String,
    },
    Mcp,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub data_dir: Option<PathBuf>,
    pub json: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub struct UsageError;
fn absolute(value: &OsString) -> Result<PathBuf, UsageError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(UsageError)
    }
}
pub fn parse_args(args: &[OsString]) -> Result<Invocation, UsageError> {
    let mut data_dir = None;
    let mut json = false;
    let mut words = Vec::new();
    // Each subcommand flag remembers how many command words preceded it.
    let mut flags: Vec<(&str, &OsString, usize)> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str().ok_or(UsageError)? {
            "--json" if !json => json = true,
            "--json" => return Err(UsageError),
            flag if flag.starts_with("--") => {
                index += 1;
                let value = args.get(index).ok_or(UsageError)?;
                if value.as_encoded_bytes().starts_with(b"--") {
                    return Err(UsageError);
                }
                if flag == "--data-dir" && data_dir.is_none() {
                    data_dir = Some(absolute(value)?);
                } else if flag == "--data-dir" || flags.iter().any(|(name, ..)| *name == flag) {
                    return Err(UsageError);
                } else {
                    flags.push((flag, value, words.len()));
                }
            }
            word => words.push(word),
        }
        index += 1;
    }
    let allowed: &[&str] = match words.as_slice() {
        ["init"] => &["--pg-bin-dir"],
        ["status"] => &["--run"],
        ["pair", _] | ["bindings", "host", "crabcode"] => &["--workspace", "--run-deadline"],
        ["bindings", "reset-thread", _] => &["--ack-unknown"],
        _ => &[],
    };
    // Subcommand flags are legal only after all command words.
    if flags
        .iter()
        .any(|(name, _, at)| !allowed.contains(name) || *at != words.len())
    {
        return Err(UsageError);
    }
    let flag = |name: &str| {
        flags
            .iter()
            .find(|(flag, ..)| *flag == name)
            .map(|(_, value, _)| *value)
    };
    let text = |name: &str| {
        flag(name)
            .map(|value| value.to_str().map(str::to_owned).ok_or(UsageError))
            .transpose()
    };
    let workspace = || {
        let path = absolute(flag("--workspace").ok_or(UsageError)?)?;
        path.to_str().ok_or(UsageError)?;
        Ok(path)
    };
    let run_deadline = || {
        text("--run-deadline")?
            .map(|seconds| seconds.parse::<u32>().map_err(|_| UsageError))
            .transpose()
    };
    let command = match words.as_slice() {
        ["init"] => Command::Init {
            pg_bin_dir: absolute(flag("--pg-bin-dir").ok_or(UsageError)?)?,
        },
        ["daemon"] => Command::Daemon,
        ["status"] => Command::Status {
            run: text("--run")?,
        },
        ["pair", channel] if !channel.is_empty() => Command::Pair {
            channel: (*channel).into(),
            workspace: workspace()?,
            run_deadline: run_deadline()?,
        },
        ["bindings", "list"] => Command::BindingsList,
        ["bindings", "revoke", id] => Command::BindingsRevoke {
            binding_id: (*id).into(),
        },
        ["bindings", "reconfirm", id] => Command::BindingsReconfirm {
            binding_id: (*id).into(),
        },
        ["bindings", "reset-thread", id] => Command::BindingsResetThread {
            binding_id: (*id).into(),
            ack_unknown: text("--ack-unknown")?.ok_or(UsageError)?,
        },
        ["bindings", "receiver", channel] if !channel.is_empty() => Command::BindingsReceiver {
            channel: (*channel).into(),
        },
        ["bindings", "host", "crabcode"] => Command::BindingsHost {
            workspace: workspace()?,
            run_deadline: run_deadline()?,
        },
        ["approve", id] => Command::Approve {
            permission_id: (*id).into(),
        },
        ["deny", id] => Command::Deny {
            permission_id: (*id).into(),
        },
        ["cancel", id] => Command::Cancel {
            run_id: (*id).into(),
        },
        ["plugins", "list"] => Command::PluginsList,
        ["plugins", "add", dir] => Command::PluginsAdd {
            dir: absolute(&OsString::from(dir))?,
        },
        ["plugins", "remove", name] => Command::PluginsRemove {
            name: (*name).into(),
        },
        ["mcp"] if !json => Command::Mcp,
        _ => return Err(UsageError),
    };
    Ok(Invocation {
        command,
        data_dir,
        json,
    })
}
impl Command {
    /// The control operation and its arguments; `init`, `daemon` and `mcp` run locally, and the
    /// receiver command asks for its credential fields first.
    pub fn control_request(&self) -> Option<(&'static str, Value)> {
        let with_deadline = |mut args: Value, run_deadline: &Option<u32>| {
            if let Some(seconds) = run_deadline {
                args["run_deadline"] = json!(seconds);
            }
            args
        };
        Some(match self {
            Self::Init { .. } | Self::Daemon | Self::Mcp | Self::BindingsReceiver { .. } => {
                return None;
            }
            Self::Status { run: None } => ("status", json!({})),
            Self::Status { run: Some(run_id) } => ("status_run", json!({"run_id": run_id})),
            Self::Pair {
                channel,
                workspace,
                run_deadline,
            } => (
                "pair_start",
                with_deadline(
                    json!({"channel": channel, "workspace": workspace}),
                    run_deadline,
                ),
            ),
            Self::BindingsList => ("bindings_list", json!({})),
            Self::BindingsRevoke { binding_id } => {
                ("bindings_revoke", json!({"binding_id": binding_id}))
            }
            Self::BindingsReconfirm { binding_id } => {
                ("bindings_reconfirm", json!({"binding_id": binding_id}))
            }
            Self::BindingsResetThread {
                binding_id,
                ack_unknown,
            } => (
                "bindings_reset_thread",
                json!({"binding_id": binding_id, "ack_unknown": ack_unknown}),
            ),
            Self::BindingsHost {
                workspace,
                run_deadline,
            } => (
                "bindings_host",
                with_deadline(json!({"workspace": workspace}), run_deadline),
            ),
            Self::Approve { permission_id } => ("approve", json!({"permission_id": permission_id})),
            Self::Deny { permission_id } => ("deny", json!({"permission_id": permission_id})),
            Self::Cancel { run_id } => ("cancel", json!({"run_id": run_id})),
            Self::PluginsList => ("plugins_list", json!({})),
            Self::PluginsAdd { dir } => ("plugins_add", json!({"dir": dir})),
            Self::PluginsRemove { name } => ("plugins_remove", json!({"name": name})),
        })
    }
}
/// One credential field value read from a line of standard input.
pub struct SecretLine(String);
impl fmt::Debug for SecretLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
/// Restores the terminal modes saved before echo was turned off.
struct EchoOff(rustix::termios::Termios);
impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &self.0,
        );
    }
}
impl SecretLine {
    /// Reads the next line, without echo when `hidden` (a secret on a terminal); one `\n` or
    /// `\r\n` is removed and the rest must be 1–512 bytes of UTF-8.
    pub fn read(reader: &mut impl BufRead, hidden: bool) -> Result<SecretLine, UsageError> {
        let _echo = if hidden {
            let saved = rustix::termios::tcgetattr(std::io::stdin()).map_err(|_| UsageError)?;
            let mut quiet = saved.clone();
            quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
            rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                &quiet,
            )
            .map_err(|_| UsageError)?;
            Some(EchoOff(saved))
        } else {
            None
        };
        let mut line = Vec::new();
        reader
            .by_ref()
            // The 512-byte limit plus 3: room for a `\r\n` ending and one more byte, so an over-long line is detected.
            .take(515)
            .read_until(b'\n', &mut line)
            .map_err(|_| UsageError)?;
        if line.ends_with(b"\n") {
            line.pop();
            if line.ends_with(b"\r") {
                line.pop();
            }
        }
        if line.is_empty() || line.len() > 512 {
            return Err(UsageError);
        }
        String::from_utf8(line)
            .map(SecretLine)
            .map_err(|_| UsageError)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
pub fn exit_code(error: &DaemonError) -> u8 {
    match error.class() {
        ErrorClass::Usage => 2,
        ErrorClass::NotRunning => 3,
        ErrorClass::Rejected => 4,
        ErrorClass::Internal => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omb_daemon::{DataDirectoryInput, StatusOptions, resolve_data_dir};
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    fn command(values: &[&str]) -> Result<Command, UsageError> {
        parse_args(&args(values)).map(|invocation| invocation.command)
    }
    #[test]
    fn parses_init_daemon_status_and_rejects_unknown_names() {
        for command in ["daemon", "status"] {
            assert!(parse_args(&args(&[command])).is_ok());
        }
        assert!(parse_args(&args(&["init", "--pg-bin-dir", "/pg"])).is_ok());
        for values in [
            vec!["unknown"],
            vec!["pair"],
            vec!["approve"],
            vec!["bindings"],
            vec!["bindings", "unknown"],
            vec!["cancel"],
            vec!["deny"],
            vec![],
            vec!["status", "--json", "--json"],
            vec!["daemon", "--pg-bin-dir", "/pg"],
            vec!["status", "--data-dir"],
            vec!["status", "--data-dir", "/one", "--data-dir", "/two"],
            vec!["status", "extra"],
        ] {
            assert_eq!(parse_args(&args(&values)), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn parses_status_with_and_without_run() {
        assert_eq!(command(&["status"]), Ok(Command::Status { run: None }));
        assert_eq!(
            command(&["status", "--run", "r1"]),
            Ok(Command::Status {
                run: Some("r1".into())
            })
        );
        for values in [
            vec!["status", "--run"],
            vec!["status", "--run", "r1", "--run", "r2"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn parses_pair_with_workspace_and_run_deadline() {
        assert_eq!(
            command(&["pair", "telegram", "--workspace", "/ws"]),
            Ok(Command::Pair {
                channel: "telegram".into(),
                workspace: "/ws".into(),
                run_deadline: None
            })
        );
        assert_eq!(
            command(&[
                "pair",
                "feishu",
                "--run-deadline",
                "900",
                "--workspace",
                "/ws"
            ]),
            Ok(Command::Pair {
                channel: "feishu".into(),
                workspace: "/ws".into(),
                run_deadline: Some(900)
            })
        );
        // Any channel word goes to the daemon, which answers `plugin_not_installed`.
        assert_eq!(
            command(&["pair", "slack", "--workspace", "/ws"]),
            Ok(Command::Pair {
                channel: "slack".into(),
                workspace: "/ws".into(),
                run_deadline: None
            })
        );
        for values in [
            vec!["pair", "", "--workspace", "/ws"],
            vec!["pair", "telegram"],
            vec!["pair", "telegram", "--workspace", "ws"],
            vec!["pair", "telegram", "--workspace"],
            vec!["pair", "telegram", "--workspace", "/a", "--workspace", "/b"],
            vec![
                "pair",
                "telegram",
                "--workspace",
                "/ws",
                "--run-deadline",
                "abc",
            ],
            vec![
                "pair",
                "telegram",
                "--workspace",
                "/ws",
                "--run-deadline",
                "-1",
            ],
            vec![
                "pair",
                "telegram",
                "--workspace",
                "/ws",
                "--run-deadline",
                "1.5",
            ],
            vec![
                "pair",
                "telegram",
                "--workspace",
                "/ws",
                "--run-deadline",
                "4294967296",
            ],
            vec!["pair", "telegram", "--workspace", "/ws", "--run-deadline"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn parses_bindings_subcommands_with_their_flags() {
        for (values, expected) in [
            (vec!["bindings", "list"], Command::BindingsList),
            (
                vec!["bindings", "revoke", "b1"],
                Command::BindingsRevoke {
                    binding_id: "b1".into(),
                },
            ),
            (
                vec!["bindings", "reconfirm", "b1"],
                Command::BindingsReconfirm {
                    binding_id: "b1".into(),
                },
            ),
            (
                vec!["bindings", "reset-thread", "b1", "--ack-unknown", "r1"],
                Command::BindingsResetThread {
                    binding_id: "b1".into(),
                    ack_unknown: "r1".into(),
                },
            ),
            (
                vec!["bindings", "receiver", "telegram"],
                Command::BindingsReceiver {
                    channel: "telegram".into(),
                },
            ),
            (
                vec!["bindings", "receiver", "slack"],
                Command::BindingsReceiver {
                    channel: "slack".into(),
                },
            ),
            (
                vec![
                    "bindings",
                    "host",
                    "crabcode",
                    "--workspace",
                    "/ws",
                    "--run-deadline",
                    "60",
                ],
                Command::BindingsHost {
                    workspace: "/ws".into(),
                    run_deadline: Some(60),
                },
            ),
        ] {
            assert_eq!(command(&values), Ok(expected), "{values:?}");
        }
        for values in [
            vec!["bindings", "reset-thread", "b1"],
            vec!["bindings", "receiver"],
            vec!["bindings", "receiver", ""],
            vec!["bindings", "receiver", "feishu", "--app-id", "cli_a"],
            vec!["bindings", "host", "claude", "--workspace", "/ws"],
            vec!["bindings", "host", "crabcode"],
            vec!["bindings", "list", "extra"],
            vec!["bindings", "revoke"],
            vec!["bindings", "list", "--app-id", "x"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn parses_approve_deny_and_cancel_with_one_argument() {
        assert_eq!(
            command(&["approve", "hp1"]),
            Ok(Command::Approve {
                permission_id: "hp1".into()
            })
        );
        assert_eq!(
            command(&["deny", "not-a-uuid"]),
            Ok(Command::Deny {
                permission_id: "not-a-uuid".into()
            })
        );
        assert_eq!(
            command(&["cancel", "run-1"]),
            Ok(Command::Cancel {
                run_id: "run-1".into()
            })
        );
        for name in ["approve", "deny", "cancel"] {
            assert_eq!(command(&[name]), Err(UsageError));
            assert_eq!(command(&[name, "a", "b"]), Err(UsageError));
        }
    }
    #[test]
    fn rejects_unknown_channel_duplicate_flags_missing_values_relative_paths_and_extra_arguments() {
        for values in [
            vec!["pair", "matrix", "extra", "--workspace", "/ws"],
            vec!["bindings", "receiver", "feishu", "--app-id", "a"],
            vec!["bindings", "reset-thread", "b1", "--ack-unknown"],
            vec!["bindings", "host", "crabcode", "--workspace", "relative"],
            vec!["init", "--pg-bin-dir", "relative"],
            vec!["approve", "hp1", "--run", "r1"],
            vec!["bindings", "receiver", "telegram", "token"],
            vec!["status", "--unknown", "x"],
            vec!["cancel", "r1", "r2"],
            vec!["--workspace", "/ws", "pair", "telegram"],
            vec!["bindings", "reset-thread", "--ack-unknown", "r1", "b1"],
            vec!["--pg-bin-dir", "/pg", "init"],
            vec!["status", "--run", "--json"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn global_flags_are_position_independent_and_at_most_once() {
        for values in [
            vec!["--json", "--data-dir", "/d", "approve", "hp1"],
            vec!["approve", "--json", "hp1", "--data-dir", "/d"],
            vec!["approve", "hp1", "--data-dir", "/d", "--json"],
        ] {
            assert_eq!(
                parse_args(&args(&values)),
                Ok(Invocation {
                    command: Command::Approve {
                        permission_id: "hp1".into()
                    },
                    data_dir: Some("/d".into()),
                    json: true
                }),
                "{values:?}"
            );
        }
        for values in [
            vec!["--json", "approve", "hp1", "--json"],
            vec!["--data-dir", "/a", "approve", "hp1", "--data-dir", "/b"],
            vec!["approve", "hp1", "--data-dir", "relative"],
        ] {
            assert_eq!(parse_args(&args(&values)), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn parses_plugins_list_add_and_remove() {
        assert_eq!(command(&["plugins", "list"]), Ok(Command::PluginsList));
        assert_eq!(
            command(&["plugins", "add", "/pkg"]),
            Ok(Command::PluginsAdd { dir: "/pkg".into() })
        );
        assert_eq!(
            command(&["plugins", "remove", "fake"]),
            Ok(Command::PluginsRemove {
                name: "fake".into()
            })
        );
        for values in [
            vec!["plugins"],
            vec!["plugins", "add"],
            vec!["plugins", "add", "pkg"],
            vec!["plugins", "add", "--built-in", "telegram"],
            vec!["plugins", "add", "/pkg", "--built-in"],
            vec!["plugins", "add", "/a", "/b"],
            vec!["plugins", "remove"],
            vec!["plugins", "list", "extra"],
            vec!["plugins", "install", "/pkg"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    #[test]
    fn mcp_takes_no_words_flags_or_json() {
        assert_eq!(command(&["mcp"]), Ok(Command::Mcp));
        for values in [["--data-dir", "/d", "mcp"], ["mcp", "--data-dir", "/d"]] {
            let invocation = parse_args(&args(&values)).unwrap();
            assert_eq!(invocation.command, Command::Mcp);
            assert_eq!(invocation.data_dir, Some(PathBuf::from("/d")));
        }
        for values in [
            vec!["mcp", "serve"],
            vec!["mcp", "extra"],
            vec!["mcp", "--json"],
            vec!["--json", "mcp"],
            vec!["mcp", "--workspace", "/w"],
            vec!["--json", "mcp", "run", "begin"],
            vec!["mcp", "--data-dir", "relative"],
        ] {
            assert_eq!(command(&values), Err(UsageError), "{values:?}");
        }
    }
    fn secret(text: &str) -> SecretLine {
        SecretLine::read(&mut std::io::Cursor::new(text.as_bytes()), false).unwrap()
    }
    #[test]
    fn control_request_builds_op_and_args_for_every_command() {
        let request = |values: &[&str]| command(values).unwrap().control_request();
        for (values, op, expected) in [
            (vec!["status"], "status", json!({})),
            (
                vec!["status", "--run", "r1"],
                "status_run",
                json!({"run_id": "r1"}),
            ),
            (
                vec!["pair", "telegram", "--workspace", "/ws"],
                "pair_start",
                json!({"channel": "telegram", "workspace": "/ws"}),
            ),
            (
                vec![
                    "pair",
                    "feishu",
                    "--workspace",
                    "/ws",
                    "--run-deadline",
                    "60",
                ],
                "pair_start",
                json!({"channel": "feishu", "workspace": "/ws", "run_deadline": 60}),
            ),
            (vec!["bindings", "list"], "bindings_list", json!({})),
            (
                vec!["bindings", "revoke", "b1"],
                "bindings_revoke",
                json!({"binding_id": "b1"}),
            ),
            (
                vec!["bindings", "reconfirm", "b1"],
                "bindings_reconfirm",
                json!({"binding_id": "b1"}),
            ),
            (
                vec!["bindings", "reset-thread", "b1", "--ack-unknown", "r1"],
                "bindings_reset_thread",
                json!({"binding_id": "b1", "ack_unknown": "r1"}),
            ),
            (
                vec!["bindings", "host", "crabcode", "--workspace", "/ws"],
                "bindings_host",
                json!({"workspace": "/ws"}),
            ),
            (
                vec![
                    "bindings",
                    "host",
                    "crabcode",
                    "--workspace",
                    "/ws",
                    "--run-deadline",
                    "5",
                ],
                "bindings_host",
                json!({"workspace": "/ws", "run_deadline": 5}),
            ),
            (
                vec!["approve", "hp1"],
                "approve",
                json!({"permission_id": "hp1"}),
            ),
            (vec!["deny", "hp1"], "deny", json!({"permission_id": "hp1"})),
            (vec!["cancel", "r1"], "cancel", json!({"run_id": "r1"})),
            (vec!["plugins", "list"], "plugins_list", json!({})),
            (
                vec!["plugins", "add", "/pkg"],
                "plugins_add",
                json!({"dir": "/pkg"}),
            ),
            (
                vec!["plugins", "remove", "fake"],
                "plugins_remove",
                json!({"name": "fake"}),
            ),
        ] {
            assert_eq!(request(&values), Some((op, expected)), "{values:?}");
        }
        // The receiver command first reads the declared fields, then sends its own request.
        for values in [
            vec!["bindings", "receiver", "telegram"],
            vec!["daemon"],
            vec!["init", "--pg-bin-dir", "/pg"],
            vec!["mcp"],
        ] {
            assert_eq!(request(&values), None, "{values:?}");
        }
    }
    #[test]
    fn control_op_names_equal_the_cli_command_words() {
        for word in ["approve", "deny", "cancel"] {
            let (op, _) = command(&[word, "x"]).unwrap().control_request().unwrap();
            assert_eq!(op, word);
        }
    }
    #[test]
    fn secret_line_strips_one_terminator_and_rejects_empty_or_over_512_bytes() {
        assert_eq!(secret("abc\n").expose(), "abc");
        assert_eq!(secret("abc\r\n").expose(), "abc");
        assert_eq!(secret("abc\n\n").expose(), "abc");
        assert_eq!(secret("abc\r\r\n").expose(), "abc\r");
        assert_eq!(secret("abc").expose(), "abc");
        let max = "x".repeat(512);
        assert_eq!(secret(&format!("{max}\r\n")).expose(), max);
        for text in [
            format!("{max}x\n"),
            format!("{max}x"),
            "x".repeat(2000),
            String::new(),
            "\n".into(),
            "\r\n".into(),
        ] {
            assert_eq!(
                SecretLine::read(&mut std::io::Cursor::new(text.as_bytes()), false).unwrap_err(),
                UsageError
            );
        }
        assert_eq!(
            SecretLine::read(&mut std::io::Cursor::new(&b"\xff\xfe\n"[..]), false).unwrap_err(),
            UsageError
        );
    }
    #[test]
    fn secret_line_from_a_pipe_reads_only_the_first_line_without_terminal_modes() {
        let mut input = std::io::Cursor::new(&b"first\nsecond\n"[..]);
        assert_eq!(
            SecretLine::read(&mut input, false).unwrap().expose(),
            "first"
        );
        let mut rest = String::new();
        input.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "second\n");
    }
    #[test]
    fn secret_line_debug_is_redacted() {
        assert_eq!(format!("{:?}", secret("123:sentinel")), "[REDACTED]");
        assert_eq!(format!("{:#?}", secret("123:sentinel")), "[REDACTED]");
    }
    #[test]
    fn requires_absolute_pg_bin_for_init() {
        for values in [
            vec!["init"],
            vec!["init", "--pg-bin-dir", "pg"],
            vec!["init", "--pg-bin-dir"],
        ] {
            assert_eq!(parse_args(&args(&values)), Err(UsageError));
        }
        assert_eq!(exit_code(&DaemonError::InvalidArguments), 2);
    }
    #[test]
    fn all_subcommands_share_data_dir_resolution() {
        for command in ["init", "daemon", "status"] {
            let mut values = vec![command, "--data-dir", "/explicit"];
            if command == "init" {
                values.extend(["--pg-bin-dir", "/pg"]);
            }
            let invocation = parse_args(&args(&values)).unwrap();
            assert_eq!(
                resolve_data_dir(DataDirectoryInput {
                    explicit: invocation.data_dir,
                    environment: Some("/environment".into()),
                    home: Some("/home".into())
                })
                .unwrap(),
                PathBuf::from("/explicit")
            );
        }
        assert_eq!(
            resolve_data_dir(DataDirectoryInput {
                explicit: None,
                environment: Some("/environment".into()),
                home: Some("/home".into())
            })
            .unwrap(),
            PathBuf::from("/environment")
        );
        assert_eq!(
            resolve_data_dir(DataDirectoryInput {
                explicit: None,
                environment: None,
                home: Some("/home".into())
            })
            .unwrap(),
            PathBuf::from("/home/Library/Application Support/OpenMyBot")
        );
        assert_eq!(
            resolve_data_dir(DataDirectoryInput {
                explicit: None,
                environment: None,
                home: None
            }),
            Err(DaemonError::InvalidArguments)
        );
    }
    #[tokio::test]
    async fn json_status_when_daemon_is_not_running() {
        let error = omb_daemon::status(StatusOptions {
            data_dir: std::env::temp_dir().join(format!("omb-missing-{}", std::process::id())),
        })
        .await
        .unwrap_err();
        assert_eq!(exit_code(&error), 3);
        assert_eq!(
            serde_json::json!({"ok":false,"code":error.code()}).to_string(),
            r#"{"code":"daemon_not_running","ok":false}"#
        );
    }
    #[test]
    fn maps_usage_business_and_internal_exit_codes() {
        for (error, expected) in [
            (DaemonError::InvalidArguments, 2),
            (DaemonError::DaemonNotRunning, 3),
            (DaemonError::DaemonAlreadyRunning, 4),
            (DaemonError::InternalError, 5),
            (DaemonError::PermissionNotPending, 4),
            (DaemonError::PermissionExpired, 4),
            (DaemonError::RunNotFound, 4),
            (DaemonError::CredentialRejected, 4),
            (DaemonError::WebhookConflict, 4),
            (DaemonError::ChannelUnreachable, 4),
            (DaemonError::RequestTimeout, 4),
        ] {
            assert_eq!(exit_code(&error), expected);
            let output = serde_json::json!({"ok":false,"code":error.code()});
            assert_eq!(output.as_object().unwrap().len(), 2);
            assert!(!output.to_string().contains('/'));
        }
        assert_eq!(
            serde_json::json!({"ok":true,"data":{}}).get("ok").unwrap(),
            true
        );
    }
}
