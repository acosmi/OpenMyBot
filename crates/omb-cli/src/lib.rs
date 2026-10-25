//! Closed local command parsing; credentials never enter arguments.
use omb_daemon::{DaemonError, ErrorClass};
use std::{ffi::OsString, path::PathBuf};
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Init { pg_bin_dir: PathBuf },
    Daemon,
    Status,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub data_dir: Option<PathBuf>,
    pub json: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub struct UsageError;
pub fn parse_args(args: &[OsString]) -> Result<Invocation, UsageError> {
    let name = args.first().and_then(|s| s.to_str()).ok_or(UsageError)?;
    if !matches!(name, "init" | "daemon" | "status") {
        return Err(UsageError);
    }
    let mut data_dir = None;
    let mut pg_bin_dir = None;
    let mut json = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].to_str().ok_or(UsageError)? {
            "--json" if !json => json = true,
            "--data-dir" if data_dir.is_none() => {
                index += 1;
                let path = PathBuf::from(args.get(index).ok_or(UsageError)?);
                if !path.is_absolute() {
                    return Err(UsageError);
                }
                data_dir = Some(path);
            }
            "--pg-bin-dir" if name == "init" && pg_bin_dir.is_none() => {
                index += 1;
                let path = PathBuf::from(args.get(index).ok_or(UsageError)?);
                if !path.is_absolute() {
                    return Err(UsageError);
                }
                pg_bin_dir = Some(path);
            }
            _ => return Err(UsageError),
        }
        index += 1;
    }
    let command = match name {
        "init" => Command::Init {
            pg_bin_dir: pg_bin_dir.ok_or(UsageError)?,
        },
        "daemon" => Command::Daemon,
        "status" => Command::Status,
        _ => return Err(UsageError),
    };
    Ok(Invocation {
        command,
        data_dir,
        json,
    })
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
    #[test]
    fn parses_only_init_daemon_and_status() {
        for command in ["daemon", "status"] {
            assert!(parse_args(&args(&[command])).is_ok());
        }
        assert!(parse_args(&args(&["init", "--pg-bin-dir", "/pg"])).is_ok());
        for command in ["mcp", "pair", "approve", "bindings", "cancel", "deny"] {
            assert_eq!(parse_args(&args(&[command])), Err(UsageError));
        }
        for values in [
            vec!["status", "--run", "x"],
            vec!["status", "--json", "--json"],
            vec!["daemon", "--pg-bin-dir", "/pg"],
            vec!["status", "--data-dir"],
            vec!["status", "--data-dir", "/one", "--data-dir", "/two"],
        ] {
            assert_eq!(parse_args(&args(&values)), Err(UsageError));
        }
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
