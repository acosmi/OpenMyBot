use omb_cli::{Command, SecretLine, exit_code, parse_args};
use omb_daemon::{
    CallOptions, DaemonError, DaemonOptions, DataDirectoryInput, InitOptions, StatusOptions,
    resolve_data_dir,
};
use std::{ffi::OsString, io::IsTerminal, path::PathBuf, process::ExitCode};
#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let invocation = match parse_args(&args) {
        Ok(value) => value,
        Err(_) => {
            output_error("invalid_arguments", args.iter().any(|s| s == "--json"));
            return ExitCode::from(2);
        }
    };
    let json = invocation.json;
    // The secret is read before any connection; it never travels in argv or the environment.
    let secret = if invocation.command.reads_secret() {
        let stdin = std::io::stdin();
        match SecretLine::read(&mut stdin.lock(), stdin.is_terminal()) {
            Ok(secret) => Some(secret),
            Err(_) => {
                output_error("invalid_arguments", json);
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    let result: Result<serde_json::Value, DaemonError> = async {
        let data_dir = resolve_data_dir(DataDirectoryInput {
            explicit: invocation.data_dir,
            environment: std::env::var_os("OPENMYBOT_DATA_DIR").map(PathBuf::from),
            home: std::env::var_os("HOME").map(PathBuf::from),
        })?;
        match invocation.command {
            Command::Init { pg_bin_dir } => serde_json::to_value(
                omb_daemon::init(InitOptions {
                    data_dir,
                    pg_bin_dir,
                })
                .await?,
            )
            .map_err(|_| DaemonError::InternalError),
            Command::Daemon => {
                omb_daemon::daemon(DaemonOptions { data_dir }).await?;
                Ok(serde_json::json!({}))
            }
            Command::Status { run: None } => {
                serde_json::to_value(omb_daemon::status(StatusOptions { data_dir }).await?)
                    .map_err(|_| DaemonError::InternalError)
            }
            command => {
                let (op, args) = command
                    .control_request(secret)
                    .ok_or(DaemonError::InternalError)?;
                omb_daemon::call(CallOptions {
                    data_dir,
                    op: op.into(),
                    args,
                })
                .await
            }
        }
    }
    .await;
    match result {
        Ok(data) => {
            if json {
                println!("{}", serde_json::json!({"ok":true,"data":data}));
            } else {
                println!("{data}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            output_error(error.code(), json);
            ExitCode::from(exit_code(&error))
        }
    }
}
fn output_error(code: &str, json: bool) {
    if json {
        println!("{}", serde_json::json!({"ok":false,"code":code}));
    } else {
        eprintln!("{code}");
    }
}
