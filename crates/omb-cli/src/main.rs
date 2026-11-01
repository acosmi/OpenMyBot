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
    let serving = invocation.command == Command::Mcp;
    // Read once at start: a host-driver child's MCP server refuses every tool call.
    let nested = std::env::var_os("OPENMYBOT_HOST_DRIVER_CHILD").is_some_and(|value| value == "1");
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
            Command::Mcp => {
                omb_mcp::serve(omb_mcp::McpOptions { data_dir, nested }).await?;
                Ok(serde_json::Value::Null)
            }
            Command::BindingsReceiver { channel } => {
                let listed = omb_daemon::call(CallOptions {
                    data_dir: data_dir.clone(),
                    op: "plugins_list".into(),
                    args: serde_json::json!({}),
                })
                .await?;
                let declared = listed["plugins"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .flat_map(|plugin| plugin["channels"].as_array().into_iter().flatten())
                    .find(|entry| entry["channel_kind"] == channel.as_str())
                    .ok_or(DaemonError::PluginNotInstalled)?["credential_fields"]
                    .clone();
                // One line per declared field, a secret without echo; values never travel in argv
                // or the environment.
                let mut fields = serde_json::Map::new();
                let stdin = std::io::stdin();
                let terminal = stdin.is_terminal();
                let mut input = stdin.lock();
                for field in declared.as_array().into_iter().flatten() {
                    let (Some(name), Some(secret)) =
                        (field["name"].as_str(), field["secret"].as_bool())
                    else {
                        return Err(DaemonError::InternalError);
                    };
                    if terminal {
                        eprint!("{name}: ");
                    }
                    let value = SecretLine::read(&mut input, terminal && secret)
                        .map_err(|_| DaemonError::InvalidArguments)?;
                    fields.insert(name.to_owned(), value.expose().into());
                }
                drop(input);
                omb_daemon::call(CallOptions {
                    data_dir,
                    op: "bindings_receiver".into(),
                    args: serde_json::json!({"channel": channel, "fields": fields}),
                })
                .await
            }
            command => {
                let (op, args) = command
                    .control_request()
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
        // stdout carries only MCP frames.
        Ok(_) if serving => ExitCode::SUCCESS,
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
