//! macOS product entry. Help/version and release checks never start a GUI or a child process.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("wrok_bot_desktop_launcher_platform_unsupported");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    use openbot_desktop::desktop_release::{
        TrustedDesktopReleaseDigest, VerifiedDesktopRelease, validate_product_context,
    };
    use openbot_desktop::register_desktop_local_runtime;

    let args = parse_args(std::env::args_os().skip(1))?;
    match args.mode {
        Mode::Help => {
            println!(
                "Wrok Bot\n\nUsage: wrok-bot [--resource-root PATH] [--check-release] [--restore-request PATH]\n       wrok-bot --help\n       wrok-bot --version\n\nRelease resources must match the reviewed digest bound into this core build.\n--check-release verifies resources without opening Keychain, PostgreSQL, or windows."
            );
            return Ok(());
        }
        Mode::Version => {
            println!("Wrok Bot {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Mode::Launch | Mode::Check => {}
    }
    let expected = TrustedDesktopReleaseDigest::from_reviewed_build(option_env!(
        "WROK_BOT_DESKTOP_RELEASE_SHA256"
    ))
    .map_err(|error| error.to_string())?;
    let root = match args.resource_root {
        Some(root) => root,
        None => bundled_resource_root()?,
    };
    let release =
        VerifiedDesktopRelease::open(&root, expected).map_err(|error| error.to_string())?;
    if args.mode == Mode::Check {
        println!("wrok_bot_release_resources_verified");
        return Ok(());
    }
    let context = product_context();
    validate_product_context(&context).map_err(|error| error.to_string())?;
    let config = match args.restore_request {
        Some(request) => release.into_runtime_config_with_request(
            std::env::current_exe().map_err(|_| "wrok_bot_program_unavailable".to_owned())?, request,
        ),
        None => release.into_runtime_config(),
    }.map_err(|error| error.to_string())?;
    register_desktop_local_runtime(tauri::Builder::default(), config)
        .map_err(|error| error.to_string())?
        .run(context)
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn product_context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Launch,
    Check,
    Help,
    Version,
}

#[cfg(target_os = "macos")]
struct Args {
    mode: Mode,
    resource_root: Option<std::path::PathBuf>,
    restore_request: Option<std::path::PathBuf>,
}

#[cfg(target_os = "macos")]
fn parse_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Args, String> {
    let mut args = args.into_iter();
    let mut parsed = Args {
        mode: Mode::Launch,
        resource_root: None,
        restore_request: None,
    };
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "--version")
                if parsed.mode == Mode::Launch && parsed.resource_root.is_none() && parsed.restore_request.is_none() =>
            {
                parsed.mode = if arg == "--help" {
                    Mode::Help
                } else {
                    Mode::Version
                };
                if args.next().is_some() {
                    return Err("wrok_bot_arguments_invalid".to_owned());
                }
                return Ok(parsed);
            }
            Some("--check-release") if parsed.mode == Mode::Launch => parsed.mode = Mode::Check,
            Some("--restore-request") if parsed.restore_request.is_none() && parsed.mode == Mode::Launch => {
                let path = args.next().map(std::path::PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or_else(|| "wrok_bot_arguments_invalid".to_owned())?;
                parsed.restore_request = Some(path);
            }
            Some("--resource-root") if parsed.resource_root.is_none() => {
                let path = args
                    .next()
                    .map(std::path::PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or_else(|| "wrok_bot_arguments_invalid".to_owned())?;
                parsed.resource_root = Some(path);
            }
            _ => return Err("wrok_bot_arguments_invalid".to_owned()),
        }
    }
    if parsed.mode != Mode::Launch && parsed.restore_request.is_some() { return Err("wrok_bot_arguments_invalid".to_owned()); }
    Ok(parsed)
}

#[cfg(target_os = "macos")]
fn bundled_resource_root() -> Result<std::path::PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|_| "wrok_bot_release_resource_root_unavailable".to_owned())?;
    let macos = executable
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "MacOS"));
    let contents = macos
        .and_then(std::path::Path::parent)
        .filter(|path| path.file_name().is_some_and(|name| name == "Contents"))
        .ok_or_else(|| "wrok_bot_release_resource_root_unavailable".to_owned())?;
    Ok(contents.join("Resources"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn cli_is_closed_and_has_no_secret_or_runtime_identity_options() {
        for args in [
            vec!["--secret", "value"],
            vec!["--tenant", "x"],
            vec!["--help", "--check-release"],
            vec!["--resource-root", "relative"],
            vec!["--check-release", "--check-release"],
            vec!["--resource-root", "/absolute", "--resource-root", "/other"],
        ] {
            assert!(parse_args(args.into_iter().map(Into::into)).is_err());
        }
        assert_eq!(parse_args(["--help".into()]).unwrap().mode, Mode::Help);
        assert_eq!(
            parse_args(["--version".into()]).unwrap().mode,
            Mode::Version
        );
        assert_eq!(
            parse_args(["--check-release".into()]).unwrap().mode,
            Mode::Check
        );
        let args = parse_args([
            "--resource-root".into(),
            "/absolute".into(),
            "--check-release".into(),
        ])
        .unwrap();
        assert_eq!(args.mode, Mode::Check);
        assert_eq!(
            args.resource_root.unwrap(),
            std::path::Path::new("/absolute")
        );
    }

    #[test]
    fn cli_restore_request_is_one_absolute_path_for_launch_only() {
        let parsed = parse_args(["--restore-request".into(), "/request".into()]).unwrap();
        assert_eq!(parsed.mode, Mode::Launch);
        assert_eq!(parsed.restore_request.as_deref(), Some(std::path::Path::new("/request")));
        for args in [
            vec!["--restore-request"],
            vec!["--restore-request", "relative"],
            vec!["--restore-request", "/a", "--restore-request", "/b"],
            vec!["--restore-request", "/a", "--check-release"],
            vec!["--check-release", "--restore-request", "/a"],
            vec!["--restore-request", "/a", "--help"],
        ] {
            assert!(parse_args(args.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn generated_context_matches_reviewed_zero_window_product_config() {
        let context = product_context();
        let mut approved: tauri::Config =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        approved.schema = None;
        assert_eq!(context.config(), &approved);
        openbot_desktop::desktop_release::validate_product_context(&context).unwrap();
        assert!(context.config().app.windows.is_empty());
    }

    #[test]
    fn generated_authority_allows_only_local_main_structured_commands() {
        use tauri::ipc::Origin;
        let mut context = product_context();
        let authority = context.runtime_authority_mut();
        for command in [
            "openbot_structured_events_open",
            "openbot_structured_events_close",
        ] {
            assert!(
                authority
                    .resolve_access(command, "main", "main", &Origin::Local)
                    .is_some()
            );
            assert!(
                authority
                    .resolve_access(command, "other", "other", &Origin::Local)
                    .is_none()
            );
            let remote = Origin::Remote {
                url: "https://example.invalid/".parse().unwrap(),
            };
            assert!(
                authority
                    .resolve_access(command, "main", "main", &remote)
                    .is_none()
            );
        }
        for command in [
            "plugin:window|create",
            "plugin:app|exit",
            "plugin:event|listen",
            "unreviewed_command",
        ] {
            assert!(
                authority
                    .resolve_access(command, "main", "main", &Origin::Local)
                    .is_none()
            );
        }
    }
}
