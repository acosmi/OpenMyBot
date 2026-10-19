//! Explicit source-authenticated maintenance consumer; never starts Desktop Local.
#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    openbot_desktop::postgres_maintenance::run_maintenance_toolchain_cli(&args).await
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("UnsupportedPlatform");
    std::process::ExitCode::from(1)
}
