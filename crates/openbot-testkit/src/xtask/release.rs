//! `cargo xtask release <subcommand>`: Desktop release production steps.

use std::path::Path;

use anyhow::{Result, bail};

#[cfg(target_os = "macos")]
use crate::{release_app, release_check, release_sign};

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        #[cfg(target_os = "macos")]
        Some("sign-components") => release_sign::run_sign_components(rest),
        #[cfg(target_os = "macos")]
        Some("app") => release_app::run(root, rest),
        #[cfg(target_os = "macos")]
        Some("sign-app") => release_sign::run_sign_app(rest),
        #[cfg(target_os = "macos")]
        Some("notarize") => release_sign::run_notarize(rest),
        #[cfg(target_os = "macos")]
        Some("check") => release_check::run(rest),
        #[cfg(target_os = "macos")]
        Some("all") => release_app::run_all(root, rest),
        _ => {
            let _ = (root, rest);
            bail!("release_unknown_command")
        }
    }
}
