//! `cargo xtask release <subcommand>`: development release assembly for the macOS product.
use anyhow::{Result, bail};
use std::path::Path;

#[cfg(unix)]
#[path = "release_root.rs"]
mod release_root;
#[cfg(not(unix))]
mod release_root {
    pub(super) fn run(_root: &std::path::Path, _args: &[String]) -> anyhow::Result<()> {
        anyhow::bail!("release_root_platform_unsupported")
    }
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("root") => release_root::run(root, &args[1..]),
        _ => bail!("release_subcommand_unknown: expected one of: root"),
    }
}
