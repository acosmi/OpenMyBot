//! Source-only entry for the distinct PG17.11 maintenance toolchain.
use anyhow::{Result, bail};
#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
#[path = "postgres_maintenance/build.rs"]
mod build;
#[cfg(target_os = "macos")]
#[path = "postgres_maintenance/manifest.rs"]
mod manifest;

#[cfg(target_os = "macos")]
pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let Some(command) = args.first() else {
        bail!("maintenance_command_required");
    };
    let mut options = parse_options(&args[1..])?;
    match command.as_str() {
        "build" => {
            let archive = take(&mut options, "source-archive")?;
            let derived = take(&mut options, "derived-root")?;
            let output = take(&mut options, "output-root")?;
            let profile = take(&mut options, "build-profile")?;
            if !options.is_empty() {
                bail!("maintenance_unknown_option");
            }
            build::build(root, &archive, &derived, &output, &profile)
        }
        "inspect" => {
            let bundle = take(&mut options, "bundle")?;
            if !options.is_empty() {
                bail!("maintenance_unknown_option");
            }
            let facts = manifest::inspect(&bundle, None)?;
            println!("{}", serde_json::to_string(&facts)?);
            Ok(())
        }
        "verify-source" => {
            let bundle = take(&mut options, "bundle")?;
            let input = take(&mut options, "reviewed-build-input")?;
            if !options.is_empty() {
                bail!("maintenance_unknown_option");
            }
            build::verify_source(root, &bundle, &input)
        }
        _ => bail!("maintenance_unknown_command"),
    }
}
#[cfg(target_os = "macos")]
fn parse_options(args: &[String]) -> Result<BTreeMap<String, String>> {
    if !args.len().is_multiple_of(2) {
        bail!("maintenance_option_value_required");
    }
    let mut out = BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        let key = pair[0]
            .strip_prefix("--")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("maintenance_option_invalid"))?;
        if pair[1].is_empty() || out.insert(key.into(), pair[1].clone()).is_some() {
            bail!("maintenance_option_duplicate_or_empty");
        }
    }
    Ok(out)
}
#[cfg(target_os = "macos")]
fn take(map: &mut BTreeMap<String, String>, key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        map.remove(key)
            .ok_or_else(|| anyhow::anyhow!("maintenance_option_missing"))?,
    );
    if !path.is_absolute() {
        bail!("maintenance_absolute_path_required");
    }
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn run(_root: &Path, _args: &[String]) -> Result<()> {
    bail!("maintenance_platform_unsupported");
}
