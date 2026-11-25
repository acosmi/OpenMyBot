//! `cargo xtask release app | all`: assemble `Wrok Bot.app` from a release root and a built
//! launcher, and chain the signing, notarization and check steps in the spec revision R485
//! section 16.2 order: components before any digest, the outer app last, then notarize.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::release_check;
use crate::release_sign::{self, Identity, Options};

pub(crate) const APP_BUNDLE: &str = "Wrok Bot.app";
pub(crate) const EXECUTABLE: &str = "wrok-bot";
const ICON: &str = "wrok-bot.icns";
const BUNDLE_IDENTIFIER: &str = "com.acosmi.wrokbot";
const BUNDLE_NAME: &str = "Wrok Bot";

pub(crate) struct AppInput {
    pub(crate) root: PathBuf,
    pub(crate) launcher: PathBuf,
    pub(crate) out: PathBuf,
    pub(crate) version: String,
    pub(crate) minimum_macos: String,
}

impl AppInput {
    fn take(options: &mut Options) -> Result<Self> {
        let root = release_sign::existing(&options.required("root")?)?;
        let launcher = release_sign::existing(&options.required("launcher")?)?;
        let out = PathBuf::from(options.required("out")?);
        let version = options.required("version")?;
        let minimum_macos = options.required("minimum-macos")?;
        let numeric = |value: &str, parts: std::ops::RangeInclusive<usize>| {
            let fields: Vec<_> = value.split('.').collect();
            parts.contains(&fields.len())
                && fields
                    .iter()
                    .all(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
        };
        if !numeric(&version, 3..=3) {
            bail!("release_version_invalid: expected MAJOR.MINOR.PATCH");
        }
        if !numeric(&minimum_macos, 1..=3) {
            bail!("release_minimum_macos_invalid");
        }
        if !out.is_absolute() {
            bail!("release_absolute_path_required: --out");
        }
        if !root.join("wrok-bot-release.json").is_file() || !launcher.is_file() {
            bail!(
                "release_app_inputs_invalid: --root needs wrok-bot-release.json, --launcher a file"
            );
        }
        Ok(Self {
            root,
            launcher,
            out,
            version,
            minimum_macos,
        })
    }
}

fn info_plist(version: &str, minimum_macos: &str) -> plist::Value {
    let mut values = plist::Dictionary::new();
    for (key, value) in [
        ("CFBundleExecutable", EXECUTABLE),
        ("CFBundleIconFile", ICON),
        ("CFBundleIdentifier", BUNDLE_IDENTIFIER),
        ("CFBundleInfoDictionaryVersion", "6.0"),
        ("CFBundleName", BUNDLE_NAME),
        ("CFBundlePackageType", "APPL"),
        ("CFBundleShortVersionString", version),
        ("CFBundleVersion", version),
        ("LSMinimumSystemVersion", minimum_macos),
    ] {
        values.insert(key.to_owned(), plist::Value::String(value.to_owned()));
    }
    plist::Value::Dictionary(values)
}

/// `Contents/{MacOS/wrok-bot, Resources/<release root>, Resources/wrok-bot.icns, Info.plist}`.
/// The release root is copied byte for byte with its modes, so its outer digest still holds.
pub(crate) fn assemble(workspace: &Path, input: &AppInput) -> Result<PathBuf> {
    let app = input.out.join(APP_BUNDLE);
    if fs::symlink_metadata(&app).is_ok() {
        bail!("{} already exists", app.display());
    }
    let contents = app.join("Contents");
    let resources = contents.join("Resources");
    fs::create_dir_all(contents.join("MacOS"))?;
    let executable = contents.join("MacOS").join(EXECUTABLE);
    fs::copy(&input.launcher, &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
    for entry in WalkDir::new(&input.root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        let target = resources.join(entry.path().strip_prefix(&input.root)?);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target)?;
        } else {
            bail!(
                "release root entry {} is not a file or directory",
                entry.path().display()
            );
        }
        fs::set_permissions(&target, entry.metadata()?.permissions())?;
    }
    let icon = workspace.join("crates/openbot-desktop/icons").join(ICON);
    fs::copy(&icon, resources.join(ICON)).with_context(|| format!("copy {}", icon.display()))?;
    fs::set_permissions(resources.join(ICON), fs::Permissions::from_mode(0o644))?;
    info_plist(&input.version, &input.minimum_macos).to_file_xml(contents.join("Info.plist"))?;
    Ok(app)
}

pub(crate) fn run(workspace: &Path, args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &[])?;
    let input = AppInput::take(&mut options)?;
    options.finish()?;
    let app = assemble(workspace, &input)?;
    println!("release app: assembled {}", app.display());
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The root's components were signed before its manifests were digested; only verify here.
    VerifyComponents,
    App,
    SignApp,
    Notarize,
    Check,
}

/// Ad-hoc signing is a development build: it is never submitted for notarization.
fn plan(identity: &Identity) -> Vec<Step> {
    let mut steps = vec![Step::VerifyComponents, Step::App, Step::SignApp];
    if *identity != Identity::AdHoc {
        steps.push(Step::Notarize);
    }
    steps.push(Step::Check);
    steps
}

/// `release all` over a release root built from already signed components (`release
/// sign-components` before the root digest). Every intermediate product lands under `--out`.
pub(crate) fn run_all(workspace: &Path, args: &[String]) -> Result<()> {
    let mut options = Options::parse(args, &["dry-run-notarize"])?;
    let input = AppInput::take(&mut options)?;
    let identity = Identity::parse(&options.optional("identity")?.unwrap_or_else(|| "-".into()))?;
    let entitlements = options
        .optional("entitlements")?
        .map(|value| release_sign::existing(&value))
        .transpose()?;
    let profile = options
        .optional("keychain-profile")?
        .map(|value| release_sign::keychain_profile(&value))
        .transpose()?;
    let expect_team = options.optional("expect-team")?;
    let dry_run = options.flag("dry-run-notarize");
    options.finish()?;
    let profile = match (&identity, profile) {
        (Identity::AdHoc, None) => String::new(),
        (Identity::AdHoc, Some(_)) => bail!("ad-hoc identity `-` is never notarized"),
        (Identity::Named(_), Some(profile)) => profile,
        (Identity::Named(_), None) => bail!("release_option_missing: --keychain-profile"),
    };
    fs::create_dir_all(&input.out)?;
    let app = input.out.join(APP_BUNDLE);
    for step in plan(&identity) {
        println!("release all: {step:?}");
        match step {
            Step::VerifyComponents => {
                release_sign::sign_components(std::slice::from_ref(&input.root), &identity, true)
                    .map(drop)?
            }
            Step::App => assemble(workspace, &input).map(drop)?,
            Step::SignApp => release_sign::sign_app(&app, &identity, entitlements.as_deref())?,
            Step::Notarize => {
                release_sign::notarize(&app, &profile, &input.out.join("notarize"), dry_run)?
            }
            Step::Check => release_check::check(&app, expect_team.as_deref(), &input.out)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_sign::tests::temp_dir;

    #[test]
    fn components_precede_assembly_and_the_outer_app_is_signed_last() {
        assert_eq!(
            plan(&Identity::Named("Developer ID Application: X (T)".into())),
            [
                Step::VerifyComponents,
                Step::App,
                Step::SignApp,
                Step::Notarize,
                Step::Check
            ]
        );
        assert_eq!(
            plan(&Identity::AdHoc),
            [
                Step::VerifyComponents,
                Step::App,
                Step::SignApp,
                Step::Check
            ]
        );
    }

    #[test]
    fn info_plist_has_exactly_the_required_keys() {
        let plist = info_plist("0.1.0", "13.0");
        let keys: Vec<_> = plist.as_dictionary().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "CFBundleExecutable",
                "CFBundleIconFile",
                "CFBundleIdentifier",
                "CFBundleInfoDictionaryVersion",
                "CFBundleName",
                "CFBundlePackageType",
                "CFBundleShortVersionString",
                "CFBundleVersion",
                "LSMinimumSystemVersion",
            ]
        );
    }

    #[test]
    fn app_layout_copies_root_launcher_icon_and_requires_explicit_minimum() {
        let dir = temp_dir("app");
        let root = dir.join("root");
        fs::create_dir_all(root.join("postgres/bin")).unwrap();
        fs::write(root.join("wrok-bot-release.json"), b"{}").unwrap();
        fs::write(root.join("postgres/bin/postgres"), b"x").unwrap();
        fs::set_permissions(
            root.join("postgres/bin/postgres"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(dir.join("launcher"), b"launcher").unwrap();
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let args = |minimum: Option<&str>| {
            let mut args = vec![
                "--root".to_owned(),
                root.display().to_string(),
                "--launcher".to_owned(),
                dir.join("launcher").display().to_string(),
                "--out".to_owned(),
                dir.join("out").display().to_string(),
                "--version".to_owned(),
                "0.1.0".to_owned(),
            ];
            if let Some(minimum) = minimum {
                args.extend(["--minimum-macos".to_owned(), minimum.to_owned()]);
            }
            args
        };
        assert!(run(&workspace, &args(None)).is_err());
        assert!(run(&workspace, &args(Some("13.x"))).is_err());
        run(&workspace, &args(Some("13.0"))).unwrap();
        let contents = dir.join("out").join(APP_BUNDLE).join("Contents");
        let mode = |path: &str| {
            fs::metadata(contents.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(
            fs::read(contents.join("MacOS/wrok-bot")).unwrap(),
            b"launcher"
        );
        assert_eq!(mode("MacOS/wrok-bot"), 0o755);
        assert_eq!(mode("Resources/postgres/bin/postgres"), 0o755);
        assert_eq!(
            fs::read(contents.join("Resources/wrok-bot-release.json")).unwrap(),
            b"{}"
        );
        assert!(contents.join("Resources/wrok-bot.icns").is_file());
        assert_eq!(
            plist::Value::from_file(contents.join("Info.plist")).unwrap(),
            info_plist("0.1.0", "13.0")
        );
        assert!(
            run(&workspace, &args(Some("13.0"))).is_err(),
            "existing app is not overwritten"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
