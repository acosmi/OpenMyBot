//! Finite derived-source builder. Only explicit G1 execution may call this module.
use super::manifest::{
    self, BuildTool, DerivedSource, FileDigest, Manifest, Outer, OuterPostgres, Programs,
};
use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;

const FIXED_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";
type AliasFileIdentity = (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);

fn checked_clt_aliases() -> Result<Vec<(AliasFileIdentity, AliasFileIdentity)>> {
    fn identity(m: &fs::Metadata) -> AliasFileIdentity {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    let mut facts = Vec::with_capacity(3);
    for (path, literal, canonical) in [
        (
            "/Library/Developer/CommandLineTools/usr/bin/nm",
            "llvm-nm",
            "/Library/Developer/CommandLineTools/usr/bin/llvm-nm",
        ),
        (
            "/Library/Developer/CommandLineTools/usr/bin/ranlib",
            "libtool",
            "/Library/Developer/CommandLineTools/usr/bin/libtool",
        ),
        (
            "/Library/Developer/CommandLineTools/usr/bin/otool",
            "llvm-otool",
            "/Library/Developer/CommandLineTools/usr/bin/llvm-otool",
        ),
    ] {
        let link = fs::symlink_metadata(path)?;
        if !link.file_type().is_symlink()
            || link.uid() != 0
            || link.nlink() != 1
            || fs::read_link(path)? != Path::new(literal)
            || fs::canonicalize(path)? != Path::new(canonical)
        {
            bail!("maintenance_fixed_tool_alias_invalid");
        }
        // Hashing is performed separately by tool() on this pinned regular target only.
        let target = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(canonical)?;
        let opened = target.metadata()?;
        if !opened.is_file()
            || opened.uid() != 0
            || opened.nlink() == 0
            || opened.mode() & 0o6022 != 0
            || opened.mode() & 0o111 == 0
            || identity(&fs::metadata(path)?) != identity(&opened)
            || identity(&fs::symlink_metadata(canonical)?) != identity(&opened)
            || identity(&fs::symlink_metadata(path)?) != identity(&link)
            || fs::read_link(path)? != Path::new(literal)
            || fs::canonicalize(path)? != Path::new(canonical)
            || identity(&target.metadata()?) != identity(&opened)
        {
            bail!("maintenance_fixed_tool_alias_changed");
        }
        facts.push((identity(&link), identity(&opened)));
    }
    Ok(facts)
}
fn require_no_pkg_config() -> Result<()> {
    // These are the four entries in the existing fixed PATH, not a search or tool invocation.
    for path in [
        "/usr/bin/pkg-config",
        "/bin/pkg-config",
        "/usr/sbin/pkg-config",
        "/sbin/pkg-config",
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => bail!("maintenance_pkg_config_not_absent"),
        }
    }
    Ok(())
}
fn actual_recipe_hash(recipe: &Recipe) -> Result<String> {
    let encoded = serde_json::to_vec(recipe)?;
    let mut digest = Sha256::new();
    digest.update(b"wrokbot-maintenance-actual-build-recipe-v1\0");
    for field in [
        b"DEVELOPER_DIR".as_slice(),
        FIXED_DEVELOPER_DIR.as_bytes(),
        encoded.as_slice(),
    ] {
        digest.update(
            u64::try_from(field.len())
                .context("maintenance_recipe_overflow")?
                .to_be_bytes(),
        );
        digest.update(field);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Limits {
    effect_ns: u64,
    convergence_ns: u64,
    max_archive_bytes: u64,
    max_expanded_source_bytes: u64,
    max_source_files: u64,
    max_derived_bytes: u64,
    max_install_bytes: u64,
    max_bundle_bytes: u64,
    max_build_files: u64,
    max_build_processes: u64,
    max_build_jobs: u64,
    max_tool_output_bytes: u64,
    capacity_reserve_bytes: u64,
    free_floor_bytes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    path: String,
    bytes: u64,
    sha256: String,
}
fn required_option<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Sdk {
    path: String,
    tree_sha256: String,
    version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ConfigureSource {
    relative_path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Utilities {
    #[serde(deserialize_with = "required_option")]
    awk: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    basename: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    cat: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    chmod: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    cp: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    cut: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    dirname: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    expr: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    find: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    grep: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    head: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    install: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    ln: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    mkdir: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    mv: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    perl: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    pwd: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    rm: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    sed: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    sort: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    tail: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    test: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    tr: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    uname: Option<Tool>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Tools {
    git: Tool,
    shell: Tool,
    make: Tool,
    compiler: Tool,
    archiver: Tool,
    ranlib: Tool,
    linker: Tool,
    #[serde(deserialize_with = "required_option")]
    otool: Option<Tool>,
    #[serde(deserialize_with = "required_option")]
    install_name_tool: Option<Tool>,
    sdk: Sdk,
    system_utilities: Utilities,
    configure_source: ConfigureSource,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    #[serde(rename = "PATH")]
    path: String,
    #[serde(rename = "CC")]
    cc: String,
    #[serde(rename = "AR")]
    ar: String,
    #[serde(rename = "RANLIB")]
    ranlib: String,
    #[serde(rename = "SDKROOT")]
    sdkroot: String,
    #[serde(rename = "MACOSX_DEPLOYMENT_TARGET")]
    deployment: String,
    #[serde(rename = "CFLAGS")]
    cflags: String,
    #[serde(rename = "CPPFLAGS")]
    cppflags: String,
    #[serde(rename = "LDFLAGS")]
    ldflags: String,
    #[serde(rename = "LC_ALL")]
    locale: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Recipe {
    configure_argv: Vec<String>,
    make_argv: Vec<String>,
    install_argv: Vec<String>,
    environment: Environment,
    #[serde(deserialize_with = "required_option")]
    loader_rewrite: Option<Vec<Vec<String>>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    os: String,
    arch: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Source {
    archive_bytes: u64,
    archive_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Profile {
    schema: String,
    schema_version: u32,
    operation: String,
    platform: Platform,
    source: Source,
    patch: FileDigest,
    recipe: Recipe,
    tools: Tools,
    limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinSource {
    version: String,
    archive_bytes: u64,
    archive_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinPatch {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinBundle {
    schema: String,
    schema_version: u32,
    release_epoch: u64,
    programs: Programs,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    schema: String,
    schema_version: u32,
    source: PinSource,
    patch: PinPatch,
    bundle: PinBundle,
    derived_sources: Vec<DerivedSource>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reviewed {
    schema: String,
    schema_version: u32,
    outer_sha256: String,
    product_patch_sha256: String,
    recipe_sha256: String,
    build_profile_sha256: String,
}
// The new handles below are observer ownership anchors, not existing old behavior.
struct OwnedBuildDirectory {
    path: PathBuf,
    directory: fs::File,
    identity: (u64, u64, u32, u32, u32),
}
impl OwnedBuildDirectory {
    fn identity(m: &fs::Metadata) -> (u64, u64, u32, u32, u32) {
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
    }
    fn open(path: &Path) -> Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK)
                    .bits() as i32,
            )
            .open(path)?;
        let identity = Self::identity(&directory.metadata()?);
        let owner = Self { path: path.to_path_buf(), directory, identity };
        owner.verify()?;
        Ok(owner)
    }
    fn verify(&self) -> Result<()> {
        let held = self.directory.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !held.is_dir() || !named.is_dir()
            || Self::identity(&held) != self.identity
            || Self::identity(&named) != self.identity
        {
            bail!("maintenance_build_root_identity");
        }
        Ok(())
    }
}
struct Budget {
    end: u64,
    close: u64,
    direct_limit: u64,
    direct_commands: u64,
    live_process_cap: Option<(u64, u32)>,
    owned: Option<(OwnedBuildDirectory, OwnedBuildDirectory)>,
}
fn clock() -> Result<u64> {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let sec = u64::try_from(t.tv_sec).context("maintenance_clock_invalid")?;
    let ns = u64::try_from(t.tv_nsec).context("maintenance_clock_invalid")?;
    if ns >= 1_000_000_000 {
        bail!("maintenance_clock_invalid");
    }
    sec.checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(ns))
        .context("maintenance_clock_overflow")
}
impl Budget {
    fn new(l: &Limits) -> Result<Self> {
        let start = clock()?;
        let end = start
            .checked_add(l.effect_ns)
            .context("maintenance_clock_overflow")?;
        let close = end
            .checked_add(l.convergence_ns)
            .context("maintenance_clock_overflow")?;
        Ok(Self {
            end,
            close,
            direct_limit: l.max_build_processes,
            direct_commands: 0,
            live_process_cap: None,
            owned: None,
        })
    }
    fn check(&self) -> Result<()> {
        if clock()? >= self.end {
            bail!("maintenance_build_deadline");
        }
        Ok(())
    }
}
fn finite_process_capacity(
    n: u64,
    inherited: rustix::process::Rlimit,
    uid: u32,
    euid: u32,
) -> Result<rustix::process::Rlimit> {
    // Darwin's RLIM_INFINITY is i64::MAX; it is never a finite operation cap.
    if n == 0 || n >= i64::MAX as u64 || uid == 0 || euid == 0 || uid != euid {
        bail!("maintenance_live_process_capacity_invalid");
    }
    if inherited.current.is_some_and(|old| n > old) || inherited.maximum.is_some_and(|old| n > old)
    {
        bail!("maintenance_live_process_capacity_would_increase");
    }
    Ok(rustix::process::Rlimit {
        current: Some(n),
        maximum: Some(n),
    })
}
fn install_live_process_capacity(p: &Profile, b: &mut Budget) -> Result<()> {
    // This is called only by the disposable, single-operation xtask build entry.
    // Unit tests exercise the pure calculation above, never lower their process limit.
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!("maintenance_live_process_platform_unsupported");
    }
    use rustix::process::{Resource, geteuid, getrlimit, getuid, setrlimit};
    let uid = getuid().as_raw();
    let wanted = finite_process_capacity(
        p.limits.max_build_processes,
        getrlimit(Resource::Nproc),
        uid,
        geteuid().as_raw(),
    )?;
    b.check()?;
    setrlimit(Resource::Nproc, wanted).context("maintenance_live_process_capacity_set")?;
    if getrlimit(Resource::Nproc) != wanted || getuid().as_raw() != uid || geteuid().as_raw() != uid
    {
        bail!("maintenance_live_process_capacity_readback");
    }
    b.live_process_cap = Some((p.limits.max_build_processes, uid));
    Ok(())
}
fn require_live_process_capacity(p: &Profile, b: &Budget) -> Result<()> {
    use rustix::process::{Resource, geteuid, getrlimit, getuid};
    let (cap, owner) = b
        .live_process_cap
        .context("maintenance_live_process_capacity_not_installed")?;
    let got = getrlimit(Resource::Nproc);
    if cap != p.limits.max_build_processes
        || getuid().as_raw() != owner
        || geteuid().as_raw() != owner
        || got.current != Some(cap)
        || got.maximum != Some(cap)
    {
        bail!("maintenance_live_process_capacity_changed");
    }
    Ok(())
}
fn verify_build_os(root: &Path, p: &Profile, b: &mut Budget) -> Result<()> {
    let uname = p
        .tools
        .system_utilities
        .uname
        .as_ref()
        .context("maintenance_explicit_uname_required")?;
    // An observed supported matrix, not a claim that an OS string proves kernel code.
    for (arg, expected) in [
        ("-s", "Darwin\n"),
        ("-r", "27.0.0\n"),
        (
            "-v",
            "Darwin Kernel Version 27.0.0: Tue Aug 11 21:06:15 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T8152\n",
        ),
    ] {
        if command(&uname.path, &[arg.into()], root, p, b)? != expected.as_bytes() {
            bail!("maintenance_live_process_os_unknown");
        }
    }
    Ok(())
}
fn fresh_dir(path: &Path) -> Result<()> {
    if !path.is_absolute() || fs::symlink_metadata(path).is_ok() {
        bail!("maintenance_new_root_required");
    }
    let parent = path.parent().context("maintenance_parent_missing")?;
    if fs::canonicalize(parent)? != parent {
        bail!("maintenance_root_alias");
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_new(path: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .mode(0o600)
        .create_new(true)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn pins(root: &Path) -> Result<Pins> {
    let text = manifest::read_regular(
        &root.join("tools/postgres-maintenance-pins.toml"),
        1024 * 1024,
    )?;
    let p: Pins = toml::from_str(std::str::from_utf8(&text)?)?;
    if p.schema != "wrokbot-pg-maintenance-pins"
        || p.schema_version != 1
        || p.source.version != "17.11"
        || p.source.archive_bytes != manifest::ARCHIVE_BYTES
        || p.source.archive_sha256 != manifest::ARCHIVE_SHA
        || p.patch.path != "tools/patches/postgresql-17.11-wrokbot-basebackup-owner-v1.patch"
        || p.patch.bytes == 0
        || !manifest::valid_sha(&p.patch.sha256)
        || p.bundle.schema != "openbot-postgres-maintenance-bundle"
        || p.bundle.schema_version != 2
        || p.bundle.release_epoch != 5
        || p.bundle.programs.paths() != Programs::exact().paths()
    {
        bail!("maintenance_pins_invalid");
    }
    let mut names = BTreeSet::new();
    for source in &p.derived_sources {
        manifest::relative(&source.path)?;
        if !names.insert(&source.path)
            || !allowed_source(&source.path)
            || !manifest::valid_sha(&source.after.sha256)
        {
            bail!("maintenance_patch_scope_invalid");
        }
    }
    if names.len() != 11 {
        bail!("maintenance_patch_scope_incomplete");
    }
    Ok(p)
}
pub(super) fn allowed_source(path: &str) -> bool {
    matches!(
        path,
        "src/bin/pg_basebackup/pg_basebackup.c"
            | "src/bin/pg_basebackup/streamutil.c"
            | "src/bin/pg_basebackup/streamutil.h"
            | "src/bin/pg_basebackup/receivelog.c"
            | "src/bin/pg_basebackup/receivelog.h"
            | "src/bin/pg_basebackup/walmethods.c"
            | "src/bin/pg_basebackup/wrokbot_owner.c"
            | "src/bin/pg_basebackup/wrokbot_owner.h"
            | "src/bin/pg_basebackup/Makefile"
            | "src/interfaces/libpq/fe-connect.c"
            | "src/common/logging.c"
    )
}
fn validate_profile(p: &Profile, pins: &Pins) -> Result<()> {
    let l = &p.limits;
    let env = &p.recipe.environment;
    if p.schema != "wrokbot-pg-maintenance-build-profile"
        || p.schema_version != 1
        || p.operation.len() != 32
        || !p
            .operation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || p.platform.os != "macos"
        || p.platform.arch != std::env::consts::ARCH
        || p.source.archive_bytes != manifest::ARCHIVE_BYTES
        || p.source.archive_sha256 != manifest::ARCHIVE_SHA
        || (p.patch.bytes, p.patch.sha256.as_str())
            != (pins.patch.bytes, pins.patch.sha256.as_str())
    {
        bail!("maintenance_build_profile_invalid");
    }
    let values = [
        l.effect_ns,
        l.convergence_ns,
        l.max_archive_bytes,
        l.max_expanded_source_bytes,
        l.max_source_files,
        l.max_derived_bytes,
        l.max_install_bytes,
        l.max_bundle_bytes,
        l.max_build_files,
        l.max_build_processes,
        l.max_build_jobs,
        l.max_tool_output_bytes,
        l.capacity_reserve_bytes,
        l.free_floor_bytes,
    ];
    if values.contains(&0)
        || l.max_build_jobs > 32
        || l.max_archive_bytes < manifest::ARCHIVE_BYTES
        || l.max_build_processes
            < l.max_build_jobs
                .checked_mul(4)
                .and_then(|n| n.checked_add(8))
                .context("maintenance_profile_overflow")?
    {
        bail!("maintenance_build_limits_invalid");
    }
    if env.path != "/usr/bin:/bin:/usr/sbin:/sbin"
        || env.cc != p.tools.compiler.path
        || env.ar != p.tools.archiver.path
        || env.ranlib != p.tools.ranlib.path
        || env.sdkroot != p.tools.sdk.path
        || env.locale != "C"
        || env.cflags != "-O2 -g0 -fstack-protector-strong"
        || !env.cppflags.is_empty()
        || env.ldflags != "-Wl,-headerpad_max_install_names"
        || env.deployment.is_empty()
        || !env
            .deployment
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
    {
        bail!("maintenance_recipe_environment_invalid");
    }
    if p.recipe.make_argv != vec![format!("-j{}", l.max_build_jobs), "all".into()]
        || p.recipe.install_argv != ["install"]
    {
        bail!("maintenance_recipe_make_invalid");
    }
    let allowed = [
        "--without-icu",
        "--without-readline",
        "--without-zlib",
        "--without-openssl",
        "--without-gssapi",
        "--without-ldap",
        "--without-libxml",
        "--without-libxslt",
        "--prefix=/wrokbot-maintenance-v2",
    ];
    if p.recipe.configure_argv.len() != allowed.len()
        || p.recipe
            .configure_argv
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != allowed.into_iter().collect()
    {
        bail!("maintenance_recipe_configure_invalid");
    }
    Ok(())
}
fn tool(role: &str, t: &Tool, path: &str) -> Result<BuildTool> {
    if t.path != path || !manifest::valid_sha(&t.sha256) || t.bytes == 0 {
        bail!("maintenance_build_tool_invalid");
    }
    let got = hash_fixed_system_tool(Path::new(&t.path), t.bytes)?;
    if (got.bytes, got.sha256.as_str()) != (t.bytes, t.sha256.as_str()) {
        bail!("maintenance_build_tool_changed");
    }
    Ok(BuildTool {
        role: role.into(),
        path: t.path.clone(),
        bytes: t.bytes,
        sha256: t.sha256.clone(),
    })
}
fn hash_fixed_system_tool(path: &Path, expected_bytes: u64) -> Result<FileDigest> {
    // Only tool()'s closed fixed external roles use this reader. Source/archive/output readers
    // keep their original nlink=1 rule. Apple launchers may share a real immutable system inode.
    fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    let before = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.nlink() == 0
        || before.len() != expected_bytes
        || before.uid() != 0
        || before.mode() & 0o6022 != 0
        || before.mode() & 0o111 == 0
    {
        bail!("maintenance_build_tool_privileged_or_mutable");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if identity(&file.metadata()?) != identity(&before) {
        bail!("maintenance_build_tool_changed");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    let bound = expected_bytes
        .checked_add(1)
        .context("maintenance_size_overflow")?;
    let mut limited = (&mut file).take(bound);
    loop {
        let n = limited.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("maintenance_size_overflow")?;
        if bytes > expected_bytes {
            bail!("maintenance_build_tool_changed");
        }
        digest.update(&buffer[..n]);
    }
    if bytes != expected_bytes
        || identity(&file.metadata()?) != identity(&before)
        || identity(&fs::symlink_metadata(path)?) != identity(&before)
    {
        bail!("maintenance_build_tool_changed");
    }
    Ok(FileDigest {
        bytes,
        sha256: format!("{:x}", digest.finalize()),
    })
}
fn sdk_digest(root: &Path, p: &Profile, b: &Budget) -> Result<String> {
    fn walk(
        root: &Path,
        dir: &Path,
        p: &Profile,
        b: &Budget,
        out: &mut Sha256,
        totals: (&mut u64, &mut u64),
        depth: u32,
    ) -> Result<()> {
        let (n, bytes) = totals;
        if depth > 64 {
            bail!("maintenance_sdk_depth");
        }
        let mut entries = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            b.check()?;
            *n = n.checked_add(1).context("maintenance_sdk_count")?;
            if *n > p.limits.max_build_files {
                bail!("maintenance_sdk_file_limit");
            }
            let path = entry.path();
            let m = fs::symlink_metadata(&path)?;
            let rel = path
                .strip_prefix(root)?
                .to_str()
                .context("maintenance_sdk_utf8")?;
            manifest::relative(rel)?;
            out.update((rel.len() as u64).to_be_bytes());
            out.update(rel.as_bytes());
            out.update((m.mode() & 0o777).to_be_bytes());
            if m.is_dir() {
                out.update([1]);
                walk(root, &path, p, b, out, (&mut *n, &mut *bytes), depth + 1)?;
            } else if m.file_type().is_symlink() {
                out.update([2]);
                let target = fs::read_link(&path)?;
                let real = fs::canonicalize(&path)?;
                if !real.starts_with(root) {
                    bail!("maintenance_sdk_link_escape");
                }
                let target = target.to_str().context("maintenance_sdk_utf8")?;
                out.update((target.len() as u64).to_be_bytes());
                out.update(target.as_bytes());
            } else if m.is_file() {
                out.update([3]);
                *bytes = bytes
                    .checked_add(m.len())
                    .context("maintenance_sdk_bytes")?;
                if *bytes > p.limits.max_expanded_source_bytes {
                    bail!("maintenance_sdk_byte_limit");
                }
                let d = manifest::hash_regular(&path, p.limits.max_expanded_source_bytes)?;
                out.update(d.bytes.to_be_bytes());
                out.update(d.sha256.as_bytes());
            } else {
                bail!("maintenance_sdk_special");
            }
        }
        Ok(())
    }
    let mut digest = Sha256::new();
    digest.update(b"wrokbot-maintenance-sdk-tree-v1\0");
    walk(root, root, p, b, &mut digest, (&mut 0, &mut 0), 0)?;
    Ok(format!("{:x}", digest.finalize()))
}
fn verify_tools(p: &Profile, b: &Budget) -> Result<Vec<BuildTool>> {
    let t = &p.tools;
    if t.system_utilities.uname.is_none() {
        bail!("maintenance_explicit_uname_required");
    }
    let mut out = Vec::new();
    for (role, t, path) in [
        ("git", &t.git, "/usr/bin/git"),
        ("shell", &t.shell, "/bin/sh"),
        ("make", &t.make, "/usr/bin/make"),
        ("compiler", &t.compiler, "/usr/bin/clang"),
        ("archiver", &t.archiver, "/usr/bin/ar"),
        ("ranlib", &t.ranlib, "/usr/bin/ranlib"),
        ("linker", &t.linker, "/usr/bin/ld"),
    ] {
        out.push(tool(role, t, path)?);
    }
    for (role, path, bytes, sha) in [
        (
            "compilerResolved",
            "/Library/Developer/CommandLineTools/usr/bin/clang",
            124676976u64,
            "1590ac950a3d627817d09ade5cb60b2115f17a72182a3141e010b4bcc482a0c9",
        ),
        (
            "linkerResolved",
            "/Library/Developer/CommandLineTools/usr/bin/ld",
            2749664u64,
            "374d9f0713bce2c8a9e1e82bde51615d5433516a10d99b63107eb6ee70542e4c",
        ),
    ] {
        out.push(tool(
            role,
            &Tool {
                path: path.into(),
                bytes,
                sha256: sha.into(),
            },
            path,
        )?);
    }
    for (role, path, bytes, sha) in manifest::FIXED_INTERNAL_TOOLS {
        b.check()?;
        out.push(tool(
            role,
            &Tool {
                path: path.into(),
                bytes,
                sha256: sha.into(),
            },
            path,
        )?);
    }
    if let Some(t) = &t.otool {
        out.push(tool("otool", t, "/usr/bin/otool")?);
    }
    if let Some(t) = &t.install_name_tool {
        out.push(tool("installNameTool", t, "/usr/bin/install_name_tool")?);
    }
    let u = &t.system_utilities;
    for (role, value) in [
        ("awk", &u.awk),
        ("basename", &u.basename),
        ("cat", &u.cat),
        ("chmod", &u.chmod),
        ("cp", &u.cp),
        ("cut", &u.cut),
        ("dirname", &u.dirname),
        ("expr", &u.expr),
        ("find", &u.find),
        ("grep", &u.grep),
        ("head", &u.head),
        ("install", &u.install),
        ("ln", &u.ln),
        ("mkdir", &u.mkdir),
        ("mv", &u.mv),
        ("perl", &u.perl),
        ("pwd", &u.pwd),
        ("rm", &u.rm),
        ("sed", &u.sed),
        ("sort", &u.sort),
        ("tail", &u.tail),
        ("test", &u.test),
        ("tr", &u.tr),
        ("uname", &u.uname),
    ] {
        if let Some(t) = value {
            if t.path != format!("/bin/{role}") && t.path != format!("/usr/bin/{role}") {
                bail!("maintenance_utility_path");
            }
            out.push(tool(role, t, &t.path)?);
        }
    }
    if !manifest::valid_sha(&t.sdk.tree_sha256)
        || t.sdk.version.is_empty()
        || !Path::new(&t.sdk.path).is_absolute()
        || fs::canonicalize(&t.sdk.path)? != Path::new(&t.sdk.path)
    {
        bail!("maintenance_sdk_invalid");
    }
    if sdk_digest(Path::new(&t.sdk.path), p, b)? != t.sdk.tree_sha256 {
        bail!("maintenance_sdk_changed");
    }
    Ok(out)
}
fn space(path: &Path, p: &Profile, remaining: u64) -> Result<()> {
    let s = rustix::fs::statvfs(path)?;
    space_snapshot(&s, p, remaining)
}
fn space_snapshot(s: &rustix::fs::StatVfs, p: &Profile, remaining: u64) -> Result<()> {
    let free = (s.f_bavail as u64)
        .checked_mul(s.f_frsize as u64)
        .context("maintenance_space_overflow")?;
    let need = remaining
        .checked_add(p.limits.capacity_reserve_bytes)
        .and_then(|n| n.checked_add(p.limits.free_floor_bytes))
        .context("maintenance_space_overflow")?;
    if free < need {
        bail!("maintenance_build_capacity");
    }
    Ok(())
}
fn command(
    program: &str,
    args: &[String],
    cwd: &Path,
    p: &Profile,
    b: &mut Budget,
) -> Result<Vec<u8>> {
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
    b.check()?;
    require_live_process_capacity(p, b)?;
    require_no_pkg_config()?;
    observe_owned(p, b, false)?;
    // An additional direct-Command bound; never a cumulative descendant count.
    b.direct_commands = b
        .direct_commands
        .checked_add(1)
        .context("maintenance_direct_command_count_overflow")?;
    if b.direct_commands > b.direct_limit {
        bail!("maintenance_direct_command_count");
    }
    let e = &p.recipe.environment;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("DEVELOPER_DIR", FIXED_DEVELOPER_DIR)
        .env("PATH", &e.path)
        .env("CC", &e.cc)
        .env("AR", &e.ar)
        .env("RANLIB", &e.ranlib)
        .env("SDKROOT", &e.sdkroot)
        .env("MACOSX_DEPLOYMENT_TARGET", &e.deployment)
        .env("CFLAGS", &e.cflags)
        .env("CPPFLAGS", &e.cppflags)
        .env("LDFLAGS", &e.ldflags)
        .env("LC_ALL", &e.locale)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("maintenance_build_spawn")?;
    // From spawn through original wait and both joins no fallible path returns early.
    let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    let count = Arc::new(AtomicU64::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let cap = p.limits.max_tool_output_bytes;
    let drain = |mut pipe: Box<dyn Read + Send>, count: Arc<AtomicU64>, over: Arc<AtomicBool>| {
        thread::Builder::new()
            .name("maintenance-build-pipe".into())
            .spawn(move || -> std::io::Result<Vec<u8>> {
                let mut out = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = match pipe.read(&mut buf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    if n == 0 {
                        break;
                    }
                    let old = count.fetch_add(n as u64, Ordering::SeqCst);
                    if old.checked_add(n as u64).is_none_or(|v| v > cap) {
                        over.store(true, Ordering::SeqCst);
                    } else {
                        out.extend_from_slice(&buf[..n]);
                    }
                }
                Ok(out)
            })
    };
    let mut first_failure = pid.is_none().then_some("pid");
    let mut first_owned_error: Option<anyhow::Error> = None;
    let mut failed = pid.is_none();
    let stdout = match child.stdout.take() {
        Some(pipe) => match drain(Box::new(pipe), Arc::clone(&count), Arc::clone(&overflow)) {
            Ok(join) => Some(join),
            Err(_) => {
                first_failure.get_or_insert("stdout_drain_spawn");
                failed = true;
                None
            }
        },
        None => {
            first_failure.get_or_insert("stdout_pipe");
            failed = true;
            None
        }
    };
    let stderr = match child.stderr.take() {
        Some(pipe) => match drain(Box::new(pipe), count, Arc::clone(&overflow)) {
            Ok(join) => Some(join),
            Err(_) => {
                first_failure.get_or_insert("stderr_drain_spawn");
                failed = true;
                None
            }
        },
        None => {
            first_failure.get_or_insert("stderr_pipe");
            failed = true;
            None
        }
    };
    let (mut term_sent, mut kill_sent, mut leader_exited) = (false, false, false);
    let mut last_observation = 0u64;
    let kill_at = b.end + (b.close - b.end) / 2;
    loop {
        let mut same_original_child = false;
        if let Some(pid) = pid {
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
            ) {
                Ok(Some(s)) => {
                    same_original_child = true;
                    leader_exited = s.exited() || s.killed() || s.dumped();
                    if !s.exited() || s.exit_status() != Some(0) {
                        first_failure.get_or_insert("leader_status");
                        failed = true;
                    }
                }
                Ok(None) => same_original_child = true,
                Err(_) => {
                    first_failure.get_or_insert("waitid");
                    failed = true;
                }
            }
        } else {
            match child.try_wait() {
                Ok(Some(_)) => leader_exited = true,
                Ok(None) => {}
                Err(_) => {
                    first_failure.get_or_insert("try_wait");
                    failed = true;
                }
            }
        }
        let now = match clock() {
            Ok(n) => Some(n),
            Err(_) => {
                first_failure.get_or_insert("clock");
                failed = true;
                None
            }
        };
        if let Some(now) = now {
            if now >= b.end || now < last_observation {
                first_failure.get_or_insert("effect_or_clock_reversal");
                failed = true;
            }
            if last_observation == 0 || now.saturating_sub(last_observation) >= 100_000_000 {
                if let Err(error) = observe_owned(p, b, true) {
                    first_failure.get_or_insert("owned_observation");
                    first_owned_error.get_or_insert(error);
                    failed = true;
                }
                last_observation = now;
            }
            if now >= b.close {
                first_failure.get_or_insert("convergence_deadline");
                failed = true;
            }
            if failed
                && same_original_child
                && now < b.close
                && let Some(pid) = pid
            {
                if !term_sent {
                    let _ = kill_process_group(pid, Signal::TERM);
                    term_sent = true;
                }
                if now >= kill_at && !kill_sent {
                    let _ = kill_process_group(pid, Signal::KILL);
                    kill_sent = true;
                }
            }
        }
        if overflow.load(Ordering::SeqCst) {
            first_failure.get_or_insert("output_overflow");
            failed = true;
        }
        let pipes_done = stdout.as_ref().is_none_or(|j| j.is_finished())
            && stderr.as_ref().is_none_or(|j| j.is_finished());
        if leader_exited && pipes_done {
            break;
        }
        // WNOWAIT keeps this original leader waitable, preventing group-id reuse.
        // An unknown wait/clock retains this owner; C never authorizes a fabricated close.
        thread::sleep(Duration::from_millis(10));
    }
    let status = loop {
        match child.wait() {
            Ok(s) => break s,
            Err(_) => {
                first_failure.get_or_insert("original_wait");
                failed = true;
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let out = stdout.map(|j| j.join());
    let err = stderr.map(|j| j.join());
    let stdout_join_ok = matches!(&out, Some(Ok(Ok(_))));
    let stderr_join_ok = matches!(&err, Some(Ok(Ok(_))));
    let out = match out {
        Some(Ok(Ok(v))) => v,
        _ => {
            first_failure.get_or_insert("stdout_join_or_read");
            failed = true;
            Vec::new()
        }
    };
    if !matches!(&err, Some(Ok(Ok(_)))) {
        first_failure.get_or_insert("stderr_join_or_read");
        failed = true;
    }
    if failed || !status.success() || overflow.load(Ordering::SeqCst) {
        let stderr_bytes = match &err {
            Some(Ok(Ok(bytes))) => bytes.as_slice(),
            _ => &[],
        };
        let owned_io = first_owned_error
            .as_ref()
            .and_then(|error| error.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error);
        struct BoundedOwnedDisplay {
            bytes: [u8; 2048],
            len: usize,
        }
        impl std::fmt::Write for BoundedOwnedDisplay {
            fn write_str(&mut self, text: &str) -> std::fmt::Result {
                let count = text.len().min(self.bytes.len() - self.len);
                self.bytes[self.len..self.len + count]
                    .copy_from_slice(&text.as_bytes()[..count]);
                self.len += count;
                if count < text.len() {
                    Err(std::fmt::Error)
                } else {
                    Ok(())
                }
            }
        }
        let mut owned_text = BoundedOwnedDisplay {
            bytes: [0; 2048],
            len: 0,
        };
        let owned_format_complete = first_owned_error.as_ref().is_none_or(|error| {
            std::fmt::write(&mut owned_text, format_args!("{error}")).is_ok()
        });
        // Pure diagnostic tails of already collected bytes; no collection cap is increased.
        bail!(
            "maintenance_build_command_failed: program={program:?}; status={status}; \
             first_failure={first_failure:?}; failed={failed}; overflow={}; \
             stdout_join_ok={stdout_join_ok}; stderr_join_ok={stderr_join_ok}; \
             stdout_bytes={}; stderr_bytes={}; stdout_tail={:?}; stderr_tail={:?}; \
             owned_io={owned_io:?}; owned_format_complete={owned_format_complete}; owned_error_prefix={:?}",
            overflow.load(Ordering::SeqCst),
            out.len(),
            stderr_bytes.len(),
            String::from_utf8_lossy(&out[out.len().saturating_sub(2048)..]),
            String::from_utf8_lossy(&stderr_bytes[stderr_bytes.len().saturating_sub(8192)..]),
            String::from_utf8_lossy(&owned_text.bytes[..owned_text.len]),
        );
    }
    observe_owned(p, b, false)?;
    b.check()?;
    Ok(out)
}
fn validate_patch_scope(patch: &[u8]) -> Result<BTreeSet<String>> {
    let text = std::str::from_utf8(patch)?;
    let mut lines = text.lines();
    let mut names = BTreeSet::new();
    while let Some(line) = lines.next() {
        if line.starts_with("diff ")
            || line.starts_with("GIT binary patch")
            || line.starts_with("Binary files ")
        {
            bail!("maintenance_patch_format");
        }
        if let Some(old) = line.strip_prefix("--- ") {
            let new = lines
                .next()
                .and_then(|s| s.strip_prefix("+++ b/"))
                .context("maintenance_patch_header")?;
            manifest::relative(new)?;
            if !allowed_source(new)
                || !names.insert(new.into())
                || !(old == "/dev/null" || old.strip_prefix("a/") == Some(new))
            {
                bail!("maintenance_patch_path");
            }
        }
    }
    if names.is_empty() {
        bail!("maintenance_patch_empty");
    }
    Ok(names)
}
fn preimages(source: &Path, pins: &Pins, b: &Budget, after: bool) -> Result<()> {
    for item in &pins.derived_sources {
        b.check()?;
        let path = source.join(&item.path);
        let expected = if after {
            Some(&item.after)
        } else {
            item.before.as_ref()
        };
        if let Some(d) = expected {
            let a = manifest::hash_regular(&path, d.bytes)?;
            if a != *d {
                bail!("maintenance_derived_source_mismatch");
            }
        } else if path.exists() {
            bail!("maintenance_new_source_already_exists");
        }
    }
    Ok(())
}
fn archive_inventory(bytes: &[u8], p: &Profile, b: &Budget) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut seen = BTreeSet::new();
    let (mut count, mut total) = (0u64, 0u64);
    for entry in archive.entries()? {
        b.check()?;
        let entry = entry?;
        let rel = entry.path()?;
        let raw = rel.to_str().context("maintenance_archive_utf8")?;
        let kind = entry.header().entry_type();
        let name = if kind.is_dir() {
            raw.strip_suffix('/').unwrap_or(raw)
        } else {
            raw
        };
        if kind.is_pax_global_extensions() {
            if name != "pax_global_header" || entry.size() > 4096 {
                bail!("maintenance_archive_pax");
            }
            continue;
        }
        manifest::relative(name)?;
        if (name != "postgresql-17.11" && !name.starts_with("postgresql-17.11/"))
            || !seen.insert(name.to_owned())
            || !(kind.is_file() || kind.is_dir())
            || (kind.is_dir() && entry.size() != 0)
        {
            bail!("maintenance_archive_layout");
        }
        count = count.checked_add(1).context("maintenance_archive_count")?;
        total = total
            .checked_add(entry.size())
            .context("maintenance_archive_size")?;
        if count > p.limits.max_source_files
            || count > p.limits.max_build_files
            || total > p.limits.max_expanded_source_bytes
            || total
                .checked_add(p.patch.bytes)
                .context("maintenance_derived_overflow")?
                > p.limits.max_derived_bytes
        {
            bail!("maintenance_archive_capacity");
        }
    }
    Ok(())
}
fn unpack(bytes: &[u8], root: &Path, p: &Profile, b: &Budget) -> Result<PathBuf> {
    // The immutable in-memory archive was completely capacity-checked before creating roots.
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut total = 0u64;
    let mut allocated = 0u64;
    let mut allocations = std::collections::BTreeMap::<PathBuf, u64>::new();
    let (derived, output) = b
        .owned
        .as_ref()
        .context("maintenance_build_roots_missing")?;
    let (derived, output) = (derived.path.as_path(), output.path.as_path());
    let same_volume = fs::metadata(derived)?.dev() == fs::metadata(output)?.dev();
    for entry in archive.entries()? {
        b.check()?;
        let mut entry = entry?;
        let rel = entry.path()?.into_owned();
        if entry.header().entry_type().is_pax_global_extensions() {
            continue;
        }
        total = total
            .checked_add(entry.size())
            .context("maintenance_archive_size")?;
        if total > p.limits.max_expanded_source_bytes
            || total
                .checked_add(p.patch.bytes)
                .context("maintenance_derived_overflow")?
                > p.limits.max_derived_bytes
        {
            bail!("maintenance_archive_capacity");
        }
        let mut remaining = p
            .limits
            .max_derived_bytes
            .saturating_sub(allocated)
            .checked_add(p.limits.max_install_bytes)
            .context("maintenance_peak_overflow")?;
        if same_volume {
            remaining = remaining
                .checked_add(p.limits.max_bundle_bytes)
                .context("maintenance_peak_overflow")?;
        } else {
            space(output, p, p.limits.max_bundle_bytes)?;
        }
        space(derived, p, remaining)?;
        if !entry.unpack_in(root)? {
            bail!("maintenance_archive_escape");
        }
        // Charge observed allocated blocks, including changed parent directories, once per path.
        let dest = root.join(rel);
        for path in dest.ancestors().take_while(|a| a.starts_with(derived)) {
            let now = fs::symlink_metadata(path)?
                .blocks()
                .checked_mul(512)
                .context("maintenance_allocated_overflow")?;
            let old = allocations.insert(path.to_path_buf(), now).unwrap_or(0);
            allocated = allocated
                .checked_sub(old)
                .and_then(|v| v.checked_add(now))
                .context("maintenance_allocated_overflow")?;
        }
    }
    observe_owned(p, b, false)?;
    Ok(root.join("postgresql-17.11"))
}
#[derive(Default)]
struct Usage {
    logical: u64,
    allocated: u64,
    nodes: u64,
}
fn usage(root: &Path, p: &Profile, b: &Budget, bounds: (u64, bool)) -> Result<Usage> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    fn same(a: &rustix::fs::Stat, b: &rustix::fs::Stat) -> bool {
        (a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode)
            == (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode)
    }
    fn not_found(error: &anyhow::Error) -> bool {
        error.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    }
    fn walk(
        dir: &fs::File,
        p: &Profile,
        b: &Budget,
        bounds: (u64, bool),
        u: &mut Usage,
        seen: &mut BTreeSet<(u64, u64)>,
        depth: u32,
    ) -> Result<()> {
        let (max, live) = bounds;
        if depth > 64 {
            bail!("maintenance_build_tree_depth");
        }
        let dm = rustix::fs::fstat(dir).map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(dm.st_mode) != FileType::Directory {
            bail!("maintenance_build_tree_root");
        }
        if seen.insert((dm.st_dev as u64, dm.st_ino)) {
            u.allocated = u.allocated
                .checked_add(u64::try_from(dm.st_blocks)?
                    .checked_mul(512).context("maintenance_allocated_overflow")?)
                .context("maintenance_allocated_overflow")?;
        }
        // read_from opens an independent directory stream; never follows an entry path.
        let entries = rustix::fs::Dir::read_from(dir).map_err(std::io::Error::from)?;
        for entry in entries {
            let entry = entry.map_err(std::io::Error::from)?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            b.check()?;
            // Charge every successfully enumerated name before any possible disappearance.
            u.nodes = u.nodes.checked_add(1).context("maintenance_build_tree_count")?;
            if u.nodes > p.limits.max_build_files {
                bail!("maintenance_build_tree_files");
            }
            let m = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(m) => m,
                Err(rustix::io::Errno::NOENT) if live => continue,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            if !live && m.st_ino != entry.ino() {
                bail!("maintenance_build_child_identity");
            }
            match FileType::from_raw_mode(m.st_mode) {
                FileType::Directory => {
                    let child = match rustix::fs::openat(
                        dir, name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(fd) => fs::File::from(fd),
                        Err(rustix::io::Errno::NOENT) if live => continue,
                        Err(error) => return Err(std::io::Error::from(error).into()),
                    };
                    let held = rustix::fs::fstat(&child).map_err(std::io::Error::from)?;
                    if !same(&m, &held) {
                        bail!("maintenance_build_child_identity");
                    }
                    let result = walk(&child, p, b, bounds, u, seen, depth + 1);
                    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                        Err(rustix::io::Errno::NOENT) if live => {
                            // Only this enumerated child's confirmed disappearance can explain
                            // an inner NotFound; capacity/clock/permission/other errors survive.
                            if let Err(error) = result && !not_found(&error) {
                                return Err(error);
                            }
                        }
                        Ok(named) => {
                            if !same(&m, &named) {
                                bail!("maintenance_build_child_identity");
                            }
                            result?;
                        }
                        Err(error) => return Err(std::io::Error::from(error).into()),
                    }
                }
                FileType::RegularFile | FileType::Symlink => {
                    if FileType::from_raw_mode(m.st_mode) == FileType::RegularFile {
                        u.logical = u.logical
                            .checked_add(u64::try_from(m.st_size)?)
                            .context("maintenance_build_tree_bytes")?;
                    }
                    if seen.insert((m.st_dev as u64, m.st_ino)) {
                        u.allocated = u.allocated
                            .checked_add(u64::try_from(m.st_blocks)?
                                .checked_mul(512).context("maintenance_allocated_overflow")?)
                            .context("maintenance_allocated_overflow")?;
                    }
                    if u.logical > max {
                        bail!("maintenance_build_tree_limit");
                    }
                }
                _ => bail!("maintenance_build_tree_special"),
            }
        }
        Ok(())
    }
    let Some((derived, output)) = &b.owned else {
        bail!("maintenance_build_roots_missing");
    };
    derived.verify()?;
    output.verify()?;
    let install;
    let (owner, directory, install_root) = if root == derived.path.as_path() {
        (derived, &derived.directory, false)
    } else if root == output.path.as_path() {
        (output, &output.directory, false)
    } else if root == derived.path.join("install").as_path() {
        install = fs::File::from(rustix::fs::openat(
            &derived.directory, c"install",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ).map_err(std::io::Error::from)?);
        (derived, &install, true)
    } else {
        bail!("maintenance_build_unknown_usage_root");
    };
    let initial = rustix::fs::fstat(directory).map_err(std::io::Error::from)?;
    let mut u = Usage::default();
    // The requested root itself is never allowed to disappear, even in live mode.
    let result = walk(directory, p, b, bounds, &mut u, &mut BTreeSet::new(), 0);
    owner.verify()?;
    derived.verify()?;
    output.verify()?;
    if install_root {
        let named = rustix::fs::statat(
            &derived.directory, c"install", AtFlags::SYMLINK_NOFOLLOW,
        ).map_err(std::io::Error::from)?;
        if !same(&initial, &named) {
            bail!("maintenance_build_root_identity");
        }
    }
    result?;
    Ok(u)
}
fn tree_usage(root: &Path, p: &Profile, b: &Budget, max: u64) -> Result<()> {
    usage(root, p, b, (max, false)).map(|_| ())
}
fn observe_owned(p: &Profile, b: &Budget, live: bool) -> Result<()> {
    let Some((derived, output)) = &b.owned else {
        return Ok(());
    };
    derived.verify()?;
    output.verify()?;
    let all = usage(
        &derived.path, p, b,
        (p.limits.max_derived_bytes
            .checked_add(p.limits.max_install_bytes).context("maintenance_peak_overflow")?, live),
    )?;
    let stage = derived.path.join("install");
    let install = match rustix::fs::statat(
        &derived.directory, c"install", rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(m) => {
            if rustix::fs::FileType::from_raw_mode(m.st_mode) != rustix::fs::FileType::Directory {
                bail!("maintenance_build_tree_root");
            }
            usage(&stage, p, b, (p.limits.max_install_bytes, live))?
        }
        // This exact optional stage is absent before its original fresh_dir; no other error hides.
        Err(rustix::io::Errno::NOENT) => Usage::default(),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    let core_bytes = all.logical.checked_sub(install.logical)
        .context("maintenance_build_tree_accounting")?;
    if core_bytes > p.limits.max_derived_bytes {
        bail!("maintenance_build_tree_limit");
    }
    let out = usage(&output.path, p, b, (p.limits.max_bundle_bytes, live))?;
    // Live snapshots cannot prove sampled blocks still exist at the later free-space query.
    // Use them for cap observations only, never to reduce required remaining capacity.
    let (core_allocated, install_allocated, output_allocated) = if live {
        (0, 0, 0)
    } else {
        (
            all.allocated.saturating_sub(install.allocated),
            install.allocated,
            out.allocated,
        )
    };
    let derived_remaining = p.limits.max_derived_bytes.saturating_sub(core_allocated)
        .checked_add(p.limits.max_install_bytes.saturating_sub(install_allocated))
        .context("maintenance_peak_overflow")?;
    let output_remaining = p.limits.max_bundle_bytes.saturating_sub(output_allocated);
    let dstat = rustix::fs::fstat(&derived.directory).map_err(std::io::Error::from)?;
    let ostat = rustix::fs::fstat(&output.directory).map_err(std::io::Error::from)?;
    if dstat.st_dev == ostat.st_dev {
        space_snapshot(
            &rustix::fs::fstatvfs(&derived.directory).map_err(std::io::Error::from)?, p,
            derived_remaining.checked_add(output_remaining).context("maintenance_peak_overflow")?,
        )?;
    } else {
        space_snapshot(
            &rustix::fs::fstatvfs(&derived.directory).map_err(std::io::Error::from)?, p, derived_remaining,
        )?;
        space_snapshot(
            &rustix::fs::fstatvfs(&output.directory).map_err(std::io::Error::from)?, p, output_remaining,
        )?;
    }
    derived.verify()?;
    output.verify()?;
    Ok(())
}
fn macho_file(path: &Path) -> Result<bool> {
    let mut buf = [0u8; 4];
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x100 | 0x4)
        .open(path)?;
    if f.read(&mut buf)? != 4 {
        return Ok(false);
    }
    Ok(matches!(
        buf,
        [0xCF, 0xFA, 0xED, 0xFE]
            | [0xFE, 0xED, 0xFA, 0xCF]
            | [0xCA, 0xFE, 0xBA, 0xBE]
            | [0xBE, 0xBA, 0xFE, 0xCA]
    ))
}
fn runtime_library_file(path: &Path) -> Result<bool> {
    let mut buf = [0u8; 32];
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x100 | 0x4)
        .open(path)?;
    if let Err(error) = f.read_exact(&mut buf) {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(error.into());
    }
    let cpu = match std::env::consts::ARCH {
        "aarch64" => 0x0100000c_u32,
        "x86_64" => 0x01000007,
        _ => return Ok(false),
    };
    // Select only the consumer's thin64 host-architecture library kinds. PGXS executables
    // remain build outputs, not an additional runtime program hidden under lib/.
    Ok(buf[..4] == [0xcf, 0xfa, 0xed, 0xfe]
        && u32::from_le_bytes(buf[4..8].try_into()?) == cpu
        && matches!(u32::from_le_bytes(buf[12..16].try_into()?), 6 | 8))
}
fn sync_tree(root: &Path, b: &Budget) -> Result<()> {
    for entry in fs::read_dir(root)? {
        b.check()?;
        let path = entry?.path();
        let m = fs::symlink_metadata(&path)?;
        if m.is_dir() {
            sync_tree(&path, b)?;
        } else if m.is_file() {
            std::fs::File::open(path)?.sync_all()?;
        } else {
            bail!("maintenance_sync_special");
        }
    }
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
fn copy_bundle_file(
    source: &Path,
    target: &Path,
    mode: u32,
    p: &Profile,
    b: &Budget,
    sum: &mut u64,
    count: &mut u64,
) -> Result<()> {
    b.check()?;
    let m = fs::symlink_metadata(source)?;
    if !m.is_file() {
        bail!("maintenance_install_special");
    }
    let next_sum = sum
        .checked_add(m.len())
        .context("maintenance_bundle_overflow")?;
    let next_count = count.checked_add(1).context("maintenance_bundle_count")?;
    if next_sum > p.limits.max_bundle_bytes || next_count > p.limits.max_build_files {
        bail!("maintenance_bundle_limit");
    }
    space(
        target.parent().context("maintenance_bundle_parent")?,
        p,
        m.len(),
    )?;
    *sum = next_sum;
    *count = next_count;
    if fs::copy(source, target)? != m.len() {
        bail!("maintenance_bundle_copy_changed");
    }
    fs::set_permissions(target, fs::Permissions::from_mode(mode))?;
    b.check()?;
    Ok(())
}
fn copy_tree(
    source: &Path,
    target: &Path,
    context: (&Path, &Profile, &Budget),
    totals: (&mut u64, &mut u64),
    depth: u32,
    seen: &mut BTreeSet<(u64, u64)>,
    runtime_lib: bool,
) -> Result<()> {
    let (inside, p, b) = context;
    let (sum, count) = totals;
    if depth > 64 {
        bail!("maintenance_install_depth");
    }
    let m = fs::metadata(source)?;
    if !seen.insert((m.dev(), m.ino())) {
        bail!("maintenance_install_directory_cycle");
    }
    *count = count.checked_add(1).context("maintenance_bundle_count")?;
    if *count > p.limits.max_build_files {
        bail!("maintenance_bundle_limit");
    }
    space(target.parent().context("maintenance_bundle_parent")?, p, 0)?;
    fs::DirBuilder::new().mode(0o700).create(target)?;
    for item in fs::read_dir(source)? {
        b.check()?;
        let item = item?;
        let path = item.path();
        let dest = target.join(item.file_name());
        if runtime_lib && fs::symlink_metadata(&path)?.file_type().is_symlink() {
            continue;
        }
        let real = fs::canonicalize(&path)?;
        if !real.starts_with(inside) {
            bail!("maintenance_install_link_escape");
        }
        if fs::metadata(&real)?.is_dir() {
            copy_tree(
                &real,
                &dest,
                (inside, p, b),
                (&mut *sum, &mut *count),
                depth + 1,
                seen,
                runtime_lib,
            )?;
            if fs::read_dir(&dest)?.next().is_none() {
                fs::remove_dir(&dest)?;
            }
        } else {
            if !fs::metadata(&real)?.is_file() {
                bail!("maintenance_install_special");
            }
            if runtime_lib && !runtime_library_file(&real)? {
                continue;
            }
            copy_bundle_file(&real, &dest, 0o644, p, b, sum, count)?;
        }
    }
    seen.remove(&(m.dev(), m.ino()));
    Ok(())
}
fn validate_loader(root: &Path, file: &Path, libraries: &str, commands: &str) -> Result<()> {
    fn inside(root: &Path, path: PathBuf) -> Result<PathBuf> {
        let real = fs::canonicalize(path)?;
        if !real.starts_with(root) || !real.is_file() {
            bail!("maintenance_library_escape");
        }
        Ok(real)
    }
    let mut rpaths = Vec::new();
    let mut rpath = false;
    for line in commands.lines() {
        let line = line.trim();
        if line == "cmd LC_RPATH" {
            rpath = true;
            continue;
        }
        if rpath
            && let Some(path) = line
                .strip_prefix("path ")
                .and_then(|s| s.split(" (offset ").next())
        {
            let candidate = if let Some(rest) = path.strip_prefix("@loader_path/") {
                file.parent().unwrap().join(rest)
            } else if let Some(rest) = path.strip_prefix("@executable_path/") {
                root.join("bin").join(rest)
            } else {
                bail!("maintenance_rpath_invalid");
            };
            let real = fs::canonicalize(candidate)?;
            if !real.starts_with(root) || !real.is_dir() {
                bail!("maintenance_rpath_escape");
            }
            rpaths.push(real);
            rpath = false;
        }
    }
    if rpath {
        bail!("maintenance_rpath_invalid");
    }
    for line in libraries.lines().skip(1) {
        let dep = line
            .split_whitespace()
            .next()
            .context("maintenance_library_empty")?;
        if dep.starts_with("/usr/lib/") || dep.starts_with("/System/Library/") {
            continue;
        }
        if let Some(t) = dep.strip_prefix("@loader_path/") {
            inside(root, file.parent().unwrap().join(t))?;
        } else if let Some(t) = dep.strip_prefix("@executable_path/") {
            inside(root, root.join("bin").join(t))?;
        } else if let Some(t) = dep.strip_prefix("@rpath/") {
            if !rpaths.iter().any(|p| inside(root, p.join(t)).is_ok()) {
                bail!("maintenance_rpath_unresolved");
            }
        } else {
            bail!("maintenance_library_escape");
        }
    }
    Ok(())
}
pub(super) fn build(
    root: &Path,
    archive: &Path,
    derived: &Path,
    output: &Path,
    profile: &Path,
) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    bail!("maintenance_build_platform_unsupported");
    let pins = pins(root)?;
    let profile_bytes = manifest::read_regular(profile, 1024 * 1024)?;
    let p: Profile = serde_json::from_slice(&profile_bytes)?;
    validate_profile(&p, &pins)?;
    let mut budget = Budget::new(&p.limits)?;
    require_no_pkg_config()?;
    let aliases = checked_clt_aliases()?;
    let tools = verify_tools(&p, &budget)?;
    if checked_clt_aliases()? != aliases {
        bail!("maintenance_fixed_tool_alias_changed");
    }
    install_live_process_capacity(&p, &mut budget)?;
    verify_build_os(root, &p, &mut budget)?;
    budget.check()?;
    let bytes = manifest::read_regular(archive, p.limits.max_archive_bytes)?;
    if manifest::digest_bytes(&bytes)
        != (FileDigest {
            bytes: manifest::ARCHIVE_BYTES,
            sha256: manifest::ARCHIVE_SHA.into(),
        })
    {
        bail!("maintenance_archive_pin");
    }
    let patch = manifest::read_regular(&root.join(&pins.patch.path), pins.patch.bytes)?;
    if manifest::digest_bytes(&patch)
        != (FileDigest {
            bytes: pins.patch.bytes,
            sha256: pins.patch.sha256.clone(),
        })
    {
        bail!("maintenance_patch_pin");
    }
    validate_patch_scope(&patch)?;
    archive_inventory(&bytes, &p, &budget)?;
    if derived.starts_with(output) || output.starts_with(derived) {
        bail!("maintenance_root_overlap");
    }
    let peak = p
        .limits
        .max_derived_bytes
        .checked_add(p.limits.max_install_bytes)
        .and_then(|v| v.checked_add(p.limits.max_bundle_bytes))
        .context("maintenance_peak_overflow")?;
    let derived_parent = derived.parent().context("maintenance_derived_parent")?;
    let output_parent = output.parent().context("maintenance_output_parent")?;
    if fs::metadata(derived_parent)?.dev() == fs::metadata(output_parent)?.dev() {
        space(derived_parent, &p, peak)?;
    } else {
        space(
            derived_parent,
            &p,
            p.limits
                .max_derived_bytes
                .checked_add(p.limits.max_install_bytes)
                .context("maintenance_peak_overflow")?,
        )?;
        space(output_parent, &p, p.limits.max_bundle_bytes)?;
    }
    budget.check()?;
    fresh_dir(derived)?;
    fresh_dir(output)?;
    budget.owned = Some((
        OwnedBuildDirectory::open(derived)?,
        OwnedBuildDirectory::open(output)?,
    ));
    let source_root = derived.join("source");
    fresh_dir(&source_root)?;
    let source = unpack(&bytes, &source_root, &p, &budget)?;
    tree_usage(derived, &p, &budget, p.limits.max_derived_bytes)?;
    preimages(&source, &pins, &budget, false)?;
    let patch_path = derived.join("product.patch");
    write_new(&patch_path, &patch)?;
    let common = vec![
        format!("--work-tree={}", source.display()),
        "apply".into(),
        "--whitespace=error-all".into(),
        patch_path.to_string_lossy().into_owned(),
    ];
    let mut check = common.clone();
    check.insert(2, "--check".into());
    command(&p.tools.git.path, &check, &source, &p, &mut budget)?;
    command(&p.tools.git.path, &common, &source, &p, &mut budget)?;
    preimages(&source, &pins, &budget, true)?;
    tree_usage(derived, &p, &budget, p.limits.max_derived_bytes)?;
    space(
        derived,
        &p,
        p.limits
            .max_install_bytes
            .checked_add(p.limits.max_bundle_bytes)
            .context("maintenance_peak_overflow")?,
    )?;
    let configure = &p.tools.configure_source;
    if configure.relative_path != "configure"
        || manifest::hash_regular(&source.join("configure"), configure.bytes)?
            != (FileDigest {
                bytes: configure.bytes,
                sha256: configure.sha256.clone(),
            })
    {
        bail!("maintenance_configure_source");
    }
    let build_root = derived.join("build");
    fresh_dir(&build_root)?;
    let mut configure_args = vec![source.join("configure").to_string_lossy().into_owned()];
    configure_args.extend(p.recipe.configure_argv.clone());
    command(
        &p.tools.shell.path,
        &configure_args,
        &build_root,
        &p,
        &mut budget,
    )?;
    command(
        &p.tools.make.path,
        &p.recipe.make_argv,
        &build_root,
        &p,
        &mut budget,
    )?;
    tree_usage(derived, &p, &budget, p.limits.max_derived_bytes)?;
    space(
        derived,
        &p,
        p.limits
            .max_install_bytes
            .checked_add(p.limits.max_bundle_bytes)
            .context("maintenance_peak_overflow")?,
    )?;
    command(
        &p.tools.make.path,
        &[
            "-C".into(),
            "src/bin/pg_basebackup".into(),
            "wrokbot-pg-basebackup".into(),
        ],
        &build_root,
        &p,
        &mut budget,
    )?;
    let stage = derived.join("install");
    fresh_dir(&stage)?;
    let mut install = p.recipe.install_argv.clone();
    install.push(format!("DESTDIR={}", stage.display()));
    command(&p.tools.make.path, &install, &build_root, &p, &mut budget)?;
    tree_usage(&stage, &p, &budget, p.limits.max_install_bytes)?;
    space(output, &p, p.limits.max_bundle_bytes)?;
    observe_owned(&p, &budget, false)?;
    // Resource/bin directories and every program/lib/share entry share this ledger.
    let (mut sum, mut count) = (0u64, 2u64);
    if count > p.limits.max_build_files {
        bail!("maintenance_bundle_limit");
    }
    let installed = stage.join("wrokbot-maintenance-v2");
    let resource = output.join(manifest::RESOURCE_ROOT);
    fresh_dir(&resource)?;
    let bin = resource.join("bin");
    fresh_dir(&bin)?;
    for (from, to) in [
        ("postgres", "postgres"),
        ("initdb", "initdb"),
        ("pg_ctl", "pg_ctl"),
    ] {
        copy_bundle_file(
            &installed.join("bin").join(from),
            &bin.join(to),
            0o755,
            &p,
            &budget,
            &mut sum,
            &mut count,
        )?;
    }
    copy_bundle_file(
        &build_root.join("src/bin/pg_basebackup/wrokbot-pg-basebackup"),
        &bin.join("wrokbot-pg-basebackup"),
        0o755,
        &p,
        &budget,
        &mut sum,
        &mut count,
    )?;
    copy_tree(
        &installed.join("lib"),
        &resource.join("lib"),
        (&installed, &p, &budget),
        (&mut sum, &mut count),
        0,
        &mut BTreeSet::new(),
        true,
    )?;
    copy_tree(
        &installed.join("share"),
        &resource.join("share"),
        (&installed, &p, &budget),
        (&mut sum, &mut count),
        0,
        &mut BTreeSet::new(),
        false,
    )?;
    if let Some(rewrites) = &p.recipe.loader_rewrite {
        let tool = p
            .tools
            .install_name_tool
            .as_ref()
            .context("maintenance_loader_tool_required")?;
        for args in rewrites {
            budget.check()?;
            if args.len() < 2 {
                bail!("maintenance_loader_argv");
            }
            let rel = args.last().context("maintenance_loader_target")?;
            manifest::relative(rel)?;
            if !(rel.starts_with("bin/") || rel.starts_with("lib/")) {
                bail!("maintenance_loader_target");
            }
            let correct = match args[0].as_str() {
                "-change" => args.len() == 4,
                "-id" | "-add_rpath" => args.len() == 3,
                _ => false,
            };
            if !correct
                || args[..args.len() - 1]
                    .iter()
                    .any(|s| s.is_empty() || s.contains('\0') || s.contains('\n'))
            {
                bail!("maintenance_loader_option");
            }
            if args[1..args.len() - 1].iter().any(|v| {
                !(v.starts_with("@loader_path/")
                    || v.starts_with("@rpath/")
                    || v.starts_with("@executable_path/")
                    || v.starts_with("/usr/lib/")
                    || v.starts_with("/System/Library/")
                    || v.starts_with("/wrokbot-maintenance-v2/"))
            }) {
                bail!("maintenance_loader_value");
            }
            let mut actual = args.clone();
            *actual.last_mut().unwrap() = resource.join(rel).to_string_lossy().into_owned();
            command(&tool.path, &actual, &resource, &p, &mut budget)?;
        }
    }
    let otool = p
        .tools
        .otool
        .as_ref()
        .context("maintenance_loader_inspection_required")?;
    let files = manifest::collect(
        &resource,
        p.limits.max_build_files,
        p.limits.max_bundle_bytes,
    )?;
    for f in &files {
        let path = resource.join(&f.path);
        if !macho_file(&path)? {
            continue;
        }
        let raw = command(
            &otool.path,
            &["-L".into(), path.to_string_lossy().into_owned()],
            &resource,
            &p,
            &mut budget,
        )?;
        let load = command(
            &otool.path,
            &["-l".into(), path.to_string_lossy().into_owned()],
            &resource,
            &p,
            &mut budget,
        )?;
        validate_loader(
            &resource,
            &path,
            std::str::from_utf8(&raw)?,
            std::str::from_utf8(&load)?,
        )?;
    }

    require_no_pkg_config()?;
    if checked_clt_aliases()? != aliases {
        bail!("maintenance_fixed_tool_alias_changed");
    }
    for t in &tools {
        budget.check()?;
        let after = hash_fixed_system_tool(Path::new(&t.path), t.bytes)?;
        if (after.bytes, after.sha256.as_str()) != (t.bytes, t.sha256.as_str()) {
            bail!("maintenance_build_tool_changed");
        }
    }
    budget.check()?;
    let m = Manifest {
        schema: "openbot-postgres-maintenance-bundle".into(),
        schema_version: 2,
        postgres_version: "17.11".into(),
        source_archive_bytes: manifest::ARCHIVE_BYTES,
        source_archive_sha256: manifest::ARCHIVE_SHA.into(),
        product_patch_bytes: pins.patch.bytes,
        product_patch_sha256: pins.patch.sha256,
        recipe_sha256: actual_recipe_hash(&p.recipe)?,
        build_profile_sha256: manifest::digest_bytes(&profile_bytes).sha256,
        release_epoch: 5,
        minimum_core_version: env!("CARGO_PKG_VERSION").into(),
        platform: "macos".into(),
        arch: std::env::consts::ARCH.into(),
        programs: Programs::exact(),
        files,
        derived_sources: pins.derived_sources,
        build_tools: tools,
    };
    sync_tree(&resource, &budget)?;
    let inner = serde_json::to_vec_pretty(&m)?;
    let outer = Outer {
        schema: "wrokbot-pg-maintenance-release".into(),
        schema_version: 1,
        postgres: OuterPostgres {
            root: manifest::RESOURCE_ROOT.into(),
            manifest_sha256: manifest::digest_bytes(&inner).sha256,
        },
    };
    let outer = serde_json::to_vec_pretty(&outer)?;
    let existing = usage(output, &p, &budget, (p.limits.max_bundle_bytes, false))?;
    if inner.len() > 1024 * 1024
        || outer.len() > 1024 * 1024
        || existing
            .nodes
            .checked_add(2)
            .is_none_or(|n| n > p.limits.max_build_files)
        || existing
            .logical
            .checked_add(inner.len() as u64)
            .and_then(|n| n.checked_add(outer.len() as u64))
            .is_none_or(|n| n > p.limits.max_bundle_bytes)
    {
        bail!("maintenance_bundle_metadata_limit");
    }
    observe_owned(&p, &budget, false)?;
    write_new(&resource.join(manifest::INNER_FILE), &inner)?;
    std::fs::File::open(&resource)?.sync_all()?;
    write_new(&output.join(manifest::OUTER_FILE), &outer)?;
    std::fs::File::open(output)?.sync_all()?;
    budget.check()?;
    let facts = manifest::inspect(output, None)?;
    // A repository build never mints runtime trust from its own freshly computed digest.
    println!("{}", serde_json::to_string(&facts)?);
    Ok(())
}
pub(super) fn verify_source(root: &Path, bundle: &Path, input: &Path) -> Result<()> {
    let p = pins(root)?;
    let bytes = manifest::read_regular(input, 1024 * 1024)?;
    let reviewed: Reviewed = serde_json::from_slice(&bytes)?;
    if reviewed.schema != "wrokbot-pg-maintenance-reviewed-build-input"
        || reviewed.schema_version != 1
        || !manifest::valid_sha(&reviewed.outer_sha256)
        || reviewed.product_patch_sha256 != p.patch.sha256
    {
        bail!("maintenance_reviewed_input_invalid");
    }
    let mut facts = manifest::inspect(bundle, Some(&reviewed.outer_sha256))?;
    let m: Manifest = serde_json::from_slice(&manifest::read_regular(
        &bundle
            .join(manifest::RESOURCE_ROOT)
            .join(manifest::INNER_FILE),
        1024 * 1024,
    )?)?;
    if m.product_patch_sha256 != reviewed.product_patch_sha256
        || m.recipe_sha256 != reviewed.recipe_sha256
        || m.build_profile_sha256 != reviewed.build_profile_sha256
    {
        bail!("maintenance_reviewed_binding_mismatch");
    }
    facts.source_authenticated = false; // This file is review data, not a compiled runtime capability.
    println!(
        "{}",
        serde_json::json!({"review_binding_matched":true,"facts":facts})
    );
    Ok(())
}

#[cfg(test)]
#[path = "build_tests.rs"]
mod build_tests;
