//! Closed source-authenticated v2 resource verification. No platform signature is inferred.
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;

use super::MaintenanceError;

pub(super) const OUTER_FILE: &str = "wrokbot-pg-maintenance-release.json";
const INNER_FILE: &str = "manifest.json";
const RESOURCE: &str = "postgres-maintenance";
const MANIFEST_MAX: u64 = 8 * 1024 * 1024;
const SOURCE_SHA: &str = "5367f6fb2ec97efe1eb2e0c7926bb33438e51b0bd3a9733b88498056a7dc9a7e";
const PROGRAMS: [&str; 4] = [
    "bin/postgres",
    "bin/initdb",
    "bin/pg_ctl",
    "bin/wrokbot-pg-basebackup",
];
const PATCH_PATHS: [&str; 11] = [
    "src/bin/pg_basebackup/pg_basebackup.c",
    "src/bin/pg_basebackup/streamutil.c",
    "src/bin/pg_basebackup/streamutil.h",
    "src/bin/pg_basebackup/receivelog.c",
    "src/bin/pg_basebackup/receivelog.h",
    "src/bin/pg_basebackup/walmethods.c",
    "src/bin/pg_basebackup/wrokbot_owner.c",
    "src/bin/pg_basebackup/wrokbot_owner.h",
    "src/bin/pg_basebackup/Makefile",
    "src/interfaces/libpq/fe-connect.c",
    "src/common/logging.c",
];

pub(super) const FIXED_INTERNAL_TOOLS: [(&str, &str, u64, &str); 21] = [
    (
        "nm",
        "/usr/bin/nm",
        200560u64,
        "34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2",
    ),
    (
        "touch",
        "/usr/bin/touch",
        167136u64,
        "83567bc0eb633230f8fb4d5c6ce9ec7a2084d5eeecd53a261d7932f38489d83b",
    ),
    (
        "gitResolved",
        "/Library/Developer/CommandLineTools/usr/bin/git",
        3837392u64,
        "a73bf622a2e470d5d57a4b1d5aef1e8680e67278018d4858a2f93825b7d595c7",
    ),
    (
        "makeResolved",
        "/Library/Developer/CommandLineTools/usr/bin/make",
        69456u64,
        "fe709619aab6d3b280cc22cb06d14432b3fa5fa7eb323e8d4817071410760f1b",
    ),
    (
        "archiverResolved",
        "/Library/Developer/CommandLineTools/usr/bin/ar",
        73520u64,
        "85d15bd3999895f659e8a483b17ea9ab44b924c8e0b3026abfe359f2de02cbd7",
    ),
    (
        "installNameToolResolved",
        "/Library/Developer/CommandLineTools/usr/bin/install_name_tool",
        214272u64,
        "ce7c944f855250c5df6b4de8ab024e94b5577f2385a122bd8993a531d466c0de",
    ),
    (
        "nmResolved",
        "/Library/Developer/CommandLineTools/usr/bin/llvm-nm",
        16367008u64,
        "82e9189ec1a359699d4b680601c0a2930a9cbea7376c7320947dff5e9862cfa8",
    ),
    (
        "ranlibResolved",
        "/Library/Developer/CommandLineTools/usr/bin/libtool",
        360272u64,
        "2840879786eb8868f03c3d378eef6c71d8416e15d8b14aebbf0c0cb80ad81c24",
    ),
    (
        "otoolResolved",
        "/Library/Developer/CommandLineTools/usr/bin/llvm-otool",
        72672u64,
        "8353ad3c42743a93e9ca7d0d4e9d3df22305252d169c42c543ee22eeb8c33809",
    ),
    (
        "ls",
        "/bin/ls",
        252512u64,
        "13f44bfe1c4af602da4465c834dbe7b16a5441ccbd843178b36116ee23422bfb",
    ),
    (
        "diff",
        "/usr/bin/diff",
        367936u64,
        "64813b8d9290d4558ea5e388ea6bf4426590adbd24132136affc9c4ceaac8980",
    ),
    (
        "strip",
        "/usr/bin/strip",
        200560u64,
        "34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2",
    ),
    (
        "bison",
        "/usr/bin/bison",
        200560u64,
        "34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2",
    ),
    (
        "flex",
        "/usr/bin/flex",
        200560u64,
        "34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2",
    ),
    (
        "lex",
        "/usr/bin/lex",
        200560u64,
        "34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2",
    ),
    (
        "mktemp",
        "/usr/bin/mktemp",
        167072u64,
        "14a9ae4763a720460ab50fb14b340ad59882645dd3d0b4f94f8b8ce8fe6ca454",
    ),
    (
        "stripResolved",
        "/Library/Developer/CommandLineTools/usr/bin/strip",
        285696u64,
        "e0d9859a299233c4b2bd48a21f55bb00e575e175eef9193616d3af8660fc846d",
    ),
    (
        "bisonResolved",
        "/Library/Developer/CommandLineTools/usr/bin/bison",
        254048u64,
        "6f5c8cded509f70b85ef5a1c92a89a617afba985515470a7e2a5c99b80e64c5c",
    ),
    (
        "flexResolved",
        "/Library/Developer/CommandLineTools/usr/bin/flex",
        336368u64,
        "f437b756f2ac89ee94835c501aaea892c4e117d50e43485711a2ba4b05098302",
    ),
    (
        "lexResolved",
        "/Library/Developer/CommandLineTools/usr/bin/lex",
        230u64,
        "1677dc6c2138bc5add8fdf8b765c063f627a02b9da22557a2ce6ad0366531f47",
    ),
    (
        "loaderObjdumpResolved",
        "/Library/Developer/CommandLineTools/usr/bin/llvm-objdump",
        18133888u64,
        "83b32f39e5475ee168927eb1509c82978e08e0100ec8c6fafeca588d9960773c",
    ),
];

pub(crate) struct TrustedMaintenanceBundleDigest([u8; 32]);

pub(crate) fn reviewed_bundle_binding() -> Result<TrustedMaintenanceBundleDigest, MaintenanceError>
{
    binding_from_compiled_value(option_env!("WROK_BOT_PG_MAINTENANCE_BUNDLE_SHA256"))
}

fn binding_from_compiled_value(
    value: Option<&str>,
) -> Result<TrustedMaintenanceBundleDigest, MaintenanceError> {
    value
        .and_then(decode_digest)
        .map(TrustedMaintenanceBundleDigest)
        .ok_or(MaintenanceError::TrustMissing)
}
#[cfg(test)]
pub(super) fn fixture_binding(value: [u8; 32]) -> TrustedMaintenanceBundleDigest {
    // Test-only independently supplied digest. It is never compiled into a release authority.
    TrustedMaintenanceBundleDigest(value)
}
#[cfg(test)]
pub(super) fn compiled_value_is_missing(value: Option<&str>) -> bool {
    matches!(
        binding_from_compiled_value(value),
        Err(MaintenanceError::TrustMissing)
    )
}

pub(crate) struct VerifiedMaintenanceBundle {
    root: PathBuf,
    _directory: File,
    outer_digest: [u8; 32],
    inner_digest: [u8; 32],
    manifest: Manifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outer {
    schema: String,
    schema_version: u32,
    postgres: OuterPostgres,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OuterPostgres {
    root: String,
    manifest_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Programs {
    postgres: String,
    initdb: String,
    pg_ctl: String,
    basebackup: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    path: String,
    bytes: u64,
    sha256: String,
    mode: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedSource {
    path: String,
    #[serde(deserialize_with = "present_optional_digest")]
    before: Option<FileDigest>,
    after: FileDigest,
}
fn present_optional_digest<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<FileDigest>, D::Error> {
    Option::<FileDigest>::deserialize(value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildTool {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    schema_version: u32,
    postgres_version: String,
    source_archive_bytes: u64,
    source_archive_sha256: String,
    product_patch_bytes: u64,
    product_patch_sha256: String,
    recipe_sha256: String,
    build_profile_sha256: String,
    release_epoch: u64,
    minimum_core_version: String,
    platform: String,
    arch: String,
    programs: Programs,
    files: Vec<FileEntry>,
    derived_sources: Vec<DerivedSource>,
    build_tools: Vec<BuildTool>,
}
#[derive(Serialize)]
pub(super) struct BundleVerificationReceipt {
    schema: &'static str,
    schema_version: u32,
    outer_sha256: String,
    inner_sha256: String,
    source_archive_sha256: String,
    product_patch_sha256: String,
    recipe_sha256: String,
    build_profile_sha256: String,
    program_count: usize,
    file_count: usize,
    source_authenticated: bool,
    platform_signature_verified: bool,
    production_release_authorized: bool,
}

#[derive(Clone, Copy)]
pub(super) enum Program {
    Postgres,
    InitDb,
    PgCtl,
    BaseBackup,
}

pub(crate) fn verify_bundle(
    root: &Path,
    expected: TrustedMaintenanceBundleDigest,
) -> Result<VerifiedMaintenanceBundle, MaintenanceError> {
    let directory = open_directory(root)?;
    let outer_bytes = read_relative(&directory, OUTER_FILE, MANIFEST_MAX)?;
    let outer_digest: [u8; 32] = Sha256::digest(&outer_bytes).into();
    if outer_digest != expected.0 {
        return Err(MaintenanceError::BundleInvalid);
    }
    let outer: Outer =
        serde_json::from_slice(&outer_bytes).map_err(|_| MaintenanceError::BundleInvalid)?;
    if outer.schema != "wrokbot-pg-maintenance-release"
        || outer.schema_version != 1
        || outer.postgres.root != RESOURCE
    {
        return Err(MaintenanceError::BundleInvalid);
    }
    let inner_expected =
        decode_digest(&outer.postgres.manifest_sha256).ok_or(MaintenanceError::BundleInvalid)?;
    let resource = open_relative_directory(&directory, RESOURCE)?;
    let inner = read_relative(&resource, INNER_FILE, MANIFEST_MAX)?;
    let inner_digest: [u8; 32] = Sha256::digest(&inner).into();
    if inner_digest != inner_expected {
        return Err(MaintenanceError::BundleInvalid);
    }
    let manifest: Manifest =
        serde_json::from_slice(&inner).map_err(|_| MaintenanceError::BundleInvalid)?;
    validate_manifest(&manifest)?;
    let mut declared = BTreeSet::new();
    let mut directories = BTreeSet::from(["bin".to_owned(), "lib".to_owned(), "share".to_owned()]);
    let mut total = 0_u64;
    let mut previous = "";
    for entry in &manifest.files {
        relative(&entry.path)?;
        if entry.path.as_str() <= previous {
            return Err(MaintenanceError::BundleInvalid);
        }
        previous = &entry.path;
        let program = PROGRAMS.contains(&entry.path.as_str());
        if (!program && !entry.path.starts_with("lib/") && !entry.path.starts_with("share/"))
            || program && entry.mode != 0o755
            || !program && entry.mode != 0o644
        {
            return Err(MaintenanceError::BundleInvalid);
        }
        total = total
            .checked_add(entry.bytes)
            .ok_or(MaintenanceError::BundleInvalid)?;
        let expected = decode_digest(&entry.sha256).ok_or(MaintenanceError::BundleInvalid)?;
        let (actual, len, mode) = hash_relative(&resource, &entry.path, entry.bytes)?;
        if actual != expected || len != entry.bytes || mode != entry.mode {
            return Err(MaintenanceError::BundleInvalid);
        }
        declared.insert(entry.path.clone());
        let mut parent = Path::new(&entry.path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            directories.insert(
                path.to_str()
                    .ok_or(MaintenanceError::BundleInvalid)?
                    .to_owned(),
            );
            parent = path.parent();
        }
    }
    // The actual tree is a closed snapshot. A pathname spawn remains a pathname spawn; recheck
    // before each child and require release protection. This is not atomic fd-based exec.
    let mut actual = BTreeSet::new();
    inventory(
        &root.join(RESOURCE),
        Path::new(""),
        &mut actual,
        &directories,
        manifest.files.len() + 1,
    )?;
    actual.remove(INNER_FILE);
    if actual != declared
        || PROGRAMS.iter().any(|p| !declared.contains(*p))
        || !declared.iter().any(|p| p.starts_with("share/"))
    {
        return Err(MaintenanceError::BundleInvalid);
    }
    let top = fs::read_dir(root)?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_top = BTreeSet::from([
        std::ffi::OsString::from(OUTER_FILE),
        std::ffi::OsString::from(RESOURCE),
    ]);
    if top != expected_top
        || fs::metadata(root)?.dev() != directory.metadata()?.dev()
        || fs::metadata(root)?.ino() != directory.metadata()?.ino()
    {
        return Err(MaintenanceError::BundleInvalid);
    }
    for entry in &manifest.files {
        if PROGRAMS.contains(&entry.path.as_str()) || entry.path.starts_with("lib/") {
            verify_loader(&resource, &entry.path, &declared)?;
        }
    }
    Ok(VerifiedMaintenanceBundle {
        root: root.to_owned(),
        _directory: directory,
        outer_digest,
        inner_digest,
        manifest,
    })
}

fn validate_manifest(m: &Manifest) -> Result<(), MaintenanceError> {
    if m.product_patch_bytes == 0 || decode_digest(&m.product_patch_sha256).is_none() {
        return Err(MaintenanceError::PatchMismatch);
    }
    if m.schema != "openbot-postgres-maintenance-bundle"
        || m.schema_version != 2
        || m.postgres_version != "17.11"
        || m.source_archive_bytes != 28_397_423
        || m.source_archive_sha256 != SOURCE_SHA
        || m.release_epoch != 5
        || m.minimum_core_version != env!("CARGO_PKG_VERSION")
        || m.platform != "macos"
        || m.arch != std::env::consts::ARCH
        || !matches!(m.arch.as_str(), "aarch64" | "x86_64")
        || m.files.len() < 4
        || decode_digest(&m.recipe_sha256).is_none()
        || decode_digest(&m.build_profile_sha256).is_none()
        || [
            m.programs.postgres.as_str(),
            m.programs.initdb.as_str(),
            m.programs.pg_ctl.as_str(),
            m.programs.basebackup.as_str(),
        ] != PROGRAMS
    {
        return Err(MaintenanceError::SourcePinMismatch);
    }
    let mut seen = BTreeSet::new();
    for d in &m.derived_sources {
        if !PATCH_PATHS.contains(&d.path.as_str())
            || !seen.insert(d.path.as_str())
            || decode_digest(&d.after.sha256).is_none()
            || d.after.bytes == 0
        {
            return Err(MaintenanceError::PatchScopeInvalid);
        }
        let unchanged_header = match d.path.as_str() {
            "src/bin/pg_basebackup/streamutil.h" => Some((
                2540,
                "82451cfacf2e033cc33923563d14e7cdd41ae0c09e1f76e3d54ffa40e975e62d",
            )),
            "src/bin/pg_basebackup/receivelog.h" => Some((
                1889,
                "88e5bfdf7aec9dd7db8ee8b3d02bbbd25235513e72592d968c39b41f29a5ee6a",
            )),
            _ => None,
        };
        if let Some((bytes, sha256)) = unchanged_header {
            if d.after.bytes != bytes
                || d.after.sha256 != sha256
                || d.before
                    .as_ref()
                    .is_none_or(|before| before.bytes != bytes || before.sha256 != sha256)
            {
                return Err(MaintenanceError::DerivedTreeMismatch);
            }
            continue;
        }
        match &d.before {
            None if matches!(
                d.path.as_str(),
                "src/bin/pg_basebackup/wrokbot_owner.c" | "src/bin/pg_basebackup/wrokbot_owner.h"
            ) => {}
            Some(before)
                if !matches!(
                    d.path.as_str(),
                    "src/bin/pg_basebackup/wrokbot_owner.c"
                        | "src/bin/pg_basebackup/wrokbot_owner.h"
                ) && decode_digest(&before.sha256).is_some()
                    && before.bytes > 0
                    && before.sha256 != d.after.sha256 => {}
            _ => return Err(MaintenanceError::DerivedTreeMismatch),
        }
    }
    if seen.len() != PATCH_PATHS.len() || !PATCH_PATHS.iter().all(|path| seen.contains(path)) {
        return Err(MaintenanceError::DerivedTreeMismatch);
    }
    const REQUIRED: [&str; 10] = [
        "git",
        "shell",
        "make",
        "compiler",
        "archiver",
        "ranlib",
        "linker",
        "compilerResolved",
        "linkerResolved",
        "otool",
    ];
    const OPTIONAL: [&str; 25] = [
        "installNameTool",
        "awk",
        "basename",
        "cat",
        "chmod",
        "cp",
        "cut",
        "dirname",
        "expr",
        "find",
        "grep",
        "head",
        "install",
        "ln",
        "mkdir",
        "mv",
        "perl",
        "pwd",
        "rm",
        "sed",
        "sort",
        "tail",
        "test",
        "tr",
        "uname",
    ];
    let mut roles = BTreeSet::new();
    for t in &m.build_tools {
        if (!REQUIRED.contains(&t.role.as_str())
            && !OPTIONAL.contains(&t.role.as_str())
            && !FIXED_INTERNAL_TOOLS.iter().any(|row| row.0 == t.role))
            || !roles.insert(t.role.as_str())
            || !Path::new(&t.path).is_absolute()
            || t.bytes == 0
            || decode_digest(&t.sha256).is_none()
        {
            return Err(MaintenanceError::BuildToolUnavailable);
        }
        if let Some((_, path, bytes, sha256)) =
            FIXED_INTERNAL_TOOLS.iter().find(|row| row.0 == t.role)
            && (t.path != *path || t.bytes != *bytes || t.sha256 != *sha256)
        {
            return Err(MaintenanceError::BuildToolUnavailable);
        }
    }
    if REQUIRED.iter().any(|role| !roles.contains(role)) {
        return Err(MaintenanceError::BuildToolUnavailable);
    }
    for (required, _, _, _) in FIXED_INTERNAL_TOOLS {
        if !roles.contains(required) {
            return Err(MaintenanceError::BuildToolUnavailable);
        }
    }
    Ok(())
}

impl VerifiedMaintenanceBundle {
    pub(super) fn verification_receipt(&self) -> BundleVerificationReceipt {
        BundleVerificationReceipt {
            schema: "wrokbot-pg-maintenance-verification",
            schema_version: 1,
            outer_sha256: encode_hex(&self.outer_digest),
            inner_sha256: encode_hex(&self.inner_digest),
            source_archive_sha256: self.manifest.source_archive_sha256.clone(),
            product_patch_sha256: self.manifest.product_patch_sha256.clone(),
            recipe_sha256: self.manifest.recipe_sha256.clone(),
            build_profile_sha256: self.manifest.build_profile_sha256.clone(),
            program_count: 4,
            file_count: self.manifest.files.len(),
            source_authenticated: true,
            platform_signature_verified: false,
            production_release_authorized: false,
        }
    }
    pub(super) fn root(&self) -> &Path {
        &self.root
    }
    pub(super) fn checked_command(&self, program: Program) -> Result<Command, MaintenanceError> {
        let _current = verify_bundle(
            &self.root,
            TrustedMaintenanceBundleDigest(self.outer_digest),
        )?;
        let relative = match program {
            Program::Postgres => PROGRAMS[0],
            Program::InitDb => PROGRAMS[1],
            Program::PgCtl => PROGRAMS[2],
            Program::BaseBackup => PROGRAMS[3],
        };
        let mut command = Command::new(self.root.join(RESOURCE).join(relative));
        command.env_clear().env("LC_ALL", "C").env("LANG", "C");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        Ok(command)
    }
}

pub(super) fn relative(value: &str) -> Result<(), MaintenanceError> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(MaintenanceError::BundleInvalid);
    }
    Ok(())
}
pub(super) fn open_directory(path: &Path) -> Result<File, MaintenanceError> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(MaintenanceError::BundleInvalid);
    }
    let mut fd = File::open("/")?;
    for part in path.components() {
        if let Component::Normal(name) = part {
            fd = rustix::fs::openat(
                &fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|_| MaintenanceError::BundleInvalid)?;
        }
    }
    Ok(fd)
}
fn open_relative_directory(root: &File, path: &str) -> Result<File, MaintenanceError> {
    relative(path)?;
    let mut fd = root.try_clone()?;
    for name in path.split('/') {
        fd = rustix::fs::openat(
            &fd,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| MaintenanceError::BundleInvalid)?;
    }
    Ok(fd)
}
fn open_relative(root: &File, path: &str) -> Result<File, MaintenanceError> {
    relative(path)?;
    let p = Path::new(path);
    let parent = p.parent().filter(|p| !p.as_os_str().is_empty());
    let fd = if let Some(parent) = parent {
        open_relative_directory(
            root,
            parent.to_str().ok_or(MaintenanceError::BundleInvalid)?,
        )?
    } else {
        root.try_clone()?
    };
    let name = p.file_name().ok_or(MaintenanceError::BundleInvalid)?;
    let file = rustix::fs::openat(
        &fd,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| MaintenanceError::BundleInvalid)?;
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.mode() & 0o7000 != 0 {
        return Err(MaintenanceError::BundleInvalid);
    }
    Ok(file)
}
fn read_relative(root: &File, path: &str, max: u64) -> Result<Vec<u8>, MaintenanceError> {
    let mut f = open_relative(root, path)?;
    let m = f.metadata()?;
    if m.len() > max {
        return Err(MaintenanceError::BundleInvalid);
    }
    let mut b = Vec::new();
    Read::by_ref(&mut f)
        .take(max.checked_add(1).ok_or(MaintenanceError::BundleInvalid)?)
        .read_to_end(&mut b)?;
    if b.len() as u64 != m.len() || !same_file(&m, &f.metadata()?) {
        return Err(MaintenanceError::BundleInvalid);
    }
    Ok(b)
}
pub(super) fn read_input_file(path: &Path, max: u64) -> Result<Vec<u8>, MaintenanceError> {
    let parent = path.parent().ok_or(MaintenanceError::InvalidArguments)?;
    let fd = open_directory(parent)?;
    read_relative(
        &fd,
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or(MaintenanceError::InvalidArguments)?,
        max,
    )
}
fn hash_relative(
    root: &File,
    path: &str,
    max: u64,
) -> Result<([u8; 32], u64, u32), MaintenanceError> {
    let mut f = open_relative(root, path)?;
    let before = f.metadata()?;
    if before.len() > max {
        return Err(MaintenanceError::BundleInvalid);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut count = 0_u64;
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(MaintenanceError::BundleInvalid)?;
        if count > max {
            return Err(MaintenanceError::BundleInvalid);
        }
        hash.update(&buffer[..n]);
    }
    if count != before.len() || !same_file(&before, &f.metadata()?) {
        return Err(MaintenanceError::BundleInvalid);
    }
    Ok((hash.finalize().into(), count, before.mode() & 0o777))
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mode(),
        a.nlink(),
        a.mtime(),
        a.mtime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mode(),
        1,
        b.mtime(),
        b.mtime_nsec(),
    )
}
fn inventory(
    root: &Path,
    relative_path: &Path,
    out: &mut BTreeSet<String>,
    directories: &BTreeSet<String>,
    max: usize,
) -> Result<(), MaintenanceError> {
    for item in fs::read_dir(root.join(relative_path))? {
        let item = item?;
        let p = relative_path.join(item.file_name());
        let m = fs::symlink_metadata(item.path())?;
        if m.file_type().is_symlink() {
            return Err(MaintenanceError::BundleInvalid);
        }
        if m.is_dir() {
            let name = p.to_str().ok_or(MaintenanceError::BundleInvalid)?;
            if !directories.contains(name) {
                return Err(MaintenanceError::BundleInvalid);
            }
            inventory(root, &p, out, directories, max)?;
        } else if m.is_file() && m.nlink() == 1 {
            let p = p.to_str().ok_or(MaintenanceError::BundleInvalid)?;
            relative(p)?;
            if !out.insert(p.to_owned()) || out.len() > max {
                return Err(MaintenanceError::BundleInvalid);
            }
        } else {
            return Err(MaintenanceError::BundleInvalid);
        }
    }
    Ok(())
}
pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 15)]));
    }
    s
}
fn decode_digest(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut b = [0; 32];
    for (i, c) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let n = |x: u8| {
            if x.is_ascii_digit() {
                x - b'0'
            } else {
                x - b'a' + 10
            }
        };
        b[i] = (n(c[0]) << 4) | n(c[1]);
    }
    Some(b)
}

// The supported build is thin 64-bit Mach-O. Fat, unexpected architecture, external prefixes,
// environment search paths and imports outside the closed lib tree are rejected.
fn verify_loader(
    root: &File,
    path: &str,
    declared: &BTreeSet<String>,
) -> Result<(), MaintenanceError> {
    let mut f = open_relative(root, path)?;
    let mut head = [0; 32];
    f.read_exact(&mut head)?;
    if head[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        return Err(MaintenanceError::LibraryClosureInvalid);
    }
    let u32at = |b: &[u8], i| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let arch = match std::env::consts::ARCH {
        "aarch64" => 0x0100000c,
        "x86_64" => 0x01000007,
        _ => return Err(MaintenanceError::UnsupportedPlatform),
    };
    let file_type = u32at(&head, 12);
    let is_program = PROGRAMS.contains(&path);
    if u32at(&head, 4) != arch
        || is_program && file_type != 2
        || !is_program && !matches!(file_type, 6 | 8)
    {
        return Err(MaintenanceError::LibraryClosureInvalid);
    }
    let commands = u32at(&head, 16);
    let bytes = u32at(&head, 20);
    if commands == 0 || commands > 4096 || bytes > 4 * 1024 * 1024 {
        return Err(MaintenanceError::LibraryClosureInvalid);
    }
    let mut data =
        vec![0; usize::try_from(bytes).map_err(|_| MaintenanceError::LibraryClosureInvalid)?];
    f.read_exact(&mut data)?;
    let mut offset = 0_usize;
    let mut imports = Vec::new();
    let mut rpaths = Vec::new();
    let mut identity_seen = false;
    for _ in 0..commands {
        let prefix = data
            .get(
                offset
                    ..offset
                        .checked_add(8)
                        .ok_or(MaintenanceError::LibraryClosureInvalid)?,
            )
            .ok_or(MaintenanceError::LibraryClosureInvalid)?;
        let cmd = u32at(prefix, 0);
        let size = usize::try_from(u32at(prefix, 4))
            .map_err(|_| MaintenanceError::LibraryClosureInvalid)?;
        if size < 8 || size % 8 != 0 {
            return Err(MaintenanceError::LibraryClosureInvalid);
        }
        let end = offset
            .checked_add(size)
            .ok_or(MaintenanceError::LibraryClosureInvalid)?;
        let entry = data
            .get(offset..end)
            .ok_or(MaintenanceError::LibraryClosureInvalid)?;
        // Reject loader environment and legacy external-file commands even when their bytes are
        // signed by the independent source binding; they are outside this closed runtime recipe.
        if matches!(cmd, 0x6 | 0x7 | 0x9 | 0x10 | 0x27) {
            return Err(MaintenanceError::LibraryClosureInvalid);
        }
        if matches!(
            cmd,
            0xc | 0x80000018 | 0x8000001f | 0x20 | 0x80000023 | 0x8000001c | 0xe | 0xd
        ) {
            if entry.len() < 12 {
                return Err(MaintenanceError::LibraryClosureInvalid);
            }
            let start = usize::try_from(u32at(entry, 8))
                .map_err(|_| MaintenanceError::LibraryClosureInvalid)?;
            let tail = entry
                .get(start..)
                .ok_or(MaintenanceError::LibraryClosureInvalid)?;
            let stop = tail
                .iter()
                .position(|b| *b == 0)
                .ok_or(MaintenanceError::LibraryClosureInvalid)?;
            let s = std::str::from_utf8(&tail[..stop])
                .map_err(|_| MaintenanceError::LibraryClosureInvalid)?;
            if cmd == 0xe {
                if s != "/usr/lib/dyld" {
                    return Err(MaintenanceError::LibraryClosureInvalid);
                }
            } else if cmd == 0xd {
                let own = path
                    .strip_prefix("lib/")
                    .ok_or(MaintenanceError::LibraryClosureInvalid)?;
                if file_type != 6 || identity_seen || s != format!("@rpath/{own}") {
                    return Err(MaintenanceError::LibraryClosureInvalid);
                }
                identity_seen = true;
            } else if cmd == 0x8000001c {
                let base = Path::new(path)
                    .parent()
                    .ok_or(MaintenanceError::LibraryClosureInvalid)?;
                let target = if s == "@loader_path" {
                    base.to_str()
                        .ok_or(MaintenanceError::LibraryClosureInvalid)?
                        .to_owned()
                } else if let Some(tail) = s.strip_prefix("@loader_path/") {
                    normalize_bundle(base, tail)?
                } else if let Some(tail) = s.strip_prefix("@executable_path/") {
                    normalize_bundle(Path::new("bin"), tail)?
                } else {
                    return Err(MaintenanceError::LibraryClosureInvalid);
                };
                if target != "lib" && !target.starts_with("lib/")
                    || !declared
                        .iter()
                        .any(|p| p.starts_with(&format!("{target}/")))
                {
                    return Err(MaintenanceError::LibraryClosureInvalid);
                }
                if !rpaths.contains(&target) {
                    rpaths.push(target);
                }
            } else {
                imports.push(s.to_owned());
            }
        }
        offset = end;
    }
    if file_type == 6 && !identity_seen {
        return Err(MaintenanceError::LibraryClosureInvalid);
    }
    if offset != data.len() {
        return Err(MaintenanceError::LibraryClosureInvalid);
    }
    for import in imports {
        if import.starts_with("/usr/lib/") || import.starts_with("/System/Library/Frameworks/") {
            if import.split('/').any(|p| p == "..") {
                return Err(MaintenanceError::LibraryClosureInvalid);
            }
            continue;
        }
        let local = if let Some(tail) = import.strip_prefix("@rpath/") {
            relative(tail)?;
            rpaths
                .iter()
                .map(|directory| format!("{directory}/{tail}"))
                .find(|candidate| declared.contains(candidate))
                .ok_or(MaintenanceError::LibraryClosureInvalid)?
        } else if let Some(tail) = import.strip_prefix("@executable_path/../lib/") {
            relative(tail)?;
            format!("lib/{tail}")
        } else if let Some(tail) = import.strip_prefix("@loader_path/") {
            let base = Path::new(path)
                .parent()
                .ok_or(MaintenanceError::LibraryClosureInvalid)?;
            normalize_bundle(base, tail)?
        } else {
            return Err(MaintenanceError::LibraryClosureInvalid);
        };
        if !local.starts_with("lib/") || !declared.contains(&local) {
            return Err(MaintenanceError::LibraryClosureInvalid);
        }
    }
    // Keep an actual original file owner through the full command parse.
    f.seek(SeekFrom::Start(0))?;
    Ok(())
}
fn normalize_bundle(base: &Path, tail: &str) -> Result<String, MaintenanceError> {
    let mut parts = base
        .components()
        .filter_map(|c| {
            if let Component::Normal(n) = c {
                Some(n.to_owned())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for c in Path::new(tail).components() {
        match c {
            Component::Normal(n) => parts.push(n.to_owned()),
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(MaintenanceError::LibraryClosureInvalid);
                }
            }
            _ => return Err(MaintenanceError::LibraryClosureInvalid),
        }
    }
    let result = parts.iter().collect::<PathBuf>();
    result
        .to_str()
        .map(str::to_owned)
        .ok_or(MaintenanceError::LibraryClosureInvalid)
}
