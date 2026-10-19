//! Closed v2 build inventories. Source authentication is distinct from platform signing.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Component, Path};

pub(super) const OUTER_FILE: &str = "wrokbot-pg-maintenance-release.json";
pub(super) const INNER_FILE: &str = "manifest.json";
pub(super) const RESOURCE_ROOT: &str = "postgres-maintenance";
pub(super) const ARCHIVE_BYTES: u64 = 28_397_423;
pub(super) const ARCHIVE_SHA: &str =
    "5367f6fb2ec97efe1eb2e0c7926bb33438e51b0bd3a9733b88498056a7dc9a7e";

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct FileDigest {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub mode: u32,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DerivedSource {
    pub path: String,
    pub before: Option<FileDigest>,
    pub after: FileDigest,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildTool {
    pub role: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Programs {
    pub postgres: String,
    pub initdb: String,
    pub pg_ctl: String,
    pub basebackup: String,
}
impl Programs {
    pub fn exact() -> Self {
        Self {
            postgres: "bin/postgres".into(),
            initdb: "bin/initdb".into(),
            pg_ctl: "bin/pg_ctl".into(),
            basebackup: "bin/wrokbot-pg-basebackup".into(),
        }
    }
    pub fn paths(&self) -> [&str; 4] {
        [&self.postgres, &self.initdb, &self.pg_ctl, &self.basebackup]
    }
    fn validate(&self) -> Result<()> {
        if self.paths() != Self::exact().paths() {
            bail!("maintenance_program_inventory_invalid");
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema: String,
    pub schema_version: u32,
    pub postgres_version: String,
    pub source_archive_bytes: u64,
    pub source_archive_sha256: String,
    pub product_patch_bytes: u64,
    pub product_patch_sha256: String,
    pub recipe_sha256: String,
    pub build_profile_sha256: String,
    pub release_epoch: u64,
    pub minimum_core_version: String,
    pub platform: String,
    pub arch: String,
    pub programs: Programs,
    pub files: Vec<FileEntry>,
    pub derived_sources: Vec<DerivedSource>,
    pub build_tools: Vec<BuildTool>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OuterPostgres {
    pub root: String,
    pub manifest_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outer {
    pub schema: String,
    pub schema_version: u32,
    pub postgres: OuterPostgres,
}
#[derive(Debug, Serialize)]
pub(super) struct Inspection {
    pub outer: FileDigest,
    pub inner: FileDigest,
    pub program_count: usize,
    pub file_count: usize,
    pub total_file_bytes: u64,
    pub source_authenticated: bool,
    pub platform_signature_verified: bool,
    pub production_release_authorized: bool,
}
pub(super) fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn relative(s: &str) -> Result<()> {
    if s.is_empty()
        || s.contains('\\')
        || s.contains('\0')
        || s.len() > 4096
        || Path::new(s).is_absolute()
        || Path::new(s)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
    {
        bail!("maintenance_relative_path_invalid");
    }
    Ok(())
}
pub(super) fn digest_bytes(b: &[u8]) -> FileDigest {
    FileDigest {
        bytes: b.len() as u64,
        sha256: format!("{:x}", Sha256::digest(b)),
    }
}
pub(super) fn read_regular(p: &Path, max: u64) -> Result<Vec<u8>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let before = fs::symlink_metadata(p).context("maintenance_input_missing")?;
    if !before.is_file() || before.len() > max {
        bail!("maintenance_input_invalid");
    }
    #[cfg(unix)]
    if before.nlink() != 1 {
        bail!("maintenance_input_linked");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    options.custom_flags(0x100 | 0x4); // O_NOFOLLOW | O_NONBLOCK.
    #[cfg(all(unix, not(target_os = "macos")))]
    options.custom_flags(0x20000 | 0x800);
    let mut file = options.open(p).context("maintenance_input_open_failed")?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
        bail!("maintenance_input_changed");
    }
    let mut b = Vec::new();
    file.by_ref()
        .take(max.checked_add(1).context("maintenance_limit_overflow")?)
        .read_to_end(&mut b)?;
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(p)?;
    if b.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified()? != before.modified()?
    {
        bail!("maintenance_input_changed");
    }
    #[cfg(unix)]
    if (after.dev(), after.ino(), after.nlink()) != (path_after.dev(), path_after.ino(), 1)
        || after.mtime_nsec() != before.mtime_nsec()
    {
        bail!("maintenance_input_changed");
    }
    Ok(b)
}
pub(super) fn hash_regular(p: &Path, max: u64) -> Result<FileDigest> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let before = fs::symlink_metadata(p)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > max {
        bail!("maintenance_input_invalid");
    }
    #[cfg(target_os = "macos")]
    let flags = 0x100 | 0x4;
    #[cfg(not(target_os = "macos"))]
    let flags = 0x20000 | 0x800;
    let mut f = OpenOptions::new().read(true).custom_flags(flags).open(p)?;
    let opened = f.metadata()?;
    if (opened.dev(), opened.ino()) != (before.dev(), before.ino()) {
        bail!("maintenance_input_changed");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut bytes = 0_u64;
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("maintenance_size_overflow")?;
        if bytes > max {
            bail!("maintenance_input_limit");
        }
        digest.update(&buffer[..n]);
    }
    let after = f.metadata()?;
    let named = fs::symlink_metadata(p)?;
    if bytes != before.len()
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.nlink(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            1,
        )
        || (named.dev(), named.ino(), named.nlink()) != (after.dev(), after.ino(), 1)
    {
        bail!("maintenance_input_changed");
    }
    Ok(FileDigest {
        bytes,
        sha256: format!("{:x}", digest.finalize()),
    })
}
pub(super) fn collect(root: &Path, max_files: u64, max_bytes: u64) -> Result<Vec<FileEntry>> {
    fn walk(
        root: &Path,
        dir: &Path,
        out: &mut Vec<FileEntry>,
        sum: &mut u64,
        max_files: u64,
        max_bytes: u64,
        depth: usize,
        nodes: &mut u64,
    ) -> Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        if depth > 64 {
            bail!("maintenance_tree_depth");
        }
        for child in fs::read_dir(dir)? {
            *nodes = nodes.checked_add(1).context("maintenance_tree_overflow")?;
            if *nodes
                > max_files
                    .checked_mul(65)
                    .and_then(|v| v.checked_add(1))
                    .context("maintenance_tree_overflow")?
            {
                bail!("maintenance_tree_node_limit");
            }
            let p = child?.path();
            let m = fs::symlink_metadata(&p)?;
            let rel = p
                .strip_prefix(root)?
                .to_str()
                .context("maintenance_path_utf8")?;
            relative(rel)?;
            if m.is_dir() {
                if fs::read_dir(&p)?.next().is_none() {
                    bail!("maintenance_empty_extra_directory");
                }
                walk(root, &p, out, sum, max_files, max_bytes, depth + 1, nodes)?;
            } else if m.is_file() {
                if rel == INNER_FILE {
                    continue;
                }
                if out.len() as u64 >= max_files {
                    bail!("maintenance_tree_file_limit");
                }
                *sum = sum
                    .checked_add(m.len())
                    .context("maintenance_tree_overflow")?;
                if *sum > max_bytes {
                    bail!("maintenance_tree_byte_limit");
                }
                let d = hash_regular(&p, max_bytes)?;
                #[cfg(unix)]
                let mode = m.permissions().mode() & 0o777;
                #[cfg(not(unix))]
                let mode = 0;
                out.push(FileEntry {
                    path: rel.into(),
                    bytes: d.bytes,
                    sha256: d.sha256,
                    mode,
                });
            } else {
                bail!("maintenance_tree_special_or_linked");
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(
        root, root, &mut out, &mut 0, max_files, max_bytes, 0, &mut 0,
    )?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}
pub(super) fn inspect(root: &Path, expected_outer: Option<&str>) -> Result<Inspection> {
    if !root.is_absolute()
        || fs::canonicalize(root)? != root
        || !fs::symlink_metadata(root)?.is_dir()
    {
        bail!("maintenance_root_invalid");
    }
    let outer_bytes = read_regular(&root.join(OUTER_FILE), 1024 * 1024)?;
    let outer_digest = digest_bytes(&outer_bytes);
    if let Some(expected) = expected_outer {
        if !valid_sha(expected) || expected != outer_digest.sha256 {
            bail!("maintenance_outer_untrusted");
        }
    }
    let outer: Outer = serde_json::from_slice(&outer_bytes)?;
    if outer.schema != "wrokbot-pg-maintenance-release"
        || outer.schema_version != 1
        || outer.postgres.root != RESOURCE_ROOT
        || !valid_sha(&outer.postgres.manifest_sha256)
    {
        bail!("maintenance_outer_invalid");
    }
    let inner_root = root.join(RESOURCE_ROOT);
    let inner_bytes = read_regular(&inner_root.join(INNER_FILE), 1024 * 1024)?;
    let inner_digest = digest_bytes(&inner_bytes);
    if inner_digest.sha256 != outer.postgres.manifest_sha256 {
        bail!("maintenance_inner_digest");
    }
    let m: Manifest = serde_json::from_slice(&inner_bytes)?;
    if m.schema != "openbot-postgres-maintenance-bundle"
        || m.schema_version != 2
        || m.postgres_version != "17.11"
        || m.source_archive_bytes != ARCHIVE_BYTES
        || m.source_archive_sha256 != ARCHIVE_SHA
        || m.product_patch_bytes == 0
        || !valid_sha(&m.product_patch_sha256)
        || !valid_sha(&m.recipe_sha256)
        || !valid_sha(&m.build_profile_sha256)
        || m.release_epoch != 5
        || m.minimum_core_version != env!("CARGO_PKG_VERSION")
        || m.platform != "macos"
        || m.arch != std::env::consts::ARCH
    {
        bail!("maintenance_manifest_identity");
    }
    m.programs.validate()?;
    let actual = collect(&inner_root, 8192, 2 * 1024 * 1024 * 1024)?;
    if actual.len() != m.files.len() {
        bail!("maintenance_tree_extra_or_missing");
    }
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for (a, e) in actual.iter().zip(&m.files) {
        relative(&e.path)?;
        if !seen.insert(e.path.clone())
            || !valid_sha(&e.sha256)
            || (a.path.as_str(), a.bytes, a.sha256.as_str(), a.mode)
                != (e.path.as_str(), e.bytes, e.sha256.as_str(), e.mode)
        {
            bail!("maintenance_tree_mismatch");
        }
        let program = m.programs.paths().contains(&e.path.as_str());
        if program && e.mode != 0o755 {
            bail!("maintenance_program_mode");
        }
        if !program && e.mode != 0o644 {
            bail!("maintenance_material_mode");
        }
        if !program && e.path.starts_with("bin/") {
            bail!("maintenance_extra_program");
        }
        if !program && !(e.path.starts_with("lib/") || e.path.starts_with("share/")) {
            bail!("maintenance_unknown_tree_entry");
        }
        total = total
            .checked_add(e.bytes)
            .context("maintenance_total_overflow")?;
    }
    for role in m.programs.paths() {
        if !seen.contains(role) {
            bail!("maintenance_program_missing");
        }
    }
    let mut source_paths = BTreeSet::new();
    if m.derived_sources.len() != 11 || m.build_tools.is_empty() {
        bail!("maintenance_provenance_missing");
    }
    for s in &m.derived_sources {
        relative(&s.path)?;
        if !source_paths.insert(&s.path)
            || !super::build::allowed_source(&s.path)
            || s.after.bytes == 0
            || !valid_sha(&s.after.sha256)
            || s.before.as_ref().is_some_and(|b| !valid_sha(&b.sha256))
        {
            bail!("maintenance_source_provenance");
        }
    }
    let mut tools = BTreeSet::new();
    for t in &m.build_tools {
        if !valid_tool_role(&t.role)
            || !tools.insert(t.role.as_str())
            || !Path::new(&t.path).is_absolute()
            || t.bytes == 0
            || !valid_sha(&t.sha256)
        {
            bail!("maintenance_tool_provenance");
        }
        if let Some((_, path, bytes, sha256)) =
            FIXED_INTERNAL_TOOLS.iter().find(|row| row.0 == t.role)
        {
            if t.path != *path || t.bytes != *bytes || t.sha256 != *sha256 {
                bail!("maintenance_tool_provenance");
            }
        }
    }
    for required in [
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
    ] {
        if !tools.contains(required) {
            bail!("maintenance_tool_provenance_missing");
        }
    }
    for (required, _, _, _) in FIXED_INTERNAL_TOOLS {
        if !tools.contains(required) {
            bail!("maintenance_tool_provenance_missing");
        }
    }
    Ok(Inspection {
        outer: outer_digest,
        inner: inner_digest,
        program_count: 4,
        file_count: actual.len(),
        total_file_bytes: total,
        source_authenticated: expected_outer.is_some(),
        platform_signature_verified: false,
        production_release_authorized: false,
    })
}

pub(super) fn valid_tool_role(role: &str) -> bool {
    matches!(
        role,
        "git"
            | "shell"
            | "make"
            | "compiler"
            | "archiver"
            | "ranlib"
            | "linker"
            | "compilerResolved"
            | "linkerResolved"
            | "otool"
            | "installNameTool"
            | "awk"
            | "basename"
            | "cat"
            | "chmod"
            | "cp"
            | "cut"
            | "dirname"
            | "expr"
            | "find"
            | "grep"
            | "head"
            | "install"
            | "ln"
            | "mkdir"
            | "mv"
            | "perl"
            | "pwd"
            | "rm"
            | "sed"
            | "sort"
            | "tail"
            | "test"
            | "tr"
            | "uname"
    ) || FIXED_INTERNAL_TOOLS.iter().any(|row| row.0 == role)
}
