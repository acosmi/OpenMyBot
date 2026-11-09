//! Private PG restore sandbox projection. This is no staging, owner or Current proof.
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::Stdio;

use tokio::process::Command;

use crate::postgres_sidecar::{PostgresProgram, VerifiedPostgresBundle};

/// A borrowed original directory, not an authority reconstructed from a pathname.
pub(crate) struct Directory<'a> {
    pub(crate) path: &'a Path,
    pub(crate) original: &'a File,
}

/// The original producer supplies these exact, independently created generation children.
pub(crate) struct Generation<'a> {
    pub(crate) root: Directory<'a>,
    pub(crate) data: Directory<'a>,
    pub(crate) wal: Directory<'a>,
    pub(crate) temp: Directory<'a>,
    pub(crate) uds: Directory<'a>,
    pub(crate) materials: Directory<'a>,
}

/// Only a trusted parent plus one component can name a protected, possibly absent old site.
pub(crate) struct ExcludedLocation<'a> {
    pub(crate) parent: Directory<'a>,
    pub(crate) component: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IsolationFault {
    IsolationUnproven,
    CapacityExceeded,
}

/// Raw IO remains available to the enclosing original owner; formatting is redacted.
pub(crate) struct IsolationFailure {
    pub(crate) fault: IsolationFault,
    pub(crate) _original_io: Option<io::Error>,
}
impl std::fmt::Debug for IsolationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolationFailure")
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}
fn unproven() -> IsolationFailure {
    IsolationFailure {
        fault: IsolationFault::IsolationUnproven,
        _original_io: None,
    }
}
fn capacity() -> IsolationFailure {
    IsolationFailure {
        fault: IsolationFault::CapacityExceeded,
        _original_io: None,
    }
}
impl From<io::Error> for IsolationFailure {
    fn from(error: io::Error) -> Self {
        Self {
            fault: IsolationFault::IsolationUnproven,
            _original_io: Some(error),
        }
    }
}

/// Immutable projection inputs stay borrowed from the same resident producer.
/// No clock, filesystem mutation, secret-store operation or native process is created here.
pub(crate) struct RestoreIsolationPolicy<'a> {
    generation: Generation<'a>,
    excluded: [ExcludedLocation<'a>; 3],
    // Exact OS loader/cache files from the trusted host's closed native input inventory.
    // These are never supplied by RecoveryRequest or by restored PostgreSQL configuration.
    system_loader_files: &'a [&'a Path],
    max_policy_bytes: usize,
}

impl<'a> RestoreIsolationPolicy<'a> {
    pub(crate) fn prepare(
        generation: Generation<'a>,
        excluded: [ExcludedLocation<'a>; 3],
        system_loader_files: &'a [&'a Path],
        max_policy_bytes: u64,
    ) -> Result<Self, IsolationFailure> {
        let max_policy_bytes = usize::try_from(max_policy_bytes).map_err(|_| capacity())?;
        if max_policy_bytes == 0 || system_loader_files.is_empty() {
            return Err(unproven());
        }
        let policy = Self {
            generation,
            excluded,
            system_loader_files,
            max_policy_bytes,
        };
        policy.revalidate()?;
        Ok(policy)
    }

    pub(crate) fn revalidate(&self) -> Result<(), IsolationFailure> {
        let g = &self.generation;
        let identity = directory(&g.root, true)?;
        for (child, name) in [
            (&g.data, "data"),
            (&g.wal, "wal"),
            (&g.temp, "temp"),
            (&g.uds, "uds"),
            (&g.materials, "materials"),
        ] {
            if child.path != g.root.path.join(name)
                || directory(child, true)?.dev() != identity.dev()
            {
                return Err(unproven());
            }
        }
        for location in &self.excluded {
            directory(&location.parent, false)?;
            component(location.component)?;
            let excluded = location.parent.path.join(location.component);
            match fs::symlink_metadata(&excluded) {
                Ok(metadata) if metadata.file_type().is_symlink() => return Err(unproven()),
                Ok(_) => (),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            if overlaps(g.root.path, &excluded) {
                return Err(unproven());
            }
        }
        // Count before traversing the borrowed inventory; no unbounded owned loader list.
        let mut bytes = 0usize;
        for path in self.system_loader_files {
            let text = path_text(path)?;
            bytes = bytes.checked_add(text.len()).ok_or_else(capacity)?;
            if bytes > self.max_policy_bytes || !system_loader(path) {
                return Err(unproven());
            }
        }
        Ok(())
    }

    /// Return the real sandbox-exec Command which the original runner must spawn and wait.
    /// This does not execute it or prove that the current OS supports the complete policy.
    pub(crate) fn checked_postgres_command(
        &self,
        bundle: &VerifiedPostgresBundle,
        args: &[std::ffi::OsString],
    ) -> Result<Command, super::RestoreProgramFailure> {
        self.revalidate()
            .map_err(|original| super::RestoreProgramFailure::Isolation { _original: original })?;
        let resource = bundle.root();
        for location in &self.excluded {
            let excluded = location.parent.path.join(location.component);
            if overlaps(resource, &excluded) {
                return Err(super::RestoreProgramFailure::Isolation { _original: unproven() });
            }
        }
        if overlaps(resource, self.generation.root.path) {
            return Err(super::RestoreProgramFailure::Isolation { _original: unproven() });
        }
        let executable = bundle.postgres();
        let profile = self
            .render(resource, executable)
            .map_err(|original| super::RestoreProgramFailure::Isolation { _original: original })?;
        // Render first, then recheck the complete original authenticated program
        // and loader tree. The runner repeats directory identity checks at spawn.
        let verified = bundle
            .checked_command(PostgresProgram::Server)
            .map_err(|original| super::RestoreProgramFailure::Bundle { _original: original })?;
        if verified.as_std().get_program() != executable.as_os_str() {
            return Err(super::RestoreProgramFailure::Isolation { _original: unproven() });
        }
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(profile).arg(executable).args(args);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .current_dir(self.generation.temp.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        Ok(command)
    }

    pub(crate) fn generation_identity(&self) -> Result<[u64; 3], IsolationFailure> {
        self.revalidate()?;
        let metadata = self.generation.root.original.metadata()?;
        Ok([metadata.dev(), metadata.ino(), u64::from(metadata.uid())])
    }

    fn render(&self, software: &Path, executable: &Path) -> Result<String, IsolationFailure> {
        let mut p = BoundedPolicy {
            text: String::new(),
            maximum: self.max_policy_bytes,
        };
        p.parts(&["(version 1)\n(deny default)\n(allow process-fork)\n(allow signal (target self))\n(allow signal (target same-sandbox))\n"])?;
        // PG17 on macOS needs its SysV interlock segment and semaphores even
        // with mmap shared memory; without them postmaster startup fails.
        p.parts(&["(allow ipc-sysv-shm)\n(allow ipc-sysv-sem)\n"])?;
        // No allow-default, imported Engine policy, no-sandbox helper, IP/loopback rule,
        // Mach service or arbitrary-executable fallback is added.
        p.rule("process-exec*", "literal", executable)?;
        p.rule("file-read*", "subpath", software)?;
        p.rule("file-read*", "subpath", self.generation.materials.path)?;
        for directory in [
            &self.generation.data,
            &self.generation.wal,
            &self.generation.temp,
            &self.generation.uds,
        ] {
            p.rule("file-read*", "subpath", directory.path)?;
            p.rule("file-write*", "subpath", directory.path)?;
        }
        // Exact private Unix socket only; no IP socket, DNS or loopback exception.
        let socket = self.generation.uds.path.join(".s.PGSQL.5432");
        p.rule(
            "network-bind network-inbound network-outbound",
            "literal",
            &socket,
        )?;
        for path in self.system_loader_files {
            p.rule("file-read*", "literal", path)?;
        }
        for path in [
            Path::new("/dev/null"),
            Path::new("/dev/random"),
            Path::new("/dev/urandom"),
        ] {
            p.rule("file-read*", "literal", path)?;
        }
        // Directory-anchor metadata is literal only, never a recursive home/tmp/OS grant.
        for directory in [
            &self.generation.root,
            &self.generation.data,
            &self.generation.wal,
            &self.generation.temp,
            &self.generation.uds,
            &self.generation.materials,
        ] {
            for path in directory.path.ancestors() {
                p.rule("file-read-metadata", "literal", path)?;
            }
        }
        for path in software.ancestors() {
            p.rule("file-read-metadata", "literal", path)?;
        }
        for loader in self.system_loader_files {
            for path in loader.ancestors() {
                p.rule("file-read-metadata", "literal", path)?;
            }
        }
        // Loader bootstrap needs the root directory itself; this grants no subtree.
        p.rule("file-read-data", "literal", Path::new("/"))?;
        Ok(p.text)
    }
}

fn directory(d: &Directory<'_>, private: bool) -> Result<fs::Metadata, IsolationFailure> {
    path_text(d.path)?;
    let held = d.original.metadata()?;
    let named = fs::symlink_metadata(d.path)?;
    // Walk every actual ancestor O_DIRECTORY|O_NOFOLLOW, then compare that FD too.
    let actual = open_directory_chain(d.path)?.metadata()?;
    let identity = |m: &fs::Metadata| (m.dev(), m.ino(), m.uid(), m.mode());
    if !held.is_dir()
        || !named.is_dir()
        || identity(&held) != identity(&named)
        || identity(&held) != identity(&actual)
        || held.uid() != rustix::process::getuid().as_raw()
        || (private && held.mode() & 0o7777 != 0o700)
        || (!private && held.mode() & 0o7022 != 0)
    {
        return Err(unproven());
    }
    Ok(held)
}
fn open_directory_chain(path: &Path) -> Result<File, IsolationFailure> {
    let mut original = File::open("/")?;
    let mut current_path = std::path::PathBuf::from("/");
    for part in path.components() {
        if let Component::Normal(name) = part {
            current_path.push(name);
            original = rustix::fs::openat(
                &original,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| IsolationFailure::from(io::Error::from(error)))?;
            let metadata = original.metadata()?;
            let uid = metadata.uid();
            if (uid != 0 && uid != rustix::process::getuid().as_raw())
                || metadata.mode() & 0o22 != 0
                    && !(metadata.mode() & 0o1000 != 0
                        && uid == 0
                        && current_path == Path::new("/private/tmp"))
            {
                return Err(unproven());
            }
        }
    }
    Ok(original)
}
fn path_text(path: &Path) -> Result<&str, IsolationFailure> {
    let text = path.to_str().ok_or_else(unproven)?;
    if !path.is_absolute()
        || text
            .bytes()
            .any(|b| b < 32 || b == 127 || matches!(b, b'"' | b'\\'))
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || text
            .split('/')
            .skip(1)
            .any(|c| c.is_empty() || c == "." || c == "..")
            && text != "/"
    {
        return Err(unproven());
    }
    Ok(text)
}
fn component(text: &str) -> Result<(), IsolationFailure> {
    let mut parts = Path::new(text).components();
    if !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
        || text
            .bytes()
            .any(|b| b < 32 || b == 127 || matches!(b, b'"' | b'\\' | b'/'))
    {
        return Err(unproven());
    }
    Ok(())
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn system_loader(path: &Path) -> bool {
    path.starts_with("/usr/lib")
        || path.starts_with("/System/Library/dyld")
        || path.starts_with("/System/Library/Frameworks")
}
struct BoundedPolicy {
    text: String,
    maximum: usize,
}
impl BoundedPolicy {
    fn parts(&mut self, parts: &[&str]) -> Result<(), IsolationFailure> {
        let extra = parts
            .iter()
            .try_fold(0usize, |n, part| n.checked_add(part.len()))
            .ok_or_else(capacity)?;
        if self
            .text
            .len()
            .checked_add(extra)
            .is_none_or(|n| n > self.maximum)
        {
            return Err(capacity());
        }
        self.text.try_reserve_exact(extra).map_err(|_| capacity())?;
        for part in parts {
            self.text.push_str(part);
        }
        Ok(())
    }
    fn rule(&mut self, operation: &str, filter: &str, path: &Path) -> Result<(), IsolationFailure> {
        let text = path_text(path)?;
        self.parts(&["(allow ", operation, " (", filter, " \"", text, "\"))\n"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Component-only: authenticated F07 software, original policy and a real wait.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires explicit retained F07 release and task-owned result directory"]
    async fn f07_authenticated_postgres_version_under_original_policy() {
        use crate::postgres_sidecar::{PostgresBundleDigest, ReviewedPostgresSigningIdentity};
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::os::unix::process::ExitStatusExt;
        use std::path::PathBuf;

        let release = PathBuf::from(
            std::env::var_os("WROKBOT_TEST_F07_RELEASE").expect("explicit F07 release"),
        );
        let results = PathBuf::from(
            std::env::var_os("WROKBOT_TEST_POLICY_RESULT_DIR")
                .expect("explicit task result directory"),
        );
        assert!(release.is_absolute() && results.is_absolute());
        let outer = fs::read(release.join("wrok-bot-release.json")).expect("read retained outer");
        // Existing tauri_background::SELF_OWNED_CAPTURE_FIXTURE pin; never
        // replace this independent expectation with a newly calculated digest.
        let expected = "02c306937c8238a34d58ddf01f1739f0b7a4a0f8929413932c9a9e8b19013ca2";
        let actual = Sha256::digest(&outer)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected);
        let manifest: serde_json::Value =
            serde_json::from_slice(&outer).expect("pinned outer JSON");
        let pg = &manifest["postgres"];
        assert_eq!(pg["root"].as_str(), Some("postgres"));
        let digest = PostgresBundleDigest::from_hex(
            pg["manifest_sha256"].as_str().expect("pinned PG digest"),
        )
        .expect("PG digest shape");
        let signer = ReviewedPostgresSigningIdentity::from_reviewed_release(
            pg["signing_identity"].as_str().expect("pinned signer"),
        )
        .expect("reviewed fixture signer");
        let bundle = VerifiedPostgresBundle::open(release.join("postgres"), digest, &signer)
            .expect("actual authenticated PG bundle");

        let root = PathBuf::from("/private/tmp").join(format!(
            "wrokbot-s20-policy-version-{}",
            uuid::Uuid::now_v7()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("exclusive own fixture");
        struct OwnFixture(PathBuf);
        impl Drop for OwnFixture {
            fn drop(&mut self) {
                if let Err(error) = fs::remove_dir_all(&self.0) {
                    eprintln!("own component fixture cleanup failed: {error}");
                }
            }
        }
        let fixture = OwnFixture(root.clone());
        let parent = File::open(&root).expect("held own parent");
        let paths = [
            "generation",
            "generation/data",
            "generation/wal",
            "generation/temp",
            "generation/uds",
            "generation/materials",
        ]
        .map(|leaf| root.join(leaf));
        for path in &paths {
            fs::create_dir(path).expect("exclusive own generation directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private generation directory");
        }
        let held = paths
            .each_ref()
            .map(|path| File::open(path).expect("held original generation directory"));
        let excluded_paths = ["old-site", "control", "key-medium"].map(|leaf| root.join(leaf));
        for path in &excluded_paths {
            fs::create_dir(path).expect("exclusive own excluded directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private excluded directory");
        }
        let excluded_held = excluded_paths
            .each_ref()
            .map(|path| File::open(path).expect("held own excluded directory"));
        let directory = |index: usize| Directory {
            path: &paths[index],
            original: &held[index],
        };
        // Actual Mach-O import paths read from this authenticated postgres.
        // This does not assert held files or a complete host cache inventory.
        let imports = [
            Path::new("/usr/lib/dyld"),
            Path::new("/usr/lib/libSystem.B.dylib"),
        ];
        let policy = RestoreIsolationPolicy::prepare(
            Generation {
                root: directory(0),
                data: directory(1),
                wal: directory(2),
                temp: directory(3),
                uds: directory(4),
                materials: directory(5),
            },
            ["old-site", "control", "key-medium"].map(|component| ExcludedLocation {
                parent: Directory {
                    path: &root,
                    original: &parent,
                },
                component,
            }),
            &imports,
            65_536, // Explicit limit for this component test, not a product default.
        )
        .expect("prepare original policy");
        let mut command = policy
            .checked_postgres_command(&bundle, &[std::ffi::OsString::from("--version")])
            .unwrap_or_else(|error| match error {
                super::super::RestoreProgramFailure::Isolation { _original: error } => {
                    panic!("original policy command: {error:?}")
                }
                super::super::RestoreProgramFailure::Bundle { _original: error } => {
                    panic!("original bundle command: {error:?}")
                }
                _ => panic!("unexpected pre-spawn failure in original policy command"),
            });
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                fs::write(results.join("spawn-error.txt"), format!("{error:?}\n"))
                    .expect("retain spawn error");
                panic!("original sandbox spawn failed: {error}");
            }
        };
        let pid = child.id().expect("actual component Child pid");
        let output = child
            .wait_with_output()
            .await
            .expect("original component Child wait and pipes");
        fs::write(results.join("stdout.txt"), &output.stdout).expect("retain full stdout");
        fs::write(results.join("stderr.txt"), &output.stderr).expect("retain full stderr");
        fs::write(
            results.join("RESULT.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "component": "authenticated-postgres-version-under-original-policy",
            "pid": pid, "status": output.status.code(), "success": output.status.success(),
            "signal": output.status.signal(), "core_dumped": output.status.core_dumped(),
            "status_debug": format!("{:?}", output.status),
                "stdout_bytes": output.stdout.len(), "stderr_bytes": output.stderr.len(),
                "original_child_wait_completed": true,
                "candidate_database_started": false,
            }))
            .expect("result JSON"),
        )
        .expect("retain actual result");
        assert!(
            output.status.success(),
            "original policy refused ({:?}); see retained raw outputs",
            output.status
        );
        assert_eq!(output.stdout, b"postgres (PostgreSQL) 17.11\n");
        assert!(output.stderr.is_empty(), "see retained component stderr");
        drop(excluded_held);
        drop(held);
        drop(parent);
        drop(fixture);
    }

    #[test]
    fn policy_text_injection_and_untrusted_loader_roots_are_rejected() {
        for text in [
            "relative", "/a/../b", "/a/./b", "/a//b", "/a/\"b", "/a/\\b", "/a/\nb",
        ] {
            assert!(path_text(Path::new(text)).is_err());
        }
        for text in ["", ".", "..", "a/b", "a\"b", "a\nb"] {
            assert!(component(text).is_err());
        }
        assert!(!system_loader(Path::new("/opt/a/lib")));
        assert!(!system_loader(Path::new("/usr/lib-other/a")));
        assert!(overlaps(Path::new("/a/b"), Path::new("/a")));
        assert!(!overlaps(Path::new("/a/b"), Path::new("/a/bad")));
    }
    #[test]
    fn policy_allocation_is_admitted_before_extension() {
        let mut p = BoundedPolicy {
            text: String::new(),
            maximum: 5,
        };
        p.parts(&["ab", "cde"]).unwrap();
        assert_eq!(p.text, "abcde");
        assert_eq!(
            p.parts(&["f"]).unwrap_err().fault,
            IsolationFault::CapacityExceeded
        );
        assert_eq!(p.text, "abcde");
    }
}
