//! Private PG restore sandbox projection. This is no staging, owner or Current proof.
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::Stdio;

use tokio::process::Command;

use super::super::bundle::{Program, VerifiedMaintenanceBundle};

/// A borrowed original directory, not an authority reconstructed from a pathname.
pub(super) struct Directory<'a> {
    pub(super) path: &'a Path,
    pub(super) original: &'a File,
}

/// The original producer supplies these exact, independently created generation children.
pub(super) struct Generation<'a> {
    pub(super) root: Directory<'a>,
    pub(super) data: Directory<'a>,
    pub(super) wal: Directory<'a>,
    pub(super) temp: Directory<'a>,
    pub(super) uds: Directory<'a>,
    pub(super) materials: Directory<'a>,
}

/// Only a trusted parent plus one component can name a protected, possibly absent old site.
pub(super) struct ExcludedLocation<'a> {
    pub(super) parent: Directory<'a>,
    pub(super) component: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IsolationFault { IsolationUnproven, CapacityExceeded }

/// Raw IO remains available to the enclosing original owner; formatting is redacted.
pub(super) struct IsolationFailure {
    pub(super) fault: IsolationFault,
    pub(super) original_io: Option<io::Error>,
}
impl std::fmt::Debug for IsolationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolationFailure").field("fault", &self.fault).finish_non_exhaustive()
    }
}
fn unproven() -> IsolationFailure {
    IsolationFailure { fault: IsolationFault::IsolationUnproven, original_io: None }
}
fn capacity() -> IsolationFailure {
    IsolationFailure { fault: IsolationFault::CapacityExceeded, original_io: None }
}
impl From<io::Error> for IsolationFailure {
    fn from(error: io::Error) -> Self {
        Self { fault: IsolationFault::IsolationUnproven, original_io: Some(error) }
    }
}

/// Immutable projection inputs stay borrowed from the same resident producer.
/// No clock, filesystem mutation, secret-store operation or native process is created here.
pub(super) struct RestoreIsolationPolicy<'a> {
    generation: Generation<'a>,
    excluded: [ExcludedLocation<'a>; 3],
    // Exact OS loader/cache files from the trusted host's closed native input inventory.
    // These are never supplied by RecoveryRequest or by restored PostgreSQL configuration.
    system_loader_files: &'a [&'a Path],
    max_policy_bytes: usize,
}

impl<'a> RestoreIsolationPolicy<'a> {
    pub(super) fn prepare(
        generation: Generation<'a>,
        excluded: [ExcludedLocation<'a>; 3],
        system_loader_files: &'a [&'a Path],
        max_policy_bytes: u64,
    ) -> Result<Self, IsolationFailure> {
        let max_policy_bytes = usize::try_from(max_policy_bytes).map_err(|_| capacity())?;
        if max_policy_bytes == 0 || system_loader_files.is_empty() { return Err(unproven()); }
        let policy = Self { generation, excluded, system_loader_files, max_policy_bytes };
        policy.revalidate()?;
        Ok(policy)
    }

    pub(super) fn revalidate(&self) -> Result<(), IsolationFailure> {
        let g = &self.generation;
        let identity = directory(&g.root, true)?;
        for (child, name) in [(&g.data, "data"), (&g.wal, "wal"), (&g.temp, "temp"),
            (&g.uds, "uds"), (&g.materials, "materials")] {
            if child.path != g.root.path.join(name) || directory(child, true)?.dev() != identity.dev() {
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
            if overlaps(g.root.path, &excluded) { return Err(unproven()); }
        }
        // Count before traversing the borrowed inventory; no unbounded owned loader list.
        let mut bytes = 0usize;
        for path in self.system_loader_files {
            let text = path_text(path)?;
            bytes = bytes.checked_add(text.len()).ok_or_else(capacity)?;
            if bytes > self.max_policy_bytes || !system_loader(path) { return Err(unproven()); }
        }
        Ok(())
    }

    /// Return the real sandbox-exec Command which the original runner must spawn and wait.
    /// This does not execute it or prove that the current OS supports the complete policy.
    pub(super) fn checked_postgres_command(
        &self,
        bundle: &VerifiedMaintenanceBundle,
        args: &[std::ffi::OsString],
    ) -> Result<Command, super::RestoreProgramFailure> {
        self.revalidate().map_err(super::RestoreProgramFailure::Isolation)?;
        let resource = bundle.root().join("postgres-maintenance");
        for location in &self.excluded {
            let excluded = location.parent.path.join(location.component);
            if overlaps(&resource, &excluded) {
                return Err(super::RestoreProgramFailure::Isolation(unproven()));
            }
        }
        if overlaps(&resource, self.generation.root.path) {
            return Err(super::RestoreProgramFailure::Isolation(unproven()));
        }
        let executable = resource.join("bin/postgres");
        let profile = self.render(&resource, &executable)
            .map_err(super::RestoreProgramFailure::Isolation)?;
        // Render first, then recheck the complete original authenticated program
        // and loader tree. The runner repeats directory identity checks at spawn.
        let verified = bundle.checked_command(Program::Postgres).map_err(super::RestoreProgramFailure::Bundle)?;
        if verified.as_std().get_program() != executable.as_os_str() {
            return Err(super::RestoreProgramFailure::Isolation(unproven()));
        }
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(profile).arg(&executable).args(args);
        command.env_clear().env("LC_ALL", "C").env("LANG", "C")
            .current_dir(self.generation.temp.path)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .kill_on_drop(false);
        Ok(command)
    }

    pub(super) fn generation_identity(&self) -> Result<[u64; 3], IsolationFailure> {
        self.revalidate()?;
        let metadata = self.generation.root.original.metadata()?;
        Ok([metadata.dev(), metadata.ino(), u64::from(metadata.uid())])
    }

    fn render(&self, software: &Path, executable: &Path) -> Result<String, IsolationFailure> {
        let mut p = BoundedPolicy { text: String::new(), maximum: self.max_policy_bytes };
        p.parts(&["(version 1)\n(deny default)\n(allow process-fork)\n(allow signal (target self))\n(allow signal (target same-sandbox))\n"])?;
        // No allow-default, imported Engine policy, no-sandbox helper, IP/loopback rule,
        // Mach service or arbitrary-executable fallback is added.
        p.rule("process-exec*", "literal", executable)?;
        p.rule("file-read*", "subpath", software)?;
        p.rule("file-read*", "subpath", self.generation.materials.path)?;
        for directory in [&self.generation.data, &self.generation.wal, &self.generation.temp, &self.generation.uds] {
            p.rule("file-read*", "subpath", directory.path)?;
            p.rule("file-write*", "subpath", directory.path)?;
        }
        // Exact private Unix socket only; no IP socket, DNS or loopback exception.
        let socket = self.generation.uds.path.join(".s.PGSQL.5432");
        p.rule("network-bind network-inbound network-outbound", "literal", &socket)?;
        for path in self.system_loader_files { p.rule("file-read*", "literal", path)?; }
        for path in [Path::new("/dev/null"), Path::new("/dev/random"), Path::new("/dev/urandom")] {
            p.rule("file-read*", "literal", path)?;
        }
        // Directory-anchor metadata is literal only, never a recursive home/tmp/OS grant.
        for directory in [&self.generation.root, &self.generation.data, &self.generation.wal,
            &self.generation.temp, &self.generation.uds, &self.generation.materials] {
            for path in directory.path.ancestors() { p.rule("file-read-metadata", "literal", path)?; }
        }
        for path in software.ancestors() { p.rule("file-read-metadata", "literal", path)?; }
        for loader in self.system_loader_files {
            for path in loader.ancestors() { p.rule("file-read-metadata", "literal", path)?; }
        }
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
    if !held.is_dir() || !named.is_dir() || identity(&held) != identity(&named)
        || identity(&held) != identity(&actual)
        || held.uid() != rustix::process::getuid().as_raw()
        || (private && held.mode() & 0o7777 != 0o700)
        || (!private && held.mode() & 0o7022 != 0)
    { return Err(unproven()); }
    Ok(held)
}
fn open_directory_chain(path: &Path) -> Result<File, IsolationFailure> {
    let mut original = File::open("/")?;
    let mut current_path = std::path::PathBuf::from("/");
    for part in path.components() {
        if let Component::Normal(name) = part {
            current_path.push(name);
            original = rustix::fs::openat(&original, name,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty())
                .map(File::from).map_err(|error| IsolationFailure::from(io::Error::from(error)))?;
            let metadata = original.metadata()?;
            let uid = metadata.uid();
            if (uid != 0 && uid != rustix::process::getuid().as_raw())
                || metadata.mode() & 0o22 != 0 && !(metadata.mode() & 0o1000 != 0
                    && uid == 0 && current_path == Path::new("/private/tmp"))
            { return Err(unproven()); }
        }
    }
    Ok(original)
}
fn path_text(path: &Path) -> Result<&str, IsolationFailure> {
    let text = path.to_str().ok_or_else(unproven)?;
    if !path.is_absolute() || text.bytes().any(|b| b < 32 || b == 127 || matches!(b, b'"' | b'\\'))
        || path.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || text.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == "..")
            && text != "/"
    { return Err(unproven()); }
    Ok(text)
}
fn component(text: &str) -> Result<(), IsolationFailure> {
    let mut parts = Path::new(text).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some()
        || text.bytes().any(|b| b < 32 || b == 127 || matches!(b, b'"' | b'\\' | b'/'))
    { return Err(unproven()); }
    Ok(())
}
fn overlaps(a: &Path, b: &Path) -> bool { a.starts_with(b) || b.starts_with(a) }
fn system_loader(path: &Path) -> bool {
    path.starts_with("/usr/lib") || path.starts_with("/System/Library/dyld")
        || path.starts_with("/System/Library/Frameworks")
}
struct BoundedPolicy { text: String, maximum: usize }
impl BoundedPolicy {
    fn parts(&mut self, parts: &[&str]) -> Result<(), IsolationFailure> {
        let extra = parts.iter().try_fold(0usize, |n, part| n.checked_add(part.len())).ok_or_else(capacity)?;
        if self.text.len().checked_add(extra).is_none_or(|n| n > self.maximum) { return Err(capacity()); }
        self.text.try_reserve_exact(extra).map_err(|_| capacity())?;
        for part in parts { self.text.push_str(part); }
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
    #[test]
    fn policy_text_injection_and_untrusted_loader_roots_are_rejected() {
        for text in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/\"b", "/a/\\b", "/a/\nb"] {
            assert!(path_text(Path::new(text)).is_err());
        }
        for text in ["", ".", "..", "a/b", "a\"b", "a\nb"] { assert!(component(text).is_err()); }
        assert!(!system_loader(Path::new("/Users/a/lib")));
        assert!(!system_loader(Path::new("/usr/lib-other/a")));
        assert!(overlaps(Path::new("/a/b"), Path::new("/a")));
        assert!(!overlaps(Path::new("/a/b"), Path::new("/a/bad")));
    }
    #[test]
    fn policy_allocation_is_admitted_before_extension() {
        let mut p = BoundedPolicy { text: String::new(), maximum: 5 };
        p.parts(&["ab", "cde"]).unwrap();
        assert_eq!(p.text, "abcde");
        assert_eq!(p.parts(&["f"]).unwrap_err().fault, IsolationFault::CapacityExceeded);
        assert_eq!(p.text, "abcde");
    }
}
