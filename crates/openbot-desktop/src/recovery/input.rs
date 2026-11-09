//! Original launcher files and their once-parsed Infra request.

use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use openbot_infra::auth::single_user::desktop_local::CurrentOsUserAppDataRoot;
use openbot_infra::recovery_control::{
    OwnedRecoveryRequestFile, RecoveryControl, RecoveryControlError, TrustedHostRecoveryLimits,
    VerifiedRecoveryHost, VerifiedRecoveryHostIntent,
};
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::desktop_release::VerifiedDesktopRelease;

use super::DesktopRestoreError;

/// One authenticated release request. It is neither serializable nor a runtime authority.
pub struct VerifiedRestoreEntry {
    pub(crate) control: RecoveryControl,
    pub(crate) intent: VerifiedRecoveryHostIntent,
    pub(crate) original: RestoreEntryInput,
}

impl std::fmt::Debug for VerifiedRestoreEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedRestoreEntry(<original-release-request>)")
    }
}

/// Until the Infra owner takes each source, failures keep the original raw results here.
pub struct RestoreEntryInput {
    release: Option<(File, OsString, File)>,
    bootstrap: Option<crate::tauri_background::DesktopRecoveryBootstrap>,
    paths: Option<(PathBuf, PathBuf)>,
    parent: Option<File>,
    opened: Option<io::Result<File>>,
    metadata: Option<io::Result<Metadata>>,
    named: Option<rustix::io::Result<rustix::fs::Stat>>,
    program: Option<(File, OsString, File)>,
    request: Option<OwnedRecoveryRequestFile>,
    host: Option<VerifiedRecoveryHost>,
    control_error: Option<RecoveryControlError>,
}

impl std::fmt::Debug for RestoreEntryInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RestoreEntryInput(<original-release-request-results>)")
    }
}

impl RestoreEntryInput {
    pub(super) fn new() -> Self {
        Self {
            release: None,
            bootstrap: None,
            paths: None,
            parent: None,
            opened: None,
            metadata: None,
            named: None,
            program: None,
            request: None,
            host: None,
            control_error: None,
        }
    }

    pub(super) fn verify(
        &mut self,
        release: &mut VerifiedDesktopRelease,
        actual: CurrentOsUserAppDataRoot,
        program_path: &Path,
        request_path: &Path,
    ) -> Result<(RecoveryControl, VerifiedRecoveryHostIntent), DesktopRestoreError> {
        *self = Self::from_release(release, program_path, request_path)?;
        self.verify_held(actual)
    }

    pub(crate) fn from_release(
        release: &mut VerifiedDesktopRelease,
        program: &Path,
        request: &Path,
    ) -> Result<Self, DesktopRestoreError> {
        let bootstrap = release.recovery.as_ref()
            .ok_or(DesktopRestoreError::InitializationRequired)?.clone();
        let held_path_bytes = program.as_os_str().len().checked_add(request.as_os_str().len())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(DesktopRestoreError::CapacityExceeded)?;
        if held_path_bytes as u64 > bootstrap.host_limits.max_metadata_bytes {
            return Err(DesktopRestoreError::CapacityExceeded);
        }
        let original = release.original_release.take().ok_or(DesktopRestoreError::EntryInvalid)?;
        let mut owner = Self::new();
        owner.release = Some(original);
        owner.bootstrap = Some(bootstrap);
        owner.paths = Some((program.to_owned(), request.to_owned()));
        Ok(owner)
    }

    pub(crate) fn verify_held(
        &mut self,
        actual: CurrentOsUserAppDataRoot,
    ) -> Result<(RecoveryControl, VerifiedRecoveryHostIntent), DesktopRestoreError> {
        let bootstrap = self.bootstrap.as_ref().ok_or(DesktopRestoreError::EntryInvalid)?.clone();
        let (program_path, request_path) = self.paths.as_ref().ok_or(DesktopRestoreError::EntryInvalid)?.clone();
        let program_path = program_path.as_path();
        let request_path = request_path.as_path();
        let limits = &bootstrap.host_limits;
        if self.release.is_none() { return Err(DesktopRestoreError::EntryInvalid); }
        let deadline = Instant::now()
            .checked_add(Duration::from_nanos(limits.admission_ns))
            .ok_or(DesktopRestoreError::ProfileInvalid)?;
        let uid = rustix::process::getuid().as_raw();
        if uid != rustix::process::geteuid().as_raw() {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        // Two release FDs, two program FDs, two request FDs and at most two
        // transient ancestor FDs. Infra charges the six retained FDs at transfer.
        if limits.max_open_files < 8 {
            return Err(DesktopRestoreError::CapacityExceeded);
        }
        let path_bytes = program_path
            .as_os_str()
            .len()
            .checked_add(request_path.as_os_str().len())
            .and_then(|n| n.checked_add(actual.as_path().as_os_str().len()))
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
            .ok_or(DesktopRestoreError::CapacityExceeded)?;
        if path_bytes as u64 > limits.max_metadata_bytes {
            return Err(DesktopRestoreError::CapacityExceeded);
        }

        let program_component = self.open_parent(program_path, uid, limits, deadline)?;
        self.opened = Some(
            rustix::fs::openat(
                self.parent
                    .as_ref()
                    .ok_or(DesktopRestoreError::EntryInvalid)?,
                &program_component,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        before(deadline)?;
        let program = self
            .opened
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(DesktopRestoreError::IoFailure)?;
        self.metadata = Some(program.metadata());
        before(deadline)?;
        let held = self
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(DesktopRestoreError::IoFailure)?;
        if !held.is_file()
            || held.nlink() != 1
            || (held.uid() != uid && held.uid() != 0)
            || held.mode() & 0o022 != 0
        {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        self.named = Some(rustix::fs::statat(
            self.parent
                .as_ref()
                .ok_or(DesktopRestoreError::EntryInvalid)?,
            &program_component,
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        before(deadline)?;
        matches_named(&self.named, held)?;
        self.program = Some((
            self.parent.take().expect("original parent retained"),
            program_component,
            self.opened
                .take()
                .expect("observed original program open")
                .expect("checked original program open"),
        ));

        let request_component = self.open_parent(request_path, uid, limits, deadline)?;
        let request = OwnedRecoveryRequestFile::from_held(
            self.parent
                .take()
                .expect("original request parent retained"),
            &request_component,
            uid,
        );
        match request {
            Ok(request) => self.request = Some(request),
            Err(error) => return Err(self.retain_control(error)),
        }
        before(deadline)?;
        let host = VerifiedRecoveryHost::from_local_release(
            self.program.take().expect("original program retained"),
            self
                .release
                .take()
                .expect("original release retained before source transfer"),
            actual.clone(),
            bootstrap.release_digest,
            limits.clone(),
            bootstrap.bounds,
            [crate::desktop_release::VAULT_KEY_STORE_SERVICE, crate::desktop_release::POSTGRES_KEY_STORE_SERVICE],
        );
        match host {
            Ok(host) => self.host = Some(host),
            Err(error) => return Err(self.retain_control(error)),
        }
        before(deadline)?;
        let original = RecoveryControl::open_local_restore_before(
            actual,
            self.request.take().expect("original request retained"),
            self.host.take().expect("original host retained"),
            deadline,
        );
        match original {
            Ok(entry) => Ok(entry),
            Err(error) => Err(self.retain_control(error)),
        }
    }

    fn retain_control(&mut self, error: RecoveryControlError) -> DesktopRestoreError {
        let fault = DesktopRestoreError::from_control(&error);
        self.control_error = Some(error);
        fault
    }

    fn open_parent(
        &mut self,
        path: &Path,
        uid: u32,
        limits: &TrustedHostRecoveryLimits,
        deadline: Instant,
    ) -> Result<OsString, DesktopRestoreError> {
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() as u64 > limits.max_relative_path_bytes
            || bytes.contains(&0)
            || bytes[1..]
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || path.components().count() as u64 > limits.max_path_depth
        {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        let parent_path = path.parent().ok_or(DesktopRestoreError::EntryInvalid)?;
        let component = path.file_name().ok_or(DesktopRestoreError::EntryInvalid)?;
        if component.len() as u64 > limits.max_component_bytes {
            return Err(DesktopRestoreError::CapacityExceeded);
        }
        let flags = OFlags::RDONLY
            | OFlags::DIRECTORY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC;
        before(deadline)?;
        self.opened = Some(
            rustix::fs::open("/", flags, Mode::empty())
                .map(File::from)
                .map_err(io::Error::from),
        );
        before(deadline)?;
        let root = self
            .opened
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(DesktopRestoreError::IoFailure)?;
        self.metadata = Some(root.metadata());
        before(deadline)?;
        let root_metadata = self
            .metadata
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(DesktopRestoreError::IoFailure)?;
        if !root_metadata.is_dir() || root_metadata.uid() != 0 || root_metadata.mode() & 0o022 != 0
        {
            return Err(DesktopRestoreError::EntryInvalid);
        }
        self.parent = Some(
            self.opened
                .take()
                .expect("observed original filesystem root")
                .expect("checked original filesystem root"),
        );
        for item in parent_path.components() {
            let Component::Normal(name) = item else {
                continue;
            };
            before(deadline)?;
            self.opened = Some(
                rustix::fs::openat(
                    self.parent.as_ref().expect("original ancestor retained"),
                    name,
                    flags,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            before(deadline)?;
            let file = self
                .opened
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(DesktopRestoreError::IoFailure)?;
            self.metadata = Some(file.metadata());
            before(deadline)?;
            let held = self
                .metadata
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(DesktopRestoreError::IoFailure)?;
            if !held.is_dir()
                || (held.uid() != uid && held.uid() != 0)
                || held.mode() & 0o022 != 0
                || held.mode() & 0o7000 != 0
            {
                return Err(DesktopRestoreError::EntryInvalid);
            }
            self.named = Some(rustix::fs::statat(
                self.parent.as_ref().expect("original ancestor retained"),
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            before(deadline)?;
            matches_named(&self.named, held)?;
            self.parent = Some(
                self.opened
                    .take()
                    .expect("observed original ancestor open")
                    .expect("checked original ancestor open"),
            );
        }
        Ok(component.to_os_string())
    }
}

fn before(deadline: Instant) -> Result<(), DesktopRestoreError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(DesktopRestoreError::EffectExpired)
    }
}

fn matches_named(
    named: &Option<rustix::io::Result<rustix::fs::Stat>>,
    held: &Metadata,
) -> Result<(), DesktopRestoreError> {
    let named = named
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(DesktopRestoreError::IoFailure)?;
    if named.st_dev as u64 != held.dev()
        || named.st_ino as u64 != held.ino()
        || named.st_uid != held.uid()
        || u32::from(named.st_mode) != held.mode()
        || named.st_nlink as u64 != held.nlink()
    {
        Err(DesktopRestoreError::EntryInvalid)
    } else {
        Ok(())
    }
}
