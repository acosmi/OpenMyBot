//! Original host seals and descriptor-relative external control resources.
//!
//! Host seals belong to real release/service producers. Source loaders verify
//! actual OS owners and held files; a nominal path/digest/bool is not a seal.

use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::backup::whole_pg_restore_stream::PendingRestoreCandidateAuthority;

use super::activation::{
    ExpectedServerDatabase, Hex32, Hex64, OrdinaryStartupBounds, PublishedActivation,
    ServiceConfigRef,
};
use super::{
    ControlBudget, RecoveryControlConfig, RecoveryControlError, RecoveryControlFault,
    RecoveryFileIdentity, TrustedHostRecoveryLimits, before, component, hex,
};

mod head;
#[cfg(feature = "server-runtime")]
mod legacy;
mod write;

pub(super) use head::Head;
#[cfg(feature = "server-runtime")]
pub(super) use legacy::adopt_server_legacy_before;

/// Sealed original service configuration. This source seal alone grants no
/// ordinary startup, database, fresh actor, restore operation or Current owner.
pub struct VerifiedServiceRecoveryHost {
    pub(super) root: PathBuf,
    pub(super) uid: u32,
    original_config: ServiceOwnedInput,
    configuration: ServerRecoveryHostConfigV1,
    control_selection: ServiceControlSelection,
    original_ordinary_input: Option<ServiceOrdinaryInput>,
}

// Bootstrap bounds the file before any value in that file can be used as a
// limit. This is a structure ceiling, never a restore/effect profile default.
const SERVICE_CONFIGURATION_MAX_BYTES: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerRecoveryHostConfigV1 {
    version: u32,
    control_root: PathBuf,
    host_limits: TrustedHostRecoveryLimits,
    ordinary_startup_bounds: OrdinaryStartupBounds,
    expected_service_owner: ExpectedServiceOwner,
    expected_installation_binding: ServiceInstallationExpectation,
    expected_server_database: ExpectedServerDatabase,
    optional_startup_intent: super::RequiredNullable<PositiveServiceOrdinarySelection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedServiceOwner {
    uid: u32,
    service: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceInstallationExpectation {
    deployment_id: String,
    tenant_id: String,
    dataset_id: Hex32,
    source_installation_id: String,
    target_installation_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceOrdinaryMode {
    FreshInit,
    LegacyAdoption,
}

// Both closed variants have precisely mode and intentFile. Neither variant
// carries a profile, actor, release pin, root or database credentials.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PositiveServiceOrdinarySelection {
    mode: ServiceOrdinaryMode,
    intent_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerOrdinaryIntentV1 {
    format_version: u32,
    request_id: Hex32,
    mode: ServiceOrdinaryMode,
    service_config: ServiceConfigRef,
}

struct ServiceOrdinaryInput {
    input: ServiceOwnedInput,
    intent: ServerOrdinaryIntentV1,
}
impl ServiceOrdinaryInput {
    // Cross-file comparisons only; the intent's own fields were checked when decoded.
    fn validate(
        &self,
        config: &ServiceOwnedInput,
        mode: ServiceOrdinaryMode,
    ) -> Result<(), RecoveryControlError> {
        if self.intent.format_version != 1
            || self.intent.mode != mode
            || self.intent.service_config.file != config.stamp.identity
            || self.intent.service_config.length != config.stamp.length
            || self.intent.service_config.digest != Hex64::of(&Sha256::digest(&config.bytes).into())
        {
            return Err(service_invalid());
        }
        Ok(())
    }
}

struct ServiceAncestor {
    file: File,
    identity: RecoveryFileIdentity,
    component: Option<std::ffi::OsString>,
}

struct ServiceNamedParent {
    ancestors: Vec<ServiceAncestor>,
    component: std::ffi::OsString,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ServiceFileStamp {
    identity: RecoveryFileIdentity,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ServiceFileStamp {
    fn of(metadata: &Metadata, uid: u32) -> Result<Self, RecoveryControlError> {
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(service_invalid());
        }
        Ok(Self {
            identity: identity(metadata),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

// Retained raw read/metadata/stat results are stored before a post-deadline
// check. No raw error or configured path is rendered by the public error.
struct ServiceInputIo {
    metadata: Option<io::Result<Metadata>>,
    named: Option<rustix::io::Result<rustix::fs::Stat>>,
    read: Option<io::Result<usize>>,
    readback: [u8; 8192],
}

struct ServiceOwnedInput {
    file: File,
    parent: ServiceNamedParent,
    stamp: ServiceFileStamp,
    bytes: Vec<u8>,
    raw: ServiceInputIo,
}

struct ServiceControlSelection {
    parent: ServiceNamedParent,
    existing: Option<ServiceAncestor>,
}

fn service_invalid() -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::EntryInvalid)
}

fn service_io(_: impl std::fmt::Debug) -> RecoveryControlError {
    RecoveryControlError::new(RecoveryControlFault::IoFailure)
}

fn service_time(deadline: Option<Instant>) -> Result<(), RecoveryControlError> {
    match deadline {
        Some(deadline) => before(deadline),
        None => Ok(()),
    }
}

fn service_directory(
    metadata: &Metadata,
    uid: u32,
) -> Result<RecoveryFileIdentity, RecoveryControlError> {
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(service_invalid());
    }
    Ok(identity(metadata))
}

fn service_absolute(path: &Path) -> Result<(), RecoveryControlError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.len() < 2
        || bytes.len() as u64 > SERVICE_CONFIGURATION_MAX_BYTES
        || bytes.contains(&0)
        || bytes[1..]
            .split(|b| *b == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(service_invalid());
    }
    Ok(())
}

impl ServiceNamedParent {
    fn open(
        path: &Path,
        uid: u32,
        deadline: Option<Instant>,
    ) -> Result<Self, RecoveryControlError> {
        service_absolute(path)?;
        let parent = path.parent().ok_or_else(service_invalid)?;
        let component = path.file_name().ok_or_else(service_invalid)?.to_os_string();
        let root = File::from(
            rustix::fs::open(
                "/",
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(service_io)?,
        );
        service_time(deadline)?;
        let root_identity = service_directory(&root.metadata().map_err(service_io)?, uid)?;
        let mut ancestors = Vec::new();
        let depth = parent.components().count();
        ancestors
            .try_reserve_exact(depth)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if ancestors.capacity() > depth.checked_mul(2).ok_or_else(service_invalid)?
            || component.capacity() > component.len().checked_mul(2).ok_or_else(service_invalid)?
        {
            return Err(service_invalid());
        }
        ancestors.push(ServiceAncestor {
            file: root,
            identity: root_identity,
            component: None,
        });
        for item in parent.components() {
            let Component::Normal(name) = item else {
                if matches!(item, Component::RootDir) {
                    continue;
                }
                return Err(service_invalid());
            };
            service_time(deadline)?;
            let previous = ancestors.last().ok_or_else(service_invalid)?;
            let file = File::from(
                rustix::fs::openat(
                    &previous.file,
                    name,
                    OFlags::RDONLY
                        | OFlags::DIRECTORY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(service_io)?,
            );
            service_time(deadline)?;
            let actual = service_directory(&file.metadata().map_err(service_io)?, uid)?;
            let named = rustix::fs::statat(&previous.file, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(service_io)?;
            service_time(deadline)?;
            if named.st_dev as u64 != actual.device
                || named.st_ino as u64 != actual.inode
                || named.st_uid != actual.uid
                || named.st_mode & 0o022 != 0
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::Directory
            {
                return Err(service_invalid());
            }
            let component = name.to_os_string();
            if component.capacity() > name.len().checked_mul(2).ok_or_else(service_invalid)? {
                return Err(service_invalid());
            }
            ancestors.push(ServiceAncestor {
                file,
                identity: actual,
                component: Some(component),
            });
        }
        let result = Self {
            ancestors,
            component,
        };
        result.recheck(uid, deadline)?;
        Ok(result)
    }

    fn directory(&self) -> Result<&File, RecoveryControlError> {
        self.ancestors
            .last()
            .map(|entry| &entry.file)
            .ok_or_else(service_invalid)
    }

    fn recheck(&self, uid: u32, deadline: Option<Instant>) -> Result<(), RecoveryControlError> {
        for (index, current) in self.ancestors.iter().enumerate() {
            service_time(deadline)?;
            if service_directory(&current.file.metadata().map_err(service_io)?, uid)?
                != current.identity
            {
                return Err(service_invalid());
            }
            let named = match &current.component {
                None if index == 0 => {
                    rustix::fs::statat(&current.file, "/", AtFlags::SYMLINK_NOFOLLOW)
                }
                Some(component) if index > 0 => rustix::fs::statat(
                    &self.ancestors[index - 1].file,
                    component.as_os_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ),
                _ => return Err(service_invalid()),
            }
            .map_err(service_io)?;
            service_time(deadline)?;
            if named.st_dev as u64 != current.identity.device
                || named.st_ino as u64 != current.identity.inode
                || named.st_uid != current.identity.uid
                || named.st_mode & 0o022 != 0
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::Directory
            {
                return Err(service_invalid());
            }
        }
        Ok(())
    }

    fn retained_bytes(&self) -> Result<u64, RecoveryControlError> {
        let backing = self
            .ancestors
            .capacity()
            .checked_mul(std::mem::size_of::<ServiceAncestor>())
            .and_then(|n| n.checked_add(self.component.capacity()))
            .ok_or_else(service_invalid)?;
        self.ancestors.iter().try_fold(backing as u64, |sum, node| {
            sum.checked_add(
                node.component
                    .as_ref()
                    .map_or(0, std::ffi::OsString::capacity) as u64,
            )
            .ok_or_else(service_invalid)
        })
    }
}

impl ServiceOwnedInput {
    fn open(
        path: &Path,
        uid: u32,
        limit: u64,
        deadline: Option<Instant>,
    ) -> Result<Self, RecoveryControlError> {
        let parent = ServiceNamedParent::open(path, uid, deadline)?;
        service_time(deadline)?;
        let file = File::from(
            rustix::fs::openat(
                parent.directory()?,
                parent.component.as_os_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(service_io)?,
        );
        service_time(deadline)?;
        let stamp = ServiceFileStamp::of(&file.metadata().map_err(service_io)?, uid)?;
        if stamp.length == 0 || stamp.length > limit {
            return Err(service_invalid());
        }
        let n = usize::try_from(stamp.length.checked_add(1).ok_or_else(service_invalid)?)
            .map_err(service_io)?;
        let mut input = Self {
            file,
            parent,
            stamp,
            bytes: Vec::new(),
            raw: ServiceInputIo {
                metadata: None,
                named: None,
                read: None,
                readback: [0; 8192],
            },
        };
        input
            .bytes
            .try_reserve_exact(n)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if input.bytes.capacity() > n.checked_mul(2).ok_or_else(service_invalid)? {
            return Err(service_invalid());
        }
        input.bytes.resize(n, 0);
        let mut offset = 0usize;
        loop {
            service_time(deadline)?;
            input.raw.read = Some(
                input
                    .file
                    .read_at(&mut input.bytes[offset..], offset as u64),
            );
            service_time(deadline)?;
            let count = *input
                .raw
                .read
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if count == 0 {
                break;
            }
            offset = offset.checked_add(count).ok_or_else(service_invalid)?;
            if offset >= n {
                return Err(service_invalid());
            }
        }
        if offset as u64 != stamp.length {
            return Err(service_invalid());
        }
        input.bytes.truncate(offset);
        input.recheck(uid, deadline)?;
        Ok(input)
    }

    fn recheck(&mut self, uid: u32, deadline: Option<Instant>) -> Result<(), RecoveryControlError> {
        self.parent.recheck(uid, deadline)?;
        self.raw.metadata = Some(self.file.metadata());
        service_time(deadline)?;
        let current = ServiceFileStamp::of(
            self.raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?,
            uid,
        )?;
        if current != self.stamp {
            return Err(service_invalid());
        }
        self.raw.named = Some(rustix::fs::statat(
            self.parent.directory()?,
            self.parent.component.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        service_time(deadline)?;
        let named = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?;
        if named.st_dev as u64 != current.identity.device
            || named.st_ino as u64 != current.identity.inode
            || named.st_uid != uid
            || named.st_nlink != 1
            || named.st_mode & 0o7777 != 0o600
            || named.st_size < 0
            || named.st_size as u64 != current.length
            || rustix::fs::FileType::from_raw_mode(named.st_mode)
                != rustix::fs::FileType::RegularFile
        {
            return Err(service_invalid());
        }
        let mut offset = 0usize;
        while offset < self.bytes.len() {
            let n = (self.bytes.len() - offset).min(self.raw.readback.len());
            service_time(deadline)?;
            self.raw.read = Some(
                self.file
                    .read_at(&mut self.raw.readback[..n], offset as u64),
            );
            service_time(deadline)?;
            let count = *self
                .raw
                .read
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if count == 0 || self.raw.readback[..count] != self.bytes[offset..offset + count] {
                return Err(service_invalid());
            }
            offset = offset.checked_add(count).ok_or_else(service_invalid)?;
        }
        self.raw.read = Some(
            self.file
                .read_at(&mut self.raw.readback[..1], offset as u64),
        );
        service_time(deadline)?;
        if !matches!(self.raw.read, Some(Ok(0))) {
            return Err(service_invalid());
        }
        self.raw.metadata = Some(self.file.metadata());
        service_time(deadline)?;
        if ServiceFileStamp::of(
            self.raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?,
            uid,
        )? != self.stamp
        {
            return Err(service_invalid());
        }
        self.parent.recheck(uid, deadline)?;
        // The final named lookup follows the complete byte readback. A rename
        // during that read cannot leave a usable seal for only the held inode.
        self.raw.named = Some(rustix::fs::statat(
            self.parent.directory()?,
            self.parent.component.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        service_time(deadline)?;
        let named = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?;
        if named.st_dev as u64 != self.stamp.identity.device
            || named.st_ino as u64 != self.stamp.identity.inode
            || named.st_uid != uid
            || named.st_nlink != 1
            || named.st_mode & 0o7777 != 0o600
            || named.st_size < 0
            || named.st_size as u64 != self.stamp.length
            || rustix::fs::FileType::from_raw_mode(named.st_mode)
                != rustix::fs::FileType::RegularFile
        {
            return Err(service_invalid());
        }
        Ok(())
    }

    fn retained_bytes(&self) -> Result<u64, RecoveryControlError> {
        self.parent
            .retained_bytes()?
            .checked_add(self.bytes.capacity() as u64)
            .ok_or_else(service_invalid)
    }

    fn files(&self) -> Result<u64, RecoveryControlError> {
        u64::try_from(self.parent.ancestors.len())
            .map_err(service_io)?
            .checked_add(1)
            .ok_or_else(service_invalid)
    }
}

impl ServiceControlSelection {
    fn open(path: &Path, uid: u32, deadline: Instant) -> Result<Self, RecoveryControlError> {
        let parent = ServiceNamedParent::open(path, uid, Some(deadline))?;
        let named = rustix::fs::statat(
            parent.directory()?,
            parent.component.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        );
        before(deadline)?;
        let existing = match named {
            Err(error) if error == rustix::io::Errno::NOENT => None,
            Ok(named) => {
                if named.st_uid != uid
                    || named.st_mode & 0o7777 != 0o700
                    || rustix::fs::FileType::from_raw_mode(named.st_mode)
                        != rustix::fs::FileType::Directory
                {
                    return Err(service_invalid());
                }
                let file = File::from(
                    rustix::fs::openat(
                        parent.directory()?,
                        parent.component.as_os_str(),
                        OFlags::RDONLY
                            | OFlags::DIRECTORY
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC
                            | OFlags::NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(service_io)?,
                );
                before(deadline)?;
                let actual = service_directory(&file.metadata().map_err(service_io)?, uid)?;
                if actual.device != named.st_dev as u64
                    || actual.inode != named.st_ino as u64
                    || actual.uid != uid
                {
                    return Err(service_invalid());
                }
                Some(ServiceAncestor {
                    file,
                    identity: actual,
                    component: None,
                })
            }
            Err(error) => return Err(service_io(error)),
        };
        Ok(Self { parent, existing })
    }

    fn excludes(&self, input: &ServiceOwnedInput) -> Result<(), RecoveryControlError> {
        if let Some(root) = &self.existing {
            if input
                .parent
                .ancestors
                .iter()
                .any(|node| node.identity == root.identity)
            {
                return Err(service_invalid());
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for VerifiedServiceRecoveryHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedServiceRecoveryHost(<redacted original owner-held configuration>)")
    }
}

fn service_configuration_backing(
    configuration: &ServerRecoveryHostConfigV1,
) -> Result<u64, RecoveryControlError> {
    let ids = &configuration.expected_installation_binding;
    let mut bytes = 0u64;
    for capacity in [
        configuration.control_root.capacity(),
        configuration.expected_service_owner.service.capacity(),
        ids.deployment_id.capacity(),
        ids.tenant_id.capacity(),
        ids.source_installation_id.capacity(),
        ids.target_installation_id.capacity(),
    ] {
        bytes = bytes
            .checked_add(capacity as u64)
            .ok_or_else(service_invalid)?;
    }
    if let super::RequiredNullable::Value(selection) = &configuration.optional_startup_intent {
        bytes = bytes
            .checked_add(selection.intent_file.capacity() as u64)
            .ok_or_else(service_invalid)?;
    }
    Ok(bytes)
}

impl VerifiedServiceRecoveryHost {
    /// Explicit configured host limits. This DATA accessor cannot clone a seal.
    #[must_use]
    pub fn host_limits(&self) -> &TrustedHostRecoveryLimits {
        &self.configuration.host_limits
    }

    /// Positive ordinary-startup E/C bounds; no operation clock is created here.
    #[must_use]
    pub fn ordinary_startup_bounds(&self) -> (u64, u64) {
        let bounds = self.configuration.ordinary_startup_bounds;
        (bounds.effect_ns.get(), bounds.convergence_ns.get())
    }

    pub(super) fn retained_usage(&self) -> Result<(u64, u64), RecoveryControlError> {
        let configuration_backing = service_configuration_backing(&self.configuration)?;
        let mut bytes = self
            .original_config
            .retained_bytes()?
            .checked_add(self.control_selection.parent.retained_bytes()?)
            .and_then(|n| n.checked_add(self.root.capacity() as u64))
            .and_then(|n| n.checked_add(configuration_backing))
            .ok_or_else(service_invalid)?;
        let mut files = self
            .original_config
            .files()?
            .checked_add(self.control_selection.parent.ancestors.len() as u64)
            .and_then(|n| n.checked_add(u64::from(self.control_selection.existing.is_some())))
            .ok_or_else(service_invalid)?;
        if let Some(intent) = &self.original_ordinary_input {
            bytes = bytes
                .checked_add(intent.input.retained_bytes()?)
                .ok_or_else(service_invalid)?;
            files = files
                .checked_add(intent.input.files()?)
                .ok_or_else(service_invalid)?;
        }
        Ok((bytes, files))
    }

    pub(super) fn recheck_original(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if rustix::process::getuid().as_raw() != self.uid
            || rustix::process::geteuid().as_raw() != self.uid
        {
            return Err(service_invalid());
        }
        self.original_config.recheck(self.uid, Some(deadline))?;
        self.control_selection
            .parent
            .recheck(self.uid, Some(deadline))?;
        if let Some(root) = &self.control_selection.existing {
            if service_directory(&root.file.metadata().map_err(service_io)?, self.uid)?
                != root.identity
            {
                return Err(service_invalid());
            }
            let named = rustix::fs::statat(
                self.control_selection.parent.directory()?,
                self.control_selection.parent.component.as_os_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(service_io)?;
            before(deadline)?;
            if named.st_dev as u64 != root.identity.device
                || named.st_ino as u64 != root.identity.inode
                || named.st_uid != self.uid
                || named.st_mode & 0o7777 != 0o700
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::Directory
            {
                return Err(service_invalid());
            }
        }
        match (
            &self.configuration.optional_startup_intent,
            &mut self.original_ordinary_input,
        ) {
            (super::RequiredNullable::Value(selection), Some(intent)) => {
                intent.input.recheck(self.uid, Some(deadline))?;
                intent.validate(&self.original_config, selection.mode)?;
            }
            (super::RequiredNullable::Null(()), None) => (),
            _ => return Err(service_invalid()),
        }
        before(deadline)
    }
}

/// Read the original service owner's required closed configuration and retain
/// its actual files. The path only selects input: successful UID/FD/owner,
/// bounded-byte and closed-DATA validation creates the nonClone source seal.
/// This function never creates control metadata, a head, epoch, startup intent,
/// pool, actor, restore session or Current. It does not read process environment.
pub fn load_service_recovery_host_from_config(
    configured_path: &Path,
) -> Result<VerifiedServiceRecoveryHost, RecoveryControlError> {
    let admission_start = Instant::now();
    let uid = rustix::process::getuid().as_raw();
    if rustix::process::geteuid().as_raw() != uid {
        return Err(service_invalid());
    }
    let original_config =
        ServiceOwnedInput::open(configured_path, uid, SERVICE_CONFIGURATION_MAX_BYTES, None)?;
    let configuration: ServerRecoveryHostConfigV1 =
        serde_json::from_slice(&original_config.bytes).map_err(RecoveryControlError::from_json)?;
    let limits = configuration.host_limits.clone().checked()?;
    if configuration.version != 1 || configuration.expected_service_owner.uid != uid {
        return Err(service_invalid());
    }
    // This tuple is an explicit expected selection, never actual PG evidence.
    super::id(
        &configuration.expected_service_owner.service,
        limits.max_id_bytes,
    )?;
    let ids = &configuration.expected_installation_binding;
    for id in [
        &ids.deployment_id,
        &ids.tenant_id,
        &ids.source_installation_id,
        &ids.target_installation_id,
    ] {
        super::id(id, limits.max_id_bytes.min(512))?;
    }
    let bounds = &configuration.ordinary_startup_bounds;
    if admission_start
        .checked_add(Duration::from_nanos(bounds.effect_ns.get()))
        .and_then(|e| e.checked_add(Duration::from_nanos(bounds.convergence_ns.get())))
        .is_none()
    {
        return Err(service_invalid());
    }
    let deadline = admission_start
        .checked_add(Duration::from_nanos(limits.admission_ns))
        .ok_or_else(service_invalid)?;
    before(deadline)?;
    service_absolute(&configuration.control_root)?;
    let control_parent_depth = configuration
        .control_root
        .parent()
        .ok_or_else(service_invalid)?
        .components()
        .count();
    super::component(
        configuration
            .control_root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(service_invalid)?,
        &limits,
    )?;
    let planned_files = original_config
        .files()?
        .checked_add(control_parent_depth as u64)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(service_invalid)?;
    let root_path_bytes = configuration.control_root.as_os_str().as_bytes().len();
    let path_backing = root_path_bytes
        .checked_mul(4)
        .and_then(|n| {
            control_parent_depth
                .checked_mul(2)
                .and_then(|depth| depth.checked_mul(std::mem::size_of::<ServiceAncestor>()))
                .and_then(|nodes| n.checked_add(nodes))
        })
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServiceNamedParent>()))
        .ok_or_else(service_invalid)?;
    let planned_metadata = original_config
        .retained_bytes()?
        .checked_add(service_configuration_backing(&configuration)?)
        .and_then(|n| n.checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64))
        .and_then(|n| n.checked_add(path_backing as u64))
        .ok_or_else(service_invalid)?;
    if control_parent_depth as u64 > limits.max_path_depth || planned_files > limits.max_open_files
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::CapacityExceeded,
        ));
    }
    if planned_metadata > limits.max_metadata_bytes {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::CapacityExceeded,
        ));
    }
    let control_selection =
        ServiceControlSelection::open(&configuration.control_root, uid, deadline)?;
    control_selection.excludes(&original_config)?;
    let mut verified = VerifiedServiceRecoveryHost {
        root: configuration.control_root.clone(),
        uid,
        original_config,
        configuration,
        control_selection,
        original_ordinary_input: None,
    };
    if verified.root.capacity() > root_path_bytes.checked_mul(2).ok_or_else(service_invalid)? {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::CapacityExceeded,
        ));
    }
    if let super::RequiredNullable::Value(selection) =
        &verified.configuration.optional_startup_intent
    {
        service_absolute(&selection.intent_file)?;
        let (base_bytes, base_files) = verified.retained_usage()?;
        let depth = selection
            .intent_file
            .parent()
            .ok_or_else(service_invalid)?
            .components()
            .count();
        let path_bytes = selection.intent_file.as_os_str().as_bytes().len();
        let extra_metadata = path_bytes
            .checked_mul(2)
            .and_then(|n| {
                depth
                    .checked_mul(2)
                    .and_then(|depth| depth.checked_mul(std::mem::size_of::<ServiceAncestor>()))
                    .and_then(|nodes| n.checked_add(nodes))
            })
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServiceOwnedInput>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServerOrdinaryIntentV1>()))
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(service_invalid)?;
        let metadata_before_bytes = base_bytes
            .checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64)
            .and_then(|n| n.checked_add(extra_metadata as u64))
            .ok_or_else(service_invalid)?;
        let available = limits
            .max_metadata_bytes
            .checked_sub(metadata_before_bytes)
            .ok_or_else(service_invalid)?;
        // Prepay the held byte Vec (at most 2 * (wire + 1)), pinned serde
        // escape/key scratch and any retained parse error before decode. The
        // fixed arrays above do not allocate. The extra 1024 bytes cover the
        // bounded decoder/field-label structure, not an effect/capacity default.
        let maximum_wire = available.checked_sub(2).ok_or_else(service_invalid)? / 8;
        let planned_files = base_files
            .checked_add(depth as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(service_invalid)?;
        if maximum_wire == 0
            || depth as u64 > limits.max_path_depth
            || planned_files > limits.max_open_files
        {
            return Err(service_invalid());
        }
        // Prepay the original intent's real path/FD/buffer and typed return
        // slots before opening or allocating it. No second complete quota.
        let input = ServiceOwnedInput::open(
            &selection.intent_file,
            uid,
            limits.max_request_bytes.min(maximum_wire),
            Some(deadline),
        )?;
        if input.stamp.identity == verified.original_config.stamp.identity {
            return Err(service_invalid());
        }
        verified.control_selection.excludes(&input)?;
        let intent = serde_json::from_slice::<ServerOrdinaryIntentV1>(&input.bytes)
            .map_err(RecoveryControlError::from_json)?;
        before(deadline)?;
        let ordinary = ServiceOrdinaryInput { input, intent };
        ordinary.validate(&verified.original_config, selection.mode)?;
        // Holding the original file is custody only. No request consumption,
        // operation/epoch, head, writer lock, SQL or initialization occurs here.
        verified.original_ordinary_input = Some(ordinary);
    }
    let (bytes, files) = verified.retained_usage()?;
    let bytes = bytes
        .checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64)
        .ok_or_else(service_invalid)?;
    if bytes > limits.max_metadata_bytes || files > limits.max_open_files {
        return Err(service_invalid());
    }
    verified.recheck_original(deadline)?;
    Ok(verified)
}

#[cfg(feature = "desktop-local")]
enum HostOrigin {
    LocalRelease {
        program: (File, std::ffi::OsString, File),
        release: (File, std::ffi::OsString, File),
        actual: crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        identities: Option<[RecoveryFileIdentity; 4]>,
        metadata: [Option<io::Result<Metadata>>; 4],
        named: [Option<rustix::io::Result<rustix::fs::Stat>>; 2],
    },
}

/// Closed request purpose; observing it grants no operation authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRequestPurpose {
    RestoreSameInstallation,
    RestoreNewInstallation,
    AdoptOrdinaryLegacy,
    ReconfirmCurrentBinding,
}

#[derive(Clone, Copy)]
struct CaptureUuid(uuid::Uuid);

impl<'de> Deserialize<'de> for CaptureUuid {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = CaptureUuid;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a canonical lowercase hyphenated capture UUID")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let parsed =
                    uuid::Uuid::parse_str(value).map_err(|_| E::custom("invalid capture UUID"))?;
                let mut canonical = [0u8; 36];
                if parsed.hyphenated().encode_lower(&mut canonical) != value
                    || parsed.as_bytes()[6] >> 4 != 4
                    || parsed.as_bytes()[8] >> 6 != 2
                {
                    return Err(E::custom("invalid capture UUID"));
                }
                Ok(CaptureUuid(parsed))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreFileSelection {
    parent: PathBuf,
    component: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreInputSelection {
    carrier: RestoreFileSelection,
    key_medium: RestoreFileSelection,
    expected_bundle_id: CaptureUuid,
    expected_source_operation_id: CaptureUuid,
    expected_manifest_sha256: Hex64,
    target: RestoreFileSelection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreRequestWire {
    format_version: u32,
    request_id: Hex32,
    purpose: RecoveryRequestPurpose,
    expected_reviewed_release_digest: Hex64,
    expected_deployment_id: String,
    expected_tenant_id: String,
    expected_dataset_id: Hex32,
    expected_source_installation_id: Hex64,
    expected_target_installation_id: Hex64,
    trusted_input_selection: RestoreInputSelection,
    profile: super::RestoreOperationProfile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyInputSelection {
    installation: RestoreFileSelection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRequestWire {
    format_version: u32,
    request_id: Hex32,
    purpose: RecoveryRequestPurpose,
    expected_reviewed_release_digest: Hex64,
    expected_deployment_id: String,
    expected_tenant_id: String,
    expected_dataset_id: Hex32,
    expected_source_installation_id: Hex64,
    expected_target_installation_id: Hex64,
    trusted_input_selection: LegacyInputSelection,
    limits: OrdinaryStartupBounds,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RecoveryRequestWire {
    Restore(RestoreRequestWire),
    Legacy(LegacyRequestWire),
    Current(CurrentRequestWire),
}

#[derive(Deserialize)]
enum CurrentLocalSubject {
    #[serde(rename = "current_os_owner")]
    CurrentOsOwner,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentSelection {
    #[serde(rename = "localSubject")]
    _local_subject: CurrentLocalSubject,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentRequestLimits {
    effect_ns: std::num::NonZeroU64,
    convergence_ns: std::num::NonZeroU64,
    max_confirmations: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentRequestWire {
    format_version: u32,
    request_id: Hex32,
    purpose: RecoveryRequestPurpose,
    expected_reviewed_release_digest: Hex64,
    expected_deployment_id: String,
    expected_tenant_id: String,
    expected_dataset_id: Hex32,
    expected_source_installation_id: Hex64,
    expected_target_installation_id: Hex64,
    #[serde(rename = "trustedInputSelection")]
    _trusted_input_selection: CurrentSelection,
    limits: CurrentRequestLimits,
}

struct LocalCurrentRequest {
    request_id: Hex32,
    expected: RecoveryRequestExpected,
    limits: OrdinaryStartupBounds,
    issued: bool,
}

enum DecodedRecoveryRequest {
    Restore(RecoveryRequestV1),
    Legacy(LocalLegacyRequest),
    Current(LocalCurrentRequest),
}

struct LocalLegacyRequest {
    request_id: Hex32,
    expected: RecoveryRequestExpected,
    selection: LegacyInputSelection,
    limits: OrdinaryStartupBounds,
}

impl DecodedRecoveryRequest {
    fn purpose(&self) -> RecoveryRequestPurpose {
        match self {
            Self::Restore(request) => request.purpose,
            Self::Legacy(_) => RecoveryRequestPurpose::AdoptOrdinaryLegacy,
            Self::Current(_) => RecoveryRequestPurpose::ReconfirmCurrentBinding,
        }
    }
    fn expected(&self) -> &RecoveryRequestExpected {
        match self {
            Self::Restore(request) => &request.expected,
            Self::Legacy(request) => &request.expected,
            Self::Current(request) => &request.expected,
        }
    }
}

struct RecoveryRequestV1 {
    request_id: Hex32,
    purpose: RecoveryRequestPurpose,
    expected: RecoveryRequestExpected,
    selection: RestoreInputSelection,
    profile: super::RestoreOperationProfile,
}

fn decode_restore_request(
    raw: &[u8],
    limits: &TrustedHostRecoveryLimits,
) -> Result<DecodedRecoveryRequest, RecoveryControlError> {
    let wire: RecoveryRequestWire = serde_json::from_slice(raw).map_err(RecoveryControlError::from_json)?;
    let wire = match wire {
        RecoveryRequestWire::Restore(wire) => wire,
        RecoveryRequestWire::Current(wire) => {
            if wire.format_version != 1 || wire.purpose != RecoveryRequestPurpose::ReconfirmCurrentBinding
                || wire.limits.max_confirmations != 1
            { return Err(service_invalid()); }
            for value in [&wire.expected_deployment_id, &wire.expected_tenant_id] { super::id(value, limits.max_id_bytes)?; }
            return Ok(DecodedRecoveryRequest::Current(LocalCurrentRequest {
                request_id: wire.request_id,
                expected: RecoveryRequestExpected { reviewed_release_digest: wire.expected_reviewed_release_digest, deployment_id: wire.expected_deployment_id, tenant_id: wire.expected_tenant_id, dataset_id: wire.expected_dataset_id, source_installation_id: wire.expected_source_installation_id, target_installation_id: wire.expected_target_installation_id },
                limits: OrdinaryStartupBounds { effect_ns: wire.limits.effect_ns, convergence_ns: wire.limits.convergence_ns }, issued: false,
            }));
        }
        RecoveryRequestWire::Legacy(wire) => {
            if wire.format_version != 1 || wire.purpose != RecoveryRequestPurpose::AdoptOrdinaryLegacy || wire.expected_source_installation_id != wire.expected_target_installation_id { return Err(service_invalid()); }
            for value in [&wire.expected_deployment_id, &wire.expected_tenant_id] { super::id(value, limits.max_id_bytes)?; }
            let selection = &wire.trusted_input_selection.installation;
            service_absolute(&selection.parent)?;
            component(&selection.component, limits)?;
            if selection.parent.components().count() as u64 > limits.max_path_depth || selection.parent.as_os_str().len() as u64 > limits.max_relative_path_bytes { return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)); }
            return Ok(DecodedRecoveryRequest::Legacy(LocalLegacyRequest {
                request_id: wire.request_id,
                expected: RecoveryRequestExpected { reviewed_release_digest: wire.expected_reviewed_release_digest, deployment_id: wire.expected_deployment_id, tenant_id: wire.expected_tenant_id, dataset_id: wire.expected_dataset_id, source_installation_id: wire.expected_source_installation_id, target_installation_id: wire.expected_target_installation_id },
                selection: wire.trusted_input_selection, limits: wire.limits,
            }));
        }
    };
    if wire.format_version != 1
        || !matches!(
            wire.purpose,
            RecoveryRequestPurpose::RestoreSameInstallation
                | RecoveryRequestPurpose::RestoreNewInstallation
        )
    {
        return Err(service_invalid());
    }
    for value in [&wire.expected_deployment_id, &wire.expected_tenant_id] {
        super::id(value, limits.max_id_bytes)?;
    }
    hex(wire.expected_source_installation_id.as_str(), 64, true)?;
    hex(wire.expected_target_installation_id.as_str(), 64, true)?;
    let same = wire.expected_source_installation_id == wire.expected_target_installation_id;
    if same
        != matches!(
            wire.purpose,
            RecoveryRequestPurpose::RestoreSameInstallation
        )
    {
        return Err(service_invalid());
    }
    for selection in [
        &wire.trusted_input_selection.carrier,
        &wire.trusted_input_selection.key_medium,
        &wire.trusted_input_selection.target,
    ] {
        service_absolute(&selection.parent)?;
        component(&selection.component, limits)?;
        if selection.parent.components().count() as u64 > limits.max_path_depth
            || selection.parent.as_os_str().len() as u64 > limits.max_relative_path_bytes
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
    }
    Ok(DecodedRecoveryRequest::Restore(RecoveryRequestV1 {
        request_id: wire.request_id,
        purpose: wire.purpose,
        expected: RecoveryRequestExpected {
            reviewed_release_digest: wire.expected_reviewed_release_digest,
            deployment_id: wire.expected_deployment_id,
            tenant_id: wire.expected_tenant_id,
            dataset_id: wire.expected_dataset_id,
            source_installation_id: wire.expected_source_installation_id,
            target_installation_id: wire.expected_target_installation_id,
        },
        selection: wire.trusted_input_selection,
        profile: wire.profile,
    }))
}

/// Independent expected identities sealed by the one request parser.
pub struct RecoveryRequestExpected {
    reviewed_release_digest: Hex64,
    deployment_id: String,
    tenant_id: String,
    dataset_id: Hex32,
    source_installation_id: Hex64,
    target_installation_id: Hex64,
}

impl RecoveryRequestExpected {
    pub fn reviewed_release_digest(&self) -> &str {
        self.reviewed_release_digest.as_str()
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn dataset_id(&self) -> &str {
        self.dataset_id.as_str()
    }
    pub fn source_installation_id(&self) -> &str {
        self.source_installation_id.as_str()
    }
    pub fn target_installation_id(&self) -> &str {
        self.target_installation_id.as_str()
    }
}

/// Original live host evidence, never Deserialize/Clone or a supplied digest.
pub struct VerifiedRecoveryHost {
    admission_deadline: Option<Instant>,
    reviewed_release_digest: [u8; 32],
    limits: TrustedHostRecoveryLimits,
    uid: u32,
    #[cfg(feature = "desktop-local")]
    original: HostOrigin,
    #[cfg(not(feature = "desktop-local"))]
    _unavailable: std::convert::Infallible,
    ordinary_bounds: OrdinaryStartupBounds,
    services: [String; 2],
}

impl VerifiedRecoveryHost {
    pub(super) fn trusted_limits(&self) -> &TrustedHostRecoveryLimits { &self.limits }
    pub(super) fn admission_deadline(&self) -> Instant { self.admission_deadline.expect("verified original host deadline") }
    /// Consume the original executable and verified release handles. Request
    /// facts and the control identity are sealed later by the control owner.
    #[cfg(feature = "desktop-local")]
    pub fn from_local_release(
        program: (File, std::ffi::OsString, File),
        release: (File, std::ffi::OsString, File),
        actual: crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        reviewed_digest: [u8; 32],
        limits: TrustedHostRecoveryLimits,
        ordinary_bounds: OrdinaryStartupBounds,
        services: [&str; 2],
    ) -> Result<Self, RecoveryControlError> {
        let mut host = Self {
            admission_deadline: None,
            reviewed_release_digest: reviewed_digest,
            limits,
            uid: rustix::process::getuid().as_raw(),
            ordinary_bounds,
            services: services.map(str::to_owned),
            original: HostOrigin::LocalRelease {
                program,
                release,
                actual,
                identities: None,
                metadata: std::array::from_fn(|_| None),
                named: std::array::from_fn(|_| None),
            },
        };
        let result = (|| {
            let deadline = Instant::now()
                .checked_add(Duration::from_nanos(host.limits.admission_ns))
                .ok_or_else(service_invalid)?;
            host.admission_deadline = Some(deadline);
            host.limits.clone().checked()?;
            let (bytes, files) = host.retained_usage()?;
            if bytes > host.limits.max_metadata_bytes || files > host.limits.max_open_files {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
            host.recheck_original(deadline)
        })();
        match result {
            Ok(()) => Ok(host),
            Err(mut error) => {
                error.retained_host = Some(Box::new(host));
                Err(error)
            }
        }
    }

    pub(super) fn retained_usage(&self) -> Result<(u64, u64), RecoveryControlError> {
        #[cfg(not(feature = "desktop-local"))]
        { Err(service_invalid()) }
        #[cfg(feature = "desktop-local")]
        {
        let fixed = (std::mem::size_of::<Self>() as u64)
            .checked_add(self.services[0].capacity() as u64).and_then(|n| n.checked_add(self.services[1].capacity() as u64)).ok_or_else(service_invalid)?;
        match &self.original {
            #[cfg(feature = "desktop-local")]
            HostOrigin::LocalRelease {
                program,
                release,
                actual,
                ..
            } => {
                let bytes = fixed
                    .checked_add(program.1.capacity() as u64)
                    .and_then(|n| n.checked_add(release.1.capacity() as u64))
                    .and_then(|n| n.checked_add(actual.retained_path_bytes()))
                    .ok_or_else(|| {
                        RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                    })?;
                Ok((bytes, 4))
            }
        }
        }
    }

    fn recheck_original(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        before(deadline)?;
        if self.uid != rustix::process::getuid().as_raw()
            || self.uid != rustix::process::geteuid().as_raw()
        {
            return Err(service_invalid());
        }
        #[cfg(feature = "desktop-local")]
        match &mut self.original {
            #[cfg(feature = "desktop-local")]
            HostOrigin::LocalRelease {
                program,
                release,
                actual,
                identities,
                metadata,
                named,
            } => {
                for name in [&program.1, &release.1] {
                    component(name.to_str().ok_or_else(service_invalid)?, &self.limits)?;
                }
                service_absolute(actual.as_path())?;
                for (slot, file) in metadata
                    .iter_mut()
                    .zip([&program.0, &program.2, &release.0, &release.2])
                {
                    *slot = Some(file.metadata());
                    before(deadline)?;
                    if !matches!(slot, Some(Ok(_))) {
                        return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
                    }
                }
                let held = metadata.each_ref().map(|slot| {
                    slot.as_ref()
                        .and_then(|r| r.as_ref().ok())
                        .expect("checked original metadata")
                });
                if !held[0].is_dir()
                    || !held[1].is_file()
                    || held[1].nlink() != 1
                    || !held[2].is_dir()
                    || !held[3].is_dir()
                    || held.iter().any(|m| m.uid() != self.uid && m.uid() != 0)
                {
                    return Err(service_invalid());
                }
                let observed = held.map(identity);
                if identities
                    .as_ref()
                    .is_some_and(|previous| *previous != observed)
                {
                    return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
                }
                named[0] = Some(rustix::fs::statat(
                    &program.0,
                    &program.1,
                    AtFlags::SYMLINK_NOFOLLOW,
                ));
                before(deadline)?;
                named[1] = Some(rustix::fs::statat(
                    &release.0,
                    &release.1,
                    AtFlags::SYMLINK_NOFOLLOW,
                ));
                before(deadline)?;
                for (slot, index, kind) in [
                    (0, 1, rustix::fs::FileType::RegularFile),
                    (1, 3, rustix::fs::FileType::Directory),
                ] {
                    let n = named[slot]
                        .as_ref()
                        .and_then(|r| r.as_ref().ok())
                        .ok_or_else(|| {
                            RecoveryControlError::new(RecoveryControlFault::IoFailure)
                        })?;
                    let h = held[index];
                    if n.st_dev as u64 != h.dev()
                        || n.st_ino as u64 != h.ino()
                        || n.st_uid != h.uid()
                        || u32::from(n.st_mode) != h.mode()
                        || rustix::fs::FileType::from_raw_mode(n.st_mode) != kind
                    {
                        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
                    }
                }
                *identities = Some(observed);
                Ok(())
            }
        }
        #[cfg(not(feature = "desktop-local"))]
        { Err(service_invalid()) }
    }
}

/// Original private request, held with its named parent and actual identity.
pub struct OwnedRecoveryRequestFile {
    file: Option<File>,
    parent: File,
    component: String,
    identity: RecoveryFileIdentity,
}

pub(super) struct RequestOpenOwner {
    parent: Option<File>,
    component: std::ffi::OsString,
    file: Option<io::Result<File>>,
    metadata: Option<io::Result<Metadata>>,
    named: Option<rustix::io::Result<rustix::fs::Stat>>,
}

impl OwnedRecoveryRequestFile {
    pub(super) fn retained_usage(&self) -> Result<(u64, u64), RecoveryControlError> {
        if self.file.is_none() { return Err(service_invalid()); }
        let bytes = (std::mem::size_of::<Self>() as u64).checked_add(self.component.capacity() as u64)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        Ok((bytes, 2))
    }
    /// Retain one private request selected below the original host-owned parent.
    /// The caller accounts for these handles under its reviewed host limits before opening;
    /// bounded bytes, complete readback and the closed request are verified by `verify_intent`.
    pub fn from_held(
        parent: File,
        component: &std::ffi::OsStr,
        uid: u32,
    ) -> Result<Self, RecoveryControlError> {
        let mut original = RequestOpenOwner {
            parent: Some(parent),
            component: component.to_os_string(),
            file: None,
            metadata: None,
            named: None,
        };
        let result = (|| {
            let name = original.component.to_str().ok_or_else(service_invalid)?;
            if uid != rustix::process::getuid().as_raw()
                || rustix::process::geteuid().as_raw() != uid
                || name.is_empty()
                || matches!(name, "." | "..")
                || name.as_bytes().contains(&b'/')
                || name.as_bytes().contains(&0)
            {
                return Err(service_invalid());
            }
            original.metadata = Some(
                original
                    .parent
                    .as_ref()
                    .ok_or_else(service_invalid)?
                    .metadata(),
            );
            let parent_metadata = original
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if !parent_metadata.is_dir()
                || parent_metadata.uid() != uid
                || parent_metadata.mode() & 0o7777 != 0o700
            {
                return Err(service_invalid());
            }
            original.file = Some(
                rustix::fs::openat(
                    original.parent.as_ref().ok_or_else(service_invalid)?,
                    &original.component,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            let file = original
                .file
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            original.metadata = Some(file.metadata());
            let metadata = original
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            let stamp = ServiceFileStamp::of(metadata, uid)?;
            original.named = Some(rustix::fs::statat(
                original.parent.as_ref().ok_or_else(service_invalid)?,
                &original.component,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            let named = original
                .named
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if named.st_dev as u64 != stamp.identity.device
                || named.st_ino as u64 != stamp.identity.inode
                || named.st_uid != uid
                || named.st_mode & 0o7777 != 0o600
                || named.st_nlink != 1
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::RegularFile
            {
                return Err(service_invalid());
            }
            Ok(stamp.identity)
        })();
        match result {
            Ok(identity) => Ok(Self {
                file: Some(
                    original
                        .file
                        .take()
                        .expect("observed original open")
                        .expect("successful original open"),
                ),
                parent: original.parent.take().expect("original parent retained"),
                component: std::mem::take(&mut original.component)
                    .into_string()
                    .expect("checked UTF-8 component"),
                identity,
            }),
            Err(mut error) => {
                error.retained_request = Some(Box::new(original));
                Err(error)
            }
        }
    }
}

/// Once verified input. It does not itself perform or complete a restore.
pub struct VerifiedRecoveryHostIntent {
    pub(super) host: VerifiedRecoveryHost,
    request: OwnedRecoveryRequestFile,
    request_bytes: Vec<u8>,
    control_root: RecoveryFileIdentity,
    decoded: DecodedRecoveryRequest,
    original_deadline: Instant,
}

struct VerifiedRestoreHostIntent {
    host: VerifiedRecoveryHost,
    request: OwnedRecoveryRequestFile,
    request_bytes: Vec<u8>,
    control_root: RecoveryFileIdentity,
    decoded: RecoveryRequestV1,
    original_deadline: Instant,
}

impl VerifiedRecoveryHostIntent {
    /// Consume this original positive adoption request with its actual control owner.
    #[cfg(feature = "desktop-local")]
    pub fn into_ordinary_legacy_intent(self, control: &super::RecoveryControl, owners: &[super::runtime::RuntimeOwner]) -> Result<super::ordinary::VerifiedOrdinaryStartupIntent, RecoveryControlError> {
        local_legacy_intent(&control.shared, self, owners)
    }

    pub fn purpose(&self) -> RecoveryRequestPurpose {
        self.decoded.purpose()
    }
    pub fn restore_profile(&self) -> Option<&super::RestoreOperationProfile> {
        match &self.decoded { DecodedRecoveryRequest::Restore(request) => Some(&request.profile), DecodedRecoveryRequest::Legacy(_) | DecodedRecoveryRequest::Current(_) => None }
    }
    pub fn expected(&self) -> &RecoveryRequestExpected {
        self.decoded.expected()
    }
}

struct RestoreOperationOwner {
    intent: VerifiedRestoreHostIntent,
    operation: Hex32,
    epoch: Hex64,
    clock: super::clock::OperationClock,
    profile: super::RestoreOperationProfile,
    ledger: super::RestoreCapacityLedger,
    pending: Option<OwnedRecord>,
    pending_stage: Option<super::activation::JournalReference>,
    pending_closing: Option<RestoreClosingAllowance>,
    confirmed_stages: Vec<(super::RestoreStage, super::activation::JournalReference)>,
    candidate_plan: super::activation::CandidatePlan,
    candidate_plan_output: Option<OwnedRestoreCandidatePlan>,
}

struct RestoreClosingAllowance {
    metadata_paid: u64,
    metadata_left: u64,
    journal_reserved: u64,
    journal_written: Option<u64>,
}

struct RestoreClosingAccess<'a> {
    files: &'a mut ControlFiles,
}
impl Deref for RestoreClosingAccess<'_> {
    type Target = ControlFiles;
    fn deref(&self) -> &Self::Target { self.files }
}
impl DerefMut for RestoreClosingAccess<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.files }
}
impl Drop for RestoreClosingAccess<'_> {
    fn drop(&mut self) {
        let allowance = self.files.closing_observation.take();
        if let Some(operation) = &mut self.files.restore_operation {
            operation.pending_closing = allowance;
        }
        if std::thread::panicking() { self.files.latch(RecoveryControlFault::OwnerLost); }
    }
}

/// Owned copies of the original exclusion descriptors and finite profile DATA.
/// This projection is neither a candidate authority nor an isolation observation.
pub struct RestoreCandidateIsolationInput {
    parents: [File; 3],
    parent_paths: [PathBuf; 3],
    components: [std::ffi::OsString; 3],
    profile: super::RestoreOperationProfile,
    operation: Hex32,
    epoch: Hex64,
    generation: String,
}

impl RestoreCandidateIsolationInput {
    /// The original operation's checked finite profile, without a new ledger.
    pub fn profile(&self) -> &super::RestoreOperationProfile { &self.profile }
    /// Original Manager site, control root and key medium, in that order.
    pub fn excluded_locations(&self) -> [(&File, &Path, &std::ffi::OsStr); 3] {
        std::array::from_fn(|index| (&self.parents[index], self.parent_paths[index].as_path(), self.components[index].as_os_str()))
    }
    /// Original operation DATA; this identifier is not authority.
    pub fn operation_id(&self) -> &str { self.operation.as_str() }
    /// Original authorization epoch DATA, without a new clock or grant.
    pub fn authorization_epoch(&self) -> &str { self.epoch.as_str() }
    /// The original candidate generation DATA.
    pub fn generation_id(&self) -> &str { &self.generation }
}

struct RestoreCandidateIsolationWork {
    parents: [Option<io::Result<File>>; 3],
    parent_paths: [PathBuf; 3],
    components: [std::ffi::OsString; 3],
    profile: super::RestoreOperationProfile,
    operation: Hex32,
    epoch: Hex64,
    generation: String,
}

/// Fixed native slot observation DATA, never a slot/candidate/runtime proof.
#[derive(Clone, Copy)]
pub enum RestoreTargetSlotOutcome {
    /// Original exact readback matched under the issuer's constant-time comparison.
    ReadbackMatched,
    /// Original write result did not prove completion.
    WriteUnknown,
    /// Original readback result did not prove the expected value.
    ReadbackUnknown,
}
#[derive(Clone, Copy)]
pub(crate) enum TargetSlotKind { Master, Scram }
impl TargetSlotKind {
    fn index(self) -> usize { match self { Self::Master => 0, Self::Scram => 1 } }
    fn prefix(self) -> &'static str { match self { Self::Master => "desktop-vault-master-v1-", Self::Scram => "postgresql-17-" } }
    fn effect_id(self) -> &'static str { match self { Self::Master => "restore_master_slot", Self::Scram => "restore_scram_slot" } }
    fn exact_length(self) -> u64 { match self { Self::Master => 33, Self::Scram => 64 } }
}
struct RestoreTargetSlotJournal {
    intent: Option<RestoreStageIntent>,
    refs: Option<(String, String)>,
    matched: bool,
}

pub struct OwnedRestoreCandidatePlan {
    parent: File,
    parent_path: PathBuf,
    component: std::ffi::OsString,
    generation_id: Hex32,
    operation_id: Hex32,
    source_installation_id: Hex64,
    target_installation_id: Hex64,
}

impl OwnedRestoreCandidatePlan {
    pub fn parent(&self) -> &File {
        &self.parent
    }
    pub fn parent_path(&self) -> &Path {
        &self.parent_path
    }
    pub fn component(&self) -> &std::ffi::OsStr {
        &self.component
    }
    pub fn generation_id(&self) -> &str {
        self.generation_id.as_str()
    }
    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }
    pub fn source_installation_id(&self) -> &str {
        self.source_installation_id.as_str()
    }
    pub fn target_installation_id(&self) -> &str {
        self.target_installation_id.as_str()
    }
}

pub(crate) struct RestoreStages {
    owner: ControlOwner,
    operation: Hex32,
}

pub(crate) struct RestoreStageIntent {
    operation: Hex32,
    stage: super::RestoreStage,
    reference: super::activation::JournalReference,
}

impl RestoreStageIntent {
    pub(crate) fn reference(&self) -> &super::activation::JournalReference {
        &self.reference
    }
}

impl RestoreStages {
    pub(crate) fn check_capacity_before(&self, deadline: Instant) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            state.verify_restore_live(self.operation, deadline)?;
            state.observe_restore_capacity(deadline)
        })();
        result.map_err(|error: RecoveryControlError| { self.failure(error.fault()); error.retain(&self.owner) })
    }
    pub(crate) fn convergence_deadline(&self) -> Result<Instant, RecoveryControlError> {
        let mut state = lock(&self.owner)?;
        let deadline = state
            .restore_operation
            .as_ref()
            .ok_or_else(service_invalid)?
            .clock
            .convergence_deadline();
        state.restore_operation.as_ref().ok_or_else(service_invalid)?.clock.require_convergence()?;
        state.post_original_owner(deadline)?;
        Ok(deadline)
    }
    pub(crate) fn admit_capacity(
        &mut self,
        resource: super::RestoreCapacityResource,
        additional: u64,
    ) -> Result<super::RestoreCapacityReservation, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation.clock.require_effect()?;
            operation.ledger.admit(resource, additional)?;
            Ok(super::RestoreCapacityReservation {
                operation: self.operation,
                resource,
                admitted: additional,
            })
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn settle_capacity(
        &mut self,
        original: super::RestoreCapacityReservation,
        observed: u64,
    ) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            if original.operation != self.operation {
                return Err(service_invalid());
            }
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation
                .ledger
                .settle(original.resource, original.admitted, observed)?;
            operation.clock.require_convergence()
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn begin_stage_before(
        &mut self,
        stage: super::RestoreStage,
        effect_id: &str,
        deadline: Instant,
    ) -> Result<RestoreStageIntent, RecoveryControlError> {
        let result = (|| {
            let deadline = self.effect_before(deadline)?;
            let mut state = lock(&self.owner)?;
            super::id(effect_id, state.limits.max_id_bytes)?;
            if state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .pending_stage
                .is_some()
            {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ClosureUnproven,
                ));
            }
            let bytes = effect_id
                .len()
                .checked_mul(2)
                .and_then(|n| {
                    n.checked_add(
                        std::mem::size_of::<super::journal::JournalData>()
                            + 2 * std::mem::size_of::<super::activation::JournalReference>()
                            + 256,
                    )
                })
                .ok_or_else(service_invalid)?;
            state.prepay(bytes as u64, 0)?;
            let data = super::journal::JournalData::stage_intent(stage, effect_id);
            let frame_cap = state.limits.max_journal_frame_bytes.checked_add(44).ok_or_else(service_invalid)?;
            let metadata_paid = frame_cap.checked_mul(16)
                .and_then(|n| n.checked_add((2 * std::mem::size_of::<super::journal::JournalData>() + 512) as u64))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            state.prepay(metadata_paid, 0)?;
            let operation = state.restore_operation.as_mut().ok_or_else(service_invalid)?;
            operation.ledger.admit(super::RestoreCapacityResource::JournalBytes, frame_cap)?;
            operation.ledger.admit(super::RestoreCapacityResource::JournalRecords, 1)?;
            operation.pending_closing = Some(RestoreClosingAllowance { metadata_paid, metadata_left: metadata_paid, journal_reserved: frame_cap, journal_written: None });
            let reference = state.append_journal(&self.operation, &data, deadline)?;
            state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?
                .pending_stage = Some(reference.clone());
            Ok(RestoreStageIntent {
                operation: self.operation,
                stage,
                reference,
            })
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn observe_stage_before(
        &mut self,
        intent: RestoreStageIntent,
        disposition: super::RestoreDisposition,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            let operation = state.restore_operation.as_mut().ok_or_else(service_invalid)?;
            if intent.operation != self.operation || operation.pending_stage.as_ref() != Some(&intent.reference) {
                return Err(service_invalid());
            }
            let allowance = operation.pending_closing.take().ok_or_else(service_invalid)?;
            state.closing_observation = Some(allowance);
            let mut closing = RestoreClosingAccess { files: &mut state };
            closing.verify_restore_live(self.operation, deadline)?;
            let first_fault = closing.first_fault;
            let data = super::journal::JournalData::stage_observed(intent.reference.sequence, disposition);
            let confirmed = data.confirms_effect();
            let reference = closing.append_journal(&self.operation, &data, deadline)?;
            let allowance = closing.closing_observation.as_ref().ok_or_else(service_invalid)?;
            let reserved = allowance.journal_reserved;
            let written = allowance.journal_written.ok_or_else(service_invalid)?;
            let metadata_paid = allowance.metadata_paid;
            {
                let operation = closing.restore_operation.as_mut().ok_or_else(service_invalid)?;
                operation.ledger.settle_prepaid_observation(super::RestoreCapacityResource::JournalBytes, reserved, written)?;
                operation.ledger.settle_prepaid_observation(super::RestoreCapacityResource::JournalRecords, 1, 1)?;
                if confirmed {
                    if operation.confirmed_stages.len() as u64 >= operation.profile.capacity.max_journal_records {
                        return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
                    }
                    operation.confirmed_stages.try_reserve_exact(1).map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
                    operation.confirmed_stages.push((intent.stage, reference));
                    operation.pending_stage = None;
                }
            }
            // Only the completed serialization/frame/readback workspace retires.
            // The original failure and persistent evidence remain resident.
            drop(data);
            drop(intent);
            closing.budget.metadata = closing.budget.metadata.checked_sub(metadata_paid).ok_or_else(service_invalid)?;
            let operation = closing.restore_operation.as_mut().ok_or_else(service_invalid)?;
            let metadata = &mut operation.ledger.admitted[super::RestoreCapacityResource::MetadataBytes as usize];
            *metadata = metadata.checked_sub(metadata_paid).ok_or_else(service_invalid)?;
            closing.closing_observation = None;
            match (first_fault, confirmed) {
                (Some(fault), _) => Err(RecoveryControlError::new(fault)),
                (None, true) => Ok(()),
                (None, false) => Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven)),
            }
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn failure(&self, fault: RecoveryControlFault) -> RecoveryControlError {
        if let Ok(mut state) = lock(&self.owner) {
            state.latch(fault);
        }
        RecoveryControlError::with_owner(fault, &self.owner)
    }

    pub(crate) fn original_native_clock(
        &self,
    ) -> Result<(u32, u64, u64, u64), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.operation, deadline)?;
            let raw = state
                .original_process_evidence
                .as_ref()
                .ok_or_else(service_invalid)?;
            let pid = u32::from_be_bytes(
                raw[..4]
                    .try_into()
                    .expect("original fixed process evidence"),
            );
            let (t0, effect, convergence) = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .observations();
            Ok((pid, t0, effect, convergence))
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn effect_before(&self, deadline: Instant) -> Result<Instant, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.owner)?;
            state.verify_restore_live(self.operation, deadline)?;
            state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .effect_before(deadline)
        })();
        result.map_err(|error: RecoveryControlError| {
            self.failure(error.fault());
            error.retain(&self.owner)
        })
    }

    pub(crate) fn capacity_available(
        &self,
        resource: super::RestoreCapacityResource,
    ) -> Result<u64, RecoveryControlError> {
        let state = lock(&self.owner)?;
        let ledger = &state
            .restore_operation
            .as_ref()
            .ok_or_else(service_invalid)?
            .ledger;
        ledger
            .ceiling(resource)
            .checked_sub(ledger.admitted[resource as usize])
            .ok_or_else(|| {
                RecoveryControlError::with_owner(
                    RecoveryControlFault::CapacityExceeded,
                    &self.owner,
                )
            })
    }
}

#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl crate::backup::whole_pg_capture_stream::CaptureClockCheck for RestoreStages {
    fn require_effect(
        &self,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        self.effect_remaining_ns().map(|_| ())
    }
    fn require_closing(
        &self,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        self.closing_remaining_ns().map(|_| ())
    }
    fn effect_remaining_ns(
        &self,
    ) -> Result<u64, openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        let (_, _, effect, _) = self.original_native_clock().map_err(|_| {
            openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::ClockUnavailable
        })?;
        effect
            .checked_sub(self.observed_ns()?)
            .filter(|n| *n > 0)
            .ok_or(openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::DeadlineExpired)
    }
    fn closing_remaining_ns(
        &self,
    ) -> Result<u64, openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        let (_, _, _, convergence) = self.original_native_clock().map_err(|_| {
            openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::ClockUnavailable
        })?;
        convergence
            .checked_sub(self.observed_ns()?)
            .filter(|n| *n > 0)
            .ok_or(openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::DeadlineExpired)
    }
    fn observed_ns(
        &self,
    ) -> Result<u64, openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        let mut state = lock(&self.owner).map_err(|_| {
            openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::ClockUnavailable
        })?;
        let deadline = state
            .restore_operation
            .as_ref()
            .ok_or(openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::ClockUnavailable)?
            .clock
            .convergence_deadline();
        state
            .verify_restore_live(self.operation, deadline)
            .map_err(|_| {
                openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::ClockUnavailable
            })?;
        Ok(state.process_monotonic_ns)
    }
}

pub(super) fn claim_restore(
    owner: &ControlOwner,
    entry: VerifiedRecoveryHostIntent,
    profile: super::RestoreOperationProfile,
) -> Result<RestoreControlSession, RecoveryControlError> {
    let mut incoming = Some(entry);
    let result = (|| {
        let mut state = lock(owner)?;
        if state.restore_operation.is_some() || state.pending_restore_intent.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        state.pending_restore_intent = Some(match incoming.take().expect("original entry retained") {
            VerifiedRecoveryHostIntent { host, request, request_bytes, control_root, decoded: DecodedRecoveryRequest::Restore(decoded), original_deadline } => VerifiedRestoreHostIntent { host, request, request_bytes, control_root, decoded, original_deadline },
            other => { incoming = Some(other); return Err(service_invalid()); }
        });
        let original = state
            .pending_restore_intent
            .as_ref()
            .ok_or_else(service_invalid)?;
        let deadline = original.original_deadline;
        if profile != original.decoded.profile {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ProfileInvalid,
            ));
        }
        let profile = profile.checked(&state.limits)?;
        state.acquire_writer_before(deadline)?;
        let admission = (|| {
            let expected_root = state
                .pending_restore_intent
                .as_ref()
                .ok_or_else(service_invalid)?
                .control_root;
            if state.root_identity(deadline)? != expected_root {
                return Err(service_invalid());
            }
            state
                .pending_restore_intent
                .as_mut()
                .ok_or_else(service_invalid)?
                .host
                .recheck_original(deadline)?;
            let head = state.read_head_before(deadline)?;
            if matches!(head, Head::Unpublished) {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            let control = match &head {
                Head::Published(published) => Some(published.control_id()),
                _ => None,
            };
            state.verify_closed_runtime_receipts(control, deadline)?;
            // The request ID selects only the original no-replace operation.
            // Any existing object, including an incomplete one, denies replay.
            let operation = state
                .pending_restore_intent
                .as_ref()
                .ok_or_else(service_invalid)?
                .decoded
                .request_id;
            state.reserve_io(0)?;
            state.raw.named = Some(rustix::fs::statat(
                state.directory(Directory::Operations)?,
                operation.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            state.post(deadline)?;
            match state.raw.named.as_ref() {
                Some(Err(rustix::io::Errno::NOENT)) => (),
                Some(Ok(_)) => {
                    return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
                }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            }
            let maximum = state.limits.max_retained_operations;
            let count = state.inventory_count(Directory::Operations, maximum, None, deadline)?;
            if count >= state.limits.max_retained_operations {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
            Ok((head, operation))
        })();
        let (head, operation) = match admission {
            Ok(value) => value,
            Err(error) => {
                state.release_writer();
                return Err(error);
            }
        };
        // All admission/old-runtime Busy checks precede operation/epoch minting.
        let request_length = state
            .pending_restore_intent
            .as_ref()
            .ok_or_else(service_invalid)?
            .request_bytes
            .len();
        let claim_metadata = request_length
            .checked_mul(32)
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<RestoreOperationOwner>()
                        + std::mem::size_of::<RestoreControlSession>(),
                )
            })
            .ok_or_else(service_invalid)?;
        state.prepay(claim_metadata as u64, 0)?;
        let selections = &state
            .pending_restore_intent
            .as_ref()
            .ok_or_else(service_invalid)?
            .decoded
            .selection;
        let selection_paths = [
            (
                selections.carrier.parent.clone(),
                selections.carrier.component.clone(),
                Some(profile.capacity.max_input_wire_bytes),
            ),
            (
                selections.key_medium.parent.clone(),
                selections.key_medium.component.clone(),
                Some(104),
            ),
            (
                selections.target.parent.clone(),
                selections.target.component.clone(),
                None,
            ),
        ];
        for (slot, (parent, component, limit)) in selection_paths.iter().enumerate() {
            state.open_restore_selection(slot, parent, component, *limit, deadline)?;
        }
        let carrier_parent = state.restore_selections[0].as_ref()
            .and_then(|selection| selection.ancestors.last()).ok_or_else(service_invalid)?.identity;
        let key_parent = state.restore_selections[1].as_ref()
            .and_then(|selection| selection.ancestors.last()).ok_or_else(service_invalid)?.identity;
        if carrier_parent.device == key_parent.device && carrier_parent.inode == key_parent.inode {
            return Err(RecoveryControlError::new(RecoveryControlFault::InputInvalid));
        }
        state.raw_random = Some(getrandom::fill(&mut state.restore_entropy));
        state.post(deadline)?;
        if !matches!(state.raw_random, Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        let control = match &head {
            Head::Published(published) => Hex32::parse(published.control_id())?,
            _ => Hex32::mint(&state.restore_entropy[..16])?,
        };
        let nonce = Hex32::mint(&state.restore_entropy[16..32])?;
        let epoch = Hex64::mint(&state.restore_entropy[32..64])?;
        let generation = Hex32::mint(&state.restore_entropy[64..80])?;
        state.pending_restore_clock = Some(super::clock::OperationClock::start(
            profile.effect_ns,
            profile.convergence_ns,
        )?);
        let clock = state
            .pending_restore_clock
            .as_ref()
            .ok_or_else(service_invalid)?;
        let effect = clock.effect_before(deadline)?;
        let (t0_ns, effect_deadline_ns, convergence_deadline_ns) = clock.observations();
        let (boot_identity, pid, process_start) = state.process_record()?;
        let owner_clock = super::journal::OwnerClockRecord {
            clock_kind: "CLOCK_MONOTONIC".to_owned(),
            boot_identity,
            pid,
            process_start,
            owner_nonce: nonce.as_str().to_owned(),
            t0_ns,
            effect_deadline_ns,
            convergence_deadline_ns,
        };
        let original = state
            .pending_restore_intent
            .as_ref()
            .ok_or_else(service_invalid)?;
        let expected = &original.decoded.expected;
        let target = state.restore_selections[2]
            .as_ref()
            .ok_or_else(service_invalid)?;
        let parent = target.ancestors.last().ok_or_else(service_invalid)?;
        let candidate_plan = super::activation::CandidatePlan::local(
            parent.identity,
            target.component.clone(),
            expected.target_installation_id.as_str().to_owned(),
            generation.as_str().to_owned(),
        );
        let carrier = state.restore_selections[0]
            .as_ref()
            .and_then(|s| s.stamp)
            .ok_or_else(service_invalid)?;
        let key = state.restore_selections[1]
            .as_ref()
            .and_then(|s| s.stamp)
            .ok_or_else(service_invalid)?;
        let input = super::journal::InputIdentities {
            carrier: super::journal::FileInput {
                file: carrier.identity,
                length: carrier.length,
            },
            key_medium: super::journal::FileInput {
                file: key.identity,
                length: key.length,
            },
        };
        let first = super::journal::JournalData::restore(super::journal::RestoreIntent {
            profile: profile.clone(),
            input_identities: input.clone(),
            business: super::journal::Business {
                deployment_id: expected.deployment_id.clone(),
                tenant_id: expected.tenant_id.clone(),
                dataset_id: expected.dataset_id.as_str().to_owned(),
            },
            source_installation_id: expected.source_installation_id.as_str().to_owned(),
            target_installation_id: expected.target_installation_id.as_str().to_owned(),
            candidate_plan: candidate_plan.clone(),
            owner_clock: owner_clock.clone(),
        });
        let profile_bytes =
            serde_json::to_vec(&profile).map_err(RecoveryControlError::from_json)?;
        let input_bytes = serde_json::to_vec(&input).map_err(RecoveryControlError::from_json)?;
        let profile_digest = Hex64::of(&Sha256::digest(&profile_bytes).into());
        let input_digest = Hex64::of(&Sha256::digest(&input_bytes).into());
        let mut ledger = super::RestoreCapacityLedger::new(profile.capacity.clone());
        ledger.admit(
            super::RestoreCapacityResource::MetadataBytes,
            state.budget.metadata,
        )?;
        ledger.admit(
            super::RestoreCapacityResource::OpenFiles,
            state.budget.files,
        )?;
        // The candidate gets a linear duplicate of the already verified parent,
        // never a caller path reopened as authority.
        ledger.admit(super::RestoreCapacityResource::OpenFiles, 1)?;
        state.reserve_io(1)?;
        state.raw.file = Some(
            state.restore_selections[2]
                .as_ref()
                .and_then(|s| s.ancestors.last())
                .ok_or_else(service_invalid)?
                .file
                .try_clone(),
        );
        state.post(effect)?;
        let parent = state.take_opened()?;
        let original = state
            .pending_restore_intent
            .take()
            .ok_or_else(service_invalid)?;
        let candidate_plan_output = OwnedRestoreCandidatePlan {
            parent,
            parent_path: original.decoded.selection.target.parent.clone(),
            component: std::ffi::OsString::from(&original.decoded.selection.target.component),
            generation_id: generation,
            operation_id: operation,
            source_installation_id: original.decoded.expected.source_installation_id,
            target_installation_id: original.decoded.expected.target_installation_id,
        };
        state.restore_operation = Some(RestoreOperationOwner {
            intent: original,
            operation,
            epoch,
            clock: state
                .pending_restore_clock
                .take()
                .ok_or_else(service_invalid)?,
            profile,
            ledger,
            pending: None,
            pending_stage: None,
            pending_closing: None,
            confirmed_stages: Vec::new(),
            candidate_plan: candidate_plan.clone(),
            candidate_plan_output: Some(candidate_plan_output),
        });
        state.observe_restore_capacity(effect)?;
        state.begin_journal(&operation, &control, epoch.as_str(), effect)?;
        let reference = state.append_journal(&operation, &first, effect)?;
        let pending = super::activation::Pending {
            operation_id: operation.as_str().to_owned(),
            epoch: epoch.as_str().to_owned(),
            profile_digest: profile_digest.as_str().to_owned(),
            prior_binding: match &head {
                Head::Published(published) => {
                    super::RequiredNullable::Value(published.binding().clone())
                }
                _ => super::RequiredNullable::Null(()),
            },
            candidate_plan,
            input_plan_digest: input_digest.as_str().to_owned(),
            owner_clock,
            journal_prefix: reference,
        };
        let record = match &head {
            Head::Published(published) => published.observation().record.successor(
                published.digest(),
                super::activation::ActivationPhase::RestorePending,
                super::activation::ActivationPayload::Pending(pending),
            )?,
            _ => super::activation::ActivationRecord::first_pending(control.as_str(), pending),
        };
        let published = state.publish_activation(&record, effect)?;
        state
            .restore_operation
            .as_mut()
            .ok_or_else(service_invalid)?
            .pending = Some(published);
        state.observe_restore_capacity(effect)?;
        Ok(RestoreControlSession {
            stages: RestoreStages {
                owner: Arc::clone(owner),
                operation,
            },
            candidate: None,
            isolation_intent: None,
            target_slots: [None, None],
            generation_root: None,
        })
    })();
    result.map_err(|mut error: RecoveryControlError| {
        error.retained_restore_intent = incoming.map(Box::new);
        if error.fault() != RecoveryControlFault::OwnerBusy {
            if let Ok(mut state) = lock(owner) {
                state.latch(error.fault());
            }
        }
        error.retain(owner)
    })
}

#[cfg(feature = "desktop-local")]
pub(super) fn observe_unclaimed_restore(owner: &ControlOwner) -> Result<ReadOnlyRestoreOwner, RecoveryControlError> {
    let original = {
        let mut state = lock(owner)?;
        if state.restore_operation.is_some() { return Err(service_invalid()); }
        state.pending_restore_intent.take().ok_or_else(service_invalid)?
    };
    let VerifiedRestoreHostIntent { host, request, request_bytes, control_root, decoded, original_deadline } = original;
    ReadOnlyRestoreOwner::from_original(Arc::clone(owner), VerifiedRecoveryHostIntent {
        host, request, request_bytes, control_root,
        decoded: DecodedRecoveryRequest::Restore(decoded), original_deadline,
    }, original_deadline)
}

/// Bounded same-operation reader after the original restore owner has gone.
/// It carries no effect clock, stages, candidate or execution API.
pub struct ReadOnlyRestoreOwner {
    owner: ControlOwner,
    intent: Option<VerifiedRecoveryHostIntent>,
    operation: Hex32,
    deadline: Instant,
    observation: Option<RestoreOriginalObservation>,
}

/// Observed descriptor/journal DATA, never a publication or runtime grant.
pub struct RestoreOriginalObservation {
    operation: Hex32,
    epoch: String,
    control_id: String,
    phase: super::ActivationPhase,
}
impl RestoreOriginalObservation {
    /// The existing operation, selected by the original authenticated request.
    pub fn operation_id(&self) -> &str { self.operation.as_str() }
    /// The old journal epoch, observed without minting or restoring a clock.
    pub fn epoch(&self) -> &str { &self.epoch }
    /// The existing external control identity.
    pub fn control_id(&self) -> &str { &self.control_id }
    /// The observed descriptor phase; it does not authorize that phase's effects.
    pub fn phase(&self) -> super::ActivationPhase { self.phase }
}
impl Drop for ReadOnlyRestoreOwner {
    fn drop(&mut self) { if let Ok(mut state) = lock(&self.owner) { state.release_writer(); } }
}
#[cfg(feature = "desktop-local")]
impl ReadOnlyRestoreOwner {
    pub(super) fn from_original(owner: ControlOwner, intent: VerifiedRecoveryHostIntent, deadline: Instant) -> Result<Self, RecoveryControlError> {
        let operation = match &intent.decoded {
            DecodedRecoveryRequest::Restore(request) => request.request_id,
            _ => { let mut error = service_invalid(); error.retained_restore_intent = Some(Box::new(intent)); return Err(error.retain(&owner)); }
        };
        let mut reader = Self { owner, operation, deadline: deadline.min(intent.original_deadline), intent: Some(intent), observation: None };
        let result: Result<(), RecoveryControlError> = (|| {
            let mut state = lock(&reader.owner)?;
            let wrapper = std::mem::size_of::<ReadOnlyRestoreOwner>().checked_sub(std::mem::size_of::<VerifiedRecoveryHostIntent>()).ok_or_else(service_invalid)?;
            state.prepay(wrapper as u64, 0)?;
            state.acquire_writer_before(reader.deadline)?;
            Ok(())
        })();
        if let Err(mut error) = result {
            error.retained_restore_intent = reader.intent.take().map(Box::new);
            return Err(error.retain(&reader.owner));
        }
        // A complete read is required before an observer is exposed.
        reader.observe_original()?;
        Ok(reader)
    }

    /// Re-read within this same host admission period; never renew E/C or the read period.
    pub fn observe_original(&mut self) -> Result<&RestoreOriginalObservation, RecoveryControlError> {
        let result: Result<RestoreOriginalObservation, RecoveryControlError> = (|| {
            let mut state = lock(&self.owner)?;
            state.post(self.deadline)?;
            let intent = self.intent.as_mut().ok_or_else(service_invalid)?;
            recheck_legacy_request_before(&mut state, intent, self.deadline)?;
            if !state.holds_writer() || state.root_identity(self.deadline)? != intent.control_root { return Err(service_invalid()); }
            for index in 0..3 {
                let (file, name) = match index {
                    0 => (state.pending_owner.take(), "owner.lock"),
                    1 => (state.pending_admission.take(), "admission.lock"),
                    _ => (state.pending_runtime.take(), "runtime.lock"),
                };
                let file = file.ok_or_else(service_invalid)?;
                let checked = state.verify_held_lock(&file, name, self.deadline);
                match index { 0 => state.pending_owner = Some(file), 1 => state.pending_admission = Some(file), _ => state.pending_runtime = Some(file) }
                checked?;
            }
            state.read_original_restore_before(self.operation, self.deadline)
        })();
        match result {
            Ok(observation) => { self.observation = Some(observation); Ok(self.observation.as_ref().expect("observed original data")) }
            Err(mut error) => {
                error.retained_restore_intent = self.intent.take().map(Box::new);
                Err(error.retain(&self.owner))
            },
        }
    }
}

/// One original restore operation. Its clock, input and journal stay in the
/// same control owner; the candidate has separate mutable custody.
pub struct RestoreControlSession {
    stages: RestoreStages,
    candidate: Option<PendingRestoreCandidateAuthority>,
    isolation_intent: Option<RestoreStageIntent>,
    target_slots: [Option<RestoreTargetSlotJournal>; 2],
    /// The held generation root's identity at bind; publication names it.
    generation_root: Option<RecoveryFileIdentity>,
}

/// The candidate stages borrow the session's stages and its separately held
/// candidate authority (spec revision R484 ¶8010, ¶8029–8041 and ¶8130).
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl RestoreControlSession {
    /// Observe original cumulative counters without a clock, admission or
    /// accounting mutation. Unknown work keeps its original admitted charge.
    pub fn capacity_observation(&self, resource: super::RestoreCapacityResource) -> Result<super::RestoreCapacityObservation, RecoveryControlError> {
        let state = lock(&self.stages.owner)?;
        let ledger = &state.restore_operation.as_ref().ok_or_else(service_invalid)?.ledger;
        Ok(super::RestoreCapacityObservation {
            limit: ledger.ceiling(resource), admitted: ledger.admitted[resource as usize], actual: ledger.actual[resource as usize],
        })
    }

    /// Bind the resident original candidate Child, held data directory and
    /// private UDS to this operation, then confirm the Isolation stage.
    pub async fn bind_candidate_before(
        &mut self,
        child_id: Option<u32>,
        program: crate::backup::whole_pg_restore_stream::CandidateProgramIdentity,
        socket_dir: &Path,
        staging: &crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if self.isolation_intent.is_none()
            || staging.candidate_plan().operation_id() != self.operation_id()
        {
            return self.retain_failure(Err(service_invalid()));
        }
        let source = &staging.manifest().claim().source;
        let secrets = staging.authenticated_secrets();
        self.bind_candidate_from_source_before(
            child_id,
            program,
            socket_dir,
            (source.system_identifier.clone(), source.database_oid),
            (secrets.postgres_scram(), secrets.historical_master()),
            staging.generation_root(),
            deadline,
        )
        .await
    }

    /// The same binding from the authenticated source identity and secrets.
    /// The production entry above takes them from the verified staging.
    pub(crate) async fn bind_candidate_from_source_before(
        &mut self,
        child_id: Option<u32>,
        program: crate::backup::whole_pg_restore_stream::CandidateProgramIdentity,
        socket_dir: &Path,
        (system_identifier, database_oid): (String, u32),
        (scram, master): (
            &openbot_domain::vault::SecretBytes,
            &openbot_domain::vault::SecretBytes,
        ),
        generation_root: &File,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let result = async {
            if self.candidate.is_some() {
                return Err(service_invalid());
            }
            let root = rustix::fs::fstat(generation_root)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            let binding = {
                let state = lock(&self.stages.owner)?;
                let operation = state
                    .restore_operation
                    .as_ref()
                    .ok_or_else(service_invalid)?;
                let expected = &operation.intent.decoded.expected;
                let profile = serde_json::to_vec(&operation.profile)
                    .map_err(RecoveryControlError::from_json)?;
                crate::backup::whole_pg_restore_stream::RestoreCandidateBinding {
                    operation_id: uuid::Uuid::from_bytes(super::hex_array(
                        operation.operation.as_str(),
                    )),
                    epoch: super::hex_array(operation.epoch.as_str()),
                    candidate_generation: uuid::Uuid::from_bytes(super::hex_array(
                        &operation.candidate_plan.generation_id,
                    )),
                    source_bundle_id: operation.intent.decoded.selection.expected_bundle_id.0,
                    deployment_id: expected.deployment_id.clone(),
                    tenant_id: expected.tenant_id.clone(),
                    dataset_id: expected.dataset_id.as_str().to_owned(),
                    source_installation_id: expected.source_installation_id.as_str().to_owned(),
                    target_installation_id: expected.target_installation_id.as_str().to_owned(),
                    candidate_database_oid: database_oid,
                    pg_system_identifier: system_identifier,
                    // The journal intent's profile digest (SHA-256 of the same bytes).
                    profile_binding: Sha256::digest(&profile).into(),
                    native_version: 0,
                    // Every retirement batch is one candidate transaction.
                    max_batches: operation.profile.capacity.max_pg_transactions,
                    max_requirements: operation.profile.capacity.max_reconfirm_requirements,
                }
            };
            let candidate = crate::backup::whole_pg_restore_stream::bind_candidate_before(
                &mut self.stages,
                child_id,
                program,
                socket_dir,
                binding,
                scram,
                master,
                deadline,
            )
            .await?;
            self.candidate = Some(candidate);
            self.generation_root = Some(RecoveryFileIdentity {
                device: root.st_dev as u64,
                inode: root.st_ino as u64,
                uid: root.st_uid,
            });
            if let Some(intent) = self.isolation_intent.take() {
                let observed_ns =
                    crate::backup::whole_pg_capture_stream::CaptureClockCheck::observed_ns(
                        &self.stages,
                    )
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
                let closing = self.stages.convergence_deadline()?;
                self.stages.observe_stage_before(
                    intent,
                    super::RestoreDisposition::TaskReturned {
                        original_task_id: "candidate_isolation".to_owned(),
                        observed_ns,
                    },
                    closing,
                )?;
            }
            Ok(())
        }
        .await;
        self.retain_failure(result)
    }

    /// Apply the registered increments a 52 or 53 source still needs, or
    /// observe a 54 source read-only, on the bound candidate.
    pub async fn upgrade_candidate_schema_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = crate::backup::whole_pg_restore_stream::upgrade_candidate_schema_before(
            &mut self.stages,
            candidate,
            deadline,
        )
        .await;
        self.retain_failure(result)
    }

    /// Retire the nine restored classes in bounded batches, enumerate the
    /// reconfirmation requirements and seal the cohort.
    pub async fn retire_cohort_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = crate::backup::whole_pg_restore_stream::retire_cohort_before(
            &mut self.stages,
            candidate,
            deadline,
        )
        .await;
        self.retain_failure(result)
    }

    /// Finish the restored closed history and its intents without completion.
    pub async fn clear_restored_closed_history_before(
        &mut self,
        request: crate::backup::whole_pg_restore_stream::RestoredClosedHistoryRequest,
    ) -> Result<
        crate::backup::whole_pg_restore_stream::RestoreClosedHistoryObservation,
        RecoveryControlError,
    > {
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = self
            .stages
            .clear_restored_closed_history_before(candidate, request)
            .await;
        self.retain_failure(result)
    }
}

/// The S23 SCRAM change, installation readback and the S24 publication
/// (spec revision R484 ¶8012–8025 and ¶8132–8134).
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
impl RestoreControlSession {
    /// Change the bound candidate's fixed administrator password to the new
    /// SCRAM secret already read back from its target slot (¶8021).
    pub async fn rotate_candidate_scram_before(
        &mut self,
        new_password: &openbot_domain::vault::SecretBytes,
        old_password: &openbot_domain::vault::SecretBytes,
        deadline: Instant,
    ) -> Result<crate::backup::whole_pg_restore_stream::RestoreScramAcknowledged, RecoveryControlError> {
        if !self.target_slots[TargetSlotKind::Scram.index()].as_ref().is_some_and(|slot| slot.matched) {
            return self.retain_failure(Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven)));
        }
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = crate::backup::whole_pg_restore_stream::rotate_candidate_scram_before(
            &mut self.stages, candidate, new_password, old_password, deadline,
        )
        .await;
        self.retain_failure(result)
    }

    /// Preserve the captured artifact identity and replace only its physical
    /// root on this isolated candidate, before any SCRAM change. An unresolved
    /// original transaction is observed read-only; it is never sent again
    /// (spec revision R484 ¶4054, ¶7280, ¶8002 and ¶8134).
    pub async fn restore_candidate_artifacts_before(
        &mut self,
        staging: &mut crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging,
        deadline: Instant,
    ) -> Result<crate::backup::whole_pg_restore_stream::RestoreArtifactRebindOutcome, RecoveryControlError> {
        let result = async {
            if staging.candidate_plan().operation_id() != self.operation_id() {
                return Err(service_invalid());
            }
            let candidate = self.candidate.as_mut().ok_or_else(service_invalid)?;
            if let Some(observed) = crate::backup::whole_pg_restore_stream::candidate_sql::prepare_artifact_binding_before(
                &mut self.stages, candidate, staging.artifact_source(), deadline,
            ).await? {
                return Ok(observed);
            }
            staging.place_artifact_spool_before(self, deadline)?;
            let candidate = self.candidate.as_mut().ok_or_else(service_invalid)?;
            crate::backup::whole_pg_restore_stream::candidate_sql::rebind_artifact_root_before(
                &mut self.stages, candidate, staging, deadline,
            ).await
        }.await;
        self.retain_failure(result)
    }

    #[cfg(test)]
    pub(crate) async fn verify_absent_artifacts_for_test(&mut self, deadline: Instant) {
        let candidate = self.candidate.as_mut().unwrap();
        let observed = crate::backup::whole_pg_restore_stream::candidate_sql::prepare_artifact_binding_before(
            &mut self.stages, candidate, None, deadline,
        ).await.unwrap();
        assert_eq!(observed, Some(crate::backup::whole_pg_restore_stream::RestoreArtifactRebindOutcome::Acknowledged));
    }

    /// Release the candidate's clients and pool before the Desktop owner's one
    /// original TERM (¶8132); publication then requires that closed pool.
    pub async fn release_candidate_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = crate::backup::whole_pg_restore_stream::release_candidate_before(&mut self.stages, candidate, deadline).await;
        self.retain_failure(result)
    }

    /// Retire only the original candidate's clients after a failed stage.
    /// This is cleanup, never a successful release or publication fact.
    pub fn abandon_candidate_connections(&mut self) {
        if let Some(candidate) = self.candidate.as_mut() {
            crate::backup::whole_pg_restore_stream::candidate_sql::abandon_candidate_connections(candidate);
        }
    }

    /// Read the installation back on a new connection with the historical
    /// master and the new password, both from their target slots (¶8019–8022).
    pub async fn verify_target_installation_before(
        &mut self,
        master: &openbot_domain::vault::SecretBytes,
        password: &openbot_domain::vault::SecretBytes,
        deadline: Instant,
    ) -> Result<crate::backup::whole_pg_restore_stream::RestoreInstallationReadbacks, RecoveryControlError> {
        if !self.target_slots[TargetSlotKind::Master.index()].as_ref().is_some_and(|slot| slot.matched) {
            return self.retain_failure(Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven)));
        }
        let Some(candidate) = self.candidate.as_mut() else {
            return self.retain_failure(Err(service_invalid()));
        };
        let result = crate::backup::whole_pg_restore_stream::verify_target_installation_before(
            &mut self.stages, candidate, master, password, deadline,
        )
        .await;
        self.retain_failure(result)
    }

    /// Publish SwitchedPending and then RestoreCurrent once every fact of
    /// ¶8132 is resident in this session: the bound candidate (only a verified
    /// staging binds it outside tests) with its schema, sealed retirement and
    /// closed-history ACK2, both target slots read back, the acknowledged SCRAM
    /// change and installation readbacks, the candidate's own exit with its
    /// drivers destroyed, and the final capacity check. Each descriptor is
    /// written by the original activation writer between its PublishIntent and
    /// PublishObserved; one whose observation is missing stays logically
    /// Pending and is never acknowledged later (¶8134).
    pub async fn publish_restore_current_before(
        &mut self,
        scram: crate::backup::whole_pg_restore_stream::RestoreScramAcknowledged,
        readbacks: crate::backup::whole_pg_restore_stream::RestoreInstallationReadbacks,
        exit: crate::backup::whole_pg_restore_stream::RestoreCandidateExit,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let result = async {
            let operation_uuid = uuid::Uuid::from_bytes(super::hex_array(self.stages.operation.as_str()));
            if scram.operation() != operation_uuid || readbacks.operation() != operation_uuid {
                return Err(service_invalid());
            }
            if !self.target_slots.iter().all(|slot| slot.as_ref().is_some_and(|slot| slot.matched)) {
                return Err(RecoveryControlError::new(RecoveryControlFault::ClosureUnproven));
            }
            let bound_root = self.generation_root.ok_or_else(service_invalid)?;
            let candidate = self.candidate.as_mut().ok_or_else(service_invalid)?;
            crate::backup::whole_pg_restore_stream::close_candidate_before(&mut self.stages, candidate, exit, deadline).await?;
            let closing = self.stages.convergence_deadline()?;
            self.stages.check_capacity_before(closing)?;
            let effect = self.stages.effect_before(deadline)?;
            let operation = self.stages.operation;
            let mut state = lock(&self.stages.owner)?;
            state.verify_restore_live(operation, effect)?;
            let limits = state.limits.clone();
            let frame_cap = limits.max_journal_frame_bytes.checked_add(44).ok_or_else(service_invalid)?;
            // Two descriptors, each encoded, written and read back, and four
            // journal frames with their serialization scratch; then the
            // binding's owned strings (bounded by the host ID limit).
            let fee = limits.max_activation_bytes.checked_mul(8)
                .and_then(|n| n.checked_add(frame_cap.checked_mul(64)?))
                .and_then(|n| n.checked_add(limits.max_id_bytes.checked_mul(32)?))
                .and_then(|n| n.checked_add(4 * std::mem::size_of::<super::activation::ActivationRecord>() as u64))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            state.prepay(fee, 0)?;
            {
                let ledger = &mut state.restore_operation.as_mut().ok_or_else(service_invalid)?.ledger;
                ledger.admit(super::RestoreCapacityResource::JournalBytes, frame_cap.checked_mul(4).ok_or_else(service_invalid)?)?;
                ledger.admit(super::RestoreCapacityResource::JournalRecords, 4)?;
            }
            // The selected generation root is observed under the held trusted
            // parent; its identity, never a path, enters the binding.
            let component = state.restore_operation.as_ref().ok_or_else(service_invalid)?.candidate_plan.entry_component.clone();
            state.reserve_io(0)?;
            state.raw.named = Some(rustix::fs::statat(
                &state.restore_selections[2].as_ref().and_then(|selection| selection.ancestors.last()).ok_or_else(service_invalid)?.file,
                component.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            state.post(effect)?;
            let root = match state.raw.named.as_ref() {
                Some(Ok(stat)) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() => RecoveryFileIdentity {
                    device: stat.st_dev as u64,
                    inode: stat.st_ino as u64,
                    uid: stat.st_uid,
                },
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            let owner = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let expected = &owner.intent.decoded.expected;
            let restored = readbacks.binding();
            let [target, deployment, tenant, dataset] = restored.ids();
            // The root observed now must be the one held at bind, not a
            // same-owner directory renamed into its place since.
            if root != bound_root
                || root.uid != owner.intent.control_root.uid
                || target != expected.target_installation_id.as_str()
                || deployment != expected.deployment_id
                || tenant != expected.tenant_id
                || dataset != expected.dataset_id.as_str()
            {
                return Err(service_invalid());
            }
            let key = |index: usize, kind: TargetSlotKind, key_id: String| super::activation::KeyReference {
                kind: match kind {
                    TargetSlotKind::Master => super::activation::KeyKind::HistoricalMaster,
                    TargetSlotKind::Scram => super::activation::KeyKind::PostgresScram,
                },
                reviewed_service: owner.intent.host.services[index].clone(),
                account: format!("{}{target}-r-{}", kind.prefix(), operation.as_str()),
                key_id,
                key_version: 1,
                target_installation_id: target.to_owned(),
                operation_id: operation.as_str().to_owned(),
            };
            let postgres_account = format!("{}{target}-r-{}", TargetSlotKind::Scram.prefix(), operation.as_str());
            let (native_version, migration_digest) = readbacks.schema();
            let binding = super::activation::ActivationBinding::restored(
                [dataset, deployment, tenant, expected.source_installation_id.as_str(), target].map(str::to_owned),
                owner.candidate_plan.generation_id.clone(),
                root,
                restored.postgres(),
                (native_version, migration_digest.to_owned()),
                owner.epoch.as_str().to_owned(),
                key(0, TargetSlotKind::Master, readbacks.key_id().to_owned()),
                key(1, TargetSlotKind::Scram, postgres_account),
            );
            binding.validate(&limits)?;
            // The closure evidence names the confirmed stage of each fact class
            // (the last one of a repeated class) and both target slots.
            let evidence: Vec<super::activation::JournalReference> = {
                use super::RestoreStage as S;
                let confirmed = &owner.confirmed_stages;
                [S::Import, S::Isolation, S::PgUpgrade, S::Retire, S::HqAck2, S::ScramChange, S::ResourceClose]
                    .into_iter()
                    .filter_map(|stage| confirmed.iter().rev().find(|(kind, _)| *kind == stage))
                    .chain(confirmed.iter().filter(|(kind, _)| *kind == S::KeySlot))
                    .map(|(_, reference)| reference.clone())
                    .collect()
            };
            let pending = owner.pending.as_ref().ok_or_else(service_invalid)?;
            let raw = pending.bytes.clone();
            state.prepay(super::activation::read_metadata_reservation(&raw)?, 0)?;
            let prior = super::activation::observe(&raw, &limits)?;
            let super::activation::ActivationPayload::Pending(pending) = prior.record.data() else {
                return Err(service_invalid());
            };
            if pending.operation_id != operation.as_str() {
                return Err(service_invalid());
            }
            let (profile_digest, epoch) = (pending.profile_digest.clone(), pending.epoch.clone());
            let switched = super::activation::Switched {
                operation_id: operation.as_str().to_owned(),
                epoch: epoch.clone(),
                profile_digest: profile_digest.clone(),
                binding: binding.clone(),
                closure_evidence: evidence.clone(),
                publish_intent: super::activation::JournalPositionRef { context_id: operation, sequence: state.next_journal_sequence()? },
            };
            let (switched, readback) = publish_restore_head(
                &mut state, operation, (&prior.record, &prior.digest),
                super::ActivationPhase::SwitchedPending,
                super::activation::ActivationPayload::Switched(switched), effect,
            )?;
            let current = super::activation::Current {
                operation_id: operation.as_str().to_owned(),
                epoch,
                profile_digest,
                binding,
                closure_evidence: evidence,
                switch_readback: readback,
                publish_intent: super::activation::JournalPositionRef { context_id: operation, sequence: state.next_journal_sequence()? },
            };
            publish_restore_head(
                &mut state, operation, (&switched.0, &switched.1),
                super::ActivationPhase::RestoreCurrent,
                super::activation::ActivationPayload::Current(current), effect,
            )?;
            state.observe_restore_capacity(effect)
        }
        .await;
        self.retain_failure(result)
    }
}

/// PublishIntent → the original activation writer → PublishObserved, in the
/// open restore operation's journal. A failed write or observation leaves the
/// intent without a PublishObserved, so no reader treats the head as published.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
fn publish_restore_head(
    state: &mut ControlFiles,
    operation: Hex32,
    (prior, prior_digest): (&super::activation::ActivationRecord, &str),
    phase: super::ActivationPhase,
    data: super::activation::ActivationPayload,
    effect: Instant,
) -> Result<((super::activation::ActivationRecord, String), super::activation::JournalReference), RecoveryControlError> {
    let next = prior.successor(prior_digest, phase, data)?;
    let (_, digest) = next.encoded()?;
    let intent = state.append_journal(&operation, &super::journal::JournalData::publish_intent(phase, &digest), effect)?;
    let published = state.publish_activation(&next, effect)?;
    let observed = state.append_journal(
        &operation,
        &super::journal::JournalData::publish_observed(intent.sequence, &digest, published.identity),
        effect,
    )?;
    state.restore_operation.as_mut().ok_or_else(service_invalid)?.pending = Some(published);
    Ok(((next, digest), observed))
}

impl Drop for RestoreControlSession {
    fn drop(&mut self) {
        let Some(candidate) = self.candidate.take() else {
            return;
        };
        let mut book = match self.stages.owner.lock() {
            Ok(book) => book,
            Err(poisoned) => {
                let mut book = poisoned.into_inner();
                book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
                book
            }
        };
        // There is one non-Clone session for this original operation. A
        // dropped caller cannot convert its still-owned candidate to closure.
        book.retained_candidate = Some(candidate);
    }
}

impl RestoreControlSession {
    /// Same original owner/E check before each native slot-store effect.
    pub fn check_restore_slot_effect_before(&mut self, deadline: Instant) -> Result<Instant, RecoveryControlError> { self.stages.effect_before(deadline) }
    /// Original C for observing already-entered native results, without renewal.
    pub fn restore_slot_convergence_deadline(&self) -> Result<Instant, RecoveryControlError> { self.stages.convergence_deadline() }
    /// Record the master's native result against its fixed intent/refs (matched33B).
    pub fn observe_restore_master_slot_before(&mut self, outcome: RestoreTargetSlotOutcome, deadline: Instant) -> Result<(), RecoveryControlError> { self.observe_target_slot_before(outcome, deadline, TargetSlotKind::Master) }
    /// Record the SCRAM native result against its fixed intent/refs (matched64B).
    pub fn observe_restore_scram_slot_before(&mut self, outcome: RestoreTargetSlotOutcome, deadline: Instant) -> Result<(), RecoveryControlError> { self.observe_target_slot_before(outcome, deadline, TargetSlotKind::Scram) }
    fn observe_target_slot_before(&mut self, outcome: RestoreTargetSlotOutcome, deadline: Instant, kind: TargetSlotKind) -> Result<(), RecoveryControlError> {
        let closing = self.stages.convergence_deadline()?.min(deadline);
        let slot = self.target_slots[kind.index()].as_mut().ok_or_else(service_invalid)?;
        let intent = slot.intent.take().ok_or_else(service_invalid)?;
        let (service_ref, account_ref) = slot.refs.take().ok_or_else(service_invalid)?;
        let intent_ref = intent.reference.clone();
        let disposition = match outcome {
            RestoreTargetSlotOutcome::ReadbackMatched => super::RestoreDisposition::OsStoreReadbackMatched { intent_ref, service_ref, account_ref, exact_length: kind.exact_length() },
            RestoreTargetSlotOutcome::WriteUnknown => super::RestoreDisposition::OsStoreWriteUnknown { intent_ref, service_ref, account_ref },
            RestoreTargetSlotOutcome::ReadbackUnknown => super::RestoreDisposition::OsStoreReadbackUnknown { intent_ref, service_ref, account_ref },
        };
        // Only a matched readback confirms the stage; it is the slot fact
        // the SCRAM change and the publication require.
        self.stages.observe_stage_before(intent, disposition, closing)?;
        self.target_slots[kind.index()].as_mut().ok_or_else(service_invalid)?.matched = true;
        Ok(())
    }

    /// Fixed historical-master service/account DATA and original E.
    #[cfg(feature = "server-runtime")]
    pub fn begin_restore_master_slot_before(&mut self, staging: &crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging, deadline: Instant) -> Result<(String, String, Instant), RecoveryControlError> { self.begin_target_slot_before(staging, deadline, TargetSlotKind::Master) }
    /// Fixed new-SCRAM service/account DATA and original E.
    #[cfg(feature = "server-runtime")]
    pub fn begin_restore_scram_slot_before(&mut self, staging: &crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging, deadline: Instant) -> Result<(String, String, Instant), RecoveryControlError> { self.begin_target_slot_before(staging, deadline, TargetSlotKind::Scram) }
    #[cfg(feature = "server-runtime")]
    fn begin_target_slot_before(&mut self, staging: &crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging, deadline: Instant, kind: TargetSlotKind) -> Result<(String, String, Instant), RecoveryControlError> {
        let matches = (|| {
            let state = lock(&self.stages.owner)?;
            let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let plan = staging.candidate_plan();
            if plan.operation_id() != self.operation_id() || plan.generation_id() != operation.candidate_plan.generation_id
                || plan.target_installation_id() != operation.intent.decoded.expected.target_installation_id.as_str() { return Err(service_invalid()); }
            Ok(())
        })();
        if let Err(error) = matches {
            return self.retain_failure(Err(error));
        }
        self.begin_target_slot_from_session_before(deadline, kind)
    }

    /// The same slot intent from this session's own claimed plan. The
    /// production entries above first match the verified staging to it.
    #[cfg(feature = "server-runtime")]
    pub(crate) fn begin_target_slot_from_session_before(&mut self, deadline: Instant, kind: TargetSlotKind) -> Result<(String, String, Instant), RecoveryControlError> {
        let result = (|| {
            let index = kind.index();
            if self.target_slots[index].is_some() { return Err(service_invalid()); }
            let effect = self.stages.effect_before(deadline)?;
            {
                let state = lock(&self.stages.owner)?;
                let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
                super::id(&operation.intent.host.services[index], state.limits.max_id_bytes)?;
                if (kind.prefix().len() + 64 + 3 + 32) as u64 > state.limits.max_id_bytes { return Err(service_invalid()); }
            }
            let intent = self.stages.begin_stage_before(super::RestoreStage::KeySlot, kind.effect_id(), effect)?;
            self.target_slots[index] = Some(RestoreTargetSlotJournal { intent: Some(intent), refs: None, matched: false });
            let mut state = lock(&self.stages.owner)?;
            let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let service_len = operation.intent.host.services[index].len();
            let account_len = kind.prefix().len() + 64 + 3 + 32;
            let prepaid = service_len.checked_add(account_len).and_then(|n| n.checked_mul(4))
                .and_then(|n| n.checked_add(std::mem::size_of::<(String, String, Instant)>())).ok_or_else(service_invalid)?;
            state.prepay(prepaid as u64, 0)?;
            let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let service = operation.intent.host.services[index].clone();
            let mut account = String::new();
            account.try_reserve_exact(account_len).map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            account.push_str(kind.prefix());
            account.push_str(operation.intent.decoded.expected.target_installation_id.as_str());
            account.push_str("-r-");
            account.push_str(self.operation_id());
            let service_reply = service.clone();
            let account_reply = account.clone();
            let observed = std::mem::size_of::<(String, String, Instant)>()
                .checked_add(service.capacity()).and_then(|n| n.checked_add(account.capacity()))
                .and_then(|n| n.checked_add(service_reply.capacity())).and_then(|n| n.checked_add(account_reply.capacity())).ok_or_else(service_invalid)?;
            self.target_slots[index].as_mut().expect("original slot intent retained").refs = Some((service, account));
            state.restore_operation.as_mut().ok_or_else(service_invalid)?.ledger.settle(super::RestoreCapacityResource::MetadataBytes, prepaid as u64, observed as u64)?;
            state.post(effect)?;
            Ok((service_reply, account_reply, effect))
        })();
        self.retain_failure(result)
    }

    /// Begin the original Isolation stage once before the first candidate write.
    /// The stage intent remains private; only original owned resource copies leave.
    #[cfg(feature = "server-runtime")]
    pub fn begin_candidate_isolation_before(
        &mut self,
        staging: &crate::backup::whole_pg_restore_stream::VerifiedWholePgRestoreStaging,
        deadline: Instant,
    ) -> Result<RestoreCandidateIsolationInput, RecoveryControlError> {
        let result = (|| {
            if self.isolation_intent.is_some() { return Err(service_invalid()); }
            let effect = self.stages.effect_before(deadline)?;
            {
                let state = lock(&self.stages.owner)?;
                let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
                if staging.candidate_plan().operation_id() != self.operation_id()
                    || staging.candidate_plan().generation_id() != operation.candidate_plan.generation_id
                    || state.restore_isolation_work.is_some()
                { return Err(service_invalid()); }
            }
            self.isolation_intent = Some(self.stages.begin_stage_before(
                super::RestoreStage::Isolation, "candidate_isolation", effect,
            )?);
            let mut state = lock(&self.stages.owner)?;
            state.verify_restore_live(self.stages.operation, effect)?;
            let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let key = &operation.intent.decoded.selection.key_medium;
            let parent = state.root_path.parent().ok_or_else(service_invalid)?;
            let app = state.app_component.as_ref().ok_or_else(service_invalid)?;
            let allocation = parent.as_os_str().len().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(key.parent.as_os_str().len()))
                .and_then(|bytes| bytes.checked_add(app.len()))
                .and_then(|bytes| bytes.checked_add(state.root_component.len()))
                .and_then(|bytes| bytes.checked_add(key.component.len()))
                .and_then(|bytes| bytes.checked_add(operation.candidate_plan.generation_id.len()))
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RestoreCandidateIsolationInput>()))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            state.prepay(allocation as u64, 3)?;
            let operation = state.restore_operation.as_ref().ok_or_else(service_invalid)?;
            let key = &operation.intent.decoded.selection.key_medium;
            let parent = state.root_path.parent().ok_or_else(service_invalid)?;
            state.restore_isolation_work = Some(RestoreCandidateIsolationWork {
                parents: std::array::from_fn(|_| None),
                parent_paths: [parent.to_owned(), parent.to_owned(), key.parent.clone()],
                components: [state.app_component.as_ref().ok_or_else(service_invalid)?.clone(), state.root_component.clone().into(), key.component.clone().into()],
                profile: operation.profile.clone(), operation: operation.operation, epoch: operation.epoch,
                generation: operation.candidate_plan.generation_id.clone(),
            });
            for index in 0..3 {
                let original = if index < 2 {
                    state.parent.as_ref().ok_or_else(service_invalid)?
                } else {
                    &state.restore_selections[1].as_ref().and_then(|selection| selection.ancestors.last()).ok_or_else(service_invalid)?.file
                };
                let copied = original.try_clone();
                state.restore_isolation_work.as_mut().expect("original projection retained").parents[index] = Some(copied);
                state.post(effect)?;
                if !matches!(state.restore_isolation_work.as_ref().and_then(|work| work.parents[index].as_ref()), Some(Ok(_))) {
                    return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
                }
            }
            let work = state.restore_isolation_work.as_ref().expect("original projection retained");
            let observed = work.parent_paths.iter().map(|path| path.capacity()).chain(work.components.iter().map(|component| component.capacity()))
                .try_fold(std::mem::size_of::<RestoreCandidateIsolationInput>(), |bytes, capacity| bytes.checked_add(capacity))
                .and_then(|bytes| bytes.checked_add(work.generation.capacity()))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            state.restore_operation.as_mut().ok_or_else(service_invalid)?.ledger.settle(
                super::RestoreCapacityResource::MetadataBytes, allocation as u64, observed as u64,
            )?;
            state.post(effect)?;
            let work = state.restore_isolation_work.take().expect("original projection retained");
            Ok(RestoreCandidateIsolationInput {
                parents: work.parents.map(|result| result.expect("original duplicate result").expect("checked original duplicate")),
                parent_paths: work.parent_paths, components: work.components,
                profile: work.profile, operation: work.operation, epoch: work.epoch, generation: work.generation,
            })
        })();
        self.retain_failure(result)
    }

    #[cfg(feature = "server-runtime")]
    pub(crate) fn input_stages(&mut self) -> &mut RestoreStages {
        &mut self.stages
    }

    /// Transfer the original held inputs once, with the same finite operation
    /// ledger and independent expectations. This does not authenticate a bundle.
    #[cfg(feature = "server-runtime")]
    pub fn frozen_input(
        &mut self,
    ) -> Result<
        (
            crate::backup::whole_pg_restore_stream::FrozenWholePgRestoreInput,
            crate::backup::whole_pg_restore_stream::ReviewedWholePgRestoreIntent,
        ),
        RecoveryControlError,
    > {
        use openbot_domain::backup::WholePgCarrierBounds;
        use openbot_domain::backup::whole_pg_carrier::WholePgManifestExpectation;
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            let operation = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?;
            let deadline = operation.clock.convergence_deadline();
            let effect = operation.clock.effect_before(deadline)?;
            state.verify_restore_live(self.stages.operation, effect)?;
            for slot in 0..2 {
                state.reserve_io(0)?;
                state.raw.metadata = Some(
                    state.restore_selections[slot]
                        .as_ref()
                        .and_then(|s| s.original.as_ref())
                        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::InputInvalid))?
                        .metadata(),
                );
                state.post(effect)?;
                let selection = state.restore_selections[slot]
                    .as_ref()
                    .ok_or_else(service_invalid)?;
                let original = selection.stamp.ok_or_else(service_invalid)?;
                let observed = ServiceFileStamp::of(
                    state
                        .raw
                        .metadata
                        .as_ref()
                        .and_then(|r| r.as_ref().ok())
                        .ok_or_else(service_invalid)?,
                    state.uid,
                ).map_err(|_| RecoveryControlError::new(RecoveryControlFault::InputInvalid))?;
                if original != observed {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::InputInvalid,
                    ));
                }
                state.raw.named = Some(rustix::fs::statat(
                    &selection.ancestors.last().ok_or_else(service_invalid)?.file,
                    selection.component.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ));
                state.post(effect)?;
                let named = state
                    .raw
                    .named
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(service_invalid)?;
                if named.st_dev as u64 != original.identity.device
                    || named.st_ino as u64 != original.identity.inode
                    || named.st_uid != original.identity.uid
                    || named.st_size as u64 != original.length
                    || named.st_nlink != 1
                    || named.st_mode & 0o7777 != 0o600
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::InputInvalid,
                    ));
                }
                state.restore_input_metadata[slot] = Some(
                    state
                        .raw
                        .metadata
                        .take()
                        .expect("original metadata retained")
                        .map_err(|_| service_invalid())?,
                );
            }
            let capacity = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .profile
                .capacity
                .clone();
            const FRAME_MAX: u64 = 4 * 1024 * 1024;
            let frame = capacity
                .max_manifest_bytes
                .min(FRAME_MAX)
                .max(capacity.max_single_material_bytes.min(FRAME_MAX))
                .max(84);
            let original = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?;
            let expected_strings = [
                &original.intent.decoded.expected.deployment_id,
                &original.intent.decoded.expected.tenant_id,
            ];
            let structures = std::mem::size_of::<
                crate::backup::whole_pg_restore_stream::FrozenWholePgRestoreInput,
            >()
            .checked_add(std::mem::size_of::<
                crate::backup::whole_pg_restore_stream::ReviewedWholePgRestoreIntent,
            >())
            .and_then(|n| {
                n.checked_add(
                    expected_strings
                        .iter()
                        .map(|s| s.len())
                        .sum::<usize>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|n| n.checked_add(2 * (32 + 64)))
            .ok_or_else(service_invalid)?;
            let buffer_ceiling = frame.checked_mul(2).ok_or_else(service_invalid)?;
            state.prepay(
                buffer_ceiling
                    .checked_add(structures as u64)
                    .ok_or_else(service_invalid)?,
                0,
            )?;
            state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?
                .ledger
                .admit(super::RestoreCapacityResource::SecretMemoryBytes, 104 + 96)?;
            state.restore_input_buffer = Some(zeroize::Zeroizing::new(Vec::new()));
            let buffer = state
                .restore_input_buffer
                .as_mut()
                .expect("prepaid original buffer");
            buffer
                .try_reserve_exact(usize::try_from(frame).map_err(|_| service_invalid())?)
                .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if buffer.capacity() as u64 > buffer_ceiling {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::CapacityExceeded,
                ));
            }
            let ledger = &state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .ledger;
            let metadata = ledger
                .ceiling(super::RestoreCapacityResource::MetadataBytes)
                .checked_sub(ledger.admitted[super::RestoreCapacityResource::MetadataBytes as usize])
                .ok_or_else(service_invalid)?;
            let bounds = WholePgCarrierBounds {
                max_material_files: capacity.max_material_files,
                max_directories: capacity.max_material_directories,
                max_path_bytes: capacity.max_path_bytes,
                max_path_depth: capacity.max_path_depth,
                max_single_plain_bytes: capacity
                    .max_single_material_bytes
                    .min(capacity.max_material_plain_bytes),
                max_material_plain_bytes: capacity.max_material_plain_bytes,
                max_manifest_bytes: capacity.max_manifest_bytes.min(FRAME_MAX),
                max_header_bytes: 80,
                max_data_chunks: (capacity.max_input_wire_bytes / 37)
                    .max(1)
                    .min(u64::from(u32::MAX - 1)),
                max_chunk_plain_bytes: capacity.max_single_material_bytes.min(FRAME_MAX),
                max_wire_bytes: capacity.max_input_wire_bytes,
                max_metadata_bytes: metadata,
                max_open_files: capacity.max_open_files,
                max_snapshot_bytes: capacity.max_material_plain_bytes,
                max_spool_bytes: capacity.max_spool_bytes,
                max_retained_prior_bytes: capacity.max_retained_prior_bytes,
                max_journal_bytes: capacity.max_journal_bytes,
                max_total_allocation_bytes: capacity.max_total_allocation_bytes,
                capacity_reserve_bytes: capacity.reserve_bytes,
                free_floor_bytes: capacity.free_floor_bytes,
                max_key_medium_allocation_bytes: capacity.max_key_medium_allocation_bytes,
                key_medium_reserve_bytes: capacity.key_medium_reserve_bytes,
                key_medium_free_floor_bytes: capacity.key_medium_free_floor_bytes,
            }
            .check()
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
            let original = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?;
            let selection = &original.intent.decoded.selection;
            let expected = WholePgManifestExpectation {
                bundle_id: *selection.expected_bundle_id.0.as_bytes(),
                source_operation_id: *selection.expected_source_operation_id.0.as_bytes(),
                manifest_sha256: super::hex_array(selection.expected_manifest_sha256.as_str()),
            };
            let independent = &original.intent.decoded.expected;
            let deployment = independent.deployment_id.clone();
            let tenant = independent.tenant_id.clone();
            let dataset = independent.dataset_id.as_str().to_owned();
            let source = independent.source_installation_id.as_str().to_owned();
            state.post(effect)?;
            let carrier = state.restore_selections[0]
                .as_mut()
                .expect("original carrier")
                .original
                .take()
                .expect("held original carrier");
            let key = state.restore_selections[1]
                .as_mut()
                .expect("original key medium")
                .original
                .take()
                .expect("held original key medium");
            state.restore_input = Some(
                crate::backup::whole_pg_restore_stream::input::from_original_held(
                    self.stages.operation,
                    (carrier, state.restore_input_metadata[0].take().expect("original carrier metadata")),
                    (key, state.restore_input_metadata[1].take().expect("original key metadata")),
                    bounds,
                    state
                        .restore_input_buffer
                        .take()
                        .expect("original prepaid buffer"),
                    expected,
                    (deployment, tenant, dataset, source),
                ),
            );
            state.post(effect)?;
            Ok(state
                .restore_input
                .take()
                .expect("complete original input retained"))
        })();
        self.retain_failure(result)
    }

    pub fn admit_new_child_before(&mut self, parent: &File, name: &std::ffi::OsStr, bytes: u64, kind: super::RestoreNewChildKind, deadline: Instant) -> Result<super::RestoreNewChildReservation, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            state.verify_restore_live(self.stages.operation, deadline)?;
            component(name.to_str().ok_or_else(service_invalid)?, &state.limits)?;
            let operation = state.restore_operation.as_mut().ok_or_else(service_invalid)?;
            operation.clock.require_effect()?;
            let ledger = &mut operation.ledger;
            ledger.observe_file(parent, false, deadline)?;
            let metadata = ledger.raw_metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            if !metadata.is_dir() || bytes == 0 { return Err(service_invalid()); }
            let parent = identity(metadata);
            let fee = name.len().checked_mul(2).and_then(|n| n.checked_add(std::mem::size_of::<super::RestoreNewChildReservation>() + 2 * std::mem::size_of::<super::RestoreInodeUse>())).ok_or_else(service_invalid)?;
            ledger.admit(super::RestoreCapacityResource::MetadataBytes, fee as u64)?;
            ledger.admit(super::RestoreCapacityResource::OpenFiles, 1)?;
            let old = ledger.inodes.capacity();
            let additional = old.checked_add(1).and_then(|n| n.checked_sub(ledger.inodes.len())).ok_or_else(service_invalid)?;
            ledger.inodes.try_reserve_exact(additional).map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if ledger.inodes.capacity().saturating_sub(old) > 2 { return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)); }
            let device = ledger.devices.iter_mut().find(|device| device.device == parent.device).ok_or_else(service_invalid)?;
            device.pending_new = device.pending_new.checked_add(bytes).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            ledger.check_storage()?;
            Ok(super::RestoreNewChildReservation { operation: self.stages.operation, parent, component: name.to_os_string(), bytes, kind })
        })();
        self.retain_failure(result)
    }

    pub fn settle_new_child_before(&mut self, original: super::RestoreNewChildReservation, parent: &File, child: &File, deadline: Instant) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            if original.operation != self.stages.operation { return Err(service_invalid()); }
            state.verify_restore_live(self.stages.operation, deadline)?;
            let uid = state.uid;
            let operation = state.restore_operation.as_mut().ok_or_else(service_invalid)?;
            let ledger = &mut operation.ledger;
            before(deadline)?;
            ledger.raw_metadata = Some(parent.metadata());
            operation.clock.require_convergence()?;
            if identity(ledger.raw_metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?) != original.parent { return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost)); }
            ledger.raw_metadata = Some(child.metadata());
            operation.clock.require_convergence()?;
            let metadata = ledger.raw_metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            let actual = identity(metadata);
            let allocated = metadata.blocks().checked_mul(512).ok_or_else(service_invalid)?;
            let valid_type = match original.kind {
                super::RestoreNewChildKind::Directory => metadata.is_dir() && metadata.mode() & 0o7777 == 0o700,
                super::RestoreNewChildKind::File => metadata.is_file() && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 1,
            };
            if !valid_type || actual.device != original.parent.device || actual.uid != uid || allocated > original.bytes { return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)); }
            ledger.raw_named = Some(rustix::fs::statat(parent, &original.component, AtFlags::SYMLINK_NOFOLLOW));
            operation.clock.require_convergence()?;
            let named = ledger.raw_named.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            if named.st_dev as u64 != actual.device || named.st_ino as u64 != actual.inode || named.st_uid != actual.uid || u32::from(named.st_mode) != metadata.mode() { return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost)); }
            let device = ledger.devices.iter_mut().find(|device| device.device == actual.device).ok_or_else(service_invalid)?;
            device.pending_new = device.pending_new.checked_sub(original.bytes).ok_or_else(service_invalid)?;
            let observed = ledger.observe_file(child, false, deadline);
            if observed.is_err() {
                if let Some(device) = ledger.devices.iter_mut().find(|device| device.device == actual.device) { device.pending_new = device.pending_new.checked_add(original.bytes).ok_or_else(service_invalid)?; }
            }
            observed?;
            operation.clock.require_convergence()
        })();
        self.retain_failure(result)
    }

    pub fn take_candidate_plan(
        &mut self,
    ) -> Result<OwnedRestoreCandidatePlan, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.stages.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation.clock.require_effect()?;
            operation
                .candidate_plan_output
                .take()
                .ok_or_else(service_invalid)
        })();
        self.retain_failure(result)
    }
    pub fn operation_id(&self) -> &str {
        self.stages.operation.as_str()
    }

    /// Observe the original live pid/t0/E/C after the native owner and its
    /// held locks have been rechecked. Serialized records cannot call this.
    pub fn original_native_clock(&mut self) -> Result<(u32, u64, u64, u64), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.stages.operation, deadline)?;
            let raw = state
                .original_process_evidence
                .as_ref()
                .ok_or_else(service_invalid)?;
            let pid = u32::from_be_bytes(
                raw[..4]
                    .try_into()
                    .expect("original fixed process evidence"),
            );
            let operation = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?;
            let (t0, effect, convergence) = operation.clock.observations();
            Ok((pid, t0, effect, convergence))
        })();
        self.retain_failure(result)
    }

    /// Check original ownership and actual retained storage under C. This is
    /// the runner's observation callback; it does not authorize another effect.
    pub fn check_capacity_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            state.verify_restore_live(self.stages.operation, deadline)?;
            state.observe_restore_capacity(deadline)
        })();
        self.retain_failure(result)
    }

    /// Admit explicit additional resources before their allocation or effect.
    pub fn admit_capacity(
        &mut self,
        resource: super::RestoreCapacityResource,
        additional: u64,
    ) -> Result<super::RestoreCapacityReservation, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.stages.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation.clock.require_effect()?;
            operation.ledger.admit(resource, additional)?;
            Ok(super::RestoreCapacityReservation {
                operation: self.stages.operation,
                resource,
                admitted: additional,
            })
        })();
        self.retain_failure(result)
    }

    /// Merge an actual post-effect observation. Unknown work leaves its
    /// reservation resident and never calls this with an invented zero.
    pub fn settle_capacity(
        &mut self,
        original: super::RestoreCapacityReservation,
        observed_additional: u64,
    ) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            if original.operation != self.stages.operation {
                return Err(service_invalid());
            }
            let deadline = state
                .restore_operation
                .as_ref()
                .ok_or_else(service_invalid)?
                .clock
                .convergence_deadline();
            state.verify_restore_live(self.stages.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation
                .ledger
                .settle(original.resource, original.admitted, observed_additional)?;
            operation.clock.require_convergence()
        })();
        self.retain_failure(result)
    }

    pub fn admit_storage_before(
        &mut self,
        file: &File,
        bytes: u64,
        kind: super::RestoreStorageKind,
        deadline: Instant,
    ) -> Result<super::RestoreStorageReservation, RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            state.verify_restore_live(self.stages.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation.clock.require_effect()?;
            let ledger = &mut operation.ledger;
            let key_medium = kind == super::RestoreStorageKind::KeyMedium;
            ledger.observe_file(file, key_medium, deadline)?;
            let metadata = ledger
                .raw_metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            let identity = identity(metadata);
            let allocated_before = metadata
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            ledger.admit_disk_growth(identity, bytes)?;
            Ok(super::RestoreStorageReservation {
                operation: self.stages.operation,
                identity,
                allocated_before,
                bytes,
                kind,
            })
        })();
        self.retain_failure(result)
    }

    pub fn settle_storage_before(
        &mut self,
        original: super::RestoreStorageReservation,
        file: &File,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let result = (|| {
            let mut state = lock(&self.stages.owner)?;
            if original.operation != self.stages.operation {
                return Err(service_invalid());
            }
            state.verify_restore_live(self.stages.operation, deadline)?;
            let operation = state
                .restore_operation
                .as_mut()
                .ok_or_else(service_invalid)?;
            operation
                .ledger
                .settle_disk_growth(original, file, deadline)?;
            operation.clock.require_convergence()
        })();
        self.retain_failure(result)
    }

    fn retain_failure<T>(
        &self,
        result: Result<T, RecoveryControlError>,
    ) -> Result<T, RecoveryControlError> {
        result.map_err(|error| {
            if let Ok(mut state) = lock(&self.stages.owner) {
                state.latch(error.fault());
            }
            error.retain(&self.stages.owner)
        })
    }
}

/// A verified published head with this process's enrollment input; only an
/// ordinary startup branch builds it, after its own head read.
pub(super) struct RuntimeEntry {
    pub(super) published: PublishedActivation,
    pub(super) control_root: RecoveryFileIdentity,
    pub(super) runtime_nonce: String,
    pub(super) original_deadline: Instant,
    pub(super) enrollment: super::runtime::OriginalRuntimeEnrollment,
}

pub(super) struct OwnedRecord {
    pub(super) file: File,
    pub(super) identity: RecoveryFileIdentity,
    pub(super) bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreRuntimeLocks {
    control_root: RecoveryFileIdentity,
    admission_lock: RecoveryFileIdentity,
    runtime_lock: RecoveryFileIdentity,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreRuntimeEnrollment {
    record_type: String,
    version: u32,
    control_id: Hex32,
    nonce: Hex32,
    boot_identity: String,
    pid: u32,
    process_start: super::journal::ProcessStart,
    activation_digest: Hex64,
    authorization_epoch: Hex64,
    business_install_binding: super::activation::ActivationBinding,
    root_and_lock_identities: RestoreRuntimeLocks,
    resource_model: super::runtime::ResourceModel,
    original_owner_set: Vec<super::runtime::RuntimeOwner>,
}

impl RestoreRuntimeEnrollment {
    fn matches(&self, other: &Self) -> bool {
        self.record_type == other.record_type
            && self.version == other.version
            && self.control_id == other.control_id
            && self.nonce == other.nonce
            && self.boot_identity == other.boot_identity
            && self.pid == other.pid
            && self.process_start.seconds == other.process_start.seconds
            && self.process_start.nanos == other.process_start.nanos
            && self.activation_digest == other.activation_digest
            && self.authorization_epoch == other.authorization_epoch
            && self.business_install_binding == other.business_install_binding
            && self.root_and_lock_identities.control_root
                == other.root_and_lock_identities.control_root
            && self.root_and_lock_identities.admission_lock
                == other.root_and_lock_identities.admission_lock
            && self.root_and_lock_identities.runtime_lock
                == other.root_and_lock_identities.runtime_lock
            && self.resource_model == other.resource_model
            && self.original_owner_set == other.original_owner_set
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestoreConnectionDestruction {
    ConnectingOwnerDestroyedBeforeStart,
    ConnectingFutureDestroyed,
    ConnectionDestroyed,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
enum RestorePassiveRetirement {
    SqlDriver(Vec<RestoreConnectionDestruction>),
    ScreenHub,
    NeverStarted(super::runtime::RuntimeOwner),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all_fields = "camelCase", deny_unknown_fields)]
enum RestoreRuntimeFact {
    NativeWait {
        original_program_id: super::runtime::RuntimeOwner,
        original_pid: u32,
        original_start_identity: super::journal::ProcessStart,
        exit: super::journal::NativeExit,
        observed_ns: u64,
        pipes: [super::journal::PipeJoin; 3],
    },
    TaskJoin {
        original_task_id: super::runtime::RuntimeOwner,
        outcome: super::runtime::RuntimeTaskOutcome,
        observed_ns: u64,
    },
    PgAck {
        original_owner: super::runtime::RuntimeOwner,
        disposition: super::runtime::RuntimePgAck,
    },
    PassiveRetirement {
        object: RestorePassiveRetirement,
    },
}

impl RestoreRuntimeFact {
    fn closed_owner(&self, observed: u64) -> Option<super::runtime::RuntimeOwner> {
        use super::journal::{NativeExit, PipeJoin};
        use super::runtime::{RuntimeOwner, RuntimePgAck, RuntimeTaskOutcome};
        match self {
            Self::NativeWait {
                original_program_id,
                original_pid,
                original_start_identity,
                exit,
                observed_ns,
                pipes,
            } => {
                if *original_pid == 0
                    || original_start_identity.nanos >= 1_000_000_000
                    || *observed_ns == 0
                    || *observed_ns > observed
                    || !matches!(exit, NativeExit::Code { .. } | NativeExit::Signal { .. })
                    || pipes.iter().any(|pipe| match pipe {
                        PipeJoin::Null => false,
                        PipeJoin::Returned { observed_ns } => {
                            *observed_ns == 0 || *observed_ns > observed
                        }
                        PipeJoin::Panicked { .. } | PipeJoin::JoinUnknown => true,
                    })
                {
                    None
                } else {
                    Some(*original_program_id)
                }
            }
            Self::TaskJoin {
                original_task_id,
                outcome: RuntimeTaskOutcome::Returned,
                observed_ns,
            } if *observed_ns != 0 && *observed_ns <= observed => Some(*original_task_id),
            Self::PgAck {
                original_owner,
                disposition: RuntimePgAck::CommitAck | RuntimePgAck::RollbackAck,
            } => Some(*original_owner),
            Self::PassiveRetirement { object } => Some(match object {
                RestorePassiveRetirement::SqlDriver(destructions) => {
                    // Each closed value is one original adapter destruction;
                    // an empty set is the registered never-connected case.
                    let _ = destructions.len();
                    RuntimeOwner::SqlDriver
                }
                RestorePassiveRetirement::ScreenHub => RuntimeOwner::ScreenHub,
                RestorePassiveRetirement::NeverStarted(owner) => *owner,
            }),
            Self::TaskJoin { .. } => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreRuntimeReceipt {
    record_type: String,
    version: u32,
    same_identity_tuple: RestoreRuntimeEnrollment,
    enrollment_digest: Hex64,
    original_resource_facts: Vec<RestoreRuntimeFact>,
    retained_unknown_effect_refs: [(); 0],
    clock_observations: [u64; 1],
}

struct RestoreRuntimeReadback {
    directory: Option<File>,
    enrollment: Option<OwnedRecord>,
    receipt: Option<OwnedRecord>,
    decoded_enrollment: Option<Result<RestoreRuntimeEnrollment, serde_json::Error>>,
    decoded_receipt: Option<Result<RestoreRuntimeReceipt, serde_json::Error>>,
}

struct RestoreHeldSelection {
    ancestors: Vec<ServiceAncestor>,
    component: String,
    original: Option<File>,
    stamp: Option<ServiceFileStamp>,
}

struct RawIo {
    file: Option<io::Result<File>>,
    metadata: Option<io::Result<Metadata>>,
    named: Option<rustix::io::Result<rustix::fs::Stat>>,
    unit: Option<io::Result<()>>,
    count: Option<io::Result<usize>>,
    small: [u8; 8],
    directory: Option<rustix::io::Result<rustix::fs::Dir>>,
    entry: Option<Option<rustix::io::Result<rustix::fs::DirEntry>>>,
}

#[derive(Clone, Copy)]
pub(super) enum Directory {
    Root,
    Operations,
    Runtimes,
    OperationWork,
    RuntimeWork,
}

/// All in-flight raw results and original FDs stay here before clock checks.
pub(super) struct ControlFiles {
    pub(super) root: Option<File>,
    parent: Option<File>,
    ancestors: Vec<File>,
    operations: Option<File>,
    runtimes: Option<File>,
    operation_work: Option<File>,
    pub(super) runtime_work: Option<File>,
    root_path: PathBuf,
    root_component: String,
    app_component: Option<std::ffi::OsString>,
    uid: u32,
    pub(super) limits: TrustedHostRecoveryLimits,
    budget: ControlBudget,
    raw: RawIo,
    // Same native object and raw observations survive deadline/error paths.
    original_process: Option<
        Result<
            wrok_bot_macos_process::ProcessIdentity,
            wrok_bot_macos_process::ProcessObservationError,
        >,
    >,
    original_process_evidence: Option<[u8; 32]>,
    raw_process_evidence: Option<Result<[u8; 32], wrok_bot_macos_process::ProcessObservationError>>,
    raw_process_clock: Option<Result<u64, RecoveryControlError>>,
    process_monotonic_ns: u64,
    scratch: Vec<u8>,
    first_fault: Option<RecoveryControlFault>,
    pub(super) activation_source: Option<Arc<OwnedRecord>>,
    activation_observation:
        Option<Result<Arc<super::activation::ActivationObservation>, RecoveryControlError>>,
    publication_journal: Option<Arc<OwnedRecord>>,
    publication_operation: Option<([u8; 32], RecoveryFileIdentity)>,
    publication_chain: Option<Result<super::journal::JournalObservation, RecoveryControlError>>,
    publication_seal: Option<Result<super::journal::VerifiedPublication, RecoveryControlError>>,
    existing_server: Option<crate::db::initialization::OwnedExistingServerDatabase>,
    #[cfg(feature = "desktop-local")]
    local_root: Option<File>,
    #[cfg(feature = "desktop-local")]
    selected_local_component: Option<String>,
    #[cfg(feature = "desktop-local")]
    local_creation: Option<
        Result<
            (
                crate::auth::single_user::desktop_local::DesktopLocalInstallation,
                Option<crate::auth::single_user::desktop_local::OriginalFreshRoot>,
            ),
            crate::auth::single_user::desktop_local::DesktopLocalAuthorityError,
        >,
    >,
    #[cfg(feature = "desktop-local")]
    existing_local_pool: Option<crate::db::pool::DatabasePool>,
    existing_read_locks: bool,
    runtime_entropy: [u8; 16],
    raw_random: Option<Result<(), getrandom::Error>>,
    pub(super) pending_admission: Option<File>,
    pub(super) pending_runtime: Option<File>,
    pub(super) pending_owner: Option<File>,
    pending_request: Option<OwnedRecoveryRequestFile>,
    pending_host: Option<VerifiedRecoveryHost>,
    raw_request_decode: Option<Result<DecodedRecoveryRequest, RecoveryControlError>>,
    preheld_restore_usage: Option<(u64, u64)>,
    service_source: Option<VerifiedServiceRecoveryHost>,
    pub(super) runtime_record: Option<OwnedRecord>,
    pub(super) pending_startup: Option<RuntimeEntry>,
    pub(super) runtime_input: Vec<u8>,
    pub(super) raw_encoding: Option<Result<(), serde_json::Error>>,
    pub(super) retained_runtime: Option<super::runtime::RuntimeOwnerBook>,
    journal_tail: Option<write::JournalTail>,
    writer_held: bool,
    restore_runtime_readbacks: Vec<RestoreRuntimeReadback>,
    restore_operation: Option<RestoreOperationOwner>,
    closing_observation: Option<RestoreClosingAllowance>,
    pending_restore_intent: Option<VerifiedRestoreHostIntent>,
    pending_restore_clock: Option<super::clock::OperationClock>,
    #[cfg(feature = "server-runtime")]
    restore_input_buffer: Option<zeroize::Zeroizing<Vec<u8>>>,
    #[cfg(feature = "server-runtime")]
    restore_input_metadata: [Option<Metadata>; 2],
    #[cfg(feature = "server-runtime")]
    restore_input: Option<(crate::backup::whole_pg_restore_stream::FrozenWholePgRestoreInput, crate::backup::whole_pg_restore_stream::ReviewedWholePgRestoreIntent)>,
    restore_selections: [Option<RestoreHeldSelection>; 3],
    restore_isolation_work: Option<RestoreCandidateIsolationWork>,
    restore_entropy: [u8; 96],
}

pub(super) struct ControlBook {
    files: Option<ControlFiles>,
    retired_metadata: u64,
    retired_files: u64,
    fault: Option<RecoveryControlFault>,
    retained_candidate: Option<PendingRestoreCandidateAuthority>,
}
pub(super) type ControlOwner = Arc<Mutex<ControlBook>>;

/// Custody of the same original value, with no book guard across IO. None
/// means Busy; it cannot initialize a second owner or replace the original.
pub(super) struct ControlAccess {
    owner: ControlOwner,
    files: Option<ControlFiles>,
}
impl Deref for ControlAccess {
    type Target = ControlFiles;
    fn deref(&self) -> &ControlFiles {
        self.files.as_ref().expect("original control access")
    }
}
impl DerefMut for ControlAccess {
    fn deref_mut(&mut self) -> &mut ControlFiles {
        self.files.as_mut().expect("original control access")
    }
}
impl Drop for ControlAccess {
    fn drop(&mut self) {
        let Some(mut files) = self.files.take() else {
            return;
        };
        let mut book = match self.owner.lock() {
            Ok(book) => book,
            Err(poisoned) => {
                let mut book = poisoned.into_inner();
                book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
                book
            }
        };
        // The original File has already dropped before each recorded known
        // retirement. Apply both aggregates exactly once to the same budget.
        let metadata = std::mem::take(&mut book.retired_metadata);
        let count = std::mem::take(&mut book.retired_files);
        files.retire_known_ordinary_leases(metadata, count);
        if let Some(fault) = book.fault {
            files.latch(fault);
        }
        // lock is the sole original-value taker; this is its sole put-back.
        book.files = Some(files);
    }
}

pub(super) fn lock(owner: &ControlOwner) -> Result<ControlAccess, RecoveryControlError> {
    let mut access = ControlAccess {
        owner: Arc::clone(owner),
        files: None,
    };
    let mut book = owner.lock().map_err(|poisoned| {
        let mut book = poisoned.into_inner();
        book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
        if let Some(files) = book.files.as_mut() {
            files.latch(RecoveryControlFault::OwnerLost);
        }
        RecoveryControlError::with_owner(RecoveryControlFault::OwnerLost, owner)
    })?;
    if let Some(fault) = book.fault {
        return Err(RecoveryControlError::with_owner(fault, owner));
    }
    access.files =
        Some(book.files.take().ok_or_else(|| {
            RecoveryControlError::with_owner(RecoveryControlFault::OwnerBusy, owner)
        })?);
    drop(book);
    Ok(access)
}

/// One short synchronous section of a runtime SH caller on the original
/// control value, left in place under the book guard. A value checked out by
/// an exclusive owner is Busy at once; the section never waits for it, never
/// awaits and never re-enters the control or runtime book.
pub(super) fn share<R>(
    owner: &ControlOwner,
    section: impl FnOnce(&mut ControlFiles) -> R,
) -> Result<R, RecoveryControlError> {
    let mut book = owner.lock().map_err(|poisoned| {
        let mut book = poisoned.into_inner();
        book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
        if let Some(files) = book.files.as_mut() {
            files.latch(RecoveryControlFault::OwnerLost);
        }
        RecoveryControlError::with_owner(RecoveryControlFault::OwnerLost, owner)
    })?;
    if let Some(fault) = book.fault {
        return Err(RecoveryControlError::with_owner(fault, owner));
    }
    let book = &mut *book;
    let files = book
        .files
        .as_mut()
        .ok_or_else(|| RecoveryControlError::with_owner(RecoveryControlFault::OwnerBusy, owner))?;
    let result = section(files);
    // The same put-back accounting as `ControlAccess`, applied in place.
    files.retire_known_ordinary_leases(
        std::mem::take(&mut book.retired_metadata),
        std::mem::take(&mut book.retired_files),
    );
    Ok(result)
}

/// Only a known ordinary admission's actual File Drop calls this. A concurrent
/// original IO owner receives checked fixed aggregates at put-back; no spin,
/// queue allocation, new quota, runtime-close fact or unknown FD retirement.
pub(super) fn retire_ordinary_lease(owner: &ControlOwner, metadata: u64) {
    let mut book = match owner.lock() {
        Ok(book) => book,
        Err(poisoned) => {
            let mut book = poisoned.into_inner();
            book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
            book
        }
    };
    let fault = book.fault;
    if let Some(files) = book.files.as_mut() {
        files.retire_known_ordinary_leases(metadata, 1);
        if let Some(fault) = fault {
            files.latch(fault);
        }
    } else {
        match (
            book.retired_metadata.checked_add(metadata),
            book.retired_files.checked_add(1),
        ) {
            (Some(bytes), Some(count)) => {
                book.retired_metadata = bytes;
                book.retired_files = count;
            }
            _ => {
                book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
            }
        }
    }
}

fn static_io_fee() -> u64 {
    // Separate resident and returned/match slots; never assume return-place
    // reuse. The resident RawIo is also included in ControlFiles' fixed fee.
    (2 * std::mem::size_of::<io::Result<File>>()
        + 2 * std::mem::size_of::<io::Result<Metadata>>()
        + 2 * std::mem::size_of::<rustix::io::Result<rustix::fs::Stat>>()
        + 2 * std::mem::size_of::<io::Result<usize>>()
        + 2 * std::mem::size_of::<io::Result<()>>()
        + 2 * std::mem::size_of::<
            Result<
                wrok_bot_macos_process::ProcessIdentity,
                wrok_bot_macos_process::ProcessObservationError,
            >,
        >()
        + 2 * std::mem::size_of::<Result<[u8; 32], wrok_bot_macos_process::ProcessObservationError>>(
        )
        + 2 * std::mem::size_of::<Result<u64, RecoveryControlError>>()
        + 2 * std::mem::size_of::<[u8; 32]>()
        + 2 * std::mem::size_of::<bool>()
        + 2 * std::mem::size_of::<(Option<u64>, Option<u64>)>()
        + 2 * std::mem::size_of::<(u64, u64)>()
        + 2 * std::mem::size_of::<(u32, u64, u32, [u8; 32])>()) as u64
}

pub(super) fn identity(meta: &Metadata) -> RecoveryFileIdentity {
    RecoveryFileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        uid: meta.uid(),
    }
}

impl ControlFiles {
    pub(super) fn existing_server_pool(
        &self,
    ) -> Result<&crate::db::pool::DatabasePool, RecoveryControlError> {
        self.existing_server
            .as_ref()
            .ok_or_else(service_invalid)?
            .pool()
    }

    pub(super) fn existing_scope(
        &self,
        pool: &crate::db::pool::DatabasePool,
        deployment: &str,
        tenant: &str,
    ) -> bool {
        let Some(Ok(observation)) = &self.activation_observation else {
            return false;
        };
        let binding = match observation.record.data() {
            super::activation::ActivationPayload::Active(active) => &active.binding,
            super::activation::ActivationPayload::Current(current) => &current.binding,
            _ => return false,
        };
        binding.scope() == (deployment, tenant) && self.matches_bound_pool(pool)
    }

    pub(super) fn matches_bound_pool(&self, pool: &crate::db::pool::DatabasePool) -> bool {
        if self
            .existing_server_pool()
            .is_ok_and(|actual| std::ptr::eq(actual.manager(), pool.manager()))
        {
            return true;
        }
        #[cfg(feature = "desktop-local")]
        if self
            .existing_local_pool
            .as_ref()
            .is_some_and(|actual| std::ptr::eq(actual.manager(), pool.manager()))
        {
            return true;
        }
        false
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn bind_original_local_pool(&mut self, pool: &crate::db::pool::DatabasePool) {
        self.existing_local_pool = Some(pool.clone());
    }

    #[cfg(feature = "desktop-local")]
    fn observe_local_root(
        &mut self,
        deadline: Instant,
    ) -> Result<(Option<RecoveryFileIdentity>, RecoveryFileIdentity, String), RecoveryControlError>
    {
        self.selected_local_component = None;
        let component = self
            .app_component
            .as_ref()
            .and_then(|s| s.to_str())
            .ok_or_else(service_invalid)?
            .to_owned();
        self.reserve_io(0)?;
        self.raw.metadata = Some(self.parent.as_ref().ok_or_else(service_invalid)?.metadata());
        self.post(deadline)?;
        let parent = identity(
            self.raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?,
        );
        self.reserve_io(1)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.parent.as_ref().ok_or_else(service_invalid)?,
                component.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let root = if self.raw.file.as_ref().is_some_and(|r| {
            r.as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        }) {
            None
        } else {
            let actual = self.check_opened(true, deadline)?;
            self.local_root = Some(self.take_opened()?);
            self.verify_local_root_before(actual, deadline)?;
            Some(actual)
        };
        Ok((root, parent, component))
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn verify_local_root_before(
        &mut self,
        expected: RecoveryFileIdentity,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        self.raw.metadata = Some(
            self.local_root
                .as_ref()
                .ok_or_else(service_invalid)?
                .metadata(),
        );
        self.post(deadline)?;
        let meta = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?;
        self.valid_meta(meta, true)?;
        if identity(meta) != expected {
            return Err(service_invalid());
        }
        self.reserve_io(0)?;
        self.raw.named = Some(rustix::fs::statat(
            self.parent.as_ref().ok_or_else(service_invalid)?,
            self.selected_local_component.as_deref().map(std::ffi::OsStr::new)
                .or(self.app_component.as_deref()).ok_or_else(service_invalid)?,
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let named = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?;
        if named.st_dev as u64 != expected.device
            || named.st_ino as u64 != expected.inode
            || named.st_uid != expected.uid
            || named.st_mode & 0o7777 != 0o700
            || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
        {
            return Err(service_invalid());
        }
        Ok(())
    }

    /// Select only the original journal's generation under the already held parent.
    #[cfg(feature = "desktop-local")]
    pub(super) fn select_restored_local_root_before(
        &mut self,
        published: &super::activation::PublishedActivation,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        let plan = published.restore_plan().ok_or_else(service_invalid)?;
        let expected = published.binding().ordinary_local()?.generation_root;
        self.prepay((plan.entry_component.len() as u64).checked_mul(4).ok_or_else(service_invalid)?, 0)?;
        self.reserve_io(0)?;
        self.raw.metadata = Some(self.parent.as_ref().ok_or_else(service_invalid)?.metadata());
        self.post(deadline)?;
        if self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(identity)
            != Some(plan.trusted_parent)
        {
            return Err(service_invalid());
        }
        self.reserve_io(1)?;
        self.raw.file = Some(rustix::fs::openat(
            self.parent.as_ref().ok_or_else(service_invalid)?,
            plan.entry_component.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ).map(File::from).map_err(io::Error::from));
        self.post(deadline)?;
        if self.check_opened(true, deadline)? != expected {
            return Err(service_invalid());
        }
        self.local_root = Some(self.take_opened()?);
        self.selected_local_component = Some(plan.entry_component.clone());
        self.verify_local_root_before(expected, deadline)?;
        Ok(expected)
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn restored_local_site_before(
        &mut self,
        published: &super::activation::PublishedActivation,
        app: &crate::auth::single_user::desktop_local::CurrentOsUserAppDataRoot,
        deadline: Instant,
    ) -> Result<crate::auth::single_user::desktop_local::RestoredLocalSite, RecoveryControlError> {
        let plan = published.restore_plan().ok_or_else(service_invalid)?;
        if app.as_path().parent() != self.root_path.parent()
            || app.as_path().file_name() != self.app_component.as_deref()
            || self.selected_local_component.as_deref() != Some(plan.entry_component.as_str())
        {
            return Err(service_invalid());
        }
        let site = published.binding().ordinary_local()?;
        self.verify_local_root_before(site.generation_root, deadline)?;
        let parent = self.root_path.parent().ok_or_else(service_invalid)?;
        let paths = parent.as_os_str().len().checked_add(plan.entry_component.len())
            .and_then(|n| n.checked_add(6)).and_then(|n| n.checked_mul(4)).ok_or_else(service_invalid)?;
        let strings = [site.installation_id, site.deployment_id, site.tenant_id, site.dataset_id,
            &site.master.account, &site.master.key_id, &site.postgres.account]
            .iter().try_fold(0usize, |n, s| n.checked_add(s.len()))
            .and_then(|n| n.checked_mul(2)).ok_or_else(service_invalid)?;
        let fee = paths.checked_add(strings)
            .and_then(|n| n.checked_add(std::mem::size_of::<crate::auth::single_user::desktop_local::RestoredLocalSite>()))
            .ok_or_else(service_invalid)?;
        self.prepay(fee as u64, 0)?;
        let parent = self.root_path.parent().ok_or_else(service_invalid)?;
        Ok(crate::auth::single_user::desktop_local::RestoredLocalSite {
            ids: [site.installation_id, site.deployment_id, site.tenant_id, site.dataset_id].map(str::to_owned),
            data_dir: parent.join(&plan.entry_component).join("data"),
            master: (site.master.account.clone(), site.master.key_id.clone()),
            postgres_account: site.postgres.account.clone(),
        })
    }

    #[cfg(feature = "desktop-local")]
    pub(super) fn create_original_local_installation(
        &mut self,
        creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
        deadline: Instant,
    ) -> Result<
        (
            crate::auth::single_user::desktop_local::DesktopLocalInstallation,
            RecoveryFileIdentity,
        ),
        RecoveryControlError,
    > {
        let expected_path = self
            .root_path
            .parent()
            .ok_or_else(service_invalid)?
            .join(self.app_component.as_ref().ok_or_else(service_invalid)?);
        if creator.original_app_data_root() != expected_path {
            return Err(service_invalid());
        }
        self.reserve_io(1)?;
        before(deadline)?;
        self.local_creation = Some(creator.load_or_create_installation_for_recovery());
        self.post(deadline)?;
        let (installation, fresh) = match self.local_creation.take() {
            Some(Ok(created)) => created,
            other => {
                self.local_creation = other;
                return Err(service_invalid());
            }
        };
        self.local_root = Some(
            fresh
                .ok_or_else(service_invalid)?
                .into_root_for(installation.authority())
                .map_err(|_| service_invalid())?,
        );
        self.reserve_io(0)?;
        self.raw.metadata = Some(
            self.local_root
                .as_ref()
                .ok_or_else(service_invalid)?
                .metadata(),
        );
        self.post(deadline)?;
        let root = identity(
            self.raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?,
        );
        self.verify_local_root_before(root, deadline)?;
        Ok((installation, root))
    }

    fn registration_free(&self) -> Result<(), RecoveryControlError> {
        if self.retained_runtime.is_some()
            || self.pending_startup.is_some()
            || self.pending_owner.is_some()
            || self.pending_admission.is_some()
            || self.pending_runtime.is_some()
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        Ok(())
    }

    /// admissionSH → NONBLOCK runtimeSH; busy releases both.
    pub(super) fn acquire_shared_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.registration_free()?;
        let held = self
            .acquire(
                "admission.lock",
                b"WBRCADM1",
                FlockOperation::NonBlockingLockShared,
                deadline,
            )
            .and_then(|admission| {
                self.pending_admission = Some(admission);
                self.acquire(
                    "runtime.lock",
                    b"WBRCRUN1",
                    FlockOperation::NonBlockingLockShared,
                    deadline,
                )
            });
        match held {
            Ok(runtime) => {
                self.pending_runtime = Some(runtime);
                self.existing_read_locks = true;
                Ok(())
            }
            Err(error) => {
                self.release_registration_attempt();
                Err(error)
            }
        }
    }

    /// ownerEX → admissionEX → NONBLOCK runtimeEX; busy releases all three
    /// before any nonce, epoch, head read or effect.
    pub(super) fn acquire_writer_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.registration_free()?;
        let exclusive = FlockOperation::NonBlockingLockExclusive;
        let held = self
            .acquire("owner.lock", b"WBRCOWN1", exclusive, deadline)
            .and_then(|owner| {
                self.pending_owner = Some(owner);
                self.acquire("admission.lock", b"WBRCADM1", exclusive, deadline)
            })
            .and_then(|admission| {
                self.pending_admission = Some(admission);
                self.acquire("runtime.lock", b"WBRCRUN1", exclusive, deadline)
            });
        match held {
            Ok(runtime) => {
                self.pending_runtime = Some(runtime);
                self.writer_held = true;
                Ok(())
            }
            Err(error) => {
                self.release_writer();
                Err(error)
            }
        }
    }

    /// The registration consumed the held locks; no branch still owns them.
    pub(super) fn existing_read_locks_retired(&mut self) {
        self.existing_read_locks = false;
        self.writer_held = false;
    }

    pub(super) fn holds_writer(&self) -> bool {
        self.writer_held
            && self.pending_owner.is_some()
            && self.pending_admission.is_some()
            && self.pending_runtime.is_some()
    }

    fn verify_restore_live(
        &mut self,
        operation_id: Hex32,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let operation = self
            .restore_operation
            .as_ref()
            .ok_or_else(service_invalid)?;
        if operation.operation != operation_id || !self.holds_writer() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        operation.clock.require_convergence()?;
        let deadline = deadline.min(operation.clock.convergence_deadline());
        let expected_root = operation.intent.control_root;
        self.post(deadline)?;
        if self.root_identity(deadline)? != expected_root {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let original_lock = |error: RecoveryControlError| {
            if error.fault() == RecoveryControlFault::ControlInvalid {
                RecoveryControlError::new(RecoveryControlFault::OwnerLost)
            } else {
                error
            }
        };
        self.held_owner_identity(deadline).map_err(original_lock)?;
        self.held_lock_identity(true, deadline).map_err(original_lock)?;
        self.held_lock_identity(false, deadline).map_err(original_lock)?;
        self.restore_operation
            .as_mut()
            .ok_or_else(service_invalid)?
            .intent
            .host
            .recheck_original(deadline)?;
        self.post(deadline)
    }

    fn observe_restore_capacity(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        let Self {
            root,
            parent,
            ancestors,
            operations,
            runtimes,
            operation_work,
            runtime_work,
            pending_owner,
            pending_admission,
            pending_runtime,
            raw,
            activation_source,
            publication_journal,
            journal_tail,
            restore_runtime_readbacks,
            restore_selections,
            restore_operation,
            ..
        } = self;
        let original = restore_operation.as_mut().ok_or_else(service_invalid)?;
        let RestoreOperationOwner {
            ledger,
            intent,
            pending,
            ..
        } = original;
        for file in [
            root.as_ref(),
            parent.as_ref(),
            operations.as_ref(),
            runtimes.as_ref(),
            operation_work.as_ref(),
            runtime_work.as_ref(),
            pending_owner.as_ref(),
            pending_admission.as_ref(),
            pending_runtime.as_ref(),
            raw.file.as_ref().and_then(|r| r.as_ref().ok()),
            activation_source.as_ref().map(|r| &r.file),
            publication_journal.as_ref().map(|r| &r.file),
            journal_tail.as_ref().map(|tail| &tail.file),
            pending.as_ref().map(|r| &r.file),
            intent.request.file.as_ref(),
            Some(&intent.request.parent),
        ]
        .into_iter()
        .flatten()
        {
            ledger.observe_file(file, false, deadline)?;
        }
        for file in ancestors {
            ledger.observe_file(file, false, deadline)?;
        }
        for readback in restore_runtime_readbacks {
            for file in [
                readback.directory.as_ref(),
                readback.enrollment.as_ref().map(|r| &r.file),
                readback.receipt.as_ref().map(|r| &r.file),
            ]
            .into_iter()
            .flatten()
            {
                ledger.observe_file(file, false, deadline)?;
            }
        }
        #[cfg(feature = "desktop-local")]
        match &intent.host.original {
            #[cfg(feature = "desktop-local")]
            HostOrigin::LocalRelease {
                program, release, ..
            } => {
                for file in [&program.0, &program.2, &release.0, &release.2] {
                    ledger.observe_file(file, false, deadline)?;
                }
            }
        }
        for (index, selection) in restore_selections.iter().enumerate() {
            if let Some(selection) = selection {
                for ancestor in &selection.ancestors { ledger.observe_file(&ancestor.file, false, deadline)?; }
                if let Some(file) = &selection.original { ledger.observe_file(file, index == 1, deadline)?; }
            }
        }
        if let Some(plan) = &original.candidate_plan_output { ledger.observe_file(&plan.parent, false, deadline)?; }
        ledger.check_storage()
    }

    pub(super) fn require_empty_legacy_control_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        let operations = self.inventory_count(Directory::Operations, self.limits.max_retained_operations, None, deadline)?;
        let runtimes = self.inventory_count(Directory::Runtimes, self.limits.max_registered_runtimes, None, deadline)?;
        if operations != 0 || runtimes != 0 { return Err(RecoveryControlError::new(RecoveryControlFault::InitializationRequired)); }
        Ok(())
    }

    /// Drop the writer's locks and open journal; written files stay.
    pub(super) fn release_writer(&mut self) {
        self.writer_held = false;
        self.journal_tail = None;
        self.raw.file = None;
        self.pending_owner = None;
        self.pending_runtime = None;
        self.pending_admission = None;
    }

    /// The same runtime lock FD goes from EX to SH.
    pub(super) fn downgrade_runtime_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if !self.holds_writer() {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(match self.pending_runtime.as_ref() {
            Some(file) => rustix::fs::flock(file, FlockOperation::NonBlockingLockShared)
                .map_err(io::Error::from),
            None => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
        });
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        Ok(())
    }

    /// Boot identity, pid and start of this process from its one native
    /// observation; no configured identity substitutes for it.
    fn process_record(
        &self,
    ) -> Result<(String, u32, super::journal::ProcessStart), RecoveryControlError> {
        let raw = self
            .original_process_evidence
            .as_ref()
            .ok_or_else(service_invalid)?;
        let mut boot = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in &raw[16..] {
            boot.push(HEX[usize::from(byte >> 4)] as char);
            boot.push(HEX[usize::from(byte & 15)] as char);
        }
        let pid = u32::from_be_bytes(raw[..4].try_into().map_err(|_| service_invalid())?);
        let start = super::journal::ProcessStart {
            seconds: u64::from_be_bytes(raw[4..12].try_into().map_err(|_| service_invalid())?),
            nanos: u32::from_be_bytes(raw[12..16].try_into().map_err(|_| service_invalid())?)
                .checked_mul(1000)
                .ok_or_else(service_invalid)?,
        };
        Ok((boot, pid, start))
    }

    /// Enrollment input of a verified head for this process; the owner set and
    /// resource model come from the sealed intent unchanged.
    pub(super) fn runtime_entry(
        &mut self,
        published: PublishedActivation,
        intent: &super::ordinary::VerifiedOrdinaryStartupIntent,
    ) -> Result<RuntimeEntry, RecoveryControlError> {
        let deadline = intent.effect_deadline();
        let control_root = self.root_identity(deadline)?;
        let (boot_identity, pid, process_start) = self.process_record()?;
        Ok(RuntimeEntry {
            published,
            control_root,
            runtime_nonce: String::with_capacity(32),
            original_deadline: deadline,
            enrollment: super::runtime::OriginalRuntimeEnrollment {
                boot_identity,
                pid,
                process_start,
                resource_model: intent.resource_model(),
                original_owner_set: intent.owners().to_vec(),
            },
        })
    }

    /// The operation owner's clock relation for an ordinary OperationIntent.
    pub(super) fn owner_clock(
        &self,
        owner_nonce: Hex32,
        t0_ns: u64,
        bounds: &super::activation::OrdinaryStartupBounds,
    ) -> Result<super::journal::OwnerClockRecord, RecoveryControlError> {
        let (boot_identity, pid, process_start) = self.process_record()?;
        let effect_deadline_ns = t0_ns
            .checked_add(bounds.effect_ns.get())
            .ok_or_else(service_invalid)?;
        Ok(super::journal::OwnerClockRecord {
            clock_kind: "CLOCK_MONOTONIC".to_owned(),
            boot_identity,
            pid,
            process_start,
            owner_nonce: owner_nonce.as_str().to_owned(),
            t0_ns,
            effect_deadline_ns,
            convergence_deadline_ns: effect_deadline_ns
                .checked_add(bounds.convergence_ns.get())
                .ok_or_else(service_invalid)?,
        })
    }

    pub(super) fn holds_existing_read_locks(&self) -> bool {
        self.existing_read_locks
            && self.pending_admission.is_some()
            && self.pending_runtime.is_some()
    }

    pub(super) fn fill_runtime_nonce(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if self.pending_owner.is_none() {
            return Err(service_invalid());
        }
        self.post(deadline)?;
        self.raw_random = Some(getrandom::fill(&mut self.runtime_entropy));
        self.post(deadline)?;
        if !matches!(self.raw_random, Some(Ok(()))) {
            return Err(service_invalid());
        }
        let original = self.pending_startup.as_mut().ok_or_else(service_invalid)?;
        if !original.runtime_nonce.is_empty() || original.runtime_nonce.capacity() < 32 {
            return Err(service_invalid());
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.runtime_entropy {
            original
                .runtime_nonce
                .push(HEX[usize::from(byte >> 4)] as char);
            original
                .runtime_nonce
                .push(HEX[usize::from(byte & 15)] as char);
        }
        hex(&original.runtime_nonce, 32, true)
    }

    fn process_clock_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.raw_process_clock = Some(super::clock::monotonic_ns());
        let observed = self
            .raw_process_clock
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied();
        match observed {
            Some(value) if value >= self.process_monotonic_ns => self.process_monotonic_ns = value,
            _ => {
                self.latch(RecoveryControlFault::OwnerLost);
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
            }
        }
        before(deadline)
    }

    fn initialize_original_process(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if self.original_process.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        before(deadline)?;
        self.process_clock_before(deadline)?;
        self.original_process = Some(super::clock::capture_original_process());
        if !matches!(self.original_process, Some(Ok(_))) {
            self.latch(RecoveryControlFault::OwnerLost);
        }
        // Actual capture result is resident before native/portable time.
        self.process_clock_before(deadline)?;
        self.post(deadline)
    }

    pub(super) fn post(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        // A process observation neither starts nor restarts operation E/C.
        // Ordinary expiry alone is not permanent owner loss. Actual native
        // process/boot/clock drift is; raw IO and results remain resident.
        if let Some(fault) = self.first_fault {
            if self.closing_observation.is_none() || fault == RecoveryControlFault::OwnerLost {
                return Err(RecoveryControlError::new(fault));
            }
        }
        self.post_original_owner(deadline)
    }

    fn post_original_owner(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        before(deadline)?;
        self.process_clock_before(deadline)?;
        let original = match self.original_process.as_ref() {
            Some(Ok(original)) => original,
            _ => {
                self.latch(RecoveryControlFault::OwnerLost);
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
            }
        };
        self.raw_process_evidence = Some(super::clock::original_process_evidence(original));
        // Remember known drift even if the following deadline check is late.
        let invalid = match self.raw_process_evidence.as_ref() {
            Some(Ok(observed)) => {
                super::clock::verify_process_evidence(observed, None).is_err()
                    || self
                        .original_process_evidence
                        .is_some_and(|expected| expected != *observed)
            }
            _ => true,
        };
        if invalid {
            self.latch(RecoveryControlFault::OwnerLost);
        }
        // Evidence/error is retained before either time check can fail.
        self.process_clock_before(deadline)?;
        if invalid {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let observed = self
            .raw_process_evidence
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        self.original_process_evidence.get_or_insert(observed);
        before(deadline)
    }

    fn check_enrollment(
        &self,
        original: &super::runtime::OriginalRuntimeEnrollment,
    ) -> Result<(), RecoveryControlError> {
        let evidence = self
            .original_process_evidence
            .as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        super::clock::verify_process_evidence(
            evidence,
            Some((
                &original.boot_identity,
                original.pid,
                &original.process_start,
            )),
        )
    }

    pub(super) fn verify_enrollment_before(
        &mut self,
        original: &super::runtime::OriginalRuntimeEnrollment,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.post(deadline)?;
        self.check_enrollment(original)
    }

    pub(super) fn verify_pending_enrollment_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.post(deadline)?;
        let original = &self
            .pending_startup
            .as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
            .enrollment;
        self.check_enrollment(original)
    }

    pub(super) fn latch(&mut self, fault: RecoveryControlFault) {
        self.first_fault.get_or_insert(fault);
    }

    pub(super) fn prepay(&mut self, bytes: u64, files: u64) -> Result<(), RecoveryControlError> {
        if let Some(allowance) = &mut self.closing_observation {
            if files != 0 || bytes > allowance.metadata_left {
                return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
            }
            allowance.metadata_left -= bytes;
            return Ok(());
        }
        if let Some(fault) = self.first_fault {
            return Err(RecoveryControlError::new(fault));
        }
        if let Some(operation) = &mut self.restore_operation {
            operation.ledger.admit(super::RestoreCapacityResource::MetadataBytes, bytes)?;
            operation.ledger.admit(super::RestoreCapacityResource::OpenFiles, files)?;
        }
        self.budget.charge(bytes, files)
    }

    fn reserve_io(&mut self, files: u64) -> Result<(), RecoveryControlError> {
        // RawIo plus separate typed return/match slots were charged once in
        // open_control, before the first IO. Reusing those same slots is not a
        // new allocation. New FD reservations remain charged per handle.
        self.prepay(0, files)
    }

    fn retire_known_ordinary_leases(&mut self, metadata: u64, files: u64) {
        if let Err(error) = self.budget.retire_ordinary_leases(metadata, files) {
            self.latch(error.fault());
        }
    }

    pub(super) fn directory(&self, dir: Directory) -> Result<&File, RecoveryControlError> {
        match dir {
            Directory::Root => self.root.as_ref(),
            Directory::Operations => self.operations.as_ref(),
            Directory::Runtimes => self.runtimes.as_ref(),
            Directory::OperationWork => self.operation_work.as_ref(),
            Directory::RuntimeWork => self.runtime_work.as_ref(),
        }
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))
    }

    fn valid_meta(&self, meta: &Metadata, directory: bool) -> Result<(), RecoveryControlError> {
        if meta.uid() != self.uid
            || meta.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || if directory {
                !meta.is_dir()
            } else {
                !meta.is_file() || meta.nlink() != 1
            }
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }

    fn take_opened(&mut self) -> Result<File, RecoveryControlError> {
        match self.raw.file.take() {
            Some(Ok(file)) => Ok(file),
            other => {
                self.raw.file = other;
                Err(RecoveryControlError::new(RecoveryControlFault::IoFailure))
            }
        }
    }

    fn check_opened(
        &mut self,
        directory: bool,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        let result = match self.raw.file.as_ref() {
            Some(Ok(file)) => file.metadata(),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        };
        self.raw.metadata = Some(result);
        self.post(deadline)?;
        let meta = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, directory)?;
        Ok(identity(meta))
    }

    fn named_matches(
        &mut self,
        dir: Directory,
        name: &str,
        expected: RecoveryFileIdentity,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        self.raw.named = Some(rustix::fs::statat(
            self.directory(dir)?,
            name,
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let s = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if s.st_dev as u64 != expected.device
            || s.st_ino as u64 != expected.inode
            || s.st_uid != expected.uid
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }

    pub(super) fn open_named(
        &mut self,
        dir: Directory,
        name: &str,
        write: bool,
        deadline: Instant,
    ) -> Result<(File, RecoveryFileIdentity), RecoveryControlError> {
        component(name, &self.limits)?;
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(dir)?,
                name,
                (if write { OFlags::RDWR } else { OFlags::RDONLY })
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let expected = self.check_opened(false, deadline)?;
        self.named_matches(dir, name, expected, deadline)?;
        Ok((self.take_opened()?, expected))
    }

    pub(super) fn read_record(
        &mut self,
        dir: Directory,
        name: &str,
        cap: u64,
        deadline: Instant,
    ) -> Result<OwnedRecord, RecoveryControlError> {
        let (file, expected) = self.open_named(dir, name, false, deadline)?;
        self.raw.file = Some(Ok(file));
        let length = self
            .raw
            .metadata
            .as_ref()
            .and_then(|m| m.as_ref().ok())
            .map(Metadata::len)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if length == 0 || length > cap {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        let n =
            usize::try_from(length.checked_add(1).ok_or_else(|| {
                RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
            })?)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay(
            (n as u64)
                .checked_mul(2)
                .and_then(|v| v.checked_add(std::mem::size_of::<Vec<u8>>() as u64))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?,
            0,
        )?;
        self.scratch = Vec::new();
        self.scratch
            .try_reserve_exact(n)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if self.scratch.capacity()
            > n.checked_mul(2)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        self.scratch.resize(n, 0);
        let mut offset = 0usize;
        loop {
            self.reserve_io(0)?;
            before(deadline)?;
            let result = match self.raw.file.as_ref() {
                Some(Ok(file)) => {
                    let mut borrowed = file;
                    borrowed.read(&mut self.scratch[offset..])
                }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            self.raw.count = Some(result);
            self.post(deadline)?;
            let got = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if got == 0 {
                break;
            }
            offset = offset
                .checked_add(got)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if offset >= n {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        if offset as u64 != length {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.scratch.truncate(offset);
        let final_identity = self.check_opened(false, deadline)?;
        let final_length = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(Metadata::len);
        if final_identity != expected || final_length != Some(length) {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.named_matches(dir, name, expected, deadline)?;
        Ok(OwnedRecord {
            file: self.take_opened()?,
            identity: expected,
            bytes: std::mem::take(&mut self.scratch),
        })
    }

    /// Move only this definitely-unlocked ordinary admission FD to its RAII
    /// attempt. Unknown IO and all runtime/registration locks stay resident.
    pub(super) fn take_known_busy_admission(&mut self) -> Option<File> {
        if &self.raw.small != b"WBRCADM1"
            || !matches!(self.raw.unit.as_ref(), Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        {
            return None;
        }
        match self.raw.file.take() {
            Some(Ok(file)) => Some(file),
            other => {
                self.raw.file = other;
                None
            }
        }
    }

    pub(super) fn acquire(
        &mut self,
        name: &str,
        marker: &[u8; 8],
        operation: FlockOperation,
        deadline: Instant,
    ) -> Result<File, RecoveryControlError> {
        let (file, _) = self.open_named(Directory::Root, name, true, deadline)?;
        self.raw.file = Some(Ok(file));
        if self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(Metadata::len)
            != Some(8)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.raw.small = [0; 8];
        for offset in 0..8 {
            self.reserve_io(0)?;
            before(deadline)?;
            let result = match self.raw.file.as_ref() {
                Some(Ok(file)) => {
                    let mut f = file;
                    f.read(&mut self.raw.small[offset..offset + 1])
                }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            self.raw.count = Some(result);
            self.post(deadline)?;
            if !matches!(self.raw.count, Some(Ok(1))) {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        if &self.raw.small != marker {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        let result = match self.raw.file.as_ref() {
            Some(Ok(file)) => rustix::fs::flock(file, operation).map_err(io::Error::from),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        };
        self.raw.unit = Some(result);
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => self.take_opened(),
            Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy))
            }
            _ => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
    }

    pub(super) fn root_identity(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(self.directory(Directory::Root)?.metadata());
        self.post(deadline)?;
        let m = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, true)?;
        let held = identity(m);
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.named = Some(rustix::fs::statat(
            self.parent
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?,
            self.root_component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let named = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != held.device
            || named.st_ino as u64 != held.inode
            || named.st_uid != held.uid
            || named.st_mode & 0o7777 != 0o700
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(held)
    }

    fn sync_directory(
        &mut self,
        dir: Directory,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(self.directory(dir)?.sync_all());
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => Ok(()),
            _ => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
    }

    /// Bootstrap only the fixed empty control namespace. This creates neither
    /// an activation nor an epoch and never repairs an existing malformed file.
    fn ensure_directory(
        &mut self,
        name: &str,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        component(name, &self.limits)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::mkdirat(
                self.directory(Directory::Root)?,
                name,
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => self.sync_directory(Directory::Root, deadline),
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
    }

    fn ensure_lock(
        &mut self,
        name: &str,
        marker: &[u8; 8],
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(Directory::Root)?,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let created = match self.raw.file.as_ref() {
            Some(Ok(_)) => true,
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => false,
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        };
        if created {
            let expected = self.check_opened(false, deadline)?;
            self.named_matches(Directory::Root, name, expected, deadline)?;
            let mut offset = 0usize;
            while offset < marker.len() {
                self.reserve_io(0)?;
                before(deadline)?;
                self.raw.count = Some(match self.raw.file.as_ref() {
                    Some(Ok(f)) => {
                        let mut borrowed = f;
                        borrowed.write(&marker[offset..])
                    }
                    _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
                });
                self.post(deadline)?;
                let n = *self
                    .raw
                    .count
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
                if n == 0 {
                    return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
                }
                offset = offset.checked_add(n).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?;
            }
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.unit = Some(
                self.raw
                    .file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .sync_all(),
            );
            self.post(deadline)?;
            if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
                return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
            }
            self.sync_directory(Directory::Root, deadline)?;
        } else {
            let (file, _) = self.open_named(Directory::Root, name, false, deadline)?;
            self.raw.file = Some(Ok(file));
        }
        let expected = self.check_opened(false, deadline)?;
        if self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(Metadata::len)
            != Some(8)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.raw.small = [0; 8];
        for offset in 0..8 {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(
                self.raw
                    .file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read_at(&mut self.raw.small[offset..offset + 1], offset as u64),
            );
            self.post(deadline)?;
            if !matches!(self.raw.count, Some(Ok(1))) {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        if &self.raw.small != marker {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.named_matches(Directory::Root, name, expected, deadline)?;
        // Only a fully synced/read-back bootstrap success retires this FD.
        self.raw.file = None;
        Ok(())
    }

    fn inventory_count(
        &mut self,
        dir: Directory,
        maximum: u64,
        mut names: Option<&mut Vec<Hex32>>,
        deadline: Instant,
    ) -> Result<u64, RecoveryControlError> {
        if !matches!(
            dir,
            Directory::Root | Directory::Operations | Directory::Runtimes
        ) {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        // Locked libc/rustix copies exactly one native dirent name into a
        // CString: Darwin's d_name[1024], Linux's d_name[256]. This is a typed
        // ABI allocation bound, not a new owner-selected quota or an allowance
        // to accept a component longer than the actual host limit.
        let name_bytes = if cfg!(target_os = "macos") {
            1024u64
        } else if cfg!(target_os = "linux") {
            256u64
        } else {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        };
        let layout = std::mem::size_of::<rustix::io::Result<rustix::fs::Dir>>()
            .checked_mul(2)
            .and_then(|n| {
                n.checked_add(
                    2 * std::mem::size_of::<Option<rustix::io::Result<rustix::fs::DirEntry>>>(),
                )
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay(
            (layout as u64)
                .checked_add(std::mem::size_of::<[u8; 32]>() as u64)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?,
            1,
        )?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(dir)?,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let source = self.check_opened(true, deadline)?;
        match dir {
            Directory::Root => {
                if self.root_identity(deadline)? != source {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
            Directory::Operations => {
                self.named_matches(Directory::Root, "operations", source, deadline)?
            }
            Directory::Runtimes => {
                self.named_matches(Directory::Root, "runtimes", source, deadline)?
            }
            _ => unreachable!("closed inventory directory checked before IO"),
        }
        let file = self.take_opened()?;
        before(deadline)?;
        self.raw.directory = Some(rustix::fs::Dir::new(file));
        self.post(deadline)?;
        let mut count = 0u64;
        loop {
            self.prepay(
                name_bytes.checked_mul(2).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?,
                0,
            )?;
            before(deadline)?;
            self.raw.entry = Some(
                self.raw
                    .directory
                    .as_mut()
                    .and_then(|r| r.as_mut().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read(),
            );
            self.post(deadline)?;
            let entry = match self.raw.entry.as_ref() {
                Some(None) => break,
                Some(Some(Ok(e))) => e,
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count = count
                .checked_add(1)
                .filter(|n| *n <= maximum)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if u64::try_from(name.len()).map_or(true, |n| n > self.limits.max_component_bytes) {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            if matches!(dir, Directory::Root) {
                // A descriptor temp names its PublishIntent digest; it is
                // preserved, never repaired or reused.
                let descriptor_temp = name
                    .strip_prefix(b"activation-v1.pending-")
                    .and_then(|digest| std::str::from_utf8(digest).ok())
                    .is_some_and(|digest| hex(digest, 64, false).is_ok());
                if !descriptor_temp
                    && !matches!(
                        name,
                        b"owner.lock"
                            | b"admission.lock"
                            | b"runtime.lock"
                            | b"activation-v1"
                            | b"operations"
                            | b"runtimes"
                    )
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            } else {
                if name.len() != 32 {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(name);
                let nonce = std::str::from_utf8(&nonce)
                    .map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
                let entry_name = Hex32::parse(nonce)?;
                if let Some(names) = names.as_deref_mut() {
                    names.push(entry_name);
                }
                self.reserve_io(0)?;
                before(deadline)?;
                self.raw.named = Some(rustix::fs::statat(
                    self.directory(dir)?,
                    nonce,
                    AtFlags::SYMLINK_NOFOLLOW,
                ));
                self.post(deadline)?;
                let stat = self
                    .raw
                    .named
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    != rustix::fs::FileType::Directory
                    || stat.st_mode & 0o7777 != 0o700
                    || stat.st_uid != self.uid
                    || stat.st_dev as u64 != source.device
                {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
        }
        // A real EOF, same root identity and matching original deadline are
        // required before successful retirement of this directory reader.
        self.root_identity(deadline)?;
        self.raw.entry = None;
        self.raw.directory = None;
        Ok(count)
    }

    fn check_root_namespace(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.inventory_count(
            Directory::Root,
            self.limits.max_root_entries,
            None,
            deadline,
        )
        .map(|_| ())
    }

    pub(super) fn verify_registration_capacity(
        &mut self,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if self.pending_owner.is_none() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        self.held_owner_identity(deadline)?;
        self.check_root_namespace(deadline)?;
        self.inventory_count(
            Directory::Operations,
            self.limits.max_retained_operations,
            None,
            deadline,
        )?;
        let count = self.inventory_count(
            Directory::Runtimes,
            self.limits.max_registered_runtimes,
            None,
            deadline,
        )?;
        if count >= self.limits.max_registered_runtimes {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        Ok(())
    }

    fn held_owner_identity(
        &mut self,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(
            self.pending_owner
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?
                .metadata(),
        );
        self.post(deadline)?;
        let meta = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if meta.len() != 8 {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let held = identity(meta);
        self.named_matches(Directory::Root, "owner.lock", held, deadline)?;
        Ok(held)
    }

    /// Read every immutable enrollment and its exact original close receipt
    /// while holding all three writer locks. Absence is Busy, never closure.
    fn verify_closed_runtime_receipts(
        &mut self,
        control_id: Option<&str>,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        if !self.holds_writer() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        let maximum = usize::try_from(self.limits.max_registered_runtimes)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let reservation = maximum
            .checked_mul(2 * std::mem::size_of::<Hex32>())
            .and_then(|n| {
                n.checked_add(
                    maximum.checked_mul(2 * std::mem::size_of::<RestoreRuntimeReadback>())?,
                )
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay(reservation as u64, 0)?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(maximum)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.restore_runtime_readbacks
            .try_reserve_exact(maximum)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if names.capacity() > maximum.checked_mul(2).ok_or_else(service_invalid)?
            || self.restore_runtime_readbacks.capacity()
                > maximum.checked_mul(2).ok_or_else(service_invalid)?
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        self.inventory_count(
            Directory::Runtimes,
            self.limits.max_registered_runtimes,
            Some(&mut names),
            deadline,
        )?;
        let root = self.root_identity(deadline)?;
        let admission = self.held_lock_identity(true, deadline)?;
        let runtime = self.held_lock_identity(false, deadline)?;
        let cap = self.limits.max_runtime_record_bytes;
        for nonce in names {
            let index = self.restore_runtime_readbacks.len();
            self.restore_runtime_readbacks.push(RestoreRuntimeReadback {
                directory: None,
                enrollment: None,
                receipt: None,
                decoded_enrollment: None,
                decoded_receipt: None,
            });
            // The runtime directory itself, read-only, as `read_journal` opens an operation.
            self.reserve_io(1)?;
            self.raw.file = Some(
                rustix::fs::openat(
                    self.directory(Directory::Runtimes)?,
                    nonce.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            self.post(deadline)?;
            let identity = self.check_opened(true, deadline)?;
            self.named_matches(Directory::Runtimes, nonce.as_str(), identity, deadline)?;
            self.runtime_work = Some(self.take_opened()?);
            self.restore_runtime_readbacks[index].enrollment =
                Some(self.read_record(Directory::RuntimeWork, "enrollment-v1", cap, deadline)?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.named = Some(rustix::fs::statat(
                self.directory(Directory::RuntimeWork)?,
                "receipt-v1",
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            self.post(deadline)?;
            if matches!(self.raw.named, Some(Err(rustix::io::Errno::NOENT))) {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            self.restore_runtime_readbacks[index].receipt =
                Some(self.read_record(Directory::RuntimeWork, "receipt-v1", cap, deadline)?);
            let readback = &self.restore_runtime_readbacks[index];
            let wire_bytes = readback
                .enrollment
                .as_ref()
                .expect("original enrollment retained")
                .bytes
                .len()
                .checked_add(
                    readback
                        .receipt
                        .as_ref()
                        .expect("original receipt retained")
                        .bytes
                        .len(),
                )
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            // Closed values have bounded scalar, string and vector headers;
            // include pinned serde escape scratch before decoding either copy.
            let decode = wire_bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(std::mem::size_of::<RestoreRuntimeEnrollment>()))
                .and_then(|n| n.checked_add(std::mem::size_of::<RestoreRuntimeReceipt>() + 1024))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            self.prepay(decode as u64, 0)?;
            let readback = &mut self.restore_runtime_readbacks[index];
            readback.decoded_enrollment = Some(serde_json::from_slice(
                &readback
                    .enrollment
                    .as_ref()
                    .expect("retained enrollment")
                    .bytes,
            ));
            readback.decoded_receipt = Some(serde_json::from_slice(
                &readback.receipt.as_ref().expect("retained receipt").bytes,
            ));
            self.post(deadline)?;
            let readback = &self.restore_runtime_readbacks[index];
            let enrollment = readback
                .decoded_enrollment
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            let receipt = readback
                .decoded_receipt
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            let owners = &enrollment.original_owner_set;
            let observed = receipt.clock_observations[0];
            enrollment.business_install_binding.validate(&self.limits)?;
            if enrollment.record_type != "wrokbot-runtime-enrollment"
                || enrollment.version != 1
                || Some(enrollment.control_id.as_str()) != control_id
                || enrollment.nonce != nonce
                || enrollment.pid == 0
                || enrollment.process_start.nanos >= 1_000_000_000
                || enrollment.root_and_lock_identities.control_root != root
                || enrollment.root_and_lock_identities.admission_lock != admission
                || enrollment.root_and_lock_identities.runtime_lock != runtime
                || enrollment.authorization_epoch.as_str()
                    != enrollment.business_install_binding.authorization_epoch()
                || owners.is_empty()
                || owners.len() as u64 > self.limits.max_runtime_resource_facts
                || owners
                    .iter()
                    .enumerate()
                    .any(|(i, owner)| owners[..i].contains(owner))
                || receipt.record_type != "wrokbot-runtime-close"
                || receipt.version != 1
                || !enrollment.matches(&receipt.same_identity_tuple)
                || !super::journal::hex_matches(
                    &Sha256::digest(
                        &readback
                            .enrollment
                            .as_ref()
                            .expect("retained enrollment")
                            .bytes,
                    )
                    .into(),
                    receipt.enrollment_digest.as_str(),
                )
                || observed == 0
                || !receipt.retained_unknown_effect_refs.is_empty()
                || receipt.original_resource_facts.len() != owners.len()
                || owners.iter().any(|owner| {
                    receipt
                        .original_resource_facts
                        .iter()
                        .filter(|fact| fact.closed_owner(observed) == Some(*owner))
                        .count()
                        != 1
                })
            {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            super::id(&enrollment.boot_identity, self.limits.max_id_bytes)?;
            self.restore_runtime_readbacks[index].directory = self.runtime_work.take();
        }
        self.post(deadline)
    }

    fn open_restore_selection(
        &mut self,
        slot: usize,
        parent: &Path,
        component: &str,
        limit: Option<u64>,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let depth = parent.components().count();
        let metadata = depth
            .checked_mul(2 * std::mem::size_of::<ServiceAncestor>())
            .and_then(|n| n.checked_add(parent.as_os_str().len().checked_mul(4)?))
            .and_then(|n| n.checked_add(component.len().checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<RestoreHeldSelection>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay(metadata as u64, 0)?;
        if self.restore_selections[slot].is_some() {
            return Err(service_invalid());
        }
        self.restore_selections[slot] = Some(RestoreHeldSelection {
            ancestors: Vec::new(),
            component: component.to_owned(),
            original: None,
            stamp: None,
        });
        let selection = self.restore_selections[slot]
            .as_mut()
            .expect("original selection retained");
        selection
            .ancestors
            .try_reserve_exact(depth)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if selection.ancestors.capacity() > depth.checked_mul(2).ok_or_else(service_invalid)? {
            return Err(service_invalid());
        }
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        self.raw.metadata = Some(
            self.raw
                .file
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                .metadata(),
        );
        self.post(deadline)?;
        let root = service_directory(
            self.raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?,
            self.uid,
        )?;
        let file = self.take_opened()?;
        self.restore_selections[slot]
            .as_mut()
            .expect("retained selection")
            .ancestors
            .push(ServiceAncestor {
                file,
                identity: root,
                component: None,
            });
        for part in parent.components() {
            let Component::Normal(name) = part else {
                if matches!(part, Component::RootDir) {
                    continue;
                }
                return Err(service_invalid());
            };
            self.reserve_io(1)?;
            before(deadline)?;
            let directory = &self.restore_selections[slot]
                .as_ref()
                .expect("retained selection")
                .ancestors
                .last()
                .ok_or_else(service_invalid)?
                .file;
            self.raw.file = Some(
                rustix::fs::openat(
                    directory,
                    name,
                    OFlags::RDONLY
                        | OFlags::DIRECTORY
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC
                        | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            self.post(deadline)?;
            self.raw.metadata = Some(
                self.raw
                    .file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .metadata(),
            );
            self.post(deadline)?;
            let actual = service_directory(
                self.raw
                    .metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(service_invalid)?,
                self.uid,
            )?;
            let directory = &self.restore_selections[slot]
                .as_ref()
                .expect("retained selection")
                .ancestors
                .last()
                .ok_or_else(service_invalid)?
                .file;
            self.raw.named = Some(rustix::fs::statat(
                directory,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            self.post(deadline)?;
            let named = self
                .raw
                .named
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if named.st_dev as u64 != actual.device
                || named.st_ino as u64 != actual.inode
                || named.st_uid != actual.uid
                || rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::Directory
                || actual
                    == self
                        .pending_restore_intent
                        .as_ref()
                        .ok_or_else(service_invalid)?
                        .control_root
            {
                return Err(service_invalid());
            }
            let file = self.take_opened()?;
            self.restore_selections[slot]
                .as_mut()
                .expect("retained selection")
                .ancestors
                .push(ServiceAncestor {
                    file,
                    identity: actual,
                    component: Some(name.to_os_string()),
                });
        }
        if let Some(limit) = limit {
            let parent_metadata = self
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if parent_metadata.uid() != self.uid || parent_metadata.mode() & 0o7777 != 0o700 {
                return Err(service_invalid());
            }
            self.reserve_io(1)?;
            before(deadline)?;
            let directory = &self.restore_selections[slot]
                .as_ref()
                .expect("retained selection")
                .ancestors
                .last()
                .ok_or_else(service_invalid)?
                .file;
            self.raw.file = Some(
                rustix::fs::openat(
                    directory,
                    component,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            self.post(deadline)?;
            self.raw.metadata = Some(
                self.raw
                    .file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .metadata(),
            );
            self.post(deadline)?;
            let stamp = ServiceFileStamp::of(
                self.raw
                    .metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(service_invalid)?,
                self.uid,
            )?;
            if stamp.length == 0 || stamp.length > limit || (slot == 1 && stamp.length != 104) {
                return Err(service_invalid());
            }
            let directory = &self.restore_selections[slot]
                .as_ref()
                .expect("retained selection")
                .ancestors
                .last()
                .ok_or_else(service_invalid)?
                .file;
            self.raw.named = Some(rustix::fs::statat(
                directory,
                component,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            self.post(deadline)?;
            let named = self
                .raw
                .named
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if named.st_dev as u64 != stamp.identity.device
                || named.st_ino as u64 != stamp.identity.inode
                || named.st_uid != self.uid
                || named.st_size as u64 != stamp.length
                || named.st_nlink != 1
                || named.st_mode & 0o7777 != 0o600
            {
                return Err(service_invalid());
            }
            let file = self.take_opened()?;
            let selection = self.restore_selections[slot]
                .as_mut()
                .expect("retained selection");
            selection.stamp = Some(stamp);
            selection.original = Some(file);
        } else {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.metadata = Some(self.parent.as_ref().ok_or_else(service_invalid)?.metadata());
            self.post(deadline)?;
            let actual_parent = identity(
                self.raw
                    .metadata
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(service_invalid)?,
            );
            let selected = self.restore_selections[slot]
                .as_ref()
                .expect("retained selection")
                .ancestors
                .last()
                .ok_or_else(service_invalid)?;
            if selected.identity != actual_parent {
                return Err(service_invalid());
            }
            self.raw.named = Some(rustix::fs::statat(
                &selected.file,
                component,
                AtFlags::SYMLINK_NOFOLLOW,
            ));
            self.post(deadline)?;
            if !matches!(self.raw.named, Some(Err(rustix::io::Errno::NOENT))) {
                return Err(service_invalid());
            }
        }
        self.post(deadline)
    }

    /// Only the pre-effect nonblocking registration failure uses this passive
    /// release. It is never a resource-close, stop, ACK or wait receipt.
    pub(super) fn release_registration_attempt(&mut self) {
        self.existing_read_locks = false;
        self.raw.file = None;
        self.pending_owner = None;
        self.pending_runtime = None;
        self.pending_admission = None;
    }

    pub(super) fn verify_head_digest(
        &mut self,
        expected: &str,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        hex(expected, 64, false)?;
        if self.activation_source.is_none() {
            let fixed = std::mem::size_of::<OwnedRecord>()
                .checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>())
                .and_then(|n| n.checked_add(2 * std::mem::align_of::<OwnedRecord>()))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            self.prepay(fixed as u64, 0)?;
            let record = self.read_record(
                Directory::Root,
                "activation-v1",
                self.limits.max_activation_bytes,
                deadline,
            )?;
            self.activation_source = Some(Arc::new(record));
        }
        // Clone only this existing Arc. The original FD/backing stays in the
        // control owner before every read/postcheck; no repeated head open or
        // new Vec allocation is charged to normal business traffic.
        let source = Arc::clone(
            self.activation_source
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?,
        );
        self.verify_original_record(&source, deadline)?;
        self.named_matches(Directory::Root, "activation-v1", source.identity, deadline)?;
        if self.activation_observation.is_none() {
            let fee = super::activation::read_metadata_reservation(&source.bytes)?
                .checked_add(
                    (2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
                        + 2 * std::mem::align_of::<super::activation::ActivationObservation>())
                        as u64,
                )
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            self.prepay(fee, 0)?;
            before(deadline)?;
            // The original FD/bytes already belong to this ControlFiles. Keep
            // the complete typed observation or parse error here before the
            // original postclock check; a late result is never discarded.
            self.activation_observation =
                Some(super::activation::observe(&source.bytes, &self.limits).map(Arc::new));
            self.post(deadline)?;
        }
        match &self.activation_observation {
            Some(Ok(observation))
                if observation.digest == expected
                    && matches!(
                        observation.record.phase,
                        super::ActivationPhase::OrdinaryActive
                            | super::ActivationPhase::RestoreCurrent
                    ) =>
            {
                ()
            }
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
        }
        // This DATA validation adds no PublishedActivation, PG/key proof or
        // Current grant. The inherited held-byte digest check still follows.
        let mut hash = Sha256::new();
        hash.update(b"wrokbot.restore.activation.v1\0");
        hash.update(&source.bytes);
        let digest: [u8; 32] = hash.finalize().into();
        if !super::journal::hex_matches(&digest, expected) {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        if let Some(journal) = self.publication_journal.as_ref().map(Arc::clone) {
            let (context, expected) = self.publication_operation.ok_or_else(service_invalid)?;
            self.reserve_io(0)?;
            self.raw.metadata = Some(self.directory(Directory::OperationWork)?.metadata());
            self.post(deadline)?;
            let actual = self
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            self.valid_meta(actual, true)?;
            if identity(actual) != expected {
                return Err(service_invalid());
            }
            let context = std::str::from_utf8(&context).map_err(|_| service_invalid())?;
            self.named_matches(Directory::Operations, context, expected, deadline)?;
            self.verify_original_record(&journal, deadline)?;
            self.named_matches(
                Directory::OperationWork,
                "journal-v1",
                journal.identity,
                deadline,
            )?;
        }
        self.post(deadline)
    }

    fn verify_original_record(
        &mut self,
        original: &OwnedRecord,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let meta = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if identity(meta) != original.identity
            || Some(meta.len()) != u64::try_from(original.bytes.len()).ok()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let mut offset = 0usize;
        while offset < original.bytes.len() {
            let end = original
                .bytes
                .len()
                .min(offset.checked_add(8).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(
                original
                    .file
                    .read_at(&mut self.raw.small[..end - offset], offset as u64),
            );
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0
                || n > end - offset
                || self.raw.small[..n] != original.bytes[offset..offset + n]
            {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            offset = offset
                .checked_add(n)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let meta = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if identity(meta) != original.identity
            || Some(meta.len()) != u64::try_from(original.bytes.len()).ok()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }

    pub(super) fn held_lock_identity(
        &mut self,
        admission: bool,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        let result = (if admission {
            self.pending_admission.as_ref()
        } else {
            self.pending_runtime.as_ref()
        })
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?
        .metadata();
        self.raw.metadata = Some(result);
        self.post(deadline)?;
        let m = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        let held = identity(m);
        if m.len() != 8 {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.named_matches(
            Directory::Root,
            if admission {
                "admission.lock"
            } else {
                "runtime.lock"
            },
            held,
            deadline,
        )?;
        Ok(held)
    }

    pub(super) fn verify_held_lock(
        &mut self,
        original: &File,
        name: &str,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        if name != "admission.lock" && name != "runtime.lock" && name != "owner.lock" {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.metadata());
        self.post(deadline)?;
        let m = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        let held = identity(m);
        if m.len() != 8 {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.named_matches(Directory::Root, name, held, deadline)?;
        Ok(held)
    }

    pub(super) fn verify_runtime_enrollment(
        &mut self,
        directory: &File,
        nonce: &str,
        original: &OwnedRecord,
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        hex(nonce, 32, true)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(directory.metadata());
        self.post(deadline)?;
        let m = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, true)?;
        let held = identity(m);
        self.named_matches(Directory::Runtimes, nonce, held, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let m = self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        if identity(m) != original.identity
            || u64::try_from(original.bytes.len()).ok() != Some(m.len())
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        let mut offset = 0usize;
        while offset < original.bytes.len() {
            let end = original
                .bytes
                .len()
                .min(offset.checked_add(8).ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
                })?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(
                original
                    .file
                    .read_at(&mut self.raw.small[..end - offset], offset as u64),
            );
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0
                || n > end - offset
                || self.raw.small[..n] != original.bytes[offset..offset + n]
            {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            offset = offset
                .checked_add(n)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.named = Some(rustix::fs::statat(
            directory,
            "enrollment-v1",
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let named = self
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != original.identity.device
            || named.st_ino as u64 != original.identity.inode
            || named.st_uid != original.identity.uid
            || named.st_size as u64 != original.bytes.len() as u64
            || named.st_mode & 0o7777 != 0o600
            || named.st_nlink != 1
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }

    pub(super) fn create_runtime_directory(
        &mut self,
        nonce: &str,
        deadline: Instant,
    ) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        hex(nonce, 32, true)?;
        component(nonce, &self.limits)?;
        if self.runtime_work.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::mkdirat(
                self.directory(Directory::Runtimes)?,
                nonce,
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => (),
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
            }
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
        self.sync_directory(Directory::Runtimes, deadline)?;
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(Directory::Runtimes)?,
                nonce,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let held = self.check_opened(true, deadline)?;
        if held.device != self.root_identity(deadline)?.device {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.named_matches(Directory::Runtimes, nonce, held, deadline)?;
        self.runtime_work = Some(self.take_opened()?);
        Ok(held)
    }

    /// The known enrollment/receipt name is published without replacement.
    /// Every temporary FD and full result remains in this owner on failure.
    pub(super) fn publish_runtime_close_record(
        &mut self,
        original_directory: &File,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<OwnedRecord, RecoveryControlError> {
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(original_directory.try_clone());
        self.post(deadline)?;
        self.runtime_work = Some(self.take_opened()?);
        self.publish_runtime_record("receipt-v1", bytes, deadline)?;
        self.runtime_work = None;
        self.runtime_record
            .take()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ClosureUnproven))
    }

    pub(super) fn publish_runtime_record(
        &mut self,
        name: &str,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let temporary = match name {
            "enrollment-v1" => "enrollment-v1.pending",
            "receipt-v1" => "receipt-v1.pending",
            _ => {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
        };
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |n| n > self.limits.max_runtime_record_bytes)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(
            rustix::fs::openat(
                self.directory(Directory::RuntimeWork)?,
                temporary,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        let original = self.check_opened(false, deadline)?;
        self.named_matches(Directory::RuntimeWork, temporary, original, deadline)?;
        let mut offset = 0usize;
        while offset < bytes.len() {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(match self.raw.file.as_ref() {
                Some(Ok(f)) => {
                    let mut f = f;
                    f.write(&bytes[offset..])
                }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            });
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 {
                return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
            }
            offset = offset
                .checked_add(n)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            self.raw
                .file
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                .sync_all(),
        );
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        // Read back the original held file, not a receipt supplied by a caller.
        self.verify_raw_bytes(bytes, deadline)?;
        self.named_matches(Directory::RuntimeWork, temporary, original, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::linkat(
                self.directory(Directory::RuntimeWork)?,
                temporary,
                self.directory(Directory::RuntimeWork)?,
                name,
                AtFlags::empty(),
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        self.named_matches(Directory::RuntimeWork, name, original, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(
            rustix::fs::unlinkat(
                self.directory(Directory::RuntimeWork)?,
                temporary,
                AtFlags::empty(),
            )
            .map_err(io::Error::from),
        );
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        self.sync_directory(Directory::RuntimeWork, deadline)?;
        if self.check_opened(false, deadline)? != original {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.verify_raw_bytes(bytes, deadline)?;
        self.named_matches(Directory::RuntimeWork, name, original, deadline)?;
        let cap = self.limits.max_runtime_record_bytes;
        self.runtime_record =
            Some(self.read_record(Directory::RuntimeWork, name, cap, deadline)?);
        if self
            .runtime_record
            .as_ref()
            .map(|r| (r.identity, r.bytes.as_slice()))
            != Some((original, bytes))
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        self.post(deadline)
    }

    fn verify_raw_bytes(
        &mut self,
        expected: &[u8],
        deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.prepay(
            (std::mem::size_of::<[u8; 8]>() + std::mem::size_of::<usize>()) as u64,
            0,
        )?;
        let mut offset = 0usize;
        while offset < expected.len() {
            let end = expected.len().min(offset.checked_add(8).ok_or_else(|| {
                RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
            })?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(
                self.raw
                    .file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read_at(&mut self.raw.small[..end - offset], offset as u64),
            );
            self.post(deadline)?;
            let n = *self
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 || n > end - offset || self.raw.small[..n] != expected[offset..offset + n] {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            offset = offset
                .checked_add(n)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        let held = self.check_opened(false, deadline)?;
        held.validate()?;
        if self
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(Metadata::len)
            != u64::try_from(expected.len()).ok()
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::ControlInvalid,
            ));
        }
        Ok(())
    }
}

/// Existing ordinary Server DATA is never allowed to mint a head. The same
/// actual read locks precede every bootstrap probe and survive into enrollment.
/// Seal the Server entry intent from the one ordinary intent loaded with the
/// service configuration (S1); the intent file is not opened again.
#[cfg(feature = "server-runtime")]
pub(super) fn server_intent(
    owner: &ControlOwner,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    owners: &[super::runtime::RuntimeOwner],
) -> Result<super::ordinary::VerifiedOrdinaryStartupIntent, RecoveryControlError> {
    use super::ordinary::{
        OrdinaryInitializationSource, OrdinarySite, SiteExpectation, VerifiedOrdinaryStartupIntent,
    };
    let files = lock(owner)?;
    let source = files.service_source.as_ref().ok_or_else(service_invalid)?;
    let configuration = &source.configuration;
    let expected = &configuration.expected_installation_binding;
    if expected.deployment_id != deployment.as_str() || expected.tenant_id != tenant.as_str() {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::EntryInvalid,
        ));
    }
    let origin = source.original_ordinary_input.as_ref().map(|input| {
        let kind = match input.intent.mode {
            ServiceOrdinaryMode::FreshInit => OrdinaryInitializationSource::ServerDatabaseFresh,
            ServiceOrdinaryMode::LegacyAdoption => OrdinaryInitializationSource::LegacyAdoption {
                site: OrdinarySite::ServerDatabase,
            },
        };
        (kind, input.intent.request_id, input.input.stamp.identity)
    });
    let config = &source.original_config;
    let site = SiteExpectation::Server {
        dataset: expected.dataset_id,
        ids: [
            expected.deployment_id.clone(),
            expected.tenant_id.clone(),
            expected.source_installation_id.clone(),
            expected.target_installation_id.clone(),
        ],
        database: configuration.expected_server_database,
        service_config: ServiceConfigRef {
            file: config.stamp.identity,
            length: config.stamp.length,
            digest: Hex64::of(&Sha256::digest(&config.bytes).into()),
        },
        owner: super::activation::ActualOsOwner::ConfiguredService {
            uid: source.uid,
            service: configuration.expected_service_owner.service.clone(),
        },
    };
    VerifiedOrdinaryStartupIntent::seal(
        origin,
        site,
        configuration.ordinary_startup_bounds,
        configuration.host_limits.admission_ns,
        owners,
    )
}

/// Seal the Local producer's expected original host before any installation write.
#[cfg(feature = "desktop-local")]
pub(super) fn local_legacy_intent(
    owner: &ControlOwner,
    request: VerifiedRecoveryHostIntent,
    owners: &[super::runtime::RuntimeOwner],
) -> Result<super::ordinary::VerifiedOrdinaryStartupIntent, RecoveryControlError> {
    use super::ordinary::{LocalSiteExpectation, OrdinaryInitializationSource, OrdinarySite, SiteExpectation, VerifiedOrdinaryStartupIntent};
    let mut original = Some(request);
    let result = (|| {
        let mut files = lock(owner)?;
        let request = original.as_mut().expect("original request retained");
        let deadline = request.original_deadline;
        if files.root_identity(deadline)? != request.control_root { return Err(service_invalid()); }
        request.host.recheck_original(deadline)?;
        let DecodedRecoveryRequest::Legacy(decoded) = &request.decoded else { return Err(service_invalid()); };
        let metadata = request.request_bytes.len().checked_mul(4).and_then(|n| n.checked_add(std::mem::size_of::<VerifiedOrdinaryStartupIntent>() + owners.len() * 2 * std::mem::size_of::<super::runtime::RuntimeOwner>())).ok_or_else(service_invalid)?;
        files.prepay(metadata as u64, 0)?;
        let (root, parent, component) = files.observe_local_root(deadline)?;
        let root = root.ok_or_else(service_invalid)?;
        let expected = &decoded.expected;
        let ids = super::journal::BusinessAndInstallation { deployment_id: expected.deployment_id.clone(), tenant_id: expected.tenant_id.clone(), dataset_id: expected.dataset_id.as_str().to_owned(), source_installation_id: expected.source_installation_id.as_str().to_owned(), target_installation_id: expected.target_installation_id.as_str().to_owned() };
        let source = (OrdinaryInitializationSource::LegacyAdoption { site: OrdinarySite::LocalPhysical }, decoded.request_id, request.request.identity);
        let site = SiteExpectation::Local(LocalSiteExpectation { root: Some(root), parent, component, release: Hex64::of(&request.host.reviewed_release_digest), master_service: request.host.services[0].clone(), postgres_service: request.host.services[1].clone(), installation_id: Some(ids.target_installation_id.clone()), legacy_expected: Some(ids) });
        let bounds = decoded.limits;
        let admission_ns = files.limits.admission_ns;
        drop(files);
        VerifiedOrdinaryStartupIntent::seal_local_legacy(source, site, bounds, admission_ns, owners, original.take().expect("original entry transferred once"), deadline)
    })();
    result.map_err(|mut error: RecoveryControlError| { if original.is_some() { error.retained_restore_intent = original.take().map(Box::new); } error.retain(owner) })
}

#[cfg(feature = "desktop-local")]
pub(super) fn recheck_legacy_request_before(files: &mut ControlFiles, request: &mut VerifiedRecoveryHostIntent, deadline: Instant) -> Result<(), RecoveryControlError> {
    request.host.recheck_original(deadline)?;
    files.raw.metadata = Some(request.request.file.as_ref().ok_or_else(service_invalid)?.metadata());
    files.post(deadline)?;
    let metadata = files.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
    let stamp = ServiceFileStamp::of(metadata, files.uid)?;
    if stamp.identity != request.request.identity || stamp.length != request.request_bytes.len() as u64 { return Err(service_invalid()); }
    files.raw.named = Some(rustix::fs::statat(&request.request.parent, request.request.component.as_str(), AtFlags::SYMLINK_NOFOLLOW));
    files.post(deadline)?;
    let named = files.raw.named.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
    if named.st_dev as u64 != stamp.identity.device || named.st_ino as u64 != stamp.identity.inode || named.st_size as u64 != stamp.length || named.st_nlink != 1 || named.st_mode & 0o7777 != 0o600 || named.st_uid != files.uid { return Err(service_invalid()); }
    let mut offset = 0;
    while offset < request.request_bytes.len() {
        let count = (request.request_bytes.len() - offset).min(8);
        before(deadline)?;
        files.raw.unit = Some(request.request.file.as_ref().ok_or_else(service_invalid)?.read_exact_at(&mut files.raw.small[..count], offset as u64));
        files.post(deadline)?;
        if !matches!(files.raw.unit, Some(Ok(()))) || files.raw.small[..count] != request.request_bytes[offset..offset+count] { return Err(service_invalid()); }
        offset += count;
    }
    files.raw.metadata = Some(request.request.file.as_ref().ok_or_else(service_invalid)?.metadata());
    files.post(deadline)?;
    if ServiceFileStamp::of(files.raw.metadata.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(service_invalid)?, files.uid)? != stamp { return Err(service_invalid()); }
    Ok(())
}

#[cfg(all(feature = "desktop-local", feature = "server-runtime"))]
pub(super) fn enter_current_reconfirmation(
    owner: &ControlOwner,
    request: &mut VerifiedRecoveryHostIntent,
    creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
    owners: &[super::runtime::RuntimeOwner],
    cancel: crate::restore_reconfirmation::CancellationToken,
) -> Result<(super::runtime::RecoveryRuntimeOwner, crate::restore_reconfirmation::OriginalReconfirmationRequest, Instant), RecoveryControlError> {
    {
        let mut files = lock(owner)?;
        let deadline = request.original_deadline;
        recheck_legacy_request_before(&mut files, request, deadline)?;
        if files.root_identity(deadline)? != request.control_root { return Err(service_invalid()); }
        files.prepay(std::mem::size_of::<crate::restore_reconfirmation::OriginalReconfirmationRequest>() as u64, 0)?;
    }
    let DecodedRecoveryRequest::Current(current) = &mut request.decoded else { return Err(service_invalid()); };
    if current.issued { return Err(service_invalid()); }
    current.issued = true;
    let intent = local_intent(owner, creator, request.host.reviewed_release_digest,
        [&request.host.services[0], &request.host.services[1]], current.limits, owners)?;
    let admission = intent.admission_deadline().min(request.original_deadline);
    let (published, intent) = super::ordinary::shared_local_head(owner, intent, admission, creator)?;
    let binding = published.binding().ordinary_local()?;
    let expected = &current.expected;
    if published.restore_cohort().is_none()
        || published.binding().source_installation_id() != expected.source_installation_id.as_str()
        || binding.deployment_id != expected.deployment_id
        || binding.tenant_id != expected.tenant_id
        || binding.dataset_id != expected.dataset_id.as_str()
        || binding.installation_id != expected.target_installation_id.as_str()
    { lock(owner)?.release_registration_attempt(); return Err(service_invalid()); }
    let sql = crate::restore_reconfirmation::OriginalReconfirmationRequest::for_current_local(
        intent.effect_deadline(), cancel, uuid::Uuid::from_bytes(super::hex_array(current.request_id.as_str())),
    );
    let convergence = intent.convergence_deadline();
    let runtime = super::ordinary::enroll(owner, published, &intent)?;
    Ok((runtime, sql, convergence))
}

#[cfg(feature = "desktop-local")]
pub(super) fn local_intent(
    owner: &ControlOwner,
    creator: &crate::auth::single_user::desktop_local::DesktopLocalAuthorityStore,
    release: [u8; 32],
    services: [&str; 2],
    bounds: OrdinaryStartupBounds,
    owners: &[super::runtime::RuntimeOwner],
) -> Result<super::ordinary::VerifiedOrdinaryStartupIntent, RecoveryControlError> {
    use super::ordinary::{LocalSiteExpectation, SiteExpectation, VerifiedOrdinaryStartupIntent};
    let t0 = Instant::now();
    let t0_ns = super::clock::monotonic_ns()?;
    let mut files = lock(owner)?;
    let admission_ns = files.limits.admission_ns;
    let deadline = t0
        .checked_add(std::time::Duration::from_nanos(
            admission_ns.min(bounds.effect_ns.get()),
        ))
        .ok_or_else(service_invalid)?;
    let expected_path = files
        .root_path
        .parent()
        .ok_or_else(service_invalid)?
        .join(files.app_component.as_ref().ok_or_else(service_invalid)?);
    if creator.original_app_data_root() != expected_path {
        return Err(service_invalid());
    }
    let (root, parent, component) = files.observe_local_root(deadline)?;
    let site = SiteExpectation::Local(LocalSiteExpectation {
        root,
        parent,
        component,
        release: Hex64::of(&release),
        master_service: services[0].to_owned(),
        postgres_service: services[1].to_owned(),
        installation_id: None,
        legacy_expected: None,
    });
    drop(files);
    VerifiedOrdinaryStartupIntent::seal_at(None, site, bounds, admission_ns, owners, t0, t0_ns)
}

/// `authority` is the ordinary installation's own; a restored Current has
/// none before its subject confirmation, and its accounts are the operation's
/// target slots (spec revision R484 ¶8023).
#[cfg(feature = "desktop-local")]
pub(super) async fn verify_local_binding_before(
    control: &ControlOwner,
    binding: &super::ActivationBinding,
    authority: Option<&crate::auth::single_user::desktop_local::DesktopLocalAuthority>,
    database: &crate::db::desktop_local::DesktopLocalDatabase,
    canary: &crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary,
    services: [&str; 2],
    deadline: Instant,
) -> Result<(), RecoveryControlError> {
    before(deadline)?;
    let expected = binding.ordinary_local()?;
    let accounts = match authority {
        Some(authority) => {
            if expected.installation_id != authority.instance_id()
                || expected.deployment_id != authority.auth_context().deployment().as_str()
                || expected.tenant_id != authority.auth_context().tenant().as_str()
            {
                return Err(service_invalid());
            }
            authority.instance_id().to_owned()
        }
        None => format!("{}-r-{}", expected.installation_id, expected.postgres.operation_id),
    };
    if !canary
        .matches_database(database)
        .await
        .map_err(|_| service_invalid())?
        || expected.dataset_id != canary.dataset_id()
        || expected.deployment_id != canary.deployment_id()
        || expected.tenant_id != canary.tenant_id()
        || expected.master.reviewed_service != services[0]
        || expected.postgres.reviewed_service != services[1]
        || expected.master.account != format!("desktop-vault-master-v1-{accounts}")
        || expected.master.key_id != canary.key_id()
        || i64::from(expected.master.key_version) != i64::from(canary.key_version())
        || expected.postgres.account != format!("postgresql-17-{accounts}")
        || expected.postgres.key_id != expected.postgres.account
        || expected.postgres.key_version != 1
    {
        return Err(service_invalid());
    }
    let client = database.pool().get().await.map_err(|_| service_invalid())?;
    let row = client.query_one(
        "SELECT pcs.system_identifier::text AS system_identifier, d.oid AS database_oid, current_setting('server_version_num')::int / 10000 AS pg_major FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
        &[],
    ).await.map_err(|_| service_invalid())?;
    if row
        .try_get::<_, String>("system_identifier")
        .ok()
        .and_then(|id| id.parse::<u64>().ok())
        != Some(expected.pg_system_id)
        || row.try_get::<_, u32>("database_oid").ok() != Some(expected.database_oid)
        || row.try_get::<_, i32>("pg_major").ok() != Some(17)
    {
        return Err(service_invalid());
    }
    let layout = crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(&client)
        .await
        .map_err(|_| service_invalid())?;
    let native_version = i32::try_from(binding.native_version()).map_err(|_| service_invalid())?;
    let digest: String = client
        .query_one(
            "SELECT checksum FROM openbot_internal.schema_migrations WHERE version = $1",
            &[&native_version],
        )
        .await
        .and_then(|row| row.try_get(0))
        .map_err(|_| service_invalid())?;
    if layout.native_version() != native_version || binding.migration_digest() != digest {
        return Err(service_invalid());
    }
    drop(client);
    let mut files = lock(control)?;
    files.verify_local_root_before(expected.generation_root, deadline)?;
    files.bind_original_local_pool(database.pool());
    Ok(())
}

/// Connect the bootstrap Pool for this Server site and keep it, with its first
/// client, in the control owner for the runtime read gate.
#[cfg(feature = "server-runtime")]
pub(super) async fn connect_server_before(
    owner: &ControlOwner,
    database: &crate::db::pool::DatabaseConfig,
    deadline: Instant,
) -> Result<crate::db::pool::DatabasePool, RecoveryControlError> {
    let mut packet = crate::db::initialization::OwnedExistingServerDatabase::new();
    packet.pool = Some(crate::db::pool::connect(database).await);
    let pool = packet.pool()?.clone();
    packet.client = Some(pool.get().await);
    let mut files = lock(owner)?;
    if files.existing_server.is_some() {
        return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
    }
    files.existing_server = Some(packet);
    files.post(deadline)?;
    Ok(pool)
}

/// Site checks against a sealed Server binding on one connection: identity,
/// principals and database owner, no known restore, and the KEK canary whose
/// key id is keyRefs[0] (R83 P2-2).
#[cfg(feature = "server-runtime")]
pub(super) async fn compare_server_site_before(
    client: &tokio_postgres::Client,
    binding: &super::activation::ActivationBinding,
    database: &crate::db::pool::DatabaseConfig,
    configured: &crate::auth::config::KeyEncryptionKey,
    dataset: &Hex32,
    deadline: Instant,
) -> Result<(), RecoveryControlError> {
    let binding = binding.ordinary_server()?;
    let row = client
        .query_one(crate::db::initialization::EXISTING_SERVER_IDENTITY_SQL, &[])
        .await
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
    let text = |column: &str| row.try_get::<_, String>(column).ok();
    let principal = text("authenticated_principal").ok_or_else(service_invalid)?;
    if text("system_identifier").and_then(|v| v.parse::<u64>().ok())
        != Some(binding.server_database.pg_system_id)
        || row.try_get::<_, u32>("database_oid").ok() != Some(binding.server_database.database_oid)
        || row.try_get::<_, i32>("pg_major").ok() != Some(17)
        || principal != binding.server_database.authenticated_principal
        || text("current_principal").as_ref() != Some(&principal)
        || principal != database.user
        || text("database_owner").as_deref()
            != Some(binding.server_database.database_owner.as_str())
        || binding.postgres.key_id != principal
        || binding.postgres.key_version != 1
    {
        return Err(service_invalid());
    }
    let known_restore: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations)",
            &[],
        )
        .await
        .and_then(|row| row.try_get(0))
        .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
    if known_restore {
        return Err(service_invalid());
    }
    let deployment = openbot_contracts::ids::DeploymentId::new(binding.deployment_id);
    let tenant = openbot_contracts::ids::TenantId::new(binding.tenant_id);
    let key_id = crate::db::initialization::verify_server_canary(
        client,
        configured,
        &deployment,
        &tenant,
        dataset,
    )
    .await?;
    if key_id.as_ref().map(Hex32::as_str) != Some(binding.master.key_id.as_str())
        || binding.master.key_version != 1
    {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::KeyUnverified,
        ));
    }
    before(deadline)
}

/// Existing latest-version Server head under SH (S8 step 2): connect in SH,
/// compare the site, then the current schema on the same connection, and
/// recheck the head digest and service source.
#[cfg(feature = "server-runtime")]
pub(super) async fn verify_existing_server_before(
    owner: &ControlOwner,
    published: &PublishedActivation,
    database: &crate::db::pool::DatabaseConfig,
    configured: &crate::auth::config::KeyEncryptionKey,
    dataset: &Hex32,
    deadline: Instant,
) -> Result<crate::db::pool::DatabasePool, RecoveryControlError> {
    let result = async {
        let pool = connect_server_before(owner, database, deadline).await?;
        let client = pool
            .get()
            .await
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        let binding = published.binding();
        compare_server_site_before(&client, binding, database, configured, dataset, deadline)
            .await?;
        let latest = crate::db::native::NATIVE_LATEST_VERSION;
        crate::db::native::validate_current(&client)
            .await
            .map_err(|_| service_invalid())?;
        let layout = crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(&client)
            .await
            .map_err(|_| service_invalid())?;
        crate::db::thread_history_writer_schema::verify(&client)
            .await
            .map_err(|_| service_invalid())?;
        let checksum: String = client
            .query_one(
                "SELECT checksum FROM openbot_internal.schema_migrations WHERE version = $1",
                &[&latest],
            )
            .await
            .and_then(|row| row.try_get(0))
            .map_err(|_| service_invalid())?;
        if layout.native_version() != latest
            || i64::from(binding.native_version()) != i64::from(latest)
            || binding.migration_digest() != checksum
        {
            return Err(service_invalid());
        }
        let mut files = lock(owner)?;
        files.verify_head_digest(published.digest(), deadline)?;
        files
            .service_source
            .as_mut()
            .ok_or_else(service_invalid)?
            .recheck_original(deadline)?;
        files.post(deadline)?;
        Ok(pool)
    }
    .await;
    result.map_err(|error: RecoveryControlError| {
        if let Ok(mut files) = lock(owner) {
            files.latch(error.fault());
        }
        error.retain(owner)
    })
}

pub(super) fn open_control(
    config: RecoveryControlConfig,
) -> Result<ControlOwner, RecoveryControlError> {
    open_control_inner(config, true)
}

pub(super) fn open_existing_control(config: RecoveryControlConfig) -> Result<ControlOwner, RecoveryControlError> {
    open_control_inner(config, false)
}

fn open_control_inner(config: RecoveryControlConfig, create_layout: bool) -> Result<ControlOwner, RecoveryControlError> {
    if !config.root.is_absolute() {
        return Err(RecoveryControlError::new(
            RecoveryControlFault::EntryInvalid,
        ));
    }
    let fixed = std::mem::size_of::<ControlFiles>()
        .checked_add(std::mem::size_of::<Mutex<ControlBook>>())
        .and_then(|n| n.checked_add(std::mem::size_of::<ControlAccess>()))
        .and_then(|n| {
            n.checked_add(std::mem::size_of::<
                Result<ControlAccess, RecoveryControlError>,
            >())
        })
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()))
        .and_then(|n| n.checked_add(2 * std::mem::align_of::<ControlFiles>()))
        .and_then(|n| n.checked_add(config.root.capacity()))
        .and_then(|n| {
            n.checked_add(
                config
                    .app_component
                    .as_ref()
                    .map_or(0, std::ffi::OsString::capacity),
            )
        })
        .and_then(|n| n.checked_add(static_io_fee() as usize))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_nanos(config.limits.admission_ns))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
    let deadline = config.original_admission_deadline.map_or(deadline, |original| original.min(deadline));
    let mut budget = ControlBudget {
        metadata: 0,
        files: 0,
        metadata_limit: config.limits.max_metadata_bytes,
        file_limit: config.limits.max_open_files,
    };
    let root_name = config
        .root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    let fixed = fixed
        .checked_add(
            root_name
                .len()
                .checked_mul(2)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?,
        )
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    budget.charge(fixed as u64, u64::from(config.service_source.is_some()))?;
    if let Some((bytes, files)) = config.preheld_restore_usage { budget.charge(bytes, files)?; }
    // The original fixed fee contains the source object's inline storage and
    // one configuration FD. Its actual additional retained backing/FDs remain
    // in the same original control budget; they are never counted as zero.
    if let Some(source) = &config.service_source {
        let (bytes, files) = source.retained_usage()?;
        budget.charge(bytes, files.checked_sub(1).ok_or_else(service_invalid)?)?;
    }
    let root_component = root_name.to_owned();
    component(&root_component, &config.limits)?;
    let shared = Arc::new(Mutex::new(ControlBook {
        files: Some(ControlFiles {
            root: None,
            parent: None,
            ancestors: Vec::new(),
            operations: None,
            runtimes: None,
            operation_work: None,
            runtime_work: None,
            root_path: config.root,
            root_component,
            app_component: config.app_component,
            uid: config.uid,
            limits: config.limits,
            budget,
            raw: RawIo {
                file: None,
                metadata: None,
                named: None,
                unit: None,
                count: None,
                small: [0; 8],
                directory: None,
                entry: None,
            },
            original_process: None,
            original_process_evidence: None,
            raw_process_evidence: None,
            raw_process_clock: None,
            process_monotonic_ns: 0,
            scratch: Vec::new(),
            first_fault: None,
            activation_source: None,
            activation_observation: None,
            publication_journal: None,
            publication_operation: None,
            publication_chain: None,
            publication_seal: None,
            existing_server: None,
            #[cfg(feature = "desktop-local")]
            local_root: None,
            #[cfg(feature = "desktop-local")]
            selected_local_component: None,
            #[cfg(feature = "desktop-local")]
            local_creation: None,
            #[cfg(feature = "desktop-local")]
            existing_local_pool: None,
            existing_read_locks: false,
            runtime_entropy: [0; 16],
            raw_random: None,
            pending_admission: None,
            pending_runtime: None,
            pending_owner: None,
            pending_request: None,
            pending_host: None,
            raw_request_decode: None,
            preheld_restore_usage: config.preheld_restore_usage,
            service_source: config.service_source,
            runtime_record: None,
            pending_startup: None,
            runtime_input: Vec::new(),
            raw_encoding: None,
            retained_runtime: None,
            journal_tail: None,
            writer_held: false,
            restore_runtime_readbacks: Vec::new(),
            restore_operation: None,
            closing_observation: None,
            pending_restore_intent: None,
            pending_restore_clock: None,
            #[cfg(feature = "server-runtime")]
            restore_input_buffer: None,
            #[cfg(feature = "server-runtime")]
            restore_input_metadata: [None, None],
            #[cfg(feature = "server-runtime")]
            restore_input: None,
            restore_selections: std::array::from_fn(|_| None),
            restore_isolation_work: None,
            restore_entropy: [0; 96],
        }),
        retired_metadata: 0,
        retired_files: 0,
        fault: None,
        retained_candidate: None,
    }));
    let result = (|| {
        let mut state = lock(&shared)?;
        state.initialize_original_process(deadline)?;
        if let Some(source) = &mut state.service_source {
            source.recheck_original(deadline)?;
        }
        let parent_bytes = state
            .root_path
            .parent()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
            .as_os_str()
            .as_bytes()
            .len();
        let parent_fee = parent_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<PathBuf>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(parent_fee as u64, 0)?;
        let parent_path = state
            .root_path
            .parent()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
            .to_path_buf();
        let depth = parent_path.components().count();
        if depth == 0 || depth as u64 > state.limits.max_path_depth {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        let ancestor_backing = depth
            .checked_mul(std::mem::size_of::<File>())
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(ancestor_backing as u64, depth as u64)?;
        state
            .ancestors
            .try_reserve_exact(depth)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if state.ancestors.capacity()
            > depth
                .checked_mul(2)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        state.raw.file = Some(
            rustix::fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        state.post(deadline)?;
        let first = state.take_opened()?;
        state.ancestors.push(first);
        for c in parent_path.components() {
            let Component::Normal(name) = c else {
                if matches!(c, Component::RootDir) {
                    continue;
                }
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            };
            state.reserve_io(0)?;
            let previous = state
                .ancestors
                .last()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            state.raw.file = Some(
                rustix::fs::openat(
                    previous,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            state.post(deadline)?;
            let result = state
                .raw
                .file
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                .metadata();
            state.raw.metadata = Some(result);
            state.post(deadline)?;
            let m = state
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if !m.is_dir() || (m.uid() != 0 && m.uid() != state.uid) || m.mode() & 0o022 != 0 {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            let file = state.take_opened()?;
            state.ancestors.push(file);
        }
        let parent = state
            .ancestors
            .pop()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        state.parent = Some(parent);
        if let Some(source) = &state.service_source {
            let expected = source
                .control_selection
                .parent
                .ancestors
                .last()
                .ok_or_else(service_invalid)?
                .identity;
            state.raw.metadata = Some(
                state
                    .parent
                    .as_ref()
                    .ok_or_else(service_invalid)?
                    .metadata(),
            );
            state.post(deadline)?;
            let actual = state
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(service_invalid)?;
            if identity(actual) != expected {
                return Err(service_invalid());
            }
        }
        if create_layout {
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.unit = Some({
            let parent = state
                .parent
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            rustix::fs::mkdirat(parent, state.root_component.as_str(), Mode::RWXU)
                .map_err(io::Error::from)
        });
        state.post(deadline)?;
        if let Some(Err(error)) = &state.raw.unit {
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
            }
        }
        if matches!(state.raw.unit, Some(Ok(()))) {
            state.reserve_io(0)?;
            before(deadline)?;
            state.raw.unit = Some(
                state
                    .parent
                    .as_ref()
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?
                    .sync_all(),
            );
            state.post(deadline)?;
            if !matches!(state.raw.unit, Some(Ok(()))) {
                return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
            }
        }
        }
        state.reserve_io(1)?;
        before(deadline)?;
        state.raw.file = Some(
            rustix::fs::openat(
                state.parent.as_ref().ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
                })?,
                state.root_component.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from),
        );
        state.post(deadline)?;
        state.check_opened(true, deadline)?;
        state.root = Some(state.take_opened()?);
        let root = state.root_identity(deadline)?;
        if let Some(expected) = state
            .service_source
            .as_ref()
            .and_then(|source| source.control_selection.existing.as_ref())
            .map(|root| root.identity)
        {
            if root != expected {
                return Err(service_invalid());
            }
        }
        if state.app_component.is_some() {
            state.reserve_io(0)?;
            before(deadline)?;
            state.raw.named = Some({
                let parent = state.parent.as_ref().ok_or_else(|| {
                    RecoveryControlError::new(RecoveryControlFault::ControlInvalid)
                })?;
                rustix::fs::statat(
                    parent,
                    state
                        .app_component
                        .as_ref()
                        .expect("actual local sibling component")
                        .as_os_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
            });
            state.post(deadline)?;
            match state.raw.named.as_ref() {
                Some(Ok(s))
                    if rustix::fs::FileType::from_raw_mode(s.st_mode)
                        == rustix::fs::FileType::Directory
                        && s.st_uid == state.uid
                        && s.st_mode & 0o7777 == 0o700
                        && (s.st_dev as u64 != root.device || s.st_ino as u64 != root.inode) =>
                {
                    ()
                }
                Some(Err(e)) if *e == rustix::io::Errno::NOENT => (),
                _ => {
                    return Err(RecoveryControlError::new(
                        RecoveryControlFault::ControlInvalid,
                    ));
                }
            }
        }
        // Only fixed control metadata is bootstrapped, never a head or epoch.
        for (name, slot) in [
            ("operations", Directory::Operations),
            ("runtimes", Directory::Runtimes),
        ] {
            if create_layout { state.ensure_directory(name, deadline)?; }
            state.reserve_io(1)?;
            before(deadline)?;
            state.raw.file = Some(
                rustix::fs::openat(
                    state.directory(Directory::Root)?,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(io::Error::from),
            );
            state.post(deadline)?;
            let child = state.check_opened(true, deadline)?;
            if child.device != root.device {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::ControlInvalid,
                ));
            }
            state.named_matches(Directory::Root, name, child, deadline)?;
            let file = state.take_opened()?;
            match slot {
                Directory::Operations => state.operations = Some(file),
                Directory::Runtimes => state.runtimes = Some(file),
                _ => unreachable!(),
            }
        }
        for (name, marker) in [
            ("owner.lock", b"WBRCOWN1"),
            ("admission.lock", b"WBRCADM1"),
            ("runtime.lock", b"WBRCRUN1"),
        ] {
            if create_layout { state.ensure_lock(name, marker, deadline)?; }
        }
        state.check_root_namespace(deadline)?;
        if let Some(source) = &mut state.service_source {
            source.recheck_original(deadline)?;
        }
        Ok(())
    })();
    result.map_err(|e: RecoveryControlError| e.retain(&shared))?;
    Ok(shared)
}

/// Request reading uses the real held original request. The later Local and
/// Server producers supply the private seals; no public construction fallback.
pub(super) fn verify_intent(
    owner: &ControlOwner,
    request: OwnedRecoveryRequestFile,
    host: VerifiedRecoveryHost,
    deadline: Instant,
) -> Result<VerifiedRecoveryHostIntent, RecoveryControlError> {
    let result = (|| {
        let mut state = lock(owner)?;
        if state.pending_request.is_some() || state.pending_host.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        state.pending_request = Some(request);
        state.pending_host = Some(host);
        before(deadline)?;
        let current = state.root_identity(deadline)?;
        state
            .pending_host
            .as_mut()
            .ok_or_else(service_invalid)?
            .recheck_original(deadline)?;
        let h = state
            .pending_host
            .as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if h.uid != state.uid {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        #[cfg(feature = "desktop-local")]
        match &h.original {
            #[cfg(feature = "desktop-local")]
            HostOrigin::LocalRelease { actual, .. } => {
                if actual.as_path().parent() != state.root_path.parent()
                    || actual.as_path().file_name() != state.app_component.as_deref()
                {
                    return Err(service_invalid());
                }
            }
        }
        let (host_bytes, host_files) = h.retained_usage()?;
        let request = state.pending_request.as_ref().ok_or_else(service_invalid)?;
        let original_identity = request.identity;
        let input_bytes = host_bytes
            .checked_add(std::mem::size_of::<OwnedRecoveryRequestFile>() as u64)
            .and_then(|n| n.checked_add(request.component.capacity() as u64))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let usage = (input_bytes, host_files.checked_add(2).ok_or_else(service_invalid)?);
        match state.preheld_restore_usage.take() {
            Some(original) if original == usage => (),
            Some(_) => return Err(service_invalid()),
            None => state.prepay(usage.0, usage.1)?,
        }
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.metadata = Some(
            state
                .pending_request
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
                .parent
                .metadata(),
        );
        state.post(deadline)?;
        state.valid_meta(
            state
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?,
            true,
        )?;
        component(
            &state
                .pending_request
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?
                .component,
            &state.limits,
        )?;
        let file = state
            .pending_request
            .as_mut()
            .and_then(|r| r.file.take())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        state.raw.file = Some(Ok(file));
        let actual = state.check_opened(false, deadline)?;
        if actual != original_identity
            || state.pending_request.as_ref().map(|r| r.identity) != Some(actual)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        let length = state
            .raw
            .metadata
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(Metadata::len)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if length == 0
            || length > state.limits.max_request_bytes
            || length
                > state
                    .pending_host
                    .as_ref()
                    .ok_or_else(service_invalid)?
                    .limits
                    .max_request_bytes
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        let n =
            usize::try_from(length.checked_add(1).ok_or_else(|| {
                RecoveryControlError::new(RecoveryControlFault::CapacityExceeded)
            })?)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let backing = n
            .checked_mul(2)
            .and_then(|v| v.checked_add(std::mem::size_of::<Vec<u8>>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(backing as u64, 0)?;
        state.scratch = Vec::new();
        state
            .scratch
            .try_reserve_exact(n)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if state.scratch.capacity()
            > n.checked_mul(2)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::CapacityExceeded,
            ));
        }
        state.scratch.resize(n, 0);
        let mut offset = 0usize;
        loop {
            state.reserve_io(0)?;
            before(deadline)?;
            let result = {
                let ControlFiles { raw, scratch, .. } = &mut *state;
                raw.file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read_at(&mut scratch[offset..], offset as u64)
            };
            state.raw.count = Some(result);
            state.post(deadline)?;
            let got = *state
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if got == 0 {
                break;
            }
            offset = offset
                .checked_add(got)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if offset >= n {
                return Err(RecoveryControlError::new(
                    RecoveryControlFault::EntryInvalid,
                ));
            }
        }
        if offset as u64 != length {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        state.scratch.truncate(offset);
        // Complete second read from the same FD, not a digest supplied by the
        // request producer. The original raw result remains resident before
        // each deadline/identity observation.
        let mut offset = 0usize;
        while offset < state.scratch.len() {
            let end = state.scratch.len().min(offset + 8);
            state.reserve_io(0)?;
            before(deadline)?;
            let result = {
                let ControlFiles { raw, .. } = &mut *state;
                raw.file
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read_at(&mut raw.small[..end - offset], offset as u64)
            };
            state.raw.count = Some(result);
            state.post(deadline)?;
            let n = *state
                .raw
                .count
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0
                || n > end - offset
                || state.raw.small[..n] != state.scratch[offset..offset + n]
            {
                return Err(service_invalid());
            }
            offset += n;
        }
        if state.check_opened(false, deadline)? != original_identity
            || state
                .raw
                .metadata
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map(Metadata::len)
                != Some(length)
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.named = Some({
            let r = state
                .pending_request
                .as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
            rustix::fs::statat(&r.parent, r.component.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        });
        state.post(deadline)?;
        let named = state
            .raw
            .named
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != original_identity.device
            || named.st_ino as u64 != original_identity.inode
            || named.st_uid != original_identity.uid
            || named.st_size as u64 != length
            || named.st_mode & 0o7777 != 0o600
            || named.st_nlink != 1
            || rustix::fs::FileType::from_raw_mode(named.st_mode)
                != rustix::fs::FileType::RegularFile
        {
            return Err(RecoveryControlError::new(
                RecoveryControlFault::EntryInvalid,
            ));
        }
        state.post(deadline)?;
        state
            .pending_host
            .as_mut()
            .ok_or_else(service_invalid)?
            .recheck_original(deadline)?;
        if state.root_identity(deadline)? != current {
            return Err(service_invalid());
        }
        let decode_bytes = state
            .scratch
            .len()
            .checked_mul(32)
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<RecoveryRequestWire>()
                        + std::mem::size_of::<DecodedRecoveryRequest>()
                        + 1024,
                )
            })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(decode_bytes as u64, 0)?;
        state.raw_request_decode = Some(decode_restore_request(&state.scratch, &state.limits));
        state.post(deadline)?;
        let decoded = match state.raw_request_decode.as_ref() {
            Some(Ok(decoded)) => decoded,
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            None => return Err(service_invalid()),
        };
        let host = state.pending_host.as_ref().ok_or_else(service_invalid)?;
        if !super::journal::hex_matches(
            &host.reviewed_release_digest,
            decoded.expected().reviewed_release_digest.as_str(),
        ) {
            return Err(service_invalid());
        }
        #[cfg(feature = "desktop-local")]
        match &host.original {
            #[cfg(feature = "desktop-local")]
            HostOrigin::LocalRelease { actual, .. } => {
                match decoded {
                    DecodedRecoveryRequest::Restore(decoded) => {
                        if Some(decoded.selection.target.parent.as_path()) != actual.as_path().parent() || decoded.selection.target.component == state.root_component { return Err(service_invalid()); }
                    }
                    DecodedRecoveryRequest::Legacy(decoded) => {
                        let selection = &decoded.selection.installation;
                        if Some(selection.parent.as_path()) != actual.as_path().parent() || actual.as_path().file_name() != Some(std::ffi::OsStr::new(&selection.component)) || decoded.limits.effect_ns > host.ordinary_bounds.effect_ns || decoded.limits.convergence_ns > host.ordinary_bounds.convergence_ns { return Err(service_invalid()); }
                    }
                    DecodedRecoveryRequest::Current(decoded) => {
                        if decoded.limits.effect_ns > host.ordinary_bounds.effect_ns || decoded.limits.convergence_ns > host.ordinary_bounds.convergence_ns { return Err(service_invalid()); }
                    }
                }
            }
        }
        let file = state.take_opened()?;
        let mut request = state
            .pending_request
            .take()
            .expect("original request remains resident through validation");
        request.file = Some(file);
        let host = state
            .pending_host
            .take()
            .expect("original host remains resident through validation");
        Ok(VerifiedRecoveryHostIntent {
            host,
            request,
            request_bytes: std::mem::take(&mut state.scratch),
            control_root: current,
            decoded: state
                .raw_request_decode
                .take()
                .expect("original decode retained")
                .expect("successful closed request decode"),
            original_deadline: deadline,
        })
    })();
    result.map_err(|e: RecoveryControlError| {
        if let Ok(mut state) = lock(owner) {
            state.latch(e.fault());
        }
        e.retain(owner)
    })
}
