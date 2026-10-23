//! Original host seals and descriptor-relative external control resources.
//!
//! Host seals belong to real release/service producers. Source loaders verify
//! actual OS owners and held files; a nominal path/digest/bool is not a seal.

use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::FileExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::activation::PublishedActivation;
use super::{
    ControlBudget, RecoveryControlConfig, RecoveryControlError, RecoveryControlFault,
    RecoveryFileIdentity, TrustedHostRecoveryLimits, before, component, hex,
};

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
    ordinary_startup_bounds: ServiceOrdinaryStartupBounds,
    expected_service_owner: ExpectedServiceOwner,
    expected_installation_binding: ServiceInstallationExpectation,
    expected_server_database: ServiceServerDatabaseExpectation,
    optional_startup_intent: super::RequiredNullable<PositiveServiceOrdinarySelection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceOrdinaryStartupBounds { effect_ns: u64, convergence_ns: u64 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedServiceOwner { uid: u32, service: String }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceInstallationExpectation {
    deployment_id: String,
    tenant_id: String,
    dataset_id: String,
    source_installation_id: String,
    target_installation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceServerDatabaseExpectation {
    pg_system_id: u64,
    database_oid: u32,
    pg_major: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceOrdinaryMode { FreshInit, LegacyAdoption }

// Both closed variants have precisely mode and intentFile. Neither variant
// carries a profile, actor, release pin, root or database credentials.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PositiveServiceOrdinarySelection {
    mode: ServiceOrdinaryMode,
    intent_file: PathBuf,
}

// Decode fixed DATA directly into stack-owned arrays. Escaped JSON strings
// are accepted through visit_str; no request-id/digest String is retained.
struct ServiceIntentHex<const N: usize>([u8; N]);
impl<const N: usize> ServiceIntentHex<N> {
    fn validate(&self) -> Result<(), RecoveryControlError> {
        let value = std::str::from_utf8(&self.0).map_err(|_| service_invalid())?;
        hex(value, N, N == 32)
    }
}
impl<'de, const N: usize> Deserialize<'de> for ServiceIntentHex<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor<const N: usize>;
        impl<const N: usize> serde::de::Visitor<'_> for HexVisitor<N> {
            type Value = ServiceIntentHex<N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "exactly {N} lowercase hexadecimal characters")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                hex(value, N, N == 32).map_err(|_| E::custom("invalid service intent reference"))?;
                let mut bytes = [0; N];
                bytes.copy_from_slice(value.as_bytes());
                Ok(ServiceIntentHex(bytes))
            }
        }
        deserializer.deserialize_str(HexVisitor::<N>)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceConfigReference {
    file: RecoveryFileIdentity,
    length: u64,
    digest: ServiceIntentHex<64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerOrdinaryIntentV1 {
    format_version: u32,
    request_id: ServiceIntentHex<32>,
    mode: ServiceOrdinaryMode,
    service_config: ServiceConfigReference,
}

struct ServiceOrdinaryInput {
    input: ServiceOwnedInput,
    intent: ServerOrdinaryIntentV1,
}
impl ServiceOrdinaryInput {
    fn validate(&self, config: &ServiceOwnedInput, mode: ServiceOrdinaryMode) -> Result<(), RecoveryControlError> {
        self.intent.request_id.validate()?;
        self.intent.service_config.file.validate()?;
        self.intent.service_config.digest.validate()?;
        if self.intent.format_version != 1 || self.intent.mode != mode
            || self.intent.service_config.file != config.stamp.identity
            || self.intent.service_config.length != config.stamp.length
        { return Err(service_invalid()); }
        let actual = Sha256::digest(&config.bytes);
        let digits = b"0123456789abcdef";
        if actual.iter().enumerate().any(|(index, byte)| {
            self.intent.service_config.digest.0[2 * index] != digits[usize::from(byte >> 4)]
                || self.intent.service_config.digest.0[2 * index + 1] != digits[usize::from(byte & 15)]
        }) { return Err(service_invalid()); }
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
        if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(service_invalid());
        }
        Ok(Self {
            identity: identity(metadata), length: metadata.len(),
            modified_seconds: metadata.mtime(), modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(), changed_nanoseconds: metadata.ctime_nsec(),
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
    match deadline { Some(deadline) => before(deadline), None => Ok(()) }
}

fn service_directory(metadata: &Metadata, uid: u32) -> Result<RecoveryFileIdentity, RecoveryControlError> {
    if !metadata.is_dir() || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & 0o022 != 0 || metadata.mode() & 0o7000 != 0
    {
        return Err(service_invalid());
    }
    Ok(identity(metadata))
}

fn service_absolute(path: &Path) -> Result<(), RecoveryControlError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.len() < 2 || bytes.len() as u64 > SERVICE_CONFIGURATION_MAX_BYTES
        || bytes.contains(&0) || bytes[1..].split(|b| *b == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(service_invalid());
    }
    Ok(())
}

impl ServiceNamedParent {
    fn open(path: &Path, uid: u32, deadline: Option<Instant>) -> Result<Self, RecoveryControlError> {
        service_absolute(path)?;
        let parent = path.parent().ok_or_else(service_invalid)?;
        let component = path.file_name().ok_or_else(service_invalid)?.to_os_string();
        let root = File::from(rustix::fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY
            | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty()).map_err(service_io)?);
        service_time(deadline)?;
        let root_identity = service_directory(&root.metadata().map_err(service_io)?, uid)?;
        let mut ancestors = Vec::new();
        let depth = parent.components().count();
        ancestors.try_reserve_exact(depth)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if ancestors.capacity() > depth.checked_mul(2).ok_or_else(service_invalid)?
            || component.capacity() > component.len().checked_mul(2).ok_or_else(service_invalid)?
        { return Err(service_invalid()); }
        ancestors.push(ServiceAncestor { file: root, identity: root_identity, component: None });
        for item in parent.components() {
            let Component::Normal(name) = item else {
                if matches!(item, Component::RootDir) { continue; }
                return Err(service_invalid());
            };
            service_time(deadline)?;
            let previous = ancestors.last().ok_or_else(service_invalid)?;
            let file = File::from(rustix::fs::openat(&previous.file, name, OFlags::RDONLY
                | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty()).map_err(service_io)?);
            service_time(deadline)?;
            let actual = service_directory(&file.metadata().map_err(service_io)?, uid)?;
            let named = rustix::fs::statat(&previous.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(service_io)?;
            service_time(deadline)?;
            if named.st_dev as u64 != actual.device || named.st_ino as u64 != actual.inode
                || named.st_uid != actual.uid || named.st_mode & 0o022 != 0
                || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
            {
                return Err(service_invalid());
            }
            let component = name.to_os_string();
            if component.capacity() > name.len().checked_mul(2).ok_or_else(service_invalid)? { return Err(service_invalid()); }
            ancestors.push(ServiceAncestor { file, identity: actual, component: Some(component) });
        }
        let result = Self { ancestors, component };
        result.recheck(uid, deadline)?;
        Ok(result)
    }

    fn directory(&self) -> Result<&File, RecoveryControlError> {
        self.ancestors.last().map(|entry| &entry.file).ok_or_else(service_invalid)
    }

    fn recheck(&self, uid: u32, deadline: Option<Instant>) -> Result<(), RecoveryControlError> {
        for (index, current) in self.ancestors.iter().enumerate() {
            service_time(deadline)?;
            if service_directory(&current.file.metadata().map_err(service_io)?, uid)? != current.identity {
                return Err(service_invalid());
            }
            let named = match &current.component {
                None if index == 0 => rustix::fs::statat(&current.file, "/", AtFlags::SYMLINK_NOFOLLOW),
                Some(component) if index > 0 => rustix::fs::statat(&self.ancestors[index - 1].file,
                    component.as_os_str(), AtFlags::SYMLINK_NOFOLLOW),
                _ => return Err(service_invalid()),
            }.map_err(service_io)?;
            service_time(deadline)?;
            if named.st_dev as u64 != current.identity.device || named.st_ino as u64 != current.identity.inode
                || named.st_uid != current.identity.uid || named.st_mode & 0o022 != 0
                || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
            {
                return Err(service_invalid());
            }
        }
        Ok(())
    }

    fn retained_bytes(&self) -> Result<u64, RecoveryControlError> {
        let backing = self.ancestors.capacity().checked_mul(std::mem::size_of::<ServiceAncestor>())
            .and_then(|n| n.checked_add(self.component.capacity())).ok_or_else(service_invalid)?;
        self.ancestors.iter().try_fold(backing as u64, |sum, node| {
            sum.checked_add(node.component.as_ref().map_or(0, std::ffi::OsString::capacity) as u64)
                .ok_or_else(service_invalid)
        })
    }
}

impl ServiceOwnedInput {
    fn open(path: &Path, uid: u32, limit: u64, deadline: Option<Instant>) -> Result<Self, RecoveryControlError> {
        let parent = ServiceNamedParent::open(path, uid, deadline)?;
        service_time(deadline)?;
        let file = File::from(rustix::fs::openat(parent.directory()?, parent.component.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty()).map_err(service_io)?);
        service_time(deadline)?;
        let stamp = ServiceFileStamp::of(&file.metadata().map_err(service_io)?, uid)?;
        if stamp.length == 0 || stamp.length > limit { return Err(service_invalid()); }
        let n = usize::try_from(stamp.length.checked_add(1).ok_or_else(service_invalid)?).map_err(service_io)?;
        let mut input = Self { file, parent, stamp, bytes: Vec::new(), raw: ServiceInputIo {
            metadata: None, named: None, read: None, readback: [0; 8192],
        } };
        input.bytes.try_reserve_exact(n)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if input.bytes.capacity() > n.checked_mul(2).ok_or_else(service_invalid)? { return Err(service_invalid()); }
        input.bytes.resize(n, 0);
        let mut offset = 0usize;
        loop {
            service_time(deadline)?;
            input.raw.read = Some(input.file.read_at(&mut input.bytes[offset..], offset as u64));
            service_time(deadline)?;
            let count = *input.raw.read.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            if count == 0 { break; }
            offset = offset.checked_add(count).ok_or_else(service_invalid)?;
            if offset >= n { return Err(service_invalid()); }
        }
        if offset as u64 != stamp.length { return Err(service_invalid()); }
        input.bytes.truncate(offset);
        input.recheck(uid, deadline)?;
        Ok(input)
    }

    fn recheck(&mut self, uid: u32, deadline: Option<Instant>) -> Result<(), RecoveryControlError> {
        self.parent.recheck(uid, deadline)?;
        self.raw.metadata = Some(self.file.metadata());
        service_time(deadline)?;
        let current = ServiceFileStamp::of(self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?, uid)?;
        if current != self.stamp { return Err(service_invalid()); }
        self.raw.named = Some(rustix::fs::statat(self.parent.directory()?, self.parent.component.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW));
        service_time(deadline)?;
        let named = self.raw.named.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
        if named.st_dev as u64 != current.identity.device || named.st_ino as u64 != current.identity.inode
            || named.st_uid != uid || named.st_nlink != 1 || named.st_mode & 0o7777 != 0o600
            || named.st_size < 0 || named.st_size as u64 != current.length
            || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        {
            return Err(service_invalid());
        }
        let mut offset = 0usize;
        while offset < self.bytes.len() {
            let n = (self.bytes.len() - offset).min(self.raw.readback.len());
            service_time(deadline)?;
            self.raw.read = Some(self.file.read_at(&mut self.raw.readback[..n], offset as u64));
            service_time(deadline)?;
            let count = *self.raw.read.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            if count == 0 || self.raw.readback[..count] != self.bytes[offset..offset + count] {
                return Err(service_invalid());
            }
            offset = offset.checked_add(count).ok_or_else(service_invalid)?;
        }
        self.raw.read = Some(self.file.read_at(&mut self.raw.readback[..1], offset as u64));
        service_time(deadline)?;
        if !matches!(self.raw.read, Some(Ok(0))) { return Err(service_invalid()); }
        self.raw.metadata = Some(self.file.metadata());
        service_time(deadline)?;
        if ServiceFileStamp::of(self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(service_invalid)?, uid)? != self.stamp
        {
            return Err(service_invalid());
        }
        self.parent.recheck(uid, deadline)?;
        // The final named lookup follows the complete byte readback. A rename
        // during that read cannot leave a usable seal for only the held inode.
        self.raw.named = Some(rustix::fs::statat(self.parent.directory()?, self.parent.component.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW));
        service_time(deadline)?;
        let named = self.raw.named.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
        if named.st_dev as u64 != self.stamp.identity.device || named.st_ino as u64 != self.stamp.identity.inode
            || named.st_uid != uid || named.st_nlink != 1 || named.st_mode & 0o7777 != 0o600
            || named.st_size < 0 || named.st_size as u64 != self.stamp.length
            || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        { return Err(service_invalid()); }
        Ok(())
    }

    fn retained_bytes(&self) -> Result<u64, RecoveryControlError> {
        self.parent.retained_bytes()?.checked_add(self.bytes.capacity() as u64).ok_or_else(service_invalid)
    }

    fn files(&self) -> Result<u64, RecoveryControlError> {
        u64::try_from(self.parent.ancestors.len()).map_err(service_io)?.checked_add(1).ok_or_else(service_invalid)
    }
}

impl ServiceControlSelection {
    fn open(path: &Path, uid: u32, deadline: Instant) -> Result<Self, RecoveryControlError> {
        let parent = ServiceNamedParent::open(path, uid, Some(deadline))?;
        let named = rustix::fs::statat(parent.directory()?, parent.component.as_os_str(), AtFlags::SYMLINK_NOFOLLOW);
        before(deadline)?;
        let existing = match named {
            Err(error) if error == rustix::io::Errno::NOENT => None,
            Ok(named) => {
                if named.st_uid != uid || named.st_mode & 0o7777 != 0o700
                    || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
                { return Err(service_invalid()); }
                let file = File::from(rustix::fs::openat(parent.directory()?, parent.component.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty()).map_err(service_io)?);
                before(deadline)?;
                let actual = service_directory(&file.metadata().map_err(service_io)?, uid)?;
                if actual.device != named.st_dev as u64 || actual.inode != named.st_ino as u64 || actual.uid != uid {
                    return Err(service_invalid());
                }
                Some(ServiceAncestor { file, identity: actual, component: None })
            }
            Err(error) => return Err(service_io(error)),
        };
        Ok(Self { parent, existing })
    }

    fn excludes(&self, input: &ServiceOwnedInput) -> Result<(), RecoveryControlError> {
        if let Some(root) = &self.existing {
            if input.parent.ancestors.iter().any(|node| node.identity == root.identity) {
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

fn service_configuration_backing(configuration: &ServerRecoveryHostConfigV1) -> Result<u64, RecoveryControlError> {
    let ids = &configuration.expected_installation_binding;
    let mut bytes = 0u64;
    for capacity in [configuration.control_root.capacity(), configuration.expected_service_owner.service.capacity(),
        ids.deployment_id.capacity(), ids.tenant_id.capacity(), ids.dataset_id.capacity(),
        ids.source_installation_id.capacity(), ids.target_installation_id.capacity()]
    {
        bytes = bytes.checked_add(capacity as u64).ok_or_else(service_invalid)?;
    }
    if let super::RequiredNullable::Value(selection) = &configuration.optional_startup_intent {
        bytes = bytes.checked_add(selection.intent_file.capacity() as u64).ok_or_else(service_invalid)?;
    }
    Ok(bytes)
}

impl VerifiedServiceRecoveryHost {
    /// Explicit configured host limits. This DATA accessor cannot clone a seal.
    #[must_use]
    pub fn host_limits(&self) -> &TrustedHostRecoveryLimits { &self.configuration.host_limits }

    /// Positive ordinary-startup E/C bounds; no operation clock is created here.
    #[must_use]
    pub fn ordinary_startup_bounds(&self) -> (u64, u64) {
        (self.configuration.ordinary_startup_bounds.effect_ns, self.configuration.ordinary_startup_bounds.convergence_ns)
    }

    pub(super) fn matches_limits(&self, limits: &TrustedHostRecoveryLimits) -> bool {
        let own = self.host_limits();
        own.max_request_bytes == limits.max_request_bytes && own.max_activation_bytes == limits.max_activation_bytes
            && own.max_journal_frame_bytes == limits.max_journal_frame_bytes && own.max_journal_bytes == limits.max_journal_bytes
            && own.max_journal_records == limits.max_journal_records && own.max_runtime_record_bytes == limits.max_runtime_record_bytes
            && own.max_registered_runtimes == limits.max_registered_runtimes && own.max_retained_operations == limits.max_retained_operations
            && own.max_root_entries == limits.max_root_entries && own.max_temp_entries == limits.max_temp_entries
            && own.max_evidence_refs == limits.max_evidence_refs && own.max_runtime_resource_facts == limits.max_runtime_resource_facts
            && own.max_id_bytes == limits.max_id_bytes && own.max_component_bytes == limits.max_component_bytes
            && own.max_relative_path_bytes == limits.max_relative_path_bytes && own.max_path_depth == limits.max_path_depth
            && own.max_open_files == limits.max_open_files && own.max_metadata_bytes == limits.max_metadata_bytes
            && own.admission_ns == limits.admission_ns
    }

    pub(super) fn retained_usage(&self) -> Result<(u64, u64), RecoveryControlError> {
        let configuration_backing = service_configuration_backing(&self.configuration)?;
        let mut bytes = self.original_config.retained_bytes()?
            .checked_add(self.control_selection.parent.retained_bytes()?)
            .and_then(|n| n.checked_add(self.root.capacity() as u64))
            .and_then(|n| n.checked_add(configuration_backing))
            .ok_or_else(service_invalid)?;
        let mut files = self.original_config.files()?.checked_add(self.control_selection.parent.ancestors.len() as u64)
            .and_then(|n| n.checked_add(u64::from(self.control_selection.existing.is_some()))).ok_or_else(service_invalid)?;
        if let Some(intent) = &self.original_ordinary_input {
            bytes = bytes.checked_add(intent.input.retained_bytes()?).ok_or_else(service_invalid)?;
            files = files.checked_add(intent.input.files()?).ok_or_else(service_invalid)?;
        }
        Ok((bytes, files))
    }

    pub(super) fn recheck_original(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        if rustix::process::getuid().as_raw() != self.uid || rustix::process::geteuid().as_raw() != self.uid {
            return Err(service_invalid());
        }
        self.original_config.recheck(self.uid, Some(deadline))?;
        self.control_selection.parent.recheck(self.uid, Some(deadline))?;
        if let Some(root) = &self.control_selection.existing {
            if service_directory(&root.file.metadata().map_err(service_io)?, self.uid)? != root.identity {
                return Err(service_invalid());
            }
            let named = rustix::fs::statat(self.control_selection.parent.directory()?,
                self.control_selection.parent.component.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(service_io)?;
            before(deadline)?;
            if named.st_dev as u64 != root.identity.device || named.st_ino as u64 != root.identity.inode
                || named.st_uid != self.uid || named.st_mode & 0o7777 != 0o700
                || rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::Directory
            { return Err(service_invalid()); }
        }
        match (&self.configuration.optional_startup_intent, &mut self.original_ordinary_input) {
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
    if rustix::process::geteuid().as_raw() != uid { return Err(service_invalid()); }
    let original_config = ServiceOwnedInput::open(configured_path, uid, SERVICE_CONFIGURATION_MAX_BYTES, None)?;
    let configuration: ServerRecoveryHostConfigV1 = serde_json::from_slice(&original_config.bytes)
        .map_err(RecoveryControlError::from_json)?;
    let limits = configuration.host_limits.clone().checked()?;
    let expected_pg = &configuration.expected_server_database;
    if configuration.version != 1 || configuration.expected_service_owner.uid != uid
        || expected_pg.pg_system_id == 0 || expected_pg.database_oid == 0 || expected_pg.pg_major != 17
    { return Err(service_invalid()); }
    // This tuple is an explicit expected selection, never actual PG evidence.
    super::id(&configuration.expected_service_owner.service, limits.max_id_bytes)?;
    let ids = &configuration.expected_installation_binding;
    for id in [&ids.deployment_id, &ids.tenant_id, &ids.dataset_id, &ids.source_installation_id, &ids.target_installation_id] {
        super::id(id, limits.max_id_bytes.min(512))?;
    }
    let bounds = &configuration.ordinary_startup_bounds;
    if bounds.effect_ns == 0 || bounds.convergence_ns == 0
        || admission_start.checked_add(Duration::from_nanos(bounds.effect_ns))
            .and_then(|e| e.checked_add(Duration::from_nanos(bounds.convergence_ns))).is_none()
    { return Err(service_invalid()); }
    let deadline = admission_start.checked_add(Duration::from_nanos(limits.admission_ns)).ok_or_else(service_invalid)?;
    before(deadline)?;
    service_absolute(&configuration.control_root)?;
    let control_parent_depth = configuration.control_root.parent().ok_or_else(service_invalid)?.components().count();
    super::component(configuration.control_root.file_name().and_then(|name| name.to_str()).ok_or_else(service_invalid)?, &limits)?;
    let planned_files = original_config.files()?.checked_add(control_parent_depth as u64)
        .and_then(|n| n.checked_add(1)).ok_or_else(service_invalid)?;
    let root_path_bytes = configuration.control_root.as_os_str().as_bytes().len();
    let path_backing = root_path_bytes.checked_mul(4)
        .and_then(|n| control_parent_depth.checked_mul(2)
            .and_then(|depth| depth.checked_mul(std::mem::size_of::<ServiceAncestor>()))
            .and_then(|nodes| n.checked_add(nodes)))
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServiceNamedParent>()))
        .ok_or_else(service_invalid)?;
    let planned_metadata = original_config.retained_bytes()?.checked_add(service_configuration_backing(&configuration)?)
        .and_then(|n| n.checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64))
        .and_then(|n| n.checked_add(path_backing as u64)).ok_or_else(service_invalid)?;
    if control_parent_depth as u64 > limits.max_path_depth || planned_files > limits.max_open_files {
        return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
    }
    if planned_metadata > limits.max_metadata_bytes {
        return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
    }
    let control_selection = ServiceControlSelection::open(&configuration.control_root, uid, deadline)?;
    control_selection.excludes(&original_config)?;
    let mut verified = VerifiedServiceRecoveryHost {
        root: configuration.control_root.clone(), uid, original_config, configuration,
        control_selection, original_ordinary_input: None,
    };
    if verified.root.capacity() > root_path_bytes.checked_mul(2).ok_or_else(service_invalid)? {
        return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
    }
    if let super::RequiredNullable::Value(selection) = &verified.configuration.optional_startup_intent {
        service_absolute(&selection.intent_file)?;
        let (base_bytes, base_files) = verified.retained_usage()?;
        let depth = selection.intent_file.parent().ok_or_else(service_invalid)?.components().count();
        let path_bytes = selection.intent_file.as_os_str().as_bytes().len();
        let extra_metadata = path_bytes.checked_mul(2)
            .and_then(|n| depth.checked_mul(2).and_then(|depth| depth.checked_mul(std::mem::size_of::<ServiceAncestor>()))
                .and_then(|nodes| n.checked_add(nodes)))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServiceOwnedInput>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<ServerOrdinaryIntentV1>()))
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(service_invalid)?;
        let metadata_before_bytes = base_bytes.checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64)
            .and_then(|n| n.checked_add(extra_metadata as u64)).ok_or_else(service_invalid)?;
        let available = limits.max_metadata_bytes.checked_sub(metadata_before_bytes).ok_or_else(service_invalid)?;
        // Prepay the held byte Vec (at most 2 * (wire + 1)), pinned serde
        // escape/key scratch and any retained parse error before decode. The
        // fixed arrays above do not allocate. The extra 1024 bytes cover the
        // bounded decoder/field-label structure, not an effect/capacity default.
        let maximum_wire = available.checked_sub(2).ok_or_else(service_invalid)? / 8;
        let planned_files = base_files.checked_add(depth as u64).and_then(|n| n.checked_add(1)).ok_or_else(service_invalid)?;
        if maximum_wire == 0 || depth as u64 > limits.max_path_depth
            || planned_files > limits.max_open_files { return Err(service_invalid()); }
        // Prepay the original intent's real path/FD/buffer and typed return
        // slots before opening or allocating it. No second complete quota.
        let input = ServiceOwnedInput::open(&selection.intent_file, uid,
            limits.max_request_bytes.min(maximum_wire), Some(deadline))?;
        if input.stamp.identity == verified.original_config.stamp.identity { return Err(service_invalid()); }
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
    let bytes = bytes.checked_add(std::mem::size_of::<VerifiedServiceRecoveryHost>() as u64).ok_or_else(service_invalid)?;
    if bytes > limits.max_metadata_bytes || files > limits.max_open_files { return Err(service_invalid()); }
    verified.recheck_original(deadline)?;
    Ok(verified)
}

enum HostOrigin { LocalRelease(File), ServiceConfig(File) }

enum OriginalRequestPurpose { RestoreSame, RestoreNew, AdoptLegacy, ReconfirmCurrent }

/// Original live host evidence, never Deserialize/Clone or a supplied digest.
pub struct VerifiedRecoveryHost {
    control_root: RecoveryFileIdentity,
    reviewed_release_digest: String,
    uid: u32,
    original: HostOrigin,
    request_identity: RecoveryFileIdentity,
    request_digest: [u8; 32],
    request_purpose: OriginalRequestPurpose,
}

/// Original private request, held with its named parent and actual identity.
pub struct OwnedRecoveryRequestFile {
    file: Option<File>,
    parent: File,
    component: String,
    identity: RecoveryFileIdentity,
}

/// Once verified input. It does not itself perform or complete a restore.
pub struct VerifiedRecoveryHostIntent {
    pub(super) host: VerifiedRecoveryHost,
    request: OwnedRecoveryRequestFile,
    request_bytes: Vec<u8>,
    original_deadline: Instant,
}

/// Original ordinary producer's complete seal. In particular a parsed phase,
/// absent head or user-supplied Fresh enum cannot construct this value.
pub struct VerifiedOrdinaryStartupIntent {
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
pub(super) enum Directory { Root, Operations, Runtimes, OperationWork, RuntimeWork }

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
    original_process: Option<Result<wrok_bot_macos_process::ProcessIdentity, wrok_bot_macos_process::ProcessObservationError>>,
    original_process_evidence: Option<[u8; 32]>,
    raw_process_evidence: Option<Result<[u8; 32], wrok_bot_macos_process::ProcessObservationError>>,
    raw_process_clock: Option<Result<u64, RecoveryControlError>>,
    process_monotonic_ns: u64,
    scratch: Vec<u8>,
    first_fault: Option<RecoveryControlFault>,
    pub(super) activation_source: Option<Arc<OwnedRecord>>,
    activation_observation: Option<Result<Arc<super::activation::ActivationObservation>, RecoveryControlError>>,
    publication_journal: Option<Arc<OwnedRecord>>,
    publication_operation: Option<([u8; 32], RecoveryFileIdentity)>,
    publication_chain: Option<Result<super::journal::JournalObservation, RecoveryControlError>>,
    publication_seal: Option<Result<super::journal::VerifiedPublication, RecoveryControlError>>,
    existing_publication: Option<Result<PublishedActivation, RecoveryControlError>>,
    existing_server: Option<crate::db::initialization::OwnedExistingServerDatabase>,
    existing_configured_master_encoding: Option<openbot_domain::vault::SecretBytes>,
    raw_master_decode: Option<Result<openbot_domain::vault::SecretBytes, base64::DecodeError>>,
    existing_read_locks: bool,
    runtime_entropy: [u8; 16],
    raw_random: Option<Result<(), getrandom::Error>>,
    pub(super) pending_admission: Option<File>,
    pub(super) pending_runtime: Option<File>,
    pub(super) pending_owner: Option<File>,
    pending_request: Option<OwnedRecoveryRequestFile>,
    pending_host: Option<VerifiedRecoveryHost>,
    service_source: Option<VerifiedServiceRecoveryHost>,
    pub(super) runtime_record: Option<OwnedRecord>,
    pub(super) pending_startup: Option<VerifiedOrdinaryStartupIntent>,
    pub(super) runtime_input: Vec<u8>,
    pub(super) raw_encoding: Option<Result<(), serde_json::Error>>,
    pub(super) retained_runtime: Option<super::runtime::RuntimeOwnerBook>,
}

pub(super) struct ControlBook {
    files: Option<ControlFiles>,
    retired_metadata: u64,
    retired_files: u64,
    fault: Option<RecoveryControlFault>,
}
pub(super) type ControlOwner = Arc<Mutex<ControlBook>>;

/// Custody of the same original value, with no book guard across IO. None
/// means Busy; it cannot initialize a second owner or replace the original.
pub(super) struct ControlAccess { owner: ControlOwner, files: Option<ControlFiles> }
impl Deref for ControlAccess {
    type Target = ControlFiles;
    fn deref(&self) -> &ControlFiles { self.files.as_ref().expect("original control access") }
}
impl DerefMut for ControlAccess {
    fn deref_mut(&mut self) -> &mut ControlFiles { self.files.as_mut().expect("original control access") }
}
impl Drop for ControlAccess {
    fn drop(&mut self) {
        let Some(mut files) = self.files.take() else { return; };
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
        if let Some(fault) = book.fault { files.latch(fault); }
        // lock is the sole original-value taker; this is its sole put-back.
        book.files = Some(files);
    }
}

pub(super) fn lock(owner: &ControlOwner) -> Result<ControlAccess, RecoveryControlError> {
    let mut access = ControlAccess { owner: Arc::clone(owner), files: None };
    let mut book = owner.lock().map_err(|poisoned| {
        let mut book = poisoned.into_inner();
        book.fault.get_or_insert(RecoveryControlFault::OwnerLost);
        if let Some(files) = book.files.as_mut() { files.latch(RecoveryControlFault::OwnerLost); }
        RecoveryControlError::with_owner(RecoveryControlFault::OwnerLost, owner)
    })?;
    if let Some(fault) = book.fault { return Err(RecoveryControlError::with_owner(fault, owner)); }
    access.files = Some(book.files.take().ok_or_else(|| RecoveryControlError::with_owner(RecoveryControlFault::OwnerBusy, owner))?);
    drop(book);
    Ok(access)
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
        if let Some(fault) = fault { files.latch(fault); }
    } else {
        match (book.retired_metadata.checked_add(metadata), book.retired_files.checked_add(1)) {
            (Some(bytes), Some(count)) => {
                book.retired_metadata = bytes;
                book.retired_files = count;
            }
            _ => { book.fault.get_or_insert(RecoveryControlFault::OwnerLost); }
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
        + 2 * std::mem::size_of::<Result<wrok_bot_macos_process::ProcessIdentity, wrok_bot_macos_process::ProcessObservationError>>()
        + 2 * std::mem::size_of::<Result<[u8; 32], wrok_bot_macos_process::ProcessObservationError>>()
        + 2 * std::mem::size_of::<Result<u64, RecoveryControlError>>()
        + 2 * std::mem::size_of::<[u8; 32]>()
        + 2 * std::mem::size_of::<bool>()
        + 2 * std::mem::size_of::<(Option<u64>, Option<u64>)>()
        + 2 * std::mem::size_of::<(u64, u64)>()
        + 2 * std::mem::size_of::<(u32, u64, u32, [u8; 32])>()) as u64
}

pub(super) fn identity(meta: &Metadata) -> RecoveryFileIdentity {
    RecoveryFileIdentity { device: meta.dev(), inode: meta.ino(), uid: meta.uid() }
}

impl ControlFiles {
    pub(super) fn existing_server_pool(&self) -> Result<&crate::db::pool::DatabasePool, RecoveryControlError> {
        self.existing_server.as_ref().ok_or_else(service_invalid)?.pool()
    }

    pub(super) fn existing_scope(&self, pool: &crate::db::pool::DatabasePool, deployment: &str, tenant: &str) -> bool {
        let Some(Ok(observation)) = &self.activation_observation else { return false; };
        let Ok((binding, _)) = observation.ordinary_active() else { return false; };
        let Ok(binding) = binding.ordinary_server() else { return false; };
        binding.deployment_id == deployment && binding.tenant_id == tenant
            && self.existing_server_pool().is_ok_and(|actual| std::ptr::eq(actual.manager(), pool.manager()))
    }

    pub(super) fn holds_existing_read_locks(&self) -> bool {
        self.existing_read_locks && self.pending_admission.is_some() && self.pending_runtime.is_some()
    }

    pub(super) fn fill_runtime_nonce(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        if self.pending_owner.is_none() { return Err(service_invalid()); }
        self.post(deadline)?;
        self.raw_random = Some(getrandom::fill(&mut self.runtime_entropy));
        self.post(deadline)?;
        if !matches!(self.raw_random, Some(Ok(()))) { return Err(service_invalid()); }
        let original = self.pending_startup.as_mut().ok_or_else(service_invalid)?;
        if !original.runtime_nonce.is_empty() || original.runtime_nonce.capacity() < 32 {
            return Err(service_invalid());
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.runtime_entropy {
            original.runtime_nonce.push(HEX[usize::from(byte >> 4)] as char);
            original.runtime_nonce.push(HEX[usize::from(byte & 15)] as char);
        }
        hex(&original.runtime_nonce, 32, true)
    }

    fn process_clock_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.raw_process_clock = Some(super::clock::monotonic_ns());
        let observed = self.raw_process_clock.as_ref().and_then(|value| value.as_ref().ok()).copied();
        match observed {
            Some(value) if value >= self.process_monotonic_ns => self.process_monotonic_ns = value,
            _ => {
                self.latch(RecoveryControlFault::OwnerLost);
                return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
            }
        }
        before(deadline)
    }

    fn initialize_original_process(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        if self.original_process.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        before(deadline)?;
        self.process_clock_before(deadline)?;
        self.original_process = Some(super::clock::capture_original_process());
        if !matches!(self.original_process, Some(Ok(_))) { self.latch(RecoveryControlFault::OwnerLost); }
        // Actual capture result is resident before native/portable time.
        self.process_clock_before(deadline)?;
        self.post(deadline)
    }

    pub(super) fn post(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        // A process observation neither starts nor restarts operation E/C.
        // Ordinary expiry alone is not permanent owner loss. Actual native
        // process/boot/clock drift is; raw IO and results remain resident.
        if let Some(fault) = self.first_fault { return Err(RecoveryControlError::new(fault)); }
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
            Some(Ok(observed)) => super::clock::verify_process_evidence(observed, None).is_err()
                || self.original_process_evidence.is_some_and(|expected| expected != *observed),
            _ => true,
        };
        if invalid { self.latch(RecoveryControlFault::OwnerLost); }
        // Evidence/error is retained before either time check can fail.
        self.process_clock_before(deadline)?;
        if invalid { return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost)); }
        let observed = self.raw_process_evidence.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        self.original_process_evidence.get_or_insert(observed);
        before(deadline)
    }

    fn check_enrollment(&self, original: &super::runtime::OriginalRuntimeEnrollment) -> Result<(), RecoveryControlError> {
        let evidence = self.original_process_evidence.as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?;
        super::clock::verify_process_evidence(evidence,
            Some((&original.boot_identity, original.pid, &original.process_start)))
    }

    pub(super) fn verify_enrollment_before(
        &mut self, original: &super::runtime::OriginalRuntimeEnrollment, deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.post(deadline)?;
        self.check_enrollment(original)
    }

    pub(super) fn verify_pending_enrollment_before(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.post(deadline)?;
        let original = &self.pending_startup.as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.enrollment;
        self.check_enrollment(original)
    }

    pub(super) fn latch(&mut self, fault: RecoveryControlFault) {
        self.first_fault.get_or_insert(fault);
    }

    pub(super) fn prepay(&mut self, bytes: u64, files: u64) -> Result<(), RecoveryControlError> {
        if let Some(fault) = self.first_fault { return Err(RecoveryControlError::new(fault)); }
        self.budget.charge(bytes, files)
    }

    fn reserve_io(&mut self, files: u64) -> Result<(), RecoveryControlError> {
        // RawIo plus separate typed return/match slots were charged once in
        // open_control, before the first IO. Reusing those same slots is not a
        // new allocation. New FD reservations remain charged per handle.
        self.prepay(0, files)
    }

    fn retire_known_ordinary_leases(&mut self, metadata: u64, files: u64) {
        if let Err(error) = self.budget.retire_ordinary_leases(metadata, files) { self.latch(error.fault()); }
    }

    pub(super) fn directory(&self, dir: Directory) -> Result<&File, RecoveryControlError> {
        match dir {
            Directory::Root => self.root.as_ref(),
            Directory::Operations => self.operations.as_ref(),
            Directory::Runtimes => self.runtimes.as_ref(),
            Directory::OperationWork => self.operation_work.as_ref(),
            Directory::RuntimeWork => self.runtime_work.as_ref(),
        }.ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))
    }

    fn valid_meta(&self, meta: &Metadata, directory: bool) -> Result<(), RecoveryControlError> {
        if meta.uid() != self.uid || meta.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || if directory { !meta.is_dir() } else { !meta.is_file() || meta.nlink() != 1 }
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }

    fn take_opened(&mut self) -> Result<File, RecoveryControlError> {
        match self.raw.file.take() {
            Some(Ok(file)) => Ok(file),
            other => { self.raw.file = other; Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)) }
        }
    }

    fn check_opened(&mut self, directory: bool, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        let result = match self.raw.file.as_ref() {
            Some(Ok(file)) => file.metadata(),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        };
        self.raw.metadata = Some(result);
        self.post(deadline)?;
        let meta = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, directory)?;
        Ok(identity(meta))
    }

    fn named_matches(
        &mut self, dir: Directory, name: &str, expected: RecoveryFileIdentity, deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        self.raw.named = Some(rustix::fs::statat(
            self.directory(dir)?, name, AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let s = self.raw.named.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if s.st_dev as u64 != expected.device || s.st_ino as u64 != expected.inode || s.st_uid != expected.uid {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }

    pub(super) fn open_named(
        &mut self, dir: Directory, name: &str, write: bool, deadline: Instant,
    ) -> Result<(File, RecoveryFileIdentity), RecoveryControlError> {
        component(name, &self.limits)?;
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(rustix::fs::openat(
            self.directory(dir)?, name,
            (if write { OFlags::RDWR } else { OFlags::RDONLY }) | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ).map(File::from).map_err(io::Error::from));
        self.post(deadline)?;
        let expected = self.check_opened(false, deadline)?;
        self.named_matches(dir, name, expected, deadline)?;
        Ok((self.take_opened()?, expected))
    }

    pub(super) fn read_record(
        &mut self, dir: Directory, name: &str, cap: u64, deadline: Instant,
    ) -> Result<OwnedRecord, RecoveryControlError> {
        let (file, expected) = self.open_named(dir, name, false, deadline)?;
        self.raw.file = Some(Ok(file));
        let length = self.raw.metadata.as_ref().and_then(|m| m.as_ref().ok())
            .map(Metadata::len).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if length == 0 || length > cap {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        let n = usize::try_from(length.checked_add(1)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay((n as u64).checked_mul(2)
            .and_then(|v| v.checked_add(std::mem::size_of::<Vec<u8>>() as u64))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?, 0)?;
        self.scratch = Vec::new();
        self.scratch.try_reserve_exact(n)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if self.scratch.capacity() > n.checked_mul(2).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))? {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        self.scratch.resize(n, 0);
        let mut offset = 0usize;
        loop {
            self.reserve_io(0)?;
            before(deadline)?;
            let result = match self.raw.file.as_ref() {
                Some(Ok(file)) => { let mut borrowed = file; borrowed.read(&mut self.scratch[offset..]) }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            self.raw.count = Some(result);
            self.post(deadline)?;
            let got = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if got == 0 { break; }
            offset = offset.checked_add(got)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if offset >= n { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        }
        if offset as u64 != length { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        self.scratch.truncate(offset);
        let final_identity = self.check_opened(false, deadline)?;
        let final_length = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len);
        if final_identity != expected || final_length != Some(length) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.named_matches(dir, name, expected, deadline)?;
        Ok(OwnedRecord { file: self.take_opened()?, identity: expected, bytes: std::mem::take(&mut self.scratch) })
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
            other => { self.raw.file = other; None }
        }
    }

    pub(super) fn acquire(
        &mut self, name: &str, marker: &[u8; 8], operation: FlockOperation, deadline: Instant,
    ) -> Result<File, RecoveryControlError> {
        let (file, _) = self.open_named(Directory::Root, name, true, deadline)?;
        self.raw.file = Some(Ok(file));
        if self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len) != Some(8) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.raw.small = [0; 8];
        for offset in 0..8 {
            self.reserve_io(0)?;
            before(deadline)?;
            let result = match self.raw.file.as_ref() {
                Some(Ok(file)) => { let mut f = file; f.read(&mut self.raw.small[offset..offset + 1]) }
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            self.raw.count = Some(result); self.post(deadline)?;
            if !matches!(self.raw.count, Some(Ok(1))) {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
        }
        if &self.raw.small != marker {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        let result = match self.raw.file.as_ref() {
            Some(Ok(file)) => rustix::fs::flock(file, operation).map_err(io::Error::from),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        };
        self.raw.unit = Some(result); self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => self.take_opened(),
            Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy)),
            _ => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
    }

    pub(super) fn root_identity(&mut self, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(self.directory(Directory::Root)?.metadata());
        self.post(deadline)?;
        let m = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, true)?;
        let held = identity(m);
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.named = Some(rustix::fs::statat(
            self.parent.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?,
            self.root_component.as_str(), AtFlags::SYMLINK_NOFOLLOW,
        ));
        self.post(deadline)?;
        let named = self.raw.named.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != held.device || named.st_ino as u64 != held.inode
            || named.st_uid != held.uid || named.st_mode & 0o7777 != 0o700
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(held)
    }

    fn sync_directory(&mut self, dir: Directory, deadline: Instant) -> Result<(), RecoveryControlError> {
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
    fn ensure_directory(&mut self, name: &str, deadline: Instant) -> Result<(), RecoveryControlError> {
        component(name, &self.limits)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(rustix::fs::mkdirat(self.directory(Directory::Root)?, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(io::Error::from));
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => self.sync_directory(Directory::Root, deadline),
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
    }

    fn ensure_lock(&mut self, name: &str, marker: &[u8; 8], deadline: Instant) -> Result<(), RecoveryControlError> {
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(rustix::fs::openat(self.directory(Directory::Root)?, name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR).map(File::from).map_err(io::Error::from));
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
                    Some(Ok(f)) => { let mut borrowed = f; borrowed.write(&marker[offset..]) },
                    _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
                });
                self.post(deadline)?;
                let n = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
                if n == 0 { return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)); }
                offset = offset.checked_add(n).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            }
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.unit = Some(self.raw.file.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?.sync_all());
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
        if self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len) != Some(8) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.raw.small = [0; 8];
        for offset in 0..8 {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(self.raw.file.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                .read_at(&mut self.raw.small[offset..offset + 1], offset as u64));
            self.post(deadline)?;
            if !matches!(self.raw.count, Some(Ok(1))) {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
        }
        if &self.raw.small != marker { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        self.named_matches(Directory::Root, name, expected, deadline)?;
        // Only a fully synced/read-back bootstrap success retires this FD.
        self.raw.file = None;
        Ok(())
    }

    fn inventory_count(&mut self, dir: Directory, maximum: u64, deadline: Instant) -> Result<u64, RecoveryControlError> {
        if !matches!(dir, Directory::Root | Directory::Operations | Directory::Runtimes) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        // Locked libc/rustix copies exactly one native dirent name into a
        // CString: Darwin's d_name[1024], Linux's d_name[256]. This is a typed
        // ABI allocation bound, not a new owner-selected quota or an allowance
        // to accept a component longer than the actual host limit.
        let name_bytes = if cfg!(target_os = "macos") { 1024u64 }
            else if cfg!(target_os = "linux") { 256u64 }
            else { return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid)); };
        let layout = std::mem::size_of::<rustix::io::Result<rustix::fs::Dir>>()
            .checked_mul(2).and_then(|n| n.checked_add(2 * std::mem::size_of::<Option<rustix::io::Result<rustix::fs::DirEntry>>>() ))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        self.prepay((layout as u64).checked_add(std::mem::size_of::<[u8; 32]>() as u64)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?, 1)?;
        before(deadline)?;
        self.raw.file = Some(rustix::fs::openat(self.directory(dir)?, ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map(File::from).map_err(io::Error::from));
        self.post(deadline)?;
        let source = self.check_opened(true, deadline)?;
        match dir {
            Directory::Root => {
                if self.root_identity(deadline)? != source {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
            Directory::Operations => self.named_matches(Directory::Root, "operations", source, deadline)?,
            Directory::Runtimes => self.named_matches(Directory::Root, "runtimes", source, deadline)?,
            _ => unreachable!("closed inventory directory checked before IO"),
        }
        let file = self.take_opened()?;
        before(deadline)?;
        self.raw.directory = Some(rustix::fs::Dir::new(file));
        self.post(deadline)?;
        let mut count = 0u64;
        loop {
            self.prepay(name_bytes.checked_mul(2).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?, 0)?;
            before(deadline)?;
            self.raw.entry = Some(self.raw.directory.as_mut().and_then(|r| r.as_mut().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?.read());
            self.post(deadline)?;
            let entry = match self.raw.entry.as_ref() {
                Some(None) => break,
                Some(Some(Ok(e))) => e,
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            };
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." { continue; }
            count = count.checked_add(1).filter(|n| *n <= maximum)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if u64::try_from(name.len()).map_or(true, |n| n > self.limits.max_component_bytes) {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            if matches!(dir, Directory::Root) {
                if !matches!(name, b"owner.lock" | b"admission.lock" | b"runtime.lock" | b"activation-v1" | b"operations" | b"runtimes") {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            } else {
                if name.len() != 32 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
                let mut nonce = [0u8; 32]; nonce.copy_from_slice(name);
                let nonce = std::str::from_utf8(&nonce).map_err(|_| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
                hex(nonce, 32, true)?;
                self.reserve_io(0)?;
                before(deadline)?;
                self.raw.named = Some(rustix::fs::statat(self.directory(dir)?, nonce, AtFlags::SYMLINK_NOFOLLOW));
                self.post(deadline)?;
                let stat = self.raw.named.as_ref().and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
                if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
                    || stat.st_mode & 0o7777 != 0o700 || stat.st_uid != self.uid || stat.st_dev as u64 != source.device
                {
                    return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
                }
            }
        }
        // A real EOF, same root identity and matching original deadline are
        // required before successful retirement of this directory reader.
        self.root_identity(deadline)?;
        self.raw.entry = None; self.raw.directory = None;
        Ok(count)
    }

    fn check_root_namespace(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.inventory_count(Directory::Root, self.limits.max_root_entries, deadline).map(|_| ())
    }

    pub(super) fn verify_registration_capacity(&mut self, deadline: Instant) -> Result<(), RecoveryControlError> {
        if self.pending_owner.is_none() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerLost));
        }
        self.held_owner_identity(deadline)?;
        self.check_root_namespace(deadline)?;
        self.inventory_count(Directory::Operations, self.limits.max_retained_operations, deadline)?;
        let count = self.inventory_count(Directory::Runtimes, self.limits.max_registered_runtimes, deadline)?;
        if count >= self.limits.max_registered_runtimes {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        Ok(())
    }

    fn held_owner_identity(&mut self, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(self.pending_owner.as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::OwnerLost))?.metadata());
        self.post(deadline)?;
        let meta = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if meta.len() != 8 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        let held = identity(meta);
        self.named_matches(Directory::Root, "owner.lock", held, deadline)?;
        Ok(held)
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

    pub(super) fn verify_head_digest(&mut self, expected: &str, deadline: Instant) -> Result<(), RecoveryControlError> {
        hex(expected, 64, false)?;
        if self.activation_source.is_none() {
            let fixed = std::mem::size_of::<OwnedRecord>()
                .checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>())
                .and_then(|n| n.checked_add(2 * std::mem::align_of::<OwnedRecord>()))
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            self.prepay(fixed as u64, 0)?;
            let record = self.read_record(Directory::Root, "activation-v1", self.limits.max_activation_bytes, deadline)?;
            self.activation_source = Some(Arc::new(record));
        }
        // Clone only this existing Arc. The original FD/backing stays in the
        // control owner before every read/postcheck; no repeated head open or
        // new Vec allocation is charged to normal business traffic.
        let source = Arc::clone(self.activation_source.as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?);
        self.verify_original_record(&source, deadline)?;
        self.named_matches(Directory::Root, "activation-v1", source.identity, deadline)?;
        if self.activation_observation.is_none() {
            let fee = super::activation::read_metadata_reservation(&source.bytes)?
                .checked_add((2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
                    + 2 * std::mem::align_of::<super::activation::ActivationObservation>()) as u64)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            self.prepay(fee, 0)?;
            before(deadline)?;
            // The original FD/bytes already belong to this ControlFiles. Keep
            // the complete typed observation or parse error here before the
            // original postclock check; a late result is never discarded.
            self.activation_observation = Some(super::activation::observe(&source.bytes, &self.limits).map(Arc::new));
            self.post(deadline)?;
        }
        match &self.activation_observation {
            Some(Ok(observation)) if observation.digest == expected
                && matches!(observation.record.phase, super::ActivationPhase::OrdinaryActive | super::ActivationPhase::RestoreCurrent) => (),
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
        }
        // This DATA validation adds no PublishedActivation, PG/key proof or
        // Current grant. The inherited held-byte digest check still follows.
        let mut hash = Sha256::new();
        hash.update(b"wrokbot.restore.activation.v1\0"); hash.update(&source.bytes);
        let digest: [u8; 32] = hash.finalize().into();
        if !super::journal::hex_matches(&digest, expected) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        if let Some(journal) = self.publication_journal.as_ref().map(Arc::clone) {
            let (context, expected) = self.publication_operation.ok_or_else(service_invalid)?;
            self.reserve_io(0)?;
            self.raw.metadata = Some(self.directory(Directory::OperationWork)?.metadata());
            self.post(deadline)?;
            let actual = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            self.valid_meta(actual, true)?;
            if identity(actual) != expected { return Err(service_invalid()); }
            let context = std::str::from_utf8(&context).map_err(|_| service_invalid())?;
            self.named_matches(Directory::Operations, context, expected, deadline)?;
            self.verify_original_record(&journal, deadline)?;
            self.named_matches(Directory::OperationWork, "journal-v1", journal.identity, deadline)?;
        }
        self.post(deadline)
    }

    fn verify_original_record(&mut self, original: &OwnedRecord, deadline: Instant) -> Result<(), RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let meta = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if identity(meta) != original.identity || Some(meta.len()) != u64::try_from(original.bytes.len()).ok() {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let mut offset = 0usize;
        while offset < original.bytes.len() {
            let end = original.bytes.len().min(offset.checked_add(8)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(original.file.read_at(&mut self.raw.small[..end - offset], offset as u64));
            self.post(deadline)?;
            let n = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 || n > end - offset || self.raw.small[..n] != original.bytes[offset..offset + n] {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            offset = offset.checked_add(n).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let meta = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(meta, false)?;
        if identity(meta) != original.identity || Some(meta.len()) != u64::try_from(original.bytes.len()).ok() {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }

    pub(super) fn held_lock_identity(&mut self, admission: bool, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        self.reserve_io(0)?;
        before(deadline)?;
        let result = (if admission { self.pending_admission.as_ref() } else { self.pending_runtime.as_ref() })
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?.metadata();
        self.raw.metadata = Some(result);
        self.post(deadline)?;
        let m = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        let held = identity(m);
        if m.len() != 8 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        self.named_matches(Directory::Root, if admission { "admission.lock" } else { "runtime.lock" }, held, deadline)?;
        Ok(held)
    }

    pub(super) fn verify_held_lock(&mut self, original: &File, name: &str, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        if name != "admission.lock" && name != "runtime.lock" && name != "owner.lock" {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.metadata());
        self.post(deadline)?;
        let m = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        let held = identity(m);
        if m.len() != 8 { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
        self.named_matches(Directory::Root, name, held, deadline)?;
        Ok(held)
    }

    pub(super) fn verify_runtime_enrollment(
        &mut self, directory: &File, nonce: &str, original: &OwnedRecord, deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        hex(nonce, 32, true)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(directory.metadata());
        self.post(deadline)?;
        let m = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, true)?;
        let held = identity(m);
        self.named_matches(Directory::Runtimes, nonce, held, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.metadata = Some(original.file.metadata());
        self.post(deadline)?;
        let m = self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        self.valid_meta(m, false)?;
        if identity(m) != original.identity || u64::try_from(original.bytes.len()).ok() != Some(m.len()) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        let mut offset = 0usize;
        while offset < original.bytes.len() {
            let end = original.bytes.len().min(offset.checked_add(8).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(original.file.read_at(&mut self.raw.small[..end - offset], offset as u64));
            self.post(deadline)?;
            let n = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 || n > end - offset || self.raw.small[..n] != original.bytes[offset..offset + n] {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            offset = offset.checked_add(n).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.named = Some(rustix::fs::statat(directory, "enrollment-v1", AtFlags::SYMLINK_NOFOLLOW));
        self.post(deadline)?;
        let named = self.raw.named.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != original.identity.device || named.st_ino as u64 != original.identity.inode
            || named.st_uid != original.identity.uid || named.st_size as u64 != original.bytes.len() as u64
            || named.st_mode & 0o7777 != 0o600 || named.st_nlink != 1
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }

    pub(super) fn create_runtime_directory(&mut self, nonce: &str, deadline: Instant) -> Result<RecoveryFileIdentity, RecoveryControlError> {
        hex(nonce, 32, true)?;
        component(nonce, &self.limits)?;
        if self.runtime_work.is_some() { return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy)); }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(rustix::fs::mkdirat(self.directory(Directory::Runtimes)?, nonce,
            Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(io::Error::from));
        self.post(deadline)?;
        match self.raw.unit.as_ref() {
            Some(Ok(())) => (),
            Some(Err(e)) if e.kind() == io::ErrorKind::AlreadyExists => return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy)),
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
        }
        self.sync_directory(Directory::Runtimes, deadline)?;
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(rustix::fs::openat(self.directory(Directory::Runtimes)?, nonce,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty()).map(File::from).map_err(io::Error::from));
        self.post(deadline)?;
        let held = self.check_opened(true, deadline)?;
        if held.device != self.root_identity(deadline)?.device {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.named_matches(Directory::Runtimes, nonce, held, deadline)?;
        self.runtime_work = Some(self.take_opened()?);
        Ok(held)
    }

    /// The known enrollment/receipt name is published without replacement.
    /// Every temporary FD and full result remains in this owner on failure.
    pub(super) fn publish_runtime_record(
        &mut self, name: &str, bytes: &[u8], deadline: Instant,
    ) -> Result<(), RecoveryControlError> {
        let temporary = match name {
            "enrollment-v1" => "enrollment-v1.pending",
            "receipt-v1" => "receipt-v1.pending",
            _ => return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid)),
        };
        if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |n| n > self.limits.max_runtime_record_bytes) {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        self.reserve_io(1)?;
        before(deadline)?;
        self.raw.file = Some(rustix::fs::openat(self.directory(Directory::RuntimeWork)?, temporary,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR).map(File::from).map_err(io::Error::from));
        self.post(deadline)?;
        let original = self.check_opened(false, deadline)?;
        self.named_matches(Directory::RuntimeWork, temporary, original, deadline)?;
        let mut offset = 0usize;
        while offset < bytes.len() {
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(match self.raw.file.as_ref() {
                Some(Ok(f)) => { let mut f = f; f.write(&bytes[offset..]) },
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)),
            });
            self.post(deadline)?;
            let n = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 { return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)); }
            offset = offset.checked_add(n).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(self.raw.file.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?.sync_all());
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        // Read back the original held file, not a receipt supplied by a caller.
        self.verify_raw_bytes(bytes, deadline)?;
        self.named_matches(Directory::RuntimeWork, temporary, original, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(rustix::fs::linkat(self.directory(Directory::RuntimeWork)?, temporary,
            self.directory(Directory::RuntimeWork)?, name, AtFlags::empty()).map_err(io::Error::from));
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        self.named_matches(Directory::RuntimeWork, name, original, deadline)?;
        self.reserve_io(0)?;
        before(deadline)?;
        self.raw.unit = Some(rustix::fs::unlinkat(self.directory(Directory::RuntimeWork)?, temporary,
            AtFlags::empty()).map_err(io::Error::from));
        self.post(deadline)?;
        if !matches!(self.raw.unit.as_ref(), Some(Ok(()))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure));
        }
        self.sync_directory(Directory::RuntimeWork, deadline)?;
        if self.check_opened(false, deadline)? != original {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.verify_raw_bytes(bytes, deadline)?;
        self.named_matches(Directory::RuntimeWork, name, original, deadline)?;
        let cap = self.limits.max_runtime_record_bytes;
        self.runtime_record = Some(self.read_record(Directory::RuntimeWork, name, cap, deadline)?);
        if self.runtime_record.as_ref().map(|r| (r.identity, r.bytes.as_slice())) != Some((original, bytes)) {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        self.post(deadline)
    }

    fn verify_raw_bytes(&mut self, expected: &[u8], deadline: Instant) -> Result<(), RecoveryControlError> {
        self.prepay((std::mem::size_of::<[u8; 8]>() + std::mem::size_of::<usize>()) as u64, 0)?;
        let mut offset = 0usize;
        while offset < expected.len() {
            let end = expected.len().min(offset.checked_add(8)
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?);
            self.reserve_io(0)?;
            before(deadline)?;
            self.raw.count = Some(self.raw.file.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                .read_at(&mut self.raw.small[..end - offset], offset as u64));
            self.post(deadline)?;
            let n = *self.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if n == 0 || n > end - offset || self.raw.small[..n] != expected[offset..offset + n] {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            offset = offset.checked_add(n).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        }
        let held = self.check_opened(false, deadline)?;
        held.validate()?;
        if self.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len) != u64::try_from(expected.len()).ok() {
            return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
        }
        Ok(())
    }
}



/// Existing ordinary Server DATA is never allowed to mint a head. The same
/// actual read locks precede every bootstrap probe and survive into enrollment.
pub(super) async fn observe_existing_server_before(
    owner: &ControlOwner, database: &crate::db::pool::DatabaseConfig,
    configured_master_encoding: openbot_domain::vault::SecretBytes,
    deployment: &str, tenant: &str, deadline: Instant,
) -> Result<VerifiedOrdinaryStartupIntent, RecoveryControlError> {
    let result = async {
        let mut files = lock(owner)?;
        if files.existing_server.is_some() || files.pending_admission.is_some()
            || files.pending_runtime.is_some() || files.retained_runtime.is_some()
        { return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy)); }
        let fixed = std::mem::size_of::<crate::db::initialization::OwnedExistingServerDatabase>()
            .checked_add(2 * std::mem::size_of::<VerifiedOrdinaryStartupIntent>())
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<super::activation::PublishedActivation>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<super::journal::VerifiedPublication>()))
            .and_then(|n| n.checked_add(2 * std::mem::size_of::<super::runtime::OriginalRuntimeEnrollment>()))
            .and_then(|n| n.checked_add(8 * std::mem::size_of::<String>()))
            .and_then(|n| n.checked_add(4 * std::mem::size_of::<Vec<String>>()))
            .and_then(|n| n.checked_add(16 * 4096 + 2 * 32 + 2 * 64))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let typed = files.limits.max_id_bytes.checked_mul(24).and_then(|n| n.checked_add(fixed as u64))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        files.prepay(typed, 0)?;
        let source = files.service_source.as_mut().ok_or_else(service_invalid)?;
        source.recheck_original(deadline)?;
        if source.configuration.expected_installation_binding.deployment_id != deployment
            || source.configuration.expected_installation_binding.tenant_id != tenant
        { return Err(service_invalid()); }
        files.pending_admission = Some(files.acquire("admission.lock", b"WBRCADM1", FlockOperation::NonBlockingLockShared, deadline)?);
        files.pending_runtime = Some(files.acquire("runtime.lock", b"WBRCRUN1", FlockOperation::NonBlockingLockShared, deadline)?);
        files.existing_read_locks = true;
        let root = files.root_identity(deadline)?;
        files.reserve_io(0)?;
        files.raw.named = Some(rustix::fs::statat(files.directory(Directory::Root)?, "activation-v1", AtFlags::SYMLINK_NOFOLLOW));
        files.post(deadline)?;
        if matches!(files.raw.named, Some(Err(rustix::io::Errno::NOENT))) {
            return Err(RecoveryControlError::new(RecoveryControlFault::InitializationRequired));
        }
        files.prepay((std::mem::size_of::<OwnedRecord>() + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + 2 * std::mem::align_of::<OwnedRecord>()) as u64, 0)?;
        let cap = files.limits.max_activation_bytes;
        let actual = files.read_record(Directory::Root, "activation-v1", cap, deadline)?;
        files.activation_source = Some(Arc::new(actual));
        let actual = Arc::clone(files.activation_source.as_ref().ok_or_else(service_invalid)?);
        files.prepay(super::activation::read_metadata_reservation(&actual.bytes)?
            .checked_add((2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>() + 2 * std::mem::align_of::<super::activation::ActivationObservation>()) as u64)
            .ok_or_else(service_invalid)?, 0)?;
        files.activation_observation = Some(super::activation::observe(&actual.bytes, &files.limits).map(Arc::new));
        files.post(deadline)?;
        let observation = Arc::clone(files.activation_observation.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?);
        let (binding, _) = observation.ordinary_active()?;
        let binding = binding.ordinary_server()?;
        let source = files.service_source.as_ref().ok_or_else(service_invalid)?;
        let expected = &source.configuration.expected_installation_binding;
        let original_config = &source.original_config;
        if [binding.dataset_id, binding.deployment_id, binding.tenant_id, binding.source_installation_id, binding.target_installation_id]
            != [expected.dataset_id.as_str(), expected.deployment_id.as_str(), expected.tenant_id.as_str(), expected.source_installation_id.as_str(), expected.target_installation_id.as_str()]
            || binding.service_config.file != original_config.stamp.identity
            || binding.service_config.length != original_config.stamp.length
            || binding.service_config.digest != super::journal::digest_hex(&Sha256::digest(&original_config.bytes).into())
            || binding.server_database.pg_system_id != source.configuration.expected_server_database.pg_system_id
            || binding.server_database.database_oid != source.configuration.expected_server_database.database_oid
            || binding.server_database.pg_major != source.configuration.expected_server_database.pg_major
        { return Err(service_invalid()); }
        let reference = observation.publication_reference()?;
        let mut context = [0u8; 32]; context.copy_from_slice(reference.context_id.as_bytes());
        let context = std::str::from_utf8(&context).map_err(|_| service_invalid())?;
        files.reserve_io(1)?;
        files.raw.file = Some(rustix::fs::openat(files.directory(Directory::Operations)?, context,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty()).map(File::from).map_err(io::Error::from));
        files.post(deadline)?;
        let operation_identity = files.check_opened(true, deadline)?;
        files.named_matches(Directory::Operations, context, operation_identity, deadline)?;
        let mut operation_context = [0u8; 32]; operation_context.copy_from_slice(context.as_bytes());
        files.publication_operation = Some((operation_context, operation_identity));
        files.operation_work = Some(files.take_opened()?);
        files.prepay((std::mem::size_of::<OwnedRecord>() + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
            + 2 * std::mem::align_of::<OwnedRecord>()) as u64, 0)?;
        let cap = files.limits.max_journal_bytes;
        let journal = files.read_record(Directory::OperationWork, "journal-v1", cap, deadline)?;
        files.publication_journal = Some(Arc::new(journal));
        let journal = Arc::clone(files.publication_journal.as_ref().ok_or_else(service_invalid)?);
        let journal_fee = super::journal::read_metadata_reservation(&journal.bytes, &files.limits)?;
        files.prepay(journal_fee, 0)?;
        files.publication_chain = Some(super::journal::observe_chain(&journal.bytes, &files.limits));
        files.post(deadline)?;
        let chain = files.publication_chain.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
        chain.verify_ordinary_evidence(&observation)?;
        files.publication_seal = Some(chain.publication_for(&observation.record.control_id, &observation.digest,
            reference, actual.identity, super::ActivationPhase::OrdinaryActive));
        files.post(deadline)?;
        let publication = match files.publication_seal.take() {
            Some(Ok(publication)) => publication,
            other => {
                let fault = other.as_ref().and_then(|result| result.as_ref().err()).map_or(RecoveryControlFault::ControlInvalid, RecoveryControlError::fault);
                files.publication_seal = other;
                return Err(RecoveryControlError::new(fault));
            }
        };
        files.existing_publication = Some(PublishedActivation::bind(Arc::clone(&observation), publication));
        files.post(deadline)?;
        match files.existing_publication.as_ref() {
            Some(Ok(_)) => (),
            Some(Err(error)) => return Err(RecoveryControlError::new(error.fault())),
            None => return Err(service_invalid()),
        }

        // This original packet is resident before the first real connect poll.
        // It is retained on every subsequent error; no timeout/dropped future
        // becomes a driver/PG close observation.
        files.existing_configured_master_encoding = Some(configured_master_encoding);
        files.post(deadline)?;
        {
            use base64::Engine as _;
            let encoded = files.existing_configured_master_encoding.as_ref().ok_or_else(service_invalid)?;
            // The actual Server main has already applied the original key policy
            // and canonical loader to this same value. Only its 32-byte master
            // encoding is supported by the existing canary; never truncate or
            // reinterpret the original raw-text audit/MCP derivation key.
            if encoded.len() != 44 { return Err(service_invalid()); }
            files.raw_master_decode = Some(base64::engine::general_purpose::STANDARD.decode(encoded.expose())
                .map(openbot_domain::vault::SecretBytes::new));
        }
        files.post(deadline)?;
        if !matches!(files.raw_master_decode.as_ref(), Some(Ok(master)) if master.len() == 32) {
            return Err(service_invalid());
        }
        let decoded_master = match files.raw_master_decode.take() {
            Some(Ok(master)) => master,
            other => { files.raw_master_decode = other; return Err(service_invalid()); }
        };
        files.existing_server = Some(crate::db::initialization::OwnedExistingServerDatabase::new(decoded_master));
        files.post(deadline)?;
        files.existing_server.as_mut().ok_or_else(service_invalid)?.pool = Some(crate::db::pool::connect(database).await);
        files.post(deadline)?;
        let pool = files.existing_server_pool()?.clone();
        files.existing_server.as_mut().ok_or_else(service_invalid)?.client = Some(pool.get().await);
        files.post(deadline)?;
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.identity = Some(client.query_one(crate::db::initialization::EXISTING_SERVER_IDENTITY_SQL, &[]).await);
        }
        files.post(deadline)?;
        {
            let packet = files.existing_server.as_ref().ok_or_else(service_invalid)?;
            let row = packet.identity.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            let system: String = row.try_get("system_identifier").map_err(|_| service_invalid())?;
            let oid: u32 = row.try_get("database_oid").map_err(|_| service_invalid())?;
            let major: i32 = row.try_get("pg_major").map_err(|_| service_invalid())?;
            let principal: String = row.try_get("authenticated_principal").map_err(|_| service_invalid())?;
            let current: String = row.try_get("current_principal").map_err(|_| service_invalid())?;
            let database_owner: String = row.try_get("database_owner").map_err(|_| service_invalid())?;
            if system.parse::<u64>().ok() != Some(binding.server_database.pg_system_id)
                || oid != binding.server_database.database_oid || major != 17
                || principal != binding.server_database.authenticated_principal || current != principal
                || principal != database.user || database_owner != binding.server_database.database_owner
                || binding.postgres.key_id != principal || binding.postgres.key_version != 1
                || packet.master.expose().len() != 32
            { return Err(service_invalid()); }
        }
        files.post(deadline)?;
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.native = Some(crate::db::native::validate_current(client).await);
        }
        files.post(deadline)?;
        if !matches!(files.existing_server.as_ref().ok_or_else(service_invalid)?.native, Some(Ok(())))
            || binding.native_version != 53
            || binding.migration_digest != crate::db::native::native_0053_checksum()
        { return Err(service_invalid()); }
        // Preserve the original complete validator, not a migration count.
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.layout = Some(crate::db::desktop_vault_canary::verify_pre_upgrade_layout_on(client).await
                .map_err(crate::db::desktop_vault_canary::DesktopVaultCanaryError::from));
        }
        files.post(deadline)?;
        if !matches!(files.existing_server.as_ref().ok_or_else(service_invalid)?.layout, Some(Ok(ref layout)) if layout.native_version() == 53) {
            return Err(service_invalid());
        }
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.writer_schema = Some(crate::db::thread_history_writer_schema::verify(client).await);
        }
        files.post(deadline)?;
        if !matches!(files.existing_server.as_ref().ok_or_else(service_invalid)?.writer_schema, Some(Ok(()))) {
            return Err(service_invalid());
        }
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.known_restore = Some(client.query_one("SELECT EXISTS(SELECT 1 FROM openbot_internal.restore_pg_operations) AS known_restore", &[]).await);
        }
        files.post(deadline)?;
        if files.existing_server.as_ref().ok_or_else(service_invalid)?.known_restore.as_ref()
            .and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?.try_get::<_, bool>("known_restore").map_err(|_| service_invalid())?
        { return Err(service_invalid()); }
        let id_limit = i64::try_from(files.limits.max_id_bytes).map_err(|_| service_invalid())?;
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let client = packet.client.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            packet.canary = Some(client.query_one(crate::db::initialization::EXISTING_SERVER_CANARY_SQL,
                &[&deployment, &tenant, &id_limit]).await);
        }
        files.post(deadline)?;
        {
            let packet = files.existing_server.as_mut().ok_or_else(service_invalid)?;
            let row = packet.canary.as_ref().and_then(|v| v.as_ref().ok()).ok_or_else(service_invalid)?;
            let dataset: String = row.try_get("dataset_id").map_err(|_| service_invalid())?;
            let row_deployment: String = row.try_get("deployment_id").map_err(|_| service_invalid())?;
            let row_tenant: String = row.try_get("tenant_id").map_err(|_| service_invalid())?;
            let key_id: String = row.try_get("key_id").map_err(|_| service_invalid())?;
            let key_version: i32 = row.try_get("key_version").map_err(|_| service_invalid())?;
            let canary_schema: i16 = row.try_get("canary_schema").map_err(|_| service_invalid())?;
            let encrypted: String = row.try_get("encrypted_canary").map_err(|_| service_invalid())?;
            if dataset != binding.dataset_id || row_deployment != deployment || row_tenant != tenant
                || key_id != binding.master.key_id || key_version != 1 || binding.master.key_version != 1
                || canary_schema != 1
            { return Err(service_invalid()); }
            let aad = openbot_domain::vault::DesktopVaultCanaryBinding::new(dataset, row_deployment, row_tenant,
                key_id, openbot_domain::vault::KeyVersion::new(1)).map_err(|_| service_invalid())?;
            let envelope = openbot_domain::vault::DesktopVaultCanaryEnvelope::parse(&encrypted).map_err(|_| service_invalid())?;
            packet.crypto = Some(openbot_domain::vault::open_desktop_vault_canary(&packet.master, &aad, &envelope));
        }
        files.post(deadline)?;
        if !matches!(files.existing_server.as_ref().ok_or_else(service_invalid)?.crypto, Some(Ok(()))) { return Err(service_invalid()); }
        files.verify_head_digest(&observation.digest, deadline)?;
        files.service_source.as_mut().ok_or_else(service_invalid)?.recheck_original(deadline)?;
        files.post(deadline)?;
        let raw = files.original_process_evidence.as_ref().ok_or_else(service_invalid)?;
        // Only the existing native 16-byte boot value is encoded; no digest,
        // configured identity or second ProcessIdentity is used as a substitute.
        let mut boot = String::with_capacity(32);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in &raw[16..] { boot.push(HEX[usize::from(byte >> 4)] as char); boot.push(HEX[usize::from(byte & 15)] as char); }
        let enrollment = super::runtime::OriginalRuntimeEnrollment {
            boot_identity: boot, pid: u32::from_be_bytes(raw[..4].try_into().map_err(|_| service_invalid())?),
            process_start: super::journal::ProcessStart { seconds: u64::from_be_bytes(raw[4..12].try_into().map_err(|_| service_invalid())?),
                nanos: u32::from_be_bytes(raw[12..16].try_into().map_err(|_| service_invalid())?).checked_mul(1000).ok_or_else(service_invalid)? },
            resource_model: super::runtime::ResourceModel::Server,
            original_owner_set: vec!["server-config-original".into(), "server-database-original".into()],
        };
        files.verify_enrollment_before(&enrollment, deadline)?;
        let published = match files.existing_publication.take() {
            Some(Ok(published)) => published,
            other => { files.existing_publication = other; return Err(service_invalid()); }
        };
        Ok(VerifiedOrdinaryStartupIntent { published, control_root: root,
            runtime_nonce: String::with_capacity(32), original_deadline: deadline, enrollment })
    }.await;
    result.map_err(|error: RecoveryControlError| {
        if let Ok(mut files) = lock(owner) {
            if error.fault() == RecoveryControlFault::OwnerBusy && files.existing_server.is_none() {
                files.release_registration_attempt();
            } else { files.latch(error.fault()); }
        }
        error.retain(owner)
    })
}

pub(super) fn open_control(config: RecoveryControlConfig) -> Result<ControlOwner, RecoveryControlError> {
    if !config.root.is_absolute() {
        return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
    }
    let fixed = std::mem::size_of::<ControlFiles>()
        .checked_add(std::mem::size_of::<Mutex<ControlBook>>())
        .and_then(|n| n.checked_add(std::mem::size_of::<ControlAccess>()))
        .and_then(|n| n.checked_add(std::mem::size_of::<Result<ControlAccess, RecoveryControlError>>()))
        .and_then(|n| n.checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()))
        .and_then(|n| n.checked_add(2 * std::mem::align_of::<ControlFiles>()))
        .and_then(|n| n.checked_add(config.root.capacity()))
        .and_then(|n| n.checked_add(config.app_component.as_ref().map_or(0, std::ffi::OsString::capacity)))
        .and_then(|n| n.checked_add(static_io_fee() as usize))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    let deadline = Instant::now().checked_add(Duration::from_nanos(config.limits.admission_ns))
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ProfileInvalid))?;
    let mut budget = ControlBudget { metadata: 0, files: 0, metadata_limit: config.limits.max_metadata_bytes, file_limit: config.limits.max_open_files };
    let root_name = config.root.file_name().and_then(|s| s.to_str())
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
    let fixed = fixed.checked_add(root_name.len().checked_mul(2)
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?)
        .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
    budget.charge(fixed as u64, u64::from(config.service_source.is_some()))?;
    // The original fixed fee contains the source object's inline storage and
    // one configuration FD. Its actual additional retained backing/FDs remain
    // in the same original control budget; they are never counted as zero.
    if let Some(source) = &config.service_source {
        let (bytes, files) = source.retained_usage()?;
        budget.charge(bytes, files.checked_sub(1).ok_or_else(service_invalid)?)?;
    }
    let root_component = root_name.to_owned();
    component(&root_component, &config.limits)?;
    let shared = Arc::new(Mutex::new(ControlBook { files: Some(ControlFiles {
        root: None, parent: None, ancestors: Vec::new(), operations: None, runtimes: None,
        operation_work: None, runtime_work: None,
        root_path: config.root, root_component, app_component: config.app_component, uid: config.uid, limits: config.limits,
        budget, raw: RawIo { file: None, metadata: None, named: None, unit: None, count: None, small: [0; 8], directory: None, entry: None },
        original_process: None, original_process_evidence: None, raw_process_evidence: None,
        raw_process_clock: None, process_monotonic_ns: 0,
        scratch: Vec::new(), first_fault: None, activation_source: None, activation_observation: None,
        publication_journal: None, publication_operation: None, publication_chain: None, publication_seal: None, existing_publication: None,
        existing_server: None, existing_configured_master_encoding: None, raw_master_decode: None,
        existing_read_locks: false, runtime_entropy: [0; 16], raw_random: None,
        pending_admission: None,
        pending_runtime: None, pending_owner: None, pending_request: None,
        pending_host: None, service_source: config.service_source,
        runtime_record: None,
        pending_startup: None, runtime_input: Vec::new(), raw_encoding: None, retained_runtime: None,
    }), retired_metadata: 0, retired_files: 0, fault: None }));
    let result = (|| {
        let mut state = lock(&shared)?;
        state.initialize_original_process(deadline)?;
        if let Some(source) = &mut state.service_source {
            source.recheck_original(deadline)?;
        }
        let parent_bytes = state.root_path.parent()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.as_os_str().as_bytes().len();
        let parent_fee = parent_bytes.checked_mul(2).and_then(|n| n.checked_add(std::mem::size_of::<PathBuf>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(parent_fee as u64, 0)?;
        let parent_path = state.root_path.parent()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.to_path_buf();
        let depth = parent_path.components().count();
        if depth == 0 || depth as u64 > state.limits.max_path_depth {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        let ancestor_backing = depth.checked_mul(std::mem::size_of::<File>())
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(ancestor_backing as u64, depth as u64)?;
        state.ancestors.try_reserve_exact(depth)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if state.ancestors.capacity() > depth.checked_mul(2).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))? {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        state.raw.file = Some(rustix::fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map(File::from).map_err(io::Error::from));
        state.post(deadline)?;
        let first = state.take_opened()?; state.ancestors.push(first);
        for c in parent_path.components() {
            let Component::Normal(name) = c else {
                if matches!(c, Component::RootDir) { continue; }
                return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
            };
            state.reserve_io(0)?;
            let previous = state.ancestors.last().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            state.raw.file = Some(rustix::fs::openat(previous, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map(File::from).map_err(io::Error::from));
            state.post(deadline)?;
            let result = state.raw.file.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?.metadata();
            state.raw.metadata = Some(result); state.post(deadline)?;
            let m = state.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if !m.is_dir() || (m.uid() != 0 && m.uid() != state.uid) || m.mode() & 0o022 != 0 {
                return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid));
            }
            let file = state.take_opened()?; state.ancestors.push(file);
        }
        let parent = state.ancestors.pop().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
        state.parent = Some(parent);
        if let Some(source) = &state.service_source {
            let expected = source.control_selection.parent.ancestors.last().ok_or_else(service_invalid)?.identity;
            state.raw.metadata = Some(state.parent.as_ref().ok_or_else(service_invalid)?.metadata());
            state.post(deadline)?;
            let actual = state.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).ok_or_else(service_invalid)?;
            if identity(actual) != expected { return Err(service_invalid()); }
        }
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.unit = Some({
            let parent = state.parent.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
            rustix::fs::mkdirat(parent, state.root_component.as_str(), Mode::RWXU).map_err(io::Error::from)
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
            state.raw.unit = Some(state.parent.as_ref()
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?.sync_all());
            state.post(deadline)?;
            if !matches!(state.raw.unit, Some(Ok(()))) { return Err(RecoveryControlError::new(RecoveryControlFault::IoFailure)); }
        }
        state.reserve_io(1)?;
        before(deadline)?;
        state.raw.file = Some(rustix::fs::openat(state.parent.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?,
            state.root_component.as_str(), OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map(File::from).map_err(io::Error::from));
        state.post(deadline)?; state.check_opened(true, deadline)?;
        state.root = Some(state.take_opened()?);
        let root = state.root_identity(deadline)?;
        if let Some(expected) = state.service_source.as_ref()
            .and_then(|source| source.control_selection.existing.as_ref()).map(|root| root.identity)
        {
            if root != expected { return Err(service_invalid()); }
        }
        if state.app_component.is_some() {
            state.reserve_io(0)?;
            before(deadline)?;
            state.raw.named = Some({
                let parent = state.parent.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::ControlInvalid))?;
                rustix::fs::statat(parent, state.app_component.as_ref().expect("actual local sibling component").as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            });
            state.post(deadline)?;
            match state.raw.named.as_ref() {
                Some(Ok(s)) if rustix::fs::FileType::from_raw_mode(s.st_mode) == rustix::fs::FileType::Directory
                    && s.st_uid == state.uid && s.st_mode & 0o7777 == 0o700
                    && (s.st_dev as u64 != root.device || s.st_ino as u64 != root.inode) => (),
                Some(Err(e)) if *e == rustix::io::Errno::NOENT => (),
                _ => return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)),
            }
        }
        // Only fixed control metadata is bootstrapped, never a head or epoch.
        for (name, slot) in [("operations", Directory::Operations), ("runtimes", Directory::Runtimes)] {
            state.ensure_directory(name, deadline)?;
            state.reserve_io(1)?;
            before(deadline)?;
            state.raw.file = Some(rustix::fs::openat(state.directory(Directory::Root)?, name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map(File::from).map_err(io::Error::from));
            state.post(deadline)?;
            let child = state.check_opened(true, deadline)?;
            if child.device != root.device { return Err(RecoveryControlError::new(RecoveryControlFault::ControlInvalid)); }
            state.named_matches(Directory::Root, name, child, deadline)?;
            let file = state.take_opened()?;
            match slot { Directory::Operations => state.operations = Some(file), Directory::Runtimes => state.runtimes = Some(file), _ => unreachable!() }
        }
        for (name, marker) in [("owner.lock", b"WBRCOWN1"), ("admission.lock", b"WBRCADM1"), ("runtime.lock", b"WBRCRUN1")] {
            state.ensure_lock(name, marker, deadline)?;
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
    owner: &ControlOwner, request: OwnedRecoveryRequestFile,
    host: VerifiedRecoveryHost, deadline: Instant,
) -> Result<VerifiedRecoveryHostIntent, RecoveryControlError> {
    let result = (|| {
        let mut state = lock(owner)?;
        if state.pending_request.is_some() || state.pending_host.is_some() {
            return Err(RecoveryControlError::new(RecoveryControlFault::OwnerBusy));
        }
        state.pending_request = Some(request); state.pending_host = Some(host);
        before(deadline)?;
        let current = state.root_identity(deadline)?;
        let h = state.pending_host.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        if h.control_root != current || h.uid != state.uid {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        hex(&h.reviewed_release_digest, 64, false)?;
        if matches!(&h.original, HostOrigin::ServiceConfig(_))
            && matches!(h.request_purpose, OriginalRequestPurpose::RestoreSame | OriginalRequestPurpose::RestoreNew)
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        let original_identity = h.request_identity;
        let original_digest = h.request_digest;
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.metadata = Some(state.pending_request.as_ref()
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.parent.metadata());
        state.post(deadline)?;
        state.valid_meta(state.raw.metadata.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?, true)?;
        component(&state.pending_request.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?.component, &state.limits)?;
        let file = state.pending_request.as_mut().and_then(|r| r.file.take())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
        state.raw.file = Some(Ok(file));
        let actual = state.check_opened(false, deadline)?;
        if actual != original_identity || state.pending_request.as_ref().map(|r| r.identity) != Some(actual) {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        let length = state.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if length == 0 || length > state.limits.max_request_bytes {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        let n = usize::try_from(length.checked_add(1)
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?)
            .map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        let backing = n.checked_mul(2).and_then(|v| v.checked_add(std::mem::size_of::<Vec<u8>>()))
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        state.prepay(backing as u64, 0)?;
        state.scratch = Vec::new();
        state.scratch.try_reserve_exact(n).map_err(|_| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
        if state.scratch.capacity() > n.checked_mul(2).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))? {
            return Err(RecoveryControlError::new(RecoveryControlFault::CapacityExceeded));
        }
        state.scratch.resize(n, 0);
        let mut offset = 0usize;
        loop {
            state.reserve_io(0)?;
            before(deadline)?;
            let result = {
                let ControlFiles { raw, scratch, .. } = &mut *state;
                raw.file.as_ref().and_then(|r| r.as_ref().ok())
                    .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?
                    .read_at(&mut scratch[offset..], offset as u64)
            };
            state.raw.count = Some(result);
            state.post(deadline)?;
            let got = *state.raw.count.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
            if got == 0 { break; }
            offset = offset.checked_add(got).ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::CapacityExceeded))?;
            if offset >= n { return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid)); }
        }
        if offset as u64 != length { return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid)); }
        state.scratch.truncate(offset);
        if state.check_opened(false, deadline)? != original_identity
            || state.raw.metadata.as_ref().and_then(|r| r.as_ref().ok()).map(Metadata::len) != Some(length)
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        state.reserve_io(0)?;
        before(deadline)?;
        state.raw.named = Some({
            let r = state.pending_request.as_ref().ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::EntryInvalid))?;
            rustix::fs::statat(&r.parent, r.component.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        });
        state.post(deadline)?;
        let named = state.raw.named.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or_else(|| RecoveryControlError::new(RecoveryControlFault::IoFailure))?;
        if named.st_dev as u64 != original_identity.device || named.st_ino as u64 != original_identity.inode
            || named.st_uid != original_identity.uid || named.st_size as u64 != length
            || Sha256::digest(&state.scratch).as_slice() != original_digest
        {
            return Err(RecoveryControlError::new(RecoveryControlFault::EntryInvalid));
        }
        state.post(deadline)?;
        let file = state.take_opened()?;
        let mut request = state.pending_request.take().expect("original request remains resident through validation");
        request.file = Some(file);
        let host = state.pending_host.take().expect("original host remains resident through validation");
        Ok(VerifiedRecoveryHostIntent { host, request, request_bytes: std::mem::take(&mut state.scratch), original_deadline: deadline })
    })();
    result.map_err(|e: RecoveryControlError| {
        if let Ok(mut state) = lock(owner) { state.latch(e.fault()); }
        e.retain(owner)
    })
}
